// Behavioural checks on the locale fill applier, against the DOM harness so
// chrome.js is EXECUTED rather than parsed.
//
// The three contracts, each of which exists because an adversarial review
// showed the failure it prevents:
//   1. A snapshot APPLIES: marked text and attributes take the snapshot's
//      strings (the non-English path is live, not theoretical).
//   2. A STALE generation is refused after a newer one applied -- a raced
//      switch must never paint a mixed-language UI.
//   3. An INCOMPLETE snapshot is refused WHOLE and does not burn its
//      generation: nothing painted, and the corrected snapshot with the
//      same generation still applies. Partial fill is the mixed-language
//      page the generation gate exists to prevent.
//   4. A LATE resolve never overwrites a newer write. Two renders of the
//      same element, the older answered last: the newer text must survive.
//      Without the guard the stale answer wins, which names the wrong site in
//      a live plain-HTTP warning.
//   5. A fill PRESERVES the interception label. The applier reapplies every
//      static data-msg-aria-label in the document, including the tab
//      button's, and that silently replaced the screen-reader announcement
//      with the plain name while interception was still live -- worst after
//      a dismissal, when the label is the only trace left.
//
// 4 and 5 exist because an adversarial review removed each fix in memory and
// this gate still passed, so its green said nothing about either.
//
// Run: node scripts/i18n-fill-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// Let queued microtasks and setImmediate callbacks run. i18nSet paints English
// synchronously and replaces it from a promise, so a check that reads the
// element in the same tick sees only the synchronous write and can never
// observe a late resolve landing -- green whether the guard is there or not.
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

// Every marker key in the document, dash form, so snapshots can be complete
// by construction.
const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
const KEYS = [
  ...new Set(
    [...html.matchAll(/data-msg(?:-[a-z-]+)?="([a-z0-9.]+)"/g)].map((m) =>
      m[1].replace(/\./g, "-"),
    ),
  ),
];

// Keys rendered from JS rather than from a markup marker. `KEYS` is scraped
// from index.html, so these were absent from every snapshot, `i18nText` fell
// back to its English literal, and a check that looked for the word
// "intercept" matched that literal whether the fill worked or not.
const JS_KEYS = ["chrome-js-tab-aria-intercepted", "chrome-js-tab-aria-plain"];

function snapshot(generation, text) {
  const messages = {};
  for (const k of KEYS) messages[k] = text + " " + k;
  for (const k of JS_KEYS) messages[k] = text + " " + k;
  return { generation, locale: "en-XA", messages };
}

require(path.join(chromeDir, "chrome.js"));

// Runtime-marked probes: the stub seeds markup elements without attribute
// VALUES, so the observable path is elements that set their marker at
// runtime -- same applier branches, real keys from the real markup.
const probeEl = global.document.createElement("p");
probeEl.setAttribute("data-msg", KEYS[0].replace(/-/g, "."));
const attrEl = global.document.createElement("button");
attrEl.setAttribute("data-msg-title", KEYS[1].replace(/-/g, "."));
attrEl.setAttribute("title", "golden");

async function main() {
  // 1. A complete snapshot applies.
  global.window.__rb_event({ event: "ui_locale_fill", data: snapshot(2, "GEN2") });
  assert(
    probeEl.textContent.startsWith("GEN2 "),
    "a complete snapshot did not apply; still " +
      JSON.stringify(probeEl.textContent),
  );

  // 2. A stale generation is refused.
  global.window.__rb_event({ event: "ui_locale_fill", data: snapshot(1, "STALE") });
  assert(
    probeEl.textContent.startsWith("GEN2 "),
    "a stale snapshot overwrote a newer one",
  );

  // 3. An incomplete snapshot is refused whole and does not burn its
  //    generation.
  // Missing key = the PROBE's own: completeness is judged against the
  // markers this document actually carries.
  const partial = snapshot(3, "PART");
  delete partial.messages[KEYS[0]];
  global.window.__rb_event({ event: "ui_locale_fill", data: partial });
  assert(
    probeEl.textContent.startsWith("GEN2 "),
    "an incomplete snapshot painted anyway -- that is a mixed-language UI",
  );
  global.window.__rb_event({ event: "ui_locale_fill", data: snapshot(3, "GEN3") });
  assert(
    probeEl.textContent.startsWith("GEN3 "),
    "the refused snapshot burned its generation; the corrected one was " +
      "rejected too",
  );
  assert(
    (attrEl.getAttribute("title") || "").startsWith("GEN3 "),
    "attribute markers were not filled; title=" +
      JSON.stringify(attrEl.getAttribute("title")),
  );

  // 4. A late resolve must not overwrite a newer write.
  //
  // Driven through the plain-HTTP banner's body, which is an `i18nSet` caller
  // with an ARGUMENT, so two renders are distinguishable in the held calls.
  // It was the TLS issuer line until that was removed; the property under
  // test belongs to i18nSet, not to either banner.
  {
    const bodyEl = global.document.getElementById("insecure-body");
    assert(bodyEl, "#insecure-body is gone; this check needs an i18nSet caller");
    const held = [];
    const realPost = global.window.ipc.postMessage;
    global.window.ipc.postMessage = (raw) => {
      const m = JSON.parse(raw);
      if (m.cmd === "i18n_resolve") {
        held.push(m);
        return;
      }
      return realPost(raw);
    };
    const feed = (host) =>
      global.window.__rb_event({
        event: "tab_status",
        data: {
          tls: "not_tls",
          profile: "persistent",
          insecure_pending: "http://" + host + "/",
          insecure_pending_host: host,
        },
      });
    feed("older.example");
    feed("newer.example");
    global.window.ipc.postMessage = realPost;

    // SELECT BY ARGUMENT, not by position: the render resolves unrelated
    // strings too, so held[0] is not necessarily the older body.
    const bodyCalls = held.filter(
      (m) => m.args && m.args.args && typeof m.args.args.host === "string",
    );
    assert(
      bodyCalls.length >= 2,
      "the banner body made fewer than two i18n_resolve calls, so this check " +
        "exercises nothing (body calls=" +
        bodyCalls.length +
        " of " +
        held.length +
        " held)",
    );
    await flush();
    const before = bodyEl.textContent;
    assert(
      before.includes("newer.example"),
      "the second render did not paint; got " + JSON.stringify(before),
    );
    global.window.__rb_reply({
      id: bodyCalls[bodyCalls.length - 1].id,
      ok: true,
      data: { text: "NEWER-RESOLVED" },
    });
    global.window.__rb_reply({
      id: bodyCalls[0].id,
      ok: true,
      data: { text: "STALE-RESOLVED" },
    });
    await flush();
    const after = bodyEl.textContent;
    // The STALE assert first, because it names the real defect. Ordered the
    // other way, removing the guard failed on "the newest resolve did not
    // land at all" while the stale value sat in the message -- a true
    // statement that reads as a broken harness.
    assert(
      !after.includes("STALE-RESOLVED"),
      "a late resolve for an older render overwrote the current text: " +
        JSON.stringify(after) +
        ". The wrong host is now named in a live security warning.",
    );
    assert(
      after.includes("NEWER-RESOLVED"),
      "the newest resolve did not land at all, so this check cannot observe " +
        "a stale one either; got " + JSON.stringify(after),
    );
  }

  // 5. A fill must not erase the interception label.
  {
    const btn = global.document.getElementById("btn-tab");
    assert(btn, "#btn-tab is gone");
    // The stub synthesises elements from ids and does NOT carry their markup
    // attributes, so without this the fill's attribute pass never touches the
    // button and the check cannot fail however broken the code is. Take the
    // marker from index.html rather than typing it, so the day the markup
    // renames it this asserts instead of quietly going vacuous.
    // Scoped to the button's OWN tag. Unanchored, the window could run past
    // `>` and pick up a later element's marker, and the guard below would
    // then be false while still reading as true.
    const btnTag = (html.match(/<button[^>]*id="btn-tab"[^>]*>/) || [])[0] || "";
    const MARKER = (btnTag.match(/data-msg-aria-label="([a-z0-9.]+)"/) || [])[1];
    assert(
      MARKER,
      "#btn-tab no longer carries data-msg-aria-label in index.html; this " +
        "check was built on it competing with the runtime label",
    );
    btn.setAttribute("data-msg-aria-label", MARKER);
    // Created BEFORE the fill and never written to by this test, so its value
    // afterwards can only have come from the applier.
    const witness = global.document.createElement("button");
    witness.setAttribute("data-msg-aria-label", MARKER);
    global.window.__rb_event({
      event: "tab_status",
      data: { tls: "intercepted", profile: "persistent" },
    });
    await flush();
    const armed = btn.getAttribute("aria-label") || "";
    // EQUALITY against the fill's own value, not a word match.
    //
    // `/intercept/i` could not tell a localized label from an untranslated
    // English one: the English literal in `applyTabButtonLabel` contains the
    // word, and so does the synthetic value "GEN3 chrome-js-tab-aria-
    // intercepted". Two mutations proved it blind -- hardcoding the English
    // literals, and emptying `localeJsStrings` so EVERY JS string in the
    // chrome stays English in every locale -- and the gate stayed green
    // through both. The real en-XA value is accented text containing no
    // ASCII "intercept" at all.
    assert(
      armed === "GEN3 chrome-js-tab-aria-intercepted",
      "the tab button is not carrying the LOCALIZED interception label " +
        "before the fill under test; got " +
        JSON.stringify(armed),
    );
    global.window.__rb_event({
      event: "ui_locale_fill",
      data: snapshot(900, "GEN900"),
    });
    await flush();
    const after = btn.getAttribute("aria-label") || "";
    assert(
      after === "GEN900 chrome-js-tab-aria-intercepted",
      "after a locale fill the tab button is not carrying the localized " +
        "interception announcement; got " +
        JSON.stringify(after) +
        ". After a dismissal that label is the only trace a screen reader has.",
    );
    // A POSITIVE WITNESS, and the third attempt at one.
    //
    // The assertion above only proves something if the fill actually ran. Two
    // earlier versions of this check did not establish that: one read
    // `btn.title`, which the button does not have, and the other counted
    // `querySelectorAll("[data-msg-aria-label]")`, which is non-zero because
    // this very test sets that attribute on `btn` a few lines up. An
    // in-memory mutation that skipped the entire GEN900 fill still passed.
    //
    // So: a separate element, carrying the SAME marker, which this test does
    // not touch afterwards. If the fill ran, it holds the fill's own string.
    // If it did not, it holds nothing and this fails -- which is the only
    // thing that makes the label assertion above mean anything.
    assert(
      witness.getAttribute("aria-label") === "GEN900 " + MARKER.replace(/\./g, "-"),
      "the GEN900 fill did not reach a marked element, so the label check " +
        "above proves nothing; witness aria-label=" +
        JSON.stringify(witness.getAttribute("aria-label")),
    );
  }

  console.log("  ok  a complete snapshot applies");
  console.log("  ok  a stale generation is refused");
  console.log("  ok  an incomplete snapshot is refused whole, generation kept");
  console.log("  ok  a late resolve does not overwrite a newer write");
  console.log("  ok  a locale fill preserves the interception label");
  console.log("\nI18N FILL UI OK");
}

main().catch((e) => {
  console.error("  FAIL " + e.message);
  console.error("\nI18N FILL GATE FAILED");
  process.exit(1);
});
