// TLS interception: the surfaces that report it, now that there is no banner.
//
// WHY THIS FILE EXISTS. Interception used to be announced by a full-width
// banner, `#tls-warning`. That banner asserted decryption in prose, across the
// whole window, without showing the certificate it reasoned from -- so every
// `classify_issuer` collision was the browser stating something untrue about
// the user's connection, and no lexical rule removes them all ("Norton Rose
// Fulbright SSL Issuing CA" matches the `norton` hint, and narrowing the hints
// far enough to miss it also switched the verdict off for the antivirus roots
// the hints exist to catch). The banner was removed; the verdict now lives
// where its evidence lives.
//
// Removing it left THREE surfaces carrying the whole feature, and a survey at
// the time found that not one of them had a test:
//
//   1. `#btn-tab.is-intercepted`   -- the red mark, the only ambient signal
//   2. the pill's accessible name  -- the only signal a screen reader gets
//   3. tab-tls-desc / tab-safety-desc / tab-issuer-desc, in the panel
//
// Only the accessible name was covered, incidentally, by i18n-fill-gate.js
// check 5 -- which is about locale fills, not about this wiring. So deleting
// the banner would have left interception with no visible tested surface at
// all, and the whole suite would still have gone green. That is the defect
// class this file pins.
//
// EVERY TEXT ASSERTION COMPARES AGAINST THE CATALOG, not against a phrase
// written into this file. Asserting `/intercept/i` would pass when the wiring
// picked the wrong key, because several of these strings share vocabulary --
// the exact mistake i18n-fill-gate.js check 5 was caught making. Reading
// en.ftl and asserting equality with the value of the key that SHOULD have
// been chosen tests the selection and survives a copy edit.
//
// Run: node scripts/interception-ui-gate.js
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

// ---- the catalog, as the source of truth for every expected string --------
// `{" "}` is Fluent's way of writing a significant trailing space; the runtime
// resolves it, so this must too or the issuer prefix would never match.
const CATALOG = (() => {
  const out = {};
  const text = fs.readFileSync(
    path.join(chromeDir, "i18n/locales/en.ftl"),
    "utf8",
  );
  for (const line of text.split("\n")) {
    const m = /^([a-z0-9-]+) = (.*)$/.exec(line);
    if (m) out[m[1]] = m[2].replace(/\{" "\}/g, " ");
  }
  return out;
})();
function msg(key) {
  const value = CATALOG[key];
  if (value === undefined) {
    throw new Error(
      "the catalog has no key " +
        key +
        "; this gate asserts against en.ftl, so a renamed key is a real " +
        "failure and not a harness problem",
    );
  }
  return value;
}

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
new Function(chromeJs)();

const fire = (event, data) => global.window.__rb_event({ event, data });

// ---- driving a real locale fill -------------------------------------------
// The applier refuses an INCOMPLETE snapshot whole, so the snapshot has to
// carry every marker key in the document. They are scraped rather than
// listed, the same way i18n-fill-gate.js does it, so adding a marker to the
// markup cannot quietly make this gate's fills start being rejected -- which
// would turn the selection check below green by never filling anything.
const MARKER_KEYS = [
  ...new Set(
    [
      ...fs
        .readFileSync(path.join(chromeDir, "index.html"), "utf8")
        .matchAll(/data-msg(?:-[a-z-]+)?="([a-z0-9.]+)"/g),
    ].map((m) => m[1].replace(/\./g, "-")),
  ),
];
// Rendered from JS, so they carry no marker and the scrape cannot see them.
// These are exactly the strings this gate is about.
const JS_KEYS = [
  "chrome-js-tab-aria-intercepted",
  "chrome-js-tab-aria-plain",
  "chrome-js-tls-intercepted",
  "chrome-js-tls-normal",
  "chrome-js-tls-not-tls",
  "chrome-js-tls-unknown",
  "chrome-js-tls-unreadable",
  "chrome-js-safety-intercepted",
  "chrome-js-safety-insecure",
  "chrome-js-safety-secure",
  "chrome-js-safety-unconfirmed",
  "chrome-js-safety-unreadable",
  "chrome-js-issuer-prefix",
  "chrome-js-issuer-none",
];
let generation = 1;
function fillLocale(tag) {
  const messages = {};
  for (const k of MARKER_KEYS) messages[k] = tag + " " + k;
  for (const k of JS_KEYS) messages[k] = tag + " " + k;
  generation += 1;
  // `locale` must not be "en": chrome.js keeps localeJsStrings empty for
  // English, so an "en" snapshot would leave every i18nText on its fallback
  // and the selection assertions would be testing nothing.
  fire("ui_locale_fill", { generation, locale: "en-XA", messages });
  const probe = global.$("btn-tab").getAttribute("aria-label") || "";
  if (!probe.startsWith(tag + " ")) {
    throw new Error(
      "the locale fill was refused, so nothing below tests key selection " +
        "(probe=" +
        JSON.stringify(probe) +
        "). A snapshot is refused whole when it is missing a marker key.",
    );
  }
}

// The shape `AppState::active_tab_status` emits. `tls` and `tls_issuer` are
// the fields under test; everything else is the ordinary steady state.
const TAB_STATUS = {
  freeze_phase: "loaded",
  freeze_enforcement: "inactive",
  profile: "persistent",
  tls: "normal",
  tls_issuer: null,
  page_insecure: false,
  freeze_enforced: true,
  network_blocking_supported: true,
  ledger_counts_blocked: true,
  interception: "registered",
  script_setting: "applied",
  smartscreen_off: "applied",
  tracking_prevention: "strict",
  navigation_tracking: "applied",
  autofill_off: "applied",
  ephemeral_confirmed: "applied",
  hardened_environment: "applied",
  content_script_registered: "applied",
  session_lock_registered: "applied",
  tunnel: "applied",
  pending_save: null,
  insecure_pending: null,
  insecure_pending_host: null,
};
const status = (over) => Object.assign({}, TAB_STATUS, over || {});

const pill = () => global.$("btn-tab");
const marked = () => pill().classList.contains("is-intercepted");
const label = () => String(pill().getAttribute("aria-label") || "");
const textOf = (id) => String(global.$(id).textContent || "");

check("an intercepted connection marks the Tab Activity pill", () => {
  fire("tab_status", status({ tls: "intercepted" }));
  assert(
    marked(),
    "#btn-tab did not get .is-intercepted. With the banner gone this mark " +
      "is the ONLY ambient sign that traffic is being decrypted -- without " +
      "it a user who never opens the panel is told nothing at all.",
  );
  assert(
    label() === msg("chrome-js-tab-aria-intercepted"),
    "the pill's accessible name does not carry the interception condition. " +
      "Colour is nothing to a screen reader and little to a red/green " +
      "deficit, so for those users this label is the whole signal. want " +
      JSON.stringify(msg("chrome-js-tab-aria-intercepted")) +
      ", got " +
      JSON.stringify(label()),
  );
});

check("a normal connection clears the mark and the announcement", () => {
  fire("tab_status", status({ tls: "intercepted" }));
  assert(marked(), "precondition: the mark is set");
  fire("tab_status", status({ tls: "normal" }));
  assert(
    !marked(),
    "the mark survived a return to a normal connection; it tracks the " +
      "connection, so a stale mark is a permanent false alarm",
  );
  assert(
    label() === msg("chrome-js-tab-aria-plain"),
    "the accessible name still announces interception on a normal " +
      "connection; got " +
      JSON.stringify(label()),
  );
});

check(
  "the panel states the verdict AND names the certificate behind it",
  () => {
    // The pairing is the point. The banner was removed precisely because it
    // made the claim without the evidence; if the issuer line ever stops
    // rendering, the panel becomes the banner and the removal bought nothing.
    //
    // WHAT THIS CHECK DOES AND DOES NOT PROVE. With no locale filled,
    // `i18nText(key, fallback)` returns the FALLBACK, so this compares the
    // English literal in chrome.js against en.ftl. That is worth holding --
    // the two drifting apart means the shipped English and the translated
    // English differ -- but it does NOT test which key the wiring chose:
    // swapping `chrome-js-tls-intercepted` for `chrome-js-tls-unknown` while
    // leaving the fallback alone left this green. Key SELECTION is tested by
    // the last check in this file, which drives a real fill.
    const issuer = "CN=Zscaler Intermediate Root CA (zscalertwo.net)";
    fire("tab_status", status({ tls: "intercepted", tls_issuer: issuer }));
    assert(
      textOf("tab-tls-desc") === msg("chrome-js-tls-intercepted"),
      "tab-tls-desc is not the intercepted verdict; got " +
        JSON.stringify(textOf("tab-tls-desc")),
    );
    assert(
      textOf("tab-safety-desc") === msg("chrome-js-safety-intercepted"),
      "tab-safety-desc is not the intercepted summary; got " +
        JSON.stringify(textOf("tab-safety-desc")),
    );
    assert(
      textOf("tab-issuer-desc") === msg("chrome-js-issuer-prefix") + issuer,
      "tab-issuer-desc must print the issuer verbatim next to the verdict; " +
        "want " +
        JSON.stringify(msg("chrome-js-issuer-prefix") + issuer) +
        ", got " +
        JSON.stringify(textOf("tab-issuer-desc")),
    );
  },
);

check(
  "a COLLIDING issuer is still shown, so a wrong verdict reads as wrong",
  () => {
    // The residual false positive that no lexical rule removes: a law firm's
    // internal CA whose name contains the `norton` hint. `classify_issuer`
    // calls it Intercepted and that is not going to change. What makes it
    // survivable is that the reader sees the name the browser reasoned from
    // and can judge it. Truncating or sanitizing this line would restore the
    // banner's defect inside the panel.
    const issuer =
      "CN=Norton Rose Fulbright SSL Issuing CA, O=Norton Rose Fulbright";
    fire("tab_status", status({ tls: "intercepted", tls_issuer: issuer }));
    assert(
      textOf("tab-issuer-desc").includes(issuer),
      "the issuer was altered before display, so the user cannot check the " +
        "verdict against the evidence; got " +
        JSON.stringify(textOf("tab-issuer-desc")),
    );
  },
);

check(
  "interception raises no banner and claims none of the strip",
  async () => {
    assert(
      global.document.getElementById("tls-warning") === null,
      "#tls-warning is back in the markup. It was removed deliberately: a " +
        "full-width banner asserts decryption without showing the certificate " +
        "it reasoned from. Re-adding it needs the rationale at the top of this " +
        "file answered, not just this assertion deleted.",
    );
    // MEASURED IN BOTH STATES, not "did becoming intercepted send anything".
    // The first draft of this check fired tab_status and asserted over the
    // set_chrome_insets calls that followed -- but the correct behaviour is
    // to send NONE, so the assertion ran over an empty array and was true no
    // matter what the strip did. Vacuous. Interception no longer triggers a
    // sync at all, so the height has to be sampled through a surface that
    // does trigger one, once in each state, and compared.
    const stripNow = async () => {
      fire("find_open", {});
      await flush();
      global.rbCalls.length = 0;
      global.$("find-close")._fire("click");
      await flush();
      const sent = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
      assert(sent.length > 0, "harness: closing the find bar moved no insets");
      return sent[sent.length - 1].args.top;
    };

    fire("tab_status", status({ tls: "normal" }));
    const base = await stripNow();
    fire("tab_status", status({ tls: "intercepted" }));
    const while_intercepted = await stripNow();
    // A strip grown for a banner that no longer exists is a blank band above
    // the page: the grey-band defect in its third costume.
    assert(
      while_intercepted === base,
      "the strip is taller while intercepted (" +
        while_intercepted +
        " vs " +
        base +
        "); there is no banner to make room for, so that space is an empty band",
    );
  },
);

check("unknown is a calm line, not a verdict", () => {
  // Unknown is COMMON -- most issuer strings are not in either hint list.
  // Marking the pill for it would make the red mark meaningless, which is
  // the whole reason the mark can be trusted when it does appear.
  fire("tab_status", status({ tls: "unknown" }));
  assert(
    !marked(),
    "an unrecognized issuer marked the pill as intercepted. Unknown means " +
      "the browser did not recognize the issuer, not that anyone is reading " +
      "the traffic; marking it trains the user to ignore the mark.",
  );
  assert(
    textOf("tab-tls-desc") === msg("chrome-js-tls-unknown"),
    "tab-tls-desc is not the unknown line; got " +
      JSON.stringify(textOf("tab-tls-desc")),
  );
});

check("unreadable does not accuse the certificate on EITHER line", () => {
  // Two lines, two ternaries, and only one of them was ever split.
  // tab-safety-desc tested page_insecure -> intercepted -> "normal" -> else,
  // with no unreadable arm -- so on WebView2, where st.tls is ALWAYS
  // "unreadable", every correctly-secured HTTPS page fell to
  // chrome-js-safety-unconfirmed and told the user its certificate could not
  // be confirmed. The most-seen security string on the primary platform,
  // accusing sites that had done nothing wrong.
  fire("tab_status", status({ tls: "unreadable" }));
  assert(
    textOf("tab-safety-desc") === msg("chrome-js-safety-unreadable"),
    "tab-safety-desc must answer for an unreadable chain with its OWN line, " +
      "not with the unconfirmed one. want " +
      JSON.stringify(msg("chrome-js-safety-unreadable")) +
      ", got " +
      JSON.stringify(textOf("tab-safety-desc")),
  );
  assert(
    msg("chrome-js-safety-unreadable") !== msg("chrome-js-safety-unconfirmed"),
    "the unreadable and unconfirmed safety strings have been collapsed; that " +
      "is the defect this check exists for",
  );
});

check("unreadable does not accuse the certificate", () => {
  // "unreadable" is NOT "unknown". Unknown is a fact about the certificate;
  // unreadable is a fact about the platform (WebView2 exposes no chain, on
  // every page, always). They were one branch once, which told every Windows
  // user their ordinary public certificate had an unrecognized issuer.
  fire("tab_status", status({ tls: "unreadable" }));
  assert(
    !marked(),
    "a platform with no readable chain marked the pill as intercepted",
  );
  assert(
    textOf("tab-tls-desc") === msg("chrome-js-tls-unreadable"),
    "tab-tls-desc is not the unreadable line; got " +
      JSON.stringify(textOf("tab-tls-desc")),
  );
  assert(
    msg("chrome-js-tls-unreadable") !== msg("chrome-js-tls-unknown"),
    "the unreadable and unknown strings have been collapsed into one; that " +
      "tells every Windows user their certificate issuer is unrecognized",
  );
});

check(
  "no certificate to show says so, rather than showing a bare prefix",
  () => {
    fire("tab_status", status({ tls: "normal", tls_issuer: null }));
    assert(
      textOf("tab-issuer-desc") === msg("chrome-js-issuer-none"),
      "a page with no issuer must say so; got " +
        JSON.stringify(textOf("tab-issuer-desc")),
    );
  },
);

check("the verdict and the certificate are ADJACENT in the markup", () => {
  // The load-bearing claim of this whole design is that the reader sees the
  // claim and the evidence together. That is a property of DOCUMENT ORDER,
  // and nothing above tests it -- every other check reads elements by id, so
  // they would all stay green with the issuer moved to the bottom of the
  // panel. A compliance audit found exactly that drift: the comments said
  // "the verdict sits two lines above" while the STRONGER sentence,
  // #tab-tls-desc under "Connection", is two sections below the issuer.
  //
  // Asserted against the markup rather than the DOM because the harness has
  // no sibling traversal, and because this is a claim about index.html.
  const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  const a = html.indexOf('id="tab-safety-desc"');
  const b = html.indexOf('id="tab-issuer-desc"');
  assert(a !== -1 && b !== -1, "one of the two panel lines is gone");
  assert(
    a < b,
    "the certificate is rendered BEFORE the verdict it is evidence for",
  );
  const between = html.slice(a, b);
  assert(
    !between.includes("section-label"),
    "a new panel section was inserted between the verdict and the " +
      "certificate that produced it. They must stay adjacent: the banner was " +
      "removed precisely because it asserted decryption without showing the " +
      "certificate, and separating these two rebuilds that defect inside the " +
      "panel. Between them now: " +
      JSON.stringify(between.slice(0, 200)),
  );
  assert(
    (between.match(/\bid="/g) || []).length === 1,
    "another element was inserted between the verdict and the certificate; " +
      "between them now: " +
      JSON.stringify(between.slice(0, 200)),
  );
});

check("the sentence that stands ALONE carries its own qualifier", () => {
  // #tab-tls-desc lives under "Connection", two sections below the issuer
  // line, so unlike #tab-safety-desc it has no evidence beside it. It is also
  // the strongest sentence in the product -- it states decryption outright.
  //
  // The banner used to end with a qualifier naming the benign causes, and it
  // was deleted along with the banner, leaving the accusation without it. That
  // hurts the exact reader this design is for: showing a CA name only helps
  // someone who can interpret a CA name, while "this is common on work
  // networks and with some antivirus software" helps everyone, including the
  // reader looking at their own employer's root and not recognizing it.
  const QUALIFIER =
    "This is common on work networks and with some antivirus software.";
  assert(
    msg("chrome-js-tls-intercepted").endsWith(QUALIFIER),
    "the standalone interception sentence has lost its qualifier. It states " +
      "decryption as fact with no certificate beside it, so without a benign " +
      "explanation a false positive reads as an accusation the reader cannot " +
      "check. Expected it to end with " +
      JSON.stringify(QUALIFIER) +
      "; got " +
      JSON.stringify(msg("chrome-js-tls-intercepted")),
  );
  // And it must actually reach the element, not merely sit in the catalog.
  fire("tab_status", status({ tls: "intercepted" }));
  assert(
    textOf("tab-tls-desc").endsWith(QUALIFIER),
    "the qualifier is in the catalog but not in the rendered line; got " +
      JSON.stringify(textOf("tab-tls-desc")),
  );
});

// LAST, because it leaves a non-English locale filled and every check above
// compares against the English catalog.
check(
  "each surface selects the key that matches the verdict, not merely the right words",
  () => {
    // WHY A REAL FILL. Without one, `i18nText(key, fallback)` returns the
    // fallback, so the rendered string is the English literal sitting next to
    // the key in chrome.js -- and a check that compares it to the catalog
    // passes no matter which key the wiring named. Proven: swapping
    // `chrome-js-tls-intercepted` for `chrome-js-tls-unknown` in the ternary,
    // leaving the fallback untouched, left every other check in this file
    // green. That is the same blindness i18n-fill-gate.js check 5 was caught
    // with, arriving by a different route.
    //
    // A fill makes each key resolve to a value that CONTAINS the key, so the
    // assertion below can only pass if the intended key was the one asked for.
    // It also proves these strings are translatable at all: before this, a
    // build where the whole panel stayed English in every locale passed.
    const issuer = "CN=Zscaler Intermediate Root CA (zscalertwo.net)";
    fillLocale("LOC");
    fire("tab_status", status({ tls: "intercepted", tls_issuer: issuer }));

    const want = (key) => "LOC " + key;
    assert(
      textOf("tab-tls-desc") === want("chrome-js-tls-intercepted"),
      "tab-tls-desc resolved the wrong key; want " +
        JSON.stringify(want("chrome-js-tls-intercepted")) +
        ", got " +
        JSON.stringify(textOf("tab-tls-desc")),
    );
    assert(
      textOf("tab-safety-desc") === want("chrome-js-safety-intercepted"),
      "tab-safety-desc resolved the wrong key; want " +
        JSON.stringify(want("chrome-js-safety-intercepted")) +
        ", got " +
        JSON.stringify(textOf("tab-safety-desc")),
    );
    assert(
      textOf("tab-issuer-desc") === want("chrome-js-issuer-prefix") + issuer,
      "tab-issuer-desc resolved the wrong key, or stopped appending the " +
        "issuer; want " +
        JSON.stringify(want("chrome-js-issuer-prefix") + issuer) +
        ", got " +
        JSON.stringify(textOf("tab-issuer-desc")),
    );
    assert(
      label() === want("chrome-js-tab-aria-intercepted"),
      "the pill's accessible name resolved the wrong key; want " +
        JSON.stringify(want("chrome-js-tab-aria-intercepted")) +
        ", got " +
        JSON.stringify(label()),
    );

    // And the other verdicts, so a wiring that answers "intercepted" to
    // everything cannot pass by only ever being asked the one question.
    fire("tab_status", status({ tls: "unknown" }));
    assert(
      textOf("tab-tls-desc") === want("chrome-js-tls-unknown"),
      "tab-tls-desc resolved the wrong key for unknown; got " +
        JSON.stringify(textOf("tab-tls-desc")),
    );
    fire("tab_status", status({ tls: "unreadable" }));
    assert(
      textOf("tab-tls-desc") === want("chrome-js-tls-unreadable"),
      "tab-tls-desc resolved the wrong key for unreadable; got " +
        JSON.stringify(textOf("tab-tls-desc")),
    );
    // AND the safety line, which is the one a Windows user reads on every
    // page. Without this assertion, swapping its key for the unconfirmed
    // one was invisible: the check above it compares against the catalog
    // with no fill, so `i18nText` returns the fallback literal and a
    // key-only change renders identically. A mutation proved that.
    assert(
      textOf("tab-safety-desc") === want("chrome-js-safety-unreadable"),
      "tab-safety-desc resolved the wrong key for unreadable; got " +
        JSON.stringify(textOf("tab-safety-desc")) +
        ". Answering with the UNCONFIRMED string here tells every Windows " +
        "user their certificate could not be confirmed on every page.",
    );
    fire("tab_status", status({ tls: "normal" }));
    assert(
      label() === want("chrome-js-tab-aria-plain"),
      "the pill's accessible name resolved the wrong key once the " +
        "connection went back to normal; got " +
        JSON.stringify(label()),
    );
  },
);

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (err) {
      failures.push(name + ": " + err.message);
      console.log("  FAIL " + name + ": " + err.message);
    }
  }
  if (failures.length) {
    console.error("\nINTERCEPTION UI GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log("\nINTERCEPTION UI OK");
})();
