// Inline credential autofill -- the save banner and the fill affordance.
// Behavioural checks run against the DOM harness so chrome.js is EXECUTED
// rather than parsed, the same discipline site-forget-gate.js and
// vault-import-ui-gate.js use for their own security-sensitive controls.
//
// WHY THIS EXISTS. This is the first feature in this codebase that puts a
// PASSWORD in Rust memory ahead of an explicit user action (Save), and the
// first that writes INTO a content webview from the chrome. Two failure
// modes matter more here than in an ordinary panel: a banner or a fill that
// fires without the user having asked for it, and a control left silently
// broken (stuck disabled, or calling the wrong command) because nothing
// exercised it end to end.
//
// Run: node scripts/credential-ui-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
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

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// Exactly the shape `AppState::active_tab_status` emits, with `origin`,
// `content_script_registered` and `pending_save` varied per check. Pushed
// through the REAL entry point (the `tab_status` event) rather than calling
// an internal renderer directly.
function statusEvent(origin, overrides) {
  global.window.__rb_event({
    event: "tab_status",
    data: Object.assign(
      {
        freeze_phase: "loaded",
        freeze_enforcement: "inactive",
        profile: "persistent",
        origin,
        tls: "normal",
        freeze_enforced: true,
        network_blocking_supported: true,
        ledger_counts_blocked: true,
        blocked_total: 0,
        interception: "registered",
        script_setting: "applied",
        smartscreen_off: "applied",
        tracking_prevention: "strict",
        navigation_tracking: "applied",
        autofill_off: "applied",
        ephemeral_confirmed: "applied",
        hardened_environment: "applied",
        content_script_registered: "applied",
        pending_save: null,
      },
      overrides || {},
    ),
  });
}

// Opening the panel for the first time triggers `refreshTabPanel`'s OWN
// `rb("tab_status")` round trip (its onOpen hook). Left unflushed, that
// promise resolves LATER -- inside some later check's own `flush()` -- with
// whatever the harness defaults `tab_status` to (`{}`, no `origin`), and
// re-runs `refreshAutofillOffer` against that empty payload, clobbering
// whatever the later check had just set up. Draining it here, once, keeps
// every later check looking at only the state IT caused.
async function openTabPanel() {
  if (global.$("tab-panel").hidden) {
    global.$("btn-tab")._fire("click");
    await flush();
  }
}

// The Passwords section, isolated the same way site-forget-gate.js isolates
// Cookies -- so a check here cannot accidentally match the destructive
// warning or ledger markup that live in the same panel.
const pwStart = html.search(/<span class="section-label"[^>]*>Passwords<\/span>/);
const pwEnd = html.search(/<h2[^>]*>Hosts this tab has contacted<\/h2>/);
const PW_SECTION = html.slice(pwStart, pwEnd);

check("the Passwords section exists between Cookies and the ledger", () => {
  const cookiesAt = html.search(/<span class="section-label"[^>]*>Cookies<\/span>/);
  assert(cookiesAt !== -1, "the Cookies section-label is missing");
  assert(pwStart !== -1, "the Passwords section-label is missing");
  assert(pwEnd !== -1, "the ledger heading it must precede is missing");
  assert(
    cookiesAt < pwStart && pwStart < pwEnd,
    "the Passwords section is out of order",
  );
});

check("the fill button starts disabled in static markup", () => {
  assert(
    /id="btn-autofill-fill"[^>]*\bdisabled\b/.test(PW_SECTION),
    "#btn-autofill-fill must start disabled -- it must never be clickable " +
      "before a real offer has been confirmed to exist",
  );
});

check(
  "no site: the Passwords section says so and the button stays disabled",
  async () => {
    await openTabPanel();
    statusEvent(null);
    assert(
      global.$("tab-autofill-desc").dataset.state === "no-site",
      "a page with no origin must report the no-site reason; got " +
        JSON.stringify(global.$("tab-autofill-desc").dataset.state),
    );
    assert(
      global.$("btn-autofill-fill").disabled === true,
      "the fill button must be disabled when the tab has no origin",
    );
  },
);

check(
  "content script not registered: autofill is reported unavailable",
  async () => {
    await openTabPanel();
    global.rbCalls.length = 0;
    statusEvent("example.com", { content_script_registered: "failed" });
    assert(
      global.$("tab-autofill-desc").dataset.state === "unavailable",
      "an unregistered content script must report the unavailable reason, " +
        "not silently the no-match one; got " +
        JSON.stringify(global.$("tab-autofill-desc").dataset.state),
    );
    assert(
      global.$("btn-autofill-fill").disabled === true,
      "the fill button must stay disabled when the engine never confirmed " +
        "the content script registered",
    );
    assert(
      !global.rbCalls.some((c) => c.cmd === "cred_autofill_offer_get"),
      "the vault should not even be asked for an offer on a tab where " +
        "autofill cannot possibly work",
    );
  },
);

// WHY THESE FOUR CHECKS REPLACED ONE.
//
// This gate used to assert that an empty offer list "must report the no-match
// reason" -- which enshrined the bug a tester found. An empty list meant four
// different things (no origin, no vault, a LOCKED vault, or a completed search
// that matched nothing) and the chrome rendered all four as "No saved password
// for this site." For three of them that is a claim it has no basis for: with
// the vault shut, nothing was searched. The host now says which happened
// (ipc.rs `autofill_offer_reason`), and each reason gets its own check here.
//
// The TEXT is asserted, not just `dataset.state`. A state attribute nobody
// reads could be correct while the sentence on screen stayed wrong, and the
// sentence is the whole defect.
const REASON_CASES = [
  {
    reason: "locked",
    // THE TESTER'S BUG.
    must: /unlock the vault/i,
    mustNot: /no saved password for this site/i,
    why: "a locked vault has not looked, so it must not report a result",
  },
  {
    reason: "no-vault",
    must: /no vault yet/i,
    mustNot: /unlock the vault/i,
    why: "with no vault created, telling the user to unlock one sends them " +
      "to a control that cannot do what the text says",
  },
  {
    reason: "no-site",
    must: /no site to check/i,
    mustNot: /no saved password for this site/i,
    why: "the host had no origin, so no lookup ran",
  },
  {
    reason: "no-match",
    must: /no saved password for this site/i,
    mustNot: /unlock the vault/i,
    why: "the only reason that may assert a search happened and found nothing",
  },
];

for (const c of REASON_CASES) {
  check(
    `reason "${c.reason}": the Passwords section says the right thing`,
    async () => {
      await openTabPanel();
      global.rbResolve["cred_autofill_offer_get"] = {
        items: [],
        reason: c.reason,
      };
      statusEvent("example.com", { content_script_registered: "applied" });
      await flush();
      const desc = global.$("tab-autofill-desc");
      assert(
        desc.dataset.state === c.reason,
        `reason ${c.reason} must reach the surface as its own state; got ` +
          JSON.stringify(desc.dataset.state),
      );
      assert(
        c.must.test(desc.textContent),
        `${c.why}: expected ${c.must} but the user is shown ` +
          JSON.stringify(desc.textContent),
      );
      assert(
        !c.mustNot.test(desc.textContent),
        `${c.why}: must not say ${c.mustNot}, but does: ` +
          JSON.stringify(desc.textContent),
      );
      assert(
        global.$("btn-autofill-fill").disabled === true,
        "the fill button must stay disabled when there is nothing to fill",
      );
    },
  );
}

check(
  "a reply with no reason at all still degrades to no-match",
  async () => {
    // DELIBERATELY SUPPORTED. The chrome assumed no-match unconditionally
    // before this change, so a host that does not send a reason must land on
    // the old behaviour rather than on a blank line or a thrown error.
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = { items: [] };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    const desc = global.$("tab-autofill-desc");
    assert(
      desc.dataset.state === "no-match",
      "a reasonless reply must fall back to no-match; got " +
        JSON.stringify(desc.dataset.state),
    );
    assert(
      /no saved password/i.test(desc.textContent),
      "the fallback must still render a sentence, got " +
        JSON.stringify(desc.textContent),
    );
  },
);

// The last three of these are not hypothetical. With an ordinary object
// literal, "constructor" rendered "[object Object]" with state "constructor",
// "toString" rendered "[object Undefined]", and "__proto__" threw and landed
// on check-failed -- none of them degrading to no-match. A reason arrives over
// IPC as a string, so the table it indexes must inherit nothing.
for (const bogus of [
  "something-this-build-has-never-heard-of",
  "constructor",
  "toString",
  "__proto__",
]) {
  check(
    `an unknown reason (${bogus}) degrades to no-match, not to something invented`,
    async () => {
      await openTabPanel();
      global.rbResolve["cred_autofill_offer_get"] = { items: [], reason: bogus };
      statusEvent("example.com", { content_script_registered: "applied" });
      await flush();
      const desc = global.$("tab-autofill-desc");
      assert(
        desc.dataset.state === "no-match",
        `reason ${bogus} must not become a state of its own; got ` +
          JSON.stringify(desc.dataset.state),
      );
      // POSITIVE assertion, not just the absence of the code. Without this, a
      // fallback that returned an empty string passed the whole gate.
      assert(
        /^No saved password for this site\.$/.test(desc.textContent),
        "the fallback must render the no-match sentence, got " +
          JSON.stringify(desc.textContent),
      );
      assert(
        !new RegExp(bogus.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(
          desc.textContent,
        ),
        "a reason code must never be shown to the user as text: " +
          JSON.stringify(desc.textContent),
      );
    },
  );
}

check(
  "a fill that returns AFTER a lock does not re-enable the button",
  async () => {
    // The click handler's `finally` used to set `disabled = false`
    // unconditionally. The vault can lock while a fill is in flight, and that
    // blanket re-enable put a live-looking Fill control back underneath a
    // panel reading "Unlock the vault".
    global.rbResolve["vault_status"] = { exists: true, unlocked: true };
    global.$("btn-vault")._fire("click");
    await flush();
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-1", site: "Example", username: "alice" }],
      reason: "match",
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    assert(
      global.$("btn-autofill-fill").disabled === false,
      "setup failed: the offer should be live before the fill starts",
    );

    let releaseFill;
    global.rbResolve["cred_autofill_fill"] = new Promise((r) => {
      releaseFill = r;
    });
    global.$("btn-autofill-fill")._fire("click");
    await flush();

    global.rbResolve["cred_autofill_offer_get"] = { items: [], reason: "locked" };
    global.window.__rb_event({ event: "vault_locked", data: {} });
    await flush();
    assert(
      global.$("btn-autofill-fill").disabled === true,
      "setup failed: the lock should have disabled the button",
    );

    releaseFill({});
    await flush();
    assert(
      global.$("btn-autofill-fill").disabled === true,
      "the held fill re-enabled the button after the vault locked",
    );
    assert(
      global.$("tab-autofill-desc").dataset.state === "locked",
      "the panel must still report the vault as locked; got " +
        JSON.stringify(global.$("tab-autofill-desc").dataset.state),
    );
    delete global.rbResolve["cred_autofill_fill"];
    delete global.rbResolve["vault_status"];
    global.rbResolve["cred_autofill_offer_get"] = { items: [], reason: "no-match" };
  },
);

check(
  "a translation that lands after a lock cannot put the account name back",
  async () => {
    // `i18nSet` guards completions with a per-element token, but the
    // empty-offer branch writes textContent directly, which left the previous
    // token valid. In a non-English locale a translation requested for a LIVE
    // OFFER landed after the vault had locked and restored the account name --
    // in the description AND on the button -- under a panel saying "Unlock the
    // vault". Only reachable with a non-en locale, which is why no earlier
    // check saw it.
    global.window.__rb_event({
      event: "ui_locale_fill",
      data: { locale: "xx", generation: 1, messages: {} },
    });
    await flush();
    global.rbResolve["vault_status"] = { exists: true, unlocked: true };
    global.$("btn-vault")._fire("click");
    await flush();
    await openTabPanel();

    let releaseI18n;
    global.rbResolve["i18n_resolve"] = new Promise((r) => {
      releaseI18n = r;
    });
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-1", site: "Example", username: "alice" }],
      reason: "match",
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();

    global.rbResolve["cred_autofill_offer_get"] = { items: [], reason: "locked" };
    global.window.__rb_event({ event: "vault_locked", data: {} });
    await flush();

    releaseI18n({ text: "A saved password for alice is available." });
    await flush();

    const desc = global.$("tab-autofill-desc");
    assert(
      !/alice/.test(desc.textContent),
      "a late translation restored the account name after the lock: " +
        JSON.stringify(desc.textContent),
    );
    assert(
      !/alice/.test(global.$("btn-autofill-fill").textContent),
      "a late translation restored the account name on the button: " +
        JSON.stringify(global.$("btn-autofill-fill").textContent),
    );
    assert(
      !/alice/.test(global.$("btn-fill").title || ""),
      "a late translation restored the account name in the toolbar tooltip: " +
        JSON.stringify(global.$("btn-fill").title),
    );
    assert(
      desc.dataset.state === "locked",
      "the panel must still report the vault as locked; got " +
        JSON.stringify(desc.dataset.state),
    );
    delete global.rbResolve["i18n_resolve"];
    delete global.rbResolve["vault_status"];
    global.window.__rb_event({
      event: "ui_locale_fill",
      data: { locale: "en", generation: 2, messages: {} },
    });
    await flush();
    global.rbResolve["cred_autofill_offer_get"] = { items: [], reason: "no-match" };
  },
);

check(
  "locking the vault retracts a live offer BEFORE the replacement reply lands",
  async () => {
    // THE INTERVAL, not the steady state. `refreshAutofillOffer` clears the
    // offer in memory and then waits for `cred_autofill_offer_get`. Until this
    // check existed, nothing repainted in between, so locking the vault left
    // "Fill password for alice" in the panel with its button ENABLED and the
    // toolbar button lit for as long as the lookup took. Reproduced in a real
    // browser by holding the reply and screenshotting the gap.
    // The chrome has to BELIEVE the vault is open, or locking it changes
    // nothing and this check passes without exercising anything. Opening the
    // vault panel runs `refreshVault`, which is the real path to that state.
    global.rbResolve["vault_status"] = { exists: true, unlocked: true };
    global.$("btn-vault")._fire("click");
    await flush();
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-1", site: "Example", username: "alice" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    assert(
      global.$("btn-autofill-fill").disabled === false,
      "setup failed: the offer should be live before the vault locks",
    );

    // From here the lookup hangs. `Promise.resolve` adopts a pending promise,
    // so rb() never settles until this check says so.
    let release;
    global.rbResolve["cred_autofill_offer_get"] = new Promise((r) => {
      release = r;
    });
    global.window.__rb_event({ event: "vault_locked", data: {} });
    await flush();

    const desc = global.$("tab-autofill-desc");
    assert(
      desc.dataset.state !== "offer",
      "the offer survived the lock: the panel still asserts a saved password " +
        "is available while the vault is shut",
    );
    assert(
      global.$("btn-autofill-fill").disabled === true,
      "the fill button stayed ENABLED after the vault locked",
    );
    assert(
      !/alice/.test(desc.textContent),
      "the locked panel still names the account: " +
        JSON.stringify(desc.textContent),
    );
    const toolbar = global.$("btn-fill");
    assert(
      toolbar.hidden === true,
      "the toolbar fill button stayed on screen after the vault locked",
    );

    // Now let the truthful answer arrive.
    release({ items: [], reason: "locked" });
    await flush();
    assert(
      global.$("tab-autofill-desc").dataset.state === "locked",
      "after the reply the panel must say the vault is locked; got " +
        JSON.stringify(global.$("tab-autofill-desc").dataset.state),
    );
    global.rbResolve["cred_autofill_offer_get"] = { items: [], reason: "no-match" };
    delete global.rbResolve["vault_status"];
  },
);

check(
  "an offer describes itself in one sentence, not two glued together",
  async () => {
    // A SEPARATE DEFECT IN THE SAME ROW, found while fixing the locked-vault
    // message. Two drafts of this sentence were concatenated in the English
    // fallback, and `i18nSet` writes that argument to textContent
    // synchronously -- and on the default "en" locale writes nothing else. So
    // every English user with a saved password read
    // "A saved password for aliceSaved password available for ".
    // The catalog entry was right the whole time; only the fallback was wrong,
    // and nothing asserted the sentence, which is why it shipped.
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-1", site: "Example", username: "alice" }],
      reason: "match",
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    const text = global.$("tab-autofill-desc").textContent;
    assert(
      /^A saved password for alice is available\.$/.test(text),
      "the offer line must be one finished sentence, got " +
        JSON.stringify(text),
    );
    assert(
      !/aliceSaved|available for\s*$/.test(text),
      "two phrasings were concatenated instead of one being chosen: " +
        JSON.stringify(text),
    );
  },
);

check(
  "a match: the button is enabled and names the account it would fill",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-1", site: "Example", username: "alice" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    assert(
      global.$("btn-autofill-fill").disabled === false,
      "the fill button must enable once a real match is confirmed",
    );
    assert(
      /alice/.test(global.$("btn-autofill-fill").textContent),
      "the button must name the account it would fill, not a bare " +
        '"Fill saved password" that leaves the user guessing which one',
    );
  },
);

check(
  "clicking Fill calls cred_autofill_fill with that credential's id, exactly once",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-7", site: "Example", username: "bob" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    global.rbCalls.length = 0;
    global.$("btn-autofill-fill")._fire("click");
    await flush();
    const calls = global.rbCalls.filter((c) => c.cmd === "cred_autofill_fill");
    assert(
      calls.length === 1,
      "expected exactly one cred_autofill_fill call, got " + calls.length,
    );
    assert(
      calls[0].args && calls[0].args.id === "cred-7",
      "cred_autofill_fill must be called with the offered credential's id, " +
        "got " +
        JSON.stringify(calls[0] && calls[0].args),
    );
  },
);

check(
  "a refused fill (origin_mismatch) re-enables the button rather than leaving it stuck",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-9", site: "Example", username: "carol" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    global.rbReject = "origin_mismatch";
    global.$("btn-autofill-fill")._fire("click");
    await flush();
    global.rbReject = null;
    assert(
      global.$("btn-autofill-fill").disabled === false,
      "a refused fill must not leave the button permanently disabled -- the " +
        "offer is still just as valid as it was before the click",
    );
  },
);

// THE TOOLBAR FILL BUTTON.
//
// Every check above drives #btn-autofill-fill, the row inside Tab Activity.
// That control worked from the day it shipped and nobody used it, because it
// sits under a "Passwords" heading below Save-as-PDF inside a panel named
// after something else -- the field report was that users could see their
// credentials and were copying and pasting them by hand. #btn-fill is the same
// offer, on the toolbar, where the password field is.
//
// It is gated HERE rather than in toolbar-gate.js because what it must do is
// an autofill property, not a layout one: appear only for a real offer, and
// -- the part that actually bites -- STOP appearing the moment that offer
// stops being valid.

check(
  "a match reveals the toolbar fill button and names the account",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-11", site: "Example", username: "erin" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    assert(
      global.$("btn-fill").hidden === false,
      "the toolbar fill button must appear once this site has a saved password " +
        "-- hidden, it is the panel row all over again",
    );
    // Asserted through `classList`, not `className`: the harness keeps
    // classes in a Set and leaves `className` empty on elements that came
    // from the markup, so a regex over `className` would compare "" to ""
    // and pass with the feature removed -- the same vacuous shape the
    // credential-list check was caught in.
    //
    // LIT, not just present. This is the defect actually reported from
    // hardware: the button was on the toolbar and looked exactly like the
    // inert controls beside it, so "it appeared" and "nothing lit up" were
    // both true at once. `.is-active` is this chrome's green live state.
    assert(
      global.$("btn-fill").classList.contains("is-active"),
      "the fill button must LIGHT UP, not merely appear -- grey among grey " +
        "neighbours reads as a control that was always there",
    );
    assert(
      /erin/.test(global.$("btn-fill").title),
      "the toolbar button's tooltip must name the account it would fill, since " +
        "the button itself is a key glyph and a label with no username in it",
    );
  },
);

check(
  "clicking the toolbar button fills that credential, exactly once",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-13", site: "Example", username: "frank" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    global.rbCalls.length = 0;
    global.$("btn-fill")._fire("click");
    await flush();
    const calls = global.rbCalls.filter((c) => c.cmd === "cred_autofill_fill");
    assert(
      calls.length === 1,
      "expected exactly one cred_autofill_fill call from the toolbar button, " +
        "got " +
        calls.length,
    );
    assert(
      calls[0].args && calls[0].args.id === "cred-13",
      "the toolbar button must fill the offered credential, got " +
        JSON.stringify(calls[0] && calls[0].args),
    );
  },
);

// The defect worth having a gate for. A fill button left on screen after the
// offer stops being valid is worse than never showing one: it offers to type a
// password into a site the password does not belong to.
check(
  "navigating to a site with no saved password retracts the button",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = {
      items: [{ id: "cred-15", site: "Example", username: "grace" }],
    };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    assert(
      global.$("btn-fill").hidden === false,
      "precondition failed: the button should be showing before this navigates",
    );

    global.rbResolve["cred_autofill_offer_get"] = { items: [] };
    statusEvent("other.example", { content_script_registered: "applied" });
    await flush();
    assert(
      global.$("btn-fill").hidden === true,
      "the fill button survived a navigation to a site with no saved password, " +
        "so it is now offering grace's credential to an unrelated origin",
    );
    assert(
      !global.$("btn-fill").classList.contains("is-active"),
      "the green live state outlived the offer; the next site's button would " +
        "arrive already lit instead of lighting up for its own credential",
    );
  },
);

check("a tab where autofill cannot work shows no fill button", async () => {
  await openTabPanel();
  global.rbResolve["cred_autofill_offer_get"] = {
    items: [{ id: "cred-17", site: "Example", username: "heidi" }],
  };
  statusEvent("example.com", { content_script_registered: "applied" });
  await flush();
  assert(
    global.$("btn-fill").hidden === false,
    "precondition failed: the button should be showing first",
  );

  // Linux, or any tab the engine refused to inject into. The panel row
  // explains why; the toolbar button must simply not be there.
  statusEvent("example.com", { content_script_registered: "failed" });
  await flush();
  assert(
    global.$("btn-fill").hidden === true,
    "a tab with no content script cannot be filled, so a button offering to " +
      "fill it must not be on the toolbar",
  );
});

// THE SITE FIELD, WHICH SILENTLY DECIDED EVERYTHING.
//
// A credential's `site` is free text; Rust parses an origin out of it, and a
// label like "Google" parses to nothing. Such a credential saves, lists,
// reveals -- and never fills, anywhere, with no symptom except an offer that
// never arrives. Real-hardware use hit exactly this, reported as the fill
// button not working.
//
// Two halves, gated together because either alone leaves the trap open:
// the button that makes a correct entry effortless, and the listing that
// makes an incorrect one visible.

check("Use this site fills the field with the tab's own origin", async () => {
  statusEvent("shop.example.com", { content_script_registered: "applied" });
  await flush();
  global.$("cred-site").value = "";
  global.$("cred-use-site")._fire("click");
  assert(
    global.$("cred-site").value === "shop.example.com",
    'Use this site must write the tab origin verbatim, got "' +
      global.$("cred-site").value +
      '" -- anything else and the saved credential will not match the page ' +
      "it was saved on",
  );
});

check("Use this site is absent when the tab has no host to offer", async () => {
  statusEvent("example.com", { content_script_registered: "applied" });
  await flush();
  assert(
    global.$("cred-use-site").hidden === false,
    "precondition failed: the button should be showing on a real site",
  );
  statusEvent(null);
  await flush();
  assert(
    global.$("cred-use-site").hidden === true,
    "a blank tab has no host, so a button promising to insert one must not " +
      "be there to press",
  );
});

check(
  "the list says which credentials actually fill, and which never will",
  async () => {
    global.rbResolve["cred_list"] = {
      items: [
        // Saved on one subdomain, offered across the registrable domain --
        // `fills_on` differs from `origin`, which is the case that must not
        // be described as filling on the subdomain alone.
        {
          id: "a",
          site: "accounts.google.com",
          username: "alice",
          origin: "accounts.google.com",
          fills_on: "google.com",
        },
        // A bare public suffix: no registrable domain, so it fills on itself
        // and nothing else.
        {
          id: "b",
          site: "co.uk",
          username: "bob",
          origin: "co.uk",
          fills_on: null,
        },
        // The inert one.
        { id: "c", site: "Google", username: "carol", origin: null },
      ],
    };
    global.rbResolve["note_list"] = { items: [] };
    global.rbResolve["vault_unlock"] = {};
    // Driven through the REAL unlock path rather than a test-only hook: that
    // is the sequence a user actually takes to see this list, and a hook
    // would let the render diverge from it with nothing failing.
    global.$("unlock-pass").value = "pw";
    global.$("unlock-form")._fire("submit");
    await flush();

    // Walked rather than read off the container's textContent: the DOM stub
    // does not aggregate descendant text, so `.textContent` on the <ul> is ""
    // no matter what rendered. Asserting on that would have passed only
    // because it compared "" against "" -- and would have kept passing with
    // the whole feature deleted.
    const rows = [];
    const walk = (n) => {
      if (/\bcred-origin\b/.test(n.className || "")) {
        rows.push({ cls: n.className, text: n.textContent || "" });
      }
      (n.children || []).forEach(walk);
    };
    [...global.$("cred-list").children].forEach(walk);

    assert(
      rows.length === 3,
      "expected one origin line per credential, got " + rows.length,
    );

    // THE UNDERSTATEMENT THIS GUARDS. Matching is by registrable domain, so
    // this credential is offered anywhere under google.com. A label naming
    // only the subdomain it was saved on would describe a narrower reach than
    // the browser actually has -- the one direction it must never be wrong in.
    const wide = rows[0];
    assert(
      /Fills on google\.com and its subdomains/.test(wide.text),
      "a credential saved on a subdomain must state the whole site it now " +
        'fills on, got: "' +
        wide.text +
        '"',
    );
    assert(
      !/accounts\.google\.com/.test(wide.text),
      'naming only accounts.google.com understates the reach, got: "' +
        wide.text +
        '"',
    );

    // ...and the opposite case must not overstate it: a bare public suffix
    // has no registrable domain, so it fills on itself alone.
    assert(
      /Fills on co\.uk only/.test(rows[1].text),
      'a credential with no registrable domain must say "only", got: "' +
        rows[1].text +
        '"',
    );
    assert(
      !/subdomain/.test(rows[1].text),
      "claiming co.uk fills its subdomains would offer this credential to " +
        'every site in the UK, got: "' +
        rows[1].text +
        '"',
    );
    const dead = rows.find((r) => /\bnone\b/.test(r.cls));
    assert(
      dead && /Copy only/.test(dead.text),
      "a credential with NO origin must say so -- otherwise it is visually " +
        "identical to a working one and the only symptom is a fill that " +
        "never happens. Got: " +
        JSON.stringify(rows),
    );
  },
);

check(
  "a locked vault says a password was not saved, and raises no save banner",
  async () => {
    // The silence a tester reported. Rust emits this when a login is submitted
    // with the vault locked: nothing was stored, and until now nothing said
    // so. The event deliberately carries NO payload -- no password, no
    // username, no origin -- because the sentence names no site.
    const before = global.$("toasts").children.length;
    global.window.__rb_event({ event: "vault_locked_no_save", data: {} });
    await flush();
    const notices = [...global.$("toasts").children];
    assert(
      notices.length === before + 1,
      `expected exactly one new notice, got ${notices.length - before}`,
    );
    const node = notices[notices.length - 1];
    assert(
      node.className === "toast",
      "the notice must be a plain .toast, which is now the centred bold " +
        "surface, got " + JSON.stringify(node.className),
    );
    // A dismiss control the user can reach when they are done reading.
    const close = node.querySelector(".toast-close");
    assert(close, "the notice has no dismiss button");
    assert(
      close.tagName === "BUTTON" && close.type === "button",
      "the dismiss control must be a real button, got " +
        JSON.stringify(close.tagName),
    );
    assert(
      (close.getAttribute("aria-label") || "").length > 0,
      "the dismiss button needs an accessible name; its label is an X glyph",
    );
    // The message must not be swallowed by the button markup.
    assert(
      /^Password not saved\. The vault is locked, so unlock it and sign in again to save it\.$/.test(
        node.querySelector(".toast-text").textContent,
      ),
      "the message text is wrong once the button is in the node: " +
        JSON.stringify(node.textContent),
    );
    // THE TWO BEHAVIOURS, ACTUALLY ASSERTED.
    //
    // The first version of this check just called `close._fire("click")` and
    // asserted nothing after it. A review removed BOTH the click wiring and
    // the expiry scheduling and all 34 checks still passed -- so the test
    // could not protect either of the things it existed for. domstub's
    // `remove()` is a no-op and its `setTimeout` runs synchronously, so the
    // work is to observe the wiring rather than the disappearance.
    assert(
      close._listeners && close._listeners.click,
      "the dismiss button has no click handler, so pressing it does nothing",
    );
    // Give this node a removal we can see, then fire the button.
    let removedByClick = false;
    node.remove = () => {
      removedByClick = true;
    };
    close._fire("click");
    await flush();
    assert(
      removedByClick,
      "clicking dismiss did not remove the notification",
    );

    // And the automatic expiry: capture what toast() schedules instead of
    // letting the stub run it, so both the delay and the effect are checked.
    const realSetTimeout = global.setTimeout;
    const scheduled = [];
    global.setTimeout = (fn, ms) => {
      scheduled.push({ fn, ms });
      return 0;
    };
    try {
      global.window.__rb_event({ event: "vault_locked_no_save", data: {} });
      await flush();
    } finally {
      global.setTimeout = realSetTimeout;
    }
    assert(
      scheduled.length === 1,
      `a notification must schedule exactly one expiry, got ${scheduled.length}`,
    );
    assert(
      scheduled[0].ms === 15000,
      "a notification must clear itself after 15 seconds, got " +
        JSON.stringify(scheduled[0].ms),
    );
    const late = [...global.$("toasts").children].pop();
    let removedByTimer = false;
    late.remove = () => {
      removedByTimer = true;
    };
    scheduled[0].fn();
    assert(
      removedByTimer,
      "the expiry fired but did not remove the notification",
    );
    // It must not imply a save is pending: the banner is the surface that
    // offers to save, and there is nothing to offer.
    assert(
      global.$("save-password-banner").hidden === true,
      "a locked vault must not raise the save banner",
    );
    assert(
      !global.rbCalls.some((c) => c.cmd === "cred_save_confirm"),
      "the notice must never confirm a save",
    );
  },
);

check(
  "no more than three notifications are on screen at once",
  async () => {
    // Centred, bold, wrapping and fifteen seconds each were fine alone.
    // Together, one long message already covers the address bar and most of
    // the toolbar, and a burst pushes later notices below the visible strip --
    // the document is `overflow: hidden`, so those are unreachable rather than
    // merely out of view, and their dismiss buttons go with them.
    const host = global.$("toasts");
    // The harness never really removes nodes (domstub's `remove()` is a
    // no-op), so start from a known floor rather than from whatever earlier
    // checks left behind.
    host.children = [];
    // DISTINGUISHABLE messages, through the same helper every caller uses.
    // Five identical notices cannot show WHICH three survived, and the first
    // version of this check could not tell keeping the newest from keeping
    // the oldest.
    for (const n of ["one", "two", "three", "four", "five"]) {
      global.window.__rb_toast(n, false);
      await flush();
    }
    assert(
      host.children.length === 3,
      `at most three notifications may be visible, got ${host.children.length}`,
    );
    // It is the OLDEST that goes. The newest message is the one the user is
    // looking for, so a flood must not silence the thing it buried.
    const surviving = host.children.map((n) =>
      n.querySelector(".toast-text").textContent,
    );
    assert(
      JSON.stringify(surviving) === JSON.stringify(["three", "four", "five"]),
      "the wrong three survived; expected the newest three, got " +
        JSON.stringify(surviving),
    );
    host.children = [];
  },
);

check("the save banner is hidden by default", () => {
  assert(
    global.$("save-password-banner").hidden === true,
    "the save-password banner must not render before any submission has " +
      "been reported",
  );
});

check(
  "a real submission (pending_save present) shows the banner with no password in it",
  () => {
    statusEvent("example.com", {
      pending_save: { origin: "example.com", username: "dora" },
    });
    assert(
      global.$("save-password-banner").hidden === false,
      "pending_save being non-null must show the banner",
    );
    const body = global.$("save-password-body").textContent;
    assert(/dora/.test(body), "the banner must name the account");
    assert(
      /example\.com/.test(body),
      "the banner must name the site the password is for",
    );
  },
);

check(
  "an ordinary tab_status with no pending save keeps the banner hidden",
  () => {
    statusEvent("elsewhere.example", { pending_save: null });
    assert(
      global.$("save-password-banner").hidden === true,
      "a tab_status with pending_save: null must hide the banner -- the " +
        "banner must not persist once the tab it belonged to moved on",
    );
  },
);

check(
  "Save calls cred_save_confirm exactly once and hides the banner",
  async () => {
    statusEvent("example.com", {
      pending_save: { origin: "example.com", username: "erin" },
    });
    assert(
      global.$("save-password-banner").hidden === false,
      "setup failed: the banner did not open",
    );
    global.rbCalls.length = 0;
    global.$("save-password-save")._fire("click");
    await flush();
    const calls = global.rbCalls.filter((c) => c.cmd === "cred_save_confirm");
    assert(
      calls.length === 1,
      "expected exactly one cred_save_confirm call, got " + calls.length,
    );
    assert(
      global.$("save-password-banner").hidden === true,
      "the banner must close once Save has been actioned",
    );
  },
);

check(
  "Not now calls cred_save_dismiss exactly once and hides the banner",
  async () => {
    statusEvent("example.com", {
      pending_save: { origin: "example.com", username: "frank" },
    });
    assert(
      global.$("save-password-banner").hidden === false,
      "setup failed: the banner did not open",
    );
    global.rbCalls.length = 0;
    global.$("save-password-dismiss")._fire("click");
    await flush();
    const calls = global.rbCalls.filter((c) => c.cmd === "cred_save_dismiss");
    assert(
      calls.length === 1,
      "expected exactly one cred_save_dismiss call, got " + calls.length,
    );
    assert(
      global.$("save-password-banner").hidden === true,
      "the banner must close once Not now has been actioned",
    );
  },
);

check(
  "login_submit_detected fetches the full status rather than rendering its own partial payload",
  async () => {
    global.rbResolve["tab_status"] = {
      freeze_phase: "loaded",
      freeze_enforcement: "inactive",
      profile: "persistent",
      origin: "fresh.example",
      tls: "normal",
      freeze_enforced: true,
      network_blocking_supported: true,
      ledger_counts_blocked: true,
      blocked_total: 0,
      interception: "registered",
      script_setting: "applied",
      smartscreen_off: "applied",
      tracking_prevention: "strict",
      navigation_tracking: "applied",
      autofill_off: "applied",
      ephemeral_confirmed: "applied",
      hardened_environment: "applied",
      content_script_registered: "applied",
      pending_save: { origin: "fresh.example", username: "gale" },
    };
    global.rbCalls.length = 0;
    global.window.__rb_event({
      event: "login_submit_detected",
      data: { origin: "fresh.example", username: "gale" },
    });
    await flush();
    assert(
      global.rbCalls.some((c) => c.cmd === "tab_status"),
      "login_submit_detected must trigger a tab_status fetch -- its own " +
        "event payload has no password, so it cannot render the banner by " +
        "itself",
    );
    assert(
      global.$("save-password-banner").hidden === false,
      "the fetched status carried a pending_save; the banner must be showing",
    );
    delete global.rbResolve["tab_status"];
  },
);

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + "\n      " + e.message);
      console.log("  FAIL " + name);
    }
  }
  if (failures.length) {
    console.error("\nCREDENTIAL AUTOFILL GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nCREDENTIAL AUTOFILL UI OK");
})();
