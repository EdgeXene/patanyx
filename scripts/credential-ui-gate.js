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
        tracking_prevention: "applied",
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
const pwStart = html.indexOf('<span class="section-label">Passwords</span>');
const pwEnd = html.indexOf("<h2>Hosts this tab has contacted</h2>");
const PW_SECTION = html.slice(pwStart, pwEnd);

check("the Passwords section exists between Cookies and the ledger", () => {
  const cookiesAt = html.indexOf('<span class="section-label">Cookies</span>');
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
      /no site/i.test(global.$("tab-autofill-desc").textContent),
      "a page with no origin must say there is no site to check",
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
      /not available/i.test(global.$("tab-autofill-desc").textContent),
      "an unregistered content script must say autofill is unavailable in " +
        'this tab, not silently show "no saved password"',
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

check(
  "no match: the Passwords section says so and the button stays disabled",
  async () => {
    await openTabPanel();
    global.rbResolve["cred_autofill_offer_get"] = { items: [] };
    statusEvent("example.com", { content_script_registered: "applied" });
    await flush();
    assert(
      /no saved password/i.test(global.$("tab-autofill-desc").textContent),
      "an empty offer list must say there is no saved password for this site",
    );
    assert(
      global.$("btn-autofill-fill").disabled === true,
      "the fill button must stay disabled with no match",
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
// after something else -- the project owner's report was that they could see their
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
    // LIT, not just present. This is the defect the project owner actually
    // reported: the button was on the toolbar and looked exactly like the
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
// never arrives. The project owner hit exactly this and reported it as the fill
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
      tracking_prevention: "applied",
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
