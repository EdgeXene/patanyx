// "Forget this site" -- cookies for the active tab's own origin, and nothing
// else. Behavioural checks run against the DOM harness so chrome.js is
// EXECUTED rather than parsed, the same discipline vault-import-ui-gate.js
// uses for its own destructive action.
//
// WHY THIS EXISTS. This is a destructive control living inside a panel
// ("Tab Activity") that already ships a form-buttons row and a small button
// or two -- exactly the setting a warning could silently stop rendering into,
// or a confirm button could end up wired to fire immediately instead of after
// confirmation. Both are asserted here rather than assumed from having
// written the markup once.
//
// The origin-switch check is the one this file exists for specifically: the
// confirmation is per-tab state (`lastForgetOrigin`), not per-click, so a
// slow reply or a tab switch while it is open must not let "yes" answer for
// a DIFFERENT site than the one the dialog was opened against.
//
// Run: node scripts/site-forget-gate.js   (or via scripts/chrome-js-gate.sh)
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

// Exactly the shape `AppState::active_tab_status` emits, `origin` varied per
// check. Pushed through the REAL entry point (`tab_status`, the event Rust
// fires on every tab switch, navigation and load-state change) rather than
// calling an internal renderer directly, which would prove only that the
// renderer works in isolation -- never the broken half in this file's history.
function statusEvent(origin) {
  global.window.__rb_event({
    event: "tab_status",
    data: {
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
    },
  });
}

// The section between the two headings this control lives between, so a
// check here cannot accidentally match the destructive-warning that belongs
// to vault import or backup restore elsewhere in the same file.
const sectionStart = html.indexOf('<span class="section-label">Cookies</span>');
const sectionEnd = html.indexOf("<h2>Hosts this tab has contacted</h2>");
const SECTION = html.slice(sectionStart, sectionEnd);

check("the address-bar icon exists and is not a toolbar pill", () => {
  // It DOES sit inside <header id="toolbar"> in the markup -- that element
  // spans both rows, address bar included -- but it must not be one of the
  // `.feature-btn` pills toolbar-gate.js's row and disclosure rules govern.
  // Those rules exist to keep every FEATURE reachable without a click; this
  // is a second entry point to a feature that is already reachable via "TA",
  // not a feature of its own, and giving it `.feature-btn` would put it in
  // toolbar-gate.js's ROW_ONE/ROW_TWO bookkeeping for no reason.
  const at = html.indexOf('id="btn-site-info"');
  assert(at !== -1, "#btn-site-info is missing from index.html");
  const tagStart = html.lastIndexOf("<button", at);
  const tagEnd = html.indexOf(">", at);
  const tag = html.slice(tagStart, tagEnd);
  assert(
    !/class="[^"]*\bfeature-btn\b/.test(tag),
    "#btn-site-info carries `feature-btn` -- toolbar-gate.js would then " +
      "expect it in MUST_BE_VISIBLE/ROW_ONE/ROW_TWO, which it deliberately " +
      "is not",
  );
});

check("the Cookies section exists between Connection and the ledger", () => {
  assert(sectionStart !== -1, "the Cookies section-label is missing");
  assert(sectionEnd !== -1, "the ledger heading it must precede is missing");
  assert(sectionStart < sectionEnd, "the Cookies section is out of order");
});

check("the warning states what is and is not cleared", () => {
  assert(
    /class="destructive-warning"/.test(SECTION),
    "the destructive warning is gone from the Cookies section",
  );
  assert(
    /cookies/i.test(SECTION),
    "the warning no longer says cookies are what gets cleared",
  );
  assert(
    /(password|local storage)/i.test(SECTION),
    "the warning no longer says what is NOT cleared -- without this a user " +
      "may believe Forget-this-site is a full site-data wipe, which it is not",
  );
  assert(
    /cannot be undone/i.test(SECTION),
    "the warning no longer says the deletion is irreversible",
  );
});

check("the warning is placed BEFORE the confirm button, not after it", () => {
  const warn = SECTION.indexOf("destructive-warning");
  const yes = SECTION.indexOf('id="site-forget-yes"');
  assert(warn !== -1 && yes !== -1, "warning or confirm button missing");
  assert(
    warn < yes,
    "the warning renders after the confirm button; a user who has already " +
      "pressed it has decided, and reads the warning too late to matter",
  );
});

check("the destructive-warning class has somewhere to be drawn", () => {
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  assert(
    /\.destructive-warning\b/.test(css),
    ".destructive-warning has no rule in chrome.css, so it renders as " +
      "another grey paragraph and reads as intro copy rather than a warning",
  );
});

check(
  "pressing Forget opens a confirmation; it does not act immediately",
  async () => {
    statusEvent("example.com");
    global.rbCalls.length = 0;
    global.$("btn-site-forget")._fire("click");
    await flush();
    assert(
      global.$("site-forget-confirm").hidden === false,
      "pressing Forget this site must reveal the confirmation, not act on its own",
    );
    assert(
      !global.rbCalls.some((c) => c.cmd === "site_forget_cookies"),
      "site_forget_cookies was called before the user confirmed anything",
    );
  },
);

check("confirming calls the backend, exactly once", async () => {
  statusEvent("example.com");
  global.$("btn-site-forget")._fire("click");
  await flush();
  global.rbCalls.length = 0;
  global.$("site-forget-yes")._fire("click");
  await flush();
  const calls = global.rbCalls.filter((c) => c.cmd === "site_forget_cookies");
  assert(
    calls.length === 1,
    "expected exactly one site_forget_cookies call after confirming, got " +
      calls.length,
  );
});

check("switching the tab's origin closes an open confirmation", async () => {
  // Open it for one site...
  statusEvent("a.example");
  global.$("btn-site-forget")._fire("click");
  await flush();
  assert(
    global.$("site-forget-confirm").hidden === false,
    "setup failed: the confirmation did not open",
  );
  // ...and switch to another before answering it.
  statusEvent("b.example");
  assert(
    global.$("site-forget-confirm").hidden === true,
    "a confirmation opened for one origin must close when the tab's origin " +
      'changes -- otherwise pressing "Yes, forget it" after switching tabs ' +
      "clears cookies for a site the user is no longer looking at",
  );
});

check(
  "a page with no site disables the control rather than hiding it silently",
  () => {
    statusEvent(null);
    assert(
      global.$("btn-site-forget").disabled === true,
      "Forget this site must be disabled when the tab has no origin " +
        "(about:blank, an internal page) -- a live button that fails with " +
        "no_site on every click is worse than one that visibly cannot be pressed",
    );
  },
);

check(
  "the icon opens the same panel Tab Activity opens, not a second one",
  async () => {
    global.$("btn-site-info")._fire("click");
    await flush();
    assert(
      global.$("tab-panel").hidden === false,
      "#btn-site-info must open #tab-panel -- if this fails after a refactor, " +
        "check it was not repointed at a newly (re)introduced parallel panel",
    );
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
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
    console.error("\nSITE-FORGET GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nSITE-FORGET UI OK");
})();
