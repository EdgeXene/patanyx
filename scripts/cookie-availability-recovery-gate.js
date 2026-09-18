// Does a dropped availability reply at STARTUP disable cookie clearing forever?
//
// WHY THIS IS ITS OWN GATE. The cookie controls are disabled until Rust says
// the backend can clear (`cookie_clear_available`). That flag starts `null`,
// meaning "not answered yet", and `refreshPrivacy()` -- the one call that asks
// at startup -- writes a failure into the Privacy panel and returns. So a
// single dropped reply used to leave BOTH controls disabled until the user
// happened to open Privacy, which on Windows is a working feature lost to one
// bad round trip (Linux readiness review 2026-09-15, finding R-001).
//
// That state can only be reached BEFORE the first successful reply: once the
// flag holds true or false, a later failure keeps the last known answer rather
// than reverting to unknown, which is what we want. It therefore cannot be
// tested from inside forget-all-cookies-gate.js, whose earlier checks have
// already answered privacy_get several times before any new check runs. This
// file exists to load chrome.js ONCE with the first privacy_get rejecting.
//
// It executes the real chrome.js through the shared DOM harness and drives the
// real `tab_status` event. It does not execute Rust, GTK or WebKit.

const fs = require("fs");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require(path.join(root, "scripts/domstub.js"));

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

// The shape `AppState::active_tab_status` emits.
function siteStatus(origin) {
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
      tracking_prevention: "strict",
      navigation_tracking: "applied",
      autofill_off: "applied",
      ephemeral_confirmed: "applied",
      hardened_environment: "applied",
    },
  });
}

// THE FIRST privacy_get FAILS. Set before chrome.js is evaluated, because
// chrome.js calls refreshPrivacy() as it loads and that call is the one under
// test.
global.rbResolve.privacy_get = new Error("ipc down");

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

check(
  "a dropped startup reply leaves the control off, but not called unavailable",
  async () => {
    await flush();
    siteStatus("example.com");
    await flush();
    assert(
      global.$("btn-site-forget").disabled === true,
      "the control must not be live while the backend has never answered",
    );
    const desc = global.$("tab-forget-desc").textContent;
    assert(
      !desc.includes("not available on this platform"),
      "an unanswered privacy_get was rendered as a platform limitation, which " +
        "is a false claim on a backend that can clear cookies: " +
        JSON.stringify(desc),
    );
    assert(
      desc.includes("example.com"),
      "the ordinary origin description should still be shown: " +
        JSON.stringify(desc),
    );
  },
);

check(
  "once the backend answers, an ordinary tab update brings the control back",
  async () => {
    // The backend recovers. No panel is opened and nothing is clicked: an
    // ordinary tab_status is all that happens, and it must be enough.
    global.rbResolve.privacy_get = {
      cookie_clear_available: true,
      forget_all: {
        intro: "i",
        warning: "w",
        button: "b",
        confirm: "c",
        cancel: "x",
      },
    };
    siteStatus("example.com");
    await flush();
    assert(
      global.$("btn-site-forget").disabled === false,
      "the per-site control was never re-enabled after the backend recovered; a " +
        "single dropped reply at startup disabled it for the whole session",
    );
    assert(
      global.$("btn-forget-all-cookies").disabled === false,
      "the browser-wide control was never re-enabled after the backend recovered",
    );
  },
);

check(
  "a backend that answers 'cannot clear' is still taken at its word",
  async () => {
    global.rbResolve.privacy_get = {
      cookie_clear_available: false,
      cookie_clear_unavailable_intro: "MARKER-OFF",
      forget_all: {
        intro: "i",
        warning: "w",
        button: "b",
        confirm: "c",
        cancel: "x",
      },
    };
    // Availability is already known, so nothing asks again on its own. Reaching
    // the new answer is what opening the panel does.
    global.$("btn-privacy")._fire("click");
    await flush();
    assert(
      global.$("btn-site-forget").disabled === true,
      "an explicit 'cannot clear' left the per-site control live",
    );
    assert(
      global.$("btn-forget-all-cookies").disabled === true,
      "an explicit 'cannot clear' left the browser-wide control live",
    );
    assert(
      global
        .$("tab-forget-desc")
        .textContent.includes("not available on this platform"),
      "an explicit 'cannot clear' did not say why the control is off: " +
        JSON.stringify(global.$("tab-forget-desc").textContent),
    );
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
    console.error("\nCOOKIE-AVAILABILITY-RECOVERY GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nCOOKIE-AVAILABILITY RECOVERY OK");
})();
