// "Clear cookies for all sites" -- the browser-wide cookie control in the
// privacy panel. Behavioural checks against the DOM harness so chrome.js is
// EXECUTED rather than parsed, mirroring site-forget-gate.js, which covers the
// per-site control this one is the counterpart to.
//
// WHY THIS EXISTS, beyond "the other one has a gate". Two properties here are
// carried by nothing else in the tree:
//
//   1. NO IPC BEFORE CONFIRMATION. This clears every cookie the browser holds.
//      A confirm button wired to fire immediately looks identical in a
//      screenshot and is unrecoverable in use.
//
//   2. THE COPY COMES FROM RUST. Every string in this section is empty in
//      index.html and written from the privacy_get payload
//      (cookie_control::forget_all_copy, pinned by its own tests there). The
//      sentence "cookies, not your saved passwords" is what keeps the feature
//      honest, and the moment somebody types a friendlier version into the
//      markup it becomes copy no test reads. This gate asserts the markup is
//      still empty AND that the payload's words are what land on screen.
//
// Also asserted: cancel closes without calling, a failure leaves the
// confirmation open rather than mimicking success, and reopening the panel
// never shows a stale "cleared" line.
//
// Run: node scripts/forget-all-cookies-gate.js  (or via scripts/chrome-js-gate.sh)
//
// PATANYX_ROOT overrides the repository root. It exists so this file can be
// run from outside scripts/ (an export-tree copy, or a review drop) without a
// second, drifting copy of the harness; when the file sits in scripts/ the
// default is correct and the variable is unnecessary.
const fs = require("fs");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require(path.join(root, "scripts/domstub.js"));

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

// The wording Rust sends. Deliberately NOT imported from anywhere and
// deliberately not the real sentences: distinctive markers prove the strings
// on screen travelled through the payload. Copy hardcoded in the markup or in
// chrome.js would leave these absent and fail every copy check below.
const COPY = {
  intro: "MARKER-INTRO clears cookies for every site.",
  warning: "MARKER-WARNING passwords are left alone. This cannot be undone.",
  button: "MARKER-BUTTON",
  confirm: "MARKER-CONFIRM",
  cancel: "MARKER-CANCEL",
};

// Exactly the shape `AppState::privacy_status` emits.
function privacyStatus(overrides) {
  return Object.assign(
    {
      block_ads: true,
      freeze_after_load: false,
      javascript: true,
      ephemeral: false,
      network_blocking_supported: true,
      freeze_enforced: true,
      forget_all: COPY,
    },
    overrides || {},
  );
}

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// Open the privacy panel through its REAL toolbar button, so the panel's own
// onOpen runs (that is where the confirmation and the result line are reset)
// and the copy arrives the way it does in the product, via privacy_get.
async function openPrivacyPanel(status) {
  global.rbResolve.privacy_get = privacyStatus(status);
  global.$("btn-privacy")._fire("click");
  await flush();
}

async function closePrivacyPanel() {
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
}

// The section between its own heading and the leak-check section, so a check
// here cannot match the per-site control's warning in the other panel.
// From the opening <section ...> tag itself, not from the id attribute inside
// it: slicing mid-tag leaves attribute text in the body and the "no hardcoded
// copy" check below then reads it as copy.
const sectionStart = html.lastIndexOf(
  "<section",
  html.indexOf('id="forget-all-choice"'),
);
// The next <section> AFTER this one, whichever it is. This used to be
// found by looking for #leakcheck, which happened to be the neighbour --
// until 2026-08-19, when the image check moved out of the Privacy panel
// into the tools modal and the landmark walked off with it, leaving
// sectionEnd BEFORE sectionStart and every check below reading a negative
// slice. A boundary should not be another feature's address.
const sectionEnd = html.indexOf("<section", sectionStart + 1);
const SECTION = html.slice(sectionStart, sectionEnd);

check("the section exists inside the privacy panel", () => {
  assert(
    html.indexOf('id="forget-all-choice"') !== -1,
    "#forget-all-choice is missing from index.html",
  );
  assert(sectionEnd !== -1, "no section follows it; the panel ends abruptly");
  assert(sectionStart < sectionEnd, "the section is out of order");
  const panelStart = html.indexOf('id="privacy-panel"');
  const panelEnd = html.indexOf('id="dns-panel"');
  assert(
    panelStart !== -1 && panelStart < sectionStart && sectionStart < panelEnd,
    "the browser-wide cookie control is not inside #privacy-panel -- it " +
      "clears every site, and a panel scoped to one tab is the wrong place " +
      "for a user to read its scope off",
  );
});

check("the markup carries no copy of its own", () => {
  // Anything between the tags in this section other than whitespace is a
  // second set of words competing with the Rust one.
  const stripped = SECTION.replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<[^>]*>/g, "")
    .replace(/\s+/g, " ")
    .replace("Cookies", "") // the section heading, which is structural
    .trim();
  assert(
    stripped === "",
    "the section hardcodes copy (" +
      JSON.stringify(stripped) +
      ") -- every user-facing string here must come from cookie_control.rs " +
      "through privacy_get, or the sentence that keeps this honest is one " +
      "no test reads",
  );
});

check("the warning is placed BEFORE the confirm button, not after it", () => {
  const warn = SECTION.indexOf('id="forget-all-warn"');
  const yes = SECTION.indexOf('id="forget-all-yes"');
  assert(warn !== -1 && yes !== -1, "warning or confirm button missing");
  assert(
    warn < yes,
    "the warning renders after the confirm button; a user who has already " +
      "pressed it has decided, and reads the warning too late to matter",
  );
});

check("the warning is styled as a warning", () => {
  assert(
    /class="destructive-warning"/.test(SECTION),
    "the destructive-warning class is gone; the warning renders as another " +
      "grey paragraph and reads as intro copy",
  );
});

check("Rust's words are what land on screen", async () => {
  await openPrivacyPanel();
  assert(
    global.$("pv-forget-all-desc").textContent === COPY.intro,
    "the intro is not the payload's: " +
      JSON.stringify(global.$("pv-forget-all-desc").textContent),
  );
  assert(
    global.$("btn-forget-all-cookies").textContent === COPY.button,
    "the button label is not the payload's",
  );
  assert(
    global.$("forget-all-warn").textContent === COPY.warning,
    "the warning is not the payload's -- a hardcoded warning can claim more " +
      "than DeleteAllCookies actually does",
  );
  assert(
    global.$("forget-all-yes").textContent === COPY.confirm,
    "the confirm label is not the payload's",
  );
  assert(
    global.$("forget-all-cancel").textContent === COPY.cancel,
    "the cancel label is not the payload's",
  );
  await closePrivacyPanel();
});

check("pressing it opens a confirmation; it does not act", async () => {
  await openPrivacyPanel();
  global.rbCalls.length = 0;
  global.$("btn-forget-all-cookies")._fire("click");
  await flush();
  assert(
    global.$("forget-all-confirm").hidden === false,
    "pressing the button must reveal the confirmation, not act on its own",
  );
  assert(
    !global.rbCalls.some((c) => c.cmd === "cookies_forget_all"),
    "cookies_forget_all was called before the user confirmed anything -- " +
      "this clears every cookie in the browser and cannot be undone",
  );
  await closePrivacyPanel();
});

check("cancelling closes it and calls nothing", async () => {
  await openPrivacyPanel();
  global.$("btn-forget-all-cookies")._fire("click");
  await flush();
  global.rbCalls.length = 0;
  global.$("forget-all-cancel")._fire("click");
  await flush();
  assert(
    global.$("forget-all-confirm").hidden === true,
    "cancel did not close the confirmation",
  );
  assert(
    !global.rbCalls.some((c) => c.cmd === "cookies_forget_all"),
    "cancel called cookies_forget_all",
  );
  await closePrivacyPanel();
});

check("confirming calls the backend, exactly once", async () => {
  await openPrivacyPanel();
  global.rbResolve.cookies_forget_all = { message: "MARKER-CLEARED" };
  global.$("btn-forget-all-cookies")._fire("click");
  await flush();
  global.rbCalls.length = 0;
  global.$("forget-all-yes")._fire("click");
  await flush();
  const calls = global.rbCalls.filter((c) => c.cmd === "cookies_forget_all");
  assert(
    calls.length === 1,
    "expected exactly one cookies_forget_all call after confirming, got " +
      calls.length,
  );
  assert(
    calls[0].args === undefined ||
      Object.keys(calls[0].args || {}).length === 0,
    "the command was sent with arguments; it takes none, and a scope the " +
      "chrome could name is a scope a compromised chrome could choose",
  );
  await closePrivacyPanel();
});

check("the result line is the REPLY's, not the click's", async () => {
  await openPrivacyPanel();
  global.rbResolve.cookies_forget_all = { message: "MARKER-CLEARED" };
  global.$("btn-forget-all-cookies")._fire("click");
  await flush();
  global.$("forget-all-yes")._fire("click");
  await flush();
  assert(
    global.$("forget-all-result").hidden === false,
    "no result was shown after a successful clear",
  );
  assert(
    global.$("forget-all-result").textContent === "MARKER-CLEARED",
    "the result line was composed in the chrome rather than taken from the " +
      "reply: " +
      JSON.stringify(global.$("forget-all-result").textContent),
  );
  assert(
    global.$("forget-all-confirm").hidden === true,
    "the confirmation stayed open after a successful clear",
  );
  await closePrivacyPanel();
});

check("a refusal never looks like a success", async () => {
  await openPrivacyPanel();
  global.$("btn-forget-all-cookies")._fire("click");
  await flush();
  global.rbReject = "no_persistent_tab";
  global.$("forget-all-yes")._fire("click");
  await flush();
  global.rbReject = null;
  assert(
    global.$("forget-all-result").hidden === true,
    "a refused clear showed the success line -- nothing was cleared",
  );
  assert(
    global.$("forget-all-confirm").hidden === false,
    "a refused clear closed the confirmation, leaving the panel looking " +
      "exactly like the success case",
  );
  assert(
    global.$("forget-all-yes").disabled === false,
    "the confirm button stayed disabled after a refusal, so the user cannot " +
      "retry once they have opened an ordinary tab",
  );
  await closePrivacyPanel();
});

check("reopening the panel never shows a stale result", async () => {
  await openPrivacyPanel();
  global.rbResolve.cookies_forget_all = { message: "MARKER-CLEARED" };
  global.$("btn-forget-all-cookies")._fire("click");
  await flush();
  global.$("forget-all-yes")._fire("click");
  await flush();
  assert(
    global.$("forget-all-result").hidden === false,
    "setup failed: no result to go stale",
  );
  await closePrivacyPanel();
  await openPrivacyPanel();
  assert(
    global.$("forget-all-result").hidden === true,
    "a 'cookies cleared' line from an earlier visit greets a fresh open, " +
      "claiming something just happened",
  );
  assert(
    global.$("forget-all-confirm").hidden === true,
    "the panel opened already confirming a destructive action",
  );
  await closePrivacyPanel();
});

check(
  "a payload with no copy leaves the section blank, not guessed",
  async () => {
    await openPrivacyPanel({ forget_all: undefined });
    assert(
      global.$("forget-all-warn").textContent === "",
      "the chrome invented a warning when Rust sent none: " +
        JSON.stringify(global.$("forget-all-warn").textContent),
    );
    await closePrivacyPanel();
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
    console.error("\nFORGET-ALL-COOKIES GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nFORGET-ALL-COOKIES UI OK");
})();
