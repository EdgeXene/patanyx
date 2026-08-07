// First-run tour. Behavioural checks run against the DOM harness so
// chrome.js is EXECUTED rather than parsed -- including its own boot
// sequence, since the tour's most important property (it opens itself on a
// fresh install and never bothers an existing one again) lives in that boot
// code, not in a click handler this file could fire on demand.
//
// WHY THIS EXISTS. `prefs::onboarding_resolved` has its own Rust-side test
// for the marker/vault decision table; what is only checkable here is the
// chrome-JS half: the boot check actually calls `togglePanelNamed` when told
// `seen: false` (and, by construction, cannot when `data` is absent or
// `seen` is anything but the literal `false`), every dismissal route marks
// it seen exactly once, and the About panel's re-open button actually
// reaches this panel and not a stale id.
//
// Run: node scripts/onboarding-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
const chromeSrc = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
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

check("the boot check tests the LITERAL false, not any falsy value", () => {
  // A fetch failure (data undefined) or an unexpected shape must not open
  // the tour either -- the strict `=== false` is what a future refactor to
  // "if (!data.seen)" would silently break, opening the tour on every
  // network hiccup instead of only on a genuine first run.
  assert(
    /data\.seen === false/.test(chromeSrc),
    "the onboarding boot check no longer tests `data.seen === false` " +
      "specifically -- a loose falsy check would also fire on a failed or " +
      "malformed onboarding_seen_get reply",
  );
});

// Set BEFORE chrome.js's own top-level code runs, unlike every other check
// in this file: the boot sequence that decides whether to open the tour
// executes once, synchronously-scheduled, the moment the script loads.
global.rbResolve.onboarding_seen_get = { seen: false };
new Function(chromeSrc)();

check("seen: false opens the tour from the boot sequence itself", async () => {
  await flush();
  assert(
    global.$("onboarding-panel").hidden === false,
    "the boot check did not open #onboarding-panel when told seen: false",
  );
});

check("a visible dismiss control exists beyond Escape and the scrim", () => {
  const start = html.indexOf('<section id="onboarding-panel"');
  const end = html.indexOf("</section>", start);
  const section = html.slice(start, end);
  assert(
    /id="onboarding-done"/.test(section),
    'no visible "Got it" control in the tour -- Escape and the scrim work ' +
      "but neither is discoverable on its own, the same gap every other " +
      "panel's auto-injected Close button exists to close",
  );
});

check("About panel's re-open button names a real, existing panel", () => {
  assert(
    html.includes('id="about-tour-again"'),
    "#about-tour-again is missing from the About panel",
  );
  const aboutStart = html.indexOf('<section id="about-panel"');
  const aboutEnd = html.indexOf("</section>", aboutStart);
  assert(
    html.slice(aboutStart, aboutEnd).includes('id="about-tour-again"'),
    "#about-tour-again exists but is not inside the About panel",
  );
});

check(
  "dismissing the tour -- by any route -- marks it seen exactly once",
  async () => {
    // Boot already opened it (previous checks proved that). Escape first.
    assert(global.$("onboarding-panel").hidden === false, "setup: not open");
    global.rbCalls.length = 0;
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
    const afterEscape = global.rbCalls.filter(
      (c) => c.cmd === "onboarding_seen_set",
    );
    assert(
      afterEscape.length === 1,
      `Escape must call onboarding_seen_set exactly once, called ${afterEscape.length} times`,
    );

    // Reopen via the About re-open button, then dismiss with "Got it".
    global.$("about-tour-again")._fire("click");
    await flush();
    assert(
      global.$("onboarding-panel").hidden === false,
      "#about-tour-again did not reopen the tour",
    );
    global.rbCalls.length = 0;
    global.$("onboarding-done")._fire("click");
    await flush();
    const afterDone = global.rbCalls.filter(
      (c) => c.cmd === "onboarding_seen_set",
    );
    assert(
      afterDone.length === 1,
      `"Got it" must call onboarding_seen_set exactly once, called ${afterDone.length} times`,
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
    console.error("\nONBOARDING GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nONBOARDING UI OK");
})();
