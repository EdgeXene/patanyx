// The "a newer version is available" banner, driven through the REAL event
// path (window.__rb_event -> chrome.js) rather than by reading the source.
//
// WHY THIS EXISTS. The banner shipped dead. chrome.js raised it only for
// `state === "offered"`, while the scheduled check emitted the value
// `check_now` returns the instant it SPAWNS its fetch, which is `checking`.
// The two never met, so no scheduled check ever raised the banner on any
// platform, and the browser's whole "notify, never install" promise had no
// notify half. Neither side looked wrong on its own; only running them
// together shows it.
//
// So this gate pins the CONTRACT BETWEEN THEM, in both directions:
//   * the states that must interrupt: offered, and ready (the default,
//     because background download ships on)
//   * the states that must NOT: checking, downloading, uptodate, failed
//     -- those belong in the panel, not across the top of the window
//
// Run: node scripts/update-banner-gate.js  (or via scripts/chrome-js-gate.sh)
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
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

function sendChecked(data) {
  global.window.__rb_event({ event: "update_checked", data });
}
function banner() {
  return global.$("update-banner");
}
function bodyText() {
  return global.$("update-banner-body").textContent || "";
}

const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}

check("a finished check offering a version raises the banner", async () => {
  sendChecked({ state: "offered", offered: "0.9.62" });
  await flush();
  assert(banner().hidden === false, "an offered update raised no banner");
  assert(
    bodyText().indexOf("0.9.62") !== -1,
    "the banner does not name the version being offered",
  );
});

// THE DEFAULT PATH, and the one the original condition missed entirely.
check("a background-downloaded update raises the banner", async () => {
  sendChecked({ state: "uptodate" });
  await flush();
  sendChecked({ state: "ready", offered: "0.9.62", wired: true });
  await flush();
  assert(
    banner().hidden === false,
    "an update that downloaded and verified in the background raised no " +
      "banner. Background download ships ON, so this is what almost every " +
      "user gets, and a banner that only fires on `offered` is silent for " +
      "them",
  );
  assert(
    bodyText().indexOf("0.9.62") !== -1,
    "the banner does not name the version that is waiting",
  );
  assert(
    /downloaded and verified/i.test(bodyText()),
    "the banner must say the bytes are already here; the offered wording " +
      "('nothing has been downloaded yet') is false in this state",
  );
  assert(
    /nothing has been installed/i.test(bodyText()),
    "the banner must say nothing was installed, because nothing was: the " +
      "install still waits on the restart click",
  );
});

// The banner must never claim an install happened. This is the product's
// loudest promise about updates and the one sentence a user reads fastest.
check("no banner state claims an install", async () => {
  for (const data of [
    { state: "offered", offered: "0.9.62" },
    { state: "ready", offered: "0.9.62", wired: true },
  ]) {
    sendChecked({ state: "uptodate" });
    await flush();
    sendChecked(data);
    await flush();
    assert(
      !/\b(installed|installing|updated)\b/i.test(
        bodyText().replace(/nothing has been installed/i, ""),
      ),
      "the banner in state " +
        data.state +
        " reads as though something was " +
        "installed: " +
        JSON.stringify(bodyText()),
    );
  }
});

check("in-flight and settled-quiet states stay out of the way", async () => {
  for (const data of [
    { state: "checking" },
    { state: "downloading", offered: "0.9.62" },
    { state: "uptodate" },
    { state: "failed", detail: "the network went away" },
  ]) {
    sendChecked({ state: "offered", offered: "0.9.62" });
    await flush();
    assert(banner().hidden === false, "setup: the banner should be showing");
    sendChecked(data);
    await flush();
    assert(
      banner().hidden === true,
      "state " +
        data.state +
        " left the banner up. That state belongs in the panel, and a banner " +
        "that never comes down stops meaning anything",
    );
  }
});

check("a malformed event changes nothing", async () => {
  sendChecked({ state: "offered", offered: "0.9.62" });
  await flush();
  sendChecked(undefined);
  await flush();
  assert(
    banner().hidden === true,
    "an event with no payload must not leave a stale banner claiming an " +
      "update is waiting",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL  " + name);
    }
  }
  if (failures.length) {
    console.error("\nUPDATE BANNER GATE FAILED");
    for (const f of failures) console.error("  - " + f);
    process.exit(1);
  }
  console.log("\nUPDATE BANNER OK");
})();
