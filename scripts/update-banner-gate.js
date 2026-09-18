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
// THE KIND SPLIT. `kind`, `security` and `auto_apply` joined the snapshot
// when updates learned to install themselves, and they change WHO the banner
// is for:
//
//   auto off  every offered/ready release announces, exactly as before
//   auto on   a release that will install ITSELF at the next launch
//             (maintenance, or anything carrying a security fix) says
//             nothing -- announcing a decision nobody has to make is how a
//             banner trains people to dismiss the one that matters
//   auto on   a pure feature release still announces, because changing what
//             the user sees without warning is the thing this split exists
//             to prevent
//
// The absent-field case is load-bearing and is covered by the first checks
// below omitting the fields entirely: every manifest published before this
// existed carries none of them, and must keep behaving exactly as it did.
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
    // The feature wording is newer and says the most, so it is the likeliest
    // to drift into claiming the install already happened.
    { state: "ready", offered: "0.9.67", kind: "feature", auto_apply: true },
    { state: "ready", offered: "0.9.67", kind: "feature", auto_apply: false },
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

// ---- the kind split -------------------------------------------------------

check("with automatic updates on, a release that installs itself says nothing", async () => {
  for (const data of [
    { state: "ready", offered: "0.9.67", auto_apply: true, kind: "maintenance", security: false },
    { state: "offered", offered: "0.9.67", auto_apply: true, kind: "maintenance", security: false },
    // A security fix takes the quiet path even inside a feature release --
    // that is the entire reason `security` is a field of its own and not a
    // third kind. It installs at the next launch, so there is nothing to ask.
    { state: "ready", offered: "0.9.67", auto_apply: true, kind: "feature", security: true },
  ]) {
    sendChecked({ state: "uptodate" });
    await flush();
    sendChecked(data);
    await flush();
    assert(
      banner().hidden === true,
      "kind=" +
        data.kind +
        " security=" +
        data.security +
        " raised a banner while automatic updates were on. That release " +
        "installs itself at the next launch, so the banner is asking for a " +
        "decision nobody has to make",
    );
  }
});

check("a feature release announces itself in both modes", async () => {
  // Auto ON: it lands on its own eventually, and the banner has to say so.
  // Without that clause "restart when it suits you" is not the whole truth.
  sendChecked({ state: "uptodate" });
  await flush();
  sendChecked({
    state: "ready",
    offered: "0.9.67",
    auto_apply: true,
    kind: "feature",
    security: false,
  });
  await flush();
  assert(
    banner().hidden === false,
    "a feature release raised no banner with automatic updates on. This is " +
      "the one release type that changes what the user sees, and it is the " +
      "only thing the banner still exists for in auto mode",
  );
  assert(
    /new features/i.test(bodyText()),
    "the feature banner does not say the thing that makes it worth reading: " +
      "that this release adds something new",
  );
  assert(
    /on its own/i.test(bodyText()),
    "with automatic updates on, the banner must disclose that an ignored " +
      "feature release installs itself once the grace period lapses",
  );

  // Auto OFF: the same announcement, minus a sentence that would be false.
  sendChecked({ state: "uptodate" });
  await flush();
  sendChecked({
    state: "ready",
    offered: "0.9.67",
    auto_apply: false,
    kind: "feature",
    security: false,
  });
  await flush();
  assert(
    banner().hidden === false,
    "a feature release raised no banner with automatic updates off",
  );
  assert(
    /new features/i.test(bodyText()),
    "the feature banner lost its point with automatic updates off",
  );
  assert(
    !/on its own/i.test(bodyText()),
    "with automatic updates OFF nothing installs itself, so the banner must " +
      "not tell the user it will",
  );
});

check("a feature OFFER is honest about what has not been downloaded", async () => {
  // The coverage gap a compliance audit caught after this gate first went
  // green: every feature row above is `ready`. In `offered` nothing has been
  // fetched, so "restart to get them" names an action that installs nothing,
  // and a self-install promise is false -- apply_pending_at_startup needs a
  // STAGED release, which only the ready path writes.
  sendChecked({ state: "uptodate" });
  await flush();
  sendChecked({
    state: "offered",
    offered: "0.9.67",
    auto_apply: true,
    kind: "feature",
    security: false,
  });
  await flush();
  assert(banner().hidden === false, "a feature offer raised no banner");
  assert(
    /nothing has been downloaded/i.test(bodyText()),
    "the feature-offer banner does not say nothing has been downloaded, so " +
      "it reads as though the bytes are already here",
  );
  assert(
    !/on its own/i.test(bodyText()),
    "the feature-offer banner promises a self-install, but nothing is " +
      "staged and nothing can apply at a launch",
  );
  assert(
    !/restart .*to get them/i.test(bodyText()),
    "the feature-offer banner tells the user to restart, which installs " +
      "nothing in the offered state",
  );
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
