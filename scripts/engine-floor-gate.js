// The "engine below the security floor" banner, driven through the REAL boot
// path: chrome.js asks `engine_status` as it loads and renders the reply.
//
// WHY THIS EXISTS. CVE-2026-87491 (exploited in the wild) was fixed in
// WebView2 runtime 152.0.4191.66, as CVE-2026-85046 was in .62 two days
// before it. PATANYX links whatever
// Evergreen runtime the machine has, so for the days between the Edge
// release and the rollout reaching a given PC, the browser is running an
// engine with a known exploited bug and, before this banner, said nothing.
// The banner is the only thing that tells the user, so it is pinned in
// both directions:
//
//   * it appears on `below_floor: true` and renders the Rust-composed body
//     VERBATIM (the wording is catalog property, pinned by the Rust test and
//     the claims manifest, never re-worded here);
//   * it stays hidden on a clean runtime, and on a FAILED reply -- unknown is
//     not unsafe, and a false alarm raised by an IPC hiccup is how people
//     learn to dismiss the banner that matters;
//   * Dismiss hides it and re-syncs the chrome strip, like every banner.
//
// The boot fetch runs once per chrome.js load, so each scenario is its own
// process: this file re-executes itself with SCENARIO set.
//
// Run: node scripts/engine-floor-gate.js  (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const scenario = process.env.ENGINE_FLOOR_SCENARIO;

if (!scenario) {
  // Parent: run each scenario in a fresh process and report.
  let failed = 0;
  for (const name of ["below", "clean", "failed", "raised", "restart"]) {
    try {
      execFileSync(process.execPath, [__filename], {
        env: { ...process.env, ENGINE_FLOOR_SCENARIO: name },
        stdio: "inherit",
      });
    } catch (e) {
      failed += 1;
    }
  }
  if (failed) {
    console.error(`engine-floor gate: ${failed} scenario(s) FAILED`);
    process.exit(1);
  }
  console.log("engine-floor gate: all scenarios passed");
  process.exit(0);
}

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

// The body arrives COMPOSED from Rust (platform::engine_floor_body). The
// stub supplies one the way the real reply does, built from the real
// catalog so the honesty checks below judge words a user actually reads.
const ftl = fs.readFileSync(
  path.join(root, "crates/app/src/chrome/i18n/locales/en.ftl"),
  "utf8",
);
function ftlValue(id) {
  const m = ftl.match(new RegExp("^" + id + " = (.*)$", "m"));
  if (!m) throw new Error("en.ftl is missing " + id);
  return m[1];
}
const FOUND = "152.0.4191.62";
const FLOOR = "152.0.4191.66";
const body =
  ftlValue("chrome-engine-floor-body")
    .replace("{ $engine }", "WebView2")
    .replace("{ $version }", FOUND)
    .replace("{ $floor }", FLOOR) +
  " " +
  ftlValue("chrome-engine-floor-evergreen");

// INSTALLED NEWER, RUNNING OLDER: the Evergreen runtime updated under an
// open browser. Rust composes the restart body (chrome-engine-floor-body-
// restart) and the chrome renders it verbatim like the other one.
const INSTALLED = "152.0.4191.70";
const restartBody = ftlValue("chrome-engine-floor-body-restart")
  .replace("{ $engine }", "WebView2")
  .replace("{ $version }", FOUND)
  .replace("{ $floor }", FLOOR)
  .replace("{ $installed }", INSTALLED);

const replies = {
  restart: {
    name: "WebView2",
    version: FOUND,
    floor: FLOOR,
    below_floor: true,
    body: restartBody,
    version_source: "running",
    installed: INSTALLED,
    restart_clears: true,
  },
  below: {
    name: "WebView2",
    version: FOUND,
    floor: FLOOR,
    below_floor: true,
    body,
  },
  clean: {
    name: "WebView2",
    version: "152.0.4191.70",
    floor: FLOOR,
    below_floor: false,
    body: "",
  },
};
if (scenario === "failed") {
  global.rbReject = "unsupported";
} else if (scenario === "raised") {
  // Boots clean; the floor rises later, via the event Rust pushes after a
  // verified manifest raised it (main.rs, UpdateChecked).
  global.rbResolve["engine_status"] = replies.clean;
} else {
  global.rbResolve["engine_status"] = replies[scenario];
}

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

function banner() {
  return global.$("engine-floor-warning");
}
function bodyText() {
  return global.$("engine-floor-body").textContent || "";
}

(async () => {
  await flush();
  const asked = global.rbCalls.some(
    (call) =>
      (Array.isArray(call) ? call[0] : call && call.cmd) === "engine_status",
  );
  assert(
    asked,
    "chrome.js never asked engine_status at boot; the banner has no producer",
  );

  if (scenario === "below") {
    assert(
      banner().hidden === false,
      "a runtime below the floor raised no banner",
    );
    assert(
      bodyText() === body,
      "the body was not rendered verbatim:\n  " + JSON.stringify(bodyText()),
    );
    assert(
      bodyText().includes(FOUND) && bodyText().includes(FLOOR),
      "the banner must name the version found and the version that clears the floor",
    );
    // THE CLAIMS THIS GATE EXISTS FOR. Nothing in PATANYX can fetch the
    // engine, so the banner may not say it will, and it may not claim the
    // user is being attacked -- below the floor means exposed, not exploited.
    const lower = bodyText().toLowerCase();
    assert(
      !/patanyx (will|is going to|can) (update|install|download)/.test(lower),
      "the banner promises an update PATANYX cannot perform",
    );
    assert(
      !/(you are|you have been|is being) (hacked|attacked|exploited)/.test(
        lower,
      ),
      "the banner asserts an attack it cannot know about",
    );
    // Dismiss: hidden, and the strip re-synced (the domstub records it).
    global.$("engine-floor-dismiss").click();
    await flush();
    assert(banner().hidden === true, "Dismiss did not hide the banner");
    console.log("  below: banner shown, body verbatim, dismiss hides -- ok");
  } else if (scenario === "clean") {
    assert(
      banner().hidden === true,
      "a runtime at or above the floor raised the banner",
    );
    console.log("  clean: banner hidden -- ok");
  } else if (scenario === "restart") {
    assert(banner().hidden === false, "installed-newer/running-older raised no banner");
    assert(bodyText() === restartBody, "the restart body was not rendered verbatim");
    assert(
      bodyText().includes(FOUND) && bodyText().includes(INSTALLED),
      "the restart banner must name the running and the installed version",
    );
    const lower = bodyText().toLowerCase();
    assert(lower.includes("restart"), "the restart banner must say a restart clears it");
    assert(
      !lower.includes("still use an older version") || lower.includes("already installed"),
      "the restart banner must name the installed build rather than only the session's older engine",
    );
    assert(
      !/patanyx (will|is going to|can) (update|install|download)/.test(lower),
      "the banner promises an update PATANYX cannot perform",
    );
    console.log("  restart: banner shown, installed named, no false claim -- ok");
  } else if (scenario === "raised") {
    assert(banner().hidden === true, "setup: clean boot should show no banner");
    global.window.__rb_event({ event: "engine_state", data: replies.below });
    await flush();
    assert(
      banner().hidden === false,
      "a floor raised mid-session (engine_state event) showed no banner",
    );
    assert(bodyText() === body, "the pushed body was not rendered verbatim");
    console.log("  raised mid-session: banner shown -- ok");
  } else {
    assert(
      banner().hidden === true,
      "a FAILED engine_status reply raised the banner; unknown is not unsafe",
    );
    console.log("  failed reply: banner hidden -- ok");
  }
})().catch((e) => {
  console.error("engine-floor gate [" + scenario + "]: " + e.message);
  process.exit(1);
});
