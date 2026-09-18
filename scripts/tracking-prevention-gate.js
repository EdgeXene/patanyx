// The Strict/Balanced WebView2 choice in the Privacy protections panel.
//
// This drives the real panel-open and button-click paths. It also pins the
// Rust runtime-application seam: persistence without applying to AppState is
// the exact half-feature this gate must reject.
//
// Run: node scripts/tracking-prevention-gate.js
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
const ipc = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, message) {
  if (!cond) throw new Error(message);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};
const normalize = (text) => text.replace(/\s+/g, " ").trim();

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

async function openWith(status) {
  global.rbResolve = {
    privacy_get: {},
    tracking_prevention_get: status,
    fingerprint_noise_get: { enabled: true },
    dns_get: { supported: false },
    permission_status: { supported: false, entries: [] },
  };
  if (global.$("privacy-panel").hidden === false) {
    global.$("btn-privacy")._fire("click");
    await flush();
  }
  global.$("btn-privacy")._fire("click");
  await flush();
}

check("the row and both choices exist", () => {
  for (const id of [
    "tracking-prevention-choice",
    "tracking-prevention-strict",
    "tracking-prevention-balanced",
    "tracking-prevention-caption",
    "tracking-prevention-scope",
  ]) {
    assert(global.$(id), `Privacy protections lost #${id}`);
  }
});

check("the trade-off and runtime scope captions stay pinned", () => {
  const copy = normalize(html);
  for (const required of [
    "Strict blocks the most and can break some sites, including Google apps.",
    "Balanced is WebView2's default and rarely breaks anything.",
    "PATANYX's own blocker works the same under both.",
    "A change reaches the WebView2 profiles behind tabs open now and tabs opened later.",
    "PATANYX does not reload a page; reload it to give the next navigation the new level from its first request.",
  ]) {
    assert(copy.includes(required), `caption lost required copy: ${required}`);
  }
});

check("WebKitGTK does not show a level control it cannot honor", async () => {
  await openWith({ supported: false, level: "strict" });
  assert(
    global.$("tracking-prevention-choice").hidden === true,
    "the Strict/Balanced row must be absent where the engine only has ITP on/off",
  );
});

check("opening the Windows row reflects the persisted choice", async () => {
  for (const level of ["strict", "balanced"]) {
    await openWith({ supported: true, level });
    assert(
      global.$("tracking-prevention-choice").hidden === false,
      "the WebView2 row is still hidden on Windows",
    );
    for (const candidate of ["strict", "balanced"]) {
      assert(
        global.$("tracking-prevention-" + candidate).classList.contains("active") ===
          (candidate === level),
        `${level} was reported but ${candidate} has the wrong selected state`,
      );
    }
  }
});

check("both choices are reachable through the live setter", async () => {
  await openWith({ supported: true, level: "strict" });
  for (const level of ["balanced", "strict"]) {
    global.rbResolve.tracking_prevention_set = {
      supported: true,
      level,
      applied: true,
    };
    global.rbCalls.length = 0;
    global.$("tracking-prevention-" + level)._fire("click");
    await flush();
    const calls = global.rbCalls.filter(
      (call) => call.cmd === "tracking_prevention_set",
    );
    assert(
      calls.length === 1 && calls[0].args && calls[0].args.level === level,
      `${level} did not send exactly one tracking_prevention_set: ${JSON.stringify(calls)}`,
    );
    assert(
      global.$("tracking-prevention-" + level).classList.contains("active"),
      `${level} was not selected after Rust confirmed it`,
    );
  }
});

check("the persisted setter applies to live AppState profiles", () => {
  assert(
    /"tracking_prevention_set"\s*=>[\s\S]*?prefs::save\(&p\)[\s\S]*?state\.set_tracking_prevention\(level\)/.test(
      ipc,
    ),
    "tracking_prevention_set saves the preference but does not call the live-profile apply seam",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (error) {
      failures.push(name + "\n      " + error.message);
      console.log("  FAIL " + name);
    }
  }
  if (failures.length) {
    console.error("\nTRACKING-PREVENTION GATE FAILED:\n");
    for (const failure of failures) console.error("  - " + failure + "\n");
    process.exit(1);
  }
  console.log("\nTRACKING-PREVENTION UI OK");
})();
