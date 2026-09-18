// The update channel row (update.js). 1.0.0 offers ONE channel. Behavioural
// checks run against the DOM harness so the file is EXECUTED rather than
// parsed.
//
// WHY THIS EXISTS. `manifest_url`'s "two fixed URLs, never a per-install
// one" property is Rust-side and has its own test in updater.rs
// (beta_and_stable_are_two_distinct_fixed_urls_not_a_query_string). What is
// only checkable here is that choosing Beta in the UI actually calls
// `update_channel_set` with the right value, that the panel reflects
// whatever Rust reports rather than just remembering the last click, and
// that a build with no update networking cannot "choose" a channel it can
// never fetch from.
//
// Run: node scripts/update-channel-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

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

// chrome.js first: it owns window.__rb, the request helper update.js calls.
for (const file of ["chrome.js", "update.js"]) {
  new Function(fs.readFileSync(path.join(chromeDir, file), "utf8"))();
}

function openUpdatePanel() {
  global.$("btn-update")._fire("click");
}

// The button is a TOGGLE: a click on an open panel closes it, and a closed
// panel never runs refreshChannel, so a check that "opens" an already-open
// panel measures stale state. Open only when actually closed.
function reopenUpdatePanel() {
  // refreshChannel runs in the panel's onOpen hook and nowhere else, so a
  // panel left open by an earlier check has to be closed and opened again
  // for a check to observe a FRESH read of the stored channel.
  if (!global.$("update-panel").hidden) openUpdatePanel();
  openUpdatePanel();
}

check("1.0.0 offers ONE channel: Stable is shown fixed, and there is no Beta button", async () => {
  global.rbResolve.update_status = { available: true, state: "idle" };
  global.rbResolve.update_channel_get = { channel: "stable" };
  global.rbCalls.length = 0;
  reopenUpdatePanel();
  await flush();
  const stable = global.$("update-channel-stable");
  assert(stable, "the Stable button was not built");
  assert(!global.$("update-channel-beta"), "a Beta button was built; there is no Beta in 1.0.0 (decided 2026-09-16)");
  assert(stable.disabled, "Stable must read as the channel this install follows, not a choice");
  assert(stable.style.fontWeight === "700", "Stable must be shown as the active channel");
  assert(
    !global.rbCalls.some((c) => c.cmd === "update_channel_set"),
    "opening the panel on Stable must not rewrite the stored channel",
  );
});

check("an install still stored on Beta is moved to Stable once, and told", async () => {
  global.rbResolve.update_status = { available: true, state: "idle" };
  global.rbResolve.update_channel_get = { channel: "beta" };
  global.rbResolve.update_channel_set = { channel: "stable" };
  global.rbCalls.length = 0;
  reopenUpdatePanel();
  await flush();
  const sets = global.rbCalls.filter((c) => c.cmd === "update_channel_set");
  assert(sets.length === 1, `expected exactly one update_channel_set, got ${sets.length}`);
  assert(sets[0].args && sets[0].args.channel === "stable", `moved to the wrong channel: ${JSON.stringify(sets[0].args)}`);
  const note = global.$("update-channel-note");
  assert(note, "the channel note was not built");
  assert(/Beta/.test(note.textContent) && /Stable/.test(note.textContent), `the note must say the install was on Beta and now follows Stable; got ${JSON.stringify(note.textContent)}`);
});

check("a build with no update networking still shows the fixed channel without offering a choice", async () => {
  global.rbResolve.update_status = { available: false, state: "idle" };
  global.rbResolve.update_channel_get = { channel: "stable" };
  reopenUpdatePanel();
  await flush();
  assert(global.$("update-channel-stable").disabled, "the channel control must never be a live choice");
  assert(!global.$("update-channel-beta"), "no Beta button in any build");
});

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
    console.error("\nUPDATE-CHANNEL GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nUPDATE-CHANNEL UI OK");
})();
