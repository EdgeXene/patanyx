// Staged/beta update channel (update.js's Stable/Beta row). Behavioural
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

check("opening Updates reflects the channel Rust reports", async () => {
  global.rbResolve.update_status = { available: true, state: "idle" };
  global.rbResolve.update_channel_get = { channel: "beta" };
  openUpdatePanel();
  await flush();
  const stable = global.$("update-channel-stable");
  const beta = global.$("update-channel-beta");
  assert(stable && beta, "the Stable/Beta buttons were not built");
  assert(
    beta.style.fontWeight === "700" && stable.style.fontWeight === "400",
    "the panel must reflect Rust's reported channel (beta), not default to " +
      "stable regardless of what update_channel_get returns",
  );
});

check(
  "clicking Beta calls update_channel_set with the right value",
  async () => {
    global.rbResolve.update_channel_get = { channel: "stable" };
    openUpdatePanel();
    await flush();
    global.rbCalls.length = 0;
    global.rbResolve.update_channel_set = { channel: "beta" };
    global.$("update-channel-beta")._fire("click");
    await flush();
    const call = global.rbCalls.find((c) => c.cmd === "update_channel_set");
    assert(call, "update_channel_set was not called");
    assert(
      call.args && call.args.channel === "beta",
      `update_channel_set was called with the wrong channel: ${JSON.stringify(call.args)}`,
    );
    assert(
      global.$("update-channel-beta").style.fontWeight === "700",
      "the panel did not switch to showing Beta as the active channel after " +
        "Rust confirmed the change",
    );
  },
);

check("clicking Stable switches back", async () => {
  global.rbResolve.update_channel_set = { channel: "stable" };
  global.$("update-channel-stable")._fire("click");
  await flush();
  assert(
    global.$("update-channel-stable").style.fontWeight === "700" &&
      global.$("update-channel-beta").style.fontWeight === "400",
    "Stable did not become the visibly active channel",
  );
});

check(
  "a build with no update networking cannot choose a channel it can never fetch from",
  async () => {
    global.rbResolve.update_status = { available: false, state: "idle" };
    openUpdatePanel();
    await flush();
    assert(
      global.$("update-channel-stable").disabled && global.$("update-channel-beta").disabled,
      "the channel buttons must be disabled when this build has no update " +
        "networking at all -- selecting a channel it can never fetch from " +
        "is not a real choice",
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
    console.error("\nUPDATE-CHANNEL GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nUPDATE-CHANNEL UI OK");
})();
