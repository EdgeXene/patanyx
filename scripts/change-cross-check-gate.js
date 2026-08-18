// Change Cross-Check reports where to look, never what happened.
//
// The finding this feature exists to surface is "it changed for you and not
// for them", and it is the one most easily turned into an accusation. So
// this pins:
//
//   1. The headline is Rust's, verbatim. This panel places wording and never
//      composes a claim.
//   2. Its own caveats render WITH every verdict, and they are NOT the
//      corroboration ones: change over time has different innocent causes
//      than being served differently right now.
//   3. No verdict ever says targeted, manipulated, attacked or tampered.
//   4. A peer's refusal is worded here from a closed set, never echoed.
//   5. An automatic answer to a contact is announced.
//
// Proven against planted defects: composing the headline in JS fails 1 and
// 3, dropping the caveat list fails 2, echoing the peer's reason fails 4.
//
// Guard shape: chrome-js-gate.sh refuses to run this when integrity.js is
// gone, so removing the surface cannot silently retire the gate.
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

// chrome.js first: integrity.js opens with `if (!window.__rb) return;` and
// would otherwise run about fifteen lines and exit, passing vacuously.
new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();
new Function(fs.readFileSync(path.join(chromeDir, "integrity.js"), "utf8"))();

const fire = (event, data) => global.window.__rb_event({ event, data });

// Rust's own headline for the pointed case, as the crate emits it.
const RUST_TEXT =
  "This page changed for you, and your contact's copy still matches what " +
  "they saved. Caches, regional editions and simple timing all produce " +
  "that, so treat it as a reason to look closer rather than a conclusion. " +
  "Comparing what each of you sees now is the next useful step.";

check("the headline is Rust's, placed and never rewritten", async () => {
  fire("change_compare_verdict", {
    peer_hash: "abc",
    url: "https://news.example/story",
    text: RUST_TEXT,
    my_change: "text_differs",
    their_change: "same",
    now: "text_differs",
    baselines: "same",
    baseline_gap_seconds: 7200,
  });
  await flush();
  assert(
    global.allText().includes(RUST_TEXT),
    "the crate's sentence must reach the DOM verbatim",
  );
});

check("no verdict reads as an accusation", async () => {
  const seen = global.allText().join(" ").toLowerCase();
  for (const word of [
    "targeted",
    "manipulat",
    "attack",
    "tamper",
    "malicious",
  ]) {
    assert(
      !seen.includes(word),
      `the panel said "${word}" about a page change, which the evidence does ` +
        "not support",
    );
  }
});

check("its own caveats render with the verdict", async () => {
  const seen = global.allText().join(" ").toLowerCase();
  // These are the CHANGE caveats, not the corroboration ones. If this ever
  // matches the corroboration wording instead, the two sections have been
  // collapsed and the distinction the feature rests on is gone.
  assert(
    seen.includes("caches, regional editions"),
    "the innocent-causes caveat for change over time must appear",
  );
  assert(
    seen.includes("saved at different times"),
    "the baseline-age caveat must appear",
  );
  assert(
    seen.includes("says where to look"),
    "the no-conclusion caveat must appear",
  );
});

check("the baseline gap reaches the reader", async () => {
  const seen = global.allText().join(" ");
  assert(
    /hours apart/.test(seen),
    "two baselines made hours apart is the most ordinary explanation there " +
      "is, and must be shown",
  );
});

check("a peer's refusal is worded here, never echoed", async () => {
  fire("change_compare_note", {
    peer_hash: "abc",
    reason: "<script>alert(1)</script> your page was altered",
  });
  await flush();
  const seen = global.allText().join(" ");
  assert(
    !seen.includes("was altered") && !seen.includes("<script>"),
    "a peer-supplied reason reached the screen",
  );
});

check("an automatic answer to a contact is announced", async () => {
  fire("change_compare_request_received", {
    peer_hash: "abc",
    url: "https://news.example/story",
  });
  await flush();
  // NOT a slice from a saved length: allText() flattens by ELEMENT order,
  // not by when each string was set, so a "what is new since" slice reads
  // the wrong tail and passes or fails for the wrong reason. Presence in
  // the document is the property that matters anyway.
  const seen = global.allText().join(" ").toLowerCase();
  assert(
    seen.includes("a contact asked"),
    "answering a contact automatically must be visible to the user",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL: " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error(
      "change-cross-check-gate: " + failures.length + " check(s) failed",
    );
    process.exit(1);
  }
  console.log("change-cross-check-gate OK (" + checks.length + " checks)");
})();
