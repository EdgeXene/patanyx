// Region-read panel gate: executes the REAL chrome.js against the DOM stub
// and drives the "Read text on this page" panel through the same
// window.__rb_event and window.ipc wire the browser uses. Each check pins
// one honesty rule; the drag state machine itself is NOT driven here
// because the stub has no layout (clientWidth is 0 and every drag would be
// a click) -- the rect mapping is pinned by Rust-side tests instead.
//
// Proven against a planted defect during development: with the
// premium-note unhide removed from regionStart's catch, checks 2 and 3
// fail; with the openPanelName guard removed from onRegionCaptureReady, a
// closed-panel event painted the stage and check 6 failed.
//
// Guard shape: chrome-js-gate.sh refuses to run this file when
// #region-panel is gone from index.html, so removing the surface cannot
// silently retire its gate.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
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

new Function(chromeJs)();

const $ = (id) => global.document.getElementById(id);
const fire = (event, data) => global.window.__rb_event({ event, data });
const captureCalls = () =>
  global.rbCalls.filter((c) => c.cmd === "ocr_region_capture");

// The toolbar starts LOCKED and is unlocked only by an answer from Rust, so
// every check that expects the feature to RUN must grant a licence first.
const grantPremium = async (state = "active") => {
  global.rbResolve.premium_status = { state, premium: true, on_sale: false };
  // Opening and closing the panel is enough to make chrome.js ask again.
  $("btn-ocr-region").click();
  await flush();
  $("btn-ocr-region").click();
  await flush();
};

check("a locked toolbar never even asks Rust to capture", async () => {
  // The default state: no licence. The OLD behavior was to capture first
  // and refuse afterwards, which is exactly what this check now forbids.
  global.rbResolve.premium_status = {
    state: "locked",
    premium: false,
    on_sale: false,
  };
  $("btn-ocr-region").click();
  await flush();
  $("btn-ocr-region").click();
  await flush();
  global.rbCalls.length = 0;
  $("btn-ocr-region").click();
  await flush();
  assert(
    captureCalls().length === 0,
    "a locked control must not start a capture it cannot finish",
  );
  assert(
    !$("region-premium").hidden,
    "the panel must say why instead of looking empty",
  );
  $("btn-ocr-region").click();
  await flush();
});

check(
  "opening the panel asks Rust to capture, nothing else starts one",
  async () => {
    await grantPremium();
    global.rbCalls.length = 0;
    $("btn-ocr-region").click();
    await flush();
    assert(
      captureCalls().length === 1,
      "open must call ocr_region_capture once",
    );
  },
);

check("premium_required is a state the panel shows, not a toast", async () => {
  // Close, then reopen with the licence refusing: the note must be
  // visible and must still be visible after a second refusal (a state,
  // not a flash).
  $("btn-ocr-region").click();
  await flush();
  global.rbReject = "premium_required";
  $("btn-ocr-region").click();
  await flush();
  assert(!$("region-premium").hidden, "the premium note must be shown");
  global.rbReject = null;
});

check("the note survives a re-render and names the vault row", async () => {
  assert(!$("region-premium").hidden, "note must persist after the refusal");
  // The note's wording is markup-authored, which the stub does not carry
  // as textContent; pin the phrasing from the source of truth instead.
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  const note = html.match(/id="region-premium"[^>]*>([\s\S]*?)<\/p>/);
  assert(note, "index.html must carry the #region-premium note");
  assert(
    /vault/i.test(note[1]),
    "the note must point at the Premium vault row",
  );
  // "never free" is BANNED from user-facing copy (settled 2026-08-11: it
  // reads as an accusation). Pinned here so it cannot creep back.
  assert(
    !/never free/i.test(note[1]),
    "the never-free phrasing is banned from user-facing copy",
  );
});

check("a ready capture paints the stage from the token alone", async () => {
  // Fresh open with the licence allowing again.
  $("btn-ocr-region").click();
  await flush();
  $("btn-ocr-region").click();
  await flush();
  fire("region_capture_ready", {
    ok: true,
    token: 5,
    w: 640,
    h: 480,
    scope: "visible area",
  });
  await flush();
  assert(
    $("region-img").getAttribute("src") === "/region-capture/5.png",
    "img src must be the token-addressed protocol path, got: " +
      $("region-img").getAttribute("src"),
  );
  assert(!$("region-stage").hidden, "the stage must be visible");
  assert(
    /visible area/.test($("region-scope").textContent),
    "the scope line must state what the capture covers",
  );
});

check("a failed capture is a sentence, and the stage stays down", async () => {
  $("btn-ocr-region").click();
  await flush();
  $("btn-ocr-region").click();
  await flush();
  fire("region_capture_ready", { ok: false, error: "no_capture_page" });
  await flush();
  assert(
    $("region-status").textContent.length > 0,
    "the failure must be worded, not silent",
  );
  assert($("region-stage").hidden, "no stage without a capture");
});

check("a capture landing after close paints nothing", async () => {
  // Panel is open from the previous check; close it.
  $("btn-ocr-region").click();
  await flush();
  const closes = global.rbCalls.filter((c) => c.cmd === "ocr_region_close");
  assert(closes.length >= 1, "closing must release the capture");
  assert(
    !$("region-img").getAttribute("src"),
    "closing must drop the image src",
  );
  fire("region_capture_ready", {
    ok: true,
    token: 9,
    w: 10,
    h: 10,
    scope: "x",
  });
  await flush();
  assert(
    !$("region-img").getAttribute("src"),
    "an event for a closed panel must not paint it",
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
    console.error("ocr-region-gate: " + failures.length + " check(s) failed");
    process.exit(1);
  }
  console.log("ocr-region-gate OK (" + checks.length + " checks)");
})();
