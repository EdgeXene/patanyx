// Region-read panel gate: executes the REAL chrome.js against the DOM stub
// and drives the "Read text on this page" panel through the same
// window.__rb_event and window.ipc wire the browser uses. Each check pins
// one honesty rule. View-to-source geometry is a deliberately exported pure
// function, so zoom and pan can be pinned here without pretending the DOM
// stub has browser layout. WP-AK adds the persisted full-page/viewport
// picker: this gate drives both options and makes the finished caption answer
// the event's ACTUAL scope, never merely the selected preference.
//
// Proven against a planted defect during development: with the
// premium-note unhide removed from regionStart's catch, checks 2 and 3
// fail; with the openPanelName guard removed from onRegionCaptureReady, a
// closed-panel event painted the stage and check 6 failed. WP-AK plant proof:
// forcing the viewport event through the full-page caption arm fails the
// scope-caption check below. WP-Z plant proof:
// deleting the previewToSource ratio at the scan call site fails the mapping-
// wire check with "selection stopped applying"; restoring it returns green.
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
const mapRegion = (args) => global.window.__rb_region_view_to_source(args);
const sameRect = (actual, expected) =>
  ["x", "y", "w", "h"].every((k) => actual[k] === expected[k]);

check("a region size refusal never pretends the capture is a bad file", async () => {
  const region = global.window.__rb.friendly(new Error("region_too_large"));
  assert(
    region ===
      "This page or selection is too large to read safely. Try a shorter page, or zoom in and select a smaller area.",
    "region_too_large lost its actionable region-panel sentence",
  );
  assert(
    !/file|PNG|JPEG/i.test(region),
    "an in-memory capture must not wear file-picker format copy",
  );
  const file = global.window.__rb.friendly(new Error("bad_image"));
  assert(
    /file/.test(file) && /PNG/.test(file) && /JPEG/.test(file),
    "the real file-picker refusal lost its format guidance",
  );
});

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

check("both scope options are reachable and persist one shared choice", async () => {
  await grantPremium();
  global.rbCalls.length = 0;
  $("btn-ocr-region").click();
  await flush();
  assert(
    captureCalls().length === 0,
    "opening must leave time to choose a scope before capture",
  );

  global.rbResolve.capture_scope_set = { scope: "viewport" };
  $("region-scope-viewport").click();
  await flush();
  assert(
    global.rbCalls.some(
      (c) => c.cmd === "capture_scope_set" && c.args.scope === "viewport",
    ),
    "Just what's on screen never reached persistence",
  );
  assert(
    $("region-scope-viewport").classList.contains("active"),
    "the viewport option did not become selected",
  );
  assert(
    $("recall-scope-viewport").classList.contains("active"),
    "Deep Recall did not mirror the shared viewport choice",
  );

  global.rbResolve.capture_scope_set = { scope: "full_page" };
  $("region-scope-full").click();
  await flush();
  assert(
    global.rbCalls.some(
      (c) => c.cmd === "capture_scope_set" && c.args.scope === "full_page",
    ),
    "Full page never reached persistence",
  );
  assert(
    $("region-scope-full").classList.contains("active"),
    "the full-page option did not become selected",
  );
});

check("Capture page uses the remembered choice", async () => {
  global.rbResolve.capture_scope_get = { scope: "viewport" };
  global.rbCalls.length = 0;
  $("region-capture").click();
  await flush();
  assert(
    global.rbCalls.some((c) => c.cmd === "capture_scope_get"),
    "capture did not re-read the persisted scope",
  );
  assert(
    captureCalls().length === 1,
    "Capture page must call ocr_region_capture exactly once",
  );
});

check("premium_required is a state the panel shows, not a toast", async () => {
  // Close, then reopen with the licence refusing: the note must be
  // visible and must still be visible after a second refusal (a state,
  // not a flash).
  $("btn-ocr-region").click();
  await flush();
  global.rbReject = "premium_required";
  $("btn-ocr-region").click();
  await flush();
  $("region-capture").click();
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

check("a ready capture paints the stage and captions its actual scope", async () => {
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
    preview_w: 640,
    preview_h: 480,
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
    $("region-scope").textContent.startsWith(
      "The picture is the part that was on screen.",
    ),
    "the viewport event must use the established on-screen wording: " +
      $("region-scope").textContent,
  );

  // Force the opposite actual result while the remembered choice remains
  // viewport. The caption follows the event, proving it is not a UI echo.
  fire("region_capture_ready", {
    ok: true,
    token: 6,
    w: 640,
    h: 1800,
    preview_w: 640,
    preview_h: 1800,
    scope: "full page",
  });
  await flush();
  assert(
    $("region-scope").textContent.startsWith("The picture is complete."),
    "the full-page event must use the established complete-picture wording: " +
      $("region-scope").textContent,
  );
});

check("view-to-source mapping pins 1x, zoom, pan, and bounds", async () => {
  assert(typeof mapRegion === "function", "the pure mapper must be exported");
  const oneToOne = mapRegion({
    zoom: 1,
    pan: { x: 0, y: 0 },
    viewport: { width: 500, height: 300 },
    source: { width: 500, height: 300 },
    previewToSource: { x: 1, y: 1 },
    rect: { x: 40, y: 30, w: 120, h: 70 },
  });
  assert(
    sameRect(oneToOne, { x: 40, y: 30, w: 120, h: 70 }),
    "1x must be a no-op at one source pixel per view pixel: " +
      JSON.stringify(oneToOne),
  );

  const fitted = mapRegion({
    zoom: 1,
    pan: { x: 0, y: 0 },
    viewport: { width: 500, height: 300 },
    source: { width: 1000, height: 800 },
    previewToSource: { x: 1, y: 1 },
    rect: { x: 50, y: 20, w: 100, h: 60 },
  });
  assert(
    sameRect(fitted, { x: 100, y: 40, w: 200, h: 120 }),
    "the width-fitted 1x preview must map by its fit scale: " +
      JSON.stringify(fitted),
  );

  const clipped = mapRegion({
    zoom: 2,
    pan: { x: 850, y: 650 },
    viewport: { width: 500, height: 300 },
    source: { width: 1000, height: 800 },
    previewToSource: { x: 1, y: 1 },
    rect: { x: 100, y: 100, w: 200, h: 200 },
  });
  assert(
    sameRect(clipped, { x: 950, y: 750, w: 50, h: 50 }),
    "zoomed panning must clamp at the source edge: " + JSON.stringify(clipped),
  );
});

check("equivalent 1x and 2x selections crop identical source pixels", async () => {
  const common = {
    viewport: { width: 500, height: 300 },
    source: { width: 1000, height: 800 },
    previewToSource: { x: 1, y: 1 },
  };
  const atOne = mapRegion({
    ...common,
    zoom: 1,
    pan: { x: 0, y: 0 },
    rect: { x: 150, y: 75, w: 100, h: 50 },
  });
  const atTwo = mapRegion({
    ...common,
    zoom: 2,
    pan: { x: 200, y: 100 },
    rect: { x: 100, y: 50, w: 200, h: 100 },
  });
  assert(
    sameRect(atOne, { x: 300, y: 150, w: 200, h: 100 }),
    "the 1x fixture mapped unexpectedly: " + JSON.stringify(atOne),
  );
  assert(
    sameRect(atTwo, atOne),
    "2x selected different source pixels: " + JSON.stringify(atTwo),
  );
});

check(
  "a downscaled preview maps the same source rect at several zooms",
  async () => {
    const common = {
      viewport: { width: 500, height: 320 },
      source: { width: 4000, height: 12000 },
      // The bounded preview is 1000x3000. These ratios are the only bridge
      // from its pixels back to the untouched native capture.
      previewToSource: { x: 4, y: 4 },
    };
    const expected = { x: 800, y: 1600, w: 600, h: 400 };
    const fixtures = [
      {
        zoom: 1,
        pan: { x: 0, y: 0 },
        rect: { x: 100, y: 200, w: 75, h: 50 },
      },
      {
        zoom: 2,
        pan: { x: 100, y: 300 },
        rect: { x: 100, y: 100, w: 150, h: 100 },
      },
      {
        zoom: 4,
        pan: { x: 300, y: 700 },
        rect: { x: 100, y: 100, w: 300, h: 200 },
      },
    ];
    for (const fixture of fixtures) {
      const actual = mapRegion({ ...common, ...fixture });
      assert(
        sameRect(actual, expected),
        "downscaled mapping drifted at " +
          fixture.zoom +
          "x: " +
          JSON.stringify(actual),
      );
    }
  },
);

check("zoom controls and wheel are reachable", async () => {
  assert($("region-zoom-in")._has("click"), "Zoom in has no click handler");
  assert($("region-zoom-out")._has("click"), "Zoom out has no click handler");
  assert($("region-stage")._has("wheel"), "the preview has no wheel zoom");
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  assert(
    /id="region-zoom-in"[\s\S]*?aria-label="Zoom in"/.test(html),
    "Zoom in must be a labelled native button",
  );
  assert(
    /id="region-zoom-out"[\s\S]*?aria-label="Zoom out"/.test(html),
    "Zoom out must be a labelled native button",
  );
});

check("the scan wire uses the pure source mapper", async () => {
  const start = chromeJs.indexOf('regionStage.addEventListener("pointerup"');
  const end = chromeJs.indexOf('regionStage.addEventListener("pointercancel"');
  const pointerUp = chromeJs.slice(start, end);
  assert(start >= 0 && end > start, "the selection pointer-up arm is missing");
  assert(
    pointerUp.includes("regionViewToSource({"),
    "selection stopped crossing the tested view-to-source boundary",
  );
  assert(
    pointerUp.includes("previewToSource:") &&
      pointerUp.includes("regionCapture.w / regionCapture.previewW") &&
      pointerUp.includes("regionCapture.h / regionCapture.previewH"),
    "selection stopped applying the bounded-preview-to-source ratio",
  );
  assert(
    pointerUp.includes('rb("ocr_region_scan"'),
    "the mapped source rect no longer reaches the OCR command",
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

check("capture failures stay distinct and a size refusal gives a remedy", async () => {
  fire("region_capture_ready", { ok: false, error: "capture_engine_failed" });
  await flush();
  const engine = $("region-status").textContent;
  fire("region_capture_ready", { ok: false, error: "capture_decode_failed" });
  await flush();
  const decode = $("region-status").textContent;
  assert(engine && decode && engine !== decode, "engine and PNG failures merged");

  fire("region_capture_ready", { ok: false, error: "capture_too_large" });
  await flush();
  assert(
    /smaller window|zoomed-in selection/i.test($("region-status").textContent),
    "the too-large refusal must tell the user what works instead",
  );
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

check("a leak-check refusal AFTER the precheck is explained as Premium", async () => {
  // The race: premium_status says active when the button is pressed, so the
  // UI precheck passes; the licence changes before ocr_scan runs, so the arm
  // refuses. That refusal must carry the shared Premium sentence, not the
  // tab pack's wording the generic error table maps the code to.
  global.rbReject = null;
  global.rbResolve.premium_status = { state: "active", premium: true, on_sale: true };
  global.rbResolve.file_pick_open = { path: "/tmp/x.png", token: 7 };
  global.rbResolve.ocr_scan = new Error("premium_required");
  $("leakcheck-pick").click();
  await flush();
  const err = $("leakcheck-error");
  const text = err._text[err._text.length - 1] || "";
  assert(/Premium/.test(text), "the error must name Premium: " + JSON.stringify(text));
  assert(!/Find across tabs/.test(text), "never the tab pack's sentence: " + JSON.stringify(text));
  delete global.rbResolve.ocr_scan;
  delete global.rbResolve.file_pick_open;
  delete global.rbResolve.premium_status;
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
