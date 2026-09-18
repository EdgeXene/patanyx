// Fingerprint probe reporting must be both reachable and honestly labelled.
// This gate drives the real Tab Activity open path, then executes the real
// divergence wrappers with native-shaped sentinels and inspects the one
// delayed host message. Source greps alone would let a dead reporting helper
// pass, which is why the wrappers and timer are actually called here.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const stateRs = fs.readFileSync(path.join(root, "crates/app/src/state.rs"), "utf8");
const ipcRs = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
const windowsRs = fs.readFileSync(
  path.join(root, "crates/app/src/platform/windows.rs"),
  "utf8",
);
const unixRs = fs.readFileSync(
  path.join(root, "crates/app/src/platform/unix.rs"),
  "utf8",
);
let divergence = fs.readFileSync(
  path.join(root, "crates/app/src/content_scripts/fingerprint_divergence.js"),
  "utf8",
);
const reportCall = "window.chrome.webview.postMessage(payload);";
if (process.env.PATANYX_FINGERPRINT_PROBE_OMIT_CALLSITE) {
  if (!divergence.includes(reportCall)) {
    throw new Error("cannot plant defect: fingerprint report call site changed");
  }
  divergence = divergence.replace(reportCall, "void payload;");
}

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(condition, message) {
  if (!condition) throw new Error(message);
}
const flush = async () => {
  for (let i = 0; i < 24; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

global.rbResolve.fingerprint_probe_activity = {
  label: "Page-reported fingerprint probes",
  caveat:
    "Page-reported, not browser-observed. These counts describe probe calls reported by this page's main-world scripts; the page can omit or forge them, and worker probes are not included.",
  status: "active",
  status_text: "",
  surface_labels: {
    audio: "Audio",
    canvas: "Canvas",
    webgl: "WebGL/Graphics",
    element_measurement: "Element measurement",
  },
  counts: { audio: 14, canvas: 3, webgl: 1, element_measurement: 40 },
};
new Function(chromeJs)();
const $ = (id) => global.document.getElementById(id);

check("Tab Activity renders every surface through its real open path", async () => {
  $("btn-tab").click();
  await flush();
  assert(!$('tab-panel').hidden, "Tab Activity did not open");
  for (const [id, expected] of [
    ["fingerprint-probe-audio", "Audio: 14 page-reported probes."],
    ["fingerprint-probe-canvas", "Canvas: 3 page-reported probes."],
    ["fingerprint-probe-webgl", "WebGL/Graphics: 1 page-reported probe."],
    [
      "fingerprint-probe-element-measurement",
      "Element measurement: 40 page-reported probes.",
    ],
  ]) {
    assert($(id).textContent === expected, id + " rendered as " + $(id).textContent);
  }
});

check("the reading is explicitly page-reported, never browser-observed", () => {
  const label = $("fingerprint-probe-label").textContent.toLowerCase();
  const caveat = $("fingerprint-probe-caveat").textContent.toLowerCase();
  assert(label.includes("page-reported"), "label lost page-reported");
  for (const phrase of [
    "not browser-observed",
    "this page's main-world scripts",
    "omit or forge",
    "worker probes are not included",
  ]) {
    assert(caveat.includes(phrase), "caveat lost: " + phrase);
  }
  assert(
    stateRs.includes(global.rbResolve.fingerprint_probe_activity.caveat),
    "the untrusted-count caveat is no longer Rust-owned copy",
  );
});

check("zero is rendered as a real reading on all four rows", async () => {
  global.rbResolve.fingerprint_probe_activity.counts = {
    audio: 0,
    canvas: 0,
    webgl: 0,
    element_measurement: 0,
  };
  $("btn-tab").click(); // close
  $("btn-tab").click(); // reopen and refresh
  await flush();
  for (const id of [
    "fingerprint-probe-audio",
    "fingerprint-probe-canvas",
    "fingerprint-probe-webgl",
    "fingerprint-probe-element-measurement",
  ]) {
    assert(
      $(id).textContent.endsWith(": 0 page-reported probes."),
      id + " hid or mislabelled zero: " + $(id).textContent,
    );
  }
});

function runDivergence(source, expectReport = true) {
  const scheduled = [];
  const messages = [];
  const pageListeners = {};

  function CanvasRenderingContext2D() {}
  CanvasRenderingContext2D.prototype.getImageData = function () {
    return { data: new Uint8ClampedArray([12, 34, 56, 255, 78, 90, 12, 255]) };
  };
  function AudioBuffer() {
    this.samples = new Float32Array([0.5, -0.25, 0]);
  }
  AudioBuffer.prototype.getChannelData = function () {
    return this.samples;
  };
  AudioBuffer.prototype.copyFromChannel = function (dest, _channel, start) {
    dest.set(this.samples.slice(start || 0, (start || 0) + dest.length));
    return "audio-copy-return";
  };
  function WebGLRenderingContext() {}
  WebGLRenderingContext.prototype.getParameter = function (pname) {
    return "native-" + String(pname);
  };
  function Element() {}
  Element.prototype.getBoundingClientRect = function () {
    return new DOMRect(3, 4, 20.25, 10.25);
  };
  Element.prototype.getClientRects = function () {
    return [new DOMRect(3, 4, 20.25, 10.25)];
  };
  function DOMRect(x, y, width, height) {
    this.x = this.left = x;
    this.y = this.top = y;
    this.width = width;
    this.height = height;
    this.right = x + width;
    this.bottom = y + height;
  }

  const context = {
    CanvasRenderingContext2D,
    AudioBuffer,
    WebGLRenderingContext,
    Element,
    DOMRect,
    Uint8ClampedArray,
    Float32Array,
    URL,
    location: { hostname: "gate.example", ancestorOrigins: [] },
    setTimeout(fn, delay) {
      scheduled.push({ fn, delay });
      return scheduled.length;
    },
  };
  context.window = context;
  context.self = context;
  context.chrome = {
    webview: {
      postMessage(raw) {
        messages.push(raw);
      },
    },
  };
  context.addEventListener = (type, fn) => {
    pageListeners[type] = fn;
  };
  vm.createContext(context);
  const built = source
    .replace("__DIVERGENCE_TOKEN__", "gate-token")
    .replace("__DIVERGENCE_OVERRIDES__", "{}");
  vm.runInContext(built, context, { filename: "fingerprint_divergence.js" });

  const canvas = new context.CanvasRenderingContext2D();
  const canvasReads = [
    Array.from(canvas.getImageData().data),
    Array.from(canvas.getImageData().data),
    Array.from(canvas.getImageData().data),
  ];
  const audio = new context.AudioBuffer();
  const channel = Array.from(audio.getChannelData(0));
  const dest = new Float32Array(2);
  const copyReturn = audio.copyFromChannel(dest, 0, 0);
  const webgl = new context.WebGLRenderingContext().getParameter(37445);
  const element = new context.Element();
  const rect = element.getBoundingClientRect();
  const rects = element.getClientRects();
  if (expectReport) {
    assert(scheduled.length === 1, "calls were not coalesced into one timer");
    assert(scheduled[0].delay === 2000, "report delay is not 2 seconds");
    scheduled[0].fn();
  } else {
    assert(scheduled.length === 0, "counter-free baseline unexpectedly scheduled");
  }
  return {
    messages,
    returns: {
      canvasReads,
      channel,
      copyReturn,
      copied: Array.from(dest),
      webgl,
      rect: [rect.x, rect.y, rect.width, rect.height],
      rects: rects.map((r) => [r.x, r.y, r.width, r.height]),
    },
  };
}

let runtime;
check("one delayed batch carries only integer counts and surface names", () => {
  runtime = runDivergence(divergence);
  assert(runtime.messages.length === 1, "reporting call site produced no single batch");
  const payload = JSON.parse(runtime.messages[0]);
  assert(payload.kind === "fingerprint_probe_counts", "wrong message kind");
  assert(
    Object.keys(payload).sort().join(",") === "counts,kind",
    "message grew content outside kind/counts",
  );
  const found = {};
  for (const delta of payload.counts) {
    assert(
      Object.keys(delta).sort().join(",") === "count,surface",
      "a delta carries content beyond surface/count",
    );
    assert(Number.isSafeInteger(delta.count), "count is not a safe integer");
    assert(typeof delta.surface === "string", "surface is not a name");
    found[delta.surface] = delta.count;
  }
  assert(
    JSON.stringify(found) ===
      JSON.stringify({ audio: 2, canvas: 3, webgl: 1, element_measurement: 2 }),
    "wrong per-surface counts: " + JSON.stringify(found),
  );
});

check("counter calls do not change divergence return values", () => {
  const withoutCounterCalls = divergence.replace(
    /^\s*noteProbe\("(?:audio|canvas|webgl|element_measurement)"\);\s*$/gm,
    "",
  );
  const baseline = runDivergence(withoutCounterCalls, false);
  assert(
    JSON.stringify(runtime.returns) === JSON.stringify(baseline.returns),
    "adding the counter changed a wrapped API result",
  );
});

check("both native platform channels are wired per tab", () => {
  for (const token of [
    "add_WebMessageReceived",
    "fingerprint_probe_report(&msg)",
    "UserEvent::FingerprintProbes",
  ]) {
    assert(windowsRs.includes(token), "Windows channel lost " + token);
  }
  for (const token of [
    'register_script_message_handler(HANDLER)',
    "connect_script_message_received(Some(HANDLER)",
    "fingerprint_probe_report(&message)",
    "UserEvent::FingerprintProbes",
  ]) {
    assert(unixRs.includes(token), "WebKitGTK channel lost " + token);
  }
});

check("probe claims stay separate from the receipt and Premium", () => {
  const receiptStart = ipcRs.indexOf('"privacy_receipt" =>');
  const probeStart = ipcRs.indexOf('"fingerprint_probe_activity" =>');
  const receiptEnd = ipcRs.indexOf("\n        // Separate from privacy_receipt", receiptStart);
  const receiptArm = ipcRs.slice(receiptStart, receiptEnd);
  assert(receiptStart >= 0 && probeStart > receiptStart, "IPC arms are missing");
  assert(
    !/fingerprint|probe/i.test(receiptArm),
    "probe counts were folded into the engine privacy receipt",
  );
  const probeEnd = ipcRs.indexOf("\n\n        //", probeStart);
  const probeArm = ipcRs.slice(probeStart, probeEnd);
  assert(
    !/premium|licen[cs]e|on_sale/i.test(probeArm),
    "free probe reporting was entitlement-gated",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (error) {
      failures.push(name + ": " + error.message);
      console.log("  FAIL: " + name + ": " + error.message);
    }
  }
  if (failures.length) {
    console.error("fingerprint-probe-gate: " + failures.length + " check(s) failed");
    process.exit(1);
  }
  console.log("fingerprint-probe-gate OK (" + checks.length + " checks)");
})();
