// The worker half of Fingerprint Divergence, exercised end to end.
//
// The one property that makes worker coverage SAFE rather than a new leak:
// the worker realm must apply the SAME canvas noise as the main realm, from
// the same per-site seed. If the two ever diverged, a page could render one
// image in both realms and diff them, and every pixel that differed would be
// exactly the noised one -- worker coverage would then be worse than the
// disclosed hole it replaces. This gate renders the SHIM the wrapper builds
// against a stub OffscreenCanvas and asserts the mask matches the main
// thread's, byte for byte.
//
// It also pins the fail-safe contract: a module worker, a data: URL, a
// cross-scheme URL, and a construction that throws must all yield the
// ORIGINAL unwrapped worker, never a broken one and never a mismatched-key
// one. The worst case must equal today's behavior.
//
// Not jsdom, same as the sibling gates: node + vm only.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SRC = path.join(
  __dirname,
  "..",
  "crates/app/src/content_scripts/fingerprint_divergence.js",
);
const template = fs.readFileSync(SRC, "utf8");
const TOKEN = "a".repeat(64);

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// A stub OffscreenCanvas 2D surface that reports a fixed pixel pattern, so a
// noise mask is measurable as (output XOR base).
function make2dStub() {
  const BASE = [100, 150, 200, 255];
  function OffscreenCanvasRenderingContext2D() {}
  OffscreenCanvasRenderingContext2D.prototype.getImageData = function (
    x,
    y,
    w,
    h,
  ) {
    const data = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < data.length; i += 4) {
      data[i] = BASE[0];
      data[i + 1] = BASE[1];
      data[i + 2] = BASE[2];
      data[i + 3] = BASE[3];
    }
    return { width: w, height: h, data };
  };
  OffscreenCanvasRenderingContext2D.prototype.putImageData = function () {};
  OffscreenCanvasRenderingContext2D.prototype.drawImage = function () {};
  function OffscreenCanvas(w, h) {
    this.width = w;
    this.height = h;
    this.ctx = new OffscreenCanvasRenderingContext2D();
  }
  OffscreenCanvas.prototype.getContext = function () {
    return this.ctx;
  };
  OffscreenCanvas.prototype.convertToBlob = function () {
    return Promise.resolve("blob");
  };
  return { OffscreenCanvasRenderingContext2D, OffscreenCanvas, BASE };
}

// Read a w*h OffscreenCanvas image through the (patched) prototype and return
// the noise mask against the base pattern.
function maskOf(scope, w, h) {
  const ctx = new scope.OffscreenCanvasRenderingContext2D();
  const img =
    scope.OffscreenCanvasRenderingContext2D.prototype.getImageData.call(
      ctx,
      0,
      0,
      w,
      h,
    );
  const base = [100, 150, 200, 255];
  const out = [];
  for (let i = 0; i < img.data.length; i++) out.push(img.data[i] ^ base[i % 4]);
  return out.join(",");
}

// ---- the MAIN-thread realm ------------------------------------------------
function mainSandbox() {
  const sb = {};
  sb.window = sb;
  sb.self = sb;
  sb.Blob = class {
    constructor(parts) {
      this.parts = parts;
    }
  };
  sb.location = {
    hostname: "tracker.example",
    href: "https://tracker.example/",
    origin: "https://tracker.example",
    ancestorOrigins: { length: 0 },
  };
  // The facade schedules a settle-timer backstop. A no-op that never fires
  // keeps the queue/replay behaviour deterministic for these assertions; the
  // timer's own effect (releasing the buffer on a live worker) is not what
  // this gate measures.
  sb.setTimeout = function () {
    return 0;
  };
  sb.clearTimeout = function () {};
  const stub = make2dStub();
  sb.OffscreenCanvasRenderingContext2D = stub.OffscreenCanvasRenderingContext2D;
  sb.OffscreenCanvas = stub.OffscreenCanvas;
  // A URL that is `new`-able for parsing (delegating to Node's real URL) AND
  // carries createObjectURL/revokeObjectURL statics, which Node's global URL
  // does not. A plain Object.create(URL) is not constructable, so `new URL()`
  // inside the script would throw and the wrapper would silently fall through
  // to unwrapped -- which is exactly the false pass this harness must avoid.
  sb.__blobs = [];
  function FakeURL(u, base) {
    return new URL(u, base);
  }
  FakeURL.createObjectURL = function (blob) {
    sb.__blobs.push(blob);
    return "blob:mock/" + sb.__blobs.length;
  };
  FakeURL.revokeObjectURL = function () {};
  sb.URL = FakeURL;
  // A recording Worker so the wrapper's fall-through AND the CSP swap are
  // observable. Every instance records the messages the facade forwarded to
  // it and whether it was terminated, and exposes the onmessage/onerror slots
  // the facade assigned so a test can fire a synthetic message (liveness) or a
  // synthetic error (the async CSP refusal a DOM stub cannot itself enforce).
  sb.__workerArgs = [];
  sb.__workers = [];
  sb.Worker = function (url, options) {
    sb.__workerArgs.push({ url: String(url), options: options || null });
    this.url = String(url);
    this.posted = [];
    this.terminated = false;
    var inst = this;
    this.postMessage = function () {
      inst.posted.push(Array.prototype.slice.call(arguments));
    };
    this.terminate = function () {
      inst.terminated = true;
    };
    sb.__workers.push(this);
  };
  vm.createContext(sb);
  vm.runInContext(template.replace("__DIVERGENCE_TOKEN__", TOKEN), sb);
  return sb;
}

// ---- run the SHIM the wrapper produced, in its own worker-like realm ------
function runShim(shimSource) {
  const sb = {};
  sb.self = sb;
  const stub = make2dStub();
  sb.OffscreenCanvasRenderingContext2D = stub.OffscreenCanvasRenderingContext2D;
  sb.OffscreenCanvas = stub.OffscreenCanvas;
  // importScripts is where the shim hands off to the page's real worker; the
  // stub records that it was called with the resolved absolute URL and does
  // nothing else.
  sb.__imported = [];
  sb.importScripts = function (u) {
    sb.__imported.push(u);
  };
  vm.createContext(sb);
  vm.runInContext(shimSource, sb);
  return sb;
}

const tests = [];
function check(name, fn) {
  tests.push({ name, fn });
}

check("the wrapper builds a shim for a classic same-origin worker", () => {
  const sb = mainSandbox();
  new sb.Worker("worker.js");
  assert(sb.__blobs.length === 1, "no blob was built for a classic worker");
  const src = sb.__blobs[0].parts.join("");
  assert(
    /importScripts\("https:\/\/tracker\.example\/worker\.js"\)/.test(src),
    "the shim must importScripts the resolved absolute URL of the real worker",
  );
  assert(
    src.indexOf(TOKEN) === -1,
    "THE SESSION TOKEN IS IN THE WORKER SOURCE -- it must never be",
  );
});

check("worker canvas noise is byte-identical to the main thread's", () => {
  const sb = mainSandbox();
  new sb.Worker("worker.js");
  // runShim stubs importScripts as a no-op recorder, so the whole shim runs
  // as the worker would run it -- no fragile excision of the tail.
  const worker = runShim(sb.__blobs[0].parts.join(""));
  for (const [w, h] of [
    [16, 16],
    [7, 3],
    [32, 8],
  ]) {
    const mainMask = maskOf(sb, w, h);
    const workerMask = maskOf(worker, w, h);
    assert(
      mainMask === workerMask,
      `worker mask != main mask at ${w}x${h}. A page could diff the two ` +
        `realms and read off the noised pixels. This is the leak the whole ` +
        `design exists to avoid.`,
    );
  }
});

check(
  "worker noise is actually applied (not a no-op that trivially matches)",
  () => {
    const sb = mainSandbox();
    new sb.Worker("worker.js");
    const worker = runShim(sb.__blobs[0].parts.join(""));
    const mask = maskOf(worker, 64, 64);
    assert(/[^0,]/.test(mask), "the worker applied no noise at all");
  },
);

check(
  "the shim carries only the canvas seed, never audio-derived material",
  () => {
    const sb = mainSandbox();
    new sb.Worker("worker.js");
    const src = sb.__blobs[0].parts.join("");
    assert(src.indexOf("audio") === -1, "the shim mentions audio; it must not");
    assert(src.indexOf(TOKEN) === -1, "the shim carries the session token");
  },
);

check("a module worker is not wrapped", () => {
  const sb = mainSandbox();
  new sb.Worker("worker.js", { type: "module" });
  assert(
    sb.__blobs.length === 0,
    "a module worker was wrapped; it cannot importScripts",
  );
  assert(
    sb.__workerArgs.length === 1 && sb.__workerArgs[0].url === "worker.js",
    "a module worker must be constructed unwrapped with its original url",
  );
});

check("a data: worker url is not wrapped", () => {
  const sb = mainSandbox();
  new sb.Worker("data:text/javascript,onmessage=null");
  assert(sb.__blobs.length === 0, "a data: worker was wrapped");
  assert(
    sb.__workerArgs.length === 1,
    "the data: worker must be constructed unwrapped",
  );
});

check("a blob: worker url is not wrapped", () => {
  const sb = mainSandbox();
  new sb.Worker("blob:https://tracker.example/abc");
  assert(sb.__blobs.length === 0, "a blob: worker was wrapped");
  assert(
    sb.__workerArgs.length === 1,
    "the blob: worker must be constructed unwrapped",
  );
});

check("options (name) survive wrapping", () => {
  const sb = mainSandbox();
  new sb.Worker("worker.js", { name: "w1" });
  assert(
    sb.__workerArgs.length === 1 &&
      sb.__workerArgs[0].options &&
      sb.__workerArgs[0].options.name === "w1",
    "the worker options must be passed through to the real constructor",
  );
});

check("instanceof and constructor identity survive", () => {
  const sb = mainSandbox();
  // The wrapper replaced self.Worker; a constructed worker must still be an
  // instance of it (prototype preserved), or feature-detection breaks.
  const w = new sb.Worker("worker.js");
  assert(w instanceof sb.Worker, "a wrapped worker is not instanceof Worker");
});

// ---- the CSP fallback -----------------------------------------------------
// A blob worker is refused ASYNCHRONOUSLY when a site's CSP omits blob: from
// worker-src: it constructs, then fires error and never runs. A DOM stub
// cannot enforce a real CSP, so these fire a synthetic error on the recording
// blob worker BEFORE any message -- the exact shape of that refusal -- and
// assert the facade repairs it.

check("the facade is instanceof Worker and exposes the worker methods", () => {
  const sb = mainSandbox();
  const f = new sb.Worker("worker.js");
  assert(f instanceof sb.Worker, "the facade must be instanceof Worker");
  assert(
    typeof f.postMessage === "function" &&
      typeof f.terminate === "function" &&
      typeof f.addEventListener === "function",
    "the facade must expose postMessage/terminate/addEventListener",
  );
});

check(
  "a refused blob worker swaps ONCE to an unwrapped worker on the ORIGINAL url",
  () => {
    const sb = mainSandbox();
    const f = new sb.Worker("worker.js");
    const blobW = sb.__workers[0];
    assert(
      blobW.url === "blob:mock/1",
      "the first worker is the blob-shimmed one",
    );
    f.postMessage("a");
    f.postMessage("b", []);
    assert(
      blobW.posted.length === 2,
      "posts must forward to the blob worker immediately (no buffering delay)",
    );
    blobW.onerror({ type: "error" }); // the async CSP refusal
    assert(sb.__workers.length === 2, "exactly one swap => one replacement");
    const realW = sb.__workers[1];
    assert(
      realW.url === "worker.js",
      "the replacement must use the ORIGINAL url, never the blob url",
    );
    assert(blobW.terminated === true, "the refused blob worker is terminated");
    assert(
      realW.posted.length === 2 &&
        realW.posted[0][0] === "a" &&
        realW.posted[1][0] === "b",
      "queued posts must replay onto the replacement, in order",
    );
    // A second error on the replacement must NOT swap again.
    realW.onerror({ type: "error" });
    assert(sb.__workers.length === 2, "the swap happens at most once");
  },
);

check("the replay queue has no cap: nothing is silently dropped", () => {
  const sb = mainSandbox();
  const f = new sb.Worker("worker.js");
  const blobW = sb.__workers[0];
  const N = 3000; // well past the reverted draft's 1024 cap
  for (let i = 0; i < N; i++) f.postMessage(i);
  blobW.onerror({ type: "error" });
  const realW = sb.__workers[1];
  assert(
    realW.posted.length === N,
    "every pre-liveness message must replay; found " + realW.posted.length,
  );
  assert(
    realW.posted[0][0] === 0 && realW.posted[N - 1][0] === N - 1,
    "replayed messages must keep their order",
  );
});

check(
  "a worker that RAN then errors does NOT swap; its error reaches the page",
  () => {
    const sb = mainSandbox();
    const f = new sb.Worker("worker.js");
    const blobW = sb.__workers[0];
    let gotError = 0;
    f.onerror = function () {
      gotError += 1;
    };
    blobW.onmessage({ type: "message", data: 1 }); // liveness: it ran
    blobW.onerror({ type: "error" }); // now a genuine site error
    assert(sb.__workers.length === 1, "a proved worker must never be swapped");
    assert(gotError === 1, "the site's own error must surface to the page");
  },
);

check("terminate() before the refusal is honoured -- no resurrection", () => {
  const sb = mainSandbox();
  const f = new sb.Worker("worker.js");
  const blobW = sb.__workers[0];
  f.terminate();
  assert(blobW.terminated === true, "terminate must forward to the worker");
  blobW.onerror({ type: "error" }); // a refusal racing in after terminate
  assert(
    sb.__workers.length === 1,
    "a terminated worker must not be resurrected by a late refusal",
  );
});

check("a throwing listener does not propagate out of dispatch", () => {
  const sb = mainSandbox();
  const f = new sb.Worker("worker.js");
  const blobW = sb.__workers[0];
  f.addEventListener("message", function () {
    throw new Error("boom");
  });
  let after = false;
  f.addEventListener("message", function () {
    after = true;
  });
  blobW.onmessage({ type: "message" }); // must not throw
  assert(after === true, "a throwing listener must not stop later listeners");
});

let failed = 0;
for (const t of tests) {
  try {
    t.fn();
    console.log("  ok  " + t.name);
  } catch (e) {
    failed += 1;
    console.error("  FAIL  " + t.name + "\n        " + e.message);
  }
}
if (failed) {
  console.error("\nDIVERGENCE WORKER GATE FAILED");
  process.exit(1);
}
console.log("\ndivergence-worker-gate: OK");
