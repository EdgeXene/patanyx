// The worker half of Fingerprint Divergence, as of 1.0.1: there is none, on
// purpose, and this gate holds it there.
//
// Commit 22ea1a3 stopped installing the Worker wrapper. Shimming a worker
// meant running it from a blob: URL; a site whose CSP restricts worker-src
// refuses those outright, and on messenger.com that left the encrypted-backup
// step hanging on "Verifying your PIN". The wrapper and its facade are still
// defined in fingerprint_divergence.js, unreferenced (`void wrapped;`), for a
// possible request-handler approach later. `self.Worker` is the engine's own.
//
// So the contract this gate pins, so it only ever changes deliberately:
//   * after the script runs AND everything it scheduled has run (timers,
//     microtasks, animation frames, idle callbacks, and DOMContentLoaded,
//     readystatechange and load listeners),
//     `self.Worker` is the SAME function object the realm had before it --
//     not a lookalike, the identical reference
//   * constructing any worker builds no Blob and mints no blob: URL
//   * the constructor receives the page's url and options untouched
//   * the document half still runs: the main-thread OffscreenCanvas hook is
//     installed and applies noise, so a script that stopped running entirely
//     cannot pass this gate by doing nothing
//   * NEGATIVE CONTROL: the pre-22ea1a3 install lines restored in a COPY of
//     the script must fail the checks above. That proves the gate can see a
//     re-install, and that the worker section is actually reached.
//   * The retained shim, planted back in, must still be safe to revive: it
//     varies with the session token ONLY in its four canvas seed words (so no
//     token- or audio-derived value rides along in any encoding), and those
//     words produce the main thread's exact canvas mask.
//
// Re-enabling worker coverage means replacing this gate, not loosening it:
// the previous version (git show cf55400:scripts/divergence-worker-gate.js)
// pinned the CSP fallback, and that would be needed again.
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
const TOKEN_B = "b".repeat(64);

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// A stub OffscreenCanvas 2D surface that reports a fixed pixel pattern, so a
// noise mask is measurable as (output XOR base).
const BASE = [100, 150, 200, 255];
function make2dStub() {
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
  return { OffscreenCanvasRenderingContext2D, OffscreenCanvas };
}

function maskOf(sb, w, h) {
  const ctx = new sb.OffscreenCanvasRenderingContext2D();
  const img = sb.OffscreenCanvasRenderingContext2D.prototype.getImageData.call(
    ctx,
    0,
    0,
    w,
    h,
  );
  const out = [];
  for (let i = 0; i < img.data.length; i++) out.push(img.data[i] ^ BASE[i % 4]);
  return out.join(",");
}

// Everything a page realm lets a script defer work through, RECORDED rather
// than dropped, so settle() can run it. A wrapper installed from a timer, an
// interval's later tick, an idle callback or a load listener must be as
// visible to this gate as one installed inline.
function deferralSurface(sb) {
  sb.__once = []; // setTimeout, requestAnimationFrame, requestIdleCallback
  sb.__repeat = []; // setInterval: runs every round
  sb.__listeners = []; // { type, fn, fired }
  const deadline = { didTimeout: false, timeRemaining: () => 50 };
  let ids = 0;
  sb.setTimeout = (fn) => (typeof fn === "function" && sb.__once.push(() => fn()), ++ids);
  sb.requestAnimationFrame = (fn) =>
    (typeof fn === "function" && sb.__once.push(() => fn(16)), ++ids);
  sb.requestIdleCallback = (fn) =>
    (typeof fn === "function" && sb.__once.push(() => fn(deadline)), ++ids);
  sb.setInterval = (fn) => (typeof fn === "function" && sb.__repeat.push(fn), ++ids);
  sb.clearTimeout = sb.clearInterval = sb.cancelAnimationFrame = () => {};
  sb.cancelIdleCallback = () => {};
  sb.queueMicrotask = (fn) => Promise.resolve().then(fn);
  // Each listener keeps the object it was registered on, and is called the
  // way a browser calls it: `this`, event.target and event.currentTarget are
  // that object, so a guard on `this.readyState` sees the document.
  const listenOn = (target) => (type, fn) => {
    const call =
      typeof fn === "function"
        ? (e) => fn.call(target, e)
        : fn && typeof fn.handleEvent === "function"
          ? (e) => fn.handleEvent(e)
          : null;
    if (call)
      sb.__listeners.push({ type: String(type), fn: call, target, seen: new Set() });
  };
  sb.addEventListener = listenOn(sb);
  sb.removeEventListener = () => {};
  sb.document = { readyState: "loading", removeEventListener: () => {} };
  sb.document.addEventListener = listenOn(sb.document);
}

// Run everything the script deferred, including work that schedules more
// work, through a page lifecycle: "interactive" (DOMContentLoaded), then
// "complete", after which every listener registered so far -- load,
// pageshow, anything -- fires once, however late it was added.
// readystatechange fires at BOTH transitions, as a browser fires it, so a
// listener waiting for "complete" is reached. Intervals tick every round. Bounded, so a repeating timer cannot hang the gate; it only
// has to outlast any plausible deferred install.
const macrotask = () => new Promise((r) => setImmediate(r));
const EARLY = new Set(["DOMContentLoaded", "readystatechange"]);
async function settle(sb) {
  const run = (fn, arg) => {
    try {
      fn(arg);
    } catch (e) {
      /* a throwing callback is the script's business, not this gate's */
    }
  };
  await macrotask();
  for (let round = 0; round < 20; round++) {
    sb.document.readyState = round === 0 ? "interactive" : "complete";
    for (const fn of sb.__once.splice(0)) run(fn);
    for (const fn of sb.__repeat.slice()) run(fn);
    const state = sb.document.readyState;
    for (const l of sb.__listeners.slice()) {
      if (round === 0 && !EARLY.has(l.type)) continue;
      // Once per listener, except readystatechange: once per state.
      const key = l.type === "readystatechange" ? state : "once";
      if (l.seen.has(key)) continue;
      l.seen.add(key);
      run(l.fn, { type: l.type, target: l.target, currentTarget: l.target });
    }
    await macrotask();
  }
  return sb;
}

// A main-world realm with everything the old wrapper needed to do its work --
// Blob, a constructable URL with createObjectURL, a recording Worker -- so an
// installed wrapper would have every opportunity to run, and would be seen.
function mainSandbox(source, token) {
  const sb = {};
  sb.window = sb;
  sb.self = sb;
  sb.__blobs = [];
  sb.Blob = class {
    constructor(parts) {
      this.parts = parts;
      sb.__blobs.push(this);
    }
  };
  sb.location = {
    hostname: "tracker.example",
    href: "https://tracker.example/",
    origin: "https://tracker.example",
    ancestorOrigins: { length: 0 },
  };
  deferralSurface(sb);
  const stub = make2dStub();
  sb.OffscreenCanvasRenderingContext2D = stub.OffscreenCanvasRenderingContext2D;
  sb.OffscreenCanvas = stub.OffscreenCanvas;
  // `new`-able for parsing (delegating to Node's URL) AND carrying the
  // createObjectURL static, which Node's global URL lacks. Without both, an
  // installed wrapper would throw inside its own try and fall through to the
  // unwrapped constructor -- and this gate would pass for the wrong reason.
  sb.__objectUrls = 0;
  function FakeURL(u, base) {
    return new URL(u, base);
  }
  FakeURL.createObjectURL = function () {
    sb.__objectUrls += 1;
    return "blob:mock/" + sb.__objectUrls;
  };
  FakeURL.revokeObjectURL = function () {};
  sb.URL = FakeURL;
  sb.__workerArgs = [];
  function Worker(url, options) {
    sb.__workerArgs.push({ url: url, options: options });
  }
  sb.Worker = Worker;
  sb.__engineWorker = Worker;
  vm.createContext(sb);
  // Both placeholders; see the note in divergence-detect-gate.js.
  vm.runInContext(
    source
      .replace("__DIVERGENCE_TOKEN__", token || TOKEN)
      .replace("__DIVERGENCE_OVERRIDES__", "{}"),
    sb,
  );
  return sb;
}

async function settledSandbox(source, token) {
  return settle(mainSandbox(source, token));
}

// Every shape of worker a page can ask for. The old wrapper treated the first
// one (classic, same-origin, http(s)) differently from the rest; now none of
// them may be treated differently at all.
const MODULE_OPTS = { type: "module" };
const NAMED_OPTS = { name: "w1" };
const CASES = [
  ["classic same-origin", "worker.js", undefined],
  ["classic same-origin, named", "worker.js", NAMED_OPTS],
  ["module", "worker.js", MODULE_OPTS],
  ["data:", "data:text/javascript,onmessage=null", undefined],
  ["blob:", "blob:https://tracker.example/abc", undefined],
  ["cross-origin", "https://other.example/w.js", undefined],
];

// The contract, as a list of violations (empty = holds). Shared by the real
// run and the negative control, so the control exercises exactly these.
function violations(sb) {
  const out = [];
  if (sb.Worker !== sb.__engineWorker) {
    out.push(
      "self.Worker was replaced; it must be the engine's own constructor",
    );
  }
  for (const [label, url, options] of CASES) {
    const blobsBefore = sb.__blobs.length;
    const urlsBefore = sb.__objectUrls;
    const argsBefore = sb.__workerArgs.length;
    try {
      new sb.Worker(url, options);
    } catch (e) {
      out.push(label + ": constructing the worker threw: " + e.message);
      continue;
    }
    if (sb.__blobs.length !== blobsBefore) {
      out.push(label + ": a Blob was built for the worker");
    }
    if (sb.__objectUrls !== urlsBefore) {
      out.push(label + ": a blob: URL was minted for the worker");
    }
    const got = sb.__workerArgs.slice(argsBefore);
    if (got.length !== 1 || got[0].url !== url || got[0].options !== options) {
      out.push(
        label +
          ": the engine constructor must be called once with the page's own " +
          "url and options object",
      );
    }
  }
  return out;
}

// The three lines 22ea1a3 replaced with `void wrapped;`, verbatim, planted
// back into a COPY. Anchored on a line that is ONLY that statement, so a
// comment quoting it can never be mistaken for the code (a comment line starts
// with `//` or `*`). Exactly one such line, or the control cannot be trusted.
const INSTALL_ANCHOR = /^([ \t]*)void wrapped;[ \t]*$/m;
function plantReinstall() {
  const lines = template.match(new RegExp(INSTALL_ANCHOR.source, "gm")) || [];
  assert(
    lines.length === 1,
    "expected exactly one line reading `void wrapped;` in the script, found " +
      lines.length +
      ". If the retained wrapper was deleted on purpose, replace these " +
      "controls with ones that plant a Worker replacement some other way -- " +
      "a gate that has never been seen to fail is not a gate",
  );
  return template.replace(
    INSTALL_ANCHOR,
    "$1wrapped.prototype = OrigWorker.prototype;" +
      " keepShape(wrapped, OrigWorker);" +
      " self.Worker = wrapped;",
  );
}

// The shim the planted re-install builds for a classic worker, under `token`.
async function plantedShim(token) {
  const sb = await settledSandbox(plantReinstall(), token);
  new sb.Worker("worker.js");
  assert(sb.__blobs.length === 1, "the planted re-install built no shim");
  return { sb, src: sb.__blobs[0].parts.join("") };
}

// The shim run in its own worker-like realm, with importScripts recorded
// rather than performed, so the whole shim runs as the worker would run it.
function runShim(src) {
  const w = {};
  w.self = w;
  const stub = make2dStub();
  w.OffscreenCanvasRenderingContext2D = stub.OffscreenCanvasRenderingContext2D;
  w.OffscreenCanvas = stub.OffscreenCanvas;
  w.__imported = [];
  w.importScripts = (u) => w.__imported.push(u);
  vm.createContext(w);
  vm.runInContext(src, w);
  return w;
}

const tests = [];
function check(name, fn) {
  tests.push({ name, fn });
}

check(
  "self.Worker is the engine's own constructor, before and after deferred work",
  async () => {
    const sb = mainSandbox(template);
    const inline = sb.Worker === sb.__engineWorker;
    await settle(sb);
    assert(
      inline &&
        sb.Worker === sb.__engineWorker &&
        sb.self.Worker === sb.__engineWorker &&
        sb.window.Worker === sb.__engineWorker,
      "self.Worker was replaced" +
        (inline ? " by deferred work (a timer, microtask or listener)" : "") +
        ". 1.0.1 stopped installing the Worker wrapper because a blob: worker " +
        "is refused under a strict worker-src CSP and hung messenger.com; " +
        "re-installing it needs the old gate back, not this one",
    );
  },
);

check(
  "no worker shape builds a Blob, mints a blob: URL, or loses its arguments",
  async () => {
    const sb = await settledSandbox(template);
    const v = violations(sb);
    assert(v.length === 0, v.join("\n        "));
  },
);

check(
  "the document half still runs: main-thread OffscreenCanvas is noised",
  async () => {
    // Without this, a script that threw at the top would leave Worker untouched
    // and pass every check above.
    const sb = await settledSandbox(template);
    assert(
      /[^0,]/.test(maskOf(sb, 64, 64)),
      "no noise on the main-thread OffscreenCanvas: the script did not run, " +
        "so the Worker checks above prove nothing",
    );
  },
);

check(
  "NEGATIVE CONTROL: restoring the pre-1.0.1 install is detected",
  async () => {
    const sb = await settledSandbox(plantReinstall());
    const v = violations(sb);
    assert(
      v.some((m) => m.indexOf("self.Worker was replaced") === 0),
      "the planted re-install was NOT seen as a Worker replacement -- either " +
        "the worker section is no longer reached, or this gate cannot see it",
    );
    assert(
      v.some((m) => m.indexOf("classic same-origin: a Blob was built") === 0),
      "the planted re-install built no Blob for a classic worker, so the Blob " +
        "check cannot be trusted to catch one either",
    );
  },
);

check(
  "the retained shim varies with the token ONLY in its four canvas seed words",
  async () => {
    // workerShimBody is still BUILT on every run (only the Blob and Worker are
    // dormant). Build it under two tokens: whatever differs between the two is
    // token-derived, in whatever encoding, and the only token-derived thing it
    // may carry is the canvas seed. A literal-string search cannot say that;
    // the session token spelled out as numbers, or the audio seed, would pass
    // it. This fails both.
    // Each word a CANONICAL unsigned 32-bit integer: no sign, no leading zero,
    // no exponent, at most 4294967295. A wider number would still seed the
    // PRNG identically after truncation while carrying extra token bits above
    // bit 32, and the comparison below excludes the words' contents.
    const W = "(0|[1-9][0-9]{0,9})";
    const SEED = new RegExp(
      "^\\(function\\(\\)\\{var __s=\\[" + [W, W, W, W].join(",") + "\\];",
    );
    const a = (await plantedShim(TOKEN)).src;
    const b = (await plantedShim(TOKEN_B)).src;
    const ma = SEED.exec(a);
    const mb = SEED.exec(b);
    assert(
      ma && mb,
      "the shim no longer opens with `var __s=[four integers]`; this check " +
        "must be updated with it, deliberately",
    );
    assert(
      ma[0] !== mb[0],
      "the canvas seed words did not change with the token",
    );
    for (const m of [ma, mb]) {
      assert(
        m.slice(1, 5).every((w) => Number(w) <= 4294967295),
        "a canvas seed word is wider than 32 bits: " + m.slice(1, 5).join(","),
      );
    }
    assert(
      a.slice(ma[0].length) === b.slice(mb[0].length),
      "the shim differs between two session tokens OUTSIDE the canvas seed " +
        "words: something token-derived (the token itself, the audio seed, " +
        "anything) is being shipped into the worker",
    );
    assert(a.indexOf(TOKEN) === -1, "THE SESSION TOKEN IS IN THE WORKER SHIM");
    assert(a.indexOf("audio") === -1, "the shim mentions audio; it must not");
  },
);

check(
  "the retained shim's seed reproduces the main thread's canvas mask exactly",
  async () => {
    // The other half of the old parity gate. Four seed words that are not the
    // canvas seed (the audio seed, say) would pass the check above; they fail
    // this one, because the two realms would then noise the same pixels
    // differently and a page could read the mask off the diff.
    const { sb, src } = await plantedShim(TOKEN);
    const worker = runShim(src);
    assert(
      worker.__imported.length === 1 &&
        worker.__imported[0] === "https://tracker.example/worker.js",
      "the shim must importScripts the page's own worker by absolute URL",
    );
    for (const [w, h] of [
      [16, 16],
      [7, 3],
      [32, 8],
    ]) {
      const main = maskOf(sb, w, h);
      assert(/[^0,]/.test(main), "the main thread applied no noise");
      assert(
        maskOf(worker, w, h) === main,
        `worker mask != main mask at ${w}x${h}: a revived shim would let a ` +
          `page diff the two realms and read the noised pixels`,
      );
    }
  },
);

(async () => {
  let failed = 0;
  for (const t of tests) {
    try {
      await t.fn();
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
})();
