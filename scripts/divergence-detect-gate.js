// How DETECTABLE Fingerprint Divergence is, measured rather than asserted.
//
// WHY THIS EXISTS, and why it is separate from divergence-gate.js. That gate
// asks whether the noise does its job. This one asks the opposite question:
// how easily can a site tell the noise is THERE? The two are not the same
// property, and the second one has teeth of its own, because "browser that
// farbles in exactly this way" is itself an identifying bit, and a small
// population makes it an expensive one.
//
// Detection is not the same as removal either. A site can always tell that a
// reading was perturbed if it supplied the input and knows the true answer;
// no noise-based defense escapes that, here or anywhere else. What matters is
// that the set of techniques which succeed is SMALL, UNDERSTOOD, and does not
// grow by accident.
//
// So this gate pins the exact set. Not a count -- a set. A technique that
// starts detecting us fails the gate, and so does one that stops, because a
// silent improvement means the published figure is now wrong and someone has
// to go and change it on purpose.
//
// This gate caught a real regression the day it was written: a per-sample
// ADDITIVE shift (introduced while fixing invertibility) turned an all-zero
// buffer into a -46 dBFS hiss. Silence stopped being silent, which is an
// audio defect before it is a privacy one, and technique A found it in one
// line of script. It also caught a bug in ITSELF: an early version of
// technique G overrode an instance method, but the patched prototype calls
// the ORIGINAL prototype, so the override was never reached and the probe
// silently measured the wrong value. Both are recorded here because a
// measurement nobody has seen fail is not a measurement.
//
// Run: node scripts/divergence-detect-gate.js  (or via chrome-js-gate.sh)
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

// THE PINNED SET: techniques that DO detect us today, each with the reason it
// is accepted. Changing this list is a deliberate act, and the website figure
// moves with it.
const EXPECTED_DETECTED = {
  B: "a constant signal stops being constant. Inherent: per-sample variation is exactly what stops normalization removing the noise, and a DC input has no variation to hide in.",
  C: "the page supplied the input and knows the true answer. Inherent to every noise-based defense; nothing can both perturb a value and return the one already known.",
  F: "a flat spectrum stops being flat. Same shape as B.",
  H: "a uniform canvas fill reads back non-uniform. Inherent to canvas noise; the alternative is not perturbing the readout at all.",
  K: "Function.prototype.toString shows the wrapper. DELIBERATE, per the no-stealth rule in the script header: hiding imperfectly is a stronger signal than not hiding.",
};

function mkSandbox(over) {
  over = over || {};
  const sb = {};
  sb.window = sb;
  sb.URL = URL;
  sb.location = { hostname: "tracker.example", ancestorOrigins: { length: 0 } };
  sb.Object = Object;

  const FILL = [255, 0, 0, 255];
  function Ctx2D() {}
  Ctx2D.prototype.getImageData = function (x, y, w, h) {
    const data = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < data.length; i += 4) {
      data[i] = FILL[0];
      data[i + 1] = FILL[1];
      data[i + 2] = FILL[2];
      data[i + 3] = FILL[3];
    }
    return { width: w, height: h, data };
  };
  Ctx2D.prototype.putImageData = function () {};
  Ctx2D.prototype.drawImage = function () {};
  sb.CanvasRenderingContext2D = Ctx2D;
  function Canvas() {
    this.width = 32;
    this.height = 32;
    this.ctx = new Ctx2D();
  }
  Canvas.prototype.getContext = function () {
    return this.ctx;
  };
  Canvas.prototype.toDataURL = function () {
    return "enc";
  };
  Canvas.prototype.toBlob = function (cb) {
    cb("blob");
  };
  sb.HTMLCanvasElement = Canvas;
  sb.document = {
    createElement() {
      return new Canvas();
    },
  };

  function AudioBuffer(values) {
    this.samples = new Float32Array(values);
    this.length = this.samples.length;
  }
  AudioBuffer.prototype.getChannelData = function () {
    return this.samples;
  };
  AudioBuffer.prototype.copyFromChannel = function (d, c, off) {
    const s = off === undefined ? 0 : off | 0;
    for (let i = 0; i < d.length && s + i < this.samples.length; i++) {
      d[i] = this.samples[s + i];
    }
  };
  sb.AudioBuffer = AudioBuffer;

  function AnalyserNode() {
    this.frequencyBinCount = 1024;
    this.fftSize = 2048;
  }
  AnalyserNode.prototype.getByteFrequencyData = function (a) {
    for (let i = 0; i < a.length; i++) a[i] = 200;
  };
  // Overridable on the PROTOTYPE, never the instance: the patched method
  // calls the original PROTOTYPE method, so an instance override is dead
  // code and the probe would silently measure the default instead.
  AnalyserNode.prototype.getFloatFrequencyData =
    over.floatFreq ||
    function (a) {
      for (let i = 0; i < a.length; i++) a[i] = -60;
    };
  AnalyserNode.prototype.getFloatTimeDomainData = function (a) {
    for (let i = 0; i < a.length; i++) a[i] = 0.5;
  };
  AnalyserNode.prototype.getByteTimeDomainData = function (a) {
    for (let i = 0; i < a.length; i++) a[i] = 128;
  };
  sb.AnalyserNode = AnalyserNode;

  function GL() {}
  GL.prototype.getParameter = function (p) {
    return "param:" + p;
  };
  sb.WebGLRenderingContext = GL;
  sb.WebGL2RenderingContext = GL;

  vm.createContext(sb);
  vm.runInContext(template.replace("__DIVERGENCE_TOKEN__", TOKEN), sb);
  return sb;
}

const TECHNIQUES = {
  A: {
    what: "digital silence: an all-zero buffer must read back as zeros",
    run: (sb) => {
      const b = new sb.AudioBuffer(new Float32Array(64));
      const out = sb.AudioBuffer.prototype.getChannelData.call(b);
      return Array.from(out).some((v) => v !== 0);
    },
  },
  B: {
    what: "a constant (DC) signal must stay constant",
    run: (sb) => {
      const b = new sb.AudioBuffer(new Float32Array(64).fill(0.5));
      const out = Array.from(sb.AudioBuffer.prototype.getChannelData.call(b));
      return new Set(out).size > 1;
    },
  },
  C: {
    what: "known input read back and compared against the truth",
    run: (sb) => {
      const known = [0.1, 0.2, 0.3, 0.4];
      const b = new sb.AudioBuffer(new Float32Array(known));
      const out = sb.AudioBuffer.prototype.getChannelData.call(b);
      return known.some((v, i) => Math.abs(out[i] - v) > 1e-9);
    },
  },
  D: {
    what: "two reads of one buffer differing (would allow averaging the noise away)",
    run: (sb) => {
      const b = new sb.AudioBuffer(new Float32Array([0.5, -0.25, 0.125, 0.62]));
      const a1 = Array.from(sb.AudioBuffer.prototype.getChannelData.call(b));
      const a2 = Array.from(sb.AudioBuffer.prototype.getChannelData.call(b));
      return a1.join() !== a2.join();
    },
  },
  E: {
    what: "getChannelData vs copyFromChannel disagreeing (leaks the shift by division)",
    run: (sb) => {
      const b = new sb.AudioBuffer(new Float32Array([0.5, -0.25, 0.125, 0.62]));
      const a = Array.from(sb.AudioBuffer.prototype.getChannelData.call(b));
      const d = new Float32Array(4);
      sb.AudioBuffer.prototype.copyFromChannel.call(b, d, 0, 0);
      return Array.from(d).some((v, i) => v !== a[i]);
    },
  },
  F: {
    what: "a flat byte spectrum must stay flat",
    run: (sb) => {
      const n = new sb.AnalyserNode();
      const a = new Uint8Array(32);
      sb.AnalyserNode.prototype.getByteFrequencyData.call(n, a);
      return new Set(Array.from(a)).size > 1;
    },
  },
  G: {
    what: "-Infinity bins (true silence) must not become finite",
    run: () => {
      const sb = mkSandbox({
        floatFreq: function (a) {
          for (let i = 0; i < a.length; i++) a[i] = -Infinity;
        },
      });
      const n = new sb.AnalyserNode();
      const a = new Float32Array(16);
      sb.AnalyserNode.prototype.getFloatFrequencyData.call(n, a);
      return Array.from(a).some((v) => v !== -Infinity);
    },
  },
  H: {
    what: "a uniform canvas fill must read back uniform",
    run: (sb) => {
      const c = new sb.HTMLCanvasElement();
      const ctx = sb.HTMLCanvasElement.prototype.getContext.call(c);
      const img = sb.CanvasRenderingContext2D.prototype.getImageData.call(
        ctx,
        0,
        0,
        32,
        32,
      );
      const seen = new Set();
      for (let i = 0; i < img.data.length; i += 4) seen.add(img.data[i]);
      return seen.size > 1;
    },
  },
  I: {
    what: "two canvas reads differing (would allow averaging)",
    run: (sb) => {
      const c = new sb.HTMLCanvasElement();
      const ctx = sb.HTMLCanvasElement.prototype.getContext.call(c);
      const g = () =>
        Array.from(
          sb.CanvasRenderingContext2D.prototype.getImageData.call(
            ctx,
            0,
            0,
            8,
            8,
          ).data,
        ).join();
      return g() !== g();
    },
  },
  J: {
    what: "opaque alpha must stay exactly 255",
    run: (sb) => {
      const c = new sb.HTMLCanvasElement();
      const ctx = sb.HTMLCanvasElement.prototype.getContext.call(c);
      const img = sb.CanvasRenderingContext2D.prototype.getImageData.call(
        ctx,
        0,
        0,
        16,
        16,
      );
      for (let i = 3; i < img.data.length; i += 4) {
        if (img.data[i] !== 255) return true;
      }
      return false;
    },
  },
  K: {
    what: "Function.prototype.toString revealing a wrapper",
    run: (sb) =>
      Function.prototype.toString
        .call(sb.AudioBuffer.prototype.getChannelData)
        .indexOf("[native code]") === -1,
  },
  L: {
    what: "a window property naming the browser, found by enumeration",
    run: (sb) => Object.keys(sb).some((n) => /patanyx/i.test(n)),
  },
};

const detected = [];
const failures = [];
for (const id of Object.keys(TECHNIQUES)) {
  const t = TECHNIQUES[id];
  let hit;
  try {
    hit = t.run(mkSandbox());
  } catch (e) {
    failures.push(id + " threw: " + e.message);
    continue;
  }
  if (hit) detected.push(id);
}

const expected = Object.keys(EXPECTED_DETECTED);
const gained = detected.filter((id) => expected.indexOf(id) === -1);
const lost = expected.filter((id) => detected.indexOf(id) === -1);

for (const id of gained) {
  failures.push(
    "NEWLY DETECTABLE: " +
      id +
      " (" +
      TECHNIQUES[id].what +
      "). Divergence got easier to spot. Fix it, or add it to " +
      "EXPECTED_DETECTED with the reason it is accepted and update the " +
      "figure published on the site.",
  );
}
for (const id of lost) {
  failures.push(
    "NO LONGER DETECTABLE: " +
      id +
      " (" +
      TECHNIQUES[id].what +
      "). Good news, but the pinned set and the published figure are now " +
      "wrong. Remove it from EXPECTED_DETECTED on purpose.",
  );
}

console.log(
  "divergence-detect: " +
    detected.length +
    " of " +
    Object.keys(TECHNIQUES).length +
    " techniques detect the noise [" +
    detected.join(", ") +
    "]",
);
if (failures.length) {
  for (const f of failures) console.error("  " + f);
  console.error("DIVERGENCE DETECT GATE FAILED");
  process.exit(1);
}
console.log("divergence-detect-gate: OK");
