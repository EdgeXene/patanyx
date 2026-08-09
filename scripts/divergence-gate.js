// What fingerprint_divergence.js actually does to the readouts, exercised end to end.
//
// WHY THIS EXISTS. The lesson autofill.js taught twice: a page-world script
// covered only by static greps can ship dead. This gate substitutes a fixed
// test token, runs the real script in a vm sandbox against stub canvas,
// audio, and WebGL prototypes, and asserts the properties the whole feature
// stands on:
//
//   noise      applied at all, small (per-channel delta <= 1), alpha
//              untouched, roughly 1 pixel in 8
//   determinism  same token + same site -> byte-identical noise (a per-load
//              jitter would average away AND make browserleaks hashes churn)
//   keying     different site -> different noise; different token (restart,
//              ephemeral) -> different noise; an iframe keys on its TOP
//              frame's host, not its own
//   encoding   toDataURL routes through the noised clone and falls back to
//              the truth on a zero-size canvas, without throwing
//   audio      perturbed in place exactly once per (buffer, channel); the
//              shift VARIES per sample (a single scalar is removable by
//              normalizing, which is what shipped through 0.9.61); every
//              read path agrees element for element, so no pair of reads
//              yields two versions of one sample to divide or average;
//              the shift is keyed to the buffer's CONTENT, so differencing
//              two known buffers cannot cancel the per-site key
//
//              NOT covered here, honestly: the STRENGTH of the key itself.
//              A gate sees outputs, and a collapsed key space produces
//              outputs that look identical to a strong one. That property
//              is argued in the source comment and has to be reviewed, not
//              asserted.
//   webgl      getParameter answers UNMASKED_* with the MASKED strings and
//              leaves every other pname alone
//   absence    deleting whole API families must not take the others down
//   idempotence  running the script twice must not stack hooks -- stacked
//              noise doubles and breaks the Windows never-register-both rule
//
// Deliberately NOT jsdom: runnable with no dependency beyond node, the same
// as every other gate in this suite.
//
// Run: node scripts/divergence-gate.js  (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SRC = path.join(
  __dirname,
  "..",
  "crates/app/src/content_scripts/fingerprint_divergence.js",
);

const PLACEHOLDER = "__DIVERGENCE_TOKEN__";
const TOKEN_A = "a".repeat(64);
const TOKEN_B = "b".repeat(64);

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const template = fs.readFileSync(SRC, "utf8");
assert(
  template.split(PLACEHOLDER).length === 2,
  "fingerprint_divergence.js must contain the token placeholder exactly once",
);

// ---- stub prototypes, one fresh set per sandbox ---------------------------

// The base image every stub getImageData returns: a fixed R/G/B/A pattern so
// noise is measurable as a delta against it.
const BASE = [100, 150, 200, 255];

function mkSandbox(opts) {
  const sandbox = {};
  sandbox.window = sandbox;
  sandbox.URL = URL; // vm contexts carry ECMAScript built-ins only
  sandbox.location = {
    hostname: opts.hostname,
    ancestorOrigins: opts.ancestors || { length: 0 },
  };

  function Ctx2D() {
    this.put = null;
    this.drew = null;
  }
  Ctx2D.prototype.getImageData = function (x, y, w, h) {
    const data = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < data.length; i += 4) {
      data[i] = BASE[0];
      data[i + 1] = BASE[1];
      data[i + 2] = BASE[2];
      data[i + 3] = BASE[3];
    }
    return { width: w, height: h, data };
  };
  Ctx2D.prototype.putImageData = function (img) {
    this.put = img;
  };
  Ctx2D.prototype.drawImage = function (src) {
    this.drew = src;
  };
  sandbox.CanvasRenderingContext2D = Ctx2D;

  function Canvas() {
    this.width = 8;
    this.height = 8;
    this.ctx = new Ctx2D();
    this.clone = false;
  }
  Canvas.prototype.getContext = function (kind) {
    return kind === "2d" ? this.ctx : null;
  };
  Canvas.prototype.toDataURL = function () {
    return this.clone ? "encoded:clone" : "encoded:self";
  };
  Canvas.prototype.toBlob = function (cb) {
    if (typeof cb === "function") cb(this.clone ? "blob:clone" : "blob:self");
  };
  sandbox.HTMLCanvasElement = Canvas;
  sandbox.document = {
    createElement(tag) {
      assert(tag === "canvas", "the script must only create canvas elements");
      const c = new Canvas();
      c.clone = true;
      return c;
    },
  };

  const AUDIO_TRUE = [0.5, -0.25, 0.125, 0.95, -0.75, 0.3, -0.1, 0.62];
  function AudioBuffer(values) {
    // The SAME Float32Array on every read, like real engines: the mark must
    // be what stops compounding, not fresh copies hiding it.
    this.samples = new Float32Array(values || AUDIO_TRUE);
    this.length = this.samples.length;
  }
  AudioBuffer.prototype.getChannelData = function () {
    return this.samples;
  };
  // COPIES FROM THE LIVE CHANNEL, which is what real engines do and what
  // this mock got wrong until 2026-08-08. It used to write a fresh literal,
  // so an in-place mutation by getChannelData was INVISIBLE here -- and the
  // whole recovery path being fixed (read once, copy once, divide) lived in
  // exactly that blind spot. A mock that cannot observe the defect cannot
  // gate against it.
  AudioBuffer.prototype.copyFromChannel = function (
    destination,
    channelNumber,
    bufferOffset,
  ) {
    const start = bufferOffset === undefined ? 0 : bufferOffset | 0;
    for (
      let i = 0;
      i < destination.length && start + i < this.samples.length;
      i++
    ) {
      destination[i] = this.samples[start + i];
    }
  };
  sandbox.AudioBuffer = AudioBuffer;

  // `fill` lets a test pick the value the engine reports, so the quiet end
  // of the byte range can be exercised: the old multiply-and-round left
  // every small value exactly where it was, and a mock that only ever
  // reports 200 cannot see that.
  function AnalyserNode() {
    this.fill = 200;
    // Real analysers fill only frequencyBinCount / fftSize entries; the rest
    // of a longer array keeps whatever the page left in it.
    this.frequencyBinCount = 1024;
    this.fftSize = 2048;
  }
  AnalyserNode.prototype.getByteFrequencyData = function (arr) {
    for (let i = 0; i < arr.length; i++) arr[i] = this.fill;
  };
  AnalyserNode.prototype.getFloatTimeDomainData = function (arr) {
    for (let i = 0; i < arr.length; i++) arr[i] = 0.5;
  };
  AnalyserNode.prototype.getFloatFrequencyData = function (arr) {
    for (let i = 0; i < arr.length; i++) arr[i] = -60;
  };
  AnalyserNode.prototype.getByteTimeDomainData = function (arr) {
    for (let i = 0; i < arr.length; i++) arr[i] = 128;
  };
  sandbox.AnalyserNode = AnalyserNode;

  function WebGL() {}
  WebGL.prototype.getParameter = function (pname) {
    return "param:" + pname;
  };
  sandbox.WebGLRenderingContext = WebGL;
  function WebGL2() {}
  WebGL2.prototype.getParameter = function (pname) {
    return "param2:" + pname;
  };
  sandbox.WebGL2RenderingContext = WebGL2;

  // Element / Range geometry, and a real DOMRect. The stubs return KNOWN
  // sub-pixel dimensions so the gate can measure the installed hook's actual
  // shift against the truth -- not a formula reimplemented in the gate, which
  // would only test the copy: run the real hook, never a copied formula.
  function DOMRect(x, y, w, h) {
    this.x = x;
    this.y = y;
    this.width = w;
    this.height = h;
    this.left = w < 0 ? x + w : x;
    this.top = h < 0 ? y + h : y;
    this.right = w < 0 ? x : x + w;
    this.bottom = h < 0 ? y : y + h;
  }
  DOMRect.prototype.toJSON = function () {
    return {
      x: this.x,
      y: this.y,
      width: this.width,
      height: this.height,
      top: this.top,
      right: this.right,
      bottom: this.bottom,
      left: this.left,
    };
  };
  sandbox.DOMRect = DOMRect;
  // The true geometry the stub reports. Fractions chosen away from a .5
  // rounding boundary so the clamp does not mask the noise here.
  const TRUE_RECT = { x: 12.2, y: 34.8, width: 100.31, height: 40.77 };
  function Element() {}
  Element.prototype.getBoundingClientRect = function () {
    return new DOMRect(
      TRUE_RECT.x,
      TRUE_RECT.y,
      TRUE_RECT.width,
      TRUE_RECT.height,
    );
  };
  Element.prototype.getClientRects = function () {
    const list = [
      new DOMRect(TRUE_RECT.x, TRUE_RECT.y, TRUE_RECT.width, TRUE_RECT.height),
    ];
    list.item = function (i) {
      return i >>> 0 < list.length ? list[i >>> 0] : null;
    };
    return list;
  };
  sandbox.Element = Element;
  function Range() {}
  Range.prototype.getBoundingClientRect =
    Element.prototype.getBoundingClientRect;
  Range.prototype.getClientRects = Element.prototype.getClientRects;
  sandbox.Range = Range;
  sandbox.__TRUE_RECT = TRUE_RECT;

  // navigator with an over-the-cap machine, so a revert to no-normalization
  // is observable: the cap gate is only fail-able on a >8 machine, so
  // the STUB provides one deterministically).
  sandbox.navigator = { hardwareConcurrency: 24, deviceMemory: 32 };
  function Navigator() {}
  Navigator.prototype = Object.getPrototypeOf(sandbox.navigator);
  sandbox.Navigator = Navigator;

  if (opts.strip) {
    for (const name of opts.strip) delete sandbox[name];
  }

  vm.createContext(sandbox);
  return sandbox;
}

function runDivergence(sandbox, token) {
  vm.runInContext(template.replace(PLACEHOLDER, token), sandbox, {
    filename: "fingerprint_divergence.js",
  });
}

// Read a 16x16 image through the (patched) prototype and return the noise
// mask: for each byte, output minus the base pattern.
function readNoise(sandbox) {
  const ctx = new sandbox.CanvasRenderingContext2D();
  const img = sandbox.CanvasRenderingContext2D.prototype.getImageData.call(
    ctx,
    0,
    0,
    16,
    16,
  );
  const deltas = [];
  for (let i = 0; i < img.data.length; i++) {
    deltas.push(img.data[i] - BASE[i % 4]);
  }
  return deltas;
}

// ---- (a) noise is applied, small, alpha-clean, ~1/8 of pixels -------------
{
  const sb = mkSandbox({ hostname: "example.com" });
  runDivergence(sb, TOKEN_A);
  const noise = readNoise(sb);
  let touchedPixels = 0;
  for (let i = 0; i < noise.length; i += 4) {
    assert(Math.abs(noise[i]) <= 1, "R delta must be at most 1");
    assert(Math.abs(noise[i + 1]) <= 1, "G delta must be at most 1");
    assert(Math.abs(noise[i + 2]) <= 1, "B delta must be at most 1");
    assert(noise[i + 3] === 0, "alpha must never be touched");
    if (noise[i] || noise[i + 1] || noise[i + 2]) touchedPixels++;
  }
  // 256 pixels at 1-in-8: expect ~32; binomial spread makes 10..70 safe and
  // still catches both "nothing happened" and "everything happened".
  assert(touchedPixels > 10, "noise must touch a real share of pixels");
  assert(touchedPixels < 70, "noise must stay around one pixel in eight");
}

// ---- (b) determinism: same token + host -> byte-identical -----------------
{
  const one = mkSandbox({ hostname: "example.com" });
  runDivergence(one, TOKEN_A);
  const two = mkSandbox({ hostname: "example.com" });
  runDivergence(two, TOKEN_A);
  assert(
    readNoise(one).join(",") === readNoise(two).join(","),
    "identical token and site must produce byte-identical noise",
  );
}

// ---- (c) keying: site, token, and top-frame all matter --------------------
{
  const base = mkSandbox({ hostname: "example.com" });
  runDivergence(base, TOKEN_A);
  const baseNoise = readNoise(base).join(",");

  const otherSite = mkSandbox({ hostname: "example.org" });
  runDivergence(otherSite, TOKEN_A);
  assert(
    readNoise(otherSite).join(",") !== baseNoise,
    "a different site must see different noise",
  );

  const otherToken = mkSandbox({ hostname: "example.com" });
  runDivergence(otherToken, TOKEN_B);
  assert(
    readNoise(otherToken).join(",") !== baseNoise,
    "a different token (restart, ephemeral) must produce different noise",
  );

  // An iframe keys on the TOP frame's host: a fingerprint iframe from
  // fingerprinter.example embedded on example.com must get exactly the
  // noise example.com itself gets, not its own host's noise everywhere it
  // is embedded.
  const framed = mkSandbox({
    hostname: "fingerprinter.example",
    ancestors: { length: 1, 0: "https://example.com" },
  });
  runDivergence(framed, TOKEN_A);
  assert(
    readNoise(framed).join(",") === baseNoise,
    "an iframe must key on its top frame's host",
  );
}

// ---- (d) toDataURL/toBlob route through the noised clone, and fall back ---
{
  const sb = mkSandbox({ hostname: "example.com" });
  runDivergence(sb, TOKEN_A);
  const canvas = new sb.HTMLCanvasElement();
  const out = sb.HTMLCanvasElement.prototype.toDataURL.call(canvas);
  assert(out === "encoded:clone", "toDataURL must encode the noised clone");
  // The clone actually received noised pixels: drawImage saw the source
  // canvas and putImageData carried bytes differing from the base pattern.
  let putSeen = null;
  let drewSeen = null;
  // The clone is reachable through document.createElement in the script
  // only; recreate the observation by calling again with a recording
  // createElement.
  const record = [];
  const origCreate = sb.document.createElement;
  sb.document.createElement = function (tag) {
    const c = origCreate.call(this, tag);
    record.push(c);
    return c;
  };
  sb.HTMLCanvasElement.prototype.toDataURL.call(canvas);
  sb.document.createElement = origCreate;
  assert(record.length === 1, "one clone canvas per encode");
  putSeen = record[0].ctx.put;
  drewSeen = record[0].ctx.drew;
  assert(drewSeen === canvas, "the clone must draw the original canvas");
  assert(putSeen && putSeen.data, "the clone must receive putImageData");
  let differing = 0;
  for (let i = 0; i < putSeen.data.length; i++) {
    const delta = putSeen.data[i] - BASE[i % 4];
    assert(Math.abs(delta) <= 1, "clone noise must stay at one bit");
    if (delta !== 0) differing++;
  }
  assert(differing > 0, "the clone's pixels must actually be noised");

  const blob = [];
  sb.HTMLCanvasElement.prototype.toBlob.call(canvas, (b) => blob.push(b));
  assert(blob[0] === "blob:clone", "toBlob must encode the noised clone");

  // Zero-size canvas: no clone possible; the truth comes back, no throw.
  const empty = new sb.HTMLCanvasElement();
  empty.width = 0;
  const fallback = sb.HTMLCanvasElement.prototype.toDataURL.call(empty);
  assert(
    fallback === "encoded:self",
    "a zero-size canvas must fall back to the original encoder",
  );
}

// ---- (e) audio: per-sample, content-keyed, and NOT invertible -------------
//
// Until 0.9.61 the audio noise was one multiplicative factor per site and
// session. These assertions exist because that shape failed two ways at once
// and the previous gate could see neither: it asserted the factor was inside
// [0.99, 1.0), which is a property only a single scalar HAS, so it was
// pinning the defect rather than the requirement.
{
  const sb = mkSandbox({ hostname: "example.com" });
  runDivergence(sb, TOKEN_A);
  const TRUE_VALUES = [0.5, -0.25, 0.125, 0.95, -0.75, 0.3, -0.1, 0.62];

  const buf = new sb.AudioBuffer();
  const first = Array.from(sb.AudioBuffer.prototype.getChannelData.call(buf));
  const second = Array.from(sb.AudioBuffer.prototype.getChannelData.call(buf));
  assert(
    first.join(",") === second.join(","),
    "a second read must not compound the shift",
  );

  // Every sample moved, and none by more than the stated linear bound.
  //
  // The test vector deliberately avoids exactly +/-1.0. A sample sitting on
  // the clamp boundary is pushed back to 1.0 whenever its shift happens to
  // be positive, so "this sample moved" would then pass or fail on the key
  // rather than on the code. Clamping gets its own assertion below instead.
  for (let i = 0; i < TRUE_VALUES.length; i++) {
    const d = Math.abs(first[i] - TRUE_VALUES[i]);
    assert(d > 0, "sample " + i + " was left untouched");
    assert(
      d <= 0.0051,
      "sample " + i + " moved " + d + ", over the 0.005 bound",
    );
  }

  // Clamping, asserted directly: a sample already inside [-1, 1] must stay
  // inside it, and one the page put OUTSIDE that range must not be dragged
  // in. Real buffers legitimately carry values past 1.0 before a limiter
  // runs, and quietly flattening them would corrupt audio.
  {
    const edge = new sb.AudioBuffer([1.0, -1.0, 1.2, -1.2]);
    const got = sb.AudioBuffer.prototype.getChannelData.call(edge);
    assert(got[0] <= 1 && got[1] >= -1, "an in-range sample left [-1, 1]");
    assert(
      got[2] > 1.19 && got[2] < 1.21,
      "an out-of-range sample was clamped, corrupting pre-limiter audio",
    );
    assert(got[3] < -1.19 && got[3] > -1.21, "same, negative side");
  }

  // THE REVERT DETECTOR. A single scalar gives every sample the same ratio,
  // so the spread is exactly zero and normalizing removes the noise
  // completely. Anyone who reintroduces one fails here.
  const ratios = TRUE_VALUES.map((v, i) => first[i] / v);
  const spread = Math.max(...ratios) - Math.min(...ratios);
  assert(
    spread > 1e-6,
    "every sample shares one ratio (spread " +
      spread +
      "), so the noise is a single scalar and normalization removes it",
  );
  // The ratio test alone only catches a MULTIPLICATIVE revert: for an
  // additive constant c the ratio (v - c) / v still varies with v, so the
  // spread above looks healthy while the noise is just as removable. Assert
  // on the shift itself, which is flat for either kind of constant.
  const shifts = TRUE_VALUES.map((v, i) => first[i] - v);
  const shiftSpread = Math.max(...shifts) - Math.min(...shifts);
  // 1e-4, not something smaller: these are Float32 values, so storing even a
  // genuinely constant shift leaves about 1e-7 of quantization scatter
  // between samples. A threshold under that reads the scatter as variation
  // and passes a constant. Real per-sample shifts span up to 0.01, so 1e-4
  // separates the two by orders of magnitude. (Found by planting exactly
  // that constant and watching a 1e-9 threshold let it through.)
  assert(
    shiftSpread > 1e-4,
    "every sample got the same shift (spread " +
      shiftSpread +
      "), so the noise is one constant, not per-sample",
  );

  // CROSS-PATH AGREEMENT. This is the direct regression test for the
  // recovery path: under the old code the copy went through the scale a
  // second time, so dest[i] / a[i] was the factor itself, in one division.
  const dest = new Float32Array(TRUE_VALUES.length);
  sb.AudioBuffer.prototype.copyFromChannel.call(buf, dest, 0, 0);
  for (let i = 0; i < TRUE_VALUES.length; i++) {
    assert(
      dest[i] === first[i],
      "copyFromChannel disagrees with getChannelData at " +
        i +
        " (" +
        dest[i] +
        " vs " +
        first[i] +
        "), which hands a site two readings of one sample",
    );
  }

  // Same, with the read order REVERSED on a fresh buffer: a copy taken
  // before any getChannelData must still match what getChannelData later
  // reports, or the result depends on the order a site happens to read in.
  {
    const b2 = new sb.AudioBuffer();
    const early = new Float32Array(TRUE_VALUES.length);
    sb.AudioBuffer.prototype.copyFromChannel.call(b2, early, 0, 0);
    const live = sb.AudioBuffer.prototype.getChannelData.call(b2);
    for (let i = 0; i < TRUE_VALUES.length; i++) {
      assert(early[i] === live[i], "read order changes the samples at " + i);
    }
  }

  // A PARTIAL copy at an offset must line up with the same absolute
  // positions of a full read. Slice-local keying would break this.
  {
    const b3 = new sb.AudioBuffer();
    const full = Array.from(sb.AudioBuffer.prototype.getChannelData.call(b3));
    const b4 = new sb.AudioBuffer();
    const part = new Float32Array(3);
    sb.AudioBuffer.prototype.copyFromChannel.call(b4, part, 0, 2);
    for (let i = 0; i < 3; i++) {
      assert(
        part[i] === full[2 + i],
        "a copy at offset 2 disagrees with absolute index " + (2 + i),
      );
    }
  }

  // CONTENT KEYING: different samples must get a different shift vector,
  // or a site can cancel the per-site key by differencing two known buffers.
  {
    const other = new sb.AudioBuffer([
      0.5, -0.25, 0.125, 1.0, -0.75, 0.3, -0.1, 0.61,
    ]);
    const shifted = Array.from(
      sb.AudioBuffer.prototype.getChannelData.call(other),
    );
    const vecA = TRUE_VALUES.map((v, i) => first[i] - v);
    const otherTrue = [0.5, -0.25, 0.125, 1.0, -0.75, 0.3, -0.1, 0.61];
    const vecB = otherTrue.map((v, i) => shifted[i] - v);
    let differs = false;
    for (let i = 0; i < vecA.length; i++) {
      if (Math.abs(vecA[i] - vecB[i]) > 1e-9) {
        differs = true;
      }
    }
    assert(
      differs,
      "two different buffers got the same shift vector, so a site can " +
        "difference two known buffers and cancel the key",
    );
  }

  const analyser = new sb.AnalyserNode();
  // Bytes: exactly one step, always, and never out of range. The old
  // multiply-and-round left every small value where it was.
  const bytes = new Uint8Array(8);
  sb.AnalyserNode.prototype.getByteFrequencyData.call(analyser, bytes);
  for (const b of bytes) {
    assert(b >= 0 && b <= 255, "byte readout left the range: " + b);
    assert(
      Math.abs(b - 200) === 1,
      "byte readout must move by exactly one step, got " + b,
    );
  }
  {
    // A value the old code could not move at all, because 3 * 0.99 rounds
    // back to 3. This is the assertion that fails on a revert.
    const quiet = new sb.AnalyserNode();
    quiet.fill = 3;
    const qb = new Uint8Array(4);
    sb.AnalyserNode.prototype.getByteFrequencyData.call(quiet, qb);
    for (const b of qb) {
      assert(b !== 3, "a quiet byte bin was left unmoved");
    }
  }

  const floats = new Float32Array(8);
  sb.AnalyserNode.prototype.getFloatTimeDomainData.call(analyser, floats);
  const fSpread = (() => {
    const r = [];
    for (let i = 0; i < floats.length; i++) r.push(floats[i] / 0.5);
    return Math.max(...r) - Math.min(...r);
  })();
  assert(fSpread > 1e-6, "analyser time-domain noise is a single scalar");
}

// ---- (f) webgl: UNMASKED_* masked, everything else untouched --------------
{
  const sb = mkSandbox({ hostname: "example.com" });
  runDivergence(sb, TOKEN_A);
  const gl = new sb.WebGLRenderingContext();
  const get = sb.WebGLRenderingContext.prototype.getParameter;
  assert(
    get.call(gl, 37445) === "param:" + 0x1f00,
    "UNMASKED_VENDOR_WEBGL must answer with masked VENDOR",
  );
  assert(
    get.call(gl, 37446) === "param:" + 0x1f01,
    "UNMASKED_RENDERER_WEBGL must answer with masked RENDERER",
  );
  assert(
    get.call(gl, 3379) === "param:3379",
    "other pnames must pass through untouched",
  );
  const gl2 = new sb.WebGL2RenderingContext();
  assert(
    sb.WebGL2RenderingContext.prototype.getParameter.call(gl2, 37446) ===
      "param2:" + 0x1f01,
    "WebGL2 must be masked independently of WebGL1",
  );
}

// ---- (g) hook independence: missing APIs take nothing else down -----------
{
  const sb = mkSandbox({
    hostname: "example.com",
    strip: [
      "AnalyserNode",
      "WebGLRenderingContext",
      "WebGL2RenderingContext",
      "AudioBuffer",
    ],
  });
  runDivergence(sb, TOKEN_A); // throwing here fails the gate
  const noise = readNoise(sb);
  assert(
    noise.some((d) => d !== 0),
    "canvas hooks must install even when audio and WebGL are absent",
  );
}

// ---- (h) idempotence: a second registration must not stack ----------------
{
  const sb = mkSandbox({ hostname: "example.com" });
  runDivergence(sb, TOKEN_A);
  const once = readNoise(sb).join(",");
  const patched = sb.CanvasRenderingContext2D.prototype.getImageData;
  runDivergence(sb, TOKEN_A);
  assert(
    sb.CanvasRenderingContext2D.prototype.getImageData === patched,
    "a second run must leave the installed hooks alone",
  );
  assert(
    readNoise(sb).join(",") === once,
    "a second run must not change the noise",
  );
}

// ---- (i) element measurement: sub-pixel, bounded, round-safe, keyed -------
//
// Every assertion runs the REAL installed hook against the stub's KNOWN
// geometry, so it measures the shipped shift, not a formula copied into the
// gate: run the real hook, never a copied formula.
{
  const T = mkSandbox({ hostname: "a.example" }).__TRUE_RECT;
  const a = mkSandbox({ hostname: "a.example" });
  runDivergence(a, TOKEN_A);
  const el = new a.Element();
  const r1 = a.Element.prototype.getBoundingClientRect.call(el);
  const r2 = a.Element.prototype.getBoundingClientRect.call(el);

  // Determinism: the same measurement twice is byte-identical.
  for (const f of [
    "x",
    "y",
    "width",
    "height",
    "top",
    "right",
    "bottom",
    "left",
  ]) {
    assert(r1[f] === r2[f], `getBoundingClientRect.${f} is not deterministic`);
  }

  // The bound, on the INSTALLED hook: width/height moved, by < 0.25px.
  assert(r1.width !== T.width, "width was not noised at all");
  assert(r1.height !== T.height, "height was not noised at all");
  assert(Math.abs(r1.width - T.width) < 0.25, "width shift exceeds 0.25px");
  assert(Math.abs(r1.height - T.height) < 0.25, "height shift exceeds 0.25px");

  // The rounding invariant: a site reading Math.round sees no change.
  assert(Math.round(r1.width) === Math.round(T.width), "rounded width changed");
  assert(
    Math.round(r1.height) === Math.round(T.height),
    "rounded height changed",
  );

  // Positions are exact (scroll-stable; the residual leak is deliberate).
  assert(r1.x === T.x && r1.y === T.y, "positions must pass through exactly");

  // Consistency: right/bottom derived from x/y + w/h.
  assert(r1.right === r1.x + r1.width, "right !== x + width");
  assert(r1.bottom === r1.y + r1.height, "bottom !== y + height");
  assert(r1.left === r1.x && r1.top === r1.y, "left/top must equal x/y");

  // A real DOMRect, not a bare object, so instanceof and toJSON match native.
  assert(
    r1 instanceof a.DOMRect,
    "getBoundingClientRect must return a DOMRect",
  );

  // getClientRects: usable list with a working item().
  const list = a.Element.prototype.getClientRects.call(el);
  assert(list.length === 1, "getClientRects length wrong");
  assert(list.item(0) === list[0], "item(0) must equal [0]");
  assert(list.item(9) === null && list.item(-1) === null, "item() range wrong");
  assert(Math.abs(list[0].width - T.width) < 0.25, "list rect width unbounded");

  // Content-keying, not a shared per-site offset: the 512px-alias case
  // flagged. Two dimensions exactly 512px apart must NOT receive the same
  // shift (the old 2^23 digest aliased them).
  const sh100 = r1.width - T.width;
  // width 100.31 and 612.31 differ by 512; drive a fresh stub reporting the
  // larger width and compare the shift.
  const big = mkSandbox({ hostname: "a.example" });
  big.__TRUE_RECT.width = T.width + 512;
  big.Element.prototype.getBoundingClientRect = function () {
    return new big.DOMRect(T.x, T.y, T.width + 512, T.height);
  };
  runDivergence(big, TOKEN_A);
  const rb = big.Element.prototype.getBoundingClientRect.call(
    new big.Element(),
  );
  const shBig = rb.width - (T.width + 512);
  assert(
    Math.abs(sh100 - shBig) > 1e-9,
    "widths 512px apart got the same shift: the digest is aliasing (2^23 bug)",
  );

  // ROUND-INVARIANT SWEEP. The clamp only bites near a .5
  // boundary, so a single mid-bucket value never exercises it. Sweep many
  // knife-edge widths -- fractions within a quarter pixel of .5 -- and assert
  // Math.round is preserved for every one. Without the clamp, at least one
  // deterministic shift crosses the boundary and this fails; with it, none do.
  const sweep = mkSandbox({ hostname: "a.example" });
  runDivergence(sweep, TOKEN_A);
  const sweepEl = new sweep.Element();
  let crossed = 0;
  for (let base = 10; base <= 400; base += 7) {
    for (const frac of [0.27, 0.4, 0.49, 0.51, 0.6, 0.73]) {
      const W = base + frac;
      sweep.__TRUE_RECT.width = W;
      const rr = sweep.Element.prototype.getBoundingClientRect.call(sweepEl);
      if (Math.round(rr.width) !== Math.round(W)) crossed += 1;
      assert(
        Math.round(rr.width) === Math.round(W),
        "a knife-edge width " + W + " crossed a rounding boundary (clamp gone)",
      );
      assert(Math.abs(rr.width - W) < 0.25, "swept width shift exceeds 0.25px");
    }
  }
  assert(crossed === 0, "internal: crossings should be zero with the clamp");

  // Content-key REVERT proof: two different origins must give different
  // width shifts for the same true width (else the noise is not keyed and a
  // revert to no-noise would still pass everything above).
  const b = mkSandbox({ hostname: "b.example" });
  runDivergence(b, TOKEN_A);
  const rbHost = b.Element.prototype.getBoundingClientRect.call(
    new b.Element(),
  );
  assert(
    rbHost.width !== r1.width,
    "two sites got the same noised width: the noise is not site-keyed",
  );
}

// ---- (j) navigator hints: capped at 8, never above the truth --------------
{
  const sb = mkSandbox({ hostname: "example.com" }); // stub reports 24 / 32
  runDivergence(sb, TOKEN_A);
  assert(
    sb.navigator.hardwareConcurrency === 8,
    "hardwareConcurrency must be capped to 8, got " +
      sb.navigator.hardwareConcurrency,
  );
  assert(
    sb.navigator.deviceMemory === 8,
    "deviceMemory must be capped to 8, got " + sb.navigator.deviceMemory,
  );
  // A value already at or below the cap passes through untouched.
  const low = mkSandbox({ hostname: "example.com" });
  low.navigator = { hardwareConcurrency: 4, deviceMemory: 4 };
  runDivergence(low, TOKEN_A);
  assert(
    low.navigator.hardwareConcurrency === 4 && low.navigator.deviceMemory === 4,
    "values at or below the cap must pass through",
  );
}

console.log("divergence-gate: OK");
