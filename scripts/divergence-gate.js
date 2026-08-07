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
//   audio      in-place scale exactly once per array (no compounding), the
//              fudge inside [0.99, 1.0)
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

  function AudioBuffer() {
    // The SAME Float32Array on every read, like real engines: the WeakSet
    // must be what stops compounding, not fresh copies hiding it.
    this.samples = new Float32Array([0.5, -0.25, 0.125, 1.0]);
  }
  AudioBuffer.prototype.getChannelData = function () {
    return this.samples;
  };
  AudioBuffer.prototype.copyFromChannel = function (destination) {
    const src = [0.5, -0.25, 0.125, 1.0];
    for (let i = 0; i < destination.length && i < src.length; i++) {
      destination[i] = src[i];
    }
  };
  sandbox.AudioBuffer = AudioBuffer;

  function AnalyserNode() {}
  AnalyserNode.prototype.getByteFrequencyData = function (arr) {
    for (let i = 0; i < arr.length; i++) arr[i] = 200;
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

// ---- (e) audio: scaled once, in place, inside [0.99, 1.0) -----------------
{
  const sb = mkSandbox({ hostname: "example.com" });
  runDivergence(sb, TOKEN_A);
  const buf = new sb.AudioBuffer();
  const first = Array.from(sb.AudioBuffer.prototype.getChannelData.call(buf));
  const second = Array.from(sb.AudioBuffer.prototype.getChannelData.call(buf));
  assert(
    first.join(",") === second.join(","),
    "a second read must not compound the fudge",
  );
  const ratio = first[0] / 0.5;
  assert(
    ratio >= 0.99 && ratio < 1.0,
    "the audio fudge must sit inside [0.99, 1.0), got " + ratio,
  );

  const dest = new Float32Array(4);
  sb.AudioBuffer.prototype.copyFromChannel.call(buf, dest);
  const copyOnce = Array.from(dest);
  sb.AudioBuffer.prototype.copyFromChannel.call(buf, dest);
  assert(
    copyOnce.join(",") === Array.from(dest).join(","),
    "copyFromChannel must scale every call identically, never compound",
  );
  const copyRatio = copyOnce[0] / 0.5;
  assert(
    copyRatio >= 0.99 && copyRatio < 1.0,
    "copyFromChannel fudge out of range: " + copyRatio,
  );

  const analyser = new sb.AnalyserNode();
  const bytes = new Uint8Array(8);
  sb.AnalyserNode.prototype.getByteFrequencyData.call(analyser, bytes);
  for (const b of bytes) {
    assert(b >= 198 && b <= 200, "byte readout must scale gently, got " + b);
  }
  const floats = new Float32Array(8);
  sb.AnalyserNode.prototype.getFloatTimeDomainData.call(analyser, floats);
  const fRatio = floats[0] / 0.5;
  assert(
    fRatio >= 0.99 && fRatio < 1.0,
    "float readout fudge out of range: " + fRatio,
  );
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

console.log("divergence-gate: OK");
