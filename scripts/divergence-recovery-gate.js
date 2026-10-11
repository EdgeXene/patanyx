// What a page can RECOVER from fingerprint_divergence.js, exercised against
// the real script with planted defects (security audit 2026-10-08).
//
//   H1  the session token must not reach a page-replaced String.prototype
//       .charCodeAt, and a page-replaced Math.imul must never be CALLED
//       during a canvas, audio or rect read: the hash state passed to imul
//       exposes the token one character at a time, so "no string leaked" is
//       not enough. Two separate planted defects prove each half fails.
//   M1  the canvas mask must not come off with one read of a known solid
//       canvas: after the XOR strip at least 40% of the noised bytes must
//       still be wrong, and repeated reads must stay byte-identical.
//
// Run: node scripts/divergence-recovery-gate.js  (or via chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const SRC = path.join(__dirname, "..", "crates/app/src/content_scripts/fingerprint_divergence.js");
const TOKEN = "f".repeat(64);
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const template = fs.readFileSync(SRC, "utf8");
function prepare(src) {
  return src.replace("__DIVERGENCE_TOKEN__", TOKEN).replace("__DIVERGENCE_OVERRIDES__", "{}");
}
// A realm with stub canvas, audio and rect surfaces, like divergence-gate.js.
function realm(src, pixels) {
  const ctx = vm.createContext({});
  vm.runInContext(`
    var window = this; window.window = window;
    var location = { hostname: "victim.example", ancestorOrigins: { length: 0 } };
    // A backing image of IMGW x IMGH; reads outside it are transparent
    // black, as the engine returns them, so the grown read the noise makes
    // behaves like a real canvas.
    var IMG = null; var IMGW = 64; var IMGH = 64;
    // Floating-point storage for rgba-float16: Float16Array where the runtime
    // has it, Float32Array otherwise (the script tells the two apart from
    // bytes by element size either way).
    var FloatSamples = typeof Float16Array !== "undefined" ? Float16Array : Float32Array;
    // ImageData as the engine shapes it: width, height and data are
    // accessors on the PROTOTYPE, which a page can replace after the script
    // captured them.
    function ImageData(w, h, data) { this.__w = w; this.__h = h; this.__d = data; }
    Object.defineProperty(ImageData.prototype, "width", { configurable: true, get: function () { return this.__w; } });
    Object.defineProperty(ImageData.prototype, "height", { configurable: true, get: function () { return this.__h; } });
    Object.defineProperty(ImageData.prototype, "data", { configurable: true, get: function () { return this.__d; } });
    function Ctx2D() {}
    var SETTINGS_SEEN = [];
    function enforceLong(v) {
      var n = +v;
      if (n !== n || n === Infinity || n === -Infinity || n < -2147483648 || n > 2147483647) throw new TypeError("EnforceRange");
      return n < 0 ? -Math.floor(-n) : Math.floor(n);
    }
    Ctx2D.prototype.getImageData = function (x, y, w, h, settings) {
      // Native semantics: [EnforceRange] long coordinates, a negative size
      // flips the rectangle, zero throws, the settings dictionary is seen.
      if (arguments.length < 4) throw new TypeError("not enough arguments");
      // Dictionary conversion: undefined and null mean defaults, any other
      // non-object is a TypeError.
      if (settings !== undefined && settings !== null && typeof settings !== "object" && typeof settings !== "function") throw new TypeError("not a dictionary");
      x = enforceLong(x); y = enforceLong(y); w = enforceLong(w); h = enforceLong(h);
      // Dictionary conversion: the engine reads the members through their
      // getters on every call, which is what a hostile getter counts on.
      // Enumeration members are converted with ToString on every call, so an
      // object's toString runs here, as it does in the engine.
      // Member by member, each validated before the next getter runs.
      var seen;
      if (settings === undefined || settings === null) { seen = undefined; } else {
        seen = Object.create(null); // the stub must not trip the planted Object.prototype setter itself
        var cs = settings.colorSpace;
        if (cs !== undefined) { cs = String(cs); if (cs !== "srgb" && cs !== "display-p3") throw new TypeError("bad colorSpace"); seen.colorSpace = cs; }
        var pf = settings.pixelFormat;
        if (pf !== undefined) { pf = String(pf); if (pf !== "rgba-unorm8" && pf !== "rgba-float16") throw new TypeError("bad pixelFormat"); seen.pixelFormat = pf; }
      }
      SETTINGS_SEEN.push(seen);
      if (w < 0) { x += w; w = -w; }
      if (h < 0) { y += h; h = -h; }
      if (w === 0 || h === 0) throw new Error("IndexSizeError");
      // rgba-float16 storage is a Float16Array of 0..1 samples, as the engine
      // shapes it.
      var isFloat = seen !== undefined && seen.pixelFormat === "rgba-float16";
      var data = isFloat ? new FloatSamples(w * h * 4) : new Uint8ClampedArray(w * h * 4);
      var scale = isFloat ? 1 / 255 : 1;
      for (var yy = 0; yy < h; yy++) for (var xx = 0; xx < w; xx++) {
        var sx = x + xx, sy = y + yy; if (sx < 0 || sy < 0 || sx >= IMGW || sy >= IMGH) continue;
        var si = (sy * IMGW + sx) * 4, di = (yy * w + xx) * 4;
        data[di] = IMG[si] * scale; data[di+1] = IMG[si+1] * scale; data[di+2] = IMG[si+2] * scale; data[di+3] = IMG[si+3] * scale;
      }
      return new ImageData(w, h, data);
    };
    var CanvasRenderingContext2D = Ctx2D;
    var navigator = {};
    function AudioBuffer() {}
    AudioBuffer.prototype.getChannelData = function () { return new Float32Array(64).fill(0.25); };
    AudioBuffer.prototype.copyFromChannel = function (dst) { dst.set(new Float32Array(dst.length).fill(0.25)); };
    var Element = function () {};
    Element.prototype.getBoundingClientRect = function () { return { x: 1.5, y: 2.5, width: 100.25, height: 50.75, top: 2.5, left: 1.5, right: 101.75, bottom: 53.25 }; };
    // The natives as they were before the script wrapped them: a page that
    // gets one of these as the receiver of a replaced call/apply can read
    // past every noise pass.
    var NATIVES = [Ctx2D.prototype.getImageData, AudioBuffer.prototype.getChannelData, AudioBuffer.prototype.copyFromChannel, Element.prototype.getBoundingClientRect];
  `, ctx);
  vm.runInContext(src, ctx);
  return ctx;
}
// ---- H1: hooked natives see nothing ----------------------------------------
function leakCounts(src) {
  const ctx = realm(src);
  return vm.runInContext(`
    var seen = []; var imulCalls = 0; var captured = 0;
    var origCC = String.prototype.charCodeAt; var origImul = Math.imul;
    String.prototype.charCodeAt = function (i) { if (String(this).indexOf("${TOKEN}") >= 0) seen.push(String(this)); return origCC.call(this, i); };
    Math.imul = function (a, b) { imulCalls++; return origImul(a, b); };
    // Function.prototype.call and apply too: a hash routed through them
    // hands its receiver to whatever a page put there.
    var origCall = Function.prototype.call, origApply = Function.prototype.apply, reflectApply = Reflect.apply, slice = Array.prototype.slice;
    Function.prototype.call = function () { if (NATIVES.indexOf(this) >= 0) captured++; if (arguments.length && String(arguments[0]).indexOf("${TOKEN}") >= 0) seen.push("call:" + String(arguments[0])); return reflectApply(this, arguments[0], reflectApply(slice, arguments, [1])); };
    Function.prototype.apply = function (t, a) { if (NATIVES.indexOf(this) >= 0) captured++; if (String(t).indexOf("${TOKEN}") >= 0) seen.push("apply:" + String(t)); return reflectApply(this, t, a || []); };
    IMG = new Uint8ClampedArray(64 * 64 * 4).fill(200);
    new Ctx2D().getImageData(0, 0, 16, 16);
    // The short-argument path too: the engine's TypeError, never the native.
    try { new Ctx2D().getImageData(); } catch (e) {}
    new AudioBuffer().getChannelData(0);
    new AudioBuffer().copyFromChannel(new Float32Array(8), 0);
    new Element().getBoundingClientRect();
    String.prototype.charCodeAt = origCC; Math.imul = origImul;
    Function.prototype.call = origCall; Function.prototype.apply = origApply;
    ({ leaked: seen.length, imulCalls: imulCalls, captured: captured })
  `, ctx);
}
const real = leakCounts(prepare(template));
assert(real.leaked === 0, "H1: the token reached a page-replaced charCodeAt (" + real.leaked + " times)");
assert(real.imulCalls === 0, "H1: a page-replaced Math.imul was called " + real.imulCalls + " times during reads");
assert(real.captured === 0, "a native reader reached a page-replaced call/apply as its receiver " + real.captured + " times");
// Planted defect 2c: the short-argument path invokes the native through a live .apply.
const liveApply = prepare(template).replace("return fnApply(origGID, this, arguments);", "return origGID.apply(this, arguments);");
assert(liveApply !== prepare(template), "planted defect 2c did not apply");
assert(leakCounts(liveApply).captured > 0, "capture gate cannot see a live .apply on the native (planted defect passed)");
// Planted defect 1: the hash reads charCodeAt live again.
// Each planted defect also empties the eager seed table, so the hash runs in
// page time the way 1.0.5's did; with the table intact a page can hook
// nothing in time, which is the point of the table.
const lazy = (src) => src.replace('var SEED_LABELS = ["canvas", "audio", "clientrects"];', "var SEED_LABELS = [];");
assert(lazy(prepare(template)) !== prepare(template), "the eager seed table is not where the gate expects");
const liveCC = lazy(prepare(template)).replace("k = charCodeAtOf(str, i);", "k = str.charCodeAt(i);");
assert(liveCC !== prepare(template), "planted defect 1 did not apply");
assert(leakCounts(liveCC).leaked > 0, "H1 gate cannot see a live charCodeAt (planted defect passed)");
// Planted defect 2: the hash multiplies through the live Math.imul again.
const liveImul = lazy(prepare(template)).replace("var imul = Math.imul;", "var imul = function (a, b) { return Math.imul(a, b); };");
assert(liveImul !== prepare(template), "planted defect 2 did not apply");
assert(leakCounts(liveImul).imulCalls > 0, "H1 gate cannot see a live Math.imul (planted defect passed)");
// Planted defect 2b: the hash goes through Function.prototype.call at read time.
const liveCall = lazy(prepare(template)).replace("k = charCodeAtOf(str, i);", "k = String.prototype.charCodeAt.call(str, i);");
assert(liveCall !== prepare(template), "planted defect 2b did not apply");
assert(leakCounts(liveCall).leaked > 0, "H1 gate cannot see a live Function.prototype.call (planted defect passed)");
// Every label the script seeds from must be in the eager table, or the
// token is hashed again lazily, in page time.
const labels = new Set(); for (const m of template.matchAll(/(?:rngFor|seedWordsFor)\("([a-z]+)"\)/g)) labels.add(m[1]);
for (const l of labels) assert(template.indexOf('"' + l + '"') >= 0 && /var SEED_LABELS = \[[^\]]*"canvas"[^\]]*\]/.test(template) && new RegExp('var SEED_LABELS = \\[[^\\]]*"' + l + '"').test(template), "label " + l + " is not seeded at document start");
// The eager table alone keeps a live charCodeAt harmless: hooks installed after
// document start never see the token because it was hashed before they existed.
assert(leakCounts(prepare(template).replace("k = charCodeAtOf(str, i);", "k = str.charCodeAt(i);")).leaked === 0, "eager seeding did not pre-empt a page hook");
// ---- M1: one known read does not strip the mask -----------------------------
function stripResidue(src) {
  const ctx = realm(src);
  return vm.runInContext(`
    var N = 64 * 64 * 4; var c = new Ctx2D();
    IMG = new Uint8ClampedArray(N).fill(255);
    var known = c.getImageData(0, 0, 64, 64).data; var mask = known.map(function (v) { return v ^ 255; });
    IMG = Uint8ClampedArray.from({ length: N }, function (_, i) { return (i * 7919) & 255; });
    var a = c.getImageData(0, 0, 64, 64).data; var b = c.getImageData(0, 0, 64, 64).data;
    var changed = 0, wrong = 0, unstable = 0;
    // wrong counts ONLY among the bytes the noise changed: errors the strip
    // introduces elsewhere are not surviving noise (review of this fix).
    for (var i = 0; i < N; i++) { if (a[i] !== IMG[i]) { changed++; if ((a[i] ^ mask[i]) !== IMG[i]) wrong++; } if (a[i] !== b[i]) unstable++; }
    ({ changed: changed, wrong: wrong, unstable: unstable })
  `, ctx);
}
const m = stripResidue(prepare(template));
// A sub-rectangle read must carry exactly the noise the same pixels get in a
// full read: that is what stops shifted reads from voting the truth back.
{
  const ctx3 = realm(prepare(template));
  const r = vm.runInContext(`
    var N = 64 * 64 * 4; var c = new Ctx2D();
    IMG = Uint8ClampedArray.from({ length: N }, function (_, i) { return (i * 7919) & 255; });
    var full = c.getImageData(0, 0, 64, 64).data;
    var mism = 0, changed = 0;
    var crops = [[0,0,64,64],[1,0,63,64],[0,1,64,63],[3,5,20,10],[5,3,10,20],[63,63,1,1],[2,2,-2,-2],[40,30,-24,-20],[64,64,-64,-64]];
    // A coordinate whose conversion changes its answer must not switch the
    // noise off: the hook converts once and hands the engine the numbers.
    var flips = 0; var tricky = { valueOf: function () { flips++; if (flips > 1) throw new Error("second conversion"); return 0; } };
    var trick = c.getImageData(tricky, 0, 16, 16); var trickChanged = 0; for (var ti = 0; ti < 16 * 16 * 4; ti++) { var fx = ti >> 2; if (trick.data[ti] !== IMG[((fx / 16 | 0) * 64 + (fx % 16)) * 4 + (ti & 3)]) trickChanged++; }
    if (trickChanged === 0) throw new Error("a throwing second conversion switched the noise off");
    // Out-of-range and non-finite coordinates throw through the hook, as the
    // engine throws, instead of reading at zero.
    var threw = 0;
    var bad = [4294967296, Infinity, NaN, "no", -2147483649];
    for (var bi = 0; bi < bad.length; bi++) { try { c.getImageData(bad[bi], 0, 1, 1); } catch (e) { if (e instanceof TypeError) threw++; } }
    if (threw !== bad.length) throw new Error("out-of-range coordinates did not throw TypeError through the hook: " + threw + "/" + bad.length);
    // The settings dictionary reaches the engine, on the read and the grown read.
    SETTINGS_SEEN.length = 0; var dict = { colorSpace: "display-p3" }; c.getImageData(0, 0, 4, 4, dict);
    var seenDict = 0; for (var si2 = 0; si2 < SETTINGS_SEEN.length; si2++) if (SETTINGS_SEEN[si2] && SETTINGS_SEEN[si2].colorSpace === "display-p3") seenDict++;
    if (seenDict < 2) throw new Error("the settings dictionary did not reach the engine on both reads: " + seenDict);
    // A getter that swaps the canvas for a known solid on its second
    // invocation must neither run twice nor leave the mask readable.
    var gets = 0; var solidImg = new Uint8ClampedArray(N).fill(255);
    var evil = {}; Object.defineProperty(evil, "colorSpace", { get: function () { gets++; if (gets >= 2) IMG = solidImg; return "srgb"; } });
    IMG = Uint8ClampedArray.from({ length: N }, function (_, i) { return (i * 7919) & 255; });
    var truth = Uint8ClampedArray.from(IMG);
    var noisedEvil = c.getImageData(0, 0, 64, 64, evil).data; IMG = truth;
    if (gets !== 1) throw new Error("a settings getter ran " + gets + " times; it must run once");
    var evilChanged = 0; for (var ei = 0; ei < N; ei++) if (noisedEvil[ei] !== truth[ei]) evilChanged++;
    if (evilChanged === 0) throw new Error("a hostile settings getter switched the noise off");
    // A setter planted on Object.prototype must not reach the snapshot: it
    // would install a getter the engine runs on both reads.
    var planted = 0;
    Object.defineProperty(Object.prototype, "colorSpace", { configurable: true, set: function (v) { planted++; var self = this; Object.defineProperty(self, "colorSpace", { configurable: true, get: function () { gets++; if (gets >= 2) IMG = solidImg; return v; } }); } });
    gets = 0; IMG = solidImg; var knownP = c.getImageData(0, 0, 64, 64).data; var mask = knownP.map(function (v) { return v ^ 255; });
    IMG = Uint8ClampedArray.from(truth);
    var noisedProto = c.getImageData(0, 0, 64, 64, { colorSpace: "srgb" }).data; IMG = truth;
    delete Object.prototype.colorSpace;
    if (planted !== 0) throw new Error("a prototype setter intercepted the settings snapshot");
    var protoChanged = 0, protoWrong = 0; for (var pi = 0; pi < N; pi++) { if (noisedProto[pi] !== truth[pi]) { protoChanged++; if ((noisedProto[pi] ^ mask[pi]) !== truth[pi]) protoWrong++; } }
    if (protoChanged === 0 || protoWrong * 10 < protoChanged * 4) throw new Error("a prototype setter made the mask readable: " + protoWrong + "/" + protoChanged);
    // An object-valued member whose toString swaps the canvas on its second
    // call: converted once in the hook, so the engine never runs it again.
    var strs = 0; var objVal = { toString: function () { strs++; if (strs >= 2) IMG = solidImg; return "srgb"; } };
    IMG = Uint8ClampedArray.from(truth);
    var noisedObj = c.getImageData(0, 0, 64, 64, { colorSpace: objVal }).data; IMG = truth;
    if (strs !== 1) throw new Error("an object-valued setting was converted " + strs + " times; once is the rule");
    var objChanged = 0, objWrong = 0; for (var oi = 0; oi < N; oi++) { if (noisedObj[oi] !== truth[oi]) { objChanged++; if ((noisedObj[oi] ^ mask[oi]) !== truth[oi]) objWrong++; } }
    if (objChanged === 0 || objWrong * 10 < objChanged * 4) throw new Error("an object-valued setting made the mask readable: " + objWrong + "/" + objChanged);
    for (var ci = 0; ci < crops.length; ci++) {
      var cr = crops[ci]; var sub = c.getImageData(cr[0], cr[1], cr[2], cr[3]);
      var ox = cr[0] + (cr[2] < 0 ? cr[2] : 0), oy = cr[1] + (cr[3] < 0 ? cr[3] : 0);
      if (!(sub.width > 0 && sub.height > 0)) throw new Error("stub returned an empty rectangle for " + cr);
      for (var y = 0; y < sub.height; y++) for (var x = 0; x < sub.width; x++) for (var ch = 0; ch < 4; ch++) {
        var si = (y * sub.width + x) * 4 + ch, fi = ((oy + y) * 64 + (ox + x)) * 4 + ch;
        if (sub.data[si] !== full[fi]) mism++;
      }
    }
    // The vote: 8 one-pixel-shifted crops, modal value per pixel, versus the truth.
    var votes = []; for (var i = 0; i < N; i++) votes.push({});
    var shifts = [[0,0],[1,0],[0,1],[1,1],[2,0],[0,2],[2,1],[1,2]];
    for (var s2 = 0; s2 < shifts.length; s2++) {
      var sh = shifts[s2]; var g = c.getImageData(sh[0], sh[1], 64 - sh[0], 64 - sh[1]);
      for (var y = 0; y < g.height; y++) for (var x = 0; x < g.width; x++) for (var ch = 0; ch < 4; ch++) {
        var gi = (y * g.width + x) * 4 + ch, ti = ((sh[1] + y) * 64 + (sh[0] + x)) * 4 + ch;
        var v = g.data[gi]; votes[ti][v] = (votes[ti][v] || 0) + 1;
      }
    }
    var wrongAfterVote = 0;
    for (var i = 0; i < N; i++) { var best = -1, bc = -1; for (var k in votes[i]) { if (votes[i][k] > bc) { bc = votes[i][k]; best = +k; } } if (full[i] !== IMG[i]) { changed++; if (best !== IMG[i]) wrongAfterVote++; } }
    ({ mismatches: mism, changed: changed, wrongAfterVote: wrongAfterVote })
  `, ctx3);
  assert(r.mismatches === 0, "a sub-rectangle read carried different noise than the full read: " + r.mismatches + " bytes");
  assert(r.wrongAfterVote * 10 >= r.changed * 9, "shifted-crop voting recovered noised bytes: " + (r.changed - r.wrongAfterVote) + " of " + r.changed);
}
assert(m.changed > 0, "M1: the canvas was not noised at all");
// The public page says roughly one pixel in eight changes: pin the band.
const pixels = 64 * 64; let changedPixels = 0;
{ const ctx2 = realm(prepare(template)); changedPixels = vm.runInContext(`
    var N = 64 * 64 * 4; var c = new Ctx2D(); IMG = Uint8ClampedArray.from({ length: N }, function (_, i) { return (i * 7919) & 255; });
    var a = c.getImageData(0, 0, 64, 64).data; var n = 0;
    for (var p = 0; p < N; p += 4) { if (a[p] !== IMG[p] || a[p+1] !== IMG[p+1] || a[p+2] !== IMG[p+2]) n++; if (a[p+3] !== IMG[p+3]) throw new Error("alpha touched"); } n`, ctx2); }
assert(changedPixels > pixels * 0.09 && changedPixels < pixels * 0.16, "noise rate is not about one pixel in eight: " + changedPixels + "/" + pixels);
assert(m.unstable === 0, "M1: two identical reads differed in " + m.unstable + " bytes");
assert(m.wrong * 10 >= m.changed * 4, "M1: the known-solid strip removed too much noise (" + m.wrong + " of " + m.changed + " still wrong)");
// Planted defect 3: a mask that ignores the neighbourhood comes straight off.
const flat = prepare(template).replace("var b = windowHash(seed, raw, rawLen, rw, x + pad, y + pad, ax, ay);", "var b = k >>> 5;");
assert(flat !== prepare(template), "planted defect 3 did not apply");
const f = stripResidue(flat);
assert(f.wrong * 10 < f.changed * 4, "M1 gate cannot see a content-independent mask (planted defect passed)");
// ---- Page-replaced accessors must not switch the noise off -------------------
// ImageData's width, height and data, and a typed array's length, are
// prototype getters a page can replace with ones that throw; the noise pass
// then throws into its catch and the true pixels come back (review of this
// fix). Each getter is tried alone, and a primitive settings value must throw.
function hostileAccessors(src) {
  const ctx = realm(src);
  return vm.runInContext(`
    var N = 64 * 64 * 4; var c = new Ctx2D();
    IMG = Uint8ClampedArray.from({ length: N }, function (_, i) { return (i * 7919) & 255; });
    var truth = Uint8ClampedArray.from(IMG);
    var TA = Object.getPrototypeOf(Uint8ClampedArray.prototype);
    var saved = {
      width: Object.getOwnPropertyDescriptor(ImageData.prototype, "width"),
      height: Object.getOwnPropertyDescriptor(ImageData.prototype, "height"),
      data: Object.getOwnPropertyDescriptor(ImageData.prototype, "data"),
      length: Object.getOwnPropertyDescriptor(TA, "length")
    };
    var out = {};
    function trial(name) {
      var target = name === "length" ? TA : ImageData.prototype;
      var orig = saved[name];
      Object.defineProperty(target, name, { configurable: true, get: function () { throw new Error("hostile " + name); } });
      var changed = 0;
      try {
        var img = c.getImageData(0, 0, 64, 64);
        var d = img.__d !== undefined ? img.__d : null;
        for (var i = 0; d && i < N; i++) if (d[i] !== truth[i]) changed++;
      } finally {
        Object.defineProperty(target, name, orig);
      }
      out[name] = changed;
    }
    trial("width"); trial("height"); trial("data"); trial("length");
    // A primitive settings value is a TypeError, not a read with defaults.
    var prim = 0;
    var prims = [true, 1, "srgb", Symbol("x")];
    for (var pi = 0; pi < prims.length; pi++) { try { c.getImageData(0, 0, 1, 1, prims[pi]); } catch (e) { if (e instanceof TypeError) prim++; } }
    out.primitiveThrows = prim; out.primitiveCount = prims.length;
    // Exception order: an invalid colorSpace is a TypeError raised before the
    // pixelFormat getter runs, so a throwing getter there never pre-empts it.
    var pfReads = 0; var ordered = { colorSpace: "bogus", get pixelFormat() { pfReads++; throw new Error("getter ran"); } };
    var orderOk = false; try { c.getImageData(0, 0, 1, 1, ordered); } catch (e) { orderOk = e instanceof TypeError && pfReads === 0; }
    // The same for a value only THIS engine rejects (the stub accepts srgb
    // and display-p3 alone): the engine's verdict, in the engine's order.
    var pfReads2 = 0; var engineOnly = { colorSpace: "rec2100-hlg", get pixelFormat() { pfReads2++; throw new Error("getter ran"); } };
    var engineOrderOk = false; try { c.getImageData(0, 0, 1, 1, engineOnly); } catch (e) { engineOrderOk = e instanceof TypeError && pfReads2 === 0; }
    out.orderOk = orderOk && engineOrderOk;
    // A valid dictionary still reads: the probes must not reject good values.
    var good = c.getImageData(0, 0, 2, 2, { colorSpace: "display-p3", pixelFormat: "rgba-unorm8" });
    out.goodRead = good.__w === 2;
    out
  `, ctx);
}
// ---- Floating-point samples get a small step, never a coercion to 0 or 1 ---
function floatNoise(src) {
  const ctx = realm(src);
  return vm.runInContext(`
    var N = 64 * 64 * 4; var c = new Ctx2D();
    IMG = new Uint8ClampedArray(N).fill(128);
    var a = c.getImageData(0, 0, 64, 64, { pixelFormat: "rgba-float16" }).data;
    var b = c.getImageData(0, 0, 64, 64, { pixelFormat: "rgba-float16" }).data;
    // Float16 rounds the stored sample; compare against the rounded truth
    // with room for one more rounding, and a step is one 8-bit level.
    var truth = new FloatSamples([128 / 255])[0]; var EPS = 1e-3; var changed = 0, big = 0, unstable = 0, alpha = 0;
    for (var i = 0; i < N; i++) {
      var d = Math.abs(a[i] - truth);
      if (d > EPS) { changed++; if ((i & 3) === 3) alpha++; if (d > 1 / 255 + 2e-3) big++; }
      if (a[i] !== b[i]) unstable++;
    }
    // Content dependence survives the float path: a different image must
    // not carry the same additive mask.
    IMG = Uint8ClampedArray.from({ length: N }, function (_, i) { return (i * 7919) & 255; });
    var c2 = c.getImageData(0, 0, 64, 64, { pixelFormat: "rgba-float16" }).data; var same = 0, moved = 0;
    for (var j = 0; j < N; j++) { var t2 = new FloatSamples([IMG[j] / 255])[0]; if (Math.abs(c2[j] - t2) > EPS) { moved++; var m1 = a[j] - truth, m2 = c2[j] - t2; if (Math.abs(m1 - m2) < 2e-3) same++; } }
    ({ changed: changed, big: big, unstable: unstable, alpha: alpha, moved: moved, same: same, isFloat: a instanceof FloatSamples })
  `, ctx);
}
const fl = floatNoise(prepare(template));
assert(fl.isFloat, "the stub did not hand back Float16Array storage for rgba-float16");
assert(fl.changed > 0, "float samples were not noised at all");
assert(fl.big === 0, "float samples were coerced instead of stepped: " + fl.big + " moved by more than one level");
assert(fl.alpha === 0 && fl.unstable === 0, "float noise touched alpha or was unstable");
assert(fl.same * 10 < fl.moved * 6, "the float mask is content-independent: " + fl.same + " of " + fl.moved + " steps identical across images");
// Planted defect 7: the byte XOR applied to float samples.
const coerce = prepare(template).replace("var isFloat = data.BYTES_PER_ELEMENT !== 1;", "var isFloat = false;");
assert(coerce !== prepare(template), "planted defect 7 did not apply");
assert(floatNoise(coerce).big > 0, "float gate cannot see a coercing XOR (planted defect passed)");
const ha = hostileAccessors(prepare(template));
for (const name of ["width", "height", "data", "length"]) {
  assert(ha[name] > 0, "a page-replaced " + name + " getter switched the canvas noise off");
}
assert(ha.orderOk, "an invalid colorSpace did not throw TypeError before the pixelFormat getter ran");
assert(ha.goodRead, "a valid settings dictionary was rejected by the member probes");
// Planted defect 6: validation postponed to the engine lets the next getter run first.
const lateEnum = prepare(template).replace('checkMember(ctx, orig, "colorSpace", cs);', "");
assert(lateEnum !== prepare(template), "planted defect 6 did not apply");
assert(hostileAccessors(lateEnum).orderOk === false, "order gate cannot see postponed enum validation (planted defect passed)");
assert(ha.primitiveThrows === ha.primitiveCount, "a primitive settings value did not throw TypeError through the hook: " + ha.primitiveThrows + "/" + ha.primitiveCount);
// Planted defect 4: noiseView reads the width through the live accessor again.
const liveWidth = prepare(template).replace("var w = widthOf(img) | 0;\n      var h = heightOf(img) | 0;\n      var ox =", "var w = img.width | 0;\n      var h = heightOf(img) | 0;\n      var ox =");
assert(liveWidth !== prepare(template), "planted defect 4 did not apply");
assert(hostileAccessors(liveWidth).width === 0, "accessor gate cannot see a live width read (planted defect passed)");
// Planted defect 5: the pixel loop reads the raw length live again.
const liveLen = prepare(template).replace("var rawLen = lengthOf(raw);", "var rawLen = raw.length;");
assert(liveLen !== prepare(template), "planted defect 5 did not apply");
assert(hostileAccessors(liveLen).length === 0, "accessor gate cannot see a live length read (planted defect passed)");
console.log("divergence-recovery-gate: OK (token hidden from hooked natives; " + m.wrong + "/" + m.changed + " noised bytes survive a known-solid strip)");
