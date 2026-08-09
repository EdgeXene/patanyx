/*
 * Fingerprint Divergence: small deterministic noise on fingerprinting
 * readouts -- canvas, audio, WebGL vendor/renderer strings, element
 * measurement, and the navigator hardware hints.
 *
 * Runs in the PAGE's main world as a registered document-start script (the
 * same category as autofill.js), before any page script, in every frame the
 * engine allows. It patches:
 *
 *   canvas  getImageData / toDataURL / toBlob   low-bit pixel noise
 *   audio   AudioBuffer.getChannelData / copyFromChannel,
 *           AnalyserNode get{Float,Byte}{Frequency,TimeDomain}Data
 *                                               inaudible amplitude fudge
 *   webgl   getParameter(UNMASKED_VENDOR/RENDERER_WEBGL)
 *                                               masked generic strings
 *   rects   Element/Range getBoundingClientRect / getClientRects
 *                                               sub-pixel WIDTH/HEIGHT noise,
 *                                               positions left exact (the
 *                                               fraction of positions is a
 *                                               known residual leak). Real
 *                                               DOMRect out; the DOMRectList
 *                                               is an Array with item().
 *   nav     hardwareConcurrency, deviceMemory   capped at min(real, 8), never
 *                                               reported above the truth
 *
 * All noise derives from one seed: a per-app-start session token mixed with
 * the TOP frame's hostname. The token is substituted over the placeholder
 * below by privacy::divergence_script; it is never persisted, and ephemeral
 * tabs get their own. (The literal placeholder must appear EXACTLY ONCE in
 * this file -- a pinned test enforces that, because the substitution
 * replaces the first occurrence only.)
 *
 * So a site sees the same readout on every visit this session (no per-load
 * jitter to average away), a DIFFERENT readout than any other site sees,
 * and a different one again after a restart. Cross-site linkage by
 * fingerprint is what breaks.
 *
 * TRUST BOUNDARY. This script has ZERO channels: no network primitive of
 * any kind, no dynamic import, no message passing, no IPC. (A pinned Rust
 * test enforces the exact list, which is why this comment does not spell
 * out the API names.) It reads the token from its own closure, patches
 * prototypes, and stops existing. The token cannot leak through
 * Function.prototype.toString on the patched functions: toString returns
 * source text, and closure VALUES are not in it.
 *
 * The worker wrapper (below) does build a Blob and a Worker, and neither is
 * a channel that carries the token OUT. The worker blob's source contains
 * ONLY the per-(site,"canvas") seed -- four numbers a determined same-site
 * page can already recover on the main thread, because the canvas mask is
 * position-keyed and low-bit XOR is self-inverse -- and it importScripts the
 * page's OWN, already-loadable worker. The session token and everything
 * audio-derived stay in this closure and never reach a worker; Web Audio
 * does not exist in workers, so the one genuinely-secret key has no reason
 * to travel.
 *
 * Deliberate non-goals, so nobody "fixes" them:
 *   - No stealth. A page that probes for patched natives can tell this is
 *     on. That is accepted: hiding imperfectly is a stronger signal than
 *     not hiding at all.
 *   - Hooks are plain writable prototype assignments, not non-configurable
 *     defineProperty: polyfills and a11y tools legitimately wrap these; a
 *     page that actively unhooks gets its real fingerprint, which is the
 *     same outcome as a page that detects the noise and special-cases it.
 *   - WORKERS, PARTIAL. Neither engine injects registered scripts into
 *     worker contexts, so the Worker constructor is wrapped here to hand the
 *     real worker a shim that installs the OffscreenCanvas and WebGL hooks
 *     before importScripts-ing it. This covers CLASSIC, same-origin
 *     (http/https) workers. It does NOT cover module workers (cannot
 *     importScripts), data:/blob: worker URLs, SharedWorker, or
 *     ServiceWorker, and the /fingerprint-divergence/ limits section names
 *     those exactly. Every failure path constructs the worker unwrapped, so
 *     the worst case is the old behavior, never a broken worker.
 *   - readPixels is NOT noised: real WebGL apps read back exact ID-encoded
 *     pixels for object picking, and the common fingerprint path (hash the
 *     rendered canvas) goes through toDataURL, which is covered.
 */
(function () {
  "use strict";
  try {
    // Idempotence: registering this script twice (e.g. through both engine
    // mechanisms on Windows) must not stack hooks -- stacked getImageData
    // noise would double and break within-site consistency. Document-start
    // scripts run before page script, so a page cannot pre-plant this.
    if (window.__patanyxDiverged) {
      return;
    }
    // NON-ENUMERABLE, and that is not stealth creeping in through the back
    // door. The no-stealth rule below accepts that a page probing the
    // patched natives can tell this is on; it does not require handing over
    // a property, named after the product, that any script sweeping
    // Object.keys(window) for browser-specific globals finds for free.
    // Telling a site "something is farbling" is inherent. Telling it
    // "PATANYX is farbling" is a separate and much narrower bit, and that
    // one is avoidable. Plain assignment as the fallback: idempotence
    // matters more than the property descriptor.
    try {
      Object.defineProperty(window, "__patanyxDiverged", { value: true });
    } catch (e) {
      window.__patanyxDiverged = true;
    }

    var TOKEN = "__DIVERGENCE_TOKEN__";

    // Key on the TOP frame's host, so a third-party fingerprint
    // iframe gets the embedding site's noise rather than its own. Otherwise
    // one fingerprinting host would see its OWN consistent readout
    // everywhere it is embedded, which is exactly the cross-site identifier
    // this exists to destroy. ancestorOrigins exists on both engines
    // (Chromium and WebKit). An opaque or unreadable origin falls through to
    // "": still gets noise, keyed per session only, which is safe -- a frame
    // with no origin has no site identity to stay consistent with.
    var topHost = "";
    try {
      var ao = location.ancestorOrigins;
      if (ao && ao.length) {
        topHost = new URL(ao[ao.length - 1]).hostname;
      } else {
        topHost = location.hostname || "";
      }
    } catch (e0) {
      try {
        topHost = location.hostname || "";
      } catch (e1) {
        topHost = "";
      }
    }

    // Seed mix + PRNG: cyrb128 into sfc32, both public-domain standards.
    // Non-cryptographic ON PURPOSE: SubtleCrypto is async and these hooks
    // must install synchronously before page script runs. A site observes at
    // most its own PRNG output; recovering the 256-bit session token from
    // that to predict another site's stream is not a realistic attack.
    function cyrb128(str) {
      var h1 = 1779033703;
      var h2 = 3144134277;
      var h3 = 1013904242;
      var h4 = 2773480762;
      for (var i = 0, k; i < str.length; i++) {
        k = str.charCodeAt(i);
        h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
        h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
        h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
        h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
      }
      h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
      h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
      h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
      h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
      return [
        (h1 ^ h2 ^ h3 ^ h4) >>> 0,
        (h2 ^ h1) >>> 0,
        (h3 ^ h1) >>> 0,
        (h4 ^ h1) >>> 0,
      ];
    }
    function sfc32(a, b, c, d) {
      return function () {
        a |= 0;
        b |= 0;
        c |= 0;
        d |= 0;
        var t = (((a + b) | 0) + d) | 0;
        d = (d + 1) | 0;
        a = b ^ (b >>> 9);
        b = (c + (c << 3)) | 0;
        c = (c << 21) | (c >>> 11);
        c = (c + t) | 0;
        return t >>> 0;
      };
    }
    // Per-endpoint labels give domain separation: the canvas stream never
    // reveals the audio fudge and vice versa.
    function rngFor(label) {
      var s = cyrb128(TOKEN + "|" + topHost + "|" + label);
      return sfc32(s[0], s[1], s[2], s[3]);
    }
    // The same key material as rngFor, but handed over as the four words
    // instead of a stream, for the audio hooks: they must be able to jump
    // straight to sample N without replaying N-1 draws, so they index a
    // keyed function rather than pull from a sequence.
    function seedWordsFor(label) {
      return cyrb128(TOKEN + "|" + topHost + "|" + label);
    }

    // Patched functions keep the original's name/length so casual
    // feature-detection ("does this look native-shaped?") behaves; see the
    // no-stealth note in the header for why it stops there.
    function keepShape(patched, orig) {
      try {
        Object.defineProperty(patched, "name", { value: orig.name });
        Object.defineProperty(patched, "length", { value: orig.length });
      } catch (e) {
        /* shape is cosmetic; the hook still works */
      }
      return patched;
    }
    // Every hook is independently feature-detected and independently
    // guarded, so one missing API (no WebGL2 on an old WebKitGTK, no
    // AnalyserNode in an exotic realm) skips THAT hook and nothing else.
    function patchMethod(proto, name, make) {
      try {
        if (!proto || typeof proto[name] !== "function") {
          return;
        }
        var orig = proto[name];
        proto[name] = keepShape(make(orig), orig);
      } catch (e) {
        /* a divergence hook must never take the API down with it */
      }
    }

    // ----- canvas ---------------------------------------------------------
    // Re-seeded PER CALL, so the identical read returns identical bytes:
    // that is what keeps a site's canvas hash stable across reloads while
    // still unique to the site. ~1 pixel in 8 gets its lowest R bit
    // flipped, sometimes G/B too; alpha is never touched (low-bit alpha
    // changes are visible against composited backgrounds).
    // The noise itself, given a PRNG. Extracted so the MAIN thread and the
    // WORKER shim run byte-for-byte the same code from one source: if the two
    // realms ever diverged, a page could render one image in both and diff
    // them, and the pixels that differ would be exactly the noised ones. The
    // parity gate pins them equal; sharing the function is what makes that
    // cheap to keep true.
    function applyCanvasNoise(data, rng) {
      for (var i = 0; i + 3 < data.length; i += 4) {
        var v = rng();
        if ((v & 7) === 0) {
          data[i] ^= 1;
          data[i + 1] ^= (v >>> 3) & 1;
          data[i + 2] ^= (v >>> 4) & 1;
        }
      }
    }
    function noiseData(data) {
      applyCanvasNoise(data, rngFor("canvas"));
    }

    var origGID = null;
    try {
      if (
        typeof CanvasRenderingContext2D !== "undefined" &&
        CanvasRenderingContext2D.prototype &&
        typeof CanvasRenderingContext2D.prototype.getImageData === "function"
      ) {
        origGID = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = keepShape(
          function () {
            var img = origGID.apply(this, arguments);
            try {
              if (img && img.data) {
                noiseData(img.data);
              }
            } catch (e) {
              /* a failed noise pass returns the true pixels; the API works */
            }
            return img;
          },
          origGID,
        );
      }
    } catch (e2) {
      /* no 2d canvas in this realm */
    }

    // toDataURL/toBlob must see the SAME noised pixels getImageData reports,
    // or the two paths disagree and the noise averages out: clone-redraw
    // through an offscreen canvas, noise the clone, encode the clone. This
    // also covers WebGL canvases -- drawImage accepts them -- which is why
    // readPixels can stay unpatched. Uses origGID (captured above) so the
    // clone's pixels are noised exactly once, not once by the hook and once
    // here.
    try {
      if (
        origGID &&
        typeof HTMLCanvasElement !== "undefined" &&
        HTMLCanvasElement.prototype
      ) {
        var noisedClone = function (canvas) {
          var w = canvas.width;
          var h = canvas.height;
          if (!(w > 0 && h > 0)) {
            return null;
          }
          var c = document.createElement("canvas");
          c.width = w;
          c.height = h;
          var ctx = c.getContext("2d");
          if (!ctx) {
            return null;
          }
          ctx.drawImage(canvas, 0, 0);
          var img = origGID.call(ctx, 0, 0, w, h);
          noiseData(img.data);
          ctx.putImageData(img, 0, 0);
          return c;
        };
        patchMethod(HTMLCanvasElement.prototype, "toDataURL", function (orig) {
          return function () {
            try {
              var c = noisedClone(this);
              if (c) {
                return orig.apply(c, arguments);
              }
            } catch (e) {
              /* 0x0 canvas, detached document: fall through to the truth */
            }
            return orig.apply(this, arguments);
          };
        });
        patchMethod(HTMLCanvasElement.prototype, "toBlob", function (orig) {
          return function () {
            try {
              var c = noisedClone(this);
              if (c) {
                return orig.apply(c, arguments);
              }
            } catch (e) {
              /* same fall-through as toDataURL */
            }
            return orig.apply(this, arguments);
          };
        });
      }
    } catch (e3) {
      /* no canvas element in this realm */
    }

    // ----- audio ----------------------------------------------------------
    // WHY THIS IS NOT ONE MULTIPLIER. Until 0.9.61 this applied a single
    // factor f in [0.99, 1.0) to every sample. That is removable twice over:
    //
    //   1. Uniform scaling survives normalization. Divide by peak or RMS and
    //      f cancels exactly, so every scale-invariant statistic -- the
    //      normalized waveform, ratios between samples, spectral shape,
    //      zero-crossing rate -- comes back untouched. Normalizing before
    //      hashing is cheap and ordinary, so this cost a determined
    //      fingerprinter nothing.
    //   2. f was recoverable outright. getChannelData scaled the channel IN
    //      PLACE, so a following copyFromChannel read already-scaled data and
    //      scaled it again: two reads, one division, f known exactly, and
    //      from there the true samples. The old comment noticed the double
    //      scale and judged it only for audibility.
    //
    // So the perturbation now VARIES ACROSS THE SIGNAL and is keyed to the
    // CONTENT being read, not just to the site:
    //
    //   shift(i) = keyed_mix(session+site key, digest of the whole channel,
    //                        absolute index i)
    //
    // Content keying is what stops a site rendering two buffers it already
    // knows, subtracting them to cancel the per-site key, and recovering the
    // perturbation vector. Absolute indexing is what makes every read path
    // agree: sample i of a channel gets the same shift whether it arrived
    // through getChannelData or a copyFromChannel at any offset, in any
    // order. Cost is two integer passes (digest, then perturb), no
    // allocation, no crypto, no async.
    //
    // MAGNITUDE, per domain, stated separately because the domains are not
    // comparable and one number for all of them would be false:
    //   * linear samples  +/-0.5% RELATIVE (a factor in [0.995, 1.005]),
    //                     about 0.04 dB. Multiplicative, so an exactly zero
    //                     sample stays exactly zero and silence stays silent.
    //   * dB readouts     +/-0.05 dB ADDITIVE. getFloatFrequencyData returns
    //                     DECIBELS, and the old code multiplied them as if
    //                     they were amplitudes, which moved a -100 dB bin by
    //                     a whole dB and made quiet bins LOUDER.
    //   * byte readouts   exactly +/-1, the smallest move the domain has. On
    //                     getByteFrequencyData one step is about 0.27 dB,
    //                     which is roughly 3% in amplitude terms -- larger
    //                     than the linear bound above and unavoidable, since
    //                     a byte cannot move by less than one. Said plainly
    //                     rather than papered over with a single "under 1%"
    //                     claim that would be arithmetically false here.
    //
    // NOT ENOUGH ON ITS OWN: workers still bypass all of this (see the
    // known-hole note in the header). Nothing here should be read as
    // covering them.
    var audioSeeds = null;
    var audioKey = function () {
      if (audioSeeds === null) {
        audioSeeds = seedWordsFor("audio");
      }
      return audioSeeds;
    };

    // A keyed uniform in [0, 1) for one (digest, index) pair.
    //
    // The four key words enter at FOUR DIFFERENT POINTS, and that placement
    // is load-bearing. An earlier shape XORed two seed words into the same
    // expression: since XOR is commutative, `sA ^ imul(sB, C)` folds into a
    // single 32-bit constant, so a nominally 128-bit key had 32 effective
    // bits and a site could brute-force it from one known buffer and then
    // invert every later reading. Each word is now separated from the next
    // by a non-linear round, so none of them can be folded together.
    var mixSample = function (k, digest, index) {
      var h = Math.imul((index | 0) + 1, 374761393) ^ k[0];
      h = Math.imul(h ^ (h >>> 15), 2246822519);
      h = (h ^ Math.imul(digest, 668265263) ^ k[1]) | 0;
      h = Math.imul(h ^ (h >>> 13), 3266489917);
      h = (h ^ k[2]) | 0;
      h = Math.imul(h ^ (h >>> 16), 668265263);
      h = (h ^ k[3]) | 0;
      h ^= h >>> 16;
      return (h >>> 0) / 4294967296;
    };

    // Content digest over the WHOLE array, one pass, integer ops only.
    //
    // Always the whole thing, never a slice: if a partial read digested only
    // the samples it copied, the same copyFromChannel call would return
    // different values depending on whether a full read happened first. That
    // is a determinism break a site can see, and worse, it would hand a site
    // two different perturbations of the same underlying samples, which can
    // be averaged toward the truth.
    var digestOf = function (arr, n) {
      var h = 2166136261;
      for (var i = 0; i < n; i++) {
        var v = arr[i];
        // Quantize to an int32 so the digest does not depend on float noise
        // far below the perturbation, and so a NaN or Infinity contributes a
        // fixed value instead of poisoning the hash.
        var q =
          v === v && v !== Infinity && v !== -Infinity ? (v * 8388608) | 0 : 0;
        h = Math.imul(h ^ (q & 255), 16777619);
        h = Math.imul(h ^ ((q >>> 8) & 255), 16777619);
        h = Math.imul(h ^ ((q >>> 16) & 255), 16777619);
        h = Math.imul(h ^ ((q >>> 24) & 255), 16777619);
      }
      // Length participates so two buffers differing only in trailing
      // silence do not share a digest.
      return Math.imul(h ^ n, 16777619) | 0;
    };

    try {
      // getChannelData: scale IN PLACE, ONCE per returned array. In place
      // because Web Audio code writes into the live array it gets back --
      // returning a scaled copy breaks synthesis. Once, tracked by WeakSet,
      // because repeated reads must not compound the fudge into something
      // audible. Mixing getChannelData with copyFromChannel on the same
      // buffer can scale a sample twice (0.9801 worst case); still
      // inaudible, accepted.
      // Which (buffer, channel) pairs getChannelData has already perturbed
      // in place. In place because Web Audio code writes into the live array
      // it gets back, so handing out a perturbed copy would break synthesis;
      // once, because a second pass would compound.
      //
      // This mark is also what closes the old recovery path. Once a channel
      // is marked, its live samples ARE the perturbed ones, so a later
      // copyFromChannel is already copying perturbed data and must not touch
      // it again. Perturbing there was what produced f and f-squared for the
      // same samples and let a site divide one by the other.
      var marks = typeof WeakMap !== "undefined" ? new WeakMap() : null;
      var isMarked = function (buffer, channel) {
        if (!marks) {
          return false;
        }
        var seen = marks.get(buffer);
        return !!seen && seen[channel] === true;
      };
      var mark = function (buffer, channel) {
        if (!marks) {
          return;
        }
        var seen = marks.get(buffer);
        if (!seen) {
          seen = {};
          marks.set(buffer, seen);
        }
        seen[channel] = true;
      };

      // Per-sample factor for absolute sample `index`, in [0.995, 1.005].
      //
      // MULTIPLICATIVE, not additive, and the difference is not cosmetic:
      // x * f leaves a zero sample at zero, so digital silence stays silent.
      // An additive shift does not, and an early version of this fix turned
      // an all-zero buffer into a -46 dBFS hiss -- audible in a quiet
      // passage, trivially detectable by reading back a buffer of zeros, and
      // a straightforward audio defect regardless of fingerprinting. The old
      // single-scalar code got this property for free and it was worth
      // keeping. What it did NOT have, and this does, is a factor that
      // varies per sample, which is what stops normalization removing it.
      var linearFactor = function (k, digest, index) {
        return 1 + (mixSample(k, digest, index) * 2 - 1) * 0.005;
      };
      var perturbLinear = function (arr, n, k, digest, base) {
        for (var i = 0; i < n; i++) {
          var x = arr[i];
          if (x !== x) {
            continue; // NaN stays NaN; skip the work
          }
          var y = x * linearFactor(k, digest, (base + i) | 0);
          // Clamp back only if the ORIGINAL was in range. Real buffers
          // legitimately carry values beyond +/-1 before a limiter runs, and
          // dragging those to 1.0 would corrupt audio this code has no
          // business editing.
          if (x <= 1 && x >= -1) {
            if (y > 1) {
              y = 1;
            } else if (y < -1) {
              y = -1;
            }
          }
          arr[i] = y;
        }
      };

      if (typeof AudioBuffer !== "undefined") {
        var origGetChannelData = AudioBuffer.prototype.getChannelData;
        patchMethod(AudioBuffer.prototype, "getChannelData", function (orig) {
          return function (channel) {
            var arr = orig.apply(this, arguments);
            try {
              var ch = channel | 0;
              if (arr && arr.length && !isMarked(this, ch)) {
                mark(this, ch);
                var k = audioKey();
                perturbLinear(arr, arr.length, k, digestOf(arr, arr.length), 0);
              }
            } catch (e) {
              /* true samples, working API */
            }
            return arr;
          };
        });
        patchMethod(AudioBuffer.prototype, "copyFromChannel", function (orig) {
          return function (destination, channelNumber, bufferOffset) {
            // COERCE ONCE, BEFORE the native call, and hand the natives the
            // primitives. Reading these arguments again afterwards is a real
            // bypass: an object whose valueOf() answers differently each time
            // can let the native copy fill the destination while this wrapper
            // computes a zero-length range and perturbs nothing, handing the
            // page true samples.
            var ch = channelNumber | 0;
            var start = bufferOffset === undefined ? 0 : bufferOffset | 0;
            var out = orig.call(this, destination, ch, start);
            try {
              if (destination && destination.length && !isMarked(this, ch)) {
                // Unmarked: the live channel still holds true samples, so
                // the copy in `destination` does too and must be perturbed
                // here. Digest the WHOLE channel, never just the copied
                // slice, and index by absolute position -- that is what makes
                // this call agree, element for element, with a getChannelData
                // read and with a copy at any other offset.
                var live = origGetChannelData.call(this, ch);
                var k = audioKey();
                var digest = digestOf(live, live.length);
                var room = (live.length - start) | 0;
                var n = destination.length < room ? destination.length : room;
                if (n > 0) {
                  perturbLinear(destination, n, k, digest, start);
                }
              }
              // Marked: `destination` already carries perturbed samples,
              // copied from the live channel. Touching them again is exactly
              // the defect this replaces.
            } catch (e) {
              /* true samples, working API */
            }
            return out;
          };
        });
      }
    } catch (e4) {
      /* no Web Audio in this realm */
    }

    try {
      if (typeof AnalyserNode !== "undefined") {
        // Time domain: linear samples, same +/-0.005 shift as a buffer read.
        var shiftTimeFloats = function (arr, n, k, digest) {
          perturbLinear(arr, n, k, digest, 0);
        };
        // Frequency domain: DECIBELS. Additive, because multiplying a dB
        // figure is not a small change -- 0.99 applied to a -100 dB bin moves
        // it a full dB, and toward LOUDER, which is the opposite of what a
        // "slightly quieter" fudge was supposed to mean.
        //
        // -Infinity marks a silent bin and NaN can appear before the first
        // analysis frame; both pass through untouched. Shifting them would
        // produce a value the engine never emits, which is a louder signal
        // than the one being hidden.
        var shiftDbFloats = function (arr, n, k, digest) {
          for (var i = 0; i < n; i++) {
            var v = arr[i];
            if (v !== v || v === Infinity || v === -Infinity) {
              continue;
            }
            arr[i] = v + (mixSample(k, digest, i) * 2 - 1) * 0.05;
          }
        };
        // Bytes: exactly one step, up or down. The old code multiplied by
        // 0.99 and rounded, so every value below about 50 rounded straight
        // back to itself and the quiet half of the spectrum carried no noise
        // at all. One LSB is the smallest move this domain has; the ends are
        // pushed inward so the range is never left.
        var shiftBytes = function (arr, n, k, digest) {
          for (var i = 0; i < n; i++) {
            var v = arr[i];
            if (v <= 0) {
              arr[i] = 1;
            } else if (v >= 255) {
              arr[i] = 254;
            } else {
              arr[i] = mixSample(k, digest, i) < 0.5 ? v - 1 : v + 1;
            }
          }
        };
        var analyserPatch = function (name, shift) {
          patchMethod(AnalyserNode.prototype, name, function (orig) {
            return function (array) {
              var out = orig.apply(this, arguments);
              try {
                if (array && array.length) {
                  // The engine fills only as much as it has bins for; a
                  // longer array keeps whatever was in its tail. Digesting or
                  // perturbing that tail would make the result depend on
                  // whatever the page left there, so only the filled prefix
                  // is touched.
                  var bins =
                    name.indexOf("Frequency") >= 0
                      ? this.frequencyBinCount
                      : this.fftSize;
                  var n = array.length;
                  if (typeof bins === "number" && bins >= 0 && bins < n) {
                    n = bins | 0;
                  }
                  if (n > 0) {
                    var k = audioKey();
                    shift(array, n, k, digestOf(array, n));
                  }
                }
              } catch (e) {
                /* true readout, working API */
              }
              return out;
            };
          });
        };
        analyserPatch("getFloatFrequencyData", shiftDbFloats);
        analyserPatch("getFloatTimeDomainData", shiftTimeFloats);
        analyserPatch("getByteFrequencyData", shiftBytes);
        analyserPatch("getByteTimeDomainData", shiftBytes);
      }
    } catch (e5) {
      /* no AnalyserNode in this realm */
    }

    // ----- webgl ----------------------------------------------------------
    // UNMASKED_VENDOR_WEBGL (37445) and UNMASKED_RENDERER_WEBGL (37446)
    // answer with the MASKED strings (VENDOR 0x1F00, RENDERER 0x1F01)
    // instead: engine-consistent, generic, and missing the GPU model, which
    // is the entropy. Hard-coded fake strings were rejected -- an
    // engine-inconsistent lie is itself a fingerprintable signal. Every
    // other pname passes straight through.
    try {
      var maskUnmasked = function (proto) {
        patchMethod(proto, "getParameter", function (orig) {
          return function (pname) {
            try {
              if (pname === 37445) {
                return orig.call(this, 0x1f00);
              }
              if (pname === 37446) {
                return orig.call(this, 0x1f01);
              }
            } catch (e) {
              /* fall through to the real answer */
            }
            return orig.apply(this, arguments);
          };
        });
      };
      if (typeof WebGLRenderingContext !== "undefined") {
        maskUnmasked(WebGLRenderingContext.prototype);
      }
      if (typeof WebGL2RenderingContext !== "undefined") {
        maskUnmasked(WebGL2RenderingContext.prototype);
      }
    } catch (e6) {
      /* no WebGL in this realm */
    }

    // ----- OffscreenCanvas -------------------------------------------------
    // The same low-bit canvas noise on OffscreenCanvas, which exists on the
    // MAIN thread too (a real gap on its own) and is the surface a WORKER
    // fingerprints through. `patchOffscreenCanvas` takes the PRNG factory so
    // the main thread passes rngFor("canvas") and the worker shim passes a
    // seed handed in from here; the pixel loop is the shared applyCanvasNoise
    // either way. Defined as a named function so the worker shim can reuse
    // its exact source rather than a second copy that could drift.
    function patchOffscreenCanvas(scope, rngFactory, noiseCore) {
      try {
        if (typeof scope.OffscreenCanvasRenderingContext2D !== "undefined") {
          var octx = scope.OffscreenCanvasRenderingContext2D.prototype;
          if (octx && typeof octx.getImageData === "function") {
            var origOGID = octx.getImageData;
            octx.getImageData = keepShape(function () {
              var img = origOGID.apply(this, arguments);
              try {
                if (img && img.data) {
                  noiseCore(img.data, rngFactory());
                }
              } catch (e) {
                /* true pixels, working API */
              }
              return img;
            }, origOGID);
            // convertToBlob encodes the canvas; noise a redrawn clone so the
            // encoded bytes carry the SAME noise getImageData reports, never a
            // second independent pass that would average out. Async (returns
            // a Promise), so this returns the clone's promise directly.
            if (typeof scope.OffscreenCanvas !== "undefined") {
              patchMethod(
                scope.OffscreenCanvas.prototype,
                "convertToBlob",
                function (orig) {
                  return function () {
                    try {
                      var w = this.width;
                      var h = this.height;
                      if (w > 0 && h > 0) {
                        var clone = new scope.OffscreenCanvas(w, h);
                        var cctx = clone.getContext("2d");
                        if (cctx) {
                          cctx.drawImage(this, 0, 0);
                          var cimg = origOGID.call(cctx, 0, 0, w, h);
                          noiseCore(cimg.data, rngFactory());
                          cctx.putImageData(cimg, 0, 0);
                          return orig.apply(clone, arguments);
                        }
                      }
                    } catch (e) {
                      /* 0x0 or detached: fall through to the true encode */
                    }
                    return orig.apply(this, arguments);
                  };
                },
              );
            }
          }
        }
      } catch (e) {
        /* no OffscreenCanvas in this realm */
      }
    }
    patchOffscreenCanvas(
      typeof self !== "undefined" ? self : window,
      function () {
        return rngFor("canvas");
      },
      applyCanvasNoise,
    );

    // ----- workers ---------------------------------------------------------
    // Classic same-origin workers are brought under the same noise. A page's
    // fingerprinting increasingly runs on a worker thread, where a browser
    // built on a system web engine cannot inject a registered script -- so we
    // wrap the Worker constructor and hand the real script a shim that
    // installs the OffscreenCanvas and WebGL hooks first, then importScripts
    // the page's own worker.
    //
    // WHY THIS IS SAFE, and never worse than not doing it:
    //   * The shim carries ONLY the per-(site,"canvas") seed -- four numbers a
    //     determined same-site page can already recover on the main thread by
    //     reading back known content (the canvas mask is position-keyed, and
    //     low-bit XOR is self-inverse). It does NOT carry the session token or
    //     anything audio-derived. Web Audio does not exist in workers, so the
    //     one genuinely-secret key never travels.
    //   * The worker applies the IDENTICAL mask to the main thread (parity
    //     gate proves it), so rendering the same content in both realms and
    //     diffing yields nothing. A mismatched key would be the leak; we never
    //     ship one -- if the seed is missing we do not wrap.
    //   * Every failure path constructs the ORIGINAL worker unwrapped, which
    //     is exactly today's behavior. A privacy courtesy must not break a
    //     worker-using site.
    //
    // NOT COVERED, and the /fingerprint-divergence/ limits section says so:
    // module workers (cannot importScripts), data:/blob: worker URLs,
    // SharedWorker and ServiceWorker.
    try {
      if (
        typeof Worker === "function" &&
        typeof URL !== "undefined" &&
        URL.createObjectURL
      ) {
        var canvasSeed = seedWordsFor("canvas");
        var fnSource = Function.prototype.toString;
        // One source of truth for the noise math: the worker runs the exact
        // sfc32 and applyCanvasNoise defined above, stringified, never a
        // retyped copy.
        //
        // SHIM BODY ONLY -- the function declarations, then the guarded hook
        // installs. It is NOT a complete program: the wrapper wraps it in the
        // IIFE and appends importScripts, so importScripts runs AFTER the
        // hooks and OUTSIDE their try/catch (a hook failure must not stop the
        // real worker loading, and an importScripts failure is the worker's
        // own error to surface, exactly as an unwrapped worker's would be).
        // Declarations sit at the IIFE top level, never inside the try, so
        // there is no block-scoped-function ambiguity.
        var workerShimBody =
          "var __s=[" +
          (canvasSeed[0] >>> 0) +
          "," +
          (canvasSeed[1] >>> 0) +
          "," +
          (canvasSeed[2] >>> 0) +
          "," +
          (canvasSeed[3] >>> 0) +
          "];" +
          fnSource.call(sfc32) +
          fnSource.call(applyCanvasNoise) +
          fnSource.call(keepShape) +
          fnSource.call(patchMethod) +
          fnSource.call(patchOffscreenCanvas) +
          "try{" +
          "var __rng=function(){return sfc32(__s[0],__s[1],__s[2],__s[3]);};" +
          "patchOffscreenCanvas(self,__rng,applyCanvasNoise);" +
          "var __mask=function(p){patchMethod(p,'getParameter',function(o){" +
          "return function(n){try{if(n===37445)return o.call(this,7936);" +
          "if(n===37446)return o.call(this,7937);}catch(e){}return o.apply(this,arguments);};});};" +
          "if(typeof WebGLRenderingContext!=='undefined')__mask(WebGLRenderingContext.prototype);" +
          "if(typeof WebGL2RenderingContext!=='undefined')__mask(WebGL2RenderingContext.prototype);" +
          "}catch(e){}";
        var OrigWorker = Worker;

        // ----- the CSP fallback -----------------------------------------------
        // The blob worker above is refused ASYNCHRONOUSLY on any site whose CSP
        // omits blob: from worker-src: the Worker object constructs fine, then
        // an error event fires and no message ever arrives. The old try/catch
        // saw only synchronous throws, so such a site was left holding a worker
        // that never worked -- the one thing this feature promised never to do
        // ("A privacy courtesy must not break a worker-using site").
        //
        // So the page never holds the blob worker directly. It holds a FACADE
        // that starts on the blob worker and, if that worker dies before it
        // ever proves it ran, swaps ONCE to an ordinary unwrapped worker built
        // from the page's ORIGINAL url, replays what the page had posted, and
        // swallows the refusal (which was ours, not the site's). A worker that
        // ran and THEN errored is the site's own error and passes straight
        // through. The swap happens at most once, so a genuinely broken site
        // worker cannot loop.
        //
        // NAMED OBSERVABLES / LIMITS (this feature does not hide itself):
        //   * instanceof Worker holds (Object.create(Worker.prototype)), but a
        //     NATIVE method borrowed and re-bound onto the facade --
        //     Worker.prototype.postMessage.call(facade, ...) -- throws, because
        //     the facade is not a branded Worker. A direct facade.postMessage()
        //     is fine and is what pages do.
        //   * "never ran" is inferred from an error arriving with no prior
        //     message/messageerror (and a short settle timer as a backstop).
        //     Sound on Chromium; UNVERIFIED on WebKitGTK. Bounded both ways: a
        //     false "blocked" restarts the worker once then surfaces its error;
        //     a false "ran" leaves the site exactly as today -- never worse.
        //   * A message that transferred an ArrayBuffer before the refusal
        //     detached that buffer into the doomed worker and cannot be
        //     replayed; that single message is lost. Narrow: CSP-refusing
        //     sites, pre-refusal messages, transferables only.
        function makeFacade(url, options, blobUrl) {
          var facade = Object.create(OrigWorker.prototype);
          var real = new OrigWorker(blobUrl, options);
          var swapped = false; // at most one swap, ever
          var proved = false; // the worker emitted a message => it ran
          var terminated = false; // the page called terminate()
          var queue = []; // pre-liveness posts, in order; null once settled
          var settleTimer = null;
          // Registration-ordered listeners; the on* attribute handlers occupy a
          // slot in the same list so dispatch order matches native EventTarget.
          var entries = [];
          var attr = { message: null, messageerror: null, error: null };

          function stopQueue() {
            queue = null;
            if (settleTimer !== null) {
              clearTimeout(settleTimer);
              settleTimer = null;
            }
          }
          function noteLive() {
            proved = true;
            stopQueue();
          }

          // The one call the channel gate is taught to allow: a method call on
          // a worker the PAGE created, forwarding the page's OWN messages. This
          // is not an outbound channel -- the session token never reaches a
          // worker, whose shim carries only the canvas seed. References, never
          // copies: the engine performs the structured clone on send.
          function forward(w, args) {
            if (args.length > 1) {
              w.postMessage(args[0], args[1]);
            } else {
              w.postMessage(args[0]);
            }
          }

          function removeEntry(target) {
            for (var i = 0; i < entries.length; i++) {
              if (entries[i] === target) {
                entries.splice(i, 1);
                return;
              }
            }
          }

          function dispatch(type, ev) {
            // Snapshot: listeners added or removed DURING dispatch do not change
            // this run, matching native EventTarget.
            var snap = [];
            var i;
            for (i = 0; i < entries.length; i++) {
              if (entries[i].type === type) {
                snap.push(entries[i]);
              }
            }
            var stop = false;
            var origSIP = ev ? ev.stopImmediatePropagation : undefined;
            if (ev) {
              try {
                ev.stopImmediatePropagation = function () {
                  stop = true;
                  if (origSIP) {
                    origSIP.call(ev);
                  }
                };
              } catch (e) {
                /* real events allow instance shadowing; if not, only the
                   stopImmediatePropagation short-circuit is lost */
              }
            }
            for (i = 0; i < snap.length && !stop; i++) {
              var e2 = snap[i];
              if (e2.removed) {
                continue;
              }
              var fn = e2.isAttr ? attr[type] : e2.fn;
              if (!fn) {
                continue;
              }
              if (e2.once) {
                e2.removed = true;
                removeEntry(e2);
              }
              try {
                if (typeof fn === "function") {
                  fn.call(facade, ev);
                } else if (fn && typeof fn.handleEvent === "function") {
                  fn.handleEvent(ev);
                }
              } catch (eL) {
                // A listener that throws must NOT propagate into the page or
                // halt the other listeners. Native reports it to the global
                // error handler; we swallow it -- surfacing it would need a
                // re-dispatch this token-bearing script must not perform.
              }
            }
            if (ev && origSIP !== undefined) {
              try {
                delete ev.stopImmediatePropagation;
              } catch (e3) {
                /* leave the shadow; the event object is transient */
              }
            }
          }

          function attach(w) {
            try {
              w.onmessage = function (ev) {
                noteLive();
                dispatch("message", ev);
              };
              w.onmessageerror = function (ev) {
                noteLive();
                dispatch("messageerror", ev);
              };
              w.onerror = function (ev) {
                onError(ev);
              };
            } catch (e) {
              /* fail open: without hooks the page still gets ordinary events
                 for the common (working) worker -- nothing worse than today */
            }
          }

          function onError(ev) {
            if (proved || swapped || terminated) {
              // ran-then-errored, already swapped, or the page gave up: this is
              // the site's error (or moot) -- surface it.
              dispatch("error", ev);
              return;
            }
            // Never ran: the blob worker was refused. Swap once.
            swapped = true;
            if (settleTimer !== null) {
              clearTimeout(settleTimer);
              settleTimer = null;
            }
            try {
              real.terminate();
            } catch (e) {
              /* ignore */
            }
            var nw;
            try {
              nw = new OrigWorker(url, options);
            } catch (e4) {
              // Cannot even build an ordinary worker: fail open by surfacing the
              // error so the page is not left silently dead.
              dispatch("error", ev);
              return;
            }
            real = nw;
            attach(nw);
            var q = queue;
            queue = null;
            if (q) {
              for (var i = 0; i < q.length; i++) {
                try {
                  forward(real, q[i]);
                } catch (e5) {
                  // A transferable posted before the refusal is already detached
                  // and cannot be replayed; that one message is lost.
                }
              }
            }
            if (terminated) {
              try {
                real.terminate();
              } catch (e6) {
                /* ignore */
              }
            }
            // ev swallowed: it was our blob worker's refusal, not the site's.
          }

          attach(real);
          // Backstop for a fire-and-forget worker that never posts back: if no
          // refusal has arrived by now, treat it as live and release the replay
          // buffer so references are not retained for the worker's lifetime.
          // Messages still forward immediately regardless; only the replay copy
          // is dropped. A refusal after this point still restarts the worker --
          // only messages sent before now cannot be replayed.
          settleTimer = setTimeout(function () {
            if (!swapped && !terminated) {
              noteLive();
            }
          }, 3000);

          facade.postMessage = function () {
            if (terminated) {
              return;
            }
            var args = Array.prototype.slice.call(arguments);
            if (!proved && !swapped && queue) {
              queue.push(args); // references, not copies (see forward())
            }
            try {
              forward(real, args);
            } catch (e) {
              /* a synchronous postMessage failure is the page's to observe as
                 today; do not throw out of here */
            }
          };
          facade.terminate = function () {
            terminated = true;
            stopQueue();
            try {
              real.terminate();
            } catch (e) {
              /* ignore */
            }
          };
          facade.addEventListener = function (type, fn, opts) {
            if (!fn) {
              return;
            }
            var capture =
              opts === true || (opts && opts.capture === true) ? true : false;
            var once = opts && opts.once === true ? true : false;
            entries.push({
              type: String(type),
              fn: fn,
              capture: capture,
              once: once,
              isAttr: false,
              removed: false,
            });
          };
          facade.removeEventListener = function (type, fn, opts) {
            var capture =
              opts === true || (opts && opts.capture === true) ? true : false;
            type = String(type);
            for (var i = 0; i < entries.length; i++) {
              var e = entries[i];
              if (
                !e.isAttr &&
                e.type === type &&
                e.fn === fn &&
                e.capture === capture
              ) {
                entries.splice(i, 1);
                return;
              }
            }
          };
          facade.dispatchEvent = function (ev) {
            if (ev && ev.type) {
              dispatch(String(ev.type), ev);
            }
            return !(ev && ev.defaultPrevented);
          };

          function defineOn(name) {
            var type = name.slice(2); // "onmessage" -> "message"
            // defineProperty is ES5 and present on both engines; if it somehow
            // failed the on* handler would simply be inactive, and the page's
            // addEventListener path still works.
            try {
              Object.defineProperty(facade, name, {
                configurable: true,
                enumerable: true,
                get: function () {
                  return attr[type] || null;
                },
                set: function (v) {
                  var fn = typeof v === "function" ? v : null;
                  if (attr[type] === null && fn) {
                    // First assignment registers the handler's slot at THIS
                    // position, matching native attribute-handler ordering;
                    // reassignment below keeps that slot's position.
                    entries.push({
                      type: type,
                      fn: null,
                      capture: false,
                      once: false,
                      isAttr: true,
                      removed: false,
                    });
                  }
                  attr[type] = fn;
                },
              });
            } catch (e) {
              /* on* inactive on this exotic realm; listeners still work */
            }
          }
          defineOn("onmessage");
          defineOn("onmessageerror");
          defineOn("onerror");

          return facade;
        }

        var wrapped = function (url, options) {
          try {
            // Classic, same-origin, http(s) workers only. Anything else -> the
            // original, unwrapped. This is the deliberate fall-through; the
            // catch below is the last resort.
            var isModule = options && options.type === "module";
            var loc = self.location;
            var abs = new URL(String(url), loc && loc.href);
            var sameOrigin = !!loc && abs.origin === loc.origin;
            var ok =
              (abs.protocol === "http:" || abs.protocol === "https:") &&
              sameOrigin;
            if (!isModule && ok) {
              var blob = new Blob(
                [
                  "(function(){" +
                    workerShimBody +
                    "importScripts(" +
                    JSON.stringify(abs.href) +
                    ");})();",
                ],
                { type: "text/javascript" },
              );
              var blobUrl = URL.createObjectURL(blob);
              try {
                return makeFacade(url, options, blobUrl);
              } catch (eF) {
                // Facade construction failed: fail OPEN to an ordinary worker,
                // never the raw blob worker (that would keep the CSP breakage).
                return new OrigWorker(url, options);
              }
            }
          } catch (e) {
            /* fall through to the unwrapped original */
          }
          return new OrigWorker(url, options);
        };
        // Preserve identity: prototype for instanceof and for the worker
        // methods the page calls, plus name/length shape.
        wrapped.prototype = OrigWorker.prototype;
        keepShape(wrapped, OrigWorker);
        self.Worker = wrapped;
      }
    } catch (e8) {
      /* no Worker here, or it could not be wrapped: leave it untouched */
    }

    // ----- element measurement --------------------------------------------
    // getBoundingClientRect / getClientRects report geometry with sub-pixel
    // precision, and the FRACTIONAL part of those numbers is a heavily used
    // fingerprint: it encodes the machine's font rendering, DPI, and layout
    // stack. The safety property and the entropy property are the same one:
    // the fingerprint lives in the sub-pixel fraction, and no legitimate
    // consumer depends on that fraction. Layout, scrolling, hit-testing and
    // drag-and-drop run on the engine's own internal values; these methods
    // only REPORT.
    //
    // WIDTH AND HEIGHT ONLY. Positions (x, y, and thus top/left) pass through
    // exactly. Width and height do not change on scroll, so keying the noise
    // on them is scroll-stable -- an element does not jitter as the page
    // moves. Positions are viewport-relative and would change every scroll
    // frame; noising them would wobble. The primary text-metrics fingerprint
    // is a run's WIDTH, which this covers. KNOWN RESIDUAL, stated so nobody
    // reads this as total: the sub-pixel fraction of POSITIONS still leaks
    // cumulative text-advance widths to a determined measurer. Covering that
    // safely needs per-element stable offsets, which is a later change; this
    // is the safe subset.
    //
    // MAGNITUDE, AND WHY IT CANNOT MOVE A ROUNDED VALUE. A dimension's raw
    // shift is (u - 0.5) * 0.5 with u a keyed uniform on [0, 1), i.e. in
    // [-0.25, +0.25) px. The reported value is then clamped to stay inside
    // the same integer-rounding bucket as the true value, so
    // Math.round(reported) === Math.round(true) ALWAYS -- a site that reads
    // Math.round(rect.width) sees no change at all, and only sub-pixel
    // consumers (the fingerprinters) see anything. The clamp only bites for
    // true fractions within a quarter pixel of a .5 boundary, which are
    // knife-edge values whose rounding was already machine-dependent.
    //
    // CONTENT-KEYED, NOT SITE-KEYED. Each dimension's shift derives from that
    // dimension's own value, so two differently-sized elements get
    // independent shifts and a site cannot subtract two known measurements to
    // cancel a shared offset. Equal sizes get equal shifts, so same-sized
    // things still compare equal. Deterministic: same session + site + value
    // -> same report every call, nothing to average away.
    //
    // FIDELITY. Single rects are real DOMRect objects (the constructor is
    // available on both engines), so instanceof, the prototype accessors,
    // toJSON, and right === x + width all come for free. getClientRects
    // returns a plain Array carrying item() (a real DOMRectList is not
    // script-constructible); indexing, length, item(), and iteration behave
    // as the native list, which is a documented limitation in the header.
    try {
      var rectKeyWords = null;
      var clientRectKey = function () {
        if (rectKeyWords === null) {
          rectKeyWords = seedWordsFor("clientrects");
        }
        return rectKeyWords;
      };
      // FNV-1a over one coordinate. The multiplier is 8192 (2^13), NOT the
      // 2^23 the audio digest uses: a dimension can be hundreds of px, and
      // 2^23 makes values exactly 512 px apart (512 * 2^23 = 2^32) alias to
      // the same int32 after `| 0`, so 100 and 612 would share a key and a
      // site could cancel the offset. 8192 keeps the quantized value inside
      // int32 for any dimension below ~262000 px -- larger than any viewport
      // -- while still resolving far finer than the engine's 1/64-px grid.
      var rectValueDigest = function (v) {
        var q =
          v === v && v !== Infinity && v !== -Infinity ? (v * 8192) | 0 : 0;
        var d = 2166136261;
        d = Math.imul(d ^ (q & 255), 16777619);
        d = Math.imul(d ^ ((q >>> 8) & 255), 16777619);
        d = Math.imul(d ^ ((q >>> 16) & 255), 16777619);
        d = Math.imul(d ^ ((q >>> 24) & 255), 16777619);
        return d | 0;
      };
      var farbleDimension = function (v, k, index) {
        if (v === 0 || v !== v || v === Infinity || v === -Infinity) {
          return v; // zero = "no box"; non-finite: leave untouched
        }
        var shift = (mixSample(k, rectValueDigest(v), index) - 0.5) * 0.5;
        var out = v + shift;
        if (out <= 0) {
          return v; // never negative, never flattened to the "hidden" zero
        }
        // Keep the integer-rounded value identical (see MAGNITUDE): clamp the
        // report into [round(v) - 0.5, round(v) + 0.5), the bucket that
        // rounds to round(v).
        var r = Math.round(v);
        var lo = r - 0.5;
        var hi = r + 0.5;
        if (out < lo) {
          out = lo;
        } else if (out >= hi) {
          out = hi - 1 / 8192; // strictly inside, below observable resolution
        }
        return out;
      };
      var farbleRect = function (rect) {
        if (!rect) {
          return rect;
        }
        var w = rect.width;
        var h = rect.height;
        var x = typeof rect.x === "number" ? rect.x : rect.left;
        var y = typeof rect.y === "number" ? rect.y : rect.top;
        if (
          typeof w !== "number" ||
          typeof h !== "number" ||
          typeof x !== "number" ||
          typeof y !== "number"
        ) {
          return rect; // an unexpected shape: hand back the native rect
        }
        var k = clientRectKey();
        var w2 = farbleDimension(w, k, 0);
        var h2 = farbleDimension(h, k, 1);
        // A real DOMRect: it derives top/right/bottom/left from x/y/w/h, so
        // right === x + w2 and bottom === y + h2 hold exactly, and instanceof
        // / toJSON / the prototype accessors all match native.
        if (typeof DOMRect === "function") {
          return new DOMRect(x, y, w2, h2);
        }
        // No DOMRect constructor (very old engine): a plain object with the
        // eight fields, consistent by construction. JSON.stringify matches
        // native because these are own enumerable fields.
        return {
          x: x,
          y: y,
          width: w2,
          height: h2,
          left: x,
          top: y,
          right: x + w2,
          bottom: y + h2,
        };
      };
      var farbleRectList = function (list) {
        if (!list || typeof list.length !== "number") {
          return list;
        }
        var out = [];
        for (var i = 0; i < list.length; i++) {
          out.push(farbleRect(list[i]));
        }
        // A real Array already indexes, measures, and iterates; only item()
        // must be added. configurable + writable so strict-mode code can
        // re-wrap it, matching this file's re-wrappable posture; index >>> 0
        // reproduces the native unsigned coercion, so item(-1) -> null.
        var itemFn = function item(index) {
          var idx = index >>> 0;
          return idx < out.length ? out[idx] : null;
        };
        try {
          Object.defineProperty(out, "item", {
            value: itemFn,
            configurable: true,
            writable: true,
          });
        } catch (eItem) {
          out.item = itemFn;
        }
        return out;
      };
      // The native call stays OUTSIDE the try: a native TypeError (wrong
      // receiver) must propagate exactly as unpatched. Only the noise is
      // guarded, and on any failure the true result is returned.
      var wrapOneRect = function (orig) {
        return function () {
          var rect = orig.apply(this, arguments);
          try {
            return farbleRect(rect);
          } catch (e) {
            return rect; /* true geometry, working API */
          }
        };
      };
      var wrapRectList = function (orig) {
        return function () {
          var list = orig.apply(this, arguments);
          try {
            return farbleRectList(list);
          } catch (e) {
            return list; /* true geometry, working API */
          }
        };
      };
      if (typeof Element !== "undefined" && Element.prototype) {
        patchMethod(Element.prototype, "getBoundingClientRect", wrapOneRect);
        patchMethod(Element.prototype, "getClientRects", wrapRectList);
      }
      if (typeof Range !== "undefined" && Range.prototype) {
        patchMethod(Range.prototype, "getBoundingClientRect", wrapOneRect);
        patchMethod(Range.prototype, "getClientRects", wrapRectList);
      }
    } catch (e9) {
      /* no DOM geometry in this realm */
    }

    // ----- navigator hardware hints ---------------------------------------
    // hardwareConcurrency (logical cores) and deviceMemory (GiB) are absolute
    // machine facts, identical on every site, so per-site keying would buy
    // nothing; they are NORMALIZED, not noised. Both caps only ever report
    // LESS than the truth, which is the zero-breakage direction: a site
    // sizing a worker pool or an adaptive-loading payload under-provisions
    // rather than over-provisions. min(real, 8): values 1..8 pass through and
    // the long identifying tail (10, 12, 16, 24, 32, 64) collapses into 8.
    // Reported cores never exceed real cores, so a pool sized from this value
    // always fits the machine. deviceMemory likewise -- current engines can
    // report 16 or 32, and folding those to 8 costs nothing since a value at
    // or below 8 still passes through and a low-memory device is never served
    // a heavier page than today. Each is detected independently (deviceMemory
    // does not exist on WebKit, so on WebKitGTK it is simply skipped) and
    // left configurable so a11y tools and polyfills can re-wrap.
    try {
      var capNavigatorHint = function (name, cap) {
        try {
          if (typeof navigator === "undefined") {
            return;
          }
          var target = null;
          if (
            typeof Navigator !== "undefined" &&
            Navigator.prototype &&
            name in Navigator.prototype
          ) {
            target = Navigator.prototype;
          } else if (name in navigator) {
            target = navigator;
          }
          if (!target) {
            return; // not exposed by this engine: nothing to normalize
          }
          var real = navigator[name];
          if (typeof real !== "number" || real !== real) {
            return;
          }
          var capped = cap(real);
          Object.defineProperty(target, name, {
            configurable: true,
            enumerable: false,
            get: function () {
              return capped;
            },
          });
        } catch (eHint) {
          /* unmodified hint, working API */
        }
      };
      capNavigatorHint("hardwareConcurrency", function (v) {
        return v > 8 ? 8 : v;
      });
      capNavigatorHint("deviceMemory", function (v) {
        return v > 8 ? 8 : v;
      });
    } catch (e10) {
      /* no navigator in this realm */
    }
  } catch (e7) {
    // A privacy courtesy must never throw into page script -- same rule as
    // GPC_SCRIPT.
  }
})();
