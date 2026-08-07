/*
 * Fingerprint Divergence: small deterministic noise on fingerprinting
 * readouts. The lite set -- canvas, audio, and the WebGL vendor/renderer
 * strings.
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
 * Deliberate non-goals, so nobody "fixes" them:
 *   - No stealth. A page that probes for patched natives can tell this is
 *     on. That is accepted: hiding imperfectly is a stronger signal than
 *     not hiding at all.
 *   - Hooks are plain writable prototype assignments, not non-configurable
 *     defineProperty: polyfills and a11y tools legitimately wrap these; a
 *     page that actively unhooks gets its real fingerprint, which is the
 *     same outcome as a page that detects the noise and special-cases it.
 *   - KNOWN HOLE: workers. Neither engine injects registered scripts into
 *     Worker/OffscreenCanvas contexts, so worker-based canvas fingerprinting
 *     bypasses this entirely. Noise applied inside the renderer itself
 *     would reach workers; a WebView embedder has no such hook. Never imply
 *     coverage there.
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
    window.__patanyxDiverged = true;

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
    function noiseData(data) {
      var r = rngFor("canvas");
      for (var i = 0; i + 3 < data.length; i += 4) {
        var v = r();
        if ((v & 7) === 0) {
          data[i] ^= 1;
          data[i + 1] ^= (v >>> 3) & 1;
          data[i + 2] ^= (v >>> 4) & 1;
        }
      }
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
    // One multiplicative fudge per site+session, in [0.99, 1.0): at most
    // 0.09 dB, far below audibility, but it moves every sample and thus the
    // whole fingerprint hash.
    var audioFudgeValue = null;
    var audioFudge = function () {
      if (audioFudgeValue === null) {
        audioFudgeValue = 0.99 + (rngFor("audio")() / 4294967296) * 0.01;
      }
      return audioFudgeValue;
    };

    try {
      // getChannelData: scale IN PLACE, ONCE per returned array. In place
      // because Web Audio code writes into the live array it gets back --
      // returning a scaled copy breaks synthesis. Once, tracked by WeakSet,
      // because repeated reads must not compound the fudge into something
      // audible. Mixing getChannelData with copyFromChannel on the same
      // buffer can scale a sample twice (0.9801 worst case); still
      // inaudible, accepted.
      var scaledArrays = typeof WeakSet !== "undefined" ? new WeakSet() : null;
      var scaleOnce = function (arr) {
        if (!arr || !arr.length) {
          return;
        }
        if (scaledArrays) {
          if (scaledArrays.has(arr)) {
            return;
          }
          scaledArrays.add(arr);
        }
        var f = audioFudge();
        for (var i = 0; i < arr.length; i++) {
          arr[i] *= f;
        }
      };
      if (typeof AudioBuffer !== "undefined") {
        patchMethod(AudioBuffer.prototype, "getChannelData", function (orig) {
          return function () {
            var arr = orig.apply(this, arguments);
            try {
              scaleOnce(arr);
            } catch (e) {
              /* true samples, working API */
            }
            return arr;
          };
        });
        patchMethod(AudioBuffer.prototype, "copyFromChannel", function (orig) {
          return function (destination) {
            var out = orig.apply(this, arguments);
            try {
              // The destination is overwritten by every call, so this
              // scales every call -- no WeakSet here, or the second copy
              // would come back clean.
              if (destination && destination.length) {
                var f = audioFudge();
                for (var i = 0; i < destination.length; i++) {
                  destination[i] *= f;
                }
              }
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
        var scaleFloats = function (arr, f) {
          for (var i = 0; i < arr.length; i++) {
            arr[i] *= f;
          }
        };
        var scaleBytes = function (arr, f) {
          for (var i = 0; i < arr.length; i++) {
            // Values are 0..255 and f < 1, so the scaled value stays in
            // range; +0.5|0 rounds without a Math call per sample.
            arr[i] = (arr[i] * f + 0.5) | 0;
          }
        };
        var analyserPatch = function (name, scale) {
          patchMethod(AnalyserNode.prototype, name, function (orig) {
            return function (array) {
              var out = orig.apply(this, arguments);
              try {
                if (array && array.length) {
                  scale(array, audioFudge());
                }
              } catch (e) {
                /* true readout, working API */
              }
              return out;
            };
          });
        };
        analyserPatch("getFloatFrequencyData", scaleFloats);
        analyserPatch("getFloatTimeDomainData", scaleFloats);
        analyserPatch("getByteFrequencyData", scaleBytes);
        analyserPatch("getByteTimeDomainData", scaleBytes);
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
  } catch (e7) {
    // A privacy courtesy must never throw into page script -- same rule as
    // GPC_SCRIPT.
  }
})();
