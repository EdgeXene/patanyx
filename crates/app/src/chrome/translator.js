// The translator document's script. Runs in the HIDDEN translator webview, on
// its OWN origin, with NO ipc handler and no access to anything the chrome UI
// can reach -- see docs/page-translation-spike.md for what that separation was
// measured to be worth.
//
// THREE STAGES, EACH ASKED FOR SEPARATELY. Booting the engine, loading a
// language pack, and translating a batch are distinct steps with distinct
// costs, and the host drives them one at a time so the panel can say which one
// is happening. Nothing here starts on its own past the engine boot.
//
// The host reads state through `window.__translator.status()`, polled with
// evaluate_script_with_callback, which serializes SYNCHRONOUS returns only.
// Everything asynchronous therefore lands in `S` and is collected on the next
// poll rather than being pushed.
//
// TRANSLATION BLOCKS THIS DOCUMENT'S MAIN THREAD, deliberately and
// unavoidably: Bergamot's `BlockingService` is what its name says. A batch of
// a couple of hundred sentences is seconds of a frozen event loop. That is
// survivable ONLY because this webview is hidden and is not the chrome and is
// not the page -- which is the third reason the separate webview exists, after
// origin isolation and the CSP cost.
//
// EVERY ENTRY POINT TAKES A JSON STRING AND RETURNS ONE. The host builds the
// call as a fixed wrapper with a serde_json-encoded argument, so page text
// never becomes JavaScript source on the way in, and never becomes anything
// but a string on the way out.
(function () {
  "use strict";

  var S = {
    phase: "boot",
    error: null,
    engineReadyMs: null,
    pair: null,
    packReadyMs: null,
    t0: performance.now(),
  };
  var Engine = null;
  // The loaded pack. One at a time: a second pair replaces the first rather
  // than accumulating, because each is tens of megabytes of wasm heap and a
  // user translating into three languages must not pay for all three at once.
  var model = null;
  var service = null;
  // Finished jobs, collected by the host on a later poll. Keyed by the id the
  // host chose; this document never invents one.
  var jobs = {};

  // Byte alignments Bergamot requires for each artifact. Not adjustable and
  // not guessed -- these come from the engine's own loader.
  var ALIGN = { model: 256, lex: 64, vocab: 64 };

  // WHICH LOAD IS CURRENT. Every loadPack takes the next number; an
  // asynchronous load that finishes after a newer one started throws its work
  // away instead of overwriting the newer model.
  //
  // Without it two loads race: `S.pair` is not set until a load COMPLETES, so
  // the duplicate guard cannot see an in-flight one, and `Promise.all` results
  // arrive in whatever order the fetches finish. Pack A completing after pack
  // B leaves B's pair recorded against A's model -- and the host, which asks
  // only whether the loaded pair matches, is then told yes about the wrong
  // model. Text for one language through another language's model is fluent
  // output unrelated to the input, which is the hardest failure to recognise.
  var loadSeq = 0;

  function fail(where, e) {
    // Catalog KEYS, never prose: this string crosses to the panel and the
    // panel renders in the user's language.
    S.error = where;
    S.detail = String((e && e.message) || e).slice(0, 300);
    S.phase = "failed";
  }

  // WHICH COPY OF THIS FILE IS RUNNING, read from the URL the browser
  // actually fetched it from.
  //
  // Four builds in a row produced byte-identical wrong output while the code
  // that produces it changed underneath them, and there was no way to tell a
  // stale script from a correct script computing a wrong answer -- so every
  // diagnosis was inference. The host serves this file at ./translator.js?v=
  // <revision of the compiled-in assets>; a copy that reports NO revision was
  // cached from a build that predates versioned URLs, and one that reports a
  // revision the host does not recognise is simply stale.
  //
  // Reported, never acted on: this is an instrument, not a control.
  var ASSET_REV = (function () {
    try {
      var el =
        document.currentScript ||
        document.querySelector('script[src*="translator.js"]');
      var m = /[?&]v=([A-Za-z0-9]+)/.exec((el && el.src) || "");
      return m ? m[1] : "unversioned";
    } catch (e) {
      return "unknown";
    }
  })();

  window.__translator = {
    status: function () {
      return JSON.stringify({
        phase: S.phase,
        error: S.error,
        detail: S.detail || null,
        engineReadyMs: S.engineReadyMs,
        pair: S.pair,
        packReadyMs: S.packReadyMs,
        // The instrument. `assetRev` says which copy of THIS file is running;
        // `heapBytes` says how much linear memory the engine actually got,
        // which is the number every heap-pressure theory was arguing about
        // without anybody being able to read it.
        assetRev: ASSET_REV,
        lastInput: S.lastInput || null,
        heapBytes:
          Engine && Engine.HEAPU8 ? Engine.HEAPU8.length : null,
      });
    },

    // Loads a language pack. The host has ALREADY checked the pair against the
    // published registry; the checks here are a shape-and-presence guard,
    // because a document that trusts its caller completely is one refactor
    // away from trusting something else.
    //
    // FROM AND TO ARRIVE EXPLICITLY, from the host's registry row. They used
    // to be sliced out of the token by fixed byte offsets, which is silently
    // wrong for any language tag longer than two letters. The token is used
    // only to name the pack directory (./pack/<token>/) and to detect an
    // already-loaded pack; the model is built from `from`/`to`.
    loadPack: function (arg) {
      try {
        var req = JSON.parse(arg);
        var pair = String(req.pair || "");
        var from = String(req.from || "");
        var to = String(req.to || "");
        // ALLOWLISTED, not passed through: the host names one of two GEMM
        // precisions and anything else falls back to the historical setting.
        // int8shiftAlphaAll uses the alphas calibrated into a pack at build
        // time; packs without them (Mozilla's students, as configured here
        // since the first spike) stay on int8shiftAll.
        var gemm =
          req.gemm === "int8shiftAlphaAll" ? "int8shiftAlphaAll" : "int8shiftAll";
        // ALLOWLISTED like the precision. "split" means this pair ships a
        // source and a target segmenter instead of one shared vocabulary --
        // Mozilla publishes Japanese and Chinese that way, and the engine
        // takes a LIST of vocabularies precisely so both can be handed over.
        var vocabLayout = req.vocab === "split" ? "split" : "joint";
        // Path-segment safety for the fetch, since `pair` names a directory.
        // Language subtags: letters, digits, hyphen; bounded; no dot or slash.
        var TAG = /^[A-Za-z0-9-]{2,20}$/;
        var SUBTAG = /^[A-Za-z0-9-]{2,12}$/;
        if (!TAG.test(pair) || !SUBTAG.test(from) || !SUBTAG.test(to)) {
          fail("translate-pack-failed", new Error("bad pair"));
          return "refused";
        }
        if (S.pair === pair && service) return "already";
        if (!Engine) {
          fail("translate-pack-failed", new Error("engine not ready"));
          return "refused";
        }
        S.phase = "loading-pack";
        loadSeq += 1;
        loadPack(pair, from, to, gemm, vocabLayout, loadSeq);
        return "loading";
      } catch (e) {
        fail("translate-pack-failed", e);
        return "refused";
      }
    },

    // Translates a batch. Returns immediately with "queued"; the result is
    // collected by `result` on a later poll, because a batch takes seconds and
    // a synchronous return would mean the host blocking on it.
    translate: function (arg) {
      var job;
      try {
        job = JSON.parse(arg);
      } catch (e) {
        return "refused";
      }
      var id = String(job.id || "");
      if (!id) return "refused";
      if (!service || !model) {
        jobs[id] = { error: "translate-no-pack" };
        return "queued";
      }
      var texts = job.texts;
      if (!texts || typeof texts.length !== "number") return "refused";
      // THE PAIR THIS TEXT IS FOR, checked against what is actually loaded.
      //
      // The host checks the same thing before calling, and that check is
      // real -- but it reads a status the host polled EARLIER, so it cannot
      // see a pack swapped in between the poll and this call. Two guards on
      // the same fact are worth it here: being wrong means a page's text goes
      // through another language's model and comes back fluent and unrelated,
      // which reads as a broken model rather than a mix-up.
      //
      // Absent `pair` is accepted so an older host still works; present and
      // mismatched is refused.
      var want = job.pair ? String(job.pair) : "";
      if (want && want !== S.pair) return "refused";
      // WHAT THE ENGINE ACTUALLY RECEIVED, as a script census -- never the
      // text itself. Page content is the user's, and a diagnostic that logs
      // it would be a worse defect than the one it chases.
      //
      // This exists because everything else has been eliminated: the pack
      // bytes are identical to a copy that translates this text correctly on
      // the other backend, the cache is gone, the heap is raised, the model
      // and precision are verified. Deterministic wrong output with all of
      // that ruled out means the ENGINE IS NOT BEING GIVEN WHAT THE HOST
      // SENT -- and the only way to know is to count, at the last point
      // before the WASM boundary, which alphabets arrived.
      //
      // If Cyrillic went in and the census reports none, the text was
      // mangled in transit and the model is innocent.
      try {
        var census = { cyrillic: 0, latin: 0, greek: 0, other: 0, chars: 0 };
        for (var ci = 0; ci < texts.length; ci++) {
          var str = String(texts[ci] || "");
          census.chars += str.length;
          for (var cj = 0; cj < str.length && cj < 2000; cj++) {
            var cc = str.charCodeAt(cj);
            if (cc >= 0x400 && cc <= 0x4ff) census.cyrillic++;
            else if ((cc >= 0x41 && cc <= 0x5a) || (cc >= 0x61 && cc <= 0x7a)) census.latin++;
            else if (cc >= 0x370 && cc <= 0x3ff) census.greek++;
            else if (cc > 0x7f) census.other++;
          }
        }
        S.lastInput = census;
      } catch (e) {
        S.lastInput = null;
      }
      // Deferred so this call returns and the host is not blocked while the
      // engine runs. The document blocks; the host does not.
      setTimeout(function () {
        runJob(id, texts);
      }, 0);
      jobs[id] = { pending: true };
      return "queued";
    },

    // Collects a finished job and FORGETS it. Page text does not linger in
    // this document after the host has taken it.
    result: function (arg) {
      var id;
      try {
        id = String(JSON.parse(arg).id || "");
      } catch (e) {
        return JSON.stringify({ error: "translate-bad-request" });
      }
      var job = jobs[id];
      if (!job || job.pending) return JSON.stringify({ pending: true });
      delete jobs[id];
      return JSON.stringify(job);
    },
  };

  function runJob(id, texts) {
    var vText = null;
    var vOpt = null;
    var vResp = null;
    try {
      var t0 = performance.now();
      vText = new Engine.VectorString();
      // BLANKS ARE DROPPED BY THE ENGINE, so they are dropped HERE too and the
      // index is carried explicitly. Pushing an empty string and trusting the
      // output to line up would silently shift every later translation onto
      // the wrong node -- the whole page one paragraph out of step.
      var idx = [];
      for (var i = 0; i < texts.length; i++) {
        var t = texts[i];
        if (typeof t !== "string" || t.trim() === "") continue;
        vText.push_back(t);
        idx.push(i);
      }
      vOpt = new Engine.VectorResponseOptions();
      for (var k = 0; k < idx.length; k++) {
        vOpt.push_back({ qualityScores: false, alignment: false, html: false });
      }
      vResp = service.translate(model, vText, vOpt);
      var out = [];
      for (var j = 0; j < vResp.size(); j++) {
        out.push({ i: idx[j], t: vResp.get(j).getTranslatedText() });
      }
      jobs[id] = { ms: Math.round(performance.now() - t0), items: out };
    } catch (e) {
      jobs[id] = {
        error: "translate-failed",
        detail: String((e && e.message) || e).slice(0, 300),
      };
    } finally {
      // Emscripten heap objects are NOT garbage collected. Every one of these
      // leaks wasm memory if it is not deleted, and this runs once per batch.
      try {
        if (vText) vText.delete();
      } catch (e) {}
      try {
        if (vOpt) vOpt.delete();
      } catch (e) {}
      try {
        if (vResp) vResp.delete();
      } catch (e) {}
    }
  }

  function aligned(buf, alignBytes) {
    var bytes = new Int8Array(buf);
    var am = new Engine.AlignedMemory(bytes.byteLength, alignBytes);
    am.getByteArrayView().set(bytes);
    return am;
  }

  function fetchBuf(url) {
    return fetch(url, { credentials: "same-origin" }).then(function (r) {
      if (!r.ok) throw new Error(url + " " + r.status);
      return r.arrayBuffer();
    });
  }

  /// Frees the native objects of the currently loaded pack, if any.
  ///
  /// Emscripten objects are not garbage collected -- each has a `delete()`
  /// that returns its memory to the WASM heap, and nothing else does. Called
  /// before installing a replacement and on the failure path, so a load that
  /// dies partway does not strand what it had already built.
  function disposePack() {
    try {
      if (model && model.delete) model.delete();
    } catch (e) {
      /* a delete that throws must not stop the replacement */
    }
    try {
      if (service && service.delete) service.delete();
    } catch (e) {
      /* same */
    }
    model = null;
    service = null;
  }

  function loadPack(pair, from, to, gemm, vocabLayout, gen) {
    var t0 = performance.now();
    var base = "./pack/" + pair + "/";
    // The vocabulary files this layout has. Fixed names either way: the
    // container carries no names, and these are the destinations the host
    // wrote them to.
    var vocabFiles =
      vocabLayout === "split"
        ? ["srcvocab.spm", "trgvocab.spm"]
        : ["vocab.spm"];
    Promise.all(
      [fetchBuf(base + "model.bin"), fetchBuf(base + "lex.bin")].concat(
        vocabFiles.map(function (n) {
          return fetchBuf(base + n);
        }),
      ),
    )
      .then(function (bufs) {
        var vocabList = new Engine.AlignedMemoryList();
        // Source first, then target, when there are two -- the order the
        // engine reads them in. With one, the same vocabulary serves both.
        for (var vi = 2; vi < bufs.length; vi++) {
          vocabList.push_back(aligned(bufs[vi], ALIGN.vocab));
        }
        var config =
          [
            "beam-size: 1",
            "normalize: 1.0",
            "word-penalty: 0",
            "max-length-break: 128",
            "mini-batch-words: 1024",
            "workspace: 128",
            "max-length-factor: 2.0",
            "skip-cost: true",
            "cpu-threads: 0",
            "quiet: true",
            "quiet-translation: true",
            "gemm-precision: " + gemm,
            "alignment: soft",
          ].join("\n") + "\n";
        // v0.6.0 takes SEVEN arguments; 0.4.5 took five. The two extra are the
        // source and target languages -- the engine registers them on the
        // model, which is what makes pivoting possible later. They are passed
        // by the HOST from its registry row, never derived from the token.
        // A ZERO-BYTE lex.bin means "this pack has no shortlist". The engine
        // treats the shortlist as optional (upstream passes null for packs
        // without one), and the OPUS-MT conversions ship none -- building one
        // needs a parallel corpus per pair. Measured working in the Latin
        // spike; an empty AlignedMemory, by contrast, is not a shortlist and
        // must not be handed to the loader as one.
        // A NEWER LOAD STARTED WHILE THIS ONE WAS FETCHING. Drop this work
        // rather than install it: the newer request is what the host is
        // waiting on, and installing this one would record the newer pair
        // against the older model.
        if (gen !== loadSeq) {
          vocabList.delete();
          return;
        }
        // THE OUTGOING PACK IS FREED EXPLICITLY. These are Emscripten heap
        // objects: dropping the JS reference frees nothing, and the heap
        // cannot grow. A model is tens of megabytes, so switching languages a
        // few times without this exhausts the heap -- which marian answers
        // with wrong arithmetic rather than an error.
        disposePack();
        model = new Engine.TranslationModel(
          from,
          to,
          config,
          aligned(bufs[0], ALIGN.model),
          bufs[1].byteLength === 0 ? null : aligned(bufs[1], ALIGN.lex),
          vocabList,
          null,
        );
        service = new Engine.BlockingService({ cacheSize: 0 });
        S.pair = pair;
        S.packReadyMs = Math.round(performance.now() - t0);
        S.phase = "ready";
      })
      .catch(function (e) {
        // Only the CURRENT load may report a failure; a superseded one
        // failing is not news, and letting it set the phase would fail a load
        // that is still running.
        if (gen !== loadSeq) return;
        disposePack();
        S.pair = null;
        fail("translate-pack-failed", e);
      });
  }

  // WE fetch the wasm and hand the bytes to the glue, which is how upstream
  // drives this engine (translations-engine.worker.js). The engine never
  // fetches anything itself, so every byte it sees came through a request this
  // document made to its own origin.
  S.phase = "loading-engine";
  fetchBuf("./bergamot-translator.wasm")
    .then(function (wasmBinary) {
      Engine = loadBergamot({
        // Upstream's figure for a simple run of Bergamot, carried over rather
        // than invented.
        //
        // RAISED TO 1.5 GiB ON 2026-09-01 AND PUT BACK THE SAME DAY. The
        // reasoning was that a 74-79 MB converted model plus the 128 MB
        // workspace could not fit 223 MiB, and that marian would compute in
        // whatever it could get rather than fail -- which would explain
        // fluent output unrelated to the input. Two things killed that: an
        // independent read of the shipped glue and WASM contradicted the
        // fixed-ceiling premise, and the same converted pack then translated
        // a different Macedonian page CORRECTLY at this original size. A
        // model that works at 223 MiB was never starved of memory.
        //
        // The 1.5 GiB version also committed that much on first translation,
        // which is a plausible way to stall a laptop, so the unjustified cost
        // goes with the unjustified theory. If a heap limit is ever genuinely
        // implicated, the engine now REPORTS its heap in status() -- measure
        // it rather than argue about it.
        INITIAL_MEMORY: 234291200,
        print: function () {},
        printErr: function () {},
        onAbort: function () {
          fail("translate-engine-aborted", new Error("engine onAbort"));
        },
        onRuntimeInitialized: function () {
          // Upstream awaits a microtask here so the captured module variable is
          // fully assigned before anything touches it. Same reason, same wait.
          Promise.resolve().then(function () {
            try {
              // NO RUNTIME VERSION FIELD, deliberately. The glue defines
              // BERGAMOT_VERSION_FULL inside loadBergamot's own scope, so this
              // document cannot see it and an earlier version of this file
              // reported "unknown" forever -- a field that is always the same
              // wrong answer is worse than no field.
              //
              // The version is COMPILE-TIME known and machine-verified: the
              // engine is include_bytes! from models/translator/, whose bytes
              // the artifact gate refuses to let drift from the hash recorded
              // in shipped-artifacts.json. Ask the build, not the page.
              S.engineReadyMs = Math.round(performance.now() - S.t0);
              // ENGINE ready, not TRANSLATION ready. A pack still has to be
              // loaded, and the phase name says so rather than implying the
              // feature works.
              S.phase = "engine-ready";
            } catch (e) {
              fail("translate-engine-failed", e);
            }
          });
        },
        wasmBinary: wasmBinary,
      });
    })
    .catch(function (e) {
      fail("translate-engine-failed", e);
    });
})();
