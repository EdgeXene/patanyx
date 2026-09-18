/*
 * Injected into every CONTENT webview, like autofill.js beside it, and running
 * in the same untrusted-page territory: there is no `window.ipc` here by
 * design, and this file must never assume anything about the page around it.
 *
 * WHY A CONTENT SCRIPT RATHER THAN INJECTED EVAL. The approved plan had Rust
 * calling `evaluate_script` on content webviews to pull text. That contradicts
 * this codebase's own invariant -- state.rs:256 says content webviews are
 * `load_url` only, and state.rs:1678 keeps the chrome webview's field private
 * specifically so that stays true. The invariant wins by decision, so
 * the seam is a content script over registered message handlers instead.
 *
 * WHAT IT DOES ON LOAD, STATED EXACTLY. It opens one channel to the host and
 * waits. That is the whole of it: no scan, no MutationObserver, no timer, no
 * reading of the page. Nothing is read and nothing is sent until the user
 * clicks Translate and the HOST asks.
 *
 * An earlier version of this header claimed the script did NOTHING until
 * asked. That was true when there was no way for the host to ask, and would be
 * false now, so it says what actually happens instead. What it opens tells the
 * host nothing it does not already know -- the host created this tab and drove
 * the navigation.
 *
 * TWO ENGINES, TWO TRANSPORTS, ONE CONVERSATION. The difference is real and is
 * confined to `webkitTransport` and `webview2Transport`; everything else is
 * shared.
 *   WebView2 has a genuine host-to-page push, so the page registers a passive
 *   listener and announces itself once.
 *   WebKitGTK has NO push, and its only substitute is the eval the invariant
 *   forbids. So the direction is inverted: the page opens ONE request and the
 *   host holds it open, answering only when the user acts. That is a long
 *   poll, not a loop -- one pending Promise and zero running code. A page that
 *   had to POLL on a timer would break the promise in the paragraph above on
 *   every page the user opens, translated or not, which is why the parked
 *   reply was worth the hand-written FFI it cost.
 *
 * Commands are host-authored JSON and are treated as DATA on both engines:
 * nothing here evals, and nothing here builds markup out of what it receives.
 *
 * WHAT IT SENDS IS THE PAGE'S OWN TEXT. Nothing here reads form fields,
 * passwords, or values the user typed: it walks rendered text nodes and skips
 * every editable and every input. The page already knows all of it; the point
 * is that the HOST must not receive more than the page displays.
 *
 * WHAT IT WRITES BACK IS TEXT, NEVER MARKUP. Patching assigns to
 * `node.nodeValue` on text nodes that were already collected. There is no
 * innerHTML, no insertAdjacentHTML, and no element creation anywhere in this
 * file, so a translated string cannot become an element no matter what it
 * contains.
 */
(function () {
  "use strict";

  // Top-level document only, for the reason autofill.js gives: an
  // initialization script runs in every frame, and a third-party iframe is not
  // the page the user asked to translate.
  if (window.top !== window) return;

  var OUT = "patanyxTranslate";
  var ASK = "patanyxTranslateAsk";
  // The single string the host's ask channel accepts. Deliberately not a
  // request for anything: the page cannot name a tab, a page, or a language.
  // Everything about WHAT gets translated is decided host-side.
  // TEMPLATED BY THE HOST at injection time, and deliberately a
  // closure-local rather than anything on `window`. The host refuses a poll
  // that does not carry the matching token, which is what keeps a
  // cross-origin iframe from taking over the top document's parked reply:
  // this script is injected TopFrame-only, so no other frame ever sees the
  // value. Putting it on `window` would hand it to a same-origin frame
  // through `parent`.
  var POLL = "__PATANYX_POLL_REQUEST__";

  // Elements whose text is not prose, or not the page's to translate.
  var SKIP =
    /^(SCRIPT|STYLE|NOSCRIPT|TEXTAREA|INPUT|SELECT|OPTION|CODE|PRE|KBD|SAMP|SVG|MATH)$/;

  // The session-scoped page state the reconciliation called for: ONE object,
  // created when the host first asks for an extraction, replaced when it asks
  // again, and never populated by anything the page itself does. It maps the
  // page's own nodes to the page's own text, so it exposes nothing the page
  // did not already have.
  var session = null;

  function isEditable(el) {
    for (var n = el; n; n = n.parentElement) {
      if (n.isContentEditable) return true;
    }
    return false;
  }

  // Deliberately conservative: a node is collected only if it has real text,
  // is not inside something we refuse, and is not inside anything the user
  // could be typing into. Missing a paragraph is a translation gap; picking up
  // a half-typed comment is a privacy incident.
  // Collects the next run of text nodes, SKIPPING the first `skip` that would
  // otherwise qualify.
  //
  // WHY A PAGE IS READ IN RUNS AT ALL. A long article is hundreds of nodes and
  // the engine is measurably seconds per hundred, so reading and translating
  // the whole document in one go is a minute of a frozen panel with nothing to
  // show. Runs let the page fill in progressively, and let a navigation or a
  // cancel stop the work that has not happened yet.
  //
  // The walk is redone from the top each time rather than resumed from a saved
  // position. That is deliberate: a TreeWalker held across an await is a
  // reference into a DOM that may have been rewritten underneath it, and the
  // skip count is cheap next to translating. Nodes already collected keep
  // their index, so a patch aimed at run 1 still lands after run 2 is read.
  function collect(skip, limitNodes, limitChars) {
    var walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function (node) {
          var text = node.nodeValue;
          if (!text || !text.trim()) return NodeFilter.FILTER_REJECT;
          var parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          if (SKIP.test(parent.tagName)) return NodeFilter.FILTER_REJECT;
          if (isEditable(parent)) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        },
      },
    );
    var texts = [];
    var nodes = [];
    var original = [];
    var chars = 0;
    var seen = 0;
    var node;
    var more = false;
    // TOTAL qualifying nodes in the document, counted by finishing the walk
    // after the batch fills. It is what makes a percentage possible: without
    // it the host knows how much it has DONE and nothing about how much is
    // left, which is a spinner wearing a number's clothes. Cheap next to
    // translating, and the walk is redone per run anyway.
    var total = 0;
    while ((node = walker.nextNode())) {
      // Already handed over in an earlier run.
      if (seen++ < skip) continue;
      if (texts.length >= limitNodes || chars >= limitChars) {
        // There is at least one more qualifying node than this run carries,
        // which is what tells the host to ask again. Established by FINDING
        // one rather than by comparing counts, so a page that ends exactly on
        // a run boundary does not produce an empty extra round trip.
        more = true;
        // Keep walking to COUNT the rest -- collecting stops here, counting
        // does not.
        total = seen;
        while (walker.nextNode()) total++;
        break;
      }
      var t = node.nodeValue.trim();
      if (t.length > 5000) t = t.slice(0, 5000);
      texts.push(t);
      // The node is kept so the translation can be put back where it came
      // from. This is the one piece of state that outlives a single message,
      // and `reset` drops it.
      nodes.push(node);
      // The RAW original value (whitespace and all), kept so Show original can
      // put back EXACTLY what was there -- `t` above is trimmed, and restoring
      // a trimmed value would quietly eat a node's leading/trailing spaces.
      original.push(node.nodeValue);
      chars += t.length;
      total = seen;
    }
    return {
      texts: texts, nodes: nodes, original: original, more: more, total: total,
    };
  }

  function doExtract(cmd) {
    var limitNodes = clampInt(cmd.limitNodes, 1, 5000, 200);
    var limitChars = clampInt(cmd.limitChars, 1, 200000, 20000);
    var id = String(cmd.session || "");
    var offset = clampInt(cmd.offset, 0, 1000000, 0);
    var got = collect(offset, limitNodes, limitChars);

    // A CONTINUATION APPENDS; A NEW RUN REPLACES. The offset alone does not
    // decide it -- the session id has to match too, or a stale continuation
    // from a cancelled run would graft its nodes onto the run that replaced
    // it and every later patch index would be wrong.
    if (offset > 0 && session && session.id === id) {
      session.nodes = session.nodes.concat(got.nodes);
      session.sent = session.sent.concat(got.texts);
      session.original = session.original.concat(got.original);
    } else {
      session = {
        id: id,
        nodes: got.nodes,
        sent: got.texts.slice(),
        original: got.original.slice(),
      };
      offset = 0;
    }

    post({
      kind: "extract",
      session: id,
      href: String(location.href).slice(0, 2048),
      // The index the first item of this batch sits at, so the host can address
      // nodes ABSOLUTELY and a patch for run 1 stays valid after run 2.
      offset: offset,
      more: got.more,
      // How many translatable nodes the whole document has, so the panel can
      // show real progress rather than an unmoving phase word.
      total: got.total,
      // WHAT LANGUAGE THIS PAGE SAYS IT IS, reported only on the first run --
      // it cannot change mid-document, and repeating it every run would be
      // noise the host has to ignore.
      //
      // The page's OWN claim, and treated as a claim: a document can declare
      // anything, and plenty declare "en" while being written in something
      // else. The host cross-checks it against the script the text is actually
      // written in and refuses when the two disagree, so a wrong lang tag
      // costs a translation rather than corrupting a page.
      lang: offset === 0 ? declaredLang() : null,
      batch: got.texts,
    });
  }

  // Puts translated text back. Every item is checked against the page as it is
  // NOW, not as it was when extracted: a page that rewrote itself mid-flight
  // gets skipped rather than stomped, which is the difference between a
  // translation gap and destroying content the user was looking at.
  function doPatch(cmd) {
    if (!session || String(cmd.session || "") !== session.id) return;
    var items = cmd.items;
    if (!items || typeof items.length !== "number") return;
    for (var k = 0; k < items.length; k++) {
      var item = items[k];
      if (!item) continue;
      var i = item.i;
      if (typeof i !== "number" || i < 0 || i >= session.nodes.length) continue;
      var text = item.t;
      if (typeof text !== "string") continue;
      var node = session.nodes[i];
      if (!node || !node.isConnected) continue;
      // STALE-NODE SKIP. If what the node holds now is not what we sent, the
      // page changed it and this translation is answering a question that is
      // no longer being asked.
      if (node.nodeValue.trim() !== session.sent[i]) continue;
      node.nodeValue = text;
      // The node now holds the translation, so a second patch for the same
      // index must not be judged against the original any more.
      session.sent[i] = text.trim();
    }
  }

  // SHOW ORIGINAL. Puts every translated node back to exactly what it held
  // before translation. Symmetric with doPatch: it only touches a node that
  // still holds what WE last wrote (session.sent[i]) and is still connected,
  // so a page that rewrote a node after translation is left alone rather than
  // stomped. Needs no engine and no network -- the originals never left the
  // page, which is why they can come back with nothing downloaded.
  function doRestore(cmd) {
    if (!session || String(cmd.session || "") !== session.id) return;
    for (var i = 0; i < session.nodes.length; i++) {
      var node = session.nodes[i];
      if (!node || !node.isConnected) continue;
      // Only restore what still holds our translation; leave anything the page
      // changed since untouched.
      if (node.nodeValue.trim() !== session.sent[i]) continue;
      node.nodeValue = session.original[i];
      // Now it holds the original again; a later re-translate judges against
      // that, so the two directions stay symmetric.
      session.sent[i] = String(session.original[i]).trim();
    }
  }

  // The document's declared language, from the two places a page states it.
  //
  // `<html lang>` first because it is the authoritative one and the only place
  // most well-formed sites put it; the http-equiv meta is a fallback for older
  // pages. Returned raw and unparsed -- the host owns deciding what "el-GR"
  // means, because that is a decision about which model to load and it belongs
  // where the model list lives, not in a script running in a hostile document.
  function declaredLang() {
    try {
      var el = document.documentElement;
      var v = (el && el.getAttribute && el.getAttribute("lang")) || "";
      if (!v) {
        var m = document.querySelector('meta[http-equiv="content-language" i]');
        v = (m && m.getAttribute("content")) || "";
      }
      return String(v).slice(0, 32);
    } catch (e) {
      return "";
    }
  }

  function clampInt(v, lo, hi, dflt) {
    if (typeof v !== "number" || !isFinite(v)) return dflt;
    v = Math.floor(v);
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
  }

  // ONE CONVERSATION, TWO TRANSPORTS. The engines differ in what they offer
  // and there is no pretending otherwise, so the difference is confined to
  // these two objects and everything above and below them is shared. Picking
  // the transport by FEATURE rather than by a build-time flag keeps one file
  // for both engines, which is what stops the two halves drifting.
  var transport = null;

  // WebKitGTK. No host-to-page push exists, so the page LONG-POLLS: one
  // request outstanding, answered by the host only when the user acts. See
  // the header -- this is what keeps "no timer" true.
  function webkitTransport() {
    var mh = window.webkit && window.webkit.messageHandlers;
    if (!mh || !mh[OUT] || !mh[ASK]) return null;
    return {
      send: function (json) {
        mh[OUT].postMessage(json);
      },
      // A rejection ENDS the pump rather than retrying, because a retry on
      // rejection is exactly the busy loop this shape exists to avoid -- and
      // a fresh document opens a fresh poll anyway, so nothing is lost.
      listen: function pump() {
        var promise;
        try {
          promise = mh[ASK].postMessage(POLL);
        } catch (e) {
          return;
        }
        if (!promise || typeof promise.then !== "function") return;
        promise.then(function (answer) {
          try {
            handle(answer);
          } catch (e) {
            /* A malformed command must not kill the pump; the host is
               trusted not to be hostile, but not to be bug-free. */
          }
          pump();
        }, function () {
          /* The page is going away, or the host refused. Stop. */
        });
      },
    };
  }

  // WebView2. A real host-to-page push exists, so there is nothing to poll:
  // the listener sits passive until the host sends something, which is the
  // same promise the long poll keeps by a longer road. The page announces
  // itself once so the host knows a document is listening -- on WebKitGTK the
  // poll itself carries that news, and the host needs it on both.
  function webview2Transport() {
    var wv = window.chrome && window.chrome.webview;
    if (!wv || typeof wv.postMessage !== "function") return null;
    return {
      send: function (json) {
        wv.postMessage(json);
      },
      listen: function () {
        wv.addEventListener("message", function (ev) {
          try {
            // WebView2 delivers PostWebMessageAsJson pre-parsed on `data`.
            // `handle` takes the string form, so this re-serialises rather
            // than growing a second code path -- one parser, one shape.
            handle(typeof ev.data === "string" ? ev.data : JSON.stringify(ev.data));
          } catch (e) {
            /* As above. */
          }
        });
        post({ kind: "ready", href: String(location.href).slice(0, 2048) });
      },
    };
  }

  function post(payload) {
    try {
      transport.send(JSON.stringify(payload));
    } catch (e) {
      /* No channel means no translation. Nothing here is worth breaking the
         page over. */
    }
  }

  function handle(answer) {
    if (typeof answer !== "string") return;
    var cmd = JSON.parse(answer);
    if (!cmd || typeof cmd.cmd !== "string") return;
    if (cmd.cmd === "extract") return doExtract(cmd);
    if (cmd.cmd === "patch") return doPatch(cmd);
    if (cmd.cmd === "restore") return doRestore(cmd);
    if (cmd.cmd === "reset") {
      session = null;
      return;
    }
  }

  transport = webkitTransport() || webview2Transport();
  // NEITHER ENGINE, NEITHER CHANNEL: a document that is not in a PATANYX
  // content webview at all. Do nothing, silently. There is no fallback worth
  // having here -- the only alternatives would be to poll something that does
  // not exist or to start reading the page for a host that cannot hear it.
  if (!transport) return;
  transport.listen();

  // TIER-1 DETECTION SIGNAL, for the badge. Reports ONLY the page's DECLARED
  // language (the <html lang> attribute, no page text at all), so the panel
  // can quietly show "this looks translatable" without anything being read or
  // sent. This is the ONLY thing that happens automatically, and it discloses
  // nothing the host did not already have -- the host drove this navigation.
  // Actual translation still needs a click; this only lights a badge.
  //
  // Sent once, after a tick so the document has its final lang attribute (some
  // pages set it late from script). A blank lang sends nothing -- no badge is
  // better than a wrong one.
  // When the page declares nothing, its LETTERS still say what writing
  // system it is in. Counted HERE, in the page, and only the winning script's
  // NAME crosses to the host -- no page text leaves automatically, same
  // ruling as the declared attribute, and the host maps a name to a language
  // only where exactly one supported language uses that script (Greek is
  // unambiguously el; Cyrillic could be four languages and maps to nothing).
  // A page can lie about either signal; both are prefill hints, and the
  // host-side cumulative script guard still judges the real text during
  // translation.
  function scriptSample() {
    try {
      var counts = {
        latin: 0, greek: 0, cyrillic: 0, hebrew: 0, arabic: 0,
        devanagari: 0, bengali: 0, gujarati: 0, tamil: 0, telugu: 0,
        kannada: 0, malayalam: 0, thai: 0, kana: 0, han: 0, hangul: 0,
        georgian: 0,
      };
      var total = 0;
      var root = document.body || document.documentElement;
      if (!root) return "";
      var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      var node;
      var seen = 0;
      while ((node = walker.nextNode()) && seen < 4000) {
        var t = node.nodeValue || "";
        seen += t.length;
        var cap = t.length < 500 ? t.length : 500;
        for (var i = 0; i < cap; i++) {
          var c = t.charCodeAt(i);
          if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0xc0 && c <= 0x24f)) counts.latin++;
          else if ((c >= 0x370 && c <= 0x3ff) || (c >= 0x1f00 && c <= 0x1fff)) counts.greek++;
          else if (c >= 0x400 && c <= 0x4ff) counts.cyrillic++;
          else if (c >= 0x590 && c <= 0x5ff) counts.hebrew++;
          else if ((c >= 0x600 && c <= 0x6ff) || (c >= 0x750 && c <= 0x77f)) counts.arabic++;
          else if (c >= 0x900 && c <= 0x97f) counts.devanagari++;
          else if (c >= 0x980 && c <= 0x9ff) counts.bengali++;
          else if (c >= 0xa80 && c <= 0xaff) counts.gujarati++;
          else if (c >= 0xb80 && c <= 0xbff) counts.tamil++;
          else if (c >= 0xc00 && c <= 0xc7f) counts.telugu++;
          else if (c >= 0xc80 && c <= 0xcff) counts.kannada++;
          else if (c >= 0xd00 && c <= 0xd7f) counts.malayalam++;
          else if (c >= 0xe00 && c <= 0xe7f) counts.thai++;
          else if ((c >= 0x10a0 && c <= 0x10ff) || (c >= 0x1c90 && c <= 0x1cbf)) counts.georgian++;
          else if ((c >= 0x3040 && c <= 0x309f) || (c >= 0x30a0 && c <= 0x30ff)) counts.kana++;
          else if (c >= 0x4e00 && c <= 0x9fff) counts.han++;
          else if (c >= 0xac00 && c <= 0xd7af) counts.hangul++;
          else continue;
          total++;
        }
      }
      // Too few letters to judge, or no clear majority: say nothing. A blank
      // is better than a guess -- the user still has the dropdown.
      if (total < 40) return "";
      var best = "";
      var bestN = 0;
      for (var k in counts) {
        if (counts[k] > bestN) { best = k; bestN = counts[k]; }
      }
      // Japanese and Chinese share Han; kana is the tell. Same threshold the
      // host-side guard uses.
      if (best === "han" || best === "kana") {
        var cj = counts.han + counts.kana;
        best = cj > 0 && counts.kana / cj >= 0.15 ? "kana" : "han";
        bestN = cj;
      }
      if (bestN / total < 0.5) return "";
      return best;
    } catch (e) {
      return "";
    }
  }

  function postDetected() {
    try {
      var declared = declaredLang();
      // The declared attribute wins; letters are the fallback for pages that
      // declare nothing.
      var script = declared ? "" : scriptSample();
      if (declared || script) {
        post({
          kind: "detected",
          href: String(location.href).slice(0, 2048),
          lang: declared,
          script: script,
        });
      }
    } catch (e) {
      /* A page that broke this does not get a badge; nothing else cares. */
    }
  }

  try {
    // Early, so the badge lights as soon as a declared attribute exists; and
    // AGAIN once the DOM is ready, because at document-start there is no body
    // to sample letters from -- and because the early post can lose a race
    // with the host learning this tab's new URL, in which case it is
    // (rightly) refused and this retry is what lands. Repeats overwrite,
    // which the host treats as a page updating its answer.
    setTimeout(postDetected, 0);
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", postDetected);
    } else {
      setTimeout(postDetected, 50);
    }
    window.addEventListener("load", postDetected);
  } catch (e) {
    /* A page that broke setTimeout does not get a badge; nothing else cares. */
  }
})();
