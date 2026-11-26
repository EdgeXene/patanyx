// THE LOCAL-NETWORK BOUNDARY, WEBSOCKET HALF. Windows content tabs only.
//
// WHY A PAGE SCRIPT. The boundary is enforced in the WebView2 request handler
// (privacy.rs, decide_intercepted), and WebView2 never raises
// WebResourceRequested for a WebSocket handshake. Measured on hardware
// 2026-09-24: a plain-HTTP public page had its iframe, image, fetch, link,
// form and window.open to localhost refused, and its
// `new WebSocket("ws://localhost:18766/...")` reached the local server on
// every load. This closes that one channel from inside the page, for both
// constructors that open it: WebSocket, and WebSocketStream where the engine
// has it.
//
// THE RULE IS THE REQUEST HANDLER'S, read from the document's side: it
// applies when the TOP document was served over plain HTTP, and it refuses a
// WebSocket to a private address (literal addresses, localhost and names
// under it; the classifier below is a port of privacy.rs is_private_host, and
// the two share private_host_vectors.json) unless that address is the top
// document's own host. HTTPS pages are outside the boundary, as they are for
// every other request.
//
// WHAT IT CANNOT COVER, stated rather than implied: workers (no document
// script runs in a dedicated, shared or service worker), and a same-origin
// frame whose window the page reaches WITHOUT the contentWindow /
// contentDocument accessors hooked below (window[0], frames[0]) in a document
// this script did not run in. The hardware checklist probes the second.
//
// TAMPER RESISTANCE. Everything the guard relies on is captured here, at
// document creation, before any page script exists: the native constructor,
// Reflect, URL and its accessors, the base-URL and ancestor-origin readers.
// Page code runs exactly once inside a check, in the single String(url)
// conversion, and it never receives the native constructor. The classifier
// uses no String.prototype method at all, only indexing and length, which a
// page cannot redefine on a primitive.
//
// ONE CONVERSION, ONE RESOLUTION. The URL is converted once and resolved once
// against the document's own base URL (a <base href> changes it), and the
// native constructor receives that checked absolute string, never the
// original argument: an object whose toString answers differently the second
// time cannot pass the check with one address and connect to another.
//
// No global is added and nothing names the product.
(function () {
  "use strict";
  var NativeWebSocket = window.WebSocket;
  if (typeof NativeWebSocket !== "function") {
    return;
  }

  var construct = Reflect.construct;
  var apply = Reflect.apply;
  var getOwnDescriptor = Reflect.getOwnPropertyDescriptor;
  var defineProperty = Reflect.defineProperty;
  var getPrototypeOf = Reflect.getPrototypeOf;
  var setPrototypeOf = Reflect.setPrototypeOf;
  var NativeURL = URL;
  var NativeString = String;
  var NativeDOMException = DOMException;
  var NativeWeakSet = WeakSet;
  var weakSetHas = WeakSet.prototype.has;
  var weakSetAdd = WeakSet.prototype.add;

  function getterOf(target, name) {
    var d = target ? getOwnDescriptor(target, name) : undefined;
    var get = d ? ownField(d, "get") : undefined;
    return typeof get === "function" ? get : null;
  }
  var urlHref = getterOf(NativeURL.prototype, "href");
  var urlHostname = getterOf(NativeURL.prototype, "hostname");
  var urlProtocol = getterOf(NativeURL.prototype, "protocol");
  var iteratorSymbol = typeof Symbol === "function" ? Symbol.iterator : undefined;
  var nodeBaseURI = getterOf(Node.prototype, "baseURI");
  var documentDefaultView = getterOf(Document.prototype, "defaultView");
  // Location's members are unforgeable: own accessors on each Location
  // object, not on a prototype. A getter from this realm applied to another
  // same-origin realm's Location passes the same interface check.
  var locationAncestorOrigins = getterOf(window.location, "ancestorOrigins");
  var locationOrigin = getterOf(window.location, "origin");
  var locationHref = getterOf(window.location, "href");
  var windowLocation = getterOf(window, "location");
  var windowDocument = getterOf(window, "document");
  var listLength =
    typeof DOMStringList === "function"
      ? getterOf(DOMStringList.prototype, "length")
      : null;
  var listItem =
    typeof DOMStringList === "function" ? DOMStringList.prototype.item : null;

  // --- the classifier: a port of privacy.rs is_private_host ---------------
  // Indexing and length only (see TAMPER RESISTANCE above).

  function lower(s) {
    var out = "";
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      out += c >= "A" && c <= "Z" ? LOWER[c] : c;
    }
    return out;
  }
  var LOWER = {};
  (function () {
    var up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var lo = "abcdefghijklmnopqrstuvwxyz";
    for (var i = 0; i < up.length; i++) {
      LOWER[up[i]] = lo[i];
    }
  })();

  function slice(s, from, to) {
    var out = "";
    for (var i = from; i < to; i++) {
      out += s[i];
    }
    return out;
  }

  function indexOf(s, ch, from) {
    for (var i = from || 0; i < s.length; i++) {
      if (s[i] === ch) {
        return i;
      }
    }
    return -1;
  }

  function endsWith(s, tail) {
    if (tail.length > s.length) {
      return false;
    }
    return slice(s, s.length - tail.length, s.length) === tail;
  }

  // Lists without arrays. Writing parts[i] into an ordinary array runs any
  // setter a page planted on Array.prototype for that index, and one planted
  // for "0" can turn 127.0.0.1 into 8.0.0.1 before the check reads it (final
  // review 5, R-001). These containers have no prototype to plant on.
  var createObject = Object.create;
  function newList() {
    var list = createObject(null);
    list.n = 0;
    list.at = createObject(null);
    return list;
  }
  function append(list, value) {
    list.at[list.n] = value;
    list.n = list.n + 1;
  }

  function splitOn(s, ch) {
    var parts = newList();
    var start = 0;
    for (var i = 0; i <= s.length; i++) {
      if (i === s.length || s[i] === ch) {
        append(parts, slice(s, start, i));
        start = i + 1;
      }
    }
    return parts;
  }

  var DIGIT = { 0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9 };
  var HEX = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 7,
    8: 8,
    9: 9,
    a: 10,
    b: 11,
    c: 12,
    d: 13,
    e: 14,
    f: 15,
  };
  function isOwn(map, key) {
    return getOwnDescriptor(map, key) !== undefined;
  }

  // privacy.rs parse_ipv4: exactly four parts, each 1-3 decimal digits, <= 255.
  // Returns a prototype-less object with keys 0..3, or null.
  function parseIPv4(s) {
    var parts = splitOn(s, ".");
    if (parts.n !== 4) {
      return null;
    }
    var out = createObject(null);
    for (var p = 0; p < 4; p++) {
      var part = parts.at[p];
      if (part.length === 0 || part.length > 3) {
        return null;
      }
      var n = 0;
      for (var i = 0; i < part.length; i++) {
        if (!isOwn(DIGIT, part[i])) {
          return null;
        }
        n = n * 10 + DIGIT[part[i]];
      }
      if (n > 255) {
        return null;
      }
      out[p] = n;
    }
    return out;
  }

  // privacy.rs is_private_ipv4.
  function isPrivateIPv4(o) {
    var a = o[0];
    var b = o[1];
    return (
      a === 127 ||
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a === 0
    );
  }

  function parseHexGroup(g) {
    if (g.length === 0 || g.length > 4) {
      return -1;
    }
    var n = 0;
    for (var i = 0; i < g.length; i++) {
      if (!isOwn(HEX, g[i])) {
        return -1;
      }
      n = n * 16 + HEX[g[i]];
    }
    return n;
  }

  // Eight 16-bit groups (a prototype-less object with keys 0..7), or null.
  // Accepts :: compression and a trailing dotted IPv4, like
  // std::net::Ipv6Addr's parser.
  function parseIPv6(a) {
    var groups = newList();
    var tail = newList();
    var dbl = -1;
    for (var i = 0; i + 1 < a.length; i++) {
      if (a[i] === ":" && a[i + 1] === ":") {
        if (dbl !== -1) {
          return null;
        }
        dbl = i;
      }
    }
    function fill(text, into) {
      if (text.length === 0) {
        return true;
      }
      var parts = splitOn(text, ":");
      for (var k = 0; k < parts.n; k++) {
        var part = parts.at[k];
        if (k === parts.n - 1 && indexOf(part, ".") !== -1) {
          var v4 = parseIPv4(part);
          if (!v4) {
            return false;
          }
          append(into, v4[0] * 256 + v4[1]);
          append(into, v4[2] * 256 + v4[3]);
        } else {
          var n = parseHexGroup(part);
          if (n < 0) {
            return false;
          }
          append(into, n);
        }
      }
      return true;
    }
    if (dbl === -1) {
      if (!fill(a, groups) || groups.n !== 8) {
        return null;
      }
      return groups.at;
    }
    if (
      !fill(slice(a, 0, dbl), groups) ||
      !fill(slice(a, dbl + 2, a.length), tail)
    ) {
      return null;
    }
    var missing = 8 - groups.n - tail.n;
    if (missing < 1) {
      return null;
    }
    for (var z = 0; z < missing; z++) {
      append(groups, 0);
    }
    for (var t = 0; t < tail.n; t++) {
      append(groups, tail.at[t]);
    }
    return groups.at;
  }

  // privacy.rs is_private_ipv6.
  function isPrivateIPv6(addr) {
    var zone = indexOf(addr, "%");
    var a = zone === -1 ? addr : slice(addr, 0, zone);
    var g = parseIPv6(a);
    if (!g) {
      return false;
    }
    var zeroHead =
      g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
    if (zeroHead && g[5] === 0 && g[6] === 0 && (g[7] === 0 || g[7] === 1)) {
      return true; // :: and ::1
    }
    if (zeroHead && (g[5] === 0 || g[5] === 0xffff)) {
      return isPrivateIPv4([g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255]);
    }
    return (g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xff80) === 0xfe80;
  }

  // privacy.rs is_private_host, over a URL host component.
  function normalizeHost(host) {
    var h = lower(NativeString(host));
    var end = h.length;
    while (end > 0 && h[end - 1] === ".") {
      end--;
    }
    return end === h.length ? h : slice(h, 0, end);
  }

  function isPrivateHost(host) {
    var h = normalizeHost(host);
    if (h.length === 0) {
      return false;
    }
    if (h[0] === "[") {
      return (
        h[h.length - 1] === "]" && isPrivateIPv6(slice(h, 1, h.length - 1))
      );
    }
    if (indexOf(h, ":") !== -1) {
      return isPrivateIPv6(h);
    }
    if (h === "localhost" || endsWith(h, ".localhost")) {
      return true;
    }
    var o = parseIPv4(h);
    return o !== null && isPrivateIPv4(o);
  }

  // --- the standing of the document a socket is opened from ---------------

  // The TOP document's origin, read from `win`'s own Location, or null when
  // it cannot be read (which the caller treats as a plain-HTTP page with no
  // address of its own: fail closed).
  function topOrigin(win) {
    try {
      var loc = apply(windowLocation, win, []);
      if (locationAncestorOrigins && listLength && listItem) {
        var list = apply(locationAncestorOrigins, loc, []);
        var n = apply(listLength, list, []);
        if (n > 0) {
          return NativeString(apply(listItem, list, [n - 1]));
        }
      }
      return NativeString(apply(locationOrigin, loc, []));
    } catch (e) {
      return null;
    }
  }

  function refuses(win, targetHost) {
    if (!isPrivateHost(targetHost)) {
      return false;
    }
    var top = topOrigin(win);
    if (top === null) {
      return true;
    }
    // "null" is an OPAQUE origin (a sandboxed document, a CSP sandbox), which
    // says nothing about whether the page came over plain HTTP. Treated as
    // the unreadable case, not as "not HTTP" (final review 5, R-004).
    if (lower(top) === "null") {
      return true;
    }
    if (slice(lower(top), 0, 5) !== "http:") {
      return false; // not a plain-HTTP page: outside the boundary
    }
    var own = null;
    try {
      own = normalizeHost(apply(urlHostname, new NativeURL(top), []));
    } catch (e) {
      own = null;
    }
    return !(
      own !== null &&
      isPrivateHost(own) &&
      own === normalizeHost(targetHost)
    );
  }

  function baseOf(win) {
    try {
      return apply(nodeBaseURI, apply(windowDocument, win, []), []);
    } catch (e) {
      return apply(locationHref, apply(windowLocation, win, []), []);
    }
  }

  // --- the policy channel (1.1.2) ----------------------------------------
  //
  // WHY. A socket to a PUBLIC host was never checked: WebView2 does not show
  // the handshake to the request filter, so the ad and tracker list never
  // applied (measured 2026-11-14 on the 1.1.1 release build: an image and a
  // fetch to a listed tracker were blocked, a socket to it connected). Every
  // socket that the private-address rule above does not refuse now waits
  // for the browser's verdict, asked over window.chrome.webview.
  //
  // WHO MAY ASK. The browser writes a per-webview token into this script's
  // text before registering it (TOKEN below). Page code cannot read an
  // injected script's text or this closure, and every native this channel
  // uses is captured here, before any page script runs, so a page that later
  // replaces postMessage, JSON or a getter never sees the token. Each
  // document draws its own GENERATION; a reply is accepted only for the
  // current generation, a live check id and that request's NONCE.
  //
  // NOT isTrusted. WebView2 hands the browser's messages to page script as
  // a plain Event with isTrusted FALSE and an own `data` property (measured
  // 2026-11-14 on WebView2 155), so a trusted-event test refused every
  // genuine reply. What a page cannot forge is the nonce: drawn here per
  // request, sent only to the browser, echoed in its reply, and used up by
  // this listener (registered before any page script) before a page
  // listener can see it.
  //
  // WHEN THE CHANNEL IS NOT THERE. No token (this script was not registered
  // by the browser that knows the protocol), no chrome.webview, or no
  // "ready" within READY_MS: DEGRADED, which is exactly the pre-1.1.2
  // behaviour (private-address rule only, native socket). After "ready", a
  // check with no verdict within VERDICT_MS is refused.
  var TOKEN = "__PATANYX_WS_TOKEN__";
  var READY_MS = 1500;
  var VERDICT_MS = 5000;
  var tokenSet = TOKEN.length === 32 && TOKEN[0] !== "_";
  var NativeWeakMap = WeakMap;
  var weakMapGet = WeakMap.prototype.get;
  var weakMapSet = WeakMap.prototype.set;
  var weakMapHas = WeakMap.prototype.has;
  var weakMapDelete = WeakMap.prototype["delete"];
  var nativeSetTimeout = window.setTimeout;
  var nativeClearTimeout = window.clearTimeout;
  var NativeUint8Array = Uint8Array;
  var perfObject = window.performance;
  var perfNow = perfObject && typeof perfObject.now === "function" ? perfObject.now : null;
  function clock() {
    return perfNow ? apply(perfNow, perfObject, []) : 0;
  }
  var cryptoObject = window.crypto;
  var getRandomValues = cryptoObject ? cryptoObject.getRandomValues : null;
  var webview = null;
  var webviewPost = null;
  var webviewListen = null;
  try {
    var chromeObject = window.chrome;
    webview = chromeObject ? chromeObject.webview : null;
    if (webview) {
      webviewPost = webview.postMessage;
      webviewListen = webview.addEventListener;
    }
  } catch (e) {
    webview = null;
  }

  function hex128() {
    var bytes = new NativeUint8Array(16);
    apply(getRandomValues, cryptoObject, [bytes]);
    var digits = "0123456789abcdef";
    var out = "";
    for (var i = 0; i < 16; i++) {
      out += digits[bytes[i] >> 4] + digits[bytes[i] & 15];
    }
    return out;
  }

  // "unavailable" | "pending" | "ready" | "degraded"
  var channelState = "unavailable";
  var generation = "";
  var helloNonce = "";
  var nextCheck = 0;
  // Live checks, keyed by id. A plain object with no prototype, indexed by
  // a string id that never names an inherited property.
  var checks = createObject(null);
  // Checks made before "ready", in order. Indexed writes only.
  var waiting = createObject(null);
  var waitingCount = 0;

  function sendToBrowser(op, nonce, id, url, outcome) {
    var m = createObject(null);
    m.k = "pws";
    m.t = TOKEN;
    m.g = generation;
    m.op = op;
    if (nonce !== undefined) {
      m.n = nonce;
    }
    if (id !== undefined) {
      m.id = id;
    }
    if (url !== undefined) {
      m.url = url;
    }
    if (outcome !== undefined) {
      m.outcome = outcome;
    }
    try {
      apply(webviewPost, webview, [m]);
      return true;
    } catch (e) {
      return false;
    }
  }

  // An own data property of a browser-made reply, never an inherited one: a
  // page that put `allow` on Object.prototype must not answer for the
  // browser.
  function ownValue(o, key) {
    var d = getOwnDescriptor(o, key);
    return d === undefined ? undefined : ownField(d, "value");
  }

  // The browser's `data` is an own property of the event. A page may
  // dispatch look-alike events; what they carry is checked against the
  // nonces below, never trusted for its shape.
  function eventData(event) {
    var own = getOwnDescriptor(event, "data");
    if (own === undefined) {
      return undefined;
    }
    var get = ownField(own, "get");
    return typeof get === "function" ? apply(get, event, []) : ownField(own, "value");
  }

  function onBrowserMessage(event) {
    var d;
    var n;
    try {
      d = eventData(event);
      if (!d || typeof d !== "object" || ownValue(d, "k") !== "pws" || ownValue(d, "g") !== generation) {
        return;
      }
      n = ownValue(d, "n");
    } catch (e) {
      return;
    }
    if (typeof n !== "string" || n.length !== 32) {
      return;
    }
    var op = ownValue(d, "op");
    if (op === "ready") {
      if (channelState === "pending" && n === helloNonce) {
        channelState = "ready";
        for (var i = 0; i < waitingCount; i++) {
          sendCheck(waiting[i]);
          waiting[i] = undefined;
        }
        waitingCount = 0;
      }
      return;
    }
    if (op === "verdict") {
      var id = ownValue(d, "id");
      if (typeof id !== "string") {
        return;
      }
      var check = checks[id];
      if (check === undefined || n !== check.nonce) {
        return; // unknown, answered, timed out, or not from the browser
      }
      checks[id] = undefined;
      apply(nativeClearTimeout, window, [check.timer]);
      // A verdict handled after VERDICT_MS (the page's thread was stalled,
      // so the timer could not run first) is refused as a timeout: the
      // browser may already have recorded this socket as blocked.
      if (clock() - check.sentAt >= VERDICT_MS) {
        check.answer(false, "timed-out");
        return;
      }
      check.answer(ownValue(d, "allow") === true, "verdict");
    }
  }

  function sendCheck(check) {
    check.sent = true;
    check.sentAt = clock();
    checks[check.id] = check;
    check.timer = apply(nativeSetTimeout, window, [
      function () {
        if (checks[check.id] === check) {
          checks[check.id] = undefined;
          check.answer(false, "timed-out");
        }
      },
      VERDICT_MS,
    ]);
    check.nonce = hex128();
    if (!sendToBrowser("check", check.nonce, check.id, check.url)) {
      checks[check.id] = undefined;
      apply(nativeClearTimeout, window, [check.timer]);
      // Never synchronously: the page has not had the socket back yet.
      apply(nativeSetTimeout, window, [function () { check.answer(false, "unsent"); }, 0]);
    }
  }

  // Asks the browser about `url`; `answer(allow, how)` is called exactly
  // once. Returns false when the channel is not in use (DEGRADED): the
  // caller then opens the socket natively, as before 1.1.2.
  function askBrowser(url, answer) {
    if (channelState !== "ready" && channelState !== "pending") {
      return false;
    }
    var check = createObject(null);
    check.id = "c" + nextCheck++;
    check.url = url;
    check.answer = answer;
    check.sent = false;
    if (channelState === "ready") {
      sendCheck(check);
    } else {
      waiting[waitingCount++] = check;
    }
    return check.id;
  }

  function startChannel() {
    if (!tokenSet || !webview || typeof webviewPost !== "function" ||
        typeof webviewListen !== "function" || typeof getRandomValues !== "function") {
      return; // "unavailable": the pre-1.1.2 behaviour
    }
    try {
      generation = hex128();
      helloNonce = hex128();
      // A CAPTURE listener, registered before any page script. WebView2 155
      // runs chrome.webview listeners in registration order and ignores the
      // flag (measured 2026-11-14), so this listener is first today. Under
      // standard EventTarget dispatch a page's later capture listener would
      // run before a non-capture one and could take the nonce first; as the
      // first CAPTURE listener this one stays first either way.
      apply(webviewListen, webview, ["message", onBrowserMessage, true]);
    } catch (e) {
      return;
    }
    channelState = "pending";
    if (!sendToBrowser("hello", helloNonce)) {
      channelState = "degraded";
      return;
    }
    apply(nativeSetTimeout, window, [
      function () {
        if (channelState !== "pending") {
          return;
        }
        // No browser answered: DEGRADED. Sockets that waited are opened
        // natively, exactly as they would have been before 1.1.2.
        channelState = "degraded";
        for (var i = 0; i < waitingCount; i++) {
          var check = waiting[i];
          waiting[i] = undefined;
          check.answer(true, "degraded");
        }
        waitingCount = 0;
      },
      READY_MS,
    ]);
  }

  // --- the wrapper ---------------------------------------------------------

  // Property descriptors without a prototype. Reflect.defineProperty reads a
  // descriptor's fields through its prototype chain, so a page that sets
  // Object.prototype.get after this script ran would turn every ordinary
  // `{ value: ... }` into an invalid half-accessor and make the definition
  // throw (final review 6, R-001).
  function dataDescriptor(value, writable, enumerable, configurable) {
    var d = createObject(null);
    d.value = value;
    d.writable = writable;
    d.enumerable = enumerable;
    d.configurable = configurable;
    return d;
  }
  function accessorDescriptor(get, set, enumerable, configurable) {
    var d = createObject(null);
    d.get = get;
    d.set = set;
    d.enumerable = enumerable;
    d.configurable = configurable;
    return d;
  }
  // A field of a descriptor Reflect returned, read without its prototype
  // chain: a data descriptor has no own `get`, and must not borrow a page's.
  function ownField(descriptor, key) {
    var field = getOwnDescriptor(descriptor, key);
    return field === undefined ? undefined : field.value;
  }

  // Every function this script installed. A realm is guarded when what it
  // holds NOW is ours, not because it was seen before: a frame's window keeps
  // its identity across navigations while the realm behind it is replaced.
  var ours = new NativeWeakSet();
  function isOurs(f) {
    return apply(weakSetHas, ours, [f]);
  }

  // Guards a window this realm can reach: every constructor that opens a
  // WebSocket connection (WebSocket, and WebSocketStream wherever the engine
  // exposes it; same handshake, same blind spot in the request handler), and
  // the realm's own frame accessors, so a frame the page makes INSIDE a
  // guarded child is guarded when reached too, however deep (final review 5,
  // R-003). Returns false when a same-origin realm could not be guarded; the
  // accessors then withhold it (final review 6, R-001).
  function guard(win) {
    if (!windowDocument) {
      return false; // cannot tell a same-origin realm from another origin's
    }
    try {
      apply(windowDocument, win, []);
    } catch (e) {
      return true; // cross-origin: that document runs its own copy of this script
    }
    try {
      return (
        wrapConstructor(win, "WebSocket", true) &&
        wrapConstructor(win, "WebSocketStream", false) &&
        guardPeerConnection(win) &&
        hookFrames(win)
      );
    } catch (e) {
      return false;
    }
  }

  // --- the checked socket (1.1.2) ----------------------------------------
  //
  // While the browser decides, the page holds a STAND-IN: a real EventTarget
  // (so addEventListener, removeEventListener and dispatchEvent are native)
  // whose prototype is the realm's WebSocket.prototype (so instanceof,
  // subclassing and prototype.constructor hold). The prototype's accessors
  // and methods are replaced, once per realm, by ones that serve a stand-in
  // from its record and hand everything else to the captured native, so a
  // real WebSocket and the engine's own brand errors are unchanged.
  //
  // On allow, the native socket is constructed with the CHECKED absolute URL
  // and the protocol SNAPSHOT, and its events are re-dispatched on the
  // stand-in. One difference is unavoidable and stated: a re-dispatched
  // event has isTrusted === false. On a refusal, or no verdict in time, the
  // stand-in fails exactly like a refused connection: "error", then "close"
  // with code 1006 and wasClean false. close() before the verdict is final:
  // a later allow never opens a socket.
  var standins = new NativeWeakMap();
  function recordOf(o) {
    return (typeof o === "object" || typeof o === "function") && o !== null
      ? apply(weakMapGet, standins, [o])
      : undefined;
  }

  var SOCKET_ACCESSORS = ["url", "readyState", "bufferedAmount", "extensions", "protocol",
                          "binaryType", "onopen", "onerror", "onclose", "onmessage"];
  var realms = new NativeWeakMap(); // Native constructor -> realm support, or null

  function makeDict() {
    return createObject(null);
  }

  // Replaces WebSocket.prototype's accessors and send/close for one realm,
  // all or nothing: every original is read and checked first, and if any
  // definition fails every one already made is put back (R-126). Returns
  // the realm's support record, or null (the realm then opens sockets
  // natively, as before 1.1.2).
  function realmSupport(win, Native) {
    if (apply(weakMapHas, realms, [Native])) {
      return apply(weakMapGet, realms, [Native]);
    }
    var support = null;
    try {
      support = buildSupport(win, Native);
    } catch (e) {
      support = null;
    }
    apply(weakMapSet, realms, [Native, support]);
    return support;
  }

  function buildSupport(win, Native) {
    var proto = Native.prototype;
    var ET = win.EventTarget;
    if (typeof ET !== "function" || typeof win.Event !== "function" ||
        typeof win.MessageEvent !== "function" || typeof win.CloseEvent !== "function") {
      return null;
    }
    var etProto = ET.prototype;
    var s = makeDict();
    s.ET = ET;
    s.Event = win.Event;
    s.MessageEvent = win.MessageEvent;
    s.CloseEvent = win.CloseEvent;
    s.DOMException = win.DOMException || NativeDOMException;
    s.addListener = etProto.addEventListener;
    s.removeListener = etProto.removeEventListener;
    s.dispatch = etProto.dispatchEvent;
    s.msgData = getterOf(win.MessageEvent.prototype, "data");
    s.msgOrigin = getterOf(win.MessageEvent.prototype, "origin");
    s.msgLastEventId = getterOf(win.MessageEvent.prototype, "lastEventId");
    s.closeCode = getterOf(win.CloseEvent.prototype, "code");
    s.closeReason = getterOf(win.CloseEvent.prototype, "reason");
    s.closeClean = getterOf(win.CloseEvent.prototype, "wasClean");
    s.setTimeout = win.setTimeout;
    if (typeof s.addListener !== "function" || typeof s.removeListener !== "function" ||
        typeof s.dispatch !== "function" || !s.msgData || !s.closeCode) {
      return null;
    }
    // Preflight: every original exists and can be replaced.
    var originals = makeDict();
    var names = SOCKET_ACCESSORS;
    for (var i = 0; i < names.length; i++) {
      var d = getOwnDescriptor(proto, names[i]);
      if (d === undefined || ownField(d, "configurable") !== true || typeof ownField(d, "get") !== "function") {
        return null;
      }
      originals[names[i]] = d;
    }
    var methods = ["send", "close"];
    for (var m = 0; m < methods.length; m++) {
      var md = getOwnDescriptor(proto, methods[m]);
      if (md === undefined || ownField(md, "configurable") !== true || typeof ownField(md, "value") !== "function") {
        return null;
      }
      originals[methods[m]] = md;
    }
    s.get = makeDict();
    s.set = makeDict();
    for (var g = 0; g < names.length; g++) {
      s.get[names[g]] = ownField(originals[names[g]], "get");
      s.set[names[g]] = ownField(originals[names[g]], "set");
    }
    s.send = ownField(originals.send, "value");
    s.close = ownField(originals.close, "value");
    s.CONNECTING = Native.CONNECTING;
    // Build every replacement, then define them; undo on any failure.
    var replacements = makeDict();
    for (var r = 0; r < names.length; r++) {
      replacements[names[r]] = accessorReplacement(names[r], originals[names[r]]);
    }
    replacements.send = dataDescriptor(sendReplacement(s), ownField(originals.send, "writable"),
                                       ownField(originals.send, "enumerable"), true);
    replacements.close = dataDescriptor(closeReplacement(s), ownField(originals.close, "writable"),
                                        ownField(originals.close, "enumerable"), true);
    var done = makeDict();
    var doneCount = 0;
    var keys = makeDict();
    var kc = 0;
    for (var a = 0; a < names.length; a++) {
      keys[kc++] = names[a];
    }
    keys[kc++] = "send";
    keys[kc++] = "close";
    for (var k = 0; k < kc; k++) {
      if (!defineProperty(proto, keys[k], replacements[keys[k]])) {
        for (var u = 0; u < doneCount; u++) {
          defineProperty(proto, done[u], originals[done[u]]);
        }
        return null;
      }
      done[doneCount++] = keys[k];
    }
    return s;
  }

  function accessorReplacement(name, original) {
    var holder = {
      get [name]() {
        var rec = recordOf(this);
        if (rec === undefined) {
          return apply(ownField(original, "get"), this, []);
        }
        return standinGet(rec, name);
      },
      set [name](value) {
        var rec = recordOf(this);
        if (rec === undefined) {
          var setter = ownField(original, "set");
          if (typeof setter !== "function") {
            return; // a read-only attribute: assignment is a no-op, as natively
          }
          apply(setter, this, [value]);
          return;
        }
        standinSet(rec, name, value);
      },
    };
    var own = getOwnDescriptor(holder, name);
    var get = ownField(own, "get");
    var set = typeof ownField(original, "set") === "function" ? ownField(own, "set") : undefined;
    apply(weakSetAdd, ours, [get]);
    if (set) {
      apply(weakSetAdd, ours, [set]);
    }
    return accessorDescriptor(get, set, ownField(original, "enumerable"), true);
  }

  function standinGet(rec, name) {
    var support = rec.support;
    if (rec.native !== null && name !== "onopen" && name !== "onerror" &&
        name !== "onclose" && name !== "onmessage") {
      return apply(support.get[name], rec.native, []);
    }
    if (name === "url") return rec.url;
    if (name === "readyState") return rec.readyState;
    if (name === "bufferedAmount") return 0;
    if (name === "extensions" || name === "protocol") return "";
    if (name === "binaryType") return rec.binaryType;
    var h = rec.handlers[name];
    return h === undefined ? null : h;
  }

  function standinSet(rec, name, value) {
    if (name === "binaryType") {
      var v = NativeString(value); // converted once
      if (v !== "blob" && v !== "arraybuffer") {
        return; // an invalid value is ignored, as natively
      }
      rec.binaryType = v;
      if (rec.native !== null) {
        apply(rec.support.set.binaryType, rec.native, [v]);
      }
      return;
    }
    if (name === "onopen" || name === "onerror" || name === "onclose" || name === "onmessage") {
      var h = typeof value === "function" || (typeof value === "object" && value !== null) ? value : null;
      rec.handlers[name] = h;
      // As natively: a handler attribute's listener joins the list when it
      // is first set, so `addEventListener("open", a); onopen = b` runs a
      // first; setting null takes it out, and setting again re-adds it last.
      var type = slice(name, 2, name.length);
      if (h !== null && !rec.active[name]) {
        rec.active[name] = true;
        apply(rec.support.addListener, rec.socket, [type, rec.handlerListener[name]]);
      } else if (h === null && rec.active[name]) {
        rec.active[name] = false;
        apply(rec.support.removeListener, rec.socket, [type, rec.handlerListener[name]]);
      }
    }
    // url, readyState, bufferedAmount, extensions, protocol: read-only.
  }

  function sendReplacement(support) {
    var holder = {
      send(data) {
        var rec = recordOf(this);
        if (rec === undefined) {
          return apply(support.send, this, arguments);
        }
        if (rec.native !== null && apply(support.get.readyState, rec.native, []) !== support.CONNECTING) {
          return apply(support.send, rec.native, arguments);
        }
        if (rec.readyState >= 2) {
          return undefined; // closing or closed: dropped, as natively
        }
        throw new support.DOMException(
          "Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.",
          "InvalidStateError",
        );
      },
    };
    var f = ownField(getOwnDescriptor(holder, "send"), "value");
    apply(weakSetAdd, ours, [f]);
    return f;
  }

  function closeReplacement(support) {
    var holder = {
      close(code, reason) {
        var rec = recordOf(this);
        if (rec === undefined || rec.native !== null) {
          return apply(support.close, rec === undefined ? this : rec.native, arguments);
        }
        if (code !== undefined) {
          var c = +code;
          c = c !== c ? 0 : c < 0 ? 0 : c > 65535 ? 65535 : c - (c % 1);
          if (c !== 1000 && !(c >= 3000 && c <= 4999)) {
            throw new support.DOMException(
              "Failed to execute 'close' on 'WebSocket': The close code must be either 1000, or between 3000 and 4999. " + c + " is neither.",
              "InvalidAccessError",
            );
          }
        }
        if (reason !== undefined && utf8Length(NativeString(reason)) > 123) {
          throw new support.DOMException(
            "Failed to execute 'close' on 'WebSocket': The close reason must not be greater than 123 UTF-8 bytes.",
            "SyntaxError",
          );
        }
        if (rec.readyState >= 2) {
          return undefined;
        }
        // Closing before the verdict FAILS the connection, as natively for
        // a socket still CONNECTING, and is final (R-128).
        rec.closedByPage = true;
        rec.readyState = 2;
        apply(support.setTimeout, rec.win, [function () { failStandin(rec); }, 0]);
        return undefined;
      },
    };
    var f = ownField(getOwnDescriptor(holder, "close"), "value");
    apply(weakSetAdd, ours, [f]);
    return f;
  }

  function utf8Length(s) {
    var n = 0;
    for (var i = 0; i < s.length; i++) {
      var u = codeUnit(s, i);
      if (u < 0x80) n += 1;
      else if (u < 0x800) n += 2;
      else if (u >= 0xd800 && u <= 0xdbff && i + 1 < s.length) { n += 4; i++; }
      else n += 3;
    }
    return n;
  }
  var nativeCharCodeAt = String.prototype.charCodeAt;
  function codeUnit(s, i) {
    return apply(nativeCharCodeAt, s, [i]);
  }

  function fire(rec, type, init) {
    var support = rec.support;
    var event;
    if (type === "message") {
      event = new support.MessageEvent("message", init);
    } else if (type === "close") {
      event = new support.CloseEvent("close", init);
    } else {
      event = new support.Event(type);
    }
    apply(support.dispatch, rec.socket, [event]);
  }

  function failStandin(rec) {
    if (rec.readyState === 3) {
      return;
    }
    rec.readyState = 3;
    fire(rec, "error");
    var init = makeDict();
    init.code = 1006;
    init.reason = "";
    init.wasClean = false;
    fire(rec, "close", init);
  }

  // Binds the native socket and re-dispatches its events on the stand-in.
  function bindNative(rec, native) {
    var support = rec.support;
    rec.native = native;
    if (rec.binaryType !== "blob") {
      apply(support.set.binaryType, native, [rec.binaryType]);
    }
    apply(support.addListener, native, ["open", function () { fire(rec, "open"); }]);
    apply(support.addListener, native, ["error", function () { fire(rec, "error"); }]);
    apply(support.addListener, native, ["message", function (e) {
      var init = makeDict();
      init.data = apply(support.msgData, e, []);
      init.origin = apply(support.msgOrigin, e, []);
      init.lastEventId = apply(support.msgLastEventId, e, []);
      fire(rec, "message", init);
    }]);
    apply(support.addListener, native, ["close", function (e) {
      var init = makeDict();
      init.code = apply(support.closeCode, e, []);
      init.reason = apply(support.closeReason, e, []);
      init.wasClean = apply(support.closeClean, e, []);
      fire(rec, "close", init);
    }]);
  }

  // Returns a stand-in, or undefined when the channel is not in use (the
  // caller then constructs natively, as before 1.1.2).
  function checkedSocket(win, Native, newTarget, href, args) {
    var support = realmSupport(win, Native);
    if (!support) {
      return undefined;
    }
    var rec = makeDict();
    rec.support = support;
    rec.win = win;
    rec.url = socketUrl(href);
    rec.readyState = 0;
    rec.binaryType = "blob";
    rec.native = null;
    rec.closedByPage = false;
    rec.handlers = makeDict();
    rec.active = makeDict();
    rec.handlerListener = makeDict();
    var socket = construct(support.ET, [], newTarget);
    rec.socket = socket;
    var answered = false;
    var asked = askBrowser(href, function (allow, how) {
      if (answered) {
        return;
      }
      answered = true;
      if (rec.closedByPage) {
        if (allow && how === "verdict") {
          sendToBrowser("ack", undefined, rec.checkId, undefined, "cancelled");
        }
        return;
      }
      if (!allow) {
        if (how === "timed-out") {
          sendToBrowser("ack", undefined, rec.checkId, undefined, "timed-out");
        }
        failStandin(rec);
        return;
      }
      var native;
      try {
        native = construct(Native, args, Native);
      } catch (e) {
        if (how === "verdict") {
          sendToBrowser("ack", undefined, rec.checkId, undefined, "failed");
        }
        failStandin(rec);
        return;
      }
      if (how === "verdict") {
        sendToBrowser("ack", undefined, rec.checkId, undefined, "constructed");
      }
      bindNative(rec, native);
    });
    if (asked === false) {
      return undefined;
    }
    rec.checkId = asked;
    apply(weakMapSet, standins, [socket, rec]);
    // Handler attributes: one listener per type, registered only when the
    // attribute is first set (standinSet).
    var types = ["open", "error", "close", "message"];
    for (var i = 0; i < 4; i++) {
      (function (type) {
        rec.handlerListener["on" + type] = function (event) {
          var h = rec.handlers["on" + type];
          if (typeof h === "function") {
            apply(h, socket, [event]);
          }
        };
      })(types[i]);
    }
    return socket;
  }

  // The URL a native WebSocket reports: http(s) is shown as ws(s).
  function socketUrl(href) {
    if (slice(href, 0, 8) === "https://") return "wss://" + slice(href, 8, href.length);
    if (slice(href, 0, 7) === "http://") return "ws://" + slice(href, 7, href.length);
    return href;
  }

  // --- validation the stand-in must do itself (1.1.2) ---------------------
  //
  // A native constructor throws these synchronously; a stand-in is returned
  // before any native exists, so it throws them here, with the engine's
  // names and messages (pinned against the engine by the gate).

  function snapshotList(values) {
    var list = [];
    for (var i = 0; i < values.count; i++) {
      // defineProperty, not assignment: an index setter on Array.prototype
      // must not see the values.
      defineProperty(list, NativeString(i), dataDescriptor(values[i], true, true, true));
    }
    return list;
  }

  // (DOMString or sequence<DOMString>), converted ONCE (R-114): a string, or
  // one pass of the iterator with each element converted once.
  function snapshotProtocols(value) {
    var values = createObject(null);
    values.count = 0;
    var method = (typeof value === "object" || typeof value === "function") && value !== null &&
      iteratorSymbol !== undefined ? value[iteratorSymbol] : undefined;
    if (typeof method === "function") {
      var iterator = apply(method, value, []);
      var next = iterator.next;
      for (;;) {
        var step = apply(next, iterator, []);
        if (step.done) {
          break;
        }
        values[values.count++] = NativeString(step.value);
      }
    } else {
      values[values.count++] = NativeString(value);
    }
    return snapshotList(values);
  }

  function isTokenChar(c) {
    return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") ||
      c === "!" || c === "#" || c === "$" || c === "%" || c === "&" || c === "'" || c === "*" ||
      c === "+" || c === "-" || c === "." || c === "^" || c === "_" || c === "`" || c === "|" || c === "~";
  }

  function validateForStandin(parsed, protocols, name) {
    var scheme = apply(urlProtocol, parsed, []);
    if (scheme !== "ws:" && scheme !== "wss:" && scheme !== "http:" && scheme !== "https:") {
      throw new NativeDOMException(
        "Failed to construct '" + name + "': The URL's scheme must be either 'http', 'https', 'ws', or 'wss'. '" +
          slice(scheme, 0, scheme.length - 1) + "' is not allowed.",
        "SyntaxError",
      );
    }
    // Any fragment, an EMPTY one included ("wss://host/#"): URL.hash reads
    // "" for both, so the serialized URL is what tells them apart.
    var href = apply(urlHref, parsed, []);
    var mark = indexOf(href, "#");
    if (mark !== -1) {
      var fragment = slice(href, mark + 1, href.length);
      throw new NativeDOMException(
        "Failed to construct '" + name + "': The URL contains a fragment identifier ('" + fragment +
          "'). Fragment identifiers are not allowed in WebSocket URLs.",
        "SyntaxError",
      );
    }
    if (protocols === undefined) {
      return;
    }
    var seen = createObject(null);
    for (var i = 0; i < protocols.length; i++) {
      var p = protocols[i];
      var ok = p.length > 0;
      for (var j = 0; ok && j < p.length; j++) {
        ok = isTokenChar(p[j]);
      }
      if (!ok) {
        throw new NativeDOMException(
          "Failed to construct '" + name + "': The subprotocol '" + p + "' is invalid.",
          "SyntaxError",
        );
      }
      if (seen["$" + p] === true) {
        throw new NativeDOMException(
          "Failed to construct '" + name + "': The subprotocol '" + p + "' is duplicated.",
          "SyntaxError",
        );
      }
      seen["$" + p] = true;
    }
  }

  function channelInUse() {
    return channelState === "ready" || channelState === "pending";
  }

  // WebSocketStream's options, read ONCE: { protocols, signal }.
  function snapshotStreamOptions(options) {
    if (options === undefined || options === null) {
      return undefined;
    }
    var o = createObject(null);
    var protocols = options.protocols;
    if (protocols !== undefined) {
      o.protocols = snapshotProtocols(protocols);
    }
    var signal = options.signal;
    if (signal !== undefined) {
      o.signal = signal;
    }
    return o;
  }

  // --- the checked stream (1.1.2) ------------------------------------------
  //
  // WebSocketStream opens the same handshake and is as blind to the request
  // filter, so it waits for the same verdict. Its stand-in carries the url
  // and the two promises; on allow they follow the native stream's, on a
  // refusal both reject as for a refused connection.
  var streamRealms = new NativeWeakMap();

  function streamSupport(win, Native) {
    if (apply(weakMapHas, streamRealms, [Native])) {
      return apply(weakMapGet, streamRealms, [Native]);
    }
    var support = null;
    try {
      support = buildStreamSupport(win, Native);
    } catch (e) {
      support = null;
    }
    apply(weakMapSet, streamRealms, [Native, support]);
    return support;
  }

  function buildStreamSupport(win, Native) {
    var proto = Native.prototype;
    if (typeof win.Promise !== "function") {
      return null;
    }
    var s = makeDict();
    s.Promise = win.Promise;
    s.then = win.Promise.prototype.then;
    s.DOMException = win.DOMException || NativeDOMException;
    s.WebSocketError = typeof win.WebSocketError === "function" ? win.WebSocketError : null;
    var getters = ["url", "opened", "closed"];
    var originals = makeDict();
    for (var i = 0; i < 3; i++) {
      var d = getOwnDescriptor(proto, getters[i]);
      if (d === undefined || ownField(d, "configurable") !== true || typeof ownField(d, "get") !== "function") {
        return null;
      }
      originals[getters[i]] = d;
    }
    var cd = getOwnDescriptor(proto, "close");
    if (cd === undefined || ownField(cd, "configurable") !== true || typeof ownField(cd, "value") !== "function") {
      return null;
    }
    s.get = makeDict();
    for (var g = 0; g < 3; g++) {
      s.get[getters[g]] = ownField(originals[getters[g]], "get");
    }
    s.close = ownField(cd, "value");
    var replacements = makeDict();
    for (var r = 0; r < 3; r++) {
      replacements[getters[r]] = streamGetter(getters[r], s);
    }
    var closeHolder = {
      close(closeInfo) {
        var rec = recordOf(this);
        if (rec === undefined || rec.native !== null) {
          return apply(s.close, rec === undefined ? this : rec.native, arguments);
        }
        if (!rec.settled) {
          rec.closedByPage = true;
          rejectStream(rec);
        }
        return undefined;
      },
    };
    var closeFn = ownField(getOwnDescriptor(closeHolder, "close"), "value");
    apply(weakSetAdd, ours, [closeFn]);
    replacements.close = dataDescriptor(closeFn, ownField(cd, "writable"), ownField(cd, "enumerable"), true);
    originals.close = cd;
    var keys = ["url", "opened", "closed", "close"];
    var done = 0;
    for (var k = 0; k < 4; k++) {
      if (!defineProperty(proto, keys[k], replacements[keys[k]])) {
        for (var u = 0; u < done; u++) {
          defineProperty(proto, keys[u], originals[keys[u]]);
        }
        return null;
      }
      done++;
    }
    return s;
  }

  function streamGetter(name, support) {
    var holder = {
      get [name]() {
        var rec = recordOf(this);
        if (rec === undefined) {
          return apply(support.get[name], this, []);
        }
        if (name === "url") return rec.url;
        return name === "opened" ? rec.opened : rec.closedPromise;
      },
    };
    var f = ownField(getOwnDescriptor(holder, name), "get");
    apply(weakSetAdd, ours, [f]);
    return accessorDescriptor(f, undefined, false, true);
  }

  function rejectStream(rec) {
    if (rec.settled) {
      return;
    }
    rec.settled = true;
    var support = rec.support;
    var error;
    if (support.WebSocketError) {
      var init = makeDict();
      init.closeCode = 1006;
      error = new support.WebSocketError("WebSocket connection failed", init);
    } else {
      error = new support.DOMException("WebSocket connection failed", "NetworkError");
    }
    rec.rejectOpened(error);
    rec.rejectClosed(error);
  }

  function checkedStream(win, Native, newTarget, href, args) {
    var support = streamSupport(win, Native);
    if (!support) {
      return undefined;
    }
    var proto = newTarget.prototype;
    if ((typeof proto !== "object" && typeof proto !== "function") || proto === null) {
      proto = Native.prototype;
    }
    var stream = createObject(proto);
    var rec = makeDict();
    rec.support = support;
    rec.url = socketUrl(href);
    rec.native = null;
    rec.settled = false;
    rec.closedByPage = false;
    rec.opened = new support.Promise(function (resolve, reject) {
      rec.resolveOpened = resolve;
      rec.rejectOpened = reject;
    });
    rec.closedPromise = new support.Promise(function (resolve, reject) {
      rec.resolveClosed = resolve;
      rec.rejectClosed = reject;
    });
    // Marked handled, so a refusal the page never awaits does not add an
    // unhandled-rejection report; a page's own handlers still run.
    var ignore = function () {};
    apply(support.then, rec.opened, [undefined, ignore]);
    apply(support.then, rec.closedPromise, [undefined, ignore]);
    var asked = askBrowser(href, function (allow, how) {
      if (rec.closedByPage) {
        if (allow && how === "verdict") {
          sendToBrowser("ack", undefined, rec.checkId, undefined, "cancelled");
        }
        return;
      }
      if (!allow) {
        if (how === "timed-out") {
          sendToBrowser("ack", undefined, rec.checkId, undefined, "timed-out");
        }
        rejectStream(rec);
        return;
      }
      var native;
      try {
        native = construct(Native, args, Native);
      } catch (e) {
        if (how === "verdict") {
          sendToBrowser("ack", undefined, rec.checkId, undefined, "failed");
        }
        rejectStream(rec);
        return;
      }
      if (how === "verdict") {
        sendToBrowser("ack", undefined, rec.checkId, undefined, "constructed");
      }
      rec.native = native;
      rec.settled = true;
      apply(support.then, apply(support.get.opened, native, []), [rec.resolveOpened, rec.rejectOpened]);
      apply(support.then, apply(support.get.closed, native, []), [rec.resolveClosed, rec.rejectClosed]);
    });
    if (asked === false) {
      return undefined;
    }
    rec.checkId = asked;
    apply(weakMapSet, standins, [stream, rec]);
    return stream;
  }

  function wrapConstructor(win, name, hasConstants) {
    var Native = win[name];
    if (typeof Native !== "function") {
      return true; // this engine has no such constructor
    }
    if (isOurs(Native)) {
      return true;
    }
    var Wrapped = function (url, second) {
      if (new.target === undefined) {
        return apply(Native, this, arguments); // the engine's own TypeError
      }
      if (arguments.length === 0) {
        return construct(Native, [], new.target); // the engine's own TypeError
      }
      var text = NativeString(url);
      var parsed;
      try {
        parsed = new NativeURL(text, baseOf(win));
      } catch (e) {
        throw new NativeDOMException(
          "Failed to construct '" + name + "': The URL '" + text + "' is invalid.",
          "SyntaxError",
        );
      }
      if (refuses(win, apply(urlHostname, parsed, []))) {
        throw new NativeDOMException(
          "Failed to construct '" + name + "': A page served over plain HTTP may not connect to the local network.",
          "SecurityError",
        );
      }
      var href = apply(urlHref, parsed, []);
      if (name === "WebSocket") {
        var protocols =
          arguments.length > 1 && second !== undefined ? snapshotProtocols(second) : undefined;
        var args = protocols === undefined ? [href] : [href, protocols];
        if (channelInUse()) {
          validateForStandin(parsed, protocols, name);
          var socket = checkedSocket(win, Native, new.target, href, args);
          if (socket !== undefined) {
            return socket;
          }
        }
        return construct(Native, args, new.target);
      }
      var options = arguments.length > 1 ? snapshotStreamOptions(second) : undefined;
      var streamArgs = options === undefined ? [href] : [href, options];
      if (channelInUse()) {
        validateForStandin(parsed, options === undefined ? undefined : options.protocols, name);
        var stream = checkedStream(win, Native, new.target, href, streamArgs);
        if (stream !== undefined) {
          return stream;
        }
      }
      return construct(Native, streamArgs, new.target);
    };
    defineProperty(Wrapped, "name", dataDescriptor(name, false, false, true));
    defineProperty(Wrapped, "length", dataDescriptor(1, false, false, true));
    Wrapped.prototype = Native.prototype;
    // The prototype's own `constructor` is the other road to the native
    // constructor. If it cannot be replaced, the realm is not guarded
    // (final review 7, R-002).
    if (
      !defineProperty(
        Native.prototype,
        "constructor",
        dataDescriptor(Wrapped, true, false, true),
      )
    ) {
      return false;
    }
    if (hasConstants) {
      // WebIDL constants: read-only, enumerable, permanent.
      defineProperty(Wrapped, "CONNECTING", dataDescriptor(Native.CONNECTING, false, true, false));
      defineProperty(Wrapped, "OPEN", dataDescriptor(Native.OPEN, false, true, false));
      defineProperty(Wrapped, "CLOSING", dataDescriptor(Native.CLOSING, false, true, false));
      defineProperty(Wrapped, "CLOSED", dataDescriptor(Native.CLOSED, false, true, false));
    }
    setPrototypeOf(Wrapped, getPrototypeOf(Native));
    apply(weakSetAdd, ours, [Wrapped]);
    return defineProperty(win, name, dataDescriptor(Wrapped, true, false, true));
  }

  // A same-origin child realm (a script-made about:blank iframe) may never
  // run this script, and its WebSocket would be untouched. Guard it the
  // moment the page reaches into it through the accessors, and withhold it if
  // it cannot be guarded.
  function hookChildAccess(proto, name, toWindow) {
    var d = proto ? getOwnDescriptor(proto, name) : undefined;
    if (d === undefined) {
      return true; // this element has no such accessor
    }
    var original = ownField(d, "get");
    if (typeof original !== "function") {
      return false;
    }
    if (isOurs(original)) {
      return true;
    }
    var hooked = {
      get [name]() {
        var value = apply(original, this, []);
        if (value) {
          var w = null;
          try {
            w = toWindow(value);
          } catch (e) {
            w = null; // detached: nothing to reach through it
          }
          if (w && !guard(w)) {
            return null;
          }
        }
        return value;
      },
    };
    var getter = ownField(getOwnDescriptor(hooked, name), "get");
    apply(weakSetAdd, ours, [getter]);
    return defineProperty(
      proto,
      name,
      accessorDescriptor(
        getter,
        ownField(d, "set"),
        ownField(d, "enumerable"),
        ownField(d, "configurable"),
      ),
    );
  }
  function asWindow(w) {
    return w;
  }
  function documentWindow(doc) {
    return apply(documentDefaultView, doc, []);
  }

  function hookFrames(win) {
    return (
      hookFrameKind(win, "HTMLIFrameElement") &&
      hookFrameKind(win, "HTMLFrameElement") &&
      hookFrameKind(win, "HTMLObjectElement")
    );
  }
  function hookFrameKind(win, kind) {
    var ctor = win[kind];
    if (typeof ctor !== "function") {
      return true;
    }
    var proto = ctor.prototype;
    return (
      hookChildAccess(proto, "contentWindow", asWindow) &&
      hookChildAccess(proto, "contentDocument", documentWindow)
    );
  }

  // --- WebRTC ICE servers (SecScan S-97924597b810, 2026-11-24) -----------
  //
  // A STUN or TURN server is a connection the page names, and the request
  // handler never sees it. Measured in Chromium on 2026-11-24 with this script
  // injected as WebView2 injects it: a plain-HTTP page reached a local TCP
  // port through "turn:127.0.0.1:PORT?transport=tcp", given to the
  // constructor or to setConfiguration. Every ICE server address now meets
  // the same rule as a socket. The configuration is read ONCE into a copy,
  // and the native receives the copy: a getter that answers differently the
  // second time cannot pass the check with one address and use another.
  //
  // NOT covered, stated rather than implied: a REMOTE candidate the page
  // supplies (in a description or through addIceCandidate) is still checked
  // by the engine alone, and a server NAME that resolves to a private address
  // is not one this classifier can see, exactly as for sockets.
  // Every RTCConfiguration and RTCIceServer member an engine reads, so a
  // checked copy loses none of them (security review 2026-11-24, R-004:
  // encodedInsertableStreams holds an encrypted call's media until its
  // transforms are ready, and the singular "url" is still accepted).
  var ICE_KEYS = ["alwaysNegotiateDataChannels", "bundlePolicy", "certificates", "encodedInsertableStreams", "iceCandidatePoolSize",
    "iceTransportPolicy", "peerIdentity", "rtcpMuxPolicy", "sdpSemantics"];
  var ICE_SERVER_KEYS = ["username", "credential", "credentialType"];
  var NativeTypeError = TypeError;

  // Whether this page is inside the boundary at all: a plain-HTTP top, or
  // one whose standing cannot be read, exactly as refuses() decides.
  function boundaryApplies(win) {
    var top = topOrigin(win);
    if (top === null || lower(top) === "null") {
      return true;
    }
    return slice(lower(top), 0, 5) === "http:";
  }

  function refuseIceAddresses(win, addresses, name) {
    for (var j = 0; j < addresses.length; j++) {
      var host = canonicalHost(iceHost(addresses[j]));
      // An address this cannot read is refused wherever a readable one
      // to this machine would be: "localhost" stands in for it.
      if (refuses(win, host === null ? "localhost" : host)) {
        throw new NativeDOMException(
          "Failed to construct '" + name + "': A page served over plain HTTP may not connect to the local network.",
          "SecurityError",
        );
      }
    }
  }

  // The host of a stun:, stuns:, turn: or turns: URI (RFC 7064, RFC 7065),
  // or null when it is not one this can read.
  function iceHost(url) {
    var colon = indexOf(url, ":", 0);
    if (colon < 0) {
      return null;
    }
    var scheme = lower(slice(url, 0, colon));
    if (scheme !== "stun" && scheme !== "stuns" && scheme !== "turn" && scheme !== "turns") {
      return null;
    }
    var rest = slice(url, colon + 1, url.length);
    var query = indexOf(rest, "?", 0);
    if (query >= 0) {
      rest = slice(rest, 0, query);
    }
    if (rest.length > 0 && rest[0] === "[") {
      var close = indexOf(rest, "]", 0);
      return close < 0 ? null : slice(rest, 0, close + 1);
    }
    var port = indexOf(rest, ":", 0);
    if (port >= 0) {
      if (indexOf(rest, ":", port + 1) >= 0) {
        return null;
      }
      rest = slice(rest, 0, port);
    }
    return rest.length > 0 ? rest : null;
  }

  // The host as the engine resolves it: "127.1" and "2130706433" are
  // 127.0.0.1 to a URL parser, and the classifier reads only canonical forms
  // (compliance audit 2026-11-24, A3). Null when it is not a host.
  function canonicalHost(host) {
    if (host === null) {
      return null;
    }
    try {
      return apply(urlHostname, new NativeURL("http://" + host + "/"), []);
    } catch (e) {
      return null;
    }
  }

  // One pass of an iterable, values kept as they are; undefined when the
  // value is not iterable (the engine then throws its own TypeError).
  function snapshotSequence(value) {
    var method = (typeof value === "object" || typeof value === "function") && value !== null &&
      iteratorSymbol !== undefined ? value[iteratorSymbol] : undefined;
    if (typeof method !== "function") {
      return undefined;
    }
    var values = createObject(null);
    values.count = 0;
    var iterator = apply(method, value, []);
    var next = iterator.next;
    for (;;) {
      var step = apply(next, iterator, []);
      if (step.done) {
        break;
      }
      values[values.count++] = step.value;
    }
    return snapshotList(values);
  }

  function setField(target, key, value) {
    defineProperty(target, key, dataDescriptor(value, true, true, true));
  }

  function checkedIceConfig(win, config, name) {
    if (config === undefined || config === null || (typeof config !== "object" && typeof config !== "function")) {
      return config; // nothing to check, or the engine's own TypeError
    }
    // Outside the boundary nothing is refused, so the engine gets the page's
    // own configuration, untouched.
    if (!boundaryApplies(win)) {
      return config;
    }
    var copy = createObject(null);
    for (var k = 0; k < ICE_KEYS.length; k++) {
      var v = config[ICE_KEYS[k]];
      if (v !== undefined) {
        setField(copy, ICE_KEYS[k], v);
      }
    }
    var servers = config.iceServers;
    if (servers === undefined) {
      return copy;
    }
    var list = snapshotSequence(servers);
    if (list === undefined) {
      // Refused here, never forwarded: the engine would ask the object for
      // its iterator again, and a getter could then hand it servers this
      // never saw (security review 2026-11-24, R-001).
      throw new NativeTypeError(
        "Failed to construct '" + name + "': The provided value cannot be converted to a sequence.",
      );
    }
    var checked = [];
    for (var i = 0; i < list.length; i++) {
      var server = list[i];
      if (server === null || (typeof server !== "object" && typeof server !== "function")) {
        setField(checked, NativeString(i), server);
        continue;
      }
      var entry = createObject(null);
      var urls = server.urls;
      var legacy = server.url;
      if (urls !== undefined) {
        var addresses = snapshotProtocols(urls);
        refuseIceAddresses(win, addresses, name);
        setField(entry, "urls", addresses);
      }
      if (legacy !== undefined) {
        var single = NativeString(legacy);
        refuseIceAddresses(win, [single], name);
        setField(entry, "url", single);
      }
      for (var f = 0; f < ICE_SERVER_KEYS.length; f++) {
        var field = server[ICE_SERVER_KEYS[f]];
        if (field !== undefined) {
          setField(entry, ICE_SERVER_KEYS[f], field);
        }
      }
      setField(checked, NativeString(i), entry);
    }
    setField(copy, "iceServers", checked);
    return copy;
  }

  function guardPeerConnection(win) {
    var Native = win.RTCPeerConnection;
    var alias = win.webkitRTCPeerConnection;
    if (!wrapPeerConnection(win, "RTCPeerConnection")) {
      return false;
    }
    // The legacy name is the SAME constructor where an engine still has it:
    // it gets the same wrapper, so prototype.constructor stays the
    // RTCPeerConnection the page sees, and the native is not reachable
    // through the old name.
    if (typeof alias === "function" && alias === Native) {
      return defineProperty(win, "webkitRTCPeerConnection", dataDescriptor(win.RTCPeerConnection, true, false, true));
    }
    return wrapPeerConnection(win, "webkitRTCPeerConnection");
  }

  function wrapPeerConnection(win, name) {
    var Native = win[name];
    if (typeof Native !== "function") {
      return true; // this engine has no such constructor
    }
    if (isOurs(Native)) {
      return true;
    }
    var proto = Native.prototype;
    var d = getOwnDescriptor(proto, "setConfiguration");
    var original = d === undefined ? undefined : ownField(d, "value");
    if (typeof original === "function" && !isOurs(original)) {
      var hooked = {
        setConfiguration(config) {
          if (arguments.length === 0) {
            return apply(original, this, []); // the engine's own TypeError
          }
          return apply(original, this, [checkedIceConfig(win, config, name)]);
        },
      }.setConfiguration;
      apply(weakSetAdd, ours, [hooked]);
      if (
        !defineProperty(
          proto,
          "setConfiguration",
          dataDescriptor(hooked, ownField(d, "writable"), ownField(d, "enumerable"), ownField(d, "configurable")),
        )
      ) {
        return false;
      }
    }
    var Wrapped = function (config) {
      if (new.target === undefined) {
        return apply(Native, this, arguments); // the engine's own TypeError
      }
      var args = [];
      for (var a = 0; a < arguments.length; a++) {
        setField(args, NativeString(a), a === 0 ? checkedIceConfig(win, config, name) : arguments[a]);
      }
      return construct(Native, args, new.target);
    };
    defineProperty(Wrapped, "name", dataDescriptor(name, false, false, true));
    defineProperty(Wrapped, "length", dataDescriptor(0, false, false, true));
    Wrapped.prototype = proto;
    if (!defineProperty(proto, "constructor", dataDescriptor(Wrapped, true, false, true))) {
      return false;
    }
    var generate = getOwnDescriptor(Native, "generateCertificate");
    if (generate !== undefined) {
      defineProperty(Wrapped, "generateCertificate", generate);
    }
    setPrototypeOf(Wrapped, getPrototypeOf(Native));
    apply(weakSetAdd, ours, [Wrapped]);
    return defineProperty(win, name, dataDescriptor(Wrapped, true, false, true));
  }

  startChannel();
  guard(window);
})();
