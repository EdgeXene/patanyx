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
        hookFrames(win)
      );
    } catch (e) {
      return false;
    }
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
      return construct(
        Native,
        arguments.length > 1 ? [href, second] : [href],
        new.target,
      );
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

  guard(window);
})();
