// What local_network_guard.js does with a socket to a PUBLIC host (1.1.2),
// exercised end to end against the REAL script in fresh vm realms.
//
// WHY THIS EXISTS. WebView2 never shows a WebSocket handshake to the request
// filter, so before 1.1.2 a page could open a socket to a listed tracker
// (measured 2026-11-14 on the 1.1.1 release build). The guard now asks the
// browser over chrome.webview before every such socket and hands the page a
// stand-in until the verdict. This gate pins that contract:
//
//   channel     hello carries the token, a generation and a nonce; every
//               check carries its own nonce; checks wait for
//               "ready"; no "ready" in time means DEGRADED (the pre-1.1.2
//               behaviour); no token means the channel is never used
//   verdicts    allow opens the native socket with the checked URL and the
//               protocol snapshot, acks "constructed", re-dispatches events;
//               deny fails the stand-in (error, close 1006) with no native
//               socket; no verdict in time denies and acks "timed-out"
//   handlers    an on* attribute's listener joins the list when first set,
//               as natively; null takes it out
//   forgery     a page CAPTURE listener registered later cannot take a live
//               nonce first (the stub dispatches by the standard, capture
//               first); a reply without the request's nonce, a replayed nonce, a wrong
//               generation, an unknown id, and an "allow" inherited from
//               Object.prototype are all ignored; a page that replaces
//               chrome.webview.postMessage after the script ran never receives
//               the token. Host replies arrive here as WebView2 delivers them
//               (measured 2026-11-14, WebView2 155): a plain Event, isTrusted
//               false, `data` an own property, so a page's forgery has exactly
//               the shape of a genuine reply and only the nonce tells them apart
//   stand-in    instanceof, subclassing, send while CONNECTING, close
//               validation, close before the verdict is final (a later allow
//               opens nothing and acks "cancelled"), the native getters'
//               brand errors are unchanged
//   one-shot    the protocols argument is read once; invalid and duplicated
//               protocols, a bad scheme and a fragment throw SyntaxError
//   install     a prototype that cannot be patched completely is left exactly
//               as it was, and sockets open natively
//   stream      WebSocketStream waits for the same verdict
//
// NOT covered here, honestly: what the real engine does with re-dispatched
// events (isTrusted is false on them), message routing between frames, and
// the browser side of the protocol. Those are the VM run and the Rust tests.
//
// Run: node scripts/websocket-check-gate.js  (or via scripts/chrome-js-gate.sh)
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const RAW = fs.readFileSync(
  path.join(ROOT, "crates/app/src/content_scripts/local_network_guard.js"),
  "utf8",
);
const TOKEN = "0123456789abcdef0123456789abcdef";
if (RAW.split("__PATANYX_WS_TOKEN__").length !== 2) {
  console.error("FAIL: the guard must carry exactly one token placeholder");
  process.exit(1);
}
const SCRIPT = RAW.replace("__PATANYX_WS_TOKEN__", TOKEN);

let failures = 0;
let checks = 0;
function check(cond, what) {
  checks++;
  if (!cond) {
    failures++;
    console.error("FAIL: " + what);
  }
}

const SETUP = `
  var window = globalThis;
  var __trusted = new WeakSet();
  function __isTrusted() { return __trusted.has(this); }

  var EventTarget = class EventTarget {
    constructor() { Object.defineProperty(this, "__l", { value: new Map() }); }
    addEventListener(type, fn) {
      if (!this || !this.__l) { throw new TypeError("Illegal invocation"); }
      var list = this.__l.get(type) || [];
      if (list.indexOf(fn) < 0) { list.push(fn); }
      this.__l.set(type, list);
    }
    removeEventListener(type, fn) {
      var list = (this.__l && this.__l.get(type)) || [];
      var i = list.indexOf(fn);
      if (i >= 0) { list.splice(i, 1); }
    }
    dispatchEvent(event) {
      if (!this || !this.__l) { throw new TypeError("Illegal invocation"); }
      var list = (this.__l.get(event.type) || []).slice();
      for (var i = 0; i < list.length; i++) { list[i].call(this, event); }
      return true;
    }
  };
  var Event = class Event {
    constructor(type) {
      Object.defineProperty(this, "isTrusted", { get: __isTrusted, enumerable: true, configurable: false });
      this.__type = String(type);
    }
    get type() { return this.__type; }
    stopImmediatePropagation() { this.__stopped = true; }
  };
  var MessageEvent = class MessageEvent extends Event {
    constructor(type, init) {
      super(type); init = init || {};
      this.__data = init.data; this.__origin = init.origin || ""; this.__lastEventId = init.lastEventId || "";
    }
    get data() { return this.__data; }
    get origin() { return this.__origin; }
    get lastEventId() { return this.__lastEventId; }
  };
  var CloseEvent = class CloseEvent extends Event {
    constructor(type, init) {
      super(type); init = init || {};
      this.__code = init.code || 0; this.__reason = init.reason || ""; this.__wasClean = !!init.wasClean;
    }
    get code() { return this.__code; }
    get reason() { return this.__reason; }
    get wasClean() { return this.__wasClean; }
  };

  // Timers the test drives.
  var __timers = [];
  var __now = 0;
  var __timerId = 0;
  function setTimeout(fn, ms) { var id = ++__timerId; __timers.push({ id: id, at: __now + (ms || 0), fn: fn }); return id; }
  function clearTimeout(id) { __timers = __timers.filter(function (t) { return t.id !== id; }); }
  function __tick(ms) {
    var end = __now + ms;
    for (;;) {
      __timers.sort(function (a, b) { return a.at - b.at || a.id - b.id; });
      var next = __timers[0];
      if (!next || next.at > end) { break; }
      __timers.shift(); __now = next.at; next.fn();
    }
    __now = end;
  }
  var performance = { now: function () { return __now; } };
  var crypto = { getRandomValues: function (a) { for (var i = 0; i < a.length; i++) { a[i] = (Math.random() * 256) | 0; } return a; } };

  // The engine's WebSocket: WebIDL-shaped accessors on the prototype that
  // brand-check their receiver.
  var __made = [];
  var __sockets = new WeakMap();
  function __state(o) { var s = __sockets.get(o); if (!s) { throw new TypeError("Illegal invocation"); } return s; }
  var WebSocket = class WebSocket extends EventTarget {
    constructor(url, protocols) {
      if (arguments.length === 0) { throw new TypeError("Failed to construct 'WebSocket': 1 argument required, but only 0 present."); }
      super();
      var s = { url: String(url), protocols: protocols, readyState: 0, binaryType: "blob", sent: [], handlers: {} };
      __sockets.set(this, s);
      __made.push({ url: String(url), protocols: protocols, socket: this });
    }
  };
  ["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach(function (n, i) {
    Object.defineProperty(WebSocket, n, { value: i, enumerable: true });
    Object.defineProperty(WebSocket.prototype, n, { value: i, enumerable: true });
  });
  ["url", "readyState", "bufferedAmount", "extensions", "protocol"].forEach(function (n) {
    Object.defineProperty(WebSocket.prototype, n, { get: function () {
      var s = __state(this); return n === "bufferedAmount" ? 0 : (n === "extensions" || n === "protocol") ? "" : s[n];
    }, enumerable: true, configurable: true });
  });
  Object.defineProperty(WebSocket.prototype, "binaryType", {
    get: function () { return __state(this).binaryType; },
    set: function (v) { var s = __state(this); v = String(v); if (v === "blob" || v === "arraybuffer") { s.binaryType = v; } },
    enumerable: true, configurable: true });
  ["onopen", "onerror", "onclose", "onmessage"].forEach(function (n) {
    Object.defineProperty(WebSocket.prototype, n, {
      get: function () { return __state(this).handlers[n] || null; },
      set: function (v) { __state(this).handlers[n] = v; },
      enumerable: true, configurable: true });
  });
  Object.defineProperty(WebSocket.prototype, "send", { value: function send(d) {
    var s = __state(this);
    if (s.readyState === 0) { throw new DOMException("Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.", "InvalidStateError"); }
    s.sent.push(d);
  }, writable: true, enumerable: true, configurable: true });
  Object.defineProperty(WebSocket.prototype, "close", { value: function close() {
    var s = __state(this); s.readyState = 3; s.closedByPage = true;
  }, writable: true, enumerable: true, configurable: true });
  Object.defineProperty(globalThis, "WebSocket", { value: WebSocket, writable: true, configurable: true });
  function __nativeOpen(ws) { __state(ws).readyState = 1; ws.dispatchEvent(new Event("open")); }
  function __nativeMessage(ws, data) { ws.dispatchEvent(new MessageEvent("message", { data: data, origin: "wss://x" })); }
  function __nativeClose(ws, code, reason) { __state(ws).readyState = 3; ws.dispatchEvent(new CloseEvent("close", { code: code, reason: reason, wasClean: true })); }

  // The engine's WebSocketStream.
  var __streams = new WeakMap();
  var WebSocketStream = class WebSocketStream {
    constructor(url, options) {
      var s = { url: String(url), options: options };
      s.opened = new Promise(function (res, rej) { s.resOpened = res; s.rejOpened = rej; });
      s.closed = new Promise(function (res, rej) { s.resClosed = res; s.rejClosed = rej; });
      __streams.set(this, s);
      __made.push({ url: String(url), stream: true, options: options, socket: this });
    }
  };
  ["url", "opened", "closed"].forEach(function (n) {
    Object.defineProperty(WebSocketStream.prototype, n, { get: function () {
      var s = __streams.get(this); if (!s) { throw new TypeError("Illegal invocation"); } return s[n];
    }, enumerable: true, configurable: true });
  });
  Object.defineProperty(WebSocketStream.prototype, "close", { value: function close() {}, writable: true, enumerable: true, configurable: true });
  Object.defineProperty(globalThis, "WebSocketStream", { value: WebSocketStream, writable: true, configurable: true });

  // chrome.webview, with a host side the test drives.
  var __stringify = JSON.stringify, __parse = JSON.parse;
  var __posted = [];
  var __wvListeners = [];
  // STANDARD EventTarget dispatch, which is stricter than WebView2 155's
  // (registration order, capture flag ignored): at the target, capture
  // listeners run before non-capture ones, and stopImmediatePropagation
  // ends the dispatch. The guard must hold under both.
  var __webview = {
    // The engine serializes outside page JavaScript; a page's JSON must not touch it.
    postMessage: function (m) { __posted.push(__parse(__stringify(m))); },
    addEventListener: function (type, fn, opts) {
      var capture = opts === true || !!(opts && typeof opts === "object" && opts.capture);
      if (type === "message") { __wvListeners.push({ fn: fn, capture: capture }); }
    },
    dispatchEvent: function (ev) { __deliver(ev); return true; },
  };
  function __deliver(ev) {
    var list = __wvListeners.filter(function (l) { return l.capture; })
      .concat(__wvListeners.filter(function (l) { return !l.capture; }));
    for (var i = 0; i < list.length && !ev.__stopped; i++) { list[i].fn.call(__webview, ev); }
  }
  var chrome = { webview: __webview };
  // WebView2's shape: a plain Event, untrusted, with an own data property.
  function __wvEvent(obj, asGetter) {
    var ev = new Event("message");
    Object.defineProperty(ev, "data", asGetter
      ? { get: function () { return obj; }, enumerable: true, configurable: true }
      : { value: obj, enumerable: true, configurable: true });
    return ev;
  }
  function __hostSend(obj, asGetter) { __deliver(__wvEvent(obj, asGetter)); }
  // A page builds the very same shape; only what it carries differs.
  function __pageForge(obj) { __hostSend(obj); }

  // Location and document, as the private-address rule reads them.
  function DOMStringList(items) { this.__items = items; }
  Object.defineProperty(DOMStringList.prototype, "length", { get: function () { return this.__items.length; }, configurable: true });
  DOMStringList.prototype.item = function (i) { return this.__items[i]; };
  function Node() {}
  Object.defineProperty(Node.prototype, "baseURI", { get: function () { return this.__base; }, configurable: true });
  function Document() {}
  Document.prototype = Object.create(Node.prototype);
  Object.defineProperty(Document.prototype, "defaultView", { get: function () { return this.__view; }, configurable: true });
  var __doc = new Document(); __doc.__base = __env.href; __doc.__view = globalThis;
  var __loc = { __env: __env };
  Object.defineProperty(__loc, "ancestorOrigins", { get: function () { return new DOMStringList([]); } });
  Object.defineProperty(__loc, "origin", { get: function () { return this.__env.origin; } });
  Object.defineProperty(__loc, "href", { get: function () { return this.__env.href; } });
  globalThis.__locObj = __loc; globalThis.__docObj = __doc;
  Object.defineProperty(globalThis, "location", { get: function () { return this.__locObj; } });
  Object.defineProperty(globalThis, "document", { get: function () { return this.__docObj; } });
  function HTMLIFrameElement() {}
  Object.defineProperty(HTMLIFrameElement.prototype, "contentWindow", { get: function () { return null; }, configurable: true });
  Object.defineProperty(HTMLIFrameElement.prototype, "contentDocument", { get: function () { return null; }, configurable: true });
`;

const PAGE = {
  href: "https://news.example/page",
  origin: "https://news.example",
};

function realm(opts) {
  const ctx = vm.createContext({
    __env: Object.assign({}, PAGE, opts || {}),
    URL,
    DOMException,
    console,
    // JSON and Promise are NOT passed in: a realm has its own, and a page
    // test that replaces JSON.stringify must not reach this file's.
  });
  vm.runInContext(SETUP, ctx);
  if (opts && opts.before) {
    vm.runInContext(opts.before, ctx);
  }
  vm.runInContext(opts && opts.raw ? RAW : SCRIPT, ctx);
  return ctx;
}
const run = (ctx, code) => vm.runInContext(code, ctx);
function hello(ctx) {
  return run(
    ctx,
    "__posted.filter(function (m) { return m.op === 'hello'; })[0]",
  );
}
function ready(ctx) {
  const h = hello(ctx);
  run(ctx, `__hostSend({ k: "pws", g: ${JSON.stringify(h.g)}, op: "ready", n: ${JSON.stringify(h.n)} })`);
  return h.g;
}
function lastCheck(ctx) {
  return run(
    ctx,
    "__posted.filter(function (m) { return m.op === 'check'; }).slice(-1)[0]",
  );
}
function acks(ctx) {
  return run(ctx, "__posted.filter(function (m) { return m.op === 'ack'; })");
}
// The browser echoes the nonce of the check it answers; `nonce` overrides.
function nonceOf(ctx, id) {
  const c = run(ctx, `__posted.filter(function (m) { return m.op === 'check' && m.id === ${JSON.stringify(id)}; })[0]`);
  return c ? c.n : "0".repeat(32);
}
function verdict(ctx, g, id, allow, nonce) {
  const n = nonce === undefined ? nonceOf(ctx, id) : nonce;
  run(
    ctx,
    `__hostSend({ k: "pws", g: ${JSON.stringify(g)}, op: "verdict", id: ${JSON.stringify(id)}, allow: ${allow}, n: ${JSON.stringify(n)} })`,
  );
}

// --- channel ---------------------------------------------------------------
{
  const ctx = realm();
  const h = hello(ctx);
  check(
    h && h.t === TOKEN && h.k === "pws" && /^[0-9a-f]{32}$/.test(h.g) && /^[0-9a-f]{32}$/.test(h.n) && h.n !== h.g,
    "hello carries the token, a 128-bit generation and a separate 128-bit nonce",
  );
  run(ctx, "var ws = new WebSocket('wss://tracker.example/s');");
  check(
    run(
      ctx,
      "ws instanceof WebSocket && ws.readyState === 0 && __made.length === 0",
    ),
    "before ready: a stand-in in CONNECTING, no native socket",
  );
  check(!lastCheck(ctx), "before ready: the check waits");
  const g = ready(ctx);
  const c = lastCheck(ctx);
  check(
    c && c.t === TOKEN && c.g === g && c.url === "wss://tracker.example/s",
    "after ready: the queued check is sent with the checked URL",
  );
}
{
  const ctx = realm({ raw: true });
  check(!hello(ctx), "no token: no hello");
  run(ctx, "var ws = new WebSocket('wss://tracker.example/s');");
  check(
    run(ctx, "__made.length === 1 && __sockets.has(ws)"),
    "no token: the native socket, as before 1.1.2",
  );
}
{
  const ctx = realm();
  run(ctx, "var ws = new WebSocket('wss://chat.example/s');");
  run(ctx, "__tick(1500)");
  check(
    run(ctx, "__made.length === 1 && __made[0].url === 'wss://chat.example/s'"),
    "no ready within 1.5 s: DEGRADED, the waiting socket opens natively",
  );
  run(ctx, "var ws2 = new WebSocket('wss://chat.example/t');");
  check(
    run(ctx, "__made.length === 2 && __sockets.has(ws2)"),
    "degraded: later sockets are native at once",
  );
  check(acks(ctx).length === 0, "degraded: no acks, there was no verdict");
}

// --- verdicts --------------------------------------------------------------
{
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var log = []; var ws = new WebSocket('wss://chat.example/s', ['a', 'b']);" +
      "ws.onopen = function (e) { log.push('onopen'); };" +
      "ws.addEventListener('open', function () { log.push('open'); });" +
      "ws.addEventListener('message', function (e) { log.push('msg:' + e.data + ':' + e.origin); });" +
      "ws.addEventListener('close', function (e) { log.push('close:' + e.code + ':' + e.reason + ':' + e.wasClean); });",
  );
  const c = lastCheck(ctx);
  verdict(ctx, g, c.id, true);
  check(
    run(
      ctx,
      "__made.length === 1 && __made[0].url === 'wss://chat.example/s' && Array.isArray(__made[0].protocols) && __made[0].protocols.join() === 'a,b'",
    ),
    "allow: native socket with the checked URL and the protocol snapshot",
  );
  check(
    acks(ctx).length === 1 &&
      acks(ctx)[0].outcome === "constructed" &&
      acks(ctx)[0].id === c.id,
    "allow: acks constructed",
  );
  run(ctx, "__nativeOpen(__made[0].socket)");
  check(
    run(ctx, "ws.readyState === 1"),
    "after the native opens, readyState is forwarded",
  );
  run(
    ctx,
    "__nativeMessage(__made[0].socket, 'hi'); ws.send('x'); __nativeClose(__made[0].socket, 1000, 'bye');",
  );
  check(
    run(ctx, "log.join('|')") ===
      "onopen|open|msg:hi:wss://x|close:1000:bye:true",
    "events re-dispatched in order with their fields: " +
      run(ctx, "log.join('|')"),
  );
  check(
    run(ctx, "__sockets.get(__made[0].socket).sent.join() === 'x'"),
    "send is forwarded once open",
  );
}
{
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var log = []; var ws = new WebSocket('wss://tracker.example/s');" +
      "ws.onerror = function () { log.push('error'); };" +
      "ws.addEventListener('close', function (e) { log.push('close:' + e.code + ':' + e.wasClean); });",
  );
  verdict(ctx, g, lastCheck(ctx).id, false);
  check(
    run(
      ctx,
      "__made.length === 0 && ws.readyState === 3 && log.join('|') === 'error|close:1006:false'",
    ),
    "deny: no native socket; error then close 1006 unclean",
  );
  check(
    acks(ctx).length === 0,
    "deny: no ack, the browser already ledgered a block",
  );
}
{
  const ctx = realm();
  ready(ctx);
  run(
    ctx,
    "var log = []; var ws = new WebSocket('wss://chat.example/s'); ws.onclose = function (e) { log.push(e.code); };",
  );
  const c = lastCheck(ctx);
  run(ctx, "__tick(5000)");
  check(
    run(
      ctx,
      "__made.length === 0 && ws.readyState === 3 && log.join() === '1006'",
    ),
    "no verdict in 5 s: denied",
  );
  check(
    acks(ctx).length === 1 &&
      acks(ctx)[0].outcome === "timed-out" &&
      acks(ctx)[0].id === c.id,
    "timeout: acks timed-out",
  );
}
{
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var a = new WebSocket('wss://one.example/'); var b = new WebSocket('wss://two.example/');",
  );
  const checksSent = run(
    ctx,
    "__posted.filter(function (m) { return m.op === 'check'; })",
  );
  verdict(ctx, g, checksSent[1].id, true);
  check(
    run(
      ctx,
      "__made.length === 1 && __made[0].url === 'wss://two.example/' && a.readyState === 0",
    ),
    "concurrent checks: each verdict reaches its own socket",
  );
}

// A verdict the page could only handle after VERDICT_MS (its thread was
// stalled, so the timer had not run) is refused and acked as a timeout.
{
  const ctx = realm();
  const g = ready(ctx);
  run(ctx, "var ws = new WebSocket('wss://chat.example/s');");
  const c = lastCheck(ctx);
  run(ctx, "__now += 6000;"); // the clock moved; no timer has fired
  verdict(ctx, g, c.id, true);
  check(run(ctx, "__made.length === 0 && ws.readyState === 3"), "a late verdict is refused: no native socket");
  check(acks(ctx).length === 1 && acks(ctx)[0].outcome === "timed-out", "and acked as timed-out");
}

// --- forgery ---------------------------------------------------------------
{
  const ctx = realm();
  const g = ready(ctx);
  run(ctx, "var ws = new WebSocket('wss://tracker.example/s');");
  const c = lastCheck(ctx);
  check(/^[0-9a-f]{32}$/.test(c.n) && c.n !== hello(ctx).n, "a check carries its own 128-bit nonce");
  run(
    ctx,
    `__pageForge({ k: "pws", g: ${JSON.stringify(g)}, op: "verdict", id: ${JSON.stringify(c.id)}, allow: true })`,
  );
  check(
    run(ctx, "__made.length === 0 && ws.readyState === 0"),
    "a verdict without the check's nonce is ignored (the page's forgery)",
  );
  verdict(ctx, g, c.id, true, hello(ctx).n);
  check(run(ctx, "__made.length === 0 && ws.readyState === 0"), "a verdict carrying the hello's nonce is ignored");
  verdict(ctx, g, c.id, true, "f".repeat(32));
  check(run(ctx, "__made.length === 0 && ws.readyState === 0"), "a verdict with a guessed nonce is ignored");
  verdict(ctx, "f".repeat(32), c.id, true);
  check(
    run(ctx, "__made.length === 0"),
    "a verdict for another generation is ignored",
  );
  verdict(ctx, g, "c999", true, c.n);
  check(
    run(ctx, "__made.length === 0"),
    "a verdict for an unknown id is ignored, even with a live nonce",
  );
  run(ctx, "Object.prototype.allow = true;");
  run(
    ctx,
    `__hostSend({ k: "pws", g: ${JSON.stringify(g)}, op: "verdict", id: ${JSON.stringify(c.id)}, n: ${JSON.stringify(c.n)} })`,
  );
  check(
    run(ctx, "__made.length === 0 && ws.readyState === 3"),
    "an allow inherited from Object.prototype is not an allow",
  );
  run(ctx, "delete Object.prototype.allow;");
}
{
  // A page that listens on chrome.webview sees each genuine reply only after
  // the guard (registered first) has used its nonce, so a replay is dead.
  const ctx = realm();
  const g = ready(ctx);
  run(ctx, "var seen = []; chrome.webview.addEventListener('message', function (e) { seen.push(e.data); });");
  run(ctx, "var a = new WebSocket('wss://chat.example/a');");
  const first = lastCheck(ctx);
  verdict(ctx, g, first.id, true);
  check(run(ctx, "__made.length === 1 && seen.length === 1 && seen[0].n"), "the page saw the genuine verdict");
  run(ctx, "var b = new WebSocket('wss://tracker.example/b');");
  const second = lastCheck(ctx);
  run(ctx, `__pageForge({ k: "pws", g: seen[0].g, op: "verdict", id: ${JSON.stringify(second.id)}, allow: true, n: seen[0].n })`);
  check(run(ctx, "__made.length === 1 && b.readyState === 0"), "a nonce replayed from a seen reply opens nothing");
  run(ctx, `__pageForge({ k: "pws", g: seen[0].g, op: "verdict", id: ${JSON.stringify(first.id)}, allow: true, n: seen[0].n })`);
  check(run(ctx, "__made.length === 1"), "replaying the whole seen verdict opens nothing");
  verdict(ctx, g, second.id, false);
  check(run(ctx, "__made.length === 1 && b.readyState === 3"), "the genuine refusal still lands");
}
{
  // A page's capture listener, added after the guard's, under STANDARD
  // dispatch: it may see the genuine refusal, stop it and forge an allow
  // with the live nonce, unless the guard's own capture listener ran first.
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var forged = 0; chrome.webview.addEventListener('message', function (e) {" +
      "  var d = e.data; if (d && d.op === 'verdict' && d.allow === false) {" +
      "    e.stopImmediatePropagation(); forged++;" +
      "    var f = new Event('message'); Object.defineProperty(f, 'data', { value: { k: 'pws', g: d.g, op: 'verdict', id: d.id, allow: true, n: d.n } });" +
      "    chrome.webview.dispatchEvent(f); } }, true);" +
      "var swallowed = 0; chrome.webview.addEventListener('message', function (e) { swallowed++; e.stopImmediatePropagation(); }, { capture: true });",
  );
  run(ctx, "var ws = new WebSocket('wss://tracker.example/s');");
  const c = lastCheck(ctx);
  verdict(ctx, g, c.id, false);
  check(run(ctx, "forged === 1"), "the attacker's capture listener did run and forge");
  check(
    run(ctx, "__made.length === 0 && ws.readyState === 3"),
    "a later page capture listener cannot steal the nonce: the refusal stands",
  );
}
{
  // The same listener swallowing everything cannot hold back "ready".
  const ctx = realm();
  const h = hello(ctx);
  run(ctx, "chrome.webview.addEventListener('message', function (e) { e.stopImmediatePropagation(); }, true);");
  run(ctx, "var ws = new WebSocket('wss://chat.example/s');");
  run(ctx, `__hostSend({ k: "pws", g: ${JSON.stringify(h.g)}, op: "ready", n: ${JSON.stringify(h.n)} })`);
  check(!!lastCheck(ctx), "a page capture listener cannot swallow ready (no fall-back to native)");
}
{
  // Handler attributes join the listener list when first set.
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var order = []; var a = new WebSocket('wss://chat.example/a');" +
      "a.addEventListener('open', function () { order.push('listener'); });" +
      "a.onopen = function () { order.push('onopen'); };" +
      "var b = new WebSocket('wss://chat.example/b');" +
      "b.onopen = function () { order.push('b-first'); };" +
      "b.addEventListener('open', function () { order.push('b-listener'); });" +
      "b.onopen = null; b.onopen = function () { order.push('b-again'); };",
  );
  const checks2 = run(ctx, "__posted.filter(function (m) { return m.op === 'check'; })");
  for (const c of checks2) { verdict(ctx, g, c.id, true); }
  run(ctx, "__made.forEach(function (m) { __nativeOpen(m.socket); })");
  check(
    run(ctx, "order.join('|')") === "listener|onopen|b-listener|b-again",
    "on* runs where it was first set; null removes it and setting again re-adds it last: " + run(ctx, "order.join('|')"),
  );
}
{
  // Handler attributes set or re-set AFTER the native socket is bound.
  const ctx = realm();
  const g = ready(ctx);
  run(ctx, "var order = []; var ws = new WebSocket('wss://chat.example/late');");
  verdict(ctx, g, lastCheck(ctx).id, true);
  run(ctx, "__nativeOpen(__made[0].socket);");
  run(
    ctx,
    "ws.addEventListener('message', function () { order.push('listener'); });" +
      "var h = function () { order.push('onmessage'); }; ws.onmessage = h;" +
      "ws.onclose = function () { order.push('first-close'); };" +
      "ws.addEventListener('close', function () { order.push('close-listener'); });" +
      "ws.onclose = null; ws.onclose = function () { order.push('onclose'); };",
  );
  check(run(ctx, "ws.onmessage === h && __sockets.get(__made[0].socket).handlers.onmessage === undefined"),
    "a handler set after binding stays on the stand-in, not the native socket");
  run(ctx, "__nativeMessage(__made[0].socket, 'm'); __nativeClose(__made[0].socket, 1000, '');");
  check(
    run(ctx, "order.join('|')") === "listener|onmessage|close-listener|onclose",
    "after binding, on* still joins where it was first set and re-set: " + run(ctx, "order.join('|')"),
  );
}
{
  // A forged "ready" cannot start the channel early; the genuine one, in
  // getter form, does.
  const ctx = realm();
  const h = hello(ctx);
  run(ctx, "var ws = new WebSocket('wss://chat.example/s');");
  run(ctx, `__pageForge({ k: "pws", g: ${JSON.stringify(h.g)}, op: "ready" })`);
  run(ctx, `__pageForge({ k: "pws", g: ${JSON.stringify(h.g)}, op: "ready", n: ${JSON.stringify("f".repeat(32))} })`);
  check(!lastCheck(ctx), "a ready without the hello's nonce, or with a guessed one, sends no check");
  run(ctx, `__hostSend({ k: "pws", g: ${JSON.stringify(h.g)}, op: "ready", n: ${JSON.stringify(h.n)} }, true)`);
  check(!!lastCheck(ctx), "the genuine ready, data as an own getter, releases the waiting check");
}
{
  const ctx = realm();
  run(
    ctx,
    "var stolen = []; chrome.webview.postMessage = function (m) { stolen.push(JSON.stringify(m)); };" +
      "JSON.stringify = function () { stolen.push('json'); return '{}'; };",
  );
  ready(ctx);
  run(ctx, "var ws = new WebSocket('wss://tracker.example/s');");
  check(
    run(ctx, "stolen.length") === 0 &&
      lastCheck(ctx) &&
      lastCheck(ctx).t === TOKEN,
    "a page that replaces postMessage or JSON after the script ran never sees the token",
  );
}

// --- stand-in shape ----------------------------------------------------------
{
  const ctx = realm();
  ready(ctx);
  run(
    ctx,
    "class Sub extends WebSocket {}; var s = new Sub('wss://chat.example/');",
  );
  check(
    run(
      ctx,
      "s instanceof Sub && s instanceof WebSocket && s.readyState === 0",
    ),
    "a subclass gets a stand-in of its own class",
  );
  const r = run(
    ctx,
    "(function () { try { s.send('x'); return 'no'; } catch (e) { return e.name; } })()",
  );
  check(
    r === "InvalidStateError",
    "send while CONNECTING throws InvalidStateError: " + r,
  );
  const c999 = run(
    ctx,
    "(function () { try { s.close(999); return 'no'; } catch (e) { return e.name; } })()",
  );
  check(
    c999 === "InvalidAccessError",
    "close(999) throws InvalidAccessError: " + c999,
  );
  const long = run(
    ctx,
    "(function () { try { s.close(1000, 'x'.repeat(124)); return 'no'; } catch (e) { return e.name; } })()",
  );
  check(
    long === "SyntaxError",
    "a close reason over 123 bytes throws SyntaxError: " + long,
  );
  const brand = run(
    ctx,
    "(function () { try { Object.getOwnPropertyDescriptor(WebSocket.prototype, 'readyState').get.call({}); return 'no'; } catch (e) { return e.message; } })()",
  );
  check(
    brand === "Illegal invocation",
    "the native getter's brand error is unchanged: " + brand,
  );
  check(
    run(
      ctx,
      "s.url === 'wss://chat.example/' && s.binaryType === 'blob' && s.bufferedAmount === 0 && s.protocol === ''",
    ),
    "stand-in attributes before the verdict",
  );
  run(ctx, "s.binaryType = 'arraybuffer'; s.binaryType = 'nonsense';");
  check(
    run(ctx, "s.binaryType === 'arraybuffer'"),
    "binaryType keeps a valid value and ignores an invalid one",
  );
}
{
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var log = []; var ws = new WebSocket('wss://chat.example/'); ws.onclose = function (e) { log.push(e.code); }; ws.close();",
  );
  check(
    run(ctx, "ws.readyState === 2"),
    "close before the verdict: CLOSING at once",
  );
  run(ctx, "__tick(0)");
  check(
    run(ctx, "ws.readyState === 3 && log.join() === '1006'"),
    "then CLOSED with close 1006",
  );
  verdict(ctx, g, lastCheck(ctx).id, true);
  check(
    run(ctx, "__made.length === 0"),
    "a later allow opens nothing: close is final",
  );
  check(
    acks(ctx).length === 1 && acks(ctx)[0].outcome === "cancelled",
    "and acks cancelled",
  );
}

// --- one-shot conversion and validation ---------------------------------------
{
  const ctx = realm();
  ready(ctx);
  run(
    ctx,
    "var reads = 0; var p = { toString: function () { reads++; return reads === 1 ? 'chat' : 'evil proto'; } };" +
      "var ws = new WebSocket('wss://chat.example/', p);",
  );
  const g = hello(ctx).g;
  verdict(ctx, g, lastCheck(ctx).id, true);
  check(
    run(ctx, "reads === 1 && __made[0].protocols.join() === 'chat'"),
    "a protocol is converted once and the native gets that value",
  );
  run(
    ctx,
    "var iters = 0; var it = { [Symbol.iterator]: function () { iters++; return ['x', 'y'][Symbol.iterator](); } };" +
      "var ws2 = new WebSocket('wss://chat.example/', it);",
  );
  check(run(ctx, "iters === 1"), "a protocol sequence is iterated once");
  for (const [expr, label] of [
    [
      "new WebSocket('wss://chat.example/', ['a', 'a'])",
      "a duplicated protocol",
    ],
    [
      "new WebSocket('wss://chat.example/', ['bad token'])",
      "an invalid protocol",
    ],
    ["new WebSocket('wss://chat.example/', [''])", "an empty protocol"],
    ["new WebSocket('ftp://chat.example/')", "a non-WebSocket scheme"],
    ["new WebSocket('wss://chat.example/#frag')", "a fragment"],
    ["new WebSocket('wss://chat.example/#')", "an empty fragment"],
  ]) {
    const name = run(
      ctx,
      `(function () { try { ${expr}; return 'no'; } catch (e) { return e.name; } })()`,
    );
    check(name === "SyntaxError", `${label} throws SyntaxError (got ${name})`);
  }
  // The messages, as Edge 155's native WebSocket words them (read from the
  // engine on 2026-11-14): an empty fragment is named as ('').
  for (const [frag, shown] of [["#", ""], ["#f", "f"]]) {
    const msg = run(
      ctx,
      `(function () { try { new WebSocket('wss://chat.example/x${frag}'); return 'no'; } catch (e) { return e.message; } })()`,
    );
    check(
      msg === "Failed to construct 'WebSocket': The URL contains a fragment identifier ('" + shown +
        "'). Fragment identifiers are not allowed in WebSocket URLs.",
      `the ${frag} message matches the engine's (got ${msg})`,
    );
  }
}

// --- the private-address rule still runs first ------------------------------------
{
  const ctx = realm({
    href: "http://news.example/page",
    origin: "http://news.example",
  });
  ready(ctx);
  const name = run(
    ctx,
    "(function () { try { new WebSocket('ws://127.0.0.1:9/'); return 'no'; } catch (e) { return e.name; } })()",
  );
  check(
    name === "SecurityError",
    "a plain-HTTP page's socket to a private address is still refused synchronously",
  );
}

// --- transactional install ----------------------------------------------------------
{
  const before =
    "Object.defineProperty(WebSocket.prototype, 'close', { value: WebSocket.prototype.close, writable: true, enumerable: true, configurable: false });" +
    "var __rsBefore = Object.getOwnPropertyDescriptor(WebSocket.prototype, 'readyState').get;";
  const ctx = realm({ before });
  ready(ctx);
  run(ctx, "var ws = new WebSocket('wss://chat.example/');");
  check(
    run(ctx, "__made.length === 1 && __sockets.has(ws)"),
    "an unpatchable prototype: sockets open natively",
  );
  check(
    run(
      ctx,
      "Object.getOwnPropertyDescriptor(WebSocket.prototype, 'readyState').get === __rsBefore",
    ),
    "and no accessor was left half-replaced",
  );
}

// A definition that fails PART-WAY (after the preflight passed) must roll
// back every replacement already made.
{
  const before =
    "var __rsBefore = Object.getOwnPropertyDescriptor(WebSocket.prototype, 'readyState').get;" +
    "var __realDefine = Reflect.defineProperty;" +
    "Reflect.defineProperty = function (target, key, desc) {" +
    "  if (target === WebSocket.prototype && key === 'close') { return false; }" +
    "  return __realDefine(target, key, desc);" +
    "};";
  const ctx = realm({ before });
  ready(ctx);
  run(ctx, "var ws = new WebSocket('wss://chat.example/');");
  check(run(ctx, "__made.length === 1 && __sockets.has(ws)"), "a mid-way failure: sockets open natively");
  check(
    run(ctx, "Object.getOwnPropertyDescriptor(WebSocket.prototype, 'readyState').get === __rsBefore"),
    "a mid-way failure rolls back the replacements already made",
  );
}

// --- WebSocketStream -------------------------------------------------------------------
{
  const ctx = realm();
  const g = ready(ctx);
  run(
    ctx,
    "var st = new WebSocketStream('wss://tracker.example/s'); var outcome = 'pending';" +
      "st.opened.then(function () { outcome = 'opened'; }, function (e) { outcome = 'rejected:' + e.name; });",
  );
  check(
    run(
      ctx,
      "st instanceof WebSocketStream && __made.length === 0 && st.url === 'wss://tracker.example/s'",
    ),
    "a stream waits for the verdict as a stand-in",
  );
  verdict(ctx, g, lastCheck(ctx).id, false);
  setImmediate(() => {
    check(
      run(ctx, "outcome").indexOf("rejected:") === 0 &&
        run(ctx, "__made.length") === 0,
      "a denied stream rejects opened and opens nothing: " +
        run(ctx, "outcome"),
    );
    const ctx2 = realm();
    const g2 = ready(ctx2);
    run(
      ctx2,
      "var st = new WebSocketStream('wss://chat.example/s', { protocols: ['p'] });",
    );
    verdict(ctx2, g2, lastCheck(ctx2).id, true);
    check(
      run(
        ctx2,
        "__made.length === 1 && __made[0].stream && __made[0].options.protocols.join() === 'p'",
      ),
      "an allowed stream is constructed natively with the options snapshot",
    );
    finish();
  });
}

function finish() {
  if (failures > 0) {
    console.error(
      `websocket-check-gate: ${failures} of ${checks} checks FAILED`,
    );
    process.exit(1);
  }
  console.log(`websocket-check-gate: ${checks} checks passed`);
}
