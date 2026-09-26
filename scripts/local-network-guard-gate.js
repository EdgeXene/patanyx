// What local_network_guard.js does to `new WebSocket(...)`, exercised end to end.
//
// WHY THIS EXISTS. WebView2 never shows the request handler a WebSocket
// handshake (hardware, 2026-09-24), so on Windows this page-world script is
// the only thing between a plain-HTTP page and a socket into the user's
// network. A page script covered only by greps can ship dead; this gate runs
// the REAL script in fresh vm realms against stub browser objects and asserts
// the properties the guard stands on:
//
//   (both constructors that open a WebSocket connection: WebSocket and, where
//   the engine exposes it, WebSocketStream)
//
//   vectors      every host in private_host_vectors.json (the file privacy.rs
//                tests against is_private_host) is refused as a socket target
//                from a plain-HTTP page, and every public one is allowed
//   standing     keyed on the TOP document (ancestorOrigins): an HTTPS top is
//                outside the boundary; a plain-HTTP local top may reach its own
//                host (any port) and no other; an unreadable standing fails
//                closed
//   base         a relative URL resolves against the document's base URL,
//                so <base href="http://localhost/"> cannot smuggle one through
//   one-shot     the URL argument is converted ONCE and the native
//                constructor receives that checked string, never the object
//   tampering    replacing Reflect, URL, String and its prototype, Array,
//                DOMStringList, the baseURI getter or WeakSet after the script
//                ran changes nothing, and no page function ever receives the
//                native constructor
//   shape        instanceof, prototype.constructor, constants, name, length,
//                subclassing, the engine's own errors for a missing `new` or
//                argument, SyntaxError for a bad URL, no new globals
//   child realm  a same-origin child window reached through contentWindow or
//                contentDocument is guarded before the page can use it
//   nabu-x       the guard is registered only for CONTENT webviews on Windows:
//                never in the chrome webview (where Private Chat's UI lives),
//                never on Linux. Chat and Relay are native Rust sockets and
//                must stay that way.
//
// NOT covered here, honestly: window[0] / frames[0] access to a child realm
// that never ran the script, and workers. Those are hardware and copy
// questions, not something a stub can answer.
//
// Run: node scripts/local-network-guard-gate.js  (or via scripts/chrome-js-gate.sh)
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const SCRIPT = fs.readFileSync(
  path.join(ROOT, "crates/app/src/content_scripts/local_network_guard.js"),
  "utf8",
);
const VECTORS = JSON.parse(
  fs.readFileSync(
    path.join(ROOT, "crates/app/src/content_scripts/private_host_vectors.json"),
    "utf8",
  ),
);

let failures = 0;
let checks = 0;
function check(cond, what) {
  checks++;
  if (!cond) {
    failures++;
    console.error("FAIL: " + what);
  }
}

// A fresh realm that looks enough like a browser window for the guard:
// unforgeable location and document accessors on the window, a DOMStringList
// ancestorOrigins, Node.prototype.baseURI, Document.prototype.defaultView,
// frame element prototypes, and a recording WebSocket stub standing in for
// the engine's.
const SETUP = `
  var window = globalThis;
  var __made = [];
  function EventTarget() {}
  function WebSocket(url, protocols) {
    if (new.target === undefined) {
      throw new TypeError("Failed to construct 'WebSocket': call it with new.");
    }
    if (arguments.length === 0) {
      throw new TypeError("Failed to construct 'WebSocket': 1 argument required, but only 0 present.");
    }
    __made[__made.length] = { url: url, type: typeof url };
    this.url = url;
  }
  Object.setPrototypeOf(WebSocket, EventTarget);
  Object.setPrototypeOf(WebSocket.prototype, EventTarget.prototype);
  ["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach(function (n, i) {
    Object.defineProperty(WebSocket, n, { value: i, enumerable: true });
    Object.defineProperty(WebSocket.prototype, n, { value: i, enumerable: true });
  });
  Object.defineProperty(globalThis, "WebSocket", { value: WebSocket, writable: true, configurable: true });
  function WebSocketStream(url, options) {
    if (new.target === undefined) {
      throw new TypeError("Failed to construct 'WebSocketStream': call it with new.");
    }
    __made[__made.length] = { url: url, type: typeof url, stream: true };
    this.url = url;
  }
  Object.defineProperty(globalThis, "WebSocketStream", { value: WebSocketStream, writable: true, configurable: true });

  function DOMStringList(items) { this.__items = items; }
  Object.defineProperty(DOMStringList.prototype, "length", { get: function () { return this.__items.length; }, configurable: true });
  DOMStringList.prototype.item = function (i) { return this.__items[i]; };

  function Node() {}
  Object.defineProperty(Node.prototype, "baseURI", { get: function () { return this.__base; }, configurable: true });
  function Document() {}
  Document.prototype = Object.create(Node.prototype);
  Object.defineProperty(Document.prototype, "defaultView", { get: function () { return this.__view; }, configurable: true });

  // Getters read their RECEIVER, as the engine's do: the guard applies this
  // realm's getters to a child realm's objects.
  var __doc = new Document();
  __doc.__base = __env.base;
  __doc.__view = globalThis;
  var __loc = { __env: __env };
  Object.defineProperty(__loc, "ancestorOrigins", { get: function () {
    if (this.__env.ancestorsThrow) { throw new Error("unreadable"); }
    return new DOMStringList(this.__env.ancestors);
  } });
  Object.defineProperty(__loc, "origin", { get: function () { return this.__env.origin; } });
  Object.defineProperty(__loc, "href", { get: function () { return this.__env.href; } });
  globalThis.__locObj = __loc;
  globalThis.__docObj = __doc;
  Object.defineProperty(globalThis, "location", { get: function () { return this.__locObj; } });
  Object.defineProperty(globalThis, "document", { get: function () {
    // Another origin's document cannot be read, as with the engine's getter.
    if (this.__env.crossOrigin) { throw new DOMException("Blocked a frame from accessing a cross-origin frame.", "SecurityError"); }
    return this.__docObj;
  } });

  function HTMLIFrameElement() {}
  Object.defineProperty(HTMLIFrameElement.prototype, "contentWindow", { get: function () { return this.__child; }, configurable: true });
  Object.defineProperty(HTMLIFrameElement.prototype, "contentDocument", { get: function () { return this.__child ? this.__child.document : null; }, configurable: true });
  function HTMLFrameElement() {}
  function HTMLObjectElement() {}
`;

function realm(env) {
  const ctx = vm.createContext({
    __env: Object.assign(
      { base: env.href, ancestors: [], ancestorsThrow: false },
      env,
    ),
    URL,
    DOMException,
    console,
  });
  vm.runInContext(SETUP, ctx);
  return ctx;
}

function install(ctx) {
  vm.runInContext(SCRIPT, ctx);
}

// Try to open a socket in `ctx`; report whether the engine stub was reached
// and with what, or which error was thrown.
function open(ctx, expr) {
  ctx.__result = null;
  vm.runInContext(
    `
    (function () {
      var before = __made.length;
      try {
        var ws = ${expr};
        __result = { ok: true, made: __made.slice(before), ws: ws };
      } catch (e) {
        __result = { ok: false, name: e && e.name, message: String(e && e.message), made: __made.slice(before) };
      }
    })();
    `,
    ctx,
  );
  return ctx.__result;
}

const PUBLIC_HTTP = {
  href: "http://news.example/page",
  origin: "http://news.example",
};

// --- vectors -------------------------------------------------------------
{
  for (const host of VECTORS.private) {
    const ctx = realm(PUBLIC_HTTP);
    install(ctx);
    const r = open(
      ctx,
      `new WebSocket(${JSON.stringify("ws://" + host + "/x")})`,
    );
    check(
      !r.ok && r.name === "SecurityError" && r.made.length === 0,
      `private vector ${host} refused (got ${JSON.stringify(r)})`,
    );
  }
  for (const host of VECTORS.public) {
    if (host === "") continue; // not a URL host
    const ctx = realm(PUBLIC_HTTP);
    install(ctx);
    const r = open(
      ctx,
      `new WebSocket(${JSON.stringify("ws://" + host + "/x")})`,
    );
    check(
      r.ok && r.made.length === 1,
      `public vector ${host} allowed (got ${JSON.stringify(r)})`,
    );
  }
  // Spellings the URL parser canonicalizes: the guard must judge the
  // canonical host, the one the socket really connects to.
  for (const url of [
    "ws://0x7f000001/",
    "ws://127.1/",
    "ws://[0:0:0:0:0:ffff:c0a8:101]/",
    "wss://LocalHost./",
    "http://192.168.1.1:8080/",
  ]) {
    const ctx = realm(PUBLIC_HTTP);
    install(ctx);
    const r = open(ctx, `new WebSocket(${JSON.stringify(url)})`);
    check(!r.ok && r.name === "SecurityError", `canonicalized ${url} refused`);
  }
}

// --- standing ------------------------------------------------------------
{
  let ctx = realm({
    href: "https://secure.example/",
    origin: "https://secure.example",
  });
  install(ctx);
  check(
    open(ctx, `new WebSocket("ws://127.0.0.1:9000/")`).ok,
    "HTTPS top is outside the boundary",
  );

  ctx = realm({
    href: "http://192.168.1.1:8080/ui",
    origin: "http://192.168.1.1:8080",
  });
  install(ctx);
  check(
    open(ctx, `new WebSocket("ws://192.168.1.1:9000/live")`).ok,
    "a local page reaches its own host on another port",
  );
  check(
    open(ctx, `new WebSocket("ws://192.168.1.1/")`).ok,
    "a local page reaches its own host",
  );
  check(
    !open(ctx, `new WebSocket("ws://192.168.1.2/")`).ok,
    "a local page does not reach another device",
  );
  check(
    !open(ctx, `new WebSocket("ws://localhost/")`).ok,
    "a local page does not reach localhost",
  );

  ctx = realm({
    href: "http://localhost:3000/",
    origin: "http://localhost:3000",
  });
  install(ctx);
  check(
    open(ctx, `new WebSocket("ws://localhost:5173/")`).ok,
    "dev server reaches its own live-reload port",
  );
  check(
    !open(ctx, `new WebSocket("ws://127.0.0.1:5173/")`).ok,
    "127.0.0.1 is not localhost's own address",
  );

  // A frame is keyed on its TOP document.
  ctx = realm({
    href: "https://frame.example/f",
    origin: "https://frame.example",
    ancestors: ["https://middle.example", "http://evil.example"],
  });
  install(ctx);
  check(
    !open(ctx, `new WebSocket("ws://127.0.0.1/")`).ok,
    "an HTTPS frame under a plain-HTTP top is held to the boundary",
  );

  ctx = realm({
    href: "http://ads.example/f",
    origin: "http://ads.example",
    ancestors: ["https://secure.example"],
  });
  install(ctx);
  check(
    open(ctx, `new WebSocket("ws://127.0.0.1/")`).ok,
    "a plain-HTTP frame under an HTTPS top is outside it, as in privacy.rs",
  );

  ctx = realm(
    Object.assign(
      { ancestorsThrow: true },
      { href: "https://x.example/", origin: "https://x.example" },
    ),
  );
  install(ctx);
  check(
    !open(ctx, `new WebSocket("ws://127.0.0.1/")`).ok,
    "an unreadable standing fails closed",
  );
  check(
    open(ctx, `new WebSocket("wss://public.example/")`).ok,
    "and still allows public targets",
  );
}

// --- base URL and one-shot conversion -------------------------------------
{
  const ctx = realm(
    Object.assign({ base: "http://localhost:18766/" }, PUBLIC_HTTP),
  );
  install(ctx);
  const r = open(ctx, `new WebSocket("chat")`);
  check(
    !r.ok && r.name === "SecurityError" && r.made.length === 0,
    "<base href> cannot smuggle a relative URL to localhost",
  );

  const ctx2 = realm(PUBLIC_HTTP);
  install(ctx2);
  const r2 = open(
    ctx2,
    `(function () {
       var calls = 0;
       var tricky = { toString: function () { calls++; return calls === 1 ? "ws://public.example/s" : "ws://127.0.0.1/s"; } };
       var ws = new WebSocket(tricky);
       __made.calls = calls;
       return ws;
     })()`,
  );
  check(
    r2.ok && r2.made.length === 1 && r2.made[0].type === "string",
    "the engine receives the checked STRING, not the object",
  );
  check(
    r2.ok && r2.made[0].url === "ws://public.example/s",
    "and it is the address that was checked",
  );
  check(
    vm.runInContext("__made.calls", ctx2) === 1,
    "the URL argument is converted exactly once",
  );
}

// --- tampering after the script ran ---------------------------------------
{
  const ctx = realm(PUBLIC_HTTP);
  install(ctx);
  vm.runInContext(
    `
    var __leaked = [];
    var realConstruct = Reflect.construct;
    Reflect.construct = function (target, args, nt) { __leaked[__leaked.length] = target; return realConstruct(target, args, nt); };
    Reflect.apply = function () { throw new Error("page Reflect.apply"); };
    URL = function () { return { href: "ws://public.example/", hostname: "public.example" }; };
    // The intrinsic String.prototype, which every primitive string uses,
    // is poisoned BEFORE the global is replaced; poisoning the replacement's
    // prototype would touch no string at all (final review 8, R-002).
    String.prototype.toLowerCase = function () { return "public.example"; };
    String.prototype.slice = function () { return "public.example"; };
    String.prototype.indexOf = function () { return -1; };
    String.prototype.endsWith = function () { return false; };
    String.prototype.split = function () { return ["8", "8", "8", "8"]; };
    String = function () { return "ws://public.example/"; };
    Array.prototype.push = function () { throw new Error("page push"); };
    Object.defineProperty(DOMStringList.prototype, "length", { get: function () { return 0; } });
    Object.defineProperty(Node.prototype, "baseURI", { get: function () { return "http://public.example/"; } });
    WeakSet.prototype.has = function () { return true; };
    // Final review 5, R-001: setters planted on array and object indices
    // that rewrite "127" to "8" as it is written.
    ["0", "1", "2", "3", "n", "at"].forEach(function (key) {
      [Array.prototype, Object.prototype].forEach(function (proto) {
        Object.defineProperty(proto, key, {
          configurable: true,
          set: function (v) {
            Object.defineProperty(this, key, { value: v === "127" ? "8" : v, writable: true, enumerable: true, configurable: true });
          },
        });
      });
    });
    `,
    ctx,
  );
  const r = open(ctx, `new WebSocket("ws://127.0.0.1/admin")`);
  check(
    !r.ok && r.name === "SecurityError",
    `tampering does not unlock a private target (got ${JSON.stringify(r)})`,
  );
  const r2 = open(ctx, `new WebSocket("wss://public.example/ok")`);
  check(r2.ok, "tampering does not break a public socket");
  // Counted, not searched for: the page's String.prototype is poisoned
  // above, so a text search inside this realm would see nothing (final
  // review 9, R-002). The guard captured Reflect.construct before the page
  // replaced it, so the page's interceptor must never have been called.
  const leakedCount = vm.runInContext(`__leaked.length`, ctx);
  check(leakedCount === 0, `no page function ever receives the native constructor (${leakedCount} leaked)`);
}

// --- shape ---------------------------------------------------------------
{
  const ctx = realm({
    href: "https://secure.example/",
    origin: "https://secure.example",
  });
  const before = vm.runInContext(
    "Object.getOwnPropertyNames(globalThis).sort().join(',')",
    ctx,
  );
  install(ctx);
  const after = vm.runInContext(
    "Object.getOwnPropertyNames(globalThis).sort().join(',')",
    ctx,
  );
  check(before === after, "the script adds no global");
  check(
    vm.runInContext(
      `new WebSocket("wss://a.example/") instanceof WebSocket`,
      ctx,
    ),
    "instanceof holds",
  );
  check(
    vm.runInContext(`WebSocket.prototype.constructor === WebSocket`, ctx),
    "prototype.constructor is the visible WebSocket",
  );
  check(
    vm.runInContext(
      `WebSocket.name === "WebSocket" && WebSocket.length === 1`,
      ctx,
    ),
    "name and length",
  );
  check(
    vm.runInContext(
      `WebSocket.CONNECTING === 0 && WebSocket.OPEN === 1 && WebSocket.CLOSING === 2 && WebSocket.CLOSED === 3`,
      ctx,
    ),
    "constants",
  );
  check(
    vm.runInContext(`Object.getPrototypeOf(WebSocket) === EventTarget`, ctx),
    "inherits like the engine's constructor",
  );
  const sub = open(
    ctx,
    `(function () { class Mine extends WebSocket {} var m = new Mine("wss://a.example/"); return m instanceof Mine && m instanceof WebSocket ? m : null; })()`,
  );
  check(
    sub.ok && sub.ws && sub.made[0].url === "wss://a.example/",
    "subclassing works and passes the checked URL",
  );
  const noNew = open(ctx, `WebSocket("wss://a.example/")`);
  check(
    !noNew.ok && noNew.name === "TypeError" && /new/.test(noNew.message),
    "no `new`: the engine's own TypeError",
  );
  const noArg = open(ctx, `new WebSocket()`);
  check(
    !noArg.ok && noArg.name === "TypeError" && /argument/.test(noArg.message),
    "no argument: the engine's own TypeError",
  );
  const bad = open(ctx, `new WebSocket("ws://[bad")`);
  check(
    !bad.ok && bad.name === "SyntaxError" && bad.made.length === 0,
    "an invalid URL is a SyntaxError and reaches nothing",
  );
}

// --- WebSocketStream: the same connection, the same guard ------------------
{
  const ctx = realm(PUBLIC_HTTP);
  install(ctx);
  const r = open(ctx, `new WebSocketStream("ws://127.0.0.1:9000/")`);
  check(!r.ok && r.name === "SecurityError" && r.made.length === 0, "WebSocketStream to a private address is refused");
  const ok = open(ctx, `new WebSocketStream("wss://public.example/", { protocols: ["x"] })`);
  check(ok.ok && ok.made.length === 1 && ok.made[0].stream && ok.made[0].type === "string", "WebSocketStream to a public address reaches the engine with the checked string");
  check(vm.runInContext(`WebSocketStream.name === "WebSocketStream"`, ctx), "WebSocketStream keeps its name");
  const ctx2 = realm({ href: "https://secure.example/", origin: "https://secure.example" });
  vm.runInContext("delete globalThis.WebSocketStream", ctx2);
  install(ctx2);
  check(open(ctx2, `new WebSocket("wss://a.example/")`).ok, "an engine without WebSocketStream still gets the WebSocket guard");
}

// --- child realm ---------------------------------------------------------
{
  for (const route of ["contentWindow", "contentDocument"]) {
    const parent = realm(PUBLIC_HTTP);
    const child = realm({
      href: "about:blank",
      origin: "http://news.example",
      ancestors: ["http://news.example"],
    });
    install(parent);
    parent.__childWindow = vm.runInContext("globalThis", child);
    vm.runInContext(
      `var frame = new HTMLIFrameElement(); frame.__child = __childWindow;
       var reached = frame.${route};`,
      parent,
    );
    const r = open(child, `new WebSocket("ws://127.0.0.1/")`);
    check(
      !r.ok && r.name === "SecurityError",
      `a child realm reached through ${route} is guarded`,
    );
  }
}

// --- a grandchild realm, reached through the child's own accessor ----------
{
  const parent = realm(PUBLIC_HTTP);
  const child = realm({ href: "about:blank", origin: "http://news.example", ancestors: ["http://news.example"] });
  const grandchild = realm({
    href: "about:blank",
    origin: "http://news.example",
    ancestors: ["http://news.example", "http://news.example"],
  });
  install(parent);
  parent.__childWindow = vm.runInContext("globalThis", child);
  child.__grandchildWindow = vm.runInContext("globalThis", grandchild);
  vm.runInContext(`var frame = new HTMLIFrameElement(); frame.__child = __childWindow; var reached = frame.contentWindow;`, parent);
  vm.runInContext(`var inner = new HTMLIFrameElement(); inner.__child = __grandchildWindow; var reached2 = inner.contentWindow;`, child);
  const r = open(grandchild, `new WebSocket("ws://127.0.0.1/")`);
  check(!r.ok && r.name === "SecurityError", "a grandchild realm reached through the child's accessor is guarded");
}

// --- descriptor poisoning after the script ran (final review 6, R-001) -----
// Reflect.defineProperty reads a descriptor's fields through its prototype
// chain; Object.prototype.get turns an ordinary `{ value }` into an invalid
// half-accessor. The child must still come out guarded.
{
  for (const field of ["get", "set", "value", "writable"]) {
    const parent = realm(PUBLIC_HTTP);
    const child = realm({ href: "about:blank", origin: "http://news.example", ancestors: ["http://news.example"] });
    install(parent);
    parent.__childWindow = vm.runInContext("globalThis", child);
    vm.runInContext(
      `Object.prototype.${field} = function () {};
       var frame = new HTMLIFrameElement(); frame.__child = __childWindow; var reached = frame.contentWindow;`,
      parent,
    );
    const r = open(child, `new WebSocket("ws://127.0.0.1:18766/")`);
    check(
      !r.ok && r.name === "SecurityError" && r.made.length === 0,
      `a child reached after Object.prototype.${field} was planted is still guarded`,
    );
  }
}

// --- a same-origin child that cannot be guarded is withheld ----------------
{
  const parent = realm(PUBLIC_HTTP);
  const child = realm({ href: "about:blank", origin: "http://news.example", ancestors: ["http://news.example"] });
  install(parent);
  // What a page could do to a child it reached some other way first: pin its
  // constructor so it cannot be replaced.
  vm.runInContext(
    `Object.defineProperty(globalThis, "WebSocket", { value: WebSocket, writable: false, configurable: false });`,
    child,
  );
  parent.__childWindow = vm.runInContext("globalThis", child);
  vm.runInContext(
    `var frame = new HTMLIFrameElement(); frame.__child = __childWindow;
     var viaWindow = frame.contentWindow; var viaDocument = frame.contentDocument;`,
    parent,
  );
  check(
    vm.runInContext("viaWindow === null && viaDocument === null", parent),
    "a same-origin child that cannot be guarded is withheld from both accessors",
  );
}

// --- ... and so is one whose prototype still leads to the native one --------
// (final review 7, R-002)
{
  const parent = realm(PUBLIC_HTTP);
  const child = realm({ href: "about:blank", origin: "http://news.example", ancestors: ["http://news.example"] });
  install(parent);
  vm.runInContext(
    `Object.defineProperty(WebSocket.prototype, "constructor", { value: WebSocket, writable: false, configurable: false });`,
    child,
  );
  parent.__childWindow = vm.runInContext("globalThis", child);
  vm.runInContext(
    `var frame = new HTMLIFrameElement(); frame.__child = __childWindow;
     var viaWindow = frame.contentWindow; var viaDocument = frame.contentDocument;`,
    parent,
  );
  check(
    vm.runInContext("viaWindow === null && viaDocument === null", parent),
    "a child whose WebSocket.prototype.constructor cannot be replaced is withheld",
  );
}

// --- a cross-origin child is passed through untouched ----------------------
{
  const parent = realm(PUBLIC_HTTP);
  const child = realm({
    href: "https://other.example/",
    origin: "https://other.example",
    ancestors: ["http://news.example"],
    crossOrigin: true,
  });
  install(parent);
  parent.__childWindow = vm.runInContext("globalThis", child);
  vm.runInContext(`var frame = new HTMLIFrameElement(); frame.__child = __childWindow; var cw = frame.contentWindow;`, parent);
  check(
    vm.runInContext("cw === __childWindow", parent) &&
      vm.runInContext(`String(WebSocket).indexOf("refuses") === -1`, child),
    "a cross-origin child is handed over untouched (its own copy of the script guards it)",
  );
}

// --- a frame whose realm was replaced behind the same window ---------------
// A frame's window keeps its identity when the frame navigates, while the
// realm behind it is new. Being seen before is not being guarded.
{
  const parent = realm(PUBLIC_HTTP);
  const child = realm({ href: "about:blank", origin: "http://news.example", ancestors: ["http://news.example"] });
  install(parent);
  parent.__childWindow = vm.runInContext("globalThis", child);
  vm.runInContext(`var frame = new HTMLIFrameElement(); frame.__child = __childWindow; var first = frame.contentWindow;`, parent);
  vm.runInContext(
    `Object.defineProperty(globalThis, "WebSocket", {
       value: function WebSocket(u) { __made[__made.length] = { url: u, type: typeof u }; },
       writable: true, configurable: true });`,
    child,
  );
  vm.runInContext(`var again = frame.contentWindow;`, parent);
  const r = open(child, `new WebSocket("ws://127.0.0.1/")`);
  check(!r.ok && r.name === "SecurityError" && r.made.length === 0, "a realm replaced behind the same window is guarded again");
}

// --- opaque origins --------------------------------------------------------
{
  let ctx = realm({ href: "https://sandboxed.example/", origin: "https://sandboxed.example", ancestors: ["null"] });
  install(ctx);
  check(!open(ctx, `new WebSocket("ws://127.0.0.1/")`).ok, "an opaque top origin is not taken for HTTPS");
  ctx = realm({ href: "http://sandboxed.example/", origin: "null" });
  install(ctx);
  check(!open(ctx, `new WebSocket("ws://127.0.0.1/")`).ok, "an opaque own origin is not taken for HTTPS");
  check(open(ctx, `new WebSocket("wss://public.example/")`).ok, "and public targets still open");
}

// --- idempotence ---------------------------------------------------------
{
  const ctx = realm(PUBLIC_HTTP);
  install(ctx);
  install(ctx);
  check(
    !open(ctx, `new WebSocket("ws://127.0.0.1/")`).ok,
    "a second run still refuses",
  );
  const ok = open(ctx, `new WebSocket("wss://public.example/")`);
  check(
    ok.ok && ok.made.length === 1,
    "and still reaches the engine exactly once for an allowed socket",
  );
}

// --- nabu-x: content webviews on Windows only -----------------------------
{
  const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");
  const windows = read("crates/app/src/platform/windows.rs");
  const unix = read("crates/app/src/platform/unix.rs");
  const main = read("crates/app/src/main.rs");
  const privacy = read("crates/app/src/platform/privacy.rs");
  check(
    /LOCAL_NETWORK_GUARD_SCRIPT[^;]*include_str!\("\.\.\/content_scripts\/local_network_guard\.js"\)/.test(
      privacy,
    ),
    "privacy.rs embeds the guard",
  );
  const registrations = windows.match(/install_local_network_guard\(/g) || [];
  check(
    registrations.length === 2,
    "windows.rs defines and calls install_local_network_guard once (" +
      registrations.length +
      ")",
  );
  const buildContent = windows.slice(windows.indexOf("pub fn build_content("));
  check(
    /install_local_network_guard\(&webview/.test(
      buildContent.slice(0, buildContent.indexOf("\n}\n")),
    ),
    "it is called from build_content, the content webview builder",
  );
  check(
    !/LOCAL_NETWORK_GUARD_SCRIPT|install_local_network_guard|local_network_guard\.js/.test(main),
    "the chrome webview (main.rs, Private Chat's UI) never gets it",
  );
  check(
    !/LOCAL_NETWORK_GUARD_SCRIPT|install_local_network_guard|local_network_guard\.js/.test(unix),
    "Linux never gets it (the rule is Windows-only)",
  );
  // A page's new tab is judged when the page asked. wry answers from the
  // message loop, later, so the engine event itself records a refusal
  // (windows.rs NewWindowRequested -> on_new_window_requested), and wry's
  // callback spends it for every request before anything else (final review
  // 6, R-002). Only refusals are recorded, so nothing left over can allow a
  // request (final review 5, R-002). The sink honours the verdict.
  const stateRs = read("crates/app/src/state.rs");
  const queue = stateRs.slice(stateRs.indexOf(".with_new_window_req_handler("));
  const queueBody = queue.slice(0, queue.indexOf("wry::NewWindowResponse::Deny"));
  check(
    /let allowed = platform::new_tab_allowed\(window_gate\.borrow\(\)\.as_ref\(\), &url\);\s*if is_allowed_content_url\(&url\) \{\s*let _ = new_window_proxy\.send_event\(UserEvent::OpenInNewTab \{ url, allowed \}\);/.test(queueBody),
    "the new-tab verdict is taken in the callback that queues the request",
  );
  check(
    /add_NewWindowRequested\([\s\S]{0,900}on_new_window_requested\(url\.as_deref\(\)\)[\s\S]{0,400}Ok\(\(\)\) => state\.borrow_mut\(\)\.new_window_tracking = true/.test(windows),
    "the refusal is recorded in the engine event itself, and only a registered handler vouches for anything",
  );
  check(
    /gate\.0\.borrow_mut\(\)\.take_new_window_verdict\(url\)/.test(windows),
    "wry's callback spends the refusal the event recorded",
  );
  check(
    /UserEvent::OpenInNewTab \{ url, allowed \}\) => \{/.test(main) &&
      /if allowed && state::is_allowed_content_url\(&url\)/.test(main),
    "the tab factory honours that verdict",
  );
  // The first page waits for the guard's answer, and an answer that never
  // comes cannot hold it forever (final review 6, R-003); a first page that
  // fails to start leaves no mark and a diagnostic (final review 6, R-004).
  check(
    /\} else \{[\s\S]{0,300}std::thread::sleep\(LOCAL_NETWORK_GUARD_ANSWER_WAIT\);\s*let _ = overdue_proxy\.send_event\(UserEvent::LocalNetworkGuardOverdue\(id\)\);/.test(windows) &&
      /UserEvent::LocalNetworkGuardOverdue\(id\)\) => \{\s*app\.on_local_network_guard_overdue\(id\)/.test(main) &&
      /fn on_local_network_guard_overdue\(&mut self, id: u64\) \{[\s\S]{0,200}platform::note_local_network_guard_overdue\(&tab\.view\);\s*tab\.finish_initial_navigation\(\);/.test(stateRs),
    "an unanswered guard releases the first page after a bounded wait",
  );
  check(
    /if let Err\(error\) = platform::load_initial_url\(&self\.webview, self\.id, &self\.url\) \{[\s\S]{0,200}platform::forget_app_navigation\(&self\.view\);\s*platform::report_initial_navigation_failure/.test(stateRs),
    "a first page that fails to start leaves no mark behind and is diagnosed",
  );
  // The exportable log names hosts, never another page's full URL
  // (compliance audit 2026-09-24; state.rs diagnostics_snapshot).
  const platformMod = read("crates/app/src/platform/mod.rs");
  check(
    [windows, unix].every((src) =>
      /fn report_initial_navigation_failure\(url: &str, error: &wry::Error\) \{\s*diag\(&super::initial_navigation_failure_line\(url, error\)\);/.test(src)) &&
      /fn initial_navigation_failure_line\([^)]*\) -> String \{\s*let host = url::Url::parse\(url\)[^;]*host_str\(\)[^;]*;\s*format!\("build: initial navigation to \{host\} failed \(\{error\}\)"\)/.test(platformMod),
    "a failed first page is logged by host, not full URL",
  );
  const chat = ["transport.rs", "relay_client.rs", "discovery.rs"]
    .map((f) => read("crates/chat/src/" + f))
    .join("\n");
  check(
    /TcpListener/.test(chat) && /tungstenite/.test(chat),
    "Chat and Relay are still native Rust sockets, outside every page",
  );
}

if (failures) {
  console.error(
    `local-network-guard-gate: ${failures} of ${checks} checks FAILED`,
  );
  process.exit(1);
}
console.log(`local-network-guard-gate: ${checks} checks passed`);
