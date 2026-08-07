// DOM harness: LOADS the chrome scripts and drives them. Catches runtime
// ReferenceErrors `node --check` cannot see, and — unlike the first version —
// keeps enough state (real classList, recorded textContent, a controllable
// window.__rb.request) to ASSERT on behaviour instead of just survival.
const ids = new Set(
  [
    ...require("fs")
      .readFileSync(process.env.HTML_PATH, "utf8")
      // Underscore included: HTML allows it in ids and `accent-blood_red`
      // uses it (the id derives from ChromeTheme::as_str, which serde
      // snake_cases). Without it the stub silently had no such element and
      // chrome.js's listener wiring threw on a "missing" id that exists.
      .matchAll(/id="([a-z0-9_-]+)"/g),
  ].map((m) => m[1]),
);
const allEls = [];
function mkEl(id) {
  const listeners = {};
  // Assigned below, after `els` exists; a plain property until then.
  let currentId = id;
  const classes = new Set();
  const attrs = {};
  const el = {
    hidden: true,
    value: "",
    className: "",
    disabled: false,
    checked: false,
    style: {},
    dataset: {},
    children: [],
    _listeners: listeners,
    _text: [],
    classList: {
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, on) =>
        on === undefined
          ? classes.has(c)
            ? classes.delete(c)
            : classes.add(c)
          : on
            ? classes.add(c)
            : classes.delete(c),
      contains: (c) => classes.has(c),
      _all: () => [...classes],
    },
    addEventListener: (ev, fn) => {
      (listeners[ev] ||= []).push(fn);
      registered.push(id + ":" + ev);
    },
    removeEventListener() {},
    _fire: (ev, arg) =>
      (listeners[ev] || []).forEach((fn) =>
        fn(
          Object.assign(
            {
              preventDefault() {},
              stopPropagation() {},
              target: el,
              currentTarget: el,
              key: "",
            },
            arg || {},
          ),
        ),
      ),
    _has: (ev) => (listeners[ev] || []).length > 0,
    setAttribute(k, v) {
      attrs[k] = String(v);
    },
    getAttribute(k) {
      return k in attrs ? attrs[k] : null;
    },
    removeAttribute(k) {
      delete attrs[k];
    },
    hasAttribute(k) {
      return k in attrs;
    },
    appendChild(c) {
      this.children.push(c);
      c.parentNode = this;
      return c;
    },
    insertBefore(c) {
      this.children.push(c);
      c.parentNode = this;
      return c;
    },
    replaceChildren(...c) {
      this.children = c;
    },
    remove() {},
    querySelector() {
      return null;
    },
    querySelectorAll() {
      return [];
    },
    closest() {
      return null;
    },
    focus() {},
    select() {},
    blur() {},
    click() {
      this._fire("click");
    },
    getBoundingClientRect() {
      return { height: 0, width: 0, top: 0, left: 0 };
    },
    scrollIntoView() {},
    firstChild: null,
    lastChild: null,
    parentNode: { insertBefore() {}, removeChild() {}, appendChild() {} },
  };
  // Record every string written, so a test can ask what the user was shown.
  Object.defineProperty(el, "textContent", {
    get() {
      return el._text.length ? el._text[el._text.length - 1] : "";
    },
    set(v) {
      el._text.push(String(v));
      if (String(v) === "") el.children = [];
    },
  });
  // `id` is a real accessor so that `el.id = "btn-update"` on a
  // createElement'd node REGISTERS it, the way a live DOM does once the node
  // is in the document. Without this the element exists, styles itself,
  // attaches listeners, and is unreachable by id forever.
  Object.defineProperty(el, "id", {
    get() {
      return currentId;
    },
    set(v) {
      currentId = String(v);
      if (typeof els !== "undefined" && !els.has(currentId)) {
        els.set(currentId, el);
      }
    },
    enumerable: true,
  });
  el.id = id;
  allEls.push(el);
  return el;
}
const registered = [];
const els = new Map();
for (const id of ids) els.set(id, mkEl(id));

global.registered = registered;
global.els = els;
global.allEls = allEls;
global.$ = (id) => els.get(id);
// Every string that reached the DOM anywhere, dynamic nodes included.
global.allText = () => allEls.flatMap((e) => e._text).filter(Boolean);
const docListeners = {};
global.document = {
  getElementById: (id) => els.get(id) || null,
  createElement: (t) => mkEl("new-" + t),
  createTextNode: (t) => {
    const n = { nodeType: 3, _text: [] };
    Object.defineProperty(n, "textContent", {
      get() {
        return n._text[n._text.length - 1] || "";
      },
      set(v) {
        n._text.push(String(v));
      },
    });
    n.textContent = t;
    allEls.push(n);
    return n;
  },
  createElementNS: (ns, t) => mkEl("svg-" + t),
  querySelector: () => null,
  querySelectorAll: () => [],
  body: mkEl("body"),
  head: mkEl("head"),
  documentElement: mkEl("html"),
  // RECORDED, not discarded. These were no-ops, which quietly made every
  // document-level handler in the chrome untestable -- and the chrome puts two
  // of its dismissal paths there: Escape, and a click outside an open surface.
  // A gate could assert that a panel OPENS and had no way to assert that it
  // can be closed, so "Escape does nothing" was not a failure any suite could
  // express. Firing them is `global.fireDocument`.
  addEventListener(type, fn) {
    (docListeners[type] = docListeners[type] || []).push(fn);
  },
  removeEventListener(type, fn) {
    const list = docListeners[type];
    if (!list) return;
    const at = list.indexOf(fn);
    if (at !== -1) list.splice(at, 1);
  },
};
/// Dispatch a document-level event, the way a real browser would.
///
/// `ev.target.closest` defaults to returning null, which is what an "outside"
/// click looks like to the chrome's dismissal handlers. A test simulating a
/// click INSIDE some region passes its own target whose `closest` answers for
/// the selectors that region would match.
global.fireDocument = (type, ev) => {
  const event = Object.assign({ target: { closest: () => null } }, ev || {});
  for (const fn of (docListeners[type] || []).slice()) fn(event);
};

// Controllable IPC. Default resolves {}; set global.rbReject to a code string
// to make every request reject with an Error carrying that code, which is how
// the tailored-copy paths are reached.
global.rbCalls = [];
global.rbReject = null;
global.rbResolve = {};
const request = (cmd, args) => {
  rbCalls.push({ cmd, args });
  if (global.rbReject) return Promise.reject(new Error(global.rbReject));
  return Promise.resolve(
    Object.prototype.hasOwnProperty.call(global.rbResolve, cmd)
      ? global.rbResolve[cmd]
      : {},
  );
};
global.window = {
  // The wire. chrome.js replaces window.__rb with its own request() that
  // posts here, so this is where a command is genuinely observable — asserting
  // on a pre-seeded __rb.request would test the harness, not the browser.
  ipc: {
    postMessage(raw) {
      const msg = JSON.parse(raw);
      rbCalls.push({ id: msg.id, cmd: msg.cmd, args: msg.args });
      // Answer on the next tick, the way Rust does.
      setImmediate(() => {
        if (!global.window.__rb_reply) return;
        if (global.rbReject) {
          global.window.__rb_reply({
            id: msg.id,
            ok: false,
            error: global.rbReject,
          });
        } else {
          const data = Object.prototype.hasOwnProperty.call(
            global.rbResolve,
            msg.cmd,
          )
            ? global.rbResolve[msg.cmd]
            : {};
          global.window.__rb_reply({ id: msg.id, ok: true, data });
        }
      });
    },
  },
  addEventListener() {},
  removeEventListener() {},
  matchMedia: () => ({
    matches: false,
    addEventListener() {},
    addListener() {},
  }),
  requestAnimationFrame: (fn) => {
    fn();
    return 1;
  },
  cancelAnimationFrame() {},
  location: { href: "about:blank" },
  // Node ships its own global `navigator` (since v21) with a setter that
  // silently discards `global.navigator = {...}` -- a plain reassignment
  // leaves chrome.js reading Node's built-in object, missing exactly the
  // property this harness needs. Mutating the existing object works
  // regardless; `window.navigator` is set to the SAME object below rather
  // than a copy, so code reading either name sees one object.
  navigator,
};
navigator.language = "en";
// Real WebView2/WebKitGTK always provide this; recorded here so a gate can
// assert what a Copy-to-clipboard control actually wrote, the same way
// `global.rbCalls` records what crossed the IPC boundary.
navigator.clipboard = {
  writeText: (text) => {
    global.clipboardText = text;
    return Promise.resolve();
  },
};
global.location = global.window.location;
// Timers run the callback immediately so async chains settle inside one tick.
global.setTimeout = (fn) => {
  try {
    fn();
  } catch (e) {
    global.timerThrew = e;
  }
  return 0;
};
global.clearTimeout = () => {};
global.setInterval = () => 1;
global.clearInterval = () => {};
global.console = console;
