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
// Ids carrying a given attribute in the real markup, so a
// `querySelectorAll("[data-premium]")` in chrome.js resolves to the elements
// index.html actually marks. Attribute-only: this stub models ids, and a
// general selector engine here would be a second, wrong browser. Elements
// created at runtime are matched too, through their own attrs (see the
// document-level implementation below).
const attrIds = new Map();
{
  const html = require("fs").readFileSync(process.env.HTML_PATH, "utf8");
  for (const tag of html.matchAll(/<[a-z]+\b[^>]*>/g)) {
    const idMatch = tag[0].match(/id="([a-z0-9_-]+)"/);
    if (!idMatch) continue;
    for (const attr of tag[0].matchAll(/\s(data-[a-z0-9-]+)[=\s>]/g)) {
      if (!attrIds.has(attr[1])) attrIds.set(attr[1], []);
      attrIds.get(attr[1]).push(idMatch[1]);
    }
  }
}

// The document's tree, such as it is: parent links and child lists, kept
// truthful by appendChild/insertBefore/removeChild below.
function detach(node) {
  const parent = node && node.parentNode;
  if (!parent || !Array.isArray(parent.children)) return;
  const at = parent.children.indexOf(node);
  if (at >= 0) parent.children.splice(at, 1);
}

// MutationObserver, childList only, delivered synchronously.
//
// The real one batches into a microtask; this fires on the spot, which a
// gate can assert against without awaiting. That is a deliberate difference
// and it is the safe direction: code that works when records arrive
// immediately also works when they arrive a tick later, and the chrome's
// use of it -- sweeping a late-appended button into the sidebar -- is
// idempotent either way.
const observers = [];
function notifyAdded(parent, node) {
  for (const obs of observers) {
    if (obs.target !== parent) continue;
    obs.fn(
      [
        {
          type: "childList",
          target: parent,
          addedNodes: [node],
          removedNodes: [],
        },
      ],
      obs,
    );
  }
}
class MutationObserverStub {
  constructor(fn) {
    this.fn = fn;
    this.target = null;
  }
  observe(target) {
    this.target = target;
    observers.push(this);
  }
  disconnect() {
    const at = observers.indexOf(this);
    if (at >= 0) observers.splice(at, 1);
  }
  takeRecords() {
    return [];
  }
}

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
    // A plain property bag that ALSO answers setProperty/getPropertyValue.
    //
    // Both shapes are used against it: integrity.js and update.js write
    // `el.style.display` directly, and chrome.js publishes its measurements
    // as CSS custom properties. The bag was untyped before, so the second
    // shape threw "setProperty is not a function" -- from inside a deferred
    // callback, which in node takes the whole gate process with it.
    //
    // Recorded rather than discarded, for the same reason the document
    // listeners are: `--chrome-left-px` and `--chrome-closed-px` are how the
    // chrome tells the stylesheet what it measured, and a gate that cannot
    // read them cannot assert that a layout reported itself correctly.
    style: {
      setProperty(k, v) {
        this[k] = String(v);
      },
      getPropertyValue(k) {
        return typeof this[k] === "string" ? this[k] : "";
      },
      removeProperty(k) {
        delete this[k];
      },
    },
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
    // MOVING A NODE DETACHES IT FIRST, the way a real DOM does.
    //
    // These used to push unconditionally, so a node appended to a second
    // parent was a child of both -- which is not a state a browser can be
    // in, and it made the one behaviour worth testing untestable: the
    // toolbar-placement feature MOVES its buttons between two containers,
    // and a gate asking "where is #btn-vault now" would have been told
    // "both". Detaching also feeds the observer below a truthful record.
    appendChild(c) {
      detach(c);
      this.children.push(c);
      c.parentNode = this;
      notifyAdded(this, c);
      return c;
    },
    insertBefore(c, ref) {
      detach(c);
      const at = ref ? this.children.indexOf(ref) : -1;
      if (at < 0) this.children.push(c);
      else this.children.splice(at, 0, c);
      c.parentNode = this;
      notifyAdded(this, c);
      return c;
    },
    removeChild(c) {
      detach(c);
      return c;
    },
    replaceChildren(...c) {
      this.children = c;
    },
    remove() {},
    // `.class` and `#id` against this element's own children, one level.
    //
    // Deliberately not a selector engine: it answers exactly the shape the
    // chrome uses to find a landmark inside a container it owns -- the
    // toolbar looking for its own `.toolbar-break` -- and returns null for
    // anything more, so a gate is never quietly told "no match" when the
    // truth is "not implemented".
    querySelector(sel) {
      return this.querySelectorAll(sel)[0] || null;
    },
    querySelectorAll(sel) {
      if (typeof sel !== "string") return [];
      const kids = Array.isArray(this.children) ? this.children : [];
      if (sel.startsWith(".")) {
        const want = sel.slice(1);
        return kids.filter(
          (c) =>
            (c.classList && c.classList.contains(want)) ||
            (typeof c.className === "string" &&
              c.className.split(/\s+/).includes(want)),
        );
      }
      if (sel.startsWith("#")) {
        const want = sel.slice(1);
        return kids.filter((c) => c.id === want);
      }
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

// #toolbar's children, seeded in SOURCE ORDER from the markup.
//
// Every element here existed already; what was missing was the fact that
// they are in a container, in an order. The toolbar-placement feature moves
// everything after `.toolbar-break` into the sidebar and back, and both
// halves of that -- which buttons move, and what order they return in --
// are only expressible against a real child list. Without this the gate can
// see thirteen buttons and nothing about where any of them is.
//
// Parsed rather than listed: a button added to the row later joins this by
// existing, exactly as it joins the real toolbar.
{
  const html = require("fs").readFileSync(process.env.HTML_PATH, "utf8");
  const header = html.slice(
    html.indexOf('<header id="toolbar"'),
    html.indexOf("</header>"),
  );
  const bar = els.get("toolbar");
  if (bar && header) {
    // DIRECT children only, which needs the nesting tracked: `#vault-dot` is
    // a span inside `#btn-vault`, and seeding it as a sibling would make the
    // toolbar's own child list disagree with the markup -- and then the
    // placement code, which moves whatever is after the row break, would
    // move a button's insides out from under it.
    let depth = 0;
    const body = header.slice(header.indexOf(">") + 1);
    for (const tag of body.matchAll(/<(\/?)([a-z]+)\b([^>]*)>/g)) {
      const [, closing, name, attrs] = tag;
      const selfClosing =
        /\/$/.test(attrs) || name === "input" || name === "img";
      if (closing) {
        depth -= 1;
        continue;
      }
      if (depth === 0) {
        const id = (attrs.match(/id="([a-z0-9_-]+)"/) || [])[1];
        const isBreak = /class="[^"]*\btoolbar-break\b/.test(attrs);
        // The break carries no id in the markup; chrome.js and the gate both
        // find it by class, so it needs an element that answers to that.
        const el = isBreak ? mkEl("toolbar-break") : id ? els.get(id) : null;
        if (el) {
          if (isBreak) el.className = "toolbar-break";
          bar.children.push(el);
          el.parentNode = bar;
        }
      }
      if (!selfClosing) depth += 1;
    }
  }
}

global.MutationObserver = MutationObserverStub;
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
  querySelector: (sel) => global.document.querySelectorAll(sel)[0] || null,
  // Attribute selectors only, resolved against the real markup plus anything
  // the chrome has since set the attribute on itself. Anything else returns
  // empty, exactly as before -- a gate that needs a richer selector should
  // teach this deliberately rather than get a silently wrong answer.
  querySelectorAll: (sel) => {
    const attr = typeof sel === "string" && sel.match(/^\[([a-z0-9-]+)\]$/);
    if (!attr) return [];
    const seeded = (attrIds.get(attr[1]) || [])
      .map((id) => els.get(id))
      .filter(Boolean);
    const dynamic = allEls.filter(
      (el) =>
        el.hasAttribute && el.hasAttribute(attr[1]) && !seeded.includes(el),
    );
    return seeded.concat(dynamic);
  },
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
