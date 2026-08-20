// What the fill actually does to a page, exercised against real page SHAPES.
//
// WHY THIS EXISTS. autofill.js was covered only by a grep for `fetch` -- a
// static check that it does not open a network channel. Nothing ever ran it.
// It shipped twice with the fill silently doing nothing on the page it is
// most wanted on, and both times the symptom was identical and unhelpful: a
// lit button, a click, and no change on screen.
//
// The defect was structural, not a typo. The username lookup was scoped to
// the password field's <form>, and accounts.google.com has NO form element at
// all -- so `usernameField(null)` returned null on its first line and the
// email was never filled, while the password went into Google's zero-area
// staged input where nobody could see it.
//
// So the fixtures below are page shapes, not unit inputs:
//
//   google    no <form> anywhere, one visible text box, one zero-area
//             password, one zero-area text decoy. Measured from the live
//             page on 2026-08-01, not imagined.
//   ordinary  a normal login <form>, plus an unrelated search box OUTSIDE it
//             that must never receive the username.
//   stepped   a first step with no password field in the DOM at all.
//
// Run: node scripts/content-autofill-gate.js  (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const SRC = path.join(
  __dirname,
  "..",
  "crates/app/src/content_scripts/autofill.js",
);

const failures = [];
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// ---- a DOM just wide enough for what autofill.js touches -------------------
//
// Deliberately NOT jsdom: this gate has to be runnable with no dependency
// beyond node, the same as every other gate in this suite.
function mkInput(spec, formEl) {
  const el = {
    _attrs: { type: spec.type || "text" },
    name: spec.name || "",
    // The value lives in ONE backing field, reached through an accessor,
    // exactly as a real element's does. That is what lets the prototype
    // setter below write a field whose own accessor a framework has
    // replaced -- with a plain data property here, a prototype write would
    // be shadowed and this gate would measure nothing.
    _raw: spec.value || "",
    _w: spec.hidden ? 0 : 200,
    _h: spec.hidden ? 0 : 30,
    form: formEl || null,
    events: [],
    getAttribute(k) {
      return Object.prototype.hasOwnProperty.call(this._attrs, k)
        ? this._attrs[k]
        : null;
    },
    getBoundingClientRect() {
      return { width: this._w, height: this._h };
    },
    closest(sel) {
      return sel === "form" ? this.form : null;
    },
    dispatchEvent(e) {
      this.events.push(e.type);
      return true;
    },
    focus() {
      this.focused = true;
    },
  };
  Object.defineProperty(el, "value", {
    configurable: true,
    get() {
      return el._raw;
    },
    set(v) {
      el._raw = v;
    },
  });
  return el;
}

// A field belonging to a React-class form.
//
// The framework installs a per-ELEMENT `value` accessor that shadows the
// prototype's and remembers every write it sees. That memory is the bug:
// when a synthetic `input` event arrives, the framework compares what the
// tracker last recorded against the current value, concludes nothing
// changed, and throws the event away -- so the box shows the password and
// the form still refuses it. Writing through the PROTOTYPE setter leaves
// `trackerSaw` untouched, which is exactly what this fixture measures.
function withTracker(el) {
  el.trackerSaw = null;
  Object.defineProperty(el, "value", {
    configurable: true,
    get() {
      return el._raw;
    },
    set(v) {
      el.trackerSaw = v;
      el._raw = v;
    },
  });
  return el;
}

function mkScope(inputs) {
  return {
    querySelectorAll(sel) {
      if (sel === "input") return inputs;
      if (sel === 'input[type="password"]') {
        return inputs.filter((i) => i.getAttribute("type") === "password");
      }
      throw new Error("fixture does not implement selector: " + sel);
    },
    querySelector(sel) {
      return this.querySelectorAll(sel)[0] || null;
    },
  };
}

// Loads a FRESH copy of autofill.js against a fixture and returns a `fill`
// function that drives the real message handler.
function load(fixture) {
  let handler = null;
  const sandbox = {
    window: {
      chrome: {
        webview: {
          addEventListener(ev, fn) {
            if (ev === "message") handler = fn;
          },
          postMessage() {},
        },
      },
    },
    document: Object.assign(mkScope(fixture.inputs), {
      addEventListener() {},
    }),
    Event: function (type) {
      this.type = type;
    },
  };
  // The real page's HTMLInputElement.prototype value setter, which writes
  // the field WITHOUT going through any per-element tracker a framework
  // installed on top of it. autofill.js reaches this through
  // window.HTMLInputElement, the same way it would in a document.
  function HTMLInputElement() {}
  Object.defineProperty(HTMLInputElement.prototype, "value", {
    configurable: true,
    get() {
      return this._raw;
    },
    set(v) {
      this._raw = v;
    },
  });
  if (!fixture.noInputPrototype) {
    sandbox.window.HTMLInputElement = HTMLInputElement;
  }
  sandbox.window.top = sandbox.window;

  const src = fs.readFileSync(SRC, "utf8");
  new Function("window", "document", "Event", src)(
    sandbox.window,
    sandbox.document,
    sandbox.Event,
  );
  assert(handler, "autofill.js never registered a message listener");
  return (username, password) =>
    handler({ data: { kind: "fill_credential", username, password } });
}

const CASES = [];
function check(name, fn) {
  CASES.push([name, fn]);
}

// ---- the page that broke it ------------------------------------------------
check("google's formless sign-in gets the email in its visible box", () => {
  const identifier = mkInput({ name: "identifier" });
  const hiddenPw = mkInput({
    name: "hiddenPassword",
    type: "password",
    hidden: true,
  });
  const decoy = mkInput({ name: "ca", hidden: true });
  const fill = load({ inputs: [identifier, hiddenPw, decoy] });

  fill("someone@example.com", "hunter2");

  assert(
    identifier.value === "someone@example.com",
    "the VISIBLE email box is still empty after a fill -- this is exactly " +
      'the "it does nothing when I click it" report. Got: "' +
      identifier.value +
      '"',
  );
  assert(
    decoy.value === "",
    "the zero-area decoy input was filled instead of the real one; on the " +
      "live page that is invisible and reads as nothing happening",
  );
  assert(
    identifier.events.includes("input"),
    "the field was set without an input event, so a page watching for typing " +
      "never learns the value arrived",
  );
});

// ---- and the shape that must not regress ----------------------------------
check("an ordinary login form fills inside the form, not the page", () => {
  const form = {};
  const user = mkInput({ name: "user" }, form);
  const pw = mkInput({ name: "pw", type: "password" }, form);
  const search = mkInput({ name: "q" }); // outside the form
  form.querySelectorAll = (sel) =>
    sel === "input" ? [user, pw] : [pw].filter((i) => sel.includes("password"));

  const fill = load({ inputs: [search, user, pw] });
  fill("alice", "hunter2");

  assert(
    user.value === "alice",
    "the form's own username field was not filled",
  );
  assert(pw.value === "hunter2", "the password field was not filled");
  assert(
    search.value === "",
    "the username was typed into a search box OUTSIDE the login form -- " +
      "widening the scope past the form must only happen when there is no form",
  );
});

check("a step with no password field still fills the username", () => {
  const identifier = mkInput({ name: "email" });
  const fill = load({ inputs: [identifier] });
  fill("alice@example.com", "hunter2");
  assert(
    identifier.value === "alice@example.com",
    "a missing password field aborted the whole fill, so the first step of " +
      "every two-step login does nothing",
  );
});

check("a visible password field is preferred over a staged one", () => {
  const user = mkInput({ name: "email" });
  const staged = mkInput({
    name: "hiddenPassword",
    type: "password",
    hidden: true,
  });
  const real = mkInput({ name: "password", type: "password" });
  const fill = load({ inputs: [user, staged, real] });
  fill("alice", "hunter2");
  assert(
    real.value === "hunter2" && staged.value === "",
    "the password went into the invisible staged field while a real one was " +
      "on screen",
  );
});

check(
  "a React-tracked form receives the fill as a real change (Crunchyroll)",
  () => {
    // THE BUG THIS PINS. Reported from Crunchyroll's login: the fill put
    // the credential in the boxes, and the form would not accept it -- the
    // submit stayed dead until it was retyped by hand. Plain `.value = x`
    // goes through the framework's per-element tracker, which then
    // recognises its own write and discards the input event, so the page's
    // state never learns anything was typed.
    const user = withTracker(mkInput({ name: "email" }));
    const pass = withTracker(mkInput({ name: "password", type: "password" }));
    const fill = load({ inputs: [user, pass] });
    fill("alice@example.com", "hunter2");

    // The value really is in the field.
    assert(
      user.value === "alice@example.com" && pass.value === "hunter2",
      "the tracked fields did not receive the credential",
    );
    // And it did NOT go through the tracker, which is what makes the event
    // that follows read as a genuine change.
    assert(
      user.trackerSaw === null && pass.trackerSaw === null,
      "the fill went through the page's own value tracker, so the framework " +
        "will discard the input event and the form will refuse the value",
    );
    // The page is still told, in the order a person would produce.
    assert(
      pass.events.join(",") === "input,change",
      "expected input then change, got: " + pass.events.join(","),
    );
    assert(user.focused === true, "the field was filled without being focused");
  },
);

check("a document with no HTMLInputElement still fills", () => {
  // The fallback must be exactly the old behaviour, never nothing: a page
  // that has deleted the descriptor, or an engine that does not expose it,
  // gets a plain assignment.
  const user = mkInput({ name: "email" });
  const pass = mkInput({ name: "password", type: "password" });
  const fill = load({ inputs: [user, pass], noInputPrototype: true });
  fill("alice", "hunter2");
  assert(
    user.value === "alice" && pass.value === "hunter2",
    "the fallback path did not fill the fields",
  );
});

for (const [name, fn] of CASES) {
  try {
    fn();
    console.log("  ok  " + name);
  } catch (e) {
    console.log("  FAIL " + name);
    failures.push([name, e.message]);
  }
}

if (failures.length) {
  console.error("\nCONTENT AUTOFILL GATE FAILED:\n");
  for (const [name, msg] of failures) {
    console.error("  - " + name + "\n      " + msg + "\n");
  }
  process.exit(1);
}
console.log("\nCONTENT AUTOFILL OK");
