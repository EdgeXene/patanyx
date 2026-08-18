// Premium controls render LOCKED, and a locked VAULT never reads as "buy it".
//
// The rule this exists for is the one that is easy to get wrong and awful
// when wrong: the licence session dies with the vault, so a PAYING customer
// whose vault is closed is indistinguishable from a free user to the gate.
// That is correct for gating and catastrophic for copy, because the honest
// version of "you have no licence" is "buy one". This gate pins that the
// locked state gets its own sentence, and that no wording anywhere offers a
// purchase while nothing is for sale.
//
// It also pins the affordance itself: dimmed but still reachable. Using the
// `disabled` property would drop the control out of the focus order, so a
// keyboard user could never reach the thing that explains why it is
// unavailable.
//
// Proven against planted defects when it landed: folding "locked" into the
// free branch fails check 2; using `disabled` instead of aria-disabled fails
// check 4; ignoring on_sale fails check 3.
//
// Guard shape: chrome-js-gate.sh refuses to run this file when no
// [data-premium] control is left in index.html, so removing the marking
// cannot silently retire the gate.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

new Function(chromeJs)();

const doc = global.document;
const gated = () => doc.querySelectorAll("[data-premium]");
// The toolbar refreshes on every vault transition; firing the lock event is
// the transition the chrome always hears from Rust.
const setState = async (status) => {
  global.rbResolve.premium_status = status;
  global.window.__rb_event({ event: "vault_locked", data: {} });
  await flush();
};

check("at least one control is marked, or this gate proves nothing", () => {
  assert(gated().length > 0, "no [data-premium] controls found in index.html");
});

check("a locked VAULT is told to unlock, never told to buy", async () => {
  await setState({ state: "locked", premium: false, on_sale: false });
  const el = gated()[0];
  const title = (el.getAttribute("title") || "").toLowerCase();
  assert(
    /unlock/.test(title),
    "a locked vault must be told to unlock, got: " + title,
  );
  for (const word of ["upgrade", "buy", "purchase", "renew"]) {
    assert(
      !title.includes(word),
      "a locked vault must never be told to " + word + ": " + title,
    );
  }
});

check("nothing offers a purchase while nothing is for sale", async () => {
  for (const state of ["free", "lapsed"]) {
    await setState({ state, premium: false, on_sale: false });
    const title = (gated()[0].getAttribute("title") || "").toLowerCase();
    for (const word of ["upgrade", "buy", "purchase", "renew"]) {
      assert(
        !title.includes(word),
        `state ${state} offered "${word}" while on_sale is false: ${title}`,
      );
    }
    assert(title.length > 0, `state ${state} said nothing at all`);
  }
});

check(
  "a locked control stays reachable and is marked, not disabled",
  async () => {
    await setState({ state: "free", premium: false, on_sale: false });
    for (const el of gated()) {
      assert(
        el.getAttribute("aria-disabled") === "true",
        "a locked control must carry aria-disabled",
      );
      assert(
        el.disabled !== true,
        "the disabled PROPERTY drops the control out of the focus order, so " +
          "nobody can reach the explanation of why it is locked",
      );
      assert(
        el.classList.contains("premium-locked"),
        "a locked control must carry the locked class the CSS dims",
      );
    }
  },
);

check(
  "a licence unlocks every marked control and restores its words",
  async () => {
    // Behavioral, not value-exact: the stub does not seed titles from the
    // markup, so this pins the property that matters either way. Locked, the
    // control explains itself; unlocked, the note is GONE rather than left
    // sitting on a working button.
    await setState({ state: "free", premium: false, on_sale: false });
    const note = gated()[0].getAttribute("title");
    assert(note && note.length > 0, "a locked control must say why");
    await setState({ state: "perpetual", premium: true, on_sale: false });
    for (const el of gated()) {
      assert(
        !el.classList.contains("premium-locked"),
        "a licensed control must not stay dimmed",
      );
      assert(
        el.getAttribute("aria-disabled") === null,
        "a licensed control must not stay aria-disabled",
      );
    }
    assert(
      gated()[0].getAttribute("title") !== note,
      "unlocking must restore the control's own description, not leave the " +
        "lock note behind: got " +
        gated()[0].getAttribute("title"),
    );
  },
);

check("when Premium IS on sale the wording may name it", async () => {
  await setState({ state: "free", premium: false, on_sale: true });
  const title = (gated()[0].getAttribute("title") || "").toLowerCase();
  assert(
    /upgrade|premium/.test(title),
    "an on-sale free state should name Premium: " + title,
  );
  // A lapsed customer is not a new customer and must not be pitched as one.
  await setState({ state: "lapsed", premium: false, on_sale: true });
  const lapsed = (gated()[0].getAttribute("title") || "").toLowerCase();
  assert(
    /renew|ended/.test(lapsed),
    "a lapsed licence should speak of renewing, not first-time buying: " +
      lapsed,
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL: " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error(
      "premium-toolbar-gate: " + failures.length + " check(s) failed",
    );
    process.exit(1);
  }
  console.log("premium-toolbar-gate OK (" + checks.length + " checks)");
})();
