// The duplicate-site notice: what it shows, what its three buttons send, and
// that it stays on screen until the user chooses.
//
// The rules about WHEN it shows live in Rust (crates/app/src/duplicate_site.rs)
// and are tested there. This gate covers the half Rust cannot: the chrome.
// What makes it worth a gate rather than a look:
//
// - The buttons must name the NOTICE and nothing else. A click that sent a tab
//   id or a site would let a queued click act on whatever that id points at
//   by the time it lands (plan review R-002).
// - The notice is a choice, so it must not expire on the 15 s timer and must
//   not be the one pushed out when ordinary notices pile up (R-005).
// - "Dismiss" replaces the X; there is not a fourth control doing the same.
//
// Run: node scripts/duplicate-site-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

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

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
new Function(chromeJs)();

// The labels a user reads, from the REAL catalog: a gate that restated them
// would pass after the catalog changed under it.
const ftl = fs.readFileSync(
  path.join(chromeDir, "i18n/locales/en.ftl"),
  "utf8",
);
function ftlValue(id) {
  const m = ftl.match(new RegExp("^" + id + " = (.*)$", "m"));
  if (!m) throw new Error("en.ftl is missing " + id);
  return m[1];
}
const LABELS = {
  switch: ftlValue("chrome-js-duplicate-site-switch"),
  close: ftlValue("chrome-js-duplicate-site-close"),
  dismiss: ftlValue("chrome-js-toast-dismiss"),
};
// Composed the way Rust composes it (isolation marks included).
const BODY = "⁨google.com⁩ is already open in another tab.";

const host = () => global.$("toasts");
const notices = () =>
  host().children.filter((n) => n.dataset && n.dataset.noticeId);
function show(noticeId) {
  global.window.__rb_event({
    event: "duplicate_site",
    data: {
      notice_id: noticeId,
      tab_id: 2,
      other_id: 1,
      site: "google.com",
      body: BODY,
    },
  });
}
function retire(noticeId) {
  global.window.__rb_event({
    event: "duplicate_site_retired",
    data: { notice_id: noticeId },
  });
}
function buttonsOf(node) {
  const row = node.children.find((c) => c.className === "toast-actions");
  return row ? row.children : [];
}
function reset() {
  host().children = [];
  global.rbCalls.length = 0;
  global.rbReject = null;
  delete global.rbResolve.duplicate_site_action;
}

check("the notice shows the sentence Rust composed, verbatim", () => {
  reset();
  show(1);
  const [n] = notices();
  assert(n, "no notice appeared for a duplicate_site event");
  const text = n.children.find((c) => c.className === "toast-text");
  assert(
    text && text.textContent === BODY,
    "the notice did not render the body verbatim",
  );
  retire(1);
});

check("three buttons, in order, and no X beside them", () => {
  reset();
  show(2);
  const [n] = notices();
  const labels = buttonsOf(n).map((b) => b.textContent);
  assert(
    JSON.stringify(labels) ===
      JSON.stringify([LABELS.switch, LABELS.close, LABELS.dismiss]),
    "expected Switch, Close, Dismiss; got " + JSON.stringify(labels),
  );
  assert(
    buttonsOf(n).every((b) => b.tagName === "BUTTON" && b.type === "button"),
    "every choice must be a real <button type=button>",
  );
  assert(
    !n.children.some((c) => c.className === "toast-close"),
    "the notice still carries the generic X; Dismiss replaces it",
  );
  retire(2);
});

for (const [index, choice] of [
  [0, "switch"],
  [1, "close"],
  [2, "dismiss"],
]) {
  check(
    choice + " sends the notice id and the choice, nothing else",
    async () => {
      reset();
      show(10 + index);
      const [n] = notices();
      buttonsOf(n)[index].click();
      await flush();
      const sent = global.rbCalls.filter(
        (c) => c.cmd === "duplicate_site_action",
      );
      assert(
        sent.length === 1,
        "expected one duplicate_site_action, got " + sent.length,
      );
      const keys = Object.keys(sent[0].args).sort();
      assert(
        JSON.stringify(keys) === '["choice","notice_id"]',
        "the click must name only the notice and the choice; it sent " +
          JSON.stringify(sent[0].args),
      );
      assert(sent[0].args.notice_id === 10 + index, "wrong notice id");
      assert(
        sent[0].args.choice === choice,
        "wrong choice: " + sent[0].args.choice,
      );
      assert(
        !global.rbCalls.some(
          (c) => c.cmd === "tab_switch" || c.cmd === "tab_close",
        ),
        "the notice must not drive tab_switch/tab_close directly",
      );
      assert(notices().length === 0, "the notice stayed up after a choice");
    },
  );
}

check("it registers no expiry timer", () => {
  reset();
  const delays = [];
  const realTimeout = global.setTimeout;
  global.setTimeout = (fn, ms) => {
    delays.push(ms);
    return 0;
  };
  try {
    show(20);
  } finally {
    global.setTimeout = realTimeout;
  }
  assert(
    !delays.includes(15000),
    "showing the notice armed the 15 s expiry; a choice must wait for the user",
  );
  assert(notices().length === 1, "the notice is gone");
  retire(20);
});

check("ordinary notices make room first", () => {
  reset();
  show(30);
  for (let i = 0; i < 3; i += 1)
    global.window.__rb_toast("Saved file " + i + ".pdf");
  assert(
    notices().length === 1,
    "three ordinary notices pushed the choice off screen",
  );
  assert(host().children.length === 3, "the cap of three no longer holds");
  retire(30);
});

check("a retire for this notice removes it; one for another does not", () => {
  reset();
  show(40);
  retire(41);
  assert(
    notices().length === 1,
    "a retire for a different notice removed this one",
  );
  retire(40);
  assert(
    notices().length === 0,
    "the retire for this notice did not remove it",
  );
});

check("a new notice replaces the old one", () => {
  reset();
  show(50);
  show(51);
  const ids = notices().map((n) => n.dataset.noticeId);
  assert(
    JSON.stringify(ids) === '["51"]',
    "expected only notice 51; got " + JSON.stringify(ids),
  );
  retire(51);
});

check("a stale refusal is silent; any other refusal is reported", async () => {
  reset();
  global.rbResolve.duplicate_site_action = new Error("stale");
  show(60);
  buttonsOf(notices()[0])[0].click();
  await flush();
  assert(
    !host().children.some((n) => String(n.className).includes("error")),
    "a stale click produced an error notice; nothing happened, so nothing needs saying",
  );
  reset();
  global.rbResolve.duplicate_site_action = new Error("not_found");
  show(61);
  buttonsOf(notices()[0])[1].click();
  await flush();
  assert(
    host().children.some((n) => String(n.className).includes("error")),
    "a real refusal was swallowed",
  );
  reset();
});

check("a malformed event shows nothing", () => {
  reset();
  global.window.__rb_event({ event: "duplicate_site", data: {} });
  global.window.__rb_event({ event: "duplicate_site", data: { notice_id: 1 } });
  global.window.__rb_event({ event: "duplicate_site" });
  assert(
    host().children.length === 0,
    "an event without an id and a body raised a notice",
  );
});

check("the setting sends its value and wears the reply", async () => {
  reset();
  // The reply DIFFERS from what the user clicked, so the last assertion can
  // only pass if the chrome applies Rust's answer (code review R-003).
  global.rbResolve.duplicate_notice_set = { enabled: false };
  const box = global.$("duplicate-notice");
  assert(box, "index.html has no #duplicate-notice switch");
  box.checked = true;
  box._fire("change", { target: box });
  await flush();
  const sent = global.rbCalls.filter((c) => c.cmd === "duplicate_notice_set");
  assert(
    sent.length === 1 && sent[0].args.enabled === true,
    "the switch did not send its value",
  );
  assert(
    box.checked === false,
    "the switch does not show the value Rust confirmed",
  );
  delete global.rbResolve.duplicate_notice_set;
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + "\n      " + e.message);
      console.log("  FAIL " + name);
    }
  }
  if (failures.length) {
    console.error("\nDUPLICATE-SITE GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nDUPLICATE-SITE NOTICE UI OK");
})();
