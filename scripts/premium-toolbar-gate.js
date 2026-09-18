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

const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const ipcRs = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
const licenceRs = fs.readFileSync(
  path.join(root, "crates/app/src/licence_control.rs"),
  "utf8",
);
const purchaseRs = fs.readFileSync(
  path.join(root, "crates/app/src/premium_purchase.rs"),
  "utf8",
);
const callSite =
  'await rb("premium_purchase_open", { purchase: "patanyx" });';

// Planted-defect mode removes the real reachable call while retaining the
// button, renderer and all backend source. The on-sale behavior check below
// must fail; a source-only assertion would incorrectly pass this defect.
if (process.env.PATANYX_PREMIUM_OMIT_PURCHASE_CALLSITE) {
  if (!chromeJs.includes(callSite)) {
    throw new Error("cannot plant defect: Premium purchase call site spelling changed");
  }
  chromeJs = chromeJs.replace(callSite, "await Promise.resolve();");
}
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
const $ = global.$;
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

check("the Vault row has no purchase affordance while on_sale is false", async () => {
  global.rbResolve.licence_get = {
    row_head: "PATANYX Free",
    row_sub: "Free features always remain free.",
    purchase_copy: null,
    state: "free",
    has_token: false,
    activation: "not_needed",
    activation_busy: false,
  };
  global.window.__rb_event({ event: "licence_changed", data: {} });
  await flush();
  const buy = $("premium-buy");
  assert(buy.hidden, "the purchase control became visible before launch");
  assert(buy.textContent === "", "the hidden purchase control retained words");
});

check("when on_sale is true the reachable control sends only an identifier", async () => {
  const copyMatch = licenceRs.match(
    /PREMIUM_ON_SALE\.then_some\("([^"]+)"\)/,
  );
  assert(copyMatch, "licence_control.rs lost the Rust-worded purchase copy");
  const copy = copyMatch[1];
  assert(
    /open.+page.+buy.+premium license/i.test(copy),
    "the control does not plainly say it opens a purchase page: " + copy,
  );
  for (const forbidden of ["$", "£", "€", "unlock", "activate", "active now"]) {
    assert(
      !copy.toLowerCase().includes(forbidden.toLowerCase()),
      `the purchase control promises price or entitlement with "${forbidden}": ${copy}`,
    );
  }

  global.rbResolve.premium_status = {
    state: "free",
    premium: false,
    on_sale: true,
  };
  global.rbResolve.licence_get = {
    row_head: "PATANYX Free",
    row_sub: "Free features always remain free.",
    purchase_copy: copy,
    state: "free",
    has_token: false,
    activation: "not_needed",
    activation_busy: false,
  };
  global.window.__rb_event({ event: "licence_changed", data: {} });
  await flush();

  const buy = $("premium-buy");
  assert(!buy.hidden, "the purchase control stayed hidden after launch");
  assert(buy.disabled !== true, "the purchase control is not reachable");
  assert(buy._has("click"), "the purchase control has no click handler");
  assert(buy.textContent === copy, "chrome did not render Rust's copy verbatim");

  global.rbCalls.length = 0;
  buy.click();
  await flush();
  const opens = global.rbCalls.filter(
    (call) => call.cmd === "premium_purchase_open",
  );
  assert(
    opens.length === 1,
    "the reachable on-sale control made " + opens.length + " purchase calls",
  );
  const args = opens[0] && opens[0].args;
  assert(args && args.purchase === "patanyx", "the call lost its identifier");
  assert(
    Object.keys(args).length === 1,
    "the chrome sent more than the identifier: " + JSON.stringify(args),
  );
  assert(
    !JSON.stringify(args).includes("http"),
    "the chrome sent a URL: " + JSON.stringify(args),
  );
});

check("visibility and backend navigation are both bound to the launch flag", () => {
  assert(
    /pub fn purchase_copy\(\)[\s\S]*?PREMIUM_ON_SALE\.then_some/.test(
      licenceRs,
    ),
    "purchase_copy is not derived from PREMIUM_ON_SALE",
  );
  const start = ipcRs.indexOf('"premium_purchase_open" =>');
  const end = ipcRs.indexOf("\n        //", start);
  const arm = start >= 0 && end > start ? ipcRs.slice(start, end) : "";
  assert(arm, "the premium_purchase_open IPC arm is missing");
  for (const proof of [
    "!crate::licence_control::PREMIUM_ON_SALE",
    "crate::premium_purchase::destination_for(args)?",
    "state.new_tab(&url, true)?",
  ]) {
    assert(arm.includes(proof), "purchase IPC lost: " + proof);
  }
  assert(
    purchaseRs.includes('.get("purchase")') &&
      purchaseRs.includes("crate::state::is_allowed_content_url(&normalized)"),
    "the identifier no longer resolves through the ordinary URL allowlist",
  );
});

// The purchase destination is never hardcoded in the chrome: it resolves
// through Rust (premium_purchase::destination_for, then the ordinary URL
// allowlist), so no asset can offer a sale while nothing is for sale.
//
// NARROWED ONCE, for offline activation, and the narrowing is the smaller
// half of this check rather than a hole in it. `patanyx.net/premium/offline`
// is where somebody who ALREADY PAID turns a device ID into a receipt from a
// network that blocks EdgeXene. It is an instruction to read, not an
// affordance to click -- so the exemption is granted ONLY to that exact path,
// and only while it stays inert: plain text, in index.html, never behind an
// href and never handed to navigation. A buy link cannot hide behind it,
// because "patanyx.net/premium" followed by anything else still fails.
const OFFLINE_ACTIVATION = "patanyx.net/premium/offline";
check("the chrome contains no Premium destination in any state", () => {
  const assets = fs
    .readdirSync(chromeDir)
    .filter((name) => /\.(?:css|html|js)$/.test(name));
  for (const name of assets) {
    const source = fs.readFileSync(path.join(chromeDir, name), "utf8");
    // Every occurrence must be the activation path EXACTLY. A longer string
    // that merely starts with it (…/premium/offline-buy) is not exempt.
    for (const hit of source.match(/patanyx\.net\/premium[^\s"'<)]*/g) || []) {
      assert(
        hit === OFFLINE_ACTIVATION,
        name + " contains the Premium destination: " + hit,
      );
    }
    if (!source.includes(OFFLINE_ACTIVATION)) continue;
    // The exemption's conditions, asserted rather than assumed.
    assert(
      name === "index.html",
      "the offline-activation address appears in " +
        name +
        ". It is exempt as static instruction text in the markup; in a script " +
        "or a stylesheet it is something else, and something else is not exempt",
    );
    assert(
      !/href\s*=\s*["'][^"']*patanyx\.net\/premium/.test(source),
      "the offline-activation address is inside an href. The exemption covers " +
        "text a person reads and types elsewhere, not a link the chrome can " +
        "navigate to -- a clickable Premium destination is the exact thing " +
        "this check exists to keep out",
    );
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

check("stored-token removal is distinct, confirmed, and honest about slots", async () => {
  global.rbResolve.vault_status = { exists: true, unlocked: true };
  global.rbResolve.licence_get = {
    row_head: "Premium active",
    row_sub: "Time left: 30 days.",
    state: "active",
    has_token: true,
    activation: "activated",
    activation_busy: false,
  };
  global.rbResolve.licence_remove = {};
  global.rbCalls.length = 0;
  // Re-open even if startup already put the panel there: the reply above was
  // installed after chrome.js booted, and onOpen is the real refresh path.
  if (!$("vault-panel").hidden) $("btn-vault").click();
  $("btn-vault").click();
  await flush();

  const remove = $("premium-remove");
  const release = $("premium-release");
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  const copy = html.match(/id="premium-token-actions"[^>]*>([\s\S]*?)<\/p>/);
  const distinction = copy ? copy[1].replace(/<[^>]+>/g, " ").toLowerCase() : "";
  assert(!remove.hidden, "a stored token has no remove control");
  assert(!release.hidden, "an activated device lost its separate release control");
  assert(!$("premium-token-actions").hidden, "the distinction copy stayed hidden");
  assert(
    /release/.test(distinction) && /keeps? the token/.test(distinction),
    "the visible copy does not say release keeps the token: " + distinction,
  );
  assert(
    /remove/.test(distinction) && /does not return/.test(distinction),
    "the visible copy does not say remove leaves the server slot alone: " +
      distinction,
  );

  remove.click();
  await flush();
  assert(
    global.rbCalls.every((call) => call.cmd !== "licence_remove"),
    "the first click removed the token without confirmation",
  );
  const warning = $("confirm-text").textContent.toLowerCase();
  assert(
    warning.includes("does not release") && warning.includes("slot will stay in use"),
    "activated removal did not explain the stranded slot: " + warning,
  );

  $("confirm-cancel").click();
  await flush();
  assert(
    global.rbCalls.every((call) => call.cmd !== "licence_remove"),
    "cancelling removal still erased the token",
  );

  remove.click();
  await flush();
  $("confirm-yes").click();
  await flush();
  const removals = global.rbCalls.filter((call) => call.cmd === "licence_remove");
  assert(removals.length === 1, "confirmed removal did not reach licence_remove once");
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
