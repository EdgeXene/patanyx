// "Allow ads and trackers on this tab", driven through the REAL chrome.js
// against the DOM stub.
//
// What this gate is for. The switch turns PATANYX's ad and tracker blocking
// OFF in one tab, so the things worth pinning are the ones that would make
// the chrome say less than the truth or ask Rust for more than the user did:
//
//   - the click sends `tab_ads_allow` for the tab the panel is SHOWING, by id,
//     and nothing that could choose the site;
//   - the box FOLLOWS tab_status: it never shows a state Rust did not report,
//     so an allowance Rust ended on navigation does not stay ticked;
//   - where it cannot be turned on (a Strict Tab, no site, blocking already
//     off everywhere, not ready) it is disabled and says why;
//   - the toolbar shield does not read as blocking in an allowed tab: no
//     blocked count (a zero reads as "nothing to block here"), ad blocking
//     not counted as a protection, and the sentence says it is off;
//   - the privacy receipt says blocking was off for the tab.
//
// Planted defects (PATANYX_ADS_PLANT): each must make this gate fail, which
// the wrapper in chrome-js-gate.sh checks. PATANYX_ADS_LIST_PLANTS=1 lists
// them.
//
// It executes chrome.js in scripts/domstub.js and drives the real tab_status
// event and the real privacy_get startup reply. It does not execute Rust, GTK
// or WebKit; the Rust side has its own tests.
"use strict";
const fs = require("fs");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");

const PLANTS = {
  // The click asks Rust for nothing.
  "no-send": [
    'rb("tab_ads_allow", { tab_id: st.id, allowed: wanted })',
    "Promise.resolve(st)",
  ],
  // The click names no tab.
  "no-tab-id": ["{ tab_id: st.id, allowed: wanted }", "{ allowed: wanted }"],
  // The box keeps what was clicked instead of what Rust last said.
  "follows-click": [
    "    box.checked = st.ads_allowed === true;\n    if (typeof st.id",
    "    if (typeof st.id",
  ],
  // tab_status no longer moves the box.
  "no-follow-status": ["    box.checked = allowed;\n", "\n"],
  // A Strict Tab's box stays live.
  "not-disabled": [
    "    box.disabled = !available;\n",
    "    box.disabled = false;\n",
  ],
  // The disabled box gives no reason.
  "no-reason": [
    "    reason.textContent = why;\n",
    '    reason.textContent = "";\n',
  ],
  // The shield ignores the allowance.
  "shield-ignores-allowance": [
    "const tabAllowed = st.ads_allowed === true;",
    "const tabAllowed = false;",
  ],
  // The badge goes back to counting blocked requests in an allowed tab.
  "badge-counts-blocked": [
    "const showBlocked = countsBlocked && tabBlocking;",
    "const showBlocked = countsBlocked && blockingActive;",
  ],
  // The receipt never says blocking was off.
  "no-receipt": [
    '$("receipt-ads-allowed").hidden = !allowed;',
    '$("receipt-ads-allowed").hidden = true;',
  ],
};
if (process.env.PATANYX_ADS_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}
let chromeSrc = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const plant = process.env.PATANYX_ADS_PLANT;
if (plant) {
  const p = PLANTS[plant];
  if (!p || !chromeSrc.includes(p[0])) {
    console.error(
      `plant ${plant}: anchor not found; the gate cannot prove anything`,
    );
    process.exit(2);
  }
  chromeSrc = chromeSrc.replace(p[0], p[1]);
}

process.env.HTML_PATH = htmlPath;
require(path.join(root, "scripts/domstub.js"));
const html = fs.readFileSync(htmlPath, "utf8");

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
    await new Promise((r) => setImmediate(r));
  }
};

// The stub's closest() finds nothing. The Privacy panel's setSupported needs
// the row of these two inputs, and without one applyPrivacyStatus throws
// before it counts protections, which is the input the shield checks need.
for (const id of ["pv-block-ads", "pv-freeze"]) {
  const row = global.document.createElement("label");
  global.$(id).closest = () => row;
}

// The browser-wide policy at startup: blocking on, so the shield has a
// protection to count and a blocked tally to show.
global.rbResolve.privacy_get = {
  block_ads: true,
  freeze_after_load: false,
  javascript: true,
  ephemeral: false,
  block_youtube_ads: true,
  network_blocking_supported: true,
  freeze_enforced: true,
  cookie_clear_available: true,
  forget_all: {
    intro: "i",
    warning: "w",
    button: "b",
    confirm: "c",
    cancel: "x",
  },
};

new Function(chromeSrc)();

// Exactly the shape `AppState::active_tab_status` emits for this feature.
function status(id, fields) {
  const data = Object.assign(
    {
      id,
      freeze_phase: "loaded",
      freeze_enforcement: "inactive",
      profile: "persistent",
      origin: "news.example",
      tls: "normal",
      freeze_enforced: true,
      network_blocking_supported: true,
      ledger_counts_blocked: true,
      blocked_total: 0,
      interception: "registered",
      script_setting: "applied",
      smartscreen_off: "applied",
      tracking_prevention: "strict",
      navigation_tracking: "applied",
      autofill_off: "applied",
      ephemeral_confirmed: "applied",
      hardened_environment: "applied",
      adlist_pending: null,
      adlist_override_host: null,
      ads_allowed: false,
      ads_allow_available: true,
      ads_allow_reason: null,
    },
    fields || {},
  );
  global.window.__rb_event({ event: "tab_status", data });
  return data;
}

const box = () => global.$("tab-ads-allow");
const reason = () => global.$("tab-ads-allow-reason");
const sent = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);

// ---- markup ------------------------------------------------------------

check(
  "the switch sits in Tab Activity's network section, with its note",
  () => {
    const net = html.indexOf(
      'data-msg="chrome.tab.panel.span">Network requests',
    );
    const storage = html.indexOf('data-msg="chrome.tab.panel.span.n2">Storage');
    const at = html.indexOf('id="tab-ads-allow"');
    assert(
      net !== -1 && storage !== -1,
      "the Network requests or Storage label moved",
    );
    assert(
      at > net && at < storage,
      "the switch is not in the Network requests section",
    );
    const row = html.slice(
      html.lastIndexOf("<label", at),
      html.indexOf("</label>", at),
    );
    assert(row.includes('type="checkbox"'), "the switch is not a checkbox");
    assert(
      row.includes("Allow ads and trackers on this tab"),
      "the label changed",
    );
    assert(
      row.includes("goes to another site or closes") &&
        row.includes("for this tab only"),
      "the note no longer says how long it lasts and how far it reaches",
    );
    assert(
      row.includes("still refuses sites reported for phishing or malware"),
      "the note dropped the harmful-site line",
    );
    assert(
      html.includes('id="receipt-ads-allowed"'),
      "the receipt has no line for an allowed tab",
    );
  },
);

// ---- behaviour ---------------------------------------------------------

check("the box follows tab_status, both ways", async () => {
  await flush();
  status(4, { ads_allowed: true });
  await flush();
  assert(box().checked === true, "an allowed tab's box is not ticked");
  status(4, { ads_allowed: false });
  await flush();
  assert(box().checked === false, "an allowance Rust ended is still ticked");
});

check(
  "a click sends tab_ads_allow for the tab on screen, and nothing else",
  async () => {
    status(7, { ads_allowed: false });
    await flush();
    global.rbCalls.length = 0;
    global.rbResolve.tab_ads_allow = Object.assign(
      {},
      global.rbResolve.tab_ads_allow,
    );
    box().checked = true;
    box()._fire("change");
    // Until Rust answers, the box shows what Rust last said.
    assert(
      box().checked === false,
      "the box took the click's value before Rust answered",
    );
    await flush();
    const calls = sent("tab_ads_allow");
    assert(
      calls.length === 1,
      `expected one tab_ads_allow, got ${calls.length}`,
    );
    const args = calls[0].args || {};
    assert(
      args.tab_id === 7,
      `the click named tab ${JSON.stringify(args.tab_id)}, not the tab on screen`,
    );
    assert(args.allowed === true, "the click did not ask to allow");
    assert(
      Object.keys(args).sort().join(",") === "allowed,tab_id",
      `the click sent more than the tab and the direction: ${JSON.stringify(args)}`,
    );
  },
);

check(
  "the reply moves the box, and turning it off sends allowed:false",
  async () => {
    global.rbResolve.tab_ads_allow = status(7, { ads_allowed: true });
    status(7, { ads_allowed: false });
    await flush();
    box().checked = true;
    box()._fire("change");
    await flush();
    assert(
      box().checked === true,
      "the reply saying allowed did not tick the box",
    );
    global.rbCalls.length = 0;
    global.rbResolve.tab_ads_allow = Object.assign(
      {},
      global.rbResolve.tab_ads_allow,
      { ads_allowed: false },
    );
    box().checked = false;
    box()._fire("change");
    await flush();
    const calls = sent("tab_ads_allow");
    assert(
      calls.length === 1 && calls[0].args.allowed === false,
      "turning it off did not send allowed:false",
    );
    assert(
      box().checked === false,
      "the reply saying not allowed left the box ticked",
    );
  },
);

check("a Strict Tab's box is disabled and says why", async () => {
  status(9, {
    ads_allow_available: false,
    ads_allow_reason: "ads_strict_tab",
    profile: "ephemeral",
  });
  await flush();
  assert(box().disabled === true, "a Strict Tab's box can be clicked");
  assert(box().checked === false);
  assert(reason().hidden === false, "the reason is hidden");
  assert(
    reason().textContent === "Strict Tabs always block ads and trackers.",
    `wrong reason: ${JSON.stringify(reason().textContent)}`,
  );
});

check("a frozen tab with ads allowed keeps the box ticked, disabled, and says why", async () => {
  status(11, {
    ads_allowed: true,
    ads_allow_available: false,
    ads_allow_reason: "ads_tab_frozen",
  });
  await flush();
  assert(box().checked === true, "the allowance on a frozen tab shows unticked");
  assert(box().disabled === true, "a frozen tab's box can be clicked");
  assert(
    reason().hidden === false &&
      reason().textContent ===
        "Unfreeze this tab first. Turning this on or off reloads the page.",
    `wrong reason: ${JSON.stringify(reason().textContent)}`,
  );
});

check(
  "every other reason is worded, and an available box hides it",
  async () => {
    for (const [code, words] of [
      ["ads_no_site", "This page has no site to allow them on."],
      [
        "ads_blocking_off",
        "Ad and tracker blocking is already off for every tab.",
      ],
      ["ads_not_ready", "Not available right now. Try again later."],
      [
        "ads_tab_frozen",
        "Unfreeze this tab first. Turning this on or off reloads the page.",
      ],
    ]) {
      status(10, { ads_allow_available: false, ads_allow_reason: code });
      await flush();
      assert(box().disabled === true, `${code}: the box can be clicked`);
      assert(
        reason().textContent === words,
        `${code}: ${JSON.stringify(reason().textContent)}`,
      );
    }
    status(10, {});
    await flush();
    assert(box().disabled === false, "an available box stayed disabled");
    assert(
      reason().hidden === true && reason().textContent === "",
      "an available box still shows a reason",
    );
  },
);

check("a refused click says why and asks Rust again", async () => {
  status(11, {});
  await flush();
  global.rbCalls.length = 0;
  global.rbResolve.tab_ads_allow = new Error("ads_not_ready");
  const before = global.$("toasts").children.length;
  box().checked = true;
  box()._fire("change");
  await flush();
  assert(box().checked === false, "a refused click left the box ticked");
  const notices = [...global.$("toasts").children].slice(before);
  const said = notices.map((n) => n.querySelector(".toast-text").textContent);
  assert(
    said.includes("Not available right now. Try again later."),
    `a refused click did not say why: ${JSON.stringify(said)}`,
  );
  assert(
    sent("tab_status").length >= 1,
    "a refused click did not ask for the status again",
  );
  delete global.rbResolve.tab_ads_allow;
});

check("the shield does not read as blocking in an allowed tab", async () => {
  // An ordinary tab first: blocking on, nothing blocked on this page.
  status(12, { ads_allowed: false, blocked_total: 0 });
  await flush();
  const btn = global.$("btn-privacy");
  const badge = global.$("privacy-count");
  assert(
    (btn.title || "").includes("Nothing blocked on this page"),
    `the control tab lost its blocked tally: ${btn.title}`,
  );
  assert(
    badge.hidden === false && badge.textContent === "0",
    "the control tab shows no blocked count",
  );
  // The same tab with ads allowed.
  status(12, { ads_allowed: true, blocked_total: 0 });
  await flush();
  const title = btn.title || "";
  assert(
    title.startsWith("PATANYX's ad and tracker list is off for this tab"),
    `the shield does not say blocking is off here: ${title}`,
  );
  assert(
    !title.includes("Nothing blocked on this page"),
    `the shield implies blocking: ${title}`,
  );
  assert(
    !title.includes("blocked on this page"),
    `the shield reports a blocked tally: ${title}`,
  );
  // Ad blocking must not be counted as a protection here, and the tooltip
  // must not claim there is no protection at all: sites reported for
  // phishing or malware are still refused (compliance audit, 2026-10-12).
  assert(
    !/\b\d+ protections? active/.test(title),
    `ad blocking is still counted: ${title}`,
  );
  assert(
    !title.includes("No protections active"),
    `the shield says nothing protects this tab: ${title}`,
  );
  assert(
    badge.hidden === true,
    `the badge still shows ${JSON.stringify(badge.textContent)}`,
  );
  assert(
    !btn.classList.contains("is-active"),
    "the shield is lit as protecting",
  );
  const aria = btn.getAttribute("aria-label") || "";
  assert(
    aria.includes("PATANYX's ad and tracker list is off for this tab"),
    "screen readers are not told",
  );
});

check(
  "the privacy receipt says blocking was off, and only in that tab",
  async () => {
    status(13, { ads_allowed: true });
    await flush();
    const line = global.$("receipt-ads-allowed");
    assert(
      line.hidden === false,
      "the receipt line is hidden in an allowed tab",
    );
    status(14, { ads_allowed: false });
    await flush();
    assert(
      line.hidden === true,
      "the receipt line stayed for a tab that blocks",
    );
  },
);

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log(`  ok  ${name}`);
    } catch (e) {
      failures.push(`${name}: ${e.message}`);
      console.log(`  FAIL  ${name}: ${e.message}`);
    }
  }
  console.log();
  if (failures.length) {
    console.error("TAB ADS ALLOW GATE FAIL:");
    for (const f of failures) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log("TAB ADS ALLOW UI OK");
})();
