// The privacy panel's ledger: "Allow while frozen" and the Allowed rows
// (chrome.js renderLedger, allowHost, applyTabStatus).
//
// WHY THIS EXISTS. activeTabId was declared and never assigned, so the
// button returned before sending anything and no row could ever read
// Allowed, in every release up to 1.0.4, and no gate noticed because none
// clicked it. The Allowed rows now follow the hosts Rust says the freeze
// really lets through (tab status "allowed_hosts"), so an exception that
// failed to install on WebKitGTK is not shown as allowed.
//
// The rows belong to ONE tab. A ledger read before a tab switch, or
// answered after one, is another tab's request history, and an Allow click
// on it would grant that host to the tab now showing (release review of
// Allow while frozen, R-003). The toolbar button names and sends the same
// host (R-004), a row reads Allowed only once Rust reports it (R-005), and a
// frozen tab with exceptions does not claim "no network requests" (R-006).
//
// Proven against planted defects: each PATANYX_LEDGER_PLANT value below
// must make this gate FAIL (chrome-js-gate.sh runs them all).
//
// Run: node scripts/ledger-allow-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const PLANT = process.env.PATANYX_LEDGER_PLANT || "";
function plant(from, to) {
  if (chromeJs.split(from).length !== 2) {
    console.error("PLANT TARGET MISSING OR NOT UNIQUE: " + from);
    process.exit(2);
  }
  chromeJs = chromeJs.replace(from, to);
}
if (PLANT === "active") {
  plant('if (typeof st.id === "number") activeTabId = st.id;', "");
} else if (PLANT === "owner") {
  plant("if (ledgerTab === null || ledgerTab !== activeTabId) return;", "");
} else if (PLANT === "stale-click") {
  plant('if (!host || typeof tabId !== "number" || tabId !== activeTabId) return;', "if (!host) return;");
} else if (PLANT === "label") {
  plant('return typeof origin === "string" && /^[A-Za-z0-9.:-]+$/.test(origin) ? origin : "";', "return hostOf(urlInput.value);");
} else if (PLANT === "optimistic") {
  // What the chrome asked for, drawn as Allowed without waiting for Rust.
  plant(
    "        applyTabStatus(st);\n      })",
    "        allowedHosts.set(tabId, new Set([...(allowedHosts.get(tabId) || []), host]));\n        renderLedger(lastLedger);\n      })",
  );
} else if (PLANT === "wording") {
  plant("const hasAllowed = Array.isArray(st.allowed_hosts) && st.allowed_hosts.length > 0;", "const hasAllowed = false;");
} else if (PLANT) {
  console.error("unknown PATANYX_LEDGER_PLANT: " + PLANT);
  process.exit(2);
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

const $ = (id) => global.document.getElementById(id);
const fire = (event, data) => global.window.__rb_event({ event, data });
const calls = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);
const text = (n) => (n.textContent || "").trim();
function descendants(node) {
  const out = [];
  for (const c of node.children || []) {
    out.push(c, ...descendants(c));
  }
  return out;
}
const allowButtons = () =>
  descendants($("ledger-list")).filter(
    (n) => n.tagName === "BUTTON" && /Allow/.test(text(n)),
  );
const rowHosts = () =>
  descendants($("ledger-list"))
    .filter((n) => /item-title/.test(n.className || ""))
    .map(text);

function status(id, hosts, origin) {
  return {
    id,
    freeze_phase: "frozen",
    freeze_enforcement: "active",
    allowed_hosts: hosts,
    profile: "persistent",
    origin: origin || "news.example",
    tls: "secure",
    interception: "registered",
  };
}
const ledgerFor = (tab, host) => ({
  tab_id: tab,
  items: [{ host, allowed: 3, blocked: 0 }],
  counts_blocked: false,
});
const LEDGER = ledgerFor(7, "cdn.example");

check("the button sends the host for the tab on screen", async () => {
  global.rbResolve.tab_status = status(7, []);
  global.rbResolve.tab_ledger = LEDGER;
  fire("tab_status", status(7, []));
  $("btn-tab")._fire("click");
  await flush();
  const [btn] = allowButtons();
  assert(btn, "no Allow button in the ledger");
  assert(!btn.disabled && /Allow while frozen/.test(text(btn)), "button state: " + text(btn));
  global.rbCalls.length = 0;
  global.rbResolve.tab_allow_site = status(7, ["cdn.example"]);
  btn._fire("click");
  await flush();
  const sent = calls("tab_allow_site");
  assert(
    sent.length === 1 && sent[0].args.host === "cdn.example" && sent[0].args.tab === 7,
    "tab_allow_site not sent for tab 7: " + JSON.stringify(sent),
  );
});

check("a host Rust reports as allowed reads Allowed", async () => {
  const [btn] = allowButtons();
  assert(btn && btn.disabled && /Allowed/.test(text(btn)), "after the reply: " + (btn && text(btn)));
});

check("an exception Rust rolled back is not shown as allowed", async () => {
  fire("tab_status", status(7, []));
  await flush();
  const [btn] = allowButtons();
  assert(btn && !btn.disabled && /Allow while frozen/.test(text(btn)), "after the rollback: " + (btn && text(btn)));
});

check("a row is not marked Allowed before Rust reports it installed", async () => {
  // WebKitGTK: the reply comes back before the replacement filter compiles,
  // so its allowed_hosts does not list the host yet.
  global.rbResolve.tab_allow_site = status(7, []);
  const [btn] = allowButtons();
  btn._fire("click");
  await flush();
  const [after] = allowButtons();
  assert(after && !after.disabled && /Allow while frozen/.test(text(after)), "marked before install: " + text(after));
});

check("switching tabs: the new tab's status first, then its ledger", async () => {
  global.rbCalls.length = 0;
  global.rbResolve.tab_ledger = ledgerFor(8, "only-tab-b.example");
  fire("tab_status", status(8, []));
  assert(rowHosts().length === 0, "tab 7's rows drawn under tab 8: " + rowHosts());
  assert(calls("tab_ledger").length === 1, "the open panel did not ask for tab 8's ledger at once");
  await flush();
  assert(rowHosts().join() === "only-tab-b.example", "tab 8's rows: " + rowHosts());
  assert(!rowHosts().includes("cdn.example"), "tab 7's row is still there");
});

check("switching tabs: the old tab's ledger answering late is not drawn", async () => {
  global.rbResolve.tab_ledger = ledgerFor(8, "only-tab-b.example");
  fire("tab_status", status(7, []));
  await flush();
  // Tab 7 is active and tab 8's ledger was what came back.
  assert(rowHosts().length === 0, "tab 8's rows drawn under tab 7: " + rowHosts());
  global.rbResolve.tab_ledger = LEDGER;
  $("btn-tab")._fire("click");
  $("btn-tab")._fire("click");
  await flush();
  assert(rowHosts().join() === "cdn.example", "tab 7's own rows: " + rowHosts());
});

check("a row clicked after a switch allows nothing", async () => {
  const [stale] = allowButtons();
  assert(stale, "no tab 7 row to click");
  global.rbResolve.tab_ledger = ledgerFor(8, "only-tab-b.example");
  fire("tab_status", status(8, []));
  await flush();
  global.rbCalls.length = 0;
  stale._fire("click");
  await flush();
  assert(calls("tab_allow_site").length === 0, "tab 7's row allowed a host on tab 8: " + JSON.stringify(calls("tab_allow_site")));
});

check("each tab shows its own exceptions", async () => {
  global.rbResolve.tab_ledger = LEDGER;
  fire("tab_status", status(7, ["cdn.example"]));
  await flush();
  let [btn] = allowButtons();
  assert(btn && btn.disabled, "tab 7's exception not shown");
  global.rbResolve.tab_ledger = ledgerFor(8, "cdn.example");
  fire("tab_status", status(8, []));
  await flush();
  [btn] = allowButtons();
  assert(btn && !btn.disabled, "tab 8 shows tab 7's exception");
  global.rbResolve.tab_ledger = LEDGER;
  fire("tab_status", status(7, ["cdn.example"]));
  await flush();
  [btn] = allowButtons();
  assert(btn && btn.disabled, "tab 7 lost its exception on switching back");
});

check("the toolbar button names and sends the loaded site, not the typed one", async () => {
  fire("tab_status", status(7, [], "actual.example"));
  $("url").value = "https://desired.example/";
  fire("tab_status", status(7, [], "actual.example"));
  await flush();
  const btn = $("btn-allow-site");
  assert(/actual\.example/.test(text(btn)) && !/desired/.test(text(btn)), "label: " + text(btn));
  global.rbCalls.length = 0;
  btn._fire("click");
  await flush();
  const sent = calls("tab_allow_site");
  assert(
    sent.length === 1 && sent[0].args.host === "actual.example" && sent[0].args.tab === 7,
    "sent: " + JSON.stringify(sent),
  );
});

check("a frozen tab with an allowed site does not claim no network requests", async () => {
  fire("tab_status", status(7, ["cdn.example"]));
  await flush();
  const claims = [$("btn-freeze").title, text($("tab-freeze-desc"))];
  assert(claims.every((t) => /except to hosts you allowed/i.test(t)), "with an exception: " + JSON.stringify(claims));
  fire("tab_status", status(7, []));
  await flush();
  const plain = [$("btn-freeze").title, text($("tab-freeze-desc"))];
  assert(
    plain.every((t) => /no new network requests/i.test(t) && !/except/i.test(t)),
    "with none: " + JSON.stringify(plain),
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name);
      console.log("  FAIL " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.log("LEDGER ALLOW GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log("LEDGER ALLOW GATE OK (" + checks.length + " checks)");
})();
