// The ad-list hold, driven through the REAL chrome.js against the DOM stub.
//
// What this gate is for. The banner is a consent surface: the sentence on it
// is what the user agrees to, and the values sent back are what Rust acts on.
// So the things worth pinning are not "does it render" but:
//
//   - it follows the DISPLAYED tab, because it is rendered from an async
//     status push and a tab switch can land between the paint and the click;
//   - the click CONFIRMS what was shown (tab id, pending id, host) rather than
//     choosing anything, so no value the chrome can send names a URL that was
//     not already pending;
//   - a non-GET navigation says its form was not sent, BEFORE the click,
//     because consent resumes a URL and a URL has no body;
//   - it never borrows the malicious banner's vocabulary, which promises
//     subdomain coverage this feature deliberately does not grant.
//
// It executes chrome.js in scripts/domstub.js and drives the real tab_status
// event. It does not execute Rust, GTK or WebKit.

const fs = require("fs");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
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

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// Exactly the shape `AppState::active_tab_status` emits for this feature.
function status(tabId, pending, overrideHost) {
  global.window.__rb_event({
    event: "tab_status",
    data: {
      id: tabId,
      freeze_phase: "loaded",
      freeze_enforcement: "inactive",
      profile: "persistent",
      origin: "https://news.example",
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
      adlist_pending: pending || null,
      adlist_override_host: overrideHost || null,
    },
  });
}

const HOST = "ipaddress.com";

// ---- markup, before anything is driven ---------------------------------

check("the banner is its own element, not the malicious one", () => {
  assert(
    html.indexOf('id="adlist-warning"') !== -1,
    "#adlist-warning is missing; a variant of #blocked-warning would inherit " +
      "its danger styling and its vocabulary",
  );
  const start = html.indexOf('id="adlist-warning"');
  const end = html.indexOf("</div>", html.indexOf("banner-actions", start));
  const section = html.slice(start, end);
  assert(
    section.indexOf("danger") === -1,
    "the ad-list Open anyway carries the danger class, so a held page arrives " +
      "painted as a hazard and every sentence written to prevent that reading " +
      "is undone before it is read",
  );
});

check(
  "it is registered as a banner so it renders inside the clipped strip",
  () => {
    const js = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
    const start = js.indexOf("const BANNERS = [");
    const list = js.slice(start, js.indexOf("]", start));
    assert(
      list.indexOf('"adlist-warning"') !== -1,
      "adlist-warning is absent from BANNERS, so it draws outside the strip the " +
        "chrome webview is clipped to and is invisible: the lock-warning defect",
    );
  },
);

// ---- behaviour ---------------------------------------------------------

check("no pending means no banner", async () => {
  status(1, null, null);
  await flush();
  assert(global.$("adlist-warning").hidden === true);
});

check("a pending raises the banner and names the host Rust sent", async () => {
  status(1, { id: 7, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  assert(
    global.$("adlist-warning").hidden === false,
    "the banner did not open",
  );
  const body = global.$("adlist-body").textContent;
  assert(body.includes(HOST), "the banner does not name the host: " + body);
  assert(
    !body.includes("covers its subdomains"),
    "the banner promised subdomain coverage, which the exception does not grant",
  );
});

/// The reason the pending id exists.
check("switching to a tab with no pending takes the banner down", async () => {
  status(1, { id: 7, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  assert(global.$("adlist-warning").hidden === false, "precondition");
  status(2, null, null);
  await flush();
  assert(
    global.$("adlist-warning").hidden === true,
    "the previous tab's banner stayed on screen after the switch, so a click " +
      "would answer a banner belonging to a tab the user is not looking at",
  );
});

check(
  "Open anyway confirms the tab, the pending and the host it displayed",
  async () => {
    status(3, { id: 42, host: HOST, method: "GET", can_allow: true }, null);
    await flush();
    global.rbCalls.length = 0;
    global.$("adlist-allow")._fire("click");
    await flush();
    const call = global.rbCalls.find((c) => c.cmd === "adlist_allow");
    assert(call, "Open anyway called nothing");
    assert(
      call.args.tab_id === 3,
      "the wrong tab was named: " + call.args.tab_id,
    );
    assert(call.args.pending_id === 42, "the wrong pending was named");
    assert(call.args.host === HOST, "the wrong host was named");
    assert(
      !("url" in call.args),
      "the chrome sent a URL; it may confirm what it showed, never choose what " +
        "loads, or it becomes an open-anything primitive",
    );
  },
);

check("Dismiss names the same pending and grants nothing", async () => {
  status(3, { id: 43, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  global.rbCalls.length = 0;
  global.$("adlist-dismiss")._fire("click");
  await flush();
  const call = global.rbCalls.find((c) => c.cmd === "adlist_dismiss");
  assert(call, "Dismiss called nothing");
  assert(call.args.pending_id === 43);
  assert(
    !global.rbCalls.some((c) => c.cmd === "adlist_allow"),
    "Dismiss also allowed",
  );
});

/// Consent resumes a URL, and a URL has no body. The user must be told before
/// the click, not after it.
check("a non-GET navigation says the form was not sent", async () => {
  status(4, { id: 8, host: HOST, method: "POST", can_allow: true }, null);
  await flush();
  const body = global.$("adlist-body").textContent;
  assert(
    body.includes("form was not sent"),
    "a held form submission did not say the form was not sent, so the user " +
      "reads 'lets this tab reach the host' as 'my submission will go " +
      "through': " +
      body,
  );
});

check("a GET navigation does not mention a form", async () => {
  status(4, { id: 9, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  assert(!global.$("adlist-body").textContent.includes("form was not sent"));
});

// ---- a backend with no per-site exception ------------------------------
//
// On WebKitGTK the engine enforces with a compiled content filter and there is
// no way to except one host from it for one tab. The banner explains and
// points at the browser-wide switch; it does not offer a button the engine
// cannot honour.

check("with no exception available, Open anyway is absent rather than disabled", async () => {
  status(5, { id: 11, host: HOST, method: "GET", can_allow: false }, null);
  await flush();
  assert(
    global.$("adlist-warning").hidden === false,
    "the banner must still explain; the user is looking at a blocked page",
  );
  assert(
    global.$("adlist-allow").hidden === true,
    "Open anyway is still rendered on a backend that cannot honour it. " +
      "Disabled is not good enough: a greyed-out control invites the user to " +
      "hunt for the way to enable it, and there is not one",
  );
});

check("the no-exception copy names the browser-wide switch and its cost", async () => {
  status(5, { id: 12, host: HOST, method: "GET", can_allow: false }, null);
  await flush();
  const body = global.$("adlist-body").textContent;
  assert(
    body.includes("no way to open a single site"),
    "the copy does not say a per-site exception is unavailable: " + body,
  );
  assert(
    body.includes("every site until you turn it back on"),
    "the copy points at the Privacy switch without saying it is browser-wide, " +
      "so the user would not know everything is unblocked while it is off: " +
      body,
  );
  assert(
    !body.includes("closes behind you") && !body.includes("in this tab only"),
    "the no-exception copy promises a per-tab consent that cannot happen here",
  );
});

check("Open anyway comes back where the backend can honour it", async () => {
  status(6, { id: 13, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  assert(
    global.$("adlist-allow").hidden === false,
    "the button stayed hidden after a backend that supports it reported in",
  );
});

// R-007. The reply to Open anyway is `{allowed, status}`, the same shape as
// the plain-HTTP Continue. A bare status was read as "no status, hide the
// banner", so every successful allow took the hide branch, and a LATE reply
// from one tab took down another tab's banner. The fix is in Rust; this pins
// the chrome's half: apply the status that came back, never hide on success.
check("a late allow reply for another tab does not hide this tab's banner", async () => {
  // Tab 7 is displayed with a live hold.
  status(7, { id: 70, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  assert(global.$("adlist-warning").hidden === false, "precondition");
  // A reply arrives for an earlier click in tab 3. Its status is the ACTIVE
  // tab's, which is 7, still pending. The banner must stay.
  global.rbResolve.adlist_allow = {
    allowed: HOST,
    status: {
      id: 7,
      adlist_pending: { id: 70, host: HOST, method: "GET", can_allow: true },
      adlist_override_host: null,
    },
  };
  status(7, { id: 70, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  global.$("adlist-allow")._fire("click");
  await flush();
  assert(
    global.$("adlist-warning").hidden === false,
    "a successful allow reply hid the displayed tab's live banner",
  );
  delete global.rbResolve.adlist_allow;
});

// R-005, round 2, the reviewer's own reproduction. A dismissal for an OLDER
// pending is refused as stale because a NEWER one exists; the refusal must not
// take the newer banner down.
check("a refused stale dismissal does not hide the newer banner", async () => {
  status(9, { id: 43, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  // Withhold the dismissal's reply.
  let reject;
  global.rbResolve.adlist_dismiss = new Promise((_, r) => { reject = r; });
  global.$("adlist-dismiss")._fire("click");
  await flush();
  // A newer hold arrives and is displayed.
  status(9, { id: 44, host: "whatismyip.com", method: "GET", can_allow: true }, null);
  await flush();
  assert(global.$("adlist-warning").hidden === false, "precondition: 44 shown");
  // Now the old dismissal's refusal lands.
  reject(new Error("adlist_stale_banner"));
  await flush();
  assert(
    global.$("adlist-warning").hidden === false,
    "a refused dismissal of pending 43 hid pending 44's banner",
  );
  delete global.rbResolve.adlist_dismiss;
});

// R-004, round 3, the reviewer's reproduction. A refusal, of ANY code, for a
// dismissal made in one tab must not hide a different tab's live banner.
check("a delayed refusal for another tab's dismissal leaves this banner up", async () => {
  status(1, { id: 51, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  let reject;
  global.rbResolve.adlist_dismiss = new Promise((_, r) => { reject = r; });
  global.$("adlist-dismiss")._fire("click");
  await flush();
  status(2, { id: 52, host: "whatismyip.com", method: "GET", can_allow: true }, null);
  await flush();
  assert(global.$("adlist-warning").hidden === false, "precondition: tab 2 shown");
  reject(new Error("adlist_no_pending"));
  await flush();
  assert(
    global.$("adlist-warning").hidden === false,
    "tab 1's refused dismissal hid tab 2's banner",
  );
  delete global.rbResolve.adlist_dismiss;
});

check("a dismissal refused because nothing is pending does hide", async () => {
  status(9, { id: 45, host: HOST, method: "GET", can_allow: true }, null);
  await flush();
  global.rbResolve.adlist_dismiss = new Error("adlist_no_pending");
  global.$("adlist-dismiss")._fire("click");
  await flush();
  assert(global.$("adlist-warning").hidden === true, "nothing pending, banner stayed");
  delete global.rbResolve.adlist_dismiss;
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
    console.error("\nADLIST-BANNER GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nADLIST BANNER UI OK");
})();
