// The plain-HTTP warning banner, and the find bar's claim on the strip.
//
// TWO surfaces in one file because they share the defect class this repo
// keeps meeting: something in the band under the toolbar that the chrome
// webview is clipped against. The find bar was the latest instance -- it was
// never in BANNERS, survived on the top toolbar's 148px slack, and vanished
// under the page the moment the toolbar moved to the left edge (Ctrl+F "did
// nothing"). The HTTP warning is a NEW banner in that band, so it is pinned
// here on the day it lands rather than the day someone notices it missing.
//
// The HTTP warning is driven from `tab_status.insecure_pending`, exactly as
// Rust emits it, never from a bespoke event: it is a per-tab fact and has to
// follow the active tab. Dismiss takes no arguments; Continue carries only
// the HOST it displayed, which Rust confirms against the pending URL -- Rust holds the
// URL and the chrome cannot substitute another -- which is asserted, because
// a banner whose Continue named a URL would be an open-anything primitive.
//
// Run: node scripts/http-warning-gate.js   (or via scripts/chrome-js-gate.sh)
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

const fire = (event, data) => global.window.__rb_event({ event, data });

// The shape `AppState::active_tab_status` emits, plus the field under test.
const TAB_STATUS = {
  freeze_phase: "loaded",
  freeze_enforcement: "inactive",
  profile: "persistent",
  tls: "not_tls",
  freeze_enforced: true,
  network_blocking_supported: true,
  ledger_counts_blocked: true,
  interception: "registered",
  script_setting: "applied",
  smartscreen_off: "applied",
  tracking_prevention: "applied",
  navigation_tracking: "applied",
  autofill_off: "applied",
  ephemeral_confirmed: "applied",
  hardened_environment: "applied",
  content_script_registered: "applied",
  session_lock_registered: "applied",
  tunnel: "applied",
  pending_save: null,
  insecure_pending: null,
  // Rust computes the host now (state.rs), because this file's own parser
  // and state.rs::host_of disagreed about ports and userinfo. The helper
  // derives it the way state.rs does -- strip userinfo at the LAST '@',
  // then the port -- so a test that sets only insecure_pending still gets a
  // coherent pair, and the checks below can set them apart deliberately.
  insecure_pending_host: null,
};
function hostLikeRust(url) {
  const m = /^https?:\/\/([^/?#\\]+)/i.exec(url || "");
  if (!m) return null;
  const authority = m[1];
  const at = authority.lastIndexOf("@");
  const hostPort = at === -1 ? authority : authority.slice(at + 1);
  const close = hostPort.indexOf("]");
  const host =
    close === -1 ? hostPort.split(":")[0] : hostPort.slice(0, close + 1);
  return host || null;
}
const status = (over) => {
  const merged = Object.assign({}, TAB_STATUS, over || {});
  if (
    merged.insecure_pending &&
    Object.prototype.hasOwnProperty.call(over || {}, "insecure_pending") &&
    !Object.prototype.hasOwnProperty.call(over || {}, "insecure_pending_host")
  ) {
    merged.insecure_pending_host = hostLikeRust(merged.insecure_pending);
  }
  return merged;
};

const banner = () => global.$("insecure-warning");

check(
  "a URL with a PORT can actually be continued past",
  () => {
    // THE DEFECT THIS PINS. The banner named its subject with a regex here
    // that kept the whole authority, while state.rs::host_of strips the
    // port -- and continue_matches_shown_banner refuses the click unless
    // the two agree. So http://example.com:8080/ warned normally and then
    // could not be continued past at all: Continue sent "example.com:8080",
    // Rust computed "example.com", and the user got "That does not look
    // right" with no way forward. Warned, and trapped.
    fire(
      "tab_status",
      status({ insecure_pending: "http://example.com:8080/admin" }),
    );
    assert(banner().hidden === false, "no banner for a host with a port");
    const body = String(global.$("insecure-body").textContent || "");
    assert(
      /example\.com/.test(body) && !/8080/.test(body),
      "the banner must name the host state.rs will compare against, " +
        "without the port: " + body,
    );
    global.rbCalls.length = 0;
    global.$("insecure-allow")._fire("click");
    const call = global.rbCalls.find((c) => c.cmd === "insecure_allow");
    assert(call, "Continue sent nothing");
    assert(
      call.args.host === "example.com",
      "Continue must echo the host it displayed, or Rust refuses it; got " +
        JSON.stringify(call.args.host),
    );
  },
);

check(
  "a userinfo URL cannot put an attacker's string in the banner",
  () => {
    // http://www.paypal.com@attacker.example/ -- the authority begins with a
    // name the reader trusts, and the old renderer printed the whole thing.
    // The warning ABOUT the attacker would have carried the attacker's
    // chosen text as the name of the site. Same relabelling class the 750ms
    // stability window exists to prevent, arriving through the parser
    // instead of through a race.
    fire(
      "tab_status",
      status({ insecure_pending: "http://www.paypal.com@attacker.example/" }),
    );
    const body = String(global.$("insecure-body").textContent || "");
    assert(
      /attacker\.example/.test(body),
      "the banner does not name the host actually being opened: " + body,
    );
    assert(
      !/paypal/i.test(body),
      "the banner rendered attacker-chosen userinfo as the site name: " + body,
    );
  },
);

check(
  "a held-back http URL in tab_status shows the banner and names the host",
  () => {
    fire(
      "tab_status",
      status({ insecure_pending: "http://plain.example/some/long/path?x=1" }),
    );
    assert(banner().hidden === false, "the banner stayed hidden");
    const body = global.$("insecure-body").textContent;
    assert(
      body.includes("plain.example"),
      "the body must name the host: " + body,
    );
    assert(
      !body.includes("/some/long/path"),
      "the body names the HOST, not the whole URL: " + body,
    );
    assert(
      /not encrypted|plain HTTP/i.test(body),
      "the body must say what the problem is (plain HTTP / not encrypted): " +
        body,
    );
  },
);

check("a status with nothing pending hides it again (tab switch)", () => {
  fire("tab_status", status({ insecure_pending: "http://plain.example/" }));
  assert(banner().hidden === false, "precondition: visible");
  fire("tab_status", status({ insecure_pending: null }));
  assert(
    banner().hidden === true,
    "a tab with nothing pending must not show a warning",
  );
});

check(
  "Continue calls insecure_allow once, naming the host it displayed and no URL",
  async () => {
    fire("tab_status", status({ insecure_pending: "http://plain.example/" }));
    global.rbCalls.length = 0;
    global.rbResolve.insecure_allow = {
      allowed: "plain.example",
      status: status(),
    };
    global.$("insecure-allow")._fire("click");
    await flush();
    delete global.rbResolve.insecure_allow;
    const calls = global.rbCalls.filter((c) => c.cmd === "insecure_allow");
    assert(
      calls.length === 1,
      "expected exactly one insecure_allow, got " + calls.length,
    );
    const args = calls[0].args || {};
    // The chrome echoes the HOST it rendered so Rust can confirm the click
    // belongs to the banner the user read; a page that rewrites the pending
    // between paint and click is then refused. It must still carry no URL of
    // its own -- confirming is not choosing.
    assert(
      Object.keys(args).sort().join(",") === "host",
      "insecure_allow must carry exactly {host}; got " + JSON.stringify(args),
    );
    assert(
      args.host === "plain.example",
      "insecure_allow must name the host the banner displayed; got " +
        JSON.stringify(args.host),
    );
    assert(
      !JSON.stringify(args).includes("://"),
      "insecure_allow must never carry a URL; got " + JSON.stringify(args),
    );
    assert(
      banner().hidden === true,
      "the banner hides once the reply's status has nothing pending",
    );
  },
);

check("Dismiss calls insecure_dismiss and allows nothing", async () => {
  fire("tab_status", status({ insecure_pending: "http://plain.example/" }));
  global.rbCalls.length = 0;
  global.rbResolve.insecure_dismiss = status();
  global.$("insecure-dismiss")._fire("click");
  await flush();
  delete global.rbResolve.insecure_dismiss;
  assert(
    global.rbCalls.some((c) => c.cmd === "insecure_dismiss"),
    "Dismiss must tell Rust to drop the held URL",
  );
  assert(
    !global.rbCalls.some((c) => c.cmd === "insecure_allow"),
    "Dismiss must never allow",
  );
  assert(banner().hidden === true, "Dismiss must hide the banner");
});

check("the warning grows the strip while it shows, like every banner", () => {
  const b = banner();
  // Baseline first: whatever the strip is right now (a panel may be open in
  // this harness), the visible warning must add exactly its own height.
  fire("tab_status", status({ insecure_pending: null }));
  global.rbCalls.length = 0;
  fire("tab_status", status({ insecure_pending: "http://plain.example/" }));
  fire("tab_status", status({ insecure_pending: null }));
  const before = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
  assert(before.length > 0, "hiding the banner sent no set_chrome_insets");
  const base = before[before.length - 1].args.top;
  b.getBoundingClientRect = () => ({ height: 40, width: 0, top: 0, left: 0 });
  global.rbCalls.length = 0;
  fire("tab_status", status({ insecure_pending: "http://plain.example/" }));
  const heights = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
  assert(heights.length > 0, "showing the banner sent no set_chrome_insets");
  const last = heights[heights.length - 1].args.top;
  // Exact, so a double count fails too.
  assert(
    last === base + 40,
    "the strip must include the visible warning (want " +
      (base + 40) +
      " = " +
      base +
      " + 40, got " +
      last +
      "); anything less clips it outside the chrome window",
  );
  delete b.getBoundingClientRect;
  fire("tab_status", status({ insecure_pending: null }));
});

check("the find bar grows the strip while it is open", async () => {
  // THE defect: opening the bar sent the closed height, the bar sat below
  // it, and with the left toolbar (no 148px slack) it was under the page.
  const bar = global.$("findbar");
  // Baseline: open and close once unmeasured, take the closed height.
  fire("find_open", {});
  await flush();
  global.rbCalls.length = 0;
  global.$("find-close")._fire("click");
  await flush();
  const before = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
  assert(before.length > 0, "closing the find bar sent no set_chrome_insets");
  const base = before[before.length - 1].args.top;
  bar.getBoundingClientRect = () => ({ height: 40, width: 0, top: 0, left: 0 });
  global.rbCalls.length = 0;
  fire("find_open", {});
  await flush();
  const heights = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
  assert(heights.length > 0, "opening the find bar sent no set_chrome_insets");
  const last = heights[heights.length - 1].args.top;
  assert(
    last === base + 40,
    "the strip must include the open find bar (want " +
      (base + 40) +
      " = " +
      base +
      " + 40, got " +
      last +
      "); anything less renders it under the page -- Ctrl+F 'does nothing'",
  );
  // And it comes back down when the bar closes.
  global.rbCalls.length = 0;
  global.$("find-close")._fire("click");
  await flush();
  const closed = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
  assert(closed.length > 0, "closing the find bar sent no set_chrome_insets");
  assert(
    closed[closed.length - 1].args.top === base,
    "closing the bar must give the height back (got " +
      closed[closed.length - 1].args.top +
      ", want " +
      base +
      ")",
  );
  delete bar.getBoundingClientRect;
});

check("the new-tab button no longer focuses the bar ahead of Rust", () => {
  // Rust emits focus_url_bar once the blank tab is showing (state.rs
  // focus_url_bar_for_blank_tab); a JS focus() before that round trip lost
  // to the content webview taking focus on Windows. So the click handler
  // must NOT focus, and the focus_url_bar event must.
  const src = chromeJs;
  const start = src.indexOf('$("btn-newtab").addEventListener');
  assert(start !== -1, "the new-tab click handler is gone");
  const body = src.slice(start, src.indexOf("});", start));
  // Code lines only: the handler's own comment is allowed to NAME the call
  // it no longer makes.
  const code = body
    .split("\n")
    .filter((line) => !/^\s*\/\//.test(line))
    .join("\n");
  assert(
    !/urlInput\.focus\(\)/.test(code),
    "btn-newtab's click handler focuses the URL bar itself again; that runs " +
      "before Rust shows the tab and loses on Windows -- Rust owns this focus",
  );
  const url = global.$("url");
  let focused = false;
  const original = url.focus;
  url.focus = () => {
    focused = true;
  };
  fire("focus_url_bar", {});
  url.focus = original;
  assert(focused, "focus_url_bar must focus #url");
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (err) {
      failures.push(name + ": " + err.message);
      console.log("  FAIL " + name + ": " + err.message);
    }
  }
  if (failures.length) {
    console.error("\nHTTP WARNING GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log("\nHTTP WARNING UI OK");
})();
