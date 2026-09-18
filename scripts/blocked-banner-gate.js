// The malicious-site blocked banner: what it says, and what its buttons do.
//
// WHY THIS EXISTS. `scripts/malicious-probe.sh` says, of the per-tab override,
// that "it is asserted in the DOM gate instead". There was no such gate.
// Grepping every scripts/*.js for `blocked-warning`, `blocked-allow`,
// `navigation_blocked` or `blocklist_allow` returned nothing at all. The
// banner and both of its buttons had never been tested by anything, while a
// comment in the probe told readers they had been -- which is worse than an
// admitted gap, because it stops anyone looking.
//
// What makes this worth testing rather than eyeballing: the banner is the
// ONLY place a user learns why a page did not load, and "Open anyway" is a
// destructive-ish control that must reach exactly one host, exactly once. The
// copy is load-bearing too. The list is built from two sources, one of which
// publishes automated suspicion and says plainly that false positives are
// routine, so the banner may not claim the site is KNOWN malicious -- and
// there is no per-entry provenance that could soften it selectively.
//
// Run: node scripts/blocked-banner-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
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

// The REAL entry point: Rust emits this from the navigation handler after
// `matched_rule` returns. Calling the renderer directly would prove only that
// the renderer works, which was never the doubtful half.
// Composed from the REAL catalog, the way main.rs does it, so the honesty
// checks below still judge the words a user actually reads -- the catalog
// moved, the pin followed. Argument substitution here mirrors Fluent's for
// the two placeables these messages use; the byte-exactness of the real
// resolver is pinned by the Rust test.
const ftl = fs.readFileSync(
  path.join(root, "crates/app/src/chrome/i18n/locales/en.ftl"),
  "utf8",
);
function ftlValue(id) {
  const m = ftl.match(new RegExp("^" + id + " = (.*)$", "m"));
  if (!m) throw new Error("en.ftl is missing " + id);
  return m[1];
}
function composeBlockedBody(host, rule) {
  const clause =
    rule && rule !== host
      ? ftlValue("chrome-blocked-rule-clause")
          .replace('{" "}', " ")
          .replace("{ $rule }", rule)
      : "";
  return ftlValue("chrome-blocked-body")
    .replace("{ $host }", host)
    .replace("{ $rulenote }", clause);
}

function blockEvent(host, rule) {
  // The body arrives COMPOSED from Rust (a catalog message with the host
  // and rule as arguments); the stub supplies it the way main.rs does, and
  // the checks below assert the chrome renders it VERBATIM -- wording is
  // pinned by the catalog test and the claims manifest, not here.
  const body = composeBlockedBody(host, rule);
  global.window.__rb_event({
    event: "navigation_blocked",
    data: { tab_id: 1, pending_id: 7, host, rule, body },
  });
}

check("a blocked navigation shows the banner and names the host", () => {
  blockEvent("evil.example", "evil.example");
  assert(
    global.$("blocked-warning").hidden === false,
    "the banner stayed hidden after a navigation_blocked event",
  );
  assert(
    global.$("blocked-body").textContent.includes("evil.example"),
    "the banner does not name the host that was blocked",
  );
});

check(
  "the rule clause appears only when the rule is not the host itself",
  () => {
    // Exact host listed: naming the rule would just repeat the host.
    blockEvent("evil.example", "evil.example");
    assert(
      global.$("blocked-body").dataset.rule === "",
      "the rule clause was shown when rule === host, which repeats itself; " +
        "rule=" + JSON.stringify(global.$("blocked-body").dataset.rule),
    );
    // Parent domain listed: the user needs to know a subdomain was covered,
    // or the block looks arbitrary.
    blockEvent("login.evil.example", "evil.example");
    const body = global.$("blocked-body").textContent;
    assert(
      body.includes("matched the rule") && body.includes("evil.example"),
      "a parent-domain match must say which rule covered the subdomain",
    );
  },
);

check("the copy does not claim more than the list can support", () => {
  blockEvent("evil.example", "evil.example");
  const body = global.$("blocked-body").textContent.toLowerCase();
  // THE CLAIM THIS GATE EXISTS FOR. The list merges a community-reported
  // source with an automated one whose publisher states that false positives
  // occur routinely, and nothing at runtime can tell which matched. "Known
  // to distribute malware" asserts a verified fact about the owner of a
  // site that may simply have been flagged by a heuristic.
  assert(
    !body.includes("known to"),
    'the banner claims the site is "known to" do something. The list is ' +
      "built from reports, one source of which is explicitly automated " +
      "suspicion, and there is no per-entry provenance to justify it",
  );
  assert(
    body.includes("reported"),
    "the banner must say the site was REPORTED, which is what both sources " +
      "actually establish",
  );
  // The override has to be discoverable in the text, not just as a button.
  assert(
    body.includes("open it anyway"),
    "the banner must tell the user the block can be overridden",
  );
  // And it must scope that offer honestly: the allow dies with the tab.
  assert(
    body.includes("this tab"),
    "the banner must say the override applies to this tab only -- the allow " +
      "is per-tab and is not persisted anywhere",
  );
});

check("keyboard activation (click with no press) still sends the notice on screen (review round 3, R-004)", () => {
  global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 3, pending_id: 21, host: "kb.example", rule: "kb.example", body: "x" } });
  const before = global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length;
  global.$("blocked-allow")._fire("click");
  const calls = global.rbCalls.filter((c) => c.cmd === "blocklist_allow");
  assert(calls.length === before + 1, "a keyboard activation sent nothing");
  assert(calls[calls.length - 1].args.pending_id === 21 && calls[calls.length - 1].args.tab_id === 3, "keyboard activation sent the wrong notice");
});

check("a notice replaced between keyboard press and click spends nothing (R-002)", () => {
  for (const key of ["Enter", " "]) {
    global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 6, pending_id: 41, host: "key-one.example", rule: "key-one.example", body: "x" } });
    global.$("blocked-allow")._fire("keydown", { key });
    global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 7, pending_id: 42, host: "key-two.example", rule: "key-two.example", body: "y" } });
    const before = global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length;
    global.$("blocked-allow")._fire("click");
    assert(global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length === before, "a " + JSON.stringify(key) + " activation that began on one notice sent consent for another");
  }
});

check("a background tab's notice comes down on navigation_blocked_retired (review round 3, R-005)", () => {
  global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 4, pending_id: 31, host: "bg.example", rule: "bg.example", body: "x" } });
  assert(global.$("blocked-warning").hidden === false, "precondition: notice shown");
  global.window.__rb_event({ event: "navigation_blocked_retired", data: { tab_id: 5 } });
  assert(global.$("blocked-warning").hidden === false, "another tab's retirement hid this notice");
  global.window.__rb_event({ event: "navigation_blocked_retired", data: { tab_id: 4 } });
  assert(global.$("blocked-warning").hidden === true, "the retired notice stayed up");
});

check("a notice replaced between press and click spends nothing (review round 2, R-003)", () => {
  global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 1, pending_id: 11, host: "one.example", rule: "one.example", body: "x" } });
  global.$("blocked-allow")._fire("pointerdown");
  global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 2, pending_id: 12, host: "two.example", rule: "two.example", body: "y" } });
  const before = global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length;
  global.$("blocked-allow")._fire("click");
  assert(global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length === before, "a click that began on one notice sent consent for another");
  global.window.__rb_event({ event: "tab_status", data: { id: 2, blocked_pending: null, tls: "normal", profile: "persistent", page_insecure: false, freeze_phase: "loaded", freeze_enforcement: "inactive", pending_save: null } });
});

check("navigating the blocked tab elsewhere takes the notice down (pentest F-006 review)", () => {
  global.window.__rb_event({ event: "navigation_blocked", data: { tab_id: 1, pending_id: 9, host: "evil.example", rule: "evil.example", body: "x" } });
  assert(global.$("blocked-warning").hidden === false, "precondition: notice shown");
  // The attempting page's own status, notice still pending: stays up.
  global.window.__rb_event({ event: "tab_status", data: { id: 1, origin: "news.example", blocked_pending: 9, tls: "normal", profile: "persistent", page_insecure: false, freeze_phase: "loaded", freeze_enforcement: "inactive", pending_save: null } });
  assert(global.$("blocked-warning").hidden === false, "a status for the attempting page hid a valid notice");
  // Rust cleared the record (navigation happened): down it comes.
  global.window.__rb_event({ event: "tab_status", data: { id: 1, origin: "news.example", blocked_pending: null, tls: "normal", profile: "persistent", page_insecure: false, freeze_phase: "loaded", freeze_enforcement: "inactive", pending_save: null } });
  assert(global.$("blocked-warning").hidden === true, "the notice survived Rust clearing its record");
  const before = global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length;
  global.$("blocked-allow")._fire("pointerdown"); global.$("blocked-allow")._fire("click");
  assert(global.rbCalls.filter((c) => c.cmd === "blocklist_allow").length === before, "a stale notice still sent an allow");
});

check(
  "Open anyway calls blocklist_allow with that host, exactly once",
  async () => {
    blockEvent("evil.example", "evil.example");
    global.rbCalls.length = 0;
    global.$("blocked-allow")._fire("pointerdown"); global.$("blocked-allow")._fire("click");
    await flush();
    const calls = global.rbCalls.filter((c) => c.cmd === "blocklist_allow");
    assert(
      calls.length === 1,
      `expected exactly one blocklist_allow call, got ${calls.length}`,
    );
    assert(
      calls[0].args && calls[0].args.host === "evil.example",
      `blocklist_allow must carry the blocked host, got ${JSON.stringify(
        calls[0] && calls[0].args,
      )}`,
    );
    assert(
      calls[0].args && calls[0].args.tab_id === 1 && calls[0].args.pending_id === 7,
      `blocklist_allow must name the BLOCKED tab and its pending id (pentest F-006), got ${JSON.stringify(calls[0].args)}`,
    );
  },
);

check(
  "Open anyway sends the HOST, never the parent rule that matched it",
  async () => {
    // Allowing the rule would exempt every sibling subdomain of a domain the
    // user only meant to visit one page of.
    blockEvent("login.evil.example", "evil.example");
    global.rbCalls.length = 0;
    global.$("blocked-allow")._fire("pointerdown"); global.$("blocked-allow")._fire("click");
    await flush();
    const call = global.rbCalls.find((c) => c.cmd === "blocklist_allow");
    assert(call, "no blocklist_allow call at all");
    assert(
      call.args.host === "login.evil.example",
      `must allow the host visited, not the rule: got ${call.args.host}`,
    );
  },
);

check("Dismiss hides the banner and allows nothing", async () => {
  blockEvent("evil.example", "evil.example");
  global.rbCalls.length = 0;
  global.$("blocked-dismiss")._fire("click");
  await flush();
  assert(
    global.$("blocked-warning").hidden === true,
    "Dismiss must hide the banner",
  );
  assert(
    !global.rbCalls.some((c) => c.cmd === "blocklist_allow"),
    "Dismiss must NOT allow the host -- it is the decline, and a dismissal " +
      "that quietly unblocked would be the worst possible confusion",
  );
});

check(
  "closing a panel while a banner shows keeps the banner measured",
  async () => {
    // The defect this guards against: `syncChromeCoverage`'s close path once
    // sent `closedChromePx()` BARE, while only `syncChromeHeight` knows to
    // add visible banner heights -- so closing any panel while a banner was
    // up clipped the banner outside the chrome window. Same class as the
    // lock-warning BANNERS omission, arriving by a second route; the BANNERS
    // membership check above cannot see it, because the list was complete
    // and the close path simply did not consult it.
    blockEvent("evil.example", "evil.example");
    const banner = global.$("blocked-warning");
    assert(banner.hidden === false, "precondition: the banner is visible");
    // domstub rects are all zero-height. The ROWS need real ones too, not
    // just the banner: with the rows at 0 the 148 floor swallows any banner
    // shorter than itself, so "measured" and "ignored" produce the same
    // number and the check proves nothing. 41 + 95 = 136 is what the two rows
    // measure on a real Windows build, which is the case that matters --
    // it is 12px UNDER the floor, and that slack is what used to get counted
    // twice.
    const rect = (h) => () => ({ height: h, width: 0, top: 0, left: 0 });
    global.$("tabstrip").getBoundingClientRect = rect(41);
    global.$("toolbar").getBoundingClientRect = rect(95);
    banner.getBoundingClientRect = rect(48);
    // A real control, twice: open the privacy panel, then close it. The
    // close is the path under test.
    global.$("btn-privacy")._fire("click");
    await flush();
    global.rbCalls.length = 0;
    global.$("btn-privacy")._fire("click");
    await flush();
    const heights = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
    assert(heights.length > 0, "closing the panel sent no set_chrome_insets");
    const last = heights[heights.length - 1].args.top;
    // max(148 floor, 136 rows + 48 banner) = 184, which is where the banner's
    // last row actually is. Exact in BOTH directions:
    //   184 is right.
    //   148 means the banner was ignored and is clipped outside the chrome.
    //   196 means the floor was applied to the rows and the banner added
    //       afterwards, counting the 12px of slack twice -- invisible while
    //       the chrome is opaque, and an unpainted band below the banner the
    //       moment the page is laid out against this number.
    assert(
      last === 184,
      "the height sent on panel close must end where the banner ends " +
        "(want 184 = max(148 floor, 136 rows + 48 banner), got " +
        last +
        "); 148 clips the banner outside the chrome window, 196 reserves " +
        "12px that nothing paints",
    );
    // The same number reaches the backend as the CLOSED strip, and with no
    // panel open the two must agree -- the page is laid out against the
    // strip, so a strip that disagreed with `top` would be a gap.
    assert(
      heights[heights.length - 1].args.strip === last,
      "with the panel closed, `strip` and `top` must be the same measurement " +
        "(top " + last + ", strip " + heights[heights.length - 1].args.strip + ")",
    );
    // TWO banners, both fractional. This is the case that tells "round each,
    // then sum" apart from "sum, then round once", and one banner cannot:
    // with a single 48.25 both give 185. Two give 234 against 233, and the
    // error grows with each additional fractional banner. Anything reserved
    // past the banners' real bottom edge is space the opaque backing does not
    // reach, which is a band once the page is laid out against this number.
    const second = global.$("update-banner");
    second.hidden = false;
    second.getBoundingClientRect = () => ({
      height: 48.25,
      width: 0,
      top: 0,
      left: 0,
    });
    banner.getBoundingClientRect = () => ({
      height: 48.25,
      width: 0,
      top: 0,
      left: 0,
    });
    global.rbCalls.length = 0;
    global.$("btn-privacy")._fire("click");
    await flush();
    global.rbCalls.length = 0;
    global.$("btn-privacy")._fire("click");
    await flush();
    const frac = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
    assert(frac.length > 0, "the fractional pass sent no set_chrome_insets");
    const fracTop = frac[frac.length - 1].args.top;
    assert(
      fracTop === 233,
      "two 48.25px banners over 136px of rows must reserve ceil(232.5) = 233 " +
        "(got " + fracTop + "); 234 means each banner was rounded up before " +
        "the sum, reserving a pixel nothing paints",
    );
    second.hidden = true;

    // The banner's allowance is on the TOP axis only. A sidebar takes width,
    // not height, and a banner measured into the left inset would push the
    // page sideways every time a warning appeared.
    assert(
      heights[heights.length - 1].args.left === 0,
      "a banner must not change the left inset",
    );
    // Leave the banner hidden for the checks that follow.
    global.$("blocked-dismiss")._fire("click");
  },
);

check("a malformed event changes nothing", () => {
  global.$("blocked-warning").hidden = true;
  global.window.__rb_event({ event: "navigation_blocked", data: {} });
  global.window.__rb_event({ event: "navigation_blocked" });
  assert(
    global.$("blocked-warning").hidden === true,
    "an event with no host must not raise an empty banner",
  );
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
    console.error("\nBLOCKED-BANNER GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nBLOCKED BANNER UI OK");
})();
