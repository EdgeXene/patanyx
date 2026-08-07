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
function blockEvent(host, rule) {
  global.window.__rb_event({
    event: "navigation_blocked",
    data: { tab_id: 1, host, rule },
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
      !global.$("blocked-body").textContent.includes("matched the rule"),
      "the rule clause was shown when rule === host, which repeats itself",
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
  // to distribute malware" asserts a verified fact about the project owner of a
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

check(
  "Open anyway calls blocklist_allow with that host, exactly once",
  async () => {
    blockEvent("evil.example", "evil.example");
    global.rbCalls.length = 0;
    global.$("blocked-allow")._fire("click");
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
  },
);

check(
  "Open anyway sends the HOST, never the parent rule that matched it",
  async () => {
    // Allowing the rule would exempt every sibling subdomain of a domain the
    // user only meant to visit one page of.
    blockEvent("login.evil.example", "evil.example");
    global.rbCalls.length = 0;
    global.$("blocked-allow")._fire("click");
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
    // domstub rects are all zero-height; give the visible banner a real one
    // so "measured" is distinguishable from "ignored".
    banner.getBoundingClientRect = () => ({
      height: 40,
      width: 0,
      top: 0,
      left: 0,
    });
    // A real control, twice: open the privacy panel, then close it. The
    // close is the path under test.
    global.$("btn-privacy")._fire("click");
    await flush();
    global.rbCalls.length = 0;
    global.$("btn-privacy")._fire("click");
    await flush();
    const heights = global.rbCalls.filter((c) => c.cmd === "set_chrome_height");
    assert(heights.length > 0, "closing the panel sent no set_chrome_height");
    const last = heights[heights.length - 1].args.px;
    // 148 is closedChromePx()'s floor (domstub measures the rows at 0), and
    // 40 is the banner planted above. Exact, so a double-count fails too.
    assert(
      last === 188,
      "the height sent on panel close must include the visible banner " +
        "(want 188 = 148 floor + 40 banner, got " +
        last +
        "); anything less clips the banner outside the chrome window",
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
