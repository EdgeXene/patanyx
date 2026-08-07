// Behavioural checks on the resolver picker, run against the DOM harness so
// chrome.js is EXECUTED rather than parsed.
//
// WHY THIS EXISTS. The picker shipped with `classList.toggle("active", ...)`
// on the selected button and no `.active` rule in chrome.css, so all three
// choices rendered identically and the user could not read back which resolver
// was in force. Nothing caught it: the JS was correct, the CSS was correct,
// and the two had simply never been checked against each other. So these
// checks assert on what a user could observe -- which button is marked, what
// the toolbar label says, whether the control is present at all -- and a
// companion check reads chrome.css for the class the JS actually sets.
//
// The picker also lives in TWO places now (its own toolbar panel and a section
// inside the privacy panel). One setting with two views is exactly the shape
// that drifts, so every check below asserts on BOTH mirrors.
//
// Run: node scripts/dns-ui-gate.js   (or via scripts/chrome-js-gate.sh)
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
// The harness answers IPC on the next tick exactly as Rust does, and a refresh
// is a CHAIN (privacy_get, then dns_get), so each step must be drained before
// its effect is observable.
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// Both mirrors, named the way a user would describe them. Every assertion runs
// over this list, so adding a third view to the UI without wiring it is a gate
// failure rather than a silent second source of truth.
const MIRRORS = [
  {
    where: "the privacy panel section",
    system: "dns-system",
    mullvad: "dns-mullvad",
    quad9: "dns-quad9",
    describe: "dns-describe",
    restart: "dns-restart",
  },
  {
    where: "the toolbar panel",
    system: "dnsp-system",
    mullvad: "dnsp-mullvad",
    quad9: "dnsp-quad9",
    describe: "dnsp-describe",
    restart: "dnsp-restart",
  },
];

const WINDOWS = {
  supported: true,
  mode: "system",
  describe: "Your system's resolver, which is your VPN's if you use one.",
};

// Re-enters through a REAL path: opening the privacy panel runs
// refreshPrivacy -> applyPrivacyStatus -> refreshDns, which is how the app
// itself reaches this code. Calling refreshDns directly would exercise a
// function no user can reach that way. The button is a toggle, so an already
// open panel is closed first.
async function refreshWith(dns) {
  global.rbResolve = { privacy_get: {}, dns_get: dns, dns_set: {} };
  if (global.$("privacy-panel").hidden === false) {
    global.$("btn-privacy")._fire("click");
    await flush();
  }
  global.$("btn-privacy")._fire("click");
  await flush();
}

check("on Linux the control is absent, not present and inert", async () => {
  await refreshWith({ supported: false });
  assert(
    global.$("btn-dns").hidden === true,
    "WebKitGTK has no encrypted-DNS support of any kind, so the menu entry " +
      "must not appear -- an entry opening a panel of controls the engine " +
      "cannot honour is worse than no entry",
  );
  assert(
    global.$("dns-choice").hidden === true,
    "and the privacy-panel section must be hidden on the same grounds",
  );
});

// NOTE ON WHAT THIS ASSERTS, AND WHAT IT NO LONGER CAN.
//
// `hidden === false` here means the PLATFORM GATE is open -- this build's
// engine can honour encrypted DNS, so the control is not suppressed. It does
// NOT mean the user can see or reach it: the control now lives in the menu
// sheet, and an element inside a closed sheet still reports `hidden === false`
// on itself. Reachability is proved in scripts/menu-gate.js, which reads the
// containment out of the markup and drives the sheet open. Splitting the two
// claims is deliberate; before the split, one assertion appeared to cover both
// and, after the move, covered only the weaker one while still reading green.
check(
  "on Windows the control is present, not suppressed, and named DNS",
  async () => {
    await refreshWith(WINDOWS);
    assert(
      global.$("btn-dns").hidden === false,
      "this engine supports encrypted DNS, so the control must not be gated " +
        "off the way it is on WebKitGTK",
    );
    assert(
      global.$("dns-label").textContent === "DNS",
      "the entry is named for the feature, not for the resolver in force; got: " +
        JSON.stringify(global.$("dns-label").textContent),
    );
    assert(
      global.$("btn-dns").title.includes("VPN"),
      "the resolver name moved OUT of the label, so the title is now the only " +
        "way to find out which one is set without opening the panel -- it must " +
        "name it",
    );
  },
);

// The chrome has ONE colour rule for the toolbar: grey is not active, green is
// active. This chip is the one most likely to drift from it, because the
// tempting alternative -- colouring it by whether the user is "safe" -- reads
// as a verdict rather than a state, and gets argued for persuasively.
check("grey on System, green on a chosen resolver", async () => {
  await refreshWith(Object.assign({}, WINDOWS, { mode: "system" }));
  assert(
    !global.$("btn-dns").classList.contains("is-active"),
    "System means the browser is not choosing a resolver, so the chip must be " +
      "grey. Green there would claim the browser is doing something it is not.",
  );
  for (const mode of ["mullvad", "quad9"]) {
    await refreshWith(Object.assign({}, WINDOWS, { mode }));
    assert(
      global.$("btn-dns").classList.contains("is-active"),
      mode +
        " is the browser actively choosing a resolver, so the chip must be " +
        "green -- the same signal every other toolbar control uses",
    );
  }
});

check("the chip keeps its name whatever is set", async () => {
  for (const mode of ["mullvad", "quad9", "system"]) {
    await refreshWith(Object.assign({}, WINDOWS, { mode }));
    assert(
      global.$("dns-label").textContent === "DNS",
      "mode " +
        mode +
        " changed the chip's NAME; the name is fixed and only the colour " +
        "moves. Got " +
        JSON.stringify(global.$("dns-label").textContent),
    );
  }
});

check("an unknown mode reads as not engaged, never as green", async () => {
  await refreshWith(
    Object.assign({}, WINDOWS, { mode: "a_resolver_from_a_newer_build" }),
  );
  assert(
    !global.$("btn-dns").classList.contains("is-active"),
    "a chip going green for a resolver this build cannot even name would be " +
      "the worst failure this control has: a protection asserted with nothing " +
      "behind it",
  );
  assert(
    global.$("dns-label").textContent === "DNS",
    "and it must not render undefined or empty; got " +
      JSON.stringify(global.$("dns-label").textContent),
  );
  for (const m of MIRRORS) {
    assert(
      !global.$(m.system).classList.contains("active") &&
        !global.$(m.mullvad).classList.contains("active") &&
        !global.$(m.quad9).classList.contains("active"),
      "and nothing may be marked chosen in " + m.where,
    );
  }
});

check("both mirrors mark the resolver in force, and only it", async () => {
  await refreshWith(Object.assign({}, WINDOWS, { mode: "mullvad" }));
  for (const m of MIRRORS) {
    assert(
      global.$(m.mullvad).classList.contains("active"),
      "the chosen resolver must be marked in " + m.where,
    );
    assert(
      !global.$(m.system).classList.contains("active") &&
        !global.$(m.quad9).classList.contains("active"),
      "and the other two must not be, in " + m.where,
    );
  }
});

check("both mirrors carry the engine's own description", async () => {
  await refreshWith(WINDOWS);
  for (const m of MIRRORS) {
    assert(
      global.$(m.describe).textContent === WINDOWS.describe,
      "the description comes from Rust so the two views cannot word the " +
        "same setting differently; " +
        m.where +
        " showed " +
        JSON.stringify(global.$(m.describe).textContent),
    );
  }
});

check("choosing from either mirror sends dns_set and warns both", async () => {
  for (const chosen of MIRRORS) {
    await refreshWith(WINDOWS);
    global.rbCalls.length = 0;
    global.$(chosen.quad9)._fire("click");
    await flush();
    const sent = global.rbCalls.filter((c) => c.cmd === "dns_set");
    assert(
      sent.length === 1 && sent[0].args && sent[0].args.mode === "quad9",
      "a click in " +
        chosen.where +
        " must send exactly one dns_set for the mode clicked; got " +
        JSON.stringify(sent),
    );
    // The restart requirement is the part a user can be wrong about, so it
    // must reach whichever view they are looking at -- and the other, since
    // the setting is shared.
    for (const m of MIRRORS) {
      const note = global.$(m.restart);
      assert(
        note.hidden === false && note.textContent.includes("next time"),
        "the restart note must be visible in " +
          m.where +
          " after a choice made in " +
          chosen.where +
          "; a restart requirement the user never saw is a setting they " +
          "believe is already in force",
      );
    }
  }
});

check("a refused dns_set leaves the UI showing what is in force", async () => {
  await refreshWith(Object.assign({}, WINDOWS, { mode: "system" }));
  global.rbReject = "unsupported";
  global.$("dnsp-mullvad")._fire("click");
  await flush();
  global.rbReject = null;
  assert(
    !global.$("btn-dns").classList.contains("is-active"),
    "the switch was REFUSED, so the resolver is still System and the chip " +
      "must still be grey. Going green off the click alone would tell the " +
      "user a protection is on that the browser declined to apply.",
  );
  for (const m of MIRRORS) {
    assert(
      !global.$(m.mullvad).classList.contains("active"),
      "and nothing may be marked chosen in " + m.where,
    );
  }
});

check(
  "an unreadable setting hides the control rather than guessing",
  async () => {
    // Reached through the toolbar panel's own open hook, because that is the
    // one path where dns_get can fail while the rest of the chrome is healthy:
    // the button is visible from an earlier good read, and the preference file
    // has since become unreadable.
    await refreshWith(WINDOWS);
    assert(
      global.$("btn-dns").hidden === false,
      "precondition: button visible",
    );
    global.rbReject = "io";
    global.$("btn-dns")._fire("click");
    await flush();
    global.rbReject = null;
    assert(
      global.$("btn-dns").hidden === true,
      "if the browser cannot read the setting it must not display one; a " +
        "stale or invented resolver name is a privacy claim the user has no " +
        "way to check",
    );
    assert(
      global.$("dns-choice").hidden === true,
      "the privacy-panel mirror must go with it",
    );
  },
);

// ---- the JS and the CSS, checked against each other ----------------------
//
// The defect this file was written for lived exactly here: chrome.js set a
// class, chrome.css never styled it, and each file was individually correct.
check("the class the JS marks the choice with is actually styled", () => {
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  assert(
    /button\.small\.active\s*\{/.test(css),
    "chrome.js marks the chosen resolver with `.active` on a `button.small`. " +
      "Without a matching rule in chrome.css all three choices render " +
      "identically and the user cannot see which resolver is in force -- " +
      "which is how this picker originally shipped",
  );
});

// ---- the comparison the panel exists to present ---------------------------
//
// This is static copy, so nothing in chrome.js would notice it going missing.
// It is also the only place a user can find out WHY they would pick one
// resolver over another, and a picker offering three unexplained proper nouns
// is a picker most people close again.
check("all three choices are compared, the default included", () => {
  // Whitespace-normalised before matching. index.html is auto-formatted, so
  // any phrase long enough to be worth asserting on is long enough to get
  // rewrapped -- and a gate that fails when prettier moves a line break is a
  // gate someone deletes rather than fixes.
  const raw = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  const html = raw.replace(/\s+/g, " ");
  const block = html.slice(
    html.indexOf('<dl id="dns-compare">'),
    html.indexOf("</dl>"),
  );
  assert(block.length > 0, "the #dns-compare block is gone");
  for (const name of ["System", "Mullvad", "Quad9"]) {
    assert(
      new RegExp("<dt>\\s*" + name + "\\s*</dt>").test(block),
      "every choice needs an entry, including the default -- a user cannot " +
        "judge whether Mullvad is worth picking without seeing what they " +
        "already have. Missing: " +
        name,
    );
  }
  // Each entry must say what the choice COSTS, not only what it blocks. These
  // are the three costs a user otherwise discovers after the fact.
  assert(
    /log what you look up/.test(block),
    "the System entry must say a provider can log lookups",
  );
  assert(
    /higher chance a page loses something/.test(block),
    "the Mullvad entry must say heavier blocking can break pages",
  );
  assert(
    /public WiFi/.test(block) || /public WiFi/.test(html),
    "the panel must say fail-closed breaks captive-portal logins",
  );
});

// The site-name (ECH) copy. Gated because this exact claim was WRONG in the
// release notes for nearly three years -- "the site name travels in plaintext,
// which no browser setting prevents" -- written carefully, argued well, and
// never rechecked after Chromium shipped ECH on by default. It was corrected
// only after a measurement (2026-07-28: sni=encrypted on both System and
// Quad9). The risk now runs the other way: copy that oversells it.
//
// So the LIMITS are what is gated, not the benefit. A future edit that
// simplifies this into "PATANYX hides which sites you visit" has to delete an
// assertion to do it.
check("the panel explains what the site-name encryption does NOT cover", () => {
  const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  const panel = html.slice(html.indexOf('id="dns-panel"'));
  // Whitespace-NORMALISED before matching. These patterns are prose, and the
  // formatter rewraps prose whenever a nearby edit changes a line length --
  // which silently split "set it up on their side" across a newline and failed
  // this check against copy that was still entirely present. A gate that fires
  // on reflow teaches people to ignore it, which is worse than not having it.
  const section = panel
    .slice(0, panel.indexOf("</section>"))
    .replace(/\s+/g, " ");
  assert(
    /address of the server you reached/i.test(section),
    "the copy no longer says the server address stays visible -- it hides " +
      "WHICH site, not THAT you connected, and the measurement that " +
      "confirmed the encryption reported the client IP in the same response",
  );
  assert(
    /set it up on their side|published an ECH key|publishes an ECH key/i.test(
      section,
    ),
    "the copy no longer says this only works where the site supports it; " +
      "most sites do not",
  );
  assert(
    /strip/i.test(section),
    "the copy no longer says an unencrypted lookup lets a network strip the " +
      "key and silently downgrade the connection -- that is the actual " +
      "argument for an encrypted resolver here",
  );
});

// The superseded claim, in either place it lived. Cheap, and it fails loudly
// if anyone restores the old wording from memory or an old branch.
check("no surviving copy claims nothing can encrypt the site name", () => {
  // Every markdown file at the repo root, plus the chrome copy. Named files
  // were the earlier shape and it was wrong twice over: the release notes
  // are excluded from the PUBLIC tree, so a clone from GitHub crashed this
  // gate with ENOENT, and naming an excluded file is itself what the export
  // script's dangling-reference check refuses. A directory read covers the
  // same ground in both trees and grows to new root docs for free.
  const targets = ["crates/app/src/chrome/index.html"].concat(
    fs.readdirSync(root).filter((f) => f.endsWith(".md")),
  );
  for (const rel of targets) {
    const abs = path.join(root, rel);
    if (!fs.existsSync(abs)) continue;
    const text = fs.readFileSync(abs, "utf8");
    assert(
      !/no browser setting prevents/i.test(text),
      rel +
        " still claims no browser setting prevents the site name leaking; " +
        "Chromium has encrypted it by default since M117 and it was measured " +
        "working here",
    );
  }
});

check("the toolbar panel has somewhere to be drawn", () => {
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  assert(
    /#dns-panel/.test(css),
    "the panel manager unhides #dns-panel; with no rule for it the panel has " +
      "no background, padding or scrolling and lands on top of the page",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL " + name + " - " + e.message);
    }
  }
  if (failures.length) {
    console.error("\nDNS UI GATE FAILED:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nDNS UI OK");
})();
