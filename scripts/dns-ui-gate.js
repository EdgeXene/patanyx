// Behavioural checks on the resolver picker, run against the DOM harness so
// chrome.js is EXECUTED rather than parsed.
//
// WHY THIS EXISTS. The picker shipped with `classList.toggle("active", ...)`
// on the selected button and no `.active` rule in chrome.css, so all the
// choices rendered identically and the user could not read back which resolver
// was in force. Nothing caught it: the JS was correct, the CSS was correct,
// and the two had simply never been checked against each other. So these
// checks assert on what a user could observe -- which button is marked, what
// the toolbar label says, whether the control is present at all -- and a
// companion check reads chrome.css for the class the JS actually sets.
//
// The picker lives in TWO places (its own toolbar panel and a section inside
// the privacy panel). One setting with two views is exactly the shape that
// drifts, so every check below asserts on BOTH mirrors.
//
// SYSTEM IS THE DEFAULT and Quad9 is the opt-in choice (Mullvad was retired
// before 1.0). The reply from `dns_get` carries two resolvers: `mode`, what
// the file says (what the NEXT start gets), and `applied`, what the engine
// was given at startup. The chip colours by `applied`; the buttons mark
// `mode`; a restart note appears when they differ. The checks below hold
// each of those apart, because the failure that matters is a chip claiming a
// state the engine is not in: green before a Quad9 choice has been applied,
// or grey under an engine still running Quad9.
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
    quad9: "dns-quad9",
    system: "dns-system",
    describe: "dns-describe",
    restart: "dns-restart",
  },
  {
    where: "the toolbar panel",
    quad9: "dnsp-quad9",
    system: "dnsp-system",
    describe: "dnsp-describe",
    restart: "dnsp-restart",
  },
];

// The opt-in choice, in force: engine and file agreeing on Quad9.
const QUAD9 = {
  supported: true,
  mode: "quad9",
  applied: "quad9",
  describe:
    "Encrypted, and sent to Quad9, a Swiss nonprofit that also blocks known malicious domains.",
};
// The default, in force: engine and file agreeing on System.
const SYSTEM = {
  supported: true,
  mode: "system",
  applied: "system",
  describe:
    "The default. Your machine keeps using whatever it uses now: your VPN's resolver if you have one, otherwise your internet provider.",
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

function chipGreen() {
  return global.$("btn-dns").classList.contains("is-active");
}
function marked(m, name) {
  return global.$(m[name]).classList.contains("active");
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
    await refreshWith(QUAD9);
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
      global.$("btn-dns").title.includes("Quad9"),
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
check("grey on System, which is the default; green on Quad9", async () => {
  await refreshWith(SYSTEM);
  assert(
    !chipGreen(),
    "System means the browser is not choosing a resolver, so the chip must be " +
      "grey -- and a fresh install starts this way. Green there would claim " +
      "the browser is doing something it is not.",
  );
  await refreshWith(QUAD9);
  assert(
    chipGreen(),
    "Quad9 is the browser actively choosing a resolver, so the chip must be " +
      "green -- the same signal every other toolbar control uses",
  );
});

check("the chip keeps its name whatever is set", async () => {
  for (const st of [QUAD9, SYSTEM]) {
    await refreshWith(st);
    assert(
      global.$("dns-label").textContent === "DNS",
      "mode " +
        st.mode +
        " changed the chip's NAME; the name is fixed and only the colour " +
        "moves. Got " +
        JSON.stringify(global.$("dns-label").textContent),
    );
  }
});

check("an unknown mode reads as not engaged, never as green", async () => {
  await refreshWith(
    Object.assign({}, QUAD9, {
      mode: "a_resolver_from_a_newer_build",
      applied: "a_resolver_from_a_newer_build",
    }),
  );
  assert(
    !chipGreen(),
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
      !marked(m, "quad9") && !marked(m, "system"),
      "and nothing may be marked chosen in " + m.where,
    );
  }
});

check("both mirrors mark the resolver in force, and only it", async () => {
  await refreshWith(QUAD9);
  for (const m of MIRRORS) {
    assert(marked(m, "quad9"), "Quad9 must be marked in " + m.where);
    assert(!marked(m, "system"), "and System must not be, in " + m.where);
  }
  await refreshWith(SYSTEM);
  for (const m of MIRRORS) {
    assert(marked(m, "system"), "System must be marked in " + m.where);
    assert(!marked(m, "quad9"), "and Quad9 must not be, in " + m.where);
  }
});

check("both mirrors carry the engine's own description", async () => {
  await refreshWith(QUAD9);
  for (const m of MIRRORS) {
    assert(
      global.$(m.describe).textContent === QUAD9.describe,
      "the description comes from Rust so the two views cannot word the " +
        "same setting differently; " +
        m.where +
        " showed " +
        JSON.stringify(global.$(m.describe).textContent),
    );
  }
});

// THE CHIP FOLLOWS THE ENGINE, THE BUTTONS FOLLOW THE FILE. The engine takes
// the resolver once, at startup; the file can change under it. With Quad9 the
// default, a chip coloured by the file would go green the moment the file
// became unreadable at runtime (the reply then carries the default), over an
// engine still running plaintext. That is the one wrong claim this control
// must never make, so it is pinned in both directions.
check("the chip follows the engine, not the file, and says a restart is pending", async () => {
  // File says Quad9, engine still on System: grey chip, Quad9 marked, note up,
  // and the tooltip -- the one place the resolver is NAMED without opening
  // the panel -- names the engine's resolver and says what is pending.
  await refreshWith(Object.assign({}, QUAD9, { applied: "system" }));
  assert(
    /now: System\. Quad9 after the next restart\./.test(global.$("btn-dns").title),
    "the tooltip must name the resolver in force and the pending one; got " +
      JSON.stringify(global.$("btn-dns").title),
  );
  assert(
    !chipGreen(),
    "the engine is running System, so the chip must be grey however the " +
      "file reads -- green here claims an encryption that is not running",
  );
  for (const m of MIRRORS) {
    assert(marked(m, "quad9"), "the file's choice must be marked in " + m.where);
    const note = global.$(m.restart);
    assert(
      note.hidden === false && note.dataset.state === "restart-pending",
      "file and engine disagree, so " + m.where + " must say a restart is pending",
    );
  }
  // File says System, engine still on Quad9: green chip, System marked, note up.
  await refreshWith(Object.assign({}, SYSTEM, { applied: "quad9" }));
  assert(
    chipGreen(),
    "the engine is still running Quad9, so the chip stays green until the " +
      "restart the note asks for",
  );
  for (const m of MIRRORS) {
    assert(marked(m, "system"), "the file's choice must be marked in " + m.where);
    assert(
      global.$(m.restart).hidden === false,
      "and " + m.where + " must still say a restart is pending",
    );
  }
  // Agreement again: the note comes down, because nothing is pending.
  await refreshWith(QUAD9);
  for (const m of MIRRORS) {
    assert(
      global.$(m.restart).hidden === true,
      "file and engine agree, so " + m.where + " must show no pending note",
    );
  }
});

// THE WAY OUT. Quad9 fails closed, so on hotel WiFi the only route online is
// choosing System and restarting. That path is what this check drives, from
// the default state, through each mirror. The mocked reply is updated the way
// Rust's would be -- the file now says System, the engine still runs Quad9 --
// so what the user sees afterwards is also asserted: System marked, chip still
// green, restart note in both mirrors.
check("choosing System from Quad9 sends dns_set and warns both mirrors", async () => {
  for (const chosen of MIRRORS) {
    await refreshWith(QUAD9);
    global.rbCalls.length = 0;
    global.$(chosen.system)._fire("click");
    // What dns_get answers from now on: the file changed, the engine did not.
    global.rbResolve.dns_get = Object.assign({}, SYSTEM, { applied: "quad9" });
    await flush();
    const sent = global.rbCalls.filter((c) => c.cmd === "dns_set");
    assert(
      sent.length === 1 && sent[0].args && sent[0].args.mode === "system",
      "a click in " +
        chosen.where +
        " must send exactly one dns_set for System; got " +
        JSON.stringify(sent),
    );
    assert(
      chipGreen(),
      "the engine is still on Quad9 until the restart, so the chip must stay " +
        "green after the click -- grey now would say the escape already worked",
    );
    for (const m of MIRRORS) {
      assert(marked(m, "system"), "System must now be marked in " + m.where);
      assert(!marked(m, "quad9"), "and Quad9 no longer marked in " + m.where);
      const note = global.$(m.restart);
      assert(
        note.hidden === false && note.dataset.state === "restart-pending",
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

check("choosing Quad9 from the default sends dns_set and the chip waits for the restart", async () => {
  for (const chosen of MIRRORS) {
    await refreshWith(SYSTEM);
    global.rbCalls.length = 0;
    global.$(chosen.quad9)._fire("click");
    global.rbResolve.dns_get = Object.assign({}, QUAD9, { applied: "system" });
    await flush();
    const sent = global.rbCalls.filter((c) => c.cmd === "dns_set");
    assert(
      sent.length === 1 && sent[0].args && sent[0].args.mode === "quad9",
      "a click in " + chosen.where + " must send exactly one dns_set for Quad9; got " +
        JSON.stringify(sent),
    );
    assert(
      !chipGreen(),
      "the engine is still on System until the restart, so the chip must stay " +
        "grey -- going green off the click alone would claim a protection not " +
        "yet applied",
    );
    for (const m of MIRRORS) {
      assert(marked(m, "quad9"), "Quad9 must now be marked in " + m.where);
      assert(
        global.$(m.restart).hidden === false,
        "the restart note must be visible in " + m.where,
      );
    }
  }
});

check("a refused dns_set leaves the UI showing what is in force", async () => {
  await refreshWith(QUAD9);
  global.rbReject = "unsupported";
  global.$("dnsp-system")._fire("click");
  await flush();
  global.rbReject = null;
  assert(
    chipGreen(),
    "the switch was REFUSED, so the engine is still on Quad9 and the chip " +
      "must still be green; and nothing may pretend the escape worked",
  );
  for (const m of MIRRORS) {
    assert(
      marked(m, "quad9") && !marked(m, "system"),
      "the refused choice must not be marked in " + m.where,
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
    await refreshWith(QUAD9);
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

// The file exists and cannot be read, under a running engine. Rust answers
// with the DEFAULT (System) and `settings_unreadable: true`; the engine is still
// on whatever it started with. The chip must not go green off the default, and
// the note must say what happened in both mirrors.
check("an unreadable file at runtime does not change the chip, and says so", async () => {
  // The engine is on Quad9; the file broke; the reply carries the default,
  // System. The chip must stay green (the engine has not changed) and both
  // mirrors must say what happens at the NEXT start.
  await refreshWith(
    Object.assign({}, SYSTEM, { applied: "quad9", settings_unreadable: true }),
  );
  assert(
    chipGreen(),
    "the engine is still running Quad9; the default the reply carries is what " +
      "the NEXT start gets, and the chip must not drop it now",
  );
  for (const m of MIRRORS) {
    const note = global.$(m.restart);
    assert(
      note.hidden === false && /from the next start/.test(note.textContent),
      "with the engine still on Quad9 the note must speak of the next start in " +
        m.where + "; got " + JSON.stringify(note.textContent),
    );
  }
  // The file was already unreadable at launch: the engine IS on System now,
  // and a note that promised a fallback "from the next start" would
  // understate a Quad9 user's exposure. The sentence must say so.
  await refreshWith(
    Object.assign({}, SYSTEM, { applied: "system", settings_unreadable: true }),
  );
  assert(!chipGreen(), "the engine is on System, so the chip is grey");
  for (const m of MIRRORS) {
    const note = global.$(m.restart);
    assert(
      note.hidden === false &&
        /DNS is on System/.test(note.textContent) &&
        !/next start/.test(note.textContent),
      "with the engine already on System the note must say so now, not at the " +
        "next start, in " + m.where + "; got " + JSON.stringify(note.textContent),
    );
  }
  // The file becomes readable again (or the user chose again): the note
  // must come down. It used to carry no state marker, so it outlived the
  // condition it described.
  await refreshWith(QUAD9);
  for (const m of MIRRORS) {
    assert(
      global.$(m.restart).hidden === true,
      "a healthy reply must clear the unreadable note in " + m.where,
    );
  }
});

// ---- the JS and the CSS, checked against each other ----------------------
//
// The defect this file was written for lived exactly here: chrome.js set a
// class, chrome.css never styled it, and each file was individually correct.
check("the class the JS marks the choice with is actually styled", () => {
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  assert(
    /button\.small\.active\s*\{/.test(css),
    "chrome.js marks the chosen resolver with `.active` on a `button.small`. " +
      "Without a matching rule in chrome.css the choices render identically " +
      "and the user cannot see which resolver is in force -- which is how " +
      "this picker originally shipped",
  );
});

// ---- the comparison the panel exists to present ---------------------------
//
// This is static copy, so nothing in chrome.js would notice it going missing.
// It is also the only place a user can find out WHY they would leave the
// default, and a picker offering unexplained proper nouns is a picker most
// people close again.
check("both choices are compared, the default first and marked as such", () => {
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
  const at = (name) => block.search(new RegExp("<dt[^>]*>\\s*" + name + "\\s*</dt>"));
  assert(at("Quad9") >= 0, "the Quad9 entry is missing");
  assert(at("System") >= 0, "the System entry is missing -- a user cannot judge " +
    "whether to leave the default without seeing what they would get");
  assert(
    at("System") < at("Quad9"),
    "System is the default and must be compared first",
  );
  assert(
    /Default\./.test(block.slice(at("System"), at("Quad9"))),
    "the System entry must say it is the default",
  );
  // Each entry must say what the choice COSTS, not only what it buys. These
  // are the costs a user otherwise discovers after the fact.
  assert(
    /log what you look up/.test(block),
    "the System entry must say a provider can log lookups",
  );
  assert(
    /every domain you look up/.test(block.slice(at("Quad9"))),
    "the Quad9 entry must say Quad9 sees every lookup",
  );
  assert(
    /public WiFi/.test(block),
    "the compare block itself must say fail-closed breaks public WiFi sign-in " +
      "-- anywhere else in the page does not count, because this is where a " +
      "user decides",
  );
});

// The two button hosts must offer the same two resolvers in the same order:
// the default first, the choice second. Read from the markup, because the
// harness cannot see layout and the order IS the message.
check("both button hosts offer System then Quad9, and nothing else", () => {
  const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  const idsIn = (openTag) => {
    const at = html.indexOf(openTag);
    assert(at >= 0, "missing host: " + openTag);
    const end = html.indexOf("</div>", at);
    return Array.from(
      html.slice(at, end).matchAll(/<button\b[^>]*\bid="([^"]+)"/g),
      (m) => m[1],
    );
  };
  const privacyHost = html.slice(html.indexOf('id="dns-choice"'));
  const privacyIds = Array.from(
    privacyHost
      .slice(0, privacyHost.indexOf("</div>"))
      .matchAll(/<button\b[^>]*\bid="([^"]+)"/g),
    (m) => m[1],
  );
  assert(
    JSON.stringify(privacyIds) === JSON.stringify(["dns-system", "dns-quad9"]),
    "the privacy-panel host must offer exactly System then Quad9; got " +
      JSON.stringify(privacyIds),
  );
  const toolbarIds = idsIn('<div id="dnsp-resolver-choices"');
  assert(
    JSON.stringify(toolbarIds) === JSON.stringify(["dnsp-system", "dnsp-quad9"]),
    "the toolbar host must offer exactly System then Quad9; got " +
      JSON.stringify(toolbarIds),
  );
});

// Mullvad shut its public encrypted DNS (announced 2026-09-03, off on
// 2026-11-02) and was retired from the picker before 1.0. A button, a string
// or a mode name restored from an old branch would point users at a resolver
// that no longer answers.
check("no surviving copy or code offers the retired resolver", () => {
  const targets = [
    "crates/app/src/chrome/index.html",
    "crates/app/src/chrome/chrome.js",
    "crates/app/src/chrome/i18n/locales/en.ftl",
  ];
  for (const rel of targets) {
    const text = fs.readFileSync(path.join(root, rel), "utf8");
    assert(!/mullvad/i.test(text), rel + " still mentions the retired resolver");
  }
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
  // WIDENED 2026-08-27. The pattern matched one exact phrasing, "server you
  // reached", and fired on copy later rewritten to "the IP address of the
  // server you connect to" -- the SAME fact, said more plainly. A gate that
  // fires on a synonym is the reflow problem again in another costume: it
  // teaches people to edit the gate instead of respecting it. What is gated is
  // the FACT that the server address stays visible, so both phrasings pass and
  // deleting the fact still fails.
  assert(
    /address of the server you (reached|connect to)/i.test(section),
    "the copy no longer says the server address stays visible -- it hides " +
      "WHICH site, not THAT you connected, and the measurement that " +
      "confirmed the encryption reported the client IP in the same response",
  );
  assert(
    // Same widening, same reason. "when the site supports it" states the
    // condition without the TLS vocabulary; an earlier draft that said
    // "publishes an ECH key" passed this gate while putting an acronym no
    // reader knows into the panel, which is a worse outcome than the one this
    // assertion was defending against.
    /set it up on their side|published an ECH key|publishes an ECH key|when the site supports it|where the site supports it/i.test(
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
