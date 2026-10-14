// The "What the engine confirmed" section must actually render rows.
//
// WHY THIS EXISTS. That section shipped, and for its entire life it rendered
// its heading, its explanatory paragraph, and NOTHING ELSE. `renderEngineConfirmed`
// was called from `applyPrivacyStatus` with the `privacy_get` reply, which
// carries six browser-wide policy fields; every key it looks up is PER-TAB and
// arrives in `tab_status`. So every lookup was `undefined`, the loop's
// "absent means this build does not report it" guard skipped every row, and a
// section whose whole purpose is to report what the engine did reported
// nothing at all -- silently, with no error, on every platform.
//
// Found by a human looking at a screenshot, which is the same way the
// panel-padding defect and the invisible Chat button were found. Nothing in
// the suite could see it: the JS was correct, the markup was correct, the Rust
// was correct, and the two halves had simply never been introduced. panel-audit
// checks that controls have LISTENERS; nothing checked that a list which is
// supposed to have contents has any.
//
// So this drives the real path -- the `tab_status` event, exactly as Rust
// pushes it -- and asserts on what a user could see.
//
// Run: node scripts/engine-confirmed-gate.js   (or via chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
function check(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failures.push(`${name}: ${e.message}`);
    console.log(`  FAIL  ${name}: ${e.message}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// Exactly the shape `AppState::active_tab_status` emits, including the two
// fields added when the ephemeral readback and the environment-fallback report
// landed. Kept as one literal so a field renamed in Rust and not here shows up
// as a missing row rather than as nothing.
const TAB_STATUS = {
  freeze_phase: "loaded",
  freeze_enforcement: "inactive",
  profile: "persistent",
  tls: "secure",
  freeze_enforced: true,
  network_blocking_supported: true,
  ledger_counts_blocked: true,
  interception: "registered",
  script_setting: "applied",
  smartscreen_off: "applied",
  tracking_prevention: "strict",
  navigation_tracking: "applied",
  autofill_off: "applied",
  ephemeral_confirmed: "applied",
  hardened_environment: "applied",
  content_script_registered: "applied",
  session_lock_registered: "applied",
  tunnel: "applied",
  divergence_script: "applied",
  youtube_ads_script: "applied",
};

// The harness records text PER NODE and does not aggregate children the way a
// live DOM does, so a row's own textContent is empty -- its label and state
// live in the <strong> and <span> it contains. Read what was actually written
// to those, which is also closer to what the check is about: the two halves of
// a row, not one flattened string.
function rowText(row) {
  return (row.children || []).map((c) => c.textContent || "").join("");
}

function rowsAfter(status) {
  // The REAL entry point: Rust pushes `tab_status` as an event on every tab
  // switch, navigation and load-state change. Calling renderEngineConfirmed
  // directly would prove only that the renderer works in isolation, which was
  // never the broken half.
  global.window.__rb_event({ event: "tab_status", data: status });
  const list = global.$("engine-list");
  return Array.from(list.children || []);
}

check("a tab_status event renders one row per reported setting", () => {
  const rows = rowsAfter(TAB_STATUS);
  assert(
    rows.length > 0,
    "the section rendered NO rows -- this is the original defect: it is being " +
      "fed a payload that does not carry these fields",
  );
  assert(
    rows.length >= 7,
    `expected a row for every engine-reported setting, got ${rows.length}`,
  );
});

check("every row names its setting and its state", () => {
  const rows = rowsAfter(TAB_STATUS);
  const text = rows.map(rowText).join(" | ");
  for (const label of [
    "JavaScript setting",
    "SmartScreen reporting off",
    "Engine tracking prevention",
    "Navigation tracking",
    "Engine autofill and password store off",
    "Ephemeral storage for this tab",
    "Hardened engine environment",
    "Login autofill script installed",
    "Lock vault when the screen locks",
    "Tunnel carrying this browser's traffic",
    "Fingerprint Divergence script",
    "YouTube ad blocking script",
  ]) {
    assert(text.includes(label), `no row labelled "${label}" (got: ${text})`);
  }
  assert(
    text.includes("confirmed by the engine"),
    "no row rendered its state text",
  );
});

check("tracking prevention names the engine level in force", () => {
  for (const level of ["strict", "balanced"]) {
    const rows = rowsAfter({ ...TAB_STATUS, tracking_prevention: level });
    const row = rows.find((r) =>
      rowText(r).includes("Engine tracking prevention"),
    );
    assert(row, `the ${level} tracking-prevention state lost its row`);
    assert(
      rowText(row).includes(level === "strict" ? "Strict" : "Balanced"),
      `the diagnostic row did not name ${level}: ${rowText(row)}`,
    );
  }
});

check("a REFUSED setting is shown as refused, not omitted", () => {
  // The load-bearing case. A protection the engine turned down must read as
  // turned down; quietly dropping the row is how an unconfirmed protection
  // gets counted as a working one.
  const rows = rowsAfter({ ...TAB_STATUS, ephemeral_confirmed: "failed" });
  const row = rows.find((r) =>
    rowText(r).includes("Ephemeral storage for this tab"),
  );
  assert(row, "the refused setting lost its row entirely");
  assert(
    rowText(row).includes("REFUSED by the engine"),
    `refused state not shown: ${rowText(row)}`,
  );
});

check("a field this build does not report gets no invented row", () => {
  const { hardened_environment, ...without } = TAB_STATUS;
  const rows = rowsAfter(without);
  assert(
    !rows.some((r) => rowText(r).includes("Hardened engine environment")),
    "invented a row for a setting the build never reported",
  );
  assert(
    rows.length >= 6,
    "dropping one unreported field should not drop the others",
  );
});

check("the tunnel row's not_attempted means off, not inapplicable", () => {
  // The generic state text calls not_attempted "not applicable on this
  // engine" -- true for every backend-specific mechanism, a lie for the
  // tunnel, which the user can switch off on ANY engine. The renderer
  // carries exactly one special case for this; here is the proof it holds.
  const rows = rowsAfter({ ...TAB_STATUS, tunnel: "not_attempted" });
  const row = rows.find((r) =>
    rowText(r).includes("Tunnel carrying this browser's traffic"),
  );
  assert(row, "the off tunnel lost its row entirely");
  assert(
    rowText(row).includes("off (no tunnel chosen)"),
    `the off tunnel must read as off, got: ${rowText(row)}`,
  );
  assert(
    !rowText(row).includes("not applicable"),
    "the off tunnel must not claim the mechanism is inapplicable",
  );
});

check("a script nobody asked for, or still being answered, gets no row", () => {
  // Rust sends null for both scripts while the setting is off for the tab or
  // the engine has not answered yet (reviews R-003, R-007). A row there would
  // invent either a confirmation or a refusal.
  const rows = rowsAfter({ ...TAB_STATUS, divergence_script: null, youtube_ads_script: null });
  const text = rows.map(rowText).join(" | ");
  assert(!text.includes("Fingerprint Divergence script"), "invented a Divergence row: " + text);
  assert(!text.includes("YouTube ad blocking script"), "invented a YouTube row: " + text);
});

check("a script the engine refused reads as refused and turns the shield amber", () => {
  // The defect behind R-003 and R-007: the panels reported the SETTING, so a
  // script the engine did not take still read as working.
  for (const key of ["divergence_script", "youtube_ads_script"]) {
    const rows = rowsAfter({ ...TAB_STATUS, [key]: "failed" });
    const label = key === "divergence_script"
      ? "Fingerprint Divergence script"
      : "YouTube ad blocking script";
    const row = rows.find((r) => rowText(r).includes(label));
    assert(row, `the refused ${key} lost its row entirely`);
    assert(rowText(row).includes("REFUSED by the engine"), `refused ${key} not shown: ${rowText(row)}`);
    assert(
      global.$("btn-privacy").classList.contains("is-warning"),
      `a refused ${key} left the toolbar shield reading as fine`,
    );
  }
  rowsAfter(TAB_STATUS);
  assert(
    !global.$("btn-privacy").classList.contains("is-warning"),
    "(control) the shield stayed amber with every script confirmed",
  );
});

check("the YouTube switch says when this tab's engine refused its script", () => {
  // The switch reads the setting; the note under it reads the engine
  // (review R-007). tab_status calls a refusal "failed".
  const note = global.$("pv-youtube-ads-refused");
  assert(note, "the refusal note is missing from index.html");
  rowsAfter({ ...TAB_STATUS, youtube_ads_script: "failed" });
  assert(!note.hidden, "the switch kept reading as working on a tab whose engine refused the script");
  rowsAfter({ ...TAB_STATUS, youtube_ads_script: "applied" });
  assert(note.hidden, "the refusal note stayed up after the engine confirmed the script");
  rowsAfter({ ...TAB_STATUS, youtube_ads_script: "failed" });
  rowsAfter({ ...TAB_STATUS, youtube_ads_script: null });
  assert(note.hidden, "the refusal note outlived the tab it described");
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  const m = html.match(/id="pv-youtube-ads-refused"[^>]*>([\s\S]*?)<\/span>/);
  assert(m, "the refusal note's markup is missing");
  assert(/hidden/.test(m[0].split(">")[0]), "the refusal note must start hidden");
  const words = m[1].toLowerCase();
  assert(words.includes("this tab") && words.includes("ads"), "the note must say it is about this tab's ads: " + words);
});

// NEGATIVE CONTROL. Every other gate in this tree carries one, because a gate
// that has never been observed to fail is a gate nobody has tested. Feed the
// renderer the payload it USED to get -- the browser-wide `privacy_get` reply
// -- and require zero rows. If this ever produces rows, the checks above have
// stopped depending on the field names and would pass against the bug.
check("(control) the old privacy_get payload produces no rows", () => {
  const rows = rowsAfter({
    block_ads: true,
    freeze_after_load: false,
    javascript: true,
    ephemeral: false,
    network_blocking_supported: true,
    freeze_enforced: true,
  });
  assert(
    rows.length === 0,
    `the control payload rendered ${rows.length} rows; these checks are no ` +
      "longer sensitive to the defect they exist to catch",
  );
});

// The privacy_get reply carries the same answer for the active tab in its own
// words ("refused"), and opening the panel must apply it too: a panel opened
// before any tab_status event would otherwise show the switch as working.
async function asyncChecks() {
  const flush = async () => {
    for (let i = 0; i < 12; i += 1) await new Promise((r) => setImmediate(r));
  };
  const note = global.$("pv-youtube-ads-refused");
  const base = { block_ads: true, freeze_after_load: false, javascript: true, ephemeral: false, block_youtube_ads: true };
  const name = "opening the privacy panel applies the active tab's YouTube answer";
  try {
    rowsAfter({ ...TAB_STATUS, youtube_ads_script: null });
    global.rbResolve.privacy_get = { ...base, youtube_ads_script: "refused" };
    global.$("btn-privacy").click();
    await flush();
    assert(!note.hidden, "privacy_get said refused and the note stayed hidden");
    global.$("btn-privacy").click();
    await flush();
    global.rbResolve.privacy_get = { ...base, youtube_ads_script: "installed" };
    global.$("btn-privacy").click();
    await flush();
    assert(note.hidden, "privacy_get said installed and the refusal note stayed up");
    global.$("btn-privacy").click();
    await flush();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failures.push(`${name}: ${e.message}`);
    console.log(`  FAIL  ${name}: ${e.message}`);
  }
}

(async () => {
await asyncChecks();
console.log();
if (failures.length) {
  console.error("ENGINE-CONFIRMED GATE FAIL:");
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log("ENGINE CONFIRMED UI OK");
})();
