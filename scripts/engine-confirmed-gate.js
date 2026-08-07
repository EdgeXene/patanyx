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
// Found by the project owner looking at a screenshot, which is the same way the
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
  tracking_prevention: "applied",
  navigation_tracking: "applied",
  autofill_off: "applied",
  ephemeral_confirmed: "applied",
  hardened_environment: "applied",
  content_script_registered: "applied",
  session_lock_registered: "applied",
  tunnel: "applied",
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
  ]) {
    assert(text.includes(label), `no row labelled "${label}" (got: ${text})`);
  }
  assert(
    text.includes("confirmed by the engine"),
    "no row rendered its state text",
  );
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

console.log();
if (failures.length) {
  console.error("ENGINE-CONFIRMED GATE FAIL:");
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log("ENGINE CONFIRMED UI OK");
