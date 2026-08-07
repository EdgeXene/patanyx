// Command palette (Ctrl+K). Behavioural checks run against the DOM harness
// so chrome.js is EXECUTED rather than parsed.
//
// WHY THIS EXISTS. Every entry in the palette's action list names a button by
// id and relies on `.click()`-ing the real element rather than carrying its
// own copy of what the action does. That is exactly the shape that goes
// stale silently: rename or remove a button and the palette keeps listing an
// action that does nothing when chosen -- the "coded but the UI lied" defect
// this project keeps finding in other shapes (toolbar-gate.js exists for the
// same reason, one layer up). The first check below is the one that catches
// it: every `buttonId` the registry names must resolve to a real element.
//
// Run: node scripts/palette-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
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

// Extracted from source rather than hand-kept: a hand-kept list of what the
// registry SHOULD contain is the same failure mode one level up. Matches
// `{ label: "...", buttonId: "..." }` entries; order-tolerant would need a
// heavier parser and every entry in this file writes `label` first, so this
// is deliberately only as general as the source actually is.
function extractRegistry() {
  const start = chromeJs.indexOf("const PALETTE_ACTIONS = [");
  assert(start !== -1, "PALETTE_ACTIONS not found in chrome.js");
  const end = chromeJs.indexOf("\n  ];", start);
  assert(end !== -1, "PALETTE_ACTIONS has no terminator");
  const body = chromeJs.slice(start, end);
  const entries = [];
  const re = /label:\s*"([^"]+)"\s*,\s*buttonId:\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(body))) entries.push({ label: m[1], buttonId: m[2] });
  return entries;
}

const registry = extractRegistry();
const registryIds = registry.map((e) => e.buttonId);

// Maps a row's rendered text back to the button it names, for checks that
// need to know WHICH real element a given row will click.
function buttonIdForLabel(label) {
  const entry = registry.find((e) => e.label === label);
  assert(entry, `no registry entry renders the label "${label}"`);
  return entry.buttonId;
}

check("the registry is non-empty and was actually parsed", () => {
  // Non-vacuity: a broken extraction regex would report zero entries and
  // every check below would pass by examining nothing.
  assert(
    registry.length >= 5,
    `expected at least 5 palette actions, extracted ${registry.length} -- ` +
      "the regex above may no longer match PALETTE_ACTIONS's shape",
  );
});

check("every registered action names a button that actually exists", () => {
  // Two kinds of real button: markup in index.html, and the two the runtime
  // injects into the toolbar (toolbar-gate's "runtime-built buttons" check
  // covers their placement). An id is accepted from an injector file only as
  // an actual `.id = "..."` assignment, so a typo'd registry entry still
  // fails here instead of matching a stray comment.
  const injected = ["update.js", "integrity.js"].flatMap((file) => {
    const src = fs.readFileSync(path.join(chromeDir, file), "utf8");
    return [...src.matchAll(/\.id = "([a-z-]+)"/g)].map((m) => m[1]);
  });
  const missing = registryIds.filter(
    (id) => !html.includes('id="' + id + '"') && !injected.includes(id),
  );
  assert(
    missing.length === 0,
    "these palette actions name a button id that is neither in index.html " +
      "nor assigned by a runtime injector, so choosing them would do " +
      "nothing: " +
      missing.join(", "),
  );
});

check("the palette has no toolbar pill of its own", () => {
  const headerAt = html.indexOf('<header id="toolbar"');
  const headerEnd = html.indexOf("</header>");
  assert(
    !html.slice(headerAt, headerEnd).includes("palette"),
    "the toolbar markup mentions the palette -- it is meant to be reachable " +
      "by Ctrl+K only, per the project owner's direction that a pill here would " +
      "just be a second, redundant way into something the shortcut already " +
      "reaches",
  );
});

// The raw event Rust sends. Firing it while already open TOGGLES closed --
// that is the behaviour under test further down, so most checks should reach
// for `ensurePaletteOpen()` instead and only this one when the toggle itself
// is the point.
function fireOpenEvent() {
  global.window.__rb_event({ event: "open_command_palette", data: {} });
}

// Drives to "open" regardless of whatever a previous check left behind,
// rather than assuming a closed starting state no check here can guarantee.
function ensurePaletteOpen() {
  if (global.$("palette-panel").hidden === false) return;
  fireOpenEvent();
}

check("Ctrl+K opens the palette and renders the visible actions", async () => {
  global.$("btn-newtab").hidden = false;
  global.$("btn-vault").hidden = false;
  global.$("btn-bookmark").hidden = false;
  // Left hidden on purpose: no chat build, no DNS support on this "platform"
  // -- the harness default -- so both must be excluded from what renders.
  ensurePaletteOpen();
  await flush();
  assert(
    global.$("palette-panel").hidden === false,
    "open_command_palette must open #palette-panel",
  );
  const rows = global.$("palette-list").children.map((c) => c.textContent);
  assert(
    rows.some((t) => /new tab/i.test(t)),
    "a visible action (New tab) did not render",
  );
  assert(
    !rows.some((t) => /chat/i.test(t)),
    "Open Chat rendered even though #btn-chat is hidden -- choosing it would " +
      "have done nothing",
  );
  assert(
    !rows.some((t) => /dns/i.test(t)),
    "Open DNS settings rendered even though #btn-dns is hidden on this " +
      "platform -- choosing it would have done nothing",
  );
});

check("typing filters the list to matching actions only", async () => {
  ensurePaletteOpen();
  await flush();
  global.$("palette-query")._fire("input", { target: { value: "vault" } });
  const rows = global.$("palette-list").children.map((c) => c.textContent);
  assert(rows.length > 0, 'no rows matched "vault"');
  assert(
    rows.every((t) => /vault/i.test(t)),
    "a non-matching row survived the filter: " + rows.join(", "),
  );
});

check(
  "Enter runs the SELECTED action's real button, not just the first match",
  async () => {
    // Needs at least two matches with the selection moved off the first, or
    // "runs the selected row" and "always runs the first row" are the same
    // observable outcome -- exactly the gap a single-match query would hide.
    global.$("btn-privacy").hidden = false;
    global.$("btn-tab").hidden = false;
    global.$("btn-vault").hidden = false;
    global.$("btn-library").hidden = false;
    ensurePaletteOpen();
    await flush();
    let firstFired = 0;
    let secondFired = 0;
    global.$("palette-query")._fire("input", { target: { value: "open" } });
    const rows = global.$("palette-list").children;
    assert(
      rows.length >= 2,
      'need at least two matches for "open" to test selection',
    );
    global
      .$(buttonIdForLabel(rows[0].textContent))
      .addEventListener("click", () => {
        firstFired += 1;
      });
    global
      .$(buttonIdForLabel(rows[1].textContent))
      .addEventListener("click", () => {
        secondFired += 1;
      });
    global.$("palette-query")._fire("keydown", { key: "ArrowDown" });
    global.$("palette-query")._fire("keydown", { key: "Enter" });
    await flush();
    assert(
      secondFired === 1 && firstFired === 0,
      `ArrowDown then Enter must run the SECOND row's button, not the first ` +
        `(first fired ${firstFired}, second fired ${secondFired})`,
    );
  },
);

check("arrow keys move the selection among matches", async () => {
  global.$("btn-freeze").hidden = false;
  ensurePaletteOpen();
  await flush();
  global.$("palette-query")._fire("input", { target: { value: "" } });
  const list = global.$("palette-list");
  assert(
    list.children[0].classList.contains("selected"),
    "the first match must be selected by default",
  );
  global.$("palette-query")._fire("keydown", { key: "ArrowDown" });
  assert(
    !list.children[0].classList.contains("selected") &&
      list.children[1].classList.contains("selected"),
    "ArrowDown must move the selection to the next row",
  );
});

check(
  "pressing the shortcut again closes it, like every other panel",
  async () => {
    ensurePaletteOpen();
    await flush();
    assert(global.$("palette-panel").hidden === false, "setup: did not open");
    // The actual toggle, not the state-aware helper: firing the raw event a
    // second time while open is exactly the behaviour under test.
    fireOpenEvent();
    await flush();
    assert(
      global.$("palette-panel").hidden === true,
      "a second open_command_palette while already open must close it, the " +
        "same toggle behaviour every toolbar pill's panel already has",
    );
  },
);

check("Escape closes it", async () => {
  ensurePaletteOpen();
  await flush();
  assert(global.$("palette-panel").hidden === false, "setup: did not open");
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  assert(
    global.$("palette-panel").hidden === true,
    "Escape did not close the palette",
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
    console.error("\nPALETTE GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nPALETTE UI OK");
})();
