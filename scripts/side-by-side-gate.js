// Side by Side in the chrome: the toolbar toggle, the marks on the two
// paired tab chips, and the right-click panel's "Show beside the tab on
// screen" / "End Side by Side" (Rust side: AppState::side_by_side_*).
//
// WHY THIS EXISTS. The pairing itself is Rust's, but the chrome decides
// WHICH tab goes beside the one on screen and tells the user which tab is
// where. Both are easy to get subtly wrong: sending the active tab instead of
// the right-clicked one pairs a tab with itself (refused, and the user never
// learns why), and a missing mark leaves two identical-looking chips for two
// visible pages.
//
// Proven against planted defects: PATANYX_SIDE_PLANT set to "with" or "mark"
// must make this gate FAIL (chrome-js-gate.sh runs both).
//
// Run: node scripts/side-by-side-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");

const PLANT = process.env.PATANYX_SIDE_PLANT || "";
function plant(from, to) {
  if (!chromeJs.includes(from)) {
    console.error("PLANT TARGET MISSING: " + from);
    process.exit(2);
  }
  chromeJs = chromeJs.replace(from, to);
}
if (PLANT === "with") {
  plant(
    'const reply = await groupCall("side_by_side_open", { with: groupPanelTab });',
    'const reply = await groupCall("side_by_side_open", { with: (lastTabItems.find((t) => t.active) || {}).id });',
  );
} else if (PLANT === "mark") {
  plant('chip.classList.toggle("paired-left", tab.paired === "left");', "");
} else if (PLANT === "refocus") {
  // Handled below: the Rust source is checked, so the plant edits it in memory.
} else if (PLANT === "hide") {
  plant(" && !tab.active && !tab.paired;", " && !tab.active;");
} else if (PLANT) {
  console.error("unknown PATANYX_SIDE_PLANT: " + PLANT);
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
const chips = () => Array.from($("tabs").children || []);
const chipFor = (id) => chips().find((c) => Number(c.dataset.tabId) === id);
const calls = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);

function items(ids, active, paired) {
  return ids.map((id) => ({
    id,
    url: "https://tab-" + id + ".example/",
    title: "Tab " + id,
    active: id === active,
    group: null,
    paired: (paired && paired[id]) || null,
  }));
}
function paint(ids, active, paired) {
  fire("tabs_changed", { items: items(ids, active, paired), groups: [] });
}

check("the button is a toolbar pill and the panel has the section", () => {
  const at = html.indexOf('id="btn-side-by-side"');
  assert(at !== -1, "#btn-side-by-side missing");
  const tag = html.slice(
    html.lastIndexOf("<button", at),
    html.indexOf(">", at),
  );
  assert(
    /class="feature-btn"/.test(tag),
    "#btn-side-by-side must be a .feature-btn",
  );
  assert(
    html.includes('id="group-side-open"') &&
      html.includes('id="group-side-close"'),
    "panel section missing",
  );
});

check(
  "the toolbar button toggles and shows whether a pair is on screen",
  async () => {
    paint([1, 2, 3], 1, null);
    assert(
      $("btn-side-by-side").getAttribute("aria-pressed") === "false",
      "pressed with no pair",
    );
    global.rbCalls.length = 0;
    $("btn-side-by-side")._fire("click");
    await flush();
    assert(calls("side_by_side_toggle").length === 1, "toggle not sent");
    paint([1, 2, 3], 1, { 1: "left", 2: "right" });
    assert(
      $("btn-side-by-side").getAttribute("aria-pressed") === "true",
      "not pressed while paired",
    );
  },
);

check(
  "the two paired chips are marked with their side; the rest are not",
  () => {
    paint([1, 2, 3], 2, { 1: "left", 2: "right" });
    assert(chipFor(1).classList.contains("paired-left"), "left tab not marked");
    assert(
      chipFor(2).classList.contains("paired-right"),
      "right tab not marked",
    );
    assert(
      !chipFor(3).classList.contains("paired"),
      "an unpaired tab was marked",
    );
    paint([1, 2, 3], 2, null);
    assert(
      !chipFor(1).classList.contains("paired") &&
        !chipFor(2).classList.contains("paired"),
      "marks stayed after the pair ended",
    );
  },
);

check(
  "right-click, Show beside: pairs the RIGHT-CLICKED tab with the one on screen",
  async () => {
    paint([1, 2, 3], 1, null);
    chipFor(3)._fire("contextmenu");
    await flush();
    assert(
      !$("group-side-open").hidden,
      "Show beside is not offered for another tab",
    );
    global.rbCalls.length = 0;
    $("group-side-open")._fire("click");
    await flush();
    const c = calls("side_by_side_open");
    assert(
      c.length === 1 && c[0].args.with === 3,
      "wrong tab sent: " + JSON.stringify(c.map((x) => x.args)),
    );
    if (!$("group-panel").hidden) $("btn-tab-group")._fire("click");
    await flush();
  },
);

check("on the tab already on screen, Show beside is not offered", async () => {
  paint([1, 2, 3], 1, null);
  chipFor(1)._fire("contextmenu");
  await flush();
  assert($("group-side-open").hidden, "offered to pair the tab with itself");
  $("btn-tab-group")._fire("click");
  await flush();
});

check(
  "while paired, the panel offers End Side by Side, which sends close",
  async () => {
    paint([1, 2, 3], 1, { 1: "left", 2: "right" });
    chipFor(3)._fire("contextmenu");
    await flush();
    assert(
      !$("group-side-close").hidden,
      "End Side by Side not offered while paired",
    );
    global.rbCalls.length = 0;
    $("group-side-close")._fire("click");
    await flush();
    assert(calls("side_by_side_close").length === 1, "close not sent");
    if (!$("group-panel").hidden) $("btn-tab-group")._fire("click");
    await flush();
  },
);

check("every refusal has words", async () => {
  const rust = fs.readFileSync(
    path.join(root, "crates/app/src/state.rs"),
    "utf8",
  );
  const codes = Array.from(
    new Set(
      Array.from(
        rust.matchAll(/(?:Err|ok_or)\("(side_by_side_[a-z_]+)"\)/g),
        (m) => m[1],
      ),
    ),
  );
  assert(
    codes.length >= 3,
    "expected the side_by_side_* refusals in state.rs, found " +
      codes.join(","),
  );
  for (const code of codes) {
    const before = global.allText().length;
    fire("side_by_side_error", { code });
    await flush();
    const said = global.allText().slice(before).join(" ");
    assert(
      said && !/Unexpected error/.test(said),
      code + " has no user-facing text: " + said,
    );
  }
});

check("a collapsed group never hides the chip of a pane on screen", () => {
  fire("tabs_changed", {
    items: [
      { id: 1, url: "https://a.example/", title: "A", active: true, group: null, paired: "left" },
      { id: 2, url: "https://b.example/", title: "B", active: false, group: 9, paired: null },
      { id: 3, url: "https://c.example/", title: "C", active: false, group: 9, paired: "right" },
    ],
    groups: [{ id: 9, name: "G", color: "blue", collapsed: true }],
  });
  assert(!chipFor(3).hidden, "the right pane's chip was hidden by its collapsed group");
});

check("a click into a pane switches panes without focusing it again (Rust source)", () => {
  let state = fs.readFileSync(path.join(root, "crates/app/src/state.rs"), "utf8");
  if (PLANT === "refocus") {
    state = state.replace("self.set_active_inner(index, false);", "self.set_active_inner(index, true);");
  }
  const at = state.indexOf("pub fn on_pane_focused(");
  assert(at >= 0, "state.rs has no on_pane_focused");
  const body = state.slice(at, state.indexOf("\n    }\n", at));
  assert(/side_by_side::focus_activates\(/.test(body), "on_pane_focused no longer asks side_by_side::focus_activates");
  assert(/self\.set_active_inner\(index, false\)/.test(body), "on_pane_focused refocuses the pane (focus reports would loop)");
  const inner = state.slice(state.indexOf("fn set_active_inner("), state.indexOf("\n    }\n", state.indexOf("fn set_active_inner(")));
  assert(/if focus \|\| !pane_switch \{\s*self\.show_and_focus_tab\(index\);/.test(inner), "set_active_inner focuses regardless of the flag");
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
    console.error(
      "SIDE BY SIDE GATE FAILED (" +
        failures.length +
        ")" +
        (PLANT ? " [plant: " + PLANT + "]" : ""),
    );
    process.exit(1);
  }
  console.log("SIDE BY SIDE GATE OK (" + checks.length + " checks)");
})();
