// Tab Groups on the strip and in the panel (crates/app/src/tab_groups.rs,
// chrome.js paintTabGroups / groupAwareOrder / the Tab Groups panel).
//
// WHY THIS EXISTS. Groups are drawn ON the tab chips rather than as extra
// elements in #tabs, because the strip places chips by index and the drag
// measures chips. That makes three things easy to break without any other
// gate noticing:
//
//   1. Collapsing must hide the right chips: every member but the first,
//      and never the tab on screen.
//   2. Dragging a group's first (labeled) chip must carry the whole group.
//   3. A group's name and color are user text: the name must stay text and
//      only palette words may ever become a class.
//
// Each is proven against a planted defect: PATANYX_TAB_GROUPS_PLANT set to
// "collapse", "drag" or "color" must make this gate FAIL (chrome-js-gate.sh
// runs all three).
//
// Run: node scripts/tab-groups-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");

const PLANT = process.env.PATANYX_TAB_GROUPS_PLANT || "";
function plant(from, to) {
  if (!chromeJs.includes(from)) {
    console.error("PLANT TARGET MISSING: " + from);
    process.exit(2);
  }
  chromeJs = chromeJs.replace(from, to);
}
if (PLANT === "collapse") {
  plant(
    "chip.hidden = !!g && g.collapsed && !first && !tab.active && !tab.paired;",
    "chip.hidden = false;",
  );
} else if (PLANT === "drag") {
  plant(
    ": groupAwareOrder(expandHiddenTabs(movedTabIds(drag.ids, drag.from, drag.to), [drag.id]), drag.id);",
    ": expandHiddenTabs(movedTabIds(drag.ids, drag.from, drag.to), [drag.id]);",
  );
} else if (PLANT === "color") {
  plant(
    'for (const c of GROUP_COLORS) chip.classList.toggle("group-color-" + c, !!g && g.color === c);',
    'if (g) chip.classList.add("group-color-" + g.color);',
  );
} else if (PLANT) {
  console.error("unknown PATANYX_TAB_GROUPS_PLANT: " + PLANT);
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
const strip = $("tabs");
const chips = () => Array.from(strip.children || []);
const chipFor = (id) => chips().find((c) => Number(c.dataset.tabId) === id);
const calls = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);
const labelOf = (chip) =>
  (chip.children || []).find((c) =>
    String(c.className).includes("chip-group-label"),
  );

function items(ids, active, groupOf) {
  return ids.map((id) => ({
    id,
    url: "https://tab-" + id + ".example/",
    title: "Tab " + id,
    active: id === active,
    group: groupOf[id] === undefined ? null : groupOf[id],
  }));
}
function layOut() {
  for (const chip of chips()) {
    chip.getBoundingClientRect = () => {
      const i = strip.children.indexOf(chip);
      return {
        left: i * 100,
        width: 96,
        right: i * 100 + 96,
        top: 0,
        height: 28,
      };
    };
  }
}
function paint(ids, active, groupOf, groups) {
  fire("tabs_changed", { items: items(ids, active, groupOf), groups });
  layOut();
}

const GROUP = { id: 50, name: "Trip", color: "blue", collapsed: false };

check(
  "the Groups button is a toolbar pill and the panel is in the markup",
  () => {
    const at = html.indexOf('id="btn-tab-group"');
    assert(at !== -1, "#btn-tab-group missing");
    const tag = html.slice(
      html.lastIndexOf("<button", at),
      html.indexOf(">", at),
    );
    assert(
      /class="feature-btn"/.test(tag),
      "#btn-tab-group must be a .feature-btn",
    );
    assert(html.includes('<section id="group-panel"'), "#group-panel missing");
  },
);

check("members wear the band; only the first carries the name", () => {
  paint([1, 2, 3, 4], 1, { 2: 50, 3: 50 }, [GROUP]);
  for (const id of [2, 3]) {
    assert(
      chipFor(id).classList.contains("in-group"),
      "tab " + id + " not marked in-group",
    );
    assert(
      chipFor(id).classList.contains("group-color-blue"),
      "tab " + id + " missing its color",
    );
  }
  assert(
    !chipFor(1).classList.contains("in-group"),
    "an ungrouped tab was marked",
  );
  assert(
    labelOf(chipFor(2)) && labelOf(chipFor(2)).textContent === "Trip",
    "first member has no name label",
  );
  assert(!labelOf(chipFor(3)), "a non-first member carries a label");
});

check("a group name with markup stays text", () => {
  const name = '<img src=x onerror="alert(1)">';
  paint([1, 2], 1, { 2: 51 }, [
    { id: 51, name, color: "red", collapsed: false },
  ]);
  const label = labelOf(chipFor(2));
  assert(label.textContent === name, "the name was not kept as literal text");
  assert(label.tagName === "BUTTON", "the label is not the fixed element");
  assert(
    (label.children || []).length === 0,
    "the name created child elements",
  );
});

check("only palette words become classes", () => {
  paint([1, 2], 1, { 2: 52 }, [
    {
      id: 52,
      name: "x",
      color: "red; background:url(//evil)",
      collapsed: false,
    },
  ]);
  const bad = chipFor(2)
    .classList._all()
    .filter(
      (c) =>
        c.startsWith("group-color-") &&
        !/^group-color-(grey|blue|red|yellow|green|pink|purple|cyan)$/.test(c),
    );
  assert(
    bad.length === 0,
    "an off-palette color became a class: " + bad.join(","),
  );
});

check(
  "collapsing hides every member but the first, never the tab on screen",
  () => {
    paint([1, 2, 3, 4, 5], 4, { 2: 53, 3: 53, 4: 53 }, [
      { id: 53, name: "G", color: "green", collapsed: true },
    ]);
    assert(!chipFor(2).hidden, "the first member was hidden");
    assert(chipFor(3).hidden, "a collapsed member stayed visible");
    assert(!chipFor(4).hidden, "the tab on screen was hidden");
    assert(
      !chipFor(5).hidden && !chipFor(1).hidden,
      "an ungrouped tab was hidden",
    );
    assert(
      labelOf(chipFor(2)).textContent === "(3) G",
      "a collapsed label must show the count",
    );
    paint([1, 2, 3, 4, 5], 1, { 2: 53, 3: 53, 4: 53 }, [
      { id: 53, name: "G", color: "green", collapsed: false },
    ]);
    assert(
      !chipFor(3).hidden && !chipFor(4).hidden,
      "expanding did not show the members",
    );
  },
);

check("Enter or Space on the name label toggles collapse and does not switch tabs", async () => {
  paint([1, 2, 3], 1, { 2: 54, 3: 54 }, [
    { id: 54, name: "T", color: "blue", collapsed: false },
  ]);
  global.rbCalls.length = 0;
  // A keyboard click carries detail 0; pointer clicks are covered by the
  // R-003 check below, through the press handler.
  labelOf(chipFor(2))._fire("click", { detail: 0 });
  await flush();
  const c = calls("group_collapse");
  assert(
    c.length === 1 && c[0].args.group === 54 && c[0].args.collapsed === true,
    "collapse not requested: " + JSON.stringify(c),
  );
  assert(
    calls("tab_switch").length === 0,
    "clicking the label also switched tabs",
  );
});

check("dragging a group's first chip carries the whole group", async () => {
  paint([1, 2, 3, 4], 1, { 2: 55, 3: 55 }, [
    { id: 55, name: "", color: "pink", collapsed: false },
  ]);
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = {
    ids: [1, 4, 2, 3],
    items: items([1, 4, 2, 3], 1, { 2: 55, 3: 55 }),
    groups: [],
  };
  const chip = chipFor(2);
  chip._fire("pointerdown", { button: 0, pointerId: 7, clientX: 148 });
  chip._fire("pointermove", { pointerId: 7, clientX: 500 });
  chip._fire("pointerup", { pointerId: 7, clientX: 500 });
  await flush();
  const sent = calls("tab_reorder");
  assert(sent.length === 1, "no reorder sent");
  assert(
    sent[0].args.ids.join(",") === "1,4,2,3",
    "the group did not travel together: " + sent[0].args.ids.join(","),
  );
  delete global.rbResolve.tab_reorder;
});

check(
  "right-click opens the panel for that tab, and Make a group sends it",
  async () => {
    paint([1, 2, 3], 1, {}, []);
    const pick = chipFor(3);
    pick._fire("contextmenu");
    await flush();
    assert(!$("group-panel").hidden, "right-click did not open the panel");
    assert(
      $("group-target").textContent.length > 0,
      "the panel does not say which tab",
    );
    $("group-name-new").value = "Reading";
    global.rbCalls.length = 0;
    $("group-create")._fire("click");
    await flush();
    const c = calls("group_create");
    assert(c.length === 1, "group_create not sent");
    assert(
      JSON.stringify(c[0].args.tabs) === "[3]",
      "grouped the wrong tab: " + JSON.stringify(c[0].args),
    );
    assert(c[0].args.name === "Reading", "name not sent");
    assert(
      /^(grey|blue|red|yellow|green|pink|purple|cyan)$/.test(c[0].args.color),
      "color not from the palette",
    );
    $("btn-tab-group")._fire("click"); // close
    await flush();
  },
);

check("closing a group's tabs takes a second, explicit click", async () => {
  paint([1, 2, 3], 2, { 2: 56, 3: 56 }, [
    { id: 56, name: "Z", color: "red", collapsed: false },
  ]);
  $("btn-tab-group")._fire("click"); // opens for the active tab (2)
  await flush();
  assert(!$("group-current").hidden, "the grouped tab's section is not shown");
  global.rbCalls.length = 0;
  $("group-close")._fire("click");
  await flush();
  assert(calls("group_close").length === 0, "one click closed the tabs");
  assert(!$("group-close-confirm").hidden, "no confirmation offered");
  $("group-close-confirm")._fire("click");
  await flush();
  const c = calls("group_close");
  assert(
    c.length === 1 && c[0].args.group === 56,
    "confirmed close not sent: " + JSON.stringify(c),
  );
  if (!$("group-panel").hidden) $("btn-tab-group")._fire("click");
  await flush();
});

check("Shelve this group sends the group, not a tab list", async () => {
  paint([1, 2, 3], 2, { 2: 57, 3: 57 }, [
    { id: 57, name: "Keep", color: "cyan", collapsed: false },
  ]);
  $("btn-tab-group")._fire("click");
  await flush();
  global.rbCalls.length = 0;
  global.rbResolve.shelf_create = {
    id: "shelf-1",
    name: "Keep",
    stored: 2,
    left_out: 0,
  };
  $("group-save-shelf")._fire("click");
  await flush();
  const c = calls("shelf_create");
  assert(
    c.length === 1 && c[0].args.group === 57 && c[0].args.ids === undefined,
    "shelf_create args: " + JSON.stringify(c),
  );
  delete global.rbResolve.shelf_create;
  if (!$("group-panel").hidden) $("btn-tab-group")._fire("click");
  await flush();
});

// ---- independent review 2026-10-06, reproduced before fixing ----

// Hidden chips have no box in a real DOM; the stub must say so too, or a
// drag check measures a strip nobody sees.
function layOutRealistic() {
  let x = 0;
  for (const chip of chips()) {
    if (chip.hidden) {
      chip.getBoundingClientRect = () => ({ left: 0, width: 0, right: 0, top: 0, height: 0 });
      continue;
    }
    const left = x;
    chip.getBoundingClientRect = () => ({ left, width: 96, right: left + 96, top: 0, height: 28 });
    x += 100;
  }
}

check("R-002: a short drag next to a collapsed group moves nothing", async () => {
  fire("tabs_changed", { items: items([1, 2, 3], 1, { 2: 60, 3: 60 }), groups: [{ id: 60, name: "C", color: "red", collapsed: true }] });
  layOutRealistic();
  global.rbCalls.length = 0;
  const chip = chipFor(1);
  chip._fire("pointerdown", { button: 0, pointerId: 11, clientX: 48 });
  chip._fire("pointermove", { pointerId: 11, clientX: 58 });
  chip._fire("pointerup", { pointerId: 11, clientX: 58 });
  await flush();
  const sent = calls("tab_reorder");
  assert(sent.length === 0, "a 10px drag committed a reorder: " + JSON.stringify(sent.map((c) => c.args.ids)));
});

check("R-002: dragging past a collapsed group sends a complete order", async () => {
  fire("tabs_changed", { items: items([1, 2, 3, 4], 1, { 2: 61, 3: 61 }), groups: [{ id: 61, name: "C", color: "red", collapsed: true }] });
  layOutRealistic();
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = { ids: [2, 3, 4, 1], items: items([2, 3, 4, 1], 1, { 2: 61, 3: 61 }), groups: [] };
  const chip = chipFor(1);
  chip._fire("pointerdown", { button: 0, pointerId: 12, clientX: 48 });
  chip._fire("pointermove", { pointerId: 12, clientX: 400 });
  chip._fire("pointerup", { pointerId: 12, clientX: 400 });
  await flush();
  const sent = calls("tab_reorder");
  assert(sent.length === 1, "no reorder sent");
  const ids = sent[0].args.ids;
  assert(ids.length === 4 && [1, 2, 3, 4].every((id) => ids.includes(id)), "incomplete order: " + ids.join(","));
  assert(ids.join(",") === "2,3,4,1", "unexpected order: " + ids.join(","));
  delete global.rbResolve.tab_reorder;
});

// ---- review round 2 2026-10-07, reproduced before fixing ----

check("round 2 R-003: a short drag keeps a collapsed group's order when two of its chips show", async () => {
  // The active tab stays visible in a collapsed group, so the group shows
  // two chips (its first and the active one). Hidden members went back
  // after the FIRST visible member, so [1,2,3,4] came back as [1,2,4,3]
  // from a drag that crossed nothing.
  fire("tabs_changed", {
    items: items([1, 2, 3, 4], 3, { 2: 62, 3: 62, 4: 62 }),
    groups: [{ id: 62, name: "C", color: "red", collapsed: true }],
  });
  layOutRealistic();
  global.rbCalls.length = 0;
  const chip = chipFor(1);
  chip._fire("pointerdown", { button: 0, pointerId: 13, clientX: 48 });
  chip._fire("pointermove", { pointerId: 13, clientX: 58 });
  chip._fire("pointerup", { pointerId: 13, clientX: 58 });
  await flush();
  const sent = calls("tab_reorder").map((c) => c.args.ids.join(","));
  assert(sent.every((o) => o === "1,2,3,4"), "a drag that crossed nothing reordered the group: " + sent.join(" | "));
});

check("round 2 R-003: dragging past a group with two visible chips keeps its inner order", async () => {
  fire("tabs_changed", {
    items: items([1, 2, 3, 4, 5], 4, { 2: 63, 3: 63, 4: 63, 5: 63 }),
    groups: [{ id: 63, name: "C", color: "red", collapsed: true }],
  });
  layOutRealistic();
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = { ids: [2, 3, 4, 5, 1], items: items([2, 3, 4, 5, 1], 4, { 2: 63, 3: 63, 4: 63, 5: 63 }), groups: [] };
  const chip = chipFor(1);
  chip._fire("pointerdown", { button: 0, pointerId: 14, clientX: 48 });
  chip._fire("pointermove", { pointerId: 14, clientX: 400 });
  chip._fire("pointerup", { pointerId: 14, clientX: 400 });
  await flush();
  const sent = calls("tab_reorder");
  assert(sent.length === 1, "no reorder sent");
  assert(sent[0].args.ids.join(",") === "2,3,4,5,1", "group order changed: " + sent[0].args.ids.join(","));
  delete global.rbResolve.tab_reorder;
});

check("round 3 R-002: dragging a group's visible active tab moves it alone", async () => {
  // Collapsed [1,2,3,4] with 3 active shows chips 1 and 3. Dragging 3 in
  // front of 1 took hidden 4 along with it ([3,4,1,2]); a member that is
  // not the group's first moves alone.
  fire("tabs_changed", {
    items: items([1, 2, 3, 4], 3, { 1: 64, 2: 64, 3: 64, 4: 64 }),
    groups: [{ id: 64, name: "C", color: "red", collapsed: true }],
  });
  layOutRealistic();
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = { ids: [3, 1, 2, 4], items: items([3, 1, 2, 4], 3, { 1: 64, 2: 64, 3: 64, 4: 64 }), groups: [] };
  const chip = chipFor(3);
  chip._fire("pointerdown", { button: 0, pointerId: 15, clientX: 148 });
  chip._fire("pointermove", { pointerId: 15, clientX: 2 });
  chip._fire("pointerup", { pointerId: 15, clientX: 2 });
  await flush();
  const sent = calls("tab_reorder");
  assert(sent.length === 1, "no reorder sent");
  assert(sent[0].args.ids.join(",") === "3,1,2,4", "hidden members moved with the dragged tab: " + sent[0].args.ids.join(","));
  delete global.rbResolve.tab_reorder;
});

check("round 4 R-003: a short drag of a group's visible active tab sends nothing", async () => {
  // Chips 1 and 3 show; a 10px drag of 3 that crosses nothing sent
  // [1,2,4,3], putting hidden 4 ahead of it.
  fire("tabs_changed", {
    items: items([1, 2, 3, 4], 3, { 1: 65, 2: 65, 3: 65, 4: 65 }),
    groups: [{ id: 65, name: "C", color: "red", collapsed: true }],
  });
  layOutRealistic();
  global.rbCalls.length = 0;
  const chip = chipFor(3);
  chip._fire("pointerdown", { button: 0, pointerId: 16, clientX: 148 });
  chip._fire("pointermove", { pointerId: 16, clientX: 158 });
  chip._fire("pointerup", { pointerId: 16, clientX: 158 });
  await flush();
  const sent = calls("tab_reorder").map((c) => c.args.ids.join(","));
  assert(sent.length === 0, "a drag that crossed nothing sent " + sent.join(" | "));
});

check("R-003: a pointer click on the group label collapses, even when the chip captured it", async () => {
  paint([1, 2, 3], 1, { 2: 62, 3: 62 }, [{ id: 62, name: "L", color: "blue", collapsed: false }]);
  global.rbCalls.length = 0;
  const chip = chipFor(2);
  const label = labelOf(chip);
  // The engine's real sequence: the press lands on the label, the chip
  // captures the pointer, and the click is delivered to the chip.
  chip._fire("pointerdown", { button: 0, pointerId: 13, clientX: 150, target: label });
  chip._fire("pointerup", { pointerId: 13, clientX: 150 });
  chip._fire("click", { detail: 1 });
  await flush();
  assert(calls("group_collapse").length === 1, "the label click did not collapse the group");
  assert(calls("tab_switch").length === 0, "the label click switched tabs");
});

check("R-005: Left/Right moves a tab past a whole group", async () => {
  paint([1, 2, 3], 3, { 1: 63, 2: 63 }, [{ id: 63, name: "", color: "green", collapsed: false }]);
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = { ids: [3, 1, 2], items: items([3, 1, 2], 3, { 1: 63, 2: 63 }), groups: [] };
  chipFor(3)._fire("keydown", { key: "ArrowLeft" });
  await flush();
  const sent = calls("tab_reorder");
  assert(sent.length === 1 && sent[0].args.ids.join(",") === "3,1,2", "Left did not jump the group: " + JSON.stringify(sent.map((c) => c.args.ids)));
  delete global.rbResolve.tab_reorder;
});

check("R-006: saving a group with tabs that cannot be stored says so", async () => {
  paint([1, 2, 3], 2, { 2: 64, 3: 64 }, [{ id: 64, name: "P", color: "cyan", collapsed: false }]);
  $("btn-tab-group")._fire("click");
  await flush();
  global.rbResolve.shelf_create = { id: "shelf-2", name: "P", stored: 1, left_out: 1 };
  $("group-save-shelf")._fire("click");
  await flush();
  await flush();
  const said = global.allText().join(" | ");
  assert(/left out/i.test(said), "the partial save was reported as complete: " + said.slice(-300));
  delete global.rbResolve.shelf_create;
  if (!$("group-panel").hidden) $("btn-tab-group")._fire("click");
  await flush();
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
      "TAB GROUPS GATE FAILED (" +
        failures.length +
        ")" +
        (PLANT ? " [plant: " + PLANT + "]" : ""),
    );
    process.exit(1);
  }
  console.log("TAB GROUPS GATE OK (" + checks.length + " checks)");
})();
