// Toolbar groups and folds (1.0.7), driven through the REAL chrome.js against
// the DOM stub and by reading index.html, chrome.css and prefs.rs.
//
// What this gate is for. Row two after the shield and the freeze chip is four
// groups by subject, and a group can be folded into one pill that opens its
// buttons as a menu, by the user's choice (stored) or by a window too narrow
// for the row (never stored). The things worth pinning are the ones that
// would quietly make that lie or lose something:
//
//   - the table chrome.js acts on and the markup and stylesheet drifting
//     apart (a pill for a group that no longer exists, a button that folds
//     with no pill to reach it);
//   - the shield or the freeze chip landing in a group: they carry the
//     standing protection state, and no fold may hide it;
//   - a fold following the click instead of what Rust stored, or the width's
//     own folds being written into the stored choice;
//   - a folded group's menu closing the panel it is drawn over, listing a
//     button that is hidden for its own reason, or sending the keyboard to a
//     button that cannot be seen;
//   - a folded pill, or the main menu button, not showing that something
//     inside wants attention (review round 2, R-004).
//
// Planted defects (PATANYX_GROUPS_PLANT): each must fail a NAMED check, which
// the wrapper in chrome-js-gate.sh requires. PATANYX_GROUPS_LIST_PLANTS=1
// lists them. A plant names the file it patches (js, css or html).
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");

const PLANTS = {
  // The width's folds are written into the stored choice.
  "js-autofold-stores": [
    "js",
    "        autoFolded.add(g);\n        wearFolds(true);\n",
    "        userFolded.add(g);\n        wearFolds(true);\n",
  ],
  // A fold box keeps what was clicked instead of what Rust stored.
  "js-fold-follows-click": [
    "js",
    "          userFolded = new Set(knownGroups(r && r.groups));\n          if (seq !== foldSeq) return;\n",
    "          userFolded = want;\n          if (seq !== foldSeq) return;\n",
  ],
  // A button hidden for its own reason is listed in its group's menu.
  "js-hidden-member-listed": [
    "js",
    "      .filter((real) => real && !real.hidden);\n",
    "      .filter((real) => real);\n",
  ],
  // Opening a group's menu closes the panel it is drawn over.
  "js-group-menu-closes-panel": [
    "js",
    "      else openMenu(groupMenuFor(g));\n",
    "      else {\n        closeOpenPanel();\n        openMenu(groupMenuFor(g));\n      }\n",
  ],
  // The menu button's dot follows the real buttons only while a menu shows.
  "js-dot-only-while-open": [
    "js",
    "      hideMenuPills();\n      syncMenuProxies();\n      syncGroupPills();\n",
    "      hideMenuPills();\n      if (menuOpen) syncMenuProxies();\n      syncGroupPills();\n",
  ],
  // A panel opened from a folded group returns the keyboard to a hidden button.
  "js-focus-to-hidden-button": [
    "js",
    '    if (g && isFolded(g)) return $("group-" + g);\n',
    "",
  ],
  // An add-on button (addons.js, runtime) is not found in its group, so a
  // panel it opened from the folded Tools menu returns the keyboard to it.
  "js-runtime-member-missed": [
    "js",
    "    for (const g of TOOLBAR_GROUP_IDS) if (membersOf(g).includes(id)) return g;\n",
    "    for (const [g, members] of TOOLBAR_GROUPS) if (members.includes(id)) return g;\n",
  ],
  // An add-on button the user took off the toolbar is still drawn on it.
  "css-hidden-addon-on-row": [
    "css",
    ".feature-btn[data-addon-button]:not([data-shown]) {\n  display: none !important;\n}\n",
    "",
  ],
  // An add-on button stays on the row while Tools is folded (the rule the
  // grouped default removed, 2026-10-22).
  "css-addon-on-folded-row": [
    "css",
    ".feature-btn[data-addon-button]:not([data-shown]) {\n  display: none !important;\n}\n",
    ".feature-btn[data-addon-button]:not([data-shown]) {\n  display: none !important;\n}\nhtml[data-folded~=\"tools\"] .feature-btn[data-group=\"tools\"][data-addon-button][data-shown]:not([hidden]) {\n  display: flex !important;\n}\n",
  ],
  // The shield joins a group.
  "html-privacy-grouped": [
    "html",
    '\n        id="btn-privacy"\n',
    '\n        id="btn-privacy"\n        data-group="network"\n',
  ],
  // A folded group's buttons stay on the row.
  "css-folded-not-hidden": [
    "css",
    'html[data-folded~="saved"] .feature-btn[data-group="saved"] {\n  display: none !important;\n}\n',
    "",
  ],
  // The observer's own writes retrigger it forever (round 3, R-001).
  "js-observer-loops": [
    "js",
    '      if (b && !b.classList.contains("in-menu")) b.classList.add("in-menu");\n',
    '      if (b) b.classList.add("in-menu");\n',
  ],
  // A folded pill does not carry an interception (round 3, R-002).
  "js-pill-ignores-interception": [
    "js",
    '        const intercepted = b.classList.contains("is-intercepted");\n',
    "        const intercepted = false;\n",
  ],
  // An open group menu stops following its buttons (round 3, R-003).
  "js-open-group-menu-stale": [
    "js",
    "      syncGroupPills();\n      syncOpenGroupMenu();\n",
    "      syncGroupPills();\n",
  ],
  // The body loses menu-open as the fade starts (round 3, R-004).
  "js-menu-open-dropped-early": [
    "js",
    '    layer.button.setAttribute("aria-expanded", "false");\n    // body.menu-open stays',
    '    layer.button.setAttribute("aria-expanded", "false");\n    document.body.classList.remove("menu-open");\n    // body.menu-open stays',
  ],
  // Measuring closes an automatically folded group's open menu (round 3, R-006).
  "js-measure-closes-menu": [
    "js",
    "      wearFolds(true);\n      for (const g of AUTO_FOLD_ORDER) {\n",
    "      wearFolds();\n      for (const g of AUTO_FOLD_ORDER) {\n",
  ],
  // Fold changes build on the last ANSWERED set (round 3, R-007).
  "js-fold-requests-overlap": [
    "js",
    "      const want = new Set(foldWanted || userFolded);\n",
    "      const want = new Set(userFolded);\n",
  ],
  // The Updates entry no longer reaches update.js's button (round 3, R-009).
  "js-updates-entry-dead": [
    "js",
    '    ["menu-update", "btn-update"],\n',
    '    ["menu-update", "btn-update-gone"],\n',
  ],
  // Print and Save as PDF offered where the platform cannot do them.
  "js-print-always-offered": [
    "js",
    '      const allowed = !needs || (needs === "ocr" ? menuOcr : printCaps[needs]);\n',
    "      const allowed = true;\n",
  ],
  // The served folds are ignored until the first reply (round 4, R-004).
  "js-boot-folds-ignored": [
    "js",
    '  let userFolded = new Set(\n    TOOLBAR_GROUP_IDS.filter((g) =>\n      (document.documentElement.dataset.folded || "").split(" ").includes(g),\n    ),\n  );\n',
    "  let userFolded = new Set();\n",
  ],
  // A refusal forgets an earlier successful save (round 4, R-001).
  "js-failure-forgets-saved": [
    "js",
    "          userFolded = new Set(knownGroups(r && r.groups));\n          if (seq !== foldSeq) return;\n",
    "          if (seq !== foldSeq) return;\n          userFolded = new Set(knownGroups(r && r.groups));\n",
  ],
  // A group menu kept open is not placed again after a resize (round 4, R-002).
  "js-menu-not-repositioned": [
    "js",
    "    if (menuOpen && menuLayer && menuLayer.group) {\n      menuHeightPx = positionGroupMenu(menuLayer.button);\n",
    "    if (false) {\n      menuHeightPx = positionGroupMenu(menuLayer.button);\n",
  ],
  // A rebuild sends the keyboard to the first entry (round 4, R-003).
  "js-rebuild-focus-first": [
    "js",
    "        const keep = groupMenuReals.indexOf(focusedReal);\n",
    "        const keep = 0;\n",
  ],
  // A remeasure resets a box whose change is on its way (round 4, R-005).
  "js-pending-box-reset": [
    "js",
    "      if (box) box.checked = (foldWanted || userFolded).has(g);\n",
    "      if (box) box.checked = userFolded.has(g);\n",
  ],
  // A group menu on a rail is placed at the pill's edge, under the rail.
  "js-menu-under-rail": [
    "js",
    "      const edge = railBox ? Math.max(r.right, railBox.right) : r.right;\n",
    "      const edge = r.right;\n",
  ],
  // A page handoff leaves an open menu covering the window (release R-001).
  "js-handoff-ignores-menu": [
    "js",
    "      if (menuOpen || menuClosing) finishMenuClose();\n",
    "",
  ],
  // About this site toggles an open Tab Activity shut (release R-002).
  "js-site-info-toggles-tab": [
    "js",
    '  const PANEL_ALSO_OPENED_BY = { "btn-site-info": "tab" };\n',
    "  const PANEL_ALSO_OPENED_BY = {};\n",
  ],
  // A menu takes the opaque repaint away from solid-backdrop (round 3, R-005).
  "css-menu-transparent-on-solid": [
    "css",
    "body.translucent-backdrop.menu-open:not(.solid-backdrop) {\n  background: transparent;\n}\n",
    "body.translucent-backdrop.menu-open {\n  background: transparent;\n}\n",
  ],
};
if (process.env.PATANYX_GROUPS_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}
let chromeSrc = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
let cssSrc = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
let htmlSrc = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
const prefsSrc = fs.readFileSync(
  path.join(root, "crates/app/src/prefs.rs"),
  "utf8",
);
let htmlPath = path.join(chromeDir, "index.html");
const plant = process.env.PATANYX_GROUPS_PLANT;
if (plant) {
  const p = PLANTS[plant];
  const target = p && { css: cssSrc, js: chromeSrc, html: htmlSrc }[p[0]];
  if (!p || !target.includes(p[1])) {
    console.error(
      `plant ${plant}: anchor not found; the gate cannot prove anything`,
    );
    process.exit(2);
  }
  if (p[0] === "css") cssSrc = cssSrc.replace(p[1], p[2]);
  else if (p[0] === "js") chromeSrc = chromeSrc.replace(p[1], p[2]);
  else {
    // The stub reads the markup from a path: a planted markup defect is
    // written to a scratch copy and the stub pointed at it.
    htmlSrc = htmlSrc.replace(p[1], p[2]);
    htmlPath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "groups-gate-")),
      "index.html",
    );
    fs.writeFileSync(htmlPath, htmlSrc);
  }
}

const failures = [];
let checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((r) => setImmediate(r));
  }
};

// ---- the table, the markup, the stylesheet, prefs.rs ------------------------

const tableLiteral = /const TOOLBAR_GROUPS = \[([\s\S]*?)\n  \];/.exec(
  chromeSrc,
);
const GROUPS = tableLiteral
  ? new Function("return [" + tableLiteral[1] + "]")()
  : [];
const autoLiteral = /const AUTO_FOLD_ORDER = (\[[^\]]*\]);/.exec(chromeSrc);
const AUTO_ORDER = autoLiteral
  ? new Function("return " + autoLiteral[1])()
  : [];
const tagOf = (id) => {
  const at = htmlSrc.indexOf('id="' + id + '"');
  if (at < 0) return null;
  return htmlSrc.slice(
    htmlSrc.lastIndexOf("<", at),
    htmlSrc.indexOf(">", at) + 1,
  );
};
const breakAt = htmlSrc.indexOf('class="toolbar-break"');

check("chrome.js, the markup and prefs.rs name the same four groups", () => {
  assert(
    GROUPS.length === 4,
    "TOOLBAR_GROUPS has " + GROUPS.length + " groups",
  );
  const ids = GROUPS.map(([g]) => g);
  const rust = /pub const TOOLBAR_GROUPS: \[&str; \d+\] = \[([^\]]*)\];/.exec(
    prefsSrc,
  );
  assert(rust, "prefs.rs has no TOOLBAR_GROUPS");
  const rustIds = [...rust[1].matchAll(/"([\w-]+)"/g)].map((m) => m[1]);
  assert(
    JSON.stringify(rustIds) === JSON.stringify(ids),
    "prefs.rs groups " + rustIds + " vs chrome.js " + ids,
  );
  assert(
    AUTO_ORDER.length === ids.length &&
      ids.every((g) => AUTO_ORDER.includes(g)),
    "AUTO_FOLD_ORDER is not the four groups once each: " + AUTO_ORDER,
  );
});

check(
  "every group has a pill before its buttons, and every button says its group",
  () => {
    for (const [g, members] of GROUPS) {
      const pill = tagOf("group-" + g);
      assert(pill, "no #group-" + g + " pill in the markup");
      for (const attr of [
        'data-group-pill="' + g + '"',
        'aria-haspopup="menu"',
        'aria-controls="group-menu"',
      ]) {
        assert(pill.includes(attr), "#group-" + g + " lacks " + attr);
      }
      const pillAt = htmlSrc.indexOf('id="group-' + g + '"');
      assert(pillAt > breakAt, "#group-" + g + " is not on row two");
      for (const id of members) {
        const tag = tagOf(id);
        assert(tag, "#" + id + " is not in the markup");
        assert(
          tag.includes('data-group="' + g + '"'),
          "#" + id + " does not say it is in " + g,
        );
        assert(
          htmlSrc.indexOf('id="' + id + '"') > pillAt,
          "#" + id + " is written before its pill",
        );
      }
    }
    // Nothing in the markup claims a group the table does not list it in.
    for (const m of htmlSrc.matchAll(
      /id="([\w-]+)"\s+data-group="([\w-]+)"/g,
    )) {
      const listed = GROUPS.some(
        ([g, members]) => g === m[2] && members.includes(m[1]),
      );
      assert(
        listed,
        "#" +
          m[1] +
          " says data-group=" +
          m[2] +
          " but TOOLBAR_GROUPS does not list it there",
      );
    }
  },
);

check("a menu never takes the opaque repaint away from solid-backdrop", () => {
  const css = cssSrc.replace(/\/\*[\s\S]*?\*\//g, "");
  const rules = [...css.matchAll(/body\.translucent-backdrop\.menu-open[^{,]*/g)].map((m) => m[0]);
  assert(rules.length >= 2, "the menu's transparent-backend rules are missing");
  for (const r of rules) {
    assert(r.includes(":not(.solid-backdrop)"), "`" + r.trim() + "` also applies under solid-backdrop");
  }
});

check("Print and Save as PDF are offered from what Rust says the platform can do", () => {
  const ipc = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
  assert(/"print": crate::platform::print_supported\(\)/.test(ipc), "chrome_caps does not report print");
  assert(/"save_pdf": crate::platform::save_pdf_supported\(\)/.test(ipc), "chrome_caps does not report save_pdf");
  assert(/r\.print\b/.test(chromeSrc) && /r\.save_pdf\b/.test(chromeSrc), "chrome.js does not read the print caps");
});

check("the shield and the freeze chip are in no group", () => {
  for (const id of ["btn-privacy", "btn-freeze"]) {
    const tag = tagOf(id);
    assert(
      tag && !/data-group=/.test(tag),
      "#" +
        id +
        " carries a data-group: a fold could hide the protection state",
    );
    assert(
      !GROUPS.some(([, members]) => members.includes(id)),
      "#" + id + " is in TOOLBAR_GROUPS",
    );
  }
});

check(
  "a folded group hides its buttons and shows its pill, in the stylesheet",
  () => {
    const css = cssSrc.replace(/\/\*[\s\S]*?\*\//g, "");
    assert(
      /\.feature-btn\.group-pill\s*\{\s*display:\s*none !important;/.test(css),
      "a pill is not hidden by default",
    );
    for (const [g] of GROUPS) {
      const hide = new RegExp(
        'html\\[data-folded~="' +
          g +
          '"\\] \\.feature-btn\\[data-group="' +
          g +
          '"\\] \\{\\s*display: none !important;',
      );
      const show = new RegExp(
        'html\\[data-folded~="' +
          g +
          '"\\] \\.feature-btn\\.group-pill\\[data-group-pill="' +
          g +
          '"\\] \\{\\s*display: flex !important;',
      );
      assert(hide.test(css), "folding " + g + " does not hide its buttons");
      assert(show.test(css), "folding " + g + " does not show its pill");
    }
  },
);

check("an add-on button is a Tools member: in its menu while Tools is folded, on the row only by choice", () => {
  const css = cssSrc.replace(/\/\*[\s\S]*?\*\//g, "");
  assert(
    /\.feature-btn\[data-addon-button\]:not\(\[data-shown\]\) \{\s*display: none !important;/.test(css),
    "an add-on button taken off the toolbar is still drawn on it",
  );
  // Since 2026-10-22 (the grouped default) nothing brings an add-on button
  // back onto the row while Tools is folded: the folded-group rule hides it
  // like Theme or Chat, and the Tools menu lists it.
  assert(
    !/html\[data-folded~="tools"\][^{]*\[data-addon-button\][^{]*\{\s*display: flex/.test(css),
    "a folded Tools still draws an add-on button on the row",
  );
});

// ---- chrome.js in the stub -------------------------------------------------
//
// Static checks run first, and a failure there ends the run before chrome.js
// is executed (a crash at load is not a named reason). The stub has neither
// observer; this gate gives chrome.js recording ones, so it can fire the
// width observer on #toolbar and the state observer by hand.
const staticChecks = checks;
checks = [];
async function runChecks(list) {
  for (const [name, fn] of list) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL  " + name + ": " + e.message);
    }
  }
}
function finish() {
  if (plant && PLANTS[plant][0] === "html")
    fs.rmSync(path.dirname(htmlPath), { recursive: true });
  if (failures.length) {
    console.error("TOOLBAR GROUPS GATE FAIL:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nTOOLBAR GROUPS GATE OK");
}

process.env.HTML_PATH = htmlPath;
require(path.join(root, "scripts/domstub.js"));
const resizeObservers = [];
global.ResizeObserver = class {
  constructor(cb) {
    this.cb = cb;
    this.targets = [];
    resizeObservers.push(this);
  }
  observe(t) {
    this.targets.push(t);
  }
  disconnect() {}
};
const mutationObservers = [];
global.MutationObserver = class {
  constructor(cb) {
    this.cb = cb;
    this.opts = [];
    mutationObservers.push(this);
  }
  observe(t, opts) {
    this.opts.push(opts || {});
  }
  disconnect() {}
};
global.getComputedStyle = () => ({ color: "rgb(0, 0, 0)" });
// Rust serves the stored folds on <html> (with_boot_attributes); the first
// toolbar_folded_get reply is held, so a measurement can land before it.
let releaseBootFolds;
global.rbResolve.toolbar_folded_get = new Promise((r) => (releaseBootFolds = r));
global.document.documentElement.dataset.folded = "saved";

const html = () => global.document.documentElement.dataset;
const sent = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);
const fireWidth = () => {
  for (const o of resizeObservers) {
    if (o.targets.includes(global.$("toolbar"))) o.cb([]);
  }
};
// The state observer is the one that watches aria-pressed.
// A REAL DOM queues a mutation record for every classList.add and remove and
// every setAttribute, changed or not, for a toggle only when it changes
// something, and for every textContent write. The stub queues nothing, so
// the elements the state observer writes to are made to count the records a
// real page would queue, and fireState delivers until no more are queued,
// as a page would. An observer whose own writes requeue it never settles,
// and that is a frozen chrome (round 3, R-001).
let queued = 0;
const watchedText = [];
function watch(node) {
  if (!node || node._watched) return;
  node._watched = true;
  const cl = node.classList;
  const add = cl.add;
  const remove = cl.remove;
  const toggle = cl.toggle;
  cl.add = (...c) => {
    queued += 1;
    return add(...c);
  };
  cl.remove = (...c) => {
    queued += 1;
    return remove(...c);
  };
  cl.toggle = (c, on) => {
    const before = cl.contains(c);
    const r = toggle(c, on);
    if (cl.contains(c) !== before) queued += 1;
    return r;
  };
  const setAttr = node.setAttribute;
  node.setAttribute = function (k, v) {
    queued += 1;
    return setAttr.call(this, k, v);
  };
  if (Array.isArray(node._text)) watchedText.push(node);
}
const watchAll = () => {
  const ids = ["btn-main-menu", "btn-reader", "btn-about", "btn-integrity", "btn-update"];
  for (const [g, members] of GROUPS) {
    ids.push("group-" + g, "group-" + g + "-state", ...members);
  }
  for (const id of ids) watch(global.$(id));
};
let lastPasses = 0;
const fireState = () => {
  watchAll();
  const mine = mutationObservers.filter((o) =>
    o.opts.some((x) => (x.attributeFilter || []).includes("aria-pressed")),
  );
  let passes = 0;
  do {
    queued = 0;
    const texts = watchedText.map((n) => n._text.length);
    for (const o of mine) o.cb([]);
    watchedText.forEach((n, i) => {
      queued += n._text.length - texts[i];
    });
    passes += 1;
  } while (queued > 0 && passes < 8);
  lastPasses = passes;
  if (queued > 0) {
    throw new Error("the state observer does not settle: its own writes keep queueing records");
  }
};
const groupMenu = () => global.$("group-menu");
const menuGone = (m) =>
  m.hidden === true || m.classList.contains("menu-closing");

check("boot wears the stored folds", async () => {
  await flush();
  // A measurement before the first reply keeps what Rust served (round 4,
  // R-004).
  fireWidth();
  await flush();
  assert(html().folded === "saved", "a measurement before the first reply erased the served folds: " + html().folded);
  releaseBootFolds({ groups: ["saved"] });
  await flush();
  assert(
    html().folded === "saved",
    "stored saved fold not worn; data-folded=" + html().folded,
  );
  assert(
    global.$("fold-saved").checked === true,
    "the Saved box is not checked",
  );
  assert(
    global.$("fold-network").checked === false,
    "the Network box is checked with nothing stored",
  );
});

check("a fold box follows what Rust stored, not the click", async () => {
  global.rbResolve.toolbar_folded_set = { groups: ["tools"] };
  global.rbCalls.length = 0;
  const box = global.$("fold-network");
  box.checked = true;
  box._fire("change");
  await flush();
  const call = sent("toolbar_folded_set")[0];
  assert(
    call &&
      JSON.stringify(call.args.groups) === JSON.stringify(["network", "saved"]),
    "the click sent " + JSON.stringify(call && call.args),
  );
  assert(
    html().folded === "tools",
    "the chrome wears the click, not the reply: " + html().folded,
  );
  assert(
    global.$("fold-network").checked === false &&
      global.$("fold-tools").checked === true,
    "the boxes do not show the reply",
  );
  // Back to Saved alone.
  global.rbResolve.toolbar_folded_set = { groups: ["saved"] };
  global.$("fold-saved").checked = true;
  global.$("fold-saved")._fire("change");
  await flush();
  assert(
    html().folded === "saved",
    "setup: could not return to the Saved fold",
  );
});

check(
  "a folded group's menu lists its shown buttons over an open panel",
  async () => {
    // The stub starts every element hidden; these two are shown, Fill stays
    // hidden as it is when nothing on the page can be filled.
    global.$("btn-vault").hidden = false;
    global.$("btn-library").hidden = false;
    global.$("btn-fill").hidden = true;
    const privacy = global.$("privacy-panel");
    if (privacy.hidden) global.$("btn-privacy")._fire("click");
    await flush();
    assert(privacy.hidden === false, "setup: the privacy panel did not open");
    const pill = global.$("group-saved");
    pill._fire("click");
    await flush();
    assert(
      groupMenu().hidden === false,
      "the Saved pill did not open its menu",
    );
    assert(
      pill.getAttribute("aria-expanded") === "true",
      "the pill does not say it is expanded",
    );
    assert(
      privacy.hidden === false,
      "opening a group's menu closed the panel under it",
    );
    const entries = Array.from(groupMenu().children || []);
    assert(
      entries.length === 2,
      "expected Vault and Library, found " + entries.length + " entries",
    );
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
    assert(menuGone(groupMenu()), "Escape did not close the group's menu");
    assert(
      privacy.hidden === false,
      "one Escape closed the menu and the panel",
    );
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
  },
);

check(
  "an entry opens the real panel, and closing it returns to the pill",
  async () => {
    const pill = global.$("group-saved");
    let focused = false;
    pill.focus = () => {
      focused = true;
    };
    pill._fire("click");
    await flush();
    const first = Array.from(groupMenu().children || [])[0];
    assert(first, "the Saved menu has no entries");
    first._fire("click");
    await flush();
    assert(
      global.$("vault-panel").hidden === false,
      "the Vault entry did not open the vault",
    );
    assert(
      menuGone(groupMenu()),
      "choosing an entry left the group's menu open",
    );
    focused = false;
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
    assert(
      global.$("vault-panel").hidden === true,
      "Escape did not close the vault",
    );
    assert(
      focused,
      "focus did not return to the folded pill; its button cannot be seen",
    );
  },
);

check("a narrow window folds from the right and never stores it", async () => {
  // Layout the stub does not do: row two wraps while Tools is unfolded.
  let roomy = false;
  const wraps = () =>
    !roomy && !(html().folded || "").split(" ").includes("tools");
  for (const id of ["btn-privacy", "btn-chat"]) {
    const node = global.$(id);
    node.offsetParent = {};
    Object.defineProperty(node, "offsetTop", {
      configurable: true,
      get: () => (id === "btn-chat" && wraps() ? 40 : 0),
    });
  }
  global.rbCalls.length = 0;
  fireWidth();
  await flush();
  assert(
    html().folded === "saved tools",
    "the width did not fold Tools: " + html().folded,
  );
  assert(
    global.$("fold-tools").checked === false,
    "the width's fold shows as a stored choice",
  );
  assert(
    sent("toolbar_folded_set").length === 0,
    "the width's fold was sent to Rust",
  );
  roomy = true;
  fireWidth();
  await flush();
  assert(
    html().folded === "saved",
    "Tools stayed folded with room for it: " + html().folded,
  );
});

check(
  "a side rail takes the pills with their buttons and forces no fold",
  async () => {
    global.rbResolve.toolbar_placement_set = { placement: "left" };
    global.$("placement-left")._fire("click");
    await flush();
    assert(
      global.$("group-saved").parentNode === global.$("sidebar"),
      "the Saved pill did not move to the rail",
    );
    assert(
      global.$("btn-vault").parentNode === global.$("sidebar"),
      "the vault did not move to the rail",
    );
    fireWidth();
    await flush();
    assert(html().folded === "saved", "a rail forced a fold: " + html().folded);
    global.rbResolve.toolbar_placement_set = { placement: "top_left" };
    global.$("placement-top_left")._fire("click");
    await flush();
  },
);

check(
  "a folded pill and the menu button show that something inside wants attention",
  async () => {
    const dns = global.$("btn-dns");
    dns.hidden = false;
    dns.classList.add("is-warning");
    fireState();
    assert(
      global.$("group-network").classList.contains("is-warning"),
      "the Network pill does not show its DNS warning",
    );
    dns.classList.remove("is-warning");
    fireState();
    assert(
      !global.$("group-network").classList.contains("is-warning"),
      "the Network pill kept a warning that cleared",
    );
    // The main menu button, with its menu closed (round 2, R-004).
    const integrity = global.$("btn-integrity");
    integrity.classList.add("is-warning");
    fireState();
    assert(
      global.$("btn-main-menu").classList.contains("is-warning"),
      "the menu button does not show a warning inside it",
    );
    integrity.classList.remove("is-warning");
    fireState();
    assert(
      !global.$("btn-main-menu").classList.contains("is-warning"),
      "the menu button kept a warning that cleared",
    );
    global.$("btn-save-pdf").disabled = true;
    fireState();
    assert(
      global.$("menu-save-pdf").disabled === true,
      "a disabled control left its entry enabled",
    );
    global.$("btn-save-pdf").disabled = false;
    fireState();
  },
);

check("the state observer settles on its own writes", () => {
  fireState();
  fireState();
  assert(lastPasses <= 2, "the state observer needed " + lastPasses + " passes with nothing changing");
});

check("an interception on a folded button is on its pill and in its menu", async () => {
  const tab = global.$("btn-tab");
  tab.hidden = false;
  tab.classList.add("is-intercepted");
  tab.setAttribute("aria-label", "Tab Activity. This connection is being intercepted.");
  fireState();
  const pill = global.$("group-network");
  assert(pill.classList.contains("is-warning"), "the Network pill does not show the interception");
  assert(
    /intercepted/.test(global.$("group-network-state").textContent),
    "the Network pill's description does not say the connection is intercepted",
  );
  pill._fire("click");
  await flush();
  const first = Array.from(groupMenu().children || [])[0];
  assert(first && first.classList.contains("is-intercepted"), "the Tab Activity entry does not carry the interception");
  const label = first && (first.children || [])[0];
  assert(label && /intercepted/.test(label.textContent), "the Tab Activity entry's name does not say it is intercepted");
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  tab.classList.remove("is-intercepted");
  tab.setAttribute("aria-label", "Tab Activity");
  fireState();
  assert(!pill.classList.contains("is-warning"), "the pill kept an interception that ended");
});

check("an open group menu keeps following its buttons", async () => {
  global.$("btn-vault").hidden = false;
  global.$("btn-library").hidden = false;
  global.$("btn-fill").hidden = true;
  global.$("btn-library").disabled = false;
  global.$("group-saved")._fire("click");
  await flush();
  assert(groupMenu().children.length === 2, "setup: expected Vault and Library");
  global.$("btn-library").disabled = true;
  fireState();
  assert(groupMenu().children[1].disabled === true, "a button disabled while its menu was open left its entry enabled");
  global.$("btn-fill").hidden = false;
  fireState();
  assert(groupMenu().children.length === 3, "Fill appeared while the menu was open and got no entry");
  global.$("btn-fill").hidden = true;
  global.$("btn-library").disabled = false;
  fireState();
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
});

check("a closing menu keeps the body's menu state until it is gone", async () => {
  // Timers held, so the fade can be looked at halfway.
  const realSetTimeout = global.setTimeout;
  const held = [];
  global.setTimeout = (fn) => {
    held.push(fn);
    return held.length;
  };
  try {
    global.$("btn-main-menu")._fire("click");
    await flush();
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
    const menu = global.$("main-menu");
    assert(menu.classList.contains("menu-closing") && menu.hidden === false, "setup: the menu did not start fading");
    assert(global.document.body.classList.contains("menu-open"), "body.menu-open went before the menu did");
    while (held.length) held.shift()();
    await flush();
    assert(menu.hidden === true, "the menu did not hide after its fade");
    assert(!global.document.body.classList.contains("menu-open"), "body.menu-open outlived the menu");
  } finally {
    global.setTimeout = realSetTimeout;
  }
});

check("re-measuring keeps an automatically folded group's menu open", async () => {
  let roomy = false;
  const wraps = () => !roomy && !(html().folded || "").split(" ").includes("tools");
  for (const id of ["btn-privacy", "btn-chat"]) {
    const node = global.$(id);
    node.offsetParent = {};
    Object.defineProperty(node, "offsetTop", {
      configurable: true,
      get: () => (id === "btn-chat" && wraps() ? 40 : 0),
    });
  }
  global.$("btn-theme").hidden = false;
  fireWidth();
  await flush();
  assert(html().folded === "saved tools", "setup: Tools did not fold");
  global.$("group-tools")._fire("click");
  await flush();
  assert(groupMenu().hidden === false, "setup: the Tools menu did not open");
  fireWidth();
  await flush();
  assert(
    groupMenu().hidden === false && !groupMenu().classList.contains("menu-closing"),
    "a resize that kept Tools folded closed its open menu",
  );
  roomy = true;
  fireWidth();
  await flush();
  assert(html().folded === "saved", "Tools stayed folded with room for it");
  assert(groupMenu().hidden === true, "the Tools menu stayed open after Tools unfolded");
});

check("two fold changes before the first reply both stick", async () => {
  // Each request's reply is held; the stub reads the reply twice per request,
  // so one promise is handed out per turn.
  const held = [];
  let current = null;
  Object.defineProperty(global.rbResolve, "toolbar_folded_set", {
    configurable: true,
    enumerable: true,
    get: () => {
      if (!current) {
        current = new Promise((r) => held.push(r));
        queueMicrotask(() => {
          current = null;
        });
      }
      return current;
    },
  });
  global.rbCalls.length = 0;
  global.$("fold-tabs").checked = true;
  global.$("fold-tabs")._fire("change");
  await flush();
  global.$("fold-network").checked = true;
  global.$("fold-network")._fire("change");
  await flush();
  const sets = sent("toolbar_folded_set").map((c) => JSON.stringify(c.args.groups));
  assert(sets[1] === JSON.stringify(["network", "tabs", "saved"]), "the second change dropped the first: " + sets.join(" then "));
  held[0]({ groups: ["tabs", "saved"] });
  held[1]({ groups: ["network", "tabs", "saved"] });
  await flush();
  assert(html().folded === "network tabs saved", "after both replies the chrome wears " + html().folded);
  delete global.rbResolve.toolbar_folded_set;
  global.rbResolve.toolbar_folded_set = { groups: ["saved"] };
  global.$("fold-saved").checked = true;
  global.$("fold-saved")._fire("change");
  await flush();
  assert(html().folded === "saved", "setup: could not return to the Saved fold");
});

check("the Updates entry reaches update.js's button", async () => {
  fireState();
  assert(global.$("btn-update"), "update.js built no Updates button");
  assert(global.$("btn-update").classList.contains("in-menu"), "the Updates pill is not in the menu");
  global.$("btn-main-menu")._fire("click");
  await flush();
  assert(global.$("menu-update").hidden === false, "the Updates entry is hidden with update.js's button present");
  global.$("menu-update")._fire("click");
  await flush();
  assert(global.$("update-panel").hidden === false, "the Updates entry did not open the update panel");
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
});

check("Print and Save as PDF stay out of the menu where the platform cannot do them", async () => {
  // This harness's chrome_caps says nothing about printing, as WebKitGTK's
  // says false.
  global.$("btn-main-menu")._fire("click");
  await flush();
  assert(global.$("menu-print").hidden === true, "Print is offered on a platform that cannot print");
  assert(global.$("menu-save-pdf").hidden === true, "Save as PDF is offered on a platform that cannot write one");
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
});

// Replies to toolbar_folded_set, held: the stub reads the reply twice per
// request, so one promise is handed out per turn.
function holdFoldReplies() {
  const held = [];
  let current = null;
  Object.defineProperty(global.rbResolve, "toolbar_folded_set", {
    configurable: true,
    enumerable: true,
    get: () => {
      if (!current) {
        current = new Promise((res, rej) => held.push({ res, rej }));
        queueMicrotask(() => {
          current = null;
        });
      }
      return current;
    },
  });
  return held;
}
async function backToSaved() {
  delete global.rbResolve.toolbar_folded_set;
  global.rbResolve.toolbar_folded_set = { groups: ["saved"] };
  global.$("fold-saved").checked = true;
  global.$("fold-saved")._fire("change");
  await flush();
  assert(html().folded === "saved", "setup: could not return to the Saved fold");
}

check("a refused fold change falls back to what Rust last stored", async () => {
  const held = holdFoldReplies();
  global.$("fold-tabs").checked = true;
  global.$("fold-tabs")._fire("change");
  await flush();
  global.$("fold-network").checked = true;
  global.$("fold-network")._fire("change");
  await flush();
  held[0].res({ groups: ["tabs", "saved"] });
  held[1].rej(new Error("io"));
  await flush();
  assert(html().folded === "tabs saved", "after a stored change and a refused one the chrome wears " + html().folded);
  assert(global.$("fold-tabs").checked === true && global.$("fold-network").checked === false, "the boxes do not show what is stored");
  global.rbCalls.length = 0;
  global.$("fold-tools").checked = true;
  global.$("fold-tools")._fire("change");
  await flush();
  const last = sent("toolbar_folded_set").pop();
  assert(last && JSON.stringify(last.args.groups) === JSON.stringify(["tabs", "saved", "tools"]), "the next change dropped the stored Tabs fold: " + JSON.stringify(last && last.args));
  held[2].res({ groups: ["tabs", "saved", "tools"] });
  await flush();
  await backToSaved();
});

check("a box whose change is on its way survives a remeasure", async () => {
  const held = holdFoldReplies();
  global.$("fold-network").checked = true;
  global.$("fold-network")._fire("change");
  await flush();
  fireWidth();
  await flush();
  assert(global.$("fold-network").checked === true, "a remeasure unchecked a box whose change is on its way");
  held[0].res({ groups: ["network", "saved"] });
  await flush();
  assert(global.$("fold-network").checked === true && html().folded === "network saved", "the stored change is not worn");
  await backToSaved();
});

check("a group menu kept open through a resize goes where its pill went", async () => {
  let roomy = false;
  const wraps = () => !roomy && !(html().folded || "").split(" ").includes("tools");
  for (const id of ["btn-privacy", "btn-chat"]) {
    const node = global.$(id);
    node.offsetParent = {};
    Object.defineProperty(node, "offsetTop", {
      configurable: true,
      get: () => (id === "btn-chat" && wraps() ? 40 : 0),
    });
  }
  const pill = global.$("group-tools");
  let pillLeft = 900;
  pill.getBoundingClientRect = () => ({ left: pillLeft, right: pillLeft + 60, top: 100, bottom: 130, width: 60, height: 30 });
  global.window.innerWidth = 1200;
  global.$("btn-theme").hidden = false;
  fireWidth();
  await flush();
  assert(html().folded === "saved tools", "setup: Tools did not fold");
  pill._fire("click");
  await flush();
  assert(groupMenu().style.getPropertyValue("--menu-left") === "900px", "setup: the menu did not open at its pill");
  global.window.innerWidth = 600;
  pillLeft = 500;
  fireWidth();
  await flush();
  assert(groupMenu().hidden === false, "setup: the menu closed on a resize that kept Tools folded");
  assert(
    groupMenu().style.getPropertyValue("--menu-left") === "364px",
    "the menu stayed at " + groupMenu().style.getPropertyValue("--menu-left") + " in a 600px window",
  );
  roomy = true;
  fireWidth();
  await flush();
});

check("a menu rebuilt under the keyboard keeps it on the same button", async () => {
  global.$("btn-vault").hidden = false;
  global.$("btn-library").hidden = false;
  global.$("btn-fill").hidden = true;
  global.$("group-saved")._fire("click");
  await flush();
  const library = groupMenu().children[1];
  assert(library, "setup: no Library entry");
  global.document.activeElement = library;
  const make = global.document.createElement;
  let focused = null;
  global.document.createElement = (t) => {
    const n = make(t);
    n.focus = () => {
      focused = n;
    };
    return n;
  };
  try {
    global.$("btn-fill").hidden = false;
    fireState();
  } finally {
    global.document.createElement = make;
    global.document.activeElement = null;
  }
  assert(groupMenu().children.length === 3, "setup: Fill did not join the menu");
  assert(focused === groupMenu().children[2], "the keyboard moved off Library when Fill appeared");
  global.$("btn-fill").hidden = true;
  fireState();
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
});

check("on a rail a group menu opens clear of the rail", async () => {
  global.rbResolve.toolbar_placement_set = { placement: "left" };
  global.$("placement-left")._fire("click");
  await flush();
  const rail = global.$("sidebar");
  rail.hidden = false;
  rail.getBoundingClientRect = () => ({ left: 0, right: 56, top: 88, bottom: 900, width: 56, height: 812 });
  const pill = global.$("group-saved");
  pill.getBoundingClientRect = () => ({ left: 9, right: 47, top: 300, bottom: 332, width: 38, height: 32 });
  pill._fire("click");
  await flush();
  const left = groupMenu().style.getPropertyValue("--menu-left");
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  global.rbResolve.toolbar_placement_set = { placement: "top_left" };
  global.$("placement-top_left")._fire("click");
  await flush();
  assert(left === "60px", "the menu opened at " + left + ", under the 56px rail");
});

check("a page handoff ends an open or fading menu before it reaches Rust", async () => {
  const menu = global.$("main-menu");
  // Open: the menu closes, and the uncover goes out before the tab switch.
  global.$("btn-main-menu")._fire("click");
  await flush();
  assert(menu.hidden === false, "setup: the menu did not open");
  global.rbCalls.length = 0;
  global.window.__rb.request("tab_switch", { id: 1 }).catch(() => {});
  await flush();
  const order = global.rbCalls.map((c) => c.cmd + (c.cmd === "chrome_overlay" ? ":" + c.args.cover : ""));
  assert(menu.hidden === true, "the menu is still open after a tab switch");
  const uncover = order.indexOf("chrome_overlay:false");
  const sw = order.indexOf("tab_switch");
  assert(uncover >= 0 && uncover < sw, "the tab switch reached Rust before the uncover: " + order.join(", "));
  // Fading: the fade is cut short the same way.
  const realSetTimeout = global.setTimeout;
  global.setTimeout = () => 1;
  try {
    global.$("btn-main-menu")._fire("click");
    await flush();
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
    assert(menu.classList.contains("menu-closing"), "setup: the menu is not fading");
    global.rbCalls.length = 0;
    global.window.__rb.request("tab_switch", { id: 1 }).catch(() => {});
    await flush();
  } finally {
    global.setTimeout = realSetTimeout;
  }
  const order2 = global.rbCalls.map((c) => c.cmd + (c.cmd === "chrome_overlay" ? ":" + c.args.cover : ""));
  assert(menu.hidden === true, "a fading menu outlived a tab switch");
  const u2 = order2.indexOf("chrome_overlay:false");
  const s2 = order2.indexOf("tab_switch");
  assert(u2 >= 0 && u2 < s2, "during a fade the tab switch reached Rust before the uncover: " + order2.join(", "));
});

check("About this site brings an open Tab Activity forward", async () => {
  const panel = global.$("tab-panel");
  if (panel.hidden) global.$("btn-tab")._fire("click");
  await flush();
  assert(panel.hidden === false, "setup: Tab Activity did not open");
  global.$("btn-main-menu")._fire("click");
  await flush();
  global.$("menu-site-info")._fire("click");
  await flush();
  assert(panel.hidden === false, "About this site closed the open Tab Activity panel");
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
});

check("an add-on button is a Tools member: in its menu, its pill, and its focus", async () => {
  const rb = global.window.__rb;
  assert(rb.addGroupMember("network", "btn-addon-test-pages") === false, "an add-on joined a group other than Tools");
  assert(rb.addGroupMember("tools", "btn-theme") === false, "a non-add-on id joined at runtime");
  assert(rb.addGroupMember("tools", "btn-addon-Bad") === false, "an id outside the pattern joined");
  const b = global.document.createElement("button");
  b.id = "btn-addon-test-pages";
  b.className = "feature-btn";
  b.dataset.group = "tools";
  b.setAttribute("data-addon-button", "");
  b.hidden = false;
  const label = global.document.createElement("span");
  label.className = "feature-label";
  label.textContent = "Test pages";
  b.appendChild(label);
  global.$("toolbar").appendChild(b);
  assert(rb.addGroupMember("tools", b.id) === true, "the add-on button could not join Tools");
  const section = global.document.createElement("section");
  section.id = "addon-panel-test-pages";
  global.document.body.appendChild(section);
  rb.registerPanel("addon-test-pages", { el: section, button: b, heightPx: 400 });
  // Fold Tools, through what Rust stores. The button is NOT kept on the
  // toolbar (no data-shown): only the menu can reach it.
  global.rbResolve.toolbar_folded_set = { groups: ["saved", "tools"] };
  global.$("fold-tools").checked = true;
  global.$("fold-tools")._fire("change");
  await flush();
  assert(html().folded === "saved tools", "setup: Tools did not fold: " + html().folded);
  for (const id of ["btn-theme", "btn-ocr-region"]) global.$(id).hidden = false;
  const pill = global.$("group-tools");
  let focused = false;
  pill.focus = () => {
    focused = true;
  };
  pill._fire("click");
  await flush();
  const entries = Array.from(groupMenu().children || []);
  const entry = entries.find((e) => (e.children || []).some((c) => c.textContent === "Test pages"));
  assert(entry, "the folded Tools menu does not list the add-on");
  entry._fire("click");
  await flush();
  assert(section.hidden === false, "the add-on's entry did not open its panel");
  focused = false;
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  assert(section.hidden === true, "Escape did not close the add-on's panel");
  assert(focused, "focus did not return to the Tools pill; the add-on's button cannot be seen");
  // The pill aggregates its members' standing state classes (is-active,
  // is-warning), as for every built-in member; an open panel is shown by its
  // button's aria-pressed, never on a pill. This proves the add-on member is
  // read, not that opening sets the class (review R-007, rejected).
  b.classList.add("is-active");
  fireState();
  assert(pill.classList.contains("is-active"), "the Tools pill does not show the add-on's state");
  b.classList.remove("is-active");
  fireState();
  global.rbResolve.toolbar_folded_set = { groups: ["saved"] };
  global.$("fold-tools").checked = false;
  global.$("fold-tools")._fire("change");
  await flush();
});

// Plan review 2026-10-22 (F2): where the keyboard goes when an add-on's panel
// closes, for each place its button can be: on the row (Tools open, shown),
// in the Tools menu (Tools folded, shown or not), nowhere on screen (Tools
// open, taken off the row: only Menu > Add-ons reached it).
check("an add-on's panel hands the keyboard back to what can be seen", async () => {
  const b = global.$("btn-addon-test-pages");
  const section = global.$("addon-panel-test-pages");
  assert(b && section, "setup: the add-on button from the previous check is gone");
  const watch = (id) => {
    const el = global.$(id);
    const box = { hit: false };
    el.focus = () => {
      box.hit = true;
    };
    return box;
  };
  const closeAndSee = async () => {
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
    assert(section.hidden === true, "Escape did not close the add-on's panel");
  };
  // Tools open, button shown on the row: back to the button itself.
  assert(!/\btools\b/.test(html().folded || ""), "setup: Tools is still folded");
  b.setAttribute("data-shown", "");
  let own = { hit: false };
  b.focus = () => {
    own.hit = true;
  };
  global.window.__rb.openPanel ? global.window.__rb.openPanel("addon-test-pages") : b._fire("click");
  await flush();
  assert(section.hidden === false, "the add-on's button did not open its panel");
  await closeAndSee();
  assert(own.hit, "with Tools open, focus did not return to the add-on's own button");
  // Tools open, button taken off the row: back to the Menu button.
  b.removeAttribute("data-shown");
  const menu = watch("btn-main-menu");
  b._fire("click");
  await flush();
  assert(section.hidden === false, "setup: the panel did not open");
  await closeAndSee();
  assert(menu.hit, "a hidden add-on's panel did not return focus to the Menu button");
  // Tools folded, button shown: off the row now, so back to the Tools pill.
  b.setAttribute("data-shown", "");
  global.rbResolve.toolbar_folded_set = { groups: ["tools"] };
  global.$("fold-tools").checked = true;
  global.$("fold-tools")._fire("change");
  await flush();
  const pill = watch("group-tools");
  own = { hit: false };
  b._fire("click");
  await flush();
  assert(section.hidden === false, "setup: the panel did not open while folded");
  await closeAndSee();
  assert(pill.hit && !own.hit, "with Tools folded, focus went to the add-on's button, which is off the row");
  global.rbResolve.toolbar_folded_set = { groups: [] };
  global.$("fold-tools").checked = false;
  global.$("fold-tools")._fire("change");
  await flush();
});

(async () => {
  await runChecks(staticChecks);
  if (failures.length) {
    finish();
    return;
  }
  try {
    new Function(chromeSrc)();
    // update.js runs after chrome.js, as the page loads it (defer); it
    // builds the Updates button the menu proxies.
    new Function(fs.readFileSync(path.join(chromeDir, "update.js"), "utf8"))();
  } catch (e) {
    failures.push("chrome.js or update.js failed to initialize: " + e.message);
    finish();
    return;
  }
  await runChecks(checks);
  finish();
})();
