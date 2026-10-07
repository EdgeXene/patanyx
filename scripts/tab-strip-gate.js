// The tab strip and the address bar behave the way a browser is expected to.
//
// WHY THIS EXISTS. Both surfaces worked, in the sense that every control had a
// handler and every gate was green, and both had friction nobody had written a
// test for: the strip was rebuilt on every tabs_changed, so nothing on it could
// slide and a repaint mid-drag threw away the chip under the pointer; the drag
// was HTML5 drag and drop, which jumped the strip under a ghost image; the bar
// replaced whatever someone was typing whenever the page redirected; and
// nothing put the keyboard anywhere at launch. This gate pins the behavior
// that replaced all of that:
//
//   1. Chips are KEYED: a repaint updates the chip it has, never a new one.
//   2. The drag is a pointer drag that is abandoned, sending nothing, when the
//      strip changes under it, on Escape, or when the pointer is taken away --
//      and the click that follows a drag never switches tabs.
//   3. Middle-click closes a tab; a double-click on the empty strip opens one.
//   4. Reorders SLIDE (an inverted frame, then released), except under
//      prefers-reduced-motion, where they land.
//   5. The address bar keeps an edit while the same tab redirects, gives it
//      up on a switch, reverts it on Escape, and selects the whole address on
//      the first click.
//   6. Boot asks Rust to place the keyboard, once; and a window coming back
//      to the front with nothing focused puts it in the address bar.
//
// Every numbered property is proven against a planted defect: run with
// PATANYX_TAB_STRIP_PLANT=<name> (names below) and this gate must fail.
// chrome-js-gate.sh runs every plant on every build.
//
// Run: node scripts/tab-strip-gate.js   (or via scripts/chrome-js-gate.sh)
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
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

// Each plant removes ONE behavior and leaves every handler and every source
// spelling intact, so what turns red is a behavioral assertion. Each must
// match exactly once, or the plant could land somewhere that proves nothing.
const PLANTS = {
  // 1: a new chip on every repaint, the way the strip used to be built.
  rebuild: ["let chip = tabChipsById.get(tab.id);", "let chip = null;"],
  // 2: the strip changes mid-drag and the drag carries on regardless.
  "no-drag-cancel": [
    "      tabDrag &&\n      (!ids.includes(tabDrag.id) ||",
    "      false &&\n      (!ids.includes(tabDrag.id) ||",
  ],
  // 2: the click after a drag switches to the tab just moved.
  "no-click-suppress": ["if (tabClickSuppressed) {", "if (false) {"],
  // 2: the swap is judged by the dragged chip's center, so a wide tab can
  // never pass a narrower last one (the defect a real strip found).
  "center-crossing": [
    "if (right >= slots[i].left + slots[i].width / 2) to = i;",
    "if (left + own.width / 2 >= slots[i].left + slots[i].width / 2) to = i;",
  ],
  // 3: middle-click does nothing.
  "no-middle-close": [
    'chip.addEventListener("auxclick", (ev) => {\n      if (ev.button !== 1) return;',
    'chip.addEventListener("auxclick", (ev) => {\n      if (ev.button !== 1 || ev) return;',
  ],
  // 4: reorders jump.
  "no-slide": [
    'chip.style.transform = "translateX(" + dx + "px)";\n      moved.push(chip);',
    "moved.push(chip);",
  ],
  // 5: a redirect replaces what someone is typing.
  "overwrite-edit": [
    "const keepEdit =\n          urlEdited &&",
    "const keepEdit =\n          false &&",
  ],
  // 5: Escape leaves the edit in the bar.
  "no-escape-revert": [
    'if (ev.key === "Escape" && urlInput.value !== urlCommitted) {',
    "if (false) {",
  ],
  // 5: the bar never learns which tab its first address belongs to, so the
  // first redirect after launch replaces what is being typed.
  "no-strip-tab-id": ["if (urlBarTabId === null) {", "if (false) {"],
  // 5: an address arriving after the launch focus collapses the selection,
  // so the first keystroke appends instead of replacing.
  "no-reselect": ["if (selectedAll) urlInput.select();", ""],
  // 5: a click that brings the keyboard back to the bar (after Enter sent it
  // to the page) places a caret instead of selecting the address.
  "no-returning-click-select": [
    "performance.now() - urlFocusedAt < URL_CLICK_FOCUS_MS;",
    "false;",
  ],
  // 5: a focus counts for every click inside the window, so a quick second
  // click re-selects instead of placing the cursor.
  "focus-counts-twice": [
    "// One focus, one click: a quick second click must place the cursor.\n    urlFocusedAt = -Infinity;",
    "// One focus, one click: a quick second click must place the cursor.",
  ],
  // 5: submitting an address leaves a panel open over the page it loads.
  "no-panel-close-on-submit": ["if (openPanelName) closeOpenPanel();", ""],
  // 5: leaving the bar keeps showing an edit the page moved on from.
  "stale-edit-after-blur": [
    "if (urlDeferred) {\n      urlDeferred = false;\n      urlInput.value = urlCommitted;",
    "if (false) {\n      urlDeferred = false;\n      urlInput.value = urlCommitted;",
  ],
  // 2: chip widths follow title repaints during a drag.
  "no-width-freeze": [
    'slot.chip.style.flex = "0 0 " + slot.width + "px";',
    "void slot;",
  ],
  // 6: showing a tab gives its page the keyboard again, before any modal check.
  "show-tab-focuses": [
    "pub fn show_tab(_view: &TabView, webview: &WebView) {\n    let _ = webview.set_visible(true);\n}",
    "pub fn show_tab(_view: &TabView, webview: &WebView) {\n    let _ = webview.set_visible(true);\n    let _ = webview.focus();\n}",
  ],
  // 6: the guard is inverted: the page gets the keyboard when a modal covers it.
  "inverted-modal-guard": [
    "    fn show_and_focus_tab(&self, index: usize) {\n        let tab = &self.tabs[index];\n        platform::show_tab(&tab.view, &tab.webview);\n        if self.modal_covers_window() {",
    "    fn show_and_focus_tab(&self, index: usize) {\n        let tab = &self.tabs[index];\n        platform::show_tab(&tab.view, &tab.webview);\n        if !self.modal_covers_window() {",
  ],
  // 6: the guard function never reports a modal.
  "guard-always-false": [
    "    fn modal_covers_window(&self) -> bool {\n        matches!(\n            self.chrome_arrangement,\n            crate::platform::ChromeLayout::Overlay\n        )\n    }",
    "    fn modal_covers_window(&self) -> bool {\n        false\n    }",
  ],
  // 6: new webviews take the keyboard as they are created again (Windows).
  "builder-focuses": [
    "    let builder = builder.with_focused(false);\n    let webview = builder.build_as_child(&hosts.window)?;",
    "    let webview = builder.build_as_child(&hosts.window)?;",
  ],
  // 6: a page is focused BEFORE the modal check, as well as after it.
  "focus-before-guard": [
    "        platform::show_tab(&tab.view, &tab.webview);\n        if self.modal_covers_window() {",
    "        platform::show_tab(&tab.view, &tab.webview);\n        platform::focus_content(&tab.webview);\n        if self.modal_covers_window() {",
  ],
  // 5: the first click puts the caret mid-URL.
  "no-first-click-select": [
    "urlSelectOnMouseUp = document.activeElement !== urlInput;",
    "urlSelectOnMouseUp = false;",
  ],
  // 6: nothing places the keyboard at launch.
  "no-startup-focus": ['rb("startup_focus").catch(() => {});', ""],
};

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const srcDir = path.join(root, "crates/app/src");
const rustSources = {
  state: fs.readFileSync(path.join(srcDir, "state.rs"), "utf8"),
  windows: fs.readFileSync(path.join(srcDir, "platform/windows.rs"), "utf8"),
  unix: fs.readFileSync(path.join(srcDir, "platform/unix.rs"), "utf8"),
};
const plant = process.env.PATANYX_TAB_STRIP_PLANT;
if (plant) {
  const spec = PLANTS[plant];
  assert(spec, "unknown plant " + plant + "; known: " + Object.keys(PLANTS));
  // A plant lands in chrome.js, or in the one Rust source that carries it.
  const inRust = Object.keys(rustSources).find(
    (k) => rustSources[k].split(spec[0]).length === 2,
  );
  if (inRust) {
    rustSources[inRust] = rustSources[inRust].replace(spec[0], spec[1]);
  } else {
    assert(
      chromeJs.split(spec[0]).length === 2,
      "cannot plant " + plant + ": its call site changed spelling",
    );
    chromeJs = chromeJs.replace(spec[0], spec[1]);
  }
}
if (process.env.PATANYX_TAB_STRIP_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}
new Function(chromeJs)();

const fireChrome = (event, data) => global.window.__rb_event({ event, data });
const strip = global.$("tabs");
const url = global.$("url");
const tabChips = () => Array.from(strip.children || []);
const chipFor = (id) =>
  tabChips().find((chip) => Number(chip.dataset.tabId) === id);
const tabItems = (ids, active, titles) =>
  ids.map((id) => ({
    id,
    url: "https://tab-" + id + ".example/",
    title: (titles && titles[id]) || "Tab " + id,
    active: id === active,
  }));
const calls = (cmd) => global.rbCalls.filter((call) => call.cmd === cmd);
// Boxes by CURRENT place in the strip, 100px apart and 96 wide, because the
// stub measures everything at zero and a drag against zeros goes nowhere.
const layOutChips = () => {
  for (const chip of tabChips()) {
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
};
const paint = (ids, active, titles) => {
  fireChrome("tabs_changed", { items: tabItems(ids, active, titles) });
  layOutChips();
};
// Press chip `id` and drag it far enough to START a drag (one slot right).
const startDrag = (id) => {
  const chip = chipFor(id);
  chip._fire("pointerdown", { button: 0, pointerId: 7, clientX: 48 });
  chip._fire("pointermove", { pointerId: 7, clientX: 160 });
  assert(
    chip.classList.contains("dragging"),
    "setup: the drag on tab " + id + " did not start",
  );
  return chip;
};
const dragIsOver = () =>
  !strip.classList.contains("tab-dragging") &&
  tabChips().every(
    (chip) => !chip.classList.contains("dragging") && !chip.style.transform,
  );

// Rust source, read as text: native focus into a PAGE is decided in one place.
// A page behind an open panel must never get the keyboard (someone typing into
// what looks like the vault's passphrase field would be typing into the page),
// and a check made AFTER a native focus call is too late.
check("native focus into a page happens only where a modal is checked first", () => {
  // Each platform's show_tab only SHOWS, and each build_content builds the
  // webview WITHOUT focus (wry defaults to focused, which moved the keyboard
  // into every new tab as it was created, background tabs included).
  for (const name of ["windows", "unix"]) {
    const src = rustSources[name];
    const at = src.indexOf("pub fn show_tab(");
    assert(at >= 0, name + ".rs has no show_tab");
    const body = src.slice(at, src.indexOf("\n}\n", at));
    assert(
      !/\.focus\(\)/.test(body),
      name + ".rs show_tab focuses the page itself, before AppState can " +
        "check for an open panel",
    );
    const bc = src.indexOf("pub fn build_content(");
    const bcBody = src.slice(bc, src.indexOf("\n}\n", bc));
    const unfocused = bcBody.indexOf("builder.with_focused(false)");
    const built = bcBody.search(/builder\.build_(as_child|gtk)\(/);
    assert(
      unfocused >= 0 && built > unfocused,
      name + ".rs build_content builds a content webview that takes the " +
        "keyboard as it is created",
    );
  }
  const state = rustSources.state;
  const fnBody = (sig) => {
    const at = state.indexOf(sig);
    assert(at >= 0, "state.rs has no `" + sig + "`");
    return state.slice(at, state.indexOf("\n    }\n", at));
  };
  // The guard itself must test the Overlay arrangement; a guard that always
  // says "no modal" would satisfy every shape check below.
  assert(
    /fn modal_covers_window\(&self\) -> bool \{\s*matches!\(\s*self\.chrome_arrangement,\s*crate::platform::ChromeLayout::Overlay\s*\)\s*\}/.test(
      state,
    ),
    "modal_covers_window no longer tests chrome_arrangement == Overlay",
  );
  // The ONLY functions allowed to focus a page, each with the guard's exact
  // shape: modal covering -> the chrome gets the keyboard, and the page
  // focus sits in the other branch.
  const guarded = [
    [
      "fn show_and_focus_tab(",
      /if self\.modal_covers_window\(\) \{\s*self\.focus_chrome\(\);\s*\} else \{[^}]*platform::focus_content\(/,
    ],
    [
      "pub fn focus_active_content(",
      /if self\.modal_covers_window\(\) \{\s*self\.focus_chrome\(\);\s*return;\s*\}[\s\S]*platform::focus_content\(/,
    ],
    [
      "pub fn restore_focus(",
      /FocusSurface::Content if self\.modal_covers_window\(\) => \{\s*self\.focus_chrome\(\);[\s\S]*FocusSurface::Content => \{[\s\S]*platform::focus_content\(/,
    ],
  ];
  let allowed = 0;
  for (const [sig, shape] of guarded) {
    const body = fnBody(sig);
    assert(
      shape.test(body),
      sig + " does not keep the chrome's keyboard while a modal covers " +
        "the window (its guard is missing, inverted or reordered)",
    );
    // EXACTLY one focus call, and the shape above puts it after the guard.
    // Counting every call would let a second one slip in BEFORE the check
    // and still pass (the case a review reproduced by mutation).
    const n = body.split("platform::focus_content(").length - 1;
    assert(
      n === 1,
      sig + " calls platform::focus_content " + n + " times; exactly one, " +
        "after the modal check, is allowed",
    );
    allowed += n;
  }
  const total = state.split("platform::focus_content(").length - 1;
  assert(
    total === allowed,
    "state.rs focuses a page in " + (total - allowed) + " place(s) outside " +
      "the three guarded functions",
  );
  // Side by Side shows its second page through platform::set_side_by_side,
  // which must only SHOW, never focus, on both backends.
  for (const name of ["windows", "unix"]) {
    const src = rustSources[name];
    const at = src.indexOf("pub fn set_side_by_side(");
    if (at < 0) continue;
    const body = src.slice(at, src.indexOf("\n}\n", at));
    assert(
      !/focus/.test(body.replace(/\/\/[^\n]*/g, "")),
      name + ".rs set_side_by_side moves the keyboard; it may only show",
    );
  }
  const shows = state.split("platform::show_tab(").length - 1;
  assert(
    shows === 1 && fnBody("fn show_and_focus_tab(").includes("platform::show_tab("),
    "state.rs calls platform::show_tab outside show_and_focus_tab",
  );
});

check("boot asks Rust to place the keyboard, exactly once", async () => {
  await flush();
  assert(
    calls("startup_focus").length === 1,
    "boot sent startup_focus " +
      calls("startup_focus").length +
      " times. With none, a launched browser leaves the keyboard nowhere and " +
      "the first thing typed is lost.",
  );
});

// BEFORE any url_changed: at a real launch the first one can fire before the
// chrome has loaded, so the bar starts not knowing which tab it describes.
check("the first redirect after launch keeps what is being typed", () => {
  paint([1, 2, 3], 1);
  withFocus(url, () => {
    typeInto("typed at launch");
    fireChrome("url_changed", { url: "https://start.example/", tab: 1 });
    assert(
      url.value === "typed at launch",
      "the start page committing replaced what was being typed: " + url.value,
    );
    url._fire("blur");
  });
});

check("an address arriving after the launch focus stays selected", () => {
  let selected = 0;
  const select = url.select;
  url.select = () => {
    selected += 1;
  };
  try {
    withFocus(url, () => {
      url.value = "";
      url.selectionStart = url.selectionEnd = 0;
      fireChrome("url_changed", { url: "https://late.example/", tab: 1 });
      assert(
        selected === 1,
        "the address landed in a focused, empty bar as a caret at the end, " +
          "so the first keystroke after launch appends to it",
      );
      // A caret someone PLACED is theirs: not turned into a selection.
      url.selectionStart = url.selectionEnd = 3;
      fireChrome("url_changed", { url: "https://later.example/", tab: 1 });
      assert(selected === 1, "a placed caret was replaced by a full selection");
    });
  } finally {
    url.select = select;
  }
});

check("a repaint updates the chip it has instead of building a new one", () => {
  paint([1, 2, 3], 1);
  const before = tabChips();
  paint([1, 2, 3], 2, { 2: "Renamed" });
  const after = tabChips();
  assert(after.length === 3, "the repaint left " + after.length + " chips");
  assert(
    after.every((chip, i) => chip === before[i]),
    "a title repaint replaced the chips. A new chip has no previous position " +
      "to slide from, and a repaint mid-drag would throw away the one under " +
      "the pointer.",
  );
  assert(
    chipFor(2).querySelector(".chip-title").textContent === "Renamed" &&
      chipFor(2).classList.contains("active") &&
      !chipFor(1).classList.contains("active"),
    "the kept chips were not repainted with the new title and active tab",
  );
});

check("a tab closing or opening mid-drag abandons the drag", async () => {
  for (const [label, next] of [
    ["the dragged tab closing", [2, 3]],
    ["another tab opening", [1, 2, 3, 4]],
  ]) {
    paint([1, 2, 3], 1);
    global.rbCalls.length = 0;
    const chip = startDrag(1);
    paint(next, next[0]);
    assert(
      dragIsOver(),
      label + " left the drag running against a strip that no longer exists",
    );
    chip._fire("pointerup", { pointerId: 7, clientX: 160 });
    await flush();
    assert(
      calls("tab_reorder").length === 0,
      label + " mid-drag still committed a reorder on release",
    );
  }
});

check(
  "Escape, a cancelled pointer, or lost capture abandons a drag",
  async () => {
    const ways = [
      [
        "Escape",
        () =>
          global.fireDocument("keydown", {
            key: "Escape",
            preventDefault() {},
            stopPropagation() {},
          }),
      ],
      [
        "pointercancel",
        (chip) => chip._fire("pointercancel", { pointerId: 7 }),
      ],
      [
        "lostpointercapture",
        (chip) => chip._fire("lostpointercapture", { pointerId: 7 }),
      ],
    ];
    for (const [label, abandon] of ways) {
      paint([1, 2, 3], 1);
      global.rbCalls.length = 0;
      const chip = startDrag(2);
      abandon(chip);
      assert(
        dragIsOver(),
        label + " did not end the drag and put the chips back",
      );
      assert(chip._capture === null, label + " left the pointer captured");
      chip._fire("pointerup", { pointerId: 7, clientX: 160 });
      chip._fire("click");
      await flush();
      assert(
        calls("tab_reorder").length === 0,
        label + " still committed a reorder",
      );
      assert(
        calls("tab_switch").length === 0,
        "the release after " + label + " became a click that switched tabs",
      );
      // The suppression is one click deep: the next press clears it.
      chip._fire("pointerdown", { button: 0, pointerId: 8, clientX: 148 });
      chip._fire("pointerup", { pointerId: 8, clientX: 148 });
      chip._fire("click");
      assert(
        calls("tab_switch").length === 1,
        "after " +
          label +
          ", the NEXT genuine click on a tab was swallowed too",
      );
    }
  },
);

check(
  "a completed drag commits, and its trailing click switches nothing",
  async () => {
    paint([1, 2, 3], 1);
    global.rbCalls.length = 0;
    global.rbResolve.tab_reorder = {
      ids: [2, 1, 3],
      items: tabItems([2, 1, 3], 1),
    };
    const chip = startDrag(1);
    chip._fire("pointerup", { pointerId: 7, clientX: 160 });
    chip._fire("click");
    await flush();
    assert(
      calls("tab_reorder").length === 1 &&
        calls("tab_reorder")[0].args.ids.join(",") === "2,1,3",
      "the drag did not commit 2,1,3: " + JSON.stringify(calls("tab_reorder")),
    );
    assert(
      calls("tab_switch").length === 0,
      "the click the engine sends after a drag switched to the tab just moved",
    );
  },
);

check("a still click switches tabs, the current tab included", () => {
  paint([1, 2, 3], 1);
  global.rbCalls.length = 0;
  for (const id of [2, 1]) {
    const chip = chipFor(id);
    chip._fire("pointerdown", { button: 0, pointerId: 9, clientX: 10 });
    chip._fire("pointermove", { pointerId: 9, clientX: 12 });
    chip._fire("pointerup", { pointerId: 9, clientX: 12 });
    chip._fire("click");
  }
  const ids = calls("tab_switch").map((call) => call.args.id);
  assert(
    ids.join(",") === "2,1",
    "clicks sent tab_switch for " +
      JSON.stringify(ids) +
      "; the CURRENT tab must be sent too, so Rust can put the keyboard in " +
      "its page",
  );
});

check("the close button and other buttons never start a drag", () => {
  paint([1, 2, 3], 1);
  const chip = chipFor(2);
  chip._fire("pointerdown", {
    button: 0,
    pointerId: 3,
    clientX: 190,
    target: chip.querySelector(".chip-close"),
  });
  chip._fire("pointermove", { pointerId: 3, clientX: 400 });
  assert(
    chip._capture === null && !chip.classList.contains("dragging"),
    "a press on the close button started a drag",
  );
  chip._fire("pointerdown", { button: 2, pointerId: 4, clientX: 150 });
  chip._fire("pointermove", { pointerId: 4, clientX: 400 });
  assert(
    !chip.classList.contains("dragging"),
    "a right-button press started a drag",
  );
});

check("a wide tab can be dragged past narrower ones to either end", async () => {
  // Chips are as wide as their titles. With every chip the same width, as
  // the other checks lay them out, a rule that only works for equal widths
  // passes; on a real strip a wide tab held at the end never took the last
  // place. Tab 1 is 200 wide, tabs 2 and 3 are 60.
  paint([1, 2, 3], 1);
  const widths = { 1: 200, 2: 60, 3: 60 };
  for (const chip of tabChips()) {
    chip.getBoundingClientRect = () => {
      let left = 0;
      for (const other of tabChips()) {
        if (other === chip) break;
        left += widths[Number(other.dataset.tabId)] + 4;
      }
      const width = widths[Number(chip.dataset.tabId)];
      return { left, width, right: left + width, top: 0, height: 28 };
    };
  }
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = { ids: [2, 3, 1], items: tabItems([2, 3, 1], 1) };
  const wide = chipFor(1);
  wide._fire("pointerdown", { button: 0, pointerId: 5, clientX: 100 });
  wide._fire("pointermove", { pointerId: 5, clientX: 400 });
  wide._fire("pointerup", { pointerId: 5, clientX: 400 });
  await flush();
  assert(
    calls("tab_reorder").length === 1 &&
      calls("tab_reorder")[0].args.ids.join(",") === "2,3,1",
    "a wide tab held at the end of the strip did not take the last place: " +
      JSON.stringify(calls("tab_reorder")),
  );
});

check(
  "middle-click closes a tab; double-click on the empty strip opens one",
  () => {
    paint([1, 2, 3], 1);
    global.rbCalls.length = 0;
    chipFor(3)._fire("auxclick", { button: 2 });
    chipFor(3)._fire("auxclick", { button: 1 });
    assert(
      calls("tab_close").length === 1 && calls("tab_close")[0].args.id === 3,
      "middle-click did not close tab 3 (and only on the middle button): " +
        JSON.stringify(calls("tab_close")),
    );
    strip._fire("dblclick", { target: chipFor(1) });
    assert(
      calls("tab_new").length === 0,
      "a double-click on a chip opened a new tab",
    );
    strip._fire("dblclick", { target: strip });
    assert(
      calls("tab_new").length === 1,
      "a double-click on the empty strip did not open a new tab",
    );
  },
);

// Records every transform written to each chip, which is how a slide is
// visible at all in a stub whose timers fire immediately: an inverted frame
// is written and then released in the same tick.
const recordTransforms = () => {
  const log = new Map();
  for (const chip of tabChips()) {
    let value = "";
    const writes = [];
    log.set(Number(chip.dataset.tabId), writes);
    Object.defineProperty(chip.style, "transform", {
      configurable: true,
      get: () => value,
      set: (v) => {
        value = String(v);
        writes.push(value);
      },
    });
  }
  return log;
};

check("a keyboard move slides, except under reduced motion", async () => {
  paint([1, 2, 3], 1);
  global.rbResolve.tab_reorder = {
    ids: [2, 1, 3],
    items: tabItems([2, 1, 3], 1),
  };
  let log = recordTransforms();
  chipFor(1)._fire("keydown", { key: "ArrowRight" });
  await flush();
  assert(
    log.get(1).includes("translateX(-100px)") &&
      log.get(2).includes("translateX(100px)"),
    "the swap jumped: no chip was drawn back at its old place to slide from. " +
      JSON.stringify([...log]),
  );
  assert(
    !chipFor(1).style.transform && !chipFor(2).style.transform,
    "a slide was left standing instead of released",
  );

  const matchMedia = global.window.matchMedia;
  global.window.matchMedia = (query) => ({
    matches: /reduce/.test(query),
    addEventListener() {},
    addListener() {},
  });
  try {
    paint([2, 1, 3], 1);
    global.rbResolve.tab_reorder = {
      ids: [1, 2, 3],
      items: tabItems([1, 2, 3], 1),
    };
    log = recordTransforms();
    chipFor(1)._fire("keydown", { key: "ArrowLeft" });
    await flush();
    const drawn = [...log.values()].flat().filter(Boolean);
    assert(
      drawn.length === 0,
      "prefers-reduced-motion still animated the move: " +
        JSON.stringify(drawn),
    );
  } finally {
    global.window.matchMedia = matchMedia;
  }
});

// ---- the address bar ----

const withFocus = (el, fn) => {
  global.document.activeElement = el;
  try {
    return fn();
  } finally {
    global.document.activeElement = undefined;
  }
};
const typeInto = (text) => {
  url.value = text;
  url._fire("input");
};

check("an edit survives the same tab redirecting, not a switch", () => {
  fireChrome("url_changed", { url: "https://a.example/", tab: 7 });
  withFocus(url, () => {
    typeInto("where I was going");
    fireChrome("url_changed", { url: "https://a.example/next", tab: 7 });
    assert(
      url.value === "where I was going",
      "a redirect on the same tab replaced what was being typed: " + url.value,
    );
    fireChrome("url_changed", { url: "https://b.example/", tab: 8 });
    assert(
      url.value === "https://b.example/",
      "a tab switch kept the old tab's edit in the bar: " + url.value,
    );
    // An event that names no tab is treated as a switch, as before.
    typeInto("again");
    fireChrome("url_changed", { url: "https://c.example/" });
    assert(
      url.value === "https://c.example/",
      "an unnamed url_changed kept the edit",
    );
    // Leaving the bar ends the edit; the page's next address is shown.
    fireChrome("url_changed", { url: "https://c.example/", tab: 9 });
    typeInto("abandoned");
    url._fire("blur");
    fireChrome("url_changed", { url: "https://c.example/2", tab: 9 });
    assert(
      url.value === "https://c.example/2",
      "an edit outlived the bar losing focus, so the bar could name a page " +
        "that is not the one showing: " +
        url.value,
    );
  });
});

check("Escape puts back the page's address and only then stops there", () => {
  fireChrome("url_changed", { url: "https://home.example/", tab: 7 });
  let selected = 0;
  const select = url.select;
  url.select = () => {
    selected += 1;
  };
  try {
    typeInto("half-typed");
    let stopped = 0;
    url._fire("keydown", {
      key: "Escape",
      stopPropagation() {
        stopped += 1;
      },
    });
    assert(
      url.value === "https://home.example/" && selected === 1,
      "Escape did not restore and select the page's address: " + url.value,
    );
    assert(stopped === 1, "the revert let Escape also close something else");
    url._fire("keydown", {
      key: "Escape",
      stopPropagation() {
        stopped += 1;
      },
    });
    assert(
      stopped === 1,
      "with nothing to revert, the bar swallowed Escape; the find bar or a " +
        "panel behind it could no longer be closed from here",
    );
  } finally {
    url.select = select;
  }
});

check("Enter submits, and the page's answer replaces the bar", () => {
  fireChrome("url_changed", { url: "https://start.example/", tab: 7 });
  withFocus(url, () => {
    global.rbCalls.length = 0;
    typeInto("example.com");
    url._fire("keydown", { key: "Enter" });
    assert(
      calls("navigate").length === 1 &&
        calls("navigate")[0].args.url === "example.com",
      "Enter did not navigate to what was typed",
    );
    fireChrome("url_changed", { url: "https://example.com/", tab: 7 });
    assert(
      url.value === "https://example.com/",
      "the submitted text stayed in the bar instead of the page's address",
    );
  });
});

check("submitting an address closes an open panel before navigating", async () => {
  await flush();
  global.$("btn-about")._fire("click");
  assert(
    global.document.body.classList.contains("modal-open"),
    "setup: the About panel did not open",
  );
  global.rbCalls.length = 0;
  withFocus(url, () => {
    typeInto("example.org");
    url._fire("keydown", { key: "Enter" });
  });
  assert(
    !global.document.body.classList.contains("modal-open"),
    "the panel stayed open over the page the address loads: the keyboard " +
      "would sit behind a dialog that looks like it holds it",
  );
  const order = global.rbCalls.map((call) => call.cmd);
  const uncover = order.findIndex(
    (cmd, i) => cmd === "chrome_overlay" && global.rbCalls[i].args.cover === false,
  );
  const nav = order.indexOf("navigate");
  assert(
    uncover >= 0 && nav > uncover,
    "the panel must be closed (chrome_overlay off) before navigate reaches " +
      "Rust, which refuses to focus a page a panel covers: " +
      JSON.stringify(order),
  );
});

check("leaving the bar ends an edit the page moved on from", () => {
  fireChrome("url_changed", { url: "https://before.example/", tab: 7 });
  withFocus(url, () => {
    typeInto("wanted.example");
    fireChrome("url_changed", { url: "https://redirected.example/", tab: 7 });
    assert(url.value === "wanted.example", "setup: the edit was not kept");
    url._fire("blur");
  });
  assert(
    url.value === "https://redirected.example/",
    "after leaving the bar it still names an address nobody submitted " +
      "instead of the page showing: " +
      url.value,
  );
});

check("a drag freezes the chips' widths and releases them", () => {
  paint([1, 2, 3], 1);
  const chip = startDrag(1);
  assert(
    tabChips().every((c) => c.style.flex === "0 0 96px"),
    "chip widths are not frozen for the drag, so a title repaint mid-drag " +
      "moves chips under the pointer: " +
      tabChips().map((c) => c.style.flex),
  );
  chip._fire("pointerup", { pointerId: 7, clientX: 160 });
  assert(
    tabChips().every((c) => !c.style.flex),
    "the frozen widths outlived the drag",
  );
});

check(
  "the first click selects the whole address; the next places a caret",
  () => {
    let selected = 0;
    const select = url.select;
    url.select = () => {
      selected += 1;
    };
    try {
      url.selectionStart = url.selectionEnd = 0;
      url._fire("mousedown");
      url._fire("mouseup");
      assert(selected === 1, "the first click into the bar did not select it");
      withFocus(url, () => {
        url._fire("mousedown");
        url._fire("mouseup");
      });
      assert(selected === 1, "a click in a focused bar re-selected everything");
      url._fire("mousedown");
      url.selectionStart = 2;
      url.selectionEnd = 6;
      url._fire("mouseup");
      assert(selected === 1, "a first press that dragged a selection lost it");
      // The commonest way back: type, Enter (the keyboard goes to the page, the
      // bar stays this document's active element), read, click the bar. The
      // click's focus event arrives with it, and the address is selected.
      url.selectionStart = url.selectionEnd = 0;
      const now = performance.now;
      let clock = 1000000;
      performance.now = () => clock;
      try {
        withFocus(url, () => {
          url._fire("focus");
          url._fire("mousedown");
          url._fire("mouseup");
          assert(
            selected === 2,
            "a click that brought the keyboard back to the bar placed a caret " +
              "instead of selecting the address",
          );
          // A QUICK second click places the cursor too: a focus counts once.
          clock += 150;
          url._fire("mousedown");
          url._fire("mouseup");
          assert(
            selected === 2,
            "a second click 150 ms after the first re-selected the address " +
              "instead of placing the cursor",
          );
          // A later click inside a bar that already has the keyboard is a caret.
          clock += 5000;
          url._fire("mousedown");
          url._fire("mouseup");
          assert(selected === 2, "a later click in a focused bar re-selected it");
        });
      } finally {
        performance.now = now;
      }
    } finally {
      url.select = select;
    }
  },
);

check("a window coming back with nothing focused types into the bar", () => {
  let focused = 0;
  const focus = url.focus;
  url.focus = () => {
    focused += 1;
  };
  try {
    fireChrome("focus_restore", {});
    assert(
      focused === 1,
      "focus_restore with nothing focused left the bar alone",
    );
    withFocus(global.$("btn-back"), () => fireChrome("focus_restore", {}));
    assert(
      focused === 1,
      "focus_restore took the keyboard from the control that had it",
    );
  } finally {
    url.focus = focus;
  }
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
    console.error("\nTAB STRIP GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nTAB STRIP OK");
})();
