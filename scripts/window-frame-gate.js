// The window frame on Windows (1.0.7): no title bar, so the tab strip is one.
//
// WHAT THIS PINS, each property proven against a planted defect on every run:
//
// 1. With chrome_caps window_frame (Windows), the three controls, the drag
//    area and the top resize band show, and each control sends exactly its
//    own window_control action. Without it (Linux) none of them shows.
// 2. A primary press on the strip's OWN space (the strip, the tab row's empty
//    part, the reserved drag area) moves the window; a double press maximizes
//    or restores. A press on a tab, a button or the new-tab button, and any
//    other mouse button, is not a title-bar press.
// 3. Where the strip is the title bar, a double-click on its empty space does
//    not also open a tab; without the frame it still does.
// 4. The resize band sends the edge it was pressed on.
// 5. window_state swaps Maximize and Restore (glyph via the html attribute,
//    label and title via the button).
//
// Run: node scripts/window-frame-gate.js   (or via scripts/chrome-js-gate.sh)
// PATANYX_WINDOW_FRAME_PLANT=<name> plants one defect; the gate must then print
// WINDOW FRAME GATE FAILED. PATANYX_WINDOW_FRAME_LIST_PLANTS=1 lists the names.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");

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

const PLANTS = {
  "controls-always": [
    '    $("window-controls").hidden = !windowFrame;\n',
    '    $("window-controls").hidden = false;\n',
  ],
  "min-sends-max": [
    '$("win-min").addEventListener("click", () => windowControl({ action: "minimize" }));',
    '$("win-min").addEventListener("click", () => windowControl({ action: "maximize" }));',
  ],
  "chip-drags": [
    '    return target === $("tabstrip") || target === $("tabs") || target === $("window-drag");\n',
    "    return true;\n",
  ],
  "double-press-drags": [
    '    windowControl({ action: ev.detail >= 2 ? "maximize" : "drag" });\n',
    '    windowControl({ action: "drag" });\n',
  ],
  "right-button-drags": [
    "    if (!windowFrame || ev.button !== 0 || !isTitleSpace(ev.target)) return;\n",
    "    if (!windowFrame || !isTitleSpace(ev.target)) return;\n",
  ],
  "dblclick-opens-tab": [
    "      if (windowFrame) return;\n      if (ev.target !== wrap) return;\n",
    "      if (ev.target !== wrap) return;\n",
  ],
  "no-restore-label": [
    '      ? i18nText("chrome-js-win-restore", "Restore")\n',
    '      ? i18nText("chrome-js-win-maximize", "Maximize")\n',
  ],
  "fill-loses-restore": [
    '  rebuildOnLocaleFill(() => {\n    if (windowFrame) setWindowMaximized(document.documentElement.dataset.windowMaximized === "on");\n  });\n',
    "",
  ],
  "resize-edge-lost": [
    '      windowControl({ action: "resize", edge });\n',
    '      windowControl({ action: "resize" });\n',
  ],
};

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const plant = process.env.PATANYX_WINDOW_FRAME_PLANT;
if (plant) {
  const spec = PLANTS[plant];
  assert(spec, "unknown plant " + plant + "; known: " + Object.keys(PLANTS));
  assert(
    chromeJs.split(spec[0]).length === 2,
    "cannot plant " + plant + ": its anchor changed spelling",
  );
  chromeJs = chromeJs.replace(spec[0], spec[1]);
}
if (process.env.PATANYX_WINDOW_FRAME_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}

// Linux, in a second harness: the same chrome.js with no window_frame.
function bootWithoutFrame() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "window-frame-"));
  try {
    const jsCopy = path.join(dir, "chrome.js");
    fs.writeFileSync(jsCopy, chromeJs);
    const probe = `
      const fs = require("fs");
      process.env.HTML_PATH = ${JSON.stringify(process.env.HTML_PATH)};
      require(${JSON.stringify(path.join(__dirname, "domstub.js"))});
      global.rbResolve.chrome_caps = { print: false, save_pdf: false };
      new Function(fs.readFileSync(${JSON.stringify(jsCopy)}, "utf8"))();
      (async () => {
        for (let i = 0; i < 12; i += 1) await new Promise((r) => setImmediate(r));
        const out = {
          controls: global.$("window-controls").hidden,
          drag: global.$("window-drag").hidden,
          band: global.$("window-resize").hidden,
        };
        global.rbCalls.length = 0;
        global.$("tabstrip")._fire("mousedown", { button: 0, detail: 1 });
        global.$("tabs")._fire("dblclick", {});
        for (let i = 0; i < 12; i += 1) await new Promise((r) => setImmediate(r));
        out.windowCalls = global.rbCalls.filter((c) => c.cmd === "window_control").length;
        out.tabNew = global.rbCalls.filter((c) => c.cmd === "tab_new").length;
        process.stdout.write(JSON.stringify(out));
      })();
    `;
    const probeFile = path.join(dir, "probe.js");
    fs.writeFileSync(probeFile, probe);
    return JSON.parse(
      execFileSync(process.execPath, [probeFile], { encoding: "utf8" })
        .trim()
        .split("\n")
        .pop(),
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

require("./domstub.js");
global.rbResolve.chrome_caps = {
  print: true,
  save_pdf: true,
  window_frame: true,
  window_maximized: false,
};
new Function(chromeJs)();

function windowCalls() {
  return global.rbCalls
    .filter((c) => c.cmd === "window_control")
    .map((c) => c.args);
}
async function press(el, init) {
  global.rbCalls.length = 0;
  el._fire("mousedown", Object.assign({ button: 0, detail: 1 }, init || {}));
  await flush();
  return windowCalls();
}

check(
  "on Windows the controls, the drag area and the resize band show",
  async () => {
    await flush();
    for (const id of ["window-controls", "window-drag", "window-resize"]) {
      assert(
        global.$(id).hidden === false,
        `#${id} is hidden although chrome_caps reports window_frame`,
      );
    }
  },
);

check("each control sends exactly its own action", async () => {
  for (const [id, action] of [
    ["win-min", "minimize"],
    ["win-max", "maximize"],
    ["win-close", "close"],
  ]) {
    global.rbCalls.length = 0;
    global.$(id)._fire("click");
    await flush();
    const calls = windowCalls();
    assert(
      calls.length === 1,
      `#${id} sent ${calls.length} window_control calls`,
    );
    assert(
      JSON.stringify(calls[0]) === JSON.stringify({ action }),
      `#${id} sent ${JSON.stringify(calls[0])}, expected {"action":"${action}"}`,
    );
  }
});

check(
  "a press on the strip's own space moves the window; a double press maximizes",
  async () => {
    const strip = global.$("tabstrip");
    for (const target of ["tabstrip", "tabs", "window-drag"]) {
      const one = await press(strip, { target: global.$(target) });
      assert(
        JSON.stringify(one) === JSON.stringify([{ action: "drag" }]),
        `a press on #${target} sent ${JSON.stringify(one)}`,
      );
      const two = await press(strip, { target: global.$(target), detail: 2 });
      assert(
        JSON.stringify(two) === JSON.stringify([{ action: "maximize" }]),
        `a double press on #${target} sent ${JSON.stringify(two)}`,
      );
    }
  },
);

check(
  "a press on a control, or with another button, is not a title-bar press",
  async () => {
    const strip = global.$("tabstrip");
    for (const target of ["btn-newtab", "win-min", "window-resize-n"]) {
      const calls = await press(strip, { target: global.$(target) });
      assert(calls.length === 0, `a press on #${target} moved the window`);
    }
    const right = await press(strip, { target: strip, button: 2 });
    assert(right.length === 0, "a right-button press moved the window");
  },
);

check(
  "a double-click on the empty strip does not also open a tab on Windows",
  async () => {
    global.rbCalls.length = 0;
    global.$("tabs")._fire("dblclick", {});
    await flush();
    assert(
      !global.rbCalls.some((c) => c.cmd === "tab_new"),
      "the double-click opened a tab as well as maximizing",
    );
  },
);

check("the resize band sends the edge it was pressed on", async () => {
  for (const edge of ["n", "nw", "ne"]) {
    const calls = await press(global.$("window-resize-" + edge));
    assert(
      JSON.stringify(calls) === JSON.stringify([{ action: "resize", edge }]),
      `the ${edge} band sent ${JSON.stringify(calls)}`,
    );
  }
});

check("window_state swaps Maximize and Restore", async () => {
  global.window.__rb_event({
    event: "window_state",
    data: { maximized: true },
  });
  await flush();
  assert(
    document.documentElement.dataset.windowMaximized === "on",
    "maximized did not reach the html attribute",
  );
  assert(
    global.$("win-max").getAttribute("aria-label") === "Restore",
    "the control is not named Restore while maximized",
  );
  global.window.__rb_event({
    event: "window_state",
    data: { maximized: false },
  });
  await flush();
  assert(
    document.documentElement.dataset.windowMaximized === "off",
    "restored did not reach the html attribute",
  );
  assert(
    global.$("win-max").getAttribute("aria-label") === "Maximize",
    "the control is not named Maximize when restored",
  );
});

check("a locale fill keeps Restore while maximized (code review R-004)", async () => {
  global.window.__rb_event({ event: "window_state", data: { maximized: true } });
  await flush();
  global.window.__rb_event({
    event: "ui_locale_fill",
    data: {
      generation: 9,
      locale: "en-XA",
      messages: { "chrome-js-win-restore": "XA Restore", "chrome-js-win-maximize": "XA Maximize" },
    },
  });
  await flush();
  assert(
    global.$("win-max").getAttribute("aria-label") === "XA Restore",
    "after a locale fill the maximized control is named " +
      JSON.stringify(global.$("win-max").getAttribute("aria-label")) +
      ", not the new Restore",
  );
});

check(
  "without window_frame (Linux) nothing shows and the strip keeps its double-click",
  () => {
    const out = bootWithoutFrame();
    assert(
      out.controls === true,
      "the window controls show without window_frame",
    );
    assert(out.drag === true, "the drag area shows without window_frame");
    assert(out.band === true, "the resize band shows without window_frame");
    assert(
      out.windowCalls === 0,
      "a press on the strip sent window_control without window_frame",
    );
    assert(
      out.tabNew === 1,
      `a double-click on the empty strip opened ${out.tabNew} tabs without window_frame, expected 1`,
    );
  },
);

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
    console.error("\nWINDOW FRAME GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nWINDOW FRAME OK");
})();
