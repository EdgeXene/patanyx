// Find, Find across tabs and Image check in the main Menu (1.0.7).
//
// WHAT THIS PINS, each property proven against a planted defect on every run:
//
// 1. "Find on this page" opens the find bar, and closes an open panel first:
//    a menu leaves panels alone, but a search under a panel is hidden by it
//    and the panel keeps the keyboard (plan review 2026-10-13, R-003).
// 2. The two Premium entries render LOCKED without a licence (marked, still
//    reachable, aria-disabled) and, while locked, do nothing at all: no
//    panel, no picker, no notice, and the menu stays open. A locked
//    feature says what it is and starts nothing.
// 3. A locked vault is told to unlock, never to buy (the shared lock note).
// 4. With a licence, Find across tabs opens its panel and Image check opens
//    the Tools tab and starts the picker.
// 5. Image check is offered only while OCR is available.
//
// Run: node scripts/menu-extras-gate.js   (or via scripts/chrome-js-gate.sh)
// PATANYX_MENU_EXTRAS_PLANT=<name> plants one defect; the gate must then print
// MENU EXTRAS GATE FAILED. PATANYX_MENU_EXTRAS_LIST_PLANTS=1 lists the names.
const fs = require("fs");
const path = require("path");

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
  "tag-never-shown": [
    ".menu-entry.premium-locked .menu-premium-tag {\n  display: inline;",
    ".menu-entry.premium-locked .menu-premium-tag {\n  display: none;",
    "css",
  ],
  "find-keeps-panel": [
    "        closeMenu({ keepFocus: true });\n        closeOpenPanel();\n        openFindBar();\n",
    "        closeMenu({ keepFocus: true });\n        openFindBar();\n",
  ],
  "find-does-nothing": [
    "        closeOpenPanel();\n        openFindBar();\n        return;\n",
    "        closeOpenPanel();\n        return;\n",
  ],
  "locked-acts": [
    '      if (PREMIUM_MENU_ENTRIES.has(entry.id) && !premiumState.premium) return;\n',
    "",
  ],
  "unlocked-tabs-dead": [
    '        if (openPanelName !== "findtabs") togglePanelNamed("findtabs");\n',
    "",
  ],
  "no-picker": ['        $("leakcheck-pick").click();\n', ""],
  "ocr-ignored": [
    '      const allowed = !needs || (needs === "ocr" ? menuOcr : printCaps[needs]);\n',
    '      const allowed = !needs || needs === "ocr" || printCaps[needs];\n',
  ],
};

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
let css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
const plant = process.env.PATANYX_MENU_EXTRAS_PLANT;
if (plant) {
  const spec = PLANTS[plant];
  assert(spec, "unknown plant " + plant + "; known: " + Object.keys(PLANTS));
  // A third element "css" plants in the stylesheet; otherwise chrome.js.
  const inCss = spec[2] === "css";
  assert(
    (inCss ? css : chromeJs).split(spec[0]).length === 2,
    "cannot plant " + plant + ": its anchor changed spelling",
  );
  if (inCss) css = css.replace(spec[0], spec[1]);
  else chromeJs = chromeJs.replace(spec[0], spec[1]);
}
if (process.env.PATANYX_MENU_EXTRAS_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}

require("./domstub.js");
// OCR answers available unless a check says otherwise; read once at boot.
global.rbResolve.ocr_status = { available: true, file_choice: true };
global.rbResolve.chrome_caps = { print: true, save_pdf: true };
new Function(chromeJs)();

const setPremium = async (status) => {
  global.rbResolve.premium_status = status;
  global.window.__rb_event({ event: "vault_locked", data: {} });
  await flush();
};
const FREE = { state: "free", premium: false, on_sale: true };
const LOCKED_VAULT = { state: "locked", premium: false, on_sale: true };
const LICENSED = { state: "active", premium: true, on_sale: true };

async function openMenu() {
  if (global.$("main-menu").hidden) global.$("btn-main-menu")._fire("click");
  await flush();
  assert(
    global.$("main-menu").hidden === false,
    "setup: the Menu did not open",
  );
}
async function closeEverything() {
  for (let i = 0; i < 3; i += 1) {
    global.fireDocument("keydown", { key: "Escape" });
    await flush();
  }
}

check(
  "Find on this page closes an open panel, then opens the find bar",
  async () => {
    await closeEverything();
    global.$("btn-about")._fire("click");
    await flush();
    assert(
      global.$("about-panel").hidden === false,
      "setup: About did not open",
    );
    await openMenu();
    global.$("menu-find")._fire("click");
    await flush();
    assert(
      global.$("main-menu").hidden === true,
      "the Menu stayed open after Find",
    );
    assert(
      global.$("about-panel").hidden === true,
      "About stayed open over the search",
    );
    assert(global.$("findbar").hidden === false, "the find bar did not open");
    await closeEverything();
  },
);

for (const [label, status] of [
  ["without a licence", FREE],
  ["with the vault locked", LOCKED_VAULT],
]) {
  check(
    `${label}, both Premium entries are locked, marked and do nothing`,
    async () => {
      await closeEverything();
      await setPremium(status);
      await openMenu();
      for (const id of ["menu-find-tabs", "menu-image-check"]) {
        const entry = global.$(id);
        assert(
          entry.classList.contains("premium-locked"),
          `#${id} is not marked locked`,
        );
        assert(
          entry.getAttribute("aria-disabled") === "true",
          `#${id} lacks aria-disabled`,
        );
        assert(
          entry.disabled !== true,
          `#${id} is disabled, so a keyboard user cannot reach it`,
        );
        // The stub does not search inside an element, so the tag is read
        // from the markup and the rule that shows it from the stylesheet.
        const at = html.indexOf(`id="${id}"`);
        const markup = html.slice(at, html.indexOf("</button>", at));
        assert(
          /<span class="menu-premium-tag"[^>]*>Premium<\/span>/.test(markup),
          `#${id} has no "Premium" tag`,
        );
        assert(
          /\.menu-entry\.premium-locked \.menu-premium-tag \{\s*display: inline;/.test(css),
          "nothing shows the Premium tag on a locked entry",
        );
        if (status.state === "locked") {
          assert(
            !/upgrade|buy|renew/i.test(entry.getAttribute("title") || ""),
            `#${id} tells a locked vault to buy`,
          );
        }
        global.rbCalls.length = 0;
        const toastsBefore = global.$("toasts").children.length;
        entry._fire("click");
        await flush();
        assert(
          global.$("main-menu").hidden === false,
          `choosing the locked #${id} closed the Menu`,
        );
        assert(
          global.$("findtabs-panel").hidden === true,
          `the locked #${id} opened Find across tabs`,
        );
        assert(
          !global.rbCalls.some((c) => c.cmd === "file_pick_open"),
          `the locked #${id} started the picker`,
        );
        assert(
          global.$("toasts").children.length === toastsBefore,
          `the locked #${id} raised a notice`,
        );
      }
      await closeEverything();
    },
  );
}

check("with a licence, Find across tabs opens its panel", async () => {
  await closeEverything();
  await setPremium(LICENSED);
  await openMenu();
  const entry = global.$("menu-find-tabs");
  assert(
    !entry.classList.contains("premium-locked"),
    "the licensed entry is still marked locked",
  );
  entry._fire("click");
  await flush();
  assert(
    global.$("findtabs-panel").hidden === false,
    "Find across tabs did not open",
  );
  await closeEverything();
});

check(
  "with a licence, Image check opens its Tools tab and starts the picker",
  async () => {
    await closeEverything();
    await setPremium(LICENSED);
    global.rbResolve.file_pick_open = {};
    await openMenu();
    global.rbCalls.length = 0;
    global.$("menu-image-check")._fire("click");
    await flush();
    assert(
      global.$("btn-tab-imagecheck").getAttribute("aria-pressed") === "true",
      "the Image check tab was not selected",
    );
    assert(
      global.rbCalls.some((c) => c.cmd === "file_pick_open"),
      "the picker did not start",
    );
    await closeEverything();
  },
);

check("Image check is offered only while OCR is available", async () => {
  // Boot answered available.
  await openMenu();
  assert(
    global.$("menu-image-check").hidden === false,
    "Image check is hidden while OCR is available",
  );
  await closeEverything();
  // The answer is read once at boot, so a second harness boot answers no.
  const { execFileSync } = require("child_process");
  const os = require("os");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "menu-extras-"));
  const jsCopy = path.join(dir, "chrome.js");
  fs.writeFileSync(jsCopy, chromeJs);
  const probe = `
    const fs = require("fs");
    process.env.HTML_PATH = ${JSON.stringify(process.env.HTML_PATH)};
    require(${JSON.stringify(path.join(__dirname, "domstub.js"))});
    global.rbResolve.ocr_status = { available: false, file_choice: false };
    global.rbResolve.chrome_caps = { print: true, save_pdf: true };
    new Function(fs.readFileSync(${JSON.stringify(jsCopy)}, "utf8"))();
    setTimeout(async () => {
      for (let i = 0; i < 12; i += 1) await new Promise((r) => setImmediate(r));
      global.$("btn-main-menu")._fire("click");
      for (let i = 0; i < 12; i += 1) await new Promise((r) => setImmediate(r));
      process.stdout.write(String(global.$("menu-image-check").hidden));
    }, 0);
  `;
  const probeFile = path.join(dir, "probe.js");
  fs.writeFileSync(probeFile, probe);
  let out;
  try {
    out = execFileSync(process.execPath, [probeFile], { encoding: "utf8" });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert(
    out.trim().endsWith("true"),
    "Image check is offered while OCR is unavailable",
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
    console.error("\nMENU EXTRAS GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nMENU EXTRAS OK");
})();
