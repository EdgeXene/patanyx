// The Guide and Premium guide buttons in About (1.0.7).
//
// WHAT THIS PINS. The two buttons beside "Watch the feature videos" are the
// only About controls that leave the chrome: each opens one fixed page on
// patanyx.net in a new tab. Each property below is proven against a planted
// defect on every run:
//
// 1. Both buttons sit inside About's own button row.
// 2. The chrome sends a NAME (site_page_open {page}), never an address: Rust
//    holds both addresses (site_pages.rs), because no Premium address may sit
//    in a chrome asset. That rule (premium-toolbar-gate.js) reads only the
//    top-level chrome files, so this gate also reads the English catalog,
//    whose strings are written into the chrome at runtime (compliance audit
//    2026-10-13).
// 3. A click closes About FIRST and tells Rust the window is uncovered
//    before the page is asked for; site_page_open is a page-handoff command,
//    so a close still fading is finished before it is sent (plan review
//    2026-10-13, R-001).
// 4. A refused request is reported, never swallowed.
// 5. The Premium guide shows only while Premium is on sale (its pages link
//    the purchase page); Rust refuses it otherwise too.
//
// Run: node scripts/about-links-gate.js   (or via scripts/chrome-js-gate.sh)
// PATANYX_ABOUT_LINKS_PLANT=<name> plants one defect; the gate must then print
// ABOUT LINKS GATE FAILED. PATANYX_ABOUT_LINKS_LIST_PLANTS=1 lists the names.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const ftlPath = path.join(chromeDir, "i18n/locales/en.ftl");
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

// [file, from, to]. `html` and `ftl` plants change only the text the static
// checks read; `js` plants change the chrome.js that runs.
const PLANTS = {
  "wrong-page": ["js", 'openSitePage("guide"));', 'openSitePage("guides"));'],
  "no-close": [
    "js",
    "  function openSitePage(page) {\n    closeOpenPanel();\n",
    "  function openSitePage(page) {\n",
  ],
  "no-handler": [
    "js",
    '  $("about-premium-guide").addEventListener("click", () => openSitePage("premium_guide"));\n',
    "",
  ],
  "address-in-chrome": [
    "js",
    'openSitePage("premium_guide"));',
    'rb("tab_new", { url: "https://patanyx.net/premium-guide/" }));',
  ],
  "silent-failure": [
    "js",
    'rb("site_page_open", { page }).catch((e) => toast(friendly(e), true));',
    'rb("site_page_open", { page }).catch(() => {});',
  ],
  "not-handoff": [
    "js",
    '    "premium_purchase_open",\n    "site_page_open",\n',
    '    "premium_purchase_open",\n',
  ],
  "on-sale-ignored": [
    "js",
    '$("about-premium-guide").hidden = !(st && st.on_sale);',
    '$("about-premium-guide").hidden = false;',
  ],
  "outside-about": [
    "html",
    '<button id="about-guide"',
    '<button id="about-guide-moved"',
  ],
  "address-in-catalog": [
    "ftl",
    "chrome-about-premium-guide-title = Opens the Premium guide on patanyx.net in a new tab",
    "chrome-about-premium-guide-title = Opens patanyx.net/premium-guide in a new tab",
  ],
};

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
let html = fs.readFileSync(process.env.HTML_PATH, "utf8");
let ftl = fs.readFileSync(ftlPath, "utf8");
const plant = process.env.PATANYX_ABOUT_LINKS_PLANT;
if (plant) {
  const spec = PLANTS[plant];
  assert(spec, "unknown plant " + plant + "; known: " + Object.keys(PLANTS));
  const [file, from, to] = spec;
  const src = { js: chromeJs, html, ftl }[file];
  assert(
    src.split(from).length === 2,
    "cannot plant " + plant + ": its anchor changed spelling",
  );
  if (file === "js") chromeJs = chromeJs.replace(from, to);
  else if (file === "html") html = html.replace(from, to);
  else ftl = ftl.replace(from, to);
}
if (process.env.PATANYX_ABOUT_LINKS_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}

require("./domstub.js");
new Function(chromeJs)();

const setPremium = async (status) => {
  global.rbResolve.premium_status = status;
  global.window.__rb_event({ event: "vault_locked", data: {} });
  await flush();
};

function aboutButtonRow() {
  const start = html.indexOf('<section id="about-panel"');
  assert(start >= 0, "index.html has no #about-panel");
  const rowStart = html.indexOf('<div class="form-buttons">', start);
  const rowEnd = html.indexOf("</div>", rowStart);
  assert(rowStart > start && rowEnd > rowStart, "About has no button row");
  return html.slice(rowStart, rowEnd);
}

check(
  "both guide buttons sit in About's own button row, after the videos button",
  () => {
    const row = aboutButtonRow();
    const videos = row.indexOf('id="about-videos"');
    const guide = row.indexOf('id="about-guide"');
    const premium = row.indexOf('id="about-premium-guide"');
    assert(videos >= 0, "#about-videos is not in About's button row");
    assert(
      guide > videos,
      "#about-guide is missing from About's button row or sits before the videos button",
    );
    assert(
      premium > guide,
      "#about-premium-guide is missing from About's button row or sits before #about-guide",
    );
  },
);

check(
  "no Premium address sits in a chrome script, the markup or the English catalog",
  () => {
    // The same pattern premium-toolbar-gate.js uses, and the same single
    // exemption: the offline-activation instruction, on its one catalog line
    // and as inert text in the markup.
    const offline = "patanyx.net/premium/offline";
    const sources = {
      "chrome.js": chromeJs,
      "index.html": html,
      "en.ftl": ftl,
    };
    for (const [name, src] of Object.entries(sources)) {
      const lines = src.split("\n");
      lines.forEach((line, i) => {
        for (const hit of line.match(/patanyx\.net\/premium[^\s"'<)]*/g) ||
          []) {
          assert(
            hit === offline,
            `${name}:${i + 1} holds the Premium address ${hit}`,
          );
          if (name === "en.ftl") {
            assert(
              line.startsWith("chrome-premium-activation-strong ="),
              `en.ftl:${i + 1} holds the offline-activation address outside its own message`,
            );
          }
        }
      });
    }
  },
);

check(
  "site_page_open is a page-handoff command, so a fading About is finished first",
  () => {
    const m = chromeJs.match(
      /const PAGE_HANDOFF_COMMANDS = new Set\(\[([\s\S]*?)\]\);/,
    );
    assert(m, "PAGE_HANDOFF_COMMANDS is missing from chrome.js");
    assert(
      /"site_page_open"/.test(m[1]),
      "site_page_open is not in PAGE_HANDOFF_COMMANDS",
    );
  },
);

async function openAbout() {
  const panel = global.$("about-panel");
  if (panel.hidden) global.$("btn-about")._fire("click");
  await flush();
  assert(
    global.$("about-panel").hidden === false,
    "setup: About did not open from #btn-about",
  );
}

for (const [id, page] of [
  ["about-guide", "guide"],
  ["about-premium-guide", "premium_guide"],
]) {
  check(
    `#${id} closes About, uncovers the window, then asks Rust for "${page}" by name`,
    async () => {
      await setPremium({ state: "free", premium: false, on_sale: true });
      global.rbResolve.site_page_open = { id: 2 };
      await openAbout();
      global.rbCalls.length = 0;
      global.$(id)._fire("click");
      await flush();
      const calls = global.rbCalls.slice();
      const opens = calls.filter((c) => c.cmd === "site_page_open");
      assert(
        opens.length === 1,
        `expected exactly one site_page_open, got ${opens.length}`,
      );
      const args = opens[0].args || {};
      assert(
        Object.keys(args).length === 1 && args.page === page,
        `site_page_open carried ${JSON.stringify(args)}, expected exactly {"page":"${page}"}`,
      );
      assert(
        !calls.some((c) => c.cmd === "tab_new"),
        "the click opened a tab by address instead of by name",
      );
      assert(
        global.$("about-panel").hidden === true,
        "About is still open after the click: the page opened behind it",
      );
      const uncover = calls.findIndex(
        (c) => c.cmd === "chrome_overlay" && c.args && c.args.cover === false,
      );
      const open = calls.findIndex((c) => c.cmd === "site_page_open");
      assert(
        uncover >= 0,
        "the click never told Rust the window is uncovered (chrome_overlay cover:false)",
      );
      assert(
        uncover < open,
        "site_page_open went out before chrome_overlay cover:false, so Rust still saw a card over the page",
      );
    },
  );
}

check(
  "a refused request is reported as an error notice, not swallowed",
  async () => {
    await openAbout();
    global.rbResolve.site_page_open = new Error("bad_args");
    const before = global.$("toasts").children.length;
    global.$("about-guide")._fire("click");
    await flush();
    delete global.rbResolve.site_page_open;
    const added = global.$("toasts").children.slice(before);
    assert(
      added.some((n) => String(n.className).split(/\s+/).includes("error")),
      "no error notice appeared when site_page_open was refused",
    );
  },
);

check("the Premium guide shows only while Premium is on sale", async () => {
  await setPremium({ state: "free", premium: false, on_sale: false });
  assert(
    global.$("about-premium-guide").hidden === true,
    "the Premium guide shows while Premium is not on sale",
  );
  await setPremium({ state: "free", premium: false, on_sale: true });
  assert(
    global.$("about-premium-guide").hidden === false,
    "the Premium guide stays hidden while Premium is on sale",
  );
  await setPremium({ state: "locked", premium: false, on_sale: false });
  assert(
    global.$("about-premium-guide").hidden === true,
    "the Premium guide did not hide again when the sale ended",
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
    console.error("\nABOUT LINKS GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nABOUT LINKS OK");
})();
