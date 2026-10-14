// Motion tokens and the Reduce motion switch, driven through the REAL
// chrome.js against the DOM stub and by reading chrome.css.
//
// What this gate is for. The motion pass (1.0.7) put every duration behind
// three tokens on `html`, so that one switch quiets the whole chrome. The
// things worth pinning are the ones that would quietly undo that:
//
//   - a duration written as a literal somewhere in chrome.css, which neither
//     the system's reduced-motion setting nor the switch could reach;
//   - the reduced-motion media query, or the switch's attribute, no longer
//     zeroing the tokens;
//   - the switch no longer worn as html[data-motion], which the stylesheet
//     keys on, or no longer following Rust's reply rather than the click.
//
// Planted defects (PATANYX_MOTION_PLANT): each must make this gate fail, which
// the wrapper in chrome-js-gate.sh checks. PATANYX_MOTION_LIST_PLANTS=1 lists
// them. A plant names the file it patches, because two of them are in CSS.
//
// It executes chrome.js in scripts/domstub.js and reads chrome.css as text.
// It does not execute Rust; the pref has its own tests in prefs.rs.
"use strict";
const fs = require("fs");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");

const PLANTS = {
  // A literal duration sneaks back into the stylesheet.
  "css-literal-duration": [
    "css",
    "transition: transform var(--motion-base) var(--motion-ease);",
    "transition: transform 150ms var(--motion-ease);",
  ],
  // The system's reduced-motion setting no longer zeroes the tokens.
  "css-media-ignored": [
    "css",
    "@media (prefers-reduced-motion: reduce) {\n  html {\n    --motion-fast: 0ms;\n    --motion-base: 0ms;\n  }\n}",
    "@media (prefers-reduced-motion: reduce) {\n  html {\n    --motion-fast: var(--motion-fast);\n  }\n}",
  ],
  // The switch's attribute no longer zeroes the tokens.
  "css-switch-ignored": [
    "css",
    'html[data-motion="reduce"] {\n  --motion-fast: 0ms;\n  --motion-base: 0ms;\n}',
    'html[data-motion="reduce"] {\n  --motion-fast: 120ms;\n  --motion-base: 150ms;\n}',
  ],
  // The switch is not worn where the stylesheet looks.
  "js-no-attribute": [
    "js",
    '      document.documentElement.dataset.motion = "reduce";\n',
    "\n",
  ],
  // The click asks Rust for nothing.
  "js-no-send": [
    "js",
    'rb("motion_set", { reduce: ev.target.checked })',
    "Promise.resolve({ reduce: ev.target.checked })",
  ],
  // The box keeps what was clicked instead of what Rust said.
  "js-follows-click": [
    "js",
    "      .then((r) => wearMotion(!!r.reduce))\n",
    "      .then(() => wearMotion(ev.target.checked))\n",
  ],
  // A closing card is hidden at once instead of fading.
  "js-close-hides-at-once": [
    "js",
    '    cur.el.classList.add("panel-closing");\n',
    '    cur.el.classList.add("panel-closing");\n    cur.el.hidden = true;\n',
  ],
  // The window is uncovered while the card is still fading.
  "js-uncover-mid-fade": [
    "js",
    "    const want = !!openPanelName || !!closingPanel || menuOpen || menuClosing;\n",
    "    const want = !!openPanelName || menuOpen || menuClosing;\n",
  ],
  // The strip height is sent while the card is still fading.
  "js-stale-height-mid-fade": [
    "js",
    "    const shown = openPanelName ? panels.get(openPanelName) : closingPanel;\n",
    "    const shown = openPanelName ? panels.get(openPanelName) : null;\n",
  ],
  // A command sent during the fade goes out before the uncover.
  "js-rb-no-flush": [
    "js",
    "      if (menuOpen || menuClosing) finishMenuClose();\n      finishPanelClose();\n      flushChromeSync();\n",
    "      if (menuOpen || menuClosing) finishMenuClose();\n",
  ],
  // A fading card's controls stay reachable from the keyboard.
  "js-fading-card-not-inert": ["js", "    cur.el.inert = true;\n", "\n"],
  // A second press on Close reopens the card it is closing.
  "js-close-reopens": [
    "js",
    "        if (closingPanel && closingPanel.el === spec.el) return;\n",
    "\n",
  ],
  // Reduce motion no longer skips the fade.
  "js-reduce-ignored": [
    "js",
    "    if (prefersReducedMotion() || document.body.classList.contains(\"solid-backdrop\")) {",
    "    if (document.body.classList.contains(\"solid-backdrop\")) {",
  ],
  // The JS deadline no longer matches the CSS fade.
  "js-close-timer-disagrees": ["js", "const PANEL_CLOSE_MS = 120;", "const PANEL_CLOSE_MS = 12;"],
  // Every caller sends its own frame.
  "js-no-coalesce": [
    "js",
    "    if (chromeSyncPending) return;\n",
    "\n",
  ],
  // A dismissed notice is removed at once instead of fading.
  "js-toast-removed-at-once": [
    "js",
    '      node.dataset.out = "1";\n',
    '      node.dataset.out = "1";\n      node.remove();\n',
  ],
  // An answered dialog is hidden at once instead of fading.
  "js-confirm-hides-at-once": [
    "js",
    '    overlay.classList.add("closing");\n',
    '    overlay.classList.add("closing");\n    overlay.hidden = true;\n',
  ],
  // Banners appear in one frame again.
  "css-banner-no-slide": [
    "css",
    "  animation: banner-in var(--motion-base) var(--motion-ease);\n",
    "\n",
  ],
  // Notices appear in one frame again.
  "css-toast-no-fade": [
    "css",
    "  animation: toast-in var(--motion-fast) ease-out;\n",
    "\n",
  ],
};
if (process.env.PATANYX_MOTION_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}
let chromeSrc = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
let cssSrc = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
const plant = process.env.PATANYX_MOTION_PLANT;
if (plant) {
  const p = PLANTS[plant];
  const target = p && (p[0] === "css" ? cssSrc : chromeSrc);
  if (!p || !target.includes(p[1])) {
    console.error(
      `plant ${plant}: anchor not found; the gate cannot prove anything`,
    );
    process.exit(2);
  }
  if (p[0] === "css") cssSrc = cssSrc.replace(p[1], p[2]);
  else chromeSrc = chromeSrc.replace(p[1], p[2]);
}

process.env.HTML_PATH = htmlPath;
require(path.join(root, "scripts/domstub.js"));

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
    await new Promise((r) => setImmediate(r));
  }
};

// ---- chrome.css, as text --------------------------------------------------

// The stylesheet without its comments, so a duration quoted in prose ("the
// same 150ms as TAB_SLIDE_MS") is not mistaken for a declaration.
const cssCode = cssSrc.replace(/\/\*[\s\S]*?\*\//g, "");

function block(selector) {
  const at = cssCode.indexOf(selector + " {");
  assert(at >= 0, "chrome.css has no `" + selector + " {` block");
  const end = cssCode.indexOf("}", at);
  return cssCode.slice(at, end);
}

check("the three motion tokens are declared on html", () => {
  const html = block("\nhtml");
  for (const token of ["--motion-fast", "--motion-base", "--motion-ease"]) {
    assert(html.includes(token + ":"), "html {} does not declare " + token);
  }
  assert(
    /--motion-fast:\s*\d+ms/.test(html),
    "--motion-fast is not a duration",
  );
  assert(
    /--motion-base:\s*\d+ms/.test(html),
    "--motion-base is not a duration",
  );
});

check("the JS timings agree with the CSS duration they wait for", () => {
  const fast = /--motion-fast:\s*(\d+)ms/.exec(block("\nhtml"));
  assert(fast, "no --motion-fast duration");
  for (const name of ["PANEL_CLOSE_MS", "TOAST_OUT_MS"]) {
    const m = new RegExp("const " + name + " = (\\d+);").exec(chromeSrc);
    assert(m, "chrome.js has no " + name);
    assert(
      m[1] === fast[1],
      name + " is " + m[1] + "ms but --motion-fast is " + fast[1] + "ms: the card or notice would be hidden before, or long after, its fade ends",
    );
  }
});

check("the system's reduced-motion setting zeroes both durations", () => {
  const at = cssCode.indexOf("@media (prefers-reduced-motion: reduce)");
  assert(at >= 0, "no prefers-reduced-motion: reduce block");
  const body = cssCode.slice(at, cssCode.indexOf("\n}\n", at));
  assert(
    /--motion-fast:\s*0m?s/.test(body),
    "the media query leaves --motion-fast on",
  );
  assert(
    /--motion-base:\s*0m?s/.test(body),
    "the media query leaves --motion-base on",
  );
});

check("the Reduce motion switch zeroes both durations", () => {
  const body = block('html[data-motion="reduce"]');
  assert(
    /--motion-fast:\s*0m?s/.test(body),
    "the switch leaves --motion-fast on",
  );
  assert(
    /--motion-base:\s*0m?s/.test(body),
    "the switch leaves --motion-base on",
  );
});

check("no duration is written as a literal outside the token blocks", () => {
  // Remove the three places a literal duration belongs, then there must be
  // none left: every transition and animation reads the tokens.
  let rest = cssCode
    .replace(/\nhtml \{[^}]*\}/, "")
    .replace(/@media \(prefers-reduced-motion: reduce\) \{[\s\S]*?\n\}\n/, "")
    .replace(/html\[data-motion="reduce"\] \{[^}]*\}/, "");
  const literal = rest.match(/[^-\w](\d+(?:\.\d+)?m?s)\b/);
  assert(
    !literal,
    "a literal duration (" +
      (literal && literal[1]) +
      ") is written in chrome.css outside the motion tokens; neither the " +
      "reduced-motion setting nor the Reduce motion switch can reach it",
  );
  assert(
    /transition:[\s\S]*?var\(--motion-/.test(rest),
    "no transition reads the motion tokens at all",
  );
});

// ---- chrome.js, executed ----------------------------------------------------

// Rust says the switch is ON at startup.
global.rbResolve.motion_get = { reduce: true };
new Function(chromeSrc)();

check("at startup the switch is worn where the stylesheet looks", async () => {
  await flush();
  assert(
    global.document.documentElement.dataset.motion === "reduce",
    "html[data-motion] is not set although Rust reported reduce: true",
  );
  assert(
    global.$("reduce-motion").checked === true,
    "the box does not show the stored ON",
  );
});

check("unticking asks Rust and follows the reply", async () => {
  global.rbCalls.length = 0;
  global.rbResolve.motion_set = { reduce: false };
  const box = global.$("reduce-motion");
  box.checked = false;
  box._fire("change");
  await flush();
  const sent = global.rbCalls.find((c) => c.cmd === "motion_set");
  assert(sent, "the click sent no motion_set");
  assert(
    sent.args && sent.args.reduce === false,
    "motion_set carried the wrong value",
  );
  assert(
    global.document.documentElement.dataset.motion === undefined,
    "html[data-motion] stayed set after Rust reported reduce: false",
  );
});

check("the box follows Rust's reply, not the click", async () => {
  // Rust answers ON whatever was clicked (a save that could not take).
  global.rbResolve.motion_set = { reduce: true };
  const box = global.$("reduce-motion");
  box.checked = false;
  box._fire("change");
  await flush();
  assert(
    box.checked === true,
    "the box kept the click instead of Rust's answer",
  );
  assert(
    global.document.documentElement.dataset.motion === "reduce",
    "the attribute does not match Rust's answer",
  );
});

// ---- the panel close fade, with timers and frames under the gate's control --
//
// The stub runs timers and frames at once, which is right for every other
// check here and wrong for these: the property is what Rust is told BETWEEN
// Escape and the end of the fade. So from here on the gate queues both and
// runs them by hand. chrome.js looks timers and frames up by name at call
// time, which is what makes the swap possible after boot.
const timers = [];
const frames = [];
let nextTimer = 1;
global.setTimeout = (fn, ms) => {
  timers.push({ id: nextTimer, fn, ms });
  return nextTimer++;
};
global.clearTimeout = (id) => {
  const at = timers.findIndex((t) => t.id === id);
  if (at >= 0) timers.splice(at, 1);
};
global.window.requestAnimationFrame = (fn) => {
  frames.push(fn);
  return frames.length;
};
const runFrames = () => {
  while (frames.length) frames.shift()();
};
const runTimers = () => {
  while (timers.length) timers.shift().fn();
};
const sentSince = (mark, cmd) =>
  global.rbCalls.slice(mark).filter((c) => c.cmd === cmd);

let openTop = null;
check("opening a panel covers the window and sends its height, in one frame", async () => {
  global.document.documentElement.dataset.motion = undefined;
  delete global.document.documentElement.dataset.motion;
  const mark = global.rbCalls.length;
  global.$("btn-vault")._fire("click");
  await flush();
  assert(global.$("vault-panel").hidden === false, "the vault did not open");
  assert(frames.length === 1, "a toggle queued " + frames.length + " frames, not one");
  runFrames();
  await flush();
  const covers = sentSince(mark, "chrome_overlay");
  const insets = sentSince(mark, "set_chrome_insets");
  assert(covers.length === 1 && covers[0].args.cover === true, "one cover was expected");
  assert(insets.length === 1, "one set_chrome_insets was expected, got " + insets.length);
  assert(
    global.rbCalls.indexOf(covers[0]) < global.rbCalls.indexOf(insets[0]),
    "the arrangement must be sent before the height",
  );
  openTop = insets[0].args.top;
  assert(openTop > insets[0].args.strip, "the open height is not above the strip");
});

check("a closing card fades, and the window stays covered at its height until the fade ends", async () => {
  const mark = global.rbCalls.length;
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  const panel = global.$("vault-panel");
  assert(panel.hidden === false, "the card was hidden at once instead of fading");
  assert(panel.classList.contains("panel-closing"), "the card is not marked as closing");
  assert(
    timers.some((t) => t.ms === 120),
    "no close timer is pending (queued: " + timers.map((t) => t.ms).join(",") + ")",
  );
  runFrames();
  await flush();
  assert(sentSince(mark, "chrome_overlay").length === 0, "the window was uncovered before the fade ended");
  const mid = sentSince(mark, "set_chrome_insets");
  assert(mid.every((c) => c.args.top === openTop), "the strip height was sent while the card was still fading");
  runTimers();
  await flush();
  assert(panel.hidden === true, "the card is still shown after the fade");
  assert(!panel.classList.contains("panel-closing"), "the closing mark was left on the hidden card");
  runFrames();
  await flush();
  const uncover = sentSince(mark, "chrome_overlay");
  assert(uncover.length === 1 && uncover[0].args.cover === false, "the fade ended without uncovering");
  const last = sentSince(mark, "set_chrome_insets").pop();
  assert(last && last.args.top === last.args.strip, "the strip height was not sent after the fade");
});

check("reopening during the fade never uncovers and re-covers", async () => {
  global.$("btn-vault")._fire("click");
  await flush();
  runFrames();
  runTimers();
  runFrames();
  await flush();
  const mark = global.rbCalls.length;
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  global.$("btn-vault")._fire("click");
  await flush();
  runFrames();
  runTimers();
  runFrames();
  await flush();
  assert(global.$("vault-panel").hidden === false, "the vault is not open");
  assert(!global.$("vault-panel").classList.contains("panel-closing"), "the reopened card is still marked closing");
  assert(
    sentSince(mark, "chrome_overlay").every((c) => c.args.cover !== false),
    "switching back to a panel uncovered the window in between",
  );
});

check("a command sent during the fade is preceded by the uncover", async () => {
  // Start from OPEN, whatever the check above left (a pill press toggles).
  if (global.$("btn-vault").getAttribute("aria-pressed") !== "true") {
    global.$("btn-vault")._fire("click");
    await flush();
  }
  runFrames();
  runTimers();
  runFrames();
  await flush();
  const mark = global.rbCalls.length;
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  assert(global.$("vault-panel").hidden === false, "the card did not fade");
  // Anything that hands the keyboard to the page: a tab switch here.
  global.window.__rb.request("tab_switch", { id: 1 }).catch(() => {});
  await flush();
  const cmds = global.rbCalls.slice(mark).map((c) => c.cmd);
  const uncover = global.rbCalls.slice(mark).findIndex((c) => c.cmd === "chrome_overlay" && c.args.cover === false);
  const insets = cmds.indexOf("set_chrome_insets");
  const sw = cmds.indexOf("tab_switch");
  assert(uncover >= 0 && insets >= 0 && sw >= 0, "expected uncover, insets and the switch, got " + cmds.join(","));
  assert(uncover < sw && insets < sw, "the switch was sent before the arrangement: " + cmds.join(","));
  assert(global.$("vault-panel").hidden === true, "the card is still shown after a command went out");
  runFrames();
  runTimers();
  runFrames();
  await flush();
});

check("a fading card is inert, and its Close pressed again does not reopen it", async () => {
  if (global.$("btn-vault").getAttribute("aria-pressed") !== "true") {
    global.$("btn-vault")._fire("click");
    await flush();
  }
  runFrames();
  runTimers();
  runFrames();
  await flush();
  const panel = global.$("vault-panel");
  const close = panel.querySelector(".panel-close");
  assert(close, "the vault has no injected Close");
  close._fire("click");
  await flush();
  assert(panel.hidden === false && panel.inert === true, "the fading card is not inert");
  close._fire("click");
  await flush();
  runFrames();
  runTimers();
  runFrames();
  await flush();
  assert(panel.hidden === true, "a second Close during the fade reopened the card");
  assert(panel.inert === false, "the hidden card was left inert");
  assert(global.$("btn-vault").getAttribute("aria-pressed") === "false", "the opener still reads pressed");
});

check("under Reduce motion a closing card is hidden in the same call", async () => {
  // Start from OPEN, and prove it: a check above leaves the vault closed,
  // and Escape over nothing would pass this for free (review round 3).
  if (global.$("btn-vault").getAttribute("aria-pressed") !== "true") {
    global.$("btn-vault")._fire("click");
    await flush();
  }
  runFrames();
  runTimers();
  runFrames();
  await flush();
  assert(global.$("vault-panel").hidden === false, "the vault is not open to begin with");
  global.document.documentElement.dataset.motion = "reduce";
  global.fireDocument("keydown", { key: "Escape" });
  assert(global.$("vault-panel").hidden === true, "the card waited for a fade under Reduce motion");
  delete global.document.documentElement.dataset.motion;
  runFrames();
  runTimers();
  runFrames();
  await flush();
});

// ---- banners, notices, the confirm dialog, tab chips -------------------------

check("banners slide open, through the tokens, by role", () => {
  const rule = block('body > [role="search"]:not([hidden])');
  assert(rule.includes("animation: banner-in var(--motion-base)"), "banners have no slide, or it ignores the tokens");
  assert(cssCode.includes('body > [role="alert"]:not([hidden])'), "alert banners are not covered");
  assert(cssCode.includes('body > [role="status"]:not([hidden])'), "status banners are not covered");
  assert(/@keyframes banner-in \{[\s\S]*?max-height: 0;/.test(cssCode), "the slide does not start from no height");
});

check("notices and the confirm dialog fade in and out; chips ease in", () => {
  assert(block(".toast").includes("animation: toast-in var(--motion-fast)"), "a notice does not fade in");
  assert(block(".toast[data-out]").includes("transition:"), "a dismissed notice does not fade out");
  assert(block("#confirm-overlay:not([hidden])").includes("animation: fade-in var(--motion-fast)"), "the dialog does not fade in");
  assert(block("#confirm-overlay.closing").includes("transition: opacity var(--motion-fast)"), "the dialog does not fade out");
  assert(cssCode.includes("animation: chip-in var(--motion-fast)"), "a new tab chip does not ease in");
});

check("a dismissed notice fades before it is removed", async () => {
  const host = global.$("toasts");
  global.rbReject = "boom";
  global.$("labels-show")._fire("click");
  await flush();
  global.rbReject = null;
  // The stub keeps className and classList apart (a real DOM does not), and
  // toast() writes the former: look at both.
  const hasClass = (c, name) =>
    c.classList.contains(name) || (c.className || "").split(" ").includes(name);
  const note = Array.prototype.find.call(host.children, (c) => hasClass(c, "toast"));
  assert(note, "no notice appeared for a refused IPC");
  const close = Array.prototype.find.call(note.children, (c) => hasClass(c, "toast-close"));
  assert(close, "the notice has no dismiss button");
  // The stub no-ops a node's own remove(); this notice gets a real one, so
  // the gate can see when the fade ends.
  note.remove = () => host.removeChild(note);
  close._fire("click");
  await flush();
  assert(note.dataset.out === "1", "the dismissed notice is not marked for the fade");
  assert(Array.prototype.includes.call(host.children, note), "the notice was removed before the fade");
  runTimers();
  await flush();
  assert(!Array.prototype.includes.call(host.children, note), "the notice is still there after the fade");
});

check("an answered confirm dialog fades before it is hidden", async () => {
  const overlay = global.$("confirm-overlay");
  const answer = global.window.__rb.askConfirm("Sure?");
  await flush();
  assert(overlay.hidden === false, "the dialog did not open");
  global.$("confirm-cancel")._fire("click");
  await flush();
  assert(overlay.classList.contains("closing"), "the answered dialog is not marked for the fade");
  assert(overlay.hidden === false, "the dialog was hidden before the fade");
  runTimers();
  await flush();
  assert(overlay.hidden === true, "the dialog is still shown after the fade");
  assert(!overlay.classList.contains("closing"), "the closing mark was left on the hidden dialog");
  assert((await answer) === false, "Cancel did not answer false");
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL  " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error("MOTION GATE FAIL:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nMOTION GATE OK");
})();
