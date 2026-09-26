// The two things that must stay ABSENT for tab dragging to work on Windows.
//
// WHY THIS FILE EXISTS. Tab reordering was broken by two independent causes,
// both fixed, and the Windows one then came BACK through a merge and shipped
// twice more before it was caught on hardware again. Nothing failed:
// the whole suite passed, because no gate asserted the absence of an API call.
// A fix that only lives in a diff is a fix that can be silently reverted.
//
// 1. `SetAllowExternalDrop` on the chrome controller. Microsoft documents it
//    as governing objects dragged in from OUTSIDE the WebView2 bounds, so it
//    reads as harmless for an in-page drag. MEASURED on Windows 11 2026-08-26:
//    with the setter a tab will not drag; with the engine default it drags.
//    Two independent source-only readings of that documentation concluded it
//    was safe and both were wrong. The measurement outranks the documentation.
//
// 2. wry's `with_drag_drop_handler` on the chrome builder. Setting one makes
//    wry call RevokeDragDrop on the WebView2 child HWNDs -- removing the
//    ENGINE'S own drop target -- and register a CF_HDROP-only replacement,
//    which cannot carry an in-page text/plain drag at all.
//
// What still refuses a dropped file is the chrome navigation handler, which
// permits only CHROME_ORIGIN_PREFIX. That is asserted here too, so this gate
// cannot be satisfied by removing the protection instead of the blocker.
//
// Run: node scripts/drag-regression-gate.js  (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.resolve(
  process.env.PATANYX_DRAG_GATE_ROOT || path.join(__dirname, ".."),
);
const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");

// Comments explain the absence; only real code may fail this gate.
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");

const failures = [];
const check = (name, condition, detail) => {
  if (condition) return;
  failures.push(`${name}: ${detail}`);
};

const windowsRs = stripComments(read("crates/app/src/platform/windows.rs"));
const mainRs = stripComments(read("crates/app/src/main.rs"));
const chromeJs = read("crates/app/src/chrome/chrome.js");

check(
  "no SetAllowExternalDrop call",
  !/SetAllowExternalDrop\s*\(/.test(windowsRs),
  "windows.rs calls SetAllowExternalDrop. Measured on hardware to stop tab " +
    "dragging, whatever Microsoft's documentation implies. Remove it.",
);

check(
  "no wry drag-drop handler",
  !/with_drag_drop_handler\s*\(/.test(mainRs),
  "main.rs sets a wry drag-drop handler, which revokes the engine's own drop " +
    "target and kills in-page dragging.",
);

// The chrome's remaining HTML5 drags (bookmarks, Quick Access tiles, bookmark
// rows) must still write SOMETHING into dataTransfer: both engines abandon a
// drag with nothing in it and select the text under the cursor instead. The
// tab drag used to be one of them and is not any more -- see the next check.
check(
  "the HTML5 drags still carry a payload",
  /setData\(\s*"text\/plain"/.test(chromeJs),
  "no dragstart in chrome.js writes into dataTransfer, so both engines " +
    "abandon the bookmark drags and select text instead.",
);

// The TAB drag is pointer events on the chip, so it depends on none of the
// engine drop-target plumbing checks 1 and 2 protect -- the plumbing that
// broke tab dragging on Windows three times. Turning it back into an HTML5
// drag would put tab reordering back at the mercy of both.
const chipBuilderAt = chromeJs.indexOf("function buildTabChip");
const chipBuilder =
  chipBuilderAt < 0
    ? ""
    : chromeJs.slice(
        chipBuilderAt,
        chromeJs.indexOf("\n  function ", chipBuilderAt + 1),
      );
check(
  "the tab drag is a pointer drag, not an HTML5 one",
  chipBuilder.length > 200 &&
    /"pointerdown"/.test(chipBuilder) &&
    !/draggable|"dragstart"|dataTransfer/.test(chipBuilder),
  "buildTabChip is missing, has no pointerdown, or makes the chip an HTML5 " +
    "drag source again (draggable / dragstart / dataTransfer).",
);

check(
  "the navigation guard that replaces the drop refusal is intact",
  /url\.starts_with\(platform::CHROME_ORIGIN_PREFIX\)/.test(mainRs),
  "the chrome navigation handler no longer pins CHROME_ORIGIN_PREFIX. That " +
    "guard is what refuses a dropped file now, so it may not be removed too.",
);

if (failures.length) {
  console.error("DRAG REGRESSION GATE FAILED:\n");
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`drag-regression-gate OK (5 checks)`);
