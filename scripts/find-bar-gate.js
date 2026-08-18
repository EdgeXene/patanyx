// Find-bar gate: the single-tab bar shipped without one while every other
// chrome surface had its own -- and the cross-tab panel's adopt handoff
// leans on exactly the honesty rules this file pins. Three rules, one
// check each: the count blanks the moment the query changes (never a stale
// number beside new text), a find_state for a closed bar is dropped, and
// an engine that cannot find at all swaps the input for the honest
// unsupported line.
//
// Guard shape: chrome-js-gate.sh refuses to run this file when
// #find-input is gone from index.html.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

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

const fire = (event, data) => global.window.__rb_event({ event, data });

check("a find_state for a closed bar is dropped", async () => {
  // The bar was never opened: an engine callback landing now must paint
  // nothing, or a late count from a closed session haunts the next open.
  fire("find_state", { text: "3 of 17" });
  await flush();
  const count = global.$("find-count");
  assert(
    (count._text[count._text.length - 1] || "") === "",
    "no count painted while the bar is closed",
  );
});

check("the count blanks the moment the query changes", async () => {
  fire("find_open", {});
  await flush();
  fire("find_state", { text: "3 of 17" });
  await flush();
  const count = global.$("find-count");
  assert(
    count._text[count._text.length - 1] === "3 of 17",
    "an open bar paints the engine's count",
  );
  global.$("find-input").value = "changed";
  global.$("find-input")._fire("input");
  assert(
    count._text[count._text.length - 1] === "",
    "typing blanks the count immediately, never a stale number beside new text",
  );
});

check(
  "an engine without find swaps the input for the unsupported line",
  async () => {
    global.rbResolve.find_start = { available: false };
    global.$("find-input").value = "needle";
    fire("find_open", {});
    await flush();
    delete global.rbResolve.find_start;
    assert(
      global.$("find-unsupported").hidden === false,
      "the honest line shows",
    );
    assert(global.$("find-input").hidden === true, "the dead input hides");
    assert(global.$("find-next").disabled === true, "stepping disables");
  },
);

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (err) {
      failures.push(name + ": " + err.message);
      console.log("  FAIL " + name + ": " + err.message);
    }
  }
  if (failures.length) {
    console.error("\nFIND BAR GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log("\nFIND BAR UI OK");
})();
