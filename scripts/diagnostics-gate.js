// Diagnostics export (About panel). Behavioural checks run against the DOM
// harness so chrome.js is EXECUTED rather than parsed.
//
// WHY THIS EXISTS. `AppState::diagnostics_snapshot` (state.rs) is where the
// "no history, no credentials, no vault content" constraint actually lives,
// and it has its own Rust-side test (`diagnostics_snapshot_never_names_a_
// forbidden_field`) because this harness has no way to construct a real
// `AppState` to call it on. What IS testable here is the half that lives in
// chrome.js: that Copy and Save actually strip the two UI-plumbing fields
// (`export_suggestion`, `file_choice`) before the report leaves the machine,
// that Save refuses to act with no destination, and that the destination
// picker's visibility follows what Rust reports the platform can do.
//
// Run: node scripts/diagnostics-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
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

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// The section between the two headings this control lives between, so a
// check here cannot accidentally match markup belonging to a different
// section of the (large) About panel.
const sectionStart = html.indexOf('<h2 class="about-head">Diagnostics</h2>');
const sectionEnd = html.indexOf("</section>", sectionStart);
const SECTION = html.slice(sectionStart, sectionEnd);

check("the Diagnostics section exists and states what it excludes", () => {
  assert(
    sectionStart !== -1,
    "the Diagnostics heading is missing from the About panel",
  );
  assert(
    /history/i.test(SECTION) && /vault/i.test(SECTION),
    "the section no longer states that history and vault content are excluded",
  );
});

function openAbout() {
  global.$("btn-about")._fire("click");
}

check(
  "opening About prefills the destination and reveals the picker when supported",
  async () => {
    global.rbResolve.diagnostics_get = {
      export_suggestion: "/home/user/patanyx-diagnostics.json",
      file_choice: true,
      build: { version: "0.9.53" },
    };
    openAbout();
    await flush();
    assert(
      global.$("diag-dest").value === "/home/user/patanyx-diagnostics.json",
      "the destination field was not prefilled from export_suggestion",
    );
    assert(
      global.$("diag-pick").hidden === false,
      "the picker button must show when file_choice is true",
    );
  },
);

check(
  "Copy to clipboard strips export_suggestion and file_choice",
  async () => {
    global.rbResolve.diagnostics_get = {
      export_suggestion: "/tmp/x.json",
      file_choice: false,
      build: { version: "0.9.53" },
      dns_mode: "mullvad",
      recent_log: ["a", "b"],
    };
    global.clipboardText = null;
    global.$("diag-copy")._fire("click");
    await flush();
    assert(global.clipboardText, "nothing was written to the clipboard");
    const written = JSON.parse(global.clipboardText);
    assert(
      !("export_suggestion" in written) && !("file_choice" in written),
      "the copied report still carries export_suggestion/file_choice -- those " +
        "are about HOW to save the report, not part of what is being reported",
    );
    assert(
      written.dns_mode === "mullvad" && Array.isArray(written.recent_log),
      "the copied report is missing real diagnostic fields -- stripping the " +
        "two UI fields must not have dropped anything else",
    );
  },
);

check("Save refuses to act with an empty destination", async () => {
  global.$("diag-dest").value = "";
  global.rbCalls.length = 0;
  global.$("diag-save")._fire("click");
  await flush();
  assert(
    !global.rbCalls.some((c) => c.cmd === "diagnostics_export"),
    "diagnostics_export was called with no destination chosen",
  );
});

check("Save calls diagnostics_export with the chosen destination", async () => {
  global.$("diag-dest").value = "/tmp/patanyx-diagnostics.json";
  global.rbCalls.length = 0;
  global.$("diag-save")._fire("click");
  await flush();
  const call = global.rbCalls.find((c) => c.cmd === "diagnostics_export");
  assert(call, "diagnostics_export was not called");
  assert(
    call.args && call.args.dest === "/tmp/patanyx-diagnostics.json",
    "diagnostics_export was called with the wrong destination",
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
    console.error("\nDIAGNOSTICS GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nDIAGNOSTICS UI OK");
})();
