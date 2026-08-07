// Behavioural checks on the site-permission panel, run against the DOM harness
// so chrome.js is EXECUTED rather than parsed.
//
// WHY THIS EXISTS. The panel is the ONLY way a user can allow a permission,
// and every failure mode here is one where the UI would lie:
//   - controls that look operable on a tab where nothing enforces them
//   - a frame's request labelled as though the page itself asked
//   - the panel keeping the previous site's rows after a tab switch, so a
//     click allows something on a site the user is no longer looking at
//   - a failed grant leaving the switch on, claiming a permission the table
//     never recorded
// Each of those renders correctly in isolation and is wrong in context, which
// is exactly what a parse-only check cannot see.
//
// Run: node scripts/permission-ui-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
const checks = [];
const check = (name, fn) => checks.push([name, fn]);
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

const $ = (id) => global.document.getElementById(id);
const rows = () => Array.from($("permission-list").children);

// WALK THE TREE, do not read a container. Two documented traps in this
// harness: `textContent` does not aggregate descendant text, so asserting on a
// parent compares "" to "", and createElement'd nodes carry no tagName. Both
// make a careless gate pass vacuously, which this project has paid for before.
function descendants(el, out = []) {
  for (const c of el.children || []) {
    out.push(c);
    descendants(c, out);
  }
  return out;
}
const inputsOf = (row) => descendants(row).filter((c) => c.type === "checkbox");
const textOf = (row) =>
  descendants(row)
    .map((c) => c.textContent || "")
    .join(" ");

// Drives the panel the way a USER does: click the toolbar button. Calling the
// renderer directly would test a function nobody can reach. The button is a
// toggle, so an already-open panel is closed first.
async function seed(status) {
  global.rbReject = null;
  global.rbResolve = {
    privacy_get: {},
    dns_get: { mode: "system", supported: false },
    permission_status: status,
    permission_grant: status,
    permission_revoke: status,
  };
  if (global.$("privacy-panel").hidden === false) {
    global.$("btn-privacy")._fire("click");
    await flush();
  }
  global.$("btn-privacy")._fire("click");
  await flush();
}

check("an unsupported tab renders NO operable controls", async () => {
  await seed({ supported: false, site: "https://example.com", entries: [] });
  const note = $("permission-note").textContent;
  assert(
    /not enforcing/i.test(note),
    `unsupported tab must say so, got: ${note}`,
  );
  assert(
    rows().length === 0,
    "an unsupported tab must not render permission switches at all",
  );
});

check("a denied request renders a switch that is OFF", async () => {
  await seed({
    supported: true,
    site: "https://example.com",
    entries: [
      {
        origin: "https://example.com",
        kind: "camera",
        granted: false,
        deniedCount: 1,
      },
    ],
  });
  const r = rows();
  assert(r.length === 1, `expected one row, got ${r.length}`);
  const input = inputsOf(r[0])[0];
  assert(input, "the row must carry a checkbox");
  assert(!input.checked, "a denied permission must render unchecked");
  assert(!input.disabled, "a supported tab's control must be operable");
});

check("an embedded frame is named, never called 'this site'", async () => {
  await seed({
    supported: true,
    site: "https://example.com",
    entries: [
      {
        origin: "https://ads.other.example",
        kind: "microphone",
        granted: false,
        deniedCount: 3,
      },
    ],
  });
  const text = textOf(rows()[0]);
  assert(
    text.includes("ads.other.example"),
    `the frame's own origin must be named, got: ${text}`,
  );
  assert(
    !/this site/i.test(text),
    `a frame must not be described as "this site", got: ${text}`,
  );
});

check("an allowed row says the grant dies on close", async () => {
  // The failure this pins is a user staring at a camera that never turns on.
  // Flipping the switch records the grant, but the request it was refused for
  // is already closed, so the page gets nothing until it asks again. A row
  // that says only "Allowed" would read as "this is working now".
  await seed({
    supported: true,
    site: "https://example.com",
    entries: [
      {
        origin: "https://example.com",
        kind: "camera",
        granted: true,
        deniedCount: 0,
      },
    ],
  });
  const text = textOf(rows()[0]);
  assert(
    /closes/i.test(text),
    `an allowed permission must say it dies when PATANYX closes, got: ${text}`,
  );
});

check("the panel warns about losing work BEFORE the switches", async () => {
  // Changing a permission reloads the page, which discards anything typed
  // into it. The warning has to be readable before the click, so this asserts
  // it exists and is not empty -- a silent reload eating a half-written post
  // is the failure being prevented.
  // Read from the MARKUP, not the DOM stub: this text is static in
  // index.html, and the harness only records textContent that JS assigned.
  // Whitespace is collapsed first so reformatting cannot fail the gate.
  const html = fs
    .readFileSync(path.join(chromeDir, "index.html"), "utf8")
    .replace(/\s+/g, " ");
  const start = html.indexOf('id="permission-warn"');
  assert(start > 0, "the #permission-warn element is gone");
  const warn = html.slice(start, html.indexOf("</p>", start));
  assert(
    /reload/i.test(warn) && /save/i.test(warn),
    `the panel must warn that changing a switch reloads the page and to save first, got: ${warn}`,
  );
  // It has to be readable BEFORE the switches, or it is an epitaph.
  assert(
    start < html.indexOf('id="permission-list"'),
    "the warning must come before the controls it warns about",
  );
});

// An empty list no longer means "nothing has asked yet": since 2026-08-06
// the Rust side seeds all four kinds for whatever site the tab is on, so a
// real site ALWAYS has four rows. Empty means there is no site to attach a
// permission to -- a blank tab or an internal page -- and the copy has to
// say that instead, while still stating the deny-by-default rule.
check(
  "the empty state explains there is no site, and that refusal is the default",
  async () => {
    await seed({ supported: true, site: null, entries: [] });
    const note = $("permission-note").textContent;
    assert(
      /open a site/i.test(note),
      `empty state must explain that no site is loaded, got: ${note}`,
    );
    assert(
      /stay off|until you allow|refused/i.test(note),
      `empty state must still state deny-by-default, got: ${note}`,
    );
  },
);

// THE DEFECT THIS EXISTS FOR, reported on hardware 2026-08-06: "No option to
// allow or deny cameras, mics, etc." The panel listed only what a site had
// already requested, and because a refusal raises no prompt, a user who had
// not yet triggered one found four kinds described in prose with no control
// anywhere. Every kind must be operable BEFORE anything asks.
check(
  "a site that has asked for nothing still offers all four controls",
  async () => {
    await seed({
      supported: true,
      site: "https://example.com",
      entries: ["camera", "microphone", "geolocation", "notifications"].map(
        (kind) => ({
          origin: "https://example.com",
          kind,
          granted: false,
          deniedCount: 0,
        }),
      ),
    });
    const shown = rows();
    assert(
      shown.length === 4,
      `expected four permission rows, got ${shown.length}`,
    );
    for (const row of shown) {
      const input = inputsOf(row)[0];
      assert(input, "every permission row must carry a switch");
      assert(
        !input.disabled,
        "a supported tab's permission control must be operable",
      );
      assert(
        !input.checked,
        "a permission nothing has granted must not read as allowed",
      );
    }
  },
);

check("a failed grant puts the switch back", async () => {
  await seed({
    supported: true,
    site: "https://example.com",
    entries: [
      {
        origin: "https://example.com",
        kind: "camera",
        granted: false,
        deniedCount: 1,
      },
    ],
  });
  const input = inputsOf(rows()[0])[0];
  global.rbReject = "bad_origin";
  input.checked = true;
  // `_fire` is the harness's event trigger, the same one the other UI gates
  // use; there is no dispatchEvent on these nodes.
  input._fire("change");
  await flush();
  assert(
    input.checked === false,
    "a refused grant must not leave the switch on, or the UI claims a permission the browser did not give",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log(`  ok  ${name}`);
    } catch (err) {
      failures.push(`${name}: ${err.message}`);
      console.log(`  FAIL  ${name}`);
    }
  }
  if (failures.length) {
    console.error("\nPERMISSION UI GATE FAILED:");
    for (const f of failures) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log("PERMISSION UI OK");
})();
