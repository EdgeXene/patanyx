// Cross-tab find panel gate: executes the REAL chrome.js against the DOM
// stub and drives the findtabs panel through the same window.__rb_event
// and window.ipc wire the browser uses. Each check pins one honesty rule
// the panel makes; the gate was proven against planted defects for the
// three rules most likely to rot silently (goto uses the clicked row's id,
// snippets never parse as markup, the locked notice survives a re-render).
//
// Guard shape: chrome-js-gate.sh refuses to run this file when
// #findtabs-list is gone from index.html, so removing the surface cannot
// silently retire its gate.
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
const gotoCalls = () =>
  global.rbCalls.filter((c) => c.cmd === "find_tabs_goto");

// A two-row snapshot: one done row with two snippets (the second row, id 9,
// is the one every click assertion targets so "always row 0" cannot pass),
// one unsearchable row. The second snippet's text carries markup and a
// two-byte character BEFORE the match, so one fixture pins both the
// inertness rule and the UTF-8/UTF-16 offset conversion.
const MARKUP = "<img src=x onerror=alert(1)> hé needle tail";
// bytes: markup 28 + " h" 2 + "é" 2 + " " 1 = 33 -> needle at 33..39
const SNAPSHOT = {
  scanning: false,
  locked: false,
  query: "needle",
  skipped_quarantine: 2,
  rows: [
    {
      id: 4,
      title: "",
      url: "https://a.example/x",
      state: "unsearchable",
      reason: "Still loading; search again in a moment.",
    },
    {
      id: 9,
      title: "Target",
      url: "https://b.example/y",
      state: "done",
      count: 2,
      capped: false,
      text: "2 matches",
      snippets: [
        {
          text: "one needle here",
          start: 4,
          end: 10,
          cut_start: false,
          cut_end: true,
        },
        { text: MARKUP, start: 33, end: 39, cut_start: true, cut_end: false },
      ],
    },
  ],
};

check("a seeded snapshot renders one group per row (non-vacuity)", async () => {
  fire("find_tabs_state", SNAPSHOT);
  await flush();
  const list = global.$("findtabs-list");
  assert(list.children.length === 2, "two rows in, two groups out");
});

check(
  "a snippet click sends find_tabs_goto with THAT row's id and the snapshot query",
  async () => {
    fire("find_tabs_state", SNAPSHOT);
    await flush();
    const before = gotoCalls().length;
    const group = global.$("findtabs-list").children[1];
    const snippet = group.children.find(
      (c) => c.className === "findtabs-snippet",
    );
    assert(snippet, "the done row renders its snippet line");
    snippet._fire("click");
    await flush();
    const calls = gotoCalls();
    assert(calls.length === before + 1, "the click reached Rust");
    const call = calls[calls.length - 1];
    assert(call.args.id === 9, "the CLICKED row's id, never the first row's");
    assert(
      call.args.query === "needle",
      "the SNAPSHOT's query, never the box's",
    );
  },
);

check("an unsearchable row has no click handler at all", async () => {
  fire("find_tabs_state", SNAPSHOT);
  await flush();
  const before = gotoCalls().length;
  const group = global.$("findtabs-list").children[0];
  for (const child of group.children) {
    if (child._fire) child._fire("click");
  }
  await flush();
  assert(
    gotoCalls().length === before,
    "a row that cannot act must not reach Rust",
  );
});

check(
  "snippet text is composed, never parsed: markup renders inert and offsets are bytes",
  async () => {
    fire("find_tabs_state", SNAPSHOT);
    await flush();
    const group = global.$("findtabs-list").children[1];
    const lines = group.children.filter(
      (c) => c.className === "findtabs-snippet",
    );
    assert(lines.length === 2, "two snippets, two lines");
    // No element was ever created FROM the markup text.
    assert(
      !global.allEls.some((e) => e.id === "new-img"),
      "markup in a snippet must never become an element",
    );
    const bold = lines[1].children.find((c) => c.id === "new-b");
    assert(bold, "the match is bolded via a composed element");
    assert(
      bold._text[bold._text.length - 1] === "needle",
      "UTF-8 offsets decoded to the match, not shifted by the two-byte char: got " +
        JSON.stringify(bold._text),
    );
  },
);

check(
  "the locked snapshot clears the list, disables entry and shows the notice",
  async () => {
    fire("find_tabs_state", SNAPSHOT);
    await flush();
    fire("find_tabs_state", { locked: true, scanning: false, rows: [] });
    await flush();
    assert(global.$("findtabs-locked").hidden === false, "notice shows");
    assert(global.$("findtabs-query").disabled === true, "query disabled");
    assert(global.$("findtabs-list").children.length === 0, "results cleared");
    // And an unlocked snapshot re-enables on its own.
    fire("find_tabs_state", SNAPSHOT);
    await flush();
    assert(global.$("findtabs-locked").hidden === true, "notice leaves");
    assert(global.$("findtabs-query").disabled === false, "query re-enabled");
  },
);

check(
  "premium_required renders the standing note, not an empty result",
  async () => {
    global.$("findtabs-query").value = "needle";
    global.rbReject = "premium_required";
    global.$("findtabs-run")._fire("click");
    await flush();
    global.rbReject = null;
    assert(
      global.$("findtabs-premium").hidden === false,
      "the premium note un-hides beside the control",
    );
  },
);

check(
  "a search round-trips even a whitespace query: Rust is the authority",
  async () => {
    const before = global.rbCalls.filter(
      (c) => c.cmd === "find_tabs_search",
    ).length;
    global.$("findtabs-query").value = "   ";
    global.$("findtabs-run")._fire("click");
    await flush();
    const after = global.rbCalls.filter(
      (c) => c.cmd === "find_tabs_search",
    ).length;
    assert(after === before + 1, "no silent client-side validation");
  },
);

check("find_adopt hands the query to the ordinary bar", async () => {
  const before = global.rbCalls.filter((c) => c.cmd === "find_start").length;
  fire("find_adopt", { query: "needle" });
  await flush();
  assert(
    global.$("find-input").value === "needle",
    "the bar carries the adopted query",
  );
  const starts = global.rbCalls.filter((c) => c.cmd === "find_start");
  assert(starts.length > before, "the bar re-sends find_start");
  assert(
    starts[starts.length - 1].args.query === "needle",
    "with the SAME string, so on_query Ignores instead of restarting",
  );
});

check(
  "the quarantine count and the standing limitation note both render",
  async () => {
    fire("find_tabs_state", SNAPSHOT);
    await flush();
    const note = global.$("findtabs-note");
    const text =
      note._text.join(" ") +
      " " +
      note.children.map((c) => (c._text || []).join(" ")).join(" ");
    assert(
      text.includes("2 quarantine tabs are not searched."),
      "the skipped count is stated",
    );
    // The standing limitation sentence lives in the MARKUP (the stub
    // carries no body text, so it is asserted at the source): if it leaves
    // index.html, the panel stops disclosing what the search cannot see.
    const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
    assert(
      /as the server\s+delivered\s+them/.test(html) &&
        /Quarantine\s+tabs\s+are\s+not\s+searched/.test(html),
      "the delivered-HTML limitation is stated in the markup",
    );
  },
);

check("the empty state never shows for a scan that never ran", async () => {
  fire("find_tabs_state", {
    scanning: false,
    locked: false,
    query: "",
    skipped_quarantine: 0,
    rows: [],
  });
  await flush();
  assert(
    global.$("findtabs-empty").hidden === true,
    "an empty row set is no scan, not a no-match verdict",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      global.rbReject = null;
      await fn();
      console.log("  ok  " + name);
    } catch (err) {
      failures.push(name + ": " + err.message);
      console.log("  FAIL " + name + ": " + err.message);
    }
  }
  if (failures.length) {
    console.error("\nCROSS-TAB FIND GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log("\nCROSS-TAB FIND UI OK");
})();
