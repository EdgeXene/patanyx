// Reader View: the article on the current page, drawn from typed blocks of
// plain strings that Rust extracted from the page the server sent
// (crates/reader, crates/app/src/reader_view.rs).
//
// WHY THIS EXISTS. The strings this panel renders are PAGE CONTENT arriving
// in the trusted chrome document. Two properties keep that safe, and both
// are the kind a later edit can quietly break while every other gate stays
// green:
//
//   1. Text is set with textContent and tag names come from fixed tables in
//      chrome.js, never from the page. A block that carries markup must end
//      up as literal text, and a block whose "level" is a page-controlled
//      string must not choose the element.
//   2. Only the CURRENT request's answer is drawn. Rust drops stale answers
//      too, but the panel is the last line: an answer naming another request
//      must not paint, and nothing may paint after the panel closed or the
//      tab changed (reader_cleared).
//
// Both are proven against planted defects: run with PATANYX_READER_PLANT set
// to "stale", "stale-clear" or "tag" and this gate must FAIL (chrome-js-gate.sh
// runs all three).
//
// Run: node scripts/reader-panel-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");

const PLANT = process.env.PATANYX_READER_PLANT || "";
function plant(from, to) {
  if (!chromeJs.includes(from)) {
    console.error("PLANT TARGET MISSING: " + from);
    process.exit(2);
  }
  chromeJs = chromeJs.replace(from, to);
}
if (PLANT === "stale") {
  // Drop the panel's own request check: any answer paints.
  plant("if (readerRequest === 0 || req !== readerRequest) return;", "");
} else if (PLANT === "stale-clear") {
  // The defect review round 2 found: a clear for any request wipes the panel.
  plant("if (readerRequest === 0 || ended !== readerRequest) return;", "");
} else if (PLANT === "tag") {
  // Let the page's heading level pick the element.
  plant(
    "node = el(readerHeadingTag(b.level), null, str(b.text));",
    'node = el("h" + b.level, null, str(b.text));',
  );
} else if (PLANT) {
  console.error("unknown PATANYX_READER_PLANT: " + PLANT);
  process.exit(2);
}

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

const $ = (id) => global.document.getElementById(id);
const send = (event, data) => global.window.__rb_event({ event, data });
const panel = () => $("reader-panel");
const blocks = () => $("reader-blocks").children;

function descendants(node) {
  const out = [];
  const stack = [...(node.children || [])];
  while (stack.length) {
    const n = stack.shift();
    out.push(n);
    stack.push(...(n.children || []));
  }
  return out;
}

const ALLOWED_TAGS = new Set([
  "H3",
  "H4",
  "H5",
  "P",
  "BLOCKQUOTE",
  "PRE",
  "UL",
  "OL",
  "LI",
]);

async function openPanel() {
  // Always from a closed panel, so a check that failed half-way cannot leave
  // the next one reading the previous request's state.
  if (!panel().hidden) {
    $("btn-reader")._fire("click");
    await flush();
  }
  global.rbCalls.length = 0;
  $("btn-reader")._fire("click");
  await flush();
  return lastRequest();
}
// The request number the chrome itself chose and sent with reader_open.
function lastRequest() {
  const opens = global.rbCalls.filter((c) => c.cmd === "reader_open");
  const last = opens[opens.length - 1];
  return last && last.args ? last.args.request : undefined;
}
async function closePanel() {
  if (!panel().hidden) $("btn-reader")._fire("click");
  await flush();
}

const ARTICLE = {
  title: "Council delays vote",
  byline: "Sam Rivera",
  site: "Example News",
  truncated: false,
  blocks: [
    { kind: "heading", level: 2, text: "What happens next" },
    { kind: "para", text: "The committee met on Tuesday." },
    { kind: "list", ordered: false, items: ["First", "Second"] },
    { kind: "quote", text: "We need more time." },
    { kind: "pre", text: "fn main() {}" },
    { kind: "caption", text: "The council chamber" },
    { kind: "unknown_future_kind", text: "ignored" },
  ],
};

check("the button is a toolbar pill and the panel is in the markup", () => {
  const at = html.indexOf('id="btn-reader"');
  assert(at !== -1, "#btn-reader missing from index.html");
  const tag = html.slice(
    html.lastIndexOf("<button", at),
    html.indexOf(">", at),
  );
  assert(
    /class="feature-btn"/.test(tag),
    "#btn-reader must be a .feature-btn so toolbar-gate governs it",
  );
  assert(html.includes('<section id="reader-panel"'), "#reader-panel missing");
  assert(
    !/innerHTML/.test(
      chromeJs.slice(
        chromeJs.indexOf("// ---- Reader View ----"),
        chromeJs.indexOf('registerPanel("reader"'),
      ),
    ),
    "the Reader View block must not touch innerHTML",
  );
});

check("opening asks Rust exactly once, closing tells it", async () => {
  const r7 = await openPanel();
  assert(!panel().hidden, "panel did not open");
  const opens = global.rbCalls.filter((c) => c.cmd === "reader_open");
  assert(opens.length === 1, "expected one reader_open, saw " + opens.length);
  global.rbCalls.length = 0;
  await closePanel();
  assert(
    global.rbCalls.some((c) => c.cmd === "reader_close"),
    "closing must send reader_close",
  );
});

check("an article renders as fixed elements holding plain text", async () => {
  const r8 = await openPanel();
  send("reader_article", { request: r8, article: ARTICLE });
  await flush();
  assert(!$("reader-body").hidden, "article body stayed hidden");
  assert(
    $("reader-title").textContent === "Council delays vote",
    "title not shown",
  );
  assert(
    $("reader-meta").textContent.includes("Sam Rivera"),
    "byline not shown",
  );
  const tags = blocks().map((n) => n.tagName);
  assert(
    JSON.stringify(tags) ===
      JSON.stringify(["H3", "P", "UL", "BLOCKQUOTE", "PRE", "P"]),
    "unexpected block elements: " + tags.join(","),
  );
  assert(blocks()[2].children.length === 2, "list items missing");
  // el() sets className; the stub keeps className and classList apart.
  assert(blocks()[5].className === "reader-caption", "caption not marked");
  await closePanel();
});

check(
  "markup inside a block stays text, and the page never picks a tag",
  async () => {
    const r9 = await openPanel();
    const hostile = '<img src=x onerror="alert(1)">';
    send("reader_article", {
      request: r9,
      article: {
        title: "<script>alert(2)</script>",
        blocks: [
          { kind: "para", text: hostile },
          { kind: "heading", level: "1><script", text: "x" },
          { kind: "heading", level: 99, text: "deep" },
          { kind: "list", ordered: "yes", items: [hostile, 5] },
        ],
      },
    });
    await flush();
    assert(
      blocks()[0].textContent === hostile,
      "markup was not kept as literal text",
    );
    assert(
      $("reader-title").textContent === "<script>alert(2)</script>",
      "title not literal",
    );
    for (const n of descendants($("reader-blocks"))) {
      assert(
        ALLOWED_TAGS.has(n.tagName),
        "a page string chose an element: " + n.tagName,
      );
    }
    assert(
      blocks()[3].tagName === "UL",
      "only ordered === true may make an <ol>",
    );
    await closePanel();
  },
);

check("an answer for another request does not paint", async () => {
  const r10 = await openPanel();
  send("reader_article", { request: r10 - 1, article: ARTICLE });
  await flush();
  assert(blocks().length === 0, "a stale request's article was drawn");
  assert($("reader-body").hidden, "body shown for a stale answer");
  send("reader_article", { request: r10, article: ARTICLE });
  await flush();
  assert(blocks().length > 0, "the current request's article was not drawn");
  await closePanel();
});

check("nothing paints after the panel closes", async () => {
  const r11 = await openPanel();
  await closePanel();
  send("reader_article", { request: r11, article: ARTICLE });
  await flush();
  assert(blocks().length === 0, "an article painted into a closed panel");
});

check("a clear for an older request does not wipe the current one", async () => {
  // Review round 2 (R-002): a tab switch queued a clear for request 1, the
  // panel was closed and reopened (request 2), and the late clear wiped
  // request 2's article. A clear names the request it ends.
  const r1 = await openPanel();
  await closePanel();
  const r2 = await openPanel();
  send("reader_cleared", { request: r1 });
  await flush();
  send("reader_article", { request: r2, article: ARTICLE });
  await flush();
  assert(blocks().length > 0, "a stale clear discarded the current article");
  assert(!$("reader-body").hidden, "a stale clear hid the current article");
  await closePanel();
});

check("reader_cleared empties the panel and offers to read again", async () => {
  const r12 = await openPanel();
  send("reader_article", { request: r12, article: ARTICLE });
  await flush();
  send("reader_cleared", { request: r12 });
  await flush();
  assert(blocks().length === 0, "blocks survived reader_cleared");
  assert($("reader-body").hidden, "body still shown after reader_cleared");
  assert(!$("reader-retry").hidden, "no way to read the new page");
  send("reader_article", { request: r12, article: ARTICLE });
  await flush();
  assert(blocks().length === 0, "the cleared request painted again");
  global.rbCalls.length = 0;
  $("reader-retry")._fire("click");
  await flush();
  assert(
    global.rbCalls.some((c) => c.cmd === "reader_open"),
    "Read this page did not ask again",
  );
  await closePanel();
});

check("every error Rust can send has words", async () => {
  const codes = [
    "reader_unsupported_url",
    "reader_unsupported",
    "reader_page_loading",
    "reader_page_unavailable",
    "reader_no_article",
    "reader_unsupported_encoding",
    "reader_busy",
  ];
  const rust = fs.readFileSync(
    path.join(root, "crates/app/src/reader_view.rs"),
    "utf8",
  );
  for (const code of codes) {
    assert(
      rust.includes('"' + code + '"'),
      code + " is listed here but Rust never sends it",
    );
  }
  for (const m of rust.matchAll(/"(reader_[a-z_]+)"/g)) {
    if (
      [
        "reader_open",
        "reader_close",
        "reader_article",
        "reader_error",
        "reader_cleared",
        "reader_extract",
      ].includes(m[1])
    )
      continue;
    assert(
      codes.includes(m[1]),
      "Rust sends " + m[1] + " but this gate does not check its words",
    );
  }
  for (const code of codes) {
    const r20 = await openPanel();
    send("reader_error", { request: r20, code });
    await flush();
    const text = $("reader-status").textContent;
    assert(
      text && !/Unexpected error/.test(text),
      code + " has no user-facing text: " + text,
    );
    assert(!$("reader-retry").hidden, code + ": no way to try again");
    await closePanel();
  }
});

check("F9 (toggle_reader_view) opens and closes the panel", async () => {
  send("toggle_reader_view", {});
  await flush();
  assert(!panel().hidden, "F9 did not open Reader View");
  send("toggle_reader_view", {});
  await flush();
  assert(panel().hidden, "F9 did not close Reader View");
});

check("text size and typeface controls change only classes", async () => {
  const r31 = await openPanel();
  const body = $("reader-body");
  const sizeOf = () =>
    body.classList._all().filter((c) => c.startsWith("reader-size-"));
  assert(
    sizeOf().length === 1,
    "exactly one size class expected, saw " + sizeOf(),
  );
  const before = sizeOf()[0];
  $("reader-larger")._fire("click");
  assert(
    sizeOf().length === 1 && sizeOf()[0] !== before,
    "Larger text did nothing",
  );
  for (let i = 0; i < 10; i += 1) $("reader-smaller")._fire("click");
  assert(
    sizeOf()[0] === "reader-size-0" && $("reader-smaller").disabled,
    "smallest size not clamped",
  );
  const pressed = $("reader-font").getAttribute("aria-pressed");
  $("reader-font")._fire("click");
  assert(
    $("reader-font").getAttribute("aria-pressed") !== pressed,
    "Serif toggle did not change state",
  );
  assert(
    body.classList.contains("reader-sans") === (pressed === "true"),
    "typeface class out of step",
  );
  await closePanel();
});

check("a quick close and reopen never paints the earlier request (review R-002)", async () => {
  // Open, then close and reopen BEFORE anything settles: the ordering the
  // review reproduced against the version that learned its request number
  // from Rust's reply.
  if (!panel().hidden) await closePanel();
  global.rbCalls.length = 0;
  $("btn-reader")._fire("click"); // open: request A
  $("btn-reader")._fire("click"); // close
  $("btn-reader")._fire("click"); // reopen: request B
  const opens = global.rbCalls.filter((c) => c.cmd === "reader_open");
  assert(opens.length === 2, "expected two reader_open calls, saw " + opens.length);
  const a = opens[0].args.request;
  const b = opens[1].args.request;
  assert(a !== b, "both opens used the same request number");
  // A's article arrives first, before either reply has been processed.
  send("reader_article", { request: a, article: ARTICLE });
  await flush();
  assert(blocks().length === 0, "the earlier request's article painted the reopened panel");
  send("reader_article", { request: b, article: ARTICLE });
  await flush();
  assert(blocks().length > 0, "the current request's article was dropped");
  await closePanel();
});

check("a superseded request's failure does not overwrite the panel", async () => {
  if (!panel().hidden) await closePanel();
  global.rbResolve.reader_open = new Error("reader_page_loading");
  global.rbCalls.length = 0;
  $("btn-reader")._fire("click"); // A, will fail
  $("btn-reader")._fire("click"); // close
  delete global.rbResolve.reader_open;
  $("btn-reader")._fire("click"); // B, succeeds
  const b = lastRequest();
  send("reader_article", { request: b, article: ARTICLE });
  await flush();
  assert(blocks().length > 0, "B's article did not paint");
  assert(!/still loading/.test($("reader-status").textContent), "A's failure overwrote the panel");
  await closePanel();
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name);
      console.log("  FAIL " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error(
      "READER PANEL GATE FAILED (" +
        failures.length +
        ")" +
        (PLANT ? " [plant: " + PLANT + "]" : ""),
    );
    process.exit(1);
  }
  console.log("READER PANEL GATE OK (" + checks.length + " checks)");
})();
