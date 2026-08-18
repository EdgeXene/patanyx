// Deep Recall says what it saved, and never quietly loses a page.
//
// Four rules this pins, each one a way the panel could mislead:
//
//   1. A LOCKED control never asks Rust to save. Same rule as the region
//      mode: a gated feature must not fire a request it cannot finish.
//   2. Listing and searching have DIFFERENT empty states. "Nothing saved
//      yet" and "no saved page has that word" are different facts, and
//      showing the first after a fruitless search would tell the user their
//      archive is empty when it is not.
//   3. A page whose picture yielded no text still SAYS so on its row. An
//      empty read is normal, and a row that hid it would leave the user
//      wondering why a search never finds that page.
//   4. Saving reports what was actually read. "Saved" alone hides the
//      difference between a page full of words and one the reader found
//      nothing in.
//
// Proven against planted defects when it landed: dropping the premium check
// in the save handler fails check 1, collapsing the two empty states into
// one fails check 2, and reporting a bare "Saved." fails check 4.
//
// Guard shape: chrome-js-gate.sh refuses to run this file when
// #recall-panel is gone from index.html.
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

const $ = (id) => global.document.getElementById(id);
const fire = (event, data) => global.window.__rb_event({ event, data });
const saveCalls = () => global.rbCalls.filter((c) => c.cmd === "archive_save");

const licensed = (premium) => {
  global.rbResolve.premium_status = {
    state: premium ? "perpetual" : "locked",
    premium,
    on_sale: false,
  };
};

// Opening and closing the panel makes chrome.js re-read the licence.
const openPanel = async () => {
  $("btn-recall").click();
  await flush();
};
const closePanel = async () => {
  $("btn-recall").click();
  await flush();
};

check("a locked Deep Recall never asks Rust to save", async () => {
  licensed(false);
  await openPanel();
  global.rbCalls.length = 0;
  $("recall-save").click();
  await flush();
  assert(
    saveCalls().length === 0,
    "a locked control started a save it cannot finish",
  );
  assert(
    !$("recall-premium").hidden,
    "the panel must say why instead of looking broken",
  );
  await closePanel();
});

check("a licensed panel lists what is saved", async () => {
  licensed(true);
  global.rbResolve.archive_list = {
    items: [
      {
        id: "a1",
        url: "https://example.com/report",
        title: "Quarterly report",
        created_at: 1700000000,
        has_picture: true,
        words: 42,
      },
    ],
    count: 1,
    max: 200,
  };
  await openPanel();
  assert($("recall-list").children.length === 1, "the saved page did not list");
  assert($("recall-empty").hidden, "empty state shown with a page present");
});

check("listing and searching have different empty states", async () => {
  // The distinction that matters: an empty archive and a fruitless search
  // are different facts about the user's data.
  licensed(true);
  global.rbResolve.archive_list = { items: [], count: 0, max: 200 };
  await closePanel();
  await openPanel();
  assert(
    !$("recall-empty").hidden,
    "an empty archive must say nothing is saved",
  );
  assert(
    $("recall-none").hidden,
    "the no-results line is not for an empty archive",
  );

  global.rbResolve.archive_search = { items: [] };
  $("recall-query").value = "needle";
  $("recall-query")._fire("input");
  await flush();
  assert(!$("recall-none").hidden, "a fruitless search must say so");
  assert(
    $("recall-empty").hidden,
    "a fruitless search must NOT claim the archive is empty",
  );
  $("recall-query").value = "";
});

check("a page with no readable text says so on its row", async () => {
  licensed(true);
  global.rbResolve.archive_list = {
    items: [
      {
        id: "a2",
        url: "https://example.com/photos",
        title: "Photo wall",
        created_at: 1700000000,
        has_picture: true,
        words: 0,
      },
    ],
    count: 1,
    max: 200,
  };
  await closePanel();
  await openPanel();
  const text = global.allText().join(" ");
  assert(
    /No text was read/.test(text),
    "a page with no read text must say so rather than look like any other row",
  );
});

check("saving reports what was actually read", async () => {
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", { ok: true, id: "a3", words: 137 });
  await flush();
  const status = $("recall-status").textContent;
  assert(/137/.test(status), "the word count must reach the user: " + status);

  fire("archive_saved", { ok: true, id: "a4", words: 0 });
  await flush();
  const empty = $("recall-status").textContent;
  assert(
    /No text was read/.test(empty),
    "a read that found nothing must say so, not just 'Saved': " + empty,
  );
});

check("a full archive is reported as a thing the user can fix", async () => {
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", { ok: false, error: "archive_full" });
  await flush();
  const status = $("recall-status").textContent.toLowerCase();
  assert(/full/.test(status), "the refusal must name the cause: " + status);
  assert(/delete/.test(status), "the refusal must name the remedy: " + status);
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL: " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error("deep-recall-gate: " + failures.length + " check(s) failed");
    process.exit(1);
  }
  console.log("deep-recall-gate OK (" + checks.length + " checks)");
})();
