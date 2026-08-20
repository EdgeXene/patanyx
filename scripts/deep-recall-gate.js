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

// Deep Recall lives in the tools modal now (2026-08-19): its toolbar button
// is gone, and the way in is the modal's recall TAB -- which opens the modal
// itself when it is closed, because every tab button is a complete door (the
// palette clicks them directly). STATE-AWARE rather than toggles: the old
// btn-recall helpers were pure toggles, and checks that assumed "open"
// while a previous check left the panel open flipped it shut and read stale
// rows. Selecting the tab re-runs the licence read, which is what the old
// panel-open did.
const openPanel = async () => {
  $("btn-tab-recall").click();
  await flush();
};
const closePanel = async () => {
  if (!$("integrity-host").hidden) {
    $("btn-integrity").click();
    await flush();
  }
};

check("locking the vault takes the picture off the screen", async () => {
  // THE LEAK THIS PINS. Rust clears the staged slot on lock, so the token
  // 404s -- but an image ALREADY LOADED stays rendered, and a full-page
  // screenshot would sit there through an idle auto-lock. The shipped
  // release notes say locking the vault takes it off screen, so this is a
  // published claim, not a preference.
  licensed(true);
  global.rbResolve.archive_list = {
    items: [
      {
        id: "a5",
        url: "https://example.com/kept",
        title: "Kept page",
        created_at: 1700000000,
        has_picture: true,
        words: 8,
      },
    ],
    count: 1,
    max: 200,
  };
  global.rbResolve.archive_picture_stage = { token: 5 };
  await ensureOpen();
  findButton($("recall-list"), "View")._fire("click");
  await flush();
  assert(!$("recall-preview").hidden, "precondition: the picture is showing");

  global.window.__rb_event({ event: "vault_locked", data: {} });
  await flush();

  assert(
    $("recall-preview").hidden,
    "the decrypted page is still on screen after the vault locked",
  );
  assert(
    !$("recall-preview-img").getAttribute("src"),
    "the img kept its src, so the picture is still rendered",
  );
  await ensureClosed();
});

check("the tools host is in the every-panel style rule", () => {
  // THE GRAY RECTANGLE, reported from hardware the same day the host was
  // created. chrome.css paints every panel through ONE id-list rule
  // (background, padding, scroll), whose own comment says a new panel
  // belongs in the list -- and #integrity-host shipped a hardware round
  // without joining it, rendering as a pale native-default rectangle with
  // integrity.js's dark card floating inside. Nothing in the suite compares
  // computed styles, so this checks the one thing that IS checkable: the
  // selector list names the host.
  const css = fs.readFileSync(
    path.join(chromeDir, "chrome.css"),
    "utf8",
  );
  const rule = css.match(/#vault-panel,[\s\S]*?\{/);
  assert(rule, "the every-panel rule is gone entirely");
  assert(
    rule[0].includes("#integrity-host"),
    "#integrity-host is missing from the every-panel rule; the tools modal " +
      "renders as an unpainted rectangle",
  );
});

check("the tools modal is one home with three doors", async () => {
  // THE RESTRUCTURE THIS PINS, 2026-08-19: Page
  // integrity, Deep Recall and the image check share one modal, and each
  // tab button is a complete door -- clicking it OPENS the modal when it is
  // closed, because the palette clicks these buttons directly and a palette
  // row that lands on a closed modal is a dead end. Deep Recall's own
  // toolbar button is gone; a stale #btn-recall reference anywhere would
  // resurrect a second door to a panel that no longer exists.
  licensed(true);
  assert(!$("btn-recall"), "the old Deep Recall toolbar button is back");
  assert($("integrity-host").hidden, "the modal must start closed");

  $("btn-tab-recall").click();
  await flush();
  assert(!$("integrity-host").hidden, "the recall tab did not open the modal");
  assert(!$("recall-panel").hidden, "the recall body is not showing");
  assert(
    $("tools-integrity-slot").hidden,
    "two tab bodies are showing at once",
  );
  assert(
    $("btn-tab-recall").getAttribute("aria-pressed") === "true",
    "the active tab does not say so",
  );

  // The toolbar button itself lands on Page integrity, as it always has.
  $("btn-integrity").click();
  await flush();
  $("btn-integrity").click();
  await flush();
  assert(!$("tools-integrity-slot").hidden, "the toolbar door lands on integrity");
  assert($("recall-panel").hidden, "recall stayed up under the integrity tab");
  await closePanel();
});

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
  // Both events carry the full shape Rust sends. They used to omit scope and
  // truncated, which is an event the app can no longer produce -- a stub that
  // drifts from the real payload tests a code path nobody runs.
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", {
    ok: true,
    id: "a3",
    words: 137,
    truncated: false,
    scope: "full page",
  });
  await flush();
  const status = $("recall-status").textContent;
  assert(/137/.test(status), "the word count must reach the user: " + status);

  fire("archive_saved", {
    ok: true,
    id: "a4",
    words: 0,
    truncated: false,
    scope: "full page",
  });
  await flush();
  const empty = $("recall-status").textContent;
  assert(
    /No text was read/.test(empty),
    "a read that found nothing must say so, not just 'Saved': " + empty,
  );
});

// THE CLAIM HAS TO TRACK THE CAPTURE. A compliance pass caught this message
// telling every user "the picture is complete" while the Windows fallback
// path -- an engine too old for the full-page protocol call -- had saved the
// viewport. The scope rides on the event; these four checks are the whole
// truth table, because three of them were true before the fix and only the
// fourth was wrong, which is how it survived.
check("a truncated read on a full-page capture says the picture is whole", async () => {
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", {
    ok: true,
    id: "s1",
    words: 900,
    truncated: true,
    scope: "full page",
  });
  await flush();
  const status = $("recall-status").textContent;
  assert(
    /stops partway down/.test(status),
    "a truncated read must admit the text stops: " + status,
  );
  assert(
    /picture is complete/.test(status),
    "a full-page capture may say the picture is whole: " + status,
  );
});

check("a truncated read on a viewport capture must NOT claim a whole picture", async () => {
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", {
    ok: true,
    id: "s2",
    words: 900,
    truncated: true,
    scope: "visible area",
  });
  await flush();
  const status = $("recall-status").textContent;
  assert(
    !/picture is complete/.test(status),
    "the viewport fallback must not claim a complete picture: " + status,
  );
  assert(
    /on screen/.test(status),
    "the viewport fallback must say what the picture actually covers: " + status,
  );
});

check("an untruncated viewport capture still says what the picture covers", async () => {
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", {
    ok: true,
    id: "s3",
    words: 40,
    truncated: false,
    scope: "visible area",
  });
  await flush();
  const status = $("recall-status").textContent;
  assert(
    /on screen/.test(status),
    "a viewport capture is worth saying even when the read was whole: " +
      status,
  );
  assert(
    !/stops partway down/.test(status),
    "an untruncated read must not claim truncation: " + status,
  );
});

check("the empty state does not out-claim the save message", async () => {
  // Found by a real browser, not by this file: the empty state sat directly
  // above a save message saying the picture was only the visible area, and
  // flatly contradicted it. A static string shown before any capture exists
  // cannot know the scope, so it defers instead of asserting.
  // Read from the markup, not the stub: this is a static string and the dom
  // stub does not carry text out of index.html.
  const text = fs
    .readFileSync(path.join(chromeDir, "index.html"), "utf8")
    .replace(/\s+/g, " ");
  const empty = (text.match(/id="recall-empty"[\s\S]{0,1500}?<\/p>/) || [
    "(#recall-empty is gone)",
  ])[0].replace(/<!--[\s\S]*?-->/g, "");
  assert(
    /each save says how much of the page it captured/.test(empty),
    "the empty state must hand the scope claim to the save message: " + empty,
  );
});

check("a truncated read that found no text must not talk about text", async () => {
  // Reachable through the tile-budget half of the truncation flag: an
  // image-dense page can exhaust detection while every line reads empty.
  // "No text was read" and "the text stops partway down" cannot both be
  // true, and the two clauses were assembled independently, which is how
  // the pair got past the four-way table above.
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", {
    ok: true,
    id: "s5",
    words: 0,
    truncated: true,
    scope: "visible area",
  });
  await flush();
  const status = $("recall-status").textContent;
  assert(
    /No text was read/.test(status),
    "an empty read must still say so: " + status,
  );
  assert(
    !/stops partway down/.test(status),
    "there is no text to stop: " + status,
  );
  assert(
    /on screen/.test(status),
    "the viewport scope is still worth saying: " + status,
  );

  fire("archive_saved", {
    ok: true,
    id: "s6",
    words: 0,
    truncated: true,
    scope: "full page",
  });
  await flush();
  const whole = $("recall-status").textContent;
  assert(
    whole === "Saved. No text was read from this picture.",
    "a whole-page capture with nothing in it needs no clause at all: " + whole,
  );
});

check("the ordinary case stays one plain sentence", async () => {
  licensed(true);
  await closePanel();
  await openPanel();
  fire("archive_saved", {
    ok: true,
    id: "s4",
    words: 40,
    truncated: false,
    scope: "full page",
  });
  await flush();
  const status = $("recall-status").textContent;
  assert(
    status === "Saved. 40 words read from this page.",
    "no shortfall means no extra clause: " + status,
  );
});

// The dom stub's querySelectorAll matches direct children by class or id
// only, so a tag search two levels deep needs its own walk.
// Both helpers above are state-aware now, so these are plain aliases kept
// so the newer checks read as they were written.
const ensureOpen = openPanel;
const ensureClosed = closePanel;

// The stub carries no tagName; a runtime-created button's id is
// "new-button" (domstub.js createElement), and its label is textContent.
const findButton = (node, label) => {
  const kids = (node && node.children) || [];
  for (const kid of kids) {
    if (
      String(kid.id || "").startsWith("new-button") &&
      kid.textContent === label
    ) {
      return kid;
    }
    const hit = findButton(kid, label);
    if (hit) return hit;
  }
  return null;
};

check("a saved picture can actually be looked at", async () => {
  // THE DEFECT THIS PINS, reported from the panel itself: "Where am I
  // supposed to find the screenshots?" archive_save stored the picture,
  // encrypted and tested, and the panel listed has_picture:true while
  // offering only Delete. No IPC arm exposed the bytes and nothing here
  // asked. The row now carries View: it stages the ONE decrypted picture
  // and points the preview img at the token URL the chrome protocol serves.
  licensed(true);
  global.rbResolve.archive_list = {
    items: [
      {
        id: "a7",
        url: "https://example.com/kept",
        title: "Kept page",
        created_at: 1700000000,
        has_picture: true,
        words: 12,
      },
    ],
    count: 1,
    max: 200,
  };
  global.rbResolve.archive_picture_stage = { token: 7 };
  await ensureOpen();

  const view = findButton($("recall-list"), "View");
  assert(view, "a row with a picture has no View button");
  view._fire("click");
  await flush();

  const staged = global.rbCalls.filter((c) => c.cmd === "archive_picture_stage");
  assert(staged.length === 1, "View never asked Rust to stage the picture");
  assert(staged[0].args.id === "a7", "staged the wrong record: " + JSON.stringify(staged[0].args));
  assert(
    $("recall-preview-img").getAttribute("src") === "/archive-picture/7.png",
    "the preview does not point at the staged token: " +
      $("recall-preview-img").getAttribute("src"),
  );
  assert(!$("recall-preview").hidden, "the preview stayed hidden");
  await ensureClosed();
});

check("a save with no picture offers no View", async () => {
  // has_picture:false is a real state (a degraded save keeps text only) and
  // a View button on it would stage a NotFound and toast an error at the
  // user for clicking the button we drew.
  licensed(true);
  global.rbResolve.archive_list = {
    items: [
      {
        id: "a8",
        url: "https://example.com/textonly",
        title: "Text only",
        created_at: 1700000000,
        has_picture: false,
        words: 3,
      },
    ],
    count: 1,
    max: 200,
  };
  await ensureOpen();
  assert(
    !findButton($("recall-list"), "View"),
    "a row with no picture grew a View button",
  );
  await ensureClosed();
});

check("closing the preview, and the panel, both release the picture", async () => {
  // The staged slot holds a DECRYPTED page. Close must wipe it (Rust side)
  // and drop the chrome's reference (src removed), and closing the whole
  // panel must do the same -- a decrypted page must not sit staged behind a
  // closed panel where nothing on screen says it exists.
  licensed(true);
  global.rbResolve.archive_list = {
    items: [
      {
        id: "a9",
        url: "https://example.com/kept",
        title: "Kept page",
        created_at: 1700000000,
        has_picture: true,
        words: 5,
      },
    ],
    count: 1,
    max: 200,
  };
  global.rbResolve.archive_picture_stage = { token: 9 };
  await ensureOpen();
  findButton($("recall-list"), "View")._fire("click");
  await flush();
  global.rbCalls.length = 0;

  $("recall-preview-close")._fire("click");
  await flush();
  assert(
    global.rbCalls.some((c) => c.cmd === "archive_picture_clear"),
    "closing the preview never told Rust to wipe the staged bytes",
  );
  assert(
    !$("recall-preview-img").getAttribute("src"),
    "the img kept its src after close",
  );
  assert($("recall-preview").hidden, "the preview stayed visible");

  // And via the panel: stage again, close the whole panel.
  findButton($("recall-list"), "View")._fire("click");
  await flush();
  global.rbCalls.length = 0;
  await ensureClosed();
  assert(
    global.rbCalls.some((c) => c.cmd === "archive_picture_clear"),
    "closing the panel left the decrypted picture staged",
  );
  // The checks below this one predate ensureOpen/ensureClosed and use the
  // raw toggles, counting on the panel being OPEN when they start. Restore
  // that so inserting these checks does not change what they test.
  await ensureOpen();
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
