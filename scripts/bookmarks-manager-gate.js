// The bookmarks manager, driven through the REAL chrome.js against a fake
// store that implements the same folder-as-tag and quick-access semantics the
// Rust store enforces.
//
// Three things here are the reason this file exists:
//
//   1. QUICK ACCESS IS PINNED. It must not be filtered away by the sidebar,
//      the search box or the sort. That is a stated requirement, and it is
//      the kind of thing a later "just reuse the filtered list" refactor
//      would quietly break.
//   2. FILING GOES THROUGH THE CLICK PATH. The Folders popover must send the
//      ATOMIC bookmark_folder_file/unfile, never the whole-list
//      bookmark_tags_set. Filing used to be drag-only, and drag did nothing
//      at all for the first person who tried it, so the click path is the
//      mechanism and is gated as such.
//   3. ADDING BY HAND reaches bookmark_add with the typed address, so the
//      Rust-side allowlist is the thing that decides -- not this side.
//   4. SNAPSHOTS IS A LIVE BUILT-IN VIEW. Digest-bearing bookmarks must be
//      reachable there, newest first, with the saved date on their rows.
//   5. QUICK ACCESS ORDER IS STORE STATE. A synthetic drag must send one full
//      id list, survive a reload, and be refused atomically when any id is not
//      pinned. The generic DOM stub already dispatches these event names.
//   6. SNAPSHOT PICTURES reuse the one Deep Recall viewer and decrypted slot.
//      Plant proof: deleting the clear-before-stage call makes the slot-order
//      check fail; deleting onLocked's close leaves src live and fails the
//      locked-vault check.
//
// Run: node scripts/bookmarks-manager-gate.js  (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 24; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// ---- the fake store ----
function norm(raw) {
  const t = String(raw == null ? "" : raw).trim();
  return [...t].slice(0, 40).join("").toLowerCase().trim();
}
const store = {
  bookmarks: [
    {
      id: "b1",
      url: "https://alpha.test/",
      title: "Alpha",
      tags: ["chem"],
      quick_access: true,
      quick_access_order: null,
      has_digest: true,
      digest_recorded_at: 1700000000,
    },
    {
      id: "b2",
      url: "https://beta.test/",
      title: "Beta",
      tags: [],
      quick_access: false,
      quick_access_order: null,
      has_digest: false,
      digest_recorded_at: null,
    },
    {
      id: "b3",
      url: "https://gamma.test/",
      title: "Gamma",
      tags: ["reading"],
      quick_access: false,
      quick_access_order: null,
      has_digest: true,
      digest_recorded_at: 1800000000,
      snapshot_times: [1800000000, 1750000000],
      snapshot_pictures: [true, true],
      snapshot_scopes: ["full page", "visible area"],
    },
  ],
  folders: ["chem", "reading"],
  quickAccessWrites: 0,
};
const posted = [];
const replies = [];
let storeOpen = true;
let integrityError = null;
let pictureToken = 40;
let stagedPicture = null;

function listReply() {
  return {
    items: store.bookmarks.map((b) => ({
      id: b.id,
      url: b.url,
      title: b.title,
      created_at: 0,
      tags: b.tags.slice(),
      quick_access: b.quick_access,
      quick_access_order: b.quick_access_order,
      has_digest: b.has_digest === true,
      digest_recorded_at:
        b.has_digest === true ? b.digest_recorded_at : null,
      snapshots:
        b.has_digest === true
          ? (b.snapshot_times || [b.digest_recorded_at]).map(
              (recorded_at, index) => ({
                id: "snapshot-" + b.id + "-" + index,
                recorded_at,
                text_available: true,
                text_trimmed: false,
                has_picture: (b.snapshot_pictures || [false])[index] === true,
                picture_scope: (b.snapshot_scopes || [null])[index] || null,
              }),
            )
          : [],
    })),
    folders: store.folders.slice(),
  };
}

function handle(cmd, args) {
  const find = (id) => store.bookmarks.find((b) => b.id === id);
  switch (cmd) {
    case "bookmark_list":
      return { ok: true, data: listReply() };
    // The panel is the Library now, so opening it asks whether the store is
    // open before it draws anything. An unlocked store is the state under
    // test; the locked state has its own behaviour and is not this file's
    // subject.
    case "store_status":
      return { ok: true, data: { open: storeOpen, digests_ready: true } };
    case "shelf_list":
      return { ok: true, data: { items: [] } };
    case "download_list":
      return { ok: true, data: { items: [] } };
    case "bookmarks_bar_get":
      return { ok: true, data: { shown: false } };
    case "integrity_check_bookmark":
      if (integrityError) return { ok: false, error: integrityError };
      return { ok: true, data: {} };
    case "snapshot_picture_stage":
      stagedPicture = args.id;
      pictureToken += 1;
      return { ok: true, data: { token: pictureToken } };
    case "archive_picture_clear":
      stagedPicture = null;
      return { ok: true, data: {} };
    case "bookmark_add": {
      // The manual path: a url argument means the user typed it.
      if (typeof args.url === "string" && args.url) {
        const url = args.url.includes("://") ? args.url : "https://" + args.url;
        const id = "new" + (store.bookmarks.length + 1);
        store.bookmarks.push({
          id,
          url,
          title: args.title || url,
          tags: [],
          quick_access: false,
          quick_access_order: null,
        });
        return { ok: true, data: { id, url, title: args.title || url } };
      }
      return { ok: false, error: "bad_args" };
    }
    case "bookmark_quick_access_set": {
      const b = find(args.id);
      if (!b) return { ok: false, error: "not_found" };
      const changed = b.quick_access !== args.on;
      b.quick_access = args.on;
      if (!args.on) b.quick_access_order = null;
      return { ok: true, data: { id: args.id, on: args.on, changed } };
    }
    case "bookmark_quick_access_reorder": {
      if (!Array.isArray(args.ids)) return { ok: false, error: "bad_args" };
      const pinned = store.bookmarks.filter((b) => b.quick_access === true);
      const pinnedIds = new Set(pinned.map((b) => b.id));
      const requested = new Set(args.ids);
      if (
        args.ids.length !== pinned.length ||
        requested.size !== args.ids.length ||
        args.ids.some((id) => typeof id !== "string" || !pinnedIds.has(id))
      ) {
        return { ok: false, error: "bad_args" };
      }
      for (const [order, id] of args.ids.entries()) {
        find(id).quick_access_order = order;
      }
      store.quickAccessWrites += 1;
      return { ok: true, data: { ids: args.ids.slice(), changed: true } };
    }
    case "bookmark_folder_file": {
      const b = find(args.id);
      if (!b) return { ok: false, error: "not_found" };
      const f = norm(args.folder);
      if (!b.tags.includes(f)) b.tags.push(f);
      return { ok: true, data: { id: args.id, folder: f, added: true } };
    }
    case "bookmark_folder_unfile": {
      const b = find(args.id);
      if (!b) return { ok: false, error: "not_found" };
      const f = norm(args.folder);
      b.tags = b.tags.filter((t) => t !== f);
      return { ok: true, data: { id: args.id, folder: f, removed: true } };
    }
    case "bookmark_folder_create": {
      const name = norm(args.name);
      if (!name) return { ok: false, error: "bad_args" };
      if (!store.folders.includes(name)) store.folders.push(name);
      return { ok: true, data: { name } };
    }
    case "bookmarks_delete_all": {
      const bookmarks = store.bookmarks.length;
      const folders = store.folders.length;
      store.bookmarks = [];
      store.folders = [];
      return { ok: true, data: { bookmarks, folders } };
    }
    case "bookmark_folder_delete": {
      const name = norm(args.name);
      store.folders = store.folders.filter((f) => f !== name);
      for (const b of store.bookmarks)
        b.tags = b.tags.filter((t) => t !== name);
      return { ok: true, data: { name, deleted: true } };
    }
    case "bookmark_delete": {
      store.bookmarks = store.bookmarks.filter((b) => b.id !== args.id);
      return { ok: true, data: {} };
    }
    default:
      return { ok: true, data: {} };
  }
}

global.window.ipc.postMessage = (raw) => {
  const msg = JSON.parse(raw);
  posted.push({ cmd: msg.cmd, args: msg.args });
  setImmediate(() => {
    const r = handle(msg.cmd, msg.args || {});
    replies.push({ id: msg.id, ok: r.ok, data: r.data, error: r.error });
    if (!global.window.__rb_reply) return;
    global.window.__rb_reply({
      id: msg.id,
      ok: r.ok,
      data: r.data,
      error: r.error,
    });
  });
};

// ---- readers over the rendered manager ----
const kids = (node) => (node && node.children) || [];
function quickNames() {
  return kids(global.$("bmm-quick"))
    .map((item) => kids(item).find((c) => c.className === "bmm-quick-name"))
    .filter(Boolean)
    .map((n) => n.textContent);
}
function quickTiles() {
  return kids(global.$("bmm-quick"));
}
function quickTile(name) {
  return quickTiles().find((item) => {
    const label = kids(item).find((c) => c.className === "bmm-quick-name");
    return label && label.textContent === name;
  });
}
function listRows() {
  return kids(global.$("bmm-list")).filter((r) => r.className === "bmm-row");
}
function rowTitles() {
  return listRows()
    .map((r) => kids(r).find((c) => c.className === "bmm-meta"))
    .filter(Boolean)
    .map((m) => kids(m).find((c) => c.className === "bmm-title").textContent);
}
function rowByTitle(title) {
  return listRows().find((r) => {
    const meta = kids(r).find((c) => c.className === "bmm-meta");
    if (!meta) return false;
    const t = kids(meta).find((c) => c.className === "bmm-title");
    return t && t.textContent === title;
  });
}
function rowAction(row, label) {
  const actions = kids(row).find((c) => c.className === "bmm-actions");
  return actions ? kids(actions).find((b) => b.textContent === label) : null;
}
function descendantText(node) {
  if (!node) return "";
  return [node.textContent]
    .concat(kids(node).map(descendantText))
    .filter(Boolean)
    .join(" ");
}
function rowSnapshotLine(row) {
  const meta = kids(row).find((c) => c.className === "bmm-meta");
  return meta
    ? kids(meta).find(
        (c) =>
          c.className === "item-sub" &&
          String(c.textContent).startsWith("Page snapshot from "),
      )
    : null;
}
function sidebarButtons() {
  return kids(global.$("bmm-folders"));
}
function sidebarByLabel(label) {
  return sidebarButtons().find((b) => {
    const l = kids(b).find((c) => c.className === "bmm-side-label");
    return l && l.textContent === label;
  });
}
function popover() {
  return kids(global.$("bookmarks-panel")).find(
    (c) => c.className === "bmm-popover",
  );
}
async function openManager() {
  global.$("btn-library")._fire("click");
  await flush();
}

// ---- checks ----

check("unlock refreshes the star even while the bookmarks bar is hidden", async () => {
  // The original substitute called refreshBookmarkBar(), which fetched the
  // bookmark list only inside `if (shown)`. With the bar hidden, the cache
  // stayed empty and the star denied a bookmark that was already in store.
  global.$("url").value = "https://alpha.test/";
  global.$("unlock-pass").value = "correct horse battery staple";
  posted.length = 0;
  global.$("unlock-form")._fire("submit");
  await flush();

  assert(
    posted.some((call) => call.cmd === "bookmark_list"),
    "unlock never populated bookmarkItems while the bar was hidden",
  );
  assert(
    global.$("btn-bookmark").classList.contains("is-active"),
    "the post-unlock star says a stored bookmark is not bookmarked",
  );
});

check("the manager panel carries panel-modal as well as panel-wide", () => {
  // panel-wide only widens; every other card property (fixed overlay,
  // position, max-height, scrolling, background) comes from panel-modal.
  const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  const at = html.indexOf('id="bookmarks-panel"');
  assert(at !== -1, "#bookmarks-panel is missing from index.html");
  const tag = html.slice(
    html.lastIndexOf("<section", at),
    html.indexOf(">", at),
  );
  assert(
    /\bpanel-modal\b/.test(tag) && /\bpanel-wide\b/.test(tag),
    "the manager must carry BOTH panel-modal and panel-wide, got: " + tag,
  );
});

check("the panel is named the same thing the About page calls it", () => {
  // A feature with two names has two names to a user. The About page's entry
  // and the panel heading drifted apart the moment the About entry was
  // written ("Bookmark Manager" there, "Bookmarks" on the panel), which also
  // collided with the Library panel's own "Bookmarks and download records".
  // Pinned in both directions so neither side can be renamed alone.
  const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  // The PANEL is "Library" now; "Bookmark Manager" names the bookmarks view
  // inside it, and that is the name the About page carries. So the heading
  // compared here is the view's, not the panel's.
  const at = html.indexOf('id="bmm-bookmarks-top"');
  assert(at !== -1, "#bmm-bookmarks-top is missing");
  const heading = /<h3[^>]*>([^<]+)<\/h3>/.exec(html.slice(at, at + 500));
  assert(heading, "the bookmarks view has no <h3> heading");
  const shown = heading[1].trim();
  const about = fs.readFileSync(
    path.join(root, "crates/app/src/about.rs"),
    "utf8",
  );
  const lead = /const F_BOOKMARKS: Feature = \(\s*"([^"]+)"/.exec(about);
  assert(
    lead,
    "about.rs has no F_BOOKMARKS entry; the manager is a user-visible panel " +
      "and the About page is meant to name it",
  );
  assert(
    shown === lead[1],
    'the panel heading is "' +
      shown +
      '" but the About page calls it "' +
      lead[1] +
      '". One feature, one name.',
  );
});

check("the name and address cannot be squeezed to nothing", () => {
  // A LAYOUT regression this harness cannot see: the DOM stub has no layout
  // engine, so every row looked correct while rendering as a tile and five
  // buttons with no visible bookmark. `.bmm-meta` was `flex: 1; min-width: 0`
  // beside `flex: none` siblings that refuse to shrink, so it collapsed to
  // zero width. Checked in the stylesheet instead, which is where the fault
  // was; caught originally by looking at a screenshot.
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  const at = css.indexOf(".bmm-meta {");
  assert(at !== -1, ".bmm-meta has no rule in chrome.css");
  const rule = css.slice(at, css.indexOf("}", at));
  assert(
    !/min-width:\s*0\b/.test(rule),
    ".bmm-meta has min-width: 0 again, which lets the bookmark's name and " +
      "address collapse to zero width beside the unshrinkable button row",
  );
  assert(
    /min-width:\s*\d/.test(rule),
    ".bmm-meta needs a non-zero min-width floor so the name always shows",
  );
});

check("opening it renders the pinned row, sidebar and list", async () => {
  await openManager();
  assert(
    global.$("bookmarks-panel").hidden === false,
    "Manage bookmarks did not open the manager panel",
  );
  assert(
    rowTitles().length === 3,
    "expected 3 rows, got " + rowTitles().length,
  );
  assert(
    quickNames().indexOf("Alpha") >= 0,
    "the pinned bookmark is not in Quick Access",
  );
  assert(sidebarByLabel("chem"), "the chem folder is missing from the sidebar");
  assert(sidebarByLabel("Unfiled"), "the Unfiled entry is missing");
});

check("Snapshots is counted, dated and newest first without leaking metadata", async () => {
  const snapshots = sidebarByLabel("Snapshots");
  assert(snapshots, "the Snapshots built-in view is missing from the sidebar");
  const count = kids(snapshots).find(
    (c) => c.className === "bmm-side-count",
  );
  assert(count && count.textContent === "3", "Snapshots should have count 3");

  snapshots._fire("click");
  await flush();
  assert(
    rowTitles().join(",") === "Gamma,Alpha",
    "Snapshots must be newest first; got " + rowTitles().join(","),
  );
  for (const expected of [
    ["Gamma", 1800000000],
    ["Alpha", 1700000000],
  ]) {
    const line = rowSnapshotLine(rowByTitle(expected[0]));
    assert(line, expected[0] + " has no snapshot date line");
    assert(
      line.textContent ===
        "Page snapshot from " + new Date(expected[1] * 1000).toLocaleString(),
      expected[0] + " has the wrong snapshot date line: " + line.textContent,
    );
  }
  assert(!rowByTitle("Beta"), "a bookmark without a digest entered Snapshots");

  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
  assert(
    !rowSnapshotLine(rowByTitle("Beta")),
    "a row without a digest rendered a snapshot date line",
  );
  assert(
    !rowSnapshotLine(rowByTitle("Alpha")),
    "snapshot metadata leaked into a non-Snapshots view",
  );
});

check("Snapshots pins its caption and exposes a bookmark-targeted check", async () => {
  const snapshots = sidebarByLabel("Snapshots");
  snapshots._fire("click");
  await flush();
  const caption = global.$("bmm-snapshots-caption");
  assert(caption && caption.hidden === false, "Snapshots caption is not pinned in the view");
  assert(
    String(caption.textContent).replace(/\s+/g, " ").trim() ===
      "A snapshot keeps hashes, visible text, and a picture of the page when capture succeeds. Check for changes compares the page as it is now with what you saved.",
    "Snapshots caption copy drifted: " + caption.textContent,
  );
  const gamma = rowByTitle("Gamma");
  const gammaMeta = kids(gamma).find((child) => child.className === "bmm-meta");
  const picker = kids(gammaMeta).find(
    (child) => child.className === "bmm-snapshot-picker",
  );
  assert(picker && kids(picker).length === 2, "the row does not expose both Gamma saves");
  assert(picker.value === "snapshot-b3-0", "the newest save is not selected by default");
  picker.value = "snapshot-b3-1";
  picker._fire("change");
  await flush();
  const checkButton = rowAction(rowByTitle("Gamma"), "Check for changes");
  assert(checkButton, "a Snapshots row has no Check for changes control");
  posted.length = 0;
  checkButton._fire("click");
  await flush();
  const call = posted.find((entry) => entry.cmd === "integrity_check_bookmark");
  assert(call, "Check for changes did not use the bookmark-targeted command");
  assert(call.args.id === "b3", "the row sent the wrong bookmark id");
  assert(
    call.args.snapshot_id === "snapshot-b3-1",
    "the comparison did not use the saved snapshot chosen on the row",
  );
  global.window.__rb_event({
    event: "bookmark_check_result",
    data: {
      bookmark_id: "b3",
      snapshot_id: "snapshot-b3-1",
      verdict: "text_differs",
      similarity: 0.75,
      text_comparison: {
        available: true,
        removed: ["Old sentence."],
        added: ["New sentence."],
        output_trimmed: false,
        saved_text_trimmed: false,
        current_text_trimmed: false,
      },
    },
  });
  await flush();
  const rendered = descendantText(rowByTitle("Gamma"));
  assert(
    rendered.includes("Removed") &&
      rendered.includes("Old sentence.") &&
      rendered.includes("Added") &&
      rendered.includes("New sentence."),
    "the row did not render its added and removed passages inline: " + rendered,
  );
});

check("Snapshot rows share one staged viewer and release it on close", async () => {
  sidebarByLabel("Snapshots")._fire("click");
  await flush();
  let gamma = rowByTitle("Gamma");
  let meta = kids(gamma).find((child) => child.className === "bmm-meta");
  let picker = kids(meta).find(
    (child) => child.className === "bmm-snapshot-picker",
  );
  picker.value = "snapshot-b3-0";
  picker._fire("change");
  await flush();
  gamma = rowByTitle("Gamma");
  posted.length = 0;
  let view = rowAction(gamma, "View picture");
  assert(view, "a picture-backed snapshot has no View picture control");
  view._fire("click");
  await flush();
  let slotCalls = posted
    .filter((call) =>
      ["archive_picture_clear", "snapshot_picture_stage"].includes(call.cmd),
    )
    .map((call) => call.cmd);
  assert(
    slotCalls.join(",") === "archive_picture_clear,snapshot_picture_stage",
    "first snapshot did not clear then stage exactly one slot: " + slotCalls,
  );
  assert(stagedPicture === "snapshot-b3-0", "the wrong snapshot was staged");
  assert(
    global.$("recall-preview-img").getAttribute("src") ===
      "/archive-picture/41.png",
    "the shared viewer did not receive the staged token",
  );
  assert(global.$("recall-preview").hidden === false, "the shared viewer stayed hidden");

  meta = kids(gamma).find((child) => child.className === "bmm-meta");
  picker = kids(meta).find(
    (child) => child.className === "bmm-snapshot-picker",
  );
  picker.value = "snapshot-b3-1";
  picker._fire("change");
  await flush();
  gamma = rowByTitle("Gamma");
  posted.length = 0;
  rowAction(gamma, "View picture")._fire("click");
  await flush();
  slotCalls = posted
    .filter((call) =>
      ["archive_picture_clear", "snapshot_picture_stage"].includes(call.cmd),
    )
    .map((call) => call.cmd);
  assert(
    slotCalls.join(",") === "archive_picture_clear,snapshot_picture_stage",
    "replacement did not clear before staging: " + slotCalls,
  );
  assert(stagedPicture === "snapshot-b3-1", "the replacement was not staged");
  assert(
    global.$("recall-preview-scope").hidden === false,
    "the stored viewport scope was not shown",
  );

  global.$("btn-library")._fire("click");
  await flush();
  assert(stagedPicture === null, "closing Library left a decrypted slot staged");
  assert(global.$("recall-preview").hidden === true, "closing Library left the viewer visible");
  assert(
    global.$("recall-preview-img").getAttribute("src") == null,
    "closing Library left the decoded image src attached",
  );
  global.$("btn-library")._fire("click");
  await flush();
});

check("a picture-less snapshot says unavailable instead of drawing a blank page", async () => {
  sidebarByLabel("Snapshots")._fire("click");
  await flush();
  const alpha = rowByTitle("Alpha");
  assert(
    descendantText(alpha).includes("Picture unavailable."),
    "the legacy/picture-less row did not say the picture is unavailable",
  );
  assert(
    !rowAction(alpha, "View picture"),
    "a picture-less snapshot offered an empty viewer",
  );
});

check("Snapshots keeps every row-check refusal distinct", async () => {
  const snapshots = sidebarByLabel("Snapshots");
  snapshots._fire("click");
  await flush();

  const expected = [
    ["not_bookmarked", "Bookmark this page first. Snapshots are kept with the bookmark."],
    ["no_snapshot", "No snapshot saved for this page yet."],
    ["not_unlocked", "Vault is locked"],
  ];
  try {
    for (const [code, copy] of expected) {
      integrityError = code;
      rowAction(rowByTitle("Gamma"), "Check for changes")._fire("click");
      await flush();
      const rendered = descendantText(rowByTitle("Gamma"));
      assert(
        rendered.includes(copy),
        code + " did not keep its own refusal on the row: " + rendered,
      );
    }

    integrityError = null;
    rowAction(rowByTitle("Gamma"), "Check for changes")._fire("click");
    await flush();
    global.window.__rb_event({
      event: "bookmark_check_error",
      data: {
        bookmark_id: "b3",
        snapshot_id: "snapshot-b3-1",
        code: "fetch_failed",
      },
    });
    await flush();
    const rendered = descendantText(rowByTitle("Gamma"));
    assert(
      rendered.includes(
        "The page could not be fetched for comparison. Check the connection and try again.",
      ),
      "the asynchronous fetch failure was not rendered distinctly: " + rendered,
    );
  } finally {
    integrityError = null;
  }
});

check("the locked Library fetches and reveals no snapshot data or control", async () => {
  // First prove a lock tears down a picture already decoded on screen, not
  // merely that a newly opened locked panel declines to fetch one.
  rowAction(rowByTitle("Gamma"), "View picture")._fire("click");
  await flush();
  assert(stagedPicture !== null, "locked test never staged its plant picture");
  storeOpen = false;
  global.window.__rb_event({ event: "vault_locked", data: {} });
  await flush();
  assert(stagedPicture === null, "vault lock left a decrypted snapshot staged");
  assert(global.$("recall-preview").hidden === true, "vault lock left its picture visible");
  assert(
    global.$("recall-preview-img").getAttribute("src") == null,
    "vault lock retained the decoded snapshot src",
  );

  // Close the currently open panel, then reopen against a locked status.
  global.$("btn-library")._fire("click");
  posted.length = 0;
  global.$("btn-library")._fire("click");
  await flush();
  assert(
    posted[0] && posted[0].cmd === "store_status",
    "locked Library must ask store_status first; got " +
      posted.map((entry) => entry.cmd).join(","),
  );
  assert(
    !posted.some((entry) =>
      [
        "bookmark_list",
        "download_list",
        "shelf_list",
        "integrity_check_bookmark",
        "snapshot_picture_stage",
      ].includes(entry.cmd),
    ),
    "locked Library fetched vault data; got " +
      posted.map((entry) => entry.cmd).join(","),
  );
  assert(global.$("library-content").hidden === true, "locked Library content is visible");
  assert(global.$("library-locked").hidden === false, "locked notice is hidden");
  assert(listRows().length === 0, "locked Library retained snapshot rows");
  assert(global.$("bmm-snapshots-caption").hidden === true, "locked Library revealed the caption");
  assert(
    !listRows().some((row) => rowAction(row, "Check for changes")),
    "locked Library revealed a snapshot check control",
  );

  global.$("btn-library")._fire("click");
  storeOpen = true;
  global.$("btn-library")._fire("click");
  await flush();
  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
});

check("Snapshots explains the empty view when no bookmark has a digest", async () => {
  const before = store.bookmarks.map((b) => ({
    id: b.id,
    has_digest: b.has_digest,
    digest_recorded_at: b.digest_recorded_at,
  }));
  try {
    for (const bookmark of store.bookmarks) bookmark.has_digest = false;
    // Close and reopen to drive the real Library refresh path and replace
    // chrome.js's bookmarkItems snapshot from bookmark_list.
    global.$("btn-library")._fire("click");
    global.$("btn-library")._fire("click");
    await flush();

    const snapshots = sidebarByLabel("Snapshots");
    const count = kids(snapshots).find(
      (c) => c.className === "bmm-side-count",
    );
    assert(count && count.textContent === "0", "empty Snapshots count is not 0");
    snapshots._fire("click");
    await flush();
    assert(listRows().length === 0, "empty Snapshots rendered bookmark rows");
    assert(global.$("bmm-empty").hidden === false, "empty note stayed hidden");
    assert(
      global.$("bmm-empty").textContent ===
        "No snapshots yet. Open Integrity, then save one in Page integrity.",
      "wrong Snapshots empty state: " + global.$("bmm-empty").textContent,
    );
  } finally {
    for (const saved of before) {
      const bookmark = store.bookmarks.find((b) => b.id === saved.id);
      if (!bookmark) continue;
      bookmark.has_digest = saved.has_digest;
      bookmark.digest_recorded_at = saved.digest_recorded_at;
    }
    if (!global.$("bookmarks-panel").hidden)
      global.$("btn-library")._fire("click");
    global.$("btn-library")._fire("click");
    await flush();
    sidebarByLabel("All bookmarks")._fire("click");
    await flush();
  }
});

check("QUICK ACCESS SURVIVES a sidebar folder filter", async () => {
  // Alpha is pinned and is in "chem". Select "reading", which does NOT
  // contain it: the list must narrow, the pinned row must not.
  sidebarByLabel("reading")._fire("click");
  await flush();
  assert(
    rowTitles().join(",") === "Gamma",
    "selecting reading should show only Gamma, got " + rowTitles().join(","),
  );
  assert(
    quickNames().indexOf("Alpha") >= 0,
    "Quick Access lost its pinned bookmark when a folder was selected. It is " +
      "pinned at the top precisely so it is always reachable.",
  );
});

check("QUICK ACCESS SURVIVES a search that matches nothing", async () => {
  global.$("bmm-search")._fire("input", { target: { value: "zzzznomatch" } });
  await flush();
  assert(listRows().length === 0, "the search should have emptied the list");
  assert(
    quickNames().indexOf("Alpha") >= 0,
    "Quick Access was filtered away by the search box",
  );
  // Put it back for the checks that follow.
  global.$("bmm-search")._fire("input", { target: { value: "" } });
  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
});

check("the Folders popover files through the ATOMIC command", async () => {
  posted.length = 0;
  const row = rowByTitle("Beta");
  assert(row, "the Beta row is missing");
  rowAction(row, "Folders")._fire("click");
  await flush();
  const pop = popover();
  assert(pop, "the Folders popover did not open");
  // Tick the "chem" checkbox.
  const chemRow = kids(pop).find(
    (r) =>
      r.className === "bmm-pop-row" &&
      kids(r).some((c) => c.textContent === "chem"),
  );
  assert(chemRow, "the chem folder is not offered in the popover");
  const box = kids(chemRow).find((c) => c._has("change"));
  box.checked = true;
  box._fire("change");
  await flush();

  const filed = posted.filter((p) => p.cmd === "bookmark_folder_file");
  assert(filed.length === 1, "expected one file call, got " + filed.length);
  assert(
    filed[0].args.id === "b2" && norm(filed[0].args.folder) === "chem",
    "wrong file arguments: " + JSON.stringify(filed[0].args),
  );
  assert(
    !posted.some((p) => p.cmd === "bookmark_tags_set"),
    "filing went through the whole-list bookmark_tags_set, which lets two " +
      "quick toggles overwrite each other",
  );
  assert(
    store.bookmarks.find((b) => b.id === "b2").tags.includes("chem"),
    "Beta was not actually filed into chem",
  );
});

check("Pin puts a bookmark into Quick Access", async () => {
  posted.length = 0;
  const row = rowByTitle("Gamma");
  rowAction(row, "Pin")._fire("click");
  await flush();
  const pinned = posted.filter((p) => p.cmd === "bookmark_quick_access_set");
  assert(pinned.length === 1, "expected one pin call, got " + pinned.length);
  assert(
    pinned[0].args.id === "b3" && pinned[0].args.on === true,
    "wrong pin arguments: " + JSON.stringify(pinned[0].args),
  );
  assert(
    quickNames().indexOf("Gamma") >= 0,
    "Gamma did not appear in Quick Access after pinning",
  );
});

check("manual positions precede unordered pins without scrambling them", async () => {
  const alpha = store.bookmarks.find((b) => b.id === "b1");
  const gamma = store.bookmarks.find((b) => b.id === "b3");
  alpha.quick_access_order = null;
  gamma.quick_access_order = 7;
  global.$("btn-library")._fire("click");
  global.$("btn-library")._fire("click");
  await flush();
  assert(
    quickNames().join(",") === "Gamma,Alpha",
    "an ordered pin did not precede an unordered one",
  );

  // With neither position present, their underlying bookmark-list order is
  // the tie breaker. This is the exact pre-field behavior a first drag sees.
  gamma.quick_access_order = null;
  global.$("btn-library")._fire("click");
  global.$("btn-library")._fire("click");
  await flush();
  assert(
    quickNames().join(",") === "Alpha,Gamma",
    "unordered pins did not retain their existing list order",
  );
});

check("drag reorders every Quick Access id once and survives a reload", async () => {
  posted.length = 0;
  const writesBefore = store.quickAccessWrites;
  const alpha = quickTile("Alpha");
  const gamma = quickTile("Gamma");
  assert(alpha && gamma, "setup: both pinned tiles must be rendered");
  assert(
    alpha.getAttribute("draggable") === "true" &&
      alpha._has("dragstart") &&
      gamma._has("dragover") &&
      gamma._has("drop"),
    "Quick Access drag handlers are not wired to draggable tiles",
  );

  const carried = [];
  const dataTransfer = {
    effectAllowed: "",
    dropEffect: "",
    setData(type, value) {
      carried.push([type, value]);
    },
  };
  alpha._fire("dragstart", { dataTransfer });
  gamma._fire("dragover", { clientX: 1, dataTransfer });
  assert(
    quickNames().join(",") === "Gamma,Alpha",
    "dragover did not preview the tile order; got " + quickNames().join(","),
  );
  gamma._fire("drop", { clientX: 1, dataTransfer });
  await flush();

  const calls = posted.filter(
    (p) => p.cmd === "bookmark_quick_access_reorder",
  );
  assert(
    calls.length === 1,
    "one drop must send one reorder, got " + calls.length,
  );
  assert(
    calls[0].args.ids.join(",") === "b3,b1",
    "drop did not send the full visible order: " + JSON.stringify(calls[0].args),
  );
  assert(
    store.quickAccessWrites === writesBefore + 1,
    "one drop must persist exactly once",
  );
  assert(
    carried.every(([, value]) => value !== "b1" && value !== "b3"),
    "an internal bookmark id rode in dataTransfer",
  );
  assert(
    store.bookmarks.find((b) => b.id === "b3").quick_access_order === 0 &&
      store.bookmarks.find((b) => b.id === "b1").quick_access_order === 1,
    "the first drag did not assign orders to every pinned bookmark",
  );

  // Close/reopen takes the real bookmark_list reload path. The order must
  // return from the fake store rather than survive merely as moved DOM nodes.
  global.$("btn-library")._fire("click");
  global.$("btn-library")._fire("click");
  await flush();
  assert(
    quickNames().join(",") === "Gamma,Alpha",
    "the persisted order did not survive a manager reload",
  );

  // The filter view shares that same order even if the general sort control
  // asks for title order (which would put Alpha first).
  sidebarByLabel("Quick Access")._fire("click");
  global.$("bmm-sort")._fire("change", { target: { value: "title" } });
  await flush();
  assert(
    rowTitles().join(",") === "Gamma,Alpha",
    "the Quick Access filter disagrees with its tile row: " +
      rowTitles().join(","),
  );
  sidebarByLabel("All bookmarks")._fire("click");
  global.$("bmm-sort")._fire("change", { target: { value: "newest" } });
  await flush();
});

check("an unknown reorder id is bad_args and persists nothing", async () => {
  const orderBefore = store.bookmarks.map((b) => [b.id, b.quick_access_order]);
  const namesBefore = quickNames().join(",");
  const writesBefore = store.quickAccessWrites;
  const id = 900001;
  global.window.ipc.postMessage(
    JSON.stringify({
      id,
      cmd: "bookmark_quick_access_reorder",
      args: { ids: ["b3", "missing"] },
    }),
  );
  await flush();
  const reply = replies.find((candidate) => candidate.id === id);
  assert(
    reply && reply.ok === false && reply.error === "bad_args",
    "the reorder arm did not refuse the unknown id with bad_args",
  );
  assert(
    store.quickAccessWrites === writesBefore &&
      JSON.stringify(store.bookmarks.map((b) => [b.id, b.quick_access_order])) ===
        JSON.stringify(orderBefore),
    "a refused reorder changed or persisted bookmark order",
  );

  // Force another store-backed render so unchanged DOM cannot hide a write.
  global.$("btn-library")._fire("click");
  global.$("btn-library")._fire("click");
  await flush();
  assert(
    quickNames().join(",") === namesBefore,
    "the refused order appeared after a reload",
  );
});

check("focused tiles reorder with Left and Right arrow keys", async () => {
  posted.length = 0;
  const writesBefore = store.quickAccessWrites;
  const gamma = quickTile("Gamma");
  assert(gamma && gamma._has("keydown"), "the focused tile has no key handler");
  gamma._fire("keydown", { key: "ArrowRight" });
  await flush();
  const calls = posted.filter(
    (p) => p.cmd === "bookmark_quick_access_reorder",
  );
  assert(calls.length === 1, "one arrow move must send one complete reorder");
  assert(
    calls[0].args.ids.join(",") === "b1,b3",
    "ArrowRight sent the wrong full order: " + JSON.stringify(calls[0].args),
  );
  assert(
    store.quickAccessWrites === writesBefore + 1 &&
      quickNames().join(",") === "Alpha,Gamma",
    "the keyboard reorder was not persisted and rendered",
  );
});

check("adding by hand sends the typed address to bookmark_add", async () => {
  posted.length = 0;
  global.$("bmm-add-url").value = "example.com";
  global.$("bmm-add-title").value = "Example";
  global.$("bmm-add")._fire("click");
  await flush();
  const adds = posted.filter((p) => p.cmd === "bookmark_add");
  assert(adds.length === 1, "expected one add call, got " + adds.length);
  assert(
    adds[0].args.url === "example.com",
    "the typed address must reach Rust as typed, so the allowlist there " +
      "decides; got " +
      JSON.stringify(adds[0].args),
  );
  assert(
    rowTitles().indexOf("Example") >= 0,
    "the new bookmark did not appear after the refresh",
  );
});

check("an empty address is refused before any IPC", async () => {
  posted.length = 0;
  global.$("bmm-add-url").value = "   ";
  global.$("bmm-add")._fire("click");
  await flush();
  assert(
    !posted.some((p) => p.cmd === "bookmark_add"),
    "an empty address must not reach the backend",
  );
  assert(
    global.$("bmm-add-error").hidden === false,
    "an empty address must show the inline error",
  );
});

check("opening a bookmark closes the panel over the page", async () => {
  // The panel is registered as "library"; two guards still tested for
  // "bookmarks" after the merge and were therefore dead, so Open loaded the
  // page behind a panel that stayed on top of it. The gate asserted the IPC
  // fired and never that the panel got out of the way.
  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
  assert(
    global.$("bookmarks-panel").hidden === false,
    "setup: the panel should be open",
  );
  const row = rowByTitle("Alpha");
  assert(row, "the Alpha row is missing");
  rowAction(row, "Open")._fire("click");
  await flush();
  assert(
    posted.some((p) => p.cmd === "bookmark_open"),
    "Open did not ask to open the bookmark",
  );
  assert(
    global.$("bookmarks-panel").hidden === true,
    "the panel stayed over the page it just opened",
  );
});

check("Downloads and Tab Shelf are views of this same panel", async () => {
  // The Library used to be a separate panel with three tabs. If a later
  // change loses these two sidebar entries, the only way to reach downloads
  // or shelved tabs goes with them and nothing else would notice.
  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
  const dl = sidebarByLabel("Downloads");
  const sh = sidebarByLabel("Tab Shelf");
  assert(dl, "Downloads is missing from the sidebar");
  assert(sh, "Tab Shelf is missing from the sidebar");

  dl._fire("click");
  await flush();
  assert(
    global.$("bmm-view-downloads").hidden === false,
    "choosing Downloads did not show the downloads view",
  );
  assert(
    global.$("bmm-view-bookmarks").hidden === true,
    "the bookmarks view stayed on screen under the downloads view",
  );
  assert(
    global.$("bmm-bookmarks-top").hidden === true,
    "the bookmarks search and Quick Access row still show while looking at " +
      "downloads, where they mean nothing",
  );

  sh._fire("click");
  await flush();
  assert(
    global.$("bmm-view-shelves").hidden === false,
    "choosing Tab Shelf did not show the shelves view",
  );

  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
  assert(
    global.$("bmm-view-bookmarks").hidden === false,
    "going back to bookmarks did not restore the bookmarks view",
  );
});

check("deleting a folder keeps its bookmarks", async () => {
  const before = store.bookmarks.length;
  posted.length = 0;
  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
  const cards = kids(global.$("bmm-cards")).filter(
    (c) => c.className === "bmm-card",
  );
  const chemCard = cards.find((c) => {
    const head = kids(c).find((x) => x.className === "bmm-card-head");
    return (
      head && kids(head).some((s) => /^chem \(/.test(String(s.textContent)))
    );
  });
  assert(chemCard, "the chem folder card is missing");
  const actions = kids(chemCard).find(
    (c) => c.className === "bmm-card-actions",
  );
  kids(actions)
    .find((b) => b.dataset.action === "delete-folder")
    ._fire("click");
  await flush();
  global.$("confirm-yes")._fire("click");
  await flush();
  assert(
    posted.some((p) => p.cmd === "bookmark_folder_delete"),
    "no delete call was made",
  );
  assert(
    store.bookmarks.length === before,
    "a folder delete destroyed bookmarks; it must only unfile them",
  );
});

check("Delete all bookmarks ASKS FIRST and cancelling changes nothing", async () => {
  // The whole feature is the question. Cancel must leave the store alone --
  // there is no undo and no bookmark export to restore from.
  posted.length = 0;
  const before = store.bookmarks.length;
  const beforeFolders = store.folders.length;
  assert(before > 0 && beforeFolders > 0, "fixture has nothing to delete");
  global.$("bmm-delete-all")._fire("click");
  await flush();
  const text = String(global.$("confirm-text").textContent || "");
  assert(
    /permanently/i.test(text),
    "the confirmation must say the word permanently; got: " + text,
  );
  assert(
    /cannot be undone/i.test(text),
    "the confirmation must say it cannot be undone; got: " + text,
  );
  assert(
    text.includes(String(before)) && text.includes(String(beforeFolders)),
    "the confirmation must name what is about to be lost; got: " + text,
  );
  // Cancel.
  global.$("confirm-cancel")._fire("click");
  await flush();
  assert(
    !posted.some((p) => p.cmd === "bookmarks_delete_all"),
    "cancelling still sent the delete",
  );
  assert(
    store.bookmarks.length === before && store.folders.length === beforeFolders,
    "cancelling destroyed data",
  );
});

check("Delete all bookmarks empties the manager once confirmed", async () => {
  posted.length = 0;
  assert(store.bookmarks.length > 0, "fixture has nothing to delete");
  global.$("bmm-delete-all")._fire("click");
  await flush();
  global.$("confirm-yes")._fire("click");
  await flush();
  const calls = posted.filter((p) => p.cmd === "bookmarks_delete_all");
  assert(calls.length === 1, "expected one delete call, got " + calls.length);
  assert(
    !calls[0].args || Object.keys(calls[0].args).length === 0,
    "bookmarks_delete_all takes no arguments; got " +
      JSON.stringify(calls[0].args),
  );
  assert(store.bookmarks.length === 0, "bookmarks survived the delete");
  assert(store.folders.length === 0, "folders survived the delete");
  // It empties the manager and nothing else: this command must never be the
  // one that touches shelved tabs or download records.
  assert(
    !posted.some(
      (p) => /shelf|download|archive/i.test(p.cmd) && p.cmd !== "bookmark_list",
    ),
    "deleting bookmarks reached another feature's data",
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
    console.error("\nBOOKMARKS-MANAGER GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nBOOKMARKS MANAGER OK");
})();
