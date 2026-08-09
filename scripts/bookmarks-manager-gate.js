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
    },
    {
      id: "b2",
      url: "https://beta.test/",
      title: "Beta",
      tags: [],
      quick_access: false,
    },
    {
      id: "b3",
      url: "https://gamma.test/",
      title: "Gamma",
      tags: ["reading"],
      quick_access: false,
    },
  ],
  folders: ["chem", "reading"],
};
const posted = [];

function listReply() {
  return {
    items: store.bookmarks.map((b) => ({
      id: b.id,
      url: b.url,
      title: b.title,
      created_at: 0,
      tags: b.tags.slice(),
      quick_access: b.quick_access,
      has_digest: false,
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
      return { ok: true, data: { open: true, digests_ready: true } };
    case "shelf_list":
      return { ok: true, data: { items: [] } };
    case "download_list":
      return { ok: true, data: { items: [] } };
    case "bookmarks_bar_get":
      return { ok: true, data: { shown: false } };
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
      return { ok: true, data: { id: args.id, on: args.on, changed } };
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

check("Downloads and Sets of tabs are views of this same panel", async () => {
  // The Library used to be a separate panel with three tabs. If a later
  // change loses these two sidebar entries, the only way to reach downloads
  // or set-aside tabs goes with them and nothing else would notice.
  sidebarByLabel("All bookmarks")._fire("click");
  await flush();
  const dl = sidebarByLabel("Downloads");
  const sh = sidebarByLabel("Sets of tabs");
  assert(dl, "Downloads is missing from the sidebar");
  assert(sh, "Sets of tabs is missing from the sidebar");

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
    "choosing Sets of tabs did not show the shelves view",
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
    .find((b) => b.textContent === "Delete folder")
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
