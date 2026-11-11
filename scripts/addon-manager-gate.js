// Execute the Add-ons UI (addons.js) against a small DOM built from the real
// markup, with hostile metadata: the catalog cards, each add-on's own panel and
// toolbar button, the Customize choice, and saved data with no panel. The
// surfaces are lean on purpose, and a word budget holds them there.
const fs = require("fs"), vm = require("vm"), assert = require("assert/strict");
const html = fs.readFileSync("crates/app/src/chrome/index.html", "utf8");
const script = fs.readFileSync("crates/app/src/chrome/addons.js", "utf8");
const nodes = new Map(), messages = new Map(), calls = [], htmlWrites = [], panelsRegistered = [], members = [];
const walk = (el) => [el, ...el.children.flatMap(walk)];
class Element {
  constructor(id = "", tag = "div") {
    this.id = id; this.tagName = tag.toUpperCase(); this.textContent = ""; this.value = ""; this.hidden = false;
    this.disabled = false; this.checked = false; this.children = []; this.dataset = {}; this.listeners = {}; this.attrs = {};
    this.parentNode = null; this.className = "";
  }
  set innerHTML(value) { htmlWrites.push(value); }
  appendChild(el) { if (el.parentNode) el.parentNode.removeChild(el); this.children.push(el); el.parentNode = this; return el; }
  insertBefore(el, ref) {
    if (el.parentNode) el.parentNode.removeChild(el);
    const at = this.children.indexOf(ref);
    this.children.splice(at < 0 ? this.children.length : at, 0, el); el.parentNode = this; return el;
  }
  removeChild(el) { this.children = this.children.filter(c => c !== el); el.parentNode = null; return el; }
  replaceChildren(...els) { for (const c of this.children) c.parentNode = null; this.children = []; for (const e of els) this.appendChild(e); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  hasAttribute(k) { return k in this.attrs; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  querySelectorAll() { return walk(this).filter(el => el.dataset.addonAction); }
  querySelector(selector) { const match = selector.match(/data-msg="([^"]+)"/); return match ? messages.get(match[1]) || null : null; }
  click() { if (!this.disabled && this.listeners.click) this.listeners.click(); }
  change() { if (this.listeners.change) this.listeners.change(); }
}
for (const match of html.matchAll(/\bid="([^"]+)"/g)) nodes.set(match[1], new Element(match[1]));
for (const match of html.matchAll(/data-msg="(addon\.[^"]+)"[^>]*>([^<]*)</g)) {
  const el = new Element(); el.textContent = match[2].trim(); messages.set(match[1], el);
}
const body = new Element("body");
for (const id of ["addon-manager", "addon-orphans", "addon-operation-status", "addon-export-result", "addon-page-failures"]) {
  nodes.get("addon-controls").appendChild(nodes.get(id));
}
for (const id of ["addon-catalog-line", "addon-known-list", "addon-whats-sent-host"]) nodes.get("addon-manager").appendChild(nodes.get(id));
for (const match of html.matchAll(/<button[^>]*data-addon-action="([^"]+)"[^>]*>/g)) {
  const button = new Element("", "button"); button.dataset.addonAction = match[1];
  nodes.get("addon-orphans").appendChild(button);
}
const toolbar = nodes.get("toolbar");
for (const id of ["btn-library", "group-tools", "btn-theme"]) toolbar.appendChild(nodes.get(id));
let confirmation = true, confirmationText = "", reply = null, refusal = null, fill, premiumChanged = () => {};
// The one-time banner's tour page refused (plan review H-1).
let pageRefusal = null;
// Real IPC answers a turn later; some checks run both ways.
let slowReplies = false;
const settleLate = () => new Promise((resolve) => setTimeout(resolve, 5));
const openPanels = new Set();
const named = (over = {}) => ({ id: "text-pages", name: "Test pages", summary: "Pages over any site.", size: 304167,
  available: "2.0.0", installed: false, version: null, rollback: null, update: false, ...over });
const base = { visible: false, unlocked: true, premium: false, pending: null, last: null, known: [named()],
  catalog: { held: true, fetched: false, error: null }, toolbar_hidden: [] };
const window = { __rb: {
  request: async (cmd, args) => {
    calls.push({cmd, args});
    const answer = reply || base;
    if (slowReplies) await new Promise((resolve) => setTimeout(resolve, 0));
    if (refusal && cmd === "addon_manager_action") throw new Error(refusal);
    if (pageRefusal && cmd === "site_page_open") throw new Error(pageRefusal);
    return answer;
  },
  askConfirm: async (text) => { confirmationText = text; return confirmation; },
  rebuildOnLocaleFill: (fn) => { fill = fn; },
  registerPanel: (name, spec) => { panelsRegistered.push({name, spec}); spec.button.addEventListener("click", () => openPanels.add(name)); },
  addGroupMember: (g, id) => { members.push([g, id]); return true; },
  isPanelOpen: (name) => openPanels.has(name),
  premiumLockNote: () => "PREMIUM LOCK NOTE",
  openVault: () => calls.push({cmd: "open_vault"}),
  openAddons: () => { calls.push({cmd: "open_addons"}); openPanels.clear(); openPanels.add("addons"); },
  onPremiumChange: (fn) => { premiumChanged = fn; },
}};
const document = {
  getElementById: (id) => nodes.get(id),
  createElement: (tag) => new Element("", tag),
  createElementNS: (_ns, tag) => new Element("", tag),
  createTextNode: (value) => { const el = new Element("", "#text"); el.textContent = value; return el; },
  body,
};
const flush = async () => { for (let i = 0; i < 10; ++i) await Promise.resolve(); };
const card = (id = "text-pages") => nodes.get("addon-known-list").children.find(el => el.dataset.addonId === id);
const cardPart = (rowAction, id) => walk(card(id)).find(el => el.dataset.rowAction === rowAction);
const panel = (id = "text-pages") => body.children.find(el => el.id === "addon-panel-" + id);
const part = (className, id) => walk(panel(id)).find(el => el.className === className);
const pbutton = (action, id) => walk(panel(id)).find(b => b.dataset.panelAction === action);
const tbutton = (id = "text-pages") => toolbar.children.find(el => el.id === "btn-addon-" + id);
const orphanButton = (action) => nodes.get("addon-orphans").children.find(b => b.dataset.addonAction === action);
const choice = (id = "text-pages") => walk(nodes.get("addon-toolbar-choices")).find(el => el.id === "addon-shown-" + id);
const live = (state) => ({...base, visible: true, premium: true, ...state});
const actions = () => calls.map(c => c.args && c.args.action).filter(Boolean);
// Words a person sees without opening anything: every shown node's own text,
// outside a <details> (More, What's sent), hidden subtrees skipped.
function visibleWords(el) {
  if (el.hidden || el.tagName === "DETAILS") return 0;
  const own = el.children.length ? 0 : (el.textContent || "").split(/\s+/).filter(Boolean).length;
  return own + el.children.reduce((n, c) => n + visibleWords(c), 0);
}
function check(name, fn) {
  try { fn(); console.log("PASS " + name); }
  catch (error) { console.error("ADDON MANAGER GATE FAIL: " + name); throw error; }
}
(async () => {
  vm.runInNewContext(script, { window, document }, { filename: "addons.js" });
  await flush(); calls.length = 0;
  check("nothing shows or is built before launch", () => {
    assert.equal(nodes.get("addon-manager").hidden, true);
    assert.equal(nodes.get("addon-controls").hidden, true);
    assert.equal(panelsRegistered.length, 0);
    assert.equal(tbutton(), undefined);
    assert.equal(nodes.get("addon-toolbar-choices").hidden, true);
  });
  const hostile = '<img src=x onerror="throw 1"><b>name</b>';
  window.__addons.render(live({ known: [named({ name: hostile, summary: hostile })] }));
  check("metadata is text", () => {
    assert.equal(cardPart("panel").textContent, hostile);
    assert(walk(card()).some(el => el.textContent === hostile && el.className === "addon-row-summary"));
    assert.equal(part("addon-panel-name").textContent, hostile);
    assert.equal(htmlWrites.length, 0);
  });
  window.__addons.render(live({ known: [named(), { id: "no-name-addon", installed: true }] }));
  check("cards name add-ons from signed data and never show a raw id", () => {
    assert.equal(nodes.get("addon-known-list").children.length, 1);
    assert.equal(card("no-name-addon"), undefined);
    assert(!walk(card()).some(el => el.textContent.includes("text-pages")));
    assert(walk(card()).some(el => el.textContent === "Pages over any site."));
    assert(walk(card()).some(el => el.className === "addon-tag" && el.textContent === "297 KB"));
    assert.equal(cardPart("install").textContent, "Install");
  });
  check("each add-on gets its own panel, and its button joins Tools after Library", () => {
    assert.deepEqual(panelsRegistered.map(p => p.name), ["addon-text-pages"]);
    assert.equal(panelsRegistered[0].spec.el, panel());
    assert.equal(panelsRegistered[0].spec.button, tbutton());
    assert.deepEqual(members, [["tools", "btn-addon-text-pages"]]);
    assert.equal(tbutton().dataset.group, "tools");
    assert(tbutton().hasAttribute("data-addon-button"));
    assert.deepEqual(toolbar.children.map(el => el.id).slice(0, 3), ["btn-library", "btn-addon-text-pages", "group-tools"]);
    assert.equal(walk(tbutton()).find(el => el.className === "feature-label").textContent, "Test pages");
  });
  check("an add-on is checked in Customize by default", () => assert(tbutton().hasAttribute("data-shown")));
  window.__addons.render(live({ known: [named()] }));
  check("a second render builds nothing twice", () => {
    assert.equal(panelsRegistered.length, 1);
    assert.equal(body.children.filter(el => el.id === "addon-panel-text-pages").length, 1);
    assert.equal(toolbar.children.filter(el => el.id === "btn-addon-text-pages").length, 1);
  });
  cardPart("panel").click();
  check("a card's name opens that add-on's panel", () => assert(openPanels.has("addon-text-pages")));

  // The lean panel: one primary action at a time.
  window.__addons.render(live({ known: [named()] }));
  check("not installed: one primary button, Install <name>, and the download size", () => {
    assert.equal(pbutton("install").hidden, false);
    assert.equal(pbutton("install").textContent, "Install Test pages");
    assert.equal(pbutton("install").className, "as-primary");
    assert.equal(pbutton("install").disabled, false);
    for (const a of ["open", "update", "unlock"]) assert.equal(pbutton(a).hidden, true, a);
    assert.equal(part("addon-panel-meta").textContent, "Download size 297 KB");
    assert.equal(part("addon-tag").textContent, "Premium");
  });
  window.__addons.render(live({ premium: false, known: [named()] }));
  check("no Premium: Install disabled, the standard Premium note shown", () => {
    assert.equal(pbutton("install").disabled, true);
    assert.equal(part("addon-panel-state").textContent, "PREMIUM LOCK NOTE");
  });
  const installed = named({ installed: true, version: "1.0.0", available: "2.0.0", update: true, rollback: "0.9.0" });
  const counted = (state) => live({ known: [installed], last: { id: "", action: "refresh", data: { ids: ["text-pages"], pages: { "text-pages": 6 } } }, ...state });
  window.__addons.render(counted());
  check("installed: Open <name> is the primary button, Update beside it, pages and version in one line", () => {
    assert.equal(pbutton("open").hidden, false);
    assert.equal(pbutton("open").textContent, "Open Test pages");
    assert.equal(pbutton("open").className, "as-primary");
    assert.equal(pbutton("update").hidden, false);
    assert.equal(pbutton("update").textContent, "Update to 2.0.0");
    assert.equal(pbutton("install").hidden, true);
    assert.equal(part("addon-panel-meta").textContent, "6 pages saved · Version 1.0.0");
  });
  check("the default view stays lean: at most 20 words outside More", () => {
    const words = visibleWords(panel());
    assert(words <= 20, words + " words on screen");
  });
  check("export, delete, the earlier version, Remove and What's sent are under More", () => {
    const more = part("addon-panel-more");
    assert.equal(more.tagName, "DETAILS");
    for (const a of ["export", "delete", "rollback", "remove"]) assert(walk(more).includes(pbutton(a)), a);
    assert.equal(pbutton("rollback").textContent, "Use version 0.9.0");
    const sent = walk(more).find(el => el.className === "addon-whats-sent");
    assert(sent && sent.tagName === "DETAILS" && !sent.hasAttribute("open"));
    // Who receives what, in four short sentences; no host names.
    const note = sent.children[1].textContent;
    assert.match(note, /sends EdgeXene your Premium token and device ID/);
    assert.match(note, /through Cloudflare, which gets neither/);
    assert.match(note, /Both see your IP address/);
    assert.match(note, /What you write never leaves your device/);
    assert.doesNotMatch(note, /edgexene\.io|patanyx\.net/);
  });
  window.__addons.render(live({ known: [named({ ...installed, update: false })], last: { id: "", action: "refresh", data: { ids: ["text-pages"], pages: { "text-pages": 1 } } } }));
  check("one page reads as one page, and no update means no Update button", () => {
    assert.equal(part("addon-panel-meta").textContent, "1 page saved · Version 1.0.0");
    assert.equal(pbutton("update").hidden, true);
  });
  window.__addons.render(live({ known: [named({ ...installed, version: "0.9.0" })] }));
  check("the earlier version is not offered while it is the one in use", () => {
    assert.equal(pbutton("rollback").hidden, true);
    assert.equal(pbutton("update").hidden, false, "Update back to the newer version is still offered");
  });
  window.__addons.render(live({ premium: false, known: [installed] }));
  check("after Premium ends: Open still works, Update and the earlier version do not", () => {
    assert.equal(pbutton("open").disabled, false);
    assert.equal(pbutton("update").disabled, true);
    assert.equal(pbutton("rollback").disabled, true);
    assert.equal(pbutton("remove").disabled, false);
  });
  window.__addons.render(live({ unlocked: false, known: [installed] }));
  check("locked: Unlock Vault is the one primary button, Remove still allowed", () => {
    assert.equal(pbutton("unlock").hidden, false);
    assert.equal(pbutton("unlock").className, "as-primary");
    assert.equal(pbutton("open").hidden, true);
    assert.equal(pbutton("install").hidden, true);
    assert.equal(pbutton("remove").disabled, false);
    assert.match(nodes.get("addon-catalog-line").textContent, /Unlock your Vault/);
    assert.equal(cardPart("open").disabled, true);
  });
  calls.length = 0;
  pbutton("unlock").click(); await flush();
  check("Unlock Vault opens the Vault", () => assert.deepEqual(calls.map(c => c.cmd), ["open_vault"]));
  window.__addons.render(counted());
  reply = counted();
  calls.length = 0;
  for (const action of ["install", "open", "update", "rollback", "remove", "export", "delete"]) {
    const b = pbutton(action); b.hidden = false; b.disabled = false; b.click(); await flush();
    window.__addons.render(counted());
  }
  check("each panel button requests its own action for its own add-on", () => {
    assert.deepEqual(actions(), ["install", "open", "update", "rollback", "remove", "export", "delete"]);
    assert(calls.every(c => c.args.id === "text-pages"));
  });
  calls.length = 0;
  cardPart("open").click(); await flush();
  check("a card's Open opens the add-on itself", () => assert.deepEqual(calls.map(c => [c.args.action, c.args.id]), [["open", "text-pages"]]));
  reply = null;

  // Saved pages in the panel, and saved pages with no panel (P-2).
  window.__addons.render(live({ known: [installed], last: { id: "", action: "refresh", data: { ids: [], pages: {} } } }));
  check("no saved pages: no page count and no export or delete to offer", () => {
    assert.equal(pbutton("export").hidden, true);
    assert.equal(pbutton("delete").hidden, true);
    assert.equal(part("addon-panel-meta").textContent, "Version 1.0.0");
    assert.equal(nodes.get("addon-orphans").hidden, true);
  });
  window.__addons.render(live({ premium: false, known: [], last: { id: "", action: "refresh", data: { ids: ["gone-addon"] } } }));
  check("saved data of an add-on with no panel stays reachable", () => {
    assert.equal(nodes.get("addon-orphans").hidden, false);
    assert.deepEqual(nodes.get("addon-data-id").children.map(o => o.value), ["gone-addon"]);
    assert.equal(orphanButton("export").disabled, false);
    assert.equal(orphanButton("delete").disabled, false);
  });
  nodes.get("addon-data-id").value = "gone-addon";
  confirmation = false; calls.length = 0; orphanButton("export").click(); orphanButton("delete").click(); await flush();
  check("confirmation cancellation makes no request", () => assert.equal(calls.length, 0));
  confirmation = true; orphanButton("export").click(); await flush();
  check("plaintext warning and explicit folder action, for the selected id", () => {
    assert.match(confirmationText, /The files will not be encrypted\./);
    assert.deepEqual(actions(), ["export"]);
    assert.equal(calls[0].args.id, "gone-addon");
    assert.equal(calls[0].args.confirmed, true);
    assert.equal(calls[0].args.path, undefined);
  });
  calls.length = 0;
  await window.__addons.exportPages("gone-addon"); await flush();
  check("the import warning's export still works for data with no panel", () => {
    assert.deepEqual(calls.map(c => [c.args.action, c.args.id]), [["export", "gone-addon"]]);
  });
  window.__addons.render(live({ known: [], last: { id: "gone-addon", action: "export", data: { export: { written: 1, failures: [{ id: "a", code: "unreadable" }, { id: "b", code: "exists" }] } } } }));
  check("each failed page is listed where the export ran", () => {
    assert.equal(nodes.get("addon-page-failures").children.length, 2);
    assert.match(nodes.get("addon-operation-status").textContent, /Some pages/);
    assert.equal(nodes.get("addon-export-count").textContent, "1");
  });
  openPanels.clear(); openPanels.add("addon-text-pages");
  window.__addons.render(live({ known: [installed], last: { id: "text-pages", action: "export", data: { export: { written: 3, failures: [] } } } }));
  check("an export run from the add-on's open panel shows there, not in Add-ons", () => {
    assert.equal(part("addon-panel-export-result").hidden, false);
    assert(walk(part("addon-panel-export-result")).some(el => el.textContent === "3"));
    assert.equal(nodes.get("addon-export-result").hidden, true);
    assert.equal(nodes.get("addon-operation-status").textContent, "");
  });
  // The import warning exports a NAMED add-on's pages and then opens Add-ons:
  // the result belongs there (review R-001).
  calls.length = 0; reply = live({ known: [installed] });
  await window.__addons.exportPages("text-pages"); await flush();
  reply = null;
  const partialNamed = { id: "text-pages", action: "export", data: { export: { written: 2, failures: [{ id: "p1", code: "unreadable" }] } } };
  window.__addons.render(live({ known: [installed], last: partialNamed }));
  check("an import-warning export of a named add-on reports in Add-ons, failures included", () => {
    assert.deepEqual(calls.map(c => [c.args.action, c.args.id]), [["export", "text-pages"]]);
    assert.equal(nodes.get("addon-export-result").hidden, false);
    assert.equal(nodes.get("addon-export-count").textContent, "2");
    assert.equal(nodes.get("addon-page-failures").children.length, 1);
    assert.match(nodes.get("addon-operation-status").textContent, /Some pages/);
    assert.equal(part("addon-panel-export-result").hidden, true);
  });
  reply = live({ known: [installed] });
  pbutton("open").click(); await flush();
  reply = null;
  window.__addons.render(live({ known: [installed], last: { id: "text-pages", action: "open", data: { installed: true } } }));
  check("an Open says nothing when it works, in its panel or in Add-ons", () => {
    assert.equal(part("addon-panel-status").textContent, "");
    assert.equal(nodes.get("addon-operation-status").textContent, "");
  });
  window.__addons.render(live({ known: [installed], last: { id: "text-pages", action: "delete", data: {} } }));
  check("a later operation hides the earlier export's count", () => {
    assert.equal(part("addon-panel-export-result").hidden, true);
    assert.equal(part("addon-panel-status").textContent, "Pages deleted.");
    assert.equal(nodes.get("addon-operation-status").textContent, "", "the add-on's own panel takes its results back once used");
  });
  // Hand test H-15: the status line names the action, while it runs and when
  // it is done, instead of "Working..." and "Operation completed.".
  window.__addons.render(live({ known: [installed], pending: { action: "remove", id: "text-pages", phase: "running" } }));
  check("a running action says what it is doing", () => {
    assert.equal(part("addon-panel-status").textContent, "Removing…");
  });
  window.__addons.render(live({ known: [installed], last: { id: "text-pages", action: "install", data: {} } }));
  check("a finished action says what happened", () => {
    assert.equal(part("addon-panel-status").textContent, "Installed.");
  });
  window.__addons.render(live({ known: [installed], last: { id: "text-pages", action: "inspect", data: {} } }));
  check("an action without its own line keeps the generic one", () => {
    assert.equal(part("addon-panel-status").textContent, "Done.");
  });
  window.__addons.render(live({ known: [installed], pending: { action: "open", id: "text-pages", phase: "running" } }));
  check("an Open under way says so", () => {
    assert.equal(part("addon-panel-status").textContent, "Opening…");
  });
  openPanels.clear(); openPanels.add("addons");
  window.__addons.render(live({ known: [installed], pending: { phase: "working", action: "install", id: "text-pages" } }));
  check("an Install started from a card shows in Add-ons while its panel is closed", () => {
    assert.equal(nodes.get("addon-operation-status").textContent, "Installing…");
  });
  openPanels.clear(); openPanels.add("addon-text-pages");
  window.__addons.render(counted({ pending: { phase: "waiting", action: "remove", id: "text-pages" } }));
  check("a pending job is shown in its panel and holds every button", () => {
    assert.match(part("addon-panel-status").textContent, /Waiting/);
    for (const action of ["open", "update", "rollback", "remove", "export", "delete"]) assert.equal(pbutton(action).disabled, true, action);
  });
  window.__addons.render(live({ known: [installed], last: { id: "text-pages", action: "install", error: "busy" } }));
  fill();
  check("failures survive repaint", () => assert.match(part("addon-panel-status").textContent, /^Busy right now/));

  // The catalog line.
  const line = () => nodes.get("addon-catalog-line").textContent;
  window.__addons.render(live({ pending: { phase: "working", action: "refresh", id: "" } }));
  check("checking while the refresh runs", () => assert.match(line(), /Checking/));
  window.__addons.render(live({ catalog: { held: true, error: "network" } }));
  check("a failure says so and that the list is the last one", () => assert.match(line(), /^Could not check your add-ons\. Showing your last add-on list\.$/));
  window.__addons.render(live({ catalog: { held: true, error: null, stale: true } }));
  check("a held list past its end date is called the last one", () => assert.match(line(), /Showing your last add-on list/));
  window.__addons.render(live({ catalog: { held: true, error: null, stale: false } }));
  check("a current list says nothing", () => assert.equal(line(), ""));
  window.__addons.render(live({ catalog: { held: false, error: "rate_limited" } }));
  check("a rate limit says so, with no list to fall back on", () => { assert.match(line(), /Too many requests/); assert.doesNotMatch(line(), /last add-on list/); });
  window.__addons.render(live({ catalog: { held: true, error: "catalog_invalid" } }));
  check("a list that did not verify is named as such", () => assert.match(line(), /Could not verify the add-on list/));
  window.__addons.render(live({ premium: false }));
  check("without Premium the line is the standard Premium note", () => assert.equal(line(), "PREMIUM LOCK NOTE"));
  window.__addons.render(live({ catalog: { held: false, error: "not_found" } }));
  check("'none available' is not said over an add-on that is shown", () => assert.equal(line(), ""));
  window.__addons.render(live({ known: [], catalog: { held: false, error: "not_found" } }));
  check("'none available' is said when nothing is shown", () => assert.match(line(), /No add-ons are available/));
  window.__addons.render(live({ known: [installed] }));
  check("Add-ons keeps its disclosure under What's sent, closed", () => {
    const host = nodes.get("addon-whats-sent-host");
    const sent = host.children[0];
    assert(sent && sent.tagName === "DETAILS" && !sent.hasAttribute("open"));
    assert.equal(sent.children[0].textContent, "What's sent");
    assert.match(sent.children[1].textContent, /Premium token and device ID/);
  });

  // Customize: show or hide the toolbar button (P-1).
  check("Customize lists the add-on by name, ticked", () => {
    assert.equal(nodes.get("addon-toolbar-choices").hidden, false);
    assert.equal(choice().checked, true);
    assert(walk(choice().parentNode).some(el => el.textContent === "Test pages"));
  });
  const box = choice();
  reply = live({ known: [installed], toolbar_hidden: ["text-pages"] });
  calls.length = 0; box.checked = false; box.change(); await flush();
  check("unticking hides the button and keeps it a Tools member", () => {
    assert.deepEqual(calls.map(c => [c.cmd, c.args.id, c.args.shown]), [["toolbar_addon_shown_set", "text-pages", false]]);
    assert(!tbutton().hasAttribute("data-shown"));
    assert.equal(tbutton().hidden, false);
    assert.equal(choice(), box, "the box is updated in place, not rebuilt");
    assert.equal(box.checked, false);
  });
  reply = null;
  window.__addons.render(live({ known: [installed] }));
  openPanels.clear(); openPanels.add("addon-text-pages"); calls.length = 0;
  window.__addons.render(live({ known: [], last: { id: "text-pages", action: "remove", data: { installed: false } } }));
  check("an add-on no longer named leaves the row and the Tools menu", () => {
    assert.equal(tbutton().hidden, true);
    assert(!tbutton().hasAttribute("data-shown"), "a folded Tools rule would still draw it");
    assert.equal(nodes.get("addon-toolbar-choices").hidden, true);
  });
  check("its open panel hands over to Add-ons, where its pages still are", () => {
    assert.deepEqual(calls.map(c => c.cmd), ["open_addons"]);
  });

  // Opening a panel refreshes once; Rust decides whether that is a request.
  calls.length = 0; reply = live({ known: [installed] });
  await window.__addons.opened(); await flush();
  check("opening unlocked refreshes once", () => assert.deepEqual(actions(), ["refresh"]));
  calls.length = 0; reply = live({ known: [installed] });
  await panelsRegistered[0].spec.onOpen(); await flush();
  check("opening an add-on's own panel refreshes too", () => assert.deepEqual(actions(), ["refresh"]));
  calls.length = 0; reply = live({ unlocked: false });
  await window.__addons.opened(); await flush();
  check("opening locked refreshes nothing", () => assert.deepEqual(actions(), []));
  calls.length = 0; reply = live({ pending: { phase: "working", action: "install", id: "text-pages" } });
  await window.__addons.opened(); await flush();
  check("opening during a job refreshes nothing", () => assert.deepEqual(actions(), []));
  calls.length = 0; reply = base;
  await window.__addons.opened(); await flush();
  check("opening before launch refreshes nothing", () => assert.deepEqual(actions(), []));

  // Found from the first unlock (hand test U-1): the change INTO Premium owes
  // one quiet refresh while no list is held, and nothing after that.
  const unheld = (over = {}) => live({ catalog: { held: false, loaded: true, fetched: false, error: null }, ...over });
  const becomePremium = async (state) => {
    reply = live({ premium: false }); premiumChanged({ premium: false }); await flush();
    calls.length = 0; reply = state; premiumChanged({ premium: true }); await flush();
  };
  nodes.get("addon-operation-status").textContent = "";
  await becomePremium({ ...unheld(), visible: false });
  check("before launch, becoming Premium asks nothing", () => assert.deepEqual(actions(), []));
  await becomePremium(unheld());
  check("becoming Premium with no list held asks once", () => assert.deepEqual(actions(), ["refresh"]));
  check("the check at unlock says nothing", () => assert.equal(nodes.get("addon-operation-status").textContent, ""));
  calls.length = 0; premiumChanged({ premium: true }); await flush();
  window.__addons.render(unheld()); await flush();
  check("a second Premium change asks nothing", () => assert.deepEqual(actions(), []));
  await becomePremium(live({ catalog: { held: true, loaded: true, fetched: false, error: null } }));
  check("a held list asks nothing", () => assert.deepEqual(actions(), []));
  calls.length = 0; reply = unheld({ premium: false }); premiumChanged({ premium: false }); await flush();
  check("not Premium asks nothing", () => assert.deepEqual(actions(), []));
  await becomePremium(unheld({ catalog: { held: false, loaded: false, fetched: false, error: null } }));
  check("it waits for the saved list to be read", () => assert.deepEqual(actions(), []));
  window.__addons.render(unheld()); await flush();
  window.__addons.render(unheld()); await flush();
  check("then asks once", () => assert.deepEqual(actions(), ["refresh"]));
  await becomePremium(unheld({ pending: { phase: "working", action: "install", id: "text-pages" } }));
  check("it waits for a running job", () => assert.deepEqual(actions(), []));
  window.__addons.render(unheld()); await flush();
  window.__addons.render(unheld()); await flush();
  check("and asks once when the job ends", () => assert.deepEqual(actions(), ["refresh"]));
  refusal = "premium_required";
  await becomePremium(unheld());
  window.__addons.render(unheld()); await flush();
  check("a refused check is not repeated and says nothing", () => {
    assert.deepEqual(actions(), ["refresh"]);
    assert.equal(nodes.get("addon-operation-status").textContent, "");
  });
  refusal = "busy";
  await becomePremium(unheld());
  refusal = null;
  window.__addons.render(unheld()); await flush();
  window.__addons.render(unheld()); await flush();
  check("a busy refusal asks again at the next status", () => assert.deepEqual(actions(), ["refresh", "refresh"]));
  // Review R-038: opening Add-ons just as the owed check goes out is that same
  // job, not a second refresh the backend would refuse as busy. Once with
  // replies at once, once with replies a turn late, as real IPC is.
  for (const late of [false, true]) {
    slowReplies = late;
    await becomePremium(unheld({ catalog: { held: false, loaded: false, fetched: false, error: null } }));
    calls.length = 0; reply = unheld();
    await window.__addons.opened(); await flush(); await settleLate();
    check("opening Add-ons as the unlock check goes out sends one refresh" + (late ? " (late replies)" : ""), () => {
      assert.deepEqual(actions(), ["refresh"]);
      assert.equal(nodes.get("addon-operation-status").textContent, "");
    });
  }
  slowReplies = false;
  calls.length = 0; reply = unheld({ catalog: { held: true, loaded: true, fetched: true, error: null } });
  await window.__addons.opened(); await flush();
  check("with no check on its way, opening Add-ons still refreshes", () => assert.deepEqual(actions(), ["refresh"]));
  // Review R-041: the fields the unlock check reads are the ones Rust sends.
  check("Rust's status names the catalog fields the unlock check reads", () => {
    const rust = fs.readFileSync("crates/app/src/addon_manager.rs", "utf8");
    const at = rust.indexOf("pub(crate) fn status(app: &AppState)");
    assert(at >= 0, "status() moved");
    const status = rust.slice(at, rust.indexOf("\n}\n", at));
    assert.match(status, /"catalog": \{ "held": !m\.view\.catalog\.is_empty\(\), "loaded": view_landed\(m\),/);
    assert.match(status, /"importing": crate::backup_job::importing\(app\) \}\)/);
    for (const field of ["catalog.held === true", "catalog.loaded !== true", "snapshot.importing === true"]) {
      assert(script.includes(field), field);
    }
  });
  // Review R-042: a backup import holds the slot without a job; the check
  // waits for it, and the end of the import brings it back.
  await becomePremium(unheld({ importing: true }));
  check("it waits for a backup import", () => assert.deepEqual(actions(), []));
  window.__addons.render(unheld()); await flush();
  window.__addons.render(unheld()); await flush();
  check("and asks once when the import ends", () => assert.deepEqual(actions(), ["refresh"]));
  check("the end of a backup refreshes Add-ons", () => {
    const chrome = fs.readFileSync("crates/app/src/chrome/chrome.js", "utf8");
    const at = chrome.indexOf('case "backup_finished":');
    assert(at >= 0, "backup_finished case moved");
    const arm = chrome.slice(at, chrome.indexOf("break;", at));
    assert.match(arm, /if \(window\.__addons\) window\.__addons\.backupFinished\(msg\.data\);/);
  });
  // Review R-043: an import that replaced the vault is a new session; one
  // whose list is still missing gets the check again, and nothing else does.
  const finished = async (data) => { calls.length = 0; reply = unheld(); await window.__addons.backupFinished(data); await flush(); };
  await finished({ kind: "export", ok: true, lock_follows: false });
  check("an export's end asks nothing", () => assert.deepEqual(actions(), []));
  await finished({ kind: "import", ok: false, lock_follows: false });
  check("a failed import's end asks nothing", () => assert.deepEqual(actions(), []));
  await finished({ kind: "import", ok: true, lock_follows: true });
  check("an import followed by a lock asks nothing", () => assert.deepEqual(actions(), []));
  await finished({ kind: "import", ok: true, lock_follows: false });
  check("a completed import with no list held asks once", () => assert.deepEqual(actions(), ["refresh"]));
  refusal = null; reply = null;
  check("one copy of each moved section lives in Add-ons", () => {
    const addonsPanel = html.match(/<section id="addons-panel"[^>]*>([\s\S]*?)<\/section>/)[1];
    for (const id of ["addon-controls", "addon-manager", "addon-messages", "translate-langs"]) {
      assert.equal(html.split('id="' + id + '"').length - 1, 1, id + " duplicated");
      assert(addonsPanel.includes('id="' + id + '"'), id + " outside Add-ons");
    }
    assert(!html.includes('id="addon-manager-id"'), "free-text id box remains");
  });
  check("no authenticated polling", () => assert(!/setInterval|setTimeout/.test(script)));
  // Hand test H-14: an add-on's panel is built at run time and appended after
  // the confirmation overlay, so at an EQUAL z-index the panel covered its own
  // Remove confirmation. The overlay must sit strictly above every panel.
  check("the confirmation opens above an add-on's panel", () => {
    const css = fs.readFileSync("crates/app/src/chrome/chrome.css", "utf8");
    const zOf = (selector) => {
      const at = css.indexOf("\n" + selector + " {");
      assert(at >= 0, selector + " rule missing");
      const rule = css.slice(at, css.indexOf("}", at));
      const m = rule.match(/z-index:\s*(\d+)/);
      assert(m, selector + " has no z-index");
      return Number(m[1]);
    };
    assert(zOf("#confirm-overlay") > zOf(".panel-modal"), "confirmation not above the panels");
  });
  // The one-time announcement (1.1.0): shown only for a current list's add-on
  // that is not installed and was never announced, with every condition the
  // manager's own panels need; its words come from the catalog; each button
  // answers it for good, the tour only once its page has opened.
  const bannerReady = { known: [named()], announced: [], tour: true, catalog: { held: true, stale: false } };
  const bannerHidden = () => nodes.get("addon-banner").hidden === true;
  reply = null; calls.length = 0;
  window.__addons.render(live(bannerReady));
  check("a current list announces the add-on it names, in its own words", () => {
    assert.equal(bannerHidden(), false);
    assert.equal(nodes.get("addon-banner-name").textContent, "Test pages");
    assert.equal(nodes.get("addon-banner-try-name").textContent, "Test pages");
    assert.equal(nodes.get("addon-banner-summary").textContent, "Pages over any site.");
    assert.equal(nodes.get("addon-banner-tour").hidden, false);
    assert.equal(calls.length, 0, "showing it asked for nothing");
  });
  for (const [why, state] of [
    ["not until the start-up read has landed", { announced: null }],
    ["not once announced", { announced: ["text-pages"] }],
    ["not when installed", { known: [named({ installed: true, version: "2.0.0" })] }],
    ["not from an expired list", { catalog: { held: true, stale: true } }],
    ["not with no list", { catalog: { held: false } }],
    ["not without Premium", { premium: false }],
    ["not while locked", { unlocked: false }],
    ["not where the manager is hidden", { visible: false }],
    ["not while a job runs", { pending: { phase: "working", action: "install", id: "text-pages" } }],
  ]) {
    window.__addons.render(live({ ...bannerReady, ...state }));
    check("the banner shows " + why, () => assert.equal(bannerHidden(), true));
  }
  window.__addons.render(live({ ...bannerReady, tour: false }));
  check("no tour button where the tour page may not open", () => {
    assert.equal(bannerHidden(), false);
    assert.equal(nodes.get("addon-banner-tour").hidden, true);
  });
  window.__addons.render(live({ ...bannerReady, known: [named({ name: "<b>N</b>", summary: "<i>S</i>" })] }));
  check("the banner's words go in as text", () => {
    assert.equal(nodes.get("addon-banner-name").textContent, "<b>N</b>");
    assert.equal(nodes.get("addon-banner-summary").textContent, "<i>S</i>");
  });
  const answered = live({ ...bannerReady, announced: ["text-pages"] });
  window.__addons.render(live(bannerReady)); calls.length = 0; reply = answered;
  nodes.get("addon-banner-later").click(); await flush();
  check("Not now answers it for good", () => {
    assert.deepEqual(calls.map(c => c.cmd), ["addon_announced_set"]);
    assert.equal(JSON.stringify(calls[0].args), '{"id":"text-pages"}');
    assert.equal(bannerHidden(), true);
  });
  window.__addons.render(live(bannerReady)); calls.length = 0; openPanels.clear();
  nodes.get("addon-banner-try").click(); await flush();
  check("Try opens the add-on's panel and answers it", () => {
    assert(openPanels.has("addon-text-pages"), "the panel did not open");
    assert(calls.some(c => c.cmd === "addon_announced_set" && c.args.id === "text-pages"));
    assert.equal(bannerHidden(), true);
  });
  window.__addons.render(live(bannerReady)); calls.length = 0;
  nodes.get("addon-banner-tour").click(); await flush();
  check("Watch the tour opens the tour page by name, then answers it", () => {
    assert.deepEqual(calls.map(c => c.cmd), ["site_page_open", "addon_announced_set"]);
    assert.equal(JSON.stringify(calls[0].args), '{"page":"premium_tour"}');
    assert.equal(bannerHidden(), true);
  });
  reply = null; window.__addons.render(live(bannerReady)); calls.length = 0; pageRefusal = "bad_args";
  nodes.get("addon-banner-tour").click(); await flush(); pageRefusal = null;
  check("a tour page that did not open answers nothing, and the banner stays", () => {
    assert.deepEqual(calls.map(c => c.cmd), ["site_page_open"]);
    assert.equal(bannerHidden(), false);
  });
  check("Rust sends the fields the banner reads, and takes its answer", () => {
    const rust = fs.readFileSync("crates/app/src/addon_manager.rs", "utf8");
    const at = rust.indexOf("pub(crate) fn status(app: &AppState)");
    const status = rust.slice(at, rust.indexOf("\n}\n", at));
    assert.match(status, /"announced": m\.announced\.clone\(\), "tour": crate::site_pages::SitePage::PremiumTour\.available\(\),/);
    assert.match(status, /"stale": catalog_stale\(/);
    const ipc = fs.readFileSync("crates/app/src/ipc.rs", "utf8");
    assert(ipc.includes('"addon_announced_set" => {'), "no addon_announced_set handler");
    for (const field of ["Array.isArray(snapshot.announced)", "snapshot.tour !== true", "catalog.stale === true"]) {
      assert(script.includes(field), field);
    }
  });
  check("the markup names no add-on and holds no Premium address", () => {
    const block = html.slice(html.indexOf('<div id="addon-banner"'), html.indexOf('<div id="engine-floor-warning"'));
    assert(block.length > 0 && !/patanyx\.net/i.test(block), "the banner markup holds an address");
    // Every name slot is empty in the markup: the catalog fills it at run time.
    for (const id of ["addon-banner-name", "addon-banner-summary", "addon-banner-try-name"]) {
      assert(new RegExp('id="' + id + '"></span>').test(block), id + " is not empty in the markup");
    }
  });
  console.log("ADDON MANAGER GATE OK");
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
