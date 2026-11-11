/* Add-ons: what Premium includes (a signed catalog), one panel and one toolbar
   button per add-on, and the saved data of add-ons that are gone. Nothing here
   names an add-on: every name and summary arrives as signed data
   (addon_manager.rs) and is inserted as text, never as markup.

   Lean on purpose: a name, a
   one-line pitch, ONE primary button and a short status line. Everything else,
   the disclosure included, sits under More / What's sent. */
(function () {
  "use strict";
  const rb = window.__rb;
  const { request, askConfirm, rebuildOnLocaleFill, untilAnswered } = rb;
  const byId = (id) => document.getElementById(id);
  const root = byId("addon-controls");
  if (!root) return;
  let snapshot = {};
  // Ids with saved pages, from the last refresh (what opening a panel runs),
  // and how many pages each holds where that could be counted.
  let saved = [];
  let pageCounts = {};
  // id -> { section, button, labelEl, parts }: built once per add-on.
  const panels = new Map();
  // id -> { label, box, name }: the Customize checkboxes, kept in place so a
  // status event never takes the keyboard off the box being toggled.
  const choices = new Map();
  // Ids whose export was started from the import warning: that warning opens
  // Add-ons, so the result is shown there, not in the add-on's own panel,
  // which nobody is looking at (review R-001).
  const exportsShownInAddons = new Set();
  // The tucked disclosure under the cards (built below, once make exists).
  let sent = null;
  const make = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  };
  const text = (key) => {
    const node = root.querySelector('[data-msg="' + key.replace(/-/g, ".") + '"]');
    return node ? node.textContent : "";
  };
  const label = {
    waiting: () => text("addon-status-waiting"),
    working: () => text("addon-status-working"),
    success: () => text("addon-status-success"),
    failed: () => text("addon-status-failed"),
    busy: () => text("addon-status-busy"),
    not_unlocked: () => text("addon-status-locked"),
    premium_required: () => text("addon-status-premium"),
    unconfigured: () => text("addon-status-unconfigured"),
    cancelled: () => text("addon-status-cancelled"),
    export_stopped: () => text("addon-status-export-stopped"),
    exists: () => text("addon-page-exists"),
    unreadable: () => text("addon-page-unreadable"),
    export_unreadable: () => text("addon-status-export-unreadable"),
  };
  const errorText = (code) => (label[code] || label.failed)();
  // Per action, so the line says what is happening and what happened (hand
  // test H-15). An action without its own line keeps the generic one.
  const WORKING = {
    install: "addon-working-install",
    update: "addon-working-update",
    rollback: "addon-working-rollback",
    remove: "addon-working-remove",
    export: "addon-working-export",
    delete: "addon-working-delete",
    check: "addon-working-check",
    open: "addon-working-open",
  };
  const DONE = {
    install: "addon-done-install",
    update: "addon-done-update",
    rollback: "addon-done-rollback",
    remove: "addon-done-remove",
    delete: "addon-done-delete",
    export: "addon-done-export",
    check: "addon-done-check",
  };
  // A list, a refresh or an Open says nothing when it works: the result is
  // on screen (the list, or the add-on's own window).
  const SILENT_DONE = ["list", "refresh", "open"];
  const has = (map, action) => Object.prototype.hasOwnProperty.call(map, action);
  const workingText = (action) => (has(WORKING, action) ? text(WORKING[action]) || label.working() : label.working());
  const doneText = (action) => (has(DONE, action) ? text(DONE[action]) || label.success() : label.success());
  // Why the catalog could not be fetched, by the code addon_manager.rs gives.
  const CATALOG_LINES = {
    network: "addon-catalog-network",
    unavailable: "addon-catalog-network",
    delivery: "addon-catalog-network",
    rate_limited: "addon-catalog-rate",
    bad_token: "addon-catalog-license",
    expired: "addon-catalog-expired",
    not_activated: "addon-catalog-inactive",
    credentials: "addon-catalog-inactive",
    not_found: "addon-catalog-none",
    catalog_invalid: "addon-catalog-invalid",
    catalog_expired: "addon-catalog-network",
  };
  // Only add-ons with a verified name: Rust never sends one without, and a
  // raw id is never shown as if it were a name.
  const named = () =>
    (snapshot.known || []).filter((a) => a && typeof a.id === "string" && typeof a.name === "string" && a.name);
  const sizeText = (bytes) => {
    if (typeof bytes !== "number" || !(bytes > 0)) return "";
    if (bytes < 1024 * 1024) return Math.max(1, Math.round(bytes / 1024)) + " " + text("addon-unit-kb");
    return (bytes / (1024 * 1024)).toFixed(1) + " " + text("addon-unit-mb");
  };
  const pagesText = (id) => {
    const n = pageCounts[id];
    if (typeof n !== "number" || n < 1) return "";
    return n === 1 ? text("addon-pages-one") : n + " " + text("addon-pages-many");
  };
  const pendingFor = (id) => snapshot.pending && snapshot.pending.id === id && !exportsShownInAddons.has(id);
  const lastFor = (id) => snapshot.last && snapshot.last.id === id && !exportsShownInAddons.has(id);
  const button = (value, className) => {
    const node = make("button", className, value);
    node.type = "button";
    return node;
  };
  // The tucked disclosure: the same text in Add-ons and in every panel,
  // refilled on every render so a language change reaches it.
  function whatsSent() {
    const details = make("details", "addon-whats-sent");
    details.appendChild(make("summary"));
    details.appendChild(make("p"));
    return details;
  }
  function fillSent(details) {
    details.children[0].textContent = text("addon-whats-sent");
    details.children[1].textContent = text("addon-network-note");
  }

  function catalogLine() {
    const catalog = snapshot.catalog || {};
    if (!snapshot.unlocked) return text("addon-catalog-locked");
    if (!snapshot.premium) return rb.premiumLockNote ? rb.premiumLockNote() : text("addon-status-premium");
    if (snapshot.pending && snapshot.pending.action === "refresh") return text("addon-catalog-checking");
    // "None available" says nothing useful over cards that are installed
    // here (VM check 2026-10-21: the line sat above an installed add-on).
    if (catalog.error === "not_found" && named().length) return "";
    if (catalog.error && catalog.error !== "cancelled") {
      const line = text(CATALOG_LINES[catalog.error] || "addon-catalog-network");
      return catalog.held ? line + " " + text("addon-catalog-previous") : line;
    }
    // A held list past its end date is said to be the old one (review R-003).
    if (catalog.held && catalog.stale) return text("addon-catalog-previous");
    return "";
  }

  // A card: the name (opens the add-on's panel), a tag, the pitch, and one
  // button: Open when installed, Install when not.
  function renderCards() {
    const host = byId("addon-known-list");
    host.replaceChildren();
    const unlocked = snapshot.unlocked === true;
    const busy = !!snapshot.pending;
    for (const addon of named()) {
      const row = make("div", "addon-row");
      row.dataset.addonId = addon.id;
      const head = make("div", "addon-row-head");
      const name = button(addon.name, "addon-row-name");
      name.dataset.rowAction = "panel";
      name.addEventListener("click", () => openPanelFor(addon.id));
      head.appendChild(name);
      const tag = addon.installed
        ? addon.update
          ? text("addon-update-available")
          : text("addon-installed")
        : sizeText(addon.size);
      if (tag) head.appendChild(make("span", "addon-tag", tag));
      row.appendChild(head);
      if (addon.summary) row.appendChild(make("p", "addon-row-summary", addon.summary));
      const action = addon.installed ? "open" : "install";
      const primary = button(text(action === "open" ? "addon-open" : "addon-install"), "as-primary");
      primary.dataset.rowAction = action;
      primary.disabled = busy || !unlocked || (action === "install" && snapshot.premium !== true);
      primary.addEventListener("click", () => act(action, addon.id));
      const actions = make("div", "form-buttons");
      actions.appendChild(primary);
      row.appendChild(actions);
      host.appendChild(row);
    }
  }

  function openPanelFor(id) {
    const panel = panels.get(id);
    if (panel && !(rb.isPanelOpen && rb.isPanelOpen("addon-" + id))) panel.button.click();
  }

  // One add-on's panel and its toolbar button, built the first time Rust
  // names it. The button is a Tools member: in the Tools menu while Tools is
  // folded (the default), and on the row while Tools is open unless the user
  // took it off (chrome.css).
  let lastToolButton = null;
  function ensurePanel(addon) {
    const existing = panels.get(addon.id);
    if (existing) return existing;
    const id = addon.id;
    const section = make("section", "addon-panel");
    section.id = "addon-panel-" + id;
    section.hidden = true;
    const parts = {
      name: make("h2", "addon-panel-name"),
      tag: make("span", "addon-tag"),
      summary: make("p", "addon-panel-summary"),
      state: make("p", "addon-panel-state"),
      meta: make("p", "addon-panel-meta"),
      more: make("details", "addon-panel-more"),
      moreLabel: make("summary"),
      sent: whatsSent(),
      status: make("p", "addon-panel-status"),
      exportResult: make("p", "addon-panel-export-result"),
      exportLabel: make("span"),
      exportCount: make("span"),
      failures: make("ul", "addon-panel-failures"),
      buttons: {},
    };
    parts.status.setAttribute("role", "status");
    parts.status.setAttribute("aria-live", "polite");
    parts.exportResult.hidden = true;
    const buttonRow = (actions, className) => {
      const row = make("div", className);
      for (const action of actions) {
        const node = button("", ["install", "open", "unlock"].includes(action) ? "as-primary" : "");
        node.dataset.panelAction = action;
        node.addEventListener("click", () => panelAction(id, action));
        parts.buttons[action] = node;
        row.appendChild(node);
      }
      return row;
    };
    const head = make("div", "addon-panel-head");
    head.appendChild(parts.name);
    head.appendChild(parts.tag);
    section.appendChild(head);
    section.appendChild(parts.summary);
    section.appendChild(parts.state);
    section.appendChild(buttonRow(["unlock", "install", "open", "update"], "form-buttons addon-panel-actions"));
    section.appendChild(parts.meta);
    parts.more.appendChild(parts.moreLabel);
    parts.more.appendChild(buttonRow(["export", "delete", "rollback", "remove"], "addon-more-actions"));
    parts.more.appendChild(parts.sent);
    section.appendChild(parts.more);
    section.appendChild(parts.status);
    parts.exportResult.appendChild(parts.exportLabel);
    parts.exportResult.appendChild(document.createTextNode(" "));
    parts.exportResult.appendChild(parts.exportCount);
    section.appendChild(parts.exportResult);
    section.appendChild(parts.failures);
    document.body.appendChild(section);

    const toolbarButton = make("button", "feature-btn");
    toolbarButton.type = "button";
    toolbarButton.id = "btn-addon-" + id;
    toolbarButton.dataset.group = "tools";
    toolbarButton.setAttribute("data-addon-button", "");
    toolbarButton.setAttribute("aria-pressed", "false");
    const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    icon.setAttribute("class", "ico");
    icon.setAttribute("viewBox", "0 0 16 16");
    icon.setAttribute("aria-hidden", "true");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M3 3 H7 V4.5 A1 1 0 0 0 9 4.5 V3 H13 V13 H3 Z");
    icon.appendChild(path);
    const labelEl = make("span", "feature-label");
    toolbarButton.appendChild(icon);
    toolbarButton.appendChild(labelEl);
    // After the last Tools button (Assistant, then any add-on built before
    // this one), so an open Tools shows its buttons in the same order as its
    // menu.
    const toolbar = byId("toolbar");
    const pill = byId("group-tools");
    const anchor =
      lastToolButton && lastToolButton.parentNode === toolbar ? lastToolButton : byId("btn-assistant");
    if (toolbar && anchor && anchor.parentNode === toolbar) toolbar.insertBefore(toolbarButton, anchor.nextSibling);
    else if (toolbar && pill && pill.parentNode === toolbar) toolbar.insertBefore(toolbarButton, pill);
    else (toolbar || document.body).appendChild(toolbarButton);
    lastToolButton = toolbarButton;
    rb.addGroupMember("tools", toolbarButton.id);
    rb.registerPanel("addon-" + id, { el: section, button: toolbarButton, heightPx: 520, onOpen: () => opened() });
    const panel = { id, section, button: toolbarButton, labelEl, parts };
    panels.set(id, panel);
    return panel;
  }

  function renderPanel(panel, addon) {
    const { parts } = panel;
    const id = addon.id;
    const unlocked = snapshot.unlocked === true;
    const premium = snapshot.premium === true;
    const busy = !!snapshot.pending;
    panel.labelEl.textContent = addon.name;
    panel.button.title = addon.name;
    panel.button.setAttribute("aria-label", addon.name);
    parts.name.textContent = addon.name;
    parts.tag.textContent = text("addon-premium-tag");
    parts.summary.textContent = addon.summary || "";
    parts.summary.hidden = !addon.summary;
    parts.state.textContent = !unlocked
      ? text("addon-state-locked")
      : !premium
        ? rb.premiumLockNote
          ? rb.premiumLockNote()
          : text("addon-status-premium")
        : "";
    parts.state.hidden = !parts.state.textContent;
    // ONE primary action: Unlock Vault, else Install, else Open (always its
    // own button when code is installed, plan P-3), with Update beside it
    // only when a newer version is listed.
    const b = parts.buttons;
    b.unlock.textContent = text("addon-unlock");
    b.unlock.hidden = unlocked;
    b.install.textContent = text("addon-install") + " " + addon.name;
    b.install.hidden = !unlocked || !!addon.installed;
    b.install.disabled = busy || !premium;
    b.open.textContent = text("addon-open") + " " + addon.name;
    b.open.hidden = !unlocked || !addon.installed;
    b.open.disabled = busy;
    b.update.textContent = text("addon-update-to") + " " + (addon.available || "");
    b.update.hidden = !unlocked || !(addon.installed && addon.update && addon.available);
    b.update.disabled = busy || !premium;
    // One short line: pages and version when installed, the download size
    // when not.
    const meta = addon.installed
      ? [pagesText(id), addon.version ? text("addon-version-word") + " " + addon.version : ""]
      : [addon.size ? text("addon-size") + " " + sizeText(addon.size) : ""];
    parts.meta.textContent = meta.filter(Boolean).join(" · ");
    parts.meta.hidden = !parts.meta.textContent;
    // More: everything a person needs now and then.
    parts.moreLabel.textContent = text("addon-more");
    fillSent(parts.sent);
    const hasPages = saved.includes(id);
    b.export.textContent = text("addon-export-short");
    b.delete.textContent = text("addon-delete-short");
    b.export.hidden = b.delete.hidden = !hasPages;
    b.export.disabled = b.delete.disabled = busy || !unlocked;
    b.rollback.textContent = text("addon-rollback-to") + " " + (addon.rollback || "");
    // Only a version other than the one in use: after going back, the index
    // still names the earlier version, and offering it again did nothing
    // (VM, 2026-10-22).
    b.rollback.hidden = !(addon.installed && addon.rollback && addon.rollback !== addon.version);
    b.rollback.disabled = busy || !unlocked || !premium;
    b.remove.textContent = text("addon-remove");
    b.remove.hidden = !addon.installed;
    b.remove.disabled = busy;
    // This add-on's own operation, and nothing else's. A refresh says nothing.
    const last = snapshot.last;
    parts.status.textContent = pendingFor(id)
      ? snapshot.pending.phase === "waiting"
        ? label.waiting()
        : workingText(snapshot.pending.action)
      : lastFor(id)
        ? last.error
          ? errorText(last.error)
          : SILENT_DONE.includes(last.action)
            ? ""
            : doneText(last.action)
        : "";
    showExport(parts.exportResult, parts.exportLabel, parts.exportCount, parts.failures, parts.status, lastFor(id));
  }

  // The count and failures belong to the export that just finished, in the
  // panel it was run from; any later step hides them (review R-002).
  function showExport(result, labelEl, count, failures, status, mine) {
    const last = snapshot.last;
    const exported =
      mine && snapshot.unlocked && !snapshot.pending && !!last && !last.error && !!last.data && !!last.data.export;
    result.hidden = !exported;
    failures.replaceChildren();
    if (!exported) return;
    if (labelEl) labelEl.textContent = text("addon-export-count");
    count.textContent = String(last.data.export.written);
    for (const failure of last.data.export.failures) {
      failures.appendChild(make("li", "", failure.id + ": " + errorText(failure.code)));
    }
    if (last.data.export.failures.length) status.textContent = text("addon-status-partial");
  }

  function syncPanels() {
    const hidden = new Set(snapshot.toolbar_hidden || []);
    const current = new Set();
    if (snapshot.visible === true) {
      for (const addon of named()) {
        current.add(addon.id);
        const panel = ensurePanel(addon);
        panel.button.hidden = false;
        if (hidden.has(addon.id)) panel.button.removeAttribute("data-shown");
        else panel.button.setAttribute("data-shown", "");
        renderPanel(panel, addon);
      }
    }
    // An add-on no longer named keeps its panel object but leaves the row and
    // the Tools menu; if its panel is open (it was just removed and nothing
    // else names it), Add-ons takes over, where its saved pages still are
    // (review R-005).
    for (const [id, panel] of panels) {
      if (current.has(id)) continue;
      panel.button.hidden = true;
      panel.button.removeAttribute("data-shown");
      if (rb.isPanelOpen && rb.isPanelOpen("addon-" + id) && rb.openAddons) rb.openAddons();
    }
  }

  function renderToolbarChoices() {
    const host = byId("addon-toolbar-choices");
    if (!host) return;
    const hidden = new Set(snapshot.toolbar_hidden || []);
    const list = snapshot.visible === true ? named() : [];
    for (const addon of list) {
      let choice = choices.get(addon.id);
      if (!choice) {
        const labelEl = make("label", "fold-choice");
        const box = make("input");
        box.type = "checkbox";
        box.id = "addon-shown-" + addon.id;
        labelEl.setAttribute("for", box.id);
        const name = make("span");
        box.addEventListener("change", () => setShown(addon.id, box.checked));
        labelEl.appendChild(box);
        labelEl.appendChild(name);
        host.appendChild(labelEl);
        choice = { label: labelEl, box, name };
        choices.set(addon.id, choice);
      }
      choice.label.hidden = false;
      choice.name.textContent = addon.name;
      choice.box.checked = !hidden.has(addon.id);
    }
    const ids = new Set(list.map((a) => a.id));
    for (const [id, choice] of choices) if (!ids.has(id)) choice.label.hidden = true;
    host.hidden = list.length === 0;
  }

  async function setShown(id, shown) {
    try {
      render(await request("toolbar_addon_shown_set", { id, shown }));
    } catch (error) {
      render(snapshot);
    }
  }

  // Saved pages of an add-on that has no panel: neither installed nor in the
  // catalog (plan P-2). They stay exportable and deletable here.
  function renderOrphans() {
    const names = new Set(named().map((a) => a.id));
    const orphans = snapshot.unlocked ? saved.filter((id) => !names.has(id)) : [];
    byId("addon-orphans").hidden = orphans.length === 0;
    const select = byId("addon-data-id");
    const selected = select.value;
    select.replaceChildren();
    for (const id of orphans) {
      const option = make("option", "", id);
      option.value = id;
      select.appendChild(option);
    }
    if (orphans.includes(selected)) select.value = selected;
    select.disabled = !!snapshot.pending || !snapshot.unlocked;
    for (const node of root.querySelectorAll("button[data-addon-action]")) {
      node.disabled = !!snapshot.pending || !snapshot.unlocked || orphans.length === 0;
    }
  }

  // The Add-ons panel's own line: operations on saved data with no panel,
  // and a card's Open or Install; a refresh says nothing when it works.
  function renderMainStatus() {
    const pending = snapshot.pending;
    const last = snapshot.last;
    const names = new Set(named().map((a) => a.id));
    const panelOpen = (id) => rb.isPanelOpen && rb.isPanelOpen("addon-" + id);
    const mine = (entry) =>
      !!entry && (!names.has(entry.id) || exportsShownInAddons.has(entry.id) || !panelOpen(entry.id));
    const status = byId("addon-operation-status");
    status.textContent =
      mine(pending) && pending.action !== "refresh"
        ? pending.phase === "waiting"
          ? label.waiting()
          : workingText(pending.action)
        : mine(last)
          ? last.error
            ? errorText(last.error)
            : SILENT_DONE.includes(last.action)
              ? ""
              : doneText(last.action)
          : "";
    showExport(byId("addon-export-result"), null, byId("addon-export-count"), byId("addon-page-failures"), status, mine(last));
  }

  function render(state) {
    snapshot = state || {};
    // The data controls and the manager show together, only where
    // `addon_manager::MANAGER_VISIBLE` is on (Windows, and qualification builds).
    root.hidden = snapshot.visible !== true;
    byId("addon-manager").hidden = snapshot.visible !== true;
    const last = snapshot.last;
    if (!snapshot.unlocked) {
      saved = [];
      pageCounts = {};
    } else if (last && !last.error && last.data && Array.isArray(last.data.ids)) {
      saved = last.data.ids.slice();
      if (last.data.pages && typeof last.data.pages === "object") pageCounts = { ...last.data.pages };
    }
    byId("addon-catalog-line").textContent = snapshot.visible === true ? catalogLine() : "";
    if (sent) fillSent(sent);
    renderCards();
    syncPanels();
    renderOrphans();
    renderToolbarChoices();
    renderMainStatus();
    discoverIfOwed();
    renderBanner();
  }

  // THE ONE-TIME ANNOUNCEMENT (1.1.0). The first add-on the signed, CURRENT
  // catalog names that is not installed here and was never announced gets one
  // banner; its name and summary come from the catalog, as the panels' do, and
  // go in as text. Only where the manager is shown, unlocked, with Premium,
  // with no job running, and once the start-up read has landed ("announced" is
  // null until then, so nothing is announced twice). A stale (expired) list
  // announces nothing (plan review M-1). Try, Watch the tour and Not now each
  // answer it for good, and only once their own step has worked: the tour is
  // answered after its page has opened (plan review H-1), and its button shows
  // only where that page may be opened at all.
  const banner = byId("addon-banner");
  let bannerId = null;
  let bannerBusy = false;
  function announceable() {
    const catalog = snapshot.catalog || {};
    if (snapshot.visible !== true || !snapshot.unlocked || !snapshot.premium || snapshot.pending) return null;
    if (catalog.held !== true || catalog.stale === true || !Array.isArray(snapshot.announced)) return null;
    return named().find((a) => !a.installed && a.available && !snapshot.announced.includes(a.id)) || null;
  }
  function renderBanner() {
    if (!banner || bannerBusy) return;
    const addon = announceable();
    bannerId = addon ? addon.id : null;
    if (addon) {
      byId("addon-banner-name").textContent = addon.name;
      byId("addon-banner-try-name").textContent = addon.name;
      const summary = byId("addon-banner-summary");
      summary.textContent = addon.summary || "";
      summary.hidden = !addon.summary;
      byId("addon-banner-tour").hidden = snapshot.tour !== true;
    }
    banner.hidden = !addon;
  }
  // Records the answer; on failure the banner stays, so it can be answered again.
  async function answerBanner(id) {
    try {
      render(await request("addon_announced_set", { id }));
      return true;
    } catch (_) {
      return false;
    }
  }
  function onBanner(node, step) {
    if (!node) return;
    node.addEventListener("click", async () => {
      const id = bannerId;
      if (!id || bannerBusy) return;
      bannerBusy = true;
      try {
        if ((await step(id)) !== false) await answerBanner(id);
      } finally {
        bannerBusy = false;
        renderBanner();
      }
    });
  }
  onBanner(byId("addon-banner-try"), async (id) => {
    openPanelFor(id);
  });
  onBanner(byId("addon-banner-tour"), async () => {
    try {
      await request("site_page_open", { page: "premium_tour" });
      return true;
    } catch (_) {
      return false;
    }
  });
  onBanner(byId("addon-banner-later"), async () => true);

  // Found from the first unlock (hand test U-1: the toolbar button should be
  // there for a Premium user from the start). An add-on's button exists only
  // once its name is known, from the catalog or an install, so a Premium user
  // who never opened Add-ons had none. On the change INTO Premium (an unlock,
  // or an activation) one quiet refresh is owed: the job opening Add-ons runs,
  // and Rust still decides whether it becomes a request (`catalog_due`). It
  // waits until the saved list has been read (review R-036) and no job is
  // running (R-035), and it is dropped once a list is held, so it is asked
  // for until there is a list and never again after. It shows nothing: the
  // user asked for nothing.
  let wasPremium = false;
  let discoveryOwed = false;
  // The check while it is on its way: opening Add-ons then waits for it rather
  // than sending a second refresh that would be refused as busy (review R-038).
  let discovery = null;
  function onPremiumChange(st) {
    const premium = !!(st && st.premium);
    discoveryOwed = premium && (discoveryOwed || !wasPremium);
    wasPremium = premium;
    refresh();
  }
  function discoverIfOwed() {
    if (!discoveryOwed) return;
    const catalog = snapshot.catalog || {};
    if (snapshot.visible !== true || catalog.held === true) {
      discoveryOwed = false;
      return;
    }
    if (!snapshot.unlocked || snapshot.premium !== true || catalog.loaded !== true || snapshot.pending) return;
    // A backup import holds the slot without a job; chrome.js refreshes this
    // status when it finishes, which brings the check back here (R-042).
    if (snapshot.importing === true) return;
    discoveryOwed = false;
    discovery = request("addon_manager_action", { action: "refresh", id: "", confirmed: false })
      .then(render, (error) => {
        // A backup import holds the slot without a pending job: ask again at
        // the next status. Any other refusal is final until the next unlock.
        if (error && error.message === "busy") discoveryOwed = wasPremium;
      })
      .finally(() => {
        discovery = null;
      });
  }

  // A completed import replaces the vault and starts its session as an unlock
  // does, without the Premium change an unlock shows (review R-043): the check
  // is owed again, and the status refresh brings it back while no list is held.
  function backupFinished(data) {
    if (data && data.kind === "import" && data.ok === true && !data.lock_follows) discoveryOwed = wasPremium;
    return refresh();
  }

  async function panelAction(id, action) {
    exportsShownInAddons.delete(id);
    if (action === "unlock") {
      if (rb.openVault) rb.openVault();
      return;
    }
    await act(action, id);
  }

  async function act(action, suppliedId) {
    const id = suppliedId === undefined ? byId("addon-data-id").value : suppliedId;
    let confirmed = false;
    if (action === "export") confirmed = await askConfirm(text("addon-export-confirm"), text("addon-export"));
    if (action === "delete") confirmed = await askConfirm(text("addon-delete-confirm"), text("addon-delete"));
    if (action === "remove") confirmed = await askConfirm(text("addon-remove-confirm"), text("addon-remove"));
    if (["export", "delete", "remove"].includes(action) && !confirmed) return;
    try {
      // An export asks for a folder first and answers only once one is
      // chosen, so it must not run against the usual deadline.
      const state = await request(
        "addon_manager_action",
        { action, id, confirmed },
        action === "export" ? untilAnswered : undefined,
      );
      // A stopped export (usually the Vault locking) leaves the files it
      // already wrote, unencrypted: say so rather than only "cancelled".
      if (state.cancelled) {
        const line = action === "export" ? label.export_stopped() : label.cancelled();
        const panel = !exportsShownInAddons.has(id) && panels.get(id);
        (panel ? panel.parts.status : byId("addon-operation-status")).textContent = line;
      } else render(state);
    } catch (error) {
      byId("addon-operation-status").textContent = errorText(error.message);
    }
  }
  async function refresh() {
    try {
      render(await request("addon_manager_status", {}));
    } catch (error) {
      byId("addon-operation-status").textContent = errorText(error.message);
    }
  }
  // Opening Add-ons, or an add-on's own panel, refreshes: the saved-data list
  // and, with Premium, the catalog, in one job. Rust decides whether that
  // becomes a request to the license service (at most every 10 minutes,
  // every minute after a failed check).
  async function opened() {
    await refresh();
    // The check owed at unlock may have just gone out: it is this same job.
    if (discovery) return discovery;
    if (snapshot.visible === true && snapshot.unlocked && !snapshot.pending) act("refresh", "");
  }
  for (const node of root.querySelectorAll("button[data-addon-action]")) {
    node.addEventListener("click", () => act(node.dataset.addonAction));
  }
  const sentHost = byId("addon-whats-sent-host");
  if (sentHost) {
    sent = whatsSent();
    sentHost.appendChild(sent);
  }

  // The import warning offers this export before an import replaces the
  // pages (M12): the same confirmation, folder and result as the buttons here.
  window.__addons = {
    render,
    refresh,
    opened,
    backupFinished,
    exportPages: (id) => {
      exportsShownInAddons.add(id);
      return act("export", id);
    },
  };
  if (rb.onPremiumChange) rb.onPremiumChange(onPremiumChange);
  rebuildOnLocaleFill(() => render(snapshot));
  refresh();
})();
