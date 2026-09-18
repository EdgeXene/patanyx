"use strict";
(() => {
  // ---- IPC plumbing ---------------------------------------------------------
  // Request/response: window.ipc.postMessage({id, cmd, args}) ->
  // Rust replies via window.__rb_reply({id, ok, data|error}).
  // Unsolicited events arrive via window.__rb_event({event, data}).
  const pending = new Map();
  let nextId = 1;

  // Chrome window heights: tab strip + toolbar when closed, vault panel open.
  //
  // MEASURED, NOT ASSERTED. This used to be a hardcoded 148, derived by
  // measuring the two rows on ONE machine. That number is a claim about the
  // height of text rendered in `system-ui, "Segoe UI"` -- a font this code
  // does not ship and whose metrics differ per platform and per DPI setting.
  // On a Windows box where those two rows came out a few pixels taller than
  // the guess, the chrome document overflowed its own strip and WebView2 drew
  // a scrollbar down the side of the toolbar: a scrollbar on a fixed strip
  // with nowhere to scroll TO, which is pure defect.
  //
  // So the chrome measures itself and tells Rust what it actually needs. The
  // floor is the old constant, so a measurement taken before layout settles
  // can only ever be too generous, never clipping.
  const CHROME_CLOSED_FLOOR_PX = 148;
  // The same floor for either layout whose toolbar is down a side edge. One
  // row of pills leaves the top, so the strip is the tab row plus the address
  // row, and the honest floor is lower. Measured at 1280x800 in Chromium:
  // 41 + 47 = 88. Keeping the 148 floor here would have padded the page down
  // by 60px of nothing, in the layout the floor was raised to protect.
  const CHROME_CLOSED_FLOOR_LEFT_PX = 88;

  // `extra` is height showing BELOW the two fixed rows right now: a banner, or
  // an open folder menu. It is part of the measurement rather than something
  // added to the result, because the floor must be applied ONCE, to the whole.
  // Flooring the rows and then adding counts the slack between the measured
  // rows and the floor a second time; see the note at the call site in
  // `syncChromeInsets`.
  function closedChromePx(extra = 0) {
    const strip = $("tabstrip");
    const bar = $("toolbar");
    const floor = sidebarShowing()
      ? CHROME_CLOSED_FLOOR_LEFT_PX
      : CHROME_CLOSED_FLOOR_PX;
    // Nothing to measure yet, at boot. Reserve the room rather than lose it:
    // an unmeasured banner given no height is a banner drawn outside the
    // clipped strip, which is the defect BANNERS exists to prevent.
    if (!strip || !bar) return floor + extra;
    // The bookmarks bar is a THIRD row when it is showing, and it has to be
    // measured with the other two. A row the strip does not know about is
    // drawn outside it, which is the scrollbar-on-a-fixed-strip defect this
    // whole measurement exists to prevent. `hidden` rows measure 0, so this
    // needs no branch of its own.
    const marks = $("bmbar");
    const measured =
      strip.getBoundingClientRect().height +
      bar.getBoundingClientRect().height +
      (marks ? marks.getBoundingClientRect().height : 0);
    // Ceil, then the floor: a fractional layout height rounded DOWN is exactly
    // how you get one row of pixels clipped and a scrollbar to reach them.
    // `extra` joins the measurement BEFORE the floor, so the floor applies to
    // the whole height once.
    return Math.max(floor, Math.ceil(measured + extra));
  }
  // Everything showing BELOW the two fixed rows: banners, and an open folder
  // menu. Its own function because TWO callers need it and they must not
  // disagree -- `syncChromeInsets`, which tells Rust, and `publishChromeMetric`,
  // which tells the stylesheet. While only the first computed it, a toolbar
  // rewrap through the ResizeObserver refreshed the bare metric and left
  // `--chrome-strip-px` stale, and a panel positioned from the stale one opens
  // underneath the row it is meant to clear.
  //
  // An open folder menu grows the strip for the same reason banners do: the
  // chrome is CLIPPED to the height Rust was told, so anything drawn below
  // that height is not drawn at all. That is the lock-warning defect in a
  // different costume, and the fix is the same -- measure it and ask for the
  // room.
  //
  // Heights stay UNROUNDED. `closedChromePx` ceils the whole measurement once;
  // rounding each banner up first repeats, a pixel at a time, the mistake the
  // floor ordering was corrected for -- two banners of 48.25 round to 98 where
  // 96.5 was wanted, claiming 234 against a real bottom edge of 232.5.
  function bannerExtraPx() {
    let extra = 0;
    const folderMenu = document.querySelector(".bmfolder-menu");
    if (folderMenu) {
      extra += folderMenu.getBoundingClientRect().height + 8;
    }
    for (const id of BANNERS) {
      const banner = $(id);
      if (banner && !banner.hidden) {
        extra += banner.getBoundingClientRect().height;
      }
    }
    return extra;
  }
  // Whether the feature buttons are currently in either side strip. Read from
  // the DOM rather than from a variable so there is one answer: the attribute
  // IS the layout, and everything else -- the stylesheet, the measurement,
  // the inset -- keys off it.
  function sidebarShowing() {
    return ["left", "right"].includes(
      document.documentElement.dataset.toolbarPlacement,
    );
  }
  // What the chrome is using down the left edge. Zero unless that sidebar is
  // showing, and measured rather than assumed for the same reason the height
  // is: a width in this file would be a claim about padding and icon metrics
  // that the stylesheet is free to change.
  function closedChromeLeftPx() {
    const rail = $("sidebar");
    if (document.documentElement.dataset.toolbarPlacement !== "left" || !rail)
      return 0;
    return Math.ceil(rail.getBoundingClientRect().width);
  }
  function closedChromeRightPx() {
    const rail = $("sidebar");
    if (document.documentElement.dataset.toolbarPlacement !== "right" || !rail)
      return 0;
    return Math.ceil(rail.getBoundingClientRect().width);
  }
  // The stylesheet needs the same measurements: panels sit BELOW the chrome
  // and beside either sidebar, and a constant there is how their first line
  // ended up rendering under the toolbar (96px against a 148px chrome).
  // Published as CSS variables and kept current whenever a row or the rail
  // changes size. The observer is guarded: the DOM harness the gates run in
  // has no ResizeObserver, and the defaults in the stylesheet keep that
  // environment honest anyway.
  function publishChromeMetric() {
    const root = document.documentElement.style;
    root.setProperty("--chrome-closed-px", closedChromePx() + "px");
    // The banner-inclusive strip, from the SAME call the backend is given. The
    // ResizeObserver refreshes this too, so a toolbar rewrap that changes the
    // rows cannot leave a panel positioned from a stale one.
    root.setProperty(
      "--chrome-strip-px",
      closedChromePx(bannerExtraPx()) + "px",
    );
    root.setProperty("--chrome-left-px", closedChromeLeftPx() + "px");
    root.setProperty("--chrome-right-px", closedChromeRightPx() + "px");
  }
  // Deferred a tick: `$` is declared further down this file, so running the
  // measurement inline here would throw at boot and take the whole chrome
  // with it. One macrotask later the script has fully evaluated and the
  // toolbar exists. (Everything else in this section is only CALLED later,
  // which is why closedChromePx itself gets away with using `$`.)
  setTimeout(() => {
    publishChromeMetric();
    if (typeof ResizeObserver !== "undefined") {
      // syncChromeInsets, NOT publishChromeMetric. The observer used to
      // refresh the stylesheet and tell Rust nothing, so a toolbar rewrap left
      // the two holding different strip heights -- the page clipped to the old
      // one while the panel was placed against the new. Going through
      // syncChromeInsets updates both, and it re-publishes the variables on
      // the way, so there is still one writer for them.
      const ro = new ResizeObserver(() => syncChromeInsets());
      // THE BANNERS ARE OBSERVED TOO, and they were the bigger gap: only a
      // change in VISIBILITY re-measured, so an already-showing banner that
      // grew -- `applyUpdateChecked` swapping its text, a Fluent string
      // arriving late and rewrapping to a second line -- kept the old height.
      // The panel is placed from that number, so it would open across the
      // banner's new rows.
      for (const id of ["tabstrip", "toolbar", "bmbar", "sidebar", ...BANNERS]) {
        const el = $(id);
        if (el) ro.observe(el);
      }
    }
  }, 0);
  const CHROME_OPEN_PX = 500;
  // The privacy panel is four explained rows; it needs less room than the
  // vault's forms. Both stay under the Rust-side clamp in ipc.rs.
  const PRIVACY_OPEN_PX = 500;
  // Raised from 500 when Toolbar labels became a fourth section: at 500 the
  // new section sat below the fold, and the panel scrolls, so it "worked"
  // while being invisible to anyone who did not think to scroll a settings
  // card. Raised again when the same section gained the placement row, for
  // the same reason and with the same test -- open it and look at the
  // bottom. Sits under the Rust-side clamp ceiling (CHROME_TOP_RANGE in
  // platform/mod.rs, 80..=800) and under the modal max-height.
  const THEME_OPEN_PX = 760;

  // How long a command may go unanswered before its Promise is rejected.
  //
  // WHY THERE IS A TIMEOUT AT ALL. Rust drops any frame it cannot parse, and
  // does so without replying, because the id it would reply to is inside the
  // body it could not read. That is the right call there -- but this side
  // inserted into `pending` BEFORE posting and had no other way out, so every
  // such frame leaked a Promise that never settled and a Map entry that was
  // never removed. An `await` on one hung its caller forever: a spinner that
  // never stops, a form that never re-enables.
  //
  // Long enough not to fire during real work. The slowest command by far is a
  // vault unlock, which runs Argon2id at 64 MiB and t=3 twice; 30s is many
  // times that even on a slow machine.
  const RB_TIMEOUT_MS = 30000;

  function rb(cmd, args) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        if (!pending.delete(id)) return;
        reject(new Error("no_reply"));
      }, RB_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer });
      window.ipc.postMessage(JSON.stringify({ id, cmd, args: args || {} }));
    });
  }

  window.__rb_reply = (msg) => {
    if (!msg) return;
    const slot = pending.get(msg.id);
    if (!slot) return;
    pending.delete(msg.id);
    // Cleared on every settle path, or a reply that arrives normally would
    // still leave a 30-second timer holding its closure alive.
    clearTimeout(slot.timer);
    if (msg.ok) slot.resolve(msg.data);
    else slot.reject(new Error(msg.error || "unknown_error"));
  };

  // The locale fill: one snapshot, all marker strings, applied atomically
  // or not at all. Strictly-newer generations only -- a stale snapshot from
  // a raced switch must never paint a mixed-language UI. And COMPLETE
  // snapshots only: if any marker on this page is missing from the payload,
  // nothing is written and the generation is NOT committed, because a
  // partial fill is exactly the mixed-language page the generation gate
  // exists to prevent (fail closed, keep the old language, say so).
  //
  // Writes go through textContent and setAttribute alone. No innerHTML --
  // the release gate bans it in this webview, and these strings include
  // the product's privacy claims.
  let lastLocaleGeneration = 0;
  // Resolved non-English strings for the JS-rendered surfaces, keyed by
  // message id. Closure-local like everything else here; delivered by the
  // same fill snapshot the markup uses. EMPTY in an English session, and
  // i18nText then returns its second argument -- the literal in the code
  // IS the golden English, so an English build never pays a lookup that
  // could miss. A surface rendered before a locale switch keeps its old
  // words until it renders again; panels re-render on open, so the seam
  // is the strip between switch and next paint, and the markup (which the
  // applier repaints in place) never shows it.
  let localeJsStrings = {};
  // Structures built from i18nText at module load would freeze their
  // English forever -- the fill arrives after load. Anything holding
  // localized text in a module-level const registers a builder here; the
  // applier re-runs every builder after committing a snapshot, so the
  // structures follow the locale the way call-site lookups already do.
  const localeRebuilders = [];
  function rebuildOnLocaleFill(build) {
    localeRebuilders.push(build);
    build();
  }
  // Async twin of i18nText for strings whose arguments are born here
  // (confirm dialogs, local counts). English sessions return the composed
  // fallback synchronously-in-a-promise and never cross the bridge; other
  // locales resolve in Rust, where the plural logic lives. On any failure
  // the English fallback renders -- a dialog the user cannot read is worse
  // than one in the wrong language. Callers that must not double-fire
  // guard with their own per-action flag; this helper stays stateless.
  let currentUiLocale = "en";
  async function i18nResolve(id, args, english) {
    if (currentUiLocale === "en") return english;
    try {
      const r = await rb("i18n_resolve", { id, args: args || {} });
      return (r && typeof r.text === "string") ? r.text : english;
    } catch (e) {
      return english;
    }
  }
  // Render-then-patch for SYNC render paths with local arguments: the
  // English paints immediately (correct and final in an English session);
  // in any other locale the resolved text replaces it when the bridge
  // answers. The brief flash of English in a non-English session is the
  // same accepted seam as text rendered just before a locale switch.
  // Every write gets a token, and a resolve only lands if its token is still
  // the element's. Without it the async assignment was unconditional: render
  // host A, render host B before A's bridge call returns, and A's completion
  // overwrites B -- naming the wrong site in a live security warning. The
  // plain-HTTP banner is the caller that matters, since it interpolates a host
  // into a sentence the user is meant to act on. Ordered replies do not save
  // it, because the window between B's synchronous paint and A's late resolve
  // is still open, and a request that fails slowly can land after a newer one
  // succeeded.
  //
  // The token lives on the element rather than in a map so it cannot leak.
  // `i18nHold` is split out so a caller that clears an element by hand can
  // take ownership before doing so; nothing does that today -- its only
  // consumer was the removed issuer line -- and it stays because the next
  // hand-clear needs it and the reason is easy to miss.
  let i18nWriteToken = 0;
  function i18nHold(el) {
    el.__i18nToken = ++i18nWriteToken;
    return el.__i18nToken;
  }
  function i18nSet(el, id, args, english) {
    const mine = i18nHold(el);
    el.textContent = english;
    if (currentUiLocale !== "en") {
      i18nResolve(id, args, english).then((t) => {
        if (el.__i18nToken !== mine) return;
        el.textContent = t;
      });
    }
  }
  function i18nText(id, english) {
    const s = localeJsStrings[id];
    return typeof s === "string" ? s : english;
  }
  // ---- the language picker -----------------------------------------------
  // Buttons are built from ui_locale_get's list, so the control and the
  // binary cannot disagree about what is on offer. `active` follows the
  // same picker convention every other choice row uses.
  async function initLocalePicker() {
    const wrap = $("locale-buttons");
    if (!wrap) return;
    let info;
    try {
      info = await rb("ui_locale_get");
    } catch (e) {
      return; // no arm, no picker -- an old engine keeps a clean panel
    }
    const NAMES = { "en": "English", "en-XA": "Ẋá-test" };
    // The generated test locale is not OFFERED to users: l10n is the second
    // stable release's story, and a layout-stress locale in a stable
    // settings panel reads as a bug. It stays fully functional through
    // prefs and ui_locale_set for the harness and the hardware pass -- and
    // if it IS the active locale, it is listed so whoever put the session
    // there can find the way back. With one visible choice, the whole
    // section hides: a picker with nothing to pick is furniture.
    const visible = (info.available || []).filter(
      (tag) => !tag.endsWith("-XA") || tag === info.locale,
    );
    const section = $("locale-choice");
    if (section) section.hidden = visible.length < 2;
    if (visible.length < 2) return;
    wrap.textContent = "";
    for (const tag of visible) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "small";
      btn.textContent = NAMES[tag] || tag;
      btn.classList.toggle("active", tag === info.locale);
      btn.addEventListener("click", async () => {
        try {
          await rb("ui_locale_set", { locale: tag });
          for (const other of wrap.children) {
            other.classList.toggle("active", other === btn);
          }
        } catch (e) {
          toast(friendly(e), true);
        }
      });
      wrap.appendChild(btn);
    }
  }

  const LOCALE_ATTR_MARKERS = {
    "data-msg-title": "title",
    "data-msg-placeholder": "placeholder",
    "data-msg-aria-label": "aria-label",
    "data-msg-alt": "alt",
  };
  function applyUiLocaleFill(data) {
    const gen = Number(data.generation) || 0;
    if (gen <= lastLocaleGeneration) return;
    const messages = data.messages || {};
    // An empty or absent key is malformed markup, which is the sync gate's
    // to catch at build time; here it is skipped, not treated as missing,
    // so a defect in one marker cannot hold the whole language hostage.
    const key = (el, attr) => (el.getAttribute(attr) || "").replace(/\./g, "-");
    // Pass 1: completeness. Every keyed marker in THIS document must
    // resolve, or the snapshot is refused whole -- a partial fill is the
    // mixed-language page the generation gate exists to prevent.
    for (const el of document.querySelectorAll("[data-msg]")) {
      const k = key(el, "data-msg");
      if (k && !(k in messages)) return;
    }
    for (const marker of Object.keys(LOCALE_ATTR_MARKERS)) {
      for (const el of document.querySelectorAll("[" + marker + "]")) {
        const k = key(el, marker);
        if (k && !(k in messages)) return;
      }
    }
    // Pass 2: write.
    for (const el of document.querySelectorAll("[data-msg]")) {
      const k = key(el, "data-msg");
      if (k) el.textContent = messages[k];
    }
    for (const [marker, attr] of Object.entries(LOCALE_ATTR_MARKERS)) {
      for (const el of document.querySelectorAll("[" + marker + "]")) {
        const k = key(el, marker);
        if (k) el.setAttribute(attr, messages[k]);
      }
    }
    localeJsStrings = data.locale === "en" ? {} : messages;
    currentUiLocale = data.locale || "en";
    // Screen readers and hyphenation read the document's lang; it follows
    // the committed locale, and only the committed one.
    document.documentElement.setAttribute("lang", currentUiLocale);
    lastLocaleGeneration = gen;
    for (const build of localeRebuilders) build();
    // LAST, because the pass above has just reapplied every static
    // `data-msg-aria-label` in the document -- including the tab button's,
    // which would otherwise replace a live interception announcement with the
    // plain name and leave a dismissed warning with no trace a screen reader
    // can reach.
    applyTabButtonLabel();
  }

  window.__rb_event = (msg) => {
    if (!msg || typeof msg.event !== "string") return;
    switch (msg.event) {
      case "url_changed": {
        const url = (msg.data && msg.data.url) || "";
        urlInput.value = url === "about:blank" ? "" : url;
        // The page under the bar changed (navigation or tab switch, both
        // land here). The old session's highlights died with the page;
        // leaving the bar open would show a query and count describing a
        // page that no longer exists.
        closeFindBar();
        break;
      }
      case "tabs_changed":
        // Remembered so entering select mode can re-render the strip with
        // checkboxes immediately instead of waiting for the next
        // tabs_changed. Reorder replies enter through the same writer, so a
        // drop renders the canonical Rust order rather than trusting its DOM
        // preview.
        acceptTabItems((msg.data && msg.data.items) || []);
        break;
      case "find_open":
        openFindBar();
        break;
      // Phase 4: an activation or release call finished on its worker;
      // the row and the toolbar re-read the state from Rust.
      case "ui_locale_fill": {
        applyUiLocaleFill(msg.data || {});
        break;
      }
      case "licence_changed":
        void refreshLicence();
        break;
      case "find_state":
        onFindState(msg.data);
        break;
      // Ctrl+Shift+F, emitted by Rust so it works while a content webview
      // has focus. Toggled like every other panel: pressing it again while
      // the panel is open closes it.
      case "find_tabs_open":
        togglePanelNamed("findtabs");
        break;
      // Always re-render, even with the panel hidden: gating on open would
      // drop the completion that lands one frame after a close/reopen, and
      // painting a hidden list costs nothing.
      case "find_tabs_state":
        renderFindTabs(msg.data);
        break;
      // A goto from the panel started the ordinary find on the now-active
      // tab, so the ordinary bar takes over the interaction from here.
      // openFindBar re-sends find_start with the same query, which is
      // harmless BY CONSTRUCTION: FindSession::on_query returns Ignore for
      // a repeat of the live query, so no session restarts and no
      // highlight repaints.
      case "find_adopt":
        if (msg.data && typeof msg.data.query === "string") {
          findInput.value = msg.data.query;
          openFindBar();
          if (openPanelName === "findtabs") togglePanelNamed("findtabs");
        }
        break;
      // Ctrl+L. The key is caught natively (a focused page has no IPC), so
      // the chrome UI only has to move focus when told.
      case "focus_url_bar":
        urlInput.focus();
        urlInput.select();
        break;
      // A Rust-side failure on something the USER asked for, surfaced where
      // they can see it. Deliberately narrow: only user-initiated paths emit
      // this. A page's window.open() failing is dropped in Rust instead,
      // because a toast any site could provoke is a notification primitive.
      case "toast":
        toast(
          (msg.data && msg.data.text) || i18nText("chrome-js-ipc-toast-fallback", "Something went wrong."),
          !!(msg.data && msg.data.error),
        );
        break;
      // The right-click menu's copy actions used to arrive here as a
      // `copy_to_clipboard` event for this webview to write with
      // navigator.clipboard. They no longer do, and the handler is gone with
      // them: that API refuses to write from a document that is not focused,
      // and the focus is in the page the user right-clicked, never here, so
      // every copy failed. Rust owns the write now and reports the outcome
      // through the ordinary `toast` event above. Do not reintroduce a
      // clipboard write on this path.
      // Printing could not open a preview. state.rs emits this rather than
      // returning silently, with the comment "say so rather than appear to do
      // nothing -- an unexplained no-op is the failure this whole path
      // replaced" -- and then NOTHING IN THE CHROME LISTENED, so the honest
      // message went nowhere and the key was an unexplained no-op anyway. The
      // reason is worded by Rust; this only shows it.
      case "print_unavailable":
        if (msg.data && msg.data.reason) {
          i18nResolve(
            "chrome-js-ipc-print-reason",
            { reason: msg.data.reason },
            "Cannot print: " + msg.data.reason,
          ).then((t) => toast(t, true));
        } else {
          toast(
            i18nText("chrome-js-ipc-print-fallback", "Cannot print from this build."),
            true,
          );
        }
        break;
      // A login was submitted while the vault was locked, so nothing was
      // saved. Said out loud, because the alternative is what a tester
      // actually hit: log in, watch nothing happen, and have no way to tell a
      // locked vault from a browser that has stopped working.
      //
      // A plain toast, NOT `toast(text, true)`. The error variant recolours
      // the text as a failure, and this is the browser explaining itself
      // rather than reporting something the user did wrong. Rust rate-limits
      // it (LOCKED_SAVE_NOTICE_COOLDOWN) so a page that submits in a loop
      // cannot stack these up the side of the chrome.
      case "vault_locked_no_save":
        // The key stays on the SAME LINE as the call: build.rs scans for a
        // contiguous `i18nText("` and a wrapped one is invisible to it, so the
        // string would silently render English in every locale.
        toast(
          i18nText("chrome-js-toast-locked-no-save", "Password not saved. The vault is locked, so unlock it and sign in again to save it."),
        );
        break;
      case "vault_locked":
        // Hide the warning too: the thing it warned about has happened, and a
        // banner counting down to a lock that already occurred is worse than
        // no banner. (A second `case "vault_locked"` further down would have
        // been unreachable -- the first match in a switch wins -- so this is
        // the one place that handles it.)
        hideLockWarning();
        onLocked();
        break;
      case "bookmark_check_result":
        rememberSnapshotCheck(msg.data || {}, null);
        break;
      case "bookmark_check_error":
        rememberSnapshotCheck(
          msg.data || {},
          (msg.data && msg.data.code) || "io",
        );
        break;
      // Ctrl+K, resolved natively in Rust (shortcuts.rs) so it works while a
      // content webview has focus. Toggled like every other panel: pressing
      // it again while the palette is already open closes it, same as
      // pressing a toolbar pill a second time.
      case "open_command_palette":
        togglePanelNamed("palette");
        break;
      // The per-tab status feed. Nothing handled this and nothing emitted it,
      // so every per-tab indicator was frozen at its markup default — most
      // seriously the TLS-interception banner, which could never appear, and
      // the toolbar chip, which asserted "Live" for tabs that were frozen.
      case "tab_status":
        applyTabStatus(msg.data || {});
        break;
      // Rust cleared a blocked-site notice's record for a tab that gets no
      // tab_status (background navigation, tab closed): take it down.
      case "navigation_blocked_retired":
        if (msg.data && blockedTabId !== null && msg.data.tab_id === blockedTabId) hideBlocked();
        break;
      // The packs panel's live feed. The host emits this on every progress
      // tick and once an install ends -- and NOTHING was listening, so the
      // panel rendered whatever it happened to hold when the tab was opened:
      // a percentage frozen at its first value, a finished install still
      // claiming to download, and a FAILED one indistinguishable from a
      // running one. Exactly the defect described two cases above, one event
      // later.
      case "packs_status":
        // VALIDATED HERE, ONCE, because ten call sites read
        // `translatePacks.languages` and guarding them individually does not
        // hold: a first attempt guarded two of them and the panel still threw
        // `TypeError: reading 'slice'` from a third. A payload without an
        // array of languages -- a truncated or errored host reply, or `{}` --
        // is not a pack list, and treating it as absent degrades the section
        // instead of taking it down.
        translatePacks =
          msg.data && Array.isArray(msg.data.languages) ? msg.data : null;
        renderTranslateUi();
        break;
      case "load_state":
        document.body.classList.toggle(
          "loading",
          !!(msg.data && msg.data.loading),
        );
        break;
      case "download_started": {
        const name = fileNameFromUrl(msg.data && msg.data.url);
        i18nResolve(
          "chrome-js-toast-downloading",
          { name },
          "Downloading " + name + "...",
        ).then((t) => toast(t));
        break;
      }
      case "download_finished": {
        const data = msg.data || {};
        if (data.success) {
          const name = fileNameFromPath(data.path) || fileNameFromUrl(data.url);
          // data.mark is what happened to the file's Mark-of-the-Web (see
          // platform/motw.rs). Only "failed" is worth a word: "scrubbed"
          // is the normal case on Windows and "clean" or "n/a" mean there
          // was nothing to do. A failure means the source address is still
          // written next to the file, and that is said plainly rather than
          // hidden behind an ordinary "Saved".
          if (data.mark === "failed") {
            i18nResolve(
              "chrome-download-mark-failed-body",
              { name },
              "Saved " + name + ", but Windows kept the download's source " +
                "address next to the file and it could not be removed.",
            ).then((t) => toast(t, true));
            // "unknown" here is the WIRE TOKEN from Rust, never a display
            // string: comparing against a localized word would break this
            // branch in any non-English session.
          } else if (data.mark === "unknown") {
            // NOT the same sentence as "failed". That one asserts the
            // address is there; this one says only that it could not be
            // checked, which is the honest limit of what the browser knows.
            i18nResolve(
              "chrome-download-mark-unknown-body",
              { name },
              "Saved " + name + ". PATANYX could not check whether Windows " +
                "wrote the download's source address next to it.",
            ).then((t) => toast(t, true));
          } else {
            i18nResolve("chrome-js-toast-saved", { name }, "Saved " + name).then(
              (t) => toast(t),
            );
          }
        } else {
          toast(i18nText("chrome-js-toast-download-failed", "Download failed"), true);
        }
        break;
      }
      // Both of these were emitted by Rust and silently dropped by the
      // default branch below. The list simply never refreshed, and a failed
      // provenance write -- the record `download_verify` later reads -- was
      // reported to nobody.
      // A finished OCR scan. The command that started it returned only a
      // token, because the work is about a second and the event loop cannot
      // be held that long -- see ocr_support.rs.
      case "update_checked":
        applyUpdateChecked(msg.data);
        break;
      case "zoom_changed":
        applyZoom(msg.data);
        break;
      // Ctrl+= / Ctrl+- / Ctrl+0 with a modal open. Routed here BY RUST:
      // our own accelerator handler on this webview marks those keys handled
      // before this document ever sees a keydown, so an event from the other
      // side of the IPC is the only spelling of "zoom the panel" that can
      // actually work. See zoom_active in state.rs and the note above the
      // wheel listener.
      case "panel_zoom":
        stepPanelZoom(msg.data && msg.data.dir | 0);
        break;
      case "navigation_blocked":
        applyNavigationBlocked(msg.data);
        break;
      case "resolver_state":
        applyResolverState(msg.data);
        break;
      // Rust re-asks the engine question after an update check, because a
      // verified manifest can raise the floor mid-session. Same renderer as
      // the boot reply; only pushed when the answer is "below".
      case "engine_state":
        applyEngineState(msg.data);
        break;
      // Rust has emitted this since the blocklist gained a refresh schedule.
      // NOTHING listened. The whole malicious-site subsystem reported its
      // health into a void: a refresh that failed left the browser running on
      // a stale list, or on the bundled floor, and said nothing -- while the
      // Updates panel truthfully told the user this check happens about once
      // an hour. It happened. It just never reported back.
      case "blocklist_refreshed":
        applyBlocklistRefreshed(msg.data);
        break;
      case "vault_lock_warning":
        showLockWarning(msg.data && msg.data.seconds);
        break;
      // A content tab's form was submitted. The event itself carries only
      // {origin, username} -- never the password, which stays in Rust -- so
      // it is not enough to drive applyTabStatus on its own; fetch the full
      // status, whose `pending_save` field is what actually renders the
      // banner. Same shape whether this event fires or the next ordinary
      // tab_status push happens to land first.
      case "login_submit_detected":
        rb("tab_status")
          .then(applyTabStatus)
          .catch(() => {});
        break;
      case "ocr_result":
        if (window.__rb_ocr) window.__rb_ocr(msg.data || {});
        break;
      // The region-read capture settled (well or badly). Function-declared
      // below and hoisted, same file, so no window hook is needed.
      case "region_capture_ready":
        onRegionCaptureReady(msg.data || {});
        break;
      // A contact asked what WE downloaded, and this browser answered
      // automatically. Surfaced unconditionally: an automatic reply the
      // user cannot see is the shape of a backdoor even when it is not one.
      case "download_compare_request_received":
        {
          const host = hostOf((msg.data && msg.data.url) || "");
          i18nResolve("chrome-compare-request-toast", { host },
            "A contact asked what you downloaded from " + host +
              ". Your record's fingerprint was sent back.",
          ).then((t) => toast(t));
        }
        break;
      case "archive_saved":
        onArchiveSaved(msg.data || {});
        break;
      case "download_compare_verdict":
        renderCompareVerdict(msg.data || {});
        break;
      case "download_compare_note":
        renderCompareNote(msg.data || {});
        break;
      case "download_compare_error":
        renderCompareNote({
          reason: (msg.data && msg.data.code) || "bad_message",
        });
        break;
      case "downloads_changed":
        if (openPanelName === "library") refreshDownloads();
        break;
      case "download_record_failed":
        toast(
          i18nText("chrome-js-toast-record-failed", "Saved the file, but could not record it. Verification will not be available for this download."),
          true,
        );
        break;
      // Chat events are handled by chat.js, which is evaluated only in chat
      // builds and registers its handlers on window.__rb_chat. Each name is
      // cased explicitly because the default branch deliberately drops
      // anything unknown — an uncased chat event would silently die here.
      case "chat_peer_state":
      case "chat_message":
      case "chat_delivery":
      case "chat_notice":
      case "chat_discovery":
      case "chat_tab_received":
      case "chat_credential_offered":
      case "chat_state":
      case "chat_presence":
      case "chat_relay_state":
      case "chat_down": {
        const handlers = window.__rb_chat;
        const handler = handlers && handlers[msg.event];
        if (handler) handler(msg.data || {});
        break;
      }
      default:
        break;
    }
  };

  // ---- helpers ---------------------------------------------------------------
  const $ = (id) => document.getElementById(id);

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  let ERROR_TEXT;
  rebuildOnLocaleFill(() => {
    ERROR_TEXT = {
      // NOT "or the vault file is damaged". A damaged file has its own code
      // and its own message (bad_format); by the time AuthFailed is raised the
      // file has been READ AND ITS SLOTS PARSED, and only the key derivation
      // failed. The old wording told a user their vault might be corrupt in
      // the one case the code had just proved it was not, and it caused
      // a genuine scare during a hardware test.
      auth_failed: i18nText("chrome-js-error-auth-failed", "Wrong passphrase. The vault file was read fine and nothing was changed."),
      unknown_locale: "This build does not carry that language",
      unknown_message: i18nText("chrome-js-error-unknown-message", "This build does not carry that text"),
      premium_language_required: i18nText("chrome-js-error-premium-required-language", "This language needs PATANYX Premium active on this device."),
      pivot_language: i18nText("chrome-js-error-pivot-language", "English comes with every language pack and is not installed on its own."),
      invalid_catalog: "This build's language data is damaged",
      bad_format: i18nText("chrome-js-error-bad-format", "That vault file is damaged or unreadable"),
      vault_newer: i18nText("chrome-js-error-vault-newer", "This vault was saved by a newer PATANYX than this build. Nothing is wrong with it. Open it with the newer build."),
      not_unlocked: i18nText("chrome-js-error-not-unlocked", "Vault is locked"),
      not_found: i18nText("chrome-js-error-not-found", "Item not found"),
      capture_engine_failed: i18nText("chrome-js-error-capture-engine-failed", "The page could not be captured"),
      capture_decode_failed: i18nText("chrome-js-error-capture-decode-failed", "The capture was not a readable PNG"),
      capture_preview_failed: i18nText("chrome-js-error-capture-preview-failed", "The page was captured, but its preview could not be prepared"),
      region_too_large: i18nText("chrome-js-error-region-too-large", "This page or selection is too large to read safely. Try a shorter page, or zoom in and select a smaller area."),
      fetch_failed: i18nText("chrome-js-error-fetch-failed", "The page could not be fetched for comparison. Check the connection and try again."),
      io: i18nText("chrome-js-error-io", "Could not read or write to this computer's storage"),
      library_not_replaced: i18nText("chrome-js-error-library-not-replaced", "The previous profile's Library could not be replaced, so bookmarks, Tab Shelf, and download records are unavailable. The imported vault and its passwords are still available."),
      library_replace_refused: i18nText("chrome-js-error-library-replace-refused", "The Library could not be prepared for safe replacement, so the vault was not imported."),
      too_large: i18nText("chrome-js-error-too-large", "That file is too big to be a bookmarks export"),
      no_capture_page: i18nText("chrome-js-error-no-capture-page", "Nothing to capture on this page"),
      capture_failed: i18nText("chrome-js-error-capture-failed", "The capture failed; nothing was saved"),
      // Whole-page capture has no size bound of its own, so a very long page
      // can exceed what this browser will hold at once. Named separately from
      // capture_failed because the remedy differs: this one has a cause the
      // user can act on.
      capture_too_large:
        i18nText("chrome-js-error-capture-too-large", "This page is too large to capture whole. Try a smaller window or a zoomed-in selection."),
      busy: i18nText("chrome-js-error-busy", "A capture is already in progress"),
      no_storable_tabs:
        i18nText("chrome-js-error-no-storable-tabs", "No tabs can be shelved. Ephemeral and internal tabs are skipped."),
      // The restart did not happen and nothing was lost: the session was put
      // back exactly as it was, so the honest thing to offer is the old
      // manual route rather than a retry that would fail the same way.
      relaunch_failed:
        "PATANYX could not start a replacement, so nothing was changed. " +
        "Close the browser and open it again to apply the tunnel setting.",
      bad_args: i18nText("chrome-js-error-bad-args", "That does not look right"),
      // Find across tabs is the first premium-gated feature. The panel ALSO
      // un-hides a standing note on this code -- a toast alone would vanish
      // and leave the run button looking broken.
      premium_required: i18nText("chrome-js-error-premium-required", "Find across tabs requires Premium."),
      // Site permissions. `bad_origin` is reachable from a real page: an
      // opaque or sandboxed document has no site to attach a permission to, so
      // there is nothing the user could allow even in principle. Say that,
      // rather than implying they mistyped something.
      unknown_permission: i18nText("chrome-js-error-unknown-permission", "That is not a permission this browser controls"),
      bad_origin:
        i18nText("chrome-js-error-bad-origin", "This page has no site address to allow, so nothing can be changed here"),
      vault_exists: i18nText("chrome-js-error-vault-exists", "A vault already exists"),
      recovery_exists:
        "This vault already has a recovery key. There can only be one, and " +
        "you were shown it when it was made.",
      // Chat codes (chat_panel.rs). peer_offline is a designed refusal — the
      // message is refused, never queued — so it must not read like a fault
      // the user should retry blindly.
      peer_offline:
        i18nText("chrome-js-error-peer-offline", "They are not on this network right now. Nothing was sent, and nothing is waiting"),
      no_session: i18nText("chrome-js-error-no-session", "You are not connected to this person right now"),
      too_long: i18nText("chrome-js-error-too-long", "Message is too long"),
      chat_down: i18nText("chrome-js-error-chat-down", "Chat is not available right now"),
      // The held-page banner's refusals (adlist_consent.rs). Without these a
      // stale click toasted the raw identifier (launch sweep F-004).
      adlist_no_pending: i18nText("chrome-js-error-adlist-no-pending", "That page is no longer held"),
      adlist_stale_banner: i18nText("chrome-js-error-adlist-stale-banner", "This notice is out of date. Try again from the page"),
      adlist_host_mismatch: i18nText("chrome-js-error-adlist-host-mismatch", "The page moved to a different site; nothing was allowed"),
      adlist_not_listed: i18nText("chrome-js-error-adlist-not-listed", "That site is no longer on the list, so nothing needs allowing"),
      adlist_no_exception: i18nText("chrome-js-error-adlist-no-exception", "Opening anyway is not available on this platform"),
      blocked_stale: i18nText("chrome-js-error-blocked-stale", "That notice is out of date. Try the page again"),
      passphrase_changed_backups_retained: i18nText("chrome-js-error-passphrase-changed-backups-retained", "Passphrase changed, but an older backup beside the vault could not be removed and still opens with the old passphrase. Delete it by hand"),
      passphrase_change_unavailable: i18nText("chrome-js-error-passphrase-change-unavailable", "Changing the passphrase is not available in this version. Your recovery key and current passphrase keep working"),
      duplicate_contact: i18nText("chrome-js-error-duplicate-contact", "You already have a contact with that number"),
      // Its own code rather than bad_args: the requirement is not guessable
      // from "Invalid input", and a well-formed http:// address is exactly the
      // thing a user reaches for. TLS is mandatory in the protocol.
      // OCR runs locally; there is no service to be down, so every one of these
      // is about the file or the install, never about a network.
      ocr_unavailable:
        i18nText("chrome-js-error-ocr-unavailable", "Text recognition is not available in this build. The model files are not installed."),
      ocr_failed:
        i18nText("chrome-js-error-ocr-failed", "Could not read any text in that picture. A sharper, straighter, better lit one usually works."),
      bad_image:
        i18nText("chrome-js-error-bad-image", "That file is not a picture PATANYX can read. Try a PNG or JPEG."),
      // The region-read mode's own refusals. Stale is a state, not a fault:
      // the capture this panel was looking at has been replaced or released,
      // and capturing again is the whole remedy.
      // Download corroboration, asking side. Both are about OUR OWN record,
      // not the contact's: the contact's refusals arrive as notes, worded
      // separately, because "you have no record of this" and "they have no
      // record of this" are different sentences and must not share one.
      no_download: i18nText("chrome-js-error-no-download", "There is no record of that download to compare."),
      record_untrusted:
        i18nText("chrome-js-error-record-untrusted", "Your own record of this download failed its integrity check, so its fingerprint cannot be trusted. Nothing was sent."),
      // Deep Recall. Its own sentence rather than a generic "full": the user
      // can act on this, and the action is to delete something first.
      archive_full:
        i18nText("chrome-js-error-archive-full", "Deep Recall is full. Delete a saved page to make room for this one."),
      region_stale: i18nText("chrome-js-error-region-stale", "That capture expired. Capture the page again."),
      region_empty: i18nText("chrome-js-error-region-empty", "Drag a rectangle around the text to read."),
      region_out_of_bounds:
        i18nText("chrome-js-error-region-out-of-bounds", "That selection is outside the capture. Drag inside the image."),
      bad_relay_url:
        i18nText("chrome-js-error-bad-relay-url", "The relay address has to start with wss://. Encrypted connections only, so http:// and ws:// are refused."),
      // Every code Rust can return must appear here, or friendly() renders the
      // raw identifier. bad_recovery_key was reachable on the vault's
      // last-resort path and showed the user "Unexpected error:
      // bad_recovery_key" when they mistyped their recovery key.
      bad_recovery_key:
        i18nText("chrome-js-error-bad-recovery-key", "That recovery key is not right. Check for typos. Capitals do not matter and the dashes are optional."),
      no_recovery_slot:
        i18nText("chrome-js-error-no-recovery-slot", "This vault has no recovery key. It was set up without one, so your passphrase is the only way in."),
      export_auth_failed: i18nText("chrome-js-error-export-auth-failed", "Wrong export passphrase, or the file is corrupt."),
      bad_export: i18nText("chrome-js-error-bad-export", "That file is not a PATANYX vault export."),
      export_not_confirmed: i18nText("chrome-js-error-export-not-confirmed", "Type the confirmation sentence exactly to continue."),
      target_is_vault:
        i18nText("chrome-js-error-target-is-vault", "That path is your live vault. Choose a different destination."),
      store_bad_format:
        i18nText("chrome-js-error-store-bad-format", "The bookmarks file is unreadable or was written by something else."),
      no_page: i18nText("chrome-js-error-no-page", "This page has not finished loading yet."),
      no_page_bytes: i18nText("chrome-js-error-no-page-bytes", "This build cannot read the page's content."),
      no_snapshot: i18nText("chrome-js-error-no-snapshot", "No snapshot saved for this page yet."),
      managed_by_flatpak:
        i18nText("chrome-js-error-managed-by-flatpak", "Updates for this installation are delivered by Flatpak. Install it from your software center, or run: flatpak update io.edgexene.Patanyx"),
      vault_in_use:
        i18nText("chrome-js-error-vault-in-use", "This vault is already open in another PATANYX window. Close that window and try again -- two copies open at once would each overwrite the other's changes."),
      not_bookmarked:
        i18nText("chrome-js-error-not-bookmarked", "Bookmark this page first. Snapshots are kept with the bookmark."),
      unsupported: i18nText("chrome-js-error-unsupported", "Not available on this platform."),
      offline:
        i18nText("chrome-js-error-offline", "You are offline. Go online from the Chat panel to reach contacts."),
      relay_unavailable: i18nText("chrome-js-error-relay-unavailable", "Relay support is not compiled into this build."),
      store_needs_passphrase:
        i18nText("chrome-js-error-store-needs-passphrase", "Bookmarks and downloads are encrypted with your passphrase, so they stay locked when you get in with a recovery key. Unlock with the passphrase to see them."),
      // FOUR CODES THAT RENDERED AS "Unexpected error: <identifier>".
      //
      // The claim above ("Every code Rust can return must appear here") and the
      // matching one in ipc.rs were both false: no_tab, not_ready and
      // install_failed have been reachable and unrenderable. There is now a test
      // in ipc.rs that fails when a code is missing from this table, so the
      // claim is enforced rather than repeated.
      no_tab: i18nText("chrome-js-error-no-tab", "No active tab. Open or select one, then try again."),
      not_ready:
        i18nText("chrome-js-error-not-ready", "The update has not finished downloading and verifying yet. Wait for it to complete, then try again."),
      install_failed:
        i18nText("chrome-js-error-install-failed", "The verified update could not be installed. The downloaded file is kept, so you can try again."),
      // The engine refused to create a webview -- out of memory, a lost GPU
      // process, or a WebView2 runtime problem. Says what to do, because
      // "engine error" leaves the user with nothing.
      tab_failed:
        i18nText("chrome-js-error-tab-failed", "The engine could not open the tab. Close some tabs and try again. If it repeats, restart PATANYX."),
      // Found by the parity test, not by hand. chat.js has a `link_lost` entry
      // already, but that table renders DELIVERY status on a message row; this
      // code also comes back as the reply to `chat_send` itself, which goes
      // through friendly() and had no text at all. Two channels, one code.
      link_lost:
        i18nText("chrome-js-error-link-lost", "The connection to that contact dropped. Reopen the conversation and try again."),
      // Client-side, not from Rust: rb() gave up waiting. Rust drops frames it
      // cannot parse without replying, so this is what that looks like from
      // here. Phrased as "no answer" rather than "failed" because the command
      // may well have run -- what is known is only that nothing came back.
      no_reply:
        i18nText("chrome-js-error-no-reply", "The browser did not answer that in time. Nothing may have changed; check before trying again."),
      // Site-info's "Forget this site". no_site is a real, expected outcome --
      // about:blank, an internal page, or anything else with no http(s)
      // authority -- not a fault; phrased as a statement, not an apology.
      no_site: i18nText("chrome-js-error-no-site", "This page has no site to forget."),
      cookie_delete_failed:
        i18nText("chrome-js-error-cookie-delete-failed", "Could not clear cookies for this site. The engine refused the request; nothing was changed."),
      // The browser-wide clear's own failures. Separate codes from the per-site
      // ones above because the sentences differ: "for this site" is false here,
      // and no_persistent_tab is not a fault at all.
      cookie_delete_all_failed:
        i18nText("chrome-js-error-cookie-delete-all-failed", "Could not clear cookies. The engine refused the request; nothing was changed."),
      // Not built for this backend (WebKitGTK, 1.0.0). The engine was never
      // asked, so neither sentence above may be used for it: both blame the
      // engine for a refusal that happened before it.
      cookie_clear_unavailable:
        i18nText("chrome-js-error-cookie-clear-unavailable", "Clearing cookies is not available on this platform in this release. Nothing was changed."),
      // Expected, not broken: quarantine tabs keep their cookies in memory and
      // throw them away when they close, so there is genuinely nothing saved to
      // clear. Says what to do rather than only what went wrong.
      no_persistent_tab:
        i18nText("chrome-js-error-no-persistent-tab", "All open tabs are quarantine tabs, so no cookies are saved. Open an ordinary tab to clear saved cookies."),
      // Inline credential autofill. no_pending_save fires if Save/Never is
      // clicked twice (e.g. a double click) -- the first click already
      // resolved it, so the second has nothing left to act on.
      no_pending_save: i18nText("chrome-js-error-no-pending-save", "There is no password waiting to be saved."),
      // Refused rather than silently skipped: the tab navigated between
      // showing the fill offer and the click, so filling now would put a
      // saved password into a different site than the one it was saved for.
      origin_mismatch:
        i18nText("chrome-js-error-origin-mismatch", "The open site does not match this saved password. Open the matching site, then try again."),
      fill_failed: i18nText("chrome-js-error-fill-failed", "Could not fill that password into the page."),
    };
  });

  function friendly(err) {
    const code = err && err.message;
    return ERROR_TEXT[code] || "Unexpected error" + (code ? ": " + code : "");
  }

  // Shared with chat.js, which is evaluated as a SEPARATE script and so cannot
  // reach inside this closure. Sharing the request helper is what lets chat.js
  // avoid running a second reply table on a disjoint id range — collision-free
  // only by assumption — and keeps ONE error vocabulary instead of two copies
  // drifting apart.
  // `registerPanel` is shared too, so chat.js joins the same one-panel-at-a-time
  // rotation instead of running a fourth independent toggle that could leave two
  // panels open fighting over the chrome height.
  initLocalePicker().catch(() => {});

  window.__rb = {
    request: rb,
    friendly,
    registerPanel: (name, spec) => registerPanel(name, spec),
    // Shared for the same reason `request` and `friendly` are: chat.js is a
    // separate script and must ask its destructive question with the same
    // dialog, not fall back to the engine's window.confirm and reintroduce
    // the rbchrome:// title this replaced.
    askConfirm: (message, confirmLabel) => askConfirm(message, confirmLabel),
    // The catalog helpers, shared for the same reason again: integrity.js,
    // update.js and chat.js render user-facing sentences and must resolve
    // them from the same catalog with the same locale, not carry a second
    // English of their own. This is the CHROME document -- pages live in
    // other webviews and cannot reach it -- so the exposure hands nothing
    // to a site.
    i18nText,
    i18nResolve,
    i18nSet,
    rebuildOnLocaleFill,
    // Shared so chat.js and integrity.js explain a `premium_required` refusal
    // with the SAME sentence the toolbar pill and the panel notes use (locked
    // vault / not on sale yet / lapsed / upgrade), instead of the tab pack's
    // wording that `friendly` maps the code to. Both are defined further
    // down; arrow wrappers so the late binding is fine.
    premiumBlocked: () => premiumBlocked(),
    premiumLockNote: () => premiumLockNote(premiumState),
    premiumActive: () => premiumState.premium === true,
    // Fired from applyPremiumState on EVERY refresh, including the one that
    // licence_changed triggers. Chat's standing note used to re-render only
    // when its pane changed, so a token pasted while the panel was open left
    // "Add your Premium token" on screen until the panel was reopened.
    onPremiumChange: (fn) => premiumListeners.push(fn),
  };

  // ---- element handles ---------------------------------------------------------
  const urlInput = $("url");
  const panel = $("vault-panel");
  const statePanes = {
    none: $("vault-none"),
    recovery: $("vault-recovery"),
    locked: $("vault-locked"),
    open: $("vault-open"),
  };
  const credListEl = $("cred-list");
  const noteListEl = $("note-list");

  // Chrome strip heights for the two panels merged in from separate drafts.
  // These, and the state below, were lost when their functions were spliced
  // in without their declarations: under "use strict" the first read threw a
  // ReferenceError at load, which aborted the file before the tab and library
  // panels were ever registered — so both toolbar buttons silently did
  // nothing. Kept next to the other panel constants so the next splice has to
  // notice them.
  const TAB_OPEN_PX = 500;
  const LIBRARY_OPEN_PX = 548;
  // The resolver panel was 300px when it held three buttons and two notes. It
  // now carries a three-way comparison, and a panel whose whole purpose is
  // helping the user decide must not make them scroll to find the third
  // option. Same budget as the privacy panel, and still under the Rust-side
  // clamp in ipc.rs.
  const DNS_OPEN_PX = 500;

  // ---- per-tab panel state ----
  let lastTabStatus = null;
  // The origin the "Forget this site" confirm dialog is currently asking
  // about. Tracked separately from `lastTabStatus.origin` so a change can be
  // detected: switching tabs or navigating must close an open confirmation
  // rather than leave it answerable against whatever site is now showing --
  // otherwise "Forget this site?" opened for site A could be confirmed after
  // the user had moved on to site B, deleting B's cookies while believing
  // they were still looking at A's prompt.
  let lastForgetOrigin;
  // Per-tab interception state, mirrored so the ledger's empty state can
  // tell "nothing happened" apart from "nothing was watching".
  let lastTabInterception;
  let activeTabId = null;
  // Mirror of the hosts we have asked Rust to allow while frozen, keyed by
  // tab id. The platform exposes no read-back of the override set, so this is
  // what we sent, not what is in force — truthful only because this UI is the
  // only thing that can send it.
  let allowedHosts = new Map();
  let lastLedger = [];
  let ledgerTimer = null;

  // ---- library panel state ----
  let bookmarkItems = [];
  // Library-only, memory-only compare state. Stored passages arrive only
  // while the vault is open and this entire cache is cleared on vault lock.
  const snapshotCheckResults = new Map();
  const snapshotChecksPending = new Set();
  const snapshotSelections = new Map();
  // Known folder names from bookmark_list's `folders` reply. Kept separate
  // from the tags carried on bookmarks so an EMPTY folder -- one made but not
  // yet filled -- still shows up. The union of the two is what the organizer
  // renders.
  let bookmarkFolderNames = [];
  // The id of the bookmark currently being dragged, or null. A module-level
  // flag rather than dataTransfer: the drop target can read it during
  // `dragover` (where dataTransfer contents are not readable on either
  // engine), and the internal bookmark id never rides in text/plain where a
  // drop onto some other app could carry it away.
  let draggedBookmarkId = null;
  let downloadItems = [];
  let editingBookmark = null;
  const btnBookmark = $("btn-bookmark");

  // ---- backup pane state ----
  let plaintextSentence = "";

  // ---- local UI state ----------------------------------------------------------
  let credItems = [];
  let noteItems = [];
  let editingCred = null;
  let editingNote = null;
  const revealed = new Map(); // credential id -> password currently shown

  // ---- tab strip -----------------------------------------------------------------
  $("btn-newtab").addEventListener("click", () => {
    // No urlInput.focus() here. It used to be, and it ran BEFORE Rust built
    // the tab and (on Windows) focused the new content webview, so the
    // cursor never landed in the bar. Rust now emits focus_url_bar itself
    // once the blank tab is showing -- one path for the button, Ctrl+T and
    // the last-tab-closed fresh tab alike.
    rb("tab_new").catch(() => {});
  });

  function hostOf(url) {
    const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]+)/.exec(url);
    return match ? match[1] : url;
  }

  function chipLabel(tab) {
    const title = (tab.title || "").trim();
    if (title) return title;
    if (!tab.url || tab.url === "about:blank") return i18nText("chrome-js-tabs-new-tab", "New tab");
    return hostOf(tab.url);
  }

  let lastTabItems = []; // last canonical tab payload from Rust
  // Stable id held in module state for the lifetime of one drag. Nothing is
  // placed in dataTransfer: tab ids are internal chrome addresses and must
  // not ride in a payload that can be dropped into another application.
  let draggedTabId = null;

  function acceptTabItems(items) {
    lastTabItems = Array.isArray(items) ? items : [];
    renderTabs(lastTabItems);
  }

  function tabDomIds(wrap) {
    return Array.from(wrap.children || [])
      .map((chip) => Number(chip.dataset && chip.dataset.tabId))
      .filter((id) => Number.isSafeInteger(id));
  }

  function reorderedTabIds(ids, draggedId, targetId, afterTarget) {
    if (
      draggedId === targetId ||
      ids.indexOf(draggedId) < 0 ||
      ids.indexOf(targetId) < 0
    ) {
      return ids.slice();
    }
    const next = ids.filter((id) => id !== draggedId);
    const target = next.indexOf(targetId);
    next.splice(target + (afterTarget ? 1 : 0), 0, draggedId);
    return next;
  }

  function putTabDomInOrder(wrap, ids) {
    const byId = new Map(
      Array.from(wrap.children || []).map((chip) => [
        Number(chip.dataset && chip.dataset.tabId),
        chip,
      ]),
    );
    for (const id of ids) {
      const chip = byId.get(id);
      if (chip) wrap.appendChild(chip);
    }
  }

  function previewTabReorder(wrap, targetChip, ev) {
    const ids = tabDomIds(wrap);
    const box = targetChip.getBoundingClientRect();
    const pointer = typeof ev.clientX === "number" ? ev.clientX : box.left;
    const after = pointer >= box.left + box.width / 2;
    const next = reorderedTabIds(
      ids,
      draggedTabId,
      Number(targetChip.dataset.tabId),
      after,
    );
    putTabDomInOrder(wrap, next);
    return next;
  }

  async function persistTabOrder(ids, focusId) {
    try {
      const reply = await rb("tab_reorder", { ids });
      if (!reply || !Array.isArray(reply.items)) throw new Error("bad_reply");
      // The dragover order was only a preview. Rust has revalidated the full
      // permutation and this is its canonical order, including active flags.
      acceptTabItems(reply.items);
      if (focusId !== undefined && focusId !== null) {
        const chip = Array.from($("tabs").children || []).find(
          (candidate) => Number(candidate.dataset.tabId) === focusId,
        );
        if (chip) chip.focus();
      }
    } catch (e) {
      // A concurrent open/close makes the preview stale. Restore the latest
      // authoritative list; the refused permutation changed no Rust state.
      renderTabs(lastTabItems);
      toast(friendly(e), true);
    }
  }

  function renderTabs(items) {
    const wrap = $("tabs");
    wrap.textContent = "";
    if (tabSelectMode) {
      // A tab closed since it was ticked must not stay selected: the
      // count would name tabs that no longer exist and the batch actions
      // would aim at ids that can only fail.
      const live = new Set();
      for (const tab of items || []) live.add(tab.id);
      for (const id of Array.from(tabSelection)) {
        if (!live.has(id)) tabSelection.delete(id);
      }
    }
    for (const tab of items || []) {
      const chip = el("div", "tab-chip" + (tab.active ? " active" : ""));
      chip.setAttribute("draggable", "true");
      chip.setAttribute("tabindex", "0");
      chip.dataset.tabId = String(tab.id);
      chip.title =
        (tab.title || tab.url || chipLabel(tab)) +
        " -- Drag or press Left/Right to reorder";
      // Truncation itself is CSS (max-width + ellipsis).
      if (tabSelectMode) {
        const tick = document.createElement("input");
        tick.type = "checkbox";
        tick.className = "chip-select";
        tick.checked = tabSelection.has(tab.id);
        const label = chipLabel(tab);
        tick.setAttribute("aria-label", "Select " + label);
        if (currentUiLocale !== "en") {
          i18nResolve(
            "chrome-js-tabs-select-aria",
            { label },
            "Select " + label,
          ).then((t) => tick.setAttribute("aria-label", t));
        }
        tick.addEventListener("click", (ev) => ev.stopPropagation());
        tick.addEventListener("change", () => {
          if (tick.checked) tabSelection.add(tab.id);
          else tabSelection.delete(tab.id);
          renderTabBatchBar();
        });
        chip.appendChild(tick);
      }
      chip.appendChild(el("span", "chip-title", chipLabel(tab)));
      const close = el("button", "chip-close", "\u00D7");
      close.type = "button";
      close.title = i18nText("chrome-js-tabs-close-title", "Close tab");
      close.addEventListener("click", (ev) => {
        ev.stopPropagation();
        rb("tab_close", { id: tab.id }).catch(() => {});
      });
      chip.appendChild(close);
      chip.addEventListener("click", () => {
        if (tabSelectMode) {
          // In select mode the whole chip is the toggle: aiming for a
          // small checkbox is how ticks get lost, and switching tabs
          // mid-selection would abandon the set being built.
          if (tabSelection.has(tab.id)) tabSelection.delete(tab.id);
          else tabSelection.add(tab.id);
          const tick = chip.querySelector(".chip-select");
          if (tick) tick.checked = tabSelection.has(tab.id);
          renderTabBatchBar();
          return;
        }
        if (!tab.active) rb("tab_switch", { id: tab.id }).catch(() => {});
      });
      chip.addEventListener("dragstart", (ev) => {
        draggedTabId = tab.id;
        chip.classList.add("dragging");
        if (ev.dataTransfer) {
          ev.dataTransfer.effectAllowed = "move";
          // A drag with NOTHING in dataTransfer is not a drag. Both engines
          // abandon it and fall back to selecting the text under the cursor,
          // which is exactly what the tab strip did: press, move, and the
          // tab title highlighted instead of the tab moving. The other three
          // drags in this file (bookmarks, Quick Access tiles, bookmark rows)
          // all call setData and all worked; this one did not and did not.
          //
          // The constant is deliberately meaningless. The rule this file set
          // out to keep still holds -- the tab id is an internal chrome
          // address and must not ride in a payload another application could
          // receive on drop -- so the id travels in `draggedTabId` and what
          // goes on the wire is a word that identifies nothing.
          ev.dataTransfer.setData("text/plain", "tab");
        }
      });
      chip.addEventListener("dragover", (ev) => {
        const ids = tabDomIds(wrap);
        if (
          draggedTabId === null ||
          ids.indexOf(draggedTabId) < 0 ||
          draggedTabId === tab.id
        ) {
          return;
        }
        ev.preventDefault();
        if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
        previewTabReorder(wrap, chip, ev);
      });
      chip.addEventListener("drop", (ev) => {
        const ids = tabDomIds(wrap);
        if (draggedTabId === null || ids.indexOf(draggedTabId) < 0) return;
        ev.preventDefault();
        const next = previewTabReorder(wrap, chip, ev);
        draggedTabId = null;
        void persistTabOrder(next);
      });
      chip.addEventListener("dragend", () => {
        draggedTabId = null;
        for (const candidate of wrap.querySelectorAll(".dragging")) {
          candidate.classList.remove("dragging");
        }
      });
      chip.addEventListener("keydown", (ev) => {
        if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
        const ids = tabDomIds(wrap);
        const from = ids.indexOf(tab.id);
        const to = from + (ev.key === "ArrowLeft" ? -1 : 1);
        if (from < 0 || to < 0 || to >= ids.length) return;
        ev.preventDefault();
        const next = ids.slice();
        [next[from], next[to]] = [next[to], next[from]];
        putTabDomInOrder(wrap, next);
        void persistTabOrder(next, tab.id);
      });
      wrap.appendChild(chip);
    }
    if (tabSelectMode) renderTabBatchBar();
  }

  // ---- tab multi-select + batch actions (Premium) ----------------------
  //
  // Select mode adds a checkbox to every chip and shows #tabbatch-bar
  // above the strip. Entry is gated server-side by the tabs_batch_enter
  // arm: what Premium sells here is the multi-select affordance itself,
  // so the refusal must happen before a single checkbox is drawn, and
  // Rust must be the one that refuses -- a chrome-side licence check is
  // text anyone can edit. The batch actions then use the same ungated
  // arms a free user already drives one tab at a time.
  let tabSelectMode = false;
  const tabSelection = new Set(); // tab ids ticked in select mode
  // One batch at a time: overlapping runs would interleave their writes
  // and their refreshes and leave the selection decided by whichever
  // finished last.
  let tabBatchBusy = false;

  async function toggleTabSelectMode() {
    if (tabSelectMode) {
      // Leaving select mode mid-batch would clear the selection the batch
      // is still working through; the bar's Cancel honors the same rule.
      if (tabBatchBusy) return;
      exitTabSelectMode();
      return;
    }
    // LEAVING mode is never gated: a lapse mid-session must not strand the
    // user inside a mode they cannot exit. Entering re-reads the licence for
    // the same reason regionStart does.
    await refreshPremium();
    if (premiumBlocked()) return;
    try {
      await rb("tabs_batch_enter", {});
    } catch (e) {
      if (e && e.message === "premium_required") {
        toast(i18nText("chrome-js-batch-premium", "Selecting multiple tabs requires Premium."), true);
      } else {
        toast(friendly(e), true);
      }
      return;
    }
    tabSelectMode = true;
    $("btn-tabselect").setAttribute("aria-pressed", "true");
    renderTabBatchBar();
    renderTabs(lastTabItems);
  }

  function exitTabSelectMode() {
    tabSelectMode = false;
    tabSelection.clear();
    $("btn-tabselect").setAttribute("aria-pressed", "false");
    renderTabBatchBar();
    renderTabs(lastTabItems);
  }

  function renderTabBatchBar() {
    const bar = $("tabbatch-bar");
    if (!bar) return;
    if (bar.hidden === tabSelectMode) {
      // The strip grew or shrank by the bar's height, and the content
      // webview must be told before anything paints under it -- the find
      // bar and the banners live by the same contract.
      bar.hidden = !tabSelectMode;
      syncChromeInsets();
    }
    if (!tabSelectMode) return;
    $("tabbatch-count").textContent =
      tabSelection.size +
      (tabSelection.size === 1 ? " tab selected" : " tabs selected");
    const idle = !tabBatchBusy && tabSelection.size > 0;
    $("tabbatch-close").disabled = !idle;
    $("tabbatch-bookmark").disabled = !idle;
    $("tabbatch-shelf").disabled = !idle;
    $("tabbatch-cancel").disabled = tabBatchBusy;
  }

  /// Runs one operation over every ticked tab, in order, and reports
  /// honestly -- the bookmark manager's runBatch contract applied to
  /// tabs. A partial failure keeps ONLY the failed ids ticked, so the
  /// user can see what did not happen and try again on exactly those.
  /// Returns the failed ids.
  async function runTabBatch(ids, op) {
    if (tabBatchBusy) return ids.slice(); // buttons disable while busy
    tabBatchBusy = true;
    renderTabBatchBar();
    const failed = [];
    for (const id of ids) {
      try {
        await op(id);
      } catch (_) {
        failed.push(id);
      }
    }
    tabSelection.clear();
    for (const id of failed) tabSelection.add(id);
    tabBatchBusy = false;
    if (failed.length) {
      i18nResolve(
        "chrome-js-batch-partial-failure",
        { failed: failed.length, total: ids.length },
        failed.length + " of " + ids.length + " tabs could not be changed.",
      ).then((t) => toast(t, true));
    }
    renderTabBatchBar();
    renderTabs(lastTabItems);
    return failed;
  }

  $("btn-tabselect").addEventListener("click", toggleTabSelectMode);

  $("tabbatch-close").addEventListener("click", async () => {
    const ids = Array.from(tabSelection);
    if (!ids.length || tabBatchBusy) return;
    const ok = await askConfirm(
      await i18nResolve(
        "chrome-js-batch-close-confirm",
        { count: ids.length },
        "Close " + ids.length + (ids.length === 1 ? " tab?" : " tabs?"),
      ),
    );
    if (!ok) return;
    const failed = await runTabBatch(ids, (id) => rb("tab_close", { id }));
    // A clean close empties the set it worked on, so the mode has nothing
    // left to do; a partial failure keeps the failed ids ticked instead.
    if (!failed.length) exitTabSelectMode();
  });

  $("tabbatch-bookmark").addEventListener("click", () => {
    const ids = Array.from(tabSelection);
    if (!ids.length || tabBatchBusy) return;
    const byId = new Map();
    for (const tab of lastTabItems) byId.set(tab.id, tab);
    // The mode stays open on purpose: nothing was closed, and "bookmark,
    // then close" is the sequence this button exists for. bookmark_add's
    // typed-url path normalizes and refuses non-content urls itself, so
    // an internal page in the selection fails its own bookmark honestly.
    runTabBatch(ids, (id) => {
      const tab = byId.get(id);
      if (!tab) return Promise.reject(new Error("not_found"));
      return rb("bookmark_add", { url: tab.url, title: tab.title || "" });
    });
  });

  $("tabbatch-shelf").addEventListener("click", async () => {
    const ids = Array.from(tabSelection);
    if (!ids.length || tabBatchBusy) return;
    tabBatchBusy = true;
    renderTabBatchBar();
    try {
      const res = await rb("shelf_create", { ids });
      tabBatchBusy = false;
      if (res && res.left_out) {
        toast(
          await i18nResolve(
            "chrome-batch-left-out",
            { count: res.left_out },
            res.left_out +
              (res.left_out === 1
                ? " ephemeral or internal tab was skipped."
                : " ephemeral or internal tabs were skipped."),
          ),
          true,
        );
      }
      exitTabSelectMode();
    } catch (e) {
      tabBatchBusy = false;
      renderTabBatchBar();
      toast(friendly(e), true);
    }
  });

  $("tabbatch-cancel").addEventListener("click", () => {
    if (tabBatchBusy) return;
    exitTabSelectMode();
  });

  // ---- the browser's own confirmation ---------------------------------------
  //
  // Replaces window.confirm(), which the engine titles with the page that
  // raised it: every "Delete this?" arrived headed
  // "JavaScript - rbchrome://localhost/index.html", showing the user our
  // internal scheme in a dialog styled like nothing else in the browser.
  //
  // Returns a promise for the answer, so call sites read the same way the
  // blocking version did (`if (!(await askConfirm(...))) return;`).
  //
  // Cancel is focused on open and Escape answers false: for a question whose
  // yes deletes something, the safe answer is the one a stray keypress hits.
  // Focus is returned to whatever raised the dialog, so a keyboard user is
  // put back where they were rather than at the top of the panel.
  let confirmResolve = null;
  function askConfirm(message, confirmLabel) {
    const overlay = $("confirm-overlay");
    const yes = $("confirm-yes");
    // A second question while one is open would strand the first promise
    // forever; answer it false and take over.
    if (confirmResolve) {
      const stale = confirmResolve;
      confirmResolve = null;
      stale(false);
    }
    $("confirm-text").textContent = message;
    yes.textContent = confirmLabel || i18nText("chrome-js-confirm-default-label", "Delete");
    const returnFocusTo =
      document.activeElement && document.activeElement.focus
        ? document.activeElement
        : null;
    overlay.hidden = false;
    $("confirm-cancel").focus();
    return new Promise((resolve) => {
      confirmResolve = (answer) => {
        overlay.hidden = true;
        if (returnFocusTo && document.contains(returnFocusTo)) {
          returnFocusTo.focus();
        }
        resolve(answer);
      };
    });
  }
  function answerConfirm(answer) {
    if (!confirmResolve) return;
    const resolve = confirmResolve;
    confirmResolve = null;
    resolve(answer);
  }
  $("confirm-cancel").addEventListener("click", () => answerConfirm(false));
  $("confirm-yes").addEventListener("click", () => answerConfirm(true));
  // The scrim is a cancel target, like every other dismissible surface here,
  // but only when the click is ON it rather than inside the card.
  $("confirm-overlay").addEventListener("click", (ev) => {
    if (ev.target === $("confirm-overlay")) answerConfirm(false);
  });
  // Captured, so Escape answers THIS dialog before the panel manager sees it
  // and closes the panel underneath the question.
  document.addEventListener(
    "keydown",
    (ev) => {
      if (!confirmResolve) return;
      if (ev.key === "Escape") {
        ev.stopPropagation();
        ev.preventDefault();
        answerConfirm(false);
      }
    },
    true,
  );

  // ---- download toasts ------------------------------------------------------------
  // How long a notification stays before it clears itself, with nothing asked
  // of the user. Fixed at 15 seconds.
  //
  // It is NOT the old 6000. These notices moved to the centre because the
  // corner was easy to miss, and six seconds is short for something you
  // actually want read -- a glance away and it is gone. Fifteen gives a reader
  // time to finish and reach the X, and the X is what makes a longer notice
  // safe: nobody has to wait it out.
  //
  // Rust's LOCKED_SAVE_NOTICE_COOLDOWN must stay LONGER than this, or two
  // locked-vault notices could be on screen at once. A test reads this
  // constant out of this file rather than restating the number, so the two
  // cannot drift apart.
  const TOAST_MS = 15000;

  // How many notifications may be on screen at once.
  //
  // Centred, bold, wrapping and fifteen seconds each were all reasonable
  // alone; together they mean a single long message can cover the address bar
  // and most of the toolbar for the whole of that fifteen seconds, and a burst
  // can push later ones below the visible strip -- the document is
  // `overflow: hidden`, so anything past the edge is unreachable rather than
  // merely off screen. Three is what fits without swallowing the chrome.
  //
  // The OLDEST goes when a fourth arrives, not the newest: the message that
  // just appeared is the one the user is most likely to be looking for, and
  // refusing it would make a flood silence the thing it buried.
  const MAX_VISIBLE_TOASTS = 3;

  function toast(text, isError) {
    const node = el("div", "toast" + (isError ? " error" : ""));
    node.title = text;
    // The message is a child now rather than the node's own text, because the
    // node also carries a dismiss button. Still textContent, never HTML.
    node.appendChild(el("span", "toast-text", text));

    // DISMISS. The container and the notice are `pointer-events: none` so a
    // notice over the address bar cannot swallow a click meant for it; this
    // button turns them back on for itself alone.
    const close = el("button", "toast-close", "\u00d7");
    close.type = "button";
    const label = i18nText("chrome-js-toast-dismiss", "Dismiss");
    close.setAttribute("aria-label", label);
    close.title = label;
    let timer = null;
    const dismiss = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      node.remove();
    };
    close.addEventListener("click", dismiss);
    node.appendChild(close);

    const host = $("toasts");
    host.appendChild(node);
    // `removeChild`, not the evicted node's own `remove()`: the DOM harness
    // implements the former and no-ops the latter, and a `while` loop around a
    // no-op removal never terminates.
    while (host.children.length > MAX_VISIBLE_TOASTS) {
      host.removeChild(host.children[0]);
    }
    timer = setTimeout(dismiss, TOAST_MS);
  }

  // chat.js is injected as a SEPARATE script in chat builds and cannot see
  // into this closure, so it grew its own `toast()` -- which meant chat
  // notices inherited the centred bold CSS while keeping a six-second life
  // and NO dismiss button. One implementation, exposed the same way
  // `window.__rb_ocr` already is, rather than two that drift.
  window.__rb_toast = toast;

  function fileNameFromUrl(url) {
    const clean = String(url || "").split(/[?#]/)[0];
    const segments = clean.split("/").filter(Boolean);
    return segments.length ? segments[segments.length - 1] : i18nText("chrome-js-toast-filename-fallback", "download");
  }

  function fileNameFromPath(path) {
    if (!path) return "";
    const segments = String(path).split(/[\\/]/).filter(Boolean);
    return segments.length ? segments[segments.length - 1] : "";
  }

  // ---- toolbar -----------------------------------------------------------------
  $("btn-back").addEventListener("click", () => rb("back").catch(() => {}));
  $("btn-fwd").addEventListener("click", () => rb("forward").catch(() => {}));
  $("btn-reload").addEventListener("click", () => rb("reload").catch(() => {}));
  urlInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      const url = urlInput.value.trim();
      if (url) rb("navigate", { url }).catch(() => {});
    }
  });
  // ---- panel manager ----
  // One panel visible at a time. With three of them, letting two open at once
  // meant the chrome height was whatever the last toggle asked for and the
  // user saw a panel clipped by another panel's geometry. Exclusivity also
  // makes the pressed-button state truthful: exactly one is ever pressed.
  const panels = new Map();
  let openPanelName = null;

  function registerPanel(name, spec) {
    panels.set(name, spec);
    spec.button.addEventListener("click", () => togglePanelNamed(name));

    // A VISIBLE way out of every panel.
    //
    // Escape and a click on the scrim both already worked, and neither is
    // discoverable: nothing on screen said either existed, so the only exit a
    // user could SEE was pressing the same feature button a second time --
    // which requires having noticed which button they pressed, in a menu that
    // has since closed.
    //
    // Injected here rather than written into markup because three of the eight
    // panels are built at runtime by update.js, integrity.js and chat.js, and
    // never touch index.html. Anything added to the markup would have reached
    // five panels out of eight and looked like a rendering bug in the other
    // three -- which is precisely how `panel-modal` had to be applied by class
    // rather than by stylesheet edit.
    //
    // Guarded so a panel that ships its own close control keeps it.
    if (!spec.el.querySelector(".panel-close")) {
      const close = el("button", "panel-close", i18nText("chrome-js-panel-close-button", "Close"));
      close.type = "button";
      close.setAttribute("aria-label", i18nText("chrome-js-panel-close-aria", "Close this panel"));
      close.addEventListener("click", () => togglePanelNamed(name));
      // Created at REGISTRATION, which runs at load -- before any fill can
      // arrive -- so without this hook every panel's Close stayed English
      // in a non-English session. Found by the first live en-XA run, not
      // by the stub, which cannot model creation-time freezing.
      rebuildOnLocaleFill(() => {
        close.textContent = i18nText("chrome-js-panel-close-button", "Close");
        close.setAttribute(
          "aria-label",
          i18nText("chrome-js-panel-close-aria", "Close this panel"),
        );
      });
      // First child, so Tab reaches the way out before the panel's contents.
      spec.el.insertBefore(close, spec.el.firstChild);
    }
  }

  $("recovery-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("recovery-error");
    err.textContent = "";
    const key = $("recovery-input").value.trim();
    if (!key) {
      err.textContent = i18nText("chrome-js-recovery-empty-prompt", "Enter the recovery key you were given.");
      return;
    }
    try {
      await rb("vault_unlock_recovery", { recovery_key: key });
      // Clear it from the DOM as well as the screen: it is a master credential.
      $("recovery-input").value = "";
      await refreshVault();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  // Runs a panel's open/close hook without letting it break the manager. A
  // failing panel should be a broken panel, not a broken browser.
  function runPanelHook(hook, which) {
    if (!hook) return;
    try {
      hook();
    } catch (e) {
      // Nothing user-facing: the panel is already in a consistent visual
      // state, and a toast here would fire on every toggle of a broken panel.
      console.error("panel " + which + " failed:", e);
    }
  }

  // ---- covering the content area -----------------------------------------
  //
  // The chrome is its own OS window, `closedChromePx()` tall, sitting above a
  // separate window that holds the page. Anything the chrome draws below that
  // height is outside its own rect and simply does not exist on screen -- the
  // two windows are siblings and do not composite. So every surface that wants
  // to be taller than the strip has to ask Rust to grow the chrome to the full
  // window first. That is not a visual nicety; without it the menu sheet would
  // render into a 148px slot and be clipped after its second row.
  //
  // Coverage is COMPUTED in one place rather than toggled by callers. The
  // menu sheet that once shared this decision is gone (toolbar-gate asserts
  // so), but the shape stays: two callers each deciding independently is how
  // you get a dismissal that uncovers the window while a panel is still
  // open, leaving that panel drawn into the strip and cut in half.
  //
  // The last-sent value is remembered so a hand-over does not emit a redundant
  // uncover/recover pair, which on Windows is a visible flicker of the page.
  //
  // A panel is a CENTERED CARD, always. It was briefly a right-docked pane
  // (2026-07-31, one build): that hijacked the Split arrangement
  // reserved for chat -- a docked chat and a docked panel would have fought
  // over one pane -- and the geometry was rejected on sight. Split
  // remains chat's; panels cover the window and say so.
  //
  // What DOES vary is the backdrop. Where the backend can lift a transparent
  // chrome above live content (Windows -- see `chrome_caps`), the page stays
  // rendered at its normal rect and the scrim is genuinely translucent: a
  // dimmed, still-playing page behind the card. Everywhere else the page gets
  // a zero rect and the scrim is solid, because siblings that cannot
  // composite must not fake a see-through.
  let chromeCovered = null;
  // One round trip carrying everything the chrome must know before it paints.
  //
  // `page_covers_chrome` is the other half of the backdrop question above,
  // and it decides how tall a modal card may be: where the chrome is NOT
  // lifted, the page covers everything the chrome is not using, so a card
  // sized against the viewport extends underneath it and its lower half is
  // simply not on screen -- with no scrollbar, because as far as the
  // document is concerned it fits.
  //
  // `toolbar_placement` rides along for a plainer reason: a second round
  // trip for it would mean a Left user watches the top layout assemble and
  // then rearrange itself. Falls back to its own get if a reply arrives
  // without it.
  function refreshChromeCaps() {
    return rb("chrome_caps", {})
      .then((r) => {
        document.body.classList.toggle(
          "translucent-backdrop",
          !!(r && r.translucent_overlay),
        );
        applyTranslateCapability(r);
        document.body.classList.toggle(
          "page-covers-chrome",
          !!(r && r.page_covers_chrome),
        );
        // Whether the accent reaches the scrollbars of pages ("live" on
        // WebView2; "unsupported" on WebKitGTK, which has no
        // scrollbar-color). The sentence is shown only where it is true,
        // rather than worded loosely enough to be true everywhere.
        const note = $("accent-scrollbar-note");
        if (note) note.hidden = !(r && r.page_scrollbar === "live");
        if (r && TOOLBAR_PLACEMENTS.includes(r.toolbar_placement)) {
          wearToolbarPlacement(r.toolbar_placement);
          return;
        }
        return refreshToolbarPlacement();
      })
      .catch(() => refreshToolbarPlacement());
  }
  function syncChromeCoverage() {
    const want = !!openPanelName;
    if (want === chromeCovered) return;
    chromeCovered = want;
    rb("chrome_overlay", { cover: want }).catch(() => {});
    // The HEIGHT is no longer sent from here at all -- `togglePanelNamed`
    // sends it on every toggle, in both directions. It used to be sent only
    // on the way back down (`if (!want)`), which was a real defect on the
    // GTK backend and not merely a tidiness problem:
    //
    //   platform::layout() is a NO-OP on unix ("GTK repacks automatically"),
    //   so `chrome_overlay` changes nothing there by itself. The chrome's
    //   visible height on that backend comes ONLY from set_chrome_height ->
    //   chrome_box.set_size_request. Closing a panel ALSO resets the Rust
    //   side's chrome_height to the strip height (set_chrome_arrangement,
    //   "leaving_cover"). So after one close, reopening any panel sent the
    //   arrangement and no height, the size request stayed at ~148px, and
    //   every panel rendered clipped to nothing: the button lit up and the
    //   body was invisible, for the rest of the session.
    //
    // Found by clicking the real Linux build. Windows was unaffected because
    // its layout() applies the arrangement itself.
  }

  function togglePanelNamed(name) {
    const target = panels.get(name);
    if (!target) return;
    const wasOpen = openPanelName === name;
    // Close whatever is open first, so its onClose runs (the vault clears
    // secrets from the DOM there; chat wipes its conversations).
    //
    // The bookkeeping is committed BEFORE the callback, and the callback is
    // isolated. Previously `openPanelName = null` sat after `onClose()`, so a
    // throw inside a callback left the manager believing a panel was still
    // open — and every subsequent toggle re-entered the same block, threw
    // again, and never reached the reset. One bad callback killed every panel
    // in the browser for the rest of the session. A panel's own bug must not
    // be able to take the chrome with it.
    if (openPanelName) {
      const cur = panels.get(openPanelName);
      openPanelName = null;
      cur.el.hidden = true;
      cur.el.classList.remove("panel-modal");
      cur.button.setAttribute("aria-pressed", "false");
      runPanelHook(cur.onClose, "onClose");
    }
    if (!wasOpen) {
      target.el.hidden = false;
      // The class rather than a per-panel stylesheet edit: update.js,
      // integrity.js and chat.js build their panels at runtime and never
      // touch index.html, so anything keyed on markup would reach five panels
      // out of eight and look like a rendering bug in the other three.
      target.el.classList.add("panel-modal");
      target.button.setAttribute("aria-pressed", "true");
      openPanelName = name;
      applyPanelZoom(target.el);
      runPanelHook(target.onOpen, "onOpen");
      // Move focus INTO the panel that just opened. Without this the first Tab
      // after opening continues from the feature button in the toolbar, so a
      // keyboard user walks the whole strip before reaching the thing they
      // asked for -- and the trap below has nothing to trap until they arrive.
      //
      // Deferred a tick because `onOpen` may still be populating the panel; the
      // Close control is injected by registerPanel and is always present.
      setTimeout(() => {
        if (openPanelName !== name) return;
        const items = focusablesIn(target.el);
        if (items.length) items[0].focus();
      }, 0);
    }
    document.body.classList.toggle("modal-open", !!openPanelName);
    syncChromeCoverage();
    // ALWAYS, in both directions, and after the arrangement rather than
    // before it: on GTK this message is the only thing that actually resizes
    // the chrome, and closing a panel resets the height Rust remembers. See
    // the comment in syncChromeCoverage for the defect this prevents.
    // `syncChromeInsets` reads `openPanelName`, which is already updated
    // here, so it resolves the panel's height when opening and the
    // banner-aware strip height when closing.
    syncChromeInsets();
  }

  // ---- panel zoom -------------------------------------------------------
  // Ctrl+= / Ctrl+- / Ctrl+0 and Ctrl+wheel, while a panel is open, scale
  // the PANEL -- not the page. The Rust shortcut path keeps zooming the
  // active tab, which with a modal open meant zooming a page nobody could
  // see; it now stands down while the window is covered (state.rs), and this
  // is the zoom that visibly answers the keys instead. Session-scoped on
  // purpose: a reading size chosen for the vault is almost always wanted in
  // the very next panel too, and a persisted pref for it would be a setting
  // nobody asked to manage.
  let panelZoom = 1;
  function applyPanelZoom(el) {
    if (el) el.style.zoom = String(panelZoom);
  }
  function stepPanelZoom(dir) {
    panelZoom =
      dir === 0
        ? 1
        : Math.min(
            1.75,
            Math.max(0.7, Math.round((panelZoom + dir * 0.1) * 10) / 10),
          );
    const cur = panels.get(openPanelName);
    if (cur) applyPanelZoom(cur.el);
  }
  // NO ctrl-key keydown handler here, and its absence is load-bearing.
  // `connect_shortcuts` runs on the CHROME webview too and marks resolved
  // accelerators handled (SetHandled(true), windows.rs), so Ctrl+= / Ctrl+- /
  // Ctrl+0 never reach this document on Windows -- a keydown listener for
  // them here is dead code that LOOKS like the feature. The keys arrive as a
  // `panel_zoom` event instead: Rust owns them everywhere, and with a modal
  // open it routes them to the panel rather than to a page nobody can see
  // (state.rs::zoom_active). One source, no double-step.
  document.addEventListener(
    "wheel",
    (ev) => {
      if (!openPanelName || !ev.ctrlKey) return;
      ev.preventDefault();
      stepPanelZoom(ev.deltaY < 0 ? 1 : -1);
    },
    { passive: false, capture: true },
  );

  /// Closing a modal, by the two routes every modal is expected to answer.
  ///
  /// Escape and a click on the scrim. Both go through `togglePanelNamed` so
  /// the panel's own onClose still runs -- the vault clears secrets there and
  /// chat wipes conversations, and a dismissal path that skipped that would
  /// leave a passphrase in the DOM of a panel the user believes they closed.
  function closeOpenPanel() {
    if (openPanelName) togglePanelNamed(openPanelName);
  }
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    // Innermost surface first, ONE layer per press: a modal panel outranks
    // the find bar, and handling both in this single listener is what makes
    // that ordering a fact rather than a registration-order accident.
    if (openPanelName) {
      const opener = panels.get(openPanelName)?.button;
      closeOpenPanel();
      // Focus returns to the control that opened the panel -- now the pill in
      // the toolbar itself. Without this it lands on <body> and the next Tab
      // restarts from the top of the chrome, which for a keyboard user reads
      // as the browser losing their place.
      if (opener) opener.focus();
      return;
    }
    closeFindBar();
  });

  // ---- find bar ----
  // The engines do the searching through their native find APIs; this bar
  // only collects a query and shows counts the ENGINE reported back. Two
  // rules keep it honest: the count blanks the moment the query changes
  // (never a stale number beside new text), and a find_state event for a
  // closed bar is dropped, because an engine callback can land after Esc or
  // a tab switch. (Stale counts from an ABANDONED query never get this far:
  // they quote a dead generation and Rust drops them.)
  const findBar = $("findbar");
  const findInput = $("find-input");
  const findCount = $("find-count");
  const findUnsupported = $("find-unsupported");
  const findPrevBtn = $("find-prev");
  const findNextBtn = $("find-next");
  let findOpen = false;
  let findDebounce = 0;

  function findSetAvailable(available) {
    // An old engine runtime lacks the Find API entirely (the platform layer
    // fails closed and says so here). The bar swaps its input for one honest
    // line instead of a box that searches nothing. The swap can change the
    // bar's height, so it rides the same sync as open/close -- the banner
    // clipping bug is the precedent.
    findInput.hidden = !available;
    findCount.hidden = !available;
    findPrevBtn.disabled = !available;
    findNextBtn.disabled = !available;
    findUnsupported.hidden = available;
    syncChromeInsets();
  }

  async function findSend(query) {
    try {
      const res = await rb("find_start", { query });
      if (res) findSetAvailable(res.available !== false);
    } catch (_) {
      // A refused or failed command means the IPC contract broke, not that
      // the page has no matches. Leave the bar as it is; Rust logged why.
    }
  }

  function openFindBar() {
    if (!findOpen) {
      findOpen = true;
      findBar.hidden = false;
      // Same contract as the banners: the strip grew, so the content webview
      // must be told before anything paints under the bar. Reopening an
      // already-open bar skips this -- nothing changed size.
      syncChromeInsets();
    }
    findInput.focus();
    findInput.select();
    // Re-sends the current value on purpose: this is also the availability
    // probe for a runtime that cannot do find at all.
    findSend(findInput.value);
  }

  function closeFindBar() {
    if (!findOpen) return;
    findOpen = false;
    clearTimeout(findDebounce);
    findDebounce = 0;
    findBar.hidden = true;
    // The strip shrank back; skipping this leaves a dead band above the
    // page, which is exactly the clipping bug the banners already fixed.
    syncChromeInsets();
    findCount.textContent = "";
    rb("find_stop", {}).catch(() => {});
  }

  findInput.addEventListener("input", () => {
    // In flight: show nothing rather than a stale count.
    findCount.textContent = "";
    clearTimeout(findDebounce);
    findDebounce = setTimeout(() => {
      findDebounce = 0;
      findSend(findInput.value);
    }, 150);
  });

  findInput.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    ev.preventDefault();
    if (findDebounce) {
      // The query changed since the last search went out. Flush it now and
      // do NOT also step: the engine's start already activates the first
      // match, so stepping here would skip past it.
      clearTimeout(findDebounce);
      findDebounce = 0;
      findSend(findInput.value);
      return;
    }
    rb(ev.shiftKey ? "find_previous" : "find_next", {}).catch(() => {});
  });

  findPrevBtn.addEventListener("click", () =>
    rb("find_previous", {}).catch(() => {}),
  );
  findNextBtn.addEventListener("click", () =>
    rb("find_next", {}).catch(() => {}),
  );
  $("find-close").addEventListener("click", closeFindBar);

  function onFindState(data) {
    if (!findOpen || !data) return;
    // The text arrives ready-formatted from Rust (find::format_count), so
    // the per-platform shapes -- "3 of 17" vs "17 matches" -- are decided
    // where they are unit-tested, never here.
    if (typeof data.text === "string") findCount.textContent = data.text;
  }

  // ---- find across tabs panel ----
  // The cross-tab counterpart of the bar above, held to the same honesty
  // rules one level up. Rust words EVERYTHING the list says -- counts come
  // from find::format_count, refusals from tab_search::reason_copy -- and
  // the chrome renders both verbatim, never wording a count or a reason
  // itself. The list is built with el() and textContent only, never
  // markup parsing (gate 2): snippet text is page content, and page content in
  // the trusted chrome document must never be parsed as markup.
  const findtabsQuery = $("findtabs-query");
  const findtabsRun = $("findtabs-run");
  const findtabsNote = $("findtabs-note");
  const findtabsPremium = $("findtabs-premium");
  const findtabsProgress = $("findtabs-progress");
  const findtabsList = $("findtabs-list");
  const findtabsEmpty = $("findtabs-empty");
  const findtabsLocked = $("findtabs-locked");
  // The standing text lives in index.html; captured once so every render
  // can rebuild the note and re-append (or drop) the quarantine line
  // without duplicating it. Normalized so reflowing the markup cannot
  // change what renders.
  const findtabsNoteText = findtabsNote.textContent.replace(/\s+/g, " ").trim();
  // Rust's snippet offsets are UTF-8 BYTE offsets; JS string indexing is
  // UTF-16 code units. Slicing the string at those numbers would bold the
  // wrong span in any snippet with a non-ASCII character before the match
  // (and could split a surrogate pair), so the text is encoded ONCE and
  // the three pieces are sliced as bytes and decoded back.
  const findtabsEncoder = new TextEncoder();
  const findtabsDecoder = new TextDecoder();

  function findtabsSnippetLine(snip) {
    const bytes = findtabsEncoder.encode((snip && snip.text) || "");
    // Clamped rather than trusted: slice() reads a negative index as
    // from-the-end, so a bad offset would bold the WRONG text quietly.
    const start = Math.min(
      Math.max(0, (snip && snip.start) || 0),
      bytes.length,
    );
    const end = Math.min(
      Math.max(start, (snip && snip.end) || 0),
      bytes.length,
    );
    const line = el("button", "findtabs-snippet");
    line.type = "button";
    line.appendChild(
      document.createTextNode(findtabsDecoder.decode(bytes.slice(0, start))),
    );
    line.appendChild(
      el("b", null, findtabsDecoder.decode(bytes.slice(start, end))),
    );
    line.appendChild(
      document.createTextNode(findtabsDecoder.decode(bytes.slice(end))),
    );
    return line;
  }

  function renderFindTabs(data) {
    data = data || {};
    const rows = Array.isArray(data.rows) ? data.rows : [];
    const scanning = !!data.scanning;
    const locked = !!data.locked;

    // A locked vault ended the scan server-side along with it. Every
    // control state here is assigned from the snapshot on every render, so
    // a later unlocked snapshot re-enables the box and button on its own --
    // there is no separate "unlock" path to keep in step.
    findtabsLocked.hidden = !locked;
    findtabsQuery.disabled = locked;
    findtabsRun.disabled = locked;
    if (locked) {
      findtabsList.textContent = "";
      findtabsProgress.textContent = "";
      findtabsEmpty.hidden = true;
      findtabsNote.textContent = findtabsNoteText;
      syncChromeInsets();
      return;
    }

    // Rebuilt wholesale on every snapshot. Clearing via textContent is the
    // only node removal here -- nothing is ever parsed as markup.
    findtabsList.textContent = "";
    for (const row of rows) {
      const item = el("li", "findtabs-row");
      // The host is parsed, never trusted: about:blank, an internal page,
      // or a closed tab's empty url all fail new URL, and the header
      // simply shows no host.
      let host = "";
      try {
        host = new URL(row.url || "").host;
      } catch (_) {
        // No host to show.
      }
      // Rust already writes "Closed tab" into the title of a row whose tab
      // is gone, so the title renders VERBATIM: an empty title on a live
      // page is a page with no title, never evidence the tab closed. The
      // fallback mirrors chipLabel: the host if there is one, else the
      // same "New tab" wording the strip uses.
      const title = row.title || host || i18nText("chrome-js-tabs-new-tab", "New tab");
      let status = "";
      if (row.state === "pending") status = i18nText("chrome-js-findtabs-searching", "Searching...");
      else if (row.state === "done" && typeof row.text === "string")
        status = row.text;
      else if (row.state === "unsearchable" && typeof row.reason === "string")
        status = row.reason;
      item.appendChild(
        el(
          "p",
          "findtabs-head",
          (host ? title + " (" + host + ")" : title) + ": " + status,
        ),
      );
      // The click handler lives ONLY on snippet lines, and only a done row
      // has snippets: a pending or unsearchable row can do nothing, so it
      // gets no handler at all -- not a no-op one.
      if (row.state === "done" && Array.isArray(row.snippets)) {
        for (const snip of row.snippets) {
          const line = findtabsSnippetLine(snip);
          line.addEventListener("click", () => {
            // The SNAPSHOT's query, not the box's -- the user may have
            // edited the box since this scan ran, and Rust hands this
            // query to the engine's find on the now-active tab.
            rb("find_tabs_goto", { id: row.id, query: data.query || "" }).catch(
              (e) => toast(friendly(e), true),
            );
          });
          item.appendChild(line);
        }
      }
      findtabsList.appendChild(item);
    }

    if (scanning) {
      const settled = rows.filter((row) => row.state !== "pending").length;
      i18nSet(
        findtabsProgress,
        "chrome-js-findtabs-progress",
        { settled, total: rows.length },
        "Searched " + settled + "/" + rows.length + " tabs.",
      );
    } else {
      findtabsProgress.textContent = "";
    }

    // rows.length > 0 because "every row is done" is vacuously true of an
    // empty list, and an empty list means NO scan has run (a search with
    // nothing to scan is refused with no_tab) -- claiming no tab contains
    // a query that was never searched for would be a lie.
    findtabsEmpty.hidden = !(
      !scanning &&
      rows.length > 0 &&
      rows.every((row) => row.state === "done") &&
      rows.every((row) => (row.count || 0) === 0)
    );

    // The quarantine line is appended to the standing note, never edited
    // into it, so rebuilding from the captured text keeps re-renders
    // idempotent.
    findtabsNote.textContent = findtabsNoteText;
    const skipped = data.skipped_quarantine || 0;
    if (skipped > 0) {
      findtabsNote.appendChild(el("br"));
      findtabsNote.appendChild(
        document.createTextNode(
          skipped === 1
            ? "1 quarantine tab is not searched."
            : skipped + " quarantine tabs are not searched.",
        ),
      );
    }

    // Same trap the find bar documents: anything that can change the
    // panel's height rides the sync, or content paints clipped.
    syncChromeInsets();
  }

  async function findtabsSearch() {
    const query = findtabsQuery.value;
    // No client-side validation on purpose: Rust's check_query is the one
    // authority on what a searchable query is, and its bad_args refusal
    // surfaces through the same toast every other refusal uses. A silent
    // return here would be exactly the broken-looking control the premium
    // note exists to prevent.
    try {
      // The reply IS the first snapshot -- every row pending -- in the
      // same shape the find_tabs_state events carry, so one renderer
      // serves the first paint and every later update.
      const first = await rb("find_tabs_search", { query });
      // A search that ran proves premium is active; the note would be a
      // stale accusation from here on.
      findtabsPremium.hidden = true;
      renderFindTabs(first);
    } catch (e) {
      if (e && e.message === "premium_required") {
        // The control stays put -- a control that silently disappears is
        // indistinguishable from a broken one -- and the note says why it
        // refused.
        findtabsPremium.hidden = false;
        syncChromeInsets();
      }
      toast(friendly(e), true);
    }
  }

  findtabsQuery.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    ev.preventDefault();
    findtabsSearch();
  });
  findtabsRun.addEventListener("click", findtabsSearch);
  // The panel's own close control (see the markup comment: shipping one
  // keeps the query box the first focusable, so the manager's deferred
  // focus lands on it).
  $("findtabs-close").addEventListener("click", () =>
    togglePanelNamed("findtabs"),
  );

  // The registerPanel button lives INSIDE the find bar rather than on the
  // toolbar -- the palette is the precedent for a panel with no pill,
  // reachable from the bar's "All tabs" button and from Ctrl+Shift+F.
  // toolbar-gate's MUST_BE_VISIBLE list is hand-kept, so adding no toolbar
  // button means no gate change.
  registerPanel("findtabs", {
    el: $("findtabs-panel"),
    button: $("find-all"),
    heightPx: 520,
    onOpen: () => findtabsQuery.focus(),
    // Deliberately no onClose: there is no find_tabs_stop command to send.
    // The scan holds no engine sessions and paints no highlights -- only a
    // goto starts one, on the chosen tab, and the ordinary find bar owns
    // that session -- so closing the panel has nothing server-side to
    // undo. A new search replaces the scan wholesale and a vault lock
    // drops it; a stop's only job would be cancelling tokens that Rust
    // already refuses by scan id.
  });

  /// Keep Tab inside an open panel.
  ///
  /// Escape and the scrim already closed a panel, and focus already returned
  /// to the opener on close -- but nothing stopped Tab walking OUT of an open
  /// panel and onto the toolbar controls sitting behind the scrim. Those are
  /// covered, so a keyboard user was driving buttons they could not see: they
  /// would tab past the end of the vault, land on the freeze chip, press it,
  /// and watch the page state change for no visible reason.
  ///
  /// A modal that can be tabbed out of is not modal for the people who cannot
  /// see the scrim, which is the only group the scrim was never doing anything
  /// for in the first place.
  const FOCUSABLE = [
    "a[href]",
    "button:not([disabled])",
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    '[tabindex]:not([tabindex="-1"])',
  ].join(",");

  function focusablesIn(root) {
    // `offsetParent` is null for anything display:none, which is how the
    // hidden halves of a panel (the vault's locked screen, the library's two
    // tabs) are kept out of the cycle without maintaining a second list.
    return Array.prototype.filter.call(
      root.querySelectorAll(FOCUSABLE),
      (node) => !node.hidden && node.offsetParent !== null,
    );
  }

  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Tab" || !openPanelName) return;
    const panel = panels.get(openPanelName);
    if (!panel) return;
    const items = focusablesIn(panel.el);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (!panel.el.contains(document.activeElement)) {
      // Focus escaped, or never entered. Pull it back rather than letting the
      // browser continue from wherever it was.
      ev.preventDefault();
      (ev.shiftKey ? last : first).focus();
    } else if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault();
      first.focus();
    }
  });

  document.addEventListener("mousedown", (ev) => {
    if (openPanelName) {
      const panel = panels.get(openPanelName);
      // Only a click on the scrim itself. A click inside the card, or anywhere
      // in the toolbar above it, is not a dismissal -- pressing a feature
      // button to switch panels must switch, not close and reopen.
      //
      // #confirm-overlay is excluded for the same reason, and it is not
      // optional: the confirmation dialog is a sibling of the panel, not a
      // descendant, so without this every click inside it -- including
      // Cancel -- read as a click outside the panel and closed the panel out
      // from under the question it was asking.
      //
      // #sidebar is exempt because in either side layout it IS the toolbar. The
      // buttons move into it, so without this a press on a feature button
      // would close the open panel before the click reached the button --
      // running its onClose, which clears vault secrets and wipes a chat
      // transcript -- and the click would then reopen it. Same button, twice
      // the work, and one of the two panels loses state doing it.
      if (
        panel &&
        !panel.el.contains(ev.target) &&
        // #toasts joins this list for exactly the reason the paragraph above
        // gives about #sidebar. Notifications became CLICKABLE over a panel
        // when their surface was lifted above the modal scrim, and the first
        // thing that made possible was this: a mousedown on the dismiss
        // button bubbled to here, read as a click outside the panel, and ran
        // `closeOpenPanel()` -- whose onClose wipes a chat transcript and its
        // unsent draft. Pressing X to clear a notice would have destroyed the
        // conversation behind it. Reproduced in a browser before this line
        // existed: panel open, press X, panel gone.
        !ev.target.closest(
          "#toolbar, #sidebar, #tabstrip, #confirm-overlay, #toasts",
        )
      ) {
        closeOpenPanel();
      }
      return;
    }
  });

  // ---- controls shipped in index.html that no draft bound ----
  // Each of these was a visible, enabled button that silently did nothing.
  $("tab-backup").addEventListener("click", () => selectTab("backup"));
  $("btn-freeze").addEventListener("click", toggleFreeze);
  $("btn-tabfreeze").addEventListener("click", toggleFreeze);
  $("btn-quarantine-panel").addEventListener("click", openQuarantineTab);

  // "Stay unlocked" needs no argument and returns nothing: reaching Rust at
  // all is the point, because dispatch treats the command as presence and
  // pushes the deadline out. See ipc.rs.
  $("lock-warning-stay").addEventListener("click", () => {
    hideLockWarning();
    rb("vault_stay_unlocked").catch(() => {});
  });
  $("lock-warning-now").addEventListener("click", () => {
    hideLockWarning();
    rb("vault_lock").catch((e) => toast(friendly(e), true));
  });

  // ---- how long the vault waits ------------------------------------------
  // EVERY OPTION CARRIES ITS UNIT, and every one is in MINUTES.
  //
  // The values are stored in seconds, so a label reading "60" beside a setting
  // whose underlying number is 3600 invites exactly the wrong guess -- and the
  // wrong guess here is a user believing their vault locks after a minute when
  // it waits an hour. 3600 is spelled "60 minutes" rather than "1 hour" for
  // the same reason: one unit across the whole row means there is nothing to
  // convert in your head while comparing them.
  const AUTOLOCK_LABELS = {
    0: i18nText("chrome-js-autolock-never", "Never"),
    300: i18nText("chrome-js-autolock-five", "5 minutes"),
    900: i18nText("chrome-js-autolock-fifteen", "15 minutes"),
    1800: i18nText("chrome-js-autolock-thirty", "30 minutes"),
    3600: i18nText("chrome-js-autolock-sixty", "60 minutes"),
  };

  function autolockLabel(seconds) {
    // Falls back to a formatted number rather than blank, so a value set by
    // hand in prefs.json still renders as something a person can read -- and
    // it too carries the unit.
    return AUTOLOCK_LABELS[seconds] || Math.round(seconds / 60) + " minutes";
  }

  /// The warning lead time. Stated in SECONDS, because that is the unit it is
  /// set in and the unit it counts down in on the banner.
  ///
  /// An earlier version converted 60 to "one minute" to avoid sitting a "60
  /// seconds" next to the "60 minutes" option. That was the wrong fix: the
  /// options now say "minutes" on every one of them, so the units are explicit
  /// on both sides and there is nothing left to confuse. Converting only put a
  /// second unit in play and made the note disagree with the banner, which
  /// counts "Locking in 47 seconds".
  function warnBeforeText(seconds) {
    return (Number(seconds) || 60) + " seconds";
  }

  /// Renders one row of choices. Shared by the two pickers below so they
  /// cannot drift into looking or behaving differently.
  function renderChoices(hostId, values, current, label, onPick) {
    const host = $(hostId);
    if (!host) return;
    host.replaceChildren();
    for (const value of values) {
      const button = el("button", "small", label(value));
      button.type = "button";
      // Same `.active` marking the resolver picker uses, so every setting in
      // this browser that offers a choice reads the same way.
      button.classList.toggle("active", value === current);
      button.setAttribute("aria-pressed", value === current ? "true" : "false");
      button.addEventListener("click", () => onPick(value));
      host.appendChild(button);
    }
  }

  // The picker exists TWICE: on the unlock screen, where it is seen while the
  // passphrase is keyed, and in the Backup pane, where it can still be changed
  // once the vault is open. It has to be both, because each screen only exists
  // in one vault state -- with it on the unlock screen alone, the setting
  // became unreachable the moment the vault was actually in use.
  //
  // ONE renderer fills both, so they cannot disagree about the current value
  // or drift in wording. Missing hosts are skipped rather than assumed: a
  // build or a DOM harness without one of them must not throw.
  const AUTOLOCK_HOSTS = [
    ["autolock-choices", "autolock-note"],
    ["autolock-choices-open", "autolock-note-open"],
  ];

  async function refreshAutolock() {
    const hosts = AUTOLOCK_HOSTS.filter(([hostId]) => $(hostId));
    if (!hosts.length) return;
    const setNote = (text) => {
      for (const [, noteId] of hosts) {
        const note = $(noteId);
        if (note) note.textContent = text;
      }
    };
    let st;
    try {
      st = await rb("vault_autolock_get");
    } catch (e) {
      const detail = friendly(e);
      i18nResolve(
        "chrome-js-autolock-read-failed",
        { detail },
        "Could not read this setting: " + detail,
      ).then(setNote);
      return;
    }
    const current = Number(st && st.seconds);

    for (const [hostId, noteId] of hosts) {
      renderChoices(
        hostId,
        (st && st.choices) || [],
        current,
        autolockLabel,
        async (seconds) => {
          try {
            await rb("vault_autolock_set", { seconds });
            // Re-renders BOTH instances, so changing it in one place is
            // reflected in the other without a reopen.
            await refreshAutolock();
          } catch (e) {
            const note = $(noteId);
            if (note) {
              const detail = friendly(e);
              i18nSet(
                note,
                "chrome-js-autolock-save-failed",
                { detail },
                "Could not save that: " + detail,
              );
            }
          }
        },
      );
    }

    // The warning is FIXED at 60 seconds before the lock, whichever timeout is
    // chosen -- 4:00 on a five-minute setting, 59:00 on a sixty-minute one.
    // How long you get to react should not depend on how long you chose to
    // stay unlocked, and there is nothing here to configure: the banner counts
    // down and offers "I'm still here", which restarts the full timeout.
    // "Once unlocked", not "The vault will": one of the two places this
    // renders is the LOCKED screen, where present-tense copy about the vault
    // staying unlocked describes a state the reader is not in. One string for
    // both, rather than two that could drift into disagreeing about the same
    // setting.
    setNote(
      current === 0
        ? i18nText("chrome-js-autolock-note-never", "Once unlocked, the vault stays unlocked until you lock it or close the browser.")
        : "Locks after " +
            autolockLabel(current) +
            " with nothing happening. A countdown appears " +
            warnBeforeText(st && st.warn_before) +
            " before it does, with a button to stay unlocked.",
    );
  }

  // The picker lives on the LOCKED screen now, not the Backup tab, so the
  // Backup-tab listener that used to refresh it would never fire on the
  // element it exists for. Refreshed instead wherever the locked state is
  // shown (see showState), so the active choice is right after a lock that
  // happened while the panel was closed.
  refreshAutolock();
  // The second entry point to quarantine, and the one most people will find.
  // It runs the SAME function as the button inside the privacy panel rather
  // than reimplementing the sequence, so the two cannot drift into applying
  // different protections under the same name.
  $("btn-quarantine-menu").addEventListener("click", openQuarantineTab);
  $("btn-allow-site").addEventListener("click", () => {
    // Was `lastTabStatus.host` -- a field `tab_status` has never sent. This
    // button has been dead since it shipped: `host` read `undefined` on every
    // click, so "Allow this site while frozen" allowed nothing. `origin` is
    // the field that actually carries this, added above for the same
    // purpose Forget-this-site needed it for.
    const host = lastTabStatus && lastTabStatus.origin;
    if (host) allowHost(host);
  });
  // The second, more conventional way into Tab Activity -- see the comment
  // on #btn-site-info in index.html for why this opens the SAME panel rather
  // than a new one.
  $("btn-site-info").addEventListener("click", () => togglePanelNamed("tab"));

  // Capture: Rust owns the async engine call, the picker and the write; the
  // toast it emits is the outcome. This click only starts it.
  $("btn-capture").addEventListener("click", async () => {
    try {
      await rb("capture_page");
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  $("btn-save-pdf").addEventListener("click", async () => {
    const btn = $("btn-save-pdf");
    btn.disabled = true;
    try {
      // The reply only says the render STARTED and where it will land. The
      // engine writes asynchronously and reports back through a toast, so
      // this must not claim the file exists yet.
      await rb("page_save_pdf");
      toast(i18nText("chrome-js-capture-saving-pdf", "Saving this page as a PDF..."));
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  // Written from privacy status; read by the per-site renderer below.
  //
  // THREE states, not two. `null` means privacy_get has not answered yet, and
  // it is NOT the same as false: `refreshPrivacy()` runs at startup, so the
  // unknown window is milliseconds, but a tab status can land inside it. While
  // unknown the button stays disabled (it cannot be known to work) and the
  // description says nothing about the platform -- claiming "not available on
  // this platform" on Windows, even for a frame, is the same species of false
  // claim this change exists to remove. Only an explicit `false` from Rust
  // prints that sentence (Linux readiness review, 2026-09-15).
  //
  // COVERAGE, stated plainly: the `false` case is gated in
  // scripts/forget-all-cookies-gate.js, and the absent-field default in
  // scripts/site-forget-gate.js. The `null` case is NOT gated -- chrome.js
  // calls refreshPrivacy() at load and the DOM harness resolves it before any
  // check runs, so the window cannot be reached there. It is reachable in the
  // product, where the reply crosses real IPC.
  let cookieClearAvailable = null;
  $("btn-site-forget").disabled = true;
  $("btn-forget-all-cookies").disabled = true;

  // RECOVERY, because "unknown" must not be permanent. refreshPrivacy() writes
  // its failure into the Privacy panel and returns, so a startup privacy_get
  // that times out used to leave both controls disabled until the user happened
  // to open Privacy -- on Windows that is a working feature lost to one dropped
  // reply (R-001). Asking again costs one IPC round trip and only ever happens
  // while the answer is still unknown.
  //
  // `inFlight` collapses the burst: tab_status fires on every navigation and
  // load-state change, and without it a backend that is down would be asked on
  // each one. A FAILED attempt clears the flag so the next render retries; a
  // successful one sets `cookieClearAvailable`, after which this returns
  // immediately and never asks again.
  let cookieAvailabilityInFlight = false;
  function ensureCookieAvailability() {
    if (cookieClearAvailable !== null || cookieAvailabilityInFlight) return;
    cookieAvailabilityInFlight = true;
    rb("privacy_get")
      .then((st) => {
        cookieAvailabilityInFlight = false;
        if (!st || typeof st !== "object") return;
        applyCookieClearAvailability(st);
      })
      .catch(() => {
        // Left unknown on purpose, and the flag is cleared so the next render
        // may try again. Guessing "available" here would put back the enabled
        // button that always fails.
        cookieAvailabilityInFlight = false;
      });
  }

  // The one place availability is applied, so the panel path and the recovery
  // path above cannot diverge.
  function applyCookieClearAvailability(st) {
    const available = st.cookie_clear_available !== false;
    cookieClearAvailable = available;
    $("btn-forget-all-cookies").disabled = !available;
    if (!available) {
      // An unsupported action must not stay actionable. A confirmation opened
      // before the backend answered is retired here rather than left on screen
      // with a live "Yes" button (R-003).
      $("forget-all-confirm").hidden = true;
      $("site-forget-confirm").hidden = true;
    }
    renderSiteForgetControl();
  }

  // ONE renderer for the per-site control, called from tab status (the origin
  // changed) AND from privacy status (availability changed), so neither can
  // leave the other's state on screen. The unavailable sentence goes through
  // i18nSet, which holds the element's translation token, so a late-resolving
  // translation of the ordinary sentence cannot overwrite it.
  function renderSiteForgetControl() {
    const origin = lastForgetOrigin;
    if (cookieClearAvailable === false) {
      $("btn-site-forget").disabled = true;
      i18nSet($("tab-forget-desc"), "chrome-js-site-forget-unavailable", {},
        "Clearing cookies for a site is not available on this platform in this release.");
      return;
    }
    if (cookieClearAvailable === null) {
      // Not yet known. Disabled, but described by the ordinary rules below,
      // and asked for again so "unknown" cannot become permanent.
      ensureCookieAvailability();
      $("btn-site-forget").disabled = true;
      if (origin) {
        i18nSet($("tab-forget-desc"), "chrome-site-forget-desc", { origin },
          "Clears cookies for " + origin +
            ". Saved passwords, local storage, and other site data stay.");
      } else $("tab-forget-desc").textContent = i18nText("chrome-js-error-no-site", "This page has no site to forget.");
      return;
    }
    if (origin) {
      i18nSet($("tab-forget-desc"), "chrome-site-forget-desc", { origin },
        "Clears cookies for " + origin +
          ". Saved passwords, local storage, and other site data stay.");
    } else $("tab-forget-desc").textContent = i18nText("chrome-js-error-no-site", "This page has no site to forget.");
    $("btn-site-forget").disabled = !origin;
  }

  $("btn-site-forget").addEventListener("click", () => {
    $("site-forget-result").hidden = true;
    $("site-forget-confirm").hidden = false;
  });
  $("site-forget-cancel").addEventListener("click", () => {
    $("site-forget-confirm").hidden = true;
  });
  $("site-forget-yes").addEventListener("click", async () => {
    const btn = $("site-forget-yes");
    // The origin this confirmation was shown for, captured now rather than
    // read again after the await: if it changed while the request was in
    // flight, the result belongs to whatever was cleared, not to whatever the
    // panel happens to be showing by the time the reply arrives.
    const target = lastForgetOrigin;
    btn.disabled = true;
    try {
      const data = await rb("site_forget_cookies");
      $("site-forget-confirm").hidden = true;
      // Only shown if the panel is still on the site this was for -- a slow
      // reply arriving after the user switched tabs must not silently claim
      // a DIFFERENT site's cookies were cleared.
      if (lastForgetOrigin === target) {
        $("site-forget-result").hidden = false;
        $("site-forget-result").textContent =
          "Cookies cleared for " + (data.origin || target) + ".";
      }
    } catch (e) {
      $("site-forget-confirm").hidden = true;
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  // ---- page translation --------------------------------------------------
  //
  // The Translation tab. Detected source (correctable), a target chosen from
  // INSTALLED languages, Translate and Show original, and a Manage-languages
  // list to install/remove packs. NOTHING starts a translation on its own --
  // not on load, not on navigation, not on a language being remembered. A
  // translation is a click, always.
  //
  // Language NAMES come from the host (packs_status), English until a second
  // locale exists -- stated in the panel, not pretended. The dropdowns and the
  // list are built from the host's data, so the UI can never offer a language
  // the build cannot actually deliver.

  let translatePacks = null; // last packs_status payload
  let translateDetected = null; // the tab's declared language, if any

  function translateLangName(code) {
    if (!translatePacks) return code;
    const row = translatePacks.languages.find((l) => l.code === code);
    return row ? row.name : code;
  }

  // Tokens installed on disk, either direction, as a Set.
  function installedTokens() {
    const set = new Set();
    if (!translatePacks) return set;
    translatePacks.languages.forEach((l) => {
      (l.directions || []).forEach((d) => {
        if (d.installed) set.add(d.token);
      });
    });
    return set;
  }

  // The pivot-free rule made concrete: from a source, the targets you can pick.
  // If the source is English, any installed en-X. Otherwise English only (and
  // only if the X-en pack is installed). Returns [{code, token}].
  function validTargets(source) {
    if (!translatePacks) return [];
    const installed = installedTokens();
    const out = [];
    translatePacks.languages.forEach((l) => {
      (l.directions || []).forEach((d) => {
        if (d.from === source && installed.has(d.token)) {
          out.push({ code: d.to, token: d.token });
        }
      });
    });
    return out;
  }

  // `preferDetected` is the CALLER's decision, and it has to be, because the
  // two callers want opposite things. A new detection should prefill the
  // source; a pack-status tick must not touch it. Before this parameter
  // existed, detection always won, so any packs_status event -- including a
  // download-progress tick -- silently discarded a user's manual correction.
  // The guard applyTabStatus documents ("a user's manual source choice is not
  // fought by every status push") was real but reachable only through that one
  // caller; renderTranslateUi went straight past it.
  function fillSourceOptions(preferDetected = false) {
    const sel = $("translate-source");
    // `.languages` AND NOT JUST THE OBJECT. Guarding the object alone left a
    // truthy-but-shapeless payload -- `{}` from a truncated or errored host
    // reply -- to reach `translatePacks.languages.slice()` and throw
    // `TypeError: reading 'slice'`, which takes the whole Translation section
    // down rather than degrading. A pack list we cannot read is a pack list
    // we have not got.
    if (!sel || !translatePacks || !Array.isArray(translatePacks.languages)) {
      return;
    }
    const prev = sel.value;
    sel.textContent = "";
    // Every registry language can be a source the user selects (detection can
    // be wrong; the dropdown is how they correct it).
    translatePacks.languages
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach((l) => {
        const o = document.createElement("option");
        o.value = l.code;
        o.textContent = l.name;
        sel.appendChild(o);
      });
    // DETECTION FIRST, then the previous choice, then NOTHING. The old
    // order preferred `prev`, which is right within one page (a manual
    // correction must stick) and wrong across a navigation: leave a Greek
    // site for a French one and the dropdown stayed Greek. The change guard
    // at the assignment site is what protects manual corrections now -- this
    // function re-runs on a NEW detection, not on every push, so `prev` only
    // wins while the page has declared nothing.
    //
    // No English fallback, by decision: a dropdown that says English
    // about a page nobody read is a guess wearing a verdict's clothes. When
    // neither signal answered, the placeholder stays selected and the user
    // is asked, which is the honest state.
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.disabled = true;
    placeholder.textContent = i18nText("chrome-translate-source-unset",
      "Choose the page's language",
    );
    sel.insertBefore(placeholder, sel.firstChild);
    const known = (code) =>
      !!code && translatePacks.languages.some((l) => l.code === code);
    // KEEP WHAT IS THERE unless the caller asked for the detection. An empty
    // `prev` still falls through to the detected language, so a first render
    // prefills exactly as it always did.
    const want = preferDetected
      ? (known(translateDetected) && translateDetected) ||
        (known(prev) && prev) ||
        ""
      : (known(prev) && prev) ||
        (known(translateDetected) && translateDetected) ||
        "";
    sel.value = want;
  }

  function fillTargetOptions() {
    const srcSel = $("translate-source");
    const tgtSel = $("translate-target");
    // Same shape as fillSourceOptions: a pack list that is not an array is
    // not a pack list.
    if (!srcSel || !tgtSel) return;
    if (!translatePacks || !Array.isArray(translatePacks.languages)) return;
    const prev = tgtSel.value;
    // No source chosen yet: the target list must not claim "no language
    // installed" (which reads as a missing pack) about a question that has
    // simply not been answered.
    if (!srcSel.value) {
      tgtSel.textContent = "";
      const o = document.createElement("option");
      o.value = "";
      o.textContent = i18nText("chrome-translate-target-unset", "Pick the page's language first");
      tgtSel.appendChild(o);
      $("btn-translate").disabled = true;
      return;
    }
    const targets = validTargets(srcSel.value);
    tgtSel.textContent = "";
    targets
      .slice()
      .sort((a, b) => translateLangName(a.code).localeCompare(translateLangName(b.code)))
      .forEach((t) => {
        const o = document.createElement("option");
        o.value = t.token; // the pair token, ready for translate_page
        o.textContent = translateLangName(t.code);
        tgtSel.appendChild(o);
      });
    if (prev && targets.some((t) => t.token === prev)) tgtSel.value = prev;
    const none = targets.length === 0;
    $("btn-translate").disabled = none;
    // Nothing to translate INTO from this source, said where the target would
    // be. Two different situations reach here and they need different words:
    // a language you have not installed at all, and one where you have the
    // direction you are not asking for. The second used to read "No language
    // installed for this", which is false and sends the user to install a
    // language the list already shows as present.
    if (none) {
      const row = translatePacks.languages.find((l) => l.code === srcSel.value);
      const o = document.createElement("option");
      o.value = "";
      o.textContent =
        row && row.partial
          ? i18nText("chrome-translate-no-target-partial",
              "You have the other direction only. Get this one below.",
            )
          : i18nText("chrome-translate-no-target",
              "No language installed for this. Install one below.",
            );
      tgtSel.appendChild(o);
    }
  }

  function renderLangList() {
    const host = $("translate-langs");
    if (!host || !translatePacks) return;
    host.textContent = "";
    translatePacks.languages
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach((l) => {
        // The pivot is not an installable thing: every pair includes English,
        // so an "Install English" row would mean "download the entire
        // registry" -- and the host refuses it. No row, no dead button.
        if (l.code === "en") return;
        const li = document.createElement("li");
        const name = document.createElement("span");
        name.textContent = l.name;
        li.appendChild(name);
        if (l.premium) {
          const chip = document.createElement("span");
          chip.className = "premium-chip";
          chip.textContent = i18nText("chrome-translate-lang-premium", "Premium");
          li.appendChild(chip);
        }

        const status = document.createElement("span");
        status.className = "muted";
        if (l.downloading) {
          // Real bytes, not a spinner, from the progress the host reports.
          const dir = (l.directions || []).find((d) => d.downloading && d.total);
          if (dir && dir.total) {
            const pct = Math.floor((dir.got / dir.total) * 100);
            status.textContent = i18nText("chrome-translate-lang-downloading-pct",
              "Downloading… ",
            ) + pct + "%";
          } else {
            status.textContent = i18nText("chrome-translate-lang-downloading", "Downloading…");
          }
        } else if (l.failed) {
          // Ahead of `installed`: with one direction on disk and the other
          // failed the row IS installed, and saying so alone would hide the
          // half that did not arrive.
          status.textContent = packFailureText(l.failed);
          status.classList.add("pack-failed");
        } else if (l.installed) {
          status.textContent = i18nText("chrome-translate-lang-installed", "Installed");
        } else if (l.partial) {
          // Half a language is not an installed language: one direction
          // present and the other missing used to read "Installed" and offer
          // only Remove, which stranded the direction the user wanted.
          status.textContent = i18nText("chrome-translate-lang-partial", "One direction only");
        } else {
          const mb = Math.round(Number(l.approx_bytes || 0) / 1048576);
          status.textContent = mb > 0 ? "~" + mb + " MB" : "";
        }
        li.appendChild(status);

        // Written once and used by two branches: `installed` removes, and
        // `partial` removes the half that landed. Duplicating the handler is
        // how the two would drift.
        const wireRemove = (b) => {
          b.classList.add("danger");
          b.textContent = i18nText("chrome-translate-lang-remove", "Remove");
          b.addEventListener("click", async () => {
            b.disabled = true;
            try {
              translatePacks = await rb("pack_remove", { code: l.code });
              renderTranslateUi();
            } catch (e) {
              toast(friendly(e), true);
              b.disabled = false;
            }
          });
          return b;
        };

        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "small";
        // A SECOND action, only for `partial`. Set below and appended after
        // `btn`; every other state leaves it null and appends nothing.
        let extraBtn = null;
        if (l.downloading) {
          btn.disabled = true;
          btn.textContent = i18nText("chrome-translate-lang-installing", "Installing…");
        } else if (l.partial) {
          // Completing costs only the missing direction: install_language
          // skips what is already on disk.
          btn.textContent = i18nText("chrome-translate-lang-complete", "Get the other direction");
          btn.addEventListener("click", async () => {
            btn.disabled = true;
            try {
              translatePacks = await rb("pack_install", { code: l.code });
              renderTranslateUi();
            } catch (e) {
              toast(friendly(e), true);
              btn.disabled = false;
            }
          });
          // AND a way out. Without this, the direction that DID install had
          // no removal control anywhere in this list: `Remove` lived only in
          // the `installed` branch below, so the only route to it was to
          // finish a download the user may not want, for tens of megabytes
          // they have decided against.
          extraBtn = document.createElement("button");
          extraBtn.type = "button";
          extraBtn.className = "small";
          wireRemove(extraBtn);
        } else if (l.installed) {
          wireRemove(btn);
        } else if (l.premium && !translatePacks.premium_active) {
          // Locked, stated, and honest: the host enforces this same rule
          // (install_language refuses tier-2 without an active licence), so
          // the disabled button is a mirror of reality, not a style choice.
          btn.disabled = true;
          btn.textContent = i18nText("chrome-translate-lang-premium-locked", "Premium required");
        } else {
          btn.textContent = i18nText("chrome-translate-lang-install", "Install");
          btn.addEventListener("click", async () => {
            btn.disabled = true;
            try {
              translatePacks = await rb("pack_install", { code: l.code });
              renderTranslateUi();
            } catch (e) {
              toast(friendly(e), true);
              btn.disabled = false;
            }
          });
        }
        li.appendChild(btn);
        if (extraBtn) li.appendChild(extraBtn);
        host.appendChild(li);
      });
  }

  function renderTranslateUi() {
    fillSourceOptions();
    fillTargetOptions();
    renderLangList();
    renderDetectedHint();
  }

  // The friendly "this page looks like X" line. Its own function because it
  // has two callers with different timing: applyTabStatus sets the detected
  // language the moment the tab reports it (often before any pack list has
  // loaded), and renderTranslateUi repaints it once packs ARE loaded so the
  // language NAME resolves. Without the second caller the line stayed hidden
  // even though the source dropdown had already been pre-set from detection.
  function renderDetectedHint() {
    const el = $("translate-detected");
    if (!el) return;
    if (translateDetected && translatePacks) {
      el.hidden = false;
      el.textContent =
        i18nText("chrome-translate-detected-prefix", "This page looks like ") +
        translateLangName(translateDetected) +
        ".";
    } else {
      el.hidden = true;
    }
  }

  async function refreshTranslatePacks() {
    try {
      translatePacks = await rb("packs_status");
      renderTranslateUi();
    } catch (e) {
      /* leave the last known state; the panel simply does not update */
    }
  }

  // Why a pack download stopped, for the packs list. Deliberately NOT
  // translateFailureText: that copy ends "the page is unchanged and still
  // readable", which is true when a translation failed and meaningless here,
  // where no page was being translated. Literal i18nText calls per case so
  // the i18n gate sees every string.
  function packFailureText(key) {
    switch (key) {
      case "translate-pack-unreachable":
        return i18nText("chrome-translate-lang-failed-unreachable",
          "Download failed: could not reach the language pack server.",
        );
      case "translate-pack-not-offered":
        return i18nText("chrome-translate-lang-failed-not-offered",
          "This language pack is not available yet.");
      case "translate-pack-untrusted":
        return i18nText("chrome-translate-lang-failed-untrusted",
          "Download failed: the pack did not verify, so nothing was kept.",
        );
      case "translate-pack-storage":
        return i18nText("chrome-translate-lang-failed-storage",
          "Download failed: it could not be saved to disk.",
        );
      default:
        return i18nText("chrome-translate-lang-failed", "Download failed.");
    }
  }

  // The failure copy for a stopped translation. Literal i18nText calls per
  // case (not a lookup table) so the i18n gate sees every string; the
  // source-unknown copy states the Latin-vs-Latin limit honestly.
  function translateFailureText(key) {
    switch (key) {
      case "translate-pack-unreachable":
        return i18nText("chrome-translate-status-failed-unreachable",
          "Could not reach the language pack server. The page is unchanged and still readable.",
        );
      case "translate-pack-not-offered":
        return i18nText("chrome-translate-lang-failed-not-offered",
          "This language pack is not available yet.");
      case "translate-pack-untrusted":
        return i18nText("chrome-translate-status-failed-untrusted",
          "The language pack did not verify, so nothing was installed. The page is unchanged and still readable.",
        );
      case "translate-pack-storage":
        return i18nText("chrome-translate-status-failed-storage",
          "The language pack could not be saved. The page is unchanged and still readable.",
        );
      case "translate-script-mismatch":
        return i18nText("chrome-translate-status-failed-script",
          "This page is not written in the language you chose, so it was left unchanged. Pick the correct source language and try again.",
        );
      case "translate-source-unknown":
        return i18nText("chrome-translate-status-failed-source-unknown",
          "Could not tell what language this page is in. Choose the source language and try again. (Languages that share an alphabet, like English and French, cannot be told apart automatically.)",
        );
      case "translate-timeout":
        return i18nText("chrome-translate-status-failed-timeout",
          "This took too long and was stopped. The page is unchanged and still readable.",
        );
      case "translate-pair-unavailable":
        return i18nText("chrome-translate-status-failed-unavailable",
          "There is no language pack for that translation direction yet. The page is unchanged.",
        );
      case "translate-busy":
        return i18nText("chrome-translate-status-failed-busy",
          "Another translation is already running. Let it finish, then try this page.",
        );
      default:
        return i18nText("chrome-translate-status-failed",
          "Translation stopped. The page is unchanged and still readable.",
        );
    }
  }

  function renderTranslate(status) {
    const active = status && status.active;
    const done = active && status.phase === "done";
    $("btn-translate-restore").hidden = !done;
    $("btn-translate").hidden = !!(active && status.phase !== "failed" && status.phase !== "done");
    const line = $("translate-status");
    if (active) {
      line.hidden = false;
      const phase = status.phase;
      // A pack download for this session names ITSELF, with real bytes --
      // the phase word alone said "loading" while fifty megabytes moved, and
      // said nothing at all about a page that never answered.
      const dlPct =
        status.downloading && status.dl_total
          ? Math.floor((status.dl_got / status.dl_total) * 100)
          : null;
      line.textContent = status.downloading
        ? i18nText("chrome-translate-status-downloading",
            "Downloading the language pack…",
          ) + (dlPct === null ? "" : " " + dlPct + "%")
        : phase === "preparing"
          ? i18nText("chrome-translate-status-preparing", "Getting ready.")
          : phase === "translating"
            ? i18nText("chrome-translate-status-translating", "Translating this page.") +
              // Real progress when the page has told us how much there is.
              // A long page can spend minutes here, and a phase word alone
              // gives a reader no way to tell working from stuck.
              (status.total_nodes
                ? " " +
                  Math.min(
                    99,
                    Math.floor((status.done_nodes / status.total_nodes) * 100),
                  ) +
                  "%"
                : "")
            : phase === "done"
              ? i18nText("chrome-translate-status-done", "This page is translated.")
              : translateFailureText(status.failure);
      $("translate-active").hidden = phase !== "translating" && phase !== "preparing";
    } else {
      line.hidden = true;
      $("translate-active").hidden = true;
    }
    // THE DIAGNOSTIC LINE. Shown only while a translation is live, and only
    // when the engine has answered: which copy of translator.js is actually
    // running, whether it matches this build, and how much heap the engine
    // got. Four builds produced identical wrong output while the code changed
    // underneath them; nothing on screen could tell a stale script from a
    // correct one computing a wrong answer, so every round was inference.
    // A person can read this and know.
    const diag = $("translate-engine-diag");
    if (diag) {
      const rev = status && status.engine_asset_rev;
      const want = status && status.expected_asset_rev;
      const heap = status && status.engine_heap_bytes;
      if (active && rev) {
        const mb = heap ? Math.round(heap / 1048576) : 0;
        const stale = !!(want && rev !== want);
        if (stale) {
          i18nSet(
            diag,
            "chrome-translate-engine-diag-stale",
            { rev, want, mb },
            "Engine " + rev + " is STALE; this build expects " + want + ". " + mb + " MB heap.",
          );
        } else {
          i18nSet(
            diag,
            "chrome-translate-engine-diag",
            { rev, mb },
            "Engine " + rev + ". " + mb + " MB heap.",
          );
        }
        // The census rides in the same line: which alphabets actually
        // reached the engine. Counts only -- never the page's words.
        // SCRIPT CODES, not words: "cyrl/grek/latn/zzzz" are ISO 15924, the
        // same identifiers a font or a locale uses, and they are the same in
        // every language. Nothing here is prose to translate, which is why it
        // is built from constants rather than routed through the catalog.
        const cen = status && status.engine_last_input;
        if (cen) {
          const CODES = [
            ["cyrl", cen.cyrillic],
            ["grek", cen.greek],
            ["latn", cen.latin],
            ["zzzz", cen.other],
          ];
          const parts = CODES.filter((c) => c[1]).map((c) => c[0] + "=" + c[1]);
          diag.textContent = diag.textContent + " | " + (parts.join(" ") || "0");
        }
        diag.classList.toggle("pack-failed", stale);
        diag.hidden = false;
      } else {
        diag.hidden = true;
      }
    }

    // The toolbar chip: visible exactly while the page on screen is
    // translated, gone the moment it is not -- same contract as the zoom
    // chip, and cleared by the same navigation-driven repaint that fixed the
    // panel. A chip that lingered would claim a page is translated when it
    // is not, which is the lie this whole feed exists to prevent.
    const chip = $("translate-chip");
    if (chip) {
      if (done) chip.textContent = i18nText("chrome-translate-chip", "Translated");
      if (chip.hidden !== !done) {
        chip.hidden = !done;
        syncChromeInsets();
      }
    }
  }

  // Gated on the host confirming the channel; a control that cannot finish its
  // own action must not be on screen. Gates the whole Translation tab body.
  function applyTranslateCapability(caps) {
    const on = !!(caps && caps.page_translation);
    const tabBtn = $("btn-tab-translate");
    if (tabBtn) tabBtn.hidden = !on;
    const body = $("tab-translate-body");
    if (body && !on) body.hidden = true;
  }
  window.__rbApplyTranslateCapability = applyTranslateCapability;

  const srcSel = $("translate-source");
  if (srcSel) srcSel.addEventListener("change", fillTargetOptions);

  $("btn-translate").addEventListener("click", async () => {
    const pair = $("translate-target").value;
    if (!pair) return;
    const btn = $("btn-translate");
    btn.disabled = true;
    try {
      // Remember the target for next time, then translate. The ONLY argument
      // is the pair; Rust picks the active tab and reads its URL itself.
      const tgtCode = validTargets($("translate-source").value).find(
        (t) => t.token === pair,
      );
      if (tgtCode) {
        try {
          await rb("translate_set_target", { code: tgtCode.code });
        } catch (e) {
          /* remembering is a convenience; a failure must not block translating */
        }
      }
      renderTranslate(await rb("translate_page", { pair }));
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  $("btn-translate-restore").addEventListener("click", async () => {
    const btn = $("btn-translate-restore");
    btn.disabled = true;
    try {
      renderTranslate(await rb("translate_restore"));
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  $("btn-translate-stop").addEventListener("click", async () => {
    const btn = $("btn-translate-stop");
    btn.disabled = true;
    try {
      renderTranslate(await rb("translate_cancel"));
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  // The Info / Translation tab strip inside the panel. Same aria-pressed
  // convention as #tools-tabs. Opening Translation refreshes the pack list so
  // install/remove state is current.
  const TAB_PANEL_SECTIONS = [
    { tab: "btn-tab-info", body: "tab-info-body" },
    { tab: "btn-tab-translate", body: "tab-translate-body" },
  ];
  function selectTabPanelSection(tabId) {
    TAB_PANEL_SECTIONS.forEach(({ tab, body }) => {
      const active = tab === tabId;
      const b = $(tab);
      if (b) b.setAttribute("aria-pressed", active ? "true" : "false");
      const el = $(body);
      if (el) el.hidden = !active;
    });
    if (tabId === "btn-tab-translate") refreshTranslatePacks();
  }
  $("btn-tab-info").addEventListener("click", () => selectTabPanelSection("btn-tab-info"));
  $("btn-tab-translate").addEventListener("click", () =>
    selectTabPanelSection("btn-tab-translate"),
  );
  // The chip opens the panel it summarises, on its Translation tab, where
  // Show original lives. It never acts on the page directly: undoing a
  // translation from a chip is one accidental click, from the panel it is a
  // deliberate one.
  $("translate-chip").addEventListener("click", () => {
    if ($("tab-panel").hidden) togglePanelNamed("tab");
    selectTabPanelSection("btn-tab-translate");
  });

  // ---- inline credential autofill ----
  //
  // Two independent surfaces, and neither ever holds a password in this
  // webview: the save banner only ever sees {origin, username} (the password
  // stays in Rust's `AppState.pending_save` until Save is clicked, and Rust
  // writes it straight to the vault); the fill button only ever sees
  // {id, username} and hands the id back for Rust to look the password up
  // again itself.

  // The single credential offered for the tab's CURRENT origin, or null.
  // Set by refreshAutofillOffer, read (never re-derived) by the fill click --
  // the origin is checked again on the Rust side regardless of what this
  // holds, see cred_autofill_fill's own origin_mismatch refusal.
  let lastAutofillOffer = null;

  // Why the offer is unavailable, for the panel row only. The toolbar button
  // says nothing in any of these cases -- it is simply absent -- so this text
  // exists purely so somebody who DOES open the panel gets a reason instead of
  // a dead control.
  let lastAutofillReason = "";
  // Machine-readable twin of the reason above, mirrored onto the desc node
  // so the gate can assert WHICH reason is showing without pinning English:
  // no-site | unavailable | no-match | check-failed | offer.
  let lastAutofillState = "";

  // Tracked here rather than read back per call because locking the vault must
  // retract a fill button that is already on screen: the offer is only valid
  // while the vault is open, and `setVaultIndicator` is the one place that
  // learns it changed.
  let vaultUnlocked = false;

  // (origin, vault state, injection state). NOT a cache key -- an in-flight
  // staleness check, compared against on the reply so a navigation or a lock
  // that happened mid-lookup cannot paint an offer for the wrong page.
  //
  // THIS WAS A CACHE FOR ONE COMMIT AND THE GATE CAUGHT IT. Keyed on these
  // three, a lookup was skipped whenever none of them had moved -- but the
  // vault's CONTENTS are not in the key, so adding a credential for the site
  // you are already standing on left the toolbar insisting there was no saved
  // password for it. The save-banner path papered over this with a `force`
  // flag; adding the same credential from the Vault panel had nothing.
  //
  // Not replaced with a contents-generation counter, because the thing it was
  // optimising does not cost anything: `credentials_for_origin` is an
  // `.iter().filter()` over an already-decrypted Vec -- no disk, no crypto --
  // and `tab_status` is event-driven rather than on a repeating timer. The
  // cache was guarding a cost that does not exist with a bug that does.
  // What the host's `reason` means, in words. Keyed by the EXACT strings
  // `autofill_offer_reason` in ipc.rs can return; a Rust test reads this table
  // and fails if either side adds, renames or drops one. Only "no-match"
  // asserts that a search actually ran -- the other three say no search was
  // made, which is the distinction this chrome used to be unable to draw.
  // Each entry RESOLVES its own text rather than holding an id to look up
  // later. Two reasons, and the second one is a gate: a catalog id must appear
  // as a literal first argument to `i18nText` or scripts/i18n-gate.sh counts
  // it unreferenced and fails -- which is how it catches wording that was
  // added to the catalog but never wired to a surface. Resolving here also
  // means the sentence follows a live locale switch instead of being frozen
  // at whatever the locale was when the table was built.
  //
  // Every key is quoted, including the one JS would let us leave bare: the
  // Rust contract test reads this table as text and looks for the quoted
  // reason.
  const AUTOFILL_REASON_TEXT = {
    // NO PROTOTYPE. With an ordinary object literal, a reason the host never
    // sends still selected something: "constructor" rendered "[object Object]"
    // with state "constructor", "toString" rendered "[object Undefined]", and
    // "__proto__" threw and landed on check-failed. None of them degraded to
    // no-match the way an unknown reason must. This is a lookup table for
    // strings that arrive over IPC, so it inherits nothing.
    __proto__: null,
    "locked": () =>
      i18nText("chrome-js-autofill-reason-locked", "Unlock the vault to check for a saved password."),
    "no-vault": () =>
      i18nText("chrome-js-autofill-reason-no-vault", "No vault yet. Create one to save passwords."),
    "no-site": () =>
      i18nText("chrome-js-autofill-reason-no-site", "No site to check for a saved password."),
    "no-match": () =>
      i18nText("chrome-js-autofill-reason-no-match", "No saved password for this site."),
  };

  function autofillKey(st) {
    if (!st) return "none";
    return [st.origin || "", vaultUnlocked, st.content_script_registered].join(
      "|",
    );
  }

  // Paints both surfaces from state already in hand. Split out from the lookup
  // so a cached pass can repaint without touching the vault, and so the two
  // controls can never disagree about whether an offer exists.
  function renderAutofillOffer() {
    const panelBtn = $("btn-autofill-fill");
    const desc = $("tab-autofill-desc");
    const toolbarBtn = $("btn-fill");
    const offer = lastAutofillOffer;

    if (offer) {
      i18nSet(
        desc,
        "chrome-js-autofill-offer-desc",
        { username: offer.username },
        // Two drafts of this sentence were concatenated instead of one being
        // chosen, and `i18nSet` writes this argument to textContent
        // SYNCHRONOUSLY -- and, on the default "en" locale, writes nothing
        // else. So every English user with a saved password read
        // "A saved password for aliceSaved password available for ". The
        // catalog entry (en.ftl chrome-js-autofill-offer-desc) was correct all
        // along; only this fallback was wrong.
        "A saved password for " + offer.username + " is available.",
      );
      desc.dataset.state = "offer";
      panelBtn.disabled = false;
      i18nSet(
        panelBtn,
        "chrome-js-autofill-offer-button",
        { username: offer.username },
        "Fill password for " + offer.username,
      );
      if (toolbarBtn) {
        toolbarBtn.hidden = false;
        // LIT, not merely present. Appearing was supposed to be the whole
        // signal, and on a real toolbar it is not: sat between Live, TA and
        // DNS in the same grey, a button that had just appeared read as one
        // more control that had always been there. A reader looked
        // straight at it and reported that nothing lit up.
        //
        // `.is-active` is this chrome's existing word for "this is live right
        // now" -- the same green Vault wears while unlocked -- so the fill
        // button borrows the vocabulary rather than inventing a tenth colour.
        toolbarBtn.classList.add("is-active");
        toolbarBtn.title = "Fill the saved password for " + offer.username;
        if (currentUiLocale !== "en") {
          // Same token discipline as `i18nSet`, which this call deliberately
          // does not use (it writes `title`, not textContent). Without it a
          // late reply would write the account name into the tooltip of a
          // button the lock had already hidden.
          const mine = i18nHold(toolbarBtn);
          i18nResolve(
            "chrome-js-autofill-offer-title",
            { username: offer.username },
            "Fill the saved password for " + offer.username,
          ).then((t) => {
            if (toolbarBtn.__i18nToken !== mine) return;
            toolbarBtn.title = t;
          });
        }
      }
      return;
    }
    // INVALIDATE ANY TRANSLATION STILL IN FLIGHT. `i18nSet` guards its own
    // completion with a per-element token, but the lines below write
    // textContent directly, which leaves the previous token valid. In a
    // non-English locale that let a translation requested for a LIVE OFFER
    // land after the vault had locked and put the account name back on
    // screen -- in the description and on the button -- under a panel that
    // said the vault was locked. Bumping the token here is what makes those
    // late writes no-ops.
    i18nHold(desc);
    i18nHold(panelBtn);
    desc.textContent = lastAutofillReason;
    desc.dataset.state = lastAutofillState;
    panelBtn.disabled = true;
    panelBtn.textContent = i18nText("chrome-js-autofill-fill-default", "Fill saved password");
    // Hidden, not disabled. See the markup comment on #btn-fill: a greyed
    // button on every page the user has no saved password for is nine-tenths
    // of the time noise, and its absence is the clearer signal.
    if (toolbarBtn) {
      // The tooltip named the account too, so it is cleared with the button
      // and its token bumped, or a translation still in flight would write it
      // back after the lock.
      i18nHold(toolbarBtn);
      toolbarBtn.title = "";
      toolbarBtn.hidden = true;
      // Cleared as well as hidden. A hidden button keeps its classes, and the
      // next offer would otherwise be able to arrive already-green from the
      // previous site rather than lighting up for this one.
      toolbarBtn.classList.remove("is-active");
    }
  }

  // Single-match only for v1 (see the plan's own scope note): if a vault
  // somehow held more than one credential for the same origin, only the
  // first is ever offered. There is no chooser to build for that here.
  function refreshAutofillOffer() {
    const st = lastTabStatus;
    const key = autofillKey(st);

    lastAutofillOffer = null;
    const origin = st && st.origin;
    if (!origin) {
      lastAutofillReason =
        i18nText("chrome-js-autofill-reason-no-site", "No site to check for a saved password.");
      lastAutofillState = "no-site";
      renderAutofillOffer();
      return;
    }
    if (st.content_script_registered !== "applied") {
      lastAutofillReason = i18nText("chrome-js-autofill-reason-unavailable", "Autofill is not available in this tab.");
      lastAutofillState = "unavailable";
      renderAutofillOffer();
      return;
    }
    // REPAINT BEFORE THE ROUND TRIP. `lastAutofillOffer` was cleared above,
    // but nothing on screen knows that until the reply lands -- and one of the
    // callers is the vault LOCKING. Without this, locking leaves the previous
    // "Fill password for alice" sitting in the panel with its button ENABLED
    // and the toolbar button lit, for as long as the lookup takes. Found by
    // holding the reply pending and looking at the screen in the gap, not by
    // reading the code.
    //
    // It paints "checking", not a guess at the answer: the one thing that is
    // certainly true here is that we have asked and do not know yet.
    lastAutofillReason = i18nText("chrome-js-autofill-reason-checking", "Checking for a saved password.");
    lastAutofillState = "checking";
    renderAutofillOffer();
    rb("cred_autofill_offer_get")
      .then((data) => {
        // The tab may have navigated to a different site while this was in
        // flight; a stale reply must not offer a fill for the wrong page.
        // Checked against the whole key, not just origin, so a vault that
        // locked mid-flight cannot leave a live-looking button behind.
        if (autofillKey(lastTabStatus) !== key) return;
        const item = ((data && data.items) || [])[0];
        lastAutofillOffer = item || null;
        if (!item) {
          // THE HOST SAYS WHICH of four things happened, because only the host
          // knows: an empty list from a locked vault and an empty list from a
          // completed search look identical from here. Assuming the second was
          // the bug -- a tester with a correctly saved password was told
          // "No saved password for this site" while his vault was simply shut.
          //
          // A reply with no reason is treated as no-match, which is exactly
          // what this code assumed unconditionally before, so an older host
          // degrades to the old behaviour rather than to a blank line.
          const reason = (data && data.reason) || "no-match";
          const text = AUTOFILL_REASON_TEXT[reason] || AUTOFILL_REASON_TEXT["no-match"];
          lastAutofillReason = text();
          lastAutofillState = AUTOFILL_REASON_TEXT[reason] ? reason : "no-match";
        }
        renderAutofillOffer();
      })
      .catch(() => {
        lastAutofillOffer = null;
        lastAutofillReason = i18nText("chrome-js-autofill-reason-check-failed", "Could not check for a saved password.");
        lastAutofillState = "check-failed";
        renderAutofillOffer();
      });
  }

  $("btn-fill").addEventListener("click", async () => {
    const offer = lastAutofillOffer;
    if (!offer) return;
    try {
      await rb("cred_autofill_fill", { id: offer.id });
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  $("btn-autofill-fill").addEventListener("click", async () => {
    const offer = lastAutofillOffer;
    if (!offer) return;
    const btn = $("btn-autofill-fill");
    btn.disabled = true;
    try {
      await rb("cred_autofill_fill", { id: offer.id });
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      // NOT an unconditional re-enable. Nothing about a fill attempt makes the
      // offer stop being valid -- but something else can, WHILE the fill is in
      // flight. Locking the vault retracts the offer and disables this button;
      // a blanket `disabled = false` here then put a live-looking Fill control
      // back underneath a panel reading "Unlock the vault". Repainting from
      // the current state is the only thing that is right in both cases: it
      // re-enables when the offer survived, and leaves it disabled when it
      // did not.
      renderAutofillOffer();
    }
  });

  function hideSavePasswordBanner() {
    const banner = $("save-password-banner");
    if (banner && !banner.hidden) {
      banner.hidden = true;
      syncChromeInsets();
    }
  }

  function applyPendingSave(pending) {
    const banner = $("save-password-banner");
    if (!pending) {
      hideSavePasswordBanner();
      return;
    }
    $("save-password-body").textContent =
      "Save the password for " +
      pending.username +
      " on " +
      pending.origin +
      "?";
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeInsets();
    }
  }

  $("save-password-save").addEventListener("click", async () => {
    const saveBtn = $("save-password-save");
    const dismissBtn = $("save-password-dismiss");
    saveBtn.disabled = true;
    dismissBtn.disabled = true;
    try {
      await rb("cred_save_confirm");
      hideSavePasswordBanner();
      // The vault now has one more entry than it did, for the origin the user
      // is still standing on -- so the toolbar fill button that was absent a
      // moment ago should appear immediately.
      //
      // No longer gated on the Tab Activity panel being open: that button is
      // on the toolbar whether any panel is open or not.
      refreshAutofillOffer();
    } catch (e) {
      // The offer is gone either way: Rust's `cred_save_confirm` always
      // takes the pending save before it can fail, so there is nothing left
      // to retry -- only something to explain.
      hideSavePasswordBanner();
      toast(friendly(e), true);
    } finally {
      saveBtn.disabled = false;
      dismissBtn.disabled = false;
    }
  });

  $("save-password-dismiss").addEventListener("click", () => {
    rb("cred_save_dismiss")
      .then(hideSavePasswordBanner)
      .catch(hideSavePasswordBanner);
  });

  // ---- first-run tour ----
  //
  // Auto-opened by the boot check further down when `onboarding_seen_get`
  // reports `seen: false`. Every dismissal route -- Escape, the scrim, the
  // auto-injected Close button, and "Got it" below -- goes through
  // `onClose`, which is the ONE call site for `onboarding_seen_set`: however
  // the tour is left, it is marked seen exactly once.
  registerPanel("onboarding", {
    el: $("onboarding-panel"),
    button: $("about-tour-again"),
    heightPx: CHROME_OPEN_PX,
    onClose: () => {
      rb("onboarding_seen_set").catch(() => {});
    },
  });
  $("onboarding-done").addEventListener("click", () => closeOpenPanel());

  // ---- command palette ----
  //
  // Ctrl+K only, deliberately -- no toolbar pill. A pill would be a second,
  // redundant way to reach something the shortcut already reaches, and this
  // toolbar's whole two-row redesign exists to keep controls from multiplying
  // for no reason. The shortcut is resolved natively in Rust (shortcuts.rs),
  // because content webviews have no IPC and the key must work while one has
  // focus; it arrives here as the "open_command_palette" event below.
  //
  // Every entry below runs the SAME element a click would -- `.click()` on
  // the real button -- never a second copy of what an action does. Two code
  // paths for one action is how they drift; this file's own history is full
  // of examples.
  let PALETTE_ACTIONS;
  rebuildOnLocaleFill(() => {
    PALETTE_ACTIONS = [
      { label: i18nText("chrome-js-tabs-new-tab", "New tab"), buttonId: "btn-newtab" },
      { label: i18nText("chrome-js-palette-new-quarantine", "New quarantine tab"), buttonId: "btn-quarantine-menu" },
      { label: i18nText("chrome-js-palette-bookmark", "Bookmark this page"), buttonId: "btn-bookmark" },
      { label: i18nText("chrome-js-palette-privacy", "Open Privacy"), buttonId: "btn-privacy" },
      { label: i18nText("chrome-js-palette-theme", "Open Theme"), buttonId: "btn-theme" },
      { label: i18nText("chrome-js-palette-freeze", "Toggle freeze for this tab"), buttonId: "btn-freeze" },
      { label: i18nText("chrome-js-palette-tab-activity", "Open Tab Activity"), buttonId: "btn-tab" },
      { label: i18nText("chrome-js-palette-vault", "Open Vault"), buttonId: "btn-vault" },
      { label: i18nText("chrome-js-palette-imagecheck", "Check an image before you share it"), buttonId: "btn-tab-imagecheck" },
      { label: i18nText("chrome-js-palette-dns", "Open DNS settings"), buttonId: "btn-dns" },
      { label: i18nText("chrome-js-palette-tunnel", "Open Tunnel"), buttonId: "btn-tunnel" },
      { label: i18nText("chrome-js-palette-chat", "Open Chat"), buttonId: "btn-chat" },
      { label: i18nText("chrome-js-palette-library", "Open Library"), buttonId: "btn-library" },
      // The only control that makes a shelf, and it sits in the bookmarks
      // view -- hidden from the "Tab Shelf" view that lists shelves. The
      // palette is its second way in.
      { label: i18nText("chrome-js-palette-set-aside", "Shelve all tabs"), buttonId: "set-aside" },
      // These two buttons are built at runtime by integrity.js/update.js, not
      // in index.html -- which is exactly why they were missed here: nothing
      // failed when the palette predated them. `paletteVisibleActions` resolves
      // ids live at open time, so runtime injection needs no special casing.
      { label: i18nText("chrome-js-palette-integrity", "Open Integrity"), buttonId: "btn-integrity" },
      // The other two tabs of the tools modal. Their buttons are the tab strip
      // itself, so choosing one opens the modal AND lands on the right tool --
      // this is what put all three in one modal in the first place: neither
      // Deep Recall nor the image check was findable from here before.
      { label: i18nText("chrome-js-palette-recall", "Open Deep Recall"), buttonId: "btn-tab-recall" },
      {
        label: i18nText("chrome-js-palette-imagecheck", "Check an image before you share it"),
        buttonId: "btn-tab-imagecheck",
      },
      { label: i18nText("chrome-js-palette-updates", "Open Updates"), buttonId: "btn-update" },
      { label: i18nText("chrome-js-palette-site-info", "About this site"), buttonId: "btn-site-info" },
      { label: i18nText("chrome-js-palette-save-pdf", "Save page as PDF"), buttonId: "btn-save-pdf" },
      { label: i18nText("chrome-js-palette-about", "About PATANYX"), buttonId: "btn-about" },
      // Premium tab-pack entries. Their buttons are hidden literals in
      // index.html (the gate resolves ids there), and the premium refusal
      // happens server-side when the clicked surface asks Rust -- the
      // palette rows stay visible so the features are discoverable.
      { label: i18nText("chrome-js-palette-switch-tab", "Switch tab..."), buttonId: "btn-switcher" },
      { label: i18nText("chrome-js-palette-select-tabs", "Select tabs..."), buttonId: "btn-tabselect" },
    ];
  });
  const PALETTE_OPEN_PX = 420;
  let paletteMatches = [];
  let paletteSelected = -1;
  // Where focus was when Ctrl+K arrived, restored on close -- so pressing the
  // shortcut from the address bar returns to the address bar rather than
  // dropping focus to <body>. Harmless and simply inert when Ctrl+K arrived
  // while a CONTENT webview had focus: this document's own activeElement is
  // then whatever the chrome last focused, if anything, and returning to it
  // changes nothing a user would notice.
  let paletteReturnFocus = null;

  // Filtered to buttons that actually exist and are not `.hidden` -- #btn-chat
  // carries `hidden` in every build until chat.js reveals it, and listing an
  // action here that quietly does nothing when chosen is the exact "coded but
  // the UI lied" defect this project keeps finding in other shapes.
  function paletteVisibleActions() {
    return PALETTE_ACTIONS.filter((a) => {
      const btn = document.getElementById(a.buttonId);
      return btn && !btn.hidden;
    });
  }

  function selectPaletteRow(i) {
    const list = $("palette-list");
    Array.from(list.children).forEach((li, idx) => {
      li.classList.toggle("selected", idx === i);
    });
    paletteSelected = i;
  }

  function renderPaletteMatches(query) {
    const q = query.trim().toLowerCase();
    paletteMatches = paletteVisibleActions().filter((a) =>
      a.label.toLowerCase().includes(q),
    );
    const list = $("palette-list");
    list.replaceChildren();
    paletteMatches.forEach((a) => {
      const li = el("li", "item palette-item");
      li.setAttribute("role", "option");
      li.textContent = a.label;
      li.addEventListener("mouseenter", () =>
        selectPaletteRow(paletteMatches.indexOf(a)),
      );
      li.addEventListener("click", () => runPaletteAction(a));
      list.appendChild(li);
    });
    selectPaletteRow(paletteMatches.length ? 0 : -1);
    $("palette-empty").hidden = paletteMatches.length > 0;
  }

  function runPaletteAction(action) {
    const btn = document.getElementById(action.buttonId);
    closeOpenPanel();
    // Deferred a tick: several targets (Vault, Privacy, Tab Activity...) are
    // panels themselves, and giving the DOM a frame between closing this one
    // and opening the next is the same handoff every other cross-panel
    // transition in this file already uses.
    setTimeout(() => {
      if (btn) btn.click();
    }, 0);
  }

  // registerPanel needs something button-shaped to write aria-pressed onto
  // and to hand focus back to on Escape; the palette has no clickable opener
  // by design, so this satisfies that contract without inventing a second
  // one. Never inserted into the page -- nothing can click it, and it is
  // invisible to panel-audit's markup scan because it is not markup.
  const paletteOpener = document.createElement("button");
  registerPanel("palette", {
    el: $("palette-panel"),
    button: paletteOpener,
    heightPx: PALETTE_OPEN_PX,
    onOpen: () => {
      paletteReturnFocus = document.activeElement;
      $("palette-query").value = "";
      renderPaletteMatches("");
    },
    onClose: () => {
      if (
        paletteReturnFocus &&
        typeof paletteReturnFocus.focus === "function"
      ) {
        paletteReturnFocus.focus();
      }
      paletteReturnFocus = null;
    },
  });
  // ---- tab switcher (Premium) ------------------------------------------
  //
  // A palette-shaped panel over the open tabs. Entry is the palette's
  // "Switch tab..." action -- which clicks the hidden #btn-switcher, ids
  // resolved from index.html exactly as the palette gate requires -- or a
  // programmatic togglePanelNamed("switcher"). The list comes from the
  // gated tabs_switcher_list arm: the gate lives in Rust because a
  // chrome-side licence check is text anyone can edit, and it cannot sit
  // on tab_list because the tab strip, which is not Premium, reads that
  // arm.
  const switcherQuery = $("switcher-query");
  const switcherList = $("switcher-list");
  const switcherEmpty = $("switcher-empty");
  const switcherPremium = $("switcher-premium");
  let switcherRows = []; // rows from the last tabs_switcher_list reply
  let switcherMatches = []; // rows passing the live query, ranked
  let switcherSelected = 0; // index into switcherMatches
  // Bumped on every open. A reply or refusal quoting an older opening is
  // dropped: open -> close -> reopen leaves the first request in flight,
  // and openPanelName alone cannot tell the two openings apart, so a
  // stale reply could paint old rows (or a stale refusal) into the new
  // panel.
  let switcherOpenGen = 0;

  registerPanel("switcher", {
    el: $("switcher-panel"),
    button: $("btn-switcher"),
    heightPx: PALETTE_OPEN_PX, // palette-shaped, palette-sized
    onOpen: openSwitcher,
  });

  function openSwitcher() {
    const gen = ++switcherOpenGen;
    switcherRows = [];
    switcherMatches = [];
    switcherSelected = 0;
    switcherQuery.value = "";
    switcherList.textContent = "";
    switcherEmpty.hidden = true;
    switcherPremium.hidden = true;
    // Show the panel's standing locked notice immediately rather than
    // asking for a list that will be refused; the panel stays open and
    // explains, which is the rule an empty list would break.
    if (!premiumState.premium) {
      switcherPremium.hidden = false;
      syncChromeInsets();
      return;
    }
    rb("tabs_switcher_list", {})
      .then((res) => {
        if (gen !== switcherOpenGen || openPanelName !== "switcher") return;
        switcherRows = (res && Array.isArray(res.items) && res.items) || [];
        renderSwitcherRows();
        switcherQuery.focus();
      })
      .catch((e) => {
        if (gen !== switcherOpenGen || openPanelName !== "switcher") return;
        if (e && e.message === "premium_required") {
          // The refusal is a state the panel shows, never an empty list
          // that reads as "you have no tabs".
          switcherPremium.hidden = false;
          syncChromeInsets();
        } else {
          toast(friendly(e), true);
        }
      });
  }

  function renderSwitcherRows() {
    switcherList.textContent = "";
    const query = switcherQuery.value.trim();
    let ranked;
    if (!query) {
      ranked = switcherRows.slice(); // strip order, as Rust listed it
    } else {
      // Title and address are the two things a person remembers about a
      // tab; the better of the two scores wins, same rule as bookmarks.
      const scored = [];
      for (const row of switcherRows) {
        const byTitle = fuzzyScore(query, String(row.title || ""));
        const byUrl = fuzzyScore(query, String(row.url || ""));
        let best = null;
        for (const score of [byTitle, byUrl]) {
          if (score !== null && (best === null || score > best)) best = score;
        }
        if (best !== null) scored.push({ row, score: best });
      }
      scored.sort((a, b) => b.score - a.score);
      ranked = scored.map((entry) => entry.row);
    }
    switcherMatches = ranked;
    if (switcherSelected >= ranked.length) switcherSelected = ranked.length - 1;
    if (switcherSelected < 0) switcherSelected = 0;
    switcherEmpty.hidden = ranked.length !== 0;
    ranked.forEach((row, i) => {
      const li = el(
        "li",
        "switcher-row" + (i === switcherSelected ? " selected" : ""),
      );
      li.setAttribute("role", "option");
      li.setAttribute(
        "aria-selected",
        i === switcherSelected ? "true" : "false",
      );
      li.appendChild(el("span", "switcher-title", chipLabel(row)));
      li.appendChild(el("span", "switcher-url", row.url || ""));
      li.addEventListener("click", () => activateSwitcherRow(i));
      switcherList.appendChild(li);
    });
  }

  function activateSwitcherRow(index) {
    const row = switcherMatches[index];
    if (!row) return;
    rb("tab_switch", { id: row.id }).catch((e) => toast(friendly(e), true));
    if (openPanelName === "switcher") togglePanelNamed("switcher");
  }

  switcherQuery.addEventListener("input", () => {
    switcherSelected = 0;
    renderSwitcherRows();
  });

  // The palette's keyboard contract, mirrored exactly: arrows WRAP around
  // the ends (the palette moves by modulo, not by clamping) and Enter
  // activates the selected row.
  switcherQuery.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
      ev.preventDefault();
      if (!switcherMatches.length) return;
      const step = ev.key === "ArrowDown" ? 1 : -1;
      switcherSelected =
        (switcherSelected + step + switcherMatches.length) %
        switcherMatches.length;
      renderSwitcherRows();
      const sel = switcherList.querySelector(".selected");
      if (sel && sel.scrollIntoView) sel.scrollIntoView({ block: "nearest" });
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      activateSwitcherRow(switcherSelected);
    }
  });

  $("palette-query").addEventListener("input", (ev) => {
    renderPaletteMatches(ev.target.value);
  });
  $("palette-query").addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown") {
      ev.preventDefault();
      if (paletteMatches.length) {
        selectPaletteRow((paletteSelected + 1) % paletteMatches.length);
      }
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      if (paletteMatches.length) {
        selectPaletteRow(
          (paletteSelected - 1 + paletteMatches.length) % paletteMatches.length,
        );
      }
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      if (paletteSelected >= 0 && paletteMatches[paletteSelected]) {
        runPaletteAction(paletteMatches[paletteSelected]);
      }
    }
  });

  btnBookmark.addEventListener("click", async () => {
    const existing = currentBookmark();
    try {
      if (existing) {
        await rb("bookmark_delete", { id: existing.id });
      } else {
        await rb("bookmark_add", {});
      }
      await refreshBookmarks();
      updateStar();
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  registerPanel("vault", {
    el: panel,
    button: $("btn-vault"),
    heightPx: CHROME_OPEN_PX,
    onOpen: () => {
      refreshVault();
      void refreshPartnerCard("partner-vault", "nordpass");
    },
    // Closing the panel must not leave secrets on screen.
    onClose: clearSecrets,
  });

  registerPanel("privacy", {
    el: $("privacy-panel"),
    button: $("btn-privacy"),
    heightPx: PRIVACY_OPEN_PX,
    onOpen: () => {
      // A destructive control must never be found already confirming, and a
      // "cleared" line from a previous visit must not greet a fresh open as
      // though something just happened. Both are reset before the refresh.
      $("forget-all-confirm").hidden = true;
      $("forget-all-result").hidden = true;
      refreshPrivacy();
    },
  });
  registerPanel("theme", {
    el: $("theme-panel"),
    button: $("btn-theme"),
    heightPx: THEME_OPEN_PX,
    onOpen: () => {
      // The two moved sections' refreshers plus the scheme's: all three
      // read Rust prefs so the rows show the truth, not the last click.
      refreshTheme();
      refreshAccent();
      refreshScheme();
      refreshToolbarLabels();
      rb("bookmarks_bar_get")
        .then((r) => wearBookmarkBar(r.shown))
        .catch(() => {});
    },
  });

  registerPanel("dns", {
    el: $("dns-panel"),
    button: $("btn-dns"),
    heightPx: DNS_OPEN_PX,
    onOpen: () => {
      // A fresh open answers the panel's question first. The affiliate
      // disclosure is reached deliberately from its fourth chip and never
      // replaces the resolver view merely because it was open last time.
      showDnsPartner(false);
      refreshDns();
    },
  });
  $("recovery-ack").addEventListener("click", () => {
    // Clear it from the DOM as well as the screen: it must not sit in the
    // trusted page's memory once the user has moved on.
    $("recovery-key").textContent = "";
    showState("open");
  });

  // ---- tunnel panel + the fail-closed banner -----------------------------
  //
  // All copy about what the tunnel DOES comes from Rust (TunnelMode::describe
  // via tunnel_get's describe_off / describe_imported). This block adds
  // mechanical labels only: button names and status prefixes.
  let tunnelMode = "off";
  // WHEN the current run of "failed" readings began, or 0 for none.
  //
  // TIME, not a count of events, and the difference is the whole point:
  // tab_status is emitted from six sites in state.rs, and a single
  // navigation fires it three times (url change, load start, load finish)
  // within milliseconds. A "two consecutive readings" rule therefore
  // triggered on the browser's FIRST navigation -- i.e. during the normal
  // pre-unlock window, when the listener is parked and refusing exactly as
  // designed -- which is the flash the rule existed to prevent. The
  // failure must persist longer than one probe cycle (10s in
  // tunnel_control) before the user is told the tunnel is down.
  let tunnelFailSince = 0;
  // The last state the PROBE reported, kept because the warning banner needs
  // to tell two different situations apart that the mode alone cannot:
  // "the vault was never unlocked, so the tunnel never came up" and "the
  // tunnel is carrying traffic and the vault locked itself behind it".
  let tunnelMeasured = "not_attempted";
  const TUNNEL_FAIL_GRACE_MS = 15000;
  // The anonymity limit is an emphasized clause, not a plain sentence, and it
  // is built as text nodes plus one strong element so the stress is real and
  // the copy never touches an unsafe HTML sink.
  const WIREGUARD_IMPORT_PRE =
    "Already have a WireGuard configuration? Import it into Private Tunnel, " +
    "PATANYX's free browser-only option. Only this browser's traffic is " +
    "routed through the server you choose. ";
  const WIREGUARD_IMPORT_STRONG = "Private Tunnel is not anonymity:";
  const WIREGUARD_IMPORT_POST =
    " the VPN server can still see the traffic you send through it.";

  function renderWireguardImport(elId) {
    const el = $(elId);
    if (!el) return;
    el.textContent = "";
    el.appendChild(document.createTextNode(WIREGUARD_IMPORT_PRE));
    const strong = document.createElement("strong");
    strong.className = "emph";
    strong.textContent = WIREGUARD_IMPORT_STRONG;
    el.appendChild(strong);
    el.appendChild(document.createTextNode(WIREGUARD_IMPORT_POST));
  }

  $("managed-vpn-framing").textContent =
    "Private Tunnel routes this browser through a WireGuard server you " +
    "supply. These are paid managed VPNs run by their own providers.";
  renderWireguardImport("managed-vpn-wireguard");

  $("tab-tunnel").addEventListener("click", () => selectTunnelTab("tunnel"));
  $("tab-managed-vpn").addEventListener("click", () =>
    selectTunnelTab("managed-vpn"),
  );

  function selectTunnelTab(which) {
    for (const name of ["tunnel", "managed-vpn"]) {
      $("tab-" + name).classList.toggle("active", which === name);
      $("pane-" + name).hidden = which !== name;
    }
  }

  registerPanel("tunnel", {
    el: $("tunnel-panel"),
    button: $("btn-tunnel"),
    heightPx: 500,
    onOpen: () => {
      refreshTunnel();
      void refreshPartnerCards("partner-tunnel", ["nordvpn", "pia"]);
    },
  });

  function renderTunnelRestart(pending) {
    const note = $("tunnelp-restart");
    if (pending) {
      // Says what is true NOW ("not in effect yet") before what to do
      // about it: the user has already changed the setting and the browser
      // is still behaving the old way, which is the surprising half.
      // "Tabs that can be" rather than "your tabs": ephemeral tabs and
      // internal pages are never shelved, and the unqualified promise was
      // simply false for anyone browsing without a saved profile. The exact
      // count is not known until the button is pressed, and that is where
      // it is now stated.
      note.textContent =
i18nText("chrome-tunnel-restart-note", "Not in effect yet. Restart to apply Private Tunnel. Shelved tabs reopen after you unlock; tabs without a saved profile do not.");
      // Machine-readable mirror of what the copy means, so the gate can
      // assert the MEANING without pinning the English words. The claims
      // manifest, not the gate, is what pins wording.
      note.dataset.state = "restart-pending";
      note.hidden = false;
    } else {
      delete note.dataset.state;
      note.hidden = true;
    }
    // The button lives or dies with the note it answers.
    const actions = $("tunnelp-restart-actions");
    if (actions) actions.hidden = !pending;
  }

  function markTunnelChoice(mode) {
    // The class is `active`, the convention every picker here uses; the
    // matching chrome.css rule is scoped `#tunnel-panel button.small.active`
    // so the tunnel gate can check THIS picker (the resolver picker once
    // shipped the class with no rule and every choice rendered alike).
    $("tunnelp-off").classList.toggle("active", mode === "off");
    $("tunnelp-imported").classList.toggle("active", mode === "imported");
  }

  // The three words the engine speaks, in words a person does. The wire
  // vocabulary is a contract (tunnel_control::report returns exactly these
  // three), and it was being printed raw -- "Status: not_attempted" -- on
  // the one surface a user opens to find out whether they are protected.
  //
  // Same phrasing as the engine-confirmed row elsewhere in this file, so
  // two surfaces cannot describe one state differently.
  let TUNNEL_REPORT_TEXT;
  rebuildOnLocaleFill(() => {
    TUNNEL_REPORT_TEXT = {
      not_attempted: i18nText("chrome-js-tunnel-report-not-attempted", "off (no tunnel chosen)"),
      applied: i18nText("chrome-js-tunnel-report-applied", "carrying this browser's traffic"),
      failed: i18nText("chrome-js-tunnel-report-failed", "not carrying traffic"),
    };
  });

  function tunnelReportStatusText(report) {
    // An unknown value from a future engine falls back to the raw word
    // rather than to silence: a status this build cannot name is still
    // better shown than hidden.
    const known = report == null ? null : TUNNEL_REPORT_TEXT[String(report)];
    return report == null
      ? i18nText("chrome-js-tunnel-no-measurement", ". Could not start: ")
      : known || String(report);
  }

  async function refreshTunnel() {
    let st;
    try {
      st = await rb("tunnel_get");
    } catch (e) {
      return; // a refused read leaves the last good state on screen
    }
    tunnelMode = st.mode === "imported" ? "imported" : "off";
    markTunnelChoice(tunnelMode);
    // The per-choice copy. NEVER retyped here: both strings are the engine's
    // own describe() text, so two surfaces cannot word the same choice
    // differently.
    $("tunnelp-describe-off").textContent = st.describe_off || "";
    $("tunnelp-describe-imported").textContent = st.describe_imported || "";
    {
      const status = tunnelReportStatusText(st.report);
      if (st.start_error) {
        // Verbatim: the engine's error text is key-free by contract.
        i18nSet(
          $("tunnelp-status"),
          "chrome-js-tunnel-status-line-error",
          { status, error: st.start_error },
          "Status: " + status + ". Could not start: " + st.start_error,
        );
      } else {
        i18nSet(
          $("tunnelp-status"),
          "chrome-js-tunnel-status-line",
          { status },
          "Status: " + status,
        );
      }
    }
    // The restart note is driven by the ENGINE's answer, on every refresh --
    // not set once as a reaction to a click. It used to be the latter, so
    // closing and reopening the panel lost it while the restart stayed just
    // as pending, and the browser went on tunnelling with nothing on screen
    // saying so.
    renderTunnelRestart(!!st.restart_pending);
    const configLine = $("tunnelp-config");
    // A null has_config means the vault is locked, so Rust cannot say
    // whether a configuration exists. That is a PREREQUISITE, not a
    // failure, and it is now said before the controls it gates rather than
    // after a click that walks the user through a file picker to nowhere.
    const vaultLocked = st.has_config === null || st.has_config === undefined;
    const prereq = $("tunnelp-vault-first");
    if (prereq) prereq.hidden = !vaultLocked;
    for (const id of [
      "tunnelp-import",
      "tunnelp-paste-import",
      "tunnelp-remove",
    ]) {
      const btn = $(id);
      if (btn) btn.disabled = vaultLocked;
    }
    const paste = $("tunnelp-paste");
    if (paste) paste.disabled = vaultLocked;

    if (vaultLocked) {
      configLine.textContent =
        i18nText("chrome-js-tunnel-config-locked", "Unlock the vault to view its configuration.");
    } else if (st.has_config) {
      configLine.textContent = i18nText("chrome-js-tunnel-config-stored", "Configuration stored.");
    } else {
      configLine.textContent = i18nText("chrome-js-tunnel-config-none", "No configuration imported yet.");
    }
    // Step 4 always says something: with nothing pending, the honest answer
    // is that there is nothing to apply, not an empty space that reads as a
    // control that failed to load.
    const appliedNote = $("tunnelp-applied-note");
    if (appliedNote) appliedNote.hidden = !!st.restart_pending;
    syncTunnelWarning();
  }

  async function setTunnelMode(mode) {
    let r;
    try {
      r = await rb("tunnel_set_mode", { mode });
    } catch (e) {
      return; // refused: keep showing what is actually in force
    }
    // The REPLY's mode, not the request's: the engine's echo is the
    // authoritative record of what was accepted and saved.
    tunnelMode = r && r.mode === "imported" ? "imported" : "off";
    tunnelFailSince = 0; // a deliberate change restarts the grace period
    markTunnelChoice(tunnelMode);
    // Re-ask rather than assume: the engine decides whether this change is
    // pending, and setting the mode BACK to whatever is already in force
    // has to clear the note, which a set-only-on-click version could never
    // do.
    await refreshTunnel();
    syncTunnelWarning();
  }

  function syncTunnelWarning() {
    // A LOCKED VAULT IS NOT A BROKEN TUNNEL, and saying so was the whole
    // defect. The configuration lives in the vault, so before the first
    // unlock there is nothing to build a tunnel from; the listener is
    // parked and refusing, every page fails, and the browser reported "the
    // tunnel is down. PATANYX will NOT fall back to a direct connection."
    // True, and useless: it describes the symptom the user can already see
    // and hides the one thing that would fix it. Someone with an entirely
    // healthy configuration reads that their internet is broken.
    //
    // Known instantly -- no measurement is needed to see that the vault is
    // shut -- so this skips the grace period the failure path needs. Fifteen
    // seconds of a blank window before any explanation is most of the
    // confusion.
    //
    // BUT A LOCKED VAULT DOES NOT MEAN A DEAD TUNNEL, and reading it that way
    // was worse than the bug it fixed. tunnel_control has deliberately no
    // on_vault_locked: the session already holds its keys, so locking the
    // password store does not stop a running tunnel. Unlock at boot, browse,
    // let the vault auto-lock, and the mode-only test raised a red alert
    // saying "pages will not load" and advising the user to switch off a
    // tunnel that was carrying their traffic -- while the toolbar button,
    // which reads the measured value, sat green two inches away. Two trusted
    // surfaces disagreeing on screen is worse than either being wrong alone.
    //
    // So the banner is owed only when the vault is shut AND the probe does
    // not report a working tunnel. The boot case still fires immediately,
    // because a tunnel that never came up is never "applied".
    const vaultShut =
      tunnelMode === "imported" &&
      !vaultUnlocked &&
      tunnelMeasured !== "applied";
    const measuredFailure =
      tunnelMode === "imported" &&
      tunnelFailSince !== 0 &&
      Date.now() - tunnelFailSince >= TUNNEL_FAIL_GRACE_MS;
    const show = vaultShut || measuredFailure;

    if (show) {
      const title = $("tunnel-warning-title");
      const body = $("tunnel-warning-body");
      const open = $("tunnel-warning-open");
      if (vaultShut) {
        title.textContent = i18nText("chrome-js-tunnel-warn-vault-title", "Unlock your vault to use Private Tunnel");
        body.textContent =
i18nText("chrome-tunnel-warn-vault-body", "Pages will not load until you unlock the vault because Private Tunnel stores its configuration there. PATANYX will NOT fall back to a direct connection. Unlock the vault or switch Private Tunnel off.");
        // Point at the thing that fixes it, not at the panel that explains
        // it. One button, retargeted, so the banner never grows a second.
        open.textContent = i18nText("chrome-js-tunnel-warn-open-vault", "Open vault");
        open.dataset.target = "vault";
        // Cause, machine-readable, on the banner itself: the gate asserts
        // WHICH failure is being explained without pinning the English.
        $("tunnel-warning").dataset.cause = "vault-locked";
      } else {
        title.textContent = i18nText("chrome-js-tunnel-warn-down-title", "The tunnel is not carrying traffic");
        body.textContent =
i18nText("chrome-tunnel-warn-down-body", "Private Tunnel is down, so pages will not load. PATANYX will NOT fall back to a direct connection.");
        open.textContent = i18nText("chrome-js-tunnel-warn-open-tunnel", "Open Tunnel panel");
        open.dataset.target = "tunnel";
        $("tunnel-warning").dataset.cause = "tunnel-down";
      }
    }

    const banner = $("tunnel-warning");
    if (banner.hidden !== !show) {
      banner.hidden = !show;
      // The chrome is a clipped strip; a (dis)appearing banner changes the
      // height Rust must be told about, same as every other banner.
      syncChromeInsets();
    }
  }

  function noteTunnelMeasured(state) {
    tunnelMeasured = state;
    if (tunnelMode !== "imported") {
      // Off means failing-to-carry-tunnel-traffic is not a failure at all.
      tunnelFailSince = 0;
    } else if (state === "failed") {
      // Start the clock on the FIRST failure of a run and leave it alone
      // afterwards: the banner is owed to a failure that has lasted, not
      // to however many status events happened to arrive.
      if (tunnelFailSince === 0) tunnelFailSince = Date.now();
    } else {
      // Anything that is not a failure -- "applied", "not_attempted", or a
      // value this build does not know -- ends the run.
      tunnelFailSince = 0;
    }
    // THE TOOLBAR SAYS SO WHILE IT IS TRUE. Driven by the MEASURED report,
    // never by the mode: "imported" only means the user asked for a tunnel,
    // and a button that lit up on the asking would be green while traffic
    // went direct. "applied" is the engine's own answer and requires both a
    // live tunnel and a real SOCKS5 round trip (tunnel_control::classify),
    // so this cannot claim protection that is not there.
    //
    // It is also the answer to "I quit days ago, am I still on the VPN?" --
    // the state survives restarts in prefs, so the only honest place to
    // answer that is somewhere always visible.
    const tunnelBtn = $("btn-tunnel");
    if (tunnelBtn) tunnelBtn.classList.toggle("is-active", state === "applied");
    syncTunnelWarning();
  }

  // The banner is time-gated, so a run of failures that stops arriving must
  // still raise it: the last tab_status can land seconds before the grace
  // period expires. Cheap, and it settles on its own once the state clears.
  setInterval(syncTunnelWarning, 5000);

  $("tunnelp-off").addEventListener("click", () => setTunnelMode("off"));
  $("tunnelp-imported").addEventListener("click", () =>
    setTunnelMode("imported"),
  );

  $("tunnelp-import").addEventListener("click", async () => {
    const err = $("tunnelp-error");
    err.hidden = true;
    try {
      const r = await rb("tunnel_import");
      if (r && r.imported) {
        // DECIDED: importing does NOT switch the tunnel on -- the static
        // note in the panel says so, and the refresh reflects the stored
        // configuration without moving the mode.
        await refreshTunnel();
      } else if (r && r.error) {
        // A refused config. The only vocabulary here is ConfigError's
        // Display text, which is key-free by design -- show it verbatim.
        // It rides the SUCCESS payload because the IPC error channel
        // carries static codes only.
        err.textContent = r.error;
        err.hidden = false;
      }
    } catch (e) {
      err.textContent = String(e && e.message ? e.message : e);
      err.hidden = false;
    }
  });

  // The pasted-text import. Same reply shape as the file path, so the
  // refusal text lands in the same place and reads the same way.
  if ($("tunnelp-paste-import")) {
    $("tunnelp-paste-import").addEventListener("click", async () => {
      const box = $("tunnelp-paste");
      const err = $("tunnelp-error");
      err.hidden = true;
      const text = box ? box.value : "";
      if (!text.trim()) {
        err.textContent = i18nText("chrome-js-tunnel-paste-empty", "Paste a configuration first.");
        err.hidden = false;
        return;
      }
      try {
        const r = await rb("tunnel_import_text", { text });
        if (r && r.imported) {
          // Cleared on success only: a refused paste stays on screen so the
          // user can see what was wrong with it rather than re-copying.
          if (box) box.value = "";
          await refreshTunnel();
        } else if (r && r.error) {
          err.textContent = r.error;
          err.hidden = false;
        }
      } catch (e) {
        err.textContent = friendly(e);
        err.hidden = false;
      }
    });
  }

  $("tunnelp-remove").addEventListener("click", async () => {
    try {
      await rb("tunnel_remove");
      tunnelFailSince = 0;
      // Removal IS a mode change (the engine set the mode Off with it), and
      // the running tunnel keeps carrying this session's traffic until the
      // restart -- refreshTunnel asks the engine and renders the note for
      // exactly that reason, so there is nothing to set by hand here.
      await refreshTunnel();
    } catch (e) {
      // Refused (locked vault): leave everything showing what is in force.
    }
  });

  // Apply and restart. This is the only button in the browser that ends the
  // process on purpose, so it is deliberately unglamorous: one send, no
  // confirmation dialog (the user has already chosen the mode and read the
  // note above it), and the button disables itself so a second click cannot
  // shelve the session twice while the first restart is under way.
  if ($("tunnelp-apply-restart")) {
    $("tunnelp-apply-restart").addEventListener("click", async () => {
      const btn = $("tunnelp-apply-restart");
      const err = $("tunnelp-error");
      err.hidden = true;

      // ASK BEFORE SPENDING SOMETHING THAT CANNOT BE GOT BACK. The engine
      // never shelves an ephemeral tab -- that is a privacy promise, not a
      // preference -- and "Open new tabs without a saved profile" is a
      // BROWSER-WIDE setting, so a user who has it on loses every tab here
      // with no way to retrieve them. This button used to restart anyway,
      // under a note promising the tabs would come back.
      //
      // The question is asked ONLY when something will actually be lost, so
      // the ordinary case keeps its one unglamorous click.
      let preview = null;
      try {
        preview = await rb("tunnel_restart_preview");
      } catch (e) {
        // A preview that cannot be taken is not a reason to block the
        // restart; it is a reason not to claim anything about the tabs.
      }
      if (preview && preview.left_out > 0) {
        const lost = preview.left_out;
        const kept = preview.kept;
        const ok = await askConfirm(
          kept === 0
            ? "Restarting will permanently close all " +
                lost +
                (lost === 1 ? " open tab" : " open tabs") +
                ". Tabs without a saved profile are never written to the vault."
            : lost +
                (lost === 1 ? " tab" : " tabs") +
                " will close for good; " +
                kept +
                (kept === 1 ? " will" : " will") +
                " reopen after you unlock. Tabs without a saved profile " +
                "are never written to the vault.",
          i18nText("chrome-js-tunnel-restart-anyway", "Restart anyway"),
        );
        if (!ok) return;
      }

      btn.disabled = true;
      btn.textContent = i18nText("chrome-js-tunnel-restarting", "Restarting…");
      try {
        await rb("tunnel_apply_restart");
        // No success path to render: the reply means the replacement is
        // already running and this process is on its way out.
      } catch (e) {
        // It did NOT happen. Nothing was shelved that is not also cleaned
        // up, so the honest thing is to put the button back.
        btn.disabled = false;
        btn.textContent = i18nText("chrome-js-tunnel-apply-restart", "Apply and restart now");
        err.textContent = friendly(e);
        err.hidden = false;
      }
    });
  }

  // The REAL toolbar button's click, so the panel opens with exactly its
  // normal wiring rather than a copy of it.
  $("tunnel-warning-open").addEventListener("click", () => {
    // Whichever panel actually helps: the vault when that is what is
    // missing, the tunnel panel otherwise. Both go through the REAL toolbar
    // button, so each panel opens with its own registered wiring rather
    // than a copy of it.
    const target = $("tunnel-warning-open").dataset.target;
    $(target === "vault" ? "btn-vault" : "btn-tunnel").click();
  });

  // Learn the mode at boot, so the banner logic has it before any panel
  // opens; it is re-learned after every panel action above.
  refreshTunnel();

  // ---- privacy panel ----

  const PRIVACY_TOGGLES = [
    { id: "pv-block-ads", key: "block_ads" },
    { id: "pv-freeze", key: "freeze_after_load" },
    { id: "pv-js", key: "javascript" },
    { id: "pv-ephemeral", key: "ephemeral" },
  ];

  for (const t of PRIVACY_TOGGLES) {
    $(t.id).addEventListener("change", (ev) => {
      rb("privacy_set", { [t.key]: ev.target.checked })
        .then(applyPrivacyStatus)
        // The reply carries privacy_status only, and a policy change can
        // clear a held-page banner on the Rust side (blocking off removes
        // every pending). Nothing pushed the tab status, so the banner
        // stayed up explaining a hold that no longer existed and its
        // action met "no pending" (review R-003, round 6). Fetch the full
        // status, same shape as login_submit_detected above.
        .then(() => rb("tab_status").then(applyTabStatus).catch(() => {}))
        // Put the switch back where it was: a control that shows "on" while
        // the setting is off is worse than one that visibly refuses.
        .catch(() => refreshPrivacy());
    });
  }

  // Fingerprint noise sits OUTSIDE PRIVACY_TOGGLES on purpose: those ride
  // privacy_set, the retroactive per-tab policy, and divergence cannot be
  // retroactive (the script registers at webview construction; the row's
  // note says "new tabs only"). It is a prefs pair instead, the same shape
  // update.js uses for the background-download checkbox. The reply re-marks
  // the box so the switch never shows a state the pref does not hold.
  $("pv-fingerprint").addEventListener("change", (ev) => {
    rb("fingerprint_noise_set", { enabled: ev.target.checked })
      .then((r) => {
        $("pv-fingerprint").checked = !!r.enabled;
      })
      .catch(() => refreshFingerprint());
  });

  async function refreshFingerprint() {
    try {
      const r = await rb("fingerprint_noise_get");
      $("pv-fingerprint").checked = !!r.enabled;
    } catch (e) {
      // Leave the box as it stands; a failing pref pair surfaces through
      // the same set-path refusal the change handler already covers.
    }
  }

  // WebView2's profile-level belt-and-braces layer. It is intentionally not
  // part of PRIVACY_TOGGLES: those mutate PATANYX's per-tab policy, while
  // this pair persists an engine-profile choice and applies it through its
  // own runtime setter. WebKitGTK has ITP on/off and no corresponding level,
  // so the entire row is absent there, exactly like encrypted DNS.
  const TRACKING_PREVENTION_LEVELS = ["strict", "balanced"];

  function applyTrackingPreventionChoice(st) {
    const section = $("tracking-prevention-choice");
    const supported = !!(st && st.supported);
    section.hidden = !supported;
    if (!supported) return;

    for (const level of TRACKING_PREVENTION_LEVELS) {
      $("tracking-prevention-" + level).classList.toggle(
        "active",
        st.level === level,
      );
    }
    const result = $("tracking-prevention-result");
    if (st.applied === false) {
      // DRAFT COPY -- WP-AB marketing-voice pass required.
      result.textContent =
        "Saved, but not confirmed for every open tab. Check What the engine " +
        "confirmed below.";
    } else if (st.applied === true) {
      // DRAFT COPY -- WP-AB marketing-voice pass required.
      result.textContent =
        (st.level === "balanced" ? "Balanced" : "Strict") +
        " confirmed for every open tab.";
    } else {
      result.textContent = "";
    }
  }

  async function refreshTrackingPrevention() {
    try {
      applyTrackingPreventionChoice(await rb("tracking_prevention_get"));
    } catch (_) {
      $("tracking-prevention-choice").hidden = true;
    }
  }

  for (const level of TRACKING_PREVENTION_LEVELS) {
    $("tracking-prevention-" + level).addEventListener("click", async () => {
      try {
        applyTrackingPreventionChoice(
          await rb("tracking_prevention_set", { level }),
        );
      } catch (_) {
        // The saved/confirmed answer owns the highlight. A refused write must
        // never leave the last button clicked looking like the level in force.
        await refreshTrackingPrevention();
      }
    });
  }

  // ---- per-site Fingerprint Divergence, and the proof ---------------------
  //
  // Two honest limits the copy must keep, and this code must not undermine:
  //
  //   1. A CHOICE REACHES THE NEXT TAB, not this one. Neither engine can
  //      re-register scripts on a live view, so flipping the switch cannot
  //      change what the page in front of you already got. The switch says
  //      so, and the proof line below shows what THIS tab actually got,
  //      which is how the two stay distinguishable.
  //   2. THE PROOF IS ABOUT REGISTRATION. It reports that the script was
  //      installed with a given profile, not that any site was fooled. Only
  //      the live test page can show the second thing, which is why the
  //      button opens it rather than this panel claiming it.

  let divergenceHost = "";

  async function refreshDivergenceSite() {
    const section = $("divergence-site");
    try {
      const proof = await rb("divergence_proof_get");
      divergenceHost = proof.host || "";
      $("dv-premium").hidden = true;
      section.hidden = false;
      if (divergenceHost) {
        i18nSet(
          $("dv-host"),
          "chrome-js-divergence-host",
          { host: divergenceHost },
          "Open tab: " + divergenceHost + ".",
        );
      } else {
        $("dv-host").textContent = i18nText("chrome-js-divergence-no-host", "This tab is not on a website.");
      }
      $("dv-off").checked = !!proof.off_for_this_site;
      $("dv-off").disabled = !divergenceHost;
      // Observed, never inferred from the pref: a tab opened before the
      // pref last changed still carries what it was built with.
      if (!proof.enabled_globally) {
        $("dv-proof").textContent =
          i18nText("chrome-js-divergence-proof-off", "Fingerprint Divergence is off in this tab.");
      } else if (proof.registered) {
        $("dv-proof").textContent =
          "Installed for " +
          (proof.surfaces || []).join(", ") +
          ". This is not proof a site was fooled.";
      } else {
        $("dv-proof").textContent =
          i18nText("chrome-js-divergence-proof-none", "No divergence in this tab; it keeps what it started with.");
      }
      const list = await rb("divergence_sites_list");
      const off = (list.items || []).filter((i) => i.off).map((i) => i.host);
      if (off.length) {
        const hosts = off.join(", ");
        i18nSet(
          $("dv-list"),
          "chrome-js-divergence-off-list",
          { hosts },
          "Divergence Exceptions: " + hosts,
        );
      } else {
        $("dv-list").textContent = i18nText("chrome-js-divergence-list-none", "No Divergence Exceptions.");
      }
    } catch (e) {
      if (e && e.message === "premium_required") {
        // The section stays VISIBLE and explains itself. Hiding it would
        // make a Premium feature indistinguishable from one that does not
        // exist.
        section.hidden = false;
        $("dv-premium").hidden = false;
        $("dv-off").disabled = true;
        $("dv-host").textContent = "";
        $("dv-list").textContent = "";
        $("dv-proof").textContent = "";
        return;
      }
      section.hidden = true;
    }
  }

  $("dv-off").addEventListener("change", async () => {
    if (!divergenceHost) return;
    // NO PREMIUM CHECK HERE, and its removal is the whole point of the
    // 2026-08-19 decision. The four divergence IPC arms were un-gated in
    // Rust, but this handler still called premiumBlocked() first: it
    // reverted the checkbox, toasted "A Premium feature, arriving the day
    // Premium launches", and returned without ever sending
    // divergence_site_set. So a free user saw the switch flip back, under a
    // note that had just been rewritten to say choosing per site is free.
    // Two surfaces contradicting each other one line apart.
    //
    // Un-gating Rust is not enough on its own; the chrome gates
    // independently, and neither licence-planted-defect-gate nor
    // divergence-site-gate caught this -- the first only reads ipc.rs, and
    // the second ran every check with premium: true.
    try {
      if ($("dv-off").checked) {
        await rb("divergence_site_set", {
          host: divergenceHost,
          off: true,
        });
      } else {
        // Default is the ABSENCE of an exception. Clearing instead of storing
        // a `Default` row keeps the list, encrypted snapshot and checkbox as
        // three views of the same fact, and reaches the purpose-built clear
        // arm rather than accumulating rows that do nothing forever.
        await rb("divergence_site_clear", { host: divergenceHost });
      }
    } catch (e) {
      $("dv-off").checked = !$("dv-off").checked;
      toast(friendly(e), true);
    }
    await refreshDivergenceSite();
  });

  // Build a disclosed partner card. DOM ONLY -- parsing HTML strings is banned
  // in this document because it holds the IPC bridge and the vault, so every
  // node here is created and filled with textContent.
  //
  // THE BUTTON IS A BUTTON, NOT AN ANCHOR. The chrome has no business holding
  // partner URLs: it names a partner and the engine resolves that name to a
  // compiled-in destination (see partner.rs). An `<a href>` here would put the
  // URL back in the document and hand anything that can reach this DOM a way
  // to change where it points.
  //
  // The disclosure is visible text in two places, above the pitch and below
  // the button, because `rel="sponsored"` is for crawlers and says nothing to
  // a person. On this surface there is no crawler at all, so the sentence is
  // the whole disclosure.
  function renderPartnerCard(container, partner) {
    const card = document.createElement("section");
    card.className = "pcard";

    const label = document.createElement("p");
    label.className = "pcard-label";
    label.textContent = i18nText("chrome-js-partner-label", "Affiliate partner");
    card.appendChild(label);

    const name = document.createElement("h3");
    name.className = "pcard-name";
    name.textContent = partner.name;
    card.appendChild(name);

    const desc = document.createElement("p");
    desc.className = "pcard-desc";
    desc.textContent = partner.description;
    card.appendChild(desc);

    // A discount code, when this partner has one. Only Saily does; the backend
    // sends `offer: null` for every other card, so no card but Saily's can show
    // a coupon here. Built as nodes, not innerHTML, and the renderer owns the
    // sentence so no partner can phrase its own -- the same discipline as the
    // affiliate label and the disclosure above and below it.
    if (partner.offer && partner.offer.code && partner.offer.terms) {
      const offer = document.createElement("p");
      offer.className = "pcard-offer";
      offer.appendChild(document.createTextNode("Use coupon code "));
      const code = document.createElement("code");
      code.className = "pcard-code";
      code.textContent = partner.offer.code;
      offer.appendChild(code);
      offer.appendChild(
        document.createTextNode(" to get a " + partner.offer.terms + "."),
      );
      card.appendChild(offer);
    }

    const cta = document.createElement("button");
    cta.type = "button";
    cta.className = "small pcard-cta";
    i18nSet(cta, "chrome-js-partner-visit", { name: partner.name }, "Visit " + partner.name);
    cta.addEventListener("click", async () => {
      try {
        await rb("partner_open", { partner: partner.id });
      } catch (e) {
        toast(friendly(e), true);
      }
    });
    card.appendChild(cta);

    const disclosure = document.createElement("p");
    disclosure.className = "pcard-disclosure";
    disclosure.textContent =
      i18nText("chrome-js-partner-disclosure", "PATANYX may earn a commission if you purchase through this link.");
    card.appendChild(disclosure);

    container.appendChild(card);
    return card;
  }

  async function refreshPartnerCards(containerId, partnerIds) {
    const container = $(containerId);
    if (!container) return;
    // Empty once so a partner that stops applying disappears on the next
    // panel open, then append every applicable card through the one renderer
    // that owns the affiliate label and commission disclosure.
    container.textContent = "";
    try {
      const list = await rb("partner_list");
      const items = Array.isArray(list && list.items) ? list.items : [];
      for (const partnerId of partnerIds) {
        const partner = items.find((item) => item.id === partnerId);
        if (partner) renderPartnerCard(container, partner);
      }
    } catch (_) {
      // A partner placement is optional. Failure must not leave a shell that
      // looks like a broken feature beside the first-party controls.
    }
  }

  function refreshPartnerCard(containerId, partnerId) {
    return refreshPartnerCards(containerId, [partnerId]);
  }

  async function refreshPartnerLibrary() {
    const container = $("partner-library");
    const empty = $("partner-library-empty");
    if (!container || !empty) return;
    container.textContent = "";
    empty.hidden = true;
    try {
      const list = await rb("partner_list");
      const items = Array.isArray(list && list.items) ? list.items : [];
      if (!items.length) {
        empty.textContent = i18nText("chrome-js-partners-empty", "No partner services are available right now.");
        empty.hidden = false;
        return;
      }
      for (const partner of items) renderPartnerCard(container, partner);
    } catch (_) {
      empty.textContent = i18nText("chrome-js-partners-failed", "Partner services could not be loaded.");
      empty.hidden = false;
    }
  }

  $("dv-prove").addEventListener("click", async () => {
    // The live test page computes its badges in whatever browser opens it,
    // with nothing hardcoded. That is the only thing that can show a site
    // being fooled, and it is deliberately not a claim this panel makes.
    try {
      await rb("tab_new", {
        url: "https://patanyx.net/fingerprint-divergence/test/",
      });
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  async function refreshPrivacy() {
    try {
      applyPrivacyStatus(await rb("privacy_get"));
    } catch (e) {
      $("privacy-foot").textContent = friendly(e);
    }
    await refreshTrackingPrevention();
    await refreshFingerprint();
    await refreshDivergenceSite();
    await refreshPermissions();
  }

  // ---- clear cookies for every site -------------------------------------
  //
  // The browser-wide counterpart to "Forget this site". Same three-step shape
  // as that control -- click, confirm, act -- and deliberately the same shape
  // rather than the shared askConfirm() dialog: this one has to show a warning
  // Rust wrote, and askConfirm takes a single message string.
  //
  // The result line is CLEARED whenever the confirm is reopened, so a "cleared"
  // notice from an earlier click can never sit under a fresh confirmation and
  // read as though it belongs to it.

  function closeForgetAll() {
    $("forget-all-confirm").hidden = true;
  }

  $("btn-forget-all-cookies").addEventListener("click", () => {
    $("forget-all-result").hidden = true;
    $("forget-all-confirm").hidden = false;
  });
  $("forget-all-cancel").addEventListener("click", closeForgetAll);
  $("forget-all-yes").addEventListener("click", async () => {
    const btn = $("forget-all-yes");
    btn.disabled = true;
    try {
      const data = await rb("cookies_forget_all");
      closeForgetAll();
      // Written from the REPLY, never from the click, and worded by Rust
      // (cookie_control::cleared_line). The fallback is only for a reply that
      // somehow arrives without one; it says the same thing rather than
      // inventing a second, looser claim.
      $("forget-all-result").hidden = false;
      $("forget-all-result").textContent =
        data.message || "Cookies cleared for every site.";
    } catch (e) {
      // The confirm stays OPEN on failure. Nothing was cleared, so closing it
      // would leave the panel looking exactly like the success case with only
      // a toast to tell them apart.
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  // ---- site permissions -----------------------------------------------------
  // Deny-by-default, session-only. Rendered from permission_status rather than
  // from anything this file remembers: the table lives in Rust and the engine
  // callback writes to it, so a cached copy here would go stale the moment a
  // page asked for something.

  let PERMISSION_LABELS;
  rebuildOnLocaleFill(() => {
    PERMISSION_LABELS = {
      camera: i18nText("chrome-js-permissions-camera", "Camera"),
      microphone: i18nText("chrome-js-permissions-microphone", "Microphone"),
      geolocation: i18nText("chrome-js-permissions-geolocation", "Location"),
      notifications: i18nText("chrome-js-permissions-notifications", "Notifications"),
    };
  });

  async function refreshPermissions() {
    let st;
    try {
      st = await rb("permission_status");
    } catch (e) {
      $("permission-note").textContent = friendly(e);
      return;
    }
    renderPermissions(st);
  }

  function renderPermissions(st) {
    const list = $("permission-list");
    const note = $("permission-note");
    list.replaceChildren();
    if (!st) return;

    // UNSUPPORTED MEANS THE CONTROLS ARE DEAD, and they are shown disabled
    // rather than merely annotated. A switch that looks operable but changes
    // nothing is the exact shape of defect this project has paid for before.
    if (!st.supported) {
      note.textContent =
        i18nText("chrome-js-permissions-unsupported", "This tab is not enforcing Permission Defaults.");
      return;
    }

    const entries = st.entries || [];
    // Empty now means there is no site to attach a permission TO -- a blank
    // tab, or an internal page. It no longer means "nothing has asked": the
    // four kinds are always listed for a real site, so the user can allow one
    // before a page ever requests it rather than having to trigger a silent
    // refusal first and go looking for the row it left behind.
    if (entries.length === 0) {
      note.textContent =
        i18nText("chrome-js-permissions-empty", "Open a site to set Permission Defaults; they stay off until allowed.");
      return;
    }
    note.textContent = "";

    for (const entry of entries) {
      const row = document.createElement("label");
      row.className = "toggle-row";
      const input = document.createElement("input");
      input.type = "checkbox";
      input.checked = !!entry.granted;
      input.disabled = !st.supported;
      input.addEventListener("change", async (ev) => {
        const want = ev.target.checked;
        try {
          renderPermissions(
            await rb(want ? "permission_grant" : "permission_revoke", {
              origin: entry.origin,
              kind: entry.kind,
            }),
          );
        } catch (e) {
          // Put the switch back where it was: the table did not change, so
          // the UI must not claim it did.
          ev.target.checked = !want;
          note.textContent = friendly(e);
        }
      });

      const text = document.createElement("span");
      text.className = "toggle-text";
      const title = document.createElement("span");
      title.className = "toggle-title";
      title.textContent = PERMISSION_LABELS[entry.kind] || entry.kind;
      const sub = document.createElement("span");
      sub.className = "toggle-note";
      // An embedded frame's own origin, named, because "this site" would be
      // wrong: the request came from something the page embeds, and allowing
      // it allows that thing, not the page.
      const who =
        entry.origin === st.site
          ? i18nText("chrome-permissions-who-this-site", "this site")
          : entry.origin;
      // The reload that makes a change take effect is done for the user now
      // (see permission_grant in ipc.rs), so this no longer tells them to do
      // it themselves. What it must still say is that the grant DIES ON CLOSE,
      // because anyone arriving from another browser will expect it to persist.
      if (entry.granted) {
        i18nSet(sub, "chrome-permissions-granted", { who },
          `Allowed for ${who} until PATANYX closes`);
      } else {
        i18nSet(sub, "chrome-permissions-refused",
          { who, count: entry.deniedCount || 0 },
          entry.deniedCount > 1
            ? `Refused ${entry.deniedCount} times for ${who}`
            : `Refused for ${who}`);
      }
      text.appendChild(title);
      text.appendChild(sub);
      row.appendChild(input);
      row.appendChild(text);
      list.appendChild(row);
    }
  }

  function applyPrivacyStatus(st) {
    if (!st) return;
    for (const t of PRIVACY_TOGGLES) {
      $(t.id).checked = !!st[t.key];
    }

    // The browser-wide cookie control's wording, written verbatim from what
    // Rust sent (state.rs's privacy_status, worded by cookie_control). Every
    // one of these elements is empty in index.html, so there is no second,
    // unchecked set of words here to drift from the Rust one.
    //
    // Written UNCONDITIONALLY, empty string included, rather than under an
    // `if (st.forget_all)`. A reply that arrives without the copy is a Rust
    // bug, and the guard would hide it in the worst possible way: the section
    // keeps whatever a PREVIOUS reply put there, so a warning could outlive
    // the payload it came from and describe a version of the feature that is
    // no longer what the button does. Blank is legible and safe; stale is
    // neither.
    const copy = st.forget_all || {};
    // Where the backend cannot clear cookies (WebKitGTK in 1.0.0) BOTH controls
    // are disabled and the intro says so in Rust's words: an enabled button
    // that always fails is a false claim about what the product does.
    // `!== false` so a reply from an older Rust that omits the field keeps the
    // enabled behaviour rather than silently disabling a working control.
    applyCookieClearAvailability(st);
    const available = cookieClearAvailable;
    $("pv-forget-all-desc").textContent = available
      ? (copy.intro || "")
      : (st.cookie_clear_unavailable_intro || "");
    $("btn-forget-all-cookies").textContent = copy.button || "";
    $("forget-all-warn").textContent = copy.warning || "";
    $("forget-all-yes").textContent = copy.confirm || "";
    $("forget-all-cancel").textContent = copy.cancel || "";

    // A protection this engine cannot enforce is shown, disabled, and
    // explained. Hiding it would misrepresent the product; leaving it live
    // would be a switch that does nothing.
    // `interception` is per TAB, unlike the platform capability flags: a
    // tab whose request handler failed to register intercepts nothing, no
    // matter what the engine can do in principle. Without this the switch
    // stayed live and counted, on a tab where it does nothing at all.
    lastTabInterception = st.interception;
    // NOT renderEngineConfirmed(st) -- see applyTabStatus.
    //
    // It was called from here, with the `privacy_get` reply, for as long as the
    // section has existed. That reply carries the six BROWSER-WIDE policy
    // fields; every key in ENGINE_LABELS is PER-TAB and arrives in
    // `tab_status`. So every lookup was undefined, the loop skipped every row,
    // and "What the engine confirmed" rendered its heading and its paragraph
    // and nothing else -- a section whose entire purpose is to report what the
    // engine did, reporting nothing, silently, since it shipped.
    //
    // `lastTabInterception` above has the same shape of bug and survives it by
    // luck: `st.interception` is undefined here too, and the reader below
    // treats undefined as "intercepting". It is left alone rather than moved,
    // because changing what that computes is a behaviour change and this is
    // not the commit for it.
    refreshDns();
    const intercepting =
      st.interception === undefined ||
      st.interception === "registered" ||
      st.interception === "registered_legacy" ||
      st.interception === "content_filter";
    setSupported(
      "pv-block-ads",
      st.network_blocking_supported && intercepting,
      intercepting
        ? i18nText("chrome-js-privacy-blockads-platform", "Ad and tracker requests cannot be blocked on this platform.")
        : i18nText("chrome-js-privacy-blockads-tab", "Ad and tracker blocking is unavailable in this tab. Reopen it."),
    );
    setSupported(
      "pv-freeze",
      st.freeze_enforced,
      i18nText("chrome-js-privacy-freeze-platform", "Page freezing is unavailable on this platform."),
    );

    // Count only what is actually protecting the user right now: JavaScript
    // being ON is the default, not a protection, and a protection the engine
    // cannot enforce must not be counted as if it were.
    let active = 0;
    if (st.block_ads && st.network_blocking_supported && intercepting)
      active += 1;
    if (st.freeze_after_load && st.freeze_enforced) active += 1;
    if (!st.javascript) active += 1;
    if (st.ephemeral) active += 1;

    shieldActive = active;
    // Whether blocking is CURRENTLY DOING SOMETHING, kept separately from the
    // count because the badge needs it on its own. A blocked-request tally of
    // zero means two opposite things -- "this page had nothing worth blocking"
    // and "blocking is switched off" -- and only this tells them apart.
    blockingActive = !!(
      st.block_ads &&
      st.network_blocking_supported &&
      intercepting
    );
    refreshShield();

    $("privacy-foot").textContent =
      active === 0
        ? i18nText("chrome-js-privacy-foot-none", "No protections selected.")
        : i18nText("chrome-js-privacy-foot-active", "Applies to all open tabs.");
  }

  // ---- the shield --------------------------------------------------------
  //
  // One control answering "am I protected right now", fed by THREE independent
  // sources that arrive at different times and from different places:
  //
  //   1. how many protections are on   -- `privacy_get`, browser-wide
  //   2. what the engine REFUSED       -- `tab_status`, per tab
  //   3. whether the malicious-site list is current -- `blocklist_refreshed`
  //
  // Hence the stored values and the single recompute, rather than each handler
  // painting the button itself: whichever message lands last would otherwise
  // overwrite what the other two had established, and the one that loses is
  // whichever the timing happened to disfavour.
  //
  // WHERE THE REFUSAL SIGNAL COMES FROM, because the obvious answer is wrong.
  // It is NOT `.toggle-row.unsupported`. That class means "not available on
  // this platform" -- a capability gap, an honest and permanent absence, and
  // the engine refusing nothing because it was never asked. Reading it here
  // would light the shield amber on Linux for having no DoH, while a Windows
  // engine that was asked for ephemeral storage and declined would show green.
  // That is exactly backwards, and it is the one misreport this browser exists
  // to refuse. The real signal is the value "failed" on the per-tab engine
  // fields, which is what Rust writes when it asked and did not get.
  let shieldActive = 0;
  let blockingActive = false;
  // TWO facts, kept apart on purpose. At startup the browser knows how many
  // hosts the list holds but knows nothing about whether the last refresh
  // succeeded -- it has not run one yet. Folding both into a single object
  // with an `ok` flag would force this code to invent one of them, and the
  // invented answer would be "refresh succeeded", which is the reassuring
  // direction and the wrong one.
  let blocklistHosts = null;
  let blocklistFailure = null;
  function refreshShield() {
    const st = lastTabStatus || {};
    // Both come from `tab_status`, and must be read together: the total is
    // meaningless without the flag saying whether the platform observed it.
    const countsBlocked = st.ledger_counts_blocked === true;
    const blockedOnPage = Number(st.blocked_total) || 0;
    const refused = [];
    for (const key of Object.keys(ENGINE_LABELS)) {
      if (st[key] === "failed") refused.push(ENGINE_LABELS[key]);
    }
    // A blocklist that failed to refresh is a protection quietly degrading:
    // the browser keeps running on whatever list it last had, or on the
    // bundled floor, and every hour that passes makes it staler. Rust has
    // always reported this; nothing had ever listened.
    const blocklistFailed = blocklistFailure !== null;

    const warn = refused.length > 0 || blocklistFailed;
    const btn = $("btn-privacy");
    const badge = $("privacy-count");

    // BOTH classes, when both are true. `.is-warning` is ranked after
    // `.is-active` in the stylesheet precisely so that a browser with three
    // protections running and one refused reads amber -- the refusal is the
    // fact the user does not already assume.
    btn.classList.toggle("is-active", shieldActive > 0);
    btn.classList.toggle("is-warning", warn);

    // THE BADGE PREFERS THE NUMBER PEOPLE ACTUALLY LOOK AT.
    //
    // It counted protections-enabled, which is a number about your settings.
    // The number a shield is read for is what it stopped ON THIS PAGE, and
    // that is what every mainstream blocker puts there.
    //
    // Shown only where it MEANS something, which is two conditions and not
    // one:
    //
    //   * `ledger_counts_blocked` -- the platform can observe blocking at all.
    //     On WebKitGTK the engine drops matching requests internally and never
    //     calls back, so the column is structurally zero. Rendering that as
    //     "0 blocked" would report a measurement that was never taken.
    //   * blocking is actually ON. A zero with the switch off means "not
    //     blocking", and a badge reading 0 next to a shield is read as "you
    //     are covered, there was nothing to stop" -- the reassuring
    //     interpretation, and the wrong one.
    //
    // Where either fails it falls back to the protections count, which is
    // always true even if it is less interesting.
    const showBlocked = countsBlocked && blockingActive;
    const badgeValue = showBlocked ? blockedOnPage : shieldActive;
    badge.hidden = !showBlocked && shieldActive === 0;
    badge.textContent = String(badgeValue);
    badge.classList.toggle("badge-count", showBlocked);
    // Green only once something was actually stopped; a muted zero, so the
    // badge cannot be read as a score for a page that had nothing on it.
    badge.classList.toggle("badge-some", !showBlocked || blockedOnPage > 0);

    // The tooltip is the whole sentence, and it NAMES what was refused. A
    // count alone would say "3 active" on a browser that had just been told
    // no, which is true and useless.
    const parts = [];
    // What was stopped here leads, when it is a real observation -- it is the
    // reason someone looks at the badge, and the badge is now showing it.
    if (showBlocked) {
      parts.push(
        blockedOnPage === 0
          ? i18nText("chrome-js-shield-blocked-none", "Nothing blocked on this page")
          : blockedOnPage +
              " request" +
              (blockedOnPage === 1 ? "" : "s") +
              " blocked on this page",
      );
    }
    parts.push(
      shieldActive === 0
        ? i18nText("chrome-js-shield-active-none", "No protections active")
        : shieldActive +
            " protection" +
            (shieldActive === 1 ? "" : "s") +
            " active",
    );
    const refusedPart = refused.length
      ? "REFUSED by the engine: " + refused.join(", ")
      : null;
    if (refusedPart) parts.push(refusedPart);
    if (blocklistFailed) {
      parts.push(i18nText("chrome-js-shield-blocklist-failed", "the malicious-site list could not be refreshed"));
    }
    const sentence = parts.join(". ") + ".";
    btn.title = sentence;
    // Screen readers get the same sentence rather than the word "Privacy".
    // The visible label stays one word because the button is 90px wide; the
    // accessible name has no such budget and should not inherit that limit.
    btn.setAttribute("aria-label", "Privacy protections: " + sentence);
    if (currentUiLocale !== "en") {
      (async () => {
        const resolved = parts.slice();
        if (refusedPart) {
          resolved[parts.indexOf(refusedPart)] = await i18nResolve(
            "chrome-js-shield-refused",
            { labels: refused.join(", ") },
            refusedPart,
          );
        }
        const text = resolved.join(". ") + ".";
        btn.title = text;
        btn.setAttribute(
          "aria-label",
          await i18nResolve(
            "chrome-js-shield-aria",
            { sentence: text },
            "Privacy protections: " + sentence,
          ),
        );
      })();
    }
  }

  // ---- the vault is about to lock ----------------------------------------
  //
  // Rust raises this once, one minute out, and the countdown is run here
  // rather than by a stream of events: one message plus a local timer beats
  // sixty messages, and if the process is too busy to tick the clock the user
  // has bigger problems than a stale number.
  let lockCountdown = null;

  function hideLockWarning() {
    if (lockCountdown) {
      clearInterval(lockCountdown);
      lockCountdown = null;
    }
    const banner = $("lock-warning");
    if (banner && !banner.hidden) {
      banner.hidden = true;
      syncChromeInsets();
    }
  }

  function showLockWarning(seconds) {
    const banner = $("lock-warning");
    if (!banner) return;
    let left = Math.max(1, Number(seconds) || 60);
    const body = $("lock-warning-body");

    const paint = () => {
      body.textContent =
        left > 1
          ? "Vault locks in " + left + " seconds."
          : i18nText("chrome-js-lockwarn-now", "Locking now.");
    };
    paint();
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeInsets();
    }
    if (lockCountdown) clearInterval(lockCountdown);
    lockCountdown = setInterval(() => {
      left -= 1;
      if (left <= 0) {
        // Rust owns the actual lock; this only stops counting. If the two
        // disagree the vault_locked event is what settles it.
        clearInterval(lockCountdown);
        lockCountdown = null;
        return;
      }
      paint();
    }, 1000);
  }

  /// The malicious-site list finished a refresh, successfully or not.
  ///
  /// Deliberately NOT a toast. The refresh runs about hourly, so a network
  /// that is down would raise the same notice twenty-four times a day and
  /// teach the user to dismiss it without reading -- which is how a warning
  /// stops being a warning. The shield turns amber and stays amber for as long
  /// as the condition holds, the tooltip says what happened, and the privacy
  /// panel carries the detail. A persistent state beats a repeated interrupt.
  function applyBlocklistRefreshed(data) {
    const d = data || {};
    if (d.ok === false) {
      // Empty string rather than null when Rust sent no detail: the FACT of
      // the failure is what matters and must not be lost because the reason
      // was missing.
      blocklistFailure = typeof d.detail === "string" ? d.detail : "";
    } else {
      blocklistFailure = null;
      if (typeof d.hosts === "number") blocklistHosts = d.hosts;
    }
    refreshShield();
    // The panel may be open while this arrives; re-render so its row is not
    // showing the previous answer until the next tab switch.
    if (lastTabStatus) renderEngineConfirmed(lastTabStatus);
  }

  function setSupported(id, supported, reason) {
    const input = $(id);
    const row = input.closest(".toggle-row");
    const note = $(id + "-note");
    input.disabled = !supported;
    row.classList.toggle("unsupported", !supported);
    if (!supported && note) {
      note.textContent = reason;
    }
  }

  // Inserted as text, never as HTML, like everything else that crosses the
  // IPC boundary into this trusted page.
  function showRecoveryKey(key) {
    $("recovery-key").textContent = key;
    showState("recovery");
  }

  function showState(name) {
    for (const key of Object.keys(statePanes)) {
      statePanes[key].hidden = key !== name;
    }
    setVaultIndicator(name);
    // The Premium row is part of the OPEN state, so it refreshes wherever
    // that state is entered -- and it is entered from FIVE places: create,
    // encrypted-import, unlock, the recovery-key acknowledgement, and
    // refreshVault. Only refreshVault used to refresh the row, so a freshly
    // created vault showed no Premium row at all until the panel was closed
    // and reopened (caught by clicking through the real Linux build, not by
    // any test). Refreshing HERE is the single-writer fix: one entry point
    // to the state, one place that populates it.
    //
    // Fire-and-forget on purpose: it is one passive IPC read that owns its
    // own error handling, and showState is called from synchronous paths.
    if (name === "open") {
      void refreshLicence();
      // Unlock is when every bookmark becomes knowable. Refresh the cache,
      // not merely the optional bar: when that bar is hidden it deliberately
      // renders nothing, but the toolbar star still needs bookmarkItems to
      // answer for the current page.
      refreshLibraryAfterUnlock();
      // The Backup pane's copy of the auto-lock picker, for the same reason
      // the locked screen's is refreshed below: the value it shows must be
      // the current one whenever the screen carrying it appears.
      void refreshAutolock();
    }
    // Same rule for the auto-lock picker, which moved to the LOCKED screen
    // (decided 2026-08-05): the value it shows must be the current one
    // whenever that screen appears, including after a lock that happened
    // while the panel was closed.
    if (name === "locked") {
      void refreshAutolock();
    }
  }

  // The padlock in the toolbar reflects the vault WITHOUT the panel being
  // open: the shackle lifts when unlocked and a dot appears, so "are my
  // secrets currently reachable" is answerable at a glance. That question
  // matters because the vault auto-locks on its own, after an interval the
  // user chooses (Never / 5 / 15 / 30 / 60 minutes, five by default --
  // AUTOLOCK_LABELS above, prefs::AUTOLOCK_DEFAULT_SECS in Rust). No string
  // in this file may name a duration for that reason.
  function setVaultIndicator(name) {
    const unlocked = name === "open" || name === "recovery";
    // Locking the vault has to retract a fill button that is already on the
    // toolbar, and unlocking has to offer one for the page in front of you
    // without waiting for a navigation. Both fall out of re-checking here,
    // because `vaultUnlocked` is part of the cache key.
    if (unlocked !== vaultUnlocked) {
      vaultUnlocked = unlocked;
      refreshAutofillOffer();
      // The tunnel banner's whole point is that a shut vault is why nothing
      // loads. Unlocking must take it down at that moment, not at whatever
      // the next status event happens to be.
      syncTunnelWarning();
    }
    const btn = $("btn-vault");
    const dot = $("vault-dot");
    const shackle = $("vault-shackle");
    btn.classList.toggle("is-active", unlocked);
    dot.hidden = !unlocked;
    if (shackle) {
      // Open padlock: the shackle swings up and to the right.
      shackle.setAttribute(
        "d",
        unlocked
          ? "M5.5 7 V4.75 A2.5 2.5 0 0 1 10.5 4.75"
          : "M5.5 7 V4.75 A2.5 2.5 0 0 1 10.5 4.75 V7",
      );
    }
    btn.title = unlocked ? i18nText("chrome-js-vault-indicator-unlocked", "Vault: unlocked") : i18nText("chrome-js-vault-indicator-locked", "Vault: locked");
  }

  async function refreshVault() {
    try {
      const st = await rb("vault_status");
      if (!st.exists) {
        showState("none");
      } else if (!st.unlocked) {
        showState("locked");
      } else {
        // No refreshLicence() here: showState("open") does it for every
        // path that reaches the open state, this one included.
        showState("open");
        await reloadLists();
      }
    } catch (e) {
      /* leave the panel as-is */
    }
  }

  // ---- Premium licence row ----------------------------------------------
  // The refusal codes ride the SUCCESS payload (the tunnel_import pattern:
  // the error channel is static codes only), so this table — not
  // ERROR_TEXT — owns their copy. It is the ONLY licence copy chrome
  // words: everything else (the row head/sub, the ended date) arrives
  // already worded by Rust. All of it is design-3.2 DRAFT copy pending
  // review.
  let LICENCE_PASTE_TEXT;
  rebuildOnLocaleFill(() => {
    LICENCE_PASTE_TEXT = {
      licence_not_a_token:
        i18nText("chrome-js-licence-not-a-token", "That doesn't look like a PATANYX Premium token. Copy the full token from your receipt and paste it again."),
      licence_needs_newer_build:
        i18nText("chrome-js-licence-needs-newer-build", "This token needs a newer version of PATANYX. Update and try again."),
      licence_not_issued:
        i18nText("chrome-js-licence-not-issued", "This token was not issued by EdgeXene. Check that you copied it from your EdgeXene receipt."),
      licence_keys_unavailable: i18nText("chrome-js-licence-keys-unavailable", "This build cannot verify Premium tokens yet."),
    };
  });

  // A pasted token awaiting the different-license confirmation. A bearer
  // credential: held in memory only and dropped on EVERY exit from the
  // confirmation state — use, a new submit, a refusal, or the row hiding
  // (which is what a vault lock looks like from here). The independent
  // review caught the first draft keeping it across those paths.
  let pendingLicenceToken = null;

  function clearLicenceConfirm() {
    pendingLicenceToken = null;
    $("premium-confirm").hidden = true;
  }

  // ---- Premium controls in the toolbar ------------------------------------
  //
  // A gated control renders LOCKED rather than looking ordinary and refusing
  // after the click. Marked in the markup with data-premium, so a new Premium
  // control is covered by adding the attribute and nothing here changes.
  //
  // THE STATE THAT MATTERS IS "locked". The licence session dies with the
  // vault, so a paying customer whose vault is closed reads as no-licence to
  // the GATE, which is correct and fail-closed. Saying "upgrade" to that
  // person would be telling someone to buy what they already own, so the
  // locked vault gets its own sentence.
  //
  // Nothing is for sale before launch, so `on_sale` decides whether the
  // wording may point at a purchase at all.
  let premiumState = { state: "locked", premium: false, on_sale: false };
  const premiumListeners = [];

  function premiumLockNote(st) {
    if (st.state === "locked") {
      return i18nText("chrome-js-premium-lock-note", "Unlock your vault to use Premium features.");
    }
    // Phase 4: paid and ACTIVE, but not activated on THIS device. Never a
    // purchase prompt (they already paid); the Vault panel says why.
    if (st.state === "unactivated") {
      return i18nText("chrome-js-premium-unactivated", "Premium is not activated on this device yet. Open the Vault panel to activate it.");
    }
    if (!st.on_sale) {
      return i18nText("chrome-js-premium-pre-launch", "A Premium feature. It unlocks with a Premium license in your Vault.");
    }
    return st.state === "lapsed"
      ? i18nText("chrome-js-premium-lapsed", "Your Premium has ended. Renew to use this again.")
      : i18nText("chrome-js-premium-upgrade", "A Premium feature. Upgrade to Premium to use it.");
  }

  // Each control's OWN description, captured from the markup once, before any
  // lock note can overwrite a title. Capturing lazily at first lock instead
  // made the saved value depend on when the first lock happened, so a title
  // set while locked could be restored over the real one. Markup is the
  // single source for this wording, so read it once and never again.
  for (const el of document.querySelectorAll("[data-premium]")) {
    el.setAttribute("data-premium-title", el.getAttribute("title") || "");
  }

  function applyPremiumState(st) {
    premiumState = st;
    const note = premiumLockNote(st);
    for (const el of document.querySelectorAll("[data-premium]")) {
      if (st.premium) {
        el.classList.remove("premium-locked");
        el.removeAttribute("aria-disabled");
        // Restore the control's own description, captured above.
        const own = el.getAttribute("data-premium-title");
        if (own !== null) el.setAttribute("title", own);
      } else {
        el.classList.add("premium-locked");
        // aria-disabled, NOT the disabled property: a disabled button cannot
        // be focused or clicked, so a keyboard user could not reach it to
        // find out WHY it is unavailable. It stays reachable and explains.
        el.setAttribute("aria-disabled", "true");
        el.setAttribute("title", note);
      }
    }
      for (const fn of premiumListeners) fn(st);
  }

  // Returns true when the click was swallowed by the lock. Every gated
  // control calls this FIRST; the Rust arm still gates independently, so a
  // chrome that forgot this cannot actually unlock anything.
  function premiumBlocked() {
    if (premiumState.premium) return false;
    toast(premiumLockNote(premiumState));
    return true;
  }

  async function refreshPremium() {
    try {
      applyPremiumState(await rb("premium_status"));
    } catch {
      // An unreadable state must not unlock the toolbar: leave whatever is
      // rendered, which starts locked.
    }
  }

  async function refreshLicence() {
    // Every path that renders the Premium row is also a path where the
    // licence may have just changed (unlock, paste, remove), so the toolbar
    // is refreshed from the same place rather than from three call sites.
    refreshPremium();
    const row = $("premium-row");
    try {
      const lic = await rb("licence_get");
      if (lic.row_head == null) {
        // Locked vault: the quietest rendering is no row at all — and no
        // held token either.
        clearLicenceConfirm();
        $("premium-remove").hidden = true;
        $("premium-token-actions").hidden = true;
        $("premium-buy").textContent = "";
        $("premium-buy").hidden = true;
        row.hidden = true;
        return;
      }
      row.hidden = false;
      $("premium-head").textContent = lic.row_head;
      $("premium-sub").textContent = lic.row_sub || "";
      const buy = $("premium-buy");
      buy.textContent = lic.purchase_copy || "";
      buy.hidden = !lic.purchase_copy;
      renderActivation(lic);
      const remove = $("premium-remove");
      remove.hidden = !lic.has_token;
      remove.disabled = !!lic.activation_busy;
      remove.dataset.activated = lic.activation === "activated" ? "1" : "0";
      $("premium-token-actions").hidden = !lic.has_token;
    } catch (e) {
      clearLicenceConfirm();
      $("premium-remove").hidden = true;
      $("premium-token-actions").hidden = true;
      $("premium-buy").textContent = "";
      $("premium-buy").hidden = true;
      row.hidden = true;
    }
  }

  // Phase 4: the activation line under the row. Rust decides the state and
  // words the note; this only chooses which of the two buttons applies.
  //   activated    -> "Activated on this device." + Release
  //   unactivated  -> the Rust sentence + Activate now (unless a call is
  //                   already running, when the sentence says so)
  //   not_needed   -> hidden (free or lapsed: nothing to activate)
  function renderActivation(lic) {
    const box = $("premium-activation");
    const note = $("premium-activation-note");
    const activate = $("premium-activate");
    const release = $("premium-release");
    const offline = $("premium-offline");
    const deviceId = $("premium-device-id");
    if (!box || !note || !activate || !release) return;
    // The device id is the same in every state; fill it whenever we have it.
    if (deviceId && lic.device_id_hex) deviceId.textContent = lic.device_id_hex;
    if (lic.activation === "activated") {
      box.hidden = false;
      note.textContent =
        i18nText("chrome-js-licence-activated-note", "Activated on this device. A license can be active on up to 5 devices.");
      activate.hidden = true;
      release.hidden = false;
      release.disabled = !!lic.activation_busy;
      // Already activated: nothing to import.
      if (offline) offline.hidden = true;
      return;
    }
    if (lic.activation === "unactivated") {
      box.hidden = false;
      note.textContent = lic.activation_note || "";
      release.hidden = true;
      activate.hidden = false;
      activate.disabled = !!lic.activation_busy;
      // Offer the offline path only when there is a device id to bind to.
      if (offline) offline.hidden = !lic.device_id_hex;
      return;
    }
    box.hidden = true;
    note.textContent = "";
    activate.hidden = true;
    release.hidden = true;
    if (offline) offline.hidden = true;
  }

  $("premium-activate").addEventListener("click", async () => {
    $("premium-activate").disabled = true;
    try {
      await rb("licence_activate", {});
    } catch (e) {
      toast(friendly(e), true);
    }
    // The outcome arrives as licence_changed; until then the row shows
    // "Activating this device..." from Rust.
    await refreshLicence();
  });

  // Offline activation: copy this device's id, and import a receipt.
  $("premium-device-id-copy")?.addEventListener("click", async () => {
    const id = ($("premium-device-id")?.textContent || "").trim();
    if (!id || id === "\u2014") return;
    try {
      await navigator.clipboard.writeText(id);
      toast(i18nText("chrome-js-device-id-copied", "Device ID copied."));
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  $("premium-receipt-import")?.addEventListener("click", async () => {
    const field = $("premium-receipt");
    const status = $("premium-receipt-status");
    const btn = $("premium-receipt-import");
    const receipt = (field?.value || "").trim();
    const show = (msg, isError) => {
      if (!status) return;
      status.hidden = false;
      status.textContent = msg;
      status.classList.toggle("error", !!isError);
    };
    if (!receipt) {
      show("Paste the activation code first.", true);
      return;
    }
    if (btn) btn.disabled = true;
    try {
      const res = await rb("licence_import_receipt", { receipt });
      if (res && res.activated) {
        if (field) field.value = "";
        show("Activated on this device.", false);
        await refreshLicence();
      } else {
        // Rust returns a stable code; word each one for a person.
        const msg =
          {
            receipt_malformed:
              "That does not look like an activation code. It should start " +
              "with prx1-.",
            looks_like_token:
              "That is your Premium token (ptx1-), not an activation code. " +
              "The token goes in \u201cAdd Premium token\u201d. The " +
              "activation code is a separate prx1- code we generate for this " +
              "device from the ID above.",
            receipt_rejected:
              "This code was not accepted. Make sure it was generated for " +
              "this device's ID, shown above.",
            no_licence: "Add your Premium token first, then import the code.",
            locked: "Unlock your vault first, then try again.",
            device_id: "Could not read this device's ID. Try reopening this panel.",
            vault_io: "Could not save the activation. Try again.",
          }[res && res.code] || "This code was not accepted.";
        show(msg, true);
      }
    } catch (e) {
      show(friendly(e), true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  $("premium-release").addEventListener("click", async () => {
    // Destructive for THIS machine (Premium goes off here), so it asks.
    const yes = await askConfirm(
      i18nText("chrome-licence-release-confirm",
        "Release this device? Premium turns off on this computer and the " +
          "slot becomes free for another one. You can activate again later " +
          "if a slot is free."),
      i18nText("chrome-js-licence-release-label", "Release"),
    );
    if (!yes) return;
    $("premium-release").disabled = true;
    try {
      await rb("licence_release", {});
    } catch (e) {
      toast(friendly(e), true);
    }
    await refreshLicence();
  });

  $("premium-remove").addEventListener("click", async () => {
    const activated = $("premium-remove").dataset.activated === "1";
    const message = activated
      ? "Remove the Premium token from this computer? This erases the token " +
        "and local activation receipt, but it does not release this device " +
        "at EdgeXene. Its server slot will stay in use. Cancel and use " +
        "Release this device first if you want the slot back."
      : "Remove the Premium token from this computer? This erases the stored " +
        "token and local activation records. This device is not currently " +
        "using a server slot.";
    const yes = await askConfirm(
      message,
      activated ? "Remove without releasing" : "Remove token",
    );
    if (!yes) return;
    $("premium-remove").disabled = true;
    try {
      await rb("licence_remove", {});
    } catch (e) {
      toast(friendly(e), true);
    }
    await refreshLicence();
  });

  async function submitLicenceToken(token, confirm) {
    const args = { token };
    if (confirm) args.confirm = true;
    const res = await rb("licence_paste", args);
    const errEl = $("premium-error");
    if (res.accepted) {
      clearLicenceConfirm();
      // DRAFT copy. The expired notice promises nothing: there is no
      // fallback license (decided 2026-08-05) — a lapsed
      // subscription has no Premium features until renewal.
      if (res.was_expired) {
        errEl.textContent =
          "This subscription ended on " +
          res.ended_display +
          ". Renew to use Premium features.";
      } else if (res.state === "active") {
        // Same vocabulary as the row headline (reworded 2026-08-05), so the
        // feedback and the row it sits above agree.
        errEl.textContent =
          "Premium active. Time left: " +
          res.days_left +
          (res.days_left === 1 ? " day." : " days.");
      } else {
        errEl.textContent = "";
      }
      await refreshLicence();
      return;
    }
    if (res.needs_confirm) {
      pendingLicenceToken = token;
      $("premium-confirm-text").textContent =
        i18nText("chrome-js-licence-confirm-replace", "This token is for a different license. Replace the current one?");
      $("premium-confirm").hidden = false;
      errEl.textContent = "";
      return;
    }
    // A refusal ends any pending confirmation: the held token must not
    // outlive the exchange that created it.
    clearLicenceConfirm();
    errEl.textContent =
      LICENCE_PASTE_TEXT[res.code] || i18nText("chrome-js-licence-add-failed", "That token could not be added.");
  }

  $("premium-add").addEventListener("click", () => {
    $("premium-add").hidden = true;
    $("premium-form").hidden = false;
    $("premium-token").focus();
  });

  $("premium-buy").addEventListener("click", async () => {
    try {
      await rb("premium_purchase_open", { purchase: "patanyx" });
    } catch (err) {
      toast(friendly(err), true);
    }
  });

  // The chrome-js gate requires every form to have a submit handler.
  $("premium-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("premium-token");
    const token = input.value;
    if (!token) return;
    // A fresh submit supersedes any pending confirmation.
    clearLicenceConfirm();
    $("premium-error").textContent = "";
    try {
      await submitLicenceToken(token, false);
    } catch (err) {
      $("premium-error").textContent = friendly(err);
    } finally {
      // The token is a bearer credential: never leave it on screen after
      // an attempt, success or failure.
      input.value = "";
    }
  });

  $("premium-confirm-replace").addEventListener("click", async () => {
    if (pendingLicenceToken == null) return;
    const token = pendingLicenceToken;
    clearLicenceConfirm();
    try {
      await submitLicenceToken(token, true);
    } catch (err) {
      $("premium-error").textContent = friendly(err);
    } finally {
      $("premium-token").value = "";
    }
  });

  function clearSecrets() {
    revealed.clear();
    editingCred = null;
    editingNote = null;
    resetCredForm();
    resetNoteForm();
    $("create-pass1").value = "";
    $("create-pass2").value = "";
    $("unlock-pass").value = "";
    // THE TUNNEL PASTE BOX HOLDS A WIREGUARD PRIVATE KEY, and it is cleared
    // on success only -- a REFUSED paste deliberately stays on screen so the
    // user can see what was wrong with it rather than re-copying. That is
    // right while they are looking at it, and wrong the moment the vault
    // locks: a rejected configuration would otherwise sit in the DOM of a
    // locked browser, through an auto-lock, with its key in it. The Rust
    // half zeroizes on both outcomes (store_tunnel_config), and the panel
    // claims "same parser, same size cap, same wipe as the file path", so
    // this is the line that makes that sentence true.
    const paste = $("tunnelp-paste");
    if (paste) paste.value = "";
    renderCreds();
    renderNotes();
  }

  function onLocked() {
    // THE DECRYPTED PAGE COMES OFF THE SCREEN WITH THE VAULT. Rust clears
    // the staged slot on lock, so the token 404s and nothing can be
    // re-fetched -- but an image already loaded stays rendered, and a
    // full-page screenshot of whatever the user saved would sit there
    // through an idle auto-lock. The release notes say locking the vault
    // takes it off screen, and archive.rs's own doc says a locked browser
    // with a decrypted page on offer makes that sentence false. This is the
    // line that keeps it true on the chrome side.
    if (typeof recallPreviewClose === "function") recallPreviewClose();
    clearSecrets();
    credItems = [];
    noteItems = [];
    clearLibrarySnapshotData();
    $("library-content").hidden = true;
    $("library-locked").hidden = false;
    $("bmm-snapshots-caption").hidden = true;
    renderCreds();
    renderNotes();
    showState("locked");
    // The licence session died with the vault, so the toolbar must relock in
    // the same breath. Without this the controls would stay unlocked-looking
    // until something else happened to refresh them.
    refreshPremium();
  }

  // ---- create / unlock / lock --------------------------------------------------
  // Both export destinations use the same chooser. The suggested FILENAME
  // still comes from the backend; only the location is the user's.
  function wireSavePicker(buttonId, fieldId, title, name) {
    $(buttonId).addEventListener("click", async () => {
      try {
        const r = await rb("file_pick_save", {
          title,
          suggested_name: name,
        });
        if (!r || !r.path) return;
        $(fieldId).value = r.path;
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }
  wireSavePicker(
    "bk-exp-pick",
    "bk-exp-dest",
    i18nText("chrome-js-backup-pick-exp-title", "Save the encrypted backup"),
    "patanyx-export.rbx",
  );
  wireSavePicker(
    "bk-plain-pick",
    "bk-plain-dest",
    i18nText("chrome-js-backup-pick-plain-title", "Save the plaintext export"),
    "patanyx-export.json",
  );

  // ---- the three backup forms ---------------------------------------------
  //
  // These shipped with markup, backend commands and working destination
  // pickers, and NO submit handlers. Filling in the form and pressing the
  // button did nothing at all: no write, no error, no toast. The backend
  // has been complete and tested throughout -- `change_passphrase` even has
  // a test proving it keeps the recovery key working -- so the entire defect
  // was three missing listeners.

  $("bk-pw-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("bk-pw-error");
    const ok = $("bk-pw-ok");
    err.textContent = "";
    ok.textContent = "";
    const current = $("bk-pw-current").value;
    const next = $("bk-pw-new1").value;
    // Confirmed client-side because the backend cannot see the second field,
    // and a typo here locks the user out of their own vault.
    if (next !== $("bk-pw-new2").value) {
      err.textContent = i18nText("chrome-js-backup-pw-mismatch", "The two new passphrases do not match.");
      return;
    }
    if (!current || !next) {
      err.textContent = i18nText("chrome-js-backup-pw-required", "Both the current and the new passphrase are required.");
      return;
    }
    try {
      await rb("vault_change_passphrase", { current, new: next });
      $("bk-pw-current").value = "";
      $("bk-pw-new1").value = "";
      $("bk-pw-new2").value = "";
      ok.textContent =
        i18nText("chrome-js-backup-pw-changed", "Passphrase changed. Your recovery key still works; the old passphrase does not.");
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  $("bk-export-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("bk-exp-error");
    const ok = $("bk-exp-ok");
    err.textContent = "";
    ok.textContent = "";
    const dest = $("bk-exp-dest").value;
    const passphrase = $("bk-exp-pass1").value;
    if (passphrase !== $("bk-exp-pass2").value) {
      err.textContent = i18nText("chrome-js-backup-exp-mismatch", "The two export passphrases do not match.");
      return;
    }
    if (!dest || !passphrase) {
      err.textContent = i18nText("chrome-js-backup-exp-required", "Choose a destination and set an export passphrase.");
      return;
    }
    try {
      await rb("vault_export_encrypted", { dest, passphrase });
      $("bk-exp-pass1").value = "";
      $("bk-exp-pass2").value = "";
      // Named plainly because it is a separate secret from the vault
      // passphrase and there is no recovery key for an export.
      ok.textContent =
        i18nText("chrome-js-backup-exp-written", "Encrypted export written. Only its passphrase can open it; there is no recovery key.");
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  $("bk-plain-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("bk-plain-error");
    const ok = $("bk-plain-ok");
    err.textContent = "";
    ok.textContent = "";
    const dest = $("bk-plain-dest").value;
    const confirmation = $("bk-plain-confirm").value;
    if (!dest) {
      err.textContent = i18nText("chrome-js-backup-plain-dest", "Choose a destination.");
      return;
    }
    // The backend enforces this too, and must -- this check only turns a
    // round trip into an immediate answer.
    if (!confirmation) {
      err.textContent = i18nText("chrome-js-error-export-not-confirmed", "Type the confirmation sentence exactly to continue.");
      return;
    }
    try {
      await rb("vault_export_plaintext", { dest, confirmation });
      $("bk-plain-confirm").value = "";
      ok.textContent =
        i18nText("chrome-js-backup-plain-written", "Plaintext export written. It is unencrypted; anyone with the file can read every credential.");
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  // ---- bringing a vault across --------------------------------------------
  //
  // Inside the Flatpak the chooser is not a convenience, it is the only way
  // to name a file: the sandbox has no filesystem access, so a typed path to
  // a native install's vault names something unreachable. Where the platform
  // has no chooser (Windows, which is not sandboxed) the typed field is the
  // way in and works, so BOTH are offered and whichever is usable is shown.
  let importFileChoice = null;
  // Every wired form's mode setter. The capability probe is async and may land
  // before or after the forms are wired, so it calls all of them rather than
  // one named function.
  const importModeAppliers = [];
  function applyImportMode() {
    for (const apply of importModeAppliers) apply();
  }
  (async () => {
    try {
      // Cheap capability probe; failure just leaves the typed field.
      const st = await rb("vault_backup_status").catch(() => null);
      importFileChoice = st && st.file_choice;
    } catch (e) {
      importFileChoice = null;
    }
    applyImportMode();
  })();

  // ONE implementation, wired to TWO forms: the one on the no-vault screen
  // and the one in the Backup pane for a machine that already has a vault.
  // Copying the handler and renaming the ids is how the two drift -- a fix
  // applied to one, a validation rule tightened in the other -- so the id
  // prefix is the only thing that varies.
  function wireImportForm(prefix) {
    const id = (suffix) => prefix + suffix;
    const form = $(id("form"));
    // A missing form is not an error, it is just not on this page.
    if (!form) return;

    function applyMode() {
      const pick = $(id("pick"));
      const typed = $(id("src"));
      if (!pick || !typed) return;
      if (importFileChoice) {
        pick.hidden = false;
        // Still shown, read-only, so the user can SEE what was chosen. A
        // portal path is not something anyone would type, and hiding it
        // entirely would leave the form looking like nothing happened.
        typed.readOnly = true;
        typed.placeholder = i18nText("chrome-js-import-no-file-placeholder", "No file chosen yet");
      } else {
        pick.hidden = true;
        typed.readOnly = false;
        typed.placeholder = i18nText("chrome-js-import-path-placeholder", "Backup file path");
      }
    }
    importModeAppliers.push(applyMode);

    $(id("pick")).addEventListener("click", async () => {
      const err = $(id("error"));
      err.textContent = "";
      try {
        const r = await rb("file_pick_open", {
          title: i18nText("chrome-js-import-pick-title", "Choose a PATANYX backup file"),
        });
        // Cancel is an answer, not a failure: leave everything as it was.
        if (!r || !r.path) return;
        $(id("src")).value = r.path;
        i18nSet(
          $(id("chosen")),
          "chrome-js-import-chosen",
          { path: r.path },
          "Chosen: " + r.path,
        );
      } catch (e) {
        err.textContent = friendly(e);
      }
    });

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const err = $(id("error"));
      err.textContent = "";
      delete err.dataset.reason;
      const src = $(id("src")).value.trim();
      const exportPass = $(id("export-pass")).value;
      const p1 = $(id("pass1")).value;
      const p2 = $(id("pass2")).value;
      // EVERY check below happens before the IPC call, because import
      // replaces the vault on this machine and cannot be undone. A typo in
      // the confirmation field must cost a re-type, not a vault.
      if (!src) {
        err.textContent = importFileChoice
          ? i18nText("chrome-js-import-no-src-pick", "Choose the backup file first.")
          : i18nText("chrome-js-import-no-src-typed", "Enter the path to the backup file.");
        return;
      }
      if (!exportPass) {
        err.textContent = i18nText("chrome-js-import-no-export-pass", "Enter the passphrase that protects the backup file.");
        return;
      }
      if (p1.length < 8) {
        err.textContent = i18nText("chrome-js-import-pass-short", "New passphrase must be at least 8 characters.");
        err.dataset.reason = "short";
        return;
      }
      if (p1 !== p2) {
        err.textContent = i18nText("chrome-js-import-pass-mismatch", "New passphrases do not match.");
        err.dataset.reason = "mismatch";
        return;
      }
      try {
        const imported = await rb("vault_import", {
          src,
          passphrase: exportPass,
          new_passphrase: p1,
        });
        for (const suffix of ["src", "export-pass", "pass1", "pass2"]) {
          $(id(suffix)).value = "";
        }
        $(id("chosen")).textContent = "";
        if (imported && imported.library !== "replaced") {
          err.textContent = imported.library === "not_replaced"
            ? i18nText("chrome-js-import-library-not-replaced", "The vault was imported, but the previous profile's Library could not be replaced. Bookmarks, Tab Shelf, and download records are unavailable. Write down the new recovery key below before continuing.")
            : i18nText("chrome-js-import-library-not-opened", "The vault was imported and the previous Library was replaced, but the new Library could not be opened. Bookmarks, Tab Shelf, and download records are unavailable. Write down the new recovery key below before continuing.");
        }
        // Import mints a FRESH recovery key, exactly like creation, and it is
        // returned once. The user must see it before anything else happens.
        if (imported && imported.recovery_key) {
          showRecoveryKey(imported.recovery_key);
        } else {
          showState("open");
        }
        await reloadLists();
      } catch (e) {
        err.textContent = friendly(e);
      }
    });
  }

  wireImportForm("import-");
  wireImportForm("bk-import-");
  applyImportMode();

  $("create-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("create-error");
    err.textContent = "";
    const p1 = $("create-pass1").value;
    const p2 = $("create-pass2").value;
    if (p1.length < 8) {
      err.textContent = i18nText("chrome-js-create-pass-short", "Passphrase must be at least 8 characters.");
      return;
    }
    if (p1 !== p2) {
      err.textContent = i18nText("chrome-js-create-pass-mismatch", "Passphrases do not match.");
      return;
    }
    try {
      const created = await rb("vault_create", { passphrase: p1 });
      $("create-pass1").value = "";
      $("create-pass2").value = "";
      // The key is returned exactly once and is not recoverable afterwards, so
      // the user has to see it before anything else happens.
      if (created && created.recovery_key) {
        showRecoveryKey(created.recovery_key);
      } else {
        showState("open");
      }
      await reloadLists();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  $("unlock-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("unlock-error");
    err.textContent = "";
    const pass = $("unlock-pass").value;
    try {
      const opened = await rb("vault_unlock", { passphrase: pass });
      $("unlock-pass").value = "";
      // Unlocking an older vault migrates it and mints a recovery key the user
      // has never seen. Showing it here is the only chance they get.
      if (opened && opened.recovery_key) {
        showRecoveryKey(opened.recovery_key);
        await reloadLists();
        return;
      }
      showState("open");
      await reloadLists();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  $("recovery-create-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("recovery-create-error");
    err.textContent = "";
    const pass = $("recovery-create-pass").value;
    if (!pass) {
      err.textContent = i18nText("chrome-js-recovery-create-confirm-prompt", "Enter your vault passphrase to confirm.");
      return;
    }
    try {
      const made = await rb("vault_recovery_create", { passphrase: pass });
      // Cleared before anything else: the passphrase has done its job and has
      // no reason to sit in the DOM while the key is on screen being copied.
      $("recovery-create-pass").value = "";
      if (made && made.recovery_key) {
        // Same screen the create flow uses, so there is one place that knows
        // how to present a key and one set of instructions for writing it
        // down. It is shown once here too -- nothing stores it.
        showRecoveryKey(made.recovery_key);
      }
      await refreshBackupStatus();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });

  $("btn-lock").addEventListener("click", async () => {
    try {
      await rb("vault_lock");
    } catch (e) {
      /* lock locally regardless */
    }
    onLocked();
  });

  // ---- tabs --------------------------------------------------------------------
  $("tab-creds").addEventListener("click", () => selectTab("creds"));
  $("tab-notes").addEventListener("click", () => selectTab("notes"));
  $("tab-sync").addEventListener("click", () => selectTab("sync"));

  $("vault-sync-framing").textContent =
    "PATANYX Vault keeps your passwords on this device. To use them on your " +
    "phone or another computer too, NordPass syncs across devices.";

  function selectTab(which) {
    // Backup was shipped in index.html with a tab button and a pane, and this
    // function never knew about it — so the whole encrypted-export,
    // change-passphrase and plaintext-export surface was unreachable.
    for (const name of ["creds", "notes", "backup", "sync"]) {
      $("tab-" + name).classList.toggle("active", which === name);
      $("pane-" + name).hidden = which !== name;
    }
    if (which === "backup") refreshBackupStatus();
    // The Premium row sits ABOVE the panes, so it survives a tab switch --
    // and so did the result of the last token paste, which meant a refusal
    // like "This build cannot verify Premium tokens yet" followed the user
    // from Credentials to Notes, Backup or Sync as if it were about the pane
    // they had just opened. A message about an action belongs to that action:
    // moving away ends it.
    const premiumError = $("premium-error");
    if (premiumError) premiumError.textContent = "";
  }

  // ---- lists -------------------------------------------------------------------
  async function reloadLists() {
    try {
      const [creds, notes] = await Promise.all([
        rb("cred_list"),
        rb("note_list"),
      ]);
      credItems = creds.items || [];
      noteItems = notes.items || [];
      renderCreds();
      renderNotes();
    } catch (e) {
      /* vault may have been locked in the meantime */
    }
  }

  function renderCreds() {
    credListEl.textContent = "";
    for (const item of credItems) {
      const li = el("li", "item");
      const head = el("div", "item-head");
      head.appendChild(el("span", "item-title", item.site));
      head.appendChild(el("span", "item-sub", item.username));
      li.appendChild(head);

      // WHICH CREDENTIALS ACTUALLY FILL, SAID OUT LOUD.
      //
      // `site` is a free-text label and the origin is parsed out of it, so
      // "Google" saves fine and then never fills anywhere. Before this line
      // the two were indistinguishable in the list: same title, same
      // username, same Reveal button, and the only symptom was a fill offer
      // that never came. Every credential saved before the origin field
      // existed is in the second state.
      //
      // Deliberately not phrased as an error. Nothing is broken about a
      // vault entry kept purely to copy and paste from, and plenty of them
      // are exactly that -- it just must not look like one that fills.
      if (item.origin) {
        // `fills_on` is the REGISTRABLE DOMAIN, and it is what the offer
        // actually matches on -- so a credential saved on
        // accounts.google.com is offered across google.com. Saying only
        // "Fills on accounts.google.com" would understate its reach, which is
        // the one direction this label must never be wrong in.
        //
        // Null when the stored origin has no registrable domain of its own
        // (a bare public suffix); then it really does fill on itself alone.
        {
          const scope = el("div", "cred-origin", "");
          if (item.fills_on) {
            i18nSet(scope, "chrome-cred-fills-subdomains", { domain: item.fills_on },
              "Fills on " + item.fills_on + " and its subdomains");
          } else {
            i18nSet(scope, "chrome-cred-fills-only", { origin: item.origin },
              "Fills on " + item.origin + " only");
          }
          li.appendChild(scope);
        }
      } else {
        li.appendChild(
          el(
            "div",
            "cred-origin none",
            i18nText("chrome-js-creds-copy-only", "Copy only: no site to match. Edit it on the site's page to fix."),
          ),
        );
      }

      const row = el("div", "item-row");
      const pw = el("input", "pw");
      pw.readOnly = true;
      pw.type = "text";
      pw.value = revealed.has(item.id) ? revealed.get(item.id) : "";
      pw.placeholder = "••••••••";
      row.appendChild(pw);

      const revealBtn = el(
        "button",
        "small",
        revealed.has(item.id) ? i18nText("chrome-js-creds-hide", "Hide") : i18nText("chrome-js-creds-reveal", "Reveal"),
      );
      revealBtn.type = "button";
      revealBtn.addEventListener("click", async () => {
        try {
          if (revealed.has(item.id)) {
            revealed.delete(item.id);
          } else {
            const entry = await rb("cred_get", { id: item.id });
            revealed.set(item.id, entry.password || "");
          }
          renderCreds();
        } catch (e) {
          /* locked or deleted */
        }
      });
      row.appendChild(revealBtn);

      const editBtn = el("button", "small", i18nText("chrome-js-creds-edit", "Edit"));
      editBtn.type = "button";
      editBtn.addEventListener("click", async () => {
        try {
          const entry = await rb("cred_get", { id: item.id });
          editingCred = item.id;
          $("cred-site").value = entry.site || "";
          $("cred-username").value = entry.username || "";
          $("cred-password").value = entry.password || "";
          $("cred-note").value = entry.note || "";
          $("cred-submit").textContent = i18nText("chrome-js-creds-save-changes", "Save changes");
          $("cred-cancel").hidden = false;
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(editBtn);

      const delBtn = el("button", "small danger", i18nText("chrome-js-confirm-default-label", "Delete"));
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        const ok = await askConfirm(
          await i18nResolve(
            "chrome-js-creds-delete-confirm",
            { site: item.site },
            "Delete credential for " + item.site + "?",
          ),
        );
        if (!ok) return;
        try {
          await rb("cred_delete", { id: item.id });
          revealed.delete(item.id);
          if (editingCred === item.id) resetCredForm();
          await reloadLists();
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(delBtn);

      li.appendChild(row);
      credListEl.appendChild(li);
    }
  }

  function renderNotes() {
    noteListEl.textContent = "";
    for (const item of noteItems) {
      const li = el("li", "item");
      const head = el("div", "item-head");
      head.appendChild(el("span", "item-title", item.title));
      li.appendChild(head);

      const row = el("div", "item-row");
      const editBtn = el("button", "small", i18nText("chrome-js-creds-edit", "Edit"));
      editBtn.type = "button";
      editBtn.addEventListener("click", async () => {
        try {
          const note = await rb("note_get", { id: item.id });
          editingNote = item.id;
          $("note-title").value = note.title || "";
          $("note-body").value = note.body || "";
          $("note-submit").textContent = i18nText("chrome-js-creds-save-changes", "Save changes");
          $("note-cancel").hidden = false;
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(editBtn);

      const delBtn = el("button", "small danger", i18nText("chrome-js-confirm-default-label", "Delete"));
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        if (!(await askConfirm('Delete note "' + item.title + '"?'))) return;
        try {
          await rb("note_delete", { id: item.id });
          if (editingNote === item.id) resetNoteForm();
          await reloadLists();
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(delBtn);

      li.appendChild(row);
      noteListEl.appendChild(li);
    }
  }

  // ---- entry forms ---------------------------------------------------------------
  $("cred-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("cred-error");
    err.textContent = "";
    const site = $("cred-site").value.trim();
    const username = $("cred-username").value;
    const password = $("cred-password").value;
    const note = $("cred-note").value;
    if (!site || !username) {
      err.textContent = i18nText("chrome-js-credform-required", "Site and username are required.");
      return;
    }
    try {
      if (editingCred) {
        await rb("cred_update", {
          id: editingCred,
          site,
          username,
          password,
          note,
        });
      } else {
        await rb("cred_add", { site, username, password, note });
      }
      resetCredForm();
      await reloadLists();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });
  $("cred-cancel").addEventListener("click", resetCredForm);

  // Fills the Site field from the tab underneath the panel, using the SAME
  // `origin` the fill lookup matches on -- so a credential saved this way
  // cannot fail to match through a typo, a scheme, a port, a trailing path,
  // or a friendly label that parses to nothing.
  //
  // Rust re-parses whatever lands here anyway (`parse_credential_origin`);
  // this does not bypass that, it just stops the user having to guess what
  // that parser wants.
  $("cred-use-site").addEventListener("click", () => {
    const origin = lastTabStatus && lastTabStatus.origin;
    if (!origin) return;
    $("cred-site").value = origin;
    $("cred-site").focus();
  });

  // Shown only when there is a host to take. Called from the vault panel's
  // own refresh and from applyTabStatus, so opening the panel on one site and
  // then navigating does not leave it offering the previous page's host.
  function syncUseSiteButton() {
    const btn = $("cred-use-site");
    if (!btn) return;
    const origin = lastTabStatus && lastTabStatus.origin;
    btn.hidden = !origin;
    if (origin) {
      btn.title = "Use " + origin + ", the site in this tab";
      if (currentUiLocale !== "en") {
        i18nResolve(
          "chrome-js-creds-use-site-title",
          { origin },
          "Use " + origin + ", the site in this tab",
        ).then((t) => {
          btn.title = t;
        });
      }
    }
  }

  function resetCredForm() {
    editingCred = null;
    $("cred-site").value = "";
    $("cred-username").value = "";
    $("cred-password").value = "";
    $("cred-note").value = "";
    $("cred-submit").textContent = i18nText("chrome-js-credform-add", "Add credential");
    $("cred-cancel").hidden = true;
    $("cred-error").textContent = "";
  }

  $("note-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("note-error");
    err.textContent = "";
    const title = $("note-title").value.trim();
    const body = $("note-body").value;
    if (!title) {
      err.textContent = i18nText("chrome-js-noteform-required", "Title is required.");
      return;
    }
    try {
      if (editingNote) {
        await rb("note_update", { id: editingNote, title, body });
      } else {
        await rb("note_add", { title, body });
      }
      resetNoteForm();
      await reloadLists();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });
  $("note-cancel").addEventListener("click", resetNoteForm);

  function resetNoteForm() {
    editingNote = null;
    $("note-title").value = "";
    $("note-body").value = "";
    $("note-submit").textContent = i18nText("chrome-js-noteform-add", "Add note");
    $("note-cancel").hidden = true;
    $("note-error").textContent = "";
  }

  // Smoke-test heartbeat; the reply also backfills the URL bar in case the
  // first url_changed event fired before this script was loaded.
  // Prime the toolbar indicators so the shield badge and the padlock are
  // correct before the user opens anything.
  refreshPrivacy();
  rb("vault_status")
    .then((st) => setVaultIndicator(st && st.unlocked ? "open" : "locked"))
    .catch(() => {});

  rb("ping")
    .then((data) => {
      if (data && data.url && data.url !== "about:blank" && !urlInput.value) {
        urlInput.value = data.url;
      }
    })
    .catch(() => {});

  // The first tabs_changed may also fire before this script loaded, so the
  // initial strip is fetched explicitly.
  rb("tab_list")
    .then((data) => acceptTabItems(data && data.items))
    .catch(() => {});

  // First-run tour. Runs after everything above has registered -- this is an
  // async callback, so by the time it fires every registerPanel call in this
  // script (including "onboarding" and "about", wherever they sit in the
  // file) has already executed. A fetch failure opens nothing rather than
  // guessing; a tour that appears on every launch because of a transient IPC
  // hiccup would be worse than one that occasionally does not appear on a
  // genuinely fresh install.
  rb("onboarding_seen_get")
    .then((data) => {
      if (data && data.seen === false) {
        togglePanelNamed("onboarding");
        // The tour wins a first run outright. Only ONE panel is ever open, so
        // asking for the vault here would either clobber the tour or be
        // clobbered by it; and being asked for a passphrase before being told
        // what a vault is in this browser is the wrong order to meet it in.
        return null;
      }
      // THE VAULT OPENS ITSELF at launch on every later run. Bookmarks, saved
      // passwords and download records all unlock with it, so a locked vault
      // is the state in which most of the browser quietly does nothing -- the
      // Library panel's own empty text is "they unlock together with your
      // vault", which is a thing a person had to go and discover.
      //
      // BUT ONLY WHEN PATANYX WAS OPENED ON ITS OWN. If another application
      // handed it a link because it is the default browser, the person wants
      // to read that page; putting a passphrase prompt over it would
      // interrupt the thing they actually asked for. `startup_info` reports
      // which of the two happened.
      //
      // Deliberately does NOT focus the passphrase field (refreshVault never
      // calls focus, and nothing here adds it): the address bar keeps the
      // keyboard, so someone who launched the browser to go somewhere can
      // just type, and someone who launched it to unlock can click once. A
      // dialog that silently swallows the first thing you type is worse than
      // one you have to click.
      return rb("startup_info").then((startup) => {
        if (startup && startup.opened_with_url === true) return null;
        return rb("vault_status").then((status) => {
          // Unlocked cannot happen at launch, but it is checked rather than
          // assumed. `openPanelName` guards the case where something else got
          // there first, so this can never close a panel a user opened.
          if (status && !status.unlocked && !openPanelName) {
            togglePanelNamed("vault");
          }
        });
      });
    })
    // One catch for both steps: a failed read opens nothing rather than
    // guessing, the same rule the tour above already follows.
    .catch(() => {});

  // ---- from the privsurface draft ----
  // The chrome strip height is owned here, in one place: the open panel's
  // budget (or the closed height) plus the measured height of every visible
  // banner. Banners live inside the chrome webview, so without this they
  // would be clipped by the fixed strip height.
  // Every banner that can appear under the toolbar. They live inside the
  // chrome webview, so the Rust side has to be told how tall the strip needs
  // to be or they are simply clipped. This began as a single hardcoded
  // reference to the only banner that existed then -- the TLS interception
  // warning, since removed -- and the second banner added rendered
  // half-visible with no error anywhere.
  // EVERY banner in index.html, and the list is gated because it was wrong.
  //
  // `lock-warning` was missing. A banner that is not measured here does not
  // grow the strip, and the chrome webview is a child window clipped to its
  // bounds -- so the banner rendered OUTSIDE the visible strip and simply was
  // not there. The vault's own "about to lock" warning, the one with a
  // deadline and an action, was invisible for exactly as long as it mattered.
  //
  // It was visible while a modal was open, which is what made it look like a
  // modal bug: in Overlay mode the chrome covers the whole window, so anything
  // below the toolbar suddenly has room. Close the modal, back to a strip, and
  // the warning vanished again.
  const BANNERS = [
    "blocked-warning",
    "update-banner",
    "resolver-warning",
    "save-password-banner",
    "lock-warning",
    // The fail-closed tunnel banner. A banner absent from this list renders
    // OUTSIDE the clipped strip and is invisible -- the lock-warning defect.
    "tunnel-warning",
    // The plain-HTTP warning: same band, same clipping rule.
    "insecure-warning",
    // The ad-list hold. Same band, same rule: a banner missing from this list
    // renders outside the clipped strip and is invisible, which is the
    // lock-warning defect and is not discoverable by reading the markup.
    "adlist-warning",
    // The engine-below-floor warning, raised at boot: same band, same rule.
    "engine-floor-warning",
    // The find bar. NOT a banner by role (role="search"), which is exactly how
    // it escaped the toolbar gate's role=alert|status sweep and this list.
    // With the toolbar across the top the closed strip is measured against a
    // 148px floor, and the ~40px of slack under the two rows happened to be
    // enough for the bar -- so Ctrl+F looked fine on every top-toolbar test.
    // With the toolbar down either side the strip is only the tab/address rows and
    // is measured tightly (floor 88), the slack is gone, and the bar rendered
    // under the page: Ctrl+F "did nothing". Its own comment in index.html
    // says it "goes through the same height sync the banners use"; now it
    // does.
    "findbar",
  ];

  function syncChromeInsets() {
    const extra = bannerExtraPx();
    // THE FLOOR IS APPLIED AFTER THE EXTRA, NOT BEFORE IT.
    //
    // This used to read `closedChromePx() + extra`, which floors the two rows
    // at 148 and THEN adds the banner. On a real Windows build the rows
    // measure ~136, so the floor wins by 12px and that slack got counted
    // twice: a 48px banner ending at 184 reported a strip of 196. Opaque
    // chrome hid the overshoot. It stops being hidden the moment anything lays
    // the page out against this number, because then 12 logical pixels between
    // the banner's last row and the page's first belong to nobody -- the same
    // twelve the stylesheet's "THE 12px NOBODY PAINTS" comment is about,
    // reached by a different route.
    //
    // Measuring first and flooring once gives max(148, 136 + 48) = 184, which
    // is where the banner actually ends. With no panel open `top` IS the
    // strip, from the same call, so the two cannot disagree.
    const strip = closedChromePx(extra);
    const left = closedChromeLeftPx();
    const right = closedChromeRightPx();
    // CEILED, because `top` crosses the IPC and ipc.rs reads it with
    // `Value::as_i64`, which returns None for a fractional number and answers
    // bad_args. `strip` already comes back whole from `closedChromePx`; this
    // branch adds a raw `extra` to a panel height and did not. Unrounded
    // banner heights are correct for the MEASUREMENT -- that is what stopped
    // the double-rounding overshoot -- but the wire wants an integer, and a
    // silently rejected inset leaves native geometry disagreeing with the CSS
    // that was published from the same number.
    const top = openPanelName
      ? Math.ceil(panels.get(openPanelName).heightPx + extra)
      : strip;
    // The stylesheet needs this number too, and the SAME one: a panel is
    // placed below the chrome, and `--chrome-closed-px` is the BARE closed
    // strip with no banner in it. With a banner showing, a panel positioned
    // from the bare value starts 52px inside the banner's band. That was
    // invisible only because banners sat under the modal scrim; it is the
    // defect the `.panel-modal` comment already describes, arriving by a
    // banner instead of by a constant.
    // Republished through the one function that owns these variables, so
    // there is no second place to keep in sync.
    publishChromeMetric();
    rb("set_chrome_insets", {
      top,
      // The CLOSED strip, sent every time and never inferred.
      //
      // `top` is the panel's height while a panel is open, and the backend
      // used to work out which kind of height it had been given from the
      // arrangement it had been told about separately. Those two commands are
      // not ordered: `togglePanelNamed` sets `openPanelName` and runs the
      // panel's onOpen (which can call this) BEFORE `syncChromeCoverage`
      // sends the arrangement, so a panel height could arrive first and be
      // recorded as the strip. On the GTK backend that put the page 272px
      // down the window for as long as the modal was open. Stating the
      // measurement removes the guess.
      strip,
      left,
      right,
    }).catch(() => {});
    // The exact number Rust was given, for the stylesheet.
    //
    // A modal card is capped against the viewport with `100vh`, and that is
    // only the same thing as the chrome's own space where the chrome is
    // RAISED above the page. Where it is not -- GTK always, Windows without
    // the translucent lift -- the page covers everything below `top`, so a
    // card sized against the viewport extends underneath it and its lower
    // half is simply not there, with no scrollbar to reach it. The
    // stylesheet cannot measure this; it can only be told.
    document.documentElement.style.setProperty(
      "--chrome-height-px",
      top + "px",
    );
  }

  // RE-MEASURE WHEN THE MEASUREMENT CAN CHANGE. `closedChromePx` reads laid-out
  // text, and two things move it after boot: a font finishing load (the first
  // paint can use a fallback with different metrics), and the window moving to
  // a monitor with different DPI scaling, which changes how many CSS pixels a
  // row of Segoe UI occupies. Both would otherwise leave Rust holding a height
  // that was right once.
  //
  // Cheap and idempotent: syncChromeInsets sends one small IPC message and
  // does nothing else, and Rust clamps whatever arrives.
  window.addEventListener("resize", syncChromeInsets);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(syncChromeInsets).catch(() => {});
  }

  // ---- from the privsurface draft ----
  // ---- per-tab privacy: freeze, allow-site, ledger, TLS, profile --------------

  // Single writer for every per-tab indicator, fed by the tab_status event,
  // the tab_status reply, and the boot/slow polls. Both freeze controls
  // (toolbar chip and panel button) are driven from here so they can never
  // disagree.
  function applyTabStatus(st) {
    retireBlockedOnNavigation(st);
    if (!st) return;
    lastTabStatus = st;
    // The engine-confirmed rows belong HERE, not in applyPrivacyStatus: every
    // one of them is a property of THIS tab, and this is the payload that
    // carries them. Called first so the section is populated even if something
    // below throws on an unexpected field.
    renderEngineConfirmed(st);
    // The fail-closed banner's input: the measured tunnel state rides this
    // same payload (there is deliberately no separate event channel for it).
    noteTunnelMeasured(st.tunnel);
    // Same payload, second reader: this is where a refusal becomes visible on
    // the toolbar instead of only inside a panel nobody has opened. Switching
    // tabs re-runs it, because "REFUSED" is per tab and the shield describes
    // the tab in front of you.
    refreshShield();
    // Third reader of the same payload, and the reason the fill button can be
    // on the toolbar at all: it has to know whether THIS site has a saved
    // password before the user thinks to ask. Cheap on repeat -- the lookup is
    // keyed and skipped when nothing that could change the answer has changed.
    refreshAutofillOffer();
    // Same payload again: the Vault's "Use this site" button names the host in
    // the tab, so it has to follow the tab rather than whatever was showing
    // when the panel was opened.
    syncUseSiteButton();
    // Site permissions follow the TAB, for the same reason the button above
    // does. Leaving the panel open across a tab switch would otherwise show
    // the previous site's requests and, worse, let the user toggle them while
    // believing they were acting on the site now in front of them.
    if (openPanelName === "privacy") refreshPermissions();
    const phase = st.freeze_phase || "loaded";
    const requested = phase === "frozen";
    const enforceable = st.freeze_enforced !== false;
    // What the user ASKED for is `freeze_phase`. Whether the engine actually
    // did it is `freeze_enforcement`, and only that entitles us to say the
    // tab is making no requests. On WebKitGTK the blocking filter compiles
    // ASYNCHRONOUSLY and can fail; this used to report "Frozen" the instant
    // the click landed, with nothing installed and requests still going out.
    const enforcement = st.freeze_enforcement || "inactive";
    const reallyFrozen = requested && enforcement === "active";
    const freezePending = requested && enforcement === "pending";
    const freezeFailed = requested && enforcement === "failed";

    // Toolbar freeze chip: the label is the TRUE state, always visible.
    const btn = $("btn-freeze");
    $("freeze-label").textContent =
      phase === "loading"
        ? i18nText("chrome-js-freeze-label-loading", "Loading\u2026")
        : freezeFailed
          ? i18nText("chrome-js-freeze-label-failed", "Not frozen")
          : freezePending
            ? i18nText("chrome-js-freeze-label-pending", "Freezing\u2026")
            : reallyFrozen
              ? i18nText("chrome-js-freeze-label-frozen", "Frozen")
              : i18nText("chrome-js-freeze-label-live", "Live");
    // aria-pressed tracks the REQUEST, because that is what the button
    // toggles: a failed freeze must still offer "unfreeze" to clear it.
    btn.setAttribute("aria-pressed", requested ? "true" : "false");
    btn.classList.toggle("is-active", reallyFrozen);
    btn.classList.toggle("is-warning", freezeFailed);
    // A control the platform cannot honour is shown, disabled, and
    // explained — never a switch that does nothing.
    btn.disabled = !enforceable;
    btn.title = !enforceable
      ? i18nText("chrome-js-freeze-title-unavailable", "Freezing is not available on this platform")
      : freezeFailed
        ? i18nText("chrome-js-freeze-title-failed", "Freeze FAILED; this tab can still send requests")
        : freezePending
          ? i18nText("chrome-js-freeze-title-pending", "Freezing this tab; requests may continue")
          : reallyFrozen
            ? i18nText("chrome-js-freeze-title-frozen", "Frozen: no network requests. Click to unfreeze.")
            : i18nText("chrome-js-freeze-title-live", "Freeze this tab: stop it from making network requests");

    // Panel mirror of the same state.
    $("tab-freeze-desc").textContent =
      phase === "loading"
        ? i18nText("chrome-js-freeze-desc-loading", "Loading. Requests are allowed until loading finishes.")
        : freezeFailed
          ? i18nText("chrome-js-freeze-desc-failed", "Freeze failed. This tab can still send requests; close it if that matters.")
          : freezePending
            ? i18nText("chrome-js-freeze-desc-pending", "Freezing. Requests may continue.")
            : reallyFrozen
              ? i18nText("chrome-js-freeze-desc-frozen", "Frozen. No network requests.")
              : i18nText("chrome-js-freeze-desc-live", "Live. Network requests can continue.");
    const panelFreeze = $("btn-tabfreeze");
    panelFreeze.textContent = requested
      ? i18nText("chrome-js-freeze-unfreeze-button", "Unfreeze this tab")
      : i18nText("chrome-js-freeze-freeze-button", "Freeze this tab");
    panelFreeze.disabled = !enforceable;

    // The Tab button lights up when the active tab has any non-default
    // posture (frozen, or keeping nothing on disk), so it is glanceable
    // with the panel closed.
    $("btn-tab").classList.toggle(
      "is-active",
      reallyFrozen || st.profile === "ephemeral",
    );
    // THE ambient interception signal. It began as a backstop -- something
    // that survived dismissing the full-width banner -- and removing that
    // banner promotes it to the only trace outside the panel. What made it
    // the right backstop makes it the right primary: it is deliberately not
    // `is-active`, which means "this tab is doing something the user chose",
    // and interception is something done TO the tab; and it tracks the
    // connection rather than any acknowledgement, so it lasts exactly as long
    // as the condition does.
    //
    // The banner was removed because it asserted decryption in prose, across
    // the whole window, without showing the certificate it reasoned from. Every
    // `classify_issuer` collision was therefore the browser stating something
    // untrue about the user's connection, and no lexical rule removes them all
    // -- "Norton Rose Fulbright SSL Issuing CA" matches the `norton` hint, and
    // narrowing the hints far enough to miss it also switched the verdict off
    // for the antivirus roots it exists to catch. In the panel the summary
    // verdict `#tab-safety-desc` sits directly above `#tab-issuer-desc`, an
    // order interception-ui-gate.js holds, so the claim and its evidence are
    // read together and a wrong one is visibly wrong instead of authoritative.
    // (Ids, not line numbers. The first draft of this comment cited lines and
    // was already wrong when it was written, because adding the comment moved
    // them.) Sensitivity is unchanged; only the loud surface went.
    //
    // The longer sentence under "Connection" is two sections further down and
    // does NOT have the issuer beside it, so it carries the qualifier the
    // banner used to carry -- common on work networks and with some antivirus
    // software. That sentence left the product with the banner and had to come
    // back: it is what lets the reader who cannot interpret a CA name shrug at
    // a false positive, which is exactly the reader this design is for.
    const intercepted = st.tls === "intercepted";
    tabButtonIntercepted = intercepted;
    $("btn-tab").classList.toggle("is-intercepted", intercepted);
    // AND IN THE ACCESSIBLE NAME, not only in the colour. A border and a glyph
    // tint are nothing at all to a screen reader and little to a red/green
    // deficit, so for those users the mark carries no information -- and with
    // the banner gone there is nothing else in the chrome to fall back on. The
    // label carries the condition while it lasts and goes back to the plain
    // one when it ends.
    applyTabButtonLabel();

    // TLS, stated once, in the panel. Unknown is common (unrecognized issuer
    // names) and stays a calm line rather than a verdict: crying wolf there
    // would teach the user to ignore the one that means something.
    //
    // "unreadable" is NOT "unknown" and the two must never share a string.
    // Unknown says the browser looked at the issuer and did not recognize it
    // -- a fact about the certificate. Unreadable says the platform exposes no
    // chain to look at (WebView2 on Windows, every page, always), so the
    // sentence has to be about the browser instead. They were one branch,
    // which told every Windows user their ordinary public certificate had an
    // issuer this browser did not recognize.
    $("tab-tls-desc").textContent =
      st.tls === "normal"
        ? i18nText("chrome-js-tls-normal", "Encrypted. The certificate issuer is a recognized public authority.")
        : intercepted
          ? i18nText("chrome-js-tls-intercepted", "This connection is being intercepted. Something between you and this site can read and change what you send and receive. This is common on work networks and with some antivirus software.")
          : st.tls === "not_tls"
            ? i18nText("chrome-js-tls-not-tls", "This connection is not encrypted.")
            : st.tls === "unknown" // wire token, not display text
              ? i18nText("chrome-js-tls-unknown", "This browser does not recognize the certificate issuer. That alone may not be a problem; the issuer is unconfirmed.")
              : // "unreadable", and the default for anything unrecognized:
                // the only claim that stays true when the browser does not
                // know what it is looking at.
                i18nText("chrome-js-tls-unreadable", "Certificate details are unavailable on this platform, so the issuer is unconfirmed. This does not indicate a site problem.");

    // Info-tab safety summary: is this page safe, in one line, plus the issuer.
    if ($("tab-safety-desc")) {
      $("tab-safety-desc").textContent = st.page_insecure
        ? i18nText("chrome-js-safety-insecure", "This page is not encrypted. Anything you send it can be read on the way.")
        : intercepted
          ? i18nText("chrome-js-safety-intercepted", "This connection is being intercepted, so it is not private.")
          : st.tls === "normal"
            ? i18nText("chrome-js-safety-secure", "This page is served over an encrypted, verified connection.")
            : st.tls === "unreadable" // wire token, not display text
              ? i18nText("chrome-js-safety-unreadable", "Encrypted. This browser cannot read certificate details on this platform, so it cannot confirm who issued it. That does not indicate a problem with this site.")
              // "unconfirmed" is for a chain the browser READ and could not
              // verify. It must never answer for a platform that exposes no
              // chain at all: on WebView2 `st.tls` is always "unreadable", so
              // without the arm above every correctly-secured page told the
              // user its certificate could not be confirmed -- the same
              // unknown/unreadable conflation chrome.js:6722 and
              // windows.rs:5104 both forbid, in the one ternary that was
              // never split.
              : i18nText("chrome-js-safety-unconfirmed", "This page is encrypted, but the certificate could not be fully confirmed.");
    }
    if ($("tab-issuer-desc")) {
      const issuer = st.tls_issuer;
      $("tab-issuer-desc").textContent = issuer
        ? i18nText("chrome-js-issuer-prefix", "Certificate issued by: ") + issuer
        : i18nText("chrome-js-issuer-none", "No certificate issuer to show for this page.");
    }

    // Storage profile: stated as fact. It is fixed when the tab is built, so
    // there is deliberately no control here — only what IS, and a pointer to
    // the way to get a tab that keeps nothing.
    $("tab-profile-desc").textContent =
      st.profile === "ephemeral"
        ? i18nText("chrome-js-profile-ephemeral", "Cookies and site data are discarded when this tab closes. This cannot change after opening.")
        : i18nText("chrome-js-profile-persistent", "This tab saves cookies, cache, and site data.");

    // Cookies: origin-scoped, and closed the moment the origin changes (see
    // the comment on `lastForgetOrigin`). `origin` is `null` for a page with
    // no http(s) authority -- about:blank, an internal page -- and there is
    // nothing to forget there.
    const origin = st.origin || null;
    if (origin !== lastForgetOrigin) {
      lastForgetOrigin = origin;
      $("site-forget-confirm").hidden = true;
      $("site-forget-result").hidden = true;
    }
    renderSiteForgetControl();

    // Save-password banner: `pending_save` is only ever non-null when the
    // ACTIVE tab is the one that submitted a login, and never carries the
    // password (see `AppState::active_tab_status`'s own doc). Read on every
    // tab_status, not gated on any panel being open -- an offer to save a
    // password is worth surfacing whether or not Tab Activity is open, unlike
    // the Passwords section below.
    applyPendingSave(st.pending_save || null);

    // Plain-HTTP warning: `insecure_pending` is the URL the navigation
    // handler is holding for the ACTIVE tab, or null. Rendered from status,
    // like the save offer, so a tab switch shows or hides it correctly.
    applyInsecurePending(
      st.insecure_pending || null,
      st.insecure_pending_host || null,
    );

    // The ad-list hold. Rendered from status for the DISPLAYED tab, like the
    // two above, so a tab switch shows or hides it correctly rather than
    // leaving the previous tab's banner on screen.
    applyAdlistPending(st.adlist_pending || null, st.id);
    // Read by the Tab Activity rows. From status rather than remembered from
    // the click, so it disappears when Rust drops the override rather than
    // when the chrome happens to notice.
    adlistOverrideHost = st.adlist_override_host || null;

    // Passwords used to be refreshed HERE, and only while Tab Activity was
    // open -- the round trip was not worth making for a panel nobody had
    // opened. It now happens unconditionally at the top of this same function,
    // because the toolbar fill button needs the answer on every page. Left as
    // a note rather than a second call: two refreshes per status update, one
    // of them conditional, is how the two controls would drift apart.

    syncAllowSiteButton();

    // Translation state rides with tab status, so the panel AND the toolbar
    // chip repaint on navigation and on every phase change -- not only on the
    // user's own three clicks, which was how a panel kept saying "This page
    // is translated" about a page the browser had never touched.
    renderTranslate(st.translation || null);

    // The declared-language signal, into the translate panel. The host has
    // sent detected_lang with every one of these payloads since the badge was
    // built, and translateDetected -- read by the source prefill AND the
    // "looks like" hint -- was never assigned from it. Fourth dangling wire
    // in this family: designed, built on the host, unplugged on the page.
    // Guarded on CHANGE so a user's manual source choice is not fought by
    // every status push; only a new detection re-prefills.
    // Always a REGISTRY code now (the host resolves the raw tag), so it is
    // compared verbatim -- splitting it here is what once cut "zh-Hans" to a
    // "zh" that named no language at all.
    const det = st.detected_lang ? String(st.detected_lang) : null;
    if (det !== translateDetected) {
      translateDetected = det;
      // A NEW detection is the one case that may overwrite the field.
      fillSourceOptions(true);
      fillTargetOptions();
      renderDetectedHint();
    }
  }

  // ---- from the privsurface draft ----
  function toggleFreeze() {
    // The REQUEST, not the enforcement: a failed freeze still needs
    // "unfreeze" to clear it back to live.
    const frozen = lastTabStatus && lastTabStatus.freeze_phase === "frozen";
    rb(frozen ? "tab_unfreeze" : "tab_freeze")
      .then(applyTabStatus)
      .catch(() => {});
  }

  // ---- from the privsurface draft ----
  function openQuarantineTab() {
    rb("tab_quarantine")
      // The user opens a quarantine tab to type a suspicious address into
      // it; meet them halfway.
      .then(() => urlInput.focus())
      .catch(() => {});
  }

  // ---- from the privsurface draft ----
  // Best-effort host for the "allow this site" convenience button, derived
  // from the URL bar. The ledger row buttons use the exact normalized hosts
  // Rust recorded, so they are always right; this one is a shortcut and the
  // Rust-side validation is the backstop.
  function normalizeAllowHost(url) {
    const host = hostOf(url || "");
    if (!host || (host === url && !/:\/\//.test(url))) return "";
    if (host.startsWith("[")) {
      const end = host.indexOf("]");
      return end > 0 ? host.slice(1, end) : "";
    }
    return host.split(":")[0];
  }

  // ---- from the privsurface draft ----
  function syncAllowSiteButton() {
    const btn = $("btn-allow-site");
    const host = normalizeAllowHost(urlInput.value);
    btn.disabled = !host;
    if (host) {
      i18nSet(
        btn,
        "chrome-js-allowsite-allow-host",
        { host },
        "Allow " + host + " while frozen",
      );
    } else {
      btn.textContent = i18nText("chrome-js-allowsite-allow-generic", "Allow this site while frozen");
    }
  }

  // ---- from the privsurface draft ----
  function allowHost(host) {
    if (!host || activeTabId == null) return;
    const tabId = activeTabId;
    rb("tab_allow_site", { host })
      .then((st) => {
        let set = allowedHosts.get(tabId);
        if (!set) {
          set = new Set();
          allowedHosts.set(tabId, set);
        }
        set.add(host);
        applyTabStatus(st);
        if (lastLedger) renderLedger(lastLedger);
      })
      .catch((e) => {
        $("ledger-foot").textContent = friendly(e);
      });
  }

  // ---- from the privsurface draft ----
  function refreshTabPanel() {
    rb("tab_status")
      .then(applyTabStatus)
      .catch(() => {});
    refreshLedger();
    refreshPrivacyReceipt();
    refreshFingerprintProbes();
  }

  // ---- privacy receipt ----
  //
  // What the browser refused on the user's behalf, in the ledger's own
  // numbers: the session across all tabs (closed ones included), and the
  // current page. Refreshed on panel open only -- no polling loop, no live
  // ticker. A number that climbs while you watch sells motion as
  // protection; panel-open freshness is honest and cheap.
  function refreshPrivacyReceipt() {
    // Blank first: a panel reopened on another tab must not show the
    // previous tab's numbers while the reply is in flight, and a failed
    // call leaves the lines EMPTY, never zeroed -- a zero would read as
    // "nothing was refused", a measurement never taken.
    $("receipt-session").textContent = "";
    $("receipt-session-caption").textContent = "";
    $("receipt-page").textContent = "";
    rb("privacy_receipt")
      .then(renderPrivacyReceipt)
      .catch(() => {});
  }

  function renderPrivacyReceipt(r) {
    const sessionEl = $("receipt-session");
    const captionEl = $("receipt-session-caption");
    const pageEl = $("receipt-page");
    if (!r) return;
    // The same gate the badge and the ledger list apply
    // (ledger_counts_blocked): where the platform cannot observe blocking
    // at all, say so in words. ONLY that case earns the engine sentence --
    // a malformed reply is a broken contract, not an engine limitation,
    // and it leaves the lines empty rather than mislabelled.
    if (r.counts_blocked !== true) {
      sessionEl.textContent =
        i18nText("chrome-js-receipt-not-observable", "Refused-request counts are not observable with this engine.");
      pageEl.textContent = "";
      return;
    }
    if (
      typeof r.session_blocked !== "number" ||
      typeof r.page_blocked !== "number"
    ) {
      return;
    }
    sessionEl.textContent =
      String(r.session_blocked) +
      (r.session_blocked === 1
        ? " request refused this session, across all tabs."
        : " requests refused this session, across all tabs.");
    captionEl.textContent =
      "Refused by the blocker since the browser was launched, counted across every tab, including tabs you have since closed.";
    pageEl.textContent =
      String(r.page_blocked) +
      (r.page_blocked === 1
        ? " refused on this page."
        : " refused on this page.");
  }

  // Separate from the privacy receipt. These numbers came from wrappers in
  // the page's own main world, so the renderer preserves Rust's explicit
  // page-reported caveat and never presents them as engine evidence.
  function refreshFingerprintProbes() {
    for (const id of [
      "fingerprint-probe-label",
      "fingerprint-probe-caveat",
      "fingerprint-probe-audio",
      "fingerprint-probe-canvas",
      "fingerprint-probe-webgl",
      "fingerprint-probe-element-measurement",
      "fingerprint-probe-status",
    ]) {
      $(id).textContent = "";
    }
    rb("fingerprint_probe_activity")
      .then(renderFingerprintProbes)
      .catch(() => {});
  }

  function renderFingerprintProbes(reading) {
    if (!reading || !reading.counts || !reading.surface_labels) return;
    $("fingerprint-probe-label").textContent = reading.label || "";
    $("fingerprint-probe-caveat").textContent = reading.caveat || "";
    const rows = [
      ["audio", "fingerprint-probe-audio"],
      ["canvas", "fingerprint-probe-canvas"],
      ["webgl", "fingerprint-probe-webgl"],
      ["element_measurement", "fingerprint-probe-element-measurement"],
    ];
    for (const [surface, id] of rows) {
      const count = reading.counts[surface];
      const label = reading.surface_labels[surface];
      if (typeof count !== "number" || typeof label !== "string") return;
      // Zero is a reading, not absence: all four rows always render.
      $(id).textContent =
        label +
        ": " +
        String(count) +
        (count === 1 ? " page-reported probe." : " page-reported probes.");
    }
    $("fingerprint-probe-status").textContent = reading.status_text || "";
  }

  // ---- from the privsurface draft ----
  function refreshLedger() {
    return rb("tab_ledger")
      .then((data) => {
        lastLedger = data;
        renderLedger(data);
      })
      .catch(() => {});
  }

  // ---- from the privsurface draft ----
  function renderLedger(data) {
    const list = $("ledger-list");
    list.textContent = "";
    const items = (data && data.items) || [];
    // Whether the blocked column is observed on this platform. On WebKitGTK
    // the content blocker reports no per-request matches, so the blocked
    // count is structurally zero and the list must be labelled as what the
    // tab CONTACTED -- never as "nothing was blocked".
    const countsBlocked = !!(data && data.counts_blocked);
    const allowed = allowedHosts.get(activeTabId) || new Set();

    if (!items.length) {
      const li = el("li", "item");
      // An empty ledger means one of two very different things, and saying
      // the wrong one is a positive claim of no contact on a tab that is
      // simply not watching. The ledger is fed by the same handler the
      // blocking is, so when that failed to register this list is
      // structurally empty however much the tab talks.
      const broken =
        lastTabInterception === "failed" ||
        lastTabInterception === "not_attempted";
      li.appendChild(
        el(
          "span",
          "item-sub",
          broken
            ? i18nText("chrome-js-ledger-empty-broken", "No request record is available for this tab. This does not mean it contacted nobody.")
            : i18nText("chrome-js-ledger-empty-ok", "No requests yet. Contacted hosts appear here."),
        ),
      );
      list.appendChild(li);
    }

    for (const rec of items) {
      const li = el("li", "item");
      const head = el("div", "item-head");
      head.appendChild(el("span", "item-title", rec.host));
      const counts = el("span", "item-sub");
      if (countsBlocked) {
        counts.appendChild(
          el("span", "allowed", String(rec.allowed) + " allowed"),
        );
        counts.appendChild(document.createTextNode(" \u00B7 "));
        counts.appendChild(
          el("span", "blocked", String(rec.blocked) + " blocked"),
        );
      } else {
        counts.appendChild(
          el("span", "allowed", String(rec.allowed) + " requested"),
        );
      }
      head.appendChild(counts);
      li.appendChild(head);

      const row = el("div", "item-row");
      const already = allowed.has(rec.host);
      const allowBtn = el(
        "button",
        "small",
        already ? i18nText("chrome-js-ledger-allowed-button", "Allowed") : i18nText("chrome-js-ledger-allow-button", "Allow while frozen"),
      );
      allowBtn.type = "button";
      allowBtn.disabled = already;
      allowBtn.title =
        i18nText("chrome-js-ledger-allow-title", "Allow this host while frozen. Ends when the tab closes.");
      allowBtn.addEventListener("click", () => allowHost(rec.host));
      row.appendChild(allowBtn);

      // THE AD-LIST EXCEPTION, if this tab holds one for this host.
      //
      // Its own label and its own sentence, deliberately not reusing the
      // "Allowed" / "Ends when the tab closes" vocabulary a few pixels to its
      // left. That button is the FREEZE override, a different consent with a
      // different scope and a different end, and two per-host permissions in
      // one panel wearing one set of words is how a user ends up believing
      // they revoked something they did not.
      //
      // A read-out, not a control: it is removed by leaving the host or
      // closing the tab, which the sentence says. There is no button here to
      // undo it, because inventing a second revocation path that the engine
      // side does not implement would be a control that lies.
      if (adlistOverrideHost && rec.host === adlistOverrideHost) {
        const chip = el("span", "item-chip",
          i18nText("chrome-adlist-exception-button", "Ad list exception"));
        // Not parameterized: i18nText takes no arguments, and the host is
        // already this row's title a few pixels away, so repeating it in the
        // tooltip buys nothing and would need the i18nSet path, which sets
        // text content rather than an attribute.
        chip.title = i18nText("chrome-adlist-exception-title",
          "PATANYX is letting this tab reach this host past ad and tracker blocking. Ends when you leave it or close the tab.");
        row.appendChild(chip);
      }
      li.appendChild(row);
      list.appendChild(li);
    }

    $("ledger-foot").textContent = countsBlocked
      ? i18nText("chrome-js-ledger-foot-blocked", "Blocked requests never left this browser.")
      : i18nText("chrome-js-ledger-foot-uncounted", "Contacted hosts only; this platform cannot count stopped requests.");
  }

  // ---- from the bookmarks draft ----
  function fmtTime(unixSeconds) {
    if (!unixSeconds) return "";
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  // ---- from the bookmarks draft ----
  function fmtBytes(n) {
    const units = [i18nText("chrome-js-fmtbytes-b", "B"), i18nText("chrome-js-fmtbytes-kb", "KB"), i18nText("chrome-js-fmtbytes-mb", "MB"), i18nText("chrome-js-fmtbytes-gb", "GB"), i18nText("chrome-js-fmtbytes-tb", "TB")];
    let value = n;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
      value = value / 1024;
      i += 1;
    }
    const rounded =
      i === 0 || value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
    return rounded + " " + units[i];
  }

  // ---- from the bookmarks draft ----
  function currentBookmark() {
    const url = urlInput.value.trim();
    if (!url) return null;
    return bookmarkItems.find((b) => b.url === url) || null;
  }

  // ---- from the bookmarks draft ----
  function updateStar() {
    const saved = !!currentBookmark();
    btnBookmark.classList.toggle("is-active", saved);
    const label = saved
      ? i18nText("chrome-js-bookmarks-star-saved", "This page is bookmarked. Open bookmarks")
      : i18nText("chrome-js-palette-bookmark", "Bookmark this page");
    btnBookmark.title = label;
    btnBookmark.setAttribute("aria-label", label);
  }

  // ---- from the bookmarks draft ----
  /// Opens the Library and selects one of its views. `tab` keeps the old
  /// vocabulary ("bookmarks" | "shelves" | "downloads") because the call
  /// sites elsewhere in this file still speak it.
  function openLibrary(tab) {
    if (openPanelName !== "library") togglePanelNamed("library");
    managerSelected =
      tab === "downloads" ? "downloads" : tab === "shelves" ? "shelves" : "all";
    renderBookmarksManager();
  }

  // The folder organizer. One source of truth: bookmark_list, whose bookmarks
  // carry their folders as tags and whose `folders` reply names the empty ones
  // too. A folder opens in place rather than in a dropdown, because this pane
  // has the room a chrome strip does not.
  let openFolderName = null;
  // The folder whose head is currently an inline rename field, or null. Inline
  // rather than a modal so no new dialog surface is added; only one folder is
  // ever being renamed at a time.
  let renamingFolder = null;

  // The known folders unioned with any tag that has bookmarks but was never
  // "made" (a tag typed into the Edit field). Known names first, in their
  // stored order, so an empty folder is visible; then the stragglers.
  function allFolders() {
    const withItems = bookmarkFolders(bookmarkItems); // [{tag, items}]
    const byTag = new Map(withItems.map((f) => [f.tag, f]));
    const out = [];
    const seen = new Set();
    for (const name of bookmarkFolderNames) {
      if (seen.has(name)) continue;
      seen.add(name);
      out.push(byTag.get(name) || { tag: name, items: [] });
    }
    for (const f of withItems) {
      if (seen.has(f.tag)) continue;
      seen.add(f.tag);
      out.push(f);
    }
    return out;
  }

  // Reload bookmarks AND folder names from the store, THROWING on failure so a
  // caller that just wrote can tell the user the view is stale rather than
  // leaving it silently drifted from disk. `refreshBookmarks` below wraps this
  // and swallows, for the many best-effort callers that predate folders.
  async function reloadBookmarkState() {
    const data = await rb("bookmark_list");
    bookmarkItems = data.items || [];
    bookmarkFolderNames = Array.isArray(data.folders) ? data.folders : [];
  }

  // Files the dragged bookmark into `folder`, then reloads and re-renders. A
  // write failure and a post-write refresh failure are reported differently:
  // the first means nothing changed, the second means it did but the view has
  // not caught up.
  async function fileDraggedInto(folder) {
    const id = draggedBookmarkId;
    draggedBookmarkId = null;
    if (!id) return;
    try {
      await rb("bookmark_folder_file", { id, folder });
    } catch (e) {
      toast(friendly(e), true);
      return;
    }
    await refreshOrganizerAfterWrite();
  }

  async function refreshOrganizerAfterWrite() {
    try {
      await reloadBookmarkState();
    } catch (e) {
      const detail = friendly(e);
      i18nResolve(
        "chrome-js-folders-refresh-failed",
        { detail },
        "Saved, but the view could not refresh: " + detail,
      ).then((t) => toast(t, true));
      return;
    }
    renderFolderGrid();
    renderBookmarkBar();
    renderBookmarksManager();
    updateStar();
  }

  function renderFolderGrid() {
    const grid = $("folder-grid");
    if (!grid) return;
    grid.textContent = "";
    const folders = allFolders();
    $("folder-empty").hidden = folders.length > 0;

    for (const folder of folders) {
      const wrap = document.createElement("div");
      wrap.className = "folder";

      // The whole card is a drop target. dragover is where the decision to
      // ACCEPT a drop is made (preventDefault), and it reads the module flag
      // -- dataTransfer contents are unreadable here on both engines, and the
      // flag is also how we ignore a drag of anything that is not a bookmark.
      const acceptDrag = (ev) => {
        if (!draggedBookmarkId) return;
        ev.preventDefault();
        if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
        wrap.classList.add("drop-hover");
      };
      wrap.addEventListener("dragover", acceptDrag);
      wrap.addEventListener("dragenter", acceptDrag);
      wrap.addEventListener("dragleave", () =>
        wrap.classList.remove("drop-hover"),
      );
      wrap.addEventListener("drop", (ev) => {
        if (!draggedBookmarkId) return;
        ev.preventDefault();
        wrap.classList.remove("drop-hover");
        fileDraggedInto(folder.tag);
      });

      if (renamingFolder === folder.tag) {
        // Inline rename: the head becomes a field pre-filled with the name.
        const form = document.createElement("form");
        form.className = "folder-rename";
        const input = document.createElement("input");
        input.type = "text";
        input.maxLength = 40;
        input.value = folder.tag;
        input.setAttribute("aria-label", i18nText("chrome-js-folders-rename-aria", "Rename folder"));
        form.appendChild(input);
        const save = el("button", "small", i18nText("chrome-js-folders-save", "Save"));
        save.type = "submit";
        form.appendChild(save);
        const cancel = el("button", "small", i18nText("chrome-js-folders-cancel", "Cancel"));
        cancel.type = "button";
        cancel.addEventListener("click", () => {
          renamingFolder = null;
          renderFolderGrid();
        });
        form.appendChild(cancel);
        form.addEventListener("submit", (ev) => {
          ev.preventDefault();
          submitRename(folder.tag, input.value);
        });
        wrap.appendChild(form);
        grid.appendChild(wrap);
        // Focus after it is in the document.
        input.focus();
        input.select();
        continue;
      }

      const head = document.createElement("button");
      head.type = "button";
      head.className = "folder-head";
      head.setAttribute("aria-expanded", String(openFolderName === folder.tag));
      head.textContent = folder.tag + " (" + folder.items.length + ")";
      head.addEventListener("click", () => {
        openFolderName = openFolderName === folder.tag ? null : folder.tag;
        renderFolderGrid();
      });
      wrap.appendChild(head);

      // Rename / delete, always visible so the folder can be managed without
      // first opening it. Delete says plainly that it unfiles, never destroys.
      const actions = document.createElement("div");
      actions.className = "folder-actions";
      const renameBtn = el("button", "small", i18nText("chrome-js-manager-rename", "Rename"));
      renameBtn.type = "button";
      renameBtn.addEventListener("click", () => {
        renamingFolder = folder.tag;
        renderFolderGrid();
      });
      actions.appendChild(renameBtn);
      const delBtn = el("button", "small danger", i18nText("chrome-js-folders-delete-folder", "Delete folder"));
      delBtn.type = "button";
      delBtn.title = i18nText("chrome-js-folders-delete-title", "Removes the folder. The bookmarks in it are kept.");
      delBtn.addEventListener("click", () => deleteFolder(folder.tag));
      actions.appendChild(delBtn);
      wrap.appendChild(actions);

      if (openFolderName === folder.tag) {
        const list = document.createElement("ul");
        list.className = "folder-items";
        if (!folder.items.length) {
          const li = document.createElement("li");
          li.className = "item-sub";
          li.textContent =
            i18nText("chrome-js-folders-empty-items", "Empty. Use Folders on any bookmark to file it here, or drag one in.");
          list.appendChild(li);
        }
        for (const item of folder.items) {
          const li = document.createElement("li");
          const open = document.createElement("button");
          open.type = "button";
          open.className = "folder-link";
          open.textContent = item.title || item.url;
          open.title = item.url;
          open.addEventListener("click", async () => {
            try {
              await rb("bookmark_open", { id: item.id });
              if (openPanelName === "library") togglePanelNamed("library");
            } catch (e) {
              toast(friendly(e), true);
            }
          });
          li.appendChild(open);
          const host = document.createElement("span");
          host.className = "item-sub";
          host.textContent = hostOf(item.url);
          li.appendChild(host);
          // Remove this one bookmark from this one folder. Its other folders
          // and the bookmark itself are untouched.
          const unfile = el("button", "small", i18nText("chrome-js-folders-remove", "Remove"));
          unfile.type = "button";
          unfile.title = i18nText("chrome-js-folders-unfile-title", "Remove from this folder. The bookmark is kept.");
          unfile.addEventListener("click", async () => {
            try {
              await rb("bookmark_folder_unfile", {
                id: item.id,
                folder: folder.tag,
              });
            } catch (e) {
              toast(friendly(e), true);
              return;
            }
            await refreshOrganizerAfterWrite();
          });
          li.appendChild(unfile);
          list.appendChild(li);
        }
        wrap.appendChild(list);
      }
      grid.appendChild(wrap);
    }

    renderFolderSource(grid, folders.length > 0);
  }

  // The draggable source: every bookmark, so any of them can be dragged into
  // any folder above. Dragging is additive and idempotent server-side, so
  // dropping a bookmark on a folder it is already in simply does nothing.
  function renderFolderSource(grid, haveFolders) {
    if (!bookmarkItems.length) return;
    const head = document.createElement("h3");
    head.className = "section-head";
    head.textContent = i18nText("chrome-js-folders-source-head", "All bookmarks");
    grid.appendChild(head);
    const hint = document.createElement("p");
    hint.className = "panel-foot";
    hint.textContent = haveFolders
      ? i18nText("chrome-js-folders-source-hint", "Drag a bookmark onto a folder above, or use Folders on any bookmark in the Bookmark Manager.")
      : i18nText("chrome-js-folders-source-hint-none", "Make a folder above, then file bookmarks into it from the Bookmark Manager.");
    grid.appendChild(hint);

    const list = document.createElement("ul");
    list.className = "folder-source";
    for (const item of bookmarkItems) {
      const li = document.createElement("li");
      li.className = "source-item";
      li.setAttribute("draggable", "true");
      li.title = item.url;
      const name = document.createElement("span");
      name.className = "source-name";
      name.textContent = item.title || hostOf(item.url);
      li.appendChild(name);
      if (Array.isArray(item.tags) && item.tags.length) {
        const inFolders = document.createElement("span");
        inFolders.className = "item-sub";
        const folders = item.tags.join(", ");
        i18nSet(
          inFolders,
          "chrome-js-folders-source-in",
          { folders },
          "in " + folders,
        );
        li.appendChild(inFolders);
      }
      li.addEventListener("dragstart", (ev) => {
        draggedBookmarkId = item.id;
        li.classList.add("dragging");
        if (ev.dataTransfer) {
          ev.dataTransfer.effectAllowed = "copy";
          // A payload is set because some engines will not start a drag
          // without one, but it is deliberately not the bookmark id -- the
          // real target is carried in the module flag, so nothing internal
          // leaks if this is dropped outside the app.
          ev.dataTransfer.setData("text/plain", item.title || "bookmark");
        }
      });
      li.addEventListener("dragend", () => {
        draggedBookmarkId = null;
        li.classList.remove("dragging");
        for (const w of grid.querySelectorAll(".drop-hover")) {
          w.classList.remove("drop-hover");
        }
      });
      list.appendChild(li);
    }
    grid.appendChild(list);
  }

  // New-folder control: makes an empty folder that survives with nothing in
  // it. Idempotent server-side, so re-creating an existing name is a quiet
  // success. Refuses empty/over-long the same way the store does.
  async function createFolderFromInput() {
    const input = $("folder-new-name");
    const errline = $("folder-new-error");
    if (!input) return;
    const name = (input.value || "").trim();
    if (errline) errline.hidden = true;
    if (!name) {
      if (errline) {
        errline.textContent = i18nText("chrome-js-folders-new-empty", "Type a folder name first.");
        errline.hidden = false;
      }
      return;
    }
    try {
      await rb("bookmark_folder_create", { name });
    } catch (e) {
      if (errline) {
        errline.textContent = friendly(e);
        errline.hidden = false;
      }
      return;
    }
    input.value = "";
    await refreshOrganizerAfterWrite();
  }

  async function submitRename(from, raw) {
    const to = (raw || "").trim();
    // An unchanged or empty name is a quiet cancel: nothing to write.
    if (!to || to === from) {
      renamingFolder = null;
      renderFolderGrid();
      return;
    }
    try {
      await rb("bookmark_folder_rename", { from, to });
    } catch (e) {
      toast(friendly(e), true);
      return;
    }
    // The renamed folder keeps its open state under its new (normalised) name.
    const normalised = to.toLowerCase();
    if (openFolderName === from) openFolderName = normalised;
    renamingFolder = null;
    await refreshOrganizerAfterWrite();
  }

  async function deleteFolder(name) {
    const ok = await askConfirm(
      await i18nResolve(
        "chrome-confirm-delete-folder",
        { name },
        "Delete the folder “" + name + "”? The bookmarks in it are kept, " +
          "just no longer filed under this folder.",
      ),
    );
    if (!ok) return;
    try {
      await rb("bookmark_folder_delete", { name });
    } catch (e) {
      toast(friendly(e), true);
      return;
    }
    if (openFolderName === name) openFolderName = null;
    await refreshOrganizerAfterWrite();
  }

  // ---- from the bookmarks draft ----
  // ---- bookmark import ----
  // The picker, the file read and the parse all live in Rust; this handler
  // only asks and then reports the arm's own numbers. A null reply is the
  // picker's cancel -- nothing to report, nothing shown.
  // Filter as you type. `input` rather than `keyup` so it also catches a
  // paste, a drag-drop of text, and the clear button browsers put in search
  // fields -- all of which change the value without a key ever going up.
  // Escape clears the filter rather than closing the panel, which is what a
  // search box in a list is expected to do. The panel's own Escape still
  // works from anywhere else in it, because this only stops the event when
  // there is a filter to clear.

  // New-folder control in the organizer pane. The button and Enter both
  // create; guards inside createFolderFromInput handle empty/over-long.
  const folderAddBtn = $("folder-new-add");
  if (folderAddBtn) {
    folderAddBtn.addEventListener("click", () => createFolderFromInput());
  }
  const folderNameInput = $("folder-new-name");
  if (folderNameInput) {
    folderNameInput.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        createFolderFromInput();
      }
    });
  }

  $("bm-import").addEventListener("click", async () => {
    const btn = $("bm-import");
    const summary = $("bm-import-summary");
    summary.hidden = true;
    btn.disabled = true;
    try {
      const r = await rb("bookmarks_import");
      if (r) {
        // Both skip categories always shown, zeros included: "skipped 0"
        // is confirmation the category was considered, not noise.
        summary.textContent =
          "Imported " +
          r.imported +
          ". Skipped " +
          r.skipped_duplicates +
          " duplicate" +
          (r.skipped_duplicates === 1 ? "" : "s") +
          ", " +
          r.skipped_unsupported +
          " unsupported.";
        summary.hidden = false;
        await refreshBookmarks();
      }
    } catch (e) {
      summary.textContent = friendly(e);
      summary.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });

  // ---- shelves ----
  // A shelf stores title + URL only: no favicons, no scroll positions, no
  // cookies, no history. That is the privacy contract of the feature.
  $("set-aside").addEventListener("click", async () => {
    const btn = $("set-aside");
    btn.disabled = true;
    try {
      const r = await rb("shelf_create");
      const leftOut =
        r.left_out > 0
          ? await i18nResolve(
              "chrome-shelf-left-out",
              { count: r.left_out },
              " " + r.left_out + " left out: ephemeral and internal pages stay open.",
            )
          : "";
      toast(r.name + "." + leftOut);
      await shelfRenderList();
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  // How many shelves the last fetch saw, for the sidebar's count. Cached
  // because shelves are fetched per render rather than held in a list here,
  // and a sidebar cannot wait on a round trip to draw itself.
  let shelfCountCached = 0;
  function shelfCount() {
    return shelfCountCached;
  }

  async function shelfRenderList() {
    // TWO lists, one fetch: the Bookmarks tab keeps its shelves where they
    // have always been, and the Shelves tab shows the same sets under its
    // folders. Rows are built per list rather than shared, because a DOM
    // node has one parent and appending it twice would silently move it.
    const lists = ["shelf-list", "shelf-list-2"].map($).filter(Boolean);
    if (!lists.length) return;
    for (const list of lists) list.textContent = "";
    let items;
    try {
      const reply = await rb("shelf_list");
      items = (reply && reply.items) || [];
      shelfCountCached = items.length;
    } catch (e) {
      // Unavailable is not empty: the panel says which one it is.
      for (const list of lists) list.textContent = friendly(e);
      return;
    }
    if (items.length === 0) {
      for (const list of lists) {
        list.textContent =
          i18nText("chrome-js-shelves-empty", "No shelves. Shelve tabs to store them here.");
      }
      return;
    }
    for (const list of lists) {
      for (const shelf of items) {
        list.appendChild(shelfRow(shelf));
      }
    }
  }

  function shelfRow(shelf) {
    const row = document.createElement("li");
    row.className = "item";

    // The name is the disclosure: a shelf behaves like a folder, so clicking
    // it opens it rather than doing nothing. The count sits beside the name
    // because "what is in here" is the question a named set of tabs raises,
    // and answering it should not require restoring the whole set.
    const count = Array.isArray(shelf.tabs)
      ? shelf.tabs.length
      : shelf.count || 0;
    const name = document.createElement("button");
    name.type = "button";
    name.className = "shelf-name";
    name.setAttribute("aria-expanded", "false");
    // textContent, never markup injection: shelf names are user-entered now,
    // so this is load-bearing rather than defensive.
    name.textContent =
      shelf.name + " (" + count + (count === 1 ? " tab)" : " tabs)");
    row.appendChild(name);

    // Built once, hidden until asked for. Rebuilt on every render, so a
    // rename or a restore cannot leave a stale list behind.
    const contents = document.createElement("ul");
    contents.className = "shelf-contents";
    contents.hidden = true;
    for (const t of shelf.tabs || []) {
      const entry = document.createElement("li");
      const open = document.createElement("button");
      open.type = "button";
      open.className = "shelf-link";
      open.textContent = t.title || t.url;
      open.title = t.url;
      open.addEventListener("click", async () => {
        try {
          // ONE tab, and the shelf is left exactly as it was. Restore opens
          // the whole set; this is for fetching a single thing back out of
          // it, which is the reason to look inside at all.
          await rb("tab_new", { url: t.url });
          if (openPanelName === "library") togglePanelNamed("library");
        } catch (e) {
          toast(friendly(e), true);
        }
      });
      entry.appendChild(open);
      const where = document.createElement("span");
      where.className = "item-sub";
      where.textContent = hostOf(t.url);
      entry.appendChild(where);
      contents.appendChild(entry);
    }
    name.addEventListener("click", () => {
      contents.hidden = !contents.hidden;
      name.setAttribute("aria-expanded", contents.hidden ? "false" : "true");
    });

    const restore = document.createElement("button");
    restore.type = "button";
    restore.className = "small";
    restore.textContent = i18nText("chrome-js-shelves-restore", "Restore");
    restore.addEventListener("click", async () => {
      try {
        const r = await rb("shelf_restore", { id: shelf.id });
        if (r.opened < r.total) {
          toast("Restored " + r.opened + "/" + r.total + " tabs. Shelf kept.");
        }
        // The shelf is KEPT on purpose: restore is never the destructive
        // step, so the row stays exactly as it was.
      } catch (e) {
        toast(friendly(e), true);
      }
    });
    row.appendChild(restore);

    const del = document.createElement("button");
    del.type = "button";
    del.className = "small";
    del.textContent = i18nText("chrome-js-confirm-default-label", "Delete");
    del.addEventListener("click", async () => {
      // No confirm dialog: a shelf is small and recreatable, and confirm
      // dialogs train click-through. The row stays until the reply
      // confirms the deletion landed.
      restore.disabled = true;
      del.disabled = true;
      try {
        await rb("shelf_delete", { id: shelf.id });
        row.remove();
      } catch (e) {
        restore.disabled = false;
        del.disabled = false;
        toast(friendly(e), true);
      }
    });
    row.appendChild(del);

    // The note, when there is one. textContent for the same reason the name
    // above uses it.
    if (shelf.note) {
      const note = document.createElement("p");
      note.className = "panel-foot";
      note.textContent = shelf.note;
      row.appendChild(note);
    }
    row.appendChild(contents);

    // Edit opens one small inline form for both the name and the note. One
    // form rather than two affordances: they are edited together in
    // practice, and the row already carries three buttons.
    //
    // `editor` is cleared whenever the form goes away, by Cancel, by Save,
    // or by the toggle. Leaving a stale reference behind is why a second
    // click would otherwise be needed to reopen it.
    let editor = null;
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "small";
    edit.textContent = i18nText("chrome-js-creds-edit", "Edit");
    edit.addEventListener("click", () => {
      if (editor) {
        editor.remove();
        editor = null;
        return;
      }
      const form = document.createElement("form");
      form.className = "entry-form";

      const nameInput = document.createElement("input");
      nameInput.type = "text";
      nameInput.placeholder = i18nText("chrome-js-shelves-name-placeholder", "Name");
      nameInput.value = shelf.name || "";
      nameInput.maxLength = 120;
      form.appendChild(nameInput);

      const noteInput = document.createElement("textarea");
      noteInput.placeholder = i18nText("chrome-js-shelves-note-placeholder", "Notes for this set, such as what it is for");
      noteInput.value = shelf.note || "";
      noteInput.maxLength = 2000;
      noteInput.rows = 3;
      form.appendChild(noteInput);

      const buttons = document.createElement("div");
      buttons.className = "form-buttons";
      const save = document.createElement("button");
      save.type = "submit";
      save.textContent = i18nText("chrome-js-folders-save", "Save");
      buttons.appendChild(save);
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = i18nText("chrome-js-folders-cancel", "Cancel");
      cancel.addEventListener("click", () => {
        form.remove();
        editor = null;
      });
      buttons.appendChild(cancel);
      form.appendChild(buttons);

      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        save.disabled = true;
        try {
          const named = await rb("shelf_rename", {
            id: shelf.id,
            name: nameInput.value,
          });
          const noted = await rb("shelf_note_set", {
            id: shelf.id,
            note: noteInput.value,
          });
          // Re-read from the REPLIES, never from what was typed: the store
          // caps both, so what it kept is the truth.
          shelf.name = named.name;
          shelf.note = noted.note;
          form.remove();
          editor = null;
          shelfRenderList();
        } catch (e) {
          save.disabled = false;
          toast(friendly(e), true);
        }
      });

      editor = form;
      row.appendChild(form);
      nameInput.focus();
    });
    row.appendChild(edit);

    return row;
  }

  async function refreshLibrary() {
    try {
      const st = await rb("store_status");
      $("library-locked").hidden = !!st.open;
      $("library-content").hidden = !st.open;
      if (!st.open) {
        clearLibrarySnapshotData();
        // A recorded open error is more useful than the generic line.
        $("library-locked-note").textContent = st.error
          ? friendly(new Error(st.error))
          : i18nText("chrome-js-library-locked-note", "Unlock the vault for bookmarks, shelved tabs, and download records. PATANYX offers this when started on its own. Downloads finished before unlock are not recorded.");
        return;
      }
      await Promise.all([
        refreshBookmarks(),
        refreshDownloads(),
        shelfRenderList(),
      ]);
      // All three views live in this panel, so one render puts every one of
      // them in step with what was just fetched.
      renderBookmarksManager();
    } catch (e) {
      /* leave the panel as-is */
    }
  }

  function clearLibrarySnapshotData() {
    bookmarkItems = [];
    snapshotCheckResults.clear();
    snapshotChecksPending.clear();
    snapshotSelections.clear();
    for (const id of ["bmm-list", "bmm-quick", "bmm-folders", "bmm-cards"]) {
      const node = $(id);
      if (node) node.textContent = "";
    }
    const caption = $("bmm-snapshots-caption");
    if (caption) caption.hidden = true;
  }

  // ---- bookmark folder bar --------------------------------------------
  //
  // The folders ARE the tags. Rendered from the same bookmark_list the
  // Library panel uses, so there is no second source of truth to drift: a
  // retag in the panel changes this row on the next refresh.
  //
  // A bookmark with two tags appears under both folders. That is the
  // deliberate difference from a filesystem folder, where a link has exactly
  // one home, and it is the reason tags were worth building on.
  let bmbarOpenFolder = null;

  function closeBookmarkFolder() {
    const bar = $("bmbar");
    if (!bar) return;
    const open = document.querySelector(".bmfolder-menu");
    if (!open) {
      bmbarOpenFolder = null;
      return;
    }
    open.remove();
    bmbarOpenFolder = null;
    // Give the room back.
    if (typeof syncChromeInsets === "function") syncChromeInsets();
  }

  function bookmarkFolders(items) {
    // Ordered by first appearance so the row is stable between renders
    // rather than reshuffling as counts change.
    const order = [];
    const byTag = new Map();
    for (const item of items) {
      for (const tag of item.tags || []) {
        if (!byTag.has(tag)) {
          byTag.set(tag, []);
          order.push(tag);
        }
        byTag.get(tag).push(item);
      }
    }
    return order.map((tag) => ({ tag, items: byTag.get(tag) }));
  }

  function renderBookmarkBar() {
    const bar = $("bmbar");
    if (!bar) return;
    closeBookmarkFolder();
    bar.textContent = "";
    const folders = bookmarkFolders(bookmarkItems);
    if (!folders.length) {
      // Nothing tagged yet. Say so rather than showing an empty strip that
      // looks broken; the row only exists because the user asked for it.
      const empty = el(
        "span",
        "bmbar-empty",
        i18nText("chrome-js-bmbar-empty", "Tag a bookmark to make a folder"),
      );
      bar.appendChild(empty);
      return;
    }
    for (const folder of folders) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "bmfolder";
      btn.setAttribute("aria-expanded", "false");
      btn.title = folder.items.length + " bookmarks tagged " + folder.tag;
      if (currentUiLocale !== "en") {
        i18nResolve(
          "chrome-js-bmbar-folder-title",
          { count: folder.items.length, tag: folder.tag },
          folder.items.length + " bookmarks tagged " + folder.tag,
        ).then((t) => {
          btn.title = t;
        });
      }
      btn.textContent = folder.tag;
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const wasOpen = bmbarOpenFolder === folder.tag;
        closeBookmarkFolder();
        if (wasOpen) return;
        const menu = document.createElement("div");
        menu.className = "bmfolder-menu";
        for (const item of folder.items) {
          const link = document.createElement("button");
          link.type = "button";
          link.className = "bmfolder-item";
          link.textContent = item.title || item.url;
          link.title = item.url;
          link.addEventListener("click", async () => {
            closeBookmarkFolder();
            try {
              await rb("bookmark_open", { id: item.id });
            } catch (e) {
              toast(friendly(e), true);
            }
          });
          menu.appendChild(link);
        }
        btn.setAttribute("aria-expanded", "true");
        bmbarOpenFolder = folder.tag;
        // Parented to the document, not the bar: the bar is a horizontal
        // scroll container and would clip this away. Anchored under the
        // button it belongs to, nudged left if it would run off the edge.
        document.body.appendChild(menu);
        const barBox = bar.getBoundingClientRect();
        const btnBox = btn.getBoundingClientRect();
        menu.style.top = Math.ceil(barBox.bottom) + 2 + "px";
        const width = menu.getBoundingClientRect().width || 240;
        const maxLeft = Math.max(4, (window.innerWidth || 1000) - width - 8);
        menu.style.left = Math.min(Math.max(4, btnBox.left), maxLeft) + "px";
        // Measured after it is laid out, so the strip grows by what it needs.
        syncChromeInsets();
      });
      bar.appendChild(btn);
    }
  }

  // Anywhere else closes it, the way every other transient menu here behaves.
  document.addEventListener("click", () => closeBookmarkFolder());
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeBookmarkFolder();
  });

  async function refreshBookmarkBar() {
    try {
      const r = await rb("bookmarks_bar_get");
      const bar = $("bmbar");
      if (bar) bar.hidden = !r.shown;
      // Both toggles are dressed from the SAME reply, so opening the Library
      // after flipping this in Theme shows the state that is actually in
      // force rather than whatever the button last said.
      wearBookmarkBar(r.shown);
      if (r.shown) {
        // The bar needs bookmarks to render folders from, and it can be
        // switched on while the Library panel has never been opened.
        if (!bookmarkItems.length) {
          try {
            await reloadBookmarkState();
          } catch (_) {
            /* store closed: the row renders its empty note */
          }
        }
        renderBookmarkBar();
      } else {
        closeBookmarkFolder();
      }
      publishChromeMetric();
    } catch (_) {
      /* leave the row as it is */
    }
  }

  // ---- from the bookmarks draft ----
  async function refreshBookmarks() {
    try {
      await reloadBookmarkState();
      renderBookmarkBar();
      renderFolderGrid();
      renderBookmarksManager();
      updateStar();
    } catch (e) {
      /* store may be closed; keep the last list */
    }
  }

  // ---- from the bookmarks draft ----
  async function refreshDownloads() {
    try {
      const data = await rb("download_list");
      // Store order is insertion order; newest first reads better.
      downloadItems = (data.items || []).slice().reverse();
      // Whether comparing with a contact is possible AT ALL: the public
      // build has no chat transport compiled in, so the control must not
      // appear there rather than appear and fail. Both reads are allowed to
      // fail quietly, which leaves the feature hidden -- the safe direction.
      try {
        const chat = await rb("chat_status");
        downloadCompareAvailable = !!(chat && chat.compiled);
      } catch {
        downloadCompareAvailable = false;
      }
      if (downloadCompareAvailable) {
        try {
          const contacts = await rb("chat_contacts", {});
          chatContacts = (contacts && contacts.items) || [];
        } catch {
          chatContacts = [];
        }
      }
      renderDownloads();
    } catch (e) {
      /* ignore */
    }
  }

  // ---- fuzzy matching, shared by bookmark search and the tab switcher ----
  //
  /// score(query, candidate) -> number | null. null means no match; a
  /// higher number is a better match. Case-insensitive, and safe on
  /// non-ASCII text: both sides are lowercased and scanned by code point
  /// (Array.from), never by UTF-16 half -- a UTF-16 scan can false-match a
  /// query's surrogate halves across two different characters. The
  /// trade-off is documented rather than fixed: casefolds that change the
  /// character count (the German sharp s folding to "ss" is the usual
  /// example) simply do not match, the same limitation the Rust side
  /// accepted.
  ///
  /// The rules, in weight order, each with its reason:
  ///  1. A contiguous substring beats a scattered subsequence: typing
  ///     "wiki" almost always means the word, not w...i...k...i spread
  ///     across a string.
  ///  2. A match starting at a word boundary (the start, or right after a
  ///     space, '/', '.' or '-') beats one mid-word, because those
  ///     boundaries are where a person mentally starts a name.
  ///  3. An earlier first match beats a later one: the identifying part
  ///     of a title or URL sits near the front.
  ///  4. At equal evidence, a shorter candidate beats a longer one: the
  ///     match fills more of it.
  ///
  /// The weights are spaced (1e6, 1e4, one point per character of
  /// position, a fraction of a point per character of length) AND the two
  /// lower-order terms are CLAMPED below the tier above them, so the rule
  /// order holds for every input, not merely realistic ones -- an
  /// unclamped position term would let a 10,000-character prefix drag a
  /// word-start match below a mid-word one. Simple and predictable on
  /// purpose -- no per-character bonuses beyond these four.
  function fuzzyScore(query, candidate) {
    const needle = String(query == null ? "" : query).toLowerCase();
    const haystack = String(candidate == null ? "" : candidate).toLowerCase();
    if (!needle) return 0; // an empty query matches everything, neutrally
    if (!haystack) return null;

    const h = Array.from(haystack);
    const q = Array.from(needle);
    let first = -1;
    let contiguous = false;
    const at = haystack.indexOf(needle);
    if (at >= 0) {
      // Checked before the subsequence scan because the greedy scan below
      // can find a scattered match even when a contiguous one exists later
      // in the string.
      contiguous = true;
      // indexOf answers in UTF-16 units and the scan answers in code
      // points; convert so the two meanings of "position" never mix.
      first = Array.from(haystack.slice(0, at)).length;
    } else {
      // Greedy earliest subsequence: each needle character takes the first
      // position the remaining characters can still follow.
      let qi = 0;
      for (let hi = 0; hi < h.length && qi < q.length; hi++) {
        if (h[hi] === q[qi]) {
          if (qi === 0) first = hi;
          qi++;
        }
      }
      if (qi < q.length) return null;
    }

    const before = first > 0 ? h[first - 1] : "";
    const wordStart =
      first === 0 ||
      before === " " ||
      before === "/" ||
      before === "." ||
      before === "-";
    return (
      (contiguous ? 1000000 : 0) +
      (wordStart ? 10000 : 0) -
      Math.min(first, 9999) -
      Math.min(h.length, 9999) / 10000
    );
  }

  // ---- from the bookmarks draft ----
  /// Fuzzy match over the two things a person actually remembers about a
  /// bookmark -- what it was called and where it went -- plus its tags.
  /// The host is covered by the URL test, so "wikipedia" finds a page
  /// whose title never mentions it. Tags are searched because grouping is
  /// only useful if typing the group name finds the group; they are
  /// already lowercased by the store, and fuzzyScore lowercases anyway.
  /// Returns the best field's score, or null when nothing matches.
  function bookmarkMatchScore(item, needle) {
    const fields = [
      fuzzyScore(needle, String(item.title || "")),
      fuzzyScore(needle, String(item.url || "")),
      Array.isArray(item.tags) ? fuzzyScore(needle, item.tags.join(" ")) : null,
    ];
    let best = null;
    for (const score of fields) {
      if (score !== null && (best === null || score > best)) best = score;
    }
    return best;
  }

  /// Boolean form kept for callers that only need yes/no. The live-query
  /// path in managerVisibleItems uses bookmarkMatchScore directly so it
  /// can rank; everything else should not have to know scores exist.
  function bookmarkMatches(item, needle) {
    if (!needle) return true;
    return bookmarkMatchScore(item, needle) !== null;
  }

  function renderBookmarks() {
    // The flat list this drew was replaced by the manager's own rows. The
    // function survives because several refresh paths still call it; with no
    // #bookmark-list in the markup there is nothing for it to draw.
    const list = $("bookmark-list");
    if (!list) return;
    list.textContent = "";

    // The search box is furniture over an empty list, so it appears only once
    // there is something to search.
    const searchRow = $("bm-search-row");
    if (searchRow) searchRow.hidden = bookmarkItems.length === 0;

    const needle = bookmarkQuery.trim().toLowerCase();
    const shown = bookmarkItems.filter((item) => bookmarkMatches(item, needle));

    // Three distinct states, because collapsing them misinforms: no
    // bookmarks at all, bookmarks that all failed the filter, and a filtered
    // subset. Only the first is "you have none".
    $("bookmark-empty").hidden = bookmarkItems.length > 0;
    const noMatch = $("bookmark-no-match");
    if (noMatch) {
      const filteredToNothing = bookmarkItems.length > 0 && shown.length === 0;
      noMatch.hidden = !filteredToNothing;
      if (filteredToNothing) {
        // textContent, never markup injection: the needle is text the user
        // typed and this is the webview that holds IPC and the vault. (The
        // gate greps for the forbidden property name even inside comments,
        // which is why this sentence does not spell it out.)
        noMatch.textContent =
          'No bookmarks match "' + bookmarkQuery.trim() + '".';
      }
    }
    const count = $("bm-search-count");
    if (count) {
      const filtering = needle.length > 0 && bookmarkItems.length > 0;
      count.hidden = !filtering;
      if (filtering) {
        i18nSet(
          count,
          "chrome-js-bookmarks-search-count",
          { shown: shown.length, total: bookmarkItems.length },
          shown.length + " of " + bookmarkItems.length + " shown",
        );
      }
    }

    for (const item of shown) {
      const li = el("li", "item");
      const head = el("div", "item-head");
      head.appendChild(
        el("span", "item-title", item.title || hostOf(item.url)),
      );
      head.appendChild(el("span", "item-sub", item.url));
      li.appendChild(head);
      {
        const sub = el("div", "item-sub", "");
        if (item.has_digest) {
          const when = fmtTime(item.digest_recorded_at);
          i18nSet(
            sub,
            "chrome-js-bookmarks-snapshot-from",
            { when },
            "Page snapshot from " + when,
          );
        } else {
          sub.textContent = i18nText("chrome-js-bookmarks-snapshot-none", "No page snapshot recorded");
        }
        li.appendChild(sub);
      }
      // Tags, when there are any. One line, textContent like every other
      // field here; the store already lowercased and deduped them.
      if (Array.isArray(item.tags) && item.tags.length) {
        const tags = item.tags.join(", ");
        const tagsRow = el("div", "item-sub", "");
        i18nSet(tagsRow, "chrome-js-bookmarks-tags", { tags }, "Tags: " + tags);
        li.appendChild(tagsRow);
      }

      const row = el("div", "item-row");

      const openBtn = el("button", "small", i18nText("chrome-js-bookmarks-open", "Open"));
      openBtn.type = "button";
      openBtn.addEventListener("click", async () => {
        try {
          await rb("bookmark_open", { id: item.id });
          // The page loads behind the panel; close it so the user sees it.
          if (openPanelName === "library") togglePanelNamed("library");
        } catch (e) {
          toast(friendly(e), true);
        }
      });
      row.appendChild(openBtn);

      // Opens the bookmark, then checks it once the page is there.
      //
      // Checking needs the page's real bytes, and those come from the engine
      // for the page that is actually loaded — there is no way to digest a
      // page without visiting it, and inventing one would mean re-fetching
      // the URL, which asks the server for a SECOND copy and is precisely
      // the behaviour corroboration exists to detect.
      //
      // This button used to call `bookmark_check`, a second implementation
      // whose page-bytes seam was a hardcoded None: it could only ever
      // return an error, and the tooltip said this build cannot read page
      // content — on a build where the integrity panel, on the same page,
      // read it and produced verdicts. One implementation now, and it is the
      // one that works.
      const checkBtn = el("button", "small", i18nText("chrome-js-bookmarks-open-check", "Open and check"));
      checkBtn.type = "button";
      checkBtn.disabled = !digestsReady;
      checkBtn.title = digestsReady
        ? i18nText("chrome-js-bookmarks-check-title", "Open this bookmark and compare the page against its recorded snapshot")
        : i18nText("chrome-js-bookmarks-check-unsupported", "Change tracking needs the page's own bytes, which this platform cannot provide");
      checkBtn.addEventListener("click", async () => {
        try {
          await rb("bookmark_open", { id: item.id });
          if (openPanelName === "library") togglePanelNamed("library");
          // The verdict arrives as a `page_check_result` event, which the
          // integrity panel renders. Requested once the page has loaded:
          // asking before that would digest the previous page.
          pendingBookmarkCheck = item.url || null;
        } catch (e) {
          toast(friendly(e), true);
        }
      });
      row.appendChild(checkBtn);

      const editBtn = el("button", "small", i18nText("chrome-js-creds-edit", "Edit"));
      editBtn.type = "button";
      editBtn.addEventListener("click", () => {
        editingBookmark = item.id;
        $("bookmark-url").value = item.url || "";
        $("bookmark-title").value = item.title || "";
        $("bookmark-tags").value = Array.isArray(item.tags)
          ? item.tags.join(", ")
          : "";
        $("bookmark-error").textContent = "";
        $("bookmark-form").hidden = false;
        $("bookmark-url").focus();
      });
      row.appendChild(editBtn);

      const delBtn = el("button", "small danger", i18nText("chrome-js-confirm-default-label", "Delete"));
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        if (
          !(await askConfirm(
            "Delete bookmark " + (item.title || item.url) + "?",
          ))
        )
          return;
        try {
          await rb("bookmark_delete", { id: item.id });
          if (editingBookmark === item.id) resetBookmarkForm();
          await refreshBookmarks();
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(delBtn);

      li.appendChild(row);
      list.appendChild(li);
    }
  }

  // ---- from the bookmarks draft ----
  function resetBookmarkForm() {
    editingBookmark = null;
    $("bookmark-form").hidden = true;
    $("bookmark-url").value = "";
    $("bookmark-title").value = "";
    $("bookmark-tags").value = "";
    $("bookmark-error").textContent = "";
  }

  // The edit form had no submit handler, which made it the most convincing
  // of the dead forms: Edit opened it and focused the URL field, so it looked
  // alive right up until "Save changes" did nothing -- no write, no error.
  if ($("bookmark-form"))
    $("bookmark-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const err = $("bookmark-error");
      err.textContent = "";
      if (!editingBookmark) {
        // Nothing selected means the form was opened by something other than an
        // Edit button; refusing beats writing to a guessed id.
        resetBookmarkForm();
        return;
      }
      const url = $("bookmark-url").value.trim();
      if (!url) {
        err.textContent = i18nText("chrome-js-bookmarkform-required", "Address is required.");
        return;
      }
      try {
        await rb("bookmark_update", {
          id: editingBookmark,
          url,
          title: $("bookmark-title").value.trim(),
        });
        // Separate call on purpose: bookmark_update drops a recorded digest
        // when the URL changes, and tags must never be able to cause that.
        await rb("bookmark_tags_set", {
          id: editingBookmark,
          tags: $("bookmark-tags")
            .value.split(",")
            .map((t) => t.trim())
            .filter((t) => t.length > 0),
        });
        resetBookmarkForm();
        await refreshBookmarks();
      } catch (e) {
        err.textContent = friendly(e);
      }
    });
  if ($("bookmark-cancel"))
    $("bookmark-cancel").addEventListener("click", () => {
      resetBookmarkForm();
    });

  // ---- local OCR ----------------------------------------------------------
  //
  // Two features, one engine, both entirely on this machine. Scans are
  // asynchronous: `ocr_scan` returns a token and the answer arrives as an
  // `ocr_result` event, so a scan cannot be awaited inline.
  //
  // Every pending scan is keyed by its token. A result whose token is not in
  // the map is DROPPED -- that is a scan the user moved on from, and applying
  // it would overwrite whatever they are looking at now.
  const ocrPending = new Map();
  let ocrAvailable = false;

  window.__rb_ocr = (data) => {
    const slot = ocrPending.get(data.token);
    if (!slot) return;
    ocrPending.delete(data.token);
    slot(data);
  };

  async function startScan(kind, onDone, onError) {
    let picked;
    try {
      picked = await rb("file_pick_open", { title: i18nText("chrome-js-ocr-pick-title", "Choose an image") });
    } catch (e) {
      // A refusal that arrives AFTER the UI precheck (the licence changed in
      // between) must explain itself as a Premium refusal, not as the tab
      // search's sentence that the shared error table maps the code to.
      onError(e && e.message === "premium_required" ? premiumLockNote(premiumState) : friendly(e));
      return;
    }
    // Cancel is an answer, not a failure: leave everything exactly as it was.
    if (!picked || !picked.path) return;
    try {
      // The TOKEN, not the path. Rust mints it when the user confirms the
      // dialog and consumes it here, so the file being read is the file that
      // was picked -- not whatever string this side happens to send.
      const r = await rb("ocr_scan", { token: picked.token, kind });
      ocrPending.set(r.token, (data) => {
        if (!data.ok) onError(friendly(new Error(data.error)));
        else onDone(data);
      });
    } catch (e) {
      // A refusal that arrives AFTER the UI precheck (the licence changed in
      // between) must explain itself as a Premium refusal, not as the tab
      // search's sentence that the shared error table maps the code to.
      onError(e && e.message === "premium_required" ? premiumLockNote(premiumState) : friendly(e));
    }
  }

  // Idea 1: fill the recovery field from a photograph of the written key.
  //
  // It NEVER submits. OCR cannot distinguish b from 6 -- both are valid hex
  // and no amount of cleverness fixes that without a checksum in the key
  // format -- so the user compares against their paper copy and presses
  // unlock themselves. Measured on real models: 63 of 64 characters recover.
  $("recovery-scan").addEventListener("click", () => {
    const err = $("recovery-error");
    const note = $("recovery-scan-note");
    err.textContent = "";
    note.hidden = false;
    note.textContent = i18nText("chrome-js-ocr-recovery-reading", "Reading the image...");
    startScan(
      "recovery",
      (data) => {
        if (!data.key) {
          note.textContent =
            i18nText("chrome-js-ocr-recovery-none", "No recovery key found in that image. A photo of the key wrapped over several lines reads best.");
          return;
        }
        $("recovery-input").value = data.key;
        note.textContent =
          i18nText("chrome-js-ocr-recovery-filled", "Filled in from the image. Check it against your written copy before unlocking, because 6 and b look alike to a scanner.");
      },
      (msg) => {
        note.hidden = true;
        err.textContent = msg;
      },
    );
  });

  // Idea 2: say what is legible in an image before it is shared.
  // Collapsed again for every new scan: text left over from the previous
  // image, under a fresh verdict, is the worst thing this panel could show.
  function leakTextReset() {
    $("leakcheck-readwrap").hidden = true;
    $("leakcheck-text").hidden = true;
    $("leakcheck-text").textContent = "";
    $("leakcheck-showtext").textContent = i18nText("chrome-js-leakcheck-show-text", "Show what it read");
  }

  $("leakcheck-showtext").addEventListener("click", () => {
    const pre = $("leakcheck-text");
    pre.hidden = !pre.hidden;
    $("leakcheck-showtext").textContent = pre.hidden
      ? i18nText("chrome-js-leakcheck-show-text", "Show what it read")
      : i18nText("chrome-js-leakcheck-hide-text", "Hide what it read");
    syncChromeInsets();
  });

  $("leakcheck-pick").addEventListener("click", async () => {
    // Premium since launch; the recovery-key scan beside it is not.
    await refreshPremium();
    if (premiumBlocked()) return;
    const err = $("leakcheck-error");
    const status = $("leakcheck-status");
    const list = $("leakcheck-list");
    err.textContent = "";
    list.replaceChildren();
    leakTextReset();
    status.textContent = i18nText("chrome-js-ocr-recovery-reading", "Reading the image...");
    startScan(
      "leaks",
      (data) => {
        const findings = data.findings || [];
        // THE EVIDENCE, whatever the verdict. Offered on a clean result too
        // -- that is the case where "how does it know?" gets asked, and the
        // only honest answer is to show the reader what it had to work with.
        if (data.text) {
          $("leakcheck-text").textContent = data.text;
          $("leakcheck-readwrap").hidden = false;
        }
        if (!findings.length) {
          // "Nothing found" and "no text at all" are different answers and
          // the difference matters to someone about to post a screenshot.
          if (data.regions) {
            i18nSet(status, "chrome-leakcheck-clean", { count: data.regions },
              "No listed clues found in " + data.regions + " line(s).");
          } else {
            status.textContent =
              i18nText("chrome-js-leakcheck-no-text", "No readable text found in that image.");
          }
          return;
        }
        i18nSet(status, "chrome-leakcheck-found", { count: findings.length },
          findings.length + " item(s) to check before sharing:");
        for (const f of findings) {
          const li = el("li", "entry");
          li.appendChild(el("strong", null, LEAK_TEXT[f.kind] || f.kind));
          li.appendChild(el("span", "muted", " " + f.text));
          list.appendChild(li);
        }
      },
      (msg) => {
        status.textContent = "";
        err.textContent = msg;
      },
    );
  });

  // ---- read text on this page (Premium region mode) -----------------------
  //
  // The panel asks Rust to capture the page into memory, shows the capture
  // as an image served over the chrome protocol, and lets the user drag a
  // rectangle to read. The preview may be zoomed and scrolled, but the rect
  // sent to Rust always names pixels in the capture PNG itself.
  //
  // premium_required is a STATE the panel shows (#region-premium stays up),
  // never only a toast -- same rule as the findtabs and switcher notes.

  const REGION_OPEN_PX = 500;
  const REGION_ZOOM_STEPS = [1, 1.25, 1.5, 2, 3, 4];
  // Source dimensions name the native PNG Rust crops for OCR; preview
  // dimensions name the bounded PNG the chrome is allowed to decode.
  let regionCapture = null; // {token, w, h, previewW, previewH}
  let regionZoom = 1; // multiplier on the width-fitted preview
  // Text Capture and Deep Recall start from the same kind of page picture,
  // so they share one persisted scope and one vocabulary. The event still
  // decides the finished caption: a requested full page may honestly arrive
  // as the viewport on an old WebView2 runtime.
  const CAPTURE_SCOPES = ["full_page", "viewport"];
  const CAPTURE_SCOPE_MIRRORS = [
    { full_page: "region-scope-full", viewport: "region-scope-viewport" },
    { full_page: "recall-scope-full", viewport: "recall-scope-viewport" },
  ];
  const VIEWPORT_PICTURE_SENTENCE =
    "The picture is the part that was on screen.";
  const FULL_PAGE_PICTURE_SENTENCE = "The picture is complete.";
  const VIEWPORT_PREVIEW_SENTENCE =
    VIEWPORT_PICTURE_SENTENCE +
    " Nothing below it was captured, so there is nothing more to scroll to -- a scrollbar you see inside the picture is part of the page it shows.";
  let captureScopeChoice = "full_page";

  function markCaptureScope(scope) {
    captureScopeChoice = CAPTURE_SCOPES.includes(scope) ? scope : "full_page";
    for (const mirror of CAPTURE_SCOPE_MIRRORS) {
      for (const name of CAPTURE_SCOPES) {
        const chosen = name === captureScopeChoice;
        $(mirror[name]).classList.toggle("active", chosen);
        $(mirror[name]).setAttribute("aria-pressed", chosen ? "true" : "false");
      }
    }
  }

  async function refreshCaptureScope() {
    try {
      const r = await rb("capture_scope_get");
      markCaptureScope(r && r.scope);
    } catch (_) {
      // A failed read leaves the last good selection on screen. On first
      // load that is the compatibility default: full page.
      markCaptureScope(captureScopeChoice);
    }
    return captureScopeChoice;
  }

  for (const mirror of CAPTURE_SCOPE_MIRRORS) {
    for (const name of CAPTURE_SCOPES) {
      $(mirror[name]).addEventListener("click", async () => {
        try {
          const r = await rb("capture_scope_set", { scope: name });
          markCaptureScope(r && r.scope);
        } catch (e) {
          toast(friendly(e), true);
        }
      });
    }
  }
  markCaptureScope(captureScopeChoice);

  let regionDrag = null; // selection or pan gesture, in viewport CSS pixels

  // THE COORDINATE-SPACE BOUNDARY. `rect` and `viewport` are CSS pixels in
  // the visible stage; `pan` is CSS pixels scrolled through the RENDERED,
  // BOUNDED preview; `previewToSource` is native-source pixels per preview
  // pixel on each axis; `source` is the native capture PNG's pixel bounds.
  // At zoom 1 the preview is fitted to viewport width. Only this pure
  // function crosses from view space to SOURCE space, and its result is what
  // ocr_region_scan uses to crop the original PNG bytes -- never pixels from
  // the rendered preview.
  function regionViewToSource({
    zoom,
    pan,
    viewport,
    source,
    previewToSource,
    rect,
  }) {
    const vw = Number(viewport.width);
    const vh = Number(viewport.height);
    const sw = Number(source.width);
    const sh = Number(source.height);
    const sx = Number(previewToSource.x);
    const sy = Number(previewToSource.y);
    const z = Number(zoom);
    if (!(vw > 0 && vh > 0 && sw > 0 && sh > 0 && sx > 0 && sy > 0 && z > 0)) {
      return { x: 0, y: 0, w: 0, h: 0 };
    }
    const previewWidth = sw / sx;
    const previewHeight = sh / sy;
    const previewScale = (vw / previewWidth) * z; // CSS px per preview pixel
    const sourceScaleX = previewScale / sx; // CSS px per native source pixel
    const sourceScaleY = previewScale / sy;
    const rx0 = Math.min(Number(rect.x), Number(rect.x) + Number(rect.w));
    const ry0 = Math.min(Number(rect.y), Number(rect.y) + Number(rect.h));
    const rx1 = Math.max(Number(rect.x), Number(rect.x) + Number(rect.w));
    const ry1 = Math.max(Number(rect.y), Number(rect.y) + Number(rect.h));
    const px = Math.max(0, Number(pan.x) || 0);
    const py = Math.max(0, Number(pan.y) || 0);
    const clamp = (n, lo, hi) => Math.max(lo, Math.min(n, hi));
    const left = clamp(px + clamp(rx0, 0, vw), 0, previewWidth * previewScale);
    const top = clamp(py + clamp(ry0, 0, vh), 0, previewHeight * previewScale);
    const right = clamp(px + clamp(rx1, 0, vw), 0, previewWidth * previewScale);
    const bottom = clamp(
      py + clamp(ry1, 0, vh),
      0,
      previewHeight * previewScale,
    );
    const x = clamp(Math.floor(left / sourceScaleX), 0, sw - 1);
    const y = clamp(Math.floor(top / sourceScaleY), 0, sh - 1);
    const x2 = clamp(Math.ceil(right / sourceScaleX), x, sw);
    const y2 = clamp(Math.ceil(bottom / sourceScaleY), y, sh);
    return { x, y, w: x2 - x, h: y2 - y };
  }

  // Deliberate small test seam: the gate calls the pure mapper without
  // manufacturing browser layout or a wheel event.
  window.__rb_region_view_to_source = regionViewToSource;

  function regionZoomSet(next, anchor) {
    const stage = $("region-stage");
    const old = regionZoom;
    regionZoom = Math.max(
      REGION_ZOOM_STEPS[0],
      Math.min(next, REGION_ZOOM_STEPS[REGION_ZOOM_STEPS.length - 1]),
    );
    const ax = anchor ? anchor.x : (stage.clientWidth || 0) / 2;
    const ay = anchor ? anchor.y : (stage.clientHeight || 0) / 2;
    const oldLeft = Number(stage.scrollLeft) || 0;
    const oldTop = Number(stage.scrollTop) || 0;
    $("region-img").style.width = Math.round(regionZoom * 100) + "%";
    $("region-zoom-level").textContent = Math.round(regionZoom * 100) + "%";
    // Keep the source point under the pointer (or viewport centre) still.
    const change = regionZoom / old;
    stage.scrollLeft = (oldLeft + ax) * change - ax;
    stage.scrollTop = (oldTop + ay) * change - ay;
  }

  function regionZoomStep(dir, anchor) {
    let at = REGION_ZOOM_STEPS.indexOf(regionZoom);
    if (at < 0) at = 0;
    regionZoomSet(
      REGION_ZOOM_STEPS[
        Math.max(0, Math.min(at + dir, REGION_ZOOM_STEPS.length - 1))
      ],
      anchor,
    );
  }

  function regionReset() {
    regionCapture = null;
    regionDrag = null;
    $("region-zoom-controls").hidden = true;
    $("region-stage").hidden = true;
    $("region-selbox").hidden = true;
    $("region-result-wrap").hidden = true;
    $("region-scope").hidden = true;
    $("region-result").textContent = "";
    $("region-status").textContent = "";
    regionZoomSet(1);
    $("region-stage").scrollLeft = 0;
    $("region-stage").scrollTop = 0;
    // Dropping the src releases the decoded image; the buffer itself is
    // freed by ocr_region_close when the panel closes.
    $("region-img").removeAttribute("src");
  }

  async function regionStart() {
    regionReset();
    // Wait for Rust's persisted answer before asking it to capture. This is
    // what makes a remembered Keep workflow apply on the first capture after
    // restart rather than only after the user touches the choice again.
    await refreshCaptureScope();
    // Re-read the licence at the moment of use rather than trusting the
    // cached value the dimming is drawn from: the vault may have auto-locked
    // since the toolbar last refreshed, and acting on a stale "unlocked"
    // would fire a request Rust is about to refuse anyway.
    await refreshPremium();
    // The panel still carries its own standing note for the refusal that
    // comes back from Rust; this is the earlier, quieter stop, so a locked
    // control does not flash a capture attempt first.
    if (premiumBlocked()) {
      $("region-premium").hidden = false;
      syncChromeInsets();
      return;
    }
    $("region-premium").hidden = true;
    $("region-status").textContent = i18nText("chrome-js-region-capturing", "Capturing the page...");
    try {
      await rb("ocr_region_capture");
      // The outcome arrives as region_capture_ready; the reply only
      // confirms the engine was asked.
    } catch (e) {
      $("region-status").textContent = "";
      if (e && e.message === "premium_required") {
        $("region-premium").hidden = false;
        syncChromeInsets();
      } else {
        $("region-status").textContent = friendly(e);
      }
    }
  }

  function onRegionCaptureReady(data) {
    if (openPanelName !== "region") {
      // The panel closed while the engine was capturing; the buffer will be
      // released by the close arm, and painting into a closed panel would
      // only confuse the next open.
      return;
    }
    if (!data.ok) {
      $("region-status").textContent =
        ERROR_TEXT[data.error] || i18nText("chrome-js-region-capture-failed", "The capture failed.");
      return;
    }
    regionCapture = {
      token: data.token,
      w: data.w,
      h: data.h,
      previewW: data.preview_w,
      previewH: data.preview_h,
    };
    // Relative URL, so the platform-specific chrome origin resolves it on
    // both engines. Cache-safe: every capture has a fresh token. Set as an
    // ATTRIBUTE so setting and removing are the same vocabulary.
    $("region-img").setAttribute(
      "src",
      "/region-capture/" + data.token + ".png",
    );
    $("region-stage").hidden = false;
    $("region-zoom-controls").hidden = false;
    $("region-scope").hidden = false;
    const scopeSentence =
      data.scope === "visible area"
        ? VIEWPORT_PICTURE_SENTENCE
        : data.scope === "full page"
          ? FULL_PAGE_PICTURE_SENTENCE
          : "";
    $("region-scope").textContent =
      scopeSentence +
      (scopeSentence ? " " : "") +
      i18nText("chrome-js-region-drag-hint", "Zoom in, then drag around the text. Smaller selections read small text better. Shift-drag pans.");
    $("region-status").textContent = "";
    syncChromeInsets();
  }

  // The drag state machine. A plain left drag always selects. While zoomed,
  // Shift+left-drag (or a middle-button drag) pans; scrollbars remain an
  // ordinary second way to pan. A stray click is ignored rather than scanned.
  const regionImg = $("region-img");
  const regionStage = $("region-stage");
  const regionSelbox = $("region-selbox");

  function regionViewPoint(ev) {
    const box = regionStage.getBoundingClientRect();
    const x = Number.isFinite(ev.clientX)
      ? ev.clientX - box.left - (regionStage.clientLeft || 0)
      : ev.offsetX;
    const y = Number.isFinite(ev.clientY)
      ? ev.clientY - box.top - (regionStage.clientTop || 0)
      : ev.offsetY;
    return {
      x: Math.max(0, Math.min(x, regionStage.clientWidth)),
      y: Math.max(0, Math.min(y, regionStage.clientHeight)),
    };
  }

  function regionDisplayedRect(ev) {
    const p = regionViewPoint(ev);
    const x1 = p.x;
    const y1 = p.y;
    const x = Math.min(regionDrag.x0, x1);
    const y = Math.min(regionDrag.y0, y1);
    return {
      x,
      y,
      w: Math.abs(x1 - regionDrag.x0),
      h: Math.abs(y1 - regionDrag.y0),
    };
  }

  regionStage.addEventListener("pointerdown", (ev) => {
    if (!regionCapture) return;
    const p = regionViewPoint(ev);
    const wantsPan = regionZoom > 1 && (ev.button === 1 || ev.shiftKey);
    if (wantsPan) {
      regionDrag = {
        kind: "pan",
        x0: p.x,
        y0: p.y,
        left: regionStage.scrollLeft,
        top: regionStage.scrollTop,
      };
      regionStage.classList.add("region-panning");
    } else {
      if (ev.button !== 0) return;
      regionDrag = { kind: "select", x0: p.x, y0: p.y };
      regionSelbox.hidden = false;
    }
    regionStage.setPointerCapture(ev.pointerId);
    ev.preventDefault();
  });
  regionStage.addEventListener("pointermove", (ev) => {
    if (!regionDrag) return;
    if (regionDrag.kind === "pan") {
      const p = regionViewPoint(ev);
      regionStage.scrollLeft = regionDrag.left - (p.x - regionDrag.x0);
      regionStage.scrollTop = regionDrag.top - (p.y - regionDrag.y0);
      return;
    }
    const r = regionDisplayedRect(ev);
    // The box lives in scroll CONTENT coordinates; r is viewport-relative.
    regionSelbox.style.left = regionStage.scrollLeft + r.x + "px";
    regionSelbox.style.top = regionStage.scrollTop + r.y + "px";
    regionSelbox.style.width = r.w + "px";
    regionSelbox.style.height = r.h + "px";
  });
  regionStage.addEventListener("pointerup", async (ev) => {
    if (!regionDrag || !regionCapture) return;
    if (regionDrag.kind === "pan") {
      regionDrag = null;
      regionStage.classList.remove("region-panning");
      return;
    }
    const r = regionDisplayedRect(ev);
    regionDrag = null;
    regionSelbox.hidden = true;
    // A sub-3px drag is a click, and a click is not a selection.
    if (r.w < 3 || r.h < 3) return;
    // The zoom/pan-aware pure mapper, which has its own tests. The older
    // one-ratio-per-axis arithmetic this replaces could not express a zoomed
    // or panned view at all.
    const { x, y, w, h } = regionViewToSource({
      zoom: regionZoom,
      pan: { x: regionStage.scrollLeft, y: regionStage.scrollTop },
      viewport: {
        width: regionStage.clientWidth,
        height: regionStage.clientHeight,
      },
      source: { width: regionCapture.w, height: regionCapture.h },
      // THE LOSSY-PREVIEW BOUNDARY. Selection geometry crosses back to
      // native pixels here; Rust still crops regionCapture's source PNG.
      previewToSource: {
        x: regionCapture.w / regionCapture.previewW,
        y: regionCapture.h / regionCapture.previewH,
      },
      rect: r,
    });
    if (w < 1 || h < 1) return;
    $("region-status").textContent = i18nText("chrome-js-region-reading", "Reading your selection...");
    try {
      const reply = await rb("ocr_region_scan", {
        capture: regionCapture.token,
        x,
        y,
        w,
        h,
      });
      ocrPending.set(reply.token, (data) => {
        if (!data.ok) {
          $("region-status").textContent =
            ERROR_TEXT[data.error] || i18nText("chrome-js-region-read-failed", "Could not read that selection.");
          return;
        }
        if (!data.text || !data.text.trim()) {
          $("region-status").textContent =
            i18nText("chrome-js-region-no-text", "No readable text in that selection. Try a larger area.");
          return;
        }
        $("region-status").textContent = "";
        $("region-result").textContent = data.text;
        $("region-result-wrap").hidden = false;
        syncChromeInsets();
      });
    } catch (e) {
      $("region-status").textContent = "";
      if (e && e.message === "premium_required") {
        $("region-premium").hidden = false;
        syncChromeInsets();
      } else {
        $("region-status").textContent = friendly(e);
      }
    }
  });

  regionStage.addEventListener("pointercancel", () => {
    regionDrag = null;
    regionSelbox.hidden = true;
    regionStage.classList.remove("region-panning");
  });
  regionStage.addEventListener(
    "wheel",
    (ev) => {
      if (!regionCapture) return;
      ev.preventDefault();
      regionZoomStep(ev.deltaY < 0 ? 1 : -1, regionViewPoint(ev));
    },
    { passive: false },
  );
  $("region-zoom-in").addEventListener("click", () => regionZoomStep(1));
  $("region-zoom-out").addEventListener("click", () => regionZoomStep(-1));

  $("region-copy").addEventListener("click", async () => {
    const text = $("region-result").textContent;
    try {
      await navigator.clipboard.writeText(text);
      $("region-status").textContent = i18nText("chrome-js-region-copied", "Copied.");
    } catch {
      // Select-and-copy still works on the visible text; say so instead of
      // failing silently.
      $("region-status").textContent =
        i18nText("chrome-js-region-clipboard-unavailable", "Clipboard is unavailable. Select the text above and copy it directly.");
    }
  });
  $("region-again").addEventListener("click", regionStart);
  $("region-capture").addEventListener("click", regionStart);

  registerPanel("region", {
    el: $("region-panel"),
    button: $("btn-ocr-region"),
    heightPx: REGION_OPEN_PX,
    onOpen: () => {
      regionReset();
      void refreshCaptureScope();
      $("region-premium").hidden = true;
      void refreshPremium().then(() => {
        const blocked = premiumBlocked();
        $("region-premium").hidden = !blocked;
        if (blocked) syncChromeInsets();
      });
    },
    onClose: () => {
      regionReset();
      // Releases the in-memory capture. Fire-and-forget: failing to free
      // is not something the user can act on.
      rb("ocr_region_close").catch(() => {});
    },
  });

  // ---- Deep Recall --------------------------------------------------------
  //
  // Save a page as a picture plus the text read off it; find it later by a
  // word. Two commands do the work and both are gated; deleting is not,
  // because removing your own data must never wait on a licence.
  //
  // The list shows either EVERYTHING saved or the answer to a search, never
  // a silent mixture: an empty query lists, a query searches, and the two
  // empty states say different things.

  let recallSearching = false;
  // The Rust side has one decrypted slot, and this id is the chrome half of
  // the same invariant. It lets delete distinguish the viewed row from any
  // other row without guessing from the preview's current DOM position.
  let recallPreviewRecordId = null;
  // One viewer node and one Rust slot serve BOTH Deep Recall and Library
  // snapshots. The owner tells list rebuilds which panel is responsible for
  // closing it before detaching rows; it is not a second cache key.
  let recallPreviewOwner = null; // "archive" | "snapshot" | null

  function recallPreviewPark() {
    // The preview starts here in the static markup. Returning the SAME node
    // before a list rebuild keeps it attached and keeps all zoom, wheel and
    // close listeners that were installed once at startup.
    $("recall-panel").insertBefore($("recall-preview"), $("recall-query"));
  }

  function recallPreviewPlaceAfter(li) {
    const list = li.parentNode;
    const rows = Array.from(list.children);
    const after = rows[rows.indexOf(li) + 1] || null;
    list.insertBefore($("recall-preview"), after);
  }

  async function openStoredPicture(li, owner, stageCommand, item, onError) {
    // Clear and retire the old token before asking Rust to decrypt the next
    // record. Both record kinds therefore share the exact one-slot custody
    // discipline, with no instant at which two pictures are staged.
    await recallPreviewClose();
    recallPreviewPlaceAfter(li);
    try {
      const r = await rb(stageCommand, { id: item.id });
      $("recall-preview-img").setAttribute(
        "src",
        "/archive-picture/" + r.token + ".png",
      );
      recallPreviewRecordId = item.id;
      recallPreviewOwner = owner;
      const scope = $("recall-preview-scope");
      const viewport = (item.scope || item.picture_scope) === "visible area";
      scope.textContent = viewport ? VIEWPORT_PREVIEW_SENTENCE : "";
      scope.hidden = !viewport;
      $("recall-preview").hidden = false;
      if (onError) onError("");
      syncChromeInsets();
    } catch (e) {
      await recallPreviewClose();
      if (onError) onError(friendly(e));
    }
  }

  function recallRow(item, snippets) {
    const li = el("li", "item");
    const head = el("div", "item-head");
    head.appendChild(el("span", "item-title", item.title || item.url));
    head.appendChild(
      el(
        "span",
        "item-sub",
        fmtTime(item.created_at) + " · " + hostOf(item.url),
      ),
    );
    li.appendChild(head);

    if (snippets && snippets.length) {
      for (const snippet of snippets.slice(0, 3)) {
        // Composed from text nodes, never markup: the match is bolded by
        // splitting the string, the same way the cross-tab rows do it.
        const line = el("div", "item-sub");
        line.appendChild(
          document.createTextNode(
            (snippet.cut_start ? "..." : "") +
              snippet.text.slice(0, snippet.match_start),
          ),
        );
        const hit = el(
          "strong",
          null,
          snippet.text.slice(snippet.match_start, snippet.match_end),
        );
        line.appendChild(hit);
        line.appendChild(
          document.createTextNode(
            snippet.text.slice(snippet.match_end) +
              (snippet.cut_end ? "..." : ""),
          ),
        );
        li.appendChild(line);
      }
    } else if (item.words === 0) {
      li.appendChild(
        el(
          "div",
          "item-sub",
          i18nText("chrome-js-recall-row-no-text", "No text was read. Find by title or address."),
        ),
      );
    }

    const row = el("div", "item-row");
    if (item.has_picture) {
      // The saved screenshot, finally reachable. archive_save had stored it
      // encrypted since the feature landed, and the panel listed it with
      // has_picture:true while offering no way to look -- reported from the
      // panel itself: "Where am I supposed to find the screenshots?" The
      // stage arm decrypts ONE record into a single slot; the token URL is
      // served by the chrome protocol, so no image bytes ride the IPC.
      const view = el("button", "small", i18nText("chrome-js-recall-view", "View"));
      view.type = "button";
      view.addEventListener("click", async () => {
        await openStoredPicture(
          li,
          "archive",
          "archive_picture_stage",
          item,
          (message) => {
            $("recall-status").textContent = message;
          },
        );
      });
      row.appendChild(view);
    }
    const del = el("button", "small", i18nText("chrome-js-confirm-default-label", "Delete"));
    del.type = "button";
    del.addEventListener("click", async () => {
      if (
        !(await askConfirm(
          i18nText("chrome-js-recall-delete-confirm", "Delete this saved page and its picture? This cannot be undone."),
        ))
      ) {
        return;
      }
      try {
        await rb("archive_delete", { id: item.id });
        if (recallPreviewRecordId === item.id) {
          // Rust has already cleared this record's slot; the close also
          // drops the decoded image and returns the preview to its home.
          await recallPreviewClose();
        }
        // Do not rebuild the list here. In particular, deleting some OTHER
        // row must not close or move the inline preview the reader is using.
        // The command succeeded, so removing this exact row is authoritative.
        li.parentNode.removeChild(li);
        const left = Array.from($("recall-list").children).filter(
          (child) => child !== $("recall-preview"),
        ).length;
        $("recall-empty").hidden = recallSearching || left > 0;
        $("recall-none").hidden = !recallSearching || left > 0;
        syncChromeInsets();
      } catch (e) {
        $("recall-status").textContent = friendly(e);
      }
    });
    row.appendChild(del);
    li.appendChild(row);
    return li;
  }

  // Closes the preview and releases the decrypted bytes on the Rust side.
  // Blanking src first drops the chrome's reference; the clear wipes the
  // slot, after which the old token URL is a 404 by design. The returned
  // promise lets View enforce close-then-stage; other close paths may ignore
  // it because failure to free is not something the user can act on.
  function recallPreviewClose() {
    const img = $("recall-preview-img");
    img.removeAttribute("src");
    // Back to Fit for the next picture: a reader who left one zoomed in
    // should not have the next one open mid-page at some arbitrary level.
    recallZoomSet(0);
    $("recall-preview").hidden = true;
    $("recall-preview-scope").textContent = "";
    $("recall-preview-scope").hidden = true;
    recallPreviewRecordId = null;
    recallPreviewOwner = null;
    recallPreviewPark();
    return rb("archive_picture_clear").catch(() => {});
  }

  // REAL ZOOM, replacing the two-state Fit/Actual toggle that shipped first.
  // "Actual size" is a developer's word for it and gives the reader exactly
  // two choices, neither of which is "a bit bigger" -- which is what someone
  // reading a saved page actually wants.
  //
  // 0 means FIT: the picture is width:100% of the stage and follows it on
  // resize. Any other value is a multiplier on the picture's NATURAL width,
  // so 1 is genuinely one image pixel per CSS pixel and the reader can go
  // either side of it. The stage scrolls both axes at every level.
  const RECALL_ZOOM_STEPS = [0.25, 0.4, 0.55, 0.75, 1, 1.5, 2, 3, 4];
  let recallZoom = 0;

  function recallZoomSet(level) {
    recallZoom = level;
    const wrap = $("recall-preview");
    const img = $("recall-preview-img");
    if (!level) {
      wrap.classList.remove("zoomed");
      img.style.width = "";
      $("recall-preview-level").textContent = i18nText("chrome-js-recall-zoom-fit", "Fit");
      return;
    }
    // NOT YET LOADED IS NOT ZOOMABLE, and it must not LOOK zoomed either.
    // naturalWidth is 0 until the picture arrives, so the width below would
    // resolve to "" and leave the image at fit size while the readout said
    // 200% -- a control that reports a change it did not make. The level is
    // remembered and applied by the load handler instead.
    const natural = img.naturalWidth || 0;
    if (!natural) {
      wrap.classList.remove("zoomed");
      img.style.width = "";
      $("recall-preview-level").textContent = i18nText("chrome-js-recall-zoom-fit", "Fit");
      return;
    }
    wrap.classList.add("zoomed");
    // Against NATURAL width, not the stage's: the number then means what it
    // says whatever size the panel happens to be.
    img.style.width = Math.round(natural * level) + "px";
    $("recall-preview-level").textContent = Math.round(level * 100) + "%";
  }

  // Keeps the point under the viewport's centre under it after a zoom.
  // Without this every step throws the reader back to a different part of the
  // page and they have to find their place again.
  function recallZoomStep(dir) {
    const stage = $("recall-preview-stage");
    const img = $("recall-preview-img");
    const before = img.clientWidth || 1;
    // Where the centre of the viewport sits within the picture, 0..1.
    const fx = (stage.scrollLeft + stage.clientWidth / 2) / Math.max(before, 1);
    const fy =
      (stage.scrollTop + stage.clientHeight / 2) /
      Math.max(img.clientHeight || 1, 1);

    // Fit is the entry point: stepping up from it starts at whichever ladder
    // rung is closest to what the reader is already seeing.
    let idx;
    if (!recallZoom) {
      const natural = img.naturalWidth || before;
      const current = before / Math.max(natural, 1);
      idx = 0;
      for (let i = 0; i < RECALL_ZOOM_STEPS.length; i += 1) {
        if (RECALL_ZOOM_STEPS[i] <= current) idx = i;
      }
    } else {
      idx = RECALL_ZOOM_STEPS.indexOf(recallZoom);
      if (idx < 0) idx = 0;
    }
    const next = idx + dir;
    // Stepping below the first rung returns to Fit rather than stopping: Fit
    // is the smallest useful view and the reader gets back to it by zooming
    // out, not by hunting for a separate button.
    if (next < 0) {
      recallZoomSet(0);
      return;
    }
    recallZoomSet(
      RECALL_ZOOM_STEPS[Math.min(next, RECALL_ZOOM_STEPS.length - 1)],
    );

    const after = img.clientWidth || 1;
    stage.scrollLeft = fx * after - stage.clientWidth / 2;
    stage.scrollTop = fy * (img.clientHeight || 1) - stage.clientHeight / 2;
  }

  // Re-apply once the picture has dimensions: a click that arrived early is
  // honoured rather than dropped, and a fresh picture always opens at Fit.
  $("recall-preview-img").addEventListener("load", () => {
    recallZoomSet(recallZoom);
  });

  $("recall-preview-in").addEventListener("click", () => recallZoomStep(1));
  $("recall-preview-out").addEventListener("click", () => recallZoomStep(-1));
  $("recall-preview-fit").addEventListener("click", () => recallZoomSet(0));

  // Ctrl+wheel over the picture. The KEYBOARD equivalents are deliberately
  // absent: connect_shortcuts resolves Ctrl+= / Ctrl+- / Ctrl+0 as global
  // accelerators and marks them handled, so those keydowns never arrive in
  // this document on Windows and a listener for them would work on Linux
  // only -- a control that exists on one platform is worse than one that
  // exists nowhere. The buttons are the answer on both.
  $("recall-preview-stage").addEventListener(
    "wheel",
    (ev) => {
      if (!ev.ctrlKey) return;
      ev.preventDefault();
      recallZoomStep(ev.deltaY < 0 ? 1 : -1);
    },
    { passive: false },
  );

  function recallRender(items, searching) {
    const list = $("recall-list");
    // Search and refresh deliberately close an open preview. Parking first
    // means clearing the list can never silently detach the one preview node.
    // Delete is the exception above: it removes one known row without a
    // rebuild, so deleting an unviewed row leaves the preview untouched.
    if (recallPreviewRecordId !== null) recallPreviewClose();
    else recallPreviewPark();
    list.textContent = "";
    $("recall-empty").hidden = searching || items.length > 0;
    $("recall-none").hidden = !searching || items.length > 0;
    for (const item of items) {
      list.appendChild(recallRow(item, item.snippets));
    }
    syncChromeInsets();
  }

  async function recallRefresh() {
    const query = $("recall-query").value.trim();
    recallSearching = query.length > 0;
    try {
      const reply = recallSearching
        ? await rb("archive_search", { q: query })
        : await rb("archive_list");
      recallRender(reply.items || [], recallSearching);
    } catch (e) {
      if (e && e.message === "premium_required") {
        $("recall-premium").hidden = false;
        syncChromeInsets();
        return;
      }
      $("recall-status").textContent = friendly(e);
    }
  }

  $("recall-save").addEventListener("click", async () => {
    await refreshCaptureScope();
    await refreshPremium();
    if (premiumBlocked()) {
      $("recall-premium").hidden = false;
      syncChromeInsets();
      return;
    }
    $("recall-status").textContent = i18nText("chrome-js-region-capturing", "Capturing the page...");
    try {
      await rb("archive_save");
      // The outcome arrives as archive_saved: the reading takes about a
      // second, so the reply only confirms the capture started.
      $("recall-status").textContent = i18nText("chrome-js-recall-reading", "Reading the text...");
    } catch (e) {
      $("recall-status").textContent = friendly(e);
    }
  });

  $("recall-query").addEventListener("input", () => {
    recallRefresh();
  });

  function onArchiveSaved(data) {
    // The panel is "tools" now and Deep Recall is one tab of it; the saved
    // event belongs on screen only while that tab is the one showing.
    if (openPanelName !== "tools" || $("recall-panel").hidden) return;
    if (!data.ok) {
      $("recall-status").textContent =
        ERROR_TEXT[data.error] || i18nText("chrome-js-recall-save-failed", "The page could not be saved.");
      return;
    }
    // Two things can fall short of the whole page, and they are independent:
    // the reader stops at its box cap, and on a WebView2 too old for the
    // full-page protocol call the capture falls back to the viewport. The
    // scope comes off the capture event itself rather than being assumed --
    // saying "the picture is complete" on the fallback path is exactly the
    // claim the capture code refuses to make about itself.
    const wholePage = data.scope === "full page";
    // "The text stops partway down" only means something if there was text.
    // An image-dense page -- a photo wall, a map -- can pass the detector's
    // tile budget while every line comes back empty, and that combination
    // used to render "No text was read from this picture. The page was long,
    // so the text stops partway down", which cannot both be true. Widening
    // the truncation flag to cover abandoned tiles is what made it reachable.
    const readShort = data.truncated && data.words > 0;
    let shortfall = "";
    if (readShort && wholePage) {
      shortfall =
        " The page was long, so the text stops partway down; the picture is complete.";
    } else if (readShort) {
      shortfall =
        " The page was long, so the text stops partway down, and " +
        VIEWPORT_PICTURE_SENTENCE.slice(0, -1).toLowerCase() +
        ".";
    } else if (!wholePage) {
      shortfall = " " + VIEWPORT_PICTURE_SENTENCE;
    }
    // Says what was actually read, since "saved" alone hides the difference
    // between a page full of words and one the reader found nothing in.
    {
      const status = $("recall-status");
      status.textContent =
        data.words > 0
          ? "Saved. " + data.words + " words read from this page." + shortfall
          : i18nText("chrome-js-recall-saved-notext", "Saved. No text was read from this picture.") + shortfall;
      if (currentUiLocale !== "en") {
        (async () => {
          const sf =
            readShort && wholePage
              ? await i18nResolve("chrome-recall-short-whole", {}, shortfall)
              : readShort
                ? await i18nResolve("chrome-recall-short-partial", {}, shortfall)
                : !wholePage
                  ? await i18nResolve("chrome-recall-screen-only", {}, shortfall)
                  : "";
          status.textContent =
            data.words > 0
              ? await i18nResolve("chrome-recall-saved-words",
                  { words: data.words, shortfall: sf }, status.textContent)
              : await i18nResolve("chrome-recall-saved-notext",
                  { shortfall: sf }, status.textContent);
        })();
      }
    }
    recallRefresh();
  }

  $("recall-preview-close").addEventListener("click", recallPreviewClose);

  // ---- the tools modal ----------------------------------------------------
  //
  // Page integrity, Deep Recall, and the image check, one modal, three tabs
  // one modal, 2026-08-19. Deep Recall's own panel and toolbar
  // button are gone; the image check moved here OUT of the Privacy panel,
  // whole. chrome.js owns the registration -- against the markup
  // #btn-integrity -- so the gate harness, which loads this file alone, can
  // open it; integrity.js detects the markup button, fills
  // #tools-integrity-slot with the panel it already builds, and hands over
  // its refresh as window.__rbIntegrityRefresh.

  const TOOLS_TABS = [
    { tab: "btn-tab-integrity", body: "tools-integrity-slot" },
    { tab: "btn-tab-recall", body: "recall-panel" },
    { tab: "btn-tab-imagecheck", body: "leakcheck" },
  ];

  // Deep Recall's old panel-open behavior, now the tab-show hook: same
  // premium note, same refresh, unchanged wording.
  async function recallTabShow() {
    $("recall-status").textContent = "";
    $("recall-premium").hidden = true;
    // The disclosed placement is not a Premium entitlement. It stays
    // reachable even when the first-party Recall controls explain that they
    // are locked.
    void refreshPartnerCard("partner-recall", "coveron");
    void refreshCaptureScope();
    await refreshPremium();
    if (!premiumState.premium) {
      $("recall-premium").hidden = false;
      syncChromeInsets();
      return;
    }
    recallRefresh();
  }

  function selectToolsTab(tabId) {
    for (const { tab, body } of TOOLS_TABS) {
      const active = tab === tabId;
      $(tab).setAttribute("aria-pressed", active ? "true" : "false");
      // Leaving the recall tab releases the staged picture, exactly as
      // closing the old panel did: a decrypted page must not sit behind a
      // body nothing on screen shows.
      if (body === "recall-panel" && !active) recallPreviewClose();
      $(body).hidden = !active;
    }
    if (tabId === "btn-tab-recall") recallTabShow();
  }

  // NO syncChromeInsets INSIDE selectToolsTab, and its absence is the fix for
  // the gray rectangle reported from Windows.
  //
  // selectToolsTab is called from this panel's onOpen, and onOpen runs INSIDE
  // togglePanelNamed BEFORE that function sends the arrangement
  // (syncChromeCoverage -> chrome_overlay) and then the height
  // (syncChromeInsets). Syncing from in here therefore sent a 640px chrome
  // height while the arrangement was still Strip. In Strip the page sits
  // BELOW the chrome, so Rust moved the page down to 640 -- and the region it
  // vacated showed the native window background, which under
  // translucent-backdrop (body transparent, scrim 0.62 alpha) reads as a flat
  // gray slab with the page pushed beneath it. Exactly what the screenshot
  // showed. No other panel does this: none of the fourteen calls
  // syncChromeInsets from its onOpen, and this one was the only one that did.
  //
  // The open path needs nothing here -- togglePanelNamed sends arrangement
  // then height, in that order, immediately after onOpen returns. Only a tab
  // switch while the panel is ALREADY open needs its own sync, and the click
  // handler below does that, by which time the arrangement is long since set.
  function selectToolsTabAndFit(tabId) {
    selectToolsTab(tabId);
    syncChromeInsets();
  }

  for (const { tab } of TOOLS_TABS) {
    $(tab).addEventListener("click", () => {
      // From the palette the panel may still be closed; opening it first
      // makes every tab button a complete door of its own.
      if ($("integrity-host").hidden) {
        // togglePanelNamed runs onOpen (which selects the integrity tab) and
        // then sends arrangement + height itself; re-selecting after it is
        // what lands the palette on the tab the user actually chose.
        togglePanelNamed("tools");
        selectToolsTabAndFit(tab);
        return;
      }
      selectToolsTabAndFit(tab);
    });
  }

  registerPanel("tools", {
    el: $("integrity-host"),
    button: $("btn-integrity"),
    heightPx: 640,
    // The preview dies with the modal, whichever tab is up.
    onClose: recallPreviewClose,
    onOpen: () => {
      // The toolbar button means "Page integrity", as it always has; the
      // other tabs are reached by their own palette entries or by hand.
      selectToolsTab("btn-tab-integrity");
      if (window.__rbIntegrityRefresh) window.__rbIntegrityRefresh();
    },
  });

  // ---- who resolves DNS ---------------------------------------------------
  //
  // A restart is genuinely required, not a shortcut: WebView2 takes DNS
  // configuration only at environment creation, and the environment is built
  // once at startup. Saying "takes effect now" would be a lie the user would
  // discover by being wrong about their own privacy.
  //
  // The default is "system", which for anyone running a VPN means their VPN's
  // resolver. Overriding that by default would split a user's traffic across
  // two companies neither of them picked.
  // The choice appears in TWO places: its own toolbar panel, and a section
  // inside the privacy panel. They are one setting with two views, so they
  // share one refresh and one click handler. Writing the wiring out twice is
  // how two mirrors of a setting start disagreeing, and a resolver this UI
  // names wrongly is a privacy claim the user cannot check from inside the
  // browser.
  const DNS_MODES = ["system", "quad9"];
  const DNS_MIRRORS = [
    {
      system: "dns-system",
      quad9: "dns-quad9",
      describe: "dns-describe",
      restart: "dns-restart",
    },
    {
      system: "dnsp-system",
      quad9: "dnsp-quad9",
      describe: "dnsp-describe",
      restart: "dnsp-restart",
    },
  ];
  const DNS_SHORT = { system: i18nText("chrome-js-dns-short-system", "System"), quad9: i18nText("chrome-js-dns-short-quad9", "Quad9") };

  const DNS_RESTART_NOTE =
    "Saved. This takes effect the next time you start PATANYX. The engine " +
    "only accepts a resolver when it starts up.";

  async function refreshDns() {
    // Only the IPC call is guarded. A failed `dns_get` is an expected
    // condition and hides the controls; a TypeError from a mistyped element id
    // is a BUG, and swallowing it here would silently hide the whole feature
    // on the one platform that supports it. Outside the try it throws where
    // the DOM gate can see it.
    let st;
    try {
      st = await rb("dns_get");
    } catch (e) {
      $("dns-choice").hidden = true;
      $("btn-dns").hidden = true;
      return;
    }
    // Windows-only: WebKitGTK has no encrypted-DNS support at all, so on Linux
    // neither the toolbar button nor the privacy section appears — rather than
    // offering controls that do nothing.
    const supported = !!(st && st.supported);
    $("dns-choice").hidden = !supported;
    $("btn-dns").hidden = !supported;
    if (!supported) return;

    // THE CHIP IS NAMED "DNS" AND COLOURED BY WHETHER IT IS DOING ANYTHING.
    // That is the chrome's convention, not a decision local to this control:
    // grey means the feature is not engaged, green means it is, everywhere in
    // the toolbar. This chip used to spell out the resolver name instead and
    // carry no colour at all, which meant the one control in the row that
    // could not be read the way the others are read.
    //
    // Green here says "this browser is choosing your resolver", NOT "you are
    // private". System is grey because the browser is doing nothing about DNS,
    // which is a statement about the browser, not a verdict on the user -- for
    // anyone running a VPN, System is still the right answer, and the panel
    // says so in the first entry of its comparison.
    //
    // A mode this build does not know about is treated as not-engaged rather
    // than guessed at. The chrome is compiled into the binary so it can never
    // be older than the Rust that answers it, and this should be unreachable --
    // but a chip claiming green for a resolver it cannot name would be the
    // worst failure this control has.
    const known = DNS_MODES.includes(st.mode);
    // THE CHIP FOLLOWS THE RESOLVER THE ENGINE IS RUNNING, not the file.
    // `applied` is what the engine was given at startup; `mode` is what the
    // file says now, which is what the NEXT start gets. They differ after a
    // choice (until restart) and after the file becomes unreadable under a
    // running engine (the reply then carries the default while the engine
    // still runs whatever it started with). Colouring the chip by `mode`
    // would claim, after a Quad9 choice, an encryption not yet running, and
    // after the file broke under a Quad9 engine, a plaintext state the
    // engine is not in. A missing or unknown `applied` reads as not engaged:
    // grey is the safe wrong.
    const applied = DNS_MODES.includes(st.applied) ? st.applied : "system";
    const engaged = applied !== "system";
    $("dns-label").textContent = i18nText("chrome-js-dns-label", "DNS");
    $("btn-dns").classList.toggle("is-active", engaged);
    // The tooltip speaks for NOW, so it names the applied resolver and says
    // what is pending when the file differs. `describe` is the file's own
    // sentence and belongs under the buttons, beside the choice it describes;
    // shown here it claimed Quad9 over an engine still running System.
    const pending = known && st.mode !== applied;
    $("btn-dns").title = known
      ? "Who resolves the sites you visit now: " +
        DNS_SHORT[applied] +
        (pending ? ". " + DNS_SHORT[st.mode] + " after the next restart." : ".")
      : "This build does not recognize the resolver that is set. Open this to " +
        "choose one.";
    for (const mirror of DNS_MIRRORS) {
      $(mirror.describe).textContent = st.describe || "";
      // The buttons mark what the FILE says: the choice, which is what the
      // next start gets. The chip above marks the engine. Both are true.
      for (const name of DNS_MODES) {
        $(mirror[name]).classList.toggle("active", known && st.mode === name);
      }
      // The file and the engine disagree: say so in both mirrors, unless the
      // unreadable-file note already holds the line (it says more). And when
      // they agree again -- a choice undone before any restart -- the note
      // comes down, because nothing is pending.
      const note = $(mirror.restart);
      // A preferences file that exists and cannot be read. The mode in the
      // reply is the DEFAULT, not the user's choice, and the default is
      // plaintext DNS -- so someone who picked Quad9 is off it. WHEN they
      // are off it depends on the engine: a file that broke under a running
      // Quad9 engine loses it at the next start, a file that was already
      // unreadable at launch means the engine is on System NOW. The two
      // sentences differ in exactly that, because "from the next start"
      // over an engine already on plaintext understates the exposure. Said
      // out loud in both mirrors, because a silent revert of a protection
      // is the failure this whole row exists to prevent. The note carries a
      // state marker so a later healthy reply clears it; without one it
      // outlived the condition it described.
      if (st.settings_unreadable) {
        note.hidden = false;
        note.textContent =
          applied === "system"
            ? i18nText("chrome-dns-settings-unreadable", "Your settings file could not be read, so DNS is on System, unencrypted. If you had chosen Quad9, choose it again and restart.")
            : i18nText("chrome-dns-settings-unreadable-pending", "Your settings file could not be read, so from the next start DNS falls back to System, unencrypted. If you had chosen Quad9, choose it again and restart.");
        note.dataset.state = "unreadable";
      } else if (known && st.mode !== applied) {
        note.hidden = false;
        note.textContent = DNS_RESTART_NOTE;
        note.dataset.state = "restart-pending";
      } else if (
        note.dataset.state === "restart-pending" ||
        note.dataset.state === "unreadable"
      ) {
        note.hidden = true;
        note.textContent = "";
        delete note.dataset.state;
      }
    }
  }

  // ---- page colors ----
  // Engine-level prefers-color-scheme. `applied` in the reply is the
  // ENGINE's acknowledgement; saved-but-not-acknowledged (an old runtime)
  // is said plainly rather than shown as a theme in force.
  const THEME_MODES = ["auto", "dark", "light"];
  function themeButtons() {
    return {
      auto: $("theme-auto"),
      dark: $("theme-dark"),
      light: $("theme-light"),
    };
  }
  function markTheme(mode) {
    const buttons = themeButtons();
    for (const name of THEME_MODES) {
      buttons[name].classList.toggle("active", mode === name);
    }
  }
  async function refreshTheme() {
    try {
      const r = await rb("page_theme_get");
      if (r && typeof r.theme === "string") markTheme(r.theme);
    } catch (_) {}
  }
  for (const name of THEME_MODES) {
    themeButtons()[name].addEventListener("click", async () => {
      const note = $("theme-note");
      note.hidden = true;
      try {
        const r = await rb("page_theme_set", { theme: name });
        markTheme(r.theme);
        if (r.applied === false) {
          note.hidden = false;
          note.textContent =
            i18nText("chrome-js-theme-not-applied", "Saved, but this browser engine version could not apply it.");
        }
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }

  // ---- chrome accent theme ----
  // Worn via a data-theme attribute on the root element; chrome.css defines
  // the accent variables per theme and defaults to the original blue when
  // the attribute is absent or unknown, so a stale or failed read renders
  // exactly the chrome every build before theming rendered.
  const ACCENT_THEMES = [
    "default",
    "violet",
    "blood_red",
    "sky",
    "green",
    "amber",
    "teal",
    "slate",
    "purple",
  ];
  // ---- the palette, resolved and reported ----
  // The stylesheet is the only place a theme is DEFINED (nine accents, three
  // schemes, color-mix tokens between them), and two things outside this
  // document wear it too: the OS title bar and border on Windows, and the
  // scrollbars of pages. Rust holds no table of hex values -- it would drift
  // -- so after every wear this reads what the tokens computed to, off the
  // live document, and reports the bytes (chrome_palette_set).
  //
  // Read through a probe's `color`, because getPropertyValue on a custom
  // property returns the token TEXT ("color-mix(...)"), not a colour. The
  // computed colour comes back as legacy "rgb(r, g, b)" or, for a mix, as
  // "color(srgb r g b)" on 0..1 -- both are parsed, and anything else means
  // "send nothing", never a guess: a partial palette would be two themes at
  // once, and Rust refuses one anyway.
  const PALETTE_TOKENS = {
    border: "--accent", // the window's border, continuing the frame
    caption: "--sf-tabstrip-a", // the title bar, continuing the tab strip
    text: "--tx-bright", // title text, legible on the caption in every scheme
    scrollbar: "--accent", // page scrollbar thumb, matching the frame
  };
  function parseCssColor(text) {
    let m = /^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/.exec(text);
    if (m) return [Number(m[1]), Number(m[2]), Number(m[3])];
    m = /^color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/.exec(text);
    if (m) {
      return [m[1], m[2], m[3]].map((v) =>
        Math.max(0, Math.min(255, Math.round(Number(v) * 255))),
      );
    }
    return null;
  }
  function resolveToken(token) {
    const probe = document.createElement("span");
    probe.style.color = "var(" + token + ")";
    document.documentElement.appendChild(probe);
    const computed = getComputedStyle(probe).color;
    probe.remove();
    return parseCssColor(computed);
  }
  function publishChromePalette() {
    const palette = {};
    for (const key of Object.keys(PALETTE_TOKENS)) {
      const rgb = resolveToken(PALETTE_TOKENS[key]);
      if (!rgb) return;
      palette[key] = rgb;
    }
    rb("chrome_palette_set", palette)
      .then((r) => {
        // With the OS caption wearing the strip's tint (Windows 11), the
        // ring's top edge is the OS border above the caption, and our own
        // 2px line under it would be a second colour band. Hidden on that
        // answer; shown wherever the caption stays the system's.
        const tinted = !!(r && r.caption_tinted);
        if (tinted) {
          document.documentElement.dataset.captionTint = "on";
        } else {
          delete document.documentElement.dataset.captionTint;
        }
      })
      .catch(() => {});
  }

  function wearTheme(name) {
    if (name === "default") {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = name;
    }
    for (const t of ACCENT_THEMES) {
      $("accent-" + t).classList.toggle("active", t === name);
    }
    publishChromePalette();
  }
  async function refreshAccent() {
    try {
      const r = await rb("chrome_theme_get");
      if (r && ACCENT_THEMES.includes(r.theme)) wearTheme(r.theme);
    } catch (_) {}
  }
  for (const t of ACCENT_THEMES) {
    $("accent-" + t).addEventListener("click", async () => {
      try {
        const r = await rb("chrome_theme_set", { theme: t });
        wearTheme(r.theme);
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }
  // Boot: wear the saved accent as early as the bridge allows, so the
  // default flashes only for users who chose another theme, briefly.
  refreshAccent();
  refreshToolbarLabels();
  refreshBookmarkBar();
  // The placement comes with chrome_caps rather than from its own get, so a
  // Left user's first paint is their layout instead of the top one visibly
  // rearranging itself. refreshToolbarPlacement is the fallback for a caps
  // reply that does not carry it.
  refreshChromeCaps();

  // ---- chrome scheme ----
  // Same contract as the accent: worn via a data-scheme attribute on the
  // root element, and chrome.css resolves an absent or unknown value to
  // the original dark chrome, so a stale read renders exactly what every
  // pre-scheme build rendered.
  const CHROME_SCHEMES = ["dark", "white", "black"];
  function wearScheme(name) {
    if (name === "dark") {
      delete document.documentElement.dataset.scheme;
    } else {
      document.documentElement.dataset.scheme = name;
    }
    for (const s of CHROME_SCHEMES) {
      $("scheme-" + s).classList.toggle("active", s === name);
    }
    // The scheme changes what the accent tokens MIX WITH, so the resolved
    // palette moves with it.
    publishChromePalette();
  }
  // Toolbar labels. Same three-part shape as the scheme above: a wear
  // function that owns the attribute and the button marking, a refresher
  // that reads Rust rather than trusting the last click, and click handlers
  // that re-mark from the REPLY.
  //
  // ABSENT means shown, deliberately: a failed read leaves the toolbar
  // labelled, which is what every build before this setting rendered.
  const TOOLBAR_LABEL_MODES = ["show", "hide"];
  function wearToolbarLabels(mode) {
    if (mode === "show") {
      delete document.documentElement.dataset.toolbarLabels;
    } else {
      document.documentElement.dataset.toolbarLabels = mode;
    }
    for (const m of TOOLBAR_LABEL_MODES) {
      $("labels-" + m).classList.toggle("active", m === mode);
    }
  }
  async function refreshToolbarLabels() {
    try {
      const r = await rb("toolbar_labels_get");
      if (r && TOOLBAR_LABEL_MODES.includes(r.mode)) wearToolbarLabels(r.mode);
    } catch (_) {}
  }
  for (const m of TOOLBAR_LABEL_MODES) {
    $("labels-" + m).addEventListener("click", async () => {
      try {
        const r = await rb("toolbar_labels_set", { mode: m });
        wearToolbarLabels(r.mode);
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }

  // ---- toolbar placement -------------------------------------------------
  //
  // Same three-part shape again -- wear, refresh, click handlers that
  // re-dress from the REPLY -- with one thing the accent and the scheme do
  // not have: the buttons physically MOVE.
  //
  // They move rather than being duplicated because there is one #btn-vault
  // in this document and everything else in this file finds it by id.
  // A second copy in the sidebar would mean two elements answering to one
  // name, two aria-pressed states to keep in step, and a permanent question
  // about which of them a listener was attached to. Changing a node's parent
  // keeps its listeners, its attributes and its identity; nothing else in
  // this file needs to know the feature exists.
  //
  // ABSENT means top, deliberately: a failed read leaves the toolbar where
  // every build before this setting put it.
  const TOOLBAR_PLACEMENTS = ["top_left", "top_right", "left", "right"];
  // Source order of the movable buttons, captured before anything moves.
  // Restoring the top layout has to put them back in the order the markup
  // declared -- which is the order the toolbar gate asserts, and the order
  // the row was designed in -- not the order they happened to be swept up.
  let toolbarOrder = null;

  // The buttons that belong in the sidebar: everything after the row break.
  // Read from the DOM rather than listed here, so a button added to the
  // second row later needs no edit in this file. update.js and integrity.js
  // append at the end of #toolbar, which is why they land in this set for
  // free.
  function movableButtons() {
    const bar = $("toolbar");
    const brk = bar && bar.querySelector(".toolbar-break");
    if (!bar || !brk) return [];
    const after = [];
    let seen = false;
    for (const el of Array.from(bar.children)) {
      if (el === brk) {
        seen = true;
        continue;
      }
      if (seen) after.push(el);
    }
    return after;
  }

  function rememberToolbarOrder() {
    const bar = $("toolbar");
    if (!bar || toolbarOrder) return;
    toolbarOrder = Array.from(bar.children);
  }

  // Move everything after the break into the rail, or put it back.
  //
  // Restoring is done against the remembered source order rather than by
  // appending, because appending would leave the two runtime-added buttons
  // in whatever order the sweep found them and silently reorder the row.
  function placeButtons(placement) {
    const bar = $("toolbar");
    const rail = $("sidebar");
    if (!bar || !rail) return;
    if (placement === "left" || placement === "right") {
      for (const el of movableButtons()) rail.appendChild(el);
      rail.hidden = false;
      return;
    }
    rail.hidden = true;
    if (!toolbarOrder) {
      // Nothing was ever moved, so there is nothing to restore.
      return;
    }
    // Re-append in source order. Elements added at runtime after the order
    // was captured are appended by the loop below rather than lost.
    for (const el of toolbarOrder) {
      if (el.parentNode === bar || el.parentNode === rail) bar.appendChild(el);
    }
    for (const el of Array.from(rail.children)) bar.appendChild(el);
  }

  function wearToolbarPlacement(placement) {
    rememberToolbarOrder();
    if (placement === "top_left") {
      delete document.documentElement.dataset.toolbarPlacement;
    } else {
      document.documentElement.dataset.toolbarPlacement = placement;
    }
    placeButtons(placement);
    for (const p of TOOLBAR_PLACEMENTS) {
      const btn = $("placement-" + p);
      if (btn) btn.classList.toggle("active", p === placement);
    }
    // The labels row below only applies to a top layout, and saying so is
    // the difference between a setting that is scoped and one that looks
    // broken. The preference itself is untouched, so choosing Top again
    // gives back whatever was set.
    const vertical = placement === "left" || placement === "right";
    for (const mode of TOOLBAR_LABEL_MODES) {
      const choice = $("labels-" + mode);
      if (choice) choice.disabled = vertical;
    }
    publishChromeMetric();
    syncChromeInsets();
  }

  async function refreshToolbarPlacement() {
    try {
      const r = await rb("toolbar_placement_get");
      if (r && TOOLBAR_PLACEMENTS.includes(r.placement)) {
        wearToolbarPlacement(r.placement);
      }
    } catch (_) {}
  }

  for (const p of TOOLBAR_PLACEMENTS) {
    const btn = $("placement-" + p);
    if (!btn) continue;
    btn.addEventListener("click", async () => {
      try {
        const r = await rb("toolbar_placement_set", { placement: p });
        wearToolbarPlacement(r.placement);
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }

  // THE TWO BUTTONS THAT ARRIVE LATE. update.js and integrity.js are
  // deferred scripts that append to #toolbar when they run, which may be
  // after the placement has already been worn -- so in a side layout they
  // would land in a container that is not on screen in that layout, and be
  // invisible with no error. The observer sweeps anything that appears after
  // the break into the rail while the rail is the toolbar.
  //
  // Guarded because the DOM harness the gates run in has no MutationObserver:
  // an unguarded constructor here throws at boot and takes every gate with
  // it, which is a worse failure than the one it prevents.
  if (typeof MutationObserver !== "undefined") {
    const bar = $("toolbar");
    if (bar) {
      new MutationObserver((records) => {
        if (!sidebarShowing()) return;
        let moved = false;
        for (const rec of records) {
          for (const node of Array.from(rec.addedNodes || [])) {
            if (node.nodeType !== 1 || node === $("sidebar")) continue;
            $("sidebar").appendChild(node);
            moved = true;
          }
        }
        if (moved) {
          publishChromeMetric();
          syncChromeInsets();
        }
      }).observe(bar, { childList: true });
    }
  }

  // Bookmark folder bar toggle, same shape as the labels trio above.
  //
  // TWO controls, one pref. The Theme panel has the pair of buttons this was
  // built with; the Library has a single toggle, because that is where a
  // person is when they think about folders. Both call the same
  // `bookmarks_bar_set` and both are re-dressed from the reply, so neither
  // can end up showing a state the other disagrees with.
  // The folder row under the toolbar and both of its switches are GONE from
  // the markup: it duplicated the Bookmark Manager and rendered as a clipped
  // sliver at the strip's height. These survive only because several refresh
  // paths still call them, and with no elements to dress they do nothing.
  // The IPC arms behind them are untouched and simply go unused.
  function wearBookmarkBar(shown) {
    const on = $("bmbar-on");
    const off = $("bmbar-off");
    if (on) on.classList.toggle("active", !!shown);
    if (off) off.classList.toggle("active", !shown);
  }

  for (const [id, shown] of [
    ["bmbar-on", true],
    ["bmbar-off", false],
  ]) {
    if (!$(id)) continue;
    $(id).addEventListener("click", async () => {
      try {
        const r = await rb("bookmarks_bar_set", { shown });
        wearBookmarkBar(r.shown);
        await refreshBookmarkBar();
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }

  async function refreshScheme() {
    try {
      const r = await rb("chrome_scheme_get");
      if (r && CHROME_SCHEMES.includes(r.scheme)) wearScheme(r.scheme);
    } catch (_) {}
  }
  for (const s of CHROME_SCHEMES) {
    $("scheme-" + s).addEventListener("click", async () => {
      try {
        const r = await rb("chrome_scheme_set", { scheme: s });
        wearScheme(r.scheme);
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }
  refreshScheme();

  function wireDnsChoice(id, mode) {
    $(id).addEventListener("click", async () => {
      // A resolver click always returns the toolbar panel to resolver copy.
      // This happens before IPC, so even a refused write cannot strand the
      // user on an affiliate card while the resolver controls say otherwise.
      showDnsPartner(false);
      try {
        await rb("dns_set", { mode });
        // Both mirrors get the note, because the user may have made the
        // choice from either one and a restart requirement they never saw is
        // a setting they believe is already in force.
        for (const mirror of DNS_MIRRORS) {
          const note = $(mirror.restart);
          note.hidden = false;
          note.textContent = DNS_RESTART_NOTE;
          note.dataset.state = "restart-pending";
        }
        await refreshDns();
      } catch (e) {
        toast(friendly(e), true);
      }
    });
  }
  for (const mirror of DNS_MIRRORS) {
    for (const mode of DNS_MODES) {
      wireDnsChoice(mirror[mode], mode);
    }
  }

  // This is a disclosure switch, deliberately NOT a fourth DNS mode. The
  // resolver buttons keep their radio-like `.active` state; this button uses
  // `aria-expanded` plus a different class so opening an affiliate card can
  // never answer "which resolver am I using?" with "Managed VPN".
  function showDnsPartner(show) {
    $("dnsp-resolver-description").hidden = show;
    $("dnsp-managed-vpn-description").hidden = !show;
    const button = $("dnsp-managed-vpn");
    button.classList.remove("active");
    button.classList.toggle("disclosed", show);
    button.setAttribute("aria-expanded", String(show));
  }

  $("managed-vpn-dns-framing").textContent =
    "Managed VPNs add connection-wide privacy through separate paid providers. They work independently of PATANYX, so choosing one here won't change your browser or resolver settings.";
  renderWireguardImport("managed-vpn-dns-wireguard");
  $("dnsp-managed-vpn").addEventListener("click", () => {
    showDnsPartner(true);
    void refreshPartnerCards("partner-dns", ["nordvpn", "pia"]);
  });

  // ---- the chosen resolver cannot be reached ------------------------------
  //
  // Rust decides whether this is true; the chrome only renders it. The copy is
  // HEDGED on purpose -- the browser genuinely cannot tell a blocking network
  // from a VPN that is still reconnecting, and a banner that overstates what it
  // knows teaches people to ignore banners.
  function applyResolverState(data) {
    const banner = $("resolver-warning");
    const show = !!(data && data.unreachable);
    if (show) {
      // Composed in Rust (resolver_probe::banner_body) for BOTH producers,
      // the probe event and the boot-time status reply, and rendered
      // verbatim: this surface cannot word the fail-closed claim
      // differently from the catalog.
      $("resolver-body").textContent = data.body || "";
    }
    if (banner.hidden !== !show) {
      banner.hidden = !show;
      syncChromeInsets();
    }
  }

  // ---- the engine underneath is below the security floor -----------------
  //
  // One producer, the `engine_status` reply at boot, because the answer can
  // only change between launches: the engine is loaded once per process, so
  // a runtime that updates while PATANYX is open is still the old one until
  // the next start. The body is composed in Rust (platform::engine_floor_body)
  // and rendered verbatim, the same contract as the resolver banner.
  function applyEngineState(data) {
    const banner = $("engine-floor-warning");
    const show = !!(data && data.below_floor);
    if (show) {
      $("engine-floor-body").textContent = data.body || "";
    }
    if (banner.hidden !== !show) {
      banner.hidden = !show;
      syncChromeInsets();
    }
  }
  $("engine-floor-dismiss").addEventListener("click", () => {
    $("engine-floor-warning").hidden = true;
    syncChromeInsets();
  });

  // ---- a scheduled check found something ---------------------------------
  //
  // NOTIFICATION ONLY. The banner never downloads or installs; "Show me" opens
  // the Updates panel, where the accept has always lived. (With automatic
  // updates ON -- an explicit opt-in -- quiet releases install themselves at
  // the NEXT LAUNCH, so this banner stays silent for them: announcing what
  // needs nothing from the user is noise. A release that adds features is
  // the one thing still worth a banner, in both modes.)
  function applyUpdateChecked(data) {
    const banner = $("update-banner");
    // The updater's own snapshot. `state`, `kind` and `auto_apply` are a
    // contract with updater.rs (status_json), pinned by tests there. TWO
    // states are worth interrupting for:
    //
    //   offered  a new version exists and nothing has been fetched
    //   ready    it is already downloaded and verified, waiting on a restart
    //
    // `ready` is the DEFAULT outcome, because background download ships on,
    // so a banner that fired only on `offered` was quiet for almost everyone.
    // Up-to-date, refused, failed and downloading still belong in the panel
    // rather than across the top of the window.
    const state = data && data.state;
    const version = data && data.offered ? String(data.offered) : "";
    const feature = data && data.kind === "feature" && !(data && data.security);
    const auto = !!(data && data.auto_apply);
    // Auto mode: a quiet (maintenance/security) release will handle itself at
    // the next launch -- no banner. A feature release always announces.
    const show =
      (state === "offered" || state === "ready") && (feature || !auto);
    if (show) {
      // The feature wording keeps the offered/ready split: in `offered`
      // nothing has been downloaded, so "restart to get them" would name an
      // action that installs nothing, and the self-install promise is false
      // -- only a staged (`ready`) release can apply itself at a launch.
      const body = $("update-banner-body");
      if (feature) {
        if (state === "ready") {
          // KEY SELECTION, not sentence building. The ternary that used to
          // live inside these fallbacks was flattened into the catalog when
          // the strings were extracted, so each value carried BOTH subjects
          // ("Version  adds An update adds ...") and no { $version } at all
          // -- invisible in English, broken in every other locale. Same
          // -version / -plain split the non-feature branch below already
          // uses.
          if (auto) {
            if (version) {
              i18nSet(body, "chrome-update-feature-ready-auto-version", { version },
                "Version " + version + " adds new features, downloaded and " +
                  "verified. Restart from the Updates panel to get them; " +
                  "otherwise it installs on its own in about a week.");
            } else {
              i18nSet(body, "chrome-update-feature-ready-auto-plain", {},
                "An update adds new features, downloaded and verified. " +
                  "Restart from the Updates panel to get them; otherwise it " +
                  "installs on its own in about a week.");
            }
          } else if (version) {
            i18nSet(body, "chrome-update-feature-ready-version", { version },
              "Version " + version + " adds new features, downloaded and " +
                "verified. Restart from the Updates panel to get them.");
          } else {
            i18nSet(body, "chrome-update-feature-ready-plain", {},
              "An update adds new features, downloaded and verified. " +
                "Restart from the Updates panel to get them.");
          }
        } else if (version) {
          i18nSet(body, "chrome-update-feature-offered-version", { version },
            "Version " + version + " adds new features. Nothing has been " +
              "downloaded yet. Open Updates to see what changed and decide.");
        } else {
          i18nSet(body, "chrome-update-feature-offered-plain", {},
            "An update adds new features. Nothing has been downloaded yet. " +
              "Open Updates to see what changed and decide.");
        }
      } else if (state === "ready") {
        if (version) {
          i18nSet(body, "chrome-update-ready-version", { version },
            "Version " + version + " is downloaded and verified. Nothing " +
              "has been installed: open Updates to see what changed and " +
              "restart when it suits you.");
        } else {
          i18nSet(body, "chrome-update-ready-plain", {},
            "It is downloaded and verified. Nothing has been installed: " +
              "open Updates to see what changed and restart when it suits you.");
        }
      } else if (version) {
        i18nSet(body, "chrome-update-offered-version", { version },
          "Version " + version + " is ready to install. Nothing has been " +
            "downloaded yet. Open Updates to see what changed and decide.");
      } else {
        i18nSet(body, "chrome-update-offered-plain", {},
          "Nothing has been downloaded yet. Open Updates to see what " +
            "changed and decide.");
      }
    }
    if (banner.hidden !== !show) {
      banner.hidden = !show;
      syncChromeInsets();
    }
  }

  $("update-banner-open").addEventListener("click", () => {
    $("update-banner").hidden = true;
    syncChromeInsets();
    // The Updates button is built by update.js, so it may not exist in a
    // stripped build; clicking nothing is better than throwing.
    const button = document.getElementById("btn-update");
    if (button) button.click();
  });
  $("update-banner-dismiss").addEventListener("click", () => {
    $("update-banner").hidden = true;
    syncChromeInsets();
  });

  // ---- page zoom -----------------------------------------------------------
  //
  // Rust owns the level; this only reports it. Shown ONLY when it is not 100%,
  // because a permanent "100%" is noise, and its absence is the answer to "am
  // I zoomed" for the overwhelmingly common case. Ctrl+0 resets, which is the
  // way back from a level the user cannot read.
  let zoomHideTimer = null;

  function applyZoom(data) {
    const percent = data && data.percent;
    const chip = $("zoom-chip");
    if (!percent) return;
    if (percent === 100) {
      chip.hidden = true;
      syncChromeInsets();
      return;
    }
    chip.textContent = percent + "%";
    if (chip.hidden) {
      chip.hidden = false;
      syncChromeInsets();
    }
    // No auto-hide: a zoomed page STAYS zoomed, so an indicator that faded
    // would leave the user wondering why text is the wrong size with nothing
    // on screen explaining it.
    if (zoomHideTimer) clearTimeout(zoomHideTimer);
  }

  $("zoom-chip").addEventListener("click", () => {
    // Clicking the indicator resets, because the thing a user wants when they
    // notice an odd zoom level is to be rid of it.
    rb("zoom_reset").catch(() => {});
  });

  // ---- a navigation was refused ------------------------------------------
  //
  // Rust already blocked it. This names the host and the rule that matched,
  // because "blocked" alone is an accusation the user cannot check -- and if
  // it is wrong, the rule is the only thing that tells them what to report.
  let blockedHost = null;

  let blockedTabId = null;
  let blockedPendingId = null;
  // The notice belongs to one blocked navigation in one tab. When that tab
  // reports a status for a different site, the navigation it described is
  // over and the notice comes down; Rust refuses the stale click anyway.
  function retireBlockedOnNavigation(st) {
    if (blockedTabId === null || !st || st.id !== blockedTabId) return;
    // Rust's word, not a guess from the origin: the tab stays on the page
    // that ATTEMPTED the blocked navigation, so comparing hosts hid a valid
    // notice and left a stale one up (review round 2). The status carries
    // the pending id Rust holds for this tab; cleared or replaced means
    // this notice is over.
    if (st.blocked_pending !== blockedPendingId) hideBlocked();
  }

  function applyNavigationBlocked(data) {
    if (!data || !data.host) return;
    blockedHost = data.host;
    // The tab that was blocked, from the host's event. The override used to
    // go to whichever tab was ACTIVE when the button was clicked, so a
    // background tab could solicit an exception for an unrelated one
    // (pentest F-006). Rust re-checks this id against that tab's own record.
    blockedTabId = typeof data.tab_id === "number" ? data.tab_id : null;
    blockedPendingId = typeof data.pending_id === "number" ? data.pending_id : null;
    // "REPORTED FOR", NOT "KNOWN TO". The list is built from two public
    // sources and neither warrants the stronger verb: Phishing.Database is
    // community-collected reports, and phishunt publishes automated
    // suspicion, saying plainly in its own terms that its data "is not a
    // legal finding" and that false positives occur routinely. Saying
    // "known to distribute malware" asserts a verified fact about whoever
    // operates the site, which nothing here establishes.
    //
    // There is no per-entry provenance to soften this only where it applies:
    // the two feeds merge into one set of 16-byte hashes with no room for a
    // source tag, so the banner cannot tell which list matched. One honest
    // sentence for the whole list is the alternative to a false one.
    // Machine-readable: the rule clause is present exactly when a broader
    // rule than the host itself matched. The gate asserts this, not words.
    $("blocked-body").dataset.rule =
      data.rule && data.rule !== data.host ? data.rule : "";
    // The body arrives COMPOSED from Rust (catalog message, Fluent args),
    // and is rendered verbatim -- this surface can never word the refusal
    // differently from the catalog, and a translation of it never passes
    // through this file. The comment above about "reported for", not
    // "known to", now guards chrome-blocked-body in en.ftl.
    $("blocked-body").textContent = data.body || "";
    const banner = $("blocked-warning");
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeInsets();
    }
  }

  function hideBlocked() {
    blockedTabId = null;
    blockedPendingId = null;
    const banner = $("blocked-warning");
    if (!banner.hidden) {
      banner.hidden = true;
      syncChromeInsets();
    }
  }

  // A gesture is bound to the notice it STARTED on. Between the press and
  // the click a background tab's blocked event can replace the notice under
  // the same button; the click used to read whatever was current and send
  // consent for the newcomer (pentest F-006, review round 2). The press
  // snapshots the notice; the click sends only if it is still the same one.
  let blockedArmed = null;
  function armBlocked() {
    blockedArmed =
      blockedHost && blockedTabId !== null && blockedPendingId !== null
        ? { host: blockedHost, tab_id: blockedTabId, pending_id: blockedPendingId }
        : null;
  }
  $("blocked-allow").addEventListener("pointerdown", armBlocked);
  // True between the press and the release of a keyboard activation. The
  // click handler uses it to tell "no press was observable" -- assistive and
  // scripted activation, which is allowed to fall back to the notice on
  // screen -- apart from "the press happened and its snapshot was already
  // spent", which must not fall back to anything.
  let blockedKeyHeld = false;
  $("blocked-allow").addEventListener("keydown", (ev) => {
    // Native button activation starts at keydown too. Enter clicks as its
    // default action and Space clicks on keyup, leaving time for another
    // tab's notice to replace this one before the click arrives.
    if (ev.key !== "Enter" && ev.key !== " " && ev.key !== "Spacebar") return;
    if (ev.repeat) {
      // AUTO-REPEAT IS NOT A NEW GESTURE, and it took two goes to close.
      // Returning early stopped the repeat re-snapshotting the newcomer, but
      // it did not stop the repeat CLICKING: Enter's default action fires
      // again on every repeat, the first click had already spent the
      // snapshot, and the next one fell through to whatever notice was on
      // screen by then -- so a held key still authorized a site the person
      // never saw. Cancelling the default is what stops those clicks
      // existing at all. A key held down is one press.
      ev.preventDefault();
      return;
    }
    blockedKeyHeld = true;
    armBlocked();
  });
  // RELEASED IS RELEASED, WHEREVER THE KEYUP LANDS. Bound to the button
  // alone, this flag could stick: Enter activation can hide the banner before
  // the key comes up, and focus can move off the button mid-press, so the
  // release never reached the listener and every later notice silently
  // refused assistive and scripted activation (review round 3). The window
  // sees the release whatever has focus, and losing focus ends the press too.
  // Deliberately NOT cleared when a new notice arrives: a replacement notice
  // must never be what ends the gesture that was meant for the old one.
  const releaseBlockedKey = (ev) => {
    if (ev && ev.type === "keyup" && ev.key !== "Enter" && ev.key !== " " && ev.key !== "Spacebar") {
      return;
    }
    blockedKeyHeld = false;
  };
  window.addEventListener("keyup", releaseBlockedKey, true);
  window.addEventListener("blur", releaseBlockedKey, true);
  $("blocked-allow").addEventListener("blur", releaseBlockedKey);
  $("blocked-allow").addEventListener("click", async () => {
    // Assistive and scripted activation can raise click with no observable
    // press before it (review round 3, R-004). With no press-to-click gap to
    // race, the notice on screen at the click IS the one activated.
    const armed =
      blockedArmed ||
      // The fallback is for activation with no observable press. While a key
      // IS down, a missing snapshot means this press already sent its one
      // consent, so there is nothing here to fall back to -- belt beside the
      // braces of cancelling the repeat above.
      (!blockedKeyHeld && blockedHost && blockedTabId !== null && blockedPendingId !== null
        ? { host: blockedHost, tab_id: blockedTabId, pending_id: blockedPendingId }
        : null);
    blockedArmed = null;
    if (!armed) return;
    if (armed.pending_id !== blockedPendingId || armed.tab_id !== blockedTabId || armed.host !== blockedHost) return;
    try {
      await rb("blocklist_allow", armed);
      hideBlocked();
    } catch (e) {
      toast(friendly(e), true);
    }
  });
  $("blocked-dismiss").addEventListener("click", hideBlocked);

  // Whether the tab button is currently carrying the interception mark.
  // Module state because TWO things write that label and they must not fight:
  // a status update, and a locale fill -- which reapplies every
  // `data-msg-aria-label` in the document, including this button's static one,
  // and so silently replaced the interception announcement with the plain
  // name while interception was still live. With the banner gone this label is
  // the only thing a screen reader gets outside the panel, so the fill has to
  // recompute it rather than overwrite it.
  //
  // SHORT ON PURPOSE, and a decision rather than an oversight. Like the
  // "Connection" line, this string stands alone with no certificate beside it,
  // so the rule that put a qualifier on that line argues for one here too --
  // and it is read by exactly the user that qualifier is for, since a CA name
  // helps nobody who cannot see it. It stays short anyway: an accessible name
  // is announced every time focus lands on the control, and a button in a row
  // of ten that reads a two-sentence paragraph on every arrow key is worse for
  // that user than a terse one. The name carries the condition; the panel the
  // button opens carries the rest, qualifier included. Revisit if the panel
  // ever stops being one keystroke away.
  let tabButtonIntercepted = false;
  function applyTabButtonLabel() {
    $("btn-tab").setAttribute(
      "aria-label",
      tabButtonIntercepted
        ? i18nText("chrome-js-tab-aria-intercepted",
            "Tab Activity. This connection is being intercepted.",
          )
        : i18nText("chrome-js-tab-aria-plain", "Tab Activity"),
    );
  }

  // ---- plain-HTTP warning ----
  // Driven by tab_status (`insecure_pending`), never by an event of its own:
  // the URL is a per-tab fact and the banner has to follow the active tab.
  // Both buttons are argument-less on purpose -- Rust holds the URL, and
  // the chrome cannot substitute another. Same height contract as every
  // banner (it is in BANNERS).
  function hideInsecure() {
    const banner = $("insecure-warning");
    if (!banner.hidden) {
      banner.hidden = true;
      syncChromeInsets();
    }
  }

  // The URL the banner is currently describing. Continue echoes its host
  // back to Rust, which refuses if the pending URL has moved on.
  let shownUrl = null;
  // The host as state.rs computed it. Never derived here; see below.
  let shownHost = "";

  function applyInsecurePending(url, host) {
    const banner = $("insecure-warning");
    shownUrl = url;
    shownHost = host || "";
    if (!url || !shownHost) {
      // No host means Rust could not name the subject, and a warning that
      // cannot say what it is about must not be shown at all.
      hideInsecure();
      return;
    }
    // THE HOST RUST COMPUTED, never one parsed here. Two parsers on the same
    // string disagreed: this file's regex keeps the whole authority, while
    // state.rs strips the port and the userinfo, and the Continue click is
    // refused unless the two agree. So every http://host:port/ URL warned
    // and then could not be continued past, and a userinfo URL rendered an
    // attacker-chosen string as the name of the site being warned about.
    // One value, computed once, on the side that decides.
    i18nSet($("insecure-body"), "chrome-insecure-body", { host: shownHost },
      "PATANYX did not open " + shownHost +
        " because HTTP is not encrypted. Anyone on the path can read or change " +
        "data. Continue anyway for this site and tab until " +
        "the tab closes.");
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeInsets();
    }
  }

  $("insecure-allow").addEventListener("click", async () => {
    const allow = $("insecure-allow");
    const dismiss = $("insecure-dismiss");
    allow.disabled = true;
    dismiss.disabled = true;
    try {
      // Send back the host this banner is DISPLAYING. Rust refuses if the
      // pending URL has changed since it was rendered, so a page that
      // rewrites the banner between the render and the click cannot borrow
      // the click. It confirms; it cannot choose.
      // The value that was SHOWN, so the confirmation is about the
      // sentence the user actually read.
      const res = await rb("insecure_allow", { host: shownHost });
      // The reply carries the refreshed status, whose insecure_pending is
      // now null -- and the load that follows re-emits it anyway.
      if (res && res.status) applyTabStatus(res.status);
      else hideInsecure();
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      allow.disabled = false;
      dismiss.disabled = false;
    }
  });
  $("insecure-dismiss").addEventListener("click", async () => {
    try {
      const st = await rb("insecure_dismiss");
      if (st) applyTabStatus(st);
      else hideInsecure();
    } catch (e) {
      // Nothing to allow and nothing to keep: hide it either way.
      hideInsecure();
    }
  });

  // ---- the ad-list hold -------------------------------------------------
  //
  // What the banner is CURRENTLY describing. Echoed back on the click so Rust
  // can refuse one that answers a banner the user is no longer looking at.
  //
  // Unlike the plain-HTTP warning this carries a pending id and a tab id, and
  // that is not symmetry for its own sake: the insecure banner is read from
  // the ACTIVE tab and cannot outlive the tab being looked at, while this one
  // is rendered per tab from an async status push, so a tab switch can land
  // between the paint and the click. Without the id a click would answer
  // whichever banner happens to be current and could consent to a host the
  // user never read.
  let adlistShown = null;
  // The host this tab may currently reach past the list, or null. Rendered as
  // a chip in Tab Activity.
  let adlistOverrideHost = null;

  function hideAdlist() {
    const banner = $("adlist-warning");
    if (!banner.hidden) {
      banner.hidden = true;
      syncChromeInsets();
    }
  }

  function applyAdlistPending(pending, tabId) {
    const banner = $("adlist-warning");
    if (!pending || !pending.host || !pending.id) {
      adlistShown = null;
      hideAdlist();
      return;
    }
    // THE HOST RUST COMPUTED, never one parsed here. The plain-HTTP warning
    // shipped that defect: this file's regex kept the whole authority while
    // state.rs stripped the port and userinfo, so the two disagreed, every
    // host:port URL became uncontinuable, and a userinfo URL rendered an
    // attacker-chosen string as the name of the site. One value, computed
    // once, on the side that decides.
    adlistShown = { id: pending.id, host: pending.host, tabId };
    // A non-GET top-level navigation cannot be replayed: consent resumes a
    // URL and a URL has no body. The copy says so before the click rather
    // than letting the user find out after it.
    //
    // Two explicit calls rather than one whose message id is chosen by a
    // ternary. The catalog scanner reads the id as a literal second argument,
    // so a computed one is invisible to it: the string would render English in
    // every locale and no gate would say so.
    //
    // WHERE THERE IS NO BUTTON, THERE IS NO BUTTON. On a backend that cannot
    // except one host from the compiled list, Open anyway is REMOVED, not
    // disabled: a greyed-out control invites the user to hunt for the way to
    // enable it, and there is not one. Rust decides, through
    // `adlist_can_allow`, so the chrome cannot offer an action the engine has
    // no path for.
    const canAllow = pending.can_allow === true;
    $("adlist-allow").hidden = !canAllow;
    const post = pending.method && pending.method !== "GET";
    if (!canAllow) {
      i18nSet($("adlist-body"), "chrome-adlist-body-no-exception", { host: pending.host },
        "PATANYX did not open " + pending.host + " because it is on the ad and tracker list. That list is built for the requests pages make in the background, so a site you typed yourself can end up on it. On Linux there is no way to open a single site past the list. You can turn blocking off in the Privacy panel, which turns it off for every site until you turn it back on.");
    } else if (post) {
      i18nSet($("adlist-body"), "chrome-adlist-body-post", { host: pending.host },
        "PATANYX did not open " + pending.host + " because it is on the ad and tracker list. Your form was not sent, and Open anyway will not send it: it loads the address without what you typed. That applies to " + pending.host + " in this tab only and ends when you leave it or close the tab. Nothing else on the list is unblocked.");
    } else {
      i18nSet($("adlist-body"), "chrome-adlist-body", { host: pending.host },
        "PATANYX did not open " + pending.host + " because it is on the ad and tracker list. That list is built for the requests pages make in the background, so a site you typed yourself can end up on it. You can open it anyway; that applies to " + pending.host + " in this tab only and ends when you leave it or close the tab. Nothing else on the list is unblocked.");
    }
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeInsets();
    }
  }

  $("adlist-allow").addEventListener("click", async () => {
    const shown = adlistShown;
    if (!shown) return;
    const allow = $("adlist-allow");
    const dismiss = $("adlist-dismiss");
    allow.disabled = true;
    dismiss.disabled = true;
    try {
      // Everything sent here is a CONFIRMATION of what was displayed, never a
      // selection. No value the chrome can put in this call names a URL that
      // was not already pending, which is what stops it becoming an
      // open-anything primitive.
      const res = await rb("adlist_allow", {
        tab_id: shown.tabId,
        pending_id: shown.id,
        host: shown.host,
      });
      if (res && res.status) applyTabStatus(res.status);
      else hideAdlist();
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      allow.disabled = false;
      dismiss.disabled = false;
    }
  });

  $("adlist-dismiss").addEventListener("click", async () => {
    const shown = adlistShown;
    if (!shown) return;
    try {
      const st = await rb("adlist_dismiss", {
        tab_id: shown.tabId,
        pending_id: shown.id,
      });
      if (st) applyTabStatus(st);
      else hideAdlist();
    } catch (e) {
      // A refusal is NOT "hide". Rust refuses a stale dismissal precisely
      // because a NEWER pending exists for this tab, and hiding here took
      // that newer banner down with its explanation and actions until the
      // next status happened to arrive (review R-005, round 2). Only "there
      // is nothing pending" means there is nothing to show.
      const code = String((e && e.message) || e);
      // ...and only the banner THIS reply answers. A reply for tab 1's old
      // dismissal must not touch tab 2's banner, whatever the code says
      // (review R-004, round 3): compare what is displayed now with what was
      // displayed when this click was made.
      const same = adlistShown && adlistShown.id === shown.id && adlistShown.tabId === shown.tabId;
      if (code === "adlist_no_pending" && same) hideAdlist();
    }
  });

  $("resolver-retry").addEventListener("click", async () => {
    const button = $("resolver-retry");
    button.disabled = true;
    try {
      await rb("resolver_retry");
    } catch (e) {
      toast(friendly(e), true);
    }
    button.disabled = false;
  });
  $("resolver-dismiss").addEventListener("click", () => {
    rb("resolver_dismiss").catch(() => {});
  });

  // ---- what the engine actually confirmed --------------------------------
  //
  // These five answers were already crossing the IPC boundary and NOTHING
  // rendered them. Rust recorded, honestly, whether each protection was
  // Applied / Failed / NotAttempted, and the user was never shown any of it --
  // the reporting existed and the reporting had no reader.
  //
  // "Failed" is the load-bearing case. A setting the engine refused must read
  // as refused, never be quietly omitted, because the whole point of tracking
  // SettingState is that a protection nobody confirmed is not a protection.
  let ENGINE_LABELS;
  rebuildOnLocaleFill(() => {
    ENGINE_LABELS = {
      script_setting: i18nText("chrome-js-engine-script-setting", "JavaScript setting"),
      smartscreen_off: i18nText("chrome-js-engine-smartscreen-off", "SmartScreen reporting off"),
      tracking_prevention: i18nText("chrome-js-engine-tracking-prevention", "Engine tracking prevention"),
      navigation_tracking: i18nText("chrome-js-engine-navigation-tracking", "Navigation tracking"),
      autofill_off: i18nText("chrome-js-engine-autofill-off", "Engine autofill and password store off"),
      // The storage promise, asked of the engine rather than assumed. This row
      // is why the panel can say "ephemeral" at all: until it read back, the
      // browser reported the mode it had REQUESTED, so a tab whose in-private
      // flag never took still displayed as keeping nothing.
      ephemeral_confirmed: i18nText("chrome-js-engine-ephemeral-confirmed", "Ephemeral storage for this tab"),
      // Process-wide, and the one row here that is not about this tab. "REFUSED"
      // means the browser fell back to the engine's default environment and lost
      // its hardened startup arguments along with crash-report suppression.
      hardened_environment: i18nText("chrome-js-engine-hardened-environment", "Hardened engine environment"),
      // Process-wide. "REFUSED" means the OS would not tell this process when
      // the workstation locks, so the vault stays open behind a locked screen
      // until the inactivity timer catches it.
      session_lock_registered: i18nText("chrome-js-engine-session-lock-registered", "Lock vault when the screen locks"),
      // Whether THIS tab's autofill save/fill channel actually registered.
      // "REFUSED" here means the Passwords section in Tab Activity cannot
      // offer or accept a fill for this tab no matter what the vault holds --
      // the same "what the engine confirmed, not what was requested" rule as
      // every other row above.
      content_script_registered: i18nText("chrome-js-engine-content-script-registered", "Login autofill script installed"),
      // Process-wide and MEASURED, not read back off an API: a background
      // thread completes a real SOCKS5 greeting against the loopback tunnel
      // front and reads the tunnel's own status before this says "confirmed".
      // "REFUSED" before the vault unlocks usually means the port is
      // deliberately accepting nothing -- the browser refusing to leak, not
      // (only) something broken. "not attempted" here means the user chose
      // no tunnel, and the special case in renderEngineConfirmed says so
      // instead of claiming "not applicable on this engine".
      tunnel: i18nText("chrome-js-engine-tunnel", "Tunnel carrying this browser's traffic"),
    };
  });
  let ENGINE_STATE_TEXT;
  rebuildOnLocaleFill(() => {
    ENGINE_STATE_TEXT = {
      strict: i18nText("chrome-js-engine-strict", "Strict, confirmed by the engine"),
      balanced: i18nText("chrome-js-engine-balanced", "Balanced, confirmed by the engine"),
      applied: i18nText("chrome-js-engine-state-applied", "confirmed by the engine"),
      failed: i18nText("chrome-js-engine-state-failed", "REFUSED by the engine"),
      not_attempted: i18nText("chrome-js-engine-state-not-attempted", "not applicable on this engine"),
    };
  });

  function renderEngineConfirmed(st) {
    const list = $("engine-list");
    if (!list) return;
    list.replaceChildren();
    for (const key of Object.keys(ENGINE_LABELS)) {
      const value = st[key];
      // Absent means this build does not report it at all, which is different
      // from reporting "not attempted"; do not invent a row for it.
      if (value === undefined || value === null) continue;
      const li = el("li", "entry");
      li.appendChild(el("strong", null, ENGINE_LABELS[key]));
      // SPECIAL CASE, and the only one this renderer should grow without a
      // rethink: ENGINE_STATE_TEXT maps not_attempted to "not applicable on
      // this engine", which is TRUE for every other key (the mechanism does
      // not exist on this backend) but a lie for the tunnel -- the user can
      // switch the tunnel off on ANY engine, and then the honest text is
      // "off". If a second key ever needs its own wording, the state
      // vocabulary is wrong, not this branch: rethink it instead of adding
      // a case per key.
      const stateText =
        key === "tunnel" && value === "not_attempted"
          ? i18nText("chrome-js-tunnel-report-not-attempted", "off (no tunnel chosen)")
          : ENGINE_STATE_TEXT[value] || value;
      li.appendChild(
        el("span", value === "failed" ? "error" : "muted", " " + stateText),
      );
      list.appendChild(li);
    }

    // The malicious-site list, appended after the per-tab rows.
    //
    // Browser-wide rather than per-tab, which makes it the second row here
    // that is not about this tab -- `hardened_environment` is the first, and
    // set the precedent. It belongs in this section for the reason the section
    // exists: it reports a protection's REAL state rather than its intended
    // one, and "the list is a week stale because every refresh since has
    // failed" is exactly the difference between those two.
    //
    // Rendered only once something is known. Before the first refresh
    // completes there is no honest row to draw: the browser is protecting the
    // user with the list it shipped with, and claiming either success or
    // failure would be inventing an answer.
    if (blocklistHosts !== null || blocklistFailure !== null) {
      const li = el("li", "entry");
      // el(tag, className, text) -- the middle argument is the CLASS. Passing
      // the label as the second argument made it a class name and left the
      // element empty, so the row rendered as a bare "REFRESH FAILED" with
      // nothing saying what had failed.
      li.appendChild(el("strong", null, i18nText("chrome-js-engine-blocklist-label", "Malicious-site list")));
      const count =
        blocklistHosts === null
          ? ""
          : ", " + blocklistHosts.toLocaleString() + " sites blocked";
      // English paints synchronously from the same composition as always;
      // other locales recompose through the catalog (count and reason as
      // sub-messages so their punctuation is translatable too), patching
      // the span when the bridge answers -- the i18nSet seam, hand-rolled
      // because two sub-resolves feed the final message.
      const failed = blocklistFailure !== null;
      const span = failed
        ? el("span", "error",
            " REFRESH FAILED. Still blocking with the list already" +
              " downloaded" + count +
              (blocklistFailure ? " (" + blocklistFailure + ")" : ""))
        : el("span", "muted", " up to date" + count);
      li.appendChild(span);
      if (currentUiLocale !== "en") {
        (async () => {
          const countnote =
            blocklistHosts === null
              ? ""
              : await i18nResolve("chrome-engine-blocklist-count",
                  { count: blocklistHosts, formatted: blocklistHosts.toLocaleString() },
                  count);
          if (failed) {
            const reasonnote = blocklistFailure
              ? await i18nResolve("chrome-engine-blocklist-reason",
                  { reason: blocklistFailure }, " (" + blocklistFailure + ")")
              : "";
            span.textContent = await i18nResolve("chrome-engine-blocklist-failed",
              { countnote, reasonnote }, span.textContent);
          } else {
            span.textContent = await i18nResolve("chrome-engine-blocklist-ok",
              { countnote }, span.textContent);
          }
        })();
      }
      list.appendChild(li);
    }
  }

  let LEAK_TEXT;
  rebuildOnLocaleFill(() => {
    LEAK_TEXT = {
      email: i18nText("chrome-js-leakcheck-email", "Email address"),
      possible_card: i18nText("chrome-js-leakcheck-possible-card", "Possible payment card number"),
      long_number: i18nText("chrome-js-leakcheck-long-number", "Long number"),
      api_token: i18nText("chrome-js-leakcheck-api-token", "Possible API key or token"),
      private_key: i18nText("chrome-js-leakcheck-private-key", "Private key header"),
      ipv4: i18nText("chrome-js-leakcheck-ipv4", "IP address"),
      // Says what was done to the text, not what the text is. Every other label
      // here names a kind of secret; this one names the reason you did not
      // notice it.
      hidden_text: i18nText("chrome-js-leakcheck-hidden-text", "Hidden: too faint to see"),
    };
  });

  // Capability probe. Both controls stay hidden unless the models are
  // actually installed AND the platform can show a file chooser, because a
  // button that cannot work is worse than no button.
  // The toolbar's Premium controls start LOCKED in the markup's default
  // state and are unlocked only by an answer from Rust, so a failed or slow
  // startup leaves them locked rather than briefly usable.
  refreshPremium();

  (async () => {
    try {
      const st = await rb("ocr_status");
      ocrAvailable = !!(st && st.available && st.file_choice);
    } catch (e) {
      ocrAvailable = false;
    }
    $("recovery-scan").hidden = !ocrAvailable;
    // Availability reveals the section AND its tab: the section alone would
    // leave a tab that opens onto nothing, the tab alone a tool with no door.
    // (While the imagecheck tab is the active one, leaving this hidden state
    // to the tab logic -- selectToolsTab re-runs on every switch.)
    $("leakcheck").hidden = !ocrAvailable;
    if ($("btn-tab-imagecheck")) $("btn-tab-imagecheck").hidden = !ocrAvailable;
  })();

  // Whether the chosen resolver is reachable, asked once at startup.
  //
  // `resolver_status` has existed with no caller. The banner appeared only when
  // the `resolver_state` EVENT fired, and that event is raised by a probe
  // triggered by a failed navigation -- so a resolver that was already
  // unreachable when the browser started showed nothing at all until the user
  // tried to load a page and it failed. The one moment they most needed the
  // explanation was the one moment it was missing.
  //
  // The reply's shape is NOT the event's shape: it carries `showing`, the event
  // carries `unreachable`. Mapped here rather than changed in Rust, because the
  // event name is what several callers already send.
  //
  // Not counted as user presence for the vault's idle clock -- see
  // counts_as_presence in ipc.rs. This is the browser asking itself a question.
  (async () => {
    try {
      const st = await rb("resolver_status");
      // `supported` is false wherever encrypted DNS does not exist, and there
      // is no banner to restore in that case.
      if (st && st.supported) {
        applyResolverState({ unreachable: !!st.showing, mode: st.mode, body: st.body });
      }
    } catch (e) {
      console.error("resolver_status failed:", e);
    }
  })();

  // Is the engine underneath one with a known, exploited bug. Asked once,
  // here, because the engine cannot change while the process lives. A
  // failed reply leaves the banner hidden: unknown is not treated as unsafe
  // (platform::EngineInfo says why), and a banner raised on an IPC hiccup
  // would be a false alarm about the one thing this banner must be right on.
  (async () => {
    try {
      applyEngineState(await rb("engine_status"));
    } catch (e) {
      console.error("engine_status failed:", e);
    }
  })();

  // How many sites the malicious-site list currently blocks.
  //
  // `blocklist_status` has existed, and returned this number, without a single
  // caller. The refresh EVENT only arrives when a refresh happens, which may
  // be an hour away, so without this probe the panel would show no blocklist
  // row at all for the first hour of every session -- on the browser whose
  // headline protection it is.
  //
  // Failure is silent and leaves the row absent. The count is context, not a
  // protection; being unable to read it says nothing about whether blocking
  // is working, and a toast claiming otherwise would be the misreport this
  // section is built to avoid.
  (async () => {
    try {
      const st = await rb("blocklist_status");
      if (st && typeof st.hosts === "number") {
        blocklistHosts = st.hosts;
        refreshShield();
        if (lastTabStatus) renderEngineConfirmed(lastTabStatus);
      }
    } catch (e) {
      console.error("blocklist_status failed:", e);
    }
  })();

  // ---- from the bookmarks draft ----
  function renderDownloads() {
    const list = $("download-list");
    list.textContent = "";
    $("download-empty").hidden = downloadItems.length > 0;
    for (const item of downloadItems) {
      const li = el("li", "item");
      const head = el("div", "item-head");
      head.appendChild(el("span", "item-title", item.filename));
      head.appendChild(
        el(
          "span",
          "item-sub",
          fmtBytes(item.byte_len) +
            " · " +
            fmtTime(item.recorded_at) +
            " · " +
            hostOf(item.url),
        ),
      );
      li.appendChild(head);

      const row = el("div", "item-row");
      const verifyBtn = el("button", "small", i18nText("chrome-js-downloads-verify", "Verify"));
      verifyBtn.type = "button";
      const result = el("span", "item-sub", "");
      verifyBtn.addEventListener("click", async () => {
        verifyBtn.disabled = true;
        result.className = "item-sub";
        result.textContent = i18nText("chrome-js-downloads-checking", "Checking...");
        try {
          const r = await rb("download_verify", { id: item.id });
          if (!r.record_ok) {
            result.className = "error";
            result.textContent =
              i18nText("chrome-js-downloads-verify-altered", "This record has been altered. It no longer matches what this browser wrote.");
          } else if (r.file === "match") {
            result.textContent =
              i18nText("chrome-js-downloads-verify-unchanged", "Unchanged: byte-identical to what was downloaded.");
          } else if (r.file === "differs") {
            result.className = "error";
            result.textContent =
              i18nText("chrome-js-downloads-verify-differs", "The file on disk differs from what was downloaded.");
          } else if (r.file === "missing") {
            result.textContent =
              i18nText("chrome-js-downloads-verify-missing", "File not found in the downloads folder. Was it moved, renamed, or deleted?");
          } else {
            result.className = "error";
            result.textContent = i18nText("chrome-js-downloads-verify-unreadable", "The file could not be read.");
          }
        } catch (e) {
          result.className = "error";
          result.textContent = friendly(e);
        }
        verifyBtn.disabled = false;
      });
      row.appendChild(verifyBtn);
      row.appendChild(result);

      // Ask a contact what THEY got from the same address. Only rendered in
      // a build that has a chat transport, and only when a contact exists:
      // a button whose only outcome is "add a contact first" is a button
      // that should not be there yet.
      if (downloadCompareAvailable && chatContacts.length > 0) {
        const askBtn = el("button", "small", i18nText("chrome-js-downloads-ask-contact", "Ask a contact"));
        askBtn.type = "button";
        askBtn.setAttribute("data-premium", "1");
        askBtn.setAttribute(
          "title",
          i18nText("chrome-js-downloads-ask-title", "Compare this download with a contact's copy"),
        );
        const picker = el("select", "small");
        for (const contact of chatContacts) {
          const opt = document.createElement("option");
          opt.value = contact.id;
          opt.textContent = contact.label;
          picker.appendChild(opt);
        }
        askBtn.addEventListener("click", async () => {
          await refreshPremium();
          if (premiumBlocked()) return;
          const target = compareSlot(item.id);
          target.className = "item-sub";
          target.textContent = i18nText("chrome-js-downloads-asking", "Asking...");
          // Claimed BEFORE the request so an answer that arrives while the
          // await is still settling has a row to land in.
          compareAwaiting = item.id;
          try {
            await rb("download_compare_request", {
              id: item.id,
              contact_id: picker.value,
            });
          } catch (e) {
            compareAwaiting = null;
            target.className = "error";
            target.textContent = friendly(e);
          }
        });
        row.appendChild(picker);
        row.appendChild(askBtn);
      }

      li.appendChild(row);
      // Where this download's comparison answer lands. One slot per record,
      // found by id, so an answer can never be painted onto another row.
      const slot = el("div", "item-sub", "");
      slot.id = "dlcmp-" + item.id;
      li.appendChild(slot);
      list.appendChild(li);
    }
    // Newly built rows start in whatever state the licence is in.
    applyPremiumState(premiumState);
  }

  // ---- download corroboration ---------------------------------------------
  //
  // The verdict's WORDS come from Rust (the corroborate crate's own Display
  // output). Nothing here composes a claim about what a hash difference
  // means; this file places the sentence and the standing caveats beside it.

  let downloadCompareAvailable = false;
  let chatContacts = [];

  const DOWNLOAD_COMPARE_CAVEATS = [
    i18nText("chrome-js-compare-caveat-scope", "This compares what two people were served. It cannot tell you whether either copy is safe."),
    i18nText("chrome-js-compare-caveat-trust", "It trusts your contact to report honestly what they downloaded."),
    i18nText("chrome-js-compare-caveat-versions", "Different versions, per-platform builds and stale mirrors all produce different files innocently."),
    i18nText("chrome-js-compare-caveat-match", "Matching hashes mean the server treated you both alike, nothing more."),
  ];

  function compareSlot(id) {
    return $("dlcmp-" + id) || el("div", "item-sub", "");
  }

  // The answer arrives keyed by peer, not by download, so it lands in the
  // row whose question is outstanding. One question at a time per contact is
  // what the backend allows, so this cannot be ambiguous.
  let compareAwaiting = null;

  function renderCompareVerdict(data) {
    const slot = compareAwaiting ? compareSlot(compareAwaiting) : null;
    if (!slot) {
      // THE RESPONDER SIDE. This browser answered a contact's question, so
      // no row of ours is waiting. Dropping it here would silently break
      // the design's promise that both sides learn the same thing at the
      // same time, and would leave the person who answered knowing less
      // than the person who asked. The crate's sentence carries its own
      // hedges, so it is safe to show alone.
      toast(data.text);
      return;
    }
    slot.textContent = "";
    slot.className = "item-sub";
    const line = el("div", data.kind === "hash_differs" ? "error" : "ok");
    // Rust's wording, verbatim. Written through textContent like every other
    // peer-adjacent string in this file.
    line.textContent = data.text;
    slot.appendChild(line);
    if (!data.byte_len_equal) {
      slot.appendChild(
        el("div", "item-sub", i18nText("chrome-js-compare-size-diff", "The two files are also different sizes.")),
      );
    }
    if (data.recorded_gap_seconds > 0) {
      slot.appendChild(
        el(
          "div",
          "item-sub",
          "The two downloads were recorded " +
            fmtGap(data.recorded_gap_seconds) +
            " apart.",
        ),
      );
    }
    const ul = el("ul", "caveats");
    for (const text of DOWNLOAD_COMPARE_CAVEATS) {
      ul.appendChild(el("li", null, text));
    }
    slot.appendChild(ul);
    compareAwaiting = null;
  }

  function fmtGap(seconds) {
    if (seconds < 90) return seconds + " seconds";
    if (seconds < 5400) return Math.round(seconds / 60) + " minutes";
    if (seconds < 172800) return Math.round(seconds / 3600) + " hours";
    return Math.round(seconds / 86400) + " days";
  }

  let DOWNLOAD_COMPARE_NOTES;
  rebuildOnLocaleFill(() => {
    DOWNLOAD_COMPARE_NOTES = {
      no_download:
        i18nText("chrome-js-compare-note-no-download", "Your contact has no record of downloading from this address. That is not evidence of anything."),
      record_untrusted:
        i18nText("chrome-js-compare-note-record-untrusted", "Your contact's own record of that download failed its integrity check, so their copy's fingerprint cannot be trusted for this comparison."),
      unsupported: i18nText("chrome-js-compare-note-unsupported", "Your contact's build cannot answer this."),
      bad_message: i18nText("chrome-js-compare-note-bad-message", "Your contact's answer could not be read."),
      unexpected:
        i18nText("chrome-js-compare-note-unexpected", "An answer arrived for a comparison this browser did not ask for. Nothing was compared."),
    };
  });

  function renderCompareNote(data) {
    const slot = compareAwaiting ? compareSlot(compareAwaiting) : null;
    compareAwaiting = null;
    if (!slot) return;
    slot.className = "item-sub";
    slot.textContent =
      DOWNLOAD_COMPARE_NOTES[data.reason] || DOWNLOAD_COMPARE_NOTES.bad_message;
  }

  // ---- from the bookmarks draft ----
  // After a vault unlock/create the store is open too; refresh the bookmark
  // cache so the star and (if open) the library reflect it.
  function refreshLibraryAfterUnlock() {
    if (openPanelName === "library") {
      refreshLibrary();
    } else {
      refreshBookmarks();
    }
  }

  // ---- from the vaultsurface draft ----
  // ---- backup and recovery (open state) -----------------------------------------

  async function refreshBackupStatus() {
    try {
      const st = await rb("vault_backup_status");
      const line = $("bk-recovery-status");
      if (st && st.has_recovery) {
        line.textContent =
          i18nText("chrome-js-backup-recovery-status", "Recovery key saved. It was shown once and belongs on paper. It is the only way in if you forget the passphrase, and passphrase changes do not affect it.");
      } else {
        line.textContent =
          i18nText("chrome-js-backup-no-recovery-status", "No recovery key. If you forget the passphrase, nobody can recover this vault. Encrypted exports do not help without their passphrase.");
      }
      // The offer to fix it, next to the sentence describing the problem. This
      // line stated the gap for as long as it has existed and there was
      // nothing to do about it: a key could only ever be obtained at vault
      // creation or at an old-format migration, both shown once.
      const createForm = $("recovery-create-form");
      if (createForm) {
        createForm.hidden = !!(st && st.has_recovery);
      }
      if (st && st.plaintext_confirmation) {
        plaintextSentence = st.plaintext_confirmation;
        // User-visible, but it is our own constant round-tripping; textContent
        // like everything else crossing the IPC boundary.
        $("bk-plain-sentence").textContent = plaintextSentence;
      }
      // Where a chooser exists, the suggested paths are NOT offered as
      // destinations. They are siblings of the vault file, which inside the
      // sandbox is a directory the user cannot browse to and will not find
      // the export in afterwards -- a write that "succeeds" into a place
      // nobody can reach is worse than being asked where to put it.
      const choice = !!(st && st.file_choice);
      // The IMPORT picker asked the same arm at chrome load, when the vault
      // is always locked and the arm refuses, so it stayed hidden forever on
      // every platform (launch sweep F-001). This is the first moment the
      // answer exists; hand it to the import form too.
      importFileChoice = st && st.file_choice;
      importModeAppliers.forEach((apply) => apply());
      $("bk-exp-pick").hidden = !choice;
      $("bk-plain-pick").hidden = !choice;
      $("bk-exp-dest").readOnly = choice;
      $("bk-plain-dest").readOnly = choice;
      if (choice) {
        $("bk-exp-dest").placeholder = i18nText("chrome-js-backup-no-location-placeholder", "No location chosen yet");
        $("bk-plain-dest").placeholder = i18nText("chrome-js-backup-no-location-placeholder", "No location chosen yet");
      } else {
        // Pre-fill only empty fields — never overwrite something the user
        // typed.
        if (st && st.export_suggestion && !$("bk-exp-dest").value) {
          $("bk-exp-dest").value = st.export_suggestion;
        }
        if (st && st.plaintext_suggestion && !$("bk-plain-dest").value) {
          $("bk-plain-dest").value = st.plaintext_suggestion;
        }
      }
    } catch (e) {
      /* locked in the meantime; the pane is hidden then anyway */
    }
  }

  registerPanel("tab", {
    el: $("tab-panel"),
    button: $("btn-tab"),
    heightPx: TAB_OPEN_PX,
    onOpen: () => {
      refreshTabPanel();
      // The ledger grows while the page runs; poll lightly so the list the
      // user is looking at keeps filling in. Cleared on close — nothing
      // polls while the panel is shut.
      ledgerTimer = setInterval(refreshLedger, 2500);
    },
    onClose: () => {
      if (ledgerTimer) {
        clearInterval(ledgerTimer);
        ledgerTimer = null;
      }
    },
  });
  // ONE panel for everything saved. Bookmarks, the tabs you shelved and
  // download records were three tabs in a separate Library; the sidebar and
  // Partnerships header control now select views of this one manager. The
  // panel keeps the id and toolbar button it always had, so nothing that
  // points at the Library has to learn a new name.
  registerPanel("library", {
    el: $("bookmarks-panel"),
    button: $("btn-library"),
    // The manager is wide and tall. 720 was the ceiling the Rust side
    // clamped to; the ceiling is 800 now (CHROME_TOP_RANGE), so this is a
    // height chosen for the panel rather than a value pressed against a
    // limit -- it stays where it is because that is what the manager needs.
    heightPx: 720,
    onOpen: refreshLibrary,
    // The shared saved-picture viewer may currently be parked after a
    // snapshot row. Closing Library must drop its decoded image and wipe the
    // same Rust staging slot Deep Recall uses.
    onClose: recallPreviewClose,
  });

  // ---- the bookmarks manager ---------------------------------------------
  //
  // A wide panel for finding, filing, pinning and batch-editing bookmarks.
  // Every write goes through the same reload the Library organizer uses, so
  // the two views cannot drift into showing different truths.
  //
  // DRAG IS NOT THE MECHANISM. Dropping a bookmark on a folder works, but
  // every drag target also has a click path, because drag is invisible to a
  // keyboard and it did nothing at all for the first person who tried it.
  // The Folders button on each row is how a bookmark is filed.
  // "all" | "quick" | "snapshots" | "partnerships" | "unfiled" | a folder name
  let managerSelected = "all";
  let managerQuery = "";
  let managerSort = "newest"; // "newest" | "oldest" | "title"
  const managerSelection = new Set(); // bookmark ids ticked for batch actions
  let managerRenamingFolder = null;
  // A batch is running. Every batch control is disabled while it is set, so
  // two overlapping runs cannot interleave their writes and their refreshes
  // and leave the selection decided by whichever finished last.
  let managerBatchBusy = false;
  // The bookmark id whose Folders popover is open, or null. The popover
  // survives a re-render: it is re-anchored and re-filled from fresh state,
  // and closes itself if its bookmark or its row has gone.
  let foldersPopoverFor = null;
  let popoverRefocusFolder = null;
  // "id|folder" pairs with a file/unfile call in flight. Only the pending
  // pair's checkbox is disabled, so one toggle cannot fire twice while a
  // different folder stays live; each call is atomic server-side anyway.
  const folderOpsPending = new Set();
  // Letter tiles: the only icon this chrome is allowed. No images and no
  // network -- the CSP forbids both, and fetching a site's icon would
  // disclose the whole bookmark list to the sites in it. One letter, on a
  // background whose hue is a hash of the name, so a given site is always the
  // same color. Colors go through node.style, which the CSP does not govern
  // (the folder menu already positions itself this way).
  function tileHostKey(url) {
    return String(hostOf(url) || "")
      .replace(/^www\./i, "")
      .split(":")[0]
      .toLowerCase();
  }

  function tileHueOf(key) {
    let h = 0;
    for (let i = 0; i < key.length; i += 1) {
      h = (h * 31 + key.charCodeAt(i)) >>> 0;
    }
    return h % 360;
  }

  /// A tile for any label: `key` decides both the letter and the color, so
  /// the same site (or the same folder) always looks the same.
  function makeTile(key) {
    const clean = String(key || "");
    const tile = el("span", "bmtile");
    const match = /[a-z0-9]/i.exec(clean);
    tile.textContent = (match ? match[0] : "?").toUpperCase();
    const hue = tileHueOf(clean.toLowerCase());
    tile.style.background = "hsl(" + hue + ", 45%, 38%)";
    // A light tint of the SAME hue, so the letter reads on its own tile in
    // all three color schemes without borrowing a panel token.
    tile.style.color = "hsl(" + hue + ", 70%, 92%)";
    // Decorative: the name beside it is the accessible label.
    tile.setAttribute("aria-hidden", "true");
    return tile;
  }

  function makeLetterTile(url) {
    return makeTile(tileHostKey(url));
  }

  function orderedQuickAccess(items) {
    // Ordered positions come first, ascending. Bookmarks without a manual
    // position follow in their existing list order. The first drag sends ALL
    // visible ids, so it assigns every current tile and never scrambles the
    // untouched remainder of a partly ordered, older store.
    return items
      .map((item, index) => ({ item, index }))
      .filter((entry) => entry.item.quick_access === true)
      .sort((a, b) => {
        const aOrder = Number.isInteger(a.item.quick_access_order)
          ? a.item.quick_access_order
          : null;
        const bOrder = Number.isInteger(b.item.quick_access_order)
          ? b.item.quick_access_order
          : null;
        if (aOrder !== null && bOrder !== null) {
          return aOrder - bOrder || a.index - b.index;
        }
        if (aOrder !== null) return -1;
        if (bOrder !== null) return 1;
        return a.index - b.index;
      })
      .map((entry) => entry.item);
  }

  function managerPinned() {
    return orderedQuickAccess(bookmarkItems);
  }

  // Pure, so the manager gate can pin the reorder calculation without
  // teaching its deliberately small DOM stub browser layout. `afterTarget`
  // is decided by which half of the hovered tile the pointer occupies.
  function reorderQuickAccessIds(ids, draggedId, targetId, afterTarget) {
    if (
      draggedId === targetId ||
      ids.indexOf(draggedId) < 0 ||
      ids.indexOf(targetId) < 0
    ) {
      return ids.slice();
    }
    const next = ids.filter((id) => id !== draggedId);
    const target = next.indexOf(targetId);
    next.splice(target + (afterTarget ? 1 : 0), 0, draggedId);
    return next;
  }

  function managerSnapshots() {
    const urls = new Set();
    return bookmarkItems.filter((bookmark) => {
      if (bookmark.has_digest !== true || urls.has(bookmark.url)) return false;
      urls.add(bookmark.url);
      return true;
    });
  }

  function managerSnapshotCount() {
    return managerSnapshots().reduce(
      (count, bookmark) =>
        count +
        (Array.isArray(bookmark.snapshots) ? bookmark.snapshots.length : 1),
      0,
    );
  }

  function managerUnfiled() {
    return bookmarkItems.filter(
      (b) => !Array.isArray(b.tags) || b.tags.length === 0,
    );
  }

  function folderMembers(name) {
    return bookmarkItems.filter(
      (b) => Array.isArray(b.tags) && b.tags.indexOf(name) >= 0,
    );
  }

  // Sidebar chooses the working set, search narrows it, sort only orders
  // what is left. Selection is by id, so none of the three can lose a tick.
  function managerVisibleItems() {
    let items;
    const quickView = managerSelected === "quick";
    const snapshotsView = managerSelected === "snapshots";
    if (quickView) {
      items = managerPinned();
    } else if (snapshotsView) {
      items = managerSnapshots();
    } else if (managerSelected === "unfiled") {
      items = managerUnfiled();
    } else if (managerSelected === "all") {
      items = bookmarkItems.slice();
    } else {
      items = folderMembers(managerSelected);
    }
    const needle = managerQuery.trim().toLowerCase();
    if (needle) {
      if (quickView || snapshotsView) {
        items = items.filter(
          (item) => bookmarkMatchScore(item, needle) !== null,
        );
      } else {
        // A live query ranks by match strength instead of the dropdown
        // sort: "most likely what was meant" is the better order while
        // someone is typing, and the dropdown takes the order back the
        // moment the box is cleared.
        const scored = [];
        for (const item of items) {
          const score = bookmarkMatchScore(item, needle);
          if (score !== null) scored.push({ item, score });
        }
        scored.sort((a, b) => b.score - a.score);
        return scored.map((entry) => entry.item);
      }
    }
    if (snapshotsView) {
      // A snapshot view is a recency lookup: keep the newest recorded
      // snapshot first, independent of the general bookmark sort control.
      items.sort(
        (a, b) => (b.digest_recorded_at || 0) - (a.digest_recorded_at || 0),
      );
      return items;
    }
    // Quick Access is itself a user-chosen ordering. The general manager
    // sort control must not make its filter view disagree with the tile row.
    if (quickView) return items;
    if (managerSort === "title") {
      items.sort((a, b) =>
        String(a.title || a.url || "").localeCompare(
          String(b.title || b.url || ""),
        ),
      );
    } else if (managerSort === "oldest") {
      items.sort((a, b) => (a.created_at || 0) - (b.created_at || 0));
    } else {
      items.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    }
    return items;
  }

  // ---- Quick Access, pinned at the top ----
  //
  // Rendered from EVERY pinned bookmark, never from the filtered list: the
  // sidebar, the search box and the sort must not be able to take it away.
  // That is the whole point of pinning something.
  function quickAccessDomIds(grid) {
    return Array.from(grid.children || [])
      .map((tile) => tile.dataset && tile.dataset.bookmarkId)
      .filter(Boolean);
  }

  function putQuickAccessDomInOrder(grid, ids) {
    const byId = new Map(
      Array.from(grid.children || []).map((tile) => [
        tile.dataset && tile.dataset.bookmarkId,
        tile,
      ]),
    );
    for (const id of ids) {
      const tile = byId.get(id);
      if (tile) grid.appendChild(tile);
    }
  }

  function previewQuickAccessReorder(grid, targetTile, ev) {
    const ids = quickAccessDomIds(grid);
    const box = targetTile.getBoundingClientRect();
    const pointer = typeof ev.clientX === "number" ? ev.clientX : box.left;
    const after = pointer >= box.left + box.width / 2;
    const next = reorderQuickAccessIds(
      ids,
      draggedBookmarkId,
      targetTile.dataset.bookmarkId,
      after,
    );
    putQuickAccessDomInOrder(grid, next);
    return next;
  }

  async function persistQuickAccessOrder(ids, focusId) {
    try {
      await rb("bookmark_quick_access_reorder", { ids });
    } catch (e) {
      // A preview is only DOM state. Put the authoritative cached order back
      // immediately when the store refuses the write.
      renderManagerQuick();
      toast(friendly(e), true);
      return;
    }
    await refreshOrganizerAfterWrite();
    if (focusId) {
      const tile = Array.from($("bmm-quick").children || []).find(
        (candidate) => candidate.dataset.bookmarkId === focusId,
      );
      if (tile) tile.focus();
    }
  }

  function renderManagerQuick() {
    const grid = $("bmm-quick");
    if (!grid) return;
    grid.textContent = "";
    const pinned = managerPinned();
    const empty = $("bmm-quick-empty");
    if (empty) empty.hidden = pinned.length > 0;
    for (const item of pinned) {
      const tile = el("button", "bmm-quick-item");
      tile.type = "button";
      tile.setAttribute("draggable", "true");
      tile.dataset.bookmarkId = item.id;
      tile.title =
        item.url + " -- Drag or use Left/Right arrow keys to reorder";
      tile.appendChild(makeLetterTile(item.url));
      tile.appendChild(
        el("span", "bmm-quick-name", item.title || hostOf(item.url)),
      );
      tile.addEventListener("click", async () => {
        try {
          await rb("bookmark_open", { id: item.id });
          if (openPanelName === "library") togglePanelNamed("library");
        } catch (e) {
          toast(friendly(e), true);
        }
      });
      tile.addEventListener("dragstart", (ev) => {
        draggedBookmarkId = item.id;
        tile.classList.add("dragging");
        if (ev.dataTransfer) {
          ev.dataTransfer.effectAllowed = "move";
          // Some engines require a payload to begin dragging. It is a fixed
          // word only: the id stays in the module flag and never crosses in
          // text/plain, where dropping into another app could disclose it.
          ev.dataTransfer.setData("text/plain", "bookmark");
        }
      });
      tile.addEventListener("dragover", (ev) => {
        const ids = quickAccessDomIds(grid);
        if (
          !draggedBookmarkId ||
          ids.indexOf(draggedBookmarkId) < 0 ||
          draggedBookmarkId === item.id
        ) {
          return;
        }
        ev.preventDefault();
        if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
        previewQuickAccessReorder(grid, tile, ev);
      });
      tile.addEventListener("drop", (ev) => {
        const ids = quickAccessDomIds(grid);
        if (!draggedBookmarkId || ids.indexOf(draggedBookmarkId) < 0) return;
        ev.preventDefault();
        const next = previewQuickAccessReorder(grid, tile, ev);
        draggedBookmarkId = null;
        persistQuickAccessOrder(next);
      });
      tile.addEventListener("dragend", () => {
        draggedBookmarkId = null;
        for (const candidate of grid.querySelectorAll(".dragging")) {
          candidate.classList.remove("dragging");
        }
      });
      tile.addEventListener("keydown", (ev) => {
        if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
        const ids = quickAccessDomIds(grid);
        const from = ids.indexOf(item.id);
        const to = from + (ev.key === "ArrowLeft" ? -1 : 1);
        if (from < 0 || to < 0 || to >= ids.length) return;
        ev.preventDefault();
        const next = ids.slice();
        [next[from], next[to]] = [next[to], next[from]];
        putQuickAccessDomInOrder(grid, next);
        persistQuickAccessOrder(next, item.id);
      });
      grid.appendChild(tile);
    }
  }

  function renderManagerSidebar() {
    const nav = $("bmm-folders");
    if (!nav) return;
    nav.textContent = "";
    const entries = [
      { key: "all", label: i18nText("chrome-js-folders-source-head", "All bookmarks"), count: bookmarkItems.length },
      { key: "quick", label: i18nText("chrome-js-manager-sidebar-quick", "Quick Access"), count: managerPinned().length },
      {
        key: "snapshots",
        label: i18nText("chrome-js-manager-sidebar-snapshots", "Snapshots"),
        count: managerSnapshotCount(),
      },
    ];
    for (const folder of allFolders()) {
      entries.push({
        key: folder.tag,
        label: folder.tag,
        count: folder.items.length,
        droppable: true,
      });
    }
    entries.push({
      key: "unfiled",
      label: i18nText("chrome-js-manager-sidebar-unfiled", "Unfiled"),
      count: managerUnfiled().length,
    });
    // The other two things this panel now holds. Below the folders and
    // marked apart, because they are not bookmarks and filing a bookmark
    // into "Downloads" would make no sense: they are deliberately NOT
    // drop targets.
    entries.push({
      key: "shelves",
      label: i18nText("chrome-js-manager-sidebar-shelves", "Tab Shelf"),
      count: shelfCount(),
      separated: true,
    });
    entries.push({
      key: "downloads",
      label: i18nText("chrome-js-manager-sidebar-downloads", "Downloads"),
      count: downloadItems.length,
    });

    for (const entry of entries) {
      const btn = el("button", "bmm-side");
      btn.type = "button";
      if (entry.separated) btn.classList.add("bmm-side-break");
      const selected = managerSelected === entry.key;
      // Both a class and the ARIA state: the class is the styling contract,
      // the attribute is what a screen reader announces.
      btn.classList.toggle("selected", selected);
      if (selected) btn.setAttribute("aria-current", "true");
      btn.appendChild(el("span", "bmm-side-label", entry.label));
      btn.appendChild(el("span", "bmm-side-count", String(entry.count)));
      btn.addEventListener("click", () => {
        managerSelected = entry.key;
        closeFoldersPopover();
        renderBookmarksManager();
      });
      if (entry.droppable) {
        const accept = (ev) => {
          if (!draggedBookmarkId) return;
          ev.preventDefault();
          if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
          btn.classList.add("drop-hover");
        };
        btn.addEventListener("dragover", accept);
        btn.addEventListener("dragenter", accept);
        btn.addEventListener("dragleave", () =>
          btn.classList.remove("drop-hover"),
        );
        btn.addEventListener("drop", (ev) => {
          if (!draggedBookmarkId) return;
          ev.preventDefault();
          btn.classList.remove("drop-hover");
          fileDraggedInto(entry.key);
        });
      }
      nav.appendChild(btn);
    }
  }

  function renderManagerCards() {
    const wrap = $("bmm-cards");
    if (!wrap) return;
    wrap.textContent = "";
    // INSIDE a folder, show that folder's own controls. The cards below only
    // render on the overview, so selecting a folder in the sidebar left
    // nothing anywhere that could rename or delete it: the folder you were
    // looking at was the one folder you could not act on.
    const knownNames = allFolders().map((f) => f.tag);
    if (knownNames.indexOf(managerSelected) >= 0) {
      const bar = el("div", "bmm-folder-bar");
      if (managerRenamingFolder === managerSelected) {
        const form = el("form", "bmm-card-rename");
        const input = document.createElement("input");
        input.type = "text";
        input.maxLength = 40;
        input.value = managerSelected;
        input.setAttribute("aria-label", i18nText("chrome-js-folders-rename-aria", "Rename folder"));
        form.appendChild(input);
        const save = el("button", "small", i18nText("chrome-js-folders-save", "Save"));
        save.type = "submit";
        form.appendChild(save);
        const cancel = el("button", "small", i18nText("chrome-js-folders-cancel", "Cancel"));
        cancel.type = "button";
        cancel.addEventListener("click", () => {
          managerRenamingFolder = null;
          renderBookmarksManager();
        });
        form.appendChild(cancel);
        const target = managerSelected;
        form.addEventListener("submit", (ev) => {
          ev.preventDefault();
          managerRenameFolder(target, input.value);
        });
        bar.appendChild(form);
        wrap.appendChild(bar);
        input.focus();
        input.select();
        return;
      }
      bar.appendChild(makeTile(managerSelected));
      bar.appendChild(
        el(
          "span",
          "bmm-folder-name",
          managerSelected + " (" + folderMembers(managerSelected).length + ")",
        ),
      );
      const rename = el("button", "small", i18nText("chrome-js-manager-rename", "Rename"));
      rename.type = "button";
      rename.addEventListener("click", () => {
        managerRenamingFolder = managerSelected;
        renderBookmarksManager();
      });
      bar.appendChild(rename);
      const del = el("button", "small danger", i18nText("chrome-js-folders-delete-folder", "Delete folder"));
      del.type = "button";
      del.title = i18nText("chrome-js-folders-delete-title", "Removes the folder. The bookmarks in it are kept.");
      const target = managerSelected;
      del.addEventListener("click", () => managerDeleteFolder(target));
      bar.appendChild(del);
      wrap.appendChild(bar);
      return;
    }
    // Folder cards belong to the overview.
    if (managerSelected !== "all") return;
    for (const folder of allFolders()) {
      const card = el("div", "bmm-card");
      const accept = (ev) => {
        if (!draggedBookmarkId) return;
        ev.preventDefault();
        if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
        card.classList.add("drop-hover");
      };
      card.addEventListener("dragover", accept);
      card.addEventListener("dragenter", accept);
      card.addEventListener("dragleave", () =>
        card.classList.remove("drop-hover"),
      );
      card.addEventListener("drop", (ev) => {
        if (!draggedBookmarkId) return;
        ev.preventDefault();
        card.classList.remove("drop-hover");
        fileDraggedInto(folder.tag);
      });

      if (managerRenamingFolder === folder.tag) {
        const form = el("form", "bmm-card-rename");
        const input = document.createElement("input");
        input.type = "text";
        input.maxLength = 40;
        input.value = folder.tag;
        input.setAttribute("aria-label", i18nText("chrome-js-folders-rename-aria", "Rename folder"));
        form.appendChild(input);
        const save = el("button", "small", i18nText("chrome-js-folders-save", "Save"));
        save.type = "submit";
        form.appendChild(save);
        const cancel = el("button", "small", i18nText("chrome-js-folders-cancel", "Cancel"));
        cancel.type = "button";
        cancel.addEventListener("click", () => {
          managerRenamingFolder = null;
          renderBookmarksManager();
        });
        form.appendChild(cancel);
        form.addEventListener("submit", (ev) => {
          ev.preventDefault();
          managerRenameFolder(folder.tag, input.value);
        });
        card.appendChild(form);
        wrap.appendChild(card);
        input.focus();
        input.select();
        continue;
      }

      const head = el("button", "bmm-card-head");
      head.type = "button";
      head.appendChild(makeTile(folder.tag));
      head.appendChild(
        el("span", null, folder.tag + " (" + folder.items.length + ")"),
      );
      head.addEventListener("click", () => {
        managerSelected = folder.tag;
        closeFoldersPopover();
        renderBookmarksManager();
      });
      card.appendChild(head);

      const actions = el("div", "bmm-card-actions");
      const rename = el("button", "small", i18nText("chrome-js-manager-rename", "Rename"));
      rename.type = "button";
      rename.addEventListener("click", () => {
        managerRenamingFolder = folder.tag;
        renderBookmarksManager();
      });
      actions.appendChild(rename);
      const del = el("button", "small danger", i18nText("chrome-js-folders-delete-folder", "Delete folder"));
      del.type = "button";
      // Named for machines too, so the gate clicks the ACTION rather than
      // the English label.
      del.dataset.action = "delete-folder";
      del.title = i18nText("chrome-js-folders-delete-title", "Removes the folder. The bookmarks in it are kept.");
      del.addEventListener("click", () => managerDeleteFolder(folder.tag));
      actions.appendChild(del);
      card.appendChild(actions);
      wrap.appendChild(card);
    }
  }

  function rememberSnapshotCheck(data, errorCode) {
    const id = data && data.bookmark_id;
    if (!id) return;
    snapshotChecksPending.delete(id);
    snapshotCheckResults.set(id, {
      snapshot_id: data.snapshot_id || snapshotSelections.get(id) || null,
      data: errorCode ? null : data,
      error: errorCode ? friendly({ message: errorCode }) : null,
    });
    if (managerSelected === "snapshots") renderManagerList();
  }

  function appendPassageGroup(parent, label, passages, className) {
    if (!Array.isArray(passages) || !passages.length) return;
    parent.appendChild(el("div", "bmm-diff-label", label));
    for (const passage of passages) {
      const passageEl = el("div", "bmm-diff-passage", passage);
      passageEl.classList.add(className);
      parent.appendChild(passageEl);
    }
  }

  function renderSnapshotCheckResult(item, snapshotId) {
    const wrap = el("div", "bmm-snapshot-result");
    const remembered = snapshotCheckResults.get(item.id);
    if (!remembered || remembered.snapshot_id !== snapshotId) {
      wrap.hidden = true;
      return wrap;
    }
    if (remembered.error) {
      wrap.classList.add("error");
      wrap.appendChild(el("div", "bmm-snapshot-verdict", remembered.error));
      return wrap;
    }
    const data = remembered.data || {};
    let headline;
    // The similarity branch is the only one carrying an argument, so it paints
    // through i18nSet on its own node; the other two are whole sentences.
    const pct =
      typeof data.similarity === "number"
        ? Math.round(data.similarity * 100)
        : 0;
    if (data.verdict === "identical") {
      headline = i18nText("chrome-js-snapshot-identical", "Matches this snapshot.");
    } else if (data.verdict === "structure_differs") {
      headline = i18nText("chrome-js-snapshot-structure", "The words match; the page markup changed.");
    } else {
      headline = null;
    }
    const verdictEl = el("div", "bmm-snapshot-verdict", headline || "");
    if (headline === null) {
      i18nSet(verdictEl, "chrome-js-snapshot-similarity", { pct },
        "The visible text changed; about " + pct + "% still matches.");
    }
    wrap.appendChild(verdictEl);
    const evidence = data.text_comparison || {};
    if (evidence.available !== true) {
      wrap.appendChild(
        el(
          "div",
          "bmm-diff-note",
          "Text comparison is unavailable for this snapshot because it was saved before this browser started keeping snapshot text.",
        ),
      );
      return wrap;
    }
    appendPassageGroup(wrap, "Removed", evidence.removed, "removed");
    appendPassageGroup(wrap, "Added", evidence.added, "added");
    if (
      (!Array.isArray(evidence.removed) || evidence.removed.length === 0) &&
      (!Array.isArray(evidence.added) || evidence.added.length === 0)
    ) {
      wrap.appendChild(
        el("div", "bmm-diff-note", i18nText("chrome-js-diff-none", "No visible-text passages changed.")),
      );
    }
    if (evidence.output_trimmed === true) {
      wrap.appendChild(
        el(
          "div",
          "bmm-diff-note",
          "The diff was trimmed to keep this result readable.",
        ),
      );
    }
    if (
      evidence.saved_text_trimmed === true ||
      evidence.current_text_trimmed === true
    ) {
      wrap.appendChild(
        el(
          "div",
          "bmm-diff-note",
          "The page text reached the 100,000-character snapshot limit, so this diff covers the stored portion.",
        ),
      );
    }
    return wrap;
  }

  function managerRow(item) {
    const li = el("li", "bmm-row");
    li.setAttribute("draggable", "true");
    let selectedSnapshot = null;

    const tick = document.createElement("input");
    tick.type = "checkbox";
    tick.checked = managerSelection.has(item.id);
    tick.setAttribute("aria-label", "Select " + (item.title || item.url));
    tick.addEventListener("change", () => {
      if (tick.checked) managerSelection.add(item.id);
      else managerSelection.delete(item.id);
      renderManagerBatch();
    });
    li.appendChild(tick);

    li.appendChild(makeLetterTile(item.url));

    const meta = el("div", "bmm-meta");
    meta.appendChild(el("span", "bmm-title", item.title || hostOf(item.url)));
    meta.appendChild(el("span", "bmm-url", item.url));
    if (managerSelected === "snapshots" && item.has_digest === true) {
      const snapshots = Array.isArray(item.snapshots) ? item.snapshots : [];
      // Hold the node rather than reaching for meta.lastChild: the element is
      // ours already, and lastChild is one more assumption about the DOM.
      const takenEl = el("div", "item-sub", "");
      i18nSet(takenEl, "chrome-js-snapshot-taken", { when: fmtTime(item.digest_recorded_at) },
        "Page snapshot from " + fmtTime(item.digest_recorded_at));
      meta.appendChild(takenEl);
      meta.appendChild(
        el(
          "div",
          "item-sub",
          snapshots.length +
            (snapshots.length === 1 ? " saved snapshot" : " saved snapshots"),
        ),
      );
      const picker = document.createElement("select");
      picker.className = "bmm-snapshot-picker";
      picker.setAttribute(
        "aria-label",
        "Saved snapshot for " + (item.title || item.url),
      );
      let selected = snapshotSelections.get(item.id);
      if (!snapshots.some((snapshot) => snapshot.id === selected)) {
        selected = snapshots.length ? snapshots[0].id : "";
        snapshotSelections.set(item.id, selected);
      }
      for (const snapshot of snapshots) {
        const option = document.createElement("option");
        option.value = snapshot.id;
        option.textContent = fmtTime(snapshot.recorded_at);
        picker.appendChild(option);
      }
      picker.value = selected;
      selectedSnapshot =
        snapshots.find((snapshot) => snapshot.id === selected) || null;
      picker.addEventListener("change", () => {
        snapshotSelections.set(item.id, picker.value);
        renderManagerList();
      });
      meta.appendChild(picker);
      if (!selectedSnapshot || selectedSnapshot.has_picture !== true) {
        meta.appendChild(el("div", "item-sub", i18nText("chrome-js-snapshot-picture-none", "Picture unavailable.")));
      }
    }
    li.appendChild(meta);

    if (Array.isArray(item.tags) && item.tags.length) {
      const chips = el("div", "bmm-chips");
      for (const tag of item.tags)
        chips.appendChild(el("span", "bmm-chip", tag));
      li.appendChild(chips);
    }

    const actions = el("div", "bmm-actions");

    if (managerSelected === "snapshots" && item.has_digest === true) {
      if (selectedSnapshot && selectedSnapshot.has_picture === true) {
        const view = el("button", "small", i18nText("chrome-js-manager-view-picture", "View picture"));
        view.type = "button";
        view.addEventListener("click", async () => {
          await openStoredPicture(
            li,
            "snapshot",
            "snapshot_picture_stage",
            selectedSnapshot,
            (message) => {
              if (message) toast(message, true);
            },
          );
        });
        actions.appendChild(view);
      }
      const check = el("button", "small", i18nText("chrome-js-manager-check-changes", "Check for changes"));
      check.type = "button";
      check.disabled = snapshotChecksPending.has(item.id);
      check.addEventListener("click", async () => {
        const snapshotId = snapshotSelections.get(item.id);
        snapshotChecksPending.add(item.id);
        snapshotCheckResults.delete(item.id);
        renderManagerList();
        try {
          await rb("integrity_check_bookmark", {
            id: item.id,
            snapshot_id: snapshotId,
          });
        } catch (error) {
          rememberSnapshotCheck(
            { bookmark_id: item.id, snapshot_id: snapshotId },
            error && error.message ? error.message : String(error),
          );
        }
      });
      actions.appendChild(check);
    }

    const foldersBtn = el("button", "small", i18nText("chrome-js-manager-folders-button", "Folders"));
    foldersBtn.type = "button";
    foldersBtn.setAttribute(
      "aria-expanded",
      String(foldersPopoverFor === item.id),
    );
    foldersBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      if (foldersPopoverFor === item.id) {
        closeFoldersPopover();
        foldersBtn.focus();
        return;
      }
      foldersPopoverFor = item.id;
      syncFoldersPopover();
    });
    actions.appendChild(foldersBtn);

    const pin = el("button", "small", item.quick_access ? i18nText("chrome-js-manager-unpin", "Unpin") : i18nText("chrome-js-manager-pin", "Pin"));
    pin.type = "button";
    pin.title = item.quick_access
      ? i18nText("chrome-js-manager-pin-title-off", "Remove from Quick Access")
      : i18nText("chrome-js-manager-pin-title-on", "Put this in Quick Access at the top");
    pin.addEventListener("click", async () => {
      try {
        await rb("bookmark_quick_access_set", {
          id: item.id,
          on: !item.quick_access,
        });
      } catch (e) {
        toast(friendly(e), true);
        return;
      }
      await refreshOrganizerAfterWrite();
    });
    actions.appendChild(pin);

    // Edit lived only on the old flat rows. Without it here a bookmark's
    // address and name would become uneditable once that list went away.
    const edit = el("button", "small", i18nText("chrome-js-creds-edit", "Edit"));
    edit.type = "button";
    edit.addEventListener("click", () => {
      editingBookmark = item.id;
      $("bookmark-url").value = item.url || "";
      $("bookmark-title").value = item.title || "";
      $("bookmark-tags").value = Array.isArray(item.tags)
        ? item.tags.join(", ")
        : "";
      $("bookmark-error").textContent = "";
      $("bookmark-form").hidden = false;
      $("bookmark-url").focus();
    });
    actions.appendChild(edit);

    const copy = el("button", "small", i18nText("chrome-js-manager-copy-url", "Copy URL"));
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(item.url);
        toast(i18nText("chrome-js-manager-address-copied", "Address copied."));
      } catch (e) {
        toast(friendly(e), true);
      }
    });
    actions.appendChild(copy);

    const open = el("button", "small", i18nText("chrome-js-bookmarks-open", "Open"));
    open.type = "button";
    open.addEventListener("click", async () => {
      try {
        await rb("bookmark_open", { id: item.id });
        if (openPanelName === "library") togglePanelNamed("library");
      } catch (e) {
        toast(friendly(e), true);
      }
    });
    actions.appendChild(open);

    const del = el("button", "small danger", i18nText("chrome-js-confirm-default-label", "Delete"));
    del.type = "button";
    del.addEventListener("click", async () => {
      const ok = await askConfirm(
        "Delete bookmark " + (item.title || item.url) + "?",
      );
      if (!ok) return;
      try {
        await rb("bookmark_delete", { id: item.id });
      } catch (e) {
        toast(friendly(e), true);
        return;
      }
      if (foldersPopoverFor === item.id) closeFoldersPopover();
      await refreshOrganizerAfterWrite();
    });
    actions.appendChild(del);

    li.appendChild(actions);

    if (managerSelected === "snapshots" && item.has_digest === true) {
      li.appendChild(
        renderSnapshotCheckResult(item, snapshotSelections.get(item.id)),
      );
    }

    li.addEventListener("dragstart", (ev) => {
      draggedBookmarkId = item.id;
      li.classList.add("dragging");
      if (ev.dataTransfer) {
        ev.dataTransfer.effectAllowed = "copy";
        // A payload is set because some engines refuse to start a drag
        // without one, but it is a CONSTANT. Neither the bookmark's id nor
        // its title rides in text/plain: if this drag ends in another
        // application, nothing about what the user has saved goes with it.
        ev.dataTransfer.setData("text/plain", "bookmark");
      }
    });
    li.addEventListener("dragend", () => {
      draggedBookmarkId = null;
      li.classList.remove("dragging");
    });

    return li;
  }

  function renderManagerList() {
    const list = $("bmm-list");
    if (!list) return;
    if (recallPreviewOwner === "snapshot") recallPreviewClose();
    list.textContent = "";
    const items = managerVisibleItems();
    const snapshotCaption = $("bmm-snapshots-caption");
    snapshotCaption.textContent =
      "A snapshot keeps hashes, visible text, and a picture of the page when capture succeeds. Check for changes compares the page as it is now with what you saved.";
    snapshotCaption.hidden = managerSelected !== "snapshots";
    const empty = $("bmm-empty");
    if (empty) {
      empty.hidden = items.length > 0;
      if (!items.length) {
        if (managerSelected === "snapshots" && !managerSnapshots().length) {
          empty.textContent = i18nText("chrome-js-manager-empty-snapshots", "No snapshots yet. Open Integrity, then save one in Page integrity.");
        } else {
          empty.textContent = bookmarkItems.length
            ? i18nText("chrome-js-manager-empty-match", "Nothing here matches.")
            : i18nText("chrome-js-manager-empty-none", "No bookmarks yet. Add one above, or use the bookmark button on a page.");
        }
      }
    }
    for (const item of items) list.appendChild(managerRow(item));
  }

  function renderManagerBatch() {
    const bar = $("bmm-batch");
    if (!bar) return;
    bar.textContent = "";
    const ids = Array.from(managerSelection);
    bar.hidden = ids.length === 0;
    if (!ids.length) return;

    bar.appendChild(el("span", "bmm-batch-count", ids.length + " selected"));

    const folderNames = allFolders().map((f) => f.tag);
    const pick = document.createElement("select");
    pick.setAttribute("aria-label", i18nText("chrome-js-manager-batch-pick-aria", "Folder for the selected bookmarks"));
    if (!folderNames.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = i18nText("chrome-js-manager-batch-no-folders", "No folders yet");
      pick.appendChild(opt);
      pick.disabled = true;
    }
    for (const name of folderNames) {
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = name;
      pick.appendChild(opt);
    }
    bar.appendChild(pick);

    const mk = (label, run) => {
      const b = el("button", "small", label);
      b.type = "button";
      b.disabled = managerBatchBusy;
      b.addEventListener("click", run);
      bar.appendChild(b);
      return b;
    };

    mk(i18nText("chrome-js-manager-batch-add", "Add to folder"), () => {
      if (!pick.value) return;
      runBatch(ids, (id) =>
        rb("bookmark_folder_file", { id, folder: pick.value }),
      );
    });
    mk(i18nText("chrome-js-manager-batch-remove", "Remove from folder"), () => {
      if (!pick.value) return;
      runBatch(ids, (id) =>
        rb("bookmark_folder_unfile", { id, folder: pick.value }),
      );
    });
    mk(i18nText("chrome-js-manager-pin", "Pin"), () =>
      runBatch(ids, (id) => rb("bookmark_quick_access_set", { id, on: true })),
    );
    mk(i18nText("chrome-js-manager-unpin", "Unpin"), () =>
      runBatch(ids, (id) => rb("bookmark_quick_access_set", { id, on: false })),
    );
    mk(i18nText("chrome-js-confirm-default-label", "Delete"), async () => {
      const ok = await askConfirm(
        "Delete " +
          ids.length +
          " bookmark" +
          (ids.length === 1 ? "" : "s") +
          "?",
      );
      if (!ok) return;
      runBatch(ids, (id) => rb("bookmark_delete", { id }));
    });
    const clear = el("button", "small", i18nText("chrome-js-manager-batch-clear", "Clear selection"));
    clear.type = "button";
    clear.disabled = managerBatchBusy;
    clear.addEventListener("click", () => {
      managerSelection.clear();
      renderBookmarksManager();
    });
    bar.appendChild(clear);
  }

  /// Runs one operation over every selected bookmark, in order, and reports
  /// honestly. A partial failure keeps ONLY the failed ids selected, so the
  /// user can see what did not happen and try again on exactly those.
  async function runBatch(ids, op) {
    if (managerBatchBusy) return;
    managerBatchBusy = true;
    renderManagerBatch(); // disable the bar while this runs
    const failed = [];
    for (const id of ids) {
      try {
        await op(id);
      } catch (_) {
        failed.push(id);
      }
    }
    managerSelection.clear();
    for (const id of failed) managerSelection.add(id);
    managerBatchBusy = false;
    if (failed.length) {
      i18nResolve(
        "chrome-js-batch-partial-failure",
        { failed: failed.length, total: ids.length },
        failed.length + " of " + ids.length + " could not be changed.",
      ).then((t) => toast(t, true));
    }
    closeFoldersPopover();
    await refreshOrganizerAfterWrite();
  }

  // ---- the Folders popover: the click path that replaces dragging ----

  function closeFoldersPopover() {
    foldersPopoverFor = null;
    popoverRefocusFolder = null;
    const open = document.querySelector(".bmm-popover");
    if (open) open.remove();
  }

  /// Rebuilds the popover from CURRENT state and re-anchors it to the row it
  /// belongs to. Called after every render, so a refresh underneath it (a
  /// folder renamed, a bookmark deleted elsewhere) can never leave it
  /// pointing at a node that is no longer in the document.
  function syncFoldersPopover() {
    const existing = document.querySelector(".bmm-popover");
    if (existing) existing.remove();
    if (!foldersPopoverFor) return;
    const panel = $("bookmarks-panel");
    const item = bookmarkItems.find((b) => b.id === foldersPopoverFor);
    if (!panel || !item) {
      // The bookmark is gone. Close rather than float over nothing.
      foldersPopoverFor = null;
      return;
    }
    // Find the row still showing this bookmark; if the current filter no
    // longer includes it, there is nothing to anchor to.
    const list = $("bmm-list");
    let anchor = null;
    const visible = managerVisibleItems();
    const index = visible.findIndex((b) => b.id === item.id);
    if (list && index >= 0 && list.children[index]) {
      const row = list.children[index];
      const actions = row.children[row.children.length - 1];
      if (actions && actions.children.length) anchor = actions.children[0];
    }
    if (!anchor) {
      foldersPopoverFor = null;
      return;
    }

    const pop = el("div", "bmm-popover");
    pop.appendChild(el("div", "bmm-pop-title", item.title || hostOf(item.url)));
    const names = allFolders().map((f) => f.tag);
    if (!names.length) {
      pop.appendChild(
        el("div", "bmm-pop-row", i18nText("chrome-js-manager-popover-no-folders", "No folders yet. Make one below.")),
      );
    }
    for (const name of names) {
      const row = el("label", "bmm-pop-row");
      const box = document.createElement("input");
      box.type = "checkbox";
      const inIt = Array.isArray(item.tags) && item.tags.indexOf(name) >= 0;
      box.checked = inIt;
      box.disabled = folderOpsPending.has(item.id + "|" + name);
      box.addEventListener("change", () =>
        toggleFolderFor(item.id, name, box.checked, box),
      );
      row.appendChild(box);
      row.appendChild(el("span", null, name));
      pop.appendChild(row);
      if (popoverRefocusFolder === name) box.focus();
    }

    // Create a folder and file this bookmark into it, in one step.
    const form = el("form", "bmm-pop-new");
    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 40;
    input.placeholder = i18nText("chrome-js-manager-popover-new-placeholder", "New folder");
    input.setAttribute("aria-label", i18nText("chrome-js-manager-popover-new-aria", "New folder name"));
    form.appendChild(input);
    const add = el("button", "small", i18nText("chrome-js-manager-popover-add", "Add"));
    add.type = "submit";
    form.appendChild(add);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      createFolderAndFile(item.id, input.value);
    });
    pop.appendChild(form);

    pop.addEventListener("click", (ev) => ev.stopPropagation());
    panel.appendChild(pop);

    // Positioned against the PANEL, which is the containing block (it is
    // position:fixed), and offset by its scroll so the popover travels with
    // the row rather than detaching when the panel is scrolled.
    const panelBox = panel.getBoundingClientRect();
    const anchorBox = anchor.getBoundingClientRect();
    pop.style.left = Math.max(8, anchorBox.left - panelBox.left) + "px";
    pop.style.top =
      anchorBox.bottom - panelBox.top + (panel.scrollTop || 0) + 4 + "px";

    if (popoverRefocusFolder === null) {
      const first = pop.querySelector("input");
      if (first) first.focus();
    }
    popoverRefocusFolder = null;
  }

  /// One checkbox, one atomic call. Never `bookmark_tags_set`: that would
  /// write the whole list from a client snapshot, so two quick toggles would
  /// each overwrite the other. `file`/`unfile` add or remove exactly one tag
  /// against the store's own current tags.
  async function toggleFolderFor(id, folder, wanted, box) {
    const key = id + "|" + folder;
    if (folderOpsPending.has(key)) return;
    folderOpsPending.add(key);
    if (box) box.disabled = true;
    popoverRefocusFolder = folder;
    try {
      await rb(wanted ? "bookmark_folder_file" : "bookmark_folder_unfile", {
        id,
        folder,
      });
    } catch (e) {
      toast(friendly(e), true);
      // Put the box back the way it was; nothing was written.
      if (box) {
        box.checked = !wanted;
        box.disabled = false;
      }
      folderOpsPending.delete(key);
      return;
    }
    folderOpsPending.delete(key);
    // Re-enable BEFORE the refresh: if the reload fails, the checkbox must
    // still be usable rather than staying dead until the popover is reopened.
    if (box) box.disabled = false;
    await refreshOrganizerAfterWrite();
  }

  async function createFolderAndFile(id, raw) {
    const name = (raw || "").trim();
    if (!name) return;
    let created = null;
    try {
      created = await rb("bookmark_folder_create", { name });
    } catch (e) {
      toast(friendly(e), true);
      return;
    }
    const folder = (created && created.name) || name.toLowerCase();
    try {
      await rb("bookmark_folder_file", { id, folder });
    } catch (e) {
      // The FOLDER WAS created even though the filing failed. Refresh anyway
      // or it exists on disk and is invisible here, which reads as the whole
      // action having failed.
      const detail = friendly(e);
      i18nResolve(
        "chrome-js-folders-file-failed",
        { detail },
        "Folder made, but filing failed: " + detail,
      ).then((t) => toast(t, true));
      await refreshOrganizerAfterWrite();
      return;
    }
    popoverRefocusFolder = folder;
    await refreshOrganizerAfterWrite();
  }

  async function managerRenameFolder(from, raw) {
    const to = (raw || "").trim();
    if (!to || to === from) {
      managerRenamingFolder = null;
      renderBookmarksManager();
      return;
    }
    try {
      await rb("bookmark_folder_rename", { from, to });
    } catch (e) {
      toast(friendly(e), true);
      return;
    }
    const normalised = to.toLowerCase();
    if (managerSelected === from) managerSelected = normalised;
    managerRenamingFolder = null;
    await refreshOrganizerAfterWrite();
  }

  async function managerDeleteFolder(name) {
    const ok = await askConfirm(
      await i18nResolve(
        "chrome-manager-delete-folder",
        { name },
        "Delete the folder “" + name + "”? The bookmarks in it are kept, " +
          "just no longer filed under it.",
      ),
    );
    if (!ok) return;
    try {
      await rb("bookmark_folder_delete", { name });
    } catch (e) {
      toast(friendly(e), true);
      return;
    }
    if (managerSelected === name) managerSelected = "all";
    await refreshOrganizerAfterWrite();
  }

  /// Add a bookmark by typing its address. Rust normalises it (so
  /// "example.com" is enough) and refuses anything the browser would not
  /// navigate to; this side only reports what came back.
  async function managerAddByHand() {
    const urlField = $("bmm-add-url");
    const titleField = $("bmm-add-title");
    const errline = $("bmm-add-error");
    if (!urlField) return;
    const url = (urlField.value || "").trim();
    if (errline) errline.hidden = true;
    if (!url) {
      if (errline) {
        errline.textContent = i18nText("chrome-js-manager-add-empty", "Type an address first.");
        errline.hidden = false;
      }
      return;
    }
    try {
      await rb("bookmark_add", {
        url,
        title: (titleField && titleField.value) || "",
      });
    } catch (e) {
      if (errline) {
        errline.textContent =
          e && String(e.message) === "bad_args"
            ? i18nText("chrome-js-manager-add-bad-args", "That is not an address this browser can open.")
            : friendly(e);
        errline.hidden = false;
      }
      return;
    }
    urlField.value = "";
    if (titleField) titleField.value = "";
    await refreshOrganizerAfterWrite();
  }

  function renderBookmarksManager() {
    const list = $("bmm-list");
    if (!list) return; // a build without the manager markup
    // Prune the selection against what the store actually holds, so the batch
    // bar can never claim a bookmark that has been deleted elsewhere.
    const live = new Set(bookmarkItems.map((b) => b.id));
    for (const id of Array.from(managerSelection)) {
      if (!live.has(id)) managerSelection.delete(id);
    }
    // The folder the sidebar is filtered on can vanish underneath us (renamed
    // or deleted from the Library organizer). Fall back to everything rather
    // than showing an unexplained empty list.
    const known = allFolders().map((f) => f.tag);
    if (
      managerSelected !== "all" &&
      managerSelected !== "quick" &&
      managerSelected !== "snapshots" &&
      managerSelected !== "partnerships" &&
      managerSelected !== "unfiled" &&
      managerSelected !== "shelves" &&
      managerSelected !== "downloads" &&
      known.indexOf(managerSelected) < 0
    ) {
      managerSelected = "all";
    }
    // Only one view is on screen at a time, and the bookmarks-only chrome
    // above (add-by-hand, Quick Access, search and sort) steps aside with it:
    // searching bookmarks while looking at downloads would be furniture.
    const view =
      managerSelected === "downloads"
        ? "downloads"
        : managerSelected === "shelves"
          ? "shelves"
          : managerSelected === "partnerships"
            ? "partnerships"
            : "bookmarks";
    const top = $("bmm-bookmarks-top");
    if (top) top.hidden = view !== "bookmarks" && view !== "partnerships";
    const tools = $("bmm-bookmark-tools");
    if (tools) tools.hidden = view !== "bookmarks";
    const partnershipsButton = $("btn-partnerships");
    if (partnershipsButton) {
      const selected = view === "partnerships";
      partnershipsButton.classList.toggle("active", selected);
      partnershipsButton.setAttribute("aria-pressed", String(selected));
    }
    const sort = $("bmm-sort");
    if (sort) {
      // Snapshot recency and Quick Access's manual positions are each the
      // view's purpose, so disable unrelated bookmark sort choices there.
      sort.disabled =
        managerSelected === "snapshots" || managerSelected === "quick";
    }
    for (const [name, id] of [
      ["bookmarks", "bmm-view-bookmarks"],
      ["shelves", "bmm-view-shelves"],
      ["downloads", "bmm-view-downloads"],
      ["partnerships", "bmm-view-partnerships"],
    ]) {
      const node = $(id);
      if (node) node.hidden = view !== name;
    }
    if (view !== "bookmarks") closeFoldersPopover();

    renderManagerQuick();
    renderManagerSidebar();
    renderManagerCards();
    renderManagerList();
    renderManagerBatch();
    if (view === "partnerships") void refreshPartnerLibrary();
    // LAST, and always: the popover is re-anchored to the rebuilt rows. Any
    // path that re-renders without this leaves it pointing at a detached node.
    syncFoldersPopover();
  }

  if ($("btn-partnerships")) {
    $("partner-library-framing").textContent =
      "Services PATANYX partners with. Each is labeled where it appears, " +
      "and PATANYX may earn a commission.";
    $("btn-partnerships").addEventListener("click", () => {
      managerSelected =
        managerSelected === "partnerships" ? "all" : "partnerships";
      closeFoldersPopover();
      renderBookmarksManager();
    });
  }

  if ($("bmm-add")) {
    $("bmm-add").addEventListener("click", () => managerAddByHand());
  }
  if ($("bmm-add-url")) {
    $("bmm-add-url").addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter") return;
      ev.preventDefault();
      managerAddByHand();
    });
  }
  if ($("bmm-search")) {
    $("bmm-search").addEventListener("input", (ev) => {
      managerQuery = ev.target.value || "";
      // The whole manager, not just the list: the rows are rebuilt, so the
      // popover has to be re-anchored with them.
      renderBookmarksManager();
    });
  }
  if ($("bmm-sort")) {
    $("bmm-sort").addEventListener("change", (ev) => {
      managerSort = ev.target.value || "newest";
      renderBookmarksManager();
    });
  }
  if ($("bmm-new-folder-add")) {
    const addFolder = async () => {
      const field = $("bmm-new-folder");
      const errline = $("bmm-folder-error");
      const name = (field.value || "").trim();
      if (errline) errline.hidden = true;
      if (!name) {
        if (errline) {
          errline.textContent = i18nText("chrome-js-folders-new-empty", "Type a folder name first.");
          errline.hidden = false;
        }
        return;
      }
      try {
        await rb("bookmark_folder_create", { name });
      } catch (e) {
        if (errline) {
          errline.textContent = friendly(e);
          errline.hidden = false;
        }
        return;
      }
      field.value = "";
      await refreshOrganizerAfterWrite();
    };
    $("bmm-new-folder-add").addEventListener("click", addFolder);
    // Delete the whole manager. The confirmation is the feature: it names
    // the exact counts the user is about to lose, says "permanently", and
    // says there is no undo -- because there is not one, and there is no
    // bookmark export to fall back on either.
    //
    // askConfirm focuses Cancel and answers false on Escape, so a stray
    // keypress lands on the safe answer. The confirm button says what it
    // does rather than "OK".
    if ($("bmm-delete-all")) {
      $("bmm-delete-all").addEventListener("click", async () => {
        const errline = $("bmm-folder-error");
        if (errline) errline.hidden = true;
        // Counted from what is loaded, so the question names what the user
        // is looking at rather than a number from somewhere else.
        const marks = Array.isArray(bookmarkItems) ? bookmarkItems.length : 0;
        // allFolders(), not bookmarkFolderNames: the grid renders the UNION
        // of named folders and tag-only folders (created through
        // bookmark_tags_set), so counting only the former asked about two
        // while the user was looking at five. A destructive confirmation
        // that understates what it destroys is the defect this whole dialog
        // exists to prevent.
        const folderList = allFolders();
        const folders = Array.isArray(folderList) ? folderList.length : 0;
        if (!marks && !folders) {
          toast(i18nText("chrome-js-manager-delete-all-none", "There are no bookmarks or folders to delete."));
          return;
        }
        const what = [
          marks === 1 ? "1 bookmark" : `${marks} bookmarks`,
          folders === 1 ? "1 folder" : `${folders} folders`,
        ].join(" and ");
        const ok = await askConfirm(
          await i18nResolve(
            "chrome-js-manager-delete-all-confirm",
            { what },
            `Permanently delete ${what}? This also removes their tags, their ` +
              `Quick Access pins, and the page snapshots kept for change ` +
              `checks. It cannot be undone, and PATANYX has no bookmark ` +
              `export to restore from. Your shelved tabs, downloads and ` +
              `archived pages are not affected.`,
          ),
          i18nText("chrome-js-manager-delete-all-label", "Delete everything"),
        );
        if (!ok) return;
        let removed;
        try {
          removed = await rb("bookmarks_delete_all");
        } catch (e) {
          if (errline) {
            errline.textContent = friendly(e);
            errline.hidden = false;
          }
          return;
        }
        await refreshOrganizerAfterWrite();
        const n = (removed && removed.bookmarks) || 0;
        const f = (removed && removed.folders) || 0;
        const bookmarksText = n === 1 ? "1 bookmark" : n + " bookmarks";
        const foldersText = f === 1 ? "1 folder" : f + " folders";
        i18nResolve(
          "chrome-js-manager-deleted-toast",
          { bookmarks: bookmarksText, folders: foldersText },
          `Deleted ${bookmarksText} and ${foldersText}.`,
        ).then((t) => toast(t));
      });
    }
    $("bmm-new-folder").addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter") return;
      ev.preventDefault();
      addFolder();
    });
  }
  // A click anywhere else closes the popover, the way every transient surface
  // in this chrome behaves. The popover stops its own clicks from reaching
  // here, and the Folders button handles its own toggle.
  document.addEventListener("click", () => {
    if (foldersPopoverFor) closeFoldersPopover();
  });
  // Escape closes the POPOVER first, and only the popover. Captured, so it
  // runs before the panel manager's own Escape and does not close the whole
  // manager out from under someone who was only dismissing a small menu.
  // Same layering askConfirm uses for its dialog.
  document.addEventListener(
    "keydown",
    (ev) => {
      if (ev.key !== "Escape" || !foldersPopoverFor) return;
      ev.stopPropagation();
      ev.preventDefault();
      closeFoldersPopover();
    },
    true,
  );

  // ---- About -------------------------------------------------------------
  //
  // Everything shown here is a fact about the COMPILED BINARY -- its version,
  // its licence text, its notices, and which third-party packages are actually
  // linked into it -- so all of it comes from Rust and none of it is written
  // into the markup. A version number typed into index.html would be correct
  // until the next release and wrong forever after, and silently so.
  let aboutLoaded = false;
  let attributionLoaded = false;

  async function refreshAbout() {
    if (aboutLoaded) return;
    let info;
    try {
      info = await rb("about_info");
    } catch (e) {
      // Named plainly. An About panel that renders empty looks like a broken
      // build, and someone reading it is often trying to find out what build
      // they have in order to report exactly that.
      const detail = friendly(e);
      i18nSet(
        $("about-build"),
        "chrome-js-about-read-failed",
        { detail },
        "Could not read this build's details: " + detail,
      );
      return;
    }
    if (!info) return;

    $("about-title").textContent = "About " + (info.name || "PATANYX");
    const buildSummary =
      (info.name || "PATANYX") +
      " version " +
      (info.version || i18nText("chrome-js-about-version-fallback", "unknown")) +
      ", rendering with " +
      (info.engine || i18nText("chrome-js-about-engine-fallback", "the system web engine")) +
      // The runtime version, every field, because "which engine am I
      // actually running" is the question that decides whether a published
      // engine fix has reached this machine. Rust sends "unknown" when it
      // could not tell, and that word is worth showing too.
      (info.engine_version ? " " + info.engine_version : "") +
      ".";
    $("about-build").textContent = info.build_warning
      ? info.build_warning + ". " + buildSummary
      : buildSummary;

    // Built with createElement and textContent, never markup. The copy crosses
    // the IPC boundary like everything else and this page holds the vault, so
    // it is rendered as DATA -- which is also why Rust sends the SHAPE rather
    // than a marked-up string this side would have to interpret.
    const body = $("about-description");
    body.replaceChildren();

    if (info.intro)
      body.appendChild(el("p", "about-para about-lede", info.intro));

    /// A titled block of lead-in/body rows. Used for the features and again for
    /// the limits, because they are the same shape and the second list is not a
    /// lesser thing than the first -- it is the other half of the same answer.
    function addRows(heading, rows, extraClass) {
      if (!rows || !rows.length) return;
      if (heading) body.appendChild(el("h2", "about-head", heading));
      const list = el(
        "ul",
        "about-list" + (extraClass ? " " + extraClass : ""),
      );
      for (const row of rows) {
        const li = el("li", "about-row");
        const head = el("p", "about-row-head");
        head.appendChild(el("strong", null, row.lead || ""));
        // The Automatic / Opt-in / On demand tag. It answers "do I have to do
        // anything" before the sentence has to, which is why it sits beside the
        // name rather than inside the description.
        if (row.when) head.appendChild(el("span", "about-when", row.when));
        li.appendChild(head);
        li.appendChild(el("p", "about-row-body", row.body || ""));
        list.appendChild(li);
      }
      body.appendChild(list);
    }

    addRows(info.features_head, info.features);

    if (info.honesty) {
      body.appendChild(el("p", "about-para about-honesty", info.honesty));
    }

    if (info.limits_head)
      body.appendChild(el("h2", "about-head", info.limits_head));
    if (info.limits_intro) {
      body.appendChild(el("p", "about-para", info.limits_intro));
    }
    addRows(null, info.limits, "about-limits");

    // Free/Premium sits after the limits and before what it is built from:
    // the reader has just been told what the product cannot do, which is the
    // honest place to tell them what costs money.
    if (info.premium_head) {
      body.appendChild(el("h2", "about-head", info.premium_head));
    }
    if (info.premium) {
      body.appendChild(el("p", "about-para", info.premium));
    }

    if (info.disclosure_head) {
      body.appendChild(el("h2", "about-head", info.disclosure_head));
    }
    if (info.disclosure) {
      body.appendChild(el("p", "about-para", info.disclosure));
    }

    // Sponsorship is its own About section, after both the Premium/affiliate
    // business-model paragraph and the build disclosure. It is not a Premium
    // call to action. Rust supplies every word; chrome supplies only the fixed
    // target NAME when the reader chooses the button.
    const support = $("about-support");
    $("about-support-head").textContent = info.support_head || "";
    $("about-support-copy").textContent = info.support || "";
    $("about-support-open").textContent = info.support_label || "";
    $("about-support-open").hidden = false;
    support.hidden = !(info.support_head && info.support && info.support_label);

    $("about-license-line").textContent =
      (info.name || "PATANYX") +
      " is free and open-source software, licensed under the " +
      (info.license_spdx || "Apache-2.0") +
      " license.";
    $("about-license-text").textContent = info.license_text || "";
    $("about-notice-text").textContent = info.notice_text || "";

    const n = Number(info.package_count) || 0;
    $("about-third-party-line").textContent =
      n > 0
        ? n.toLocaleString() +
          " third-party open-source packages in this build."
        : i18nText("chrome-js-about-third-party-failed", "This build's third-party inventory could not be counted.");

    aboutLoaded = true;
  }

  $("about-support-open").addEventListener("click", async () => {
    try {
      await rb("sponsorship_open", { sponsorship: "patanyx" });
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  /// Show/hide a block of text, with the button naming what the NEXT press
  /// does. Shared by the licence and the third-party sections so the two
  /// cannot drift into describing themselves differently.
  function wireDisclosure(buttonId, textId, showLabel, hideLabel, load) {
    const button = $(buttonId);
    const text = $(textId);
    button.setAttribute("aria-expanded", "false");
    button.setAttribute("aria-controls", textId);
    button.addEventListener("click", async () => {
      const opening = text.hidden;
      if (opening && load) {
        button.disabled = true;
        button.textContent = i18nText("chrome-js-about-loading", "Loading…");
        try {
          await load();
        } catch (e) {
          button.disabled = false;
          button.textContent = showLabel;
          toast(friendly(e), true);
          return;
        }
        button.disabled = false;
      }
      text.hidden = !opening;
      button.textContent = opening ? hideLabel : showLabel;
      button.setAttribute("aria-expanded", opening ? "true" : "false");
    });
  }

  wireDisclosure(
    "about-license-toggle",
    "about-license-text",
    i18nText("chrome-js-about-show-license", "Show the full license"),
    i18nText("chrome-js-about-hide-license", "Hide the license"),
    null,
  );

  wireDisclosure(
    "about-third-party-toggle",
    "about-third-party-text",
    i18nText("chrome-js-about-show-third-party", "Show third-party licenses"),
    i18nText("chrome-js-about-hide-third-party", "Hide third-party licenses"),
    // Fetched on FIRST open and kept. Roughly 300 KB of licence text for the
    // Windows build: worth not sending every time the About panel is opened,
    // and worth not re-sending once it has been.
    async () => {
      if (attributionLoaded) return;
      const reply = await rb("about_attribution");
      $("about-third-party-text").textContent = (reply && reply.text) || "";
      attributionLoaded = true;
    },
  );

  // ---- diagnostics export ----
  //
  // A snapshot of THIS session for troubleshooting, not the same thing as
  // About above: About is what this BUILD is; this is what the running
  // browser's state actually is right now, so unlike About it is re-fetched
  // on every open and again at the moment of copy or save, rather than
  // cached -- a stale export is a wrong export.
  //
  // What Rust composes is documented in `AppState::diagnostics_snapshot` as
  // excluding history, page content beyond the current tab's own origin, and
  // anything from the vault. `export_suggestion`/`file_choice` are stripped
  // out here before the snapshot is copied or saved: they are about HOW to
  // save it, not part of what is being reported.
  function diagnosticsReportOf(data) {
    const { export_suggestion, file_choice, ...report } = data || {};
    return JSON.stringify(report, null, 2);
  }

  async function refreshDiagnosticsPrefill() {
    try {
      const data = await rb("diagnostics_get");
      $("diag-pick").hidden = !data.file_choice;
      if (data.export_suggestion && !$("diag-dest").value) {
        $("diag-dest").value = data.export_suggestion;
      }
    } catch (e) {
      // Prefill only; Copy/Save still work; the field simply starts blank.
    }
  }

  $("diag-copy").addEventListener("click", async () => {
    $("diag-result").hidden = true;
    try {
      const data = await rb("diagnostics_get");
      await navigator.clipboard.writeText(diagnosticsReportOf(data));
      $("diag-result").hidden = false;
      $("diag-result").textContent = i18nText("chrome-js-diagnostics-copied", "Copied to clipboard.");
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  wireSavePicker(
    "diag-pick",
    "diag-dest",
    i18nText("chrome-js-diagnostics-pick-title", "Save the diagnostic report"),
    "patanyx-diagnostics.json",
  );

  $("diag-save").addEventListener("click", async () => {
    $("diag-result").hidden = true;
    const dest = $("diag-dest").value.trim();
    if (!dest) {
      toast(i18nText("chrome-js-diagnostics-dest-empty", "Choose or type a destination first."), true);
      return;
    }
    try {
      await rb("diagnostics_export", { dest });
      $("diag-result").hidden = false;
      i18nSet(
        $("diag-result"),
        "chrome-js-diagnostics-saved",
        { dest },
        "Saved to " + dest + ".",
      );
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  registerPanel("about", {
    el: $("about-panel"),
    button: $("btn-about"),
    heightPx: CHROME_OPEN_PX,
    onOpen: () => {
      refreshAbout();
      refreshDiagnosticsPrefill();
    },
  });
})();
