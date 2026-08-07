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

  function closedChromePx() {
    const strip = $("tabstrip");
    const bar = $("toolbar");
    if (!strip || !bar) return CHROME_CLOSED_FLOOR_PX;
    const measured =
      strip.getBoundingClientRect().height + bar.getBoundingClientRect().height;
    // Ceil, then the floor: a fractional layout height rounded DOWN is exactly
    // how you get one row of pixels clipped and a scrollbar to reach them.
    return Math.max(CHROME_CLOSED_FLOOR_PX, Math.ceil(measured));
  }
  // The stylesheet needs the same measurement: panels sit BELOW the chrome,
  // and a constant there is how their first line ended up rendering under the
  // toolbar (96px against a 148px chrome). Published as a CSS variable and
  // kept current whenever either row changes height. The observer is guarded:
  // the DOM harness the gates run in has no ResizeObserver, and the floor
  // default in the stylesheet keeps that environment honest anyway.
  function publishChromeMetric() {
    document.documentElement.style.setProperty(
      "--chrome-closed-px",
      closedChromePx() + "px",
    );
  }
  // Deferred a tick: `$` is declared further down this file, so running the
  // measurement inline here would throw at boot and take the whole chrome
  // with it. One macrotask later the script has fully evaluated and the
  // toolbar exists. (Everything else in this section is only CALLED later,
  // which is why closedChromePx itself gets away with using `$`.)
  setTimeout(() => {
    publishChromeMetric();
    if (typeof ResizeObserver !== "undefined") {
      const ro = new ResizeObserver(publishChromeMetric);
      for (const id of ["tabstrip", "toolbar"]) {
        const el = $(id);
        if (el) ro.observe(el);
      }
    }
  }, 0);
  const CHROME_OPEN_PX = 500;
  // The privacy panel is four explained rows; it needs less room than the
  // vault's forms. Both stay under the Rust-side clamp in ipc.rs.
  const PRIVACY_OPEN_PX = 500;
  const THEME_OPEN_PX = 500;

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
        renderTabs(msg.data && msg.data.items);
        break;
      case "find_open":
        openFindBar();
        break;
      case "find_state":
        onFindState(msg.data);
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
          (msg.data && msg.data.text) || "Something went wrong.",
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
        toast(
          msg.data && msg.data.reason
            ? "Cannot print: " + msg.data.reason
            : "Cannot print from this build.",
          true,
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
      case "load_state":
        document.body.classList.toggle(
          "loading",
          !!(msg.data && msg.data.loading),
        );
        // A check requested from the bookmarks list runs when the page it
        // named has finished loading. Checking earlier would digest the
        // PREVIOUS page and report a verdict about the wrong document,
        // which is worse than no verdict.
        if (pendingBookmarkCheck && !(msg.data && msg.data.loading)) {
          const wanted = pendingBookmarkCheck;
          pendingBookmarkCheck = null;
          // Only if we actually landed where we were sent: a redirect, a
          // refusal by the URL allowlist, or the user navigating away in the
          // meantime all mean the request no longer refers to this page.
          if (urlInput.value === wanted) {
            rb("integrity_check", {}).catch((e) => toast(friendly(e), true));
          }
        }
        break;
      case "download_started":
        toast(
          "Downloading " + fileNameFromUrl(msg.data && msg.data.url) + "...",
        );
        break;
      case "download_finished": {
        const data = msg.data || {};
        if (data.success) {
          toast(
            "Saved " +
              (fileNameFromPath(data.path) || fileNameFromUrl(data.url)),
          );
        } else {
          toast("Download failed", true);
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
      case "downloads_changed":
        if (openPanelName === "library") refreshDownloads();
        break;
      case "download_record_failed":
        toast(
          "Saved the file, but could not record it. Verification will not be available for this download.",
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

  const ERROR_TEXT = {
    auth_failed: "Wrong passphrase, or the vault file is damaged",
    bad_format: "That vault file is damaged or unreadable",
    not_unlocked: "Vault is locked",
    not_found: "Item not found",
    io: "Could not read or write to this computer's storage",
    too_large: "That file is too big to be a bookmarks export",
    no_capture_page: "Nothing to capture on this page",
    capture_failed: "The capture failed; nothing was saved",
    busy: "A capture is already in progress",
    no_storable_tabs:
      "Nothing to set aside: every tab here is ephemeral or an internal page",
    bad_args: "That does not look right",
    // Site permissions. `bad_origin` is reachable from a real page: an
    // opaque or sandboxed document has no site to attach a permission to, so
    // there is nothing the user could allow even in principle. Say that,
    // rather than implying they mistyped something.
    unknown_permission: "That is not a permission this browser controls",
    bad_origin:
      "This page has no site address to allow, so nothing can be changed here",
    vault_exists: "A vault already exists",
    recovery_exists:
      "This vault already has a recovery key. There can only be one, and " +
      "you were shown it when it was made.",
    // Chat codes (chat_panel.rs). peer_offline is a designed refusal — the
    // message is refused, never queued — so it must not read like a fault
    // the user should retry blindly.
    peer_offline:
      "They are not on this network right now. Nothing was sent, and nothing is waiting",
    no_session: "You are not connected to this person right now",
    too_long: "Message is too long",
    chat_down: "Chat is not available right now",
    duplicate_contact: "You already have a contact with that number",
    // Its own code rather than bad_args: the requirement is not guessable
    // from "Invalid input", and a well-formed http:// address is exactly the
    // thing a user reaches for. TLS is mandatory in the protocol.
    // OCR runs locally; there is no service to be down, so every one of these
    // is about the file or the install, never about a network.
    ocr_unavailable:
      "Text recognition is not available in this build. The model files are not installed.",
    ocr_failed:
      "Could not read any text in that picture. A sharper, straighter, better lit one usually works.",
    bad_image:
      "That file is not a picture PATANYX can read. Try a PNG or JPEG.",
    bad_relay_url:
      "The relay address has to start with wss://. Encrypted connections only, so http:// and ws:// are refused.",
    // Every code Rust can return must appear here, or friendly() renders the
    // raw identifier. bad_recovery_key was reachable on the vault's
    // last-resort path and showed the user "Unexpected error:
    // bad_recovery_key" when they mistyped their recovery key.
    bad_recovery_key:
      "That recovery key is not right. Check for typos. Capitals do not matter and the dashes are optional.",
    no_recovery_slot:
      "This vault has no recovery key. It was set up without one, so your passphrase is the only way in.",
    export_auth_failed: "Wrong export passphrase, or the file is corrupt.",
    bad_export: "That file is not a PATANYX vault export.",
    export_not_confirmed: "Type the confirmation sentence exactly to continue.",
    target_is_vault:
      "That path is your live vault. Choose a different destination.",
    store_bad_format:
      "The bookmarks file is unreadable or was written by something else.",
    no_page: "This page has not finished loading yet.",
    no_page_bytes: "This build cannot read the page's content.",
    no_snapshot: "No snapshot saved for this page yet.",
    managed_by_flatpak:
      "Updates for this installation are delivered by Flatpak. Install it from your software center, or run: flatpak update io.edgexene.Patanyx",
    vault_in_use:
      "This vault is already open in another PATANYX window. Close that window and try again \u2014 two copies open at once would each overwrite the other's changes.",
    not_bookmarked:
      "Bookmark this page first. Snapshots are kept with the bookmark.",
    unsupported: "Not available on this platform.",
    offline:
      "You are offline. Go online from the Chat panel to reach contacts.",
    relay_unavailable: "Relay support is not compiled into this build.",
    store_needs_passphrase:
      "Bookmarks and downloads are encrypted with your passphrase, so they stay locked when you get in with a recovery key. Unlock with the passphrase to see them.",
    // FOUR CODES THAT RENDERED AS "Unexpected error: <identifier>".
    //
    // The claim above ("Every code Rust can return must appear here") and the
    // matching one in ipc.rs were both false: no_tab, not_ready and
    // install_failed have been reachable and unrenderable. There is now a test
    // in ipc.rs that fails when a code is missing from this table, so the
    // claim is enforced rather than repeated.
    no_tab: "There is no active tab to apply that to.",
    not_ready:
      "The update has not finished downloading and verifying yet. Wait for it to complete, then try again.",
    install_failed:
      "The verified update could not be installed. The downloaded file is kept, so you can try again.",
    // The engine refused to create a webview -- out of memory, a lost GPU
    // process, or a WebView2 runtime problem. Says what to do, because
    // "engine error" leaves the user with nothing.
    tab_failed:
      "The browser engine could not open that tab. Close some tabs and try again; if it keeps happening, restart PATANYX.",
    // Found by the parity test, not by hand. chat.js has a `link_lost` entry
    // already, but that table renders DELIVERY status on a message row; this
    // code also comes back as the reply to `chat_send` itself, which goes
    // through friendly() and had no text at all. Two channels, one code.
    link_lost:
      "The connection to that contact dropped. Reopen the conversation and try again.",
    // Client-side, not from Rust: rb() gave up waiting. Rust drops frames it
    // cannot parse without replying, so this is what that looks like from
    // here. Phrased as "no answer" rather than "failed" because the command
    // may well have run -- what is known is only that nothing came back.
    no_reply:
      "The browser did not answer that in time. Nothing may have changed; check before trying again.",
    // Site-info's "Forget this site". no_site is a real, expected outcome --
    // about:blank, an internal page, or anything else with no http(s)
    // authority -- not a fault; phrased as a statement, not an apology.
    no_site: "This page has no site to forget.",
    cookie_delete_failed:
      "Could not clear cookies for this site. The engine refused the request; nothing was changed.",
    // Inline credential autofill. no_pending_save fires if Save/Never is
    // clicked twice (e.g. a double click) -- the first click already
    // resolved it, so the second has nothing left to act on.
    no_pending_save: "There is no password waiting to be saved.",
    // Refused rather than silently skipped: the tab navigated between
    // showing the fill offer and the click, so filling now would put a
    // saved password into a different site than the one it was saved for.
    origin_mismatch:
      "That saved password is for a different site than the one open now.",
    fill_failed: "Could not fill that password into the page.",
  };

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
  window.__rb = {
    request: rb,
    friendly,
    registerPanel: (name, spec) => registerPanel(name, spec),
    // Shared for the same reason `request` and `friendly` are: chat.js is a
    // separate script and must ask its destructive question with the same
    // dialog, not fall back to the engine's window.confirm and reintroduce
    // the rbchrome:// title this replaced.
    askConfirm: (message, confirmLabel) => askConfirm(message, confirmLabel),
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
  let digestsReady = false;
  // URL of a bookmark opened from the library with "Open and check": the
  // check fires when that page finishes loading. Null when nothing is
  // pending, and cleared on the first load event either way, so a stale
  // request cannot attach itself to some later page.
  let pendingBookmarkCheck = null;
  let bookmarkItems = [];
  // The bookmark search box's current text. Held here, never sent anywhere:
  // filtering is done over the list this panel already has, so searching your
  // own bookmarks produces no IPC, no request, and no record of the term.
  let bookmarkQuery = "";
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
    rb("tab_new").catch(() => {});
    urlInput.focus();
  });

  function hostOf(url) {
    const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]+)/.exec(url);
    return match ? match[1] : url;
  }

  function chipLabel(tab) {
    const title = (tab.title || "").trim();
    if (title) return title;
    if (!tab.url || tab.url === "about:blank") return "New tab";
    return hostOf(tab.url);
  }

  function renderTabs(items) {
    const wrap = $("tabs");
    wrap.textContent = "";
    for (const tab of items || []) {
      const chip = el("div", "tab-chip" + (tab.active ? " active" : ""));
      chip.title = tab.title || tab.url || "";
      // Truncation itself is CSS (max-width + ellipsis).
      chip.appendChild(el("span", "chip-title", chipLabel(tab)));
      const close = el("button", "chip-close", "\u00D7");
      close.type = "button";
      close.title = "Close tab";
      close.addEventListener("click", (ev) => {
        ev.stopPropagation();
        rb("tab_close", { id: tab.id }).catch(() => {});
      });
      chip.appendChild(close);
      chip.addEventListener("click", () => {
        if (!tab.active) rb("tab_switch", { id: tab.id }).catch(() => {});
      });
      wrap.appendChild(chip);
    }
  }

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
    yes.textContent = confirmLabel || "Delete";
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
  function toast(text, isError) {
    const node = el("div", "toast" + (isError ? " error" : ""), text);
    node.title = text;
    $("toasts").appendChild(node);
    setTimeout(() => node.remove(), 6000);
  }

  function fileNameFromUrl(url) {
    const clean = String(url || "").split(/[?#]/)[0];
    const segments = clean.split("/").filter(Boolean);
    return segments.length ? segments[segments.length - 1] : "download";
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
      const close = el("button", "panel-close", "Close");
      close.type = "button";
      close.setAttribute("aria-label", "Close this panel");
      close.addEventListener("click", () => togglePanelNamed(name));
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
      err.textContent = "Enter the recovery key you were given.";
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
  // over one pane -- and the project owner rejected the geometry on sight. Split
  // remains chat's; panels cover the window and say so.
  //
  // What DOES vary is the backdrop. Where the backend can lift a transparent
  // chrome above live content (Windows -- see `chrome_caps`), the page stays
  // rendered at its normal rect and the scrim is genuinely translucent: a
  // dimmed, still-playing page behind the card. Everywhere else the page gets
  // a zero rect and the scrim is solid, because siblings that cannot
  // composite must not fake a see-through.
  let chromeCovered = null;
  rb("chrome_caps", {})
    .then((r) => {
      document.body.classList.toggle(
        "translucent-backdrop",
        !!(r && r.translucent_overlay),
      );
    })
    .catch(() => {});
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
    // `syncChromeHeight` reads `openPanelName`, which is already updated
    // here, so it resolves the panel's height when opening and the
    // banner-aware strip height when closing.
    syncChromeHeight();
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
    syncChromeHeight();
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
      syncChromeHeight();
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
    syncChromeHeight();
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
      if (
        panel &&
        !panel.el.contains(ev.target) &&
        !ev.target.closest("#toolbar, #tabstrip, #confirm-overlay")
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
    0: "Never",
    300: "5 minutes",
    900: "15 minutes",
    1800: "30 minutes",
    3600: "60 minutes",
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
      setNote("Could not read this setting: " + friendly(e));
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
            if (note) note.textContent = "Could not save that: " + friendly(e);
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
        ? "Once unlocked, the vault stays unlocked until you lock it or close the browser."
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
      toast("Saving this page as a PDF...");
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

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
      desc.textContent =
        "A saved password for " + offer.username + " is available.";
      panelBtn.disabled = false;
      panelBtn.textContent = "Fill password for " + offer.username;
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
      }
      return;
    }
    desc.textContent = lastAutofillReason;
    panelBtn.disabled = true;
    panelBtn.textContent = "Fill saved password";
    // Hidden, not disabled. See the markup comment on #btn-fill: a greyed
    // button on every page the user has no saved password for is nine-tenths
    // of the time noise, and its absence is the clearer signal.
    if (toolbarBtn) {
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
        "This page has no site to check for a saved password.";
      renderAutofillOffer();
      return;
    }
    if (st.content_script_registered !== "applied") {
      lastAutofillReason = "Autofill is not available in this tab.";
      renderAutofillOffer();
      return;
    }
    rb("cred_autofill_offer_get")
      .then((data) => {
        // The tab may have navigated to a different site while this was in
        // flight; a stale reply must not offer a fill for the wrong page.
        // Checked against the whole key, not just origin, so a vault that
        // locked mid-flight cannot leave a live-looking button behind.
        if (autofillKey(lastTabStatus) !== key) return;
        const item = ((data && data.items) || [])[0];
        lastAutofillOffer = item || null;
        if (!item) lastAutofillReason = "No saved password for this site.";
        renderAutofillOffer();
      })
      .catch(() => {
        lastAutofillOffer = null;
        lastAutofillReason = "Could not check for a saved password.";
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
      // Re-enabled regardless of outcome: nothing about a fill attempt makes
      // the offer stop being valid, so there is no reason to leave the
      // button stuck disabled after either a success or a refusal.
      btn.disabled = false;
    }
  });

  function hideSavePasswordBanner() {
    const banner = $("save-password-banner");
    if (banner && !banner.hidden) {
      banner.hidden = true;
      syncChromeHeight();
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
      syncChromeHeight();
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
  const PALETTE_ACTIONS = [
    { label: "New tab", buttonId: "btn-newtab" },
    { label: "New quarantine tab", buttonId: "btn-quarantine-menu" },
    { label: "Bookmark this page", buttonId: "btn-bookmark" },
    { label: "Open Privacy", buttonId: "btn-privacy" },
    { label: "Open Theme", buttonId: "btn-theme" },
    { label: "Toggle freeze for this tab", buttonId: "btn-freeze" },
    { label: "Open Tab Activity", buttonId: "btn-tab" },
    { label: "Open Vault", buttonId: "btn-vault" },
    { label: "Open DNS settings", buttonId: "btn-dns" },
    { label: "Open Tunnel", buttonId: "btn-tunnel" },
    { label: "Open Chat", buttonId: "btn-chat" },
    { label: "Open Library", buttonId: "btn-library" },
    // These two buttons are built at runtime by integrity.js/update.js, not
    // in index.html -- which is exactly why they were missed here: nothing
    // failed when the palette predated them. `paletteVisibleActions` resolves
    // ids live at open time, so runtime injection needs no special casing.
    { label: "Open Integrity", buttonId: "btn-integrity" },
    { label: "Open Updates", buttonId: "btn-update" },
    { label: "About this site", buttonId: "btn-site-info" },
    { label: "Save page as PDF", buttonId: "btn-save-pdf" },
    { label: "About PATANYX", buttonId: "btn-about" },
  ];
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

  $("lib-tab-bookmarks").addEventListener("click", () =>
    selectLibraryTab("bookmarks"),
  );
  $("lib-tab-downloads").addEventListener("click", () =>
    selectLibraryTab("downloads"),
  );
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
    onOpen: refreshVault,
    // Closing the panel must not leave secrets on screen.
    onClose: clearSecrets,
  });

  registerPanel("privacy", {
    el: $("privacy-panel"),
    button: $("btn-privacy"),
    heightPx: PRIVACY_OPEN_PX,
    onOpen: () => {
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
    },
  });

  registerPanel("dns", {
    el: $("dns-panel"),
    button: $("btn-dns"),
    heightPx: DNS_OPEN_PX,
    onOpen: refreshDns,
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
  const TUNNEL_FAIL_GRACE_MS = 15000;

  registerPanel("tunnel", {
    el: $("tunnel-panel"),
    button: $("btn-tunnel"),
    heightPx: 500,
    onOpen: refreshTunnel,
  });

  function renderTunnelRestart(pending) {
    const note = $("tunnelp-restart");
    if (pending) {
      // Says what is true NOW ("not in effect yet") before what to do
      // about it: the user has already changed the setting and the browser
      // is still behaving the old way, which is the surprising half.
      note.textContent =
        "Not in effect yet. Close PATANYX and open it again to apply this " +
        "change. The engine takes the tunnel setting only at startup.";
      note.hidden = false;
    } else {
      note.hidden = true;
    }
  }

  function markTunnelChoice(mode) {
    // The class is `active`, the convention every picker here uses; the
    // matching chrome.css rule is scoped `#tunnel-panel button.small.active`
    // so the tunnel gate can check THIS picker (the resolver picker once
    // shipped the class with no rule and every choice rendered alike).
    $("tunnelp-off").classList.toggle("active", mode === "off");
    $("tunnelp-imported").classList.toggle("active", mode === "imported");
  }

  function tunnelReportLine(report, startError) {
    let line =
      "Status: " + (report == null ? "no measurement yet" : String(report));
    if (startError) {
      line += ". Could not start: " + startError;
    }
    return line;
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
    $("tunnelp-status").textContent = tunnelReportLine(
      st.report,
      st.start_error,
    );
    // The restart note is driven by the ENGINE's answer, on every refresh --
    // not set once as a reaction to a click. It used to be the latter, so
    // closing and reopening the panel lost it while the restart stayed just
    // as pending, and the browser went on tunnelling with nothing on screen
    // saying so.
    renderTunnelRestart(!!st.restart_pending);
    const configLine = $("tunnelp-config");
    if (st.has_config === null || st.has_config === undefined) {
      // Locked vault: Rust cannot say whether a configuration exists, and
      // this line must not render "null" or guess.
      configLine.textContent =
        "Unlock the vault to see whether a configuration is stored.";
    } else if (st.has_config) {
      configLine.textContent = "A configuration is stored in the vault.";
    } else {
      configLine.textContent = "No configuration imported yet.";
    }
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
    const show =
      tunnelMode === "imported" &&
      tunnelFailSince !== 0 &&
      Date.now() - tunnelFailSince >= TUNNEL_FAIL_GRACE_MS;
    const banner = $("tunnel-warning");
    if (banner.hidden !== !show) {
      banner.hidden = !show;
      // The chrome is a clipped strip; a (dis)appearing banner changes the
      // height Rust must be told about, same as every other banner.
      syncChromeHeight();
    }
  }

  function noteTunnelMeasured(state) {
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

  // The REAL toolbar button's click, so the panel opens with exactly its
  // normal wiring rather than a copy of it.
  $("tunnel-warning-open").addEventListener("click", () => {
    $("btn-tunnel").click();
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

  async function refreshPrivacy() {
    try {
      applyPrivacyStatus(await rb("privacy_get"));
    } catch (e) {
      $("privacy-foot").textContent = friendly(e);
    }
    await refreshFingerprint();
    await refreshPermissions();
  }

  // ---- site permissions -----------------------------------------------------
  // Deny-by-default, session-only. Rendered from permission_status rather than
  // from anything this file remembers: the table lives in Rust and the engine
  // callback writes to it, so a cached copy here would go stale the moment a
  // page asked for something.

  const PERMISSION_LABELS = {
    camera: "Camera",
    microphone: "Microphone",
    geolocation: "Location",
    notifications: "Notifications",
  };

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
        "This tab is not enforcing permission choices, so nothing here would take effect.";
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
        "Open a site to choose what it may use. Camera, microphone, location and notifications stay off until you allow them.";
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
      const who = entry.origin === st.site ? "this site" : entry.origin;
      // The reload that makes a change take effect is done for the user now
      // (see permission_grant in ipc.rs), so this no longer tells them to do
      // it themselves. What it must still say is that the grant DIES ON CLOSE,
      // because anyone arriving from another browser will expect it to persist.
      sub.textContent = entry.granted
        ? `Allowed for ${who} until PATANYX closes`
        : entry.deniedCount > 1
          ? `Refused ${entry.deniedCount} times for ${who}`
          : `Refused for ${who}`;
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
        ? "Not available on this platform: ads can be hidden here, but their requests are still made."
        : "Not available in this tab: its request filter could not be installed, so nothing is being intercepted. Reopen the page in a new tab.",
    );
    setSupported(
      "pv-freeze",
      st.freeze_enforced,
      "Not available on this platform: pages cannot be stopped from making requests.",
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
        ? "No protections are active. This browser is behaving like an ordinary one."
        : "Protections apply to every open tab.";
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
          ? "Nothing blocked on this page"
          : blockedOnPage +
              " request" +
              (blockedOnPage === 1 ? "" : "s") +
              " blocked on this page",
      );
    }
    parts.push(
      shieldActive === 0
        ? "No protections active"
        : shieldActive +
            " protection" +
            (shieldActive === 1 ? "" : "s") +
            " active",
    );
    if (refused.length) {
      parts.push("REFUSED by the engine: " + refused.join(", "));
    }
    if (blocklistFailed) {
      parts.push("the malicious-site list could not be refreshed");
    }
    const sentence = parts.join(". ") + ".";
    btn.title = sentence;
    // Screen readers get the same sentence rather than the word "Privacy".
    // The visible label stays one word because the button is 90px wide; the
    // accessible name has no such budget and should not inherit that limit.
    btn.setAttribute("aria-label", "Privacy protections: " + sentence);
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
      syncChromeHeight();
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
          ? "Locking in " +
            left +
            " seconds because nothing has happened for a while."
          : "Locking now.";
    };
    paint();
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeHeight();
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
  // matters because the vault auto-locks after five minutes.
  function setVaultIndicator(name) {
    const unlocked = name === "open" || name === "recovery";
    // Locking the vault has to retract a fill button that is already on the
    // toolbar, and unlocking has to offer one for the page in front of you
    // without waiting for a navigation. Both fall out of re-checking here,
    // because `vaultUnlocked` is part of the cache key.
    if (unlocked !== vaultUnlocked) {
      vaultUnlocked = unlocked;
      refreshAutofillOffer();
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
    btn.title = unlocked ? "Vault: unlocked" : "Vault: locked";
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
  const LICENCE_PASTE_TEXT = {
    licence_not_a_token:
      "That doesn't look like a PATANYX Premium token. Copy the full token from your receipt and paste it again.",
    licence_needs_newer_build:
      "This token needs a newer version of PATANYX. Update and try again.",
    licence_not_issued:
      "This token was not issued by EdgeXene. Check that you copied it from your EdgeXene receipt.",
    licence_keys_unavailable: "This build cannot verify Premium tokens yet.",
  };

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

  async function refreshLicence() {
    const row = $("premium-row");
    try {
      const lic = await rb("licence_get");
      if (lic.row_head == null) {
        // Locked vault: the quietest rendering is no row at all — and no
        // held token either.
        clearLicenceConfirm();
        row.hidden = true;
        return;
      }
      row.hidden = false;
      $("premium-head").textContent = lic.row_head;
      $("premium-sub").textContent = lic.row_sub || "";
    } catch (e) {
      clearLicenceConfirm();
      row.hidden = true;
    }
  }

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
        // Same vocabulary as the row headline (operator rewording
        // 2026-08-05), so the feedback and the row it sits above agree.
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
        "This token is for a different license. Replace the current one?";
      $("premium-confirm").hidden = false;
      errEl.textContent = "";
      return;
    }
    // A refusal ends any pending confirmation: the held token must not
    // outlive the exchange that created it.
    clearLicenceConfirm();
    errEl.textContent =
      LICENCE_PASTE_TEXT[res.code] || "That token could not be added.";
  }

  $("premium-add").addEventListener("click", () => {
    $("premium-add").hidden = true;
    $("premium-form").hidden = false;
    $("premium-token").focus();
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
    renderCreds();
    renderNotes();
  }

  function onLocked() {
    clearSecrets();
    credItems = [];
    noteItems = [];
    renderCreds();
    renderNotes();
    showState("locked");
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
    "Save the encrypted backup",
    "patanyx-export.rbx",
  );
  wireSavePicker(
    "bk-plain-pick",
    "bk-plain-dest",
    "Save the plaintext export",
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
      err.textContent = "The two new passphrases do not match.";
      return;
    }
    if (!current || !next) {
      err.textContent = "Both the current and the new passphrase are required.";
      return;
    }
    try {
      await rb("vault_change_passphrase", { current, new: next });
      $("bk-pw-current").value = "";
      $("bk-pw-new1").value = "";
      $("bk-pw-new2").value = "";
      ok.textContent =
        "Passphrase changed. The old one no longer opens this vault; your recovery key is unchanged.";
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
      err.textContent = "The two export passphrases do not match.";
      return;
    }
    if (!dest || !passphrase) {
      err.textContent = "Choose a destination and set an export passphrase.";
      return;
    }
    try {
      await rb("vault_export_encrypted", { dest, passphrase });
      $("bk-exp-pass1").value = "";
      $("bk-exp-pass2").value = "";
      // Named plainly because it is a separate secret from the vault
      // passphrase and there is no recovery key for an export.
      ok.textContent =
        "Encrypted export written. It opens only with the export passphrase you just set, and there is no recovery key for it.";
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
      err.textContent = "Choose a destination.";
      return;
    }
    // The backend enforces this too, and must -- this check only turns a
    // round trip into an immediate answer.
    if (!confirmation) {
      err.textContent = "Type the confirmation sentence exactly to continue.";
      return;
    }
    try {
      await rb("vault_export_plaintext", { dest, confirmation });
      $("bk-plain-confirm").value = "";
      ok.textContent =
        "Plaintext export written. It is NOT encrypted, so anyone who opens that file can read every credential in it.";
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
        typed.placeholder = "No file chosen yet";
      } else {
        pick.hidden = true;
        typed.readOnly = false;
        typed.placeholder = "Backup file path";
      }
    }
    importModeAppliers.push(applyMode);

    $(id("pick")).addEventListener("click", async () => {
      const err = $(id("error"));
      err.textContent = "";
      try {
        const r = await rb("file_pick_open", {
          title: "Choose a PATANYX backup file",
        });
        // Cancel is an answer, not a failure: leave everything as it was.
        if (!r || !r.path) return;
        $(id("src")).value = r.path;
        $(id("chosen")).textContent = "Chosen: " + r.path;
      } catch (e) {
        err.textContent = friendly(e);
      }
    });

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const err = $(id("error"));
      err.textContent = "";
      const src = $(id("src")).value.trim();
      const exportPass = $(id("export-pass")).value;
      const p1 = $(id("pass1")).value;
      const p2 = $(id("pass2")).value;
      // EVERY check below happens before the IPC call, because import
      // replaces the vault on this machine and cannot be undone. A typo in
      // the confirmation field must cost a re-type, not a vault.
      if (!src) {
        err.textContent = importFileChoice
          ? "Choose the backup file first."
          : "Enter the path to the backup file.";
        return;
      }
      if (!exportPass) {
        err.textContent = "Enter the passphrase that protects the backup file.";
        return;
      }
      if (p1.length < 8) {
        err.textContent = "New passphrase must be at least 8 characters.";
        return;
      }
      if (p1 !== p2) {
        err.textContent = "New passphrases do not match.";
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
      err.textContent = "Passphrase must be at least 8 characters.";
      return;
    }
    if (p1 !== p2) {
      err.textContent = "Passphrases do not match.";
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
      err.textContent = "Enter your vault passphrase to confirm.";
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

  function selectTab(which) {
    // Backup was shipped in index.html with a tab button and a pane, and this
    // function never knew about it — so the whole encrypted-export,
    // change-passphrase and plaintext-export surface was unreachable.
    for (const name of ["creds", "notes", "backup"]) {
      $("tab-" + name).classList.toggle("active", which === name);
      $("pane-" + name).hidden = which !== name;
    }
    if (which === "backup") refreshBackupStatus();
    // The Premium row sits ABOVE the panes, so it survives a tab switch --
    // and so did the result of the last token paste, which meant a refusal
    // like "This build cannot verify Premium tokens yet" followed the user
    // from Credentials to Notes to Backup as if it were about the pane they
    // had just opened. A message about an action belongs to that action:
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
        li.appendChild(
          el(
            "div",
            "cred-origin",
            item.fills_on
              ? "Fills on " + item.fills_on + " and its subdomains"
              : "Fills on " + item.origin + " only",
          ),
        );
      } else {
        li.appendChild(
          el(
            "div",
            "cred-origin none",
            "Copy only: no site to match. Edit it on the site's page to fix.",
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
        revealed.has(item.id) ? "Hide" : "Reveal",
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

      const editBtn = el("button", "small", "Edit");
      editBtn.type = "button";
      editBtn.addEventListener("click", async () => {
        try {
          const entry = await rb("cred_get", { id: item.id });
          editingCred = item.id;
          $("cred-site").value = entry.site || "";
          $("cred-username").value = entry.username || "";
          $("cred-password").value = entry.password || "";
          $("cred-note").value = entry.note || "";
          $("cred-submit").textContent = "Save changes";
          $("cred-cancel").hidden = false;
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(editBtn);

      const delBtn = el("button", "small danger", "Delete");
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        if (!(await askConfirm("Delete credential for " + item.site + "?")))
          return;
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
      const editBtn = el("button", "small", "Edit");
      editBtn.type = "button";
      editBtn.addEventListener("click", async () => {
        try {
          const note = await rb("note_get", { id: item.id });
          editingNote = item.id;
          $("note-title").value = note.title || "";
          $("note-body").value = note.body || "";
          $("note-submit").textContent = "Save changes";
          $("note-cancel").hidden = false;
        } catch (e) {
          /* ignore */
        }
      });
      row.appendChild(editBtn);

      const delBtn = el("button", "small danger", "Delete");
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
      err.textContent = "Site and username are required.";
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
    if (origin) btn.title = "Use " + origin + ", the site in this tab";
  }

  function resetCredForm() {
    editingCred = null;
    $("cred-site").value = "";
    $("cred-username").value = "";
    $("cred-password").value = "";
    $("cred-note").value = "";
    $("cred-submit").textContent = "Add credential";
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
      err.textContent = "Title is required.";
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
    $("note-submit").textContent = "Add note";
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
    .then((data) => renderTabs(data && data.items))
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
      if (data && data.seen === false) togglePanelNamed("onboarding");
    })
    .catch(() => {});

  // ---- from the privsurface draft ----
  // The chrome strip height is owned here, in one place: the open panel's
  // budget (or the closed height) plus the TLS warning's measured height
  // while it is visible. The warning lives inside the chrome webview, so
  // without this it would be clipped by the fixed strip height.
  // Every banner that can appear under the toolbar. They live inside the
  // chrome webview, so the Rust side has to be told how tall the strip needs
  // to be or they are simply clipped. This was a single hardcoded reference to
  // #tls-warning; a second banner would have rendered half-visible with no
  // error anywhere.
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
    "tls-warning",
    "save-password-banner",
    "lock-warning",
    // The fail-closed tunnel banner. A banner absent from this list renders
    // OUTSIDE the clipped strip and is invisible -- the lock-warning defect.
    "tunnel-warning",
  ];

  function syncChromeHeight() {
    const base = openPanelName
      ? panels.get(openPanelName).heightPx
      : closedChromePx();
    let extra = 0;
    for (const id of BANNERS) {
      const banner = $(id);
      if (banner && !banner.hidden) {
        extra += Math.ceil(banner.getBoundingClientRect().height);
      }
    }
    rb("set_chrome_height", { px: base + extra }).catch(() => {});
  }

  // RE-MEASURE WHEN THE MEASUREMENT CAN CHANGE. `closedChromePx` reads laid-out
  // text, and two things move it after boot: a font finishing load (the first
  // paint can use a fallback with different metrics), and the window moving to
  // a monitor with different DPI scaling, which changes how many CSS pixels a
  // row of Segoe UI occupies. Both would otherwise leave Rust holding a height
  // that was right once.
  //
  // Cheap and idempotent: syncChromeHeight sends one small IPC message and
  // does nothing else, and Rust clamps whatever arrives.
  window.addEventListener("resize", syncChromeHeight);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(syncChromeHeight).catch(() => {});
  }

  // ---- from the privsurface draft ----
  // ---- per-tab privacy: freeze, allow-site, ledger, TLS, profile --------------

  // Single writer for every per-tab indicator, fed by the tab_status event,
  // the tab_status reply, and the boot/slow polls. Both freeze controls
  // (toolbar chip and panel button) are driven from here so they can never
  // disagree.
  function applyTabStatus(st) {
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
        ? "Loading\u2026"
        : freezeFailed
          ? "Not frozen"
          : freezePending
            ? "Freezing\u2026"
            : reallyFrozen
              ? "Frozen"
              : "Live";
    // aria-pressed tracks the REQUEST, because that is what the button
    // toggles: a failed freeze must still offer "unfreeze" to clear it.
    btn.setAttribute("aria-pressed", requested ? "true" : "false");
    btn.classList.toggle("is-active", reallyFrozen);
    btn.classList.toggle("is-warning", freezeFailed);
    // A control the platform cannot honour is shown, disabled, and
    // explained — never a switch that does nothing.
    btn.disabled = !enforceable;
    btn.title = !enforceable
      ? "Freezing is not available on this platform"
      : freezeFailed
        ? "Freeze FAILED: the engine could not install the block, so this tab is still making network requests"
        : freezePending
          ? "Freezing this tab\u2026 requests may still be going out until it finishes"
          : reallyFrozen
            ? "This tab is frozen and sending nothing. Click to unfreeze."
            : "Freeze this tab: stop it from making network requests";

    // Panel mirror of the same state.
    $("tab-freeze-desc").textContent =
      phase === "loading"
        ? "This tab is loading. Requests are allowed until it finishes."
        : freezeFailed
          ? "Freeze failed. The engine could not install the block, so this tab is STILL making network requests. Close it if that matters."
          : freezePending
            ? "Freezing this tab. Until that finishes it may still be making requests."
            : reallyFrozen
              ? "This tab is frozen. It is making no network requests."
              : "This tab is live. It can keep making network requests.";
    const panelFreeze = $("btn-tabfreeze");
    panelFreeze.textContent = requested
      ? "Unfreeze this tab"
      : "Freeze this tab";
    panelFreeze.disabled = !enforceable;

    // The Tab button lights up when the active tab has any non-default
    // posture (frozen, or keeping nothing on disk), so it is glanceable
    // with the panel closed.
    $("btn-tab").classList.toggle(
      "is-active",
      reallyFrozen || st.profile === "ephemeral",
    );

    // TLS: the full-width banner is reserved for the one verdict that must
    // not be missable — Intercepted means traffic the user believes is
    // private is being decrypted by a third party. It has no dismiss
    // control; it clears when the connection state does. Unknown is common
    // (unrecognized issuer names) and stays a calm line in the panel:
    // crying wolf there would teach the user to ignore the real warning.
    //
    // "unreadable" is NOT "unknown" and the two must never share a string.
    // Unknown says the browser looked at the issuer and did not recognize
    // it — a fact about the certificate. Unreadable says the platform
    // exposes no chain to look at (WebView2 on Windows, every page, always),
    // so the sentence has to be about the browser instead. They were one
    // branch, which told every Windows user their ordinary public
    // certificate had an issuer this browser did not recognize.
    const intercepted = st.tls === "intercepted";
    const banner = $("tls-warning");
    if (banner.hidden !== !intercepted) {
      banner.hidden = !intercepted;
      syncChromeHeight();
    }
    $("tab-tls-desc").textContent =
      st.tls === "normal"
        ? "This connection is encrypted and the certificate issuer is a recognized public authority."
        : intercepted
          ? "This connection is being intercepted. See the warning above."
          : st.tls === "not_tls"
            ? "This page is not using an encrypted connection."
            : st.tls === "unknown"
              ? "The certificate issuer is not one this browser recognizes. That is not necessarily a problem; it is simply unconfirmed."
              : // "unreadable", and the default for anything unrecognized:
                // the only claim that stays true when the browser does not
                // know what it is looking at.
                "This browser cannot read certificate details on this platform, so the issuer is unconfirmed. That is a limit of the browser, not a finding about this site.";

    // Storage profile: stated as fact. It is fixed when the tab is built, so
    // there is deliberately no control here — only what IS, and a pointer to
    // the way to get a tab that keeps nothing.
    $("tab-profile-desc").textContent =
      st.profile === "ephemeral"
        ? "This tab keeps no site data: cookies and storage live only in memory and die with the session. This was chosen when the tab opened and cannot change."
        : "This tab saves cookies, cache and site data, like an ordinary browser.";

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
    $("tab-forget-desc").textContent = origin
      ? "Clears cookies for " +
        origin +
        ". Saved passwords, local storage, and other site data are not affected."
      : "This page has no site to forget.";
    $("btn-site-forget").disabled = !origin;

    // Save-password banner: `pending_save` is only ever non-null when the
    // ACTIVE tab is the one that submitted a login, and never carries the
    // password (see `AppState::active_tab_status`'s own doc). Read on every
    // tab_status, not gated on any panel being open -- an offer to save a
    // password is worth surfacing whether or not Tab Activity is open, unlike
    // the Passwords section below.
    applyPendingSave(st.pending_save || null);

    // Passwords used to be refreshed HERE, and only while Tab Activity was
    // open -- the round trip was not worth making for a panel nobody had
    // opened. It now happens unconditionally at the top of this same function,
    // because the toolbar fill button needs the answer on every page. Left as
    // a note rather than a second call: two refreshes per status update, one
    // of them conditional, is how the two controls would drift apart.

    syncAllowSiteButton();
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
    btn.textContent = host
      ? "Allow " + host + " while frozen"
      : "Allow this site while frozen";
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
    $("receipt-page").textContent = "";
    rb("privacy_receipt")
      .then(renderPrivacyReceipt)
      .catch(() => {});
  }

  function renderPrivacyReceipt(r) {
    const sessionEl = $("receipt-session");
    const pageEl = $("receipt-page");
    if (!r) return;
    // The same gate the badge and the ledger list apply
    // (ledger_counts_blocked): where the platform cannot observe blocking
    // at all, say so in words. ONLY that case earns the engine sentence --
    // a malformed reply is a broken contract, not an engine limitation,
    // and it leaves the lines empty rather than mislabelled.
    if (r.counts_blocked !== true) {
      sessionEl.textContent =
        "Refused-request counts are not observable with this engine.";
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
    pageEl.textContent =
      String(r.page_blocked) +
      (r.page_blocked === 1
        ? " refused on this page."
        : " refused on this page.");
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
            ? "This tab's request filter could not be installed, so nothing is being recorded here. This is not a claim that the tab contacted nobody."
            : "No requests recorded yet. Every host this tab contacts will appear here.",
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
        already ? "Allowed" : "Allow while frozen",
      );
      allowBtn.type = "button";
      allowBtn.disabled = already;
      allowBtn.title =
        "Let this host through even while the tab is frozen. Lasts until the tab closes.";
      allowBtn.addEventListener("click", () => allowHost(rec.host));
      row.appendChild(allowBtn);
      li.appendChild(row);
      list.appendChild(li);
    }

    $("ledger-foot").textContent = countsBlocked
      ? "Requests counted as blocked never left this browser."
      : "This list shows every host the tab contacted. On this platform the blocker does not report the requests it stops, so they are not counted here. Blocking still happens, it just cannot be counted.";
  }

  // ---- from the bookmarks draft ----
  function fmtTime(unixSeconds) {
    if (!unixSeconds) return "";
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  // ---- from the bookmarks draft ----
  function fmtBytes(n) {
    const units = ["B", "KB", "MB", "GB", "TB"];
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
      ? "This page is bookmarked. Open bookmarks"
      : "Bookmark this page";
    btnBookmark.title = label;
    btnBookmark.setAttribute("aria-label", label);
  }

  // ---- from the bookmarks draft ----
  function openLibrary(tab) {
    if (openPanelName !== "library") togglePanelNamed("library");
    selectLibraryTab(tab || "bookmarks");
  }

  // ---- from the bookmarks draft ----
  function selectLibraryTab(which) {
    $("lib-tab-bookmarks").classList.toggle("active", which === "bookmarks");
    $("lib-tab-downloads").classList.toggle("active", which === "downloads");
    $("lib-pane-bookmarks").hidden = which !== "bookmarks";
    $("lib-pane-downloads").hidden = which !== "downloads";
  }

  // ---- from the bookmarks draft ----
  // ---- bookmark import ----
  // The picker, the file read and the parse all live in Rust; this handler
  // only asks and then reports the arm's own numbers. A null reply is the
  // picker's cancel -- nothing to report, nothing shown.
  // Filter as you type. `input` rather than `keyup` so it also catches a
  // paste, a drag-drop of text, and the clear button browsers put in search
  // fields -- all of which change the value without a key ever going up.
  $("bm-search").addEventListener("input", (ev) => {
    bookmarkQuery = ev.target.value || "";
    renderBookmarks();
  });
  // Escape clears the filter rather than closing the panel, which is what a
  // search box in a list is expected to do. The panel's own Escape still
  // works from anywhere else in it, because this only stops the event when
  // there is a filter to clear.
  $("bm-search").addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    if (!bookmarkQuery) return;
    ev.stopPropagation();
    ev.preventDefault();
    bookmarkQuery = "";
    ev.target.value = "";
    renderBookmarks();
  });

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

  // ---- set-aside shelves ----
  // A shelf stores title + URL only: no favicons, no scroll positions, no
  // cookies, no history. That is the privacy contract of the feature.
  $("set-aside").addEventListener("click", async () => {
    const btn = $("set-aside");
    btn.disabled = true;
    try {
      const r = await rb("shelf_create");
      const leftOut =
        r.left_out > 0
          ? " " +
            r.left_out +
            " left out: ephemeral and internal pages stay open."
          : "";
      toast(r.name + "." + leftOut);
      await shelfRenderList();
    } catch (e) {
      toast(friendly(e), true);
    } finally {
      btn.disabled = false;
    }
  });

  async function shelfRenderList() {
    const list = $("shelf-list");
    list.textContent = "";
    let items;
    try {
      const reply = await rb("shelf_list");
      items = (reply && reply.items) || [];
    } catch (e) {
      // Unavailable is not empty: the panel says which one it is.
      list.textContent = friendly(e);
      return;
    }
    if (items.length === 0) {
      list.textContent =
        "No shelves. Set aside stores this window's tabs here.";
      return;
    }
    for (const shelf of items) {
      list.appendChild(shelfRow(shelf));
    }
  }

  function shelfRow(shelf) {
    const row = document.createElement("li");
    row.className = "item";

    const name = document.createElement("span");
    // textContent, never markup injection: shelf names are fixed today but
    // this row must stay safe if they ever carry page-derived text.
    name.textContent = shelf.name;
    row.appendChild(name);

    const restore = document.createElement("button");
    restore.type = "button";
    restore.className = "small";
    restore.textContent = "Restore";
    restore.addEventListener("click", async () => {
      try {
        const r = await rb("shelf_restore", { id: shelf.id });
        if (r.opened < r.total) {
          toast(
            "Restored " +
              r.opened +
              " of " +
              r.total +
              " tabs. The shelf was kept.",
          );
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
    del.textContent = "Delete";
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

    return row;
  }

  async function refreshLibrary() {
    try {
      const st = await rb("store_status");
      digestsReady = !!st.digests_ready;
      $("library-locked").hidden = !!st.open;
      $("library-content").hidden = !st.open;
      if (!st.open) {
        // A recorded open error is more useful than the generic line.
        $("library-locked-note").textContent = st.error
          ? friendly(new Error(st.error))
          : "They unlock together with your vault. Open the Vault panel from the toolbar. Downloads finished before unlocking are not recorded.";
        return;
      }
      await Promise.all([
        refreshBookmarks(),
        refreshDownloads(),
        shelfRenderList(),
      ]);
    } catch (e) {
      /* leave the panel as-is */
    }
  }

  // ---- from the bookmarks draft ----
  async function refreshBookmarks() {
    try {
      const data = await rb("bookmark_list");
      bookmarkItems = data.items || [];
      renderBookmarks();
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
      renderDownloads();
    } catch (e) {
      /* ignore */
    }
  }

  // ---- from the bookmarks draft ----
  /// Case-insensitive substring match over the two things a person actually
  /// remembers about a bookmark: what it was called and where it went. The
  /// host is covered by the URL test, so "wikipedia" finds a page whose title
  /// never mentions it.
  function bookmarkMatches(item, needle) {
    if (!needle) return true;
    const title = String(item.title || "").toLowerCase();
    const url = String(item.url || "").toLowerCase();
    return title.includes(needle) || url.includes(needle);
  }

  function renderBookmarks() {
    const list = $("bookmark-list");
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
        count.textContent =
          shown.length + " of " + bookmarkItems.length + " shown";
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
      li.appendChild(
        el(
          "div",
          "item-sub",
          item.has_digest
            ? "Page snapshot from " + fmtTime(item.digest_recorded_at)
            : "No page snapshot recorded",
        ),
      );

      const row = el("div", "item-row");

      const openBtn = el("button", "small", "Open");
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
      const checkBtn = el("button", "small", "Open and check");
      checkBtn.type = "button";
      checkBtn.disabled = !digestsReady;
      checkBtn.title = digestsReady
        ? "Open this bookmark and compare the page against its recorded snapshot"
        : "Change tracking needs the page's own bytes, which this platform cannot provide";
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

      const editBtn = el("button", "small", "Edit");
      editBtn.type = "button";
      editBtn.addEventListener("click", () => {
        editingBookmark = item.id;
        $("bookmark-url").value = item.url || "";
        $("bookmark-title").value = item.title || "";
        $("bookmark-error").textContent = "";
        $("bookmark-form").hidden = false;
        $("bookmark-url").focus();
      });
      row.appendChild(editBtn);

      const delBtn = el("button", "small danger", "Delete");
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
    $("bookmark-error").textContent = "";
  }

  // The edit form had no submit handler, which made it the most convincing
  // of the dead forms: Edit opened it and focused the URL field, so it looked
  // alive right up until "Save changes" did nothing -- no write, no error.
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
      err.textContent = "Address is required.";
      return;
    }
    try {
      await rb("bookmark_update", {
        id: editingBookmark,
        url,
        title: $("bookmark-title").value.trim(),
      });
      resetBookmarkForm();
      await refreshBookmarks();
    } catch (e) {
      err.textContent = friendly(e);
    }
  });
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
      picked = await rb("file_pick_open", { title: "Choose an image" });
    } catch (e) {
      onError(friendly(e));
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
      onError(friendly(e));
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
    note.textContent = "Reading the image...";
    startScan(
      "recovery",
      (data) => {
        if (!data.key) {
          note.textContent =
            "No recovery key found in that image. A photo of the key wrapped over several lines reads best.";
          return;
        }
        $("recovery-input").value = data.key;
        note.textContent =
          "Filled in from the image. Check it against your written copy before unlocking, because 6 and b look alike to a scanner.";
      },
      (msg) => {
        note.hidden = true;
        err.textContent = msg;
      },
    );
  });

  // Idea 2: say what is legible in an image before it is shared.
  $("leakcheck-pick").addEventListener("click", () => {
    const err = $("leakcheck-error");
    const status = $("leakcheck-status");
    const list = $("leakcheck-list");
    err.textContent = "";
    list.replaceChildren();
    status.textContent = "Reading the image...";
    startScan(
      "leaks",
      (data) => {
        const findings = data.findings || [];
        if (!findings.length) {
          // "Nothing found" and "no text at all" are different answers and
          // the difference matters to someone about to post a screenshot.
          status.textContent = data.regions
            ? "Read " + data.regions + " line(s) and found nothing sensitive."
            : "No readable text found in that image.";
          return;
        }
        status.textContent =
          "Found " +
          findings.length +
          " thing(s) worth checking before sharing:";
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
  const DNS_MODES = ["system", "mullvad", "quad9"];
  const DNS_MIRRORS = [
    {
      system: "dns-system",
      mullvad: "dns-mullvad",
      quad9: "dns-quad9",
      describe: "dns-describe",
      restart: "dns-restart",
    },
    {
      system: "dnsp-system",
      mullvad: "dnsp-mullvad",
      quad9: "dnsp-quad9",
      describe: "dnsp-describe",
      restart: "dnsp-restart",
    },
  ];
  const DNS_SHORT = { system: "System", mullvad: "Mullvad", quad9: "Quad9" };

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
    // A preferences file that exists and cannot be read. The mode shown is the
    // DEFAULT, not the user's choice, and the default is plaintext DNS -- so
    // someone who picked Mullvad or Quad9 is no longer on it. Said out loud in
    // both mirrors of this control, because a silent revert of a protection is
    // the failure this whole row exists to prevent.
    for (const mirror of DNS_MIRRORS) {
      const note = $(mirror.restart);
      if (st.settings_unreadable) {
        note.hidden = false;
        note.textContent =
          "Your settings file could not be read, so this reverted to System " +
          "(unencrypted) DNS. Choose a resolver again to restore it.";
      }
    }

    const known = DNS_MODES.includes(st.mode);
    const engaged = known && st.mode !== "system";
    $("dns-label").textContent = "DNS";
    $("btn-dns").classList.toggle("is-active", engaged);
    $("btn-dns").title = known
      ? "Who resolves the sites you visit: " +
        (st.describe || DNS_SHORT[st.mode])
      : "This build does not recognize the resolver that is set. Open this to " +
        "choose one.";
    for (const mirror of DNS_MIRRORS) {
      $(mirror.describe).textContent = st.describe || "";
      for (const name of DNS_MODES) {
        $(mirror[name]).classList.toggle("active", known && st.mode === name);
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
            "Saved, but this browser engine version could not apply it.";
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
  function wearTheme(name) {
    if (name === "default") {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = name;
    }
    for (const t of ACCENT_THEMES) {
      $("accent-" + t).classList.toggle("active", t === name);
    }
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
      try {
        await rb("dns_set", { mode });
        // Both mirrors get the note, because the user may have made the
        // choice from either one and a restart requirement they never saw is
        // a setting they believe is already in force.
        for (const mirror of DNS_MIRRORS) {
          const note = $(mirror.restart);
          note.hidden = false;
          note.textContent = DNS_RESTART_NOTE;
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

  // ---- the chosen resolver cannot be reached ------------------------------
  //
  // Rust decides whether this is true; the chrome only renders it. The copy is
  // HEDGED on purpose -- the browser genuinely cannot tell a blocking network
  // from a VPN that is still reconnecting, and a banner that overstates what it
  // knows teaches people to ignore banners.
  const RESOLVER_NAMES = { mullvad: "Mullvad", quad9: "Quad9" };

  function applyResolverState(data) {
    const banner = $("resolver-warning");
    const show = !!(data && data.unreachable);
    if (show) {
      const name = RESOLVER_NAMES[data.mode] || "your DNS service";
      $("resolver-body").textContent =
        "PATANYX cannot reach " +
        name +
        ", which you chose to resolve the sites you visit, so pages will not " +
        "load until it can. This usually means the network is blocking it, " +
        "which is common on hotel, airport and cafe WiFi before you sign in. " +
        "It can also mean the connection is down, or a VPN is still " +
        "reconnecting. To get online here: open DNS in the toolbar, choose " +
        "System, and restart PATANYX. That sends your lookups to this network " +
        "instead of to " +
        name +
        ", so change it back when you leave.";
    }
    if (banner.hidden !== !show) {
      banner.hidden = !show;
      syncChromeHeight();
    }
  }

  // ---- a scheduled check found something ---------------------------------
  //
  // NOTIFICATION ONLY. The banner never downloads or installs; "Show me" opens
  // the Updates panel, where the accept has always lived. A browser that
  // installed on its own would be a different product.
  function applyUpdateChecked(data) {
    const banner = $("update-banner");
    // The updater's own snapshot. `state` and its values are a contract with
    // updater.rs (status_json), pinned by tests there -- "offered" is the one
    // state worth interrupting for. Up-to-date, refused, failed and
    // downloading all belong in the panel, not across the top of the window.
    const offered = data && data.state === "offered";
    if (offered) {
      $("update-banner-body").textContent =
        (data.offered
          ? "Version " + data.offered + " is ready to install. "
          : "") +
        "Nothing has been downloaded yet. Open Updates to see what changed " +
        "and decide.";
    }
    if (banner.hidden !== !offered) {
      banner.hidden = !offered;
      syncChromeHeight();
    }
  }

  $("update-banner-open").addEventListener("click", () => {
    $("update-banner").hidden = true;
    syncChromeHeight();
    // The Updates button is built by update.js, so it may not exist in a
    // stripped build; clicking nothing is better than throwing.
    const button = document.getElementById("btn-update");
    if (button) button.click();
  });
  $("update-banner-dismiss").addEventListener("click", () => {
    $("update-banner").hidden = true;
    syncChromeHeight();
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
      syncChromeHeight();
      return;
    }
    chip.textContent = percent + "%";
    if (chip.hidden) {
      chip.hidden = false;
      syncChromeHeight();
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

  function applyNavigationBlocked(data) {
    if (!data || !data.host) return;
    blockedHost = data.host;
    const rule =
      data.rule && data.rule !== data.host
        ? " It matched the rule " +
          data.rule +
          ", which also covers its subdomains."
        : "";
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
    $("blocked-body").textContent =
      "PATANYX did not open " +
      data.host +
      " because it has been reported for phishing or malware." +
      rule +
      " If you believe this is wrong, you can open it anyway. That applies " +
      "to this tab only and ends when you close it.";
    const banner = $("blocked-warning");
    if (banner.hidden) {
      banner.hidden = false;
      syncChromeHeight();
    }
  }

  function hideBlocked() {
    const banner = $("blocked-warning");
    if (!banner.hidden) {
      banner.hidden = true;
      syncChromeHeight();
    }
  }

  $("blocked-allow").addEventListener("click", async () => {
    if (!blockedHost) return;
    try {
      await rb("blocklist_allow", { host: blockedHost });
      hideBlocked();
    } catch (e) {
      toast(friendly(e), true);
    }
  });
  $("blocked-dismiss").addEventListener("click", hideBlocked);

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
  const ENGINE_LABELS = {
    script_setting: "JavaScript setting",
    smartscreen_off: "SmartScreen reporting off",
    tracking_prevention: "Engine tracking prevention",
    navigation_tracking: "Navigation tracking",
    autofill_off: "Engine autofill and password store off",
    // The storage promise, asked of the engine rather than assumed. This row
    // is why the panel can say "ephemeral" at all: until it read back, the
    // browser reported the mode it had REQUESTED, so a tab whose in-private
    // flag never took still displayed as keeping nothing.
    ephemeral_confirmed: "Ephemeral storage for this tab",
    // Process-wide, and the one row here that is not about this tab. "REFUSED"
    // means the browser fell back to the engine's default environment and lost
    // its hardened startup arguments along with crash-report suppression.
    hardened_environment: "Hardened engine environment",
    // Process-wide. "REFUSED" means the OS would not tell this process when
    // the workstation locks, so the vault stays open behind a locked screen
    // until the inactivity timer catches it.
    session_lock_registered: "Lock vault when the screen locks",
    // Whether THIS tab's autofill save/fill channel actually registered.
    // "REFUSED" here means the Passwords section in Tab Activity cannot
    // offer or accept a fill for this tab no matter what the vault holds --
    // the same "what the engine confirmed, not what was requested" rule as
    // every other row above.
    content_script_registered: "Login autofill script installed",
    // Process-wide and MEASURED, not read back off an API: a background
    // thread completes a real SOCKS5 greeting against the loopback tunnel
    // front and reads the tunnel's own status before this says "confirmed".
    // "REFUSED" before the vault unlocks usually means the port is
    // deliberately accepting nothing -- the browser refusing to leak, not
    // (only) something broken. "not attempted" here means the user chose
    // no tunnel, and the special case in renderEngineConfirmed says so
    // instead of claiming "not applicable on this engine".
    tunnel: "Tunnel carrying this browser's traffic",
  };
  const ENGINE_STATE_TEXT = {
    applied: "confirmed by the engine",
    failed: "REFUSED by the engine",
    not_attempted: "not applicable on this engine",
  };

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
          ? "off (no tunnel chosen)"
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
      li.appendChild(el("strong", null, "Malicious-site list"));
      const count =
        blocklistHosts === null
          ? ""
          : ", " + blocklistHosts.toLocaleString() + " sites blocked";
      if (blocklistFailure !== null) {
        li.appendChild(
          el(
            "span",
            "error",
            " REFRESH FAILED. Still blocking with the list already" +
              " downloaded" +
              count +
              (blocklistFailure ? " (" + blocklistFailure + ")" : ""),
          ),
        );
      } else {
        li.appendChild(el("span", "muted", " up to date" + count));
      }
      list.appendChild(li);
    }
  }

  const LEAK_TEXT = {
    email: "Email address",
    possible_card: "Possible payment card number",
    long_number: "Long number",
    api_token: "Possible API key or token",
    private_key: "Private key header",
    ipv4: "IP address",
    // Says what was done to the text, not what the text is. Every other label
    // here names a kind of secret; this one names the reason you did not
    // notice it.
    hidden_text: "Hidden: too faint to see",
  };

  // Capability probe. Both controls stay hidden unless the models are
  // actually installed AND the platform can show a file chooser, because a
  // button that cannot work is worse than no button.
  (async () => {
    try {
      const st = await rb("ocr_status");
      ocrAvailable = !!(st && st.available && st.file_choice);
    } catch (e) {
      ocrAvailable = false;
    }
    $("recovery-scan").hidden = !ocrAvailable;
    $("leakcheck").hidden = !ocrAvailable;
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
        applyResolverState({ unreachable: !!st.showing, mode: st.mode });
      }
    } catch (e) {
      console.error("resolver_status failed:", e);
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
      const verifyBtn = el("button", "small", "Verify");
      verifyBtn.type = "button";
      const result = el("span", "item-sub", "");
      verifyBtn.addEventListener("click", async () => {
        verifyBtn.disabled = true;
        result.className = "item-sub";
        result.textContent = "Checking...";
        try {
          const r = await rb("download_verify", { id: item.id });
          if (!r.record_ok) {
            result.className = "error";
            result.textContent =
              "This record has been altered. It no longer matches what this browser wrote.";
          } else if (r.file === "match") {
            result.textContent =
              "Unchanged: byte-identical to what was downloaded.";
          } else if (r.file === "differs") {
            result.className = "error";
            result.textContent =
              "The file on disk differs from what was downloaded.";
          } else if (r.file === "missing") {
            result.textContent =
              "File not found in the downloads folder. Was it moved, renamed, or deleted?";
          } else {
            result.className = "error";
            result.textContent = "The file could not be read.";
          }
        } catch (e) {
          result.className = "error";
          result.textContent = friendly(e);
        }
        verifyBtn.disabled = false;
      });
      row.appendChild(verifyBtn);
      row.appendChild(result);
      li.appendChild(row);
      list.appendChild(li);
    }
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
          "Recovery: this vault has a recovery key, the one shown once and meant for paper. It is the only way in if the passphrase is forgotten, and a passphrase change does not affect it.";
      } else {
        line.textContent =
          "Recovery: this vault has NO recovery key. If the passphrase is forgotten, the contents are unrecoverable by you, by us, by anyone. Exports do not change that; they are encrypted under a passphrase too.";
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
      $("bk-exp-pick").hidden = !choice;
      $("bk-plain-pick").hidden = !choice;
      $("bk-exp-dest").readOnly = choice;
      $("bk-plain-dest").readOnly = choice;
      if (choice) {
        $("bk-exp-dest").placeholder = "No location chosen yet";
        $("bk-plain-dest").placeholder = "No location chosen yet";
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
  registerPanel("library", {
    el: $("library-panel"),
    button: $("btn-library"),
    heightPx: LIBRARY_OPEN_PX,
    onOpen: refreshLibrary,
  });

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
      $("about-build").textContent =
        "Could not read this build's details: " + friendly(e);
      return;
    }
    if (!info) return;

    $("about-title").textContent = "About " + (info.name || "PATANYX");
    $("about-build").textContent =
      (info.name || "PATANYX") +
      " version " +
      (info.version || "unknown") +
      ", rendering with " +
      (info.engine || "the system web engine") +
      ".";

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
        ? "This build is made with " +
          n.toLocaleString() +
          " third-party open-source packages."
        : "This build's third-party inventory could not be counted.";

    aboutLoaded = true;
  }

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
        button.textContent = "Loading…";
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
    "Show the full license",
    "Hide the license",
    null,
  );

  wireDisclosure(
    "about-third-party-toggle",
    "about-third-party-text",
    "Show third-party licenses",
    "Hide third-party licenses",
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
      $("diag-result").textContent = "Copied to clipboard.";
    } catch (e) {
      toast(friendly(e), true);
    }
  });

  wireSavePicker(
    "diag-pick",
    "diag-dest",
    "Save the diagnostic report",
    "patanyx-diagnostics.json",
  );

  $("diag-save").addEventListener("click", async () => {
    $("diag-result").hidden = true;
    const dest = $("diag-dest").value.trim();
    if (!dest) {
      toast("Choose or type a destination first.", true);
      return;
    }
    try {
      await rb("diagnostics_export", { dest });
      $("diag-result").hidden = false;
      $("diag-result").textContent = "Saved to " + dest + ".";
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
