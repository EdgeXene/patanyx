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
  // The same floor for the layout whose toolbar is down the left edge. One
  // row of pills leaves the top, so the strip is the tab row plus the address
  // row, and the honest floor is lower. Measured at 1280x800 in Chromium:
  // 41 + 47 = 88. Keeping the 148 floor here would have padded the page down
  // by 60px of nothing, in the layout the floor was raised to protect.
  const CHROME_CLOSED_FLOOR_LEFT_PX = 88;

  function closedChromePx() {
    const strip = $("tabstrip");
    const bar = $("toolbar");
    const floor = sidebarShowing()
      ? CHROME_CLOSED_FLOOR_LEFT_PX
      : CHROME_CLOSED_FLOOR_PX;
    if (!strip || !bar) return floor;
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
    return Math.max(floor, Math.ceil(measured));
  }
  // Whether the feature buttons are currently in the left strip. Read from
  // the DOM rather than from a variable so there is one answer: the attribute
  // IS the layout, and everything else -- the stylesheet, the measurement,
  // the inset -- keys off it.
  function sidebarShowing() {
    return document.documentElement.dataset.toolbarPlacement === "left";
  }
  // What the chrome is using down the left edge. Zero unless the sidebar is
  // showing, and measured rather than assumed for the same reason the height
  // is: a width in this file would be a claim about padding and icon metrics
  // that the stylesheet is free to change.
  function closedChromeLeftPx() {
    const rail = $("sidebar");
    if (!sidebarShowing() || !rail) return 0;
    return Math.ceil(rail.getBoundingClientRect().width);
  }
  // The stylesheet needs the same measurements: panels sit BELOW the chrome
  // and beside the sidebar, and a constant there is how their first line
  // ended up rendering under the toolbar (96px against a 148px chrome).
  // Published as CSS variables and kept current whenever a row or the rail
  // changes size. The observer is guarded: the DOM harness the gates run in
  // has no ResizeObserver, and the defaults in the stylesheet keep that
  // environment honest anyway.
  function publishChromeMetric() {
    const root = document.documentElement.style;
    root.setProperty("--chrome-closed-px", closedChromePx() + "px");
    root.setProperty("--chrome-left-px", closedChromeLeftPx() + "px");
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
      for (const id of ["tabstrip", "toolbar", "bmbar", "sidebar"]) {
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
        // tabs_changed. This event stays the only writer, so there is
        // still exactly one source of truth for what the strip shows.
        lastTabItems = (msg.data && msg.data.items) || [];
        renderTabs(lastTabItems);
        break;
      case "find_open":
        openFindBar();
        break;
      // Phase 4: an activation or release call finished on its worker;
      // the row and the toolbar re-read the state from Rust.
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
          const name = fileNameFromPath(data.path) || fileNameFromUrl(data.url);
          // data.mark is what happened to the file's Mark-of-the-Web (see
          // platform/motw.rs). Only "failed" is worth a word: "scrubbed"
          // is the normal case on Windows and "clean" or "n/a" mean there
          // was nothing to do. A failure means the source address is still
          // written next to the file, and that is said plainly rather than
          // hidden behind an ordinary "Saved".
          if (data.mark === "failed") {
            toast(
              "Saved " +
                name +
                ", but Windows kept the download's source " +
                "address next to the file and it could not be removed.",
              true,
            );
          } else if (data.mark === "unknown") {
            // NOT the same sentence as "failed". That one asserts the
            // address is there; this one says only that it could not be
            // checked, which is the honest limit of what the browser knows.
            toast(
              "Saved " +
                name +
                ". PATANYX could not check whether Windows wrote the " +
                "download's source address next to it.",
              true,
            );
          } else {
            toast("Saved " + name);
          }
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
      // The region-read capture settled (well or badly). Function-declared
      // below and hoisted, same file, so no window hook is needed.
      case "region_capture_ready":
        onRegionCaptureReady(msg.data || {});
        break;
      // A contact asked what WE downloaded, and this browser answered
      // automatically. Surfaced unconditionally: an automatic reply the
      // user cannot see is the shape of a backdoor even when it is not one.
      case "download_compare_request_received":
        toast(
          "A contact asked what you downloaded from " +
            hostOf((msg.data && msg.data.url) || "") +
            ". Your record's fingerprint was sent back.",
        );
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
    // Whole-page capture has no size bound of its own, so a very long page
    // can exceed what this browser will hold at once. Named separately from
    // capture_failed because the remedy differs: this one has a cause the
    // user can act on.
    capture_too_large:
      "That page is too long to capture in one picture. Try saving a shorter page.",
    busy: "A capture is already in progress",
    no_storable_tabs:
      "Nothing to set aside: every tab here is ephemeral or an internal page",
    // The restart did not happen and nothing was lost: the session was put
    // back exactly as it was, so the honest thing to offer is the old
    // manual route rather than a retry that would fail the same way.
    relaunch_failed:
      "PATANYX could not start a replacement, so nothing was changed. " +
      "Close the browser and open it again to apply the tunnel setting.",
    bad_args: "That does not look right",
    // Find across tabs is the first premium-gated feature. The panel ALSO
    // un-hides a standing note on this code -- a toast alone would vanish
    // and leave the run button looking broken.
    premium_required: "Find across tabs is a Premium feature.",
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
    // The region-read mode's own refusals. Stale is a state, not a fault:
    // the capture this panel was looking at has been replaced or released,
    // and capturing again is the whole remedy.
    // Download corroboration, asking side. Both are about OUR OWN record,
    // not the contact's: the contact's refusals arrive as notes, worded
    // separately, because "you have no record of this" and "they have no
    // record of this" are different sentences and must not share one.
    no_download: "There is no record of that download to compare.",
    record_untrusted:
      "Your own record of this download failed its integrity check, so its fingerprint cannot be trusted. Nothing was sent.",
    // Deep Recall. Its own sentence rather than a generic "full": the user
    // can act on this, and the action is to delete something first.
    archive_full:
      "Deep Recall is full. Delete a saved page to make room for this one.",
    region_stale: "That capture expired. Capture the page again.",
    region_empty: "Drag a rectangle around the text to read.",
    region_out_of_bounds:
      "That selection is outside the capture. Drag inside the image.",
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
    // The browser-wide clear's own failures. Separate codes from the per-site
    // ones above because the sentences differ: "for this site" is false here,
    // and no_persistent_tab is not a fault at all.
    cookie_delete_all_failed:
      "Could not clear cookies. The engine refused the request; nothing was changed.",
    // Expected, not broken: quarantine tabs keep their cookies in memory and
    // throw them away when they close, so there is genuinely nothing saved to
    // clear. Says what to do rather than only what went wrong.
    no_persistent_tab:
      "Every open tab is a quarantine tab, and those keep no saved cookies. Open an ordinary tab to clear the saved ones.",
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
    if (!tab.url || tab.url === "about:blank") return "New tab";
    return hostOf(tab.url);
  }

  let lastTabItems = []; // last payload of the tabs_changed event

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
      chip.title = tab.title || tab.url || "";
      // Truncation itself is CSS (max-width + ellipsis).
      if (tabSelectMode) {
        const tick = document.createElement("input");
        tick.type = "checkbox";
        tick.className = "chip-select";
        tick.checked = tabSelection.has(tab.id);
        tick.setAttribute("aria-label", "Select " + chipLabel(tab));
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
      close.title = "Close tab";
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
        toast("Selecting several tabs at once is a Premium feature.", true);
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
      toast(
        failed.length + " of " + ids.length + " could not be changed.",
        true,
      );
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
      "Close " + ids.length + (ids.length === 1 ? " tab?" : " tabs?"),
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
          res.left_out +
            (res.left_out === 1 ? " tab was" : " tabs were") +
            " not set aside: ephemeral and internal tabs are never shelved.",
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
      const title = row.title || host || "New tab";
      let status = "";
      if (row.state === "pending") status = "Searching...";
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
      findtabsProgress.textContent =
        "Searched " + settled + " of " + rows.length + " tabs.";
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
      // #sidebar is exempt because in the left layout it IS the toolbar. The
      // buttons move into it, so without this a press on a feature button
      // would close the open panel before the click reached the button --
      // running its onClose, which clears vault secrets and wipes a chat
      // transcript -- and the click would then reopen it. Same button, twice
      // the work, and one of the two panels loses state doing it.
      if (
        panel &&
        !panel.el.contains(ev.target) &&
        !ev.target.closest("#toolbar, #sidebar, #tabstrip, #confirm-overlay")
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
    // The only control that makes a shelf, and it sits in the bookmarks
    // view -- hidden from the "Sets of tabs" view that lists shelves. The
    // palette is its second way in.
    { label: "Set aside all tabs", buttonId: "set-aside" },
    // These two buttons are built at runtime by integrity.js/update.js, not
    // in index.html -- which is exactly why they were missed here: nothing
    // failed when the palette predated them. `paletteVisibleActions` resolves
    // ids live at open time, so runtime injection needs no special casing.
    { label: "Open Integrity", buttonId: "btn-integrity" },
    // The other two tabs of the tools modal. Their buttons are the tab strip
    // itself, so choosing one opens the modal AND lands on the right tool --
    // this is what put all three in one modal in the first place: neither
    // Deep Recall nor the image check was findable from here before.
    { label: "Open Deep Recall", buttonId: "btn-tab-recall" },
    { label: "Check an image before you share it", buttonId: "btn-tab-imagecheck" },
    { label: "Open Updates", buttonId: "btn-update" },
    { label: "About this site", buttonId: "btn-site-info" },
    { label: "Save page as PDF", buttonId: "btn-save-pdf" },
    { label: "About PATANYX", buttonId: "btn-about" },
    // Premium tab-pack entries. Their buttons are hidden literals in
    // index.html (the gate resolves ids there), and the premium refusal
    // happens server-side when the clicked surface asks Rust -- the
    // palette rows stay visible so the features are discoverable.
    { label: "Switch tab...", buttonId: "btn-switcher" },
    { label: "Select tabs...", buttonId: "btn-tabselect" },
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
    onOpen: refreshVault,
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
  // The last state the PROBE reported, kept because the warning banner needs
  // to tell two different situations apart that the mode alone cannot:
  // "the vault was never unlocked, so the tunnel never came up" and "the
  // tunnel is carrying traffic and the vault locked itself behind it".
  let tunnelMeasured = "not_attempted";
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
      // "Tabs that can be" rather than "your tabs": ephemeral tabs and
      // internal pages are never set aside, and the unqualified promise was
      // simply false for anyone browsing without a saved profile. The exact
      // count is not known until the button is pressed, and that is where
      // it is now stated.
      note.textContent =
        "Not in effect yet. The engine takes the tunnel setting only at " +
        "startup. Apply and restart does it for you: the tabs that can be " +
        "set aside reopen after you unlock.";
      note.hidden = false;
    } else {
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
  const TUNNEL_REPORT_TEXT = {
    not_attempted: "off (no tunnel chosen)",
    applied: "carrying this browser's traffic",
    failed: "not carrying traffic",
  };

  function tunnelReportLine(report, startError) {
    // An unknown value from a future engine falls back to the raw word
    // rather than to silence: a status this build cannot name is still
    // better shown than hidden.
    const known = report == null ? null : TUNNEL_REPORT_TEXT[String(report)];
    let line =
      "Status: " +
      (report == null ? "no measurement yet" : known || String(report));
    if (startError) {
      // Verbatim: the engine's error text is key-free by contract.
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
    // A null has_config means the vault is locked, so Rust cannot say
    // whether a configuration exists. That is a PREREQUISITE, not a
    // failure, and it is now said before the controls it gates rather than
    // after a click that walks the user through a file picker to nowhere.
    const vaultLocked = st.has_config === null || st.has_config === undefined;
    const prereq = $("tunnelp-vault-first");
    if (prereq) prereq.hidden = !vaultLocked;
    for (const id of ["tunnelp-import", "tunnelp-paste-import", "tunnelp-remove"]) {
      const btn = $(id);
      if (btn) btn.disabled = vaultLocked;
    }
    const paste = $("tunnelp-paste");
    if (paste) paste.disabled = vaultLocked;

    if (vaultLocked) {
      configLine.textContent =
        "Unlock the vault to see whether a configuration is stored.";
    } else if (st.has_config) {
      configLine.textContent = "A configuration is stored in the vault.";
    } else {
      configLine.textContent = "No configuration imported yet.";
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
      tunnelMode === "imported" && !vaultUnlocked && tunnelMeasured !== "applied";
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
        title.textContent = "Unlock your vault to use Private Tunnel";
        body.textContent =
          "Private Tunnel keeps its configuration in the vault, so pages " +
          "will not load until you unlock it. PATANYX will NOT fall back " +
          "to a direct connection. Unlock the vault, or switch the tunnel " +
          "off in its panel.";
        // Point at the thing that fixes it, not at the panel that explains
        // it. One button, retargeted, so the banner never grows a second.
        open.textContent = "Open vault";
        open.dataset.target = "vault";
      } else {
        title.textContent = "The tunnel is not carrying traffic";
        body.textContent =
          "Pages are not loading because the tunnel is down. PATANYX will " +
          "NOT fall back to a direct connection. Open the tunnel panel.";
        open.textContent = "Open Tunnel panel";
        open.dataset.target = "tunnel";
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
        err.textContent = "Paste a configuration first.";
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
            ? "None of your " +
                lost +
                (lost === 1 ? " open tab" : " open tabs") +
                " can be set aside, because tabs opened without a saved " +
                "profile are never written to the vault. Restarting now " +
                "closes them for good."
            : lost +
                (lost === 1 ? " tab" : " tabs") +
                " cannot be set aside and will close for good; " +
                kept +
                (kept === 1 ? " will" : " will") +
                " reopen after you unlock. Tabs opened without a saved " +
                "profile are never written to the vault.",
          "Restart anyway",
        );
        if (!ok) return;
      }

      btn.disabled = true;
      btn.textContent = "Restarting…";
      try {
        await rb("tunnel_apply_restart");
        // No success path to render: the reply means the replacement is
        // already running and this process is on its way out.
      } catch (e) {
        // It did NOT happen. Nothing was shelved that is not also cleaned
        // up, so the honest thing is to put the button back.
        btn.disabled = false;
        btn.textContent = "Apply and restart now";
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
      $("dv-host").textContent = divergenceHost
        ? "This tab is on " + divergenceHost + "."
        : "This tab is not on a website.";
      $("dv-off").checked = !!proof.off_for_this_site;
      $("dv-off").disabled = !divergenceHost;
      // Observed, never inferred from the pref: a tab opened before the
      // pref last changed still carries what it was built with.
      if (!proof.enabled_globally) {
        $("dv-proof").textContent =
          "Fingerprint Divergence is switched off, so this tab was given no noise.";
      } else if (proof.registered) {
        $("dv-proof").textContent =
          "This tab was given divergence for " +
          (proof.surfaces || []).join(", ") +
          ". That is what was installed in it, not proof that a site was fooled.";
      } else {
        $("dv-proof").textContent =
          "This tab was given no divergence. A tab keeps whatever it started with, so a change made since it opened is not in it.";
      }
      const list = await rb("divergence_sites_list");
      const off = (list.items || []).filter((i) => i.off).map((i) => i.host);
      $("dv-list").textContent = off.length
        ? "Switched off for: " + off.join(", ")
        : "No site has it switched off.";
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
      await rb("divergence_site_set", {
        host: divergenceHost,
        off: $("dv-off").checked,
      });
    } catch (e) {
      $("dv-off").checked = !$("dv-off").checked;
      toast(friendly(e), true);
    }
    await refreshDivergenceSite();
  });

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
    $("pv-forget-all-desc").textContent = copy.intro || "";
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
          ? "Locking in " +
            left +
            " seconds because nothing has happened for a while."
          : "Locking now.";
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
      // The folder bar draws from bookmarks, which only exist once the store
      // is open. At boot it rendered its empty note because the vault was
      // still locked, and nothing brought it back: unlock is the moment its
      // contents become knowable, so it refreshes here rather than waiting
      // for the Library panel to be opened.
      void refreshBookmarkBar();
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

  function premiumLockNote(st) {
    if (st.state === "locked") {
      return "Unlock your vault to use Premium features.";
    }
    // Phase 4: paid and ACTIVE, but not activated on THIS device. Never a
    // purchase prompt (they already paid); the Vault panel says why.
    if (st.state === "unactivated") {
      return "Premium is not activated on this device yet. Open the Vault panel to activate it.";
    }
    if (!st.on_sale) {
      return "A Premium feature, arriving the day Premium launches.";
    }
    return st.state === "lapsed"
      ? "Your Premium has ended. Renew to use this again."
      : "A Premium feature. Upgrade to Premium to use it.";
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
        row.hidden = true;
        return;
      }
      row.hidden = false;
      $("premium-head").textContent = lic.row_head;
      $("premium-sub").textContent = lic.row_sub || "";
      renderActivation(lic);
    } catch (e) {
      clearLicenceConfirm();
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
    if (!box || !note || !activate || !release) return;
    if (lic.activation === "activated") {
      box.hidden = false;
      note.textContent =
        "Activated on this device. A license can be active on up to 5 devices.";
      activate.hidden = true;
      release.hidden = false;
      release.disabled = !!lic.activation_busy;
      return;
    }
    if (lic.activation === "unactivated") {
      box.hidden = false;
      note.textContent = lic.activation_note || "";
      release.hidden = true;
      activate.hidden = false;
      activate.disabled = !!lic.activation_busy;
      return;
    }
    box.hidden = true;
    note.textContent = "";
    activate.hidden = true;
    release.hidden = true;
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

  $("premium-release").addEventListener("click", async () => {
    // Destructive for THIS machine (Premium goes off here), so it asks.
    const yes = await askConfirm(
      "Release this device? Premium turns off on this computer and the " +
        "slot becomes free for another one. You can activate again later " +
        "if a slot is free.",
      "Release",
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
    // The plain-HTTP warning: same band, same clipping rule.
    "insecure-warning",
    // The find bar. NOT a banner by role (role="search"), which is exactly how
    // it escaped the toolbar gate's role=alert|status sweep and this list.
    // With the toolbar across the top the closed strip is measured against a
    // 148px floor, and the ~40px of slack under the two rows happened to be
    // enough for the bar -- so Ctrl+F looked fine on every top-toolbar test.
    // With the toolbar down the LEFT edge the strip is only the tab row and
    // is measured tightly (floor 88), the slack is gone, and the bar rendered
    // under the page: Ctrl+F "did nothing". Its own comment in index.html
    // says it "goes through the same height sync the banners use"; now it
    // does.
    "findbar",
  ];

  function syncChromeInsets() {
    const base = openPanelName
      ? panels.get(openPanelName).heightPx
      : closedChromePx();
    let extra = 0;
    // An open folder menu grows the strip while it is open, for the same
    // reason banners do: the chrome is CLIPPED to the height Rust was told,
    // so anything drawn below that height is not drawn at all. This is the
    // lock-warning banner defect in a different costume, and the fix is the
    // same one -- measure it and ask for the room.
    const folderMenu = document.querySelector(".bmfolder-menu");
    if (folderMenu) {
      extra += Math.ceil(folderMenu.getBoundingClientRect().height) + 8;
    }
    for (const id of BANNERS) {
      const banner = $(id);
      if (banner && !banner.hidden) {
        extra += Math.ceil(banner.getBoundingClientRect().height);
      }
    }
    const top = base + extra;
    rb("set_chrome_insets", { top, left: closedChromeLeftPx() }).catch(
      () => {},
    );
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
      syncChromeInsets();
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

    // Plain-HTTP warning: `insecure_pending` is the URL the navigation
    // handler is holding for the ACTIVE tab, or null. Rendered from status,
    // like the save offer, so a tab switch shows or hides it correctly.
    applyInsecurePending(
      st.insecure_pending || null,
      st.insecure_pending_host || null,
    );

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
      toast("Saved, but the view could not refresh: " + friendly(e), true);
      return;
    }
    renderFolderGrid();
    renderBookmarks();
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
        input.setAttribute("aria-label", "Rename folder");
        form.appendChild(input);
        const save = el("button", "small", "Save");
        save.type = "submit";
        form.appendChild(save);
        const cancel = el("button", "small", "Cancel");
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
      const renameBtn = el("button", "small", "Rename");
      renameBtn.type = "button";
      renameBtn.addEventListener("click", () => {
        renamingFolder = folder.tag;
        renderFolderGrid();
      });
      actions.appendChild(renameBtn);
      const delBtn = el("button", "small danger", "Delete folder");
      delBtn.type = "button";
      delBtn.title = "Removes the folder. The bookmarks in it are kept.";
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
            "Empty. Use Folders on any bookmark to file it here, or drag one in.";
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
          const unfile = el("button", "small", "Remove");
          unfile.type = "button";
          unfile.title = "Remove from this folder. The bookmark is kept.";
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
    head.textContent = "All bookmarks";
    grid.appendChild(head);
    const hint = document.createElement("p");
    hint.className = "panel-foot";
    hint.textContent = haveFolders
      ? "Drag a bookmark onto a folder above, or use Folders on any bookmark in the Bookmark Manager."
      : "Make a folder above, then file bookmarks into it from the Bookmark Manager.";
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
        inFolders.textContent = "in " + item.tags.join(", ");
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
        errline.textContent = "Type a folder name first.";
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
      "Delete the folder “" +
        name +
        "”? The bookmarks in it are kept, just " +
        "no longer filed under this folder.",
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
          "No shelves. Set aside stores this window's tabs here.";
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
    edit.textContent = "Edit";
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
      nameInput.placeholder = "Name";
      nameInput.value = shelf.name || "";
      nameInput.maxLength = 120;
      form.appendChild(nameInput);

      const noteInput = document.createElement("textarea");
      noteInput.placeholder = "Notes for this set, such as what it is for";
      noteInput.value = shelf.note || "";
      noteInput.maxLength = 2000;
      noteInput.rows = 3;
      form.appendChild(noteInput);

      const buttons = document.createElement("div");
      buttons.className = "form-buttons";
      const save = document.createElement("button");
      save.type = "submit";
      save.textContent = "Save";
      buttons.appendChild(save);
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = "Cancel";
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
      digestsReady = !!st.digests_ready;
      $("library-locked").hidden = !!st.open;
      $("library-content").hidden = !st.open;
      if (!st.open) {
        // A recorded open error is more useful than the generic line.
        $("library-locked-note").textContent = st.error
          ? friendly(new Error(st.error))
          : "Bookmarks, the tabs you set aside and download records all unlock with your vault. PATANYX offers it when you start it on its own. Downloads that finish before you unlock are not recorded.";
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
        "Tag a bookmark to make a folder",
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
      renderBookmarks();
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
      // Tags, when there are any. One line, textContent like every other
      // field here; the store already lowercased and deduped them.
      if (Array.isArray(item.tags) && item.tags.length) {
        li.appendChild(el("div", "item-sub", "Tags: " + item.tags.join(", ")));
      }

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
        $("bookmark-tags").value = Array.isArray(item.tags)
          ? item.tags.join(", ")
          : "";
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
        err.textContent = "Address is required.";
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
  // Collapsed again for every new scan: text left over from the previous
  // image, under a fresh verdict, is the worst thing this panel could show.
  function leakTextReset() {
    $("leakcheck-readwrap").hidden = true;
    $("leakcheck-text").hidden = true;
    $("leakcheck-text").textContent = "";
    $("leakcheck-showtext").textContent = "Show what it read";
  }

  $("leakcheck-showtext").addEventListener("click", () => {
    const pre = $("leakcheck-text");
    pre.hidden = !pre.hidden;
    $("leakcheck-showtext").textContent = pre.hidden
      ? "Show what it read"
      : "Hide what it read";
    syncChromeInsets();
  });

  $("leakcheck-pick").addEventListener("click", () => {
    const err = $("leakcheck-error");
    const status = $("leakcheck-status");
    const list = $("leakcheck-list");
    err.textContent = "";
    list.replaceChildren();
    leakTextReset();
    status.textContent = "Reading the image...";
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

  // ---- read text on this page (Premium region mode) -----------------------
  //
  // The panel asks Rust to capture the page into memory, shows the capture
  // as an image served over the chrome protocol, and lets the user drag a
  // rectangle to read. The drag happens ON THE IMAGE, so the rect maps to
  // capture pixels with one ratio (naturalWidth / clientWidth) and no
  // chrome-to-content coordinate arithmetic exists to get wrong.
  //
  // premium_required is a STATE the panel shows (#region-premium stays up),
  // never only a toast -- same rule as the findtabs and switcher notes.

  const REGION_OPEN_PX = 500;
  let regionCapture = null; // {token, w, h} of the capture on display
  let regionDrag = null; // {x0, y0} in displayed-image pixels during a drag

  function regionReset() {
    regionCapture = null;
    regionDrag = null;
    $("region-stage").hidden = true;
    $("region-selbox").hidden = true;
    $("region-result-wrap").hidden = true;
    $("region-scope").hidden = true;
    $("region-result").textContent = "";
    $("region-status").textContent = "";
    // Dropping the src releases the decoded image; the buffer itself is
    // freed by ocr_region_close when the panel closes.
    $("region-img").removeAttribute("src");
  }

  async function regionStart() {
    regionReset();
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
    $("region-status").textContent = "Capturing the page...";
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
        ERROR_TEXT[data.error] || "The capture failed.";
      return;
    }
    regionCapture = { token: data.token, w: data.w, h: data.h };
    // Relative URL, so the platform-specific chrome origin resolves it on
    // both engines. Cache-safe: every capture has a fresh token. Set as an
    // ATTRIBUTE so setting and removing are the same vocabulary.
    $("region-img").setAttribute(
      "src",
      "/region-capture/" + data.token + ".png",
    );
    $("region-stage").hidden = false;
    $("region-scope").hidden = false;
    $("region-scope").textContent =
      "Showing the " +
      (data.scope || "capture") +
      ". Drag a rectangle around the text to read.";
    $("region-status").textContent = "";
    syncChromeInsets();
  }

  // The drag state machine. Pointer events on the image only; a stray
  // click (no meaningful drag) is ignored rather than scanned.
  const regionImg = $("region-img");
  const regionSelbox = $("region-selbox");

  function regionDisplayedRect(ev) {
    const x1 = Math.max(0, Math.min(ev.offsetX, regionImg.clientWidth));
    const y1 = Math.max(0, Math.min(ev.offsetY, regionImg.clientHeight));
    const x = Math.min(regionDrag.x0, x1);
    const y = Math.min(regionDrag.y0, y1);
    return {
      x,
      y,
      w: Math.abs(x1 - regionDrag.x0),
      h: Math.abs(y1 - regionDrag.y0),
    };
  }

  regionImg.addEventListener("pointerdown", (ev) => {
    if (!regionCapture || ev.button !== 0) return;
    regionDrag = { x0: ev.offsetX, y0: ev.offsetY };
    regionImg.setPointerCapture(ev.pointerId);
    regionSelbox.hidden = false;
    ev.preventDefault();
  });
  regionImg.addEventListener("pointermove", (ev) => {
    if (!regionDrag) return;
    const r = regionDisplayedRect(ev);
    regionSelbox.style.left = r.x + "px";
    regionSelbox.style.top = r.y + "px";
    regionSelbox.style.width = r.w + "px";
    regionSelbox.style.height = r.h + "px";
  });
  regionImg.addEventListener("pointerup", async (ev) => {
    if (!regionDrag || !regionCapture) return;
    const r = regionDisplayedRect(ev);
    regionDrag = null;
    regionSelbox.hidden = true;
    // A sub-3px drag is a click, and a click is not a selection.
    if (r.w < 3 || r.h < 3) return;
    // One ratio per axis maps displayed pixels to capture pixels; clamping
    // guards the right/bottom edge where rounding could land one past.
    const sx = regionCapture.w / regionImg.clientWidth;
    const sy = regionCapture.h / regionImg.clientHeight;
    const x = Math.min(regionCapture.w - 1, Math.round(r.x * sx));
    const y = Math.min(regionCapture.h - 1, Math.round(r.y * sy));
    const w = Math.max(1, Math.min(regionCapture.w - x, Math.round(r.w * sx)));
    const h = Math.max(1, Math.min(regionCapture.h - y, Math.round(r.h * sy)));
    $("region-status").textContent = "Reading your selection...";
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
            ERROR_TEXT[data.error] || "Could not read that selection.";
          return;
        }
        if (!data.text || !data.text.trim()) {
          $("region-status").textContent =
            "No readable text in that selection. Try a larger area.";
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

  $("region-copy").addEventListener("click", async () => {
    const text = $("region-result").textContent;
    try {
      await navigator.clipboard.writeText(text);
      $("region-status").textContent = "Copied.";
    } catch {
      // Select-and-copy still works on the visible text; say so instead of
      // failing silently.
      $("region-status").textContent =
        "Clipboard is unavailable. Select the text above and copy it directly.";
    }
  });
  $("region-again").addEventListener("click", regionStart);

  registerPanel("region", {
    el: $("region-panel"),
    button: $("btn-ocr-region"),
    heightPx: REGION_OPEN_PX,
    onOpen: regionStart,
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
          "No text was read from this picture. The page is saved and findable by title and address.",
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
      const view = el("button", "small", "View");
      view.type = "button";
      view.addEventListener("click", async () => {
        try {
          const r = await rb("archive_picture_stage", { id: item.id });
          const img = $("recall-preview-img");
          // As an ATTRIBUTE, like the region panel: setting and removing
          // are then the same vocabulary (removeAttribute in the close).
          img.setAttribute("src", "/archive-picture/" + r.token + ".png");
          $("recall-preview").hidden = false;
          $("recall-status").textContent = "";
          syncChromeInsets();
        } catch (e) {
          $("recall-status").textContent = friendly(e);
        }
      });
      row.appendChild(view);
    }
    const del = el("button", "small", "Delete");
    del.type = "button";
    del.addEventListener("click", async () => {
      if (
        !(await askConfirm(
          "Delete this saved page and its picture? This cannot be undone.",
        ))
      ) {
        return;
      }
      try {
        await rb("archive_delete", { id: item.id });
        // The record just deleted may be the one on screen. Rust cleared
        // the slot with the delete; drop the chrome's reference too.
        recallPreviewClose();
        await recallRefresh();
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
  // slot, after which the old token URL is a 404 by design. fire-and-forget
  // on the IPC: closing a picture must never be able to fail on screen.
  function recallPreviewClose() {
    const img = $("recall-preview-img");
    img.removeAttribute("src");
    // Back to Fit for the next picture: a reader who left one zoomed in
    // should not have the next one open mid-page at some arbitrary level.
    recallZoomSet(0);
    $("recall-preview").hidden = true;
    rb("archive_picture_clear").catch(() => {});
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
      $("recall-preview-level").textContent = "Fit";
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
      $("recall-preview-level").textContent = "Fit";
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
    recallZoomSet(RECALL_ZOOM_STEPS[Math.min(next, RECALL_ZOOM_STEPS.length - 1)]);

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
    await refreshPremium();
    if (premiumBlocked()) {
      $("recall-premium").hidden = false;
      syncChromeInsets();
      return;
    }
    $("recall-status").textContent = "Capturing the page...";
    try {
      await rb("archive_save");
      // The outcome arrives as archive_saved: the reading takes about a
      // second, so the reply only confirms the capture started.
      $("recall-status").textContent = "Reading the text...";
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
        ERROR_TEXT[data.error] || "The page could not be saved.";
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
        " The page was long, so the text stops partway down, and the picture is the part that was on screen.";
    } else if (!wholePage) {
      shortfall = " The picture is the part that was on screen.";
    }
    // Says what was actually read, since "saved" alone hides the difference
    // between a page full of words and one the reader found nothing in.
    $("recall-status").textContent =
      data.words > 0
        ? "Saved. " + data.words + " words read from this page." + shortfall
        : "Saved. No text was read from this picture." + shortfall;
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
  const TOOLBAR_PLACEMENTS = ["top", "left"];
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
    if (placement === "left") {
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
    if (placement === "top") {
      delete document.documentElement.dataset.toolbarPlacement;
    } else {
      document.documentElement.dataset.toolbarPlacement = placement;
    }
    placeButtons(placement);
    for (const p of TOOLBAR_PLACEMENTS) {
      const btn = $("placement-" + p);
      if (btn) btn.classList.toggle("active", p === placement);
    }
    // The labels row below only applies to the top layout, and saying so is
    // the difference between a setting that is scoped and one that looks
    // broken. The preference itself is untouched, so choosing Top again
    // gives back whatever was set.
    const note = $("placement-note");
    if (note) {
      note.hidden = placement !== "left";
      note.textContent =
        placement === "left"
          ? "Down the left, buttons are icons only. The choice below applies on top."
          : "";
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
  // after the placement has already been worn -- so in the left layout they
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
      syncChromeInsets();
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
    // updater.rs (status_json), pinned by tests there. TWO states are worth
    // interrupting for, and for a while this listed only one:
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
    const show = state === "offered" || state === "ready";
    if (show) {
      $("update-banner-body").textContent =
        state === "ready"
          ? (version ? "Version " + version + " is " : "It is ") +
            "downloaded and verified. Nothing has been installed: open " +
            "Updates to see what changed and restart when it suits you."
          : (version ? "Version " + version + " is ready to install. " : "") +
            "Nothing has been downloaded yet. Open Updates to see what " +
            "changed and decide.";
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
      syncChromeInsets();
    }
  }

  function hideBlocked() {
    const banner = $("blocked-warning");
    if (!banner.hidden) {
      banner.hidden = true;
      syncChromeInsets();
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
    $("insecure-body").textContent =
      "PATANYX did not open " +
      shownHost +
      " because the connection is plain HTTP, not encrypted. Anything you " +
      "send or receive on this site, including passwords, can be read or " +
      "changed by anyone on the path. You can continue anyway; that applies " +
      "to this site in this tab only and ends when you close the tab.";
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

      // Ask a contact what THEY got from the same address. Only rendered in
      // a build that has a chat transport, and only when a contact exists:
      // a button whose only outcome is "add a contact first" is a button
      // that should not be there yet.
      if (downloadCompareAvailable && chatContacts.length > 0) {
        const askBtn = el("button", "small", "Ask a contact");
        askBtn.type = "button";
        askBtn.setAttribute("data-premium", "1");
        askBtn.setAttribute(
          "title",
          "Compare this download with a contact's copy",
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
          target.textContent = "Asking...";
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
    "This compares what two people were served. It cannot tell you whether either copy is safe.",
    "It trusts your contact to report honestly what they downloaded.",
    "Different versions, per-platform builds and stale mirrors all produce different files innocently.",
    "Matching hashes mean the server treated you both alike, nothing more.",
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
        el("div", "item-sub", "The two files are also different sizes."),
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

  const DOWNLOAD_COMPARE_NOTES = {
    no_download:
      "Your contact has no record of downloading from this address. That is not evidence of anything.",
    record_untrusted:
      "Your contact's own record of that download failed its integrity check, so their copy's fingerprint cannot be trusted for this comparison.",
    unsupported: "Your contact's build cannot answer this.",
    bad_message: "Your contact's answer could not be read.",
    unexpected:
      "An answer arrived for a comparison this browser did not ask for. Nothing was compared.",
  };

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
  // ONE panel for everything saved. Bookmarks, the tabs you set aside and
  // download records were three tabs in a separate Library; they are now
  // three views of this one, chosen from its sidebar. The panel keeps the
  // id and the toolbar button it always had, so nothing that points at the
  // Library has to learn a new name.
  registerPanel("library", {
    el: $("bookmarks-panel"),
    button: $("btn-library"),
    // The manager is wide and tall. 720 was the ceiling the Rust side
    // clamped to; the ceiling is 800 now (CHROME_TOP_RANGE), so this is a
    // height chosen for the panel rather than a value pressed against a
    // limit -- it stays where it is because that is what the manager needs.
    heightPx: 720,
    onOpen: refreshLibrary,
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
  let managerSelected = "all"; // "all" | "quick" | "unfiled" | a folder name
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

  function managerPinned() {
    return bookmarkItems.filter((b) => b.quick_access === true);
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
    if (managerSelected === "quick") {
      items = managerPinned();
    } else if (managerSelected === "unfiled") {
      items = managerUnfiled();
    } else if (managerSelected === "all") {
      items = bookmarkItems.slice();
    } else {
      items = folderMembers(managerSelected);
    }
    const needle = managerQuery.trim().toLowerCase();
    if (needle) {
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
      tile.title = item.url;
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
      grid.appendChild(tile);
    }
  }

  function renderManagerSidebar() {
    const nav = $("bmm-folders");
    if (!nav) return;
    nav.textContent = "";
    const entries = [
      { key: "all", label: "All bookmarks", count: bookmarkItems.length },
      { key: "quick", label: "Quick Access", count: managerPinned().length },
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
      label: "Unfiled",
      count: managerUnfiled().length,
    });
    // The other two things this panel now holds. Below the folders and
    // marked apart, because they are not bookmarks and filing a bookmark
    // into "Downloads" would make no sense: they are deliberately NOT
    // drop targets.
    entries.push({
      key: "shelves",
      label: "Sets of tabs",
      count: shelfCount(),
      separated: true,
    });
    entries.push({
      key: "downloads",
      label: "Downloads",
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
        input.setAttribute("aria-label", "Rename folder");
        form.appendChild(input);
        const save = el("button", "small", "Save");
        save.type = "submit";
        form.appendChild(save);
        const cancel = el("button", "small", "Cancel");
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
      const rename = el("button", "small", "Rename");
      rename.type = "button";
      rename.addEventListener("click", () => {
        managerRenamingFolder = managerSelected;
        renderBookmarksManager();
      });
      bar.appendChild(rename);
      const del = el("button", "small danger", "Delete folder");
      del.type = "button";
      del.title = "Removes the folder. The bookmarks in it are kept.";
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
        input.setAttribute("aria-label", "Rename folder");
        form.appendChild(input);
        const save = el("button", "small", "Save");
        save.type = "submit";
        form.appendChild(save);
        const cancel = el("button", "small", "Cancel");
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
      const rename = el("button", "small", "Rename");
      rename.type = "button";
      rename.addEventListener("click", () => {
        managerRenamingFolder = folder.tag;
        renderBookmarksManager();
      });
      actions.appendChild(rename);
      const del = el("button", "small danger", "Delete folder");
      del.type = "button";
      del.title = "Removes the folder. The bookmarks in it are kept.";
      del.addEventListener("click", () => managerDeleteFolder(folder.tag));
      actions.appendChild(del);
      card.appendChild(actions);
      wrap.appendChild(card);
    }
  }

  function managerRow(item) {
    const li = el("li", "bmm-row");
    li.setAttribute("draggable", "true");

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
    li.appendChild(meta);

    if (Array.isArray(item.tags) && item.tags.length) {
      const chips = el("div", "bmm-chips");
      for (const tag of item.tags)
        chips.appendChild(el("span", "bmm-chip", tag));
      li.appendChild(chips);
    }

    const actions = el("div", "bmm-actions");

    const foldersBtn = el("button", "small", "Folders");
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

    const pin = el("button", "small", item.quick_access ? "Unpin" : "Pin");
    pin.type = "button";
    pin.title = item.quick_access
      ? "Remove from Quick Access"
      : "Put this in Quick Access at the top";
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
    const edit = el("button", "small", "Edit");
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

    const copy = el("button", "small", "Copy URL");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(item.url);
        toast("Address copied.");
      } catch (e) {
        toast(friendly(e), true);
      }
    });
    actions.appendChild(copy);

    const open = el("button", "small", "Open");
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

    const del = el("button", "small danger", "Delete");
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
    list.textContent = "";
    const items = managerVisibleItems();
    const empty = $("bmm-empty");
    if (empty) {
      empty.hidden = items.length > 0;
      if (!items.length) {
        empty.textContent = bookmarkItems.length
          ? "Nothing here matches."
          : "No bookmarks yet. Add one above, or use the bookmark button on a page.";
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
    pick.setAttribute("aria-label", "Folder for the selected bookmarks");
    if (!folderNames.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No folders yet";
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

    mk("Add to folder", () => {
      if (!pick.value) return;
      runBatch(ids, (id) =>
        rb("bookmark_folder_file", { id, folder: pick.value }),
      );
    });
    mk("Remove from folder", () => {
      if (!pick.value) return;
      runBatch(ids, (id) =>
        rb("bookmark_folder_unfile", { id, folder: pick.value }),
      );
    });
    mk("Pin", () =>
      runBatch(ids, (id) => rb("bookmark_quick_access_set", { id, on: true })),
    );
    mk("Unpin", () =>
      runBatch(ids, (id) => rb("bookmark_quick_access_set", { id, on: false })),
    );
    mk("Delete", async () => {
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
    const clear = el("button", "small", "Clear selection");
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
      toast(
        failed.length + " of " + ids.length + " could not be changed.",
        true,
      );
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
        el("div", "bmm-pop-row", "No folders yet. Make one below."),
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
    input.placeholder = "New folder";
    input.setAttribute("aria-label", "New folder name");
    form.appendChild(input);
    const add = el("button", "small", "Add");
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
      toast("Folder made, but filing failed: " + friendly(e), true);
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
      "Delete the folder “" +
        name +
        "”? The bookmarks in it are kept, just no longer filed under it.",
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
        errline.textContent = "Type an address first.";
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
            ? "That is not an address this browser can open."
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
          : "bookmarks";
    const top = $("bmm-bookmarks-top");
    if (top) top.hidden = view !== "bookmarks";
    for (const [name, id] of [
      ["bookmarks", "bmm-view-bookmarks"],
      ["shelves", "bmm-view-shelves"],
      ["downloads", "bmm-view-downloads"],
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
    // LAST, and always: the popover is re-anchored to the rebuilt rows. Any
    // path that re-renders without this leaves it pointing at a detached node.
    syncFoldersPopover();
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
          errline.textContent = "Type a folder name first.";
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
          toast("There are no bookmarks or folders to delete.");
          return;
        }
        const what = [
          marks === 1 ? "1 bookmark" : `${marks} bookmarks`,
          folders === 1 ? "1 folder" : `${folders} folders`,
        ].join(" and ");
        const ok = await askConfirm(
          `Permanently delete ${what}? This also removes their tags, their ` +
            `Quick Access pins, and the page snapshots kept for change ` +
            `checks. It cannot be undone, and PATANYX has no bookmark ` +
            `export to restore from. Your set-aside tabs, downloads and ` +
            `archived pages are not affected.`,
          "Delete everything",
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
        toast(
          `Deleted ${n === 1 ? "1 bookmark" : n + " bookmarks"} and ` +
            `${f === 1 ? "1 folder" : f + " folders"}.`,
        );
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
