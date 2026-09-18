"use strict";
(() => {
  // The publisher's relay, offered as a starting point and nothing more.
  //
  // Pre-FILLED, never pre-enabled, and the distinction is the whole design. A
  // hardcoded relay that connected on its own would mean every install
  // announces itself to one relay operator the moment chat comes up -- exactly the
  // phoning-home this product refuses. Filling the box removes the barrier
  // (nobody types a WebSocket URL correctly from memory) while leaving the
  // decision where it belongs: the user still ticks the box.
  const DEFAULT_RELAY_URL = "wss://relay.edgexene.io/ws";
  // chat.js is evaluated in the chrome webview only in chat builds, after
  // chrome.js has run (index.html deliberately carries no script tag for
  // it). Guard against a double evaluation and against a DOM built without
  // the chat panel: in both cases this script must do nothing at all.
  if (window.__rb_chat) return;
  const panel = document.getElementById("chat-panel");
  if (!panel) return;

  // ---- IPC plumbing ---------------------------------------------------------
  // chrome.js exposes its request helper and error vocabulary on window.__rb
  // (it runs first -- this script is evaluated on chrome.js's own load ping).
  // Reusing them means ONE reply table and ONE id counter, so chat requests
  // cannot collide with chrome's, and one error vocabulary that cannot drift.
  // If chrome.js is somehow absent there is nothing to talk to, so bail rather
  // than half-initialise a panel whose every action would throw.
  if (!window.__rb || typeof window.__rb.request !== "function") return;
  const rb = window.__rb.request;
  // Chat is a Premium feature: every action arm can answer premium_required.
  // That code is explained with the shared lock note (locked vault / not on
  // sale yet / lapsed / upgrade), never with the tab pack's sentence that the
  // shared table maps it to.
  const friendlyChat = (e) => {
    const code = e && typeof e === "object" ? e.message : e;
    if (code === "premium_required" && typeof window.__rb.premiumLockNote === "function") {
      return window.__rb.premiumLockNote();
    }
    return window.__rb.friendly(e);
  };
  // The catalog helpers, shared through the same bridge object every
  // cross-script capability rides (__rb.request, __rb.askConfirm...).
  const { i18nText, i18nResolve, i18nSet, rebuildOnLocaleFill } =
    window.__rb || {};
  // The chrome's confirmation dialog. Guarded rather than assumed: if an
  // older chrome.js is ever loaded beside this file, removing a contact must
  // still work -- it falls back to acting without a prompt only if the shared
  // dialog is genuinely absent, and never to the engine's rbchrome-titled one.
  const askConfirmChat =
    typeof window.__rb.askConfirm === "function"
      ? window.__rb.askConfirm
      : () => Promise.resolve(true);

  // The chat row in the vault's "needs the passphrase" list ships hidden in
  // index.html, because index.html is ONE static file serving both builds and
  // a free build must not claim a feature it does not carry. This script
  // running IS the capability signal -- chat.js is evaluated only in chat
  // builds, and only after the guards above -- so no status call is needed to
  // decide it. (An IPC probe would answer the same question later, over a
  // round trip that can fail.)
  const needsChat = document.getElementById("np-chat");
  if (needsChat) needsChat.hidden = false;

  // ---- helpers ---------------------------------------------------------------
  const $ = (id) => document.getElementById(id);

  // Everything a peer sends — message text, contact labels, hash numbers,
  // URLs, and every field of a credential offer — enters the DOM through
  // this helper as textContent. Peer strings must never become markup in
  // this webview: it holds IPC and vault access, so markup injection here
  // would be a vault-reading vector. There is no exception to this.
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // The chat error codes (peer_offline, no_session, too_long, chat_down,
  // duplicate_contact) live in chrome.js's ERROR_TEXT alongside the vault
  // ones, and reach this file through window.__rb.friendly above.

  // One honest sentence per notice reason (see chat_panel.rs). refused_url
  // is the security property working, not a glitch, and says so.
  // What an out-message may say about itself. "Delivered" means it reached
  // the peer's DEVICE and their key said so; there is no read receipt and its
  // absence is deliberate, not an omission.
  // Module-level maps keyed by wire token (state, reason), so they are
  // filled inside the rebuild hook: a live locale switch re-runs this and
  // every later lookup reads the new catalog. The KEYS stay bare.
  let DELIVERY_TEXT;
  let DELIVERY_TITLE;
  let FAILURE_TEXT;
  let NOTICE_TEXT;
  rebuildOnLocaleFill(function () {
    DELIVERY_TEXT = {
      sending: i18nText("chrome-js-chat-delivery-sending", "Sending…"),
      delivered: i18nText("chrome-js-chat-delivery-delivered", "Delivered"),
    };
    DELIVERY_TITLE = {
      sending: i18nText("chrome-js-chat-delivery-title-sending", "Sent, but not confirmed."),
      delivered: i18nText("chrome-js-chat-delivery-title-delivered", "Confirmed by their device."),
    };
    // One line per cause. These used to be one line for every cause, which is
    // how "they are not on this network right now" ended up under a message to
    // someone who was demonstrably on this network.
    FAILURE_TEXT = {
      peer_offline: i18nText("chrome-js-chat-failure-peer-offline", "Not sent. They are not reachable, and nothing is waiting."),
      no_session: i18nText("chrome-js-chat-failure-no-session", "Not sent. Reopen the conversation and try again."),
      link_lost: i18nText("chrome-js-chat-failure-link-lost", "Not delivered. The connection dropped on the way."),
      refused: i18nText("chrome-js-chat-failure-refused", "Not delivered. The relay could not pass it on, and nothing is waiting."),
      no_ack: i18nText("chrome-js-chat-failure-no-ack", "Not delivered. No confirmation came back, so try again."),
      session_ended: i18nText("chrome-js-chat-failure-session-ended", "Not delivered. The session ended before it arrived."),
      too_many_outstanding: i18nText("chrome-js-chat-failure-too-many-outstanding", "Not sent. Too many messages are still unconfirmed, so wait a moment."),
    };
    NOTICE_TEXT = {
      session_failed: i18nText("chrome-js-chat-notice-session-failed", "The secure session could not be opened. Try reopening the conversation."),
      undecodable: i18nText("chrome-js-chat-notice-undecodable", "A message from this peer could not be read and was discarded."),
      dropped: i18nText("chrome-js-chat-notice-dropped", "A message from this peer failed its security checks and was dropped."),
      peer_offline: i18nText("chrome-js-chat-notice-peer-offline", "They are not on this network right now. Nothing was sent, and nothing is waiting."),
      no_session: i18nText("chrome-js-chat-notice-no-session", "There is no open session with this peer. Reopen the conversation to start one."),
      refused_url: i18nText("chrome-js-chat-notice-refused-url", "Blocked a link this browser refuses to open. The message was not lost."),
      too_long: i18nText("chrome-js-chat-notice-too-long", "A message was too long and was not delivered."),
      candidates_capped: i18nText("chrome-js-chat-notice-candidates-capped", "Some contacts may be missing because this network is announcing too many addresses. Your connection is unaffected."),
      not_announced: i18nText("chrome-js-chat-notice-not-announced", "Contacts using one of your addresses cannot find you. Your other addresses still work."),
    };
  });

  // ---- element handles ---------------------------------------------------------
  const statePanes = {
    locked: $("chat-locked"),
    intro: $("chat-intro"),
    contacts: $("chat-contacts"),
    conversation: $("chat-conversation"),
  };

  // ---- local UI state ----------------------------------------------------------
  // Everything here is memory only. Nothing is written to any storage API;
  // closing the panel wipes the conversations (see the onClose above), and the app
  // restarting wipes the rest.
  let chatOpen = false;
  let viewState = "locked"; // key into statePanes
  let contacts = []; // [{id, label, peer_hash, note}]
  const peerStates = new Map(); // peer_hash -> {online, connected, verified, away}
  let discoveryState = "starting";
  let transportDown = false;
  let selectedId = null; // contact id whose hash number is on screen
  let current = null; // {contact_id, peer_hash, label} of the open chat
  const conversations = new Map(); // peer_hash -> [message descriptors]

  // Messages that arrived for a conversation the user was not looking at.
  //
  // WHY THIS EXISTS. An incoming message raised a toast and nothing else, and
  // a toast removes itself after six seconds. Step away from the desk and the
  // only evidence a contact wrote to you was gone -- no count, no dot, nothing
  // anywhere in the UI. The message itself was still in memory and perfectly
  // readable; there was simply no way to find out it had come.
  //
  // In memory only, like the conversations it counts. It is emptied in
  // `wipeConversations`, so it cannot outlive the messages it refers to.
  const unread = new Map(); // peer_hash -> count

  function unreadTotal() {
    let total = 0;
    for (const n of unread.values()) total += n;
    return total;
  }

  /// Paint the count on the chat pill.
  ///
  /// One place now: the pill sits in the toolbar's second row and is always
  /// visible, so there is no menu button that needs to relay the number on its
  /// behalf. That relay existed only because the entry was hidden inside a
  /// sheet, which is the arrangement this layout replaced.
  // Async for the aria-label's count arg; the badge itself is numbers only
  // and stays sync. Strictly-newest: paints race their resolve.
  let unreadGen = 0;
  async function paintUnread() {
    const gen = ++unreadGen;
    const total = unreadTotal();
    const label = total > 99 ? "99+" : String(total);
    for (const id of ["chat-unread"]) {
      const badge = document.getElementById(id);
      if (!badge) continue;
      badge.hidden = total === 0;
      badge.textContent = label;
    }
    const button = document.getElementById("btn-chat");
    if (button) {
      const aria = await i18nResolve(
        "chrome-js-chat-unread-aria",
        { count: total },
        total === 0
          ? "Local-network chat"
          : "Local-network chat, " +
              total +
              (total === 1 ? " unread message" : " unread messages"),
      );
      if (gen !== unreadGen) return;
      button.setAttribute("aria-label", aria);
    }
  }

  /// Everything from this peer has now been seen.
  function markRead(peerHash) {
    if (unread.delete(String(peerHash))) paintUnread();
  }
  // mid -> descriptor, for out-messages only. Without this a delivery event
  // has nothing to revise: the descriptors used to be positional and
  // anonymous, so a bubble once drawn could never be corrected.
  const outbox = new Map();
  // Enough for any conversation someone is actually watching, and a bound
  // rather than a hope. Maps iterate in insertion order, so the oldest goes.
  const OUTBOX_LIMIT = 500;

  // The conversation view was the tallest panel; the theme panel passed it
  // when the toolbar section gained a placement row. The Rust clamp is the
  // tallest panel PLUS banner allowance (CHROME_TOP_RANGE in
  // platform/mod.rs, now 80..=800 for a 760 theme panel): a ceiling sitting
  // exactly at the tallest panel is what once discarded banner heights over
  // an open chat in full, so if this number grows past 720, that range is
  // where the arithmetic lives.
  const CHAT_OPEN_PX = 640;

  // ---- panel registration ------------------------------------------------------
  // index.html ships this button hidden so a non-chat build shows no dead
  // control; reaching this line means chat is compiled in and wired up.
  const chatButton = $("btn-chat");
  if (!chatButton || typeof window.__rb.registerPanel !== "function") return;
  chatButton.hidden = false;

  // Joins chrome.js's one-panel-at-a-time rotation rather than running an
  // independent toggle, so opening chat closes the vault (and vice versa) and
  // exactly one toolbar button ever reads as pressed.
  window.__rb.registerPanel("chat", {
    el: panel,
    button: chatButton,
    heightPx: CHAT_OPEN_PX,
    onOpen: () => {
      chatOpen = true;
      refreshAll();
    },
    onClose: () => {
      chatOpen = false;
      // The conversation is gone when the panel closes — by design, not by
      // accident. The next open starts from the vault's contact list again.
      wipeConversations();
    },
  });

  // Dot titles, keyed by the presence token. Rebuilt on locale fill like
  // the vocabularies above.
  let PRESENCE_TEXT;
  rebuildOnLocaleFill(function () {
    PRESENCE_TEXT = {
      online: i18nText("chrome-js-chat-presence-title-online", "Online: they have said they are reachable"),
      offline: i18nText("chrome-js-chat-presence-title-offline", "Offline: nothing can be sent to them right now"),
      away: i18nText("chrome-js-chat-presence-title-away", "Away: reachable, but they have flagged themselves as not at the keyboard"),
    };
  });

  // ---- own presence + relay surface --------------------------------------------
  // Note: index.html was not in this drafter's context, so the presence
  // bar and the relay surface are built at runtime — the same pattern
  // update.js and integrity.js use for the same reason. Moving the markup
  // into index.html next to the other chat panes is a tidy follow-up; keep
  // the element references below if you do. chrome.css rules for the
  // chat-presence / chat-relay classes ship with the integration patch.
  //
  // Presence is MANUAL (presence-spec.md): default invisible, the user goes
  // online explicitly, status is never inferred. This bar exists to answer
  // one question at a glance: "am I discoverable right now?"

  let ownOnline = false;
  let ownAway = false;
  let relayInfo = null; // last chat_relay_get / chat_relay_state payload
  let relayOpen = false;
  let relayDirty = false; // user is mid-edit; live events must not clobber inputs

  // Rebuilt on locale fill. The ERROR clauses are only ever appended to a
  // state line, so each carries its own leading space ({" "} in the
  // catalog) and the join in renderRelayState is a plain append -- the
  // chrome-engine-blocklist / recall-shortfall shape.
  let RELAY_STATE_TEXT;
  let RELAY_ERROR_TEXT;
  rebuildOnLocaleFill(function () {
    RELAY_STATE_TEXT = {
      not_compiled: i18nText("chrome-js-chat-relay-state-not-compiled", "Private Chat works only on local networks in this build."),
      off: i18nText("chrome-js-chat-relay-state-off", "Off. You are not registered with any relay."),
      not_configured: i18nText("chrome-js-chat-relay-state-not-configured", "Enabled but incomplete. Set a server address and choose which of your addresses to register."),
      connecting: i18nText("chrome-js-chat-relay-state-connecting", "Connecting to the relay\u2026"),
      up: i18nText("chrome-js-chat-relay-state-up", "Connected. Your chosen address is registered with the relay."),
      down: i18nText("chrome-js-chat-relay-state-down", "Connection to the relay lost. Retrying."),
    };
    RELAY_ERROR_TEXT = {
      already_registered: i18nText("chrome-js-chat-relay-error-already-registered", " The relay says this address is already registered from another connection: a second device, or a stale registration that has not expired yet."),
      unavailable: i18nText("chrome-js-chat-relay-error-unavailable", " The relay is refusing registrations right now."),
      version_mismatch: i18nText("chrome-js-chat-relay-error-version-mismatch", " This relay is incompatible with this PATANYX version."),
      // Premium licence refusals (P3, design 4.4). DRAFT copy pending
      // review; no purchase links anywhere -- nothing is for sale
      // until the payment flow ships. There is no fallback license: a lapsed
      // subscription has no Premium features until renewal.
      token_required: i18nText("chrome-js-chat-relay-error-token-required", " Private Chat requires PATANYX Premium."),
      token_expired: i18nText("chrome-js-chat-relay-error-token-expired", " Chat disconnected: your subscription has ended."),
      token_invalid: i18nText("chrome-js-chat-relay-error-token-invalid", " Chat could not verify your subscription. Try again, or contact support if it keeps happening."),
      key_rejected: i18nText("chrome-js-chat-relay-error-key-rejected", " Chat could not verify your subscription. Try again, or contact support if it keeps happening."),
      error: i18nText("chrome-js-chat-relay-error-error", " The relay reported an error."),
    };
  });

  function buildPresenceUI() {
    const root = el("div", "chat-presence");

    const row = el("div", "chat-presence-row");
    const dot = el("span", "presence presence-offline");
    const text = el("span", "chat-presence-text");
    const buttons = el("span", "chat-presence-buttons");

    const goOnline = el("button", "small", i18nText("chrome-js-chat-go-online", "Go online"));
    goOnline.type = "button";
    const goOffline = el("button", "small", i18nText("chrome-js-chat-go-offline", "Go offline"));
    goOffline.type = "button";
    const away = el("button", "small", i18nText("chrome-js-chat-away-flag", "Flag as away"));
    away.type = "button";
    const relayToggle = el("button", "small", i18nText("chrome-js-chat-relay-toggle", "Relay settings"));
    relayToggle.type = "button";
    relayToggle.setAttribute("aria-expanded", "false");

    buttons.appendChild(goOnline);
    buttons.appendChild(goOffline);
    buttons.appendChild(away);
    buttons.appendChild(relayToggle);
    row.appendChild(dot);
    row.appendChild(text);
    row.appendChild(buttons);
    root.appendChild(row);

    const err = el("div", "error");
    root.appendChild(err);

    // ---- relay section ----
    const relay = el("div", "chat-relay");
    relay.hidden = true;
    const relayTitle = el(
      "div",
      "chat-relay-title",
      "Reachable beyond this network (optional)",
    );
    relay.appendChild(relayTitle);
    const relayNote = el(
      "div",
      "chat-relay-note",
      i18nText("chrome-js-chat-relay-note", "A relay keeps one chosen address reachable outside your local network. Whoever runs it sees that address and when it is online, not your contacts or messages. Off by default; nothing connects until configured."),
    );
    relay.appendChild(relayNote);
    // The field is PRE-FILLED, not pre-enabled, and the distinction is the
    // whole design. A hardcoded relay that connects on its own would mean every
    // install announces itself to one relay operator the moment chat comes up --
    // exactly the phoning-home this product refuses. Filling the box removes
    // the barrier (nobody types a WebSocket URL correctly from memory) while
    // leaving the decision where it belongs: the user still ticks the box.
    const relayPublisherNote = el(
      "div",
      "chat-relay-note",
      i18nText("chrome-js-chat-relay-publisher-note", "The prefilled relay is run by this browser's publisher. You can replace it with any relay you trust, or one you run yourself. Both people need the same relay. It sees when you are online and connected, not messages."),
    );
    relay.appendChild(relayPublisherNote);
    const rState = el("div", "chat-relay-state");
    relay.appendChild(rState);

    const rEnableLabel = el("label", "chat-relay-enable");
    const rEnable = document.createElement("input");
    rEnable.type = "checkbox";
    rEnableLabel.appendChild(rEnable);
    // The label text leads with a space ({" "} in the catalog) so the
    // checkbox keeps its gap after a fill.
    const rEnableText = document.createTextNode(" Use a relay server");
    rEnableLabel.appendChild(rEnableText);
    relay.appendChild(rEnableLabel);

    const rUrlLabel = el("div", "chat-relay-label", i18nText("chrome-js-chat-relay-url-label", "Server address"));
    relay.appendChild(rUrlLabel);
    const rUrl = document.createElement("input");
    rUrl.type = "text";
    rUrl.className = "chat-relay-url";
    rUrl.placeholder = "wss://relay.example/ws";
    rUrl.value = DEFAULT_RELAY_URL;
    rUrl.autocomplete = "off";
    rUrl.spellcheck = false;
    relay.appendChild(rUrl);

    const rIdLabel = el("div", "chat-relay-label", i18nText("chrome-js-chat-relay-identity-label", "Your address to register"));
    relay.appendChild(rIdLabel);
    const rId = document.createElement("select");
    rId.className = "chat-relay-identity";
    relay.appendChild(rId);

    const rSave = el("button", "small", i18nText("chrome-js-chat-relay-save", "Save relay settings"));
    rSave.type = "button";
    const rSaveRow = el("div", "chat-relay-save");
    rSaveRow.appendChild(rSave);
    relay.appendChild(rSaveRow);
    const rSaveNote = el(
      "div",
      "chat-relay-note",
      i18nText("chrome-js-chat-relay-save-note", "Saving while online reconnects Private Chat briefly."),
    );
    relay.appendChild(rSaveNote);
    const rErr = el("div", "error");
    relay.appendChild(rErr);
    root.appendChild(relay);

    goOnline.addEventListener("click", () => {
      err.textContent = "";
      rb("chat_go_online", {})
        .then((data) => applyStatus(data))
        .catch((e) => {
          err.textContent = friendlyChat(e);
        });
    });
    goOffline.addEventListener("click", () => {
      err.textContent = "";
      rb("chat_go_offline", {})
        .then((data) => applyStatus(data))
        .catch((e) => {
          err.textContent = friendlyChat(e);
        });
    });
    away.addEventListener("click", () => {
      err.textContent = "";
      rb("chat_set_away", { away: !ownAway })
        .then((data) => applyStatus(data))
        .catch((e) => {
          err.textContent = friendlyChat(e);
        });
    });
    relayToggle.addEventListener("click", () => {
      relayOpen = !relayOpen;
      relay.hidden = !relayOpen;
      relayToggle.setAttribute("aria-expanded", relayOpen ? "true" : "false");
      if (relayOpen) loadRelay();
    });

    const markDirty = () => {
      relayDirty = true;
    };
    rUrl.addEventListener("input", markDirty);
    rId.addEventListener("input", markDirty);
    rEnable.addEventListener("change", markDirty);

    rSave.addEventListener("click", () => {
      rErr.textContent = "";
      if (rEnable.checked && (!rUrl.value.trim() || !rId.value)) {
        // The Rust side refuses the same shape with bad_args; saying which
        // half is missing here is kinder than the generic code.
        rErr.textContent = i18nText("chrome-js-chat-relay-needs-both",
          "Enabling needs both a server address and one of your addresses to register.",
        );
        return;
      }
      rSave.disabled = true;
      rb("chat_relay_set", {
        enabled: rEnable.checked,
        url: rUrl.value.trim(),
        identity_hash: rId.value || null,
      })
        .then((data) => {
          rSave.disabled = false;
          relayDirty = false;
          applyRelay(data);
          toast(i18nText("chrome-js-chat-relay-saved", "Relay settings saved."));
        })
        .catch((e) => {
          rSave.disabled = false;
          rErr.textContent =
            e && e.message === "relay_unavailable"
              ? RELAY_STATE_TEXT.not_compiled
              : friendlyChat(e);
        });
    });

    // Build-once labels, re-labelled on every locale fill. The away button
    // is NOT here: its label toggles with state, so renderPresence owns it
    // (and renderPresence is itself re-run on fill, registered below where
    // presenceUI exists). The fallbacks are the joined single-line strings:
    // the source-width concatenations were never runtime composition.
    rebuildOnLocaleFill(function () {
      goOnline.textContent = i18nText("chrome-js-chat-go-online", "Go online");
      goOffline.textContent = i18nText("chrome-js-chat-go-offline", "Go offline");
      relayToggle.textContent = i18nText("chrome-js-chat-relay-toggle", "Relay settings");
      relayTitle.textContent = i18nText("chrome-js-chat-relay-title", "Reachable beyond this network (optional)");
      relayNote.textContent = i18nText("chrome-js-chat-relay-note", "A relay keeps one chosen address reachable outside your local network. Whoever runs it sees that address and when it is online, not your contacts or messages. Off by default; nothing connects until configured.");
      relayPublisherNote.textContent = i18nText("chrome-js-chat-relay-publisher-note", "The prefilled relay is run by this browser's publisher. You can replace it with any relay you trust, or one you run yourself. Both people need the same relay. It sees when you are online and connected, not messages.");
      rEnableText.textContent = i18nText("chrome-js-chat-relay-enable", " Use a relay server");
      rUrlLabel.textContent = i18nText("chrome-js-chat-relay-url-label", "Server address");
      rUrl.placeholder = i18nText("chrome-js-chat-relay-url-placeholder", "wss://relay.example/ws");
      rIdLabel.textContent = i18nText("chrome-js-chat-relay-identity-label", "Your address to register");
      rSave.textContent = i18nText("chrome-js-chat-relay-save", "Save relay settings");
      rSaveNote.textContent = i18nText("chrome-js-chat-relay-save-note", "Saving while online reconnects Private Chat briefly.");
    });

    return {
      root,
      dot,
      text,
      err,
      goOnline,
      goOffline,
      away,
      relay,
      rState,
      rEnable,
      rUrl,
      rId,
      rSave,
    };
  }

  const presenceUI = buildPresenceUI();
  panel.insertBefore(presenceUI.root, panel.firstChild);
  renderPresence();
  renderRelayState();
  // The presence line and the toggling away button follow a live locale
  // switch too. Registered HERE, not inside buildPresenceUI: the hook runs
  // its callback at registration, and presenceUI does not exist yet inside
  // the builder. Both renders are idempotent.
  rebuildOnLocaleFill(function () {
    renderPresence();
    renderRelayState();
  });

  function setRelayFormDisabled(off) {
    presenceUI.rEnable.disabled = off;
    presenceUI.rUrl.disabled = off;
    presenceUI.rId.disabled = off;
    presenceUI.rSave.disabled = off;
  }

  // The user's own status, stated plainly: offline / online / away. The
  // toolbar button reports state like every other feature button (§3):
  // online means this control is DOING something — announcing — so it
  // carries .is-active even while the panel is closed.
  function renderPresence() {
    const ui = presenceUI;
    let state;
    let text;
    if (!ownOnline) {
      state = "offline";
      text = i18nText("chrome-js-chat-presence-line-offline",
        "Offline. Nobody can find or message you.",
      );
    } else if (ownAway) {
      state = "away";
      text = i18nText("chrome-js-chat-presence-line-away",
        "Away, but reachable; messages still arrive.",
      );
    } else {
      state = "online";
      text = i18nText("chrome-js-chat-presence-line-online",
        "Online and reachable on this network.",
      );
    }
    ui.dot.className = "presence presence-" + state;
    ui.dot.title = PRESENCE_TEXT[state];
    ui.text.textContent = text;
    ui.goOnline.hidden = ownOnline;
    ui.goOffline.hidden = !ownOnline;
    ui.away.hidden = !ownOnline;
    ui.away.textContent = ownAway
      ? i18nText("chrome-js-chat-away-im-back", "I'm back")
      : i18nText("chrome-js-chat-away-flag", "Flag as away");
    ui.root.hidden = viewState === "locked";
    chatButton.classList.toggle("is-active", ownOnline);

    // The menu entry's dot. It shipped in index.html hidden, and NOTHING in
    // any script ever touched it -- `#vault-dot` beside it has a driver and
    // this one never did, so it was a permanently invisible indicator.
    //
    // It reports AWAY, not online. Online is already carried by `is-active`
    // turning the row green, and a green dot next to a green row says the same
    // thing twice; away is the state that colour cannot express, and `.dot.warn`
    // is the amber this chrome already uses for it. So: no dot offline, no dot
    // when plainly online, amber dot when online and flagged away.
    var dot = document.getElementById("chat-dot");
    if (dot) {
      dot.hidden = !(ownOnline && ownAway);
      dot.className = "dot warn";
      dot.title = i18nText("chrome-js-chat-dot-away-title", "You are flagged as away");
    }
  }

  function renderRelayState() {
    if (!relayInfo) {
      presenceUI.rState.textContent = i18nText("chrome-js-chat-relay-reading",
        "Reading relay settings…",
      );
      setRelayFormDisabled(true);
      return;
    }
    const compiled = relayInfo.compiled !== false;
    const state = relayInfo.state || (compiled ? "off" : "not_compiled");
    let line = RELAY_STATE_TEXT[state] || RELAY_STATE_TEXT.off;
    if (relayInfo.error && RELAY_ERROR_TEXT[relayInfo.error]) {
      // The error clause carries its own leading space ({" "} in the
      // catalog); the join is a plain append.
      line += RELAY_ERROR_TEXT[relayInfo.error];
    }
    presenceUI.rState.textContent = line;
    // A control the build cannot honour is shown, disabled, and explained —
    // never silently absent, never a switch that does nothing.
    setRelayFormDisabled(!compiled);
  }

  function applyStatus(data) {
    if (!data) return;
    if (typeof data.online === "boolean") ownOnline = data.online;
    if (typeof data.away === "boolean") ownAway = data.away;
    if (data.discovery) discoveryState = data.discovery;
    if (data.relay) applyRelay(data.relay);
    renderPresence();
    renderDiscovery();
  }

  function applyRelay(data) {
    if (!data) return;
    relayInfo = Object.assign({}, relayInfo, data);
    // Populate the form only from a FULL settings load (chat_relay_get and
    // the chat_relay_set reply carry identity_choices; live state events do
    // not) and never while the user is mid-edit — a relay event must not
    // clobber a half-typed server address.
    if (!relayDirty && Array.isArray(data.identity_choices)) {
      presenceUI.rEnable.checked = !!data.enabled;
      // An unset relay shows the default rather than an empty box: a user who
      // has never configured one should see what they would get, not a blank
      // they have to research. A user who DID configure one sees theirs.
      presenceUI.rUrl.value = data.url || DEFAULT_RELAY_URL;
      const sel = presenceUI.rId;
      sel.textContent = "";
      if (data.identity_choices.length === 0) {
        const o = document.createElement("option");
        o.value = "";
        o.textContent = i18nText("chrome-js-chat-relay-no-identities",
          "No addresses yet. Create one or add a contact first",
        );
        sel.appendChild(o);
      } else {
        for (const choice of data.identity_choices) {
          const o = document.createElement("option");
          o.value = String(choice.hash || "");
          o.textContent = String(choice.label || choice.hash || "");
          sel.appendChild(o);
        }
        if (data.identity_hash) sel.value = data.identity_hash;
      }
    }
    renderRelayState();
  }

  function loadRelay() {
    rb("chat_relay_get", {})
      .then((data) => applyRelay(data))
      .catch(() => {
        // Locked or otherwise unavailable: the state line keeps its last
        // rendering rather than guessing.
      });
  }

  /// Inline note editing. Deliberately in the list rather than a separate
  /// panel: the note only means anything next to the contact it describes.
  function startNoteEdit(contact, wrap) {
    wrap.textContent = "";
    const input = document.createElement("textarea");
    input.className = "note-input";
    input.rows = 2;
    input.maxLength = 2000;
    input.value = contact.note || "";
    input.placeholder = i18nText("chrome-js-chat-note-placeholder",
      "Anything you do not want to forget about this contact",
    );
    wrap.appendChild(input);

    const row = el("div", "form-buttons");
    const save = el("button", "small", i18nText("chrome-js-chat-note-save", "Save"));
    save.type = "button";
    const cancel = el("button", "small", i18nText("chrome-js-chat-note-cancel", "Cancel"));
    cancel.type = "button";
    const err = el("div", "error");

    save.addEventListener("click", () => {
      save.disabled = true;
      rb("chat_contact_note", { contact_id: contact.id, note: input.value })
        .then(() => {
          contact.note = input.value.trim();
          renderContacts();
        })
        .catch((e) => {
          save.disabled = false;
          err.textContent = friendlyChat(e);
        });
    });
    cancel.addEventListener("click", renderContacts);
    row.appendChild(save);
    row.appendChild(cancel);
    wrap.appendChild(row);
    wrap.appendChild(err);
    input.focus();
  }

  function wipeConversations() {
    conversations.clear();
    // CLEARED HERE, INSIDE the wipe, and that placement is the design.
    //
    // The count is a view of the conversation store, so it must die at exactly
    // the moment the store does -- panel close and vault lock, the only two
    // callers of this function. Nothing is written to disk and nothing
    // survives; a badge still reading "3" after the messages were destroyed
    // would be pointing at something the user cannot open and cannot recover,
    // which is a worse lie than showing nothing.
    //
    // Putting it anywhere else would mean two things that must agree being
    // updated in two places, and one of them eventually being forgotten.
    unread.clear();
    paintUnread();
    outbox.clear();
    current = null;
    $("chat-input").value = "";
    $("chat-send-error").textContent = "";
    $("chat-cred-picker").hidden = true;
    $("chat-messages").textContent = "";
  }

  function showState(name) {
    viewState = name;
    for (const key of Object.keys(statePanes)) {
      statePanes[key].hidden = key !== name;
    }
    renderPremiumNote(name);
    // The presence bar follows the pane: hidden while locked, visible for
    // intro/contacts/conversation, since "am I discoverable" matters most
    // exactly when the panel is showing people.
    renderPresence();
  }

  // DELEGATES. This used to be a second implementation: a plain `.toast` with
  // no dismiss button, removed after 6000ms. It inherited the centred bold
  // styling automatically and so LOOKED like every other notification while
  // behaving like the old ones -- no X, and gone in six seconds instead of
  // fifteen. chrome.js owns the one implementation and publishes it.
  // The standing Premium sentence at the top of the panel: shown whenever
  // Premium is off and the vault is not the thing in the way (the locked pane
  // already tells the user what to do). Reads chrome.js's state through the
  // shared bridge, so the wording is the toolbar pill's, verbatim.
  function renderPremiumNote(name) {
    const note = $("chat-premium-note");
    if (!note) return;
    const bridge = window.__rb;
    const active =
      typeof bridge.premiumActive === "function" ? bridge.premiumActive() : true;
    if (active || name === "locked") {
      note.hidden = true;
      note.textContent = "";
      return;
    }
    note.textContent =
      typeof bridge.premiumLockNote === "function"
        ? bridge.premiumLockNote()
        : "A Premium feature.";
    note.hidden = false;
  }

  function toast(text, isError) {
    if (typeof window.__rb_toast === "function") {
      window.__rb_toast(text, isError);
      return;
    }
    // NO FALLBACK. An earlier version appended a notice here with no dismiss
    // button and no timer, which a review pointed out is worse than showing
    // nothing: those accumulate for the life of the document and cannot be
    // cleared. chrome.js publishes the hook at load and is always loaded
    // before this file in a chat build, so reaching this line at all means the
    // chrome is broken in a way one dropped notice does not describe.
  }

  // ---- refresh -----------------------------------------------------------------
  async function refreshAll() {
    // Presence first: chat_status answers even while locked, so the bar can
    // render the truth before the contact list is reachable.
    try {
      const status = await rb("chat_status");
      if (status && status.locked) {
        ownOnline = false;
        ownAway = false;
        showState("locked");
        renderPresence();
        return;
      }
      applyStatus(status);
    } catch (e) {
      /* best-effort; the contacts call below is the locked gate of record */
    }
    try {
      const data = await rb("chat_contacts");
      contacts = (data && data.items) || [];
      transportDown = false;
    } catch (e) {
      if (e && e.message === "not_unlocked") {
        // Chat needs the vault because contact keys live in it; say so
        // plainly instead of failing mysteriously.
        showState("locked");
        return;
      }
      // Any OTHER failure used to fall through with contacts = [], which
      // landed on the intro pane -- telling a user with an established
      // identity to create one because a storage read blipped. Say what
      // happened instead of inventing a first-run state.
      contacts = [];
      showState("intro");
      $("chat-intro-error").textContent = friendlyChat(e);
      return;
    }
    loadRelay();
    try {
      const peers = await rb("chat_peers");
      applyPeers(peers);
    } catch (e) {
      /* discovery status stays as it was */
    }
    // Which pane to show is decided by whether an IDENTITY exists, never by
    // the contact count. Keying it on `contacts.length === 0` meant anyone
    // who had not yet added a contact was told to "Create my hash number" on
    // every unlock, forever, no matter how long they had had one.
    //
    // `chat_identity` is a pure read now, so asking is free -- it used to
    // mint on call, which is why the old code could not ask at all.
    let myHash = null;
    try {
      const id = await rb("chat_identity");
      myHash = (id && id.hash) || null;
    } catch (e) {
      /* leave null; the intro pane is the safe answer for an unknown state */
    }
    showMyHash(myHash);
    if (myHash === null) {
      showState("intro");
    } else {
      showState("contacts");
      renderContacts();
    }
  }

  // Reveals the user's own hash number once one exists.
  //
  // The markup ships both nodes hidden and, before this existed, the ONLY
  // thing that ever unhid them was the mint button's click handler. So an
  // existing identity stayed invisible until the user clicked a button
  // telling them to create the thing they already had.
  function showMyHash(hash) {
    const node = $("chat-myhash");
    const note = $("chat-myhash-note");
    if (!node || !note) return;
    node.textContent = hash || "";
    node.hidden = hash === null;
    note.hidden = hash === null;
  }

  async function refreshContacts() {
    try {
      const data = await rb("chat_contacts");
      contacts = (data && data.items) || [];
    } catch (e) {
      /* keep the last good list */
    }
    renderContacts();
  }

  function applyPeers(data) {
    if (!data) return;
    discoveryState = data.discovery || discoveryState;
    peerStates.clear();
    for (const p of data.peers || []) {
      // chat_peers lists only currently visible peers, so presence == online.
      peerStates.set(String(p.hash), {
        online: true,
        connected: !!p.connected,
        verified: false,
        away: !!p.away,
      });
    }
    renderDiscovery();
  }

  // ---- contact list --------------------------------------------------------------
  /// Presence for the contact list, in three fixed colours:
  /// green online, red offline, orange away.
  ///
  /// "connected" (a live session) collapses into online -- it is a fact about
  /// the session, not about the person, and the light answers "can I reach
  /// them". Offline needs no announcement: a contact who has not gone online
  /// simply is not announcing, and absence IS offline.
  ///
  /// `away` arrives as a Status envelope inside the encrypted chat session
  /// (ChatPayload::Status in chat_panel.rs) — deliberately NOT in the mDNS
  /// TXT record, which is public to the whole LAN. It is pushed on session
  /// start and broadcast on toggle, and only the peer themselves ever sets
  /// it; nothing here is inferred.
  function presenceOf(peerHash) {
    const st = peerStates.get(peerHash);
    if (st && st.away) return "away";
    if (st && (st.connected || st.online)) return "online";
    return "offline";
  }

  function stateOf(peerHash) {
    const st = peerStates.get(peerHash);
    if (st && st.away) return "away";
    if (st && st.connected) return "connected";
    if (st && st.online) return "online";
    return "offline";
  }

  // Async now: the fallback carries the truncated hash as a catalog arg.
  // The hash itself is peer data -- displayed, never translated.
  async function labelFor(contactId, peerHash) {
    const found = contacts.find((c) => c.id === contactId);
    if (found) return found.label;
    const hash = String(peerHash || "");
    if (!hash) return i18nText("chrome-js-chat-unknown-peer", "Unknown peer");
    const short = hash.slice(0, 12);
    return i18nResolve(
      "chrome-js-chat-peer-fallback",
      { hash: short },
      "Peer " + short + "…",
    );
  }

  function renderContacts() {
    const list = $("chat-contact-list");
    list.textContent = "";
    for (const contact of contacts) {
      const li = el(
        "li",
        "item" + (selectedId === contact.id ? " selected" : ""),
      );
      const head = el("div", "item-head");
      // The hash number carries the presence colour, because the hash IS the
      // address: green online, red offline, orange away. Absence of an
      // announcement is offline, which is why offline needs no broadcast.
      const state = presenceOf(contact.peer_hash);
      const dot = el("span", "presence presence-" + state);
      dot.title = PRESENCE_TEXT[state] || state;
      head.appendChild(dot);
      head.appendChild(el("span", "item-title", contact.label));
      head.appendChild(el("span", "item-sub chat-st-" + state, state));
      li.appendChild(head);

      // The user's own note about this person. A hash number is unmemorable
      // by design; this is where "the one from the conference" lives. The
      // note arrives from the vault (encrypted at rest); while the vault is
      // locked this whole pane is replaced by the locked state, so an empty
      // note here always means "no note yet", never "cannot be read".
      const noteWrap = el("div", "item-note");
      const noteText = el("div", "note-text", contact.note || "");
      if (!contact.note) {
        noteText.classList.add("note-empty");
        noteText.textContent = i18nText("chrome-js-chat-contact-note-empty",
          "Add a note about this contact",
        );
      }
      noteText.title = i18nText("chrome-js-chat-contact-note-title", "Click to edit");
      noteText.addEventListener("click", () =>
        startNoteEdit(contact, noteWrap),
      );
      noteWrap.appendChild(noteText);
      li.appendChild(noteWrap);

      const row = el("div", "item-row");

      const chatBtn = el("button", "small", i18nText("chrome-js-chat-contact-chat", "Chat"));
      chatBtn.type = "button";
      chatBtn.addEventListener("click", () => openConversation(contact));
      row.appendChild(chatBtn);

      const numBtn = el("button", "small", i18nText("chrome-js-chat-contact-number", "My number"));
      numBtn.type = "button";
      numBtn.addEventListener("click", () => selectContact(contact));
      row.appendChild(numBtn);

      const delBtn = el("button", "small danger", i18nText("chrome-js-chat-remove", "Remove"));
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        // The chrome's own dialog, shared through window.__rb: the engine's
        // window.confirm titles itself with the page that raised it, so this
        // question used to arrive headed "JavaScript - rbchrome://...".
        if (
          !(await askConfirmChat(
            await i18nResolve(
              "chrome-js-chat-remove-confirm",
              { label: contact.label },
              "Remove contact " + contact.label + "?",
            ),
            i18nText("chrome-js-chat-remove", "Remove"),
          ))
        ) {
          return;
        }
        rb("chat_contact_remove", { contact_id: contact.id })
          .then(() => {
            if (selectedId === contact.id) {
              selectedId = null;
              $("chat-ourhash-wrap").hidden = true;
            }
            return refreshContacts();
          })
          .catch((e) => {
            $("chat-add-error").textContent = friendlyChat(e);
          });
      });
      row.appendChild(delBtn);

      li.appendChild(row);
      list.appendChild(li);
    }
    renderDiscovery();
  }

  // Show OUR hash number for one contact — the address that one person dials
  // to reach us. It is meant to be read aloud or copied, so it is rendered
  // in the same select-all monospace treatment as the recovery key.
  function selectContact(contact) {
    selectedId = contact.id;
    renderContacts();
    $("chat-ourhash-wrap").hidden = true;
    rb("chat_identity", { contact_id: contact.id })
      .then(async (data) => {
        if (selectedId !== contact.id) return;
        $("chat-ourhash-label").textContent = await i18nResolve(
          "chrome-js-chat-ourhash-label",
          { label: contact.label },
          "Give this hash number to " + contact.label + ":",
        );
        $("chat-ourhash").textContent = (data && data.hash) || "";
        $("chat-ourhash-wrap").hidden = false;
      })
      .catch(() => {});
  }

  function renderDiscovery() {
    const node = $("chat-discovery");
    let text;
    if (transportDown) {
      text = i18nText("chrome-js-chat-discovery-transport-down", "Chat is unavailable right now.");
    } else if (discoveryState === "unavailable") {
      text = i18nText("chrome-js-chat-discovery-unavailable", "Local discovery is unavailable. This network may block it.");
    } else if (discoveryState === "starting") {
      // Rust emits exactly "active", "quiet" and "unavailable" (DiscoveryState
      // in crates/chat/src/discovery.rs). "starting" is this panel's own
      // placeholder from before the transport has reported anything.
      text = i18nText("chrome-js-chat-discovery-starting", "Looking for devices on this network…");
    } else if (discoveryState === "quiet") {
      // Discovery is running but has never seen anyone. mDNS cannot tell that
      // apart from "this network ate the multicast", so say both rather than
      // showing a bare empty list that reads as "nobody is there".
      text = i18nText("chrome-js-chat-discovery-empty", "No peers found. This network may block local discovery.");
    } else {
      let anyOnline = false;
      for (const st of peerStates.values()) {
        if (st.online) anyOnline = true;
      }
      // An empty list with no explanation would look like "nobody is
      // there", which is a lie the user would act on: mDNS is routinely
      // blocked on public and guest WiFi.
      text = anyOnline
        ? i18nText("chrome-js-chat-discovery-on", "Local discovery is on.")
        : i18nText("chrome-js-chat-discovery-empty", "No peers found. This network may block local discovery.");
    }
    node.textContent = text;
  }

  // ---- intro (mint identity) ------------------------------------------------------
  // The ONE place that may mint. `chat_identity` is a pure read and will
  // never create a key, so the explicit create command is what this button
  // has to call. It is idempotent server-side: clicking it with an identity
  // already in the vault returns that one rather than replacing it, which
  // would orphan every contact who knows the old hash number.
  $("chat-mint").addEventListener("click", async () => {
    const err = $("chat-intro-error");
    err.textContent = "";
    try {
      const data = await rb("chat_identity_create");
      showMyHash((data && data.hash) || null);
    } catch (e) {
      err.textContent = friendlyChat(e);
    }
  });
  $("chat-intro-add").addEventListener("click", () => {
    showState("contacts");
    renderContacts();
  });

  // ---- add contact ------------------------------------------------------------------
  $("chat-add-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("chat-add-error");
    err.textContent = "";
    const label = $("chat-add-label").value.trim();
    const peerHash = $("chat-add-hash").value.trim();
    if (!label || !peerHash) {
      err.textContent = i18nText("chrome-js-chat-add-required",
        "Both a name and their hash number are required.",
      );
      return;
    }
    try {
      const added = await rb("chat_contact_add", {
        label,
        peer_hash: peerHash,
      });
      $("chat-add-label").value = "";
      $("chat-add-hash").value = "";
      // The reply carries our fresh per-contact number — the address the new
      // contact must dial to reach us. Showing it immediately is the whole
      // point of adding someone.
      $("chat-added-label").textContent = await i18nResolve(
        "chrome-js-chat-added-label",
        { label: label },
        "Added " + label + ". Give them this hash number:",
      );
      $("chat-added-hash").textContent = (added && added.hash) || "";
      $("chat-added-wrap").hidden = false;
      await refreshContacts();
    } catch (e) {
      err.textContent = friendlyChat(e);
    }
  });

  // ---- conversation --------------------------------------------------------------------
  $("chat-back").addEventListener("click", () => {
    current = null;
    showState("contacts");
    renderContacts();
  });

  // Ending a session destroys its keys (chat_close); reopening starts a
  // fresh one. Offered explicitly next to Back — until now nothing in the
  // UI ever sent chat_close, so sessions outlived their conversations with
  // no way to end them.
  (() => {
    const backBtn = $("chat-back");
    if (!backBtn || !backBtn.parentNode) return;
    const endBtn = el("button", "small", i18nText("chrome-js-chat-end-session", "End session"));
    endBtn.type = "button";
    endBtn.title = i18nText("chrome-js-chat-end-session-title",
      "Clear this conversation and start a Fresh Session",
    );
    // Built once; label and tooltip follow a live locale switch.
    rebuildOnLocaleFill(function () {
      endBtn.textContent = i18nText("chrome-js-chat-end-session", "End session");
      endBtn.title = i18nText("chrome-js-chat-end-session-title", "Clear this conversation and start a Fresh Session");
    });
    backBtn.parentNode.insertBefore(endBtn, backBtn.nextSibling);
    endBtn.addEventListener("click", () => {
      if (!current) return;
      const args = current.contact_id
        ? { contact_id: current.contact_id }
        : { peer_hash: current.peer_hash };
      rb("chat_close", args)
        .catch(() => {})
        .then(() => {
          current = null;
          showState("contacts");
          renderContacts();
        });
    });
  })();

  async function openConversation(contact) {
    current = {
      contact_id: contact.id,
      peer_hash: contact.peer_hash,
      label: contact.label,
    };
    showState("conversation");
    // Opening the conversation IS reading it -- the messages are on screen the
    // moment this returns, so the count for this peer has served its purpose.
    markRead(contact.peer_hash);
    $("chat-peer-name").textContent = contact.label;
    $("chat-cred-picker").hidden = true;
    $("chat-send-error").textContent = "";
    updatePeerStateLine();
    renderMessages();
    $("chat-input").focus();
    try {
      // Session establishment is asynchronous: the outcome arrives as
      // chat_peer_state (connected) or chat_notice (session_failed). The
      // contact_id form is required so we present THIS contact's key, not
      // the throwaway one.
      await rb("chat_open", { contact_id: contact.id });
    } catch (e) {
      addSys(
        current.peer_hash,
        await i18nResolve(
          "chrome-js-chat-open-session-failed",
          { detail: friendlyChat(e) },
          "Could not open a session: " + friendlyChat(e),
        ),
      );
    }
  }

  function updatePeerStateLine() {
    const node = $("chat-peer-state");
    const state = current ? stateOf(current.peer_hash) : "offline";
    node.textContent = state;
    node.className = "chat-st-" + state;
  }

  // ---- emoji ---------------------------------------------------------------
  //
  // Nothing about the message path needed changing: `validate_outgoing` caps
  // BYTES and `decode_incoming` is strict UTF-8 that refuses invalid input
  // rather than substituting, so emoji already travelled and rendered. What
  // was missing was any way to enter one without a system picker.
  //
  // No image sprite and no webfont, because the CSP forbids fetching either --
  // and neither is needed. An emoji is text; the platform's own emoji face
  // draws it, which is also why these look native rather than like one
  // vendor's artwork pasted into someone else's desktop.
  //
  // Grouped, because a flat grid of a hundred glyphs is a wall. Labels are
  // plain words: this is the panel that explains "hash number" in a sentence,
  // so it is not going to say "Smileys & Emotion".
  const EMOJI_GROUPS = [
    {
      label: { id: "chrome-js-chat-emoji-faces", text: "Faces" },
      items: [
        "😀",
        "😄",
        "😁",
        "😅",
        "😂",
        "🙂",
        "🙃",
        "😉",
        "😊",
        "😍",
        "😘",
        "😜",
        "🤔",
        "🤨",
        "😐",
        "😶",
        "😴",
        "😢",
        "😭",
        "😤",
        "😡",
        "🥳",
        "😎",
        "🤯",
        "😬",
        "🙄",
        "😷",
        "🤒",
        "🤝",
        "🫡",
      ],
    },
    {
      label: { id: "chrome-js-chat-emoji-hands", text: "Hands" },
      items: ["👍", "👎", "👌", "✌️", "🤞", "👋", "🙏", "💪", "👏", "🤙"],
    },
    {
      label: { id: "chrome-js-chat-emoji-hearts-marks", text: "Hearts and marks" },
      items: [
        "❤️",
        "🧡",
        "💛",
        "💚",
        "💙",
        "💜",
        "🖤",
        "✨",
        "🔥",
        "⭐",
        "✅",
        "❌",
        "⚠️",
        "❓",
        "❗",
        "💯",
      ],
    },
    {
      label: { id: "chrome-js-chat-emoji-things", text: "Things" },
      items: [
        "🎉",
        "🎂",
        "☕",
        "🍕",
        "🚀",
        "💡",
        "📎",
        "🔒",
        "🔑",
        "📅",
        "⏰",
        "📷",
        "🎧",
        "💻",
        "📁",
        "🗑️",
      ],
    },
  ];

  const emojiPanel = $("chat-emoji-panel");
  const emojiToggle = $("chat-emoji-toggle");
  let emojiBuilt = false;
  // The label nodes are kept so a live locale switch can re-label them --
  // the one-shot emojiBuilt guard below forbids rebuilding the grid itself.
  const emojiLabelEls = [];
  rebuildOnLocaleFill(function () {
    for (const entry of emojiLabelEls) {
      entry.node.textContent = i18nText(entry.id, entry.text);
    }
  });

  /// Put an emoji where the caret is, not at the end.
  ///
  /// Appending would be simpler and wrong: somebody who goes back to add a
  /// face mid-sentence would find it at the end of the line instead. The caret
  /// is then placed AFTER what was inserted so a second pick reads left to
  /// right, and focus returns to the field so typing continues normally.
  function insertEmoji(glyph) {
    const input = $("chat-input");
    const start = input.selectionStart;
    const end = input.selectionEnd;
    if (typeof start === "number" && typeof end === "number") {
      const before = input.value.slice(0, start);
      const after = input.value.slice(end);
      input.value = before + glyph + after;
      const caret = start + glyph.length;
      input.setSelectionRange(caret, caret);
    } else {
      input.value += glyph;
    }
    input.focus();
  }

  function buildEmojiPanel() {
    if (emojiBuilt) return;
    emojiBuilt = true;
    for (const group of EMOJI_GROUPS) {
      const labelNode = el(
        "div",
        "chat-emoji-label",
        i18nText(group.label.id, group.label.text),
      );
      emojiLabelEls.push({
        node: labelNode,
        id: group.label.id,
        text: group.label.text,
      });
      emojiPanel.appendChild(labelNode);
      const grid = el("div", "chat-emoji-grid");
      for (const glyph of group.items) {
        const button = el("button", "chat-emoji", glyph);
        button.type = "button";
        // The glyph is the whole label, so a screen reader would read the
        // codepoint name and nothing else. That is actually the right answer
        // here -- "grinning face" is what the button inserts -- so no
        // aria-label is invented on top of it.
        button.addEventListener("click", () => {
          insertEmoji(glyph);
          setEmojiOpen(false);
        });
        grid.appendChild(button);
      }
      emojiPanel.appendChild(grid);
    }
  }

  function setEmojiOpen(open) {
    if (open) buildEmojiPanel();
    emojiPanel.hidden = !open;
    emojiToggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  emojiToggle.addEventListener("click", () => {
    setEmojiOpen(emojiPanel.hidden);
  });

  // CAPTURE phase, and that is the point. chrome.js listens for Escape on
  // `document` to close the whole panel; without capturing first, one Escape
  // with the picker open would shut the conversation as well. Innermost
  // surface closes first, and only that one.
  document.addEventListener(
    "keydown",
    (ev) => {
      if (ev.key !== "Escape" || emojiPanel.hidden) return;
      setEmojiOpen(false);
      $("chat-input").focus();
      ev.stopPropagation();
    },
    true,
  );

  document.addEventListener("mousedown", (ev) => {
    if (emojiPanel.hidden) return;
    if (!ev.target.closest("#chat-emoji-panel, #chat-emoji-toggle")) {
      setEmojiOpen(false);
    }
  });

  $("chat-send-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!current) return;
    const err = $("chat-send-error");
    err.textContent = "";
    const input = $("chat-input");
    const text = input.value;
    if (!text.trim()) return;
    // The reply is NOT the verdict. It means the message was accepted and
    // identified, nothing more: this used to resolve off a cached "connected"
    // flag that link death never cleared, so the UI drew a delivered-looking
    // bubble for a message that had already vanished with its link.
    //
    // The bubble starts at Sending and is revised only by a chat_delivery
    // event -- and only an authenticated acknowledgement from the peer's own
    // key can make that event say Delivered.
    rb("chat_send", { peer_hash: current.peer_hash, text })
      .then((data) => {
        addText(current.peer_hash, "out", text, data && data.mid);
        input.value = "";
        input.focus();
      })
      .catch((e) => {
        err.textContent = friendlyChat(e);
      });
  });

  $("chat-send-tab").addEventListener("click", () => {
    if (!current) return;
    const err = $("chat-send-error");
    err.textContent = "";
    rb("chat_send_tab", { peer_hash: current.peer_hash })
      .then(() =>
        addSys(
          current.peer_hash,
          i18nText("chrome-js-chat-sent-tab", "You sent this tab's address."),
        ),
      )
      .catch((e) => {
        // bad_args here means the current tab's address is not one we would
        // open ourselves, so it cannot be shared either. The COMPARISON
        // stays bare; only the display side is catalogued.
        err.textContent =
          e && e.message === "bad_args"
            ? i18nText("chrome-js-chat-tab-not-shareable", "This tab cannot be shared.")
            : friendlyChat(e);
      });
  });

  $("chat-share-cred").addEventListener("click", () => {
    if (!current) return;
    const picker = $("chat-cred-picker");
    if (!picker.hidden) {
      picker.hidden = true;
      return;
    }
    const err = $("chat-send-error");
    err.textContent = "";
    rb("cred_list")
      .then((data) => {
        const items = (data && data.items) || [];
        const select = $("chat-cred-select");
        select.textContent = "";
        if (items.length === 0) {
          err.textContent = i18nText("chrome-js-chat-no-credentials",
            "There are no credentials in the vault to share.",
          );
          return;
        }
        for (const item of items) {
          const opt = document.createElement("option");
          opt.value = item.id;
          opt.textContent = item.site + ": " + item.username;
          select.appendChild(opt);
        }
        picker.hidden = false;
      })
      .catch((e) => {
        err.textContent = friendlyChat(e);
      });
  });
  $("chat-cred-cancel").addEventListener("click", () => {
    $("chat-cred-picker").hidden = true;
  });
  $("chat-cred-send").addEventListener("click", () => {
    if (!current) return;
    const select = $("chat-cred-select");
    const credId = select.value;
    if (!credId) return;
    const err = $("chat-send-error");
    err.textContent = "";
    const chosen = select.options[select.selectedIndex];
    const what = chosen
      ? chosen.textContent
      : i18nText("chrome-js-chat-login-fallback", "login");
    rb("chat_share_credential", {
      contact_id: current.contact_id,
      cred_id: credId,
    })
      .then(async () => {
        $("chat-cred-picker").hidden = true;
        addSys(
          current.peer_hash,
          await i18nResolve(
            "chrome-js-chat-shared-login",
            { what: what },
            "You shared the login for " + what + ".",
          ),
        );
      })
      .catch((e) => {
        err.textContent = friendlyChat(e);
      });
  });

  // ---- message list ------------------------------------------------------------------
  function bufFor(peerHash) {
    let buf = conversations.get(peerHash);
    if (!buf) {
      buf = [];
      conversations.set(peerHash, buf);
    }
    return buf;
  }

  function viewing(peerHash) {
    return (
      chatOpen &&
      viewState === "conversation" &&
      current &&
      current.peer_hash === peerHash
    );
  }

  function pushDesc(peerHash, desc) {
    bufFor(peerHash).push(desc);
    if (viewing(peerHash)) {
      $("chat-messages").appendChild(renderDesc(desc));
      scrollMessages();
    }
  }

  function addText(peerHash, dir, text, mid) {
    const desc = {
      kind: "text",
      dir,
      text,
      mid: mid || null,
      state: null,
      reason: null,
      node: null,
    };
    // Only out-messages have a delivery state: nothing we could say about an
    // INCOMING message would be honest — we cannot know what the sender knows.
    if (dir === "out") {
      desc.state = "sending";
      if (desc.mid) {
        outbox.set(desc.mid, desc);
        // Bounded. This index exists only so a delivery event can find its
        // bubble, and an event for a message this old is not coming; without
        // a limit it grew for the life of the panel.
        while (outbox.size > OUTBOX_LIMIT) {
          outbox.delete(outbox.keys().next().value);
        }
      }
    }
    pushDesc(peerHash, desc);
  }

  function addSys(peerHash, text) {
    pushDesc(peerHash, { kind: "sys", text });
  }

  function scrollMessages() {
    const box = $("chat-messages");
    box.scrollTop = box.scrollHeight;
  }

  function renderMessages() {
    const box = $("chat-messages");
    box.textContent = "";
    if (!current) return;
    for (const desc of bufFor(current.peer_hash)) {
      box.appendChild(renderDesc(desc));
    }
    scrollMessages();
  }

  function renderDesc(desc) {
    if (desc.kind === "sys") {
      return el("div", "msg sys", desc.text);
    }
    if (desc.kind === "tab") {
      return buildTabOffer(desc);
    }
    if (desc.kind === "cred") {
      return buildCredOffer(desc);
    }
    const node = el("div", "msg" + (desc.dir === "out" ? " out" : ""));
    node.appendChild(el("div", "msg-text", desc.text));
    if (desc.dir === "out" && desc.state) {
      node.dataset.state = desc.state;
      node.appendChild(el("div", "msg-state", deliveryLine(desc)));
      node.setAttribute("title", DELIVERY_TITLE[desc.state] || "");
    }
    // Re-render replaces nodes, so the handle must be refreshed here or a
    // later revision writes into an element no longer on the page.
    desc.node = node;
    return node;
  }

  function deliveryLine(desc) {
    if (desc.state === "failed") {
      return (
        FAILURE_TEXT[desc.reason] ||
        i18nText("chrome-js-chat-delivery-unknown-failure",
          "Not delivered. The reason was not recognized.",
        )
      );
    }
    return DELIVERY_TEXT[desc.state] || "";
  }

  // A message's state may only move forward once, and never backward out of
  // a terminal state: an acknowledgement is proof, and a refusal arriving
  // after one is answering a retry of something already delivered.
  function onDelivery(data) {
    if (!data || !data.mid) return;
    const desc = outbox.get(data.mid);
    if (!desc) return;
    if (desc.state === "delivered" || desc.state === "failed") return;
    desc.state = data.state;
    desc.reason = data.reason || null;
    if (desc.node) {
      desc.node.dataset.state = desc.state;
      desc.node.setAttribute("title", DELIVERY_TITLE[desc.state] || "");
      const line = desc.node.querySelector
        ? desc.node.children[desc.node.children.length - 1]
        : null;
      if (line) line.textContent = deliveryLine(desc);
    }
  }

  function settle(actions, text, isError) {
    actions.textContent = "";
    actions.appendChild(el("span", isError ? "error" : "chat-note", text));
  }

  // A received URL is untrusted navigation input. It is shown as plain text
  // — never as a link — so reading it can neither inject markup nor navigate
  // anything. The only path to opening it is the explicit button, and Rust
  // validates the URL again on accept. Consent opens a background tab, so a
  // peer can never take the foreground.
  function buildTabOffer(desc) {
    const node = el("div", "msg offer");
    // desc.title was composed at event time (it carries the peer's label);
    // this builder only places wording, like the Rust-headline renders.
    node.appendChild(el("div", "offer-title", desc.title));
    node.appendChild(el("div", "chat-url", desc.url));
    node.appendChild(
      el(
        "div",
        "chat-note",
        i18nText("chrome-js-chat-tab-offer-note", "Opens in a background tab only if you choose."),
      ),
    );
    const actions = el("div", "form-buttons");
    const open = el("button", "small", i18nText("chrome-js-chat-tab-open", "Open in background tab"));
    open.type = "button";
    const dismiss = el("button", "small", i18nText("chrome-js-chat-tab-dismiss", "Dismiss"));
    dismiss.type = "button";
    open.addEventListener("click", () => {
      open.disabled = true;
      rb("chat_accept_tab", { url: desc.url })
        .then(() => settle(actions, i18nText("chrome-js-chat-tab-opened", "Opened in a background tab.")))
        .catch((e) => settle(actions, friendlyChat(e), true));
    });
    dismiss.addEventListener("click", () =>
      settle(actions, i18nText("chrome-js-chat-tab-dismissed", "Dismissed.")),
    );
    actions.appendChild(open);
    actions.appendChild(dismiss);
    node.appendChild(actions);
    return node;
  }

  // A received credential is NOT in the vault: the sender's message alone
  // never writes anything. Only the explicit "Save to vault" click calls the
  // existing cred_add path. The password is held in this closure and reaches
  // the DOM only if the user asks to see it.
  function buildCredOffer(desc) {
    const offer = desc.offer;
    const node = el("div", "msg offer");
    // desc.title was composed at event time (it carries the peer's label).
    node.appendChild(el("div", "offer-title", desc.title));
    node.appendChild(offerRow(i18nText("chrome-js-chat-offer-site", "Site"), offer.site));
    node.appendChild(offerRow(i18nText("chrome-js-chat-offer-username", "Username"), offer.username));
    if (offer.note) node.appendChild(offerRow(i18nText("chrome-js-chat-offer-note", "Note"), offer.note));

    const pwRow = el("div", "offer-row");
    pwRow.appendChild(el("span", "offer-key", i18nText("chrome-js-chat-offer-password", "Password")));
    const pwVal = el("span", null, "••••••••");
    pwRow.appendChild(pwVal);
    const revealBtn = el("button", "small", i18nText("chrome-js-chat-offer-reveal", "Reveal"));
    revealBtn.type = "button";
    let shown = false;
    revealBtn.addEventListener("click", () => {
      shown = !shown;
      pwVal.textContent = shown ? offer.password || "" : "••••••••";
      revealBtn.textContent = shown
        ? i18nText("chrome-js-chat-offer-hide", "Hide")
        : i18nText("chrome-js-chat-offer-reveal", "Reveal");
    });
    pwRow.appendChild(revealBtn);
    node.appendChild(pwRow);

    const actions = el("div", "form-buttons");
    const save = el("button", "small", i18nText("chrome-js-chat-offer-save", "Save to vault"));
    save.type = "button";
    const decline = el("button", "small", i18nText("chrome-js-chat-offer-decline", "Decline"));
    decline.type = "button";
    save.addEventListener("click", () => {
      save.disabled = true;
      rb("cred_add", {
        site: offer.site,
        username: offer.username,
        password: offer.password,
        note: offer.note,
      })
        .then(() => settle(actions, i18nText("chrome-js-chat-offer-saved", "Saved to your vault.")))
        .catch((e) => settle(actions, friendlyChat(e), true));
    });
    decline.addEventListener("click", () =>
      settle(actions, i18nText("chrome-js-chat-offer-declined", "Declined.")),
    );
    actions.appendChild(save);
    actions.appendChild(decline);
    node.appendChild(actions);
    return node;
  }

  function offerRow(key, value) {
    const row = el("div", "offer-row");
    row.appendChild(el("span", "offer-key", key));
    row.appendChild(el("span", null, value));
    return row;
  }

  // ---- event handlers (routed by chrome.js from window.__rb_event) ----------------
  function onPeerState(data) {
    if (!data) return;
    const hash = String(data.peer_hash || "");
    if (!hash) return;
    peerStates.set(hash, {
      online: !!data.online,
      connected: !!data.connected,
      verified: !!data.verified,
      away: !!data.away,
    });
    if (viewState === "contacts") renderContacts();
    if (current && current.peer_hash === hash) updatePeerStateLine();
    renderDiscovery();
  }

  async function onChatMessage(data) {
    if (!data) return;
    const hash = String(data.peer_hash || "");
    if (!hash) return;
    const text = String(data.text == null ? "" : data.text);
    addText(hash, "in", text);
    if (!viewing(hash)) {
      // The toast stays: it is the thing that catches your eye in the moment.
      // The count is what is still there a minute later, when the toast has
      // removed itself and you have looked back at the screen.
      unread.set(hash, (unread.get(hash) || 0) + 1);
      paintUnread();
      const label = await labelFor(data.contact_id, hash);
      toast(
        await i18nResolve(
          "chrome-js-chat-toast-message",
          { label: label },
          "Message from " + label,
        ),
      );
    }
  }

  async function onChatNotice(data) {
    if (!data) return;
    const hash = String(data.peer_hash || "");
    // The reason is a wire token: it selects the message, and only the
    // unrecognized fallback DISPLAYS it (as an arg, never translated).
    const text =
      NOTICE_TEXT[data.reason] ||
      (await i18nResolve(
        "chrome-js-chat-notice-unknown",
        { reason: String(data.reason) },
        "Unrecognized chat notice: " + String(data.reason),
      ));
    if (hash) addSys(hash, text);
    if (!hash || !viewing(hash)) toast(text, true);
  }

  function onDiscovery(data) {
    discoveryState = (data && data.state) || discoveryState;
    renderDiscovery();
  }

  // Async now: the offer title and the toast are composed here, at event
  // time, because renderDesc is synchronous and re-renders in loops. The
  // descriptor stores display strings, not the label.
  async function onTabReceived(data) {
    if (!data) return;
    const hash = String(data.peer_hash || "");
    const url = String(data.url || "");
    if (!hash || !url) return;
    const label = await labelFor(data.contact_id, hash);
    const title = await i18nResolve(
      "chrome-js-chat-tab-offer-title",
      { label: label },
      label + " sent a link",
    );
    pushDesc(hash, { kind: "tab", url, title });
    if (!viewing(hash)) {
      toast(
        await i18nResolve(
          "chrome-js-chat-toast-link",
          { label: label },
          "Link received from " + label,
        ),
      );
    }
  }

  async function onCredOffered(data) {
    if (!data) return;
    const hash = String(data.peer_hash || "");
    if (!hash) return;
    const label = await labelFor(data.contact_id, hash);
    const title = await i18nResolve(
      "chrome-js-chat-cred-offer-title",
      { label: label },
      label + " shared a login",
    );
    pushDesc(hash, {
      kind: "cred",
      title,
      offer: {
        site: String(data.site || ""),
        username: String(data.username || ""),
        password: String(data.password || ""),
        note: String(data.note || ""),
      },
    });
    if (!viewing(hash)) {
      toast(
        await i18nResolve(
          "chrome-js-chat-toast-login",
          { label: label },
          "Login shared by " + label,
        ),
      );
    }
  }

  function onChatState(data) {
    if (data && data.locked) {
      // The vault locked: contact keys are gone, so everything chat holds in
      // memory goes with them.
      contacts = [];
      peerStates.clear();
      ownOnline = false;
      ownAway = false;
      wipeConversations();
      if (chatOpen) showState("locked");
      renderPresence();
    } else if (chatOpen) {
      refreshAll();
    }
  }

  function onChatDown() {
    transportDown = true;
    peerStates.clear();
    if (current) {
      addSys(
        current.peer_hash,
        i18nText("chrome-js-chat-down-line",
          "Chat has stopped. Messages cannot be sent or received.",
        ),
      );
    }
    if (viewState === "contacts") renderContacts();
    renderDiscovery();
    toast(i18nText("chrome-js-chat-down-toast", "Chat has stopped"), true);
  }

  // Our own presence (online/offline/away) and the relay's live state. Both
  // are idempotent renders, so it does not matter which delivery path fires.
  function onPresence(data) {
    if (!data) return;
    ownOnline = !!data.online;
    ownAway = !!data.away;
    renderPresence();
  }

  function onRelayState(data) {
    applyRelay(data);
  }

  // chrome.js routes every chat_* event it KNOWS to the handler registered
  // here under the same name; anything else is dropped there by design.
  // chat_presence and chat_relay_state predate that switch, so they are
  // additionally caught by the __rb_event chain below — the two handlers
  // are idempotent renders, so whichever path delivers an event wins.
  window.__rb_chat = {
    chat_peer_state: onPeerState,
    chat_message: onChatMessage,
    chat_delivery: onDelivery,
    chat_notice: onChatNotice,
    chat_discovery: onDiscovery,
    chat_tab_received: onTabReceived,
    chat_credential_offered: onCredOffered,
    chat_state: onChatState,
    chat_down: onChatDown,
    chat_presence: onPresence,
    chat_relay_state: onRelayState,
  };

  // Chain, don't replace -- the same pattern integrity.js uses, and for the
  // same reason: chrome.js's __rb_event switch drops event names it does not
  // know, and today it does not know chat_presence / chat_relay_state, so
  // without this every presence and relay transition would be discarded.
  // Everything else flows on to the previous handler (chrome.js's router).
  // The standing Premium note follows the LICENCE, not only the pane: when
  // chrome.js finishes a premium_status refresh (paste, activate, remove,
  // unlock) the note re-renders for whichever pane is showing.
  if (window.__rb && typeof window.__rb.onPremiumChange === "function") {
    window.__rb.onPremiumChange(() => {
      if (viewState) renderPremiumNote(viewState);
    });
  }
  const previousEventHandler = window.__rb_event;
  window.__rb_event = function (msg) {
    if (msg && msg.event === "chat_presence") {
      onPresence(msg.data);
      return;
    }
    if (msg && msg.event === "chat_relay_state") {
      onRelayState(msg.data);
      return;
    }
    if (typeof previousEventHandler === "function") {
      previousEventHandler(msg);
    }
  };

  // Preload the contact list so incoming-message toasts can use labels even
  // before the panel is first opened. Fails quietly while the vault is
  // locked; the real load happens on panel open.
  rb("chat_contacts")
    .then((data) => {
      contacts = (data && data.items) || [];
    })
    .catch(() => {});
})();
