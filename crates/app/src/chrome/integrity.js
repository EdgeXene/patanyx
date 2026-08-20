/*
 * Page integrity & peer corroboration — chrome panel.
 *
 * Loaded by index.html with a script tag and served by main.rs over the
 * chrome's custom protocol, in EVERY build. (It is NOT evaluated at first ping
 * the way chat.js is -- chat.js takes that route because it must not be
 * referenced from index.html, or a non-chat build would request a file that
 * does not exist. This one ships everywhere, so a script tag is simpler.)
 * Change detection works everywhere; the corroboration section hides itself
 * unless integrity_status reports a chat build.
 *
 * Note: index.html, chrome.css and chrome.js were not in this
 * drafter's context. Consequences, all safe for the reviewer to change:
 *   1. This file builds its own DOM with createElement + textContent ONLY
 *      (so §4.2 holds by construction) and styles it through CSSOM
 *      (el.style), which the chrome CSP cannot block. Moving the static
 *      rules into chrome.css and the skeleton into index.html is a tidy
 *      follow-up, not a fix.
 *   2. The toolbar container is assumed to be #toolbar (see TOOLBAR below).
 *   3. Rust events arrive via window.__rb_event; how chrome.js/chat.js fan
 *      out is unknown from here, so this file CHAINS whatever handler
 *      exists. If chat.js REPLACES __rb_event instead of chaining, merge
 *      the two fan-outs or integrity events die silently in chat builds.
 */
(function () {
  "use strict";

  if (!window.__rb) {
    return;
  }

  var THEME = {
    panelBg: "#1a1b20",
    rowBg: "#1f2027",
    buttonBg: "#2b2c33",
    border: "#3a3b43",
    text: "#d7d7dc",
    bright: "#e9e9ee",
    dim: "#8f909a",
    accent: "#4f8cff",
    goodBorder: "#3f6b4a",
    warn: "#d8b46a",
    dangerBorder: "#6b3333",
  };

  // ---- DOM helpers (textContent only) --------------------------------------

  function el(tag, text) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) {
      node.textContent = text;
    }
    return node;
  }

  function sty(node, props) {
    for (var key in props) {
      node.style[key] = props[key];
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function box(borderColor) {
    return sty(el("div"), {
      marginTop: "10px",
      padding: "9px 10px",
      borderRadius: "4px",
      background: THEME.rowBg,
      borderLeft: "3px solid " + borderColor,
      fontSize: "12.5px",
      lineHeight: "1.5",
    });
  }

  // ---- error text -----------------------------------------------------------
  // Note: these codes should ALSO be added to ERROR_TEXT in chrome.js
  // (convention §2); they live here too so this panel is correct even before
  // that edit lands.
  var ERROR_TEXT = {
    unsupported:
      "This build cannot read the page's bytes from the engine, so this is unavailable rather than guessed.",
    no_page:
      "Could not read the page yet. It may still be loading, so try again when it finishes.",
    not_bookmarked:
      "Bookmark this page first. Snapshots are kept with the bookmark.",
    no_snapshot: "No snapshot saved for this page yet. Save one first.",
    too_long: "The page is too large to fingerprint.",
    not_unlocked: "Unlock the vault first.",
    peer_offline:
      "They are not connected right now. Open the conversation in Chat first, then try again.",
    no_session: "Open a chat session with that contact first, then try again.",
    bad_args:
      "This page cannot be compared (its address is not a public web page).",
    io: "Something went wrong; nothing was stored or sent.",
  };

  // window.__rb.request rejects with an Error whose .message is the code;
  // Rust EVENTS (page_integrity_error, corroborate_note) carry the bare
  // string. Both paths land in friendly(), so normalize first — previously
  // the IPC path stringified the Error ("Error: not_bookmarked"), missed
  // every entry above, and fell through to developer jargon, while the
  // event path produced the tailored sentence. The two paths now agree.
  function codeOf(err) {
    if (typeof err === "string") {
      return err;
    }
    if (err && typeof err.message === "string") {
      return err.message;
    }
    return String(err);
  }

  function friendly(err) {
    var code = codeOf(err);
    if (ERROR_TEXT[code]) {
      return ERROR_TEXT[code];
    }
    if (window.__rb.friendly) {
      return window.__rb.friendly(code);
    }
    return "Unexpected error: " + code;
  }

  // ---- panel skeleton -------------------------------------------------------

  var panel = sty(el("div"), {
    background: THEME.panelBg,
    color: THEME.text,
    padding: "12px 14px",
    overflowY: "auto",
    boxSizing: "border-box",
    // NO INLINE WIDTH. `panel-modal` is added by chrome.js when a panel opens
    // and sizes the card with `width: min(600px, 100vw - 32px)` -- but an
    // INLINE style beats a class rule, so `width: 100%` here quietly won and
    // this panel alone rendered as a full-width band across the window while
    // every markup-declared panel was a centred card. It looked like a layout
    // bug in the browser; it was one line of specificity.
    fontSize: "13px",
    lineHeight: "1.45",
  });
  panel.id = "integrity-panel";
  // Starts hidden: the panel manager reveals it when its toolbar button is
  // pressed. Without this it renders on launch, which both misrepresents the
  // panel as "open" and eats the chrome strip.
  panel.hidden = true;

  panel.appendChild(
    sty(el("div", "Page integrity"), {
      color: THEME.bright,
      fontSize: "14px",
      fontWeight: "600",
      marginBottom: "4px",
    }),
  );

  var statusLine = sty(el("div", ""), {
    color: THEME.dim,
    fontSize: "12px",
    marginBottom: "4px",
  });
  panel.appendChild(statusLine);

  function sectionTitle(text) {
    return sty(el("div", text), {
      color: THEME.bright,
      fontSize: "13px",
      fontWeight: "600",
      marginTop: "14px",
    });
  }

  function explainer(text) {
    return sty(el("div", text), {
      color: THEME.dim,
      fontSize: "12px",
      marginTop: "4px",
    });
  }

  function makeButton(label) {
    var b = el("button", label);
    b.type = "button";
    sty(b, {
      background: THEME.buttonBg,
      border: "1px solid " + THEME.border,
      color: THEME.text,
      borderRadius: "4px",
      padding: "5px 10px",
      cursor: "pointer",
      fontSize: "12px",
      marginRight: "8px",
      marginTop: "8px",
    });
    return b;
  }

  function setDisabled(button, off) {
    button.disabled = off;
    button.style.opacity = off ? "0.5" : "1";
  }

  // -- section 1: change detection --
  panel.appendChild(sectionTitle("Has this page changed?"));
  panel.appendChild(
    explainer(
      // "not Deep Recall" is named EXPLICITLY, and it earns its words. These
      // three tools moved into one modal on 2026-08-19, and the moment they
      // shared a card the timestamp under this section started reading as
      // Deep Recall's -- reported within the hour. The tools have separate
      // stores (this one is the bookmark store; Deep Recall has its own
      // encrypted archive) and the old layout conveyed that for free by
      // keeping them in different places. Sharing a modal spent that, so the
      // sentence has to pay it back.
      "Save a snapshot of this page as it was served to you. Later, compare: PATANYX tells you " +
        "how much of the visible text still matches. Snapshots live in your bookmark store, next " +
        "to the bookmark -- not in Deep Recall, and nowhere else. A page has to be bookmarked " +
        "before it can be snapshotted.",
    ),
  );
  var saveButton = makeButton("Save snapshot now");
  var checkButton = makeButton("Compare with saved snapshot");
  var checkRow = el("div");
  checkRow.appendChild(saveButton);
  checkRow.appendChild(checkButton);
  panel.appendChild(checkRow);
  var checkResult = el("div");
  panel.appendChild(checkResult);

  // -- section 2: peer corroboration (chat builds only) --
  var corrSection = el("div");
  corrSection.style.display = "none";
  corrSection.appendChild(
    sectionTitle("Is a contact being served the same page?"),
  );
  corrSection.appendChild(
    explainer(
      "Their browser fetches nothing -- it compares the copy it already has open with yours, and " +
        "you both see the result. Only for public pages: anything behind a login differs by design.",
    ),
  );
  var contactSelect = sty(el("select"), {
    background: THEME.buttonBg,
    color: THEME.text,
    border: "1px solid " + THEME.border,
    borderRadius: "4px",
    padding: "4px 6px",
    marginRight: "8px",
    marginTop: "8px",
    maxWidth: "220px",
    fontSize: "12px",
  });
  var askButton = makeButton("Ask to compare");
  var corrRow = el("div");
  corrRow.appendChild(contactSelect);
  corrRow.appendChild(askButton);
  corrSection.appendChild(corrRow);
  var corrStatus = sty(el("div", ""), {
    color: THEME.dim,
    fontSize: "12px",
    marginTop: "8px",
  });
  corrSection.appendChild(corrStatus);
  var corrResult = el("div");
  corrSection.appendChild(corrResult);
  panel.appendChild(corrSection);

  // -- section 3: Change Cross-Check (chat builds only) --
  //
  // Deliberately a SEPARATE section from corroboration above, not a second
  // button inside it. The two ask different questions: corroboration asks
  // whether a contact is being served the same page RIGHT NOW, this asks
  // whether a page changed for them since each of you saved it. Sharing one
  // control would blur that, and the answers would arrive looking alike.
  var xSection = el("div");
  xSection.style.display = "none";
  xSection.appendChild(sectionTitle("Did this page change for a contact too?"));
  xSection.appendChild(
    explainer(
      "Compares what each of you saved with what each of you sees. A change you both got is an " +
        "ordinary edit; a change only you got is worth a closer look, and has innocent causes too. " +
        "Needs a page you have saved a copy of.",
    ),
  );
  var xSelect = sty(el("select"), {
    background: THEME.buttonBg,
    color: THEME.text,
    border: "1px solid " + THEME.border,
    borderRadius: "4px",
    padding: "4px 6px",
    marginRight: "8px",
    marginTop: "8px",
    maxWidth: "220px",
    fontSize: "12px",
  });
  var xButton = makeButton("Ask a contact");
  var xRow = el("div");
  xRow.appendChild(xSelect);
  xRow.appendChild(xButton);
  xSection.appendChild(xRow);
  var xStatus = sty(el("div", ""), {
    color: THEME.dim,
    fontSize: "12px",
    marginTop: "8px",
  });
  xSection.appendChild(xStatus);
  var xResult = el("div");
  xSection.appendChild(xResult);
  panel.appendChild(xSection);

  // ---- state ----------------------------------------------------------------

  var supported = false;
  var chatBuild = false;
  var contacts = [];

  function setCorrStatus(text) {
    corrStatus.textContent = text;
  }

  function contactLabel(contactId) {
    for (var i = 0; i < contacts.length; i++) {
      if (contacts[i].id === contactId) {
        return contacts[i].label;
      }
    }
    return "A contact";
  }

  function option(value, label) {
    var o = el("option", label);
    o.value = value;
    return o;
  }

  function loadContacts() {
    window.__rb
      .request("chat_contacts", {})
      .then(function (data) {
        contacts = (data && data.items) || [];
        // Both pickers are filled from ONE fetch: two sections asking the
        // same question of the same list would be two chances for them to
        // disagree about who your contacts are.
        var pickers = [contactSelect, xSelect];
        for (var p = 0; p < pickers.length; p++) {
          clear(pickers[p]);
          if (contacts.length === 0) {
            pickers[p].appendChild(
              option("", "No contacts yet -- add one in Chat"),
            );
            continue;
          }
          for (var i = 0; i < contacts.length; i++) {
            pickers[p].appendChild(option(contacts[i].id, contacts[i].label));
          }
        }
      })
      .catch(function (err) {
        var pickers = [contactSelect, xSelect];
        for (var p = 0; p < pickers.length; p++) {
          clear(pickers[p]);
          pickers[p].appendChild(option("", friendly(err)));
        }
      });
  }

  function refreshCapability() {
    window.__rb
      .request("integrity_status", {})
      .then(function (s) {
        supported = !!s.supported;
        chatBuild = !!s.chat;
        if (supported) {
          statusLine.textContent =
            "Fingerprints are computed from the exact bytes the engine received -- never by " +
            "injecting script into the page.";
        } else {
          // A control the platform cannot honour is shown, disabled, and
          // explained — never silently absent, never a switch that does nothing.
          statusLine.textContent =
            "Unavailable on this platform: the engine cannot hand back the bytes it was served, " +
            "and PATANYX will not guess.";
        }
        setDisabled(saveButton, !supported);
        setDisabled(checkButton, !supported);
        setDisabled(askButton, !supported || !chatBuild);
        setDisabled(xButton, !supported || !chatBuild);
        corrSection.style.display = chatBuild ? "block" : "none";
        xSection.style.display = chatBuild ? "block" : "none";
        if (chatBuild) {
          loadContacts();
        }
      })
      .catch(function () {
        statusLine.textContent = "Capability check failed.";
      });
  }

  // ---- formatting ------------------------------------------------------------

  function fmtDate(epochSecs) {
    return new Date(epochSecs * 1000).toLocaleString();
  }

  function gapPhrase(seconds) {
    if (seconds < 2) {
      return "at almost the same moment";
    }
    if (seconds < 90) {
      return seconds + " seconds apart";
    }
    var minutes = Math.round(seconds / 60);
    if (minutes < 90) {
      return minutes + " minutes apart";
    }
    var hours = Math.round(minutes / 60);
    if (hours < 48) {
      return hours + " hours apart";
    }
    return Math.round(hours / 24) + " days apart";
  }

  // ---- change-detection rendering --------------------------------------------

  function showCheckError(err) {
    clear(checkResult);
    var wrap = box(THEME.dangerBorder);
    // `err` is the rejected Error from request(); friendly() normalizes it.
    wrap.appendChild(el("div", friendly(err)));
    checkResult.appendChild(wrap);
  }

  saveButton.addEventListener("click", function () {
    clear(checkResult);
    window.__rb.request("integrity_mark_seen", {}).catch(showCheckError);
  });

  checkButton.addEventListener("click", function () {
    clear(checkResult);
    window.__rb.request("integrity_check", {}).catch(showCheckError);
  });

  function renderMarked(data) {
    clear(checkResult);
    var wrap = box(THEME.goodBorder);
    wrap.appendChild(
      sty(el("div", "Snapshot saved."), {
        color: THEME.bright,
        fontWeight: "600",
        marginBottom: "4px",
      }),
    );
    wrap.appendChild(
      el(
        "div",
        "It sits next to the bookmark for " +
          data.url +
          " -- compare any time from this panel.",
      ),
    );
    checkResult.appendChild(wrap);
  }

  function renderCheck(data) {
    clear(checkResult);
    var head;
    var body = null;
    var color;
    if (data.verdict === "identical") {
      color = THEME.goodBorder;
      head = "Matches the snapshot.";
      body =
        "Only details that legitimately change on every load (tokens, script bodies) may differ -- " +
        "those are ignored on purpose.";
    } else if (data.verdict === "structure_differs") {
      color = THEME.accent;
      head = "Same words, different markup.";
      body =
        "The visible text is word-for-word unchanged since the snapshot; the page around it changed.";
    } else {
      color = THEME.warn;
      var pct =
        typeof data.similarity === "number"
          ? Math.round(data.similarity * 100)
          : 0;
      head =
        "The visible text has changed -- about " + pct + "% still matches.";
    }
    var wrap = box(color);
    wrap.appendChild(
      sty(el("div", head), {
        color: THEME.bright,
        fontWeight: "600",
        marginBottom: "4px",
      }),
    );
    if (body) {
      wrap.appendChild(el("div", body));
    }
    wrap.appendChild(
      sty(
        el(
          "div",
          "Snapshot saved " +
            fmtDate(data.baseline_fetched_at) +
            " · compared " +
            fmtDate(data.checked_at),
        ),
        { color: THEME.dim, marginTop: "6px", fontSize: "12px" },
      ),
    );
    // The caveat travels WITH the verdict, not on a help page.
    wrap.appendChild(
      sty(
        el(
          "div",
          "A change can be an edit, an A/B test, or a CDN variant -- this says that the page " +
            "changed, not why, and not which copy is genuine.",
        ),
        { color: THEME.dim, marginTop: "6px", fontSize: "12px" },
      ),
    );
    checkResult.appendChild(wrap);
  }

  // ---- corroboration rendering -------------------------------------------------

  askButton.addEventListener("click", function () {
    var contactId = contactSelect.value;
    if (!contactId) {
      setCorrStatus("Add a contact in Chat first.");
      return;
    }
    clear(corrResult);
    setCorrStatus("Reading this page's bytes…");
    window.__rb
      .request("corroborate_request", { contact_id: contactId })
      .catch(function (err) {
        setCorrStatus(friendly(err));
      });
  });


  function setXStatus(text) {
    xStatus.textContent = text;
  }

  xButton.addEventListener("click", function () {
    var contactId = xSelect.value;
    if (!contactId) {
      setXStatus("Add a contact in Chat first.");
      return;
    }
    clear(xResult);
    setXStatus("Reading this page's bytes...");
    window.__rb
      .request("change_compare_request", { contact_id: contactId })
      .catch(function (err) {
        setXStatus(friendly(err));
      });
  });

  // The caveats for THIS comparison, which are not the corroboration ones.
  // Corroboration is about being served differently right now; this is about
  // change over time, so its innocent explanations are different and its
  // strongest reading is weaker.
  function xCaveatList() {
    var items = [
      "A change only you saw has innocent causes: caches, regional editions, an edit between the two visits.",
      "It trusts your contact to report honestly what they saved and what they see.",
      "Two copies saved at different times routinely differ for that reason alone.",
      "Nothing here says a page was aimed at you. It says where to look.",
    ];
    var ul = sty(el("ul"), {
      margin: "4px 0 0",
      paddingLeft: "18px",
      color: THEME.dim,
      fontSize: "12px",
    });
    for (var i = 0; i < items.length; i++) {
      ul.appendChild(el("li", items[i]));
    }
    return ul;
  }

  function gapText(seconds) {
    if (seconds === null || seconds === undefined) {
      return null;
    }
    if (seconds < 3600) {
      return Math.round(seconds / 60) + " minutes apart";
    }
    if (seconds < 172800) {
      return Math.round(seconds / 3600) + " hours apart";
    }
    return Math.round(seconds / 86400) + " days apart";
  }

  function renderXVerdict(data) {
    clear(xResult);
    setXStatus("");
    // "changed for me, not for them" is the one worth colouring; everything
    // else is ordinary. The colour never carries meaning on its own -- the
    // sentence below says the same thing in words.
    var pointed = data.my_change === "text_differs" && data.their_change === "same";
    var wrap = box(pointed ? THEME.warn : THEME.goodBorder);
    // Rust's headline, verbatim. This file places wording, never composes it.
    wrap.appendChild(sty(el("div", data.text), { color: THEME.bright }));
    var gap = gapText(data.baseline_gap_seconds);
    if (gap) {
      wrap.appendChild(
        sty(el("div", "Your saved copies were made " + gap + "."), {
          color: THEME.dim,
          fontSize: "12px",
          marginTop: "6px",
        }),
      );
    }
    wrap.appendChild(xCaveatList());
    xResult.appendChild(wrap);
  }

  var X_NOTES = {
    no_baseline:
      "Your contact has nothing saved for this address, so there was nothing on their side to compare.",
    no_page: "Your contact could not read the page just now.",
    unsupported: "Your contact's build cannot answer this.",
    bad_message: "Your contact's answer could not be read.",
    unexpected:
      "An answer arrived for a comparison this browser did not ask for. Nothing was compared.",
  };

  function renderXNote(data) {
    clear(xResult);
    setXStatus(X_NOTES[data.reason] || X_NOTES.bad_message);
  }

  // The four standing caveats, rendered WITH every verdict (brief: surface
  // them there, not on a help page).
  function caveatList() {
    var items = [
      "This only tells you whether the server treated the two of you differently -- not whether what you both saw is true.",
      "It is meaningless on logged-in or personalised pages, which differ by design.",
      "It trusts your contact to report honestly what they were served.",
      "A difference has many innocent causes: A/B tests, CDNs, regionalisation, or an edit between the two fetches.",
    ];
    var ul = sty(el("ul"), {
      margin: "4px 0 0",
      paddingLeft: "18px",
      color: THEME.dim,
      fontSize: "12px",
    });
    for (var i = 0; i < items.length; i++) {
      ul.appendChild(el("li", items[i]));
    }
    return ul;
  }

  function renderVerdict(data) {
    clear(corrResult);
    var color =
      data.kind === "same_content"
        ? THEME.goodBorder
        : data.kind === "same_text"
          ? THEME.accent
          : THEME.warn;
    var wrap = box(color);
    // The sentence is the corroborate crate's own Display text, verbatim:
    // it was written to be honest about scope and safe to show unedited.
    wrap.appendChild(sty(el("div", data.text), { color: THEME.bright }));
    wrap.appendChild(
      sty(
        el(
          "div",
          "Copies read " +
            gapPhrase(data.fetch_gap_seconds) +
            " · byte-for-byte identical: " +
            (data.byte_identical ? "yes" : "no") +
            " · shown to both of you.",
        ),
        { color: THEME.dim, marginTop: "6px", fontSize: "12px" },
      ),
    );
    var caveats = sty(el("div"), { marginTop: "8px" });
    caveats.appendChild(
      sty(el("div", "Read this with the result:"), {
        color: THEME.dim,
        fontWeight: "600",
        fontSize: "12px",
      }),
    );
    caveats.appendChild(caveatList());
    wrap.appendChild(caveats);
    corrResult.appendChild(wrap);
    setCorrStatus("");
  }

  function renderNote(data) {
    var msg;
    switch (data.reason) {
      case "no_page":
        msg = data.local
          ? "The page bytes could not be read here -- it may still be loading; nothing was sent."
          : "Your contact does not have this page open, so nothing was compared.";
        break;
      case "unsupported":
        msg = data.local
          ? "This build cannot read page bytes."
          : "Your contact's build cannot read page bytes on its platform, so the comparison could not run.";
        break;
      case "url_mismatch":
        msg =
          "The two open pages did not address-match, so nothing was compared.";
        break;
      case "too_large":
      case "too_long":
        msg = "The page was too large to fingerprint.";
        break;
      case "bad_message":
        msg =
          "The comparison message could not be understood (version mismatch or corruption).";
        break;
      case "unexpected":
        msg =
          "A comparison reply arrived with nothing waiting for it -- the vault may have been locked in between.";
        break;
      default:
        msg = friendly(data.reason);
    }
    setCorrStatus(msg);
  }

  function renderRequestReceived(data) {
    // The response is automatic, so the user must be able to SEE it happen.
    setCorrStatus(
      contactLabel(data.contact_id) +
        " asked to compare “" +
        data.url +
        "”. If it is open here, the copy already loaded is used -- nothing is fetched.",
    );
  }

  function renderStatus(data) {
    if (data.state === "sent") {
      setCorrStatus(
        "Request sent -- waiting for " +
          contactLabel(data.contact_id) +
          " to compare against the copy they already have.",
      );
    }
  }

  function renderOpError(data) {
    if (data.op === "check" || data.op === "mark_seen") {
      showCheckError(data.code);
    } else {
      setCorrStatus(friendly(data.code));
    }
  }

  // ---- event wiring -------------------------------------------------------------

  function handleIntegrityEvent(msg) {
    if (!msg || typeof msg.event !== "string") {
      return false;
    }
    var data = msg.data || {};
    switch (msg.event) {
      case "page_check_result":
        renderCheck(data);
        return true;
      case "page_marked_seen":
        renderMarked(data);
        return true;
      case "page_integrity_error":
        renderOpError(data);
        return true;
      case "corroborate_request_received":
        renderRequestReceived(data);
        return true;
      case "corroborate_status":
        renderStatus(data);
        return true;
      case "corroborate_verdict":
        renderVerdict(data);
        return true;
      case "corroborate_note":
        renderNote(data);
        return true;
      case "change_compare_verdict":
        renderXVerdict(data);
        return true;
      case "change_compare_note":
        renderXNote(data);
        return true;
      case "change_compare_status":
        setXStatus("Asked. Waiting for their answer...");
        return true;
      case "change_compare_error":
        setXStatus(friendly(data.code || "io"));
        return true;
      case "change_compare_request_received":
        // The automatic answer, surfaced. Same rule the other two peer
        // features follow: a reply the user cannot see is the shape of a
        // backdoor even when it is not one.
        setXStatus(
          "A contact asked whether a page changed for you. Your saved copy was compared and the answer sent.",
        );
        return true;
      default:
        return false;
    }
  }

  // Chain, don't replace: chrome.js owns __rb_event and chat.js may wrap it
  // the same way. Unhandled events flow to the previous handler.
  var previousEventHandler = window.__rb_event;
  window.__rb_event = function (msg) {
    if (handleIntegrityEvent(msg)) {
      return;
    }
    if (typeof previousEventHandler === "function") {
      previousEventHandler(msg);
    }
  };

  // ---- registration ---------------------------------------------------------------

  // THE MARKUP-BUTTON HANDOVER, 2026-08-19. index.html now carries
  // #btn-integrity itself and chrome.js registers the combined tools modal
  // (Page integrity / Deep Recall / Image check) against it; this file's job
  // shrank to providing the integrity tab's content. When the markup button
  // and the slot exist, append the panel there, expose the refresh, and stop
  // -- building a second button or registering a second panel would give the
  // modal two competing doors. The old path below is kept whole as the
  // fallback the button-creation comment always promised: if the markup is
  // ever renamed, integrity stays REACHABLE rather than silently vanishing.
  var markupButton = document.getElementById("btn-integrity");
  var toolsSlot = document.getElementById("tools-integrity-slot");
  if (markupButton && toolsSlot && window.__rb && window.__rb.registerPanel) {
    panel.hidden = false;
    // The HOST paints the panel now -- background, padding and scrolling all
    // come from chrome.css's every-panel rule on #integrity-host. This inner
    // div keeping its own inline background and padding is what rendered as
    // a dark card floating in a pale rectangle on hardware: inline styles
    // beat the class rule, which is the exact specificity trap this file's
    // own width comment already documents. As a tab body it owns nothing but
    // its content.
    sty(panel, { background: "transparent", padding: "0", overflowY: "visible" });
    toolsSlot.appendChild(panel);
    window.__rbIntegrityRefresh = refreshCapability;
    refreshCapability();
    return;
  }

  var button = el("button");
  button.id = "btn-integrity";
  button.type = "button";
  button.setAttribute("aria-pressed", "false");
  // Styled by chrome.css like every other toolbar control, NOT inline. This
  // file was drafted without chrome.css in context (see the header note) and
  // hand-rolled a button that merely resembled the others: slightly different
  // padding, its own font size, a marginLeft on top of the toolbar's own gap,
  // and -- because inline styles win -- no way for a stylesheet rule to reach
  // it. That last part is why this button silently sat out the toolbar's
  // grey-is-off / green-is-on convention and its width breakpoints.
  button.className = "feature-btn";
  // Icon + text label (§3): an icon alone makes the user guess, and guessing
  // wrong about a privacy control is worse than a wider toolbar. Inline SVG,
  // stroked in currentColor — the CSP forbids external resources.
  var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "13");
  svg.setAttribute("height", "13");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  var shield = document.createElementNS("http://www.w3.org/2000/svg", "path");
  shield.setAttribute("d", "M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7z");
  var tick = document.createElementNS("http://www.w3.org/2000/svg", "path");
  tick.setAttribute("d", "M9 12l2 2 4-4");
  svg.appendChild(shield);
  svg.appendChild(tick);
  button.appendChild(svg);
  // Labelled, deliberately. It was icon-only on the argument
  // that the address bar needed the width more -- but a shield with a tick,
  // unlabelled, is indistinguishable from the Privacy shield two buttons away,
  // and this one does something quite different. The width comes out of the
  // address bar's floor instead; see #url in chrome.css.
  var label = document.createElement("span");
  label.className = "feature-label";
  label.textContent = "Integrity";
  button.appendChild(label);
  button.title = "Page integrity: has this page changed since you saved it?";

  // The Note that stood here guessed "#toolbar" as the strip id without
  // index.html in context, and asked a reviewer to confirm it. Confirmed, and
  // now stale twice over: the id was right, and the destination has since
  // changed. Feature controls live in the menu sheet, so this button is
  // appended there rather than to a toolbar that now holds three things.
  //
  // The fixed-position fallback is kept, and it is not defensive padding: if
  // the sheet is ever renamed this button must stay REACHABLE rather than
  // silently vanish. A privacy feature that disappears without a trace is the
  // failure mode this whole file is careful about.
  var host = document.getElementById("toolbar");
  if (host) {
    button.className = "feature-btn";
    host.appendChild(button);
  } else {
    sty(button, { position: "fixed", top: "6px", right: "6px", zIndex: "50" });
    document.body.appendChild(button);
  }
  document.body.appendChild(panel);

  window.__rb.registerPanel("integrity", {
    el: panel,
    button: button,
    heightPx: 608,
    onOpen: function () {
      refreshCapability();
    },
    onClose: function () {
      // No secrets are ever held here; nothing to clear.
    },
  });

  refreshCapability();
})();
