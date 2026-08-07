/*
 * update.js — the Updates panel.
 *
 * Injected into the chrome webview at first ping (see dispatch in ipc.rs),
 * the same mechanism chat.js uses. Present in EVERY build: when this binary
 * was compiled without the updater-net feature, the panel still opens, the
 * Check button is disabled, and the reason is on the screen — shown,
 * disabled, explained.
 *
 * Note (reviewer): the panel and its toolbar button are built here at
 * runtime so this draft does not have to edit index.html blind (I could not
 * see it). One integration guess remains to check:
 *   1. buildDom() appends the button to the element with id "toolbar"
 *      (falling back to document.body) — adjust that one lookup to the real
 *      toolbar container.
 * RESOLVED since this draft first shipped: the panel manager toggles the
 * [hidden] attribute only (integrity.js had it right), so the panel is
 * hidden with panel.hidden = true and carries NO inline display style. An
 * inline display:none beats the UA [hidden] rule unconditionally — which is
 * exactly why this panel previously grew the chrome strip by 300px of empty
 * band and showed nothing.
 *
 * Everything the updater says arrives as strings from Rust; all of it
 * enters the DOM through textContent. No exceptions.
 */
(function () {
  "use strict";

  var POLL_MS = 1000;
  var pollTimer = null;

  var panel = null;
  var els = {};

  // WHAT THIS PARAGRAPH IS FOR, and why it grew a second half.
  //
  // It is the disclosure of the one thing this feature costs: contact with a
  // server. It has to be true about ALL of that contact, not the flattering
  // part. The first half was written when a check happened only on a button
  // press, and it was accurate then. Scheduled checking landed afterwards
  // (see schedule.rs) and the paragraph did not move, so it went on
  // describing a browser that reached the network only when asked -- while
  // the running one sent that IP address and timestamp roughly four times a
  // day for updates and twenty-four for the blocklist, unprompted. A privacy
  // note that understates contact by an order of magnitude is worse than no
  // note: the reader has been given a number and has no reason to doubt it.
  //
  // "Fetched and installed only when you ask" was never the false part and
  // stays -- download and install still require an explicit accept. What was
  // missing is that CHECKS do not.
  //
  // Keep both halves true or delete them. The frequencies here are the
  // constants in schedule.rs; if those change, this changes with them.
  var NOTE_SCHEDULED =
    "A check is one plain request to the update server: no account, no ID, " +
    "no version number -- the address names only the platform this build " +
    "targets. The server still sees an IP address and a time; that is " +
    "unavoidable, and it is all it sees.\n\n" +
    "PATANYX also checks on its own, on a deliberately irregular schedule: " +
    "roughly every six hours for updates, about once an hour for the " +
    "malicious-site list, the first shortly after launch. Each one is the " +
    "same identifier-free request, so the server sees an IP address and a time on " +
    "that schedule too, not only when you press the button. When a check " +
    "finds a signed update and the background switch above is on, the " +
    "download and its verification happen then too, on the same terms. " +
    "With a tunnel imported, all of this goes through the tunnel or fails; " +
    "it never falls back to a direct connection. Nothing is ever INSTALLED " +
    "without your explicit accept.";

  // A build compiled without `updater-net` has no HTTP stack at all: the
  // scheduled tasks still come due, but the fetch behind both of them is a
  // stub that returns an error without touching the network (updater.rs).
  // So the paragraph above would be false here -- it promises contact that
  // never happens, which is the same defect in the opposite direction.
  var NOTE_NO_NETWORK =
    "This build has no update networking compiled into it, so it contacts " +
    "no server at all -- not on a schedule, and not when you press the " +
    "button.";

  // Two fixed manifest URLs, not a per-install one -- see UpdateChannel's own
  // doc in prefs.rs. Switching takes effect on the NEXT check; nothing here
  // restarts anything.
  var CHANNEL_NOTE_STABLE = "Fetches the regular release manifest.";
  var CHANNEL_NOTE_BETA =
    "Fetches a second, separate manifest carrying the next release before " +
    "it reaches Stable. Every Beta subscriber requests the same address " +
    "as every other one -- nothing here is specific to this install.";

  function make(tag, text) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function setStyles(node, styles) {
    for (var name in styles) node.style[name] = styles[name];
  }

  function svgEl(tag, attrs) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (var name in attrs) node.setAttribute(name, attrs[name]);
    return node;
  }

  function makeButton(bodyText) {
    var b = make("button", bodyText);
    b.type = "button";
    setStyles(b, {
      background: "#2b2c33",
      color: "#d7d7dc",
      border: "1px solid #3a3b43",
      borderRadius: "4px",
      padding: "4px 10px",
      cursor: "pointer",
    });
    return b;
  }

  function buildDom() {
    // Toolbar button: icon AND text label, like every other feature button.
    var button = make("button");
    button.id = "btn-update";
    button.type = "button";
    button.title = "Updates";
    button.setAttribute("aria-pressed", "false");

    // Inline SVG stroked in currentColor; the CSP forbids external assets.
    var svg = svgEl("svg", {
      viewBox: "0 0 24 24",
      width: "16",
      height: "16",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "2",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
    });
    // An arrow coming down into a tray: the standard "download and install"
    // glyph.
    //
    // It used to be a circular arrow with a tick -- which is the RELOAD button's
    // icon, at the other end of the same toolbar, at a different scale. Two
    // controls in one row drawn with the same symbol and meaning different
    // things ("reload this page" versus "check for a new version of the
    // browser"), and reload's circular arrow is one of the most fixed symbols
    // in any browser, so this one was always going to be the one misread.
    svg.appendChild(svgEl("path", { d: "M12 15V3" }));
    svg.appendChild(svgEl("polyline", { points: "7 10 12 15 17 10" }));
    svg.appendChild(
      svgEl("path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }),
    );
    button.appendChild(svg);
    // Icon-only for the same reason as the integrity button; `title` above
    // already says "Updates".

    // Labelled, at the project owner's direction, and named by chrome.css rather
    // than by copying a neighbour.
    //
    // This used to read `button.className = toolbar.querySelector("button")
    // .className` -- "borrow the toolbar's own styling" -- which sounds
    // reasonable and grabs the FIRST button in the strip. That is #btn-back, a
    // `nav-btn`: the icon-only navigation style, not the labelled feature
    // style this button wanted. It worked only because the button had no label
    // to lay out. Naming the class directly also means the width breakpoints
    // and the grey/green convention finally reach it.
    var label = document.createElement("span");
    label.className = "feature-label";
    label.textContent = "Updates";
    button.appendChild(label);
    // Feature controls live in the menu sheet now; the toolbar keeps only the
    // shield, the freeze chip and the menu button itself. `menu-item` supplies
    // the row geometry, `feature-btn` keeps the state classes -- is-active,
    // is-warning and aria-pressed are all written against that selector.
    var host = document.getElementById("toolbar");
    button.className = "feature-btn";
    (host || document.body).appendChild(button);

    // The panel, appended to the chrome page; the panel manager shows and
    // hides it. Panels live in the chrome strip, so normal flow is right.
    panel = make("div");
    panel.id = "update-panel";
    setStyles(panel, {
      background: "#1a1b20",
      color: "#d7d7dc",
      padding: "14px 16px",
      borderTop: "1px solid #3a3b43",
      fontSize: "13px",
      lineHeight: "1.5",
    });
    // Hidden via the ATTRIBUTE, not an inline display style: the panel
    // manager toggles [hidden] only, and an inline display:none beats the
    // UA's [hidden] rule unconditionally (that was the bug -- see the header).
    panel.hidden = true;
    document.body.appendChild(panel);

    var title = make("div", "Updates");
    setStyles(title, {
      color: "#e9e9ee",
      fontWeight: "600",
      marginBottom: "6px",
    });
    panel.appendChild(title);

    els.version = make("div");
    setStyles(els.version, { color: "#8f909a", marginBottom: "10px" });
    panel.appendChild(els.version);

    var channelRow = make("div");
    setStyles(channelRow, {
      display: "flex",
      gap: "8px",
      alignItems: "center",
      marginBottom: "4px",
    });
    var channelLabel = make("span", "Updates:");
    setStyles(channelLabel, { color: "#8f909a" });
    els.channelStable = makeButton("Stable");
    els.channelStable.id = "update-channel-stable";
    els.channelBeta = makeButton("Beta");
    els.channelBeta.id = "update-channel-beta";
    channelRow.appendChild(channelLabel);
    channelRow.appendChild(els.channelStable);
    channelRow.appendChild(els.channelBeta);
    panel.appendChild(channelRow);

    els.channelNote = make("div", CHANNEL_NOTE_STABLE);
    setStyles(els.channelNote, {
      color: "#8f909a",
      fontSize: "12px",
      marginBottom: "10px",
    });
    panel.appendChild(els.channelNote);

    els.status = make("div");
    setStyles(els.status, { color: "#e9e9ee", marginBottom: "4px" });
    panel.appendChild(els.status);

    els.detail = make("div");
    setStyles(els.detail, { marginBottom: "10px", whiteSpace: "pre-wrap" });
    panel.appendChild(els.detail);

    var row = make("div");
    setStyles(row, { display: "flex", gap: "8px", marginBottom: "10px" });
    els.check = makeButton("Check now");
    els.install = makeButton("Download and install");
    els.restart = makeButton("Restart and update now");
    row.appendChild(els.check);
    row.appendChild(els.install);
    row.appendChild(els.restart);
    panel.appendChild(row);

    // The background-download switch. A LABELLED checkbox rather than the
    // channel row's button pair: this is one independent yes/no, not a
    // choice between peers.
    var bgRow = make("label");
    setStyles(bgRow, {
      display: "flex",
      gap: "8px",
      alignItems: "center",
      marginBottom: "10px",
      cursor: "pointer",
    });
    els.bg = document.createElement("input");
    els.bg.type = "checkbox";
    els.bg.id = "update-background";
    // chrome.css sizes `input` for TEXT fields (full width), and a checkbox
    // inherits that -- it rendered 335px wide with the label stranded
    // across the panel. This panel builds its DOM in JS, so the correction
    // belongs here with the element.
    setStyles(els.bg, {
      width: "13px",
      height: "13px",
      flex: "none",
      margin: "0",
      accentColor: "#4d8f5e",
    });
    var bgText = make(
      "span",
      "Download updates in the background (installing still asks first)",
    );
    setStyles(bgText, { color: "#8f909a", fontSize: "12px" });
    bgRow.appendChild(els.bg);
    bgRow.appendChild(bgText);
    panel.appendChild(bgRow);
    els.bg.addEventListener("change", function () {
      window.__rb
        .request("update_background_set", { enabled: !!els.bg.checked })
        .then(function (data) {
          els.bg.checked = !!(data && data.enabled);
        })
        .catch(showError);
    });
    window.__rb
      .request("update_background_get", {})
      .then(function (data) {
        els.bg.checked = !!(data && data.enabled);
      })
      .catch(function () {});

    // The privacy cost of a check, stated plainly and always visible. What it
    // has to keep saying truthfully is argued where the strings are defined;
    // render() picks which one this build is entitled to.
    els.note = make("div", NOTE_SCHEDULED);
    // pre-wrap, so the second paragraph is a paragraph. Without it the "\n\n"
    // collapses and the whole disclosure runs together as one grey block.
    setStyles(els.note, {
      color: "#8f909a",
      fontSize: "12px",
      whiteSpace: "pre-wrap",
    });
    panel.appendChild(els.note);

    els.check.addEventListener("click", onCheck);
    els.install.addEventListener("click", onInstall);
    els.restart.addEventListener("click", onRestartClick);
    els.channelStable.addEventListener("click", function () {
      setChannel("stable");
    });
    els.channelBeta.addEventListener("click", function () {
      setChannel("beta");
    });

    return button;
  }

  // Visual state only; `render()` separately disables both when this build
  // has no update networking at all, same as the Check button.
  function setChannelButtons(active) {
    var stable = active !== "beta";
    els.channelStable.style.borderColor = stable ? "#4f8cff" : "#3a3b43";
    els.channelStable.style.fontWeight = stable ? "700" : "400";
    els.channelBeta.style.borderColor = stable ? "#3a3b43" : "#4f8cff";
    els.channelBeta.style.fontWeight = stable ? "400" : "700";
    els.channelNote.textContent = stable
      ? CHANNEL_NOTE_STABLE
      : CHANNEL_NOTE_BETA;
  }

  function refreshChannel() {
    window.__rb
      .request("update_channel_get", {})
      .then(function (data) {
        setChannelButtons(data && data.channel);
      })
      .catch(function () {});
  }

  function setChannel(channel) {
    window.__rb
      .request("update_channel_set", { channel: channel })
      .then(function (data) {
        setChannelButtons(data && data.channel);
      })
      .catch(showError);
  }

  function approxSize(size) {
    if (!size || size < 1024 * 1024) return "under 1 MB";
    return "about " + Math.round(size / (1024 * 1024)) + " MB";
  }

  // ONE CLICK -- but only THEIR click. The user pressed "Download and
  // install"; they should not then have to press a second button to install
  // what they just installed, so `ready` reached from THAT click applies
  // automatically. A background download also parks at `ready`, and that
  // one waits for the Restart button: reaching `ready` unattended must
  // never replace the running browser by itself.
  //
  // Guarded so it fires once: the panel polls every second, and `ready`
  // persists until the process is replaced.
  var applying = false;
  var userInstalled = false;

  function maybeApply(st) {
    if (applying || !userInstalled || st.state !== "ready" || !st.wired) return;
    applying = true;
    window.__rb.request("update_apply").catch(function () {
      // A failure leaves the staged file in place and the phase reports it;
      // re-arm so the user can retry rather than being stuck at "installing".
      applying = false;
    });
  }

  function onRestartClick() {
    if (applying) return;
    applying = true;
    window.__rb.request("update_apply").catch(function () {
      applying = false;
    });
  }

  function render(st) {
    if (!panel) return;
    maybeApply(st);
    els.version.textContent =
      "This PATANYX is version " +
      (st.running || "?") +
      (st.platform ? " (" + st.platform + ")" : "") +
      ".";

    var busy = st.state === "checking" || st.state === "downloading";
    var stateText = "";
    var detailText = "";
    var detailColor = "#8f909a";

    if (!st.available) {
      stateText = "Update checking is not built into this PATANYX.";
      detailText =
        "This build contains no update networking at all, so it never " +
        "contacts an update server -- there is nothing here to switch off.";
    } else if (st.state === "idle") {
      stateText = "No check has run yet.";
    } else if (st.state === "checking") {
      stateText = "Checking for updates…";
    } else if (st.state === "uptodate") {
      stateText = "PATANYX is up to date.";
      detailColor = "#9fd6ac";
      detailText =
        "The update server offers the version this machine already runs.";
    } else if (st.state === "offered") {
      stateText = "Version " + st.offered + " is available.";
      detailText =
        "You run " +
        st.running +
        ". The download is " +
        approxSize(st.size) +
        ". The publisher's signature is verified before anything is installed.";
    } else if (st.state === "downloading") {
      stateText = "Downloading version " + st.offered + "…";
      detailText =
        "The download is verified against the signed manifest before it is kept.";
    } else if (st.state === "refused") {
      stateText = "Update refused.";
      detailColor = "#e2a1a1";
      // The reason string comes from patanyx-update verbatim. Do not
      // paraphrase a security event.
      detailText = st.reason + "\n\nNothing was installed.";
    } else if (st.state === "failed") {
      stateText = st.retry
        ? "The download failed."
        : "The update check failed.";
      detailColor = "#d8b46a";
      detailText = (st.detail || "") + "\n\nNothing was installed.";
    } else if (st.state === "ready") {
      stateText = "Version " + st.offered + " is downloaded and verified.";
      detailColor = "#9fd6ac";
      detailText = !st.wired
        ? "Installed. Restart PATANYX to finish \u2014 the new version is already running in a new window.\n" +
          (st.staged || "")
        : userInstalled
          ? "Ready to install."
          : "Downloaded in the background and verified. Nothing is installed " +
            "until you choose to restart, whenever suits you.";
    }

    // The publisher-signed release blurb, when the manifest carries one.
    // Appended to the three states that present an update the user can act
    // on; textContent keeps it text whatever it says, and Rust has already
    // refused control and direction-override characters at verify time.
    if (
      st.notes &&
      (st.state === "offered" ||
        st.state === "downloading" ||
        st.state === "ready")
    ) {
      detailText += "\n\nWhat is new in " + st.offered + ":\n" + st.notes;
    }

    els.status.textContent = stateText;
    els.detail.textContent = detailText;
    els.detail.style.color = detailColor;

    // The disclosure follows the build, not the default. `available` is the
    // `updater-net` feature as the running binary reports it.
    els.note.textContent = st.available ? NOTE_SCHEDULED : NOTE_NO_NETWORK;

    els.check.disabled = !st.available || busy;
    els.check.style.opacity = els.check.disabled ? "0.5" : "1";
    els.check.style.cursor = els.check.disabled ? "default" : "pointer";

    // Choosing a channel this build can never fetch from is not a choice.
    els.channelStable.disabled = !st.available;
    els.channelBeta.disabled = !st.available;
    els.channelStable.style.opacity = st.available ? "1" : "0.5";
    els.channelBeta.style.opacity = st.available ? "1" : "0.5";

    var canInstall =
      st.available &&
      !busy &&
      (st.state === "offered" || (st.state === "failed" && st.retry));
    els.install.style.display = canInstall ? "" : "none";
    els.install.textContent =
      st.state === "failed" ? "Try downloading again" : "Download and install";

    // The background-ready case: verified bytes are waiting and no click
    // consented yet, so the consent IS this button.
    var canRestart =
      st.available && st.state === "ready" && st.wired && !userInstalled;
    els.restart.style.display = canRestart ? "" : "none";

    if (!busy) stopPolling();
  }

  function showError(err) {
    els.status.textContent = "Something went wrong.";
    els.detail.style.color = "#d8b46a";
    els.detail.textContent = window.__rb.friendly
      ? window.__rb.friendly(err)
      : String(err);
  }

  function onCheck() {
    window.__rb.request("update_check", {}).then(render).catch(showError);
    startPolling();
  }

  function onInstall() {
    // Consent for the auto-apply when THIS download completes.
    userInstalled = true;
    window.__rb.request("update_install", {}).then(render).catch(showError);
    startPolling();
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(function () {
      window.__rb
        .request("update_status", {})
        .then(render)
        .catch(function () {
          stopPolling();
        });
    }, POLL_MS);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function refresh() {
    window.__rb
      .request("update_status", {})
      .then(render)
      .catch(function () {});
  }

  function init() {
    if (!window.__rb || !window.__rb.registerPanel) return;
    var button = buildDom();
    window.__rb.registerPanel("update", {
      el: panel,
      button: button,
      // 452, the same budget every other feature panel asks for, because at
      // 300 this panel had 15px of slack under the privacy note and the note
      // just got longer. The panel does not scroll by itself (it is built
      // here, in JS, and was never in chrome.css's panel rule -- now it is),
      // so overflow was not a scrollbar: the disclosure simply stopped
      // existing below the fold. Measured at 1100x300, the window's default
      // width; a narrower window wraps it further.
      heightPx: 500,
      onOpen: function () {
        refresh();
        refreshChannel();
      },
      onClose: function () {
        stopPolling();
      },
    });
    // Pick up the status once (e.g. an unavailable build) so the first open
    // renders real state instead of a blank.
    refresh();
    refreshChannel();
  }

  try {
    init();
  } catch (e) {
    // A broken updater panel must not break the rest of the chrome.
  }
})();
