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
  // The catalog helpers, shared through the same bridge object every
  // cross-script capability rides (__rb.request, __rb.askConfirm...).
  const { i18nText, i18nResolve, i18nSet, rebuildOnLocaleFill } =
    window.__rb || {};

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
  // SHORTENED 2026-08-27 because: 150 words nobody read.
  // The three facts kept are the three the long version was written to fix,
  // in the order a reader cares about: it checks WITHOUT being asked, the
  // server sees an IP and a time, and nothing installs without an accept.
  // The tunnel clause stays because it is a fail-closed guarantee.
  //
  // The frequencies are the constants in schedule.rs. If those change this
  // changes with them: a note that understates contact is worse than none.
  var NOTE_SCHEDULED, NOTE_NO_NETWORK;
  rebuildOnLocaleFill(function () {
    NOTE_SCHEDULED = i18nText("chrome-js-update-note-scheduled", "PATANYX checks for updates about every six hours, and the malicious-site list about once an hour, whether or not you press the button. Update checks request release information and, when configured, engine advisories. They do not send your account, an installation ID, your engine version, or browsing activity. The update server can see your IP address, when you check, which update files you request, and a generic PATANYX user-agent label. With a tunnel imported, checks go through the tunnel or fail.\n\nWith automatic updates off, nothing installs without your accept. With them on, fixes install themselves at the next launch; a release that adds new features asks first and installs on its own only after seven days, unless it also carries a security fix, which installs at the next launch.");
    // A build compiled without `updater-net` has no HTTP stack at all, so the
    // paragraph above would promise contact that never happens.
    NOTE_NO_NETWORK = i18nText("chrome-js-update-note-no-network", "This build has no update networking compiled into it, so it contacts no server at all -- not on a schedule, and not when you press the button.");
  });

  // Two fixed manifest URLs, not a per-install one -- see UpdateChannel's own
  // doc in prefs.rs. Switching takes effect on the NEXT check; nothing here
  // restarts anything.
  var CHANNEL_NOTE_STABLE, CHANNEL_NOTE_BETA;
  rebuildOnLocaleFill(function () {
    CHANNEL_NOTE_STABLE = i18nText("chrome-js-update-channel-stable", "The regular release.");
    // The second sentence stays: it is the one that says Beta does not make
    // this install identifiable, which is the question a privacy-minded
    // reader actually has about opting into a smaller group.
    CHANNEL_NOTE_BETA = i18nText("chrome-js-update-channel-beta", "This install was on the Beta channel from the pre-release line. There is no Beta in 1.0.0; it follows Stable from now on.");
  });

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
    button.title = i18nText("chrome-js-update-button", "Updates");
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

    // Labelled, deliberately, and named by chrome.css rather
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
    label.textContent = i18nText("chrome-js-update-button", "Updates");
    button.appendChild(label);
    // Built once; label and tooltip follow a live locale switch.
    rebuildOnLocaleFill(function () {
      var text = i18nText("chrome-js-update-button", "Updates");
      button.title = text;
      label.textContent = text;
    });
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
    // An id so the gate can assert the buttons are IN the row, not merely
    // created: the DOM harness registers an element by id the moment it is
    // made, so "the button exists" was true even when nothing appended it.
    channelRow.id = "update-channel-row";
    setStyles(channelRow, {
      display: "flex",
      gap: "8px",
      alignItems: "center",
      marginBottom: "4px",
    });
    var channelLabel = make("span", "Updates:");
    setStyles(channelLabel, { color: "#8f909a" });
    // BOTH CHANNELS, because 1.0.0 is a stable line. Through the 0.9.x
    // pre-releases this row showed one "Beta" button: every release was a
    // pre-release, both channel URLs served the identical signed manifest,
    // and a "Stable" button would have offered a maturity that did not
    // exist. That reasoning ended with the first stable release. Stable is
    // the regular release; Beta is the next one before it reaches Stable.
    // ONE CHANNEL IN 1.0.0. The Beta button is not built (decided
    // 2026-09-16: "There shouldn't be a Beta button"); Stable is shown as the
    // channel this install follows, not as a choice. The backend keeps its
    // channel preference and arm; an install still stored on Beta from the
    // pre-release line is moved to Stable once, with a note, in
    // setChannelButtons.
    els.channelStable = makeButton("Stable");
    els.channelStable.id = "update-channel-stable";
    els.channelStable.disabled = true;
    els.channelStable.style.cursor = "default";
    channelRow.appendChild(channelLabel);
    channelRow.appendChild(els.channelStable);
    panel.appendChild(channelRow);

    els.channelNote = make("div", CHANNEL_NOTE_STABLE);
    els.channelNote.id = "update-channel-note";
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
    // Built once; the labels follow the locale through the same rebuild
    // hook the chrome's own tables use.
    rebuildOnLocaleFill(function () {
      els.check.textContent = i18nText("chrome-js-update-check-label", "Check now");
      els.install.textContent = i18nText("chrome-js-update-install-label", "Download and install");
      els.restart.textContent = i18nText("chrome-js-update-restart-label", "Restart and update now");
    });
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
      "Download updates in the background (installing is a separate switch, below)",
    );
    setStyles(bgText, { color: "#8f909a", fontSize: "12px" });
    bgRow.appendChild(els.bg);
    bgRow.appendChild(bgText);
    panel.appendChild(bgRow);
    els.bg.addEventListener("change", function () {
      clearErrorAndShowStatus();
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

    // The auto-apply switch. What it turns on is decided per release by the
    // SIGNED manifest (maintenance and security releases install themselves
    // at the next launch; feature releases ask first and wait out a 7-day
    // grace) -- this checkbox only says whether this install participates.
    // Ships OFF in 1.0.0 by decision: self-replacement has never run in the
    // field, and the recovery path covers a failed write but not a failed
    // relaunch, so it stays opt-in until a real replace-and-relaunch test
    // has been run on hardware.
    var autoRow = make("label");
    setStyles(autoRow, {
      display: "flex",
      gap: "8px",
      alignItems: "center",
      marginBottom: "10px",
      cursor: "pointer",
    });
    els.auto = document.createElement("input");
    els.auto.type = "checkbox";
    els.auto.id = "update-auto-apply";
    setStyles(els.auto, {
      width: "13px",
      height: "13px",
      flex: "none",
      margin: "0",
      accentColor: "#4d8f5e",
    });
    var autoText = make(
      "span",
      "Install updates automatically at the next launch (releases that " +
        "add new features ask first, unless they carry a security fix)",
    );
    setStyles(autoText, { color: "#8f909a", fontSize: "12px" });
    autoRow.appendChild(els.auto);
    autoRow.appendChild(autoText);
    panel.appendChild(autoRow);
    els.auto.addEventListener("change", function () {
      clearErrorAndShowStatus();
      window.__rb
        .request("update_auto_apply_set", { enabled: !!els.auto.checked })
        .then(function (data) {
          els.auto.checked = !!(data && data.enabled);
        })
        .catch(showError);
    });
    window.__rb
      .request("update_auto_apply_get", {})
      .then(function (data) {
        els.auto.checked = !!(data && data.enabled);
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

    return button;
  }

  // Visual state only; `render()` separately disables both when this build
  // has no update networking at all, same as the Check button.
  var channelMoved = false;
  // Separate from `channelMoved` on purpose. `channelMoved` means the
  // preference IS stored as Stable; this one means a write is in the air.
  // Two callers ask the channel today -- once at init, once when the panel
  // opens -- and they are far enough apart that each settles before the next
  // begins, so the retry works without this. It is here so that a third
  // caller, or a reply that lands slower than a microtask, cannot turn one
  // migration into two writes racing to set the same value.
  var channelMoving = false;
  function setChannelButtons(active) {
    els.channelStable.style.borderColor = "#4f8cff";
    els.channelStable.style.fontWeight = "700";
    if (active === "beta" && !channelMoved && !channelMoving) {
      // A pre-release install still stored on Beta. There is no Beta in
      // 1.0.0, so it follows Stable from here; said once, done once.
      //
      // MARKED DONE ONLY ONCE IT IS STORED. Setting the flag before the
      // write and swallowing the rejection meant a failed preference save
      // left the install fetching the Beta manifest while this panel said it
      // now follows Stable, and no later open ever retried, so such an
      // install quietly stopped receiving updates (review R-005).
      els.channelNote.textContent = CHANNEL_NOTE_BETA;
      channelMoving = true;
      window.__rb
        .request("update_channel_set", { channel: "stable" })
        .then(function () {
          channelMoving = false;
          channelMoved = true;
        })
        .catch(function () {
          // Nothing moved, so withdraw the sentence that says it did and
          // leave the migration unmarked for the next time the panel opens.
          channelMoving = false;
          els.channelNote.textContent = CHANNEL_NOTE_STABLE;
        });
      return;
    }
    els.channelNote.textContent = CHANNEL_NOTE_STABLE;
  }

  function refreshChannel() {
    window.__rb
      .request("update_channel_get", {})
      .then(function (data) {
        var channel = data && data.channel;
        // The 0.9.x panel moved a stored Stable to Beta here, because the
        // Beta button was the only one drawn. That migration is gone with
        // the single-button row; the one-time reset of installs it moved
        // lives in Rust (prefs::load), where a stored value is actually
        // decided, not in a renderer that runs only when the panel opens.
        setChannelButtons(channel);
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

  async function approxSize(size) {
    if (!size || size < 1024 * 1024) {
      return i18nResolve("chrome-js-update-size-small", {}, "under 1 MB");
    }
    var mb = Math.round(size / (1024 * 1024));
    return i18nResolve("chrome-js-update-size-mb", { mb }, "about " + mb + " MB");
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
    clearError();
    window.__rb.request("update_apply").catch(function (e) {
      // Rust refuses BEFORE the phase moves (not_ready, install_failed), so
      // "the phase reports it" was never true for this path: the click did
      // nothing visible (launch sweep F-003).
      //
      // AND THEN THE FIX RE-ADDED THE SILENCE. It showed the code and called
      // refresh(), whose async render overwrote the explanation with the
      // ordinary ready text a moment later, leaving the panel identical
      // before and after a failed install (review R-004). There is nothing to
      // re-read: the phase did not move, which is exactly why this path
      // exists. The error stands until the person asks for something new.
      applying = false;
      showError(e);
    });
  }

  var renderGen = 0;
  async function render(st) {
    if (!panel) return;
    // Successive status events race their awaits; only the newest render
    // may touch the sinks -- the same strictly-newest rule the locale fill
    // itself uses.
    var gen = ++renderGen;
    maybeApply(st);
    var versionPlain =
      "This PATANYX is version " +
      (st.running || "?") +
      (st.platform ? " (" + st.platform + ")" : "") +
      ".";
    var versionText = await i18nResolve(
      "chrome-js-update-version-line",
      { version: st.running || "?", platform: st.platform || "" },
      versionPlain,
    );

    var busy = st.state === "checking" || st.state === "downloading";
    var stateText = "";
    var detailText = "";
    var detailColor = "#8f909a";

    if (!st.available) {
      stateText = i18nText("chrome-js-update-not-built", "Update checking is not built into this PATANYX.");
      detailText = i18nText("chrome-js-update-not-built-detail",
        "This build contains no update networking at all, so it never " +
          "contacts an update server -- there is nothing here to switch off.");
    } else if (st.state === "idle") {
      stateText = i18nText("chrome-js-update-idle", "No check has run yet.");
    } else if (st.state === "checking") {
      stateText = i18nText("chrome-js-update-checking", "Checking for updates…");
    } else if (st.state === "uptodate") {
      stateText = i18nText("chrome-js-update-uptodate", "PATANYX is up to date.");
      detailColor = "#9fd6ac";
      detailText = i18nText("chrome-js-update-uptodate-detail",
        "The update server offers the version this machine already runs.");
    } else if (st.state === "ahead") {
      stateText = i18nText("chrome-js-update-uptodate", "PATANYX is up to date.");
      detailColor = "#9fd6ac";
      detailText = await i18nResolve("chrome-js-update-ahead-detail",
        { running: st.running || "", offered: st.offered || "" },
        "This machine runs " + (st.running || "") + ", newer than the " + (st.offered || "") + " the update server offers.");
    } else if (st.state === "offered") {
      stateText = await i18nResolve("chrome-js-update-offered-state",
        { version: st.offered },
        "Version " + st.offered + " is available.");
      detailText = await i18nResolve("chrome-js-update-offered-detail",
        { running: st.running, size: await approxSize(st.size) },
        "You run " + st.running + ". The download is " + await approxSize(st.size) +
          ". The publisher's signature is verified before anything is installed.");
    } else if (st.state === "downloading") {
      stateText = await i18nResolve("chrome-js-update-downloading",
        { version: st.offered },
        "Downloading version " + st.offered + "…");
      detailText = i18nText("chrome-js-update-downloading-detail",
        "The download is verified against the signed manifest before it is kept.");
    } else if (st.state === "refused") {
      stateText = i18nText("chrome-js-update-refused", "Update refused.");
      detailColor = "#e2a1a1";
      // The reason string comes from patanyx-update verbatim. Do not
      // paraphrase a security event.
      detailText =
        st.reason +
        (await i18nResolve("chrome-js-update-nothing-installed", {},
          "\n\nNothing was installed."));
    } else if (st.state === "failed") {
      stateText = st.retry
        ? i18nText("chrome-js-update-download-failed", "The download failed.")
        : i18nText("chrome-js-update-check-failed", "The update check failed.");
      detailColor = "#d8b46a";
      detailText =
        (st.detail || "") +
        (await i18nResolve("chrome-js-update-nothing-installed", {},
          "\n\nNothing was installed."));
    } else if (st.state === "ready") {
      stateText = await i18nResolve("chrome-js-update-ready-state",
        { version: st.offered },
        "Version " + st.offered + " is downloaded and verified.");
      detailColor = "#9fd6ac";
      detailText = !st.wired
        ? i18nText("chrome-js-update-restart-finish",
            "Installed. Restart PATANYX to finish. The new version is already running in a new window.\n") +
          (st.staged || "")
        : userInstalled
          ? i18nText("chrome-js-update-ready-install", "Ready to install.")
          // Quiet releases self-install at the next launch; an announced
          // feature release waits out its grace period first. Say the one
          // that is true of THIS release, from the same signed fields the
          // policy reads.
          : st.auto_apply && (st.kind !== "feature" || st.security)
            ? i18nText("chrome-js-update-bg-ready-next-launch",
                "Downloaded in the background and verified. It installs at the next launch, or restart now to take it immediately.")
            : st.auto_apply
              ? i18nText("chrome-js-update-bg-ready-week",
                  "Downloaded in the background and verified. Restart to take it now; otherwise it installs on its own in about a week.")
              : i18nText("chrome-js-update-bg-ready",
                  "Downloaded in the background and verified. Nothing is installed until you choose to restart, whenever suits you.");
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
      detailText += await i18nResolve("chrome-js-update-whats-new",
        { version: st.offered, notes: st.notes },
        "\n\nWhat is new in " + st.offered + ":\n" + st.notes);
    }

    // YOUR NETWORK IS READING THIS CONNECTION, AND SAYING SO IS THE POINT.
    //
    // A corporate proxy terminates TLS and re-signs it with a CA the machine
    // trusts and no public root list does. The check now retries against the
    // OS trust store so such a user still RECEIVES updates -- before, they
    // silently received none at all -- and this is the half that keeps the
    // fallback honest: the fact is shown, not swallowed, along with what
    // still protected the download when TLS did not.
    //
    // Deliberately not styled as an error. Nothing failed, and the update is
    // exactly as trustworthy as any other: the manifest carries the
    // publisher's signature and the bytes are checked against it.
    //
    // PRESENT TENSE, AND THAT IS LOAD-BEARING. The flag is set by the
    // MANIFEST fetch, which is the check -- so this notice appears with no
    // download in existence, and an earlier draft saying "the download was
    // still verified" was simply false on screen in the ordinary
    // up-to-date case. It states the standing property instead.
    //
    // The last sentence is the inconvenient half, and it belongs here: a
    // proxy that terminates TLS sees the request. Scoped to what this
    // request actually reveals -- that a check happened -- because the
    // manifest URL is identical for every install and carries no version.
    if (st.intercepted) {
      detailText += i18nText("chrome-js-update-intercepted",
        "\n\nSomething on this computer or its network is inspecting " +
          "encrypted traffic, so " +
          "the last signed fetch from the update server was accepted against " +
          "the certificates your computer trusts. Updates are verified against " +
          "the publisher's signature, " +
          "which does not depend on the connection. Whoever runs that equipment " +
          "can see that this browser checked for an update.");
    }

    if (gen !== renderGen) return; // a newer status event superseded this one
    els.version.textContent = versionText;
    // The version line and the controls below always follow the status. The
    // status and detail do not, while a failure is on screen waiting to be
    // read: a poll landing a moment later must not erase it (review R-004).
    if (!errorShown) {
      els.status.textContent = stateText;
      els.detail.textContent = detailText;
      els.detail.style.color = detailColor;
    }

    // The disclosure follows the build, not the default. `available` is the
    // `updater-net` feature as the running binary reports it.
    els.note.textContent = st.available ? NOTE_SCHEDULED : NOTE_NO_NETWORK;

    els.check.disabled = !st.available || busy;
    els.check.style.opacity = els.check.disabled ? "0.5" : "1";
    els.check.style.cursor = els.check.disabled ? "default" : "pointer";

    // Choosing a channel this build can never fetch from is not a choice.

    var canInstall =
      st.available &&
      !busy &&
      (st.state === "offered" || (st.state === "failed" && st.retry));
    els.install.style.display = canInstall ? "" : "none";
    els.install.textContent =
      st.state === "failed"
        ? i18nText("chrome-js-update-retry-label", "Try downloading again")
        : i18nText("chrome-js-update-install-label", "Download and install");

    // The background-ready case: verified bytes are waiting and no click
    // consented yet, so the consent IS this button.
    var canRestart =
      st.available && st.state === "ready" && st.wired && !userInstalled;
    els.restart.style.display = canRestart ? "" : "none";

    if (!busy) stopPolling();
  }

  // While this is set, the status sinks belong to the explanation and a
  // status render may not touch them. Cleared when the person asks for
  // something new, which is the only moment an old failure stops being the
  // most recent thing that happened to them.
  var errorShown = false;

  // Two clears, and the difference is load-bearing.
  //
  // Dropping the flag does NOT repaint: while it was set every render skipped
  // the status and detail lines, so the words of the old failure are still on
  // screen. Somebody has to ask the panel what is true now. But making the
  // clear itself do that broke a different thing (review round 3): a status
  // read carrying the state from BEFORE the action can land after the action
  // started, and `render` ends with `if (!busy) stopPolling()` -- so clicking
  // Download and install while an old settings error was showing cancelled
  // the polling that the download it had just started depended on, and the
  // panel sat on "Downloading" forever.
  //
  // So: callers that render on their own take `clearError`, and only the ones
  // that would otherwise leave stale words on screen pay for a refresh.
  function clearError() {
    errorShown = false;
  }

  // Any render still suspended on its localization is holding a status from
  // BEFORE this action, and `render` ends by stopping the poll timer when the
  // state it is carrying is not busy. So an old `offered` render resuming
  // after a click started a download stopped that download's polling, and the
  // panel sat on "Downloading" with nothing left to notice it had finished
  // (review round 4). A non-English locale makes that await a real gap rather
  // than a theoretical one. Bumping the generation retires those renders: the
  // check they already perform on the way out does the rest.
  function supersedeRenders() {
    renderGen++;
  }

  function clearErrorAndShowStatus() {
    if (!errorShown) return;
    errorShown = false;
    // If this answer arrives after a fresh failure, the guard is already back
    // up and the render will leave the new explanation alone.
    refresh();
  }

  function showError(err) {
    errorShown = true;
    els.status.textContent = i18nText("chrome-js-update-wrong", "Something went wrong.");
    els.detail.style.color = "#d8b46a";
    els.detail.textContent = window.__rb.friendly
      ? window.__rb.friendly(err)
      : String(err);
  }

  function onCheck() {
    clearError();
    window.__rb.request("update_check", {}).then(render).catch(showError);
    supersedeRenders();
    startPolling();
  }

  function onInstall() {
    // Consent for the auto-apply when THIS download completes.
    userInstalled = true;
    clearError();
    window.__rb.request("update_install", {}).then(render).catch(showError);
    supersedeRenders();
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
        // Opening the panel is the person asking what the state is NOW. An
        // error from a previous visit must not outlive that question: it
        // suppressed the status lines while the version line above kept
        // updating, so the panel showed a stale failure beside fresh facts
        // (review R-004).
        clearError();
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
