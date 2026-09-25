// Every feature control is IN the toolbar, and nothing hides one.
//
// WHY THIS EXISTS, AND WHY IT HAS BEEN REWRITTEN ONCE.
//
// This file began as menu-gate.js, guarding the opposite arrangement: the
// toolbar held three controls and the rest lived in a menu sheet. That gate
// existed because moving a control into a sheet made older assertions VACUOUS
// rather than failing -- `$("btn-dns").hidden === false` stays true for a
// button sealed inside a closed sheet, so the DNS gate went on passing while
// proving nothing about whether anyone could reach it.
//
// The layout is now two rows with every pill visible, and the same trap points
// the other way: it would be easy to reintroduce an overflow menu, move two
// controls into it, and have every existing gate stay green because each
// button still exists and still has a handler. So this asserts the property
// the layout is FOR:
//
//   1. Every feature control is inside #toolbar in the markup.
//   2. There is no disclosure -- no sheet, no hamburger -- that could hold one.
//   3. The row break exists, so they wrap under the address bar rather than
//      crowding its right-hand end.
//   4. Nothing in the row is a button that does nothing.
//
// Point 2 is the one that earns its keep. Without it, "every control is in the
// toolbar" stays true the moment somebody puts a sheet INSIDE the toolbar,
// which is exactly how the previous arrangement was built.
//
// Run: node scripts/toolbar-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
// Planted-defect mode: keep the renderer and every source assertion intact,
// but rename the one listener this feature needs -- the tab STRIP's drop,
// which is where the drop target lives now that it is no longer bound per
// chip. The normal run never edits a workspace file; running with
// PATANYX_TAB_REORDER_OMIT_DROP_HANDLER=1 must fail the behavioral check below.
//
// Anchored on the guard line too, and required to match exactly once:
// chrome.js has a second `wrap.addEventListener("drop"` for the bookmark
// organizer's cards, and renaming that one would prove nothing about tabs.
if (process.env.PATANYX_TAB_REORDER_OMIT_DROP_HANDLER) {
  const guard = "\n      if (draggedTabId === null) return;";
  const callSite = 'wrap.addEventListener("drop", (ev) => {' + guard;
  assert(
    chromeJs.split(callSite).length === 2,
    "cannot plant defect: the tab strip's drop handler spelling changed",
  );
  chromeJs = chromeJs.replace(
    callSite,
    'wrap.addEventListener("drop-removed", (ev) => {' + guard,
  );
}
// WP-V plant proofs. Each removes one live behavior while leaving the markup
// and source-level contracts intact, so the behavioral assertions below must
// be what turn red.
//
// The right inset is measured once into a local in syncChromeInsets and handed
// to set_chrome_insets as shorthand, so zeroing that local zeroes exactly what
// Rust is told. The stylesheet's --chrome-right-px comes from its own call in
// publishChromeMetric and is left alone: "all four layouts report symmetric
// insets to Rust" is the check that must turn red. Required to match exactly
// once, as the tab-drop plant is: a second spelling means this no longer names
// the one value Rust is sent.
if (process.env.PATANYX_TOOLBAR_OMIT_RIGHT_INSET) {
  const callSite = "const right = closedChromeRightPx();";
  assert(
    chromeJs.split(callSite).length === 2,
    "cannot plant defect: the right inset sent to Rust changed spelling",
  );
  chromeJs = chromeJs.replace(callSite, "const right = 0;");
}
if (process.env.PATANYX_TOOLBAR_OMIT_LABEL_GRAY) {
  const callSite = "if (choice) choice.disabled = vertical;";
  assert(
    chromeJs.includes(callSite),
    "cannot plant defect: label graying call changed",
  );
  chromeJs = chromeJs.replace(callSite, "if (choice) choice.disabled = false;");
}
if (process.env.PATANYX_RECEIPT_OMIT_CAPTION) {
  const callSite =
    'captionEl.textContent =\n      "Refused by the blocker since the browser was launched, counted across every tab, including tabs you have since closed.";';
  assert(
    chromeJs.includes(callSite),
    "cannot plant defect: receipt caption changed",
  );
  chromeJs = chromeJs.replace(callSite, 'captionEl.textContent = "";');
}
new Function(chromeJs)();

const headerAt = html.indexOf('<header id="toolbar"');
const headerEnd = html.indexOf("</header>");
const TOOLBAR_SRC = html.slice(headerAt, headerEnd);
const TOOLBAR_AT = headerAt;

// Press a placement button and let the round trip settle.
//
// Through the real control, not by calling an internal: what is under test
// is the whole path -- click, IPC, reply, wear -- and a gate that reached
// past the button would keep passing after the button stopped being wired.
// The stub answers `toolbar_placement_set` by echoing the argument, which is
// what Rust does.
// The rail has a width, because nothing here has a layout.
//
// The stub measures every element at zero, so `closedChromeLeftPx()` would
// report 0 for a sidebar that is genuinely showing -- and a gate asserting
// "the inset is non-zero" would be asserting against the harness rather than
// the chrome. Planted, the same way blocked-banner-gate plants a banner's
// height to prove the banner is measured. 56 is the width the stylesheet
// gives it.
const RAIL_PX = 56;
global.$("sidebar").getBoundingClientRect = () => ({
  height: 0,
  width: RAIL_PX,
  top: 0,
  left: 0,
});

const wear = async (placement) => {
  // Rust echoes the value it accepted, and the chrome re-dresses from the
  // REPLY rather than from the click -- so a stub that answered `{}` would
  // leave the layout where it was and every check below would fail for the
  // wrong reason. Seeded per call, which is also what makes a mismatched
  // echo expressible if anyone wants to test one.
  global.rbResolve.toolbar_placement_set = { placement };
  global.$("placement-" + placement)._fire("click");
  await flush();
};

// Every control a user chose to have. None of these may be hidden behind
// anything: that is the whole point of the two-row layout.
const MUST_BE_VISIBLE = [
  ["btn-privacy", "the protection summary"],
  ["btn-freeze", "the freeze chip"],
  ["btn-quarantine-menu", "opening a quarantine tab"],
  ["btn-tab", "the per-tab activity ledger"],
  ["btn-vault", "the vault"],
  ["btn-dns", "the resolver picker"],
  ["btn-chat", "chat, in the builds that have it"],
  ["btn-bookmark", "bookmarking the current page"],
  ["btn-library", "bookmarks and downloads"],
  ["btn-about", "version, licence and third-party notices"],
];

const fireChrome = (event, data) => global.window.__rb_event({ event, data });
const tabChips = () => Array.from(global.$("tabs").children || []);
const tabChipIds = () => tabChips().map((chip) => Number(chip.dataset.tabId));
const activeChipId = () => {
  const chip = tabChips().find((candidate) =>
    String(candidate.className || "")
      .split(/\s+/)
      .includes("active"),
  );
  return chip ? Number(chip.dataset.tabId) : null;
};
const tabItems = (ids, active) =>
  ids.map((id) => ({
    id,
    url: "https://tab-" + id + ".example/",
    title: "Tab " + id,
    active: id === active,
  }));

check(
  "tab chips drag one full permutation and keep the active tab by id",
  async () => {
    // Let the boot-time tab_list promise settle before publishing the test's
    // authoritative event; otherwise its empty stub reply could clear the
    // strip between dragstart and drop.
    await flush();
    fireChrome("tabs_changed", { items: tabItems([11, 22, 33], 22) });
    const strip = global.$("tabs");
    const [first, , third] = tabChips();
    assert(first && third, "setup did not render three tab chips");
    // THE DRAG HAS TWO ENDS, AND THEY LIVE ON DIFFERENT ELEMENTS.
    //
    // A chip is the SOURCE: draggable, named by dragstart, cleaned up after by
    // dragend. The STRIP is the target: one dragover and one drop on the
    // container. The target used to be each chip, so a release past the last
    // tab -- the commonest reorder there is -- landed on container, fired no
    // drop, and the next repaint undid the move. This check went on demanding
    // the per-chip target after it moved, so it failed a correct build at its
    // first assertion and said nothing about the drag itself.
    assert(
      first.getAttribute("draggable") === "true" &&
        first._has("dragstart") &&
        first._has("dragend"),
      "tab chips are not drag sources through draggable/dragstart/dragend",
    );
    assert(
      strip._has("dragover") && strip._has("drop"),
      "the tab strip is not the drop target through dragover/drop, so a " +
        "release past the last tab would fire nothing",
    );
    // And ONLY the strip. A chip-level pair beside it is two handlers
    // previewing one pointer against a DOM the other has just rearranged.
    assert(
      !tabChips().some((chip) => chip._has("dragover") || chip._has("drop")),
      "a tab chip carries its own dragover/drop beside the strip's",
    );

    const carried = [];
    const dataTransfer = {
      effectAllowed: "",
      dropEffect: "",
      setData(type, value) {
        carried.push([type, value]);
      },
    };
    global.rbCalls.length = 0;
    global.rbResolve.tab_reorder = {
      ids: [22, 33, 11],
      items: tabItems([22, 33, 11], 22),
    };
    first._fire("dragstart", { dataTransfer });
    // Dispatched on the strip, because that is where the listeners are and
    // this stub does not bubble. Nothing is lost by it: the handlers read the
    // pointer's clientX and never the event's target, so a release over a
    // chip (which bubbles up to the strip) and one past the last chip (which
    // starts there) reach the same code. Every chip measures zero here, so
    // clientX 1 is past the last of them.
    strip._fire("dragover", { clientX: 1, dataTransfer });
    assert(
      tabChipIds().join(",") === "22,33,11",
      "dragover did not preview the order; got " + tabChipIds().join(","),
    );
    // By the drop, the preview has already put the dragged tab under the
    // pointer, so the drop's own preview resolves to that tab and returns
    // nothing. That is the ordinary successful drag, and it must commit the
    // order the strip is showing rather than read it as "nothing to do".
    strip._fire("drop", { clientX: 1, dataTransfer });
    assert(
      global.rbCalls.some((call) => call.cmd === "tab_reorder"),
      "the drop sent no tab_reorder, so the order it showed was never committed",
    );
    // dragend fires on the source right after the drop, before Rust replies.
    // It repaints only an ABANDONED drag; repainting here would put the old
    // order back over a commit that is still in flight.
    first._fire("dragend", { dataTransfer });
    assert(
      tabChipIds().join(",") === "22,33,11",
      "dragend repainted the pre-drag order over a committed drop; got " +
        tabChipIds().join(","),
    );
    await flush();

    const calls = global.rbCalls.filter((call) => call.cmd === "tab_reorder");
    assert(calls.length === 1, "one drop sent " + calls.length + " reorders");
    assert(
      calls[0].args.ids.join(",") === "22,33,11",
      "drop did not send the full previewed permutation: " +
        JSON.stringify(calls[0].args),
    );
    assert(
      tabChipIds().join(",") === "22,33,11",
      "the canonical reorder reply was not rendered",
    );
    assert(
      activeChipId() === 22,
      "active chip changed identity after reorder: " + activeChipId(),
    );
    // Bound once, on a container every repaint keeps. The strip has been
    // rendered at least twice by now (this test's tabs_changed and the
    // reorder reply), so wiring inside the render would show as a second pair.
    const wired = (type) => (strip._listeners[type] || []).length;
    assert(
      wired("dragover") === 1 && wired("drop") === 1,
      "the strip holds " +
        wired("dragover") +
        " dragover and " +
        wired("drop") +
        " drop listeners; the pair is being re-wired on every repaint",
    );
    // A drag MUST write something, and it must not be the tab id.
    //
    // This assertion used to demand `carried.length === 0`, and that is how a
    // gate enforced a defect: an HTML5 drag with an empty dataTransfer is
    // abandoned by both engines, which fall back to selecting the text under
    // the cursor. The tab strip did exactly that on real hardware -- press,
    // move, and the tab TITLE highlighted while the tab stayed put. The
    // property actually worth protecting was never "carry nothing", it was
    // "never carry an internal address", so that is what is checked now.
    assert(
      carried.length > 0,
      "tab drag wrote NO dataTransfer payload, so no drag can start",
    );
    const ids = ["11", "22", "33"];
    assert(
      !carried.some(([, value]) => ids.includes(String(value))),
      "an internal tab id rode in dataTransfer: " + JSON.stringify(carried),
    );

    // Re-rendering after a drop must not cost the two existing direct actions.
    global.rbCalls.length = 0;
    const inactive = tabChips().find(
      (chip) => Number(chip.dataset.tabId) === 33,
    );
    inactive._fire("click");
    inactive.querySelector(".chip-close")._fire("click");
    const direct = global.rbCalls.filter(
      (call) => call.cmd === "tab_switch" || call.cmd === "tab_close",
    );
    assert(
      direct.length === 2 &&
        direct[0].cmd === "tab_switch" &&
        direct[0].args.id === 33 &&
        direct[1].cmd === "tab_close" &&
        direct[1].args.id === 33,
      "click-to-switch or close lost its stable tab id after reorder: " +
        JSON.stringify(direct),
    );
  },
);

check("focused tab chips reorder with Left and Right arrow keys", async () => {
  fireChrome("tabs_changed", { items: tabItems([11, 22, 33], 22) });
  global.rbCalls.length = 0;
  global.rbResolve.tab_reorder = {
    ids: [11, 33, 22],
    items: tabItems([11, 33, 22], 22),
  };
  const active = tabChips().find((chip) => Number(chip.dataset.tabId) === 22);
  assert(
    active && active.getAttribute("tabindex") === "0" && active._has("keydown"),
    "tab chips are not focusable with a keyboard reorder handler",
  );
  active._fire("keydown", { key: "ArrowRight" });
  await flush();
  const calls = global.rbCalls.filter((call) => call.cmd === "tab_reorder");
  assert(
    calls.length === 1,
    "one arrow move sent " + calls.length + " reorders",
  );
  assert(
    calls[0].args.ids.join(",") === "11,33,22" && activeChipId() === 22,
    "ArrowRight did not persist the full order with active id 22",
  );
});

check("the toolbar exists and breaks onto a second row", () => {
  assert(headerAt !== -1, 'no <header id="toolbar"> in index.html');
  assert(headerEnd !== -1, "no </header> in index.html");
  assert(
    /class="toolbar-break"/.test(TOOLBAR_SRC),
    "the row break is missing, so the feature pills would crowd the right-hand " +
      "end of the address bar instead of wrapping underneath it",
  );
});

check("every feature control is in the toolbar", () => {
  for (const [id, what] of MUST_BE_VISIBLE) {
    assert(
      TOOLBAR_SRC.includes('id="' + id + '"'),
      "#" +
        id +
        " (" +
        what +
        ") is not in the toolbar. Every control is meant to be visible " +
        "without opening anything; a gate that only checked `.hidden` on the " +
        "element would not notice it had moved.",
    );
  }
});

// Which row each control belongs to, by subject: row one is the page in front
// of you, row two is the browser's standing state.
const ROW_ONE = ["btn-bookmark", "btn-quarantine-menu", "btn-about"];
const ROW_TWO = [
  "btn-privacy",
  "btn-freeze",
  "btn-tab",
  "btn-vault",
  "btn-dns",
  "btn-chat",
  "btn-library",
  // Conditional, unlike everything else on this row -- see the dedicated
  // check below. Pinned to row two anyway because "the browser's standing
  // state" is exactly what a saved password for this site is, and because it
  // must sit beside the vault it draws from rather than drifting up to row one.
  "btn-fill",
];

check("each control is on the row it belongs to", () => {
  const brk = TOOLBAR_SRC.indexOf('class="toolbar-break"');
  assert(brk !== -1, "the row break is missing");
  for (const id of ROW_ONE) {
    const at = TOOLBAR_SRC.indexOf('id="' + id + '"');
    assert(at !== -1, "#" + id + " is not in the toolbar");
    assert(
      at < brk,
      "#" +
        id +
        " is meant to be on row ONE -- the page in front of you -- but it is " +
        "written after the row break.",
    );
  }
  for (const id of ROW_TWO) {
    const at = TOOLBAR_SRC.indexOf('id="' + id + '"');
    assert(at !== -1, "#" + id + " is not in the toolbar");
    assert(
      at > brk,
      "#" +
        id +
        " is meant to be on row TWO -- the browser's standing state -- but " +
        "it is written before the row break.",
    );
  }
});

check("no stylesheet rule can move a control across the row break", () => {
  // THE CHECK ABOVE IS NOT ENOUGH ON ITS OWN, and this is why.
  //
  // `#btn-about` once carried `order: 99`, left over from the menu sheet where
  // About was pinned to the bottom of a flex COLUMN. Flex `order` reorders
  // across the entire container, so it dragged About past .toolbar-break onto
  // row two while the markup -- and therefore the check above -- said row one.
  // Moving the button in index.html looked like it had simply failed to work.
  //
  // Source order is the only thing that decides rows now, so `order` must not
  // reappear. If a future layout genuinely needs it, this gate is the thing to
  // change deliberately, with the row check taught to account for it.
  //
  // The sidebar layout was that future layout, and it did NOT need it: the
  // buttons are moved in the DOM rather than reordered in CSS, which is why
  // the ban still stands and why the checks below can assert on parentage.
  const css = fs
    .readFileSync(path.join(chromeDir, "chrome.css"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  const hit = /(^|[;{\s])order\s*:/.exec(css);
  assert(
    !hit,
    "chrome.css sets `order`, which silently overrides the markup order this " +
      "layout depends on -- a control can be written on row one and render on " +
      "row two with nothing to show for it.",
  );
});

// ---- the toolbar can move to the left edge, and come back ----------------
//
// The property this layout is FOR is that moving the toolbar moves the SAME
// buttons -- not copies. A second markup copy of the row would satisfy every
// check above (each id still exists, each still has a handler) while giving
// the browser two #btn-vault elements, one of which is wired and one of
// which is not. So these assert parentage, and that the trip back is exact.

check("every accent swatch names its colour to a screen reader", () => {
  // THE NAMES ARE GREEK, AND A NAME IS NOT A COLOUR.
  //
  // The nine accents are labelled Ion, Sardonyx, Aether and so on. That is
  // a deliberate choice about how a palette reads, and it costs something
  // real: "Chloris" tells a reader who does not know the word nothing about
  // what they are about to pick. The plain colour therefore has to survive
  // somewhere, for everyone.
  //
  // `title` alone does NOT do it, which is the trap this check exists for.
  // It is the last resort in the accessible name computation, used only
  // when nothing else names the element -- and these buttons have text
  // content, so the name is the Greek word and the tooltip is at most a
  // description most screen readers skip. A keyboard-only user never gets
  // it at all. Against the build before the rename, whose accessible name
  // was "Lavender", relying on `title` was a regression.
  //
  // So both attributes are required, and each must carry a plain colour
  // word. A rename that forgets this fails here rather than shipping.
  const COLOUR_WORDS = [
    "blue",
    "violet",
    "red",
    "green",
    "amber",
    "teal",
    "gray",
    "purple",
  ];
  const swatches = [
    ...html.matchAll(/<button\b([^>]*\bclass="[^"]*theme-swatch[^"]*"[^>]*)>/g),
  ];
  assert(
    swatches.length === 9,
    "expected nine accent swatches, found " + swatches.length,
  );
  for (const [, attrs] of swatches) {
    const id = (attrs.match(/id="([a-z0-9_-]+)"/) || [])[1] || "(no id)";
    const aria = (attrs.match(/aria-label="([^"]*)"/) || [])[1];
    const title = (attrs.match(/title="([^"]*)"/) || [])[1];
    assert(
      aria,
      "#" +
        id +
        " has no aria-label. Its accessible name is then the Greek " +
        "word alone, and the colour it picks is unreachable without a mouse.",
    );
    assert(
      title,
      "#" + id + " has no title, so a hovering reader gets no plain colour",
    );
    for (const [what, value] of [
      ["aria-label", aria],
      ["title", title],
    ]) {
      assert(
        COLOUR_WORDS.some((w) => value.toLowerCase().includes(w)),
        "#" +
          id +
          "'s " +
          what +
          " (" +
          JSON.stringify(value) +
          ") names no " +
          "plain colour. The label is a proper noun; if neither attribute " +
          "says what colour it is, nothing does.",
      );
    }
  }
});

check("the sidebar exists, is empty, and starts hidden", () => {
  const rail = html.indexOf('<nav id="sidebar"');
  assert(rail !== -1, "there is no #sidebar for the toolbar to move into");
  assert(
    rail > TOOLBAR_AT,
    "#sidebar must come after #toolbar in the markup: the buttons are moved " +
      "into it at runtime, and a container written first would be the one a " +
      "reader assumes owns them.",
  );
  const tag = html.slice(rail, html.indexOf(">", rail) + 1);
  assert(
    / hidden/.test(tag),
    "#sidebar must start hidden: the default layout is Top, and an empty " +
      "56px strip down the left of every fresh install is not it.",
  );
  assert(
    /aria-label="/.test(tag),
    "#sidebar is a nav and needs a label: in the left layout it IS the " +
      "toolbar, and a screen reader arriving at an unlabelled group of " +
      "icon-only buttons has been told nothing.",
  );
  const inner = html.slice(
    html.indexOf(">", rail) + 1,
    html.indexOf("</nav>", rail),
  );
  assert(
    inner.trim() === "",
    "#sidebar must be EMPTY in the markup. Anything written here is a second " +
      "copy of a control that already exists in #toolbar, and only one of the " +
      "two can be the one chrome.js wired.",
  );
});

for (const side of ["left", "right"]) {
  check(
    "choosing " + side + " moves every second-row control into the sidebar",
    async () => {
      await wear(side);
      const rail = global.$("sidebar");
      const bar = global.$("toolbar");
      assert(!rail.hidden, "the sidebar is still hidden after choosing Left");
      for (const id of ROW_TWO) {
        const el = global.$(id);
        assert(
          el.parentNode === rail,
          "#" +
            id +
            " stayed in the toolbar when the toolbar moved left. In that " +
            "layout the top strip is not where a feature button is looked for, " +
            "and a control drawn outside the chrome's own bounds is not drawn.",
        );
      }
      // The two that arrive late, appended by update.js and integrity.js after
      // the placement may already have been worn.
      for (const id of ["btn-integrity", "btn-update"]) {
        const el = global.$(id);
        if (!el || !el.parentNode) continue;
        assert(
          el.parentNode === rail,
          "#" +
            id +
            " is appended to #toolbar at runtime and was not swept into " +
            "the sidebar. It would render in a container the layout does not show.",
        );
      }
      for (const id of ROW_ONE) {
        assert(
          global.$(id).parentNode === bar,
          "#" +
            id +
            " moved to the sidebar. Row one acts on the page in front of " +
            "you and stays with the address bar in both layouts.",
        );
      }
    },
  );
}

check(
  "choosing either Top placement puts them back in source order",
  async () => {
    const bar = global.$("toolbar");
    const rail = global.$("sidebar");
    // Snapshot from the TOP layout: the previous check left the buttons in the
    // sidebar, and comparing a full row against a half one proves nothing.
    await wear("top_left");
    const before = bar.children.map((c) => c.id).join(",");
    await wear("left");
    // SCRAMBLE THE RAIL before coming back, and this is the part that earns
    // the check.
    //
    // Restoring by appending whatever the rail currently holds gives the right
    // answer as long as the rail's order happens to equal the markup's -- which
    // it does on a first trip, so a gate that only went left-and-back would
    // pass against an implementation with no notion of source order at all.
    // update.js and integrity.js append at runtime and are swept in whenever
    // they arrive, so "the rail's order" is not a thing that can be relied on.
    // Moving one button to the front is the cheapest way to make the two
    // orders genuinely disagree.
    if (rail.children.length > 1) {
      rail.insertBefore(
        rail.children[rail.children.length - 1],
        rail.children[0],
      );
    }
    await wear("top_right");
    const after = bar.children.map((c) => c.id).join(",");
    assert(
      global.$("sidebar").hidden,
      "the sidebar is still showing after choosing Top Right",
    );
    assert(
      global.$("sidebar").children.length === 0,
      "the sidebar still holds controls after choosing Top: they are in a " +
        "hidden container, which is the disclosure this whole gate exists to " +
        "forbid.",
    );
    assert(
      after === before,
      "the row came back in a different order than it went out.\n      was: " +
        before +
        "\n      now: " +
        after,
    );
  },
);

check("all four layouts report symmetric insets to Rust", async () => {
  for (const [placement, wantLeft, wantRight] of [
    ["top_left", false, false],
    ["top_right", false, false],
    ["left", true, false],
    ["right", false, true],
  ]) {
    global.rbCalls.length = 0;
    await wear(placement);
    const insets = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
    assert(insets.length > 0, placement + " reported no insets to Rust");
    const last = insets[insets.length - 1].args;
    assert(
      typeof last.top === "number" &&
        typeof last.left === "number" &&
        typeof last.right === "number",
      "all three insets must be numbers for " +
        placement +
        ": " +
        JSON.stringify(last),
    );
    assert(
      last.left > 0 === wantLeft && last.right > 0 === wantRight,
      placement + " sent the wrong side insets: " + JSON.stringify(last),
    );
  }
});

check("the stylesheet is told what Rust was told", async () => {
  // Compared against the PAYLOAD, not checked for being set. Rust and the
  // stylesheet are told from separate measurements: syncChromeInsets sends
  // its own `left` and `right` locals, while publishChromeMetric calls
  // closedChromeLeftPx/RightPx again for --chrome-left-px/--chrome-right-px.
  // Each side can look plausible alone while the two disagree. This used to
  // assert only zero or non-zero on the variables, so with Rust sent right:0
  // and the stylesheet 56px (PATANYX_TOOLBAR_OMIT_RIGHT_INSET) it passed.
  // Which sides SHOULD be non-zero is the check above; this one is agreement.
  //
  // The log is cleared before each wear so the payload read is that wear's,
  // and --chrome-height-px is written after the send from the same `top`.
  const vars = global.document.documentElement.style;
  for (const placement of ["left", "right", "top_left", "top_right"]) {
    global.rbCalls.length = 0;
    await wear(placement);
    const insets = global.rbCalls.filter((c) => c.cmd === "set_chrome_insets");
    assert(insets.length > 0, placement + " reported no insets to Rust");
    const sent = insets[insets.length - 1].args;
    for (const [arg, name] of [
      ["left", "--chrome-left-px"],
      ["right", "--chrome-right-px"],
      ["top", "--chrome-height-px"],
    ]) {
      const told = vars.getPropertyValue(name);
      assert(
        /^\d+px$/.test(told) && parseInt(told, 10) === sent[arg],
        placement +
          ": " +
          name +
          " is " +
          JSON.stringify(told) +
          " but Rust was sent " +
          arg +
          ": " +
          JSON.stringify(sent[arg]) +
          ". Banners, the find bar and panels are laid out from the " +
          "stylesheet's number and the page from Rust's, so a mismatch draws " +
          "one underneath the other.",
      );
    }
  }
});

check("CSS gives all four placements distinct, mirrored geometry", () => {
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  assert(
    /#toolbar\s*\{[\s\S]*?justify-content:\s*flex-start/.test(css) &&
      /data-toolbar-placement="top_right"[\s\S]*?#toolbar\s*\{[\s\S]*?justify-content:\s*flex-end/.test(
        css,
      ),
    "Top Left and Top Right do not align the feature row to opposite ends",
  );
  assert(
    /data-toolbar-placement="left"[^}]*#sidebar[\s\S]*?left:\s*0[\s\S]*?border-right/.test(
      css,
    ) &&
      /data-toolbar-placement="right"[^}]*#sidebar[\s\S]*?right:\s*0[\s\S]*?border-left/.test(
        css,
      ) &&
      css.includes("margin-left: var(--chrome-left-px") &&
      css.includes("margin-right: var(--chrome-right-px"),
    "Left and Right do not mirror rail borders and chrome-flow margins",
  );
  // Whitespace-flattened: the prose is pinned by wording, not by however the
  // formatter happens to wrap it across lines.
  const htmlFlat = html.replace(/\s+/g, " ");
  // THE TOP-STRIP PROMISE WAS REMOVED FROM THE PANEL, 2026-08-27, because
  // the Theme modal now carries titles and control labels only,
  // no prose at all. This assertion used to require the sentence "Tabs and
  // the address bar stay at the top in every arrangement." and it is dropped
  // rather than quietly left passing on something else.
  //
  // What that sentence did: the four placements move the FEATURE buttons and
  // not the tabs or address bar, so a reader choosing Left could expect the
  // whole strip to follow. The panel no longer says otherwise. If that turns
  // out to confuse people on hardware, the fix is to restore the sentence and
  // this assertion together, not to reword the buttons.
  //
  // The placement NAMES are still gated, because those are what the CSS
  // assertions above are checked against.
  assert(
    htmlFlat.includes("Top Left") && htmlFlat.includes("Top Right"),
    "the panel does not offer/name all four placements",
  );
});

check(
  "labels gray live only in side strips and keep their stored choice",
  async () => {
    global.rbResolve.toolbar_labels_set = { mode: "hide" };
    global.$("labels-hide")._fire("click");
    await flush();
    assert(
      global.document.documentElement.dataset.toolbarLabels === "hide",
      "setup did not wear the hidden-label preference",
    );
    const setsBefore = global.rbCalls.filter(
      (c) => c.cmd === "toolbar_labels_set",
    ).length;
    for (const side of ["left", "right"]) {
      await wear(side);
      assert(
        global.$("labels-show").disabled && global.$("labels-hide").disabled,
        side + " did not disable the labels choice",
      );
        // The reason moved from a paragraph onto the buttons themselves,
        // 2026-08-27: the Theme modal was cut back to titles and
        // control labels only. What must not be lost is that a DISABLED
        // control still says WHY, so this checks the hover title rather than a
        // note element. Dropping the assertion instead would have left two
        // greyed-out buttons with no explanation anywhere in the product.
        assert(
          /id="labels-show"[\s\S]{0,240}?The left and right strips show icons only\./.test(
            html,
          ) &&
            /id="labels-hide"[\s\S]{0,240}?The left and right strips show icons only\./.test(
              html,
            ),
          side + " did not give the disabled choice a reason on hover",
        );
    }
    for (const top of ["top_left", "top_right"]) {
      await wear(top);
      assert(
        !global.$("labels-show").disabled && !global.$("labels-hide").disabled,
        top + " did not re-enable the labels choice",
      );
        // The counterpart assertion is gone with the note it checked: a
        // hover title is always present rather than shown and hidden, so
        // there is nothing here to leave showing. The re-enable check above
        // is what still matters for the top placements.
    }
    assert(
      global.document.documentElement.dataset.toolbarLabels === "hide" &&
        global.rbCalls.filter((c) => c.cmd === "toolbar_labels_set").length ===
          setsBefore,
      "a side-to-top round trip mutated the stored label choice",
    );
  },
);

check(
  "the privacy receipt explains the session count including closed tabs",
  async () => {
    global.rbResolve.privacy_receipt = {
      counts_blocked: true,
      session_blocked: 7,
      page_blocked: 2,
    };
    global.$("btn-tab")._fire("click");
    await flush();
    assert(
      global.$("receipt-session-caption").textContent ===
        "Refused by the blocker since the browser was launched, counted across every tab, including tabs you have since closed.",
      "the session receipt caption is absent or changed",
    );
  },
);

check("nothing can hide a control behind a disclosure", () => {
  // The property that actually matters, and the reason the previous version of
  // this file existed. "Every control is in the toolbar" would stay true if
  // somebody nested a sheet inside the toolbar and filled it.
  for (const [id, what] of [
    ["menu-sheet", "an overflow sheet"],
    ["btn-menu", "a hamburger"],
  ]) {
    assert(
      !html.includes('id="' + id + '"'),
      "#" +
        id +
        " (" +
        what +
        ") is back in index.html. The layout exists so every control is " +
        "visible without opening anything -- if an overflow menu is genuinely " +
        "wanted again, this gate is the thing to change deliberately, not to " +
        "route around.",
    );
  }
  assert(
    !/class="[^"]*\bmenu-item\b/.test(html),
    "menu-item markup is back; the pills are toolbar buttons now",
  );
});

check("nothing in the toolbar is a button that does nothing", () => {
  for (const [id, what] of MUST_BE_VISIBLE) {
    // btn-chat is exempt HERE and nowhere else. This harness loads chrome.js
    // only, which is what a public build evaluates, and in that build the chat
    // button is correctly inert and correctly hidden -- chat.js binds it and
    // is compiled in for private builds only. The wired case is covered by
    // chat-ui-gate.js, which loads chat.js and fires this very button.
    if (id === "btn-chat") continue;
    const el = global.$(id);
    assert(el, "#" + id + " is not in the harness at all");
    const clicks = el._listeners && el._listeners.click;
    assert(
      clicks && clicks.length > 0,
      "#" +
        id +
        " (" +
        what +
        ") has no click handler. It renders, it highlights on hover, and it " +
        "does nothing when pressed -- the exact defect this chrome has " +
        "shipped more than once.",
    );
  }
});

// THE ONE CONDITIONAL CONTROL ON THE STRIP, AND WHY IT IS GATED SEPARATELY.
//
// #btn-fill is deliberately absent on most pages: it appears only when the
// vault is unlocked AND this exact site has a saved credential, because a
// permanently greyed ninth pill is noise. That makes it the one button on the
// toolbar whose CORRECT state is usually hidden -- so the every-control-is-
// visible checks above must not own it, and the failure it can suffer is the
// opposite of theirs.
//
// The defect this guards is a fill button that stays on screen after the offer
// stops being valid: navigate to another site, or lock the vault, and a button
// still offering to type a password into the page would be both wrong and
// alarming. `renderAutofillOffer` is the single writer for that, and it is
// reachable here because the harness evaluates chrome.js.
check(
  "the fill button is conditional, and hides when there is no offer",
  () => {
    const el = global.$("btn-fill");
    assert(el, "#btn-fill is not in the harness at all");

    assert(
      /id="btn-fill"[^>]*\shidden/s.test(TOOLBAR_SRC),
      "#btn-fill is not `hidden` in the markup, so it would be on screen from " +
        "the first paint -- before any tab status has said whether this site " +
        "even has a saved password.",
    );

    const clicks = el._listeners && el._listeners.click;
    assert(
      clicks && clicks.length > 0,
      "#btn-fill has no click handler: it would appear exactly when a password " +
        "is available and then do nothing when pressed.",
    );
  },
);

// A RUNTIME PANEL MUST NOT SET ITS OWN WIDTH OR POSITION.
//
// update.js, integrity.js and chat.js build their panels in JavaScript rather
// than in index.html, and chrome.js turns whichever panel opens into a centred
// card by adding `panel-modal`. That class sets
// `width: min(600px, 100vw - 32px)` and `position: fixed` -- and an INLINE
// style beats a class rule, so a single `width: "100%"` in the builder wins
// silently. integrity.js had exactly that, and its panel alone rendered as a
// full-width band across the window while every other panel was a card. It
// read as a browser layout bug and was one line of specificity.
check("runtime-built panels do not inline-override panel-modal", () => {
  for (const file of ["update.js", "integrity.js", "chat.js"]) {
    const full = path.join(chromeDir, file);
    if (!fs.existsSync(full)) continue;
    const src = fs.readFileSync(full, "utf8");
    // The window has to cover BOTH shapes these files use, or it reads the
    // wrong styles: integrity.js styles the element as it creates it
    // (`var panel = sty(el("div"), {...})`), update.js creates it bare and
    // styles it AFTER setting the id (`setStyles(panel, {...})`). Scanning
    // only up to `panel.id` caught update.js's unrelated BUTTON styles and
    // reported a failure that was not there. Both files reach `panel.hidden`
    // once the element is fully built, so that is the honest end marker.
    const end = src.indexOf("panel.hidden");
    if (end === -1) continue;
    const first = src.search(/\bpanel\s*=|\bvar panel\b/);
    if (first === -1 || first > end) continue;
    const decl = src.slice(first, end);
    for (const prop of ["width", "position", "left", "top", "transform"]) {
      assert(
        !new RegExp("\\b" + prop + ":\\s*[\"']").test(decl),
        file +
          " sets `" +
          prop +
          "` inline on its panel element. Inline styles beat `.panel-modal`, " +
          "so this panel will not be a centred card while every other one is.",
      );
    }
  }
});

// EVERY BANNER MUST BE MEASURED, OR IT IS INVISIBLE WHEN IT MATTERS.
//
// The chrome webview is a child window clipped to its bounds. `syncChromeHeight`
// grows those bounds by the height of each visible banner in its `BANNERS`
// list -- and a banner missing from that list therefore renders OUTSIDE the
// strip and cannot be seen at all.
//
// `lock-warning` was missing. The vault's "about to lock" warning, the one
// banner with a deadline and a button, was invisible for precisely as long as
// it was relevant. It appeared only while a modal was open -- Overlay mode
// makes the chrome cover the window, so there is suddenly room below the
// toolbar -- which is what disguised it as a modal bug rather than a
// measurement one.
//
// Keyed on role=alert/status because that is what every banner in this file
// already carries, and a new one will carry it too -- plus role=search, which
// is the find bar. It sits in the same band under the toolbar and is clipped
// by the same rule, and it was NOT in BANNERS: with the toolbar across the top
// the 148px floor happened to leave enough slack for it, and with the toolbar
// down the left edge (strip measured tightly) it rendered under the page and
// Ctrl+F "did nothing". The `hidden` attribute is optional in the pattern
// only because the find bar carries it before the role.
check("every banner in the chrome is measured by syncChromeHeight", () => {
  const declared = [
    ...html.matchAll(
      /<div id="([a-z-]+)"(?: hidden)? role="(?:alert|status|search)"/g,
    ),
  ].map((m) => m[1]);
  assert(
    declared.includes("findbar"),
    "the find bar (#findbar, role=search) is no longer found by the sweep",
  );
  assert(
    declared.length >= 6,
    "found only " + declared.length + " banners; the pattern stopped matching",
  );
  const js = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
  const listed = js.slice(
    js.indexOf("const BANNERS"),
    js.indexOf("]", js.indexOf("const BANNERS")),
  );
  for (const id of declared) {
    assert(
      listed.includes('"' + id + '"'),
      "#" +
        id +
        " is a banner in index.html but is not in chrome.js's " +
        "BANNERS list. The strip will not grow for it, so it renders outside " +
        "the chrome's own window and is invisible -- except while a modal " +
        "happens to be open.",
    );
  }
});

check("the runtime-built buttons land in the toolbar", () => {
  for (const file of ["update.js", "integrity.js"]) {
    const src = fs.readFileSync(path.join(chromeDir, file), "utf8");
    assert(
      src.includes('getElementById("toolbar")'),
      file +
        " must append its button to #toolbar. Appending anywhere else puts " +
        "Updates or Integrity outside the row a user is looking at.",
    );
    assert(
      !/getElementById\("menu-sheet"\)/.test(src),
      file + " still looks up #menu-sheet, which no longer exists.",
    );
  }
});

check("a pill opens its panel, and Escape closes it", async () => {
  // START FROM CLOSED, whatever the checks above left open.
  //
  // This asserts that a press OPENS, and a press is a toggle -- so arriving
  // with the vault already open turned the check into "a press closes it",
  // which failed for a reason that had nothing to do with the property under
  // test. It passed for a long time on the accident that the preceding
  // checks happened to leave a different panel open; adding checks above
  // changed which one, and the accident stopped holding.
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  assert(
    global.$("vault-panel").hidden === true,
    "the vault panel is still open after Escape, so this check cannot tell " +
      "an open from a toggle",
  );
  // The pills reach the panels directly now that nothing sits between them.
  global.$("btn-vault")._fire("click");
  await flush();
  assert(
    global.$("vault-panel").hidden === false,
    "pressing a toolbar pill must open its panel",
  );
  global.fireDocument("keydown", { key: "Escape" });
  await flush();
  assert(
    global.$("vault-panel").hidden === true,
    "Escape must dismiss the panel. Assertable only because the DOM harness " +
      "records document-level listeners; it used to drop them, which is why " +
      "no gate had ever checked a dismissal path.",
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
    console.error("\nTOOLBAR GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nTOOLBAR UI OK");
})();
