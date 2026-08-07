// Behavioural checks on the tunnel panel and the fail-closed banner, run
// against the DOM harness so chrome.js is EXECUTED rather than parsed.
// Modelled on scripts/dns-ui-gate.js.
//
// WHY THIS EXISTS. The tunnel UI repeats three defect classes this suite has
// shipped before: a picker whose active class had no css rule (all choices
// rendered identically), a banner missing from BANNERS (rendered outside the
// clipped strip, invisible), and one setting worded two ways by two surfaces.
// It adds one of its own: the fail-closed banner must not flash during the
// normal startup unlock, when the parked listener reads as not carrying
// traffic -- so the banner needs TWO consecutive failed readings, and that
// number is checked here.
//
// Run: node scripts/tunnel-ui-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
// The harness answers IPC on the next tick exactly as Rust does, and a
// refresh is a CHAIN, so each step must be drained before its effect is
// observable.
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// The two describes are deliberately different in the stub: a panel showing
// the same copy for both choices, or copy that did not come from the reply,
// fails the first check below.
const OFF_COPY = "Engine copy for Off: direct browsing.";
const IMPORTED_COPY = "Engine copy for Imported: through your server.";

function stubTunnel(overrides) {
  global.rbResolve = Object.assign(
    {
      tunnel_get: {
        mode: "off",
        describe_off: OFF_COPY,
        describe_imported: IMPORTED_COPY,
        has_config: false,
        report: "not_attempted",
        start_error: null,
      },
      // The real arm ECHOES the accepted mode, and the JS trusts the echo
      // (not its own request) -- so the stub must echo too. Checks that
      // click Off override this.
      tunnel_set_mode: { mode: "imported", restart_required: true },
      tunnel_status: { mode: "off", report: "not_attempted" },
      tunnel_import: { imported: true },
      tunnel_remove: {},
    },
    overrides || {},
  );
}

// Re-enters through a REAL path: the toolbar button runs the panel's
// registered open hook, which is how the app itself reaches refreshTunnel.
async function openTunnelPanel() {
  if (global.$("tunnel-panel").hidden === false) {
    global.$("btn-tunnel")._fire("click");
    await flush();
  }
  global.$("btn-tunnel")._fire("click");
  await flush();
}

// Drives the SAME entry point the engine's events use -- window.__rb_event,
// carrying the tab_status payload shape Rust pushes. The banner reads only
// the `tunnel` key; the other fields keep applyTabStatus's other readers
// fed so this gate does not depend on their tolerance for absence.
function sendTabStatus(tunnelState) {
  global.window.__rb_event({
    event: "tab_status",
    data: {
      freeze_phase: "loaded",
      freeze_enforcement: "inactive",
      profile: "persistent",
      tls: "secure",
      interception: "registered",
      script_setting: "applied",
      tunnel: tunnelState,
    },
  });
}

check(
  "each choice carries the engine's own copy, and the two differ",
  async () => {
    // Planted defect: one setting worded two ways by two surfaces -- the
    // copy retyped (or drifted) in HTML/JS instead of rendered from
    // tunnel_get.
    stubTunnel();
    await openTunnelPanel();
    assert(
      global.$("tunnelp-describe-off").textContent === OFF_COPY,
      "the Off copy must be tunnel_get's describe_off verbatim; got " +
        JSON.stringify(global.$("tunnelp-describe-off").textContent),
    );
    assert(
      global.$("tunnelp-describe-imported").textContent === IMPORTED_COPY,
      "the Imported copy must be tunnel_get's describe_imported verbatim; " +
        "got " +
        JSON.stringify(global.$("tunnelp-describe-imported").textContent),
    );
    assert(
      global.$("tunnelp-describe-off").textContent !==
        global.$("tunnelp-describe-imported").textContent,
      "the two choices rendered the SAME copy; a two-way choice whose " +
        "options read identically is a coin flip",
    );
  },
);

check("the describe copy is not retyped in index.html", () => {
  // Planted defect: the same one, committed in the markup instead -- the
  // engine's describe() text has no business being spelled out in HTML.
  const html = fs
    .readFileSync(path.join(chromeDir, "index.html"), "utf8")
    .replace(/\s+/g, " ");
  const panel = html.slice(
    html.indexOf('id="tunnel-panel"'),
    html.indexOf("</section>", html.indexOf('id="tunnel-panel"')),
  );
  assert(
    !/goes direct|WireGuard server you imported|anonymity tool/i.test(panel),
    "the tunnel-panel markup contains describe() phrasing; that copy's only " +
      "source is TunnelMode::describe, delivered by tunnel_get",
  );
});

check("the mode in force is marked, and only it", async () => {
  // Planted defect: a picker that marks nothing, or everything -- the user
  // cannot read back which choice is in force.
  stubTunnel();
  await openTunnelPanel();
  assert(
    global.$("tunnelp-off").classList.contains("active") &&
      !global.$("tunnelp-imported").classList.contains("active"),
    "mode off must mark Off and only Off",
  );
  stubTunnel({
    tunnel_get: {
      mode: "imported",
      describe_off: OFF_COPY,
      describe_imported: IMPORTED_COPY,
      has_config: true,
      report: "applied",
      start_error: null,
    },
  });
  await openTunnelPanel();
  assert(
    global.$("tunnelp-imported").classList.contains("active") &&
      !global.$("tunnelp-off").classList.contains("active"),
    "mode imported must mark Imported and only Imported",
  );
});

check(
  "a pending restart is shown on a plain open, not only after a click",
  async () => {
    // THE DEFECT HARDWARE TESTING HIT. The note used to be set as a
    // reaction to clicking a mode button and nowhere else, so closing the
    // panel and reopening it lost the note while the restart stayed exactly
    // as pending -- the browser went on tunnelling with nothing on screen
    // saying the setting they were looking at was not in force. The engine
    // knows this fact; the panel must render it on every open.
    stubTunnel({
      tunnel_get: {
        mode: "off",
        describe_off: OFF_COPY,
        describe_imported: IMPORTED_COPY,
        has_config: true,
        report: "applied",
        start_error: null,
        restart_pending: true,
      },
    });
    await openTunnelPanel();
    const note = global.$("tunnelp-restart");
    assert(
      note.hidden === false,
      "a restart pending at open time must be shown without any click",
    );
    assert(
      /not in effect/i.test(note.textContent),
      "the note must lead with the setting not being live; got " +
        JSON.stringify(note.textContent),
    );
    // And it must CLEAR when the engine says nothing is pending -- a note
    // that cannot go away is one the user learns to ignore.
    stubTunnel({
      tunnel_get: {
        mode: "off",
        describe_off: OFF_COPY,
        describe_imported: IMPORTED_COPY,
        has_config: true,
        report: "not_attempted",
        start_error: null,
        restart_pending: false,
      },
    });
    await openTunnelPanel();
    assert(
      global.$("tunnelp-restart").hidden === true,
      "with no restart pending the note must clear itself",
    );
  },
);

check(
  "choosing Imported sends tunnel_set_mode and shows the restart note",
  async () => {
    // Planted defect: a mode change the user believes is already live
    // because nothing said restart. The engine reports the change as
    // pending (the mode now differs from the one it booted with), and the
    // panel must render that after the click without being told twice.
    stubTunnel({
      tunnel_get: {
        mode: "off",
        describe_off: OFF_COPY,
        describe_imported: IMPORTED_COPY,
        has_config: true,
        report: "not_attempted",
        start_error: null,
        restart_pending: true,
      },
    });
    await openTunnelPanel();
    assert(
      global.$("tunnelp-off").classList.contains("active"),
      "precondition: Off is the mode in force before the click",
    );
    // The panel re-asks the engine after a change (that is what makes the
    // note able to CLEAR), so the stub has to answer the way the engine
    // would once prefs are saved: the new mode, with the restart pending.
    // A stub frozen on the old mode would have the panel correctly render
    // a state the real engine never returns.
    stubTunnel({
      tunnel_get: {
        mode: "imported",
        describe_off: OFF_COPY,
        describe_imported: IMPORTED_COPY,
        has_config: true,
        report: "not_attempted",
        start_error: null,
        restart_pending: true,
      },
    });
    global.rbCalls.length = 0;
    global.$("tunnelp-imported")._fire("click");
    await flush();
    const sent = global.rbCalls.filter((c) => c.cmd === "tunnel_set_mode");
    assert(
      sent.length === 1 && sent[0].args && sent[0].args.mode === "imported",
      "clicking Imported must send exactly one tunnel_set_mode for " +
        "imported; got " +
        JSON.stringify(sent),
    );
    const note = global.$("tunnelp-restart");
    assert(
      note.hidden === false && /not in effect/i.test(note.textContent),
      "the restart note must be visible after an accepted change; got " +
        "hidden=" +
        note.hidden +
        " text=" +
        JSON.stringify(note.textContent),
    );
    assert(
      global.$("tunnelp-imported").classList.contains("active"),
      "and the new choice must be marked after the engine accepted it",
    );
  },
);

check("choosing Off sends off, not a hardcoded mode", async () => {
  // Planted defect: both buttons sending the same mode.
  stubTunnel({
    tunnel_get: {
      mode: "imported",
      describe_off: OFF_COPY,
      describe_imported: IMPORTED_COPY,
      has_config: true,
      report: "applied",
      start_error: null,
    },
    tunnel_set_mode: { mode: "off", restart_required: true },
  });
  await openTunnelPanel();
  global.rbCalls.length = 0;
  global.$("tunnelp-off")._fire("click");
  await flush();
  const sent = global.rbCalls.filter((c) => c.cmd === "tunnel_set_mode");
  assert(
    sent.length === 1 && sent[0].args && sent[0].args.mode === "off",
    'clicking Off must send tunnel_set_mode for "off"; got ' +
      JSON.stringify(sent),
  );
});

check("the class the JS marks the choice with is styled for THIS panel", () => {
  // Planted defect: THE dns-gate defect -- chrome.js sets a class,
  // chrome.css never styles it, each file individually correct, all choices
  // identical.
  const css = fs
    .readFileSync(path.join(chromeDir, "chrome.css"), "utf8")
    .replace(/\s+/g, " ");
  assert(
    /#tunnel-panel button\.small\.active\s*\{/.test(css),
    "chrome.js marks the chosen mode with `active` on a button.small inside " +
      "#tunnel-panel. Without a scoped matching rule in chrome.css both " +
      "choices render identically -- which is how the resolver picker " +
      "originally shipped",
  );
});

check("the import button sends tunnel_import", async () => {
  // Planted defect: a button that looks like it imports but sends nothing
  // -- or a different command.
  stubTunnel();
  await openTunnelPanel();
  global.rbCalls.length = 0;
  global.$("tunnelp-import")._fire("click");
  await flush();
  const sent = global.rbCalls.filter((c) => c.cmd === "tunnel_import");
  assert(
    sent.length === 1,
    "the import button must send exactly one tunnel_import; got " +
      JSON.stringify(sent),
  );
});

check("a refused import shows the engine's refusal text verbatim", async () => {
  // Planted defect: a swallowed parse error -- the user clicks Import, the
  // config is refused, and the panel says nothing, reading as success. The
  // refusal rides the SUCCESS payload (the IPC error channel is static
  // codes only), and ConfigError's Display texts are the ONLY vocabulary --
  // key-free by design, so the panel may and must show them.
  stubTunnel({
    tunnel_import: {
      imported: false,
      error: "the configuration has no [Peer] section",
    },
  });
  await openTunnelPanel();
  global.$("tunnelp-import")._fire("click");
  await flush();
  const err = global.$("tunnelp-error");
  assert(
    err.hidden === false &&
      err.textContent.includes("the configuration has no [Peer] section"),
    "the refused import must surface the engine's refusal text; got " +
      "hidden=" +
      err.hidden +
      " text=" +
      JSON.stringify(err.textContent),
  );
});

check("the remove button sends tunnel_remove", async () => {
  // Planted defect: a dead Remove -- the config stays in the vault while
  // the user believes it gone.
  stubTunnel({
    tunnel_get: {
      mode: "imported",
      describe_off: OFF_COPY,
      describe_imported: IMPORTED_COPY,
      has_config: true,
      report: "applied",
      start_error: null,
      // Removing sets the mode Off while the tunnel keeps carrying this
      // session's traffic, so the engine reports a pending restart.
      restart_pending: true,
    },
  });
  await openTunnelPanel();
  global.rbCalls.length = 0;
  global.$("tunnelp-remove")._fire("click");
  await flush();
  const sent = global.rbCalls.filter((c) => c.cmd === "tunnel_remove");
  assert(
    sent.length === 1,
    "the remove button must send exactly one tunnel_remove; got " +
      JSON.stringify(sent),
  );
  // Removal is a mode change (the engine flips the mode to Off with it),
  // and the running tunnel keeps carrying traffic until restart -- so the
  // restart note is owed here exactly as after the mode buttons.
  const note = global.$("tunnelp-restart");
  assert(
    note.hidden === false && /not in effect/i.test(note.textContent),
    "removing the config must show the restart note; got hidden=" + note.hidden,
  );
});

check("a locked vault reads as unlock-to-see, never as null", async () => {
  // Planted defect: has_config null rendered literally -- "null" on screen,
  // or a blank line where the panel should admit it cannot know.
  stubTunnel({
    tunnel_get: {
      mode: "off",
      describe_off: OFF_COPY,
      describe_imported: IMPORTED_COPY,
      has_config: null,
      report: "not_attempted",
      start_error: null,
    },
  });
  await openTunnelPanel();
  const line = global.$("tunnelp-config").textContent;
  assert(
    /unlock/i.test(line) && !/null|undefined/.test(line),
    "a locked vault must be presented as unlock-to-see; got " +
      JSON.stringify(line),
  );
});

// The banner is gated on ELAPSED TIME, so these checks must control the
// clock. Driving it by event count is what the first version did, and it
// certified a property production did not have: one navigation emits
// tab_status three times, so a count-based rule fired during the ordinary
// pre-unlock window it was written to survive.
let fakeNow = null;
const REAL_NOW = Date.now;
function withClock(startMs) {
  fakeNow = startMs;
  Date.now = () => fakeNow;
}
function advance(ms) {
  fakeNow += ms;
}
function realClock() {
  Date.now = REAL_NOW;
  fakeNow = null;
}

check(
  "a failure must LAST before the banner appears, and clears on applied",
  async () => {
    // Planted defects, three of them. (1) Showing on the first failed
    // reading: before the vault unlocks the listener is parked and reads
    // as not-carrying-traffic, so an eager banner flashes on every boot.
    // (2) Counting events instead of time: a single navigation emits three
    // tab_status updates, so any small count is reached instantly during
    // that same parked window. (3) Never clearing: a banner that stays up
    // after the tunnel recovers teaches the user to ignore it.
    stubTunnel({
      tunnel_get: {
        mode: "imported",
        describe_off: OFF_COPY,
        describe_imported: IMPORTED_COPY,
        has_config: true,
        report: "failed",
        start_error: null,
      },
    });
    withClock(1_000_000);
    try {
      await openTunnelPanel(); // learns mode imported, clock unstarted
      const banner = global.$("tunnel-warning");
      assert(
        banner.hidden === true,
        "precondition: no banner before any reading",
      );
      // The burst a single real navigation produces: three tab_status
      // updates in the same instant. A count-based rule shows the banner
      // here; a time-based one must not.
      sendTabStatus("failed");
      await flush();
      sendTabStatus("failed");
      await flush();
      sendTabStatus("failed");
      await flush();
      assert(
        banner.hidden === true,
        "three failed readings in the SAME instant are one navigation's " +
          "burst during the pre-unlock parked window; the banner must not " +
          "flash on it",
      );
      // The same failure, still there a quarter-minute later.
      advance(16000);
      sendTabStatus("failed");
      await flush();
      assert(
        banner.hidden === false,
        "a failure that has lasted past the grace period is a tunnel down " +
          "in force; the fail-closed banner must be up",
      );
      sendTabStatus("applied");
      await flush();
      assert(
        banner.hidden === true,
        "an applied reading means the tunnel carries traffic again; the " +
          "banner must come down",
      );
      // And the clock restarts: a new failure run does not inherit the old
      // run's age.
      sendTabStatus("failed");
      await flush();
      assert(
        banner.hidden === true,
        "a NEW failure run must serve its own grace period, not inherit " +
          "the elapsed time of the run that already cleared",
      );
    } finally {
      realClock();
    }
  },
);

check(
  "the banner stays down in mode Off however many readings fail",
  async () => {
    // Planted defect: a banner that ignores the mode -- fail-closed copy
    // shown to a user who never switched the tunnel on.
    withClock(2_000_000);
    try {
      stubTunnel();
      await openTunnelPanel(); // mode off
      sendTabStatus("failed");
      await flush();
      advance(60000); // long past any grace period
      sendTabStatus("failed");
      await flush();
      assert(
        global.$("tunnel-warning").hidden === true,
        "mode Off means there is no tunnel to fail; the banner must stay " +
          "down however long the readings say failed",
      );
    } finally {
      realClock();
    }
  },
);

check("the banner states the fail-closed promise, never a fallback", () => {
  // Planted defect: banner copy implying the browser will fall back to a
  // direct connection. Fail-closed is the product promise.
  const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
  const start = html.indexOf('id="tunnel-warning-body"');
  const body = html
    .slice(start, html.indexOf("</span>", start))
    .replace(/\s+/g, " ");
  assert(
    /NOT fall back/.test(body),
    "the banner must state there is no fallback; got " + JSON.stringify(body),
  );
});

check("the banner is in chrome.js's BANNERS list", () => {
  // Planted defect: the lock-warning defect -- a banner missing from
  // BANNERS renders OUTSIDE the clipped strip and is invisible for exactly
  // as long as it matters.
  const src = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
  const start = src.indexOf("const BANNERS");
  assert(start !== -1, "the BANNERS list is gone from chrome.js");
  const list = src.slice(start, src.indexOf("];", start));
  assert(
    /"tunnel-warning"/.test(list),
    "tunnel-warning is not in BANNERS, so syncChromeHeight will never make " +
      "room for it and it renders outside the visible strip",
  );
});

check("the banner's button opens the real tunnel panel", async () => {
  // Planted defect: a button wired to an id that does not exist, or to a
  // copy of the panel-opening logic that has since drifted from the real
  // one. The wiring is the real btn-tunnel click; this drives the banner
  // button and asserts the panel actually opened.
  stubTunnel({
    tunnel_get: {
      mode: "imported",
      describe_off: OFF_COPY,
      describe_imported: IMPORTED_COPY,
      has_config: true,
      report: "failed",
      start_error: null,
    },
  });
  withClock(3_000_000);
  await openTunnelPanel();
  sendTabStatus("failed");
  await flush();
  advance(16000); // past the grace period, so the banner is genuinely up
  sendTabStatus("failed");
  await flush();
  assert(
    global.$("tunnel-warning").hidden === false,
    "precondition: banner up",
  );
  realClock();
  // Close the panel first so "opened by the banner button" is observable.
  global.$("btn-tunnel")._fire("click");
  await flush();
  assert(
    global.$("tunnel-panel").hidden === true,
    "precondition: panel closed",
  );
  global.$("tunnel-warning-open")._fire("click");
  await flush();
  assert(
    global.$("tunnel-panel").hidden === false,
    "the banner's button must open the tunnel panel through the real " +
      "btn-tunnel wiring",
  );
});

check("the toolbar panel has somewhere to be drawn", () => {
  // Planted defect: the panel manager unhides #tunnel-panel; with no rule
  // for it the panel has no background, padding or scrolling and lands on
  // top of the page. Asserted against the SHARED panel selector list (the
  // one #vault-panel opens), not against any occurrence of the selector:
  // the active-choice rule below also names #tunnel-panel, and matching it
  // here would make this check vacuous (the independent review caught
  // exactly that).
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  const shared = css.indexOf("#vault-panel");
  assert(shared !== -1, "the shared panel rule is gone from chrome.css");
  const selectors = css.slice(shared, css.indexOf("{", shared));
  assert(
    selectors.includes("#tunnel-panel"),
    "#tunnel-panel is not in the SHARED panel rule, so it has no " +
      "background, padding or scrolling -- the exact defect that shipped " +
      "as the transparent update panel",
  );
});

check("the command palette can open the tunnel panel", () => {
  // Planted defect: palette drift -- a panel reachable only by those who
  // already know where the button is.
  const src = fs
    .readFileSync(path.join(chromeDir, "chrome.js"), "utf8")
    .replace(/\s+/g, " ");
  assert(
    /label:\s*"Open Tunnel",\s*buttonId:\s*"btn-tunnel"/.test(src),
    'PALETTE_ACTIONS needs { label: "Open Tunnel", buttonId: "btn-tunnel" }',
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL " + name + " - " + e.message);
    }
  }
  if (failures.length) {
    console.error("\nTUNNEL UI GATE FAILED:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nTUNNEL UI OK");
})();
