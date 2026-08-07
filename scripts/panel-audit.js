// Panel-by-panel audit: every interactive control in the chrome, and whether
// anything is listening to it.
//
// WHY THIS EXISTS. Four forms once shipped with markup, backend commands and
// working file pickers, and no submit listener -- they rendered, accepted
// input, and did nothing. chrome-js-gate gate 3 now covers FORMS. Nothing
// covers BUTTONS and CHECKBOXES, which are most of the chrome, and the same
// defect in a button looks identical to the user: a control that responds to
// the click by doing nothing at all.
//
// This is an AUDIT, not a gate: it prints a report and exits 0 unless
// --strict is passed. It is meant to be read by a person deciding what to
// fix, and then run with --strict in CI once the findings are at zero.
//
// Run: node scripts/panel-audit.js [--strict]
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
require("./domstub.js");

const html = fs.readFileSync(htmlPath, "utf8");
const scriptText = ["chrome.js", "integrity.js", "update.js", "chat.js"]
  .map((f) => path.join(chromeDir, f))
  .filter((p) => fs.existsSync(p))
  .map((p) => fs.readFileSync(p, "utf8"))
  .join("\n");
const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
const strict = process.argv.includes("--strict");

// Load every chrome script the way the app does. Panel scripts are injected
// after chrome.js and register themselves through window.__rb.
for (const f of ["chrome.js", "integrity.js", "update.js", "chat.js"]) {
  const p = path.join(chromeDir, f);
  if (fs.existsSync(p)) {
    try {
      new Function(fs.readFileSync(p, "utf8"))();
    } catch (e) {
      console.log(`  LOAD FAIL ${f}: ${e.message}`);
    }
  }
}

const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((r) => setImmediate(r));
  }
};

// Which ids received a listener, and for what event.
const listeners = new Map();
for (const entry of global.registered) {
  const [id, ev] = entry.split(":");
  if (!listeners.has(id)) listeners.set(id, new Set());
  listeners.get(id).add(ev);
}

// Controls declared in static markup, with the panel they live in.
const controls = [];
{
  const parts = html.split(/(<section id="[a-z0-9-]+")/);
  for (let i = 1; i < parts.length; i += 2) {
    const panel = /id="([a-z0-9-]+)"/.exec(parts[i])[1];
    const body = parts[i + 1].split("</section>")[0];
    const re =
      /<(button|input|select|textarea)\b([^>]*)id="([a-z0-9-]+)"([^>]*)>/g;
    let m;
    while ((m = re.exec(body))) {
      const attrs = m[2] + m[4];
      controls.push({
        panel,
        tag: m[1],
        id: m[3],
        type: (/type="([a-z]+)"/.exec(attrs) || [])[1] || "",
        // A submit button inside a wired form needs no listener of its own.
        inForm: /<form\b/.test(body.slice(0, m.index)),
      });
    }
  }
}

const findings = [];
function finding(severity, where, what) {
  findings.push({ severity, where, what });
}

// ---------------------------------------------------------------------------
// 1. Controls nothing listens to.
// ---------------------------------------------------------------------------
for (const c of controls) {
  const evs = listeners.get(c.id);
  if (evs && evs.size) continue;
  // Text-ish inputs, textareas and selects are READ when their form submits
  // rather than listened to. That is a legitimate pattern, so the test for
  // them is not "does anything listen" but "does anything reference this id
  // at all" -- a control nothing listens to AND nothing reads is orphaned.
  const readSomewhere = scriptText.includes(`"${c.id}"`);
  if (
    readSomewhere &&
    (c.tag === "textarea" ||
      c.tag === "select" ||
      (c.tag === "input" &&
        ["text", "password", "url", "search", ""].includes(c.type)))
  ) {
    continue;
  }
  // A submit button is activated by its form, which gate 3 already covers.
  if (c.tag === "button" && c.type === "submit") continue;
  if (c.tag === "button" && c.inForm && !c.type) continue;
  finding(
    "DEAD",
    `${c.panel} / #${c.id}`,
    `<${c.tag}${c.type ? ' type="' + c.type + '"' : ""}> has no event listener ` +
      `in any chrome script -- clicking it does nothing`,
  );
}

// ---------------------------------------------------------------------------
// 2. Panels with no CSS of their own.
//
// #tab-panel and #library-panel both shipped with no rule at all: the panel
// manager unhid them and they landed on the page with no background, padding
// or scrolling. Found by screenshot, not by any check.
// ---------------------------------------------------------------------------
const panelIds = [...html.matchAll(/<section id="([a-z0-9-]+)-panel"/g)].map(
  (m) => m[1] + "-panel",
);
for (const p of ["update-panel", "integrity-panel"]) panelIds.push(p);
for (const p of panelIds) {
  // update.js and integrity.js style their panels inline, which is fine.
  const inlineStyled = /setStyles\(panel/.test(
    fs.readFileSync(path.join(chromeDir, "update.js"), "utf8") +
      fs.readFileSync(path.join(chromeDir, "integrity.js"), "utf8"),
  );
  if ((p === "update-panel" || p === "integrity-panel") && inlineStyled)
    continue;
  if (!new RegExp(`#${p}\\b`).test(css)) {
    finding(
      "UNSTYLED",
      p,
      "no rule in chrome.css -- the panel manager unhides it and it renders " +
        "with no background, padding or scrolling",
    );
  }
}

// ---------------------------------------------------------------------------
// 2b. [hidden] must actually hide.
//
// chrome.css sets `display: flex` on .feature-btn, and a class rule beats the
// UA stylesheet's `[hidden] { display: none }`. So every control that relies on
// the hidden ATTRIBUTE was visible regardless -- #btn-chat shipped visible in
// every public build and did nothing when clicked, which its own markup says
// must never happen.
//
// Checked as a CSS invariant rather than per-control: the harness does not
// compute styles, and the next control to rely on [hidden] should not have to
// rediscover this.
// ---------------------------------------------------------------------------
{
  const guard = /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/;
  if (!guard.test(css)) {
    finding(
      "HIDDEN",
      "chrome.css",
      "no global `[hidden] { display: none !important }`. Any class setting " +
        "`display` silently outranks the hidden attribute, so controls meant " +
        "to be invisible render and do nothing when clicked",
    );
  }
}

// ---------------------------------------------------------------------------
// 3. Every registered panel opens, and asks the backend for something.
//
// A panel that opens without refreshing shows whatever was last there, which
// on a privacy surface means stale state presented as current.
// ---------------------------------------------------------------------------
(async () => {
  const panels = global.__panelRegistry || null;
  const openable = [
    ["privacy", "btn-privacy"],
    ["dns", "btn-dns"],
    ["tab", "btn-tab"],
    ["library", "btn-library"],
    ["vault", "btn-vault"],
    ["integrity", "btn-integrity"],
    ["update", "btn-update"],
    ["chat", "btn-chat"],
  ];
  for (const [name, btn] of openable) {
    const b = global.$(btn);
    if (!b) {
      finding("MISSING", name, `#${btn} does not exist in the chrome`);
      continue;
    }
    global.rbCalls.length = 0;
    global.rbReject = null;
    try {
      b._fire("click");
      await flush();
    } catch (e) {
      finding("THROWS", `${name} / #${btn}`, `opening it threw: ${e.message}`);
      continue;
    }
    if (global.rbCalls.length === 0) {
      finding(
        "STALE",
        `${name} / #${btn}`,
        "opening the panel makes no backend request -- whatever it shows is " +
          "left over from the last time, presented as current",
      );
    }
    // Close again so the next open is a real open.
    try {
      b._fire("click");
      await flush();
    } catch (e) {
      /* closing is best-effort */
    }
  }

  // -------------------------------------------------------------------------
  // Report.
  // -------------------------------------------------------------------------
  const byPanel = new Map();
  for (const f of findings) {
    const key = f.where.split(" / ")[0];
    if (!byPanel.has(key)) byPanel.set(key, []);
    byPanel.get(key).push(f);
  }
  console.log(
    `\nPANEL AUDIT: ${controls.length} static controls, ` +
      `${listeners.size} ids with listeners, ${findings.length} findings\n`,
  );
  if (!findings.length) {
    console.log("  no findings");
  }
  for (const [panel, fs_] of [...byPanel.entries()].sort()) {
    console.log(`  ${panel}`);
    for (const f of fs_) {
      console.log(`    [${f.severity}] ${f.where}`);
      console.log(`        ${f.what}`);
    }
  }
  if (strict && findings.length) process.exit(1);
})();
