// What the browser opens ON LAUNCH.
//
// The vault opens itself at startup so the parts of the browser that unlock
// with it (bookmarks, saved passwords, download records) are available
// without the user first discovering that a panel elsewhere is the reason
// they are empty. Three rules make that safe rather than annoying, and all
// three are the kind that break silently:
//
//   1. THE FIRST-RUN TOUR WINS. Only one panel is ever open, so the two boot
//      openers cannot both fire. Being asked for a passphrase before being
//      told what a vault is here is the wrong order to meet it in.
//   2. AN UNLOCKED VAULT OPENS NOTHING. It cannot happen at launch today, but
//      it is checked rather than assumed.
//   3. A FAILED READ OPENS NOTHING. A transient IPC failure must not put a
//      passphrase prompt in front of someone; the tour has always followed
//      this rule and the vault follows it too.
//
// The boot sequence runs ONCE per document, so each scenario needs its own
// process rather than its own function call.
//
// Run: node scripts/startup-vault-gate.js  (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const chromeSrc = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

/// Boots chrome.js in a FRESH process with the given IPC replies and reports
/// which panel ended up open. `replies` is a map of command -> reply object;
/// a command mapped to null is made to REJECT, which is how the failed-read
/// case is exercised through the same path a real failure would take.
function bootWith(replies) {
  // chrome.js is read from disk INSIDE the child rather than inlined into the
  // command: it is a quarter of a megabyte, and passing it as an argument
  // exceeds the OS argument limit outright (E2BIG).
  const script = `
    const fs = require("fs");
    process.env.HTML_PATH = ${JSON.stringify(path.join(chromeDir, "index.html"))};
    require(${JSON.stringify(path.join(__dirname, "domstub.js"))});
    const chromeSrc = fs.readFileSync(${JSON.stringify(path.join(chromeDir, "chrome.js"))}, "utf8");
    const replies = ${JSON.stringify(replies)};
    const rejecting = new Set(Object.keys(replies).filter((k) => replies[k] === null));
    for (const [k, v] of Object.entries(replies)) {
      if (v !== null) global.rbResolve[k] = v;
    }
    // Reject only the named commands; everything else answers {} as usual.
    const realPost = global.window.ipc.postMessage;
    global.window.ipc.postMessage = (raw) => {
      const msg = JSON.parse(raw);
      if (rejecting.has(msg.cmd)) {
        setImmediate(() => {
          if (global.window.__rb_reply) {
            global.window.__rb_reply({ id: msg.id, ok: false, error: "io" });
          }
        });
        return;
      }
      realPost(raw);
    };
    new Function(chromeSrc)();
    (async () => {
      for (let i = 0; i < 40; i += 1) {
        await new Promise((r) => setImmediate(r));
      }
      const open = [];
      for (const id of ["vault-panel", "onboarding-panel", "bookmarks-panel"]) {
        const el = global.$(id);
        if (el && el.hidden === false) open.push(id);
      }
      console.log(JSON.stringify(open));
    })();
  `;
  const out = execFileSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    cwd: root,
  });
  const last = out.trim().split("\n").pop();
  return JSON.parse(last);
}

check("the vault opens itself when PATANYX was opened on its own", () => {
  const open = bootWith({
    onboarding_seen_get: { seen: true },
    startup_info: { opened_with_url: false },
    vault_status: { exists: true, unlocked: false },
  });
  assert(
    open.indexOf("vault-panel") >= 0,
    "the vault did not open at launch; got " + JSON.stringify(open),
  );
});

check("A LINK HANDED OVER BY ANOTHER APP opens no vault prompt", () => {
  // PATANYX as the default browser: someone clicked a link in their mail
  // client and wants to read THAT PAGE. Covering it with a passphrase prompt
  // interrupts the only thing they asked for. This is the rule most likely to
  // be lost in a later refactor of the boot sequence, because it looks like a
  // special case rather than the point.
  const open = bootWith({
    onboarding_seen_get: { seen: true },
    startup_info: { opened_with_url: true },
    vault_status: { exists: true, unlocked: false },
  });
  assert(
    open.indexOf("vault-panel") < 0,
    "the vault opened over a page PATANYX was launched to display; got " +
      JSON.stringify(open),
  );
});

check("a failed startup read opens nothing", () => {
  // Same fail-quiet rule as everything else in this boot sequence: if we
  // cannot tell how the browser was started, do not guess in the direction
  // that interrupts someone.
  const open = bootWith({
    onboarding_seen_get: { seen: true },
    startup_info: null, // rejects
    vault_status: { exists: true, unlocked: false },
  });
  assert(
    open.indexOf("vault-panel") < 0,
    "an unreadable startup_info still opened the vault; got " +
      JSON.stringify(open),
  );
});

check("it opens even when no vault has been made yet", () => {
  // The create-vault form is the useful thing to be shown in that state:
  // nothing else in the browser will retain a bookmark until it exists.
  const open = bootWith({
    onboarding_seen_get: { seen: true },
    startup_info: { opened_with_url: false },
    vault_status: { exists: false, unlocked: false },
  });
  assert(
    open.indexOf("vault-panel") >= 0,
    "with no vault yet the panel should still open to offer creating one; got " +
      JSON.stringify(open),
  );
});

check("THE FIRST-RUN TOUR WINS, and the vault stays shut", () => {
  const open = bootWith({
    onboarding_seen_get: { seen: false },
    startup_info: { opened_with_url: false },
    vault_status: { exists: true, unlocked: false },
  });
  assert(
    open.indexOf("onboarding-panel") >= 0,
    "the first-run tour did not open; got " + JSON.stringify(open),
  );
  assert(
    open.indexOf("vault-panel") < 0,
    "the vault opened on a FIRST RUN and clobbered the tour, or was clobbered " +
      "by it. Only one panel is ever open, so these two cannot both fire; got " +
      JSON.stringify(open),
  );
});

check("an already-unlocked vault opens nothing", () => {
  const open = bootWith({
    onboarding_seen_get: { seen: true },
    startup_info: { opened_with_url: false },
    vault_status: { exists: true, unlocked: true },
  });
  assert(
    open.indexOf("vault-panel") < 0,
    "the vault panel opened even though the vault was already unlocked; got " +
      JSON.stringify(open),
  );
});

check("a failed status read opens nothing", () => {
  // A passphrase prompt must never be the consequence of an IPC hiccup.
  const open = bootWith({
    onboarding_seen_get: { seen: true },
    startup_info: { opened_with_url: false },
    vault_status: null, // rejects
  });
  assert(
    open.indexOf("vault-panel") < 0,
    "a failed vault_status still opened the panel; got " + JSON.stringify(open),
  );
});

check("launch never steals the keyboard into the passphrase field", () => {
  // Someone who opened the browser to go somewhere must be able to just type.
  // Asserted on the source because focus is not observable in the stub: the
  // vault's refresh must not focus, and the boot opener must not add one.
  // refreshVault is defined AFTER the registerPanel call that names it, so
  // slicing between the two in that order yields an EMPTY string and the
  // regex below then passes on nothing. Take the function itself: from its
  // declaration to the next top-level function in the file.
  const start = chromeSrc.indexOf("function refreshVault");
  const next = chromeSrc.indexOf("\n  function ", start + 1);
  const vaultSection = start === -1 ? "" : chromeSrc.slice(start, next);
  assert(
    vaultSection.length > 200,
    "could not locate the body of refreshVault; this check needs rewiring " +
      "rather than deleting -- it is the reason launch does not eat your typing",
  );
  assert(
    !/\.focus\(\)/.test(vaultSection),
    "something in the vault refresh now calls focus(). At launch that would " +
      "swallow the first thing typed into the address bar.",
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
    console.error("\nSTARTUP-VAULT GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nSTARTUP VAULT OK");
})();
