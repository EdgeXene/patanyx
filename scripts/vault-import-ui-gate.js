// Behavioural checks on the vault import forms, run against the DOM harness so
// chrome.js is EXECUTED rather than parsed.
//
// WHY THIS EXISTS. Import is now DESTRUCTIVE: it replaces the vault on this
// machine, and the vault crate no longer refuses when one already exists. The
// refusal was the safety net, and it was deliberately removed so the control
// could be offered to the people who actually need it -- anyone moving to a
// machine they already use. What replaces the net is a sentence in the panel,
// which means the sentence is now a security control and has to be gated like
// one. A warning that quietly stops rendering is a data-loss defect.
//
// The form also exists TWICE (the no-vault screen and the Backup pane), served
// by one factory. Two views of one action is exactly the shape that drifts, so
// every behavioural check below runs over BOTH.
//
// Run: node scripts/vault-import-ui-gate.js   (or via scripts/chrome-js-gate.sh)
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

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

// Both mirrors, named the way a user would describe them.
const MIRRORS = [
  { where: "the no-vault screen", prefix: "import-", destructive: false },
  { where: "the Backup pane", prefix: "bk-import-", destructive: true },
];

function fill(prefix, over) {
  const v = Object.assign(
    {
      src: "/tmp/backup.rbx",
      "export-pass": "export-passphrase",
      pass1: "new-passphrase",
      pass2: "new-passphrase",
    },
    over || {},
  );
  for (const [suffix, value] of Object.entries(v)) {
    global.$(prefix + suffix).value = value;
  }
}

async function submit(prefix, over) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = {
    vault_import: { recovery_key: "AAAA-BBBB", bookmarks: 3 },
  };
  fill(prefix, over);
  global.$(prefix + "form")._fire("submit");
  await flush();
  return global.rbCalls.filter((c) => c.cmd === "vault_import");
}

for (const m of MIRRORS) {
  check(`${m.where}: the form exists and is wired to submit`, () => {
    const form = global.$(m.prefix + "form");
    assert(form, `${m.prefix}form is not in index.html`);
    assert(
      form._has("submit"),
      `${m.prefix}form renders and does nothing on submit -- the user believes ` +
        `their vault was imported and it was not`,
    );
  });

  check(`${m.where}: a valid submission calls vault_import`, async () => {
    const calls = await submit(m.prefix);
    assert(
      calls.length === 1,
      `expected one vault_import call, saw ${calls.length}`,
    );
    assert(
      calls[0].args.src === "/tmp/backup.rbx",
      "the chosen file was not sent",
    );
    assert(
      calls[0].args.passphrase === "export-passphrase",
      "the export passphrase was not sent",
    );
    assert(
      calls[0].args.new_passphrase === "new-passphrase",
      "the new passphrase was not sent",
    );
  });

  // THE IMPORTANT ONE. Import destroys the current vault, so a submission that
  // should not have gone through must not reach Rust at all. Validating after
  // the call would mean a typo'd confirmation still wiped the vault.
  check(`${m.where}: mismatched passphrases never reach Rust`, async () => {
    const calls = await submit(m.prefix, { pass2: "different-passphrase" });
    assert(
      calls.length === 0,
      "a mismatched confirmation still sent vault_import -- that is an " +
        "irreversible wipe on a typo",
    );
    assert(
      /do not match/i.test(global.$(m.prefix + "error").textContent),
      "the user was not told why nothing happened",
    );
  });

  check(`${m.where}: a short passphrase never reaches Rust`, async () => {
    const calls = await submit(m.prefix, { pass1: "short", pass2: "short" });
    assert(
      calls.length === 0,
      "a too-short passphrase still sent vault_import",
    );
  });

  check(`${m.where}: a missing file never reaches Rust`, async () => {
    const calls = await submit(m.prefix, { src: "   " });
    assert(calls.length === 0, "an empty path still sent vault_import");
  });

  check(`${m.where}: a refusal from Rust is shown, not swallowed`, async () => {
    global.rbCalls.length = 0;
    global.rbResolve = {};
    global.rbReject = "auth_failed";
    fill(m.prefix);
    global.$(m.prefix + "form")._fire("submit");
    await flush();
    global.rbReject = null;
    assert(
      global.$(m.prefix + "error").textContent.length > 0,
      "the import failed and the form said nothing -- the user is left " +
        "believing it worked",
    );
  });

  check(`${m.where}: the secrets typed in are cleared afterwards`, async () => {
    await submit(m.prefix);
    for (const suffix of ["export-pass", "pass1", "pass2"]) {
      assert(
        global.$(m.prefix + suffix).value === "",
        `${m.prefix}${suffix} still holds a passphrase after import`,
      );
    }
  });
}

// The warning is the ONLY thing standing between a user and an irreversible
// wipe, now that the vault crate no longer refuses. It is asserted on the
// markup rather than through the harness because it is static copy: the
// failure being gated is someone deleting or softening it, not a runtime bug.
check(
  "the Backup pane states that importing replaces the current vault",
  () => {
    const pane = html.slice(html.indexOf('id="pane-backup"'));
    const section = pane.slice(0, pane.indexOf("<h2>Change passphrase</h2>"));
    assert(
      /class="destructive-warning"/.test(section),
      "the destructive-import warning is gone from the Backup pane",
    );
    assert(
      /replaces the vault on this machine/i.test(section),
      "the warning no longer says the current vault is replaced",
    );
    assert(
      /no undo/i.test(section),
      "the warning no longer says the loss is irreversible",
    );
    assert(
      /bookmark/i.test(section),
      "the warning does not mention bookmarks, which now travel with the vault " +
        "and are therefore also destroyed by an import",
    );
  },
);

check("the warning is placed BEFORE the form, not after it", () => {
  const pane = html.slice(html.indexOf('id="pane-backup"'));
  const warn = pane.indexOf("destructive-warning");
  const form = pane.indexOf('id="bk-import-form"');
  assert(warn !== -1 && form !== -1, "warning or form missing");
  assert(
    warn < form,
    "the warning renders after the form; a user who has already filled in " +
      "four fields has decided, and reads it too late to matter",
  );
});

check("the destructive-warning class has somewhere to be drawn", () => {
  const css = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
  assert(
    /\.destructive-warning\b/.test(css),
    "index.html marks the warning with .destructive-warning and chrome.css " +
      "has no rule for it, so it renders as another grey paragraph and reads " +
      "as intro copy",
  );
});

// Regression guard for the reason the form could not be offered before: the
// no-vault screen's copy used to explain that import refuses over an existing
// vault. That stopped being true, and stale copy about a safety property is
// worse than none.
check("no surviving copy claims import refuses over an existing vault", () => {
  assert(
    !/import refuses to run when a vault already/i.test(html),
    "index.html still claims import refuses when a vault exists; it now " +
      "replaces it",
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
    console.error("\nVAULT IMPORT UI GATE FAILED:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nVAULT IMPORT UI OK");
})();
