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
// Node's own timer, kept BEFORE domstub replaces it with one that runs every
// callback at once, so a request deadline can be made to fire for real.
const nodeSetTimeout = setTimeout;
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
    vault_import: { recovery_key: "AAAA-BBBB", bookmarks: 3, library: "replaced" },
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
    assert(
      global.$(m.prefix + "error").textContent === "",
      "a complete import left a Library warning up",
    );
  });

  for (const outcome of ["not_replaced", "not_opened"]) {
    check(
      `${m.where}: a successful import with Library ${outcome} pins a result note without costing the recovery key`,
      async () => {
        global.rbCalls.length = 0;
        global.rbReject = null;
        global.rbResolve = {
          vault_import: {
            recovery_key: "AAAA-BBBB",
            bookmarks: 0,
            library: outcome,
          },
        };
        fill(m.prefix);
        global.$(m.prefix + "form")._fire("submit");
        await flush();

        assert(
          global.$("vault-recovery").hidden === false,
          "the Library warning displaced the one-time recovery-key screen",
        );
        assert(
          global.$("recovery-key").textContent === "AAAA-BBBB",
          "the Library warning cost the only display of the new recovery key",
        );
        const note = global.$(m.prefix + "error");
        assert(
          /vault was imported/i.test(note.textContent),
          "the note does not distinguish a successful vault import from the Library failure",
        );
        assert(
          /library/i.test(note.textContent) && /unavailable/i.test(note.textContent),
          "the note does not say which data is unavailable",
        );
      },
    );
  }

  check(
    `${m.where}: retained old-vault copies are named without costing the recovery key`,
    async () => {
      global.rbCalls.length = 0;
      global.rbReject = null;
      global.rbResolve = {
        vault_import: { recovery_key: "AAAA-BBBB", bookmarks: 0, library: "replaced", retained_copies: 2 },
      };
      fill(m.prefix);
      global.$(m.prefix + "form")._fire("submit");
      await flush();
      assert(global.$("vault-recovery").hidden === false, "the retained-copies warning displaced the recovery-key screen");
      assert(global.$("recovery-key").textContent === "AAAA-BBBB", "the retained-copies warning cost the recovery key");
      const note = global.$(m.prefix + "error");
      assert(/kept/i.test(note.textContent) && /earlier passphrase/i.test(note.textContent), "retained copies were not named to the user");
      // The form's pane is hidden behind the recovery screen, so the warning
      // must ALSO be on that screen, visible, or the user never sees it.
      const shown = global.$("recovery-import-note");
      assert(shown && shown.hidden === false && /kept/i.test(shown.textContent), "the retained-copies warning is not visible on the recovery screen");
      // And both notes when the Library also failed.
      global.rbResolve = {
        vault_import: { recovery_key: "CCCC-DDDD", bookmarks: 0, library: "not_replaced", retained_copies: 1 },
      };
      fill(m.prefix);
      global.$(m.prefix + "form")._fire("submit");
      await flush();
      const both = global.$(m.prefix + "error").textContent;
      assert(/unavailable/i.test(both) && /kept/i.test(both), "the Library note and the retained-copies note must both show");
      const bothShown = global.$("recovery-import-note").textContent;
      assert(/unavailable/i.test(bothShown) && /kept/i.test(bothShown), "both notes must reach the recovery screen");
      // Zero retained: no warning.
      global.rbResolve = {
        vault_import: { recovery_key: "EEEE-FFFF", bookmarks: 0, library: "replaced", retained_copies: 0 },
      };
      fill(m.prefix);
      global.$(m.prefix + "form")._fire("submit");
      await flush();
      assert(!/kept/i.test(global.$(m.prefix + "error").textContent), "a clean import must not warn about kept copies");
      assert(global.$("recovery-import-note").hidden === true, "a clean import must leave the recovery screen's note hidden");
    },
  );

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
      global.$(m.prefix + "error").dataset.reason === "mismatch",
      "the user was not told why nothing happened; reason=" +
        JSON.stringify(global.$(m.prefix + "error").dataset.reason),
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

  check(`${m.where}: Library refusal codes are explained as user-facing text`, async () => {
    for (const [code, claim] of [
      ["library_replace_refused", /vault was not imported/i],
      ["library_not_replaced", /library.*unavailable/i],
    ]) {
      global.rbCalls.length = 0;
      global.rbResolve = {};
      global.rbReject = code;
      fill(m.prefix);
      global.$(m.prefix + "form")._fire("submit");
      await flush();
      const shown = global.$(m.prefix + "error").textContent;
      assert(
        claim.test(shown),
        `${code} rendered as ${JSON.stringify(shown)} instead of explaining the outcome`,
      );
    }
    global.rbReject = null;
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
    const section = pane.slice(0, pane.search(/<h2[^>]*>Change passphrase<\/h2>/));
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

// Every node under `root` whose own text is `text`.
function findByText(root, text, out = []) {
  for (const c of root.children || []) {
    if (c.textContent === text) out.push(c);
    findByText(c, text, out);
  }
  return out;
}

check("a successful import forgets what the replaced vault had on screen", async () => {
  // Review 2026-10-12 R-001: a password revealed, or an edit form opened, in
  // the vault being replaced survived the import. The next render showed the
  // old password against the imported entry with the same id, and saving the
  // still-open form wrote the old password into the imported vault.
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = {
    vault_import: { recovery_key: "AAAA-BBBB", bookmarks: 0, library: "replaced" },
    cred_list: { items: [{ id: "c1", site: "example.com", username: "u", origin: "https://example.com", fills_on: "example.com" }] },
    note_list: { items: [] },
    cred_get: { site: "example.com", username: "u", password: "OLD-SECRET", note: "" },
  };
  fill("bk-import-");
  global.$("bk-import-form")._fire("submit");
  await flush();
  const list = global.$("cred-list");
  const reveal = findByText(list, "Reveal")[0];
  const edit = findByText(list, "Edit")[0];
  assert(reveal && edit, "the harness did not render the credential row");
  reveal._fire("click");
  await flush();
  edit._fire("click");
  await flush();
  assert(global.$("cred-password").value === "OLD-SECRET", "(control) the edit form did not open");
  const shown = () => findByText(global.$("cred-list"), "Hide").length;
  assert(shown() === 1, "(control) the password was not revealed");

  fill("bk-import-");
  global.$("bk-import-form")._fire("submit");
  await flush();
  assert(shown() === 0, "the replaced vault's revealed password is still shown after the import");
  assert(global.$("cred-password").value === "", "the replaced vault's edit form is still open after the import");
  assert(global.$("cred-cancel").hidden === true, "the edit form still offers to save changes after the import");
});

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

// ---- the whole-Library backup ------------------------------------------------
//
// The backup now carries the whole Library, and the import replaces it. Three
// things the person must be told, each gated because each is the kind of
// sentence that quietly stops rendering: what came back (counted, so a missing
// kind is visible), that an OLDER backup file brings back less than it
// replaces (before they confirm), and why an export wrote nothing (with the
// item in the way named, so they can find it).

const WHOLE_REPLY = {
  recovery_key: "AAAA-BBBB",
  bookmarks: 12,
  library: "replaced",
  library_included: true,
  restored: {
    bookmarks: 12,
    folders: 2,
    tab_groups: 3,
    deep_recall_pages: 5,
    snapshots: 1,
    pictures: 4,
    site_exceptions: 2,
    downloads_kept: 7,
  },
};

async function importWith(prefix, reply) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = { vault_import: reply };
  fill(prefix);
  global.$(prefix + "form")._fire("submit");
  await flush();
  return global.$("recovery-import-result");
}

for (const m of MIRRORS) {
  check(`${m.where}: a whole-Library import says what came back, with the recovery key`, async () => {
    const note = await importWith(m.prefix, WHOLE_REPLY);
    assert(global.$("recovery-key").textContent === "AAAA-BBBB", "the recovery key was not shown");
    assert(note && note.hidden === false, "the restored counts were not shown with the recovery key");
    for (const count of ["12", "3", "5", "4", "2"]) {
      assert(note.textContent.includes(count), `the count ${count} is missing from: ${note.textContent}`);
    }
    assert(/download/i.test(note.textContent), "kept download history was not mentioned");
    assert(
      /<p id="recovery-import-result" class="ok"/.test(html),
      "the import result is not drawn as a result (class ok) in index.html",
    );
    const warning = global.$("recovery-import-note");
    assert(warning.hidden === true, "a complete import showed a warning beside its result");
    assert(
      global.$(m.prefix + "error").textContent === "",
      "a result was left behind in the form's error line",
    );
  });

  check(`${m.where}: a backup with no Library says the Library starts empty`, async () => {
    const reply = Object.assign({}, WHOLE_REPLY, { library_included: false });
    const note = await importWith(m.prefix, reply);
    assert(note.hidden === false && note.textContent.length > 0, "no-Library result was not stated");
    assert(!/Restored from/i.test(note.textContent), "counts were claimed for a backup with no Library");
    assert(/download/i.test(note.textContent), "kept download records went unmentioned");
  });

  check(`${m.where}: a Library that could not be moved into place is told apart`, async () => {
    const reply = Object.assign({}, WHOLE_REPLY, { library: "library_import_unfinished" });
    const result = await importWith(m.prefix, reply);
    const note = global.$("recovery-import-note");
    assert(/vault was imported/i.test(note.textContent), "the vault import was not acknowledged");
    assert(result.hidden === true && !/Restored from/i.test(result.textContent), "counts were claimed for a Library that is not in place");
  });
}

async function pick(prefix, inspect) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = {
    file_pick_open: { path: "/tmp/chosen.rbx" },
    vault_import_inspect: inspect,
  };
  global.$(prefix + "pick")._fire("click");
  await flush();
}

check("the Backup pane warns before an OLDER backup replaces the whole Library", async () => {
  const note = global.$("bk-import-older");
  assert(note, "bk-import-older is not in index.html");
  await pick("bk-import-", { version: 2, whole_library: false, older: true });
  assert(
    global.rbCalls.some((c) => c.cmd === "vault_import_inspect" && c.args.src === "/tmp/chosen.rbx"),
    "the chosen file was not inspected",
  );
  assert(note.hidden === false, "an older backup was chosen and no warning appeared");
  const markup = html.slice(html.indexOf('id="bk-import-older"'));
  const body = markup.slice(markup.indexOf(">") + 1, markup.indexOf("</p>"));
  assert(/Library/.test(body) && /gone/.test(body), "the older-backup warning says nothing about what is lost");
  await pick("bk-import-", { version: 4, whole_library: true, older: false });
  assert(note.hidden === true, "the older-backup warning stayed up for a whole-Library backup");
});

check("an older backup submitted before its warning appeared is held for a second submit", async () => {
  const note = global.$("bk-import-older");
  note.hidden = true;
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = {
    vault_import_inspect: { version: 1, whole_library: false, older: true },
    vault_import: { recovery_key: "AAAA-BBBB", bookmarks: 0, library: "replaced" },
  };
  // A typed path, submitted at once: no change event has run the check.
  fill("bk-import-", { src: "/tmp/typed-old.rbx" });
  global.$("bk-import-form")._fire("submit");
  await flush();
  assert(
    !global.rbCalls.some((c) => c.cmd === "vault_import"),
    "an older backup was imported before its warning was on screen",
  );
  assert(note.hidden === false, "the older-backup warning was not shown on submit");
  fill("bk-import-", { src: "/tmp/typed-old.rbx" });
  global.$("bk-import-form")._fire("submit");
  await flush();
  assert(
    global.rbCalls.filter((c) => c.cmd === "vault_import").length === 1,
    "the second submit, with the warning read, did not import",
  );
});

check("a closed Library's download records are not dropped silently", async () => {
  const reply = JSON.parse(JSON.stringify(WHOLE_REPLY));
  reply.restored.downloads_kept = 0;
  reply.restored.downloads_not_kept_library_closed = true;
  const result = await importWith("bk-import-", reply);
  assert(/not kept/i.test(result.textContent), "lost download records went unmentioned: " + result.textContent);
});

check("the older-backup warning sits inside the form, before its button", () => {
  const form = html.slice(html.indexOf('id="bk-import-form"'));
  const note = form.indexOf('id="bk-import-older"');
  const button = form.indexOf('type="submit"');
  assert(note !== -1 && note < button, "the warning is not in the form above the button");
});

check("the no-vault screen has nothing to lose and inspects nothing", async () => {
  assert(!global.$("import-older"), "the no-vault screen grew an older-backup note");
  await pick("import-", { version: 2, older: true });
  assert(
    !global.rbCalls.some((c) => c.cmd === "vault_import_inspect"),
    "a file was inspected where no Library can be lost",
  );
});

async function exportWith(reply) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = { vault_export_encrypted: reply };
  global.$("bk-exp-dest").value = "/tmp/out.rbx";
  global.$("bk-exp-pass1").value = "export-pass";
  global.$("bk-exp-pass2").value = "export-pass";
  global.$("bk-export-form")._fire("submit");
  await flush();
  return { ok: global.$("bk-exp-ok"), err: global.$("bk-exp-error") };
}

check("an export says what it wrote, counted", async () => {
  const { ok, err } = await exportWith({
    library_included: true,
    bookmarks: 12,
    tab_groups: 3,
    deep_recall_pages: 5,
    pictures: 4,
    pictures_left_out: 0,
  });
  assert(err.textContent === "", "a written export showed an error");
  for (const count of ["12", "3", "5", "4"]) {
    assert(ok.textContent.includes(count), `the count ${count} is missing from: ${ok.textContent}`);
  }
  assert(/recovery key/i.test(ok.textContent), "the no-recovery-key reminder was lost");
  assert(global.$("bk-exp-pass1").value === "", "the export passphrase stayed on screen");
});

check("an export with pictures left out says so", async () => {
  const { ok } = await exportWith({ library_included: true, bookmarks: 1, pictures_left_out: 6 });
  assert(/\b6\b/.test(ok.textContent), "the left-out pictures were not counted: " + ok.textContent);
});

check("an export made with no Library open says it holds the vault only", async () => {
  const { ok } = await exportWith({ library_included: false });
  assert(ok.textContent.length > 0 && !/\d/.test(ok.textContent), "vault-only export not stated: " + ok.textContent);
});

for (const code of ["export_item_too_large", "export_picture_unreadable"]) {
  check(`an export refused with ${code} wrote nothing and names the item`, async () => {
    const { ok, err } = await exportWith({ refused: code, item: "My saved page", bookmark_limit: 100000 });
    assert(ok.textContent === "", "a refused export claimed it was written");
    assert(err.textContent.includes("My saved page"), "the item in the way is not named: " + err.textContent);
    assert(global.$("bk-exp-pass1").value === "export-pass", "the passphrases were cleared for a retry");
  });
}

for (const code of [
  "export_too_many_bookmarks",
  "export_library_too_large",
  "export_library_unusable",
  "something_new",
]) {
  check(`an export refused with ${code} is explained, never shown as written`, async () => {
    const { ok, err } = await exportWith({ refused: code, bookmark_limit: 100000 });
    assert(ok.textContent === "", "a refused export claimed it was written");
    assert(err.textContent.trim().length > 0 && !/Unexpected error/.test(err.textContent), "refusal not explained");
  });
}

for (const code of ["export_version_unreadable", "import_over_limit", "disk_full", "library_import_unfinished"]) {
  check(`the code ${code} has words`, async () => {
    global.rbCalls.length = 0;
    global.rbReject = code;
    fill("bk-import-");
    global.$("bk-import-form")._fire("submit");
    await flush();
    const err = global.$("bk-import-error").textContent;
    assert(err && !/Unexpected error/.test(err), `${code} reaches the person as: ${err}`);
    global.rbReject = null;
  });
}

// ---- a slow import or export is waited for, never given up on ----------------
// A whole Library with its pictures can take longer than the 30-second request
// deadline to import or export. A reply arriving after it used to be dropped,
// and an import's reply carries the one-time recovery key: the vault was
// replaced and the key for it was never shown, while the form said nothing may
// have changed. Both now wait for their answer with the button held down, as a
// passphrase change does.

// A GENUINELY late reply, as in vault-passphrase-ui-gate.js: the answer for
// `cmd` is held back (domstub would otherwise answer on the next tick), request
// deadlines (30 s and up) are put on Node's real clock at zero delay so they
// fire first, and the answer is delivered only after that.
async function withLateReply(cmd, reply, run) {
  const stubSetTimeout = global.setTimeout;
  const stubPost = global.window.ipc.postMessage;
  let held = null;
  global.setTimeout = (fn, ms, ...rest) =>
    ms >= 30000 ? nodeSetTimeout(fn, 0, ...rest) : stubSetTimeout(fn, ms, ...rest);
  global.window.ipc.postMessage = (raw) => {
    const msg = JSON.parse(raw);
    if (msg.cmd !== cmd) return stubPost(raw);
    global.rbCalls.push({ id: msg.id, cmd: msg.cmd, args: msg.args });
    held = msg;
  };
  const answerLate = async () => {
    await new Promise((resolve) => nodeSetTimeout(resolve, 25));
    await flush();
    assert(held, cmd + " was never sent");
    global.window.__rb_reply({ id: held.id, ok: true, data: reply });
    await flush();
  };
  try {
    await run(answerLate);
  } finally {
    global.setTimeout = stubSetTimeout;
    global.window.ipc.postMessage = stubPost;
  }
}

for (const m of MIRRORS) {
  check(`${m.where}: an import answered after any deadline still shows its recovery key`, async () => {
    const button = global.$(m.prefix + "submit");
    assert(button, `${m.prefix}submit is not in index.html`);
    let heldDown = null;
    await withLateReply("vault_import", WHOLE_REPLY, async (answerLate) => {
      global.rbCalls.length = 0;
      global.rbReject = null;
      global.rbResolve = {};
      global.$("recovery-key").textContent = "";
      fill(m.prefix);
      global.$(m.prefix + "form")._fire("submit");
      await flush();
      heldDown = button.disabled;
      await answerLate();
    });
    const err = global.$(m.prefix + "error").textContent;
    assert(err === "", "a late import was shown as a failure: " + err);
    assert(
      global.$("recovery-key").textContent === "AAAA-BBBB",
      "the late import's recovery key was never shown",
    );
    assert(heldDown === true, "a second press could start a second import");
    assert(button.disabled === false, "the button stayed down after the answer");
  });
}

check("an export answered after any deadline still says what it wrote", async () => {
  const button = global.$("bk-exp-submit");
  assert(button, "bk-exp-submit is not in index.html");
  let heldDown = null;
  await withLateReply("vault_export_encrypted", { library_included: false }, async (answerLate) => {
    global.rbCalls.length = 0;
    global.rbReject = null;
    global.rbResolve = {};
    global.$("bk-exp-error").textContent = "";
    global.$("bk-exp-ok").textContent = "";
    global.$("bk-exp-dest").value = "/tmp/out.rbx";
    global.$("bk-exp-pass1").value = "export-passphrase";
    global.$("bk-exp-pass2").value = "export-passphrase";
    global.$("bk-export-form")._fire("submit");
    await flush();
    heldDown = button.disabled;
    await answerLate();
  });
  const err = global.$("bk-exp-error").textContent;
  assert(err === "", "a late export was shown as a failure: " + err);
  assert(
    /vault only/i.test(global.$("bk-exp-ok").textContent),
    "the late export's result was not shown: " + global.$("bk-exp-ok").textContent,
  );
  assert(global.$("bk-exp-pass1").value === "", "a written export left its passphrase in the field");
  assert(heldDown === true, "a second press could start a second export");
  assert(button.disabled === false, "the button stayed down after the answer");
});

check("an export refused by Rust brings its button back up", async () => {
  global.rbCalls.length = 0;
  global.rbReject = "bad_args";
  global.$("bk-exp-dest").value = "/tmp/out.rbx";
  global.$("bk-exp-pass1").value = "export-passphrase";
  global.$("bk-exp-pass2").value = "export-passphrase";
  global.$("bk-export-form")._fire("submit");
  await flush();
  global.rbReject = null;
  assert(global.$("bk-exp-error").textContent !== "", "the refusal was not shown");
  assert(global.$("bk-exp-submit").disabled === false, "a refused export left the button down");
});

for (const m of MIRRORS) {
  check(`${m.where}: an import refused by Rust brings its button back up`, async () => {
    global.rbCalls.length = 0;
    global.rbReject = "auth_failed";
    fill(m.prefix);
    global.$(m.prefix + "form")._fire("submit");
    await flush();
    global.rbReject = null;
    assert(global.$(m.prefix + "error").textContent !== "", "the refusal was not shown");
    assert(global.$(m.prefix + "submit").disabled === false, "a refused import left the button down");
  });
}

// ---- an export runs as a job: progress, Stop, and one result -----------------------
// The command answers at once with {job}; progress and the result arrive as
// events (backup_job.rs). These drive the real handler through those events.

const EXPORT_DONE = {
  library_included: true,
  bookmarks: 4,
  tab_groups: 1,
  deep_recall_pages: 2,
  pictures: 3,
  site_exceptions: 1,
};

async function startExportJob(job) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = { vault_export_encrypted: { job, kind: "export" } };
  global.$("bk-exp-error").textContent = "";
  global.$("bk-exp-ok").textContent = "";
  global.$("bk-exp-dest").value = "/tmp/job.rbx";
  global.$("bk-exp-pass1").value = "job-passphrase";
  global.$("bk-exp-pass2").value = "job-passphrase";
  global.$("bk-export-form")._fire("submit");
  await flush();
}

function jobEvent(event, data) {
  global.window.__rb_event({ event, data });
}

check("an export job shows its progress, then its result once, and lets go of the form", async () => {
  await startExportJob(41);
  assert(global.$("bk-exp-progress").hidden === false, "no progress shown while the export runs");
  assert(global.$("bk-exp-submit").disabled === true, "a second export could start under the first");
  jobEvent("backup_progress", {
    job: 41, kind: "export", phase: "writing", done: 50, total: 100,
    items_done: 2, items_total: 3, cancellable: true, stopping: false,
  });
  await flush();
  const line = global.$("bk-exp-status").textContent;
  assert(/Writing/.test(line) && /2 \/ 3/.test(line), "the progress line is wrong: " + line);
  // Writing fills the first 80% of the bar; half of it is 0.4.
  assert(Math.abs(global.$("bk-exp-bar").value - 0.4) < 1e-9, "the bar did not move: " + global.$("bk-exp-bar").value);
  assert(global.$("bk-exp-stop").disabled === false, "Stop is not offered while stopping is possible");
  jobEvent("backup_finished", { job: 41, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: null });
  await flush();
  assert(/vault and your Library/.test(global.$("bk-exp-ok").textContent), "the result was not shown");
  assert(global.$("bk-exp-error").textContent === "", "a result left an error behind");
  assert(global.$("bk-exp-progress").hidden === true, "the progress stayed up after the result");
  assert(global.$("bk-exp-submit").disabled === false, "the button stayed down after the result");
  assert(global.$("bk-exp-pass1").value === "", "a written export left its passphrase in the field");
});

check("a result that arrives before the start reply is kept until it is handled", async () => {
  const stubPost = global.window.ipc.postMessage;
  let held = null;
  global.window.ipc.postMessage = (raw) => {
    const msg = JSON.parse(raw);
    if (msg.cmd !== "vault_export_encrypted") return stubPost(raw);
    global.rbCalls.push({ id: msg.id, cmd: msg.cmd, args: msg.args });
    held = msg;
  };
  try {
    global.$("bk-exp-ok").textContent = "";
    global.$("bk-exp-dest").value = "/tmp/early.rbx";
    global.$("bk-exp-pass1").value = "job-passphrase";
    global.$("bk-exp-pass2").value = "job-passphrase";
    global.$("bk-export-form")._fire("submit");
    await flush();
    assert(held, "the export was never sent");
    jobEvent("backup_finished", { job: 42, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: null });
    global.window.__rb_reply({ id: held.id, ok: true, data: { job: 42, kind: "export" } });
    await flush();
  } finally {
    global.window.ipc.postMessage = stubPost;
  }
  assert(/vault and your Library/.test(global.$("bk-exp-ok").textContent), "an early result was lost");
  assert(global.$("bk-exp-submit").disabled === false, "the button stayed down");
});

check("Stop asks for the job by id, and a stopped export says nothing was written", async () => {
  await startExportJob(43);
  global.$("bk-exp-stop")._fire("click");
  await flush();
  const cancel = global.rbCalls.find((c) => c.cmd === "backup_job_cancel");
  assert(cancel && cancel.args.job === 43, "Stop did not name its job");
  jobEvent("backup_finished", { job: 43, kind: "export", ok: false, error: "backup_cancelled", stopped_by: "person" });
  await flush();
  const err = global.$("bk-exp-error").textContent;
  assert(/Export stopped before it was saved/.test(err), "a stop was not explained: " + err);
  assert(global.$("bk-exp-pass1").value === "job-passphrase", "a stop cleared the passphrases a retry needs");
  assert(global.$("bk-exp-progress").hidden === true && global.$("bk-exp-submit").disabled === false);
});

check("a stop that lands after the backup was whole says it was written anyway", async () => {
  await startExportJob(44);
  jobEvent("backup_finished", { job: 44, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: "person" });
  await flush();
  const ok = global.$("bk-exp-ok").textContent;
  assert(/vault and your Library/.test(ok) && /already complete, so stopping it changed nothing/.test(ok), "a late stop was misreported: " + ok);
});

check("a lock during an export draws nothing into the pane afterwards", async () => {
  await startExportJob(45);
  jobEvent("vault_locked", {});
  await flush();
  jobEvent("backup_finished", { job: 45, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: null });
  await flush();
  assert(global.$("bk-exp-ok").textContent === "", "a result was drawn after the lock");
  assert(global.$("bk-exp-submit").disabled === false, "the button stayed down after the lock");
});

check("Stop is withdrawn once a job can no longer stop, and progress for another job is ignored", async () => {
  await startExportJob(46);
  jobEvent("backup_progress", { job: 99, kind: "export", phase: "writing", done: 1, total: 2, cancellable: true, stopping: false });
  await flush();
  assert(global.$("bk-exp-bar").value === 0, "another job's progress moved this bar");
  jobEvent("backup_progress", { job: 46, kind: "export", phase: "checking", done: 2, total: 4, cancellable: false, stopping: false });
  await flush();
  assert(global.$("bk-exp-stop").disabled === true, "Stop stayed offered when it could do nothing");
  jobEvent("backup_finished", { job: 46, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: null });
  await flush();
});

// The job's own error codes are covered by the Rust error-text gate, which
// scans backup_job.rs; the refusal below travels as an export result instead.
check("a picture deleted mid-export is refused by name", async () => {
  await startExportJob(47);
  jobEvent("backup_finished", {
    job: 47, kind: "export", ok: true, stopped_by: null,
    data: { refused: "export_library_changed", item: "C page" },
  });
  await flush();
  const err = global.$("bk-exp-error").textContent;
  assert(/"C page" was removed from your Library during the export/.test(err), "the refusal was not explained: " + err);
  assert(global.$("bk-exp-ok").textContent === "", "a refused export was reported as written");
});

// ---- an import runs as a job: reading, a commit that cannot stop, the key once ---

async function startImportJob(m, job) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = { vault_import: { job, kind: "import" } };
  global.$("recovery-key").textContent = "";
  global.$(m.prefix + "error").textContent = "";
  fill(m.prefix);
  global.$(m.prefix + "form")._fire("submit");
  await flush();
}

for (const m of MIRRORS) {
  check(`${m.where}: an import job reads, commits without a Stop, then shows the key once`, async () => {
    await startImportJob(m, 60);
    assert(global.$(m.prefix + "progress").hidden === false, "no progress while the import runs");
    assert(global.$(m.prefix + "submit").disabled === true, "a second import could start under the first");
    jobEvent("backup_progress", {
      job: 60, kind: "import", phase: "reading", done: 10, total: 100,
      items_done: 1, items_total: 2, cancellable: true, stopping: false,
    });
    await flush();
    let line = global.$(m.prefix + "status").textContent;
    assert(/Reading/.test(line) && /1 \/ 2/.test(line), "the reading line is wrong: " + line);
    assert(global.$(m.prefix + "stop").disabled === false, "Stop is not offered while reading");
    jobEvent("backup_progress", { job: 60, kind: "import", phase: "committing", cancellable: false, stopping: false });
    await flush();
    line = global.$(m.prefix + "status").textContent;
    assert(/can no longer be stopped/.test(line), "the commit is not said to be unstoppable: " + line);
    assert(global.$(m.prefix + "stop").disabled === true, "Stop stayed offered during the commit");
    jobEvent("backup_finished", { job: 60, kind: "import", ok: true, data: WHOLE_REPLY, stopped_by: null });
    await flush();
    assert(global.$("recovery-key").textContent === "AAAA-BBBB", "the recovery key was not shown");
    assert(global.$(m.prefix + "error").textContent === "", "a result left an error behind");
    assert(global.$(m.prefix + "progress").hidden === true, "the progress stayed up");
    assert(global.$(m.prefix + "submit").disabled === false, "the button stayed down");
    assert(global.$(m.prefix + "pass1").value === "", "the new passphrase stayed in the field");
  });

  check(`${m.where}: a stopped import says nothing changed and keeps what was typed`, async () => {
    await startImportJob(m, 61);
    global.$(m.prefix + "stop")._fire("click");
    await flush();
    const cancel = global.rbCalls.find((c) => c.cmd === "backup_job_cancel");
    assert(cancel && cancel.args.job === 61, "Stop did not name its job");
    jobEvent("backup_finished", { job: 61, kind: "import", ok: false, error: "backup_cancelled", stopped_by: "person" });
    await flush();
    const err = global.$(m.prefix + "error").textContent;
    assert(/Import stopped\. Nothing was imported or replaced/.test(err), "a stop was not explained: " + err);
    assert(global.$("recovery-key").textContent === "", "a stopped import showed a key");
    assert(global.$(m.prefix + "pass1").value === "new-passphrase", "a stop cleared what a retry needs");
  });

  check(`${m.where}: a stop that could not clean up says files remain`, async () => {
    await startImportJob(m, 62);
    jobEvent("backup_finished", {
      job: 62, kind: "import", ok: false, error: "backup_cancelled_cleanup_pending", stopped_by: "person",
    });
    await flush();
    const err = global.$(m.prefix + "error").textContent;
    assert(/temporary files remain/.test(err), "leftovers went unmentioned: " + err);
  });

  check(`${m.where}: a lock during an import never shows the key, and says it was lost`, async () => {
    await startImportJob(m, 63);
    jobEvent("vault_locked", {});
    await flush();
    jobEvent("backup_finished", { job: 63, kind: "import", ok: true, data: WHOLE_REPLY, stopped_by: null });
    await flush();
    assert(global.$("recovery-key").textContent === "", "the key was drawn after a lock");
    assert(global.$(m.prefix + "submit").disabled === false, "the button stayed down after the lock");
    // The newest notice: the host keeps only a few, so a count cannot grow.
    const host = global.$("toasts");
    const notices = host.children.length > 0 ? [host.children[host.children.length - 1].title || ""] : [];
    assert(notices.some((n) => /so that key is lost/.test(n)), "the lost key went unmentioned: " + JSON.stringify(notices));
    assert(!notices.some((n) => n.includes("AAAA-BBBB")), "a notice carried the key itself");
  });
}

// In another language the counts are worded through a round trip. A lock that
// lands in that moment must still keep the key off the screen (review R-040),
// and with no lock the key shows exactly once (review R-045).
// Each switch needs a newer generation than the last, or it is refused and
// the chrome stays in English (code review round 1, R-006).
let localeGeneration = 900;
async function withHeldTranslations(run) {
  const stubPost = global.window.ipc.postMessage;
  const held = [];
  global.window.ipc.postMessage = (raw) => {
    const msg = JSON.parse(raw);
    if (msg.cmd !== "i18n_resolve") return stubPost(raw);
    global.rbCalls.push({ id: msg.id, cmd: msg.cmd, args: msg.args });
    held.push(msg);
  };
  localeGeneration += 2;
  global.window.__rb_event({ event: "ui_locale_fill", data: { generation: localeGeneration, locale: "en-XA", messages: {} } });
  // Answers every held request, and the ones they lead to: the counts are
  // worded in several round trips, one after another.
  const release = async () => {
    for (let round = 0; round < 20; round += 1) {
      const batch = held.splice(0);
      if (!batch.length) return;
      for (const msg of batch) global.window.__rb_reply({ id: msg.id, ok: true, data: {} });
      await flush();
    }
    throw new Error("the wording never stopped asking");
  };
  try {
    await run(held, release);
  } finally {
    global.window.ipc.postMessage = stubPost;
    global.window.__rb_event({ event: "ui_locale_fill", data: { generation: localeGeneration + 1, locale: "en", messages: {} } });
  }
}

check("a lock while the counts are worded in another language keeps the key off the screen", async () => {
  await withHeldTranslations(async (held, release) => {
    await startImportJob(MIRRORS[1], 64);
    jobEvent("backup_finished", { job: 64, kind: "import", ok: true, data: WHOLE_REPLY, stopped_by: null });
    await flush();
    assert(held.length > 0, "the counts were not worded through the bridge; this check proves nothing");
    jobEvent("vault_locked", {});
    await flush();
    await release();
    assert(global.$("recovery-key").textContent === "", "the key was drawn after a lock");
  });
});

check("with no lock, the key shows exactly once in another language too", async () => {
  await withHeldTranslations(async (held, release) => {
    await startImportJob(MIRRORS[1], 65);
    jobEvent("backup_finished", { job: 65, kind: "import", ok: true, data: WHOLE_REPLY, stopped_by: null });
    await flush();
    assert(held.length > 0, "the counts were not worded through the bridge; this check proves nothing");
    await release();
    assert(global.$("recovery-key").textContent === "AAAA-BBBB", "an import's own handover hid its key");
  });
});

// Code review round 1: a lock during the older-backup check (R-001), and a lock
// while an export's counts are worded in another language (R-004).
check("a lock during the older-backup check stops the import from being sent", async () => {
  const m = MIRRORS[1];
  const stubPost = global.window.ipc.postMessage;
  let held = null;
  global.window.ipc.postMessage = (raw) => {
    const msg = JSON.parse(raw);
    if (msg.cmd !== "vault_import_inspect") return stubPost(raw);
    global.rbCalls.push({ id: msg.id, cmd: msg.cmd, args: msg.args });
    held = msg;
  };
  try {
    global.rbCalls.length = 0;
    global.rbReject = null;
    global.rbResolve = { vault_import: { job: 70, kind: "import" } };
    global.$("recovery-key").textContent = "";
    fill(m.prefix, { src: "/tmp/never-inspected-" + Date.now() + ".rbx" });
    global.$(m.prefix + "form")._fire("submit");
    await flush();
    assert(held, "the older-backup check was not asked; this check proves nothing");
    jobEvent("vault_locked", {});
    await flush();
    global.window.__rb_reply({ id: held.id, ok: true, data: { older: false } });
    await flush();
  } finally {
    global.window.ipc.postMessage = stubPost;
  }
  assert(!global.rbCalls.some((c) => c.cmd === "vault_import"), "an import was sent after the lock");
  assert(global.$(m.prefix + "submit").disabled === false, "the button stayed down");
});

check("a lock while an export's counts are worded in another language draws nothing", async () => {
  await withHeldTranslations(async (held, release) => {
    await startExportJob(71);
    jobEvent("backup_finished", { job: 71, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: "person" });
    await flush();
    assert(held.length > 0, "the counts were not worded through the bridge; this check proves nothing");
    jobEvent("vault_locked", {});
    await flush();
    await release();
    assert(global.$("bk-exp-ok").textContent === "", "counts were drawn after the lock: " + global.$("bk-exp-ok").textContent);
  });
});

// ---- code review round 2 -------------------------------------------------------

check("the bar never moves back when the next stage starts at zero, or on a stop", async () => {
  await startExportJob(80);
  jobEvent("backup_progress", { job: 80, kind: "export", phase: "writing", done: 95, total: 100, items_done: 4, items_total: 4, cancellable: true, stopping: false });
  await flush();
  const writing = global.$("bk-exp-bar").value;
  jobEvent("backup_progress", { job: 80, kind: "export", phase: "checking", done: 0, total: 100, items_done: 4, items_total: 4, cancellable: true, stopping: false });
  await flush();
  assert(global.$("bk-exp-bar").value >= writing, "the bar went back when checking began");
  jobEvent("backup_progress", { job: 80, kind: "export", phase: "checking", done: 0, total: 100, items_done: 0, items_total: 0, cancellable: true, stopping: true });
  await flush();
  assert(global.$("bk-exp-bar").value >= writing, "the bar went back on a stop");
  jobEvent("backup_finished", { job: 80, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: null });
  await flush();
});

// R-001: a key already on screen, and the no-vault form's passphrases, are
// emptied by a lock, not only hidden.
check("a lock empties a recovery key already on screen and the no-vault form's passphrases", async () => {
  await startImportJob(MIRRORS[1], 81);
  jobEvent("backup_finished", { job: 81, kind: "import", ok: true, data: WHOLE_REPLY, stopped_by: null });
  await flush();
  assert(global.$("recovery-key").textContent === "AAAA-BBBB", "setup: the key was not shown");
  fill("import-");
  jobEvent("vault_locked", {});
  await flush();
  assert(global.$("recovery-key").textContent === "", "the key stayed in the locked browser");
  assert(global.$("recovery-import-result").textContent === "", "the restored counts stayed in the locked browser");
  for (const suffix of ["export-pass", "pass1", "pass2"]) {
    assert(global.$("import-" + suffix).value === "", "import-" + suffix + " kept its passphrase after the lock");
  }
});

// R-003: the backend sends the result first and the lock after it. Each check
// below fails if the fix it covers is removed (code review round 3, R-003).

// Notices from earlier checks are cleared, so the newest one is this check's.
function clearNotices() {
  const host = global.$("toasts");
  while (host.children.length) host.removeChild(host.children[0]);
}
function newestNotice() {
  const host = global.$("toasts");
  return host.children.length ? host.children[host.children.length - 1].title || "" : "";
}
// The vault panel starts locked, so a result screen entered during the check
// is visible as such.
async function fromLocked() {
  jobEvent("vault_locked", {});
  await flush();
  assert(global.$("vault-recovery").hidden === true, "setup: the recovery screen is still up");
}

for (const m of MIRRORS) {
  check(`${m.where}: a result a lock follows is never drawn, even if it carried the key`, async () => {
    await fromLocked();
    await startImportJob(m, 82);
    clearNotices();
    // The key IS in this payload, so only the lock_follows check can stop it.
    jobEvent("backup_finished", { job: 82, kind: "import", ok: true, data: WHOLE_REPLY, stopped_by: null, lock_follows: true });
    await flush();
    assert(global.$("recovery-key").textContent === "", "the key was drawn although a lock follows");
    assert(global.$("vault-recovery").hidden === true, "the recovery screen was entered although a lock follows");
    assert(/so that key is lost/.test(newestNotice()), "the lost key went unmentioned: " + newestNotice());
    assert(!newestNotice().includes("AAAA-BBBB"), "a notice carried the key itself");
    jobEvent("vault_locked", {});
    await flush();
  });

  check(`${m.where}: a stripped result says the key was lost, with any kept copies`, async () => {
    await fromLocked();
    await startImportJob(m, 84);
    clearNotices();
    // What Rust sends when a lock follows: no key, key_lost set, and here
    // kept copies of the replaced vault, which must still be named.
    const data = Object.assign({}, WHOLE_REPLY, { key_lost: true, retained_copies: 2 });
    delete data.recovery_key;
    jobEvent("backup_finished", { job: 84, kind: "import", ok: true, data, stopped_by: null, lock_follows: true });
    await flush();
    const notice = newestNotice();
    assert(/so that key is lost/.test(notice), "the lost key went unmentioned: " + notice);
    assert(/PATANYX kept some vault files/.test(notice), "kept copies went unmentioned: " + notice);
    assert(global.$("vault-recovery").hidden === true, "the recovery screen was entered for a lost key");
    jobEvent("vault_locked", {});
    await flush();
  });

  check(`${m.where}: a commit that failed with a lock following is still explained`, async () => {
    await fromLocked();
    await startImportJob(m, 85);
    clearNotices();
    jobEvent("backup_finished", { job: 85, kind: "import", ok: false, error: "disk_full", stopped_by: null, lock_follows: true });
    await flush();
    jobEvent("vault_locked", {});
    await flush();
    assert(newestNotice() !== "" && !/Unexpected error/.test(newestNotice()), "a failed commit went unexplained after the lock");
  });

  check(`${m.where}: a stop by a lock that left files says so`, async () => {
    await fromLocked();
    await startImportJob(m, 86);
    clearNotices();
    jobEvent("vault_locked", {});
    await flush();
    jobEvent("backup_finished", {
      job: 86, kind: "import", ok: false, error: "backup_cancelled_cleanup_pending", stopped_by: "lock",
    });
    await flush();
    assert(/locked/.test(newestNotice()) && /temporary files remain/.test(newestNotice()), "leftovers after a lock went unmentioned: " + newestNotice());
  });
}

check("an export result followed by a lock draws nothing", async () => {
  await startExportJob(83);
  jobEvent("backup_finished", { job: 83, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: null, lock_follows: true });
  await flush();
  assert(global.$("bk-exp-ok").textContent === "", "counts were drawn although a lock follows");
  jobEvent("vault_locked", {});
  await flush();
});

// ---- code review round 4 ----------------------------------------------------------

// R-001: with the idle countdown started by the result, nothing that counts as
// presence is sent until the person acts on the key screen.
check("an import whose countdown started refreshes nothing until the key is acknowledged", async () => {
  await fromLocked();
  await startImportJob(MIRRORS[1], 90);
  global.rbCalls.length = 0;
  const data = Object.assign({}, WHOLE_REPLY, { idle_warning: true });
  jobEvent("backup_finished", { job: 90, kind: "import", ok: true, data, stopped_by: null, lock_follows: false });
  await flush();
  assert(global.$("recovery-key").textContent === "AAAA-BBBB", "the key was not shown");
  const refreshed = global.rbCalls.filter((c) => c.cmd === "cred_list" || c.cmd === "note_list");
  assert(refreshed.length === 0, "a refresh restarted the countdown: " + refreshed.map((c) => c.cmd).join(","));
  global.$("recovery-ack")._fire("click");
  await flush();
  assert(global.rbCalls.some((c) => c.cmd === "cred_list"), "the lists never refreshed after the key was acknowledged");
});

// R-002: the lost-key notice names a Library that did not come back.
check("a lost key with a Library that did not come back says both", async () => {
  await fromLocked();
  await startImportJob(MIRRORS[1], 91);
  clearNotices();
  const data = Object.assign({}, WHOLE_REPLY, { key_lost: true, library: "library_import_unfinished" });
  delete data.recovery_key;
  jobEvent("backup_finished", { job: 91, kind: "import", ok: true, data, stopped_by: null, lock_follows: true });
  await flush();
  const notice = newestNotice();
  assert(/so that key is lost/.test(notice) && /could not be moved into place/.test(notice), "the notice left something out: " + notice);
  jobEvent("vault_locked", {});
  await flush();
});

// R-003: an export that finished around a lock still says it was saved, or why not.
check("an export saved with a lock following says it was saved, without its counts", async () => {
  await startExportJob(92);
  clearNotices();
  jobEvent("backup_finished", { job: 92, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: "lock", lock_follows: true });
  await flush();
  const notice = newestNotice();
  assert(/The encrypted export was saved/.test(notice), "a saved export went unmentioned: " + notice);
  assert(/already complete/.test(notice), "the late stop went unmentioned: " + notice);
  assert(!/Bookmarks: 4/.test(notice), "the Library's counts appeared over the lock");
  jobEvent("vault_locked", {});
  await flush();
});

check("an export that failed after a lock still says so", async () => {
  await startExportJob(93);
  clearNotices();
  jobEvent("vault_locked", {});
  await flush();
  jobEvent("backup_finished", { job: 93, kind: "export", ok: false, error: "disk_full", stopped_by: null });
  await flush();
  assert(newestNotice() !== "" && !/Unexpected error/.test(newestNotice()), "a failed export went unexplained after the lock");
});

// ---- code review round 5 ----------------------------------------------------------

// R-001: an export refusal names a private Library item; a lock erases it,
// and a translation still on its way cannot write it back.
check("a lock erases an export refusal that names a Library item", async () => {
  await startExportJob(95);
  jobEvent("backup_finished", {
    job: 95, kind: "export", ok: true, stopped_by: null,
    data: { refused: "export_picture_unreadable", item: "Private Trip Notes" },
  });
  await flush();
  assert(/Private Trip Notes/.test(global.$("bk-exp-error").textContent), "setup: the refusal was not shown");
  jobEvent("vault_locked", {});
  await flush();
  assert(global.$("bk-exp-error").textContent === "", "the item's name stayed in the locked browser");
});

check("a refusal still being worded in another language is not written after a lock", async () => {
  await withHeldTranslations(async (held, release) => {
    await startExportJob(96);
    jobEvent("backup_finished", {
      job: 96, kind: "export", ok: true, stopped_by: null,
      data: { refused: "export_picture_unreadable", item: "Private Trip Notes" },
    });
    await flush();
    assert(held.length > 0, "the refusal was not worded through the bridge; this check proves nothing");
    jobEvent("vault_locked", {});
    await flush();
    await release();
    assert(!/Private Trip Notes/.test(global.$("bk-exp-error").textContent), "the item's name was written after the lock");
  });
});

// R-002: a lock while a saved export's counts are worded still says it was
// saved, late stop included, in a notice that stays.
check("a lock while a saved export's counts are worded still says it was saved", async () => {
  await withHeldTranslations(async (held, release) => {
    await startExportJob(97);
    clearNotices();
    jobEvent("backup_finished", { job: 97, kind: "export", ok: true, data: EXPORT_DONE, stopped_by: "person" });
    await flush();
    assert(held.length > 0, "the counts were not worded through the bridge; this check proves nothing");
    jobEvent("vault_locked", {});
    await flush();
    await release();
    const host = global.$("toasts");
    const last = host.children[host.children.length - 1];
    assert(last && /The encrypted export was saved/.test(last.title || ""), "a saved export went unmentioned: " + (last && last.title));
    assert(/already complete/.test(last.title || ""), "the late stop went unmentioned");
    assert(last.dataset && last.dataset.sticky === "1", "the notice does not stay");
  });
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
