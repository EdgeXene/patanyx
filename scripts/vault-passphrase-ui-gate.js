// Behavioural checks on the passphrase-change form and the Library repair
// prompt, run against the DOM harness so chrome.js is EXECUTED, not parsed.
//
// WHY THIS EXISTS. Passphrase change was hidden in 1.0.0 and 1.0.1 because
// rotating the vault alone stranded the Library (pentest F-001). It returns
// with the vault and the Library sharing one passphrase (the Library opens
// with the vault), and the form has three kinds of outcome the person must be
// able to tell apart: not changed (the old passphrase still works), changed,
// and changed with cleanup still owed (the NEW passphrase works; each warning
// says what is left). The intro paragraph is a pinned claim about those
// outcomes. A form that reports a committed change as a failure, or promises
// a rollback that did not happen, tells the person the wrong passphrase at
// the one moment they need the right one.
//
// It also pins what the plan review found (2026-09-26): every passphrase
// field in the Backup pane and the repair form is cleared when the vault
// locks (R-002), both cleanup warnings can show together (R-003), and the
// intro no longer promises that every failure leaves the old passphrase
// working (R-005).
//
// Run: node scripts/vault-passphrase-ui-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
const htmlPath = path.join(chromeDir, "index.html");
process.env.HTML_PATH = htmlPath;
// Node's own timer, kept BEFORE domstub replaces it with one that runs every
// callback at once (which also makes a request deadline unobservable: it
// fires before the request is registered).
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

const $ = (id) => global.$(id);
const text = (id) => $(id).textContent || "";

function fillChange(current, next, confirm) {
  $("bk-pw-current").value = current;
  $("bk-pw-new1").value = next;
  $("bk-pw-new2").value = confirm === undefined ? next : confirm;
  $("bk-pw-error").textContent = "";
  $("bk-pw-ok").textContent = "";
}

async function submitChange(reply) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = { vault_change_passphrase: reply };
  $("bk-pw-form")._fire("submit");
  await flush();
  return global.rbCalls.filter((c) => c.cmd === "vault_change_passphrase");
}

// ---- the markup ----------------------------------------------------------

function paneSection() {
  const pane = html.slice(html.indexOf('id="pane-backup"'));
  const start = pane.indexOf('data-msg="chrome.pane.backup.h2.n4"');
  const end = pane.indexOf('data-msg="chrome.pane.backup.h2.n5"');
  assert(
    start !== -1 && end > start,
    "the Change passphrase section is missing from the Backup pane",
  );
  return pane.slice(start, end);
}

check(
  "the change form is offered again, and the 'not available' note is gone",
  () => {
    const section = paneSection();
    assert(
      /<form id="bk-pw-form"[^>]*>/.test(section),
      "the change form is missing",
    );
    assert(
      !/<form id="bk-pw-form"[^>]*\bhidden\b/.test(section),
      "the change form is still hidden in the markup",
    );
    assert(
      !/bk-pw-unavailable/.test(section),
      "the 'not available in this version' note still renders",
    );
    assert(
      !/data-msg="chrome.pane.backup.p.n4"[^>]*\bhidden\b/.test(section),
      "the form's intro paragraph is still hidden",
    );
  },
);

check(
  "the intro no longer promises every failure leaves the old passphrase working",
  () => {
    // Plan review, 2026-09-26: two outcomes are COMMITTED with a warning, and in
    // both the new passphrase is the one that works.
    const section = paneSection();
    assert(
      !/If this fails, your old passphrase still works/.test(section),
      "the unconditional rollback promise is back",
    );
  },
);

check(
  "the intro says a copy made before the change still opens with the old passphrase",
  () => {
    // Neither file's key changes (nothing is re-encrypted), so an old copy of
    // the vault still opens with the old passphrase, and through it the
    // Library. Saying so is the honest limit of what a passphrase change does.
    const intro = paneSection().match(
      /data-msg="chrome.pane.backup.p.n4"[^>]*>([\s\S]*?)<\/p>/,
    );
    assert(intro, "intro paragraph not found");
    // One passphrase for both the vault and the Library.
    assert(
      /vault and your Library share this passphrase/i.test(intro[1]),
      "the intro no longer says the vault and the Library share the passphrase",
    );
    assert(
      /cop(y|ies)/i.test(intro[1]),
      "the intro no longer mentions an earlier copy of the Library",
    );
    assert(
      /old passphrase/i.test(intro[1]),
      "the intro no longer names the old passphrase",
    );
    // The key does not change on a passphrase change, so the intro
    // must also say an old copy plus the old passphrase reads NEWER copies.
    assert(
      /newer copies/i.test(intro[1]),
      "the intro no longer discloses that newer copies are readable",
    );
    // Final review R-006 and the copy review (2026-09-27): only a Library that
    // opened with the passphrase alone gives the passphrase a way in; one made
    // inside the vault does not, and a failed attempt already moves it.
    assert(
      /made while it opened only with your passphrase/i.test(intro[1]),
      "the intro no longer limits the Library-copy clause to passphrase-only Libraries",
    );
    assert(
      !/before your first passphrase change/i.test(intro[1]),
      "the intro anchors the Library-copy clause to the first change again",
    );
  },
);

// ---- the change form -----------------------------------------------------

check(
  "a new passphrase shorter than 8 characters is refused before any call",
  async () => {
    fillChange("current-pass", "short", "short");
    const calls = await submitChange({ warnings: [] });
    assert(
      calls.length === 0,
      "the change was sent with a 5-character passphrase",
    );
    assert(text("bk-pw-error"), "no message said why nothing happened");
  },
);

check("mismatched confirmation is refused before any call", async () => {
  fillChange("current-pass", "new-passphrase", "new-passphrasX");
  const calls = await submitChange({ warnings: [] });
  assert(
    calls.length === 0,
    "the change was sent with a mistyped confirmation",
  );
});

check("a change to the same passphrase is refused before any call, and says so", async () => {
  // Compliance review, 2026-09-26: it changes nothing, and would still move
  // the Library to a format 1.0.2 and older cannot read.
  fillChange("current-pass", "current-pass");
  const calls = await submitChange({ warnings: [] });
  assert(calls.length === 0, "a change to the same passphrase was sent");
  const err = text("bk-pw-error");
  // About what was typed, not about the vault: the current field may hold a
  // wrong passphrase (compliance review, 2026-09-26).
  assert(/current and new passphrases you entered are the same/i.test(err), "the refusal does not say why: " + err);
  assert(/Nothing was changed/i.test(err), "the refusal does not say nothing changed: " + err);
  assert(!text("bk-pw-ok"), "the refusal also said it changed");
});

check(
  "a change sends current and new, clears the fields and says it changed",
  async () => {
    fillChange("current-pass", "new-passphrase");
    const calls = await submitChange({ warnings: [] });
    assert(
      calls.length === 1,
      "expected one vault_change_passphrase call, got " + calls.length,
    );
    assert(
      calls[0].args.current === "current-pass" &&
        calls[0].args.new === "new-passphrase",
      "the call carried the wrong fields: " + JSON.stringify(calls[0].args),
    );
    for (const id of ["bk-pw-current", "bk-pw-new1", "bk-pw-new2"]) {
      assert(
        $(id).value === "",
        id + " still holds a passphrase after the change",
      );
    }
    assert(text("bk-pw-ok"), "success said nothing");
    assert(!text("bk-pw-error"), "success also showed an error");
  },
);

check(
  "both cleanup warnings show together and the change still reads as done",
  async () => {
    // Plan review, 2026-09-26: both warnings at once.
    fillChange("current-pass", "new-passphrase");
    await submitChange({
      warnings: [
        "passphrase_changed_backups_retained",
        "passphrase_changed_library_leftover_retained",
      ],
    });
    const ok = text("bk-pw-ok");
    assert(!text("bk-pw-error"), "a committed change was shown as an error");
    assert(/backup/i.test(ok), "the old-backup warning is missing: " + ok);
    assert(/leftover copy of your Library/.test(ok), "the Library warning is missing: " + ok);
    // Nothing retries at unlock any more: the next passphrase change does, so
    // the warning must not promise an attempt the next unlock never makes.
    assert(!/will try|next time you unlock/i.test(ok), "the Library warning promises a retry: " + ok);
    assert(
      !/passphrase_changed_/.test(ok),
      "a raw code reached the person: " + ok,
    );
    assert(
      $("bk-pw-current").value === "",
      "a committed change left the old passphrase in the field",
    );
  },
);

check(
  "a change that did not happen shows the reason and keeps the fields",
  async () => {
    fillChange("current-pass", "new-passphrase");
    await submitChange(new Error("passphrase_change_library_unavailable"));
    const err = text("bk-pw-error");
    assert(
      err && !/passphrase_change_library_unavailable/.test(err),
      "no readable reason: " + err,
    );
    assert(!text("bk-pw-ok"), "a refused change was reported as done");
    assert(
      $("bk-pw-current").value === "current-pass",
      "a refusal cleared what the person typed",
    );
  },
);

check(
  "the button stays down while the change runs, and comes back up",
  async () => {
    fillChange("current-pass", "new-passphrase");
    let answer;
    const pending = new Promise((resolve) => {
      answer = resolve;
    });
    global.rbCalls.length = 0;
    global.rbReject = null;
    global.rbResolve = { vault_change_passphrase: pending };
    $("bk-pw-form")._fire("submit");
    await flush();
    assert(
      $("bk-pw-submit").disabled === true,
      "a second press could start a second change",
    );
    answer({ warnings: [] });
    await flush();
    assert(
      $("bk-pw-submit").disabled === false,
      "the button stayed disabled after the answer",
    );
  },
);

// ---- lock clears every passphrase field (plan review, 2026-09-26) -------------

// Every passphrase field in the Backup pane and the repair form, read from the
// MARKUP rather than listed by hand, so a field added later without being
// cleared on lock fails here (the hand list once missed recovery-create-pass).
function passwordFieldsIn(sectionId, endMarker) {
  const from = html.indexOf('id="' + sectionId + '"');
  assert(from !== -1, sectionId + " is not in index.html");
  // Search for the end AFTER this section's own id, which may itself match.
  const found = endMarker ? html.indexOf(endMarker, from + 1) : -1;
  const to = found === -1 ? html.length : found;
  const ids = [];
  for (const tag of html.slice(from, to).match(/<input\b[^>]*>/g) || []) {
    if (!/type="password"/.test(tag)) continue;
    const id = tag.match(/id="([^"]+)"/);
    if (id) ids.push(id[1]);
  }
  return ids;
}
const SECRET_FIELDS = [
  ...passwordFieldsIn("pane-backup", 'id="pane-'),
  ...passwordFieldsIn("library-repair-form", "</form>"),
];

check(
  "locking the vault clears every passphrase field in the Backup pane and the repair form",
  async () => {
    // NON-VACUITY: the markup scan must find what is known to be there.
    for (const known of ["recovery-create-pass", "bk-pw-current", "bk-import-pass1", "library-repair-old"]) {
      assert(SECRET_FIELDS.includes(known), "the field scan missed " + known + ": " + SECRET_FIELDS.join(", "));
    }
    for (const id of SECRET_FIELDS) {
      assert(html.includes('id="' + id + '"'), id + " is not in index.html");
      $(id).value = "typed-" + id;
    }
    global.window.__rb_event({ event: "vault_locked", data: {} });
    await flush();
    const left = SECRET_FIELDS.filter((id) => $(id).value !== "");
    assert(
      left.length === 0,
      "still holding a passphrase after lock: " + left.join(", "),
    );
  },
);

// ---- the Library repair prompt -------------------------------------------

// The chrome's own record of the vault state (`vaultUnlocked`) is set when
// the vault panel reads vault_status, the same route credential-ui-gate uses.
let vaultOpen = false;
async function setVault(unlocked) {
  vaultOpen = unlocked;
  global.rbResolve = { vault_status: { exists: true, unlocked } };
  $("btn-vault")._fire("click");
  await flush();
  $("btn-vault")._fire("click");
  await flush();
  if (!unlocked) {
    global.window.__rb_event({ event: "vault_locked", data: {} });
    await flush();
  }
}

async function openLibraryWith(status) {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = {
    store_status: status,
    vault_status: { exists: true, unlocked: vaultOpen },
  };
  $("btn-library")._fire("click");
  await flush();
}

async function closeLibrary() {
  $("btn-library")._fire("click");
  await flush();
}

check(
  "the repair prompt shows only when the Library did not open with the vault's passphrase",
  async () => {
    await setVault(true);
    await openLibraryWith({ open: false, error: "store_passphrase_mismatch" });
    assert(
      $("library-repair-form").hidden === false,
      "the repair prompt is hidden for a stranded Library",
    );
    assert(
      !/store_passphrase_mismatch/.test(text("library-locked-note")),
      "the raw code reached the note",
    );
    await closeLibrary();
    await openLibraryWith({ open: false, error: "store_bad_format" });
    assert(
      $("library-repair-form").hidden === true,
      "the repair prompt shows for an unreadable file",
    );
    await closeLibrary();
    // Made with another vault: no passphrase can open it, so no repair.
    await openLibraryWith({ open: false, error: "store_vault_mismatch" });
    assert(
      $("library-repair-form").hidden === true,
      "the repair prompt shows for a Library made with another vault",
    );
    assert(
      /different vault/.test(text("library-locked-note")),
      "the note does not say the Library was made with another vault: " + text("library-locked-note"),
    );
    await closeLibrary();
    await openLibraryWith({ open: false, error: null });
    assert(
      $("library-repair-form").hidden === true,
      "the repair prompt shows for a locked vault",
    );
    await closeLibrary();
  },
);

check(
  "repair sends both passphrases, clears them on success, and explains a refusal",
  async () => {
    global.rbCalls.length = 0;
    global.rbReject = null;
    global.rbResolve = {
      store_repair_passphrase: {},
      store_status: { open: true },
    };
    $("library-repair-old").value = "previous-pass";
    $("library-repair-current").value = "current-pass";
    $("library-repair-form")._fire("submit");
    await flush();
    const calls = global.rbCalls.filter(
      (c) => c.cmd === "store_repair_passphrase",
    );
    assert(
      calls.length === 1,
      "expected one store_repair_passphrase call, got " + calls.length,
    );
    assert(
      calls[0].args.library_passphrase === "previous-pass" &&
        calls[0].args.current === "current-pass",
      "the repair carried the wrong fields: " + JSON.stringify(calls[0].args),
    );
    assert(
      $("library-repair-old").value === "",
      "the Library's old passphrase stayed in the field",
    );
    assert(
      $("library-repair-current").value === "",
      "the current passphrase stayed in the field",
    );

    global.rbCalls.length = 0;
    global.rbResolve = {
      store_repair_passphrase: new Error("store_library_passphrase_wrong"),
    };
    $("library-repair-old").value = "not-it";
    $("library-repair-current").value = "current-pass";
    $("library-repair-form")._fire("submit");
    await flush();
    const err = text("library-repair-error");
    assert(
      err && !/store_library_passphrase_wrong/.test(err),
      "no readable reason for a wrong passphrase: " + err,
    );
  },
);

check("the repair prompt goes away when the vault locks, and stays away while it is locked", async () => {
  // The mismatch stays recorded after a lock, and the repair needs the
  // vault open: a form offered then invites passphrases into a call the
  // backend refuses (final review, 2026-09-26).
  await setVault(true);
  await openLibraryWith({ open: false, error: "store_passphrase_mismatch" });
  assert($("library-repair-form").hidden === false, "setup: the prompt should show while unlocked");
  global.window.__rb_event({ event: "vault_locked", data: {} });
  await flush();
  assert($("library-repair-form").hidden === true, "the prompt stayed up after the vault locked");
  // Checked with the panel still open, straight after the lock (final review round 4).
  assert(
    !/Enter that passphrase/.test(text("library-locked-note")),
    "right after the lock, the note still asks for a passphrase: " + text("library-locked-note"),
  );
  await closeLibrary();
  vaultOpen = false;
  await openLibraryWith({ open: false, error: "store_passphrase_mismatch" });
  assert($("library-repair-form").hidden === true, "the prompt came back while the vault is locked");
  assert(
    !/Enter that passphrase/.test(text("library-locked-note")),
    "while locked, the note still asks for a passphrase the panel cannot take: " + text("library-locked-note"),
  );
  await closeLibrary();
});

check("a Library open in another PATANYX window says so, and offers no repair", async () => {
  // One writer per Library (plan gate, R-611).
  await setVault(true);
  await openLibraryWith({ open: false, error: "library_in_use" });
  const note = text("library-locked-note");
  assert(/another PATANYX window/.test(note), "the note does not say where the Library is open: " + note);
  assert($("library-repair-form").hidden === true, "the repair prompt shows for a Library in use");
  await closeLibrary();
});

check("the panel keeps no warning about a retired passphrase", () => {
  // The Library opens with the vault, so no Library file holds a second
  // passphrase any more, and nothing is left to warn about in the panel.
  assert(!html.includes('id="library-warning"'), "the retired-passphrase warning element is back");
});

check("the recovery-key note is about a Library that has not moved into the vault", async () => {
  await setVault(true);
  await openLibraryWith({ open: false, error: "store_needs_passphrase" });
  const note = text("library-locked-note");
  assert(/recovery key/i.test(note), "the note does not mention the recovery key: " + note);
  assert(
    /next passphrase change, your recovery key opens it too/i.test(note),
    "the note no longer says the recovery key opens the Library after a change: " + note,
  );
  await closeLibrary();
});

// A GENUINELY late reply: the IPC answer for `cmd` is held back (domstub would
// otherwise answer on the next tick), request deadlines (30 s and up) are put
// on Node's real clock at zero delay so they fire first, and the answer is
// delivered only after that. Other timers keep domstub's run-at-once behaviour.
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

check("a change answered after any deadline still reads as done, warning included", async () => {
  // A reply that arrives after a deadline used to be dropped, so a change
  // that DID happen read as a failure (final review, both rounds). Drive it.
  await withLateReply(
    "vault_change_passphrase",
    { warnings: ["passphrase_changed_library_leftover_retained"] },
    async (answerLate) => {
      fillChange("current-pass", "new-passphrase");
      global.rbCalls.length = 0;
      global.rbReject = null;
      global.rbResolve = {};
      $("bk-pw-form")._fire("submit");
      await flush();
      await answerLate();
    },
  );
  assert(!text("bk-pw-error"), "a late committed reply was shown as a failure: " + text("bk-pw-error"));
  assert(/Library/.test(text("bk-pw-ok")), "the late reply's warning is missing: " + text("bk-pw-ok"));
  assert($("bk-pw-current").value === "", "a committed change left the old passphrase in the field");
  assert($("bk-pw-submit").disabled === false, "the button stayed down after the late answer");
});

check("a repair answered after any deadline still completes", async () => {
  await withLateReply("store_repair_passphrase", {}, async (answerLate) => {
    global.rbCalls.length = 0;
    global.rbReject = null;
    global.rbResolve = { store_status: { open: true } };
    $("library-repair-old").value = "previous-pass";
    $("library-repair-current").value = "current-pass";
    $("library-repair-error").textContent = "";
    $("library-repair-form")._fire("submit");
    await flush();
    await answerLate();
  });
  assert(!text("library-repair-error"), "a late repair was shown as a failure: " + text("library-repair-error"));
  assert($("library-repair-old").value === "", "a completed repair left the old passphrase in the field");
});

// Just over the Rust frame limit once serialised (final review round 3: the
// Rust side drops such a frame without answering, and these two requests have
// no deadline, so a pasted blob used to leave the form waiting forever).
const OVERSIZED = "x".repeat(1024 * 1024 + 16);

check("an oversized passphrase is refused at once, nothing is sent, and the change form comes back", async () => {
  fillChange(OVERSIZED, "new-passphrase");
  const calls = await submitChange({ warnings: [] });
  assert(calls.length === 0, "an oversized frame was posted");
  const err = text("bk-pw-error");
  assert(err && !/request_too_large/.test(err), "no readable refusal: " + err);
  // rb refuses before posting, so "not sent" is true for every caller; a form
  // that sends two requests (the bookmark editor) may already have saved the
  // first, so the refusal must not claim nothing changed (compliance review,
  // 2026-09-26).
  assert(/not sent/i.test(err), "the refusal does not say it was not sent: " + err);
  assert(!/Nothing was changed/i.test(err), "the generic refusal claims nothing changed: " + err);
  assert($("bk-pw-submit").disabled === false, "the button stayed down after the refusal");
});

check("an oversized passphrase in the repair form is refused at once, and the form comes back", async () => {
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = {};
  $("library-repair-old").value = OVERSIZED;
  $("library-repair-current").value = "current-pass";
  $("library-repair-error").textContent = "";
  $("library-repair-form")._fire("submit");
  await flush();
  assert(
    global.rbCalls.filter((c) => c.cmd === "store_repair_passphrase").length === 0,
    "an oversized repair frame was posted",
  );
  const err = text("library-repair-error");
  assert(err && !/request_too_large/.test(err), "no readable refusal: " + err);
  assert($("library-repair-submit").disabled === false, "the repair button stayed down");
});

check("the chrome's frame limit is the Rust side's", () => {
  const rust = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
  const js = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
  const rustSize = rust.match(/const MAX_FRAME_BYTES: usize = ([0-9 *]+);/);
  const jsSize = js.match(/const RB_MAX_FRAME_BYTES = ([0-9 *]+);/);
  assert(rustSize && jsSize, "a frame limit constant was renamed");
  const value = (expr) => expr.split("*").reduce((acc, part) => acc * Number(part.trim()), 1);
  assert(
    value(rustSize[1]) === value(jsSize[1]),
    "chrome.js allows " + value(jsSize[1]) + " bytes but ipc.rs drops above " + value(rustSize[1]),
  );
});

check("a wrong current passphrase in the repair form says which one was wrong", async () => {
  // Two passphrase fields: "wrong passphrase" alone would leave the person
  // guessing which to retype. The vault refuses the current one before the
  // Library is touched, and the message must say so.
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve = { store_repair_passphrase: new Error("auth_failed") };
  $("library-repair-old").value = "previous-pass";
  $("library-repair-current").value = "not-current";
  $("library-repair-form")._fire("submit");
  await flush();
  const err = text("library-repair-error");
  assert(/current passphrase/i.test(err), "the refusal does not name the current passphrase: " + err);
  assert(/Nothing was changed/i.test(err), "the refusal does not say nothing changed: " + err);
});

check(
  "every code the change and the repair can return has words in the error table",
  () => {
    const js = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
    for (const code of [
      "passphrase_changed_backups_retained",
      "passphrase_changed_library_leftover_retained",
      "passphrase_change_library_unavailable",
      "passphrase_change_not_confirmed",
      "store_passphrase_mismatch",
      "store_needs_passphrase",
      "store_vault_mismatch",
      "library_in_use",
      "import_library_in_use",
      "store_library_passphrase_wrong",
      "store_repair_not_needed",
      "passphrase_unchanged",
      "request_too_large",
    ]) {
      assert(
        new RegExp("\\b" + code + ":").test(js),
        code + " has no entry in the error table",
      );
    }
  },
);

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
    console.error(
      "\nVAULT PASSPHRASE UI GATE FAILED:\n  " + failures.join("\n  "),
    );
    process.exit(1);
  }
  console.log("\nVAULT PASSPHRASE UI OK");
})();
