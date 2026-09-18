// The translation panel's own gate.
//
// WHY IT EXISTS AT ALL: this branch's headline feature had no DOM gate. The
// i18n gates cover its strings, translator-isolation-gate.sh covers the
// engine's origin, and nothing covered the panel a user actually operates.
// Both defects pinned below were found by driving it by hand, not by a test.
//
// Run: node scripts/translate-panel-gate.js
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const failures = [];
const checks = [];
const check = (name, fn) => checks.push([name, fn]);
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
new Function(chromeJs)();
const fire = (event, data) => global.window.__rb_event({ event, data });

// Two installed languages, so a source choice has somewhere to go.
const PACKS = {
  languages: [
    {
      code: "en",
      name: "English",
      installed: true,
      partial: false,
      downloading: false,
    },
    {
      code: "el",
      name: "Greek",
      installed: true,
      partial: false,
      downloading: false,
    },
  ],
  premium_active: true,
};

const STATUS = {
  tls: "normal",
  profile: "persistent",
  page_insecure: false,
  freeze_phase: "loaded",
  freeze_enforcement: "inactive",
  pending_save: null,
};
const status = (over) => Object.assign({}, STATUS, over || {});
const source = () => global.$("translate-source");

check(
  "a pack-status tick does not discard the user's source-language choice",
  () => {
    // THE DEFECT. `fillSourceOptions` preferred the detected language over
    // the current selection, and `packs_status` reaches it through
    // `renderTranslateUi` on EVERY event -- including a download-progress
    // tick. So: correct a mislabeled page, and the next tick silently put it
    // back. Reproduced in a browser before the fix.
    //
    // The consequence was worse than a reset field. With the source forced
    // back to English and only Greek installed there is no valid pair, so
    // "Translate into" read "No language installed for this" and the button
    // went disabled -- while the list below still said "Greek, Installed".
    //
    // applyTabStatus already guarded this ("a user's manual source choice is
    // not fought by every status push"); the guard was simply unreachable
    // from the other caller.
    fire("packs_status", PACKS);
    fire("tab_status", status({ detected_lang: "en" }));
    assert(source(), "#translate-source is gone");
    assert(
      source().value === "en",
      "precondition: the detected language should prefill; got " +
        JSON.stringify(source().value),
    );

    source().value = "el";
    source()._fire("change");
    assert(source().value === "el", "harness: the manual choice did not take");

    // An UNCHANGED snapshot, exactly what a progress tick delivers.
    fire("packs_status", PACKS);
    assert(
      source().value === "el",
      "a pack-status event overwrote the user's source choice (now " +
        JSON.stringify(source().value) +
        "). Any download-progress tick is enough to do this.",
    );
  },
);

check("a NEW detection still prefills the source", () => {
  // The other half of the contract, and the reason the fix is a parameter
  // rather than "never overwrite": a genuinely new detection SHOULD prefill.
  // Without this check the first one could be satisfied by never writing the
  // field at all, which would break the feature's normal path.
  fire("packs_status", PACKS);
  fire("tab_status", status({ detected_lang: "en" }));
  source().value = "el";
  source()._fire("change");
  // A different page, a different declared language.
  fire("tab_status", status({ detected_lang: "el" }));
  assert(
    source().value === "el",
    "a new detection must prefill the source; got " +
      JSON.stringify(source().value),
  );
  fire("tab_status", status({ detected_lang: "en" }));
  assert(
    source().value === "en",
    "a new detection must overwrite a stale manual choice; got " +
      JSON.stringify(source().value),
  );
});

check("a half-installed language can be removed", () => {
  // THE DEFECT. The row's action chain put `Remove` only in the `installed`
  // branch, so a language whose second direction failed offered "Get the
  // other direction" and nothing else. The direction that DID persist sat on
  // disk -- tens of megabytes -- with no control anywhere in this list to
  // delete it, and the only route to a Remove button was to finish a
  // download the user had decided against.
  fire("packs_status", {
    languages: [
      { code: "el", name: "Greek", installed: false, partial: true, downloading: false },
    ],
    premium_active: true,
  });
  const host = global.$("translate-langs");
  assert(host, "#translate-langs is gone");
  // BY TEXT, not by tagName: the DOM stub does not report tagName, so a
  // `.filter(e => e.tagName === "button")` matched nothing and this check
  // reported an empty row against a row that was correct.
  const labels = [...(host.children || [])]
    .flatMap((li) => [...(li.children || [])])
    .map((e) => String(e.textContent || "").trim())
    .filter(Boolean);
  assert(
    labels.length >= 2,
    "a partial row offers only " +
      JSON.stringify(labels) +
      "; it needs both a way to complete it and a way out",
  );
  assert(
    labels.some((t) => /remove/i.test(t)),
    "a partial row has no Remove; the installed half is stranded on disk. " +
      "buttons: " + JSON.stringify(labels),
  );
  assert(
    labels.some((t) => /other direction|complete/i.test(t)),
    "a partial row lost its completion action. buttons: " +
      JSON.stringify(labels),
  );
});

check("a missing pack list cannot throw", () => {
  // `fillSourceOptions` guards `!translatePacks` but not
  // `translatePacks.languages`. A truthy-but-shapeless reply -- which the IPC
  // stub produces, and a truncated host reply would too -- threw a TypeError
  // and took the whole Translation section down with it.
  let threw = null;
  try {
    fire("packs_status", {});
    fire("tab_status", status({ detected_lang: "en" }));
  } catch (e) {
    threw = String(e);
  }
  assert(
    !threw,
    "a pack payload without `languages` threw instead of being ignored: " +
      threw,
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (err) {
      failures.push(name);
      console.log("  FAIL " + name + ": " + err.message);
    }
  }
  if (failures.length) {
    console.error("\nTRANSLATE PANEL GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log("\nTRANSLATE PANEL OK");
})();
