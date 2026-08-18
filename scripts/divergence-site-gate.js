// Per-site Fingerprint Divergence keeps two limits it would be easy to lose.
//
//   1. THE PROOF IS ABOUT REGISTRATION. It reports that a script was
//      installed in THIS tab with a given profile. It is not evidence that
//      any site was fooled, and only the live test page can show that. A
//      panel that blurred the two would be claiming a measurement it never
//      made.
//   2. A CHOICE REACHES THE NEXT TAB. Neither engine can re-register scripts
//      on a live view, so the switch cannot change what the page in front of
//      you already got. The copy says so, and the proof line reports the tab
//      as it is rather than as the setting says it should be. Those two
//      disagreeing is a normal, honest state.
//
// Also pinned: a Premium refusal leaves the section VISIBLE and explaining
// itself, since hiding it would make a gated feature look like one that does
// not exist; and the free global toggle is never described as Premium.
//
// Proven against planted defects: claiming the tab is protected when nothing
// was registered fails check 2, and hiding the section on refusal fails 4.
//
// Guard shape: chrome-js-gate.sh refuses to run this when #divergence-site
// is gone from index.html.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
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

new Function(chromeJs)();

const $ = (id) => global.document.getElementById(id);
// The privacy panel is what refreshes this section.
const openPrivacy = async () => {
  $("btn-privacy").click();
  await flush();
};
const closePrivacy = async () => {
  $("btn-privacy").click();
  await flush();
};

const state = (proof, sites) => {
  global.rbResolve.divergence_proof_get = proof;
  global.rbResolve.divergence_sites_list = { items: sites || [] };
  global.rbResolve.premium_status = {
    state: "perpetual",
    premium: true,
    on_sale: false,
  };
};

check("a registered tab is described as installed, not as proven", async () => {
  state({
    host: "example.com",
    enabled_globally: true,
    off_for_this_site: false,
    registered: true,
    surfaces: ["canvas", "audio"],
  });
  await openPrivacy();
  const proof = $("dv-proof").textContent.toLowerCase();
  assert(proof.length > 0, "the proof line said nothing");
  assert(
    proof.includes("not proof") || proof.includes("was installed"),
    "the proof must describe what was INSTALLED: " + proof,
  );
  for (const word in { protected: 1, blocked: 1, anonymous: 1, hidden: 1 }) {
    assert(
      !proof.includes(word),
      `the proof claimed "${word}", which registration does not show`,
    );
  }
  await closePrivacy();
});

check("a tab with nothing registered says so plainly", async () => {
  // The honest disagreement: the setting can be on while THIS tab has
  // nothing, because a tab keeps what it started with.
  state({
    host: "example.com",
    enabled_globally: true,
    off_for_this_site: false,
    registered: false,
    surfaces: [],
  });
  await openPrivacy();
  const proof = $("dv-proof").textContent.toLowerCase();
  assert(
    proof.includes("no divergence"),
    "a tab with nothing registered must say so: " + proof,
  );
  assert(
    proof.includes("started with") || proof.includes("since it opened"),
    "it must explain that a tab keeps what it started with: " + proof,
  );
  await closePrivacy();
});

check("the switch is described as reaching the next tab", async () => {
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  const note = html.match(/id="dv-off"[\s\S]{0,600}?<\/label>/);
  assert(note, "the per-site switch is missing from index.html");
  const text = note[0].toLowerCase();
  assert(
    text.includes("next time") || text.includes("new tab"),
    "the switch must say the choice reaches the next tab: " + text,
  );
  assert(
    text.includes("full name") || text.includes("www."),
    "it must say sites are matched by full hostname",
  );
});

check("a Premium refusal explains rather than hides the section", async () => {
  global.rbReject = "premium_required";
  await openPrivacy();
  assert(
    !$("divergence-site").hidden,
    "the section vanished, making a gated feature look like a missing one",
  );
  assert(!$("dv-premium").hidden, "the refusal must be explained");
  assert($("dv-off").disabled, "a refused control must not look operable");
  global.rbReject = null;
  await closePrivacy();
});

check("the per-site note does not call Fingerprint Divergence free", async () => {
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  const premium = html.match(/id="dv-premium"[^>]*>([\s\S]*?)<\/p>/);
  assert(premium, "the premium note is missing");
  const text = premium[1].toLowerCase();
  assert(
    text.includes("per site"),
    "the note must scope Premium to the per-site choice: " + text,
  );
  // Fingerprint Divergence is what Premium sells (design preamble
  // 2026-08-06, reaffirmed 2026-08-16); a note that called the global
  // toggle free would be the exact claim a buyer could hold against the
  // page. Until launch it is simply switched on for everyone, which is
  // not a promise and is not said here.
  assert(
    !text.includes("stays free") && !text.includes("remains free"),
    "Fingerprint Divergence is Premium; the note must not call it free: " + text,
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL: " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error(
      "divergence-site-gate: " + failures.length + " check(s) failed",
    );
    process.exit(1);
  }
  console.log("divergence-site-gate OK (" + checks.length + " checks)");
})();
