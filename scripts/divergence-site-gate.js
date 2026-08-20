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

// `premium` defaults to true for the older checks, which is exactly how a
// UI-side Premium gate on a FREE feature survived every run of this gate:
// no check here had ever been a free user. Pass premium:false to be one.
const state = (proof, sites, premium) => {
  global.rbResolve.divergence_proof_get = proof;
  global.rbResolve.divergence_sites_list = { items: sites || [] };
  // The write arm needs an answer too, or the handler's catch reverts the
  // checkbox and the test cannot tell a refusal from a missing stub.
  global.rbResolve.divergence_site_set = {};
  global.rbResolve.divergence_site_clear = {};
  const isPremium = premium === undefined ? true : premium;
  global.rbResolve.premium_status = {
    state: isPremium ? "perpetual" : "free",
    premium: isPremium,
    on_sale: false,
  };
};

check(
  "a FREE user can actually turn divergence off for a site",
  async () => {
    // THE DEFECT THIS PINS. Fingerprint Divergence and its per-site
    // exceptions became free permanently on 2026-08-19, and the four IPC
    // arms in ipc.rs were un-gated to match. The chrome kept its own gate:
    // the dv-off handler called premiumBlocked() first, reverted the
    // checkbox, toasted "A Premium feature, arriving the day Premium
    // launches", and never sent divergence_site_set. So the feature was
    // free in Rust, published as free on four surfaces, and unusable.
    //
    // Neither guard caught it. licence-planted-defect-gate only reads
    // ipc.rs and never opens chrome.js; every check in THIS file ran as a
    // Premium user. A free user is the only one who can see it.
    state(
      {
        host: "example.com",
        enabled_globally: true,
        off_for_this_site: false,
        registered: true,
        surfaces: ["canvas"],
      },
      [],
      false,
    );
    await openPrivacy();
    global.rbCalls.length = 0;

    const box = global.$("dv-off");
    box.checked = true;
    box._fire("change");
    await flush();

    const sent = global.rbCalls.filter((c) => c.cmd === "divergence_site_set");
    // REACHING RUST IS THE WHOLE ASSERTION. The checkbox's final state is
    // not: the handler re-reads divergence_proof_get afterwards, and this
    // stub keeps reporting off_for_this_site:false, so asserting on the box
    // would test the harness rather than the gate.
    const ok = sent.length === 1;
    const args = ok ? JSON.stringify(sent[0].args) : "";
    await closePrivacy();
    assert(
      ok,
      "a free user's per-site choice never reached Rust; the chrome refused " +
        "it. Commands sent: " + JSON.stringify(global.rbCalls.map((c) => c.cmd)),
    );
    assert(
      args.includes("example.com"),
      "the command went out without the host it was about: " + args,
    );
  },
);

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

check("the per-site note states that choosing per site is free", async () => {
  const html = fs.readFileSync(process.env.HTML_PATH, "utf8");
  const premium = html.match(/id="dv-premium"[^>]*>([\s\S]*?)<\/p>/);
  assert(premium, "the premium note is missing");
  const text = premium[1].toLowerCase();
  assert(
    text.includes("per site"),
    "the note must name the per-site choice: " + text,
  );
  // REVERSED 2026-08-19. This assertion used to REQUIRE that the note never
  // call Divergence free, because Divergence was what Premium sold. The
  // it became free permanently, exceptions included, and the site now
  // says so on three pages -- so the old assertion would have blocked the
  // correct copy. It is inverted rather than deleted, because the thing worth
  // pinning is still that this note and the published pages agree.
  assert(
    text.includes("free"),
    "choosing per site is free now; the note must say so: " + text,
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
