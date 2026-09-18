// The About sponsorship button must be reachable through its real panel-open
// call site and must send only a compiled destination's identifier. A source
// search for the renderer is not enough: the original partner-card defect was
// dead code, so this gate clicks what a reader clicks.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const html = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const aboutRs = fs.readFileSync(path.join(root, "crates/app/src/about.rs"), "utf8");
const sponsorshipRs = fs.readFileSync(
  path.join(root, "crates/app/src/sponsorship.rs"),
  "utf8",
);
const ipcRs = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
const mainRs = fs.readFileSync(path.join(root, "crates/app/src/main.rs"), "utf8");
const licenceRs = fs.readFileSync(
  path.join(root, "crates/app/src/licence_control.rs"),
  "utf8",
);
const ci = fs.readFileSync(path.join(root, "scripts/ci-trixie.sh"), "utf8");
const destination = "https://donate.stripe.com/7sYaEZ1Qxh126KteDRbsc00";
const callSite = 'await rb("sponsorship_open", { sponsorship: "patanyx" });';

// Used for the planted-defect proof: remove the actual IPC call from the JS
// evaluated by this gate, while leaving the rest of the renderer untouched.
// The normal run never rewrites a workspace file.
if (process.env.PATANYX_SPONSORSHIP_OMIT_CALLSITE) {
  if (!chromeJs.includes(callSite)) {
    throw new Error("cannot plant defect: sponsorship call site spelling changed");
  }
  chromeJs = chromeJs.replace(callSite, "await Promise.resolve();");
}

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 24; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};
function rustString(name) {
  const match = aboutRs.match(new RegExp(`const ${name}: &str = "([^"]*)";`));
  assert(match, `about.rs has no simple ${name} string constant`);
  return match[1];
}

const supportHead = rustString("SUPPORT_HEAD");
const supportCopy = rustString("SUPPORT");
const supportLabel = rustString("SUPPORT_LABEL");
global.rbResolve.about_info = {
  name: "PATANYX",
  version: "gate",
  engine: "gate engine",
  support_head: supportHead,
  support: supportCopy,
  support_label: supportLabel,
};
global.rbResolve.premium_status = {
  premium: false,
  on_sale: true,
};

new Function(chromeJs)();
const $ = (id) => global.document.getElementById(id);

check("support control is inside the About modal", () => {
  const start = html.indexOf('<section id="about-panel"');
  const end = html.indexOf("</section>", html.indexOf("<h2", start));
  const about = start >= 0 && end > start ? html.slice(start, end) : "";
  assert(about, "the About modal is missing");
  assert(
    about.includes('id="about-support"') &&
      about.includes('id="about-support-open"'),
    "the support control is not inside the About modal",
  );
  assert(
    about.indexOf('id="about-support"') > about.indexOf('id="about-description"'),
    "support is not a separate section after the About business-model copy",
  );
});

check("opening About reveals the sponsorship copy and control", async () => {
  global.rbCalls.length = 0;
  $("btn-about").click();
  await flush();
  assert(!$("about-panel").hidden, "the About modal did not open");
  assert(!$("about-support").hidden, "the support section stayed hidden");
  assert(!$("about-support-open").hidden, "the support control is not reachable");
  assert(
    $("about-support-open").textContent === "support PATANYX",
    "the support control lost its label",
  );
});

check("copy keeps sponsorship, Premium and affiliates distinct", () => {
  const shown = $("about-support-copy").textContent.toLowerCase();
  for (const required of [
    "optional support for continued development",
    "buys no features",
    "unlocks nothing",
    "not a premium license",
    "does not become one",
    "separate from both premium and the disclosed affiliate placements",
  ]) {
    assert(shown.includes(required), "support copy lost: " + required);
  }
  for (const forbidden of [
    "buy premium",
    "purchase",
    "unlock features",
    "premium included",
    "premium for supporters",
  ]) {
    assert(!shown.includes(forbidden), "support copy makes a sale claim: " + forbidden);
  }
});

check("button sends only the sponsorship identifier", async () => {
  global.rbCalls.length = 0;
  $("about-support-open").click();
  await flush();
  const opens = global.rbCalls.filter((call) => call.cmd === "sponsorship_open");
  assert(
    opens.length === 1,
    "the reachable About button made " + opens.length + " sponsorship_open calls",
  );
  const args = opens[0].args;
  assert(
    args && args.sponsorship === "patanyx",
    "sponsorship_open did not carry the compiled target's identifier",
  );
  assert(
    Object.keys(args).length === 1 && !("url" in args) && !/:\/\//.test(JSON.stringify(args)),
    "chrome sent more than the sponsorship identifier: " + JSON.stringify(args),
  );
});

check("the chrome contains no sponsorship destination", () => {
  for (const name of fs.readdirSync(chromeDir)) {
    const file = path.join(chromeDir, name);
    if (!fs.statSync(file).isFile()) continue;
    const source = fs.readFileSync(file, "utf8");
    assert(!source.includes(destination), `${name} contains the sponsorship URL`);
    assert(!source.includes("donate.stripe.com"), `${name} contains the sponsorship host`);
  }
});

check("Rust resolves and gates the compiled destination", () => {
  for (const field of [
    destination,
    '.get("sponsorship")',
    "SponsorshipTarget::from_id",
    "crate::ipc::normalize_input",
    "crate::state::is_allowed_content_url",
  ]) {
    assert(sponsorshipRs.includes(field), "sponsorship.rs lost " + field);
  }
  const start = ipcRs.indexOf('"sponsorship_open" =>');
  const end = ipcRs.indexOf("\n        // Public metadata", start);
  const arm = start >= 0 && end > start ? ipcRs.slice(start, end) : "";
  assert(arm, "the sponsorship_open IPC arm is missing");
  assert(
    arm.includes("crate::sponsorship::destination_for(args)?") &&
      arm.includes("state.new_tab(&url, true)?"),
    "sponsorship_open no longer resolves then enters the ordinary new-tab path",
  );
  assert(
    !/premium|on_sale|partner_open/i.test(arm),
    "sponsorship_open was coupled to Premium or affiliate dispatch",
  );
});

check("sponsorship remains available while Premium is on sale", () => {
  assert(
    licenceRs.includes("pub const PREMIUM_ON_SALE: bool = true;"),
    "PREMIUM_ON_SALE is no longer pinned true for launch",
  );
  assert(
    aboutRs.includes('"support": SUPPORT') &&
      aboutRs.includes('"support_label": SUPPORT_LABEL'),
    "about_info no longer publishes the support section while Premium is on sale",
  );
});

check("real-dispatch smoke pins refusal and the approved navigation", () => {
  const start = ipcRs.indexOf("pub fn smoke_sponsorship_sequence");
  const end = ipcRs.indexOf("\n}\n", start);
  const smoke = start >= 0 && end > start ? ipcRs.slice(start, end + 3) : "";
  assert(smoke, "ipc::smoke_sponsorship_sequence is missing");
  for (const proof of [
    'json!({ "url": SPONSORSHIP })',
    'json!({ "sponsorship": "not-a-target" })',
    'json!({ "sponsorship": "patanyx" })',
    "smoke_tab_count(state)?",
    'println!("SPONSORSHIP ok")',
  ]) {
    assert(smoke.includes(proof), "live sponsorship smoke lost: " + proof);
  }
  assert(
    mainRs.includes("ipc::smoke_sponsorship_sequence(&mut app)"),
    "the live sponsorship smoke is not chained into the app smoke",
  );
  assert(
    ci.includes("grep -q '^SPONSORSHIP ok$'"),
    "ci-trixie does not require the live sponsorship result",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (error) {
      failures.push(name + ": " + error.message);
      console.log("  FAIL: " + name + ": " + error.message);
    }
  }
  if (failures.length) {
    console.error("sponsorship-gate: " + failures.length + " check(s) failed");
    process.exit(1);
  }
  console.log("sponsorship-gate OK (" + checks.length + " checks)");
})();
