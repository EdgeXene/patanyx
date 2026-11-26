// Names the chrome shows for sites and files, driven through the REAL
// chrome.js against the DOM stub (SecScan run 88, 2026-11-24).
//
// Each check is a sentence a hostile page or server could otherwise choose
// the first words of:
//
//   - hostOf drops userinfo: "https://github.com@evil.example/" is
//     evil.example everywhere a site name is shown (S-71e4148a2960);
//   - the download-start notice names the file as SAVED, not the URL's last
//     segment (S-ef8b1eff7640);
//   - the save-password banner names the site first, and the page-chosen
//     username last, quoted, capped and without direction controls
//     (S-0bde5b62f5ef).
//
// It executes chrome.js in scripts/domstub.js. It does not execute Rust.

const fs = require("fs");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require(path.join(root, "scripts/domstub.js"));

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
    await new Promise((r) => setImmediate(r));
  }
};
function lastToast() {
  const all = [...global.$("toasts").children];
  const node = all[all.length - 1];
  return node ? node.querySelector(".toast-text").textContent : "";
}
function status(pendingSave) {
  global.window.__rb_event({
    event: "tab_status",
    data: {
      id: 1,
      freeze_phase: "loaded",
      freeze_enforcement: "inactive",
      profile: "persistent",
      origin: "https://evil.example",
      tls: "normal",
      freeze_enforced: true,
      network_blocking_supported: true,
      ledger_counts_blocked: true,
      blocked_total: 0,
      interception: "registered",
      script_setting: "applied",
      smartscreen_off: "applied",
      tracking_prevention: "strict",
      navigation_tracking: "applied",
      autofill_off: "applied",
      ephemeral_confirmed: "applied",
      hardened_environment: "applied",
      pending_save: pendingSave,
    },
  });
}

new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

check("a site name never carries userinfo", async () => {
  global.window.__rb_event({
    event: "download_compare_request_received",
    data: { url: "https://github.com@evil.example/tool.exe" },
  });
  await flush();
  const text = lastToast();
  assert(text.indexOf("evil.example") !== -1, "real host missing: " + text);
  assert(
    text.indexOf("github.com") === -1,
    "userinfo shown as the site: " + text,
  );
});

check("the download-start notice names the saved file", async () => {
  global.window.__rb_event({
    event: "download_started",
    data: { url: "https://evil.example/invoice.pdf", name: "invoice.pdf.exe" },
  });
  await flush();
  const text = lastToast();
  assert(text.indexOf("invoice.pdf.exe") !== -1, "saved name missing: " + text);
});

check("an older event without a name still says something", async () => {
  global.window.__rb_event({
    event: "download_started",
    data: { url: "https://example.org/files/report.pdf?x=1" },
  });
  await flush();
  assert(lastToast().indexOf("report.pdf") !== -1, lastToast());
});

check(
  "the save banner names the site before the page-chosen username",
  async () => {
    status({
      username: "alice on https://accounts.google.com (previously saved",
      origin: "https://evil.example",
    });
    await flush();
    const text = global.$("save-password-body").textContent;
    assert(
      text.indexOf("Save the password on https://evil.example for “") === 0,
      "the site must come first: " + text,
    );
    assert(text.endsWith("”?"), "the username must be quoted last: " + text);
  },
);

check("the username cannot close its own quotes", async () => {
  status({
    username: "x\u201D on https://accounts.google.com, not \u201Cy",
    origin: "https://evil.example",
  });
  await flush();
  const text = global.$("save-password-body").textContent;
  assert(
    text.split("\u201C").length === 2 && text.split("\u201D").length === 2,
    "exactly one opening and one closing quote: " + text,
  );
});

check("the username loses direction controls and is capped", async () => {
  status({ username: "a‮b" + "x".repeat(200), origin: "https://evil.example" });
  await flush();
  const text = global.$("save-password-body").textContent;
  assert(text.indexOf("‮") === -1, "a direction override survived: " + text);
  assert(text.indexOf("…”?") !== -1, "a long username must be cut: " + text);
  assert(text.length < 140, "too long: " + text.length);
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok   " + name);
    } catch (e) {
      failures.push(name);
      console.log("  FAIL " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.error("display-names gate: " + failures.length + " failed");
    process.exit(1);
  }
  console.log("display-names gate: " + checks.length + " checks passed");
})();
