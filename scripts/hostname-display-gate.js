// The address bar must never decode an internationalized hostname.
//
// WHY THIS EXISTS, and why it guards something nobody wrote. A homograph
// domain -- Cyrillic "а" standing in for Latin "a", so that аpple.com reads
// as apple.com to a human -- is defeated here by an omission rather than by a
// check: the chrome shows the URL exactly as the engine reports it, and the
// URL Standard serializes a host in ASCII, so the hostile domain arrives and
// is displayed as "xn--pple-43d.com". The spoof is visible because nothing
// prettifies it.
//
// That is a strong property and an ACCIDENTAL-LOOKING one. A future change
// that decodes punycode for friendliness -- showing "日本.jp" instead of
// "xn--wgv71a119e.jp", which is a perfectly reasonable-sounding improvement
// and is what large browsers do -- would silently reinstate the attack,
// because we have no confusable/mixed-script checker to tell a safe IDN from
// a spoof. This gate makes that trade explicit: punycode for everyone,
// including legitimate IDN sites, until something can actually distinguish
// them. Usability is the price; the price is deliberate.
//
// Two layers, because either alone is weak:
//   behavioral -- drive the REAL url_changed path and the REAL host helper,
//                 and assert the xn-- form survives to what a user reads;
//   structural -- assert no chrome script carries a punycode decoder or a
//                 Unicode-normalizing call that could reintroduce one.
//
// Run: node scripts/hostname-display-gate.js  (or via chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
// domstub builds its document from the real index.html, so the toolbar's
// url input exists exactly as it ships.
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// chrome.js owns window.__rb_event and the toolbar, exactly as the other
// chrome gates load it.
new Function(fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8"))();

const results = [];
function check(name, fn) {
  try {
    fn();
    results.push("  ok  " + name);
  } catch (e) {
    results.push("  FAIL  " + name + "\n        " + e.message);
    process.exitCode = 1;
  }
}

// The classic spoof: "аpple.com" with a Cyrillic а. Its ASCII serialization,
// which is what the engine hands us and what the user must therefore see.
const SPOOF_PUNY = "https://xn--pple-43d.com/login";
// A legitimate IDN, shown as punycode too. Named so nobody "fixes" it later
// believing it to be a bug.
const LEGIT_PUNY = "https://xn--wgv71a119e.jp/";

check("a homograph host stays punycode in the address bar", () => {
  global.window.__rb_event({ event: "url_changed", data: { url: SPOOF_PUNY } });
  const shown = global.$("url").value;
  assert(
    shown === SPOOF_PUNY,
    "the address bar altered the URL it was given: " + shown,
  );
  assert(
    shown.indexOf("xn--") !== -1,
    "the punycode form was decoded away, so a homograph domain would read " +
      "as the domain it is impersonating: " +
      shown,
  );
});

check("a legitimate IDN is also shown as punycode, deliberately", () => {
  global.window.__rb_event({ event: "url_changed", data: { url: LEGIT_PUNY } });
  const shown = global.$("url").value;
  assert(
    shown === LEGIT_PUNY,
    "a legitimate IDN was decoded. That is friendlier, and it is exactly " +
      "the change that reinstates the homograph attack: without a " +
      "confusable checker there is no way to decode this one and refuse " +
      "the spoof. If a checker now exists, update this gate deliberately.",
  );
});

check("about:blank still clears the bar", () => {
  global.window.__rb_event({
    event: "url_changed",
    data: { url: "about:blank" },
  });
  assert(global.$("url").value === "", "about:blank must leave the bar empty");
});

// Structural: no decoder anywhere in the chrome scripts. A behavioral test
// alone would pass if a decoder existed but were applied on a path this gate
// does not drive (history rows, the tab list, the site panel).
check("no chrome script carries a punycode decoder", () => {
  const files = fs
    .readdirSync(chromeDir)
    .filter((f) => f.endsWith(".js"))
    .concat([]);
  const banned =
    /\btoUnicode\b|\bpunycode\b|\bdecodeIdn\b|\bidnToUnicode\b|normalize\(\s*["']NF/;
  for (const f of files) {
    const src = fs.readFileSync(path.join(chromeDir, f), "utf8");
    const hit = banned.exec(src);
    assert(
      !hit,
      f +
        " contains " +
        JSON.stringify(hit && hit[0]) +
        ", which can turn a punycode host back into the Unicode it spoofs. " +
        "If this is deliberate, it needs a confusable check beside it and " +
        "this gate updated in the same commit.",
    );
  }
});

for (const line of results) console.log(line);
if (process.exitCode) {
  console.error("\nHOSTNAME DISPLAY GATE FAILED");
} else {
  console.log("\nhostname-display-gate: OK");
}
