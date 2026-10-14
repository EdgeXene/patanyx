// The keep-this-site offer for Messenger (1.0.7).
//
// WHAT THIS PINS, each property proven against a planted defect on every run:
//
// 1. The offer shows the sentence Rust composed, verbatim, with exactly two
//    buttons, Keep this site and Not now.
// 2. Keep sends exactly one wipe_exempt_add carrying the site Rust named, and
//    nothing else; the offer goes away and a confirmation follows.
// 3. Not now sends nothing and takes the offer away.
// 4. One offer at a time: a second replaces the first rather than stacking.
// 5. A malformed event shows nothing.
// 6. The confirmation claims no more than Rust reported: reopened, kept
//    but not moved, or kept only from the next start.
//
// When an offer appears, and for which site, is Rust's (keep_offer.rs, with
// its own tests). This gate pins the chrome's half.
//
// Run: node scripts/keep-offer-gate.js   (or via scripts/chrome-js-gate.sh)
// PATANYX_KEEP_OFFER_PLANT=<name> plants one defect; the gate must then print
// KEEP OFFER GATE FAILED. PATANYX_KEEP_OFFER_LIST_PLANTS=1 lists the names.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");

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

const PLANTS = {
  "claims-reopened": [
    "                  reply && reply.reopened\n",
    "                  true\n",
  ],
  "wrong-site": [
    'rb("wipe_exempt_add", { host: site })',
    'rb("wipe_exempt_add", { host: "facebook.com" })',
  ],
  "keep-does-nothing": [
    '            rb("wipe_exempt_add", { host: site })\n',
    "            Promise.resolve({})\n",
  ],
  "later-keeps": [
    '{ label: i18nText("chrome-js-keep-offer-later", "Not now"), onClick: retireKeepOffer },',
    '{ label: i18nText("chrome-js-keep-offer-later", "Not now"), onClick: () => { retireKeepOffer(); rb("wipe_exempt_add", { host: site }); } },',
  ],
  "offers-stack": [
    "    retireKeepOffer();\n    const site = data.site;\n",
    "    const site = data.site;\n",
  ],
  "ignores-unavailable": [
    "                    : reply && reply.available === false\n",
    "                    : false\n",
  ],
  "no-validation": [
    '    if (!data || typeof data.site !== "string" || typeof data.body !== "string") return;\n',
    "    if (!data) return;\n",
  ],
};

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const plant = process.env.PATANYX_KEEP_OFFER_PLANT;
if (plant) {
  const spec = PLANTS[plant];
  assert(spec, "unknown plant " + plant + "; known: " + Object.keys(PLANTS));
  assert(
    chromeJs.split(spec[0]).length === 2,
    "cannot plant " + plant + ": its anchor changed spelling",
  );
  chromeJs = chromeJs.replace(spec[0], spec[1]);
}
if (process.env.PATANYX_KEEP_OFFER_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}

require("./domstub.js");
new Function(chromeJs)();

const BODY =
  "PATANYX clears site data every time it starts, so Messenger may have to download your encrypted chats again each time. Keep \u2068messenger.com\u2069 in its own storage, which stays on this computer between sessions? It applies to every page on \u2068messenger.com\u2069. This tab reopens there, and you sign in once more.";
const host = () => global.$("toasts");
const offers = () =>
  host().children.filter((n) => {
    const text =
      n.children && n.children.find((c) => c.className === "toast-text");
    return (
      text && String(text.textContent).startsWith("PATANYX clears site data")
    );
  });
function buttonsOf(node) {
  const row = node.children.find((c) => c.className === "toast-actions");
  return row ? row.children : [];
}
function offer(site, body) {
  global.window.__rb_event({ event: "keep_site_offer", data: { site, body } });
}
function reset() {
  host().children = [];
  global.rbCalls.length = 0;
  global.rbReject = null;
  global.rbResolve.wipe_exempt_add = {
    hosts: ["messenger.com"],
    supported: true,
    reopened: true,
    available: true,
  };
}
function confirmations() {
  return host().children
    .map((t) => t.children && t.children.find((c) => c.className === "toast-text"))
    .filter(Boolean)
    .map((t) => String(t.textContent));
}

check(
  "the offer shows Rust's sentence verbatim with Keep this site and Not now",
  async () => {
    reset();
    offer("messenger.com", BODY);
    await flush();
    const [n] = offers();
    assert(n, "no offer appeared for a keep_site_offer event");
    const text = n.children.find((c) => c.className === "toast-text");
    assert(
      text.textContent === BODY,
      "the offer did not render the body verbatim",
    );
    const labels = buttonsOf(n).map((b) => String(b.textContent).trim());
    assert(
      JSON.stringify(labels) === JSON.stringify(["Keep this site", "Not now"]),
      "the offer's buttons are " + JSON.stringify(labels),
    );
  },
);

check(
  "Keep sends exactly one wipe_exempt_add with the site Rust named",
  async () => {
    reset();
    offer("messenger.com", BODY);
    await flush();
    const [n] = offers();
    global.rbCalls.length = 0;
    buttonsOf(n)[0]._fire("click");
    await flush();
    const adds = global.rbCalls.filter((c) => c.cmd === "wipe_exempt_add");
    assert(adds.length === 1, `Keep sent ${adds.length} wipe_exempt_add calls`);
    assert(
      JSON.stringify(adds[0].args) ===
        JSON.stringify({ host: "messenger.com" }),
      "Keep sent " + JSON.stringify(adds[0].args),
    );
    assert(offers().length === 0, "the offer stayed on screen after Keep");
    assert(
      host().children.some((t) => {
        const text =
          t.children && t.children.find((c) => c.className === "toast-text");
        return text && String(text.textContent).startsWith("Kept.");
      }),
      "no confirmation followed Keep",
    );
  },
);

check("Not now sends nothing and takes the offer away", async () => {
  reset();
  offer("messenger.com", BODY);
  await flush();
  const [n] = offers();
  global.rbCalls.length = 0;
  buttonsOf(n)[1]._fire("click");
  await flush();
  assert(
    !global.rbCalls.some((c) => c.cmd === "wipe_exempt_add"),
    "Not now kept the site",
  );
  assert(offers().length === 0, "the offer stayed on screen after Not now");
});

check("one offer at a time: a second replaces the first", async () => {
  reset();
  offer("messenger.com", BODY);
  offer("facebook.com", BODY.replace("messenger.com", "facebook.com"));
  await flush();
  assert(offers().length === 1, `${offers().length} offers are on screen`);
});

check("a malformed offer shows nothing", async () => {
  // One at a time: a second malformed offer would retire the first.
  for (const [site, body] of [
    [undefined, BODY],
    [42, BODY],
    ["messenger.com", undefined],
  ]) {
    reset();
    offer(site, body);
    await flush();
    assert(host().children.length === 0, "a malformed keep_site_offer was shown: " + JSON.stringify([site, body]));
  }
});

check("the confirmation says the tab reopened only when Rust says it did", async () => {
  for (const [reopened, available, expected] of [
    [true, true, "Kept. This tab reopened"],
    [false, true, "Kept. This tab could not move"],
    [false, false, "Kept from the next start"],
  ]) {
    reset();
    global.rbResolve.wipe_exempt_add.reopened = reopened;
    global.rbResolve.wipe_exempt_add.available = available;
    offer("messenger.com", BODY);
    await flush();
    const [n] = offers();
    buttonsOf(n)[0]._fire("click");
    await flush();
    assert(
      confirmations().some((t) => t.startsWith(expected)),
      `with reopened=${reopened} available=${available} the confirmation was ${JSON.stringify(confirmations())}`,
    );
  }
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
    console.error("\nKEEP OFFER GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nKEEP OFFER OK");
})();
