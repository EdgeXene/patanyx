// The download-comparison panel tells the truth about a hash difference.
//
// The rule worth a gate: a differing hash is EVIDENCE, not a verdict about
// anybody's conduct. Version drift, per-platform builds and stale mirrors
// all produce different files innocently, and a UI that renders "different"
// as "you were attacked" would be the failure the corroborate crate's own
// docs call worse than no feature at all.
//
// So this pins four things the browser must not quietly lose:
//   1. The verdict SENTENCE comes from Rust, verbatim. This file may place
//      it, never compose it.
//   2. The standing caveats render WITH the verdict, not behind a link.
//   3. A contact's refusal is worded from a closed vocabulary, so a peer
//      cannot put chosen text on the screen.
//   4. An automatic answer to a contact's question is always announced.
//
// Proven against planted defects when it landed: composing the headline in
// JS fails check 1, dropping the caveat list fails check 2, and echoing the
// peer's raw reason string fails check 3.
//
// Guard shape: chrome-js-gate.sh refuses to run this file when
// #download-list is gone from index.html.
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

const fire = (event, data) => global.window.__rb_event({ event, data });

// Text that is ACTUALLY ATTACHED under a node, descendants included.
//
// Not global.allText(): that returns every string ever set on any element,
// including ones created and then dropped on the floor. Asserting against it
// proved only that a string had been constructed, which let a planted defect
// that removed `slot.appendChild(ul)` pass this gate untouched. Reading the
// tree is the difference between "the words exist" and "the user sees them".
const attachedText = (node) => {
  if (!node) return "";
  const own =
    node._text && node._text.length ? node._text[node._text.length - 1] : "";
  const kids = (node.children || []).map(attachedText).join(" ");
  return (own + " " + kids).trim();
};
const slotText = () => attachedText(global.$("dlcmp-d1"));
// Rust's own wording, as the corroborate crate emits it. The point of the
// first check is that this exact string survives to the DOM untouched.
const RUST_TEXT =
  "The two downloads are not the same file (the SHA-256 hashes differ). " +
  "Innocent causes are common: a new version published between the two " +
  "downloads, per-platform or per-region builds, or a stale CDN copy, and " +
  "this result cannot say which copy, if either, is the genuine one. " +
  "Compare the version numbers and the publisher's own checksums or " +
  "signatures before concluding anything.";

// Drive the real ASKING path: a licensed browser, a chat build, one contact
// and one download record, then click Ask. Firing a verdict without this
// exercises the responder branch only and leaves the row rendering, and its
// caveats, unproven.
const askAboutADownload = async () => {
  global.rbResolve.premium_status = {
    state: "perpetual",
    premium: true,
    on_sale: false,
  };
  global.rbResolve.chat_status = { compiled: true };
  global.rbResolve.chat_contacts = { items: [{ id: "c1", label: "Alice" }] };
  // The library renders nothing until the store is open, and download
  // records live in the store: a locked vault has no downloads to compare.
  global.rbResolve.store_status = { open: true, digests_ready: true };
  global.rbResolve.download_list = {
    items: [
      {
        id: "d1",
        url: "https://dl.example/setup.exe",
        filename: "setup.exe",
        byte_len: 1024,
        recorded_at: 1700000000,
      },
    ],
  };
  // Opening the library is what refreshes downloads.
  global.$("btn-library").click();
  await flush();
  const ask = global.allEls.find(
    (e) => e._text && e._text.includes("Ask a contact"),
  );
  assert(ask, "the Ask a contact control was not rendered");
  ask.click();
  await flush();
};

check(
  "the verdict sentence is Rust's, placed and never rewritten",
  async () => {
    await askAboutADownload();
    fire("download_compare_verdict", {
      peer_hash: "abc",
      url: "https://dl.example/setup.exe",
      kind: "hash_differs",
      text: RUST_TEXT,
      byte_len_equal: false,
      recorded_gap_seconds: 3600,
    });
    await flush();
    const seen = global.allText();
    assert(
      seen.includes(RUST_TEXT),
      "the crate's sentence must reach the DOM verbatim; the chrome may " +
        "place the wording but never compose it",
    );
  },
);

check("a difference is never rendered as an accusation", async () => {
  const seen = slotText().toLowerCase();
  assert(seen.length > 0, "nothing rendered, so this check would be vacuous");
  for (const word of [
    "tampered",
    "attack",
    "malicious",
    "compromised",
    "hacked",
  ]) {
    assert(
      !seen.includes(word),
      `the panel said "${word}" about a hash difference, which the evidence ` +
        "does not support",
    );
  }
});

check(
  "the standing caveats render with the verdict, not behind a link",
  async () => {
    // Read the SLOT, not every string the run ever created: the caveats
    // must be attached under the verdict, and a version that builds them
    // and forgets to append must fail here.
    const seen = slotText().toLowerCase();
    assert(
      seen.includes("cannot tell you whether either copy is safe"),
      "the safety caveat must be attached beside the verdict",
    );
    assert(
      seen.includes("honestly"),
      "the honest-contact caveat must be attached beside the verdict",
    );
    assert(
      seen.includes("innocently") || seen.includes("innocent"),
      "the innocent-causes caveat must be attached beside the verdict",
    );
  },
);

check("a peer's refusal is worded here, never echoed", async () => {
  // Re-arm: the previous check's verdict consumed the awaiting row, and a
  // note with nothing awaiting renders nothing at all, which would make
  // this check pass by doing nothing.
  await askAboutADownload();
  fire("download_compare_note", {
    peer_hash: "abc",
    // A hostile reason string. The backend sanitizes to a closed set, and
    // the chrome must key off that set rather than print what arrived.
    reason: "<script>alert(1)</script> your files are infected",
  });
  await flush();
  const seen = slotText();
  assert(seen.length > 0, "nothing rendered, so this check would be vacuous");
  assert(
    !seen.includes("infected") && !seen.includes("<script>"),
    "a peer-supplied reason reached the screen; refusals must be worded " +
      "from the closed vocabulary in this file",
  );
  assert(
    seen.includes("could not be read"),
    "an unknown reason must degrade to the bad_message wording",
  );
});

check("an automatic answer to a contact is always announced", async () => {
  const before = global.allText().length;
  fire("download_compare_request_received", {
    peer_hash: "abc",
    url: "https://dl.example/setup.exe",
  });
  await flush();
  const seen = global.allText().slice(before).join(" ").toLowerCase();
  assert(
    seen.includes("asked what you downloaded"),
    "answering a contact automatically must be visible to the user",
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
      "download-compare-gate: " + failures.length + " check(s) failed",
    );
    process.exit(1);
  }
  console.log("download-compare-gate OK (" + checks.length + " checks)");
})();
