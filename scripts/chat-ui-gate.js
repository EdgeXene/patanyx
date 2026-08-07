// Behavioural checks on the chat panel's delivery display, run against the
// DOM harness so the file is EXECUTED rather than parsed.
//
// What these exist to prevent is a specific, already-shipped failure: the
// panel used to draw an out-message on the IPC reply and never touch it
// again, which read to the user as delivery. A test asserting that a
// chat_delivery event "round-trips" would miss that entirely — the property
// is what the USER SEES on the node, before and after.
//
// Run: node scripts/chat-ui-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
process.env.HTML_PATH = path.join(root, "crates/app/src/chrome/index.html");
require("./domstub.js");

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
// The panel talks to Rust over window.ipc.postMessage and the harness answers
// on the next tick, exactly as the real IPC does. Every step that sends a
// command must therefore be flushed before its effect is observable — a
// synchronous test would see the state BEFORE the reply and prove nothing.
// Drains repeatedly, because the panel's refresh is a CHAIN of commands
// (contacts, then relay settings, then peers) and each reply schedules the
// next. Settling only one tick leaves a later reply to land mid-test and
// re-render the pane out from under it — which is precisely what happened
// while writing this, and why the count is generous rather than minimal.
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// chrome.js first: it owns window.__rb, the request helper chat.js calls.
for (const file of ["chrome.js", "chat.js"]) {
  new Function(
    fs.readFileSync(path.join(root, "crates/app/src/chrome", file), "utf8"),
  )();
}

// Events go in the way Rust sends them: through chrome.js's dispatcher, not
// by calling the panel's handler directly.
//
// Calling window.__rb_chat.chat_delivery(...) skips chrome.js entirely, and
// chrome.js's `case "chat_delivery":` is the ONE line that joins the two
// halves. Deleting it made every bubble stay "Sending…" forever while this
// gate still reported six passes — so the gate was green precisely because
// it bypassed the thing under test.
function emitFromRust(event, data) {
  if (typeof global.window.__rb_event !== "function") {
    throw new Error(
      "chrome.js exposes no event entry point; this gate cannot reach the " +
        "panel the way Rust does",
    );
  }
  global.window.__rb_event({ event, data });
}

const MID = "00112233445566778899aabbccddeeff";
const PEER = "1111-2222-3333-4444-5555-6666-7777-8888";
const MY_HASH = "aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111";

// Opens a conversation through the REAL path: contacts arrive over IPC, the
// list renders, and the contact's chat button is clicked. Reaching in to set
// the panel's internal state would test the harness rather than the panel.
async function openConversation() {
  global.rbResolve = {
    chat_contacts: {
      items: [{ id: "c1", label: "Peer", peer_hash: PEER, note: "" }],
    },
    // Required: pane selection reads the identity, not the contact count.
    // Without this the panel correctly decides there is no identity yet and
    // shows the intro pane, so no contact row -- and no Chat button -- is
    // ever drawn.
    chat_identity: { hash: MY_HASH, minted: false },
    chat_open: {},
  };
  emitFromRust("chat_peer_state", {
    peer_hash: PEER,
    online: true,
    connected: true,
    reachable: true,
    verified: false,
    away: false,
  });
  // The panel must be OPEN before it will load anything: chat_state is a
  // no-op while it is closed, which is correct (a closed panel has no reason
  // to hold contacts in memory) and is exactly the kind of thing a test that
  // reached into internals would have missed.
  global.$("btn-chat")._fire("click");
  await flush();
  emitFromRust("chat_state", { online: true });
  await flush();
  // The contact row's "Chat" button, matched exactly: a loose match picks up
  // "My number" and "Remove" and would click the wrong thing.
  const opened = global.allEls.filter(
    (e) => e._has && e._has("click") && e._text.includes("Chat"),
  );
  if (!opened.length) {
    throw new Error("the contact list rendered no Chat button");
  }
  // The list re-renders during the refresh chain, so earlier button objects
  // are stale detached nodes; the most recent one is the live row.
  opened[opened.length - 1]._fire("click");
  await flush();
}

// Text that is actually ON THE PAGE, walked from the conversation pane down.
//
// NOT `allText()`, which returns every string written to any element for the
// whole run, attached or not. With that, dropping the appendChild entirely --
// so the conversation renders empty -- still passed six of six, and so did
// routing every revision into a detached node. A gate that cannot tell the
// difference between "shown to the user" and "constructed and thrown away"
// is measuring the wrong thing.
function textsWritten() {
  const out = [];
  const walk = (node) => {
    if (!node) return;
    if (node._text && node._text.length)
      out.push(node._text[node._text.length - 1]);
    for (const child of node.children || []) walk(child);
  };
  walk(global.$("chat-messages"));
  return out;
}

check("an out-message is drawn at Sending, not as delivered", async () => {
  await openConversation();
  global.rbResolve = { chat_send: { mid: MID } };
  emitFromRust("chat_message", { peer_hash: PEER, text: "incoming" });

  const input = global.$("chat-input");
  input.value = "hello";
  global.$("chat-send-form")._fire("submit");
  await flush();

  const seen = textsWritten();
  assert(
    seen.includes("Sending…"),
    "the bubble must say Sending before anything is confirmed, saw: " +
      JSON.stringify(seen.slice(-6)),
  );
  assert(
    !seen.includes("Delivered"),
    "nothing may claim delivery off the IPC reply alone",
  );
});

check("a delivery event revises the bubble to Delivered", () => {
  emitFromRust("chat_delivery", {
    peer_hash: PEER,
    mid: MID,
    state: "delivered",
    reason: null,
  });
  assert(
    textsWritten().includes("Delivered"),
    "an authenticated acknowledgement must reach the user",
  );
});

check("a delivered message is never downgraded by a later failure", () => {
  const before = textsWritten().length;
  emitFromRust("chat_delivery", {
    peer_hash: PEER,
    mid: MID,
    state: "failed",
    reason: "refused",
  });
  const after = textsWritten().slice(before);
  assert(
    !after.some((t) => t.startsWith("Not delivered")),
    "a refusal arriving after an acknowledgement is answering a retry, " +
      "and must not un-deliver the message: " +
      JSON.stringify(after),
  );
});

check("each failure cause gets its own sentence", async () => {
  const causes = [
    "peer_offline",
    "no_session",
    "link_lost",
    "refused",
    "no_ack",
    "session_ended",
    "too_many_outstanding",
  ];
  for (const [i, reason] of causes.entries()) {
    const mid = String(i).repeat(32).slice(0, 32);
    global.rbResolve = { chat_send: { mid } };
    global.$("chat-input").value = "msg " + i;
    global.$("chat-send-form")._fire("submit");
    await flush();
    emitFromRust("chat_delivery", {
      peer_hash: PEER,
      mid,
      state: "failed",
      reason,
    });
  }
  // Read the pane, not a slice of creation order: the bubbles are separate
  // nodes and nothing guarantees the newest is last in that order.
  const lines = textsWritten().filter((t) => t.startsWith("Not "));
  assert(
    !lines.some((t) => t.includes("not recognized")),
    "a known cause fell through to the unknown-cause fallback: " +
      JSON.stringify(lines),
  );
  const distinct = new Set(lines);
  assert(
    distinct.size === causes.length,
    "every cause needs its OWN sentence, or one borrows another's meaning; " +
      "got " +
      distinct.size +
      " distinct lines for " +
      causes.length +
      " causes: " +
      JSON.stringify([...distinct]),
  );
});

check("an unknown cause does not render undefined at the user", async () => {
  const mid = "ffffffffffffffffffffffffffffffff";
  global.rbResolve = { chat_send: { mid } };
  global.$("chat-input").value = "future";
  global.$("chat-send-form")._fire("submit");
  await flush();
  emitFromRust("chat_delivery", {
    peer_hash: PEER,
    mid,
    state: "failed",
    reason: "a_cause_from_a_newer_build",
  });
  const shown = textsWritten();
  assert(
    shown.some((t) => t.includes("not recognized")),
    "an unrecognised cause must say so plainly, never render undefined",
  );
  assert(
    !shown.some((t) => t.includes("undefined")),
    "and must never write the word undefined at a user",
  );
});

check("a delivery event for an unknown id is ignored quietly", () => {
  const before = textsWritten().length;
  emitFromRust("chat_delivery", {
    peer_hash: PEER,
    mid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    state: "delivered",
    reason: null,
  });
  assert(
    textsWritten().length === before,
    "an event naming a message we never sent must change nothing",
  );
});

// ---- which pane the panel shows ------------------------------------------
//
// These exist because the pane was chosen by `contacts.length === 0` for
// months, so every user who had an identity but had not yet added a contact
// was told to "Create my hash number" on every single unlock. Five gates
// missed it, this one included -- it had no coverage of pane selection at
// all, only of the conversation view.
//
// Re-runs the refresh chain against a fresh fixture. The panel is ALREADY
// open by this point (the conversation checks above opened it, and the
// toolbar button is a toggle -- clicking again would close it), so the
// unlock event is what re-enters refreshAll, exactly as it does in the app.
async function refreshWith(resolve, rejectCode) {
  global.rbResolve = resolve;
  global.rbReject = rejectCode || null;
  emitFromRust("chat_state", { locked: false });
  await flush();
  global.rbReject = null;
}

check(
  "an identity with no contacts shows the contact list, not the intro",
  async () => {
    await refreshWith({
      chat_contacts: { items: [] },
      chat_identity: { hash: MY_HASH, minted: false },
    });
    assert(
      global.$("chat-intro").hidden === true,
      "the intro pane is for users with NO identity, not users with no " +
        "contacts -- keying it on an empty contact list asked every such " +
        "user to create a hash number they already had, on every unlock",
    );
    assert(
      global.$("chat-contacts").hidden === false,
      "the contact list is the correct pane for an identity with zero contacts",
    );
  },
);

check("no identity at all still shows the intro", async () => {
  await refreshWith({
    chat_contacts: { items: [] },
    chat_identity: { hash: null, minted: false },
  });
  assert(
    global.$("chat-intro").hidden === false,
    "a genuine first run must still be offered the create button",
  );
});

check("an existing hash number is shown without clicking create", async () => {
  await refreshWith({
    chat_contacts: { items: [] },
    chat_identity: { hash: MY_HASH, minted: false },
  });
  assert(
    global.$("chat-myhash")._text.includes(MY_HASH),
    "the hash was previously revealed ONLY by the mint button's click " +
      "handler, so an existing identity stayed invisible until the user " +
      "pressed a button telling them to create what they already had",
  );
  assert(
    global.$("chat-myhash").hidden === false,
    "and the node must actually be unhidden, not merely populated",
  );
});

check(
  "a contacts failure is reported, not rendered as a first run",
  async () => {
    // rbReject fails every command, which is what a storage fault looks like
    // from the panel's side. The code under test must tell this apart from
    // not_unlocked and from a genuine first run.
    await refreshWith({}, "io");
    assert(
      global.$("chat-intro-error")._text.length > 0,
      "a storage error must say what happened instead of silently claiming " +
        "the user has no identity",
    );
  },
);

// ---- the relay default -----------------------------------------------------
//
// Source-level, because the relay field carries no id and the DOM stub cannot
// reach it by class. Cheap, and it pins the two properties that matter: the
// box is FILLED so nobody has to type a WebSocket URL from memory, and it is
// not silently ENABLED, which would make every install announce itself to one
// operator the moment chat came up.
check("the relay address is pre-filled but not pre-enabled", () => {
  const src = fs.readFileSync(
    path.join(root, "crates/app/src/chrome/chat.js"),
    "utf8",
  );
  assert(
    /const DEFAULT_RELAY_URL = "wss:\/\/[^"]+"/.test(src),
    "a default relay URL must be defined, or the field ships blank and the " +
      "feature goes unused",
  );
  assert(
    /rUrl\.value = DEFAULT_RELAY_URL/.test(src),
    "the input must actually be filled with it",
  );
  assert(
    /data\.url \|\| DEFAULT_RELAY_URL/.test(src),
    "a user who has never configured a relay must see the default rather " +
      "than an empty box when settings come back unset",
  );
  assert(
    !/rEnable\.checked = true/.test(src),
    "PRE-FILLED, NEVER PRE-ENABLED: auto-connecting would mean every install " +
      "announces itself to one operator without being asked, which is the " +
      "phoning-home this product refuses",
  );
  assert(
    /replace it with any relay you|relay you\s*\+?\s*"?\s*trust/.test(src),
    "the panel must tell the user they can point this elsewhere, where they " +
      "will read it rather than in a document nobody opens",
  );
});

check("the emoji picker exists, starts shut, and is wired", () => {
  const toggle = global.$("chat-emoji-toggle");
  const panel = global.$("chat-emoji-panel");
  assert(toggle, "#chat-emoji-toggle is missing from index.html");
  assert(panel, "#chat-emoji-panel is missing from index.html");
  const clicks = toggle._listeners && toggle._listeners.click;
  assert(
    clicks && clicks.length > 0,
    "the emoji button has no click handler -- it would render, highlight on " +
      "hover and do nothing, which is this chrome's most-repeated defect",
  );
  // The markup must carry `hidden`; the DOM harness defaults everything to
  // hidden, so only reading the source can tell a picker that ships shut from
  // one that ships open across the composer.
  const markup = fs.readFileSync(
    path.join(root, "crates/app/src/chrome/index.html"),
    "utf8",
  );
  assert(
    /<div id="chat-emoji-panel"[^>]*\shidden(\s|>)/.test(markup),
    "#chat-emoji-panel must be hidden in index.html",
  );
});

check("emoji are text, never a fetched asset", () => {
  // The CSP is `default-src 'none'` with no font-src. An emoji sprite sheet or
  // a webfont would silently fail to load and leave the picker blank, which
  // looks like a rendering bug rather than a blocked request.
  const chatSrc = fs.readFileSync(
    path.join(root, "crates/app/src/chrome/chat.js"),
    "utf8",
  );
  const css = fs.readFileSync(
    path.join(root, "crates/app/src/chrome/chrome.css"),
    "utf8",
  );
  assert(
    !/emoji[^"']*\.(png|svg|woff2?|ttf)/i.test(chatSrc + css),
    "the picker must not reference an image or font file for emoji",
  );
  assert(
    /Segoe UI Emoji|Noto Color Emoji|Apple Color Emoji/.test(css),
    "chrome.css must name the platform emoji faces, so a glyph renders in the " +
      "system's own artwork rather than falling back to tofu",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL " + name + " — " + e.message);
    }
  }
  if (failures.length) {
    console.error("\nCHAT UI GATE FAILED:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nCHAT UI OK");
})();
