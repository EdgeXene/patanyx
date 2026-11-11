#!/usr/bin/env node
"use strict";
// Execute the shipped script with controlled document/frame state. No DOM
// emulator dependency and no network; native transport is covered separately.
const assert = require("assert/strict");
const fs = require("fs");
const vm = require("vm");
const script = fs.readFileSync("crates/app/src/content_scripts/selection_capture.js", "utf8");
const token = "document-token";
const request = "a".repeat(32);
let checks = 0;

async function capture({text = "selected λ 🦀", field = null, focused = true, fails = false, leave = false} = {}) {
  const replies = [];
  let resolvePoll;
  let reads = 0;
  const listeners = {};
  const window = {
    addEventListener(name, callback) { listeners[name] = callback; },
    webkit: {messageHandlers: {
      selectionAsk: {postMessage(value) {
        assert.equal(value, token);
        return new Promise(resolve => { resolvePoll = resolve; });
      }},
      selectionReply: {postMessage(value) { replies.push(value); }},
    }},
    getSelection() { reads++; if (fails) throw Error("capture failed"); return {toString: () => text}; },
  };
  Object.defineProperty(window, "ipc", {get() { throw Error("privileged IPC touched"); }});
  const navigator = {};
  Object.defineProperty(navigator, "clipboard", {get() { throw Error("clipboard touched"); }});
  vm.runInNewContext(script.replace("__SELECTION_DOCUMENT_TOKEN__", token), {
    window, document: {activeElement: field, hasFocus: () => focused}, navigator, TextEncoder,
  });
  assert.equal(reads, 0, "injection must not read selection");
  assert.equal(replies.length, 0);
  resolvePoll(request);
  await new Promise(resolve => setImmediate(resolve));
  if (leave) {
    listeners.pagehide({isTrusted: false});
    assert.equal(replies.length, 1, "synthetic pagehide cannot change the source generation");
    listeners.pagehide({isTrusted: true});
  }
  checks++;
  return replies.map(reply => {
    assert.ok(Buffer.byteLength(reply) <= 512 * 1024 + 256);
    if (reply === token + " end") return "document-ended";
    assert.ok(reply.startsWith(token + " " + request + " "));
    return reply.slice(token.length + request.length + 2);
  });
}

(async () => {
  assert.deepEqual(await capture(), ["selected λ 🦀"]);
  assert.deepEqual(await capture({leave: true}), ["selected λ 🦀", "document-ended"]);
  assert.deepEqual(await capture({field: {tagName: "TEXTAREA", value: "before chosen after", selectionStart: 7, selectionEnd: 13}}), ["chosen"]);
  assert.deepEqual(await capture({field: {tagName: "INPUT", type: "text", value: "input", selectionStart: 1, selectionEnd: 4}}), ["npu"]);
  assert.deepEqual(await capture({field: {tagName: "DIV", isContentEditable: true}, text: "editable"}), ["editable"]);
  assert.deepEqual(await capture({field: {tagName: "INPUT", type: "password"}}), [""]);
  // A focused child answers; its parent and unrelated frames cannot donate
  // an earlier selection to this menu.
  assert.deepEqual(await capture({field: {tagName: "IFRAME"}, text: "old parent"}), []);
  assert.deepEqual(await capture({focused: false, text: "old frame"}), []);
  assert.deepEqual(await capture({text: "child selection"}), ["child selection"]);
  assert.deepEqual(await capture({fails: true}), [""]);
  assert.deepEqual(await capture({text: ""}), [""]);
  assert.deepEqual(await capture({text: "x".repeat(512 * 1024 + 1)}), [""]);
  assert.deepEqual(await capture({text: "🦀".repeat(128 * 1024 + 1)}), [""]);
  assert.equal((await capture({text: "🦀".repeat(128 * 1024)}))[0].length, 256 * 1024);
  console.log(`SELECTION CAPTURE GATE OK (${checks} scenarios)`);
})().catch(error => { console.error("SELECTION CAPTURE GATE FAIL", error); process.exit(1); });
