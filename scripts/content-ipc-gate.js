#!/usr/bin/env node
"use strict";

// Source-pin the boundary this project cannot express through wry 0.55.1's
// public API: content builders have no ipc_handler, therefore the vendored
// backends must not install wry's frozen window.ipc bootstrap. This is a
// source gate because neither WebView2 nor WebKitGTK can be instantiated in
// the ordinary headless Rust test process.

const fs = require("fs");
const path = require("path");

const root = path.resolve(process.env.PATANYX_IPC_GATE_ROOT || path.join(__dirname, ".."));
let checks = 0;

function read(relative) {
  return fs.readFileSync(path.join(root, relative), "utf8");
}

function requireThat(condition, message) {
  if (!condition) {
    console.error(`GATE FAIL: ${message}`);
    process.exit(1);
  }
  checks += 1;
}

function occurrences(source, needle) {
  return source.split(needle).length - 1;
}

function functionBody(source, signature) {
  const start = source.indexOf(signature);
  requireThat(start >= 0, `missing ${signature}`);
  const next = source.indexOf("\npub fn ", start + signature.length);
  return source.slice(start, next < 0 ? source.length : next);
}

const cargo = read("Cargo.toml");
requireThat(
  /\[patch\.crates-io\][\s\S]*?^wry\s*=\s*\{\s*path\s*=\s*"vendor\/wry"\s*\}/m.test(cargo),
  "workspace [patch.crates-io] does not pin wry to vendor/wry",
);

const webview2 = read("vendor/wry/src/webview2/mod.rs");
const winAttach = functionBody(webview2, "unsafe fn attach_ipc_handler(");
requireThat(
  /if attributes\.ipc_handler\.is_some\(\) \{[\s\S]*?Self::add_script_to_execute_on_document_created\([\s\S]*?Object\.defineProperty\(window, 'ipc'[\s\S]*?\n    \}/.test(winAttach),
  "WebView2 window.ipc bootstrap is not guarded by ipc_handler.is_some()",
);
requireThat(
  occurrences(webview2, "Object.defineProperty(window, 'ipc'") === 1,
  "WebView2 must contain exactly one auditable window.ipc bootstrap",
);
requireThat(
  winAttach.includes("add_WebMessageReceived"),
  "WebView2 receive registration changed; this patch is injection-only",
);

const webkitgtk = read("vendor/wry/src/webkitgtk/mod.rs");
const gtkFlag = webkitgtk.indexOf(
  "let has_ipc_handler = attributes.ipc_handler.is_some();",
);
const gtkAttach = webkitgtk.indexOf(
  "Self::attach_ipc_handler(webview.clone(), &mut attributes);",
);
const gtkConditional = webkitgtk.indexOf("if has_ipc_handler {");
const gtkBootstrap = webkitgtk.indexOf("Object.defineProperty(window, 'ipc'");
requireThat(
  gtkFlag >= 0 &&
    gtkAttach > gtkFlag &&
    gtkConditional > gtkAttach &&
    gtkBootstrap > gtkConditional,
  "WebKitGTK window.ipc bootstrap is not guarded by the pre-take handler state",
);
requireThat(
  occurrences(webkitgtk, "Object.defineProperty(window, 'ipc'") === 1,
  "WebKitGTK must contain exactly one auditable window.ipc bootstrap",
);
requireThat(
  webkitgtk.includes('manager.register_script_message_handler("ipc")'),
  "WebKitGTK native script-message registration changed",
);

for (const platform of ["windows", "unix"]) {
  const source = read(`crates/app/src/platform/${platform}.rs`);
  const content = functionBody(source, "pub fn build_content(");
  requireThat(
    !content.includes("with_ipc_handler"),
    `${platform} content builder acquired an ipc_handler`,
  );
}

const main = read("crates/app/src/main.rs");
requireThat(
  functionBody(main, "fn main()").includes(".with_ipc_handler("),
  "trusted chrome no longer installs its required IPC handler",
);

const autofill = read("crates/app/src/content_scripts/autofill.js");
requireThat(
  autofill.includes("window.chrome.webview.postMessage("),
  "Windows autofill no longer uses the native WebView2 message path",
);

const divergence = read("crates/app/src/content_scripts/fingerprint_divergence.js");
requireThat(
  divergence.includes("window.chrome.webview.postMessage(payload);") &&
    divergence.includes("window.webkit.messageHandlers.ipc.postMessage(payload);"),
  "divergence reporting lost a native content-message path",
);

const activeContent = [autofill, divergence]
  .join("\n")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/^\s*\/\/.*$/gm, "");
requireThat(
  !activeContent.includes("window.ipc"),
  "executable content-script source references the privileged window.ipc shim",
);

console.log(`CONTENT IPC GATE OK (${checks} assertions)`);
