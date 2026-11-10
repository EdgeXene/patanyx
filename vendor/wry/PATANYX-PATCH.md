# PATANYX patch: do not install `window.ipc` without an IPC handler

Source: crates.io `wry` 0.55.1, checksum
`186f9871daa55fd9c016578b810d149de58367113db7fb72b462d2323ce19514`.
The vendored crate is byte-identical to that registry source except for this
file and the two source hunks below.

wry 0.55.1 injects a frozen, non-writable, non-configurable `window.ipc` into
every WebView2 and WebKitGTK document, including builders whose
`WebViewAttributes::ipc_handler` is `None`. A page with a top-level `var ipc`
then binds to wry's object instead of its own symbol. Google Keep is one such
page and aborts during boot.

PATANYX deliberately gives IPC only to its trusted chrome webview. Content
builders leave `ipc_handler` unset and use engine-native channels instead:
`window.chrome.webview.postMessage` on WebView2, and the directly registered
`window.webkit.messageHandlers.ipc` path on WebKitGTK.

## Exact source diff

```diff
--- registry/wry-0.55.1/src/webview2/mod.rs
+++ vendor/wry/src/webview2/mod.rs
@@
-    Self::add_script_to_execute_on_document_created(
-      webview,
-      String::from(
-        r#"Object.defineProperty(window, 'ipc', { value: Object.freeze({ postMessage: s=> window.chrome.webview.postMessage(s) }) });"#,
-      ),
-    )?;
+    if attributes.ipc_handler.is_some() {
+      Self::add_script_to_execute_on_document_created(
+        webview,
+        String::from(
+          r#"Object.defineProperty(window, 'ipc', { value: Object.freeze({ postMessage: s=> window.chrome.webview.postMessage(s) }) });"#,
+        ),
+      )?;
+    }

--- registry/wry-0.55.1/src/webkitgtk/mod.rs
+++ vendor/wry/src/webkitgtk/mod.rs
@@
     // IPC handler
+    let has_ipc_handler = attributes.ipc_handler.is_some();
     Self::attach_ipc_handler(webview.clone(), &mut attributes);
@@
     // Initialize message handler
-    w.init("Object.defineProperty(window, 'ipc', { value: Object.freeze({ postMessage: function(x) { window.webkit.messageHandlers['ipc'].postMessage(x) } }) })", true)?;
+    if has_ipc_handler {
+      w.init("Object.defineProperty(window, 'ipc', { value: Object.freeze({ postMessage: function(x) { window.webkit.messageHandlers['ipc'].postMessage(x) } }) })", true)?;
+    }
```

The receive-side registrations are intentionally retained. On WebView2 the
existing closure remains a no-op when no handler exists. On WebKitGTK the
registered `window.webkit.messageHandlers.ipc` engine channel is not the
`window.ipc` shim and PATANYX content uses that native channel for count-only
fingerprint-divergence reports. Keeping both registrations limits this patch
to bootstrap injection and preserves existing content messaging.

As of 2026-08-25, 0.55.1 is the latest released wry. The development branch
conditions WebView2 handler attachment but still injects the WebKitGTK
`window.ipc` bootstrap unconditionally, so no released upgrade fixes both
backends.

## macOS arm (2026-09-22, added for the darwin backend)

Upstream `wkwebview/mod.rs` injects the same frozen `window.ipc` shim into
EVERY WKWebView document, unconditionally, while registering the
`window.webkit.messageHandlers.ipc` receiver only when an `ipc_handler`
exists. On a macOS build of PATANYX a content page that says `var ipc = …`
still binds to the shim, and any page that CALLS `window.ipc.postMessage`
gets a TypeError (the receiver was never registered). Same defect, third
engine. The receive-side registration stays as-is, for the same reason as
WebKitGTK: the fingerprint-divergence reporter posts through
`window.webkit.messageHandlers.ipc`.

```diff
--- registry/wry-0.55.1/src/wkwebview/mod.rs
+++ vendor/wry/src/wkwebview/mod.rs
@@
       // Initialize scripts
-      w.init(
+      if ipc_handler_delegate.is_some() {
+        w.init(
 r#"Object.defineProperty(window, 'ipc', {
   value: Object.freeze({postMessage: function(s) {window.webkit.messageHandlers.ipc.postMessage(s);}})
 });"#,
-      true
-      );
+        true
+        );
+      }
```

## Third hunk (1.0.6): enable the WebKitGTK process sandbox

Security audit 2026-10-08, confirmed at runtime: no context ever called
`webkit_web_context_set_sandbox_enabled`, so every WebKitWebProcess ran
unconfined (a direct child of the browser, no bubblewrap). The GTK3 API keeps
the sandbox off unless the embedder enables it before the context creates its
first process. `WebContextImpl::create_context` is the one place every wry
context passes through before a WebView exists on it, so the call lives there.

```diff
--- registry/wry-0.55.1/src/webkitgtk/web_context.rs
+++ vendor/wry/src/webkitgtk/web_context.rs
@@ pub fn create_context(context: WebContext) -> Self {
     let automation = false;
     context.set_automation_allowed(automation);
+    context.set_sandbox_enabled(true);
```

Runtime dependency: bubblewrap (`bwrap`) and `xdg-dbus-proxy`, which
libwebkit2gtk-4.1 already depends on in Debian. The browser reads the state
back per tab (`EngineSettings::sandbox`).

Where the system does not let bubblewrap start (a default Docker container, a
system that refuses unprivileged user namespaces), the engine aborts the browser
with SIGTRAP. From 1.0.7 `crates/app/src/sandbox_check.rs` tests this before
any window exists and refuses with a window that says so; it never starts the
browser without the sandbox.
