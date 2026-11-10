# macOS port: what works, what is off, and why

State of the WKWebView backend (`crates/app/src/platform/macos.rs`), current as
of the 2026-10-29 interim snapshot of the release line (1.0.8). The rule the
backend follows: a feature this
port cannot deliver is reported OFF, never half-built and never faked. The
panel renders these answers, so each `false` below is a promise the UI makes
to the person using it.

Tests pin the off-switches (`the_declared_off_switches_stay_off`,
`the_engine_settings_rows_without_a_macos_answer_say_not_attempted` in
macos.rs): if one of them turns true, the port grew the feature and this list
must be rewritten in the same change.

## Working

- Rendering (WKWebView via the vendored, patched wry), tab lifecycle, manual layout, Side by Side, window fullscreen.
- Ad and tracker blocking: compiled `WKContentRuleList`s inside the engine (the WebKitGTK model). A blocked request never leaves the machine. Cosmetic hiding rides a style-injecting user script.
- Per-tab "allow ads on this tab" (1.0.7): allowance lives in `TabState`, the tab's rule lists rebuild from what the state wants, and the malicious-overlap filter covers an allowed tab. Browser-wide switches can never re-block an allowed tab (`apply_policy` rebases through `TabState::apply_base_policy`).
- YouTube ad script, GPC, fingerprint divergence, scrollbar styling: user-script set, rebuilt as a whole on every change.
- Freeze (auto and manual) with a compiled freeze filter; enforcement reported only after WebKit confirms the compile. A replacement freeze filter lands before the superseded one leaves (no unfrozen moment on a frozen tab), a compile that finishes after the tab thawed installs nothing, and a freeze that names allowed hosts compiles into a per-run private store whose stored copy is removed as soon as the filter is handled.
- Strict Tabs, private (ephemeral) tabs on an ephemeral `WKWebsiteDataStore`, ITP (WebKit ships it on; no toggle exists).
- Session wipe at first tab: every public website-data type, asked of `WKWebsiteDataStore` itself (`allWebsiteDataTypes()`), cleared once per process, held behind WebKit's async completion. A type WebKit adds later is wiped by default. Strict-transport data is deliberately NOT cleared, matching unix.
- Downloads, file open/save panels, clipboard, page capture (visible area), find-in-page UI state, devtools, tunnel proxying, the fingerprint-probe IPC channel (the only channel any content view gets).
- About page: names the engine as WKWebView and compiles an attribution file generated for this configuration, so the objc2 and block2 notices travel with the binary (`scripts/shipping-licenses.py` carries the darwin configs). The accent disclosure sentence compiles in here too, because the scrollbar colour reaches pages through the injected style (`set_page_scrollbar`), exactly as on Windows.

## Reported off, honestly

| Feature | Answer | Why |
|---|---|---|
| Page translation | `translate_channel_supported()` = false | The GTK translator rides WebKitGTK's script-message-with-reply channel; the pinned objc2 bindings have no equivalent, and building one means script evaluation in a content view, which is forbidden absolutely. |
| Page integrity (main-resource bytes) | `page_bytes_supported()` = false | WebKit offers no UI-process path to the rendered main resource; re-fetching would be a different document, the one thing integrity checking exists to catch. |
| Full-page capture | `CaptureScope::FullPage` refuses with `capture_full_page_unsupported` | `WKSnapshotConfiguration` has no full-document option; relabeling a viewport crop as the whole page would be a lie. Visible-area capture works. |
| PDF export | `save_page_as_pdf` = false | WKWebView's `createPDF` is a different API shape needing its own verification pass; unavailable beats a button that does nothing. |
| Credential autofill | `fill_credential` = false, row "not_attempted" | Content-script injection plus a message channel, Windows-only upstream; no channel exists here to deliver a fill through. |
| Vault lock on screen lock | `session_lock_registered` = "not_attempted" | Needs the distributed-notification centre and its own verification pass; deferred, not half-built. Same reasoning as unix's logind deferral. |
| Hover readout | stubs are no-ops; smoke prints `READOUT skipped (macOS port: hover readout is off)` | No native host view over page pixels from this process. |
| Page fullscreen (engine side) | `fullscreen_notice_can_draw()` = false, so no page is ever granted the screen | wry 0.55 does not relay WKWebView element-fullscreen events; the browser-side exit path is real but unreachable. Window fullscreen works. |
| Kept profile | `kept_profile_supported()` = false | A Windows feature (`kept_profile.rs`); every tab is Main and profile-scoped releases stay coherent. |
| Custom window frame | `custom_window_frame()` = false | macOS keeps the standard title bar, matching unix. |
| Engine sandbox row | "not_attempted" | WebKit's WebContent sandbox is the OS's, always on, and not queryable through the pinned bindings. |
| Print preview | `show_print_ui` = false | The print path needs its own verification pass on a real session. |
| Find in page (native) | honest no-ops; `find_probe` = false | WebKit has no find-in-page API in the pinned bindings; the private `WKFindInteractionHost` is out of bounds. |

## Known behavioural differences from the other backends

- TLS classification: WKWebView exposes no UI-process path to the serving certificate, so `tls_state` answers `NotTls` for plaintext (observable from the scheme) and `Unreadable` for everything secured, with `tls_issuer` returning None; the interception warning cannot fire here, and unix's issuer classification needs a wry patch relaying the authentication challenge. Same shape as Windows's answer.
- Blocking is enforced inside the engine, so per-request UI-process behaviour
  (WebView2's NavigationStarting veto) is structurally absent. Where a
  decision must precede a navigation (ending an allowance), this backend does
  the work before handing WebKit the request.
- A tab's first navigation is held until the start-up clear completes AND
  the tab's bundled ad and tracker lists have compiled (the lists are
  async); the release path is the shared `BundledFiltersSettled` event. The
  wipe mask, the distant-past reach, the held navigation and the per-run
  freeze store are pinned by
  `macos_mask_matches_the_site_data_promise` and
  `macos_freeze_filters_stay_out_of_the_persistent_store` in
  platform/mod.rs and `macos_first_page_waits_for_the_ad_and_tracker_filters`
  in privacy.rs, and exercised end to end by `--smoke-test` on hardware.
