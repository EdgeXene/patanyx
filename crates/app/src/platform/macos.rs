//! macOS backend glue (WKWebView via vendored wry).
//!
//! Layout is manual, the way the Windows backend does it: the chrome webview
//! is built FIRST and covers the whole window; the content tab is built after
//! (so it wins z-order) and is re-bounded on every `layout()` call to the
//! rectangle `page_rect` carves out. `set_chrome_*` are store-only; state.rs
//! always follows them with `relayout()`, which reaches this module's
//! `layout` with all four geometry values plus the live window size.
//!
//! Privacy controls: WebKit has no per-request UI-process hook, so network
//! blocking (ads AND freeze) uses compiled `WKContentRuleList`s on the
//! per-webview `WKUserContentController` wry already created, a blocked
//! request never leaves the machine. Cosmetic filtering is a style-injecting
//! user script (the sanctioned mechanism; content webviews are never
//! script-evaluated by this process). Same invariants as unix.rs, WebKit
//! edition.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::{MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAppearance, NSApplication, NSBitmapImageFileType, NSBitmapImageRep, NSImage, NSOpenPanel,
    NSPasteboard, NSSavePanel, NSView, NSWindowOrderingMode,
};
use objc2_foundation::{ns_string, NSDate, NSDictionary, NSProcessInfo, NSSet, NSString};
use objc2_web_kit::{WKContentRuleList, WKContentRuleListStore, WKUserScript};
use tao::event_loop::EventLoopProxy;
use tao::window::Window;
use wry::{WebView, WebViewBuilder, WebViewExtMacOS};

use super::privacy::{
    self, EngineSettings, FreezePhase, HostRecord, ProfileMode, SettingState, TabPolicy, TabState,
    TlsState, TrackingPreventionState,
};
use super::{ChromeLayout, CHROME_HEIGHT_PX};
use crate::page_integrity::{IntegrityEvent, PageBytesError};
use crate::UserEvent;

/// True once the chrome webview was successfully made transparent (private
/// `drawsBackground` KVC, macOS 10.14+, the same key vendored wry uses at
/// build time for the builder attribute this backend does not have).
static CHROME_TRANSPARENT: AtomicBool = AtomicBool::new(false);

/// Weak-but-real proxy for "the engine confirmed ITP": WebKit ships ITP
/// enabled and exposes no runtime toggle or query. Reaching the default
/// website data store at all is the one observable the backend has.
static ITP_CONFIRMED: AtomicBool = AtomicBool::new(false);

/// This backend's interception mechanism name, reported via
/// `interception_state`. Same honesty rule as unix's `UNIX_INTERCEPTION_NAME`:
/// name what actually runs, never borrow Windows' word for it.
pub const MACOS_INTERCEPTION_NAME: &str = "content_rule_list";

/// WebKit floor for the OS WebKit proxy version. WebKit has no separately
/// installed runtime on macOS, it ships with the OS, so the honest version
/// signal is the OS version, and the floor is a macOS floor.
const MIN_MACOS_WEBKIT: [u32; 3] = [14, 0, 0];

/// Why the compiled floor is where it is.
const MACOS_WEBKIT_ADVISORY: &str = "WebKit ships with macOS updates; PATANYX cannot pin it. Keep macOS updated.";

pub struct Hosts {
    /// Held so the window outlives the event loop (main.rs moves it in here);
    /// every webview is a child of this window's content view.
    _window: Window,
    /// What the chrome is using along top/left/right, logical px. Store-only
    /// here (layout() recomputes geometry from the values state.rs passes),
    /// kept so a getter-shaped future needs no signature change.
    _insets: Cell<(i32, i32, i32)>,
    /// The CLOSED strip's top inset, which is where the page starts.
    _strip_top: Cell<i32>,
    /// True while a modal covers the window (`ChromeLayout::Overlay`) and the
    /// chrome has been reordered above the page.
    lifted: Cell<bool>,
    /// Page fullscreen, for parity with the other backends' `Hosts`. Written
    /// by set_page_fullscreen; nothing reads it yet, because no engine event
    /// can enter fullscreen on this backend (see the page-fullscreen note).
    fullscreen: Cell<bool>,
}

/// One per tab. Opaque to the rest of the crate, like unix's.
pub struct TabView {
    state: Rc<RefCell<TabState>>,
}

pub fn create_hosts(window: Window) -> Hosts {
    Hosts {
        _window: window,
        _insets: Cell::new((CHROME_HEIGHT_PX, 0, 0)),
        _strip_top: Cell::new(CHROME_HEIGHT_PX),
        lifted: Cell::new(false),
        fullscreen: Cell::new(false),
    }
}

// , hover readout,
// Not ported. WebKitGTK gets one because GTK widgets can cheaply host a label
// over the content view; on macOS it would need another native view layered
// between chrome and page. Feature off, honestly: hover_readout_state reports
// disabled and the chrome renders nothing.

pub fn arm_hover_readout(_hosts: &Hosts, _scheme: crate::prefs::ChromeScheme) {}

pub fn set_hover_readout_scheme(_hosts: &Hosts, _scheme: crate::prefs::ChromeScheme) {}

pub fn set_hover_readout(_hosts: &Hosts, _text: Option<&str>) {}

pub fn hover_readout_state(_hosts: &Hosts) -> (bool, String) {
    (false, String::new())
}

pub fn show_all(hosts: &Hosts) {
    // The window starts hidden so the chrome lands before the first paint.
    hosts._window.set_visible(true);
}

pub fn new_webview_builder() -> WebViewBuilder<'static> {
    WebViewBuilder::new()
}

/// Separate data store from the chrome webview's. The translator itself is
/// not ported (see `translate_channel_supported`), so this only needs to keep
/// hostile page text on its own origin and its own store.
pub fn new_translator_webview_builder() -> WebViewBuilder<'static> {
    WebViewBuilder::new()
        .with_navigation_handler(|url: String| url.starts_with(super::TRANSLATE_ORIGIN_PREFIX))
}

/// Nothing to report: no macOS build ever wrote a profile beside the
/// executable, so there is no orphan to find.
pub fn report_stray_profile() {}

pub fn build_chrome(
    hosts: &Hosts,
    builder: WebViewBuilder<'_>,
    _proxy: &EventLoopProxy<UserEvent>,
) -> Result<WebView, wry::Error> {
    // Earliest engine touch on this path; same reason unix binds here.
    crate::tunnel_control::bind_if_enabled();
    // TRANSPARENT BACKGROUND. The chrome covers the whole window and the page
    // renders underneath it when a modal is up, so an opaque chrome would make
    // the stylesheet's "live dimmed page" scrim a lie. `drawsBackground` is a
    // private KVC key (macOS 10.14+); wry's transparent attribute writes it on
    // the WKWebViewConfiguration before the view exists, which is the only
    // shape that works, the same key sent to the built view raises
    // NSUnknownKeyException (and an ObjC exception aborts the process).
    let builder = builder.with_transparent(true);
    let webview = builder.build_as_child(&hosts._window)?;
    CHROME_TRANSPARENT.store(true, Ordering::Relaxed);

    // No context menu or shortcut wiring on the chrome webview yet, unix's
    // versions are GTK-signal shaped and need their NSMenu/NSResponder
    // counterparts. `ponytail:` the chrome still works; every menu action is
    // reachable through the chrome's own UI.
    // No privacy policy on the chrome webview on purpose: it is our own UI
    // (needs JavaScript, talks IPC), not web content.
    let _ = hosts;
    Ok(webview)
}

/// No-op on macOS. No permission decision is persisted for PATANYX to clear.
pub fn clear_persisted_permissions(_webview: &WebView) {}

/// No-op on macOS: WebKit owns keypad zoom and reports nothing; wry has no
/// zoom-changed surface here either. The indicator cannot drift because this
/// process is the only thing that moves the factor.
pub fn connect_zoom_changed(_webview: &WebView, _proxy: &EventLoopProxy<UserEvent>, _id: u64) {}

/// Builds the hidden translator webview.
///
/// HIDDEN BY CONSTRUCTION: built as a window child and immediately hidden, so
/// it can never paint a frame. Holds text scraped from hostile pages, so it
/// gets NO ipc handler and NO content-tab wiring.
pub fn build_translator(hosts: &Hosts, builder: WebViewBuilder<'_>) -> Result<WebView, wry::Error> {
    let webview = builder.build_as_child(&hosts._window)?;
    let _ = webview.set_visible(false);
    Ok(webview)
}

/// Builds the hidden tunnel-probe webview. Same shape as the translator.
pub fn build_probe(hosts: &Hosts, builder: WebViewBuilder<'_>) -> Result<WebView, wry::Error> {
    let webview = builder.build_as_child(&hosts._window)?;
    let _ = webview.set_visible(false);
    Ok(webview)
}

/// Converts logical px to the PHYSICAL-pixel rect wry's `set_bounds` takes
/// (wry converts back to logical via the backing scale, then flips Y to the
/// top-left-based frame Cocoa wants, so pass a top-left origin here).
fn set_bounds_logical(webview: &WebView, x: f64, y: f64, w: f64, h: f64) {
    let Some(win) = webview.webview().window() else {
        return;
    };
    let scale = win.backingScaleFactor() as f64;
    let rect = wry::Rect {
        position: wry::dpi::PhysicalPosition::new(
            (x * scale).round() as i32,
            (y * scale).round() as i32,
        )
        .into(),
        size: wry::dpi::PhysicalSize::new((w * scale).round() as i32, (h * scale).round() as i32)
            .into(),
    };
    let _ = webview.set_bounds(rect);
}

fn logical_window_size(hosts: &Hosts) -> (f64, f64) {
    let scale = hosts._window.scale_factor();
    let size = hosts._window.inner_size();
    (
        size.width as f64 / scale,
        size.height as f64 / scale,
    )
}

pub fn build_content(
    hosts: &Hosts,
    builder: WebViewBuilder<'_>,
    policy: &TabPolicy,
    proxy: &EventLoopProxy<UserEvent>,
    url: &str,
    _malicious_override: Rc<RefCell<std::collections::BTreeSet<String>>>,
    id: u64,
    // Windows-only feature; accepted so both backends keep one signature.
    _permissions: crate::state::PermissionBook,
) -> Result<(WebView, TabView, bool), wry::Error> {
    // Blank build, navigate after every script and filter is registered,
    // applying the URL on the builder starts WebKit loading during the build,
    // which races document-start registration and loses the first page's
    // probe reports. Same reasoning as unix's build_content.
    crate::tunnel_control::bind_if_enabled();
    let builder = match crate::tunnel_control::engine_proxy_port() {
        Some(port) => builder.with_proxy_config(wry::ProxyConfig::Socks5(wry::ProxyEndpoint {
            host: "127.0.0.1".to_string(),
            port: port.to_string(),
        })),
        None => builder, // TunnelMode::Off: direct, by the user's choice.
    };
    // wry's macOS incognito arm uses an ephemeral WKWebsiteDataStore; nothing
    // persists from an ephemeral tab.
    let builder = if policy.ephemeral {
        builder.with_incognito(true)
    } else {
        builder
    };
    // JavaScript off is a BUILD-TIME preference on WebKit (WKPreferences);
    // wry's attribute is the only honest lever. Post-build toggling does not
    // exist, which `script_setting` reports through the engine's own answer.
    let builder = if policy.javascript {
        builder
    } else {
        builder.with_javascript_disabled()
    };
    // The fingerprint-probe channel: the ONLY IPC any content view gets, and
    // its handler accepts exactly one strict JSON shape (decoded by
    // `fingerprint_probe_report`, deny_unknown_fields) before anything is
    // believed. wry injects its `window.ipc` shim on this view for it; a page
    // can post anything it likes and everything else is dropped here.
    let probe_proxy = proxy.clone();
    let builder = builder.with_ipc_handler(move |request| {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(request.body()) else {
            return;
        };
        if let Some(counts) = crate::state::fingerprint_probe_report(&value) {
            let _ = probe_proxy.send_event(UserEvent::FingerprintProbes {
                tab_id: id,
                counts,
            });
        }
    });

    let state = Rc::new(RefCell::new(TabState::new(policy)));
    // The handler above is either installed or build_content already failed;
    // there is no partial state to report honestly.
    state.borrow_mut().fingerprint_probe_reporting = SettingState::Applied;

    // Load events: state.rs already put an `on_page_load` handler on this
    // builder (UrlChanged/LoadState to the event loop). wry allows ONE such
    // handler, and the platform needs the same events to drive TabState,
    // on_load_started keys the local-network boundary, on_load_finished starts
    // the freeze grace clock, and without it a quarantine tab never
    // auto-freezes (windows.rs hit the identical trap; see its
    // NavigationCompleted note). So this REPLACES the caller's handler with
    // the same event sends PLUS the TabState calls. Keep in sync with
    // state.rs's closure. MUST happen before build, the builder is consumed.
    // `ponytail:` duplicated closure; if state.rs's grows, port the growth.
    let load_proxy = proxy.clone();
    let load_state = state.clone();
    let builder = builder.with_on_page_load_handler(
        move |event: wry::PageLoadEvent, url: String| {
            let loading = matches!(event, wry::PageLoadEvent::Started);
            if loading {
                let _ = load_proxy.send_event(UserEvent::UrlChanged(id, url.clone()));
                load_state.borrow_mut().on_load_started(Some(url.as_str()));
            } else {
                load_state.borrow_mut().on_load_finished(Instant::now());
            }
            let _ = load_proxy.send_event(UserEvent::LoadState(id, loading));
        },
    );

    // Built AFTER the chrome (which already exists as a window child), so the
    // content view lands on top in sibling order. Hidden until this tab is
    // the visible one.
    let webview = builder.build_as_child(&hosts._window)?;
    let _ = webview.set_visible(false);

    let view = TabView { state };
    apply_policy(&webview, &view, policy);
    // GPC's navigator property, document-start, all frames, main world, so
    // it is visible before the page's own scripts.
    install_content_scripts(&webview, &view);
    // The page-scrollbar courtesy, as an injected style. Author rules beat it
    // by definition, which is the "the page's own choice wins" contract.
    set_page_scrollbar(
        &webview,
        &view,
        crate::prefs::load().chrome_palette.scrollbar,
    );
    // Saved-profile promise: clear the persistent website data once per
    // process and hold this tab's first navigation behind the async
    // completion. Ephemeral tabs use an ephemeral store, nothing to clear.
    ITP_CONFIRMED.store(true, Ordering::Relaxed);
    let initial_navigation_pending = if policy.ephemeral {
        false
    } else {
        begin_new_session_wipe(proxy)
    };
    if !initial_navigation_pending {
        super::load_initial_url(&webview, id, url)?;
    }

    // Initial geometry so the tab's first show is not a zero frame if the
    // next relayout has not landed yet. layout() corrects everything after.
    {
        let (win_w, win_h) = logical_window_size(hosts);
        let (x, y, w, h) = super::page_rect(
            win_w,
            win_h,
            CHROME_HEIGHT_PX,
            0,
            0,
            0,
            super::PAGE_FRAME_PX,
        );
        set_bounds_logical(&webview, x, y, w, h);
    }

    Ok((webview, view, initial_navigation_pending))
}

// ,
// User scripts and content filters
//
// One `WKUserContentController` per webview (wry's `manager()`). All script
// installs go through `install_content_scripts`, which clears and re-adds the
// full set, WebKit has no per-script removal without keeping instances, and
// the set is small enough that rebuild is cheaper than bookkeeping.

const GPC_INJECTION: objc2_web_kit::WKUserScriptInjectionTime =
    objc2_web_kit::WKUserScriptInjectionTime::AtDocumentStart;
const STYLE_INJECTION: objc2_web_kit::WKUserScriptInjectionTime =
    objc2_web_kit::WKUserScriptInjectionTime::AtDocumentEnd;

/// Wraps author CSS in a style-injecting IIFE. This is the macOS shape of
/// unix's user STYLESHEET: WKUserScript is the only per-view style channel,
/// and the CSS crosses as DATA (json-escaped), nothing page-controlled ever
/// becomes code on this path.
fn css_user_script(mtm: MainThreadMarker, css: &str, at_start: bool) -> Option<Retained<WKUserScript>> {
    let escaped = serde_json::to_string(css).ok()?;
    let js = format!(
        "(function(){{var s=document.createElement('style');\
         s.setAttribute('data-patanyx','1');s.textContent={escaped};\
         (document.head||document.documentElement).appendChild(s);}})();"
    );
    Some(user_script(
        mtm,
        &js,
        if at_start { GPC_INJECTION } else { STYLE_INJECTION },
    ))
}

fn user_script(
    mtm: MainThreadMarker,
    source: &str,
    at: objc2_web_kit::WKUserScriptInjectionTime,
) -> Retained<WKUserScript> {
    // SAFETY: main-thread allocation of a plain WebKit value object; init
    // never fails for a non-nil source.
    unsafe {
        WKUserScript::initWithSource_injectionTime_forMainFrameOnly(
            WKUserScript::alloc(mtm),
            &NSString::from_str(source),
            at,
            false,
        )
    }
}

fn content_controller(webview: &WebView) -> Option<Retained<objc2_web_kit::WKUserContentController>> {
    Some(webview.manager())
}

/// Installs this tab's full user-script set: GPC always, fingerprint noise
/// when ephemeral, cosmetic hiding when ad blocking is on, scrollbar colour.
/// Called on every change; `removeAllUserScripts` makes re-registration a
/// rebuild rather than a diff.
fn install_content_scripts(webview: &WebView, view: &TabView) {
    let Some(cc) = content_controller(webview) else { return };
    let mtm = main_thread_marker();
    let (ephemeral, block_ads) = {
        let st = view.state.borrow();
        (st.policy.ephemeral, st.policy.block_ads)
    };
    // SAFETY: main-thread controller mutation.
    unsafe {
        cc.removeAllUserScripts();
        cc.addUserScript(&user_script(mtm, privacy::GPC_SCRIPT, GPC_INJECTION));
        if let Some(source) = privacy::divergence_script(ephemeral) {
            cc.addUserScript(&user_script(mtm, &source, GPC_INJECTION));
        }
        if block_ads {
            let css = privacy::cosmetic_css(privacy::bundled_rules());
            if !css.is_empty() {
                if let Some(script) = css_user_script(mtm, &css, false) {
                    cc.addUserScript(&script);
                }
            }
        }
    }
}

pub fn page_scrollbar_support() -> &'static str {
    // Same honesty as unix: the style is installed, but WebKit's scrollbar
    // rendering does not reliably honour author colour for the whole bar, so
    // the feature cannot promise what the copy says.
    "unsupported"
}

pub fn set_page_scrollbar(webview: &WebView, view: &TabView, rgb: [u8; 3]) {
    let css = privacy::page_scrollbar_css(rgb);
    if css.is_empty() {
        return;
    }
    let mtm = main_thread_marker();
    let Some(script) = css_user_script(mtm, &css, false) else { return };
    // Rebuild the whole set with the new colour. Author rules win by
    // definition (injected as a user script, the page's own <style> tags
    // still win the cascade), which is the page's-own-choice contract.
    install_content_scripts_with_scrollbar(webview, view, &script);
}

fn install_content_scripts_with_scrollbar(
    webview: &WebView,
    view: &TabView,
    scrollbar: &WKUserScript,
) {
    let Some(cc) = content_controller(webview) else { return };
    let mtm = main_thread_marker();
    let (ephemeral, block_ads) = {
        let st = view.state.borrow();
        (st.policy.ephemeral, st.policy.block_ads)
    };
    // SAFETY: main-thread controller mutation.
    unsafe {
        cc.removeAllUserScripts();
        cc.addUserScript(&user_script(mtm, privacy::GPC_SCRIPT, GPC_INJECTION));
        if let Some(source) = privacy::divergence_script(ephemeral) {
            cc.addUserScript(&user_script(mtm, &source, GPC_INJECTION));
        }
        if block_ads {
            let css = privacy::cosmetic_css(privacy::bundled_rules());
            if !css.is_empty() {
                if let Some(script) = css_user_script(mtm, &css, false) {
                    cc.addUserScript(&script);
                }
            }
        }
        cc.addUserScript(scrollbar);
    }
}

// , compiled content filters (WKContentRuleList),

/// The shipped filters. TWO, not one merged set, for the same reason unix
/// states: WebKit refuses a compiled list over 150,000 rules and the merged
/// set brushes it. Each is well under.
#[derive(Clone, Copy)]
enum BundledFilter {
    Ads,
    Tracking,
}

impl BundledFilter {
    fn id(self) -> &'static str {
        match self {
            BundledFilter::Ads => privacy::bundled_ads_filter_id(),
            BundledFilter::Tracking => privacy::bundled_tracking_filter_id(),
        }
    }

    fn json(self) -> String {
        match self {
            BundledFilter::Ads => privacy::content_blocker_json(privacy::bundled_ads()),
            BundledFilter::Tracking => privacy::content_blocker_json(privacy::bundled_tracking()),
        }
    }
}

fn rule_list_store() -> Option<Retained<WKContentRuleListStore>> {
    // SAFETY: process-wide singleton, main thread.
    unsafe { WKContentRuleListStore::defaultStore(main_thread_marker()) }
}

/// Compiles `json` into a content rule list and adds it to `cc`.
///
/// Degrades rather than crashing: any failure leaves the controller without
/// this filter, visible as ads not being blocked, never as a panic mid
/// session. `freeze_state`, when present, is marked `Failed` on every path
/// that does not reach the engine, so a freeze that failed to compile cannot
/// keep the UI saying "Frozen, making no requests".
fn compile_and_add(
    cc: &Retained<objc2_web_kit::WKUserContentController>,
    json: &str,
    freeze_state: Option<Rc<RefCell<TabState>>>,
) {
    let Some(store) = rule_list_store() else {
        if let Some(state) = &freeze_state {
            state.borrow_mut().freeze.note_enforcement_failed();
        }
        diag("content rule list store unavailable");
        return;
    };
    // The block outlives this frame, so it captures the controller by value.
    let cc = cc.clone();
    let id_string = privacy::filter_id_for(json);
    let id = NSString::from_str(&id_string);
    let source = NSString::from_str(json);
    // SAFETY: the block is retained by the callee for the async lifetime; the
    // captures (controller, state) are Rc, and WebKit raises this callback on
    // the main thread the webview was built on. Block parameters are
    // __unsafe_unretained object pointers, retained before use.
    unsafe {
        store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler(
            Some(&id),
            Some(&source),
            Some(&block2::RcBlock::new(
                move |list: *mut WKContentRuleList, error: *mut objc2_foundation::NSError| {
                    if !list.is_null() {
                        let list = Retained::retain(list).expect("rule list pointer");
                        cc.addContentRuleList(&list);
                        if let Some(state) = &freeze_state {
                            state.borrow_mut().freeze.note_enforced();
                        }
                    } else {
                        let why = (!error.is_null())
                            .then(|| Retained::retain(error).expect("error pointer"))
                            .map(|e| e.localizedDescription().to_string())
                            .unwrap_or_else(|| "unknown error".to_string());
                        match &freeze_state {
                            Some(state) => {
                                state.borrow_mut().freeze.note_enforcement_failed();
                                diag(&format!("freeze filter not installed: {why}"));
                            }
                            None => {
                                diag(&format!("ad/tracker filter not installed: {why}"));
                            }
                        }
                    }
                },
            )),
        );
    }
}

/// Installs both shipped filters, compile-first. WebKit's store has no
/// load-first query in the pinned bindings; compilation is cached by
/// identifier in-process, and the OS-level recompile cost is the price of
/// first run per session. `ponytail:` no disk cache probe; add when tab
/// startup measurably pays for it.
fn install_bundled_filters(cc: &Retained<objc2_web_kit::WKUserContentController>) {
    let ads = BundledFilter::Ads.json();
    let tracking = BundledFilter::Tracking.json();
    compile_and_add(cc, &ads, None);
    compile_and_add(cc, &tracking, None);
}

/// Removes every compiled rule list. Filters are managed as a set, so this
/// drops ad filters AND any freeze filter, callers re-install what should
/// survive, which is what makes the "ORs its filters" hazard unix documents
/// structurally impossible here.
fn remove_all_filters(cc: &objc2_web_kit::WKUserContentController) {
    // SAFETY: main-thread controller mutation.
    unsafe { cc.removeAllContentRuleLists() };
}

/// Installs the freeze filter for the tab's OWN webview: everything except
/// the session's allow-override hosts. Clear-first (a previous freeze filter
/// with wider exceptions must not survive alongside the narrower new one),
/// then compile-and-add with the state handed to the completion, so the
/// enforcement ledger only records what WebKit confirmed.
fn install_freeze_filter(webview: &WebView, view: &TabView) {
    let Some(cc) = content_controller(webview) else { return };
    let exceptions = view.state.borrow().freeze.overrides();
    let json = privacy::freeze_filter_json(&exceptions);
    remove_all_filters(&cc);
    compile_and_add(&cc, &json, Some(view.state.clone()));
}

/// Whether freezing actually blocks requests on this platform.
pub fn freeze_enforced() -> bool {
    true
}

// ,
// Upstream API surface (state.rs is cfg-free; unix.rs is the semantic
// reference). WebKit enforces blocking inside the engine via content rule
// lists, so the navigation/wipe bookkeeping that coordinates a UI-process
// veto on Windows is structurally absent here, the no-op/true shapes
// below match unix.rs for the same reasons.

/// No-op: the local-network boundary has no per-request veto to enforce it
/// with on WebKit (blocking happens in the engine, see the header comment).
pub fn note_app_navigation(_view: &TabView, _url: &str) {}

/// No-op, as `note_app_navigation`.
pub fn forget_app_navigation(_view: &TabView) {}

/// Always: nothing but the session wipe holds a first page here, and
/// AppState already waits for that.
pub fn initial_navigation_ready(_view: &TabView) -> bool {
    true
}

/// No-op: the WebSocket guard is Windows-only, so nothing here is overdue.
pub fn note_local_network_guard_overdue(_view: &TabView) {}

/// A tab's first navigation could not be issued (host only:
/// `super::initial_navigation_failure_line`).
pub fn report_initial_navigation_failure(url: &str, error: &wry::Error) {
    diag(&super::initial_navigation_failure_line(url, error));
}

/// No-op: the tab's pending flag is the whole wipe state here.
pub fn note_session_wipe_finished(_view: &TabView) {}

/// A pending first page here means the tab waits for the session wipe.
pub fn holds_session_wipe(_view: &TabView, first_page_pending: bool) -> bool {
    first_page_pending
}

/// No standing to hand over: the local-network boundary is not enforced in
/// the UI process on WebKit (see `note_app_navigation`).
pub struct NewTabGate;

pub fn new_tab_gate(_view: &TabView) -> NewTabGate {
    NewTabGate
}

/// Always true, for the same reason as `note_app_navigation`: refusing a
/// page's new tab here while the page itself may reach the same address
/// would be a rule with nothing behind it.
pub fn new_tab_allowed(_gate: Option<&NewTabGate>, _url: &str) -> bool {
    true
}

// ,
// Session wipe
//
// WebKit's default store persists cookies, caches and storage between runs.
// One explicit type-set clear per process, held behind its async completion:
// HSTS is deliberately NOT in the set, matching the unix mask's promise.

pub fn begin_new_session_wipe(proxy: &EventLoopProxy<UserEvent>) -> bool {
    match super::enter_session_wipe() {
        super::SessionWipeEntry::Ready => return false,
        super::SessionWipeEntry::Waiting => return true,
        super::SessionWipeEntry::Start => {}
    }
    let types = NSSet::from_slice(&[
        ns_string!("WKWebsiteDataTypeCookies"),
        ns_string!("WKWebsiteDataTypeDiskCache"),
        ns_string!("WKWebsiteDataTypeMemoryCache"),
        ns_string!("WKWebsiteDataTypeOfflineWebApplicationCache"),
        ns_string!("WKWebsiteDataTypeLocalStorage"),
        ns_string!("WKWebsiteDataTypeSessionStorage"),
        ns_string!("WKWebsiteDataTypeWebSQLDatabases"),
        ns_string!("WKWebsiteDataTypeIndexedDBDatabases"),
        ns_string!("WKWebsiteDataTypeServiceWorkerRegistrations"),
        ns_string!("WKWebsiteDataTypeFetchCache"),
        ns_string!("WKWebsiteDataTypeHashSalt"),
    ]);
    // SAFETY: main-thread singleton store; the block is retained by WebKit.
    let store = unsafe {
        objc2_web_kit::WKWebsiteDataStore::defaultDataStore(main_thread_marker())
    };
    let proxy = proxy.clone();
    // SAFETY: completion block retained by WebKit; runs on the main thread.
    unsafe {
        store.removeDataOfTypes_modifiedSince_completionHandler(
            &types,
            &NSDate::distantPast(),
            &block2::RcBlock::new(move || {
                super::finish_session_wipe();
                let _ = proxy.send_event(UserEvent::SessionWipeFinished);
            }),
        );
    }
    true
}

// ,
// Translate, NOT ported. The GTK translator rides WebKitGTK's
// script-message-with-reply channel, which has no WebKit equivalent in the
// pinned bindings (building one means script evaluation in a content view,
// which is forbidden absolutely). The types and constants exist so the rest
// of the crate keeps one surface; every entry point reports unsupported.

pub const TRANSLATE_CHANNEL: &str = "patanyxTranslate";
pub const TRANSLATE_ASK_CHANNEL: &str = "patanyxTranslateAsk";
pub const TRANSLATE_POLL_REQUEST: &str = "poll";

pub fn translate_channel_supported() -> bool {
    false
}

pub fn connect_translate_channel(
    _webview: &WebView,
    _id: u64,
    _proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    false
}

pub fn connect_translate_reply_channel(_webview: &WebView) -> bool {
    false
}

/// Placeholder for unix's parked WebKit reply. Never constructed here: the
/// macOS channel does not exist, so nothing ever parks.
pub struct ParkedReply;

impl ParkedReply {
    fn answer(self, _text: &str) {}
}

/// The mailbox between the event loop and one content page. macOS edition:
/// nothing parks (there is no page-side channel), so `deliver` only queues
/// and `is_parked` is always false. The token discipline stays, because the
/// type's contract, an exact expected request, constant-time compared, is
/// what any future port must satisfy.
#[derive(Default)]
pub struct TranslateOutbox {
    expected_request: String,
    pending: std::collections::VecDeque<String>,
    cleared: u64,
}

const MAX_PENDING_TRANSLATE_MESSAGES: usize = 8;

impl TranslateOutbox {
    pub fn with_token(token: &str) -> Self {
        Self {
            expected_request: if token.is_empty() {
                // Unmatchable on purpose: a token we could not randomise must
                // not become a predictable one.
                String::new()
            } else {
                format!("{TRANSLATE_POLL_REQUEST}:{token}")
            },
            ..Self::default()
        }
    }

    pub fn expected_request(&self) -> &str {
        &self.expected_request
    }

    pub fn deliver(&mut self, message: String) -> bool {
        if self.pending.len() >= MAX_PENDING_TRANSLATE_MESSAGES {
            return false;
        }
        self.pending.push_back(message);
        true
    }

    pub fn is_parked(&self) -> bool {
        false
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.cleared = self.cleared.wrapping_add(1);
    }

    pub fn clears(&self) -> u64 {
        self.cleared
    }
}

pub fn deliver_translation(_webview: &WebView, _view: &TabView, _message: String) -> bool {
    false
}

pub fn translate_page_ready(_view: &TabView) -> bool {
    false
}

pub fn translate_poll_parked(_view: &TabView) -> bool {
    false
}

pub fn translate_outbox_clears(_view: &TabView) -> u64 {
    0
}

// ,
// Policy, freeze, filters

pub fn apply_policy(webview: &WebView, view: &TabView, policy: &TabPolicy) {
    {
        let mut st = view.state.borrow_mut();
        st.policy = policy.clone();
        st.freeze.set_auto(policy.freeze_after_load);
    }
    // Record what the ENGINE did, not what was asked: the preference was set
    // at build time (see build_content); read it back and report that.
    let applied = {
        // SAFETY: main-thread read of this webview's own configuration.
        let pref = unsafe {
            webview.webview().configuration().preferences()
        };
        // SAFETY: main-thread property read. The deprecated getter is the one
        // that mirrors the deprecated builder attribute actually used.
        #[allow(deprecated)]
        let enabled = unsafe { pref.javaScriptEnabled() };
        enabled == policy.javascript
    };
    view.state.borrow_mut().script_setting = if applied {
        SettingState::Applied
    } else {
        SettingState::Failed
    };
    set_ad_blocking(webview, view, policy.block_ads);
}

fn set_ad_blocking(webview: &WebView, view: &TabView, enable: bool) {
    // Cosmetic hiding rides the user-script set; the network half rides the
    // rule lists. Both halves, or the claim is not true.
    install_content_scripts(webview, view);
    let Some(cc) = content_controller(webview) else { return };
    if enable {
        install_bundled_filters(&cc);
    } else {
        remove_all_filters(&cc);
        // Removing every filter also drops any freeze filter, so a frozen tab
        // whose ad blocking is switched off must re-install it.
        if view.state.borrow().freeze.phase() == FreezePhase::Frozen {
            install_freeze_filter(webview, view);
        }
    }
}

/// WebKit's ITP is enabled or absent; it has no Strict/Balanced level. The
/// honest answer is NotAttempted, nothing was or could be configured.
pub fn set_tracking_prevention(
    _webview: &WebView,
    view: &TabView,
    _level: crate::prefs::TrackingPreventionLevel,
) -> TrackingPreventionState {
    view.state.borrow_mut().tracking_prevention = TrackingPreventionState::NotAttempted;
    TrackingPreventionState::NotAttempted
}

/// Manual freeze: immediate, per-tab, survives the page's load finishing.
pub fn freeze(webview: &WebView, view: &TabView) {
    view.state.borrow_mut().freeze.freeze();
    install_freeze_filter(webview, view);
}

/// One-call unfreeze. Removes the freeze filter and puts ad blocking back if
/// the policy still wants it, filters are removed as a set, so the ad filter
/// necessarily went with the freeze filter.
pub fn unfreeze(webview: &WebView, view: &TabView) {
    let block_ads = {
        let mut st = view.state.borrow_mut();
        st.freeze.unfreeze(Instant::now());
        st.freeze_json = None;
        st.policy.block_ads
    };
    let Some(cc) = content_controller(webview) else { return };
    remove_all_filters(&cc);
    if block_ads {
        install_bundled_filters(&cc);
    }
}

/// Set or clear this tab's ad-list override. Same call in both directions so
/// the revocation cannot be the path nobody wrote. State-only on macOS: there
/// is no per-host exception in the rule-list model (same as WebKitGTK).
pub fn set_adlist_override(view: &TabView, host: Option<String>) {
    view.state.borrow_mut().set_adlist_override(host);
}

/// Per-site override: `host` keeps working even while the tab is frozen.
pub fn allow_site(webview: &WebView, view: &TabView, host: &str) {
    let frozen = {
        let mut st = view.state.borrow_mut();
        st.freeze.add_override(host);
        st.freeze.phase() == FreezePhase::Frozen
    };
    if frozen {
        install_freeze_filter(webview, view);
    }
}

/// Not implemented on this backend, always refuses, like unix. WebKit CAN
/// clear per-host cookies (`deleteDataForDomain`), but the feature's contract
/// was designed and verified on Windows' cookie manager; shipping an
/// unverified path in a privacy browser is worse than refusing it.
pub fn forget_site_cookies(_webview: &WebView, _host: &str) -> bool {
    false
}

/// Not implemented, same rule as unix: the browser-wide clear this feature
/// is allowed to touch is cookies alone, and the untested path stays closed.
pub fn forget_all_cookies(_webview: &WebView) -> bool {
    false
}

// ,
// Diagnostics

const DIAG_LOG_CAP: usize = 50;
static DIAG_LOG: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<String>>> =
    std::sync::OnceLock::new();

/// One bounded, host-only diagnostic ring. HOST ONLY, never a full URI: the
/// ring is process-global and ships in diagnostics exports (R-002), and a
/// private tab's full URL must never land in it (R-001).
fn diag(message: &str) {
    if cfg!(debug_assertions) {
        eprintln!("patanyx: {message}");
    }
    let Ok(mut log) = DIAG_LOG.get_or_init(Default::default).lock() else {
        return; // Poisoned lock tolerated: logging never takes the process down.
    };
    if log.len() >= DIAG_LOG_CAP {
        log.pop_front();
    }
    log.push_back(message.to_string());
}

pub fn recent_diagnostics() -> Vec<String> {
    DIAG_LOG
        .get_or_init(Default::default)
        .lock()
        .map(|log| log.iter().cloned().collect())
        .unwrap_or_default()
}

// ,
// Readers

pub fn fill_credential(_webview: &WebView, _username: &str, _password: &str) -> bool {
    // Content-script autofill is Windows-only for this pass; nothing was
    // attempted here. Refuse rather than type into a page.
    false
}

pub fn ledger(view: &TabView) -> Vec<HostRecord> {
    view.state.borrow().ledger.snapshot()
}

pub fn blocked_total(view: &TabView) -> u64 {
    view.state.borrow().ledger.blocked_total()
}

pub fn page_insecure(view: &TabView) -> bool {
    view.state.borrow().page_insecure
}

pub fn tls_state(webview: &WebView, view: &TabView) -> TlsState {
    let st = view.state.borrow();
    // The live URL's scheme is the engine's own current truth; the state's
    // last verdict fills in when there is no URL to read yet.
    // SAFETY: main-thread property read.
    if let Some(url) = unsafe { webview.webview().URL() } {
        if let Some(scheme) = url.scheme() {
            match scheme.to_string().as_str() {
                "https" => return TlsState::Normal,
                "http" => return TlsState::NotTls,
                _ => {}
            }
        }
    }
    st.tls_error_verdict.unwrap_or(TlsState::NotTls)
}

pub fn tls_issuer(_webview: &WebView, view: &TabView) -> Option<String> {
    // WebKit exposes no UI-process certificate info without the private
    // diagnostics delegate; the last verdict from a TLS error page is all
    // there is to say honestly.
    view.state.borrow().tls_issuer.clone()
}

pub fn profile_mode(view: &TabView) -> ProfileMode {
    view.state.borrow().profile_mode()
}

pub fn freeze_phase(view: &TabView) -> FreezePhase {
    view.state.borrow().freeze.phase()
}

pub fn freeze_enforcement(view: &TabView) -> privacy::FreezeEnforcement {
    view.state.borrow().freeze.enforcement()
}

pub fn engine_settings(view: &TabView) -> EngineSettings {
    let st = view.state.borrow();
    EngineSettings {
        smartscreen_off: st.smartscreen_off.as_str(),
        tracking_prevention: st.tracking_prevention.as_str(),
        navigation_tracking: st.navigation_tracking.as_str(),
        autofill_off: st.autofill_off.as_str(),
        ephemeral_confirmed: st.ephemeral_confirmed.as_str(),
        // No equivalent on WebKit: there is no environment object to create
        // and no crash-report upload to suppress. "Not attempted" is the
        // honest answer, exactly as on unix.
        hardened_environment: SettingState::NotAttempted.as_str(),
        session_lock_registered: SettingState::NotAttempted.as_str(),
        content_script_registered: SettingState::NotAttempted.as_str(),
        permissions_registered: SettingState::NotAttempted.as_str(),
        // Same source as both other backends on purpose: the tunnel is the
        // one setting here that is genuinely cross-platform.
        tunnel: crate::tunnel_control::report(),
        // WKWebView's WebContent sandbox is the OS's, always on, and not
        // queryable through the pinned bindings, so the per-tab answer stays
        // TabState's default, "not attempted", exactly like every other
        // engine state this backend cannot measure.
        sandbox: st.sandbox.as_str(),
    }
}

pub fn script_setting(view: &TabView) -> &'static str {
    view.state.borrow().script_setting.as_str()
}

pub fn fingerprint_probe_reporting(view: &TabView) -> &'static str {
    view.state.borrow().fingerprint_probe_reporting.as_str()
}

pub fn interception_state(_view: &TabView) -> &'static str {
    MACOS_INTERCEPTION_NAME
}

/// Network-level request blocking works on macOS via compiled content rule
/// lists. Not a firewall: it governs what the WEB ENGINE does, nothing about
/// traffic from outside the content process.
pub fn network_blocking_supported() -> bool {
    true
}

// ,
// Clipboard, files, devtools, printing

/// SAFETY per call site: every caller runs on the main thread (the event
/// loop), which is what Cocoa requires for these classes.
fn main_thread_marker() -> MainThreadMarker {
    // SAFETY: all of this module's entry points are invoked from tao's event
    // loop, which runs on the main thread by construction (tao asserts it).
    unsafe { MainThreadMarker::new_unchecked() }
}

pub fn set_clipboard_text(text: &str) -> bool {
    let pasteboard = NSPasteboard::generalPasteboard();
    pasteboard.clearContents();
    // SAFETY: extern static, read on the main thread.
    let utf8 = unsafe { objc2_app_kit::NSPasteboardTypeString };
    pasteboard.setString_forType(&NSString::from_str(text), utf8)
}

/// Whether the user can be asked to choose a file. True: NSOpenPanel is the
/// same modal shape the GTK portal gives unix.
pub fn file_choice_supported() -> bool {
    true
}

/// Asks the user for one existing file. Modal, on the main thread, which is
/// correct in this position: the caller is mid-IPC on the event loop. Returns
/// None on cancel, which callers treat as "no answer", never an error.
pub fn pick_file_to_open(_hosts: &Hosts, title: &str) -> Option<std::path::PathBuf> {
    let mtm = main_thread_marker();
    let panel = NSOpenPanel::openPanel(mtm);
    panel.setCanChooseFiles(true);
    panel.setCanChooseDirectories(false);
    panel.setAllowsMultipleSelection(false);
    panel.setTitle(Some(&NSString::from_str(title)));
    if panel.runModal() != objc2_app_kit::NSModalResponseOK {
        return None;
    }
    let urls = panel.URLs();
    let url = urls.firstObject()?;
    url.path().map(|p| std::path::PathBuf::from(p.to_string()))
}

/// Asks the user where to write one file, pre-filled with `suggested_name`.
/// The suggestion is a NAME, never a path.
pub fn pick_file_to_save(
    _hosts: &Hosts,
    title: &str,
    suggested_name: &str,
) -> Option<std::path::PathBuf> {
    let mtm = main_thread_marker();
    let panel = NSSavePanel::savePanel(mtm);
    panel.setTitle(Some(&NSString::from_str(title)));
    panel.setNameFieldStringValue(&NSString::from_str(suggested_name));
    if panel.runModal() != objc2_app_kit::NSModalResponseOK {
        return None;
    }
    let url = panel.URL()?;
    url.path().map(|p| std::path::PathBuf::from(p.to_string()))
}

/// Whether this engine can hand back the bytes it was served for the main
/// resource. False: WebKit offers no UI-process path to the rendered main
/// resource, and re-fetching would be a different document, the one thing
/// integrity checking exists to catch. Feature unavailable, honestly.
pub fn page_bytes_supported() -> bool {
    false
}

/// The answer always arrives as `UserEvent::Integrity`, even when the platform
/// cannot serve it: callers key follow-up UI on the event, never on this call
/// returning.
pub fn request_main_resource_bytes(
    _webview: &WebView,
    token: u64,
    proxy: &EventLoopProxy<UserEvent>,
) {
    let _ = proxy.send_event(UserEvent::Integrity(IntegrityEvent::PageBytes {
        token,
        result: Err(PageBytesError::NoMainResource),
    }));
}

/// Opens WebKit's inspector on this CONTENT webview via wry (developer extras
/// are enabled on content views only). The privileged chrome must never be
/// the thing that opens it.
pub fn open_devtools(webview: &WebView) {
    webview.open_devtools();
}

pub fn show_print_ui(_webview: &WebView) -> bool {
    // WKWebView's print path needs its own verification pass on a real
    // session; false keeps the caller honest rather than reporting a preview
    // that never opened.
    false
}

pub fn save_page_as_pdf(
    _webview: &WebView,
    _dest: &std::path::Path,
    _proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    // WKWebView's createPDF is a different API shape and needs its own
    // verification pass; unavailable beats a button that does nothing.
    false
}

/// Lock-the-vault-when-the-screen-locks: needs the distributed-notification
/// centre and its own verification pass; deferred, not half-built. Same
/// reasoning as unix's logind deferral.
pub fn connect_session_lock(_hosts: &Hosts, _proxy: &EventLoopProxy<UserEvent>) {}

pub fn session_lock_registered() -> SettingState {
    SettingState::NotAttempted
}

pub fn fix_downloads(_webview: &WebView) {
    // wry's macOS download delegate already lands files at the paths this
    // process chose; unix needs this hook for GTK's scheme quirks, macOS does
    // not (yet).
}

// ,
// Find, NOT ported. WebKit has no find-in-page API in the pinned bindings
// (the private WKFindInteractionHost is out of bounds). Every entry point is
// an honest no-op and `find_probe` reports false, so the chrome renders the
// bar as unavailable instead of a control that does nothing.

/// Identity key shared with the UserEvent path. The native view's address is
/// stable for the webview's life, which is all this key needs to be.
pub fn find_key(webview: &WebView) -> usize {
    Retained::as_ptr(&webview.webview()) as usize
}

pub fn find_probe(_webview: &WebView) -> bool {
    false
}

pub fn find_start(
    _webview: &WebView,
    _query: &str,
    _generation: u64,
    _proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    false
}

pub fn find_next(_webview: &WebView) {}

pub fn find_previous(_webview: &WebView) {}

pub fn find_stop(_webview: &WebView) {}

pub fn find_teardown(_webview: &WebView) {}

// ,
// Page theme, capture, tab lifecycle

/// Asks pages for the given prefers-color-scheme. The honest lever is the
/// application appearance: WebKit derives the media query from it, app-wide
/// by nature (the window chrome follows along), never anything injected into
/// content.
pub fn apply_page_theme(_webview: &WebView, theme: crate::prefs::PageTheme) -> bool {
    let mtm = main_thread_marker();
    let app = NSApplication::sharedApplication(mtm);
    let named = match theme {
        crate::prefs::PageTheme::Auto => None,
        // SAFETY: extern statics, read on the main thread.
        crate::prefs::PageTheme::Dark => Some(unsafe { objc2_app_kit::NSAppearanceNameDarkAqua }),
        crate::prefs::PageTheme::Light => Some(unsafe { objc2_app_kit::NSAppearanceNameAqua }),
    };
    let appearance = named.and_then(NSAppearance::appearanceNamed);
    // nil is the documented "follow the system" value.
    app.setAppearance(appearance.as_deref());
    true
}

// , page capture,

/// Ask WebKit for the requested snapshot region and deliver PNG bytes (or an
/// honest failure) as a UserEvent. Visible-area only: WKSnapshotConfiguration
/// has no full-document option, so FullPage refuses rather than relabeling a
/// viewport crop as the whole page.
pub fn capture_page(
    webview: &WebView,
    proxy: &EventLoopProxy<UserEvent>,
    requested: crate::capture::CaptureScope,
) {
    if matches!(requested, crate::capture::CaptureScope::FullPage) {
        let _ = proxy.send_event(UserEvent::Capture(crate::capture::CaptureEvent {
            png: Err("capture_full_page_unsupported"),
            scope: requested,
        }));
        return;
    }
    let proxy = proxy.clone();
    let wv = webview.webview();
    // SAFETY: main-thread snapshot; the completion block is retained by
    // WebKit and raised on the main thread. Block parameters are
    // __unsafe_unretained object pointers, retained before use.
    unsafe {
        wv.takeSnapshotWithConfiguration_completionHandler(
            None,
            &block2::RcBlock::new(
                move |image: *mut NSImage, _error: *mut objc2_foundation::NSError| {
                    let png: Result<Vec<u8>, &'static str> = (|| {
                        let image = Retained::retain(image).ok_or("capture_engine_failed")?;
                        let tiff = image.TIFFRepresentation().ok_or("capture_engine_failed")?;
                        let rep = NSBitmapImageRep::initWithData(
                            main_thread_marker().alloc(),
                            &tiff,
                        )
                        .ok_or("capture_engine_failed")?;
                        let data = rep
                            .representationUsingType_properties(
                                NSBitmapImageFileType::PNG,
                                &NSDictionary::new(),
                            )
                            .ok_or("capture_engine_failed")?;
                        Ok(data.to_vec())
                    })();
                    let _ = proxy.send_event(UserEvent::Capture(crate::capture::CaptureEvent {
                        png,
                        scope: crate::capture::CaptureScope::VisibleArea,
                    }));
                },
            ),
        );
    }
}

pub fn show_tab(_view: &TabView, webview: &WebView) {
    // Geometry lands on the next relayout, which state.rs performs on every
    // activation; showing is visibility only.
    let _ = webview.set_visible(true);
    // Focus travels WITH the show, as on Windows: state.rs activates the
    // current tab at startup, and on that backend show_tab focuses the shown
    // webview, which is the only reason keyboard ever reaches a page. Without
    // the same call here the window's first responder stayed the content
    // view, clicks still worked (buttons need no responder), and every
    // keystroke in every webview went nowhere.
    let _ = webview.focus();
}

pub fn hide_tab(_view: &TabView, webview: &WebView) {
    let _ = webview.set_visible(false);
}

/// Give a tab's page the keyboard (wry's focus on the WKWebView).
pub fn focus_content(webview: &WebView) {
    let _ = webview.focus();
}

pub fn remove_tab(view: &TabView, webview: &WebView) {
    find_teardown(webview);
    // The tab's refusals move into the session receipt (structurally zero on
    // this backend, see blocked_total, but folded anyway so the accounting
    // is one code path, not a platform special case).
    privacy::fold_closed_tab(std::mem::take(&mut view.state.borrow_mut().ledger));
    // The window's content view retains the webview; dropping our handle
    // alone would leak the page. Detach first, then the drop is real.
    webview.webview().removeFromSuperview();
}

// ,
// Window geometry

pub fn set_chrome_height(hosts: &Hosts, px: i32) {
    let (_, left, right) = hosts._insets.get();
    hosts._insets.set((px, left, right));
}

/// The CLOSED strip's height, which is where the page starts. Stated by the
/// chrome rather than worked out here (see unix's note: a panel's height
/// arrives through this same command while a modal is open).
pub fn set_chrome_strip(hosts: &Hosts, px: i32) {
    hosts._strip_top.set(px);
}

/// The title bar is the system's on this backend, and its colour is the
/// desktop theme's, not ours. Accepted so state.rs has one call on both
/// platforms; the chrome's own frame is all the accent there is here.
pub fn set_window_accent(_hosts: &Hosts, _palette: &super::ChromePalette) -> bool {
    false
}

pub fn reapply_window_accent(_hosts: &Hosts, _palette: &super::ChromePalette) {}

pub fn refresh_window_accent(_hosts: &Hosts, _palette: &super::ChromePalette) {}

/// The OS's answer; only the Windows backend acts on it.
pub fn window_is_maximized(hosts: &Hosts) -> bool {
    hosts._window.is_maximized()
}

pub fn set_chrome_left(hosts: &Hosts, px: i32) {
    let (top, _, right) = hosts._insets.get();
    hosts._insets.set((top, px, right));
}

pub fn set_chrome_right(hosts: &Hosts, px: i32) {
    let (top, left, _) = hosts._insets.get();
    hosts._insets.set((top, left, px));
}

pub fn layout(
    hosts: &Hosts,
    chrome: &WebView,
    active: Option<&WebView>,
    // Side by Side's right-hand page. Both panes are positioned here, the
    // same one signature as the other backends; the ARRANGEMENT below still
    // owns the z-order flip.
    pair: Option<(&WebView, &WebView)>,
    _chrome_height: i32,
    // Where the page starts: the CLOSED strip. An open panel's height rides
    // `chrome_height` and the lift below, never this value.
    chrome_strip: i32,
    chrome_left: i32,
    chrome_right: i32,
    arrangement: ChromeLayout,
) {
    let (win_w, win_h) = logical_window_size(hosts);

    // The chrome ALWAYS takes the whole window. The page sits on top of it,
    // inset by the rectangle page_rect carves, the same inverted arrangement
    // unix describes in create_hosts, arrived at manually because Cocoa gives
    // no packing to borrow.
    set_bounds_logical(chrome, 0.0, 0.0, win_w, win_h);

    if let Some(page) = active {
        let (x, y, w, h) = super::page_rect(
            win_w,
            win_h,
            chrome_strip,
            chrome_left,
            chrome_right,
            0,
            super::PAGE_FRAME_PX,
        );
        set_bounds_logical(page, x, y, w, h);

        // Side by Side: the right-hand page shares the active page's
        // rectangle, moved right by its width plus the shared gap. The left
        // pane IS the active page above, `pair` is ordered left-right and
        // the active tab is always one of the two panes (state.rs ends the
        // pair before showing any other tab), so two rectangles cover both
        // pages and the frame's right edge stays where the single-tab
        // layout put it.
        if let Some((_, right_page)) = pair {
            set_bounds_logical(
                right_page,
                x + w + f64::from(super::SIDE_BY_SIDE_GAP_PX),
                y,
                (w - f64::from(super::SIDE_BY_SIDE_GAP_PX)).max(0.0),
                h,
            );
        }

        // The z-order IS the arrangement, and only content-on-top-of-chrome
        // or chrome-on-top-of-content exist. Reordered only on change: the
        // addSubview call is a remove+reinsert, and doing it every relayout
        // would churn WebKit compositing on every resize.
        let lift = matches!(arrangement, ChromeLayout::Overlay);
        if hosts.lifted.get() != lift {
            hosts.lifted.set(lift);
            // Main-thread view reorder; both views share the window's
            // content view as parent. Deferred off this context, see
            // reorder_views for why that is not a nicety. The two into_super
            // hops are wry's view class up to WKWebView up to NSView.
            reorder_views(
                page.webview().into_super().into_super(),
                chrome.webview().into_super().into_super(),
                lift,
            );
        }
    }
}

/// objc2 handles are !Send on purpose, these views are main-thread-only,
/// but DispatchQueue::exec_async requires a `Send` block. Sound anyway: the
/// block is only ever enqueued on the MAIN queue, back where the handles are
/// legal, and a `MainThreadOnly` type cannot be touched from anywhere else to
/// begin with.
struct MainQueueSend<T: MainThreadOnly>(Retained<T>);
impl<T: MainThreadOnly> MainQueueSend<T> {
    // A method, not a field access: the closure's precise capture would
    // otherwise grab the raw `Retained` out of `.0` and defeat the Send impl.
    fn into_inner(self) -> Retained<T> {
        self.0
    }
}
// SAFETY: see the type comment; the value never leaves the main queue.
unsafe impl<T: MainThreadOnly> Send for MainQueueSend<T> {}

/// Reorder the chrome and the page inside the window's content view.
///
/// DEFERRED through the main dispatch queue, and not as a style choice: tao
/// delivers user events from an end-of-run-loop OBSERVER callback, and an
/// `addSubview` issued from inside that observer deadlocks in
/// `-[NSView _setSuperview:]`, the reorder waits on a Core Animation
/// transaction the observer-blocked run loop can never commit (observed live:
/// the whole app wedged solid the moment a modal flipped ChromeLayout to
/// Overlay, taking every later click with it). The same mutation serviced
/// from the run loop's main-queue drain, a normal run-loop turn, is the
/// ordinary, safe shape AppKit expects.
fn reorder_views(page: Retained<NSView>, chrome: Retained<NSView>, chrome_on_top: bool) {
    let (page, chrome) = (MainQueueSend(page), MainQueueSend(chrome));
    DispatchQueue::main().exec_async(move || {
        let (page, chrome) = (page.into_inner(), chrome.into_inner());
        // SAFETY: main-thread-only view access, inside the main-queue block.
        let content = unsafe { page.window() }
            .and_then(|w| unsafe { w.contentView() });
        let Some(content) = content else { return };
        // SIBLINGS, not nesting: re-add both to the content view, frontmost
        // LAST. addSubview:positioned:relativeTo: with a nil sibling appends
        // to the end of the list, which is the FRONT of the z-order. Nesting
        // one WKWebView inside the other (the first cut of this code did
        // exactly that) puts the chrome inside the page's WebContent tree,
        // where click routing through WebKit's own view hierarchy eats the
        // panel clicks the toolbar still receives.
        if chrome_on_top {
            content.addSubview_positioned_relativeTo(&page, NSWindowOrderingMode::Above, None);
            content.addSubview_positioned_relativeTo(&chrome, NSWindowOrderingMode::Above, None);
        } else {
            content.addSubview_positioned_relativeTo(&chrome, NSWindowOrderingMode::Above, None);
            content.addSubview_positioned_relativeTo(&page, NSWindowOrderingMode::Above, None);
        }
    });
}

/// Whether a docked pane can actually be laid out on this backend. False: a
/// control the platform cannot deliver is hidden or explained, never shown
/// and inert.
pub fn split_supported() -> bool {
    false
}

/// Whether a modal's backdrop is a LIVE dimmed page rather than an opaque
/// cover. True only if the chrome actually went transparent, see
/// `build_chrome`.
pub fn translucent_overlay_supported() -> bool {
    CHROME_TRANSPARENT.load(Ordering::Relaxed)
}

pub fn engine_info() -> crate::platform::EngineInfo {
    // The OS version is the honest version signal: WebKit ships with macOS
    // and exposes no runtime version getter through the pinned bindings.
    let os = NSProcessInfo::processInfo().operatingSystemVersion();
    let found = crate::platform::debug_version_override().unwrap_or_else(|| {
        vec![
            os.majorVersion as u32,
            os.minorVersion as u32,
            os.patchVersion as u32,
        ]
    });
    let compiled = &MIN_MACOS_WEBKIT;
    let floor = crate::platform::effective_floor("WKWebView", compiled);
    crate::platform::EngineInfo {
        name: "WKWebView",
        below_floor: crate::platform::below_floor(&found, &floor),
        below_compiled_floor: crate::platform::below_floor(&found, compiled),
        version: Some(found),
        floor,
        compiled_floor: compiled,
        advisory: MACOS_WEBKIT_ADVISORY,
        // The OS WebKit IS the loaded framework: no separately installed
        // runtime to be newer than it.
        installed: None,
        version_source: crate::platform::EngineVersionSource::Running,
        tracking_prevention: if itp_confirmed() {
            "ITP enabled"
        } else {
            "ITP unknown"
        },
    }
}

fn itp_confirmed() -> bool {
    ITP_CONFIRMED.load(Ordering::Relaxed)
}

/// macOS has no GTK-style timeout, so the event loop's tick IS the
/// auto-freeze driver, the Windows model. `should_auto_freeze` is fed by
/// `on_load_finished`, which the content builder's page-load handler runs on
/// every finished navigation (success or failure; a failed load must not
/// leave the tab permanently unfreezable). Returns whether the controller
/// decided to freeze NOW, plus the deadline for the UI's countdown if one is
/// pending.
pub fn tick_auto_freeze(view: &TabView, now: Instant) -> (bool, Option<Instant>) {
    let mut st = view.state.borrow_mut();
    if st.freeze.should_auto_freeze(now) {
        st.freeze.freeze_auto_now();
        return (true, None);
    }
    (false, st.freeze.auto_freeze_deadline())
}

/// Strip the source address from a finished download's Mark-of-the-Web.
/// A no-op here: quarantine attributes (`com.apple.quarantine`) are written
/// by LaunchServices for apps that opt in, and WKWebView downloads via this
/// process do not carry provenance xattrs to scrub. Present so `platform`
/// exposes one shape on both targets. See `platform::motw`.
pub fn scrub_download_mark(_path: &std::path::Path) -> super::motw::Outcome {
    super::motw::Outcome::NotApplicable
}

// ,
// 1.0.6 API surface, ported from unix.rs / windows.rs. Everything below adds
// to the existing macOS backend without touching what already shipped.

/// Whether a modal's backdrop must draw OPAQUE. WebKit on macOS composites
/// normally here (the WKWebView backing is the OS compositor's own), so the
/// answer is always NO: the translucency the chrome falls back to solid
/// backdrop for is a WebKitGTK compositing quirk, not a macOS one. The
/// `Option<&str>` helper mirrors unix's `compositing_disabled_by`, whose
/// decision logic is unit-tested on the Linux build.
pub fn compositing_disabled() -> bool {
    compositing_disabled_by(None)
}

pub(crate) fn compositing_disabled_by(value: Option<&str>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "0")
}

/// The AUTO freeze yields before a browser-issued navigation: lift it now,
/// reinstall the tab's normal filters, and re-arm the freeze timer in case
/// this navigation never becomes a load. Same semantics as unix's, but
/// WITHOUT the GTK-only pieces: no `freeze_json` bookkeeping (state stays in
/// TabState; `unfreeze` here never had that arm) and no re-arm timer (the
/// tick driver re-freezes on the next deadline miss; the old page has no
/// runloop timer of its own to schedule). A manual freeze is left alone.
pub fn yield_auto_freeze(webview: &WebView, view: &TabView) {
    if !view.state.borrow().freeze.is_auto_frozen() {
        return;
    }
    let block_ads = {
        let mut st = view.state.borrow_mut();
        st.freeze.unfreeze(Instant::now());
        st.policy.block_ads
    };
    let Some(cc) = content_controller(webview) else { return };
    remove_all_filters(&cc);
    if block_ads {
        install_bundled_filters(&cc);
    }
}

/// The hosts the tab's freeze lets through, for the panel's "Allowed" rows.
pub fn freeze_allowed_hosts(view: &TabView) -> Vec<String> {
    view.state.borrow().freeze.overrides()
}

/// Side by Side: two tabs' pages next to each other, or back to one tab at
/// a time. There is no packing on this backend, `layout` positions both
/// pages by hand, so this only manages VISIBILITY, never focus (the
/// keyboard stays where it is; see AppState::show_and_focus_tab). Both
/// panes are made visible here; hiding the pane being left is state.rs's
/// job, as on every backend.
pub fn set_side_by_side(
    _hosts: &Hosts,
    pair: Option<((&TabView, &WebView), (&TabView, &WebView))>,
) {
    match pair {
        Some(((_, left), (_, right))) => {
            let _ = left.set_visible(true);
            let _ = right.set_visible(true);
        }
        None => {}
    }
}

/// Page fullscreen: a page's own element taking the whole screen (a video's
/// fullscreen button). NOT PORTED: WKWebView reports element fullscreen
/// through `WKUIDelegate` responses wry 0.55 does not relay, so no engine
/// event on this backend can ever raise `UserEvent::PageFullscreen`. What
/// remains reachable is the BROWSER side (`exit_page_fullscreen`, a
/// shortcut, a modal, a tab switch), and these stubs make it safe: the
/// window was never fullscreen, `set_page_fullscreen(false)` is the
/// idempotent give-back, and the notice is a no-op like the hover readout
/// it borrows its shape from. Feature off, honestly, the same choice the
/// hover readout made; see the stub philosophy above.
pub fn connect_fullscreen(
    _hosts: &Hosts,
    _webview: &WebView,
    _proxy: &EventLoopProxy<UserEvent>,
    _id: u64,
) {
}

/// Publishes which tabs may go fullscreen. Nothing on this backend can ask
/// (see the page-fullscreen note); kept so state.rs has one call shape.
pub fn set_fullscreen_eligible(_hosts: &Hosts, _tabs: &[u64]) {}

/// The window side of page fullscreen. The browser never ENTERS a page
/// fullscreen on this backend (nothing can raise the event), but the exit
/// path is shared (`exit_page_fullscreen` fires `on=false` after a tab
/// switch away from a pane), so both directions record state and the
/// window call is unconditional, it is the idempotent give-back.
pub fn set_page_fullscreen(hosts: &Hosts, on: bool) {
    hosts.fullscreen.set(on);
    hosts
        ._window
        .set_fullscreen(on.then_some(tao::window::Fullscreen::Borderless(None)));
}

/// Nothing to place: geometry keeps coming from `layout`, which state.rs
/// calls on every relayout, including the fullscreen ones, before this
/// runs (its early return is AFTER `layout_fullscreen` in relayout).
/// Fullscreen never engages on this backend anyway (see the note above).
pub fn layout_fullscreen(_hosts: &Hosts, _chrome: &WebView, _page: &WebView) {}

/// The fullscreen notice, top centre. Reuses the hover readout's slot the
/// way unix does, but the readout is not ported on macOS (its host view
/// would be another native layer between chrome and page), so this is an
/// honest no-op, the browser-side fullscreen that could show it never
/// engages on this backend either.
pub fn set_fullscreen_notice(_hosts: &Hosts, _text: Option<&str>) {}
