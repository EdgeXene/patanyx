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
//! per-webview `WKUserContentController` wry already created — a blocked
//! request never leaves the machine. Cosmetic filtering is a style-injecting
//! user script (the sanctioned mechanism; content webviews are never
//! script-evaluated by this process). Same invariants as unix.rs, WebKit
//! edition.

use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;
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
use objc2_foundation::{NSArray, NSDate, NSDictionary, NSProcessInfo, NSString, NSURL};
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
/// `drawsBackground` KVC, macOS 10.14+ — the same key vendored wry uses at
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
/// installed runtime on macOS — it ships with the OS — so the honest version
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
    /// The tab id state.rs assigned, carried for the wake events the
    /// allowance-ending paths send (`AdsAllowanceEnded` needs it; `TabView`
    /// is otherwise opaque).
    id: u64,
    state: Rc<RefCell<TabState>>,
    /// Whether the YouTube ad script is in the controller, kept in step by
    /// every rebuild. WKUserScript has no removal-by-id and the whole set is
    /// rebuilt on change, so the slot exists to ANSWER `youtube_ads_install`
    /// with evidence, the way unix's script slot does -- not to enable
    /// removal.
    youtube_script: RefCell<bool>,
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

// ---- hover readout ----
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
    // shape that works — the same key sent to the built view raises
    // NSUnknownKeyException (and an ObjC exception aborts the process).
    let builder = builder.with_transparent(true);
    let webview = builder.build_as_child(&hosts._window)?;
    CHROME_TRANSPARENT.store(true, Ordering::Relaxed);

    // No context menu or shortcut wiring on the chrome webview yet — unix's
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
/// top-left-based frame Cocoa wants — so pass a top-left origin here).
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
    // Kept-profile tabs do not exist on this backend yet (see
    // `new_webview_builder_for`); recorded on the tab's state so the panel
    // and `finish_session_wipe` see Main everywhere.
    profile: crate::kept_profile::ProfileKind,
    // Windows only: a page's new tab is never held on this backend (the
    // adoption stubs below); a page's new tab loads its address.
    _adopting: bool,
) -> Result<(WebView, TabView, bool), wry::Error> {
    // The wake every filter completion sends its settled events through, set
    // before anything can compile, so a caller that builds a tab outside the
    // app shell (the translate probe) has its own loop reached too.
    OVERLAP_WAKE.with(|w| *w.borrow_mut() = Some(proxy.clone()));
    // Blank build, navigate after every script and filter is registered —
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
    // Main everywhere on this backend (`new_webview_builder_for`), recorded
    // so the panel and the profile-scoped releases read one answer.
    state.borrow_mut().profile = profile;

    // Load events: state.rs already put an `on_page_load` handler on this
    // builder (UrlChanged/LoadState to the event loop). wry allows ONE such
    // handler, and the platform needs the same events to drive TabState —
    // on_load_started keys the local-network boundary, on_load_finished starts
    // the freeze grace clock, and without it a quarantine tab never
    // auto-freezes (windows.rs hit the identical trap; see its
    // NavigationCompleted note). So this REPLACES the caller's handler with
    // the same event sends PLUS the TabState calls. Keep in sync with
    // state.rs's closure. MUST happen before build — the builder is consumed.
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

    let view = TabView {
        id,
        state,
        youtube_script: RefCell::new(false),
    };
    apply_policy(&webview, &view, policy);
    // GPC's navigator property, document-start, all frames — main world, so
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
    // completion. Ephemeral tabs use an ephemeral store — nothing to clear.
    ITP_CONFIRMED.store(true, Ordering::Relaxed);
    // The first page waits for the start-up clear AND for this tab's bundled
    // rule lists to land: the lists compile asynchronously, and a page issued
    // meanwhile sent its requests with no filters in place (unix's gate).
    let waiting_for_wipe = if policy.ephemeral {
        false
    } else {
        begin_new_session_wipe(proxy)
    };
    let initial_navigation_pending = waiting_for_wipe || !initial_navigation_ready(&view);
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

// ---------------------------------------------------------------------------
// User scripts and content filters
//
// One `WKUserContentController` per webview (wry's `manager()`). All script
// installs go through `install_content_scripts`, which clears and re-adds the
// full set — WebKit has no per-script removal without keeping instances, and
// the set is small enough that rebuild is cheaper than bookkeeping.

const GPC_INJECTION: objc2_web_kit::WKUserScriptInjectionTime =
    objc2_web_kit::WKUserScriptInjectionTime::AtDocumentStart;
const STYLE_INJECTION: objc2_web_kit::WKUserScriptInjectionTime =
    objc2_web_kit::WKUserScriptInjectionTime::AtDocumentEnd;

/// Wraps author CSS in a style-injecting IIFE. This is the macOS shape of
/// unix's user STYLESHEET: WKUserScript is the only per-view style channel,
/// and the CSS crosses as DATA (json-escaped) — nothing page-controlled ever
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
/// when ephemeral, the YouTube ad script when the policy wants it, cosmetic
/// hiding when ad blocking is on, scrollbar colour. Called on every change;
/// `removeAllUserScripts` makes re-registration a rebuild rather than a diff.
/// The single rebuild path, so the youtube_script slot and the controller
/// cannot drift apart.
fn install_content_scripts(webview: &WebView, view: &TabView) {
    rebuild_user_scripts(webview, view);
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
    // The scrollbar sheet joins the same rebuild as everything else, so the
    // set stays exactly one GPC + divergence + YouTube + cosmetic + scrollbar.
    rebuild_user_scripts(webview, view);
    let Some(cc) = content_controller(webview) else { return };
    // SAFETY: main-thread controller mutation.
    unsafe { cc.addUserScript(scrollbar) };
}

// -- compiled content filters (WKContentRuleList) --

/// The shipped filters. TWO, not one merged set, for the same reason unix
/// states: WebKit refuses a compiled list over 150,000 rules and the merged
/// set brushes it. Each is well under.
#[derive(Clone, Copy)]
enum BundledFilter {
    Ads,
    Tracking,
}

impl BundledFilter {
    fn json(&self) -> String {
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

// The compiled rule lists this run made, by the id each compiles under.
// Keeping the objects in memory is what makes a rebuild synchronous: the
// controller gets the SAME object back with `addContentRuleList`, with no
// store round-trip in between. Between `removeAllContentRuleLists` and an
// async re-add, a tab would briefly block nothing at all, and the reload a
// switch issues could outrun its own lists.
thread_local! {
    static COMPILED_RULE_LISTS:
        RefCell<std::collections::HashMap<String, Retained<WKContentRuleList>>> =
        RefCell::new(std::collections::HashMap::new());
}

/// Remembers a compiled list under its id. A list is content-addressed
/// (`filter_id_for`), so remembering a compile the tab then declined costs
/// nothing: a later rebuild that wants it adds it from here.
fn remember_rule_list(id: &str, list: &Retained<WKContentRuleList>) {
    COMPILED_RULE_LISTS.with(|c| {
        c.borrow_mut().insert(id.to_string(), list.clone());
    });
}

/// The run's in-memory copy of the list `id`, when there is one.
fn cached_rule_list(id: &str) -> Option<Retained<WKContentRuleList>> {
    COMPILED_RULE_LISTS.with(|c| c.borrow().get(id).cloned())
}

fn forget_rule_list(id: &str) {
    COMPILED_RULE_LISTS.with(|c| {
        c.borrow_mut().remove(id);
    });
}

/// Sends a settled event through the event loop. `OVERLAP_WAKE` is set at
/// the first build (`build_content`), before anything can compile.
fn wake(event: UserEvent) {
    OVERLAP_WAKE.with(|w| {
        if let Some(proxy) = w.borrow().as_ref() {
            let _ = proxy.send_event(event);
        }
    });
}

/// One bundled compile started for a tab has ended, however it ended. The
/// tab's count goes down, and at zero the tab's held first page is looked at
/// again (`BundledFiltersSettled`). A drop guard, so no return path in the
/// completion can forget the count.
struct BundledLoadEnds {
    state: Option<Rc<RefCell<TabState>>>,
}

impl Drop for BundledLoadEnds {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        let settled = {
            let mut st = state.borrow_mut();
            st.bundled_filters_loading = st.bundled_filters_loading.saturating_sub(1);
            st.bundled_filters_loading == 0
        };
        if settled {
            wake(UserEvent::BundledFiltersSettled);
        }
    }
}

/// Installs both shipped filters. A list this run already compiled goes
/// straight back on the controller from memory, synchronously; only a run's
/// first use compiles, and that compile is counted on the tab
/// (`bundled_filters_loading`) so its first page waits for the lists.
fn install_bundled_filters(
    cc: &Retained<objc2_web_kit::WKUserContentController>,
    view: &TabView,
) {
    for json in [BundledFilter::Ads.json(), BundledFilter::Tracking.json()] {
        let id = privacy::filter_id_for(&json);
        if let Some(list) = cached_rule_list(&id) {
            // SAFETY: main-thread controller mutation of a list we hold.
            unsafe { cc.addContentRuleList(&list) };
            continue;
        }
        compile_bundled_list(cc, &json, &id, view);
    }
}

/// The one compile a bundled list needs per run. Counted up before it
/// starts, counted down when the completion ends, on success and failure
/// alike. On success the list is remembered, and added only if the tab still
/// wants it: a compile that finishes after the tab's blocking changed adds
/// nothing, so a late compile cannot come back over a switched-off policy.
fn compile_bundled_list(
    cc: &Retained<objc2_web_kit::WKUserContentController>,
    json: &str,
    id: &str,
    view: &TabView,
) {
    let Some(store) = rule_list_store() else {
        diag("content rule list store unavailable");
        return;
    };
    view.state.borrow_mut().bundled_filters_loading += 1;
    let state = view.state.clone();
    // The guard is dropped INSIDE the block (a block is `Fn`, it may run
    // more than once only in principle, but it must stay callable): the
    // RefCell lets the one drop happen through a shared reference.
    let guard = std::cell::RefCell::new(Some(BundledLoadEnds {
        state: Some(view.state.clone()),
    }));
    let id_ns = NSString::from_str(id);
    let source = NSString::from_str(json);
    let id = id.to_string();
    let cc = cc.clone();
    // SAFETY: the block is retained by the callee for the async lifetime;
    // the captured Retained, Rc and guard values live with it. WebKit raises
    // this callback on the main thread the webview was built on. Block
    // parameters are __unsafe_unretained object pointers: retained before
    // use.
    unsafe {
        store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler(
            Some(&id_ns),
            Some(&source),
            Some(&block2::RcBlock::new(
                move |list: *mut WKContentRuleList, error: *mut objc2_foundation::NSError| {
                    if !list.is_null() {
                        let list = Retained::retain(list).expect("rule list pointer");
                        remember_rule_list(&id, &list);
                        let lands = state.borrow().wants_ad_filters();
                        if lands {
                            cc.addContentRuleList(&list);
                        }
                    } else {
                        let why = (!error.is_null())
                            .then(|| Retained::retain(error).expect("error pointer"))
                            .map(|e| e.localizedDescription().to_string())
                            .unwrap_or_else(|| "unknown error".to_string());
                        diag(&format!("ad/tracker filter not installed: {why}"));
                    }
                    // Ends the count; at zero the tab's first page may go.
                    if let Some(guard) = guard.borrow_mut().take() {
                        drop(guard);
                    }
                },
            )),
        );
    }
}

/// Removes every compiled rule list. Filters are managed as a set, so this
/// drops ad filters AND any freeze filter — callers re-install what should
/// survive, which is what makes the "ORs its filters" hazard unix documents
/// structurally impossible here.
fn remove_all_filters(cc: &objc2_web_kit::WKUserContentController) {
    // SAFETY: main-thread controller mutation.
    unsafe { cc.removeAllContentRuleLists() };
}

/// Puts the tab's INSTALLED freeze filter back on its controller from the
/// run's memory cache: for paths that removed every filter while the freeze
/// itself did not change. No request is made of any store, no generation is
/// quoted, and the Book still holds the filter as installed; the engine
/// simply gets the same object back. A frozen tab therefore has no moment
/// with no freeze, even across a rebuild.
fn reinstall_installed_freeze_filter(
    cc: &Retained<objc2_web_kit::WKUserContentController>,
    view: &TabView,
) {
    for id in view.state.borrow().freeze_filters.installed_list_ids() {
        if let Some(list) = cached_rule_list(&id) {
            // SAFETY: main-thread controller mutation of a list we hold.
            unsafe { cc.addContentRuleList(&list) };
        }
    }
}

/// Where a freeze filter compiles: a per-run directory (0700) under the
/// user's temp folder. A freeze filter's rules name every host the user
/// allowed on the frozen tab, so its compiled copy must not land in the
/// persistent store, where nothing would ever remove it and the hosts would
/// outlive the session (the Strict Tabs promise to keep nothing). Without a
/// usable directory the default store is used and the removal still applies,
/// and `remove_stale_freeze_stores` clears anything a crash left behind.
fn freeze_rule_list_store() -> Option<Retained<WKContentRuleListStore>> {
    let dir = freeze_store_dir()?;
    let path = NSString::from_str(dir.to_str()?);
    let url = NSURL::fileURLWithPath_isDirectory(&path, true);
    // SAFETY: main-thread store construction on a directory this process
    // just made, 0700.
    let store = unsafe { WKContentRuleListStore::storeWithURL(Some(&url), main_thread_marker()) };
    match store {
        Some(store) => Some(store),
        None => rule_list_store(),
    }
}

/// The per-run freeze store directory: `patanyx-<pid>-freeze` under the
/// user's temp folder, 0700, also re-tightened when a directory of the same
/// name was left by an ended run whose pid this run reused.
fn freeze_store_dir() -> Option<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("patanyx-{}-freeze", std::process::id()));
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        // This run already made it; a second store request reuses it.
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    Some(dir)
}

/// Once per run, before any freeze: a freeze filter means nothing to the
/// next run, so the per-run store of a run that has ended is deleted. A
/// directory goes only when its pid is not ours and the kernel says the
/// process is gone (`process_is_gone`), and only when the entry is a real
/// directory (`symlink_metadata` does not follow links). The default store
/// is then swept of every list this run does not itself compile: earlier
/// builds saved a freeze filter's stored copy there and never removed it.
fn remove_stale_freeze_stores() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let me = std::process::id();
        for entry in entries.flatten() {
            let Some(pid) = freeze_dir_pid(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            if pid == me || !process_is_gone(pid) {
                continue;
            }
            if !std::fs::symlink_metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            let _ = std::fs::remove_dir_all(entry.path());
        }
        sweep_default_store_of_foreign_lists();
    });
}

/// The per-run store directory name, `patanyx-<pid>-freeze`, parsed.
fn freeze_dir_pid(name: &str) -> Option<u32> {
    name.strip_prefix("patanyx-")?
        .strip_suffix("-freeze")?
        .parse::<u32>()
        .ok()
}

/// `kill(pid, 0)` sends nothing; the kernel answers whether a process the
/// caller may signal exists, and ESRCH means none does. A process that
/// exists but may not be signalled (EPERM) counts as alive: deleting the
/// store of a run we cannot inspect would be the bolder answer, not the
/// safer one.
fn process_is_gone(pid: u32) -> bool {
    // SAFETY: signal 0 performs only the existence and permission checks.
    let answered = unsafe { libc::kill(pid as libc::pid_t, 0) };
    answered == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Removes every stored list in the default store whose id this run does not
/// itself compile. Earlier builds kept a freeze filter's stored copy there
/// forever; the ids of a list naming allowed hosts cannot be picked out by
/// name, so the sweep keeps only the bundled lists, whose ids are computed
/// from the same JSON this run installs (an in-flight compile of theirs is
/// therefore never swept by mistake). A stale overlap entry is only a cache:
/// its content moves with the shipped lists, and it is recompiled when next
/// wanted.
fn sweep_default_store_of_foreign_lists() {
    let Some(store) = rule_list_store() else {
        return;
    };
    let keep = [
        privacy::filter_id_for(&BundledFilter::Ads.json()),
        privacy::filter_id_for(&BundledFilter::Tracking.json()),
    ];
    // The block holds its own ref on the store: the removals run after this
    // frame is gone.
    let store_for_block = store.clone();
    // SAFETY: main-thread store read; the block is retained by WebKit.
    unsafe {
        store.getAvailableContentRuleListIdentifiers(Some(&block2::RcBlock::new(
            move |ids: *mut NSArray<NSString>| {
                let store = &store_for_block;
                // Already inside this call's unsafe block.
                let Some(ids) = ids.as_ref() else {
                    return;
                };
                for i in 0..ids.count() {
                    let id = ids.objectAtIndex(i).to_string();
                    if !keep.contains(&id) {
                        remove_stored_rule_list(&store, &id);
                    }
                }
            },
        )));
    }
}

/// Removes the stored copy of `id` from `store`. A list works from the
/// controller's memory once installed, so the copy is only WebKit's compile
/// cache; for a freeze filter it is a cache of the hosts the user allowed,
/// which nothing else would ever remove.
fn remove_stored_rule_list(store: &Retained<WKContentRuleListStore>, id: &str) {
    let id_ns = NSString::from_str(id);
    // SAFETY: main-thread store mutation; the block is retained by WebKit.
    unsafe {
        store.removeContentRuleListForIdentifier_completionHandler(
            Some(&id_ns),
            Some(&block2::RcBlock::new(|_error: *mut objc2_foundation::NSError| {})),
        );
    }
}

/// Installs the freeze filter for the tab's OWN webview: everything except
/// the session's allow-override hosts. A PREVIOUS freeze filter (fewer
/// exceptions, when one host is being allowed) stays in place until this one
/// is installed: removing it first left a frozen tab with no freeze while
/// the replacement compiled. `FreezeFilterBook` swaps them in the completion
/// and quotes a generation back, so a late compile of a superseded request
/// installs nothing.
fn install_freeze_filter(webview: &WebView, view: &TabView) {
    // Once per run, before the first freeze, so nothing a crashed run left
    // behind outlives it.
    remove_stale_freeze_stores();
    let Some(cc) = content_controller(webview) else {
        return;
    };
    let exceptions = view.state.borrow().freeze.overrides();
    let json = privacy::freeze_filter_json(&exceptions);
    let id = privacy::filter_id_for(&json);
    let holds_hosts = !exceptions.is_empty();
    let generation = view
        .state
        .borrow_mut()
        .freeze_filters
        .request_with_hosts(id.clone(), exceptions);
    compile_freeze_list(&cc, &json, &id, view.state.clone(), generation, holds_hosts);
}

/// The freeze compile, into the per-run store. The completion quotes the
/// generation back through `FreezeFilterBook::on_compiled`: only the freeze
/// the tab still wants, while it is still frozen, lands. A compile that
/// finished after an unfreeze, or after a newer freeze was asked for,
/// installs nothing and reports nothing about the freeze the tab wants now;
/// a superseded list that named hosts still has its stored copy removed.
fn compile_freeze_list(
    cc: &Retained<objc2_web_kit::WKUserContentController>,
    json: &str,
    id: &str,
    state: Rc<RefCell<TabState>>,
    generation: u64,
    holds_hosts: bool,
) {
    let Some(store) = freeze_rule_list_store() else {
        state.borrow_mut().freeze.note_enforcement_failed();
        diag("content rule list store unavailable");
        return;
    };
    let id_ns = NSString::from_str(id);
    let source = NSString::from_str(json);
    let id = id.to_string();
    let cc = cc.clone();
    // The block holds its own ref on the store: the removal runs on it after
    // this frame is gone.
    let store_for_block = store.clone();
    // SAFETY: as compile_bundled_list.
    unsafe {
        store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler(
            Some(&id_ns),
            Some(&source),
            Some(&block2::RcBlock::new(
                move |list: *mut WKContentRuleList, error: *mut objc2_foundation::NSError| {
                    let store = &store_for_block;
                    if list.is_null() {
                        let why = (!error.is_null())
                            .then(|| Retained::retain(error).expect("error pointer"))
                            .map(|e| e.localizedDescription().to_string())
                            .unwrap_or_else(|| "unknown error".to_string());
                        // A failure for a superseded freeze request says
                        // nothing about the freeze the tab wants now.
                        let current = state
                            .borrow()
                            .freeze_filters
                            .failure_is_current(&id, generation);
                        if current {
                            state.borrow_mut().freeze.note_enforcement_failed();
                            diag(&format!("freeze filter not installed: {why}"));
                        }
                        return;
                    }
                    let list = Retained::retain(list).expect("rule list pointer");
                    let decision = {
                        let mut st = state.borrow_mut();
                        let frozen = st.freeze.phase() == FreezePhase::Frozen;
                        st.freeze_filters.on_compiled(&id, generation, frozen)
                    };
                    if let privacy::CompiledFreeze::Install { remove } = decision {
                        cc.addContentRuleList(&list);
                        remember_rule_list(&id, &list);
                        state.borrow_mut().freeze.note_enforced();
                        // Superseded freeze filters come off only now that
                        // the replacement enforces: until this moment the old
                        // filter was the freeze the tab had.
                        for old in remove {
                            if let Some(old_list) = cached_rule_list(&old) {
                                cc.removeContentRuleList(&old_list);
                            }
                            forget_rule_list(&old);
                        }
                    }
                    // The stored copy leaves on every path out of a handled
                    // freeze compile: the filter works from the controller's
                    // memory, and a copy on disk names the hosts that were
                    // allowed when it was asked for.
                    if holds_hosts {
                        remove_stored_rule_list(&store, &id);
                    }
                },
            )),
        );
    }
}

/// Whether freezing actually blocks requests on this platform.
pub fn freeze_enforced() -> bool {
    true
}

/// The smoke gate's hardware lever, macOS side: drops the STORED copies of
/// the bundled lists from the default store, after the controllers already
/// hold the compiled objects. If a stored copy were load-bearing, the smoke
/// run's blocking probe would see the page's requests escape. Unix does not
/// drop its store: there it is the backend's compile cache and the smoke has
/// no equivalent lever, which is fine, the question is about this backend's
/// persistent store.
pub fn drop_stored_rule_list_copies() {
    let Some(store) = rule_list_store() else {
        return;
    };
    for json in [BundledFilter::Ads.json(), BundledFilter::Tracking.json()] {
        remove_stored_rule_list(&store, &privacy::filter_id_for(&json));
    }
}

// ---------------------------------------------------------------------------
// Upstream API surface (state.rs is cfg-free; unix.rs is the semantic
// reference). WebKit enforces blocking inside the engine via content rule
// lists, so the navigation/wipe bookkeeping that coordinates a UI-process
// veto on Windows is structurally absent here -- the no-op/true shapes
// below match unix.rs for the same reasons.

/// No-op: the local-network boundary has no per-request veto to enforce it
/// with on WebKit (blocking happens in the engine, see the header comment).
pub fn note_app_navigation(_view: &TabView, _url: &str) {}

/// No-op, as `note_app_navigation`.
pub fn forget_app_navigation(_view: &TabView) {}

/// Whether this tab's first page may be issued: its bundled ad and tracker
/// filters are in (or their loads ended), and the start-up clear its profile
/// waits on is done. The clear used to be the only hold here and
/// `SessionWipeFinished` the only release; the bundled compiles hold their
/// own count now and release through `BundledFiltersSettled`, so both are
/// asked (unix's shape).
pub fn initial_navigation_ready(view: &TabView) -> bool {
    let st = view.state.borrow();
    st.bundled_filters_loading == 0
        && (st.policy.ephemeral
            || super::session_wipe_finished(crate::kept_profile::ProfileKind::Main))
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

/// A pending first page means the tab waits for the session wipe ONLY while
/// that clear is still running (and never for an ephemeral tab, which does
/// not take part in it): a tab held just for its bundled rule lists is safe
/// to destroy, and deferring its close would leave it in the tab list until
/// an event that has already fired.
pub fn holds_session_wipe(view: &TabView, first_page_pending: bool) -> bool {
    first_page_pending
        && !view.state.borrow().policy.ephemeral
        && !super::session_wipe_finished(crate::kept_profile::ProfileKind::Main)
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

/// Windows only (new_window.rs): WKWebView never holds a page's new-tab
/// request, so no ticket exists here and every function taking one is
/// unreachable. Same shape as unix's.
pub enum AdoptionTicket {}

/// No-op: nothing here needs the opener's environment at build.
pub fn on_opener_environment<'a>(
    builder: WebViewBuilder<'a>,
    _opener: &WebView,
) -> WebViewBuilder<'a> {
    builder
}

/// Always: a page's new tab is never held, so there is nothing to be not
/// ready for.
pub fn adoption_ready(_view: &TabView) -> bool {
    true
}

/// Always: every registration this backend makes is answered at build
/// (`apply_policy` records the engine's own answers; WKUserScript adds are
/// synchronous).
pub fn registrations_answered(_view: &TabView) -> bool {
    true
}

/// Always: the hand-over guard judges a Windows NavigationStarting veto,
/// which has no counterpart here.
pub fn handover_guarded(_view: &TabView) -> bool {
    true
}

/// Unreachable: the ticket type has no values.
pub fn release_adoption(_webview: &WebView, _view: &TabView, ticket: AdoptionTicket) -> bool {
    match ticket {}
}

/// Always: every filter on this backend is in place at build; nothing is
/// attached after a hand-over.
pub fn attach_deferred_interception(_webview: &WebView, _view: &TabView) -> bool {
    true
}

// ---------------------------------------------------------------------------
// Session wipe
//
// WebKit's default store persists cookies, caches and storage between runs.
// One explicit type-set clear per process, held behind its async completion:
// HSTS is deliberately NOT in the set, matching the unix mask's promise.

pub fn begin_new_session_wipe(proxy: &EventLoopProxy<UserEvent>) -> bool {
    match super::enter_session_wipe(crate::kept_profile::ProfileKind::Main) {
        super::SessionWipeEntry::Ready => return false,
        super::SessionWipeEntry::Waiting => return true,
        super::SessionWipeEntry::Start => {}
    }
    // Every public type WebKit knows, asked of the store itself rather than
    // hand-kept: a type WebKit adds later is then wiped by default instead
    // of surviving until someone notices. The engine's strict-transport
    // cache is deliberately not among the public types, so the mask keeps
    // the unix mask's promise on its own.
    let types = unsafe {
        objc2_web_kit::WKWebsiteDataStore::allWebsiteDataTypes(main_thread_marker())
    };
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
                super::finish_session_wipe(crate::kept_profile::ProfileKind::Main);
                let _ = proxy.send_event(UserEvent::SessionWipeFinished(
                    crate::kept_profile::ProfileKind::Main,
                ));
            }),
        );
    }
    true
}

// ---------------------------------------------------------------------------
// Translate — NOT ported. The GTK translator rides WebKitGTK's
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
/// type's contract — an exact expected request, constant-time compared — is
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

// ---------------------------------------------------------------------------
// Policy, freeze, filters

pub fn apply_policy(webview: &WebView, view: &TabView, policy: &TabPolicy) -> TabPolicy {
    let policy = {
        let mut st = view.state.borrow_mut();
        // TabState is the ONE place an allowance lives; rebasing on it keeps a
        // browser-wide switch from quietly re-blocking an allowed tab.
        let effective = st.apply_base_policy(policy);
        st.freeze.set_auto(effective.freeze_after_load);
        effective
    };
    // Record what the ENGINE did, not what was asked: the preference was set
    // at build time (see build_content); read it back and report that.
    let applied = {
        // SAFETY: main-thread read of this webview's own configuration.
        let config = unsafe { webview.webview().configuration() };
        // wry's javascript_disabled arm sets the MODERN preference
        // (defaultWebpagePreferences.allowsContentJavaScript, macOS 10.15+),
        // not the deprecated per-preferences javaScriptEnabled this read
        // used to consult. The engine's answer for "does this view run
        // script" lives in the same property wry wrote, so read it back
        // from there; the deprecated getter no longer moves.
        let page_prefs = unsafe { config.defaultWebpagePreferences() };
        let enabled = unsafe { page_prefs.allowsContentJavaScript() };
        enabled == policy.javascript
    };
    view.state.borrow_mut().script_setting = if applied {
        SettingState::Applied
    } else {
        SettingState::Failed
    };
    set_ad_blocking(webview, view, policy.block_ads);
    set_youtube_ads(webview, view, policy.block_youtube_ads);
    policy
}

fn set_ad_blocking(webview: &WebView, view: &TabView, enable: bool) {
    // Cosmetic hiding rides the user-script set; the network half rides the
    // rule lists. Both halves, or the claim is not true.
    install_content_scripts(webview, view);
    let Some(cc) = content_controller(webview) else { return };
    if enable {
        install_bundled_filters(&cc, view);
    } else {
        remove_all_filters(&cc);
        // Removing every filter also drops any freeze filter, so a frozen
        // tab whose ad blocking is switched off must get it back. The
        // installed list is in the run's memory cache, so the re-add is
        // synchronous: no new compile, no Book round-trip.
        if view.state.borrow().freeze.phase() == FreezePhase::Frozen {
            reinstall_installed_freeze_filter(&cc, view);
        }
    }
}

/// Adds or removes the YouTube ad script on this tab. WKUserScript cannot be
/// scoped by URL pattern the way WebKitGTK's UserScript can, so the script's
/// own host check is the scoping (privacy.rs's tests pin the gate). The whole
/// user-script set is rebuilt, so the switch's effect lands on the NEXT
/// YouTube page load in this tab, which the panel's note says.
fn set_youtube_ads(webview: &WebView, view: &TabView, on: bool) {
    *view.youtube_script.borrow_mut() = on;
    rebuild_user_scripts(webview, view);
}

/// Rebuilds the tab's whole user-script set: GPC, divergence, the YouTube ad
/// script when the policy wants it, the cosmetic sheet while blocking, and
/// the scrollbar sheet through `set_page_scrollbar`'s own path. One rebuild
/// function so the youtube_script slot and the controller stay in step.
fn rebuild_user_scripts(webview: &WebView, view: &TabView) {
    let Some(cc) = content_controller(webview) else { return };
    let mtm = main_thread_marker();
    let (ephemeral, block_ads, block_youtube) = {
        let st = view.state.borrow();
        (
            st.policy.ephemeral,
            st.policy.block_ads,
            st.policy.block_youtube_ads,
        )
    };
    // SAFETY: main-thread controller mutation.
    unsafe {
        cc.removeAllUserScripts();
        cc.addUserScript(&user_script(mtm, privacy::GPC_SCRIPT, GPC_INJECTION));
        if let Some(source) = privacy::divergence_script(ephemeral) {
            cc.addUserScript(&user_script(mtm, &source, GPC_INJECTION));
        }
        if block_youtube {
            cc.addUserScript(&user_script(
                mtm,
                privacy::YOUTUBE_ADS_SCRIPT,
                GPC_INJECTION,
            ));
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
    // The slot mirrors what was handed to the controller this rebuild, which
    // is the evidence `youtube_ads_install` reports.
    *view.youtube_script.borrow_mut() = block_youtube;
}

/// WebKit's ITP is enabled or absent; it has no Strict/Balanced level. The
/// honest answer is NotAttempted — nothing was or could be configured.
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
/// the policy still wants it — filters are removed as a set, so the ad filter
/// necessarily went with the freeze filter.
pub fn unfreeze(webview: &WebView, view: &TabView) {
    let block_ads = {
        let mut st = view.state.borrow_mut();
        st.freeze.unfreeze(Instant::now());
        st.freeze_json = None;
        // The freeze ends in the Book too: an in-flight compile of a freeze
        // this tab no longer wants is discarded by its completion, and that
        // completion still removes the stored copy of a list naming hosts.
        // The in-memory copies go with it; a later re-freeze re-remembers
        // them when they land.
        for id in st.freeze_filters.lift() {
            forget_rule_list(&id);
        }
        st.policy.block_ads
    };
    let Some(cc) = content_controller(webview) else { return };
    remove_all_filters(&cc);
    if block_ads {
        install_bundled_filters(&cc, view);
    }
}

/// Set or clear this tab's ad-list override. Same call in both directions so
/// the revocation cannot be the path nobody wrote. State-only on macOS: there
/// is no per-host exception in the rule-list model (same as WebKitGTK).
pub fn set_adlist_override(view: &TabView, host: Option<String>) {
    view.state.borrow_mut().set_adlist_override(host);
}

// ---------------------------------------------------------------------------
// "Allow ads and trackers on this tab" (1.0.7)
//
// WKWebView decides inside the engine via compiled rule lists, the same
// mechanism unix uses, so the shape here is unix's: the ALLOWANCE is pure
// `TabState` (grant/end/unless-same-site), and the engine side is a rebuild
// of this tab's rule lists from what the state now wants. The malicious
// overlap rides along, process-wide like unix's, so an allowed tab keeps a
// malicious-host backstop and `ads_allow_ready` can refuse the switch until
// that backstop exists.
//
// `allow_ads_on_tab` rebuilds synchronously BEFORE returning, so the reload
// `set_tab_ads_allowed` issues next can never go out without its lists. The
// rebuild is truly synchronous now that the run keeps its compiled lists in
// memory: removal and re-add are both plain controller calls, with no store
// round-trip in between (review finding: only the removal used to be).

thread_local! {
    /// The proxy the overlap filter's settled event goes out through. Set at
    /// the first tab build, like unix's FREEZE_STATUS_WAKE.
    static OVERLAP_WAKE: RefCell<Option<EventLoopProxy<UserEvent>>> = const { RefCell::new(None) };
    /// The malicious-overlap rule list in memory, keyed by the id it compiles
    /// under. Mirrors unix's `OverlapFilter`.
    static OVERLAP: RefCell<OverlapFilter> = RefCell::new(OverlapFilter::NotBuilt);
    /// Guards the async compile: a stale completion (the lists refreshed
    /// again meanwhile) must never install. Same shape as unix's
    /// AD_OVERLAP_GENERATION.
    static OVERLAP_GENERATION: RefCell<crate::adlist_consent::FilterGeneration> =
        RefCell::new(crate::adlist_consent::FilterGeneration::new());
}

/// The in-memory malicious-overlap filter, mirroring unix's `OverlapFilter`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OverlapFilter {
    NotBuilt,
    /// The rule list WebKit accepted, by id. `None` = computed empty: there
    /// is genuinely no overlap, and an allowed tab is fully covered.
    Ready(Option<String>),
    /// Handed to the store; the completion has not answered yet.
    Compiling(String),
    /// The compile failed or was never possible. Fail closed: the switch
    /// stays unavailable and no allowance may rely on this.
    Failed,
}

fn wake_overlap(event: UserEvent) {
    OVERLAP_WAKE.with(|w| {
        if let Some(proxy) = w.borrow().as_ref() {
            let _ = proxy.send_event(event);
        }
    });
}

/// Whether the switch may be offered: the bundled lists the switch has to put
/// back are always in memory on this backend (compile-first, cached by
/// identifier), so the only wait is the overlap filter that keeps an allowed
/// tab covered for hosts on BOTH lists.
pub fn ads_allow_ready() -> bool {
    let overlap_ready = OVERLAP.with(|o| matches!(&*o.borrow(), OverlapFilter::Ready(_)));
    overlap_ready
}

/// The overlap filter is this backend's: WKWebView has no per-request
/// malicious-host veto outside the blocklist's navigation handler, so an
/// allowed tab needs the small compiled filter (unix's reasoning, and the
/// reason `ad_overlap_wanted` is true on unix and false on Windows).
pub fn ad_overlap_wanted() -> bool {
    true
}

/// The overlap could not be computed (its worker did not start). Fail
/// closed: nothing compiling may land, and the switch stays unavailable.
pub fn on_ad_overlap_failed() {
    OVERLAP_GENERATION.with(|g| g.borrow_mut().invalidate());
    OVERLAP.with(|o| *o.borrow_mut() = OverlapFilter::Failed);
    diag("overlap filter not computed: the worker did not start");
}

/// The hosts on both lists, from the worker (`blocklist::ad_overlap`).
/// Compiles them into a WKContentRuleList unless the one in force (or
/// compiling) already carries exactly these. Returns true when a filter that
/// allowed tabs may rely on is being replaced, so the caller ends their
/// allowances rather than leave them running on the old one.
pub fn on_ad_overlap_computed(hosts: Vec<String>, proxy: &EventLoopProxy<UserEvent>) -> bool {
    let next = privacy::overlap_filter(&hosts);
    let next_id = next.as_ref().map(|(_, id)| id.clone());
    let (unchanged, had_one) = OVERLAP.with(|overlap| match &*overlap.borrow() {
        OverlapFilter::Ready(ready) => (ready.as_ref() == next_id.as_ref(), true),
        OverlapFilter::Compiling(id) => (Some(id) == next_id.as_ref(), true),
        OverlapFilter::NotBuilt | OverlapFilter::Failed => (false, false),
    });
    if unchanged {
        return false;
    }
    // Register the proxy first: the very first computation may come back
    // before any tab build ran (main.rs asks at boot, before the first tab).
    OVERLAP_WAKE.with(|w| *w.borrow_mut() = Some(proxy.clone()));
    match next {
        None => {
            OVERLAP_GENERATION.with(|g| g.borrow_mut().invalidate());
            OVERLAP.with(|o| *o.borrow_mut() = OverlapFilter::Ready(None));
            wake_overlap(UserEvent::AdOverlapSettled);
        }
        Some((json, id)) => {
            let token = OVERLAP_GENERATION.with(|g| g.borrow_mut().begin());
            OVERLAP.with(|o| *o.borrow_mut() = OverlapFilter::Compiling(id.clone()));
            compile_overlap_filter(&json, &id, token, proxy);
        }
    }
    had_one
}

/// The overlap compile, WKWebView edition. The degrade path (store
/// unavailable, async failure diagnostics) matches the bundled compiles; the
/// generation guard rides in through the captured token so a stale
/// completion cannot mark the filter Ready, and the accepted list is kept
/// for the run so an allowed tab's rebuilds are synchronous.
fn compile_overlap_filter(json: &str, id: &str, token: u64, proxy: &EventLoopProxy<UserEvent>) {
    let Some(store) = rule_list_store() else {
        let current = OVERLAP_GENERATION.with(|g| g.borrow().may_apply(token));
        if current {
            OVERLAP.with(|o| *o.borrow_mut() = OverlapFilter::Failed);
            diag("overlap filter not compiled: no rule list store");
            wake_overlap(UserEvent::AdOverlapSettled);
        }
        return;
    };
    let id_string = privacy::filter_id_for(json);
    debug_assert_eq!(id_string, *id);
    let _ = id;
    let id_ns = NSString::from_str(&id_string);
    let source = NSString::from_str(json);
    let proxy = proxy.clone();
    // SAFETY: the block is retained by the callee for the async lifetime;
    // WebKit raises the callback on the main thread.
    unsafe {
        store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler(
            Some(&id_ns),
            Some(&source),
            Some(&block2::RcBlock::new(
                move |list: *mut WKContentRuleList, error: *mut objc2_foundation::NSError| {
                    let current = OVERLAP_GENERATION.with(|g| g.borrow().may_apply(token));
                    if !current {
                        // Superseded while compiling: OVERLAP already moved on.
                        return;
                    }
                    if !list.is_null() {
                        // Kept for the run: a rebuild re-adds this same
                        // object synchronously.
                        let list = Retained::retain(list).expect("rule list pointer");
                        remember_rule_list(&id_string, &list);
                        OVERLAP.with(|o| *o.borrow_mut() = OverlapFilter::Ready(Some(id_string.clone())));
                    } else {
                        let why = (!error.is_null())
                            .then(|| Retained::retain(error).expect("error pointer"))
                            .map(|e| e.localizedDescription().to_string())
                            .unwrap_or_else(|| "unknown error".to_string());
                        OVERLAP.with(|o| *o.borrow_mut() = OverlapFilter::Failed);
                        diag(&format!("overlap filter not compiled: {why}"));
                    }
                    let _ = proxy.send_event(UserEvent::AdOverlapSettled);
                },
            )),
        );
    }
}

/// Turns the allowance on for `site`. Refused while the overlap filter the
/// allowed tab must rely on is not in memory. The engine rebuild happens
/// HERE, before the return, so the caller's reload cannot race the lists.
pub fn allow_ads_on_tab(
    webview: &WebView,
    view: &TabView,
    site: String,
) -> Result<TabPolicy, &'static str> {
    if !ads_allow_ready() {
        return Err("ads_not_ready");
    }
    let policy = {
        let mut st = view.state.borrow_mut();
        let policy = st.grant_ads_allowance(site)?;
        st.set_adlist_override(None);
        policy
    };
    // The allowance lifts the bundled lists; the malicious-overlap filter
    // covers the blind spot it opens. Rebuilt inline, synchronously.
    rebuild_tab_rule_lists(webview, view);
    set_youtube_ads(webview, view, policy.block_youtube_ads);
    Ok(policy)
}

/// Ends the allowance, if there is one, and puts blocking back. Returns
/// whether there was one. Rebuilds inline for the same reason as
/// `allow_ads_on_tab`: the reload that follows must see the lists in place.
pub fn end_ads_allowance(webview: &WebView, view: &TabView) -> bool {
    let ended = view.state.borrow_mut().end_ads_allowance();
    if ended {
        rebuild_tab_rule_lists(webview, view);
        let on = view.state.borrow().policy.block_youtube_ads;
        set_youtube_ads(webview, view, on);
    }
    ended
}

/// Ends the allowance if `url` is on another site. Returns whether it ended.
/// Called from the load handler for every top-level load; WKWebView has no
/// pre-request veto, so the old document's tail requests ride with the lists
/// it loaded under -- the same boundary unix's load-signal path draws.
pub fn end_ads_allowance_if_leaving(webview: &WebView, view: &TabView, url: &str) -> bool {
    let ended = view
        .state
        .borrow_mut()
        .end_ads_allowance_unless_same_site(url);
    if ended {
        rebuild_tab_rule_lists(webview, view);
        let on = view.state.borrow().policy.block_youtube_ads;
        set_youtube_ads(webview, view, on);
        wake_overlap(UserEvent::AdsAllowanceEnded { tab_id: tab_id_of(view) });
    }
    ended
}

/// The browser is about to take this tab to `url` itself. Called BEFORE
/// `load_url` hands the request to WebKit, so a navigation the browser issues
/// ends the allowance before the new document's requests can go out. The tab
/// id travels in the wake because `TabView` is opaque here.
pub fn end_ads_allowance_before_navigation(webview: &WebView, view: &TabView, url: &str) {
    // `end_ads_allowance_if_leaving` posts `AdsAllowanceEnded` itself when it
    // ends the allowance; posting here too sent the event twice.
    end_ads_allowance_if_leaving(webview, view, url);
}

pub fn ads_allowed_site(view: &TabView) -> Option<String> {
    view.state.borrow().ads_allowed_site().map(str::to_string)
}

/// The policy in force in this tab, the allowance included.
pub fn tab_policy(view: &TabView) -> TabPolicy {
    view.state.borrow().policy.clone()
}

/// What this tab blocks without its allowance (the allowance's base policy).
pub fn ads_base_blocking(view: &TabView) -> bool {
    view.state.borrow().ads_base_policy().block_ads
}

/// Brings this tab's rule lists in line with what its `TabState` wants NOW:
/// bundled filters while blocking, the malicious-overlap filter while an
/// allowance is live (and none while there is nothing to cover). The freeze
/// filter re-rides when the tab is frozen, because WKWebView removes rule
/// lists as a set. Cosmetic hiding follows the bundled lists.
fn rebuild_tab_rule_lists(webview: &WebView, view: &TabView) {
    let Some(cc) = content_controller(webview) else { return };
    let (wants, wants_overlap, frozen) = {
        let st = view.state.borrow();
        (
            st.wants_ad_filters(),
            st.wants_overlap_filter(),
            st.freeze.phase() == FreezePhase::Frozen,
        )
    };
    // Rebuild is the whole set: remove everything, then add exactly what the
    // state wants. Every list comes from the run's memory cache, so the
    // whole rebuild is synchronous: there is no gap between the removal and
    // the adds in which the tab blocks nothing, and the reload the switch
    // issues cannot outrun its lists. WKWebView applies lists to NEW loads,
    // and the caller follows with a reload.
    remove_all_filters(&cc);
    if wants {
        install_bundled_filters(&cc, view);
    } else if wants_overlap {
        let ready = OVERLAP.with(|o| match &*o.borrow() {
            OverlapFilter::Ready(Some(id)) => Some(id.clone()),
            _ => None,
        });
        if let Some(id) = ready {
            add_rule_list(&cc, &id);
        }
    }
    if frozen {
        reinstall_installed_freeze_filter(&cc, view);
    }
    install_content_scripts(webview, view);
}

/// Adds an ALREADY-COMPILED rule list back to this tab's controller. The
/// run's memory cache answers synchronously when this run compiled the list;
/// the store lookup stays as the fallback (an id reached without its compile
/// in this run), which is correct but slower, and async.
fn add_rule_list(cc: &Retained<objc2_web_kit::WKUserContentController>, id: &str) {
    if let Some(list) = cached_rule_list(id) {
        // SAFETY: main-thread controller mutation of a list we hold.
        unsafe { cc.addContentRuleList(&list) };
        return;
    }
    let Some(store) = rule_list_store() else { return };
    // The block outlives this frame, so it captures the controller by value.
    let cc = cc.clone();
    let id_ns = NSString::from_str(id);
    // SAFETY: main-thread store read; the block is retained by WebKit for the
    // async lifetime.
    unsafe {
        store.lookUpContentRuleListForIdentifier_completionHandler(
            Some(&id_ns),
            Some(&block2::RcBlock::new(
                move |list: *mut WKContentRuleList, _error: *mut objc2_foundation::NSError| {
                    if !list.is_null() {
                        let list = Retained::retain(list).expect("rule list pointer");
                        cc.addContentRuleList(&list);
                    }
                },
            )),
        );
    }
}

/// The id recorded on this tab's build, for the wake events. `TabView` is
/// deliberately opaque, so the id lives beside the state it belongs to.
fn tab_id_of(view: &TabView) -> u64 {
    view.id
}

// ---------------------------------------------------------------------------
// Per-tab engine reads the panels make (1.0.7)

/// Whether another top-level navigation is about to replace this tab's page.
/// Windows-only in use upstream (`AdsAllowancePageKept` is a Windows event
/// shape); the honest answer here is unix's: never asked, always false.
#[allow(dead_code)]
pub fn replacement_pending(_view: &TabView) -> bool {
    false
}

/// The document on screen. As `replacement_pending`: the kept-page repair
/// that consumes it is a Windows path.
#[allow(dead_code)]
pub fn current_document(_view: &TabView) -> Option<u64> {
    None
}

/// Whether a reload without the cache failed since last asked. This backend
/// reloads synchronously through WebKit (`reloadFromOrigin` below) and never
/// records a later failure, so there is never one to take -- unix's shape.
pub fn take_bypass_reload_failed(_view: &TabView) -> bool {
    false
}

/// Reload without the cache (the engine's Ctrl+F5), for where ad and tracker
/// blocking has just come back for the tab. `WKWebView.reloadFromOrigin` is
/// WebKit's uncached reload, and it answers synchronously -- an error here is
/// returned, not recorded for later, which is what `take_bypass_reload_failed`
/// reporting false above says.
pub fn reload_bypassing_cache(webview: &WebView, _view: &TabView) -> Result<(), ()> {
    use wry::WebViewExtMacOS as _;
    // SAFETY: main-thread navigation call on this webview's own WKWebView.
    unsafe { webview.webview().reloadFromOrigin() };
    Ok(())
}

/// No kept profile on this backend, so there is no kept boundary to verify:
/// every tab is MAIN and the boundary is trivially ready.
pub fn kept_boundary_ready(_view: &TabView) -> bool {
    true
}

/// Frozen by the user's click, which a reload does not lift.
pub fn manually_frozen(view: &TabView) -> bool {
    view.state.borrow().freeze.is_manually_frozen()
}

/// What the engine did with this tab's Fingerprint Divergence script,
/// recorded at build. See the unix counterpart.
pub fn divergence_install(view: &TabView) -> privacy::ScriptInstall {
    view.state.borrow().divergence_install
}

/// What the engine did with this tab's YouTube ad script. The evidence is the
/// slot `set_youtube_ads` keeps in step with every rebuild: a tab that wants
/// the script and shows no slot has none.
pub fn youtube_ads_install(view: &TabView) -> privacy::ScriptInstall {
    privacy::youtube_script_install(
        view.state.borrow().policy.block_youtube_ads,
        *view.youtube_script.borrow(),
        false,
    )
}

/// Whether the ENGINE runs script in this tab right now, read back from
/// WebKit's own preferences rather than from the policy the tab was given.
/// `None` when the preferences object cannot be had. The smoke run's
/// strict-tab check reads THIS, so it proves the engine, not our bookkeeping.
pub fn engine_script_enabled(webview: &WebView) -> Option<bool> {
    // Same property wry's javascript_disabled arm writes: the modern
    // defaultWebpagePreferences.allowsContentJavaScript, not the deprecated
    // per-preferences getter, which no longer moves on this OS.
    // SAFETY: main-thread reads of this webview's own configuration.
    let config = unsafe { webview.webview().configuration() };
    let page_prefs = unsafe { config.defaultWebpagePreferences() };
    Some(unsafe { page_prefs.allowsContentJavaScript() })
}

// ---------------------------------------------------------------------------
// Kept profile (1.0.7) and window frame (1.0.7): shared-surface stubs.
// Kept tabs are a Windows feature (kept_profile.rs) and the desktop's title
// bar stays (window_frame.rs is the Windows half); both answers mirror
// unix's so every backend exposes one API.

/// No second profile here; every kind builds the ordinary way.
pub fn new_webview_builder_for(_kind: crate::kept_profile::ProfileKind) -> WebViewBuilder<'static> {
    new_webview_builder()
}

/// No kept profile on this backend.
pub fn kept_profile_supported() -> bool {
    false
}

/// The MAIN clear starts with the first content tab on this backend.
pub fn begin_main_profile_wipe(_webview: &WebView, _proxy: &EventLoopProxy<UserEvent>) {}

/// No kept profile on this backend.
pub fn begin_kept_profile_start(_hosts: &Hosts, _proxy: &EventLoopProxy<UserEvent>) {}

/// No kept profile on this backend.
pub fn sweep_kept_permissions(_hosts: &Hosts, _create: bool) {}

/// Nothing to remove on this backend.
pub fn remove_kept_profile_folder() -> bool {
    true
}

/// Linux keeps the desktop's title bar; the chrome draws no window controls
/// (window_frame.rs is the Windows half). macOS matches: the standard
/// title bar stays, and `window_control` is never reached.
pub fn custom_window_frame() -> bool {
    false
}

/// Never reached: AppState::window_control refuses first where
/// `custom_window_frame` is false. Kept so all backends expose one API.
pub fn window_control(
    _hosts: &Hosts,
    _action: crate::window_frame::WindowAction,
) -> Result<(), &'static str> {
    Err("unsupported")
}

/// The fullscreen notice cannot be drawn on this backend (no native view
/// layer over page pixels; see the page-fullscreen note), so AppState never
/// grants a page the screen and the notice never has to show. `set_page_fullscreen`
/// remains store-only; this false is what keeps the pair honest.
pub fn fullscreen_notice_can_draw(_hosts: &Hosts) -> bool {
    false
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

/// Not implemented on this backend — always refuses, like unix. WebKit CAN
/// clear per-host cookies (`deleteDataForDomain`), but the feature's contract
/// was designed and verified on Windows' cookie manager; shipping an
/// unverified path in a privacy browser is worse than refusing it.
pub fn forget_site_cookies(_webview: &WebView, _host: &str) -> bool {
    false
}

/// Not implemented — same rule as unix: the browser-wide clear this feature
/// is allowed to touch is cookies alone, and the untested path stays closed.
pub fn forget_all_cookies(_webview: &WebView) -> bool {
    false
}

// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
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
    // Plaintext is observable from the scheme alone: no chain exists to
    // classify, so `NotTls` there is a statement about the transport, not a
    // guess about a certificate. A secured scheme is NOT that statement: the
    // scheme says nothing about the chain, and WKWebView exposes no
    // UI-process path to the serving certificate (see `tls_issuer`), so
    // answering `Normal` from the scheme would tell the user their traffic
    // is verified when this process never read a certificate at all. It
    // answers `Unreadable` instead, the same shape as Windows: a statement
    // about this browser, not about the site. The interception warning
    // cannot fire here until a wry patch relays the authentication
    // challenge; when one does, this arm classifies for real.
    // SAFETY: main-thread property read.
    if let Some(url) = unsafe { webview.webview().URL() } {
        if let Some(scheme) = url.scheme() {
            if scheme.to_string() == "http" {
                return TlsState::NotTls;
            }
        }
    }
    st.tls_error_verdict.unwrap_or(TlsState::Unreadable)
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
        // queryable through the pinned bindings -- so the per-tab answer stays
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

// ---------------------------------------------------------------------------
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
/// resource, and re-fetching would be a different document — the one thing
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

// ---------------------------------------------------------------------------
// Find — NOT ported. WebKit has no find-in-page API in the pinned bindings
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

// ---------------------------------------------------------------------------
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

// ---- page capture ----

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
    // __unsafe_unretained object pointers — retained before use.
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
    // this backend — see blocked_total — but folded anyway so the accounting
    // is one code path, not a platform special case).
    privacy::fold_closed_tab(std::mem::take(&mut view.state.borrow_mut().ledger));
    // The window's content view retains the webview; dropping our handle
    // alone would leak the page. Detach first, then the drop is real.
    webview.webview().removeFromSuperview();
}

// ---------------------------------------------------------------------------
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
    // inset by the rectangle page_rect carves — the same inverted arrangement
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
        // pane IS the active page above — `pair` is ordered left-right and
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
            // content view as parent. Deferred off this context -- see
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

/// objc2 handles are !Send on purpose -- these views are main-thread-only --
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
/// `-[NSView _setSuperview:]` -- the reorder waits on a Core Animation
/// transaction the observer-blocked run loop can never commit (observed live:
/// the whole app wedged solid the moment a modal flipped ChromeLayout to
/// Overlay, taking every later click with it). The same mutation serviced
/// from the run loop's main-queue drain -- a normal run-loop turn -- is the
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
/// cover. True only if the chrome actually went transparent — see
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
/// auto-freeze driver — the Windows model. `should_auto_freeze` is fed by
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
/// Checked on hardware 2026-11-09 (macOS 27.2): a WKWebView download saved
/// through this process arrives WITH `com.apple.quarantine` written by
/// WebKit itself (`0083;<epoch>;;`), so Gatekeeper's first-open warning is
/// already there and there is nothing to scrub or add. Present so
/// `platform` exposes one shape on every target. See `platform::motw`.
pub fn scrub_download_mark(_path: &std::path::Path) -> super::motw::Outcome {
    super::motw::Outcome::NotApplicable
}

// ---------------------------------------------------------------------------
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
        // Same as `unfreeze`: the freeze ends in the Book too, so an
        // in-flight compile of this tab's freeze is discarded by its
        // completion.
        for id in st.freeze_filters.lift() {
            forget_rule_list(&id);
        }
        st.policy.block_ads
    };
    let Some(cc) = content_controller(webview) else { return };
    remove_all_filters(&cc);
    if block_ads {
        install_bundled_filters(&cc, view);
    }
}

/// The hosts the tab's freeze lets through, for the panel's "Allowed" rows.
pub fn freeze_allowed_hosts(view: &TabView) -> Vec<String> {
    view.state.borrow().freeze.overrides()
}

/// Side by Side: two tabs' pages next to each other, or back to one tab at
/// a time. There is no packing on this backend — `layout` positions both
/// pages by hand — so this only manages VISIBILITY, never focus (the
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
/// remains reachable is the BROWSER side (`exit_page_fullscreen` — a
/// shortcut, a modal, a tab switch), and these stubs make it safe: the
/// window was never fullscreen, `set_page_fullscreen(false)` is the
/// idempotent give-back, and the notice is a no-op like the hover readout
/// it borrows its shape from. Feature off, honestly — the same choice the
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
/// window call is unconditional — it is the idempotent give-back.
pub fn set_page_fullscreen(hosts: &Hosts, on: bool) {
    hosts.fullscreen.set(on);
    hosts
        ._window
        .set_fullscreen(on.then_some(tao::window::Fullscreen::Borderless(None)));
}

/// Nothing to place: geometry keeps coming from `layout`, which state.rs
/// calls on every relayout — including the fullscreen ones, before this
/// runs (its early return is AFTER `layout_fullscreen` in relayout).
/// Fullscreen never engages on this backend anyway (see the note above).
pub fn layout_fullscreen(_hosts: &Hosts, _chrome: &WebView, _page: &WebView) {}

/// The fullscreen notice, top centre. Reuses the hover readout's slot the
/// way unix does, but the readout is not ported on macOS (its host view
/// would be another native layer between chrome and page), so the notice
/// cannot be shown -- reported as false, which AppState takes as "no page
/// gets the screen". The browser-side fullscreen that would raise it never
/// engages on this backend either.
pub fn set_fullscreen_notice(_hosts: &Hosts, _text: Option<&str>) -> bool {
    // False is the honest answer, not a failure: the notice's host widget
    // does not exist here, so nothing was shown and the caller must not
    // hand a page the screen over it.
    false
}

#[cfg(test)]
mod macos_backend_tests {
    use super::{diag, recent_diagnostics, DIAG_LOG_CAP};
    use super::{
        ads_allowed_site, ads_base_blocking, current_document, custom_window_frame,
        engine_settings, freeze_dir_pid, freeze_enforced, initial_navigation_ready,
        interception_state, kept_boundary_ready, kept_profile_supported, manually_frozen,
        network_blocking_supported, page_bytes_supported, process_is_gone, replacement_pending,
        session_lock_registered, split_supported, take_bypass_reload_failed,
        translate_channel_supported, youtube_ads_install, TabView, MACOS_INTERCEPTION_NAME,
    };
    use crate::platform::privacy::{ScriptInstall, SettingState, TabPolicy, TabState};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A tab with no engine behind it: enough for every store-only path this
    /// backend keeps in `TabState` and its own slots. The engine-backed
    /// answers (rule lists, script installs on a live controller) are the
    /// smoke gate's job on real hardware; these tests pin the answers that
    /// do not need a webview, including on Linux CI via the source contracts
    /// in state.rs and platform/mod.rs.
    fn store_only_tab(policy: &TabPolicy) -> TabView {
        TabView {
            id: 7,
            state: Rc::new(RefCell::new(TabState::new(policy))),
            youtube_script: RefCell::new(false),
        }
    }

    /// Each `false` here is a promise the panel renders: a control this
    /// backend cannot honour is hidden or explained, never shown and inert.
    /// If one of these turns true, the port grew the feature and the parity
    /// list shipped with it is stale and must be rewritten in the same
    /// change.
    #[test]
    fn the_declared_off_switches_stay_off() {
        assert!(!kept_profile_supported(), "kept profile is not ported");
        assert!(
            !custom_window_frame(),
            "macOS keeps the standard title bar, matching unix"
        );
        assert!(!split_supported(), "docked panes are not laid out here");
        assert!(
            !page_bytes_supported(),
            "WebKit serves no main-resource bytes to this process"
        );
        assert!(
            !translate_channel_supported(),
            "the translator channel is not ported"
        );
        assert_eq!(
            session_lock_registered(),
            SettingState::NotAttempted,
            "the vault lock on screen lock is deferred, not half-built"
        );
    }

    /// The stubs that answer from `TabState` must refuse rather than invent:
    /// a pending replacement, a document id or a recorded reload failure on
    /// this backend would be bookkeeping with no engine event behind it,
    /// which is exactly the class of lie the honest-stub rule exists for.
    #[test]
    fn the_store_only_stub_answers_refuse_rather_than_invent() {
        let view = store_only_tab(&TabPolicy::default());
        assert!(!replacement_pending(&view));
        assert_eq!(current_document(&view), None);
        assert!(
            !take_bypass_reload_failed(&view),
            "reloadFromOrigin answers synchronously; there is no later failure to record"
        );
        assert!(kept_boundary_ready(&view), "every tab is MAIN, boundary trivially ready");
        assert!(!manually_frozen(&view));
        assert_eq!(ads_allowed_site(&view), None);
        assert!(
            ads_base_blocking(&view),
            "the default policy blocks ads, with or without an allowance path"
        );
    }

    /// The mechanism the panel shows must name what actually blocks on this
    /// platform, never Windows' word for it, and blocking must be real.
    #[test]
    fn the_interception_name_says_what_actually_runs() {
        let view = store_only_tab(&TabPolicy::default());
        assert_eq!(interception_state(&view), MACOS_INTERCEPTION_NAME);
        assert_eq!(MACOS_INTERCEPTION_NAME, "content_rule_list");
        assert!(network_blocking_supported());
        assert!(freeze_enforced());
    }

    /// The rows with no macOS answer stay "not_attempted" exactly as on unix:
    /// a row that claimed "applied" without an engine acknowledgement is the
    /// finding the 2026-10-08 audit was about.
    #[test]
    fn the_engine_settings_rows_without_a_macos_answer_say_not_attempted() {
        let view = store_only_tab(&TabPolicy::default());
        let settings = engine_settings(&view);
        assert_eq!(settings.hardened_environment, "not_attempted");
        assert_eq!(settings.session_lock_registered, "not_attempted");
        assert_eq!(settings.content_script_registered, "not_attempted");
        assert_eq!(settings.permissions_registered, "not_attempted");
        assert_eq!(
            settings.sandbox, "not_attempted",
            "WebContent's sandbox is the OS's and not queryable here"
        );
    }

    /// The YouTube script's reported state comes from the slot the rebuild
    /// keeps in step with the controller, not from the switch: wanted but
    /// never installed is a refusal, present is installed, unwanted and
    /// absent is not-wanted. Same rule privacy.rs pins for the other
    /// backends, read through this backend's evidence.
    #[test]
    fn the_youtube_script_evidence_reports_the_controller_not_the_wish() {
        let mut off = TabPolicy::default();
        off.block_youtube_ads = false;
        let view = store_only_tab(&off);
        assert_eq!(youtube_ads_install(&view), ScriptInstall::NotWanted);

        let view = store_only_tab(&TabPolicy::default());
        assert_eq!(
            youtube_ads_install(&view),
            ScriptInstall::Refused,
            "switched on, slot empty, nothing in flight: the engine has no script"
        );
        *view.youtube_script.borrow_mut() = true;
        assert_eq!(youtube_ads_install(&view), ScriptInstall::Installed);
    }

    /// ONE test, not two, because `diag` writes to a process-global ring
    /// buffer and cargo runs tests in parallel: split in two, the
    /// bounded-ness check evicted the entry the other test was asserting on
    /// (unix.rs hit exactly this). A flaky test is worse than no test.
    #[test]
    fn the_diagnostic_log_records_failures_and_stays_bounded() {
        diag("macos test probe");
        let first = recent_diagnostics();
        assert!(
            first.iter().any(|l| l.contains("macos test probe")),
            "a recorded failure did not reach the export"
        );
        assert_eq!(first, recent_diagnostics(), "reading the log drained it");
        for i in 0..(DIAG_LOG_CAP * 2) {
            diag(&format!("macos bound probe {i}"));
        }
        assert!(recent_diagnostics().len() <= DIAG_LOG_CAP);
    }

    /// The gate the first page waits behind: a tab whose bundled rule lists
    /// are still compiling holds its first page, and an ephemeral tab whose
    /// lists have landed may go. The engine-backed half (that the lists do
    /// land, and that `BundledFiltersSettled` fires) is the smoke gate's job;
    /// this pins the store-only answers.
    #[test]
    fn a_first_page_waits_while_its_rule_lists_compile() {
        let view = store_only_tab(&TabPolicy::default());
        view.state.borrow_mut().bundled_filters_loading = 2;
        assert!(
            !initial_navigation_ready(&view),
            "a first page issued while its rule lists compile would go out unfiltered"
        );
        view.state.borrow_mut().bundled_filters_loading = 0;
        view.state.borrow_mut().policy.ephemeral = true;
        assert!(initial_navigation_ready(&view));
    }

    /// Only a directory named for a pid may be considered for the sweep, and
    /// only a real one; the name parser is the first guard.
    #[test]
    fn freeze_store_directory_names_parse_to_their_pid() {
        assert_eq!(freeze_dir_pid("patanyx-42-freeze"), Some(42));
        assert_eq!(freeze_dir_pid("patanyx-0-freeze"), Some(0));
        assert_eq!(freeze_dir_pid("patanyx-4294967295-freeze"), Some(4294967295));
        assert_eq!(
            freeze_dir_pid("patanyx-42-freeze-old"),
            None,
            "a name that is not exactly the pattern is not a store"
        );
        assert_eq!(freeze_dir_pid("patanyx--freeze"), None);
        assert_eq!(freeze_dir_pid("patanyx-4294967296-freeze"), None);
        assert_eq!(freeze_dir_pid("other-42-freeze"), None);
        assert_eq!(freeze_dir_pid("patanyx-42"), None);
    }

    /// The sweep's liveness answer: the running process is not gone. (That a
    /// reaped pid answers gone is the kernel's word, exercised on the gate
    /// run itself.)
    #[test]
    fn the_running_process_is_not_reported_gone() {
        assert!(!process_is_gone(std::process::id()));
    }
}
