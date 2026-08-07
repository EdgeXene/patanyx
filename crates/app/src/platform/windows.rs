//! WebView2 backend glue.
//!
//! There is no GTK on Windows: child webviews are created with
//! `build_as_child`, laid out manually with `set_bounds`, and shown or
//! hidden with `set_visible`. Every resize, scale-factor change, tab
//! switch, and chrome-height change must therefore be followed by
//! `layout()` (see AppState::relayout). Downloads are native here -- wry's
//! `with_download_*_handler` work through ICoreWebView2_4 -- so the
//! webkit2gtk Response-policy workaround is neither needed nor portable.
//!
//! Privacy controls: one `WebResourceRequested` handler per content tab is
//! the single interception mechanism for network-level ad blocking, freeze
//! enforcement and the ledger. A matched request is answered locally with
//! an empty 403 -- it never leaves the machine. Cosmetic filtering does not
//! exist here (see set_cosmetic note on the unix side and the Note in
//! apply_policy): WebView2 has no user-stylesheet API, and injected script
//! is forbidden for content webviews.
//!
//! That handler is also the single point of failure, and the first
//! behavioural measurement of this backend (2026-07-25) found it silent:
//! a manually frozen tab kept fetching. So registration now records how
//! far it got (`InterceptionState`), no getter failure inside the handler
//! lets a request through while frozen, and nothing here claims the tab is
//! protected until the engine has accepted a block. Every decision itself
//! lives in `privacy.rs`, where `cargo test` can reach it -- this file is
//! COM plumbing, and the plumbing is what was never executed.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use patanyx_vault::Vault;
use tao::dpi::{LogicalPosition, LogicalSize};
use tao::event_loop::EventLoopProxy;
use tao::window::Window;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Environment, COREWEBVIEW2_WEB_ERROR_STATUS,
    COREWEBVIEW2_WEB_ERROR_STATUS_CANNOT_CONNECT, COREWEBVIEW2_WEB_ERROR_STATUS_CONNECTION_ABORTED,
    COREWEBVIEW2_WEB_ERROR_STATUS_CONNECTION_RESET, COREWEBVIEW2_WEB_ERROR_STATUS_DISCONNECTED,
    COREWEBVIEW2_WEB_ERROR_STATUS_HOST_NAME_NOT_RESOLVED,
    COREWEBVIEW2_WEB_ERROR_STATUS_SERVER_UNREACHABLE, COREWEBVIEW2_WEB_ERROR_STATUS_TIMEOUT,
    COREWEBVIEW2_WEB_ERROR_STATUS_UNKNOWN,
};
use wry::{Rect, WebContext, WebView, WebViewBuilder, WebViewBuilderExtWindows};

use super::privacy::{
    self, EngineSettings, FreezePhase, HostRecord, ProfileMode, SettingState, TabPolicy, TabState,
    TlsState,
};
use super::{ChromeLayout, CHROME_HEIGHT_PX};
use crate::shortcuts::{self, Key, Mods};
use crate::UserEvent;

/// Strips WebView2's built-in right-click menu.
///
/// That menu is Edge's, not ours, and it advertises Microsoft account features
/// this browser does not implement and should not imply: "Share" and "Send tab
/// to your devices" both suggest a sync relationship with an account that does
/// not exist here. Back and Refresh already live in the toolbar.
fn without_default_context_menu(builder: WebViewBuilder<'_>) -> WebViewBuilder<'_> {
    builder.with_default_context_menus(false)
}

/// Routes browser shortcuts from WebView2 into the event loop.
///
/// `AcceleratorKeyPressed` fires on the host for keys pressed inside the
/// webview, which is exactly the hook needed here: shortcuts must work while a
/// page has focus, and content webviews have no IPC by design. wry does not
/// register this event itself, so it is free to use.
///
/// Handled keys are marked handled so the page does not also act on them;
/// everything else is left alone so typing still works.
fn connect_shortcuts(webview: &WebView, proxy: &EventLoopProxy<UserEvent>) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN, COREWEBVIEW2_PHYSICAL_KEY_STATUS,
    };
    use webview2_com::AcceleratorKeyPressedEventHandler;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetKeyState, VK_CONTROL, VK_MENU, VK_SHIFT,
    };
    use wry::WebViewExtWindows;

    let proxy = proxy.clone();
    let controller = webview.controller();
    let mut token = Default::default();
    unsafe {
        let _ = controller.add_AcceleratorKeyPressed(
            &AcceleratorKeyPressedEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                // Key-up would fire a second time for the same press.
                let mut kind = COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN;
                args.KeyEventKind(&mut kind)?;
                if kind != COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN {
                    return Ok(());
                }
                let mut virtual_key = 0u32;
                args.VirtualKey(&mut virtual_key)?;

                // The keypad, read from the HARDWARE SCAN CODE rather than the
                // virtual key. Ctrl+= zoomed and Ctrl+keypad-plus did nothing,
                // on a build where `vk_key` maps VK_ADD and `resolve` binds it
                // -- every line of our own path was correct, so the virtual key
                // arriving here is not the one the keypad sent. Scan codes come
                // off the keyboard before any layout or engine normalisation
                // can rewrite them, so they say what was physically pressed.
                let mut status = COREWEBVIEW2_PHYSICAL_KEY_STATUS::default();
                let _ = args.PhysicalKeyStatus(&mut status);

                // The event carries no modifier state, so it is read from the
                // keyboard: the high bit of GetKeyState means "currently down".
                let down = |vk| (GetKeyState(i32::from(vk)) as u16 & 0x8000) != 0;
                let mods = Mods::new(
                    down(VK_CONTROL.0),
                    down(VK_SHIFT.0),
                    down(VK_MENU.0),
                );

                // EVERY keydown is evidence a human is here, not just the bound
                // ones. This hook already sees them all and used to discard
                // whatever did not resolve to a shortcut -- so typing inside a
                // page counted for nothing, and the vault auto-locked out from
                // under someone filling in a form.
                //
                // Raised BEFORE the shortcut match so an unbound key still
                // counts, and throttled so holding a key does not flood the
                // loop. Nothing about which key was pressed leaves this
                // closure.
                if super::presence_throttle_elapsed() {
                    let _ = proxy.send_event(UserEvent::UserPresence);
                }

                // Virtual key first, scan code only as a fallback: the main row
                // works today and must keep working exactly as it does.
                let pressed = shortcuts::vk_key(virtual_key)
                    .or_else(|| shortcuts::keypad_scan_code(status.ScanCode, status.IsExtendedKey.as_bool()));
                if let Some(action) = pressed.and_then(|k| shortcuts::resolve(mods, k)) {
                    let _ = proxy.send_event(UserEvent::Shortcut(action));
                    args.SetHandled(true)?;
                }
                Ok(())
            })),
            &mut token,
        );
    }
}

// `vk_key` moved to shortcuts.rs, beside `keypad_scan_code` and the resolver
// it feeds. It is a pure u32 -> Key mapping with no Win32 types in it, and
// living in a #[cfg(windows)] file meant NOTHING could test it from the Linux
// CI -- which is exactly how the unix table silently lost its `k` and `p`
// entries and left Ctrl+K and Ctrl+P dead on that platform. Now one test
// checks both tables against the resolver on every run.

/// Reports zoom the ENGINE performed, so the indicator matches reality.
///
/// Without this, a keypad zoom would change the page and leave the chip
/// showing the last level this process set -- an indicator that is wrong
/// precisely when the user just acted, which is worse than no indicator.
///
/// Fires for programmatic `SetZoomFactor` too, so the chip is driven from one
/// place regardless of which path did the zooming.
pub fn connect_zoom_changed(webview: &WebView, proxy: &EventLoopProxy<UserEvent>, id: u64) {
    use webview2_com::ZoomFactorChangedEventHandler;
    use wry::WebViewExtWindows;

    let proxy = proxy.clone();
    let controller = webview.controller();
    let reader = controller.clone();
    let mut token = Default::default();
    unsafe {
        let _ = controller.add_ZoomFactorChanged(
            &ZoomFactorChangedEventHandler::create(Box::new(move |_sender, _args| {
                let mut factor = 1.0f64;
                reader.ZoomFactor(&mut factor)?;
                let _ = proxy.send_event(UserEvent::ZoomFactorChanged(id, factor));
                Ok(())
            })),
            &mut token,
        );
    }
}

/// Owns the window: it is the parent of every child webview and the source
/// of truth for the client-area size used by `layout`.
pub struct Hosts {
    window: Window,
    /// The chrome webview's own child HWND, captured at `build_chrome` time
    /// while it is the ONLY child of the window -- the single moment it can
    /// be identified without guessing. Zero means "never captured", and every
    /// consumer treats that as "the translucent-backdrop lift is off", never
    /// as an error: the modal must keep working on a machine where the
    /// capture failed, it just keeps the opaque cover.
    ///
    /// Stored as the raw isize rather than HWND so Hosts stays free of
    /// windows-crate types in its public shape.
    chrome_child: std::cell::Cell<isize>,
}

/// WebView2 has no container widget; the tab's `WebView` itself is the only
/// engine handle, and dropping it destroys the controller (see remove_tab).
/// Per-tab privacy state lives here, shared (Rc) with the event handlers
/// registered at build time; WebView2 raises its events on the UI thread,
/// so Rc/RefCell is correct.
pub struct TabView {
    state: Rc<RefCell<TabState>>,
}

pub fn create_hosts(window: Window) -> Hosts {
    Hosts {
        window,
        chrome_child: std::cell::Cell::new(0),
    }
}

/// tao windows are visible by default; there is no GTK `show_all` step.
pub fn show_all(_hosts: &Hosts) {}

// ---------------------------------------------------------------------------
// The persistent browsing profile
//
// Until 2026-07-27 nothing here configured a user-data directory at all, so
// WebView2 used its default: a folder named `<exe-file-name>.WebView2` beside
// the executable. On the project owner's machine that meant a full Chromium
// profile -- Local State, Default, Crashpad, GrShaderCache, BrowserMetrics --
// sitting in Downloads next to the exe, while the vault and store were
// deliberately living under `%APPDATA%\patanyx\`. Deleting the executable
// removed none of it, which for a browser whose slogan is "Leave less
// behind." is residue in the least expected place.
//
// It now goes beside the vault. Three things about the wry 0.55.1 API that a
// reader will otherwise reasonably assume, and which were checked against the
// vendored source rather than guessed:
//
//  1. There is NO `WebViewBuilder::with_web_context` setter. The only route
//     is `new_with_web_context`, at construction (wry lib.rs:882), which is
//     why this backend exposes a builder factory instead of a mutator and
//     why the change reaches state.rs and main.rs at all.
//  2. `WebContext` is the ONLY way in. wry's webview2 backend reads
//     `attributes.context.data_directory()` and passes it straight to
//     `CreateCoreWebView2EnvironmentWithOptions` (wry webview2/mod.rs:287
//     and :343). A `--user-data-dir` in `with_additional_browser_args` would
//     not work: the user-data folder is an environment-CREATION parameter,
//     not a Chromium switch WebView2 honours.
//  3. wry's own doc on `incognito` says "WebContext will be ignored if
//     incognito is enabled". That is true of the wkwebview backend and NOT
//     of this one: `create_environment` runs unconditionally, and incognito
//     is applied afterwards to the CONTROLLER via
//     `SetIsInPrivateModeEnabled` (wry webview2/mod.rs:407). So the
//     ephemeral arm in `build_content` is untouched by this -- an ephemeral
//     tab keeps its memory-only site state, and additionally stops
//     scattering the environment-level scaffolding (Crashpad, BrowserMetrics)
//     beside the exe, which it did before.
// ---------------------------------------------------------------------------

/// The user-data directory handed to every WebView2 environment this process
/// creates, or None to leave wry on its default.
///
/// Resolved and created ONCE. None means the directory could not be made, and
/// the fallback is deliberately the old behaviour: a browser that cannot open
/// a tab because a profile directory was unwritable would be a far worse
/// failure than one that puts the profile in the wrong place and says so.
fn profile_dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = super::browsing_profile_dir(&Vault::default_path());
        // WebView2 would create the leaf itself, but not necessarily the
        // parents, and a failure here is reportable while a failure inside
        // `CreateCoreWebView2EnvironmentWithOptions` surfaces only as a tab
        // that would not build.
        if let Err(error) = std::fs::create_dir_all(&dir) {
            diag(&format!(
                "profile: could not create {} ({error}); falling back to WebView2's default, \
                 which is a folder beside the executable",
                dir.display()
            ));
            return None;
        }
        diag(&format!("profile: user data folder is {}", dir.display()));
        Some(dir)
    })
    .as_deref()
}

/// Every webview in this process is built from here, so every one of them
/// lands in the same profile.
///
/// A fresh `WebContext` is leaked per call, and both halves of that want
/// justifying. `new_with_web_context` takes `&'a mut WebContext` tied to the
/// builder's lifetime, and the builders are assembled in state.rs and main.rs
/// -- platform-neutral files that cannot own a Windows-only type without the
/// `#[cfg]` sprawl this module exists to prevent. Leaking gives the `'static`
/// that resolves it, and it costs a `PathBuf` per webview created.
///
/// Per-webview rather than shared is not a compromise: on Windows a
/// `WebContext` carries NOTHING but the path (`WebContextImpl` is a unit
/// struct off gtk, and the webview2 backend reads only `data_directory()`),
/// and wry creates a separate `ICoreWebView2Environment` per webview either
/// way. Sharing one instance would change nothing an environment can observe.
///
/// CONSTRAINT that comes with a shared folder: concurrent WebView2
/// environments over one user-data directory must be created with IDENTICAL
/// `CoreWebView2EnvironmentOptions`, or creation fails.
///
/// THIS PARAGRAPH USED TO SAY the options were identical because "nothing in
/// this crate sets `with_additional_browser_args`, autoplay, a proxy,
/// extensions or a scrollbar style". That stopped being true when
/// `shared_environment` landed: it sets browser args, extensions and a
/// scrollbar style explicitly. The constraint is still satisfied, but for a
/// stronger reason -- there is now exactly ONE environment for the process,
/// handed to every webview, so the options cannot differ between them rather
/// than merely happening not to. Anything that ever needs per-webview options
/// has to give that webview its own directory.
/// Chromium switches this browser passes, on top of wry's own.
///
/// wry's default string is retyped VERBATIM at the front. It is not decoration:
/// `msSmartScreenProtection` is where wry's half of the SmartScreen suppression
/// lives, alongside `harden_privacy`'s `SetIsReputationCheckingRequired(false)`.
/// `additionalBrowserArguments` REPLACES the default rather than appending, so
/// dropping those three silently restores a protection we deliberately removed.
///
/// Everything after them turns off Chromium's own background chatter. None of
/// this is WebView2's "required" diagnostic pipe -- that one genuinely cannot
/// be closed from an embedding app and Microsoft documents it. These are the
/// other callbacks, which have been running since the first Windows build
/// because nobody looked at what the engine does when left alone:
///
///   --disable-background-networking   variations/Finch, and the assorted
///                                     fetches that need no user action
///   --disable-domain-reliability      Google's network-error reporting, which
///                                     carries HOSTNAMES when a request fails
///   --no-pings                        `<a ping>`, which reports the link a
///                                     user clicked to a third party
///   --disable-sync                    no account exists here to sync to
///   --force-webrtc-ip-handling-policy=disable_non_proxied_udp
///                                     WebRTC must not route around a tunnel
///
/// That last one matters more than its length suggests. WebRTC gathers ICE
/// candidates from every local interface and can reach a STUN server directly,
/// which is the classic way a browser hands out a user's real address while
/// they believe a VPN is carrying their traffic. `disable_non_proxied_udp`
/// keeps WebRTC WORKING -- video calls still connect -- but forbids the
/// non-proxied path, so it cannot step around the tunnel. Turning WebRTC off
/// outright would also fix it and would break every web video call; this does
/// not.
///
/// `--disable-component-update` was here and was REMOVED, deliberately. It
/// sends no browsing data -- it downloads components -- so against the threat
/// this browser actually defends against (a company learning which sites a
/// user visits and what they type) it buys nothing. What it costs is real:
/// Widevine, so DRM video stops playing, and CRLSet, so certificate REVOCATION
/// stops refreshing. Trading a live security update for no privacy gain is a
/// bad trade, and it was made here by momentum rather than by reasoning.
///
/// A MALFORMED ARGUMENT FAILS ENVIRONMENT CREATION, which means the browser
/// does not open at all. That is the risk, it is not hypothetical, and it is
/// why this is one commit on its own.
const BROWSER_ARGS: &str = concat!(
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection",
    " --disable-background-networking",
    " --disable-domain-reliability",
    " --no-pings",
    " --disable-sync",
    " --force-webrtc-ip-handling-policy=disable_non_proxied_udp",
);

/// The ONE WebView2 environment this process uses.
///
/// Taking creation over is what makes two things reachable that wry's own
/// environment leaves at their defaults:
///
///   * `SetIsCustomCrashReportingEnabled(true)` -- WebView2 stops uploading
///     crash dumps to Microsoft. A dump is a memory snapshot of the crashed
///     process, not an error string: for a renderer that can carry the URL and
///     whatever page data was live. The vault is in OUR process and never in
///     one of these, but page content is exactly what this product promises
///     does not leave the machine.
///   * `BROWSER_ARGS` -- see above.
///
/// It also makes `EnableTrackingPrevention(true)` EXPLICIT. It was true before
/// only because `CoreWebView2EnvironmentOptions::default()` happens to set it,
/// and the STRICT profile level in `harden_privacy` silently depends on it. An
/// inherited default holding up a shipped protection is the shape of defect
/// this file has been finding all week.
///
/// ONE environment for the whole process, handed to every webview. That is not
/// incidental: concurrent environments over a single user-data folder must be
/// created with IDENTICAL options or creation fails outright, and the shared
/// profile directory made that a live constraint. One environment retires it
/// instead of adding to it.
///
/// Every option wry sets is reproduced -- browser args, extensions flag, UI
/// language, scrollbar style -- because we are replacing its `create_environment`
/// wholesale, not extending it. Anything missed here is a default silently
/// changing under the engine.
///
/// Returns `None` on any failure, and the caller then lets wry create the
/// environment exactly as before. That fallback is today's behaviour, so the
/// worst case is losing the new hardening rather than losing the browser.
/// The full Chromium argument string this browser wants, built in ONE place
/// so the two paths that can create an environment cannot disagree: the
/// hardened `shared_environment` passes it through environment options, and
/// `new_webview_builder`'s fallback branch passes the SAME string through
/// wry's `with_additional_browser_args` -- which REPLACES wry's default, so
/// `BROWSER_ARGS` retyping that default verbatim at the front is what keeps
/// wry's own SmartScreen suppression intact on both paths.
fn desired_browser_args() -> String {
    // The user's resolver choice. Read at environment creation, because
    // that is the ONLY place WebView2 accepts it -- there is no runtime API
    // for DNS, which is why changing it needs a restart and why the UI says
    // so rather than pretending otherwise.
    let mut args = String::from(BROWSER_ARGS);
    let dns = crate::prefs::load().dns;
    if let (Some(mode), Some(template)) = (dns.doh_mode(), dns.doh_template()) {
        // `secure`, which FAILS CLOSED. Picking a resolver and then being
        // silently downgraded to the network's plaintext DNS is the exact
        // leak the setting exists to close, and WebView2 gives no signal
        // that it happened -- so an `automatic` fallback would be a
        // protection the user believes in and cannot verify.
        //
        // The cost is captive portals, which work BY hijacking DNS: with a
        // resolver chosen, hotel and airport login pages will not load.
        // That is survivable only because it is opt-in and reversible --
        // `System` carries no mode at all, so switching back and
        // restarting is the way onto such a network, and `describe()` says
        // so in the sentence shown before the choice is made.
        args.push_str(" --dns-over-https-mode=");
        args.push_str(mode);
        args.push_str(" --dns-over-https-templates=");
        args.push_str(template);
    }

    // The tunnel proxy, for the same reason DoH is here: WebView2 accepts
    // --proxy-server only at environment creation, so a mode change takes a
    // restart -- `TunnelMode::describe` already says so, and there is
    // deliberately no runtime path.
    crate::tunnel_control::bind_if_enabled();
    if let Some(port) = crate::tunnel_control::engine_proxy_port() {
        // The value is built ONLY from a port this process chose (a u16
        // formatted by us): a malformed argument kills environment
        // creation, so no user-influenced text may ever enter it.
        // FAIL CLOSED: when the mode is Imported but the bind failed,
        // `engine_proxy_port` yields 1 -- a closed port, so every request
        // fails rather than silently going direct, which is the one
        // unacceptable outcome. And because BOTH environment paths take
        // this same string, an environment-creation failure no longer
        // strips the proxy either -- the independent review correctly
        // refused to ship the version where it did.
        args.push_str(" --proxy-server=socks5://127.0.0.1:");
        args.push_str(&port.to_string());
    }
    args
}

fn shared_environment() -> Option<&'static ICoreWebView2Environment> {
    use webview2_com::CoreWebView2EnvironmentOptions;
    use webview2_com::CreateCoreWebView2EnvironmentCompletedHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        CreateCoreWebView2EnvironmentWithOptions, ICoreWebView2EnvironmentOptions,
        COREWEBVIEW2_SCROLLBAR_STYLE_DEFAULT,
    };
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Globalization::{
        LCIDToLocaleName, GetUserDefaultUILanguage, LOCALE_ALLOW_NEUTRAL_NAMES, MAX_LOCALE_NAME,
    };

    static ENV: OnceLock<Option<SendEnv>> = OnceLock::new();
    // The environment is created on, and only ever used from, the UI thread.
    // The wrapper exists solely to park it in a `OnceLock`.
    struct SendEnv(ICoreWebView2Environment);
    unsafe impl Send for SendEnv {}
    unsafe impl Sync for SendEnv {}

    ENV.get_or_init(|| {
        let args = desired_browser_args();

        let options = CoreWebView2EnvironmentOptions::default();
        unsafe {
            options.set_additional_browser_arguments(args);
            // The two this whole function exists for.
            options.set_is_custom_crash_reporting_enabled(true);
            options.set_enable_tracking_prevention(true);
            // Reproducing wry, so nothing silently changes.
            options.set_are_browser_extensions_enabled(false);
            let lcid = GetUserDefaultUILanguage();
            let mut lang = [0u16; MAX_LOCALE_NAME as usize];
            LCIDToLocaleName(lcid as u32, Some(&mut lang), LOCALE_ALLOW_NEUTRAL_NAMES);
            options.set_language(String::from_utf16_lossy(&lang));
            options.set_scroll_bar_style(COREWEBVIEW2_SCROLLBAR_STYLE_DEFAULT);

            let data_dir = profile_dir()
                .map(|d| HSTRING::from(d.as_os_str()))
                .unwrap_or_default();
            let (tx, rx) = std::sync::mpsc::channel();
            let created = CreateCoreWebView2EnvironmentWithOptions(
                PCWSTR::null(),
                &data_dir,
                &ICoreWebView2EnvironmentOptions::from(options),
                &CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(
                    move |code, environment| {
                        // The error type is spelled out: several crates in
                        // this tree provide `From<windows_result::Error>`, so
                        // inference has more than one candidate and picks none.
                        let result: windows::core::Result<ICoreWebView2Environment> = (|| {
                            code?;
                            environment.ok_or_else(|| {
                                windows::core::Error::from(windows::Win32::Foundation::E_POINTER)
                            })
                        })();
                        tx.send(result).map_err(|_| {
                            windows::core::Error::from(
                                windows::Win32::Foundation::E_UNEXPECTED,
                            )
                        })?;
                        Ok(())
                    },
                )),
            );
            if let Err(error) = created {
                diag(&format!(
                    "environment: CreateCoreWebView2EnvironmentWithOptions FAILED ({error}); \
                     falling back to wry's environment -- crash reporting stays ON"
                ));
                return None;
            }
            // Same nested pump wry uses; environment creation is asynchronous
            // and there is no event loop running yet at first call.
            // Doubly wrapped on purpose: `wait_with_pump` reports whether the
            // pump itself survived, and the channel carries whether WebView2
            // succeeded. Both are failures and both fall back.
            match webview2_com::wait_with_pump(rx).map(|inner| inner) {
                Ok(Ok(env)) => {
                    diag("environment: created with crash reporting OFF and hardened browser args");
                    Some(SendEnv(env))
                }
                Ok(Err(error)) => {
                    diag(&format!(
                        "environment: WebView2 refused the options ({error}); falling back to \
                         wry's environment -- crash reporting stays ON"
                    ));
                    None
                }
                Err(error) => {
                    diag(&format!(
                        "environment: creation did not complete ({error}); falling back to \
                         wry's environment -- crash reporting stays ON"
                    ));
                    None
                }
            }
        }
    })
    .as_ref()
    .map(|e| &e.0)
}

/// Whether this process got its OWN hardened WebView2 environment.
///
/// WHY THIS IS REPORTED RATHER THAN LOGGED. When `shared_environment()` fails
/// the builder silently falls back to wry's environment. Since the tunnel
/// work, that fallback KEEPS the argument string (`desired_browser_args()`
/// travels through `with_additional_browser_args` -- see
/// `new_webview_builder`), so the WebRTC policy, DoH and the tunnel proxy
/// survive; what it still loses is the options-level hardening -- Microsoft
/// crash-dump upload comes back on, extensions come back on. The only notice
/// was a `diag`, which compiles to nothing in release; combined with
/// `windows_subsystem = "windows"` there is no console for it to print to
/// either. So in a shipped build the browser could lose that hardening and
/// say nothing at all, while the privacy panel went on reporting the
/// per-tab settings that DID apply.
///
/// Calling this forces environment creation if it has not happened yet, which
/// is harmless: it is memoized, and every webview build calls it anyway.
pub fn hardened_environment() -> SettingState {
    match shared_environment() {
        Some(_) => SettingState::Applied,
        None => SettingState::Failed,
    }
}

pub fn new_webview_builder() -> WebViewBuilder<'static> {
    let builder = match profile_dir() {
        Some(dir) => WebViewBuilder::new_with_web_context(Box::leak(Box::new(WebContext::new(
            Some(dir.to_path_buf()),
        )))),
        None => WebViewBuilder::new(),
    };
    // Our environment if we got one, wry's otherwise. Handing the SAME
    // environment to every webview is what makes the shared user-data folder
    // safe: identical options by construction rather than by everyone
    // remembering to keep them identical.
    //
    // THE FALLBACK CARRIES THE ARGS TOO. It used to drop every one of them
    // -- hardening, DoH, and the tunnel proxy -- which for a user with the
    // tunnel on meant traffic going DIRECT while the UI said Imported: the
    // independent review rated that a blocker, correctly. wry's
    // `additionalBrowserArguments` REPLACES its default and `BROWSER_ARGS`
    // retypes that default verbatim, so passing `desired_browser_args()`
    // here gives wry-created environments the same argument set as ours.
    // Every builder gets the identical string, so the shared-folder
    // identical-options constraint holds in the fallback regime as well.
    // What the fallback still loses -- crash-reporting off, extensions off
    // -- is exactly what `hardened_environment()` reports.
    let builder = match shared_environment() {
        Some(env) => builder.with_environment(env.clone()),
        None => builder.with_additional_browser_args(&desired_browser_args()),
    };
    // WebView2's OWN autofill, off. This is not a hardening nicety -- wry
    // defaults `general_autofill_enabled` to TRUE and applies it
    // unconditionally, so every build until now has had Edge quietly
    // accumulating names, emails, phone numbers and street addresses in the
    // browsing profile. A second credential store, outside the vault, in a
    // browser whose whole claim is that data does not accumulate.
    //
    // Set on the BUILDER rather than through the profile because it is a
    // per-webview setting: it does not touch the environment options, which
    // must stay byte-identical across chrome and content webviews sharing one
    // user-data folder (see the CONSTRAINT above). `harden_privacy` sets the
    // profile-level pair as well, so a future wry that stops applying this
    // one still lands somewhere.
    builder.with_general_autofill_enabled(false)
}

/// Reports a profile left beside the executable by an earlier build.
///
/// MIGRATION DECISION, recorded here because "nothing happened" and "nobody
/// thought about it" look identical in code: an existing profile is LEFT
/// ORPHANED and NAMED. It is not moved, not copied, and not deleted.
///
/// Not migrated: a Chromium profile is a multi-gigabyte tree with lock files
/// and a running engine's handles on it, so a copy that fails halfway leaves a
/// corrupt profile rather than an old one. What is inside is browsing
/// convenience -- cookies, cache, shader blobs -- not user-authored data. The
/// vault, store and bookmarks were never in there and are unaffected, so the
/// standing rule this project applies to the data directory (a silent empty
/// profile next to a full one is indistinguishable from data loss) is answered
/// by the SAYING, not by the moving. What a user loses is being logged in.
///
/// Not deleted: silently removing a directory holding a user's cookies
/// because we decided it was stale is exactly the behaviour a browser sold on
/// leaving less behind should never take unasked.
///
/// The honest limit: `diag` compiles to nothing in a release build, and
/// `windows_subsystem = "windows"` leaves no console for it anyway, so the
/// release binary is silent about this and the project owner's Windows checklist
/// carries the instruction instead. Surfacing it in the chrome UI is the
/// right answer for GA and is a deliberately separate change.
pub fn report_stray_profile() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(stray) = super::stray_profile_dir(&exe) else {
        return;
    };
    if stray.is_dir() {
        diag(&format!(
            "profile: an OLD browsing profile from a previous build is still at {} - \
             it is no longer read or written, nothing was migrated out of it, and it is \
             safe to delete",
            stray.display()
        ));
    }
}

pub fn build_chrome(
    hosts: &Hosts,
    builder: WebViewBuilder<'_>,
    proxy: &EventLoopProxy<UserEvent>,
) -> Result<WebView, wry::Error> {
    let webview = without_default_context_menu(builder).build_as_child(&hosts.window)?;
    // Discarded deliberately: the chrome is our own UI, not web content, and
    // has no TabState to report against. `false` because the chrome webview is
    // never built incognito -- it is the persistent UI, and asking for
    // ephemeral here would be a question about a tab that does not exist.
    let _ = harden_privacy(&webview, false);
    connect_shortcuts(&webview, proxy);
    // Child webviews get no automatic layout; the chrome strip gets its
    // initial bounds here and layout() keeps them current from then on.
    let _ = webview.set_bounds(chrome_rect(&hosts.window, CHROME_HEIGHT_PX));
    // No privacy policy on the chrome webview: it is our own UI, not web
    // content (needs JavaScript, talks IPC).
    arm_translucent_overlay(hosts, &webview);
    Ok(webview)
}

/// Arms the translucent-backdrop lift, and ONLY if both of its legs stand.
///
/// The modal used to cover the window with an opaque chrome because sibling
/// child windows do not composite -- the page behind a modal was genuinely
/// gone, and the solid scrim said so. The lift changes the geometry instead
/// of pretending: during Overlay the content keeps its normal rectangle and
/// keeps rendering, and the CHROME is raised above it with a transparent
/// default background, so the page shows through wherever the chrome paints
/// nothing and the CSS scrim dims it for real.
///
/// Two things must be true before any of that is offered to the stylesheet
/// (`chrome_caps` reports this flag):
///
///  1. The chrome's own child HWND is known. It is captured HERE because
///     this is the one moment it is identifiable without guessing: the
///     chrome is built before any content webview, so the window has exactly
///     one child right now. `EnumChildWindows` recurses into grandchildren
///     (WebView2 builds a small tree), so the walk keeps only DIRECT
///     children.
///  2. The runtime honours a transparent default background
///     (`ICoreWebView2Controller2`, SDK 1.0.774+). On a runtime too old to
///     cast, lifting the chrome would put an OPAQUE sheet over the page --
///     strictly worse than the honest cover.
///
/// If either leg fails the flag stays false, `layout` keeps the legacy
/// zero-rect Overlay, and the UI keeps the solid scrim. Degraded is the old
/// behaviour, never a new lie.
fn arm_translucent_overlay(hosts: &Hosts, webview: &WebView) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Controller2, COREWEBVIEW2_COLOR,
    };
    use windows::core::BOOL;
    use windows::Win32::Foundation::{HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{EnumChildWindows, GetParent};
    use wry::WebViewExtWindows;

    let parent = window_hwnd(hosts);

    // Direct children only, and exactly one expected.
    unsafe extern "system" fn keep_direct(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let out = unsafe { &mut *(lparam.0 as *mut (HWND, Vec<isize>)) };
        if unsafe { GetParent(hwnd) }.is_ok_and(|p| p == out.0) {
            out.1.push(hwnd.0 as isize);
        }
        BOOL(1)
    }
    let mut acc: (HWND, Vec<isize>) = (parent, Vec::new());
    unsafe {
        let _ = EnumChildWindows(
            Some(parent),
            Some(keep_direct),
            LPARAM(&mut acc as *mut _ as isize),
        );
    }
    // Skip a child we created ourselves. Zero never matches a real HWND, so
    // this is inert until the hover readout exists -- which by construction
    // is AFTER this function has run (main.rs arms it post-build_chrome). It
    // is here so that ordering becomes an EXPLICIT invariant rather than an
    // accident of two call sites.
    let readout = READOUT_CHILD.load(std::sync::atomic::Ordering::Relaxed);
    acc.1.retain(|h| *h != readout);
    let &[child] = acc.1.as_slice() else {
        // Zero or several: either the controller has no HWND yet or something
        // else already parented one here. Refuse to guess -- but SAY so: the
        // old silent return here cost real diagnosis time, because the only
        // symptom is a modal that keeps the opaque scrim.
        diag(&format!(
            "translucent overlay: expected exactly ONE direct child of the \
             window at build_chrome time, found {} -- the modal lift is NOT \
             armed and panels keep the opaque scrim. A native child window \
             created before build_chrome is the usual cause.",
            acc.1.len()
        ));
        return;
    };

    let controller = webview.controller();
    let Ok(c2) = windows::core::Interface::cast::<ICoreWebView2Controller2>(&controller) else {
        return;
    };
    let transparent = COREWEBVIEW2_COLOR {
        A: 0,
        R: 0,
        G: 0,
        B: 0,
    };
    if unsafe { c2.SetDefaultBackgroundColor(transparent) }.is_err() {
        return;
    }

    hosts.chrome_child.set(child);
    TRANSLUCENT_OVERLAY.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Set once by `arm_translucent_overlay`; read by `chrome_caps` over IPC and
/// by `layout`. An atomic rather than a field because the IPC layer asks the
/// PLATFORM, not a Hosts it does not hold -- same shape as `split_supported`,
/// which this flag is the dynamic sibling of.
static TRANSLUCENT_OVERLAY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether a modal's backdrop is a LIVE dimmed page rather than an opaque
/// cover. Dynamic: true only after `arm_translucent_overlay` proved both the
/// HWND capture and the transparent background on THIS runtime.
pub fn translucent_overlay_supported() -> bool {
    TRANSLUCENT_OVERLAY.load(std::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// The hover readout
//
// A native child window, bottom-left, showing the target of the link under
// the pointer -- the status bar's one surviving job. Native rather than a
// third webview (a whole engine instance to display one line) or a reserved
// chrome row (permanent height cost for an occasional string).
//
// This is the first native drawing code in the crate, so the conventions are
// set here: the window is created strictly AFTER build_chrome (see
// arm_translucent_overlay's one-child requirement), it never takes input
// (WS_EX_TRANSPARENT and WM_NCHITTEST both say so -- if it consumed a mouse
// move, the webview beneath would stop reporting hover and the readout would
// FREEZE on a link the pointer has left), and every failure leaves
// READOUT_CHILD at zero, which every entry point treats as "the feature is
// off", the same contract chrome_child established.
//
// State is module-level, not Hosts fields, for the same reason as
// TRANSLUCENT_OVERLAY: the WebView2 status-bar callback is a 'static COM
// closure and cannot hold &Hosts. Everything is only ever touched on the UI
// thread; the atomics are for Rust's benefit, not for concurrency.

use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, Ordering};

/// The readout's own child HWND. Zero = never created = feature off.
static READOUT_CHILD: AtomicIsize = AtomicIsize::new(0);
/// The main window's HWND, for GetClientRect from the 'static callback.
static READOUT_PARENT: AtomicIsize = AtomicIsize::new(0);
/// The DPI-scaled HFONT, and the scale it was built for. Rebuilt only when
/// the scale moves; the old font is deleted first (the one leak here that
/// would actually repeat).
static READOUT_FONT: AtomicIsize = AtomicIsize::new(0);
static READOUT_FONT_SCALE: AtomicU64 = AtomicU64::new(0);
/// The window's current scale factor, as f64 bits. Written wherever &Hosts
/// is in hand (arm, layout, set_hover_readout); read by the COM callback,
/// which has no Hosts. One source of truth -- tao's scale_factor(), the same
/// number layout() trusts -- cached, never recomputed from a second API.
static READOUT_SCALE: AtomicU64 = AtomicU64::new(0);
/// True while a modal covers the page (ChromeLayout::Overlay): a readout
/// floating over a modal would describe a link the user can neither see nor
/// click, and it would fight the raised chrome for z-order.
static READOUT_SUPPRESSED: AtomicBool = AtomicBool::new(false);
/// Palette, as Win32 COLORREFs (0x00BBGGRR -- hover_style::colorref does the
/// swap and its tests are what stop these being orange).
static READOUT_FG: AtomicU32 = AtomicU32::new(0);
static READOUT_BG: AtomicU32 = AtomicU32::new(0);
static READOUT_BORDER: AtomicU32 = AtomicU32::new(0);

thread_local! {
    /// What WM_PAINT draws. UI-thread only: the window is created on it and
    /// WM_PAINT is delivered on the creating thread.
    static READOUT_TEXT: RefCell<String> = const { RefCell::new(String::new()) };
}

fn readout_scale() -> f64 {
    let bits = READOUT_SCALE.load(Ordering::Relaxed);
    let scale = f64::from_bits(bits);
    if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    }
}

/// Creates the readout window. Called once from main.rs, strictly after
/// `build_chrome` -- see the comment there and in arm_translucent_overlay.
pub fn arm_hover_readout(hosts: &Hosts, scheme: crate::prefs::ChromeScheme) {
    use windows::core::w;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, LoadCursorW, RegisterClassW, IDC_ARROW, WNDCLASSW, WS_CHILD,
        WS_CLIPSIBLINGS, WS_EX_TRANSPARENT,
    };

    set_hover_readout_scheme(hosts, scheme);
    READOUT_SCALE.store(hosts.window.scale_factor().to_bits(), Ordering::Relaxed);

    let Ok(module) = (unsafe { GetModuleHandleW(None) }) else {
        diag("hover readout: GetModuleHandleW failed; the readout is OFF");
        return;
    };

    // hbrBackground stays null and WM_ERASEBKGND answers "done": WM_PAINT
    // fills the whole client area itself, so there is no erase-then-draw
    // flash on a window that repaints on every hover.
    let class = WNDCLASSW {
        lpfnWndProc: Some(readout_proc),
        hInstance: module.into(),
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
        lpszClassName: w!("PatanyxHoverReadout"),
        ..Default::default()
    };
    // A zero atom is failure -- unless the class already exists, which cannot
    // happen here (arm runs once per process), so zero is simply failure.
    if unsafe { RegisterClassW(&class) } == 0 {
        diag("hover readout: RegisterClassW failed; the readout is OFF");
        return;
    }

    // WS_EX_TRANSPARENT: excluded from hit testing AND painted after its
    // siblings -- the belt to WM_NCHITTEST's braces. WS_CLIPSIBLINGS so a
    // repainting neighbour does not scribble through it. Created HIDDEN (no
    // WS_VISIBLE): nothing is hovered yet.
    let parent = window_hwnd(hosts);
    let created = unsafe {
        CreateWindowExW(
            WS_EX_TRANSPARENT,
            w!("PatanyxHoverReadout"),
            w!(""),
            WS_CHILD | WS_CLIPSIBLINGS,
            0,
            0,
            0,
            0,
            Some(parent),
            None,
            Some(module.into()),
            None,
        )
    };
    let Ok(hwnd) = created else {
        // Fail-safe: READOUT_CHILD stays 0 and every entry point is a no-op.
        // The browser is otherwise unaffected.
        diag("hover readout: CreateWindowExW failed; the readout is OFF");
        return;
    };
    READOUT_PARENT.store(parent.0 as isize, Ordering::Relaxed);
    READOUT_CHILD.store(hwnd.0 as isize, Ordering::Relaxed);
    rebuild_readout_font();
    // No destruction path on purpose: the readout is a child of the tao
    // window and dies with it at process exit. The one resource that MUST be
    // freed on a repeating basis is the old HFONT on a DPI change, and
    // rebuild_readout_font does that before replacing it.
}

/// Re-colours the readout. The single runtime scheme-change point is the
/// `chrome_scheme_set` IPC arm, which calls this on both backends.
pub fn set_hover_readout_scheme(_hosts: &Hosts, scheme: crate::prefs::ChromeScheme) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::InvalidateRect;

    let p = crate::hover_style::palette(scheme);
    READOUT_FG.store(crate::hover_style::colorref(p.fg), Ordering::Relaxed);
    READOUT_BG.store(crate::hover_style::colorref(p.bg), Ordering::Relaxed);
    READOUT_BORDER.store(crate::hover_style::colorref(p.border), Ordering::Relaxed);

    let raw = READOUT_CHILD.load(Ordering::Relaxed);
    if raw != 0 {
        let _ = unsafe { InvalidateRect(Some(HWND(raw as _)), None, false) };
    }
}

/// Shows `text`, or hides the readout for `None`. `None` means HIDE, never
/// "draw empty" (hover.rs documents the contract).
pub fn set_hover_readout(hosts: &Hosts, text: Option<&str>) {
    READOUT_SCALE.store(hosts.window.scale_factor().to_bits(), Ordering::Relaxed);
    readout_apply(text);
}

/// (visible, text) for the smoke gate; not used by any UI path.
pub fn hover_readout_state(_hosts: &Hosts) -> (bool, String) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::IsWindowVisible;

    let raw = READOUT_CHILD.load(Ordering::Relaxed);
    if raw == 0 {
        return (false, String::new());
    }
    let visible = unsafe { IsWindowVisible(HWND(raw as _)) }.as_bool();
    (visible, READOUT_TEXT.with(|t| t.borrow().clone()))
}

/// The `&Hosts`-free half, callable from the 'static status-bar callback.
fn readout_apply(text: Option<&str>) {
    use windows::Win32::Foundation::{HWND, RECT, SIZE};
    use windows::Win32::Graphics::Gdi::{
        GetDC, GetTextExtentPoint32W, InvalidateRect, ReleaseDC, SelectObject, HFONT, HGDIOBJ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetClientRect, SetWindowPos, ShowWindow, HWND_TOP, SWP_NOACTIVATE, SWP_SHOWWINDOW, SW_HIDE,
    };

    let raw = READOUT_CHILD.load(Ordering::Relaxed);
    if raw == 0 {
        return; // Never created: the feature is off.
    }
    let hwnd = HWND(raw as _);

    let suppressed = READOUT_SUPPRESSED.load(Ordering::Relaxed);
    let Some(text) = text.filter(|_| !suppressed) else {
        let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
        return;
    };

    READOUT_TEXT.with(|t| {
        let mut t = t.borrow_mut();
        t.clear();
        t.push_str(text);
    });
    rebuild_readout_font(); // No-op unless the scale moved.

    // Measure with the REAL font selected into a DC. Guessing an average
    // character width is how a readout ends up clipped at 150% DPI.
    let wide: Vec<u16> = text.encode_utf16().collect();
    let (text_w, line_h) = unsafe {
        let hdc = GetDC(Some(hwnd));
        let font = READOUT_FONT.load(Ordering::Relaxed);
        let previous = if font != 0 {
            SelectObject(hdc, HGDIOBJ(HFONT(font as _).0))
        } else {
            HGDIOBJ::default()
        };
        let mut size = SIZE::default();
        let ok = GetTextExtentPoint32W(hdc, &wide, &mut size).as_bool();
        if !previous.is_invalid() {
            SelectObject(hdc, previous);
        }
        ReleaseDC(Some(hwnd), hdc);
        if ok {
            (size.cx, size.cy)
        } else {
            // A failed measure still shows SOMETHING readable rather than
            // nothing: a generous guess, clamped by readout_rect anyway.
            (text.len() as i32 * 8, 16)
        }
    };

    // Physical pixels throughout: GetClientRect and SetWindowPos both speak
    // client-area physical px, and the font was built for the physical scale,
    // so no logical conversion belongs anywhere in this path.
    let parent = HWND(READOUT_PARENT.load(Ordering::Relaxed) as _);
    let mut client = RECT::default();
    if unsafe { GetClientRect(parent, &mut client) }.is_err() {
        let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
        return;
    }
    let (x, y, w, h) =
        crate::hover_style::readout_rect(client.right, client.bottom, text_w, line_h);

    // HWND_TOP on every show: content webviews are created AFTER this window
    // (arm runs before the first tab), and siblings later in creation order
    // draw over earlier ones -- the same fact layout() and set_chrome_z are
    // built on. Without the raise the page simply covers the readout.
    let _ = unsafe {
        SetWindowPos(
            hwnd,
            Some(HWND_TOP),
            x,
            y,
            w,
            h,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )
    };
    let _ = unsafe { InvalidateRect(Some(hwnd), None, false) };
}

/// Builds (or rebuilds) the readout font for the current scale.
fn rebuild_readout_font() {
    use windows::Win32::Graphics::Gdi::{
        CreateFontIndirectW, DeleteObject, HFONT, HGDIOBJ, CLEARTYPE_QUALITY, FW_NORMAL, LOGFONTW,
    };

    let scale = readout_scale();
    let wanted = scale.to_bits();
    if READOUT_FONT.load(Ordering::Relaxed) != 0
        && READOUT_FONT_SCALE.load(Ordering::Relaxed) == wanted
    {
        return;
    }

    let mut lf = LOGFONTW {
        // Negative = character height; positive would silently mean CELL
        // height and oversize the font. hover_style's tests pin the sign.
        lfHeight: crate::hover_style::font_height_px(scale),
        lfWeight: FW_NORMAL.0 as i32,
        lfQuality: CLEARTYPE_QUALITY,
        ..Default::default()
    };
    for (slot, unit) in lf.lfFaceName.iter_mut().zip("Segoe UI\0".encode_utf16()) {
        *slot = unit;
    }

    let font = unsafe { CreateFontIndirectW(&lf) };
    if font.is_invalid() {
        // Keep whatever font is current (possibly none: DrawTextW then uses
        // the DC's default -- wrong size but legible, which beats invisible).
        diag("hover readout: CreateFontIndirectW failed; keeping the previous font");
        return;
    }
    let old = READOUT_FONT.swap(font.0 as isize, Ordering::Relaxed);
    READOUT_FONT_SCALE.store(wanted, Ordering::Relaxed);
    if old != 0 {
        let _ = unsafe { DeleteObject(HGDIOBJ(HFONT(old as _).0)) };
    }
}

/// The readout's window procedure. Three messages, everything else deferred.
unsafe extern "system" fn readout_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::LRESULT;
    use windows::Win32::UI::WindowsAndMessaging::{
        DefWindowProcW, HTTRANSPARENT, WM_ERASEBKGND, WM_NCHITTEST, WM_PAINT,
    };

    match msg {
        // Never eat a click and never eat a MOUSEMOVE: if this window
        // consumed motion, the webview beneath would stop reporting hover,
        // StatusBarTextChanged would never fire again, and the readout would
        // freeze showing a link the pointer has long left.
        WM_NCHITTEST => LRESULT(HTTRANSPARENT as isize),
        // WM_PAINT fills the entire client area; claiming the erase is done
        // avoids a background flash between the two.
        WM_ERASEBKGND => LRESULT(1),
        WM_PAINT => {
            readout_paint(hwnd);
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn readout_paint(hwnd: windows::Win32::Foundation::HWND) {
    use windows::Win32::Foundation::{COLORREF, RECT};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect, SelectObject,
        SetBkMode, SetTextColor, HFONT, HGDIOBJ, DT_LEFT, DT_NOPREFIX, DT_PATH_ELLIPSIS,
        DT_SINGLELINE, DT_VCENTER, PAINTSTRUCT, TRANSPARENT,
    };
    use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        let mut rect = RECT::default();
        if GetClientRect(hwnd, &mut rect).is_ok() {
            // Background.
            let bg = CreateSolidBrush(COLORREF(READOUT_BG.load(Ordering::Relaxed)));
            FillRect(hdc, &rect, bg);
            let _ = DeleteObject(HGDIOBJ(bg.0));

            // A 1px hairline on the two exposed edges (the readout hugs the
            // window's left and bottom, so only top and right meet the page).
            let ln = CreateSolidBrush(COLORREF(READOUT_BORDER.load(Ordering::Relaxed)));
            let top = RECT {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.top + 1,
            };
            let right = RECT {
                left: rect.right - 1,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
            };
            FillRect(hdc, &top, ln);
            FillRect(hdc, &right, ln);
            let _ = DeleteObject(HGDIOBJ(ln.0));

            // Text. DT_NOPREFIX carries real weight: without it DrawTextW
            // eats `&` as an accelerator prefix, and a URL's query string is
            // full of them -- the Win32 mirror of GTK's "set_text, never
            // set_markup" (hover.rs pins the ampersand contract).
            // DT_PATH_ELLIPSIS elides mid-path, matching elide_middle's
            // intent, for windows narrower than the pre-elided 110 chars.
            let font = READOUT_FONT.load(Ordering::Relaxed);
            let previous = if font != 0 {
                SelectObject(hdc, HGDIOBJ(HFONT(font as _).0))
            } else {
                HGDIOBJ::default()
            };
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLORREF(READOUT_FG.load(Ordering::Relaxed)));
            let mut text_rect = RECT {
                left: rect.left + 8,
                top: rect.top,
                right: (rect.right - 8).max(rect.left + 8),
                bottom: rect.bottom,
            };
            READOUT_TEXT.with(|t| {
                let mut wide: Vec<u16> = t.borrow().encode_utf16().collect();
                DrawTextW(
                    hdc,
                    &mut wide,
                    &mut text_rect,
                    DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_NOPREFIX | DT_PATH_ELLIPSIS,
                );
            });
            if !previous.is_invalid() {
                SelectObject(hdc, previous);
            }
        }
        let _ = EndPaint(hwnd, &ps);
    }
}

/// Feeds the readout from WebView2's status-bar text.
///
/// The status bubble also carries engine chatter -- "Waiting for host...",
/// "Transferring data..." -- which is NOT a destination. Nothing here filters
/// that: `hover::readout_for` refuses anything that is not http(s), so those
/// strings HIDE the readout rather than being rendered as somewhere to go.
/// That is a deliberate difference from the Linux backend, which reads the
/// link URI itself; this side errs toward showing less.
///
/// Returns false (and the tab reports no link targets) when the readout was
/// never created or the runtime predates `ICoreWebView2_12` (SDK 1.0.1108).
fn connect_hover_readout(webview: &WebView) -> bool {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2_12;
    use webview2_com::{
        NavigationStartingEventHandler, StatusBarTextChangedEventHandler,
    };
    use windows::core::Interface as _;
    use wry::WebViewExtWindows;

    if READOUT_CHILD.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let core = webview.webview();

    // THE STATUS BAR MUST BE ON, OR THE EVENT BELOW NEVER FIRES.
    //
    // `StatusBarText` IS the status bar: with `IsStatusBarEnabled` false the
    // engine has no status text to report and raises no change event. wry
    // turns it off for every webview it builds
    // (wry-0.55.1/src/webview2/mod.rs:570), which it is right to do for an
    // embedder that does not want Edge's own bubble -- but it left the first
    // build of this feature registered against an event that could not
    // happen. The handler was correct, the interface was correct, and
    // nothing ever arrived. Registering an event without checking what
    // enables it is the same class of mistake as reading a binding without
    // compiling against it.
    //
    // Turned on HERE rather than through wry's builder because wry exposes
    // no setter for it, and after `build_as_child` rather than before,
    // because wry applies its own settings during construction and would
    // overwrite this.
    match unsafe { core.Settings() } {
        Ok(settings) => {
            if let Err(error) = unsafe { settings.SetIsStatusBarEnabled(true) } {
                diag(&format!(
                    "hover readout: SetIsStatusBarEnabled FAILED ({error}); this tab \
                     reports no link targets"
                ));
                return false;
            }
        }
        Err(error) => {
            diag(&format!(
                "hover readout: Settings() FAILED ({error}); this tab reports no link targets"
            ));
            return false;
        }
    }

    let Ok(v12) = core.cast::<ICoreWebView2_12>() else {
        diag("hover readout: no ICoreWebView2_12 on this runtime; this tab reports no link targets");
        return false;
    };

    // Clicking the hovered link navigates; the readout must not survive into
    // the new document. A second NavigationStarting handler beside
    // connect_navigation_events' is ordinary COM multi-dispatch; Cancel is
    // never touched here.
    let mut nav_token = Default::default();
    let nav_ok = unsafe {
        core.add_NavigationStarting(
            &NavigationStartingEventHandler::create(Box::new(move |_sender, _args| {
                readout_apply(None);
                Ok(())
            })),
            &mut nav_token,
        )
    }
    .is_ok();

    let reader = v12.clone();
    let mut token = Default::default();
    let status_ok = unsafe {
        v12.add_StatusBarTextChanged(
            &StatusBarTextChangedEventHandler::create(Box::new(move |_sender, _args| {
                let mut raw = windows::core::PWSTR::null();
                let status = reader
                    .StatusBarText(&mut raw)
                    .ok()
                    .map(|()| webview2_com::take_pwstr(raw))
                    .unwrap_or_default();
                readout_apply(crate::hover::readout_for(&status).as_deref());
                Ok(())
            })),
            &mut token,
        )
    }
    .is_ok();

    nav_ok && status_ok
}

/// Builds a content webview under `policy`. The policy is a construction
/// parameter because `ephemeral` and the initial JavaScript setting are
/// fixed at creation time (the WebView2 profile and the script-enabled flag
/// are set before the first navigation; quarantine depends on it).
/// Password-form detection and fill, injected into every content tab's own
/// document only -- `with_initialization_script`'s default is main-frame-only
/// (wry 0.55.1, confirmed against its source), and the script repeats the
/// same check itself as cheap defence in depth against that default ever
/// changing out from under this file.
///
/// This is the first script this codebase has ever injected into content.
/// The trust boundary this crosses is real and deliberately narrow: the
/// script can post a form's own values UP (received by
/// `connect_content_messages` below, never evaluated as anything but data)
/// and accept a fill DOWN (`fill_credential`), and nothing else. There is no
/// message shape that reads a page's DOM back out on demand, and no shape
/// this side will act on besides the two named in the script's own header.
const CONTENT_AUTOFILL_SCRIPT: &str = include_str!("../content_scripts/autofill.js");

pub fn build_content(
    hosts: &Hosts,
    builder: WebViewBuilder<'_>,
    policy: &TabPolicy,
    proxy: &EventLoopProxy<UserEvent>,
    url: &str,
    malicious_override: Rc<RefCell<std::collections::BTreeSet<String>>>,
    id: u64,
    permissions: crate::state::PermissionBook,
) -> Result<(WebView, TabView), wry::Error> {
    // ENGINE-OWNED ZOOM HOTKEYS, on content tabs only.
    //
    // Measured 2026-07-28: WebView2 never delivers keypad keys to
    // `AcceleratorKeyPressed` -- a diagnostic build logged every accelerator
    // event while Ctrl was held and the keypad produced none at all, while the
    // main row produced two each. Nothing in this process can intercept a key
    // the engine keeps: a message hook saw nothing either, because those
    // messages never enter our message queue.
    //
    // So stop fighting it. Chromium already knows the keypad, and Ctrl+scroll
    // with it. The two paths do not collide: our handler consumes the main row
    // and marks it handled, so the engine only ever acts on what we could not
    // see. Both converge on ZoomFactorChanged, which is what keeps the chip
    // honest whichever one did the work.
    //
    // Purely local input handling -- it reads keystrokes the engine already
    // has and changes a scale factor. Nothing is sent anywhere.
    //
    // Deliberately NOT on the chrome webview: the chrome is our own UI and
    // zooming it would resize the toolbar rather than the page.
    let builder = builder.with_hotkeys_zoom(true);
    let builder = without_default_context_menu(builder);
    // Incognito = an in-memory InPrivate-style profile: site state dies
    // with the controller and never reaches the on-disk profile.
    let builder = if policy.ephemeral {
        builder.with_incognito(true)
    } else {
        builder
    };
    // RESOLVED (the signature was previously guessed at): wry 0.55.1's
    // `with_javascript_disabled` is PARAMETERLESS, so it is called only when
    // JavaScript is meant to be off. The tree cross-compiles, which is what
    // settles it. Left as a comment rather than deleted because the shape
    // below reads like a bool was intended and is not.
    //
    // This is a BUILDER-time setting and applies to the tab from creation.
    // Later changes go through `apply_policy`, which asks the engine and
    // records whether it agreed -- see `SettingState`.
    let builder = if !policy.javascript {
        builder.with_javascript_disabled()
    } else {
        builder
    };
    // Registered regardless of `policy.javascript`: a quarantine tab already
    // disables the setting the ENGINE checks for the page's own scripts, and
    // an initialization script queued before construction is inert on a tab
    // where script is off. No separate gate needed here.
    let builder = builder.with_initialization_script(CONTENT_AUTOFILL_SCRIPT);
    // GPC's navigator.globalPrivacyControl, presented the same registered
    // document-start way as autofill. wry keeps initialization scripts in a
    // Vec, so this ADDS to autofill rather than replacing it.
    let builder = builder.with_initialization_script(privacy::GPC_SCRIPT);
    let webview = builder.build_as_child(&hosts.window)?;
    let hardening = harden_privacy(&webview, policy.ephemeral);
    // Before this tab can navigate anywhere: a new session must not inherit
    // the last one's logins. No-op after the first content webview.
    clear_cookies_for_new_session(&webview);
    connect_shortcuts(&webview, proxy);
    // Tabs start hidden; AppState activates one via show_tab + layout. A
    // fresh WebView2 child defaults to visible, so hide it before it can
    // paint over the chrome strip or another tab.
    let _ = webview.set_visible(false);
    let _ = webview.set_bounds(content_rect(&hosts.window, CHROME_HEIGHT_PX));

    let state = Rc::new(RefCell::new(TabState::new(policy)));
    {
        // What the runtime accepted, recorded before anything can present it
        // as a protection.
        let mut st = state.borrow_mut();
        st.smartscreen_off = hardening.smartscreen_off;
        st.tracking_prevention = hardening.tracking_prevention;
        st.autofill_off = hardening.autofill_off;
        st.ephemeral_confirmed = hardening.ephemeral;
        // The init-script itself has no separate confirm signal (wry's
        // builder-time call cannot fail on its own; only construction as a
        // whole can, which already surfaced via `build_as_child`'s `?`
        // above). What CAN be confirmed directly, and is what actually gates
        // the fill/save affordance, is whether the message channel back from
        // that script registered.
        // Right-click menu. Its own registration, because a tab whose menu
        // failed to register is not a tab whose autofill failed.
        connect_context_menu(&webview, proxy, window_hwnd(hosts));
        st.content_script_registered = if connect_content_messages(&webview, proxy, id) {
            SettingState::Applied
        } else {
            SettingState::Failed
        };
        // Deny-by-default permissions. Its own registration line, because a
        // tab whose permission handler failed is not a tab whose autofill
        // failed, and the panel reports them separately.
        st.permissions_registered =
            if connect_permission_policy(&webview, permissions.clone(), id) {
                SettingState::Applied
            } else {
                SettingState::Failed
            };
        // The hover readout's status-bar hook. Content tabs only -- the
        // chrome is our own UI and a hover in the toolbar is not a
        // destination. Failure diags inside and the tab simply reports no
        // link targets; nothing else about the tab is affected.
        let _ = connect_hover_readout(&webview);
    }
    connect_request_interception(&webview, state.clone(), malicious_override);
    connect_navigation_events(&webview, state.clone(), proxy);
    connect_cert_errors(&webview, state.clone());
    // Fingerprint noise. Registered on the raw ICoreWebView2 rather than the
    // wry builder like autofill and GPC above, because this one needs ALL
    // FRAMES -- see install_divergence_script. Before the deferred load_url
    // below for the same reason the handlers are: the first document must
    // not be created before the registration lands.
    install_divergence_script(&webview, policy.ephemeral);
    // The first navigation happens HERE, not on the builder, and the
    // ordering is the whole point: wry issues `Navigate` inside
    // `build_as_child` when the builder carries a url, which is before any
    // of the three handlers above exist. Every tab's first document load
    // therefore raced the filter -- unblocked, unledgered, unfrozen -- on a
    // backend whose only interception mechanism is that filter. Building
    // blank and navigating after registration closes it.
    //
    // The deferred load now passes through wry's NavigationStarting, i.e.
    // `is_allowed_content_url`, which every legitimate initial URL already
    // satisfies (about:blank is allowed explicitly, and the rest arrive
    // pre-validated by the same predicate). Strictly more restrictive, in
    // the direction the allowlist already intended.
    if let Err(error) = webview.load_url(url) {
        diag(&format!("build: initial navigation to {url} failed ({error})"));
    }
    Ok((webview, TabView { state }))
}

/// Registers the Fingerprint Divergence script for every document this
/// tab will create, ALL frames included.
///
/// Raw `ICoreWebView2::AddScriptToExecuteOnDocumentCreated`, the same escape
/// hatch `connect_content_messages` below uses -- deliberately NOT wry's
/// `with_initialization_script`, which is main-frame-only in wry 0.55.1
/// (confirmed against its source, see CONTENT_AUTOFILL_SCRIPT's doc), and
/// fingerprinting scripts routinely run in third-party iframes. NEVER
/// register this script through both mechanisms: the script's own marker
/// makes a second run a no-op (the divergence gate pins that), but one
/// registration is the design, not "two and a guard".
///
/// Ordering: called before `build_content`'s deferred `load_url`. The
/// AddScript call and the later Navigate marshal in order over the same COM
/// channel, so the first document cannot be created before the registration
/// lands; the hardware checklist's iframe test is what confirms this on a
/// real machine.
///
/// The completion callback is a genuine engine ack, and a refusal goes to
/// the diag ring. It is deliberately NOT a TabState/engine-confirmed row:
/// no panel copy claims this is on for any particular tab (the privacy
/// toggle describes the pref, "new tabs only"), so there is no per-tab
/// claim to keep honest -- and the engine-confirmed vocabulary has no honest word
/// for the unix side, where the script is active but WebKitGTK offers no
/// readback (renderEngineConfirmed's own comment forbids growing special
/// cases). Same no-row shape as GPC_SCRIPT.
fn install_divergence_script(webview: &WebView, ephemeral: bool) {
    use webview2_com::AddScriptToExecuteOnDocumentCreatedCompletedHandler;
    use wry::WebViewExtWindows;

    // None = pref off, or OS randomness failed: register nothing, which is
    // the honest posture on both counts (no script, no claim).
    let Some(source) = privacy::divergence_script(ephemeral) else {
        return;
    };
    let core = webview.webview();
    let source_wide: Vec<u16> = source.encode_utf16().chain(std::iter::once(0)).collect();
    let handler = AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(
        |hr, _script_id| {
            if hr.is_err() {
                diag(
                    "divergence: registration REFUSED by the engine; \
                     documents in this tab read clean fingerprints",
                );
            }
            Ok(())
        },
    ));
    let result = unsafe {
        core.AddScriptToExecuteOnDocumentCreated(
            windows::core::PCWSTR(source_wide.as_ptr()),
            &handler,
        )
    };
    if result.is_err() {
        diag("divergence: AddScriptToExecuteOnDocumentCreated call failed; this tab reads clean fingerprints");
    }
}

/// Receives what `CONTENT_AUTOFILL_SCRIPT` posts UP from this tab.
///
/// Registered directly on the raw `ICoreWebView2`, the same escape hatch
/// `connect_navigation_events` already uses -- NOT through wry's
/// `with_ipc_handler`, which bundles `window.ipc` injection together with
/// message receipt and would put a second `window.ipc` on content, breaking
/// the "chrome only" invariant `state.rs` documents for `evaluate_script`.
/// The content side needs no shim either way: `window.chrome.webview.
/// postMessage` is native to every WebView2 document regardless of what this
/// process registers.
///
/// Returns whether registration itself succeeded, which is what
/// `content_script_registered` reports -- not whether any message has
/// arrived yet, which most tabs (no login form, nothing submitted) will
/// never see and must not be reported as a failure.
fn connect_content_messages(webview: &WebView, proxy: &EventLoopProxy<UserEvent>, id: u64) -> bool {
    use webview2_com::{take_pwstr, WebMessageReceivedEventHandler};
    use windows::core::PWSTR;
    use wry::WebViewExtWindows;

    let proxy = proxy.clone();
    let core = webview.webview();
    let mut token = Default::default();
    let result = unsafe {
        core.add_WebMessageReceived(
            &WebMessageReceivedEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                // The message was POSTED AS A STRING (the content script
                // calls `postMessage(JSON.stringify(...))`), so this is the
                // matching accessor -- `WebMessageAsJson` would return that
                // string double-JSON-encoded, quoted and escaped, which is
                // not what `serde_json::from_str` below expects.
                let mut raw = PWSTR::null();
                if args.TryGetWebMessageAsString(&mut raw).is_err() {
                    return Ok(());
                }
                let text = take_pwstr(raw);
                let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) else {
                    return Ok(());
                };
                // The ONE message shape this side acts on, named in the
                // script's own header comment. Anything else -- a future
                // script version, a malformed frame -- is silently ignored,
                // not an error: content is untrusted input, and a parse
                // failure here must never do anything but nothing.
                if msg.get("kind").and_then(|v| v.as_str()) != Some("login_submit") {
                    return Ok(());
                }
                let origin = msg.get("origin").and_then(|v| v.as_str()).unwrap_or("");
                let username = msg.get("username").and_then(|v| v.as_str()).unwrap_or("");
                let password = msg.get("password").and_then(|v| v.as_str()).unwrap_or("");
                if password.is_empty() {
                    return Ok(());
                }
                let _ = proxy.send_event(UserEvent::LoginSubmitted {
                    tab_id: id,
                    origin: origin.to_string(),
                    username: username.to_string(),
                    password: password.to_string(),
                });
                Ok(())
            })),
            &mut token,
        )
    };
    if let Err(error) = &result {
        diag(&format!(
            "autofill: add_WebMessageReceived FAILED for tab {id} ({error}); this tab cannot offer to save or fill a credential"
        ));
    }
    result.is_ok()
}

/// Fills a stored credential into the CURRENTLY LOADED document of `webview`,
/// on explicit user action only -- the caller (`ipc.rs`'s `cred_autofill_
/// fill`) has already re-verified the credential's origin matches this tab's
/// tracked URL at the moment of the click, not merely at the moment the
/// offer was rendered.
///
/// One-way by construction: this posts a JSON OBJECT (`PostWebMessageAsJson`,
/// not `AsString`), so the content script's handler receives `event.data` as
/// a real object with no `JSON.parse` on its side -- and that handler, per
/// its own file, has no code path that reads a value back out in response.
pub fn fill_credential(webview: &WebView, username: &str, password: &str) -> bool {
    use windows::core::{HSTRING, PCWSTR};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let payload = serde_json::json!({
        "kind": "fill_credential",
        "username": username,
        "password": password,
    });
    let text = match serde_json::to_string(&payload) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let hstring = HSTRING::from(text);
    unsafe { core.PostWebMessageAsJson(PCWSTR(hstring.as_ptr())) }.is_ok()
}

/// Deny-by-default site permissions for one content tab.
///
/// Registered on the raw `ICoreWebView2`, the same escape hatch
/// `connect_content_messages` uses. Returns whether registration succeeded, so
/// the tab can report "not in force" honestly rather than the panel implying a
/// protection this tab never received.
///
/// THREE INTERFACES, THREE METHODS, and they are not interchangeable. Measured
/// against the pinned webview2-com-sys 0.38.2 bindings:
///   `ICoreWebView2PermissionRequestedEventArgs`  -> PermissionKind, Uri, SetState
///   `ICoreWebView2PermissionRequestedEventArgs2` -> SetHandled
///   `ICoreWebView2PermissionRequestedEventArgs3` -> SetSavesInProfile
/// A draft of this called SetSavesInProfile on Args2 and SetHandled on the
/// base, which does not compile.
///
/// SetSavesInProfile(false) IS WHAT MAKES "SESSION ONLY" TRUE. WebView2
/// persists permission decisions into the profile by default, across restarts.
/// Without that call an Allow would outlive the browser while this process's
/// own table forgot it, and the About page's promise that allowed sites reset
/// on close would be false. So if the Args3 cast fails -- an older runtime --
/// this DENIES and reports the tab unsupported rather than applying an Allow
/// it cannot promise to forget. Refusing to offer a control is honest; offering
/// one that silently persists is not.
///
/// Every error path ends in deny-and-handled. A failed Uri read or a failed
/// PermissionKind read must not fall through to the engine default, which
/// would prompt or allow.
fn connect_permission_policy(webview: &WebView, book: crate::state::PermissionBook, id: u64) -> bool {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2PermissionRequestedEventArgs2, ICoreWebView2PermissionRequestedEventArgs3,
        COREWEBVIEW2_PERMISSION_KIND_CAMERA, COREWEBVIEW2_PERMISSION_KIND_GEOLOCATION,
        COREWEBVIEW2_PERMISSION_KIND_MICROPHONE, COREWEBVIEW2_PERMISSION_KIND_NOTIFICATIONS,
        COREWEBVIEW2_PERMISSION_KIND_UNKNOWN_PERMISSION,
        COREWEBVIEW2_PERMISSION_STATE_ALLOW, COREWEBVIEW2_PERMISSION_STATE_DENY,
    };
    use webview2_com::{take_pwstr, PermissionRequestedEventHandler};
    use windows::core::{Interface, PWSTR};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let mut token = Default::default();
    let result = unsafe {
        core.add_PermissionRequested(
            &PermissionRequestedEventHandler::create(Box::new(move |sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };

                // Out-of-scope kinds are left entirely alone: not handled, not
                // recorded, engine default applies. The UI must never imply a
                // control this does not have.
                // Out-parameter style, like every getter on these interfaces.
                let mut raw_kind = COREWEBVIEW2_PERMISSION_KIND_UNKNOWN_PERMISSION;
                if args.PermissionKind(&mut raw_kind).is_err() {
                    // A kind we cannot even read is one we cannot reason about.
                    deny_and_handle(&args);
                    return Ok(());
                }
                let kind = if raw_kind == COREWEBVIEW2_PERMISSION_KIND_CAMERA {
                    crate::state::PermKind::Camera
                } else if raw_kind == COREWEBVIEW2_PERMISSION_KIND_MICROPHONE {
                    crate::state::PermKind::Microphone
                } else if raw_kind == COREWEBVIEW2_PERMISSION_KIND_GEOLOCATION {
                    crate::state::PermKind::Geolocation
                } else if raw_kind == COREWEBVIEW2_PERMISSION_KIND_NOTIFICATIONS {
                    crate::state::PermKind::Notifications
                } else {
                    // Out of scope: not handled, not recorded, engine default.
                    return Ok(());
                };

                // Stop the engine remembering this decision. Checked BEFORE
                // any Allow can be applied.
                let persistence_off = args
                    .cast::<ICoreWebView2PermissionRequestedEventArgs3>()
                    .ok()
                    .and_then(|a3| a3.SetSavesInProfile(false).ok())
                    .is_some();
                if !persistence_off {
                    deny_and_handle(&args);
                    return Ok(());
                }

                let requesting = {
                    let mut raw = PWSTR::null();
                    if args.Uri(&mut raw).is_err() {
                        deny_and_handle(&args);
                        return Ok(());
                    }
                    take_pwstr(raw)
                };
                // The tab's own address, for attributing a frame's request to
                // the tab it happened under. Unreadable is not fatal: the
                // decision below keys on the REQUESTING origin either way.
                let top = sender
                    .and_then(|s| {
                        let mut raw = PWSTR::null();
                        s.Source(&mut raw).ok().map(|()| take_pwstr(raw))
                    })
                    .unwrap_or_default();

                let allow = book.decide(&requesting, &top, kind);
                let state = if allow {
                    COREWEBVIEW2_PERMISSION_STATE_ALLOW
                } else {
                    COREWEBVIEW2_PERMISSION_STATE_DENY
                };
                if args.SetState(state).is_err() {
                    deny_and_handle(&args);
                    return Ok(());
                }
                // Handled last: an unhandled event falls back to the engine's
                // own prompt, which is the thing this exists to replace.
                if let Ok(a2) = args.cast::<ICoreWebView2PermissionRequestedEventArgs2>() {
                    let _ = a2.SetHandled(true);
                }
                Ok(())
            })),
            &mut token,
        )
    };
    if let Err(error) = &result {
        diag(&format!(
            "permissions: add_PermissionRequested FAILED for tab {id} ({error}); this tab falls back to the engine's own prompts"
        ));
    }
    result.is_ok()
}

/// Resets every permission decision WebView2 has persisted in this profile.
///
/// WHY THIS EXISTS AT ALL. WebView2 saves permission decisions into the
/// profile by default, so a user who allowed a site's camera before this
/// feature shipped still has that Allow on disk. Worse than merely stale: a
/// stored decision means the engine may never RAISE PermissionRequested for
/// that origin again, so the handler above would never see it and the site
/// would keep its access while the panel showed nothing. The upgrade would
/// silently grandfather in exactly what this feature exists to prevent.
///
/// SO THIS RUNS ON EXIT (a deliberate decision): when the browser closes, every
/// decision the engine persisted goes back to default, which is what makes
/// "allowed sites reset when PATANYX closes" true of the ENGINE and not merely
/// of this process's own table.
///
/// It also runs at startup, and that is not a duplicate. Exit-time clearing
/// cannot run if the browser is killed, crashes, or loses power, and a
/// persisted Allow surviving a crash is exactly the case that would silently
/// grandfather access back in. Startup is the backstop; exit is the promise.
/// Both are cheap: the list is empty for anyone who has only ever run a build
/// carrying the handler above, and the sweep is idempotent.
///
/// It resets what the ENGINE remembers, never this process's session table.
///
/// Best-effort. `ICoreWebView2Profile4` is a newer interface; on an older
/// runtime this cannot run, and the request handler already refuses to apply
/// an Allow it cannot keep out of the profile, so the session-only promise
/// still holds. Failure is diagnosed, never fatal.
pub fn clear_persisted_permissions(webview: &WebView) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Profile4, ICoreWebView2_13, COREWEBVIEW2_PERMISSION_STATE_DEFAULT,
    };
    use webview2_com::{
        take_pwstr, GetNonDefaultPermissionSettingsCompletedHandler,
        SetPermissionStateCompletedHandler,
    };
    use windows::core::{Interface, HSTRING, PCWSTR, PWSTR};
    use wry::WebViewExtWindows;

    unsafe {
        let core = webview.webview();
        let Ok(v13) = core.cast::<ICoreWebView2_13>() else {
            diag("permissions: no ICoreWebView2_13; cannot clear persisted decisions");
            return;
        };
        let Ok(profile) = v13.Profile() else {
            return;
        };
        let Ok(p4) = profile.cast::<ICoreWebView2Profile4>() else {
            diag(
                "permissions: no ICoreWebView2Profile4; decisions this runtime persisted earlier \
                 cannot be cleared, and a pre-existing Allow may survive",
            );
            return;
        };

        let p4_for_reset = p4.clone();
        let handler = GetNonDefaultPermissionSettingsCompletedHandler::create(Box::new(
            move |result, settings| {
                if result.is_err() {
                    diag("permissions: could not read persisted decisions");
                    return Ok(());
                }
                let Some(settings) = settings else {
                    return Ok(());
                };
                let mut count = 0u32;
                if settings.Count(&mut count).is_err() {
                    return Ok(());
                }
                let mut cleared = 0u32;
                for i in 0..count {
                    let Ok(item) = settings.GetValueAtIndex(i) else {
                        continue;
                    };
                    let mut kind = Default::default();
                    if item.PermissionKind(&mut kind).is_err() {
                        continue;
                    }
                    let mut raw = PWSTR::null();
                    if item.PermissionOrigin(&mut raw).is_err() {
                        continue;
                    }
                    let origin = take_pwstr(raw);
                    if origin.is_empty() {
                        continue;
                    }
                    let wide = HSTRING::from(origin.as_str());
                    let done = SetPermissionStateCompletedHandler::create(Box::new(|_| Ok(())));
                    if p4_for_reset
                        .SetPermissionState(
                            kind,
                            PCWSTR(wide.as_ptr()),
                            COREWEBVIEW2_PERMISSION_STATE_DEFAULT,
                            &done,
                        )
                        .is_ok()
                    {
                        cleared += 1;
                    }
                }
                if cleared > 0 {
                    diag(&format!(
                        "permissions: reset {cleared} decision(s) this profile had persisted; \
                         every site starts denied again"
                    ));
                }
                Ok(())
            },
        ));
        if p4.GetNonDefaultPermissionSettings(&handler).is_err() {
            diag("permissions: GetNonDefaultPermissionSettings refused; persisted decisions stand");
        }
    }
}

/// Deny and mark handled, ignoring failures: this is the path taken when
/// something has already gone wrong, and there is nothing better to try.
fn deny_and_handle(
    args: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2PermissionRequestedEventArgs,
) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2PermissionRequestedEventArgs2, COREWEBVIEW2_PERMISSION_STATE_DENY,
    };
    use windows::core::Interface;

    unsafe {
        let _ = args.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY);
        if let Ok(a2) = args.cast::<ICoreWebView2PermissionRequestedEventArgs2>() {
            let _ = a2.SetHandled(true);
        }
    }
}

/// The ONE interception mechanism, shared by ad blocking, freeze and the
/// ledger (constraint: no second mechanism). Registered for every content
/// tab regardless of policy so the ledger is complete; blocking decisions
/// read live per-request state, so policy toggles need no re-registration.
///
/// A blocked request is answered with a locally synthesized empty 403:
/// WebView2 never puts it on the wire. That is the property the `privacy`
/// matcher tests prove.
fn connect_request_interception(
    webview: &WebView,
    state: Rc<RefCell<TabState>>,
    malicious_override: Rc<RefCell<std::collections::BTreeSet<String>>>,
) {
    use webview2_com::take_pwstr;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_22, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_WEBSOCKET,
        COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
    };
    // Generated handler wrappers live at the crate root, not under the raw
    // Win32 bindings.
    use webview2_com::WebResourceRequestedEventHandler;
    use windows::core::{Interface, HSTRING, PCWSTR, PWSTR};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    // The environment synthesizes block responses. wry already holds the
    // one it created and hands back a clone, so this cannot fail -- which
    // matters: the previous version reached the environment through
    // `cast::<ICoreWebView2_2>()` then `.Environment()`, and BOTH failures
    // returned silently, leaving a tab with no interception whatsoever
    // while `freeze_enforced()` still answered true. Two whole classes of
    // silent breakage deleted by using the accessor wry already exposes.
    let environment = webview.environment();

    // Registering the filter is where "the tab is protected" is actually
    // decided, so every step's outcome is recorded rather than discarded.
    let registration = unsafe {
        // SAFETY: COM interop requires unsafe; raw out-params are the
        // webview2-com idiom used throughout this file.
        //
        // Two overloads exist and the difference is not cosmetic. The
        // legacy AddWebResourceRequestedFilter implies request source kind
        // DOCUMENT, so service, shared and dedicated workers never reach
        // the handler at all -- they would keep talking through a freeze
        // that claims the tab is silent. ICoreWebView2_22's
        // WithRequestSourceKinds variant covers them. wry itself does
        // exactly this cast-and-fall-back for its custom protocols
        // (webview2/mod.rs), so the shape is copied rather than invented;
        // what differs is that the HRESULT is captured here instead of
        // propagated, because a failure has to be REPORTED to the user,
        // not turned into an early return nobody can see.
        let filter = HSTRING::from("*");
        let filter_result = if let Ok(core22) = core.cast::<ICoreWebView2_22>() {
            core22
                .AddWebResourceRequestedFilterWithRequestSourceKinds(
                    PCWSTR(filter.as_ptr()),
                    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                    COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
                )
                .map(|()| true)
        } else {
            core.AddWebResourceRequestedFilter(
                PCWSTR(filter.as_ptr()),
                COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
            )
            .map(|()| false)
        };

        match filter_result {
            Err(error) => Err((privacy::InterceptionFailure::AddFilter, error)),
            Ok(covers_workers) => {
                let handler_state = state.clone();
                let mut token = Default::default();
                let attached = core.add_WebResourceRequested(
                    &WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
                        let Some(args) = args else {
                            return Ok(());
                        };
                        // Nothing below may use `?` on a getter. Every one
                        // of those was a fail-open exit: the request went
                        // out and the tab still claimed to be frozen. An
                        // unreadable value now means "decide without it",
                        // and the pure layer fails closed while frozen.
                        //
                        // A FAILED context read maps to not-a-socket on
                        // purpose: the socket path is an exemption, and an
                        // unclassifiable request must not inherit it.
                        let websocket = {
                            let mut context = COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL;
                            args.ResourceContext(&mut context)
                                .map(|()| context == COREWEBVIEW2_WEB_RESOURCE_CONTEXT_WEBSOCKET)
                                .unwrap_or(false)
                        };
                        // These bindings return the object rather than
                        // filling an out-param. take_pwstr converts and
                        // frees.
                        let uri: Option<String> = args.Request().ok().and_then(|request| {
                            let mut uri = PWSTR::null();
                            request.Uri(&mut uri).ok().map(|()| take_pwstr(uri))
                        });

                        // KNOWN-MALICIOUS HOSTS, refused HERE.
                        //
                        // The navigation handler already refuses them, and on
                        // Windows that refusal does not take: measured
                        // 2026-07-29, the handler fires, matches the rule, and
                        // returns false -- wry turns that into
                        // `args.SetCancel(true)` -- and WebView2 performs the
                        // navigation regardless. Every Windows build shipped so
                        // far has had non-functional malicious-host blocking
                        // while reporting it as protection.
                        //
                        // This path demonstrably works on Windows: it is how ad
                        // blocking and freeze already enforce, and the same
                        // registration line the probe reports as
                        // "source-kinds filter; workers covered". It also
                        // covers SUBRESOURCES, which the navigation handler
                        // cannot see and which the probe caught being fetched
                        // from a listed host.
                        //
                        // Checked BEFORE decide_request and independently of
                        // `policy.block_ads`, so turning off ad blocking cannot
                        // silently turn off malware blocking -- the reason the
                        // two sets were kept separate in the first place.
                        let malicious = uri
                            .as_deref()
                            .and_then(privacy::host_of)
                            .filter(|host| !malicious_override.borrow().contains(host))
                            .and_then(|host| {
                                crate::blocklist::matched_rule(&host).map(|rule| (host, rule))
                            });
                        if let Some((host, rule)) = malicious {
                            diag(&format!("request: refusing {host} ({rule})"));
                            let blocked = (|| -> windows::core::Result<()> {
                                let text = HSTRING::from("Blocked by PATANYX");
                                let headers = HSTRING::from("");
                                let response = environment.CreateWebResourceResponse(
                                    None,
                                    403,
                                    PCWSTR(text.as_ptr()),
                                    PCWSTR(headers.as_ptr()),
                                )?;
                                args.SetResponse(&response)
                            })();
                            if blocked.is_err() {
                                // The request is about to leave. Say so rather
                                // than let a failed synthesis read as a block.
                                diag(&format!("request: FAILED to refuse {host}; it will proceed"));
                            }
                            return Ok(());
                        }

                        // One borrow, released before any COM call below:
                        // WebView2 can re-enter on the UI thread, and a
                        // RefCell held across a COM call is a panic waiting
                        // for the right page.
                        let decision = {
                            let mut st = handler_state.borrow_mut();
                            st.decide_request(
                                uri.as_deref(),
                                websocket,
                                privacy::bundled_rules(),
                                Instant::now(),
                            )
                        };
                        trace_request(&decision, uri.as_deref(), websocket);

                        let privacy::RequestDecision::Block(reason) = decision else {
                            // ALLOWED. Before the request proceeds, stamp the
                            // GPC signal on it: this browser asks every server
                            // not to sell or share. A failure to set it is
                            // diag'd but the request STILL proceeds -- unlike
                            // a blocked request proceeding (a leak), a missing
                            // GPC header is only an unstated preference, and
                            // refusing to load the page over it would be worse
                            // for the user than the absent courtesy.
                            match args.Request().and_then(|r| r.Headers()) {
                                Ok(headers) => {
                                    if let Err(error) = headers.SetHeader(
                                        windows::core::w!("Sec-GPC"),
                                        windows::core::w!("1"),
                                    ) {
                                        diag(&format!(
                                            "gpc: SetHeader FAILED ({error}); this request carries no Sec-GPC"
                                        ));
                                    }
                                }
                                Err(error) => diag(&format!(
                                    "gpc: request headers unavailable ({error}); no Sec-GPC this request"
                                )),
                            }
                            // Referrer trimming used to sit here,
                            // env-gated, awaiting proof it survived the
                            // engine's own header pass. The probe settled it
                            // on 2026-07-31, on real hardware: the BASELINE
                            // Referer this engine sends cross-origin is
                            // already origin-only (Chromium's
                            // strict-origin-when-cross-origin default), so
                            // the rewrite had nothing to do and was deleted.
                            // docs/referrer-trimming.md holds the measurement
                            // and what would have to change to revisit it.
                            return Ok(());
                        };
                        let blocked = (|| -> windows::core::Result<()> {
                            let text = HSTRING::from("Blocked by PATANYX");
                            let headers = HSTRING::from("");
                            let response = environment.CreateWebResourceResponse(
                                None,
                                403,
                                PCWSTR(text.as_ptr()),
                                PCWSTR(headers.as_ptr()),
                            )?;
                            args.SetResponse(&response)
                        })();

                        let mut st = handler_state.borrow_mut();
                        match blocked {
                            // The engine accepted a locally synthesized
                            // 403 while frozen: the request did not leave
                            // the machine, and that is the ONLY evidence
                            // entitling the UI to say so. The pure gate
                            // decides whether this tab may claim it (a
                            // legacy filter may not -- workers bypass it).
                            Ok(()) => {
                                if reason.confirms_freeze() && st.confirm_freeze_block() {
                                    diag("freeze: CONFIRMED - engine accepted a synthesized 403 while frozen");
                                }
                            }
                            // The 403 never happened, so the request went
                            // out. Whatever the toolbar was saying, it
                            // stops saying it now. This is the downgrade
                            // the old backend could not issue at all.
                            Err(error) => {
                                st.freeze_block_failed(uri.as_deref());
                                diag(&format!(
                                    "req BLOCK FAILED ({error}) for {} - request went out; enforcement marked failed",
                                    uri.as_deref().unwrap_or("<unreadable>")
                                ));
                            }
                        }
                        Ok(())
                    })),
                    &mut token,
                );
                match attached {
                    Ok(()) => Ok(covers_workers),
                    Err(error) => Err((privacy::InterceptionFailure::AttachHandler, error)),
                }
            }
        }
    };

    // Record the outcome before anything can consult it. WebView2 raises
    // its events on this thread, so no request can be decided between the
    // attach above and this write.
    let mut st = state.borrow_mut();
    match registration {
        Ok(true) => {
            st.interception = privacy::InterceptionState::Registered {
                covers_workers: true,
            };
            diag("interception: registered (source-kinds filter; workers covered)");
        }
        Ok(false) => {
            st.interception = privacy::InterceptionState::Registered {
                covers_workers: false,
            };
            diag("interception: registered (LEGACY filter; ICoreWebView2_22 unavailable - worker requests are NOT intercepted, so freeze will report Failed on this runtime)");
        }
        Err((step, error)) => {
            st.interception = privacy::InterceptionState::Failed(step);
            let call = match step {
                privacy::InterceptionFailure::AddFilter => "AddWebResourceRequestedFilter",
                privacy::InterceptionFailure::AttachHandler => "add_WebResourceRequested",
            };
            diag(&format!(
                "interception: {call} FAILED ({error}); this tab has NO interception - freeze will report Failed"
            ));
        }
    }

    // Main-resource capture rides the same per-tab registration pass. It
    // reports its own failures and never disturbs interception: a tab that
    // cannot capture bytes still blocks and still freezes.
    connect_page_bytes(webview);
}

/// Debug-build console trace. The release build sets
/// `windows_subsystem = "windows"` and has no console at all, so this is
/// gated rather than merely quiet -- and the project owner runs the DEBUG exe
/// against `scripts/freeze-probe.ps1` precisely to read these lines.
///
/// One grep token (`patanyx:`) on every line, because a probe run is read
/// by eye alongside WebView2's own noise.
/// Bounded so a long session cannot grow it without limit. In memory only --
/// never written to disk except as part of an explicit diagnostics export,
/// never sent anywhere.
const DIAG_LOG_CAP: usize = 50;
static DIAG_LOG: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn diag_log() -> &'static Mutex<VecDeque<String>> {
    DIAG_LOG.get_or_init(|| Mutex::new(VecDeque::with_capacity(DIAG_LOG_CAP)))
}

fn diag(message: &str) {
    if cfg!(debug_assertions) {
        eprintln!("patanyx: {message}");
    }
    // Recorded unconditionally, release included. The `eprintln!` above is
    // the only trace a release build has ever had, and `windows_subsystem =
    // "windows"` (main.rs) means there is nowhere for it to print even with
    // the cfg gate lifted -- so this is what makes hardening fallbacks,
    // freeze-enforcement failures and interception-registration failures
    // (the categories `diag` already covers) reachable by a user who can
    // export a diagnostic report, instead of unreachable in every shipped
    // build. A poisoned lock (a previous panic while holding it) is treated
    // as "nothing to log this time" rather than propagated -- diagnostics
    // must never be the thing that brings down the browser.
    if let Ok(mut log) = diag_log().lock() {
        if log.len() >= DIAG_LOG_CAP {
            log.pop_front();
        }
        log.push_back(message.to_string());
    }
}

/// A snapshot of the diagnostic log, oldest first. Read-only: the export
/// panel may be opened more than once in a session, and each open should see
/// everything recorded so far, not drain what an earlier open already saw.
pub fn recent_diagnostics() -> Vec<String> {
    diag_log()
        .lock()
        .map(|log| log.iter().cloned().collect())
        .unwrap_or_default()
}

/// Per-request trace. Cheap enough at the probe's few requests a second,
/// and it is what turns "the counter still went up" into a located fault:
/// no lines at all means events are not firing, `req allow` after a freeze
/// means the decision was wrong, `req BLOCK` with the counter still rising
/// means the engine took the 403 and ignored it.
fn trace_request(decision: &privacy::RequestDecision, uri: Option<&str>, websocket: bool) {
    if !cfg!(debug_assertions) {
        return;
    }
    let uri = uri.unwrap_or("<unreadable>");
    match decision {
        privacy::RequestDecision::Allow if websocket => diag(&format!("req allow-websocket {uri}")),
        privacy::RequestDecision::Allow => diag(&format!("req allow {uri}")),
        privacy::RequestDecision::Block(reason) => {
            diag(&format!("req BLOCK({}) {uri}", reason.as_str()))
        }
    }
}

/// Feeds the freeze state machine from navigation events. There is no timer
/// here: the auto-freeze transition happens lazily inside
/// FreezeController::should_block on the first request past the grace
/// period, which keeps behaviour identical to the timer-driven unix backend
/// without hooking the tao event loop.
/// Does this failure look like the network is gone, rather than like the site
/// being wrong?
///
/// The list is DELIBERATELY GENEROUS, including `UNKNOWN`, and the asymmetry is
/// the reason. This answer only decides whether to spend one HTTPS request
/// probing the configured resolver; the probe is what decides whether anything
/// is shown. Too wide costs a request that comes back "the resolver is fine"
/// and nothing appears. Too narrow costs a banner that never appears on the
/// network it exists for. Nothing published documents which status Chromium
/// reports when secure-mode DoH fails, so guessing wide is the safe direction.
///
/// Excluded on purpose:
///   * the CERTIFICATE_* statuses -- a TLS problem, which `#tls-warning`
///     already owns and which says nothing about name resolution;
///   * OPERATION_CANCELED -- that is a user navigating away mid-load, not a
///     failure at all, and counting it would accuse the network every time
///     someone was impatient.
///
/// Every constant here was checked against webview2-com 0.38.2 rather than
/// recalled. `CONNECTION_REFUSED` is NOT among them: it does not exist in this
/// SDK, though it is the obvious name to reach for.
#[cfg(windows)]
fn network_looks_dead(status: COREWEBVIEW2_WEB_ERROR_STATUS) -> bool {
    matches!(
        status,
        COREWEBVIEW2_WEB_ERROR_STATUS_HOST_NAME_NOT_RESOLVED
            | COREWEBVIEW2_WEB_ERROR_STATUS_CANNOT_CONNECT
            | COREWEBVIEW2_WEB_ERROR_STATUS_SERVER_UNREACHABLE
            | COREWEBVIEW2_WEB_ERROR_STATUS_CONNECTION_RESET
            | COREWEBVIEW2_WEB_ERROR_STATUS_CONNECTION_ABORTED
            | COREWEBVIEW2_WEB_ERROR_STATUS_DISCONNECTED
            | COREWEBVIEW2_WEB_ERROR_STATUS_TIMEOUT
            | COREWEBVIEW2_WEB_ERROR_STATUS_UNKNOWN
    )
}

fn connect_navigation_events(
    webview: &WebView,
    state: Rc<RefCell<TabState>>,
    proxy: &EventLoopProxy<UserEvent>,
) {
    let record = state.clone();
    use webview2_com::{NavigationCompletedEventHandler, NavigationStartingEventHandler};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let (starting, completed) = unsafe {
        // SAFETY: COM event registration; handlers run on the UI thread.
        let mut token = Default::default();
        let starting_state = state.clone();
        // Handle used to re-navigate when a tracking URL is stripped. Cloned
        // here because the closure outlives this scope; the COM pointer is
        // refcounted, so this is a reference, not a second webview.
        let navigating = core.clone();
        let starting = core.add_NavigationStarting(
            &NavigationStartingEventHandler::create(Box::new(move |_sender, args| {
                // The document being navigated to, for the local-network
                // boundary: it keys on whether THIS PAGE is plain HTTP.
                let nav_url = args.as_ref().and_then(|a| {
                    let mut raw = windows::core::PWSTR::null();
                    unsafe { a.Uri(&mut raw) }
                        .ok()
                        .map(|()| webview2_com::take_pwstr(raw))
                });
                starting_state
                    .borrow_mut()
                    .on_load_started(nav_url.as_deref());
                // MALICIOUS-HOST BLOCKING, ENFORCED HERE TOO.
                //
                // Measured on real Windows hardware 2026-07-29: the shared
                // navigation handler in state.rs fires, extracts the host, and
                // matches the rule -- the browser prints
                // `matched=Some("127.0.0.1")` -- and the request goes out
                // anyway. wry translates that verdict into
                // `args.SetCancel(!allow)` and WebView2 did not honour it.
                //
                // Rather than trust one path, this handler reads Cancel back
                // and sets it itself when the list matches. Reading it back is
                // the diagnosis (it says whether wry's write survived) and
                // setting it is the fix. Belt and braces on the one code path
                // whose entire job is refusing to contact a malicious host.
                if let Some(args) = args {
                    use webview2_com::take_pwstr;
                    use windows::core::PWSTR;
                    let mut uri = PWSTR::null();
                    if args.Uri(&mut uri).is_ok() {
                        let uri = take_pwstr(uri);
                        // TRACKING-PARAM STRIPPING, top-level only.
                        //
                        // This event is the TOP FRAME: WebView2 has a separate
                        // FrameNavigationStarting for subframes, which is what
                        // makes cancel-and-renavigate safe here -- a tracked
                        // iframe can never redirect the whole tab.
                        //
                        // Cancel the tracked URL and navigate to the clean one.
                        // No loop: navigation_strip_target returns Some only
                        // when the string changed, and the replacement strips
                        // to itself (pinned by test), so the re-entry is None.
                        //
                        // NEVER on a form submission. Cancel-and-renavigate
                        // always re-issues as a GET, so stripping a POST would
                        // silently drop the body and lose what the user typed.
                        // The event exposes no request method, but it does
                        // expose the request headers, and a form POST carries
                        // Content-Type on the navigation request while a plain
                        // link GET does not. A failure to READ the headers is
                        // treated as "might be a POST" and skips stripping:
                        // the conservative end is losing a strip, never losing
                        // someone's typed data.
                        let body_bearing = match args.RequestHeaders() {
                            Ok(headers) => {
                                let name = windows::core::w!("Content-Type");
                                let mut has = windows::core::BOOL(0);
                                match headers.Contains(name, &mut has) {
                                    Ok(()) => has.as_bool(),
                                    Err(error) => {
                                        diag(&format!(
                                            "nav-strip: header probe FAILED ({error}); not stripping"
                                        ));
                                        true
                                    }
                                }
                            }
                            Err(error) => {
                                diag(&format!(
                                    "nav-strip: RequestHeaders FAILED ({error}); not stripping"
                                ));
                                true
                            }
                        };
                        if let Some(clean) =
                            (!body_bearing).then(|| crate::ipc::navigation_strip_target(&uri)).flatten()
                        {
                            let mut wide: Vec<u16> =
                                clean.encode_utf16().chain(std::iter::once(0)).collect();
                            let target = windows::core::PCWSTR(wide.as_mut_ptr());
                            match navigating.Navigate(target) {
                                Ok(()) => {
                                    let _ = args.SetCancel(true);
                                    return Ok(());
                                }
                                // Navigate refused: let the ORIGINAL proceed
                                // rather than cancelling into a blank tab. A
                                // tracked page beats no page.
                                Err(error) => diag(&format!(
                                    "nav-strip: Navigate FAILED ({error}); letting the tracked URL through"
                                )),
                            }
                        }
                        if let Some(host) = privacy::host_of(&uri) {
                            if let Some(rule) = crate::blocklist::matched_rule(&host) {
                                let mut already = windows::core::BOOL(0);
                                let _ = args.Cancel(&mut already);
                                diag(&format!(
                                    "nav: {host} matches {rule}; wry_cancel={}",
                                    already.as_bool()
                                ));
                                if !already.as_bool() {
                                    let _ = args.SetCancel(true);
                                }
                            }
                        }
                    }
                }
                Ok(())
            })),
            &mut token,
        );
        let mut token = Default::default();
        let nav_proxy = proxy.clone();
        let completed = core.add_NavigationCompleted(
            &NavigationCompletedEventHandler::create(Box::new(move |_sender, args| {
                // Success and failure both count as finished: a failed load
                // must not leave the tab permanently unfreezable.
                state.borrow_mut().on_load_finished(Instant::now());

                // The args used to be discarded. They carry the engine's own
                // verdict on this navigation, which is the only evidence the
                // browser has that a chosen DNS resolver has stopped working.
                if let Some(args) = args.as_ref() {
                    // Out-parameter accessors, windows-rs style. Both are read
                    // before either is used, and a failure to read EITHER means
                    // this navigation is simply not evidence -- the detector is
                    // fed nothing rather than fed a default.
                    let mut success = windows::core::BOOL::default();
                    let mut status = COREWEBVIEW2_WEB_ERROR_STATUS::default();
                    let ok = unsafe { args.IsSuccess(&mut success) }.is_ok()
                        && unsafe { args.WebErrorStatus(&mut status) }.is_ok();
                    if ok {
                        crate::resolver_probe::note_navigation(
                            success.as_bool(),
                            network_looks_dead(status),
                            &nav_proxy,
                        );
                    }
                }
                Ok(())
            })),
            &mut token,
        );
        (starting, completed)
    };
    // These outcomes matter as much as the request filter's, and discarding
    // them was the same silent-registration failure this file set out to
    // eliminate -- two functions further down.
    //
    // Without NavigationCompleted, `on_load_finished` never runs, `loaded_at`
    // stays None, and a quarantine tab NEVER auto-freezes -- while
    // `interception_state` still reports "registered" and the privacy panel
    // counts freeze as an active protection.
    let mut ok = true;
    if let Err(error) = starting {
        ok = false;
        diag(&format!(
            "navigation: add_NavigationStarting FAILED ({error}); freeze state will not track page loads"
        ));
    }
    if let Err(error) = completed {
        ok = false;
        diag(&format!(
            "navigation: add_NavigationCompleted FAILED ({error}); this tab will never auto-freeze"
        ));
    }
    // Recorded, not just logged. The comment above says these outcomes matter
    // as much as the request filter's; until now only the request filter's
    // were kept, so a tab that could never auto-freeze still reported freeze
    // as an available protection.
    record.borrow_mut().navigation_tracking = if ok {
        SettingState::Applied
    } else {
        SettingState::Failed
    };
}

/// Observes certificate errors. Detection informs, never obstructs: the
/// default action (WebView2's error page) is left alone. WebView2 exposes
/// no chain issuer through this event or anywhere else, so the only honest
/// verdict it can record is Unreadable -- the same "this platform cannot
/// look" that tls_state reports, not the "looked and did not recognize it"
/// that Unknown means (see tls_state).
fn connect_cert_errors(webview: &WebView, state: Rc<RefCell<TabState>>) {
    use webview2_com::ServerCertificateErrorDetectedEventHandler;
    use wry::WebViewExtWindows;

    let core = webview.webview();
    unsafe {
        // SAFETY: COM event registration; handler runs on the UI thread.
        let mut token = Default::default();
        use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2_14;
        use windows::core::Interface as _;
        // Older WebView2 runtimes have no ICoreWebView2_14; degrade to no TLS
        // verdict rather than failing to build the tab.
        let Ok(core14) = core.cast::<ICoreWebView2_14>() else {
            return;
        };
        let _ = core14.add_ServerCertificateErrorDetected(
            &ServerCertificateErrorDetectedEventHandler::create(Box::new(
                move |_sender, _args| {
                    state.borrow_mut().tls_error_verdict = Some(TlsState::Unreadable);
                    Ok(())
                },
            )),
            &mut token,
        );
    }
}

/// What `harden_privacy` managed to apply. Returned rather than logged: both
/// of these are protections the panel would otherwise present as active on a
/// runtime that silently refused them.
struct Hardening {
    smartscreen_off: SettingState,
    tracking_prevention: SettingState,
    /// The engine's OWN autofill and password store, off. Reported like the
    /// others because a browser that says it does not accumulate your details
    /// must not be guessing about whether it stopped.
    autofill_off: SettingState,
    /// Whether the engine actually put this webview in an in-memory profile.
    ///
    /// THE LAST POLICY FIELD THAT WAS NEVER ASKED ABOUT. `with_incognito` was
    /// set on the builder and then simply believed: `profile_mode()` answered
    /// out of `TabPolicy`, so the UI said "Ephemeral" whether or not the
    /// engine had agreed, and a quarantine tab -- the preset whose entire
    /// purpose is keeping nothing -- rested on that. Every other protection in
    /// this struct is recorded from the engine's own answer precisely so the
    /// UI cannot claim an unconfirmed one; this one now is too.
    ephemeral: SettingState,
}

/// Stops WebView2 sending the user's browsing to Microsoft.
///
/// SmartScreen is ON by default and reputation-checks what is visited, which
/// means the URLs a user opens leave the machine. Microsoft documents that
/// disabling it also turns off the other privacy services in WebView2, and that
/// shipping with it enabled obliges the app to tell users their information is
/// sent to Microsoft. Neither is acceptable in a browser sold on privacy.
///
/// What this does NOT fix, and must not be claimed otherwise: WebView2 reports
/// "required" component health data (API and SDK usage, creation failures) that
/// no embedding application can switch off. That limit is real, nothing here
/// reaches it, and it is the reason "zero telemetry" must not be written
/// anywhere.
///
/// Crash-dump upload is a DIFFERENT limit, and it is NOT out of reach. This
/// comment claimed it was until 2026-07-27, and the claim was load-bearing:
/// it is one of the two legs the product's telemetry wording rests on.
/// Corrected by reading the vendored crates rather than reasoning about them.
/// `ICoreWebView2EnvironmentOptions3::SetIsCustomCrashReportingEnabled` does
/// have to be set when the environment is CREATED -- but wry does not insist on
/// creating it. `WebViewBuilderExtWindows::with_environment` accepts a finished
/// `ICoreWebView2Environment` (wry 0.55.1 `src/lib.rs:1778`), and
/// `src/webview2/mod.rs:134` calls `create_environment` ONLY when none was
/// supplied. webview2-com 0.38.2 already implements the option
/// (`src/options.rs:444`). The app can build its own environment and hand it
/// over, with no patch to wry.
///
/// DONE since this paragraph was written, and it used to say "NOT DONE". See
/// `shared_environment` above: the process now builds its own environment,
/// reproducing every option wry sets in `create_environment` -- the
/// `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection` browser
/// args, the UI language from `GetUserDefaultUILanguage` /
/// `LCIDToLocaleName`, the scrollbar style, the browser-extensions flag, and
/// the `enable_tracking_prevention: true` that
/// `CoreWebView2EnvironmentOptions::default()` supplies and that the STRICT
/// setter below silently depends on. Getting any one of them wrong would make
/// a protection inert without failing, which is why they are enumerated here
/// rather than left to be rediscovered.
///
/// The sequencing worry in the old text -- that this and the shared profile
/// directory should not land together on a platform the build host cannot run
/// -- was resolved by doing the profile directory first. `hardened_environment`
/// now reports whether the environment creation actually succeeded, so a
/// silent fallback to wry's environment (which drops every argument above) is
/// visible in the privacy panel instead of only in a debug log.
fn harden_privacy(webview: &WebView, want_ephemeral: bool) -> Hardening {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Profile3, ICoreWebView2Profile6, ICoreWebView2Settings8, ICoreWebView2_13,
        COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_STRICT,
    };
    use windows::core::Interface;
    use wry::WebViewExtWindows;

    // Best-effort: ICoreWebView2Settings8 needs a recent WebView2 runtime, and
    // an older one should degrade to "SmartScreen still on" rather than a crash
    // on startup.
    let mut smartscreen_off = SettingState::Failed;
    let mut tracking_prevention = SettingState::Failed;
    let mut autofill_off = SettingState::Failed;
    let mut ephemeral = SettingState::Failed;
    unsafe {
        let core = webview.webview();
        if let Ok(settings) = core.Settings() {
            if let Ok(settings8) = settings.cast::<ICoreWebView2Settings8>() {
                match settings8.SetIsReputationCheckingRequired(false) {
                    Ok(()) => smartscreen_off = SettingState::Applied,
                    Err(error) => diag(&format!(
                        "harden: SetIsReputationCheckingRequired FAILED ({error}); SmartScreen is STILL ON"
                    )),
                }
            } else {
                diag("harden: no ICoreWebView2Settings8; SmartScreen is STILL ON on this runtime");
            }
        }

        // Tracking prevention. WebView2 defaults this to BALANCED, which lets
        // a great deal through; STRICT is the strongest level the runtime
        // offers and is what a browser making this product's claims has to
        // ask for. Same reasoning as ITP on the GTK side, and the reason
        // both are set is that the two engines' defaults disagree.
        //
        // Best-effort in the same way as above: Profile() is
        // ICoreWebView2_13 (Runtime 102+) and the level setter is
        // ICoreWebView2Profile3 (Runtime 111+). An older runtime keeps
        // BALANCED rather than failing to start. Note that STRICT here does
        // NOT replace the content blocker: this stops known trackers the
        // engine recognises, the filter stops the hosts we list.
        // DEPENDENCY: the profile level only takes effect when tracking
        // prevention is enabled on the ENVIRONMENT via
        // ICoreWebView2EnvironmentOptions5. wry 0.55.1 builds its environment
        // from CoreWebView2EnvironmentOptions::default(), and webview2-com
        // 0.38.2 defaults enable_tracking_prevention to true, so the setter
        // below is live rather than inert. Verified by reading both crates.
        // If wry ever changes that default, STRICT goes silently inert and
        // this comment is where to start looking.
        if let Ok(v13) = core.cast::<ICoreWebView2_13>() {
            if let Ok(profile) = v13.Profile() {
                if let Ok(p3) = profile.cast::<ICoreWebView2Profile3>() {
                    match p3.SetPreferredTrackingPreventionLevel(
                        COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_STRICT,
                    ) {
                        Ok(()) => tracking_prevention = SettingState::Applied,
                        Err(error) => diag(&format!(
                            "harden: SetPreferredTrackingPreventionLevel(STRICT) FAILED ({error}); \
                             the runtime keeps BALANCED"
                        )),
                    }
                } else {
                    diag("harden: no ICoreWebView2Profile3; tracking prevention stays BALANCED");
                }
            }
        } else {
            diag("harden: no ICoreWebView2_13; tracking prevention stays BALANCED");
        }

        // Autofill and password autosave, at the PROFILE level.
        //
        // The builder already sets `with_general_autofill_enabled(false)` per
        // webview; this is the profile-scoped pair, and both are set on
        // purpose. wry applies the per-webview one today, but it is wry's
        // default that put autofill ON in the first place -- so relying on a
        // single layer here is relying on an upstream default staying the way
        // it happens to be. Password autosave has no wry setter at all and is
        // reachable ONLY here.
        //
        // ICoreWebView2Profile6 is the interface that carries both.
        // READ BACK, NOT ASSUMED -- and this block used to get that wrong.
        //
        // It reported `Applied` when the two SETTERS returned Ok, which is a
        // claim about the call succeeding, not about the engine's state. A
        // setter that is accepted and then ignored would leave the Privacy
        // panel saying "Engine autofill and password store off" over an
        // engine still autofilling passwords -- the same shape of defect as
        // the ad-block rule that reported success while matching nothing, and
        // as referrer trimming, both of which this project has already paid
        // for. `ICoreWebView2Profile6` carries getters for both values, so
        // there is no excuse for guessing.
        //
        // Applied now requires BOTH to read back false. Anything else --
        // a refused setter, a refused getter, or a getter that still says
        // true -- is Failed, because the user is entitled to know the
        // difference between "off" and "we asked for off".
        if let Ok(v13) = core.cast::<ICoreWebView2_13>() {
            if let Ok(profile) = v13.Profile() {
                if let Ok(p6) = profile.cast::<ICoreWebView2Profile6>() {
                    let set_general = p6.SetIsGeneralAutofillEnabled(false);
                    let set_passwords = p6.SetIsPasswordAutosaveEnabled(false);

                    let mut general_now = windows::core::BOOL::from(true);
                    let mut passwords_now = windows::core::BOOL::from(true);
                    let read_general = p6.IsGeneralAutofillEnabled(&mut general_now);
                    let read_passwords = p6.IsPasswordAutosaveEnabled(&mut passwords_now);

                    match (set_general, set_passwords, read_general, read_passwords) {
                        (Ok(()), Ok(()), Ok(()), Ok(())) => {
                            if !general_now.as_bool() && !passwords_now.as_bool() {
                                autofill_off = SettingState::Applied;
                            } else {
                                diag(&format!(
                                    "harden: autofill off IGNORED BY THE ENGINE (both setters \
                                     returned OK but it still reports general={}, passwords={}); \
                                     the engine may still be storing form data and passwords",
                                    general_now.as_bool(),
                                    passwords_now.as_bool()
                                ));
                            }
                        }
                        (sg, sp, rg, rp) => diag(&format!(
                            "harden: autofill off UNCONFIRMED (set general={sg:?}, set \
                             passwords={sp:?}, read general={rg:?}, read passwords={rp:?}); the \
                             engine may still be storing form data and passwords"
                        )),
                    }
                } else {
                    diag("harden: no ICoreWebView2Profile6; engine autofill state is unknown");
                }
            }
        }

        // EPHEMERAL, READ BACK RATHER THAN ASSUMED.
        //
        // `IsInPrivateModeEnabled` is on the BASE ICoreWebView2Profile, so it
        // needs no interface newer than the ICoreWebView2_13 the two blocks
        // above already require. wry sets the flag at controller creation
        // (webview2/mod.rs:407) from the builder's `incognito`; this asks the
        // engine what it ended up with.
        //
        // Compared against what was REQUESTED, not against `true`: a
        // persistent tab correctly reports in-private = false, and that is
        // just as much an agreement as an ephemeral tab reporting true. A
        // mismatch in either direction is the interesting case.
        if let Ok(v13) = core.cast::<ICoreWebView2_13>() {
            if let Ok(profile) = v13.Profile() {
                let mut in_private = windows::core::BOOL::default();
                match profile.IsInPrivateModeEnabled(&mut in_private) {
                    Ok(()) if in_private.as_bool() == want_ephemeral => {
                        ephemeral = SettingState::Applied
                    }
                    Ok(()) => diag(&format!(
                        "harden: in-private is {} but {} was requested; the tab's storage \
                         is NOT what the policy says",
                        in_private.as_bool(),
                        want_ephemeral
                    )),
                    Err(error) => diag(&format!(
                        "harden: IsInPrivateModeEnabled FAILED ({error}); storage mode unconfirmed"
                    )),
                }
            }
        }
    }
    Hardening {
        smartscreen_off,
        tracking_prevention,
        autofill_off,
        ephemeral,
    }
}

/// Deletes cookies for `host` -- matching any cookie name and any path within
/// that domain -- and nothing else. Best-effort, same shape as
/// `harden_privacy` above: an older runtime may lack the interface, and the
/// delete call itself returns an HRESULT that must be checked, never assumed
/// to have succeeded.
///
/// COOKIES ONLY, AND THAT IS A REAL CEILING, NOT A FIRST DRAFT.
/// `ICoreWebView2Profile::ClearBrowsingData`/`ClearBrowsingDataInTimeRange`
/// exist and could plausibly look like the more thorough choice, but they
/// take only a data-kind bitmask and a time range -- there is no origin
/// parameter, so either would clear that data for the ENTIRE profile, wiping
/// every other open site along with the one the user asked to forget. There
/// is no WebView2 API found that scopes localStorage or IndexedDB clearing to
/// a single origin from the embedder side. The caller-facing copy must say
/// "cookies", never "site data" -- overstating this is exactly the kind of
/// claim this project's own About page exists to refuse.
pub fn forget_site_cookies(webview: &WebView, host: &str) -> bool {
    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2Profile6, ICoreWebView2_13};
    use windows::core::{Interface, HSTRING, PCWSTR};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    unsafe {
        let Ok(v13) = core.cast::<ICoreWebView2_13>() else {
            diag("forget_site: no ICoreWebView2_13 on this runtime; cookies were NOT cleared");
            return false;
        };
        let Ok(profile) = v13.Profile() else {
            diag("forget_site: could not reach the profile; cookies were NOT cleared");
            return false;
        };
        // ICoreWebView2Profile6 derefs to ICoreWebView2Profile5, which is
        // where CookieManager lives -- one cast reaches both, the same way
        // the autofill block above reaches Profile6 for its own setters.
        let Ok(manager) = profile
            .cast::<ICoreWebView2Profile6>()
            .and_then(|p6| p6.CookieManager())
        else {
            diag("forget_site: no CookieManager on this runtime; cookies were NOT cleared");
            return false;
        };
        let domain = HSTRING::from(host);
        match manager.DeleteCookiesWithDomainAndPath(
            PCWSTR::null(),
            PCWSTR(domain.as_ptr()),
            PCWSTR::null(),
        ) {
            Ok(()) => true,
            Err(error) => {
                diag(&format!(
                    "forget_site: DeleteCookiesWithDomainAndPath({host}) FAILED ({error})"
                ));
                false
            }
        }
    }
}

/// Drops every cookie in the profile, ONCE per process, at the first content
/// webview.
///
/// WHY THIS EXISTS. Measured 2026-08-01 on real hardware
/// (`scripts/login-probe.ps1`): a login cookie set in one launch was still
/// present in the next. WebKitGTK loses them, WebView2 keeps them -- the same
/// product behaving oppositely on a user-visible property, and NOTHING chose
/// that. It was an engine default on each side. The project owner's decision is
/// that neither platform keeps them: a session should not know who you were
/// last time. See docs/third-party-cookies.md.
///
/// WHY AT STARTUP RATHER THAN AT EXIT, when the property is named "forget on
/// exit". An exit hook does not run when the process is killed, crashes, or
/// loses power -- precisely the cases where somebody else may later open the
/// browser. Clearing as the first thing a session does is unconditional: it
/// cannot be skipped by dying badly, and it delivers the guarantee users
/// actually care about, which is that a NEW session starts anonymous. The
/// honest cost, and it belongs in the About copy rather than hidden here: the
/// data does sit on disk between sessions, so this is not erasure against
/// someone with the machine and forensic tools.
///
/// ONCE PER PROCESS, not per tab: every content webview shares one profile,
/// so doing this on the second tab would delete the cookies the first tab
/// just legitimately acquired -- logging the user out mid-session, which is a
/// different and much worse product than the one being asked for.
fn clear_cookies_for_new_session(webview: &WebView) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2Profile6, ICoreWebView2_13};
    use windows::core::Interface;
    use wry::WebViewExtWindows;

    static DONE: AtomicBool = AtomicBool::new(false);
    // swap, not load-then-store: two webviews could otherwise both read false.
    if DONE.swap(true, Ordering::SeqCst) {
        return;
    }

    let core = webview.webview();
    unsafe {
        let Ok(v13) = core.cast::<ICoreWebView2_13>() else {
            diag("session: no ICoreWebView2_13; cookies from the last session were NOT cleared");
            return;
        };
        let Ok(profile) = v13.Profile() else {
            diag("session: could not reach the profile; cookies were NOT cleared");
            return;
        };
        let Ok(manager) = profile
            .cast::<ICoreWebView2Profile6>()
            .and_then(|p6| p6.CookieManager())
        else {
            diag("session: no CookieManager; cookies from the last session were NOT cleared");
            return;
        };
        match manager.DeleteAllCookies() {
            // Reported, because a silent success is indistinguishable from a
            // silent no-op and this one is a privacy claim.
            Ok(()) => diag("session: cookies from the previous session cleared"),
            Err(error) => diag(&format!(
                "session: DeleteAllCookies FAILED ({error}); cookies from the last session REMAIN"
            )),
        }
    }
}

/// Applies a policy to a live tab. Ad blocking and freeze need no engine
/// work here (the request handler reads live state); JavaScript is toggled
/// through settings. `ephemeral` is construction-time -- the WebView2
/// profile is fixed once the controller exists -- and this function does not
/// fake it.
///
/// Note: cosmetic filtering is engine-unsupported on WebView2 (no
/// user-stylesheet API exists, and script injection is forbidden for
/// content webviews), so blocked-ad containers are NOT hidden on Windows.
/// Network-level blocking -- the part that stops data leaving the machine --
/// works identically on both backends.
pub fn apply_policy(webview: &WebView, view: &TabView, policy: &TabPolicy) {
    use wry::WebViewExtWindows;
    {
        let mut st = view.state.borrow_mut();
        st.policy = policy.clone();
        st.freeze.set_auto(policy.freeze_after_load);
    }
    // The engine's answer, not our request. `st.policy` above is what the user
    // asked for; this is whether it is in force. They used to be the same
    // write, which is how a failed setter left the tab running script while
    // the panel counted JavaScript-off as a protection -- and in a release
    // build the only evidence was a `diag()` that compiles to nothing.
    let applied = unsafe {
        // SAFETY: COM property setter; failure degrades to "previous
        // JavaScript setting kept", never a crash.
        match webview.webview().Settings() {
            Ok(settings) => match settings.SetIsScriptEnabled(policy.javascript) {
                Ok(()) => true,
                Err(error) => {
                    diag(&format!(
                        "policy: SetIsScriptEnabled({}) FAILED ({error}); reported to the UI as not enforced",
                        policy.javascript
                    ));
                    false
                }
            },
            Err(error) => {
                diag(&format!(
                    "policy: Settings() FAILED ({error}); no policy could be applied to this tab"
                ));
                false
            }
        }
    };
    view.state.borrow_mut().script_setting = if applied {
        SettingState::Applied
    } else {
        SettingState::Failed
    };
}

// ---------------------------------------------------------------------------
// File choice
//
// This was a deliberate stub returning None until 2026-07-27, on the argument
// that Windows is not sandboxed so a typed path always works, and that writing
// untestable COM on a host with no Windows to run it on is the pattern that
// produced the Freeze defect measured on 2026-07-25.
//
// That argument expired the moment an operator with a Windows machine started
// running these builds, and the cost of the deferral turned out to be larger
// than "a convenience": with `file_choice_supported()` false, the vault's
// export and import flows were unreachable on Windows entirely, because the
// UI branches on that predicate to decide between a chooser and a typed field.
//
// The dialogs below are still UNVERIFIED on Windows -- they cross-compile and
// that is all this host can say. Every failure path returns None, which is the
// same answer as a cancelled dialog, so the worst case is the button appearing
// to do nothing rather than the browser misbehaving.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SAVE PAGE AS PDF
//
// Writes through the EXISTING download pipeline rather than beside it, so an
// archived page gets the same sanitized destination, the same SHA-256 and the
// same provenance record as any other download, and can be checked with the
// same Verify button.
//
// WHY THERE IS NO "CHOOSE WHERE TO SAVE". `check_download_file` looks only in
// `download_dir()`, by BARE FILENAME, and refuses any name containing a
// separator. A PDF written to the Desktop would therefore get a perfectly good
// record whose Verify reports "missing" forever. Teaching the record a
// directory means changing the canonical encoding the HMAC covers, which
// invalidates every record already written, with no migration path. A file
// that lands somewhere predictable and verifiable beats a file the user placed
// and cannot check.
// ---------------------------------------------------------------------------

/// Opens the engine's own print preview for `webview`.
///
/// WHY THIS EXISTS AT ALL: BEFORE IT, Ctrl+P PRINTED THE TOOLBAR. Nothing in
/// this codebase handled the key, so WebView2's built-in handling took it on
/// whichever webview happened to hold focus -- and that is usually the chrome.
/// The project owner got a preview of the PATANYX tab strip, footed
/// `rbchrome.localhost/index.html`, in a dialog anchored to the chrome's own
/// window and therefore clipped to the height of the toolbar strip. All three
/// symptoms were the one cause.
///
/// So the key is intercepted and aimed at the CONTENT webview explicitly,
/// rather than left to focus. Printing the browser's own interface is never
/// what anyone meant, and "it depends where you clicked last" is not a
/// behaviour worth preserving.
///
/// `COREWEBVIEW2_PRINT_DIALOG_KIND_BROWSER` is the engine's preview, which is
/// what a browser's Ctrl+P is expected to open; the system dialog is one click
/// further in from there for anyone who wants it.
///
/// Returns false when the runtime is too old to carry `ICoreWebView2_16`, so
/// the caller can say so instead of appearing to do nothing -- the failure this
/// whole function exists to stop.
pub fn show_print_ui(webview: &WebView) -> bool {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_16, COREWEBVIEW2_PRINT_DIALOG_KIND_BROWSER,
    };
    use windows::core::Interface as _;
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let Ok(v16) = core.cast::<ICoreWebView2_16>() else {
        diag("print: runtime has no ICoreWebView2_16; cannot open a print preview");
        return false;
    };
    match unsafe { v16.ShowPrintUI(COREWEBVIEW2_PRINT_DIALOG_KIND_BROWSER) } {
        Ok(()) => true,
        Err(e) => {
            diag(&format!("print: ShowPrintUI refused ({e})"));
            false
        }
    }
}

/// Starts a PDF render of `webview` into `dest`.
///
/// ASYNCHRONOUS, like OCR and the page-bytes read, and for the same reason:
/// IPC dispatch runs on the event loop, and a multi-second render done inline
/// would freeze the browser before it could paint anything. The reply goes
/// back as a `UserEvent::PdfSaved`.
///
/// Returns false if the render could not even be STARTED -- an old runtime
/// without `ICoreWebView2_7`, or a refused call -- so the caller can say so
/// immediately rather than leaving the user waiting for an event that will
/// never arrive.
pub fn save_page_as_pdf(
    webview: &WebView,
    dest: &Path,
    proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Environment6, ICoreWebView2_7,
    };
    use webview2_com::PrintToPdfCompletedHandler;
    use windows::core::{Interface as _, HSTRING, PCWSTR};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let Ok(core7) = core.cast::<ICoreWebView2_7>() else {
        diag("save as pdf: runtime has no ICoreWebView2_7");
        return false;
    };

    // Settings are optional (null means the engine's defaults), but the
    // defaults STAMP THE URL AND PAGE NUMBERS onto every sheet. This browser's
    // whole line is "leave less behind", and that includes paper: an archived
    // page should not carry a header nobody asked for. Backgrounds stay on so
    // the archive looks like the page did.
    let settings = shared_environment()
        .and_then(|env| env.cast::<ICoreWebView2Environment6>().ok())
        .and_then(|env6| unsafe { env6.CreatePrintSettings() }.ok());
    if let Some(settings) = &settings {
        unsafe {
            let _ = settings.SetShouldPrintHeaderAndFooter(false);
            let _ = settings.SetShouldPrintBackgrounds(true);
        }
    }

    let path = HSTRING::from(dest.as_os_str());
    let dest_owned = dest.to_string_lossy().into_owned();
    let proxy = proxy.clone();
    let result = unsafe {
        core7.PrintToPdf(
            PCWSTR(path.as_ptr()),
            settings.as_ref(),
            &PrintToPdfCompletedHandler::create(Box::new(move |hr, ok| {
                // BOTH are checked. The handler carries an HRESULT and a
                // separate success flag, and the engine can report S_OK with
                // ok=false -- the render was attempted and did not produce a
                // file. Treating S_OK alone as success would record provenance
                // for a PDF that is not there.
                let success = hr.is_ok() && ok;
                let _ = proxy.send_event(UserEvent::PdfSaved {
                    path: dest_owned.clone(),
                    success,
                });
                Ok(())
            })),
        )
    };
    if let Err(error) = &result {
        diag(&format!("save as pdf: PrintToPdf refused ({error})"));
    }
    result.is_ok()
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// RIGHT-CLICK MENU
//
// A NATIVE Win32 popup, not a chrome overlay, and that is forced by the
// architecture rather than chosen for looks. The chrome and the content
// webview are sibling OS windows that do not composite (see `layout` below):
// the only way the chrome can draw below its fixed strip is `ChromeLayout::
// Overlay`, which hands the content webview a 0x0 rect. A menu drawn that way
// would blank the very page it was invoked on. `TrackPopupMenu` is an OS-level
// popup that floats over everything, needs no layout change, and brings
// keyboard navigation, screen-reader support and edge-flipping with it.
//
// WHY THE VENDOR MENU NEVER SHOWS, AND WHY THE SETTING IS RE-ENABLED.
// WebView2 raises `ContextMenuRequested` ONLY while
// `AreDefaultContextMenusEnabled` is true; with the setting off the event
// never fires and right-click is dead air on every target. That is not in the
// setting's own doc -- it was measured on the project owner's hardware 2026-08-04,
// after shipping two menus built on the opposite assumption, and it is why
// the vendor's custom-menu sample keeps the setting ENABLED and suppresses
// per event. So: the BUILDER still disables the setting (the fail-closed
// state -- a tab whose handler never registered shows no menu at all, never
// the vendor's), and successful registration re-enables it, with
// `SetHandled(true)` on every event keeping the vendor menu from drawing.
// Restoring WebView2's own menu instead was considered: it would give
// copy/paste back, but it also ships whatever Microsoft chose to put in it,
// which this project cannot audit from here and has no way to keep true across
// runtime updates. Shipping an unaudited vendor menu inside a privacy browser
// is exactly the kind of unverifiable surface the rest of this codebase
// refuses. What shows instead is built row by row from
// `menu_compose::compose` -- the same entries WebKitGTK shows on Linux -- with
// cut/copy/paste/select-all delegated to the ENGINE's own commands via
// SetSelectedCommandId, so the vendor menu itself never appears even for
// those.
// ---------------------------------------------------------------------------

// The ids live in platform::mod so AppState can match on them on every
// target; this file builds the menu, state.rs interprets the answer.
use super::{menu_compose, menu_ids};

// Win32-only command ids for the engine-local editing commands. TrackPopupMenu
// needs some u32 per row, but these must never reach state.rs, so they sit far
// above the menu_ids range and the handler match intercepts them first.
// Non-zero for the same TPM_RETURNCMD dismissal reason as menu_ids.
const LOCAL_CUT: u32 = 101;
const LOCAL_COPY: u32 = 102;
const LOCAL_PASTE: u32 = 103;
const LOCAL_SELECT_ALL: u32 = 104;

/// Registers the right-click handler on a content webview.
///
/// Returns whether registration succeeded, on the same terms as
/// `connect_content_messages`: a tab whose menu never registered simply has no
/// menu, and the caller records that rather than assuming.
fn connect_context_menu(
    webview: &WebView,
    proxy: &EventLoopProxy<UserEvent>,
    parent: windows::Win32::Foundation::HWND,
) -> bool {
    use webview2_com::ContextMenuRequestedEventHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2_11;
    use windows::core::Interface as _;
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let controller = webview.controller();
    // HWND is a raw pointer wrapper; carried as isize so the 'static closure
    // does not borrow, same trick as the subclass code below.
    let parent_ptr = parent.0 as isize;
    // ICoreWebView2_11 is where ContextMenuRequested arrives. An older runtime
    // simply does not have it; that is a capability gap, not an error.
    let Ok(core11) = core.cast::<ICoreWebView2_11>() else {
        diag("context menu: runtime has no ICoreWebView2_11; right-click stays inert");
        return false;
    };

    let proxy = proxy.clone();
    let mut token = Default::default();
    let result = unsafe {
        core11.add_ContextMenuRequested(
            &ContextMenuRequestedEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                // ALWAYS handled: without it WebView2 draws its own menu,
                // the surface this feature deliberately does not expose. A
                // failure here is the one place fail-open would leak the
                // vendor menu, so it is diag'd rather than swallowed.
                if let Err(error) = args.SetHandled(true) {
                    diag(&format!(
                        "context menu: SetHandled FAILED ({error}); the vendor menu may appear"
                    ));
                }

                let Ok(target) = args.ContextMenuTarget() else {
                    diag("context menu: ContextMenuTarget FAILED; no menu this click");
                    return Ok(());
                };
                let clicked = click_target_of(&target);
                let compose_target = menu_compose::Target {
                    link: clicked.link.is_some(),
                    image: clicked.image.is_some(),
                    editable: clicked.editable,
                    selection: clicked.selection,
                };
                let entries = menu_compose::compose(compose_target);

                // The engine's own command ids for cut/copy/paste/select-all
                // on THIS target. Only worth enumerating when an editing
                // entry can appear at all.
                let engine = if clicked.editable || clicked.selection {
                    engine_commands(&args)
                } else {
                    EngineCommands::default()
                };

                // Where to open the menu, in SCREEN pixels. `Location` alone
                // is webview-relative CSS pixels and TrackPopupMenu wants
                // screen pixels; the conversion lives in menu_screen_point.
                let parent =
                    windows::Win32::Foundation::HWND(parent_ptr as *mut core::ffi::c_void);
                let point = menu_screen_point(&args, &controller, parent);

                let Some(chosen) = show_menu(point, parent, &entries, &engine) else {
                    return Ok(());
                };

                match chosen {
                    // Engine-local: reported to the engine, still inside the
                    // event, and NEVER sent to state.rs. With Handled set,
                    // WebView2 invokes SelectedCommandId instead of drawing a
                    // menu -- the engine runs its own audited command.
                    LOCAL_CUT => set_selected_command(&args, engine.cut),
                    LOCAL_COPY => set_selected_command(&args, engine.copy),
                    LOCAL_PASTE => set_selected_command(&args, engine.paste),
                    LOCAL_SELECT_ALL => set_selected_command(&args, engine.select_all),
                    // Cross-platform: state.rs is the one interpreter of menu
                    // ids. What each action carries is decided in one place.
                    action => {
                        let _ = proxy.send_event(UserEvent::ContextMenuAction {
                            action,
                            target: dispatch_payload(action, &clicked),
                        });
                    }
                }
                Ok(())
            })),
            &mut token,
        )
    };
    if let Err(error) = &result {
        diag(&format!(
            "context menu: add_ContextMenuRequested FAILED ({error}); right-click stays inert"
        ));
        return false;
    }
    // The builder ships with the vendor menu disabled, and WebView2 raises
    // ContextMenuRequested ONLY while the setting is enabled -- disabled
    // means no event at all, the 2026-08-04 hardware finding this section's
    // header records. Enable it now that OUR handler owns every event;
    // SetHandled(true) above keeps the vendor menu suppressed. The change
    // applies from the next top-level navigation, which is before this tab's
    // first page. If enabling fails, right-click stays inert -- the failure
    // direction is never the vendor menu.
    let enabled = unsafe {
        core.Settings()
            .and_then(|settings| settings.SetAreDefaultContextMenusEnabled(true))
    };
    if let Err(error) = enabled {
        diag(&format!(
            "context menu: SetAreDefaultContextMenusEnabled FAILED ({error}); right-click stays inert"
        ));
        return false;
    }
    true
}

/// Where to open the popup, in SCREEN pixels.
///
/// `Location` reports the click in the WEBVIEW's own coordinate space in CSS
/// pixels. The engine's documented custom-menu sample converts exactly this
/// way: scale by the controller's `RasterizationScale`, offset by the
/// controller's bounds inside the parent window, then client-to-screen
/// through the parent. Any read failing falls back to the CURSOR, which for
/// a mouse right-click is the click point (a keyboard-invoked menu then
/// opens at the pointer rather than the caret -- misplaced, not lost).
fn menu_screen_point(
    args: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ContextMenuRequestedEventArgs,
    controller: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Controller,
    parent: windows::Win32::Foundation::HWND,
) -> windows::Win32::Foundation::POINT {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Controller3;
    use windows::core::Interface as _;
    use windows::Win32::Foundation::{POINT, RECT};
    use windows::Win32::Graphics::Gdi::ClientToScreen;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    unsafe {
        let mut css = POINT::default();
        let mut bounds = RECT::default();
        if args.Location(&mut css).is_ok() && controller.Bounds(&mut bounds).is_ok() {
            let mut raw_scale = 0f64;
            let scale = match controller
                .cast::<ICoreWebView2Controller3>()
                .and_then(|c3| c3.RasterizationScale(&mut raw_scale).map(|()| raw_scale))
            {
                Ok(s) if s > 0.0 => s,
                // Controller3 predates every runtime this app supports, but a
                // failed read must not zero the coordinates.
                _ => 1.0,
            };
            let mut origin = POINT { x: 0, y: 0 };
            if ClientToScreen(parent, &mut origin).as_bool() {
                return POINT {
                    x: origin.x + bounds.left + (f64::from(css.x) * scale) as i32,
                    y: origin.y + bounds.top + (f64::from(css.y) * scale) as i32,
                };
            }
        }
        let mut cursor = POINT::default();
        if GetCursorPos(&mut cursor).is_ok() {
            return cursor;
        }
        diag("context menu: no usable coordinates; menu opens at the screen origin");
        POINT::default()
    }
}

/// The link URI a right-click landed on, or None.
///
/// Guarded by `HasLinkUri` rather than by testing the string: reading
/// `LinkUri` on a target that has none is not defined to give anything
/// useful. Both are out-parameter accessors, the same shape as the `Uri`
/// read in `connect_request_interception`.
fn link_uri_of(
    target: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ContextMenuTarget,
) -> Option<String> {
    use webview2_com::take_pwstr;
    use windows::core::PWSTR;

    unsafe {
        let mut has = Default::default();
        if target.HasLinkUri(&mut has).is_err() || !has.as_bool() {
            return None;
        }
        let mut raw = PWSTR::null();
        if target.LinkUri(&mut raw).is_err() {
            return None;
        }
        let text = take_pwstr(raw);
        (!text.is_empty()).then_some(text)
    }
}

/// What a right-click landed on, gathered once so the menu and the dispatch
/// agree. None/false for anything the engine does not confirm: every read
/// here is an out-parameter COM call whose failure means "that section does
/// not appear", never "guess" -- the same failure direction as link_uri_of.
struct ClickTarget {
    link: Option<String>,
    image: Option<String>,
    editable: bool,
    selection: bool,
}

fn click_target_of(
    target: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ContextMenuTarget,
) -> ClickTarget {
    use webview2_com::take_pwstr;
    use windows::core::PWSTR;

    let link = link_uri_of(target);
    let image = source_uri_if_image(target);
    let editable = unsafe {
        let mut editable = Default::default();
        target.IsEditable(&mut editable).is_ok() && editable.as_bool()
    };
    // SelectionText only decides whether a Copy/Select-all section appears;
    // the copy itself is the engine's command, so the string is not kept.
    let selection = unsafe {
        let mut raw = PWSTR::null();
        match target.SelectionText(&mut raw) {
            Ok(()) => !take_pwstr(raw).is_empty(),
            Err(_) => false,
        }
    };
    ClickTarget { link, image, editable, selection }
}

/// The image source, or None unless the target IS an image. SourceUri is also
/// set for audio and video targets, and "Copy image address" on a video would
/// copy a media URL under a false label, so the kind is checked first.
fn source_uri_if_image(
    target: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ContextMenuTarget,
) -> Option<String> {
    use webview2_com::take_pwstr;
    use webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_CONTEXT_MENU_TARGET_KIND_IMAGE;
    use windows::core::PWSTR;

    unsafe {
        let mut kind = Default::default();
        if target.Kind(&mut kind).is_err() || kind != COREWEBVIEW2_CONTEXT_MENU_TARGET_KIND_IMAGE {
            return None;
        }
        let mut raw = PWSTR::null();
        if target.SourceUri(&mut raw).is_err() {
            return None;
        }
        let text = take_pwstr(raw);
        (!text.is_empty()).then_some(text)
    }
}

/// The engine's command ids for cut/copy/paste/select-all on THIS target,
/// read off the default menu items WebView2 would have shown.
///
/// WHY THIS SHAPE: numeric command ids are reassigned by the runtime between
/// events and must never be hardcoded (Microsoft's docs), and the display
/// Label is localized, so the match key is `Name` -- documented as the item's
/// unlocalized name, present to distinguish item types. Matched
/// case-insensitively because the contract is "unlocalized", not a casing.
///
/// HONEST DEGRADATION: a command not offered for this target, renamed by a
/// future runtime, or currently disabled is simply left out of the menu -- an
/// absent item, not a broken one. If an editable/selection target yields NONE
/// of the four, that is diag'd: it means the name contract changed and the
/// operator's hardware test should surface it.
#[derive(Default)]
struct EngineCommands {
    cut: Option<i32>,
    copy: Option<i32>,
    paste: Option<i32>,
    select_all: Option<i32>,
}

fn engine_commands(
    args: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ContextMenuRequestedEventArgs,
) -> EngineCommands {
    use webview2_com::take_pwstr;
    use windows::core::PWSTR;

    let mut found = EngineCommands::default();
    unsafe {
        let items = match args.MenuItems() {
            Ok(items) => items,
            Err(error) => {
                diag(&format!(
                    "context menu: MenuItems FAILED ({error}); editing commands unavailable"
                ));
                return found;
            }
        };
        let mut count = 0u32;
        if let Err(error) = items.Count(&mut count) {
            diag(&format!(
                "context menu: MenuItems.Count FAILED ({error}); editing commands unavailable"
            ));
            return found;
        }
        for index in 0..count {
            let Ok(item) = items.GetValueAtIndex(index) else {
                continue;
            };
            // A disabled default item (paste with an empty clipboard, cut
            // with no selection) would be a dead row; skip it like a missing
            // one.
            let mut enabled = Default::default();
            if item.IsEnabled(&mut enabled).is_err() || !enabled.as_bool() {
                continue;
            }
            let mut raw_name = PWSTR::null();
            if item.Name(&mut raw_name).is_err() {
                continue;
            }
            let name = take_pwstr(raw_name);
            let slot = if name.eq_ignore_ascii_case("cut") {
                &mut found.cut
            } else if name.eq_ignore_ascii_case("copy") {
                &mut found.copy
            } else if name.eq_ignore_ascii_case("paste") {
                &mut found.paste
            } else if name.eq_ignore_ascii_case("selectAll") {
                &mut found.select_all
            } else {
                continue;
            };
            let mut id = 0i32;
            if item.CommandId(&mut id).is_ok() {
                *slot = Some(id);
            }
        }
    }
    if found.cut.is_none()
        && found.copy.is_none()
        && found.paste.is_none()
        && found.select_all.is_none()
    {
        diag("context menu: no cut/copy/paste/selectAll among the engine's items; the Name contract may have changed (hardware check)");
    }
    found
}

/// Reports the user's editing choice to the engine. Must be called while the
/// ContextMenuRequested event is still open -- it is: the popup ran modally
/// inside the handler -- and only with a CommandId read off the engine's own
/// MenuItems for this event, never a remembered number.
fn set_selected_command(
    args: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ContextMenuRequestedEventArgs,
    command: Option<i32>,
) {
    // The menu row only exists when the command was found, so None here means
    // an internal mismatch; doing nothing is the safe end of it.
    let Some(id) = command else {
        return;
    };
    if let Err(error) = unsafe { args.SetSelectedCommandId(id) } {
        diag(&format!(
            "context menu: SetSelectedCommandId({id}) FAILED ({error}); command not run"
        ));
    }
}

/// The target URL an action carries into state.rs: link actions carry the
/// link, image actions the image source, navigation carries none. Editing
/// commands never reach here (they are engine-local).
fn dispatch_payload(action: u32, clicked: &ClickTarget) -> Option<String> {
    match action {
        menu_ids::OPEN_IMAGE_NEW_TAB | menu_ids::COPY_IMAGE => clicked.image.clone(),
        menu_ids::HISTORY_BACK | menu_ids::HISTORY_FORWARD | menu_ids::HISTORY_RELOAD => None,
        _ => clicked.link.clone(),
    }
}

/// Builds and runs the popup for `entries`, returning the chosen id.
///
/// `entries` comes from `menu_compose::compose`: what is offered, and in what
/// order, is decided (and unit-tested) there; this function only maps entries
/// to Win32 rows. Two kinds of id leave here: `menu_ids::*` for cross-platform
/// actions (state.rs interprets), and `LOCAL_*` for engine-local editing
/// commands (the handler intercepts). Editing commands the engine did not
/// offer for this target are skipped: an absent item, not a broken one.
///
/// Runs MODALLY, as the shipped link menu did: `TrackPopupMenu` with
/// `TPM_RETURNCMD` pumps its own loop and returns the selection; it returns 0
/// when dismissed, which is why no command uses 0.
fn show_menu(
    point: windows::Win32::Foundation::POINT,
    owner: windows::Win32::Foundation::HWND,
    entries: &[menu_compose::Entry],
    engine: &EngineCommands,
) -> Option<u32> {
    use windows::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, DestroyMenu, SetForegroundWindow, TrackPopupMenu,
        MF_SEPARATOR, MF_STRING, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    };

    unsafe {
        let Ok(menu) = CreatePopupMenu() else {
            return None;
        };
        let mut rows = 0usize;
        // Only counts a row that actually went on the menu; a failed
        // AppendMenuW leaves `rows` unchanged so an all-failed menu is treated
        // as empty rather than shown blank.
        let mut add = |id: u32, label: &str| {
            let wide: Vec<u16> = label.encode_utf16().chain(std::iter::once(0)).collect();
            if AppendMenuW(menu, MF_STRING, id as usize, windows::core::PCWSTR(wide.as_ptr()))
                .is_ok()
            {
                rows += 1;
            }
        };
        for entry in entries {
            match entry {
                menu_compose::Entry::Separator => {
                    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, windows::core::PCWSTR::null());
                }
                menu_compose::Entry::Action(id) => {
                    if let Some(label) = menu_compose::action_label(*id) {
                        add(*id, label);
                    }
                }
                menu_compose::Entry::Editing(command) => {
                    let (local, present) = match command {
                        menu_compose::Editing::Cut => (LOCAL_CUT, engine.cut.is_some()),
                        menu_compose::Editing::Copy => (LOCAL_COPY, engine.copy.is_some()),
                        menu_compose::Editing::Paste => (LOCAL_PASTE, engine.paste.is_some()),
                        menu_compose::Editing::SelectAll => {
                            (LOCAL_SELECT_ALL, engine.select_all.is_some())
                        }
                    };
                    if present {
                        add(local, command.label());
                    }
                }
            }
        }
        // Everything the target produced was unavailable (reachable only when
        // the engine offered no editing commands for an editable/selection
        // target): an absent menu, the pre-feature behaviour, not a blank
        // stub.
        if rows == 0 {
            let _ = DestroyMenu(menu);
            return None;
        }

        // Windows dismisses a popup owned by a window that is not foreground,
        // which would make the menu flash and vanish. Documented Win32
        // behaviour, not a workaround. The owner is OUR window, passed in --
        // GetForegroundWindow here was a self-assignment that owned the menu
        // to whatever happened to be foreground.
        let _ = SetForegroundWindow(owner);
        let chosen = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            Some(0),
            owner,
            None,
        );
        let _ = DestroyMenu(menu);
        // 0 means dismissed without choosing.
        (chosen.0 != 0).then_some(chosen.0 as u32)
    }
}

// ---------------------------------------------------------------------------
// WORKSTATION LOCK AND SUSPEND -> VAULT LOCK
//
// The inactivity timer counts keypresses INSIDE THE BROWSER. It cannot see the
// one moment that most obviously means "I have left": locking the screen. Walk
// away with ten minutes still on the clock and the vault sits unlocked behind
// the OS lock screen.
//
// WHY A SUBCLASS AND NOT tao's MESSAGE HOOK. tao 0.35 exposes
// `EventLoopBuilderExtWindows::with_msg_hook`, and the slot is free -- but that
// hook runs inside the `GetMessageW` pump, which only sees POSTED messages.
// `WM_WTSSESSION_CHANGE` and `WM_POWERBROADCAST` are SENT directly to the
// window procedure and never touch the thread queue, so the hook would compile,
// register, and silently observe nothing. A subclass sits where they actually
// arrive.
// ---------------------------------------------------------------------------

/// Whether the session/power notifications actually registered.
///
/// Reported, not logged, for the same reason `hardened_environment` is: a
/// protection the user is told about must be one the OS acknowledged. If
/// `WTSRegisterSessionNotification` fails there is no lock-on-lock, and the
/// panel has to say so rather than leave the claim standing.
static SESSION_LOCK_STATE: OnceLock<SettingState> = OnceLock::new();

pub fn session_lock_registered() -> SettingState {
    *SESSION_LOCK_STATE.get().unwrap_or(&SettingState::NotAttempted)
}

/// Where the subclass sends what it sees. Set once, before the subclass is
/// installed, so the procedure can never observe a half-initialised value.
static SESSION_LOCK_PROXY: OnceLock<Mutex<EventLoopProxy<UserEvent>>> = OnceLock::new();

/// Arbitrary, but must be unique among subclasses on this window. Nothing else
/// in this process subclasses it.
const SESSION_SUBCLASS_ID: usize = 0x5041_544E;

/// Installs the subclass and asks Windows for session and power notifications.
///
/// Every failure is recorded and reported; none of them is fatal, because the
/// inactivity timer still works and is the backstop.
pub fn connect_session_lock(hosts: &Hosts, proxy: &EventLoopProxy<UserEvent>) {
    use windows::Win32::System::Power::RegisterSuspendResumeNotification;
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::UI::Shell::SetWindowSubclass;
    // DEVICE_NOTIFY_WINDOW_HANDLE lives in WindowsAndMessaging, not in
    // System::Power beside the function that consumes it -- the generated
    // bindings group constants by the header that declares them, not by the
    // API that takes them.
    use windows::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_WINDOW_HANDLE;

    let hwnd = window_hwnd(hosts);
    let _ = SESSION_LOCK_PROXY.set(Mutex::new(proxy.clone()));

    let state = unsafe {
        // The subclass goes on FIRST. Registering for notifications before the
        // procedure that reads them exists would open a window -- small, but
        // real -- where a lock event arrives and is dropped.
        if !SetWindowSubclass(hwnd, Some(session_subclass_proc), SESSION_SUBCLASS_ID, 0).as_bool() {
            diag("session lock: SetWindowSubclass failed");
            SettingState::Failed
        } else if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION).is_err() {
            // Suspend is deliberately NOT attempted if this failed: the two
            // are reported as one capability, and a half-registered state that
            // reads "applied" would be exactly the lie this field exists to
            // prevent.
            diag("session lock: WTSRegisterSessionNotification failed");
            SettingState::Failed
        } else {
            // Suspend notification is best-effort ON TOP of session lock. It
            // uses a different API family and can fail independently; losing
            // it costs the suspend trigger, not the lock trigger, so it does
            // not downgrade the whole capability.
            if RegisterSuspendResumeNotification(
                windows::Win32::Foundation::HANDLE(hwnd.0),
                DEVICE_NOTIFY_WINDOW_HANDLE,
            )
            .is_err()
            {
                diag("session lock: RegisterSuspendResumeNotification failed (lock still armed)");
            }
            SettingState::Applied
        }
    };
    let _ = SESSION_LOCK_STATE.set(state);
}

/// The subclass procedure. Does the minimum: recognise the two messages, hand
/// them to the event loop, and pass everything through untouched.
///
/// It must not lock the vault directly. This runs on whatever stack Windows
/// chose to send the message on, and `AppState` belongs to the event loop --
/// so it does what every other cross-thread signal here does and sends a
/// `UserEvent`.
unsafe extern "system" fn session_subclass_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
    _id: usize,
    _ref_data: usize,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::Shell::DefSubclassProc;
    // All four constants live together in WindowsAndMessaging, including the
    // two that name Power and RemoteDesktop concepts.
    use windows::Win32::UI::WindowsAndMessaging::{
        PBT_APMSUSPEND, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK,
    };

    let signal = match msg {
        WM_WTSSESSION_CHANGE if wparam.0 as u32 == WTS_SESSION_LOCK => true,
        WM_POWERBROADCAST if wparam.0 as u32 == PBT_APMSUSPEND => true,
        _ => false,
    };
    if signal {
        if let Some(proxy) = SESSION_LOCK_PROXY.get() {
            if let Ok(proxy) = proxy.lock() {
                let _ = proxy.send_event(UserEvent::SessionLocked);
            }
        }
    }
    // ALWAYS chain. Swallowing a message here would break whatever tao and
    // WebView2 expect from this window, and neither of these two is ours to
    // consume -- we are observing, not handling.
    DefSubclassProc(hwnd, msg, wparam, lparam)
}

/// Parent HWND for a modal dialog, or null.
///
/// Null is a legitimate parent: the dialog is then unparented rather than
/// absent, which matches what the GTK side already does (`gtk::Window::NONE`).
/// It is not worth failing a file pick over.
fn window_hwnd(hosts: &Hosts) -> windows::Win32::Foundation::HWND {
    use tao::platform::windows::WindowExtWindows;
    use windows::Win32::Foundation::HWND;
    HWND(hosts.window.hwnd() as _)
}

/// Reads the chosen path off a completed dialog.
///
/// `GetDisplayName(SIGDN_FILESYSPATH)` rather than the item's plain name: the
/// display name of a shell item can be a label with no filesystem meaning, and
/// every caller here is about to open or write an actual file.
unsafe fn shell_item_path(
    item: &windows::Win32::UI::Shell::IShellItem,
) -> Option<std::path::PathBuf> {
    use windows::Win32::UI::Shell::SIGDN_FILESYSPATH;
    let wide = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
    // Converted, then freed UNCONDITIONALLY, then the result is unwrapped.
    // Freeing after a `?` on the conversion would leak the buffer on exactly
    // the path where something already went wrong.
    let path = wide.to_string().ok();
    windows::Win32::System::Com::CoTaskMemFree(Some(wide.0 as *const _));
    Some(std::path::PathBuf::from(path?))
}

/// Puts text on the system clipboard. True when it was written.
///
/// THE PROCESS DOES THIS ITSELF, rather than handing the text to the chrome
/// webview to write with `navigator.clipboard`. That is what it used to do,
/// and the round trip is why "Copy link" reported "Could not copy that link":
/// the Clipboard API refuses to write from a document that is not focused,
/// and the document doing the writing was the chrome while the focus was in
/// the page the user had just right-clicked. Owning the write removes the
/// focus requirement, the permission surface and the secure-context question
/// in one go, and the copied URL no longer has to enter a JS context at all.
///
/// The clipboard takes ownership of the moveable HGLOBAL on success and frees
/// it itself; the only path that must free is the one where
/// `SetClipboardData` fails, which is why the guard below is written as it is.
pub fn set_clipboard_text(text: &str) -> bool {
    // GlobalFree lives in Foundation, not Memory, in this binding generation.
    use windows::Win32::Foundation::{GlobalFree, HANDLE};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    // CF_UNICODETEXT. Spelled out rather than imported so this does not pull
    // the whole Win32_System_Ole feature in for one u16.
    const CF_UNICODETEXT: u32 = 13;

    // NUL-terminated UTF-16, which is what the format is defined as.
    let mut utf16: Vec<u16> = text.encode_utf16().collect();
    utf16.push(0);
    let bytes = std::mem::size_of_val(&utf16[..]);

    unsafe {
        // SAFETY: every call below runs on the UI thread that owns the window,
        // which is the thread the clipboard is opened for; each pointer is
        // checked before use and the allocation is freed on every failing path.
        if OpenClipboard(None).is_err() {
            return false;
        }
        let ok = (|| {
            EmptyClipboard().ok()?;
            let handle = GlobalAlloc(GMEM_MOVEABLE, bytes).ok()?;
            let dest = GlobalLock(handle);
            if dest.is_null() {
                let _ = GlobalFree(Some(handle));
                return None;
            }
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), dest as *mut u16, utf16.len());
            let _ = GlobalUnlock(handle);
            // Ownership transfers to the clipboard here and ONLY here. A
            // failure means we still own it and must free it, or the text
            // leaks for the life of the process.
            if SetClipboardData(CF_UNICODETEXT, Some(HANDLE(handle.0))).is_err() {
                let _ = GlobalFree(Some(handle));
                return None;
            }
            Some(())
        })()
        .is_some();
        let _ = CloseClipboard();
        ok
    }
}

/// Whether the user can be asked to choose a file.
pub fn file_choice_supported() -> bool {
    true
}

pub fn pick_file_to_open(hosts: &Hosts, title: &str) -> Option<std::path::PathBuf> {
    use windows::core::HSTRING;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
    use windows::Win32::UI::Shell::{FileOpenDialog, IFileOpenDialog};

    unsafe {
        // SAFETY: COM apartment is already initialised on this thread -- wry
        // calls CoInitializeEx before creating any webview, and this only ever
        // runs from an IPC command on that same UI thread.
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)
            .ok()?;
        let _ = dialog.SetTitle(&HSTRING::from(title));
        // Show() returns an error when the user cancels. Cancel is an answer,
        // not a fault: every caller treats None as "they changed their mind".
        dialog.Show(Some(window_hwnd(hosts))).ok()?;
        let item = dialog.GetResult().ok()?;
        shell_item_path(&item)
    }
}

pub fn pick_file_to_save(
    hosts: &Hosts,
    title: &str,
    suggested_name: &str,
) -> Option<std::path::PathBuf> {
    use windows::core::HSTRING;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
    use windows::Win32::UI::Shell::{FileSaveDialog, IFileSaveDialog};

    unsafe {
        // SAFETY: as above.
        let dialog: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)
            .ok()?;
        let _ = dialog.SetTitle(&HSTRING::from(title));
        let _ = dialog.SetFileName(&HSTRING::from(suggested_name));
        // The overwrite prompt is on by default for IFileSaveDialog, matching
        // the GTK side's explicit set_do_overwrite_confirmation(true).
        dialog.Show(Some(window_hwnd(hosts))).ok()?;
        let item = dialog.GetResult().ok()?;
        shell_item_path(&item)
    }
}

/// Whether the engine can hand us the page's real bytes.
///
/// FALSE on WebView2, deliberately. Page integrity and peer corroboration need
/// what the SERVER actually served, and WebView2 exposes no equivalent of
/// WebKit's main-resource read. The honest routes both cost real work:
/// capturing the main document body from `WebResourceResponseReceived` at
/// response time, keyed per navigation, with cached and 304 responses handled
/// -- get any of that wrong and the digest is of the wrong bytes.
///
/// The alternatives were considered and rejected. Re-fetching the URL asks the
/// server for a SECOND copy, which is precisely the behaviour corroboration
/// exists to detect. Evaluating script in the content webview is forbidden
/// outright, and would yield post-DOM bytes rather than what was served.
///
/// Those constraints now have an honest mechanism: the
/// `WebResourceResponseReceived` event hands back the response AS SERVED
/// (see `connect_page_bytes` below), so this reports available only when
/// that handler actually registered. Where registration failed the UI
/// still says unavailable -- a wrong digest is worse than no digest: it
/// would let someone conclude a page was unmodified on evidence that never
/// described the page.
pub fn page_bytes_supported() -> bool {
    PAGE_BYTES_REGISTERED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Whether the page-bytes pipeline has registered for real on at least one
/// tab. Set true only after ALL THREE registrations (NavigationStarting,
/// WebResourceRequested, WebResourceResponseReceived) and the
/// `ICoreWebView2_2` cast succeeded, so it is never true merely because the
/// build intended it.
///
/// PROCESS-WIDE, AND THAT IS ITS LIMIT, stated rather than papered over:
/// `page_bytes_supported()` takes no tab, so it cannot answer per tab, and
/// once one tab registers this stays true. A LATER tab whose registration
/// failed is not covered by this flag -- it is covered where it actually
/// matters, at the point of use: such a tab has no tracker in
/// `PAGE_BYTES_TRACKERS` (the insert happens only on full success), so
/// `request_main_resource_bytes` answers `NoMainResource` for it and the UI
/// reports the feature unavailable for that page. The flag says "this
/// runtime can do it"; the per-tab truth is told by the tracker's absence.
static PAGE_BYTES_REGISTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

thread_local! {
    /// Per-tab main-resource trackers, keyed by the raw `ICoreWebView2`
    /// pointer. UI-thread confined: every reader and writer (WebView2 event
    /// callbacks, `request_main_resource_bytes`, tab teardown) runs on the
    /// wry event-loop thread, so a thread_local RefCell is the entire
    /// synchronization story -- no Mutex, and the tracker never needs Send.
    static PAGE_BYTES_TRACKERS: std::cell::RefCell<
        std::collections::HashMap<
            usize,
            std::rc::Rc<std::cell::RefCell<super::main_resource::MainResourceTracker>>,
        >,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The ONE main-resource capture mechanism, shared by change detection and
/// peer corroboration (constraint: no second mechanism).
///
/// Why this source and no other, unchanged from the analysis above:
/// evaluating script in a content webview is forbidden by §4.1 outright and
/// would yield post-DOM bytes rather than what the server sent -- the exact
/// lie these features exist to detect -- and re-fetching the URL asks the
/// server for a SECOND copy, which is precisely the behaviour
/// corroboration exists to detect. `WebResourceResponseReceived` +
/// `GetContent` returns the response AS SERVED, which is the only honest
/// input.
///
/// Registered alongside `connect_request_interception` for every content
/// tab. Every step's outcome is captured and diag()'d; no `?` fail-open
/// anywhere. On ANY failure the function returns with
/// `PAGE_BYTES_REGISTERED` still false and the UI shows the feature
/// unavailable, rather than a tab silently capturing nothing while the
/// capability flag claims otherwise.
///
/// Two handlers, because identification needs both (see
/// platform/main_resource.rs for the pure decision logic this drives):
///   * NavigationStarting  -- the only honest source of "which request is
///     the document": the response event has no resource context and the
///     committed URL lags the document's response event.
///   * WebResourceResponseReceived (ICoreWebView2_2) -- the bytes.
fn connect_page_bytes(webview: &WebView) {
    use super::main_resource::{MainResourceTracker, ResponseAction};
    use crate::page_integrity::PageBytesError;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_2, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT,
    };
    use webview2_com::{
        take_pwstr, NavigationStartingEventHandler, WebResourceRequestedEventHandler,
        WebResourceResponseReceivedEventHandler, WebResourceResponseViewGetContentCompletedHandler,
    };
    use windows::core::{Interface, HSTRING, PCWSTR, PWSTR};
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let tracker = Rc::new(RefCell::new(MainResourceTracker::new()));

    // SAFETY: COM interop requires unsafe; raw out-params are the
    // webview2-com idiom used throughout this file. The unsafe block covers
    // the closures defined within it, exactly as in
    // `connect_request_interception`.
    unsafe {
        // (1) NavigationStarting -- open a new generation and seed the
        // document candidate.
        let nav_tracker = tracker.clone();
        let mut nav_token = Default::default();
        if let Err(error) = core.add_NavigationStarting(
            &NavigationStartingEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                let mut uri = PWSTR::null();
                match args.Uri(&mut uri) {
                    Ok(()) => nav_tracker.borrow_mut().begin_navigation(&take_pwstr(uri)),
                    Err(_) => {
                        // Unnamed navigation: open a generation with no
                        // candidate, which captures nothing rather than
                        // leaving the previous one armed.
                        diag("page-bytes: NavigationStarting with unreadable URI; capturing nothing");
                        nav_tracker.borrow_mut().begin_navigation("");
                    }
                }
                Ok(())
            })),
            &mut nav_token,
        ) {
            diag(&format!(
                "page-bytes: add_NavigationStarting FAILED ({error}); this tab captures nothing"
            ));
            return;
        }

        // (2) WebResourceRequested -- ask the ENGINE which request is the
        // document. This is what makes identification a fact rather than a
        // guess: a fetch to the page's own URL is never DOCUMENT, so it can
        // never be mistaken for the page even if it answers first. The
        // filter set is already installed by connect_request_interception
        // (CONTEXT_ALL), so this handler observes and never writes -- it
        // sets no Response and no Cancel, and cannot disturb blocking.
        let req_tracker = tracker.clone();
        let mut req_token = Default::default();
        if let Err(error) = core.add_WebResourceRequested(
            &WebResourceRequestedEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                let mut context = COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT;
                if args.ResourceContext(&mut context).is_err()
                    || context != COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT
                {
                    return Ok(());
                }
                let Ok(request) = args.Request() else {
                    return Ok(());
                };
                let mut uri = PWSTR::null();
                if request.Uri(&mut uri).is_ok() {
                    req_tracker
                        .borrow_mut()
                        .note_document_request(&take_pwstr(uri));
                }
                Ok(())
            })),
            &mut req_token,
        ) {
            diag(&format!(
                "page-bytes: add_WebResourceRequested FAILED ({error}); this tab captures nothing"
            ));
            return;
        }

        // (3) WebResourceResponseReceived -- the bytes themselves.
        let core2 = match core.cast::<ICoreWebView2_2>() {
            Ok(core2) => core2,
            Err(error) => {
                diag(&format!(
                    "page-bytes: ICoreWebView2_2 cast FAILED ({error}); this tab captures nothing"
                ));
                return;
            }
        };
        let resp_tracker = tracker.clone();
        let mut resp_token = Default::default();
        let resp_result = core2.add_WebResourceResponseReceived(
            &WebResourceResponseReceivedEventHandler::create(Box::new(move |_sender, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                // No `?` on getters, per this file's discipline. Every
                // unreadable getter DISARMS the candidate rather than
                // returning quietly: leaving it armed would let a later
                // response at the same URI be taken for the document.
                let Ok(request) = args.Request() else {
                    resp_tracker.borrow_mut().abandon();
                    return Ok(());
                };
                let mut uri = PWSTR::null();
                let Ok(()) = request.Uri(&mut uri) else {
                    resp_tracker.borrow_mut().abandon();
                    return Ok(());
                };
                let request_uri = take_pwstr(uri);
                let Ok(response) = args.Response() else {
                    resp_tracker.borrow_mut().abandon();
                    return Ok(());
                };
                // None means unreadable, which the pure layer fails closed
                // on -- it cannot tell a redirect from a document.
                let mut raw_status: i32 = 0;
                let status = response
                    .StatusCode(&mut raw_status)
                    .ok()
                    .map(|()| raw_status.clamp(0, u16::MAX as i32) as u16);
                let location: Option<String> = response.Headers().ok().and_then(|headers| {
                    let name = HSTRING::from("Location");
                    let mut value = PWSTR::null();
                    headers
                        .GetHeader(PCWSTR(name.as_ptr()), &mut value)
                        .ok()
                        .map(|()| take_pwstr(value))
                });

                let action = resp_tracker.borrow_mut().handle_response(
                    &request_uri,
                    status,
                    location.as_deref(),
                );
                let ResponseAction::FetchContent { generation } = action else {
                    return Ok(());
                };

                let done_tracker = resp_tracker.clone();
                let done_uri = request_uri.clone();
                let get = response.GetContent(
                    &WebResourceResponseViewGetContentCompletedHandler::create(Box::new(
                        move |error_code, content| {
                            let result = if error_code.is_err() {
                                Err(PageBytesError::FetchFailed)
                            } else {
                                match content {
                                    Some(stream) => read_stream_capped(&stream),
                                    None => Err(PageBytesError::FetchFailed),
                                }
                            };
                            // Quoting the generation is what makes this
                            // async completion safe: a late answer from an
                            // abandoned visit is dropped, never written over
                            // the page now displayed.
                            done_tracker.borrow_mut().store(&done_uri, generation, result);
                            Ok(())
                        },
                    )),
                );
                if let Err(error) = get {
                    diag(&format!("page-bytes: GetContent call FAILED: {error}"));
                    resp_tracker.borrow_mut().store(
                        &request_uri,
                        generation,
                        Err(PageBytesError::FetchFailed),
                    );
                }
                Ok(())
            })),
            &mut resp_token,
        );
        match resp_result {
            Ok(()) => {
                // Registered ONLY now, after all three succeeded: a tab that
                // failed anywhere above has no tracker, and `serve` answers
                // NoMainResource for it rather than a silent empty capture.
                PAGE_BYTES_TRACKERS.with(|tabs| {
                    tabs.borrow_mut().insert(core.as_raw() as usize, tracker);
                });
                PAGE_BYTES_REGISTERED.store(true, std::sync::atomic::Ordering::SeqCst);
                diag("page-bytes: main-resource capture registered");
            }
            Err(error) => {
                diag(&format!(
                    "page-bytes: add_WebResourceResponseReceived FAILED ({error}); this tab captures nothing"
                ));
            }
        }
    }
}

/// Read a response body stream to memory, bounded by the integrity cap.
///
/// Threading assumption: the stream arrives inside the GetContent
/// completion callback, which WebView2 delivers on the UI thread -- the same
/// thread every handler in this file runs on -- and it is read there and
/// then; no marshalling is attempted. The cap keeps worst-case memory
/// bounded during the read, and crossing it is TooLarge, never truncation.
///
/// End-of-stream is a short read or S_FALSE (the IStream contract); a
/// failed HRESULT is FetchFailed, matching the unix path's honesty.
fn read_stream_capped(
    stream: &windows::Win32::System::Com::IStream,
) -> Result<Vec<u8>, crate::page_integrity::PageBytesError> {
    use super::main_resource::push_capped;
    use crate::page_integrity::PageBytesError;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let mut read: u32 = 0;
        // SAFETY: `chunk` is valid for writes of `chunk.len()` bytes and
        // `read` is a valid out-pointer for the duration of the call.
        let hr = unsafe {
            stream.Read(
                chunk.as_mut_ptr() as *mut _,
                chunk.len() as u32,
                Some(&mut read as *mut u32),
            )
        };
        if hr.is_err() {
            return Err(PageBytesError::FetchFailed);
        }
        if read == 0 {
            break;
        }
        push_capped(&mut buf, &chunk[..read as usize])?;
        if (read as usize) < chunk.len() {
            break; // short read: end of stream
        }
    }
    Ok(buf)
}

/// Drop a tab's page-bytes tracker. MUST be called from the tab-teardown
/// path: it frees the cached page (up to the integrity cap) with the tab,
/// and guarantees a future webview that reuses the raw address can never
/// inherit a dead tab's bytes. (`serve`'s committed-URL check already made
/// that practically unreachable; this makes it impossible.)
pub(crate) fn drop_page_bytes_tracker(webview: &WebView) {
    use windows::core::Interface;
    use wry::WebViewExtWindows;

    let key = webview.webview().as_raw() as usize;
    PAGE_BYTES_TRACKERS.with(|tabs| {
        tabs.borrow_mut().remove(&key);
    });
}

/// Serve the cached main-resource bytes for the page this tab is CURRENTLY
/// displaying. The answer -- success or failure -- always arrives as
/// `UserEvent::Integrity(IntegrityEvent::PageBytes { token, .. })`, exactly
/// as on unix.
///
/// Never called while `page_bytes_supported()` is false -- callers check
/// first -- but it answers honestly even then: with no registered handler
/// the cache is empty and the result is NoMainResource.
///
/// The committed URL is read NOW, on demand, and the cached entry is only
/// handed out if its URI is that URL: bytes from a previous page, a
/// redirect hop, or a download are never served as this page. A page still
/// loading (or a 304 reload, which carries no body we may digest) reports
/// NoMainResource -- the UI's `no_page` copy already names the usual cause.
pub fn request_main_resource_bytes(
    webview: &WebView,
    token: u64,
    proxy: &EventLoopProxy<UserEvent>,
) {
    use crate::page_integrity::{IntegrityEvent, PageBytesError};
    use webview2_com::take_pwstr;
    use windows::core::{Interface, PWSTR};
    use wry::WebViewExtWindows;

    let send = |result: Result<Vec<u8>, PageBytesError>| {
        let _ = proxy.send_event(UserEvent::Integrity(IntegrityEvent::PageBytes { token, result }));
    };

    let core = webview.webview();
    let key = core.as_raw() as usize;

    let mut source = PWSTR::null();
    // SAFETY: `source` is a valid out-pointer; take_pwstr frees what the
    // engine allocated.
    let committed = match unsafe { core.Source(&mut source) } {
        Ok(()) => take_pwstr(source),
        Err(error) => {
            diag(&format!("page-bytes: Source read FAILED: {error}"));
            send(Err(PageBytesError::FetchFailed));
            return;
        }
    };

    let result = PAGE_BYTES_TRACKERS
        .with(|tabs| {
            tabs.borrow()
                .get(&key)
                .and_then(|tracker| tracker.borrow().serve(&committed))
        })
        .unwrap_or(Err(PageBytesError::NoMainResource));
    send(result);
}

/// Whether network-level request blocking is real on this backend.
///
/// True: the `WebResourceRequested` handler above answers 403 before the
/// request leaves, matching against the same `RuleSet` the unix content
/// filter compiles. Both engines therefore block an identical set.
///
/// As on unix, this covers requests the WEB ENGINE makes. It is not a
/// firewall.
pub fn network_blocking_supported() -> bool {
    true
}

/// Whether the freeze CONTROL is available on this backend.
///
/// True: the mechanism exists, so the button is offered. It is a platform
/// capability flag and nothing more -- whether a given tab's freeze is
/// actually holding is per-tab, and lives in `freeze_enforcement`. Reading
/// this as "freezing works" is the mistake that shipped: the old backend
/// answered true here and claimed enforcement unconditionally, on a build
/// no WebView2 runtime had ever executed.
pub fn freeze_enforced() -> bool {
    true
}

/// Manual freeze: immediate request, honest reporting.
///
/// The previous version called `note_enforced()` on the next line, arguing
/// that a per-request handler leaves no window in which a frozen tab still
/// makes requests. The first behavioural measurement of this backend
/// (2026-07-25, commit 98ec725) recorded ten fetches leaving a tab whose
/// toolbar read "Frozen. It is making no network requests." The reasoning
/// was sound and the code was wrong, which is the whole argument for
/// reporting what the ENGINE did rather than what we expect it to do.
///
/// So enforcement now starts Pending and is settled by
/// `freeze_with_interception`: Failed at once when this tab has no working
/// handler (or only the worker-blind legacy filter), otherwise Pending
/// until the engine accepts a synthesized 403 for a freeze-motivated
/// block. Same rule as unix, where only the filter-save callback confirms.
pub fn freeze(_webview: &WebView, view: &TabView) {
    let mut st = view.state.borrow_mut();
    let interception = st.interception;
    st.freeze.freeze_with_interception(interception);
    diag(&format!(
        "freeze: requested; interception={} events_seen={} -> enforcement={}",
        interception.as_str(),
        st.handler_events,
        st.freeze.enforcement().as_str()
    ));
}

/// One-call unfreeze.
pub fn unfreeze(_webview: &WebView, view: &TabView) {
    view.state
        .borrow_mut()
        .freeze
        .unfreeze(Instant::now());
}

/// Per-site override: `host` is allowed even while the tab is frozen. The
/// request handler consults overrides per request, so no engine work.
pub fn allow_site(_webview: &WebView, view: &TabView, host: &str) {
    view.state.borrow_mut().freeze.add_override(host);
}

/// The user-visible ledger: every host the tab contacted THAT REACHED THE
/// HANDLER, with allowed and blocked counts. This backend observes blocked
/// requests directly, unlike the unix content blocker (see the Note on
/// unix's ledger()).
///
/// The qualifier is not pedantry. On a runtime too old for
/// `ICoreWebView2_22` the filter falls back to the legacy overload, which
/// implies request source kind DOCUMENT -- so worker-sourced requests never
/// reach the handler, are never blocked by the ad rules, and are never
/// counted here. `interception_state()` reports `registered_legacy` when
/// that is the case, and the panel must say so rather than presenting this
/// list as complete. Freeze already refuses to claim enforcement on such a
/// runtime; ad blocking and this ledger degrade quietly, which is why the
/// state is exposed.
pub fn ledger(view: &TabView) -> Vec<HostRecord> {
    view.state.borrow().ledger.snapshot()
}

/// Requests blocked in this tab, totalled. Rides on `tab_status` for the
/// shield badge; see `Ledger::blocked_total`.
pub fn blocked_total(view: &TabView) -> u64 {
    view.state.borrow().ledger.blocked_total()
}

/// Current TLS verdict. Deviation from the brief's sketch: takes `view` as
/// well, to match the unix signature (which needs the stored error verdict).
///
/// Note: WebView2 has no API to read the serving certificate's chain
/// or issuer for the current page -- ServerCertificateErrorDetected fires
/// only on errors and exposes no issuer either. Guessing would
/// false-positive on exactly the corporate machines this feature must
/// tolerate, so this backend classifies nothing.
///
/// It reports `Unreadable`, NOT `Unknown`, and the difference is the whole
/// point: `Unknown` means an issuer was looked at and not recognized, which
/// on this backend never happens -- there is nothing to look at. The UI copy
/// for `Unknown` said the browser did not recognize the issuer, which was
/// false on every Windows page load, including ordinary public certificates.
/// Same conflation `SettingState` splits into NotAttempted vs Failed.
/// Revisit if a future SDK adds chain inspection.
pub fn tls_state(_webview: &WebView, view: &TabView) -> TlsState {
    view.state
        .borrow()
        .tls_error_verdict
        .unwrap_or(TlsState::Unreadable)
}

/// Persistent vs. ephemeral, for the UI to display. See the privacy.rs
/// module docs before writing any user-facing wording: ephemeral is
/// memory-only, not shredded (swap/hibernation can still reach disk).
///
/// Reads `TabState::profile_mode`, which answers from the engine's confirmed
/// in-private flag rather than from the policy that requested it.
pub fn profile_mode(view: &TabView) -> ProfileMode {
    view.state.borrow().profile_mode()
}

pub fn freeze_phase(view: &TabView) -> FreezePhase {
    view.state.borrow().freeze.phase()
}

/// Whether the block behind a freeze is actually in place. See
/// `privacy::FreezeEnforcement`.
pub fn freeze_enforcement(view: &TabView) -> privacy::FreezeEnforcement {
    view.state.borrow().freeze.enforcement()
}

/// The engine answers recorded outside `apply_policy`: SmartScreen off,
/// STRICT tracking prevention and the engine's own autofill from
/// `harden_privacy`, navigation-handler registration from tab construction.
/// Same rule as `script_setting`: what the engine CONFIRMED, not what was
/// requested.
pub fn engine_settings(view: &TabView) -> EngineSettings {
    let st = view.state.borrow();
    EngineSettings {
        smartscreen_off: st.smartscreen_off.as_str(),
        tracking_prevention: st.tracking_prevention.as_str(),
        navigation_tracking: st.navigation_tracking.as_str(),
        autofill_off: st.autofill_off.as_str(),
        ephemeral_confirmed: st.ephemeral_confirmed.as_str(),
        hardened_environment: hardened_environment().as_str(),
        session_lock_registered: session_lock_registered().as_str(),
        content_script_registered: st.content_script_registered.as_str(),
        permissions_registered: st.permissions_registered.as_str(),
        // Same source as the unix backend: the tunnel is the one setting
        // here that is genuinely cross-platform, so both engines read the
        // one measured answer in tunnel_control.
        tunnel: crate::tunnel_control::report(),
    }
}

/// Whether the ENGINE confirmed this tab's JavaScript setting.
///
/// `TabPolicy::javascript` is the ask; this is the answer. They diverge when
/// a COM setter fails, and the panel must present the answer, or it counts a
/// protection the tab does not have.
pub fn script_setting(view: &TabView) -> &'static str {
    view.state.borrow().script_setting.as_str()
}

/// How far this tab's request interception got. Reported in `tab_status` so
/// a probe run (or a future panel) can tell "no handler was ever registered"
/// apart from "registered, but the block is not sticking" -- two failures
/// that look identical from the outside and need completely different fixes.
pub fn interception_state(view: &TabView) -> &'static str {
    view.state.borrow().interception.as_str()
}

/// WebView2 downloads are native; the unix webkit2gtk workaround does not
/// exist (and would not compile) here.
pub fn fix_downloads(_webview: &WebView) {}

pub fn show_tab(_view: &TabView, webview: &WebView) {
    let _ = webview.set_visible(true);
    // Each WebView2 child has its own HWND, so keyboard focus must be moved
    // explicitly when a tab becomes visible (best-effort).
    let _ = webview.focus();
}

pub fn hide_tab(_view: &TabView, webview: &WebView) {
    let _ = webview.set_visible(false);
}

// ---- find in page ----
//
// WebView2's Find API (SDK 1.0.2903+) is reached through two interfaces an
// older runtime may not have: ICoreWebView2_28 and ICoreWebView2Environment15.
// Either cast can fail on a machine the browser otherwise runs fine on, so
// every step fails CLOSED: diag the reason, report unavailable, and let the
// chrome show its unsupported line. Same registration-honesty discipline as
// the page-bytes pipeline: the bar reflects what actually registered.

struct WinFindSession {
    find: webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Find,
    options: webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2FindOptions,
    /// Shared with the two change-event closures. Counts quote whatever
    /// generation is current AT EMIT TIME; find_start rewrites it per query,
    /// which is what lets a late callback from an abandoned query be dropped
    /// by state.rs instead of painted beside the new one.
    generation: std::rc::Rc<std::cell::Cell<u64>>,
    match_token: i64,
    active_token: i64,
}

thread_local! {
    /// Keyed by the content webview's raw ICoreWebView2 pointer, the same key
    /// PAGE_BYTES_TRACKERS uses, so every per-tab table agrees on identity.
    /// Entries MUST leave with their tab (find_teardown in remove_tab): a key
    /// that outlives its webview can collide with a new webview reusing the
    /// freed address, and counts would then route into the wrong tab's bar.
    static FIND_SESSIONS: std::cell::RefCell<std::collections::HashMap<usize, WinFindSession>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Identity key shared by FIND_SESSIONS and by the UserEvent the callbacks
/// emit. state.rs compares this against the active tab before forwarding a
/// count to the chrome.
pub fn find_key(webview: &WebView) -> usize {
    use windows::core::Interface;
    use wry::WebViewExtWindows;
    webview.webview().as_raw() as usize
}

/// Cheap availability check used to word the bar BEFORE the user types: can
/// this runtime hand us the find interfaces at all. Deliberately shallower
/// than a real session (no handlers registered): its job is wording, and the
/// authoritative answer is find_start's own return, which the chrome applies
/// to the same UI on the first real query.
pub fn find_probe(webview: &WebView) -> bool {
    use wry::WebViewExtWindows;
    find_interfaces(&webview.webview()).is_some()
}

fn find_interfaces(
    core: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2,
) -> Option<(
    webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Find,
    webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2FindOptions,
)> {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2Environment15, ICoreWebView2_2, ICoreWebView2_28,
    };
    use windows::core::Interface;

    let core28 = match core.cast::<ICoreWebView2_28>() {
        Ok(c) => c,
        Err(error) => {
            diag(&format!(
                "find: ICoreWebView2_28 cast FAILED (runtime predates the Find API): {error}"
            ));
            return None;
        }
    };
    // SAFETY: COM calls; every result is checked, nothing fails open.
    let find = match unsafe { core28.Find() } {
        Ok(find) => find,
        Err(error) => {
            diag(&format!("find: ICoreWebView2_28::Find FAILED: {error}"));
            return None;
        }
    };
    // ICoreWebView2_2 is ancient, but it is the hop to Environment, so it is
    // cast and checked like everything else rather than assumed.
    let core2 = match core.cast::<ICoreWebView2_2>() {
        Ok(c) => c,
        Err(error) => {
            diag(&format!("find: ICoreWebView2_2 cast FAILED: {error}"));
            return None;
        }
    };
    let env = match unsafe { core2.Environment() } {
        Ok(env) => env,
        Err(error) => {
            diag(&format!("find: Environment read FAILED: {error}"));
            return None;
        }
    };
    let env15 = match env.cast::<ICoreWebView2Environment15>() {
        Ok(e) => e,
        Err(error) => {
            diag(&format!(
                "find: ICoreWebView2Environment15 cast FAILED (runtime predates find options): {error}"
            ));
            return None;
        }
    };
    let options = match unsafe { env15.CreateFindOptions() } {
        Ok(options) => options,
        Err(error) => {
            diag(&format!("find: CreateFindOptions FAILED: {error}"));
            return None;
        }
    };
    Some((find, options))
}

fn find_create_session(
    core: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2,
    key: usize,
    proxy: &EventLoopProxy<UserEvent>,
) -> Option<WinFindSession> {
    use webview2_com::{
        FindActiveMatchIndexChangedEventHandler, FindMatchCountChangedEventHandler,
    };

    let (find, options) = find_interfaces(core)?;

    // Fixed v1 policy: case-insensitive, highlight all, no whole-word.
    // These three degrade mildly if a setter fails (each engine default
    // matches or approximates the policy), so they diag and continue.
    // SAFETY: COM setters, results checked below.
    for (name, result) in [
        ("SetIsCaseSensitive", unsafe { options.SetIsCaseSensitive(false) }),
        ("SetShouldHighlightAllMatches", unsafe {
            options.SetShouldHighlightAllMatches(true)
        }),
        ("SetShouldMatchWord", unsafe { options.SetShouldMatchWord(false) }),
    ] {
        if let Err(error) = result {
            diag(&format!(
                "find: {name} FAILED (continuing with the engine default): {error}"
            ));
        }
    }
    // The default-dialog suppression is NOT allowed to degrade: two find UIs
    // at once is worse than none, so a failure here fails the session and
    // the bar honestly reports unavailable.
    if let Err(error) = unsafe { options.SetSuppressDefaultFindDialog(true) } {
        diag(&format!(
            "find: SetSuppressDefaultFindDialog FAILED; refusing a second find UI: {error}"
        ));
        return None;
    }

    let generation = std::rc::Rc::new(std::cell::Cell::new(0u64));

    let mut match_token: i64 = 0;
    let count_find = find.clone();
    let count_gen = generation.clone();
    let count_proxy = proxy.clone();
    let on_count = FindMatchCountChangedEventHandler::create(Box::new(move |_, _| {
        find_emit_counts(&count_find, key, count_gen.get(), &count_proxy);
        Ok(())
    }));
    // SAFETY: registration; token receives the id used at teardown.
    if let Err(error) = unsafe { find.add_MatchCountChanged(&on_count, &mut match_token) } {
        diag(&format!("find: add_MatchCountChanged FAILED: {error}"));
        return None;
    }

    let mut active_token: i64 = 0;
    let active_find = find.clone();
    let active_gen = generation.clone();
    let active_proxy = proxy.clone();
    let on_active = FindActiveMatchIndexChangedEventHandler::create(Box::new(move |_, _| {
        find_emit_counts(&active_find, key, active_gen.get(), &active_proxy);
        Ok(())
    }));
    if let Err(error) = unsafe { find.add_ActiveMatchIndexChanged(&on_active, &mut active_token) }
    {
        diag(&format!("find: add_ActiveMatchIndexChanged FAILED: {error}"));
        // Do not leave the count handler registered for a session we are
        // about to drop: it would keep emitting counts nobody owns.
        // SAFETY: unregistering the token registered above.
        let _ = unsafe { find.remove_MatchCountChanged(match_token) };
        return None;
    }

    Some(WinFindSession {
        find,
        options,
        generation,
        match_token,
        active_token,
    })
}

fn find_emit_counts(
    find: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Find,
    key: usize,
    generation: u64,
    proxy: &EventLoopProxy<UserEvent>,
) {
    let mut total: i32 = 0;
    // SAFETY: out-param reads; failures drop the emit rather than guessing.
    if let Err(error) = unsafe { find.MatchCount(&mut total) } {
        diag(&format!("find: MatchCount read FAILED: {error}"));
        return;
    }
    let mut active: i32 = 0;
    if let Err(error) = unsafe { find.ActiveMatchIndex(&mut active) } {
        diag(&format!("find: ActiveMatchIndex read FAILED: {error}"));
        return;
    }
    // The SDK reports the active index 1-based with -1 for "none". Anything
    // below 1 normalises to None so find.rs never has to know which engine a
    // count came from. (Hardware check: stepping should move "1 of N" to
    // "2 of N"; an off-by-one here means the contract read differently.)
    let active = if active >= 1 { Some(active as u32) } else { None };
    let total = if total > 0 { total as u32 } else { 0 };
    // WebView2 documents no count cap the way WebKitGTK's max does.
    let _ = proxy.send_event(UserEvent::Find(crate::find::FindEvent {
        key,
        generation,
        active,
        total,
        capped: false,
    }));
}

/// Starts (or re-terms) the find session for this tab's webview. Returns
/// whether find is available, so the chrome can swap its input for the
/// unsupported line on an old runtime. The query goes ONLY into the engine's
/// find options -- never near a script string.
pub fn find_start(
    webview: &WebView,
    query: &str,
    generation: u64,
    proxy: &EventLoopProxy<UserEvent>,
) -> bool {
    use webview2_com::FindStartCompletedHandler;
    use windows::core::{Interface, PCWSTR};
    use wry::WebViewExtWindows;
    let core = webview.webview();
    let key = core.as_raw() as usize;

    let session = match FIND_SESSIONS.with(|s| s.borrow_mut().remove(&key)) {
        Some(session) => session,
        None => match find_create_session(&core, key, proxy) {
            Some(session) => session,
            None => return false,
        },
    };
    // Counts emitted from here on describe THIS query.
    session.generation.set(generation);

    let mut wide: Vec<u16> = query.encode_utf16().collect();
    wide.push(0);
    // SAFETY: `wide` outlives the call and the setter copies the term (input
    // LPCWSTR by SDK contract). If the copy assumption were ever wrong the
    // symptom would be a stale term, not memory the engine still owns.
    if let Err(error) = unsafe { session.options.SetFindTerm(PCWSTR(wide.as_ptr())) } {
        diag(&format!("find: SetFindTerm FAILED: {error}"));
        find_destroy_session(session);
        return false;
    }

    // The completion itself is uninteresting -- counts arrive via the change
    // events -- but a failed Start must not leave a session cached as live.
    let done = FindStartCompletedHandler::create(Box::new(|_error_code| Ok(())));
    // SAFETY: Start takes the options and completion handler by COM ref.
    match unsafe { session.find.Start(&session.options, &done) } {
        Ok(()) => {
            FIND_SESSIONS.with(|s| s.borrow_mut().insert(key, session));
            true
        }
        Err(error) => {
            diag(&format!("find: Start FAILED: {error}"));
            find_destroy_session(session);
            false
        }
    }
}

pub fn find_next(webview: &WebView) {
    find_step(webview, true);
}

pub fn find_previous(webview: &WebView) {
    find_step(webview, false);
}

fn find_step(webview: &WebView, forward: bool) {
    let key = find_key(webview);
    FIND_SESSIONS.with(|sessions| {
        let sessions = sessions.borrow();
        // No entry is the NORMAL case (F3 with no live session) and stays
        // silent; a present-but-failing call is the one worth a diag line.
        let Some(session) = sessions.get(&key) else {
            return;
        };
        // SAFETY: COM step calls on a live session.
        let result = unsafe {
            if forward {
                session.find.FindNext()
            } else {
                session.find.FindPrevious()
            }
        };
        if let Err(error) = result {
            diag(&format!("find: step FAILED: {error}"));
        }
    });
}

/// Stops the session and clears highlights. Idempotent by design: the bar's
/// close, a tab switch and a tab close can all ask, in any order.
pub fn find_stop(webview: &WebView) {
    let key = find_key(webview);
    let session = FIND_SESSIONS.with(|s| s.borrow_mut().remove(&key));
    if let Some(session) = session {
        find_destroy_session(session);
    }
}

/// Tab-close hook. Same work as find_stop today, kept as a separate name so
/// the tab-close path says what it means -- and so the day teardown grows,
/// callers are already right.
pub fn find_teardown(webview: &WebView) {
    find_stop(webview);
}

fn find_destroy_session(session: WinFindSession) {
    // Order: Stop first (clears highlights, ends callbacks), then unregister.
    // A handler left registered after the session is gone would keep emitting
    // counts for a session nobody owns.
    // SAFETY: COM teardown of objects this module registered.
    if let Err(error) = unsafe { session.find.Stop() } {
        diag(&format!("find: Stop FAILED: {error}"));
    }
    if let Err(error) = unsafe { session.find.remove_MatchCountChanged(session.match_token) } {
        diag(&format!("find: remove_MatchCountChanged FAILED: {error}"));
    }
    if let Err(error) =
        unsafe { session.find.remove_ActiveMatchIndexChanged(session.active_token) }
    {
        diag(&format!("find: remove_ActiveMatchIndexChanged FAILED: {error}"));
    }
}

// ---- page color scheme ----

/// Ask the engine to report the given prefers-color-scheme to pages.
/// Profile-wide, so one call covers every tab sharing the environment.
/// Returns whether the engine ACKNOWLEDGED the setting -- an older runtime
/// without ICoreWebView2_13 reports false and the UI says the preference
/// could not be applied, rather than claiming a theme nothing enforces.
pub fn apply_page_theme(webview: &WebView, theme: crate::prefs::PageTheme) -> bool {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_13, COREWEBVIEW2_PREFERRED_COLOR_SCHEME_AUTO,
        COREWEBVIEW2_PREFERRED_COLOR_SCHEME_DARK, COREWEBVIEW2_PREFERRED_COLOR_SCHEME_LIGHT,
    };
    use windows::core::Interface;
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let core13 = match core.cast::<ICoreWebView2_13>() {
        Ok(c) => c,
        Err(error) => {
            diag(&format!(
                "page-theme: ICoreWebView2_13 cast FAILED (runtime predates profiles): {error}"
            ));
            return false;
        }
    };
    // SAFETY: COM calls; every result checked, a failure reports not-applied.
    let profile = match unsafe { core13.Profile() } {
        Ok(profile) => profile,
        Err(error) => {
            diag(&format!("page-theme: Profile read FAILED: {error}"));
            return false;
        }
    };
    let scheme = match theme {
        crate::prefs::PageTheme::Auto => COREWEBVIEW2_PREFERRED_COLOR_SCHEME_AUTO,
        crate::prefs::PageTheme::Dark => COREWEBVIEW2_PREFERRED_COLOR_SCHEME_DARK,
        crate::prefs::PageTheme::Light => COREWEBVIEW2_PREFERRED_COLOR_SCHEME_LIGHT,
    };
    match unsafe { profile.SetPreferredColorScheme(scheme) } {
        Ok(()) => true,
        Err(error) => {
            diag(&format!("page-theme: SetPreferredColorScheme FAILED: {error}"));
            false
        }
    }
}

// ---- page capture ----

/// Ask WebView2 for a PNG of the VISIBLE VIEWPORT and deliver the bytes (or
/// an honest failure) as a UserEvent. CapturePreview is all the engine
/// offers; faking a full page by resizing the real webview would repaint
/// the user's window and lie about what was on screen, so the smaller
/// honest scope ships and the labels say so.
pub fn capture_page(webview: &WebView, proxy: &EventLoopProxy<UserEvent>) {
    use webview2_com::CapturePreviewCompletedHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG;
    use windows::Win32::System::Com::{STREAM_SEEK_SET};
    use windows::Win32::UI::Shell::SHCreateMemStream;
    use wry::WebViewExtWindows;

    let core = webview.webview();
    let fail = |proxy: &EventLoopProxy<UserEvent>| {
        let _ = proxy.send_event(UserEvent::Capture(crate::capture::CaptureEvent {
            png: Err("capture_failed"),
        }));
    };
    // SAFETY: COM interop; every result checked, failures reported as an
    // event so the user is never left waiting on a capture that died.
    unsafe {
        let Some(stream) = SHCreateMemStream(None) else {
            diag("capture: SHCreateMemStream FAILED");
            fail(proxy);
            return;
        };
        let done_stream = stream.clone();
        let done_proxy = proxy.clone();
        let handler = CapturePreviewCompletedHandler::create(Box::new(move |error_code| {
            let png: Result<Vec<u8>, &'static str> = (|| {
                if let Err(error) = &error_code {
                    diag(&format!("capture: CapturePreview FAILED: {error}"));
                    return Err("capture_failed");
                }
                // The engine wrote the PNG; rewind before reading it back.
                // SAFETY: COM stream owned by this closure.
                if let Err(error) = unsafe { done_stream.Seek(0, STREAM_SEEK_SET, None) } {
                    diag(&format!("capture: stream Seek FAILED: {error}"));
                    return Err("capture_failed");
                }
                read_stream_capped(&done_stream).map_err(|_| "capture_failed")
            })();
            let _ = done_proxy.send_event(UserEvent::Capture(crate::capture::CaptureEvent { png }));
            Ok(())
        }));
        if let Err(error) = core.CapturePreview(
            COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG,
            &stream,
            &handler,
        ) {
            diag(&format!("capture: CapturePreview call FAILED: {error}"));
            fail(proxy);
        }
    }
}

pub fn remove_tab(view: &TabView, webview: &WebView) {
    // The controller needs no detaching: dropping the tab's WebView field is
    // what destroys the WebView2. (On unix the container must first be
    // removed from its GTK parent.) What DOES need releasing is this tab's
    // cached main-resource bytes, which live in a process-lived map and
    // would otherwise be retained for every tab ever closed.
    drop_page_bytes_tracker(webview);
    // Same reasoning for the find session: its COM handlers and map entry
    // must not outlive the tab, or a new webview reusing the address would
    // inherit them.
    find_teardown(webview);
    // The tab's refusals move into the session receipt. mem::take, not a
    // read: the fold must MOVE the count so a teardown that ever ran twice
    // would fold zero the second time, never a copy.
    privacy::fold_closed_tab(std::mem::take(&mut view.state.borrow_mut().ledger));
}

/// The chrome height lives in AppState and is applied by layout(); there is
/// no GTK size-request to update here.
pub fn set_chrome_height(_hosts: &Hosts, _px: i32) {}

/// Re-apply bounds for the chrome strip (top `chrome_height` logical
/// pixels, full width) and the active tab's webview (the rest). Inactive
/// tabs stay hidden and get correct bounds when next activated.
pub fn layout(
    hosts: &Hosts,
    chrome: &WebView,
    active: Option<&WebView>,
    chrome_height: i32,
    arrangement: ChromeLayout,
) {
    // THE ONE FACT EVERY ARRANGEMENT BELOW RESTS ON: content webviews are
    // created AFTER the chrome, so where the two overlap the CONTENT draws
    // over the chrome. Nothing is composited -- these are sibling child
    // windows -- so the chrome is never "on top of" anything. It is visible
    // exactly where the content is not.
    //
    // That inverts how these look at first glance. Giving the chrome the whole
    // window does not hide the page; it only means the chrome fills whatever
    // the page's rectangle leaves over.
    //
    // The hover readout first: everything that reaches this function -- tab
    // switch, tab close, arrangement change, resize, scale change -- has
    // moved either the pointer's meaning or the window it sits in, so the
    // readout describes a link that is no longer under the pointer. Hide
    // unconditionally (the next mouse move re-shows it, with a font rebuilt
    // for the current scale) and suppress outright during Overlay: a modal
    // covers the page, so a readout floating over it would claim something
    // the user can neither see nor click -- and it would fight the raised
    // chrome for z-order. Split is NOT suppressed: the page stays visible and
    // still reaches the window's bottom-left, which is where the readout sits.
    READOUT_SUPPRESSED.store(
        matches!(arrangement, ChromeLayout::Overlay),
        Ordering::Relaxed,
    );
    READOUT_SCALE.store(hosts.window.scale_factor().to_bits(), Ordering::Relaxed);
    readout_apply(None);

    let size = hosts
        .window
        .inner_size()
        .to_logical::<f64>(hosts.window.scale_factor());

    match arrangement {
        ChromeLayout::Strip => {
            let _ = set_chrome_z(hosts, false);
            let _ = chrome.set_bounds(chrome_rect(&hosts.window, chrome_height));
            if let Some(webview) = active {
                let _ = webview.set_bounds(content_rect(&hosts.window, chrome_height));
            }
        }

        // A modal. Two geometries, decided by what `arm_translucent_overlay`
        // proved at startup:
        //
        // LIFTED (the modern path): the content KEEPS its normal rectangle
        // and keeps rendering -- the video keeps playing -- while the chrome
        // takes the whole window and is raised ABOVE the content in the
        // sibling z-order, with a transparent default background. The page
        // shows through wherever the chrome paints nothing, and the CSS
        // scrim (`translucent-backdrop`) dims a page that is really there.
        // Input goes wholly to the chrome, which is exactly what modal
        // means; a click on the scrim closes the panel as before.
        //
        // LEGACY (the fallback): the chrome takes the window and the page is
        // given a zero rect -- a zero-size sibling cannot draw over
        // anything, which without the lift is the only way to put the chrome
        // in front at all. The page is genuinely NOT visible and the solid
        // scrim says so. This is the whole behaviour on runtimes where the
        // lift could not be armed, and the UI knows which world it is in via
        // `chrome_caps`.
        ChromeLayout::Overlay => {
            let _ = chrome.set_bounds(Rect {
                position: LogicalPosition::new(0.0, 0.0).into(),
                size: LogicalSize::new(size.width, size.height).into(),
            });
            if translucent_overlay_supported() {
                // The return value stays CHECKED rather than discarded: an
                // unraised chrome is drawn over by the page, and that silent
                // no-op was a live suspect while the band was open.
                if !set_chrome_z(hosts, true) {
                    diag("layout: overlay wanted, but the chrome could not be raised");
                }
                // THE PAGE IS NOT MOVED AT ALL, and that is the point.
                //
                // Opening a modal must not change where the page sits. Every
                // attempt to RECOMPUTE its position here has been wrong by
                // some amount and the error is always visible: laying it out
                // against `chrome_height` pushed it down by the whole panel
                // height, and against a separately-tracked strip height pulled
                // it ~12px UP,
                // exposing a sliver of undimmed page above the scrim -- a band
                // whose colour tracked the site, white on bbc.com and grey on
                // google.com, which is how it was identified.
                //
                // There is no correct number to compute, because the right
                // answer is "wherever it already was". Rust seeds its idea of
                // the strip from CHROME_HEIGHT_PX (120) while chrome.js
                // measures itself against a floor of 148 -- two constants for
                // one quantity, and any arithmetic mixing them inherits the
                // gap.
                //
                // KNOWN LIMIT: resizing the window while a modal is open
                // leaves the page at its old size until the modal closes and
                // the Strip arm below re-applies bounds. A stale rect for the
                // seconds a modal is open is a far smaller defect than a band
                // that is wrong every single time one opens.
            } else if let Some(webview) = active {
                let _ = webview.set_bounds(Rect {
                    position: LogicalPosition::new(0.0, 0.0).into(),
                    size: LogicalSize::new(0.0, 0.0).into(),
                });
            }
        }

        // A docked pane, and the page STAYS VISIBLE beside it -- which is the
        // whole reason this arrangement exists. Chat used to be a modal, so
        // reading a conversation meant covering the page, and closing the
        // panel to look at the page destroyed the conversation.
        //
        // The chrome takes the window and the page is given the area below the
        // strip and left of the pane. The page draws over the chrome in that
        // rectangle, so the chrome shows through in exactly two places: the
        // strip along the top, and the pane's column down the right.
        //
        // The pane is clamped so it can never take the window: a page squeezed
        // to nothing is not a browser, and a drag handle that can do that is a
        // trap rather than a control.
        ChromeLayout::Split { pane_width } => {
            set_chrome_z(hosts, false);
            let top = f64::from(chrome_height.max(0));
            let max_pane = (size.width * MAX_PANE_FRACTION).max(0.0);
            let pane = f64::from(pane_width.max(0)).clamp(0.0, max_pane);
            let page_width = (size.width - pane).max(0.0);

            let _ = chrome.set_bounds(Rect {
                position: LogicalPosition::new(0.0, 0.0).into(),
                size: LogicalSize::new(size.width, size.height).into(),
            });
            if let Some(webview) = active {
                let _ = webview.set_bounds(Rect {
                    position: LogicalPosition::new(0.0, top).into(),
                    size: LogicalSize::new(page_width, (size.height - top).max(0.0)).into(),
                });
            }
        }
    }
}

/// The most of the window a docked pane may take.
///
/// Half. Past that the page stops being the thing you are looking at, and a
/// browser whose page area is a minority of the window has stopped being a
/// browser. The clamp lives here rather than in the UI so a bad width from any
/// caller -- a dragged handle, a restored setting, a malformed IPC frame --
/// lands somewhere survivable.
const MAX_PANE_FRACTION: f64 = 0.5;

/// Whether a docked pane can actually be laid out on this backend.
pub fn split_supported() -> bool {
    true
}

// Note: bounds are computed in logical pixels, assuming wry converts
// Logical rect components with the window's scale factor internally before
// calling WebView2's (physical) put_Bounds. If a manual HiDPI test shows
// mis-scaled/misplaced webviews, switch these to Physical using
// window.inner_size() directly and chrome_height * scale_factor.
/// Raises or restores the chrome in the SIBLING z-order.
///
/// `top` lifts it above every content webview for the translucent modal;
/// `false` sends it to the bottom, which restores the invariant every other
/// arrangement rests on -- content created later, content drawing over the
/// chrome. HWND_BOTTOM rather than remembering the previous neighbour: the
/// set of content webviews changes as tabs open and close, and "below all of
/// them" is the actual requirement, not "where it was".
///
/// A no-op when the chrome child was never captured, which also makes it a
/// no-op wherever the lift is unarmed -- callers do not need to ask twice.
/// Returns whether the raise was actually ATTEMPTED. It silently did nothing
/// when the chrome's child HWND had never been captured, which is
/// indistinguishable from success at every call site -- and an unraised chrome
/// is drawn over by the page, because content webviews are created later.
fn set_chrome_z(hosts: &Hosts, top: bool) -> bool {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowPos, HWND_BOTTOM, HWND_TOP, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
    };
    let raw = hosts.chrome_child.get();
    if raw == 0 {
        diag("set_chrome_z: chrome child HWND never captured -- NOT raised");
        return false;
    }
    let after = if top { HWND_TOP } else { HWND_BOTTOM };
    unsafe {
        let _ = SetWindowPos(
            HWND(raw as _),
            Some(after),
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
        );
    }
    true
}

fn chrome_rect(window: &Window, chrome_height: i32) -> Rect {
    let size = window.inner_size().to_logical::<f64>(window.scale_factor());
    Rect {
        position: LogicalPosition::new(0.0, 0.0).into(),
        size: LogicalSize::new(size.width, f64::from(chrome_height.max(0))).into(),
    }
}

fn content_rect(window: &Window, chrome_height: i32) -> Rect {
    let size = window.inner_size().to_logical::<f64>(window.scale_factor());
    let top = f64::from(chrome_height.max(0));
    Rect {
        position: LogicalPosition::new(0.0, top).into(),
        size: LogicalSize::new(size.width, (size.height - top).max(0.0)).into(),
    }
}

/// Runtime WebView2 version.
///
/// No floor is enforced here, deliberately. The WebView2 Evergreen runtime
/// updates itself out of band from this application, so a stale one is not a
/// state the user can be in for long and not one we would be right to nag
/// about. The version is still reported, because "which engine am I actually
/// running" is a question a privacy browser should answer on both platforms.
pub fn engine_info() -> crate::platform::EngineInfo {
    use webview2_com::Microsoft::Web::WebView2::Win32::GetAvailableCoreWebView2BrowserVersionString;
    use windows::core::PCWSTR;

    // SAFETY: the runtime writes an allocated wide string we must free with
    // CoTaskMemFree; a null browser-executable folder means "use the
    // installed Evergreen runtime".
    let version = unsafe {
        let mut raw = windows::core::PWSTR::null();
        match GetAvailableCoreWebView2BrowserVersionString(PCWSTR::null(), &mut raw) {
            Ok(()) if !raw.is_null() => {
                let text = raw.to_string().unwrap_or_default();
                windows::Win32::System::Com::CoTaskMemFree(Some(raw.0 as *const _));
                // "141.0.3537.57" -> (141, 0, 3537); the fourth field is
                // dropped because EngineInfo carries a semver-shaped triple.
                let mut parts = text.split('.').filter_map(|p| p.parse::<u32>().ok());
                match (parts.next(), parts.next(), parts.next()) {
                    (Some(a), Some(b), Some(c)) => Some((a, b, c)),
                    _ => None,
                }
            }
            _ => None,
        }
    };
    crate::platform::EngineInfo {
        name: "WebView2",
        version,
        below_floor: false,
        // Requested at build time in harden_privacy. Unlike the GTK side
        // there is no cheap read-back here (the getter lives on the profile,
        // which needs a live webview), so this states what was asked for.
        // Confirming it is a Windows runtime test, not something this
        // process can prove.
        tracking_prevention: "Tracking prevention: Strict (requested)",
    }
}

/// Drive the auto-freeze transition on a timer, and report the next deadline.
///
/// WHY THIS EXISTS. `should_block` performs the transition lazily, on the next
/// request, and the comment there says WebView2 therefore "needs no timer at
/// all". That reasoning covers ENFORCEMENT and not REPORTING, and the gap is
/// user-visible: a quiet loaded page with freeze-after-load enabled stayed at
/// phase Loaded forever, so the toolbar said "Live" on a tab that was armed to
/// freeze. The project owner reported it as the setting not working, which is the
/// only conclusion available from what the UI showed.
///
/// Linux never had this problem -- unix.rs schedules a GTK timeout on load
/// finish. This is the same thing, driven from the event loop's existing wait
/// rather than a new thread.
///
/// Returns `(changed, next_deadline)`. `changed` tells the caller to push a
/// fresh tab status; `next_deadline` lets the loop wake exactly when the grace
/// period ends instead of polling.
pub fn tick_auto_freeze(view: &TabView, now: Instant) -> (bool, Option<Instant>) {
    let mut st = view.state.borrow_mut();
    if st.freeze.should_auto_freeze(now) {
        st.freeze.freeze_auto_now();
        return (true, None);
    }
    (false, st.freeze.auto_freeze_deadline())
}
