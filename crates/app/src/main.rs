// Release builds on Windows must not allocate a console: without this the GUI
// opens with an empty black console window behind it. Debug builds keep the
// console, because --smoke-test reports SMOKE OK / SMOKE FAIL on stdout and
// scripts/smoke.ps1 runs the debug binary.
#![cfg_attr(
    all(windows, not(debug_assertions)),
    windows_subsystem = "windows"
)]

//! PATANYX Browser — tao event loop and the chrome webview setup.
//!
//! Security invariants enforced here:
//!   * the `rbchrome` custom protocol, the IPC handler, and all
//!     `evaluate_script` calls exist ONLY on the chrome webview;
//!   * the chrome webview may only navigate to its own origin; the origin's
//!     URL form is platform-specific (see platform::CHROME_ORIGIN_PREFIX);
//!   * content webviews (one per tab, built in state.rs) may only navigate
//!     to http/https/about:blank, may not open new windows (http/https
//!     targets open in a background tab instead), and have no custom
//!     protocol and no IPC.
//!
//! KNOWN LIMIT, stated because the invariant above would otherwise overclaim:
//! the scheme allowlist covers TOP-LEVEL navigation only on Windows. wry drives
//! it from WebView2's `NavigationStarting`, which does not fire for subframes,
//! and does not use `FrameNavigationStarting`. So an iframe inside a page is not
//! filtered by us there. The dangerous cases are still closed by the engine
//! itself (file:// is refused from an http origin, and the chrome origin in a
//! content webview has no custom protocol registered so it reaches only the
//! network), but this is engine behaviour rather than something we enforce.
//! Closing it properly needs a frame-aware hook wry does not currently expose.
//!
//! The same missing frame information cuts the other way on WebKitGTK, where
//! the navigation handler DOES fire for subframes. That is why the displayed URL
//! and history are driven from the page-load handler rather than from the
//! navigation handler; see the comment in state.rs::build_tab.
//!
//! All platform-specific window/webview glue lives in `platform`; this file
//! and the other modules are cfg-free.

/// Identity, licence and the third-party inventory for THIS binary. The
/// attribution is chosen by `cfg`, so a build cannot describe another build's
/// dependency set.
mod about;
/// Known-malicious hosts, refused in the navigation handler. Present in every
/// build: this is the protection for users who change no settings.
mod blocklist;
/// Chat exists only under `--features chat`, which is off by default. The
/// published browser contains none of it: `patanyx-chat` is an optional
/// dependency and this module is the only place the app references it.
#[cfg(feature = "chat")]
mod chat_panel;
mod ipc;
mod ocr_support;
mod prefs;
/// Page digesting and peer corroboration. Needs the page's real bytes, which
/// come from the ENGINE (never from evaluating script in a content webview).
mod page_integrity;
mod platform;
mod psl;
mod resolver_probe;
/// The browser's only self-initiated network activity, and its timing.
mod schedule;
mod bookmark_import;
mod capture;
mod find;
mod hover;
/// Colours, font metrics and geometry for the hover readout, kept apart from
/// both backends so the Windows-only arithmetic is testable on any box.
mod hover_style;
mod shelf;
mod shortcuts;
mod state;
/// Engine-side tunnel lifecycle: bind the proxy port before the vault
/// exists, start the tunnel when it opens. Unconditional, like the tunnel
/// crate itself.
mod licence_control;
mod tunnel_control;
/// Signed update checking. Verification is `patanyx-update`; this is the
/// fetch, decide and prompt layer around it.
mod updater;

use std::borrow::Cow;
use std::thread;
use std::time::Duration;

use serde_json::json;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::http;

use state::AppState;

/// wry callbacks never touch state directly; they only send these events
/// through an `EventLoopProxy` clone. All mutation happens in the match arms
/// of the event loop below. Note the new-window-request handler runs on a
/// separate thread on Windows: every closure sending these events captures
/// only `EventLoopProxy` clones (`Send`) plus Copy data — keep it that way.
enum UserEvent {
    Ipc(String),
    UrlChanged(u64, String),
    LoadState(u64, bool),
    TitleChanged(u64, String),
    OpenInNewTab(String),
    /// The behavioural blocking probe has had long enough to load.
    ProbeDone,
    DownloadStarted(String),
    DownloadDone {
        url: String,
        path: Option<String>,
        success: bool,
    },
    Shortcut(shortcuts::Shortcut),
    /// A key was pressed inside a PAGE. Carries nothing -- not the key, not a
    /// timestamp -- because the only thing it is used for is "a human is
    /// here", and a keystroke stream crossing this boundary would be a
    /// keylogger by another name.
    ///
    /// WHY KEYS AND NOT NAVIGATION. The vault auto-lock needs evidence that
    /// somebody is present. Navigation looks like the obvious signal and is
    /// unsafe: a page navigates itself with a meta refresh, a JS redirect or
    /// an ad frame, so one hostile tab could hold the vault open on an
    /// unattended machine forever. A physical keypress is delivered by the
    /// OS/host outside the page's reach and cannot be forged by content.
    ///
    /// Throttled at the source, so holding a key down does not flood the loop.
    UserPresence,
    /// The staged update was installed; this process must end so the
    /// relaunched one is the only browser left.
    QuitForUpdate,
    /// The engine zoomed a tab on keys this process never receives.
    ZoomFactorChanged(u64, f64),
    AutoLockTick,
    /// The user chose something from the right-click menu.
    ///
    /// Carries the target URL the menu was built from rather than re-reading
    /// it, because by the time this reaches the loop the page may have
    /// navigated and the target is gone. `target` is the link OR the image
    /// source, depending on the action -- one URL per event, never both.
    /// `action` is one of the `menu_ids` in platform/mod.rs; the loop maps it,
    /// and refuses anything it does not recognise rather than guessing.
    /// Editing commands (cut/copy/paste/select-all) never arrive here: they
    /// run engine-local in the platform layer.
    ContextMenuAction { action: u32, target: Option<String> },
    /// A save-as-PDF render finished, or failed. Carries the destination
    /// rather than a tab id: by the time this arrives the tab may have
    /// navigated or closed, and the path is what identifies the job.
    PdfSaved { path: String, success: bool },
    /// The workstation locked, or the machine is suspending.
    ///
    /// Carries nothing: what happened is the whole message, and the decision
    /// about whether to act on it (the `vault_lock_on_session_lock` pref)
    /// belongs on the event-loop side where the prefs live, not in a window
    /// procedure running on whatever stack Windows chose.
    SessionLocked,
    /// A finished OCR scan. Asynchronous for the same reason as Integrity
    /// below: the work is ~1s and IPC dispatch runs on this event loop, so
    /// doing it inline would freeze the browser before it could even paint
    /// the "scanning" state. See ocr_support.rs.
    Ocr(ocr_support::OcrEvent),
    /// A finished (or failed) page capture, from the engine's async callback.
    Capture(capture::CaptureEvent),
    /// An engine find callback, normalised by the platform layer. Carries the
    /// webview identity key so a count landing after a tab switch is dropped
    /// instead of painted onto another tab's bar.
    Find(find::FindEvent),
    /// Page bytes arriving from the engine's main-resource read, which is
    /// asynchronous. See page_integrity.rs.
    Integrity(page_integrity::IntegrityEvent),
    /// A navigation was refused because its host is on the malicious-host
    /// list. Carries the HOST and the matched rule, never the full URL: the
    /// path can hold a session token, and this event is rendered in the
    /// chrome and would end up in a log line.
    NavigationBlocked {
        tab_id: u64,
        host: String,
        rule: String,
    },
    /// A content tab's password form was submitted. Carries exactly what the
    /// save-password banner needs -- the PASSWORD IS HERE because the banner
    /// offers to save it on the strength of this one message, held only in
    /// `AppState::pending_save`'s in-memory slot until the user accepts (or
    /// dismisses, navigates, or switches tabs, any of which drops it
    /// unwritten). See `note_login_submitted` in state.rs.
    LoginSubmitted {
        tab_id: u64,
        origin: String,
        username: String,
        password: String,
    },
    /// An hourly blocklist refresh finished: the new list version and host
    /// count, or why it did not happen. A failure leaves the previous list in
    /// force and is reported, never swallowed -- a protection that silently
    /// stopped refreshing is the failure mode this channel exists to avoid.
    BlocklistRefreshed(Result<(u64, usize), String>),
    /// A scheduled update check finished. Carries the updater's own status
    /// snapshot; the chrome decides whether it is worth showing.
    UpdateChecked(serde_json::Value),
    /// A finished probe of the configured DNS resolver. Runs on a worker
    /// thread for the same reason OCR does: it is a network round trip with a
    /// multi-second timeout, and IPC dispatch runs on this event loop.
    ResolverProbe(bool),
    /// The resolver-unreachable banner should be shown or hidden. Carries the
    /// user's own setting name and nothing else — never a hostname or a URL.
    ResolverBanner { visible: bool, mode: &'static str },
    /// A transport event from the chat subsystem. The transport's callback
    /// runs on its own thread and, like every other callback here, only
    /// forwards — all mutation happens in the match arm below.
    #[cfg(feature = "chat")]
    Chat(patanyx_chat::TransportEvent),
}

/// Mirrors the CSP <meta> in chrome/index.html — keep the two in sync.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'";

const INDEX_HTML: &str = include_str!("chrome/index.html");
const CHROME_CSS: &str = include_str!("chrome/chrome.css");
const CHROME_JS: &str = include_str!("chrome/chrome.js");
/// Page-integrity and updater UI. Served like chrome.js rather than evaluated,
/// because unlike chat these exist in every build.
const INTEGRITY_JS: &str = include_str!("chrome/integrity.js");
const UPDATE_JS: &str = include_str!("chrome/update.js");

/// Whether devtools may be attached to the privileged chrome webview.
///
/// Deliberately separate from `debug_assertions`: a developer console inside
/// the trusted UI should be something someone asked for, not something that
/// ships with any debug build.
fn chrome_devtools_opted_in() -> bool {
    std::env::var_os("PATANYX_CHROME_DEVTOOLS").is_some_and(|value| value == "1")
}

fn serve_chrome(request: &http::Request<Vec<u8>>) -> http::Response<Cow<'static, [u8]>> {
    let (mime, body): (&str, &[u8]) = match request.uri().path() {
        "/" | "/index.html" => ("text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        "/chrome.css" => ("text/css; charset=utf-8", CHROME_CSS.as_bytes()),
        "/chrome.js" => ("text/javascript; charset=utf-8", CHROME_JS.as_bytes()),
        "/integrity.js" => ("text/javascript; charset=utf-8", INTEGRITY_JS.as_bytes()),
        "/update.js" => ("text/javascript; charset=utf-8", UPDATE_JS.as_bytes()),
        _ => {
            return http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Security-Policy", CSP)
                .body(Cow::Borrowed(&b"not found"[..]))
                .expect("static 404 response");
        }
    };
    http::Response::builder()
        .header("Content-Type", mime)
        .header("Content-Security-Policy", CSP)
        .body(Cow::Borrowed(body))
        .expect("static asset response")
}

/// Refuses to start a RELEASE build on an engine below the security floor.
///
/// A warning that never blocks becomes wallpaper, and this one would be
/// printed on every launch of a stock Debian 12 box, which is precisely how
/// users learn to stop reading warnings. Debug builds warn and continue so
/// development on an old runtime stays possible; release builds refuse,
/// because "we told you in a log line" is not a defence for shipping a
/// browser onto a runtime with known memory-corruption bugs reachable by
/// visiting a page.
///
/// PATANYX_ALLOW_OLD_ENGINE=1 overrides, for someone who has genuinely
/// decided to accept it. It is deliberately an environment variable rather
/// than a setting in the UI: this should be an explicit act, not a checkbox
/// someone clicks past.
fn enforce_engine_floor() {
    let engine = platform::engine_info();
    if !engine.below_floor {
        return;
    }
    let override_set = std::env::var("PATANYX_ALLOW_OLD_ENGINE").is_ok_and(|v| v == "1");
    eprintln!(
        "PATANYX: {} {} is below the security floor {}.{}.{}",
        engine.name,
        engine.version_string(),
        platform::MIN_WEBKITGTK.0,
        platform::MIN_WEBKITGTK.1,
        platform::MIN_WEBKITGTK.2,
    );
    eprintln!(
        "  WSA-2026-0004 fixes 23 CVEs in this engine, several of them memory\n  \
         corruption reachable by visiting a page. Debian marks webkit2gtk in\n  \
         bookworm END-OF-LIFE, so no update is coming on that release: the fix\n  \
         is Debian 13 (2.52.5-1~deb13u1) or a Flatpak carrying its own runtime."
    );
    if cfg!(debug_assertions) {
        eprintln!("  Debug build: continuing anyway.");
    } else if override_set {
        eprintln!("  PATANYX_ALLOW_OLD_ENGINE=1 set: continuing at your own risk.");
    } else {
        eprintln!("  Release build: refusing to start. Set PATANYX_ALLOW_OLD_ENGINE=1 to override.");
        std::process::exit(2);
    }
}

/// How long the blocking probe lets a page load before reporting. Generous:
/// a false "nothing was requested" would be the most misleading possible
/// result for a test whose whole job is proving requests do not happen.
const PROBE_SETTLE: std::time::Duration = std::time::Duration::from_secs(6);

/// How long the SECOND smoke ping gets, measured from the moment it is asked
/// for rather than from process start.
///
/// The startup deadline and this one answer different questions and used to be
/// the same 25 seconds. The vault sequence runs Argon2id at production
/// parameters twice, synchronously on the event loop -- ~25s in an unoptimised
/// Linux build and longer on Windows -- so the startup deadline had usually
/// already fired and was queued behind it, landing before the second ping
/// could round-trip. The result was `SMOKE FAIL: pings=1 vault_done=true` on
/// Windows every time, and a coin flip on Linux.
const SMOKE_SECOND_PING_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(test)]
mod build_variant_tests {
    /// The title must name the variant, because a user running the build
    /// with no chat compiled in and a user whose chat is broken look
    /// identical otherwise -- and only one of those is a bug.
    #[test]
    fn the_window_title_names_the_build_variant() {
        let title = super::window_title();
        assert!(title.starts_with("PATANYX Browser"), "{title}");
        assert_eq!(
            title.contains("Premium"),
            cfg!(feature = "chat"),
            "the title must say whether this is the Premium build: {title}"
        );
        // The relay is a SEPARATE feature. A chat build without it reaches
        // the local network only, and the title must not imply otherwise.
        assert_eq!(
            title.contains("relay"),
            cfg!(feature = "relay-client"),
            "the title must not claim a relay this build does not have: {title}"
        );
    }
}

/// The window title, which SAYS WHICH BUILD THIS IS.
///
/// Two variants ship from one tree: the public build has no chat compiled in
/// at all, and the private one does. The design has required this suffix
/// since the variants were decided, and it had never been implemented -- so
/// until now the only way to tell which binary you were running was to open
/// the panel and see whether chat existed.
///
/// That matters more than tidiness once both are in circulation. A user
/// reporting "chat does not work" and a user running the build with no chat
/// in it look identical without this, and the second is not a bug.
///
/// The relay is named separately because it is a separate feature: a private
/// build without `relay-client` reaches contacts on the local network only,
/// and the title should not imply otherwise.
/// The taskbar and titlebar icon: the wisp on a dark tile.
///
/// RAW RGBA, not a PNG, and that is the whole reason this asset looks odd in
/// the tree. Decoding a PNG at runtime means an image-decoder dependency, and
/// a dependency change here is not free: it forces `cargo-sources.json` to be
/// regenerated for the offline Flatpak build, which is a gate. 16 KiB of
/// pre-decoded pixels costs less than that and cannot fail to parse.
///
/// The tile is not decoration. The wisp is a thin monochrome glyph, and at the
/// 16px a taskbar actually renders it, a bare glyph on transparent disappears
/// against a dark shell. The tile gives it a silhouette at every size.
///
/// Returns `None` rather than panicking if the bytes are ever the wrong shape:
/// a browser that will not start because its icon is malformed would be a
/// remarkable way to fail.
fn app_icon() -> Option<tao::window::Icon> {
    const SIDE: u32 = 64;
    const PIXELS: &[u8] = include_bytes!("chrome/app-icon-64.rgba");
    if PIXELS.len() != (SIDE * SIDE * 4) as usize {
        return None;
    }
    tao::window::Icon::from_rgba(PIXELS.to_vec(), SIDE, SIDE).ok()
}

fn window_title() -> &'static str {
    match (cfg!(feature = "chat"), cfg!(feature = "relay-client")) {
        (false, _) => "PATANYX Browser",
        // "Premium", not "chat": the private build was renamed PATANYX-Premium
        // (decided 2026-08-05) because chat is one of the premium
        // features, not the whole of them. The suffix deliberately stays a
        // DISTINCTIVE multi-word fragment -- the free build's About copy
        // already contains the bare word "Premium" (the future-tense teaser),
        // so a build gate grepping for "Premium" alone would fail the public
        // binary it exists to protect. The gates in build-windows.sh and
        // build-flatpak.sh match these exact fragments; change them together.
        (true, false) => "PATANYX Browser — Premium (LAN chat only)",
        (true, true) => "PATANYX Browser — Premium + relay",
    }
}

fn main() {
    // Publishing helper: write the compiled-in blocklist hashes and exit.
    //
    // The published file MUST be byte-identical to what this binary matches
    // against, or the manifest's hash covers something the browser never uses.
    // Emitting it from the binary itself makes that identity structural rather
    // than a step someone has to remember -- there is no second code path that
    // could drift. See docs/update-channel.md.
    if let Some(dest) = std::env::args()
        .skip_while(|a| a != "--emit-blocklist")
        .nth(1)
    {
        match blocklist::write_bundled(std::path::Path::new(&dest)) {
            Ok(n) => {
                println!("{n} hosts -> {dest}");
                return;
            }
            Err(e) => {
                eprintln!("patanyx: --emit-blocklist: {e}");
                std::process::exit(1);
            }
        }
    }

    let smoke_mode = std::env::args().any(|arg| arg == "--smoke-test");
    enforce_engine_floor();
    // Before the first webview exists, so the line lands ahead of WebView2's
    // own startup noise in a probe run. No-op on unix and in release builds;
    // see platform::report_stray_profile for what is and is not done about a
    // profile an earlier build left beside the executable.
    platform::report_stray_profile();
    // Optional positional argument: URL or search terms to open at startup.
    let start_url = std::env::args()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .map(|raw| ipc::normalize_input(&raw))
        .unwrap_or_else(|| "about:blank".to_string());

    // A probe URL is only meaningful in smoke mode: it is navigated to AFTER
    // ad blocking is on, which is the whole point.
    // Deliberately NOT the positional URL. That loads at startup, before the
    // smoke sequence turns ad blocking on, so a "nothing was blocked" result
    // could have come from either load and would prove nothing. With the
    // initial tab blank, the only page load in the run is this one, and it is
    // unambiguously after the filter is live.
    let probe_url = if smoke_mode {
        std::env::var("PATANYX_BLOCKING_PROBE_URL").ok()
    } else {
        None
    };

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    let window = WindowBuilder::new()
        .with_title(window_title())
        .with_window_icon(app_icon())
        .with_inner_size(tao::dpi::LogicalSize::new(1100.0, 780.0))
        .build(&event_loop)
        .expect("failed to create main window");

    // Platform host areas (GTK boxes on unix; nothing but the window itself
    // on Windows). Takes ownership of the window so it outlives the loop.
    let hosts = platform::create_hosts(window);

    let proxy = event_loop.create_proxy();

    // ---- chrome webview: the ONLY place with custom protocol + IPC ----
    let ipc_proxy = proxy.clone();
    let chrome = platform::build_chrome(
        &hosts,
        // Same factory the content tabs use, so the chrome webview shares
        // their profile directory rather than creating a second one — on
        // Windows this is the webview that exists first and would otherwise
        // be the one that creates the folder beside the exe.
        platform::new_webview_builder()
            .with_url(platform::CHROME_URL)
            .with_custom_protocol(
                "rbchrome".to_string(),
                move |_id, request: http::Request<Vec<u8>>| serve_chrome(&request),
            )
            .with_ipc_handler(move |request: http::Request<String>| {
                let _ = ipc_proxy.send_event(UserEvent::Ipc(request.body().clone()));
            })
            // Chrome must never leave its own origin. The prefix is exact
            // and platform-specific; it must NOT be loosened into "any http
            // URL" to accommodate the WebView2 form, or the trusted chrome
            // webview could navigate onto the open web.
            .with_navigation_handler(|url: String| {
                url.starts_with(platform::CHROME_ORIGIN_PREFIX)
            })
            // The privileged UI opens no windows. wry's default when no handler
            // is set falls through to the engine, and this is the one surface
            // where an unguarded default is unacceptable.
            .with_new_window_req_handler(|_url, _features| wry::NewWindowResponse::Deny)
            // The privileged UI downloads nothing. wry's DEFAULT handler allows
            // every download, which would also bypass the sanitized,
            // collision-safe destination that content downloads go through.
            .with_download_started_handler(|_url, _destination| false)
            // Block OS drop handling here. The chrome UI has no file inputs, so
            // unlike the content webviews (where blocking would break
            // drag-to-upload) there is nothing to lose and a door to close.
            .with_drag_drop_handler(|_event| true)
            // Devtools on the PRIVILEGED webview is a console with vault-adjacent
            // reach, so it needs an explicit opt-in rather than riding along with
            // any debug build. Content webviews keep plain debug-only devtools.
            .with_devtools(cfg!(debug_assertions) && chrome_devtools_opted_in()),
        &proxy,
    )
    .expect("failed to build chrome webview");

    // Ask the OS to tell us when the workstation locks or the machine sleeps,
    // so the vault can close on the one signal that most clearly means the
    // user has left. Windows-only; the unix build is a no-op that reports
    // NotAttempted. Registered AFTER the window exists (it needs the HWND) and
    // records its own success for the engine-confirmed panel.
    platform::connect_session_lock(&hosts, &proxy);

    // The hover readout's native surface. Strictly AFTER build_chrome, and
    // before the first content tab exists: on Windows the translucent-overlay
    // probe inside build_chrome requires the window to have exactly one child
    // at that moment, and a readout window created earlier would disarm it
    // silently. Content webviews are created after this, which is why the
    // Windows side re-raises the readout on every show.
    platform::arm_hover_readout(&hosts, prefs::load().chrome_scheme);

    let probe_proxy = proxy.clone();
    // The resolver probe reports back on this loop, and handling its result
    // may push a banner update straight back out through the same channel.
    // Remove the .old binary a previous update left behind. It could not be
    // deleted then -- Windows locks a running executable -- and can be now.
    updater::installer::clean_previous();
    let probe_result_proxy = proxy.clone();
    // Periodic checks. Created before the loop so its first deadline is
    // measured from startup, not from the first event to arrive.
    let mut schedule = schedule::Schedule::new(std::time::Instant::now());
    let mut app = AppState::new(chrome, hosts, proxy.clone(), smoke_mode);
    // First tab: active and visible; further tabs are built via the same
    // factory (tab_new IPC / OpenInNewTab event).
    //
    // The one place a build failure is genuinely fatal: with no first tab
    // there is no browser to run, and every later path assumes a non-empty
    // tab list. Reported and exited rather than panicked, so the user gets a
    // sentence instead of a backtrace -- and so this reads as the deliberate
    // exception to the rule that a tab failure is survivable.
    // Page color scheme, applied once at boot to the engine the first tab
    // brings up (profile-wide on Windows; GTK-wide on Linux). Applied
    // BEFORE first paint would be ideal, but the profile only exists with
    // a webview; the first navigation is what shows it either way.
    let boot_theme = prefs::load().page_theme;
    if app.new_tab(&start_url, true).is_err() {
        eprintln!(
            "PATANYX: the web engine could not create the first tab.\n  \
             On Windows this usually means the WebView2 runtime is missing or \
             the profile directory is unwritable."
        );
        std::process::exit(1);
    }
    if boot_theme != prefs::PageTheme::Auto {
        if let Some(webview) = app.active_webview() {
            // A false return (engine did not acknowledge) needs nothing
            // here: the settings row reads the ack live on every set, so
            // the next visit to it tells the user honestly.
            let _ = platform::apply_page_theme(webview, boot_theme);
        }
    }

    platform::show_all(&app.hosts);

    if smoke_mode {
        // chrome.js sends an IPC {cmd:"ping"} on load; if it has not arrived
        // by the deadline the webview stack is broken.
        // Generous deadline: the vault sequence runs Argon2id at production
        // parameters (64 MiB, t=3) twice.
        let smoke_proxy = proxy.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(25));
            let _ = smoke_proxy.send_event(UserEvent::AutoLockTick);
        });
    }

    event_loop.run(move |event, _target, control_flow| {
        // Re-arm the auto-lock deadline after every event; activity updates
        // `last_activity` in the IPC arm below. (The window is owned by
        // `app.hosts`, keeping it alive for the duration of the loop.)
        // The periodic checks fold into the SAME wait rather than bringing
        // their own thread. A timer thread would have to be woken, joined and
        // shut down cleanly on quit; a deadline the loop already computes
        // costs nothing and cannot outlive the loop.
        //
        // Smoke runs are excluded: they must exit on a fixed script, and a
        // scheduled fetch during one would make the gate depend on the network.
        // A load may have armed a tab since the last pass, so re-read the
        // deadline every time rather than only after a timer fires.
        //
        // Closure-local, and that is the point: it is recomputed from the tabs
        // on EVERY event, so nothing about it needs to survive to the next one.
        // It used to be a captured `mut` assigned in two places, which read as
        // if the second assignment carried information forward. It could not
        // -- this line overwrites it before any reader runs. See the timer arm.
        let freeze_deadline = app.tick_auto_freeze(std::time::Instant::now());
        let scheduled = if smoke_mode {
            None
        } else {
            Some(schedule.next_deadline())
        };
        let scheduled = match (scheduled, freeze_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        // The vault deadline is now the WARNING first and the lock second, and
        // it is `None` when there is nothing pending -- no vault open, or the
        // user chose never. Asking the state for it keeps the timeout, the
        // never case and the warning window in one place instead of spread
        // between here and check_autolock.
        *control_flow = match (app.autolock_deadline(), scheduled) {
            (Some(vault), Some(next)) => ControlFlow::WaitUntil(vault.min(next)),
            (Some(vault), None) => ControlFlow::WaitUntil(vault),
            (None, Some(next)) => ControlFlow::WaitUntil(next),
            (None, None) => ControlFlow::Wait,
        };

        match event {
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                app.check_autolock();
                // NO tick_auto_freeze HERE, deliberately. There used to be one,
                // whose comment said the deadline it returned "folds into the
                // wait below" -- it did not, and could not: the wait is
                // computed ABOVE this match, from the tick that already ran
                // this pass. The value was assigned and never read, so the
                // compiler flagged it; the real cost was that `tick_auto_freeze`
                // is side-effecting (it freezes due tabs and emits tab status),
                // so every timer wake ran the whole per-tab sweep twice.
                // `due` reschedules whatever it returns, so a failing task is
                // pushed forward rather than retried on every wake.
                for task in schedule.due(std::time::Instant::now()) {
                    match task {
                        schedule::Task::Update => updater::check_in_background(&app.proxy()),
                        schedule::Task::Blocklist => {
                            blocklist::refresh_in_background(&app.proxy())
                        }
                    }
                }
            }
            Event::UserEvent(UserEvent::QuitForUpdate) => {
                // The replacement is already running. Leaving this one open is
                // what produced two browsers per click.
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            // Child-webview geometry is manual on Windows; GTK repacks on
            // its own, so relayout() is a no-op there.
            Event::WindowEvent {
                event: WindowEvent::Resized(_),
                ..
            } => app.relayout(),
            Event::WindowEvent {
                event: WindowEvent::ScaleFactorChanged { .. },
                ..
            } => app.relayout(),
            // A key was pressed inside a page. The ONLY effect is to say a
            // human is here; see UserEvent::UserPresence.
            Event::UserEvent(UserEvent::UserPresence) => app.touch(),
            Event::UserEvent(UserEvent::Ipc(body)) => {
                // NOT touched here any more. Every frame used to count as
                // presence, including the ones nobody sent: the Tab Activity
                // panel polls the ledger every 2.5 seconds, so leaving that
                // panel open re-armed the auto-lock twenty-four times a minute
                // and the vault never locked at all on an unattended machine.
                // `dispatch` knows the command name and decides there.
                ipc::dispatch(&mut app, &body);
                // First ping in smoke mode: run the vault and tab lifecycles
                // through the real dispatch surface, then request a second
                // ping via evaluate_script to prove the Rust->JS direction too.
                if app.smoke_mode && app.ping_count == 1 && !app.smoke_vault_done {
                    app.smoke_vault_done = true;
                    let result = ipc::smoke_vault_sequence(&mut app)
                        .and_then(|()| ipc::smoke_tab_sequence(&mut app))
                        .and_then(|()| ipc::smoke_readout_sequence(&mut app));
                    match result {
                        Ok(()) => {
                            app.smoke_second_ping_requested = true;
                            app.request_second_ping();
                            // A FRESH deadline, measured from here rather than
                            // from startup. The sequence above blocks this
                            // loop for ~25s (Argon2id twice, and far longer in
                            // an unoptimised build), so the original deadline
                            // has usually already fired and is queued -- it
                            // would be processed the instant this returns,
                            // before the second ping could possibly arrive.
                            let p = proxy.clone();
                            thread::spawn(move || {
                                thread::sleep(SMOKE_SECOND_PING_GRACE);
                                let _ = p.send_event(UserEvent::AutoLockTick);
                            });
                        }
                        Err(err) => {
                            println!("SMOKE FAIL: {err}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            Event::UserEvent(UserEvent::ProbeDone) => {
                println!("PROBE DONE");
                std::process::exit(0);
            }
            Event::UserEvent(UserEvent::ZoomFactorChanged(id, factor)) => {
                app.on_zoom_factor_changed(id, factor)
            }
            Event::UserEvent(UserEvent::UrlChanged(id, url)) => app.on_url_changed(id, url),
            Event::UserEvent(UserEvent::LoadState(id, loading)) => app.on_load_state(id, loading),
            Event::UserEvent(UserEvent::TitleChanged(id, title)) => {
                app.on_title_changed(id, title)
            }
            Event::UserEvent(UserEvent::OpenInNewTab(url)) => {
                // Re-checked at the sink as well as at the source. The source
                // is a wry callback on the content webview, so it is the half
                // of this path an untrusted page gets to talk to; validating
                // only there leaves the invariant one refactor away from being
                // lost. new_tab() calls with_url directly, and a new webview's
                // initial load is not a navigation, so this is the last point
                // at which anything checks.
                if state::is_allowed_content_url(&url) && app.tabs.len() < state::MAX_TABS {
                    // THE REMOTE PATH. A page reaches this with window.open(),
                    // so a refusal here must cost the page its tab and nothing
                    // else. Dropped deliberately rather than surfaced: the
                    // request came from the page, not the user, and a toast
                    // the user did not ask for is a notification any site
                    // could trigger at will.
                    let _ = app.new_tab(&url, false); // background tab: do not switch
                }
            }
            Event::UserEvent(UserEvent::DownloadStarted(url)) => {
                app.emit("download_started", json!({ "url": url }));
            }
            Event::UserEvent(UserEvent::DownloadDone {
                url,
                path,
                success,
            }) => {
                // Provenance BEFORE the toast: the downloads view refreshes
                // off `download_finished`, and that refresh must already see
                // this file's fingerprint record — or the explicit
                // `download_record_failed` event naming why there is none.
                // Recording is what the downloads view promises ("every
                // finished download is recorded"); until this call existed,
                // the re-check it offers could never run.
                app.record_download_provenance(&url, path.as_deref(), success);
                app.emit(
                    "download_finished",
                    json!({ "url": url, "path": path, "success": success }),
                );
            }
            // The async main-resource read (or its failure) returns here from
            // the platform layer. Without this arm the wildcard below dropped
            // the event on the floor: "Save snapshot now", "Compare with
            // saved snapshot" and "Ask to compare" all acknowledged the start
            // over IPC and then never answered.
            Event::UserEvent(UserEvent::Integrity(event)) => {
                page_integrity::handle_event(&mut app, event);
            }
            Event::UserEvent(UserEvent::Ocr(event)) => {
                ocr_support::handle_event(&mut app, event);
            }
            Event::UserEvent(UserEvent::Find(event)) => {
                app.on_find_event(event);
            }
            Event::UserEvent(UserEvent::Capture(event)) => {
                app.on_capture_done(event);
            }
            Event::UserEvent(UserEvent::NavigationBlocked { tab_id, host, rule }) => {
                // The refusal already happened, in the navigation handler.
                // This only tells the user, and it must, or a blocked page is
                // indistinguishable from a broken browser.
                app.emit(
                    "navigation_blocked",
                    json!({ "tab_id": tab_id, "host": host, "rule": rule }),
                );
            }
            Event::UserEvent(UserEvent::LoginSubmitted {
                tab_id,
                origin,
                username,
                password,
            }) => {
                app.note_login_submitted(tab_id, origin, username, password);
            }
            Event::UserEvent(UserEvent::BlocklistRefreshed(outcome)) => {
                // Reported to the chrome either way. A refresh that keeps
                // failing means the list is ageing, and the user is entitled to
                // know that rather than to keep seeing a protection indicator
                // backed by a month-old set.
                let data = match &outcome {
                    Ok((version, hosts)) => serde_json::json!({
                        "ok": true, "version": version, "hosts": hosts,
                    }),
                    Err(why) => serde_json::json!({ "ok": false, "detail": why }),
                };
                app.emit("blocklist_refreshed", data);
            }
            Event::UserEvent(UserEvent::UpdateChecked(status)) => {
                // Pushed to the chrome rather than acted on here. Offering an
                // update is a UI decision, and nothing downloads until the
                // user says so.
                app.emit("update_checked", status);
            }
            Event::UserEvent(UserEvent::ResolverProbe(reachable)) => {
                resolver_probe::on_probe_result(reachable, &probe_result_proxy);
            }
            Event::UserEvent(UserEvent::ResolverBanner { visible, mode }) => {
                app.emit(
                    "resolver_state",
                    serde_json::json!({ "unreachable": visible, "mode": mode }),
                );
            }
            Event::UserEvent(UserEvent::Shortcut(action)) => {
                use shortcuts::Shortcut;
                app.touch();
                match action {
                    shortcuts::Shortcut::ZoomIn => app.zoom_active(1),
                    shortcuts::Shortcut::ZoomOut => app.zoom_active(-1),
                    shortcuts::Shortcut::ZoomReset => app.zoom_active(0),
                    Shortcut::NewTab => {
                        if app.tabs.len() < state::MAX_TABS {
                            // The USER asked for this one, so a refusal is
                            // theirs to see -- unlike the window.open() path
                            // above, where the request came from a page.
                            if app.new_tab("about:blank", true).is_err() {
                                app.emit(
                                    "toast",
                                    json!({ "text": "The engine could not open a new tab.", "error": true }),
                                );
                            }
                        }
                    }
                    Shortcut::CloseTab => app.close_active_tab(),
                    Shortcut::NextTab => app.cycle_tab(1),
                    Shortcut::PrevTab => app.cycle_tab(-1),
                    Shortcut::SelectTab(index) => app.select_tab_index(index),
                    Shortcut::SelectLastTab => app.select_last_tab(),
                    Shortcut::FocusUrlBar => app.focus_url_bar(),
                    Shortcut::Reload => {
                        let _ = app.history_reload();
                    }
                    Shortcut::Back => {
                        let _ = app.history_back();
                    }
                    Shortcut::Forward => {
                        let _ = app.history_forward();
                    }
                    Shortcut::LockVault => app.lock_vault(),
                    Shortcut::OpenCommandPalette => app.open_command_palette(),
                    Shortcut::Print => app.print_active_tab(),
                    // The chrome owns the bar; the key only asks it to open.
                    Shortcut::OpenFind => app.emit("find_open", json!({})),
                    // The session gate keeps F3 a true no-op when nothing was
                    // ever searched; the platform layer is also a quiet no-op,
                    // so this is belt and braces, not load-bearing.
                    Shortcut::FindNext => {
                        if app.find.is_active() {
                            if let Some(webview) = app.active_webview() {
                                platform::find_next(webview);
                            }
                        }
                    }
                    Shortcut::FindPrevious => {
                        if app.find.is_active() {
                            if let Some(webview) = app.active_webview() {
                                platform::find_previous(webview);
                            }
                        }
                    }
                }
            }
            // The workstation locked, or the machine is going to sleep. Honour
            // the user's setting, and go through the ONE lock path -- see
            // `AppState::lock_vault`, which every other trigger also calls.
            //
            // No-ops harmlessly when the vault is already locked or was never
            // opened; `lock_vault` is idempotent and the emit tells a chrome
            // that already shows "locked" nothing it did not know.
            Event::UserEvent(UserEvent::ContextMenuAction { action, target }) => {
                app.on_context_menu_action(action, target.as_deref());
            }
            Event::UserEvent(UserEvent::PdfSaved { path, success }) => {
                app.on_pdf_saved(&path, success);
            }
            Event::UserEvent(UserEvent::SessionLocked) => {
                // Read from disk rather than from a cached copy. This fires a
                // handful of times a day, so the read costs nothing, and it
                // means a change to the setting takes effect immediately with
                // no cache to invalidate -- unlike `autolock_secs`, which is
                // cached in AppState and needs a setter to keep it in step.
                if crate::prefs::load().vault_lock_on_session_lock {
                    app.lock_vault();
                }
            }
            Event::UserEvent(UserEvent::AutoLockTick) => {
                app.check_autolock();
                if app.smoke_mode {
                    if app.ping_count >= 2 && app.smoke_vault_done {
                        // Engine facts, printed from the running engine rather
                        // than asserted from a constant. ITP in particular is
                        // the value READ BACK after the write, so this line is
                        // the only thing entitled to claim it is on.
                        // Behavioural blocking probe. `--smoke-test <url>`
                        // navigates AFTER the smoke sequence has turned ad
                        // blocking on, waits, and only then exits, so the
                        // page loads under a live content filter.
                        //
                        // This is the one thing 296 passing tests still could
                        // not tell us: the matcher tests prove the rules are
                        // right and the smoke gate proves a filter compiled,
                        // but nothing proved a blocked request fails to leave
                        // the machine. That is exactly the gap the ad-block
                        // bug lived in for as long as it shipped.
                        //
                        // When probing, this arm NEVER exits: it starts the
                        // navigation once and then leaves, and the only way
                        // out is `ProbeDone`. This block runs on every IPC
                        // event once its conditions hold, so an exit here
                        // would fire on the next ping and end the process
                        // before the page had made a single request --
                        // reporting a clean "nothing was blocked" from a run
                        // in which nothing was even attempted.
                        if let Some(url) = probe_url.as_deref() {
                            if !app.probe_started {
                                app.probe_started = true;
                                // THE SET ACTUALLY IN FORCE, printed before the
                                // navigation. Without this a probe cannot tell
                                // "blocking is broken" from "my override never
                                // reached the process and it used the real
                                // 390k list" -- the two produce identical
                                // output, and the second silently turns the
                                // whole run into a test of nothing.
                                println!("BLOCKLIST hosts={}", blocklist::len());
                                let _ = app.navigate(url);
                                let proxy = probe_proxy.clone();
                                std::thread::spawn(move || {
                                    std::thread::sleep(PROBE_SETTLE);
                                    let _ = proxy.send_event(UserEvent::ProbeDone);
                                });
                            }
                        } else {
                        let engine = platform::engine_info();
                        println!(
                            "ENGINE {} {} | {} | floor {}",
                            engine.name,
                            engine.version_string(),
                            engine.tracking_prevention,
                            if engine.below_floor {
                                "BELOW (known-vulnerable runtime)"
                            } else {
                                "ok"
                            }
                        );
                        println!("SMOKE OK");
                        std::process::exit(0);
                        }
                    }
                    // Not a failure while the blocking probe is in flight:
                    // that path deliberately does not exit here and is
                    // waiting for `ProbeDone`.
                    if !app.probe_started {
                        app.smoke_deadline_ticks += 1;
                        // The startup deadline answers "did the webview stack
                        // come up at all". Once the second ping has been
                        // REQUESTED that question is already answered yes, and
                        // this tick is merely early -- it was queued while the
                        // vault sequence held the loop. Let the grace deadline
                        // armed above decide instead.
                        //
                        // Bounded to one reprieve, so a second ping that never
                        // arrives still fails rather than hanging.
                        if app.smoke_second_ping_requested && app.smoke_deadline_ticks < 2 {
                            return;
                        }
                        println!(
                            "SMOKE FAIL: pings={} vault_done={} second_ping_requested={}",
                            app.ping_count,
                            app.smoke_vault_done,
                            app.smoke_second_ping_requested
                        );
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(feature = "chat")]
            Event::UserEvent(UserEvent::Chat(event)) => {
                chat_panel::handle_transport_event(&mut app, event)
            }
            // ON EXIT, ERASE WHAT THE ENGINE REMEMBERED. Site permission
            // grants are session-only, and on Windows the engine persists its
            // own copy of every decision into the profile. Clearing it here is
            // what makes "allowed sites reset when PATANYX closes" true of the
            // ENGINE rather than only of this process's table -- without it a
            // grant would outlive the browser that promised to forget it.
            //
            // Ahead of the chat teardown below because that JOINS threads and
            // can block; this is a handful of async calls into a profile that
            // is about to go away, and it should be issued before anything
            // that might delay the wind-down.
            //
            // The platform pair both export this, so no `#[cfg]` here: it is a
            // no-op on unix, where no permission state is ever written.
            Event::LoopDestroyed => {
                platform::clear_persisted_permissions(app.chrome());
                #[cfg(feature = "chat")]
                chat_panel::shutdown(&mut app);
            }
            _ => {}
        }
    });
}
