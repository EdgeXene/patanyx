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
mod activation;
mod adlist_consent;
mod toplevel_request;
/// Searching the personal archive: which archived pages answer a query, and
/// what each row shows. Pure logic over records the store owns.
mod archive;
/// Known-malicious hosts, refused in the navigation handler. Present in every
/// build: this is the protection for users who change no settings.
mod blocklist;
mod bookmark_import;
mod capture;
/// Chat exists only under `--features chat`, which is off by default. The
/// published browser contains none of it: `patanyx-chat` is an optional
/// dependency and this module is the only place the app references it.
#[cfg(feature = "chat")]
mod chat_panel;
/// Every user-facing string the cookie-clearing controls say. Pure copy with
/// the wording pinned by tests, so the sentence that keeps "clears cookies"
/// from becoming "clears everything" is checked rather than remembered.
mod cookie_control;
/// Download corroboration: comparing what two people were served from the
/// same address. Rides the chat transport, so it exists only in the build
/// that has one.
#[cfg(feature = "chat")]
mod download_compare;
mod engine_advisory;
/// The message catalog and its resolver: every user-facing string in the
/// chrome and in Rust comes from here, so a second locale is a file rather
/// than a rewrite.
mod i18n;
/// Debug-only in-product isolation battery; see the module header.
#[cfg(debug_assertions)]
mod isolation_probe;
/// Debug-only in-product proof of the translation reply channel; see the
/// module header. Unix-only for now: it exercises the WebKitGTK parked-reply
/// mechanism, and the Windows half of the seam is a different mechanism that
/// needs its own proof rather than a shared one that would only pretend to
/// cover both.
#[cfg(all(debug_assertions, unix))]
mod translate_channel_probe;
/// Downloading, verifying and installing language packs.
mod langpack;
/// The generated language/pair registry (see scripts/gen-language-registry.py).
mod languages;
/// Page-language sanity checking by Unicode script (the corruption guard).
mod detect;
mod find;
mod hover;
/// Colours, font metrics and geometry for the hover readout, kept apart from
/// both backends so the Windows-only arithmetic is testable on any box.
mod hover_style;
mod ipc;
/// Engine-side tunnel lifecycle: bind the proxy port before the vault
/// exists, start the tunnel when it opens. Unconditional, like the tunnel
/// crate itself.
mod licence_control;
mod marker;
mod net;
mod ocr_support;
/// Page digesting and peer corroboration. Needs the page's real bytes, which
/// come from the ENGINE (never from evaluating script in a content webview).
mod page_integrity;
mod partner;
mod platform;
mod prefs;
mod premium_purchase;
mod psl;
mod resolver_probe;
/// The browser's only self-initiated network activity, and its timing.
mod schedule;
mod shelf;
mod shortcuts;
mod sponsorship;
mod state;
/// Cross-tab text search over each tab's visible text: pure matching,
/// snippet shaping and refusal wording, identical on every platform.
mod tab_search;
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
    /// The once-per-process engine-profile wipe has completed (successfully
    /// or not), so tabs held blank behind it may issue their initial
    /// navigation. Failure still releases them; the platform diagnostic says
    /// plainly which data were NOT cleared instead of turning an unavailable
    /// privacy primitive into a browser that never loads.
    SessionWipeFinished,
    UrlChanged(u64, String),
    /// A message a CONTENT webview's translation script posted UP.
    ///
    /// Deliberately NOT `Ipc`. `Ipc` carries privileged commands from the
    /// trusted chrome origin; this carries text scraped from a hostile page,
    /// and the two must never arrive through the same door. Tagged with the
    /// tab id because the sender is a page, and a page does not get to say
    /// which tab it is.
    ContentTranslate(u64, String),
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
    /// A replacement of THIS binary is already running and this process must
    /// end. Same exit as `QuitForUpdate` and deliberately a separate variant:
    /// nothing was installed, so a reader of either arm can tell at a glance
    /// whether the binary on disk changed.
    ///
    /// Raised by the tunnel's "Apply and restart", which needs a new process
    /// because the engine reads the proxy setting only at startup.
    QuitForRelaunch,
    /// The engine zoomed a tab on keys this process never receives.
    ZoomFactorChanged(u64, f64),
    AutoLockTick,
    /// Drive one step of an in-flight translation.
    ///
    /// A POLL, because the translator document cannot push. It has no ipc
    /// handler by design -- that is the isolation the separate origin exists
    /// for -- so the only way to read it is `evaluate_script_with_callback`,
    /// which the host must initiate. Raised by a thread that runs ONLY while
    /// work is in flight and stops itself when there is none.
    TranslateTick,
    /// Drives the debug-only full-loop self-test. Absent from release builds.
    #[cfg(all(debug_assertions, unix))]
    TranslateSelfTest,
    /// A language pack finished installing, or failed to. Carries the pair
    /// and, on failure, a catalog key the panel can render.
    PackInstalled(&'static str, Option<&'static str>),
    /// Download progress for an in-flight pack: pair, bytes so far, total when
    /// the server offered one. Advisory -- drives the UI only.
    PackProgress(&'static str, u64, Option<u64>),
    /// The translator document's `status()`, as it answered it.
    TranslateEngine(String),
    /// A finished (or still-pending) translation job, as `result()` answered.
    /// Carries the job id the host chose, never one the document invented.
    TranslateResult(u64, String),
    /// The window finished a maximize or a restore a moment ago; the title
    /// bar colours are re-applied AFTER Windows has repainted the frame in
    /// the system colour, which it does on that transition (see
    /// `AppState::relayout`). Posted from a short timer so it lands after
    /// the transition, not inside the resize that announces it.
    WindowFrameSettled,
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
    ContextMenuAction {
        action: u32,
        target: Option<String>,
    },
    /// A save-as-PDF render finished, or failed. Carries the destination
    /// rather than a tab id: by the time this arrives the tab may have
    /// navigated or closed, and the path is what identifies the job.
    PdfSaved {
        path: String,
        success: bool,
    },
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
    /// A finished Premium activation or release call (Phase 4). The call
    /// runs on a worker so an unreachable server never freezes the event
    /// loop; the result lands here and activation.rs writes the vault.
    Activation(activation::ActivationEvent),
    /// A Deep Recall capture has been read for text and is ready to store.
    /// Carries the picture back with it: the archive writes both halves in
    /// one place, so the bytes travel rather than being parked somewhere the
    /// storing code would have to find them again.
    ArchiveRead {
        png: Vec<u8>,
        url: String,
        title: String,
        scope: &'static str,
        text: String,
    },
    /// A finished (or failed) page capture, from the engine's async callback.
    Capture(capture::CaptureEvent),
    /// A native region capture has been turned into its bounded chrome
    /// preview on a worker. The event loop only publishes its dimensions.
    RegionCapturePrepared {
        result: Result<(u64, u32, u32, u32, u32), &'static str>,
        scope: capture::CaptureScope,
    },
    /// A snapshot capture has passed through WP-Z's bounded picture path on
    /// a worker. Hash/text storage remains possible when `result` is Err.
    SnapshotPicturePrepared {
        result: Result<Vec<u8>, &'static str>,
        scope: capture::CaptureScope,
    },
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
    /// A plain-HTTP navigation was held back by the navigation handler
    /// pending the user's Continue. Carries the URL so the chrome can name
    /// the site and Rust can re-issue the same load; see
    /// `AppState::note_insecure_navigation`.
    InsecureNavigation {
        tab_id: u64,
        url: String,
    },
    /// A TOP-LEVEL navigation to a host on the ad/tracker list was refused by
    /// the engine, and the tab is now showing our placeholder instead of the
    /// engine's error page. Carries the complete URL (fragment included) so
    /// consent can resume exactly what was asked for, the host the banner
    /// names, and the method, because a held form submission cannot be
    /// replayed and the banner must say so before the click.
    AdlistBlocked {
        tab_id: u64,
        url: String,
        host: String,
        method: String,
    },
    /// A content tab's password form was submitted. Carries exactly what the
    /// save-password banner needs -- the PASSWORD IS HERE because the banner
    /// offers to save it on the strength of this one message, held only in
    /// `AppState::pending_save`'s in-memory slot until the user accepts (or
    /// dismisses, navigates, or switches tabs, any of which drops it
    /// unwritten). See `note_login_submitted` in state.rs.
    LoginSubmitted {
        tab_id: u64,
        /// The URI of the document that sent the message, as the ENGINE
        /// reports it (`ICoreWebView2WebMessageReceivedEventArgs::Source`),
        /// never the `origin` the page put in its own JSON. See
        /// `note_login_submitted`, which refuses the offer outright when this
        /// disagrees with the tab's tracked URL.
        source_url: String,
        username: String,
        password: String,
    },
    /// Batched count deltas claimed by a tab's page-world divergence
    /// wrappers. Unlike request blocking, this is not an engine observation:
    /// hostile page code can use the same bridge and forge the report.
    FingerprintProbes {
        tab_id: u64,
        counts: Vec<(state::FingerprintSurface, u64)>,
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
    ResolverBanner {
        visible: bool,
        mode: &'static str,
    },
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

/// The translator document's policy. TWO DIRECTIVES LOOSER than `CSP`, and
/// exactly two, established by bisection against both engines rather than from
/// specs (`docs/page-translation-spike.md`):
///
///   * `connect-src 'self'` -- under the chrome policy's `connect-src 'none'`
///     the engine cannot fetch its OWN `.wasm`, before any model file is
///     touched.
///   * `'wasm-unsafe-eval'` -- granting the fetch, WebAssembly then refuses to
///     compile: "Refused to create a WebAssembly object because 'unsafe-eval'
///     or 'wasm-unsafe-eval' is not an allowed source of script".
///
/// Both engines agreed exactly on that cost. Being on a SEPARATE ORIGIN is
/// what contains it: these two directives are granted to the translator
/// document and to nothing else, where on the shared origin the privileged UI
/// would have had to be granted them too.
const TRANSLATE_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'";

/// The translator document, its script, and the engine it hosts.
///
/// Compiled in, like the OCR models (`crates/ocr/src/lib.rs:165`) and for the
/// same reason: the engine SHIPS IN THE INSTALLER. The language packs do not —
/// those download on demand, which is the whole point of not bundling every
/// pair. That split is what the privacy copy promises, so it is worth stating
/// where the bytes actually are.
const TRANSLATOR_HTML: &str = include_str!("chrome/translator.html");
const TRANSLATOR_JS: &str = include_str!("chrome/translator.js");
/// Mozilla's build, v0.6.0 @ 1de4a085. Provenance, licence and the rule that
/// these two move together: `models/translator/README.md`.
const TRANSLATOR_GLUE: &str = include_str!("../../../models/translator/bergamot-translator.js");
const TRANSLATOR_WASM: &[u8] = include_bytes!("../../../models/translator/bergamot-translator.wasm");

/// Serves the translator origin, and NOTHING the chrome origin serves.
///
/// Deliberately not `serve_chrome` with an extra route. The chrome handler
/// answers `/region-capture/<token>.png` with a screen capture and
/// `/archive-picture/<token>.png` with a DECRYPTED page from the encrypted
/// archive; phase 0 confirmed a fetch from a second webview reaches that
/// handler. A view that will hold text scraped from hostile pages must not be
/// wired to it, so this is a separate function with its own, closed, route
/// table and a 404 for everything else.
///
/// Must not panic on ANY input: a wry protocol handler runs across an
/// `extern "C"` boundary, so a panic here ABORTS the process rather than
/// unwinding. Phase 0 lost three hardware runs to exactly that, because
/// WebView2 requests `/favicon.ico` from a custom scheme unprompted.
/// Where language packs are read from.
///
/// A `OnceLock` because the protocol handler is a free function with no place
/// to carry state: wry hands it a request and nothing else. Resolved on FIRST
/// USE rather than at startup, so there is no ordering requirement between
/// this and webview construction and therefore no window in which a request
/// could see a half-initialised path.
static PACK_ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// The directory packs are read from, resolved once.
///
/// DEBUG BUILDS TAKE AN OVERRIDE, release builds do not. The override exists so
/// a probe can prove translation against a pack placed in a scratch directory
/// without writing into a tester's real profile. It is compiled out of
/// release binaries entirely rather than merely ignored there: a shipped
/// product must not contain an environment variable that redirects where model
/// weights are loaded from.
fn pack_root() -> &'static std::path::Path {
    PACK_ROOT.get_or_init(|| {
        #[cfg(debug_assertions)]
        if let Ok(dir) = std::env::var("PATANYX_PACK_ROOT") {
            if !dir.is_empty() {
                return std::path::PathBuf::from(dir);
            }
        }
        platform::translator_pack_dir_for(&patanyx_vault::Vault::default_path())
    })
}

/// Serves one file of an installed language pack.
///
/// THIS IS THE ONLY PATH IN THE PRODUCT WHERE A REQUEST REACHES THE DISK, so
/// it is built to make traversal impossible rather than to detect it:
///   - the pair is matched against the PUBLISHED REGISTRY and replaced with the
///     matching `&'static str` (`validate_translation_pair` -> languages::PAIRS),
///     so what reaches the path is a registry-owned constant and never the
///     caller's bytes. The set is larger than it was (one pair -> the whole
///     published registry), but the property is identical: membership, not
///     shape, and the returned value is not the caller's;
///   - the filename is matched against a fixed three-entry table and likewise
///     replaced with a constant;
///   - the two constants are joined onto a root this process chose.
/// There is no request-derived string anywhere in the resulting path. `..`,
/// encoded separators, NUL, absolute paths and unicode homoglyphs are all
/// answered by the same thing: they match no allowlist entry, so they 404.
///
/// IT MUST NOT PANIC. A wry protocol handler runs across an `extern "C"`
/// boundary, so a panic here ABORTS the process rather than unwinding -- phase
/// 0 lost three hardware runs to exactly that. Every step below returns None
/// rather than unwrapping, and the read is size-capped so a corrupt or
/// substituted file cannot be turned into an allocation the size of the disk.
fn serve_translator_pack(path: &str) -> Option<Vec<u8>> {
    let rest = path.strip_prefix("/pack/")?;
    let (pair, file) = rest.split_once('/')?;
    // Allowlist, then DISCARD the caller's copy: `pair` is shadowed by the
    // static the allowlist returned.
    let pair = state::validate_translation_pair(pair)?;
    // Allowlisted against EVERY layout's filenames, then replaced with the
    // constant: which layout a pair actually uses is the registry's business,
    // not this handler's, and serving a name the pair does not have simply
    // finds no file on disk.
    let file = platform::PACK_FILES_ANY.iter().find(|f| **f == file)?;
    let full = pack_root().join(pair).join(file);
    let meta = std::fs::metadata(&full).ok()?;
    if !meta.is_file() || meta.len() > patanyx_update::MAX_MODEL_PACK_BYTES {
        return None;
    }
    std::fs::read(&full).ok()
}

/// Never cache a compiled-in asset.
///
/// THE UI AND THE ENGINE GLUE CHANGE WITH EVERY BUILD, and the profile they
/// are served into OUTLIVES the build: the data directory is keyed to the
/// vault, not the version. Neither handler set a cache directive, so WebView2
/// applied its own heuristic and kept serving the PREVIOUS build's files to
/// the new binary.
///
/// That is how a fix to `translator.js` -- raising the engine heap so a
/// converted model fits -- reached a tester's machine and changed
/// nothing: the running engine was still the cached copy. The Rust-side
/// change in the same build DID take effect, so the output changed once and
/// then stopped changing, which is what finally identified this: identical
/// bytes out of two different binaries.
///
/// These are not network assets. They are compiled into the executable, cost
/// nothing to serve, and are wrong the moment they are stale.
const NO_STORE: (&str, &str) = ("Cache-Control", "no-store, must-revalidate");

/// A short revision derived from the compiled-in assets themselves.
///
/// `no-store` fixes the FUTURE and cannot heal a profile that already cached
/// these files: a stored entry is reused without ever asking the handler, so
/// the header on the response the handler would have sent is never seen. That
/// is not a theory -- three consecutive builds served a tester the same
/// stale `translator.js` and produced byte-identical wrong output, while
/// Rust-side changes in the same builds took effect normally.
///
/// Changing the URL is what actually evicts it, because a different URL is a
/// different cache key. Derived from the bytes rather than the app version so
/// that a rebuild WITHIN a version -- which is every build a tester runs
/// -- also gets a fresh key.
pub fn asset_revision() -> &'static str {
    static REV: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    REV.get_or_init(|| {
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        for part in [
            TRANSLATOR_JS.as_bytes(),
            TRANSLATOR_GLUE.as_bytes(),
            TRANSLATOR_WASM,
            INDEX_HTML.as_bytes(),
        ] {
            sha2::Digest::update(&mut h, part);
        }
        let digest = sha2::Digest::finalize(h);
        digest[..6].iter().map(|b| format!("{b:02x}")).collect()
    })
}

/// The same document with its asset URLs carrying the revision.
///
/// Rewritten at serve time rather than templated into the file so the HTML
/// stays a plain, readable document that opens correctly on its own.
fn with_asset_revision(html: &str) -> String {
    let rev = asset_revision();
    html.replace(".js\"", &format!(".js?v={rev}\""))
        .replace(".css\"", &format!(".css?v={rev}\""))
}

fn serve_translator(request: &http::Request<Vec<u8>>) -> http::Response<Cow<'static, [u8]>> {
    if request.uri().path().starts_with("/pack/") {
        return match serve_translator_pack(request.uri().path()) {
            // `application/octet-stream`: these are opaque weights, and the
            // document reads them as an ArrayBuffer. Naming any richer type
            // would be a claim about the bytes that nothing here checks.
            Some(bytes) => http::Response::builder()
                .header("Content-Type", "application/octet-stream")
                .header("Content-Security-Policy", TRANSLATE_CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Owned(bytes))
                .expect("pack response"),
            None => http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Security-Policy", TRANSLATE_CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Borrowed(&b"not found"[..]))
                .expect("pack 404 response"),
        };
    }
    let (mime, body): (&str, &[u8]) = match request.uri().path() {
        // Rewritten, so a profile holding the previous build's scripts asks
        // for new URLs instead of reusing what it has.
        "/" | "/translator.html" => {
            return http::Response::builder()
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Content-Security-Policy", TRANSLATE_CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Owned(with_asset_revision(TRANSLATOR_HTML).into_bytes()))
                .expect("translator html response");
        }
        "/translator.js" => ("text/javascript; charset=utf-8", TRANSLATOR_JS.as_bytes()),
        "/bergamot-translator.js" => ("text/javascript; charset=utf-8", TRANSLATOR_GLUE.as_bytes()),
        // The engine. `application/wasm` is not decoration: a browser refuses
        // to compile a wasm response served under any other type.
        "/bergamot-translator.wasm" => ("application/wasm", TRANSLATOR_WASM),
        _ => {
            return http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Security-Policy", TRANSLATE_CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Borrowed(&b"not found"[..]))
                .expect("translator 404 response");
        }
    };
    http::Response::builder()
        .header("Content-Type", mime)
        .header("Content-Security-Policy", TRANSLATE_CSP)
                .header(NO_STORE.0, NO_STORE.1)
        .body(Cow::Borrowed(body))
        .expect("translator asset response")
}

fn serve_chrome(request: &http::Request<Vec<u8>>) -> http::Response<Cow<'static, [u8]>> {
    // The region-read panel's image. Token-addressed, chrome-origin only (this
    // protocol exists on no other webview), and served from the bounded
    // in-memory PREVIEW -- the CSP's img-src 'self' stays exactly as it is,
    // and the native PNG never crosses into the chrome renderer. OCR retains
    // and crops the native buffer separately. A token that names nothing
    // (stale panel, replaced capture) is a plain 404.
    if let Some(name) = request.uri().path().strip_prefix("/region-capture/") {
        let png = name
            .strip_suffix(".png")
            .and_then(|t| t.parse::<u64>().ok())
            .and_then(capture::region_preview_png);
        return match png {
            Some(bytes) => http::Response::builder()
                .header("Content-Type", "image/png")
                .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Owned(bytes))
                .expect("region capture response"),
            None => http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Borrowed(&b"not found"[..]))
                .expect("static 404 response"),
        };
    }
    // The Deep Recall preview's image. Same contract as /region-capture/
    // above -- token-addressed, chrome-origin only, stale token is a 404 --
    // with one difference in what the bytes ARE: this is a decrypted page
    // from the encrypted archive, staged one at a time by
    // archive_picture_stage and wiped on preview close, panel close, and
    // vault lock. See archive.rs::STAGED_PICTURE for the custody rules.
    if let Some(name) = request.uri().path().strip_prefix("/archive-picture/") {
        let png = name
            .strip_suffix(".png")
            .and_then(|t| t.parse::<u64>().ok())
            .and_then(archive::staged_png);
        return match png {
            Some(bytes) => http::Response::builder()
                .header("Content-Type", "image/png")
                .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Owned(bytes))
                .expect("archive picture response"),
            None => http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Borrowed(&b"not found"[..]))
                .expect("static 404 response"),
        };
    }
    let (mime, body): (&str, &[u8]) = match request.uri().path() {
        // Same reason as the translator document: a stale chrome.js is how a
        // shipped UI fix silently does not run.
        "/" | "/index.html" => {
            return http::Response::builder()
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Owned(with_asset_revision(INDEX_HTML).into_bytes()))
                .expect("chrome html response");
        }
        "/chrome.css" => ("text/css; charset=utf-8", CHROME_CSS.as_bytes()),
        "/chrome.js" => ("text/javascript; charset=utf-8", CHROME_JS.as_bytes()),
        "/integrity.js" => ("text/javascript; charset=utf-8", INTEGRITY_JS.as_bytes()),
        "/update.js" => ("text/javascript; charset=utf-8", UPDATE_JS.as_bytes()),
        _ => {
            return http::Response::builder()
                .status(404)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
                .body(Cow::Borrowed(&b"not found"[..]))
                .expect("static 404 response");
        }
    };
    http::Response::builder()
        .header("Content-Type", mime)
        .header("Content-Security-Policy", CSP)
                .header(NO_STORE.0, NO_STORE.1)
        .body(Cow::Borrowed(body))
        .expect("static asset response")
}

/// Refuses to start a RELEASE build on a WebKitGTK below the security floor;
/// warns and continues on a WebView2 below its floor.
///
/// A warning that never blocks becomes wallpaper, and this one would be
/// printed on every launch of a stock Debian 12 box, which is precisely how
/// users learn to stop reading warnings. Debug builds warn and continue so
/// development on an old runtime stays possible; release builds refuse,
/// because "we told you in a log line" is not a defence for shipping a
/// browser onto a runtime with known memory-corruption bugs reachable by
/// visiting a page.
///
/// WINDOWS IS THE OTHER WAY ROUND, on purpose. The WebKitGTK floor refuses
/// because Debian 12 will NEVER ship its fix, so the only way forward is an
/// act by the user. The WebView2 Evergreen runtime updates itself, on a
/// rollout that takes days from the Edge release, and nothing the user does
/// in PATANYX hurries it. Refusing to start would lock someone out of their
/// browser for those days, with no console to read the reason in -- so the
/// chrome raises a banner instead (`engine_status` at boot,
/// `#engine-floor-warning`), which says what version clears it and that a
/// restart after the update is all that is needed.
///
/// PATANYX_ALLOW_OLD_ENGINE=1 overrides the Linux refusal, for someone who
/// has genuinely decided to accept it. It is deliberately an environment
/// variable rather than a setting in the UI: this should be an explicit act,
/// not a checkbox someone clicks past.
fn enforce_engine_floor() {
    let engine = platform::engine_info();
    if !engine.below_floor {
        return;
    }
    let override_set = std::env::var("PATANYX_ALLOW_OLD_ENGINE").is_ok_and(|v| v == "1");
    eprintln!(
        "PATANYX: {} {} is below the security floor {}",
        engine.name,
        engine.version_string(),
        engine.floor_string(),
    );
    eprintln!("  {}", engine.advisory);
    if engine.floor_raised() {
        eprintln!(
            "  (The floor was raised past the compiled {} by a signed update manifest \
             or engine advisory; the advisory above names the earlier fix.)",
            platform::join_version(engine.compiled_floor)
        );
    }
    if engine.restart_clears() {
        eprintln!(
            "  The installed runtime is already {}; restarting PATANYX is all that is \
             needed to use it.",
            engine.installed_string()
        );
    }
    if cfg!(windows) {
        eprintln!("  The runtime updates itself; the banner in the window says so. Continuing.");
    } else if !engine.below_compiled_floor {
        // Only a floor raised by a signed manifest is unmet. A signed
        // document may make the browser warn; it may not turn it off.
        eprintln!("  Above the compiled floor; the banner in the window says so. Continuing.");
    } else if cfg!(debug_assertions) {
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

/// The wire name for a `motw::Outcome`, for the `download_finished` event.
/// Spelled here rather than with a serde derive so the strings the chrome
/// matches on are visible in one place next to where they are emitted.
fn mark_outcome_name(outcome: platform::motw::Outcome) -> &'static str {
    use platform::motw::Outcome::*;
    match outcome {
        NotApplicable => "n/a",
        Clean => "clean",
        Scrubbed => "scrubbed",
        Failed => "failed",
        Unknown => "unknown",
    }
}

#[cfg(test)]
mod build_variant_tests {
    /// The title must name the variant, because a user running the build
    /// with no chat compiled in and a user whose chat is broken look
    /// identical otherwise -- and only one of those is a bug.
    #[test]
    fn the_window_title_names_the_build_variant() {
        let title = super::window_title();
        assert!(title.starts_with("PATANYX"), "{title}");
        #[cfg(feature = "premium-unlocked")]
        {
            assert!(
                title.contains(crate::about::UNLOCKED_BUILD_MARKER),
                "an unlocked title must carry the exact public-build tripwire: {title}"
            );
            return;
        }
        #[cfg(not(feature = "premium-unlocked"))]
        {
            assert_eq!(
                title.contains("PATANYX Nabu-X"),
                cfg!(feature = "chat"),
                "the title must say whether this is the Nabu-X build: {title}"
            );
            // A chat build WITHOUT the relay reaches the local network only,
            // and the title must not let it pass for a complete Nabu-X. The
            // word "relay" is deliberately absent from both titles now, so
            // this is asserted on the LAN-only marker instead.
            assert_eq!(
                title.contains("(LAN chat only)"),
                cfg!(feature = "chat") && !cfg!(feature = "relay-client"),
                "only a chat build with no relay may say LAN chat only: {title}"
            );
            assert!(
                !title.contains("relay"),
                "no title says relay any more; Nabu-X already means it: {title}"
            );
        }
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

#[cfg(feature = "premium-unlocked")]
fn window_title() -> &'static str {
    // This warning outranks the chat/relay description when features are
    // combined: mistaking the bypass build for public is the dangerous error,
    // and the full marker must remain visible in a screenshot.
    "PATANYX Browser -- UNLOCKED TEST BUILD: Premium forced on; no license checked"
}

#[cfg(not(feature = "premium-unlocked"))]
fn window_title() -> &'static str {
    match (cfg!(feature = "chat"), cfg!(feature = "relay-client")) {
        (false, _) => "PATANYX Browser",
        // The chat build is its own product: PATANYX Nabu-X (decided
        // 2026-08-27). It was PATANYX-Premium from 2026-08-05 and
        // PATANYX-chat before that. The reason for leaving "Premium" behind
        // is that the plain browser now carries Premium features too, so the
        // word no longer told the two builds apart -- which is the entire job
        // of this title.
        //
        // NO "+ relay" SUFFIX, and that is the point of the name. Nabu-X IS
        // the build with chat and the relay in it, so appending "+ relay"
        // both restated the definition and invented a product name nobody
        // chose. The previous scheme ("Premium + relay") needed the suffix
        // because "Premium" did not imply either one; this name does.
        //
        // The LAN-only arm keeps a suffix for the opposite reason: that build
        // is NOT a complete Nabu-X, it reaches the local network only, and a
        // title claiming otherwise is the one dishonest thing this function
        // could do.
        //
        // The gates match on "PATANYX Nabu-X", which is why the public About
        // copy says "a separate Nabu-X build" and never the full phrase --
        // otherwise the marker would appear in the very binary the gate
        // exists to clear. The gates in build-windows.sh and
        // build-flatpak.sh match this exact fragment; change them together.
        (true, false) => "PATANYX Nabu-X (LAN chat only)",
        (true, true) => "PATANYX Nabu-X",
    }
}

/// The page the first tab opens when the browser is started on its own:
/// PATANYX Search, which we operate. Its front page and that page's own
/// assets are served without access logging, so a launch does not write the
/// person's address anywhere; the privacy policy (Part A s2.1, Part B B.2)
/// says so and this constant is what has to stay true for it to be right.
pub(crate) const HOME_URL: &str = "https://patanyx.com/";

/// What the first tab opens. A URL or search handed on the command line
/// wins outright. With none, the smoke run stays on `about:blank` because
/// its blocking probe has to be the ONLY page load of the run (see the
/// `probe_url` comment in `main`); every other launch opens `HOME_URL`.
///
/// THE COMMAND LINE IS AN UNTRUSTED INPUT and it is checked here, because the
/// first tab is built with `new_tab`, which passes the URL straight to the
/// webview's initial `with_url` -- and an initial load is not a navigation, so
/// it never reaches the navigation handler that guards every later one. Every
/// OTHER way a URL becomes a tab (the `tab_new` IPC command, the new-window
/// handler, a chat-sent tab) already asks `is_allowed_content_url` first; this
/// path did not, so `PATANYX "http://rbchrome.localhost/"` put the trusted
/// chrome document in a content tab, and `file:///…` opened local files the
/// same way (security assessment 2026-08-28, R5).
///
/// A refused argument falls back to the home page rather than failing to start:
/// the user asked for a browser, and the safe page is a better answer than no
/// window. `normalize_input` has already turned bare words into a search, so
/// what arrives here is either a URL or `about:blank`.
fn choose_start_url(positional: Option<String>, smoke_mode: bool) -> String {
    match positional {
        Some(url) if state::is_allowed_content_url(&url) => url,
        Some(refused) => {
            eprintln!(
                "patanyx: refusing to open {refused:?} from the command line; \
                 opening the home page instead"
            );
            HOME_URL.to_string()
        }
        None if smoke_mode => "about:blank".to_string(),
        None => HOME_URL.to_string(),
    }
}

#[cfg(test)]
mod start_url_tests {
    use super::{choose_start_url, HOME_URL};

    #[test]
    fn a_plain_launch_opens_the_home_page() {
        assert_eq!(choose_start_url(None, false), HOME_URL);
        assert!(HOME_URL.starts_with("https://patanyx.com/"));
    }

    #[test]
    fn a_page_on_the_command_line_wins() {
        let given = "https://example.com/x".to_string();
        assert_eq!(choose_start_url(Some(given.clone()), false), given);
        assert_eq!(choose_start_url(Some(given.clone()), true), given);
    }

    /// The smoke sequence proves blocking by making its probe the only page
    /// load; a home page opened first would make that proof ambiguous.
    #[test]
    fn the_smoke_run_keeps_the_first_tab_blank() {
        assert_eq!(choose_start_url(None, true), "about:blank");
    }

    /// A shortcut, a file association or any local launcher chooses this
    /// string, and the first tab's initial load skips the navigation handler.
    /// So the chrome origin and local files must not survive the trip, in any
    /// spelling the predicate knows -- including the trailing-dot one that
    /// defeated it before (security assessment 2026-08-28, R1/R5).
    #[test]
    fn the_command_line_cannot_open_the_chrome_origin_or_local_files() {
        for refused in [
            "http://rbchrome.localhost/",
            "http://rbchrome.localhost./",
            "http://rbchrome.localhost:80/index.html",
            "http://RBCHROME.LOCALHOST/",
            "rbchrome://localhost/index.html",
            "file:///etc/passwd",
            "file:///C:/Users/victim/secret.txt",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ] {
            assert_eq!(
                choose_start_url(Some(refused.to_string()), false),
                HOME_URL,
                "a refused command-line argument still opened: {refused:?}"
            );
            // Smoke mode takes the same path; it must not be a way around it.
            assert_eq!(
                choose_start_url(Some(refused.to_string()), true),
                HOME_URL,
                "smoke mode opened a refused argument: {refused:?}"
            );
        }
    }

    /// And the guard must not have cost the feature: opening a page from the
    /// command line is why the argument exists.
    #[test]
    fn ordinary_pages_on_the_command_line_still_open() {
        for allowed in [
            "https://example.com/x",
            "http://example.com/",
            "https://start.duckduckgo.com/?q=what+is+a+browser",
            "about:blank",
        ] {
            assert_eq!(
                choose_start_url(Some(allowed.to_string()), false),
                allowed,
                "an ordinary command-line page was refused: {allowed:?}"
            );
        }
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
    //
    // DEBUG BUILDS ONLY, and the shipped browser is the reason. This takes a
    // destination path from the command line and writes to it with no validation:
    // it truncates, it follows symlinks, it says nothing (the release build is
    // `windows_subsystem = "windows"`), and it returns before any window exists.
    // In a consumer binary that is an arbitrary-file-write primitive for anyone
    // who can choose PATANYX's arguments -- a crafted shortcut clobbers a chosen
    // file, and a UNC destination makes Windows authenticate to an attacker's SMB
    // server and leak the user's NetNTLMv2 hash (security assessment 2026-08-28,
    // R6). The attacker does not control the bytes, only the path, which is
    // already enough.
    //
    // Nothing is lost by gating it: the publisher builds with a
    // plain `cargo build -q -p patanyx` and runs `$CARGO_TARGET_DIR/debug/patanyx
    // --emit-blocklist`, so the publisher keeps the flag it actually uses, and the
    // byte-identity argument above is untouched because the SAME compiled list is
    // still what emits it.
    #[cfg(debug_assertions)]
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

    // THE ENGINE GATE. Asks the WebKit we are about to ship against whether the
    // shipped ad and tracker rules actually compile, and exits non-zero if not.
    //
    // Not gated on debug_assertions, unlike --emit-blocklist above: that flag
    // WRITES a caller-named path, which is why it is restricted. This one only
    // reads, compiles into a temporary directory it creates itself, and
    // prints a verdict, so it is safe in a release binary -- and it has to be,
    // because the thing worth gating is the RELEASE build's rules against the
    // release image's engine.
    //
    // Unix only. On Windows the rules are answered by a HostSet membership
    // check in our own code rather than compiled by the engine, so there is no
    // engine verdict to ask for.
    #[cfg(unix)]
    if std::env::args().any(|arg| arg == "--verify-content-filter") {
        match platform::verify_content_filters() {
            Ok(()) => {
                println!("CONTENT FILTER OK");
                return;
            }
            Err(why) => {
                eprintln!("CONTENT FILTER FAIL: {why}");
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
    // That is how the OS starts the default browser when someone clicks a
    // link in another application, so when it is present it is the page the
    // person asked for and nothing else opens in its place.
    let positional = std::env::args()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .map(|raw| ipc::normalize_input(&raw));
    let opened_with_url = positional.is_some();
    let start_url = choose_start_url(positional, smoke_mode);

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

    // A pending, verified update may install itself HERE, before any window,
    // webview or vault exists -- the cheapest possible moment to swap the
    // binary. When it does, the replacement is already spawned and this
    // process's only remaining job is to not exist. Feature releases wait for
    // consent or their grace period; the signed manifest decides which is
    // which (updater::apply_pending_at_startup, and the policy table in
    // patanyx-update's Manifest::installs_silently).
    if updater::apply_pending_at_startup() {
        return;
    }

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
            // THE PRIVILEGED DOCUMENT NEEDS THE REVISION TOO, and it was the
            // one left behind. The translator's entry point was versioned
            // after a stale script cost four builds; this one stayed constant,
            // so a profile holding the old index.html keeps requesting its old
            // unversioned chrome.js -- the privileged UI, including its IPC
            // and security-sensitive rendering. Revisioning the scripts inside
            // the document cannot help when the document itself never
            // reloads. Found by an independent audit, 2026-09-01.
            .with_url(&format!(
                "{}?v={}",
                platform::CHROME_URL,
                asset_revision()
            ))
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
            .with_navigation_handler(|url: String| url.starts_with(platform::CHROME_ORIGIN_PREFIX))
            // The privileged UI opens no windows. wry's default when no handler
            // is set falls through to the engine, and this is the one surface
            // where an unguarded default is unacceptable.
            .with_new_window_req_handler(|_url, _features| wry::NewWindowResponse::Deny)
            // The privileged UI downloads nothing. wry's DEFAULT handler allows
            // every download, which would also bypass the sanitized,
            // collision-safe destination that content downloads go through.
            .with_download_started_handler(|_url, _destination| false)
            // NO drag-drop handler here, and the absence is load-bearing.
            //
            // This used to set one, to block file drops onto the chrome. The
            // comment said "there is nothing to lose", and that was wrong.
            // Setting ANY handler makes wry, on Windows, walk the WebView2
            // child windows calling RevokeDragDrop -- tearing out the
            // ENGINE'S OWN drop target -- and register a CF_HDROP-only
            // listener in its place. In-page HTML5 drag and drop is delivered
            // by that engine target, so this silently killed tab reordering.
            //
            // Nothing replaces it, deliberately: SetAllowExternalDrop(false)
            // was tried as a narrower substitute and measured on hardware to
            // break the drag just as thoroughly (see the block comment in
            // platform/windows.rs::harden_privacy). What refuses a dropped
            // file is the navigation handler above -- the chrome may only
            // ever navigate to CHROME_ORIGIN_PREFIX -- plus the fact that the
            // chrome has no file inputs and denies new windows outright.
            // Devtools on the PRIVILEGED webview is a console with vault-adjacent
            // reach, so it needs an explicit opt-in rather than riding along with
            // any debug build. Content webviews keep plain debug-only devtools.
            .with_devtools(cfg!(debug_assertions) && chrome_devtools_opted_in()),
        &proxy,
    )
    .expect("failed to build chrome webview");

    // The isolation battery, measured against THIS webview rather than a
    // stand-in. Diverges, so nothing below runs when it is armed. Absent from
    // release binaries entirely -- the module, the platform helpers and this
    // call site are all `#[cfg(debug_assertions)]`.
    #[cfg(debug_assertions)]
    if isolation_probe::enabled() {
        isolation_probe::run(event_loop, &hosts, &chrome);
    }

    // The translation reply channel's proof, same discipline: diverges, and
    // absent from release binaries entirely.
    #[cfg(all(debug_assertions, unix))]
    if translate_channel_probe::enabled() {
        translate_channel_probe::run(event_loop, &hosts);
    }

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
    // The full-loop self-test needs its own heartbeat: the translation poller
    // only runs while a translation is in flight, and the first click has not
    // happened yet. Debug builds only, and only when explicitly armed.
    #[cfg(all(debug_assertions, unix))]
    if translate_channel_probe::selftest_enabled() {
        let p = proxy.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if p.send_event(UserEvent::TranslateSelfTest).is_err() {
                break;
            }
        });
    }
    // Was this launch handed a page to open? The chrome uses it to decide
    // whether opening the vault would be welcome or an interruption. It is
    // whether an ARGUMENT was given, not whether the first tab has a URL: a
    // plain launch now opens the home page, and that is still the browser
    // opened on its own.
    app.opened_with_url = opened_with_url;
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
            Event::UserEvent(UserEvent::QuitForRelaunch) => {
                // Same reason, and the same exit: Exit unwinds the event loop,
                // which drops AppState and with it the vault, so the key
                // material is zeroized and the vault's file lock is released
                // for the process already waiting at its unlock screen.
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
                        .and_then(|()| ipc::smoke_licence_sequence(&mut app))
                        .and_then(|()| ipc::smoke_tab_sequence(&mut app))
                        .and_then(|()| ipc::smoke_partner_sequence(&mut app))
                        .and_then(|()| ipc::smoke_sponsorship_sequence(&mut app))
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
            Event::UserEvent(UserEvent::SessionWipeFinished) => {
                app.finish_session_wipe()
            }
            Event::UserEvent(UserEvent::UrlChanged(id, url)) => app.on_url_changed(id, url),
            Event::UserEvent(UserEvent::LoadState(id, loading)) => app.on_load_state(id, loading),
            // Text a CONTENT page's extractor posted up. UNTRUSTED, and
            // handled in exactly one place so there is one schema check
            // rather than several. It arrives tagged with the tab id the HOST
            // recorded at construction, never one the page supplied.
            Event::UserEvent(UserEvent::ContentTranslate(id, raw)) => {
                app.on_content_translate(id, &raw);
            }
            Event::UserEvent(UserEvent::TranslateTick) => app.on_translate_tick(),
            #[cfg(all(debug_assertions, unix))]
            Event::UserEvent(UserEvent::TranslateSelfTest) => {
                translate_channel_probe::selftest_step(&mut app);
            }
            Event::UserEvent(UserEvent::PackInstalled(pair, failure)) => {
                app.on_pack_installed(pair, failure);
            }
            Event::UserEvent(UserEvent::PackProgress(pair, got, total)) => {
                app.on_pack_progress(pair, got, total);
            }
            Event::UserEvent(UserEvent::TranslateEngine(json)) => {
                app.on_translate_engine(&json);
            }
            Event::UserEvent(UserEvent::TranslateResult(job, json)) => {
                app.on_translate_result(job, &json);
            }
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
                // Then the mark. On Windows the engine has just written a
                // Zone.Identifier stream carrying the source URL next to the
                // file (observed on a real install, 2026-08-18); this keeps
                // the zone and drops the address. AFTER provenance on
                // purpose: provenance hashes the file's main stream, which
                // this does not touch, but ordering it second means a
                // failure here can never cost the fingerprint. The outcome
                // rides on the finished event so the downloads view can say
                // what happened -- `Failed` in particular, because then the
                // address is still on disk and the user should hear it.
                let mark = match (success, path.as_deref()) {
                    (true, Some(p)) => platform::scrub_download_mark(std::path::Path::new(p)),
                    _ => platform::motw::Outcome::NotApplicable,
                };
                app.emit(
                    "download_finished",
                    json!({
                        "url": url,
                        "path": path,
                        "success": success,
                        "mark": mark_outcome_name(mark),
                    }),
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
            Event::UserEvent(UserEvent::Activation(event)) => {
                activation::handle_event(&mut app, event);
            }
            Event::UserEvent(UserEvent::ArchiveRead {
                png,
                url,
                title,
                scope,
                text,
            }) => {
                app.finish_archive(png, url, title, scope, text);
            }
            Event::UserEvent(UserEvent::Find(event)) => {
                app.on_find_event(event);
            }
            Event::UserEvent(UserEvent::Capture(event)) => {
                app.on_capture_done(event);
            }
            Event::UserEvent(UserEvent::RegionCapturePrepared { result, scope }) => {
                app.on_region_capture_prepared(result, scope);
            }
            Event::UserEvent(UserEvent::SnapshotPicturePrepared { result, scope }) => {
                page_integrity::finish_snapshot_picture(&mut app, result, scope);
            }
            Event::UserEvent(UserEvent::NavigationBlocked { tab_id, host, rule }) => {
                let pending_id = app.note_navigation_blocked(tab_id, &host);
                // The refusal already happened, in the navigation handler.
                // This only tells the user, and it must, or a blocked page is
                // indistinguishable from a broken browser.
                // The sentence is composed HERE, in the locale, with the
                // host and rule crossing as Fluent arguments -- never
                // concatenated into catalog text. The chrome renders the
                // body verbatim; host and rule still ride along for the
                // machine-readable state the gate asserts.
                let rulenote = if !rule.is_empty() && rule != host {
                    let mut args = crate::i18n::Args::default();
                    args.set("rule", rule.as_str());
                    app.i18n
                        .resolve(crate::i18n::keys::CHROME_BLOCKED_RULE_CLAUSE, &args)
                } else {
                    String::new()
                };
                let mut args = crate::i18n::Args::default();
                args.set("host", host.as_str());
                args.set("rulenote", rulenote);
                let body = app
                    .i18n
                    .resolve(crate::i18n::keys::CHROME_BLOCKED_BODY, &args);
                app.emit(
                    "navigation_blocked",
                    json!({ "tab_id": tab_id, "pending_id": pending_id, "host": host, "rule": rule, "body": body }),
                );
            }
            Event::UserEvent(UserEvent::AdlistBlocked { tab_id, url, host, method }) => {
                // The refusal already happened in the engine; this records it
                // on the tab so the chrome can explain and, where the backend
                // allows it, ask. tab_status carries the pending from here.
                if app.adlist_hold(tab_id, &url, &host, &method).is_some() {
                    app.emit_tab_status();
                }
            }
            Event::UserEvent(UserEvent::InsecureNavigation { tab_id, url }) => {
                // Same shape as NavigationBlocked: the refusal already
                // happened; this records it on the tab and lets the chrome
                // ask the user, or a held-back page is indistinguishable from
                // a broken browser.
                app.note_insecure_navigation(tab_id, url);
            }
            Event::UserEvent(UserEvent::LoginSubmitted {
                tab_id,
                source_url,
                username,
                password,
            }) => {
                app.note_login_submitted(tab_id, source_url, username, password);
            }
            Event::UserEvent(UserEvent::FingerprintProbes { tab_id, counts }) => {
                app.note_fingerprint_probes(tab_id, &counts);
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
                // A verified manifest may have raised the engine floor just
                // now (updater::remember_engine_floors). The boot-time
                // engine_status reply already happened, so re-ask and push:
                // a floor that rises mid-session must not wait for a
                // restart to be seen, when seeing it is its entire purpose.
                if let Ok(state) = platform::engine_ipc_status(&app.i18n) {
                    if state["below_floor"] == serde_json::Value::Bool(true) {
                        app.emit("engine_state", state);
                    }
                }
            }
            Event::UserEvent(UserEvent::ResolverProbe(reachable)) => {
                resolver_probe::on_probe_result(reachable, &probe_result_proxy);
            }
            Event::UserEvent(UserEvent::ResolverBanner { visible, mode }) => {
                // Composed once, in the locale, for the same reason the
                // blocked banner is: the words a fail-closed claim uses are
                // catalog property, and the chrome renders them verbatim.
                let body = resolver_probe::banner_body(&app.i18n, &mode);
                app.emit(
                    "resolver_state",
                    serde_json::json!({ "unreachable": visible, "mode": mode, "body": body }),
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
                    Shortcut::OpenDeveloperTools => {
                        // The accelerator has nowhere to report "no active tab";
                        // the panel button is the path that surfaces it.
                        let _ = app.open_active_devtools();
                    }
                    // The chrome owns the bar; the key asks it to open AND
                    // takes keyboard focus off the page first, or the bar
                    // opens with a caret in it that receives nothing.
                    Shortcut::OpenFind => app.open_find_bar(),
                    // Same shape as OpenFind: the chrome owns the panel, the
                    // key only asks it to open, and the premium gate lives
                    // in the find_tabs_search arm -- the key is never a way
                    // around the licence.
                    Shortcut::OpenFindAcrossTabs => app.emit("find_tabs_open", json!({})),
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
            Event::UserEvent(UserEvent::WindowFrameSettled) => {
                app.refresh_window_accent();
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

#[cfg(test)]
mod info_tab_tests {
    //! Pins that the certificate ISSUER string is DISPLAY ONLY. The security
    //! verdict comes from `classify_issuer`; the issuer text is shown in the
    //! Info tab and must never steer a decision, or a hostile-issuer string
    //! could influence behaviour instead of merely being labelled.

    /// The issuer string is never read into a control-flow branch. Source-level
    /// pin: `tls_issuer` may be ASSIGNED and EMITTED, never matched or tested.
    #[test]
    fn tls_issuer_is_display_only() {
        for src in [
            include_str!("state.rs"),
            include_str!("platform/unix.rs"),
            include_str!("platform/windows.rs"),
        ] {
            for line in src.lines() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                // A decision would look like `if ... tls_issuer` or
                // `match ... tls_issuer` or `tls_issuer ==`. None may exist.
                let mentions = line.contains("tls_issuer");
                if !mentions {
                    continue;
                }
                assert!(
                    !(t.starts_with("if ") || t.starts_with("match ")),
                    "tls_issuer must not appear in a branch: {line}"
                );
                assert!(
                    !line.contains("tls_issuer ==") && !line.contains("tls_issuer.eq"),
                    "tls_issuer must not be compared: {line}"
                );
            }
        }
    }
}

#[cfg(test)]
mod translator_origin_tests {
    //! Pins the phase-0 fix. Every assertion here corresponds to something
    //! that was MEASURED to leak when the translator shared the chrome
    //! origin (`docs/page-translation-spike.md`), so a future change that
    //! quietly undoes one of them fails here rather than in a browser.

    use super::*;

    /// The whole fix in one line. If these ever match, a view that holds text
    /// scraped from hostile pages is back on the privileged UI's origin, and
    /// the storage leak returns with it.
    #[test]
    fn the_translator_does_not_share_the_chrome_origin() {
        assert_ne!(
            platform::TRANSLATE_ORIGIN_PREFIX,
            platform::CHROME_ORIGIN_PREFIX,
            "the translator webview must not share the chrome origin"
        );
        assert!(!platform::TRANSLATE_URL.starts_with(platform::CHROME_ORIGIN_PREFIX));
        assert!(!platform::CHROME_URL.starts_with(platform::TRANSLATE_ORIGIN_PREFIX));
    }

    /// The endpoints that make sharing a handler dangerous. serve_chrome
    /// answers /region-capture/ with a screen capture and /archive-picture/
    /// with a DECRYPTED page from the encrypted archive; phase 0 confirmed a
    /// fetch from a second webview reaches its handler. The translator's
    /// handler must answer neither, and must not answer chrome's assets
    /// either.
    #[test]
    fn the_translator_handler_serves_nothing_the_chrome_handler_serves() {
        for path in [
            "/region-capture/1.png",
            "/archive-picture/1.png",
            "/index.html",
            "/chrome.js",
            "/chrome.css",
            "/integrity.js",
            "/update.js",
        ] {
            let req = http::Request::builder()
                .uri(format!("rbtranslate://localhost{path}"))
                .body(Vec::new())
                .expect("request");
            let res = serve_translator(&req);
            assert_eq!(
                res.status(),
                404,
                "the translator origin must not serve {path}"
            );
        }
    }

    /// A wry protocol handler runs across an extern "C" boundary, so a panic
    /// inside it ABORTS the process rather than unwinding. Phase 0 lost three
    /// hardware runs to exactly that, because WebView2 asks a custom scheme
    /// for /favicon.ico unprompted.
    #[test]
    fn the_translator_handler_answers_hostile_paths_without_panicking() {
        for path in [
            "/",
            "/favicon.ico",
            "/../../etc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "//",
            "/translator.html?x=1",
            "/\u{202e}rewrite",
        ] {
            let req = http::Request::builder()
                .uri(format!("rbtranslate://localhost{path}"))
                .body(Vec::new())
                .expect("request");
            let res = serve_translator(&req);
            assert!(res.status() == 200 || res.status() == 404, "{path}");
        }
    }

    /// Every response carries the policy, including the 404 -- the same rule
    /// serve_chrome follows.
    #[test]
    fn every_translator_response_carries_its_policy() {
        for path in ["/translator.html", "/nope"] {
            let req = http::Request::builder()
                .uri(format!("rbtranslate://localhost{path}"))
                .body(Vec::new())
                .expect("request");
            let res = serve_translator(&req);
            assert_eq!(
                res.headers()
                    .get("Content-Security-Policy")
                    .and_then(|v| v.to_str().ok()),
                Some(TRANSLATE_CSP),
                "{path} must carry the translator policy"
            );
        }
    }

    /// The translator policy is the chrome policy plus EXACTLY the two
    /// directives phase 0 measured as necessary, and nothing else. Written as
    /// a test because "two directives looser" is the claim the separate origin
    /// is justified by: if this drifts, the justification drifts with it.
    #[test]
    fn the_translator_policy_is_looser_by_exactly_two_directives() {
        assert!(
            TRANSLATE_CSP.contains("connect-src 'self'"),
            "without it the engine cannot fetch its own .wasm"
        );
        assert!(
            TRANSLATE_CSP.contains("'wasm-unsafe-eval'"),
            "without it WebAssembly refuses to compile"
        );
        // The chrome policy must NOT have acquired either of them. That is
        // what moving the translator off the shared origin bought.
        assert!(CSP.contains("connect-src 'none'"), "chrome must stay closed");
        assert!(!CSP.contains("wasm-unsafe-eval"), "chrome must stay closed");
        // Everything else stays identical, so the delta is auditable.
        for directive in [
            "default-src 'none'",
            "style-src 'self'",
            "img-src 'self'",
            "form-action 'none'",
            "base-uri 'none'",
        ] {
            assert!(TRANSLATE_CSP.contains(directive), "missing {directive}");
            assert!(CSP.contains(directive), "missing {directive}");
        }
    }

    /// The translator's data directory sits BESIDE the browsing profile, not
    /// inside it: a future "clear browsing data" that empties the profile must
    /// not silently take downloaded language packs with it.
    #[test]
    fn the_translator_data_directory_is_not_inside_the_browsing_profile() {
        let vault = std::path::Path::new("/tmp/x/vault.db");
        let browsing = platform::browsing_profile_dir(vault);
        let translator = platform::translator_profile_dir_for(vault);
        assert_ne!(browsing, translator);
        assert!(
            !translator.starts_with(&browsing),
            "{translator:?} must not sit inside {browsing:?}"
        );
    }
}
