//! The host side of a separately delivered add-on.
//!
//! An add-on runs in its OWN webview: its own origin (`rbaddon-<id>`), its own
//! engine folder (one per session, removed when the session ends), and its
//! own channel, `UserEvent::AddonIpc`, which never reaches `ipc::dispatch`.
//! The add-on can ask only for what `addon_protocol::Command` lists, and this
//! module answers each one.
//!
//! WHAT FENCES IT IN.
//! - The bytes it runs are the verified bundle's, served from memory by
//!   `serve`; an unlisted path is a 404.
//! - Every response carries `ADDON_CSP`: no network, no frames, no workers,
//!   no plugins, no forms, no inline code.
//! - Navigation is locked to its own origin; new windows and downloads are
//!   refused. On Windows a request wall answers every other request with a
//!   403 before it leaves (`platform::build_addon`), because WebView2 sends a
//!   refused navigation's request anyway.
//! - Every frame is checked against the generation captured when THIS window
//!   was built. A frame from an older window is ignored; a frame that claims
//!   another generation is refused.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};
use wry::{http, WebView};

use crate::addon_protocol::{self as proto, Command};
use crate::addon_session::{self, Reason, Then};
use crate::addon_storage::{self, Job, Outcome};
use crate::platform;
use crate::state::AppState;
use crate::UserEvent;

/// Every response from an add-on origin carries this.
pub const ADDON_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self'; font-src 'self'; connect-src 'none'; frame-src 'none'; child-src 'none'; \
worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; media-src 'none'; \
manifest-src 'none'";

pub const MIN_W: f64 = 220.0;
pub const MIN_H: f64 = 160.0;
/// The add-on's title strip, which is all a collapsed window shows.
pub const COLLAPSED_H: f64 = 40.0;

pub(crate) type Rect = (f64, f64, f64, f64);

/// Non-secret window preferences, beside the other layout preferences.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(default)]
pub struct WindowMemory {
    pub wanted: Rect,
    pub collapsed: bool,
}

impl Default for WindowMemory {
    fn default() -> Self {
        Self { wanted: (40.0, 40.0, 420.0, 360.0), collapsed: false }
    }
}

impl WindowMemory {
    pub fn checked(self) -> Self {
        let (x, y, w, h) = self.wanted;
        if [x, y, w, h].iter().all(|v| v.is_finite()) && w > 0.0 && h > 0.0 {
            self
        } else {
            Self::default()
        }
    }
}

/// The verified files of one add-on version, served only from memory.
pub struct ServedBundle {
    pub id: String,
    /// Display name from the verified manifest.
    pub name: String,
    pub version: String,
    pub files: HashMap<String, Arc<Vec<u8>>>,
}

/// An open add-on window.
pub struct AddonSession {
    pub id: String,
    pub name: String,
    pub version: String,
    /// Captured when this window was built; every frame must carry it.
    pub generation: u64,
    webview: WebView,
    engine_dir: PathBuf,
    /// Applied rectangle, relative to the page area.
    pub rect: Cell<Rect>,
    /// What was last asked for; the applied rect is always its clamp.
    pub wanted: Cell<Rect>,
    pub collapsed: Cell<bool>,
    ready: Cell<bool>,
    /// Whether writes are admitted (Premium active) or only reads (lapsed).
    pub mode: Cell<Mode>,
    /// Why it is read-only, as the add-on is told (`addon_entitlement`).
    pub reason: Cell<Option<&'static str>>,
    /// The storage worker, started at the first storage request.
    worker: RefCell<Option<addon_storage::Worker>>,
    /// Set while the session ends (`addon_session`).
    pub(crate) ending: RefCell<Option<addon_session::Ending>>,
    /// Selections handed over and not yet answered (`deliver_selection`).
    deliveries: RefCell<std::collections::HashSet<String>>,
    /// The last request id: ids rise within a generation, so none repeats.
    last_request: Cell<u32>,
    /// The latest geometry sequence the add-on sent; host-driven geometry
    /// carries it, or the add-on would discard it as older.
    last_sequence: Cell<u32>,
    /// The geometry the add-on was last told, so only changes are sent.
    told_geometry: RefCell<Option<Value>>,
    /// The active tab's site the add-on was last told (outer `None`: not
    /// told yet), so only changes are sent.
    told_site: RefCell<Option<Option<String>>>,
    /// Whether the add-on has been told the browser's theme yet.
    told_theme: Cell<bool>,
}

impl AddonSession {
    /// The add-on has said it is ready, so it may hold unsaved text.
    pub fn is_ready(&self) -> bool {
        self.ready.get()
    }

    /// Every storage request it was given has been answered.
    pub fn storage_idle(&self) -> bool {
        self.worker.borrow().as_ref().is_none_or(|w| w.pending == 0)
    }

    fn is_ending(&self) -> bool {
        self.ending.borrow().is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Full,
    ReadOnly,
}

/// An add-on id: lowercase letters, digits and single hyphens, 1 to 32.
pub fn id_ok(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
}

/// Keeps `r` inside an area of `aw` x `ah`. Containment wins over the
/// minimum size: on a page smaller than the minimum, the window is the page.
pub fn clamp_rect(r: Rect, aw: f64, ah: f64, collapsed: bool) -> Rect {
    let aw = aw.max(1.0);
    let ah = ah.max(1.0);
    let min_w = MIN_W.min(aw);
    let min_h = if collapsed { COLLAPSED_H } else { MIN_H }.min(ah);
    let w = r.2.clamp(min_w, aw);
    let h = if collapsed { min_h } else { r.3.clamp(min_h, ah) };
    let x = r.0.clamp(0.0, (aw - w).max(0.0));
    let y = r.1.clamp(0.0, (ah - h).max(0.0));
    (x, y, w, h)
}

fn mime_for(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Serves only the verified bundle's files, from memory.
pub fn serve(files: &HashMap<String, Arc<Vec<u8>>>, request: &http::Request<Vec<u8>>) -> http::Response<Cow<'static, [u8]>> {
    let path = request.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match files.get(path) {
        Some(bytes) => http::Response::builder()
            .header("Content-Type", mime_for(path))
            .header("Content-Security-Policy", ADDON_CSP)
            .header("Cache-Control", "no-store")
            .header("X-Content-Type-Options", "nosniff")
            .body(Cow::Owned(bytes.as_ref().clone()))
            .expect("add-on response"),
        None => http::Response::builder()
            .status(404)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Content-Security-Policy", ADDON_CSP)
            .header("Cache-Control", "no-store")
            .body(Cow::Borrowed(&b"not found"[..]))
            .expect("add-on 404"),
    }
}

/// The script run before the bundle's own: the three facts the add-on needs
/// to address the host, frozen. Never authority (the host checks the
/// generation it captured itself).
fn host_facts_script(id: &str, generation: u64) -> String {
    format!(
        "Object.defineProperty(window,'__addonHost',{{value:Object.freeze({{host_api:{},addon_id:{},generation:{}}}),writable:false,configurable:false}});",
        proto::HOST_API,
        serde_json::to_string(id).unwrap_or_default(),
        serde_json::to_string(&generation.to_string()).unwrap_or_default(),
    )
}

/// Opens `bundle` in a new add-on window. One add-on window at a time.
pub fn open(app: &mut AppState, bundle: ServedBundle) -> Result<(), String> {
    if app.addon.is_some() {
        return Err("already_open".to_string());
    }
    // Nothing reopens the add-on's files while a Library replacement runs or
    // an earlier window's worker is still writing to them.
    if crate::backup_job::importing(app) || crate::addon_manager::busy(app) || !addon_session::quiescent(app) {
        return Err("busy".to_string());
    }
    if !id_ok(&bundle.id) {
        return Err("bad_id".to_string());
    }
    if !bundle.files.contains_key("index.html") {
        return Err("no_entry_point".to_string());
    }
    let generation = app.next_addon_generation();
    let base = platform::addon_profile_dir_for(&patanyx_vault::Vault::default_path(), &bundle.id);
    // Engine storage is not the encrypted page store (PLAN 2.2, compliance
    // audit A5): each session gets a fresh folder, and folders left by
    // earlier sessions (whose removal the engine held up) go now.
    sweep_engine_dirs(&base);
    let engine_dir = base.join(format!("s{generation}-{:016x}", session_nonce()));
    let prefix = platform::addon_origin_prefix(&bundle.id);
    let url = platform::addon_url(&bundle.id);
    let files = Arc::new(bundle.files);
    let proxy = app.proxy();
    let nav_prefix = prefix.clone();
    // Before the add-on's page paints, the engine fills its window with its
    // default background, white: a white flash of about a quarter second on
    // every open over a dark chrome (found recording the add-on video,
    // 2026-11-03). The chrome's own surface colour instead, so the window
    // opens in the scheme it is about to wear.
    let surface = app.chrome_palette().caption;
    let builder = platform::new_addon_webview_builder(&engine_dir)?
        .with_background_color((surface[0], surface[1], surface[2], 255))
        .with_focused(false)
        .with_initialization_script(&host_facts_script(&bundle.id, generation))
        .with_custom_protocol(platform::addon_scheme(&bundle.id), move |_id, request: http::Request<Vec<u8>>| {
            serve(&files, &request)
        })
        .with_ipc_handler(move |request: http::Request<String>| {
            let _ = proxy.send_event(UserEvent::AddonIpc { generation, raw: request.body().clone(), #[cfg(debug_assertions)] received: std::time::Instant::now() });
        })
        .with_navigation_handler(move |url: String| {
            let allowed = url.starts_with(&nav_prefix);
            // Never the address: the add-on chose it, and it could carry text.
            #[cfg(debug_assertions)]
            if !allowed {
                eprintln!("addon: navigation refused");
            }
            allowed
        })
        .with_new_window_req_handler(|_url, _features| wry::NewWindowResponse::Deny)
        .with_download_started_handler(|_url, _destination| false)
        .with_devtools(false);
    let webview = match platform::build_addon(&app.hosts, builder, &url, &prefix) {
        Ok(webview) => webview,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&engine_dir);
            return Err(e);
        }
    };
    platform::connect_addon_presence(&webview, &app.proxy());
    platform::connect_addon_layout(&app.hosts, &app.proxy());
    let memory = app.addon_geometry.borrow().get(&bundle.id).copied().unwrap_or_default().checked();
    let start = memory.wanted;
    app.addon = Some(AddonSession {
        id: bundle.id,
        name: bundle.name,
        version: bundle.version,
        generation,
        webview,
        engine_dir,
        rect: Cell::new(start),
        wanted: Cell::new(start),
        collapsed: Cell::new(memory.collapsed),
        ready: Cell::new(false),
        mode: Cell::new(Mode::Full),
        reason: Cell::new(None),
        worker: RefCell::new(None),
        ending: RefCell::new(None),
        deliveries: RefCell::new(std::collections::HashSet::new()),
        last_request: Cell::new(0),
        last_sequence: Cell::new(0),
        told_geometry: RefCell::new(None),
        told_site: RefCell::new(None),
        told_theme: Cell::new(false),
    });
    apply(app);
    focus(app);
    Ok(())
}

/// Ends the add-on window at once: the view is dropped, its generation dies
/// with it, and its engine folder is removed (or left for the next sweep
/// while the engine still holds it). Every exit path reaches this through
/// `addon_session`, which gives the add-on its chance to save first.
pub fn destroy(app: &mut AppState) {
    remember(app);
    if let Some(session) = app.addon.take() {
        platform::destroy_addon(&app.hosts);
        // A worker still inside a write keeps going on the old namespace; it
        // is tracked until it stops (`addon_session::quiescent`).
        if let Some(worker) = session.worker.borrow_mut().take() {
            app.addon_draining.push(worker.quiet_token());
        }
        let dir = session.engine_dir.clone();
        drop(session);
        let _ = std::fs::remove_dir_all(dir);
        if app.focus_intent.get() == crate::state::FocusSurface::Addon {
            app.focus_active_content();
        }
    }
}

fn remember(app: &AppState) {
    if let Some(session) = &app.addon {
        let memory = WindowMemory { wanted: session.wanted.get(), collapsed: session.collapsed.get() };
        app.addon_geometry.borrow_mut().insert(session.id.clone(), memory);
        // Moves never wait for prefs I/O. Persist only when this view ends.
        let mut prefs = crate::prefs::load();
        prefs.addon_windows = app.addon_geometry.borrow().clone();
        let _ = crate::prefs::save(&prefs);
    }
}

pub fn focus(app: &AppState) -> bool {
    let Some(session) = &app.addon else { return false };
    let area = platform::addon_area(&app.hosts, app.active_webview());
    if hidden_reason(app, area).is_some() || session.is_ending() {
        return false;
    }
    app.focus_intent.set(crate::state::FocusSurface::Addon);
    let _ = session.webview.focus();
    true
}

/// The add-on shortcut: collapse or expand an open window. With no window
/// open, a debug build reopens its development add-on (a test package has no
/// other way back after Close), under the manager's own rule: only while the
/// Vault is unlocked. A release build has nothing to open here.
pub fn shortcut(app: &mut AppState) {
    if app.addon.is_some() {
        toggle(app, false);
        return;
    }
    #[cfg(debug_assertions)]
    if app.vault.is_some() {
        dev_open_bundle(app);
    }
}

/// The native toggle (Ctrl+Shift+J) only changes an already open window.
pub fn toggle(app: &AppState, collapse: bool) {
    let Some(session) = &app.addon else { return };
    if session.is_ending() || app.addon_hidden_by_modal() { return; }
    session.collapsed.set(collapse || !session.collapsed.get());
    apply(app);
    focus(app);
}

/// At startup, before any add-on window exists: the engine folders of every
/// add-on's earlier sessions go.
pub fn sweep_all_engine_dirs() {
    let base = platform::addon_profile_dir_for(&patanyx_vault::Vault::default_path(), "x");
    let Some(root) = base.parent() else {
        return;
    };
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                sweep_engine_dirs(&entry.path());
            }
        }
    }
}

fn sweep_engine_dirs(base: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

fn session_nonce() -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    u64::from_le_bytes(b)
}

/// Re-clamps the add-on to the current page area and shows it, or hides it
/// while a modal covers the window, a page is fullscreen, or the page area
/// is empty. Called at the end of every relayout and after tab changes.
pub fn apply(app: &AppState) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    let area = platform::addon_area(&app.hosts, app.active_webview());
    // An ending session is out of the person's reach.
    let visible = hidden_reason(app, area).is_none() && !session.is_ending();
    let r = apply_rect(session.wanted.get(), area, session.collapsed.get(), |r| {
        platform::place_addon_in(&app.hosts, &session.webview, (area.0, area.1), r, visible);
    });
    session.rect.set(r);
    // Under the latest sequence the add-on sent, never 0: the add-on drops a
    // geometry older than its last move or resize, so after one, a
    // host-driven change (Ctrl+Shift+J, a layout change) reached the window
    // but not the add-on, which kept drawing its old state in the new frame
    // (add-on hand test 2026-10-21, H-11).
    if session.is_ready() { emit(app, "addon_geometry", told(app)); }
}

fn apply_rect(wanted: Rect, area: Rect, collapsed: bool, place: impl FnOnce(Rect)) -> Rect {
    let r = clamp_rect(wanted, area.2, area.3, collapsed);
    place(r);
    r
}

fn hidden_reason(app: &AppState, area: Rect) -> Option<&'static str> {
    if app.page_fullscreen.is_some() {
        Some("fullscreen")
    } else if app.addon_hidden_by_modal() {
        Some("modal")
    } else if area.2 < 1.0 || area.3 < 1.0 {
        Some("empty_area")
    } else {
        None
    }
}

fn geometry(app: &AppState, session: &AddonSession, sequence: u32) -> Value {
    let area = platform::addon_area(&app.hosts, app.active_webview());
    let (x, y, w, h) = session.rect.get();
    let hidden = hidden_reason(app, area);
    json!({
        "sequence": sequence, "x": x, "y": y, "width": w, "height": h,
        "collapsed": session.collapsed.get(), "visible": hidden.is_none(), "hidden_reason": hidden,
    })
}

/// The geometry now, under the latest sequence, recorded as told.
fn told(app: &AppState) -> Value {
    let Some(session) = app.addon.as_ref() else {
        return Value::Null;
    };
    let now = geometry(app, session, session.last_sequence.get());
    *session.told_geometry.borrow_mut() = Some(now.clone());
    now
}

/// After a host-driven layout change (a resize of the window, a modal, a
/// fullscreen page): tells the add-on its geometry if it changed.
pub fn notify_geometry(app: &AppState) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    if session.ending.borrow().is_some() || !session.is_ready() {
        return;
    }
    let now = geometry(app, session, session.last_sequence.get());
    if session.told_geometry.borrow().as_ref() != Some(&now) {
        *session.told_geometry.borrow_mut() = Some(now.clone());
        emit(app, "addon_geometry", now);
    }
}

/// After every event: tells a ready add-on the active tab's site (its
/// registrable domain, `site_for`; `null` for anything that is not an
/// http(s) site) when it differs from what the add-on was last
/// told. Checking after every event covers navigation, tab switches, both
/// tab-close paths and Ready without a hook in each. Only while the Vault is
/// unlocked; the add-on keeps the value in memory and stores a site only
/// when the user attaches a page to it.
pub fn site_check(app: &AppState) {
    let Some(session) = &app.addon else { return };
    if !session.is_ready() || session.is_ending() || app.vault.is_none() {
        return;
    }
    let Some(site) = site_update(session.told_site.borrow().as_ref(), &app.active_url()) else { return };
    *session.told_site.borrow_mut() = Some(site.clone());
    emit(app, "addon_site", json!({ "site": site }));
}

/// The site to tell the add-on for `url`, or `None` when that is what it was
/// last told (`told`; `None` when it was never told).
fn site_update(told: Option<&Option<String>>, url: &str) -> Option<Option<String>> {
    let site = site_for(url);
    (told != Some(&site)).then_some(site)
}

/// The registrable domain of an http(s) URL in the one form a page can be
/// attached to. A tab can hold the URL as typed until its first load commits,
/// so it is parsed first: the URL parser applies IDNA, and `bücher.de`
/// becomes `xn--bcher-kva.de`, which the store's validator accepts. Anything
/// the validator would refuse is `None`, so no value the add-on is told can
/// make a later save unsavable.
fn site_for(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    crate::duplicate_site::site_key(parsed.as_str()).filter(|site| patanyx_store::valid_site(site))
}

/// After every event: tells a newly ready add-on the browser's color scheme
/// and accent once (one prefs read per window); later changes come from
/// `theme_changed`.
pub fn theme_check(app: &AppState) {
    let Some(session) = &app.addon else { return };
    if session.told_theme.get() || !session.is_ready() || session.is_ending() {
        return;
    }
    session.told_theme.set(true);
    let prefs = crate::prefs::load();
    emit(app, "addon_theme", theme_json(prefs.chrome_scheme, prefs.chrome_theme));
}

/// The scheme or the accent changed: an open window follows at once.
pub fn theme_changed(app: &AppState, scheme: crate::prefs::ChromeScheme, accent: crate::prefs::ChromeTheme) {
    let Some(session) = &app.addon else { return };
    if !session.is_ready() || session.is_ending() {
        // Not deliverable now (an ending can resume read-only after a
        // Premium lapse): `theme_check` sends the saved choice once it can.
        session.told_theme.set(false);
        return;
    }
    session.told_theme.set(true);
    emit(app, "addon_theme", theme_json(scheme, accent));
}

/// The names the chrome wears as `data-scheme` and `data-theme`.
fn theme_json(scheme: crate::prefs::ChromeScheme, accent: crate::prefs::ChromeTheme) -> Value {
    json!({ "scheme": scheme.as_str(), "accent": accent.as_str() })
}

/// The Vault's notes changed (added, edited, deleted): the add-on refetches.
pub fn notes_changed(app: &AppState) {
    emit(app, "vault_notes_changed", json!({}));
}

fn send(session: &AddonSession, frame: &str) {
    // A frame is JSON, which is a valid JavaScript expression; no title or
    // page text is ever interpolated as source.
    let _ = session
        .webview
        .evaluate_script(&format!("window.__addonReceive&&window.__addonReceive({frame})"));
}

fn write_marker(marker: &std::path::Path) {
    if let Some(dir) = marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(marker, b"");
}

/// Switches the open window's mode and tells the add-on. An editable session
/// carries the incomplete-session marker from here on.
pub fn set_mode(app: &AppState, mode: Mode, reason: Option<&'static str>) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    session.mode.set(mode);
    session.reason.set(if mode == Mode::Full { None } else { reason });
    if mode == Mode::Full {
        write_marker(&addon_session::incomplete_marker(&session.id));
    }
    let wire = if mode == Mode::Full { "full" } else { "read_only" };
    emit(app, "addon_mode_changed", json!({ "mode": wire, "reason": session.reason.get() }));
}

/// Sends a host event to the open add-on, if any.
pub fn emit(app: &AppState, name: &str, data: Value) {
    if let Some(session) = app.addon.as_ref() {
        if let Some(frame) = proto::event(session.generation, name, data) {
            send(session, &frame);
        }
    }
}

/// Handles one frame from the add-on window built at `generation`.
pub fn handle_ipc(app: &mut AppState, generation: u64, raw: &str) {
    // A frame from a window that is no longer the open one is ignored: that
    // view is gone or going, and nothing it says reaches the new session.
    match app.addon.as_ref() {
        Some(session) if session.generation == generation => {}
        _ => return,
    }
    let request = match proto::parse(raw) {
        Ok(request) => request,
        Err(rejection) => {
            #[cfg(debug_assertions)]
            eprintln!("addon: frame refused ({})", rejection.error.code());
            if let Some(session) = app.addon.as_ref() {
                send(session, &proto::failure(rejection.id, generation, rejection.error.code()));
            }
            return;
        }
    };
    if request.generation != generation {
        if let Some(session) = app.addon.as_ref() {
            send(session, &proto::failure(Some(request.id), generation, "stale_session"));
        }
        return;
    }
    if let Some(session) = app.addon.as_ref() {
        // Request ids rise within a generation, so a repeated one (a replayed
        // create, say) never runs twice.
        if request.id <= session.last_request.get() {
            send(session, &proto::failure(Some(request.id), generation, "bad_frame"));
            return;
        }
        session.last_request.set(request.id);
        if let Some(code) = addon_session::admission(session.ending.borrow().as_ref(), &request.command) {
            send(session, &proto::failure(Some(request.id), generation, code));
            return;
        }
    }
    // A frame never counts as someone being here, `presence` or not: a
    // bundle could send one on a timer and keep the Vault open forever.
    // Typing in the add-on's window counts, natively, as it does in a tab
    // (`platform::connect_addon_presence`).
    let id = request.id;
    #[cfg(debug_assertions)]
    let name = request.command.name();
    #[cfg(debug_assertions)]
    let timing = crate::addon_window_timing::begin(match &request.command {
        Command::WindowMove { sequence, .. } | Command::WindowResize { sequence, .. } => Some(*sequence),
        _ => None,
    });
    let outcome = answer(app, id, request.command);
    #[cfg(debug_assertions)]
    crate::addon_window_timing::handled(timing);
    #[cfg(debug_assertions)]
    eprintln!(
        "addon: {name} -> {}",
        match &outcome {
            Answer::Reply(_) => "ok",
            Answer::Refuse(code) => code,
            Answer::Close => "closing",
            Answer::Pending => "queued",
        }
    );
    match outcome {
        Answer::Reply(result) => {
            if let Some(session) = app.addon.as_ref() {
                send(session, &proto::success(id, generation, result));
            }
        }
        Answer::Refuse(code) => {
            if let Some(session) = app.addon.as_ref() {
                send(session, &proto::failure(Some(id), generation, code));
            }
        }
        Answer::Close => {
            if let Some(session) = app.addon.as_ref() {
                send(session, &proto::success(id, generation, json!({ "closing": true })));
            }
            addon_session::end(app, Reason::WindowClose, Then::NOTHING);
        }
        // Answered by `storage_done` when the worker finishes.
        Answer::Pending => {}
    }
    addon_session::settle(app);
}

enum Answer {
    Reply(Value),
    Refuse(&'static str),
    Close,
    Pending,
}

/// Admits a storage job and queues it on the session's worker, starting the
/// worker (and with it the namespace's recovery) at the first request.
fn admit_storage(app: &mut AppState, request_id: u32, job: Job) -> Answer {
    if app.vault.is_none() {
        return Answer::Refuse("vault_locked");
    }
    // The Library is being replaced: nothing written to it now would survive.
    // The one exception is the final save of the session the import is
    // ending; the import's commit waits for it (`backup_job::staged_ready`).
    let final_save = app.addon.as_ref().is_some_and(|s| s.is_ending());
    if crate::backup_job::importing(app) && !final_save {
        return Answer::Refuse("busy");
    }
    let proxy = app.proxy();
    let Some(session) = app.addon.as_ref() else {
        return Answer::Refuse("stale_session");
    };
    // Writes need live Premium, checked against today's date on every one
    // (the loop's next recheck then starts the lapse and its final save).
    if matches!(job, Job::Put { .. })
        && !final_save
        && (session.mode.get() == Mode::ReadOnly
            || crate::addon_entitlement::current() != crate::addon_entitlement::Access::Full)
    {
        return Answer::Refuse("premium_required");
    }
    let mut worker = session.worker.borrow_mut();
    if worker.is_none() {
        let Some(store) = app.store.as_ref() else {
            return Answer::Refuse("storage_unavailable");
        };
        let Ok(namespace) = store.addon_namespace(&session.id) else {
            return Answer::Refuse("storage_unavailable");
        };
        *worker = Some(addon_storage::Worker::spawn(namespace, session.generation, proxy));
    }
    match worker.as_mut().expect("started above").submit(request_id, job) {
        Ok(()) => Answer::Pending,
        Err(code) => Answer::Refuse(code),
    }
}

/// A storage job finished on the worker.
pub fn storage_done(app: &mut AppState, generation: u64, request_id: u32, outcome: Outcome, bytes: usize) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    // A completion for an older window is dropped: its view is gone.
    if session.generation != generation {
        return;
    }
    if let Some(worker) = session.worker.borrow_mut().as_mut() {
        worker.done(bytes);
    }
    if let Some(ending) = session.ending.borrow_mut().as_mut() {
        if ending.flush_request == Some(request_id) && matches!(outcome, Outcome::Refuse(_)) {
            ending.flush_failed = true;
        }
    }
    let frame = match outcome {
        Outcome::Reply(result) => proto::success(request_id, generation, result),
        Outcome::Refuse(code) => proto::failure(Some(request_id), generation, code),
    };
    send(session, &frame);
    addon_session::settle(app);
}

/// The most selections handed to the add-on and not yet answered.
const MAX_PENDING_DELIVERIES: usize = 8;

/// The open add-on, if it can take a selection now: it has said it is
/// ready, writes are admitted, it is not ending, and the Vault is unlocked.
pub fn selection_receiver(app: &AppState) -> Option<crate::addon_selection::ReceiverInfo> {
    let session = app.addon.as_ref()?;
    (app.vault.is_some() && session.is_ready() && session.mode.get() == Mode::Full && !session.is_ending()).then(|| {
        crate::addon_selection::ReceiverInfo { id: session.id.clone(), name: session.name.clone() }
    })
}

/// Hands a selection the person chose to send to the open add-on. False when
/// it cannot take one now. Its answer is `addon_selection_result`.
pub fn deliver_selection(app: &AppState, text: &str) -> bool {
    if selection_receiver(app).is_none() {
        return false;
    }
    let Some(session) = app.addon.as_ref() else {
        return false;
    };
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return false;
    }
    let delivery_id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    {
        let mut pending = session.deliveries.borrow_mut();
        if pending.len() >= MAX_PENDING_DELIVERIES {
            return false;
        }
        pending.insert(delivery_id.clone());
    }
    emit(app, "addon_selection", json!({ "delivery_id": delivery_id, "text_b64": proto::encode_body(text.as_bytes()) }));
    true
}

/// A note title as a preview: at most the protocol's title length.
fn title_preview(title: &str) -> (String, bool) {
    let truncated = title.chars().count() > proto::MAX_TITLE_CHARS;
    (title.chars().take(proto::MAX_TITLE_CHARS).collect(), truncated)
}

/// A Vault note's content revision: changes whenever its title or body does,
/// so chunked reads never mix two versions of a note.
fn note_revision(title: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(title.as_bytes());
    h.update([0]);
    h.update(body.as_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().expect("8 bytes")).to_string()
}

fn notes_list(app: &AppState, cursor: Option<String>, limit: u16) -> Answer {
    let Some(vault) = app.vault.as_ref() else {
        return Answer::Refuse("vault_locked");
    };
    let mut notes = vault.list_notes();
    notes.sort_by(|a, b| a.id.cmp(&b.id));
    let mut items: Vec<_> = notes
        .into_iter()
        .filter(|n| cursor.as_deref().is_none_or(|c| n.id.as_str() > c))
        .take(usize::from(limit) + 1)
        .collect();
    let next = if items.len() > usize::from(limit) {
        items.truncate(usize::from(limit));
        items.last().map(|n| n.id.clone())
    } else {
        None
    };
    let items: Vec<Value> = items
        .into_iter()
        .map(|n| {
            let (title, title_truncated) = title_preview(&n.title);
            json!({ "id": n.id, "title": title, "title_truncated": title_truncated })
        })
        .collect();
    Answer::Reply(json!({ "items": items, "next_cursor": next }))
}

fn notes_get(app: &AppState, id: &str, offset: u64, limit: u64, revision: Option<String>) -> Answer {
    let Some(vault) = app.vault.as_ref() else {
        return Answer::Refuse("vault_locked");
    };
    let Some(note) = vault.get_note(id) else {
        return Answer::Refuse("not_found");
    };
    let current = note_revision(&note.title, &note.body);
    // A continuation read names the revision it continues, so two versions
    // of a note are never stitched together.
    if offset > 0 && revision.is_none() {
        return Answer::Refuse("bad_args");
    }
    if revision.as_deref().is_some_and(|r| r != current) {
        return Answer::Refuse("conflict");
    }
    let body = note.body.as_bytes();
    let total = body.len() as u64;
    let Ok(start) = usize::try_from(offset.min(total)) else {
        return Answer::Refuse("bad_args");
    };
    if !note.body.is_char_boundary(start) {
        return Answer::Refuse("bad_args");
    }
    // The chunk ends on a character boundary at or below the limit.
    let mut end = start.saturating_add(usize::try_from(limit).unwrap_or(usize::MAX)).min(body.len());
    while !note.body.is_char_boundary(end) {
        end -= 1;
    }
    let (title, title_truncated) = title_preview(&note.title);
    Answer::Reply(json!({
        "id": note.id, "title": title, "title_truncated": title_truncated,
        "body_b64": proto::encode_body(&body[start..end]), "offset": start,
        "next_offset": if end < body.len() { Some(end as u64) } else { None },
        "total_bytes": total, "revision": current,
    }))
}

fn answer(app: &mut AppState, request_id: u32, command: Command) -> Answer {
    let Some(session) = app.addon.as_ref() else {
        return Answer::Refuse("stale_session");
    };
    match command {
        Command::Ready { host_api } => {
            if host_api != proto::HOST_API {
                return Answer::Refuse("host_api_mismatch");
            }
            if session.ready.replace(true) {
                return Answer::Refuse("already_ready");
            }
            // Read before this session sets its own: an earlier session that
            // never ended with a clean save left it behind.
            let marker = addon_session::incomplete_marker(&session.id);
            let previous_save_incomplete = marker.exists();
            // Live Premium decides the mode the add-on starts in.
            let (mode, reason) = match crate::addon_entitlement::current() {
                crate::addon_entitlement::Access::Full => (Mode::Full, None),
                crate::addon_entitlement::Access::ReadOnly(reason) => (Mode::ReadOnly, reason),
            };
            session.mode.set(mode);
            session.reason.set(reason);
            if mode == Mode::Full {
                write_marker(&marker);
            } else if previous_save_incomplete {
                // Reported now; a read-only session has nothing it could
                // still lose, so the notice is not repeated at every open.
                let _ = std::fs::remove_file(&marker);
            }
            Answer::Reply(json!({
                "host_api": proto::HOST_API,
                "addon_id": session.id,
                "version": session.version,
                "generation": session.generation.to_string(),
                "mode": if mode == Mode::Full { "full" } else { "read_only" },
                "reason": reason,
                "geometry": geometry(app, session, 0),
                "limits": {
                    "frame_bytes": proto::MAX_FRAME_BYTES, "page_bytes": proto::MAX_PAGE_BYTES,
                    "title_chars": proto::MAX_TITLE_CHARS, "quota_bytes": 268_435_456u64,
                    "list_items": proto::MAX_LIST_ITEMS, "page_count": 4096,
                    "index_bytes": 8_388_608u64, "pending_requests": 16, "queued_bytes": 8_388_608u64,
                },
                "previous_save_incomplete": previous_save_incomplete,
            }))
        }
        Command::Presence => Answer::Reply(json!({})),
        Command::WindowMove { x, y, sequence } => {
            let (_, _, w, h) = session.wanted.get();
            session.wanted.set((x, y, w, h));
            session.last_sequence.set(session.last_sequence.get().max(sequence));
            apply(app);
            Answer::Reply(told(app))
        }
        Command::WindowResize { width, height, sequence } => {
            // Resizing starts from what the person sees.
            let (x, y, _, _) = session.rect.get();
            session.wanted.set((x, y, width, height));
            session.last_sequence.set(session.last_sequence.get().max(sequence));
            apply(app);
            Answer::Reply(told(app))
        }
        Command::WindowCollapse { collapsed } => {
            session.collapsed.set(collapsed);
            apply(app);
            Answer::Reply(told(app))
        }
        Command::WindowClose => Answer::Close,
        // The same checks the chrome's own purchase arm makes.
        Command::PremiumPurchaseOpen if !crate::licence_control::PREMIUM_ON_SALE || app.tabs.len() >= crate::state::MAX_TABS => {
            Answer::Refuse("navigation_refused")
        }
        Command::PremiumPurchaseOpen => match crate::premium_purchase::destination_for(&json!({ "purchase": "patanyx" })) {
            Ok(url) => match app.new_tab(&url, true) {
                Ok(_) => Answer::Reply(json!({ "opened": true })),
                Err(_) => Answer::Refuse("navigation_refused"),
            },
            Err(_) => Answer::Refuse("navigation_refused"),
        },
        Command::VaultPremiumOpen => {
            // The chrome opens its Premium view on this event (M16 wires the
            // panel). The add-on supplies nothing but the request.
            app.emit("addon_open_vault_premium", json!({}));
            Answer::Reply(json!({ "opened": true }))
        }
        Command::StoreList { cursor, limit } => admit_storage(app, request_id, Job::List { cursor, limit }),
        Command::StoreGet { id } => admit_storage(app, request_id, Job::Get { id: id.as_str().to_string() }),
        Command::StorePut { id, base_revision, title, body, flush_id, site, collection } => {
            // The ending's one final save (admitted by `addon_session::admission`).
            let answer = admit_storage(
                app,
                request_id,
                Job::Put { id: id.map(|i| i.as_str().to_string()), base_revision: base_revision.0, title, body, site, collection },
            );
            if flush_id.is_some() {
                if let Some(session) = app.addon.as_ref() {
                    if let Some(e) = session.ending.borrow_mut().as_mut() {
                        e.flush_request = Some(request_id);
                        e.flush_failed |= !matches!(answer, Answer::Pending);
                    }
                }
            }
            answer
        }
        Command::StoreDelete { id, base_revision } => {
            admit_storage(app, request_id, Job::Delete { id: id.as_str().to_string(), base_revision: base_revision.0 })
        }
        Command::VaultNotesList { cursor, limit } => notes_list(app, cursor, limit),
        Command::VaultNotesGet { id, offset, limit, revision } => notes_get(app, &id, offset, limit, revision),
        Command::VaultNoteEditInVault { id } => {
            if app.vault.as_ref().is_none_or(|v| v.get_note(&id).is_none()) {
                return Answer::Refuse("not_found");
            }
            // The chrome opens the Vault's own note editor on that note; the
            // add-on itself never writes to the Vault.
            app.emit("addon_vault_note_edit", json!({ "id": id }));
            Answer::Reply(json!({ "opened": true }))
        }
        // Admitted only for the ending's own flush id; completion waits for
        // the worker (`addon_session::settle`), not for this claim.
        Command::FlushDone { status, .. } => {
            if let Some(ending) = session.ending.borrow_mut().as_mut() {
                ending.acked = Some(status == proto::FlushStatus::Saved);
            }
            Answer::Reply(json!({ "accepted": true }))
        }
        // Only for a selection this window was actually handed, once.
        Command::SelectionResult { delivery_id, .. } => {
            if session.deliveries.borrow_mut().remove(&delivery_id) {
                Answer::Reply(json!({ "accepted": true }))
            } else {
                Answer::Refuse("unknown_delivery")
            }
        }
    }
}

/// DEBUG BUILDS ONLY: opens the files of a plain folder as an add-on, for
/// the real-engine isolation runs before signed installation exists (M15).
/// `PATANYX_ADDON_DEV_BUNDLE=<dir>` names the folder; its files are served as
/// they are, unsigned, so this never exists in a release binary.
/// `PATANYX_DEV_VAULT_PASSPHRASE` creates or unlocks the test profile's Vault
/// first, so a run can write pages without driving the Vault panel.
#[cfg(debug_assertions)]
pub fn dev_open_from_env(app: &mut AppState) {
    if std::env::var_os("PATANYX_ADDON_DEV_BUNDLE").is_none() {
        return;
    }
    if let Ok(pass) = std::env::var("PATANYX_DEV_VAULT_PASSPHRASE") {
        let exists = crate::ipc::dev_command(app, "vault_status", &json!({}))
            .is_ok_and(|status| status["exists"] == json!(true));
        let cmd = if exists { "vault_unlock" } else { "vault_create" };
        match crate::ipc::dev_command(app, cmd, &json!({ "passphrase": pass })) {
            Ok(_) => eprintln!("addon dev vault: {cmd} ok"),
            Err(e) => eprintln!("addon dev vault: {cmd} {e}"),
        }
    }
    dev_open_bundle(app);
}

/// DEBUG BUILDS ONLY: (re)opens the development add-on's folder, read fresh
/// each time. At startup, and from the add-on shortcut after Close.
#[cfg(debug_assertions)]
fn dev_open_bundle(app: &mut AppState) {
    let Some(dir) = std::env::var_os("PATANYX_ADDON_DEV_BUNDLE") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let mut files = HashMap::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let (Ok(rel), Ok(bytes)) = (path.strip_prefix(&dir), std::fs::read(&path)) {
                files.insert(rel.to_string_lossy().replace('\\', "/"), Arc::new(bytes));
            }
        }
    }
    // The display name a private test package passes in (it shows in the
    // right-click Send item); a generic one otherwise.
    let name = std::env::var("PATANYX_ADDON_DEV_NAME").unwrap_or_else(|_| "Test add-on".to_string());
    let bundle = ServedBundle { id: "text-pages".to_string(), name, version: "0.0.1".to_string(), files };
    if let Err(e) = open(app, bundle) {
        eprintln!("addon dev bundle: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_site_is_sent_once_per_change_and_null_for_anything_but_a_web_site() {
        let github = Some("github.com".to_string());
        assert_eq!(site_update(None, "https://github.com/a/b"), Some(github.clone()));
        assert_eq!(site_update(Some(&github), "https://gist.github.com/x"), None);
        assert_eq!(site_update(Some(&github), "https://example.org/"), Some(Some("example.org".into())));
        assert_eq!(site_update(Some(&github), "about:blank"), Some(None));
        assert_eq!(site_update(Some(&None), "about:blank"), None);
        assert_eq!(site_update(Some(&None), "http://localhost:3000/"), None);
        assert_eq!(site_update(None, "file:///C:/notes.txt"), Some(None));
        assert_eq!(site_update(None, "https://192.168.1.10/"), Some(None));
    }

    #[test]
    fn an_internationalized_site_is_sent_in_the_form_the_store_accepts() {
        for typed in ["https://bücher.de/", "https://BÜCHER.de/x", "https://www.xn--bcher-kva.de/"] {
            assert_eq!(site_for(typed).as_deref(), Some("xn--bcher-kva.de"), "{typed}");
        }
        assert!(patanyx_store::valid_site("xn--bcher-kva.de"));
        assert_eq!(site_for("ftp://example.com/"), None);
        assert_eq!(site_for("not a url"), None);
    }

    #[test]
    fn a_rect_past_every_edge_comes_back_inside() {
        for r in [(-50.0, -50.0, 300.0, 200.0), (900.0, 650.0, 300.0, 200.0), (10.0, 10.0, 5000.0, 5000.0)] {
            let (x, y, w, h) = clamp_rect(r, 1000.0, 700.0, false);
            assert!(x >= 0.0 && y >= 0.0 && x + w <= 1000.0 && y + h <= 700.0, "{r:?}");
        }
    }

    #[test]
    fn undersized_and_empty_pages_keep_it_inside() {
        for (aw, ah) in [(100.0, 80.0), (219.0, 159.0), (0.0, 0.0)] {
            let (x, y, w, h) = clamp_rect((50.0, 50.0, 400.0, 300.0), aw, ah, false);
            assert!(x >= 0.0 && y >= 0.0 && x + w <= f64::max(aw, 1.0) && y + h <= f64::max(ah, 1.0));
        }
        assert_eq!(clamp_rect((0.0, 0.0, 10.0, 10.0), 1000.0, 700.0, false), (0.0, 0.0, MIN_W, MIN_H));
        assert_eq!(clamp_rect((0.0, 0.0, 300.0, 500.0), 1000.0, 700.0, true).3, COLLAPSED_H);
    }

    #[test]
    fn ids_are_safe_scheme_labels() {
        for ok in ["text-pages", "a", "a1-b2"] {
            assert!(id_ok(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "a--b", "A", "a_b", "a.b", "../a", &"a".repeat(33)] {
            assert!(!id_ok(bad), "{bad}");
        }
    }

    #[test]
    fn only_listed_files_are_served_and_every_answer_carries_the_csp() {
        let mut files = HashMap::new();
        files.insert("index.html".to_string(), Arc::new(b"<html>".to_vec()));
        let get = |path: &str| serve(&files, &http::Request::builder().uri(format!("rbaddon-x://localhost{path}")).body(Vec::new()).unwrap());
        let ok = get("/index.html");
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.headers()["Content-Security-Policy"], ADDON_CSP);
        assert_eq!(get("/").status(), 200);
        let missing = get("/unlisted.js");
        assert_eq!(missing.status(), 404);
        assert_eq!(missing.headers()["Content-Security-Policy"], ADDON_CSP);
    }

    #[test]
    fn the_csp_denies_every_network_and_frame_channel() {
        for directive in ["default-src 'none'", "connect-src 'none'", "frame-src 'none'", "worker-src 'none'", "object-src 'none'", "form-action 'none'", "base-uri 'none'"] {
            assert!(ADDON_CSP.contains(directive), "{directive}");
        }
        assert!(!ADDON_CSP.contains("unsafe-inline") && !ADDON_CSP.contains("unsafe-eval"));
    }

    /// No frame keeps the Vault open: the presence flag alone never counts
    /// (host API 1), and typing in the window counts natively instead.
    /// Checked in the source because an AppState cannot be built here.
    #[test]
    fn no_add_on_frame_counts_as_presence() {
        let source = include_str!("addon_host.rs");
        let start = source.find("pub fn handle_ipc(").expect("handle_ipc moved");
        let end = start + source[start..].find("\n}\n").expect("handle_ipc has no end");
        assert!(!source[start..end].contains(".touch("), "a frame resets the auto-lock");
        assert!(source.contains("platform::connect_addon_presence(&webview, &app.proxy());
    platform::connect_addon_layout(&app.hosts, &app.proxy());"));
    }

    /// Navigation stays on the add-on's own origin, host included.
    #[test]
    fn the_navigation_prefix_is_the_exact_origin() {
        let prefix = platform::addon_origin_prefix("text-pages");
        #[cfg(unix)]
        assert_eq!(prefix, "rbaddon-text-pages://localhost/");
        #[cfg(windows)]
        assert_eq!(prefix, "http://rbaddon-text-pages.localhost/");
        assert!(platform::addon_url("text-pages").starts_with(&prefix));
        assert!(!"rbaddon-text-pages://elsewhere/index.html".starts_with(&prefix));
    }

    /// Review findings R-005, R-007, R-009, R-011 and R-015, checked in the
    /// source because an AppState cannot be built in a unit test.
    #[test]
    fn requests_once_reads_pinned_deadlines_per_flush_and_host_events() {
        let host = include_str!("addon_host.rs");
        let handle = &host[host.find("pub fn handle_ipc(").expect("handle_ipc moved")..];
        let rising = handle.find("request.id <= session.last_request.get()").expect("a repeated request id would run twice");
        let admitted = handle.find("addon_session::admission(").expect("handle_ipc moved");
        assert!(rising < admitted);
        let notes = &host[host.find("fn notes_get(").expect("notes_get moved")..];
        assert!(notes[..900].contains("if offset > 0 && revision.is_none()"), "a continuation could mix two versions");
        let session = include_str!("addon_session.rs");
        assert!(session.contains("e.flush_id == flush_id"), "a deadline would end a later flush");
        let windows = include_str!("platform/windows.rs");
        let wall = &windows[windows.find("fn connect_addon_request_wall(").expect("the wall moved")..];
        assert!(!wall[..2500].contains("core.AddWebResourceRequestedFilter("), "the narrower filter is back as a fallback");
        let state = include_str!("state.rs");
        assert_eq!(state.matches("crate::addon_host::notify_geometry(self);").count(), 2, "host-driven layout is not told");
        let ipc = include_str!("ipc.rs");
        assert_eq!(ipc.matches("crate::addon_host::notes_changed(state);").count(), 3, "a note change is not told");
    }

    #[test]
    fn the_host_facts_are_json_never_raw_text() {
        let s = host_facts_script("text-pages", 12);
        assert!(s.contains("addon_id:\"text-pages\""));
        assert!(s.contains("generation:\"12\""));
    }
}

#[cfg(test)]
#[path = "addon_window_tests.rs"]
mod window_tests;
