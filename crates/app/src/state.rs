//! Shared application state. All mutation happens on the event-loop thread.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use patanyx_store::Store;
use patanyx_vault::Vault;
use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;
use wry::{PageLoadEvent, WebView};

use crate::platform;
use crate::UserEvent;

/// Whether this backend's ledger records BLOCKED requests, not merely
/// contacted hosts.
///
/// WebKitGTK's content blocker reports no per-request matches, so on unix the
/// blocked column is structurally always zero and the UI must say "contacted"
/// rather than imply a block count. WebView2 answers 403 from its own
/// callback and can count them.
pub(crate) const LEDGER_COUNTS_BLOCKED: bool = cfg!(windows);

/// How long before the lock the user is warned.
///
/// The warning is what makes a short timeout liveable. Keypresses inside a page
/// now count as activity, but reading a long article or watching a video
/// involves no input at all -- and for a chat build, an auto-lock tears down
/// the transport, so someone reading a conversation would drop off the LAN
/// mid-sentence with no notice. A minute is enough to notice and act without
/// being so early that it becomes background noise.
pub const AUTO_LOCK_WARN_BEFORE: Duration = Duration::from_secs(60);

/// Hard ceiling on open tabs, for both page-driven and IPC-driven creation.
pub const MAX_TABS: usize = 32;

/// How many recently-picked file paths stay redeemable.
///
/// Small on purpose. A token is handed out per dialog and consumed by the one
/// command that uses it; more than a handful outstanding means something is
/// picking files and never redeeming them, and the oldest should go rather
/// than accumulate.
pub const MAX_PICKED_PATHS: usize = 8;

/// Scheme allowlist for content webviews, shared by the navigation handler and
/// the `tab_new` IPC command (a new webview's initial `with_url` never passes
/// through the navigation handler).
///
/// The chrome origin is excluded explicitly because on Windows it IS an http
/// URL — WebView2 cannot register custom schemes, so wry serves the chrome UI
/// at `http://rbchrome.localhost/`. Without this exclusion a plain scheme check
/// would let an untrusted page put itself on the trusted origin. On unix the
/// chrome scheme is not http and the exclusion costs nothing.
/// This is an ORIGIN test, not a string-prefix test, and the difference is the
/// whole point. `!url.starts_with("http://rbchrome.localhost/")` is trivially
/// evaded by every spelling of the same origin that does not happen to be that
/// byte sequence: no trailing slash, an explicit `:80`, a `user@` prefix, a `?`
/// straight after the host, or capital letters (hosts are case-insensitive).
/// All of those load the trusted chrome document. The predicate now extracts
/// the host and compares it, so a spelling it has never seen still fails.
///
/// It is reachable remotely: a contact can send a tab over chat, and
/// `chat_panel` validates with this same function.
pub fn is_allowed_content_url(url: &str) -> bool {
    if url == "about:blank" {
        return true;
    }
    match host_of(url) {
        // Compared case-insensitively; `host_of` has already lowercased.
        Some(host) => host != platform::CHROME_RESERVED_HOST,
        // No http(s) authority: file://, data:, javascript:, rbchrome://, or
        // something malformed. All denied.
        None => false,
    }
}

/// Host of an http(s) URL, lowercased, with userinfo and port removed.
/// `None` for any other scheme or a missing authority.
///
/// Deliberately mirrors two browser normalisations that a naive split misses,
/// because a parser that disagrees with the engine about where the host ends
/// is a bypass rather than a bug:
///
///   * ASCII tab, LF and CR are STRIPPED from URLs entirely, so
///     `http://rbchrome.loc\talhost/` is the chrome origin to the engine
///     while a naive parser reads an unrelated name;
///   * a backslash terminates the authority exactly as `/` does, so
///     `http://rbchrome.localhost\.evil.com/` is likewise the chrome origin
///     to the engine and an unrelated name to a naive parser.
///
/// Both of those are false-ALLOW directions, which is why they are handled
/// here rather than left to fail closed.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let cleaned: String = url.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect();
    let lower = cleaned.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    // The LAST '@' separates userinfo from host: userinfo may itself contain
    // an encoded '@', and taking the first one would read the attacker's half.
    let host_port = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    // An IPv6 literal keeps its brackets and its colons; the port, if any,
    // follows the closing bracket.
    let host = match host_port.find(']') {
        Some(end) => &host_port[..=end],
        None => host_port.split(':').next().unwrap_or(""),
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

pub struct Tab {
    pub id: u64,
    /// Platform handle for the tab's view: the GTK container on unix, a
    /// placeholder on Windows where the WebView itself is the only handle.
    view: platform::TabView,
    /// Content webview — untrusted web pages; `load_url` only, never
    /// `evaluate_script`.
    pub webview: WebView,
    pub url: String,
    pub title: String,
    /// Whether this tab was BUILT ephemeral (quarantine profile). Recorded
    /// at construction because the policy is fixed once the WebContext
    /// exists, and features that must respect the ephemeral contract (a
    /// set-aside shelf must never remember one) need the per-tab fact, not
    /// the browser-wide policy of the moment.
    pub ephemeral: bool,
    history: Vec<String>,
    history_index: Option<usize>,
    /// Set when `load_url` originates from back/forward/reload so the
    /// resulting UrlChanged event is not recorded as a new history entry.
    suppress_history: bool,
    /// Page zoom, as a scale factor. Per TAB, like every mainstream browser:
    /// a global level would resize a page the user never asked about, and a
    /// per-site one needs storage this browser deliberately does not keep for
    /// unvisited sites.
    zoom: f64,
    /// Hosts the user chose to visit despite the malicious-host list. Shared
    /// with the navigation handler's closure; dropped with the tab, which is
    /// the point -- an override that outlived its tab would be a hole nobody
    /// remembers opening.
    malicious_override: Rc<RefCell<BTreeSet<String>>>,
}

impl Tab {
    pub fn record_history(&mut self, url: String) {
        if self.suppress_history {
            self.suppress_history = false;
            return;
        }
        let next = self.history_index.map_or(0, |i| i + 1);
        self.history.truncate(next);
        if self.history.last() != Some(&url) {
            self.history.push(url);
        }
        self.history_index = Some(self.history.len().saturating_sub(1));
    }

    // wry 0.55 exposes no native back/forward/reload API on its
    // WebView, and evaluating `history.back()` on the content webview is
    // forbidden by the security rules, so navigation history is kept here
    // and replayed with `load_url()`. "reload" is a re-fetch of the current
    // URL.
    pub fn history_back(&mut self) -> Result<(), &'static str> {
        let index = match self.history_index {
            Some(i) if i > 0 => i,
            _ => return Ok(()),
        };
        let url = self.history[index - 1].clone();
        self.history_index = Some(index - 1);
        self.suppress_history = true;
        self.webview.load_url(&url).map_err(|_| "io")
    }

    pub fn history_forward(&mut self) -> Result<(), &'static str> {
        let index = match self.history_index {
            Some(i) if i + 1 < self.history.len() => i,
            _ => return Ok(()),
        };
        let url = self.history[index + 1].clone();
        self.history_index = Some(index + 1);
        self.suppress_history = true;
        self.webview.load_url(&url).map_err(|_| "io")
    }

    pub fn history_reload(&mut self) -> Result<(), &'static str> {
        if self.url.is_empty() {
            return Ok(());
        }
        self.suppress_history = true;
        // A real reload, not a re-navigation. `load_url` to the current
        // address is a fresh navigation, and a navigation is allowed to be
        // answered entirely from the HTTP cache: a page inside its heuristic
        // freshness window is served with NO network traffic, so the button
        // could not pick up a changed page -- observed 2026-07-29 against a
        // server that had demonstrably changed. `reload()` carries browser
        // reload semantics on every engine (Chromium revalidates the main
        // document; WebKitGTK likewise), which is what a button drawn as a
        // circular arrow promises.
        self.webview.reload().map_err(|_| "io")
    }
}

/// The zoom steps, matching what mainstream browsers offer. Multiplicative
/// steps rather than fixed increments, so each press is the same perceived
/// change at any level.
const ZOOM_STEPS: &[f64] = &[0.5, 0.67, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0];

/// The nearest entry in [`ZOOM_STEPS`] to a factor the engine reports.
///
/// Ctrl+scroll produces levels that are not in the table -- 1.03, 1.4 -- and
/// `zoom_index` matches on exact equality, so an unsnapped value makes the
/// next Ctrl+`+` jump back to 110% from wherever the user had scrolled to
/// instead of stepping up from there.
fn snap_to_step(factor: f64) -> f64 {
    ZOOM_STEPS
        .iter()
        .copied()
        .min_by(|a, b| {
            (a - factor)
                .abs()
                .partial_cmp(&(b - factor).abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or(factor)
}

/// What to tell the user after a right-click copy: the message, and whether it
/// is an error.
///
/// Pure, so the three outcomes are testable without a clipboard or a display.
/// `stripped` is true ONLY when the URL actually changed -- saying tracking
/// parameters were removed from a URL that had none claims work that was not
/// done, which is the same reason the chrome drew this distinction before the
/// write moved into the process.
fn copy_result_message(wrote: bool, change: crate::ipc::LinkChange) -> (&'static str, bool) {
    use crate::ipc::LinkChange;
    if !wrote {
        return ("Could not copy that link", true);
    }
    // Says exactly which of the two things happened, never the more impressive
    // one. "Redirect skipped" on a link that only lost a utm_ would claim a
    // wrapper was found where there was none.
    let message = match change {
        LinkChange::Unchanged => "Link copied",
        LinkChange::Stripped => "Link copied, tracking parameters removed",
        LinkChange::Unwrapped => "Link copied, redirect skipped",
        LinkChange::UnwrappedAndStripped => {
            "Link copied, redirect skipped and tracking parameters removed"
        }
    };
    (message, false)
}

#[cfg(test)]
mod copy_message_tests {
    use super::copy_result_message;
    use crate::ipc::LinkChange;

    const EVERY_CHANGE: [LinkChange; 4] = [
        LinkChange::Unchanged,
        LinkChange::Stripped,
        LinkChange::Unwrapped,
        LinkChange::UnwrappedAndStripped,
    ];

    #[test]
    fn a_failed_write_is_reported_as_an_error_and_never_claims_a_copy() {
        for change in EVERY_CHANGE {
            let (message, error) = copy_result_message(false, change);
            assert!(error, "a failed clipboard write must be flagged as an error");
            assert!(
                !message.contains("copied"),
                "failure copy must not say the link was copied: {message}"
            );
        }
    }

    #[test]
    fn each_outcome_claims_exactly_what_happened_and_no_more() {
        assert_eq!(
            copy_result_message(true, LinkChange::Unchanged),
            ("Link copied", false)
        );
        assert_eq!(
            copy_result_message(true, LinkChange::Stripped),
            ("Link copied, tracking parameters removed", false)
        );
        assert_eq!(
            copy_result_message(true, LinkChange::Unwrapped),
            ("Link copied, redirect skipped", false)
        );
        assert_eq!(
            copy_result_message(true, LinkChange::UnwrappedAndStripped),
            (
                "Link copied, redirect skipped and tracking parameters removed",
                false
            )
        );
    }

    /// The failure this pins: a message that mentions a redirect when none was
    /// unwrapped, or parameters when none were removed. Either would report a
    /// protection the user did not receive.
    #[test]
    fn no_outcome_claims_a_change_it_did_not_make() {
        for change in EVERY_CHANGE {
            let (message, _) = copy_result_message(true, change);
            let says_redirect = message.contains("redirect");
            let says_params = message.contains("parameters");
            let did_unwrap = matches!(
                change,
                LinkChange::Unwrapped | LinkChange::UnwrappedAndStripped
            );
            let did_strip = matches!(
                change,
                LinkChange::Stripped | LinkChange::UnwrappedAndStripped
            );
            assert_eq!(says_redirect, did_unwrap, "{change:?}: {message}");
            assert_eq!(says_params, did_strip, "{change:?}: {message}");
        }
    }
}

#[cfg(test)]
mod zoom_snap_tests {
    use super::*;

    #[test]
    fn an_exact_step_is_left_alone() {
        for step in ZOOM_STEPS {
            assert_eq!(snap_to_step(*step), *step);
        }
    }

    #[test]
    fn a_scrolled_level_snaps_to_the_nearest_step() {
        // Ctrl+scroll lands between steps; these are the values the next
        // keypress has to continue sensibly from.
        assert_eq!(snap_to_step(1.03), 1.0);
        assert_eq!(snap_to_step(1.4), 1.5);
        assert_eq!(snap_to_step(0.72), 0.67);
        assert_eq!(snap_to_step(2.3), 2.5);
    }

    #[test]
    fn levels_beyond_the_table_clamp_to_its_ends() {
        assert_eq!(snap_to_step(0.1), 0.5);
        assert_eq!(snap_to_step(9.0), 3.0);
    }

    #[test]
    fn a_snapped_level_is_findable_again() {
        // The point of snapping: `zoom_index` matches on exact equality, so a
        // value that snapped must be one the step walk can find, or the next
        // keypress restarts from the default instead of continuing.
        for probe in [1.03, 1.4, 0.72, 2.3, 9.0] {
            let snapped = snap_to_step(probe);
            assert!(
                ZOOM_STEPS.iter().any(|z| (z - snapped).abs() < f64::EPSILON),
                "{probe} snapped to {snapped}, which is not a step"
            );
        }
    }
}

impl Tab {
    /// Step the zoom and apply it. `dir` is +1 to enlarge, -1 to shrink, 0 to
    /// reset.
    ///
    /// Clamped to the ends of the table rather than wrapping or growing
    /// without bound: a page at 20x is not a feature, and neither is one the
    /// user cannot read their way back from.
    pub fn zoom_step(&mut self, dir: i32) -> f64 {
        let current = self
            .zoom_index()
            .unwrap_or(ZOOM_STEPS.iter().position(|z| *z == 1.0).unwrap_or(4));
        self.zoom = match dir {
            0 => 1.0,
            d if d > 0 => ZOOM_STEPS[(current + 1).min(ZOOM_STEPS.len() - 1)],
            _ => ZOOM_STEPS[current.saturating_sub(1)],
        };
        // A failure here is not worth interrupting the user for: the zoom
        // simply did not change, which they can see.
        let _ = self.webview.zoom(self.zoom);
        self.zoom
    }

    fn zoom_index(&self) -> Option<usize> {
        ZOOM_STEPS
            .iter()
            .position(|z| (z - self.zoom).abs() < f64::EPSILON)
    }

    pub fn zoom_level(&self) -> f64 {
        self.zoom
    }

    /// Record a zoom the ENGINE applied. Does not call back into the engine:
    /// it already did the work, and re-applying would fight whatever the user
    /// is doing with Ctrl+scroll.
    ///
    /// Snapped to the nearest step so the next Ctrl+`+` continues from where
    /// the user actually is. Ctrl+scroll produces levels that are not in the
    /// table at all, and without snapping `zoom_index` returns None and the
    /// next keypress would jump back to 110% from wherever they had scrolled.
    fn note_engine_zoom(&mut self, factor: f64) {
        self.zoom = snap_to_step(factor);
    }

    /// Let this tab reach `host` despite the malicious-host list.
    ///
    /// Takes effect on the NEXT navigation; the caller reloads. Scoped to this
    /// tab and gone when it closes -- there is deliberately no way to make it
    /// permanent, because "allow forever" is how a one-off decision becomes a
    /// standing exemption the user cannot remember granting.
    pub fn allow_malicious_host(&self, host: &str) {
        self.malicious_override
            .borrow_mut()
            .insert(host.to_ascii_lowercase());
    }
}

impl Drop for Tab {
    fn drop(&mut self) {
        // unix: removes the container from its GTK parent. Windows: drops
        // this tab's cached main-resource bytes (up to the integrity cap),
        // which would otherwise outlive the tab in a process-lived map --
        // dropping the `webview` field below is what destroys the WebView2
        // itself.
        platform::remove_tab(&self.view, &self.webview);
    }
}

/// Builds one content tab through the platform layer (a hidden gtk::Box on
/// unix, a hidden WebView2 child window on Windows) holding a content
/// webview with all content security handlers. Every handler closure
/// captures the tab id and only sends `EventLoopProxy` events. The view
/// starts hidden; the caller decides visibility.
///
/// Fallible on purpose: see the comment at the `build_content` call below.
fn build_tab(
    hosts: &platform::Hosts,
    proxy: &EventLoopProxy<UserEvent>,
    id: u64,
    url: &str,
    policy: &platform::TabPolicy,
    // The session permission table, cloned into this tab's engine callback.
    // Passed rather than reached for: build_tab is a free function precisely
    // so it cannot touch AppState while AppState is mutably borrowed.
    permissions: crate::state::PermissionBook,
) -> Result<Tab, wry::Error> {
    let nav_proxy = proxy.clone();
    // Hosts this tab may visit despite the blocklist, because the user chose
    // to. PER TAB and dies with the tab: an override that outlived the tab
    // would be a permanent hole nobody remembers opening. Deliberately NOT
    // `allowed_hosts` (the freeze exemption) -- overloading one word for two
    // security decisions is how one of them ends up wrong.
    let malicious_override: Rc<RefCell<BTreeSet<String>>> = Rc::new(RefCell::new(BTreeSet::new()));
    let nav_allowed = malicious_override.clone();
    let load_proxy = proxy.clone();
    let title_proxy = proxy.clone();
    let new_window_proxy = proxy.clone();
    let download_start_proxy = proxy.clone();
    let download_done_proxy = proxy.clone();

    // ---- content webview: no custom protocol, no IPC, no script eval ----
    //
    // The initial URL is NOT set here. It travels to `build_content` and
    // each backend applies it where its blocking is already in place: on
    // the builder for WebKitGTK, after handler registration for WebView2,
    // whose `build_as_child` would otherwise navigate before the request
    // filter exists.
    // Built through the platform factory, not `WebViewBuilder::new()`: on
    // Windows that is where the WebView2 user-data directory is attached, and
    // it has to be attached at CONSTRUCTION (wry 0.55.1 has no
    // `with_web_context` setter). See platform::new_webview_builder.
    let builder = platform::new_webview_builder()
        // PURE ALLOWLIST. This must not be the source of the displayed URL.
        //
        // wry's navigation handler carries no frame information and is never
        // filtered to the main frame, so on WebKitGTK it fires for iframe
        // navigations too. Reporting those as the tab's URL let any page put an
        // arbitrary address in the URL bar by embedding an iframe, which is
        // straightforward spoofing, and polluted history with subframe URLs
        // that back/forward would then load as top-level pages. The displayed
        // URL now comes from the page-load handler below, which is main-frame
        // only on both engines.
        .with_navigation_handler(move |url: String| {
            // DEBUG BUILDS ONLY. Answers the one question reading the code
            // cannot: does NavigationStarting fire at all on WebView2 for a
            // given navigation, and if it does, what verdict does this closure
            // reach? Every link in this chain verifies on paper and the block
            // still does not happen on Windows, which is the point at which
            // guessing stops being worth anything.
            #[cfg(debug_assertions)]
            {
                let host = host_of(&url);
                let matched = host
                    .as_deref()
                    .and_then(crate::blocklist::matched_rule);
                println!(
                    "NAV url={url} host={host:?} matched={matched:?} set_len={}",
                    crate::blocklist::len()
                );
            }
            // Anything else (file://, the chrome origin, data:, ...) is denied.
            if !is_allowed_content_url(&url) {
                return false;
            }
            // KNOWN-MALICIOUS HOSTS. Refused here rather than in the content
            // filter -- see blocklist.rs for why -- and independently of
            // `block_ads`, so turning off ad blocking cannot silently turn off
            // malware blocking.
            //
            // The per-tab override is checked FIRST and lives in an Rc the
            // tab owns, so it dies with the tab. wry's handler bound is
            // `Fn(String) -> bool + 'static` with no `Send`, which is what
            // makes an Rc legal here.
            if let Some(host) = host_of(&url) {
                if !nav_allowed.borrow().contains(&host) {
                    if let Some(rule) = crate::blocklist::matched_rule(&host) {
                        // Reported, not silently dropped: a page that simply
                        // fails to load teaches the user the browser is
                        // broken. The chrome names the host and offers the
                        // override. No frame information is available here,
                        // so this fires for subframes too on WebKitGTK --
                        // which is right for BLOCKING and is why the report
                        // is a banner rather than a full-page interstitial
                        // that would replace a page the user is reading.
                        let _ = nav_proxy.send_event(UserEvent::NavigationBlocked {
                            tab_id: id,
                            host,
                            rule: rule.to_string(),
                        });
                        return false;
                    }
                }
            }
            true
        })
        .with_new_window_req_handler(move |url, _features| {
            // New windows stay denied; allowed targets get a background tab.
            //
            // This MUST be the same predicate the navigation handler uses. It
            // used to be a bare scheme test, which on Windows was a hole
            // straight through the trust boundary: the chrome document is
            // served at http://rbchrome.localhost/ there, so a page calling
            // window.open() on it passed the scheme test, and the tab that
            // opened bypassed the navigation handler entirely because a new
            // webview's initial with_url is not a navigation. An untrusted
            // page ended up on the origin that holds IPC and the vault.
            if is_allowed_content_url(&url) {
                let _ = new_window_proxy.send_event(UserEvent::OpenInNewTab(url));
            }
            wry::NewWindowResponse::Deny
        })
        // Main-frame only on both engines (WebKitGTK load-changed reports
        // webview.uri(), WebView2 ContentLoading reports the top-level Source),
        // which is why the displayed URL and history are driven from here
        // rather than from the navigation handler.
        .with_on_page_load_handler(move |event, url| {
            let loading = matches!(event, PageLoadEvent::Started);
            if loading {
                let _ = load_proxy.send_event(UserEvent::UrlChanged(id, url));
            }
            let _ = load_proxy.send_event(UserEvent::LoadState(id, loading));
        })
        .with_document_title_changed_handler(move |title| {
            let _ = title_proxy.send_event(UserEvent::TitleChanged(id, title));
        })
        .with_download_started_handler(move |url, destination| {
            *destination = unique_download_path(&url, destination);
            let _ = download_start_proxy.send_event(UserEvent::DownloadStarted(url));
            true
        })
        .with_download_completed_handler(move |url, path, success| {
            let _ = download_done_proxy.send_event(UserEvent::DownloadDone {
                url,
                path: path.map(|p| p.to_string_lossy().into_owned()),
                success,
            });
        })
        .with_devtools(cfg!(debug_assertions));

    // A CONSTRUCTION FAILURE IS A VALUE, NOT A PANIC.
    //
    // This was `.expect("failed to build content webview")`, and it was
    // reachable from web content: a page calling `window.open()` raises
    // `UserEvent::OpenInNewTab`, which lands here after the origin and
    // MAX_TABS checks. There is no `catch_unwind` anywhere in the workspace
    // and this runs inside the tao event-loop closure, so any engine-side
    // failure -- GPU process loss, a COM error, memory pressure -- took the
    // whole browser down: every tab gone, the vault dropped mid-session, and
    // on Windows a panic crossing the `extern "system"` message pump aborts
    // rather than unwinds. A page could reach that on purpose.
    //
    // The caller decides what to do instead; nothing here can.
    let (webview, view) =
        platform::build_content(
            hosts,
            builder,
            policy,
            proxy,
            url,
            malicious_override.clone(),
            id,
            permissions.clone(),
        )?;
    // The engine zooms on keys this process never sees; this is how the
    // indicator learns about it.
    platform::connect_zoom_changed(&webview, proxy, id);
    // Download plumbing wry cannot express on its own: the webkit2gtk
    // Response-policy workaround on unix, a no-op on Windows where wry's
    // download handlers are implemented natively.
    platform::fix_downloads(&webview);

    Ok(Tab {
        id,
        view,
        webview,
        url: url.to_string(),
        title: String::new(),
        ephemeral: policy.ephemeral,
        history: Vec::new(),
        history_index: None,
        suppress_history: false,
        zoom: 1.0,
        malicious_override,
    })
}

/// Directory downloads are written to; created if missing.
pub fn download_dir() -> PathBuf {
    // unix follows XDG; Windows uses the per-user Downloads folder. (The
    // FOLDERID_Downloads "known folder" API would need a WinAPI dependency;
    // %USERPROFILE%\Downloads matches the default location.)
    #[cfg(unix)]
    let dir = std::env::var_os("XDG_DOWNLOAD_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Downloads")))
        .unwrap_or_else(|| PathBuf::from("./Downloads"));
    #[cfg(windows)]
    let dir = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .map(|profile| PathBuf::from(profile).join("Downloads"))
        .unwrap_or_else(|| PathBuf::from("./Downloads"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Destination for an incoming download: `download_dir()` plus a sanitized,
/// collision-free file name derived from the suggested path (falling back to
/// the URL's last path segment, then to `download`).
/// A filename for a page saved as PDF, derived from its host and path.
///
/// The HOST leads, because a folder full of "index.pdf" is useless. Falls back
/// to a fixed name rather than to anything derived from a URL that did not
/// parse; `sanitize_filename` then does the platform-specific work, and
/// `unique_download_path` handles collisions.
pub(crate) fn pdf_name_for(url: &str) -> String {
    let host = host_of(url).unwrap_or_else(|| "page".to_string());
    let slug: String = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .chars()
        .take(48)
        .collect();
    if slug.is_empty() || slug == host {
        format!("{host}.pdf")
    } else {
        format!("{host}-{slug}.pdf")
    }
}

fn unique_download_path(url: &str, suggested: &Path) -> PathBuf {
    let raw = suggested
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .or_else(|| {
            url.split(|c| c == '?' || c == '#')
                .next()
                .and_then(|base| base.rsplit('/').next())
                .filter(|segment| !segment.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "download".to_string());
    let name = sanitize_filename(&raw);
    let dir = download_dir();
    let candidate = dir.join(&name);
    if !candidate.exists() {
        return candidate;
    }
    // Collision: insert " (n)" before the (last) extension.
    let (stem, ext) = match name.rfind('.') {
        Some(pos) if pos > 0 => (&name[..pos], &name[pos..]),
        _ => (&name[..], ""),
    };
    let mut n = 1u32;
    loop {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

// Filename sanitization is platform-aware: a hostile Content-Disposition
// name must not be able to escape the download directory (path separators,
// leading dots) nor, on Windows, use characters or device names the OS
// treats specially in every directory.

#[cfg(unix)]
fn sanitize_filename(name: &str) -> String {
    let stripped: String = name.chars().filter(|c| *c != '/' && *c != '\\').collect();
    let stripped = stripped.trim_start_matches('.');
    if stripped.is_empty() {
        "download".to_string()
    } else {
        stripped.to_string()
    }
}

#[cfg(windows)]
fn sanitize_filename(name: &str) -> String {
    // Win32 forbids < > : " / \ | ? * and ASCII control characters in file
    // names; replace them (rather than remove, so a crafted name cannot
    // collapse into a traversal like ".." or an alternate-data-stream ":").
    let mapped: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    // Leading dots hide files (same as unix); trailing dots/spaces are
    // silently stripped by Win32, which would change the name AFTER the
    // collision check in unique_download_path ran.
    let trimmed = mapped
        .trim_start_matches('.')
        .trim_end_matches(|c| c == '.' || c == ' ');
    // DOS device names are reserved in every directory, with any extension
    // (CON.txt still opens the console), so neutralize them by prefix.
    const DEVICES: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = trimmed.split('.').next().unwrap_or_default();
    if trimmed.is_empty() {
        "download".to_string()
    } else if DEVICES.iter().any(|dev| stem.eq_ignore_ascii_case(dev)) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Outcome of re-checking a downloaded file against the fingerprint recorded
/// at completion. `as_str` is the IPC vocabulary the downloads view speaks.
pub enum FileVerdict {
    Match,
    Differs,
    Missing,
    Unreadable,
}

impl FileVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileVerdict::Match => "match",
            FileVerdict::Differs => "differs",
            FileVerdict::Missing => "missing",
            FileVerdict::Unreadable => "unreadable",
        }
    }
}

/// SHA-256 of a file, streamed in 64 KiB reads — downloads can be far larger
/// than a single in-memory read should assume. Returns the digest and the
/// exact number of bytes that went into it (which is what the stored record's
/// `byte_len` must describe).
pub fn hash_file(path: &Path) -> std::io::Result<([u8; 32], u64)> {
    use sha2::Digest;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = std::io::Read::read(&mut file, &mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        total += read as u64;
    }
    Ok((hasher.finalize().into(), total))
}

/// Re-check a recorded download: the bare file name is looked up in the
/// current download directory and re-hashed against the record.
pub fn check_download_file(filename: &str, sha256: &[u8; 32]) -> FileVerdict {
    check_download_file_in(&download_dir(), filename, sha256)
}

fn check_download_file_in(dir: &Path, filename: &str, sha256: &[u8; 32]) -> FileVerdict {
    // `filename` comes out of an HMAC-verified record and was sanitized when
    // the download landed. A separator here therefore means something is
    // deeply wrong, so refuse rather than follow it out of the download
    // directory — defense in depth behind the HMAC gate.
    if filename.is_empty()
        || Path::new(filename).file_name().and_then(|n| n.to_str()) != Some(filename)
    {
        return FileVerdict::Unreadable;
    }
    match hash_file(&dir.join(filename)) {
        Ok((hash, _)) => {
            if &hash == sha256 {
                FileVerdict::Match
            } else {
                FileVerdict::Differs
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => FileVerdict::Missing,
        Err(_) => FileVerdict::Unreadable,
    }
}

pub struct AppState {
    pub vault: Option<Vault>,
    pub vault_path: PathBuf,
    /// Bookmark/provenance store. Session-lifetime BY DESIGN: it opens
    /// alongside the vault (same passphrase, separate file, separate key via
    /// domain separation) and is NOT dropped when the vault locks. See the
    /// Notes in `lock_vault`/`check_autolock` — the brief asked for
    /// lock-step behavior and this deliberately deviates, for the reasons
    /// the store crate's own docs give.
    pub store: Option<Store>,
    pub store_path: PathBuf,
    /// Why the store failed to open alongside the vault, if it did. Surfaced
    /// through `store_status` so the UI can say what happened instead of
    /// showing a silently empty panel.
    store_error: Option<&'static str>,
    pub last_activity: Instant,
    /// Idle timeout in seconds, 0 meaning never. Cached from prefs rather than
    /// re-read from disk: this is consulted on every pass of the event loop.
    pub autolock_secs: u64,
    /// Whether the "about to lock" warning has already been raised for the
    /// current idle stretch. Cleared by `touch`, so acting on the warning --
    /// which is itself activity -- re-arms it for next time.
    lock_warning_sent: bool,
    pub tabs: Vec<Tab>,
    pub active: usize,
    /// Find session of the ACTIVE tab, per-tab by construction: the
    /// tab-switch path stops it and tab teardown unwires it, so one slot
    /// never has to describe two tabs. The query lives only here and inside
    /// the engine; nothing is persisted, for any tab kind.
    pub find: crate::find::FindSession,
    /// Monotonically increasing; never reused even after tabs close.
    next_tab_id: u64,
    /// Platform host areas (chrome/content containers on unix, the parent
    /// window on Windows).
    pub hosts: platform::Hosts,
    /// Cloned into every tab's webview handlers.
    proxy: EventLoopProxy<UserEvent>,
    /// Chrome webview — the ONLY webview we may call `evaluate_script` on.
    chrome: WebView,
    /// Current chrome strip height in logical pixels. Stored here (not only
    /// on the GTK widget) because Windows must re-apply it on every resize.
    chrome_height: i32,
    /// Whether the chrome is covering the window instead of sitting in a strip.
    ///
    /// SEPARATE FROM `chrome_height`, and deliberately not just a taller
    /// height. The clamp on `set_chrome_height` exists to stop a stray number
    /// swallowing the window -- the panel that once grew this strip by 300px
    /// of empty band is why -- and folding "cover" into that number would
    /// delete the guard to gain the feature. A panel that wants the whole
    /// window has to ASK for it by name, through a command that carries no
    /// arithmetic to get wrong.
    /// How the chrome and the page currently share the window.
    chrome_arrangement: platform::ChromeLayout,
    /// Browser-wide privacy policy. Applied to every existing tab when it
    /// changes and inherited by new ones, so "block ads" means the browser
    /// rather than whichever tab happened to be focused when it was toggled.
    /// `ephemeral` is the exception: a WebContext is fixed once its view
    /// exists, so it only affects tabs opened afterwards.
    pub privacy: platform::TabPolicy,
    pub smoke_mode: bool,
    /// Set once the behavioural blocking probe has navigated, so the smoke
    /// exit does not fire before the page has had a chance to make requests.
    pub probe_started: bool,
    /// Pings seen from chrome.js. In smoke mode the first ping proves the
    /// JS->Rust IPC path; a second, requested via `evaluate_script`, proves
    /// the Rust->JS path as well.
    pub ping_count: u32,
    /// Files the USER picked through a native dialog, keyed by a one-shot
    /// token.
    ///
    /// WHY A TOKEN RATHER THAN THE PATH. `ocr_scan` used to take a path
    /// straight from IPC under a comment describing it as "a path the user
    /// just chose" -- nothing connected the two. The chrome could name any
    /// file on disk, and the reply distinguishes "read it" from "could not",
    /// which is a file-existence and size oracle on top of a bounded
    /// arbitrary-file read. The path now never travels back across the
    /// boundary: the dialog records it here and hands out a token.
    ///
    /// Bounded and one-shot: redeeming removes the entry, and the oldest is
    /// dropped past `MAX_PICKED_PATHS`, so this cannot grow and a token cannot
    /// be replayed.
    pub picked_paths: std::collections::VecDeque<(u64, PathBuf)>,
    pub next_pick_token: u64,
    /// Smoke only: the second ping has been ASKED for. Distinguishes "the
    /// webview never came up" from "the reply is still in flight", which the
    /// single deadline used to conflate.
    pub smoke_second_ping_requested: bool,
    /// Smoke only: deadline ticks seen. Bounds the reprieve so a second ping
    /// that never arrives still fails instead of re-arming forever.
    pub smoke_deadline_ticks: u32,
    pub smoke_vault_done: bool,
    /// In-flight page-byte reads and corroboration requests. Memory only.
    pub integrity: crate::page_integrity::IntegrityState,
    /// A password a content tab just submitted, waiting on the user's Save/
    /// Never. NEVER PERSISTED: this field is the entire lifetime of that
    /// password outside the vault -- it exists here only from the moment the
    /// content script posts a submission to the moment `cred_save_confirm`
    /// writes it (dropping this) or `cred_save_dismiss`/a navigation/a tab
    /// switch clears it unwritten. See `note_login_submitted`.
    pending_save: Option<PendingSave>,
    /// PDF renders in flight, keyed by destination path, valued by the URL
    /// they were started from. The engine answers asynchronously and the tab
    /// may have navigated by then, so the source URL cannot be re-read at
    /// completion time -- it has to be remembered here.
    pending_pdf: std::collections::HashMap<String, String>,
    /// Chat transport handle and session mirror. Absent from the default build.
    #[cfg(feature = "chat")]
    pub chat: crate::chat_panel::ChatState,
    /// Site permission grants and denials for THIS SESSION.
    ///
    /// Session-only by construction, which is a product promise rather than an
    /// implementation detail: this is process memory, nothing ever serialises
    /// it, and it dies with the browser. Nothing here touches prefs (which
    /// forbids secrets anyway) or the vault. The engine callback holds a clone
    /// of the same handle, so the decision is made against one table on
    /// whatever thread the engine picks.
    pub permissions: PermissionBook,
}

/// The permission kinds this product polices.
///
/// Deliberately four. Clipboard read, autoplay, local fonts and the rest are
/// out of scope: their events are left to the engine default and nothing here
/// records them, so the UI never implies a control it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermKind {
    Camera,
    Microphone,
    Geolocation,
    Notifications,
}

impl PermKind {
    pub fn from_ipc(name: &str) -> Option<Self> {
        match name {
            "camera" => Some(Self::Camera),
            "microphone" => Some(Self::Microphone),
            "geolocation" => Some(Self::Geolocation),
            "notifications" => Some(Self::Notifications),
            _ => None,
        }
    }

    pub fn as_ipc(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::Geolocation => "geolocation",
            Self::Notifications => "notifications",
        }
    }

    pub const ALL: [Self; 4] = [
        Self::Camera,
        Self::Microphone,
        Self::Geolocation,
        Self::Notifications,
    ];
}

/// A site permission key: the origin that ASKED, which is not always the site
/// in the address bar.
///
/// An embedded frame gets its own entry rather than inheriting the top-level
/// grant. Allowing example.com must never hand the camera to an advertising
/// iframe it happens to embed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PermKey {
    pub origin: String,
    pub kind: PermKind,
}

/// A denied request, kept so the privacy panel can offer it back as a toggle.
#[derive(Debug, Clone, Default)]
pub struct DeniedRecord {
    pub count: u64,
    /// Top-level origins this frame asked from, so the panel can show a
    /// frame's request on the tab where it happened.
    pub seen_under: std::collections::BTreeSet<String>,
}

/// The largest number of distinct denied keys retained.
///
/// Page content chooses these origins, so without a cap a hostile page can
/// mint subdomains until the process runs out of memory. Session-only bounds
/// the DURATION of the growth, not its peak. On overflow the table stops
/// accepting NEW keys and keeps counting existing ones: dropping an entry a
/// user might be about to allow is worse than declining to remember one more.
const MAX_DENIED_KEYS: usize = 512;

#[derive(Debug, Default)]
struct PermTable {
    grants: std::collections::BTreeSet<PermKey>,
    denied: std::collections::BTreeMap<PermKey, DeniedRecord>,
}

/// Session-only site permission ledger. Cheap to clone; every clone is the
/// same table.
#[derive(Debug, Clone, Default)]
pub struct PermissionBook(std::sync::Arc<std::sync::Mutex<PermTable>>);

impl PermissionBook {
    /// The one question the engine asks, on whatever thread it likes.
    ///
    /// True ONLY on an explicit session grant for the origin that actually
    /// asked. Every other path denies and is counted: never asked, revoked,
    /// an unusable origin, or a poisoned lock. Fail closed, always -- a
    /// permission check that cannot reach its table must not answer yes.
    pub fn decide(&self, requesting_origin: &str, top_origin: &str, kind: PermKind) -> bool {
        let Some(origin) = normalize_origin(requesting_origin) else {
            return false;
        };
        let key = PermKey { origin, kind };
        let Ok(mut table) = self.0.lock() else {
            return false;
        };
        if table.grants.contains(&key) {
            return true;
        }
        let at_cap = table.denied.len() >= MAX_DENIED_KEYS;
        if let Some(record) = table.denied.get_mut(&key) {
            record.count = record.count.saturating_add(1);
            if let Some(top) = normalize_origin(top_origin) {
                record.seen_under.insert(top);
            }
        } else if !at_cap {
            let mut record = DeniedRecord {
                count: 1,
                ..Default::default()
            };
            if let Some(top) = normalize_origin(top_origin) {
                record.seen_under.insert(top);
            }
            table.denied.insert(key, record);
        }
        false
    }

    /// Grants for the session. False when the origin is unusable.
    pub fn grant(&self, origin: &str, kind: PermKind) -> bool {
        let Some(origin) = normalize_origin(origin) else {
            return false;
        };
        let key = PermKey { origin, kind };
        let Ok(mut table) = self.0.lock() else {
            return false;
        };
        // The denial RECORD IS NOT REMOVED, only its count reset. That record
        // is the only thing remembering which tabs this origin asked from, and
        // for an embedded frame the frame's origin is not the tab's, so
        // dropping it here would make a just-granted frame permission vanish
        // from the panel of the very tab the user granted it on -- leaving no
        // way to revoke it from the context where it matters.
        if let Some(record) = table.denied.get_mut(&key) {
            record.count = 0;
        }
        table.grants.insert(key);
        true
    }

    pub fn revoke(&self, origin: &str, kind: PermKind) -> bool {
        let Some(origin) = normalize_origin(origin) else {
            return false;
        };
        let Ok(mut table) = self.0.lock() else {
            return false;
        };
        table.grants.remove(&PermKey { origin, kind });
        true
    }

    /// What the panel shows for the tab currently on `top_origin`: everything
    /// granted to that origin, plus anything denied while the user was there,
    /// including frames whose own origin differs.
    pub fn status_for(&self, top_origin: &str) -> Vec<(PermKey, bool, u64)> {
        let Some(top) = normalize_origin(top_origin) else {
            return Vec::new();
        };
        let Ok(table) = self.0.lock() else {
            return Vec::new();
        };
        let mut out: std::collections::BTreeMap<PermKey, (bool, u64)> =
            std::collections::BTreeMap::new();
        for (key, record) in &table.denied {
            if record.seen_under.contains(&top) {
                out.insert(key.clone(), (false, record.count));
            }
        }
        // A grant stays visible on the tab it is active under even if it was
        // first granted elsewhere, so it can always be revoked from context.
        for key in &table.grants {
            if key.origin == top || out.contains_key(key) {
                out.insert(key.clone(), (true, 0));
            }
        }
        out.into_iter()
            .map(|(key, (granted, count))| (key, granted, count))
            .collect()
    }
}

/// Reduces a URL or origin to a comparable `scheme://host[:port]`, or None
/// when it cannot be a permission subject.
///
/// REJECTS opaque and malformed origins outright rather than turning them into
/// keys. "null", "about:blank" and a bare "https://" are not sites; accepting
/// them would collapse unrelated sandboxed documents onto one grant, so a
/// single allow could speak for all of them. Default ports are dropped so
/// `https://example.com` and `https://example.com:443` cannot become two
/// entries the user has to allow twice.
pub fn normalize_origin(input: &str) -> Option<String> {
    let input = input.trim();
    let (scheme, rest) = if let Some(rest) = input.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = input.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rfind(':') {
        Some(at) if !authority[at..].contains(']') => {
            let port = &authority[at + 1..];
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (&authority[..at], Some(port))
        }
        _ => (authority, None),
    };
    if host.is_empty() {
        return None;
    }
    let host_lower = host.to_ascii_lowercase();
    if host_lower.starts_with('[') {
        if !host_lower.ends_with(']') || host_lower.len() <= 2 {
            return None;
        }
    } else {
        let ok = !host_lower.starts_with('.')
            && !host_lower.ends_with('.')
            && !host_lower.contains("..")
            && host_lower
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
        if !ok {
            return None;
        }
    }
    let default_port = if scheme == "https" { "443" } else { "80" };
    match port {
        Some(p) if p != default_port => Some(format!("{scheme}://{host_lower}:{p}")),
        _ => Some(format!("{scheme}://{host_lower}")),
    }
}

/// See `AppState::pending_save`. `origin` is what the content script itself
/// reported (`location.origin`) -- trusted no further than any other content
/// input, which is why `cred_save_confirm` re-derives the ORIGIN IT ACTUALLY
/// SAVES UNDER from `Tab.url` (the same tracked field `forget_active_tab_
/// cookies` and `active_tab_status`'s `origin` use), not from this struct.
/// This copy exists only to show the user which site the offer is for.
pub(crate) struct PendingSave {
    pub(crate) tab_id: u64,
    origin: String,
    pub(crate) username: String,
    pub(crate) password: String,
}

impl AppState {
    pub fn new(
        chrome: WebView,
        hosts: platform::Hosts,
        proxy: EventLoopProxy<UserEvent>,
        smoke_mode: bool,
    ) -> Self {
        Self {
            vault: None,
            vault_path: Vault::default_path(),
            store: None,
            store_path: Store::default_path(),
            store_error: None,
            last_activity: Instant::now(),
            autolock_secs: crate::prefs::load().vault_autolock_secs,
            lock_warning_sent: false,
            tabs: Vec::new(),
            active: 0,
            find: crate::find::FindSession::default(),
            next_tab_id: 1,
            hosts,
            proxy,
            chrome,
            chrome_height: platform::CHROME_HEIGHT_PX,
            chrome_arrangement: platform::ChromeLayout::Strip,
            privacy: platform::TabPolicy::default(),
            smoke_mode,
            probe_started: false,
            ping_count: 0,
            picked_paths: std::collections::VecDeque::new(),
            next_pick_token: 1,
            smoke_second_ping_requested: false,
            smoke_deadline_ticks: 0,
            smoke_vault_done: false,
            integrity: crate::page_integrity::IntegrityState::default(),
            pending_save: None,
            pending_pdf: std::collections::HashMap::new(),
            #[cfg(feature = "chat")]
            chat: crate::chat_panel::ChatState::default(),
            permissions: PermissionBook::default(),
        }
    }

    /// The chrome webview, for platform calls that need any live webview to
    /// reach process-wide engine state (the profile, for instance).
    ///
    /// Returned as `&WebView` rather than exposing the field: this is the one
    /// webview `evaluate_script` may target, and that invariant is easier to
    /// keep when the field itself stays private.
    pub fn chrome(&self) -> &WebView {
        &self.chrome
    }

    /// What the privacy panel shows for the ACTIVE tab's site.
    ///
    /// `supported` is the honest half: on a tab whose permission handler never
    /// registered, and on every unix build, the browser is not policing these
    /// requests at all. The panel disables its controls on that answer rather
    /// than showing switches that would do nothing.
    pub fn permission_status(&self) -> serde_json::Value {
        let origin = self
            .tabs
            .get(self.active)
            .map(|t| t.url.as_str())
            .unwrap_or_default();
        let supported = self
            .tabs
            .get(self.active)
            .map(|t| {
                platform::engine_settings(&t.view).permissions_registered == "applied"
            })
            .unwrap_or(false);
        let site = normalize_origin(origin);
        // ALL FOUR KINDS, ALWAYS, for whatever site the tab is on -- not just
        // the ones that happen to have asked.
        //
        // The panel used to list only what a site had already requested, so a
        // user who opened it before any request found the four kinds
        // DESCRIBED in prose and no control anywhere, which reads as "this
        // browser has no permission settings". Worse, a site whose request we
        // silently denied gives no prompt, so the only way to reach a control
        // was to already know a row would appear once you triggered the
        // refusal a second time. Reported as a defect on 2026-08-06 hardware
        // testing, in exactly those words: "No option to allow or deny
        // cameras, mics, etc."
        //
        // Seeding here rather than in chrome.js keeps the rule in one place
        // and testable: the renderer stays a renderer.
        let mut entries: Vec<serde_json::Value> = Vec::new();
        if let Some(s) = site.as_deref() {
            let recorded = self.permissions.status_for(s);
            // The site's own four, in a fixed order so the list never
            // reshuffles under the pointer as requests arrive.
            for kind in PermKind::ALL {
                let found = recorded
                    .iter()
                    .find(|(key, _, _)| key.origin == s && key.kind == kind);
                let (granted, count) = found.map_or((false, 0), |(_, g, c)| (*g, *c));
                entries.push(json!({
                    "origin": s,
                    "kind": kind.as_ipc(),
                    "granted": granted,
                    "deniedCount": count,
                }));
            }
            // Then anything belonging to an EMBEDDED frame, which is a
            // different origin from the tab's and cannot be pre-seeded: we
            // only learn such an origin exists when it asks.
            for (key, granted, count) in &recorded {
                if key.origin != s {
                    entries.push(json!({
                        "origin": key.origin,
                        "kind": key.kind.as_ipc(),
                        "granted": granted,
                        "deniedCount": count,
                    }));
                }
            }
        }
        json!({
            "supported": supported,
            "site": site,
            "entries": entries,
        })
    }

    /// Runs a script in the chrome webview — the ONE surface where script
    /// evaluation is permitted. Used to install the chat panel's JS, which is
    /// not referenced from index.html so that a non-chat build does not ask
    /// for an asset it never serves.
    #[cfg(feature = "chat")]
    pub fn eval_chrome(&self, script: &str) {
        let _ = self.chrome.evaluate_script(script);
    }

    /// Smoke mode only: ask chrome.js to send a second ping. The eval itself
    /// exercises the Rust->JS direction; the resulting IPC message exercises
    /// JS->Rust again.
    pub fn request_second_ping(&self) {
        let _ = self.chrome.evaluate_script(
            r#"window.ipc.postMessage(JSON.stringify({id: 9999, cmd: "ping", args: {}}));"#,
        );
    }

    /// A proxy clone for code that must hand the event loop to a background
    /// thread's callback. The field stays private: handing out `&mut` access to
    /// it would let a caller replace the loop's only channel.
    pub fn proxy(&self) -> EventLoopProxy<UserEvent> {
        self.proxy.clone()
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        // A fresh idle stretch gets a fresh warning. Without this the notice
        // would fire once per session and every later approach to the deadline
        // would be silent.
        self.lock_warning_sent = false;
    }

    /// The configured idle timeout, or `None` when the user chose never.
    pub fn autolock_after(&self) -> Option<Duration> {
        (self.autolock_secs > 0).then(|| Duration::from_secs(self.autolock_secs))
    }


    /// When the event loop next needs to wake for the vault: the warning if it
    /// has not been raised yet, otherwise the lock itself.
    ///
    /// `None` whenever nothing is pending -- no vault open, or auto-lock
    /// disabled -- so the loop can go back to waiting indefinitely instead of
    /// spinning on a deadline that will never do anything.
    pub fn autolock_deadline(&self) -> Option<Instant> {
        let after = self.autolock_after()?;
        self.vault.as_ref()?;
        Some(if self.lock_warning_sent {
            self.last_activity + after
        } else {
            // saturating: a timeout shorter than the warning window means the
            // warning is due immediately rather than in the past.
            self.last_activity + after.saturating_sub(AUTO_LOCK_WARN_BEFORE)
        })
    }

    /// Reply to a chrome IPC request. Evaluates on the chrome webview only —
    /// never on the content webview.
    pub fn reply(&self, id: u64, result: Result<Value, &'static str>) {
        let payload = match result {
            Ok(data) => json!({ "id": id, "ok": true, "data": data }),
            Err(code) => json!({ "id": id, "ok": false, "error": code }),
        };
        let _ = self
            .chrome
            .evaluate_script(&format!("window.__rb_reply({payload});"));
    }

    /// Push an unsolicited event to the chrome UI.
    pub fn emit(&self, event: &str, data: Value) {
        let payload = json!({ "event": event, "data": data });
        let _ = self
            .chrome
            .evaluate_script(&format!("window.__rb_event({payload});"));
    }

    /// A page capture finished (or failed) in the engine. Validate, let the
    /// user choose where it goes, write it, and say what happened -- all on
    /// the UI thread, like every other picker flow. A cancelled picker is a
    /// changed mind, not an error: no file, no toast.
    pub fn on_capture_done(&mut self, ev: crate::capture::CaptureEvent) {
        // Whatever happens below, the next capture may start.
        crate::capture::CAPTURE_IN_FLIGHT.store(false, std::sync::atomic::Ordering::SeqCst);
        let scope = crate::capture::current_scope();
        let bytes = match ev.png.and_then(|bytes| {
            crate::capture::validate_capture_bytes(&bytes).map(|()| bytes)
        }) {
            Ok(bytes) => bytes,
            Err(code) => {
                let text = match code {
                    "no_capture_page" => "Nothing to capture on this page.".to_string(),
                    _ => "The capture failed; nothing was saved.".to_string(),
                };
                self.emit("toast", json!({ "text": text, "error": true }));
                return;
            }
        };
        let title = format!(
            "Save capture ({})",
            crate::capture::scope_label(scope)
        );
        let Some(path) = platform::pick_file_to_save(
            &self.hosts,
            &title,
            crate::capture::default_save_name(scope),
        ) else {
            return;
        };
        match std::fs::write(&path, &bytes) {
            Ok(()) => {
                self.emit(
                    "toast",
                    json!({
                        "text": format!(
                            "Saved a picture of the {}.",
                            crate::capture::scope_label(scope)
                        ),
                    }),
                );
            }
            Err(_) => {
                self.emit(
                    "toast",
                    json!({
                        "text": "Could not write the capture to that location.",
                        "error": true,
                    }),
                );
            }
        }
    }

    /// Forward an engine find-count callback to the chrome, if it still
    /// belongs to the tab the user is looking at. A callback already in
    /// flight when a tab switch stopped the session must not paint counts
    /// onto another tab's bar, which is why this checks the webview identity
    /// rather than trusting delivery order.
    pub fn on_find_event(&self, ev: crate::find::FindEvent) {
        if !self.find.is_active() {
            return;
        }
        let Some(webview) = self.active_webview() else {
            return;
        };
        if platform::find_key(webview) != ev.key {
            return;
        }
        self.emit(
            "find_state",
            json!({ "text": crate::find::format_count(ev.active, ev.total, ev.capped) }),
        );
    }

    pub fn check_autolock(&mut self) {
        let Some(after) = self.autolock_after() else {
            return; // the user chose never
        };
        if self.vault.is_none() {
            return;
        }
        let idle = self.last_activity.elapsed();

        // The warning, one minute out. Raised before the lock check so a very
        // short configured timeout still gets one, and only once per idle
        // stretch -- `touch` clears the flag, so acting on it re-arms it.
        if !self.lock_warning_sent && idle >= after.saturating_sub(AUTO_LOCK_WARN_BEFORE) {
            self.lock_warning_sent = true;
            if idle < after {
                let seconds = (after - idle).as_secs().max(1);
                self.emit("vault_lock_warning", json!({ "seconds": seconds }));
            }
        }

        if self.last_activity.elapsed() >= after {
            // ONE LOCK PATH, and this call is the whole point of it.
            //
            // This branch used to inline the lock -- `vault = None`, the chat
            // teardown, the `vault_locked` emit -- a byte-for-byte copy of
            // `lock_vault`, while ipc.rs's `vault_lock` arm carried a comment
            // claiming an explicit lock takes the SAME path as the auto-lock.
            // It did not. The copies even shared a note reading "to flip this
            // decision, add `self.store = None;` here (and in `lock_vault`)",
            // which is the hazard stated out loud: two sites, one of which
            // will eventually be edited alone. Adding a third trigger
            // (workstation lock) on top of that is how one of them silently
            // stops zeroizing or stops telling the chrome.
            self.lock_vault();
        }
    }

    // ---- layout ----------------------------------------------------------

    /// Windows: (re-)apply bounds for the chrome strip and the active tab —
    /// needed after resize, scale-factor change, tab switch, and chrome
    /// height change. unix: no-op, GTK packing owns layout there.
    pub fn relayout(&self) {
        let active = self.tabs.get(self.active).map(|tab| &tab.webview);
        platform::layout(
            &self.hosts,
            &self.chrome,
            active,
            self.chrome_height,
            self.chrome_arrangement,
        );
    }

    /// Cover the window with the chrome, or give it back to the page.
    ///
    /// This is what a modal panel opens into. The content webview is given a
    /// zero rect rather than being painted over, because the two are SIBLING
    /// child windows on Windows and siblings do not composite: whichever was
    /// created last draws on top, and the content webviews are all created
    /// after the chrome. Overlapping them would be a z-order fight that looks
    /// fine on one machine and wrong on another. Nothing overlaps if nothing
    /// has size.
    pub fn set_chrome_arrangement(&mut self, next: platform::ChromeLayout) {
        if self.chrome_arrangement == next {
            return;
        }
        let leaving_cover = !matches!(self.chrome_arrangement, platform::ChromeLayout::Strip)
            && matches!(next, platform::ChromeLayout::Strip);
        self.chrome_arrangement = next;
        // COMING BACK TO A STRIP, THE HEIGHT IS STALE FOR ONE FRAME.
        //
        // Closing a panel sends two messages: the arrangement first, the height
        // second. Between them `chrome_height` still holds the PANEL's height,
        // and the Strip arm believes it -- the project owner's own diagnostic log
        // caught it:
        //
        //   arrangement=Strip chrome_height=500
        //     STRIP chrome_rect top=0 h=500
        //     STRIP content top=500 h=329      <- page shoved down 352px
        //   arrangement=Strip chrome_height=148
        //     STRIP content top=148 h=681      <- and back
        //
        // One frame of the page jumping a third of the window down, every time
        // a panel closes. The strip cannot be 500 tall, so the stale value is
        // dropped rather than laid out: the height message arriving directly
        // behind this one relayouts with the real number.
        if leaving_cover {
            self.chrome_height = platform::CHROME_HEIGHT_PX.max(0);
        }
        self.relayout();
    }

    /// Whether a docked pane is currently laid out.
    pub fn is_split(&self) -> bool {
        matches!(self.chrome_arrangement, platform::ChromeLayout::Split { .. })
    }

    pub fn set_chrome_height(&mut self, px: i32) {
        self.chrome_height = px;
        // unix: updates the GTK size request (and GTK repacks by itself).
        // Windows: no-op, the relayout() below applies the new height.
        platform::set_chrome_height(&self.hosts, px);
        self.relayout();
    }

    // ---- tabs ---------------------------------------------------------------

    /// Records a path the user picked and returns the token that redeems it.
    pub fn remember_picked_path(&mut self, path: PathBuf) -> u64 {
        let token = self.next_pick_token;
        self.next_pick_token += 1;
        self.picked_paths.push_back((token, path));
        while self.picked_paths.len() > MAX_PICKED_PATHS {
            self.picked_paths.pop_front();
        }
        token
    }

    /// Redeems a token for the path it names, consuming it.
    ///
    /// One-shot: a token cannot be replayed, so a leaked one is worth a single
    /// read of a file the user themselves selected, and only until the next
    /// eight picks push it out.
    pub fn take_picked_path(&mut self, token: u64) -> Option<PathBuf> {
        let at = self.picked_paths.iter().position(|(t, _)| *t == token)?;
        self.picked_paths.remove(at).map(|(_, path)| path)
    }

    /// Creates a tab and returns its id. `switch` selects and shows it;
    /// otherwise it stays hidden in the background.
    ///
    /// `Err("tab_failed")` when the engine could not build the webview. The
    /// caller must handle it: this is reachable from web content via
    /// `window.open`, and it used to be a process-wide panic.
    pub fn new_tab(&mut self, url: &str, switch: bool) -> Result<u64, &'static str> {
        let id = self.next_tab_id;
        let tab = build_tab(
            &self.hosts,
            &self.proxy,
            id,
            url,
            &self.privacy,
            self.permissions.clone(),
        )
        .map_err(|_| "tab_failed")?;
        // Bumped only AFTER the build succeeds, so a failed attempt does not
        // burn an id and leave a gap in the sequence.
        self.next_tab_id += 1;
        let was_empty = self.tabs.is_empty();
        self.tabs.push(tab);
        if was_empty {
            self.active = 0;
            platform::show_tab(&self.tabs[0].view, &self.tabs[0].webview);
            self.relayout();
        } else if switch {
            let index = self.tabs.len() - 1;
            self.set_active(index);
        }
        self.emit_tabs_changed();
        Ok(id)
    }

    pub fn close_tab(&mut self, id: u64) -> Result<(), &'static str> {
        let index = self
            .tabs
            .iter()
            .position(|tab| tab.id == id)
            .ok_or("not_found")?;
        let was_active = index == self.active;

        // CLOSING THE LAST TAB: build the replacement BEFORE removing.
        //
        // The invariant is "never zero tabs", and several accessors below and
        // in set_active index `self.tabs[self.active]` directly -- so an empty
        // list does not degrade, it panics somewhere else instead. The old
        // order (remove, then build, then `.expect`) had no way to keep the
        // invariant when the engine refused to build: it took the process
        // down. Building first means a refusal leaves the browser exactly as
        // it was and the user is told, which is the only outcome here that is
        // both honest and survivable.
        if self.tabs.len() == 1 {
            let fresh = build_tab(
                &self.hosts,
                &self.proxy,
                self.next_tab_id,
                "about:blank",
                &self.privacy,
                self.permissions.clone(),
            )
            .map_err(|_| "tab_failed")?;
            self.next_tab_id += 1;
            drop(self.tabs.remove(index)); // detaches (unix) / destroys (windows)
            self.tabs.push(fresh);
            self.active = 0;
            platform::show_tab(&self.tabs[0].view, &self.tabs[0].webview);
            self.relayout();
            self.emit_tabs_changed();
            let url = self.tabs[0].url.clone();
            self.emit("url_changed", json!({ "url": url }));
            self.emit_tab_status();
            return Ok(());
        }

        let tab = self.tabs.remove(index);
        drop(tab); // Tab::drop detaches the view (unix) / destroys the WebView2 (windows)

        // At least one tab remains -- the single-tab case returned above -- so
        // every index below is in range.
        if index < self.active {
            self.active -= 1;
        } else if was_active {
            // Right neighbor (shifted into `index`) if any, else left.
            self.active = index.min(self.tabs.len() - 1);
        }
        if was_active {
            platform::show_tab(&self.tabs[self.active].view, &self.tabs[self.active].webview);
            self.relayout();
        }
        self.emit_tabs_changed();
        if was_active {
            let url = self.tabs[self.active].url.clone();
            self.emit("url_changed", json!({ "url": url }));
            self.emit_tab_status();
        }
        Ok(())
    }

    pub fn switch_tab(&mut self, id: u64) -> Result<(), &'static str> {
        let index = self
            .tabs
            .iter()
            .position(|tab| tab.id == id)
            .ok_or("not_found")?;
        self.set_active(index);
        self.emit_tabs_changed();
        Ok(())
    }

    /// Selects a tab by position, ignoring an out-of-range index.
    ///
    /// Out of range is normal rather than exceptional here: Ctrl+5 with three
    /// tabs open should do nothing, not error.
    pub fn select_tab_index(&mut self, index: usize) {
        if index < self.tabs.len() {
            self.set_active(index);
            self.emit_tabs_changed();
        }
    }

    pub fn select_last_tab(&mut self) {
        if !self.tabs.is_empty() {
            self.select_tab_index(self.tabs.len() - 1);
        }
    }

    /// Moves `delta` tabs forward or backward, wrapping at both ends the way
    /// Ctrl+Tab does in every other browser.
    pub fn cycle_tab(&mut self, delta: i32) {
        let count = self.tabs.len();
        if count < 2 {
            return;
        }
        let count_i = count as i32;
        let next = (self.active as i32 + delta).rem_euclid(count_i) as usize;
        self.select_tab_index(next);
    }

    /// Closes the active tab. Ctrl+W has no id to work with, unlike the IPC
    /// command which is driven by a click on a specific tab.
    pub fn close_active_tab(&mut self) {
        if let Some(id) = self.tabs.get(self.active).map(|tab| tab.id) {
            let _ = self.close_tab(id);
        }
    }

    /// Asks the chrome UI to focus and select the URL bar.
    ///
    /// Evaluated on the chrome webview only, which is the one surface where
    /// script evaluation is permitted.
    pub fn focus_url_bar(&self) {
        self.emit("focus_url_bar", json!({}));
    }

    /// Ctrl+K. Pushed to the chrome rather than acted on here: which actions
    /// exist and how they are matched is a chrome-JS concern, same reasoning
    /// as `UpdateChecked` deferring the install decision to the UI.
    pub fn open_command_palette(&self) {
        self.emit("open_command_palette", json!({}));
    }

    /// Print the ACTIVE TAB, never the chrome.
    ///
    /// The whole reason Ctrl+P is intercepted: unbound, the engine handled it
    /// on whichever webview had focus and printed the browser's own toolbar.
    /// Naming the active tab here removes focus from the question entirely.
    pub fn print_active_tab(&self) {
        let Some(tab) = self.tabs.get(self.active) else {
            return;
        };
        if !platform::show_print_ui(&tab.webview) {
            // Say so rather than appear to do nothing -- an unexplained no-op
            // is the failure this whole path replaced.
            self.emit(
                "print_unavailable",
                json!({ "reason": "this runtime cannot open a print preview" }),
            );
        }
    }

    /// Replaces the browser-wide privacy policy and applies it to every open
    /// tab, so a toggle takes effect on what the user is already looking at
    /// rather than only on the next tab they open.
    ///
    /// `ephemeral` is deliberately NOT retroactive: a WebContext is fixed when
    /// its view is built, and pretending otherwise would claim a tab had no
    /// on-disk profile when it still did.
    pub fn set_privacy(&mut self, policy: platform::TabPolicy) {
        self.privacy = policy;
        for tab in &self.tabs {
            platform::apply_policy(&tab.webview, &tab.view, &self.privacy);
        }
    }

    /// The policy plus what this ENGINE can actually enforce. The UI needs
    /// both: a checkbox that silently does nothing is worse than one that
    /// says it is unavailable here.
    pub fn privacy_status(&self) -> Value {
        json!({
            "block_ads": self.privacy.block_ads,
            "freeze_after_load": self.privacy.freeze_after_load,
            "javascript": self.privacy.javascript,
            "ephemeral": self.privacy.ephemeral,
            "network_blocking_supported": platform::network_blocking_supported(),
            "freeze_enforced": platform::freeze_enforced(),
        })
    }

    /// JSON snapshot of the active tab's privacy posture. This is both the
    /// `tab_status` reply and the payload of the `tab_status` event pushed on
    /// tab switch, navigation and load-state change, so the always-visible
    /// indicators (freeze chip, TLS warning) never go stale.
    pub fn active_tab_status(&self) -> Value {
        let Some(tab) = self.tabs.get(self.active) else {
            // Unreachable in practice (the app never runs with zero tabs),
            // but a status endpoint degrades rather than panicking. The
            // string literals are the serde wire names locked by the
            // wire-names test in privacy.rs.
            return json!({
                "freeze_phase": "loaded",
                "freeze_enforcement": "inactive",
                "profile": "persistent",
                "origin": Value::Null,
                "tls": "unknown",
                "freeze_enforced": platform::freeze_enforced(),
                "network_blocking_supported": platform::network_blocking_supported(),
                "ledger_counts_blocked": LEDGER_COUNTS_BLOCKED,
                "blocked_total": 0,
                "interception": "not_attempted",
                "script_setting": "not_attempted",
                "smartscreen_off": "not_attempted",
                "tracking_prevention": "not_attempted",
                "navigation_tracking": "not_attempted",
                // Drift fix: this key and session_lock_registered (below)
                // are carried by the tab arm but were absent here. A key
                // present in one arm and absent in the other renders as a
                // missing row only in the zero-tab state, which is why
                // nobody noticed.
                "autofill_off": "not_attempted",
                "ephemeral_confirmed": "not_attempted",
                "hardened_environment": "not_attempted",
                "session_lock_registered": "not_attempted",
                // Same degraded default as everything else in this
                // unreachable arm; the measured value lives in the tab arm.
                "tunnel": "not_attempted",
                "content_script_registered": "not_attempted",
                "pending_save": Value::Null,
            });
        };
        let engine_settings = platform::engine_settings(&tab.view);
        json!({
            "freeze_phase": platform::freeze_phase(&tab.view),
            // What the user ASKED for is `freeze_phase`; what the ENGINE did
            // about it is this. They differ on WebKitGTK, where the blocking
            // filter compiles asynchronously and can fail — so the UI must
            // read this before claiming the tab is making no requests.
            "freeze_enforcement": platform::freeze_enforcement(&tab.view).as_str(),
            "profile": platform::profile_mode(&tab.view),
            // The host of the page actually loaded, not the address-bar text
            // (which may be mid-edit or a search string that never
            // navigated). `null` for a page with no http(s) authority --
            // about:blank, an internal page, or a malformed URL -- so the
            // site-info popover can say "no site" rather than showing an
            // empty label with nothing behind it.
            "origin": host_of(&tab.url),
            "tls": platform::tls_state(&tab.webview, &tab.view),
            // Capability flags ride along so the UI can disable (and
            // explain) a control the running platform cannot honour, instead
            // of offering a switch that does nothing.
            "freeze_enforced": platform::freeze_enforced(),
            "network_blocking_supported": platform::network_blocking_supported(),
            "ledger_counts_blocked": LEDGER_COUNTS_BLOCKED,
            // Requests this tab has had blocked. Rides here rather than on
            // `tab_ledger` because the shield shows it without any panel being
            // open, and this is the payload that arrives on navigation and tab
            // switch. Read it ONLY together with `ledger_counts_blocked`: on a
            // backend that cannot observe blocking this is zero because nothing
            // was counted, not because nothing was stopped.
            "blocked_total": platform::blocked_total(&tab.view),
            // Which blocking mechanism this tab actually holds. Diagnostic,
            // not a control: it separates "no handler was ever registered"
            // from "registered, but the block is not sticking" — identical
            // from outside, and needing opposite fixes.
            "interception": platform::interception_state(&tab.view),
            // Whether the ENGINE confirmed the JavaScript setting, as opposed
            // to whether the user asked for it. "failed" means the tab is
            // still running script no matter what `javascript` above says.
            "script_setting": platform::script_setting(&tab.view),
            // Four more engine answers, same rule: what was CONFIRMED, not
            // what was requested. "failed" on smartscreen means reputation
            // checking is still on; on navigation it means this tab can never
            // auto-freeze.
            "smartscreen_off": engine_settings.smartscreen_off,
            "tracking_prevention": engine_settings.tracking_prevention,
            "navigation_tracking": engine_settings.navigation_tracking,
            "autofill_off": engine_settings.autofill_off,
            // Whether the engine confirmed this tab's STORAGE mode. Anything
            // other than "applied" on an ephemeral tab means the cookies and
            // cache may be landing on disk after all -- which is why "profile"
            // above already refuses to say "ephemeral" without it.
            "ephemeral_confirmed": engine_settings.ephemeral_confirmed,
            // Process-wide. "failed" means the browser is running on the
            // engine's default environment, having lost its hardened browser
            // arguments and crash-report suppression -- which used to be
            // reported only to a debug-build log nobody shipping ever sees.
            "hardened_environment": engine_settings.hardened_environment,
            // Process-wide, and the only MEASURED row: "applied" means the
            // probe thread's latest cycle completed a real SOCKS5 greeting
            // against the loopback tunnel front AND the tunnel reported Up.
            // Before the vault unlocks this reads "failed" on purpose --
            // the port is refusing every connection, so the tunnel is not
            // carrying traffic, and the row says so.
            "tunnel": engine_settings.tunnel,
            // Process-wide, like `hardened_environment`. "failed" means the OS
            // refused to tell us about workstation locks, so the vault will
            // NOT close when the screen does and only the inactivity timer is
            // guarding it. The user is told that rather than left with a
            // setting that reads as on.
            "session_lock_registered": engine_settings.session_lock_registered,
            // Whether the content-script + message-handler registration this
            // tab's autofill save/fill flow depends on actually succeeded.
            // The fill/save affordance must never be offered on the strength
            // of an unconfirmed capability -- same discipline as every other
            // field above.
            "content_script_registered": engine_settings.content_script_registered,
            // Set only if the ACTIVE tab is the one that submitted it -- see
            // `note_login_submitted` and `PendingSave`'s own doc. Never the
            // password: chrome.js gets enough to render "Save password for
            // X (Y)?" and nothing that would let the raw value sit in this
            // webview's own DOM.
            "pending_save": self.pending_save.as_ref().and_then(|p| {
                (self.tabs.get(self.active).map(|t| t.id) == Some(p.tab_id))
                    .then(|| json!({ "origin": p.origin, "username": p.username }))
            }),
        })
    }

    /// Pushes the active tab's status to the chrome UI. Called from every
    /// transition that can change it without an IPC round trip: tab switch,
    /// navigation, load-state change, tab close.
    /// Apply any due auto-freeze transitions and report the next deadline.
    ///
    /// Called from the event loop's timer arm. Exists because the WINDOWS
    /// backend has no engine timer -- its transition happens lazily on the next
    /// request, which enforces correctly but leaves the toolbar reporting
    /// "Live" on a tab that is armed to freeze. Unix returns None here; its GTK
    /// timeout already did the work.
    pub fn tick_auto_freeze(&mut self, now: Instant) -> Option<Instant> {
        let mut changed = false;
        let mut next: Option<Instant> = None;
        for tab in &self.tabs {
            let (did, deadline) = platform::tick_auto_freeze(&tab.view, now);
            changed |= did;
            next = match (next, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        if changed {
            self.emit_tab_status();
        }
        next
    }

    /// Zoom the active tab and tell the chrome, so the level is visible
    /// rather than something the user has to infer from the page.
    pub fn zoom_active(&mut self, dir: i32) {
        // With a MODAL open, the zoom keys belong to the PANEL, and this is
        // the only place that can honour them. Our own accelerator handler
        // runs on the chrome webview too and marks Ctrl+= / Ctrl+- / Ctrl+0
        // handled (connect_shortcuts), so a keydown listener in chrome.js
        // would never fire -- one shipped, looked exactly like the feature,
        // and did nothing on real hardware (decided 2026-07-31). Routing
        // the event back across the IPC is the one spelling that works, and
        // it also stops the old failure of rescaling a page nobody can see.
        if matches!(
            self.chrome_arrangement,
            crate::platform::ChromeLayout::Overlay
        ) {
            self.emit("panel_zoom", json!({ "dir": dir }));
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return;
        };
        let level = tab.zoom_step(dir);
        self.emit("zoom_changed", json!({ "percent": (level * 100.0).round() }));
    }

    /// The engine zoomed a tab by itself -- a keypad shortcut, or Ctrl+scroll.
    ///
    /// Reported for the tab it happened to, but only shown when that tab is
    /// the visible one: a background tab's level is not what the chip is
    /// describing.
    pub fn on_zoom_factor_changed(&mut self, id: u64, factor: f64) {
        let Some(index) = self.tabs.iter().position(|t| t.id == id) else {
            return;
        };
        self.tabs[index].note_engine_zoom(factor);
        if index == self.active {
            let level = self.tabs[index].zoom_level();
            self.emit("zoom_changed", json!({ "percent": (level * 100.0).round() }));
        }
    }

    pub fn emit_tab_status(&self) {
        let status = self.active_tab_status();
        self.emit("tab_status", status);
    }

    /// Manual freeze of the active tab. Per-tab and reversible; the reply is
    /// the refreshed status so the toolbar chip and panel update in one
    /// round trip. Honoured even mid-load: a load finishing does not undo a
    /// manual freeze (see FreezeController::on_load_finished).
    pub fn freeze_active_tab(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        platform::freeze(&tab.webview, &tab.view);
        Ok(self.active_tab_status())
    }

    /// One-call unfreeze of the active tab.
    pub fn unfreeze_active_tab(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        platform::unfreeze(&tab.webview, &tab.view);
        Ok(self.active_tab_status())
    }

    /// Per-site override on the active tab: `host` keeps working even while
    /// the tab is frozen. Survives navigation, dies with the tab (the
    /// override is the user's exception, not the page's).
    pub fn allow_site_active_tab(&self, host: &str) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        platform::allow_site(&tab.webview, &tab.view, host);
        Ok(self.active_tab_status())
    }

    /// Deletes cookies for the active tab's own host -- and ONLY cookies.
    ///
    /// The host is read fresh from `Tab.url` at the moment of the call, never
    /// taken as an argument: the chrome UI has no legitimate reason to name a
    /// domain other than the one it is currently showing, and refusing to
    /// accept one closes off this becoming a delete-any-domain primitive if
    /// the chrome origin were ever compromised.
    ///
    /// There is no origin-scoped API for localStorage or IndexedDB on
    /// `ICoreWebView2Profile` -- only a profile-WIDE clear exists, and using
    /// it here would erase every other open site's data along with this
    /// one's. So this clears cookies alone, and the UI copy must say exactly
    /// that; see `forget_site_cookies`'s own doc for why.
    pub fn forget_active_tab_cookies(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("no_tab")?;
        let host = host_of(&tab.url).ok_or("no_site")?;
        if platform::forget_site_cookies(&tab.webview, &host) {
            Ok(json!({ "origin": host }))
        } else {
            Err("cookie_delete_failed")
        }
    }

    /// A content tab's password form was submitted. Only stashed if the tab
    /// is the ACTIVE one -- a background tab submitting a form must not pop
    /// a save offer for a page the user is not looking at, and there is
    /// nowhere else in this browser a save-password prompt could sensibly
    /// appear.
    ///
    /// Silently drops the submission if the vault is locked: offering to
    /// save into a vault the user has not opened is not this feature's job,
    /// and there is no "unlock, then continue" flow here to build.
    pub fn note_login_submitted(&mut self, tab_id: u64, origin: String, username: String, password: String) {
        if self.tabs.get(self.active).map(|t| t.id) != Some(tab_id) {
            return;
        }
        if self.vault.is_none() {
            return;
        }
        self.pending_save = Some(PendingSave {
            tab_id,
            origin: origin.clone(),
            username: username.clone(),
            password,
        });
        // Never the password: this event only tells chrome.js a save offer
        // exists, so the save banner can render without the raw password
        // ever entering the chrome webview's own DOM.
        self.emit(
            "login_submit_detected",
            json!({ "origin": origin, "username": username }),
        );
    }

    /// Takes and clears the pending save, for `cred_save_confirm` and
    /// `cred_save_dismiss` -- both consume it, neither peeks without taking.
    pub(crate) fn take_pending_save(&mut self) -> Option<PendingSave> {
        self.pending_save.take()
    }

    /// Drops the pending save if it belongs to the tab that just navigated --
    /// the DOM state that produced it is gone, so the offer must go with it.
    /// Called from `on_url_changed` regardless of which tab navigated: a
    /// pending save is tied to a specific tab, not only the active one.
    fn clear_pending_save_for(&mut self, tab_id: u64) {
        if self.pending_save.as_ref().map(|p| p.tab_id) == Some(tab_id) {
            self.pending_save = None;
        }
    }

    /// A snapshot for the diagnostics export: build/version, the active
    /// tab's engine-confirmed status, DNS mode, vault auto-lock setting, the
    /// last update check, and the recent in-memory diagnostic log.
    ///
    /// EXCLUDED ON PURPOSE, and this is the constraint the export exists
    /// under, not an afterthought: no browsing history, no page content, no
    /// URL beyond the one field `tab_status` already carries for the
    /// CURRENT tab, and nothing from the vault. `panel-audit.js` asserts the
    /// rendered template never grows a field shaped like one of those.
    pub fn diagnostics_snapshot(&self) -> Value {
        let prefs = crate::prefs::load();
        json!({
            "build": crate::about::ipc_info().unwrap_or_else(|_| json!({})),
            "tab_status": self.active_tab_status(),
            "dns_mode": prefs.dns.as_str(),
            "vault_autolock_secs": prefs.vault_autolock_secs,
            "update_status": crate::updater::status(),
            "recent_log": platform::recent_diagnostics(),
        })
    }

    /// Writes the same snapshot `diagnostics_get` returns, as plain text, to
    /// `dest`. No confirmation sentence like the vault's plaintext export --
    /// there is nothing destructive here, only information the user already
    /// has on screen, and no vault content is ever included.
    pub fn export_diagnostics(&self, dest: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(&self.diagnostics_snapshot())
            .unwrap_or_else(|_| "{}".to_string());
        std::fs::write(dest, text)
    }

    /// The active tab's per-host ledger. `counts_blocked` tells the UI
    /// whether the blocked column is observed (Windows) or structurally
    /// zero (WebKitGTK — see LEDGER_COUNTS_BLOCKED), so the ledger is
    /// labelled as what was STOPPED only where that is true.
    pub fn active_ledger(&self) -> Result<Value, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("not_found")?;
        Ok(json!({
            "items": platform::ledger(&tab.view),
            "counts_blocked": LEDGER_COUNTS_BLOCKED,
        }))
    }

    /// One command, full paranoid preset: ephemeral profile, JavaScript off,
    /// ad/tracker blocking on, freeze right after load (privacy.rs documents
    /// the policy). Always opens on about:blank and always switches to it —
    /// the point is that the user immediately types the suspicious URL into
    /// a tab that keeps nothing and runs nothing.
    pub fn new_quarantine_tab(&mut self) -> Result<u64, &'static str> {
        self.new_tab_with_policy("about:blank", true, &platform::TabPolicy::quarantine())
    }

    /// Renders the active tab to a PDF in the downloads folder.
    ///
    /// Returns the destination so the chrome can say where it went. The write
    /// itself is asynchronous; `on_pdf_saved` finishes the job when the engine
    /// reports back.
    pub fn save_active_page_as_pdf(&mut self) -> Result<String, &'static str> {
        let tab = self.tabs.get(self.active).ok_or("no_tab")?;
        let url = tab.url.clone();
        // A page that never loaded has nothing to render, and `about:blank`
        // would produce a blank sheet with a provenance record pointing at
        // nothing.
        if !is_allowed_content_url(&url) {
            return Err("no_page");
        }
        // Named from the URL and de-duplicated exactly like a real download,
        // so two saves of the same page do not overwrite each other.
        let suggested = download_dir().join(pdf_name_for(&url));
        let dest = unique_download_path(&url, &suggested);
        if !platform::save_page_as_pdf(&tab.webview, &dest, &self.proxy) {
            return Err("unsupported");
        }
        // Remembered so the completion handler can attribute the file to the
        // page it came from: by the time the engine answers, the tab may have
        // navigated somewhere else entirely.
        self.pending_pdf
            .insert(dest.to_string_lossy().into_owned(), url);
        Ok(dest.to_string_lossy().into_owned())
    }

    /// The engine finished (or failed) a PDF render.
    pub fn on_pdf_saved(&mut self, path: &str, success: bool) {
        let Some(source_url) = self.pending_pdf.remove(path) else {
            return; // not ours, or already handled
        };
        if !success {
            self.emit(
                "toast",
                json!({ "text": "Could not save that page as a PDF.", "error": true }),
            );
            return;
        }
        // The SAME call an ordinary download makes, so the PDF is hashed and
        // recorded identically and the Library's Verify button works on it
        // with no special case.
        self.record_download_provenance(&source_url, Some(path), true);
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        self.emit("toast", json!({ "text": format!("Saved {name}") }));
    }

    /// Writes one of the right-click menu's copy actions to the clipboard and
    /// says what happened.
    fn copy_to_clipboard(&mut self, text: &str, change: crate::ipc::LinkChange) {
        let (message, error) = copy_result_message(platform::set_clipboard_text(text), change);
        self.emit("toast", json!({ "text": message, "error": error }));
    }

    /// Image addresses take the same path but never the link vocabulary, and
    /// are never unwrapped or stripped: an image src is not a click target.
    fn copy_image_to_clipboard(&mut self, text: &str) {
        let (message, error) = if platform::set_clipboard_text(text) {
            ("Image address copied", false)
        } else {
            ("Could not copy that image address", true)
        };
        self.emit("toast", json!({ "text": message, "error": error }));
    }

    /// Acts on a right-click menu choice.
    ///
    /// The ids come from `platform::windows`'s MENU_* constants, and this is
    /// the only place they are interpreted. Every URL is re-validated by the
    /// path it takes (`new_tab_with_policy` -> `is_allowed_content_url`)
    /// rather than trusted because a menu produced it: the target originated
    /// in an untrusted page.
    pub fn on_context_menu_action(&mut self, action: u32, target: Option<&str>) {
        use crate::platform::menu_ids;

        // Cloned BEFORE the closure below, which needs `&mut self`: reading
        // `self.privacy` inside a match arm while that closure is alive is a
        // borrow conflict, and the value is four bools.
        let browser_policy = self.privacy.clone();

        // A failure here is reported the way every other user-initiated
        // failure is -- a toast -- rather than silently doing nothing, which
        // is indistinguishable from a menu that is broken.
        let mut open = |url: &str, background: bool, policy: platform::TabPolicy| {
            if !is_allowed_content_url(url) {
                self.emit(
                    "toast",
                    json!({ "text": "That link cannot be opened.", "error": true }),
                );
                return;
            }
            if self.new_tab_with_policy(url, !background, &policy).is_err() {
                self.emit(
                    "toast",
                    json!({ "text": "Could not open that link.", "error": true }),
                );
            }
        };

        match (action, target) {
            (menu_ids::OPEN_NEW_TAB, Some(url)) => {
                open(url, false, browser_policy.clone());
            }
            (menu_ids::OPEN_BACKGROUND, Some(url)) => {
                open(url, true, browser_policy.clone());
            }
            (menu_ids::OPEN_EPHEMERAL, Some(url)) => {
                open(url, false, platform::TabPolicy::ephemeral());
            }
            (menu_ids::OPEN_QUARANTINE, Some(url)) => {
                open(url, false, platform::TabPolicy::quarantine());
            }
            // Image open reuses the browser policy and the same allow-list
            // gate: the image source is untrusted page data like every other
            // menu URL.
            (menu_ids::OPEN_IMAGE_NEW_TAB, Some(url)) => {
                open(url, false, browser_policy.clone());
            }
            // Copying is done by THIS PROCESS, not by handing the text to the
            // chrome webview to write with `navigator.clipboard`. That is what
            // it used to do, and it could not work: the Clipboard API refuses
            // to write from a document that is not focused, and the focus is
            // in the page the user just right-clicked, never in the chrome.
            // See platform::set_clipboard_text. Nothing is evaluated in the
            // content webview either way.
            // SPLIT, not one arm for both. These used to share an arm, and
            // folding the image case in with the link case meant "Copy image
            // address" reported "Link copied". Same call, different noun.
            (menu_ids::COPY_LINK, Some(url)) => {
                self.copy_to_clipboard(url, crate::ipc::LinkChange::Unchanged);
            }
            (menu_ids::COPY_IMAGE, Some(url)) => {
                self.copy_image_to_clipboard(url);
            }
            (menu_ids::COPY_LINK_CLEAN, Some(url)) => {
                // Unwrap the redirect wrapper first, then strip tracking
                // parameters off whatever came out: a recovered destination
                // usually carries its own. `clean_link` pins that order.
                let (cleaned, change) = crate::ipc::clean_link(url);
                self.copy_to_clipboard(&cleaned, change);
            }
            // Navigation acts on the active tab and carries no URL. A failure
            // (nothing to go back to) is a normal state, not an error to
            // surface, so it is swallowed like the Back/Forward shortcuts.
            (menu_ids::HISTORY_BACK, _) => {
                let _ = self.history_back();
            }
            (menu_ids::HISTORY_FORWARD, _) => {
                let _ = self.history_forward();
            }
            (menu_ids::HISTORY_RELOAD, _) => {
                let _ = self.history_reload();
            }
            // Includes every id this build does not know and every action
            // whose target is missing. Doing nothing is correct: the menu is
            // built from the same constants, so a mismatch means a bug, not a
            // user request to guess at.
            _ => {}
        }
    }

    /// THE ONLY PLACE THE VAULT LOCKS. Every trigger routes here: the
    /// inactivity timer (`check_autolock`), the explicit `vault_lock` IPC
    /// command, the Ctrl+Shift+L shortcut, and workstation lock/suspend. Add
    /// a new trigger by calling this, never by repeating what it does -- a
    /// second copy is what let the auto-lock and the explicit lock drift
    /// apart once already.
    pub fn lock_vault(&mut self) {
        self.vault = None; // dropping Vault zeroizes key material
        // The store deliberately stays OPEN. The store crate's own docs say
        // "Bookmarks survive a vault auto-lock; passwords do not" -- at a
        // 300 s timeout a lock-step store would make bookmarks vanish
        // mid-session and silently skip provenance for any download
        // completing while locked. The store key is domain-separated from the
        // vault key, so keeping it does not widen the vault's attack surface,
        // and process exit drops it (Zeroizing) regardless. To flip this:
        // add `self.store = None;` HERE and nowhere else, then invert the
        // smoke assertion in ipc.rs and adjust the panel copy.
        //
        // The transport holds identities derived from the vault, so it has to
        // go down with it -- otherwise a locked vault keeps announcing the
        // user's addresses on the LAN.
        #[cfg(feature = "chat")]
        crate::chat_panel::on_vault_locked(self);
        // The licence session state derives from the vault the same way:
        // nothing licence-related survives a lock, and the next unlock
        // re-verifies from the stored record. Ungated, like the tunnel.
        crate::licence_control::on_vault_locked();
        self.emit("vault_locked", json!({}));
    }

    // ---- bookmark/provenance store -------------------------------------------

    /// Opens the store with the vault's passphrase, creating it on first use
    /// (existing vaults from before the store was wired get one silently, at
    /// the moment of unlock — no second prompt, no passphrase reuse nudge).
    ///
    /// Failure is recorded rather than propagated: a damaged bookmark file
    /// must not make the vault unusable, and the next unlock retries.
    pub fn open_store(&mut self, passphrase: &str) {
        let opened = if Store::exists(&self.store_path) {
            Store::unlock(&self.store_path, passphrase)
        } else {
            Store::create(&self.store_path, passphrase)
        };
        match opened {
            Ok(store) => {
                self.store = Some(store);
                self.store_error = None;
            }
            Err(err) => {
                self.store = None;
                self.store_error = Some(crate::ipc::store_code(err));
            }
        }
    }

    pub fn store_status(&self) -> Value {
        json!({
            "open": self.store.is_some(),
            "error": self.store_error,
            // Whether this build can digest a page is one question with one
            // answer, and it lives with the code that does the digesting:
            // `integrity_status` reports `platform::page_bytes_supported()`.
            // There used to be a second answer here — a hardcoded `false`
            // beside a seam that always returned None — so the bookmarks UI
            // said "this build cannot read page content yet" on a build that
            // demonstrably could, while the integrity panel on the same page
            // read it and produced verdicts.
            "digests_ready": crate::platform::page_bytes_supported(),
        })
    }

    /// Marks the bookmarks/downloads store as unavailable for this session.
    ///
    /// Used after a recovery-key unlock: the store is encrypted under the
    /// vault PASSPHRASE, and a recovery unlock legitimately does not have it.
    /// The library is therefore genuinely unreadable until the user unlocks
    /// with their passphrase again — which is a true statement about the
    /// encryption, not a bug, and the UI says exactly that instead of showing
    /// an empty list that reads as "you have no bookmarks".
    pub fn mark_store_unavailable(&mut self) {
        self.store = None;
        self.store_error = Some("store_needs_passphrase");
    }

    pub fn store_error(&self) -> Option<&'static str> {
        self.store_error
    }

    /// Called from the event loop's `UserEvent::DownloadDone` arm — BEFORE
    /// the `download_finished` emit there, so a downloads-view refresh
    /// triggered by that event already sees the record (or the explicit
    /// failure event). On a successful completion, hashes the saved file and
    /// records it in the store: "this is exactly what arrived".
    ///
    /// What happens when recording is impossible is a decision, not a silent
    /// drop:
    ///   * failed download, or no destination path: nothing to fingerprint;
    ///     the download toast already covered the download itself.
    ///   * store never opened this session (vault never unlocked, a
    ///     recovery-key unlock, or the store failed to open): the file is
    ///     fine on disk, but the downloads view promises a fingerprint for
    ///     every finished download, so `download_record_failed` is emitted
    ///     with reason `store_unavailable` and the UI names the exception.
    ///     Note the store survives a vault LOCK by design (see `lock_vault`),
    ///     so "locked" alone does NOT land here — recording still happens.
    ///   * save failure: same event, reason `io` — otherwise the panel would
    ///     imply every download is fingerprinted when this one is not.
    ///
    /// Note: this hashes on the event-loop thread. Fine for typical
    /// downloads; a multi-GB file stalls the UI for seconds. The threaded
    /// fix needs one new `UserEvent` variant in main.rs (hash on a worker,
    /// post the result back, record here) — flagged for the reviewer rather
    /// than done blind, because main.rs was not in my context.
    pub fn record_download_provenance(&mut self, url: &str, path: Option<&str>, success: bool) {
        if !success {
            return;
        }
        let path = match path {
            Some(path) => path,
            None => return,
        };
        let filename = match Path::new(path).file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => return,
        };
        let (sha256, byte_len) = match hash_file(Path::new(path)) {
            Ok(result) => result,
            // The file vanished or became unreadable between completion and
            // hashing; there is nothing truthful left to record.
            Err(_) => return,
        };
        if self.store.is_none() {
            self.emit(
                "download_record_failed",
                json!({ "reason": "store_unavailable" }),
            );
            return;
        }
        let result = match self.store.as_mut() {
            Some(store) => store.record_download(url, &filename, byte_len, sha256),
            None => return, // unreachable: checked above
        };
        match result {
            Ok(_) => self.emit("downloads_changed", json!({})),
            // A save failure means the record is gone; the panel would
            // otherwise imply every download is fingerprinted.
            Err(_) => self.emit("download_record_failed", json!({ "reason": "io" })),
        }
    }

    fn set_active(&mut self, index: usize) {
        if index >= self.tabs.len() || index == self.active {
            return;
        }
        // Find sessions are per-tab: highlights must not stay lit on a tab
        // the user is leaving, and a count arriving late must find nothing
        // to describe. The chrome closes its bar off the url_changed this
        // switch emits below.
        if self.find.stop() {
            platform::find_stop(&self.tabs[self.active].webview);
        }
        platform::hide_tab(&self.tabs[self.active].view, &self.tabs[self.active].webview);
        self.active = index;
        platform::show_tab(&self.tabs[index].view, &self.tabs[index].webview);
        // A freshly shown Windows tab may have stale bounds (created hidden,
        // or hidden during a resize); re-apply geometry for it and chrome.
        self.relayout();
        let url = self.tabs[index].url.clone();
        self.emit("url_changed", json!({ "url": url }));
    }

    pub fn tab_list(&self) -> Value {
        let items: Vec<Value> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                json!({
                    "id": tab.id,
                    "url": tab.url,
                    "title": tab.title,
                    "active": i == self.active,
                })
            })
            .collect();
        json!({ "items": items })
    }

    pub fn emit_tabs_changed(&self) {
        let list = self.tab_list();
        self.emit("tabs_changed", list);
    }

    /// The active tab's webview, for engine reads that must go through the
    /// real page (never through evaluating script in it).
    pub fn active_webview(&self) -> Option<&WebView> {
        self.tabs.get(self.active).map(|tab| &tab.webview)
    }

    /// Per-tab refused-request totals for every OPEN tab, for the session
    /// receipt. The same per-tab source `tab_status` reads -- never a
    /// second ledger walk maintained for the receipt.
    pub fn live_blocked_totals(&self) -> impl Iterator<Item = u64> + '_ {
        self.tabs.iter().map(|tab| platform::blocked_total(&tab.view))
    }

    /// The ACTIVE tab's refused-request total ("on this page").
    pub fn active_blocked_total(&self) -> u64 {
        self.tabs
            .get(self.active)
            .map(|tab| platform::blocked_total(&tab.view))
            .unwrap_or(0)
    }

    /// Builds a tab under an explicit policy rather than the browser-wide one.
    /// A quarantine tab is the reason this exists: `ephemeral` and the initial
    /// JavaScript setting are fixed at construction, so they cannot be applied
    /// to a tab that already exists.
    pub fn new_tab_with_policy(
        &mut self,
        url: &str,
        switch: bool,
        policy: &platform::TabPolicy,
    ) -> Result<u64, &'static str> {
        let id = self.next_tab_id;
        let tab = build_tab(
            &self.hosts,
            &self.proxy,
            id,
            url,
            policy,
            self.permissions.clone(),
        )
        .map_err(|_| "tab_failed")?;
        // As in `new_tab`: the id is consumed only once the tab exists.
        self.next_tab_id += 1;
        let was_empty = self.tabs.is_empty();
        self.tabs.push(tab);
        if was_empty {
            self.active = 0;
            platform::show_tab(&self.tabs[0].view, &self.tabs[0].webview);
            self.relayout();
        } else if switch {
            let index = self.tabs.len() - 1;
            self.set_active(index);
        }
        self.emit_tabs_changed();
        Ok(id)
    }

    pub fn active_url(&self) -> String {
        self.tabs
            .get(self.active)
            .map(|tab| tab.url.clone())
            .unwrap_or_default()
    }

    // ---- navigation (always the active tab) ----------------------------------

    pub fn navigate(&mut self, url: &str) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.webview.load_url(url).map_err(|_| "io"),
            None => Err("not_found"),
        }
    }

    pub fn history_back(&mut self) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.history_back(),
            None => Ok(()),
        }
    }

    pub fn history_forward(&mut self) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.history_forward(),
            None => Ok(()),
        }
    }

    pub fn history_reload(&mut self) -> Result<(), &'static str> {
        match self.tabs.get_mut(self.active) {
            Some(tab) => tab.history_reload(),
            None => Ok(()),
        }
    }

    // ---- tab events (routed by tab id) ----------------------------------------

    pub fn on_url_changed(&mut self, id: u64, url: String) {
        let is_active = self.tabs.get(self.active).map(|t| t.id) == Some(id);
        let index = match self.tabs.iter().position(|tab| tab.id == id) {
            Some(index) => index,
            None => return, // late event from a closed tab
        };
        self.tabs[index].url = url.clone();
        self.tabs[index].record_history(url.clone());
        // The DOM state that produced any pending save offer for THIS tab is
        // gone the moment it navigates -- confirming it now would save under
        // whatever origin the tab happens to show next.
        self.clear_pending_save_for(id);
        // url_changed is emitted for the active tab only; the strip learns
        // about every URL change through tabs_changed.
        if index == self.active {
            self.emit("url_changed", json!({ "url": url }));
        }
        self.emit_tabs_changed();
            if is_active {
            self.emit_tab_status();
        }
    }

    pub fn on_title_changed(&mut self, id: u64, title: String) {
        if let Some(tab) = self.tabs.iter_mut().find(|tab| tab.id == id) {
            tab.title = title;
            self.emit_tabs_changed();
        }
    }

    /// The URL bar's loading indicator tracks the active tab only.
    pub fn on_load_state(&self, id: u64, loading: bool) {
        // Freeze phase and TLS state both change across a load, and the
        // banner that warns about an intercepted connection is driven from
        // here. Without this the whole per-tab feed was silent.
        if self.tabs.get(self.active).map(|t| t.id) == Some(id) {
            self.emit_tab_status();
        }
        if self.tabs.get(self.active).map(|tab| tab.id) == Some(id) {
            self.emit("load_state", json!({ "loading": loading }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{check_download_file_in, hash_file, sanitize_filename, FileVerdict};
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    #[test]
    fn unix_strips_separators_and_leading_dots() {
        assert_eq!(sanitize_filename("/etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_filename("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
        assert_eq!(sanitize_filename(""), "download");
    }

    #[cfg(windows)]
    #[test]
    fn windows_replaces_reserved_chars() {
        assert_eq!(sanitize_filename("report?.pdf"), "report_.pdf");
        assert_eq!(sanitize_filename("a\\b/c:d"), "a_b_c_d");
        // Trailing dots/spaces would be silently stripped by Win32.
        assert_eq!(sanitize_filename("file."), "file");
        assert_eq!(sanitize_filename("file "), "file");
    }

    #[cfg(windows)]
    #[test]
    fn windows_blocks_device_names() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("con.txt"), "_con.txt");
        assert_eq!(sanitize_filename("COM1"), "_COM1");
        assert_eq!(sanitize_filename("lpt9.png"), "_lpt9.png");
        assert_eq!(sanitize_filename("company.txt"), "company.txt");
        assert_eq!(sanitize_filename("..."), "download");
    }

    fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        let unique = format!(
            "patanyx-app-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn hash_file_matches_the_sha256_test_vector_for_abc() {
        let path = temp_file("abc", b"abc");
        let (hash, len) = hash_file(&path).unwrap();
        assert_eq!(len, 3);
        assert_eq!(
            hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_download_file_distinguishes_match_differs_and_missing() {
        let dir = std::env::temp_dir();
        let path = temp_file("content", b"some downloaded bytes");
        let filename = path.file_name().unwrap().to_str().unwrap().to_string();
        let (sha256, _) = hash_file(&path).unwrap();

        assert!(matches!(
            check_download_file_in(&dir, &filename, &sha256),
            FileVerdict::Match
        ));

        let mut wrong = sha256;
        wrong[0] ^= 0x01;
        assert!(matches!(
            check_download_file_in(&dir, &filename, &wrong),
            FileVerdict::Differs
        ));

        assert!(matches!(
            check_download_file_in(&dir, "definitely-not-here.bin", &sha256),
            FileVerdict::Missing
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn check_download_file_refuses_names_with_separators() {
        // A record's filename must be a bare file name; anything else is
        // rejected before the filesystem is followed anywhere.
        assert!(matches!(
            check_download_file_in(Path::new("/tmp"), "../escape", &[0u8; 32]),
            FileVerdict::Unreadable
        ));
        assert!(matches!(
            check_download_file_in(Path::new("/tmp"), "a/b", &[0u8; 32]),
            FileVerdict::Unreadable
        ));
        assert!(matches!(
            check_download_file_in(Path::new("/tmp"), "", &[0u8; 32]),
            FileVerdict::Unreadable
        ));
    }

    /// `diagnostics_snapshot` cannot be exercised end-to-end here: `AppState`
    /// needs a real `WebView`/`Hosts` pair, which needs a display this test
    /// runner does not have. So this checks the constraint the function's own
    /// doc states -- reading its SOURCE, the same way `every_error_code_has_
    /// user_facing_text` in ipc.rs checks a claim by scanning text rather
    /// than by constructing what would be needed to observe it directly.
    ///
    /// Deliberately conservative: fails if the substring appears ANYWHERE in
    /// the function body, not just in an obviously-dangerous position. A
    /// diagnostics export composing a field named `history`/`credential`/
    /// `password`/`browsing_url` is the exact class of scope-creep this
    /// guards against, whatever form adding it took.
    #[test]
    fn diagnostics_snapshot_never_names_a_forbidden_field() {
        let source = include_str!("state.rs");
        let start = source
            .find("pub fn diagnostics_snapshot(&self) -> Value {")
            .expect("diagnostics_snapshot not found; this test's anchor was renamed");
        let end = source[start..]
            .find("\n    }\n")
            .map(|i| start + i)
            .expect("diagnostics_snapshot has no terminator");
        let body = &source[start..end];

        // Non-vacuity: the function must actually have grown past a stub, or
        // this test would pass by examining nothing.
        assert!(
            body.len() > 100,
            "diagnostics_snapshot's body is suspiciously short ({} bytes) -- \
             check the anchors above still bound the real function",
            body.len()
        );

        for forbidden in [
            "history",
            "credential",
            "password",
            "browsing_url",
            "self.vault",
            "self.store",
            "\"url\"",
        ] {
            assert!(
                !body.to_ascii_lowercase().contains(&forbidden.to_ascii_lowercase()),
                "diagnostics_snapshot's body mentions \"{forbidden}\" -- the \
                 diagnostics export must never carry history, credentials, or \
                 vault content",
            );
        }
    }
}

#[cfg(test)]
mod permission_book_tests {
    use super::{normalize_origin, PermKind, PermissionBook};

    const SITE: &str = "https://example.com";
    const FRAME: &str = "https://ads.other.example";

    /// The whole premise. Nothing is allowed until a human allows it.
    #[test]
    fn everything_is_denied_before_anyone_grants_anything() {
        let book = PermissionBook::default();
        for kind in PermKind::ALL {
            assert!(!book.decide(SITE, SITE, kind), "{kind:?} must start denied");
        }
    }

    #[test]
    fn a_granted_origin_is_allowed_and_a_revoked_one_is_not() {
        let book = PermissionBook::default();
        assert!(book.grant(SITE, PermKind::Camera));
        assert!(book.decide(SITE, SITE, PermKind::Camera));
        // The grant is per KIND, never a blanket allow for the site.
        assert!(!book.decide(SITE, SITE, PermKind::Microphone));
        assert!(book.revoke(SITE, PermKind::Camera));
        assert!(!book.decide(SITE, SITE, PermKind::Camera));
    }

    /// A non-negotiable rule. Allowing the page must never hand
    /// the camera to an advertising iframe the page embeds.
    #[test]
    fn an_embedded_frame_does_not_inherit_the_pages_grant() {
        let book = PermissionBook::default();
        book.grant(SITE, PermKind::Camera);
        assert!(book.decide(SITE, SITE, PermKind::Camera));
        assert!(
            !book.decide(FRAME, SITE, PermKind::Camera),
            "a frame with its own origin must ask for itself"
        );
    }

    /// A frame's denial has to surface on the tab where it happened, or the
    /// user cannot allow it from the only context they have.
    #[test]
    fn a_frames_denial_is_visible_on_the_tab_it_happened_under() {
        let book = PermissionBook::default();
        book.decide(FRAME, SITE, PermKind::Camera);
        let rows = book.status_for(SITE);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.origin, FRAME);
        assert!(!rows[0].1, "it was denied");
        assert_eq!(rows[0].2, 1, "and counted");
    }

    /// A grant made under one site stays revocable from wherever it is active.
    #[test]
    fn an_active_frame_grant_stays_visible_for_revocation() {
        let book = PermissionBook::default();
        book.decide(FRAME, SITE, PermKind::Camera);
        book.grant(FRAME, PermKind::Camera);
        let rows = book.status_for(SITE);
        assert_eq!(rows.len(), 1, "still listed after being granted");
        assert!(rows[0].1, "now shown as granted");
    }

    #[test]
    fn repeated_denials_are_counted_not_duplicated() {
        let book = PermissionBook::default();
        for _ in 0..5 {
            book.decide(SITE, SITE, PermKind::Geolocation);
        }
        let rows = book.status_for(SITE);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, 5);
    }

    /// Page content picks these origins, so the table must not grow forever.
    #[test]
    fn the_denied_table_is_bounded_against_hostile_content() {
        let book = PermissionBook::default();
        for i in 0..2000 {
            book.decide(&format!("https://n{i}.attacker.example"), SITE, PermKind::Camera);
        }
        let rows = book.status_for(SITE);
        assert!(
            rows.len() <= super::MAX_DENIED_KEYS,
            "denied table grew to {} entries",
            rows.len()
        );
    }

    /// Opaque and malformed origins are not sites. Accepting them would let
    /// unrelated sandboxed documents share one grant.
    #[test]
    fn an_unusable_origin_can_never_be_granted() {
        let book = PermissionBook::default();
        for bad in [
            "null",
            "about:blank",
            "https://",
            "http://",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,x",
            "https://@",
            "https://:443",
            "https://exa mple.com",
            "https://..",
            "",
        ] {
            assert!(normalize_origin(bad).is_none(), "must reject {bad:?}");
            assert!(!book.grant(bad, PermKind::Camera), "must not grant {bad:?}");
            assert!(
                !book.decide(bad, SITE, PermKind::Camera),
                "must not allow {bad:?}"
            );
        }
    }

    /// Two spellings of one site must not need allowing twice.
    #[test]
    fn origins_normalise_so_one_grant_is_one_site() {
        let book = PermissionBook::default();
        book.grant("https://Example.COM:443/some/path?q=1#frag", PermKind::Camera);
        for spelling in [
            "https://example.com",
            "https://EXAMPLE.com",
            "https://example.com:443",
            "https://example.com/other/page",
        ] {
            assert!(
                book.decide(spelling, SITE, PermKind::Camera),
                "{spelling} is the same site"
            );
        }
        // A different port IS a different origin, and a different scheme too.
        assert!(!book.decide("https://example.com:8443", SITE, PermKind::Camera));
        assert!(!book.decide("http://example.com", SITE, PermKind::Camera));
    }

    /// Fail closed. A table that cannot be reached must not answer yes.
    #[test]
    fn a_poisoned_table_denies_rather_than_allowing() {
        let book = PermissionBook::default();
        book.grant(SITE, PermKind::Camera);
        assert!(book.decide(SITE, SITE, PermKind::Camera), "granted first");

        let poisoner = book.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.0.lock().unwrap();
            panic!("poison the mutex on purpose");
        })
        .join();

        assert!(
            !book.decide(SITE, SITE, PermKind::Camera),
            "an unreachable table must deny even a granted permission"
        );
        assert!(book.status_for(SITE).is_empty(), "and show nothing");
    }
}
