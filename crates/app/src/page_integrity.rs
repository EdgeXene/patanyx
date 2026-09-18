//! Page integrity & peer corroboration — app wiring for the `patanyx-integrity`
//! and `patanyx-corroborate` crates.
//!
//! Two features share one pipeline:
//!
//!   1. CHANGE DETECTION — snapshot a bookmarked page now, compare on a later
//!      visit: "this page has changed since you saved it, here is how much".
//!      The baseline digest lives in the bookmark store (see the BOOKMARKS
//!      SEAM note below); this module only fetches bytes, digests, compares.
//!   2. PEER CORROBORATION — ask a contact whether the server served them the
//!      same page. Requests/responses travel as text chat envelopes
//!      (hex-encoded `to_bytes()` — §4.4 forbids a binary payload path), and
//!      the peer's browser fetches NOTHING: it digests the copy it already
//!      has open.
//!
//! Both need the exact bytes the engine rendered. Those come from the
//! platform's main-resource API (see platform/unix.rs for why no other source
//! is honest) and NEVER from script evaluated in a content webview (§4.1).
//! Where the platform cannot provide bytes, every entry point refuses with
//! `unsupported` and the UI says so — a wrong digest is worse than no digest.
//!
//! Honesty contract for the UI (mirrors the corroborate crate's docs): a
//! verdict answers exactly "did the server treat these two viewers
//! differently?" It cannot vouch for content both saw identically, it is
//! meaningless on logged-in pages, it trusts the peer, and innocent
//! differences are common. chrome/integrity.js renders those caveats WITH
//! every verdict, not on a help page.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use patanyx_integrity::{compare, digest, ContentDigest, Verdict as IntegrityVerdict};

use crate::state::AppState;

// The panel script is not embedded here. This was a second `include_str!` of
// chrome/integrity.js claiming "ipc.rs evaluates it into the chrome webview on
// the first ping" -- a mechanism that is real (chat.js uses it) but was not
// this file's. index.html loads integrity.js with a script tag and main.rs
// serves it, so this copy was dead weight the compiler had been flagging.

// ---------------------------------------------------------------------------
// Events from the platform layer
// ---------------------------------------------------------------------------

/// Why the engine could not hand over the main-resource bytes. Mapped to IPC
/// codes by `bytes_error_code`; the UI copy for `no_page` names the common
/// cause (page still loading).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageBytesError {
    /// No SERVER document at all: about:blank, or the tab is showing the
    /// adlist placeholder this binary loaded in place of a refused page
    /// (both platforms exclude it; Windows by response nonce, Linux by
    /// byte identity).
    NoMainResource,
    /// Resource exceeded patanyx-integrity's input cap.
    TooLarge,
    /// The async read failed — usually because the page is still loading.
    FetchFailed,
}

/// Carried by `UserEvent::Integrity` (variant added in main.rs — see the
/// integration note in this module's Note block at the bottom).
#[derive(Debug)]
pub enum IntegrityEvent {
    PageBytes {
        token: u64,
        result: Result<Vec<u8>, PageBytesError>,
    },
}

fn bytes_error_code(error: &PageBytesError) -> &'static str {
    match error {
        PageBytesError::NoMainResource | PageBytesError::FetchFailed => "no_page",
        PageBytesError::TooLarge => "too_long",
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// What a pending byte-fetch is for. The token ties the async platform
/// callback back to the request that started it; a token whose purpose is
/// gone (vault locked, transport down) is dropped silently.
enum Pending {
    Check {
        url: String,
        baseline: ContentDigest,
        baseline_fetched_at: u64,
        baseline_text: Option<String>,
        baseline_text_trimmed: bool,
        target: CheckTarget,
    },
    MarkSeen {
        url: String,
        bookmark_id: String,
    },
    /// One tab's byte read for the live cross-tab scan. No url is captured:
    /// the snapshot joins rows with live tab titles/urls at emit time, so
    /// there is nothing here to go stale. `scan` is the TabScan id the read
    /// was issued under; TabScan::record refuses an answer quoting any
    /// other scan, which is what lets a scan be replaced or dropped without
    /// cancelling reads one by one.
    TabSearch { tab_id: u64, scan: u64 },
    #[cfg(feature = "chat")]
    CorroborateBegin {
        peer_hash: String,
        contact_id: Option<String>,
        url: String,
    },
    #[cfg(feature = "chat")]
    CorroborateRespond {
        peer_hash: String,
        contact_id: Option<String>,
        own_url: String,
        request: patanyx_corroborate::CompareRequest,
    },
    /// Change Cross-Check, asking side: reading OUR page now, so the
    /// request can carry both what we saved and what we see.
    #[cfg(feature = "chat")]
    ChangeBegin {
        peer_hash: String,
        contact_id: Option<String>,
        url: String,
        baseline: ContentDigest,
        baseline_recorded_at: u64,
    },
    /// Change Cross-Check, answering side: reading OUR page now, so the
    /// answer can say whether it changed for us.
    #[cfg(feature = "chat")]
    ChangeRespond {
        peer_hash: String,
        contact_id: Option<String>,
        request: patanyx_corroborate::ChangeCompareRequest,
        /// Absent when we have no bookmark for that address. The answer is
        /// still worth sending: a current reading with no baseline says
        /// what we see now, which is half the matrix.
        baseline: Option<ContentDigest>,
        baseline_recorded_at: Option<u64>,
    },
}

#[derive(Clone)]
enum CheckTarget {
    Active,
    Bookmark {
        bookmark_id: String,
        snapshot_id: String,
        temporary_tab_id: Option<u64>,
    },
}

impl CheckTarget {
    fn temporary_tab_id(&self) -> Option<u64> {
        match self {
            CheckTarget::Bookmark {
                temporary_tab_id, ..
            } => *temporary_tab_id,
            CheckTarget::Active => None,
        }
    }
}

#[cfg(feature = "chat")]
impl Pending {
    fn is_corroboration(&self) -> bool {
        matches!(
            self,
            Pending::CorroborateBegin { .. }
                | Pending::CorroborateRespond { .. }
                | Pending::ChangeBegin { .. }
                | Pending::ChangeRespond { .. }
        )
    }
}

pub struct IntegrityState {
    next_token: u64,
    pending: HashMap<u64, Pending>,
    /// Bookmark-row checks whose temporary background tab is still loading,
    /// keyed by that tab id. They move into `pending` only after LoadFinished.
    waiting_checks: HashMap<u64, Pending>,
    /// Hashes/text waiting for the native page capture that will optionally
    /// accompany them. One slot matches capture::CAPTURE_IN_FLIGHT: a second
    /// snapshot may save without a picture, but can never replace this one.
    snapshot_capture: Option<SnapshotDraft>,
    /// Requests WE sent, keyed by peer hash, so a reply can be turned into a
    /// verdict. Memory only: nothing is stored, so a locked vault or a
    /// restarted app simply forgets a comparison was ever asked.
    #[cfg(feature = "chat")]
    pending_corroborations: HashMap<String, patanyx_corroborate::CompareRequest>,
    /// Change Cross-Check requests we sent, same shape and same lifetime as
    /// the map above. Separate rather than merged: an answer to one kind of
    /// question must never be matched against the other.
    #[cfg(feature = "chat")]
    pending_changes: HashMap<String, patanyx_corroborate::ChangeCompareRequest>,
}

impl Default for IntegrityState {
    fn default() -> Self {
        Self {
            next_token: 0,
            pending: HashMap::new(),
            waiting_checks: HashMap::new(),
            snapshot_capture: None,
            #[cfg(feature = "chat")]
            pending_corroborations: HashMap::new(),
            #[cfg(feature = "chat")]
            pending_changes: HashMap::new(),
        }
    }
}

struct SnapshotDraft {
    url: String,
    bookmark_id: String,
    digest: ContentDigest,
    visible_text: String,
    fetched_at: u64,
}

impl IntegrityState {
    fn issue(&mut self, purpose: Pending) -> u64 {
        self.next_token += 1;
        let token = self.next_token;
        self.pending.insert(token, purpose);
        token
    }
}

// ---------------------------------------------------------------------------
// BOOKMARKS SEAM — Note (read first)
//
// Change detection stores its baseline INSIDE the bookmark store: the
// bookmarks brief owns that storage (`mark_seen` / `check` live there), and
// neither state.rs nor the store crate was in this drafter's context. Every
// assumption is isolated in the three functions below; reconcile their
// bodies with the landed bookmarks API and leave the rest of this module
// untouched. Assumed minimal surface on `state.bookmarks`:
//
//   fn find_by_url(&self, url: &str) -> Option<Bookmark-ish>;
//   Bookmark { id: String, digest_json: Option<String>, digest_fetched_at: u64 }
//   fn set_digest(&mut self, id: &str, digest_json: &str, fetched_at: u64) -> Result<_, _>;
//
// The digest round-trips through JSON losslessly (proved by
// patanyx-integrity's digest_survives_serde_roundtrip).
// ---------------------------------------------------------------------------

// Reconciled against the store API as landed: bookmarks live in the encrypted
// `patanyx-store`, which holds the digest as a typed `RecordedDigest` rather
// than JSON, so no serialization happens at this seam at all.
fn bookmark_id_for(state: &AppState, url: &str) -> Option<String> {
    let store = state.store.as_ref()?;
    store
        .bookmarks()
        .iter()
        .find(|b| b.url == url)
        .map(|b| b.id.clone())
}

fn stored_snapshot(state: &AppState, url: &str) -> Option<(String, ContentDigest, u64)> {
    let store = state.store.as_ref()?;
    let bookmark = store.bookmarks().iter().find(|b| b.url == url)?;
    let recorded = store.page_snapshot_for(&bookmark.id, None).ok()??;
    Some((bookmark.id.clone(), recorded.digest, recorded.recorded_at))
}

fn save_snapshot(
    state: &mut AppState,
    bookmark_id: &str,
    digest: &ContentDigest,
    visible_text: &str,
    picture: Option<(&[u8], &'static str)>,
) -> Result<patanyx_store::PageSnapshot, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let store = state.store.as_mut().ok_or("not_unlocked")?;
    match picture {
        Some((png, scope)) => store.save_page_snapshot_with_picture(
            bookmark_id,
            digest.clone(),
            visible_text,
            png,
            scope,
        ),
        None => store.save_page_snapshot(bookmark_id, digest.clone(), visible_text),
    }
    .map_err(|_| "io")
}

// ---------------------------------------------------------------------------
// TAB ACCESSORS — Note
//
// state.rs and the tab struct were not in this drafter's context. Assumed:
// `state.active_webview() -> Option<&wry::WebView>` (one-line accessor next
// to active_url()) and tabs iterable as `state.tabs` with `url` / `webview`
// fields. Adjust these two helpers to the real shapes; nothing else in the
// module knows them.
// ---------------------------------------------------------------------------

fn active_webview(state: &AppState) -> Option<&wry::WebView> {
    state.active_webview()
}

#[cfg(feature = "chat")]
fn tab_url_for_normalized(state: &AppState, want_normalized: &str) -> Option<String> {
    state.tabs.iter().find_map(|tab| {
        // Note: `tab.url` field name assumed.
        let typed: &str = tab.url.as_str();
        match patanyx_corroborate::normalize_url(typed) {
            Ok(n) if n.as_str() == want_normalized => Some(typed.to_string()),
            _ => None,
        }
    })
}

fn tab_webview_for_url<'a>(state: &'a AppState, typed_url: &str) -> Option<&'a wry::WebView> {
    // Note: `tab.url` / `tab.webview` field names assumed.
    state
        .tabs
        .iter()
        .find(|tab| tab.url == typed_url)
        .map(|tab| &tab.webview)
}

// ---------------------------------------------------------------------------
// Fetch kick-off shared by all entry points
// ---------------------------------------------------------------------------

/// Gate on the platform capability, register the purpose, and ask the engine
/// for the ACTIVE tab's main-resource bytes. The capability check lives here
/// (not in each caller) so no path can forget it: where bytes are not
/// honestly obtainable the answer is `unsupported`, never a guess.
fn begin_fetch_for_active(state: &mut AppState, purpose: Pending) -> Result<(), &'static str> {
    if !crate::platform::page_bytes_supported() {
        return Err("unsupported");
    }
    if active_webview(state).is_none() {
        return Err("no_page");
    }
    let token = state.integrity.issue(purpose);
    let proxy = state.proxy();
    if let Some(webview) = active_webview(state) {
        crate::platform::request_main_resource_bytes(webview, token, &proxy);
    }
    Ok(())
}

/// Register one tab of the live cross-tab scan for a byte read and return
/// the token the caller hands to `request_main_resource_bytes`. This is the
/// per-tab half of begin_fetch_for_active's issue-and-ask, for tabs that
/// are not the active one; it lives here because `Pending` and the token
/// registry are this module's own, and a second token space answering the
/// same platform callback is how tokens get routed to the wrong owner. The
/// capability gate stays in the find_tabs_search arm: one "unsupported"
/// refusal up front, not N per-tab surprises half-way through issuing.
pub fn issue_tab_search_fetch(state: &mut AppState, tab_id: u64, scan: u64) -> u64 {
    state.integrity.issue(Pending::TabSearch { tab_id, scan })
}

/// The corroborate crate deliberately never reads a clock; the app supplies
/// unix seconds at CAPTURE time.
///
/// Note: this is when we read the bytes, which for a page loaded an
/// hour ago is later than the true fetch time — so `fetch_gap_seconds` can
/// understate how far apart the two SERVINGS were. Recording each tab's last
/// navigation wall-time would fix it; listed under Proposed enhancements.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn emit_op_error(state: &AppState, op: &'static str, code: &'static str) {
    state.emit("page_integrity_error", json!({ "op": op, "code": code }));
}

// ---------------------------------------------------------------------------
// IPC handlers (dispatched from ipc.rs)
// ---------------------------------------------------------------------------

/// `integrity_status` — capability flags travel with the values so the UI
/// can disable and EXPLAIN a control the platform cannot honour, exactly
/// like `network_blocking_supported`.
pub fn ipc_status(state: &mut AppState) -> Result<Value, &'static str> {
    let snapshots = if state.vault.is_some() {
        bookmark_id_for(state, &state.active_url())
            .and_then(|id| state.store.as_ref()?.page_snapshots_for(&id).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|snapshot| {
                json!({
                    "id": snapshot.id,
                    "recorded_at": snapshot.recorded_at,
                    "text_available": snapshot.text.is_some(),
                    "text_trimmed": snapshot.text_trimmed,
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    Ok(json!({
        "supported": crate::platform::page_bytes_supported(),
        "chat": cfg!(feature = "chat"),
        "active_url": state.active_url(),
        "snapshots": snapshots,
    }))
}

/// `integrity_check` — compare the active page against the snapshot stored
/// with its bookmark. The verdict arrives as a `page_check_result` event.
pub fn ipc_check(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let url = state.active_url();
    // Two distinct refusals, because the user-facing next step differs:
    // bookmark the page vs. save a snapshot for a bookmark that has none.
    bookmark_id_for(state, &url).ok_or("not_bookmarked")?;
    let bookmark_id = bookmark_id_for(state, &url).ok_or("not_bookmarked")?;
    let selected = args.get("snapshot_id").and_then(Value::as_str);
    let snapshot = state
        .store
        .as_ref()
        .ok_or("not_unlocked")?
        .page_snapshot_for(&bookmark_id, selected)
        .map_err(|_| "io")?
        .ok_or("no_snapshot")?;
    begin_fetch_for_active(
        state,
        Pending::Check {
            url,
            baseline: snapshot.digest,
            baseline_fetched_at: snapshot.recorded_at,
            baseline_text: snapshot.text,
            baseline_text_trimmed: snapshot.text_trimmed,
            target: CheckTarget::Active,
        },
    )?;
    Ok(json!({}))
}

/// `integrity_check_bookmark` — the Library-row entry point. It resolves the
/// bookmark and chosen baseline through the unlocked encrypted store, then
/// reads engine-received bytes from an already loaded tab at that exact URL.
/// It never re-fetches with a second HTTP stack and never injects script.
pub fn ipc_check_bookmark(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let bookmark_id = args
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("not_bookmarked")?
        .to_string();
    let selected = args.get("snapshot_id").and_then(Value::as_str);
    let (url, snapshot) = resolve_bookmark_target(
        state.store.as_ref().ok_or("not_unlocked")?,
        &bookmark_id,
        selected,
    )?;
    if !crate::platform::page_bytes_supported() {
        return Err("unsupported");
    }
    if tab_webview_for_url(state, &url).is_some() {
        let target = CheckTarget::Bookmark {
            bookmark_id,
            snapshot_id: snapshot.id.clone(),
            temporary_tab_id: None,
        };
        let token = state.integrity.issue(Pending::Check {
            url: url.clone(),
            baseline: snapshot.digest,
            baseline_fetched_at: snapshot.recorded_at,
            baseline_text: snapshot.text,
            baseline_text_trimmed: snapshot.text_trimmed,
            target,
        });
        let proxy = state.proxy();
        let webview = tab_webview_for_url(state, &url).ok_or("fetch_failed")?;
        crate::platform::request_main_resource_bytes(webview, token, &proxy);
    } else {
        if !crate::state::is_allowed_content_url(&url) {
            return Err("fetch_failed");
        }
        if state.tabs.len() >= crate::state::MAX_TABS {
            return Err("fetch_failed");
        }
        let tab_id = state.new_tab(&url, false).map_err(|_| "fetch_failed")?;
        state.integrity.waiting_checks.insert(
            tab_id,
            Pending::Check {
                url,
                baseline: snapshot.digest,
                baseline_fetched_at: snapshot.recorded_at,
                baseline_text: snapshot.text,
                baseline_text_trimmed: snapshot.text_trimmed,
                target: CheckTarget::Bookmark {
                    bookmark_id,
                    snapshot_id: snapshot.id,
                    temporary_tab_id: Some(tab_id),
                },
            },
        );
    }
    Ok(json!({}))
}

/// Continue a Library check after its temporary engine tab finishes loading.
/// This is the same byte source active-tab comparison uses; the temporary tab
/// merely gives the bookmark URL an engine-owned main resource to read.
pub fn on_tab_load_state(state: &mut AppState, tab_id: u64, loading: bool) {
    if loading {
        return;
    }
    let Some(purpose) = state.integrity.waiting_checks.remove(&tab_id) else {
        return;
    };
    if state.vault.is_none() {
        let _ = state.close_tab(tab_id);
        return;
    }
    let target = match &purpose {
        Pending::Check { target, .. } => target.clone(),
        _ => return,
    };
    if !state.tabs.iter().any(|tab| tab.id == tab_id) {
        emit_check_error(state, &target, "fetch_failed");
        return;
    }
    let token = state.integrity.issue(purpose);
    let proxy = state.proxy();
    let Some(webview) = state
        .tabs
        .iter()
        .find(|tab| tab.id == tab_id)
        .map(|tab| &tab.webview)
    else {
        state.integrity.pending.remove(&token);
        emit_check_error(state, &target, "fetch_failed");
        return;
    };
    crate::platform::request_main_resource_bytes(webview, token, &proxy);
}

pub fn on_tab_closed(state: &mut AppState, tab_id: u64) {
    let mut interrupted = Vec::new();
    if let Some(Pending::Check { target, .. }) = state.integrity.waiting_checks.remove(&tab_id) {
        interrupted.push(target);
    }
    state.integrity.pending.retain(|_, purpose| {
        if let Pending::Check { target, .. } = purpose {
            if target.temporary_tab_id() == Some(tab_id) {
                interrupted.push(target.clone());
                return false;
            }
        }
        true
    });
    for target in interrupted {
        emit_check_error(state, &target, "fetch_failed");
    }
}

fn resolve_bookmark_target(
    store: &patanyx_store::Store,
    bookmark_id: &str,
    snapshot_id: Option<&str>,
) -> Result<(String, patanyx_store::PageSnapshot), &'static str> {
    let bookmark = store
        .get_bookmark(bookmark_id)
        .ok_or("not_bookmarked")?;
    let snapshot = store
        .page_snapshot_for(bookmark_id, snapshot_id)
        .map_err(|_| "io")?
        .ok_or("no_snapshot")?;
    Ok((bookmark.url.clone(), snapshot))
}

/// `integrity_mark_seen` — digest the active page and store the result as
/// the bookmark's baseline ("this is what I saw"). Confirmed by a
/// `page_marked_seen` event.
pub fn ipc_mark_seen(state: &mut AppState) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let url = state.active_url();
    let bookmark_id = bookmark_id_for(state, &url).ok_or("not_bookmarked")?;
    begin_fetch_for_active(state, Pending::MarkSeen { url, bookmark_id })?;
    Ok(json!({}))
}

/// `corroborate_request` — ask one contact to compare what they were served.
/// The request goes out only after our own bytes arrive; the verdict arrives
/// as a `corroborate_verdict` event on BOTH sides.
#[cfg(feature = "chat")]
pub fn ipc_corroborate_request(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let peer_hash = crate::chat_panel::resolve_peer_hash(state, args)?;
    let contact_id = args
        .get("contact_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let url = state.active_url();
    // Corroboration is for public web pages; refuse about:blank & co up
    // front rather than after the async read.
    if patanyx_corroborate::normalize_url(&url).is_err() {
        return Err("bad_args");
    }
    begin_fetch_for_active(
        state,
        Pending::CorroborateBegin {
            peer_hash,
            contact_id,
            url,
        },
    )?;
    Ok(json!({}))
}

/// Fold one tab's byte read into the live cross-tab scan and re-emit the
/// snapshot when a row changed. Every refusal is a quiet no-op, each for a
/// reason: a token whose scan is gone (replaced by a newer search, dropped
/// by the vault lock) meets no scan; an answer quoting a REPLACED scan's id
/// is refused by TabScan::record even when the live scan covers the same
/// tab -- without that, bytes captured under the old scan (or a pre-lock
/// licence session) would be presented as the tab's current content.
fn finish_tab_search_row(
    state: &mut AppState,
    tab_id: u64,
    scan_id: u64,
    result: Result<Vec<u8>, PageBytesError>,
) {
    let changed = {
        let Some(scan) = state.tab_scan.as_mut() else {
            return;
        };
        let row = match &result {
            Ok(bytes) => match patanyx_integrity::visible_text(bytes) {
                Ok(text) => crate::tab_search::ScanRow::Done(crate::tab_search::find_snippets(
                    &text,
                    scan.query(),
                )),
                // visible_text's only error is its input cap (the enum has
                // one variant); the reason key is the one the byte-level
                // TooLarge already uses, so the wording stays single-authored.
                Err(patanyx_integrity::IntegrityError::InputTooLarge { .. }) => {
                    crate::tab_search::ScanRow::Unsearchable("too_large")
                }
            },
            // The keys come from tab_search's own mapping, so the wording
            // stays single-authored in reason_copy.
            Err(e) => crate::tab_search::ScanRow::Unsearchable(
                crate::tab_search::unsearchable_reason(Some(&Err(*e)))
                    .expect("every PageBytesError maps to a reason key"),
            ),
        };
        scan.record(scan_id, tab_id, row)
    };
    // No change means a stale scan id, a late duplicate or an unknown tab:
    // nothing to repaint. When the scan completes there is nothing further
    // to do -- the snapshot carries the `scanning` flag.
    if changed {
        state.emit_tab_scan_state();
    }
}

// ---------------------------------------------------------------------------
// Event handling (UserEvent::Integrity dispatch from main.rs)
// ---------------------------------------------------------------------------

pub fn handle_event(state: &mut AppState, event: IntegrityEvent) {
    match event {
        IntegrityEvent::PageBytes { token, result } => {
            let Some(purpose) = state.integrity.pending.remove(&token) else {
                // Purpose died while the read was in flight (vault locked,
                // transport down). Nothing to do, nothing to leak.
                return;
            };
            match purpose {
                Pending::Check {
                    url,
                    baseline,
                    baseline_fetched_at,
                    baseline_text,
                    baseline_text_trimmed,
                    target,
                } => finish_check(
                    state,
                    url,
                    baseline,
                    baseline_fetched_at,
                    baseline_text,
                    baseline_text_trimmed,
                    target,
                    result,
                ),
                Pending::MarkSeen { url, bookmark_id } => {
                    finish_mark_seen(state, url, bookmark_id, result)
                }
                Pending::TabSearch { tab_id, scan } => {
                    finish_tab_search_row(state, tab_id, scan, result)
                }
                #[cfg(feature = "chat")]
                Pending::CorroborateBegin {
                    peer_hash,
                    contact_id,
                    url,
                } => finish_corroborate_begin(state, peer_hash, contact_id, url, result),
                #[cfg(feature = "chat")]
                Pending::CorroborateRespond {
                    peer_hash,
                    contact_id,
                    own_url,
                    request,
                } => finish_corroborate_respond(state, peer_hash, contact_id, own_url, request, result),
                #[cfg(feature = "chat")]
                Pending::ChangeBegin {
                    peer_hash,
                    contact_id,
                    url,
                    baseline,
                    baseline_recorded_at,
                } => finish_change_begin(
                    state,
                    peer_hash,
                    contact_id,
                    url,
                    baseline,
                    baseline_recorded_at,
                    result,
                ),
                #[cfg(feature = "chat")]
                Pending::ChangeRespond {
                    peer_hash,
                    contact_id,
                    request,
                    baseline,
                    baseline_recorded_at,
                } => finish_change_respond(
                    state,
                    peer_hash,
                    contact_id,
                    request,
                    baseline,
                    baseline_recorded_at,
                    result,
                ),
            }
        }
    }
}

fn finish_check(
    state: &mut AppState,
    url: String,
    baseline: ContentDigest,
    baseline_fetched_at: u64,
    baseline_text: Option<String>,
    baseline_text_trimmed: bool,
    target: CheckTarget,
    result: Result<Vec<u8>, PageBytesError>,
) {
    if let Some(tab_id) = target.temporary_tab_id() {
        let _ = state.close_tab(tab_id);
    }
    // Snapshot text is vault data. A lock between the click and the engine's
    // asynchronous answer turns the answer into a quiet drop: no diff and no
    // stored passage is emitted into the locked chrome document.
    if state.vault.is_none() {
        return;
    }
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(e) => {
            return emit_check_error(
                state,
                &target,
                match &target {
                    CheckTarget::Active => bytes_error_code(&e),
                    CheckTarget::Bookmark { .. } => "fetch_failed",
                },
            )
        }
    };
    // digest() fails only on oversize input, and the platform layer already
    // caps at the same limit — this is defence in depth, not a live path.
    let fresh = match digest(&bytes) {
        Ok(fresh) => fresh,
        Err(_) => return emit_check_error(state, &target, "too_long"),
    };
    let fresh_text = match patanyx_integrity::visible_text(&bytes) {
        Ok(text) => text,
        Err(_) => return emit_check_error(state, &target, "too_long"),
    };
    let (verdict, similarity) = match compare(&baseline, &fresh) {
        IntegrityVerdict::Identical => ("identical", None),
        IntegrityVerdict::StructureDiffers => ("structure_differs", None),
        IntegrityVerdict::TextDiffers { similarity } => ("text_differs", Some(similarity)),
    };
    let evidence = text_evidence(
        baseline_text.as_deref(),
        baseline_text_trimmed,
        &fresh_text,
    );
    let mut payload = json!({
        "url": url,
        "verdict": verdict,
        "similarity": similarity,
        "baseline_fetched_at": baseline_fetched_at,
        "checked_at": now_secs(),
        "text_comparison": evidence,
    });
    match target {
        CheckTarget::Active => state.emit("page_check_result", payload),
        CheckTarget::Bookmark {
            bookmark_id,
            snapshot_id,
            ..
        } => {
            payload["bookmark_id"] = json!(bookmark_id);
            payload["snapshot_id"] = json!(snapshot_id);
            state.emit("bookmark_check_result", payload);
        }
    }
}

fn emit_check_error(state: &AppState, target: &CheckTarget, code: &'static str) {
    match target {
        CheckTarget::Active => emit_op_error(state, "check", code),
        CheckTarget::Bookmark {
            bookmark_id,
            snapshot_id,
            ..
        } => state.emit(
            "bookmark_check_error",
            json!({
                "bookmark_id": bookmark_id,
                "snapshot_id": snapshot_id,
                "code": code,
            }),
        ),
    }
}

const MAX_DIFF_PASSAGES: usize = 20;
const MAX_DIFF_PASSAGE_CHARS: usize = 500;

/// Human-sized sentence passages. Visible text is whitespace-normalized by
/// the integrity crate, so line boundaries no longer exist; sentence
/// boundaries are the least noisy honest granularity. Very long/no-punctuation
/// runs are split every 40 words to keep one passage from becoming a wall.
fn passages(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    let mut current = String::new();
    let mut words = 0usize;
    for word in text.split_whitespace() {
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
        words += 1;
        let sentence_end = word
            .chars()
            .last()
            .is_some_and(|ch| matches!(ch, '.' | '!' | '?'));
        if sentence_end || words >= 40 {
            sentences.push(std::mem::take(&mut current));
            words = 0;
        }
    }
    if !current.is_empty() {
        sentences.push(current);
    }
    sentences
}

fn multiset_difference(left: &[String], right: &[String]) -> Vec<String> {
    let mut counts = std::collections::HashMap::<&str, usize>::new();
    for passage in right {
        *counts.entry(passage.as_str()).or_default() += 1;
    }
    let mut difference = Vec::new();
    for passage in left {
        match counts.get_mut(passage.as_str()) {
            Some(remaining) if *remaining > 0 => *remaining -= 1,
            _ => difference.push(passage.clone()),
        }
    }
    difference
}

fn bounded_passages(passages: Vec<String>, max: usize, trimmed: &mut bool) -> Vec<String> {
    if passages.len() > max {
        *trimmed = true;
    }
    passages
        .into_iter()
        .take(max)
        .map(|passage| {
            if passage.chars().count() > MAX_DIFF_PASSAGE_CHARS {
                *trimmed = true;
                passage.chars().take(MAX_DIFF_PASSAGE_CHARS).collect()
            } else {
                passage
            }
        })
        .collect()
}

fn text_evidence(saved: Option<&str>, saved_text_trimmed: bool, fresh: &str) -> Value {
    let Some(saved) = saved else {
        return json!({ "available": false });
    };
    let saved_passages = passages(saved);
    let fresh_capped: String = fresh
        .chars()
        .take(patanyx_store::SNAPSHOT_TEXT_MAX_CHARS)
        .collect();
    let fresh_text_trimmed = fresh.chars().count() > patanyx_store::SNAPSHOT_TEXT_MAX_CHARS;
    let fresh_passages = passages(&fresh_capped);
    let removed_all = multiset_difference(&saved_passages, &fresh_passages);
    let added_all = multiset_difference(&fresh_passages, &saved_passages);
    let both = !removed_all.is_empty() && !added_all.is_empty();
    let removed_max = if both {
        MAX_DIFF_PASSAGES / 2
    } else {
        MAX_DIFF_PASSAGES
    };
    let added_max = if both {
        MAX_DIFF_PASSAGES - removed_max
    } else {
        MAX_DIFF_PASSAGES
    };
    let mut output_trimmed = false;
    let removed = bounded_passages(removed_all, removed_max, &mut output_trimmed);
    let added = bounded_passages(added_all, added_max, &mut output_trimmed);
    json!({
        "available": true,
        "removed": removed,
        "added": added,
        "output_trimmed": output_trimmed,
        "saved_text_trimmed": saved_text_trimmed,
        "current_text_trimmed": fresh_text_trimmed,
    })
}

fn finish_mark_seen(
    state: &mut AppState,
    url: String,
    bookmark_id: String,
    result: Result<Vec<u8>, PageBytesError>,
) {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(e) => return emit_op_error(state, "mark_seen", bytes_error_code(&e)),
    };
    let digest = match digest(&bytes) {
        Ok(digest) => digest,
        Err(_) => return emit_op_error(state, "mark_seen", "too_long"),
    };
    let visible_text = match patanyx_integrity::visible_text(&bytes) {
        Ok(text) => text,
        Err(_) => return emit_op_error(state, "mark_seen", "too_long"),
    };
    let draft = SnapshotDraft {
        url,
        bookmark_id,
        digest,
        visible_text,
        fetched_at: now_secs(),
    };

    // The integrity evidence is ready before the optional picture. If the
    // shared capture slot is busy, the tab moved, or there is no capturable
    // webview, commit that evidence immediately and report the picture as
    // unavailable instead of turning an image issue into lost change data.
    let capturable = state.active_url() == draft.url
        && crate::capture::refuse_capture(&draft.url).is_none()
        && state.active_webview().is_some();
    if !capturable
        || crate::capture::CAPTURE_IN_FLIGHT.swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        commit_snapshot(state, draft, None);
        return;
    }
    state.capture_intent = crate::capture::CaptureIntent::Snapshot;
    let scope = crate::prefs::load().capture_scope.capture_scope();
    state.integrity.snapshot_capture = Some(draft);
    // `capturable` proved this exists and the active URL has not changed.
    let webview = state.active_webview().expect("capturable webview");
    crate::platform::capture_page(webview, &state.proxy(), scope);
}

fn commit_snapshot(
    state: &mut AppState,
    draft: SnapshotDraft,
    picture: Option<(&[u8], crate::capture::CaptureScope)>,
) {
    // A lock between either engine answer and this commit destroys the draft
    // rather than writing or emitting vault data behind the gate.
    if state.vault.is_none() {
        return;
    }
    let stored = save_snapshot(
        state,
        &draft.bookmark_id,
        &draft.digest,
        &draft.visible_text,
        picture.map(|(png, scope)| (png, crate::capture::scope_label(scope))),
    );
    match stored {
        Ok(snapshot) => state.emit(
            "page_marked_seen",
            json!({
                "url": draft.url,
                "fetched_at": draft.fetched_at,
                "picture_available": snapshot.has_picture,
                "picture_scope": snapshot.picture_scope,
            }),
        ),
        Err(code) => emit_op_error(state, "mark_seen", code),
    }
}

/// Finish the optional picture half of a snapshot. `None` covers capture,
/// validation, and WP-Z bounding failures; all take the same non-fatal path.
pub fn finish_snapshot_picture(
    state: &mut AppState,
    result: Result<Vec<u8>, &'static str>,
    scope: crate::capture::CaptureScope,
) {
    crate::capture::CAPTURE_IN_FLIGHT.store(false, std::sync::atomic::Ordering::SeqCst);
    let Some(draft) = state.integrity.snapshot_capture.take() else {
        return;
    };
    commit_snapshot(state, draft, result.ok().as_deref().map(|png| (png, scope)));
}

// ---------------------------------------------------------------------------
// Corroboration (chat builds only)
// ---------------------------------------------------------------------------

#[cfg(feature = "chat")]
fn finish_corroborate_begin(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    url: String,
    result: Result<Vec<u8>, PageBytesError>,
) {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(e) => return emit_op_error(state, "corroborate", bytes_error_code(&e)),
    };
    let request = match patanyx_corroborate::begin_comparison(&url, &bytes, now_secs()) {
        Ok(request) => request,
        Err(patanyx_corroborate::CorroborateError::Integrity(_)) => {
            return emit_op_error(state, "corroborate", "too_long")
        }
        Err(_) => return emit_op_error(state, "corroborate", "bad_args"),
    };
    let data = match request.to_bytes() {
        Ok(bytes) => hex_encode(&bytes),
        Err(_) => return emit_op_error(state, "corroborate", "io"),
    };
    let payload = crate::chat_panel::ChatPayload::CorroborateRequest {
        url: request.url.clone(),
        data,
    };
    state
        .integrity
        .pending_corroborations
        .insert(peer_hash.clone(), request);
    if let Err(code) = crate::chat_panel::send_payload(state, &peer_hash, &payload) {
        state.integrity.pending_corroborations.remove(&peer_hash);
        state.emit(
            "corroborate_note",
            json!({ "peer_hash": peer_hash, "contact_id": contact_id, "local": true, "reason": code }),
        );
    } else {
        state.emit(
            "corroborate_status",
            json!({ "peer_hash": peer_hash, "contact_id": contact_id, "state": "sent" }),
        );
    }
}

#[cfg(feature = "chat")]
fn finish_corroborate_respond(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    own_url: String,
    request: patanyx_corroborate::CompareRequest,
    result: Result<Vec<u8>, PageBytesError>,
) {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(e) => {
            // Tell the peer honestly that nothing was compared, and tell our
            // own user why their side stayed silent.
            send_note(state, &peer_hash, bytes_error_code(&e));
            return emit_op_error(state, "corroborate", bytes_error_code(&e));
        }
    };
    let response = match patanyx_corroborate::respond(&request, &own_url, &bytes, now_secs()) {
        Ok(response) => response,
        Err(patanyx_corroborate::CorroborateError::UrlMismatch { .. }) => {
            // Should not happen (tabs were matched on normalized URL), but
            // comparing two different pages produces garbage, not insight —
            // refuse rather than guess.
            send_note(state, &peer_hash, "url_mismatch");
            return emit_op_error(state, "corroborate", "url_mismatch");
        }
        Err(patanyx_corroborate::CorroborateError::Integrity(_)) => {
            return send_note(state, &peer_hash, "too_large")
        }
        Err(_) => return send_note(state, &peer_hash, "bad_message"),
    };
    // Verdict BEFORE moving the response: it is shown to both sides.
    let local = patanyx_corroborate::verdict(&request, &response);
    let data = match response.to_bytes() {
        Ok(bytes) => hex_encode(&bytes),
        Err(_) => return emit_op_error(state, "corroborate", "io"),
    };
    // Best effort: if the session died mid-comparison there is nothing more
    // to do; the requester's pending entry simply never completes.
    let _ = crate::chat_panel::send_payload(
        state,
        &peer_hash,
        &crate::chat_panel::ChatPayload::CorroborateResponse { data },
    );
    if let Ok(verdict) = local {
        state.emit(
            "corroborate_verdict",
            verdict_json(&peer_hash, contact_id.as_deref(), &request.url, &verdict),
        );
    }
}

/// A peer asked us to corroborate. We fetch NOTHING: if one of our open
/// tabs already has the page, its bytes answer; otherwise the peer gets an
/// honest "no_page" rather than a comparison against a fresh fetch (a second
/// serving is exactly the thing this feature exists to detect).
#[cfg(feature = "chat")]
pub fn handle_corroborate_request(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    url: String,
    data: String,
) {
    // Transparency before anything else: the response below is automatic,
    // so the user must be able to SEE that it happened.
    state.emit(
        "corroborate_request_received",
        json!({ "peer_hash": peer_hash, "contact_id": contact_id, "url": url }),
    );
    let Some(raw) = hex_decode(&data) else {
        return send_note(state, &peer_hash, "bad_message");
    };
    let request = match patanyx_corroborate::CompareRequest::from_bytes(&raw) {
        Ok(request) => request,
        Err(_) => return send_note(state, &peer_hash, "bad_message"),
    };
    if !crate::platform::page_bytes_supported() {
        return send_note(state, &peer_hash, "unsupported");
    }
    let Some(own_url) = tab_url_for_normalized(state, &request.url) else {
        return send_note(state, &peer_hash, "no_page");
    };
    let note_hash = peer_hash.clone();
    let token = state.integrity.issue(Pending::CorroborateRespond {
        peer_hash,
        contact_id,
        own_url: own_url.clone(),
        request,
    });
    let proxy = state.proxy();
    match tab_webview_for_url(state, &own_url) {
        Some(webview) => crate::platform::request_main_resource_bytes(webview, token, &proxy),
        None => {
            // The tab vanished between the two lookups (same thread, so only
            // possible if the accessor shape changed) — degrade, never crash.
            state.integrity.pending.remove(&token);
            send_note(state, &note_hash, "no_page");
        }
    }
}

/// Our request was answered: turn request + response into the verdict.
#[cfg(feature = "chat")]
pub fn handle_corroborate_response(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    data: String,
) {
    let Some(raw) = hex_decode(&data) else {
        return emit_op_error(state, "corroborate", "bad_message");
    };
    let response = match patanyx_corroborate::CompareResponse::from_bytes(&raw) {
        Ok(response) => response,
        Err(_) => return emit_op_error(state, "corroborate", "bad_message"),
    };
    let Some(request) = state.integrity.pending_corroborations.remove(&peer_hash) else {
        state.emit(
            "corroborate_note",
            json!({ "peer_hash": peer_hash, "contact_id": contact_id, "local": true, "reason": "unexpected" }),
        );
        return;
    };
    match patanyx_corroborate::verdict(&request, &response) {
        Ok(verdict) => state.emit(
            "corroborate_verdict",
            verdict_json(&peer_hash, contact_id.as_deref(), &request.url, &verdict),
        ),
        Err(_) => emit_op_error(state, "corroborate", "url_mismatch"),
    }
}

/// The peer (or our own send path) reported that no comparison happened.
#[cfg(feature = "chat")]
pub fn handle_corroborate_note(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    reason: &str,
) {
    state.integrity.pending_corroborations.remove(&peer_hash);
    state.emit(
        "corroborate_note",
        json!({
            "peer_hash": peer_hash,
            "contact_id": contact_id,
            "local": false,
            "reason": sanitize_reason(reason),
        }),
    );
}

/// A peer-controlled string that lands in UI text mapping: pin it to the
/// known vocabulary so a crafted note cannot inject arbitrary copy.
#[cfg(feature = "chat")]
fn sanitize_reason(reason: &str) -> &'static str {
    match reason {
        "no_page" => "no_page",
        "unsupported" => "unsupported",
        "url_mismatch" => "url_mismatch",
        "too_large" => "too_large",
        "too_long" => "too_long",
        "bad_message" => "bad_message",
        _ => "bad_message",
    }
}

#[cfg(feature = "chat")]
fn send_note(state: &AppState, peer_hash: &str, reason: &str) {
    let _ = crate::chat_panel::send_payload(
        state,
        peer_hash,
        &crate::chat_panel::ChatPayload::CorroborateNote {
            reason: reason.to_string(),
        },
    );
}

/// Verdict → the JSON event the panel renders. The human sentence is the
/// crate's own Display text: it was written to be honest about scope and
/// safe to show verbatim, so the UI adds caveats but never rewords it.
#[cfg(feature = "chat")]
fn verdict_json(
    peer_hash: &str,
    contact_id: Option<&str>,
    url: &str,
    verdict: &patanyx_corroborate::Verdict,
) -> Value {
    use patanyx_corroborate::Corroboration;
    let (kind, similarity) = match verdict.corroboration {
        Corroboration::SameContent => ("same_content", None),
        Corroboration::SameTextDifferentMarkup => ("same_text", None),
        Corroboration::DifferentText { similarity } => ("different_text", Some(similarity)),
    };
    json!({
        "peer_hash": peer_hash,
        "contact_id": contact_id,
        "url": url,
        "kind": kind,
        "text": verdict.corroboration.to_string(),
        "byte_identical": verdict.byte_identical,
        "fetch_gap_seconds": verdict.fetch_gap_seconds,
        "similarity": similarity,
    })
}

/// Corroboration rides on chat sessions; when the transport dies (vault
/// lock, shutdown) every in-flight comparison dies with it. Nothing is
/// stored, so nothing is lost — a late peer reply meets an empty pending
/// table and surfaces as "unexpected".
pub fn on_transport_down(state: &mut AppState) {
    #[cfg(feature = "chat")]
    {
        state.integrity.pending_corroborations.clear();
        state
            .integrity
            .pending
            .retain(|_, purpose| !purpose.is_corroboration());
    }
    #[cfg(not(feature = "chat"))]
    let _ = state;
}

/// Drop every local snapshot operation at the vault boundary. In particular,
/// a `Check` owns cloned stored text while the engine read is in flight; that
/// text must not survive a lock or later produce a chrome event.
pub fn on_vault_locked(state: &mut AppState) {
    // This may hold freshly derived hashes/text while a native picture is
    // being bounded. Drop it before the lock event can repaint the chrome.
    state.integrity.snapshot_capture = None;
    let mut temporary_tabs = state
        .integrity
        .waiting_checks
        .values()
        .filter_map(|purpose| match purpose {
            Pending::Check { target, .. } => target.temporary_tab_id(),
            _ => None,
        })
        .collect::<Vec<_>>();
    state.integrity.waiting_checks.clear();
    let remove = state
        .integrity
        .pending
        .iter()
        .filter_map(|(token, purpose)| match purpose {
            Pending::Check { target, .. } => {
                temporary_tabs.extend(target.temporary_tab_id());
                Some(*token)
            }
            Pending::MarkSeen { .. } => Some(*token),
            _ => None,
        })
        .collect::<Vec<_>>();
    for token in remove {
        state.integrity.pending.remove(&token);
    }
    temporary_tabs.sort_unstable();
    temporary_tabs.dedup();
    for tab_id in temporary_tabs {
        let _ = state.close_tab(tab_id);
    }
}

// ---------------------------------------------------------------------------
// Hex encoding
//
// The brief allows base64 OR hex into the text envelope. Hex is chosen so no
// new dependency is needed (§4.3 discipline applied to dependencies too).
// ---------------------------------------------------------------------------

#[cfg(feature = "chat")]
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "chat")]
pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    // Peer-supplied: cap BEFORE allocating (from_bytes caps again at the
    // protocol's 64 KiB after decoding).
    if text.len() % 2 != 0 || text.len() > 2 * patanyx_corroborate::MAX_MESSAGE_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(feature = "chat")]
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// tests — pure helpers only (AppState is not constructible in this crate's
// tests); the wire format is proved end-to-end without I/O.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "chat")]
mod tests {
    use super::*;
    use patanyx_corroborate::{begin_comparison, respond, verdict, Corroboration, CompareRequest};

    const PAGE: &[u8] = b"<p>hello world, this is a public page with a fair \
        number of visible words in it for shingling</p>";

    #[test]
    fn hex_round_trip_and_rejects_bad_input() {
        let bytes = b"\x00\xff\x10\xab";
        let hex = hex_encode(bytes);
        assert_eq!(hex, "00ff10ab");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
        assert!(hex_decode("abc").is_none(), "odd length");
        assert!(hex_decode("zz").is_none(), "non-hex");
        assert!(hex_decode(&"aa".repeat(patanyx_corroborate::MAX_MESSAGE_BYTES + 1)).is_none());
    }

    #[test]
    fn wire_format_round_trips_end_to_end() {
        let request = begin_comparison("https://example.com/a", PAGE, 100).unwrap();
        let data = hex_encode(&request.to_bytes().unwrap());
        let back = CompareRequest::from_bytes(&hex_decode(&data).unwrap()).unwrap();
        let response = respond(&back, "example.com/a", PAGE, 105).unwrap();
        let v = verdict(&back, &response).unwrap();
        assert_eq!(v.corroboration, Corroboration::SameContent);
        assert!(v.byte_identical);
        assert_eq!(v.fetch_gap_seconds, 5);
    }

    /// The whole protocol rides inside the chat transport's text cap: a
    /// request envelope must fit, even for a large page. (Digest size is
    /// fixed by construction — three hashes plus a 64-word sketch — so the
    /// page size barely matters, but prove it rather than assume it.)
    #[test]
    fn corroboration_envelope_fits_the_chat_cap() {
        let big_page = PAGE.repeat(8192); // ~600 KiB page
        let request = begin_comparison("https://example.com/a", &big_page, 1).unwrap();
        let payload = crate::chat_panel::ChatPayload::CorroborateRequest {
            url: request.url.clone(),
            data: hex_encode(&request.to_bytes().unwrap()),
        };
        let wire = serde_json::to_string(&payload).unwrap();
        assert!(
            wire.len() <= patanyx_chat::MAX_MESSAGE_BYTES,
            "envelope {} bytes exceeds chat cap {}",
            wire.len(),
            patanyx_chat::MAX_MESSAGE_BYTES
        );
    }

    #[test]
    fn verdict_json_carries_the_honest_fields() {
        let v = patanyx_corroborate::Verdict {
            corroboration: Corroboration::DifferentText { similarity: 0.5 },
            byte_identical: false,
            fetch_gap_seconds: 7,
        };
        let j = verdict_json("hash", Some("contact"), "https://x/", &v);
        assert_eq!(j["kind"], "different_text");
        assert_eq!(j["fetch_gap_seconds"], 7);
        assert_eq!(j["byte_identical"], false);
        assert!(j["text"].as_str().unwrap().contains("50%"));
        // The crate's sentence must reach the UI unedited.
        assert!(j["text"].as_str().unwrap().contains("innocent causes"));
    }

    #[test]
    fn peer_reasons_are_pinned_to_the_known_vocabulary() {
        assert_eq!(sanitize_reason("no_page"), "no_page");
        assert_eq!(sanitize_reason("<script>alert(1)</script>"), "bad_message");
    }
}

// ---------------------------------------------------------------------------
// Change Cross-Check
//
// The same shape as peer corroboration one section up, with one difference
// that matters: corroboration compares what two people are being served NOW,
// while this compares what each of them SAVED against what each of them sees.
// So both sides read their own page, and the answer carries two digests
// rather than one.
// ---------------------------------------------------------------------------

/// `change_compare_request` — ask a contact whether a bookmarked page
/// changed for them too.
///
/// Requires a baseline of our own. Without one there is no change to
/// cross-check, and asking would be asking the contact to answer a question
/// this browser has not asked itself.
#[cfg(feature = "chat")]
pub fn ipc_change_request(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let peer_hash = crate::chat_panel::resolve_peer_hash(state, args)?;
    let contact_id = args
        .get("contact_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let url = state.active_url();
    if patanyx_corroborate::normalize_url(&url).is_err() {
        return Err("bad_args");
    }
    let (_, baseline, baseline_recorded_at) =
        stored_snapshot(state, &url).ok_or("no_snapshot")?;
    begin_fetch_for_active(
        state,
        Pending::ChangeBegin {
            peer_hash,
            contact_id,
            url,
            baseline,
            baseline_recorded_at,
        },
    )?;
    Ok(json!({ "state": "sent" }))
}

/// Our page has been read: send what we saved and what we see.
#[cfg(feature = "chat")]
#[allow(clippy::too_many_arguments)]
fn finish_change_begin(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    url: String,
    baseline: ContentDigest,
    baseline_recorded_at: u64,
    result: Result<Vec<u8>, PageBytesError>,
) {
    let Ok(url) = patanyx_corroborate::normalize_url(&url) else {
        return emit_change_error(state, "bad_args");
    };
    // A failed read is not fatal here: the question can still be asked from
    // the baseline alone, and the contact's answer is the point. This is the
    // one place a byte-read failure degrades rather than refuses.
    let current = result.ok().and_then(|bytes| digest(&bytes).ok());
    let request = patanyx_corroborate::ChangeCompareRequest::new(
        &url,
        baseline,
        baseline_recorded_at,
        current,
        now_secs(),
    );
    let Ok(bytes) = request.to_bytes() else {
        return emit_change_error(state, "bad_message");
    };
    let payload = crate::chat_panel::ChatPayload::ChangeCompareRequest {
        url: url.as_str().to_string(),
        data: hex_encode(&bytes),
    };
    if crate::chat_panel::send_payload(state, &peer_hash, &payload).is_err() {
        return emit_change_error(state, "send_failed");
    }
    state
        .integrity
        .pending_changes
        .insert(peer_hash.clone(), request);
    state.emit(
        "change_compare_status",
        json!({ "peer_hash": peer_hash, "contact_id": contact_id, "state": "sent" }),
    );
}

/// A contact asked whether a page changed for us. Answered automatically,
/// and visibly: the transparency event goes out BEFORE the message is even
/// decoded, exactly as the other two peer features do it.
#[cfg(feature = "chat")]
pub fn handle_change_request(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    url: String,
    data: String,
) {
    state.emit(
        "change_compare_request_received",
        json!({ "peer_hash": peer_hash, "contact_id": contact_id, "url": url }),
    );
    let Some(raw) = hex_decode(&data) else {
        return send_change_note(state, &peer_hash, "bad_message");
    };
    let request = match patanyx_corroborate::ChangeCompareRequest::from_bytes(&raw) {
        Ok(request) => request,
        Err(_) => return send_change_note(state, &peer_hash, "bad_message"),
    };
    // Our own baseline for that address, if we have one. Absent is an
    // ordinary answer, not a refusal: what we see NOW is still half the
    // matrix, and refusing would hide it.
    let own = stored_snapshot(state, &request.url)
        .map(|(_, digest, at)| (digest, at))
        .or_else(|| {
            tab_url_for_normalized(state, &request.url)
                .and_then(|typed| stored_snapshot(state, &typed))
                .map(|(_, digest, at)| (digest, at))
        });
    let (baseline, baseline_recorded_at) = match own {
        Some((digest, at)) => (Some(digest), Some(at)),
        None => (None, None),
    };
    // Read the page ONLY if it is already open. Fetching it now would be
    // fetching on a peer's say-so, which is the thing peer corroboration
    // refuses to do and for the same reason.
    let open_here = tab_url_for_normalized(state, &request.url);
    if open_here.is_none() {
        // Nothing to read, but a baseline may still answer.
        if baseline.is_none() {
            return send_change_note(state, &peer_hash, "no_baseline");
        }
        send_change_answer(
            state,
            &peer_hash,
            &request,
            baseline,
            baseline_recorded_at,
            None,
        );
        return;
    }
    if !crate::platform::page_bytes_supported() {
        return send_change_note(state, &peer_hash, "unsupported");
    }
    let own_url = open_here.expect("checked above");
    let note_hash = peer_hash.clone();
    let token = state.integrity.issue(Pending::ChangeRespond {
        peer_hash,
        contact_id,
        request,
        baseline,
        baseline_recorded_at,
    });
    let proxy = state.proxy();
    match tab_webview_for_url(state, &own_url) {
        Some(webview) => crate::platform::request_main_resource_bytes(webview, token, &proxy),
        None => {
            state.integrity.pending.remove(&token);
            send_change_note(state, &note_hash, "no_page");
        }
    }
}

/// Our page has been read on the answering side: send both digests.
#[cfg(feature = "chat")]
#[allow(clippy::too_many_arguments)]
fn finish_change_respond(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    request: patanyx_corroborate::ChangeCompareRequest,
    baseline: Option<ContentDigest>,
    baseline_recorded_at: Option<u64>,
    result: Result<Vec<u8>, PageBytesError>,
) {
    let current = result.ok().and_then(|bytes| digest(&bytes).ok());
    let Some(response) = send_change_answer(
        state,
        &peer_hash,
        &request,
        baseline,
        baseline_recorded_at,
        current,
    ) else {
        // The answer did not go out. Emitting a verdict here would show
        // this side a comparison the other side never received.
        return;
    };
    // The responder sees the verdict too, the same rule Copy Compare
    // follows: both sides learn the same thing at the same time, and hiding
    // it from whoever answered would make the feature feel like
    // surveillance. The verdict is computed from the SENT response, so the
    // two sides are reading the same two messages.
    if let Ok(verdict) = patanyx_corroborate::change_verdict(&request, &response) {
        state.emit(
            "change_compare_verdict",
            change_verdict_json(&peer_hash, contact_id.as_deref(), &request.url, &verdict),
        );
    }
}

/// Assembles and sends one answer.
#[cfg(feature = "chat")]
fn send_change_answer(
    state: &mut AppState,
    peer_hash: &str,
    request: &patanyx_corroborate::ChangeCompareRequest,
    baseline: Option<ContentDigest>,
    baseline_recorded_at: Option<u64>,
    current: Option<ContentDigest>,
) -> Option<patanyx_corroborate::ChangeCompareResponse> {
    let Ok(url) = patanyx_corroborate::normalize_url(&request.url) else {
        send_change_note(state, peer_hash, "bad_message");
        return None;
    };
    let response = patanyx_corroborate::ChangeCompareResponse::new(
        &url,
        baseline,
        baseline_recorded_at,
        current,
        now_secs(),
    );
    let Ok(bytes) = response.to_bytes() else {
        send_change_note(state, peer_hash, "bad_message");
        return None;
    };
    let payload = crate::chat_panel::ChatPayload::ChangeCompareResponse {
        data: hex_encode(&bytes),
    };
    if crate::chat_panel::send_payload(state, peer_hash, &payload).is_err() {
        return None;
    }
    Some(response)
}

/// Our question was answered: request plus response become the matrix.
#[cfg(feature = "chat")]
pub fn handle_change_response(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    data: String,
) {
    let Some(raw) = hex_decode(&data) else {
        return emit_change_error(state, "bad_message");
    };
    let response = match patanyx_corroborate::ChangeCompareResponse::from_bytes(&raw) {
        Ok(response) => response,
        Err(_) => return emit_change_error(state, "bad_message"),
    };
    let Some(request) = state.integrity.pending_changes.remove(&peer_hash) else {
        state.emit(
            "change_compare_note",
            json!({
                "peer_hash": peer_hash,
                "contact_id": contact_id,
                "local": true,
                "reason": "unexpected",
            }),
        );
        return;
    };
    match patanyx_corroborate::change_verdict(&request, &response) {
        Ok(verdict) => state.emit(
            "change_compare_verdict",
            change_verdict_json(&peer_hash, contact_id.as_deref(), &request.url, &verdict),
        ),
        Err(_) => emit_change_error(state, "url_mismatch"),
    }
}

/// A contact could not answer. The reason is peer-supplied, so it is pinned
/// to a closed set before it can reach the chrome.
#[cfg(feature = "chat")]
pub fn handle_change_note(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    reason: &str,
) {
    state.integrity.pending_changes.remove(&peer_hash);
    let reason = match reason {
        "no_baseline" | "no_page" | "unsupported" | "bad_message" => reason,
        _ => "bad_message",
    };
    state.emit(
        "change_compare_note",
        json!({
            "peer_hash": peer_hash,
            "contact_id": contact_id,
            "local": false,
            "reason": reason,
        }),
    );
}

#[cfg(feature = "chat")]
fn send_change_note(state: &mut AppState, peer_hash: &str, reason: &str) {
    let payload = crate::chat_panel::ChatPayload::ChangeCompareNote {
        reason: reason.to_string(),
    };
    let _ = crate::chat_panel::send_payload(state, peer_hash, &payload);
}

#[cfg(feature = "chat")]
fn emit_change_error(state: &AppState, code: &'static str) {
    state.emit(
        "change_compare_error",
        json!({ "op": "change_compare", "code": code }),
    );
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn page(words: &str) -> ContentDigest {
        patanyx_integrity::digest(format!("<p>{words}</p>").as_bytes()).unwrap()
    }

    #[test]
    fn bookmark_targeted_compare_resolves_the_named_record_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.rbs");
        let mut store = patanyx_store::Store::create_with_params(&path, "pw", 8192, 1, 1).unwrap();
        let alpha = store.add_bookmark("https://alpha.test/", "Alpha").unwrap();
        let beta = store.add_bookmark("https://beta.test/", "Beta").unwrap();
        let alpha_saved = store
            .save_page_snapshot(&alpha, page("alpha saved words"), "Alpha saved words.")
            .unwrap();
        let beta_saved = store
            .save_page_snapshot(&beta, page("beta saved words"), "Beta saved words.")
            .unwrap();

        let (url, selected) =
            resolve_bookmark_target(&store, &beta, Some(&beta_saved.id)).unwrap();
        assert_eq!(url, "https://beta.test/");
        assert_eq!(selected.id, beta_saved.id);
        assert_eq!(selected.digest, page("beta saved words"));
        assert_eq!(
            resolve_bookmark_target(&store, &beta, Some(&alpha_saved.id)),
            Err("no_snapshot"),
            "a snapshot for another bookmark URL must not resolve"
        );
    }

    #[test]
    fn pre_text_snapshot_reports_unavailable_instead_of_an_empty_diff() {
        let evidence = text_evidence(None, false, "Fresh visible text.");
        assert_eq!(evidence["available"], json!(false));
        assert!(evidence.get("added").is_none());
        assert!(evidence.get("removed").is_none());
    }

    #[test]
    fn sentence_diff_reports_known_added_and_removed_passages() {
        let evidence = text_evidence(
            Some("Keep this sentence. Remove this passage. Shared ending!"),
            false,
            "Keep this sentence. Add this passage. Shared ending!",
        );
        assert_eq!(evidence["available"], json!(true));
        assert_eq!(evidence["removed"], json!(["Remove this passage."]));
        assert_eq!(evidence["added"], json!(["Add this passage."]));
        assert_eq!(evidence["output_trimmed"], json!(false));
    }
}

/// One shape for the matrix, so the chrome never assembles a claim. `text`
/// is the crate's own headline, shown verbatim.
#[cfg(feature = "chat")]
fn change_verdict_json(
    peer_hash: &str,
    contact_id: Option<&str>,
    url: &str,
    verdict: &patanyx_corroborate::ChangeVerdict,
) -> Value {
    let cell = |c: Option<patanyx_corroborate::Cell>| match c {
        None => Value::Null,
        Some(patanyx_corroborate::Cell::Same) => json!("same"),
        Some(patanyx_corroborate::Cell::TextSameMarkupDiffers) => json!("same_text"),
        Some(patanyx_corroborate::Cell::TextDiffers { .. }) => json!("text_differs"),
    };
    json!({
        "peer_hash": peer_hash,
        "contact_id": contact_id,
        "url": url,
        "text": verdict.to_string(),
        "now": cell(verdict.now),
        "baselines": cell(verdict.baselines),
        "their_change": cell(verdict.their_change),
        "my_change": cell(verdict.my_change),
        "baseline_gap_seconds": verdict.baseline_gap_seconds,
    })
}
