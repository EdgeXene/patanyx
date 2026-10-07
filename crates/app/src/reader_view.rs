//! Reader View: the article on the current page, as plain text in a panel.
//!
//! WHERE THE TEXT COMES FROM. The page's main resource as the server sent
//! it, read through the same engine path page integrity uses
//! (`platform::request_main_resource_bytes`, one token space shared with
//! page_integrity so an answer can never reach the wrong owner). No script
//! runs in the page for this: content webviews are never evaluated, and
//! Reader View does not change that. It therefore works in a tab where
//! script is off (Strict Tab), and it costs no network request: the bytes
//! are the ones the engine already received.
//!
//! WHAT CROSSES INTO THE CHROME. `patanyx_reader::Article`, a list of typed
//! blocks holding plain strings, rendered with textContent. Never markup.
//!
//! LIFETIME. Memory only, and bound to one tab and one document:
//! - one request is current at a time; an answer for any other is dropped;
//! - the tab closing, starting a new load, or stopping being the active tab
//!   ends the request and clears the panel (`reader_cleared`), so an article
//!   from a Strict Tab never outlives it and a late answer never paints a
//!   page the user has left;
//! - nothing is written anywhere. Rust keeps no copy of the article once it
//!   has been handed to the chrome.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

use crate::page_integrity::PageBytesError;
use crate::state::AppState;
use crate::UserEvent;

/// Extractions running on worker threads. A page takes well under a second
/// to extract (worst measured: about 1 s for an 8 MiB hostile page), but a
/// held-down shortcut must not stack up CPU-bound threads behind it.
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_IN_FLIGHT: usize = 2;

#[derive(Default)]
pub struct ReaderState {
    current: Option<Current>,
    /// Tabs with a document load in progress, from LoadState events. A byte
    /// read on one of these is refused up front as reader_page_loading, which is
    /// what makes NoMainResource on a loaded page an honest "unavailable"
    /// rather than "try again in a moment".
    loading: HashSet<u64>,
}

struct Current {
    request: u64,
    tab_id: u64,
    url: String,
}

#[derive(Debug)]
pub enum ReaderEvent {
    Extracted {
        request: u64,
        result: Result<patanyx_reader::Article, patanyx_reader::ReaderError>,
    },
}

/// `reader_open`: start reading the active tab. The article (or the reason
/// there is none) arrives as a `reader_article` / `reader_error` event
/// carrying the request number returned here.
/// The request number is the CHROME's: it picks it before asking, so it
/// can tell its own answer from a stale one without waiting for this reply.
/// Rust only needs it to be the one it echoes; it is never trusted for more.
pub fn ipc_open(state: &mut AppState, request: u64) -> Result<Value, &'static str> {
    let tab = state.tabs.get(state.active).ok_or("no_tab")?;
    if !crate::state::is_translatable_url(&tab.url) {
        return Err("reader_unsupported_url");
    }
    if !crate::platform::page_bytes_supported() {
        return Err("reader_unsupported");
    }
    if state.reader.loading.contains(&tab.id) {
        return Err("reader_page_loading");
    }
    let (tab_id, url) = (tab.id, tab.url.clone());
    state.reader.current = Some(Current {
        request,
        tab_id,
        url,
    });
    let token = crate::page_integrity::issue_reader_fetch(state, request);
    let proxy = state.proxy();
    let tab = state.tabs.get(state.active).ok_or("no_tab")?;
    crate::platform::request_main_resource_bytes(&tab.webview, token, &proxy);
    Ok(json!({ "request": request }))
}

/// `reader_close`: the user closed the panel. Forget the request so a late
/// answer is dropped.
pub fn ipc_close(state: &mut AppState) -> Result<Value, &'static str> {
    state.reader.current = None;
    Ok(json!({}))
}

/// The tab this request was for still exists and still shows the document
/// the request was made on.
fn still_on_page(state: &AppState, request: u64) -> bool {
    let Some(c) = state.reader.current.as_ref().filter(|c| c.request == request) else {
        return false;
    };
    state
        .tabs
        .iter()
        .any(|t| t.id == c.tab_id && same_document(&t.url, &c.url))
}

/// Same address ignoring the fragment: an in-page jump is not a new
/// document. (platform::main_resource has the same helper but is compiled
/// for Windows only.)
fn same_document(a: &str, b: &str) -> bool {
    fn strip(u: &str) -> &str {
        u.split_once('#').map_or(u, |(base, _)| base)
    }
    strip(a) == strip(b)
}

fn fail(state: &mut AppState, request: u64, code: &'static str) {
    state.reader.current = None;
    state.emit("reader_error", json!({ "request": request, "code": code }));
}

/// The page bytes for a Reader request, from page_integrity's dispatcher.
pub(crate) fn on_bytes(
    state: &mut AppState,
    request: u64,
    result: Result<Vec<u8>, PageBytesError>,
) {
    if !still_on_page(state, request) {
        return;
    }
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(_) => {
            // No body to read: a 304 reload, an error page, a page the
            // blocker replaced, a capture over the size cap. None of these
            // gets better by waiting, and Reader View does not refetch.
            let tab_loading = state
                .reader
                .current
                .as_ref()
                .is_some_and(|c| state.reader.loading.contains(&c.tab_id));
            let code = if tab_loading {
                "reader_page_loading"
            } else {
                "reader_page_unavailable"
            };
            fail(state, request, code);
            return;
        }
    };
    if IN_FLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        fail(state, request, "reader_busy");
        return;
    }
    let proxy = state.proxy();
    let spawned = std::thread::Builder::new()
        .name("reader-extract".into())
        .spawn(move || {
            let result = patanyx_reader::extract(&bytes);
            drop(bytes);
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            let _ = proxy.send_event(UserEvent::Reader(ReaderEvent::Extracted { request, result }));
        });
    if spawned.is_err() {
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        fail(state, request, "reader_page_unavailable");
    }
}

pub fn handle_event(state: &mut AppState, event: ReaderEvent) {
    match event {
        ReaderEvent::Extracted { request, result } => {
            if !still_on_page(state, request) {
                return;
            }
            match result {
                Ok(article) => {
                    // Handed over and forgotten: Rust keeps no copy. The
                    // request stays current so a later tab event can still
                    // clear the panel that is now showing it.
                    state.emit(
                        "reader_article",
                        json!({ "request": request, "article": article }),
                    );
                }
                Err(e) => fail(state, request, error_code(&e)),
            }
        }
    }
}

fn error_code(e: &patanyx_reader::ReaderError) -> &'static str {
    use patanyx_reader::ReaderError::*;
    match e {
        InputTooLarge { .. } | TooComplex => "reader_page_unavailable",
        UnsupportedEncoding(_) => "reader_unsupported_encoding",
        NoArticle => "reader_no_article",
    }
}

fn clear_if_for(state: &mut AppState, tab_id: u64) {
    let ended = match state.reader.current.as_ref() {
        Some(c) if c.tab_id == tab_id => c.request,
        _ => return,
    };
    state.reader.current = None;
    // The request it ends travels with it: the chrome ignores a clear that
    // arrives after the panel has moved on to a newer request.
    state.emit("reader_cleared", json!({ "request": ended }));
}

/// A tab started or finished loading a document.
pub fn on_tab_load_state(state: &mut AppState, tab_id: u64, loading: bool) {
    if loading {
        state.reader.loading.insert(tab_id);
        // A new document: whatever Reader View holds for this tab
        // describes a page that is gone.
        clear_if_for(state, tab_id);
    } else {
        state.reader.loading.remove(&tab_id);
    }
}

pub fn on_tab_closed(state: &mut AppState, tab_id: u64) {
    state.reader.loading.remove(&tab_id);
    clear_if_for(state, tab_id);
}

/// The active tab changed. Reader View describes the active tab only, so
/// any other tab's article is cleared rather than left on screen over a
/// page it does not describe.
pub fn on_active_changed(state: &mut AppState) {
    let active = state.tabs.get(state.active).map(|t| t.id);
    if let Some(c) = state.reader.current.as_ref() {
        if Some(c.tab_id) != active {
            let tab_id = c.tab_id;
            clear_if_for(state, tab_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_changes_are_the_same_document() {
        assert!(same_document("https://a.test/x#one", "https://a.test/x#two"));
        assert!(!same_document("https://a.test/x", "https://a.test/y"));
    }

    #[test]
    fn every_extractor_error_has_a_code() {
        use patanyx_reader::ReaderError::*;
        for (e, code) in [
            (InputTooLarge { len: 1, max: 0 }, "reader_page_unavailable"),
            (TooComplex, "reader_page_unavailable"),
            (UnsupportedEncoding("x".into()), "reader_unsupported_encoding"),
            (NoArticle, "reader_no_article"),
        ] {
            assert_eq!(error_code(&e), code);
        }
    }
}
