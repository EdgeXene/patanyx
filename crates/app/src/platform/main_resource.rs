//! Main-resource identification and caching -- the pure half of the Windows
//! page-bytes path.
//!
//! Everything here is free of COM so the decisions that pick WHICH response
//! becomes "the bytes the server sent for this page" are unit-testable on
//! any OS (the COM plumbing in `platform/windows.rs` cannot run on the
//! Linux build machine). `windows.rs` is deliberately thin: read getters,
//! call into here, act on the answer.
//!
//! Why identification is not "request URI == committed URL":
//!
//!   * ORDERING -- WebResourceResponseReceived carries no resource context
//!     and fires for every subresource. The committed URL only updates when
//!     the navigation commits, and Microsoft documents no ordering between
//!     response processing and the host handler, so at the moment the
//!     document's response arrives the committed URL is usually still the
//!     PREVIOUS page. Comparing against it would miss the document.
//!   * REDIRECTS -- the committed URL is the FINAL URL of a redirect chain.
//!     Loosening the match to "anything we navigated to" would capture an
//!     earlier hop (the 301 body), which is not the page being displayed.
//!     So the tracker FOLLOWS the chain: NavigationStarting sets the first
//!     candidate, each 3xx candidate advances it by its resolved Location,
//!     and only the final hop's bytes can ever be served (`serve` compares
//!     the stored URI with the tab's current committed URL).
//!   * SAME-URL SUBRESOURCES -- once the document response is seen the
//!     candidate is cleared BEFORE its content is read, so a later XHR to
//!     the page's own URL is never mistaken for the main resource.
//!   * 304 -- a revalidated reload carries no body we may digest; the chain
//!     is dropped (honest NoMainResource) rather than storing an empty
//!     "body" that is not the displayed page.
//!
//! Fragments are stripped on every boundary: request URIs never carry one
//! but the committed URL can, and following an in-page #link must not
//! invalidate a page's bytes.

use crate::page_integrity::PageBytesError;

/// Largest main resource buffered, in bytes. This is the same cap the
/// digest layer enforces; the read loop stops at it rather than
/// truncating, because a truncated digest that compared "equal" would be
/// the exact lie these features exist to detect.
pub const MAX_MAIN_RESOURCE_BYTES: usize = patanyx_integrity::MAX_INPUT_BYTES;

/// Strip any `#fragment` (see module docs).
pub fn strip_fragment(uri: &str) -> &str {
    match uri.find('#') {
        Some(i) => &uri[..i],
        None => uri,
    }
}

/// Only http(s) documents have "bytes the server sent". file:/data:/about:
/// pages therefore report NoMainResource, which the UI already phrases
/// correctly, instead of digesting something no server sent.
pub fn is_http(uri: &str) -> bool {
    uri.starts_with("http://") || uri.starts_with("https://")
}

/// Resolve a Location header value against the URI that produced it.
///
/// A deliberately small subset of RFC 3986 §5 covering real-world redirect
/// targets: absolute URIs, scheme-relative (`//host/...`), absolute-path
/// (`/...`), query-only (`?...`), fragment-only/empty, and relative paths
/// with `.`/`..` segments. Anything unresolvable yields None and the
/// caller FAILS CLOSED (drops the chain → NoMainResource): a guessed
/// redirect target is wrong-bytes input.
pub fn resolve_location(base: &str, reference: &str) -> Option<String> {
    let reference = strip_fragment(reference.trim());
    if reference.is_empty() {
        let base = strip_fragment(base);
        return if is_http(base) { Some(base.to_string()) } else { None };
    }
    // Absolute URI (scheme per RFC 3986 §3.1).
    if let Some(colon) = reference.find(':') {
        let scheme = &reference[..colon];
        if !scheme.is_empty()
            && scheme.chars().next().map_or(false, |c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return Some(reference.to_string());
        }
    }
    // Everything below needs the base's scheme and authority.
    let scheme_sep = base.find("://")?;
    let scheme = &base[..scheme_sep];
    let after_authority = {
        let rest = &base[scheme_sep + 3..];
        scheme_sep + 3 + rest.find('/').unwrap_or(rest.len())
    };
    let origin = &base[..after_authority]; // e.g. https://a.example
    if reference.starts_with("//") {
        return Some(format!("{scheme}:{reference}"));
    }
    if let Some(path) = reference.strip_prefix('/') {
        return Some(format!("{origin}/{path}"));
    }
    // Split the reference into path + query before merging, so dot-segment
    // removal never touches the query.
    let (ref_path, ref_query) = match reference.find('?') {
        Some(i) => (&reference[..i], &reference[i..]),
        None => (reference, ""),
    };
    if ref_path.is_empty() {
        // Query-only reference: replace the base's query.
        let b = strip_fragment(base);
        let b = match b.find('?') {
            Some(i) => &b[..i],
            None => b,
        };
        return Some(format!("{b}{ref_query}"));
    }
    // Relative path: merge against the base path's directory.
    let base_path = &base[after_authority..];
    let base_path = match base_path.find('?') {
        Some(i) => &base_path[..i],
        None => base_path,
    };
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..i + 1],
        None => "/",
    };
    let merged = format!("{dir}{ref_path}");
    // Dot-segment removal (path-only form of RFC 3986 §5.2.4).
    let mut segs: Vec<&str> = Vec::new();
    for seg in merged.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut resolved = format!("{origin}/{}", segs.join("/"));
    if (merged.ends_with('/') || merged.ends_with("/.") || merged.ends_with("/.."))
        && !resolved.ends_with('/')
    {
        resolved.push('/');
    }
    resolved.push_str(ref_query);
    Some(resolved)
}

/// What a `WebResourceResponseReceived` event means for main-resource
/// capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAction {
    /// Not the main document (subresource, a redirect hop, or a chain we
    /// refused to follow). Read nothing.
    Ignore,
    /// The page's bytes: fetch the response content and hand the outcome to
    /// `store`, quoting this generation back.
    FetchContent { generation: u64 },
}

#[derive(Debug, Clone)]
struct MainResourceEntry {
    uri: String,
    generation: u64,
    result: Result<Vec<u8>, PageBytesError>,
}

/// Per-tab main-resource state. One entry, replaced on every candidate,
/// never served for the wrong page.
#[derive(Default)]
pub struct MainResourceTracker {
    /// Bumped by every `begin_navigation`. It is what makes an ASYNCHRONOUS
    /// `GetContent` completion safe: the callback quotes the generation it
    /// was issued under, and a late answer from an abandoned or previous
    /// visit is dropped instead of overwriting the current page. Without it
    /// a same-URL reload could serve the older visit's bytes, since the URI
    /// alone cannot tell two visits apart.
    generation: u64,
    /// Request URI of the main-document response expected next.
    pending: Option<String>,
    /// URIs the ENGINE classified as document requests in this generation.
    ///
    /// This is the difference between guessing and knowing. Matching a
    /// response by URL alone cannot tell the document apart from an XHR to
    /// the same URL that happens to complete first -- and that would digest
    /// subresource bytes while claiming they are the page, the exact lie
    /// these features exist to detect. WebView2 labels every request with a
    /// `ResourceContext`, so the COM layer marks only DOCUMENT requests
    /// here and a response is a candidate only if its URI was marked.
    document_uris: Vec<String>,
    entry: Option<MainResourceEntry>,
}

/// How many document URIs one navigation may mark before we stop growing
/// the list. A redirect chain is a handful of hops; anything longer is a
/// loop, and the list must not grow with it.
const MAX_DOCUMENT_URIS: usize = 32;

impl MainResourceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The generation a fetch should quote back to `store`.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// NavigationStarting for the main frame.
    ///
    /// The previous entry is DROPPED, not kept. Keeping it was tempting --
    /// the old page is still on screen until the new navigation commits --
    /// but it makes a 304 reload serve the earlier visit's bytes as though
    /// they had just been re-served, and it is exactly the stale-answer
    /// hazard the generation counter exists to close. Reporting
    /// NoMainResource until the new bytes arrive is the honest direction:
    /// the UI already phrases that as "page still loading".
    pub fn begin_navigation(&mut self, uri: &str) {
        let uri = strip_fragment(uri);
        self.generation = self.generation.wrapping_add(1);
        self.document_uris.clear();
        self.entry = None;
        self.pending = if is_http(uri) {
            Some(uri.to_string())
        } else {
            None
        };
    }

    /// The engine classified a request as `ResourceContext == DOCUMENT`.
    pub fn note_document_request(&mut self, uri: &str) {
        let uri = strip_fragment(uri);
        if !is_http(uri) || self.document_uris.iter().any(|u| u == uri) {
            return;
        }
        if self.document_uris.len() >= MAX_DOCUMENT_URIS {
            return;
        }
        self.document_uris.push(uri.to_string());
    }

    /// Give up on the current navigation's capture without serving
    /// anything. Called when a COM getter fails: leaving `pending` armed
    /// would let a LATER response at the same URI be taken for the
    /// document, so an unreadable event fails closed.
    pub fn abandon(&mut self) {
        self.pending = None;
    }

    /// One WebResourceResponseReceived event. `status` is the HTTP status;
    /// pass `None` when the getter failed, which fails closed rather than
    /// guessing that an unreadable status means "not a redirect".
    pub fn handle_response(
        &mut self,
        request_uri: &str,
        status: Option<u16>,
        location: Option<&str>,
    ) -> ResponseAction {
        let request_uri = strip_fragment(request_uri);
        if self.pending.as_deref() != Some(request_uri) {
            return ResponseAction::Ignore;
        }
        // The engine must have called this request a DOCUMENT. An XHR or
        // fetch to the page's own URL never is, so it can no longer be
        // mistaken for the page even if it completes first.
        if !self.document_uris.iter().any(|u| u == request_uri) {
            return ResponseAction::Ignore;
        }
        let Some(status) = status else {
            // Unreadable status: cannot tell a redirect from a document.
            self.pending = None;
            return ResponseAction::Ignore;
        };
        if (300..400).contains(&status) {
            return match location.and_then(|l| resolve_location(request_uri, l)) {
                Some(next) if is_http(&next) => {
                    self.pending = Some(next);
                    ResponseAction::Ignore
                }
                // 304 (no Location, no body we may digest) or an
                // unresolvable/non-http Location: fail CLOSED.
                _ => {
                    self.pending = None;
                    ResponseAction::Ignore
                }
            };
        }
        // Final document. Clear the candidate BEFORE the caller fetches
        // content, so no later same-URL response can match.
        self.pending = None;
        ResponseAction::FetchContent {
            generation: self.generation,
        }
    }

    /// Store the outcome of a content fetch. `generation` is what
    /// `handle_response` handed out; a mismatch means the navigation moved
    /// on while the async read was in flight, and the answer is discarded
    /// rather than overwriting the page now displayed.
    pub fn store(&mut self, uri: &str, generation: u64, result: Result<Vec<u8>, PageBytesError>) {
        if generation != self.generation {
            return;
        }
        self.entry = Some(MainResourceEntry {
            uri: strip_fragment(uri).to_string(),
            generation,
            result,
        });
    }

    /// The bytes (or recorded failure) for the page at `committed_uri` --
    /// only if what we hold IS that page, captured in the navigation now in
    /// force. None means report NoMainResource.
    pub fn serve(&self, committed_uri: &str) -> Option<Result<Vec<u8>, PageBytesError>> {
        let committed = strip_fragment(committed_uri);
        match &self.entry {
            Some(e) if e.uri == committed && e.generation == self.generation => {
                Some(e.result.clone())
            }
            _ => None,
        }
    }
}

/// Append one stream chunk, honouring the integrity input cap. Crossing
/// the cap is reported (TooLarge), never truncated.
pub fn push_capped(buf: &mut Vec<u8>, chunk: &[u8]) -> Result<(), PageBytesError> {
    if buf.len() + chunk.len() > MAX_MAIN_RESOURCE_BYTES {
        return Err(PageBytesError::TooLarge);
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- URI handling ---------------------------------------------------

    #[test]
    fn fragment_is_stripped() {
        assert_eq!(strip_fragment("https://a.example/p#frag"), "https://a.example/p");
        assert_eq!(strip_fragment("https://a.example/p"), "https://a.example/p");
        assert_eq!(strip_fragment("https://a.example/#"), "https://a.example/");
    }

    #[test]
    fn only_http_counts_as_served() {
        assert!(is_http("http://a.example/"));
        assert!(is_http("https://a.example/"));
        assert!(!is_http("about:blank"));
        assert!(!is_http("data:text/html,hi"));
        assert!(!is_http("file:///C:/page.html"));
    }

    // --- Location resolution --------------------------------------------

    #[test]
    fn resolve_absolute_uri() {
        assert_eq!(
            resolve_location("https://a.example/x", "https://b.example/y").as_deref(),
            Some("https://b.example/y")
        );
    }

    #[test]
    fn resolve_scheme_relative() {
        assert_eq!(
            resolve_location("https://a.example/x", "//b.example/y").as_deref(),
            Some("https://b.example/y")
        );
    }

    #[test]
    fn resolve_absolute_path() {
        assert_eq!(
            resolve_location("https://a.example/dir/page", "/next").as_deref(),
            Some("https://a.example/next")
        );
    }

    #[test]
    fn resolve_relative_path_and_dot_segments() {
        assert_eq!(
            resolve_location("https://a.example/dir/page", "next").as_deref(),
            Some("https://a.example/dir/next")
        );
        assert_eq!(
            resolve_location("https://a.example/dir/page", "../up").as_deref(),
            Some("https://a.example/up")
        );
        assert_eq!(
            resolve_location("https://a.example/dir/", "./x").as_deref(),
            Some("https://a.example/dir/x")
        );
        // Base with no path at all.
        assert_eq!(
            resolve_location("https://a.example", "next").as_deref(),
            Some("https://a.example/next")
        );
    }

    #[test]
    fn resolve_query_only_and_fragment_only() {
        assert_eq!(
            resolve_location("https://a.example/p?old=1", "?new=2").as_deref(),
            Some("https://a.example/p?new=2")
        );
        assert_eq!(
            resolve_location("https://a.example/p", "#top").as_deref(),
            Some("https://a.example/p")
        );
    }

    #[test]
    fn resolve_unresolvable_fails_closed() {
        assert_eq!(resolve_location("not a url", "rel"), None);
        assert_eq!(resolve_location("", "/x"), None);
    }

    // --- Main-resource matching -----------------------------------------

    // --- Tracker: identification, generations, cache ---------------------

    fn nav(t: &mut MainResourceTracker, uri: &str) {
        t.begin_navigation(uri);
        t.note_document_request(uri);
    }

    #[test]
    fn the_document_response_is_captured_and_served_at_its_url() {
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        let action = t.handle_response("https://a.example/p", Some(200), None);
        let gen = match action {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("expected FetchContent, got {other:?}"),
        };
        t.store("https://a.example/p", gen, Ok(b"<html>".to_vec()));
        assert_eq!(
            t.serve("https://a.example/p"),
            Some(Ok(b"<html>".to_vec()))
        );
    }

    #[test]
    fn a_same_url_xhr_can_never_be_taken_for_the_document() {
        // THE hazard URL-matching alone cannot close: a fetch to the page's
        // own address, arriving BEFORE the document response. The engine
        // labels it something other than DOCUMENT, so it is never marked and
        // never matches -- without that, its bytes would be digested and
        // reported as the page.
        let mut t = MainResourceTracker::new();
        t.begin_navigation("https://a.example/p");
        // Deliberately NOT marked as a document request.
        assert_eq!(
            t.handle_response("https://a.example/p", Some(200), None),
            ResponseAction::Ignore
        );
        // The real document still lands afterwards and IS captured.
        t.note_document_request("https://a.example/p");
        assert!(matches!(
            t.handle_response("https://a.example/p", Some(200), None),
            ResponseAction::FetchContent { .. }
        ));
    }

    #[test]
    fn a_late_read_from_an_abandoned_visit_is_discarded() {
        // GetContent is asynchronous. A completion from the previous visit
        // must not overwrite the page now displayed -- the same-URL reload
        // case, where the URI alone cannot tell the two visits apart.
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        let old_gen = match t.handle_response("https://a.example/p", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        // The user reloads before the first read finished.
        nav(&mut t, "https://a.example/p");
        let new_gen = match t.handle_response("https://a.example/p", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        assert_ne!(old_gen, new_gen);
        t.store("https://a.example/p", new_gen, Ok(b"new".to_vec()));
        t.store("https://a.example/p", old_gen, Ok(b"stale".to_vec()));
        assert_eq!(
            t.serve("https://a.example/p"),
            Some(Ok(b"new".to_vec())),
            "the stale completion must not overwrite the current page"
        );
    }

    #[test]
    fn a_reload_serves_nothing_until_its_own_bytes_arrive() {
        // A 304 reload carries no body we may digest, and the previous
        // visit's entry is dropped at begin_navigation -- so the answer is
        // NoMainResource rather than last visit's bytes dressed as this one.
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        let gen = match t.handle_response("https://a.example/p", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        t.store("https://a.example/p", gen, Ok(b"first".to_vec()));
        assert!(t.serve("https://a.example/p").is_some());

        nav(&mut t, "https://a.example/p");
        assert_eq!(
            t.handle_response("https://a.example/p", Some(304), None),
            ResponseAction::Ignore
        );
        assert_eq!(
            t.serve("https://a.example/p"),
            None,
            "a 304 must not serve the previous visit's bytes"
        );
    }

    #[test]
    fn an_unreadable_status_fails_closed() {
        // If the status getter fails we cannot tell a redirect from a
        // document, so the chain is dropped rather than fetched.
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        assert_eq!(
            t.handle_response("https://a.example/p", None, None),
            ResponseAction::Ignore
        );
        // And the candidate is disarmed: a later response cannot sneak in.
        assert_eq!(
            t.handle_response("https://a.example/p", Some(200), None),
            ResponseAction::Ignore
        );
    }

    #[test]
    fn abandon_disarms_the_candidate() {
        // What the COM layer calls when a getter fails mid-event.
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        t.abandon();
        assert_eq!(
            t.handle_response("https://a.example/p", Some(200), None),
            ResponseAction::Ignore
        );
    }

    #[test]
    fn a_redirect_chain_serves_only_the_final_hop() {
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/one");
        assert_eq!(
            t.handle_response("https://a.example/one", Some(301), Some("/two")),
            ResponseAction::Ignore,
            "a hop is never the page"
        );
        t.note_document_request("https://a.example/two");
        let gen = match t.handle_response("https://a.example/two", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        t.store("https://a.example/two", gen, Ok(b"final".to_vec()));
        assert_eq!(t.serve("https://a.example/one"), None, "the hop is not the page");
        assert_eq!(t.serve("https://a.example/two"), Some(Ok(b"final".to_vec())));
    }

    #[test]
    fn an_unresolvable_redirect_target_fails_closed() {
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        assert_eq!(
            t.handle_response("https://a.example/p", Some(302), Some("mailto:x@y.z")),
            ResponseAction::Ignore
        );
        assert_eq!(
            t.handle_response("https://a.example/p", Some(200), None),
            ResponseAction::Ignore,
            "the chain is dropped, not left armed"
        );
    }

    #[test]
    fn bytes_are_never_served_for_a_different_page() {
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        let gen = match t.handle_response("https://a.example/p", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        t.store("https://a.example/p", gen, Ok(b"p".to_vec()));
        assert_eq!(t.serve("https://a.example/other"), None);
    }

    #[test]
    fn a_fragment_link_still_serves_the_same_page() {
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        let gen = match t.handle_response("https://a.example/p", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        t.store("https://a.example/p", gen, Ok(b"p".to_vec()));
        assert_eq!(t.serve("https://a.example/p#section"), Some(Ok(b"p".to_vec())));
    }

    #[test]
    fn a_recorded_failure_is_served_as_that_failure() {
        let mut t = MainResourceTracker::new();
        nav(&mut t, "https://a.example/p");
        let gen = match t.handle_response("https://a.example/p", Some(200), None) {
            ResponseAction::FetchContent { generation } => generation,
            other => panic!("{other:?}"),
        };
        t.store("https://a.example/p", gen, Err(PageBytesError::TooLarge));
        assert_eq!(
            t.serve("https://a.example/p"),
            Some(Err(PageBytesError::TooLarge))
        );
    }

    #[test]
    fn the_document_uri_list_is_bounded() {
        // A redirect loop must not grow this without limit.
        let mut t = MainResourceTracker::new();
        t.begin_navigation("https://a.example/0");
        for i in 0..(MAX_DOCUMENT_URIS + 50) {
            t.note_document_request(&format!("https://a.example/{i}"));
        }
        assert_eq!(t.document_uris.len(), MAX_DOCUMENT_URIS);
    }

    #[test]
    fn non_http_pages_capture_nothing() {
        let mut t = MainResourceTracker::new();
        t.begin_navigation("about:blank");
        t.note_document_request("about:blank");
        assert_eq!(
            t.handle_response("about:blank", Some(200), None),
            ResponseAction::Ignore
        );
    }

    // --- Cap --------------------------------------------------------------

    #[test]
    fn the_cap_reports_rather_than_truncating() {
        let mut buf = Vec::new();
        assert!(push_capped(&mut buf, b"hello").is_ok());
        let huge = vec![0u8; MAX_MAIN_RESOURCE_BYTES];
        assert_eq!(push_capped(&mut buf, &huge), Err(PageBytesError::TooLarge));
        assert_eq!(buf, b"hello", "a refused push must not append part of it");
    }

    #[test]
    fn the_cap_admits_exactly_the_limit() {
        let mut buf = Vec::new();
        let exact = vec![0u8; MAX_MAIN_RESOURCE_BYTES];
        assert!(push_capped(&mut buf, &exact).is_ok());
        assert_eq!(push_capped(&mut buf, b"x"), Err(PageBytesError::TooLarge));
    }
}
