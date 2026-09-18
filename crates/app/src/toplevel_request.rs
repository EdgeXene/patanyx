//! Which intercepted request is the TOP-LEVEL DOCUMENT, on WebView2.
//!
//! WHY THIS EXISTS AT ALL. The ad-list banner may only be raised for a page the
//! user navigated to. Enforcement on Windows happens in the request handler
//! (the navigation handler's refusal is not honoured: windows.rs:2466,
//! measured on hardware 2026-07-29), so the question "is this request the page
//! itself, or something the page asked for" has to be answered THERE. Get it
//! wrong in the permissive direction and any page can raise a banner with a
//! one-line hidden iframe, and the "Open anyway" under it grants a real,
//! host-wide override for the tab. That is a consent-spoofing surface, not a
//! cosmetic bug.
//!
//! WHAT THE ENGINE WILL NOT TELL US, checked against the pinned bindings
//! (webview2-com 0.38.2) rather than assumed:
//!
//! - `ICoreWebView2WebResourceRequestedEventArgs` exposes Request, Response,
//!   SetResponse, GetDeferral and ResourceContext. Args2 adds
//!   RequestedSourceKind. There is NO NavigationId and NO frame id anywhere on
//!   that path, so a request cannot name the navigation it belongs to.
//! - `RequestedSourceKind` is ALL / DOCUMENT / NONE / SERVICE_WORKER /
//!   SHARED_WORKER: DOCUMENT there means "not a worker", not "not an iframe".
//! - `ResourceContext` has DOCUMENT but no subframe variant, so a top-level
//!   document request and an iframe's document request are indistinguishable
//!   by context alone.
//!
//! WHAT IT WILL. `NavigationStarting` fires for the TOP FRAME ONLY, and
//! `FrameNavigationStarting` fires for subframes -- a split windows.rs already
//! relies on for tracking-parameter stripping. So the correlation is built from
//! the navigation events and consulted from the request handler: a DOCUMENT
//! request is the top-level document exactly when it matches a top-level
//! navigation that is in flight and has not yet had its document request.
//!
//! Pure, and tested on every platform, because the rule is the dangerous part
//! and a rule that can only be exercised on one tester's laptop is a rule
//! nobody checks.

use std::collections::BTreeMap;

/// A URL compared for identity, not for display: the fragment is removed.
///
/// R3-1. The intercepted request URI NEVER carries a fragment -- the engine
/// resolves it client side -- while the navigation URL does. Comparing them
/// raw makes every navigation to `page#section` fail to correlate, which fails
/// CLOSED (no banner, an engine error page) rather than open, but it fails on
/// exactly the ordinary case of following an in-page link. The fragment is
/// kept on the pending itself, so consent still resumes the complete URL.
fn identity(url: &str) -> &str {
    match url.find('#') {
        Some(i) => &url[..i],
        None => url,
    }
}

#[derive(Debug)]
struct InFlight {
    /// Fragment-stripped target of the CURRENT hop, for matching.
    uri: String,
    /// The hop's target AS THE NAVIGATION EVENT GAVE IT, fragment included.
    ///
    /// R3-1 and R-006. The intercepted request URI never carries a fragment,
    /// so if the pending were built from the request, "Open anyway" on
    /// `page#section` would resume `page` and lose the anchor, or a whole
    /// fragment-routed application state. The navigation event is the only
    /// place the complete URL survives, so it is kept here and handed back
    /// when the request is matched.
    full_url: String,
    /// Whether this hop's document request has already been matched.
    ///
    /// This is the tie-break for a page that embeds ITSELF, or a redirect that
    /// lands a frame and the top level on the same URL. Set membership alone
    /// cannot separate those: the same string is legitimately both. Ordering
    /// can, because a subframe cannot begin before the top-level document it
    /// is written in has been received. So the FIRST matching document request
    /// for a hop is the page, and any later one with the same URL is a frame.
    document_seen: bool,
}

/// Per tab. Lives beside the tab's other native state and is consulted from
/// the request handler.
#[derive(Debug, Default)]
pub struct TopLevelRequests {
    /// Keyed by NavigationId, which the navigation events DO carry.
    ///
    /// `NavigationStarting` re-fires per REDIRECT HOP with the same id and the
    /// new URI, so an entry is updated rather than added, and the new hop has
    /// its own unseen document request. A map rather than a single slot
    /// because a tab can have more than one navigation in flight.
    in_flight: BTreeMap<u64, InFlight>,
}

// THERE IS NO SUBFRAME SET, and there was one. Two drafts tracked in-flight
// frame navigations so that a frame to X could not consume the slot when the
// user navigated the top level to X. The second draft keyed them correctly and
// still had to go: with a frame to X outstanding, the PAGE'S OWN document
// request for X was refused as "a frame exists", answered with the ordinary
// 403, and the user got the engine error page with no banner, which is the
// original defect (review R-003, round 3). A refusal cannot be recovered; the
// request is already answered.
//
// Ordering is the only tie-break the engine allows, and it is enough: the
// first document request matching an in-flight top-level hop is the page. The
// residual case, a frame of the OLD document to the same URL whose request
// happens to arrive first, consumes the slot and loses the banner. That is
// rare, fails closed, and cannot manufacture a banner: a frame can only
// contend when a top-level navigation to that URL is genuinely in flight.

impl TopLevelRequests {
    /// `NavigationStarting`: top frame only on WebView2.
    pub fn on_navigation_starting(&mut self, navigation_id: u64, uri: &str) {
        // NOT the place to drop the old document's frames, and the first
        // draft did. A navigation START is precisely when the old document
        // is still displayed and its frames are still loading, so it is the
        // contention window: a frame to X in flight while the user navigates
        // the top level to X. Clearing here threw that protection away. The
        // old frames go when the new document COMPLETES, below.
        self.in_flight.insert(
            navigation_id,
            InFlight {
                uri: identity(uri).to_string(),
                full_url: uri.to_string(),
                // A redirect hop is a NEW document request, so this resets
                // even when the entry already existed.
                document_seen: false,
            },
        );
    }

    /// `NavigationCompleted`, success or failure. A navigation that ended can
    /// no longer explain a request, and leaving it in would let a later
    /// same-URL frame be mistaken for the page.
    pub fn on_navigation_completed(&mut self, navigation_id: u64) {
        self.in_flight.remove(&navigation_id);
    }

    /// The whole question, asked once per DOCUMENT-context request.
    ///
    /// CONSUMING on purpose: answering true marks this hop's document request
    /// as taken, so a second request for the same URL is a frame. Calling this
    /// for a non-DOCUMENT request would consume the answer for something that
    /// is not the page, which is why the caller checks ResourceContext first.
    ///
    /// Fails CLOSED. An unmatched request is treated as not-top-level, so the
    /// worst case is a listed subresource getting the silent refusal it would
    /// have got anyway, never a banner for a page the user did not ask for.
    /// Returns the COMPLETE navigation URL for the matched hop, fragment
    /// included, which is what consent must resume. `None` is "not the page".
    pub fn take_top_level_document(&mut self, request_uri: &str) -> Option<String> {
        let wanted = identity(request_uri);
        let entry = self
            .in_flight
            .values_mut()
            .find(|e| !e.document_seen && e.uri == wanted)?;
        entry.document_seen = true;
        Some(entry.full_url.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "https://ipaddress.com/lookup";

    #[test]
    fn a_navigated_page_is_the_top_level_document() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, PAGE);
        assert!(t.take_top_level_document(PAGE).is_some());
    }


    /// R3-1. The request URI never carries the fragment; the navigation URL
    /// does. Raw comparison would break every in-page link.
    #[test]
    fn a_fragment_on_the_navigation_still_correlates() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, "https://ipaddress.com/lookup#result");
        assert!(
            t.take_top_level_document(PAGE).is_some(),
            "the fragment stopped the page correlating with its own request"
        );
    }

    /// Redirect hops re-fire with the SAME id and a new URI. Each hop has its
    /// own document request, and the banner must name where the user lands.
    #[test]
    fn each_redirect_hop_gets_its_own_document_request() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(7, "https://short.example/x");
        assert!(t.take_top_level_document("https://short.example/x").is_some());
        // 302 to the listed host, same navigation id.
        t.on_navigation_starting(7, PAGE);
        assert!(
            t.take_top_level_document(PAGE).is_some(),
            "the hop the user actually lands on was not treated as the page, \
             so a redirect into a listed host would get an engine error rather \
             than the banner"
        );
    }



    /// A finished navigation cannot explain a later request.
    #[test]
    fn a_completed_navigation_stops_explaining_requests() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, PAGE);
        t.on_navigation_completed(1);
        assert!(
            t.take_top_level_document(PAGE).is_none(),
            "a request after the navigation finished was still called the page"
        );
    }

    /// Two tabs' worth of navigation in one tab: a second navigation starting
    /// does not make the first one's request correlate again.
    #[test]
    fn one_navigation_yields_exactly_one_top_level_document() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, PAGE);
        assert!(t.take_top_level_document(PAGE).is_some());
        assert!(
            t.take_top_level_document(PAGE).is_none(),
            "one navigation produced two top-level documents, so one page \
             could raise two banners"
        );
    }

    /// Concurrent navigations in a tab are distinct ids and must not borrow
    /// each other's answer.
    #[test]
    fn concurrent_navigations_are_kept_apart() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, PAGE);
        t.on_navigation_starting(2, "https://whatismyip.com/");
        assert!(t.take_top_level_document("https://whatismyip.com/").is_some());
        assert!(
            t.take_top_level_document(PAGE).is_some(),
            "the other in-flight navigation's document request was consumed by \
             the wrong entry"
        );
    }

    /// Nothing in flight means nothing is the page. The unknown case must fail
    /// closed: a silent refusal, never a banner.
    #[test]
    fn an_uncorrelated_request_is_not_the_page() {
        let mut t = TopLevelRequests::default();
        assert!(t.take_top_level_document(PAGE).is_none());
    }

    /// The consent-spoofing case this module exists for. Nothing navigated the
    /// top frame to this URL, so nothing may be treated as the page: a page's
    /// hidden iframe to a listed host has no in-flight top-level hop to match.
    #[test]
    fn a_hidden_iframe_is_never_the_top_level_document() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, "https://news.example/");
        assert!(t.take_top_level_document("https://news.example/").is_some());
        // The page injects <iframe src=PAGE>. There is no top-level hop for it.
        assert!(
            t.take_top_level_document(PAGE).is_none(),
            "an iframe was taken for the page; a one-line iframe could raise a \
             banner and harvest a real override for a host the user never \
             navigated to"
        );
    }

    /// Ordering is the tie-break. A page that embeds ITSELF: the first
    /// document request for the hop is the page, the second is the frame.
    #[test]
    fn a_page_embedding_itself_yields_the_page_first_and_the_frame_second() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, PAGE);
        assert!(t.take_top_level_document(PAGE).is_some(), "the first is the page");
        assert!(
            t.take_top_level_document(PAGE).is_none(),
            "a same-URL iframe was taken for the page a second time"
        );
    }

    /// R-003, round 3. With a frame to X outstanding, the page's OWN request
    /// for X must still be the page. Two drafts refused it because a frame
    /// existed, answered it with a 403, and reproduced the original defect.
    #[test]
    fn a_frame_to_the_same_url_does_not_cost_the_page_its_banner() {
        let mut t = TopLevelRequests::default();
        // (a frame to PAGE is loading in the old document; no state is kept
        // for it, deliberately)
        t.on_navigation_starting(1, PAGE);
        assert!(
            t.take_top_level_document(PAGE).is_some(),
            "the page's own document request was refused because a frame to \
             the same URL existed; the user gets the engine error page"
        );
    }

    /// R-006. The request URI has no fragment; the navigation URL does; consent
    /// must resume the latter. The correlation is what carries it across.
    #[test]
    fn the_matched_hop_hands_back_the_complete_navigation_url() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, "https://ipaddress.com/lookup#result");
        assert_eq!(
            t.take_top_level_document(PAGE).as_deref(),
            Some("https://ipaddress.com/lookup#result"),
            "the fragment was lost between the navigation and the pending, so \
             Open anyway would resume the wrong place"
        );
    }



}
