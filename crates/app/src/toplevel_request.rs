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
pub(crate) fn identity(url: &str) -> &str {
    match url.find('#') {
        Some(i) => &url[..i],
        None => url,
    }
}

/// A URL compared for identity when ONE side came from the browser's own code
/// rather than from the engine: an app-issued navigation is announced with the
/// URL as the app holds it (`http://192.168.1.1`, `HTTP://Router.localhost:80`),
/// and the engine reports it normalized (`http://192.168.1.1/`). Parsed and
/// re-serialized, which lowercases scheme and host, drops a default port and
/// supplies the root path; fragment removed as in `identity`. A string the
/// parser refuses is compared as `identity` gives it (final review 3, R-004).
pub(crate) fn normalized_identity(url: &str) -> String {
    match url::Url::parse(url.trim()) {
        Ok(mut parsed) => {
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => identity(url).to_string(),
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
    /// Whether THIS hop may take the tab to a private address, decided when
    /// the hop started, from who sent the tab there (see
    /// `TabState::on_top_level_navigation_starting`). Only the local-network
    /// exemption reads it; the banner does not.
    reaches_private: bool,
}

/// What the correlation knows about the request it matched.
#[derive(Debug, PartialEq, Eq)]
pub struct TopLevelHop {
    /// The complete navigation URL, fragment included (R-006).
    pub url: String,
    /// See `InFlight::reaches_private`.
    pub reaches_private: bool,
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
    /// Subframe navigations in flight, keyed by THEIR NavigationId, holding
    /// the fragment-stripped target of the current hop.
    ///
    /// Consulted ONLY by `frame_may_be_navigating_to`, which the local-network
    /// exemption asks; `take_top_level_hop` never reads it (see below
    /// for why the banner must not). Keyed by id, not URL, because the frame
    /// completion event carries only the id: its sender is the WebView, whose
    /// Source is the TOP-LEVEL document (R-005).
    frames_in_flight: BTreeMap<u64, String>,
    /// Whether the frame events are wired at all. Until the platform says so,
    /// an empty `frames_in_flight` means "not watching", not "no frames", and
    /// the exemption must not be granted on it (final review R-001).
    frame_tracking: bool,
    /// A frame navigation started whose target or id could not be read. Its
    /// URL is unknown, so until the document it belongs to is replaced it may
    /// be the URL of any request (final review R-001).
    frame_unreadable: bool,
}

// THE BANNER DOES NOT CONSULT THE SUBFRAME SET, and once did. Two drafts made
// `take_top_level_document` decline while a frame navigation to the same URL
// was in flight, so a frame to X could not consume the slot when the user
// navigated the top level to X. The second draft keyed them correctly and
// still had to go: with a frame to X outstanding, the PAGE'S OWN document
// request for X was refused as "a frame exists", answered with the ordinary
// 403, and the user got the engine error page with no banner, which is the
// original defect (review R-003, round 3). A refusal cannot be recovered; the
// request is already answered.
//
// Ordering is the only tie-break the engine allows, and for the banner it is
// enough: the first document request matching an in-flight top-level hop is
// the page. The residual case, a frame of the OLD document to the same URL
// whose request happens to arrive first, consumes the slot and loses the
// banner. That is rare, fails closed, and cannot manufacture a banner: a frame
// can only contend when a top-level navigation to that URL is genuinely in
// flight.
//
// The set came back for a different consumer with the opposite stake. The
// local-network boundary exempts the tab's own top-level document, and there
// the same residual is not a lost banner: a frame of the old page that wins
// the race would be the request that reaches the router. So the EXEMPTION
// asks `frame_may_be_navigating_to` and is withheld under contention, which
// fails closed in the direction that boundary needs, while the banner keeps
// the ordering rule above unchanged.

impl TopLevelRequests {
    /// `NavigationStarting`: top frame only on WebView2.
    pub fn on_navigation_starting(&mut self, navigation_id: u64, uri: &str, reaches_private: bool) {
        // NOT the place to drop the old document's frames, and the first
        // draft did. A navigation START is precisely when the old document
        // is still displayed and its frames are still loading, so it is the
        // contention window: a frame to X in flight while the user navigates
        // the top level to X. Clearing here threw that protection away. The
        // old frames go when the new document starts loading, in
        // `on_document_committed`.
        self.in_flight.insert(
            navigation_id,
            InFlight {
                uri: identity(uri).to_string(),
                full_url: uri.to_string(),
                // A redirect hop is a NEW document request, so this resets
                // even when the entry already existed.
                document_seen: false,
                reaches_private,
            },
        );
    }

    /// The current hop of a top-level navigation in flight, as its
    /// NavigationStarting gave it. `Some` for an id already in flight is how a
    /// redirect hop is told from a first hop, and it is the URL a commit for
    /// that id loaded.
    pub fn hop_url(&self, navigation_id: u64) -> Option<&str> {
        self.in_flight.get(&navigation_id).map(|e| e.full_url.as_str())
    }

    /// `NavigationCompleted`, success or failure. A navigation that ended can
    /// no longer explain a request, and leaving it in would let a later
    /// same-URL frame be mistaken for the page.
    pub fn on_navigation_completed(&mut self, navigation_id: u64) {
        self.in_flight.remove(&navigation_id);
    }

    /// `ContentLoading` for the navigation with this id: a new document is
    /// replacing the old one, whose frames go with it. A frame torn down that
    /// way may never report completion; left in the set, its URL would
    /// withhold the exemption from every later typed navigation to it.
    ///
    /// WHY THIS EVENT (final review R-002). The first draft cleared on a
    /// successful NavigationCompleted, and both halves of that were wrong: the
    /// completion arrives after the NEW document's frames have started, so it
    /// dropped live entries, and a success is not proof the document was
    /// replaced (a same-document navigation is not a new page). ContentLoading
    /// comes before the new document has parsed a single frame, and is not
    /// raised for same-document navigations, so at that moment every entry in
    /// the set belongs to the document being replaced.
    ///
    /// Only for a TOP-LEVEL navigation in flight. The id is checked against
    /// the hops `on_navigation_starting` recorded, so an event carrying any
    /// other id, a frame's included, clears nothing. An unreadable id is never
    /// passed in: keeping a stale entry withholds an exemption, forgetting a
    /// live one could grant it.
    pub fn on_document_committed(&mut self, navigation_id: u64) {
        if self.in_flight.contains_key(&navigation_id) {
            self.frames_in_flight.clear();
            self.frame_unreadable = false;
        }
    }

    /// The platform wired `FrameNavigationStarting`. Without this call no
    /// document request is ever exempted: see `frame_tracking`.
    pub fn on_frame_tracking_registered(&mut self) {
        self.frame_tracking = true;
    }

    /// `FrameNavigationStarting`: subframes only. Re-fires per redirect hop
    /// with the same id and the new URI, so the entry follows the hop.
    pub fn on_frame_navigation_starting(&mut self, navigation_id: u64, uri: &str) {
        self.frames_in_flight
            .insert(navigation_id, identity(uri).to_string());
    }

    /// `FrameNavigationStarting` whose URI or id could not be read. Where that
    /// frame is going is unknown, so it may be going anywhere until its
    /// document is replaced.
    pub fn on_frame_navigation_unreadable(&mut self) {
        self.frame_unreadable = true;
    }

    /// `FrameNavigationCompleted`, by the frame navigation's own id (R-005).
    pub fn on_frame_navigation_completed(&mut self, navigation_id: u64) {
        self.frames_in_flight.remove(&navigation_id);
    }

    /// Whether a subframe navigation may be heading for this URL, in which
    /// case a document request for it may be that frame's rather than the
    /// page's, whatever `take_top_level_hop` concluded. Not consuming.
    ///
    /// Answers YES whenever it cannot know: frame events not wired, or a frame
    /// navigation whose target could not be read. The one caller is an
    /// exemption, and an exemption granted on missing evidence is the
    /// direction this must never fail in (final review R-001).
    pub fn frame_may_be_navigating_to(&self, request_uri: &str) -> bool {
        if !self.frame_tracking || self.frame_unreadable {
            return true;
        }
        let wanted = identity(request_uri);
        self.frames_in_flight.values().any(|uri| uri == wanted)
    }

    /// `take_top_level_hop`, URL only. Test-only since the request handler
    /// moved to `take_top_level_hop`; the banner-correlation tests read the
    /// URL alone.
    #[cfg(test)]
    pub fn take_top_level_document(&mut self, request_uri: &str) -> Option<String> {
        self.take_top_level_hop(request_uri).map(|hop| hop.url)
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
    /// included, which is what consent must resume, and whether the hop may
    /// reach a private address. `None` is "not the page".
    pub fn take_top_level_hop(&mut self, request_uri: &str) -> Option<TopLevelHop> {
        let wanted = identity(request_uri);
        // Two navigations in flight to one URL, one the user's and one the
        // page's (a POST, say), are indistinguishable at the request: it
        // carries no navigation id, so a request cannot be told apart from
        // another request for the same URL either. While ANY hop to this URL
        // that may not reach a private address is in flight, matched or not,
        // no request for the URL is allowed to: every hop to it is marked so,
        // and the refusal outlives the request that first met it (plan review
        // 2, M-4; final review 3, R-002).
        let refused = self
            .in_flight
            .values()
            .find(|e| e.uri == wanted && !e.reaches_private)
            .map(|e| e.full_url.clone());
        if refused.is_some() {
            for entry in self.in_flight.values_mut().filter(|e| e.uri == wanted) {
                entry.reaches_private = false;
            }
        }
        match self
            .in_flight
            .values_mut()
            .find(|e| !e.document_seen && e.uri == wanted)
        {
            Some(entry) => {
                entry.document_seen = true;
                Some(TopLevelHop {
                    url: entry.full_url.clone(),
                    reaches_private: entry.reaches_private,
                })
            }
            // Every hop to this URL already had its document request, and one
            // of them was refused. This request may be the refused hop's own
            // (a frame took its slot first), so it is refused as that hop,
            // not judged as an ordinary request against the page on screen.
            None => refused.map(|url| TopLevelHop {
                url,
                reaches_private: false,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "https://ipaddress.com/lookup";

    #[test]
    fn a_navigated_page_is_the_top_level_document() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, PAGE, true);
        assert!(t.take_top_level_document(PAGE).is_some());
    }


    /// R3-1. The request URI never carries the fragment; the navigation URL
    /// does. Raw comparison would break every in-page link.
    #[test]
    fn a_fragment_on_the_navigation_still_correlates() {
        let mut t = TopLevelRequests::default();
        t.on_navigation_starting(1, "https://ipaddress.com/lookup#result", true);
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
        t.on_navigation_starting(7, "https://short.example/x", true);
        assert!(t.take_top_level_document("https://short.example/x").is_some());
        // 302 to the listed host, same navigation id.
        t.on_navigation_starting(7, PAGE, true);
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
        t.on_navigation_starting(1, PAGE, true);
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
        t.on_navigation_starting(1, PAGE, true);
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
        t.on_navigation_starting(1, PAGE, true);
        t.on_navigation_starting(2, "https://whatismyip.com/", true);
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
        t.on_navigation_starting(1, "https://news.example/", true);
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
        t.on_navigation_starting(1, PAGE, true);
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
        t.on_navigation_starting(1, PAGE, true);
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
        t.on_navigation_starting(1, "https://ipaddress.com/lookup#result", true);
        assert_eq!(
            t.take_top_level_document(PAGE).as_deref(),
            Some("https://ipaddress.com/lookup#result"),
            "the fragment was lost between the navigation and the pending, so \
             Open anyway would resume the wrong place"
        );
    }

    /// R-003, round 3, kept true now that the frame set is back: the BANNER's
    /// correlation never reads it. A frame to X in flight must not refuse the
    /// page's own document request for X.
    #[test]
    fn the_banner_correlation_ignores_in_flight_frames() {
        let mut t = tracked();
        t.on_frame_navigation_starting(9, PAGE);
        t.on_navigation_starting(1, PAGE, true);
        assert!(t.frame_may_be_navigating_to(PAGE));
        assert!(
            t.take_top_level_document(PAGE).is_some(),
            "an in-flight frame cost the page its banner again"
        );
    }

    /// Frame tracking as the Windows backend leaves it once the frame events
    /// registered.
    fn tracked() -> TopLevelRequests {
        let mut t = TopLevelRequests::default();
        t.on_frame_tracking_registered();
        t
    }

    /// Final review R-001. With the frame events not wired, an empty set means
    /// "not watching", and the answer must be "a frame may be going there".
    #[test]
    fn unwired_frame_tracking_vouches_for_nothing() {
        let t = TopLevelRequests::default();
        assert!(
            t.frame_may_be_navigating_to(PAGE),
            "an unwired tracker vouched that no frame was heading for the page's URL"
        );
        assert!(!tracked().frame_may_be_navigating_to(PAGE));
    }

    /// Final review R-001. A frame navigation whose target could not be read
    /// may be going anywhere, until the document it belongs to is replaced.
    #[test]
    fn an_unreadable_frame_contends_with_every_url_until_the_page_changes() {
        let mut t = tracked();
        t.on_frame_navigation_unreadable();
        assert!(t.frame_may_be_navigating_to(PAGE));
        assert!(t.frame_may_be_navigating_to("http://192.168.1.1/"));
        t.on_navigation_starting(1, "http://news.example/", true);
        t.on_document_committed(1);
        assert!(!t.frame_may_be_navigating_to(PAGE));
    }

    /// R-005. Frame completion carries only the frame's own navigation id.
    #[test]
    fn a_frame_leaves_the_set_by_its_own_id() {
        let mut t = tracked();
        t.on_frame_navigation_starting(9, PAGE);
        t.on_navigation_completed(9); // a TOP-LEVEL id that happens to match
        assert!(t.frame_may_be_navigating_to(PAGE), "a top-level completion removed a frame");
        t.on_frame_navigation_completed(1);
        assert!(t.frame_may_be_navigating_to(PAGE), "another frame's completion removed it");
        t.on_frame_navigation_completed(9);
        assert!(!t.frame_may_be_navigating_to(PAGE));
    }

    /// A frame's redirect hop re-fires with the same id; the entry follows the
    /// hop, so a frame redirected onto X is caught and its old target is not.
    #[test]
    fn a_frame_redirect_hop_moves_its_entry() {
        let mut t = tracked();
        t.on_frame_navigation_starting(9, "http://slow.example/r");
        assert!(!t.frame_may_be_navigating_to(PAGE));
        t.on_frame_navigation_starting(9, PAGE);
        assert!(t.frame_may_be_navigating_to(PAGE));
        assert!(!t.frame_may_be_navigating_to("http://slow.example/r"));
    }

    /// Same identity rule as the top-level match: the request URI never has
    /// the fragment.
    #[test]
    fn frame_contention_ignores_the_fragment() {
        let mut t = tracked();
        t.on_frame_navigation_starting(9, "https://ipaddress.com/lookup#x");
        assert!(t.frame_may_be_navigating_to(PAGE));
    }

    /// A new top-level document takes the old one's frames with it, so a frame
    /// that never reported completion cannot shadow its URL for the life of
    /// the tab.
    #[test]
    fn a_new_top_level_document_clears_the_frame_set() {
        let mut t = tracked();
        t.on_frame_navigation_starting(9, PAGE);
        t.on_navigation_starting(1, "http://news.example/", true);
        t.on_document_committed(1);
        assert!(!t.frame_may_be_navigating_to(PAGE));
    }

    /// Final review R-002. Only a TOP-LEVEL navigation in flight replaces the
    /// document. An id nothing recorded (a frame's, or a navigation already
    /// finished) must clear nothing, or any stray event would wipe the set.
    #[test]
    fn only_an_in_flight_top_level_navigation_clears_the_frame_set() {
        let mut t = tracked();
        t.on_frame_navigation_starting(9, PAGE);
        t.on_document_committed(9);
        assert!(t.frame_may_be_navigating_to(PAGE), "a frame's own id cleared the set");
        t.on_navigation_starting(1, "http://news.example/", true);
        t.on_navigation_completed(1);
        t.on_document_committed(1);
        assert!(t.frame_may_be_navigating_to(PAGE), "a finished navigation cleared the set");
    }



}
