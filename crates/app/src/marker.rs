//! The first-party marker: how PATANYX identifies itself to its own sites,
//! and to nothing else.
//!
//! WHY THIS EXISTS. The browser's page loads carry WebView2's stock user
//! agent, indistinguishable from Edge -- deliberately, because a browser
//! whose users can be picked out of traffic is the opposite of this product.
//! The cost is that our OWN analytics cannot tell a PATANYX visit to
//! patanyx.com from any other visit. So requests to the PATANYX first-party
//! domains, and only there, carry a marker that closes that gap without
//! widening what any other site can learn.
//!
//! WHAT IS SENT. `X-Patanyx: 1` on requests whose host is exactly one of the
//! four first-party names below, over https. Additionally
//! `X-Patanyx-Launch: 1` on the one navigation the browser makes by itself:
//! the first tab opening the home page. Both are constants -- no version, no
//! install id, no state. Every copy of PATANYX sends identical bytes, so the
//! marker says "a PATANYX browser" and can never say WHICH one.
//!
//! WHAT THIS GIVES UP, said plainly: an observer of traffic to the two
//! PATANYX domains (the sites themselves, or a middlebox that sees plaintext
//! after TLS termination) can distinguish PATANYX from Edge THERE. Nowhere
//! else -- the exact-host check below is the entire escape surface, and the
//! tests pin it. The header is also forgeable with one curl flag, so the
//! analytics on the receiving end may only ever claim "carried the marker",
//! never "was a person using PATANYX".
//!
//! WHY EXACT HOSTS AND NOT A SUFFIX. `ends_with("patanyx.net")` would match
//! `evilpatanyx.net`, and a subdomain wildcard would mark
//! `patanyx.edgexene.io` -- the update host, which must never be able to
//! tell one installation from another and is deliberately uninstrumented.

use wry::http::{HeaderMap, HeaderName, HeaderValue};

/// The only hosts the marker may ever reach. Exact, lowercase, no ports.
const OUR_HOSTS: [&str; 4] = [
    "patanyx.net",
    "www.patanyx.net",
    "patanyx.com",
    "www.patanyx.com",
];

/// Is this URL a first-party PATANYX page over https?
pub fn is_our_site(url: &str) -> bool {
    // Scheme first: the marker must not ride a downgraded connection.
    if !url.to_ascii_lowercase().starts_with("https://") {
        return false;
    }
    match crate::platform::privacy::host_of(url) {
        Some(host) => OUR_HOSTS.contains(&host.as_str()),
        None => false,
    }
}

/// Headers for an explicit navigation the app itself performs.
///
/// `launch` is true only for the first tab opening the home page -- the one
/// navigation nobody typed. Returns None for every non-first-party URL, so
/// call sites cannot attach the marker somewhere it must not go by
/// forgetting a check: the check IS the constructor.
pub fn headers_for(url: &str, launch: bool) -> Option<HeaderMap> {
    if !is_our_site(url) {
        return None;
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-patanyx"),
        HeaderValue::from_static("1"),
    );
    if launch {
        headers.insert(
            HeaderName::from_static("x-patanyx-launch"),
            HeaderValue::from_static("1"),
        );
    }
    Some(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_reaches_exactly_the_four_first_party_hosts() {
        for url in [
            "https://patanyx.net/",
            "https://www.patanyx.net/download/",
            "https://patanyx.com/quakes",
            "https://www.patanyx.com/?from=patanyx-net",
        ] {
            assert!(is_our_site(url), "{url} must carry the marker");
        }
    }

    #[test]
    fn the_marker_reaches_nothing_else() {
        // THE LOAD-BEARING TEST. Each of these is a distinct way the check
        // could leak: a lookalike suffix, a subdomain trick, the update host,
        // a downgraded scheme, a userinfo confusion, a port variant.
        for url in [
            "https://evilpatanyx.net/",
            "https://patanyx.net.evil.example/",
            "https://sub.patanyx.com/",
            "https://patanyx.edgexene.io/v1/manifest.json",
            "http://patanyx.net/",
            "https://patanyx.org/",
            "https://example.com/https://patanyx.net/",
            "https://patanyx.net@evil.example/",
            "not a url",
            "",
        ] {
            assert!(!is_our_site(url), "{url} must NOT carry the marker");
        }
    }

    #[test]
    fn headers_carry_no_state() {
        // Every copy of the browser must send identical bytes: a version, a
        // timestamp or an id here would turn a product marker into a tracking
        // header. The whole map is asserted, so a new header cannot appear
        // without failing this test.
        let plain = headers_for("https://patanyx.com/", false).unwrap();
        assert_eq!(plain.len(), 1);
        assert_eq!(plain.get("x-patanyx").unwrap(), "1");

        let launch = headers_for("https://patanyx.com/", true).unwrap();
        assert_eq!(launch.len(), 2);
        assert_eq!(launch.get("x-patanyx").unwrap(), "1");
        assert_eq!(launch.get("x-patanyx-launch").unwrap(), "1");
    }

    #[test]
    fn a_foreign_url_gets_no_headers_even_when_asked_for_launch() {
        assert!(headers_for("https://example.com/", true).is_none());
        assert!(headers_for("http://patanyx.com/", true).is_none());
    }
}
