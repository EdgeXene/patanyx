#![forbid(unsafe_code)]
//! patanyx-corroborate — corroborated page views.
//!
//! When two people who trust each other open the same URL, their browsers
//! can compare what each was actually *served*. Differing content means one
//! of them is being shown something the other is not — which is how targeted
//! manipulation and personalised censorship become visible at all. This
//! crate is the comparison protocol layer: message shapes, a verdict
//! function, and URL normalisation. It is pure logic. It does no I/O, knows
//! nothing about transport, and never reads a clock (timestamps are supplied
//! by the caller).
//!
//! It builds on the integrity crate's digest *ladder* (raw bytes →
//! structure → visible text → fuzzy similarity) and reimplements none of
//! that. The ladder matters because two loads of the same page routinely
//! differ in bytes for innocent reasons; the useful question is usually "is
//! the visible text the same", not "are the bytes identical".
//!
//! # What this proves, and what it does not — read before building UI on it
//!
//! 1. **This detects a SERVER treating two viewers differently.** A
//!    "different" verdict means the two browsers were not served the same
//!    content. It cannot tell you that content shown identically to both is
//!    *true* — a server can lie to everyone at once, and "we saw the same
//!    thing" is not "we saw the truth".
//! 2. **It is for public URLs.** It does not work on logged-in or
//!    legitimately personalised pages, where differences are the product
//!    working as intended, not manipulation.
//! 3. **It assumes the peer is honest.** Messages are expected to arrive
//!    over a channel that authenticates *who* sent them (the caller's
//!    responsibility — there is deliberately no identity layer here). That
//!    proves a message came from the peer; nothing stops a dishonest peer
//!    lying about what they saw. This is a tool for mutual verification
//!    between people who already trust each other, not a defence against
//!    the peer.
//! 4. **Innocent differences are common.** Timestamps, A/B tests, CDN
//!    variance, ad slots, regionalisation. The ladder exists precisely so
//!    the answer can be "the visible text is identical" rather than a false
//!    alarm about bytes — and even a text difference needs a human to ask
//!    whether it's a timestamp or a changed headline.
//!
//! A feature that overclaims here is worse than no feature. Every string
//! this crate produces is written to be safe to show a user verbatim.

mod url;

use serde::{Deserialize, Serialize};
use std::fmt;

// The draft's open question here -- whether the lib target is `integrity` or
// `patanyx_integrity` -- was answered by the line below compiling: it is
// `patanyx_integrity`, and the items are imported by name. The module alias
// that sat beside it (`use patanyx_integrity as integrity;`) was never used
// and is removed rather than left as a second way to name the same crate.
use patanyx_integrity::{compare, digest, ContentDigest, IntegrityError, Verdict as IntegrityVerdict};

pub use url::{normalize_url, NormalizedUrl};

/// Bumped when the message shapes change incompatibly. Decoding rejects any
/// other version rather than guessing at the peer's intent.
pub const PROTOCOL_VERSION: u32 = 1;

/// Generous ceiling for one encoded message. A real message is a few
/// kilobytes (three hashes plus a 64-word sketch); the cap exists so a
/// hostile or buggy peer cannot make us allocate without bound.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CorroborateError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("the two browsers did not open the same page ({ours} vs {theirs})")]
    UrlMismatch { ours: String, theirs: String },
    #[error("message too large: {len} bytes (max {max})")]
    MessageTooLarge { len: usize, max: usize },
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("malformed protocol message: {0}")]
    MalformedMessage(String),
    #[error("could not digest the page: {0}")]
    Integrity(#[from] IntegrityError),
}

/// "I have opened this URL; here is my digest ladder and when I fetched it."
///
/// `url` is always the NORMALIZED form (see [`normalize_url`]) so both sides
/// compare the same canonical address; the constructors enforce this.
/// `fetched_at` is unix seconds, supplied by the caller — a large gap
/// between the two fetch times weakens the comparison, and the verdict
/// reports it rather than hiding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareRequest {
    pub version: u32,
    pub url: String,
    pub fetched_at: u64,
    pub digest: ContentDigest,
}

/// The other side's ladder, for the same URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareResponse {
    pub version: u32,
    pub url: String,
    pub fetched_at: u64,
    pub digest: ContentDigest,
}

impl CompareRequest {
    pub fn new(url: &NormalizedUrl, fetched_at: u64, digest: ContentDigest) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            url: url.as_str().to_string(),
            fetched_at,
            digest,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CorroborateError> {
        serde_json::to_vec(self).map_err(|e| CorroborateError::MalformedMessage(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CorroborateError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CorroborateError::MessageTooLarge {
                len: bytes.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        let msg: Self = serde_json::from_slice(bytes)
            .map_err(|e| CorroborateError::MalformedMessage(e.to_string()))?;
        if msg.version != PROTOCOL_VERSION {
            return Err(CorroborateError::UnsupportedVersion(msg.version));
        }
        Ok(msg)
    }
}

impl CompareResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CorroborateError> {
        serde_json::to_vec(self).map_err(|e| CorroborateError::MalformedMessage(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CorroborateError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CorroborateError::MessageTooLarge {
                len: bytes.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        let msg: Self = serde_json::from_slice(bytes)
            .map_err(|e| CorroborateError::MalformedMessage(e.to_string()))?;
        if msg.version != PROTOCOL_VERSION {
            return Err(CorroborateError::UnsupportedVersion(msg.version));
        }
        Ok(msg)
    }
}

/// Build the request half of a comparison from a URL as the user typed it
/// and the exact bytes the browser was served.
pub fn begin_comparison(
    url_typed: &str,
    page_bytes: &[u8],
    fetched_at: u64,
) -> Result<CompareRequest, CorroborateError> {
    let url = normalize_url(url_typed)?;
    Ok(CompareRequest::new(&url, fetched_at, digest(page_bytes)?))
}

/// Build the response half. Fails with [`CorroborateError::UrlMismatch`]
/// when the page this browser actually opened is not the one the request is
/// about — comparing two different pages produces garbage, not insight.
pub fn respond(
    request: &CompareRequest,
    own_url_typed: &str,
    own_page_bytes: &[u8],
    own_fetched_at: u64,
) -> Result<CompareResponse, CorroborateError> {
    let own_url = normalize_url(own_url_typed)?;
    if own_url.as_str() != request.url {
        return Err(CorroborateError::UrlMismatch {
            ours: request.url.clone(),
            theirs: own_url.into_string(),
        });
    }
    Ok(CompareResponse {
        version: PROTOCOL_VERSION,
        url: own_url.into_string(),
        fetched_at: own_fetched_at,
        digest: digest(own_page_bytes)?,
    })
}

/// The human-meaningful result of comparing what two browsers were served.
///
/// The `Display` strings are deliberately honest about scope (see the module
/// docs) and are safe to show a user verbatim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Corroboration {
    /// The pages match at the structure level or better: either identical
    /// bytes, or every difference is content that legitimately varies per
    /// load (CSRF tokens, nonces, script/style bodies) which normalisation
    /// discards. The server treated both viewers the same.
    SameContent,
    /// The visible text is word-for-word identical, but the markup around
    /// it differs. The viewers read the same words; the server did not send
    /// them the same page.
    SameTextDifferentMarkup,
    /// The visible text differs. `similarity` is a 0.0..=1.0 Jaccard
    /// estimate over word shingles (1.0 = identical; unrelated texts score
    /// near 0.0).
    DifferentText { similarity: f32 },
}

impl fmt::Display for Corroboration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Corroboration::SameContent => f.write_str(
                "Both browsers were served the same content (ignoring details that \
                 legitimately change on every load, such as tokens and script bodies). \
                 This only means the server treated both viewers alike; it says nothing \
                 about whether the content is true.",
            ),
            Corroboration::SameTextDifferentMarkup => f.write_str(
                "The visible text is identical, but the markup around it differs. That is \
                 common with A/B tests, CDN variants, and ad slots — and it also means the \
                 server did not send both viewers the same page, only the same words.",
            ),
            Corroboration::DifferentText { similarity } => write!(
                f,
                "The visible text differs ({:.0}% similar). The two viewers were not served \
                 the same page. On a public page this can reveal targeted manipulation, but \
                 innocent causes (timestamps, regionalisation, A/B tests) are common, and \
                 this cannot say which version — if either — is the genuine one.",
                similarity * 100.0
            ),
        }
    }
}

/// The verdict plus the context needed to read it honestly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    pub corroboration: Corroboration,
    /// True only when the two copies were bit-for-bit identical. When
    /// `corroboration` is [`Corroboration::SameContent`] but this is false,
    /// the pages matched after ignoring per-load noise (tokens, nonces) —
    /// worth knowing, not worth alarming anyone over.
    pub byte_identical: bool,
    /// Seconds between the two fetches. A large gap weakens the comparison:
    /// the page may simply have been edited in between.
    pub fetch_gap_seconds: u64,
}

/// Compare what two browsers were served for the same URL.
///
/// This answers exactly one question: **did the server treat these two
/// viewers differently?** Read the module docs before surfacing the answer:
/// it cannot vouch for content both viewers saw identically, it is
/// meaningless on logged-in or personalised pages, it trusts the peer's
/// ladder to be honestly reported, and a "different" verdict has many
/// innocent explanations. Errors when the two messages are not about the
/// same (normalized) URL.
pub fn verdict(
    request: &CompareRequest,
    response: &CompareResponse,
) -> Result<Verdict, CorroborateError> {
    if request.url != response.url {
        return Err(CorroborateError::UrlMismatch {
            ours: request.url.clone(),
            theirs: response.url.clone(),
        });
    }
    let corroboration = match compare(&request.digest, &response.digest) {
        // Note: the integrity crate folds "raw bytes differ but only in
        // volatile content" into `Identical`, and so do we (exposed via
        // `byte_identical` rather than a scarier-sounding verdict). If the
        // reviewer splits that variant upstream, mirror the split here.
        IntegrityVerdict::Identical => Corroboration::SameContent,
        IntegrityVerdict::StructureDiffers => Corroboration::SameTextDifferentMarkup,
        IntegrityVerdict::TextDiffers { similarity } => {
            Corroboration::DifferentText { similarity }
        }
    };
    Ok(Verdict {
        corroboration,
        byte_identical: request.digest.raw == response.digest.raw,
        fetch_gap_seconds: request.fetched_at.abs_diff(response.fetched_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &[u8] = b"<!doctype html><html><body><p>Hello <b>world</b>, this is a public \
        page with a fair number of visible words in it.</p></body></html>";

    #[test]
    fn two_identical_pages_agree_at_every_rung() {
        let req = begin_comparison("https://news.example/article", PAGE, 1000).unwrap();
        // The peer typed the same address in a different but equivalent form.
        let resp = respond(&req, "news.example/article", PAGE, 1005).unwrap();

        // Every rung of the ladder agrees, not just the verdict.
        assert_eq!(req.digest.raw, resp.digest.raw);
        assert_eq!(req.digest.structure, resp.digest.structure);
        assert_eq!(req.digest.text, resp.digest.text);
        assert_eq!(req.digest.minhash, resp.digest.minhash);

        let v = verdict(&req, &resp).unwrap();
        assert_eq!(v.corroboration, Corroboration::SameContent);
        assert!(v.byte_identical);
        assert_eq!(v.fetch_gap_seconds, 5);
    }

    #[test]
    fn page_differing_only_in_a_token_agrees_on_visible_text() {
        // Two loads of the same form page: different CSRF token, different
        // nonce attribute, different inline script body — all volatile.
        let page_a: &[u8] = br#"<!doctype html>
<html><head><script>var seed=11111;</script><meta name="csrf-token" content="aB3x9Kp2Lm7Qw8Rt5Yu1Io6Pz4"></head>
<body><div class="wrap" nonce="n0nceValueAAAA1111"><h1>Transfer</h1><form method="post"><input type="submit" value="Send"></form></div></body></html>"#;
        let page_b: &[u8] = br#"<!doctype html>
<html><head><script>var seed=99999;</script><meta name="csrf-token" content="Zz9Y8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0P"></head>
<body><div class="wrap" nonce="differentNonce9999"><h1>Transfer</h1><form method="post"><input type="submit" value="Send"></form></div></body></html>"#;
        let req = begin_comparison("https://bank.example/transfer", page_a, 100).unwrap();
        let resp = respond(&req, "https://bank.example/transfer", page_b, 101).unwrap();

        assert_ne!(req.digest.raw, resp.digest.raw, "bytes genuinely differ");
        assert_eq!(
            req.digest.text, resp.digest.text,
            "a token-only difference must leave the visible text identical"
        );
        let v = verdict(&req, &resp).unwrap();
        assert_eq!(v.corroboration, Corroboration::SameContent);
        assert!(!v.byte_identical);
    }

    #[test]
    fn same_words_in_different_markup_is_markup_level_agreement() {
        let req = begin_comparison("https://example.com/", b"<p>Hello brave new world</p>", 1)
            .unwrap();
        let resp = respond(
            &req,
            "https://example.com/",
            b"<div>Hello <span>brave</span> new world</div>",
            2,
        )
        .unwrap();
        let v = verdict(&req, &resp).unwrap();
        assert_eq!(v.corroboration, Corroboration::SameTextDifferentMarkup);
    }

    #[test]
    fn genuinely_different_text_disagrees() {
        let page_a: &[u8] =
            b"<p>The committee published the report on Tuesday morning after a long debate about rising prices</p>";
        let page_b: &[u8] =
            b"<p>The committee published the letter on Tuesday morning after a long debate about rising prices</p>";
        let req = begin_comparison("https://news.example/story", page_a, 10).unwrap();
        let resp = respond(&req, "https://news.example/story", page_b, 11).unwrap();
        assert_ne!(req.digest.text, resp.digest.text);
        match verdict(&req, &resp).unwrap().corroboration {
            Corroboration::DifferentText { similarity } => {
                // One word in sixteen changed: clearly below 1.0, clearly
                // above unrelated text. Bounds conservative; the estimate
                // itself is deterministic.
                assert!(
                    (0.3..1.0).contains(&similarity),
                    "small edit should score high but below 1.0, got {similarity}"
                );
            }
            other => panic!("expected DifferentText, got {other:?}"),
        }
    }

    #[test]
    fn verdict_refuses_two_different_pages() {
        let req = begin_comparison("https://a.example/", PAGE, 1).unwrap();
        let mut resp = respond(&req, "https://a.example/", PAGE, 2).unwrap();
        resp.url = "https://b.example/".to_string();
        assert!(matches!(
            verdict(&req, &resp),
            Err(CorroborateError::UrlMismatch { .. })
        ));
    }

    #[test]
    fn respond_refuses_when_the_peer_opened_a_different_page() {
        let req = begin_comparison("https://a.example/", PAGE, 1).unwrap();
        assert!(matches!(
            respond(&req, "https://b.example/", PAGE, 2),
            Err(CorroborateError::UrlMismatch { .. })
        ));
    }

    #[test]
    fn messages_survive_an_encoded_round_trip() {
        let req = begin_comparison("https://news.example/article", PAGE, 42).unwrap();
        let bytes = req.to_bytes().unwrap();
        let back = CompareRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back.url, req.url);
        assert_eq!(back.fetched_at, 42);
        assert_eq!(back.digest, req.digest);

        let resp = respond(&req, "https://news.example/article", PAGE, 43).unwrap();
        let back = CompareResponse::from_bytes(&resp.to_bytes().unwrap()).unwrap();
        assert_eq!(back.digest, resp.digest);
    }

    #[test]
    fn foreign_versions_and_bloated_messages_are_rejected() {
        let req = begin_comparison("https://news.example/", PAGE, 1).unwrap();
        let json = String::from_utf8(req.to_bytes().unwrap()).unwrap();
        let newer = json.replace("\"version\":1", "\"version\":99");
        assert!(matches!(
            CompareRequest::from_bytes(newer.as_bytes()),
            Err(CorroborateError::UnsupportedVersion(99))
        ));
        let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            CompareRequest::from_bytes(&big),
            Err(CorroborateError::MessageTooLarge { .. })
        ));
    }
}
