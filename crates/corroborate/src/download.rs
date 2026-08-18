//! Download corroboration: did the server hand two people the same file?
//!
//! When two people who trust each other download "the same" installer or
//! document from the same URL, they can compare the SHA-256 of what each of
//! them actually received. Matching hashes mean both were served identical
//! bytes; differing hashes mean they were not, which is how a targeted
//! supply-chain swap (one person's installer quietly replaced with a
//! different build) becomes visible at all. This module is the comparison
//! protocol layer for that exchange: message shapes, refusal reasons, and a
//! verdict function. It is pure logic. It does no I/O, knows nothing about
//! transport, never hashes a file itself (each side supplies the digest of
//! its own download), and never reads a clock (`recorded_at` is supplied by
//! the caller).
//!
//! # What this proves, and what it does not: read before building UI on it
//!
//! 1. **This detects a SERVER treating two downloaders differently.** A
//!    "different" verdict means the two people were not served the same
//!    file. It cannot vouch for a file both received identically: a server
//!    can hand everyone the same poisoned build, and "we got the same bytes"
//!    is not "the bytes are safe".
//! 2. **It assumes the peer is honest.** Messages are expected to arrive
//!    over a channel that authenticates who sent them; authentication is the
//!    transport's job, and there is deliberately no identity layer here.
//!    Nothing stops a dishonest peer lying about what it downloaded. This is
//!    a tool for mutual verification between people who already trust each
//!    other, not a defense against the peer.
//! 3. **Hash differences have common innocent causes.** A new version
//!    published between the two downloads, per-platform or per-region builds,
//!    and CDN staleness all produce legitimately different files. The verdict
//!    states that the files differ; a human has to ask why.
//! 4. **The comparison is only as good as each side's own recorded hash.** If
//!    either record of what was downloaded is wrong or corrupted, a verdict
//!    built on it is worthless, which is why a contact whose own record
//!    failed its integrity check refuses rather than answers.
//!
//! A feature that overclaims here is worse than no feature. Every string this
//! module produces is written to be safe to show a user verbatim.
//!
//! # A note on the URL in errors
//!
//! Unlike page corroboration, a download URL is not assumed public and can
//! carry userinfo or signed query parameters. Two defenses keep such a URL
//! out of anything a user or a log sees. First, [`DownloadCompareRequest::
//! from_bytes`] and [`DownloadCompareResponse::from_bytes`] reject any URL
//! that is not already in canonical normalized form, so a peer cannot inject
//! control characters or a noncanonical address that would later be echoed.
//! Second, the caller matches the two URLs before asking for a verdict, so a
//! [`CorroborateError::UrlMismatch`] from [`download_verdict`] is an internal
//! inconsistency, not a user-facing state, and the app layer maps it to a
//! generic refusal rather than showing the error's text.

use super::{normalize_url, CorroborateError, NormalizedUrl, MAX_MESSAGE_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Bumped when the download message shapes change incompatibly. Decoding
/// rejects any other version rather than guessing at the peer's intent.
/// Independent of the page protocol's version: the two protocols evolve
/// separately.
pub const DOWNLOAD_PROTOCOL_VERSION: u32 = 1;

/// Rejects a decoded message whose `url` is not already in canonical
/// normalized form. The message crossed the transport from a peer, so its
/// URL is untrusted input: re-normalizing and requiring the result to equal
/// what arrived rejects control characters, embedded spaces, and any
/// noncanonical spelling that would otherwise produce a false mismatch or be
/// echoed into an error. `normalize_url`'s own idempotence is what makes this
/// a fixed point for a genuinely normalized address.
fn require_normalized(url: &str) -> Result<(), CorroborateError> {
    // Any unacceptable URL on decode is one error class, MalformedMessage, so
    // the app layer has a single "the peer's message was bad" case to handle
    // rather than telling InvalidUrl and a noncanonical form apart. The
    // normalize failure's reason is carried through for logs.
    let canonical = normalize_url(url).map_err(|e| {
        CorroborateError::MalformedMessage(format!("url does not normalize: {e}"))
    })?;
    if canonical.as_str() != url {
        return Err(CorroborateError::MalformedMessage(
            "url is not in canonical normalized form".to_string(),
        ));
    }
    Ok(())
}

/// "I downloaded a file from this URL; here is its SHA-256, its length in
/// bytes, and when I recorded it."
///
/// `url` is always the NORMALIZED form (see
/// [`normalize_url`](crate::normalize_url)) so both sides compare the same
/// canonical address; the constructor enforces this on the way out and
/// [`from_bytes`](Self::from_bytes) enforces it on the way in. `recorded_at`
/// is unix seconds, supplied by the caller: a large gap between the two
/// records weakens the comparison, and the verdict reports it rather than
/// hiding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadCompareRequest {
    pub version: u32,
    pub url: String,
    pub sha256: [u8; 32],
    pub byte_len: u64,
    pub recorded_at: u64,
}

/// The other side's record, for the same URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadCompareResponse {
    pub version: u32,
    pub url: String,
    pub sha256: [u8; 32],
    pub byte_len: u64,
    pub recorded_at: u64,
}

impl DownloadCompareRequest {
    pub fn new(url: &NormalizedUrl, sha256: [u8; 32], byte_len: u64, recorded_at: u64) -> Self {
        Self {
            version: DOWNLOAD_PROTOCOL_VERSION,
            url: url.as_str().to_string(),
            sha256,
            byte_len,
            recorded_at,
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
        if msg.version != DOWNLOAD_PROTOCOL_VERSION {
            return Err(CorroborateError::UnsupportedVersion(msg.version));
        }
        require_normalized(&msg.url)?;
        Ok(msg)
    }
}

impl DownloadCompareResponse {
    pub fn new(url: &NormalizedUrl, sha256: [u8; 32], byte_len: u64, recorded_at: u64) -> Self {
        Self {
            version: DOWNLOAD_PROTOCOL_VERSION,
            url: url.as_str().to_string(),
            sha256,
            byte_len,
            recorded_at,
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
        if msg.version != DOWNLOAD_PROTOCOL_VERSION {
            return Err(CorroborateError::UnsupportedVersion(msg.version));
        }
        require_normalized(&msg.url)?;
        Ok(msg)
    }
}

/// Why a contact did not answer a download comparison.
///
/// A refusal is NOT a verdict: it arrives instead of a
/// [`DownloadCompareResponse`], on its own channel, and says nothing about
/// whether the two files match. The wire form is a short machine word
/// ([`DownloadRefusal::as_str`]); a word received from a peer must go through
/// [`DownloadRefusal::parse`], which accepts only the closed set below, so an
/// arbitrary peer-supplied string can never reach the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadRefusal {
    /// The contact has no recorded download from that address.
    NoDownload,
    /// The contact's own record failed its integrity check, so its hash
    /// proves nothing.
    RecordUntrusted,
    /// The request did not parse.
    BadMessage,
    /// The contact's build cannot answer.
    Unsupported,
}

impl DownloadRefusal {
    /// The wire word for this reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            DownloadRefusal::NoDownload => "no_download",
            DownloadRefusal::RecordUntrusted => "record_untrusted",
            DownloadRefusal::BadMessage => "bad_message",
            DownloadRefusal::Unsupported => "unsupported",
        }
    }

    /// The sanitizer. Accepts exactly the four wire words; anything else
    /// (wrong case, stray whitespace, an invented reason) is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "no_download" => Some(DownloadRefusal::NoDownload),
            "record_untrusted" => Some(DownloadRefusal::RecordUntrusted),
            "bad_message" => Some(DownloadRefusal::BadMessage),
            "unsupported" => Some(DownloadRefusal::Unsupported),
            _ => None,
        }
    }
}

/// The human-meaningful result of comparing what two people downloaded.
///
/// The `Display` strings are deliberately honest about scope (see the module
/// docs) and are safe to show a user verbatim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DownloadCorroboration {
    /// The two recorded hashes match: both downloaders were served
    /// byte-identical files. This says nothing about whether the file is
    /// safe.
    HashEqual,
    /// The two recorded hashes differ: the downloaders were not served the
    /// same file. This has common innocent causes; the `Display` text says
    /// what to check before concluding anything.
    HashDiffers,
}

impl fmt::Display for DownloadCorroboration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadCorroboration::HashEqual => f.write_str(
                "Both downloads are byte-for-byte identical (the SHA-256 hashes match). \
                 This only means the server treated both downloaders alike; it says \
                 nothing about whether the file is safe.",
            ),
            DownloadCorroboration::HashDiffers => f.write_str(
                "The two downloads are not the same file (the SHA-256 hashes differ). \
                 Innocent causes are common: a new version published between the two \
                 downloads, per-platform or per-region builds, or a stale CDN copy, and \
                 this result cannot say which copy, if either, is the genuine one. \
                 Compare the version numbers and the publisher's own checksums or \
                 signatures before concluding anything.",
            ),
        }
    }
}

/// The verdict plus the context needed to read it honestly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DownloadVerdict {
    pub corroboration: DownloadCorroboration,
    /// True when both sides recorded the same file length. A length
    /// difference guarantees the files differ; equal lengths say nothing on
    /// their own, which is why the corroboration is decided by the hash
    /// alone.
    pub byte_len_equal: bool,
    /// Seconds between the two records. A large gap weakens the comparison:
    /// the publisher may simply have shipped a new version in between.
    pub recorded_gap_seconds: u64,
}

/// Compare what two people recorded downloading from the same URL.
///
/// This answers exactly one question: **did the server treat these two
/// downloaders differently?** Read the module docs before surfacing the
/// answer: it cannot vouch for a file both received identically, it trusts
/// each side's record to be honestly reported and correctly kept, and a
/// "different" verdict has many innocent explanations. Errors when the two
/// messages are not about the same (normalized) URL; the caller matches URLs
/// before calling, so that error is an internal inconsistency rather than a
/// user-facing state.
pub fn download_verdict(
    request: &DownloadCompareRequest,
    response: &DownloadCompareResponse,
) -> Result<DownloadVerdict, CorroborateError> {
    if request.url != response.url {
        return Err(CorroborateError::UrlMismatch {
            ours: request.url.clone(),
            theirs: response.url.clone(),
        });
    }
    Ok(DownloadVerdict {
        corroboration: if request.sha256 == response.sha256 {
            DownloadCorroboration::HashEqual
        } else {
            DownloadCorroboration::HashDiffers
        },
        byte_len_equal: request.byte_len == response.byte_len,
        recorded_gap_seconds: request.recorded_at.abs_diff(response.recorded_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_url() -> NormalizedUrl {
        normalize_url("https://downloads.example/tool/setup.exe").unwrap()
    }

    #[test]
    fn both_message_types_survive_an_encoded_round_trip() {
        let url = test_url();
        let req = DownloadCompareRequest::new(&url, [42u8; 32], 100_000, 1_700_000_000);
        let back = DownloadCompareRequest::from_bytes(&req.to_bytes().unwrap()).unwrap();
        assert_eq!(back.version, DOWNLOAD_PROTOCOL_VERSION);
        assert_eq!(back.url, req.url);
        assert_eq!(back.sha256, req.sha256);
        assert_eq!(back.byte_len, req.byte_len);
        assert_eq!(back.recorded_at, req.recorded_at);

        let resp = DownloadCompareResponse::new(&url, [42u8; 32], 100_000, 1_700_000_007);
        let back = DownloadCompareResponse::from_bytes(&resp.to_bytes().unwrap()).unwrap();
        assert_eq!(back.version, DOWNLOAD_PROTOCOL_VERSION);
        assert_eq!(back.url, resp.url);
        assert_eq!(back.sha256, resp.sha256);
        assert_eq!(back.byte_len, resp.byte_len);
        assert_eq!(back.recorded_at, resp.recorded_at);
    }

    #[test]
    fn foreign_versions_and_bloated_messages_are_rejected() {
        let url = test_url();
        let req = DownloadCompareRequest::new(&url, [1u8; 32], 10, 1);
        let json = String::from_utf8(req.to_bytes().unwrap()).unwrap();
        let newer = json.replace("\"version\":1", "\"version\":99");
        assert!(matches!(
            DownloadCompareRequest::from_bytes(newer.as_bytes()),
            Err(CorroborateError::UnsupportedVersion(99))
        ));

        let resp = DownloadCompareResponse::new(&url, [1u8; 32], 10, 1);
        let json = String::from_utf8(resp.to_bytes().unwrap()).unwrap();
        let newer = json.replace("\"version\":1", "\"version\":99");
        assert!(matches!(
            DownloadCompareResponse::from_bytes(newer.as_bytes()),
            Err(CorroborateError::UnsupportedVersion(99))
        ));

        // The size cap is checked before parsing, so a blob of spaces reports
        // MessageTooLarge, not MalformedMessage.
        let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            DownloadCompareRequest::from_bytes(&big),
            Err(CorroborateError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn a_decoded_message_must_carry_an_already_normalized_url() {
        // A peer-supplied noncanonical URL (uppercase host) is rejected on
        // decode rather than silently compared or echoed into an error. The
        // bytes are otherwise a perfectly valid, correctly versioned message.
        let url = test_url();
        let req = DownloadCompareRequest::new(&url, [3u8; 32], 5, 9);
        let json = String::from_utf8(req.to_bytes().unwrap())
            .unwrap()
            .replace("downloads.example", "Downloads.EXAMPLE");
        assert!(matches!(
            DownloadCompareRequest::from_bytes(json.as_bytes()),
            Err(CorroborateError::MalformedMessage(_))
        ));

        // An embedded space is valid inside a JSON string but rejected by
        // normalize_url, so require_normalized surfaces it as malformed
        // rather than letting it through to a mismatch error.
        let json = String::from_utf8(req.to_bytes().unwrap())
            .unwrap()
            .replace("setup.exe", "setup .exe");
        assert!(matches!(
            DownloadCompareRequest::from_bytes(json.as_bytes()),
            Err(CorroborateError::MalformedMessage(_))
        ));
    }

    #[test]
    fn identical_downloads_agree_whichever_side_recorded_first() {
        let url = test_url();
        let req = DownloadCompareRequest::new(&url, [9u8; 32], 4096, 1000);
        let resp = DownloadCompareResponse::new(&url, [9u8; 32], 4096, 1005);
        let v = download_verdict(&req, &resp).unwrap();
        assert_eq!(v.corroboration, DownloadCorroboration::HashEqual);
        assert!(v.byte_len_equal);
        assert_eq!(v.recorded_gap_seconds, 5);

        // Swapping the timestamps must give the same gap.
        let req = DownloadCompareRequest::new(&url, [9u8; 32], 4096, 1005);
        let resp = DownloadCompareResponse::new(&url, [9u8; 32], 4096, 1000);
        assert_eq!(
            download_verdict(&req, &resp).unwrap().recorded_gap_seconds,
            5
        );
    }

    #[test]
    fn differing_hashes_disagree_and_a_length_difference_is_reported() {
        let url = test_url();
        let req = DownloadCompareRequest::new(&url, [1u8; 32], 4096, 100);
        let resp = DownloadCompareResponse::new(&url, [2u8; 32], 5120, 100);
        let v = download_verdict(&req, &resp).unwrap();
        assert_eq!(v.corroboration, DownloadCorroboration::HashDiffers);
        assert!(!v.byte_len_equal, "the length difference must be reported");

        // Same length, different bytes: still a clean difference, with no
        // length clue to help explain it.
        let resp = DownloadCompareResponse::new(&url, [2u8; 32], 4096, 100);
        let v = download_verdict(&req, &resp).unwrap();
        assert_eq!(v.corroboration, DownloadCorroboration::HashDiffers);
        assert!(v.byte_len_equal);
    }

    #[test]
    fn the_verdict_is_refused_when_the_two_urls_differ() {
        let req = DownloadCompareRequest::new(
            &normalize_url("https://a.example/file").unwrap(),
            [7u8; 32],
            1,
            1,
        );
        // Even with identical hashes, two different addresses cannot be
        // compared.
        let resp = DownloadCompareResponse::new(
            &normalize_url("https://b.example/file").unwrap(),
            [7u8; 32],
            1,
            1,
        );
        match download_verdict(&req, &resp) {
            Err(CorroborateError::UrlMismatch { ours, theirs }) => {
                assert_eq!(ours, "https://a.example/file");
                assert_eq!(theirs, "https://b.example/file");
            }
            other => panic!("expected UrlMismatch, got {other:?}"),
        }
    }

    #[test]
    fn only_the_four_known_refusal_reasons_parse() {
        let known = [
            (DownloadRefusal::NoDownload, "no_download"),
            (DownloadRefusal::RecordUntrusted, "record_untrusted"),
            (DownloadRefusal::BadMessage, "bad_message"),
            (DownloadRefusal::Unsupported, "unsupported"),
        ];
        for (reason, wire) in known {
            assert_eq!(reason.as_str(), wire);
            assert_eq!(DownloadRefusal::parse(wire), Some(reason));
            // as_str and parse are exact inverses on the closed set.
            assert_eq!(DownloadRefusal::parse(reason.as_str()), Some(reason));
        }
        // Anything outside the closed set is None: a peer-supplied reason
        // must never reach the UI unsanitized.
        for bogus in ["gotcha", "", "NO_DOWNLOAD", "no_download ", "no-download"] {
            assert_eq!(DownloadRefusal::parse(bogus), None, "{bogus:?} must not parse");
        }
    }

    #[test]
    fn a_long_url_message_still_fits_the_chat_envelope() {
        // The chat transport carries hex(to_bytes()) inside a JSON envelope,
        // and the whole envelope must stay under 4096 bytes of plaintext. Pin
        // the worst realistic case: a 200-character normalized URL, a hash of
        // 0xFF bytes (the widest decimal digits), and full-width u64 counters.
        let url_text = format!("https://example.com/{}", "a".repeat(180));
        assert_eq!(url_text.len(), 200);
        let url = normalize_url(&url_text).unwrap();
        assert_eq!(url.as_str().len(), 200, "normalization must leave this URL alone");

        let req = DownloadCompareRequest::new(&url, [0xFF; 32], u64::MAX, u64::MAX);
        let bytes = req.to_bytes().unwrap();
        let hex_len = bytes.len() * 2;
        // {"kind":"...","url":"...","data":"<hex>"} plus punctuation.
        const ENVELOPE_SLACK: usize = 120;
        assert!(
            hex_len + ENVELOPE_SLACK < 4096,
            "hex-encoded request is {hex_len} bytes; with {ENVELOPE_SLACK} bytes of \
             envelope slack it must fit the 4096-byte chat envelope"
        );
    }

    #[test]
    fn the_differing_verdict_states_facts_without_overclaiming() {
        let text = DownloadCorroboration::HashDiffers.to_string();
        assert!(
            !text.contains("tampered"),
            "a differing hash must not be presented as proof of tampering: {text}"
        );
        assert!(
            !text.contains("attack"),
            "a differing hash must not be presented as proof of an attack: {text}"
        );
        assert!(
            text.contains("version"),
            "the text must point at version numbers as an innocent cause: {text}"
        );
    }
}
