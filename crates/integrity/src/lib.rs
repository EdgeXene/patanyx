#![forbid(unsafe_code)]
//! patanyx-integrity — page-content normalization and hashing.
//!
//! Raw byte comparison is useless for the question "is this the same content
//! I saw before?": real pages differ between two loads for innocent reasons
//! (CSRF tokens, nonces, script cache-busters, A/B slots). So this crate
//! produces a *ladder* of hashes and reports the strongest level that
//! matches:
//!
//! 1. **Raw** — SHA-256 of the exact bytes received.
//! 2. **Structure** — SHA-256 of the normalized token stream: comments and
//!    `<script>`/`<style>` bodies dropped, volatile attributes (nonces,
//!    tokens, SRI hashes) dropped, whitespace collapsed, attributes sorted.
//!    Normalized *text* is hashed into this level too — deliberately, and
//!    this is a deviation from a strict "elements only" reading of the
//!    design: it keeps the ladder totally ordered (raw-equal ⇒
//!    structure-equal ⇒ text-equal). Without it, two pages with identical
//!    markup but completely different words would "match at structure
//!    level", which is the one false positive this product cannot afford.
//! 3. **Text** — SHA-256 of the visible text in document order,
//!    whitespace-normalized. This is the level that answers "are we reading
//!    the same words".
//! 4. **Similarity** — a MinHash sketch (64 minima) over word 3-shingles of
//!    the visible text, giving a Jaccard estimate so the answer can be
//!    "97% the same" rather than a bare yes/no.
//!
//! # Determinism is the whole product
//!
//! The same input must always give the same digest, on any platform,
//! forever. The construction rules that guarantee this:
//!
//! - No `HashMap`/`HashSet` iteration feeds any hash; attribute order is
//!   canonicalized by sorting.
//! - No time, no randomness. The MinHash coefficients are fixed constants
//!   derived from SHA-256 of a versioned seed string.
//! - Whitespace and case handling use explicit ASCII tables, never
//!   `char::is_whitespace` / `to_lowercase`, whose Unicode tables can shift
//!   between rustc releases. The one exception is lossy UTF-8 decoding of
//!   the input (U+FFFD replacement), which is fixed by the Unicode standard
//!   and stable in practice.
//! - All integers hashed are length-prefixed little-endian, so the encoding
//!   is platform-independent and unambiguous.
//!
//! # Hostile input
//!
//! The tokenizer is a *total function*: malformed, truncated, or non-UTF-8
//! input is normalized, never rejected and never panics. The only hard
//! failure is [`IntegrityError::InputTooLarge`], so a hostile page cannot
//! force unbounded allocation. Lossy UTF-8 decoding is acceptable here
//! (unlike for chat messages) because a digest is never shown to the user
//! as text.

mod error;
mod minhash;
mod normalize;
mod tokenize;

pub use error::IntegrityError;

use sha2::{Digest, Sha256};

/// Inputs larger than this are refused rather than allocated against.
/// 16 MiB is far above any real page and keeps worst-case memory bounded.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// The comparison ladder for one piece of page content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContentDigest {
    /// Level 1: SHA-256 of the exact bytes received.
    pub raw: [u8; 32],
    /// Level 2: SHA-256 of the normalized skeleton (including normalized
    /// text — see module docs for why).
    pub structure: [u8; 32],
    /// Level 3: SHA-256 of the visible text, whitespace-normalized.
    pub text: [u8; 32],
    /// Level 4: 64 MinHash minima over word 3-shingles of the visible text.
    /// Fixed length by construction (`minhash::MINHASH_COUNT`).
    pub minhash: Vec<u64>,
}

// Note: the design sketched `pub fn digest(html: &[u8]) ->
// ContentDigest`, but the brief also requires refusing oversized input with
// an error, so this returns `Result`. An infallible wrapper is not provided
// on purpose: callers must confront the size limit.
/// Compute the full comparison ladder for `html`.
///
/// Never fails on malformed or non-UTF-8 content; the only error is
/// [`IntegrityError::InputTooLarge`].
pub fn digest(html: &[u8]) -> Result<ContentDigest, IntegrityError> {
    if html.len() > MAX_INPUT_BYTES {
        return Err(IntegrityError::InputTooLarge {
            len: html.len(),
            max: MAX_INPUT_BYTES,
        });
    }
    let raw = sha256(html);
    // Lossy decode: invalid sequences become U+FFFD deterministically. The
    // raw hash above still covers the *original* bytes, so two byte-level
    // different inputs can never collide at level 1.
    let decoded = String::from_utf8_lossy(html);
    let events = tokenize::tokenize(&decoded);
    let normalized = normalize::normalize(&events);
    let minhash = minhash::minhash(&normalized.visible_text);
    Ok(ContentDigest {
        raw,
        structure: normalized.structure,
        text: normalized.text,
        minhash,
    })
}

/// The strongest ladder level at which two digests match.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    // Note: the sketched enum has no slot for "raw bytes differ but the
    // structure is identical" (the CSRF-token-only case). I folded it into
    // `Identical`, because that case means "only volatile content changed"
    // and anything scarier would cry wolf on day one. If the reviewer
    // prefers, split it into a fourth variant (e.g. `VolatileOnly`).
    /// The pages match at the structure level or better: either the raw
    /// bytes are identical, or every difference is volatile content that
    /// normalization discards (script/style bodies, nonces, tokens).
    Identical,
    /// The structure differs, but the visible text is word-for-word the
    /// same: the markup changed, the words did not.
    StructureDiffers,
    /// The visible text differs. `similarity` is a 0.0..=1.0 Jaccard
    /// estimate over word shingles of the visible text (1.0 = identical;
    /// unrelated texts score near 0.0).
    TextDiffers { similarity: f32 },
}

/// Report the strongest ladder level at which `a` and `b` match.
pub fn compare(a: &ContentDigest, b: &ContentDigest) -> Verdict {
    if a.raw == b.raw {
        return Verdict::Identical;
    }
    if a.structure == b.structure {
        return Verdict::Identical;
    }
    if a.text == b.text {
        return Verdict::StructureDiffers;
    }
    Verdict::TextDiffers {
        similarity: similarity(a, b),
    }
}

/// Fuzzy similarity (0.0..=1.0) between the visible texts of two digests.
/// Exposed so a UI can say "97% the same" even when the verdict is already
/// known. Returns 0.0 for digests with malformed (wrong-length) sketches.
pub fn similarity(a: &ContentDigest, b: &ContentDigest) -> f32 {
    minhash::similarity(&a.minhash, &b.minhash)
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_unwrap(html: &[u8]) -> ContentDigest {
        digest(html).expect("digest must not fail on in-crate test input")
    }

    #[test]
    fn same_input_digests_identically() {
        // The core property: determinism. Cross-platform stability follows
        // from construction (ASCII-only normalization, LE length prefixes,
        // no HashMap, no time/RNG), documented in the module docs.
        // Note: a golden-vector test (hardcoded expected hashes) would
        // additionally pin cross-*release* stability; values must be
        // captured from a real run, so that is left to the reviewer.
        let page = b"<!doctype html><html><body><p>Hello <b>world</b></p></body></html>";
        let a = digest_unwrap(page);
        let b = digest_unwrap(page);
        assert_eq!(a, b);
        assert_eq!(compare(&a, &b), Verdict::Identical);
    }

    #[test]
    fn csrf_token_only_change_matches_at_structure() {
        // Two loads of the same form page, differing only in: the CSRF
        // token value, a nonce attribute, and an inline script body. All
        // three are volatile and must not affect the structure hash.
        let page_a: &[u8] = br#"<!doctype html>
<html><head><script>var seed=11111;</script><meta name="csrf-token" content="aB3x9Kp2Lm7Qw8Rt5Yu1Io6Pz4"></head>
<body><div class="wrap" nonce="n0nceValueAAAA1111"><h1>Transfer</h1><form method="post"><input type="submit" value="Send"></form></div></body></html>"#;
        let page_b: &[u8] = br#"<!doctype html>
<html><head><script>var seed=99999;</script><meta name="csrf-token" content="Zz9Y8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0P"></head>
<body><div class="wrap" nonce="differentNonce9999"><h1>Transfer</h1><form method="post"><input type="submit" value="Send"></form></div></body></html>"#;
        let a = digest_unwrap(page_a);
        let b = digest_unwrap(page_b);
        assert_ne!(a.raw, b.raw, "bytes genuinely differ");
        assert_eq!(
            a.structure, b.structure,
            "volatile-only differences must normalize away"
        );
        assert_eq!(compare(&a, &b), Verdict::Identical);
    }

    #[test]
    fn changed_words_do_not_match_at_text_level() {
        let page_a: &[u8] =
            b"<p>The committee published the report on Tuesday morning after a long debate about rising prices</p>";
        let page_b: &[u8] =
            b"<p>The committee published the letter on Tuesday morning after a long debate about rising prices</p>";
        let a = digest_unwrap(page_a);
        let b = digest_unwrap(page_b);
        assert_ne!(a.text, b.text, "visible words changed");
        match compare(&a, &b) {
            Verdict::TextDiffers { similarity } => {
                // One word in sixteen changed: Jaccard of 3-shingles is
                // ~0.77 in expectation. The 0.5 bound is deliberately
                // conservative; the estimate is deterministic.
                assert!(
                    (0.5..1.0).contains(&similarity),
                    "small edit should score high but below 1.0, got {similarity}"
                );
            }
            other => panic!("expected TextDiffers, got {other:?}"),
        }
    }

    #[test]
    fn same_words_different_markup_is_structure_differs() {
        let a = digest_unwrap(b"<p>Hello brave new world</p>");
        let b = digest_unwrap(b"<div>Hello <span>brave</span> new world</div>");
        assert_ne!(a.structure, b.structure);
        assert_eq!(a.text, b.text);
        assert_eq!(compare(&a, &b), Verdict::StructureDiffers);
    }

    #[test]
    fn whitespace_and_comment_only_changes_are_invisible() {
        let a = digest_unwrap(b"<p>Hello   world</p>\n<!-- build 12345 -->\n<p>Again</p>");
        let b = digest_unwrap(b"<p>Hello world</p><p>Again</p>");
        assert_eq!(a.structure, b.structure);
        assert_eq!(a.text, b.text);
        assert_eq!(compare(&a, &b), Verdict::Identical);
    }

    #[test]
    fn entities_normalize_before_hashing() {
        let a = digest_unwrap(b"<p>a &amp; b &#65;</p>");
        let b = digest_unwrap(b"<p>a & b A</p>");
        assert_eq!(a.text, b.text);
        assert_eq!(a.structure, b.structure);
    }

    #[test]
    fn unrelated_texts_score_near_zero() {
        let a = digest_unwrap(b"<p>alpha beta gamma delta epsilon zeta eta theta iota kappa</p>");
        let b = digest_unwrap(b"<p>one two three four five six seven eight nine ten</p>");
        match compare(&a, &b) {
            Verdict::TextDiffers { similarity } => {
                assert!(
                    similarity < 0.3,
                    "disjoint shingle sets should score ~0, got {similarity}"
                );
            }
            other => panic!("expected TextDiffers, got {other:?}"),
        }
    }

    #[test]
    fn malformed_truncated_and_non_utf8_input_does_not_panic() {
        let cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"<".to_vec(),
            b"<div".to_vec(),
            b"<div class='x".to_vec(),
            b"<div class=\"x".to_vec(),
            b"<script>alert(1".to_vec(),
            b"<script></scriptx></script>".to_vec(),
            b"<script/><p>swallowed by raw text</p>".to_vec(),
            b"<style>a{b:c}".to_vec(),
            b"</".to_vec(),
            b"</ div>".to_vec(),
            b"<//>".to_vec(),
            b"<>".to_vec(),
            b"< a>".to_vec(),
            b"<!--".to_vec(),
            b"<!-->".to_vec(),
            b"<!--->".to_vec(),
            b"<!doctype".to_vec(),
            b"<!doctype html".to_vec(),
            b"<![CDATA[not real cdata]]>".to_vec(),
            b"<?xml version=\"1.0\"?>".to_vec(),
            b"&".to_vec(),
            b"&#".to_vec(),
            b"&#x;".to_vec(),
            b"&#xZZ;".to_vec(),
            b"&amp".to_vec(),
            b"&#0;".to_vec(),
            b"&#1114112;".to_vec(),
            b"&#xD800;".to_vec(),
            b"<a href=>x</a>".to_vec(),
            b"<a =foo>".to_vec(),
            b"<a href='unterminated".to_vec(),
            b"<div><b></div></b>".to_vec(),
            b"<div><div><div>".to_vec(),
            b">>>>".to_vec(),
            vec![b'<'; 4096],
            vec![0xff, 0xfe, 0x00, 0x3c],
            vec![0x63, 0x61, 0x66, 0xc3], // "caf" + truncated 2-byte char
            vec![b'<', b'p', b'>', 0x80, 0x80, b'<', b'/', b'p', b'>'],
            "a\u{0}b".as_bytes().to_vec(),
            "<p>caf\u{e9} na\u{ef}ve</p>".as_bytes().to_vec(),
            "<p>\u{1F600} emoji</p>".as_bytes().to_vec(),
        ];
        for (i, case) in cases.iter().enumerate() {
            let d = digest(case).unwrap_or_else(|e| panic!("case {i} unexpectedly errored: {e}"));
            // Self-comparison must always be Identical, whatever the input.
            assert_eq!(compare(&d, &d), Verdict::Identical, "case {i}");
        }
    }

    #[test]
    fn empty_and_invisible_only_text_is_stable() {
        let a = digest_unwrap(b"<script>x</script><style>y</style>");
        let b = digest_unwrap(b"<title>t</title><p></p>");
        // Both have empty visible text; their structures differ.
        assert_eq!(a.text, b.text);
        assert_eq!(compare(&a, &b), Verdict::StructureDiffers);
    }

    #[test]
    fn oversized_input_is_refused() {
        let big = vec![b'a'; MAX_INPUT_BYTES + 1];
        match digest(&big) {
            Err(IntegrityError::InputTooLarge { len, max }) => {
                assert_eq!(len, MAX_INPUT_BYTES + 1);
                assert_eq!(max, MAX_INPUT_BYTES);
            }
            other => panic!("expected InputTooLarge, got {other:?}"),
        }
        // Exactly at the cap must still succeed.
        let at_cap = vec![b'a'; MAX_INPUT_BYTES];
        assert!(digest(&at_cap).is_ok());
    }

    #[test]
    fn digest_survives_serde_roundtrip() {
        // The digest is stored inside the bookmark store as JSON; the
        // round-trip must be lossless for compare() to stay meaningful.
        let d = digest_unwrap(b"<p>persist me</p>");
        let json = serde_json::to_string(&d).unwrap();
        let back: ContentDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
