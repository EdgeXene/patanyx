//! Pre-share leak scan over recognized text.
//!
//! These detectors are deliberately simple hand-rolled scanners rather than a
//! regex dependency: the project's dependency budget is explicit, and each
//! pattern here is small enough to test exhaustively. OCR errors degrade
//! gracefully -- a missed hit or a false positive is tolerable for this
//! feature, so no accuracy heroics.

use crate::TextRegion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakKind {
    Email,
    PossibleCard,
    LongNumber,
    ApiToken,
    PrivateKey,
    Ipv4,
    /// Text the recognizer could read and a person cannot: stroke colour too
    /// close to the colour behind it.
    ///
    /// The odd one out here. Every other kind is about what the text SAYS; this
    /// one is about whether it can be seen at all, and it fires regardless of
    /// content. It belongs in this list anyway, because the question the scan
    /// answers is "what is in this picture that I did not mean to send", and
    /// something invisible qualifies twice over.
    HiddenText,
}

impl LeakKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LeakKind::Email => "email",
            LeakKind::PossibleCard => "possible_card",
            LeakKind::LongNumber => "long_number",
            LeakKind::ApiToken => "api_token",
            LeakKind::PrivateKey => "private_key",
            LeakKind::Ipv4 => "ipv4",
            LeakKind::HiddenText => "hidden_text",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: LeakKind,
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// Scans every region and returns findings sorted by position. A finding
/// inherits its region's box: the recognizer emits line-level boxes only, so
/// character-precise boxes would need an alignment-aware recognizer that
/// tract does not give us for free. Pointing at the line is enough for a
/// "here is what is visible" report.
pub fn scan_regions(regions: &[TextRegion]) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in regions {
        // Reported before the content scanners, because "you cannot see this"
        // is the more surprising fact about a line and should lead. The text
        // itself is carried in the finding: knowing something is hidden is
        // only half an answer, and the other half is what it said.
        if r.color.as_ref().is_some_and(|c| c.is_low_contrast()) {
            out.push(Finding {
                kind: LeakKind::HiddenText,
                text: r.text.clone(),
                x: r.x,
                y: r.y,
                w: r.w,
                h: r.h,
            });
        }
        for (kind, start, end) in scan_text(&r.text) {
            out.push(Finding {
                kind,
                // All detectors cut spans at ASCII boundaries, so byte
                // slicing is always on a char boundary.
                text: r.text[start..end].to_string(),
                x: r.x,
                y: r.y,
                w: r.w,
                h: r.h,
            });
        }
    }
    out.sort_by(|a, b| (a.y, a.x, a.kind.as_str()).cmp(&(b.y, b.x, b.kind.as_str())));
    out
}

fn scan_text(s: &str) -> Vec<(LeakKind, usize, usize)> {
    let mut out = Vec::new();
    for (start, end) in emails(s) {
        out.push((LeakKind::Email, start, end));
    }
    for (start, end, digits) in digit_runs(s) {
        // Below 12 digits, runs are dominated by dates and phone fragments;
        // the noise is not worth it. 12..=19 with a Luhn pass covers the
        // card range including Maestro's 12-digit variants.
        if digits.len() < 12 {
            continue;
        }
        let kind = if digits.len() <= 19 && luhn_ok(&digits) {
            LeakKind::PossibleCard
        } else {
            LeakKind::LongNumber
        };
        out.push((kind, start, end));
    }
    for (start, end) in tokens(s) {
        out.push((LeakKind::ApiToken, start, end));
    }
    for (start, end) in private_key_headers(s) {
        out.push((LeakKind::PrivateKey, start, end));
    }
    for (start, end) in ipv4s(s) {
        out.push((LeakKind::Ipv4, start, end));
    }
    out
}

pub fn luhn_ok(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, b) in digits.bytes().rev().enumerate() {
        let mut d = (b - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

fn is_local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')
}

fn emails(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    for at in 0..b.len() {
        if b[at] != b'@' {
            continue;
        }
        let mut start = at;
        while start > 0 && is_local_char(b[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < b.len() && is_domain_char(b[end]) {
            end += 1;
        }
        let local = &b[start..at];
        let domain = &b[at + 1..end];
        if local.is_empty() {
            continue;
        }
        // Require a dotted domain with an alphabetic TLD of 2+ chars; that
        // is what separates an address from "meet @ 3.pm" noise.
        let Some(tld) = domain.rsplit(|c| *c == b'.').next() else {
            continue;
        };
        if !domain.contains(&b'.') || tld.len() < 2 || !tld.iter().all(|c| c.is_ascii_alphabetic())
        {
            continue;
        }
        out.push((start, end));
    }
    out
}

/// Runs of digits allowing single spaces or dashes between digit groups, the
/// way cards are printed. Boundary rule: a run glued to other alphanumerics
/// belongs to the token detector, not here.
fn digit_runs(s: &str) -> Vec<(usize, usize, String)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let start = i;
            let mut digits = String::new();
            while i < b.len() {
                if b[i].is_ascii_digit() {
                    digits.push(b[i] as char);
                    i += 1;
                } else if (b[i] == b' ' || b[i] == b'-')
                    && i + 1 < b.len()
                    && b[i + 1].is_ascii_digit()
                {
                    i += 1;
                } else {
                    break;
                }
            }
            if i >= b.len() || !b[i].is_ascii_alphanumeric() {
                out.push((start, i, digits));
            }
        } else {
            i += 1;
        }
    }
    out
}

// Well-known secret prefixes. Length is gated so "sk-short" in prose does
// not fire. eyJ catches JWTs (base64 of `{"`); AKIA/ASIA catch AWS key ids.
const TOKEN_PREFIXES: &[&str] = &[
    "sk_live_",
    "sk_test_",
    "sk-",
    "pk_live_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "eyJ",
];
const PREFIX_MIN_LEN: usize = 16;

fn shannon_bits(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    for b in s.as_bytes() {
        freq[*b as usize] += 1;
    }
    let n = s.len() as f64;
    freq.iter()
        .filter(|f| **f > 0)
        .map(|f| {
            let p = *f as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_secret(tok: &str) -> bool {
    if tok.len() >= PREFIX_MIN_LEN && TOKEN_PREFIXES.iter().any(|p| tok.starts_with(p)) {
        return true;
    }
    // Generic high-entropy run: long, mixed character classes, and ~4+ bits
    // per char. The class requirement alone would flag mixed-case English
    // with digits; entropy alone would flag "abcabc..."; together they are
    // a decent secret heuristic with tolerable false positives.
    if tok.len() < 24 {
        return false;
    }
    let has_upper = tok.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = tok.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = tok.bytes().any(|b| b.is_ascii_digit());
    has_upper && has_lower && has_digit && shannon_bits(tok) >= 3.9
}

fn tokens(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let is_tok = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if is_tok(b[i]) {
            let start = i;
            while i < b.len() && is_tok(b[i]) {
                i += 1;
            }
            if looks_like_secret(&s[start..i]) {
                out.push((start, i));
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Matches "BEGIN ... PRIVATE KEY" within a short window. The surrounding
/// dashes are deliberately not required: OCR mangles punctuation runs, and
/// the phrase pair is specific enough on its own.
fn private_key_headers(s: &str) -> Vec<(usize, usize)> {
    let lower: Vec<u8> = s.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= lower.len() {
        if &lower[i..i + 5] == b"begin" {
            let window_end = (i + 64).min(lower.len());
            let window = &lower[i..window_end];
            if let Some(rel) = window
                .windows(b"private key".len())
                .position(|w| w == b"private key")
            {
                let end = i + rel + b"private key".len();
                out.push((i, end));
                i = end;
                continue;
            }
            i += 5;
        } else {
            i += 1;
        }
    }
    out
}

fn ipv4s(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit()
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.'))
        {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let end = i;
            let bounded = end >= b.len() || !(b[end].is_ascii_alphanumeric() || b[end] == b'.');
            if bounded {
                let parts: Vec<&str> = s[start..end].split('.').collect();
                let valid = parts.len() == 4
                    && parts.iter().all(|p| {
                        !p.is_empty()
                            && p.len() <= 3
                            && p.bytes().all(|c| c.is_ascii_digit())
                            && p.parse::<u16>().map_or(false, |v| v <= 255)
                    });
                if valid {
                    out.push((start, end));
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(text: &str, x: u32, y: u32) -> TextRegion {
        TextRegion {
            text: text.to_string(),
            x,
            y,
            w: 100,
            h: 20,
            color: None,
        }
    }

    /// Same, with a measured colour. `contrast` is the RGB distance between
    /// stroke and background; below 32 counts as hidden.
    fn region_with_contrast(text: &str, contrast: f32) -> TextRegion {
        TextRegion {
            text: text.to_string(),
            x: 0,
            y: 0,
            w: 100,
            h: 20,
            color: Some(crate::color::RegionColor {
                rgb: [250, 250, 250],
                hex: "#fafafa".to_string(),
                name: "white",
                background_rgb: [255, 255, 255],
                contrast,
            }),
        }
    }

    fn kinds(s: &str) -> Vec<LeakKind> {
        scan_text(s).into_iter().map(|(k, _, _)| k).collect()
    }

    #[test]
    fn text_too_close_to_its_background_is_reported_as_hidden() {
        let out = scan_regions(&[region_with_contrast("severance terms apply", 4.0)]);
        assert_eq!(out.len(), 1, "expected one finding, got {out:?}");
        assert_eq!(out[0].kind, LeakKind::HiddenText);
        assert_eq!(
            out[0].text, "severance terms apply",
            "the finding must carry what the hidden text said, not just that \
             something was hidden"
        );
    }

    #[test]
    fn ordinary_contrast_is_not_reported() {
        let out = scan_regions(&[region_with_contrast("plain visible text", 300.0)]);
        assert!(out.is_empty(), "expected no findings, got {out:?}");
    }

    /// A region whose colour could not be measured must not be guessed at in
    /// either direction. Silence, not a finding and not a clean bill.
    #[test]
    fn an_unmeasured_region_reports_nothing_about_contrast() {
        let out = scan_regions(&[region("nothing sensitive here", 0, 0)]);
        assert!(
            !out.iter().any(|f| f.kind == LeakKind::HiddenText),
            "got {out:?}"
        );
    }

    /// Hidden AND sensitive is two findings, not one. Collapsing them would
    /// make the report depend on which scanner happened to run first.
    #[test]
    fn hidden_text_that_is_also_sensitive_reports_both() {
        let out = scan_regions(&[region_with_contrast("mail me at a@b.com", 5.0)]);
        let found: Vec<LeakKind> = out.iter().map(|f| f.kind).collect();
        assert!(found.contains(&LeakKind::HiddenText), "got {found:?}");
        assert!(found.contains(&LeakKind::Email), "got {found:?}");
    }

    #[test]
    fn luhn_accepts_and_rejects() {
        assert!(luhn_ok("4111111111111111"));
        assert!(luhn_ok("79927398713"));
        assert!(!luhn_ok("4111111111111112"));
        assert!(!luhn_ok(""));
        assert!(!luhn_ok("4111a11111111111"));
    }

    #[test]
    fn card_and_long_number_classification() {
        assert_eq!(kinds("4111111111111111"), vec![LeakKind::PossibleCard]);
        assert_eq!(kinds("4111 1111 1111 1111"), vec![LeakKind::PossibleCard]);
        assert_eq!(kinds("4111-1111-1111-1111"), vec![LeakKind::PossibleCard]);
        // Luhn fails: still long, but not a card.
        assert_eq!(kinds("4111111111111112"), vec![LeakKind::LongNumber]);
        // Too long for a card even with valid shape.
        assert_eq!(
            kinds("123456789012345678901234"),
            vec![LeakKind::LongNumber]
        );
        // Short runs are noise for this feature.
        assert!(kinds("call 555 1234 now").is_empty());
        // Glued to letters it is a token problem, not a number.
        assert!(kinds("abc123456789012").is_empty());
    }

    #[test]
    fn email_detection() {
        let spans = emails("mail bob@corp.example.com today");
        assert_eq!(spans.len(), 1);
        let (s0, e0) = spans[0];
        assert_eq!(
            &"mail bob@corp.example.com today"[s0..e0],
            "bob@corp.example.com"
        );
        assert!(emails("meet @ 3pm").is_empty());
        assert!(emails("a@b").is_empty()); // no dot
        assert!(emails("x@y.12").is_empty()); // non-alpha TLD
        assert!(emails("@x.com").is_empty()); // no local part
        assert_eq!(emails("x@y.co").len(), 1);
    }

    #[test]
    fn ipv4_detection() {
        assert_eq!(ipv4s("host 192.168.1.1 down").len(), 1);
        assert_eq!(ipv4s("10.0.0.1 and 8.8.8.8").len(), 2);
        assert!(ipv4s("999.1.1.1").is_empty()); // octet > 255
        assert!(ipv4s("1.2.3").is_empty()); // too few parts
        assert!(ipv4s("1.2.3.4.5").is_empty()); // too many parts
        assert!(ipv4s("version10.0.0.1").is_empty()); // glued to a word
    }

    #[test]
    fn private_key_header_detection() {
        let s = "-----BEGIN RSA PRIVATE KEY----- MIIabc";
        let spans = private_key_headers(s);
        assert_eq!(spans.len(), 1);
        assert!(s[spans[0].0..spans[0].1].contains("PRIVATE KEY"));
        assert_eq!(private_key_headers("begin private key").len(), 1); // case-insensitive
        assert!(private_key_headers("begin at the start").is_empty());
    }

    #[test]
    fn token_detection() {
        // Prefixed forms.
        assert_eq!(tokens("ghp_ab3dF5kL9mN2pQ7rS4tV6wX8yZ01ab").len(), 1);
        assert_eq!(tokens("AKIAIOSFODNN7EXAMPLE").len(), 1);
        assert!(tokens("sk-short").is_empty()); // prefix but too short
                                                // Generic high-entropy run: 32 unique mixed chars, entropy 5.0.
        assert_eq!(tokens("aB3xY9qL2mN8pR4tV6wZ1cF7hJ5kD0sT").len(), 1);
        // Lowercase-only long string fails the class requirement.
        assert!(tokens("correcthorsebatterystaplecorrecthorse").is_empty());
        // Repetition fails entropy.
        assert!(tokens("aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1aB1a").is_empty());
        // Normal prose does not fire.
        assert!(tokens("the quick brown fox jumps over the lazy dog").is_empty());
    }

    #[test]
    fn shannon_sanity() {
        assert_eq!(shannon_bits("aaaaaaaa"), 0.0);
        assert!((shannon_bits("abcdefgh") - 3.0).abs() < 1e-9);
    }

    #[test]
    fn findings_carry_region_box_and_sort() {
        let regions = vec![
            region("contact admin@corp.example.com", 10, 200),
            region("card 4111111111111111 ends", 5, 50),
        ];
        let findings = scan_regions(&regions);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].kind, LeakKind::PossibleCard); // y=50 sorts first
        assert_eq!(findings[0].y, 50);
        assert_eq!(findings[0].x, 5);
        assert_eq!(findings[1].kind, LeakKind::Email);
        assert_eq!(findings[1].text, "admin@corp.example.com");
        assert_eq!(findings[1].w, 100); // inherits region box
    }

    #[test]
    fn clean_text_reports_nothing() {
        let regions = vec![region("quarterly report draft, page 3 of 12", 0, 0)];
        assert!(scan_regions(&regions).is_empty());
    }
}
