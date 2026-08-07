//! Event stream -> structure skeleton + visible text.
//!
//! The structure hash covers a canonical byte encoding of: the doctype,
//! every start/end tag (names ASCII-lowercased, the self-closing bit
//! preserved), every attribute that survives the volatility filter (sorted
//! by (name, value) so document order of attributes cannot matter), and
//! every whitespace-collapsed text event. Normalized text is included so
//! that structure-equal implies text-equal — see the crate docs for why the
//! ladder must be totally ordered.
//!
//! The visible text collects only text events outside the "invisible
//! content" tags, joined with single spaces. That is the level-3 hash input
//! and the level-4 MinHash input.

use sha2::{Digest, Sha256};

use crate::tokenize::Event;

pub struct Normalized {
    pub structure: [u8; 32],
    pub text: [u8; 32],
    pub visible_text: String,
}

/// Tags whose content is never "words the user is reading" in a rendered
/// page: script/style (already dropped as raw text), title (chrome text,
/// not page text), template (inert until cloned by script), noscript (not
/// rendered when scripting works). Note the structure level still sees
/// title/noscript/template *text* — only the visible-text level suppresses
/// it — which keeps structure-equal ⇒ text-equal.
fn is_invisible_content_tag(name: &str) -> bool {
    matches!(name, "script" | "style" | "title" | "noscript" | "template")
}

pub fn normalize(events: &[Event]) -> Normalized {
    let mut skeleton = Sha256::new();
    let mut visible = String::new();
    let mut invisible_depth: u32 = 0;
    for ev in events {
        match ev {
            Event::StartTag {
                name,
                attrs,
                self_closing,
            } => {
                if is_invisible_content_tag(name) {
                    invisible_depth = invisible_depth.saturating_add(1);
                }
                skeleton.update([0x01]);
                feed(&mut skeleton, name.as_bytes());
                skeleton.update([u8::from(*self_closing)]);
                // Sorting makes attribute order irrelevant: CDN variance
                // that reorders attributes must not change the digest.
                // Total order, no hashing of hashes — deterministic.
                let mut kept: Vec<&(String, String)> = attrs
                    .iter()
                    .filter(|(n, v)| !volatile_attr_name(n) && !looks_like_token(v))
                    .collect();
                kept.sort();
                for (n, v) in kept {
                    feed(&mut skeleton, n.as_bytes());
                    feed(&mut skeleton, collapse_ws(v).as_bytes());
                }
            }
            Event::EndTag { name } => {
                if is_invisible_content_tag(name) {
                    // Saturating: a stray "</title>" without an open tag
                    // must not drive the counter negative (malformed input
                    // is expected). Mismatched-tag bookkeeping is an
                    // accepted approximation of a flat stream.
                    invisible_depth = invisible_depth.saturating_sub(1);
                }
                skeleton.update([0x02]);
                feed(&mut skeleton, name.as_bytes());
            }
            Event::Text(raw) => {
                let collapsed = collapse_ws(raw);
                if collapsed.is_empty() {
                    continue;
                }
                skeleton.update([0x03]);
                feed(&mut skeleton, collapsed.as_bytes());
                if invisible_depth == 0 {
                    if !visible.is_empty() {
                        visible.push(' ');
                    }
                    visible.push_str(&collapsed);
                }
            }
            Event::Doctype(name) => {
                skeleton.update([0x04]);
                feed(&mut skeleton, name.as_bytes());
            }
        }
    }
    let mut structure = [0u8; 32];
    structure.copy_from_slice(&skeleton.finalize());
    Normalized {
        structure,
        text: crate::sha256(visible.as_bytes()),
        visible_text: visible,
    }
}

/// Length-prefixed feeding: an unambiguous, platform-independent encoding.
/// Without the length prefix, ("ab","c") and ("a","bc") would hash alike.
fn feed(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_le_bytes());
    h.update(bytes);
}

/// Collapse runs of HTML whitespace to a single space and trim.
///
/// `is_html_space` is an explicit fixed table — HTML's five ASCII
/// whitespace chars plus U+00A0 (so `&nbsp;` and plain non-breaking spaces
/// behave like spaces). It deliberately does NOT use `char::is_whitespace`:
/// that table is Unicode-version-dependent and would tie digests to the
/// rustc that compiled them.
pub fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if is_html_space(c) {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

fn is_html_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{0C}' | '\r' | '\u{00A0}')
}

/// Volatile attribute names (names arrive ASCII-lowercased from the
/// tokenizer). Covers the design's minimum — `nonce`, `integrity`, `csrf*`,
/// `data-*-token` — plus the "name looks like a token" heuristic.
fn volatile_attr_name(name: &str) -> bool {
    name == "nonce"
        || name == "integrity"
        || name.starts_with("csrf")
        || name.starts_with("xsrf")
        || (name.starts_with("data-") && name.ends_with("-token"))
        || name.contains("token")
        || name.contains("nonce")
        || name.contains("signature")
}

/// "Value looks like a token": a long unbroken run of base64/hex-ish
/// characters with enough character-class mixing to look random rather
/// than like a word. The alphabet includes '.', '-' and '_' (JWT and
/// base64url), and the mixing rules are:
///
/// - >= 24 chars with digits AND upper AND lower (typical base64 token), or
/// - >= 32 chars with digits and letters of one case (hex tokens, UUIDs,
///   cache-busted bundle names like `app.a1b2c3....min.js`).
///
/// When in doubt this errs toward *dropping* the attribute: a false
/// positive merely forgives a real change (which the text level still
/// catches), while a false negative reintroduces the false alarms the
/// ladder exists to suppress. URLs survive because ':' breaks the alphabet.
fn looks_like_token(value: &str) -> bool {
    let v = value.trim_matches(is_html_space);
    if v.len() < 24 {
        return false;
    }
    let (mut digit, mut upper, mut lower) = (false, false, false);
    for c in v.chars() {
        match c {
            '0'..='9' => digit = true,
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '+' | '/' | '=' | '-' | '_' | '.' => {}
            _ => return false,
        }
    }
    (digit && upper && lower) || (v.len() >= 32 && digit && (upper || lower))
}
