//! Registrable domains, via Mozilla's Public Suffix List.
//!
//! WHAT THIS IS FOR. A password saved on `accounts.google.com` should be
//! offered on `mail.google.com`; a password saved on `mybank.co.uk` must never
//! be offered on `evil.co.uk`. Those two sentences look alike and are decided
//! by the same question -- where does the shared infrastructure stop and
//! somebody's own domain begin -- and that question has no answer in logic.
//! `co.uk`, `com.au`, `github.io` and `s3.amazonaws.com` are suffixes anyone
//! can register under; `google.com` is not. Only the list knows.
//!
//! THE FAILURE MODE IS SILENT AND IT IS THE DANGEROUS DIRECTION. A missing or
//! mismatched rule does not error -- it makes a registrable domain LARGER, so
//! more hosts look like "the same site" and a credential is offered to more
//! places than the user ever agreed to. Nothing on screen would say so. That
//! is why the list is size-asserted at build time, why the rules are compiled
//! from a reviewable text file, and why the tests below include the upstream
//! project's own published test vectors rather than only cases I thought of.
//!
//! The algorithm is the one publicsuffix.org specifies:
//!
//!   1. An exception rule (`!www.ck`) beats everything; the public suffix is
//!      that rule minus its leftmost label.
//!   2. Otherwise the LONGEST matching rule wins, where a wildcard (`*.ck`)
//!      matches exactly one label in that position.
//!   3. If no rule matches at all, the implicit rule is `*` -- the public
//!      suffix is the rightmost label.
//!
//! Rule bodies are compared as `hash_host` values (see build.rs for why the
//! list ships hashed), and every candidate is a SUFFIX SLICE of the caller's
//! host, so matching allocates nothing.

use crate::platform::hash_host;

const BUNDLED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/psl.bin"));

/// Deepest host we will walk. The longest real public suffix is a handful of
/// labels; this bounds work on pathological input rather than expressing a
/// protocol limit.
const MAX_LABELS: usize = 24;

struct Rules {
    normal: &'static [u8],
    wildcard: &'static [u8],
    exception: &'static [u8],
}

fn rules() -> Rules {
    // Three u32 counts, then the three sorted hash runs back to back.
    let n = u32::from_le_bytes(BUNDLED[0..4].try_into().unwrap()) as usize;
    let w = u32::from_le_bytes(BUNDLED[4..8].try_into().unwrap()) as usize;
    let e = u32::from_le_bytes(BUNDLED[8..12].try_into().unwrap()) as usize;
    let base = 12;
    Rules {
        normal: &BUNDLED[base..base + n * 16],
        wildcard: &BUNDLED[base + n * 16..base + (n + w) * 16],
        exception: &BUNDLED[base + (n + w) * 16..base + (n + w + e) * 16],
    }
}

/// Binary search over a sorted run of little-endian u128s.
fn contains(run: &[u8], needle: u128) -> bool {
    let (mut lo, mut hi) = (0usize, run.len() / 16);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let at = u128::from_le_bytes(run[mid * 16..mid * 16 + 16].try_into().unwrap());
        match at.cmp(&needle) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

/// Byte offsets at which each label of `host` begins.
fn label_starts(host: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in host.bytes().enumerate() {
        if b == b'.' {
            starts.push(i + 1);
        }
    }
    starts
}

/// The public suffix of `host`, as a slice of it.
///
/// Returns the whole host when the host IS a public suffix (`co.uk`, `com`).
pub fn public_suffix(host: &str) -> &str {
    let starts = label_starts(host);
    let r = rules();

    // Only the last few labels can ever match a rule -- the deepest real
    // public suffix is a handful of labels -- so a pathologically deep host is
    // walked from the tail rather than being given up on.
    //
    // THE OBVIOUS SHORTCUT HERE IS WRONG IN THE DANGEROUS DIRECTION. Bailing
    // out to the rightmost label for a too-deep host looks conservative and is
    // not: for a host under `co.uk` it yields `uk`, making the registrable
    // domain `co.uk` -- a PUBLIC SUFFIX treated as somebody's domain, so every
    // deep `.co.uk` host collapses into one site and they are offered each
    // other's passwords. Truncating the WALK keeps the answer correct instead.
    let first = starts.len().saturating_sub(MAX_LABELS);

    // 1. Exceptions first and unconditionally: an exception rule outranks every
    //    other rule regardless of length, so this cannot be folded into the
    //    longest-match walk below.
    for (i, &at) in starts.iter().enumerate().skip(first) {
        if contains(r.exception, hash_host(&host[at..])) {
            // "Modify it by removing the leftmost label" -- so the suffix is
            // the candidate's PARENT. An exception rule always has a parent,
            // because a bare `!tld` would be meaningless and the list has none.
            return match starts.get(i + 1) {
                Some(&next) => &host[next..],
                None => &host[at..],
            };
        }
    }

    // 2. Longest match wins, and `starts` runs longest-candidate-first, so the
    //    first hit IS the longest.
    for (i, &at) in starts.iter().enumerate().skip(first) {
        let candidate = &host[at..];
        if contains(r.normal, hash_host(candidate)) {
            return candidate;
        }
        // A wildcard rule `*.X` makes any single label under X a public
        // suffix. This candidate qualifies when its own parent is a wildcard
        // root -- one lookup, no string building.
        if let Some(&parent) = starts.get(i + 1) {
            if contains(r.wildcard, hash_host(&host[parent..])) {
                return candidate;
            }
        }
    }

    // 3. The implicit `*` rule.
    &host[*starts.last().unwrap()..]
}

/// The registrable domain of `host` -- its public suffix plus one label.
///
/// `None` when the host is itself a public suffix and therefore belongs to
/// nobody: `com`, `co.uk`, `github.io`. Callers must treat `None` as "no
/// site-level identity here" and fall back to exact-host comparison, NEVER as
/// "matches anything".
pub fn registrable_domain(host: &str) -> Option<&str> {
    // An empty label means this is not a host: a leading dot, a trailing dot,
    // or `a..b`. `host_of` does not produce these, but answering anyway would
    // mean inventing a site identity for a string that has none -- and the
    // upstream test vectors specifically pin `.com` and `.example.com` to
    // "no registrable domain" rather than to something plausible-looking.
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }
    let suffix = public_suffix(host);
    if suffix.len() == host.len() {
        return None;
    }
    // One label to the left of the suffix. `host` is longer than `suffix`, so
    // the boundary byte exists and is the '.' immediately before it.
    let cut = host.len() - suffix.len() - 1;
    let start = host[..cut].rfind('.').map(|i| i + 1).unwrap_or(0);
    Some(&host[start..])
}

/// Whether two hosts belong to the same registrable domain.
///
/// THE ONE PLACE THE CREDENTIAL DECISION IS MADE. Exact equality always
/// counts. Beyond that both hosts must resolve to the same registrable domain,
/// and a host with no registrable domain matches nothing but itself -- so a
/// credential somehow saved against `co.uk` is offered on `co.uk` alone and
/// not across the whole of the United Kingdom.
pub fn same_site(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (registrable_domain(a), registrable_domain(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_actually_compiled_in() {
        let r = rules();
        assert!(
            r.normal.len() / 16 > 9_000,
            "only {} normal rules reached the binary",
            r.normal.len() / 16
        );
        assert!(r.wildcard.len() / 16 > 200);
        assert!(r.exception.len() / 16 >= 5);
    }

    /// The case that started this: Google's login lives on one subdomain and
    /// the things you log in to live on others.
    #[test]
    fn google_subdomains_are_one_site() {
        assert!(same_site("accounts.google.com", "mail.google.com"));
        assert!(same_site("accounts.google.com", "drive.google.com"));
        assert!(same_site("google.com", "mail.google.com"));
        assert_eq!(registrable_domain("mail.google.com"), Some("google.com"));
    }

    /// The reason this file exists rather than a two-label rule. Every one of
    /// these would be a credential handed to a stranger.
    #[test]
    fn multi_label_public_suffixes_do_not_merge_strangers() {
        assert!(!same_site("mybank.co.uk", "evil.co.uk"));
        assert!(!same_site("a.com.au", "b.com.au"));
        assert!(!same_site("alice.github.io", "bob.github.io"));
        assert_eq!(registrable_domain("mybank.co.uk"), Some("mybank.co.uk"));
        assert_eq!(registrable_domain("www.mybank.co.uk"), Some("mybank.co.uk"));
    }

    #[test]
    fn a_shared_suffix_is_not_a_shared_site() {
        // Suffix-string equality would pass every one of these.
        assert!(!same_site("google.com", "notgoogle.com"));
        assert!(!same_site("evilgoogle.com", "google.com"));
        assert!(!same_site("example.com", "example.com.evil.net"));
    }

    #[test]
    fn a_public_suffix_itself_has_no_site() {
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("github.io"), None);
        // ...and therefore matches only itself, never its children.
        assert!(!same_site("co.uk", "anything.co.uk"));
        assert!(same_site("co.uk", "co.uk"));
    }

    #[test]
    fn wildcard_and_exception_rules_are_honoured() {
        // `*.ck` makes every single label under ck a public suffix...
        assert_eq!(registrable_domain("foo.ck"), None);
        assert_eq!(registrable_domain("bar.foo.ck"), Some("bar.foo.ck"));
        // ...except `!www.ck`, which is registrable itself.
        assert_eq!(registrable_domain("www.ck"), Some("www.ck"));
        assert!(!same_site("a.foo.ck", "b.foo.ck"));
    }

    #[test]
    fn idn_rules_survived_the_punycode_conversion() {
        // 公司.cn, which upstream ships only in Unicode. If the conversion in
        // scripts/build-psl.py were dropped, this suffix would be unknown and
        // these two unrelated registrants would collapse into one site.
        assert_eq!(registrable_domain("xn--55qx5d.cn"), None);
        assert!(!same_site("a.xn--55qx5d.cn", "b.xn--55qx5d.cn"));
        assert_eq!(
            registrable_domain("shop.a.xn--55qx5d.cn"),
            Some("a.xn--55qx5d.cn")
        );
    }

    /// The Public Suffix List project's OWN published test file, fetched from
    /// publicsuffix.org rather than transcribed.
    ///
    /// WRITTEN FROM MEMORY FIRST, AND IT WAS WRONG. The classic vector set
    /// pins `c.cy` to "no registrable domain" because `*.cy` used to be a
    /// wildcard rule. It is not one any more -- the current list spells out
    /// `ac.cy`, `com.cy` and the rest -- so the remembered expectation failed
    /// against a matcher that was behaving correctly. Vectors that describe a
    /// list are only worth anything when they come from the same list.
    ///
    /// Excluded, deliberately: lines COMMENTED OUT upstream (the first pass
    /// of this extractor matched inside `//` and pulled in the disabled
    /// `example.local` vectors, which fail because `local` was removed from
    /// the list years ago), the null case (not representable), and the
    /// Unicode cases (this matcher is only ever handed hosts from `host_of`,
    /// which never decodes punycode -- IDN coverage is proven separately by
    /// `idn_rules_survived_the_punycode_conversion`). Mixed-case inputs are
    /// lowered here because `host_of` guarantees lowercase to every caller.
    #[test]
    fn upstream_published_vectors() {
        let cases: &[(&str, Option<&str>)] = &[
            ("com", None),
            ("example.com", Some("example.com")),
            ("www.example.com", Some("example.com")),
            (".com", None),
            (".example", None),
            (".example.com", None),
            (".example.example", None),
            ("example", None),
            ("example.example", Some("example.example")),
            ("b.example.example", Some("example.example")),
            ("a.b.example.example", Some("example.example")),
            ("biz", None),
            ("domain.biz", Some("domain.biz")),
            ("b.domain.biz", Some("domain.biz")),
            ("a.b.domain.biz", Some("domain.biz")),
            ("com", None),
            ("example.com", Some("example.com")),
            ("b.example.com", Some("example.com")),
            ("a.b.example.com", Some("example.com")),
            ("uk.com", None),
            ("example.uk.com", Some("example.uk.com")),
            ("b.example.uk.com", Some("example.uk.com")),
            ("a.b.example.uk.com", Some("example.uk.com")),
            ("test.ac", Some("test.ac")),
            ("mm", None),
            ("c.mm", None),
            ("b.c.mm", Some("b.c.mm")),
            ("a.b.c.mm", Some("b.c.mm")),
            ("jp", None),
            ("test.jp", Some("test.jp")),
            ("www.test.jp", Some("test.jp")),
            ("ac.jp", None),
            ("test.ac.jp", Some("test.ac.jp")),
            ("www.test.ac.jp", Some("test.ac.jp")),
            ("kyoto.jp", None),
            ("test.kyoto.jp", Some("test.kyoto.jp")),
            ("ide.kyoto.jp", None),
            ("b.ide.kyoto.jp", Some("b.ide.kyoto.jp")),
            ("a.b.ide.kyoto.jp", Some("b.ide.kyoto.jp")),
            ("c.kobe.jp", None),
            ("b.c.kobe.jp", Some("b.c.kobe.jp")),
            ("a.b.c.kobe.jp", Some("b.c.kobe.jp")),
            ("city.kobe.jp", Some("city.kobe.jp")),
            ("www.city.kobe.jp", Some("city.kobe.jp")),
            ("ck", None),
            ("test.ck", None),
            ("b.test.ck", Some("b.test.ck")),
            ("a.b.test.ck", Some("b.test.ck")),
            ("www.ck", Some("www.ck")),
            ("www.www.ck", Some("www.ck")),
            ("us", None),
            ("test.us", Some("test.us")),
            ("www.test.us", Some("test.us")),
            ("ak.us", None),
            ("test.ak.us", Some("test.ak.us")),
            ("www.test.ak.us", Some("test.ak.us")),
            ("k12.ak.us", None),
            ("test.k12.ak.us", Some("test.k12.ak.us")),
            ("www.test.k12.ak.us", Some("test.k12.ak.us")),
            ("xn--85x722f.com.cn", Some("xn--85x722f.com.cn")),
            ("xn--85x722f.xn--55qx5d.cn", Some("xn--85x722f.xn--55qx5d.cn")),
            ("www.xn--85x722f.xn--55qx5d.cn", Some("xn--85x722f.xn--55qx5d.cn")),
            ("shishi.xn--55qx5d.cn", Some("shishi.xn--55qx5d.cn")),
            ("xn--55qx5d.cn", None),
            ("xn--85x722f.xn--fiqs8s", Some("xn--85x722f.xn--fiqs8s")),
            ("www.xn--85x722f.xn--fiqs8s", Some("xn--85x722f.xn--fiqs8s")),
            ("shishi.xn--fiqs8s", Some("shishi.xn--fiqs8s")),
            ("xn--fiqs8s", None),
        ];
        for (host, want) in cases {
            assert_eq!(
                registrable_domain(host),
                *want,
                "registrable_domain({host:?})"
            );
        }
    }

    #[test]
    fn absurd_input_does_not_widen_anything() {
        assert_eq!(registrable_domain(""), None);
        // Deeper than MAX_LABELS: falls back to the implicit `*` rule, which
        // yields the SMALLEST possible registrable domain rather than the
        // largest -- wrong in the safe direction.
        // Deeper than MAX_LABELS. The walk is truncated, not abandoned, so
        // the answer stays correct -- and it genuinely IS the same site.
        let deep = "a.".repeat(40) + "example.com";
        assert_eq!(registrable_domain(&deep), Some("example.com"));
        assert!(same_site(&deep, "other.example.com"));

        // The case the truncation must not get wrong: equally deep, but under
        // a multi-label public suffix. Giving up and using the rightmost label
        // would make both of these `co.uk` and therefore one site.
        let deep_a = "x.".repeat(40) + "alpha.co.uk";
        let deep_b = "y.".repeat(40) + "beta.co.uk";
        assert_eq!(registrable_domain(&deep_a), Some("alpha.co.uk"));
        assert!(!same_site(&deep_a, &deep_b));

        assert_eq!(registrable_domain("a..b.com"), None);
        assert_eq!(registrable_domain("trailing.com."), None);
    }
}
