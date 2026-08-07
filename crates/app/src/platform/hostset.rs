//! A large, allocation-free host blocklist.
//!
//! Separate from `privacy::RuleSet` on purpose, and the separation is a
//! security property rather than tidiness. `decide_request` gates ad blocking
//! on `policy.block_ads && rules.blocks_host(..)`, so folding malicious hosts
//! into the same set would mean **turning off ad blocking also turns off
//! malware blocking**. Those are different decisions and a user who makes one
//! must not silently make the other.
//!
//! # Why not just a bigger `Vec<String>`
//!
//! `RuleSet::blocks_host` is a linear scan. At the 51 bundled ad hosts that is
//! free. A malicious-domain list is 10k-200k entries, and on Windows the scan
//! runs inside the `WebResourceRequested` COM handler **on the UI thread, for
//! every request the page makes**. 200k string comparisons per subresource is
//! not a budget that exists.
//!
//! So: a sorted index, and lookup walks the candidate suffixes of the host
//! rather than the rules. A host has at most a handful of labels, so the work
//! is bounded by the HOST, not by the list. At 400k entries a lookup is a
//! handful of hashes and ~19 binary-search probes of one integer compare each.
//!
//! # Why 128-bit hashes and not the hosts themselves
//!
//! This stored the hosts as text, arguing that a 64-bit hash set would be
//! smaller but a collision "would silently block a legitimate site with no way
//! to diagnose it". That reasoning was right and is answered by WIDTH rather
//! than abandoned.
//!
//! What forced the change: shipping ~400k domain names as plaintext inside an
//! executable makes it look like malware to signature scanners, because a
//! phishing blocklist and a banking trojan contain the same strings for
//! opposite reasons. On 2026-07-29 ClamAV quarantined every Windows build of
//! this browser as `Win.Keylogger.Stawin-9837241-0` -- five bank names ANDed
//! together. That is not a problem that can be argued with on a user's machine.
//!
//! At 128 bits the probability that a host a user visits collides with any of
//! ~400k entries is about 10^-33 per lookup. Diagnosability survives because
//! [`HostSet::matched_rule`] returns the CANDIDATE IT HASHED -- a slice of the
//! caller's own host string -- so the interstitial still names what matched.
//! Nothing is read back out of storage, so nothing needs to be stored in
//! readable form.
//!
//! Hashes are also 72% smaller than the text, and a sorted integer index is an
//! ordinary data structure rather than a packed blob that would itself look
//! evasive.

// Acceptance and hashing rules, shared verbatim with build.rs so the
// compiled hashes and `from_lines` can never disagree.
include!("hostrules.rs");

/// An immutable set of blocked hosts, matched by suffix on label boundaries.
///
/// Built once and swapped wholesale when a refreshed list arrives -- never
/// mutated in place, so a request being decided can never observe a half-built
/// list.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostSet {
    /// Sorted, deduplicated `hash_host` values. Sorted so lookup is a binary
    /// search; deduplicated so `len()` is the number of distinct hosts.
    hashes: Vec<u128>,
}

impl HostSet {
    /// Parses the same minimal format `RuleSet::from_lines` uses: one host per
    /// line, `#` comments, blank lines ignored.
    ///
    /// Entries are REJECTED rather than accepted-and-never-matched when they
    /// cannot possibly match a real host. Hosts reach us punycode-encoded from
    /// the engine, so a non-ASCII rule would sit in the list looking like
    /// protection and match nothing -- the worst kind of failure for a security
    /// list. Rejecting loudly at load is the only honest option.
    pub fn from_lines(input: &str) -> Self {
        Self {
            hashes: hashes_from_lines(input),
        }
    }

    /// The compiled form: little-endian `u128` hashes, already sorted.
    ///
    /// This is how the bundled list and every refreshed list arrive. Trailing
    /// bytes that do not form a whole hash are a TRUNCATED file, and a
    /// truncated blocklist is a partial one -- refused rather than silently
    /// used, because a set that quietly lost its tail is exactly the failure
    /// mode this module exists to prevent.
    ///
    /// Re-sorted and deduplicated rather than trusted: the search below is
    /// only correct on sorted input, and a mis-ordered file would make lookups
    /// miss unpredictably instead of failing.
    pub fn from_hashes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() % 16 != 0 {
            return None;
        }
        let mut hashes: Vec<u128> = bytes
            .chunks_exact(16)
            .map(|c| u128::from_le_bytes(c.try_into().expect("chunks_exact(16)")))
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        Some(Self { hashes })
    }

    /// The compiled form, for writing.
    pub fn to_hashes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.hashes.len() * 16);
        for h in &self.hashes {
            out.extend_from_slice(&h.to_le_bytes());
        }
        out
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The rule that matched, or `None`.
    ///
    /// Returns the RULE rather than a bool so the interstitial can name what
    /// matched -- telling a user "example.com is on the list" is actionable in
    /// a way that "this page was blocked" is not, and a probe can assert on it.
    ///
    /// Walks the host's suffixes right-to-left: `a.b.example.com` tries
    /// `a.b.example.com`, `b.example.com`, `example.com`. Each is one binary
    /// search. No allocation anywhere on this path.
    pub fn matched_rule<'h>(&self, host: &'h str) -> Option<&'h str> {
        if self.is_empty() || host.is_empty() || host.len() > MAX_HOST_LEN {
            return None;
        }
        // Trailing dot is legal in a URL and means the same host.
        let host = host.strip_suffix('.').unwrap_or(host);

        let mut start = 0usize;
        for _ in 0..MAX_RULE_LABELS {
            let candidate = &host[start..];
            // Returns the CANDIDATE, not something read back from storage --
            // which is what keeps the interstitial able to name the rule now
            // that the hosts themselves are not kept.
            if !candidate.is_empty() && self.contains(candidate) {
                return Some(candidate);
            }
            match host[start..].find('.') {
                // Advance past the next dot to drop one leading label.
                Some(dot) => start += dot + 1,
                None => break,
            }
            if start >= host.len() {
                break;
            }
        }
        None
    }

    /// Whether the set holds this exact host.
    ///
    /// Case is folded before hashing rather than during comparison: hashing is
    /// exact-match on bytes, so `EVIL.example` and `evil.example` must reach
    /// the same value or a host would evade the list by capitalisation.
    ///
    /// The lowercase copy is the one allocation on this path, and only for
    /// hosts that are not already lowercase -- which, coming from `host_of`,
    /// is nearly none of them.
    fn contains(&self, host: &str) -> bool {
        self.hashes.binary_search(&hash_host(host)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(lines: &str) -> HostSet {
        HostSet::from_lines(lines)
    }

    #[test]
    fn matches_on_label_boundaries_only() {
        let s = set("evil.example\nphish.test\n");
        assert_eq!(s.matched_rule("evil.example"), Some("evil.example"));
        assert_eq!(s.matched_rule("login.evil.example"), Some("evil.example"));
        assert_eq!(s.matched_rule("a.b.c.evil.example"), Some("evil.example"));
        // Suffix without a boundary is a DIFFERENT domain.
        assert_eq!(s.matched_rule("notevil.example"), None);
        // The rule as a prefix of a longer domain is also different.
        assert_eq!(s.matched_rule("evil.example.safe.test"), None);
        assert_eq!(s.matched_rule("unrelated.test"), None);
    }

    #[test]
    fn matching_is_case_insensitive_without_allocating_a_lowercase_copy() {
        let s = set("evil.example\n");
        // The rule comes back in the CALLER's casing now, because it is a
        // slice of the host they passed rather than something read out of
        // storage -- storage holds hashes. Same host either way (hostnames are
        // case-insensitive), and arguably better for the interstitial, which
        // now echoes the address as the user saw it.
        assert_eq!(s.matched_rule("EVIL.EXAMPLE"), Some("EVIL.EXAMPLE"));
        assert_eq!(s.matched_rule("Login.Evil.Example"), Some("Evil.Example"));
        // The point of the test: casing does not change WHETHER it matches.
        assert!(s.matched_rule("eViL.eXaMpLe").is_some());
    }

    #[test]
    fn trailing_dot_is_the_same_host() {
        let s = set("evil.example\n");
        assert_eq!(s.matched_rule("evil.example."), Some("evil.example"));
    }

    #[test]
    fn returns_the_rule_not_the_host() {
        // The interstitial names the rule. Returning the host would tell the
        // user "login.evil.example is blocked" when what is listed is the
        // parent domain, which is misleading about the scope of the block.
        let s = set("evil.example\n");
        assert_eq!(s.matched_rule("login.evil.example"), Some("evil.example"));
    }

    #[test]
    fn parses_comments_blank_lines_and_hosts_file_shape() {
        let s = set("# a comment\n\n  evil.example  \n0.0.0.0 phish.test\n127.0.0.1\tbad.test\n");
        assert!(s.matched_rule("evil.example").is_some());
        assert!(s.matched_rule("phish.test").is_some());
        assert!(s.matched_rule("bad.test").is_some());
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn rejects_entries_that_could_never_match_rather_than_storing_them() {
        // Non-ASCII: hosts arrive punycode, so a unicode rule would sit in the
        // list looking like protection and match nothing.
        let s = set("bösewicht.example\nevil.example\n");
        assert_eq!(s.len(), 1);
        assert!(s.matched_rule("evil.example").is_some());

        // A bare TLD would block an entire suffix of the internet.
        assert_eq!(set("com\n").len(), 0);
        // Malformed boundaries break the arithmetic the whole match relies on.
        assert_eq!(set(".evil.example\n").len(), 0);
        assert_eq!(set("evil.example.\n").len(), 0);
        assert_eq!(set("evil..example\n").len(), 0);
    }

    #[test]
    fn url_shaped_feed_junk_is_rejected() {
        // Every one of these is a lightly-anonymised REAL line that passed
        // acceptance before 2026-07-31 -- 95 of them were sitting in the
        // shipped list as hashes that could never match, because a parsed
        // host cannot contain `/ ? % : @` or a space. They inflate the count
        // a marketing page quotes while providing nothing.
        for junk in [
            "%20mailer.example",
            "203.0.113.9?rid=abc123",
            "evil.example/login?token=x",
            "https://evil.example/path",
            "user@evil.example",
            "evil.example:8080",
            "trailing-colon.example:",
        ] {
            assert_eq!(set(&format!("{junk}\n")).len(), 0, "{junk}");
        }
        // Underscore is invalid DNS but engines navigate to it, so a rule
        // carrying one can genuinely match and must stay accepted.
        assert_eq!(set("weird_host.example\n").len(), 1);
        // 63 bytes is the DNS label cap; 64 is not a navigable name.
        assert_eq!(set(&format!("{}.example\n", "a".repeat(63))).len(), 1);
        assert_eq!(set(&format!("{}.example\n", "a".repeat(64))).len(), 0);
    }

    #[test]
    fn a_bare_shared_platform_suffix_is_refused_but_its_subdomains_are_not() {
        // `github.io` as a rule is a feed accident that blocks every project
        // page on the platform; `evil.github.io` is an ordinary, correct rule
        // that upstream feeds carry constantly. The tripwire must tell them
        // apart exactly.
        for suffix in PROTECTED_SUFFIXES {
            assert_eq!(set(&format!("{suffix}\n")).len(), 0, "bare {suffix}");
            let sub = format!("evil.{suffix}\n");
            assert_eq!(set(&sub).len(), 1, "subdomain of {suffix}");
        }
    }

    #[test]
    fn duplicates_collapse_and_order_does_not_matter() {
        let a = set("b.example\na.example\nb.example\n");
        let b = set("a.example\nb.example\n");
        assert_eq!(a.len(), 2);
        assert_eq!(a, b, "the built set must not depend on input order");
    }

    #[test]
    fn empty_set_matches_nothing() {
        // The probe's most important control runs against an empty list, and a
        // lookup into one must be a clean miss rather than a panic on the
        // offsets index.
        let s = set("# nothing but a comment\n");
        assert!(s.is_empty());
        assert_eq!(s.matched_rule("evil.example"), None);
    }

    #[test]
    fn deep_and_oversized_hosts_terminate() {
        let s = set("evil.example\n");
        // Deeper than MAX_RULE_LABELS: must not loop forever, must not match.
        let deep = "a.".repeat(64) + "unrelated.test";
        assert_eq!(s.matched_rule(&deep), None);
        // Over the length bound: rejected outright.
        let long = "a".repeat(300) + ".test";
        assert_eq!(s.matched_rule(&long), None);
    }

    #[test]
    fn a_deeply_nested_host_still_finds_a_shallow_rule() {
        // The walk must reach the parent domain even from far down, up to the
        // label cap. This is the case a phishing subdomain actually looks like.
        let s = set("evil.example\n");
        let host = "a.b.c.d.e.f.evil.example";
        assert_eq!(s.matched_rule(host), Some("evil.example"));
    }

    #[test]
    fn scales_to_a_realistic_list() {
        // Not a benchmark -- a check that the structure holds at a size where
        // a linear scan would be the wrong answer, and that a near-miss
        // neighbour of a real entry does not match.
        let mut lines = String::new();
        for i in 0..50_000 {
            lines.push_str(&format!("host{i}.example\n"));
        }
        let s = set(&lines);
        assert_eq!(s.len(), 50_000);
        assert!(s.matched_rule("host49999.example").is_some());
        assert!(s.matched_rule("sub.host0.example").is_some());
        assert_eq!(s.matched_rule("host50000.example"), None);
        assert_eq!(s.matched_rule("nothost0.example"), None);
    }
}

#[cfg(test)]
mod probe_assumption {
    use super::*;
    #[test]
    fn an_ip_literal_is_usable_as_a_rule() {
        // malicious-probe.ps1 lists 127.0.0.1 and matches on the Host header.
        // If `acceptable` rejected it the probe would silently test nothing.
        let s = HostSet::from_lines("127.0.0.1\n");
        assert_eq!(s.len(), 1);
        assert_eq!(s.matched_rule("127.0.0.1"), Some("127.0.0.1"));
        assert_eq!(s.matched_rule("127.0.0.2"), None);
    }
}
