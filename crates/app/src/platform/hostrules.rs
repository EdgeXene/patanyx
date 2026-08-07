// Host acceptance and hashing, shared by the crate and by build.rs.
//
// INCLUDED, not imported. build.rs runs before the crate exists, so it cannot
// `use` anything from it; `include!` is how both ends get literally the same
// code. If these rules lived in two places they would drift, and the failure
// would be silent and terrible: the compiled-in hashes would stop
// corresponding to what `from_lines` produces, so a host present in the source
// list would simply never match, and every indicator would still report a
// blocklist of the right size.
//
// Keep this file free of `use` statements and crate paths for that reason --
// it is textually pasted into two different compilation units.

/// Longest host we will even consider. Hosts arrive from `host_of`, which has
/// already parsed them; this is a bound on pathological input rather than a
/// protocol limit.
pub const MAX_HOST_LEN: usize = 253;

/// Deepest rule we accept at load. A rule with more labels than this matches
/// nothing a real host would reach, and the cap keeps the lookup walk bounded
/// so a malformed list cannot make matching slow.
pub const MAX_RULE_LABELS: usize = 16;

/// Shared-infrastructure suffixes a rule must never BE.
///
/// A listed host covers its subdomains, so a bare `github.io` entry would
/// block every project page on the platform in one line. Phishing lives on
/// these platforms constantly -- `evil.github.io` is a fine rule and upstream
/// feeds are full of such entries -- but the bare suffix itself can only ever
/// be a feed accident, and the blast radius of that accident is a large part
/// of the web.
///
/// This is a TRIPWIRE, not the Public Suffix List: two dozen suffixes whose
/// bare blocking would be catastrophic, checked exactly. `acceptable` already
/// refuses single-label rules, which covers every plain TLD; this list covers
/// the multi-label suffixes that rule cannot see.
///
/// THE REPOSITORY DOES NOW SHIP THE FULL PSL (`src/public_suffix_list.txt`,
/// matched by `psl.rs`), which this comment used to argue against carrying.
/// That argument still holds HERE and the two must not be merged. This file is
/// `include!`d verbatim into both build.rs and the runtime, and its whole
/// point is to be textually identical in both; the PSL is 10,000 rules
/// compiled into a hash index for a different question entirely -- "where does
/// one party's domain end", asked of credential matching, not "is this feed
/// entry an accident", asked of a blocklist import. Wiring one to the other
/// would make a blocklist rejection depend on a list that refreshes on its own
/// schedule, for no gain: the catastrophic-bare-suffix set is short, stable,
/// and deliberately curated.
///
/// 2026-07-31: none of these appear as bare entries in the current feeds --
/// this guards the next pull, not the last one.
pub const PROTECTED_SUFFIXES: &[&str] = &[
    // developer platforms
    "github.io",
    "githubusercontent.com",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "glitch.me",
    "repl.co",
    // big shared hosting
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "weebly.com",
    "weeblysite.com",
    // cloud infrastructure
    "amazonaws.com",
    "azurewebsites.net",
    "cloudfront.net",
    "windows.net",
    "googleapis.com",
    // multi-label country registrations
    "co.uk",
    "org.uk",
    "com.au",
    "com.br",
    "co.jp",
    "co.in",
    "com.mx",
];

/// Whether a line can possibly match a real host.
///
/// Entries are REJECTED rather than accepted-and-never-matched. Hosts reach us
/// punycode-encoded from the engine, so a non-ASCII rule would sit in the list
/// looking like protection and match nothing -- the worst kind of failure for
/// a security list.
pub fn acceptable(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        // Punycode only.
        && host.is_ascii()
        // Only bytes that can appear in a host the engine hands us. The
        // 2026-07-31 pull carried 95 entries with `/ ? % : @` or similar --
        // full URLs, query fragments, percent-escapes. A parsed host can
        // contain none of those, so such an entry is dead weight that inflates
        // the count while matching nothing. Underscore stays: it is invalid
        // DNS but engines navigate to it, so a rule for it can really match.
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        // A leading or trailing dot would break the boundary arithmetic and
        // cannot be a real rule.
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.split('.').count() <= MAX_RULE_LABELS
        // DNS caps a label at 63 bytes; nothing navigable exceeds it.
        && host.split('.').all(|label| label.len() <= 63)
        // A bare TLD rule would block an entire suffix. That is never what a
        // blocklist means and is catastrophic if it slips in.
        && host.contains('.')
        // And a bare shared-platform suffix is the same catastrophe with a
        // second label. Subdomain rules on these platforms remain accepted.
        && !PROTECTED_SUFFIXES.contains(&host)
}

/// The stored form of a host: the low 128 bits of its SHA-256.
///
/// WHY 128 AND NOT 64. This file used to store the hosts themselves, with a
/// comment arguing that a 64-bit hash set would be smaller but that a
/// collision "would silently block a legitimate site with no way to diagnose
/// it". That reasoning was right, and it is answered by width rather than
/// abandoned: at 128 bits the chance that any host a user visits collides with
/// one of ~400k entries is around 10^-33 per lookup. Diagnosability is
/// preserved separately -- `matched_rule` returns the candidate it hashed, so
/// the interstitial can still name what matched.
///
/// The input is lowercased by the caller; hashing is exact-match on bytes.
pub fn hash_host(host: &str) -> u128 {
    use sha2::Digest;
    // Lowercased in fixed-size chunks on the stack rather than via
    // `to_ascii_lowercase()`, which would allocate on a path that runs for
    // every request a page makes. Hosts arrive lowercased from `host_of`
    // already; this makes the guarantee hold regardless of caller.
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64];
    for chunk in host.as_bytes().chunks(buf.len()) {
        let lowered = &mut buf[..chunk.len()];
        lowered.copy_from_slice(chunk);
        lowered.make_ascii_lowercase();
        hasher.update(&*lowered);
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(bytes)
}

/// Parse a text list into sorted, deduplicated hashes.
///
/// The same minimal format `RuleSet::from_lines` uses: one host per line, `#`
/// comments, blank lines ignored, and a hosts-file style leading address
/// tolerated by taking the last whitespace-separated field.
pub fn hashes_from_lines(input: &str) -> Vec<u128> {
    let mut out: Vec<u128> = input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().last())
        .filter(|host| acceptable(host))
        .map(hash_host)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}
