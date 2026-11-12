// The blocklist set (crates/app/src/platform/hostset.rs) in both forms. The
// compiled form is what the browser reads back from disk at every start; the
// text form is what build.rs and a refresh parse. Asserts:
//
//   * the compiled form is refused exactly when it is not whole 16-byte hashes,
//     and round-trips when it is;
//   * a lookup only ever names a label suffix of the host it was given;
//   * a listed host is still found under any number of extra subdomains, the
//     property the 2026-09-01 red-team pass found broken in 0.9.66.
#![no_main]
use libfuzzer_sys::fuzz_target;
use patanyx_app::fuzz_api::HostSet;

/// hostrules.rs MAX_HOST_LEN: longer hosts are never looked up.
const MAX_HOST_LEN: usize = 253;

fuzz_target!(|data: &[u8]| {
    match HostSet::from_hashes(data) {
        None => assert_ne!(data.len() % 16, 0, "whole hashes were refused"),
        Some(set) => {
            assert_eq!(data.len() % 16, 0, "a truncated hash was accepted");
            assert!(set.len() <= data.len() / 16);
            assert_eq!(
                HostSet::from_hashes(&set.to_hashes()).as_ref(),
                Some(&set),
                "the compiled form does not round-trip"
            );
        }
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let set = HostSet::from_lines(text);
    for line in text.lines().take(32) {
        let Some(host) = line.split_whitespace().last() else {
            continue;
        };
        if let Some(rule) = set.matched_rule(host) {
            let h = host.strip_suffix('.').unwrap_or(host);
            assert!(
                h == rule || h.ends_with(&format!(".{rule}")),
                "matched {rule:?}, which is not a label suffix of {host:?}"
            );
        }
        // A host the text form accepted as a rule must be found, at any depth.
        if line.trim_start().starts_with('#') || HostSet::from_lines(host).is_empty() {
            continue;
        }
        assert!(set.matched_rule(host).is_some(), "listed {host:?} was not found");
        let mut padded = host.to_string();
        for depth in 0..40 {
            let next = format!("a{depth}.{padded}");
            if next.len() > MAX_HOST_LEN {
                break;
            }
            padded = next;
        }
        assert!(
            set.matched_rule(&padded).is_some(),
            "listed {host:?} was not found under extra subdomains: {padded:?}"
        );
    }
});
