// The link readout (crates/app/src/hover.rs). A link target is page data,
// chosen by whoever wrote the page, and the readout is where the browser shows
// it as text the user trusts. Beyond not panicking, this asserts the readout's
// own promises: nothing at all for a non-web scheme, never an empty bar, never
// longer than its budget, and never a character that can make a URL read as a
// different site.
#![no_main]
use libfuzzer_sys::fuzz_target;
use patanyx_app::fuzz_api::{hover_is_deceptive, hover_readout, HOVER_MAX_CHARS};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let lower = raw.trim().to_ascii_lowercase();
    let web = lower.starts_with("http://") || lower.starts_with("https://");
    if let Some(shown) = hover_readout(raw) {
        assert!(web, "a non-web target was shown: {raw:?}");
        assert!(!shown.is_empty(), "an empty readout instead of None");
        let chars = shown.chars().count();
        assert!(chars <= HOVER_MAX_CHARS, "readout over budget: {chars} chars");
        assert!(
            !shown.chars().any(|c| hover_is_deceptive(c) || c.is_control()),
            "a deceptive or control character reached the readout: {shown:?}"
        );
    }
});
