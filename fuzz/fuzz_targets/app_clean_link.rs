// "Copy clean link" (crates/app/src/ipc.rs) on a page-supplied URL: unwrap a
// known redirect wrapper, then strip tracking parameters. Asserts the contracts
// both steps document, not only that they return:
//
//   * unwrapping returns the input unchanged or an accepted http(s)
//     destination: at most 4096 bytes, no whitespace or control byte;
//   * stripping only removes, keeps the fragment as it was, and is stable (a
//     second pass finds nothing left to remove).
#![no_main]
use libfuzzer_sys::fuzz_target;
use patanyx_app::fuzz_api::{clean_link, strip_tracking_params, unwrap_redirect};

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else {
        return;
    };

    let unwrapped = unwrap_redirect(url);
    if unwrapped != url {
        let lower = unwrapped.to_ascii_lowercase();
        assert!(
            lower.starts_with("http://") || lower.starts_with("https://"),
            "unwrapped to a non-web destination: {unwrapped:?}"
        );
        assert!(unwrapped.len() <= 4096, "unwrapped past the length cap");
        assert!(
            !unwrapped.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
            "unwrapped to a destination with whitespace or a control byte: {unwrapped:?}"
        );
    }

    let stripped = strip_tracking_params(url);
    assert!(stripped.len() <= url.len(), "stripping made the URL longer");
    if let Some(at) = url.find('#') {
        assert!(stripped.ends_with(&url[at..]), "stripping changed the fragment");
    }
    assert_eq!(
        strip_tracking_params(&stripped),
        stripped,
        "a second strip still found something to remove"
    );

    assert_eq!(clean_link(url), strip_tracking_params(&unwrapped));
});
