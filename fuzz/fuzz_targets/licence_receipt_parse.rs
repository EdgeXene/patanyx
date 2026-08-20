// The activation receipt. It arrives in an HTTP response body, so it is
// network input parsed on the client, and it shares the token's decoder
// while carrying a different length and signing domain.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let keys = match patanyx_licence::licence_keys() {
        Ok(k) => k,
        Err(_) => return,
    };
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = patanyx_licence::Receipt::parse(text, &keys);
    }
});
