// A pasted licence token, and the same bytes arrive over the relay in the
// wire form. Text goes in raw: whitespace stripping, the prefix check, the
// base64url decoder, the length and CRC gates and then the signature all sit
// behind this one call.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let keys = match patanyx_licence::licence_keys() {
        Ok(k) => k,
        Err(_) => return,
    };
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = patanyx_licence::Token::parse(text, &keys);
    }
    // The wire form takes bytes directly, with no text stage in front.
    let _ = patanyx_licence::Token::parse_wire(data, &keys);
});
