// The length-prefixed framing in front of `decode`. Fuzzed separately because
// the length prefix is its own attack surface: the header claims a size, and
// the guarantee is that a hostile claim costs at most the 4 bytes of prefix
// rather than an allocation.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = patanyx_chat::wire::read_frame(&mut cursor);
});
