// A frame from another person's machine. The highest-reachability parser in
// the tree: a chat peer sends these, so a panic here is a remote crash with
// no user action.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = patanyx_chat::wire::decode(data);
});
