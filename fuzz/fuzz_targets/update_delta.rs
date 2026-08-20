// The delta decoder: DEFLATE over a raw bsdiff control stream.
//
// The caller hash-checks the patch before calling this, so reaching it needs
// a signed manifest. It is fuzzed anyway because "parse attacker input only
// after a hash check" is a property that can regress, and because the
// decompression bomb guard (a hard output limit) is exactly the kind of
// bound a fuzzer is good at probing.
//
// The first 8 bytes steer `expected_size` so the fuzzer can explore both
// sides of that limit instead of always tripping the same early return; the
// value is capped so a run cannot try to allocate the machine to death.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let (head, rest) = data.split_at(8);
    let raw = u64::from_le_bytes(head.try_into().expect("8 bytes"));
    let expected_size = raw % (4 * 1024 * 1024);
    let split = rest.len() / 2;
    let (old, patch) = rest.split_at(split);
    let _ = patanyx_update::apply_delta(old, patch, expected_size);
});
