// The signed update manifest, fetched over the network on a schedule.
//
// FUZZED WITH THE REAL COMPILED-IN KEYS, so this exercises the path a real
// client takes: every input is opaque attacker bytes until the signature
// verifies, and the point is that PARSING must not panic before that gate is
// reached. An input that actually verifies is not reachable without the
// private key, which is exactly the property being leaned on.
#![no_main]
use libfuzzer_sys::fuzz_target;
use patanyx_update::TrustedKeys;

const PUBLISHER_KEYS: &[&str] = &[
    "49ecd13929f38f8961e52b284bf55d725c38e990fddf4e7ea949729584cc0a09",
    "6c0d4f23c5d5b5fd9c0cb86fddf35cefac44719a710058747cffdfe5235f219b",
];

fuzz_target!(|data: &[u8]| {
    let keys = TrustedKeys::from_hex(PUBLISHER_KEYS).expect("compiled keys parse");
    let _ = patanyx_update::verify_manifest(data, &keys);
});
