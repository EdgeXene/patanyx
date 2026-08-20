// The blocklist manifest, refreshed hourly from the distribution host. Same
// shape as the update manifest but a different signing domain and its own
// key, and it is fetched far more often.
#![no_main]
use libfuzzer_sys::fuzz_target;
use patanyx_update::TrustedKeys;

const BLOCKLIST_KEYS: &[&str] =
    &["49ecd13929f38f8961e52b284bf55d725c38e990fddf4e7ea949729584cc0a09"];

fuzz_target!(|data: &[u8]| {
    let keys = TrustedKeys::from_hex(BLOCKLIST_KEYS).expect("compiled keys parse");
    let _ = patanyx_update::verify_blocklist_manifest(data, &keys);
});
