// The records inside a whole-Library backup (file version 4), after the
// authentication a fuzzer cannot forge: the bytes are sealed exactly as an
// export seals them and read back by the import's reader, so the frame
// parser, the per-kind size limits, the vault section, the END manifest and
// the "nothing after END" rule all see arbitrary input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    patanyx_vault::fuzz_read_sealed(data);
});
