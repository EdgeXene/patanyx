//! Test tooling for the licence server's smoke script (Phase 4): given a
//! THROWAWAY seed, does a `prx1-` receipt the server returned verify under
//! the browser's own crate, and does it bind to the right device and not to
//! another? Answers on stdout so a shell can pattern-match it:
//!
//! ```text
//! cargo run -p patanyx-licence --example check_receipt -- \
//!     <seed-hex-64> <key-id> <ptx1-token> <prx1-receipt> <device-hex-32> <other-device-hex-32>
//! stdout: BINDS=yes|no NOTBIND=yes|no
//! ```
//!
//! `BINDS` is whether the receipt binds to (token, device); `NOTBIND` is
//! whether it correctly does NOT bind to (token, other device). A healthy
//! run prints `BINDS=yes NOTBIND=yes`. Exit 1 if the receipt does not even
//! verify, 2 on usage errors. Seed and key id are arguments because the ring
//! under test is the throwaway one, never this build's compiled-in ring.

use std::process::ExitCode;

use ed25519_dalek::SigningKey;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn hex16(s: &str) -> Option<[u8; 16]> {
    hex_decode(s)?.try_into().ok()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [seed_hex, key_id, token_text, receipt_text, device_hex, other_hex] = args.as_slice()
    else {
        eprintln!(
            "usage: check_receipt <seed-hex-64> <key-id> <ptx1-token> <prx1-receipt> \
             <device-hex-32> <other-device-hex-32>"
        );
        return ExitCode::from(2);
    };
    let (Some(seed), Ok(key_id), Some(device), Some(other)) = (
        hex_decode(seed_hex.trim()),
        key_id.parse::<u8>(),
        hex16(device_hex),
        hex16(other_hex),
    ) else {
        eprintln!("bad arguments");
        return ExitCode::from(2);
    };
    let Ok(seed): Result<[u8; 32], _> = seed.try_into() else {
        eprintln!("seed must be 32 bytes");
        return ExitCode::from(2);
    };
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let ring = match patanyx_licence::LicenceKeys::new(vec![key; usize::from(key_id) + 1]) {
        Ok(ring) => ring,
        Err(error) => {
            eprintln!("ring: {error}");
            return ExitCode::from(2);
        }
    };
    let token = match patanyx_licence::Token::parse(token_text, &ring) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("token REFUSED: {error}");
            return ExitCode::FAILURE;
        }
    };
    let receipt = match patanyx_licence::Receipt::parse(receipt_text, &ring) {
        Ok(receipt) => receipt,
        Err(error) => {
            eprintln!("receipt REFUSED: {error}");
            return ExitCode::FAILURE;
        }
    };
    let binds = receipt.binds(&token, &device);
    let not_bind = !receipt.binds(&token, &other);
    println!(
        "BINDS={} NOTBIND={}",
        if binds { "yes" } else { "no" },
        if not_bind { "yes" } else { "no" }
    );
    ExitCode::SUCCESS
}
