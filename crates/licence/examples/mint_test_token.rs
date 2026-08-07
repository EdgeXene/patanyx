//! Mints a test licence token and prints the verifying key and the 90-byte
//! wire form as hex. Test tooling for scripts/relay-token-log-gate.sh: the
//! gate drives a live relay (RELAY_REQUIRE_TOKEN=1, RUST_LOG=trace) with
//! registrations carrying these tokens and asserts the token hex and the
//! license_id hex appear in NO captured output (design 4.3). The relay's
//! auth tests also use it to (re)generate their pinned fixture.
//!
//! Only ever run with a THROWAWAY seed. It exists to make test tokens, and
//! nothing here is a real signing key.
//!
//! Usage: mint_test_token <seed-hex-64> <key-id> <license-id-hex-32> <expires-day>
//! stdout:
//!   KEY_HEX=<64 lowercase hex>     verifying key, for RELAY_LICENCE_KEYS
//!   WIRE_HEX=<180 lowercase hex>   token.to_wire_bytes(), for the Register frame

use ed25519_dalek::SigningKey;
use patanyx_licence::Token;

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

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <seed-hex-64> <key-id> <license-id-hex-32> <expires-day>",
            args[0]
        );
        std::process::exit(2);
    }
    let seed: [u8; 32] = hex_decode(&args[1])
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| {
            eprintln!("seed must be 32 bytes (64 hex chars)");
            std::process::exit(2);
        });
    let key_id: u8 = args[2].parse().unwrap_or_else(|_| {
        eprintln!("key-id must be 0..=255");
        std::process::exit(2);
    });
    let license_id: [u8; 16] = hex_decode(&args[3])
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| {
            eprintln!("license-id must be 16 bytes (32 hex chars)");
            std::process::exit(2);
        });
    let expires_day: u32 = args[4].parse().unwrap_or_else(|_| {
        eprintln!("expires-day must be a u32 day number");
        std::process::exit(2);
    });

    let signing_key = SigningKey::from_bytes(&seed);
    let token = Token::mint(&signing_key, key_id, license_id, expires_day);
    println!(
        "KEY_HEX={}",
        hex_lower(&signing_key.verifying_key().to_bytes())
    );
    println!("WIRE_HEX={}", hex_lower(&token.to_wire_bytes()));
}
