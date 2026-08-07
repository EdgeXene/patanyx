//! Lowercase hex, hand-rolled the way the vault crate rolls its IDs: two
//! small functions rather than a new dependency for sixteen lines of code.

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encoding has no caller in the BROWSER -- it only ever decodes hex the
/// publisher produced -- but it has one in publisher tooling, which emits a
/// verifying key and a signature as hex (`examples/patanyx-sign.rs`). It was
/// `#[cfg(test)]` until that tool existed, which is also why `HEX_DIGITS`
/// warned as unused in every non-test build.
///
/// Signer and verifier sharing one implementation is worth more than the
/// sixteen lines it saves: a hex bug that only affected the signer would
/// produce manifests every install refuses.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Exact-length decode: a wrong length is an error, never a truncation.
/// Uppercase is accepted on input (key tables are typed by humans); output
/// encoding is always lowercase.
fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], ()> {
    if s.len() != N * 2 {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(bytes[2 * i]).ok_or(())?;
        let lo = nibble(bytes[2 * i + 1]).ok_or(())?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

pub fn decode_32(s: &str) -> Result<[u8; 32], ()> {
    decode_fixed(s)
}

pub fn decode_64(s: &str) -> Result<[u8; 64], ()> {
    decode_fixed(s)
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let encoded = super::encode(&bytes);
        assert_eq!(encoded.len(), 64);
        assert_eq!(super::decode_32(&encoded).unwrap(), bytes);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(super::decode_32("").is_err());
        assert!(super::decode_32(&"0".repeat(63)).is_err());
        assert!(super::decode_32(&"0".repeat(65)).is_err());
        assert!(super::decode_32(&"zz".repeat(32)).is_err());
        assert!(super::decode_32(&"A".repeat(64)).is_ok());
    }
}
