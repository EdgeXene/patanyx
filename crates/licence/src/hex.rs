//! Lowercase hex decoding, hand-rolled the way the update crate rolls its
//! own: two dozen lines rather than a new dependency. Only decoding exists
//! here — the update crate carries `encode` because its publisher signing
//! tool emits hex; this crate's signing tool does not exist yet (P4), and
//! the tests keep their own throwaway encoder rather than growing API
//! surface ahead of need.

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Exact-length decode: a wrong length is an error, never a truncation.
/// Uppercase is accepted on input (key tables are typed by humans).
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

pub(crate) fn decode_32(s: &str) -> Result<[u8; 32], ()> {
    decode_fixed(s)
}

#[cfg(test)]
mod tests {
    use super::decode_32;

    #[test]
    fn decodes_exactly_32_bytes() {
        assert_eq!(decode_32(&"00".repeat(32)).unwrap(), [0u8; 32]);
        assert_eq!(decode_32(&"ff".repeat(32)).unwrap(), [0xFFu8; 32]);
        let mut expected = [0u8; 32];
        for (i, b) in expected.iter_mut().enumerate() {
            *b = i as u8;
        }
        let encoded: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_32(&encoded).unwrap(), expected);
        assert!(decode_32(&encoded.to_uppercase()).is_ok());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode_32("").is_err());
        assert!(decode_32(&"0".repeat(63)).is_err());
        assert!(decode_32(&"0".repeat(65)).is_err());
        assert!(decode_32(&"zz".repeat(32)).is_err());
    }
}
