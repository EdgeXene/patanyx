//! base64url (RFC 4648 section 5), NO padding, hand-written for the same
//! reason the update crate hand-writes its hex: the signer (mint, and later
//! the project owner's tool) and the verifier (parse) share one codec, and a
//! codec bug that only affected one side would mint tokens every browser
//! refuses. The alphabet is small enough that a table and two loops are the
//! whole implementation.
//!
//! Decode is strict, because a bearer token should have exactly one text
//! form:
//! * `=` padding is rejected — the text form is unpadded by definition, so
//!   a padded paste is a corrupted paste;
//! * characters outside the URL-safe alphabet are rejected;
//! * a length of 1 mod 4 is rejected (it cannot encode any whole number of
//!   bytes);
//! * non-canonical trailing bits are rejected: the unused low bits of the
//!   final character must be zero, so two different strings cannot decode
//!   to the same token.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3f] as char);
        }
    }
    out
}

fn value_of(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

pub(crate) fn decode(input: &str) -> Result<Vec<u8>, ()> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(());
    }
    // Canonical-form check on the final character's unused low bits.
    if let Some(&last) = bytes.last() {
        let value = value_of(last).ok_or(())?;
        let unused = match bytes.len() % 4 {
            2 => 4,
            3 => 2,
            _ => 0,
        };
        let mask = (1u8 << unused) - 1;
        if value & mask != 0 {
            return Err(());
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for &b in chunk {
            n = (n << 6) | u32::from(value_of(b).ok_or(())?);
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                out.push((n >> 10) as u8);
                out.push((n >> 2) as u8);
            }
            2 => {
                out.push((n >> 4) as u8);
            }
            _ => unreachable!("chunks are 4, or 2/3 on the final partial chunk"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors_without_padding() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in cases {
            assert_eq!(encode(bytes), text);
            assert_eq!(decode(text).unwrap(), bytes);
        }
    }

    #[test]
    fn the_url_safe_alphabet_is_used_and_the_standard_one_rejected() {
        // 0xfb 0xff 0xfe -> 6-bit groups 62, 63, 63, 62 -> "-__-": both
        // URL-safe substitute characters, in both positions. (The draft
        // this landed from pinned this vector wrong; it was recomputed by
        // hand before landing.)
        assert_eq!(encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(decode("-__-").unwrap(), vec![0xfb, 0xff, 0xfe]);
        assert!(decode("+/+/").is_err());
    }

    #[test]
    fn padding_is_rejected() {
        assert!(decode("Zg==").is_err());
        assert!(decode("Zm8=").is_err());
        assert!(decode("====").is_err());
    }

    #[test]
    fn a_length_of_one_mod_four_cannot_encode_bytes() {
        assert!(decode("Z").is_err());
        assert!(decode("Zm9vY").is_err());
    }

    #[test]
    fn non_canonical_trailing_bits_are_rejected() {
        // 'h' is alphabet index 33; a 2-char final group carries 8 payload
        // bits, so the low 4 bits of the final character (0b0001 for 'h')
        // must be zero.
        assert!(decode("Zh").is_err());
        assert_eq!(decode("Zg").unwrap(), b"f");
        // '9' is alphabet index 61 (0b111101); a 3-char final group carries
        // 16 payload bits, so the low 2 bits (0b01) must be zero.
        assert!(decode("Zm9").is_err());
        assert_eq!(decode("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn invalid_characters_are_rejected() {
        assert!(decode("Zm 9").is_err());
        assert!(decode("Zm9v!bcd").is_err());
        assert!(decode("Zm9\u{a0}").is_err());
    }

    #[test]
    fn round_trips_every_length_up_to_128() {
        for len in 0..=128usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes, "length {len}");
        }
    }
}
