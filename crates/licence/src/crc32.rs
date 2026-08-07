//! CRC-32 (IEEE 802.3: reflected polynomial 0xEDB88320, init and final XOR
//! 0xFFFFFFFF), hand-written. The token's CRC exists so a truncated or
//! corrupted paste is caught BEFORE any cryptography runs (design 2.3), and
//! mint and parse must compute it identically — one shared implementation,
//! no dependency, no drift.
//!
//! Bitwise, not table-driven: it runs on 90 bytes per paste and per mint,
//! so the eight inner iterations cost nothing and there is no table to
//! mis-generate.

pub(crate) fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Branch-free: mask is all-ones exactly when the low bit was set.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32_ieee;

    #[test]
    fn matches_the_published_check_values() {
        // The standard CRC-32/IEEE check values (as produced by zlib).
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32_ieee(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn every_single_bit_flip_in_90_bytes_changes_the_result() {
        // The token CRC covers bytes 0..89; a paste corrupted anywhere in
        // them must never collide with the original.
        let base = [0x5Au8; 90];
        let original = crc32_ieee(&base);
        for byte in 0..90 {
            for bit in 0..8 {
                let mut flipped = base;
                flipped[byte] ^= 1 << bit;
                assert_ne!(crc32_ieee(&flipped), original);
            }
        }
    }
}
