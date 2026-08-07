//! The licence verifying keys, compiled into the binary — the discipline of
//! `crates/update/src/keys.rs`, restated rather than shared because the two
//! rings are separate signing concerns (design 2.4) and must rotate
//! independently.

use ed25519_dalek::VerifyingKey;

use crate::error::LicenceError;
use crate::hex;

/// The compiled-in licence verification key ring, as hex strings. key_id in
/// a token is an INDEX into this slice (design 2.4).
///
/// key_id 0 is the REAL licence verifying key, minted by the project owner's
/// ceremony on 2026-08-05 with the same house tool as the release and
/// blocklist keys (`patanyx-sign keygen ... licence`). The signing half
/// lives on the server for the licence server to mint with; it is never in
/// this repository. From this commit on, `licence_keys()` succeeds and
/// `the_real_ring_builds_and_carries_key_id_zero` pins it (the inversion of
/// `placeholder_keys_are_refused_not_merely_inert`, exactly as that test's
/// comment instructed).
///
/// Why compiled in: a key fetched over the network authenticates nothing,
/// because whoever can substitute the token-checker can substitute the key.
///
/// Why a RING that only ever grows: rotation (design 2.5). Minting moves
/// to the newest key while tokens signed by older keys are still in the
/// field and must verify until their natural expiry; renewals reuse the
/// same license_id, so a paying user may hold an old-key token right up to
/// the day they renew. Dropping a key early would break exactly those
/// users. The ring holds 32-byte keys; the cost of keeping them all is
/// nothing. (An earlier draft also justified this with a perpetual
/// fallback entitlement; that fallback was removed by deliberate decision
/// 2026-08-05 -- see the design preamble -- and the rotation argument
/// above stands on its own.)
pub const LICENCE_KEYS: &[&str] =
    &["46ce8d667a534c78c194f732a7635c03d778248fa1b4da104442bcf4730b1615"];

/// The parsed ring. Construct once at startup; `Token::parse` borrows it.
#[derive(Debug, Clone)]
pub struct LicenceKeys {
    keys: Vec<VerifyingKey>,
}

impl LicenceKeys {
    /// An empty ring is rejected rather than merely failing closed: zero
    /// trusted keys is a build mistake, and build mistakes should be loud.
    ///
    /// A WEAK (small-order) key is rejected for the same reason and a
    /// sharper one. The all-zeros placeholder decodes to a valid
    /// small-order point — so it parses, and a build carrying it looks
    /// configured. Signatures can be crafted that verify against such a key
    /// for ANY message, so the placeholder is not merely inert: it is the
    /// one input that would make forged tokens verify. Refusing turns that
    /// into `NoLicenceKeys`/`BadKey` at startup — the truth, and impossible
    /// to mistake for a bad paste.
    pub fn new(keys: Vec<VerifyingKey>) -> Result<Self, LicenceError> {
        if keys.is_empty() {
            return Err(LicenceError::NoLicenceKeys);
        }
        if keys.iter().any(VerifyingKey::is_weak) {
            return Err(LicenceError::BadKey(
                "a licence key is a small-order Ed25519 point -- this is the \
                 all-zeros placeholder, not a real key. Generate the signing \
                 keypair under the offline-discipline of design 2.4 and paste \
                 the verifying key into LICENCE_KEYS."
                    .to_string(),
            ));
        }
        Ok(Self { keys })
    }

    /// Build from hex-encoded keys, the shape compiled-in key material most
    /// conveniently takes (`const LICENCE_KEYS: &[&str] = &[...]`).
    pub fn from_hex(encoded: &[&str]) -> Result<Self, LicenceError> {
        let mut keys = Vec::with_capacity(encoded.len());
        for (index, s) in encoded.iter().enumerate() {
            let raw = hex::decode_32(s).map_err(|_| {
                LicenceError::BadKey(format!("licence key #{index} is not valid hex"))
            })?;
            let key = VerifyingKey::from_bytes(&raw).map_err(|_| {
                LicenceError::BadKey(format!("licence key #{index} is not an Ed25519 public key"))
            })?;
            keys.push(key);
        }
        Self::new(keys)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Always false — construction rejects the empty ring — but provided so
    /// no caller is tempted to re-check a state that cannot exist.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// key_id is an index into the ring (design 2.4). Out of range is
    /// `None`, which the validator reports as `UnknownKeyId`.
    pub(crate) fn get(&self, key_id: u8) -> Option<&VerifyingKey> {
        self.keys.get(key_id as usize)
    }
}

/// Build the ring from the compiled-in `LICENCE_KEYS` table. Fails loudly
/// while the table is empty — see the const's comment.
pub fn licence_keys() -> Result<LicenceKeys, LicenceError> {
    LicenceKeys::from_hex(LICENCE_KEYS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_real_ring_builds_and_carries_key_id_zero() {
        // The inversion of `placeholder_keys_are_refused_not_merely_inert`,
        // performed the day the project owner's ceremony produced the first real
        // key (2026-08-05), exactly as that test's comment instructed. The
        // shipped ring must build, hold exactly the ceremony's one key at
        // key_id 0, and refuse the out-of-range ids the validator maps to
        // UnknownKeyId.
        let ring = licence_keys().expect("the shipped LICENCE_KEYS ring builds");
        assert_eq!(ring.len(), 1, "one ceremony, one key, key_id 0");
        assert!(ring.get(0).is_some());
        assert!(ring.get(1).is_none());
        assert_eq!(LICENCE_KEYS.len(), 1);
    }

    #[test]
    fn an_empty_ring_is_a_loud_build_mistake() {
        assert!(matches!(
            LicenceKeys::new(vec![]),
            Err(LicenceError::NoLicenceKeys)
        ));
        assert!(matches!(
            LicenceKeys::from_hex(&[]),
            Err(LicenceError::NoLicenceKeys)
        ));
    }

    #[test]
    fn a_weak_key_is_refused_not_merely_inert() {
        // 32 zero bytes decode to a valid small-order point; signatures can
        // be crafted that verify against it for ANY message, so accepting
        // it would be worse than accepting nothing.
        let weak = VerifyingKey::from_bytes(&[0u8; 32]).expect("all-zeros decodes");
        assert!(weak.is_weak());
        assert!(matches!(
            LicenceKeys::new(vec![weak]),
            Err(LicenceError::BadKey(_))
        ));
        let zeros_hex = "00".repeat(32);
        assert!(matches!(
            LicenceKeys::from_hex(&[&zeros_hex]),
            Err(LicenceError::BadKey(_))
        ));
    }

    #[test]
    fn from_hex_rejects_bad_hex_and_wrong_lengths() {
        let not_hex = "zz".repeat(32);
        assert!(matches!(
            LicenceKeys::from_hex(&[&not_hex]),
            Err(LicenceError::BadKey(_))
        ));
        assert!(matches!(
            LicenceKeys::from_hex(&["ab"]),
            Err(LicenceError::BadKey(_))
        ));
        let too_long = "ab".repeat(33);
        assert!(matches!(
            LicenceKeys::from_hex(&[&too_long]),
            Err(LicenceError::BadKey(_))
        ));
    }

    #[test]
    fn from_hex_accepts_a_real_key_and_indexes_it_at_key_id_zero() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let hex_key = to_hex(&signing.verifying_key().to_bytes());
        let ring = LicenceKeys::from_hex(&[&hex_key]).expect("a real key builds a ring");
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());
        assert!(ring.get(0).is_some());
        assert!(ring.get(1).is_none());
        // Key tables are typed by humans; uppercase input is accepted.
        let upper = hex_key.to_uppercase();
        assert!(LicenceKeys::from_hex(&[&upper]).is_ok());
    }
}
