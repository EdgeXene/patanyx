//! The publisher's verifying keys, compiled into the binary.

use ed25519_dalek::VerifyingKey;

use crate::error::UpdateError;
use crate::hex;

/// The set of Ed25519 public keys an update manifest may be signed with.
///
/// Why compiled in: a key fetched over the network authenticates nothing,
/// because whoever can substitute the update can substitute the key.
///
/// Why MORE THAN ONE: a signing key must be rotatable while old installs are
/// still in the field, and rotation is impossible if only one key can ever
/// be valid. The dance is (1) ship a release signed by the old key whose
/// binary already trusts old AND new, (2) start signing releases with the
/// new key, (3) drop the old key once every supported install trusts the new
/// one. A single hard-coded key makes step 1 impossible, and a compromised
/// key with no rotation path means abandoning the product.
///
/// Construct once at startup from a `const` table of hex strings.
#[derive(Debug, Clone)]
pub struct TrustedKeys {
    keys: Vec<VerifyingKey>,
}

impl TrustedKeys {
    /// An empty set is rejected rather than merely failing closed: zero
    /// trusted keys is a build mistake, and build mistakes should be loud.
    ///
    /// A WEAK (small-order) key is rejected for the same reason and a sharper
    /// one. The placeholder this project ships until the project owner pastes the
    /// real key is 32 zero bytes, which decodes to a valid small-order point
    /// -- so it parsed, and a build carrying it looked configured. Signatures
    /// can be crafted that verify against such a key for ANY message, so the
    /// placeholder was not merely inert: it was the one input that would make
    /// forged manifests verify the moment a reachable endpoint existed.
    ///
    /// Refusing here turns that into `NoTrustedKeys` at startup, which the
    /// panel reports as "updates are not configured for this build" -- the
    /// truth, and impossible to mistake for a transient network fault.
    pub fn new(keys: Vec<VerifyingKey>) -> Result<Self, UpdateError> {
        if keys.is_empty() {
            return Err(UpdateError::NoTrustedKeys);
        }
        if keys.iter().any(VerifyingKey::is_weak) {
            return Err(UpdateError::BadKey(
                "a trusted key is a small-order Ed25519 point -- this is the \
                 all-zeros placeholder, not a publisher key. Generate the \
                 signing keypair offline and paste the verifying key in."
                    .to_string(),
            ));
        }
        Ok(Self { keys })
    }

    /// Build from hex-encoded keys, the shape compiled-in key material most
    /// conveniently takes (`const UPDATE_KEYS: &[&str] = &[...]`).
    pub fn from_hex(encoded: &[&str]) -> Result<Self, UpdateError> {
        let mut keys = Vec::with_capacity(encoded.len());
        for (index, s) in encoded.iter().enumerate() {
            let raw = hex::decode_32(s).map_err(|_| {
                UpdateError::BadKey(format!("trusted key #{index} is not valid hex"))
            })?;
            let key = VerifyingKey::from_bytes(&raw).map_err(|_| {
                UpdateError::BadKey(format!("trusted key #{index} is not an Ed25519 public key"))
            })?;
            keys.push(key);
        }
        Self::new(keys)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Always false — construction rejects the empty set — but provided so
    /// no caller is tempted to re-check a state that cannot exist.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &VerifyingKey> {
        self.keys.iter()
    }
}
