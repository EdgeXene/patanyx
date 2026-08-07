//! Identities and the user-visible "hash number".
//!
//! There is no account, no registration, and no server involvement in identity:
//! a keypair is generated locally and its fingerprint IS the address. Because
//! the fingerprint is bound to the key that decrypts traffic, an address is
//! self-authenticating — a relay cannot impersonate anyone or sit in the middle,
//! and comparing hash numbers out of band is the entire verification step.

use std::fmt;

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Bytes of the fingerprint shown to users. 16 bytes (128 bits) makes an
/// accidental collision impossible in practice and a deliberate one infeasible:
/// second-preimage work is 2^128, and the birthday bound across every address
/// ever generated is 2^64.
pub const FINGERPRINT_LEN: usize = 16;

/// Domain separator so a fingerprint can never be confused with a hash computed
/// for another purpose over the same key bytes.
const FINGERPRINT_CONTEXT: &[u8] = b"patanyx-chat/fingerprint/v1";

/// A contact-facing keypair. The project owner holds one of these PER CONTACT, so
/// revoking one person is deleting one key and nobody else's address changes.
/// Contacts cannot correlate the same user across conversations because each
/// sees an unrelated public key.
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    /// Fresh identity from the OS RNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Rebuild from stored secret bytes (the vault holds these for persistent
    /// contacts; ephemeral chats never call this).
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let mut bytes = bytes;
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// The address handed to exactly one contact.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // StaticSecret zeroizes itself via the `zeroize` feature; this exists so
        // the guarantee is visible at the type that owns it.
    }
}

impl fmt::Debug for Identity {
    /// Never render the secret, including through `{:?}` in a log or a panic
    /// message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// A peer address: the truncated hash of an X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    pub fn of(public: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_CONTEXT);
        hasher.update(public.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; FINGERPRINT_LEN];
        out.copy_from_slice(&digest[..FINGERPRINT_LEN]);
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// Grouped lowercase hex, e.g. `f81c-2a7b-...`. Grouping exists because
    /// users compare these by eye or read them aloud to verify a contact, and
    /// ungrouped hex is where transcription errors hide.
    pub fn to_hash_number(self) -> String {
        let mut out = String::with_capacity(FINGERPRINT_LEN * 2 + FINGERPRINT_LEN / 2 - 1);
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                out.push('-');
            }
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Parses a hash number, ignoring grouping separators and case. Returns
    /// None rather than a partial match: an address that is not exactly right
    /// is not an address.
    pub fn parse_hash_number(input: &str) -> Option<Self> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        if cleaned.len() != FINGERPRINT_LEN * 2 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; FINGERPRINT_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hash_number())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hash_number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identities_are_distinct() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.public_bytes(), b.public_bytes());
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_is_stable_for_a_key() {
        let id = Identity::generate();
        assert_eq!(id.fingerprint(), id.fingerprint());
    }

    #[test]
    fn secret_bytes_round_trip_to_the_same_identity() {
        let original = Identity::generate();
        let restored = Identity::from_secret_bytes(original.secret_bytes());
        assert_eq!(original.public_bytes(), restored.public_bytes());
        assert_eq!(original.fingerprint(), restored.fingerprint());
    }

    #[test]
    fn hash_number_round_trips() {
        let id = Identity::generate();
        let printed = id.fingerprint().to_hash_number();
        assert_eq!(
            Fingerprint::parse_hash_number(&printed),
            Some(id.fingerprint())
        );
    }

    #[test]
    fn hash_number_parsing_tolerates_formatting_but_not_errors() {
        let id = Identity::generate();
        let printed = id.fingerprint().to_hash_number();
        let ungrouped = printed.replace('-', "");
        let spaced = format!("  {}  ", printed.to_uppercase());
        assert_eq!(
            Fingerprint::parse_hash_number(&ungrouped),
            Some(id.fingerprint())
        );
        assert_eq!(
            Fingerprint::parse_hash_number(&spaced),
            Some(id.fingerprint())
        );
        // Wrong length, non-hex, and empty are all rejected outright.
        assert_eq!(Fingerprint::parse_hash_number(&ungrouped[..30]), None);
        assert_eq!(Fingerprint::parse_hash_number(""), None);
        assert_eq!(
            Fingerprint::parse_hash_number(&"z".repeat(FINGERPRINT_LEN * 2)),
            None
        );
    }

    #[test]
    fn debug_never_leaks_the_secret() {
        let id = Identity::generate();
        let rendered = format!("{id:?}");
        let secret_hex: String = id
            .secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!rendered.contains(&secret_hex));
        assert!(rendered.contains(&id.fingerprint().to_hash_number()));
    }
}
