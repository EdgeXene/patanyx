//! The recovery key: a second, independent way into the vault.
//!
//! A vault key derived from a passphrase can only ever have one door, because
//! the key IS a function of the passphrase. Forgetting it means the data is
//! gone, with no exception for the owner and no exception for us. That is
//! correct security and unacceptable product behaviour at the same time.
//!
//! So the vault stores a random master key wrapped once per unlock method, and
//! this is the second method: 256 bits from the OS RNG, shown once at creation,
//! meant to be written down and stored physically.
//!
//! It is NOT a backdoor. It is generated on the user's machine, never
//! transmitted, and cannot be reconstructed by anyone who did not see it. The
//! honest trade is that a key which exists can be stolen or compelled, which is
//! why creating one is refusable.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto;
use crate::error::VaultError;

/// 256 bits. Far beyond brute force, and the reason unwrapping with a recovery
/// key needs no slow KDF (see `crypto::derive_from_recovery`).
pub const RECOVERY_LEN: usize = 32;

/// Printed in groups of two bytes, matching how fingerprints are shown
/// elsewhere in the project. Grouping is not decoration: people transcribe
/// these by hand off paper, and ungrouped hex is where digits get dropped.
const GROUP_BYTES: usize = 2;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; RECOVERY_LEN]);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(crypto::random_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_LEN] {
        &self.0
    }

    /// Grouped lowercase hex, the form shown to the user exactly once.
    pub fn to_printable(&self) -> String {
        let mut out = String::with_capacity(RECOVERY_LEN * 2 + RECOVERY_LEN / GROUP_BYTES);
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 && i % GROUP_BYTES == 0 {
                out.push('-');
            }
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Parses a key back, tolerating the grouping separators, surrounding
    /// whitespace and case that hand transcription produces.
    ///
    /// Anything not exactly the right length is rejected rather than padded:
    /// a partially recalled recovery key is not a recovery key, and accepting
    /// one would only produce a confusing authentication failure later.
    pub fn parse(input: &str) -> Result<Self, VaultError> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        if cleaned.len() != RECOVERY_LEN * 2 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VaultError::BadRecoveryKey);
        }
        let mut bytes = [0u8; RECOVERY_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
                .map_err(|_| VaultError::BadRecoveryKey)?;
        }
        let key = Self(bytes);
        bytes.zeroize();
        Ok(key)
    }
}

impl fmt::Debug for RecoveryKey {
    /// Never render the key itself, including through `{:?}` in a log line or
    /// a panic message. A recovery key in a crash report is a compromised
    /// vault.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ() {
        assert_ne!(
            RecoveryKey::generate().as_bytes(),
            RecoveryKey::generate().as_bytes()
        );
    }

    #[test]
    fn printable_form_round_trips() {
        let key = RecoveryKey::generate();
        let printed = key.to_printable();
        assert_eq!(RecoveryKey::parse(&printed).unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn parsing_tolerates_how_people_actually_type_it() {
        let key = RecoveryKey::generate();
        let printed = key.to_printable();
        for variant in [
            printed.replace('-', ""),
            printed.to_uppercase(),
            format!("  {printed}  "),
            printed.replace('-', " "),
        ] {
            assert_eq!(
                RecoveryKey::parse(&variant).unwrap().as_bytes(),
                key.as_bytes(),
                "failed on variant {variant:?}"
            );
        }
    }

    #[test]
    fn partial_or_malformed_keys_are_refused() {
        let printed = RecoveryKey::generate().to_printable();
        for bad in [
            String::new(),
            printed[..printed.len() - 4].to_string(),
            format!("{printed}00"),
            "z".repeat(RECOVERY_LEN * 2),
        ] {
            assert!(matches!(
                RecoveryKey::parse(&bad),
                Err(VaultError::BadRecoveryKey)
            ));
        }
    }

    #[test]
    fn debug_never_prints_the_key() {
        let key = RecoveryKey::generate();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&key.to_printable()));
        assert_eq!(rendered, "RecoveryKey(redacted)");
    }
}
