use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    /// Truncated file, bad magic, unknown header version (the message carries
    /// the offending version byte, e.g. "unsupported version 0x02"),
    /// implausible KDF parameters, or an undecodable payload.
    #[error("invalid vault file: {0}")]
    BadFormat(String),
    /// Wrong passphrase and tampered ciphertext/header are deliberately
    /// indistinguishable: both surface as this single AEAD failure.
    #[error("wrong passphrase or corrupted vault")]
    AuthFailed,
    #[error("vault already exists at {}", .0.display())]
    AlreadyExists(PathBuf),
    /// Another PATANYX process has this vault open.
    ///
    /// Refusing is the point. Two instances each hold their own decrypted
    /// copy and `save` writes the WHOLE payload, so whichever saves last
    /// silently discards everything the other did -- no error, no conflict,
    /// and a password added an hour ago simply gone.
    #[error("this vault is already open in another PATANYX window")]
    Locked,
    /// The supplied recovery key is not the right shape. Distinct from
    /// `AuthFailed` on purpose: "that is not a recovery key" is a typo the user
    /// can fix, whereas "that is a recovery key but not this vault's" must stay
    /// indistinguishable from tampering.
    #[error("not a valid recovery key")]
    BadRecoveryKey,
    /// This vault was created with no recovery key, so there is no second door
    /// to try.
    #[error("this vault has no recovery key")]
    NoRecoverySlot,
    #[error("no entry with id {0}")]
    NotFound(String),
    /// A contact field failed validation: empty after trimming, or over its
    /// length cap. Distinct from `NotFound` — the caller can fix the input
    /// and retry.
    #[error("invalid contact: {0}")]
    InvalidContact(String),
    /// Two contacts must never share a peer hash: the caller keys its session
    /// map by hash number, so a duplicate would make one contact unreachable.
    /// Rejected rather than silently accepted — and not silently replaced
    /// either, because swapping the key stored under a hash would be an
    /// invisible re-key.
    #[error("a contact with peer hash {0} already exists")]
    DuplicatePeerHash(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// KDF/AEAD parameter or primitive failure; not reachable through normal
    /// user input.
    #[error("cryptographic failure: {0}")]
    Crypto(String),
}
