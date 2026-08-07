use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    /// Truncated file, bad magic (including a vault file presented to this
    /// store), unknown header version, implausible KDF parameters, or an
    /// undecodable payload.
    #[error("invalid store file: {0}")]
    BadFormat(String),
    /// Wrong passphrase and tampered ciphertext/header are deliberately
    /// indistinguishable: both surface as this single AEAD failure.
    #[error("wrong passphrase or corrupted store")]
    AuthFailed,
    #[error("store already exists at {}", .0.display())]
    AlreadyExists(PathBuf),
    #[error("no entry with id {0}")]
    NotFound(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// KDF/AEAD parameter or primitive failure; not reachable through normal
    /// user input. Kept coarse so it cannot become an oracle.
    #[error("cryptographic failure: {0}")]
    Crypto(String),
}
