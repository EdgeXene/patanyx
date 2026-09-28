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
    /// A bounded collection is at its limit. Its own variant rather than an
    /// io error: nothing is wrong with the disk or the file, the answer is
    /// simply no, and the caller should say so plainly rather than reporting
    /// a fault. Carries what is full and what the limit is.
    #[error("{0}")]
    Full(String),
    /// The Library's directory entry could not be confirmed flushed, so a
    /// power loss could still bring a previous file back. Only
    /// `Store::confirm_durable` reports it: a passphrase change asks for that
    /// guarantee before the vault moves, because losing the Library's move
    /// into the vault after that point would strand it. The caller must treat
    /// the Library as saved, never as absent, and must not move the vault.
    #[error("saved, but the save could not be confirmed on disk: {0}")]
    NotDurable(std::io::Error),
    /// A version 1 Library, which opens only with the passphrase, and none
    /// was given: the vault was unlocked with the recovery key. Nothing is
    /// wrong with the file.
    #[error("this Library opens with the passphrase, and none was given")]
    NeedsPassphrase,
    /// A version 3 Library whose key this vault could not unwrap, or whose
    /// contents then failed to open: it was made under another vault, or it is
    /// damaged, and the two are deliberately indistinguishable. No passphrase
    /// helps, unlike `AuthFailed` on a version 1 file, so it has its own
    /// variant and the app never offers the passphrase repair for it.
    #[error("the Library does not open with this vault, or is corrupted")]
    VaultMismatch,
    /// PATANYX could not confirm that every leftover copy of the Library's
    /// version 1 file is gone: one could not be proven to be this Library's,
    /// or the directory could not be listed, a leftover read or removed, or
    /// the directory flushed (see `retire.rs`). The Library itself is fine.
    #[error("not every leftover copy of the Library could be confirmed gone: {0}")]
    LeftoversRetained(String),
}
