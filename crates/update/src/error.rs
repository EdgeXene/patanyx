use thiserror::Error;

/// Errors from manifest and payload verification.
///
/// The granularity is deliberate, and mirrors the vault's split between
/// `BadFormat` and `AuthFailed`. Everything about the SIGNATURE collapses
/// into one variant so a would-be forger learns nothing from the error:
/// "no trusted key produced a valid signature" is all there is to say.
/// Structural problems (oversize, trailing data, bad JSON) and payload
/// problems (wrong length, wrong hash) are distinct because they describe
/// data, not cryptography — and the UI is expected to show them honestly.
#[derive(Debug, Error)]
pub enum UpdateError {
    /// Bytes that do not even parse as an update manifest: too large,
    /// trailing data, not the expected JSON, bad hex, wrong wire version, or
    /// out-of-range fields. Most attacker-controlled input lands here.
    #[error("malformed manifest: {0}")]
    Malformed(String),

    /// The signature did not verify under ANY trusted key. Forgery, a
    /// tampered field, and a signature from an untrusted key are deliberately
    /// indistinguishable: anything more specific would be an oracle for which
    /// key or which field failed.
    #[error("manifest signature does not verify against any trusted key")]
    BadSignature,

    /// Compiled-in key material that does not decode as an Ed25519 public
    /// key. Distinct from `BadSignature` on purpose: this is a build
    /// configuration error, not a runtime verification event, and it should
    /// be loud.
    #[error("invalid trusted key: {0}")]
    BadKey(String),

    /// Zero trusted keys were configured. Verification with zero keys would
    /// fail closed anyway; refusing to construct the set makes the build
    /// mistake impossible to miss.
    #[error("no trusted update keys configured")]
    NoTrustedKeys,

    /// The downloaded payload's length differs from the signed manifest.
    /// Usually a truncated download; also what a substitution attempt looks
    /// like before the hash is even checked.
    #[error("payload is {actual} bytes, but the signed manifest says {expected}")]
    PayloadLength { expected: u64, actual: u64 },

    /// The payload is the right length but hashes differently than the
    /// signed manifest promises. Compared in constant time; there is no
    /// "close enough".
    #[error("payload hash does not match the signed manifest")]
    PayloadHash,
}
