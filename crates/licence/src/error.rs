//! The one error enum for the crate, in the workspace's `UpdateError`
//! style: one variant per failure class, no user-facing copy.
//!
//! Why no copy: the paste-flow messages in design 3.2 are DRAFT and belong
//! to the app layer (P2). This crate returns typed errors; the app maps
//! them to reviewed strings. Two mappings the design fixes are recorded on
//! the variants: `NotAToken` and `CrcMismatch` share one user message (a
//! truncated paste is the common cause of both), and an
//! `expires_day < features_until_day` token is reported as `BadSignature`
//! (3.2 step 6: "treat as step 4 failure").

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LicenceError {
    /// Design 3.2 step 1: after stripping all ASCII whitespace the text did
    /// not carry the `ptx1-` prefix — a `ptx2-` prefix from a future layout
    /// lands here too, by design — or the base64url payload did not decode.
    #[error("not a PATANYX licence token (bad prefix or undecodable base64url)")]
    NotAToken,

    /// Design 3.2 step 2: the decoded length is not 94 bytes, or the CRC-32
    /// over bytes 0..89 did not match. Checked before any cryptography so a
    /// truncated paste is reported as a paste problem, not a forgery.
    #[error("token is truncated or corrupted (length or CRC-32 check failed)")]
    CrcMismatch,

    /// Design 3.2 step 3: `key_id` is an INDEX into the compiled-in ring
    /// (2.4) and this build carries no key at that index. Almost always
    /// means the token was minted by a key newer than this build.
    #[error("token names licence key id {key_id}, which this build does not carry")]
    UnknownKeyId { key_id: u8 },

    /// Design 3.2 step 4 — and step 6: the Ed25519 signature did not verify
    /// strictly against the named key, OR the token is internally
    /// inconsistent (`expires_day < features_until_day`). No legitimate
    /// signer produces the second shape, and the design maps it to this
    /// class rather than inventing a "malformed but honestly signed"
    /// category the user cannot act on.
    #[error("token signature does not verify against the named key")]
    BadSignature,

    /// Design 3.2 step 5: the tier byte reserves future tiers; only 0x01
    /// (premium) exists. Same "needs a newer version" user message as
    /// `UnknownKeyId`, but a distinct variant so tests and logs can tell
    /// them apart.
    #[error("token carries unknown tier byte {tier:#04x}")]
    UnknownTier { tier: u8 },

    /// Ring construction refused: zero verifying keys compiled in. An empty
    /// ring is a build mistake, and build mistakes should be loud — see the
    /// long comment on `LICENCE_KEYS`.
    #[error("no licence verifying keys are compiled into this build")]
    NoLicenceKeys,

    /// Ring construction refused: a compiled-in key is not hex of an
    /// Ed25519 point, or is a weak (small-order) point. The all-zeros
    /// placeholder decodes as small-order, and signatures can be crafted
    /// that verify against such a key for ANY message — hence refusal, not
    /// inertness.
    #[error("a compiled-in licence key is unusable: {0}")]
    BadKey(String),
}
