//! Verification of the downloaded binary against a verified manifest.

use sha2::{Digest, Sha256};

use crate::error::UpdateError;
use crate::manifest::Manifest;

/// Confirm that `bytes` is EXACTLY the payload `manifest` promises: the
/// length matches and the SHA-256 matches. There is no "probably": any
/// deviation is a hard `Err`, and the hash comparison runs in constant time.
///
/// The manifest is authentic by construction (only `verify_manifest` can
/// make one), so a mismatch here means the network — or a mirror, or a
/// cache — served something other than what the publisher signed. That is
/// precisely the substitution this whole design exists to refuse.
pub fn verify_payload(bytes: &[u8], manifest: &Manifest) -> Result<(), UpdateError> {
    // Length first: it is cheap, and a wrong-length payload is not worth
    // hashing. This reveals nothing secret — the manifest is public.
    let actual = bytes.len() as u64;
    if actual != manifest.size() {
        return Err(UpdateError::PayloadLength {
            expected: manifest.size(),
            actual,
        });
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if !constant_time_eq(&digest, manifest.sha256()) {
        return Err(UpdateError::PayloadHash);
    }
    Ok(())
}

/// Fixed-trip comparison: the loop always runs all 32 bytes and branches on
/// nothing derived from the data, so its duration says nothing about WHERE
/// two digests first differ. The hash in a manifest is public, so the direct
/// stake here is low — the point is that "compare digests in constant time"
/// is a rule with no exceptions, because the day it is bent for convenience
/// is the day the same habit is missing somewhere the stake is not low.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    // End-to-end behaviour is covered by the crate-level tests; here only
    // the primitive itself.
    #[test]
    fn constant_time_eq_behaves_like_eq() {
        let a = [7u8; 32];
        let mut b = a;
        assert!(super::constant_time_eq(&a, &b));
        b[31] ^= 1;
        assert!(!super::constant_time_eq(&a, &b));
        b[31] ^= 1;
        b[0] ^= 1;
        assert!(!super::constant_time_eq(&a, &b));
    }
}

/// The blocklist counterpart of [`verify_payload`]: same guarantee, different
/// manifest type.
///
/// Deliberately a separate function rather than a generic over "things with a
/// hash and a size". The two channels carry different documents and are
/// verified under different signing domains; a shared abstraction here would
/// invite exactly the kind of call site that passes the wrong manifest and
/// still compiles.
pub fn verify_blocklist_bytes(
    bytes: &[u8],
    manifest: &crate::BlocklistManifest,
) -> Result<(), UpdateError> {
    let actual = bytes.len() as u64;
    if actual != manifest.size() {
        return Err(UpdateError::PayloadLength {
            expected: manifest.size(),
            actual,
        });
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if !constant_time_eq(&digest, manifest.sha256()) {
        return Err(UpdateError::PayloadHash);
    }
    Ok(())
}
