//! Applying a published delta to the running binary's bytes.
//!
//! A delta is a TRANSPORT optimization and nothing more. The trust chain is
//! unchanged: the patched result must hash to the signed manifest's own
//! `sha256`, exactly as a full download must, and the caller enforces that
//! with the same `verify_payload` it always ran. This module only turns
//! (old bytes, patch bytes) into candidate new bytes; it proves nothing.
//!
//! FORMAT: DEFLATE over the `bsdiff` crate's raw control stream. Not
//! interchangeable with `bspatch(1)` (bsdiff 4.x wraps its stream in bzip2
//! and a header); nothing outside this repo should be handed one. The
//! generator (`src/bin/patanyx-delta.rs`) uses this module's own
//! [`compress`], so the two halves cannot drift.
//!
//! THE COMPRESSION IS NOT OPTIONAL, and that was measured: bsdiff's raw
//! output is mostly zero bytes by design (it stores byte-wise differences),
//! so uncompressed it runs LARGER than the binary it patches -- an 80 KB
//! fixture produced an 80,060-byte "delta". The manifest validator refused
//! it, correctly, and that refusal is what surfaced the omission. Deflated,
//! the same patch is a small fraction of the payload.
//!
//! WHY THESE CRATES. The obvious pick, `qbsdiff`, is bsdiff-4.x compatible
//! and faster -- and it depends unconditionally on `suffix_array`, whose
//! `cdivsufsort` is C. Only the DIFF half needs a suffix array, but the
//! dependency is not feature-gated, so shipping it broke the Windows
//! cross-compile outright (caught by building for the target, not by
//! reading). `bsdiff` 0.2 has zero dependencies and `miniz_oxide` was
//! already in this tree; both are pure Rust. Do not swap either without
//! cross-compiling first.

use crate::UpdateError;

/// Deflate a raw patch stream. Publish-side only -- the browser never
/// compresses anything -- but it lives here so the format has ONE
/// definition.
pub fn compress(raw: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(raw, 9)
}

/// Patch `old` with `patch`, producing the candidate new binary.
///
/// `expected_size` is the SIGNED full-payload size from the manifest. The
/// result must be exactly that long or this refuses -- a length-correct
/// forgery still has to survive the caller's hash check, so this is the
/// cheap gate in front of the real one.
///
/// Memory is bounded at both layers: inflation is capped at
/// `expected_size + old.len()`, and every output byte then comes from a
/// read of that raw stream, so the result cannot exceed it.
pub fn apply_delta(old: &[u8], patch: &[u8], expected_size: u64) -> Result<Vec<u8>, UpdateError> {
    let cap = usize::try_from(expected_size)
        .map_err(|_| UpdateError::Malformed("delta target size does not fit memory".into()))?;
    // Inflate with a HARD output limit rather than unbounded: the patch is
    // attacker-reachable bytes (it is hash-checked by the caller first, but
    // depth beats order here), and a decompression bomb is the one way a
    // small download could otherwise cost unbounded memory. The raw stream
    // is never usefully larger than old + new, so that sum is the ceiling.
    let raw_limit = cap.saturating_add(old.len());
    let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(patch, raw_limit)
        .map_err(|e| UpdateError::Malformed(format!("delta is not a valid patch: {e:?}")))?;
    let mut out = Vec::with_capacity(cap);
    bsdiff::patch(old, &mut std::io::Cursor::new(&raw), &mut out)
        .map_err(|e| UpdateError::Malformed(format!("delta did not apply: {e}")))?;
    if out.len() as u64 != expected_size {
        return Err(UpdateError::Malformed(format!(
            "delta produced {} bytes but the signed manifest says {expected_size}",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff(old: &[u8], new: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        bsdiff::diff(old, new, &mut raw).expect("diffing in-memory slices cannot fail");
        compress(&raw)
    }

    #[test]
    fn a_generated_delta_reproduces_the_new_bytes_exactly() {
        let old: Vec<u8> = (0u32..40_000).flat_map(|i| i.to_le_bytes()).collect();
        let mut new = old.clone();
        new[1000..1100].fill(0xAB);
        new.extend_from_slice(b"appended tail");
        let patch = diff(&old, &new);
        // The whole reason deltas exist: a small edit must yield a small
        // download. Uncompressed this ran LARGER than the payload.
        assert!(
            patch.len() < new.len() / 10,
            "a small edit must yield a small patch ({} vs {})",
            patch.len(),
            new.len()
        );
        let out = apply_delta(&old, &patch, new.len() as u64).expect("patch applies");
        assert_eq!(out, new);
    }

    #[test]
    fn a_size_lie_is_refused() {
        let old = b"aaaaaaaaaaaaaaaa".to_vec();
        let new = b"aaaaaaaabbbbbbbb".to_vec();
        let patch = diff(&old, &new);
        let err = apply_delta(&old, &patch, new.len() as u64 + 1).unwrap_err();
        assert!(matches!(err, UpdateError::Malformed(_)));
    }

    #[test]
    fn garbage_is_not_a_patch() {
        // Truncated control data: the decoder must error, not read past it.
        assert!(apply_delta(b"old", b"certainly not bsdiff", 3).is_err());
    }

    #[test]
    fn applying_against_the_wrong_old_bytes_yields_wrong_output_not_panic() {
        // The caller's hash check is what catches this case in production;
        // here we pin only that it FAILS SAFE (error or wrong bytes, never
        // a panic or the right bytes).
        let old = b"the version this patch was made from".to_vec();
        let new = b"the version this patch produces!!!!!".to_vec();
        let patch = diff(&old, &new);
        let wrong_old = b"a different binary entirely..!!!!!!!".to_vec();
        match apply_delta(&wrong_old, &patch, new.len() as u64) {
            Ok(out) => assert_ne!(out, new),
            Err(_) => {}
        }
    }

    #[test]
    fn a_patch_cannot_expand_without_bound() {
        // Hostile control values inside a well-formed deflate stream: every
        // output byte still has to come from a read of the raw stream, so
        // the result cannot exceed it, and inflation itself is capped.
        let hostile = {
            let mut v = Vec::new();
            v.extend_from_slice(&u64::MAX.to_le_bytes()); // mix_len
            v.extend_from_slice(&u64::MAX.to_le_bytes()); // copy_len
            v.extend_from_slice(&0u64.to_le_bytes()); // seek
            v.extend_from_slice(b"only a few real bytes follow");
            compress(&v)
        };
        let err = apply_delta(b"old bytes", &hostile, 1 << 30).unwrap_err();
        assert!(matches!(err, UpdateError::Malformed(_)));
    }

    #[test]
    fn a_decompression_bomb_is_refused_by_the_inflate_limit() {
        // 4 MB of zeros deflates to a few KB. Announcing a small target
        // size must make inflation REFUSE rather than allocate 4 MB from a
        // KB-sized download.
        let bomb = compress(&vec![0u8; 4 << 20]);
        assert!(bomb.len() < 64 * 1024, "the bomb must be small on the wire");
        let err = apply_delta(b"tiny old", &bomb, 64).unwrap_err();
        assert!(matches!(err, UpdateError::Malformed(_)));
    }
}
