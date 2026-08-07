//! Level 4: a MinHash sketch over word shingles of the visible text.
//!
//! Why MinHash and not SimHash: SimHash gives unrelated texts a similarity
//! of ~0.5 (random 64-bit sketches differ in ~32 bits), which is a terrible
//! answer to "how same is this page". MinHash estimates the Jaccard
//! similarity of the shingle sets directly, so unrelated texts score ~0.0
//! and "97% the same" actually means 97% of shingles are shared.
//!
//! Determinism: the 64 coefficient pairs are fixed constants derived from
//! SHA-256 of a versioned seed string — no randomness, no time, no HashMap.
//! Hashing is `(a*x + b) mod (2^61 - 1)` in u128, which is exact on every
//! platform. Change nothing here without bumping the seed label: any change
//! invalidates every stored digest.

use sha2::{Digest, Sha256};

/// Number of minima in the sketch. Similarity granularity is 1/64 (~1.6%);
/// the standard error at p=0.9 is ~4%.
pub const MINHASH_COUNT: usize = 64;

/// Words per shingle. 3-word shingles localize edits (one changed word
/// disturbs ~3 shingles) while staying robust to single-word churn.
const SHINGLE_K: usize = 3;

/// Mersenne prime 2^61 - 1: large enough that shingle-hash collisions are
/// negligible, small enough that `a*x + b` fits a u128 with room to spare.
const P: u64 = (1u64 << 61) - 1;

/// Versioned seed for coefficient derivation. Bump = new digest format.
const COEFF_SEED: &[u8] = b"patanyx-integrity/minhash/v1";

/// 64 minima over the word 3-shingles of `text` (already
/// whitespace-normalized with single-space separators). Empty text yields
/// the all-`u64::MAX` sentinel sketch, so two empty texts compare as fully
/// similar (their level-3 hashes match anyway, so compare() never reaches
/// the sketch for them).
pub fn minhash(text: &str) -> Vec<u64> {
    let mut mins = vec![u64::MAX; MINHASH_COUNT];
    if text.is_empty() {
        return mins;
    }
    let words: Vec<&str> = text.split(' ').filter(|w| !w.is_empty()).collect();
    if words.is_empty() {
        return mins;
    }
    let coeffs = coefficients();
    if words.len() < SHINGLE_K {
        // Too few words for a 3-shingle: the whole text is one shingle, so
        // identical tiny texts score 1.0 and different ones ~0.0.
        absorb(&Sha256::digest(text.as_bytes()), &coeffs, &mut mins);
    } else {
        for window in words.windows(SHINGLE_K) {
            let mut h = Sha256::new();
            for (i, w) in window.iter().enumerate() {
                if i > 0 {
                    h.update(b" ");
                }
                h.update(w.as_bytes());
            }
            absorb(&h.finalize(), &coeffs, &mut mins);
        }
    }
    mins
}

/// Jaccard estimate in 0.0..=1.0. Wrong-length sketches (corrupt stored
/// data) return 0.0 rather than panicking.
pub fn similarity(a: &[u64], b: &[u64]) -> f32 {
    if a.len() != MINHASH_COUNT || b.len() != MINHASH_COUNT {
        return 0.0;
    }
    let equal = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    equal as f32 / MINHASH_COUNT as f32
}

fn absorb(digest: &[u8], coeffs: &[(u64, u64); MINHASH_COUNT], mins: &mut [u64]) {
    let mut xb = [0u8; 8];
    xb.copy_from_slice(&digest[..8]);
    let x = u64::from_le_bytes(xb) % P;
    for (i, &(a, b)) in coeffs.iter().enumerate() {
        let v = ((a as u128 * x as u128 + b as u128) % P as u128) as u64;
        if v < mins[i] {
            mins[i] = v;
        }
    }
}

/// The 64 hash functions, as (a, b) pairs for `(a*x + b) mod P` with
/// a in [1, P-1]. Derived deterministically from SHA-256 so there is no
/// table of magic constants to audit and no RNG anywhere.
fn coefficients() -> [(u64, u64); MINHASH_COUNT] {
    let mut out = [(0u64, 0u64); MINHASH_COUNT];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut h = Sha256::new();
        h.update(COEFF_SEED);
        h.update((i as u32).to_le_bytes());
        let d = h.finalize();
        let mut a8 = [0u8; 8];
        a8.copy_from_slice(&d[0..8]);
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&d[8..16]);
        let a = u64::from_le_bytes(a8) % (P - 1) + 1;
        let b = u64::from_le_bytes(b8) % P;
        *slot = (a, b);
    }
    out
}
