//! Per-record HMAC authentication for download provenance.
//!
//! Scope of the guarantee, stated once and precisely: a valid HMAC proves
//! the record has not been altered **since it was recorded, to the owner**
//! — and it proves nothing to anyone else. The MAC key is derived from the
//! store key, which is derived from the owner's passphrase; anyone with the
//! passphrase can forge records, and no one can verify a record without
//! it. This is intentionally NOT a signature: the browser's identity key is
//! X25519 (Diffie-Hellman), which cannot sign, and third-party-verifiable
//! provenance would require a separate Ed25519 identity decision.
//!
//! This is a low-level module exposed so records can be built/verified
//! independently of an open `Store` (and so the tamper property is directly
//! testable). Prefer `Store::record_download` / `Store::verify_download`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::KEY_LEN;
use crate::model::DownloadRecord;

type HmacSha256 = Hmac<Sha256>;

/// Key-separation label: the provenance MAC key must not be usable as an
/// encryption key or vice versa.
const MAC_KEY_LABEL: &[u8] = b"patanyx-store/provenance-mac-key/v1";
/// Domain label prefixed to every record MAC, so a record MAC can never be
/// confused with a MAC computed for some future purpose.
const RECORD_DOMAIN: &[u8] = b"patanyx-store/download-record/v1";

/// Derive the provenance MAC key from the store key. HMAC-SHA256 is used
/// here as a one-step PRF (a standard extract-with-label construction); no
/// HKDF crate needed.
pub fn mac_key(store_key: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(store_key)
        .expect("HMAC-SHA256 accepts keys of any length; this is infallible");
    mac.update(MAC_KEY_LABEL);
    let out = mac.finalize().into_bytes();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&out);
    key
}

/// Length-prefix each field: without it, ("ab","c") and ("a","bc") would
/// MAC identically. Integers are little-endian so the encoding is
/// platform-independent.
fn feed(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_le_bytes());
    mac.update(field);
}

/// Compute the HMAC-SHA256 for one record's canonical field encoding.
#[allow(clippy::too_many_arguments)]
pub fn record_mac(
    key: &[u8; KEY_LEN],
    id: &str,
    url: &str,
    filename: &str,
    byte_len: u64,
    sha256: &[u8; 32],
    recorded_at: u64,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of any length; this is infallible");
    mac.update(RECORD_DOMAIN);
    feed(&mut mac, id.as_bytes());
    feed(&mut mac, url.as_bytes());
    feed(&mut mac, filename.as_bytes());
    mac.update(&byte_len.to_le_bytes());
    feed(&mut mac, sha256);
    mac.update(&recorded_at.to_le_bytes());
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Recompute the record's MAC and compare in constant time
/// (`Mac::verify_slice`), so verification does not leak where a forged tag
/// first differs.
pub fn verify(key: &[u8; KEY_LEN], record: &DownloadRecord) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of any length; this is infallible");
    mac.update(RECORD_DOMAIN);
    feed(&mut mac, record.id.as_bytes());
    feed(&mut mac, record.url.as_bytes());
    feed(&mut mac, record.filename.as_bytes());
    mac.update(&record.byte_len.to_le_bytes());
    feed(&mut mac, &record.sha256);
    mac.update(&record.recorded_at.to_le_bytes());
    mac.verify_slice(&record.hmac).is_ok()
}
