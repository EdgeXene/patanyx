use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::StoreError;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

/// Domain separation from the vault's key. The passphrase is pre-hashed
/// with this label before Argon2id, so the store key and the vault key are
/// unrelated even when derived from the same passphrase. (The per-file
/// random salt already separates them in practice; the label makes the
/// separation explicit and robust even against a salt collision or a future
/// refactor that shares salt files.)
const KDF_DOMAIN: &[u8] = b"patanyx-store/kdf/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Argon2id(SHA-256(domain || passphrase), salt, params) -> 32-byte key.
///
/// The passphrase is only ever borrowed (never copied into an owned
/// buffer); the domain-separated pre-hash and the derived key both live in
/// `Zeroizing` wrappers so all key material is wiped on drop.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    let mut pre = Sha256::new();
    pre.update(KDF_DOMAIN);
    pre.update([0x00]);
    pre.update(passphrase);
    let digest = pre.finalize();
    let mut domain_separated = Zeroizing::new([0u8; KEY_LEN]);
    domain_separated.copy_from_slice(&digest);

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|e| StoreError::Crypto(format!("invalid argon2 parameters: {e}")))?,
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(&domain_separated[..], salt, &mut key[..])
        .map_err(|e| StoreError::Crypto(format!("argon2 key derivation failed: {e}")))?;
    Ok(key)
}

pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| StoreError::Crypto(format!("cipher init: {e:?}")))?;
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| StoreError::Crypto("aead encryption failed".to_string()))
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| StoreError::Crypto(format!("cipher init: {e:?}")))?;
    // Every AEAD failure maps to AuthFailed so that a wrong passphrase is
    // indistinguishable from tampered data.
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| StoreError::AuthFailed)?;
    Ok(Zeroizing::new(plaintext))
}
