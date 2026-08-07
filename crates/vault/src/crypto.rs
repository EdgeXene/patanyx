use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::VaultError;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

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

/// Argon2id(passphrase, salt, params) -> 32-byte key.
///
/// The passphrase is only ever borrowed (never copied into an owned buffer),
/// and the derived key is returned already wrapped in `Zeroizing`, so all
/// key material is wiped on drop.
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|e| VaultError::Crypto(format!("invalid argon2 parameters: {e}")))?,
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|e| VaultError::Crypto(format!("argon2 key derivation failed: {e}")))?;
    Ok(key)
}

/// HKDF-SHA256(recovery_key, salt) -> 32-byte slot key.
///
/// Deliberately a FAST kdf, unlike the passphrase path. Argon2id exists to make
/// guessing expensive, and guessing is only a threat when the input has little
/// entropy. A recovery key is 256 random bits from the OS RNG, so there is
/// nothing to slow down: an attacker who must brute force it has already lost,
/// and making the owner wait seconds to use their own paper backup would buy
/// exactly nothing.
pub fn derive_from_recovery(
    recovery: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), recovery);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"patanyx-vault/recovery-slot/v1", &mut key[..])
        .map_err(|e| VaultError::Crypto(format!("hkdf expand failed: {e}")))?;
    Ok(key)
}

pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("cipher init: {e:?}")))?;
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Crypto("aead encryption failed".to_string()))
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("cipher init: {e:?}")))?;
    // Every AEAD failure maps to AuthFailed so that a wrong passphrase is
    // indistinguishable from tampered data.
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::AuthFailed)?;
    Ok(Zeroizing::new(plaintext))
}
