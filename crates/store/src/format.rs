use crate::crypto::{KdfParams, NONCE_LEN, SALT_LEN};
use crate::error::StoreError;

/// Distinct from the vault's `b"RBVAULT"` so the two files can never be
/// confused: each store rejects the other's file at the framing level,
/// before any key derivation happens.
/// File magic. DELIBERATELY UNCHANGED by the rename to PATANYX, for the same
/// reason as the vault's (see vault/src/format.rs): it is a format identifier
/// bound into authenticated data, not branding, and changing it would orphan
/// existing files to no user-visible benefit.
pub const MAGIC: &[u8; 7] = b"RBSTORE";

/// Whether `bytes` opens with the expected magic.
pub fn has_known_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 7 && &bytes[0..7] == MAGIC
}
pub const VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 7 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 60

#[derive(Debug, Clone)]
pub struct Header {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

// Sanity bounds for KDF parameters read from disk. The header is
// authenticated (it is the AEAD AAD), but authentication can only be checked
// *after* key derivation, so implausible parameters must be rejected before
// running Argon2 — otherwise a tampered header could force huge memory/time
// consumption.
const MIN_M_COST: u32 = 8;
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, in KiB
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 64;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 64;

pub fn encode_header(
    params: &KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..7].copy_from_slice(MAGIC);
    out[7] = VERSION;
    out[8..12].copy_from_slice(&params.m_cost.to_le_bytes());
    out[12..16].copy_from_slice(&params.t_cost.to_le_bytes());
    out[16..20].copy_from_slice(&params.p_cost.to_le_bytes());
    out[20..36].copy_from_slice(salt);
    out[36..60].copy_from_slice(nonce);
    out
}

pub fn decode_header(bytes: &[u8]) -> Result<Header, StoreError> {
    if bytes.len() < HEADER_LEN {
        return Err(StoreError::BadFormat(format!(
            "file too short: {} bytes, need at least {HEADER_LEN}",
            bytes.len()
        )));
    }
    if !has_known_magic(bytes) {
        return Err(StoreError::BadFormat("bad magic".into()));
    }
    let version = bytes[7];
    if version != VERSION {
        return Err(StoreError::BadFormat(format!(
            "unsupported version {version:#04x}"
        )));
    }
    let m_cost = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let t_cost = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let p_cost = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost)
        || !(MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        || !(MIN_P_COST..=MAX_P_COST).contains(&p_cost)
    {
        return Err(StoreError::BadFormat(format!(
            "implausible kdf parameters m={m_cost} t={t_cost} p={p_cost}"
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[20..36]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[36..60]);
    Ok(Header {
        params: KdfParams {
            m_cost,
            t_cost,
            p_cost,
        },
        salt,
        nonce,
    })
}
