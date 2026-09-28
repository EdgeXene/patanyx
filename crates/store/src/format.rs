use crate::crypto::{KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN};
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
    let params = decode_params(bytes)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[20..36]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[36..60]);
    Ok(Header {
        params,
        salt,
        nonce,
    })
}

/// Bytes 8..20 of either version: the three Argon2id costs, bounded here so
/// no caller can reach a key derivation with an implausible header. The caller
/// has already checked that at least 20 bytes exist.
fn decode_params(bytes: &[u8]) -> Result<KdfParams, StoreError> {
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
    Ok(KdfParams {
        m_cost,
        t_cost,
        p_cost,
    })
}

/// The version byte of a file that carries this store's magic, read before
/// anything else so the reader can pick a decoder. A file too short to hold
/// a version, or with foreign magic, is refused here, before any KDF.
pub fn version_of(bytes: &[u8]) -> Result<u8, StoreError> {
    if bytes.len() < 8 {
        return Err(StoreError::BadFormat(format!(
            "file too short: {} bytes",
            bytes.len()
        )));
    }
    if !has_known_magic(bytes) {
        return Err(StoreError::BadFormat("bad magic".into()));
    }
    Ok(bytes[7])
}

// ---- version 3: the Library opens with the vault -------------------------
//
// ONE PASSPHRASE: THE VAULT'S. The Vault and the Library share one
// passphrase, and a change made in the vault carries over to the Library with
// no second file to keep in step. So a version 3 Library has no passphrase
// material at all. Its data key (the same key a version 1 file derives from the
// passphrase, so no picture and no download record is ever rewritten) is stored
// wrapped under a key the vault derives from its own master
// (`Vault::library_key`). That master is random and never changes when the
// passphrase does, so a passphrase change touches only the vault, and the
// recovery key opens the Library too.
//
// A Library becomes version 3 when it is created (an import creates one too),
// or when an existing one moves into the vault: at a passphrase change attempt
// that gets past the vault's check of the current passphrase, or at the repair
// of a Library left under an earlier passphrase. Everyone else keeps a version 1
// file, which every build reads. Builds that predate version 3 refuse it at the
// version byte, before any key derivation. One of them that ALREADY holds the
// Library open, from before the move, can still save over it (final review,
// R-002): the Library lock that keeps one writer per Library is new in this
// build, and older builds do not take it. If that build saves last, the next
// unlock with the passphrase finds a version 1 Library under the passphrase that
// build opened it with and offers the repair, which moves it back into the
// vault; whatever the newer build saved in between is lost. The same goes for an
// import made while such a build holds the Library open: its next save puts the
// previous profile's Library back, and if the imported vault has the same
// passphrase nothing flags it (final review round 2, R-001). So older PATANYX
// windows must be closed before a passphrase change or an import, and the 1.0.3
// release notes must say so.
//
// ```text
// offset  size  field
// 0       7     magic = b"RBSTORE"
// 7       1     version = 0x03
// 8       24    wrap nonce (OS RNG, fixed when the key is wrapped)
// 32      48    the data key, wrapped under the vault's Library key (32 + tag)
// 80      24    content nonce (OS RNG, fresh on every save)
// 104     ..    ciphertext || 16-byte Poly1305 tag
// ```
//
// The wrapped key's AAD is bytes 0..32 (magic, version, wrap nonce). The
// content's AAD is the whole 104-byte header, so neither the wrapped key nor
// either nonce can be altered without the contents failing to open.

pub const VERSION_V3: u8 = 0x03;
/// 32-byte key plus the 16-byte AEAD tag.
pub const WRAPPED_LEN: usize = KEY_LEN + 16; // 48
/// What the wrapped key's AAD covers: magic, version and wrap nonce.
pub const WRAP_AAD_LEN: usize = 7 + 1 + NONCE_LEN; // 32
pub const HEADER_LEN_V3: usize = WRAP_AAD_LEN + WRAPPED_LEN + NONCE_LEN; // 104

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderV3 {
    pub wrap_nonce: [u8; NONCE_LEN],
    pub wrapped: [u8; WRAPPED_LEN],
    pub nonce: [u8; NONCE_LEN],
}

pub fn encode_header_v3(
    wrap_nonce: &[u8; NONCE_LEN],
    wrapped: &[u8; WRAPPED_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN_V3] {
    let mut out = [0u8; HEADER_LEN_V3];
    out[0..7].copy_from_slice(MAGIC);
    out[7] = VERSION_V3;
    out[8..WRAP_AAD_LEN].copy_from_slice(wrap_nonce);
    out[WRAP_AAD_LEN..WRAP_AAD_LEN + WRAPPED_LEN].copy_from_slice(wrapped);
    out[WRAP_AAD_LEN + WRAPPED_LEN..HEADER_LEN_V3].copy_from_slice(nonce);
    out
}

/// The AAD the wrapped key is bound to, for wrapping it before a whole header
/// exists. Byte-identical to bytes 0..32 of every version 3 header with this
/// wrap nonce.
pub fn wrap_aad_v3(wrap_nonce: &[u8; NONCE_LEN]) -> [u8; WRAP_AAD_LEN] {
    let mut out = [0u8; WRAP_AAD_LEN];
    out[0..7].copy_from_slice(MAGIC);
    out[7] = VERSION_V3;
    out[8..WRAP_AAD_LEN].copy_from_slice(wrap_nonce);
    out
}

pub fn decode_header_v3(bytes: &[u8]) -> Result<HeaderV3, StoreError> {
    if bytes.len() < HEADER_LEN_V3 {
        return Err(StoreError::BadFormat(format!(
            "file too short: {} bytes, need at least {HEADER_LEN_V3}",
            bytes.len()
        )));
    }
    if !has_known_magic(bytes) {
        return Err(StoreError::BadFormat("bad magic".into()));
    }
    let version = bytes[7];
    if version != VERSION_V3 {
        return Err(StoreError::BadFormat(format!(
            "unsupported version {version:#04x}"
        )));
    }
    let mut wrap_nonce = [0u8; NONCE_LEN];
    wrap_nonce.copy_from_slice(&bytes[8..WRAP_AAD_LEN]);
    let mut wrapped = [0u8; WRAPPED_LEN];
    wrapped.copy_from_slice(&bytes[WRAP_AAD_LEN..WRAP_AAD_LEN + WRAPPED_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[WRAP_AAD_LEN + WRAPPED_LEN..HEADER_LEN_V3]);
    Ok(HeaderV3 {
        wrap_nonce,
        wrapped,
        nonce,
    })
}
