//! On-disk format.
//!
//! # Version 2 (current)
//!
//! ```text
//! offset  size  field
//! 0       7     magic = b"RBVAULT"
//! 7       1     version = 0x02
//! 8       4     argon2 m_cost in KiB (u32 LE)   -- passphrase slots only
//! 12      4     argon2 t_cost (u32 LE)
//! 16      4     argon2 p_cost (u32 LE)
//! 20      1     slot count (1..=MAX_SLOTS)
//! 21      24    content nonce (OS RNG, fresh on every save)
//! 45      ..    slots, 89 bytes each
//! ..      ..    ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! Each slot:
//!
//! ```text
//! 0       1     kind: 1 = passphrase (Argon2id), 2 = recovery (HKDF)
//! 1       16    slot salt
//! 17      24    slot nonce
//! 41      48    the master key, wrapped (32 bytes + 16-byte tag)
//! ```
//!
//! # Why a master key at all
//!
//! Version 1 encrypted the contents directly under the passphrase-derived key.
//! That is simple and it permanently forecloses a second way in, because the
//! key IS a function of the passphrase. Version 2 encrypts the contents under a
//! random master key and stores that master key once per unlock method. Adding
//! a hardware token or a second device later becomes another slot rather than
//! another format.
//!
//! # What is authenticated, and why it is arranged this way
//!
//! The content AAD is the ENTIRE header including every slot, so adding,
//! removing, or reordering slots makes the contents fail to open. Without that,
//! an attacker who could append a slot wrapped under a key they chose would own
//! the vault.
//!
//! Each slot is wrapped with its own AAD: the fixed prefix plus that slot's own
//! kind, salt and nonce. This stops a slot being lifted out of one vault file
//! and pasted into another.

use crate::crypto::{KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::VaultError;

/// File magic. DELIBERATELY UNCHANGED by the rename to PATANYX.
///
/// This is a format identifier, not branding, and it CANNOT be rebranded
/// without destroying existing vaults. Each slot's AAD is built from the
/// header prefix, which includes these seven bytes, so the wrapped master key
/// is cryptographically bound to them:
///
///   * writing new magic while keeping the existing slots makes the next
///     unlock compute a different AAD than the slots were wrapped under, and
///     the vault stops opening — permanently, with no error that points at
///     the cause;
///   * re-wrapping the slots to match would need each slot's derived key,
///     which for a passphrase slot needs the passphrase. The vault never
///     retains it, by design.
///
/// So the only way to "rename" this constant is to make every user re-enter
/// their passphrase on upgrade, to gain nothing a user ever sees. The bytes
/// stay `RBVAULT`.
pub const MAGIC: &[u8; 7] = b"RBVAULT";

/// Whether `bytes` opens with the expected magic.
pub fn has_known_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 7 && &bytes[0..7] == MAGIC
}

pub const VERSION_V1: u8 = 0x01;
pub const VERSION: u8 = 0x02;

/// Fixed part of a v2 header, before the slot array.
pub const PREFIX_LEN: usize = 7 + 1 + 4 + 4 + 4 + 1 + NONCE_LEN; // 45
/// 32-byte key plus the 16-byte AEAD tag.
pub const WRAPPED_LEN: usize = KEY_LEN + 16; // 48
pub const SLOT_LEN: usize = 1 + SALT_LEN + NONCE_LEN + WRAPPED_LEN; // 89

/// Small on purpose. Slots are unlock methods, not a list, and a bounded count
/// means a corrupt length byte cannot make us allocate wildly.
pub const MAX_SLOTS: usize = 8;

pub const V1_HEADER_LEN: usize = 7 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 60

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Passphrase,
    Recovery,
}

impl SlotKind {
    fn to_byte(self) -> u8 {
        match self {
            SlotKind::Passphrase => 1,
            SlotKind::Recovery => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, VaultError> {
        match byte {
            1 => Ok(SlotKind::Passphrase),
            2 => Ok(SlotKind::Recovery),
            other => Err(VaultError::BadFormat(format!("unknown slot kind {other}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub kind: SlotKind,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub wrapped: [u8; WRAPPED_LEN],
}

impl Slot {
    fn write_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind.to_byte());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub params: KdfParams,
    pub nonce: [u8; NONCE_LEN],
    pub slots: Vec<Slot>,
}

impl Header {
    pub fn len(&self) -> usize {
        PREFIX_LEN + self.slots.len() * SLOT_LEN
    }
}

// Sanity bounds for KDF parameters read from disk. The header is
// authenticated, but authentication can only be checked AFTER key derivation,
// so implausible parameters must be rejected before Argon2 runs. Otherwise a
// tampered header is a denial-of-service: it could demand a terabyte of RAM.
const MIN_M_COST: u32 = 8;
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, in KiB
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 64;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 64;

pub fn encode_header(params: &KdfParams, nonce: &[u8; NONCE_LEN], slots: &[Slot]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX_LEN + slots.len() * SLOT_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&params.m_cost.to_le_bytes());
    out.extend_from_slice(&params.t_cost.to_le_bytes());
    out.extend_from_slice(&params.p_cost.to_le_bytes());
    out.push(slots.len() as u8);
    out.extend_from_slice(nonce);
    for slot in slots {
        slot.write_into(&mut out);
    }
    out
}

/// Bytes covered by a slot's AAD: magic, version, and the KDF parameters.
///
/// Deliberately stops before the slot count and the content nonce. Both change
/// during the vault's life, the count when a slot is added and the nonce on
/// every single save, and a slot wrapped against them would stop opening the
/// moment either moved. Slot integrity does not depend on them anyway: the
/// CONTENT aad covers the whole header including every slot, so adding,
/// removing or reordering slots already breaks the contents.
pub const SLOT_BOUND_PREFIX_LEN: usize = 7 + 1 + 4 + 4 + 4; // 20

/// AAD for wrapping and unwrapping one slot: the stable header prefix plus that
/// slot's own kind, salt and nonce. This stops a slot being lifted out of one
/// vault and pasted into another with different parameters, and stops its salt
/// or nonce being edited underneath it.
pub fn slot_aad(header_bytes: &[u8], slot: &Slot) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SLOT_BOUND_PREFIX_LEN + 1 + SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(&header_bytes[..SLOT_BOUND_PREFIX_LEN]);
    aad.push(slot.kind.to_byte());
    aad.extend_from_slice(&slot.salt);
    aad.extend_from_slice(&slot.nonce);
    aad
}

/// The stable prefix on its own, for wrapping a slot before a full header
/// exists.
pub fn slot_bound_prefix(params: &KdfParams) -> [u8; SLOT_BOUND_PREFIX_LEN] {
    let mut out = [0u8; SLOT_BOUND_PREFIX_LEN];
    out[0..7].copy_from_slice(MAGIC);
    out[7] = VERSION;
    out[8..12].copy_from_slice(&params.m_cost.to_le_bytes());
    out[12..16].copy_from_slice(&params.t_cost.to_le_bytes());
    out[16..20].copy_from_slice(&params.p_cost.to_le_bytes());
    out
}

/// True when the file is a version 1 vault, which unlocks through the
/// migration path rather than the slot path.
pub fn is_v1(bytes: &[u8]) -> bool {
    // Either magic: a v1 vault predates the rename, so in practice this is
    // always the legacy one, but accepting both keeps the two axes (format
    // version, file magic) independent.
    bytes.len() >= 8 && has_known_magic(bytes) && bytes[7] == VERSION_V1
}

#[derive(Debug, Clone)]
pub struct V1Header {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

/// Reads a version 1 header so an existing vault can be migrated on unlock.
pub fn decode_v1_header(bytes: &[u8]) -> Result<V1Header, VaultError> {
    if bytes.len() < V1_HEADER_LEN {
        return Err(VaultError::BadFormat(format!(
            "file too short: {} bytes, need at least {V1_HEADER_LEN}",
            bytes.len()
        )));
    }
    let params = decode_params(bytes)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[20..36]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[36..60]);
    Ok(V1Header {
        params,
        salt,
        nonce,
    })
}

fn decode_params(bytes: &[u8]) -> Result<KdfParams, VaultError> {
    let m_cost = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let t_cost = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let p_cost = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost)
        || !(MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        || !(MIN_P_COST..=MAX_P_COST).contains(&p_cost)
    {
        return Err(VaultError::BadFormat(format!(
            "implausible kdf parameters m={m_cost} t={t_cost} p={p_cost}"
        )));
    }
    Ok(KdfParams {
        m_cost,
        t_cost,
        p_cost,
    })
}

pub fn decode_header(bytes: &[u8]) -> Result<Header, VaultError> {
    if bytes.len() < PREFIX_LEN {
        return Err(VaultError::BadFormat(format!(
            "file too short: {} bytes, need at least {PREFIX_LEN}",
            bytes.len()
        )));
    }
    if !has_known_magic(bytes) {
        return Err(VaultError::BadFormat("bad magic".into()));
    }
    let version = bytes[7];
    if version != VERSION {
        return Err(VaultError::BadFormat(format!(
            "unsupported version {version:#04x}"
        )));
    }
    let params = decode_params(bytes)?;

    let slot_count = bytes[20] as usize;
    if slot_count == 0 || slot_count > MAX_SLOTS {
        return Err(VaultError::BadFormat(format!(
            "implausible slot count {slot_count}"
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[21..PREFIX_LEN]);

    let header_len = PREFIX_LEN + slot_count * SLOT_LEN;
    if bytes.len() < header_len {
        return Err(VaultError::BadFormat(format!(
            "file too short for {slot_count} slots: {} bytes, need {header_len}",
            bytes.len()
        )));
    }

    let mut slots = Vec::with_capacity(slot_count);
    for index in 0..slot_count {
        let base = PREFIX_LEN + index * SLOT_LEN;
        let kind = SlotKind::from_byte(bytes[base])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[base + 1..base + 1 + SALT_LEN]);
        let mut slot_nonce = [0u8; NONCE_LEN];
        slot_nonce.copy_from_slice(&bytes[base + 17..base + 17 + NONCE_LEN]);
        let mut wrapped = [0u8; WRAPPED_LEN];
        wrapped.copy_from_slice(&bytes[base + 41..base + 41 + WRAPPED_LEN]);
        slots.push(Slot {
            kind,
            salt,
            nonce: slot_nonce,
            wrapped,
        });
    }

    Ok(Header {
        params,
        nonce,
        slots,
    })
}
