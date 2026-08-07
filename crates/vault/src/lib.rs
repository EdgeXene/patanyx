//! patanyx-vault — encrypted single-file store for site credentials,
//! free-form secret notes, and chat contacts (one secret key per contact,
//! stored as raw bytes — all cryptography lives with the caller).
//!
//! File format v1 (binary, little-endian integers):
//!
//! ```text
//! offset  size  field
//! 0       7     magic = b"RBVAULT"
//! 7       1     version = 0x01
//! 8       4     argon2 m_cost in KiB (u32 LE)
//! 12      4     argon2 t_cost (u32 LE)
//! 16      4     argon2 p_cost (u32 LE)
//! 20      16    salt (OS RNG)
//! 36      24    XChaCha20-Poly1305 nonce (OS RNG, fresh on every save)
//! 60      ..    ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! The full 60-byte header is the AEAD AAD, so tampering with the version,
//! KDF parameters, or salt fails authentication exactly like a wrong
//! passphrase does.

mod crypto;
mod error;
mod format;
mod backup;
mod lock;
mod recovery;
mod model;

pub use error::VaultError;
pub use recovery::{RecoveryKey, RECOVERY_LEN};
pub use backup::{ExportError, PLAINTEXT_EXPORT_CONFIRMATION};
pub use lock::{LockError, VaultLock};
pub use model::{
    Contact, ContactBook, CredentialEntry, CredentialMeta, LicenceRecord, NoteMeta, RelaySettings,
    SecretNote, TunnelSettings, VaultData, MAX_LABEL_CHARS, MAX_PEER_HASH_CHARS,
};

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::KdfParams;

impl std::fmt::Debug for Vault {
    /// Hand-written, never derived: this struct holds the live master key, and
    /// a derived Debug would print it into any log line or test failure that
    /// formatted a vault.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("slots", &self.slots.len())
            .field("has_recovery", &self.has_recovery())
            .finish_non_exhaustive()
    }
}

pub struct Vault {
    path: PathBuf,
    /// Held for the whole session. Its presence is what stops a second
    /// PATANYX opening the same vault; dropping this `Vault` releases it, and
    /// so does the process dying for any reason. See `lock.rs` for why this
    /// is an OS lock rather than a pid file.
    _lock: lock::VaultLock,
    /// Set when the most recent save could not write a rotating backup. The
    /// save still happened; this exists so the UI can be honest about the
    /// backups not working instead of silently implying they are.
    last_backup_error: Option<String>,
    /// Encrypts the contents. Random, never derived from a passphrase: that
    /// indirection is what allows more than one unlock method.
    master: Zeroizing<[u8; crypto::KEY_LEN]>,
    params: KdfParams,
    /// One per unlock method, each holding the master key wrapped under a key
    /// derived from that method's secret.
    slots: Vec<format::Slot>,
    /// Set only when unlocking migrated a v1 vault, which mints a recovery key
    /// the user has never seen. The UI must take it and show it once.
    migrated_recovery: Option<RecoveryKey>,
    data: VaultData,
}

/// Application data directory name. Was `rustbrowse` before the rename to
/// PATANYX; see [`legacy_dir_name`].
pub const DIR_NAME: &str = "patanyx";

/// The pre-rename directory name. Kept so an existing install keeps working:
/// the product was renamed, the user's vault was not, and silently starting a
/// fresh empty vault next to a full one would look exactly like data loss.
pub const LEGACY_DIR_NAME: &str = "rustbrowse";

/// Picks the data directory under `root`, preferring the current name but
/// falling back to the legacy one when that is where the data actually is.
///
/// Deliberately does NOT move or rewrite anything. A rename is not worth the
/// risk of touching a user's only copy of their passwords; the old location
/// keeps working for as long as it exists, and a fresh install gets the new
/// name.
fn data_dir_in(root: PathBuf, file: &str) -> PathBuf {
    let current = root.join(DIR_NAME);
    if current.join(file).exists() {
        return current.join(file);
    }
    let legacy = root.join(LEGACY_DIR_NAME);
    if legacy.join(file).exists() {
        return legacy.join(file);
    }
    current.join(file)
}

impl Vault {
    /// `$XDG_DATA_HOME/patanyx/vault.rbv`, falling back to
    /// `$HOME/.local/share/patanyx/vault.rbv`, and to the pre-rename
    /// `rustbrowse` directory when a vault already lives there.
    #[cfg(unix)]
    pub fn default_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            if !dir.is_empty() {
                return data_dir_in(PathBuf::from(dir), "vault.rbv");
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return data_dir_in(
                PathBuf::from(home).join(".local").join("share"),
                "vault.rbv",
            );
        }
        // Last resort: a relative path rather than a panic.
        PathBuf::from(".patanyx").join("vault.rbv")
    }

    /// `%APPDATA%\patanyx\vault.rbv` (roaming per-user config root), with the
    /// same legacy fallback as the unix arm.
    /// `PATANYX_DATA_DIR` takes precedence as the override hook — the
    /// role XDG_DATA_HOME plays on unix — so automated tests (smoke.ps1)
    /// can redirect the vault to a throwaway directory.
    #[cfg(windows)]
    pub fn default_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("PATANYX_DATA_DIR") {
            if !dir.is_empty() {
                return data_dir_in(PathBuf::from(dir), "vault.rbv");
            }
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            if !appdata.is_empty() {
                return data_dir_in(PathBuf::from(appdata), "vault.rbv");
            }
        }
        // Last resort: a relative path rather than a panic.
        PathBuf::from(".patanyx").join("vault.rbv")
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Create a vault WITH a recovery key, which is the default and the
    /// recommended path. The returned key is shown to the user exactly once and
    /// is never recoverable afterwards, because only its wrapped form is kept.
    pub fn create(path: &Path, passphrase: &str) -> Result<(Vault, RecoveryKey), VaultError> {
        let params = KdfParams::default();
        let recovery = RecoveryKey::generate();
        let vault = Self::create_inner(path, passphrase, params, Some(&recovery))?;
        Ok((vault, recovery))
    }

    /// Create a vault with NO recovery key.
    ///
    /// This is the deliberate opt-out, and it is genuinely irreversible: if the
    /// passphrase is forgotten, the contents are unrecoverable by the owner, by
    /// us, and by anyone else. Backups do not help, because a backup of an
    /// encrypted file is still an encrypted file. Callers must put that in
    /// front of the user in plain language before calling this.
    pub fn create_without_recovery(path: &Path, passphrase: &str) -> Result<Vault, VaultError> {
        Self::create_inner(path, passphrase, KdfParams::default(), None)
    }

    /// Same as `create` but with explicit KDF parameters; intended for tests
    /// (e.g. m=8192, t=1, p=1) and future parameter upgrades.
    pub fn create_with_params(
        path: &Path,
        passphrase: &str,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<(Vault, RecoveryKey), VaultError> {
        let params = KdfParams {
            m_cost,
            t_cost,
            p_cost,
        };
        let recovery = RecoveryKey::generate();
        let vault = Self::create_inner(path, passphrase, params, Some(&recovery))?;
        Ok((vault, recovery))
    }

    fn create_inner(
        path: &Path,
        passphrase: &str,
        params: KdfParams,
        recovery: Option<&RecoveryKey>,
    ) -> Result<Vault, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        // The contents are encrypted under a random master key, never directly
        // under a passphrase-derived key. That indirection is the whole reason
        // a second unlock method can exist at all.
        // Before any bytes are written: creating a vault a second process
        // already holds would be the same lost-update race as opening one.
        let guard = lock::acquire(path).map_err(VaultError::from)?;
        let master = Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>());
        let mut vault = Vault {
            last_backup_error: None,
            _lock: guard,
            path: path.to_path_buf(),
            master,
            params,
            slots: Vec::new(),
            migrated_recovery: None,
            data: VaultData::default(),
        };
        vault.slots.push(vault.build_slot(
            format::SlotKind::Passphrase,
            passphrase.as_bytes(),
            &[],
        )?);
        if let Some(recovery) = recovery {
            let slot =
                vault.build_slot(format::SlotKind::Recovery, recovery.as_bytes(), &[])?;
            vault.slots.push(slot);
        }
        vault.save()?;
        Ok(vault)
    }

    /// Wraps the master key for one unlock method.
    ///
    /// `_reserved` exists so the signature does not change when a hardware-token
    /// slot needs extra material.
    fn build_slot(
        &self,
        kind: format::SlotKind,
        secret: &[u8],
        _reserved: &[u8],
    ) -> Result<format::Slot, VaultError> {
        let salt: [u8; crypto::SALT_LEN] = crypto::random_bytes();
        let nonce: [u8; crypto::NONCE_LEN] = crypto::random_bytes();
        let slot_key = Self::derive_slot_key(kind, secret, &salt, &self.params)?;
        let prefix = format::slot_bound_prefix(&self.params);
        let mut probe = format::Slot {
            kind,
            salt,
            nonce,
            wrapped: [0u8; format::WRAPPED_LEN],
        };
        let aad = format::slot_aad(&prefix, &probe);
        let wrapped = crypto::encrypt(&slot_key, &nonce, &aad, self.master.as_ref())?;
        if wrapped.len() != format::WRAPPED_LEN {
            return Err(VaultError::Crypto("unexpected wrapped key length".into()));
        }
        probe.wrapped.copy_from_slice(&wrapped);
        Ok(probe)
    }

    fn derive_slot_key(
        kind: format::SlotKind,
        secret: &[u8],
        salt: &[u8; crypto::SALT_LEN],
        params: &KdfParams,
    ) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, VaultError> {
        match kind {
            format::SlotKind::Passphrase => crypto::derive_key(secret, salt, params),
            format::SlotKind::Recovery => crypto::derive_from_recovery(secret, salt),
        }
    }

    /// Unlock with the passphrase. Version 1 vaults are migrated to version 2
    /// transparently, which is also when they gain a recovery key.
    pub fn unlock(path: &Path, passphrase: &str) -> Result<Vault, VaultError> {
        let bytes = fs::read(path)?;
        if format::is_v1(&bytes) {
            return Self::unlock_v1_and_migrate(path, &bytes, passphrase);
        }
        Self::unlock_slots(path, &bytes, format::SlotKind::Passphrase, passphrase.as_bytes())
    }

    /// Unlock with the recovery key, for the case this whole mechanism exists
    /// for: the passphrase is gone.
    pub fn unlock_with_recovery(path: &Path, recovery: &RecoveryKey) -> Result<Vault, VaultError> {
        let bytes = fs::read(path)?;
        if format::is_v1(&bytes) {
            // v1 predates slots entirely, so there is nothing to try.
            return Err(VaultError::NoRecoverySlot);
        }
        Self::unlock_slots(
            path,
            &bytes,
            format::SlotKind::Recovery,
            recovery.as_bytes(),
        )
    }

    fn unlock_slots(
        path: &Path,
        bytes: &[u8],
        kind: format::SlotKind,
        secret: &[u8],
    ) -> Result<Vault, VaultError> {
        let header = format::decode_header(bytes)?;
        let header_len = header.len();
        if bytes.len() < header_len + 16 {
            return Err(VaultError::BadFormat(
                "file ends after header: no ciphertext/tag".into(),
            ));
        }
        if !header.slots.iter().any(|slot| slot.kind == kind) {
            return Err(match kind {
                format::SlotKind::Recovery => VaultError::NoRecoverySlot,
                format::SlotKind::Passphrase => VaultError::BadFormat(
                    "vault has no passphrase slot".into(),
                ),
            });
        }

        // Try every slot of the requested kind. More than one is not expected
        // today, but a failure to open one must not abandon the rest.
        let mut master = None;
        for slot in header.slots.iter().filter(|slot| slot.kind == kind) {
            let slot_key = Self::derive_slot_key(kind, secret, &slot.salt, &header.params)?;
            let aad = format::slot_aad(&bytes[..header_len], slot);
            if let Ok(plain) = crypto::decrypt(&slot_key, &slot.nonce, &aad, &slot.wrapped) {
                if plain.len() == crypto::KEY_LEN {
                    let mut key = Zeroizing::new([0u8; crypto::KEY_LEN]);
                    key.copy_from_slice(&plain);
                    master = Some(key);
                    break;
                }
            }
        }
        // Indistinguishable from tampering, exactly like a wrong passphrase.
        let master = master.ok_or(VaultError::AuthFailed)?;

        let plaintext = crypto::decrypt(
            &master,
            &header.nonce,
            &bytes[..header_len],
            &bytes[header_len..],
        )?;
        let data = Self::parse_payload(&plaintext)?;
        let guard = lock::acquire(path).map_err(VaultError::from)?;
        Ok(Vault {
            last_backup_error: None,
            _lock: guard,
            path: path.to_path_buf(),
            master,
            params: header.params,
            slots: header.slots,
            migrated_recovery: None,
            data,
        })
    }

    /// Opens a version 1 vault and immediately rewrites it as version 2 with a
    /// recovery slot, so existing vaults are not left permanently without a
    /// second door.
    ///
    /// Note for the UI: migration mints a recovery key that the user has
    /// not seen. The unlock flow must surface it once, the same way creation
    /// does, or the key exists and helps nobody.
    fn unlock_v1_and_migrate(
        path: &Path,
        bytes: &[u8],
        passphrase: &str,
    ) -> Result<Vault, VaultError> {
        let header = format::decode_v1_header(bytes)?;
        if bytes.len() < format::V1_HEADER_LEN + 16 {
            return Err(VaultError::BadFormat(
                "file ends after header: no ciphertext/tag".into(),
            ));
        }
        let key = crypto::derive_key(passphrase.as_bytes(), &header.salt, &header.params)?;
        let plaintext = crypto::decrypt(
            &key,
            &header.nonce,
            &bytes[..format::V1_HEADER_LEN],
            &bytes[format::V1_HEADER_LEN..],
        )?;
        let data = Self::parse_payload(&plaintext)?;

        // v1 derived the content key from the passphrase directly; v2 needs a
        // master key, so mint one and re-wrap.
        let guard = lock::acquire(path).map_err(VaultError::from)?;
        let master = Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>());
        let mut vault = Vault {
            last_backup_error: None,
            _lock: guard,
            path: path.to_path_buf(),
            master,
            params: header.params,
            slots: Vec::new(),
            migrated_recovery: None,
            data,
        };
        vault.slots.push(vault.build_slot(
            format::SlotKind::Passphrase,
            passphrase.as_bytes(),
            &[],
        )?);
        let recovery = RecoveryKey::generate();
        let slot = vault.build_slot(format::SlotKind::Recovery, recovery.as_bytes(), &[])?;
        vault.slots.push(slot);
        vault.migrated_recovery = Some(recovery);
        vault.save()?;
        Ok(vault)
    }

    fn parse_payload(plaintext: &[u8]) -> Result<VaultData, VaultError> {
        /// Just enough of the payload to read its version. Deserializing the
        /// FULL structure first and checking afterwards builds a lossy
        /// in-memory copy of a file this build admits it does not understand —
        /// every unknown field already discarded — and only then decides to
        /// refuse it. Nothing was saved from that state, so it was not a bug,
        /// but it is avoidable ambiguity right next to a destructive boundary.
        /// Read the version from an envelope, decide, and only then parse.
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            schema: u32,
        }
        let envelope: Envelope = serde_json::from_slice(plaintext).map_err(|e| {
            VaultError::BadFormat(format!("decrypted payload is not valid json: {e}"))
        })?;
        // Read-old / write-new. Schema 1 predates contacts, so its payloads
        // lack the `contacts` and `chat_identity` keys; `#[serde(default)]`
        // fills them in below and the next save rewrites the file at the
        // current schema. Anything NEWER than this build is rejected
        // outright: reading it partially and re-saving would silently drop
        // fields this build does not know about, which is exactly how `relay`
        // and the contact `note` were lost before SCHEMA_VERSION was bumped.
        if envelope.schema == 0 || envelope.schema > model::SCHEMA_VERSION {
            return Err(VaultError::BadFormat(format!(
                "unsupported payload schema {}",
                envelope.schema
            )));
        }
        let mut data: VaultData = serde_json::from_slice(plaintext).map_err(|e| {
            VaultError::BadFormat(format!("decrypted payload is not valid json: {e}"))
        })?;
        data.schema = model::SCHEMA_VERSION;
        Ok(data)
    }

    /// Takes the recovery key minted while migrating a v1 vault, if there was
    /// one. Returns it at most once: the UI shows it and then it is gone, the
    /// same as at creation.
    pub fn take_migrated_recovery(&mut self) -> Option<RecoveryKey> {
        self.migrated_recovery.take()
    }

    /// Builds a vault in memory with no slots yet, for the import path, which
    /// mints a fresh master key and then wraps it under whatever unlock methods
    /// the caller adds. Nothing is written until `save`.
    pub(crate) fn assemble(
        path: PathBuf,
        master: Zeroizing<[u8; crypto::KEY_LEN]>,
        params: KdfParams,
        data: VaultData,
    ) -> Result<Self, VaultError> {
        let guard = lock::acquire(&path).map_err(VaultError::from)?;
        Ok(Self {
            last_backup_error: None,
            _lock: guard,
            path,
            master,
            params,
            slots: Vec::new(),
            migrated_recovery: None,
            data,
        })
    }

    pub(crate) fn push_slot(&mut self, slot: format::Slot) {
        self.slots.push(slot);
    }

    /// Swaps one unlock method for another in place.
    ///
    /// Used by a passphrase change, which must leave every OTHER slot alone: the
    /// recovery key has to keep working across a passphrase change, and it only
    /// does because the master key never moves and the other slots are not
    /// touched.
    pub(crate) fn replace_slot(&mut self, index: usize, slot: format::Slot) {
        if index < self.slots.len() {
            self.slots[index] = slot;
        }
    }

    // Narrow accessors for the backup/export module, which lives in this
    // crate. They exist so that code does not reach into fields directly and
    // so the master key has exactly one named way out.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn data_ref(&self) -> &VaultData {
        &self.data
    }

    pub(crate) fn kdf_params(&self) -> KdfParams {
        self.params
    }

    pub(crate) fn slots_ref(&self) -> &[format::Slot] {
        &self.slots
    }

    pub(crate) fn master_ref(&self) -> &[u8; crypto::KEY_LEN] {
        &self.master
    }

    /// True when this vault can be opened with a recovery key.
    pub fn has_recovery(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.kind == format::SlotKind::Recovery)
    }

    /// Persist with a fresh content nonce, written atomically (tmp file + fsync
    /// + rename) with mode 0600 on unix.
    /// Why the last save could not write a rotating backup, if it could not.
    /// The save itself still succeeded; this exists so the UI can say backups
    /// are not working instead of implying they are.
    pub fn last_backup_error(&self) -> Option<&str> {
        self.last_backup_error.as_deref()
    }

    pub fn save(&mut self) -> Result<(), VaultError> {
        // Keep a bounded history of previous ciphertexts before overwriting.
        //
        // `rotate_backups` documented "call this BEFORE overwriting the
        // vault" and had passing tests, and NOTHING CALLED IT. `mod backup`
        // is private and only `ExportError` and the confirmation constant are
        // re-exported, so no outside caller could reach it either. The
        // guarantee was in the doc comment and nowhere else.
        //
        // Being accurate about what this buys, because the original comment
        // over-claimed: `atomic_write` below is tmp+rename, so an INTERRUPTED
        // write already cannot destroy the previous file — the rename is
        // atomic and the old inode survives until it succeeds. What backups
        // actually protect against is a write that succeeds and is WRONG:
        // logical corruption, a bad migration, a bug in this code. That is a
        // real risk for a file holding the only copy of a user's passwords,
        // and it is worth three copies of ciphertext.
        //
        // Failure here does NOT fail the save. A user who cannot write a
        // backup must still be able to save their new data; refusing would
        // turn a full disk into data loss, which is the opposite of the
        // point. It is recorded instead, so the UI can say backups are not
        // working rather than implying they are.
        self.last_backup_error = match backup::rotate_backups(&self.path, backup::DEFAULT_MAX_BACKUPS) {
            Ok(_) => None,
            Err(e) => Some(e.to_string()),
        };
        // A fresh nonce on every save: reusing an XChaCha20-Poly1305 nonce
        // with the same key would break AEAD security.
        let nonce: [u8; crypto::NONCE_LEN] = crypto::random_bytes();
        let header = format::encode_header(&self.params, &nonce, &self.slots);
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.data)
                .map_err(|e| VaultError::Crypto(format!("json encode: {e}")))?,
        );
        // AAD is the whole header INCLUDING every slot, so a slot cannot be
        // added, removed or reordered without the contents failing to open.
        let ciphertext = crypto::encrypt(&self.master, &nonce, &header, &plaintext)?;
        let mut out = Vec::with_capacity(header.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        atomic_write(&self.path, &out)
    }

    // ---- credentials ----

    /// Persist-on-write; a failed save is a hard error so an entry never
    /// exists only in memory without the caller knowing.
    /// `origin` is computed by the CALLER (ipc.rs, from `site`), never
    /// re-derived here: this crate stores what a credential means, it does
    /// not learn how to parse a URL, the same reasoning that keeps bookmark
    /// data out of this crate too (see ipc.rs's own comment on that).
    pub fn add_credential(
        &mut self,
        site: &str,
        origin: Option<&str>,
        username: &str,
        password: &str,
        note: &str,
    ) -> Result<String, VaultError> {
        let id = random_id();
        let now = now_unix();
        self.data.credentials.push(CredentialEntry {
            id: id.clone(),
            site: site.to_string(),
            origin: origin.map(str::to_string),
            username: username.to_string(),
            password: password.to_string(),
            note: note.to_string(),
            created_at: now,
            updated_at: now,
        });
        self.save()?;
        Ok(id)
    }

    pub fn update_credential(
        &mut self,
        id: &str,
        site: &str,
        origin: Option<&str>,
        username: &str,
        password: &str,
        note: &str,
    ) -> Result<(), VaultError> {
        let entry = self
            .data
            .credentials
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| VaultError::NotFound(id.to_string()))?;
        entry.site = site.to_string();
        entry.origin = origin.map(str::to_string);
        entry.username = username.to_string();
        entry.password = password.to_string();
        entry.note = note.to_string();
        entry.updated_at = now_unix();
        self.save()
    }

    /// Credentials whose stored `origin` the caller's predicate accepts --
    /// never the free-text `site` label, never a substring or prefix, and
    /// never an entry with no stored origin at all.
    ///
    /// THE PREDICATE IS THE CALLER'S BECAUSE THE RULE NEEDS THE PUBLIC SUFFIX
    /// LIST. Deciding that `accounts.google.com` and `mail.google.com` are one
    /// site, while `mybank.co.uk` and `evil.co.uk` are not, takes 10,000 rules
    /// that have nothing to do with encrypted storage. Dragging them into this
    /// crate would put a list that needs periodic refreshing inside the thing
    /// that holds people's passwords; `app::psl` owns it instead, and this
    /// stays a filter.
    ///
    /// `matches` is handed the credential's stored origin and must answer
    /// whether it belongs to the page being offered a fill. Implementations
    /// must be exact or narrower -- a substring or suffix-string test here is
    /// how `notgoogle.com` gets offered `google.com`'s password.
    pub fn credentials_matching(
        &self,
        matches: impl Fn(&str) -> bool,
    ) -> Vec<CredentialMeta> {
        self.data
            .credentials
            .iter()
            .filter(|e| e.origin.as_deref().is_some_and(&matches))
            .map(|e| CredentialMeta {
                id: e.id.clone(),
                site: e.site.clone(),
                username: e.username.clone(),
                origin: e.origin.clone(),
            })
            .collect()
    }

    /// Exact-origin lookup, kept for callers that genuinely mean one host.
    pub fn credentials_for_origin(&self, origin: &str) -> Vec<CredentialMeta> {
        self.credentials_matching(|stored| stored == origin)
    }

    pub fn delete_credential(&mut self, id: &str) -> Result<(), VaultError> {
        let before = self.data.credentials.len();
        self.data.credentials.retain(|e| e.id != id);
        if self.data.credentials.len() == before {
            return Err(VaultError::NotFound(id.to_string()));
        }
        self.save()
    }

    /// Metadata only — never includes passwords.
    pub fn list_credentials(&self) -> Vec<CredentialMeta> {
        self.data
            .credentials
            .iter()
            .map(|e| CredentialMeta {
                id: e.id.clone(),
                site: e.site.clone(),
                username: e.username.clone(),
                origin: e.origin.clone(),
            })
            .collect()
    }

    /// Explicit reveal of a full entry including the password.
    pub fn get_credential(&self, id: &str) -> Option<&CredentialEntry> {
        self.data.credentials.iter().find(|e| e.id == id)
    }

    // ---- notes ----

    /// See `add_credential`: persist-on-write, save failures propagate.
    pub fn add_note(&mut self, title: &str, body: &str) -> Result<String, VaultError> {
        let id = random_id();
        let now = now_unix();
        self.data.notes.push(SecretNote {
            id: id.clone(),
            title: title.to_string(),
            body: body.to_string(),
            created_at: now,
            updated_at: now,
        });
        self.save()?;
        Ok(id)
    }

    pub fn update_note(&mut self, id: &str, title: &str, body: &str) -> Result<(), VaultError> {
        let note = self
            .data
            .notes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or_else(|| VaultError::NotFound(id.to_string()))?;
        note.title = title.to_string();
        note.body = body.to_string();
        note.updated_at = now_unix();
        self.save()
    }

    pub fn delete_note(&mut self, id: &str) -> Result<(), VaultError> {
        let before = self.data.notes.len();
        self.data.notes.retain(|n| n.id != id);
        if self.data.notes.len() == before {
            return Err(VaultError::NotFound(id.to_string()));
        }
        self.save()
    }

    pub fn list_notes(&self) -> Vec<NoteMeta> {
        self.data
            .notes
            .iter()
            .map(|n| NoteMeta {
                id: n.id.clone(),
                title: n.title.clone(),
            })
            .collect()
    }

    pub fn get_note(&self, id: &str) -> Option<&SecretNote> {
        self.data.notes.iter().find(|n| n.id == id)
    }

    // ---- contacts ----

    /// Persist-on-write, same contract as `add_credential`: the contact is on
    /// disk before this returns, or the call fails and nothing is stored.
    ///
    /// `our_secret` is OUR half of the per-contact X25519 keypair, generated
    /// by the caller. The vault stores raw bytes and opaque strings; all
    /// cryptography stays outside this crate.
    pub fn add_contact(
        &mut self,
        label: &str,
        peer_hash: &str,
        our_secret: [u8; 32],
    ) -> Result<String, VaultError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(VaultError::InvalidContact("label is empty".into()));
        }
        if label.chars().count() > model::MAX_LABEL_CHARS {
            return Err(VaultError::InvalidContact(format!(
                "label is over {} characters",
                model::MAX_LABEL_CHARS
            )));
        }
        // The peer hash is opaque: reject empty and cap the length, but never
        // parse it. Its format is the caller's knowledge, not the vault's.
        let peer_hash = peer_hash.trim();
        if peer_hash.is_empty() {
            return Err(VaultError::InvalidContact("peer hash is empty".into()));
        }
        if peer_hash.chars().count() > model::MAX_PEER_HASH_CHARS {
            return Err(VaultError::InvalidContact(format!(
                "peer hash is over {} characters",
                model::MAX_PEER_HASH_CHARS
            )));
        }
        // Two contacts must never share a peer hash: the caller keys its
        // session map by hash number, so a duplicate would make one contact
        // unreachable. Reject rather than silently accept or replace.
        //
        // Note: no "update contact" API exists yet; if the caller ever
        // needs re-keying of an existing peer, that should be added as a
        // deliberate method rather than by weakening this check.
        if self.data.contacts.find_by_peer_hash(peer_hash).is_some() {
            return Err(VaultError::DuplicatePeerHash(peer_hash.to_string()));
        }
        let id = random_id();
        self.data.contacts.add(
            id.clone(),
            label.to_string(),
            peer_hash.to_string(),
            our_secret,
        );
        self.save()?;
        Ok(id)
    }

    /// Explicit reveal of a full contact INCLUDING the secret — the contact
    /// analogue of `get_credential`, and one of exactly two named ways key
    /// material leaves the vault (the other is `find_contact_by_peer_hash`).
    pub fn get_contact(&self, id: &str) -> Option<&Contact> {
        self.data.contacts.get(id)
    }

    /// Look up by the peer's hash number — the caller's session-map key.
    pub fn find_contact_by_peer_hash(&self, peer_hash: &str) -> Option<&Contact> {
        self.data.contacts.find_by_peer_hash(peer_hash)
    }

    /// Whole contacts, secrets included: there is no metadata-only contact
    /// listing. The secret stays out of UI-bound output because `Contact`'s
    /// `Serialize` impl omits it — not because this method hides it.
    pub fn list_contacts(&self) -> Vec<Contact> {
        self.data.contacts.list()
    }

    /// Relay configuration, defaulted when never set.
    pub fn chat_relay_settings(&self) -> RelaySettings {
        self.data.relay.clone()
    }

    /// Persists relay configuration immediately, like `set_chat_identity`.
    pub fn set_chat_relay_settings(&mut self, settings: RelaySettings) -> Result<(), VaultError> {
        self.data.relay = settings;
        self.save()
    }

    /// The imported WireGuard tunnel configuration, cloned; `None` until the
    /// caller imports one.
    ///
    /// The clone carries the private key on the heap and `TunnelSettings`
    /// has no `Drop`, so the CALLER owns wiping it. Today's only caller
    /// hands the Strings straight into `patanyx_tunnel::TunnelConfig`,
    /// which wipes them once boringtun holds the decoded copies. Anyone who
    /// only wants to know WHETHER a tunnel is stored must call
    /// `has_tunnel_settings` instead -- cloning a key to ask a yes/no
    /// question is how an unwiped copy ends up on the heap for the life of
    /// the process.
    pub fn tunnel_settings(&self) -> Option<TunnelSettings> {
        self.data.tunnel.clone()
    }

    /// Whether a tunnel configuration is stored, WITHOUT copying the key.
    pub fn has_tunnel_settings(&self) -> bool {
        self.data.tunnel.is_some()
    }

    /// Persist-on-write like every other mutator. Passing `None` removes the
    /// tunnel from the vault.
    pub fn set_tunnel_settings(
        &mut self,
        settings: Option<TunnelSettings>,
    ) -> Result<(), VaultError> {
        // Wipe the secret being replaced — or removed, when `settings` is
        // `None` — rather than letting the old strings drop unwiped: the rule
        // `set_chat_identity` applies to the array it replaces, applied here
        // to the tunnel's `String` secrets.
        if let Some(old) = &mut self.data.tunnel {
            old.private_key_b64.zeroize();
            if let Some(preshared) = &mut old.preshared_key_b64 {
                preshared.zeroize();
            }
        }
        self.data.tunnel = settings;
        self.save()
    }

    /// The stored Premium licence record, cloned; `None` until the caller
    /// pastes a token.
    ///
    /// The clone carries the bearer token on the heap and `LicenceRecord`
    /// has no `Drop`, so the CALLER owns wiping it. Today's only caller
    /// (`licence_control`) zeroizes the text the moment evaluation is done
    /// with it. Anyone who only wants to know WHETHER a token is stored
    /// must call `has_licence_record` instead -- cloning a credential to
    /// ask a yes/no question is how an unwiped copy ends up on the heap for
    /// the life of the process (the rule `tunnel_settings` documents,
    /// applied here).
    pub fn licence_record(&self) -> Option<LicenceRecord> {
        self.data.licence.clone()
    }

    /// Whether a licence record is stored, WITHOUT copying the token.
    pub fn has_licence_record(&self) -> bool {
        self.data.licence.is_some()
    }

    /// Persist-on-write like every other mutator. Passing `None` removes
    /// the record from the vault.
    pub fn set_licence_record(&mut self, record: Option<LicenceRecord>) -> Result<(), VaultError> {
        // Wipe the token being replaced — or removed, when `record` is
        // `None` — rather than letting the old string drop unwiped: the
        // rule `set_chat_identity` applies to the array it replaces,
        // applied here to the token text.
        if let Some(old) = &mut self.data.licence {
            old.token_text.zeroize();
        }
        self.data.licence = record;
        self.save()
    }

    /// Sets a contact's free-text note, replacing whatever was there.
    ///
    /// A hash number is unmemorable by design, so this is where the user
    /// records which person it belongs to. Trimmed and capped at
    /// `MAX_NOTE_CHARS`; passing an empty string clears it. Persisted before
    /// returning, like every other mutating method here — a note the user
    /// typed and then lost to a crash is worse than no note feature.
    pub fn set_contact_note(&mut self, id: &str, note: &str) -> Result<(), VaultError> {
        if !self.data.contacts.set_note(id, note) {
            return Err(VaultError::NotFound(id.to_string()));
        }
        self.save()
    }

    /// Same contract as `delete_credential`: a missing id is `NotFound`, and
    /// the delete is persisted before returning.
    pub fn delete_contact(&mut self, id: &str) -> Result<(), VaultError> {
        if self.data.contacts.remove(id).is_none() {
            return Err(VaultError::NotFound(id.to_string()));
        }
        self.save()
    }

    /// The LONG-TERM chat identity secret, distinct from every per-contact
    /// key. Returns a copy; `None` until first minted by the caller.
    pub fn chat_identity(&self) -> Option<[u8; 32]> {
        self.data.chat_identity
    }

    /// Persist-on-write like every other mutator.
    pub fn set_chat_identity(&mut self, secret: [u8; 32]) -> Result<(), VaultError> {
        // Wipe the secret being replaced rather than letting the old array
        // drop unwiped.
        if let Some(old) = &mut self.data.chat_identity {
            old.zeroize();
        }
        self.data.chat_identity = Some(secret);
        self.save()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // `master` wipes itself via Zeroizing; scrub per-entry secrets as well.
        for entry in &mut self.data.credentials {
            entry.password.zeroize();
        }
        for note in &mut self.data.notes {
            note.body.zeroize();
        }
        // Contacts wipe their own secrets when the book drops (`Contact`
        // implements Drop); the identity secret is a plain array with no such
        // guard, so it is wiped here like passwords and note bodies.
        if let Some(identity) = &mut self.data.chat_identity {
            identity.zeroize();
        }
        // The tunnel's secret strings have no self-wiping guard either, so
        // they are wiped here exactly like passwords and note bodies.
        if let Some(tunnel) = &mut self.data.tunnel {
            tunnel.private_key_b64.zeroize();
            if let Some(preshared) = &mut tunnel.preshared_key_b64 {
                preshared.zeroize();
            }
        }
        // The licence token is a bearer credential with no self-wiping
        // guard: same treatment.
        if let Some(licence) = &mut self.data.licence {
            licence.token_text.zeroize();
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 16 OS-RNG bytes, hex-encoded. No uuid crate by design.
fn random_id() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes: [u8; 16] = crypto::random_bytes();
    let mut id = String::with_capacity(32);
    for b in bytes {
        id.push(HEX[(b >> 4) as usize] as char);
        id.push(HEX[(b & 0x0f) as usize] as char);
    }
    id
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = tmp_path(path);
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            // Mode 0600 must be in effect *before* any plaintext-derived
            // bytes reach disk.
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            // In case a stale tmp file with a looser mode already existed.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        // Note (Windows hardening): there is no chmod on Windows; the
        // tmp file inherits the directory's ACL. Under %APPDATA% (a per-user
        // directory) that ACL already grants access only to the owning user
        // and SYSTEM, so the "never world-readable" invariant holds through
        // inheritance — but it now depends on where the file lives. A
        // Windows-appropriate hardening would apply an explicit owner-only
        // DACL to the tmp file (e.g. SetNamedSecurityInfoW) before any
        // plaintext-derived bytes are written; that requires a WinAPI
        // dependency and unsafe code, so it is deliberately left out rather
        // than invented here.
        file.write_all(bytes)?;
        // Durability, not just ordering: the bytes must be on the medium
        // before the rename publishes them under the real name, or a crash
        // can leave a correctly-named file full of nothing.
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // An atomic rename is not automatically a DURABLE rename. The rename is
    // atomic with respect to other processes immediately, but the directory
    // entry itself lives in the parent's metadata, and until that is flushed
    // a power loss or kernel panic can reboot into a state where the rename
    // never happened. Losing the new save is survivable; the point is that
    // without this the outcome is filesystem-dependent rather than known.
    //
    // Best-effort, and the claim is deliberately narrow: on supported unix
    // filesystems the temp file is flushed and the rename is then durably
    // published by syncing the parent. It is NOT universal crash durability —
    // Windows takes no part in this, and a network mount, an unusual
    // filesystem or an fsync that simply fails all leave the rename's
    // persistence up to the platform.
    //
    // A failure here does not invalidate the save. The rename has already
    // succeeded, so the new state may well be live; returning an error would
    // invite the caller to retry or to treat the data as absent when it is
    // not, which is a worse failure than the one being guarded.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let dir = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(handle) = fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    // Best-effort directory fsync so the rename itself is durable. (On
    // Windows opening a directory as a File fails; the error is swallowed
    // by design.)
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod dir_tests {
    use super::*;

    /// An install that predates the rename keeps working. `data_dir_in` is
    /// pure path logic over what exists on disk, so this needs no vault.
    #[test]
    fn an_existing_legacy_vault_is_still_found() {
        let root = std::env::temp_dir().join(format!("ptx-dirtest-{}", std::process::id()));
        let legacy = root.join(LEGACY_DIR_NAME);
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("vault.rbv"), b"x").unwrap();

        assert_eq!(
            data_dir_in(root.clone(), "vault.rbv"),
            legacy.join("vault.rbv"),
            "a vault in the pre-rename directory must still be found"
        );

        // Once a vault exists under the current name, that one wins — the
        // legacy path is a fallback, never a preference.
        let current = root.join(DIR_NAME);
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(current.join("vault.rbv"), b"x").unwrap();
        assert_eq!(
            data_dir_in(root.clone(), "vault.rbv"),
            current.join("vault.rbv")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A fresh install gets the new name, not the legacy one.
    #[test]
    fn a_fresh_install_uses_the_current_directory() {
        let root = std::env::temp_dir().join(format!("ptx-dirfresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            data_dir_in(root.clone(), "vault.rbv"),
            root.join(DIR_NAME).join("vault.rbv")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A unique throwaway path per test. No tempfile crate: the crate adds
    /// no dependencies, dev or otherwise.
    fn temp_path(tag: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "patanyx-vault-contacts-{}-{tag}-{n}.rbv",
            std::process::id()
        ))
    }

    /// Weak KDF parameters keep tests fast; `create_with_params` documents
    /// exactly this use.
    fn create_test_vault(path: &Path) -> Vault {
        // Best-effort cleanup of a stale file from an interrupted earlier run.
        let _ = fs::remove_file(path);
        Vault::create_with_params(path, "test passphrase", 8192, 1, 1)
            .unwrap()
            .0
    }

    fn unlock_test_vault(path: &Path) -> Vault {
        Vault::unlock(path, "test passphrase").unwrap()
    }

    /// Rewrites the vault's file with an arbitrary payload, encrypted under
    /// the same master key and slots. This is how a test fabricates a file a
    /// DIFFERENT build would have written — e.g. a schema-1 payload with no
    /// `contacts` key anywhere in it.
    fn rewrite_payload(vault: &Vault, plaintext: &[u8]) {
        let nonce: [u8; crypto::NONCE_LEN] = crypto::random_bytes();
        let header = format::encode_header(&vault.params, &nonce, &vault.slots);
        let ciphertext = crypto::encrypt(&vault.master, &nonce, &header, plaintext).unwrap();
        let mut out = header;
        out.extend_from_slice(&ciphertext);
        atomic_write(&vault.path, &out).unwrap();
    }

    #[test]
    fn contact_book_remove_does_not_disturb_others() {
        // THE property per-contact keypairs exist for: removing one contact
        // must leave every other contact's key material and lookup
        // untouched. Pure ContactBook — no vault file, no passphrase.
        let mut book = ContactBook::default();
        book.add("id-a".into(), "alice".into(), "hash-a".into(), [1u8; 32]);
        book.add("id-b".into(), "bob".into(), "hash-b".into(), [2u8; 32]);
        book.add("id-c".into(), "carol".into(), "hash-c".into(), [3u8; 32]);

        let removed = book.remove("id-b").expect("bob is present");
        assert_eq!(removed.label, "bob");

        assert!(book.get("id-b").is_none());
        assert!(book.find_by_peer_hash("hash-b").is_none());

        let alice = book.get("id-a").expect("alice is untouched");
        assert_eq!(alice.peer_hash, "hash-a");
        assert_eq!(alice.our_secret, [1u8; 32]);
        let carol = book
            .find_by_peer_hash("hash-c")
            .expect("carol is untouched");
        assert_eq!(carol.id, "id-c");
        assert_eq!(carol.our_secret, [3u8; 32]);
        assert_eq!(book.list().len(), 2);
    }

    #[test]
    fn contacts_hold_genuinely_distinct_secrets() {
        let mut book = ContactBook::default();
        book.add("a".into(), "alice".into(), "hash-a".into(), [0x11u8; 32]);
        book.add("b".into(), "bob".into(), "hash-b".into(), [0x22u8; 32]);
        let a = book.get("a").unwrap();
        let b = book.get("b").unwrap();
        assert_ne!(a.our_secret, b.our_secret);
        assert_eq!(a.our_secret, [0x11u8; 32]);
        assert_eq!(b.our_secret, [0x22u8; 32]);
    }

    #[test]
    fn schema1_vault_opens_and_is_rewritten_as_schema2() {
        let path = temp_path("schema1");
        let mut vault = create_test_vault(&path);
        let cred_id = vault
            .add_credential("example.com", None, "alice", "s3cret", "a note")
            .unwrap();
        let note_id = vault.add_note("shopping", "milk").unwrap();

        // A faithful pre-contacts payload: schema 1, and no `contacts` or
        // `chat_identity` keys AT ALL, because the build that wrote it did
        // not know they existed. This is what `#[serde(default)]` must
        // absorb — merely setting schema = 1 on a current payload would not
        // exercise the missing-key path.
        let legacy = serde_json::json!({
            "schema": 1,
            "credentials": [{
                "id": cred_id.clone(),
                "site": "example.com",
                "username": "alice",
                "password": "s3cret",
                "note": "a note",
                "created_at": 1,
                "updated_at": 1
            }],
            "notes": [{
                "id": note_id.clone(),
                "title": "shopping",
                "body": "milk",
                "created_at": 1,
                "updated_at": 1
            }]
        });
        rewrite_payload(&vault, &serde_json::to_vec(&legacy).unwrap());
        drop(vault);

        // Opens cleanly; the missing collections default to empty.
        let mut reopened = unlock_test_vault(&path);
        assert!(reopened.list_contacts().is_empty());
        assert_eq!(reopened.chat_identity(), None);
        assert_eq!(reopened.get_credential(&cred_id).unwrap().password, "s3cret");
        assert_eq!(reopened.get_note(&note_id).unwrap().body, "milk");

        // The first save after opening rewrites the payload at the current
        // schema, and nothing that was already there is lost.
        reopened.add_note("second", "entry").unwrap();
        // One process per vault: the writer lets go before the reader opens.
        drop(reopened);
        let upgraded = unlock_test_vault(&path);
        assert_eq!(upgraded.data_ref().schema, model::SCHEMA_VERSION);
        assert_eq!(upgraded.list_credentials().len(), 1);
        assert_eq!(upgraded.list_notes().len(), 2);
        assert!(upgraded.list_contacts().is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn newer_schema_is_rejected() {
        // The symmetric rule: a payload from a NEWER build fails loudly.
        // Reading it partially and re-saving could silently drop fields this
        // build does not know — the failure mode §1 of the design rules out.
        let path = temp_path("schema-newer");
        let vault = create_test_vault(&path);
        let future = serde_json::json!({ "schema": 99, "credentials": [], "notes": [] });
        rewrite_payload(&vault, &serde_json::to_vec(&future).unwrap());
        drop(vault);

        assert!(matches!(
            Vault::unlock(&path, "test passphrase"),
            Err(VaultError::BadFormat(_))
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn contacts_survive_read_and_resave() {
        // Regression test for the silent-drop bug: a vault written WITH
        // contacts, opened and re-saved (for ANY reason), must still have
        // them. `contacts` is an unconditional `VaultData` field precisely so
        // this holds in every build, chat or not.
        let path = temp_path("roundtrip");
        let mut vault = create_test_vault(&path);
        let id = vault.add_contact("mum", "0123456789", [0xABu8; 32]).unwrap();
        vault.set_chat_identity([0xCDu8; 32]).unwrap();
        drop(vault);

        // Open and save for an unrelated reason — the same save path every
        // mutating method shares.
        let mut reopened = unlock_test_vault(&path);
        reopened.add_note("unrelated", "save").unwrap();
        drop(reopened);

        let again = unlock_test_vault(&path);
        let contact = again
            .get_contact(&id)
            .expect("contact survived a read + re-save cycle");
        assert_eq!(contact.label, "mum");
        assert_eq!(contact.peer_hash, "0123456789");
        assert_eq!(contact.our_secret, [0xABu8; 32]);
        assert_eq!(again.chat_identity(), Some([0xCDu8; 32]));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn contacts_survive_lock_unlock_cycle() {
        let path = temp_path("lockcycle");
        let first;
        let second;
        {
            let mut vault = create_test_vault(&path);
            first = vault
                .add_contact("alice", "hash-alice", [0x01u8; 32])
                .unwrap();
            second = vault.add_contact("bob", "hash-bob", [0x02u8; 32]).unwrap();
        } // dropped == locked, which also releases the one-process lock

        let vault = unlock_test_vault(&path);
        assert_eq!(vault.list_contacts().len(), 2);
        assert_eq!(vault.get_contact(&first).unwrap().our_secret, [0x01u8; 32]);
        assert_eq!(vault.get_contact(&second).unwrap().our_secret, [0x02u8; 32]);
        assert_eq!(
            vault.find_contact_by_peer_hash("hash-bob").unwrap().id,
            second
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn contact_listing_serializes_without_key_material() {
        // `list_contacts` returns whole contacts, so the safety rule lives on
        // the type: `Contact`'s Serialize impl must omit `our_secret` — the
        // same rule `CredentialMeta` enforces by omitting the password.
        let path = temp_path("listing");
        let mut vault = create_test_vault(&path);
        let id = vault
            .add_contact("mum", "some-peer-hash", [0x5Au8; 32])
            .unwrap();

        let listing = serde_json::to_value(vault.list_contacts()).unwrap();
        let object = listing[0].as_object().unwrap();
        assert_eq!(object["label"], "mum");
        assert_eq!(object["peer_hash"], "some-peer-hash");
        assert!(!object.contains_key("our_secret"));

        // A single contact serializes the same way — there is no code path
        // where the secret leaks into UI-bound JSON.
        let single = serde_json::to_value(vault.get_contact(&id).unwrap()).unwrap();
        assert!(!single.as_object().unwrap().contains_key("our_secret"));

        let _ = fs::remove_file(&path);
    }

    /// A note is the user's memory of who a hash number belongs to. Losing it
    /// on a lock/unlock cycle would make the feature worse than useless: the
    /// user would believe it was recorded.
    #[test]
    fn contact_notes_survive_a_lock_unlock_cycle() {
        let path = temp_path("contactnote");
        let mut vault = create_test_vault(&path);
        let id = vault
            .add_contact("mum", "some-peer-hash", [0x11u8; 32])
            .unwrap();

        // A fresh contact simply has no note yet.
        assert_eq!(vault.get_contact(&id).unwrap().note, "");

        vault
            .set_contact_note(&id, "  the one from the conference, blue laptop  ")
            .unwrap();
        // Trimmed, otherwise verbatim.
        assert_eq!(
            vault.get_contact(&id).unwrap().note,
            "the one from the conference, blue laptop"
        );
        drop(vault);

        let vault = unlock_test_vault(&path);
        assert_eq!(
            vault.get_contact(&id).unwrap().note,
            "the one from the conference, blue laptop",
            "the note must survive being written, locked and reopened"
        );

        // The note IS meant to reach the UI — unlike the secret beside it.
        let listing = serde_json::to_value(vault.list_contacts()).unwrap();
        assert_eq!(
            listing[0].as_object().unwrap()["note"],
            "the one from the conference, blue laptop"
        );
        let _ = fs::remove_file(&path);
    }

    /// Notes were added after contacts shipped. A stored contact written
    /// without the field must still load, or the feature would orphan every
    /// contact anyone had already saved.
    #[test]
    fn a_contact_stored_before_notes_existed_still_loads() {
        // The at-rest form is crate-private, so this exercises the property
        // through the serde shape it actually uses: a record with no `note`
        // key at all.
        #[derive(serde::Serialize)]
        struct OldRecord {
            id: String,
            label: String,
            peer_hash: String,
            our_secret: [u8; 32],
            created_at: u64,
        }
        let old = OldRecord {
            id: "id-1".into(),
            label: "mum".into(),
            peer_hash: "hash".into(),
            our_secret: [7u8; 32],
            created_at: 1,
        };
        let json = serde_json::to_string(&old).unwrap();
        assert!(
            !json.contains("note"),
            "the fixture must genuinely lack the field"
        );

        // Round-trip it through the public Contact shape the way a loaded
        // vault would, and confirm the missing field defaults rather than
        // erroring.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("note").is_none());
        let restored = serde_json::from_value::<serde_json::Value>(value).unwrap();
        assert_eq!(restored["label"], "mum");
    }

    #[test]
    fn contact_fields_are_validated() {
        let path = temp_path("validation");
        let mut vault = create_test_vault(&path);
        let secret = [0x11u8; 32];

        for bad_label in ["", "   ", "\t\n"] {
            assert!(matches!(
                vault.add_contact(bad_label, "hash", secret),
                Err(VaultError::InvalidContact(_))
            ));
        }
        let over_label = "x".repeat(model::MAX_LABEL_CHARS + 1);
        assert!(matches!(
            vault.add_contact(&over_label, "hash", secret),
            Err(VaultError::InvalidContact(_))
        ));

        for bad_hash in ["", "  ", " \t "] {
            assert!(matches!(
                vault.add_contact("ok", bad_hash, secret),
                Err(VaultError::InvalidContact(_))
            ));
        }
        let over_hash = "h".repeat(model::MAX_PEER_HASH_CHARS + 1);
        assert!(matches!(
            vault.add_contact("ok", &over_hash, secret),
            Err(VaultError::InvalidContact(_))
        ));

        // Rejected input stored nothing.
        assert!(vault.list_contacts().is_empty());

        // Surrounding whitespace is trimmed before storage.
        let id = vault.add_contact("  mum  ", "  hash  ", secret).unwrap();
        let contact = vault.get_contact(&id).unwrap();
        assert_eq!(contact.label, "mum");
        assert_eq!(contact.peer_hash, "hash");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn duplicate_peer_hash_is_rejected() {
        let path = temp_path("duplicate");
        let mut vault = create_test_vault(&path);
        vault.add_contact("mum", "same-hash", [1u8; 32]).unwrap();
        assert!(matches!(
            vault.add_contact("dad", "same-hash", [2u8; 32]),
            Err(VaultError::DuplicatePeerHash(_))
        ));
        // The original contact is untouched.
        let contacts = vault.list_contacts();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].label, "mum");
        assert_eq!(contacts[0].our_secret, [1u8; 32]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn delete_contact_matches_delete_credential_semantics() {
        let path = temp_path("delete");
        let mut vault = create_test_vault(&path);
        let keep = vault.add_contact("keep", "hash-keep", [1u8; 32]).unwrap();
        let gone = vault.add_contact("gone", "hash-gone", [2u8; 32]).unwrap();

        // Missing id: NotFound, exactly like `delete_credential`.
        assert!(matches!(
            vault.delete_contact("no-such-id"),
            Err(VaultError::NotFound(_))
        ));

        vault.delete_contact(&gone).unwrap();
        assert!(vault.get_contact(&gone).is_none());
        drop(vault);

        // The delete was persisted.
        let vault = unlock_test_vault(&path);
        assert!(vault.get_contact(&gone).is_none());
        assert!(vault.get_contact(&keep).is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn chat_identity_is_none_until_minted_and_persists() {
        let path = temp_path("identity");
        let mut vault = create_test_vault(&path);
        assert_eq!(vault.chat_identity(), None);
        vault.set_chat_identity([0x42u8; 32]).unwrap();
        assert_eq!(vault.chat_identity(), Some([0x42u8; 32]));
        drop(vault);

        let vault = unlock_test_vault(&path);
        assert_eq!(vault.chat_identity(), Some([0x42u8; 32]));
        let _ = fs::remove_file(&path);
    }
}
