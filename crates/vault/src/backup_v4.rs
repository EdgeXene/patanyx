//! Vault backup file, version 4: the vault and everything connected to it.
//!
//! Versions 1 and 2 were one AEAD message built whole in memory: fine for a
//! vault and its bookmarks, impossible for a Library whose pictures run to
//! hundreds of megabytes. Version 4 seals the same contents as a STREAM
//! (Hoang, Reyhanitabar, Rogaway, Vizár: online authenticated encryption,
//! `aead::stream` with the 32-bit big-endian counter and last-segment flag),
//! so neither writing nor reading ever holds the whole backup in memory, and
//! a segment that is reordered, dropped, repeated or appended fails to open.
//!
//! # File layout
//!
//! ```text
//! offset  size  field
//! 0       7     magic = b"RBVEXPT"     (the export magic, as versions 1 and 2)
//! 7       1     version = 0x04
//! 8       12    argon2 m_cost, t_cost, p_cost (u32 LE each)
//! 20      16    salt (OS RNG)
//! 36      19    STREAM nonce prefix (OS RNG)
//! 55      5     zero (reserved; the STREAM counter and flag fill these per segment)
//! 60      ..    segments: 1 MiB of plaintext + 16-byte tag each, the last one
//!               shorter (down to the tag alone)
//! ```
//!
//! The whole 60-byte header is the associated data of every segment, so the
//! version, the KDF parameters, the salt and the nonce are authenticated
//! exactly as in versions 1 and 2. Version 3 is taken: an experimental build
//! line uses it for version 2's layout under a number older builds refuse.
//!
//! # The plaintext inside
//!
//! A sequence of records, each `kind (u8) | name length (u16 LE) | name |
//! body length (u64 LE) | body`:
//!
//! - `VAULT` first and exactly once: the vault's contents, the same JSON a
//!   version 1 export carried, read under the same schema rule as an unlock.
//! - `LIBRARY`, `PICTURE` and `ADDON`: opaque to this crate, which never
//!   learns what a bookmark or a picture is. The app decides what they hold
//!   and checks them; this crate only bounds their sizes, with limits the app
//!   hands it, BEFORE reading a body.
//! - `END` last: how many records came before it, their total body size, and
//!   a SHA-256 over all of them, so an end that is not this writer's own is
//!   refused even though the STREAM's last-segment flag already pins it.
//!
//! # Reading writes nothing
//!
//! [`BackupReader`] decrypts and checks; it never touches the vault on disk.
//! The vault it reads comes back as a [`PendingImport`], which already has the
//! new master key, so the app can build the new Library under the new
//! vault's Library key BEFORE anything is replaced. Only
//! [`PendingImport::install`] writes the vault, and the app calls it once the
//! rest of the backup has been read and checked.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backup::{
    discard_replaced_vault_leftovers, kdf_params_plausible, prepare_export_dest, ExportError,
    EXPORT_HEADER_LEN, EXPORT_MAGIC,
};
use crate::crypto::{self, KdfParams, KEY_LEN, SALT_LEN};
use crate::format::SlotKind;
use crate::model::VaultData;
use crate::{open_new_temp, temp_path_in, RecoveryKey, Vault, VaultError};

/// The version byte this module writes and reads.
pub const BACKUP_VERSION: u8 = 0x04;

/// Plaintext per STREAM segment.
const SEGMENT_PLAIN: usize = 1 << 20;
/// Poly1305 tag carried by every segment.
const TAG_LEN: usize = 16;
/// Ciphertext of a full segment.
const SEGMENT_CIPHER: usize = SEGMENT_PLAIN + TAG_LEN;
/// XChaCha20's 24-byte nonce, less STREAM's 5 bytes of counter and flag.
const NONCE_PREFIX_LEN: usize = 19;

const KIND_VAULT: u8 = 1;
const KIND_LIBRARY: u8 = 2;
const KIND_PICTURE: u8 = 3;
const KIND_ADDON: u8 = 4;
const KIND_END: u8 = 0xFF;

/// Longest record name: a picture id or an add-on path.
const MAX_NAME_LEN: usize = 255;
/// A vault's contents. Far above any real vault; it only bounds what a
/// crafted file can make this build allocate.
pub const MAX_VAULT_SECTION: u64 = 256 * 1024 * 1024;
/// The END record's small JSON.
const MAX_END_SECTION: u64 = 64 * 1024;

/// What the app may put in a backup besides the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    /// The Library's records, without pictures.
    Library,
    /// One picture, named by its id.
    Picture,
    /// One add-on's data, named `<add-on id>/<item id>`.
    Addon,
}

impl SectionKind {
    fn byte(self) -> u8 {
        match self {
            SectionKind::Library => KIND_LIBRARY,
            SectionKind::Picture => KIND_PICTURE,
            SectionKind::Addon => KIND_ADDON,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            KIND_LIBRARY => Some(SectionKind::Library),
            KIND_PICTURE => Some(SectionKind::Picture),
            KIND_ADDON => Some(SectionKind::Addon),
            _ => None,
        }
    }
}

/// The largest body the reader accepts for each kind, checked BEFORE a body
/// is read. The app sets them from its own limits; this crate does not know
/// what a Library or a picture is.
///
/// A limit of 0 means this build does not read that kind at all. A section of
/// it is then refused as coming from a newer PATANYX
/// ([`ExportError::UnreadableVersion`]), not as damage: inside the sealed
/// stream it can only have been written by a build that knew the kind.
#[derive(Clone, Copy, Debug)]
pub struct SectionLimits {
    pub library: u64,
    pub picture: u64,
    pub addon: u64,
}

impl SectionLimits {
    fn of(&self, kind: SectionKind) -> u64 {
        match kind {
            SectionKind::Library => self.library,
            SectionKind::Picture => self.picture,
            SectionKind::Addon => self.addon,
        }
    }
}

/// One section read back from a backup. The body is wiped when dropped.
pub struct Section {
    pub kind: SectionKind,
    pub name: String,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Section")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("bytes", &self.body.len())
            .finish()
    }
}

/// What the END record vouches for.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EndManifest {
    records: u64,
    bytes: u64,
    sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bad(what: impl Into<String>) -> ExportError {
    ExportError::BadExport(what.into())
}

/// The version byte of a backup file, read without a passphrase, so the app
/// can choose the reader (versions 1 and 2: [`Vault::import_encrypted`];
/// version 4: [`BackupReader`]) and name a version it cannot read.
pub fn backup_file_version(src: &Path) -> Result<u8, ExportError> {
    let mut head = [0u8; 8];
    let mut file = fs::File::open(src)?;
    file.read_exact(&mut head)
        .map_err(|_| bad("file too short to be a PATANYX vault export"))?;
    if &head[0..7] != EXPORT_MAGIC {
        return Err(bad("bad magic"));
    }
    Ok(head[7])
}

fn encode_header(
    params: &KdfParams,
    salt: &[u8; SALT_LEN],
    prefix: &[u8; NONCE_PREFIX_LEN],
) -> [u8; EXPORT_HEADER_LEN] {
    let mut out = [0u8; EXPORT_HEADER_LEN];
    out[0..7].copy_from_slice(EXPORT_MAGIC);
    out[7] = BACKUP_VERSION;
    out[8..12].copy_from_slice(&params.m_cost.to_le_bytes());
    out[12..16].copy_from_slice(&params.t_cost.to_le_bytes());
    out[16..20].copy_from_slice(&params.p_cost.to_le_bytes());
    out[20..36].copy_from_slice(salt);
    out[36..55].copy_from_slice(prefix);
    // 55..60 stay zero.
    out
}

fn decode_header(
    header: &[u8; EXPORT_HEADER_LEN],
) -> Result<(KdfParams, [u8; SALT_LEN], [u8; NONCE_PREFIX_LEN]), ExportError> {
    if &header[0..7] != EXPORT_MAGIC {
        return Err(bad("bad magic"));
    }
    if header[7] != BACKUP_VERSION {
        return Err(ExportError::UnreadableVersion(header[7]));
    }
    let params = KdfParams {
        m_cost: u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
        t_cost: u32::from_le_bytes([header[12], header[13], header[14], header[15]]),
        p_cost: u32::from_le_bytes([header[16], header[17], header[18], header[19]]),
    };
    // Bounds BEFORE Argon2: the header is only authenticated after the key is
    // derived, so a tampered m_cost would otherwise be a denial of service.
    if !kdf_params_plausible(&params) {
        return Err(bad(format!(
            "implausible kdf parameters m={} t={} p={}",
            params.m_cost, params.t_cost, params.p_cost
        )));
    }
    if header[55..60] != [0u8; 5] {
        return Err(bad("reserved header bytes are not zero"));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[20..36]);
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    prefix.copy_from_slice(&header[36..55]);
    Ok((params, salt, prefix))
}

fn frame(kind: u8, name: &str, body_len: u64) -> Result<Vec<u8>, ExportError> {
    if name.len() > MAX_NAME_LEN {
        return Err(bad("a section name is too long"));
    }
    let mut out = Vec::with_capacity(1 + 2 + name.len() + 8);
    out.push(kind);
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&body_len.to_le_bytes());
    Ok(out)
}

// ---- progress and stopping -------------------------------------------------

/// Which part of a backup is running, for the progress the person sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupStage {
    /// Deriving the key from a passphrase: no byte count, and it cannot be
    /// interrupted (a second or two).
    Preparing,
    /// An export sealing and writing segments. Its total is the estimate the
    /// app gave ([`BackupWatch::set_estimate`]), so the bytes can pass it.
    Writing,
    /// An export reading back the file it wrote, the way an import would.
    /// Its total is the file's exact size.
    Checking,
    /// An import reading the backup. Its total is the file's exact size.
    Reading,
}

impl BackupStage {
    fn byte(self) -> u8 {
        match self {
            BackupStage::Preparing => 0,
            BackupStage::Writing => 1,
            BackupStage::Checking => 2,
            BackupStage::Reading => 3,
        }
    }

    fn from_byte(byte: u8) -> Self {
        match byte {
            1 => BackupStage::Writing,
            2 => BackupStage::Checking,
            3 => BackupStage::Reading,
            _ => BackupStage::Preparing,
        }
    }
}

/// What a running backup has done so far, and the way to stop it. Shared by
/// the thread doing the work and the one showing it; a clone shares the same
/// state.
///
/// Stopping is cooperative. The work looks at every 1 MiB segment it writes
/// or reads, at every section the app writes or reads, and once more right
/// before an export's rename. A stop seen at any of those points ends the work
/// with [`ExportError::Cancelled`] through the ordinary failure path: an
/// export removes its temporary file and leaves the destination untouched. A
/// stop that arrives after the rename changes nothing, because the backup is
/// finished by then. Key derivation is the one step that cannot be
/// interrupted.
#[derive(Clone, Default)]
pub struct BackupWatch(Arc<WatchState>);

#[derive(Default)]
struct WatchState {
    stopped: AtomicBool,
    stage: AtomicU8,
    done: AtomicU64,
    total: AtomicU64,
    estimate: AtomicU64,
    items_done: AtomicU64,
    items_total: AtomicU64,
    #[cfg(test)]
    test: std::sync::Mutex<WatchTest>,
}

/// One reading of a [`BackupWatch`]. The fields are read one at a time, so a
/// reading taken while the stage changes can mix the two; it is for showing
/// progress, never for deciding anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchSnapshot {
    pub stage: BackupStage,
    pub done: u64,
    /// `None` while the size is not known.
    pub total: Option<u64>,
    pub items_done: u64,
    pub items_total: u64,
    pub stopped: bool,
}

impl std::fmt::Debug for BackupWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BackupWatch").field(&self.snapshot()).finish()
    }
}

impl BackupWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the work to stop at its next check.
    pub fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.0.stopped.load(Ordering::SeqCst)
    }

    /// `Err(Cancelled)` once [`BackupWatch::stop`] has been called.
    pub fn check(&self) -> Result<(), ExportError> {
        if self.is_stopped() {
            Err(ExportError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Sections done and expected, counted by the app (pictures, for both
    /// directions).
    pub fn set_items(&self, done: u64, total: u64) {
        self.0.items_total.store(total, Ordering::Relaxed);
        self.0.items_done.store(done, Ordering::Relaxed);
    }

    /// How many bytes an export expects to write, given before it starts.
    pub fn set_estimate(&self, bytes: u64) {
        self.0.estimate.store(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> WatchSnapshot {
        let total = self.0.total.load(Ordering::Relaxed);
        WatchSnapshot {
            stage: BackupStage::from_byte(self.0.stage.load(Ordering::Relaxed)),
            done: self.0.done.load(Ordering::Relaxed),
            total: (total > 0).then_some(total),
            items_done: self.0.items_done.load(Ordering::Relaxed),
            items_total: self.0.items_total.load(Ordering::Relaxed),
            stopped: self.is_stopped(),
        }
    }

    /// Starts a stage with nothing done yet, then checks for a stop.
    pub(crate) fn enter(&self, stage: BackupStage, total: u64) -> Result<(), ExportError> {
        self.0.total.store(total, Ordering::Relaxed);
        self.0.done.store(0, Ordering::Relaxed);
        self.0.stage.store(stage.byte(), Ordering::Relaxed);
        #[cfg(test)]
        self.test_hook(stage, 0);
        self.check()
    }

    /// Records progress within the current stage (it never goes back), then
    /// checks for a stop.
    pub(crate) fn reached(&self, done: u64) -> Result<(), ExportError> {
        self.0.done.fetch_max(done, Ordering::Relaxed);
        #[cfg(test)]
        self.test_hook(BackupStage::from_byte(self.0.stage.load(Ordering::Relaxed)), done);
        self.check()
    }

    fn estimate(&self) -> u64 {
        self.0.estimate.load(Ordering::Relaxed)
    }
}

/// Test-only: stop the work at a chosen point, and keep every step it
/// reported so the order of stages can be checked.
#[cfg(test)]
#[derive(Default)]
struct WatchTest {
    stop_at: Option<(BackupStage, u64)>,
    history: Vec<(BackupStage, u64)>,
}

#[cfg(test)]
impl BackupWatch {
    /// Stops the work once `stage` has reached `done` bytes.
    pub(crate) fn stop_at(&self, stage: BackupStage, done: u64) {
        self.0.test.lock().unwrap().stop_at = Some((stage, done));
    }

    pub(crate) fn history(&self) -> Vec<(BackupStage, u64)> {
        self.0.test.lock().unwrap().history.clone()
    }

    fn test_hook(&self, stage: BackupStage, done: u64) {
        let mut test = self.0.test.lock().unwrap();
        test.history.push((stage, done));
        if let Some((at, bytes)) = test.stop_at {
            if at == stage && done >= bytes {
                self.stop();
            }
        }
    }
}

// ---- writing ---------------------------------------------------------------

/// Seals plaintext into 1 MiB STREAM segments as it arrives.
struct SegmentWriter<'f> {
    file: &'f mut (dyn Write + Send),
    encryptor: Option<EncryptorBE32<XChaCha20Poly1305>>,
    header: [u8; EXPORT_HEADER_LEN],
    buffer: Zeroizing<Vec<u8>>,
    hasher: Sha256,
    records: u64,
    bytes: u64,
    /// Sealed bytes written so far, reported to `watch` per segment.
    written: u64,
    watch: Option<BackupWatch>,
}

impl<'f> SegmentWriter<'f> {
    fn new(
        file: &'f mut (dyn Write + Send),
        key: &[u8; KEY_LEN],
        prefix: &[u8; NONCE_PREFIX_LEN],
        header: [u8; EXPORT_HEADER_LEN],
    ) -> Self {
        let encryptor = EncryptorBE32::<XChaCha20Poly1305>::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(prefix),
        );
        Self {
            file,
            encryptor: Some(encryptor),
            header,
            buffer: Zeroizing::new(Vec::with_capacity(SEGMENT_PLAIN)),
            hasher: Sha256::new(),
            records: 0,
            bytes: 0,
            written: 0,
            watch: None,
        }
    }

    fn watched(mut self, watch: &BackupWatch) -> Self {
        self.watch = Some(watch.clone());
        self
    }

    /// Writes one sealed segment and reports it; a stop asked for meanwhile
    /// ends the export here.
    fn emit(&mut self, sealed: &[u8]) -> Result<(), ExportError> {
        self.file.write_all(sealed)?;
        self.written += sealed.len() as u64;
        match &self.watch {
            Some(watch) => watch.reached(self.written),
            None => Ok(()),
        }
    }

    fn push(&mut self, mut data: &[u8]) -> Result<(), ExportError> {
        while !data.is_empty() {
            let room = SEGMENT_PLAIN - self.buffer.len();
            let take = room.min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == SEGMENT_PLAIN {
                let encryptor = self.encryptor.as_mut().ok_or_else(|| bad("writer finished"))?;
                let sealed = encryptor
                    .encrypt_next(Payload {
                        msg: &self.buffer[..],
                        aad: &self.header,
                    })
                    .map_err(|_| VaultError::Crypto("aead encryption failed".into()))?;
                self.emit(&sealed)?;
                self.buffer.clear();
            }
        }
        Ok(())
    }

    fn record(&mut self, kind: u8, name: &str, body: &[u8]) -> Result<(), ExportError> {
        let head = frame(kind, name, body.len() as u64)?;
        self.hasher.update(&head);
        self.hasher.update(body);
        self.records += 1;
        self.bytes += body.len() as u64;
        self.push(&head)?;
        self.push(body)
    }

    /// Writes END and the last segment. Consumes the writer: nothing can be
    /// appended after the last-segment flag.
    fn finish(mut self) -> Result<BackupStats, ExportError> {
        let manifest = EndManifest {
            records: self.records,
            bytes: self.bytes,
            sha256: hex(&self.hasher.clone().finalize()),
        };
        let body = serde_json::to_vec(&manifest)
            .map_err(|e| VaultError::Crypto(format!("json encode: {e}")))?;
        let head = frame(KIND_END, "", body.len() as u64)?;
        self.push(&head)?;
        self.push(&body)?;
        let encryptor = self.encryptor.take().ok_or_else(|| bad("writer finished"))?;
        let sealed = encryptor
            .encrypt_last(Payload {
                msg: &self.buffer[..],
                aad: &self.header,
            })
            .map_err(|_| VaultError::Crypto("aead encryption failed".into()))?;
        self.emit(&sealed)?;
        Ok(BackupStats {
            sections: self.records.saturating_sub(1),
            bytes: self.bytes,
        })
    }

    /// Seals whatever was pushed as the last segment, with no END of its own:
    /// the fuzzer writes its own records, END included or not.
    #[cfg(fuzzing)]
    fn seal_last(mut self) -> Result<(), ExportError> {
        let encryptor = self.encryptor.take().ok_or_else(|| bad("writer finished"))?;
        let sealed = encryptor
            .encrypt_last(Payload {
                msg: &self.buffer[..],
                aad: &self.header,
            })
            .map_err(|_| VaultError::Crypto("aead encryption failed".into()))?;
        self.file.write_all(&sealed)?;
        Ok(())
    }
}

/// Where the app writes its sections during [`Vault::export_backup`].
pub struct BackupSink<'w, 'f> {
    writer: &'w mut SegmentWriter<'f>,
}

impl BackupSink<'_, '_> {
    /// Adds one section. A picture body is at most one picture, so the
    /// backup never needs every picture in memory at once.
    pub fn section(&mut self, kind: SectionKind, name: &str, body: &[u8]) -> Result<(), ExportError> {
        self.writer.record(kind.byte(), name, body)
    }
}

/// What an export wrote, besides the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupStats {
    pub sections: u64,
    pub bytes: u64,
}

/// Everything an export needs from the vault, taken in one go so the export
/// can run on another thread while the vault itself stays with the app: the
/// vault's path (an export must never land on it), its KDF parameters, and
/// its contents. The contents are zeroized when this is dropped.
pub struct BackupSource {
    vault_path: PathBuf,
    params: KdfParams,
    vault_json: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for BackupSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupSource")
            .field("vault_path", &self.vault_path)
            .field("vault_json", &format_args!("<{} bytes>", self.vault_json.len()))
            .finish()
    }
}

impl Vault {
    /// What [`BackupSource::write`] needs, taken now.
    pub fn backup_source(&self) -> Result<BackupSource, ExportError> {
        let vault_json = Zeroizing::new(
            serde_json::to_vec(self.data_ref())
                .map_err(|e| VaultError::Crypto(format!("json encode: {e}")))?,
        );
        Ok(BackupSource {
            vault_path: self.path().to_path_buf(),
            params: self.kdf_params(),
            vault_json,
        })
    }

    /// Writes a version 4 backup of this vault at once: [`BackupSource::write`]
    /// with a watch nobody stops.
    pub fn export_backup(
        &self,
        dest: &Path,
        export_passphrase: &str,
        limits: SectionLimits,
        write_sections: &mut dyn FnMut(&mut BackupSink<'_, '_>) -> Result<(), ExportError>,
    ) -> Result<BackupStats, ExportError> {
        self.backup_source()?
            .write(dest, export_passphrase, limits, write_sections, &BackupWatch::new())
    }
}

impl BackupSource {
    /// Writes a version 4 backup: the vault, then whatever `write_sections`
    /// adds, sealed under `export_passphrase`.
    ///
    /// The file is written to an unpredictably named temporary file beside
    /// `dest` (0600 on unix), flushed, then READ BACK in full with the same
    /// reader an import uses, and only then renamed into place. A backup this
    /// build cannot read is therefore never left where the person expects one.
    /// Any failure, a stop through `watch` included, removes the temporary
    /// file and leaves `dest` untouched.
    pub fn write(
        &self,
        dest: &Path,
        export_passphrase: &str,
        limits: SectionLimits,
        write_sections: &mut dyn FnMut(&mut BackupSink<'_, '_>) -> Result<(), ExportError>,
        watch: &BackupWatch,
    ) -> Result<BackupStats, ExportError> {
        watch.enter(BackupStage::Preparing, 0)?;
        prepare_export_dest(dest, &self.vault_path)?;
        let params = self.params;
        let salt: [u8; SALT_LEN] = crypto::random_bytes();
        let prefix: [u8; NONCE_PREFIX_LEN] = crypto::random_bytes();
        let key = crypto::derive_key(export_passphrase.as_bytes(), &salt, &params)?;
        watch.check()?;
        let header = encode_header(&params, &salt, &prefix);

        let dir = match dest.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let temp = temp_path_in(dir);
        let mut file = open_new_temp(&temp)?;
        let written = (|| -> Result<BackupStats, ExportError> {
            file.write_all(&header)?;
            watch.enter(BackupStage::Writing, watch.estimate())?;
            let mut writer = SegmentWriter::new(&mut file, &key, &prefix, header).watched(watch);
            writer.record(KIND_VAULT, "", &self.vault_json)?;
            write_sections(&mut BackupSink {
                writer: &mut writer,
            })?;
            let stats = writer.finish()?;
            file.sync_all()?;
            Ok(stats)
        })();
        // Dropped before any removal: Windows cannot delete an open file.
        drop(file);
        let checked = written.and_then(|stats| {
            BackupReader::open_with_key(&temp, &key, limits, Some(watch))?.read_to_end()?;
            // The last point a stop is honoured: past the rename the backup
            // exists and is whole, and is reported as finished.
            watch.check()?;
            Ok(stats)
        });
        let stats = match checked {
            Ok(stats) => stats,
            Err(error) => {
                let _ = fs::remove_file(&temp);
                return Err(error);
            }
        };
        if let Err(error) = fs::rename(&temp, dest) {
            let _ = fs::remove_file(&temp);
            return Err(ExportError::Io(error));
        }
        // Best effort, as for every other file this crate writes: the rename
        // already happened, so a failed directory flush is not a failed export.
        if let Ok(handle) = fs::File::open(dir) {
            let _ = handle.sync_all();
        }
        Ok(stats)
    }
}

// ---- reading -----------------------------------------------------------------

/// A vault read from a backup and not yet written anywhere, with the master
/// key it will have. Holds the same secrets a vault does.
pub struct PendingImport {
    params: KdfParams,
    data: VaultData,
    master: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for PendingImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingImport(<redacted>)")
    }
}

impl PendingImport {
    pub(crate) fn new(params: KdfParams, data: VaultData) -> Self {
        Self {
            params,
            data,
            master: Zeroizing::new(crypto::random_bytes::<KEY_LEN>()),
        }
    }

    /// The Library key the vault will have once installed: what the new
    /// Library is created under, aside, before anything is replaced.
    pub fn library_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        crypto::derive_library_key(&self.master)
    }

    /// Writes the pending vault at `dest`, REPLACING any vault there: the
    /// import's commit point. A new passphrase slot and a newly minted
    /// recovery key, which must be shown exactly once.
    pub fn install(
        self,
        dest: &Path,
        new_vault_passphrase: &str,
    ) -> Result<(Vault, RecoveryKey), ExportError> {
        self.install_waiting(dest, new_vault_passphrase, std::time::Duration::ZERO)
    }

    /// [`PendingImport::install`], waiting up to `patience` for the vault's
    /// lock (`lock::acquire_patiently`). For a worker thread only: the wait
    /// sleeps.
    pub fn install_waiting(
        self,
        dest: &Path,
        new_vault_passphrase: &str,
        patience: std::time::Duration,
    ) -> Result<(Vault, RecoveryKey), ExportError> {
        // A destination that is a symbolic link would be replaced by NAME
        // while the real file, and every copy beside it, stayed where the
        // link pointed, under the retired passphrase. Refused outright.
        if fs::symlink_metadata(dest).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(ExportError::Io(std::io::Error::other(
                "the vault path is a symbolic link; import refused",
            )));
        }
        let PendingImport {
            params,
            data,
            master,
        } = self;
        let mut vault = Vault::assemble_waiting(dest.to_path_buf(), master, params, data, patience)?;
        // Everything in the replaced vault is lost, as the import panel says:
        // its rotated copies go first, under the lock, before anything is
        // written (security audit 2026-10-08).
        let retained = discard_replaced_vault_leftovers(dest)?.retained;
        let passphrase_slot =
            vault.build_slot(SlotKind::Passphrase, new_vault_passphrase.as_bytes(), &[])?;
        vault.push_slot(passphrase_slot);
        let recovery = RecoveryKey::generate();
        let recovery_slot = vault.build_slot(SlotKind::Recovery, recovery.as_bytes(), &[])?;
        vault.push_slot(recovery_slot);
        // No rotation: a copy taken here would be of the vault being discarded.
        vault.save_inner(false)?;
        vault.import_retained_leftovers = retained;
        Ok((vault, recovery))
    }
}

/// Reads a version 4 backup in ONE pass and writes nothing.
///
/// [`BackupReader::open`] reads the header and the vault; then
/// [`BackupReader::next_section`] returns each other section in file order
/// until END, which it checks; then [`BackupReader::finish`] hands back the
/// pending vault. A backup that ends before END never yields its vault.
pub struct BackupReader {
    file: Box<dyn Read + Send>,
    decryptor: Option<DecryptorBE32<XChaCha20Poly1305>>,
    header: [u8; EXPORT_HEADER_LEN],
    raw: Vec<u8>,
    plain: Zeroizing<Vec<u8>>,
    position: usize,
    last_seen: bool,
    limits: SectionLimits,
    hasher: Sha256,
    records: u64,
    bytes: u64,
    ended: bool,
    pending: Option<PendingImport>,
    /// Bytes of the file consumed so far, header included, reported to
    /// `watch` per segment.
    consumed: u64,
    watch: Option<BackupWatch>,
}

impl BackupReader {
    /// Opens a backup with its passphrase and reads the vault inside.
    pub fn open(
        src: &Path,
        export_passphrase: &str,
        limits: SectionLimits,
    ) -> Result<Self, ExportError> {
        Self::open_inner(src, export_passphrase, limits, None)
    }

    /// [`BackupReader::open`], reporting to `watch` (key derivation, then
    /// every segment read against the file's size) and stopping at the next
    /// segment once `watch` is stopped.
    pub fn open_watched(
        src: &Path,
        export_passphrase: &str,
        limits: SectionLimits,
        watch: &BackupWatch,
    ) -> Result<Self, ExportError> {
        Self::open_inner(src, export_passphrase, limits, Some(watch))
    }

    fn open_inner(
        src: &Path,
        export_passphrase: &str,
        limits: SectionLimits,
        watch: Option<&BackupWatch>,
    ) -> Result<Self, ExportError> {
        if let Some(watch) = watch {
            watch.enter(BackupStage::Preparing, 0)?;
        }
        let (file, header) = Self::read_header(src)?;
        let (params, salt, _) = decode_header(&header)?;
        let key = crypto::derive_key(export_passphrase.as_bytes(), &salt, &params)?;
        if let Some(watch) = watch {
            watch.enter(BackupStage::Reading, file.metadata()?.len())?;
        }
        Self::begin(Box::new(file), header, &key, limits, params, watch.cloned())
    }

    /// The export's own read-back, with the key it already holds.
    fn open_with_key(
        src: &Path,
        key: &[u8; KEY_LEN],
        limits: SectionLimits,
        watch: Option<&BackupWatch>,
    ) -> Result<Self, ExportError> {
        let (file, header) = Self::read_header(src)?;
        let (params, _, _) = decode_header(&header)?;
        if let Some(watch) = watch {
            watch.enter(BackupStage::Checking, file.metadata()?.len())?;
        }
        Self::begin(Box::new(file), header, key, limits, params, watch.cloned())
    }

    fn read_header(src: &Path) -> Result<(fs::File, [u8; EXPORT_HEADER_LEN]), ExportError> {
        let mut file = fs::File::open(src)?;
        let mut header = [0u8; EXPORT_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|_| bad("file too short to be a PATANYX vault export"))?;
        Ok((file, header))
    }

    /// Starts the STREAM and reads the vault, which must come first.
    fn begin(
        file: Box<dyn Read + Send>,
        header: [u8; EXPORT_HEADER_LEN],
        key: &[u8; KEY_LEN],
        limits: SectionLimits,
        params: KdfParams,
        watch: Option<BackupWatch>,
    ) -> Result<Self, ExportError> {
        let (_, _, prefix) = decode_header(&header)?;
        let decryptor = DecryptorBE32::<XChaCha20Poly1305>::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(&prefix),
        );
        let mut reader = Self {
            file,
            decryptor: Some(decryptor),
            header,
            raw: Vec::with_capacity(SEGMENT_CIPHER + 1),
            plain: Zeroizing::new(Vec::new()),
            position: 0,
            last_seen: false,
            limits,
            hasher: Sha256::new(),
            records: 0,
            bytes: 0,
            ended: false,
            pending: None,
            consumed: EXPORT_HEADER_LEN as u64,
            watch,
        };
        reader.read_vault(params)?;
        Ok(reader)
    }

    fn read_vault(&mut self, params: KdfParams) -> Result<(), ExportError> {
        let (kind, name, len) = self.read_frame()?;
        if kind != KIND_VAULT || !name.is_empty() {
            return Err(bad("the backup does not start with the vault"));
        }
        if len > MAX_VAULT_SECTION {
            return Err(bad("the vault section is larger than any vault"));
        }
        let body = self.read_body(kind, &name, len)?;
        // The same rule an unlock applies: a newer schema is refused as newer,
        // none is refused, and an accepted vault is stamped with this build's.
        let data = Vault::parse_payload(&body)?;
        self.pending = Some(PendingImport::new(params, data));
        Ok(())
    }

    /// The vault this backup will install, for its Library key.
    pub fn pending(&self) -> &PendingImport {
        self.pending
            .as_ref()
            .expect("open() only returns a reader that has read the vault")
    }

    /// The next section, or `None` once END has been read and checked.
    pub fn next_section(&mut self) -> Result<Option<Section>, ExportError> {
        if self.ended {
            return Ok(None);
        }
        let (kind_byte, name, len) = self.read_frame()?;
        if kind_byte == KIND_END {
            self.read_end(len)?;
            return Ok(None);
        }
        if kind_byte == KIND_VAULT {
            return Err(bad("the vault appears twice"));
        }
        // A kind this build cannot name, or one it is set not to read, was
        // written by a newer build: everything here is authenticated, so it is
        // not damage, and the person is told to update rather than that the
        // file is broken.
        let kind = SectionKind::from_byte(kind_byte)
            .ok_or(ExportError::UnreadableVersion(BACKUP_VERSION))?;
        if self.limits.of(kind) == 0 {
            return Err(ExportError::UnreadableVersion(BACKUP_VERSION));
        }
        if len > self.limits.of(kind) {
            return Err(bad(format!("a {kind:?} section is larger than allowed")));
        }
        let body = self.read_body(kind_byte, &name, len)?;
        Ok(Some(Section { kind, name, body }))
    }

    /// Hands back the pending vault. Only after END has been read and checked:
    /// a backup that stops early never installs anything.
    pub fn finish(mut self) -> Result<PendingImport, ExportError> {
        if !self.ended {
            return Err(bad("the backup was not read to its end"));
        }
        self.pending
            .take()
            .ok_or_else(|| bad("the backup holds no vault"))
    }

    /// Reads every remaining section and discards it: the export's read-back.
    fn read_to_end(mut self) -> Result<(), ExportError> {
        while self.next_section()?.is_some() {}
        self.finish().map(|_| ())
    }

    fn read_frame(&mut self) -> Result<(u8, String, u64), ExportError> {
        let kind = self.read_plain(1)?[0];
        let name_len = u16::from_le_bytes(self.read_plain(2)?[..].try_into().unwrap()) as usize;
        if name_len > MAX_NAME_LEN {
            return Err(bad("a section name is too long"));
        }
        let name_bytes = self.read_plain(name_len)?;
        let name = String::from_utf8(name_bytes.to_vec())
            .map_err(|_| bad("a section name is not text"))?;
        let len = u64::from_le_bytes(self.read_plain(8)?[..].try_into().unwrap());
        Ok((kind, name, len))
    }

    fn read_body(&mut self, kind: u8, name: &str, len: u64) -> Result<Zeroizing<Vec<u8>>, ExportError> {
        let len_usize = usize::try_from(len).map_err(|_| bad("a section is too large"))?;
        let body = self.read_plain(len_usize)?;
        self.hasher.update(frame(kind, name, len)?);
        self.hasher.update(&body[..]);
        self.records += 1;
        self.bytes += len;
        Ok(body)
    }

    fn read_end(&mut self, len: u64) -> Result<(), ExportError> {
        if len > MAX_END_SECTION {
            return Err(bad("the end record is too large"));
        }
        let body = self.read_plain(len as usize)?;
        let manifest: EndManifest =
            serde_json::from_slice(&body).map_err(|_| bad("the end record is unreadable"))?;
        let digest = hex(&self.hasher.clone().finalize());
        if manifest.records != self.records
            || manifest.bytes != self.bytes
            || manifest.sha256 != digest
        {
            return Err(bad("the end record does not match what came before it"));
        }
        // Nothing may follow END: not in this segment, not in another one.
        if self.position != self.plain.len() {
            return Err(bad("data follows the end record"));
        }
        if !self.last_seen {
            self.pull_segment()?;
            if self.position != self.plain.len() || !self.last_seen {
                return Err(bad("data follows the end record"));
            }
        }
        self.ended = true;
        Ok(())
    }

    /// `n` bytes of plaintext, pulling and opening segments as needed.
    fn read_plain(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>, ExportError> {
        let mut out = Zeroizing::new(Vec::with_capacity(n.min(SEGMENT_PLAIN)));
        while out.len() < n {
            if self.position == self.plain.len() {
                if self.last_seen {
                    return Err(bad("the backup ends in the middle of a record"));
                }
                self.pull_segment()?;
                continue;
            }
            let take = (n - out.len()).min(self.plain.len() - self.position);
            out.extend_from_slice(&self.plain[self.position..self.position + take]);
            self.position += take;
        }
        Ok(out)
    }

    /// Reads and opens the next segment. A full segment followed by more bytes
    /// is an ordinary one; whatever ends the file is the last, and opening it
    /// as the last is what proves nothing was cut off or added.
    fn pull_segment(&mut self) -> Result<(), ExportError> {
        while self.raw.len() <= SEGMENT_CIPHER {
            let mut chunk = [0u8; 64 * 1024];
            let want = (SEGMENT_CIPHER + 1 - self.raw.len()).min(chunk.len());
            let got = self.file.read(&mut chunk[..want])?;
            if got == 0 {
                break;
            }
            self.consumed += got as u64;
            self.raw.extend_from_slice(&chunk[..got]);
        }
        let opened = if self.raw.len() > SEGMENT_CIPHER {
            let segment: Vec<u8> = self.raw.drain(..SEGMENT_CIPHER).collect();
            let decryptor = self.decryptor.as_mut().ok_or(ExportError::AuthFailed)?;
            decryptor.decrypt_next(Payload {
                msg: &segment,
                aad: &self.header,
            })
        } else {
            if self.raw.len() < TAG_LEN {
                return Err(ExportError::AuthFailed);
            }
            let segment = std::mem::take(&mut self.raw);
            let decryptor = self.decryptor.take().ok_or(ExportError::AuthFailed)?;
            self.last_seen = true;
            decryptor.decrypt_last(Payload {
                msg: &segment,
                aad: &self.header,
            })
        };
        // Every AEAD failure is the same coarse error, as for versions 1 and 2.
        let plain = opened.map_err(|_| ExportError::AuthFailed)?;
        self.plain = Zeroizing::new(plain);
        self.position = 0;
        match &self.watch {
            Some(watch) => watch.reached(self.consumed),
            None => Ok(()),
        }
    }
}

/// Fuzzing entry, compiled only under `--cfg fuzzing` (set by cargo-fuzz for
/// its own builds, never by a release build): seals `plaintext` as one STREAM under a fixed key, exactly as an
/// export seals its records, then reads it back to its end with the import's
/// reader. A fuzzer cannot forge the authentication tags, so without this it
/// would never reach the record parser behind them.
#[cfg(fuzzing)]
pub fn fuzz_read_sealed(plaintext: &[u8]) {
    let _ = read_sealed(plaintext);
}

#[cfg(fuzzing)]
fn read_sealed(plaintext: &[u8]) -> Result<(), ExportError> {
    let key = [7u8; KEY_LEN];
    let prefix = [2u8; NONCE_PREFIX_LEN];
    let params = KdfParams::default();
    let header = encode_header(&params, &[1u8; SALT_LEN], &prefix);
    let mut body = Vec::new();
    {
        let mut writer = SegmentWriter::new(&mut body, &key, &prefix, header);
        writer.push(plaintext)?;
        writer.seal_last()?;
    }
    let limits = SectionLimits {
        library: 1 << 20,
        picture: 1 << 20,
        addon: 1 << 20,
    };
    let source: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(body));
    BackupReader::begin(source, header, &key, limits, params, None)?.read_to_end()
}

#[cfg(test)]
#[path = "backup_v4_tests.rs"]
mod tests;
