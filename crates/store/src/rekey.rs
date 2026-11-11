//! Renewing the data key of a Library that moved from version 1 into the
//! vault (secscan S-1a563619ce84).
//!
//! # Why
//!
//! A version 1 Library's data key is derived from the passphrase and the
//! file's salt, and `move_into_vault` keeps that key (it only wraps it), which
//! is what kept every picture and download record valid. But it also means the
//! OLD passphrase plus any surviving version 1 header still derives the key of
//! the current Library, its pictures and its add-on pages. A re-key draws a
//! fresh random key and re-encrypts all of it, so that pair opens nothing that
//! is current.
//!
//! # How: build aside, then swap
//!
//! 1. A journal is written BEFORE anything else (`<library>.rekey-journal`):
//!    the phase, the three folder names this re-key uses, and check values of
//!    the old and new keys (a hash, never a key).
//! 2. Everything is rebuilt under the new key in a staging folder beside the
//!    Library: every picture, every add-on file, and the Library file itself
//!    (download records re-signed). Nothing live is touched.
//! 3. The staged copy is reopened and checked.
//! 4. The journal moves to `swapping`; `archive` and `addons` are set aside
//!    and the staged ones moved in; the Library file is renamed in LAST. That
//!    rename is the commit point.
//! 5. The old folders, the staging folder and the journal are removed, and
//!    the writer's crash leftovers made under the old key are retired.
//!
//! A crash at any point leaves a journal, and `recover_rekey` (run before the
//! Library is opened, after an import's own recovery) ends with the Library
//! wholly under the old key or wholly under the new one: see the table on
//! `recover_rekey`.
//!
//! # What is carried, and what is not
//!
//! - A picture or add-on file that opens under the old key is re-encrypted.
//! - One that does NOT open (authentication or format failure: it is damaged)
//!   is left out, never copied: copied old ciphertext would still read with
//!   the old key. Its record then reads as a missing picture or page, as a
//!   missing one does today. An add-on index that does not open becomes an
//!   index that still does not open (`{}` under the new key), so the add-on's
//!   own recovery still deletes nothing.
//! - Any I/O error stops the re-key with the Library untouched: a file that
//!   could not be read is not a damaged file.
//! - Anything this build does not recognise is carried byte for byte: data
//!   this build cannot re-encrypt is kept rather than lost. Recognised means
//!   a blob id under `archive/` (the folder is the Library's alone; its own
//!   sweep already removes any such file no record names), and in an add-on's
//!   folder only the names the add-on store writes (its index and page
//!   versions). Any other name, and anything else under `addons/`, is carried.
//! - The writer's temporary files (`.tmp-...`) are not carried: they are
//!   leftovers of interrupted writes.
//! - A download record whose seal does not verify is kept as it is, so it
//!   still fails; the others are re-sealed under the new key.
//!
//! # What it cannot reach
//!
//! Copies of the profile made before the re-key (an OS backup, a sync), data
//! the disk still holds after a delete, and an old vault copy with its old
//! passphrase (which still unwraps the Library: the vault master never
//! changes).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::blob::BlobStore;
use crate::model::RekeyTry;
use crate::{addon, crypto, provenance, Envelope, Store, StoreError};

const CHECK_LABEL: &[u8] = b"patanyx-store/rekey-check/v1";
const STAGING_PREFIX: &str = "library-rekey-";
const OLD_ARCHIVE_PREFIX: &str = "archive.prerekey-";
const OLD_ADDONS_PREFIX: &str = "addons.prerekey-";
const MAX_JOURNAL_BYTES: u64 = 4096;
/// Attempts of one build that may start and never finish (a crash) before
/// that build stops trying at unlock; the next build tries again.
pub const MAX_UNFINISHED_ATTEMPTS: u8 = 3;
/// Directory renames are retried this many times, 100 ms apart: on Windows a
/// scanner that has just opened a new file can hold its folder briefly.
const RENAME_TRIES: u32 = 5;

/// A key's check value: `SHA-256(label || 0 || key)`, hex. Recognises a key
/// without revealing it.
pub(crate) fn check_value(key: &[u8; crypto::KEY_LEN]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CHECK_LABEL);
    hasher.update([0x00]);
    hasher.update(key);
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// What a finished re-key did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RekeyReport {
    /// Pictures re-encrypted under the new key.
    pub pictures: usize,
    /// Pictures that did not open under the old key (damaged): left out.
    pub pictures_left_out: usize,
    /// Add-on files (indexes and page versions) re-encrypted.
    pub addon_files: usize,
    /// Add-on files that did not open: left out (an index becomes `{}`).
    pub addon_files_left_out: usize,
    /// Entries this build does not recognise, carried byte for byte.
    pub carried_as_is: usize,
    /// Leftovers under the old key that could not be confirmed gone; the
    /// next unlock retries (`Store::retire_old_key_leftovers`).
    pub leftovers_retained: bool,
}

/// Why a re-key did not finish.
#[derive(Debug)]
pub enum RekeyError {
    /// Nothing changed: the Library is under the old key, the Store is still
    /// usable, and a later attempt can try again (the app: the first unlock
    /// of each run, and every passphrase change).
    Undone(StoreError),
    /// Neither finished nor undone, or finished on disk but not reopened:
    /// the Store must not be used, and the Library stays shut until
    /// `recover_rekey` resolves it.
    Unfinished(StoreError),
    /// This build has started the re-key `MAX_UNFINISHED_ATTEMPTS` times and
    /// never finished it; it does not try again. The Store is usable.
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Building,
    Swapping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    phase: Phase,
    staging: String,
    old_archive: String,
    old_addons: String,
    old_check: String,
    new_check: String,
}

impl Journal {
    /// Every name is one this module makes: a fixed prefix and 16 lowercase
    /// hex. Anything else is refused before a path is built from it.
    fn names_ok(&self) -> bool {
        let named = |name: &str, prefix: &str| {
            name.strip_prefix(prefix).is_some_and(|hex| {
                hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        };
        let check = |c: &str| c.len() == 64 && c.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        named(&self.staging, STAGING_PREFIX)
            && named(&self.old_archive, OLD_ARCHIVE_PREFIX)
            && named(&self.old_addons, OLD_ADDONS_PREFIX)
            && check(&self.old_check)
            && check(&self.new_check)
    }
}

fn random_hex16() -> String {
    let bytes: [u8; 8] = crypto::random_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn library_dir(store_path: &Path) -> PathBuf {
    match store_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn file_name(store_path: &Path) -> std::ffi::OsString {
    store_path.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| "store.rbs".into())
}

/// `<library>.rekey-journal`.
pub fn journal_path(store_path: &Path) -> PathBuf {
    let mut name = file_name(store_path);
    name.push(".rekey-journal");
    library_dir(store_path).join(name)
}

/// Whether a re-key journal is present (`recover_rekey` must run first).
pub fn rekey_journal_exists(store_path: &Path) -> bool {
    // Anything but a clean "not found" counts as present, so a journal that
    // cannot even be looked at keeps the Library shut rather than ignored.
    match fs::symlink_metadata(journal_path(store_path)) {
        Ok(_) => true,
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

/// Whether the Library file is there: `Ok(false)` only for a clean "not
/// found"; any other error is an error, never taken for "absent".
fn library_present(store_path: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(store_path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(StoreError::Io(e)),
    }
}

/// The longest file a re-key reads into memory: nothing this Library writes
/// is larger (`MAX_ARCHIVE_BYTES` for all pictures together, the add-on quota
/// for all of one add-on's files). Larger is damage, not data.
const MAX_BLOB_PLAINTEXT: usize = crate::MAX_ARCHIVE_BYTES as usize;

fn write_journal(store_path: &Path, journal: &Journal) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(journal).map_err(|e| StoreError::Crypto(format!("journal: {e}")))?;
    crate::atomic_replace(&journal_path(store_path), &bytes, crate::Fault::None)?;
    crate::sync_parent(store_path, crate::DirSync::Strict)
}

/// `Ok(None)`: no journal. `Err`: a journal that cannot be trusted (a link,
/// too large, unreadable, or naming anything this module would not make).
fn read_journal(store_path: &Path) -> Result<Option<Journal>, StoreError> {
    let path = journal_path(store_path);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(StoreError::Io(e)),
    };
    if !meta.file_type().is_file() || meta.len() > MAX_JOURNAL_BYTES {
        return Err(StoreError::BadFormat("the re-key journal is not a small regular file".into()));
    }
    let bytes = fs::read(&path)?;
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|e| StoreError::BadFormat(format!("the re-key journal does not parse: {e}")))?;
    if !journal.names_ok() {
        return Err(StoreError::BadFormat("the re-key journal names something it should not".into()));
    }
    Ok(Some(journal))
}

fn remove_journal(store_path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(journal_path(store_path)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(StoreError::Io(e)),
        _ => {}
    }
    crate::sync_parent(store_path, crate::DirSync::BestEffort)
}

/// A real directory (never a link) at `path`, or nothing there.
fn real_dir_or_absent(path: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => Ok(true),
        Ok(_) => Err(StoreError::BadFormat(format!("{} is not a real folder", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(StoreError::Io(e)),
    }
}

fn make_dir(path: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn remove_tree(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => fs::remove_dir_all(path).map_err(StoreError::Io),
        Ok(_) => fs::remove_file(path).map_err(StoreError::Io),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io(e)),
    }
}

/// Flushes a directory's entries (unix; a no-op where there is no such call).
fn sync_dir(path: &Path) -> Result<(), StoreError> {
    crate::sync_parent(&path.join("x"), crate::DirSync::Strict)
}

fn rename_retrying(from: &Path, to: &Path) -> Result<(), StoreError> {
    #[cfg(test)]
    crash::rename_fault(from)?;
    let mut tries = 0;
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if tries + 1 < RENAME_TRIES && e.kind() != io::ErrorKind::NotFound => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(StoreError::Io(e)),
        }
    }
}

/// Copies a file or a folder, byte for byte, never following a link.
fn copy_as_is(from: &Path, to: &Path) -> Result<(), StoreError> {
    let meta = fs::symlink_metadata(from)?;
    if meta.file_type().is_dir() {
        make_dir(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_as_is(&entry.path(), &to.join(entry.file_name()))?;
        }
        // Its own entries flushed, at every depth, before the original goes.
        sync_dir(to)
    } else if meta.file_type().is_file() {
        // Streamed, never read whole: an unrecognised file can be any size.
        let mut source = fs::File::open(from)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(to)?;
        io::copy(&mut source, &mut file)?;
        file.sync_all()?;
        Ok(())
    } else {
        // A link or a special file cannot be carried as it is, and dropping
        // it would lose it silently: the re-key refuses instead, and the
        // Library stays as it was.
        Err(StoreError::BadFormat(format!(
            "{} is a link or a special file; the re-key does not carry it",
            from.display()
        )))
    }
}

/// A blob read failure that means the file is DAMAGED (does not authenticate
/// or is not a blob), as opposed to one that could not be read at all.
fn damaged(error: &StoreError) -> bool {
    matches!(error, StoreError::AuthFailed | StoreError::BadFormat(_))
}

/// Exactly a writer's temporary name: `.tmp-` and 32 lowercase hex.
fn is_writer_temp(name: &str) -> bool {
    name.strip_prefix(".tmp-").is_some_and(|hex| {
        hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[derive(Default)]
struct Carried {
    blobs: usize,
    left_out: usize,
    as_is: usize,
}

/// Re-encrypts one folder of blobs from `old` to `new` (same ids). `addon_folder`
/// marks an add-on folder: only the add-on store's own names are its blobs,
/// and a damaged index becomes `{}`.
fn carry_blobs(
    from_dir: &Path,
    to_dir: &Path,
    old: &BlobStore,
    new: &BlobStore,
    addon_folder: bool,
    carried: &mut Carried,
    written: &mut Vec<(PathBuf, String)>,
) -> Result<(), StoreError> {
    for entry in fs::read_dir(from_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().map(str::to_string) else {
            copy_as_is(&entry.path(), &to_dir.join(entry.file_name()))?;
            carried.as_is += 1;
            continue;
        };
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(StoreError::BadFormat(format!("{name} is a link; the re-key does not carry it")));
        }
        // Only a REGULAR file with exactly the writer's temporary name is an
        // interrupted write; a folder or anything else named like one is
        // someone's data and is carried.
        if kind.is_file() && is_writer_temp(&name) {
            continue;
        }
        // A name that is only SAFE as a blob id is not enough in an add-on's
        // folder (review R-001): a file there that the add-on store did not
        // name is someone's data, not a damaged page, and is carried.
        let ours = if addon_folder {
            addon::is_namespace_file(&name)
        } else {
            crate::blob::is_valid_id(&name)
        };
        if !kind.is_file() || !ours {
            copy_as_is(&entry.path(), &to_dir.join(&name))?;
            carried.as_is += 1;
            continue;
        }
        #[cfg(test)]
        crash::read_fault(&name)?;
        // A blob in a format a newer build writes is not damage: this build
        // can neither re-encrypt it nor drop it, so the re-key refuses and
        // the Library stays as it was.
        if crate::blob::is_other_version(&entry.path())? {
            return Err(StoreError::BadFormat(format!(
                "{name} is in a blob format from a newer build; the re-key does not rewrite it"
            )));
        }
        match old.get_bounded(&name, MAX_BLOB_PLAINTEXT) {
            Ok(plaintext) => {
                new.put(&name, &plaintext)?;
                written.push((to_dir.to_path_buf(), name));
                carried.blobs += 1;
            }
            Err(error) if damaged(&error) => {
                carried.left_out += 1;
                if addon_folder && name == "index" {
                    new.put(&name, b"{}")?;
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Store {
    /// Whether this Library still uses the data key its version 1 file
    /// derived from a passphrase: a version 3 Library that moved from
    /// version 1 and has not been re-keyed.
    pub fn needs_rekey(&self) -> bool {
        matches!(self.envelope, Envelope::V3 { .. }) && self.data.v1_salt.is_some() && !self.data.rekeyed
    }

    /// Renews the data key (see the module). `library_key` is the vault's
    /// Library key; `build` names this build, for the attempt count. The
    /// caller must make sure nothing else holds a key derived from this
    /// Library's data key (no add-on worker, no export), and must have run
    /// `recover_rekey` first. Does nothing when `needs_rekey` is false.
    pub fn rekey(
        &mut self,
        library_key: &[u8; crypto::KEY_LEN],
        build: &str,
    ) -> Result<RekeyReport, RekeyError> {
        if !self.needs_rekey() {
            return Ok(RekeyReport::default());
        }
        if rekey_journal_exists(&self.path) {
            return Err(RekeyError::Unfinished(StoreError::BadFormat(
                "a re-key journal is present; recover first".into(),
            )));
        }
        let dir = library_dir(&self.path);
        let archive = dir.join("archive");
        let addons = addon::addons_dir(&self.path);
        for folder in [&archive, &addons] {
            match real_dir_or_absent(folder) {
                Ok(true) => {}
                Ok(false) => make_dir(folder).map_err(RekeyError::Undone)?,
                Err(error) => return Err(RekeyError::Undone(error)),
            }
        }

        // Count the attempt BEFORE starting, so one that crashes is counted.
        let previous = self.data.rekey_try.clone();
        let started = match &previous {
            Some(t) if t.build == build => t.started,
            _ => 0,
        };
        if started >= MAX_UNFINISHED_ATTEMPTS {
            return Err(RekeyError::Paused);
        }
        self.data.rekey_try = Some(RekeyTry { build: build.to_string(), started: started + 1 });
        if let Err(error) = self.save() {
            self.data.rekey_try = previous;
            return Err(RekeyError::Undone(error));
        }

        let new_key = Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>());
        let journal = Journal {
            phase: Phase::Building,
            staging: format!("{STAGING_PREFIX}{}", random_hex16()),
            old_archive: format!("{OLD_ARCHIVE_PREFIX}{}", random_hex16()),
            old_addons: format!("{OLD_ADDONS_PREFIX}{}", random_hex16()),
            old_check: check_value(&self.key),
            new_check: check_value(&new_key),
        };
        let staging = dir.join(&journal.staging);

        // ---- build aside: nothing live is touched until the swap ----
        let built = write_journal(&self.path, &journal)
            .and_then(|()| self.build_staged(&staging, &new_key, library_key));
        let report = match built {
            Ok(report) => report,
            Err(error) => {
                let _ = remove_tree(&staging);
                let _ = remove_journal(&self.path);
                // A journal that would not go means recovery is still owed:
                // not "undone", whatever the build's own error was.
                if rekey_journal_exists(&self.path) {
                    return Err(RekeyError::Unfinished(error));
                }
                self.give_back_attempt(previous);
                return Err(RekeyError::Undone(error));
            }
        };
        #[cfg(test)]
        crash::point(crash::AFTER_BUILD);

        // ---- swap: the Library file last ----
        let swapping = Journal { phase: Phase::Swapping, ..journal.clone() };
        if let Err(error) = write_journal(&self.path, &swapping) {
            let _ = remove_tree(&staging);
            let _ = remove_journal(&self.path);
            if rekey_journal_exists(&self.path) {
                return Err(RekeyError::Unfinished(error));
            }
            self.give_back_attempt(previous);
            return Err(RekeyError::Undone(error));
        }
        if let Err(error) = swap(&self.path, &swapping) {
            // Not committed: put the old folders back.
            return match undo(&self.path, &swapping) {
                Ok(()) => {
                    self.give_back_attempt(previous);
                    Err(RekeyError::Undone(error))
                }
                Err(_) => Err(RekeyError::Unfinished(error)),
            };
        }
        #[cfg(test)]
        crash::point(crash::AFTER_COMMIT);

        // ---- committed: reopen under the new key, then clean up ----
        let reopened = match Store::open(&self.path, None, library_key) {
            Ok(store) if check_value(&store.key) == swapping.new_check => store,
            Ok(_) => {
                return Err(RekeyError::Unfinished(StoreError::BadFormat(
                    "the re-keyed Library did not reopen under its new key".into(),
                )))
            }
            Err(error) => return Err(RekeyError::Unfinished(error)),
        };
        *self = reopened;
        // The old folders still hold old-key copies until they are gone; a
        // failure here (a scanner holding a file) is not ignored: the
        // folders join the old-key leftovers, retried at every unlock
        // (`retire_old_key_leftovers`), and the report says so.
        let _ = finish_cleanup(&self.path, &swapping);
        // Retirement sweeps the re-key's own folders too, so the report says
        // what is left once both have run.
        let mut report = report;
        report.leftovers_retained = self.retire_old_key_leftovers(library_key).is_err();
        Ok(report)
    }

    /// An attempt that ended cleanly does not count against the build.
    fn give_back_attempt(&mut self, previous: Option<RekeyTry>) {
        self.data.rekey_try = previous;
        let _ = self.save();
    }

    fn build_staged(
        &self,
        staging: &Path,
        new_key: &Zeroizing<[u8; crypto::KEY_LEN]>,
        library_key: &[u8; crypto::KEY_LEN],
    ) -> Result<RekeyReport, StoreError> {
        let dir = library_dir(&self.path);
        make_dir(staging)?;
        let staged_archive = staging.join("archive");
        let staged_addons = staging.join("addons");
        make_dir(&staged_archive)?;
        make_dir(&staged_addons)?;
        let mut written: Vec<(PathBuf, String)> = Vec::new();

        // Pictures.
        let mut pictures = Carried::default();
        let old = BlobStore::open(&dir.join("archive"), &self.key)?;
        let new = BlobStore::open(&staged_archive, new_key)?;
        carry_blobs(&dir.join("archive"), &staged_archive, &old, &new, false, &mut pictures, &mut written)?;

        // Add-ons: each namespace under its own key; anything else as is.
        let mut addon_files = Carried::default();
        let mut as_is = pictures.as_is;
        let addons = addon::addons_dir(&self.path);
        for entry in fs::read_dir(&addons)? {
            let entry = entry?;
            let name = entry.file_name();
            let id = name.to_str().filter(|id| addon::addon_id_ok(id)).map(str::to_string);
            match id {
                Some(id) if entry.file_type()?.is_dir() => {
                    let from = addons.join(&id);
                    let to = staged_addons.join(&id);
                    let old = BlobStore::open(&from, &addon::namespace_key(&self.key, &id))?;
                    let new = BlobStore::open(&to, &addon::namespace_key(new_key, &id))?;
                    carry_blobs(&from, &to, &old, &new, true, &mut addon_files, &mut written)?;
                }
                _ => {
                    copy_as_is(&entry.path(), &staged_addons.join(&name))?;
                    as_is += 1;
                }
            }
        }
        as_is += addon_files.as_is;

        // The Library file: the same contents, download seals renewed.
        let mut data = self.data.clone();
        data.rekeyed = true;
        data.rekey_try = None;
        data.k1_leftovers = Some(check_value(&self.key));
        let new_provenance = provenance::mac_key(new_key);
        for record in &mut data.downloads {
            if provenance::verify(&self.provenance_key, record) {
                record.hmac = provenance::record_mac(
                    &new_provenance,
                    &record.id,
                    &record.url,
                    &record.filename,
                    record.byte_len,
                    &record.sha256,
                    record.recorded_at,
                );
            }
        }
        let staged_path = staging.join(file_name(&self.path));
        let envelope = crate::wrap_for_vault(new_key, library_key)?;
        let staged = Store::assembled(&staged_path, Zeroizing::new(**new_key), envelope, data);
        staged.save()?;

        // Flush, then check the staged copy before anything live moves.
        sync_dir(&staged_archive)?;
        for entry in fs::read_dir(&staged_addons)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                sync_dir(&entry.path())?;
            }
        }
        sync_dir(&staged_addons)?;
        sync_dir(staging)?;
        let reopened = Store::open(&staged_path, None, library_key)?;
        if check_value(&reopened.key) != check_value(new_key) || reopened.data != staged.data {
            return Err(StoreError::BadFormat("the staged Library did not read back".into()));
        }
        for (folder, id) in &written {
            let key = if folder == &staged_archive {
                Zeroizing::new(**new_key)
            } else {
                let addon_id = folder.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                addon::namespace_key(new_key, addon_id)
            };
            BlobStore::open(folder, &key)?.get(id)?;
        }

        Ok(RekeyReport {
            pictures: pictures.blobs,
            pictures_left_out: pictures.left_out,
            addon_files: addon_files.blobs,
            addon_files_left_out: addon_files.left_out,
            carried_as_is: as_is,
            leftovers_retained: false,
        })
    }

    /// Retires the writer's crash leftovers made under a data key a re-key
    /// has retired (and the version 1 leftovers, as a passphrase change
    /// does). Clears the pending mark once both succeed; until then every
    /// unlock retries. Does nothing when nothing is pending.
    pub fn retire_old_key_leftovers(
        &mut self,
        library_key: &[u8; crypto::KEY_LEN],
    ) -> Result<(), StoreError> {
        let Some(old_check) = self.data.k1_leftovers.clone() else {
            // No mark, but a finished re-key's folders can outlive one: an
            // import replaces the Library and its mark with it (review
            // F-002). So they are swept at every unlock regardless; exact
            // names only, and never while a journal says they may be needed.
            if rekey_journal_exists(&self.path) {
                return Ok(());
            }
            return retire_rekey_folders(&self.path, false);
        };
        let v3 = crate::retire::retire_v3_leftovers(&self.path, library_key, &old_check, || {
            crate::retire::flush_dir(&self.path)
        });
        let v1 = self.retire_v1_leftovers();
        let folders = retire_rekey_folders(&self.path, true);
        v3.and(v1).and(folders)?;
        self.data.k1_leftovers = None;
        self.save()
    }
}

/// Moves the staged folders in and the old ones aside, then the Library file
/// in (the commit point). Each folder: live -> aside, staged -> live.
fn swap(store_path: &Path, journal: &Journal) -> Result<(), StoreError> {
    let dir = library_dir(store_path);
    let staging = dir.join(&journal.staging);
    for (live, aside) in [("archive", &journal.old_archive), ("addons", &journal.old_addons)] {
        rename_retrying(&dir.join(live), &dir.join(aside))?;
        #[cfg(test)]
        crash::point(crash::FOLDER_ASIDE);
        rename_retrying(&staging.join(live), &dir.join(live))?;
        #[cfg(test)]
        crash::point(crash::FOLDER_IN);
    }
    sync_dir(&dir)?;
    rename_retrying(&staging.join(file_name(store_path)), store_path)?;
    let _ = sync_dir(&dir);
    Ok(())
}

/// After the commit: the old folders, the staging folder and the journal go.
/// The journal goes even if a folder does not: the commit is done and nothing
/// needs recovering, and a folder left behind is retired at the next unlock
/// as an old-key leftover (`retire_rekey_folders`).
fn finish_cleanup(store_path: &Path, journal: &Journal) -> Result<(), StoreError> {
    let dir = library_dir(store_path);
    let remove_folders = || {
        remove_tree(&dir.join(&journal.old_archive))
            .and(remove_tree(&dir.join(&journal.old_addons)))
            .and(remove_tree(&dir.join(&journal.staging)))
    };
    // A test can make the folders stay, as a held file would.
    #[cfg(test)]
    let folders = crash::remove_fault().and_then(|()| remove_folders());
    #[cfg(not(test))]
    let folders = remove_folders();
    let _ = sync_dir(&dir);
    remove_journal(store_path)?;
    folders
}

/// Removes every folder a finished re-key left behind (names this module
/// makes), which hold old-key copies. Only ever run with no journal present:
/// while a journal exists such folders may still be needed to recover.
fn retire_rekey_folders(store_path: &Path, flush_always: bool) -> Result<(), StoreError> {
    if rekey_journal_exists(store_path) {
        return Err(StoreError::BadFormat("a re-key journal is present".into()));
    }
    let dir = library_dir(store_path);
    let mut first_error = None;
    let mut removed = false;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        // Exactly a name this module makes (a prefix and 16 lowercase hex),
        // and a real folder: nothing else is ever removed here.
        let ours = [STAGING_PREFIX, OLD_ARCHIVE_PREFIX, OLD_ADDONS_PREFIX].iter().any(|prefix| {
            name.strip_prefix(prefix).is_some_and(|hex| {
                hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        });
        if ours && entry.file_type()?.is_dir() {
            match fs::remove_dir_all(entry.path()) {
                Ok(()) => removed = true,
                Err(error) => {
                    first_error.get_or_insert(StoreError::Io(error));
                }
            }
        }
    }
    // The removals reach the disk before the caller clears its mark: a power
    // cut must not bring back a folder the mark no longer points to. With no
    // mark to clear (the sweep at every unlock) only after a removal.
    if removed || flush_always {
        if let Err(error) = sync_dir(&dir) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Before the commit: every folder back where it was, then the staging
/// folder and the journal go. Per folder: if the staged copy was already
/// moved in, it goes back to staging; then the set-aside one comes back.
fn undo(store_path: &Path, journal: &Journal) -> Result<(), StoreError> {
    let dir = library_dir(store_path);
    let staging = dir.join(&journal.staging);
    for (live, aside) in [("archive", &journal.old_archive), ("addons", &journal.old_addons)] {
        let live_path = dir.join(live);
        let aside_path = dir.join(aside);
        let staged_path = staging.join(live);
        let aside_there = real_dir_or_absent(&aside_path)?;
        if !aside_there {
            continue; // never set aside: the live folder is the old one
        }
        if !real_dir_or_absent(&staged_path)? && real_dir_or_absent(&live_path)? {
            // The staged folder was moved in: send it back.
            if !real_dir_or_absent(&staging)? {
                make_dir(&staging)?;
            }
            rename_retrying(&live_path, &staged_path)?;
        }
        if real_dir_or_absent(&live_path)? {
            return Err(StoreError::BadFormat(format!("{live} and its set-aside copy both exist")));
        }
        rename_retrying(&aside_path, &live_path)?;
    }
    let _ = sync_dir(&dir);
    remove_tree(&staging)?;
    remove_journal(store_path)
}

/// Before a commit, the build is just discarded; after an import replaced the
/// Library meanwhile, only what this re-key made is removed, nothing live.
fn discard(store_path: &Path, journal: &Journal) -> Result<(), StoreError> {
    let dir = library_dir(store_path);
    remove_tree(&dir.join(&journal.staging))?;
    remove_tree(&dir.join(&journal.old_archive))?;
    remove_tree(&dir.join(&journal.old_addons))?;
    remove_journal(store_path)
}

/// Resolves a re-key that did not finish. Run before the Library is opened,
/// AFTER an import's own recovery (an import can replace the Library while a
/// re-key journal is present).
///
/// | journal / Library file                         | action                              |
/// |------------------------------------------------|-------------------------------------|
/// | none                                           | nothing                             |
/// | unreadable, a link, too large, bad names       | `Err`: keep the Library shut        |
/// | `building`                                     | discard the build                   |
/// | `swapping`, the file's key is the new one      | finish: move in what is left, clean |
/// | `swapping`, the file's key is the old one      | undo, folder by folder              |
/// | `swapping`, any other key, or no Library file  | discard: nothing live is touched    |
/// | `swapping`, the file does not open             | `Err`: keep the Library shut        |
pub fn recover_rekey(
    store_path: &Path,
    library_key: &[u8; crypto::KEY_LEN],
) -> Result<(), StoreError> {
    let Some(journal) = read_journal(store_path)? else {
        return Ok(());
    };
    match journal.phase {
        Phase::Building => discard(store_path, &journal),
        Phase::Swapping => {
            if !library_present(store_path)? {
                return discard(store_path, &journal);
            }
            let store = Store::open(store_path, None, library_key)?;
            let check = check_value(&store.key);
            drop(store);
            if check == journal.new_check {
                finish(store_path, &journal)
            } else if check == journal.old_check {
                undo(store_path, &journal)
            } else {
                discard(store_path, &journal)
            }
        }
    }
}

/// The commit happened: move in any staged folder not yet moved, then clean.
fn finish(store_path: &Path, journal: &Journal) -> Result<(), StoreError> {
    let dir = library_dir(store_path);
    let staging = dir.join(&journal.staging);
    for (live, aside) in [("archive", &journal.old_archive), ("addons", &journal.old_addons)] {
        let staged_path = staging.join(live);
        if !real_dir_or_absent(&staged_path)? {
            continue; // already moved in
        }
        let live_path = dir.join(live);
        let aside_path = dir.join(aside);
        if real_dir_or_absent(&live_path)? {
            if real_dir_or_absent(&aside_path)? {
                return Err(StoreError::BadFormat(format!("{live}, its staged and its set-aside copy all exist")));
            }
            rename_retrying(&live_path, &aside_path)?;
        }
        rename_retrying(&staged_path, &live_path)?;
    }
    let _ = sync_dir(&dir);
    match finish_cleanup(store_path, journal) {
        // The commit is complete and the journal is gone: folders that would
        // not go are old-key leftovers, retired at this unlock and the next
        // (`retire_old_key_leftovers`), not a reason to keep the Library shut.
        Err(_) if !rekey_journal_exists(store_path) => Ok(()),
        other => other,
    }
}

/// Test-only crash points and faults, so every step can be interrupted.
#[cfg(test)]
pub(crate) mod crash {
    use std::cell::{Cell, RefCell};

    pub const AFTER_BUILD: u8 = 1;
    pub const FOLDER_ASIDE: u8 = 2;
    pub const FOLDER_IN: u8 = 3;
    pub const AFTER_COMMIT: u8 = 4;

    thread_local! {
        /// (point, how many times to pass it first)
        static CRASH_AT: Cell<Option<(u8, u8)>> = const { Cell::new(None) };
        static FAIL_READ: RefCell<Option<String>> = const { RefCell::new(None) };
        static FAIL_RENAME: RefCell<Option<String>> = const { RefCell::new(None) };
        static FAIL_REMOVE: Cell<bool> = const { Cell::new(false) };
    }
    /// Makes the post-commit cleanup fail once, as a held file would.
    pub fn fail_cleanup_once() {
        FAIL_REMOVE.with(|f| f.set(true));
    }
    pub(crate) fn remove_fault() -> Result<(), crate::StoreError> {
        FAIL_REMOVE.with(|f| {
            if f.replace(false) {
                return Err(crate::StoreError::Io(std::io::Error::other("injected cleanup failure")));
            }
            Ok(())
        })
    }

    /// The panic payload a simulated crash raises.
    pub struct Crashed;

    pub fn crash_at(point: u8, pass: u8) {
        CRASH_AT.with(|c| c.set(Some((point, pass))));
    }
    pub fn clear() {
        FAIL_REMOVE.with(|f| f.set(false));
        CRASH_AT.with(|c| c.set(None));
        FAIL_READ.with(|f| *f.borrow_mut() = None);
        FAIL_RENAME.with(|f| *f.borrow_mut() = None);
    }
    pub fn point(at: u8) {
        CRASH_AT.with(|c| {
            if let Some((point, pass)) = c.get() {
                if point == at {
                    if pass == 0 {
                        c.set(None);
                        std::panic::panic_any(Crashed);
                    }
                    c.set(Some((point, pass - 1)));
                }
            }
        });
    }
    /// Makes reading the blob named `id` fail with an I/O error.
    pub fn fail_read_of(id: &str) {
        FAIL_READ.with(|f| *f.borrow_mut() = Some(id.to_string()));
    }
    pub(crate) fn read_fault(id: &str) -> Result<(), crate::StoreError> {
        FAIL_READ.with(|f| {
            if f.borrow().as_deref() == Some(id) {
                return Err(crate::StoreError::Io(std::io::Error::other("injected read failure")));
            }
            Ok(())
        })
    }
    /// Makes renaming anything whose name ends with `suffix` fail.
    pub fn fail_rename_of(suffix: &str) {
        FAIL_RENAME.with(|f| *f.borrow_mut() = Some(suffix.to_string()));
    }
    pub(crate) fn rename_fault(from: &std::path::Path) -> Result<(), crate::StoreError> {
        FAIL_RENAME.with(|f| {
            if let Some(suffix) = f.borrow().as_deref() {
                if from.to_string_lossy().ends_with(suffix) {
                    return Err(crate::StoreError::Io(std::io::Error::other("injected rename failure")));
                }
            }
            Ok(())
        })
    }
}
