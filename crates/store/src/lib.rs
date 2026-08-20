#![forbid(unsafe_code)]
//! patanyx-store — encrypted session store for bookmarks and download
//! provenance.
//!
//! # Why this is a separate store from the vault — do not merge them
//!
//! The vault holds passwords and auto-locks after 300 seconds of
//! inactivity. Bookmarks that vanish every five minutes would be useless,
//! so sensitivity is tiered deliberately:
//!
//! - **Passwords** (vault): locked aggressively; the key is dropped at
//!   auto-lock.
//! - **Bookmarks and provenance** (this store): encrypted at rest with a
//!   key derived from the same passphrase, but that key is held for the
//!   whole session. There is intentionally NO lock/timeout API on `Store` —
//!   the session owner keeps it open, and a vault auto-lock event must not
//!   touch it. "Bookmarks survive a vault auto-lock; passwords do not" is
//!   realized by this separation, not by anything the store does at
//!   runtime.
//!
//! The two stores still cannot share a key: the passphrase is pre-hashed
//! with a store-specific domain label before Argon2id (see `crypto.rs`), so
//! the keys are unrelated even for the same passphrase, and the files have
//! distinct magic values so they can never be confused with each other.
//!
//! # What download provenance proves — and what it does not
//!
//! Each record carries an HMAC-SHA256 under a key derived from the store's
//! key. That makes records **tamper-evident to the owner and nothing
//! more**: it proves the record (url, filename, length, content hash,
//! timestamp) has not been altered since it was recorded. It proves NOTHING
//! to a third party — anyone holding the passphrase can forge records, and
//! the owner cannot demonstrate a record's authenticity without revealing
//! the key. An earlier sketch said "signed by your identity key"; that was
//! wrong, because the identity key is X25519, a Diffie-Hellman key, which
//! cannot sign. Real third-party-verifiable provenance would need an
//! Ed25519 identity; that is a separate, explicitly deferred decision.
//!
//! (The whole file is additionally AEAD-authenticated, so on-disk tampering
//! already fails at unlock. The per-record HMAC matters when a record
//! leaves the store — displayed, exported, compared later.)
//!
//! # File format v1 (binary, little-endian integers)
//!
//! ```text
//! offset  size  field
//! 0       7     magic = b"RBSTORE"   (distinct from the vault's b"RBVAULT")
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
//! passphrase does. Same shape as the vault, same atomic-write and 0600
//! rules.

mod blob;
mod crypto;
mod error;
mod format;
mod model;
pub mod provenance;

pub use error::StoreError;
pub use model::{
    normalize_folder_name, ArchiveRecord, Bookmark, DivergenceLevel, DivergenceOverride,
    DownloadRecord, RecordedDigest, Shelf, ShelfTab, StoreData,
};
// Re-exported so callers of the bookmark API don't need to name the
// integrity crate in their own manifests.
pub use patanyx_integrity::{ContentDigest, Verdict};

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::crypto::KdfParams;

/// An open bookmark/provenance store. The key lives as long as this value
/// does — that is the session-lifetime guarantee documented above.
pub struct Store {
    path: PathBuf,
    key: Zeroizing<[u8; crypto::KEY_LEN]>,
    provenance_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    params: KdfParams,
    salt: [u8; crypto::SALT_LEN],
    data: StoreData,
}

impl std::fmt::Debug for Store {
    /// Hand-written, never derived. This struct holds two live keys, and a
    /// derived Debug would print them into any log line, panic message, or
    /// test failure that happened to format the store.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("bookmarks", &self.data.bookmarks.len())
            .field("downloads", &self.data.downloads.len())
            .field("shelves", &self.data.shelves.len())
            .finish_non_exhaustive()
    }
}

/// Application data directory name, and the pre-rename one. Same reasoning as
/// the vault's: the product was renamed, the user's data was not.
pub const DIR_NAME: &str = "patanyx";
pub const LEGACY_DIR_NAME: &str = "rustbrowse";

/// Prefers the current directory name, falling back to the legacy one when
/// that is where the file actually is. Moves nothing.
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

impl Store {
    /// `$XDG_DATA_HOME/patanyx/store.rbs`, falling back to
    /// `$HOME/.local/share/patanyx/store.rbs`, and to the pre-rename
    /// `rustbrowse` directory when a store already lives there.
    #[cfg(unix)]
    pub fn default_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            if !dir.is_empty() {
                return data_dir_in(PathBuf::from(dir), "store.rbs");
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return data_dir_in(
                PathBuf::from(home).join(".local").join("share"),
                "store.rbs",
            );
        }
        // Last resort: a relative path rather than a panic.
        PathBuf::from(".patanyx").join("store.rbs")
    }

    /// `%APPDATA%\patanyx\store.rbs` (roaming per-user config root), with the
    /// same legacy fallback as the unix arm.
    /// `PATANYX_DATA_DIR` takes precedence as the test override hook,
    /// mirroring the vault.
    #[cfg(windows)]
    pub fn default_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("PATANYX_DATA_DIR") {
            if !dir.is_empty() {
                return data_dir_in(PathBuf::from(dir), "store.rbs");
            }
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            if !appdata.is_empty() {
                return data_dir_in(PathBuf::from(appdata), "store.rbs");
            }
        }
        // Last resort: a relative path rather than a panic.
        PathBuf::from(".patanyx").join("store.rbs")
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Create a new store with default Argon2id parameters (m=64 MiB, t=3,
    /// p=1). Fails with `StoreError::AlreadyExists` if `path` exists — this
    /// function never clobbers.
    pub fn create(path: &Path, passphrase: &str) -> Result<Store, StoreError> {
        let KdfParams {
            m_cost,
            t_cost,
            p_cost,
        } = KdfParams::default();
        Self::create_with_params(path, passphrase, m_cost, t_cost, p_cost)
    }

    /// Same as `create` but with explicit KDF parameters; intended for
    /// tests (e.g. m=8192, t=1, p=1) and future parameter upgrades.
    pub fn create_with_params(
        path: &Path,
        passphrase: &str,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Store, StoreError> {
        if path.exists() {
            return Err(StoreError::AlreadyExists(path.to_path_buf()));
        }
        let params = KdfParams {
            m_cost,
            t_cost,
            p_cost,
        };
        let salt: [u8; crypto::SALT_LEN] = crypto::random_bytes();
        let key = crypto::derive_key(passphrase.as_bytes(), &salt, &params)?;
        let provenance_key = provenance::mac_key(&key);
        let store = Store {
            path: path.to_path_buf(),
            key,
            provenance_key,
            params,
            salt,
            data: StoreData::default(),
        };
        store.save()?;
        Ok(store)
    }

    pub fn unlock(path: &Path, passphrase: &str) -> Result<Store, StoreError> {
        let bytes = fs::read(path)?;
        let header = format::decode_header(&bytes)?;
        if bytes.len() < format::HEADER_LEN + 16 {
            return Err(StoreError::BadFormat(
                "file ends after header: no ciphertext/tag".into(),
            ));
        }
        let key = crypto::derive_key(passphrase.as_bytes(), &header.salt, &header.params)?;
        // AAD = the full 60-byte header, binding version, KDF params, salt,
        // and nonce to the ciphertext.
        let aad = &bytes[..format::HEADER_LEN];
        let plaintext = crypto::decrypt(&key, &header.nonce, aad, &bytes[format::HEADER_LEN..])?;
        let data: StoreData = serde_json::from_slice(&plaintext).map_err(|e| {
            StoreError::BadFormat(format!("decrypted payload is not valid json: {e}"))
        })?;
        if data.schema != model::SCHEMA_VERSION {
            return Err(StoreError::BadFormat(format!(
                "unsupported payload schema {}",
                data.schema
            )));
        }
        let provenance_key = provenance::mac_key(&key);
        Ok(Store {
            path: path.to_path_buf(),
            key,
            provenance_key,
            params: header.params,
            salt: header.salt,
            data,
        })
    }

    /// Persist with a fresh nonce, written atomically (tmp file + fsync +
    /// rename) with mode 0600 on unix — same discipline as the vault.
    pub fn save(&self) -> Result<(), StoreError> {
        // A fresh nonce on every save: reusing an XChaCha20-Poly1305 nonce
        // with the same key would break AEAD security.
        let nonce: [u8; crypto::NONCE_LEN] = crypto::random_bytes();
        let header = format::encode_header(&self.params, &self.salt, &nonce);
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.data)
                .map_err(|e| StoreError::Crypto(format!("json encode: {e}")))?,
        );
        let ciphertext = crypto::encrypt(&self.key, &nonce, &header, &plaintext)?;
        let mut out = Vec::with_capacity(header.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        atomic_write(&self.path, &out)
    }

    // ---- shelves ----

    /// All shelves in creation order (`seq` ascending). Callers that need
    /// to mutate browser state afterwards clone entries out first.
    pub fn shelves(&self) -> &[Shelf] {
        &self.data.shelves
    }

    /// Appends a shelf and persists it through the same save path every
    /// other collection uses. On write failure the in-memory change is
    /// rolled back: Ok is the ONLY state in which the shelf exists, which
    /// is what set-aside relies on when it closes tabs after this returns.
    pub fn add_shelf(&mut self, name: String, tabs: Vec<ShelfTab>) -> Result<Shelf, StoreError> {
        let seq_before = self.data.next_shelf_seq;
        let shelf = self.data.plan_new_shelf(name, tabs, now_unix());
        if let Err(err) = self.save() {
            self.data.shelves.pop();
            self.data.next_shelf_seq = seq_before;
            return Err(err);
        }
        Ok(shelf)
    }

    /// Removes a shelf and persists the removal. Ok(false) means no shelf
    /// had that id. On write failure the shelf goes back where it was: a
    /// delete that could not be written did not happen.
    pub fn remove_shelf(&mut self, id: &str) -> Result<bool, StoreError> {
        let (index, shelf) = match self.data.take_shelf(id) {
            Some(pair) => pair,
            None => return Ok(false),
        };
        if let Err(err) = self.save() {
            self.data.shelves.insert(index, shelf);
            return Err(err);
        }
        Ok(true)
    }

    /// Renames a shelf. `Ok(false)` means no shelf had that id.
    ///
    /// Capped at [`SHELF_NAME_MAX_CHARS`] CHARACTERS, not bytes, so a name
    /// in a non-Latin script is never cut through the middle of a letter.
    /// Over-length input is truncated rather than refused: the user has
    /// already typed it, and losing the whole edit to enforce a limit they
    /// were not shown is the worse outcome.
    ///
    /// Rolls back on write failure, like its two neighbours above: Ok is the
    /// only state in which the change exists.
    pub fn rename_shelf(&mut self, id: &str, name: &str) -> Result<bool, StoreError> {
        let capped = cap_chars(name, SHELF_NAME_MAX_CHARS);
        let Some(shelf) = self.data.shelves.iter_mut().find(|s| s.id == id) else {
            return Ok(false);
        };
        let previous = std::mem::replace(&mut shelf.name, capped);
        if let Err(err) = self.save() {
            if let Some(shelf) = self.data.shelves.iter_mut().find(|s| s.id == id) {
                shelf.name = previous;
            }
            return Err(err);
        }
        Ok(true)
    }

    /// Sets a shelf's note. `Ok(false)` means no shelf had that id. Same
    /// character cap, truncation, and rollback rules as [`Self::rename_shelf`].
    pub fn set_shelf_note(&mut self, id: &str, note: &str) -> Result<bool, StoreError> {
        let capped = cap_chars(note, SHELF_NOTE_MAX_CHARS);
        let Some(shelf) = self.data.shelves.iter_mut().find(|s| s.id == id) else {
            return Ok(false);
        };
        let previous = std::mem::replace(&mut shelf.note, capped);
        if let Err(err) = self.save() {
            if let Some(shelf) = self.data.shelves.iter_mut().find(|s| s.id == id) {
                shelf.note = previous;
            }
            return Err(err);
        }
        Ok(true)
    }

    // ---- bookmarks ----

    /// Persist-on-write, same rule as the vault: a failed save is a hard
    /// error so an entry never exists only in memory.
    pub fn add_bookmark(&mut self, url: &str, title: &str) -> Result<String, StoreError> {
        let id = random_id();
        self.data.bookmarks.push(Bookmark {
            id: id.clone(),
            url: url.to_string(),
            title: title.to_string(),
            created_at: now_unix(),
            tags: Vec::new(),
            quick_access: false,
            digest: None,
        });
        self.save()?;
        Ok(id)
    }

    /// Edit url/title. If the URL changes, any recorded digest is dropped:
    /// the digest describes the page at the OLD url, and keeping it would
    /// compare the new page against the old page's content on the next
    /// `check`.
    pub fn update_bookmark(
        &mut self,
        id: &str,
        url: &str,
        title: &str,
    ) -> Result<(), StoreError> {
        let entry = self
            .data
            .bookmarks
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        if entry.url != url {
            entry.url = url.to_string();
            entry.digest = None;
        }
        entry.title = title.to_string();
        self.save()
    }

    /// Replaces a bookmark's tags. `Ok(false)` means no bookmark had that id.
    ///
    /// Normalised here rather than at the edges: trimmed, lowercased, empties
    /// dropped, duplicates removed, and capped. Tags are for grouping, so
    /// "Chem" and "chem" being two different groups would be a bug the user
    /// cannot see and cannot fix.
    ///
    /// ROLLS BACK on write failure. `update_bookmark` beside this one does
    /// not, and that is a latent defect rather than a pattern worth copying:
    /// a failed save there leaves the edit in memory, where an unrelated
    /// later save can persist it. Not changed here because it is not this
    /// change's business, but it should be.
    pub fn set_bookmark_tags(&mut self, id: &str, tags: Vec<String>) -> Result<bool, StoreError> {
        let normalised = normalize_tags(tags);
        let Some(entry) = self.data.bookmarks.iter_mut().find(|b| b.id == id) else {
            return Ok(false);
        };
        let previous = std::mem::replace(&mut entry.tags, normalised);
        if let Err(err) = self.save() {
            if let Some(entry) = self.data.bookmarks.iter_mut().find(|b| b.id == id) {
                entry.tags = previous;
            }
            return Err(err);
        }
        Ok(true)
    }

    // ---- bookmark folders --------------------------------------------------
    //
    // A folder IS a tag (see `plan_folder_*` in model.rs). These four wrap the
    // pure planners with the same persist-then-rollback contract the bookmark
    // and shelf methods above use, so a folder change that could not be written
    // did not happen. Create/file/unfile touch one place and roll back that one
    // place; rename/delete rewrite every bookmark's tags, so they snapshot the
    // whole `StoreData` (it derives Clone) and restore it wholesale on failure
    // rather than trying to unwind each edit. The names arrive pre-normalized
    // (`normalize_folder_name`), so the store never has to reconcile spellings.

    /// Records an empty folder so it survives with no bookmarks in it.
    /// Idempotent: creating a folder that already exists is a silent success
    /// with no write. Rolls back on write failure.
    pub fn create_folder(&mut self, name: &str) -> Result<(), StoreError> {
        if !self.data.plan_folder_create(name) {
            return Ok(());
        }
        if let Err(err) = self.save() {
            self.data.bookmark_folders.pop();
            return Err(err);
        }
        Ok(())
    }

    /// Renames a folder across the known list AND every bookmark tagged with
    /// it. `Ok(false)` means nothing carried the old name. Snapshots the whole
    /// store and restores it if the write fails.
    pub fn rename_folder(&mut self, from: &str, to: &str) -> Result<bool, StoreError> {
        let snapshot = self.data.clone();
        if !self.data.plan_folder_rename(from, to) {
            return Ok(false);
        }
        if let Err(err) = self.save() {
            self.data = snapshot;
            return Err(err);
        }
        Ok(true)
    }

    /// Deletes a folder: drops it from the known list and unfiles it from
    /// every bookmark. THE BOOKMARKS SURVIVE, untagged by that folder.
    /// `Ok(false)` means nothing carried the name. Snapshot rollback on write
    /// failure.
    pub fn delete_folder(&mut self, name: &str) -> Result<bool, StoreError> {
        let snapshot = self.data.clone();
        if !self.data.plan_folder_delete(name) {
            return Ok(false);
        }
        if let Err(err) = self.save() {
            self.data = snapshot;
            return Err(err);
        }
        Ok(true)
    }

    /// Files one bookmark into a folder by ADDING that folder to the
    /// bookmark's current tags, read authoritatively from the store here so
    /// two quick drops cannot each clobber the other. `Ok(None)` means no
    /// bookmark had that id; `Ok(Some(false))` means it was already there (no
    /// write). Rolls back the single added tag on write failure.
    pub fn file_bookmark(&mut self, id: &str, folder: &str) -> Result<Option<bool>, StoreError> {
        match self.data.plan_folder_file(id, folder) {
            None => Ok(None),
            Some(false) => Ok(Some(false)),
            Some(true) => {
                if let Err(err) = self.save() {
                    if let Some(entry) = self.data.bookmarks.iter_mut().find(|b| b.id == id) {
                        entry.tags.pop();
                    }
                    return Err(err);
                }
                Ok(Some(true))
            }
        }
    }

    /// Removes one bookmark from one folder, leaving its other folders and the
    /// bookmark itself intact. Same return shape as [`Self::file_bookmark`].
    /// Rolls back the removed tag on write failure.
    pub fn unfile_bookmark(&mut self, id: &str, folder: &str) -> Result<Option<bool>, StoreError> {
        let previous_tags = self
            .data
            .bookmarks
            .iter()
            .find(|b| b.id == id)
            .map(|b| b.tags.clone());
        match self.data.plan_folder_unfile(id, folder) {
            None => Ok(None),
            Some(false) => Ok(Some(false)),
            Some(true) => {
                if let Err(err) = self.save() {
                    if let (Some(entry), Some(tags)) = (
                        self.data.bookmarks.iter_mut().find(|b| b.id == id),
                        previous_tags,
                    ) {
                        entry.tags = tags;
                    }
                    return Err(err);
                }
                Ok(Some(true))
            }
        }
    }

    /// The known folder names, so the UI can show a folder that has no
    /// bookmarks in it yet.
    pub fn folders(&self) -> &[String] {
        &self.data.bookmark_folders
    }

    /// Pins or unpins a bookmark in the Quick Access row. Same
    /// mutate-then-persist-with-rollback contract as the folder methods
    /// above: the in-memory flag goes back if the write fails, so `Ok` is the
    /// only state in which the change exists.
    ///
    /// `Ok(None)` = no bookmark had that id. `Ok(Some(false))` = it was
    /// already in the requested state, so nothing was written.
    /// `Ok(Some(true))` = flipped and persisted.
    pub fn set_quick_access(
        &mut self,
        id: &str,
        on: bool,
    ) -> Result<Option<bool>, StoreError> {
        let Some(entry) = self.data.bookmarks.iter_mut().find(|b| b.id == id) else {
            return Ok(None);
        };
        if entry.quick_access == on {
            return Ok(Some(false));
        }
        entry.quick_access = on;
        if let Err(err) = self.save() {
            if let Some(entry) = self.data.bookmarks.iter_mut().find(|b| b.id == id) {
                entry.quick_access = !on;
            }
            return Err(err);
        }
        Ok(Some(true))
    }

    /// Deleting a bookmark removes its recorded digest along with it (the
    /// digest lives inside the entry, so this cannot be forgotten).
    pub fn delete_bookmark(&mut self, id: &str) -> Result<(), StoreError> {
        let before = self.data.bookmarks.len();
        self.data.bookmarks.retain(|b| b.id != id);
        if self.data.bookmarks.len() == before {
            return Err(StoreError::NotFound(id.to_string()));
        }
        self.save()
    }

    /// Empty the bookmark manager: every bookmark and every folder name.
    ///
    /// IRREVERSIBLE, AND THAT IS THE POINT OF THE NAME. There is no undo
    /// buffer, no trash, and no bookmark export to fall back on -- the only
    /// copy of this data lives in the vault this store is, so once saved it
    /// is gone. The confirmation belongs in the UI; this function does what
    /// it is told.
    ///
    /// WHAT GOES, and why it is both vectors rather than just the first:
    ///   * every `Bookmark`, which OWNS its tags, its Quick Access pin and
    ///     its provenance digest -- so those go with it and cannot be left
    ///     behind pointing at nothing (see `Bookmark::digest`);
    ///   * every folder NAME in `bookmark_folders`, which exists only to
    ///     keep an empty folder visible. Leaving those would empty the
    ///     manager and still show a sidebar of folders, which is not what
    ///     "delete everything" looked like when it was asked for.
    ///
    /// WHAT STAYS, deliberately: downloads, shelves, archived pages and
    /// divergence overrides. They share this store but they are not the
    /// bookmark manager, and a bulk delete that quietly took them too would
    /// be the worst kind of surprise.
    ///
    /// Returns what was removed, so the caller can report a number the user
    /// can check against what they were just looking at.
    pub fn delete_all_bookmarks(&mut self) -> Result<(usize, usize), StoreError> {
        let bookmarks = self.data.bookmarks.len();
        let folders = self.data.bookmark_folders.len();
        if bookmarks == 0 && folders == 0 {
            // Nothing to do, and no reason to rewrite the vault for it.
            return Ok((0, 0));
        }
        self.data.bookmarks.clear();
        self.data.bookmark_folders.clear();
        self.save()?;
        Ok((bookmarks, folders))
    }

    /// Replace the whole bookmark set, for vault import. Returns how many
    /// were kept.
    ///
    /// Entries are ACCEPTED AS GIVEN, ids included. They came out of a file
    /// this process just decrypted and authenticated with the user's own
    /// passphrase, so re-minting ids would only break the provenance digests
    /// that reference them.
    ///
    /// Duplicate ids ARE dropped: `get_bookmark` and every delete path find by
    /// id and stop at the first hit, so a duplicate is an entry the user can
    /// see and cannot remove.
    pub fn replace_bookmarks(&mut self, bookmarks: Vec<Bookmark>) -> Result<usize, StoreError> {
        let mut seen = std::collections::BTreeSet::new();
        self.data.bookmarks = bookmarks
            .into_iter()
            .filter(|b| !b.id.is_empty() && seen.insert(b.id.clone()))
            .collect();
        let kept = self.data.bookmarks.len();
        // Persist-on-write, same rule as everything else here: a failed save
        // must not leave a set that exists only in memory.
        self.save()?;
        Ok(kept)
    }

    pub fn bookmarks(&self) -> &[Bookmark] {
        &self.data.bookmarks
    }

    pub fn get_bookmark(&self, id: &str) -> Option<&Bookmark> {
        self.data.bookmarks.iter().find(|b| b.id == id)
    }

    /// Record (or replace) the content digest for this bookmark — "this is
    /// what the page looked like when I last saw it".
    pub fn mark_seen(&mut self, id: &str, digest: ContentDigest) -> Result<(), StoreError> {
        let entry = self
            .data
            .bookmarks
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        entry.digest = Some(RecordedDigest {
            digest,
            recorded_at: now_unix(),
        });
        self.save()
    }

    /// Compare freshly fetched content against the stored digest. Returns
    /// `Ok(None)` when no digest has been recorded yet (nothing to compare
    /// against — not an error, the caller should usually `mark_seen`).
    pub fn check(&self, id: &str, current: &ContentDigest) -> Result<Option<Verdict>, StoreError> {
        let entry = self
            .data
            .bookmarks
            .iter()
            .find(|b| b.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        Ok(entry
            .digest
            .as_ref()
            .map(|recorded| patanyx_integrity::compare(&recorded.digest, current)))
    }

    // ---- download provenance ----

    /// Record a completed download. `sha256` is the SHA-256 of the file
    /// contents, computed by the caller (the download code streams large
    /// files; this crate only stores the result). The record is
    /// HMAC-authenticated at write time; see the module docs for exactly
    /// what that does and does not prove.
    pub fn record_download(
        &mut self,
        url: &str,
        filename: &str,
        byte_len: u64,
        sha256: [u8; 32],
    ) -> Result<String, StoreError> {
        let id = random_id();
        let recorded_at = now_unix();
        let hmac = provenance::record_mac(
            &self.provenance_key,
            &id,
            url,
            filename,
            byte_len,
            &sha256,
            recorded_at,
        );
        self.data.downloads.push(DownloadRecord {
            id: id.clone(),
            url: url.to_string(),
            filename: filename.to_string(),
            byte_len,
            sha256,
            recorded_at,
            hmac,
        });
        self.save()?;
        Ok(id)
    }

    pub fn downloads(&self) -> &[DownloadRecord] {
        &self.data.downloads
    }

    pub fn get_download(&self, id: &str) -> Option<&DownloadRecord> {
        self.data.downloads.iter().find(|d| d.id == id)
    }

    /// Re-verify a record's HMAC. `Ok(true)` = the record is exactly what
    /// was written; `Ok(false)` = it has been altered since.
    pub fn verify_download(&self, id: &str) -> Result<bool, StoreError> {
        let record = self
            .data
            .downloads
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        Ok(provenance::verify(&self.provenance_key, record))
    }
}

// No manual Drop impl: both keys wipe themselves via Zeroizing, and — by
// the tiered-sensitivity design above — bookmark/provenance entries are not
// treated as in-memory secrets the way vault passwords are.

/// Caps for user-entered shelf text. Generous: these exist to bound a write,
/// not to shape what a user may say. Counted in characters, so the limit
/// means the same thing whatever script the user writes in.
const SHELF_NAME_MAX_CHARS: usize = 120;
const SHELF_NOTE_MAX_CHARS: usize = 2000;

/// Truncates to `max` CHARACTERS, never bytes. `String::truncate` panics on a
/// non-boundary index, and byte-slicing multi-byte text is how a cap turns
/// into a crash or a broken glyph.
fn cap_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// At most this many tags per bookmark, each at most this many characters.
/// Bounds a write; not an opinion about how anyone organises their reading.
const BOOKMARK_MAX_TAGS: usize = 12;
const BOOKMARK_TAG_MAX_CHARS: usize = 40;

/// Trim, lowercase, drop empties, dedupe, and cap. Order of first appearance
/// is kept so a user's own ordering survives.
fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let cleaned = cap_chars(tag.trim(), BOOKMARK_TAG_MAX_CHARS)
            .to_lowercase()
            .trim()
            .to_string();
        if cleaned.is_empty() || out.iter().any(|t| t == &cleaned) {
            continue;
        }
        out.push(cleaned);
        if out.len() == BOOKMARK_MAX_TAGS {
            break;
        }
    }
    out
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

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
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
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
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
mod tests {
    use super::*;
    use chacha20poly1305::aead::rand_core::RngCore;
    use chacha20poly1305::aead::OsRng;

    fn test_path(tag: &str) -> PathBuf {
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        std::env::temp_dir().join(format!(
            "patanyx-store-test-{tag}-{:016x}",
            u64::from_le_bytes(suffix)
        ))
    }

    /// Fast KDF parameters so tests don't spend 64 MiB and three iterations
    /// per unlock.
    fn make_store(path: &Path, passphrase: &str) -> Store {
        Store::create_with_params(path, passphrase, 8192, 1, 1).unwrap()
    }

    // ---- the archive ----------------------------------------------------

    /// The archive's blob directory sits beside the store file, so tests
    /// clean up the whole parent rather than the file alone.
    fn archive_store(tag: &str) -> (PathBuf, Store) {
        let dir = test_path(tag);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.rbs");
        let store = make_store(&path, "pw");
        (dir, store)
    }

    #[test]
    fn an_archived_page_keeps_its_text_and_its_picture_together() {
        let (dir, mut store) = archive_store("archive-add");
        let png = b"\x89PNG\r\n\x1a\n pretend pixels";
        let id = store
            .add_archive(
                "https://example.com/report",
                "Quarterly report",
                "visible area",
                "Revenue 4,182,000",
                Some(png),
            )
            .unwrap();
        let record = store.get_archive(&id).expect("record");
        assert_eq!(record.text, "Revenue 4,182,000");
        assert!(record.has_picture);
        assert!(record.picture_bytes > png.len() as u64, "header and tag");
        assert_eq!(&store.archive_picture(&id).unwrap()[..], png);
        // It survives a lock/unlock cycle, which is the whole point of
        // putting it in the store rather than in memory.
        let reopened = Store::unlock(&dir.join("store.rbs"), "pw").unwrap();
        assert_eq!(reopened.archive().len(), 1);
        assert_eq!(reopened.get_archive(&id).unwrap().text, "Revenue 4,182,000");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_page_can_be_archived_with_no_picture_at_all() {
        // OCR finding nothing, or a capture that failed, still leaves
        // something worth keeping.
        let (dir, mut store) = archive_store("archive-nopic");
        let id = store
            .add_archive("https://a.example/", "Title", "full page", "read words", None)
            .unwrap();
        let record = store.get_archive(&id).unwrap();
        assert!(!record.has_picture);
        assert_eq!(record.picture_bytes, 0);
        assert!(store.archive_picture(&id).is_err(), "there is no picture");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deleting_a_page_takes_its_picture_with_it() {
        let (dir, mut store) = archive_store("archive-del");
        let id = store
            .add_archive("https://a.example/", "t", "full page", "x", Some(b"pixels"))
            .unwrap();
        assert!(dir.join("archive").join(&id).is_file());
        store.delete_archive(&id).unwrap();
        assert!(store.get_archive(&id).is_none());
        assert!(
            !dir.join("archive").join(&id).exists(),
            "the picture outlived its record"
        );
        assert!(store.delete_archive(&id).is_err(), "deleting twice is not silent");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_full_archive_refuses_rather_than_evicting_the_oldest_page() {
        // The rule that matters: throwing away something the user saved, to
        // make room for something else they saved, is a decision they did
        // not make.
        let (dir, mut store) = archive_store("archive-full");
        for i in 0..MAX_ARCHIVE_RECORDS {
            store
                .add_archive(&format!("https://a.example/{i}"), "t", "full page", "x", None)
                .unwrap();
        }
        let first = store.archive()[0].id.clone();
        let verdict = store.add_archive("https://a.example/extra", "t", "full page", "x", None);
        assert!(matches!(verdict, Err(StoreError::Full(_))));
        assert_eq!(store.archive().len(), MAX_ARCHIVE_RECORDS);
        assert!(store.get_archive(&first).is_some(), "the oldest was evicted");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_blob_no_record_names_is_swept_and_a_named_one_is_kept() {
        let (dir, mut store) = archive_store("archive-reconcile");
        let kept = store
            .add_archive("https://a.example/", "t", "full page", "x", Some(b"pixels"))
            .unwrap();
        // Debris of the shape an interrupted write leaves behind.
        fs::write(dir.join("archive").join("0123456789abcdef"), b"orphan").unwrap();
        assert_eq!(store.reconcile_archive().unwrap(), 1);
        assert!(dir.join("archive").join(&kept).is_file(), "swept a live blob");
        assert!(store.archive_picture(&kept).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn archive_ids_are_usable_as_blob_filenames() {
        // The two modules agree on the alphabet: a generated id must pass
        // the blob module's own validator, or a save would fail at the last
        // step for a reason the user cannot act on.
        let (dir, mut store) = archive_store("archive-ids");
        for _ in 0..16 {
            let id = store
                .add_archive("https://a.example/", "t", "full page", "x", Some(b"p"))
                .unwrap();
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "id {id:?} is not blob-safe"
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    fn page_digest(words: &str) -> ContentDigest {
        patanyx_integrity::digest(format!("<p>{words}</p>").as_bytes()).unwrap()
    }

    #[test]
    fn bookmark_tags_survive_close_and_unlock_and_normalise() {
        let path = test_path("bm-tags");
        let id;
        {
            let mut store = make_store(&path, "correct horse");
            id = store.add_bookmark("https://example.com/", "Example").unwrap();
            assert!(store.get_bookmark(&id).unwrap().tags.is_empty());
            assert!(store
                .set_bookmark_tags(
                    &id,
                    vec![
                        "  Chem  ".to_string(),
                        "CHEM".to_string(),   // same tag, different case
                        "".to_string(),       // dropped
                        "lab".to_string(),
                    ],
                )
                .unwrap());
        }
        {
            let store = Store::unlock(&path, "correct horse").unwrap();
            let b = store.get_bookmark(&id).unwrap();
            assert_eq!(
                b.tags,
                vec!["chem".to_string(), "lab".to_string()],
                "trimmed, lowercased, deduped, empties dropped, order kept"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bookmark_tags_are_capped_and_survive_the_export_round_trip() {
        let path = test_path("bm-tags-cap");
        let mut store = make_store(&path, "correct horse");
        let id = store.add_bookmark("https://example.com/", "Example").unwrap();
        let many: Vec<String> = (0..BOOKMARK_MAX_TAGS + 10)
            .map(|n| format!("tag{n}"))
            .collect();
        assert!(store.set_bookmark_tags(&id, many).unwrap());
        assert_eq!(store.get_bookmark(&id).unwrap().tags.len(), BOOKMARK_MAX_TAGS);

        // The export path serialises the whole struct and the import path
        // deserialises it, so this proves tags survive that round trip
        // rather than asserting it from the type.
        let encoded = serde_json::to_vec(store.bookmarks()).unwrap();
        let decoded: Vec<Bookmark> = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded[0].tags.len(), BOOKMARK_MAX_TAGS);

        // And an entry written before tags existed still loads.
        let old = r#"[{"id":"a","url":"https://e.com/","title":"E","created_at":1,"digest":null}]"#;
        let legacy: Vec<Bookmark> = serde_json::from_str(old).unwrap();
        assert!(legacy[0].tags.is_empty(), "absent tags read as an empty list");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn shelf_name_and_note_survive_close_and_unlock() {
        // The acceptance requirement is restart survival, so this exercises
        // the REAL write path and re-unlocks, rather than asserting on the
        // capping helper. A method that forgot to call save() would pass a
        // helper test and fail this one.
        let path = test_path("shelf-note");
        let id;
        {
            let mut store = make_store(&path, "correct horse");
            let shelf = store
                .add_shelf(
                    "Set aside 2 tabs".to_string(),
                    vec![ShelfTab {
                        title: "Paper".to_string(),
                        url: "https://example.com/paper".to_string(),
                    }],
                )
                .unwrap();
            id = shelf.id.clone();
            assert_eq!(shelf.note, "", "a new shelf starts with no note");
            assert!(store.rename_shelf(&id, "Chem lab").unwrap());
            assert!(store
                .set_shelf_note(&id, "Due Friday, cite the 2019 paper")
                .unwrap());
        }
        {
            let store = Store::unlock(&path, "correct horse").unwrap();
            let shelf = store.shelves().iter().find(|s| s.id == id).unwrap();
            assert_eq!(shelf.name, "Chem lab");
            assert_eq!(shelf.note, "Due Friday, cite the 2019 paper");
            assert_eq!(shelf.tabs.len(), 1, "editing text must not touch the tabs");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn shelf_text_is_capped_by_characters_not_bytes() {
        // A byte cap would panic or cut a glyph in half on multi-byte text.
        // The store is the authoritative cap, so this is where it is proven.
        let path = test_path("shelf-cap");
        let mut store = make_store(&path, "correct horse");
        let shelf = store.add_shelf("s".to_string(), Vec::new()).unwrap();
        let long = "\u{1F600}".repeat(SHELF_NOTE_MAX_CHARS + 50);
        assert!(store.set_shelf_note(&shelf.id, &long).unwrap());
        let stored = &store.shelves()[0].note;
        assert_eq!(stored.chars().count(), SHELF_NOTE_MAX_CHARS);
        assert!(
            stored.chars().all(|c| c == '\u{1F600}'),
            "no glyph was split"
        );
        assert!(!store.rename_shelf("shelf-does-not-exist", "x").unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn folders_round_trip_the_full_organizer_workflow() {
        // The whole organizer workflow, against the REAL write path with a
        // close-and-reopen so a method that forgot save() would fail: create
        // an empty folder, file two bookmarks, rename the
        // folder (both bookmarks must follow), delete another folder (its
        // bookmark must SURVIVE, only unfiled). Every step persists.
        let path = test_path("folders");
        let (a, b);
        {
            let mut store = make_store(&path, "correct horse");
            a = store.add_bookmark("https://a.test/", "A").unwrap();
            b = store.add_bookmark("https://b.test/", "B").unwrap();

            // An empty folder survives with nothing in it.
            store.create_folder("chem").unwrap();
            assert_eq!(store.folders(), &["chem".to_string()]);
            store.create_folder("chem").unwrap(); // idempotent, still one
            assert_eq!(store.folders().len(), 1);

            // File both bookmarks into it; filing is additive and idempotent.
            assert_eq!(store.file_bookmark(&a, "chem").unwrap(), Some(true));
            assert_eq!(store.file_bookmark(&a, "chem").unwrap(), Some(false));
            assert_eq!(store.file_bookmark(&b, "chem").unwrap(), Some(true));
            assert_eq!(store.file_bookmark("missing", "chem").unwrap(), None);

            // A second folder for the delete-survives check.
            store.file_bookmark(&b, "reading").unwrap();
        }
        {
            // Reopened: rename must carry every filed bookmark with it.
            let mut store = Store::unlock(&path, "correct horse").unwrap();
            assert!(store.rename_folder("chem", "chemistry").unwrap());
            assert!(!store.rename_folder("chem", "chemistry").unwrap()); // gone
            assert_eq!(store.folders(), &["chemistry".to_string()]);
            for id in [&a, &b] {
                assert!(store
                    .get_bookmark(id)
                    .unwrap()
                    .tags
                    .contains(&"chemistry".to_string()));
            }

            // Deleting a folder unfiles but never destroys its bookmark.
            assert!(store.delete_folder("reading").unwrap());
            let survivor = store.get_bookmark(&b).unwrap();
            assert!(!survivor.tags.contains(&"reading".to_string()));
            assert!(survivor.tags.contains(&"chemistry".to_string()));
            assert!(store.get_bookmark(&b).is_some(), "bookmark survived delete");

            // Unfile one, its other folder stays.
            assert_eq!(store.unfile_bookmark(&b, "chemistry").unwrap(), Some(true));
            assert!(store.get_bookmark(&b).is_some());
        }
        {
            // Everything above must have hit disk.
            let store = Store::unlock(&path, "correct horse").unwrap();
            assert_eq!(store.folders(), &["chemistry".to_string()]);
            assert!(store
                .get_bookmark(&a)
                .unwrap()
                .tags
                .contains(&"chemistry".to_string()));
            assert!(!store
                .get_bookmark(&b)
                .unwrap()
                .tags
                .contains(&"chemistry".to_string()));
        }
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn quick_access_flips_is_idempotent_and_survives_a_reopen() {
        // The real write path, with a close-and-reopen: a method that forgot
        // to save() would pass an in-memory assertion and fail this.
        let path = test_path("quickaccess");
        let id;
        {
            let mut store = make_store(&path, "correct horse");
            id = store.add_bookmark("https://a.test/", "A").unwrap();
            assert!(
                !store.get_bookmark(&id).unwrap().quick_access,
                "a new bookmark starts unpinned"
            );
            assert_eq!(store.set_quick_access("missing", true).unwrap(), None);
            assert_eq!(store.set_quick_access(&id, true).unwrap(), Some(true));
            // Pinning an already-pinned bookmark writes nothing.
            assert_eq!(store.set_quick_access(&id, true).unwrap(), Some(false));
        }
        {
            let mut store = Store::unlock(&path, "correct horse").unwrap();
            assert!(store.get_bookmark(&id).unwrap().quick_access, "pin persisted");
            assert_eq!(store.set_quick_access(&id, false).unwrap(), Some(true));
        }
        {
            let store = Store::unlock(&path, "correct horse").unwrap();
            assert!(!store.get_bookmark(&id).unwrap().quick_access, "unpin persisted");
        }
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn bookmark_roundtrips_through_close_and_unlock() {
        let path = test_path("roundtrip");
        let id;
        let seen = page_digest("the quick brown fox jumps over the lazy dog");
        {
            let mut store = make_store(&path, "correct horse");
            id = store.add_bookmark("https://example.com/", "Example").unwrap();
            store.mark_seen(&id, seen.clone()).unwrap();
        } // store closed: "locked"
        {
            let store = Store::unlock(&path, "correct horse").unwrap();
            let b = store.get_bookmark(&id).unwrap();
            assert_eq!(b.url, "https://example.com/");
            assert_eq!(b.title, "Example");
            assert_eq!(
                store.check(&id, &seen).unwrap(),
                Some(Verdict::Identical),
                "same content must compare Identical after re-unlock"
            );
            let changed = page_digest("the quick brown wolf jumps over the lazy dog");
            match store.check(&id, &changed).unwrap() {
                Some(Verdict::TextDiffers { similarity }) => {
                    assert!((0.0..1.0).contains(&similarity));
                }
                other => panic!("expected TextDiffers, got {other:?}"),
            }
        }
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let path = test_path("wrongpass");
        make_store(&path, "right");
        let err = Store::unlock(&path, "wrong").unwrap_err();
        assert!(
            matches!(err, StoreError::AuthFailed),
            "wrong passphrase must be indistinguishable from tampering, got {err:?}"
        );
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn vault_file_is_rejected() {
        // A vault file has magic b"RBVAULT". Take a real store file and flip
        // its magic to the vault's: the store must refuse it at the framing
        // level, before any key derivation.
        let path = test_path("vaultmagic");
        make_store(&path, "pw");
        let file = path.join("dummy"); // silence unused-var style confusion
        let _ = file;
        let store_file = path.with_file_name(format!(
            "{}",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = store_file;
        let mut bytes = fs::read(&path).unwrap();
        bytes[..7].copy_from_slice(b"RBVAULT");
        fs::write(&path, &bytes).unwrap();
        let err = Store::unlock(&path, "pw").unwrap_err();
        assert!(
            matches!(err, StoreError::BadFormat(_)),
            "vault magic must be rejected, got {err:?}"
        );
        // Note: the reverse direction (Store file rejected BY the
        // vault) needs a dev-dependency on patanyx-vault; see the closing
        // notes. It is guaranteed by the vault's existing bad-magic check.
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let path = test_path("tamper");
        make_store(&path, "pw");
        let mut bytes = fs::read(&path).unwrap();
        // Flip one bit in the ciphertext region (past the 60-byte header).
        bytes[format::HEADER_LEN] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let err = Store::unlock(&path, "pw").unwrap_err();
        assert!(matches!(err, StoreError::AuthFailed), "got {err:?}");
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn deleting_the_whole_manager_takes_bookmarks_folders_tags_pins_and_digests() {
        let path = test_path("delete-all");
        let mut store = make_store(&path, "pw");

        let a = store.add_bookmark("https://a.example/", "A").unwrap();
        let b = store.add_bookmark("https://b.example/", "B").unwrap();
        store.mark_seen(&a, page_digest("page a content")).unwrap();
        store.set_bookmark_tags(&b, vec!["work".into()]).unwrap();
        store.set_quick_access(&a, true).unwrap();
        store.create_folder("Reading").unwrap();

        // A download record shares this store and must NOT be swept up: it
        // is not the bookmark manager.
        store
            .record_download("https://a.example/f.bin", "f.bin", 10, [7u8; 32])
            .unwrap();

        assert_eq!(store.delete_all_bookmarks().unwrap(), (2, 1));

        assert!(store.bookmarks().is_empty(), "bookmarks survived");
        assert!(store.folders().is_empty(), "folder names survived");
        // The digest went with the bookmark that owned it.
        assert!(matches!(
            store.check(&a, &page_digest("page a content")),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(store.downloads().len(), 1, "downloads must not be swept up");

        // Gone from the vault, not merely from memory.
        let store = Store::unlock(&path, "pw").unwrap();
        assert!(
            store.bookmarks().is_empty(),
            "bookmarks came back on unlock"
        );
        assert!(store.folders().is_empty(), "folders came back on unlock");
        assert_eq!(store.downloads().len(), 1, "downloads lost on unlock");
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn deleting_an_already_empty_manager_is_a_no_op() {
        // Reports nothing removed, and does not rewrite the vault for it.
        let path = test_path("delete-all-empty");
        let mut store = make_store(&path, "pw");
        assert_eq!(store.delete_all_bookmarks().unwrap(), (0, 0));
        assert!(store.bookmarks().is_empty());
        // Twice in a row is still fine.
        assert_eq!(store.delete_all_bookmarks().unwrap(), (0, 0));
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn an_empty_folder_alone_is_still_worth_deleting() {
        // A manager with no bookmarks but folders the user made is not
        // "already empty": the delete must still clear and report them.
        let path = test_path("delete-all-folders");
        let mut store = make_store(&path, "pw");
        store.create_folder("Reading").unwrap();
        store.create_folder("Work").unwrap();
        assert_eq!(store.delete_all_bookmarks().unwrap(), (0, 2));
        assert!(store.folders().is_empty());
        let store = Store::unlock(&path, "pw").unwrap();
        assert!(store.folders().is_empty(), "folders came back on unlock");
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn delete_bookmark_removes_its_digest() {
        let path = test_path("delete");
        let mut store = make_store(&path, "pw");
        let id = store.add_bookmark("https://example.com/", "Example").unwrap();
        store.mark_seen(&id, page_digest("hello world content")).unwrap();
        store.delete_bookmark(&id).unwrap();
        assert!(store.get_bookmark(&id).is_none());
        assert!(matches!(
            store.check(&id, &page_digest("hello world content")),
            Err(StoreError::NotFound(_))
        ));
        // And it stays gone after a fresh unlock (not just in memory).
        let store = Store::unlock(&path, "pw").unwrap();
        assert!(store.bookmarks().is_empty());
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn updating_url_clears_digest_but_renaming_keeps_it() {
        let path = test_path("update");
        let mut store = make_store(&path, "pw");
        let id = store.add_bookmark("https://a.example/", "A").unwrap();
        store.mark_seen(&id, page_digest("some stable page words")).unwrap();
        store.update_bookmark(&id, "https://a.example/", "Renamed").unwrap();
        assert!(
            store.get_bookmark(&id).unwrap().digest.is_some(),
            "title-only edit must keep the digest"
        );
        store
            .update_bookmark(&id, "https://b.example/", "Renamed")
            .unwrap();
        assert!(
            store.get_bookmark(&id).unwrap().digest.is_none(),
            "URL change must drop the stale digest"
        );
        assert_eq!(store.check(&id, &page_digest("x")).unwrap(), None);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn check_without_digest_returns_none() {
        let path = test_path("nodigest");
        let mut store = make_store(&path, "pw");
        let id = store.add_bookmark("https://example.com/", "Example").unwrap();
        assert_eq!(store.check(&id, &page_digest("anything at all")).unwrap(), None);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn provenance_record_verifies_and_tampering_fails() {
        let path = test_path("provenance");
        let mut store = make_store(&path, "pw");
        let id = store
            .record_download("https://example.com/f.zip", "f.zip", 1234, [7u8; 32])
            .unwrap();
        assert_eq!(store.verify_download(&id).unwrap(), true);
        // Verification must still hold after a fresh unlock (the MAC key is
        // re-derived from the store key, not held only in memory).
        let store = Store::unlock(&path, "pw").unwrap();
        assert_eq!(store.verify_download(&id).unwrap(), true);
        let record = store.get_download(&id).unwrap();
        assert_eq!(record.byte_len, 1234);
        assert_eq!(record.sha256, [7u8; 32]);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn tampered_provenance_record_fails_its_hmac() {
        // Unit-level property over the MAC itself: flip any covered field
        // and verification must fail; a wrong key must also fail.
        let store_key = [7u8; 32];
        let key = provenance::mac_key(&store_key);
        let mut record = DownloadRecord {
            id: "id0123".to_string(),
            url: "https://example.com/f.zip".to_string(),
            filename: "f.zip".to_string(),
            byte_len: 1234,
            sha256: [1u8; 32],
            recorded_at: 1_700_000_000,
            hmac: [0u8; 32],
        };
        record.hmac = provenance::record_mac(
            &key,
            &record.id,
            &record.url,
            &record.filename,
            record.byte_len,
            &record.sha256,
            record.recorded_at,
        );
        assert!(provenance::verify(&key, &record));

        let mut altered = record.clone();
        altered.byte_len = 1235;
        assert!(!provenance::verify(&key, &altered));

        let mut altered = record.clone();
        altered.filename = "g.zip".to_string();
        assert!(!provenance::verify(&key, &altered));

        let mut altered = record.clone();
        altered.sha256[0] ^= 0x01;
        assert!(!provenance::verify(&key, &altered));

        let mut altered = record.clone();
        altered.recorded_at += 1;
        assert!(!provenance::verify(&key, &altered));

        let wrong_key = provenance::mac_key(&[8u8; 32]);
        assert!(!provenance::verify(&wrong_key, &record));
    }

    #[test]
    #[cfg(unix)]
    fn store_file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = test_path("mode");
        make_store(&path, "pw");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store file must be owner-only");
        let _ = fs::remove_dir_all(&path);
    }
}

// ---- the archive: a page's metadata here, its picture in a blob ----------
//
// Two stores of different shapes, kept in step by this impl block. The
// record is the truth about what exists; a blob without a record is debris
// (swept by `reconcile_archive`), and a record whose blob is missing still
// lists and still searches, because the TEXT is the part that answers a
// search and the picture is the part that can be lost without lying.

/// Bounded on purpose, both ways. Records bound the whole-file rewrite the
/// store does on every mutation; bytes bound the disk. Reaching either is a
/// refusal, never a silent eviction: deleting the user's oldest saved page
/// to make room for a new one is a decision they did not make.
pub const MAX_ARCHIVE_RECORDS: usize = 200;
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

impl Store {
    /// The blob directory sits beside the store file. Opened on demand
    /// rather than held: it is a path plus a derived key, so constructing
    /// it costs one hash, and a store whose archive directory cannot be
    /// created must still open for bookmarks.
    fn blobs(&self) -> Result<blob::BlobStore, StoreError> {
        let dir = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("archive");
        blob::BlobStore::open(&dir, &self.key)
    }

    pub fn archive(&self) -> &[ArchiveRecord] {
        &self.data.archive
    }

    pub fn get_archive(&self, id: &str) -> Option<&ArchiveRecord> {
        self.data.archive.iter().find(|record| record.id == id)
    }

    /// Bytes currently held by archived pictures, from the records rather
    /// than from the disk: the cap is enforced against what this store
    /// believes it owns, and debris on disk is not the user's fault to pay
    /// for.
    pub fn archive_bytes(&self) -> u64 {
        self.data
            .archive
            .iter()
            .map(|record| record.picture_bytes)
            .sum()
    }

    /// Saves one page. The picture is optional: OCR text alone is a
    /// legitimate archive entry, and is what remains if a capture failed.
    ///
    /// ORDER MATTERS. The blob is written FIRST, and the record is added
    /// only if that succeeded, so a record can never name a picture that was
    /// never written. If the store's own save then fails, the blob is
    /// removed again and the in-memory record rolled back, which is the same
    /// all-or-nothing shape `add_shelf` uses.
    pub fn add_archive(
        &mut self,
        url: &str,
        title: &str,
        scope: &str,
        text: &str,
        picture: Option<&[u8]>,
    ) -> Result<String, StoreError> {
        if self.data.archive.len() >= MAX_ARCHIVE_RECORDS {
            return Err(StoreError::Full(format!(
                "the archive holds its limit of {MAX_ARCHIVE_RECORDS} pages"
            )));
        }
        let incoming = picture.map(|bytes| bytes.len() as u64).unwrap_or(0);
        if self.archive_bytes().saturating_add(incoming) > MAX_ARCHIVE_BYTES {
            return Err(StoreError::Full(format!(
                "archived pictures would pass the limit of {} MB",
                MAX_ARCHIVE_BYTES / (1024 * 1024)
            )));
        }

        let id = random_id();
        let mut picture_bytes = 0u64;
        let mut has_picture = false;
        if let Some(bytes) = picture {
            picture_bytes = self.blobs()?.put(&id, bytes)?;
            has_picture = true;
        }
        self.data.archive.push(ArchiveRecord {
            id: id.clone(),
            url: url.to_string(),
            title: title.to_string(),
            created_at: now_unix(),
            scope: scope.to_string(),
            text: text.to_string(),
            picture_bytes,
            has_picture,
        });
        if let Err(e) = self.save() {
            self.data.archive.pop();
            if has_picture {
                let _ = self.blobs().and_then(|blobs| blobs.delete(&id));
            }
            return Err(e);
        }
        Ok(id)
    }

    /// The decrypted picture for one record.
    pub fn archive_picture(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let record = self
            .get_archive(id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        if !record.has_picture {
            return Err(StoreError::NotFound(format!("{id} has no picture")));
        }
        self.blobs()?.get(id)
    }

    /// Removes a record and its picture.
    ///
    /// The RECORD goes first here, the opposite order from adding, and for
    /// the same reason: whichever half is written last must be the one whose
    /// absence is harmless. A record with no blob still lists and searches;
    /// a blob with no record is invisible debris that `reconcile_archive`
    /// sweeps. Neither leaves a dangling promise.
    pub fn delete_archive(&mut self, id: &str) -> Result<(), StoreError> {
        let index = self
            .data
            .archive
            .iter()
            .position(|record| record.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        let record = self.data.archive.remove(index);
        if let Err(e) = self.save() {
            self.data.archive.insert(index, record);
            return Err(e);
        }
        if record.has_picture {
            let _ = self.blobs().and_then(|blobs| blobs.delete(id));
        }
        Ok(())
    }

    /// Deletes blobs no record names, and returns how many went.
    ///
    /// Runs at unlock. Debris is possible whenever a write is interrupted
    /// between the two stores, and a picture the user cannot see or delete
    /// through any UI is exactly the kind of thing that should not sit on
    /// disk encrypted-but-forgotten.
    pub fn reconcile_archive(&self) -> Result<usize, StoreError> {
        let keep: Vec<String> = self
            .data
            .archive
            .iter()
            .filter(|record| record.has_picture)
            .map(|record| record.id.clone())
            .collect();
        self.blobs()?.prune(&keep)
    }
}

// ---- per-site Fingerprint Divergence ------------------------------------

impl Store {
    pub fn divergence_overrides(&self) -> &[DivergenceOverride] {
        &self.data.divergence_overrides
    }

    /// Sets one site's level, replacing any previous choice for that host.
    ///
    /// The host is lowercased here so a user typing `Example.com` and the
    /// in-page key `example.com` cannot become two entries for one site.
    pub fn set_divergence_override(
        &mut self,
        host: &str,
        level: DivergenceLevel,
    ) -> Result<(), StoreError> {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() || host.contains('/') || host.contains(char::is_whitespace) {
            return Err(StoreError::NotFound(format!("unusable host: {host:?}")));
        }
        let before = self.data.divergence_overrides.clone();
        self.data.divergence_overrides.retain(|o| o.host != host);
        self.data
            .divergence_overrides
            .push(DivergenceOverride { host, level });
        if let Err(e) = self.save() {
            self.data.divergence_overrides = before;
            return Err(e);
        }
        Ok(())
    }

    /// Removes a site's choice, returning it to the global setting. Absent
    /// is success: the caller wanted it gone.
    pub fn clear_divergence_override(&mut self, host: &str) -> Result<(), StoreError> {
        let host = host.trim().to_ascii_lowercase();
        let before = self.data.divergence_overrides.clone();
        self.data.divergence_overrides.retain(|o| o.host != host);
        if before.len() == self.data.divergence_overrides.len() {
            return Ok(());
        }
        if let Err(e) = self.save() {
            self.data.divergence_overrides = before;
            return Err(e);
        }
        Ok(())
    }
}
