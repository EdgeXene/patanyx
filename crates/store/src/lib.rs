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

mod crypto;
mod error;
mod format;
mod model;
pub mod provenance;

pub use error::StoreError;
pub use model::{Bookmark, DownloadRecord, RecordedDigest, Shelf, ShelfTab, StoreData};
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

    fn page_digest(words: &str) -> ContentDigest {
        patanyx_integrity::digest(format!("<p>{words}</p>").as_bytes()).unwrap()
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
