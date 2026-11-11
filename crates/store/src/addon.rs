//! Encrypted storage for one add-on's text pages: `<store dir>/addons/<id>/`.
//!
//! WHERE AND HOW. Beside the archive, never inside it, so `reconcile_archive`
//! (which prunes `archive/` only) can never see it. Each namespace has its
//! own key, derived from the Library's data key and the add-on id, so one
//! add-on's files cannot be read with another's key or with the archive's.
//! Inside: one encrypted `index` blob and one IMMUTABLE encrypted blob per
//! page version. An autosave never rewrites `store.rbs`.
//!
//! WRITE ORDER, so a page and the index never disagree:
//!   1. write the new page version as its own blob (temp file, fsync, rename);
//!   2. replace the index atomically so it names that version, and make the
//!      directory entry durable;
//!   3. only then report success;
//!   4. delete the previous version's blob.
//! A crash before 2 leaves an unreferenced version (removed by `recover`); a
//! crash between 2 and 4 leaves the old version unreferenced (removed by
//! `recover`). The index is never ahead of a page it names.
//!
//! WHAT THIS MODULE DOES NOT DO. It never decides WHEN a caller may write
//! (Vault unlocked, Premium, session): that is the host's admission. It
//! runs on whatever thread calls it; the host calls it from a worker.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::blob::BlobStore;
use crate::crypto;
use crate::{Store, StoreError};

/// The most bytes one add-on's files may take on disk, everything counted.
pub const ADDON_QUOTA_BYTES: u64 = 256 * 1024 * 1024;
/// The largest page body, in UTF-8 bytes.
pub const ADDON_MAX_PAGE_BYTES: usize = 524_288;
/// The most pages one add-on may hold.
pub const ADDON_MAX_PAGES: usize = 4096;
/// The largest serialized index, in bytes.
pub const ADDON_MAX_INDEX_BYTES: usize = 8 * 1024 * 1024;
/// The longest page title, in Unicode scalar values.
pub const ADDON_MAX_TITLE_CHARS: usize = 200;

const INDEX_ID: &str = "index";
const KEY_DOMAIN: &[u8] = b"patanyx-store-addon-v1";

/// An add-on id: lowercase letters, digits and single hyphens, 1 to 32.
pub fn addon_id_ok(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
}

/// `SHA-256(domain || 0x00 || store key || 0x00 || "addon:" || id)`. The
/// blob layer then derives its own key from this one, as it does for the
/// archive, so the two stages are separate by construction.
pub(crate) fn namespace_key(store_key: &[u8; crypto::KEY_LEN], id: &str) -> Zeroizing<[u8; crypto::KEY_LEN]> {
    let mut hasher = Sha256::new();
    hasher.update(KEY_DOMAIN);
    hasher.update([0x00]);
    hasher.update(store_key);
    hasher.update([0x00]);
    hasher.update(b"addon:");
    hasher.update(id.as_bytes());
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; crypto::KEY_LEN]);
    key.copy_from_slice(&digest);
    key
}

/// One page as the index records it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageMeta {
    /// 32 lowercase hex characters, chosen here.
    pub id: String,
    pub title: String,
    pub revision: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub body_bytes: u64,
    /// The blob holding this revision's body.
    version: String,
    /// The site the user attached this page to (a registrable domain), if
    /// any. Only an explicit attach sets it; nothing here records visits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// The collection the page was created in (`valid_collection`), if any:
    /// set once, at creation, and kept by every later write. The AI Notebook
    /// is the collection `assistant`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
}

/// The longest collection name, in bytes.
pub const ADDON_MAX_COLLECTION_BYTES: usize = 32;

/// A collection name: 1 to 32 lowercase ASCII letters, digits or hyphens.
pub fn valid_collection(collection: &str) -> bool {
    !collection.is_empty()
        && collection.len() <= ADDON_MAX_COLLECTION_BYTES
        && collection.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// What a write does to a page's site attachment. `Keep` is what every
/// ordinary text or title save sends, so a save never drops the attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteChange {
    Keep,
    Set(String),
    Clear,
}

/// The longest site a page can be attached to, in bytes (a DNS name).
pub const ADDON_MAX_SITE_BYTES: usize = 253;

/// A registrable domain as the browser computes one: lowercase ASCII
/// (internationalized names in their xn-- form), dot-separated labels of
/// 1-63 letters, digits or hyphens that neither start nor end with a hyphen,
/// at least two labels.
pub fn valid_site(site: &str) -> bool {
    if site.is_empty() || site.len() > ADDON_MAX_SITE_BYTES {
        return false;
    }
    let labels: Vec<&str> = site.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A page as a list shows it: its record, and whether its body is there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageEntry {
    pub meta: PageMeta,
    pub readable: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: u32,
    pages: Vec<PageMeta>,
}

/// Why a write was refused. `Store` is an I/O or crypto failure; the rest
/// are the caller's to show.
#[derive(Debug)]
pub enum AddonWriteError {
    NotFound,
    /// The page changed since the caller read it.
    Conflict,
    PageTooLarge,
    TitleTooLong,
    InvalidBody,
    /// A site that is not a well-formed registrable domain.
    InvalidSite,
    /// A collection name that is not well formed, or one given on an update
    /// (a page's collection is chosen once, when it is created).
    InvalidCollection,
    TooManyPages,
    QuotaExceeded,
    /// The index exists but could not be read: nothing was changed.
    IndexUnreadable,
    Store(StoreError),
}

impl From<StoreError> for AddonWriteError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// The limits a namespace enforces. Real ones in production; tests use
/// small ones to reach every bound quickly.
#[derive(Clone, Copy, Debug)]
pub struct AddonLimits {
    pub quota_bytes: u64,
    pub max_page_bytes: usize,
    pub max_pages: usize,
}

impl Default for AddonLimits {
    fn default() -> Self {
        Self { quota_bytes: ADDON_QUOTA_BYTES, max_page_bytes: ADDON_MAX_PAGE_BYTES, max_pages: ADDON_MAX_PAGES }
    }
}

/// One add-on's encrypted namespace. Holds a path and a derived key, never
/// the Store, so a worker can own it while the Library is used elsewhere.
pub struct AddonNamespace {
    dir: PathBuf,
    blobs: BlobStore,
    limits: AddonLimits,
}

/// A namespace's scoped key and path, captured without filesystem access.
/// A host can move this to a worker before opening the blob directory.
pub struct AddonNamespaceInput {
    dir: PathBuf,
    key: Zeroizing<[u8; crypto::KEY_LEN]>,
}

impl AddonNamespaceInput {
    pub fn open(self) -> Result<AddonNamespace, StoreError> {
        let blobs = BlobStore::open(&self.dir, &self.key)?;
        Ok(AddonNamespace { dir: self.dir, blobs, limits: AddonLimits::default() })
    }
}

impl Store {
    pub fn addon_namespace_input(&self, id: &str) -> Result<AddonNamespaceInput, StoreError> {
        if !addon_id_ok(id) {
            return Err(StoreError::NotFound("unusable add-on id".into()));
        }
        Ok(AddonNamespaceInput {
            dir: addons_dir(self.path()).join(id),
            key: namespace_key(self.data_key(), id),
        })
    }
    /// Opens (creating if absent) the namespace of add-on `id`.
    pub fn addon_namespace(&self, id: &str) -> Result<AddonNamespace, StoreError> {
        self.addon_namespace_with(id, AddonLimits::default())
    }

    pub fn addon_namespace_with(&self, id: &str, limits: AddonLimits) -> Result<AddonNamespace, StoreError> {
        if !addon_id_ok(id) {
            return Err(StoreError::NotFound(format!("unusable add-on id: {id:?}")));
        }
        let dir = addons_dir(self.path()).join(id);
        let blobs = BlobStore::open(&dir, &namespace_key(self.data_key(), id))?;
        Ok(AddonNamespace { dir, blobs, limits })
    }
}

/// `<store dir>/addons`.
pub fn addons_dir(store_path: &Path) -> PathBuf {
    store_path.parent().unwrap_or_else(|| Path::new(".")).join("addons")
}

fn new_page_id() -> String {
    let bytes: [u8; 16] = crypto::random_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn page_id_ok(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn version_id(page: &str, revision: u64) -> String {
    format!("p-{page}-{revision}")
}

/// Exactly a name this module writes in a namespace: the index, or a page
/// version as `version_ok` accepts it. Anything else in the folder is not
/// this module's to rewrite or drop.
pub(crate) fn is_namespace_file(name: &str) -> bool {
    name == INDEX_ID || version_ok(name)
}

/// Makes a rename inside `dir` durable. No such call exists on Windows,
/// where the rename itself is the commit the file system gives.
fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

impl AddonNamespace {
    fn read_index(&self) -> Result<Index, AddonWriteError> {
        if !self.blobs.exists(INDEX_ID) {
            return Ok(Index { schema: 1, pages: Vec::new() });
        }
        let bytes = self
            .blobs
            .get_bounded(INDEX_ID, ADDON_MAX_INDEX_BYTES)
            .map_err(|_| AddonWriteError::IndexUnreadable)?;
        let index: Index = serde_json::from_slice(&bytes).map_err(|_| AddonWriteError::IndexUnreadable)?;
        let mut seen = std::collections::BTreeSet::new();
        let sound = index.schema == 1
            && index.pages.len() <= ADDON_MAX_PAGES
            && index.pages.iter().all(|p| {
                page_id_ok(&p.id) && p.version == version_id(&p.id, p.revision) && seen.insert(p.id.clone())
            });
        if !sound {
            return Err(AddonWriteError::IndexUnreadable);
        }
        Ok(index)
    }

    /// Replaces the index. An error means the old index still stands.
    /// `Ok(false)` means the new one is in place but the folder flush failed:
    /// the caller then deletes no version, since either index may be the one
    /// a crash leaves behind, and `recover` settles it at the next open.
    fn write_index(&self, index: &Index) -> Result<bool, AddonWriteError> {
        let json = Zeroizing::new(serde_json::to_vec(index).map_err(|e| StoreError::BadFormat(e.to_string()))?);
        if json.len() > ADDON_MAX_INDEX_BYTES {
            return Err(AddonWriteError::QuotaExceeded);
        }
        self.blobs.put(INDEX_ID, &json)?;
        #[cfg(test)]
        if crash_at(Crash::IndexFlush) {
            return Ok(false);
        }
        Ok(sync_dir(&self.dir).is_ok())
    }

    /// Every file in the namespace, counted on disk: what the quota is
    /// judged against, debris included.
    pub fn used_bytes(&self) -> Result<u64, StoreError> {
        let mut total = 0u64;
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total = total.saturating_add(meta.len());
                    }
                }
            }
        }
        Ok(total)
    }

    /// Every page, by id, with whether its body is present.
    pub fn list(&self) -> Result<Vec<PageEntry>, AddonWriteError> {
        let mut pages = self.read_index()?.pages;
        pages.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(pages
            .into_iter()
            .map(|meta| {
                let readable = self.blobs.exists(&meta.version);
                PageEntry { meta, readable }
            })
            .collect())
    }

    /// One page and its body.
    pub fn get(&self, id: &str) -> Result<(PageMeta, Zeroizing<Vec<u8>>), AddonWriteError> {
        let index = self.read_index()?;
        let meta = index.pages.into_iter().find(|p| p.id == id).ok_or(AddonWriteError::NotFound)?;
        let body = self
            .blobs
            .get_bounded(&meta.version, self.limits.max_page_bytes)
            .map_err(AddonWriteError::Store)?;
        Ok((meta, body))
    }

    /// Creates (`id` None, `base_revision` 0) or replaces a page. Returns the
    /// committed record once page and index are both durable. Keeps the
    /// page's site attachment as it is.
    pub fn put(
        &self,
        id: Option<&str>,
        base_revision: u64,
        title: &str,
        body: &[u8],
        now_ms: u64,
    ) -> Result<PageMeta, AddonWriteError> {
        self.put_with_site(id, base_revision, title, body, SiteChange::Keep, now_ms)
    }

    /// `put`, with an explicit change to the page's site attachment.
    pub fn put_with_site(
        &self,
        id: Option<&str>,
        base_revision: u64,
        title: &str,
        body: &[u8],
        site: SiteChange,
        now_ms: u64,
    ) -> Result<PageMeta, AddonWriteError> {
        self.put_in(id, base_revision, title, body, site, None, now_ms)
    }

    /// `put_with_site`, creating the page in `collection`. A collection is
    /// accepted only on a create; an update keeps the page's own.
    #[allow(clippy::too_many_arguments)]
    pub fn put_in(
        &self,
        id: Option<&str>,
        base_revision: u64,
        title: &str,
        body: &[u8],
        site: SiteChange,
        collection: Option<&str>,
        now_ms: u64,
    ) -> Result<PageMeta, AddonWriteError> {
        if let Some(c) = collection {
            if id.is_some() || !valid_collection(c) {
                return Err(AddonWriteError::InvalidCollection);
            }
        }
        if let SiteChange::Set(site) = &site {
            if !valid_site(site) {
                return Err(AddonWriteError::InvalidSite);
            }
        }
        if body.len() > self.limits.max_page_bytes {
            return Err(AddonWriteError::PageTooLarge);
        }
        if std::str::from_utf8(body).is_err() {
            return Err(AddonWriteError::InvalidBody);
        }
        if title.chars().count() > ADDON_MAX_TITLE_CHARS {
            return Err(AddonWriteError::TitleTooLong);
        }
        let mut index = self.read_index()?;
        let (page_id, revision, created, old_version, old_site, collection) = match id {
            None => {
                if base_revision != 0 {
                    return Err(AddonWriteError::Conflict);
                }
                if index.pages.len() >= self.limits.max_pages {
                    return Err(AddonWriteError::TooManyPages);
                }
                (new_page_id(), 1, now_ms, None, None, collection.map(str::to_string))
            }
            Some(id) => {
                let current = index.pages.iter().find(|p| p.id == id).ok_or(AddonWriteError::NotFound)?;
                if current.revision != base_revision {
                    return Err(AddonWriteError::Conflict);
                }
                (
                    id.to_string(),
                    current
                        .revision
                        .checked_add(1)
                        .filter(|next| *next <= ADDON_MAX_REVISION)
                        .ok_or(AddonWriteError::Conflict)?,
                    current.created_at_ms,
                    Some(current.version.clone()),
                    current.site.clone(),
                    current.collection.clone(),
                )
            }
        };
        let site = match site {
            SiteChange::Keep => old_site,
            SiteChange::Set(site) => Some(site),
            SiteChange::Clear => None,
        };
        // The record and the index that will name it, built first so that
        // admission can count the index at its real size.
        let version = version_id(&page_id, revision);
        let meta = PageMeta {
            id: page_id.clone(),
            title: title.to_string(),
            revision,
            created_at_ms: created,
            updated_at_ms: now_ms,
            body_bytes: body.len() as u64,
            version: version.clone(),
            site,
            collection,
        };
        index.pages.retain(|p| p.id != page_id);
        index.pages.push(meta.clone());
        let index_len = Zeroizing::new(serde_json::to_vec(&index).map_err(|e| StoreError::BadFormat(e.to_string()))?).len();
        if index_len > ADDON_MAX_INDEX_BYTES {
            return Err(AddonWriteError::QuotaExceeded);
        }
        // Admission: what is on disk now, plus the new version, plus the
        // replacement index beside the old one while it is replaced.
        let needed = self
            .used_bytes()?
            .saturating_add(BlobStore::stored_len(body.len()))
            .saturating_add(BlobStore::stored_len(index_len));
        if needed > self.limits.quota_bytes {
            return Err(AddonWriteError::QuotaExceeded);
        }
        // 1. The new version.
        self.blobs.put(&version, body)?;
        sync_dir(&self.dir)?;
        #[cfg(test)]
        if crash_at(Crash::AfterVersion) {
            return Err(AddonWriteError::Store(StoreError::BadFormat("test crash".into())));
        }
        // 2. The index that names it.
        let durable = match self.write_index(&index) {
            Ok(durable) => durable,
            Err(e) => {
                let _ = self.blobs.delete(&meta.version);
                return Err(e);
            }
        };
        #[cfg(test)]
        if crash_at(Crash::AfterIndex) {
            return Ok(meta);
        }
        // 4. The old version, best effort and only behind a durable index: a
        // leftover is removed by `recover`.
        if let (true, Some(old)) = (durable, old_version) {
            let _ = self.blobs.delete(&old);
        }
        Ok(meta)
    }

    /// Removes a page: the index first, then its body.
    pub fn delete(&self, id: &str, base_revision: u64) -> Result<(), AddonWriteError> {
        let mut index = self.read_index()?;
        let current = index.pages.iter().find(|p| p.id == id).ok_or(AddonWriteError::NotFound)?;
        if current.revision != base_revision {
            return Err(AddonWriteError::Conflict);
        }
        let version = current.version.clone();
        index.pages.retain(|p| p.id != id);
        if self.write_index(&index)? {
            let _ = self.blobs.delete(&version);
        }
        Ok(())
    }

    /// Run when the add-on opens: removes page versions the index does not
    /// name and abandoned temporary files, within this namespace only.
    /// Returns the ids of pages the index names but whose body is missing.
    ///
    /// An index that cannot be read removes NOTHING, and a missing one
    /// removes no page version: a sweep against a damaged or lost index
    /// would delete every page.
    pub fn recover(&self) -> Result<Vec<String>, AddonWriteError> {
        let indexed = self.blobs.exists(INDEX_ID);
        let index = self.read_index()?;
        let keep: std::collections::BTreeSet<&str> = index.pages.iter().map(|p| p.version.as_str()).collect();
        for id in self.blobs.ids()? {
            if indexed && id.starts_with("p-") && !keep.contains(id.as_str()) {
                let _ = self.blobs.delete(&id);
            }
        }
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_str().is_some_and(|n| n.starts_with(".tmp-")) && entry.file_type().is_ok_and(|t| t.is_file()) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Ok(index
            .pages
            .iter()
            .filter(|p| !self.blobs.exists(&p.version))
            .map(|p| p.id.clone())
            .collect())
    }

    /// Removes the whole namespace ("Delete add-on data").
    pub fn delete_all(self) -> Result<(), StoreError> {
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

// ---- the Vault backup: pages carried as data, never code -----------------------
//
// An export reads each page's body by the version the index names and writes
// the index last, naming exactly the versions it wrote; a page saved or deleted
// meanwhile is read again or left out, so nothing pins the namespace and no
// write waits for a backup. A restore fills a NEW Library's namespace (a staged
// one) and accepts the index only when it names exactly the versions written,
// each checked as `put` checks a page.

/// The section name of an add-on's index in a backup: `<id>/index`. Its pages
/// are `<id>/<version>`.
pub const ADDON_BACKUP_INDEX: &str = "index";

/// The add-on namespaces beside a Library, by id, sorted: every folder under
/// `addons/` whose name an add-on can have; other names are neither carried
/// nor touched. No `addons/` folder is none. A folder that cannot be listed,
/// or an entry with an add-on's name that is not a real folder (a link is
/// never followed), is an error: never to be taken for "no add-on data".
pub fn addon_ids(store_path: &Path) -> Result<Vec<String>, StoreError> {
    let entries = match fs::read_dir(addons_dir(store_path)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::Io(e)),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !addon_id_ok(&name) {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Err(StoreError::BadFormat(format!("add-on folder {name} is not a real folder")));
        }
        ids.push(name);
    }
    ids.sort();
    Ok(ids)
}

/// The highest revision a page may carry: far beyond any real page's saves,
/// and well short of where `revision + 1` could overflow.
const ADDON_MAX_REVISION: u64 = 1 << 53;

/// `p-<page id>-<revision>`, exactly as `version_id` writes it, with a revision
/// a save can have reached: from 1, and with room for the next save.
fn version_ok(name: &str) -> bool {
    let Some((page, revision)) = name.strip_prefix("p-").and_then(|rest| rest.rsplit_once('-')) else {
        return false;
    };
    page_id_ok(page)
        && revision
            .parse::<u64>()
            .is_ok_and(|r| (1..=ADDON_MAX_REVISION).contains(&r) && version_id(page, r) == name)
}

/// What one page body adds to an add-on's stored size: what both the export
/// and the restore count against [`ADDON_QUOTA_BYTES`].
pub fn addon_stored_len(plaintext_len: usize) -> u64 {
    BlobStore::stored_len(plaintext_len)
}

/// The index a backup carries for `pages`: what [`AddonRestore::finish`] reads.
pub fn addon_backup_index(pages: &[PageMeta]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let index = Index { schema: 1, pages: pages.to_vec() };
    Ok(Zeroizing::new(serde_json::to_vec(&index).map_err(|e| StoreError::BadFormat(e.to_string()))?))
}

impl PageMeta {
    /// The blob holding this revision's body, which a backup section carrying
    /// it is named after.
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl Store {
    /// What an export needs to read every add-on namespace on a worker: the id
    /// and the scoped key and path of each. Nothing here borrows the Store.
    pub fn addon_backup_inputs(&self) -> Result<Vec<(String, AddonNamespaceInput)>, StoreError> {
        addon_ids(self.path())?
            .into_iter()
            .map(|id| self.addon_namespace_input(&id).map(|input| (id, input)))
            .collect()
    }

    /// What a restore needs to fill this Library's add-on namespaces while the
    /// Library itself is being restored. Taken first, since the Library's own
    /// restore holds it.
    pub fn addon_restorer(&self) -> AddonRestorer {
        AddonRestorer {
            dir: addons_dir(self.path()),
            key: Zeroizing::new(*self.data_key()),
        }
    }

    /// Every add-on index beside this Library opens under its key. A Library
    /// moved into place by an import is judged by this too: an index left
    /// under the replaced Library's key does not open.
    pub fn addon_indexes_open(&self) -> bool {
        addon_ids(self.path()).is_ok_and(|ids| {
            ids.iter().all(|id| {
                self.addon_namespace(id).is_ok_and(|ns| match ns.has_index() {
                    Ok(true) => ns.read_index().is_ok(),
                    Ok(false) => true,
                    Err(_) => false,
                })
            })
        })
    }
}

impl AddonNamespace {
    /// Whether this namespace has an index. `Ok(false)` only when nothing at
    /// all is there by that name; anything there that is not a regular file,
    /// or that cannot be looked at, is an unreadable index, never "none".
    fn has_index(&self) -> Result<bool, AddonWriteError> {
        match fs::symlink_metadata(self.dir.join(INDEX_ID)) {
            Ok(meta) if meta.is_file() => Ok(true),
            Ok(_) => Err(AddonWriteError::IndexUnreadable),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(AddonWriteError::IndexUnreadable),
        }
    }

    /// The pages a backup carries, as the index names them now, by id.
    /// `Ok(None)`: no index was ever written, so there is nothing to carry.
    pub fn backup_pages(&self) -> Result<Option<Vec<PageMeta>>, AddonWriteError> {
        if !self.has_index()? {
            return Ok(None);
        }
        let mut pages = self.read_index()?.pages;
        pages.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Some(pages))
    }

    /// The body of exactly the version `meta` names. `Ok(None)`: that version
    /// is not there (a later save or a delete replaced it since the index was
    /// read). A body that is there but does not open, or is not the size the
    /// index records, is an error.
    pub fn backup_body(&self, meta: &PageMeta) -> Result<Option<Zeroizing<Vec<u8>>>, AddonWriteError> {
        match self.blobs.get_bounded(&meta.version, ADDON_MAX_PAGE_BYTES) {
            Ok(body) if body.len() as u64 == meta.body_bytes => Ok(Some(body)),
            Ok(_) => Err(AddonWriteError::Store(StoreError::BadFormat("a page that is not its recorded size".into()))),
            Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AddonWriteError::Store(e)),
        }
    }
}

/// A Library's add-on folder and key, for [`AddonRestorer::begin`].
pub struct AddonRestorer {
    dir: PathBuf,
    key: Zeroizing<[u8; crypto::KEY_LEN]>,
}

impl AddonRestorer {
    /// Starts restoring add-on `id`. Refused when its namespace already
    /// exists: a restore only ever fills a new Library, once per add-on.
    pub fn begin(&self, id: &str) -> Result<AddonRestore, crate::BackupError> {
        self.begin_with(id, AddonLimits::default())
    }

    /// [`AddonRestorer::begin`] with other limits: tests reach every bound
    /// with small ones.
    pub(crate) fn begin_with(&self, id: &str, limits: AddonLimits) -> Result<AddonRestore, crate::BackupError> {
        if !addon_id_ok(id) {
            return Err(crate::BackupError::Invalid("an add-on section with an unusable add-on id".into()));
        }
        let dir = self.dir.join(id);
        if fs::symlink_metadata(&dir).is_ok() {
            return Err(crate::BackupError::Invalid(format!("add-on {id} appears twice")));
        }
        let blobs = BlobStore::open(&dir, &namespace_key(&self.key, id))?;
        Ok(AddonRestore {
            ns: AddonNamespace { dir, blobs, limits },
            written: std::collections::BTreeMap::new(),
            stored: 0,
        })
    }
}

/// One add-on's pages being written back from a backup. Every page is
/// checked as `put` checks one; the index comes last.
pub struct AddonRestore {
    ns: AddonNamespace,
    /// Version name to body size, for every page written.
    written: std::collections::BTreeMap<String, u64>,
    stored: u64,
}

impl AddonRestore {
    pub fn put_version(&mut self, version: &str, body: &[u8]) -> Result<(), crate::BackupError> {
        use crate::BackupError::{Invalid, OverLimit};
        if !version_ok(version) {
            return Err(Invalid("an add-on page with an unusable name".into()));
        }
        if self.written.contains_key(version) {
            return Err(Invalid("an add-on page appears twice".into()));
        }
        if self.written.len() >= self.ns.limits.max_pages {
            return Err(OverLimit(format!("more than {} pages in one add-on", self.ns.limits.max_pages)));
        }
        if body.len() > self.ns.limits.max_page_bytes {
            return Err(OverLimit("an add-on page larger than one may be".into()));
        }
        if std::str::from_utf8(body).is_err() {
            return Err(Invalid("an add-on page that is not text".into()));
        }
        let stored = self.stored.saturating_add(BlobStore::stored_len(body.len()));
        if stored > self.ns.limits.quota_bytes {
            return Err(OverLimit("more add-on data than one add-on may hold".into()));
        }
        self.ns.blobs.put(version, body)?;
        self.stored = stored;
        self.written.insert(version.to_string(), body.len() as u64);
        Ok(())
    }

    /// Checks the index against the pages written and writes it: the add-on
    /// is restored. Returns how many pages it holds.
    pub fn finish(self, index: &[u8]) -> Result<usize, crate::BackupError> {
        use crate::BackupError::{Invalid, OverLimit};
        if index.len() > ADDON_MAX_INDEX_BYTES
            || self.stored.saturating_add(BlobStore::stored_len(index.len())) > self.ns.limits.quota_bytes
        {
            return Err(OverLimit("an add-on index larger than one may be".into()));
        }
        let parsed: Index = serde_json::from_slice(index).map_err(|_| Invalid("an add-on index that is unreadable".into()))?;
        // What `read_index` requires of an index, what `put` requires of each
        // page, and exactly the pages written: no more, no fewer.
        let mut seen = std::collections::BTreeSet::new();
        let sound = parsed.schema == 1
            && parsed.pages.len() == self.written.len()
            && parsed.pages.iter().all(|p| {
                page_id_ok(&p.id)
                    && p.version == version_id(&p.id, p.revision)
                    && seen.insert(p.id.clone())
                    && p.title.chars().count() <= ADDON_MAX_TITLE_CHARS
                    && p.site.as_deref().is_none_or(valid_site)
                    && p.collection.as_deref().is_none_or(valid_collection)
                    && self.written.get(&p.version) == Some(&p.body_bytes)
            });
        if !sound {
            return Err(Invalid("an add-on index that does not match its pages".into()));
        }
        match self.ns.write_index(&parsed) {
            Ok(true) => Ok(parsed.pages.len()),
            Ok(false) => Err(crate::BackupError::Store(StoreError::Io(std::io::Error::other("add-on folder flush failed")))),
            Err(AddonWriteError::Store(e)) => Err(crate::BackupError::Store(e)),
            Err(_) => Err(OverLimit("an add-on index larger than one may be".into())),
        }
    }
}

// ---- test-only crash points --------------------------------------------------

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Crash {
    AfterVersion,
    AfterIndex,
    IndexFlush,
}

#[cfg(test)]
thread_local! {
    pub(crate) static CRASH: std::cell::Cell<Option<Crash>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn crash_at(point: Crash) -> bool {
    CRASH.with(|c| {
        if c.get() == Some(point) {
            c.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
#[path = "addon_tests.rs"]
mod tests;
