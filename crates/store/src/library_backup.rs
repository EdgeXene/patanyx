//! The Library half of a Vault backup.
//!
//! A Vault backup carries everything connected to the Vault, so that importing
//! it on another computer brings back what the person chose to keep, not only
//! their passwords. The vault writes and reads the backup file; this module is
//! the Library's side of it: what is taken out at export, how it is checked,
//! and how it is put back.
//!
//! # What travels
//!
//! Bookmarks (with tags, Quick Access and recorded digests), the bookmark
//! folder list, shelves with their notes and groups, Deep Recall pages, page
//! snapshots, the pictures of both, and per-site Fingerprint Divergence
//! choices.
//!
//! # What never travels, and has no field here to travel in
//!
//! - **Download records.** They are browsing history: what was fetched, and
//!   when. A backup carried to another computer would be a copy of that
//!   history that nobody asked for. They stay on this computer, and an import
//!   KEEPS them, re-signed under the new Library key
//!   ([`RestoreInProgress::commit`]).
//! - **The version 1 salt.** With an old passphrase it derives an old key.
//!
//! # Why a backup is treated as untrusted input
//!
//! A backup may come from another computer, or from someone else. Everything
//! is checked by [`validate_backup`] before anything is written, and a backup
//! that fails any check is refused whole, never trimmed to fit. The limits are
//! exactly the ones this store enforces on its own writes, so every Library
//! this build can hold restores, and nothing it could not hold gets in.
//!
//! # Why a restore only goes into an empty Library
//!
//! The import builds its Library aside, in a directory of its own, and swaps
//! it in only once everything is written. [`Store::begin_restore`] refuses a
//! Library that already holds anything, so a restore can never merge into, or
//! overwrite, a Library in use.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::model::{
    normalize_folder_name, ArchiveRecord, Bookmark, DivergenceOverride, DownloadRecord,
    PageSnapshot, Shelf, StoreData, SCHEMA_VERSION,
};
use crate::{
    blob, provenance, Store, StoreError, BOOKMARK_TAG_MAX_CHARS,
    MAX_ARCHIVE_BYTES, MAX_ARCHIVE_RECORDS, MAX_PAGE_SNAPSHOTS, MAX_SNAPSHOTS_PER_URL,
    MAX_SNAPSHOT_PICTURE_BYTES, SHELF_NOTE_MAX_CHARS, SNAPSHOT_TEXT_MAX_CHARS,
};

/// The shape of [`LibraryBackup`]. Bump it whenever a field is added to,
/// removed from, or changes meaning in any type the backup carries; a test
/// pins every carried type's keys so that a new field cannot slip in without
/// a decision here. A build refuses a backup whose schema is newer than its
/// own, rather than restoring it with the fields it cannot name dropped.
pub const LIBRARY_BACKUP_SCHEMA: u32 = 1;

/// Most bookmarks a Library holds. Far above real use; it exists so that a
/// backup this build makes is always one it can restore, and so that a
/// crafted backup cannot ask for an unbounded number.
pub const MAX_BOOKMARKS: usize = 100_000;

/// Most characters of text one Deep Recall page holds. OCR of a dense full
/// page is in the tens of thousands; this bound exists for the same two
/// reasons as [`MAX_BOOKMARKS`].
pub const ARCHIVE_TEXT_MAX_CHARS: usize = 1_000_000;

/// Highest shelf number, and next-shelf counter, a backup may carry: far
/// beyond anything one shelf at a time can reach, and far enough below the
/// top that the counter can never run out.
pub const MAX_SHELF_SEQ: u64 = 1 << 53;

/// Largest picture a backup may carry: the largest one this browser can
/// write. The app refuses a capture above 96 MiB of base64, which decodes to
/// 72 MiB; the app's tests pin that its capture limit stays under this one.
pub const MAX_BACKUP_PICTURE_BYTES: u64 = 72 * 1024 * 1024;

/// Everything a Vault backup carries from the Library. There is deliberately
/// no `downloads` field and no `v1_salt`: see the module documentation.
///
/// `deny_unknown_fields` is on the top level so that a field added later is
/// refused by an older build, together with the schema check, instead of
/// being dropped without a word.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryBackup {
    pub schema: u32,
    pub bookmarks: Vec<Bookmark>,
    pub bookmark_folders: Vec<String>,
    pub shelves: Vec<Shelf>,
    pub next_shelf_seq: u64,
    pub archive: Vec<ArchiveRecord>,
    pub page_snapshots: Vec<PageSnapshot>,
    pub divergence_overrides: Vec<DivergenceOverride>,
}

/// Hand-written: a derived Debug would print addresses, titles and the text
/// read off saved pages into any log line or test failure that formatted a
/// backup. Counts are enough to debug with.
impl std::fmt::Debug for LibraryBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibraryBackup")
            .field("schema", &self.schema)
            .field("bookmarks", &self.bookmarks.len())
            .field("bookmark_folders", &self.bookmark_folders.len())
            .field("shelves", &self.shelves.len())
            .field("archive", &self.archive.len())
            .field("page_snapshots", &self.page_snapshots.len())
            .field("divergence_overrides", &self.divergence_overrides.len())
            .finish()
    }
}

/// Why a backup's Library section was refused. The messages never quote what
/// the backup holds (no address, title or text): they name the kind of item
/// and, where useful, its id.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("this backup was made by a newer PATANYX (Library section {0}); update PATANYX, then import it")]
    NewerSchema(u32),
    #[error("this backup's Library section has no usable version")]
    BadSchema,
    #[error("this backup holds more than PATANYX allows: {0}")]
    OverLimit(String),
    #[error("this backup is damaged or was altered: {0}")]
    Invalid(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// What a restore put back, for the result the person sees.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreSummary {
    pub bookmarks: usize,
    pub folders: usize,
    pub shelves: usize,
    pub archive_pages: usize,
    pub snapshots: usize,
    pub pictures: usize,
    pub site_exceptions: usize,
    /// This computer's own download records, kept and re-signed.
    pub downloads_kept: usize,
    /// Download records left behind because they failed their check under the
    /// old key: kept records must be ones the old Library vouched for.
    pub downloads_dropped: usize,
}

/// A backup's Library section that passed [`validate_backup`], with the
/// pictures it names. The only way to start a restore.
pub struct ValidatedBackup {
    backup: LibraryBackup,
    pictures: BTreeSet<String>,
}

impl ValidatedBackup {
    /// The ids of the pictures the backup must deliver, each exactly once.
    pub fn expected_pictures(&self) -> impl Iterator<Item = &str> {
        self.pictures.iter().map(String::as_str)
    }
}

/// True when `id` can name a picture: the blob writer's own check, shared so
/// that a backup can never pass validation with an id the writer refuses
/// (`con`, `nul`, an empty id, upper case, ...).
pub fn is_valid_blob_id(id: &str) -> bool {
    blob::is_valid_id(id)
}

fn invalid(what: impl Into<String>) -> BackupError {
    BackupError::Invalid(what.into())
}

fn over(what: impl Into<String>) -> BackupError {
    BackupError::OverLimit(what.into())
}

/// Whether a carried tag is one the store's own writers could have made.
///
/// Two writers make tags and they differ: tag editing caps at 40 characters
/// and THEN lowercases (one capital can lowercase to two characters, so 40
/// can become 80), while filing into a folder lowercases first and refuses
/// over 40. So the test is the shape both share, not a re-run of either:
/// trimmed, lowercase, not empty, and no longer than lowercasing 40
/// characters can make.
fn tag_is_storable(tag: &str) -> bool {
    !tag.is_empty()
        && tag == tag.trim()
        && tag == tag.to_lowercase()
        && tag.chars().count() <= BOOKMARK_TAG_MAX_CHARS * 3
}

/// A host exactly as `Store::set_divergence_override` would store it.
fn host_is_normalized(host: &str) -> bool {
    !host.is_empty()
        && host == host.trim()
        && host == host.to_ascii_lowercase()
        && !host.contains('/')
        && !host.contains(char::is_whitespace)
}

/// Checks a backup's Library section completely, before anything is written.
/// Everything that would make the restore fail part-way, or put into the
/// Library something this build would never have let in, is refused here.
pub fn validate_backup(backup: LibraryBackup) -> Result<ValidatedBackup, BackupError> {
    match backup.schema {
        0 => return Err(BackupError::BadSchema),
        s if s > LIBRARY_BACKUP_SCHEMA => return Err(BackupError::NewerSchema(s)),
        _ => {}
    }

    // ---- bookmarks ----
    if backup.bookmarks.len() > MAX_BOOKMARKS {
        return Err(over(format!(
            "{} bookmarks, and the limit is {MAX_BOOKMARKS}",
            backup.bookmarks.len()
        )));
    }
    let mut bookmark_urls: BTreeMap<&str, &str> = BTreeMap::new();
    for bookmark in &backup.bookmarks {
        if !is_valid_blob_id(&bookmark.id) {
            return Err(invalid("a bookmark with an unusable id"));
        }
        if bookmark_urls
            .insert(bookmark.id.as_str(), bookmark.url.as_str())
            .is_some()
        {
            return Err(invalid(format!("bookmark {} appears twice", bookmark.id)));
        }
        // No count limit: tag editing keeps 12, but filing into folders has
        // none, so a count limit here would refuse Libraries the store made.
        // The Library section's size limit bounds a crafted backup.
        let mut seen_tags = BTreeSet::new();
        for tag in &bookmark.tags {
            if !tag_is_storable(tag) || !seen_tags.insert(tag.as_str()) {
                return Err(invalid(format!("bookmark {} has an unusable folder name", bookmark.id)));
            }
        }
    }

    // ---- folders ----
    let mut seen_folders = BTreeSet::new();
    for folder in &backup.bookmark_folders {
        if normalize_folder_name(folder).ok().as_deref() != Some(folder.as_str())
            || !seen_folders.insert(folder.as_str())
        {
            return Err(invalid("an unusable or repeated folder name"));
        }
    }

    // ---- shelves ----
    // The counter the next shelf is numbered from must have room to grow.
    if backup.next_shelf_seq > MAX_SHELF_SEQ {
        return Err(invalid("the shelf counter leaves no room for a next shelf"));
    }
    let mut seen_shelf_ids = BTreeSet::new();
    let mut seen_seqs = BTreeSet::new();
    for shelf in &backup.shelves {
        if shelf.id != format!("shelf-{}", shelf.seq) {
            return Err(invalid("a shelf whose id does not match its number"));
        }
        if !seen_shelf_ids.insert(shelf.id.as_str()) || !seen_seqs.insert(shelf.seq) {
            return Err(invalid(format!("{} appears twice", shelf.id)));
        }
        // Restored, the counter goes past the highest shelf; it must still
        // have room to grow from there.
        if shelf.seq >= MAX_SHELF_SEQ {
            return Err(invalid(format!("{} leaves no room for a next shelf", shelf.id)));
        }
        if shelf.note.chars().count() > SHELF_NOTE_MAX_CHARS {
            return Err(over(format!(
                "the note on {} is longer than {SHELF_NOTE_MAX_CHARS} characters",
                shelf.id
            )));
        }
    }

    // ---- Deep Recall ----
    if backup.archive.len() > MAX_ARCHIVE_RECORDS {
        return Err(over(format!(
            "{} Deep Recall pages, and the limit is {MAX_ARCHIVE_RECORDS}",
            backup.archive.len()
        )));
    }
    // Archive pages and snapshots share one picture directory, so their ids
    // must not collide with each other either.
    let mut picture_dir_ids: BTreeSet<&str> = BTreeSet::new();
    let mut pictures = BTreeSet::new();
    for record in &backup.archive {
        if !is_valid_blob_id(&record.id) {
            return Err(invalid("a Deep Recall page with an unusable id"));
        }
        if !picture_dir_ids.insert(record.id.as_str()) {
            return Err(invalid(format!("Deep Recall page {} appears twice", record.id)));
        }
        if record.text.chars().count() > ARCHIVE_TEXT_MAX_CHARS {
            return Err(over(format!(
                "Deep Recall page {} holds more than {ARCHIVE_TEXT_MAX_CHARS} characters of text",
                record.id
            )));
        }
        if record.has_picture {
            pictures.insert(record.id.clone());
        }
    }

    // ---- page snapshots ----
    if backup.page_snapshots.len() > MAX_PAGE_SNAPSHOTS {
        return Err(over(format!(
            "{} page snapshots, and the limit is {MAX_PAGE_SNAPSHOTS}",
            backup.page_snapshots.len()
        )));
    }
    let mut per_url: BTreeMap<&str, usize> = BTreeMap::new();
    for snapshot in &backup.page_snapshots {
        if !is_valid_blob_id(&snapshot.id) {
            return Err(invalid("a page snapshot with an unusable id"));
        }
        if !picture_dir_ids.insert(snapshot.id.as_str()) {
            return Err(invalid(format!("snapshot {} reuses an id", snapshot.id)));
        }
        // The same rule `Store::replace_bookmarks` keeps: a snapshot belongs to
        // a bookmark AT the address it was taken of.
        if bookmark_urls.get(snapshot.bookmark_id.as_str()) != Some(&snapshot.url.as_str()) {
            return Err(invalid(format!(
                "snapshot {} belongs to no bookmark in the backup",
                snapshot.id
            )));
        }
        let count = per_url.entry(snapshot.url.as_str()).or_insert(0);
        *count += 1;
        if *count > MAX_SNAPSHOTS_PER_URL {
            return Err(over(format!(
                "more than {MAX_SNAPSHOTS_PER_URL} snapshots of one page"
            )));
        }
        if let Some(text) = &snapshot.text {
            if text.chars().count() > SNAPSHOT_TEXT_MAX_CHARS {
                return Err(over(format!(
                    "snapshot {} holds more than {SNAPSHOT_TEXT_MAX_CHARS} characters of text",
                    snapshot.id
                )));
            }
        }
        if snapshot.has_picture {
            pictures.insert(snapshot.id.clone());
        }
    }

    // ---- per-site exceptions ----
    let mut seen_hosts = BTreeSet::new();
    for exception in &backup.divergence_overrides {
        if !host_is_normalized(&exception.host) || !seen_hosts.insert(exception.host.as_str()) {
            return Err(invalid("an unusable or repeated site in the site exceptions"));
        }
    }

    Ok(ValidatedBackup { backup, pictures })
}

impl Store {
    /// The Library section of a backup: everything except download records
    /// and the version 1 salt. Pictures are delivered separately, one at a
    /// time ([`Store::backup_picture_ids`], [`Store::backup_picture`]), so a
    /// backup never needs every picture in memory at once.
    pub fn library_backup(&self) -> LibraryBackup {
        LibraryBackup {
            schema: LIBRARY_BACKUP_SCHEMA,
            bookmarks: self.data.bookmarks.clone(),
            bookmark_folders: self.data.bookmark_folders.clone(),
            shelves: self.data.shelves.clone(),
            next_shelf_seq: self.data.next_shelf_seq,
            archive: self.data.archive.clone(),
            page_snapshots: self.data.page_snapshots.clone(),
            divergence_overrides: self.data.divergence_overrides.clone(),
        }
    }

    /// The Library section an export writes: [`Store::library_backup`], with
    /// every record whose picture file is no longer on disk marked as having
    /// none, and how many were marked. A lost picture file must not make the
    /// whole Library impossible to back up, and a record that still claimed
    /// its picture would make the backup refuse itself on import.
    pub fn library_backup_for_export(&self) -> (LibraryBackup, usize) {
        let mut backup = self.library_backup();
        let present = |id: &str| self.blobs().is_ok_and(|blobs| blobs.exists(id));
        let mut left_out = 0;
        for record in &mut backup.archive {
            if record.has_picture && !present(&record.id) {
                record.has_picture = false;
                record.picture_bytes = 0;
                left_out += 1;
            }
        }
        for snapshot in &mut backup.page_snapshots {
            if snapshot.has_picture && !present(&snapshot.id) {
                snapshot.has_picture = false;
                snapshot.picture_bytes = 0;
                snapshot.picture_scope = None;
                left_out += 1;
            }
        }
        (backup, left_out)
    }

    /// How many records claim a picture whose file is not on disk. Zero for a
    /// Library a restore has just written; anything else means its pictures
    /// were not all moved into place.
    pub fn pictures_missing(&self) -> usize {
        self.library_backup_for_export().1
    }

    /// Whether EVERY picture this Library's records name opens under its own
    /// key: a file swapped for another Library's copy of the same id does
    /// not. Each is read with a bound (the largest picture a restore writes),
    /// one at a time, so a damaged or substituted file cannot make this hold
    /// more than one picture. True when it has none.
    pub fn pictures_open(&self) -> bool {
        let Ok(blobs) = self.blobs() else {
            return false;
        };
        let max = MAX_BACKUP_PICTURE_BYTES as usize;
        self.data
            .archive
            .iter()
            .filter(|r| r.has_picture)
            .map(|r| r.id.as_str())
            .chain(
                self.data
                    .page_snapshots
                    .iter()
                    .filter(|s| s.has_picture)
                    .map(|s| s.id.as_str()),
            )
            .all(|id| blobs.get_bounded(id, max).is_ok())
    }

    /// The pictures a backup of this Library carries, Deep Recall first, in
    /// a stable order.
    pub fn backup_picture_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .data
            .archive
            .iter()
            .filter(|record| record.has_picture)
            .map(|record| record.id.clone())
            .collect();
        ids.extend(
            self.data
                .page_snapshots
                .iter()
                .filter(|snapshot| snapshot.has_picture)
                .map(|snapshot| snapshot.id.clone()),
        );
        ids
    }

    /// One decrypted picture, for the backup. Only an id a record names is
    /// served: this is not a way to read arbitrary files in the directory.
    pub fn backup_picture(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let named = self
            .data
            .archive
            .iter()
            .any(|record| record.has_picture && record.id == id)
            || self
                .data
                .page_snapshots
                .iter()
                .any(|snapshot| snapshot.has_picture && snapshot.id == id);
        if !named {
            return Err(StoreError::NotFound(format!("no picture {id}")));
        }
        self.blobs()?.get(id)
    }

    /// The pictures an export of this Library reads, taken now so a worker
    /// thread can read them while the Store stays with the app. Like
    /// [`Store::backup_picture`], only ids the records name are served.
    pub fn backup_pictures(&self) -> Result<BackupPictures, StoreError> {
        Ok(BackupPictures {
            blobs: self.blobs()?,
            named: self.backup_picture_ids().into_iter().collect(),
        })
    }

    /// The download records an import keeps from this Library, taken now:
    /// the ones that still check under its key, and how many did not. See
    /// [`RestoreInProgress::commit_keeping`].
    pub fn kept_downloads(&self) -> KeptDownloads {
        let records = self.verified_downloads();
        let dropped = self.data.downloads.len() - records.len();
        KeptDownloads { records, dropped }
    }

    /// Download records whose signature still checks under this Library's
    /// key. Only these are carried over to a new Library on import.
    pub fn verified_downloads(&self) -> Vec<DownloadRecord> {
        self.data
            .downloads
            .iter()
            .filter(|record| provenance::verify(&self.provenance_key, record))
            .cloned()
            .collect()
    }

    /// Starts restoring a validated backup into THIS Library, which must be
    /// empty: the one an import has just created aside for the purpose.
    pub fn begin_restore(
        &mut self,
        validated: ValidatedBackup,
    ) -> Result<RestoreInProgress<'_>, BackupError> {
        let empty = self.data == StoreData::default();
        if !empty {
            return Err(invalid("a backup is only restored into a new, empty Library"));
        }
        let ValidatedBackup { backup, pictures } = validated;
        Ok(RestoreInProgress {
            store: self,
            backup,
            expected: pictures,
            written: BTreeMap::new(),
            archive_bytes: 0,
            snapshot_bytes: 0,
            archive_limit: MAX_ARCHIVE_BYTES,
            snapshot_limit: MAX_SNAPSHOT_PICTURE_BYTES,
        })
    }
}

/// A restore that has started: pictures are added one by one with
/// [`RestoreInProgress::put_picture`], then [`RestoreInProgress::commit`]
/// writes everything else in one save.
///
/// Dropping it without committing leaves pictures in this Library's
/// directory and nothing in the Library itself. That directory belongs to the
/// import, which deletes it when the import does not complete.
pub struct RestoreInProgress<'a> {
    store: &'a mut Store,
    backup: LibraryBackup,
    expected: BTreeSet<String>,
    written: BTreeMap<String, u64>,
    /// Running totals, as stored, of the two picture budgets, and the
    /// budgets themselves (crate-visible so a test can lower them and
    /// exercise accumulation with small pictures).
    pub(crate) archive_bytes: u64,
    pub(crate) snapshot_bytes: u64,
    pub(crate) archive_limit: u64,
    pub(crate) snapshot_limit: u64,
}

impl RestoreInProgress<'_> {
    /// Encrypts one picture under this Library's key and writes it. Only a
    /// picture the backup's records name is accepted, each exactly once.
    pub fn put_picture(&mut self, id: &str, plaintext: &[u8]) -> Result<(), BackupError> {
        if !self.expected.contains(id) {
            return Err(invalid("a picture that no saved page names"));
        }
        if self.written.contains_key(id) {
            return Err(invalid(format!("picture {id} appears twice")));
        }
        if plaintext.len() as u64 > MAX_BACKUP_PICTURE_BYTES {
            return Err(over(format!(
                "picture {id} is larger than {} MB",
                MAX_BACKUP_PICTURE_BYTES / (1024 * 1024)
            )));
        }
        // Each budget is enforced as pictures arrive, before one is written:
        // a crafted backup must not fill the disk with pictures this restore
        // will refuse at the end anyway.
        let incoming = blob::BlobStore::stored_len(plaintext.len());
        let is_page = self.backup.archive.iter().any(|record| record.id == id);
        let (total, limit, what) = if is_page {
            (&mut self.archive_bytes, self.archive_limit, "Deep Recall pictures")
        } else {
            (&mut self.snapshot_bytes, self.snapshot_limit, "page snapshot pictures")
        };
        if total.saturating_add(incoming) > limit {
            return Err(over(format!(
                "{what} pass the limit of {} MB",
                limit / (1024 * 1024)
            )));
        }
        let stored = self.store.blobs()?.put(id, plaintext)?;
        *total = total.saturating_add(stored);
        self.written.insert(id.to_string(), stored);
        Ok(())
    }

    /// Writes the restored Library in ONE save, after checking that every
    /// picture arrived and that the pictures, as actually stored, fit this
    /// build's limits.
    ///
    /// `keep_downloads_from` is the Library being replaced. Its download
    /// records that still check under ITS key are re-signed under this one and
    /// kept: they never travel in a backup, and an import does not erase this
    /// computer's own history. A record that fails its check is left behind,
    /// never re-signed, since signing it would vouch for it.
    ///
    /// On failure, nothing is left in this Library, and the pictures written
    /// so far are deleted again.
    pub fn commit(self, keep_downloads_from: Option<&Store>) -> Result<RestoreSummary, BackupError> {
        let kept = keep_downloads_from.map(Store::kept_downloads);
        self.commit_keeping(kept.as_ref())
    }

    /// [`RestoreInProgress::commit`], with the records to keep taken earlier
    /// ([`Store::kept_downloads`]), so the Library being replaced need not be
    /// open, or on this thread, when the restore finishes.
    pub fn commit_keeping(self, keep: Option<&KeptDownloads>) -> Result<RestoreSummary, BackupError> {
        let RestoreInProgress {
            store,
            mut backup,
            expected,
            written,
            ..
        } = self;

        let undo = |store: &Store, written: &BTreeMap<String, u64>| {
            if let Ok(blobs) = store.blobs() {
                for id in written.keys() {
                    let _ = blobs.delete(id);
                }
            }
        };

        if let Some(missing) = expected.iter().find(|id| !written.contains_key(*id)) {
            undo(store, &written);
            return Err(invalid(format!("picture {missing} is missing from the backup")));
        }

        // Record what is actually on disk, never what the backup claims: the
        // byte limits below are judged against these.
        for record in &mut backup.archive {
            record.picture_bytes = written.get(&record.id).copied().unwrap_or(0);
        }
        for snapshot in &mut backup.page_snapshots {
            if snapshot.has_picture {
                snapshot.picture_bytes = written.get(&snapshot.id).copied().unwrap_or(0);
            } else {
                snapshot.picture_bytes = 0;
                snapshot.picture_scope = None;
            }
        }
        let archive_bytes: u64 = backup.archive.iter().map(|r| r.picture_bytes).sum();
        if archive_bytes > MAX_ARCHIVE_BYTES {
            undo(store, &written);
            return Err(over(format!(
                "Deep Recall pictures pass the limit of {} MB",
                MAX_ARCHIVE_BYTES / (1024 * 1024)
            )));
        }
        let snapshot_bytes: u64 = backup.page_snapshots.iter().map(|s| s.picture_bytes).sum();
        if snapshot_bytes > MAX_SNAPSHOT_PICTURE_BYTES {
            undo(store, &written);
            return Err(over(format!(
                "page snapshot pictures pass the limit of {} MB",
                MAX_SNAPSHOT_PICTURE_BYTES / (1024 * 1024)
            )));
        }

        let (downloads, downloads_dropped) = match keep {
            None => (Vec::new(), 0),
            Some(kept) => {
                let dropped = kept.dropped;
                let resigned = kept
                    .records
                    .iter()
                    .cloned()
                    .map(|mut record| {
                        record.hmac = provenance::record_mac(
                            &store.provenance_key,
                            &record.id,
                            &record.url,
                            &record.filename,
                            record.byte_len,
                            &record.sha256,
                            record.recorded_at,
                        );
                        record
                    })
                    .collect::<Vec<_>>();
                (resigned, dropped)
            }
        };

        let highest_seq = backup.shelves.iter().map(|shelf| shelf.seq).max();
        let next_shelf_seq = match highest_seq {
            Some(highest) => backup.next_shelf_seq.max(highest + 1),
            None => backup.next_shelf_seq,
        };

        let summary = RestoreSummary {
            bookmarks: backup.bookmarks.len(),
            folders: backup.bookmark_folders.len(),
            shelves: backup.shelves.len(),
            archive_pages: backup.archive.len(),
            snapshots: backup.page_snapshots.len(),
            pictures: written.len(),
            site_exceptions: backup.divergence_overrides.len(),
            downloads_kept: downloads.len(),
            downloads_dropped,
        };

        store.data = StoreData {
            schema: SCHEMA_VERSION,
            bookmarks: backup.bookmarks,
            bookmark_folders: backup.bookmark_folders,
            downloads,
            shelves: backup.shelves,
            next_shelf_seq,
            archive: backup.archive,
            page_snapshots: backup.page_snapshots,
            divergence_overrides: backup.divergence_overrides,
            v1_salt: None,
        };
        if let Err(error) = store.save() {
            store.data = StoreData::default();
            undo(store, &written);
            return Err(error.into());
        }
        Ok(summary)
    }
}

/// The pictures an export reads, separate from the [`Store`] they came from
/// ([`Store::backup_pictures`]): a worker thread reads them while the Store
/// stays with the app. Serves only the ids the records named when it was
/// taken; a picture deleted since then is `NotFound`.
pub struct BackupPictures {
    blobs: crate::blob::BlobStore,
    named: BTreeSet<String>,
}

impl BackupPictures {
    pub fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if !self.named.contains(id) {
            return Err(StoreError::NotFound(format!("no picture {id}")));
        }
        self.blobs.get(id)
    }
}

impl std::fmt::Debug for BackupPictures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupPictures").field("named", &self.named.len()).finish()
    }
}

/// Download records an import keeps from the Library it replaces
/// ([`Store::kept_downloads`]). They never travel in a backup; these are this
/// computer's own, re-signed under the new Library's key at the commit.
/// Prints counts only: a record is browsing history.
pub struct KeptDownloads {
    records: Vec<DownloadRecord>,
    dropped: usize,
}

impl KeptDownloads {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Records left behind because their signature no longer checked.
    pub fn dropped(&self) -> usize {
        self.dropped
    }
}

impl std::fmt::Debug for KeptDownloads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptDownloads")
            .field("records", &self.records.len())
            .field("dropped", &self.dropped)
            .finish()
    }
}
