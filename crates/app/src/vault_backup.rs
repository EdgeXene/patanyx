//! The Vault backup: one encrypted file holding the vault and the whole
//! Library, written by [`export`] and read back by [`stage`].
//!
//! # What it carries
//!
//! The vault, then the Library's records (bookmarks, bookmark folders, shelved
//! tab groups and their notes, Deep Recall pages, page snapshots and per-site
//! exceptions), then each picture as a section of its own, so a backup never
//! needs every picture in memory at once. Download records never go in: they
//! are browsing history, and they stay on the computer that made them
//! (`patanyx_store::library_backup`). An import keeps this computer's own.
//!
//! # How an import replaces two files with no moment in which either is lost
//!
//! The vault and the Library are separate encrypted files, and no filesystem
//! replaces two files at once. So an import works in phases, and a replacement
//! journal beside the Library file records which one was reached:
//!
//! 1. `preparing`: the backup is read ONCE, start to end. The vault in it stays
//!    in memory, and a new Library is built under that vault's key in a staging
//!    folder of its own beside the live one. Nothing live is touched, and the
//!    file is never read a second time, so what is installed is exactly what
//!    was checked.
//! 2. `staged`: everything checked, END included. The journal now holds a
//!    check value of the imported vault's Library key.
//! 3. The imported vault replaces the old one: the commit point.
//!    `vault_committed`.
//! 4. The staged Library moves into place: the live picture folder aside, the
//!    staged one in, the staged Library file over the live one. `swapped`.
//! 5. Leftovers are deleted and the journal goes.
//!
//! The Library is only ever opened through `AppState::open_store`, which runs
//! [`recover`] first whenever a journal exists. Recovery needs the vault that
//! is open, because the question it has to answer, whether step 3 happened, is
//! answered by comparing that vault's Library key with the check value. If
//! they match, the vault on disk is the imported one and the move is finished.
//! If not, the staging folder is deleted and the live Library, never touched,
//! opens as before. A file's timestamp or contents cannot answer that question
//! reliably (an ordinary save in another window changes both); the key can.
//!
//! An import that starts while an earlier one is still unresolved does not
//! throw the earlier one away: its journal is kept inside the new one, put
//! back if the new import fails, and its folders deleted if the new import
//! completes, since everything they held has then been replaced.
//!
//! # Why the journal can only ever name its own folders
//!
//! Recovery renames and deletes the folders a journal names, so a journal is
//! read as untrusted input: a name must be exactly `library-staging-` or
//! `archive.old-` followed by 16 hex digits, which can only mean a folder
//! beside the Library file that an import created.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use patanyx_store::{
    validate_backup, BackupError, BackupPictures, KeptDownloads, LibraryBackup, RestoreSummary,
    Store, StoreError,
    ARCHIVE_TEXT_MAX_CHARS, LIBRARY_BACKUP_SCHEMA, MAX_ARCHIVE_BYTES, MAX_BACKUP_PICTURE_BYTES,
    MAX_BOOKMARKS, MAX_SNAPSHOT_PICTURE_BYTES,
};
use patanyx_vault::{
    BackupReader, BackupSource, BackupWatch, ExportError, PendingImport, RecoveryKey, SectionKind,
    SectionLimits, Vault,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MIB: u64 = 1024 * 1024;

/// Largest Library section (the records, without pictures) a backup may
/// carry. Real Libraries come to a few megabytes. It bounds what a crafted
/// backup can make an import hold in memory, and the export checks it too, so
/// this build never writes a backup it would then refuse.
pub const MAX_LIBRARY_SECTION: u64 = 512 * MIB;

/// What each kind of section may weigh, checked before its body is read.
///
/// Add-on sections are not read yet (0): no add-on writes them in this build,
/// and the reader then answers that a newer PATANYX made the file.
pub fn section_limits() -> SectionLimits {
    SectionLimits {
        library: MAX_LIBRARY_SECTION,
        picture: MAX_BACKUP_PICTURE_BYTES,
        addon: 0,
    }
}

// ---- export -------------------------------------------------------------------

/// What an export put in the file, for the result the person sees.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExportSummary {
    /// False when no Library was open: the file then holds the vault alone.
    pub library_included: bool,
    pub bookmarks: usize,
    pub folders: usize,
    pub tab_groups: usize,
    pub deep_recall_pages: usize,
    pub snapshots: usize,
    pub pictures: usize,
    pub site_exceptions: usize,
    /// Pictures whose file was no longer on disk. Their pages travel without
    /// them.
    pub pictures_left_out: usize,
}

#[derive(Debug)]
pub enum ExportOutcome {
    Written(ExportSummary),
    /// The Library holds something this build could not import back, so no
    /// backup was written.
    Refused(ExportRefusal),
}

/// Why an export wrote nothing, as a code the chrome words, and the item in
/// the way, by the title or address the person knows it by, where there is
/// one item to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRefusal {
    pub code: &'static str,
    pub item: Option<String>,
}


/// Writes a backup of the vault and, when one is open, its Library, at once:
/// [`ExportInput::take`] then [`ExportInput::write`] with a watch nobody
/// stops.
// Tests only: the app goes through the job's own entry points.
#[cfg(test)]
pub fn export(
    vault: &Vault,
    library: Option<&Store>,
    dest: &Path,
    passphrase: &str,
) -> Result<ExportOutcome, ExportError> {
    ExportInput::take(vault, library)?.write(dest, passphrase, &BackupWatch::new())
}

/// Everything an export needs, taken on the UI thread so the export itself
/// can run on a worker: the vault's contents, the Library's records as they
/// are now, and a reader for its pictures. Nothing in it borrows the Vault or
/// the Store, so the Library can change while the backup is written; a
/// picture deleted meanwhile refuses the export by name
/// (`export_library_changed`) rather than writing records that name it.
pub struct ExportInput {
    source: BackupSource,
    library: Option<ExportLibrary>,
}

struct ExportLibrary {
    backup: LibraryBackup,
    pictures_left_out: usize,
    pictures: BackupPictures,
}

impl std::fmt::Debug for ExportInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportInput")
            .field("library", &self.library.is_some())
            .finish_non_exhaustive()
    }
}

impl ExportInput {
    /// Cheap: no encryption, no picture read. The Library's records are
    /// copied, so this holds them in memory as an export always has.
    pub fn take(vault: &Vault, library: Option<&Store>) -> Result<Self, ExportError> {
        let source = vault.backup_source()?;
        let library = match library {
            None => None,
            Some(store) => {
                let (backup, pictures_left_out) = store.library_backup_for_export();
                let pictures = store
                    .backup_pictures()
                    .map_err(|e| ExportError::BadExport(format!("library pictures: {e}")))?;
                Some(ExportLibrary {
                    backup,
                    pictures_left_out,
                    pictures,
                })
            }
        };
        Ok(Self { source, library })
    }

    /// Writes the backup. Before anything is written, the Library goes
    /// through the same checks an import applies, so this build never
    /// produces a backup it would refuse: a Library created before a limit
    /// existed is told which item is over it. The vault crate then reads the
    /// finished file back before it is renamed into place
    /// ([`BackupSource::write`]). `watch` reports progress and stops the work
    /// at its next check: before each picture, and per segment.
    pub fn write(
        self,
        dest: &Path,
        passphrase: &str,
        watch: &BackupWatch,
    ) -> Result<ExportOutcome, ExportError> {
        self.write_watched(dest, passphrase, watch, &mut |_| {})
    }

    /// [`ExportInput::write`], calling `before_picture` with each picture's
    /// index before it is read. Tests use it to stop or change the Library at
    /// an exact point.
    fn write_watched(
        self,
        dest: &Path,
        passphrase: &str,
        watch: &BackupWatch,
        before_picture: &mut dyn FnMut(usize),
    ) -> Result<ExportOutcome, ExportError> {
        let ExportInput { source, library } = self;
        let Some(ExportLibrary {
            backup,
            pictures_left_out,
            pictures: reader,
        }) = library
        else {
            source.write(dest, passphrase, section_limits(), &mut |_| Ok(()), watch)?;
            return Ok(ExportOutcome::Written(ExportSummary::default()));
        };
        let pictures = picture_ids(&backup);
        let summary = ExportSummary {
            library_included: true,
            bookmarks: backup.bookmarks.len(),
            folders: backup.bookmark_folders.len(),
            tab_groups: backup.shelves.len(),
            deep_recall_pages: backup.archive.len(),
            snapshots: backup.page_snapshots.len(),
            pictures: pictures.len(),
            site_exceptions: backup.divergence_overrides.len(),
            pictures_left_out,
        };
        if let Some(refusal) = refusal_for(&backup) {
            return Ok(ExportOutcome::Refused(refusal));
        }
        let records = Zeroizing::new(
            serde_json::to_vec(&backup)
                .map_err(|e| ExportError::BadExport(format!("library encode: {e}")))?,
        );
        if records.len() as u64 > MAX_LIBRARY_SECTION {
            return Ok(ExportOutcome::Refused(ExportRefusal {
                code: "export_library_too_large",
                item: None,
            }));
        }
        // What the progress bar measures against. The pictures' sizes are
        // their stored sizes, close to what is sealed; the bar never shows
        // done before the end.
        let picture_bytes: u64 = backup.archive.iter().map(|r| r.picture_bytes).sum::<u64>()
            + backup.page_snapshots.iter().map(|s| s.picture_bytes).sum::<u64>();
        watch.set_estimate(records.len() as u64 + picture_bytes);
        watch.set_items(0, pictures.len() as u64);

        let mut refusal = None;
        let written = source.write(
            dest,
            passphrase,
            section_limits(),
            &mut |sink| {
                sink.section(SectionKind::Library, "", &records)?;
                for (done, id) in pictures.iter().enumerate() {
                    before_picture(done);
                    watch.check()?;
                    let picture = match reader.read(id) {
                        Ok(picture) => picture,
                        // Deleted after the export started: the records already
                        // written name it, so the backup cannot be finished.
                        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                            refusal = Some(ExportRefusal {
                                code: "export_library_changed",
                                item: Some(name_of(&backup, id)),
                            });
                            return Err(ExportError::BadExport("refused".into()));
                        }
                        // A picture file that is there but will not decrypt
                        // cannot be left out at this point either: an import
                        // would then refuse the whole backup.
                        Err(_) => {
                            refusal = Some(ExportRefusal {
                                code: "export_picture_unreadable",
                                item: Some(name_of(&backup, id)),
                            });
                            return Err(ExportError::BadExport("refused".into()));
                        }
                    };
                    if picture.len() as u64 > MAX_BACKUP_PICTURE_BYTES {
                        refusal = Some(ExportRefusal {
                            code: "export_item_too_large",
                            item: Some(name_of(&backup, id)),
                        });
                        return Err(ExportError::BadExport("refused".into()));
                    }
                    sink.section(SectionKind::Picture, id, &picture)?;
                    watch.set_items(done as u64 + 1, pictures.len() as u64);
                }
                Ok(())
            },
            watch,
        );
        match written {
            Ok(_) => Ok(ExportOutcome::Written(summary)),
            Err(error) => match refusal {
                Some(refusal) => Ok(ExportOutcome::Refused(refusal)),
                None => Err(error),
            },
        }
    }
}

/// The import's own checks, run on what an export is about to write, so this
/// build never writes a backup it would refuse. The limits a Library made
/// before they existed can pass are checked first, so the refusal can say
/// which one; then everything else the import checks.
fn refusal_for(backup: &LibraryBackup) -> Option<ExportRefusal> {
    if backup.bookmarks.len() > MAX_BOOKMARKS {
        return Some(ExportRefusal {
            code: "export_too_many_bookmarks",
            item: None,
        });
    }
    if let Some(page) = backup
        .archive
        .iter()
        .find(|r| r.text.chars().count() > ARCHIVE_TEXT_MAX_CHARS)
    {
        return Some(ExportRefusal {
            code: "export_item_too_large",
            item: Some(name_of(backup, &page.id)),
        });
    }
    // The picture totals, as stored, which a restore re-checks: a Library
    // can sit just over them (the store judged pictures before encryption
    // until 2026-10), and its backup would then be refused on import.
    let stored = |sizes: &mut dyn Iterator<Item = u64>| sizes.sum::<u64>();
    if stored(&mut backup.archive.iter().filter(|r| r.has_picture).map(|r| r.picture_bytes))
        > MAX_ARCHIVE_BYTES
        || stored(&mut backup.page_snapshots.iter().filter(|s| s.has_picture).map(|s| s.picture_bytes))
            > MAX_SNAPSHOT_PICTURE_BYTES
    {
        return Some(ExportRefusal {
            code: "export_library_over_limit",
            item: None,
        });
    }
    let error = validate_backup(backup.clone()).err()?;
    let item = named_in(backup, &error.to_string());
    let code = match (&error, &item) {
        (BackupError::OverLimit(_), Some(_)) => "export_item_too_large",
        (BackupError::OverLimit(_), None) => "export_library_over_limit",
        _ => "export_library_unusable",
    };
    Some(ExportRefusal { code, item })
}

/// The pictures a backup carries, in the order it carries them.
fn picture_ids(backup: &LibraryBackup) -> Vec<String> {
    let pages = backup.archive.iter().filter(|r| r.has_picture).map(|r| r.id.clone());
    let snapshots = backup
        .page_snapshots
        .iter()
        .filter(|s| s.has_picture)
        .map(|s| s.id.clone());
    pages.chain(snapshots).collect()
}

/// How the person would recognize the item with `id`: its title, or its
/// address when it has none. Shown only in the chrome, never logged.
fn name_of(backup: &LibraryBackup, id: &str) -> String {
    let titled = |title: &str, url: &str| {
        if title.trim().is_empty() {
            url.to_string()
        } else {
            title.to_string()
        }
    };
    if let Some(page) = backup.archive.iter().find(|r| r.id == id) {
        return titled(&page.title, &page.url);
    }
    // A snapshot goes when its bookmark is deleted, so the bookmark is what
    // the person is pointed to.
    if let Some(snapshot) = backup.page_snapshots.iter().find(|s| s.id == id) {
        return match backup.bookmarks.iter().find(|b| b.id == snapshot.bookmark_id) {
            Some(bookmark) => titled(&bookmark.title, &bookmark.url),
            None => snapshot.url.clone(),
        };
    }
    if let Some(bookmark) = backup.bookmarks.iter().find(|b| b.id == id) {
        return titled(&bookmark.title, &bookmark.url);
    }
    if let Some(shelf) = backup.shelves.iter().find(|s| s.id == id) {
        return shelf.name.clone();
    }
    id.to_string()
}

/// The store's checks name records by id, which the person never sees: the
/// first record `reason` mentions, by the name they know it by.
fn named_in(backup: &LibraryBackup, reason: &str) -> Option<String> {
    backup
        .archive
        .iter()
        .map(|r| r.id.as_str())
        .chain(backup.page_snapshots.iter().map(|s| s.id.as_str()))
        .chain(backup.shelves.iter().map(|s| s.id.as_str()))
        .chain(backup.bookmarks.iter().map(|b| b.id.as_str()))
        .find(|id| mentions(reason, id))
        .map(|id| name_of(backup, id))
}

/// Whether `reason` names `id` as a whole word: `shelf-1` is not named by a
/// message about `shelf-12`.
fn mentions(reason: &str, id: &str) -> bool {
    let part_of_id = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    !id.is_empty()
        && reason.match_indices(id).any(|(at, _)| {
            let before = reason[..at].chars().next_back();
            let after = reason[at + id.len()..].chars().next();
            !before.is_some_and(part_of_id) && !after.is_some_and(part_of_id)
        })
}

// ---- import -------------------------------------------------------------------

/// Why an import stopped. `ipc` turns each into the code the form explains.
#[derive(Debug)]
pub enum ImportError {
    /// The file: a wrong passphrase, damage, a newer version, a section limit.
    Backup(ExportError),
    /// The Library section, refused by the store's own checks.
    Library(BackupError),
    Store(StoreError),
    Io(std::io::Error),
    /// Earlier imports that did not finish, more than one journal can keep.
    /// Unlocking the vault resolves them ([`recover`]); then import again.
    EarlierUnfinished,
    /// The import was stopped before anything live changed, but what it had
    /// built aside could not all be removed. The journal still names it, so
    /// the next time the Library opens it is undone ([`recover`]).
    StoppedLeavingFiles,
}

impl From<ExportError> for ImportError {
    fn from(error: ExportError) -> Self {
        ImportError::Backup(error)
    }
}

impl From<BackupError> for ImportError {
    fn from(error: BackupError) -> Self {
        ImportError::Library(error)
    }
}

impl From<StoreError> for ImportError {
    fn from(error: StoreError) -> Self {
        ImportError::Store(error)
    }
}

impl From<std::io::Error> for ImportError {
    fn from(error: std::io::Error) -> Self {
        ImportError::Io(error)
    }
}

fn bad(what: &str) -> ImportError {
    ImportError::Backup(ExportError::BadExport(what.to_string()))
}

/// A backup read to its end and checked, its Library built in the staging
/// folder, its vault not yet written anywhere.
pub struct Staged {
    pending: PendingImport,
    journal: Journal,
    store_path: PathBuf,
    pub summary: RestoreSummary,
    /// False when the backup held no Library (one made while no Library was
    /// open): the new Library then starts empty, apart from this computer's
    /// own download records.
    pub library_included: bool,
}

impl std::fmt::Debug for Staged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Staged")
            .field("summary", &self.summary)
            .field("library_included", &self.library_included)
            .finish_non_exhaustive()
    }
}

/// Reads the backup at `src` once and builds its Library aside. Writes
/// nothing live. `keep_downloads_from` is the Library being replaced, when it
/// is open: its own verified download records are kept.
///
/// The caller holds the Library lock and the import lock.
// Tests only: the app goes through the job's own entry points.
#[cfg(test)]
pub fn stage(
    store_path: &Path,
    src: &Path,
    passphrase: &str,
    keep_downloads_from: Option<&Store>,
) -> Result<Staged, ImportError> {
    stage_watched(store_path, src, passphrase, keep_downloads_from, &mut |_| {})
}

/// [`stage`] for a worker thread: the download records to keep were taken
/// on the UI thread ([`Store::kept_downloads`]), and `watch` reports progress
/// and stops the import at its next check. A stop undoes everything this
/// import built, exactly as any other failure does; nothing live has been
/// touched.
pub fn stage_with(
    store_path: &Path,
    src: &Path,
    passphrase: &str,
    keep: Option<&KeptDownloads>,
    watch: &BackupWatch,
) -> Result<Staged, ImportError> {
    stage_inner(store_path, src, passphrase, keep, watch, &mut |_| {})
}

/// [`stage`], calling `after_section` with a running count after each
/// section is read. Tests use it to change the file mid-import.
// Tests only: the app goes through the job's own entry points.
#[cfg(test)]
fn stage_watched(
    store_path: &Path,
    src: &Path,
    passphrase: &str,
    keep_downloads_from: Option<&Store>,
    after_section: &mut dyn FnMut(usize),
) -> Result<Staged, ImportError> {
    let kept = keep_downloads_from.map(Store::kept_downloads);
    stage_inner(store_path, src, passphrase, kept.as_ref(), &BackupWatch::new(), after_section)
}

fn stage_inner(
    store_path: &Path,
    src: &Path,
    passphrase: &str,
    keep: Option<&KeptDownloads>,
    watch: &BackupWatch,
    after_section: &mut dyn FnMut(usize),
) -> Result<Staged, ImportError> {
    let superseded = settle(store_path)?;
    let mut journal = Journal {
        phase: Phase::Preparing,
        staging: random_name(STAGING_PREFIX),
        old_archive: random_name(OLD_ARCHIVE_PREFIX),
        vault_check: None,
        source: src.to_string_lossy().into_owned(),
        superseded,
    };
    // Written before the staging folder exists, so a crash at any point after
    // leaves a journal that names it.
    write_journal(store_path, &journal)?;
    let built = build(
        store_path,
        &journal.staging,
        src,
        passphrase,
        keep,
        watch,
        after_section,
    );
    let (pending, summary, library_included, check) = match built {
        Ok(built) => built,
        Err(error) => {
            let cleaned = undo(store_path, &journal);
            return Err(stopped_or(error, cleaned));
        }
    };
    journal.phase = Phase::Staged;
    journal.vault_check = Some(check);
    if let Err(error) = write_journal(store_path, &journal) {
        let cleaned = undo(store_path, &journal);
        return Err(stopped_or(error.into(), cleaned));
    }
    Ok(Staged {
        pending,
        journal,
        store_path: store_path.to_path_buf(),
        summary,
        library_included,
    })
}

type Built = (PendingImport, RestoreSummary, bool, String);

/// A stop is only reported as clean when everything it built aside is gone;
/// otherwise the person is told some files remain until the next open. Any
/// other failure keeps its own reason, as before: the journal still names
/// what is left, and the next open undoes it.
fn stopped_or(error: ImportError, cleaned: std::io::Result<()>) -> ImportError {
    match (error, cleaned) {
        (ImportError::Backup(ExportError::Cancelled), Err(_)) => ImportError::StoppedLeavingFiles,
        (error, _) => error,
    }
}

#[allow(clippy::too_many_arguments)]
fn build(
    store_path: &Path,
    staging_name: &str,
    src: &Path,
    passphrase: &str,
    keep: Option<&KeptDownloads>,
    watch: &BackupWatch,
    after_section: &mut dyn FnMut(usize),
) -> Result<Built, ImportError> {
    let file_name = store_path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the Library path has no file name"))?;
    let staging = library_dir(store_path).join(staging_name);
    crash::point("staging-folder-next");
    create_private_dir(&staging)?;
    crash::point("archive-folder-next");
    // Always created, even for a Library with no pictures, so that whether
    // it still exists tells recovery whether it has been moved yet.
    create_private_dir(&staging.join("archive"))?;
    crash::point("library-create-next");

    let mut reader = BackupReader::open_watched(src, passphrase, section_limits(), watch)?;
    let key = reader
        .pending()
        .library_key()
        .map_err(|e| ImportError::Backup(ExportError::Vault(e)))?;
    let mut library = Store::create_in_vault(&staging.join(file_name), &key)?;
    crash::point("library-created");

    let mut sections = 0;
    let first = reader.next_section()?;
    after_section(sections);
    let (summary, library_included) = match first {
        // A backup made while no Library was open: the new one starts empty,
        // and this computer's own download records are still kept.
        None => {
            let empty = validate_backup(empty_backup())?;
            (library.begin_restore(empty)?.commit_keeping(keep)?, false)
        }
        Some(section) if section.kind == SectionKind::Library && section.name.is_empty() => {
            let backup: LibraryBackup = serde_json::from_slice(&section.body)
                .map_err(|_| bad("the Library section is unreadable"))?;
            drop(section);
            let expected = picture_ids(&backup).len() as u64;
            watch.set_items(0, expected);
            let mut restore = library.begin_restore(validate_backup(backup)?)?;
            while let Some(section) = reader.next_section()? {
                sections += 1;
                after_section(sections);
                watch.set_items(sections as u64, expected);
                watch.check()?;
                match section.kind {
                    SectionKind::Picture => {
                        restore.put_picture(&section.name, &section.body)?;
                        crash::point("picture-written");
                    }
                    SectionKind::Library => return Err(bad("the Library appears twice")),
                    // Unreachable while add-on sections are not read (their
                    // limit is 0), and refused the same way if they ever are
                    // before something here can restore them.
                    SectionKind::Addon => {
                        return Err(ImportError::Backup(ExportError::UnreadableVersion(
                            patanyx_vault::BACKUP_VERSION,
                        )))
                    }
                }
            }
            // Only reached after END was read and matched everything before
            // it: `next_section` returns `None` for nothing else.
            watch.check()?;
            let committed = restore.commit_keeping(keep)?;
            crash::point("library-committed");
            (committed, true)
        }
        Some(_) => return Err(bad("the backup does not start with the Library")),
    };
    let pending = reader.finish()?;
    drop(library);
    sync_dir(&staging.join("archive"))?;
    sync_dir(&staging)?;
    Ok((pending, summary, library_included, check_value(&key)))
}

fn empty_backup() -> LibraryBackup {
    LibraryBackup {
        schema: LIBRARY_BACKUP_SCHEMA,
        bookmarks: Vec::new(),
        bookmark_folders: Vec::new(),
        shelves: Vec::new(),
        next_shelf_seq: 0,
        archive: Vec::new(),
        page_snapshots: Vec::new(),
        divergence_overrides: Vec::new(),
    }
}

impl Staged {
    /// Gives up a staged import before its commit: what it built aside goes
    /// and an earlier journal it superseded comes back, as for a failure while
    /// staging. Nothing live was touched. An error means some of it is still
    /// there; the journal still names it, so the next open undoes it.
    pub fn abandon(self) -> std::io::Result<()> {
        undo(&self.store_path, &self.journal)
    }

    /// Writes the imported vault over the old one: the commit point. A new
    /// passphrase slot and a new recovery key, which must be shown once.
    ///
    /// If this fails, the journal stays at `staged` and the staging folder
    /// stays too: whether the vault was replaced is then decided by the next
    /// [`recover`], from the vault that is actually there.
    pub fn install(
        self,
        vault_path: &Path,
        new_passphrase: &str,
    ) -> Result<(Vault, RecoveryKey), ImportError> {
        let Staged {
            pending,
            mut journal,
            store_path,
            ..
        } = self;
        // This runs on the import's commit worker (and in tests), never on the
        // UI thread, so it may wait a moment for a lock a child process
        // briefly shares (`lock::acquire_patiently`).
        let installed =
            pending.install_waiting(vault_path, new_passphrase, std::time::Duration::from_millis(500))?;
        crash::point("vault-committed");
        // Best effort: `staged` with a matching check value already means the
        // same thing to recovery.
        journal.phase = Phase::VaultCommitted;
        let _ = write_journal(&store_path, &journal);
        Ok(installed)
    }
}

/// What [`commit`] hands back: the imported vault, its one-time recovery key,
/// and its Library, already opened so the UI thread only attaches it.
pub struct Committed {
    pub vault: Vault,
    pub recovery: RecoveryKey,
    pub summary: RestoreSummary,
    pub library_included: bool,
    pub library: ImportedLibrary,
}

impl std::fmt::Debug for Committed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Committed")
            .field("summary", &self.summary)
            .field("library", &self.library)
            .finish_non_exhaustive()
    }
}

/// The imported Library, as [`commit`] left it.
pub enum ImportedLibrary {
    /// In place and open. `cleanup_pending`: a leftover could not be removed,
    /// so the journal is still there and the next open finishes it; the
    /// Library itself was checked in place.
    Opened { store: Store, cleanup_pending: bool },
    /// The swap could not be finished: the Library stays closed
    /// (`library_import_unfinished`) until a later open finishes it.
    Unfinished,
    /// In place, but it did not open.
    NotOpened(StoreError),
}

impl std::fmt::Debug for ImportedLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportedLibrary::Opened { cleanup_pending, .. } => f
                .debug_struct("Opened")
                .field("cleanup_pending", cleanup_pending)
                .finish_non_exhaustive(),
            ImportedLibrary::Unfinished => f.write_str("Unfinished"),
            ImportedLibrary::NotOpened(error) => f.debug_tuple("NotOpened").field(error).finish(),
        }
    }
}

/// The second half of an import, all of it slow and none of it cancellable:
/// writes the imported vault ([`Staged::install`], the commit point), then
/// moves its Library into place ([`recover`], which also checks every
/// picture opens), then opens it. Built to run on a worker; the caller holds
/// the Library lock and the import lock throughout, and has already closed
/// the live vault and Library.
///
/// An `Err` is a failure to write the vault: the journal stays at `staged`
/// and the next [`recover`] decides from the vault actually on disk.
pub fn commit(
    staged: Staged,
    vault_path: &Path,
    new_passphrase: &str,
) -> Result<Committed, ImportError> {
    let store_path = staged.store_path.clone();
    let summary = staged.summary;
    let library_included = staged.library_included;
    let (vault, recovery) = staged.install(vault_path, new_passphrase)?;
    let library = match vault.library_key() {
        Err(error) => ImportedLibrary::NotOpened(StoreError::Io(std::io::Error::other(format!(
            "library key: {error}"
        )))),
        Ok(key) => match recover(&store_path, &key) {
            Err(Unfinished) => ImportedLibrary::Unfinished,
            Ok(()) => {
                let cleanup_pending = journal_exists(&store_path);
                match Store::open(&store_path, None, &key) {
                    Ok(store) => ImportedLibrary::Opened {
                        store,
                        cleanup_pending,
                    },
                    Err(error) => ImportedLibrary::NotOpened(error),
                }
            }
        },
    };
    Ok(Committed {
        vault,
        recovery,
        summary,
        library_included,
        library,
    })
}

// ---- recovery -----------------------------------------------------------------

/// The Library cannot be opened: an import moved part of it and its state
/// cannot be finished from what is on disk. Repeating the import from the same
/// file replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unfinished;

/// True when an import left a journal beside the Library, however
/// unreadable, or the temporary file of one a crash cut off before its
/// rename (it names the backup file, so it is not left lying there).
pub fn journal_exists(store_path: &Path) -> bool {
    if fs::symlink_metadata(journal_path(store_path)).is_ok() {
        return true;
    }
    fs::read_dir(library_dir(store_path)).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| is_journal_temp(store_path, name))
                && entry.file_type().is_ok_and(|kind| kind.is_file())
        })
    })
}

/// Finishes or undoes whatever import the journal records, for the vault whose
/// Library key is `library_key` (the vault that is open). Afterwards there is
/// no journal and the Library at `store_path`, if there is one, is the right
/// one for this vault; or the answer is [`Unfinished`] and nothing may be
/// opened.
///
/// The caller holds the Library lock.
pub fn recover(store_path: &Path, library_key: &[u8; 32]) -> Result<(), Unfinished> {
    let check = check_value(library_key);
    // Each pass resolves one journal; undoing one can put back the one it
    // superseded, which the next pass resolves.
    loop {
        let journal = match read_journal(store_path) {
            Ok(None) => {
                return remove_journal_temps(store_path).map_err(|_| Unfinished);
            }
            Ok(Some(journal)) => journal,
            Err(()) => return Err(Unfinished),
        };
        let ours = journal.vault_check.as_deref() == Some(check.as_str());
        let resolved = match journal.phase {
            Phase::Preparing => undo(store_path, &journal),
            Phase::Staged if !ours => undo(store_path, &journal),
            Phase::Staged | Phase::VaultCommitted => {
                if !ours {
                    // Committed for a vault that is no longer here. Moving its
                    // Library in would put one this vault cannot open over the
                    // live one, so nothing is touched.
                    return Err(Unfinished);
                }
                return finish(store_path, &journal, library_key);
            }
            // A finished swap still has to belong to this vault, with its
            // Library in place, before the leftovers and the older import's
            // marker go: `swapped` is the journal's claim, and a journal is
            // untrusted.
            Phase::Swapped => {
                if !ours || !library_in_place(store_path, library_key) {
                    return Err(Unfinished);
                }
                // As `finish` treats it: the right Library is in place, so a
                // leftover that cannot be deleted yet (a file another program
                // holds open) does not keep it shut. It is retried at the next
                // open, unless the marker that would keep this Library shut is
                // among what could not go (security pass, F-101).
                match clean_up(store_path, &journal) {
                    Err(_) if !replace_marker(store_path).exists() => return Ok(()),
                    other => other,
                }
            }
        };
        if resolved.is_err() {
            return Err(Unfinished);
        }
    }
}

/// The Library at `store_path` is a regular file this vault opens, its picture folder is
/// a real folder (never a link the store would prune through), every picture
/// its records name is there, and they open under this Library's key. The
/// last matters for a backup of this very profile: every id is the same, so
/// the old pictures would all be "there" by name.
fn library_in_place(store_path: &Path, library_key: &[u8; 32]) -> bool {
    // The Library file itself is a regular file, not a link: a link could
    // point into the staging folder that cleanup is about to delete.
    if !is_regular_file(store_path) {
        return false;
    }
    let archive = library_dir(store_path).join("archive");
    if present(&archive) && !is_real_dir(&archive) {
        return false;
    }
    match Store::open(store_path, None, library_key) {
        Ok(library) => library.pictures_missing() == 0 && library.pictures_open(),
        Err(_) => false,
    }
}

/// Clears what can be cleared without a vault before a new import, and hands
/// back, hex-encoded, the exact bytes of any journal still unresolved, for the
/// new import to keep. Kept as bytes so that even a journal nothing can read
/// is put back as it was if the new import fails: the new import never has to
/// understand an earlier one to stand aside for it, and when it completes, the
/// folders every earlier one made are swept by name ([`clean_up`]).
fn settle(store_path: &Path) -> Result<Option<String>, ImportError> {
    loop {
        let Some(raw) = read_journal_bytes(store_path)? else {
            remove_journal_temps(store_path)?;
            return Ok(None);
        };
        match parse_journal(&raw) {
            // Safe without a vault: before `staged`, nothing live was touched.
            Some(journal) if journal.phase == Phase::Preparing => undo(store_path, &journal)?,
            // Everything else, `swapped` included, needs the vault to check,
            // so it is kept, and swept if this import completes.
            _ => {
                // Each import that keeps another doubles its size; past the
                // journal's limit, the person is asked to resolve the earlier
                // ones by unlocking first.
                if (raw.len() as u64) * 2 + 1024 > MAX_JOURNAL_BYTES {
                    return Err(ImportError::EarlierUnfinished);
                }
                return Ok(Some(hex(&raw)));
            }
        }
    }
}

/// The source file named by an unfinished import, for the message that asks
/// the person to repeat it.
pub fn unfinished_source(store_path: &Path) -> Option<String> {
    match read_journal(store_path) {
        Ok(Some(journal)) => Some(journal.source),
        _ => None,
    }
}

/// After an import of an older backup (versions 1 and 2) has committed its
/// vault and removed the Library: nothing a whole-Library import staged can
/// belong to the new vault, so every folder an import could have created, and
/// the journal, go. Matched by name, so an unreadable journal goes too.
pub fn discard(store_path: &Path) -> std::io::Result<()> {
    sweep_import_folders(library_dir(store_path))?;
    remove_journal_temps(store_path)?;
    remove_journal(store_path)
}

/// Moves the staged Library into place, idempotently: every step checks what
/// is already done, so a crash between any two of them is finished here.
fn finish(store_path: &Path, journal: &Journal, library_key: &[u8; 32]) -> Result<(), Unfinished> {
    let dir = library_dir(store_path);
    let file_name = store_path.file_name().ok_or(Unfinished)?;
    let staging = dir.join(&journal.staging);
    let staged_archive = staging.join("archive");
    let staged_library = staging.join(file_name);
    let live_archive = dir.join("archive");
    let old_archive = dir.join(&journal.old_archive);

    let moved = (|| -> std::io::Result<bool> {
        if !is_real_dir(&staging) {
            return Ok(false);
        }
        // Only a real folder and a regular file are ever moved into place: a
        // link would be followed by the store, outside the profile.
        if (present(&staged_archive) && !is_real_dir(&staged_archive))
            || (present(&staged_library) && !is_regular_file(&staged_library))
        {
            return Ok(false);
        }
        if present(&staged_archive) {
            if present(&live_archive) {
                // Both a live folder and the aside one: something other than
                // this import is at work in the folder. Touch nothing.
                if present(&old_archive) {
                    return Ok(false);
                }
                crash::point("live-archive-aside-next");
                fs::rename(&live_archive, &old_archive)?;
            }
            crash::point("staged-archive-in-next");
            fs::rename(&staged_archive, &live_archive)?;
        }
        if present(&staged_library) {
            crash::point("staged-library-in-next");
            fs::rename(&staged_library, store_path)?;
        }
        sync_dir(dir)?;
        Ok(true)
    })();
    if !matches!(moved, Ok(true)) {
        return Err(Unfinished);
    }
    // The Library now in place must be the one this import built: it opens
    // with this vault and every picture it names is there. Anything else (the
    // old Library because the staged file went missing, or pictures because
    // the staged folder did) is never declared done.
    if !library_in_place(store_path, library_key) {
        return Err(Unfinished);
    }
    let mut swapped = journal.clone();
    swapped.phase = Phase::Swapped;
    write_journal(store_path, &swapped).map_err(|_| Unfinished)?;
    // The Library is in place. Leftovers that cannot be deleted now are
    // retried the next time the Library opens, unless the marker that would
    // keep the new Library shut is among them.
    match clean_up(store_path, &swapped) {
        Ok(()) => Ok(()),
        Err(_) if replace_marker(store_path).exists() => Err(Unfinished),
        Err(_) => Ok(()),
    }
}

/// Deletes the folder this import staged and puts back the journal it
/// superseded, if any. Only valid before the swap began: the live Library
/// and its pictures were never touched.
fn undo(store_path: &Path, journal: &Journal) -> std::io::Result<()> {
    remove_folder(library_dir(store_path), &journal.staging)?;
    match journal.superseded.as_deref().map(unhex) {
        Some(Some(previous)) => write_journal_bytes(store_path, &previous),
        // `is_valid` refuses a journal whose kept bytes do not decode.
        Some(None) => Err(std::io::Error::other("the kept journal does not decode")),
        None => remove_journal(store_path),
    }
}

/// After the swap: the old pictures, the empty staging folder and every
/// folder an earlier, superseded import made go, then the journal. The
/// earlier ones are swept by name rather than read from the journals kept
/// inside this one, which may be unreadable: everything they held has now
/// been replaced.
fn clean_up(store_path: &Path, journal: &Journal) -> std::io::Result<()> {
    // First: the marker an older import may have left to keep the Library it
    // could not delete shut. That Library has now been replaced, and the
    // marker left in place would keep the new one shut instead.
    crash::point("marker-removal-next");
    match fs::remove_file(replace_marker(store_path)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let dir = library_dir(store_path);
    remove_folder(dir, &journal.old_archive)?;
    remove_folder(dir, &journal.staging)?;
    sweep_import_folders(dir)?;
    remove_journal_temps(store_path)?;
    remove_journal(store_path)
}

/// Removes every folder beside the Library whose name only an import gives.
fn sweep_import_folders(dir: &Path) -> std::io::Result<()> {
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if valid_name(name, STAGING_PREFIX) || valid_name(name, OLD_ARCHIVE_PREFIX) {
                    remove_folder(dir, name)?;
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The marker `ipc::replace_library` publishes (`AppState::library_replace_marker`).
fn replace_marker(store_path: &Path) -> PathBuf {
    let mut path = store_path.as_os_str().to_owned();
    path.push(".replace-pending");
    PathBuf::from(path)
}

// ---- the journal ----------------------------------------------------------------

const STAGING_PREFIX: &str = "library-staging-";
const OLD_ARCHIVE_PREFIX: &str = "archive.old-";
const NAME_HEX: usize = 16;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Preparing,
    Staged,
    VaultCommitted,
    Swapped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    phase: Phase,
    /// The staging folder, beside the Library file.
    staging: String,
    /// The name the live picture folder is moved to during the swap.
    old_archive: String,
    /// Check value of the imported vault's Library key, from `staged` on.
    vault_check: Option<String>,
    /// The backup file, so an unfinished import can be named.
    source: String,
    /// The exact bytes, hex-encoded, of the journal of an earlier import that
    /// was unresolved when this one began, put back if this one fails.
    superseded: Option<String>,
}

impl Journal {
    fn is_valid(&self) -> bool {
        let check_ok = match (&self.vault_check, self.phase) {
            (None, Phase::Preparing) => true,
            (Some(check), Phase::Staged | Phase::VaultCommitted | Phase::Swapped) => {
                check.len() == 64 && check.bytes().all(|b| b.is_ascii_hexdigit())
            }
            _ => false,
        };
        check_ok
            && valid_name(&self.staging, STAGING_PREFIX)
            && valid_name(&self.old_archive, OLD_ARCHIVE_PREFIX)
            && self.superseded.as_deref().is_none_or(|kept| unhex(kept).is_some())
    }
}

fn valid_name(name: &str, prefix: &str) -> bool {
    name.len() == prefix.len() + NAME_HEX
        && name.starts_with(prefix)
        && name[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn random_name(prefix: &str) -> String {
    let mut bytes = [0u8; NAME_HEX / 2];
    getrandom::getrandom(&mut bytes).expect("the OS random source is available");
    format!("{prefix}{}", hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            let pair = text.get(at..at + 2)?;
            if !pair.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

/// Identifies the vault an import installs without revealing anything about
/// its key: a hash of the 256-bit Library key under a label of its own.
fn check_value(library_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"patanyx/import-journal/v1\0");
    hasher.update(library_key);
    hex(&hasher.finalize())
}

fn journal_path(store_path: &Path) -> PathBuf {
    let mut path = store_path.as_os_str().to_owned();
    path.push(".replace-journal");
    PathBuf::from(path)
}

fn library_dir(store_path: &Path) -> &Path {
    match store_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// `Ok(None)`: no journal. `Err`: one that is not a regular file, too large,
/// unreadable, or naming anything but an import's own folders.
fn read_journal(store_path: &Path) -> Result<Option<Journal>, ()> {
    match read_journal_bytes(store_path) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => parse_journal(&bytes).map(Some).ok_or(()),
        Err(_) => Err(()),
    }
}

/// The journal's bytes, whatever they hold. `Err` for anything that is not a
/// regular file of at most [`MAX_JOURNAL_BYTES`].
fn read_journal_bytes(store_path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let path = journal_path(store_path);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !meta.is_file() || meta.len() > MAX_JOURNAL_BYTES {
        return Err(std::io::Error::other("the import journal is not a small regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(&path)?
        .take(MAX_JOURNAL_BYTES)
        .read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn parse_journal(bytes: &[u8]) -> Option<Journal> {
    serde_json::from_slice::<Journal>(bytes)
        .ok()
        .filter(Journal::is_valid)
}

fn write_journal(store_path: &Path, journal: &Journal) -> std::io::Result<()> {
    let body = serde_json::to_vec(journal).map_err(std::io::Error::other)?;
    if body.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(std::io::Error::other("the import journal would be too large"));
    }
    write_journal_bytes(store_path, &body)
}

/// Atomic and durable: a new file beside the journal, flushed, renamed over
/// it, and the folder flushed, so a crash leaves the old phase or the new one.
fn write_journal_bytes(store_path: &Path, body: &[u8]) -> std::io::Result<()> {
    let path = journal_path(store_path);
    let dir = library_dir(store_path);
    let mut temp_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the journal path has no file name"))?
        .to_owned();
    temp_name.push(format!(".tmp-{}", random_name("")));
    let temp = dir.join(temp_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    crash::point("journal-temp-next");
    let written = options.open(&temp).and_then(|mut file| {
        file.write_all(body)?;
        file.sync_all()
    });
    crash::point("journal-rename-next");
    if let Err(error) = written.and_then(|()| fs::rename(&temp, &path)) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    sync_dir(dir)
}

fn remove_journal(store_path: &Path) -> std::io::Result<()> {
    crash::point("journal-removal-next");
    match fs::remove_file(journal_path(store_path)) {
        Ok(()) => sync_dir(library_dir(store_path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

// ---- files and folders ----------------------------------------------------------

fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Removes `dir/name` whatever it is. A symbolic link is removed as a link,
/// never followed.
fn remove_folder(dir: &Path, name: &str) -> std::io::Result<()> {
    crash::point("folder-removal-next");
    if crash::removal_fails() {
        return Err(std::io::Error::other("folder removal failed"));
    }
    let path = dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(&path),
        Ok(_) => fs::remove_file(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// A new folder only this user can read. Fails if it exists: the names are
/// random, so an existing one is not ours.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Makes renames and new entries in `dir` durable where the platform can.
/// Windows cannot open a directory this way to flush it; there a rename is as
/// durable as the file system makes it, the same limit `sync_parent` in the
/// store documents.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Removes this Library's journal temporary files that a crash left between
/// write and rename. Regular files only, by this Library's exact journal
/// name: never a folder, never another file's look-alike.
fn remove_journal_temps(store_path: &Path) -> std::io::Result<()> {
    let dir = library_dir(store_path);
    for entry in fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_journal_temp(store_path, name) && entry.file_type()?.is_file() {
            crash::point("temp-removal-next");
            match fs::remove_file(dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// Exactly `<this Library's journal file name>.tmp-<16 hex>`, as
/// `write_journal_bytes` names its temporary file.
fn is_journal_temp(store_path: &Path, name: &str) -> bool {
    let journal = journal_path(store_path);
    let Some(journal) = journal.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.strip_prefix(journal)
        .and_then(|rest| rest.strip_prefix(".tmp-"))
        .is_some_and(|tail| valid_name(tail, ""))
}

/// Crash points, for tests only. With one armed, reaching it panics, which
/// unwinds without running any of the cleanup a returned error would: the
/// way a process killed at that point leaves the disk. Every step that
/// changes what is on disk passes one. In a build, `point` is empty.
#[cfg(test)]
pub(crate) mod crash {
    use std::cell::{Cell, RefCell};

    thread_local! {
        pub(crate) static ARMED: Cell<Option<usize>> = const { Cell::new(None) };
        pub(crate) static REACHED: Cell<usize> = const { Cell::new(0) };
        /// The name of every point reached, so a test can show which steps
        /// it covered rather than only how many.
        pub(crate) static NAMES: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        /// Makes every folder removal fail, the way a file held open by
        /// another program would on Windows: for the paths that must report
        /// a clean-up they could not finish.
        pub(crate) static FAIL_REMOVAL: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn removal_fails() -> bool {
        FAIL_REMOVAL.with(Cell::get)
    }

    pub(crate) fn point(name: &'static str) {
        NAMES.with(|names| names.borrow_mut().push(name));
        let n = REACHED.with(|reached| {
            let n = reached.get();
            reached.set(n + 1);
            n
        });
        if ARMED.with(Cell::get) == Some(n) {
            panic!("crash point {n} ({name})");
        }
    }
}

#[cfg(not(test))]
mod crash {
    #[inline(always)]
    pub(crate) fn point(_name: &'static str) {}

    #[inline(always)]
    pub(crate) fn removal_fails() -> bool {
        false
    }
}

#[cfg(test)]
#[path = "vault_backup_tests.rs"]
mod tests;
