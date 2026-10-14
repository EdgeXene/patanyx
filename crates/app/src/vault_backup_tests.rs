//! The Vault backup, end to end below the IPC layer (`vault_backup.rs`).
//!
//! Properties pinned here:
//! - a whole Library travels to another profile and comes back complete, under
//!   the imported vault, with this computer's own download records kept;
//! - no download address is anywhere in a decrypted backup;
//! - an export never writes a backup this build would refuse, and names the
//!   item that is in the way;
//! - any failure before the vault commit leaves every live file byte for byte
//!   as it was, and the staged Library never touches the live one;
//! - the backup is read once: replacing it mid-import changes nothing, and
//!   changing it in place is refused;
//! - an import interrupted at any step is finished, or undone, by the next
//!   open, decided by the vault that is actually there;
//! - a journal is untrusted: one naming anything but an import's own folders
//!   is never acted on.

use super::*;
use patanyx_store::{DivergenceLevel, ShelfGroup, ShelfTab};

const PASS: &str = "vault passphrase";
const EXPORT_PASS: &str = "export passphrase";
const NEW_PASS: &str = "new vault passphrase";
const ARCHIVE_PNG: &[u8] = b"\x89PNG\r\n\x1a\n archived pixels";
const SNAPSHOT_PNG: &[u8] = b"\x89PNG\r\n\x1a\n snapshot pixels";
const DOWNLOAD_URL: &str = "https://downloads.example.test/private-history.zip";
const LOCAL_DOWNLOAD_URL: &str = "https://downloads.example.test/this-computer.zip";
const LOGIN_ORIGIN: &str = "https://login.example.test";

/// One browser profile: a vault and a Library beside it, in a folder of its
/// own.
struct Profile {
    dir: tempfile::TempDir,
    vault_path: PathBuf,
    store_path: PathBuf,
}

impl Profile {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.rbv");
        let store_path = dir.path().join("store.rbs");
        Profile {
            dir,
            vault_path,
            store_path,
        }
    }

    fn vault(&self) -> Vault {
        Vault::create_with_params(&self.vault_path, PASS, 8192, 1, 1)
            .unwrap()
            .0
    }

    fn library(&self, vault: &Vault) -> Store {
        Store::create_in_vault(&self.store_path, &vault.library_key().unwrap()).unwrap()
    }

    /// Every file under the profile, by relative path, with its bytes.
    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        walk(self.dir.path(), self.dir.path(), &mut out);
        out.sort();
        out
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// No journal and no folder an import made is left beside the Library.
    fn assert_no_leftovers(&self) {
        for name in self.names() {
            assert!(
                !name.starts_with(STAGING_PREFIX)
                    && !name.starts_with(OLD_ARCHIVE_PREFIX)
                    && !name.contains(".replace-journal"),
                "left behind: {name}"
            );
        }
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let relative = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            out.push((relative, fs::read(&path).unwrap()));
        }
    }
}

fn page_digest(words: &str) -> patanyx_store::ContentDigest {
    patanyx_integrity::digest(format!("<p>{words}</p>").as_bytes()).unwrap()
}

/// A Library holding one of everything, the way a real one does.
fn fill(store: &mut Store) {
    let kept = store.add_bookmark("https://a.example.test/", "A").unwrap();
    store.set_bookmark_tags(&kept, vec!["chem".into()]).unwrap();
    store.set_quick_access(&kept, true).unwrap();
    store.add_bookmark("https://b.example.test/", "B").unwrap();
    store.create_folder("empty folder").unwrap();
    let shelf = store
        .add_shelf_grouped(
            "Trip".into(),
            vec![ShelfTab {
                title: "Map".into(),
                url: "https://map.example.test/".into(),
            }],
            Some(ShelfGroup {
                name: "Trip".into(),
                color: "blue".into(),
            }),
        )
        .unwrap();
    store.set_shelf_note(&shelf.id, "pack the charger").unwrap();
    store
        .add_archive("https://c.example.test/", "C page", "full page", "words in a picture", Some(ARCHIVE_PNG))
        .unwrap();
    store
        .add_archive("https://d.example.test/", "D page", "visible area", "text only", None)
        .unwrap();
    store
        .save_page_snapshot_with_picture(&kept, page_digest("a page"), "a page", SNAPSHOT_PNG, "visible area")
        .unwrap();
    store
        .set_divergence_override("www.example.test", DivergenceLevel::Off)
        .unwrap();
    store
        .record_download(DOWNLOAD_URL, "private-history.zip", 42, [7u8; 32])
        .unwrap();
}

/// A source profile with a credential and a full Library, exported to a
/// backup file outside every profile. Returns the source too, for comparing.
fn source_backup() -> (Profile, PathBuf, ExportSummary) {
    let source = Profile::new();
    let mut vault = source.vault();
    vault
        .add_credential("login", Some(LOGIN_ORIGIN), "ada", "s3cret", "")
        .unwrap();
    let mut library = source.library(&vault);
    fill(&mut library);
    let backup = source.dir.path().join("backup.rbx");
    let summary = match export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap() {
        ExportOutcome::Written(summary) => summary,
        ExportOutcome::Refused(refusal) => panic!("refused: {refusal:?}"),
    };
    (source, backup, summary)
}

/// A target profile with a vault, a small Library of its own, and one
/// download record of its own.
fn target() -> (Profile, Vault, Store) {
    let target = Profile::new();
    let vault = target.vault();
    let mut library = target.library(&vault);
    library.add_bookmark("https://old.example.test/", "Old").unwrap();
    library
        .add_archive("https://old-page.example.test/", "Old page", "full page", "", Some(b"old pixels"))
        .unwrap();
    library
        .record_download(LOCAL_DOWNLOAD_URL, "this-computer.zip", 7, [1u8; 32])
        .unwrap();
    (target, vault, library)
}

/// Stages, commits and opens, as the import arm and the next `open_store` do.
fn import_into(
    target: &Profile,
    backup: &Path,
    live: Option<Store>,
    live_vault: Option<Vault>,
) -> (Vault, Store, ImportReport) {
    let staged = stage(&target.store_path, backup, EXPORT_PASS, live.as_ref()).unwrap();
    let report = ImportReport {
        summary: staged.summary,
        library_included: staged.library_included,
    };
    // Nothing keeps writing to the files being replaced.
    drop(live);
    drop(live_vault);
    let (vault, _recovery) = staged.install(&target.vault_path, NEW_PASS).unwrap();
    let key = vault.library_key().unwrap();
    recover(&target.store_path, &key).unwrap();
    let library = Store::open(&target.store_path, None, &key).unwrap();
    (vault, library, report)
}

struct ImportReport {
    summary: RestoreSummary,
    library_included: bool,
}

fn assert_is_the_source_library(library: &Store) {
    let urls: Vec<&str> = library.bookmarks().iter().map(|b| b.url.as_str()).collect();
    assert_eq!(urls, ["https://a.example.test/", "https://b.example.test/"]);
    assert_eq!(library.shelves().len(), 1);
    assert_eq!(library.shelves()[0].note, "pack the charger");
    assert_eq!(library.archive().len(), 2);
    let pictured = library.archive().iter().find(|r| r.title == "C page").unwrap();
    assert_eq!(&library.backup_picture(&pictured.id).unwrap()[..], ARCHIVE_PNG);
    let snapshots = library.library_backup().page_snapshots;
    assert_eq!(snapshots.len(), 1);
    assert_eq!(&library.backup_picture(&snapshots[0].id).unwrap()[..], SNAPSHOT_PNG);
    assert_eq!(library.divergence_overrides().len(), 1);
}

// ---- the round trip ---------------------------------------------------------------

#[test]
fn a_whole_library_travels_to_another_profile_and_the_local_downloads_stay() {
    let (_source, backup, exported) = source_backup();
    assert!(exported.library_included);
    assert_eq!(
        (exported.bookmarks, exported.tab_groups, exported.deep_recall_pages),
        (2, 1, 2)
    );
    assert_eq!(
        (exported.snapshots, exported.pictures, exported.site_exceptions),
        (1, 2, 1)
    );
    assert!(exported.folders >= 1);
    assert_eq!(exported.pictures_left_out, 0);

    let (target, vault, library) = target();
    let (imported, library, report) = import_into(&target, &backup, Some(library), Some(vault));
    assert!(report.library_included);
    assert_eq!(report.summary.bookmarks, 2);
    assert_eq!(report.summary.pictures, 2);
    assert_eq!(report.summary.downloads_kept, 1);

    assert_is_the_source_library(&library);
    // The old Library's bookmark is gone; its download record is kept, under
    // the new key, and the source's never arrived.
    let downloads: Vec<&str> = library.downloads().iter().map(|d| d.url.as_str()).collect();
    assert_eq!(downloads, [LOCAL_DOWNLOAD_URL]);
    assert_eq!(library.verified_downloads().len(), 1);
    // The vault came over too.
    assert_eq!(imported.credentials_for_origin(LOGIN_ORIGIN).len(), 1);
    drop(imported);
    assert!(Vault::unlock(&target.vault_path, NEW_PASS).is_ok());
    target.assert_no_leftovers();
}

#[test]
fn a_decrypted_backup_never_holds_a_download_address() {
    let (_source, backup, _) = source_backup();
    let mut reader = BackupReader::open(&backup, EXPORT_PASS, section_limits()).unwrap();
    let needle = DOWNLOAD_URL.as_bytes();
    let mut sections = 0;
    while let Some(section) = reader.next_section().unwrap() {
        sections += 1;
        assert!(
            !section.body.windows(needle.len()).any(|w| w == needle),
            "a download address is in a {:?} section",
            section.kind
        );
    }
    assert_eq!(sections, 3, "the Library and two pictures");
    reader.finish().unwrap();
}

#[test]
fn a_backup_made_with_no_library_open_restores_an_empty_one_keeping_local_downloads() {
    let source = Profile::new();
    let vault = source.vault();
    let backup = source.dir.path().join("vault-only.rbx");
    assert!(matches!(
        export(&vault, None, &backup, EXPORT_PASS).unwrap(),
        ExportOutcome::Written(ExportSummary {
            library_included: false,
            ..
        })
    ));

    let (target, vault, library) = target();
    let (_, library, report) = import_into(&target, &backup, Some(library), Some(vault));
    assert!(!report.library_included);
    assert!(library.bookmarks().is_empty());
    assert_eq!(library.downloads().len(), 1);
    target.assert_no_leftovers();
}

#[test]
fn an_import_over_a_locked_profile_starts_its_library_from_the_backup_alone() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    // Locked: the old Library is not open, so its records cannot be checked
    // and none are kept.
    drop(library);
    let (_, library, report) = import_into(&target, &backup, None, Some(vault));
    assert_eq!(report.summary.downloads_kept, 0);
    assert!(library.downloads().is_empty());
    assert_is_the_source_library(&library);
}

// ---- the export's own checks ---------------------------------------------------

#[test]
fn an_export_refuses_a_library_it_could_not_import_and_names_the_item() {
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    // Larger than any capture this build can make: a picture stored before
    // that limit existed.
    let huge = vec![0u8; (MAX_BACKUP_PICTURE_BYTES + 1) as usize];
    library
        .add_archive("https://big.example.test/", "The huge page", "full page", "", Some(&huge))
        .unwrap();
    let backup = source.dir.path().join("backup.rbx");
    match export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap() {
        ExportOutcome::Refused(refusal) => assert_eq!(
            refusal,
            ExportRefusal {
                code: "export_item_too_large",
                item: Some("The huge page".into()),
            }
        ),
        ExportOutcome::Written(_) => panic!("wrote a backup this build would refuse"),
    }
    assert!(!backup.exists());
}

#[test]
fn an_export_leaves_out_a_lost_picture_and_the_backup_still_imports() {
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    fill(&mut library);
    let lost = library.archive().iter().find(|r| r.has_picture).unwrap().id.clone();
    fs::remove_file(source.dir.path().join("archive").join(&lost)).unwrap();
    let backup = source.dir.path().join("backup.rbx");
    let ExportOutcome::Written(summary) = export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap()
    else {
        panic!("refused");
    };
    assert_eq!((summary.pictures, summary.pictures_left_out), (1, 1));

    let (target, vault, library) = target();
    let (_, library, _) = import_into(&target, &backup, Some(library), Some(vault));
    assert!(!library.get_archive(&lost).unwrap().has_picture);
    assert_eq!(library.archive().len(), 2);
}

/// A Library this build wrote always passes; these are Libraries an older
/// build or a damaged file could leave, built by hand because the store's own
/// writers refuse to make them.
#[test]
fn an_export_runs_the_imports_checks_and_names_what_fails() {
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    fill(&mut library);
    let good = library.library_backup();
    assert_eq!(refusal_for(&good), None);

    let mut reserved = good.clone();
    reserved.bookmarks[0].id = "con".into();
    assert_eq!(refusal_for(&reserved).unwrap().code, "export_library_unusable");

    let mut shouting = good.clone();
    shouting.bookmarks[0].tags = vec!["CHEM".into()];
    assert_eq!(
        refusal_for(&shouting),
        Some(ExportRefusal {
            code: "export_library_unusable",
            item: Some("A".into()),
        })
    );

    let mut crowded = good.clone();
    let page = crowded.archive[0].clone();
    crowded.archive = (0..=patanyx_store::MAX_ARCHIVE_RECORDS)
        .map(|n| {
            let mut copy = page.clone();
            copy.id = format!("{:016x}", n);
            copy.has_picture = false;
            copy
        })
        .collect();
    assert_eq!(
        refusal_for(&crowded),
        Some(ExportRefusal {
            code: "export_library_over_limit",
            item: None,
        })
    );

    // R-004: picture totals as stored, which a restore re-checks.
    let mut heavy = good.clone();
    let pictured = heavy.archive.iter().position(|r| r.has_picture).unwrap();
    heavy.archive[pictured].picture_bytes = patanyx_store::MAX_ARCHIVE_BYTES + 1;
    assert_eq!(
        refusal_for(&heavy),
        Some(ExportRefusal {
            code: "export_library_over_limit",
            item: None,
        })
    );

    let mut wordy = good.clone();
    let d = wordy.archive.iter().position(|r| r.title == "D page").unwrap();
    wordy.archive[d].text = "x".repeat(ARCHIVE_TEXT_MAX_CHARS + 1);
    assert_eq!(
        refusal_for(&wordy),
        Some(ExportRefusal {
            code: "export_item_too_large",
            item: Some("D page".into()),
        })
    );
}

#[test]
fn a_refusal_names_an_item_only_by_its_whole_id() {
    assert!(mentions("the note on shelf-12 is too long", "shelf-12"));
    assert!(!mentions("the note on shelf-12 is too long", "shelf-1"));
    assert!(!mentions("the note on shelf-12 is too long", "helf-12"));
    assert!(mentions("shelf-1", "shelf-1"));
    assert!(!mentions("anything", ""));
}

#[test]
fn an_export_checks_before_it_writes() {
    let source = include_str!("vault_backup.rs");
    // The one-call export is take-then-write, so it carries the same check.
    let export = &source[source.find("pub fn export(").unwrap()..];
    let export = &export[..export.find("\n}\n").unwrap()];
    assert!(
        export.contains("ExportInput::take(vault, library)?.write("),
        "export() no longer goes through ExportInput::write"
    );
    let body = &source[source.find("    fn write_watched(").unwrap()..];
    let body = &body[..body.find("\n    }\n").unwrap()];
    let checked = body.find("refusal_for(&backup)").expect("the export no longer checks");
    let written = body.find("source.write(").expect("the export no longer writes");
    // The early return for a vault with no Library open comes first and has
    // nothing to check; the Library's write is the second one.
    let library_written = written + 1 + body[written + 1..].find("source.write(").unwrap();
    assert!(checked < library_written, "the Library is written before it is checked");
}

// ---- nothing live changes before the commit --------------------------------------

#[test]
fn a_wrong_passphrase_or_a_damaged_file_leaves_every_live_file_as_it_was() {
    let (_source, backup, _) = source_backup();
    let (target, _vault, library) = target();
    let before = target.snapshot();

    let wrong = stage(&target.store_path, &backup, "not the passphrase", Some(&library));
    assert!(matches!(wrong, Err(ImportError::Backup(ExportError::AuthFailed))));
    assert_eq!(target.snapshot(), before);

    let bytes = fs::read(&backup).unwrap();
    for (tag, damaged) in [
        ("flipped", {
            let mut b = bytes.clone();
            let at = b.len() - 40;
            b[at] ^= 1;
            b
        }),
        ("cut", bytes[..bytes.len() - 17].to_vec()),
        ("appended", [bytes.as_slice(), b"x"].concat()),
    ] {
        let path = target.dir.path().with_extension(tag);
        fs::write(&path, &damaged).unwrap();
        assert!(stage(&target.store_path, &path, EXPORT_PASS, Some(&library)).is_err(), "{tag}");
        assert_eq!(target.snapshot(), before, "{tag} changed a live file");
        fs::remove_file(&path).unwrap();
    }
    target.assert_no_leftovers();
}

#[test]
fn the_staged_library_never_touches_the_live_one_even_with_the_same_ids() {
    // A backup of this very Library: every picture id exists live too.
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    fill(&mut library);
    let backup_dir = tempfile::tempdir().unwrap();
    let backup = backup_dir.path().join("self.rbx");
    export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap();
    let before = source.snapshot();

    let staged = stage(&source.store_path, &backup, EXPORT_PASS, Some(&library)).unwrap();
    let after: Vec<_> = source
        .snapshot()
        .into_iter()
        .filter(|(path, _)| !path.starts_with(STAGING_PREFIX) && !path.ends_with(".replace-journal"))
        .collect();
    assert_eq!(after, before, "a live file changed while staging");
    let staging = source.dir.path().join(&staged.journal.staging);
    for id in library.backup_picture_ids() {
        assert!(staging.join("archive").join(&id).is_file(), "staged picture {id}");
    }

    // Not committed: the next open, with the vault that is still here, undoes it.
    drop(staged);
    recover(&source.store_path, &vault.library_key().unwrap()).unwrap();
    assert_eq!(source.snapshot(), before);
    source.assert_no_leftovers();
}

#[cfg(unix)]
#[test]
fn the_backup_is_read_once_so_replacing_the_file_mid_import_changes_nothing() {
    let (_source, backup, _) = source_backup();
    let (_other, other_backup, _) = {
        let other = Profile::new();
        let vault = other.vault();
        let mut library = other.library(&vault);
        library.add_bookmark("https://other.example.test/", "Other").unwrap();
        let path = other.dir.path().join("other.rbx");
        export(&vault, Some(&library), &path, EXPORT_PASS).unwrap();
        (other, path, ())
    };
    let (target, vault, library) = target();
    let staged = stage_watched(&target.store_path, &backup, EXPORT_PASS, Some(&library), &mut |n| {
        if n == 0 {
            fs::copy(&other_backup, target.dir.path().join("swap.tmp")).unwrap();
            fs::rename(target.dir.path().join("swap.tmp"), &backup).unwrap();
        }
    })
    .unwrap();
    drop((vault, library));
    let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
    let key = vault.library_key().unwrap();
    recover(&target.store_path, &key).unwrap();
    assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
}

#[test]
fn a_backup_changed_in_place_mid_import_is_refused_with_nothing_live_changed() {
    // Large enough to span several sealed segments, so there is a later
    // segment to change after the first one has been read.
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    let pixels = vec![0x5au8; 3 * 1024 * 1024];
    library
        .add_archive("https://e.example.test/", "E", "full page", "", Some(&pixels))
        .unwrap();
    let backup = source.dir.path().join("big.rbx");
    export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap();

    let (target, _vault, live) = target();
    let before = target.snapshot();
    let result = stage_watched(&target.store_path, &backup, EXPORT_PASS, Some(&live), &mut |n| {
        if n == 0 {
            use std::io::{Seek, SeekFrom};
            let mut file = fs::OpenOptions::new().write(true).open(&backup).unwrap();
            file.seek(SeekFrom::End(-100)).unwrap();
            file.write_all(&[0u8; 50]).unwrap();
        }
    });
    assert!(result.is_err());
    assert_eq!(target.snapshot(), before);
    target.assert_no_leftovers();
}

/// Round 2, R-003: a folder the store holds, whatever writer made it (and
/// whatever a backup restored), can be named again to rename, delete or
/// unfile it; creating one or renaming TO a name keeps the strict rule.
#[test]
fn folder_requests_name_held_folders_by_the_held_rule() {
    let source = include_str!("ipc.rs");
    let arm = |name: &str| {
        let at = source.find(&format!("\"{name}\" => {{")).expect(name);
        &source[at..at + 700]
    };
    assert!(arm("bookmark_folder_rename").contains("existing_folder_name(arg_str(args, \"from\")?)"));
    assert!(arm("bookmark_folder_rename").contains("normalize_folder_name(arg_str(args, \"to\")?)"));
    assert!(arm("bookmark_folder_delete").contains("existing_folder_name(arg_str(args, \"name\")?)"));
    assert!(arm("bookmark_folder_unfile").contains("existing_folder_name(arg_str(args, \"folder\")?)"));
    assert!(arm("bookmark_folder_file").contains("normalize_folder_name(arg_str(args, \"folder\")?)"));
}

#[test]
fn the_import_reads_its_source_in_exactly_one_place() {
    let source = include_str!("vault_backup.rs");
    // Up to the test module itself: earlier `#[cfg(test)]` items (the
    // test-only wrappers) are not where the shipped code ends.
    let code = &source[..source.find("#[path = \"vault_backup_tests.rs\"]").unwrap()];
    // The import's one read of its source is the watched open (progress and
    // stopping); a second, unwatched open would read the file twice.
    assert_eq!(code.matches("BackupReader::open_watched(src,").count(), 1);
    assert_eq!(code.matches("BackupReader::open(src,").count(), 0);
    for second_read in ["fs::read(src", "File::open(src", "read_to_end(src"] {
        assert!(!code.contains(second_read), "{second_read}");
    }
}

// ---- interrupted imports ----------------------------------------------------------

/// Stages and commits an import, then stops: the state a crash right after
/// the vault commit leaves.
struct Committed {
    target: Profile,
    vault: Vault,
    /// Kept alive: the backup lives in the source profile's folder.
    _source: Profile,
    backup: PathBuf,
    journal: Journal,
    before: Vec<(String, Vec<u8>)>,
}

fn committed_but_not_moved() -> Committed {
    let (source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let before = target.snapshot();
    let staged = stage(&target.store_path, &backup, EXPORT_PASS, Some(&library)).unwrap();
    drop((vault, library));
    let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
    let journal = read_journal(&target.store_path).unwrap().unwrap();
    assert_eq!(journal.phase, Phase::VaultCommitted);
    Committed {
        target,
        vault,
        _source: source,
        backup,
        journal,
        before,
    }
}

/// Performs the first `steps` moves of the swap by hand, as a crash between
/// them would leave them.
fn move_by_hand(target: &Profile, journal: &Journal, steps: usize) {
    let dir = target.dir.path();
    let staging = dir.join(&journal.staging);
    if steps >= 1 {
        // The target's own Library has a picture, so its folder exists.
        fs::rename(dir.join("archive"), dir.join(&journal.old_archive)).unwrap();
    }
    if steps >= 2 {
        fs::rename(staging.join("archive"), dir.join("archive")).unwrap();
    }
    if steps >= 3 {
        fs::rename(staging.join("store.rbs"), &target.store_path).unwrap();
    }
    if steps >= 4 {
        let mut swapped = journal.clone();
        swapped.phase = Phase::Swapped;
        write_journal(&target.store_path, &swapped).unwrap();
    }
}

#[test]
fn an_import_interrupted_after_the_vault_commit_is_finished_whatever_step_it_reached() {
    for steps in 0..=4 {
        let Committed {
            target,
            vault,
            journal,
            ..
        } = committed_but_not_moved();
        move_by_hand(&target, &journal, steps);
        let key = vault.library_key().unwrap();
        // Twice: a crash during recovery is the same as one before it.
        recover(&target.store_path, &key).unwrap_or_else(|_| panic!("step {steps}"));
        recover(&target.store_path, &key).unwrap();
        assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
        target.assert_no_leftovers();
    }
}

/// R-011: a crash part-way through the cleanup that follows `swapped`, at each
/// step it takes, is finished by the next open, and the older import's marker
/// goes only once the Library has been checked.
#[test]
fn a_crash_during_the_clean_up_is_finished_by_the_next_open() {
    for done in 0..=3 {
        let Committed {
            target,
            vault,
            journal,
            ..
        } = committed_but_not_moved();
        let marker = replace_marker(&target.store_path);
        fs::write(&marker, b"left by an older import\n").unwrap();
        move_by_hand(&target, &journal, 4);
        let dir = target.dir.path();
        if done >= 1 {
            fs::remove_file(&marker).unwrap();
        }
        if done >= 2 {
            fs::remove_dir_all(dir.join(&journal.old_archive)).unwrap();
        }
        if done >= 3 {
            fs::remove_dir_all(dir.join(&journal.staging)).unwrap();
        }
        let key = vault.library_key().unwrap();
        recover(&target.store_path, &key).unwrap_or_else(|_| panic!("after {done} cleanup steps"));
        assert!(!marker.exists());
        assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
        target.assert_no_leftovers();
    }
}

/// A new import keeps a `swapped` journal it cannot check (no vault is open),
/// and sweeps its folders when it completes.
#[test]
fn an_import_over_a_finished_but_unswept_one_keeps_it_until_it_completes() {
    let Committed {
        target,
        vault,
        journal,
        ..
    } = committed_but_not_moved();
    move_by_hand(&target, &journal, 4);
    drop(vault);
    let swapped = fs::read(journal_path(&target.store_path)).unwrap();
    let (_second, second_backup, _) = source_backup();
    let staged = stage(&target.store_path, &second_backup, EXPORT_PASS, None).unwrap();
    assert_eq!(staged.journal.superseded, Some(hex(&swapped)));
    let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
    let key = vault.library_key().unwrap();
    recover(&target.store_path, &key).unwrap();
    assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
    target.assert_no_leftovers();
}

/// Round 2, R-004: the process killed at EVERY step that changes the disk,
/// during the import or during the recovery that follows it. The next open,
/// with whichever vault is then on disk, leaves one whole profile: the
/// imported one, complete, or the original, untouched, and no leftovers.
#[test]
fn an_import_killed_at_any_step_leaves_one_whole_profile() {
    fn run(arm: Option<usize>) -> (Profile, usize, bool) {
        let (source, backup, _) = source_backup();
        let (target, vault, library) = target();
        let mut live_vault = Some(vault);
        let mut live_library = Some(library);
        let (finished, reached) = with_crash_at(arm, || {
            let staged = stage(&target.store_path, &backup, EXPORT_PASS, live_library.as_ref()).unwrap();
            live_library = None;
            live_vault = None;
            let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
            recover(&target.store_path, &vault.library_key().unwrap()).unwrap();
        });
        drop((live_vault, live_library, source));
        (target, reached, finished)
    }

    let (_, steps, finished) = run(None);
    assert_baseline(finished, WHOLE_IMPORT_STEPS);
    for at in 0..steps {
        let (target, _, _) = run(Some(at));
        // Whichever vault is on disk now decides what the next open finishes.
        let (vault, imported) = match Vault::unlock(&target.vault_path, NEW_PASS) {
            Ok(vault) => (vault, true),
            Err(_) => (Vault::unlock(&target.vault_path, PASS).unwrap(), false),
        };
        let key = vault.library_key().unwrap();
        recover(&target.store_path, &key).unwrap_or_else(|_| panic!("killed at step {at}"));
        let library = Store::open(&target.store_path, None, &key).unwrap();
        if imported {
            assert_is_the_source_library(&library);
            assert_eq!(library.downloads()[0].url, LOCAL_DOWNLOAD_URL);
        } else {
            assert_eq!(library.bookmarks()[0].url, "https://old.example.test/", "step {at}");
            assert!(library.pictures_open());
        }
        assert!(library.pictures_missing() == 0, "step {at}");
        target.assert_no_leftovers();
    }
}

/// Runs `act` with crash point `arm` armed; true when it ran to the end.
fn with_crash_at(arm: Option<usize>, act: impl FnOnce()) -> (bool, usize) {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    crash::REACHED.with(|r| r.set(0));
    crash::NAMES.with(|names| names.borrow_mut().clear());
    crash::ARMED.with(|a| a.set(arm));
    let finished = catch_unwind(AssertUnwindSafe(act)).is_ok();
    crash::ARMED.with(|a| a.set(None));
    (finished, crash::REACHED.with(|r| r.get()))
}

/// An unarmed run that a crash test counts its steps from must itself have
/// finished, and must have passed every named step it is meant to cover:
/// a count alone would not show a step was lost.
fn assert_baseline(finished: bool, covers: &[&str]) {
    assert!(finished, "the unarmed run did not finish");
    let reached = crash::NAMES.with(|names| names.borrow().clone());
    for name in covers {
        assert!(reached.contains(name), "the run never passed `{name}`: {reached:?}");
    }
}

/// Every named step a whole import and its recovery pass, except removing a
/// journal temp file, which only a crash leaves.
const WHOLE_IMPORT_STEPS: &[&str] = &[
    "journal-temp-next",
    "journal-rename-next",
    "staging-folder-next",
    "archive-folder-next",
    "library-create-next",
    "library-created",
    "picture-written",
    "library-committed",
    "vault-committed",
    "live-archive-aside-next",
    "staged-archive-in-next",
    "staged-library-in-next",
    "marker-removal-next",
    "folder-removal-next",
    "journal-removal-next",
];

/// The named steps a refused import and its rollback pass.
const ROLLBACK_STEPS: &[&str] = &[
    "journal-temp-next",
    "journal-rename-next",
    "staging-folder-next",
    "archive-folder-next",
    "library-create-next",
    "folder-removal-next",
];

/// Round 3, R-005: a failed import killed at every step of its own rollback
/// leaves the original profile whole once the next open has run.
#[test]
fn a_failed_import_killed_during_its_rollback_leaves_the_original_whole() {
    let (_source, backup, _) = source_backup();
    let steps = {
        let (target, _vault, library) = target();
        let (finished, steps) = with_crash_at(None, || {
            assert!(stage(&target.store_path, &backup, "not the passphrase", Some(&library)).is_err());
        });
        assert_baseline(finished, ROLLBACK_STEPS);
        assert_baseline(finished, &["journal-removal-next"]);
        steps
    };
    for at in 0..steps {
        let (target, vault, library) = target();
        with_crash_at(Some(at), || {
            let _ = stage(&target.store_path, &backup, "not the passphrase", Some(&library));
        });
        recover(&target.store_path, &vault.library_key().unwrap()).unwrap_or_else(|_| panic!("step {at}"));
        let reopened = Store::open(&target.store_path, None, &vault.library_key().unwrap()).unwrap();
        assert_eq!(reopened.bookmarks()[0].url, "https://old.example.test/", "step {at}");
        target.assert_no_leftovers();
    }
}

/// Round 3, R-005: a failed import over an unfinished one, killed at every
/// step of the rollback that puts the earlier journal back, still lets the
/// earlier import finish.
#[test]
fn a_failed_import_over_an_unfinished_one_killed_during_rollback_lets_it_finish() {
    let (_second, second_backup, _) = source_backup();
    let steps = {
        let Committed { target, .. } = committed_but_not_moved();
        let (finished, steps) = with_crash_at(None, || {
            assert!(stage(&target.store_path, &second_backup, "not the passphrase", None).is_err());
        });
        // The rollback here puts the earlier journal back: a journal write,
        // not a removal.
        assert_baseline(finished, ROLLBACK_STEPS);
        steps
    };
    for at in 0..steps {
        let Committed { target, vault, .. } = committed_but_not_moved();
        with_crash_at(Some(at), || {
            let _ = stage(&target.store_path, &second_backup, "not the passphrase", None);
        });
        let key = vault.library_key().unwrap();
        recover(&target.store_path, &key).unwrap_or_else(|_| panic!("step {at}"));
        assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
        target.assert_no_leftovers();
    }
}

/// Round 3, R-005: the import killed at any step AND the recovery that
/// follows killed at any of its own steps; a third open still leaves one
/// whole profile. Re-runs the import once per pair of steps, so it is
/// ignored in ordinary runs: `cargo test -p patanyx --bin patanyx --
/// --ignored killed_twice`.
#[test]
#[ignore]
fn an_import_killed_twice_still_leaves_one_whole_profile() {
    fn crashed_import(at: usize) -> Profile {
        let (_source, backup, _) = source_backup();
        let (target, vault, library) = target();
        let mut live = Some((vault, library));
        with_crash_at(Some(at), || {
            let staged = stage(&target.store_path, &backup, EXPORT_PASS, live.as_ref().map(|l| &l.1)).unwrap();
            live = None;
            let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
            recover(&target.store_path, &vault.library_key().unwrap()).unwrap();
        });
        drop(live);
        target
    }
    fn on_disk(target: &Profile) -> (Vault, bool) {
        match Vault::unlock(&target.vault_path, NEW_PASS) {
            Ok(vault) => (vault, true),
            Err(_) => (Vault::unlock(&target.vault_path, PASS).unwrap(), false),
        }
    }
    let steps = {
        let (_source, backup, _) = source_backup();
        let (target, vault, library) = target();
        let mut live = Some((vault, library));
        let (finished, steps) = with_crash_at(None, || {
            let staged = stage(&target.store_path, &backup, EXPORT_PASS, live.as_ref().map(|l| &l.1)).unwrap();
            live = None;
            let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
            recover(&target.store_path, &vault.library_key().unwrap()).unwrap();
        });
        assert_baseline(finished, WHOLE_IMPORT_STEPS);
        steps
    };
    let mut pairs = 0;
    for first in 0..steps {
        for second in 0.. {
            let target = crashed_import(first);
            let (vault, imported) = on_disk(&target);
            let key = vault.library_key().unwrap();
            let (completed, _) = with_crash_at(Some(second), || {
                let _ = recover(&target.store_path, &key);
            });
            recover(&target.store_path, &key).unwrap_or_else(|_| panic!("steps {first}, {second}"));
            let library = Store::open(&target.store_path, None, &key).unwrap();
            if imported {
                assert_is_the_source_library(&library);
            } else {
                assert_eq!(library.bookmarks()[0].url, "https://old.example.test/");
            }
            assert!(library.pictures_open(), "steps {first}, {second}");
            target.assert_no_leftovers();
            pairs += 1;
            if completed {
                break;
            }
        }
    }
    assert!(pairs > steps);
}

#[test]
fn a_crash_after_the_vault_commit_but_before_the_journal_said_so_is_finished_too() {
    let Committed {
        target,
        vault,
        mut journal,
        ..
    } = committed_but_not_moved();
    journal.phase = Phase::Staged;
    write_journal(&target.store_path, &journal).unwrap();
    let key = vault.library_key().unwrap();
    recover(&target.store_path, &key).unwrap();
    assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
}

#[test]
fn an_import_interrupted_before_the_vault_commit_is_undone_by_the_vault_still_there() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let before = target.snapshot();
    let staged = stage(&target.store_path, &backup, EXPORT_PASS, Some(&library)).unwrap();
    drop(staged);
    drop(library);
    let key = vault.library_key().unwrap();
    recover(&target.store_path, &key).unwrap();
    assert_eq!(target.snapshot(), before);
    let library = Store::open(&target.store_path, None, &key).unwrap();
    assert_eq!(library.bookmarks()[0].url, "https://old.example.test/");
}

#[test]
fn an_import_that_crashed_while_reading_is_undone_without_any_key() {
    let (target, vault, _library) = target();
    let before = target.snapshot();
    let journal = Journal {
        phase: Phase::Preparing,
        staging: random_name(STAGING_PREFIX),
        old_archive: random_name(OLD_ARCHIVE_PREFIX),
        vault_check: None,
        source: "/backups/b.rbx".into(),
        superseded: None,
    };
    write_journal(&target.store_path, &journal).unwrap();
    fs::create_dir(target.dir.path().join(&journal.staging)).unwrap();
    fs::write(target.dir.path().join(&journal.staging).join("half"), b"partial").unwrap();
    recover(&target.store_path, &vault.library_key().unwrap()).unwrap();
    assert_eq!(target.snapshot(), before);
}

#[test]
fn a_committed_import_whose_staging_folder_is_gone_is_reported_never_opened() {
    let Committed {
        target,
        vault,
        backup,
        journal,
        before,
        ..
    } = committed_but_not_moved();
    fs::remove_dir_all(target.dir.path().join(&journal.staging)).unwrap();
    let key = vault.library_key().unwrap();
    assert_eq!(recover(&target.store_path, &key), Err(Unfinished));
    assert_eq!(unfinished_source(&target.store_path), Some(backup.to_string_lossy().into_owned()));
    // The old Library is still there, untouched, and does not open under the
    // imported vault.
    let library = before.iter().find(|(p, _)| p == "store.rbs").unwrap();
    assert_eq!(fs::read(&target.store_path).unwrap(), library.1);
    assert!(Store::open(&target.store_path, None, &key).is_err());
}

#[test]
fn a_committed_import_whose_staged_library_file_is_gone_never_opens_the_old_one() {
    let Committed {
        target,
        vault,
        journal,
        ..
    } = committed_but_not_moved();
    fs::remove_file(target.dir.path().join(&journal.staging).join("store.rbs")).unwrap();
    let key = vault.library_key().unwrap();
    assert_eq!(recover(&target.store_path, &key), Err(Unfinished));
    // Still unfinished on the next try: never declared done over the old file.
    assert_eq!(recover(&target.store_path, &key), Err(Unfinished));
    assert!(journal_exists(&target.store_path));
    assert!(Store::open(&target.store_path, None, &key).is_err());
}

// ---- review round 1 reproductions ------------------------------------------------

/// R-001: a `swapped` journal is a claim, not a fact. One that does not belong
/// to the open vault must not remove the marker that keeps an older import's
/// Library shut.
#[test]
fn a_swapped_journal_for_another_vault_removes_no_protection() {
    let (target, vault, library) = target();
    drop(library);
    let marker = replace_marker(&target.store_path);
    fs::write(&marker, b"left by an older import\n").unwrap();
    let forged = Journal {
        phase: Phase::Swapped,
        staging: random_name(STAGING_PREFIX),
        old_archive: random_name(OLD_ARCHIVE_PREFIX),
        vault_check: Some("ab".repeat(32)),
        source: "x".into(),
        superseded: None,
    };
    write_journal(&target.store_path, &forged).unwrap();
    assert_eq!(recover(&target.store_path, &vault.library_key().unwrap()), Err(Unfinished));
    assert!(marker.exists(), "the protection marker was removed on a forged claim");
}

/// R-002: a staged picture folder that is a link is never moved into place:
/// the store would then prune through it, outside the profile.
#[cfg(unix)]
#[test]
fn a_linked_staged_picture_folder_is_never_moved_into_place() {
    let Committed {
        target,
        vault,
        journal,
        ..
    } = committed_but_not_moved();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("precious"), b"keep me").unwrap();
    let staged_archive = target.dir.path().join(&journal.staging).join("archive");
    fs::remove_dir_all(&staged_archive).unwrap();
    std::os::unix::fs::symlink(outside.path(), &staged_archive).unwrap();
    let key = vault.library_key().unwrap();
    assert_eq!(recover(&target.store_path, &key), Err(Unfinished));
    let live = target.dir.path().join("archive");
    assert!(!fs::symlink_metadata(&live).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(outside.path().join("precious")).unwrap(), b"keep me");
}

/// R-005: a staged picture folder that has gone missing is not an
/// already-finished move: the Library is not declared done without the
/// pictures its records name.
#[test]
fn a_missing_staged_picture_folder_is_never_taken_as_already_moved() {
    let Committed {
        target,
        vault,
        journal,
        ..
    } = committed_but_not_moved();
    fs::remove_dir_all(target.dir.path().join(&journal.staging).join("archive")).unwrap();
    let key = vault.library_key().unwrap();
    assert_eq!(recover(&target.store_path, &key), Err(Unfinished));
    assert!(journal_exists(&target.store_path), "the evidence was cleaned away");
}

/// R-004: the round-trip contract at the Deep Recall picture total. Pictures
/// the store's own API accepts must export into a backup this build imports,
/// or the export must refuse. About 256 MB of pictures, so it is ignored in
/// ordinary runs: `cargo test -p patanyx --bin patanyx -- --ignored
/// at_the_picture_total`.
#[test]
#[ignore]
fn at_the_picture_total_an_export_is_one_this_build_imports() {
    const MIB: usize = 1024 * 1024;
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    let mut sizes = vec![64 * MIB; 3];
    sizes.push(64 * MIB - 147);
    for (n, size) in sizes.into_iter().enumerate() {
        let pixels = vec![n as u8; size];
        let _ = library.add_archive(&format!("https://big{n}.example.test/"), "big", "full page", "", Some(&pixels));
    }
    let backup = source.dir.path().join("total.rbx");
    match export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap() {
        ExportOutcome::Refused(_) => assert!(!backup.exists()),
        ExportOutcome::Written(_) => {
            let (target, _vault, live) = target();
            let staged = stage(&target.store_path, &backup, EXPORT_PASS, Some(&live));
            assert!(staged.is_ok(), "this build refused its own export: {staged:?}");
        }
    }
}

/// Round 2, R-001: a backup of this very profile reuses every picture id, so
/// the old pictures (under the old Library's key) are all present by name.
/// A staged picture folder that went missing must still not be taken for
/// one already moved: the pictures have to open under the new Library.
#[test]
fn old_pictures_with_the_same_ids_are_not_taken_for_the_restored_ones() {
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    fill(&mut library);
    let backup_dir = tempfile::tempdir().unwrap();
    let backup = backup_dir.path().join("self.rbx");
    export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap();
    let staged = stage(&source.store_path, &backup, EXPORT_PASS, Some(&library)).unwrap();
    let staging = source.dir.path().join(&staged.journal.staging);
    drop((vault, library));
    let (vault, _) = staged.install(&source.vault_path, NEW_PASS).unwrap();
    fs::remove_dir_all(staging.join("archive")).unwrap();
    let key = vault.library_key().unwrap();
    assert_eq!(recover(&source.store_path, &key), Err(Unfinished));
    assert!(journal_exists(&source.store_path));
}

#[test]
fn a_journal_for_a_vault_that_is_not_here_touches_nothing() {
    let Committed { target, .. } = committed_but_not_moved();
    let before = target.snapshot();
    assert_eq!(recover(&target.store_path, &[9u8; 32]), Err(Unfinished));
    assert_eq!(target.snapshot(), before);
}

#[test]
fn a_journal_naming_anything_but_an_imports_own_folders_is_never_acted_on() {
    let (target, vault, _library) = target();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("precious"), b"keep me").unwrap();
    let escape = format!("../{}", outside.path().file_name().unwrap().to_string_lossy());
    for (staging, old_archive) in [
        (escape.as_str(), "archive.old-0123456789abcdef"),
        ("library-staging-0123456789abcdef", "archive"),
        ("library-staging-0123456789ABCDEF", "archive.old-0123456789abcdef"),
        ("library-staging-01234567", "archive.old-0123456789abcdef"),
    ] {
        let body = serde_json::json!({
            "phase": "preparing",
            "staging": staging,
            "old_archive": old_archive,
            "vault_check": null,
            "source": "x",
            "superseded": null,
        });
        fs::write(journal_path(&target.store_path), body.to_string()).unwrap();
        let before = target.snapshot();
        assert_eq!(recover(&target.store_path, &vault.library_key().unwrap()), Err(Unfinished));
        // A new import keeps it, as bytes, without acting on what it names.
        assert!(settle(&target.store_path).unwrap().is_some());
        assert_eq!(target.snapshot(), before);
        assert_eq!(fs::read(outside.path().join("precious")).unwrap(), b"keep me");
    }
}

#[test]
fn an_unreadable_journal_is_put_back_by_a_failed_import_and_cleared_by_a_completed_one() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("precious"), b"keep me").unwrap();
    let escape = format!("../{}", outside.path().file_name().unwrap().to_string_lossy());
    let unreadable = serde_json::json!({
        "phase": "vault_committed",
        "staging": escape,
        "old_archive": "archive",
        "vault_check": "00",
        "source": "x",
        "superseded": null,
    })
    .to_string();
    fs::write(journal_path(&target.store_path), &unreadable).unwrap();
    // Debris an earlier import left, which only a sweep by name can find.
    fs::create_dir(target.dir.path().join("library-staging-00112233445566aa")).unwrap();

    let failed = stage(&target.store_path, &backup, "not the passphrase", Some(&library));
    assert!(failed.is_err());
    assert_eq!(fs::read(journal_path(&target.store_path)).unwrap(), unreadable.as_bytes());

    let (_, library, _) = import_into(&target, &backup, Some(library), Some(vault));
    assert_is_the_source_library(&library);
    target.assert_no_leftovers();
    assert_eq!(fs::read(outside.path().join("precious")).unwrap(), b"keep me");
    assert!(target.dir.path().join("archive").is_dir());
}

#[test]
fn an_import_over_an_unfinished_one_puts_it_back_if_it_fails() {
    let Committed {
        target,
        vault: first_vault,
        journal: first_journal,
        ..
    } = committed_but_not_moved();
    let first_key = first_vault.library_key().unwrap();
    let (_second, second_backup, _) = source_backup();
    let failed = stage(&target.store_path, &second_backup, "not the passphrase", None);
    assert!(failed.is_err());
    assert_eq!(read_journal(&target.store_path).unwrap(), Some(first_journal));
    recover(&target.store_path, &first_key).unwrap();
    assert_is_the_source_library(&Store::open(&target.store_path, None, &first_key).unwrap());
    target.assert_no_leftovers();
}

#[test]
fn an_import_over_an_unfinished_one_clears_it_when_it_completes() {
    let Committed {
        target,
        vault: first_vault,
        journal: first_journal,
        ..
    } = committed_but_not_moved();
    drop(first_vault);
    let first_bytes = fs::read(journal_path(&target.store_path)).unwrap();
    assert_eq!(parse_journal(&first_bytes), Some(first_journal));
    let (_second, second_backup, _) = source_backup();
    let staged = stage(&target.store_path, &second_backup, EXPORT_PASS, None).unwrap();
    assert_eq!(staged.journal.superseded, Some(hex(&first_bytes)));
    let (vault, _) = staged.install(&target.vault_path, NEW_PASS).unwrap();
    let key = vault.library_key().unwrap();
    recover(&target.store_path, &key).unwrap();
    assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
    target.assert_no_leftovers();
}

#[test]
fn the_older_imports_marker_goes_once_the_library_it_guarded_is_replaced() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let marker = replace_marker(&target.store_path);
    fs::write(&marker, b"left by an older import\n").unwrap();
    let (_, _, _) = import_into(&target, &backup, Some(library), Some(vault));
    assert!(!marker.exists());
}

/// A journal temporary file a crash left before its rename names the backup
/// file: it alone makes the next open run recovery, which removes it.
#[test]
fn a_journal_temp_file_alone_brings_recovery_which_removes_it() {
    let (target, vault, _library) = target();
    assert!(!journal_exists(&target.store_path));
    let temp = target.dir.path().join("store.rbs.replace-journal.tmp-0123456789abcdef");
    fs::write(&temp, b"{\"source\":\"/backups/b.rbx\"}").unwrap();
    fs::write(target.dir.path().join("store.rbs.replace-journal.tmp-not-ours"), b"x").unwrap();
    assert!(journal_exists(&target.store_path));
    recover(&target.store_path, &vault.library_key().unwrap()).unwrap();
    assert!(!temp.exists());
    assert!(target.dir.path().join("store.rbs.replace-journal.tmp-not-ours").exists());
}

/// Round 3, R-001: only THIS Library's journal temporary FILES are removed;
/// a folder, or another file's look-alike, is never touched.
#[test]
fn only_this_librarys_journal_temp_files_are_ever_removed() {
    let (target, vault, _library) = target();
    let dir = target.dir.path();
    let folder = dir.join("store.rbs.replace-journal.tmp-0123456789abcdef");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("precious"), b"keep me").unwrap();
    let other = dir.join("notes.replace-journal.tmp-0123456789abcdef");
    fs::write(&other, b"not ours").unwrap();
    recover(&target.store_path, &vault.library_key().unwrap()).unwrap();
    assert_eq!(fs::read(folder.join("precious")).unwrap(), b"keep me");
    assert!(other.exists());
}

/// Round 3, R-002: every restored picture must open under the new Library,
/// not only one of them.
#[test]
fn one_old_picture_among_new_ones_keeps_the_import_unfinished() {
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    fill(&mut library);
    library
        .add_archive("https://e.example.test/", "E", "full page", "", Some(&[5u8; 4096]))
        .unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let backup = backup_dir.path().join("self.rbx");
    export(&vault, Some(&library), &backup, EXPORT_PASS).unwrap();
    let staged = stage(&source.store_path, &backup, EXPORT_PASS, Some(&library)).unwrap();
    let staged_archive = source.dir.path().join(&staged.journal.staging).join("archive");
    // The largest picture, swapped for the old Library's copy of the same id.
    let largest = library
        .archive()
        .iter()
        .filter(|r| r.has_picture)
        .max_by_key(|r| r.picture_bytes)
        .unwrap()
        .id
        .clone();
    fs::copy(source.dir.path().join("archive").join(&largest), staged_archive.join(&largest)).unwrap();
    drop((vault, library));
    let (vault, _) = staged.install(&source.vault_path, NEW_PASS).unwrap();
    let key = vault.library_key().unwrap();
    assert_eq!(recover(&source.store_path, &key), Err(Unfinished));
    assert!(journal_exists(&source.store_path));
}

/// Round 4, R-001: a picture entry that is a link is not a restored picture,
/// even when what it points at opens: cleanup can delete the target. The
/// test reads every picture AFTER recovery to show nothing was lost.
#[cfg(unix)]
#[test]
fn a_linked_picture_entry_keeps_the_import_unfinished() {
    let Committed {
        target,
        vault,
        journal,
        ..
    } = committed_but_not_moved();
    let staging = target.dir.path().join(&journal.staging);
    let entry = fs::read_dir(staging.join("archive"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .next()
        .unwrap();
    let elsewhere = staging.join("moved-picture");
    fs::rename(&entry, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &entry).unwrap();
    let key = vault.library_key().unwrap();
    match recover(&target.store_path, &key) {
        Err(Unfinished) => assert!(journal_exists(&target.store_path)),
        Ok(()) => {
            let library = Store::open(&target.store_path, None, &key).unwrap();
            assert!(library.pictures_open(), "declared done, and a picture no longer opens");
        }
    }
}

/// Round 5, R-001: the live Library file must be a regular file too. A link
/// to a Library inside the staging folder would open, and cleanup would
/// then delete what it points at. The test reopens the Library afterwards.
#[cfg(unix)]
#[test]
fn a_linked_live_library_is_never_taken_as_in_place() {
    let Committed {
        target,
        vault,
        journal,
        ..
    } = committed_but_not_moved();
    move_by_hand(&target, &journal, 4);
    let elsewhere = target.dir.path().join(&journal.staging).join("moved-library");
    fs::rename(&target.store_path, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &target.store_path).unwrap();
    let key = vault.library_key().unwrap();
    match recover(&target.store_path, &key) {
        Err(Unfinished) => assert!(journal_exists(&target.store_path)),
        Ok(()) => assert!(
            Store::open(&target.store_path, None, &key).is_ok(),
            "declared done, and the Library no longer opens"
        ),
    }
}

#[test]
fn discard_removes_only_what_an_import_made() {
    let (target, _vault, _library) = target();
    let dir = target.dir.path();
    fs::create_dir(dir.join("library-staging-0123456789abcdef")).unwrap();
    fs::create_dir(dir.join("archive.old-fedcba9876543210")).unwrap();
    fs::create_dir(dir.join("library-staging-not-ours")).unwrap();
    fs::write(journal_path(&target.store_path), b"anything at all").unwrap();
    discard(&target.store_path).unwrap();
    assert!(!dir.join("library-staging-0123456789abcdef").exists());
    assert!(!dir.join("archive.old-fedcba9876543210").exists());
    assert!(dir.join("library-staging-not-ours").exists());
    assert!(dir.join("archive").exists() && target.store_path.exists());
    assert!(!journal_exists(&target.store_path));
}

#[test]
fn add_on_data_is_refused_as_coming_from_a_newer_patanyx() {
    let source = Profile::new();
    let vault = source.vault();
    let backup = source.dir.path().join("with-addon.rbx");
    let records = serde_json::to_vec(&empty_backup()).unwrap();
    let writer_limits = SectionLimits {
        addon: 1024,
        ..section_limits()
    };
    vault
        .export_backup(&backup, EXPORT_PASS, writer_limits, &mut |sink| {
            sink.section(SectionKind::Library, "", &records)?;
            sink.section(SectionKind::Addon, "notes/1", b"a page of notes")
        })
        .unwrap();
    let (target, _vault, library) = target();
    let before = target.snapshot();
    let refused = stage(&target.store_path, &backup, EXPORT_PASS, Some(&library));
    assert!(matches!(
        refused,
        Err(ImportError::Backup(ExportError::UnreadableVersion(_)))
    ));
    assert_eq!(target.snapshot(), before);
}


// ---- stopping, and the import's second half (the worker steps) ------------------

/// Files beside `dest` an export left: its temporary file is named `.tmp-`.
fn export_leftovers(dest: &Path) -> usize {
    fs::read_dir(dest.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .count()
}

/// A source profile whose vault and Library stay open, for exporting.
fn open_source() -> (Profile, Vault, Store) {
    let source = Profile::new();
    let vault = source.vault();
    let mut library = source.library(&vault);
    fill(&mut library);
    (source, vault, library)
}

#[test]
fn an_export_stopped_before_any_picture_writes_nothing_and_changes_nothing() {
    let (source, vault, library) = open_source();
    let pictures = library.backup_picture_ids().len();
    assert_eq!(pictures, 2);
    let out = tempfile::tempdir().unwrap();
    for stop_at in 0..pictures {
        let before = source.snapshot();
        let dest = out.path().join(format!("stopped-{stop_at}.rbx"));
        let watch = BackupWatch::new();
        let input = ExportInput::take(&vault, Some(&library)).unwrap();
        let result = input.write_watched(&dest, EXPORT_PASS, &watch, &mut |index| {
            if index == stop_at {
                watch.stop();
            }
        });
        assert!(matches!(result, Err(ExportError::Cancelled)), "stop at picture {stop_at}: {result:?}");
        assert!(!dest.exists(), "stop at picture {stop_at} left a backup");
        assert_eq!(export_leftovers(&dest), 0, "stop at picture {stop_at} left a temporary file");
        assert!(source.snapshot() == before, "stop at picture {stop_at} changed the source profile");
    }
    let snapshot = BackupWatch::new();
    drop(snapshot);
}

#[test]
fn a_picture_deleted_after_the_export_started_refuses_it_by_name() {
    let (_source, vault, mut library) = open_source();
    let input = ExportInput::take(&vault, Some(&library)).unwrap();
    let id = library.archive().iter().find(|r| r.has_picture).unwrap().id.clone();
    library.delete_archive(&id).unwrap();
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("changed.rbx");
    match input.write(&dest, EXPORT_PASS, &BackupWatch::new()).unwrap() {
        ExportOutcome::Refused(refusal) => {
            assert_eq!(refusal.code, "export_library_changed");
            assert_eq!(refusal.item.as_deref(), Some("C page"));
        }
        ExportOutcome::Written(_) => panic!("a backup naming a deleted picture was written"),
    }
    assert!(!dest.exists());
    assert_eq!(export_leftovers(&dest), 0);
}

/// The backup holds the Library as it was when the export started: a change
/// made while it is written is not half in it.
#[test]
fn an_export_writes_the_library_as_it_was_when_it_started() {
    let (_source, vault, mut library) = open_source();
    let input = ExportInput::take(&vault, Some(&library)).unwrap();
    library.add_bookmark("https://later.example.test/", "Later").unwrap();
    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("as-taken.rbx");
    let summary = match input.write(&dest, EXPORT_PASS, &BackupWatch::new()).unwrap() {
        ExportOutcome::Written(summary) => summary,
        ExportOutcome::Refused(refusal) => panic!("refused: {refusal:?}"),
    };
    assert_eq!(summary.bookmarks, 2);
    let mut reader = BackupReader::open(&dest, EXPORT_PASS, section_limits()).unwrap();
    let section = reader.next_section().unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&section.body).contains("later.example.test"));
}

#[test]
fn an_import_stopped_after_any_section_changes_nothing_live() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let before = target.snapshot();
    let kept = library.kept_downloads();
    // The Library section, then each of the two pictures.
    for stop_after in 0..3 {
        let watch = BackupWatch::new();
        let result = stage_inner(&target.store_path, &backup, EXPORT_PASS, Some(&kept), &watch, &mut |n| {
            if n == stop_after {
                watch.stop();
            }
        });
        assert!(
            matches!(result, Err(ImportError::Backup(ExportError::Cancelled))),
            "stop after section {stop_after}: {result:?}"
        );
        assert!(target.snapshot() == before, "stop after section {stop_after} changed a live file");
        target.assert_no_leftovers();
    }
    drop((vault, library));
}

#[test]
fn a_stopped_import_over_an_unfinished_one_puts_it_back() {
    let Committed {
        target,
        vault: first_vault,
        journal: first_journal,
        ..
    } = committed_but_not_moved();
    let first_key = first_vault.library_key().unwrap();
    let (_second, second_backup, _) = source_backup();
    let watch = BackupWatch::new();
    let result = stage_inner(&target.store_path, &second_backup, EXPORT_PASS, None, &watch, &mut |_| watch.stop());
    assert!(matches!(result, Err(ImportError::Backup(ExportError::Cancelled))), "{result:?}");
    assert_eq!(read_journal(&target.store_path).unwrap(), Some(first_journal));
    recover(&target.store_path, &first_key).unwrap();
    assert_is_the_source_library(&Store::open(&target.store_path, None, &first_key).unwrap());
    target.assert_no_leftovers();
}

/// A stop is only called clean when what it built is gone. When a folder
/// cannot be removed, the answer says files remain, and the next open (any
/// vault: the journal is still at `preparing`) removes them.
#[test]
fn a_stop_whose_clean_up_fails_says_files_remain_and_the_next_open_removes_them() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let kept = library.kept_downloads();
    let watch = BackupWatch::new();
    let result = stage_inner(&target.store_path, &backup, EXPORT_PASS, Some(&kept), &watch, &mut |n| {
        if n == 1 {
            watch.stop();
            crash::FAIL_REMOVAL.with(|fail| fail.set(true));
        }
    });
    crash::FAIL_REMOVAL.with(|fail| fail.set(false));
    assert!(matches!(result, Err(ImportError::StoppedLeavingFiles)), "{result:?}");
    assert!(journal_exists(&target.store_path), "the journal no longer names what is left");
    let key = vault.library_key().unwrap();
    drop(library);
    recover(&target.store_path, &key).unwrap();
    target.assert_no_leftovers();
    let reopened = Store::open(&target.store_path, None, &key).unwrap();
    assert_eq!(reopened.bookmarks().len(), 1, "the live Library is not the one it was");
}

/// Staged, then given up before the commit: as if it never ran.
#[test]
fn a_staged_import_abandoned_before_its_commit_changes_nothing() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let before = target.snapshot();
    let kept = library.kept_downloads();
    let staged = stage_with(&target.store_path, &backup, EXPORT_PASS, Some(&kept), &BackupWatch::new()).unwrap();
    staged.abandon().unwrap();
    assert!(target.snapshot() == before);
    target.assert_no_leftovers();
    drop((vault, library));
}

/// The second half, as a worker runs it: the vault is written, the Library
/// moved into place and checked, and opened, all off the caller's thread.
#[test]
fn commit_installs_the_vault_and_hands_back_its_library_open() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let kept = library.kept_downloads();
    let staged = stage_with(&target.store_path, &backup, EXPORT_PASS, Some(&kept), &BackupWatch::new()).unwrap();
    drop((vault, library));
    let super::Committed { vault, recovery, summary, library, .. } =
        commit(staged, &target.vault_path, NEW_PASS).unwrap();
    assert!(!recovery.to_printable().is_empty());
    assert_eq!(summary.downloads_kept, 1);
    match library {
        ImportedLibrary::Opened { store, cleanup_pending } => {
            assert!(!cleanup_pending);
            assert_is_the_source_library(&store);
            assert!(store.downloads().iter().any(|d| d.filename == "this-computer.zip"));
        }
        other => panic!("not opened: {other:?}"),
    }
    target.assert_no_leftovers();
    // The vault on disk is the imported one, under the new passphrase.
    drop(vault);
    assert!(Vault::unlock(&target.vault_path, NEW_PASS).is_ok());
}

/// A leftover the clean-up cannot remove leaves the journal, but the Library
/// was checked in place, so it opens now; the next open finishes the rest.
#[test]
fn a_commit_whose_clean_up_fails_opens_the_library_and_says_the_journal_remains() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let kept = library.kept_downloads();
    let staged = stage_with(&target.store_path, &backup, EXPORT_PASS, Some(&kept), &BackupWatch::new()).unwrap();
    drop((vault, library));
    crash::FAIL_REMOVAL.with(|fail| fail.set(true));
    let committed = commit(staged, &target.vault_path, NEW_PASS);
    crash::FAIL_REMOVAL.with(|fail| fail.set(false));
    let committed = committed.unwrap();
    let key = committed.vault.library_key().unwrap();
    match committed.library {
        ImportedLibrary::Opened { store, cleanup_pending } => {
            assert!(cleanup_pending, "a journal left behind was not reported");
            assert_is_the_source_library(&store);
        }
        other => panic!("not opened: {other:?}"),
    }
    assert!(journal_exists(&target.store_path));
    recover(&target.store_path, &key).unwrap();
    target.assert_no_leftovers();
}


/// A finished swap whose leftovers cannot be deleted yet (on Windows, a file
/// an antivirus holds open) still opens the Library at every later open, as
/// the commit itself already did; the leftovers go when they can (security
/// pass, F-101).
#[test]
fn an_undeletable_leftover_after_the_swap_does_not_keep_the_library_shut() {
    let (_source, backup, _) = source_backup();
    let (target, vault, library) = target();
    let kept = library.kept_downloads();
    let staged = stage_with(&target.store_path, &backup, EXPORT_PASS, Some(&kept), &BackupWatch::new()).unwrap();
    drop((vault, library));
    crash::FAIL_REMOVAL.with(|fail| fail.set(true));
    let committed = commit(staged, &target.vault_path, NEW_PASS);
    let key = committed.as_ref().unwrap().vault.library_key().unwrap();
    // A later open, with the leftover still undeletable.
    let reopened = recover(&target.store_path, &key);
    crash::FAIL_REMOVAL.with(|fail| fail.set(false));
    drop(committed);
    assert!(reopened.is_ok(), "an undeletable leftover kept the Library shut");
    assert!(journal_exists(&target.store_path), "the leftover's journal is gone before the leftover");
    assert_is_the_source_library(&Store::open(&target.store_path, None, &key).unwrap());
    // Once it can be deleted, the next open finishes the clean-up.
    recover(&target.store_path, &key).unwrap();
    target.assert_no_leftovers();
}
