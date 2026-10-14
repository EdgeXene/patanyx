//! The Library half of a Vault backup (`library_backup.rs`).
//!
//! Properties pinned here:
//! - a full Library round-trips into a new, empty Library under a different
//!   key: every bookmark, folder, shelf, Deep Recall page, snapshot, picture
//!   and site exception, with ids, times and shelf numbers kept;
//! - download records never travel, and the old computer's own records are
//!   kept and re-signed, while a record that fails its check is left behind;
//! - every limit and every cross-reference is checked BEFORE anything is
//!   written, with the blob writer's own id check;
//! - a restore only ever goes into an empty Library, and a failed commit
//!   leaves nothing behind;
//! - the carried types' keys are pinned to `LIBRARY_BACKUP_SCHEMA`.

use super::*;

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("patanyx-library-backup-{tag}-{}", random_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn vault_key() -> Zeroizing<[u8; crypto::KEY_LEN]> {
    Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>())
}

fn new_library(dir: &Path) -> Store {
    new_library_keyed(dir).0
}

/// A new Library and the vault key it opens with.
fn new_library_keyed(dir: &Path) -> (Store, Zeroizing<[u8; crypto::KEY_LEN]>) {
    let key = vault_key();
    (Store::create_in_vault(&dir.join("store.rbs"), &key).unwrap(), key)
}

fn page_digest(words: &str) -> ContentDigest {
    patanyx_integrity::digest(format!("<p>{words}</p>").as_bytes()).unwrap()
}

const ARCHIVE_PNG: &[u8] = b"\x89PNG\r\n\x1a\n archived pixels";
const SNAPSHOT_PNG: &[u8] = b"\x89PNG\r\n\x1a\n snapshot pixels";
const DOWNLOAD_URL: &str = "https://downloads.example.test/private-history.zip";

/// A Library holding one of everything, the way a real one does.
fn full_library(dir: &Path) -> Store {
    let mut store = new_library(dir);
    let kept = store.add_bookmark("https://a.example.test/", "A").unwrap();
    store.set_bookmark_tags(&kept, vec!["Chem".into(), "lab".into()]).unwrap();
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
        .add_archive("https://c.example.test/", "C", "full page", "words in a picture", Some(ARCHIVE_PNG))
        .unwrap();
    store
        .add_archive("https://d.example.test/", "D", "visible area", "text only", None)
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
    store
}

/// Exports `from` and restores it into a new Library in its own directory,
/// the way an import does, keeping `from`'s download records.
fn round_trip(from: &Store) -> (PathBuf, Store, RestoreSummary) {
    let (dir, to, summary, _) = round_trip_keyed(from);
    (dir, to, summary)
}

fn round_trip_keyed(
    from: &Store,
) -> (PathBuf, Store, RestoreSummary, Zeroizing<[u8; crypto::KEY_LEN]>) {
    let dir = scratch_dir("restored");
    let (mut to, key) = new_library_keyed(&dir);
    let validated = validate_backup(from.library_backup()).unwrap();
    let mut restore = to.begin_restore(validated).unwrap();
    for id in from.backup_picture_ids() {
        restore.put_picture(&id, &from.backup_picture(&id).unwrap()).unwrap();
    }
    let summary = restore.commit(Some(from)).unwrap();
    (dir, to, summary, key)
}

#[test]
fn a_full_library_round_trips_into_a_new_library_under_a_new_key() {
    let src_dir = scratch_dir("source");
    let source = full_library(&src_dir);
    let (dst_dir, restored, summary, key) = round_trip_keyed(&source);

    assert_eq!(restored.data.bookmarks, source.data.bookmarks, "ids, tags, pins, digests kept");
    assert_eq!(restored.data.bookmark_folders, source.data.bookmark_folders);
    assert_eq!(restored.data.shelves, source.data.shelves, "ids, numbers, times, notes, groups kept");
    assert_eq!(restored.data.next_shelf_seq, source.data.next_shelf_seq);
    assert_eq!(restored.data.divergence_overrides, source.data.divergence_overrides);
    assert_eq!(restored.data.page_snapshots.len(), 1);
    assert_eq!(restored.data.archive.len(), 2);
    for (a, b) in restored.data.archive.iter().zip(&source.data.archive) {
        assert_eq!((&a.id, &a.url, &a.title, a.created_at, &a.scope, &a.text, a.has_picture),
                   (&b.id, &b.url, &b.title, b.created_at, &b.scope, &b.text, b.has_picture));
    }

    // The pictures came back, and only under the NEW key: the restored
    // Library's directory is a different one with a different key.
    for id in source.backup_picture_ids() {
        assert_eq!(&*restored.backup_picture(&id).unwrap(), &*source.backup_picture(&id).unwrap());
    }
    assert_ne!(*restored.key, *source.key, "a new Library has its own key");

    // It is on disk, not only in memory: reopened with its own vault key, it
    // holds the same Library, and no other key opens it.
    let in_memory = restored.data.clone();
    drop(restored);
    let reopened = Store::open(&dst_dir.join("store.rbs"), None, &key).unwrap();
    assert_eq!(reopened.data, in_memory);
    assert!(Store::open(&dst_dir.join("store.rbs"), None, &vault_key()).is_err());

    assert_eq!(summary.bookmarks, 2);
    assert_eq!(summary.folders, 1);
    assert_eq!(summary.shelves, 1);
    assert_eq!(summary.archive_pages, 2);
    assert_eq!(summary.snapshots, 1);
    assert_eq!(summary.pictures, 2);
    assert_eq!(summary.site_exceptions, 1);
    assert_eq!(summary.downloads_kept, 1);
    assert_eq!(summary.downloads_dropped, 0);
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dst_dir);
}

#[test]
fn download_records_never_travel_but_this_computers_own_are_kept_and_re_signed() {
    let src_dir = scratch_dir("downloads");
    let source = full_library(&src_dir);

    // Never in the backup, in any form.
    let json = serde_json::to_string(&source.library_backup()).unwrap();
    assert!(!json.contains(DOWNLOAD_URL), "a download address leaked into a backup");
    assert!(!json.contains("private-history.zip"));
    assert!(!json.contains("downloads"), "there is no downloads field at all");

    // Kept on import, and signed under the new Library's key.
    let (dst_dir, restored, _) = round_trip(&source);
    assert_eq!(restored.data.downloads.len(), 1);
    let id = restored.data.downloads[0].id.clone();
    assert!(restored.verify_download(&id).unwrap(), "re-signed under the new key");
    assert_ne!(restored.data.downloads[0].hmac, source.data.downloads[0].hmac);
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dst_dir);
}

#[test]
fn a_download_record_that_fails_its_check_is_left_behind_never_re_signed() {
    let src_dir = scratch_dir("tampered");
    let mut source = full_library(&src_dir);
    source.data.downloads[0].byte_len += 1; // its signature no longer matches
    let (dst_dir, restored, summary) = round_trip(&source);
    assert!(restored.data.downloads.is_empty());
    assert_eq!(summary.downloads_kept, 0);
    assert_eq!(summary.downloads_dropped, 1);
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dst_dir);
}

#[test]
fn the_version_1_salt_never_travels() {
    let dir = scratch_dir("salt");
    let mut source = new_library(&dir);
    source.data.v1_salt = Some(model::V1Salt([9u8; 16]));
    let json = serde_json::to_string(&source.library_backup()).unwrap();
    assert!(!json.contains("v1_salt"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_restore_only_goes_into_an_empty_library() {
    let src_dir = scratch_dir("nonempty-src");
    let source = full_library(&src_dir);
    let dir = scratch_dir("nonempty");
    let mut busy = new_library(&dir);
    busy.add_bookmark("https://mine.example.test/", "mine").unwrap();
    let validated = validate_backup(source.library_backup()).unwrap();
    assert!(matches!(busy.begin_restore(validated), Err(BackupError::Invalid(_))));
    assert_eq!(busy.data.bookmarks.len(), 1, "untouched");
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

// ---- pictures ---------------------------------------------------------------

/// An empty Library to restore into, in its own directory.
fn fresh(tag: &str) -> (PathBuf, Store) {
    let dir = scratch_dir(tag);
    let store = new_library(&dir);
    (dir, store)
}

#[test]
fn a_picture_no_record_names_or_a_repeated_one_is_refused() {
    let src_dir = scratch_dir("pic-src");
    let source = full_library(&src_dir);
    let (dir, mut to) = fresh("pic");
    let mut restore = to.begin_restore(validate_backup(source.library_backup()).unwrap()).unwrap();
    assert!(matches!(restore.put_picture("aaaa", b"stray"), Err(BackupError::Invalid(_))));
    let id = source.backup_picture_ids()[0].clone();
    restore.put_picture(&id, b"first").unwrap();
    assert!(matches!(restore.put_picture(&id, b"again"), Err(BackupError::Invalid(_))));
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_picture_refuses_the_commit_and_leaves_nothing_behind() {
    let src_dir = scratch_dir("missing-src");
    let source = full_library(&src_dir);
    let (dir, mut to) = fresh("missing");
    let ids = source.backup_picture_ids();
    {
        let mut restore = to.begin_restore(validate_backup(source.library_backup()).unwrap()).unwrap();
        restore.put_picture(&ids[0], b"only one of two").unwrap();
        assert!(matches!(restore.commit(Some(&source)), Err(BackupError::Invalid(_))));
    }
    assert_eq!(to.data, StoreData::default(), "the Library holds nothing");
    assert!(to.blobs().unwrap().ids().unwrap().is_empty(), "the written picture went again");
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_oversized_picture_is_refused_before_it_is_written() {
    let src_dir = scratch_dir("big-src");
    let source = full_library(&src_dir);
    let (dir, mut to) = fresh("big");
    let mut restore = to.begin_restore(validate_backup(source.library_backup()).unwrap()).unwrap();
    let id = source.backup_picture_ids()[0].clone();
    let too_big = vec![0u8; MAX_BACKUP_PICTURE_BYTES as usize + 1];
    assert!(matches!(restore.put_picture(&id, &too_big), Err(BackupError::OverLimit(_))));
    drop(restore);
    assert!(to.blobs().unwrap().ids().unwrap().is_empty());
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_save_at_commit_leaves_nothing_behind() {
    let src_dir = scratch_dir("savefail-src");
    let source = full_library(&src_dir);
    let (dir, mut to) = fresh("savefail");
    to.fail_next_write_for_test(FailPoint::BeforeRename);
    let mut restore = to.begin_restore(validate_backup(source.library_backup()).unwrap()).unwrap();
    for id in source.backup_picture_ids() {
        restore.put_picture(&id, &source.backup_picture(&id).unwrap()).unwrap();
    }
    assert!(matches!(restore.commit(Some(&source)), Err(BackupError::Store(_))));
    assert_eq!(to.data, StoreData::default());
    assert!(to.blobs().unwrap().ids().unwrap().is_empty());
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn picture_bytes_are_what_is_on_disk_not_what_the_backup_claims() {
    let src_dir = scratch_dir("bytes-src");
    let source = full_library(&src_dir);
    let mut backup = source.library_backup();
    backup.archive[0].picture_bytes = 1; // a lie
    backup.archive[1].picture_bytes = 999; // no picture, yet bytes claimed
    let (dir, mut to) = fresh("bytes");
    let mut restore = to.begin_restore(validate_backup(backup).unwrap()).unwrap();
    for id in source.backup_picture_ids() {
        restore.put_picture(&id, &source.backup_picture(&id).unwrap()).unwrap();
    }
    restore.commit(None).unwrap();
    assert_eq!(to.data.archive[0].picture_bytes, source.data.archive[0].picture_bytes);
    assert_eq!(to.data.archive[1].picture_bytes, 0);
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn backup_picture_serves_only_ids_a_record_names() {
    let dir = scratch_dir("serve");
    let store = full_library(&dir);
    store.blobs().unwrap().put("debris", b"not named by anything").unwrap();
    assert!(store.backup_picture("debris").is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_export_leaves_out_a_lost_picture_file_instead_of_refusing_the_library() {
    let dir = scratch_dir("lost-picture");
    let store = full_library(&dir);
    let archived = store.data.archive.iter().find(|r| r.has_picture).unwrap().id.clone();
    fs::remove_file(dir.join("archive").join(&archived)).unwrap();

    let (backup, left_out) = store.library_backup_for_export();
    assert_eq!(left_out, 1);
    let page = backup.archive.iter().find(|r| r.id == archived).unwrap();
    assert!(!page.has_picture && page.picture_bytes == 0);
    // The snapshot's picture is still on disk, so it still travels.
    assert!(backup.page_snapshots.iter().all(|s| s.has_picture));

    // What the export writes restores: no record names a picture it lacks.
    let validated = validate_backup(backup).unwrap();
    assert!(validated.expected_pictures().all(|id| id != archived));
    // The Library itself is unchanged: only the backup's copy is marked.
    assert!(store.get_archive(&archived).unwrap().has_picture);
    let _ = fs::remove_dir_all(&dir);
}

/// R-009: a picture budget is enforced as pictures arrive, before writing,
/// so a crafted backup cannot fill the disk with pictures the restore would
/// refuse at the end.
#[test]
fn a_picture_past_its_budget_is_refused_before_it_is_written() {
    let src_dir = scratch_dir("budget-source");
    let source = full_library(&src_dir);
    let (dir, mut to) = fresh("budget");
    let validated = validate_backup(source.library_backup()).unwrap();
    let mut restore = to.begin_restore(validated).unwrap();
    let page = source.data.archive.iter().find(|r| r.has_picture).unwrap().id.clone();
    restore.archive_bytes = MAX_ARCHIVE_BYTES - 10;
    assert!(matches!(
        restore.put_picture(&page, ARCHIVE_PNG),
        Err(BackupError::OverLimit(_))
    ));
    assert!(!dir.join("archive").join(&page).exists(), "written before it was refused");
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

/// R-004: the Deep Recall budget admits a picture by the size it will have on
/// disk, the size `archive_bytes` sums and a restore re-checks.
#[test]
fn a_deep_recall_picture_is_admitted_by_its_stored_size() {
    let dir = scratch_dir("admit-stored");
    let mut store = new_library(&dir);
    store
        .add_archive("https://a.example.test/", "A", "full page", "", Some(b"pixels"))
        .unwrap();
    // Leave exactly room for 10 bytes of plaintext, not for its encryption.
    store.data.archive[0].picture_bytes = MAX_ARCHIVE_BYTES - 10;
    assert!(
        store
            .add_archive("https://b.example.test/", "B", "full page", "", Some(&[1u8; 10]))
            .is_err(),
        "admitted by plaintext, over the budget once stored"
    );
    store.data.archive[0].picture_bytes = MAX_ARCHIVE_BYTES - blob::BlobStore::stored_len(10);
    assert!(store
        .add_archive("https://b.example.test/", "B", "full page", "", Some(&[1u8; 10]))
        .is_ok());
    assert!(store.archive_bytes() <= MAX_ARCHIVE_BYTES);
    let _ = fs::remove_dir_all(&dir);
}

/// Round 2, R-004: both budgets add up across successive pictures, as stored,
/// and the picture that would cross one is refused before it is written.
#[test]
fn both_picture_budgets_add_up_across_successive_pictures() {
    let src_dir = scratch_dir("accumulate-source");
    let mut source = new_library(&src_dir);
    let page_one = source
        .add_archive("https://one.example.test/", "One", "full page", "", Some(&[1u8; 40]))
        .unwrap();
    let page_two = source
        .add_archive("https://two.example.test/", "Two", "full page", "", Some(&[2u8; 40]))
        .unwrap();
    let mark = source.add_bookmark("https://snap.example.test/", "Snap").unwrap();
    let shot_one = source
        .save_page_snapshot_with_picture(&mark, page_digest("one"), "one", &[3u8; 40], "visible area")
        .unwrap()
        .id;
    let shot_two = source
        .save_page_snapshot_with_picture(&mark, page_digest("two"), "two", &[4u8; 40], "visible area")
        .unwrap()
        .id;

    let (dir, mut to) = fresh("accumulate");
    let mut restore = to
        .begin_restore(validate_backup(source.library_backup()).unwrap())
        .unwrap();
    // Room for one picture of each kind, not two.
    let one = blob::BlobStore::stored_len(40);
    restore.archive_limit = 2 * one - 1;
    restore.snapshot_limit = 2 * one - 1;
    for (first, second) in [(&page_one, &page_two), (&shot_one, &shot_two)] {
        let first_bytes = source.backup_picture(first).unwrap();
        restore.put_picture(first, &first_bytes).unwrap();
        let second_bytes = source.backup_picture(second).unwrap();
        assert!(matches!(
            restore.put_picture(second, &second_bytes),
            Err(BackupError::OverLimit(_))
        ));
        assert!(!dir.join("archive").join(second).exists(), "written before it was refused");
    }
    assert_eq!((restore.archive_bytes, restore.snapshot_bytes), (one, one));
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

/// Round 3, R-003: a picture read with a bound reads no more than the bound,
/// whatever the file on disk holds.
#[test]
fn a_bounded_picture_read_stops_at_its_bound() {
    let dir = scratch_dir("bounded-read");
    let store = new_library(&dir);
    let blobs = store.blobs().unwrap();
    blobs.put("small", &[7u8; 10]).unwrap();
    assert_eq!(&blobs.get_bounded("small", 10).unwrap()[..], &[7u8; 10]);
    assert!(blobs.get_bounded("small", 9).is_err(), "a file over the bound was read");
    let big = vec![0u8; 1 << 20];
    fs::write(dir.join("archive").join("small"), &big).unwrap();
    assert!(blobs.get_bounded("small", 10).is_err());
    let _ = fs::remove_dir_all(&dir);
}

/// Round 4, R-002: the bounded read never asks its source for more than the
/// limit and one byte, whatever the source could give. The source here is
/// endless and refuses (panics) past that budget.
#[test]
fn a_bounded_read_never_asks_for_more_than_its_budget() {
    struct Endless {
        served: u64,
        budget: u64,
    }
    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(self.served + buf.len() as u64 <= self.budget, "asked past the budget");
            buf.fill(0);
            self.served += buf.len() as u64;
            Ok(buf.len())
        }
    }
    let limit = 4096u64;
    let mut source = Endless { served: 0, budget: limit + 1 };
    assert!(blob::read_bounded(&mut source, limit).is_err());
    assert!(source.served <= limit + 1);
}

/// The size every picture limit is judged by is the size the writer stores.
#[test]
fn a_pictures_stored_size_is_known_before_it_is_written() {
    let dir = scratch_dir("stored-len");
    let store = new_library(&dir);
    for len in [0usize, 1, 4096, 100_000] {
        let stored = store.blobs().unwrap().put("sized", &vec![7u8; len]).unwrap();
        assert_eq!(stored, blob::BlobStore::stored_len(len));
    }
    let _ = fs::remove_dir_all(&dir);
}

/// R-007: a restored counter must leave room for the next shelf.
#[test]
fn a_shelf_counter_with_no_room_left_is_refused() {
    let (dir, mut backup) = valid_backup("seq-room");
    backup.next_shelf_seq = u64::MAX;
    assert!(validate_backup(backup.clone()).is_err(), "next_shelf_seq at the top");
    backup.next_shelf_seq = 0;
    if let Some(shelf) = backup.shelves.first_mut() {
        shelf.seq = u64::MAX - 1;
        shelf.id = format!("shelf-{}", shelf.seq);
    }
    assert!(validate_backup(backup).is_err(), "a shelf at the top leaves no next number");
    let _ = fs::remove_dir_all(&dir);
}

/// Round 2, R-002: a restored counter may not sit anywhere near the top, and
/// the store's own allocator refuses rather than wrapping when it is there.
#[test]
fn a_shelf_counter_near_the_top_is_refused_and_never_wraps() {
    let (dir, mut backup) = valid_backup("seq-near-top");
    if let Some(shelf) = backup.shelves.first_mut() {
        shelf.seq = u64::MAX - 2;
        shelf.id = format!("shelf-{}", shelf.seq);
    }
    assert!(validate_backup(backup).is_err(), "a shelf near the top was accepted");
    let (dir2, mut store) = fresh("seq-alloc");
    store.data.next_shelf_seq = u64::MAX;
    let tabs = vec![ShelfTab {
        title: "t".into(),
        url: "https://t.example.test/".into(),
    }];
    assert!(store.add_shelf_grouped("full".into(), tabs.clone(), None).is_err());
    assert_eq!(store.data.next_shelf_seq, u64::MAX);
    // Round 3, R-004: at exactly the boundary a backup may carry, a new shelf
    // is refused, and the Library stays one a backup accepts.
    store.data.next_shelf_seq = MAX_SHELF_SEQ;
    assert!(validate_backup(store.library_backup()).is_ok());
    assert!(store.add_shelf_grouped("full".into(), tabs, None).is_err());
    assert!(validate_backup(store.library_backup()).is_ok());
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&dir2);
}

/// Round 2, R-003: a folder the store holds, whatever writer made it, can be
/// named again to rename, delete or unfile it. Tag editing can make a name
/// longer than 40 characters (a capital that lowercases to two).
#[test]
fn every_folder_the_store_holds_can_be_named_again() {
    let dir = scratch_dir("long-folder");
    let mut store = new_library(&dir);
    let id = store.add_bookmark("https://dotted.example.test/", "Dotted").unwrap();
    store.set_bookmark_tags(&id, vec!["İ".repeat(40)]).unwrap();
    let held = store.get_bookmark(&id).unwrap().tags[0].clone();
    assert!(held.chars().count() > 40);
    let named = existing_folder_name(&held).expect("a held folder can be named");
    assert_eq!(named, held);
    assert!(store.delete_folder(&named).unwrap());
    // Creating or renaming TO a name keeps the strict rule.
    assert!(normalize_folder_name(&held).is_err());
    let _ = fs::remove_dir_all(&dir);
}

/// R-008: whatever the store's own writers let a Library hold, a backup of it
/// accepts.
#[test]
fn a_library_the_stores_writers_made_always_passes() {
    let dir = scratch_dir("writers");
    let mut store = new_library(&dir);
    let id = store.add_bookmark("https://many.example.test/", "Many").unwrap();
    for n in 0..13 {
        store.file_bookmark(&id, &format!("folder {n}")).unwrap();
    }
    let other = store.add_bookmark("https://dotted.example.test/", "Dotted").unwrap();
    store.set_bookmark_tags(&other, vec!["İ".repeat(40)]).unwrap();
    assert!(validate_backup(store.library_backup()).is_ok());
    let _ = fs::remove_dir_all(&dir);
}

// ---- validation: every refusal happens before anything is written ------------

fn valid_backup(tag: &str) -> (PathBuf, LibraryBackup) {
    let dir = scratch_dir(tag);
    let store = full_library(&dir);
    (dir, store.library_backup())
}

fn refused(backup: LibraryBackup) -> BackupError {
    match validate_backup(backup) {
        Ok(_) => panic!("a bad backup was accepted"),
        Err(e) => e,
    }
}

#[test]
fn schema_newer_than_this_build_or_absent_is_refused() {
    let (dir, mut backup) = valid_backup("schema");
    backup.schema = LIBRARY_BACKUP_SCHEMA + 1;
    assert!(matches!(refused(backup.clone()), BackupError::NewerSchema(_)));
    backup.schema = 0;
    assert!(matches!(refused(backup), BackupError::BadSchema));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ids_the_blob_writer_would_refuse_are_refused_up_front() {
    let (dir, backup) = valid_backup("ids");
    for bad in ["", "con", "nul", "com1", "LPT1", "Upper", "has space", "../escape", &"x".repeat(65)] {
        let mut b = backup.clone();
        b.archive[0].id = bad.to_string();
        assert!(matches!(refused(b), BackupError::Invalid(_)), "archive id {bad:?} accepted");
        let mut b = backup.clone();
        b.page_snapshots[0].id = bad.to_string();
        assert!(matches!(refused(b), BackupError::Invalid(_)), "snapshot id {bad:?} accepted");
        let mut b = backup.clone();
        b.bookmarks[1].id = bad.to_string();
        assert!(matches!(refused(b), BackupError::Invalid(_)), "bookmark id {bad:?} accepted");
        assert!(!is_valid_blob_id(bad), "parity with the writer for {bad:?}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn repeated_ids_are_refused_including_across_pages_and_snapshots() {
    let (dir, backup) = valid_backup("dups");
    let mut b = backup.clone();
    b.bookmarks[1].id = b.bookmarks[0].id.clone();
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    b.archive[1].id = b.archive[0].id.clone();
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    // They share one picture directory.
    let mut b = backup.clone();
    b.page_snapshots[0].id = b.archive[0].id.clone();
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_snapshot_must_belong_to_a_bookmark_at_the_same_address() {
    let (dir, backup) = valid_backup("orphan");
    let mut b = backup.clone();
    b.page_snapshots[0].bookmark_id = "nosuchbookmark".into();
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    b.page_snapshots[0].url = "https://elsewhere.example.test/".into();
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn shelves_must_keep_their_numbers_straight() {
    let (dir, backup) = valid_backup("shelves");
    let mut b = backup.clone();
    b.shelves[0].id = "shelf-99".into(); // does not match seq
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    let twin = b.shelves[0].clone();
    b.shelves.push(twin);
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    b.shelves[0].note = "n".repeat(SHELF_NOTE_MAX_CHARS + 1);
    assert!(matches!(refused(b), BackupError::OverLimit(_)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_lower_next_shelf_number_is_raised_so_a_number_is_never_reused() {
    let src_dir = scratch_dir("seq-src");
    let source = full_library(&src_dir);
    let mut backup = source.library_backup();
    backup.next_shelf_seq = 0; // behind the shelf it holds
    let dir = scratch_dir("seq");
    let mut to = new_library(&dir);
    let mut restore = to.begin_restore(validate_backup(backup).unwrap()).unwrap();
    for id in source.backup_picture_ids() {
        restore.put_picture(&id, &source.backup_picture(&id).unwrap()).unwrap();
    }
    restore.commit(None).unwrap();
    let highest = to.data.shelves.iter().map(|s| s.seq).max().unwrap();
    assert!(to.data.next_shelf_seq > highest);
    let next = to.add_shelf("new".into(), vec![]).unwrap();
    assert!(to.data.shelves.iter().filter(|s| s.id == next.id).count() == 1);
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn folder_tag_and_site_names_must_be_in_the_stores_own_form() {
    let (dir, backup) = valid_backup("names");
    let mut b = backup.clone();
    b.bookmark_folders.push("Not Lowercase".into());
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    b.bookmark_folders.push(b.bookmark_folders[0].clone());
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    b.bookmarks[0].tags.push(" Spaced ".into());
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    // More folders than tag editing keeps is fine: filing into folders has
    // no count limit. A capital, or a length no writer can produce, is not.
    let mut b = backup.clone();
    b.bookmarks[0].tags = (0..=BOOKMARK_MAX_TAGS).map(|i| format!("t{i}")).collect();
    assert!(validate_backup(b).is_ok(), "as many folders as filing allows");
    let mut b = backup.clone();
    b.bookmarks[0].tags = vec!["Chem".into()];
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    let mut b = backup.clone();
    b.bookmarks[0].tags = vec!["x".repeat(BOOKMARK_TAG_MAX_CHARS * 3 + 1)];
    assert!(matches!(refused(b), BackupError::Invalid(_)));
    for bad in ["Example.test", "a/b", "a b", ""] {
        let mut b = backup.clone();
        b.divergence_overrides[0].host = bad.into();
        assert!(matches!(refused(b), BackupError::Invalid(_)), "host {bad:?} accepted");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn every_count_and_text_limit_is_refused_never_trimmed() {
    let (dir, backup) = valid_backup("limits");
    let mut b = backup.clone();
    let template = b.bookmarks[1].clone();
    b.bookmarks = (0..=MAX_BOOKMARKS)
        .map(|i| Bookmark { id: format!("b{i}"), ..template.clone() })
        .collect();
    b.page_snapshots.clear();
    assert!(matches!(refused(b), BackupError::OverLimit(_)));

    let mut b = backup.clone();
    let page = b.archive[1].clone();
    b.archive = (0..=MAX_ARCHIVE_RECORDS)
        .map(|i| ArchiveRecord { id: format!("p{i}"), ..page.clone() })
        .collect();
    assert!(matches!(refused(b), BackupError::OverLimit(_)));

    let mut b = backup.clone();
    b.archive[1].text = "x".repeat(ARCHIVE_TEXT_MAX_CHARS + 1);
    assert!(matches!(refused(b), BackupError::OverLimit(_)));

    let mut b = backup.clone();
    b.page_snapshots[0].text = Some("x".repeat(SNAPSHOT_TEXT_MAX_CHARS + 1));
    assert!(matches!(refused(b), BackupError::OverLimit(_)));

    let mut b = backup.clone();
    let snap = b.page_snapshots[0].clone();
    b.page_snapshots = (0..=MAX_SNAPSHOTS_PER_URL)
        .map(|i| PageSnapshot { id: format!("s{i}"), has_picture: false, ..snap.clone() })
        .collect();
    assert!(matches!(refused(b), BackupError::OverLimit(_)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_backup_writes_nothing() {
    let (src, mut backup) = valid_backup("nowrite");
    backup.archive[0].id = "con".into();
    let dir = scratch_dir("nowrite-dst");
    let to = new_library(&dir);
    let before = fs::read(dir.join("store.rbs")).unwrap();
    assert!(validate_backup(backup).is_err());
    assert_eq!(fs::read(dir.join("store.rbs")).unwrap(), before);
    assert!(!dir.join("archive").exists(), "no picture directory was even created");
    drop(to);
    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unknown_top_level_fields_are_refused_not_dropped() {
    let (dir, backup) = valid_backup("unknown");
    let mut value = serde_json::to_value(&backup).unwrap();
    value["a_field_from_the_future"] = serde_json::json!(true);
    assert!(serde_json::from_value::<LibraryBackup>(value).is_err());
    let _ = fs::remove_dir_all(&dir);
}

// ---- new-write caps that keep every Library restorable ----------------------

/// New writes stop at the limit. A backup made by an older PATANYX, which had
/// none, is restored whole: by then its vault has replaced this one, so a
/// refusal would empty the Library. The next export's check then names it.
#[test]
fn a_bookmark_past_the_limit_is_refused_on_new_writes_and_kept_from_older_backups() {
    let dir = scratch_dir("bm-cap");
    let mut store = new_library(&dir);
    let template = Bookmark {
        id: String::new(),
        url: "https://x.example.test/".into(),
        title: "x".into(),
        created_at: 0,
        tags: vec![],
        quick_access: false,
        quick_access_order: None,
        digest: None,
    };
    store.data.bookmarks = (0..MAX_BOOKMARKS)
        .map(|i| Bookmark { id: format!("b{i}"), ..template.clone() })
        .collect();
    assert!(matches!(store.add_bookmark("https://y.example.test/", "y"), Err(StoreError::Full(_))));
    let mut over: Vec<Bookmark> = store.data.bookmarks.clone();
    over.push(Bookmark { id: "one-more".into(), ..template });
    assert_eq!(store.replace_bookmarks(over).unwrap(), MAX_BOOKMARKS + 1, "nothing was cut");
    assert!(matches!(
        validate_backup(store.library_backup()),
        Err(BackupError::OverLimit(_))
    ));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_deep_recall_page_with_too_much_text_is_refused() {
    let dir = scratch_dir("text-cap");
    let mut store = new_library(&dir);
    let long = "x".repeat(ARCHIVE_TEXT_MAX_CHARS + 1);
    assert!(matches!(
        store.add_archive("https://x.example.test/", "x", "full page", &long, None),
        Err(StoreError::Full(_))
    ));
    assert!(store.data.archive.is_empty());
    let exact = "x".repeat(ARCHIVE_TEXT_MAX_CHARS);
    store.add_archive("https://x.example.test/", "x", "full page", &exact, None).unwrap();
    let _ = fs::remove_dir_all(&dir);
}

// ---- the schema pin ------------------------------------------------------------

fn keys_of<T: serde::Serialize>(value: &T) -> Vec<String> {
    let mut keys: Vec<String> = serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// A canary, not a style check. If this fails, a field was added to or
/// removed from something a backup carries: bump LIBRARY_BACKUP_SCHEMA, then
/// update the lists. An older build refuses a newer schema; without the bump
/// it would restore the backup and drop the new field without a word.
#[test]
fn every_carried_types_keys_are_pinned_to_the_schema() {
    let dir = scratch_dir("pin");
    let store = full_library(&dir);
    let backup = store.library_backup();
    assert_eq!(LIBRARY_BACKUP_SCHEMA, 1, "bump the lists below with the schema");
    assert_eq!(
        keys_of(&backup),
        ["archive", "bookmark_folders", "bookmarks", "divergence_overrides", "next_shelf_seq", "page_snapshots", "schema", "shelves"]
    );
    assert_eq!(
        keys_of(&backup.bookmarks[0]),
        ["created_at", "digest", "id", "quick_access", "quick_access_order", "tags", "title", "url"]
    );
    assert_eq!(
        keys_of(&backup.shelves[0]),
        ["created_at", "group", "id", "name", "note", "seq", "tabs"]
    );
    assert_eq!(keys_of(&backup.shelves[0].tabs[0]), ["title", "url"]);
    assert_eq!(keys_of(backup.shelves[0].group.as_ref().unwrap()), ["color", "name"]);
    assert_eq!(
        keys_of(&backup.archive[0]),
        ["created_at", "has_picture", "id", "picture_bytes", "scope", "text", "title", "url"]
    );
    assert_eq!(
        keys_of(&backup.page_snapshots[0]),
        ["bookmark_id", "digest", "has_picture", "id", "picture_bytes", "picture_scope", "recorded_at", "text", "text_trimmed", "url"]
    );
    assert_eq!(keys_of(&backup.divergence_overrides[0]), ["host", "level"]);
    let recorded = store.data.bookmarks.iter().find_map(|b| b.digest.as_ref()).unwrap();
    assert_eq!(keys_of(recorded), ["digest", "recorded_at"]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_backup_never_prints_its_contents() {
    let (dir, backup) = valid_backup("debug");
    let printed = format!("{backup:?}");
    assert!(!printed.contains("example.test"));
    assert!(!printed.contains("pack the charger"));
    let _ = fs::remove_dir_all(&dir);
}

// ---- what a backup worker takes from a Library (BackupPictures, KeptDownloads)

#[test]
fn backup_pictures_serve_named_ids_only_and_outlive_the_store() {
    let dir = scratch_dir("pictures-taken");
    let store = full_library(&dir);
    store.blobs().unwrap().put("debris", b"not named by anything").unwrap();
    let ids = store.backup_picture_ids();
    assert_eq!(ids.len(), 2, "one Deep Recall picture and one snapshot picture");
    let expected: Vec<_> = ids.iter().map(|id| store.backup_picture(id).unwrap()).collect();
    let pictures = store.backup_pictures().unwrap();
    drop(store);
    for (id, want) in ids.iter().zip(&expected) {
        assert_eq!(&pictures.read(id).unwrap()[..], &want[..], "{id} differs once the Store is gone");
    }
    assert!(pictures.read("debris").is_err(), "an unnamed file was served");
    assert!(!format!("{pictures:?}").contains(&ids[0]), "the ids are not printed");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_picture_deleted_after_it_was_taken_is_not_found() {
    let dir = scratch_dir("pictures-deleted");
    let mut store = full_library(&dir);
    let pictures = store.backup_pictures().unwrap();
    let id = store.archive().iter().find(|r| r.has_picture).unwrap().id.clone();
    store.delete_archive(&id).unwrap();
    assert!(pictures.read(&id).is_err(), "a deleted picture was still served");
    let _ = fs::remove_dir_all(&dir);
}

/// The records an import keeps are those of the moment they were taken:
/// one recorded later is not in them (the app parks and replays those).
#[test]
fn kept_downloads_are_a_snapshot_and_commit_keeping_matches_commit() {
    let src_dir = scratch_dir("kept-snapshot");
    let mut source = full_library(&src_dir);
    let kept = source.kept_downloads();
    assert_eq!((kept.len(), kept.dropped()), (1, 0));
    source
        .record_download("https://later.example.test/f.zip", "later.zip", 9, [3u8; 32])
        .unwrap();

    let dir = scratch_dir("kept-restored");
    let mut to = new_library(&dir);
    let validated = validate_backup(source.library_backup()).unwrap();
    let mut restore = to.begin_restore(validated).unwrap();
    for id in source.backup_picture_ids() {
        restore.put_picture(&id, &source.backup_picture(&id).unwrap()).unwrap();
    }
    let summary = restore.commit_keeping(Some(&kept)).unwrap();
    assert_eq!((summary.downloads_kept, summary.downloads_dropped), (1, 0));
    assert_eq!(to.data.downloads.len(), 1);
    assert_eq!(to.data.downloads[0].filename, "private-history.zip");
    let id = to.data.downloads[0].id.clone();
    assert!(to.verify_download(&id).unwrap(), "re-signed under the new key");
    let printed = format!("{kept:?}");
    assert!(!printed.contains("private-history") && !printed.contains(DOWNLOAD_URL), "{printed}");
    let _ = fs::remove_dir_all(&src_dir);
    let _ = fs::remove_dir_all(&dir);
}
