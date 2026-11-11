//! Renewing the data key of a Library that moved from version 1 (secscan
//! S-1a563619ce84, `rekey.rs`). Throwaway directories, cheap Argon2id
//! parameters, and a random key standing in for `Vault::library_key`.

use super::*;
use crate::rekey::{crash, journal_path, recover_rekey};

const OLD: &str = "old passphrase";
const BUILD: &str = "1.1.0-test";
const ADDON: &str = "notes-addon";
const ARCHIVE_PNG: &[u8] = b"\x89PNG\r\n\x1a\n archived pixels";
const SNAPSHOT_PNG: &[u8] = b"\x89PNG\r\n\x1a\n snapshot pixels";

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("patanyx-rekey-{tag}-{}", random_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn vault_key() -> Zeroizing<[u8; crypto::KEY_LEN]> {
    Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>())
}

struct Filled {
    bookmark: String,
    archive: String,
    snapshot: String,
    download: String,
    page: String,
}

/// A version 1 Library holding everything whose key matters, moved into the
/// vault the way a passphrase change moves it.
fn moved_library(dir: &Path, key: &[u8; crypto::KEY_LEN]) -> (PathBuf, Filled) {
    let path = dir.join("store.rbs");
    let mut store = Store::create_with_params(&path, OLD, 8192, 1, 1).unwrap();
    let bookmark = store.add_bookmark("https://kept.example/", "Kept").unwrap();
    let archive = store
        .add_archive("https://archived.example/", "Archived", "full page", "archived words", Some(ARCHIVE_PNG))
        .unwrap();
    let digest = patanyx_integrity::digest(b"<p>snapshot words</p>").unwrap();
    let snapshot = store
        .save_page_snapshot_with_picture(&bookmark, digest, "snapshot words", SNAPSHOT_PNG, "visible")
        .unwrap()
        .id;
    let download = store.record_download("https://files.example/a.bin", "a.bin", 4, [7u8; 32]).unwrap();
    let page = store
        .addon_namespace(ADDON)
        .unwrap()
        .put(None, 0, "A page", b"page body text", 1)
        .unwrap()
        .id;
    store.move_into_vault(key).unwrap();
    assert!(store.needs_rekey());
    (path, Filled { bookmark, archive, snapshot, download, page })
}

fn assert_everything_reads(store: &Store, f: &Filled) {
    assert!(store.get_bookmark(&f.bookmark).is_some());
    assert_eq!(&store.archive_picture(&f.archive).unwrap()[..], ARCHIVE_PNG);
    assert_eq!(&store.page_snapshot_picture(&f.snapshot).unwrap()[..], SNAPSHOT_PNG);
    assert!(store.verify_download(&f.download).unwrap(), "a download seal no longer verifies");
    let (_, body) = store.addon_namespace(ADDON).unwrap().get(&f.page).unwrap();
    assert_eq!(&body[..], b"page body text");
}

/// Every regular file under `dir`, recursively, sorted.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn no_debris(dir: &Path) {
    let names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("rekey"))
        .collect();
    assert!(names.is_empty(), "re-key leftovers remain: {names:?}");
}

/// THE FINDING: after a re-key, the old key (what the old passphrase and the
/// version 1 salt derive) opens nothing that is current -- not the Library
/// file, not a picture, not an add-on file, and no download seal verifies
/// under it -- while everything still reads under the new key.
#[test]
fn after_a_rekey_the_old_key_opens_nothing_and_everything_still_reads() {
    let dir = scratch("old-key");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    let old_key = Zeroizing::new(*store.key);
    let report = store.rekey(&key, BUILD).unwrap();
    assert_eq!((report.pictures, report.pictures_left_out), (2, 0), "{report:?}");
    assert!(report.addon_files >= 2, "{report:?}");
    assert!(!store.needs_rekey());
    assert_everything_reads(&store, &filled);
    drop(store);

    let store = Store::open(&path, None, &key).unwrap();
    assert_everything_reads(&store, &filled);
    assert!(store.data.rekeyed && store.data.v1_salt.is_some(), "the flag is set and the salt is kept");
    assert_ne!(*store.key, *old_key);

    let bytes = fs::read(&path).unwrap();
    let header = format::decode_header_v3(&bytes).unwrap();
    assert!(crypto::decrypt(&old_key, &header.nonce, &bytes[..format::HEADER_LEN_V3], &bytes[format::HEADER_LEN_V3..]).is_err());
    let old_pictures = blob::BlobStore::open(&dir.join("archive"), &old_key).unwrap();
    let ids = old_pictures.ids().unwrap();
    assert_eq!(ids.len(), 2);
    for id in ids {
        assert!(old_pictures.get(&id).is_err(), "picture {id} still opens under the old key");
    }
    let old_addon =
        blob::BlobStore::open(&dir.join("addons").join(ADDON), &addon::namespace_key(&old_key, ADDON)).unwrap();
    let ids = old_addon.ids().unwrap();
    assert!(ids.len() >= 2);
    for id in ids {
        assert!(old_addon.get(&id).is_err(), "add-on file {id} still opens under the old key");
    }
    let old_seal = provenance::mac_key(&old_key);
    assert!(store.data.downloads.iter().all(|r| !provenance::verify(&old_seal, r)));
    no_debris(&dir);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn only_a_library_that_moved_from_version_1_needs_a_rekey_and_only_once() {
    let dir = scratch("needs");
    let key = vault_key();
    let fresh = Store::create_in_vault(&dir.join("fresh.rbs"), &key).unwrap();
    assert!(!fresh.needs_rekey(), "a Library made in the vault has a random key already");
    let v1 = Store::create_with_params(&dir.join("v1.rbs"), OLD, 8192, 1, 1).unwrap();
    assert!(!v1.needs_rekey(), "a version 1 Library's key comes from the CURRENT passphrase");

    let (path, _) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    store.rekey(&key, BUILD).unwrap();
    let key_after = *store.key;
    assert!(!store.needs_rekey());
    assert_eq!(store.rekey(&key, BUILD).unwrap(), RekeyReport::default());
    drop(store);
    let store = Store::open(&path, None, &key).unwrap();
    assert!(!store.needs_rekey());
    assert_eq!(*store.key, key_after);
    fs::remove_dir_all(&dir).ok();
}

fn flip_last_byte(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(path, &bytes).unwrap();
}

/// A damaged picture is left out (never copied as old ciphertext), a damaged
/// add-on index stays unreadable so the add-on's recovery deletes nothing,
/// and a tampered download record still fails.
#[test]
fn damaged_data_is_left_out_or_stays_unreadable() {
    let dir = scratch("damaged");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    let picture_file = dir.join("archive").join(&filled.archive);
    flip_last_byte(&picture_file);
    flip_last_byte(&dir.join("addons").join(ADDON).join("index"));
    let mut store = Store::open(&path, None, &key).unwrap();
    store.data.downloads[0].hmac[0] ^= 0xff;
    store.save().unwrap();

    let report = store.rekey(&key, BUILD).unwrap();
    assert_eq!(report.pictures_left_out, 1, "{report:?}");
    assert!(report.addon_files_left_out >= 1, "{report:?}");
    assert!(!picture_file.exists(), "a damaged picture was carried");
    assert!(store.archive_picture(&filled.archive).is_err(), "it reads as missing, as before");
    assert_eq!(&store.page_snapshot_picture(&filled.snapshot).unwrap()[..], SNAPSHOT_PNG);
    let namespace = store.addon_namespace(ADDON).unwrap();
    assert!(namespace.list().is_err(), "the damaged index must still read as unreadable");
    assert!(namespace.recover().is_err(), "recovery against an unreadable index removes nothing");
    assert!(!store.verify_download(&filled.download).unwrap(), "a tampered record must still fail");
    fs::remove_dir_all(&dir).ok();
}

/// Entries this build does not recognise are carried byte for byte.
#[test]
fn unknown_entries_are_carried_byte_for_byte() {
    let dir = scratch("unknown");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    fs::create_dir_all(dir.join("addons").join("Not An Id")).unwrap();
    fs::write(dir.join("addons").join("Not An Id").join("data"), b"someone else's").unwrap();
    fs::write(dir.join("archive").join("README.TXT"), b"kept as is").unwrap();
    fs::write(dir.join("addons").join(ADDON).join("Extra.Bin"), b"also kept").unwrap();
    // A name that is safe as a blob id but is not one the add-on store
    // writes is someone's data, not a damaged page (review R-001).
    fs::write(dir.join("addons").join(ADDON).join("metadata"), b"plain text, kept").unwrap();
    fs::write(dir.join("addons").join(ADDON).join("p-notapage"), b"kept too").unwrap();
    // A page version's exact name that does not open IS damage: left out.
    let damaged_page = format!("p-{}-9", "ab".repeat(16));
    fs::write(dir.join("addons").join(ADDON).join(&damaged_page), b"not a blob").unwrap();
    let mut store = Store::open(&path, None, &key).unwrap();
    let report = store.rekey(&key, BUILD).unwrap();
    assert_eq!(report.carried_as_is, 5, "{report:?}");
    assert_eq!(report.addon_files_left_out, 1, "{report:?}");
    assert_eq!(fs::read(dir.join("addons").join("Not An Id").join("data")).unwrap(), b"someone else's");
    assert_eq!(fs::read(dir.join("archive").join("README.TXT")).unwrap(), b"kept as is");
    assert_eq!(fs::read(dir.join("addons").join(ADDON).join("Extra.Bin")).unwrap(), b"also kept");
    assert_eq!(fs::read(dir.join("addons").join(ADDON).join("metadata")).unwrap(), b"plain text, kept");
    assert_eq!(fs::read(dir.join("addons").join(ADDON).join("p-notapage")).unwrap(), b"kept too");
    assert!(!dir.join("addons").join(ADDON).join(&damaged_page).exists(), "a damaged page was carried");
    fs::remove_dir_all(&dir).ok();
}

/// Only the add-on store's own names count as its files.
#[test]
fn the_add_on_store_names_are_exact() {
    let page = "0123456789abcdef0123456789abcdef";
    assert!(addon::is_namespace_file("index"));
    assert!(addon::is_namespace_file(&format!("p-{page}-1")));
    assert!(addon::is_namespace_file(&format!("p-{page}-{}", 1u64 << 53)));
    for name in [
        "metadata".to_string(),
        format!("p-{page}-0"),
        format!("p-{page}-01"),
        format!("p-{page}-{}", (1u64 << 53) + 1),
        format!("p-{page}-18446744073709551616"),
        "indexes".to_string(),
        format!("p-{page}"),
        format!("p-{page}-"),
        format!("p-{page}-1a"),
        format!("p-{}-1", &page[..31]),
        format!("p-{}-1", page.to_uppercase()),
        format!("p-{page}-1-2"),
    ] {
        assert!(!addon::is_namespace_file(&name), "{name} taken for the add-on store's");
    }
}

/// A finished re-key's folders are swept at every unlock even with no mark
/// (an import replaces the Library and drops it, review F-002), and never
/// while a journal is present.
#[test]
fn rekey_folders_are_swept_without_a_mark_but_never_with_a_journal() {
    let dir = scratch("unmarked-sweep");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    store.rekey(&key, BUILD).unwrap();
    assert_eq!(store.data.k1_leftovers, None);
    let aside = dir.join("archive.prerekey-0123456789abcdef");
    let other = dir.join("archive.old-0123456789abcdef");
    fs::create_dir(&aside).unwrap();
    fs::create_dir(&other).unwrap();
    fs::write(journal_path(&path), b"{}").unwrap();
    store.retire_old_key_leftovers(&key).unwrap();
    assert!(aside.exists(), "removed while a journal was present");
    fs::remove_file(journal_path(&path)).unwrap();
    store.retire_old_key_leftovers(&key).unwrap();
    assert!(!aside.exists());
    assert!(other.exists(), "an import's own folder is not the re-key's to remove");
    fs::remove_dir_all(&dir).ok();
}

/// A read that fails for any reason but damage stops the re-key with every
/// file untouched and the Library usable under its old key.
#[test]
fn an_io_error_stops_the_rekey_and_changes_nothing() {
    let dir = scratch("io");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    let old_key = *store.key;
    let before: Vec<(PathBuf, Vec<u8>)> = files_under(&dir)
        .into_iter()
        .filter(|p| !p.ends_with("store.rbs") && !p.ends_with("store.rbs.lock"))
        .map(|p| {
            let b = fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    crash::fail_read_of("index");
    let outcome = store.rekey(&key, BUILD);
    crash::clear();
    assert!(matches!(outcome, Err(RekeyError::Undone(_))), "{outcome:?}");
    assert_eq!(*store.key, old_key);
    assert!(store.needs_rekey(), "it is tried again at the next unlock");
    assert_eq!(store.data.rekey_try, None, "an attempt that ended cleanly is not counted");
    assert_everything_reads(&store, &filled);
    for (path, bytes) in before {
        assert_eq!(fs::read(&path).unwrap(), bytes, "{} changed", path.display());
    }
    no_debris(&dir);
    assert!(!journal_path(&path).exists());
    store.rekey(&key, BUILD).unwrap();
    assert_everything_reads(&store, &filled);
    fs::remove_dir_all(&dir).ok();
}

/// A rename that fails during the swap puts everything back.
#[test]
fn a_rename_that_fails_during_the_swap_puts_everything_back() {
    for which in ["archive", "addons", "store.rbs"] {
        let dir = scratch("rename");
        let key = vault_key();
        let (path, filled) = moved_library(&dir, &key);
        let mut store = Store::open(&path, None, &key).unwrap();
        let old_key = *store.key;
        crash::fail_rename_of(&format!("{}{which}", std::path::MAIN_SEPARATOR));
        let outcome = store.rekey(&key, BUILD);
        crash::clear();
        assert!(matches!(outcome, Err(RekeyError::Undone(_))), "{which}: {outcome:?}");
        drop(store);
        let store = Store::open(&path, None, &key).unwrap();
        assert_eq!(*store.key, old_key, "{which}");
        assert_everything_reads(&store, &filled);
        no_debris(&dir);
        fs::remove_dir_all(&dir).ok();
    }
}

/// A crash at every step of the re-key, then recovery at the next unlock:
/// the Library is wholly under the old key or wholly under the new one, with
/// nothing left behind, and a re-key afterwards completes.
#[test]
fn a_crash_at_any_step_recovers_to_one_whole_library() {
    let points = [
        (crash::AFTER_BUILD, 0),
        (crash::FOLDER_ASIDE, 0),
        (crash::FOLDER_IN, 0),
        (crash::FOLDER_ASIDE, 1),
        (crash::FOLDER_IN, 1),
        (crash::AFTER_COMMIT, 0),
    ];
    for (point, pass) in points {
        let dir = scratch("crash");
        let key = vault_key();
        let (path, filled) = moved_library(&dir, &key);
        let mut store = Store::open(&path, None, &key).unwrap();
        let old_key = *store.key;
        crash::crash_at(point, pass);
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.rekey(&key, BUILD)));
        crash::clear();
        assert!(crashed.is_err(), "point {point}/{pass} did not crash");
        drop(store);

        assert!(journal_path(&path).exists(), "point {point}/{pass}: no journal left by the crash");
        recover_rekey(&path, &key).unwrap();
        assert!(!journal_path(&path).exists());
        no_debris(&dir);
        let mut store = Store::open(&path, None, &key).unwrap();
        assert_everything_reads(&store, &filled);
        if point == crash::AFTER_COMMIT {
            assert_ne!(*store.key, old_key, "committed: the new key");
            assert!(!store.needs_rekey());
        } else {
            assert_eq!(*store.key, old_key, "point {point}/{pass}: not committed, the old key");
            assert!(store.needs_rekey());
            assert_eq!(store.data.rekey_try.as_ref().map(|t| t.started), Some(1), "the crash counts");
            store.rekey(&key, BUILD).unwrap();
            assert_everything_reads(&store, &filled);
        }
        fs::remove_dir_all(&dir).ok();
    }
}

/// A recovery that fails part way (here a rename) is finished at the next try.
#[test]
fn a_recovery_that_fails_part_way_is_finished_at_the_next_try() {
    let dir = scratch("crash-twice");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    crash::crash_at(crash::FOLDER_IN, 1);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.rekey(&key, BUILD)));
    crash::clear();
    drop(store);
    crash::fail_rename_of(&format!("{}addons", std::path::MAIN_SEPARATOR));
    assert!(recover_rekey(&path, &key).is_err());
    crash::clear();
    recover_rekey(&path, &key).unwrap();
    no_debris(&dir);
    assert_everything_reads(&Store::open(&path, None, &key).unwrap(), &filled);
    fs::remove_dir_all(&dir).ok();
}

/// After a crash, an import may replace the Library before the next unlock:
/// recovery then removes only what the re-key made and touches nothing live.
#[test]
fn a_library_replaced_after_a_crash_is_left_alone() {
    let dir = scratch("replaced");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    crash::crash_at(crash::FOLDER_IN, 0);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.rekey(&key, BUILD)));
    crash::clear();
    drop(store);
    fs::remove_file(&path).unwrap();
    let mut replaced = Store::create_in_vault(&path, &key).unwrap();
    let kept = replaced.add_bookmark("https://imported.example/", "Imported").unwrap();
    drop(replaced);
    let live_archive = files_under(&dir.join("archive"));
    recover_rekey(&path, &key).unwrap();
    no_debris(&dir);
    let store = Store::open(&path, None, &key).unwrap();
    assert!(store.get_bookmark(&kept).is_some());
    assert_eq!(files_under(&dir.join("archive")), live_archive, "the live archive was touched");
    fs::remove_dir_all(&dir).ok();
}

/// A journal this module did not write keeps the Library shut.
#[test]
fn an_untrustworthy_journal_keeps_the_library_shut() {
    let dir = scratch("journal");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let bad_names = br#"{"phase":"swapping","staging":"../x","old_archive":"archive.prerekey-0000000000000000","old_addons":"addons.prerekey-0000000000000000","old_check":"","new_check":""}"#;
    for body in [&b"not json"[..], &bad_names[..]] {
        fs::write(journal_path(&path), body).unwrap();
        assert!(recover_rekey(&path, &key).is_err());
    }
    fs::remove_file(journal_path(&path)).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&path, journal_path(&path)).unwrap();
        assert!(recover_rekey(&path, &key).is_err(), "a linked journal is not followed");
        fs::remove_file(journal_path(&path)).unwrap();
    }
    fs::remove_dir_all(&dir).ok();
}

/// The writer's crash leftovers made under the old key are removed; one
/// under another key is kept.
#[test]
fn version_3_leftovers_under_the_old_key_are_retired() {
    let dir = scratch("leftovers");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let ours = dir.join(".tmp-0123456789abcdef0123456789abcdef");
    fs::copy(&path, &ours).unwrap();
    let other_dir = scratch("leftovers-other");
    drop(Store::create_in_vault(&other_dir.join("store.rbs"), &key).unwrap());
    let theirs = dir.join(".tmp-fedcba9876543210fedcba9876543210");
    fs::copy(other_dir.join("store.rbs"), &theirs).unwrap();

    let mut store = Store::open(&path, None, &key).unwrap();
    let report = store.rekey(&key, BUILD).unwrap();
    assert!(!report.leftovers_retained, "{report:?}");
    assert!(!ours.exists(), "a copy under the old key survived the re-key");
    assert!(theirs.exists(), "a copy under another key was removed");
    assert_eq!(store.data.k1_leftovers, None, "nothing pending once retired");
    fs::remove_dir_all(&dir).ok();
    fs::remove_dir_all(&other_dir).ok();
}

/// A build stops trying after attempts that never finished; another build
/// starts again.
#[test]
fn unfinished_attempts_pause_this_build_but_not_the_next() {
    let dir = scratch("paused");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    store.data.rekey_try = Some(model::RekeyTry { build: BUILD.into(), started: MAX_UNFINISHED_ATTEMPTS });
    store.save().unwrap();
    assert!(matches!(store.rekey(&key, BUILD), Err(RekeyError::Paused)));
    assert!(store.needs_rekey());
    store.rekey(&key, "1.1.1-test").unwrap();
    assert!(!store.needs_rekey());
    fs::remove_dir_all(&dir).ok();
}

/// A linked `archive` is refused, and the re-keyed folders are owner-only.
#[cfg(unix)]
#[test]
fn a_linked_archive_is_refused_and_new_folders_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("unix");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let elsewhere = scratch("unix-elsewhere");
    fs::rename(dir.join("archive"), elsewhere.join("archive")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("archive"), dir.join("archive")).unwrap();
    let mut store = Store::open(&path, None, &key).unwrap();
    assert!(matches!(store.rekey(&key, BUILD), Err(RekeyError::Undone(_))));
    fs::remove_file(dir.join("archive")).unwrap();
    fs::rename(elsewhere.join("archive"), dir.join("archive")).unwrap();
    store.rekey(&key, BUILD).unwrap();
    for folder in ["archive", "addons"] {
        let mode = fs::metadata(dir.join(folder)).unwrap().permissions().mode() & 0o077;
        assert_eq!(mode, 0, "{folder} is readable by others");
    }
    fs::remove_dir_all(&dir).ok();
    fs::remove_dir_all(&elsewhere).ok();
}

/// How long a re-key takes on a Library at its size limits (pictures near the
/// archive cap, one add-on with many pages). Run by hand, in release:
/// `cargo test --release -p patanyx-store rekey_timing -- --ignored --nocapture`.
#[test]
#[ignore]
fn rekey_timing_on_a_full_library() {
    let dir = scratch("timing");
    let key = vault_key();
    let path = dir.join("store.rbs");
    let mut store = Store::create_with_params(&path, OLD, 8192, 1, 1).unwrap();
    let picture: Vec<u8> = (0..1_200_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let mut pictures = 0;
    while store.add_archive("https://a.example/", "t", "full page", "x", Some(&picture)).is_ok() {
        pictures += 1;
        if pictures >= 200 {
            break;
        }
    }
    let namespace = store.addon_namespace(ADDON).unwrap();
    let body = vec![b'a'; 500_000];
    for i in 0..400u64 {
        namespace.put(None, 0, "page", &body, i).unwrap();
    }
    store.move_into_vault(&key).unwrap();
    let bytes: u64 = files_under(&dir).iter().map(|p| fs::metadata(p).unwrap().len()).sum();
    let started = std::time::Instant::now();
    let report = store.rekey(&key, BUILD).unwrap();
    let took = started.elapsed();
    println!(
        "REKEY TIMING: {} MB on disk, {} pictures, {} add-on files, took {:.2} s",
        bytes / 1_000_000,
        report.pictures,
        report.addon_files,
        took.as_secs_f64()
    );
    fs::remove_dir_all(&dir).ok();
}

/// Old folders the post-commit cleanup could not remove (a scanner holding a
/// file) are not ignored: they are old-key leftovers, and retirement, which
/// runs right after and at every unlock while the mark is set, removes them.
#[test]
fn old_folders_that_will_not_go_are_retired_by_the_leftover_sweep() {
    let dir = scratch("cleanup");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    crash::fail_cleanup_once();
    let report = store.rekey(&key, BUILD).unwrap();
    crash::clear();
    assert!(!journal_path(&path).exists(), "the commit is done; no recovery is needed");
    assert!(!report.leftovers_retained, "the sweep removed them: {report:?}");
    assert!(store.data.k1_leftovers.is_none());
    no_debris(&dir);
    assert_everything_reads(&store, &filled);

    // And the sweep itself: folders left by a finished re-key, with no
    // journal, are removed; with a journal present it touches nothing.
    fs::create_dir(dir.join("archive.prerekey-0123456789abcdef")).unwrap();
    store.data.k1_leftovers = Some("0".repeat(64));
    fs::write(journal_path(&path), b"{}").unwrap();
    assert!(store.retire_old_key_leftovers(&key).is_err());
    assert!(dir.join("archive.prerekey-0123456789abcdef").exists(), "removed while a journal was present");
    fs::remove_file(journal_path(&path)).unwrap();
    store.retire_old_key_leftovers(&key).unwrap();
    assert!(!dir.join("archive.prerekey-0123456789abcdef").exists());
    fs::remove_dir_all(&dir).ok();
}

/// Only the writer's exact temporary name is left behind; another name that
/// merely starts the same way is someone's data, carried as is.
#[test]
fn only_exact_writer_temp_names_are_left_behind() {
    let dir = scratch("tempnames");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    fs::write(dir.join("archive").join(".tmp-user-data"), b"keep me").unwrap();
    fs::write(dir.join("archive").join(".tmp-0123456789abcdef0123456789abcdef"), b"junk").unwrap();
    let mut store = Store::open(&path, None, &key).unwrap();
    store.rekey(&key, BUILD).unwrap();
    assert_eq!(fs::read(dir.join("archive").join(".tmp-user-data")).unwrap(), b"keep me");
    assert!(!dir.join("archive").join(".tmp-0123456789abcdef0123456789abcdef").exists());
    fs::remove_dir_all(&dir).ok();
}

/// A link inside the Library's folders cannot be carried as it is, and is
/// never dropped silently: the re-key refuses and nothing changes.
#[cfg(unix)]
#[test]
fn a_link_inside_the_library_refuses_the_rekey() {
    let dir = scratch("inner-link");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    std::os::unix::fs::symlink("/etc/hostname", dir.join("addons").join(ADDON).join("linked")).unwrap();
    let mut store = Store::open(&path, None, &key).unwrap();
    let old_key = *store.key;
    assert!(matches!(store.rekey(&key, BUILD), Err(RekeyError::Undone(_))));
    assert_eq!(*store.key, old_key);
    assert_everything_reads(&store, &filled);
    no_debris(&dir);
    fs::remove_dir_all(&dir).ok();
}

/// A folder or a link that merely has the writer's temporary name is not an
/// interrupted write: a folder is carried, a link refuses the re-key.
#[test]
fn temp_named_folders_are_carried_and_temp_named_links_refuse() {
    let dir = scratch("temp-kinds");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let temp_name = ".tmp-00112233445566778899aabbccddeeff";
    fs::create_dir(dir.join("archive").join(temp_name)).unwrap();
    fs::write(dir.join("archive").join(temp_name).join("inside"), b"data").unwrap();
    let mut store = Store::open(&path, None, &key).unwrap();
    store.rekey(&key, BUILD).unwrap();
    assert_eq!(fs::read(dir.join("archive").join(temp_name).join("inside")).unwrap(), b"data");
    fs::remove_dir_all(&dir).ok();

    #[cfg(unix)]
    {
        let dir = scratch("temp-link");
        let (path, _) = moved_library(&dir, &key);
        std::os::unix::fs::symlink("/etc/hostname", dir.join("archive").join(temp_name)).unwrap();
        let mut store = Store::open(&path, None, &key).unwrap();
        assert!(matches!(store.rekey(&key, BUILD), Err(RekeyError::Undone(_))));
        assert!(store.needs_rekey());
        fs::remove_dir_all(&dir).ok();
    }
}

/// The leftover sweep removes only folders with exactly this module's names.
#[test]
fn the_leftover_sweep_touches_only_its_own_exact_names() {
    let dir = scratch("sweep-names");
    let key = vault_key();
    let (path, _) = moved_library(&dir, &key);
    let mut store = Store::open(&path, None, &key).unwrap();
    store.rekey(&key, BUILD).unwrap();
    let ours = dir.join("library-rekey-0123456789abcdef");
    let not_hex = dir.join("archive.prerekey-NOT-HEX-AT-ALL!");
    let a_file = dir.join("addons.prerekey-0123456789abcdef");
    fs::create_dir(&ours).unwrap();
    fs::create_dir(&not_hex).unwrap();
    fs::write(&a_file, b"a file, not ours").unwrap();
    store.data.k1_leftovers = Some("0".repeat(64));
    store.retire_old_key_leftovers(&key).unwrap();
    assert!(!ours.exists());
    assert!(not_hex.exists(), "a name that is not exactly ours was removed");
    assert!(a_file.exists(), "a file was removed");
    fs::remove_dir_all(&dir).ok();
}

/// A picture or add-on file in a blob format a newer build writes is not
/// damage: the re-key refuses and nothing is lost or changed.
#[test]
fn a_blob_from_a_newer_build_refuses_the_rekey() {
    let dir = scratch("newer-blob");
    let key = vault_key();
    let (path, filled) = moved_library(&dir, &key);
    let picture = dir.join("archive").join(&filled.archive);
    let mut bytes = fs::read(&picture).unwrap();
    bytes[8] = 0xEE; // the version byte follows the 8-byte blob magic
    assert!(crate::blob::is_other_version(&picture).is_ok());
    fs::write(&picture, &bytes).unwrap();
    let mut store = Store::open(&path, None, &key).unwrap();
    let old_key = *store.key;
    assert!(matches!(store.rekey(&key, BUILD), Err(RekeyError::Undone(_))));
    assert_eq!(*store.key, old_key);
    assert_eq!(fs::read(&picture).unwrap(), bytes, "the newer build's file changed");
    no_debris(&dir);
    fs::remove_dir_all(&dir).ok();
}
