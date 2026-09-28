//! The Library opening with the vault (format version 3, 2026-09-27).
//!
//! Every test runs on a throwaway directory with cheap Argon2id parameters,
//! and a random 32-byte key stands in for `Vault::library_key` (the store does
//! not depend on the vault; the app's tests use a real one). The properties
//! pinned here: a new Library is version 3 and opens only with its vault's
//! key; a version 1 Library stays version 1 until it moves; the move keeps the
//! data key, so pictures and download MACs still verify; after it, nothing in
//! the Library file opens with the old passphrase; a failed move leaves file
//! and memory as they were; and the version 3 header is fully authenticated
//! and bounded.

use super::*;

const OLD: &str = "old passphrase";
const FAST_M: u32 = 8192;

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("patanyx-library-key-{tag}-{}", random_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn vault_key() -> Zeroizing<[u8; crypto::KEY_LEN]> {
    Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>())
}

/// A Library from before version 3.
fn v1_library(path: &Path) -> Store {
    Store::create_with_params(path, OLD, FAST_M, 1, 1).unwrap()
}

fn page_digest(words: &str) -> ContentDigest {
    patanyx_integrity::digest(format!("<p>{words}</p>").as_bytes()).unwrap()
}

const ARCHIVE_PNG: &[u8] = b"\x89PNG\r\n\x1a\n archived pixels";
const SNAPSHOT_PNG: &[u8] = b"\x89PNG\r\n\x1a\n snapshot pixels";

/// What a real Library holds whose key matters beyond the file: an archived
/// page's picture and a snapshot's picture (both encrypted under a key
/// derived from the data key), and a download record (MACed under another).
struct Contents {
    bookmark: String,
    archive: String,
    snapshot: String,
    download: String,
}

fn fill(store: &mut Store) -> Contents {
    let bookmark = store.add_bookmark("https://kept.example/", "Kept").unwrap();
    let archive = store
        .add_archive(
            "https://archived.example/",
            "Archived",
            "full page",
            "archived words",
            Some(ARCHIVE_PNG),
        )
        .unwrap();
    let snapshot = store
        .save_page_snapshot_with_picture(
            &bookmark,
            page_digest("snapshot words"),
            "snapshot words",
            SNAPSHOT_PNG,
            "visible",
        )
        .unwrap()
        .id;
    let download = store
        .record_download("https://files.example/a.bin", "a.bin", 4, [7u8; 32])
        .unwrap();
    Contents {
        bookmark,
        archive,
        snapshot,
        download,
    }
}

fn assert_contents(store: &Store, contents: &Contents) {
    assert!(store.get_bookmark(&contents.bookmark).is_some());
    assert_eq!(
        &store.archive_picture(&contents.archive).unwrap()[..],
        ARCHIVE_PNG,
        "an archived picture no longer decrypts"
    );
    assert_eq!(
        &store.page_snapshot_picture(&contents.snapshot).unwrap()[..],
        SNAPSHOT_PNG,
        "a snapshot picture no longer decrypts"
    );
    assert!(
        store.verify_download(&contents.download).unwrap(),
        "a download record's MAC no longer verifies"
    );
}

#[test]
fn a_new_library_is_version_3_and_opens_only_with_its_vaults_key() {
    let dir = scratch_dir("new");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let mut store = Store::create_in_vault(&path, &key).unwrap();
    assert_eq!(store.format_version(), 3);
    let id = store.add_bookmark("https://a.example/", "A").unwrap();
    drop(store);

    let bytes = fs::read(&path).unwrap();
    assert_eq!(&bytes[..7], format::MAGIC);
    assert_eq!(bytes[7], format::VERSION_V3);
    for passphrase in [None, Some(OLD)] {
        let reopened = Store::open(&path, passphrase, &key).unwrap();
        assert_eq!(reopened.format_version(), 3);
        assert!(reopened.get_bookmark(&id).is_some());
    }
    assert!(matches!(
        Store::open(&path, None, &vault_key()),
        Err(StoreError::VaultMismatch)
    ));
    assert!(
        matches!(Store::unlock(&path, OLD), Err(StoreError::BadFormat(_))),
        "a version 3 Library must not open with a passphrase"
    );
    assert!(matches!(
        Store::create_in_vault(&path, &key),
        Err(StoreError::AlreadyExists(_))
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn each_version_keeps_its_format_across_saves() {
    let dir = scratch_dir("saves");
    let key = vault_key();
    let v3 = dir.join("v3.rbs");
    let mut store = Store::create_in_vault(&v3, &key).unwrap();
    let first = fs::read(&v3).unwrap();
    store.add_bookmark("https://a.example/", "A").unwrap();
    let second = fs::read(&v3).unwrap();
    assert_eq!(second[7], format::VERSION_V3);
    assert_eq!(
        first[..format::WRAP_AAD_LEN + format::WRAPPED_LEN],
        second[..format::WRAP_AAD_LEN + format::WRAPPED_LEN],
        "a save re-wrapped the key"
    );
    assert_ne!(
        first[format::WRAP_AAD_LEN + format::WRAPPED_LEN..format::HEADER_LEN_V3],
        second[format::WRAP_AAD_LEN + format::WRAPPED_LEN..format::HEADER_LEN_V3],
        "a save reused the content nonce"
    );

    let v1 = dir.join("v1.rbs");
    let mut old = v1_library(&v1);
    old.add_bookmark("https://b.example/", "B").unwrap();
    assert_eq!(old.format_version(), 1);
    assert_eq!(fs::read(&v1).unwrap()[7], format::VERSION);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_version_1_library_opens_with_the_passphrase_and_without_it_needs_one() {
    let dir = scratch_dir("needs");
    let path = dir.join("store.rbs");
    drop(v1_library(&path));
    let key = vault_key();
    assert!(matches!(
        Store::open(&path, None, &key),
        Err(StoreError::NeedsPassphrase)
    ));
    assert!(matches!(
        Store::open(&path, Some("wrong"), &key),
        Err(StoreError::AuthFailed)
    ));
    let opened = Store::open(&path, Some(OLD), &key).unwrap();
    assert_eq!(opened.format_version(), 1);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_move_keeps_the_key_so_pictures_and_download_records_still_verify() {
    let dir = scratch_dir("move");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let mut store = v1_library(&path);
    let contents = fill(&mut store);
    let v1_salt: [u8; crypto::SALT_LEN] = fs::read(&path).unwrap()[20..36].try_into().unwrap();

    store.move_into_vault(&key).unwrap();

    assert_eq!(store.format_version(), 3);
    assert_contents(&store, &contents);
    drop(store);
    let reopened = Store::open(&path, None, &key).unwrap();
    assert_eq!(reopened.format_version(), 3);
    assert_contents(&reopened, &contents);
    assert_eq!(
        reopened.data.v1_salt,
        Some(model::V1Salt(v1_salt)),
        "the version 1 salt was not recorded inside the Library"
    );
    // With the old passphrase it gives the key: never in a debug line.
    let shown = format!("{:?}", reopened.data);
    assert!(shown.contains("V1Salt(<redacted>)"), "{shown}");
    assert!(
        !shown.contains(&format!("{:?}", v1_salt)),
        "the recorded salt is printable: {shown}"
    );
    // Moved already: a second move writes nothing.
    let before = fs::read(&path).unwrap();
    let mut reopened = reopened;
    reopened.move_into_vault(&vault_key()).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn after_the_move_the_library_file_holds_nothing_the_old_passphrase_opens() {
    let dir = scratch_dir("old-pass");
    let path = dir.join("store.rbs");
    let mut store = v1_library(&path);
    store.add_bookmark("https://a.example/", "A").unwrap();
    let v1 = fs::read(&path).unwrap();
    let salt = &v1[20..36];
    store.move_into_vault(&vault_key()).unwrap();
    drop(store);

    let moved = fs::read(&path).unwrap();
    assert!(
        !moved.windows(salt.len()).any(|window| window == salt),
        "the version 1 salt, which with the old passphrase gives the key, is readable in the file"
    );
    assert!(Store::unlock(&path, OLD).is_err());
    assert!(matches!(
        Store::open(&path, Some(OLD), &vault_key()),
        Err(StoreError::VaultMismatch)
    ));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_failed_move_leaves_the_file_and_memory_as_they_were() {
    let dir = scratch_dir("move-fails");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let mut store = v1_library(&path);
    store.add_bookmark("https://a.example/", "A").unwrap();
    let before = fs::read(&path).unwrap();
    for point in [
        FailPoint::DuringWrite,
        FailPoint::DuringSync,
        FailPoint::BeforeRename,
    ] {
        store.fail_next_write_for_test(point);
        assert!(
            store.move_into_vault(&key).is_err(),
            "{point:?}: the injected failure did not surface"
        );
        assert_eq!(store.format_version(), 1, "{point:?}");
        assert_eq!(store.data.v1_salt, None, "{point:?}");
        assert_eq!(fs::read(&path).unwrap(), before, "{point:?}");
    }
    // Memory still matches the version 1 file: an ordinary save keeps it
    // version 1, and the move then goes through.
    store.add_bookmark("https://b.example/", "B").unwrap();
    assert_eq!(fs::read(&path).unwrap()[7], format::VERSION);
    assert!(Store::unlock(&path, OLD).is_ok());
    store.move_into_vault(&key).unwrap();
    assert_eq!(Store::open(&path, None, &key).unwrap().bookmarks().len(), 2);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn confirm_durable_reports_an_injected_failure_once() {
    let dir = scratch_dir("confirm");
    let store = Store::create_in_vault(&dir.join("store.rbs"), &vault_key()).unwrap();
    store.confirm_durable().unwrap();
    store.fail_next_confirm_for_test();
    assert!(matches!(
        store.confirm_durable(),
        Err(StoreError::NotDurable(_))
    ));
    store.confirm_durable().unwrap();
    fs::remove_dir_all(&dir).ok();
}

/// Strict for real: a flush that fails (here, the directory is gone) is
/// `NotDurable`, where an ordinary save shrugs it off. Unix only: elsewhere a
/// directory cannot be flushed at all, which is not an error.
#[cfg(unix)]
#[test]
fn confirm_durable_is_strict_about_a_real_flush_failure() {
    let dir = scratch_dir("confirm-strict");
    let store = Store::create_in_vault(&dir.join("store.rbs"), &vault_key()).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert!(matches!(
        store.confirm_durable(),
        Err(StoreError::NotDurable(_))
    ));
}

#[test]
fn every_byte_of_a_version_3_header_is_authenticated() {
    let dir = scratch_dir("tamper");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let mut store = Store::create_in_vault(&path, &key).unwrap();
    store.add_bookmark("https://a.example/", "A").unwrap();
    drop(store);
    let good = fs::read(&path).unwrap();
    for at in (0..format::HEADER_LEN_V3).chain([format::HEADER_LEN_V3, good.len() - 1]) {
        let mut bad = good.clone();
        bad[at] ^= 0x01;
        fs::write(&path, &bad).unwrap();
        let outcome = Store::open(&path, None, &key);
        match at {
            0..=7 => assert!(
                matches!(outcome, Err(StoreError::BadFormat(_))),
                "byte {at}: {outcome:?}"
            ),
            _ => assert!(
                matches!(outcome, Err(StoreError::VaultMismatch)),
                "byte {at}: {outcome:?}"
            ),
        }
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_short_version_3_file_is_refused_before_any_decryption() {
    let dir = scratch_dir("short");
    let path = dir.join("store.rbs");
    let key = vault_key();
    drop(Store::create_in_vault(&path, &key).unwrap());
    let good = fs::read(&path).unwrap();
    for len in 0..format::HEADER_LEN_V3 + 16 {
        fs::write(&path, &good[..len]).unwrap();
        assert!(
            matches!(
                Store::open(&path, None, &key),
                Err(StoreError::BadFormat(_))
            ),
            "a {len}-byte file was not refused as malformed"
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_unknown_version_is_refused_and_left_alone() {
    let dir = scratch_dir("unknown");
    let path = dir.join("store.rbs");
    let key = vault_key();
    drop(Store::create_in_vault(&path, &key).unwrap());
    let mut bytes = fs::read(&path).unwrap();
    for version in [0x00u8, 0x02, 0x04, 0xff] {
        bytes[7] = version;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            Store::open(&path, Some(OLD), &key),
            Err(StoreError::BadFormat(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes, "version {version:#04x}");
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_library_without_the_recorded_salt_reads_as_none_and_writes_nothing_for_it() {
    let dir = scratch_dir("salt-field");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let store = Store::create_in_vault(&path, &key).unwrap();
    assert_eq!(store.data.v1_salt, None);
    let json = serde_json::to_string(&store.data).unwrap();
    assert!(
        !json.contains("v1_salt"),
        "an unset salt was written: {json}"
    );
    fs::remove_dir_all(&dir).ok();
}
