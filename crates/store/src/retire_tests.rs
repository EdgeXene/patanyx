//! Retiring the leftover copies of a Library's version 1 file (2026-09-27).
//!
//! A version 1 copy of the Library opens with the passphrase it was written
//! under and, since the data key never changes, reads every later version of
//! the Library. These tests pin what a change removes (copies of THIS
//! Library's version 1 file at the writer's exact names, whole or cut short
//! but carrying at least 8 bytes of its salt), what it keeps (everything
//! else, reported whenever it is shaped like a Library), and when it runs
//! (only for a Library that moved into the vault, at every later change).

use super::*;
use crate::retire::{judge, retire_entries, Leftover};

const OLD: &str = "old passphrase";

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("patanyx-retire-test-{tag}-{}", random_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn vault_key() -> Zeroizing<[u8; crypto::KEY_LEN]> {
    Zeroizing::new(crypto::random_bytes::<{ crypto::KEY_LEN }>())
}

/// A Library from before version 3, and its file's bytes.
fn v1_library(path: &Path) -> (Store, Vec<u8>) {
    let mut store = Store::create_with_params(path, OLD, 8192, 1, 1).unwrap();
    store.add_bookmark("https://kept.example/", "Kept").unwrap();
    let bytes = fs::read(path).unwrap();
    (store, bytes)
}

/// A fresh name in the writer's shape, in `dir`.
fn leftover_in(dir: &Path) -> PathBuf {
    dir.join(format!(".tmp-{}", random_id()))
}

/// Puts `bytes` at a fresh leftover name in `dir`.
fn plant(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = leftover_in(dir);
    fs::write(&path, bytes).unwrap();
    path
}

/// Whether `passphrase` derives `key` from `bytes`, the way someone holding
/// the file would: the version 1 derivation over its header's salt.
fn hands_over_key(bytes: &[u8], passphrase: &str, key: &[u8; crypto::KEY_LEN]) -> bool {
    let Ok(header) = format::decode_header(bytes) else {
        return false;
    };
    crypto::derive_key(passphrase.as_bytes(), &header.salt, &header.params)
        .is_ok_and(|derived| derived[..] == key[..])
}

#[test]
fn the_move_then_retirement_removes_every_copy_the_version_1_writer_left() {
    let dir = scratch_dir("move");
    let path = dir.join("store.rbs");
    let (mut store, v1) = v1_library(&path);
    assert!(hands_over_key(&v1, OLD, &store.key), "precondition");
    let whole = plant(&dir, &v1);
    let cut = plant(
        &dir,
        &v1[..format::HEADER_LEN + (v1.len() - format::HEADER_LEN) / 2],
    );
    // 15 of the 16 salt bytes: 256 guesses from the key, and eight is the
    // least that proves the copy is this Library's.
    let most_of_a_salt = plant(&dir, &v1[..35]);
    let eight_salt_bytes = plant(&dir, &v1[..28]);
    // Where every build up to 1.0.2 left its temporary file.
    let legacy = dir.join("store.rbs.tmp");
    fs::write(&legacy, &v1).unwrap();

    store.move_into_vault(&vault_key()).unwrap();
    let outcome = store.retire_v1_leftovers();

    assert!(outcome.is_ok(), "{outcome:?}");
    for file in [&whole, &cut, &most_of_a_salt, &eight_salt_bytes, &legacy] {
        assert!(!file.exists(), "{} survived", file.display());
    }
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap().path();
        if entry.is_file() && entry != path {
            assert!(
                !hands_over_key(&fs::read(&entry).unwrap(), OLD, &store.key),
                "{} still opens with the old passphrase",
                entry.display()
            );
        }
    }
    assert_eq!(store.format_version(), 3);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_later_change_retries_with_the_salt_the_library_recorded() {
    let dir = scratch_dir("retry");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let (mut store, v1) = v1_library(&path);
    store.move_into_vault(&key).unwrap();
    // A leftover this change could not inspect is kept and reported ...
    let stuck = plant(&dir, &v1);
    let entries = vec![Ok((
        stuck.file_name().unwrap().to_os_string(),
        stuck.clone(),
    ))];
    let outcome = retire_entries(
        &path,
        entries.into_iter(),
        |_| Err(std::io::Error::other("injected: unreadable")),
        || Ok(()),
    );
    assert!(
        matches!(outcome, Err(StoreError::LeftoversRetained(_))),
        "{outcome:?}"
    );
    assert!(stuck.exists());
    drop(store);

    // ... and the next change, after a lock and an unlock, still knows it.
    let reopened = Store::open(&path, None, &key).unwrap();
    reopened.retire_v1_leftovers().unwrap();
    assert!(!stuck.exists(), "a later change did not retry");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_fragment_with_fewer_than_eight_salt_bytes_is_kept_and_reported() {
    let dir = scratch_dir("fragment");
    let path = dir.join("store.rbs");
    let (mut store, v1) = v1_library(&path);
    let fragment = plant(&dir, &v1[..27]);
    store.move_into_vault(&vault_key()).unwrap();

    let outcome = store.retire_v1_leftovers();

    assert!(
        matches!(outcome, Err(StoreError::LeftoversRetained(_))),
        "{outcome:?}"
    );
    assert!(
        fragment.exists(),
        "a fragment that proves nothing was removed"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn another_library_and_an_unknown_version_are_kept_and_reported() {
    for tag in ["another", "unknown-version"] {
        let dir = scratch_dir(tag);
        let path = dir.join("store.rbs");
        let (mut store, v1) = v1_library(&path);
        let bytes = if tag == "another" {
            // Another Library made with the same passphrase: another salt.
            let other_dir = scratch_dir("another-source");
            let (_, other) = v1_library(&other_dir.join("store.rbs"));
            fs::remove_dir_all(&other_dir).ok();
            other
        } else {
            let mut unknown = v1.clone();
            unknown[7] = 0x02;
            unknown
        };
        let kept = plant(&dir, &bytes);
        store.move_into_vault(&vault_key()).unwrap();

        let outcome = store.retire_v1_leftovers();

        assert!(
            matches!(outcome, Err(StoreError::LeftoversRetained(_))),
            "{tag}: {outcome:?}"
        );
        assert_eq!(fs::read(&kept).unwrap(), bytes, "{tag}");
        fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn files_that_hold_nothing_a_passphrase_opens_are_kept_without_a_word() {
    let dir = scratch_dir("foreign");
    let outside = scratch_dir("foreign-outside");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let (mut store, v1) = v1_library(&path);
    let mut vaultish = b"RBVAULT".to_vec();
    vaultish.extend_from_slice(&v1[7..]);
    let another_v3 = {
        let other = scratch_dir("v3-source");
        drop(Store::create_in_vault(&other.join("store.rbs"), &key).unwrap());
        let bytes = fs::read(other.join("store.rbs")).unwrap();
        fs::remove_dir_all(&other).ok();
        bytes
    };
    let kept = [
        plant(&dir, &vaultish),
        plant(&dir, b"not a library at all"),
        plant(&dir, b""),
        plant(&dir, format::MAGIC),
        // Up to the salt and not one byte of it.
        plant(&dir, &v1[..20]),
        // A version 3 file holds nothing a passphrase opens.
        plant(&dir, &another_v3),
    ];
    let directory = leftover_in(&dir);
    fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    let (link, target) = {
        let target = outside.join("copy-of-the-library");
        fs::write(&target, &v1).unwrap();
        let link = leftover_in(&dir);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        (link, target)
    };

    store.move_into_vault(&key).unwrap();
    let outcome = store.retire_v1_leftovers();

    assert!(outcome.is_ok(), "{outcome:?}");
    for file in &kept {
        assert!(file.exists(), "{} was removed", file.display());
    }
    assert!(
        directory.is_dir(),
        "a directory at a leftover's name was removed"
    );
    #[cfg(unix)]
    {
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink was removed or replaced"
        );
        assert_eq!(fs::read(&target).unwrap(), v1, "the symlink was followed");
    }
    fs::remove_dir_all(&dir).ok();
    fs::remove_dir_all(&outside).ok();
}

#[cfg(unix)]
#[test]
fn retirement_does_not_block_on_a_fifo_at_a_leftovers_name() {
    use std::os::unix::fs::FileTypeExt;
    let dir = scratch_dir("fifo");
    let path = dir.join("store.rbs");
    let (mut store, _) = v1_library(&path);
    let fifo = leftover_in(&dir);
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success(), "precondition: mkfifo");
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = store
            .move_into_vault(&vault_key())
            .and_then(|()| store.retire_v1_leftovers());
        let _ = done.send(result);
    });
    let result = outcome
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("retirement blocked on a FIFO at a leftover's name");
    assert!(result.is_ok(), "{result:?}");
    assert!(
        fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo(),
        "the FIFO was removed"
    );
    fs::remove_dir_all(&dir).ok();
}

/// A copy at any other spelling may be one someone kept on purpose, which
/// the salt would call ours, so only the writer's exact names are ever
/// considered, compared as bytes (the held retirement's final review, rounds
/// 1 to 4).
#[test]
fn only_the_writers_exact_names_are_considered() {
    let dir = scratch_dir("names");
    let path = dir.join("STORE.RBS");
    let (mut store, v1) = v1_library(&path);
    let ignores_case = fs::symlink_metadata(dir.join("store.rbs")).is_ok();
    let exact = [
        dir.join("STORE.RBS.tmp"),
        dir.join(format!(".tmp-{}", "0123456789abcdef".repeat(2))),
    ];
    // Uppercase hex under other digits, so it is another name even where the
    // directory ignores case (final review, R-004).
    let mut others = vec![
        dir.join(format!(".tmp-{}", "FEDCBA9876543210".repeat(2))),
        dir.join(format!(".tmp-{}", &"0123456789abcdef".repeat(2)[..31])),
        dir.join(format!(".tmp-{}0", "0123456789abcdef".repeat(2))),
        dir.join(format!("x.tmp-{}", "0123456789abcdef".repeat(2))),
        dir.join("STORE.RBS.tmp.bak"),
        dir.join("STORE.RBS.tmp~"),
        dir.join("STORE.RBS.mine"),
    ];
    if !ignores_case {
        others.push(dir.join("store.rbs.tmp"));
        others.push(dir.join("Store.Rbs.TMP"));
        others.push(dir.join(format!(".TMP-{}", "0123456789abcdef".repeat(2))));
    }
    for file in exact.iter().chain(&others) {
        fs::write(file, &v1).unwrap();
    }

    store.move_into_vault(&vault_key()).unwrap();
    store.retire_v1_leftovers().unwrap();

    for file in &exact {
        assert!(!file.exists(), "{} survived", file.display());
    }
    for file in &others {
        assert!(file.exists(), "{} was taken for a leftover", file.display());
    }
    fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn a_leftover_at_the_old_name_of_a_library_whose_name_is_not_utf8_is_removed() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let dir = scratch_dir("non-utf8");
    let name = OsString::from_vec(b"sto\xFFre.rbs".to_vec());
    let path = dir.join(&name);
    let (mut store, v1) = v1_library(&path);
    let mut legacy = name.into_vec();
    legacy.extend_from_slice(b".tmp");
    let legacy = dir.join(OsString::from_vec(legacy));
    fs::write(&legacy, &v1).unwrap();

    store.move_into_vault(&vault_key()).unwrap();
    let outcome = store.retire_v1_leftovers();

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(!legacy.exists(), "1.0.2's leftover survived");
    fs::remove_dir_all(&dir).ok();
}

/// The Library's path may be a link to a file in its own directory under a
/// leftover's name. The move's rename replaces the link with the version 3
/// file, so what the link reached is then a copy of the version 1 file, and
/// it goes; the Library itself keeps working.
#[cfg(unix)]
#[test]
fn a_library_reached_through_a_link_under_a_leftovers_name_keeps_working() {
    let dir = scratch_dir("alias");
    let path = dir.join("store.rbs");
    let key = vault_key();
    let (store, _) = v1_library(&path);
    drop(store);
    let target = leftover_in(&dir);
    fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(target.file_name().unwrap(), &path).unwrap();

    let mut store = Store::unlock(&path, OLD).unwrap();
    store.move_into_vault(&key).unwrap();
    store.retire_v1_leftovers().unwrap();
    drop(store);

    assert!(
        !target.exists(),
        "the version 1 file the link reached survived"
    );
    assert!(!fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    let reopened = Store::open(&path, None, &key).unwrap();
    assert_eq!(reopened.bookmarks().len(), 1);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn only_a_library_that_moved_into_the_vault_retires_anything() {
    let dir = scratch_dir("when");
    let path = dir.join("store.rbs");
    let (store, v1) = v1_library(&path);
    let copy = plant(&dir, &v1);
    // Not moved: its own copies still open with the passphrase it opens with.
    store.retire_v1_leftovers().unwrap();
    assert!(copy.exists(), "a version 1 Library's copy was removed");
    fs::remove_dir_all(&dir).ok();

    // Born in the vault: no version 1 file ever existed, and a stray one
    // (another Library's) is neither removed nor reported.
    let dir = scratch_dir("when-v3");
    let path = dir.join("store.rbs");
    let store = Store::create_in_vault(&path, &vault_key()).unwrap();
    let stray = plant(&dir, &v1);
    store.retire_v1_leftovers().unwrap();
    assert!(stray.exists());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_failure_on_one_entry_does_not_stop_the_rest_and_the_directory_is_still_flushed() {
    let dir = scratch_dir("failures");
    let path = dir.join("store.rbs");
    let (mut store, v1) = v1_library(&path);
    store.move_into_vault(&vault_key()).unwrap();
    let broken = plant(&dir, &v1);
    let fine = plant(&dir, &v1);
    let flushed = std::cell::Cell::new(false);
    let entries = vec![
        Err(std::io::Error::other(
            "injected: the listing failed part-way",
        )),
        Ok((broken.file_name().unwrap().to_os_string(), broken.clone())),
        Ok((fine.file_name().unwrap().to_os_string(), fine.clone())),
    ];
    let outcome = retire_entries(
        &path,
        entries.into_iter(),
        |entry| {
            if entry == broken {
                Err(std::io::Error::other("injected: unreadable"))
            } else {
                Ok(Leftover::Ours)
            }
        },
        || {
            flushed.set(true);
            Ok(())
        },
    );
    assert!(
        matches!(&outcome, Err(StoreError::LeftoversRetained(why)) if why.contains("listed, read")),
        "{outcome:?}"
    );
    assert!(broken.exists());
    assert!(!fine.exists(), "one failure stopped the rest");
    assert!(flushed.get(), "the directory was not flushed");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_directory_flush_that_fails_is_reported_even_with_nothing_removed() {
    let dir = scratch_dir("flush");
    let path = dir.join("store.rbs");
    let outcome = retire_entries(
        &path,
        std::iter::empty(),
        |_| Ok(Leftover::Ours),
        || Err(std::io::Error::other("injected: the flush failed")),
    );
    assert!(
        matches!(outcome, Err(StoreError::LeftoversRetained(_))),
        "{outcome:?}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_boundaries_of_the_proof() {
    let dir = scratch_dir("judge");
    let (_, v1) = v1_library(&dir.join("store.rbs"));
    let salt: [u8; crypto::SALT_LEN] = v1[20..36].try_into().unwrap();
    let mut other_salt = salt;
    other_salt[0] ^= 0x01;
    assert_eq!(judge(&salt, &v1[..6]), Leftover::Foreign);
    assert_eq!(judge(&salt, &v1[..7]), Leftover::Foreign);
    assert_eq!(judge(&salt, &v1[..20]), Leftover::Foreign);
    assert_eq!(judge(&salt, &v1[..21]), Leftover::Unknown);
    assert_eq!(judge(&salt, &v1[..27]), Leftover::Unknown);
    assert_eq!(judge(&salt, &v1[..28]), Leftover::Ours);
    assert_eq!(judge(&salt, &v1[..36]), Leftover::Ours);
    assert_eq!(judge(&other_salt, &v1[..28]), Leftover::Unknown);
    assert_eq!(judge(&other_salt, &v1[..36]), Leftover::Unknown);
    let mut versioned = v1[..36].to_vec();
    for (version, expected) in [
        (format::VERSION_V3, Leftover::Foreign),
        (0x02, Leftover::Unknown),
        (0xff, Leftover::Unknown),
    ] {
        versioned[7] = version;
        assert_eq!(judge(&salt, &versioned), expected, "version {version:#04x}");
    }
    fs::remove_dir_all(&dir).ok();
}
