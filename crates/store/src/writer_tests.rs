//! The Library writer's temporary file (2026-09-27).
//!
//! Until this change the Store wrote through `<path>.tmp`, a name anyone who
//! can write to the Library's directory could predict, opened with an ordinary
//! create that FOLLOWS a symlink already sitting there. `blob.rs` had avoided
//! exactly that shape for picture files from the start; these tests pin the
//! Store to the same discipline, prove the old name is no longer used, and
//! prove every failure before the rename cleans up after itself.

use super::*;

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("patanyx-writer-test-{tag}-{}", random_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fast KDF parameters, as in the other store tests.
fn make_store(path: &Path, passphrase: &str) -> Store {
    Store::create_with_params(path, passphrase, 8192, 1, 1).unwrap()
}

/// Every temporary file this writer could have left in `dir`.
fn temp_files(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with(".tmp-"))
        .collect();
    out.sort();
    out
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_old_predictable_temp_name_is_not_followed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = scratch_dir("oldname");
    let outside = scratch_dir("oldname-outside");
    let victim = outside.join("victim");
    fs::write(&victim, b"do not touch").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();

    let path = dir.join("store.rbs");
    let mut store = make_store(&path, "pw");
    // Planted where every build up to 1.0.2 put its temporary file.
    let old_tmp = dir.join("store.rbs.tmp");
    symlink(&victim, &old_tmp).unwrap();

    store.create_folder("planted").unwrap();

    assert_eq!(
        fs::read(&victim).unwrap(),
        b"do not touch",
        "the save wrote through a symlink planted at the old temp name"
    );
    assert_eq!(
        fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644,
        "the save changed the mode of the file the symlink pointed at"
    );
    assert!(
        fs::symlink_metadata(&old_tmp)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the save touched the planted link at all"
    );
    assert!(
        fs::symlink_metadata(&path).unwrap().file_type().is_file(),
        "the Library itself is no longer a regular file"
    );
    let reopened = Store::unlock(&path, "pw").unwrap();
    assert!(reopened.folders().iter().any(|f| f == "planted"));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
}

#[cfg(unix)]
#[test]
fn a_new_temp_file_refuses_whatever_is_already_at_its_name() {
    use std::io::ErrorKind::AlreadyExists;
    use std::os::unix::fs::symlink;
    let dir = scratch_dir("createnew");
    let outside = scratch_dir("createnew-outside");

    // A symlink to an existing file: neither followed nor written through.
    let victim = outside.join("victim");
    fs::write(&victim, b"do not touch").unwrap();
    let link = dir.join(".tmp-planted-link");
    symlink(&victim, &link).unwrap();
    assert_eq!(open_new_temp(&link).unwrap_err().kind(), AlreadyExists);
    assert_eq!(fs::read(&victim).unwrap(), b"do not touch");

    // A DANGLING symlink: an ordinary create would make its target.
    let would_be_created = outside.join("would-be-created");
    let dangling = dir.join(".tmp-dangling");
    symlink(&would_be_created, &dangling).unwrap();
    assert_eq!(open_new_temp(&dangling).unwrap_err().kind(), AlreadyExists);
    assert!(
        !would_be_created.exists(),
        "a create followed a dangling symlink and made its target"
    );

    // An ordinary file: not truncated.
    let existing = dir.join(".tmp-planted-file");
    fs::write(&existing, b"existing").unwrap();
    assert_eq!(open_new_temp(&existing).unwrap_err().kind(), AlreadyExists);
    assert_eq!(fs::read(&existing).unwrap(), b"existing");

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn temp_names_are_unpredictable_and_never_reused() {
    let dir = Path::new("somewhere");
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let temp = temp_path_in(dir);
        assert_eq!(
            temp.parent(),
            Some(dir),
            "the temp file must sit beside the Library"
        );
        let name = temp.file_name().unwrap().to_str().unwrap().to_string();
        let hex = name
            .strip_prefix(".tmp-")
            .expect("temp files must be recognisable by their prefix");
        assert_eq!(hex.len(), 32, "{name}");
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{name}"
        );
        assert!(seen.insert(name), "a temp name repeated");
    }
}

#[cfg(unix)]
#[test]
fn a_failed_rename_removes_the_temp_file_and_leaves_the_target_alone() {
    let dir = scratch_dir("rename");
    // The target is a non-empty directory, so the rename itself fails after
    // the temporary file was written and flushed.
    let path = dir.join("lib.rbs");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("inside"), b"kept").unwrap();

    let result = atomic_replace(&path, b"new bytes", Fault::None);

    assert!(matches!(result, Err(StoreError::Io(_))), "{result:?}");
    assert_eq!(fs::read(path.join("inside")).unwrap(), b"kept");
    assert_eq!(
        temp_files(&dir),
        Vec::<String>::new(),
        "the temp file was left behind"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_cleanup_that_fails_too_still_returns_the_original_error() {
    // Final review, 2026-09-27: cleanup is best effort. When it fails as well,
    // the caller must still see the error that mattered (here, the rename's),
    // and the file left behind must be as protected as crash debris.
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch_dir("cleanupfails");
    let path = dir.join("lib.rbs");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("inside"), b"kept").unwrap();

    let result = atomic_replace(&path, b"new bytes", Fault::Cleanup);

    let Err(StoreError::Io(error)) = result else {
        panic!("expected an i/o error, got {result:?}");
    };
    assert!(
        !error.to_string().contains("removing the temporary file"),
        "the cleanup's error replaced the rename's: {error}"
    );
    let left = temp_files(&dir);
    assert_eq!(left.len(), 1, "{left:?}");
    let mode = fs::metadata(dir.join(&left[0]))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "a leftover temp file must be owner-only");
    assert_eq!(fs::read(path.join("inside")).unwrap(), b"kept");
    let _ = fs::remove_dir_all(&dir);
}

/// A fault at `point` must return the ORIGINAL error, leave the previous
/// Library byte-for-byte as it was, remove the temporary file, and roll the
/// in-memory change back; and the next save must work.
fn a_fault_before_the_rename_leaves_everything_as_it_was(point: FailPoint, message: &str) {
    let dir = scratch_dir("fault");
    let path = dir.join("store.rbs");
    let mut store = make_store(&path, "pw");
    store.create_folder("kept").unwrap();
    let before = fs::read(&path).unwrap();

    store.fail_next_write_for_test(point);
    let error = store.create_folder("lost").unwrap_err();

    assert!(
        error.to_string().contains(message),
        "the original error was not returned: {error}"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "the previous Library changed"
    );
    assert_eq!(
        temp_files(&dir),
        Vec::<String>::new(),
        "a temporary file was left behind"
    );
    assert!(
        !store.folders().iter().any(|f| f == "lost"),
        "the in-memory change was not rolled back"
    );
    let reopened = Store::unlock(&path, "pw").unwrap();
    assert!(reopened.folders().iter().any(|f| f == "kept"));
    assert!(!reopened.folders().iter().any(|f| f == "lost"));

    store.create_folder("after").unwrap();
    assert!(Store::unlock(&path, "pw")
        .unwrap()
        .folders()
        .iter()
        .any(|f| f == "after"));
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_write_that_fails_part_way_is_cleaned_up() {
    a_fault_before_the_rename_leaves_everything_as_it_was(
        FailPoint::DuringWrite,
        "part-way through the write",
    );
}

#[test]
fn a_failed_flush_of_the_temp_file_is_cleaned_up() {
    a_fault_before_the_rename_leaves_everything_as_it_was(
        FailPoint::DuringSync,
        "temporary file's flush",
    );
}

#[test]
fn a_failure_just_before_the_rename_is_cleaned_up() {
    a_fault_before_the_rename_leaves_everything_as_it_was(
        FailPoint::BeforeRename,
        "before the rename",
    );
}

#[test]
fn a_successful_save_leaves_no_temp_file() {
    let dir = scratch_dir("clean");
    let path = dir.join("store.rbs");
    let mut store = make_store(&path, "pw");
    for name in ["one", "two", "three"] {
        store.create_folder(name).unwrap();
    }
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_long_file_name_still_saves() {
    // Plan review, 2026-09-27: a temp name built from the Library's name would
    // add 38 bytes, and 240 + 38 is past the usual 255-byte limit.
    let dir = scratch_dir("longname");
    let name = format!("{}.rbs", "l".repeat(236));
    assert_eq!(name.len(), 240);
    let path = dir.join(&name);
    let mut store = make_store(&path, "pw");
    store.create_folder("long").unwrap();
    assert!(Store::unlock(&path, "pw")
        .unwrap()
        .folders()
        .iter()
        .any(|f| f == "long"));
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_utf8_still_saves() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch_dir("nonutf8");
    let path = dir.join(std::ffi::OsStr::from_bytes(b"store-\xff.rbs"));
    let mut store = make_store(&path, "pw");
    store.create_folder("bytes").unwrap();
    assert!(Store::unlock(&path, "pw")
        .unwrap()
        .folders()
        .iter()
        .any(|f| f == "bytes"));
    let _ = fs::remove_dir_all(&dir);
}

/// The mode must come from the create itself, not from a friendly umask. A test
/// process that inherited umask 077 would pass even with the mode removed, so
/// the check runs in a CHILD under umask 000. The child writes a marker, so a
/// filter that matched no test cannot pass vacuously.
#[cfg(unix)]
#[test]
fn the_library_is_0600_even_under_a_permissive_umask() {
    const CHILD: &str = "PATANYX_STORE_UMASK_CHILD";
    const NAME: &str = "writer_tests::the_library_is_0600_even_under_a_permissive_umask";
    if let Some(dir) = std::env::var_os(CHILD) {
        use std::os::unix::fs::PermissionsExt;
        let dir = PathBuf::from(dir);
        let path = dir.join("store.rbs");
        let mut store = make_store(&path, "pw");
        store.create_folder("umask").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "under umask 000 the Library was {mode:o}");
        fs::write(dir.join("child-ran"), b"yes").unwrap();
        return;
    }
    let dir = scratch_dir("umask");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"umask 000 && exec "$0" --exact "$1" --test-threads=1 --nocapture"#)
        .arg(std::env::current_exe().unwrap())
        .arg(NAME)
        .env(CHILD, &dir)
        .status()
        .unwrap();
    assert!(status.success(), "the check under umask 000 failed");
    assert!(
        dir.join("child-ran").exists(),
        "the child never ran the check"
    );
    let _ = fs::remove_dir_all(&dir);
}
