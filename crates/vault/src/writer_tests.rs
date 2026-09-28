//! The vault writer's temporary file (2026-09-27).
//!
//! Until this change the vault wrote through `<path>.tmp`, a name anyone who
//! can write to the vault's directory could predict, opened with an ordinary
//! create that FOLLOWS a symlink already sitting there. The same writer serves
//! the rotating backups and both exports. The Library's writer was moved off
//! that shape first; these tests pin the vault to the same discipline.

use super::*;

const PASS: &str = "test passphrase";

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("patanyx-vault-writer-{tag}-{}", random_id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fast KDF parameters, as in the other vault tests.
fn make_vault(path: &Path) -> Vault {
    Vault::create_with_params(path, PASS, 8192, 1, 1).unwrap().0
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
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

    let path = dir.join("vault.rbv");
    let mut vault = make_vault(&path);
    // Planted where every build up to 1.0.2 put its temporary file.
    let old_tmp = dir.join("vault.rbv.tmp");
    symlink(&victim, &old_tmp).unwrap();

    vault.add_note("planted", "body").unwrap();

    assert_eq!(
        fs::read(&victim).unwrap(),
        b"do not touch",
        "the save wrote through a symlink planted at the old temp name"
    );
    assert_eq!(
        mode_of(&victim),
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
        "the vault itself is no longer a regular file"
    );
    drop(vault); // one process per vault: release before reopening
    let reopened = Vault::unlock(&path, PASS).unwrap();
    assert!(reopened.list_notes().iter().any(|n| n.title == "planted"));
    drop(reopened);
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
}

/// The export that matters most: a link planted at `<dest>.tmp` received
/// every password in clear text.
#[cfg(unix)]
#[test]
fn a_plaintext_export_does_not_write_through_a_symlink_at_the_old_temp_name() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = scratch_dir("oldname-export");
    let outside = scratch_dir("oldname-export-outside");
    let victim = outside.join("victim");
    fs::write(&victim, b"do not touch").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();

    let path = dir.join("vault.rbv");
    let mut vault = make_vault(&path);
    vault
        .add_credential(
            "example.com",
            Some("example.com"),
            "alice",
            "visible-password",
            "",
        )
        .unwrap();
    let dest = dir.join("passwords.json");
    let old_tmp = dir.join("passwords.json.tmp");
    symlink(&victim, &old_tmp).unwrap();

    vault
        .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();

    assert_eq!(
        fs::read(&victim).unwrap(),
        b"do not touch",
        "the plaintext export was written through a symlink planted at the old temp name"
    );
    assert_eq!(mode_of(&victim), 0o644);
    assert!(
        fs::symlink_metadata(&old_tmp)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the export touched the planted link at all"
    );
    assert!(
        fs::symlink_metadata(&dest).unwrap().file_type().is_file(),
        "the export is not a regular file at the destination"
    );
    assert!(String::from_utf8(fs::read(&dest).unwrap())
        .unwrap()
        .contains("visible-password"));
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
}

/// Every temporary file a writer could have left in `dir`: this writer's
/// `.tmp-<hex>`, and the `.tmp` suffix every build up to 1.0.2 used.
fn temp_files(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with(".tmp-") || name.ends_with(".tmp"))
        .collect();
    out.sort();
    out
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
fn temp_names_are_unpredictable_and_recognised() {
    let dir = Path::new("somewhere");
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let temp = temp_path_in(dir);
        assert_eq!(
            temp.parent(),
            Some(dir),
            "the temp file must sit beside its target"
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
        assert!(is_temp_name(&name), "a rotation would not recognise {name}");
        assert!(seen.insert(name), "a temp name repeated");
    }
    // The recognizer takes exactly that shape and nothing near it.
    let hex = "0123456789abcdef".repeat(2);
    assert!(is_temp_name(&format!(".tmp-{hex}")));
    for near_miss in [
        format!(".tmp-{}", &hex[..31]),
        format!(".tmp-{hex}0"),
        format!(".tmp-{}", hex.to_uppercase()),
        format!(".tmp-{}g", &hex[..31]),
        format!("tmp-{hex}"),
        format!(".tmp{hex}"),
        format!("x.tmp-{hex}"),
        "vault.rbv.tmp".to_string(),
    ] {
        assert!(
            !is_temp_name(&near_miss),
            "{near_miss} is not this writer's name"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_failed_rename_removes_the_temp_file_and_leaves_the_target_alone() {
    let dir = scratch_dir("rename");
    // The target is a non-empty directory, so the rename itself fails after
    // the temporary file was written and flushed.
    let path = dir.join("vault.rbv");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("inside"), b"kept").unwrap();

    let result = atomic_write(&path, b"new bytes");

    assert!(matches!(result, Err(VaultError::Io(_))), "{result:?}");
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
    // Cleanup is best effort. When it fails as well, the caller must still see
    // the error that mattered (here, the rename's), and the file left behind
    // must be as protected as crash debris.
    let dir = scratch_dir("cleanupfails");
    let path = dir.join("vault.rbv");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("inside"), b"kept").unwrap();

    let result = atomic_write_with(&path, b"new bytes", Fault::Cleanup);

    let Err(VaultError::Io(error)) = result else {
        panic!("expected an i/o error, got {result:?}");
    };
    assert!(
        !error.to_string().contains("removing the temporary file"),
        "the cleanup's error replaced the rename's: {error}"
    );
    let left = temp_files(&dir);
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(
        mode_of(&dir.join(&left[0])),
        0o600,
        "a leftover temp file must be owner-only"
    );
    assert_eq!(fs::read(path.join("inside")).unwrap(), b"kept");
    let _ = fs::remove_dir_all(&dir);
}

/// A fault inside the writer must return the ORIGINAL error, leave the
/// previous vault byte for byte as it was, and remove the temporary file; and
/// the next save must work. (What the vault keeps IN MEMORY after a failed
/// save is its own, older contract: persist-on-write, and a failed save is a
/// hard error. Nothing here asserts about it.)
fn a_fault_inside_the_writer_leaves_the_vault_as_it_was(fault: Fault, message: &str) {
    let dir = scratch_dir("fault");
    let path = dir.join("vault.rbv");
    let mut vault = make_vault(&path);
    vault.add_note("kept", "body").unwrap();
    let before = fs::read(&path).unwrap();

    vault.fail_next_write_for_test(fault);
    let error = vault.add_note("failed", "body").unwrap_err();

    assert!(
        error.to_string().contains(message),
        "the original error was not returned: {error}"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "the previous vault changed"
    );
    assert_eq!(
        temp_files(&dir),
        Vec::<String>::new(),
        "a temporary file was left behind"
    );

    vault.add_note("after", "body").unwrap();
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    drop(vault);
    let reopened = Vault::unlock(&path, PASS).unwrap();
    assert!(reopened.list_notes().iter().any(|n| n.title == "after"));
    drop(reopened);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_write_that_fails_part_way_is_cleaned_up() {
    a_fault_inside_the_writer_leaves_the_vault_as_it_was(
        Fault::Write,
        "part-way through the write",
    );
}

#[test]
fn a_failed_flush_of_the_temp_file_is_cleaned_up() {
    a_fault_inside_the_writer_leaves_the_vault_as_it_was(Fault::Sync, "temporary file's flush");
}

#[test]
fn a_failure_just_before_the_rename_is_cleaned_up() {
    a_fault_inside_the_writer_leaves_the_vault_as_it_was(Fault::Rename, "before the rename");
}

/// `fail_next_save_for_test`, and the smoke run's `inject_save_failure_once`
/// that sets the same flag, keep their meaning: the save fails before ANYTHING
/// touches the disk. No backup is taken, no temporary file is made, and the
/// vault is untouched.
#[test]
fn an_injected_save_failure_still_touches_nothing() {
    let dir = scratch_dir("savefail");
    let path = dir.join("vault.rbv");
    let mut vault = make_vault(&path);
    vault.add_note("kept", "body").unwrap();
    let listing = |dir: &Path| {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    };
    let names_before = listing(&dir);
    assert!(
        names_before.iter().any(|n| n.starts_with("vault.rbv.bak-")),
        "precondition: a save here takes a backup first: {names_before:?}"
    );
    let before = fs::read(&path).unwrap();

    vault.fail_next_save_for_test();
    let error = vault.add_note("failed", "body").unwrap_err();

    assert!(
        error.to_string().contains("injected save failure (smoke)"),
        "{error}"
    );
    assert_eq!(
        listing(&dir),
        names_before,
        "the injected failure touched the directory"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "the injected failure touched the vault"
    );
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_successful_save_leaves_no_temp_file() {
    let dir = scratch_dir("clean");
    let path = dir.join("vault.rbv");
    let mut vault = make_vault(&path);
    for title in ["one", "two", "three"] {
        vault.add_note(title, "body").unwrap();
    }
    assert!(
        fs::read_dir(&dir).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("vault.rbv.bak-")),
        "precondition: the backup writer ran too"
    );
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    // Both exports, into the vault's own directory as the app suggests.
    vault
        .export_encrypted(&dir.join("vault-export.rbve"), "export-pass")
        .unwrap();
    vault
        .export_plaintext(&dir.join("passwords.json"), PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_long_file_name_still_saves() {
    // A temp name built from the target's name would add 37 bytes or more,
    // and 240 + 37 is past the usual 255-byte limit. Builds up to 1.0.2 added
    // 4 (`.tmp`), so a 240-byte name always worked.
    let dir = scratch_dir("longname");
    let name = format!("{}.rbv", "v".repeat(236));
    assert_eq!(name.len(), 240);
    let path = dir.join(&name);
    let mut vault = make_vault(&path);
    vault.add_note("long", "body").unwrap();
    let dest = dir.join(format!("{}.rbve", "e".repeat(235)));
    assert_eq!(dest.file_name().unwrap().len(), 240);
    vault.export_encrypted(&dest, "export-pass").unwrap();
    assert!(dest.is_file());
    drop(vault);
    let reopened = Vault::unlock(&path, PASS).unwrap();
    assert!(reopened.list_notes().iter().any(|n| n.title == "long"));
    drop(reopened);
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_utf8_still_saves() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch_dir("nonutf8");
    let path = dir.join(std::ffi::OsStr::from_bytes(b"vault-\xff.rbv"));
    let mut vault = make_vault(&path);
    vault.add_note("bytes", "body").unwrap();
    drop(vault);
    let reopened = Vault::unlock(&path, PASS).unwrap();
    assert!(reopened.list_notes().iter().any(|n| n.title == "bytes"));
    drop(reopened);
    assert_eq!(temp_files(&dir), Vec::<String>::new());
    let _ = fs::remove_dir_all(&dir);
}

/// The mode must come from the create itself, not from a friendly umask. A test
/// process that inherited umask 077 would pass even with the mode removed, so
/// the check runs in a CHILD under umask 000. The child writes a marker, so a
/// filter that matched no test cannot pass vacuously, and the marker's own mode
/// proves the child really ran under umask 000.
#[cfg(unix)]
#[test]
fn the_vault_is_0600_even_under_a_permissive_umask() {
    const CHILD: &str = "PATANYX_VAULT_UMASK_CHILD";
    const NAME: &str = "writer_tests::the_vault_is_0600_even_under_a_permissive_umask";
    if let Some(dir) = std::env::var_os(CHILD) {
        let dir = PathBuf::from(dir);
        let path = dir.join("vault.rbv");
        let mut vault = make_vault(&path);
        vault.add_note("umask", "body").unwrap();
        let backup = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("vault.rbv.bak-")
            })
            .expect("the save took a backup");
        let export = dir.join("passwords.json");
        vault
            .export_plaintext(&export, PLAINTEXT_EXPORT_CONFIRMATION)
            .unwrap();
        for file in [&path, &backup, &export] {
            let mode = mode_of(file);
            assert_eq!(
                mode,
                0o600,
                "under umask 000 {} was {mode:o}",
                file.display()
            );
        }
        drop(vault);
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
    let marker = dir.join("child-ran");
    assert!(marker.exists(), "the child never ran the check");
    assert_eq!(
        mode_of(&marker),
        0o666,
        "the child did not run under umask 000"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The plaintext export writes straight into the chosen file (since 1.0.3):
// no temporary file of any kind, so an interrupted export
// can never leave passwords under a hidden name.
// ---------------------------------------------------------------------------

use crate::backup::{PlainFault, PlainHooks};

/// A vault in `dir` holding one credential whose password is `SECRET`.
const SECRET: &str = "export-secret-7f3a";

fn vault_with_secret(dir: &Path) -> Vault {
    let mut vault = make_vault(&dir.join("vault.rbv"));
    vault
        .add_credential("example.com", Some("example.com"), "alice", SECRET, "")
        .unwrap();
    vault
}

/// Every name in `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    out.sort();
    out
}

fn hooks(fault: PlainFault) -> PlainHooks<'static> {
    PlainHooks {
        fault,
        ..PlainHooks::default()
    }
}

#[test]
fn a_plaintext_export_writes_only_the_chosen_file() {
    let dir = scratch_dir("plain-only");
    let vault = vault_with_secret(&dir);
    let before = names_in(&dir);
    let dest = dir.join("passwords.json");
    vault
        .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();
    let mut expected = before;
    expected.push("passwords.json".to_string());
    expected.sort();
    assert_eq!(
        names_in(&dir),
        expected,
        "the export left another name behind"
    );
    assert!(fs::read_to_string(&dest).unwrap().contains(SECRET));
    #[cfg(unix)]
    assert_eq!(mode_of(&dest), 0o600);
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_plaintext_export_replaces_an_existing_file() {
    let dir = scratch_dir("plain-replace");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    fs::write(&dest, b"the previous export").unwrap();
    vault
        .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();
    let text = fs::read_to_string(&dest).unwrap();
    assert!(text.contains(SECRET));
    assert!(!text.contains("the previous export"));
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_export_name_is_replaced_not_followed() {
    use std::os::unix::fs::symlink;
    let dir = scratch_dir("plain-link");
    let outside = scratch_dir("plain-link-outside");
    let victim = outside.join("victim");
    fs::write(&victim, b"do not touch").unwrap();
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    symlink(&victim, &dest).unwrap();
    vault
        .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"do not touch",
        "the export followed the link"
    );
    let meta = fs::symlink_metadata(&dest).unwrap();
    assert!(
        meta.file_type().is_file(),
        "the link was not replaced by a file"
    );
    assert!(fs::read_to_string(&dest).unwrap().contains(SECRET));
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&outside);
}

#[cfg(unix)]
#[test]
fn a_hard_link_at_the_export_name_keeps_its_other_name() {
    let dir = scratch_dir("plain-hardlink");
    let vault = vault_with_secret(&dir);
    let other = dir.join("other.txt");
    fs::write(&other, b"keep me").unwrap();
    let dest = dir.join("passwords.json");
    fs::hard_link(&other, &dest).unwrap();
    vault
        .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();
    assert_eq!(
        fs::read(&other).unwrap(),
        b"keep me",
        "the export wrote through a hard link"
    );
    assert!(fs::read_to_string(&dest).unwrap().contains(SECRET));
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_folder_at_the_export_name_is_refused() {
    let dir = scratch_dir("plain-folder");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    fs::create_dir(&dest).unwrap();
    let result = vault.export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION);
    assert!(matches!(result, Err(ExportError::Io(_))), "got {result:?}");
    assert!(dest.is_dir());
    assert!(
        fs::read_dir(&dest).unwrap().next().is_none(),
        "something was written into the folder"
    );
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_plaintext_export_creates_missing_folders() {
    let dir = scratch_dir("plain-nested");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("new").join("deeper").join("passwords.json");
    vault
        .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
        .unwrap();
    assert!(fs::read_to_string(&dest).unwrap().contains(SECRET));
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

/// R-043: a parent that does not exist yet could not be resolved, so the
/// live-vault check fell through and `newdir/../vault.rbv` reached the vault.
#[test]
fn a_path_through_a_missing_folder_to_the_live_vault_is_refused() {
    let dir = scratch_dir("plain-traversal");
    let vault = vault_with_secret(&dir);
    let path = dir.join("vault.rbv");
    let before = fs::read(&path).unwrap();
    let plain = dir.join("missing-a").join("..").join("vault.rbv");
    let result = vault.export_plaintext(&plain, PLAINTEXT_EXPORT_CONFIRMATION);
    assert!(
        matches!(result, Err(ExportError::TargetIsLiveVault)),
        "plaintext: got {result:?}"
    );
    let sealed = dir.join("missing-b").join("..").join("vault.rbv");
    let result = vault.export_encrypted(&sealed, "export-pass");
    assert!(
        matches!(result, Err(ExportError::TargetIsLiveVault)),
        "encrypted: got {result:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), before, "the live vault changed");
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

/// R-042: a failure wipes the export's OWN file through its handle and deletes
/// nothing by name.
#[test]
fn a_failed_plaintext_export_wipes_its_own_file() {
    for fault in [PlainFault::Write, PlainFault::Sync] {
        let dir = scratch_dir("plain-fail");
        let vault = vault_with_secret(&dir);
        let dest = dir.join("passwords.json");
        let result =
            vault.export_plaintext_with(&dest, PLAINTEXT_EXPORT_CONFIRMATION, &hooks(fault));
        assert!(
            matches!(result, Err(ExportError::Io(_))),
            "{fault:?}: got {result:?}"
        );
        assert_eq!(
            fs::read(&dest).unwrap().len(),
            0,
            "{fault:?}: the failed export left plaintext in its file"
        );
        assert_eq!(temp_files(&dir), Vec::<String>::new());
        drop(vault);
        let _ = fs::remove_dir_all(&dir);
    }
}

/// R-044: when even the wipe fails, the error says plaintext may remain.
#[test]
fn a_failed_wipe_reports_that_plaintext_may_remain() {
    let dir = scratch_dir("plain-wipe-fail");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    let result = vault.export_plaintext_with(
        &dest,
        PLAINTEXT_EXPORT_CONFIRMATION,
        &hooks(PlainFault::WriteAndWipe),
    );
    assert!(
        matches!(result, Err(ExportError::PlaintextMayRemain)),
        "got {result:?}"
    );
    assert!(
        !fs::read(&dest).unwrap().is_empty(),
        "precondition: part of the export was written"
    );
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

/// R-042: if the name now belongs to another export, the failed one leaves it
/// alone and wipes only the file it created (which moved with its handle).
#[cfg(unix)]
#[test]
fn a_failed_export_never_touches_a_file_that_replaced_it() {
    let dir = scratch_dir("plain-owner");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    let moved = dir.join("moved.json");
    let replace = |d: &Path| {
        fs::rename(d, &moved).unwrap();
        fs::write(d, b"another export").unwrap();
    };
    let result = vault.export_plaintext_with(
        &dest,
        PLAINTEXT_EXPORT_CONFIRMATION,
        &PlainHooks {
            fault: PlainFault::Write,
            after_create: Some(&replace),
            ..PlainHooks::default()
        },
    );
    assert!(matches!(result, Err(ExportError::Io(_))), "got {result:?}");
    assert_eq!(
        fs::read(&dest).unwrap(),
        b"another export",
        "the failed export touched the other file"
    );
    assert_eq!(
        fs::read(&moved).unwrap().len(),
        0,
        "the failed export's own file was not wiped"
    );
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

/// A file that appears between clearing the name and creating it is left
/// alone: `create_new` refuses it.
#[test]
fn a_file_that_appears_before_creation_is_left_alone() {
    let dir = scratch_dir("plain-race");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    let appear = |d: &Path| fs::write(d, b"appeared meanwhile").unwrap();
    let result = vault.export_plaintext_with(
        &dest,
        PLAINTEXT_EXPORT_CONFIRMATION,
        &PlainHooks {
            after_clear: Some(&appear),
            ..PlainHooks::default()
        },
    );
    assert!(
        matches!(&result, Err(ExportError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
        "got {result:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"appeared meanwhile");
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

/// A real process death part-way through the export. Afterwards the folder
/// holds nothing new except the chosen name, holding a partial export.
#[cfg(unix)]
#[test]
fn a_process_death_mid_export_leaves_only_the_chosen_file() {
    const CHILD: &str = "PATANYX_VAULT_EXPORT_ABORT_CHILD";
    const NAME: &str = "writer_tests::a_process_death_mid_export_leaves_only_the_chosen_file";
    if let Some(dir) = std::env::var_os(CHILD) {
        let dir = PathBuf::from(dir);
        let vault = Vault::unlock(&dir.join("vault.rbv"), PASS).unwrap();
        fs::write(dir.join("child-started"), b"yes").unwrap();
        let _ = vault.export_plaintext_with(
            &dir.join("passwords.json"),
            PLAINTEXT_EXPORT_CONFIRMATION,
            &hooks(PlainFault::Abort),
        );
        unreachable!("the injected abort did not stop the process");
    }
    let dir = scratch_dir("plain-abort");
    drop(vault_with_secret(&dir));
    let before = names_in(&dir);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
        .env(CHILD, &dir)
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "the child was supposed to die mid-export"
    );
    assert!(
        dir.join("child-started").exists(),
        "the child never reached the export"
    );
    let mut expected = before;
    expected.push("child-started".to_string());
    expected.push("passwords.json".to_string());
    expected.sort();
    assert_eq!(
        names_in(&dir),
        expected,
        "the dead export left another name behind"
    );
    let partial = fs::read(dir.join("passwords.json")).unwrap();
    assert!(
        !partial.is_empty(),
        "the child died before writing anything"
    );
    assert!(
        serde_json::from_slice::<serde_json::Value>(&partial).is_err(),
        "the export was complete, so this did not test a death part-way"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Review R-045: a folder on the way to `dest` is swapped for a link to the
/// vault's own folder after the check. The re-check before the unlink refuses,
/// and the live vault is untouched.
#[cfg(unix)]
#[test]
fn a_folder_swapped_to_the_vault_after_the_check_is_refused() {
    use std::os::unix::fs::symlink;
    let dir = scratch_dir("plain-swap");
    let elsewhere = scratch_dir("plain-swap-elsewhere");
    let vault = vault_with_secret(&dir);
    let path = dir.join("vault.rbv");
    let before = fs::read(&path).unwrap();
    let link = elsewhere.join("via");
    let export_dir = elsewhere.join("exports");
    fs::create_dir(&export_dir).unwrap();
    symlink(&export_dir, &link).unwrap();
    let dest = link.join("vault.rbv");
    let swap = |_: &Path| {
        fs::remove_file(&link).unwrap();
        symlink(&dir, &link).unwrap();
    };
    let result = vault.export_plaintext_with(
        &dest,
        PLAINTEXT_EXPORT_CONFIRMATION,
        &PlainHooks {
            after_prepare: Some(&swap),
            ..PlainHooks::default()
        },
    );
    assert!(
        matches!(result, Err(ExportError::TargetIsLiveVault)),
        "got {result:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), before, "the live vault changed");
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&elsewhere);
}

/// Review R-046: a vault unlocked through a symlink that is then removed can no
/// longer be resolved; exporting onto its real file is refused, not allowed.
#[cfg(unix)]
#[test]
fn an_unresolvable_vault_path_refuses_the_export() {
    use std::os::unix::fs::symlink;
    let dir = scratch_dir("plain-unresolved");
    let real = dir.join("vault.rbv");
    drop(vault_with_secret(&dir));
    let before = fs::read(&real).unwrap();
    let alias = dir.join("alias.rbv");
    symlink(&real, &alias).unwrap();
    let vault = Vault::unlock(&alias, PASS).unwrap();
    fs::remove_file(&alias).unwrap();
    let result = vault.export_plaintext(&real, PLAINTEXT_EXPORT_CONFIRMATION);
    assert!(
        result.is_err(),
        "the export onto the real vault file went ahead"
    );
    assert_eq!(fs::read(&real).unwrap(), before, "the live vault changed");
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}

/// Review R-048: another file replaced the name, then the failed export could
/// not wipe its own file. The error says plaintext may remain, and the other
/// file is still untouched.
#[cfg(unix)]
#[test]
fn a_failed_wipe_after_a_replacement_leaves_the_other_file_alone() {
    let dir = scratch_dir("plain-owner-wipe");
    let vault = vault_with_secret(&dir);
    let dest = dir.join("passwords.json");
    let moved = dir.join("moved.json");
    let replace = |d: &Path| {
        fs::rename(d, &moved).unwrap();
        fs::write(d, b"another export").unwrap();
    };
    let result = vault.export_plaintext_with(
        &dest,
        PLAINTEXT_EXPORT_CONFIRMATION,
        &PlainHooks {
            fault: PlainFault::WriteAndWipe,
            after_create: Some(&replace),
            ..PlainHooks::default()
        },
    );
    assert!(
        matches!(result, Err(ExportError::PlaintextMayRemain)),
        "got {result:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"another export");
    assert!(
        !fs::read(&moved).unwrap().is_empty(),
        "precondition: the moved file was not wiped"
    );
    drop(vault);
    let _ = fs::remove_dir_all(&dir);
}
