use super::*;
use crate::addon_testkit::*;

#[test]
fn addon_install_update_rollback_uninstall_preserves_pages() {
    let (temp, store) = store();
    let cancel = Cancellation::new();
    let data = temp.path().join("library/addons/text-pages");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("page.enc"), b"opaque page data").unwrap();
    let old = package("1.0.0", "old");
    let new = package("2.0.0", "new");
    store
        .activate(prepare(&store, 1, &old, None), &cancel, || true)
        .unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"old".as_slice())
    );
    store
        .activate(prepare(&store, 2, &new, Some(&old)), &cancel, || true)
        .unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"new".as_slice())
    );
    store.rollback(ID, &cancel, || true).unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"old".as_slice())
    );
    store.uninstall(ID, &cancel, || true).unwrap();
    assert!(matches!(store.open(ID), Err(InstallError::NotInstalled)));
    assert_eq!(
        fs::read(data.join("page.enc")).unwrap(),
        b"opaque page data"
    );
    assert!(store.root.join(ID).join("index.sig.json").exists());
    let stale = sign(&index(1, &old, None), SIGNING_DOMAIN_ADDON_INDEX);
    assert_eq!(
        store.accept_index(ID, &stale, now().unwrap()).unwrap_err(),
        InstallError::StaleIndex
    );
}

#[test]
fn addon_stale_index_is_persistent() {
    let (temp, store) = store();
    let p = package("1.0.0", "ok");
    let bytes = sign(&index(8, &p, None), SIGNING_DOMAIN_ADDON_INDEX);
    store.accept_index(ID, &bytes, 10).unwrap();
    store.accept_index(ID, &bytes, 10).unwrap();
    let reopened = InstallStore::test_store(temp.path().join("updates/addon-code"), keys());
    let stale = sign(&index(7, &p, None), SIGNING_DOMAIN_ADDON_INDEX);
    assert_eq!(
        reopened.accept_index(ID, &stale, 10).unwrap_err(),
        InstallError::StaleIndex
    );
    let mut changed = index(8, &p, None);
    changed["issued_at"] = serde_json::json!(2);
    assert_eq!(
        reopened
            .accept_index(ID, &sign(&changed, SIGNING_DOMAIN_ADDON_INDEX), 10)
            .unwrap_err(),
        InstallError::StaleIndex
    );
    fs::write(store.root.join(ID).join("index.sig.json"), b"broken").unwrap();
    assert!(reopened.accept_index(ID, &bytes, 10).is_err());
}

#[test]
fn addon_open_reverifies_and_install_never_activates_unverified() {
    let (_temp, store) = store();
    let p = package("1.0.0", "old");
    let cancel = Cancellation::new();
    store
        .activate(prepare(&store, 1, &p, None), &cancel, || true)
        .unwrap();
    let active = fs::read(store.root.join(ID).join("active.json")).unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"old".as_slice())
    );
    let next = package("2.0.0", "new");
    let mut damaged = prepare(&store, 2, &next, Some(&p));
    // Model a staging corruption after network verification. No production API
    // exposes this mutation; the assertion checks the storage commit ordering.
    damaged
        .selected
        .files
        .insert("index.html".into(), b"bad".to_vec());
    assert!(store.activate(damaged, &cancel, || true).is_err());
    assert_eq!(
        fs::read(store.root.join(ID).join("active.json")).unwrap(),
        active
    );
    let record = store.active(&store.root.join(ID)).unwrap();
    let file = store
        .root
        .join(ID)
        .join("releases")
        .join(record.manifest)
        .join("files/index.html");
    fs::write(&file, b"bad").unwrap();
    assert!(store.open(ID).is_err());
}

#[test]
fn addon_activation_rechecks_session_index_and_expiry() {
    let (_temp, store) = store();
    let p = package("1.0.0", "old");
    let cancel = Cancellation::new();
    store
        .activate(prepare(&store, 1, &p, None), &cancel, || true)
        .unwrap();
    let new = package("2.0.0", "new");
    let prepared = prepare(&store, 2, &new, Some(&p));
    assert_eq!(
        store.activate(prepared, &cancel, || false),
        Err(InstallError::Unauthorized)
    );
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"old".as_slice())
    );
    let prepared = prepare(&store, 2, &new, Some(&p));
    let newer = sign(&index(3, &new, Some(&p)), SIGNING_DOMAIN_ADDON_INDEX);
    store.accept_index(ID, &newer, now().unwrap()).unwrap();
    assert_eq!(
        store.activate(prepared, &cancel, || true),
        Err(InstallError::StaleIndex)
    );
    let prepared = prepare(&store, 3, &new, Some(&p));
    cancel.cancel();
    assert_eq!(
        store.activate(prepared, &cancel, || true),
        Err(InstallError::Cancelled)
    );
    let mut expired = index(4, &new, Some(&p));
    expired["expires_at"] = serde_json::json!(2);
    assert_eq!(
        store
            .accept_index(ID, &sign(&expired, SIGNING_DOMAIN_ADDON_INDEX), 2)
            .unwrap_err(),
        InstallError::ExpiredIndex
    );
    // Opening uses the saved authorization without a live-index freshness gate.
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"old".as_slice())
    );
}

#[test]
fn addon_disk_paths_refuse_missing_extra_and_linked_assets() {
    let (_temp, store) = store();
    let p = package("1.0.0", "hello");
    store
        .activate(prepare(&store, 1, &p, None), &Cancellation::new(), || true)
        .unwrap();
    let dir = store.root.join(ID);
    let record = store.active(&dir).unwrap();
    let assets = dir.join("releases").join(record.manifest).join("files");
    fs::write(assets.join("extra.js"), b"unexpected").unwrap();
    assert!(store.open(ID).is_err());
    fs::remove_file(assets.join("extra.js")).unwrap();
    fs::remove_file(assets.join("index.html")).unwrap();
    assert!(store.open(ID).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(assets.join("assets/main.js"), assets.join("index.html"))
            .unwrap();
        assert!(store.open(ID).is_err());
    }
}

#[test]
fn addon_install_storage_failure_boundaries_keep_previous_active() {
    for boundary in [
        "before_stage",
        "file_written",
        "metadata_written",
        "stage_verified",
        "stage_renamed",
        "before_activate",
    ] {
        let (_temp, store) = store();
        let old = package("1.0.0", "old");
        let new = package("2.0.0", "new");
        let cancel = Cancellation::new();
        store
            .activate(prepare(&store, 1, &old, None), &cancel, || true)
            .unwrap();
        let prepared = prepare(&store, 2, &new, Some(&old));
        store.fail_at.set(Some(boundary));
        assert_eq!(
            store.activate(prepared, &cancel, || true),
            Err(InstallError::Io),
            "{boundary}"
        );
        store.fail_at.set(None);
        assert_eq!(
            store.open(ID).unwrap().file("index.html"),
            Some(b"old".as_slice()),
            "{boundary}"
        );
        store
            .activate(prepare(&store, 2, &new, Some(&old)), &cancel, || true)
            .unwrap();
        assert_eq!(
            store.open(ID).unwrap().file("index.html"),
            Some(b"new".as_slice())
        );
    }
}

#[test]
fn addon_offline_open_allows_expired_authorization_but_rollback_needs_current_index() {
    let (_temp, store) = store();
    let p = package("1.0.0", "hello");
    let cancel = Cancellation::new();
    store
        .activate(prepare(&store, 1, &p, None), &cancel, || true)
        .unwrap();
    let dir = store.root.join(ID);
    let record = store.active(&dir).unwrap();
    let mut expired = index(1, &p, None);
    expired["expires_at"] = serde_json::json!(2);
    // A still-authentic authorization whose lifetime has elapsed. No secret or
    // new trust key is installed; this exercises the exact open verification.
    fs::write(
        dir.join("releases")
            .join(record.manifest)
            .join("authorization.sig.json"),
        sign(&expired, SIGNING_DOMAIN_ADDON_INDEX),
    )
    .unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"hello".as_slice())
    );
    assert_eq!(
        store.rollback(ID, &cancel, || true),
        Err(InstallError::Unauthorized)
    );
}

#[test]
fn addon_host_entry_point_does_not_fall_back_to_test_keys() {
    // The entry point builds its store from ADDON_KEYS alone (the test key is
    // not among them: `updater::addon_key_tests`), so it is configured, and
    // nothing a test installed with the test key is visible through it.
    assert!(InstallStore::production().is_ok());
    assert!(!matches!(installed_bundle(ID), Ok(_)));
}

#[test]
fn addon_reinstall_replaces_a_release_damaged_on_disk() {
    let (_temp, store) = store();
    let p = package("1.0.0", "good");
    let cancel = Cancellation::new();
    store
        .activate(prepare(&store, 1, &p, None), &cancel, || true)
        .unwrap();
    let record = store.active(&store.root.join(ID)).unwrap();
    let files = store
        .root
        .join(ID)
        .join("releases")
        .join(record.manifest)
        .join("files");
    // A scanner removed one file: the copy no longer opens...
    fs::remove_file(files.join("index.html")).unwrap();
    assert!(store.open(ID).is_err());
    // ...and installing the same release again repairs it.
    store
        .activate(prepare(&store, 1, &p, None), &cancel, || true)
        .unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"good".as_slice())
    );
}

#[cfg(unix)]
#[test]
fn addon_install_works_under_a_linked_home_folder() {
    // As on Linux systems where /home is a link: links above the install
    // root are the person's own folders, not the add-on's.
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("var-home");
    fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, temp.path().join("home")).unwrap();
    let store = InstallStore::test_store(temp.path().join("home/updates/addon-code"), keys());
    let p = package("1.0.0", "linked");
    store
        .activate(prepare(&store, 1, &p, None), &Cancellation::new(), || true)
        .unwrap();
    assert_eq!(
        store.open(ID).unwrap().file("index.html"),
        Some(b"linked".as_slice())
    );
    // A link inside the add-on's own folder is still refused.
    let releases = store.root.join(ID).join("releases");
    let record = store.active(&store.root.join(ID)).unwrap();
    let package_dir = releases.join(&record.manifest);
    let moved = temp.path().join("elsewhere");
    fs::rename(&package_dir, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &package_dir).unwrap();
    assert!(store.open(ID).is_err());
}

#[cfg(unix)]
#[test]
fn addon_install_folders_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, store) = store();
    let p = package("1.0.0", "x");
    store
        .activate(prepare(&store, 1, &p, None), &Cancellation::new(), || true)
        .unwrap();
    for dir in [store.root.clone(), store.root.join(ID), store.root.join(ID).join("releases")] {
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", dir.display());
    }
}

#[test]
fn a_lock_still_held_is_busy_after_a_short_wait() {
    let (_temp, store) = store();
    let held = store.lock(ID).unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(store.lock(ID), Err(InstallError::Busy)));
    assert!(started.elapsed() >= std::time::Duration::from_millis(400), "busy was called without the wait");
    drop(held);
    assert!(store.lock(ID).is_ok(), "a released lock was still busy");
}

#[test]
fn a_lock_released_during_the_wait_is_taken() {
    let (_temp, store) = store();
    let held = store.lock(ID).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(held);
    });
    // Asked while it is still held: the call waits and takes it once released.
    assert!(store.lock(ID).is_ok(), "a lock released during the wait was reported busy");
    release.join().unwrap();
}

#[test]
fn a_catalog_is_kept_only_when_newer_and_shown_after_it_expires() {
    let (_temp, store) = store();
    assert_eq!(store.saved_catalog().unwrap(), None);
    let first = catalog(3, &[(ID, "Test pages", "1.0.0")]);
    let held = store.accept_catalog(&first, now().unwrap()).unwrap();
    assert_eq!(store.saved_catalog().unwrap(), Some(held.clone()));
    // The same bytes again are a repeat, not a regression.
    store.accept_catalog(&first, now().unwrap()).unwrap();
    // An older sequence, or the same sequence with other contents, is refused
    // and the held catalog stays.
    for refused in [catalog(2, &[(ID, "Older", "1.0.0")]), catalog(3, &[(ID, "Changed", "1.0.0")])] {
        assert_eq!(store.accept_catalog(&refused, now().unwrap()).unwrap_err(), InstallError::StaleCatalog);
    }
    assert_eq!(store.saved_catalog().unwrap(), Some(held));
    let newer = catalog(4, &[(ID, "Test pages", "2.0.0")]);
    store.accept_catalog(&newer, now().unwrap()).unwrap();
    assert_eq!(store.saved_catalog().unwrap().unwrap().addons()[0].version().to_string(), "2.0.0");
    // A fetched catalog that is no longer valid is refused; the held one is
    // still shown (no time check for display).
    let mut expired: serde_json::Value = serde_json::from_slice(&newer).unwrap();
    let mut payload: serde_json::Value = serde_json::from_str(expired["payload"].as_str().unwrap()).unwrap();
    payload["sequence"] = serde_json::json!(9);
    payload["expires_at"] = serde_json::json!(2);
    let expired_bytes = sign(&payload, SIGNING_DOMAIN_ADDON_CATALOG);
    assert_eq!(store.accept_catalog(&expired_bytes, now().unwrap()).unwrap_err(), InstallError::ExpiredCatalog);
    assert_eq!(store.saved_catalog().unwrap().unwrap().sequence(), 4);
    // A forged or wrong-domain catalog is never accepted.
    expired["payload"] = serde_json::json!(expired["payload"].as_str().unwrap().replace("Test pages", "Evil"));
    assert!(store.accept_catalog(&serde_json::to_vec(&expired).unwrap(), now().unwrap()).is_err());
    let as_index = sign(&payload, SIGNING_DOMAIN_ADDON_INDEX);
    assert!(store.accept_catalog(&as_index, now().unwrap()).is_err());
    // A saved catalog that was tampered with on disk is not shown.
    fs::write(store.root.join("catalog.sig.json"), b"{}").unwrap();
    assert!(store.saved_catalog().is_err());
}

#[test]
fn the_installed_summary_reads_the_active_manifest_without_the_files() {
    let (_temp, store) = store();
    let cancel = Cancellation::new();
    assert_eq!(store.installed_summary(ID).unwrap(), None);
    assert!(store.installed_ids().is_empty());
    let old = package("1.0.0", "old");
    let new = package("2.0.0", "new");
    store.activate(prepare(&store, 1, &old, None), &cancel, || true).unwrap();
    store.activate(prepare(&store, 2, &new, Some(&old)), &cancel, || true).unwrap();
    assert_eq!(store.installed_ids(), vec![ID.to_string()]);
    let summary = store.installed_summary(ID).unwrap().unwrap();
    assert_eq!(summary.name, "Test pages");
    assert_eq!(summary.version, "2.0.0");
    assert_eq!(summary.rollback.as_deref(), Some("1.0.0"));
    // A damaged FILE does not hide the name (Open is what refuses it) ...
    let dir = store.root.join(ID);
    let record = store.active(&dir).unwrap();
    let release = dir.join("releases").join(&record.manifest);
    fs::write(release.join("files/index.html"), b"tampered").unwrap();
    assert_eq!(store.installed_summary(ID).unwrap().unwrap().version, "2.0.0");
    assert!(store.open(ID).is_err());
    // ... but a manifest that is not the one active.json names is refused.
    fs::write(release.join("manifest.sig.json"), &old.manifest).unwrap();
    assert_eq!(store.installed_summary(ID).unwrap_err(), InstallError::Integrity);
    // An expired saved index still names its rollback for display.
    fs::write(release.join("manifest.sig.json"), &new.manifest).unwrap();
    let mut expired = index(2, &new, Some(&old));
    expired["expires_at"] = serde_json::json!(2);
    fs::write(dir.join("index.sig.json"), sign(&expired, SIGNING_DOMAIN_ADDON_INDEX)).unwrap();
    assert_eq!(store.installed_summary(ID).unwrap().unwrap().rollback.as_deref(), Some("1.0.0"));
    store.uninstall(ID, &cancel, || true).unwrap();
    assert_eq!(store.installed_summary(ID).unwrap(), None);
    assert!(store.installed_ids().is_empty());
    // Folder names that are not add-on ids are never listed.
    fs::create_dir_all(store.root.join("Not An Id")).unwrap();
    fs::write(store.root.join("Not An Id/active.json"), b"{}").unwrap();
    assert!(store.installed_ids().is_empty());
}
