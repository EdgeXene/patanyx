use super::*;

#[test]
fn every_action_has_its_documented_gate() {
    use Action::*;
    for action in [
        List, Refresh, Inspect, Open, Install, Check, Update, Rollback, Remove, Export, Delete,
    ] {
        for entitled in [false, true] {
            assert_eq!(
                gate(action, true, entitled, true),
                Err("busy"),
                "{action:?}"
            );
            assert_eq!(
                gate(action, false, entitled, false),
                if action == Remove {
                    Ok(())
                } else {
                    Err("not_unlocked")
                }
            );
            let paid = matches!(action, Install | Check | Update | Rollback);
            assert_eq!(
                gate(action, true, entitled, false),
                if paid && !entitled {
                    Err("premium_required")
                } else {
                    Ok(())
                },
                "{action:?}"
            );
        }
    }
}

#[test]
fn addon_install_requires_premium_at_admission_and_commit() {
    assert_eq!(
        gate(Action::Install, true, false, false),
        Err("premium_required")
    );
    assert!(!authorize(Action::Install, false));
    assert!(authorize(Action::Install, true));
}
#[test]
fn addon_update_requires_premium_at_admission_and_commit() {
    assert_eq!(
        gate(Action::Update, true, false, false),
        Err("premium_required")
    );
    assert!(!authorize(Action::Update, false));
    assert!(authorize(Action::Update, true));
}

#[test]
fn delete_waits_for_quiescence_without_blocking_the_caller() {
    // The session is gone but its writer still owns a quiet token. This is
    // the deadline-expiry case that checking just the window misses.
    let quiet = Arc::new(());
    let worker = quiet.clone();
    let quiescent = || Arc::strong_count(&quiet) == 1;
    let started = std::time::Instant::now();
    assert!(
        wait_for_quiescence(Action::Delete, quiescent()),
        "deletion began before the writer stopped"
    );
    assert!(started.elapsed() < std::time::Duration::from_millis(33));
    drop(worker);
    assert!(!wait_for_quiescence(Action::Delete, quiescent()));
    for action in [
        Action::Update,
        Action::Remove,
        Action::Export,
        Action::Rollback,
    ] {
        assert!(wait_for_quiescence(action, false));
    }
    let source = include_str!("main.rs");
    for event in [
        "AddonIpc {",
        "AddonStorageDone {",
        "AddonFlushDeadline {",
        "AddonWorkerQuiet)",
    ] {
        let start = source
            .find(&format!("Event::UserEvent(UserEvent::{event}"))
            .unwrap();
        let end = source[start..].find("\n            }").unwrap() + start;
        assert!(
            source[start..end].contains("addon_manager::resume(&mut app)"),
            "{event} never resumes deletion"
        );
    }
}

#[test]
fn manager_open_serves_only_verified_memory_and_lapse_is_read_only() {
    let source = include_str!("addon_manager.rs");
    let worker = source.find("std::thread::spawn(move ||").unwrap();
    let read = source.find("addon_install::installed_bundle(&id)").unwrap();
    assert!(worker < read);
    assert!(source.contains("Arc::new(bytes.clone())"));
    assert_eq!(open_mode(false), addon_host::Mode::ReadOnly);
    assert_eq!(open_mode(true), addon_host::Mode::Full);
    // Shown in Windows builds; on Linux only in a qualification build, which
    // carries its marker.
    assert_eq!(MANAGER_VISIBLE, cfg!(any(windows, feature = "addon-launch")));
    let switch = source.split("pub(crate) const MANAGER_VISIBLE: bool = ").nth(1).unwrap();
    assert!(switch.starts_with("cfg!(any(windows, feature = \"addon-launch\"));"), "the release switch moved");
}

/// A script beside the crates, read when the test runs rather than compiled
/// in: the licence planted-defect gate builds the app from a copy of
/// `crates/` alone, and must not need `scripts/` to compile.
fn script(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn a_qualification_build_says_so_and_a_release_build_does_not() {
    let status = include_str!("addon_manager.rs");
    assert!(status.contains("\"test_build\": test_build()"));
    assert_eq!(test_build().is_null(), !cfg!(feature = "addon-launch"));
    // The build scripts refuse exactly this marker in a public build.
    let marker = status.split("LAUNCH_TEST_MARKER: &str = \"").nth(1).unwrap().split('"').next().unwrap();
    assert!(script("build-windows.sh").contains(marker));
    assert!(script("build-flatpak.sh").contains(marker));
    // And the one list every Linux release check reads.
    assert!(script("forbidden-build-markers.py").contains(marker));
}

#[test]
fn manager_has_one_premium_seam_and_fresh_cancellation() {
    let source = include_str!("addon_manager.rs");
    // One seam, and it is the live decision (today's date and activation).
    assert_eq!(source.matches("crate::addon_entitlement::current()").count(), 1);
    assert_eq!(source.matches("premium_active()").count(), 0);
    assert!(source.contains("cancel: Cancellation::new()"));
    assert!(source.contains(".activate(prepared, &cancel, authorize)"));
    assert!(!source.contains("thread::sleep"));
    assert_eq!(Reason::DeleteData.name(), "delete_data");
    assert_eq!(Reason::AddonUpdate.name(), "addon_update");
    assert_eq!(Reason::AddonRemove.name(), "addon_remove");
}

#[test]
fn public_data_requires_unlock_in_every_premium_state() {
    for action in [Action::Export, Action::Delete] {
        for premium in [false, true] {
            assert_eq!(gate(action, false, premium, false), Err("not_unlocked"));
            assert_eq!(gate(action, true, premium, false), Ok(()));
        }
    }
}

#[test]
fn revoked_entitlement_cannot_publish_install_or_update() {
    use crate::addon_testkit::{package, prepare, store, ID};
    let (temp, install) = store();
    let first = package("1.0.0", "first");
    let cancel = Cancellation::new();
    let active = temp
        .path()
        .join("updates/addon-code")
        .join(ID)
        .join("active.json");
    assert_eq!(
        install.activate(prepare(&install, 1, &first, None), &cancel, || authorize(
            Action::Install,
            false
        )),
        Err(InstallError::Unauthorized)
    );
    assert!(!active.exists());
    install
        .activate(prepare(&install, 1, &first, None), &cancel, || {
            authorize(Action::Install, true)
        })
        .unwrap();
    let before = std::fs::read(&active).unwrap();
    let second = package("2.0.0", "second");
    assert_eq!(
        install.activate(prepare(&install, 2, &second, Some(&first)), &cancel, || {
            authorize(Action::Update, false)
        }),
        Err(InstallError::Unauthorized)
    );
    assert_eq!(std::fs::read(&active).unwrap(), before);
    let cancelled = Cancellation::new();
    cancelled.cancel();
    assert_eq!(
        install.activate(
            prepare(&install, 2, &second, Some(&first)),
            &cancelled,
            || authorize(Action::Update, true)
        ),
        Err(InstallError::Cancelled)
    );
    assert_eq!(std::fs::read(&active).unwrap(), before);
}

#[test]
fn served_bundle_owns_the_verified_bytes() {
    use crate::addon_testkit::{index, package, sign, store, ID};
    let (_temp, install) = store();
    let mut package = package("1.0.0", "verified bytes");
    let envelope = sign(
        &index(1, &package, None),
        patanyx_update::addon::SIGNING_DOMAIN_ADDON_INDEX,
    );
    let index = install.accept_index(ID, &envelope, 2).unwrap();
    let bundle = install
        .verify_package(
            &index,
            index.current(),
            package.manifest.clone(),
            package.files.clone(),
        )
        .unwrap();
    let served = served(bundle);
    package.files.get_mut("index.html").unwrap().fill(0);
    assert_eq!(served.id, ID);
    assert_eq!(served.name, "Test pages");
    assert_eq!(served.version, "1.0.0");
    assert_eq!(
        &**served.files.get("index.html").unwrap(),
        b"verified bytes"
    );
}

#[test]
fn the_catalog_throttle_counts_failures_and_honours_retry_after() {
    let now = Instant::now();
    // Never without Premium; at once the first time; not before the moment.
    assert!(!catalog_due(false, None, now));
    assert!(catalog_due(true, None, now));
    assert!(!catalog_due(true, Some(now + Duration::from_secs(1)), now));
    assert!(catalog_due(true, Some(now), now));
    assert_eq!(catalog_wait(&Ok(())), Duration::from_secs(600));
    assert_eq!(catalog_wait(&Err(("network", None))), Duration::from_secs(60));
    assert_eq!(catalog_wait(&Err(("rate_limited", Some(5)))), Duration::from_secs(60));
    assert_eq!(catalog_wait(&Err(("rate_limited", Some(300)))), Duration::from_secs(300));
    assert_eq!(catalog_wait(&Err(("rate_limited", Some(u64::MAX)))), Duration::from_secs(3600));
    // The next moment is pushed out when the job is admitted, not when it ends.
    let source = include_str!("addon_manager.rs");
    let admit = source.split("fn start_inner(").nth(1).unwrap().split("fn resume(").next().unwrap();
    assert!(admit.contains("catalog_next = Some(now + CATALOG_AFTER_FAILURE)"));
}

#[test]
fn the_panels_name_only_verified_add_ons_and_offer_updates_by_version() {
    use crate::addon_testkit::{catalog, keys};
    let held = patanyx_update::verify_addon_catalog(
        &catalog(1, &[("text-pages", "Test pages", "2.0.0"), ("other-tool", "Other", "1.0.0")]),
        &keys(),
    )
    .unwrap();
    let mut view = View { catalog: held.addons().to_vec(), catalog_expires: Some(held.expires_at()), installed: BTreeMap::new() };
    view.installed.insert(
        "text-pages".into(),
        InstalledSummary { name: "Installed name".into(), version: "1.0.0".into(), rollback: Some("0.9.0".into()) },
    );
    view.installed.insert(
        "gone-addon".into(),
        InstalledSummary { name: "No longer listed".into(), version: "1.0.0".into(), rollback: None },
    );
    let known = known(&view);
    let ids: Vec<&str> = known.iter().map(|k| k["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["text-pages", "other-tool", "gone-addon"]);
    // The catalog's name wins; an update is offered by version, not by text.
    assert_eq!(known[0]["name"], "Test pages");
    assert_eq!(known[0]["installed"], true);
    assert_eq!(known[0]["version"], "1.0.0");
    assert_eq!(known[0]["available"], "2.0.0");
    assert_eq!(known[0]["rollback"], "0.9.0");
    assert_eq!(known[0]["update"], true);
    assert_eq!(known[1]["installed"], false);
    assert_eq!(known[1]["update"], false);
    assert_eq!(known[1]["size"], 10);
    // Installed but no longer in the catalog: named from its manifest.
    assert_eq!(known[2]["name"], "No longer listed");
    assert!(known[2]["summary"].is_null());
    // Same version installed: no update.
    view.installed.get_mut("text-pages").unwrap().version = "2.0.0".into();
    assert_eq!(super::known(&view)[0]["update"], false);
}

#[test]
fn an_expired_catalog_is_told_apart_from_a_forged_one() {
    let expired = DeliveryError::Install(InstallError::ExpiredCatalog);
    assert_eq!(catalog_failure(&expired).0, "catalog_expired");
    assert_eq!(catalog_failure(&DeliveryError::Install(InstallError::Integrity)).0, "catalog_invalid");
    assert_eq!(catalog_failure(&DeliveryError::Response).0, "catalog_invalid");
    assert_eq!(catalog_failure(&DeliveryError::Transport).0, "network");
}

#[test]
fn a_held_catalog_is_stale_from_its_end_date() {
    assert!(!catalog_stale(None, Some(100)), "no catalog is not a stale one");
    assert!(!catalog_stale(Some(200), Some(199)));
    assert!(catalog_stale(Some(200), Some(200)));
    assert!(catalog_stale(Some(200), Some(201)));
    assert!(catalog_stale(Some(200), None), "an unreadable clock counts as past the end");
}

#[test]
fn an_older_view_read_never_replaces_a_newer_one() {
    let mut m = Manager::default();
    let named = |name: &str| {
        let mut v = View::default();
        v.installed.insert("text-pages".into(), InstalledSummary { name: name.into(), version: "1.0.0".into(), rollback: None });
        v
    };
    apply_view(&mut m, 2, named("after the job"));
    apply_view(&mut m, 1, named("start-up read"));
    assert_eq!(m.view.installed["text-pages"].name, "after the job");
}

#[test]
fn an_empty_catalog_counts_as_none_held_only_once_a_read_has_landed() {
    let mut m = Manager::default();
    assert!(!view_landed(&m), "before the start-up read, nothing is known");
    apply_view(&mut m, 1, View::default());
    assert!(view_landed(&m), "a read that found no catalog has still landed");
    assert!(m.view.catalog.is_empty());
}
