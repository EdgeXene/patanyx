use super::*;
use std::path::PathBuf;

fn test_dir(tag: &str) -> PathBuf {
    let n: [u8; 8] = crypto::random_bytes();
    let dir = std::env::temp_dir().join(format!("patanyx-addon-test-{tag}-{:016x}", u64::from_le_bytes(n)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fresh(tag: &str) -> (PathBuf, Store) {
    let dir = test_dir(tag);
    let store = Store::create_with_params(&dir.join("store.rbs"), "pw", 8192, 1, 1).unwrap();
    (dir, store)
}

const T0: u64 = 1_792_000_000_000;

#[test]
fn a_page_round_trips_and_updates_by_revision() {
    let (dir, store) = fresh("roundtrip");
    let ns = store.addon_namespace("text-pages").unwrap();
    let created = ns.put(None, 0, "First", "hello é".as_bytes(), T0).unwrap();
    assert_eq!(created.revision, 1);
    let (meta, body) = ns.get(&created.id).unwrap();
    assert_eq!((meta.title.as_str(), body.as_slice()), ("First", "hello é".as_bytes()));
    let updated = ns.put(Some(&created.id), 1, "First", b"hello again", T0 + 5).unwrap();
    assert_eq!((updated.revision, updated.created_at_ms, updated.updated_at_ms), (2, T0, T0 + 5));
    // A stale revision is a conflict and changes nothing.
    assert!(matches!(ns.put(Some(&created.id), 1, "x", b"x", T0 + 9), Err(AddonWriteError::Conflict)));
    assert_eq!(ns.get(&created.id).unwrap().1.as_slice(), b"hello again");
    // Exactly one version on disk for the page, plus the index.
    let versions: Vec<_> = ns.blobs.ids().unwrap().into_iter().filter(|i| i.starts_with("p-")).collect();
    assert_eq!(versions, vec![version_id(&created.id, 2)]);
    ns.delete(&created.id, 2).unwrap();
    assert!(ns.list().unwrap().is_empty());
    assert!(ns.blobs.ids().unwrap().iter().all(|i| !i.starts_with("p-")));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_collection_is_chosen_at_creation_and_kept() {
    let (dir, store) = fresh("collection");
    let ns = store.addon_namespace("text-pages").unwrap();
    let note = ns.put_in(None, 0, "Note", b"answer", SiteChange::Keep, Some("assistant"), T0).unwrap();
    assert_eq!(note.collection.as_deref(), Some("assistant"));
    // Every later write keeps it, whatever else changes.
    let edited = ns.put_with_site(Some(&note.id), 1, "Note", b"edited", SiteChange::Set("example.com".into()), T0 + 1).unwrap();
    assert_eq!(edited.collection.as_deref(), Some("assistant"));
    assert_eq!(ns.get(&note.id).unwrap().0.collection.as_deref(), Some("assistant"));
    // An update cannot move a page to another collection, and a bad name is refused.
    assert!(matches!(
        ns.put_in(Some(&note.id), 2, "Note", b"x", SiteChange::Keep, Some("other"), T0 + 2),
        Err(AddonWriteError::InvalidCollection)
    ));
    for bad in ["", "Assistant", "a b", "notes/1", &"x".repeat(ADDON_MAX_COLLECTION_BYTES + 1)] {
        assert!(matches!(
            ns.put_in(None, 0, "N", b"x", SiteChange::Keep, Some(bad), T0),
            Err(AddonWriteError::InvalidCollection)
        ), "{bad:?}");
    }
    // An ordinary page has none, and its record does not mention the field.
    let plain = ns.put(None, 0, "Plain", b"text", T0).unwrap();
    assert_eq!(plain.collection, None);
    assert!(!serde_json::to_string(&plain).unwrap().contains("collection"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn namespaces_and_the_archive_cannot_read_each_other() {
    let (dir, store) = fresh("separation");
    let a = store.addon_namespace("text-pages").unwrap();
    let page = a.put(None, 0, "t", b"secret text", T0).unwrap();
    // The same file, read under another add-on's key and under the
    // archive's key, does not decrypt.
    let b = store.addon_namespace("other-addon").unwrap();
    fs::copy(a.dir.join(&page.version), b.dir.join(&page.version)).unwrap();
    assert!(b.blobs.get(&page.version).is_err());
    let archive = BlobStore::open(&dir.join("archive"), store.data_key()).unwrap();
    fs::copy(a.dir.join(&page.version), dir.join("archive").join(&page.version)).unwrap();
    assert!(archive.get(&page.version).is_err());
    // And nothing on disk holds the plaintext.
    for entry in fs::read_dir(&a.dir).unwrap().flatten() {
        let bytes = fs::read(entry.path()).unwrap();
        assert!(!bytes.windows(11).any(|w| w == b"secret text"));
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_autosave_never_rewrites_the_library_file() {
    let (dir, store) = fresh("no-rbs");
    let before = fs::read(dir.join("store.rbs")).unwrap();
    let ns = store.addon_namespace("text-pages").unwrap();
    let p = ns.put(None, 0, "t", b"1", T0).unwrap();
    for rev in 1..5 {
        ns.put(Some(&p.id), rev, "t", format!("{rev}").as_bytes(), T0).unwrap();
    }
    assert_eq!(fs::read(dir.join("store.rbs")).unwrap(), before);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn archive_reconciliation_leaves_add_on_data_untouched() {
    let (dir, store) = fresh("reconcile");
    let ns = store.addon_namespace("text-pages").unwrap();
    ns.put(None, 0, "t", b"keep me", T0).unwrap();
    let snapshot: Vec<(String, Vec<u8>)> = fs::read_dir(&ns.dir)
        .unwrap()
        .flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), fs::read(e.path()).unwrap()))
        .collect();
    store.reconcile_archive().unwrap();
    for (name, bytes) in snapshot {
        assert_eq!(fs::read(ns.dir.join(&name)).unwrap(), bytes, "{name} changed");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_limits_hold() {
    let (dir, store) = fresh("limits");
    let limits = AddonLimits { quota_bytes: 64 * 1024 + 200_000, max_page_bytes: 1000, max_pages: 2 };
    let ns = store.addon_namespace_with("text-pages", limits).unwrap();
    assert!(matches!(ns.put(None, 0, "t", &[b'a'; 1001], T0), Err(AddonWriteError::PageTooLarge)));
    assert!(matches!(ns.put(None, 0, &"x".repeat(201), b"a", T0), Err(AddonWriteError::TitleTooLong)));
    assert!(matches!(ns.put(None, 0, "t", &[0xff], T0), Err(AddonWriteError::InvalidBody)));
    ns.put(None, 0, "1", b"a", T0).unwrap();
    ns.put(None, 0, "2", b"a", T0).unwrap();
    assert!(matches!(ns.put(None, 0, "3", b"a", T0), Err(AddonWriteError::TooManyPages)));
    fs::remove_dir_all(dir).unwrap();
    // The quota counts what is actually on disk, debris included.
    let (dir, store) = fresh("quota");
    // Admission counts the replacement index at its real size, so the debris
    // alone is what tips this write over the quota.
    let limits = AddonLimits { quota_bytes: 12 * 1024, max_page_bytes: 4000, max_pages: 100 };
    let ns = store.addon_namespace_with("text-pages", limits).unwrap();
    let first = ns.put(None, 0, "t", &[b'a'; 3000], T0).unwrap();
    fs::write(ns.dir.join(".tmp-debris"), vec![0u8; 6000]).unwrap();
    assert!(matches!(ns.put(Some(&first.id), 1, "t", &[b'b'; 3000], T0), Err(AddonWriteError::QuotaExceeded)));
    // The refused write changed nothing.
    assert_eq!(ns.get(&first.id).unwrap().1.as_slice(), &[b'a'; 3000][..]);
    fs::remove_file(ns.dir.join(".tmp-debris")).unwrap();
    ns.put(Some(&first.id), 1, "t", &[b'b'; 3000], T0).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_crash_after_the_new_version_keeps_the_old_page_and_recovery_sweeps() {
    let (dir, store) = fresh("crash-version");
    let ns = store.addon_namespace("text-pages").unwrap();
    let p = ns.put(None, 0, "t", b"old", T0).unwrap();
    CRASH.with(|c| c.set(Some(Crash::AfterVersion)));
    assert!(ns.put(Some(&p.id), 1, "t", b"new", T0).is_err());
    // The page still reads as the old version; the orphan goes at recovery.
    assert_eq!(ns.get(&p.id).unwrap().1.as_slice(), b"old");
    assert!(ns.blobs.exists(&version_id(&p.id, 2)));
    fs::write(ns.dir.join(".tmp-0123"), b"half").unwrap();
    assert!(ns.recover().unwrap().is_empty());
    assert!(!ns.blobs.exists(&version_id(&p.id, 2)));
    assert!(!ns.dir.join(".tmp-0123").exists());
    assert_eq!(ns.get(&p.id).unwrap().1.as_slice(), b"old");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_crash_after_the_index_keeps_the_new_page_and_recovery_drops_the_old() {
    let (dir, store) = fresh("crash-index");
    let ns = store.addon_namespace("text-pages").unwrap();
    let p = ns.put(None, 0, "t", b"old", T0).unwrap();
    CRASH.with(|c| c.set(Some(Crash::AfterIndex)));
    ns.put(Some(&p.id), 1, "t", b"new", T0).unwrap();
    assert!(ns.blobs.exists(&version_id(&p.id, 1)), "the old version is still there");
    ns.recover().unwrap();
    assert!(!ns.blobs.exists(&version_id(&p.id, 1)));
    assert_eq!(ns.get(&p.id).unwrap().1.as_slice(), b"new");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_failed_index_flush_keeps_both_versions_until_recovery() {
    let (dir, store) = fresh("flush");
    let ns = store.addon_namespace("text-pages").unwrap();
    let p = ns.put(None, 0, "t", b"old", T0).unwrap();
    CRASH.with(|c| c.set(Some(Crash::IndexFlush)));
    let updated = ns.put(Some(&p.id), 1, "t", b"new", T0).unwrap();
    assert!(ns.blobs.exists(&version_id(&p.id, 1)) && ns.blobs.exists(&version_id(&p.id, 2)));
    assert_eq!(ns.get(&p.id).unwrap().1.as_slice(), b"new");
    ns.recover().unwrap();
    assert!(!ns.blobs.exists(&version_id(&p.id, 1)));
    assert_eq!(ns.get(&p.id).unwrap().1.as_slice(), b"new");
    // A delete behind an undurable index keeps the body for recovery too.
    CRASH.with(|c| c.set(Some(Crash::IndexFlush)));
    ns.delete(&p.id, updated.revision).unwrap();
    assert!(ns.list().unwrap().is_empty());
    assert!(ns.blobs.exists(&version_id(&p.id, 2)));
    ns.recover().unwrap();
    assert!(!ns.blobs.exists(&version_id(&p.id, 2)));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_missing_index_removes_no_page_version() {
    let (dir, store) = fresh("no-index");
    let ns = store.addon_namespace("text-pages").unwrap();
    let a = ns.put(None, 0, "a", b"aaa", T0).unwrap();
    let b = ns.put(None, 0, "b", b"bbb", T0).unwrap();
    fs::remove_file(ns.dir.join(INDEX_ID)).unwrap();
    fs::write(ns.dir.join(".tmp-0456"), b"half").unwrap();
    assert!(ns.recover().unwrap().is_empty());
    assert!(ns.blobs.exists(&a.version) && ns.blobs.exists(&b.version));
    assert!(!ns.dir.join(".tmp-0456").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_unreadable_index_removes_nothing_and_a_missing_page_is_listed_unreadable() {
    let (dir, store) = fresh("unreadable");
    let ns = store.addon_namespace("text-pages").unwrap();
    let a = ns.put(None, 0, "a", b"aaa", T0).unwrap();
    let b = ns.put(None, 0, "b", b"bbb", T0).unwrap();
    // A missing body: listed, not readable, the other page intact.
    fs::remove_file(ns.dir.join(&b.version)).unwrap();
    assert_eq!(ns.recover().unwrap(), vec![b.id.clone()]);
    let list = ns.list().unwrap();
    assert!(list.iter().any(|e| e.meta.id == b.id && !e.readable));
    assert!(list.iter().any(|e| e.meta.id == a.id && e.readable));
    // A damaged index: recovery refuses and every page file stays.
    let index_path = ns.dir.join(INDEX_ID);
    let mut bytes = fs::read(&index_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&index_path, bytes).unwrap();
    let files_before = fs::read_dir(&ns.dir).unwrap().count();
    assert!(matches!(ns.recover(), Err(AddonWriteError::IndexUnreadable)));
    assert!(matches!(ns.put(None, 0, "c", b"c", T0), Err(AddonWriteError::IndexUnreadable)));
    assert_eq!(fs::read_dir(&ns.dir).unwrap().count(), files_before);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn delete_all_removes_only_its_own_namespace() {
    let (dir, store) = fresh("delete-all");
    let a = store.addon_namespace("text-pages").unwrap();
    a.put(None, 0, "t", b"x", T0).unwrap();
    let b = store.addon_namespace("other-addon").unwrap();
    b.put(None, 0, "t", b"y", T0).unwrap();
    let a_dir = a.dir.clone();
    a.delete_all().unwrap();
    assert!(!a_dir.exists());
    assert_eq!(b.list().unwrap().len(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unsafe_add_on_ids_never_name_a_folder() {
    let (dir, store) = fresh("ids");
    for bad in ["", "../x", "A", "a--b", "-a", "a/b"] {
        assert!(store.addon_namespace(bad).is_err(), "{bad}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_site_attachment_survives_ordinary_saves_and_changes_only_when_asked() {
    let (dir, store) = fresh("site");
    let ns = store.addon_namespace("text-pages").unwrap();
    let p = ns.put(None, 0, "t", b"body", T0).unwrap();
    assert_eq!(p.site, None);
    let set = ns.put_with_site(Some(&p.id), 1, "t", b"body", SiteChange::Set("example.com".into()), T0).unwrap();
    assert_eq!(set.site.as_deref(), Some("example.com"));
    // A text save and a rename keep it.
    let text = ns.put(Some(&p.id), 2, "t", b"changed", T0).unwrap();
    let renamed = ns.put_with_site(Some(&p.id), 3, "renamed", b"changed", SiteChange::Keep, T0).unwrap();
    assert_eq!(text.site.as_deref(), Some("example.com"));
    assert_eq!(renamed.site.as_deref(), Some("example.com"));
    // It is in the index a later list reads, and in a reopened namespace.
    assert_eq!(ns.list().unwrap()[0].meta.site.as_deref(), Some("example.com"));
    drop(ns);
    let ns = store.addon_namespace("text-pages").unwrap();
    assert_eq!(ns.get(&p.id).unwrap().0.site.as_deref(), Some("example.com"));
    let cleared = ns.put_with_site(Some(&p.id), 4, "renamed", b"changed", SiteChange::Clear, T0).unwrap();
    assert_eq!(cleared.site, None);
    assert_eq!(ns.list().unwrap()[0].meta.site, None);
    // A new page can be created attached.
    let attached = ns.put_with_site(None, 0, "n", b"", SiteChange::Set("github.com".into()), T0).unwrap();
    assert_eq!(attached.site.as_deref(), Some("github.com"));
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_a_well_formed_registrable_domain_can_be_attached() {
    let (dir, store) = fresh("site-valid");
    let ns = store.addon_namespace("text-pages").unwrap();
    for good in ["example.com", "bbc.co.uk", "xn--bcher-kva.de", "a-b.example", "1password.com"] {
        assert!(valid_site(good), "{good}");
    }
    for bad in [
        "", "com", "Example.com", "exa mple.com", ".example.com", "example.com.", "-a.com", "a-.com",
        "a..com", "https://example.com", "example.com/path", "\u{e9}t\u{e9}.fr", &"a".repeat(64), &format!("{}.com", "a.".repeat(130)),
    ] {
        assert!(!valid_site(bad), "{bad}");
    }
    let p = ns.put(None, 0, "t", b"x", T0).unwrap();
    assert!(matches!(
        ns.put_with_site(Some(&p.id), 1, "t", b"x", SiteChange::Set("Example.com".into()), T0),
        Err(AddonWriteError::InvalidSite)
    ));
    assert_eq!(ns.get(&p.id).unwrap().0.revision, 1);
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_index_written_before_sites_existed_still_reads() {
    let meta: PageMeta = serde_json::from_str(
        r#"{"id":"00000000000000000000000000000001","title":"t","revision":1,"created_at_ms":1,"updated_at_ms":1,"body_bytes":0,"version":"v"}"#,
    )
    .unwrap();
    assert_eq!(meta.site, None);
    assert!(!serde_json::to_string(&meta).unwrap().contains("site"));
}

#[test]
fn the_index_reservation_counts_long_titles_and_sites() {
    // 30 pages with 200-character titles of 4-byte characters and 253-byte
    // sites: the old flat estimate (64 KiB + 512 per page) would have been
    // short; admission now counts the serialized index itself.
    let (dir, store) = fresh("index-room");
    let ns = store.addon_namespace("text-pages").unwrap();
    let title = "\u{1F600}".repeat(200);
    let site = format!("{}.{}.{}.{}.com", "a".repeat(62), "b".repeat(62), "c".repeat(62), "d".repeat(60));
    assert!(valid_site(&site));
    for _ in 0..30 {
        ns.put_with_site(None, 0, &title, b"x", SiteChange::Set(site.clone()), T0).unwrap();
    }
    assert_eq!(ns.list().unwrap().len(), 30);
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_conflicting_attachment_change_leaves_the_record_untouched() {
    let (dir, store) = fresh("site-conflict");
    let ns = store.addon_namespace("text-pages").unwrap();
    let p = ns.put_with_site(None, 0, "t", b"x", SiteChange::Set("example.com".into()), T0).unwrap();
    ns.put(Some(&p.id), 1, "t", b"y", T0).unwrap();
    for change in [SiteChange::Clear, SiteChange::Set("github.com".into())] {
        assert!(matches!(ns.put_with_site(Some(&p.id), 1, "t", b"z", change, T0), Err(AddonWriteError::Conflict)));
    }
    let (meta, body) = ns.get(&p.id).unwrap();
    assert_eq!((meta.revision, meta.site.as_deref(), body.as_slice()), (2, Some("example.com"), &b"y"[..]));
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_replacement_index_alone_can_tip_a_write_over_the_quota() {
    // 200 pages whose records (800-byte titles, 253-byte sites) make the
    // index larger than the old flat estimate (64 KiB + 512 per page). The
    // quota then leaves room for the body and for an index the size of the
    // current one, but not for the larger one this write needs: refused, and
    // nothing changes. Without the index reservation it would be admitted.
    let (dir, store) = fresh("index-boundary");
    let title = "\u{1F600}".repeat(200);
    let site = format!("{}.{}.{}.{}.com", "a".repeat(62), "b".repeat(62), "c".repeat(62), "d".repeat(60));
    {
        let ns = store.addon_namespace("text-pages").unwrap();
        for _ in 0..200 {
            ns.put_with_site(None, 0, &title, b"x", SiteChange::Set(site.clone()), T0).unwrap();
        }
    }
    let probe = store.addon_namespace("text-pages").unwrap();
    let used = probe.used_bytes().unwrap();
    let index_on_disk = fs::metadata(probe.dir.join(INDEX_ID)).unwrap().len();
    assert!(index_on_disk > (64 * 1024 + 200 * 512) as u64, "index {index_on_disk} under the old estimate");
    let room = used + BlobStore::stored_len(1) + index_on_disk;
    drop(probe);
    let limits = AddonLimits { quota_bytes: room, max_page_bytes: 4000, max_pages: 1000 };
    let ns = store.addon_namespace_with("text-pages", limits).unwrap();
    let before = ns.list().unwrap().len();
    assert!(matches!(
        ns.put_with_site(None, 0, &title, b"x", SiteChange::Set(site.clone()), T0),
        Err(AddonWriteError::QuotaExceeded)
    ));
    assert_eq!(ns.list().unwrap().len(), before);
    assert_eq!(ns.used_bytes().unwrap(), used);
    // With room for the larger index too, the same write is admitted.
    drop(ns);
    let limits = AddonLimits { quota_bytes: room + 4096, ..limits };
    let ns = store.addon_namespace_with("text-pages", limits).unwrap();
    ns.put_with_site(None, 0, &title, b"x", SiteChange::Set(site), T0).unwrap();
    assert_eq!(ns.list().unwrap().len(), before + 1);
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}

// ---- the Vault backup carry ----------------------------------------------------

/// A source Library with two pages: one saved twice and attached to a site.
fn backup_source(tag: &str) -> (PathBuf, Store, Vec<PageMeta>) {
    let (dir, store) = fresh(tag);
    let ns = store.addon_namespace("text-pages").unwrap();
    let first = ns.put(None, 0, "Plans", b"draft", T0).unwrap();
    ns.put_with_site(Some(&first.id), 1, "Plans", "final é".as_bytes(), SiteChange::Set("example.test".into()), T0 + 1)
        .unwrap();
    ns.put(None, 0, "Empty", b"", T0 + 2).unwrap();
    let pages = ns.backup_pages().unwrap().unwrap();
    (dir, store, pages)
}

/// Everything the export writes for `pages`: (version, body) and the index.
fn carried(store: &Store, pages: &[PageMeta]) -> (Vec<(String, Vec<u8>)>, Vec<u8>) {
    let ns = store.addon_namespace("text-pages").unwrap();
    let bodies = pages
        .iter()
        .map(|p| (p.version().to_string(), ns.backup_body(p).unwrap().unwrap().to_vec()))
        .collect();
    (bodies, addon_backup_index(pages).unwrap().to_vec())
}

#[test]
fn pages_restore_into_a_new_library_under_its_own_key() {
    let (src_dir, source, pages) = backup_source("carry-src");
    assert_eq!(pages.len(), 2);
    let (bodies, index) = carried(&source, &pages);
    let (dir, target) = fresh("carry-dst");
    assert_ne!(source.data_key(), target.data_key());
    let mut restore = target.addon_restorer().begin("text-pages").unwrap();
    for (version, body) in &bodies {
        restore.put_version(version, body).unwrap();
    }
    assert_eq!(restore.finish(&index).unwrap(), 2);
    assert!(target.addon_indexes_open());
    let ns = target.addon_namespace("text-pages").unwrap();
    let restored: Vec<_> = ns.list().unwrap().into_iter().map(|e| (e.meta, e.readable)).collect();
    assert_eq!(restored.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>(), pages);
    assert!(restored.iter().all(|(_, readable)| *readable));
    let plans = pages.iter().find(|p| p.title == "Plans").unwrap();
    let (meta, body) = ns.get(&plans.id).unwrap();
    assert_eq!((body.as_slice(), meta.site.as_deref(), meta.revision), ("final é".as_bytes(), Some("example.test"), 2));
    // And it goes on like any namespace: the next save is revision 3.
    assert_eq!(ns.put(Some(&plans.id), 2, "Plans", b"later", T0 + 9).unwrap().revision, 3);
    drop((ns, source, target));
    fs::remove_dir_all(src_dir).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_restored_index_must_name_exactly_the_pages_written() {
    let (src_dir, source, pages) = backup_source("carry-exact");
    let (bodies, index) = carried(&source, &pages);
    let attempt = |tag: &str, write: &[(String, Vec<u8>)], index: &[u8]| {
        let (dir, target) = fresh(tag);
        let mut restore = target.addon_restorer().begin("text-pages").unwrap();
        for (version, body) in write {
            restore.put_version(version, body).unwrap();
        }
        let result = restore.finish(index);
        drop(target);
        fs::remove_dir_all(dir).unwrap();
        result
    };
    // A page the index names was never written.
    assert!(matches!(attempt("carry-missing", &bodies[..1], &index), Err(crate::BackupError::Invalid(_))));
    // A page was written that the index does not name.
    let mut extra = bodies.clone();
    extra.push((version_id(&"ab".repeat(16), 1), b"stray".to_vec()));
    assert!(matches!(attempt("carry-extra", &extra, &index), Err(crate::BackupError::Invalid(_))));
    // A body that is not the size the index records.
    let mut resized = bodies.clone();
    resized[0].1.push(b'!');
    assert!(matches!(attempt("carry-size", &resized, &index), Err(crate::BackupError::Invalid(_))));
    // An index with an unknown field, a bad site, or a long title.
    let edit = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut value: serde_json::Value = serde_json::from_slice(&index).unwrap();
        change(&mut value);
        serde_json::to_vec(&value).unwrap()
    };
    let bad_indexes = [
        edit(&|v| v["pages"][0]["extra"] = serde_json::json!(1)),
        edit(&|v| v["pages"][1]["site"] = serde_json::json!("Not A Site")),
        edit(&|v| v["pages"][0]["title"] = serde_json::json!("t".repeat(ADDON_MAX_TITLE_CHARS + 1))),
        edit(&|v| v["schema"] = serde_json::json!(2)),
        // A collection is checked on restore as on a save (review R-003).
        edit(&|v| v["pages"][1]["collection"] = serde_json::json!("Not A Collection")),
        edit(&|v| v["pages"][0]["collection"] = serde_json::json!("")),
    ];
    for (n, bad) in bad_indexes.iter().enumerate() {
        assert!(matches!(attempt("carry-bad-index", &bodies, bad), Err(crate::BackupError::Invalid(_))), "index {n}");
    }
    // The good one, for contrast, with and without a well-formed collection.
    assert_eq!(attempt("carry-good", &bodies, &index).unwrap(), 2);
    let in_notebook = edit(&|v| v["pages"][0]["collection"] = serde_json::json!("assistant"));
    assert_eq!(attempt("carry-good-collection", &bodies, &in_notebook).unwrap(), 2);
    drop(source);
    fs::remove_dir_all(src_dir).unwrap();
}

#[test]
fn every_restored_page_is_checked_as_a_save_checks_one() {
    let (dir, target) = fresh("carry-pages");
    let restorer = target.addon_restorer();
    let mut restore = restorer.begin("text-pages").unwrap();
    let good = version_id(&"cd".repeat(16), 4);
    for bad in ["index", "p-xyz-1", &format!("p-{}-01", "cd".repeat(16)), "../escape", &format!("{good}x")] {
        assert!(matches!(restore.put_version(bad, b"x"), Err(crate::BackupError::Invalid(_))), "{bad}");
    }
    assert!(matches!(restore.put_version(&good, b"\xff\xfe"), Err(crate::BackupError::Invalid(_))));
    assert!(matches!(
        restore.put_version(&good, &vec![b'a'; ADDON_MAX_PAGE_BYTES + 1]),
        Err(crate::BackupError::OverLimit(_))
    ));
    restore.put_version(&good, b"text").unwrap();
    assert!(matches!(restore.put_version(&good, b"text"), Err(crate::BackupError::Invalid(_))));
    // An add-on is restored once, and only under an id an add-on can have.
    assert!(matches!(restorer.begin("text-pages"), Err(crate::BackupError::Invalid(_))));
    assert!(matches!(restorer.begin("../x"), Err(crate::BackupError::Invalid(_))));
    drop((restore, target));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_superseded_version_reads_as_gone_and_a_damaged_one_as_an_error() {
    let (dir, store, pages) = backup_source("carry-moved");
    let ns = store.addon_namespace("text-pages").unwrap();
    let plans = pages.iter().find(|p| p.title == "Plans").unwrap().clone();
    ns.put(Some(&plans.id), plans.revision, "Plans", b"newer", T0 + 5).unwrap();
    assert!(ns.backup_body(&plans).unwrap().is_none(), "a later save replaced it");
    let empty = pages.iter().find(|p| p.title == "Empty").unwrap();
    fs::write(ns.dir.join(empty.version()), b"not a blob").unwrap();
    assert!(ns.backup_body(empty).is_err());
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_index_under_another_librarys_key_is_not_in_place() {
    let (src_dir, source, _) = backup_source("carry-key-a");
    let (dir, target) = fresh("carry-key-b");
    assert!(target.addon_indexes_open(), "no add-on folder is in place");
    let from = addons_dir(source.path()).join("text-pages");
    let to = addons_dir(target.path()).join("text-pages");
    fs::create_dir_all(&to).unwrap();
    for entry in fs::read_dir(&from).unwrap().flatten() {
        fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
    assert!(!target.addon_indexes_open());
    drop((source, target));
    fs::remove_dir_all(src_dir).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_restore_stops_at_each_limit() {
    let (dir, target) = fresh("carry-limits");
    let restorer = target.addon_restorer();
    let page = |n: u8, rev: u64| version_id(&format!("{n:02x}").repeat(16), rev);
    // The page count.
    let limits = AddonLimits { quota_bytes: ADDON_QUOTA_BYTES, max_page_bytes: 64, max_pages: 2 };
    let mut restore = restorer.begin_with("count", limits).unwrap();
    restore.put_version(&page(1, 1), b"a").unwrap();
    restore.put_version(&page(2, 1), b"b").unwrap();
    assert!(matches!(restore.put_version(&page(3, 1), b"c"), Err(crate::BackupError::OverLimit(_))));
    // The add-on's total, bodies and then the index counted.
    let room = BlobStore::stored_len(10) * 2;
    let limits = AddonLimits { quota_bytes: room, max_page_bytes: 64, max_pages: 100 };
    let mut restore = restorer.begin_with("quota", limits).unwrap();
    restore.put_version(&page(1, 1), &[b'x'; 10]).unwrap();
    restore.put_version(&page(2, 1), &[b'x'; 10]).unwrap();
    assert!(matches!(restore.put_version(&page(3, 1), b"x"), Err(crate::BackupError::OverLimit(_))));
    assert!(matches!(restore.finish(b"{\"schema\":1,\"pages\":[]}"), Err(crate::BackupError::OverLimit(_))));
    // One page over its own limit.
    let limits = AddonLimits { quota_bytes: ADDON_QUOTA_BYTES, max_page_bytes: 4, max_pages: 100 };
    let mut restore = restorer.begin_with("page", limits).unwrap();
    assert!(matches!(restore.put_version(&page(1, 1), b"12345"), Err(crate::BackupError::OverLimit(_))));
    drop(target);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_restored_revision_is_one_a_save_can_follow() {
    let (dir, target) = fresh("carry-revision");
    let mut restore = target.addon_restorer().begin("text-pages").unwrap();
    let id = "ef".repeat(16);
    for bad in [0, ADDON_MAX_REVISION + 1, u64::MAX] {
        assert!(matches!(restore.put_version(&version_id(&id, bad), b"x"), Err(crate::BackupError::Invalid(_))), "revision {bad}");
    }
    restore.put_version(&version_id(&id, ADDON_MAX_REVISION), b"x").unwrap();
    let index = format!(
        "{{\"schema\":1,\"pages\":[{{\"id\":\"{id}\",\"title\":\"t\",\"revision\":{ADDON_MAX_REVISION},\"created_at_ms\":1,\"updated_at_ms\":1,\"body_bytes\":1,\"version\":\"{}\"}}]}}",
        version_id(&id, ADDON_MAX_REVISION)
    );
    assert_eq!(restore.finish(index.as_bytes()).unwrap(), 1);
    // A save past the bound is refused, so no backup ever carries a revision
    // a restore would refuse.
    let ns = target.addon_namespace("text-pages").unwrap();
    assert!(matches!(ns.put(Some(&id), ADDON_MAX_REVISION, "t", b"y", 2), Err(AddonWriteError::Conflict)));
    assert_eq!(ns.get(&id).unwrap().0.revision, ADDON_MAX_REVISION);
    drop((ns, target));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_add_on_folder_that_cannot_be_read_is_never_taken_for_none() {
    let (dir, store, _) = backup_source("carry-odd");
    // An index that is not a regular file: unreadable, never "no index".
    let ns = store.addon_namespace("other-addon").unwrap();
    fs::create_dir(ns.dir.join(INDEX_ID)).unwrap();
    assert!(matches!(ns.backup_pages(), Err(AddonWriteError::IndexUnreadable)));
    assert!(!store.addon_indexes_open());
    fs::remove_dir(ns.dir.join(INDEX_ID)).unwrap();
    assert!(store.addon_indexes_open());
    // A namespace that is a link: listed as an error, never followed or skipped.
    #[cfg(unix)]
    {
        let outside = test_dir("carry-outside");
        std::os::unix::fs::symlink(&outside, addons_dir(store.path()).join("linked")).unwrap();
        assert!(addon_ids(store.path()).is_err());
        assert!(store.addon_backup_inputs().is_err());
        assert!(!store.addon_indexes_open());
        fs::remove_file(addons_dir(store.path()).join("linked")).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
    assert_eq!(addon_ids(store.path()).unwrap(), ["other-addon", "text-pages"]);
    drop((ns, store));
    fs::remove_dir_all(dir).unwrap();
}
