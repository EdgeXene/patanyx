use super::*;
use patanyx_store::Store;

struct Fixture(PathBuf);
impl Fixture {
    fn new(tag: &str) -> Self {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path =
            std::env::temp_dir().join(format!("addon-data-{tag}-{:x}", u64::from_le_bytes(random)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> Store {
        Store::create_with_params(&self.0.join("store.rbs"), "pw", 8192, 1, 1).unwrap()
    }
    fn folder(&self) -> PathBuf {
        let p = self.0.join("exports");
        fs::create_dir(&p).unwrap();
        p
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn export_unsafe_titles_are_contents_and_existing_files_are_never_overwritten() {
    let f = Fixture::new("export");
    let store = f.store();
    let ns = store.addon_namespace("text-pages").unwrap();
    let first = ns
        .put(None, 0, "../../CON/unsafe 📝", b"first body", 1)
        .unwrap();
    let second = ns
        .put(None, 0, "NUL.txt\nnext", "Unicode body 📝".as_bytes(), 1)
        .unwrap();
    let folder = f.folder();
    let existing = page_path(&folder, &first.id).unwrap();
    fs::write(&existing, b"keep these bytes").unwrap();
    let report = export(&ns, &folder, &Cancellation::new()).unwrap();
    assert_eq!(
        fs::read(existing).unwrap(),
        b"keep these bytes",
        "overwrite boundary"
    );
    assert_eq!(report.written, 1);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].id, first.id);
    assert_eq!(report.failures[0].code, "exists");
    assert_eq!(
        fs::read_to_string(page_path(&folder, &second.id).unwrap()).unwrap(),
        "NUL.txt\nnext\n\nUnicode body 📝"
    );
    assert_eq!(fs::read_dir(&folder).unwrap().count(), 2);
}

#[test]
fn export_reports_each_unreadable_page_and_continues() {
    let f = Fixture::new("broken");
    let ns = f.store().addon_namespace("text-pages").unwrap();
    let a = ns.put(None, 0, "a", b"body", 1).unwrap();
    let b = ns.put(None, 0, "b", b"body", 1).unwrap();
    ns.put(None, 0, "readable", b"intact", 1).unwrap();
    let dir = f.0.join("addons/text-pages");
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(&a.id) || name.contains(&b.id) {
            fs::write(entry.path(), b"damaged").unwrap();
        }
    }
    let report = export(&ns, &f.folder(), &Cancellation::new()).unwrap();
    assert_eq!(report.written, 1);
    assert_eq!(report.failures.len(), 2);
    assert!(report.failures.iter().all(|f| f.code == "unreadable"));
}

#[test]
fn delete_removes_namespace_and_engine_marker_but_keeps_neighbors_and_bundle() {
    let f = Fixture::new("delete");
    let store = f.store();
    let ns = store.addon_namespace("text-pages").unwrap();
    ns.put(None, 0, "page", b"body", 1).unwrap();
    let other = store.addon_namespace("another-addon").unwrap();
    let page = other.put(None, 0, "keep", b"neighbor", 1).unwrap();
    let engine = f.0.join("addon-data/text-pages");
    let neighbor = f.0.join("addon-data/another-addon");
    fs::create_dir_all(engine.join("s1")).unwrap();
    fs::create_dir_all(&neighbor).unwrap();
    fs::write(engine.join("session-incomplete"), b"").unwrap();
    fs::write(engine.join("s1/cache"), b"engine").unwrap();
    let code = f.0.join("addon-code");
    fs::create_dir(&code).unwrap();
    fs::write(code.join("keep"), b"bundle").unwrap();
    delete(ns, &engine, &Cancellation::new()).unwrap();
    assert!(!f.0.join("addons/text-pages").exists());
    assert!(
        !engine.exists(),
        "engine folder and incomplete marker must go"
    );
    assert!(neighbor.exists());
    assert_eq!(&*other.get(&page.id).unwrap().1, b"neighbor");
    assert_eq!(fs::read(code.join("keep")).unwrap(), b"bundle");
}

#[test]
fn cancelled_export_and_delete_leave_data_untouched() {
    let f = Fixture::new("cancel");
    let ns = f.store().addon_namespace("text-pages").unwrap();
    let page = ns.put(None, 0, "keep", b"keep", 1).unwrap();
    let cancel = Cancellation::new();
    cancel.cancel();
    let folder = f.folder();
    assert_eq!(export(&ns, &folder, &cancel).unwrap_err(), "cancelled");
    assert_eq!(fs::read_dir(folder).unwrap().count(), 0);
    assert_eq!(&*ns.get(&page.id).unwrap().1, b"keep");
    assert_eq!(delete(ns, &f.0.join("engine"), &cancel), Err("cancelled"));
    assert!(f.0.join("addons/text-pages").exists());
}

#[test]
fn namespace_capture_does_no_io_and_public_discovery_needs_no_bundle() {
    let f = Fixture::new("capture");
    let store = f.store();
    let input = store.addon_namespace_input("text-pages").unwrap();
    assert!(!f.0.join("addons").exists());
    let ns = std::thread::spawn(move || input.open().unwrap())
        .join()
        .unwrap();
    ns.put(None, 0, "page", b"text", 1).unwrap();
    assert_eq!(
        namespaces(&f.0.join("store.rbs")).unwrap(),
        vec!["text-pages"]
    );
    assert!(!f.0.join("addon-code").exists());
}

#[test]
fn export_path_and_folder_refusals() {
    for id in ["../escape", "CON", "", "0123456789012345678901234567890/1"] {
        assert!(page_path(Path::new("/exports"), id).is_err());
    }
    let f = Fixture::new("path");
    let ns = f.store().addon_namespace("text-pages").unwrap();
    ns.put(None, 0, "page", b"body", 1).unwrap();
    assert_eq!(
        export(&ns, &f.0.join("missing"), &Cancellation::new()).unwrap_err(),
        "folder"
    );
}

/// Exported pages are plain text, so on Unix only their owner can read them.
#[cfg(unix)]
#[test]
fn exported_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new("mode");
    let store = f.store();
    let ns = store.addon_namespace("text-pages").unwrap();
    let page = ns.put(None, 0, "t", b"private text", 1).unwrap();
    let folder = f.folder();
    let report = export(&ns, &folder, &Cancellation::new()).unwrap();
    assert_eq!(report.written, 1);
    let mode = fs::metadata(page_path(&folder, &page.id).unwrap()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn an_import_is_told_which_add_ons_have_pages_and_how_many() {
    let fixture = Fixture::new("exposure");
    let store = fixture.store();
    let path = fixture.0.join("store.rbs");
    assert_eq!(import_exposure(Some(&store), &path, false), (Some(0), Vec::<String>::new()));
    let notes = store.addon_namespace("text-pages").unwrap();
    notes.put(None, 0, "One", b"1", 1).unwrap();
    notes.put(None, 0, "Two", b"2", 2).unwrap();
    // An add-on whose pages were all deleted holds nothing to lose.
    let empty = store.addon_namespace("emptied").unwrap();
    let gone = empty.put(None, 0, "Gone", b"x", 3).unwrap();
    empty.delete(&gone.id, 1).unwrap();
    assert_eq!(import_exposure(Some(&store), &path, false), (Some(2), vec!["text-pages".to_string()]));
    // Locked: nothing can be counted, and the warning is not withheld.
    assert_eq!(import_exposure(None, &path, false), (None, vec!["emptied".to_string(), "text-pages".to_string()]));
    // An index that cannot be read is data of unknown size.
    let index = patanyx_store::addons_dir(&path).join("emptied").join("index");
    fs::write(&index, b"damaged").unwrap();
    assert_eq!(import_exposure(Some(&store), &path, false), (None, vec!["emptied".to_string(), "text-pages".to_string()]));
    // An index that is not a regular file is unreadable too, never "no pages".
    fs::remove_file(&index).unwrap();
    fs::create_dir(&index).unwrap();
    assert_eq!(import_exposure(Some(&store), &path, false), (None, vec!["emptied".to_string(), "text-pages".to_string()]));
    fs::remove_dir(&index).unwrap();
    // An open add-on window's last save can add pages after the count.
    let fresh = Fixture::new("exposure-open");
    let empty = fresh.store();
    let empty_path = fresh.0.join("store.rbs");
    assert_eq!(import_exposure(Some(&empty), &empty_path, false), (Some(0), Vec::<String>::new()));
    assert_eq!(import_exposure(Some(&empty), &empty_path, true), (None, Vec::<String>::new()));
}
