//! Public data controls. No installation or entitlement is needed.
//! The caller owns unlock admission and waits for session quiescence before
//! handing a namespace to these worker-only operations.
use crate::addon_delivery::Cancellation;
use patanyx_store::AddonNamespace;
use serde::Serialize;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Serialize)]
pub(crate) struct ExportReport {
    pub written: usize,
    pub failures: Vec<PageFailure>,
}
#[derive(Debug, Serialize)]
pub(crate) struct PageFailure {
    pub id: String,
    pub code: &'static str,
}

/// Only an id enters a filename. Titles are file contents, including slashes,
/// reserved device names, control characters and Unicode.
fn page_path(folder: &Path, id: &str) -> Result<PathBuf, &'static str> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid");
    }
    Ok(folder.join(format!("page-{id}.txt")))
}

pub(crate) fn export(
    namespace: &AddonNamespace,
    folder: &Path,
    cancel: &Cancellation,
) -> Result<ExportReport, &'static str> {
    if !folder.is_absolute() || !fs::metadata(folder).is_ok_and(|m| m.is_dir()) {
        return Err("folder");
    }
    let pages = namespace.list().map_err(|_| "export_unreadable")?;
    let mut report = ExportReport::default();
    for page in pages {
        cancel.check().map_err(|_| "cancelled")?;
        let id = page.meta.id;
        let result = (|| {
            let (meta, body) = namespace.get(&id).map_err(|_| "unreadable")?;
            std::str::from_utf8(&body).map_err(|_| "unreadable")?;
            let dest = page_path(folder, &id)?;
            // Cancellation serializes each page's publication with a Vault lock.
            let mut failure = "io";
            cancel
                .commit(|| {
                    let mut options = fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    let mut file = options.open(&dest).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::AlreadyExists {
                            failure = "exists";
                        }
                        crate::addon_install::InstallError::Io
                    })?;
                    let written = file
                        .write_all(meta.title.as_bytes())
                        .and_then(|_| file.write_all(b"\n\n"))
                        .and_then(|_| file.write_all(&body))
                        .and_then(|_| file.sync_all());
                    if written.is_err() {
                        drop(file);
                        let _ = fs::remove_file(&dest);
                        return Err(crate::addon_install::InstallError::Io);
                    }
                    Ok(())
                })
                .map_err(|e| {
                    if e == crate::addon_install::InstallError::Cancelled {
                        "cancelled"
                    } else {
                        failure
                    }
                })
        })();
        match result {
            Ok(()) => report.written += 1,
            Err(code) => report.failures.push(PageFailure { id, code }),
        }
    }
    Ok(report)
}

/// Both data locations belong to this id. Removing code is a separate job.
pub(crate) fn delete(
    namespace: AddonNamespace,
    engine: &Path,
    cancel: &Cancellation,
) -> Result<(), &'static str> {
    cancel
        .commit(|| {
            namespace
                .delete_all()
                .map_err(|_| crate::addon_install::InstallError::Io)?;
            remove_engine(engine).map_err(|_| crate::addon_install::InstallError::Io)?;
            Ok(())
        })
        .map_err(|e| {
            if e == crate::addon_install::InstallError::Cancelled {
                "cancelled"
            } else {
                "io"
            }
        })
}

fn remove_engine(engine: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(engine) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => fs::remove_dir_all(engine),
        Ok(_) => Err(std::io::Error::other("unsafe engine folder")),
    }
}

/// Directory names only, never page contents or display-name guesses.
pub(crate) fn namespaces(store_path: &Path) -> Result<Vec<String>, &'static str> {
    let dir = patanyx_store::addons_dir(store_path);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("io"),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "io")?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().map_err(|_| "io")?.is_dir() && patanyx_store::addon_id_ok(&id) {
            ids.push(id);
        }
    }
    ids.sort();
    Ok(ids)
}

/// What an import would replace (M12): the add-ons with saved pages beside
/// the Library, and how many pages they hold, counted in `library` (the one
/// open now, with its vault unlocked). Without it pages cannot be counted, and
/// any add-on folder is reported as data of unknown size (`None`): a warning
/// is never withheld for want of a key. `window_open`: an add-on window (or
/// its storage worker) is still live, and its last save, which an import
/// waits for, can add pages after this count; that is reported as unknown
/// too. Names only, never page contents.
pub(crate) fn import_exposure(
    library: Option<&patanyx_store::Store>,
    store_path: &Path,
    window_open: bool,
) -> (Option<usize>, Vec<String>) {
    let Ok(ids) = patanyx_store::addon_ids(store_path) else {
        return (None, Vec::new());
    };
    let Some(library) = library.filter(|_| !window_open) else {
        return (if ids.is_empty() && !window_open { Some(0) } else { None }, ids);
    };
    let (mut pages, mut counted, mut with_pages) = (0, true, Vec::new());
    for id in ids {
        // `backup_pages`, not `list`: an index that is there but is not a
        // regular file is unreadable, never "no pages".
        match library.addon_namespace(&id).ok().map(|ns| ns.backup_pages()) {
            Some(Ok(None)) => {}
            Some(Ok(Some(list))) if list.is_empty() => {}
            Some(Ok(Some(list))) => {
                pages += list.len();
                with_pages.push(id);
            }
            _ => {
                counted = false;
                with_pages.push(id);
            }
        }
    }
    (counted.then_some(pages), with_pages)
}

#[cfg(test)]
#[path = "addon_data_tests.rs"]
mod tests;
