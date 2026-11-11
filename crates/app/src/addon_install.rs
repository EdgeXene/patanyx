//! Executable packages live under updates/addon-code, never the Library's
//! addons data namespace. The host receives checked memory, not disk paths.
//! Call install/rollback/uninstall on a worker, after M7 has quiesced the view.

use crate::addon_delivery::Cancellation;
use patanyx_update::{addon::*, AddonCatalog, AddonIndex, AddonManifest, AddonRelease, TrustedKeys};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallError {
    Unconfigured,
    Invalid,
    Integrity,
    Io,
    Busy,
    StaleIndex,
    ExpiredIndex,
    StaleCatalog,
    ExpiredCatalog,
    Cancelled,
    NotInstalled,
    Unauthorized,
}
impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "addon_install_{self:?}")
    }
}
impl std::error::Error for InstallError {}
impl From<std::io::Error> for InstallError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
impl From<patanyx_update::UpdateError> for InstallError {
    fn from(_: patanyx_update::UpdateError) -> Self {
        Self::Integrity
    }
}

/// The fields cannot be mutated or constructed by a host. All assets have been
/// read and checked together; serve only these bytes for the life of the view.
pub(crate) struct VerifiedBundle {
    manifest: AddonManifest,
    files: BTreeMap<String, Vec<u8>>,
    envelope: Vec<u8>,
}
impl VerifiedBundle {
    pub(crate) fn manifest(&self) -> &AddonManifest {
        &self.manifest
    }
    pub(crate) fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }
    pub(crate) fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseChoice {
    Current,
    Rollback,
}
impl ReleaseChoice {
    pub(crate) fn release(self, index: &AddonIndex) -> Result<&AddonRelease, InstallError> {
        match self {
            Self::Current => Ok(index.current()),
            Self::Rollback => index.rollback().ok_or(InstallError::Unauthorized),
        }
    }
}

/// What the panels show of an installed add-on without reading its files:
/// the installed manifest's name and version (signature checked, and the
/// manifest is the one active.json names), and the rollback version the saved
/// index authorizes. Display only; Open still verifies every file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledSummary {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) rollback: Option<String>,
}

/// Only the verifier below can construct a prepared transaction.
pub(crate) struct PreparedInstall {
    index: Vec<u8>,
    choice: ReleaseChoice,
    selected: VerifiedBundle,
    rollback: Option<VerifiedBundle>,
}

pub(crate) struct InstallStore {
    root: PathBuf,
    keys: TrustedKeys,
    #[cfg(test)]
    fail_at: std::cell::Cell<Option<&'static str>>,
}
impl InstallStore {
    pub(crate) fn production() -> Result<Self, InstallError> {
        let keys = crate::updater::addon_trusted_keys().map_err(|_| InstallError::Unconfigured)?;
        let root = crate::updater::data_dir().join("addon-code");
        if !root.is_absolute()
            || root
                .ancestors()
                .any(|p| p.join(".git").exists() || p.join("Cargo.toml").exists())
        {
            return Err(InstallError::Invalid);
        }
        Ok(Self {
            root,
            keys,
            #[cfg(test)]
            fail_at: std::cell::Cell::new(None),
        })
    }
    #[cfg(test)]
    pub(super) fn test_store(root: PathBuf, keys: TrustedKeys) -> Self {
        Self {
            root,
            keys,
            fail_at: std::cell::Cell::new(None),
        }
    }
    #[cfg(test)]
    fn checkpoint(&self, point: &'static str) -> Result<(), InstallError> {
        if self.fail_at.get() == Some(point) {
            Err(InstallError::Io)
        } else {
            Ok(())
        }
    }
    pub(crate) fn keys(&self) -> &TrustedKeys {
        &self.keys
    }
    fn dir(&self, id: &str) -> Result<PathBuf, InstallError> {
        if !valid_addon_id(id) {
            return Err(InstallError::Invalid);
        }
        Ok(self.root.join(id))
    }
    fn lock(&self, id: &str) -> Result<fs::File, InstallError> {
        let dir = self.dir(id)?;
        self.lock_in(&dir, "install.lock")
    }
    fn lock_in(&self, dir: &Path, name: &str) -> Result<fs::File, InstallError> {
        ensure_dir(&self.root, dir)?;
        let path = dir.join(name);
        refuse_link_if_present(&path)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        // A child process another thread was starting shares this open file
        // until it runs its program, so a lock just released can stay held
        // for a moment (Linux). That is not a second install: it is waited
        // out briefly before anything is called busy.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            match lock.try_lock() {
                Ok(()) => return Ok(lock),
                Err(fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => return Err(InstallError::Busy),
            }
        }
    }
    fn saved_index(&self, dir: &Path) -> Result<Option<AddonIndex>, InstallError> {
        let path = dir.join("index.sig.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(InstallError::Io),
            Ok(_) => Ok(Some(patanyx_update::verify_addon_index(
                &read_file(&self.root, &path, MAX_ADDON_ENVELOPE_BYTES as u64)?,
                &self.keys,
            )?)),
        }
    }
    pub(crate) fn accept_index(
        &self,
        id: &str,
        envelope: &[u8],
        now: u64,
    ) -> Result<AddonIndex, InstallError> {
        let index = patanyx_update::verify_addon_index(envelope, &self.keys)?;
        if index.id() != id {
            return Err(InstallError::Invalid);
        }
        if !index.valid_at(now) {
            return Err(InstallError::ExpiredIndex);
        }
        let _lock = self.lock(id)?;
        let dir = self.dir(id)?;
        if let Some(previous) = self.saved_index(&dir)? {
            if !index.succeeds(&previous) {
                return Err(InstallError::StaleIndex);
            }
        }
        atomic_record(&self.root, &dir.join("index.sig.json"), envelope)?;
        Ok(index)
    }
    /// The last accepted catalog, signature checked, no time check: what the
    /// Add-ons panel shows offline, while the Vault is locked, or after it
    /// expires. `None` when there has never been one.
    pub(crate) fn saved_catalog(&self) -> Result<Option<AddonCatalog>, InstallError> {
        let path = self.root.join("catalog.sig.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(InstallError::Io),
            Ok(_) => Ok(Some(patanyx_update::verify_addon_catalog(
                &read_file(&self.root, &path, MAX_ADDON_ENVELOPE_BYTES as u64)?,
                &self.keys,
            )?)),
        }
    }
    /// A fetched catalog: verified, valid now, and not older than the one
    /// held (the same succession rule as an index), then recorded atomically.
    pub(crate) fn accept_catalog(&self, envelope: &[u8], now: u64) -> Result<AddonCatalog, InstallError> {
        let catalog = patanyx_update::verify_addon_catalog(envelope, &self.keys)?;
        if !catalog.valid_at(now) {
            return Err(InstallError::ExpiredCatalog);
        }
        let _lock = self.lock_in(&self.root, "catalog.lock")?;
        if let Some(previous) = self.saved_catalog()? {
            if !catalog.succeeds(&previous) {
                return Err(InstallError::StaleCatalog);
            }
        }
        atomic_record(&self.root, &self.root.join("catalog.sig.json"), envelope)?;
        Ok(catalog)
    }
    /// Ids with installed code (an active.json), for the panels. Folder names
    /// that are not ids are skipped, never trusted.
    pub(crate) fn installed_ids(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|id| valid_addon_id(id) && self.root.join(id).join("active.json").exists())
            .collect();
        ids.sort();
        ids
    }
    /// See [`InstalledSummary`]. `Ok(None)` when nothing is installed.
    pub(crate) fn installed_summary(&self, id: &str) -> Result<Option<InstalledSummary>, InstallError> {
        let dir = self.dir(id)?;
        if !dir.exists() {
            return Ok(None);
        }
        let _lock = self.lock(id)?;
        let record = match self.active(&dir) {
            Ok(record) => record,
            Err(InstallError::NotInstalled) => return Ok(None),
            Err(e) => return Err(e),
        };
        let envelope = read_file(
            &self.root,
            &dir.join("releases").join(&record.manifest).join("manifest.sig.json"),
            MAX_ADDON_ENVELOPE_BYTES as u64,
        )?;
        use sha2::Digest;
        if patanyx_update::hex::encode(&sha2::Sha256::digest(&envelope)) != record.manifest {
            return Err(InstallError::Integrity);
        }
        let manifest = verify_addon_manifest(&envelope, &self.keys)?;
        if manifest.id() != id {
            return Err(InstallError::Integrity);
        }
        // No time check: an expired index still says which version it named.
        let rollback = self
            .saved_index(&dir)
            .ok()
            .flatten()
            .and_then(|index| index.rollback().map(|r| r.version().to_string()));
        Ok(Some(InstalledSummary {
            name: manifest.name().to_owned(),
            version: manifest.version().to_string(),
            rollback,
        }))
    }
    pub(crate) fn verify_package(
        &self,
        index: &AddonIndex,
        release: &AddonRelease,
        envelope: Vec<u8>,
        files: BTreeMap<String, Vec<u8>>,
    ) -> Result<VerifiedBundle, InstallError> {
        let manifest = release.verify_manifest(index.id(), &envelope, &self.keys)?;
        if files.len() != manifest.files().len() {
            return Err(InstallError::Integrity);
        }
        for file in manifest.files() {
            file.verify(files.get(file.path()).ok_or(InstallError::Integrity)?)?;
        }
        Ok(VerifiedBundle {
            manifest,
            files,
            envelope,
        })
    }
    pub(crate) fn prepare(
        &self,
        envelope: Vec<u8>,
        choice: ReleaseChoice,
        selected: VerifiedBundle,
        rollback: Option<VerifiedBundle>,
    ) -> Result<PreparedInstall, InstallError> {
        let index = patanyx_update::verify_addon_index(&envelope, &self.keys)?;
        choice
            .release(&index)?
            .verify_manifest(index.id(), &selected.envelope, &self.keys)?;
        if choice == ReleaseChoice::Current && index.rollback().is_some() != rollback.is_some() {
            return Err(InstallError::Integrity);
        }
        if let Some(bundle) = &rollback {
            index
                .rollback()
                .ok_or(InstallError::Unauthorized)?
                .verify_manifest(index.id(), &bundle.envelope, &self.keys)?;
        }
        Ok(PreparedInstall {
            index: envelope,
            choice,
            selected,
            rollback,
        })
    }
    /// `authorize` runs immediately before the atomic switch. The caller must
    /// recheck its captured licence/session identity and finish old-view teardown.
    /// Call cancel before changing that identity; cancellation and commit serialize.
    pub(crate) fn activate(
        &self,
        prepared: PreparedInstall,
        cancel: &Cancellation,
        authorize: impl FnOnce() -> bool,
    ) -> Result<(), InstallError> {
        cancel.check().map_err(|_| InstallError::Cancelled)?;
        let index = patanyx_update::verify_addon_index(&prepared.index, &self.keys)?;
        let id = index.id();
        let _lock = self.lock(id)?;
        let dir = self.dir(id)?;
        self.check_current_index(&dir, &index)?;
        let release = prepared.choice.release(&index)?;
        if let Some(rollback) = &prepared.rollback {
            self.stage(
                &dir,
                &index,
                index.rollback().ok_or(InstallError::Unauthorized)?,
                &prepared.index,
                rollback,
                cancel,
            )?;
        }
        #[cfg(test)]
        self.checkpoint("before_stage")?;
        let package = self.stage(
            &dir,
            &index,
            release,
            &prepared.index,
            &prepared.selected,
            cancel,
        )?;
        // Disk bytes are verified after staging and before any active record changes.
        self.read_package(&package, &index, release)?;
        #[cfg(test)]
        self.checkpoint("before_activate")?;
        cancel.commit(|| {
            self.check_current_index(&dir, &index)?;
            if !index.valid_at(now()?) {
                return Err(InstallError::ExpiredIndex);
            }
            if !authorize() {
                return Err(InstallError::Unauthorized);
            }
            let record = Active {
                schema: 1,
                manifest: patanyx_update::hex::encode(release.manifest_sha256()),
            };
            atomic_record(
                &self.root,
                &dir.join("active.json"),
                &serde_json::to_vec(&record).map_err(|_| InstallError::Invalid)?,
            )
        })?;
        // Cleanup is best effort after the commit. Preserve exactly the authorized
        // current/rollback pair. An error here cannot turn a saved switch into failure.
        self.prune(&dir, &index);
        Ok(())
    }
    fn check_current_index(&self, dir: &Path, index: &AddonIndex) -> Result<(), InstallError> {
        let latest = self.saved_index(dir)?.ok_or(InstallError::StaleIndex)?;
        if latest.sequence() != index.sequence()
            || latest.payload_sha256() != index.payload_sha256()
        {
            return Err(InstallError::StaleIndex);
        }
        Ok(())
    }
    fn stage(
        &self,
        dir: &Path,
        index: &AddonIndex,
        release: &AddonRelease,
        index_bytes: &[u8],
        bundle: &VerifiedBundle,
        cancel: &Cancellation,
    ) -> Result<PathBuf, InstallError> {
        let releases = dir.join("releases");
        ensure_dir(&self.root, &releases)?;
        let target = releases.join(patanyx_update::hex::encode(release.manifest_sha256()));
        if fs::symlink_metadata(&target).is_ok() {
            if self.read_package(&target, index, release).is_ok() {
                return Ok(target);
            }
            // A copy damaged on disk (a file removed or changed, say by a
            // virus scanner) is replaced rather than refusing every later
            // install of the same release. It is not the active copy's
            // concern: an active copy that fails verification never opens.
            match fs::symlink_metadata(&target) {
                Ok(m) if m.file_type().is_symlink() => fs::remove_file(&target)?,
                Ok(_) => fs::remove_dir_all(&target)?,
                Err(_) => (),
            }
            sync_dir(&releases)?;
        }
        let temp = releases.join(format!(".stage-{}", nonce()?));
        private_dir(&temp)?;
        let result = (|| {
            for (path, bytes) in &bundle.files {
                cancel.check().map_err(|_| InstallError::Cancelled)?;
                let file = temp.join("files").join(path);
                ensure_dir(&self.root, file.parent().ok_or(InstallError::Invalid)?)?;
                write_new(&file, bytes)?;
                #[cfg(test)]
                self.checkpoint("file_written")?;
                sync_dir(file.parent().unwrap())?;
            }
            write_new(&temp.join("manifest.sig.json"), &bundle.envelope)?;
            write_new(&temp.join("authorization.sig.json"), index_bytes)?;
            #[cfg(test)]
            self.checkpoint("metadata_written")?;
            self.read_package(&temp, index, release)?;
            #[cfg(test)]
            self.checkpoint("stage_verified")?;
            sync_tree_dirs(&temp)?;
            fs::rename(&temp, &target)?;
            sync_dir(&releases)?;
            #[cfg(test)]
            self.checkpoint("stage_renamed")?;
            Ok(target)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp);
        }
        result
    }
    fn read_package(
        &self,
        dir: &Path,
        index: &AddonIndex,
        release: &AddonRelease,
    ) -> Result<VerifiedBundle, InstallError> {
        check_directory_chain(&self.root, dir)?;
        let envelope = read_file(
            &self.root,
            &dir.join("manifest.sig.json"),
            MAX_ADDON_ENVELOPE_BYTES as u64,
        )?;
        let manifest = release.verify_manifest(index.id(), &envelope, &self.keys)?;
        let mut files = BTreeMap::new();
        collect_files(
            &self.root,
            &dir.join("files"),
            &dir.join("files"),
            &mut files,
            &manifest,
        )?;
        self.verify_package(index, release, envelope, files)
    }
    /// What `installed_bundle` returns, from a test store (qualification).
    #[cfg(test)]
    pub(crate) fn open_for_test(&self, id: &str) -> Result<VerifiedBundle, InstallError> {
        self.open(id)
    }
    fn open(&self, id: &str) -> Result<VerifiedBundle, InstallError> {
        let dir = self.dir(id)?;
        if !dir.exists() {
            return Err(InstallError::NotInstalled);
        }
        let _lock = self.lock(id)?;
        let record = self.active(&dir)?;
        let package = dir.join("releases").join(&record.manifest);
        let index = patanyx_update::verify_addon_index(
            &read_file(
                &self.root,
                &package.join("authorization.sig.json"),
                MAX_ADDON_ENVELOPE_BYTES as u64,
            )?,
            &self.keys,
        )?;
        if index.id() != id {
            return Err(InstallError::Integrity);
        }
        let release = std::iter::once(index.current())
            .chain(index.rollback())
            .find(|r| patanyx_update::hex::encode(r.manifest_sha256()) == record.manifest)
            .ok_or(InstallError::Unauthorized)?;
        // No time check: already installed, authentic code remains usable offline.
        self.read_package(&package, &index, release)
    }
    fn active(&self, dir: &Path) -> Result<Active, InstallError> {
        let path = dir.join("active.json");
        if !path.exists() {
            return Err(InstallError::NotInstalled);
        }
        let active: Active = serde_json::from_slice(&read_file(&self.root, &path, 4096)?)
            .map_err(|_| InstallError::Integrity)?;
        if active.schema != 1
            || active.manifest.len() != 64
            || !active
                .manifest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(InstallError::Integrity);
        }
        Ok(active)
    }
    pub(crate) fn rollback(
        &self,
        id: &str,
        cancel: &Cancellation,
        authorize: impl FnOnce() -> bool,
    ) -> Result<(), InstallError> {
        let prepared = {
            let _lock = self.lock(id)?;
            let dir = self.dir(id)?;
            let bytes = read_file(&self.root, &dir.join("index.sig.json"), MAX_ADDON_ENVELOPE_BYTES as u64)?;
            let index = patanyx_update::verify_addon_index(&bytes, &self.keys)?;
            if !index.valid_at(now()?) {
                return Err(InstallError::ExpiredIndex);
            }
            let release = index.rollback().ok_or(InstallError::Unauthorized)?;
            let bundle = self.read_package(
                &dir.join("releases")
                    .join(patanyx_update::hex::encode(release.manifest_sha256())),
                &index,
                release,
            )?;
            self.prepare(bytes, ReleaseChoice::Rollback, bundle, None)?
        };
        self.activate(prepared, cancel, authorize)
    }
    pub(crate) fn uninstall(
        &self,
        id: &str,
        cancel: &Cancellation,
        authorize: impl FnOnce() -> bool,
    ) -> Result<(), InstallError> {
        let _lock = self.lock(id)?;
        let dir = self.dir(id)?;
        cancel.commit(|| {
            if !authorize() {
                return Err(InstallError::Unauthorized);
            }
            let active = dir.join("active.json");
            match fs::remove_file(&active) {
                Ok(()) => sync_dir(&dir)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(InstallError::Io),
            }
            Ok(())
        })?;
        // Do not delete the sequence register, even on uninstall/reinstall.
        let releases = dir.join("releases");
        if releases.exists() {
            check_directory_chain(&self.root, &releases)?;
            fs::remove_dir_all(releases)?;
        }
        Ok(())
    }
    fn prune(&self, dir: &Path, index: &AddonIndex) {
        let keep: Vec<_> = std::iter::once(index.current())
            .chain(index.rollback())
            .map(|r| patanyx_update::hex::encode(r.manifest_sha256()))
            .collect();
        if let Ok(entries) = fs::read_dir(dir.join("releases")) {
            for entry in entries.flatten() {
                if !keep
                    .iter()
                    .any(|k| entry.file_name() == std::ffi::OsStr::new(k))
                    && entry.file_type().is_ok_and(|t| t.is_dir())
                {
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
    }
}

/// The single host-facing entry point. No path, environment key or test key can
/// bypass the production ring. The host serves these immutable checked bytes.
pub(crate) fn installed_bundle(id: &str) -> Result<VerifiedBundle, InstallError> {
    InstallStore::production()?.open(id)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    schema: u32,
    manifest: String,
}

pub(super) fn now() -> Result<u64, InstallError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| InstallError::Invalid)?
        .as_secs())
}
fn nonce() -> Result<String, InstallError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| InstallError::Io)?;
    Ok(patanyx_update::hex::encode(&b))
}
fn refuse_link_if_present(path: &Path) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(InstallError::Integrity),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Io),
    }
}
/// No link and nothing but directories from `path` up to the install root.
/// Above the root are the system's and the person's own folders, where a
/// link is ordinary (on some Linux systems `/home` is one).
fn check_directory_chain(root: &Path, path: &Path) -> Result<(), InstallError> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() || !ancestor.starts_with(root) {
            break;
        }
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(InstallError::Integrity);
        }
    }
    Ok(())
}
fn ensure_dir(root: &Path, path: &Path) -> Result<(), InstallError> {
    if path.exists() {
        return check_directory_chain(root, path);
    }
    let parent = path.parent().ok_or(InstallError::Invalid)?;
    if parent.starts_with(root) {
        ensure_dir(root, parent)?;
    } else {
        // Above the install root: the application's own data folders.
        fs::create_dir_all(parent).map_err(|_| InstallError::Io)?;
    }
    match private_dir(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(InstallError::Io),
    }
    check_directory_chain(root, path)?;
    sync_dir(parent)
}
/// A directory only its owner can list: which add-ons are installed is
/// nobody else's business on a shared computer.
fn private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
fn read_file(root: &Path, path: &Path, cap: u64) -> Result<Vec<u8>, InstallError> {
    check_directory_chain(root, path.parent().ok_or(InstallError::Invalid)?)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > cap {
        return Err(InstallError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(InstallError::Integrity);
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > cap {
        return Err(InstallError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1 {
            return Err(InstallError::Integrity);
        }
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(InstallError::Integrity);
    }
    Ok(bytes)
}
fn collect_files(
    install_root: &Path,
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, Vec<u8>>,
    manifest: &AddonManifest,
) -> Result<(), InstallError> {
    check_directory_chain(install_root, dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| InstallError::Invalid)?
            .to_str()
            .ok_or(InstallError::Invalid)?
            .to_owned();
        #[cfg(windows)]
        let relative = relative.replace('\\', "/");
        if !valid_addon_path(&relative) || ty.is_symlink() {
            return Err(InstallError::Integrity);
        }
        if ty.is_dir() {
            if !manifest
                .files()
                .iter()
                .any(|f| f.path().starts_with(&format!("{relative}/")))
            {
                return Err(InstallError::Integrity);
            }
            collect_files(install_root, root, &path, out, manifest)?;
        } else {
            let file = manifest
                .files()
                .iter()
                .find(|f| f.path() == relative)
                .ok_or(InstallError::Integrity)?;
            if out
                .insert(relative, read_file(install_root, &path, file.size())?)
                .is_some()
            {
                return Err(InstallError::Integrity);
            }
        }
    }
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn atomic_record(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let dir = path.parent().ok_or(InstallError::Invalid)?;
    check_directory_chain(root, dir)?;
    refuse_link_if_present(path)?;
    let temp = dir.join(format!(".record-{}", nonce()?));
    let result = (|| {
        write_new(&temp, bytes)?;
        fs::rename(&temp, path)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn sync_dir(path: &Path) -> Result<(), InstallError> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn sync_tree_dirs(path: &Path) -> Result<(), InstallError> {
    for e in fs::read_dir(path)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            sync_tree_dirs(&e.path())?;
        }
    }
    sync_dir(path)
}

#[cfg(test)]
#[path = "addon_install_tests.rs"]
mod tests;
