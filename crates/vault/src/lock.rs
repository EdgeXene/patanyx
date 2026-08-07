//! One live process per vault.
//!
//! Two PATANYX instances open on the same vault is a data-loss shape, not a
//! curiosity. Each holds its own decrypted `VaultData`, and `save()` writes
//! the WHOLE payload; so whichever saves last silently discards everything
//! the other one did. No error, no conflict, no clue — the user simply finds
//! a password they added an hour ago is gone.
//!
//! The lock is held by an OS file lock on an open handle, NOT by a pid file.
//! That distinction is the whole design:
//!
//!   * a pid file survives a crash and locks the user out of their own vault
//!     until they find and delete it, which is a worse failure than the one
//!     being prevented;
//!   * an OS lock is released by the kernel when the process dies, however it
//!     dies, so a crash costs nothing.
//!
//! Advisory on unix (flock), mandatory on Windows (exclusive share mode).
//! Neither stops a determined program from editing the file behind our back —
//! this guards against the accident of running the app twice, which is the
//! thing that actually happens.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Held for as long as the vault is open. Dropping it releases the lock;
/// so does the process exiting for any reason.
#[derive(Debug)]
pub struct VaultLock {
    /// The lock lives on this handle. Never read or written — opening it and
    /// holding it IS the lock.
    _handle: File,
    path: PathBuf,
}

impl VaultLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Why a vault could not be locked.
#[derive(Debug)]
pub enum LockError {
    /// Another process holds it. Almost always a second copy of the app.
    Busy,
    /// The lock file could not be created or opened at all.
    Io(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Busy => write!(
                f,
                "this vault is already open in another PATANYX window"
            ),
            LockError::Io(e) => write!(f, "could not lock the vault: {e}"),
        }
    }
}

impl From<io::Error> for LockError {
    fn from(e: io::Error) -> Self {
        LockError::Io(e)
    }
}

/// A sidecar rather than the vault file itself.
///
/// Locking the vault directly would be tidier, but `save()` replaces that
/// file by atomic rename — the inode the lock was taken on stops being the
/// vault on the very first save, and the lock silently protects nothing. A
/// sidecar is never renamed, so it stays the same object for the whole
/// session.
fn lock_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// Takes the lock, or reports who has it.
pub fn acquire(vault_path: &Path) -> Result<VaultLock, LockError> {
    let path = lock_path(vault_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let handle = open_locked(&path)?;
    Ok(VaultLock {
        _handle: handle,
        path,
    })
}

#[cfg(unix)]
fn open_locked(path: &Path) -> Result<File, LockError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        // The lock file sits beside the vault and should be no more readable
        // than it is, even though it holds nothing.
        .mode(0o600)
        .open(path)?;
    // SAFETY: a valid fd we own for the duration of the call. LOCK_NB so a
    // second instance is told immediately rather than hanging on a lock the
    // first will not release until it exits.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code == libc::EWOULDBLOCK => Err(LockError::Busy),
            _ => Err(LockError::Io(err)),
        };
    }
    Ok(file)
}

#[cfg(windows)]
fn open_locked(path: &Path) -> Result<File, LockError> {
    use std::os::windows::fs::OpenOptionsExt;

    // share_mode(0) means no other handle may open this file at all, which is
    // Windows' native way to say "mine". No flock, no extra crate, and the
    // handle is closed by the OS when the process dies.
    match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(file),
        // ERROR_SHARING_VIOLATION (32) is exactly "someone else has it".
        Err(e) if e.raw_os_error() == Some(32) => Err(LockError::Busy),
        Err(e) => Err(LockError::Io(e)),
    }
}

impl From<LockError> for crate::VaultError {
    fn from(e: LockError) -> Self {
        match e {
            // A genuine I/O problem is reported as one; only contention
            // becomes `Locked`, so "the disk is full" never reads as
            // "another window has it".
            LockError::Io(io) => crate::VaultError::Io(io),
            LockError::Busy => crate::VaultError::Locked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "patanyx-lock-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The defect this exists for: two instances on one vault, where the
    /// second save silently discards everything the first one did.
    #[test]
    fn a_second_holder_is_refused() {
        let dir = Dir::new("second");
        let vault = dir.0.join("vault.rbv");
        let first = acquire(&vault).expect("first holder gets the lock");
        assert!(
            matches!(acquire(&vault), Err(LockError::Busy)),
            "a second holder must be refused, not queued behind the first"
        );
        drop(first);
    }

    /// Releasing must actually release, or closing one window locks the user
    /// out of their own vault until they reboot.
    #[test]
    fn dropping_the_lock_frees_it() {
        let dir = Dir::new("drop");
        let vault = dir.0.join("vault.rbv");
        let first = acquire(&vault).unwrap();
        drop(first);
        assert!(
            acquire(&vault).is_ok(),
            "the lock must be reusable once the holder lets go"
        );
    }

    /// Different vaults are independent. A shared lock would stop someone
    /// keeping a work vault and a personal vault open at once, which is a
    /// reasonable thing to do.
    #[test]
    fn separate_vaults_do_not_contend() {
        let dir = Dir::new("separate");
        let a = acquire(&dir.0.join("a.rbv")).unwrap();
        let b = acquire(&dir.0.join("b.rbv")).unwrap();
        drop((a, b));
    }

    /// The lock must NOT live on the vault file itself: `save()` replaces
    /// that by atomic rename, so a lock taken on it would stop describing the
    /// vault after the first save and would silently protect nothing.
    #[test]
    fn the_lock_is_a_sidecar_and_survives_a_vault_rewrite() {
        let dir = Dir::new("sidecar");
        let vault = dir.0.join("vault.rbv");
        let held = acquire(&vault).unwrap();
        assert_ne!(held.path(), vault, "the lock must not be the vault file");

        // Simulate what save() does: write a new file and rename it over.
        std::fs::write(dir.0.join("tmp"), b"new contents").unwrap();
        std::fs::rename(dir.0.join("tmp"), &vault).unwrap();

        assert!(
            matches!(acquire(&vault), Err(LockError::Busy)),
            "the lock must still be held after the vault file is replaced"
        );
        drop(held);
    }
}
