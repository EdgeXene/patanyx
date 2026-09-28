//! Retiring the leftover copies of a Library's version 1 file when its owner
//! changes the passphrase (2026-09-27).
//!
//! # Why
//!
//! A version 1 Library's data key is derived from the passphrase and the
//! file's salt, and the key does not change when the Library moves into the
//! vault (version 3): that is what keeps its pictures and download records
//! valid. So any copy of the version 1 file still opens with the passphrase
//! it was written under and, through the unchanged key, reads every later
//! version of the Library. The writer's crash leftovers are such copies: a
//! save that dies between writing its temporary file and the rename leaves
//! one that nothing overwrites, named `.tmp-<32 lowercase hex>`, or
//! `<library name>.tmp` from builds up to 1.0.2. A passphrase change removes
//! every one it can prove is a copy of this Library, and reports the rest.
//!
//! # What is removed
//!
//! Only an entry of the Library's directory with exactly one of those two
//! names, compared as bytes and never more broadly (a copy someone keeps
//! under another spelling is theirs to keep), opened without following a
//! symlink or blocking on a FIFO, that is a regular file, starts with this
//! store's magic, is version 1, and carries at least 8 bytes of its salt,
//! all equal to the salt recorded when the Library moved. A version 1
//! Library's salt never changes, so every copy of it carries that salt, and
//! a copy cut short inside the salt still counts: each missing byte costs
//! only 256 guesses. Fewer than 8 bytes prove nothing, since a chance match
//! is then no longer one in 2^64.
//!
//! Anything else shaped like a Library (a version 1 file not proven ours, a
//! version this build does not know) is kept, and the change reports it. A
//! version 3 file is never a candidate: it holds nothing a passphrase opens,
//! and the Library itself is version 3 whenever this runs, so it can never be
//! the file removed. A file that is not this store's, or that stops before
//! its salt, is kept silently.
//!
//! No other process of this build or later writes this Library meanwhile: the
//! app holds the Library lock for as long as the Library is open. Older builds
//! take no such lock (see `format.rs`). Nothing here defends
//! against a process that rewrites the directory between a file's check and
//! its removal (final review, R-003): whoever can do that can already delete
//! or replace any file in it, the Library included.

use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};

use crate::crypto::SALT_LEN;
use crate::error::StoreError;
use crate::format;

/// What an entry named like a leftover turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Leftover {
    /// A copy of this Library's version 1 file, whole or cut short: removed.
    Ours,
    /// Nothing a passphrase opens: kept, silently.
    Foreign,
    /// Shaped like a Library but not proven to be this one: kept, and
    /// reported.
    Unknown,
}

/// Where a version 1 header keeps its salt.
const V1_SALT_AT: usize = 20;
/// The fewest salt bytes whose match proves a copy is this Library's.
const MIN_SALT_PROOF: usize = 8;

/// Removes every leftover proven to be a copy of the version 1 file of the
/// Library at `library`, whose salt was `v1_salt`. `flush` is the directory
/// flush (`flush_dir`), passed in so a test can make it fail.
pub(crate) fn retire_leftovers(
    library: &Path,
    v1_salt: &[u8; SALT_LEN],
    flush: impl FnOnce() -> io::Result<()>,
) -> Result<(), StoreError> {
    let entries = match fs::read_dir(library_dir(library)) {
        Ok(entries) => entries.map(|entry| entry.map(|entry| (entry.file_name(), entry.path()))),
        Err(error) => return Err(retained(Some(error), 0)),
    };
    retire_entries(library, entries, |path| classify(v1_salt, path), flush)
}

/// The retirement proper, over a listing, a judgment and a directory flush
/// passed in, so a test can make any of them fail (the tests run as root,
/// where no permission ever refuses a read).
///
/// A failure on one entry does not stop the rest: the first error is kept,
/// every other entry is still judged, the directory is still flushed, and
/// the error is returned at the end, always as `LeftoversRetained`, so the
/// caller can never mistake it for a failure of the change itself.
pub(crate) fn retire_entries(
    library: &Path,
    entries: impl Iterator<Item = io::Result<(OsString, PathBuf)>>,
    classify: impl Fn(&Path) -> io::Result<Leftover>,
    flush: impl FnOnce() -> io::Result<()>,
) -> Result<(), StoreError> {
    let own = library.file_name();
    // 1.0.2's name, built as that writer built it: from bytes, so a Library
    // whose name is not UTF-8 has one too.
    let legacy = own.map(|name| {
        let mut legacy = name.to_os_string();
        legacy.push(".tmp");
        legacy
    });
    let mut first_error: Option<io::Error> = None;
    let mut unidentified = 0usize;
    for entry in entries {
        let (name, path) = match entry {
            Ok(entry) => entry,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        // Never the Library itself, whatever it is named.
        if Some(name.as_os_str()) == own {
            continue;
        }
        if legacy.as_deref() != Some(name.as_os_str()) && !name.to_str().is_some_and(is_temp_name) {
            continue;
        }
        let outcome = match classify(&path) {
            Ok(Leftover::Ours) => match fs::remove_file(&path) {
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                removed => removed,
            },
            Ok(Leftover::Foreign) => Ok(()),
            Ok(Leftover::Unknown) => {
                unidentified += 1;
                Ok(())
            }
            Err(error) => Err(error),
        };
        if let Err(error) = outcome {
            first_error.get_or_insert(error);
        }
    }
    // The removals must reach the disk before the change reports success: a
    // power cut before the directory is written back would bring back a file
    // the old passphrase opens. Flushed even when this pass removed nothing,
    // since only a flush that succeeds confirms an earlier pass's removals.
    if let Err(error) = flush() {
        first_error.get_or_insert(error);
    }
    if first_error.is_none() && unidentified == 0 {
        return Ok(());
    }
    Err(retained(first_error, unidentified))
}

/// The directory the Library lives in, `.` for a bare file name.
fn library_dir(library: &Path) -> PathBuf {
    match library.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Flushes the Library's directory under the strict rule
/// (`Store::confirm_durable`): a real failure is an error, a platform or
/// filesystem that cannot flush a directory at all is not.
pub(crate) fn flush_dir(library: &Path) -> io::Result<()> {
    match crate::sync_parent(library, crate::DirSync::Strict) {
        Err(StoreError::NotDurable(error)) => Err(error),
        _ => Ok(()),
    }
}

/// Why not every leftover could be confirmed gone. After a failed flush the
/// removed files are gone from the listing but not confirmed on disk, so the
/// wording claims no more than that.
fn retained(error: Option<io::Error>, unidentified: usize) -> StoreError {
    let mut parts = Vec::new();
    if unidentified > 0 {
        parts.push(format!(
            "{unidentified} file(s) shaped like a Library could not be proven to be this one \
             and were kept"
        ));
    }
    if let Some(error) = error {
        parts.push(format!(
            "the directory or a leftover could not be listed, read, removed or flushed: {error}"
        ));
    }
    StoreError::LeftoversRetained(parts.join("; "))
}

/// Exactly the writer's temporary name: `.tmp-` and 32 lowercase hex
/// (`temp_path_in`).
fn is_temp_name(name: &str) -> bool {
    name.strip_prefix(".tmp-").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Reads as much of an entry named like a leftover as its judgment needs.
fn classify(v1_salt: &[u8; SALT_LEN], path: &Path) -> io::Result<Leftover> {
    let Some(file) = open_leftover(path)? else {
        return Ok(Leftover::Foreign);
    };
    let mut head = Vec::with_capacity(V1_SALT_AT + SALT_LEN);
    file.take((V1_SALT_AT + SALT_LEN) as u64)
        .read_to_end(&mut head)?;
    Ok(judge(v1_salt, &head))
}

/// The judgment on the first bytes of an entry named like a leftover.
pub(crate) fn judge(v1_salt: &[u8; SALT_LEN], head: &[u8]) -> Leftover {
    if !format::has_known_magic(head) {
        return Leftover::Foreign;
    }
    match head.get(7) {
        None => Leftover::Foreign,
        Some(&format::VERSION) => {
            let salt = match head.get(V1_SALT_AT..) {
                Some(rest) if !rest.is_empty() => &rest[..rest.len().min(SALT_LEN)],
                _ => return Leftover::Foreign,
            };
            if salt.len() >= MIN_SALT_PROOF && v1_salt[..salt.len()] == *salt {
                Leftover::Ours
            } else {
                Leftover::Unknown
            }
        }
        Some(&format::VERSION_V3) => Leftover::Foreign,
        Some(_) => Leftover::Unknown,
    }
}

/// Opens a leftover for reading WITHOUT following a symlink and without
/// blocking on a FIFO, and only if what was opened is a regular file, so the
/// entry judged is the entry named. On unix both are flags of the open itself
/// and the type is read from the handle. Windows has neither flag, so there a
/// check just before the open refuses anything but a regular file; the window
/// between them is open only to someone who can already write to this
/// directory.
fn open_leftover(path: &Path) -> io::Result<Option<fs::File>> {
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => return Ok(None),
        Ok(_) => fs::File::open(path),
        Err(e) => Err(e),
    };
    match opened {
        Ok(file) => Ok(file.metadata()?.is_file().then_some(file)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        // A symlink (O_NOFOLLOW) or a socket: never a leftover of ours.
        #[cfg(unix)]
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENXIO)) => Ok(None),
        Err(e) => Err(e),
    }
}
