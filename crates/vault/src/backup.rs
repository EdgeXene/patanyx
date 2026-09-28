//! Rotating backups, export/import, plaintext export, and passphrase change
//! for the vault.
//!
//! # Backups are not recovery — read this before exposing any of it to a user
//!
//! Every backup and every encrypted export produced here is CIPHERTEXT. A
//! copy of an encrypted vault is still an encrypted vault: none of it can be
//! opened without the passphrase it was encrypted under. These mechanisms
//! exist to protect against a corrupted or interrupted write destroying the
//! only copy of the file, and — if the user keeps copies elsewhere — against
//! losing the machine. They do absolutely nothing for a forgotten
//! passphrase. The answer to a forgotten passphrase is the recovery key
//! ([`RecoveryKey`]), a second, independent unlock method created alongside
//! the vault — not a copy of it.
//!
//! UI and documentation must never present a backup or an export as
//! protection against a lost passphrase. That false confidence makes data
//! loss more likely, not less: a user who believes their backup covers a
//! forgotten passphrase will not write down the recovery key, and then loses
//! everything while several useless encrypted copies sit on disk.
//!
//! # What lives here
//!
//! - [`rotate_backups`]: bounded, timestamped copies of the vault file,
//!   taken before a save overwrites it, oldest pruned first.
//! - [`Vault::export_encrypted`] / [`Vault::import_encrypted`]: ciphertext
//!   under a passphrase chosen for the export, for moving to another
//!   machine. Import refuses to overwrite an existing vault.
//! - [`Vault::export_plaintext`]: the way out, deliberately awkward.
//! - [`Vault::change_passphrase`]: re-wraps the passphrase slot only; the
//!   contents and the recovery key are untouched.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::VaultError;
use crate::format::{self, SlotKind};
use crate::{atomic_write, is_temp_name, open_new_temp, RecoveryKey, Vault, VaultData};

// Note: these bounds duplicate the (private) sanity limits in
// `format.rs`. They MUST be checked before Argon2 runs, because an export
// header can only be authenticated after key derivation — an implausible
// m_cost would otherwise be a memory-exhaustion attack against import.
// `format::decode_params` is private to that module, so it cannot be reused
// from here without editing the provided file; hoisting both copies into
// one pub(crate) constant set is left to the reviewer.
const MIN_M_COST: u32 = 8;
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, in KiB
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 64;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 64;

/// How many timestamped copies of the vault file are kept by default.
/// Small on purpose: backups exist to survive a bad write, not to be an
/// archive, and an unbounded directory of ciphertext is clutter with no
/// security benefit.
pub const DEFAULT_MAX_BACKUPS: usize = 5;

/// Separator between the vault file name and the millisecond stamp, e.g.
/// `vault.rbv.bak-1705315845123`. The stamp — not file metadata — is what
/// pruning sorts by, so ordering survives copies across filesystems.
const BACKUP_SUFFIX: &str = ".bak-";

/// Errors from backup rotation. Kept separate from [`VaultError`] so a
/// backup failure is never silently folded into a vault-open failure.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("i/o error while rotating backups: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error while rotating backups: {0}")]
    Vault(#[from] VaultError),
}

/// Errors from export and import. Crypto failures stay coarse — a wrong
/// export passphrase must be indistinguishable from a tampered file, exactly
/// as the vault treats a wrong passphrase.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Coarse on purpose, mirroring `VaultError::AuthFailed`: anything the
    /// AEAD rejects lands here, never a more specific reason.
    #[error("wrong export passphrase, or the export file is corrupt or tampered")]
    AuthFailed,
    /// Structural problems detectable BEFORE any key derivation: bad magic,
    /// unsupported version, implausible KDF parameters, truncated file.
    #[error("file is not a PATANYX vault export: {0}")]
    BadExport(String),
    #[error(
        "plaintext export was not confirmed; the caller must pass \
         PLAINTEXT_EXPORT_CONFIRMATION verbatim"
    )]
    PlaintextNotConfirmed,
    #[error("refusing to overwrite the live vault file with an export")]
    TargetIsLiveVault,
    /// A plaintext export failed part-way AND the file it had started could
    /// not be wiped, so some passwords may remain readable under the name the
    /// user chose.
    #[error("the plaintext export failed and its partial file could not be wiped")]
    PlaintextMayRemain,
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Rotating backups
// ---------------------------------------------------------------------------

/// Copy the current vault file to a timestamped sibling, then prune older
/// copies so at most `max_backups` remain, oldest deleted first.
///
/// Call this BEFORE overwriting the vault: the point is that a corrupted or
/// interrupted write can never destroy the only good copy, because the
/// previous one survives next to it.
///
/// The copies are the vault's ciphertext byte-for-byte, so they are safe to
/// sit beside the vault — but remember (see module docs) that ciphertext is
/// all they are: they protect the file, not the passphrase.
///
/// Returns the path of the backup created, or `None` when there was nothing
/// to back up (first save) or when `max_backups` is 0. A 0 bound disables
/// backups entirely and — deliberately — leaves existing backups untouched
/// rather than deleting user data as a side effect of a config change.
pub fn rotate_backups(vault_path: &Path, max_backups: usize) -> Result<Option<PathBuf>, BackupError> {
    if max_backups == 0 || !vault_path.is_file() {
        return Ok(None);
    }
    // Ciphertext in, ciphertext out; nothing here is key material or
    // decrypted content, so no zeroizing is needed on this buffer.
    let bytes = fs::read(vault_path)?;
    let backup = fresh_backup_path(vault_path)?;
    // Same rules as the vault itself: atomic tmp+rename, 0600 on unix.
    atomic_write(&backup, &bytes)?;
    prune_backups(vault_path, max_backups)?;
    Ok(Some(backup))
}

fn vault_file_name(vault_path: &Path) -> Result<&str, BackupError> {
    vault_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "vault path has no usable file name",
            )
            .into()
        })
}

fn fresh_backup_path(vault_path: &Path) -> Result<PathBuf, BackupError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let fname = vault_file_name(vault_path)?;
    // Two saves in the same millisecond happen (tests do it deliberately);
    // bump the stamp rather than overwrite a backup that already exists.
    // Ordering — the only thing pruning relies on — is preserved.
    for bump in 0..1000u128 {
        let candidate =
            vault_path.with_file_name(format!("{fname}{BACKUP_SUFFIX}{}", millis + bump));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not find a free backup file name",
    )
    .into())
}

/// Remove EVERY backup of this vault. Called after a passphrase rotation: each
/// backup on disk is a byte copy of a file under the OLD passphrase, so the
/// UI's "the old passphrase no longer works" was false for up to five files
/// beside the vault (pentest F-002). The next ordinary save recreates one
/// under the new passphrase. `retired` is the passphrase slot the rotation
/// just replaced.
pub(crate) fn retire_backups(vault: &Vault, retired: &format::Slot) -> Result<(), BackupError> {
    retire_backups_with(vault.path(), |path| classify_leftover(vault, retired, path))
}

/// What an entry named like one of the writer's leftovers turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leftover {
    /// A copy of this vault, whole or cut short: retired.
    Ours,
    /// Holds nothing any passphrase opens: not a regular file, not a vault,
    /// or a fragment too short to hold a slot. Kept, silently.
    Foreign,
    /// Shaped like a vault but not proven to be a copy of this one. Kept, and
    /// the retirement reported as incomplete.
    Unknown,
}

/// `retire_backups`, with the judgement of each leftover passed in, so a test
/// can make it fail the way an unreadable file would: the tests run as root,
/// where no permission ever refuses a read.
fn retire_backups_with(
    vault_path: &Path,
    classify: impl Fn(&Path) -> std::io::Result<Leftover>,
) -> Result<(), BackupError> {
    let dir = vault_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let entries =
        fs::read_dir(&dir)?.map(|entry| entry.map(|entry| (entry.file_name(), entry.path())));
    retire_entries(vault_path, &dir, entries, classify)
}

/// The retirement proper, over a listing of `dir` passed in, so a test can
/// make the listing itself fail part-way.
fn retire_entries(
    vault_path: &Path,
    dir: &Path,
    entries: impl Iterator<Item = std::io::Result<(std::ffi::OsString, PathBuf)>>,
    classify: impl Fn(&Path) -> std::io::Result<Leftover>,
) -> Result<(), BackupError> {
    // EVERYTHING wearing the backup prefix, not only the stamped files
    // prune_backups counts: an interrupted backup write in a build up to
    // 1.0.2 left a complete ciphertext as `<name>.bak-<stamp>.tmp` (the
    // writer syncs before it renames), and that file opens with the old
    // passphrase just the same.
    //
    // And the writer's own leftovers. Since 2026-09-27 the writer's
    // temporary file is `.tmp-<32 hex>` (`crate::temp_path_in`), so a save or
    // a backup write that dies between creating it and the rename leaves a
    // copy of the vault that no prefix matches. So does the `<name>.tmp` an
    // older build left for the vault itself: those builds reused that name,
    // so the rotation's own save consumed it, and this writer never touches
    // it again. Such an entry is removed only when `classify_leftover` proves
    // it is a copy of THIS vault: the Library's writer leaves the same shape
    // of name in this same directory, and a name proves nothing about
    // ownership (final review, 2026-09-27). One that looks like a vault but
    // is not proven ours is kept and makes the retirement fail, as a removal
    // that fails does: success is never reported while a file a retired
    // passphrase may open is still here. So does a leftover that cannot be
    // read at all.
    //
    // Never the vault itself, even when it is named like a leftover (plan
    // review, 2026-09-27): it carries this vault's slots. No save of THIS
    // vault can be in flight: the rotation holds `&mut Vault` and the vault's
    // lock.
    //
    // A failure on one entry does not stop the rest: the first error is kept,
    // every other entry is still retired, the directory is still flushed, and
    // the error is returned at the end (compliance and final reviews,
    // 2026-09-27). Stopping at once let one unreadable leftover, listed first,
    // leave every backup in place.
    let name = vault_file_name(vault_path)?;
    let prefix = format!("{name}{BACKUP_SUFFIX}");
    let legacy_temp = format!("{name}.tmp");
    let mut first_error: Option<std::io::Error> = None;
    let mut unresolved = 0usize;
    for entry in entries {
        let (entry_name, path) = match entry {
            Ok(entry) => entry,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };
        let Some(entry_name) = entry_name.to_str() else {
            continue;
        };
        if entry_name == name {
            continue;
        }
        let outcome = if entry_name.starts_with(prefix.as_str()) {
            fs::remove_file(&path)
        } else if entry_name == legacy_temp || is_temp_name(entry_name) {
            classify(&path).and_then(|leftover| match leftover {
                Leftover::Ours => fs::remove_file(&path),
                Leftover::Foreign => Ok(()),
                Leftover::Unknown => {
                    unresolved += 1;
                    Ok(())
                }
            })
        } else {
            Ok(())
        };
        if let Err(error) = outcome {
            first_error.get_or_insert(error);
        }
    }
    // The deletions must reach the platter before "retired" is reported:
    // a power cut after the unlinks but before the directory is written
    // back would resurrect an old-passphrase file (review round 3, R-003).
    // Directory fsync is a Unix notion; Windows has no equivalent to call.
    #[cfg(unix)]
    {
        if let Err(error) = fs::File::open(dir).and_then(|handle| handle.sync_all()) {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error.into());
    }
    if unresolved > 0 {
        return Err(std::io::Error::other(format!(
            "{unresolved} file(s) beside the vault look like a vault but could not be \
             identified; they were kept"
        ))
        .into());
    }
    Ok(())
}

/// How much of a leftover is read to judge it. A copy of a vault is far
/// smaller; past this, only its slots are compared.
const LEFTOVER_READ_LIMIT: u64 = 64 << 20;

/// Decides whether an entry named like a leftover is a copy of `vault`.
///
/// A copy carries the vault's slots: every file this vault writes between two
/// rotations holds the same slot bytes, and the recovery slot outlives
/// rotations. So a leftover holding a slot byte-identical to one the vault
/// holds now, or to `retired`, is ours, even when a crash cut it short after
/// its header. A copy from before an EARLIER rotation may share no slot any
/// more, but a whole one still decrypts under the vault's master key, which
/// never changes. Anything else that looks like a vault is `Unknown`, whatever
/// sits beside it: a lock sidecar proves nothing, since opening a leftover
/// gives it one too (final reviews, 2026-09-27).
fn classify_leftover(
    vault: &Vault,
    retired: &format::Slot,
    path: &Path,
) -> std::io::Result<Leftover> {
    use std::io::{ErrorKind, Read};
    let Some(mut file) = open_leftover(path)? else {
        return Ok(Leftover::Foreign);
    };
    // The magic first, and nothing further unless it is a vault's: an
    // export's leftover can be plaintext. The buffer is wiped on drop all the
    // same (final review, 2026-09-27).
    let mut bytes = Zeroizing::new(vec![0u8; format::MAGIC.len()]);
    match file.read_exact(&mut bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(Leftover::Foreign),
        Err(e) => return Err(e),
    }
    if !format::has_known_magic(&bytes) {
        return Ok(Leftover::Foreign);
    }
    file.take(LEFTOVER_READ_LIMIT + 1 - bytes.len() as u64)
        .read_to_end(&mut bytes)?;
    // A slot cut short once its encrypted key has begun still exposes key
    // bytes to its passphrase (see `format::slot_prefixes_with_key_bytes`).
    // One that matches the start of a slot this vault holds, or the one just
    // retired, is a copy of it; key bytes that match nothing are kept and
    // reported rather than passed over as a fragment (review 2026-09-28,
    // full-diff R-001).
    let mut unmatched_key_bytes = false;
    if let Some(prefixes) = format::slot_prefixes_with_key_bytes(&bytes) {
        let known: Vec<Vec<u8>> = std::iter::once(retired)
            .chain(vault.slots_ref().iter())
            .map(format::Slot::encoded)
            .collect();
        if prefixes
            .iter()
            .any(|prefix| known.iter().any(|slot| slot.starts_with(prefix)))
        {
            return Ok(Leftover::Ours);
        }
        unmatched_key_bytes = !prefixes.is_empty();
    }
    match format::complete_slots(&bytes) {
        // No slot is complete. Without a single key byte nothing in it opens
        // with any passphrase; with key bytes that matched nothing above, it
        // is kept and reported.
        Some(slots) if slots.is_empty() => {
            return Ok(if unmatched_key_bytes {
                Leftover::Unknown
            } else {
                Leftover::Foreign
            })
        }
        Some(slots)
            if slots
                .iter()
                .any(|slot| slot == retired || vault.slots_ref().contains(slot)) =>
        {
            return Ok(Leftover::Ours)
        }
        _ => {}
    }
    if bytes.len() as u64 <= LEFTOVER_READ_LIMIT {
        if let Ok(header) = format::decode_header(&bytes) {
            let len = header.len();
            if len <= bytes.len()
                && crypto::decrypt(
                    vault.master_ref(),
                    &header.nonce,
                    &bytes[..len],
                    &bytes[len..],
                )
                .is_ok()
            {
                return Ok(Leftover::Ours);
            }
        }
    }
    Ok(Leftover::Unknown)
}

/// Opens a leftover for reading WITHOUT following a symlink and without
/// blocking on a FIFO, and only if what was opened is a regular file, so the
/// entry judged is the entry named (final review, 2026-09-27). On unix both
/// are flags of the open itself and the type is read from the handle. Windows
/// has neither flag, so there a check just before the open refuses anything
/// but a regular file; the window between them is open only to someone who
/// can already write to this directory.
fn open_leftover(path: &Path) -> std::io::Result<Option<fs::File>> {
    use std::io::ErrorKind;
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

fn prune_backups(vault_path: &Path, max_backups: usize) -> Result<(), BackupError> {
    let dir = vault_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let prefix = format!("{}{BACKUP_SUFFIX}", vault_file_name(vault_path)?);
    let mut stamped: Vec<(u128, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(prefix.as_str()) else {
            continue;
        };
        // Anything that is not exactly our naming scheme (the vault itself,
        // `.tmp` files, foreign files) is ignored, never deleted.
        let Ok(stamp) = rest.parse::<u128>() else { continue };
        stamped.push((stamp, entry.path()));
    }
    // Newest first; everything past the bound is pruned, so the survivors
    // are always the most recent copies.
    stamped.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in stamped.iter().skip(max_backups) {
        fs::remove_file(path)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Export file format (v1)
// ---------------------------------------------------------------------------
//
// Same primitives and the same layout discipline as the vault's own v1
// format, under a different magic so an export can never be mistaken for a
// vault (or vice versa):
//
// offset  size  field
// 0       7     magic = b"RBVEXPT"
// 7       1     version = 0x01
// 8       4     argon2 m_cost in KiB (u32 LE)
// 12      4     argon2 t_cost (u32 LE)
// 16      4     argon2 p_cost (u32 LE)
// 20      16    salt (OS RNG)
// 36      24    XChaCha20-Poly1305 nonce (OS RNG)
// 60      ..    ciphertext || 16-byte tag
//
// The whole 60-byte header is the AEAD AAD, so the version, the KDF
// parameters, and the salt are authenticated exactly like the vault's.
// Unlike the vault there are no slots and no master key: an export has
// exactly one unlock method (the export passphrase), so the payload is
// encrypted directly under the passphrase-derived key.

const EXPORT_MAGIC: &[u8; 7] = b"RBVEXPT";
const EXPORT_VERSION: u8 = 0x02;

/// Version 1 exports carried a bare `VaultData`. Version 2 wraps it in
/// [`ExportPayload`] so an export can also carry things that are not the
/// vault -- today, bookmarks.
///
/// Old exports STILL IMPORT: the decoder tries the envelope first and falls
/// back to a bare `VaultData`. A backup someone made months ago must not stop
/// working because the format grew, and the fallback is three lines.
const EXPORT_VERSION_V1: u8 = 0x01;

/// What an export carries.
///
/// `extra` is OPAQUE BYTES this crate never interprets. The vault crate does
/// not know what a bookmark is and must not learn: deciding what belongs in a
/// backup is application policy, and wiring `patanyx-store` in here would make
/// the vault depend on the thing it is meant to be independent of. The app
/// serialises whatever it wants carried and hands it over sealed.
#[derive(serde::Serialize, serde::Deserialize)]
struct ExportPayload {
    vault: VaultData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extra: Option<Vec<u8>>,
}
const EXPORT_HEADER_LEN: usize = 7 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 60

fn encode_export_header(
    params: &KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; EXPORT_HEADER_LEN] {
    let mut out = [0u8; EXPORT_HEADER_LEN];
    out[0..7].copy_from_slice(EXPORT_MAGIC);
    out[7] = EXPORT_VERSION;
    out[8..12].copy_from_slice(&params.m_cost.to_le_bytes());
    out[12..16].copy_from_slice(&params.t_cost.to_le_bytes());
    out[16..20].copy_from_slice(&params.p_cost.to_le_bytes());
    out[20..36].copy_from_slice(salt);
    out[36..60].copy_from_slice(nonce);
    out
}

fn decode_export_header(
    bytes: &[u8],
) -> Result<(KdfParams, [u8; SALT_LEN], [u8; NONCE_LEN]), ExportError> {
    if bytes.len() < EXPORT_HEADER_LEN {
        return Err(ExportError::BadExport(format!(
            "file too short: {} bytes, need at least {EXPORT_HEADER_LEN}",
            bytes.len()
        )));
    }
    if &bytes[0..7] != EXPORT_MAGIC {
        return Err(ExportError::BadExport("bad magic".into()));
    }
    // v1 and v2 are both accepted. A backup made before the format grew must
    // keep working; refusing it would mean the only copy of someone's
    // credentials became unreadable because we added a field.
    if bytes[7] != EXPORT_VERSION && bytes[7] != EXPORT_VERSION_V1 {
        return Err(ExportError::BadExport(format!(
            "unsupported export version {:#04x}",
            bytes[7]
        )));
    }
    let params = KdfParams {
        m_cost: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        t_cost: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        p_cost: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
    };
    // Bounds BEFORE Argon2, for the same reason `format.rs` does it: the
    // header is only authenticated after derivation, so a tampered m_cost is
    // otherwise a denial of service.
    if !(MIN_M_COST..=MAX_M_COST).contains(&params.m_cost)
        || !(MIN_T_COST..=MAX_T_COST).contains(&params.t_cost)
        || !(MIN_P_COST..=MAX_P_COST).contains(&params.p_cost)
    {
        return Err(ExportError::BadExport(format!(
            "implausible kdf parameters m={} t={} p={}",
            params.m_cost, params.t_cost, params.p_cost
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[20..36]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[36..60]);
    Ok((params, salt, nonce))
}

// ---------------------------------------------------------------------------
// Export, import, plaintext export, passphrase change
// ---------------------------------------------------------------------------

/// The exact string a caller must pass to [`Vault::export_plaintext`] as
/// `confirmation`. The intended flow is that the UI shows this sentence to
/// the user and has them affirm it; a checkbox the caller ignores is not a
/// confirmation.
/// Refuses a destination that resolves to the live vault file.
///
/// `Path` equality is component-wise, so `..` traversal and symlinks both
/// slipped past a bare `dest == vault` comparison — and the destination is a
/// free-text field pre-filled with a SIBLING of the vault, so typing a path in
/// the vault's own directory is the expected flow rather than an exotic
/// mistake. Getting past it overwrote the vault with the export: irreversible
/// data loss, and for the plaintext export it also wrote every password in
/// cleartext into the file the user believed was their encrypted vault.
///
/// Both paths are resolved before comparison. The vault always exists (we have
/// it open). The destination usually does not, so its PARENT is resolved and
/// the file name compared — which is what catches `sub/../vault.rbv`. An
/// existing destination is resolved directly, which is what catches a symlink
/// pointing at the vault.
fn refuse_live_vault(dest: &Path, vault: &Path) -> Result<(), ExportError> {
    if dest == vault {
        return Err(ExportError::TargetIsLiveVault);
    }
    let Ok(real_vault) = vault.canonicalize() else {
        // The vault is open, so this should rarely happen; one way it does is
        // unlocking through a symlink that is removed while the vault stays
        // open. Without the vault's real location nothing here can tell
        // whether `dest` is the live vault, so the export is refused rather
        // than allowed on the strength of a failed syscall (review R-046,
        // 2026-09-28; this used to return Ok).
        return Err(ExportError::Io(std::io::Error::other(
            "could not resolve the live vault's location to check the export destination",
        )));
    };
    if let Ok(real_dest) = dest.canonicalize() {
        // Destination exists: a symlink or hardlink alias resolves here.
        if real_dest == real_vault {
            return Err(ExportError::TargetIsLiveVault);
        }
        return Ok(());
    }
    // Destination does not exist yet: resolve the directory it would be
    // created in, which normalises any `..` in the path.
    let (Some(parent), Some(name)) = (dest.parent(), dest.file_name()) else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    if let Ok(real_parent) = parent.canonicalize() {
        if real_parent.join(name) == real_vault {
            return Err(ExportError::TargetIsLiveVault);
        }
    }
    Ok(())
}

/// Creates any missing folders on the way to `dest`, THEN refuses a
/// destination that resolves to the live vault.
///
/// The order is the point (plan-gate R-043, 2026-09-28). `refuse_live_vault`
/// resolves `dest`'s parent, and a parent that does not exist yet cannot be
/// resolved, so the check used to fall through to "allowed": a typed
/// `newdir/../vault.rbv` passed, the writer created `newdir`, and the write
/// landed on the live vault. With the folders created first, every parent
/// resolves and the comparison is real. A refused export can leave the new
/// empty folders behind; that is the cost of checking the path that will
/// actually be written.
fn prepare_export_dest(dest: &Path, vault: &Path) -> Result<(), ExportError> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    refuse_live_vault(dest, vault)
}

/// A fault only tests inject into [`write_plaintext_export`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum PlainFault {
    #[default]
    None,
    /// Half the bytes are written, then the write fails, the way a full disk
    /// would.
    Write,
    /// Every byte is written, then the flush fails.
    Sync,
    /// The write fails part-way AND wiping the file afterwards fails too.
    WriteAndWipe,
    /// Half the bytes are written and flushed, then the process dies (only
    /// ever set inside a child process by a test).
    Abort,
}

/// Test-only fault points for [`write_plaintext_export`]; production passes
/// the default, which does nothing.
#[derive(Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PlainHooks<'a> {
    pub(crate) fault: PlainFault,
    /// Runs after the destination was checked and before its name is cleared.
    pub(crate) after_prepare: Option<&'a dyn Fn(&Path)>,
    /// Runs after `dest` is cleared and before it is created.
    pub(crate) after_clear: Option<&'a dyn Fn(&Path)>,
    /// Runs after `dest` is created and before the first byte is written.
    pub(crate) after_create: Option<&'a dyn Fn(&Path)>,
}

/// Writes a plaintext export straight into `dest`, never through a temporary
/// file.
///
/// 1. Clears the name WITHOUT following a link: an existing regular file or
///    symlink at `dest` is unlinked, which removes that name only (a link's
///    target, and a hard link's other names, are never touched). A directory
///    or anything else there is refused before anything is written.
/// 2. Creates `dest` with `create_new` and mode 0600 on unix. If anything
///    appeared at the name after step 1, creation fails and it is left alone.
/// 3. Writes every byte and flushes. On a failure it wipes its OWN file
///    through the handle it holds (truncate to zero, flush) and never deletes
///    by name, because the name may by then belong to another export
///    (plan-gate R-042). If even the wipe fails, the error says plaintext may
///    remain (R-044).
/// 4. Flushes the folder best effort (unix), as the shared writer does.
///
/// Not atomic, by decision: the old file is gone before the new one is
/// complete, and a process that dies part-way leaves a partial file under the
/// visible name the user chose.
fn write_plaintext_export(
    dest: &Path,
    vault: &Path,
    bytes: &[u8],
    hooks: &PlainHooks<'_>,
) -> Result<(), ExportError> {
    if let Some(hook) = hooks.after_prepare {
        hook(dest);
    }
    match fs::symlink_metadata(dest) {
        Ok(meta) => {
            let kind = meta.file_type();
            if kind.is_file() {
                // Re-check right before the unlink (review R-045): the name is
                // resolved again here, and a folder on the way to it may have
                // changed since `prepare_export_dest` checked it. A regular
                // file that resolves to the live vault is never removed.
                refuse_live_vault(dest, vault)?;
                fs::remove_file(dest)?;
            } else if kind.is_symlink() {
                // Removes the link itself, never its target. A link that
                // `remove_file` cannot remove (on Windows, a link to a folder)
                // fails the export instead of falling back to a directory
                // removal, which could delete a real folder swapped in after
                // the check (review 2026-09-28, round 2).
                fs::remove_file(dest)?;
            } else {
                return Err(ExportError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "the export destination is a folder or special file",
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(hook) = hooks.after_clear {
        hook(dest);
    }
    let mut file = open_new_temp(dest)?;
    if let Some(hook) = hooks.after_create {
        hook(dest);
    }
    if let Err(error) = write_and_flush(&mut file, bytes, hooks.fault) {
        let wiped = if hooks.fault == PlainFault::WriteAndWipe {
            Err(std::io::Error::other("injected failure wiping the export"))
        } else {
            file.set_len(0).and_then(|()| file.sync_all())
        };
        return Err(match wiped {
            Ok(()) => ExportError::Io(error),
            Err(_) => ExportError::PlaintextMayRemain,
        });
    }
    drop(file);
    #[cfg(unix)]
    {
        let dir = match dest.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if let Ok(handle) = fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

fn write_and_flush(file: &mut fs::File, bytes: &[u8], fault: PlainFault) -> std::io::Result<()> {
    use std::io::Write;
    match fault {
        PlainFault::Write | PlainFault::WriteAndWipe => {
            file.write_all(&bytes[..bytes.len() / 2])?;
            return Err(std::io::Error::other(
                "injected failure part-way through the export",
            ));
        }
        PlainFault::Abort => {
            file.write_all(&bytes[..bytes.len() / 2])?;
            let _ = file.sync_all();
            std::process::abort();
        }
        PlainFault::None | PlainFault::Sync => {}
    }
    file.write_all(bytes)?;
    if fault == PlainFault::Sync {
        return Err(std::io::Error::other(
            "injected failure at the export's flush",
        ));
    }
    file.sync_all()
}

pub const PLAINTEXT_EXPORT_CONFIRMATION: &str =
    "I understand my passwords will be readable in this file";

impl Vault {
    /// Export the vault's contents encrypted under `export_passphrase`,
    /// chosen by the user for this export and independent of the vault's own
    /// passphrase, for moving the vault to another machine.
    ///
    /// The result is ciphertext (Argon2id + XChaCha20-Poly1305, header bound
    /// as AAD — the same primitives as the vault itself), written atomically
    /// with mode 0600 on unix. It is safe to carry on a USB stick. It is
    /// NOT a form of recovery: forgetting the export passphrase makes the
    /// export exactly as unreadable as a vault whose passphrase is gone, and
    /// an export made from a vault you can no longer open is impossible.
    ///
    /// An existing file at `dest` is replaced — an export is a disposable
    /// copy, and "save over my last export" is expected behaviour. The one
    /// hard refusal is `dest` being the live vault file itself, which would
    /// replace the vault with something `Vault::unlock` cannot read.
    pub fn export_encrypted(&self, dest: &Path, export_passphrase: &str) -> Result<(), ExportError> {
        self.export_encrypted_with(dest, export_passphrase, None)
    }

    /// As [`Vault::export_encrypted`], plus opaque bytes carried alongside.
    ///
    /// `extra` is never interpreted here -- see [`ExportPayload`]. The app
    /// decides what belongs in a backup; this crate only seals it under the
    /// same key and authenticates it with the same header.
    pub fn export_encrypted_with(
        &self,
        dest: &Path,
        export_passphrase: &str,
        extra: Option<&[u8]>,
    ) -> Result<(), ExportError> {
        prepare_export_dest(dest, self.path())?;
        // The export reuses the vault's KDF parameters: they were chosen for
        // this threat model already, and the header authenticates them.
        let params = self.kdf_params();
        let salt: [u8; SALT_LEN] = crypto::random_bytes();
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes();
        let key = crypto::derive_key(export_passphrase.as_bytes(), &salt, &params)?;
        let header = encode_export_header(&params, &salt, &nonce);
        // Built fully in memory and written once; no intermediate file ever
        // holds the serialized contents.
        let payload = ExportPayload {
            vault: self.data_ref().clone(),
            extra: extra.map(<[u8]>::to_vec),
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|e| VaultError::Crypto(format!("json encode: {e}")))?,
        );
        let ciphertext = crypto::encrypt(&key, &nonce, &header, &plaintext[..])?;
        let mut out = Vec::with_capacity(header.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        atomic_write(dest, &out)?;
        Ok(())
    }

    /// Import an encrypted export as a NEW vault at `dest`.
    ///
    /// REPLACES any vault already there, and does so silently at this layer.
    /// It used to refuse outright, which made the import form impossible to
    /// offer on a machine that already had a vault -- what was asked for
    /// the control to exist and for the warning to live in the UI instead,
    /// where the person can read it before deciding.
    ///
    /// So the refusal moved, it did not disappear: the panel states plainly
    /// that importing replaces the current vault and that everything in it is
    /// lost. Nothing here can make that reversible, which is exactly why the
    /// sentence belongs next to the button rather than in this doc comment.
    ///
    /// The imported vault is a fresh vault, not a copy of the source file:
    /// new master key, new passphrase slot wrapped under
    /// `new_vault_passphrase`, and a newly minted recovery key, which is
    /// returned and must be shown to the user exactly once, the same as at
    /// creation. The new vault's KDF parameters are taken from the export's
    /// (authenticated) header. After import, the export passphrase opens
    /// nothing except the export file.
    pub fn import_encrypted(
        src: &Path,
        dest: &Path,
        export_passphrase: &str,
        new_vault_passphrase: &str,
    ) -> Result<(Vault, RecoveryKey, Option<Vec<u8>>), ExportError> {
        let bytes = fs::read(src)?;
        let (params, salt, nonce) = decode_export_header(&bytes)?;
        if bytes.len() < EXPORT_HEADER_LEN + 16 {
            return Err(ExportError::BadExport(
                "file ends after header: no ciphertext/tag".into(),
            ));
        }
        let key = crypto::derive_key(export_passphrase.as_bytes(), &salt, &params)?;
        // Every AEAD failure collapses to AuthFailed: no oracle.
        let plaintext = crypto::decrypt(
            &key,
            &nonce,
            &bytes[..EXPORT_HEADER_LEN],
            &bytes[EXPORT_HEADER_LEN..],
        )
        .map_err(|_| ExportError::AuthFailed)?;
        // v2 wraps the vault in an envelope; v1 was a bare VaultData. Try the
        // envelope, fall back, so an older backup still opens.
        let (data, extra) = match serde_json::from_slice::<ExportPayload>(&plaintext) {
            Ok(payload) => (payload.vault, payload.extra),
            Err(_) => (Vault::parse_payload(&plaintext)?, None),
        };
        // `plaintext` (Zeroizing) wipes itself here.

        let master = Zeroizing::new(crypto::random_bytes::<KEY_LEN>());
        let mut vault = Vault::assemble(dest.to_path_buf(), master, params, data)?;
        let passphrase_slot =
            vault.build_slot(SlotKind::Passphrase, new_vault_passphrase.as_bytes(), &[])?;
        vault.push_slot(passphrase_slot);
        let recovery = RecoveryKey::generate();
        let recovery_slot = vault.build_slot(SlotKind::Recovery, recovery.as_bytes(), &[])?;
        vault.push_slot(recovery_slot);
        vault.save()?;
        Ok((vault, recovery, extra))
    }

    /// Export the entire vault — every password, every note body — as
    /// PLAIN, UNENCRYPTED JSON.
    ///
    /// This exists so users can leave: holding people's data hostage behind
    /// an encrypted format is not a privacy feature. It is deliberately
    /// awkward to call: `confirmation` must be exactly
    /// [`PLAINTEXT_EXPORT_CONFIRMATION`], and anything else is an error
    /// BEFORE any file is touched.
    ///
    /// The moment this returns `Ok`, the user's passwords are sitting in a
    /// readable file on disk, visible to anyone who can read that file, to
    /// backups of it, to search indexers, and to whatever the disk retains
    /// after deletion. The file is written directly under the chosen name,
    /// created fresh with mode 0600 on unix, and never through a temporary
    /// file (see [`write_plaintext_export`]); 0600 does not make plaintext
    /// safe — it only narrows who can read it on this machine. Callers must say all of this to the user in
    /// plain language, and should encourage deleting the file once it has
    /// served its purpose.
    pub fn export_plaintext(&self, dest: &Path, confirmation: &str) -> Result<(), ExportError> {
        self.export_plaintext_with(dest, confirmation, &PlainHooks::default())
    }

    /// [`Vault::export_plaintext`] with the fault points only tests set.
    pub(crate) fn export_plaintext_with(
        &self,
        dest: &Path,
        confirmation: &str,
        hooks: &PlainHooks<'_>,
    ) -> Result<(), ExportError> {
        if confirmation != PLAINTEXT_EXPORT_CONFIRMATION {
            return Err(ExportError::PlaintextNotConfirmed);
        }
        prepare_export_dest(dest, self.path())?;
        // Serialized in memory and written once, straight into `dest`
        // (since 1.0.3). Up to 1.0.2 the write went through
        // a visible `<dest>.tmp`; the hardened shared writer then used a new
        // hidden `.tmp-<hex>` beside `dest`, and a process that died between
        // creating that file and renaming it left every password in plain
        // text under a name nobody would look for. Plaintext now never exists
        // under any name but the one the user chose, so an interrupted export
        // leaves at most a partial file THERE, where they can see it.
        //
        // KEY MATERIAL IS OMITTED. This exports what the user consented to —
        // "my passwords will be readable in this file" — and nothing else.
        // Serializing `VaultData` wholesale also wrote every per-contact
        // X25519 private key and the long-term chat identity secret in
        // cleartext, because `ContactBook`'s Serialize goes through the
        // at-rest record type that deliberately includes `our_secret`. The
        // per-`Contact` skip_serializing guard covers every UI path and does
        // not cover that one. Nothing in the confirmation sentence or the UI
        // mentions chat keys, and a file that hands over the ability to
        // impersonate someone to all their contacts is not what "readable
        // passwords" means.
        let plaintext = Zeroizing::new(
            serde_json::to_vec_pretty(&self.data_ref().to_plaintext_export())
                .map_err(|e| VaultError::Crypto(format!("json encode: {e}")))?,
        );
        write_plaintext_export(dest, self.path(), &plaintext[..], hooks)?;
        // `plaintext` wipes itself on drop.
        Ok(())
    }

    /// Change the vault's passphrase.
    ///
    /// This is a slot operation, made possible by the v2 format: the
    /// contents are encrypted under a random master key that never changes,
    /// so the passphrase slot is simply re-wrapped under a key derived from
    /// the new passphrase. The contents are NOT re-encrypted (this is fast
    /// even for a large vault) and the recovery slot is NOT touched — a
    /// recovery key written down before the change keeps working after it,
    /// which is the whole point of storing it on paper in a drawer.
    ///
    /// `current` must open an existing passphrase slot, or the error is
    /// [`VaultError::AuthFailed`] and nothing changes. Only after the new
    /// slot is built does anything get replaced, and the change is durable
    /// only once the save succeeds; the old passphrase keeps working until
    /// then. KDF parameters are kept as stored in the vault.
    pub fn change_passphrase(&mut self, current: &str, new: &str) -> Result<(), VaultError> {
        let prefix = format::slot_bound_prefix(&self.kdf_params());
        // Verify `current` against a passphrase slot by unwrapping it and
        // confirming the unwrapped key IS this vault's master key. Success
        // of the AEAD already proves the passphrase was right; comparing
        // against the in-memory master additionally proves this slot belongs
        // to this vault.
        let mut matched: Option<usize> = None;
        for (index, slot) in self.slots_ref().iter().enumerate() {
            if slot.kind != SlotKind::Passphrase {
                continue;
            }
            let slot_key = Self::derive_slot_key(
                SlotKind::Passphrase,
                current.as_bytes(),
                &slot.salt,
                &self.kdf_params(),
            )?;
            let aad = format::slot_aad(&prefix, slot);
            if let Ok(unwrapped) = crypto::decrypt(&slot_key, &slot.nonce, &aad, &slot.wrapped) {
                if unwrapped.len() == KEY_LEN && unwrapped[..] == self.master_ref()[..] {
                    matched = Some(index);
                    break;
                }
            }
        }
        // A wrong current passphrase is indistinguishable from tampering,
        // exactly like unlock.
        let index = matched.ok_or(VaultError::AuthFailed)?;
        let new_slot = self.build_slot(SlotKind::Passphrase, new.as_bytes(), &[])?;
        // ROLLBACK-SAFE, and WITHOUT a backup of the old file. The slot used
        // to be replaced and then saved with no way back: a failed save left
        // memory under the new passphrase and disk under the old, and the
        // next successful save silently committed a change the UI had
        // reported as failed (pentest F-004). And the ordinary save copies
        // the old file to a backup first, which after a rotation is a
        // complete vault under the passphrase the user just retired
        // (pentest F-002).
        let old_slot = self.slots_ref()[index].clone();
        self.replace_slot(index, new_slot);
        if let Err(e) = self.save_inner(false) {
            self.replace_slot(index, old_slot);
            return Err(e);
        }
        // Retirement failing is NOT success: the rotation is committed and
        // consistent, but a file the old passphrase opens is still beside the
        // vault. Reported as its own outcome, never swallowed into
        // last_backup_error where the next ordinary save would erase it.
        match retire_backups(self, &old_slot) {
            Ok(()) => {
                self.last_backup_error = None;
                Ok(())
            }
            Err(e) => Err(VaultError::BackupsRetained(e.to_string())),
        }
    }

    /// Mint a recovery key for a vault that has none, and return it once.
    ///
    /// WHY THIS EXISTS. A recovery key was only ever obtainable at two moments:
    /// when the vault was created, and when an old-format vault was migrated.
    /// Both show it exactly once. Miss either -- close the window, look away,
    /// upgrade from a build that predated the feature -- and there was no way
    /// to get one, ever. `has_recovery` existed solely so the panel could tell
    /// you that you had no safety net, and then offer nothing to do about it.
    ///
    /// Possible at all because the contents are encrypted under a random
    /// master key rather than under a passphrase-derived one: adding an unlock
    /// method is adding a slot that wraps the same master, so nothing is
    /// re-encrypted and no stored data is touched.
    ///
    /// THE CURRENT PASSPHRASE IS REQUIRED even though the vault is already
    /// open. What this creates is a permanent second credential that unlocks
    /// everything, so it must not be something a person who walks up to an
    /// unattended unlocked browser can mint and pocket. That is the same threat
    /// the idle auto-lock exists for, and re-authenticating costs one field.
    ///
    /// Refuses when a recovery key already exists rather than silently issuing
    /// a second one: two live keys where the user believes there is one is a
    /// worse position than the one they started in.
    pub fn add_recovery(&mut self, passphrase: &str) -> Result<RecoveryKey, VaultError> {
        if self.has_recovery() {
            return Err(VaultError::AlreadyExists(self.path().to_path_buf()));
        }
        // Same verification as change_passphrase: unwrap a passphrase slot and
        // confirm what comes out IS this vault's master key. AEAD success alone
        // proves the passphrase; the comparison proves the slot is ours.
        let prefix = format::slot_bound_prefix(&self.kdf_params());
        let mut ok = false;
        for slot in self.slots_ref() {
            if slot.kind != SlotKind::Passphrase {
                continue;
            }
            let slot_key = Self::derive_slot_key(
                SlotKind::Passphrase,
                passphrase.as_bytes(),
                &slot.salt,
                &self.kdf_params(),
            )?;
            let aad = format::slot_aad(&prefix, slot);
            if let Ok(unwrapped) = crypto::decrypt(&slot_key, &slot.nonce, &aad, &slot.wrapped) {
                if unwrapped.len() == KEY_LEN && unwrapped[..] == self.master_ref()[..] {
                    ok = true;
                    break;
                }
            }
        }
        if !ok {
            return Err(VaultError::AuthFailed);
        }

        let recovery = RecoveryKey::generate();
        let slot = self.build_slot(SlotKind::Recovery, recovery.as_bytes(), &[])?;
        self.push_slot(slot);
        // Saved BEFORE the key is handed back. If the write fails the caller
        // gets an error and no key -- rather than a key the user writes down
        // that unlocks nothing, which is the worst of the available outcomes.
        self.save()?;
        Ok(recovery)
    }

    /// Whether `passphrase` opens one of this vault's passphrase slots AND
    /// what comes out is this vault's master key: the same check
    /// `change_passphrase` and `add_recovery` make, for a caller that needs
    /// the current passphrase confirmed without changing anything (the
    /// Library repair step). Writes nothing.
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool, VaultError> {
        let prefix = format::slot_bound_prefix(&self.kdf_params());
        for slot in self.slots_ref() {
            if slot.kind != SlotKind::Passphrase {
                continue;
            }
            let slot_key = Self::derive_slot_key(
                SlotKind::Passphrase,
                passphrase.as_bytes(),
                &slot.salt,
                &self.kdf_params(),
            )?;
            let aad = format::slot_aad(&prefix, slot);
            if let Ok(unwrapped) = crypto::decrypt(&slot_key, &slot.nonce, &aad, &slot.wrapped) {
                if unwrapped.len() == KEY_LEN && unwrapped[..] == self.master_ref()[..] {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    fn rekey_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("patanyx-vault-rekey-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault.rbv")
    }
    /// Where `lock.rs` puts a vault's lock sidecar: `<path>.lock`.
    fn sidecar_of(path: &std::path::Path) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        std::path::PathBuf::from(name)
    }
    fn backups_of(path: &std::path::Path) -> Vec<std::path::PathBuf> {
        let prefix = format!("{}{BACKUP_SUFFIX}", path.file_name().unwrap().to_str().unwrap());
        let mut v: Vec<std::path::PathBuf> = std::fs::read_dir(path.parent().unwrap()).unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(&prefix)))
            .collect();
        v.sort();
        v
    }

    /// Pentest F-002. A rotation leaves NO backup that the old passphrase
    /// opens, and creates none of its own.
    #[test]
    fn a_passphrase_rotation_retires_every_old_passphrase_backup() {
        let path = rekey_path("retire");
        let (mut vault, _rk) = crate::Vault::create(&path, "old-pass").unwrap();
        vault.save().unwrap();
        vault.save().unwrap();
        assert!(!backups_of(&path).is_empty(), "precondition: backups exist under the old passphrase");
        // An interrupted backup write: a complete old-passphrase ciphertext
        // under a .tmp name, which the stamped-only pruning walked past.
        let leftover = path.with_file_name(format!("vault.rbv{BACKUP_SUFFIX}1700000000000.tmp"));
        std::fs::copy(&path, &leftover).unwrap();
        vault.change_passphrase("old-pass", "new-pass").unwrap();
        assert!(backups_of(&path).is_empty(), "a backup under the old passphrase survived the rotation");
        assert!(!leftover.exists(), "a .tmp backup under the old passphrase survived the rotation");
        drop(vault); // one process per vault: release before reopening
        let reopened = crate::Vault::unlock(&path, "new-pass");
        assert!(reopened.is_ok(), "the new passphrase must open the vault");
        drop(reopened);
        assert!(crate::Vault::unlock(&path, "old-pass").is_err(), "the old passphrase still opens the vault");
    }

    /// Review R-001. If a backup cannot be removed, the rotation is still
    /// committed (new passphrase opens the vault) but it is reported as
    /// BackupsRetained, never as plain success.
    #[test]
    fn a_rotation_that_cannot_retire_a_backup_says_so() {
        let path = rekey_path("retained");
        let (mut vault, _rk) = crate::Vault::create(&path, "old-pass").unwrap();
        vault.save().unwrap();
        // A directory wearing a backup's name: remove_file refuses it.
        let stuck = path.with_file_name(format!("vault.rbv{BACKUP_SUFFIX}1"));
        std::fs::create_dir(&stuck).unwrap();
        let outcome = vault.change_passphrase("old-pass", "new-pass");
        assert!(matches!(outcome, Err(crate::VaultError::BackupsRetained(_))), "got {outcome:?}");
        drop(vault);
        assert!(crate::Vault::unlock(&path, "new-pass").is_ok(), "the rotation must still be committed");
        let _ = std::fs::remove_dir(&stuck);
    }

    /// The Library opens with the vault (2026-09-27): its key must survive a
    /// passphrase change and come out the same after a recovery-key unlock,
    /// or a change would lock the Library; and it must differ per vault.
    #[test]
    fn the_library_key_outlives_a_passphrase_change_and_follows_the_recovery_key() {
        let path = rekey_path("library-key");
        let (mut vault, recovery) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        let before = vault.library_key().unwrap();
        vault.change_passphrase("old-pass", "new-pass").unwrap();
        assert_eq!(
            *vault.library_key().unwrap(),
            *before,
            "a change moved the Library key"
        );
        drop(vault);
        let reopened = crate::Vault::unlock(&path, "new-pass").unwrap();
        assert_eq!(*reopened.library_key().unwrap(), *before);
        drop(reopened);
        let recovered = crate::Vault::unlock_with_recovery(&path, &recovery).unwrap();
        assert_eq!(
            *recovered.library_key().unwrap(),
            *before,
            "the recovery key reaches another key"
        );
        drop(recovered);

        let other = rekey_path("library-key-other");
        let (other_vault, _) =
            crate::Vault::create_with_params(&other, "old-pass", 8192, 1, 1).unwrap();
        assert_ne!(
            *other_vault.library_key().unwrap(),
            *before,
            "two vaults share a Library key"
        );
    }

    /// Pentest F-002 under the writer's new names (2026-09-27). A save or a
    /// backup write that died between creating its temporary file and the
    /// rename leaves a vault copy named `.tmp-<hex>`, which no backup prefix
    /// matches; a build up to 1.0.2 left `vault.rbv.tmp`, which this writer
    /// never reuses. The rotation retires them all, including one cut short
    /// after its header and one somebody opened, which gave it a lock sidecar
    /// (final review, 2026-09-27).
    #[test]
    fn a_passphrase_rotation_retires_leftover_temp_files_holding_the_vault() {
        let path = rekey_path("retire-temp");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        vault.save().unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        let backup = backups_of(&path)
            .pop()
            .expect("precondition: a backup exists");
        let leftover = || dir.join(format!(".tmp-{}", crate::random_id()));
        let crashed_save = leftover();
        std::fs::copy(&path, &crashed_save).unwrap();
        let crashed_backup = leftover();
        std::fs::copy(&backup, &crashed_backup).unwrap();
        // Cut short by a crash: the header, and with it every slot, is on
        // disk; the contents are not.
        let bytes = std::fs::read(&path).unwrap();
        let header_len = format::decode_header(&bytes).unwrap().len();
        assert_eq!(
            header_len,
            format::PREFIX_LEN + 2 * format::SLOT_LEN,
            "precondition: a passphrase slot and a recovery slot"
        );
        let partial = leftover();
        std::fs::write(&partial, &bytes[..header_len + 10]).unwrap();
        // Cut inside the slot array: the passphrase slot is whole, the
        // recovery slot is not.
        let cut_in_slots = leftover();
        std::fs::write(
            &cut_in_slots,
            &bytes[..format::PREFIX_LEN + format::SLOT_LEN + 5],
        )
        .unwrap();
        // What a build up to 1.0.2 left for the vault itself.
        let legacy = path.with_file_name("vault.rbv.tmp");
        std::fs::copy(&path, &legacy).unwrap();
        // One somebody opened. That proves the old passphrase opens such a
        // leftover, and it leaves a sidecar, which must not protect it.
        let opened = leftover();
        std::fs::copy(&path, &opened).unwrap();
        assert!(
            crate::Vault::unlock(&opened, "old-pass").is_ok(),
            "precondition: the leftover is an old-passphrase vault"
        );
        assert!(
            sidecar_of(&opened).exists(),
            "precondition: opening it left a sidecar"
        );

        vault.change_passphrase("old-pass", "new-pass").unwrap();

        for file in [
            &crashed_save,
            &crashed_backup,
            &partial,
            &cut_in_slots,
            &legacy,
            &opened,
        ] {
            assert!(!file.exists(), "{} survived the rotation", file.display());
        }
        drop(vault);
        assert!(crate::Vault::unlock(&path, "new-pass").is_ok());
    }

    /// A copy from before an EARLIER rotation, of a vault with no recovery
    /// key, shares no slot with the vault any more. Its contents still
    /// decrypt under the vault's master key, which never changes, and that is
    /// what identifies it. This one was also opened, so it has a sidecar.
    #[test]
    fn a_leftover_from_an_earlier_passphrase_is_retired_too() {
        let path = rekey_path("retire-earlier");
        let params = KdfParams {
            m_cost: 8192,
            t_cost: 1,
            p_cost: 1,
        };
        let mut vault = crate::Vault::create_inner(&path, "first-pass", params, None).unwrap();
        let copy = rekey_path("retire-earlier-copy");
        std::fs::copy(&path, &copy).unwrap();
        vault
            .change_passphrase("first-pass", "second-pass")
            .unwrap();
        let earlier = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        std::fs::rename(&copy, &earlier).unwrap();
        assert!(
            crate::Vault::unlock(&earlier, "first-pass").is_ok(),
            "precondition: the earlier passphrase opens it"
        );

        vault
            .change_passphrase("second-pass", "third-pass")
            .unwrap();

        assert!(
            !earlier.exists(),
            "a copy under an earlier passphrase survived the rotation"
        );
    }

    /// Full-diff review R-001 (2026-09-28): a copy cut short INSIDE its first
    /// slot, once the encrypted key has begun, holds key bytes the old
    /// passphrase decrypts without the tag. Every such cut is a copy of this
    /// vault and is retired, up to one byte short of a whole slot.
    #[test]
    fn a_copy_cut_inside_a_slot_after_its_key_began_is_retired() {
        let path = rekey_path("retire-cut-key");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        let bytes = std::fs::read(&path).unwrap();
        let key_start = format::PREFIX_LEN + format::SLOT_KEY_START;
        let whole_slot = format::PREFIX_LEN + format::SLOT_LEN;
        let cuts = [
            key_start + 1,
            key_start + 16,
            key_start + 32,
            key_start + 33,
            whole_slot - 1,
        ];
        let mut files = Vec::new();
        for cut in cuts {
            let file = dir.join(format!(".tmp-{}", crate::random_id()));
            std::fs::write(&file, &bytes[..cut]).unwrap();
            files.push((cut, file));
        }

        vault.change_passphrase("old-pass", "new-pass").unwrap();

        for (cut, file) in &files {
            assert!(
                !file.exists(),
                "a copy cut at {cut} bytes, holding key bytes, survived the rotation"
            );
        }
    }

    /// The other side of R-001: key bytes that match no slot of this vault are
    /// not this vault's to delete. The copy is kept, and the rotation reports
    /// its cleanup as incomplete instead of claiming success.
    #[test]
    fn a_cut_copy_of_another_vault_holding_key_bytes_is_kept_and_reported() {
        let path = rekey_path("retire-cut-other");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        let other = rekey_path("retire-cut-other-source");
        let (other_vault, _) =
            crate::Vault::create_with_params(&other, "old-pass", 8192, 1, 1).unwrap();
        drop(other_vault);
        let other_bytes = std::fs::read(&other).unwrap();
        let cut = format::PREFIX_LEN + format::SLOT_KEY_START + 32;
        let file = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        std::fs::write(&file, &other_bytes[..cut]).unwrap();

        let outcome = vault.change_passphrase("old-pass", "new-pass");

        assert!(
            matches!(outcome, Err(crate::VaultError::BackupsRetained(_))),
            "got {outcome:?}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), &other_bytes[..cut]);
        drop(vault);
        assert!(crate::Vault::unlock(&path, "new-pass").is_ok());
    }

    /// Full-diff review R-002 (2026-09-28): unlock takes the vault's lock
    /// BEFORE reading it. With the vault open elsewhere, even a wrong
    /// passphrase or recovery key gets Locked, because nothing was read or
    /// tried; before the fix the file was read and decrypted first.
    #[test]
    fn unlock_takes_the_lock_before_reading_the_vault() {
        let path = rekey_path("lock-first");
        let (vault, _rk) =
            crate::Vault::create_with_params(&path, "right-pass", 8192, 1, 1).unwrap();
        assert!(
            matches!(
                crate::Vault::unlock(&path, "wrong-pass"),
                Err(crate::VaultError::Locked)
            ),
            "a wrong passphrase was tried against a vault open elsewhere"
        );
        let impostor = crate::RecoveryKey::generate();
        assert!(
            matches!(
                crate::Vault::unlock_with_recovery(&path, &impostor),
                Err(crate::VaultError::Locked)
            ),
            "a recovery key was tried against a vault open elsewhere"
        );
        // Decisive for READ order, not only for the passphrase check: with the
        // vault's name taken by a folder, an unlock that reads first fails on
        // the read, while one that locks first answers Locked without reading.
        // The open vault holds its lock on the sidecar, not the file.
        let moved = path.with_file_name("lock-first-moved.rbv");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        let outcome = crate::Vault::unlock(&path, "right-pass");
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&moved, &path).unwrap();
        assert!(
            matches!(outcome, Err(crate::VaultError::Locked)),
            "the vault was read before its lock was taken: {outcome:?}"
        );
        drop(vault);
        assert!(crate::Vault::unlock(&path, "right-pass").is_ok());
    }

    /// A lock held for a moment longer, the way a child process being spawned
    /// holds a copy of it until its program starts, does not turn into a false
    /// "already open in another window": unlock waits briefly and gets in.
    #[test]
    fn unlock_waits_out_a_lock_released_a_moment_later() {
        let path = rekey_path("lock-moment");
        // The creating handle is the lock that is let go of late, handed to a
        // thread that drops it after 60 ms. Re-acquiring the lock here instead
        // could itself meet a spawning child's copy (review round 3).
        let (vault, _rk) =
            crate::Vault::create_with_params(&path, "right-pass", 8192, 1, 1).unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            drop(vault);
        });
        let outcome = crate::Vault::unlock(&path, "right-pass");
        releaser.join().unwrap();
        assert!(
            outcome.is_ok(),
            "a lock released 60 ms later was reported as busy: {:?}",
            outcome.err()
        );
    }

    /// The rotation retires only copies of this vault. The Library's writer
    /// leaves the same shape of temporary name in this same directory, an
    /// export's leftover is under its own passphrase or none, a fragment too
    /// short to hold a slot holds nothing to open, and nothing that is not a
    /// regular file is touched or followed.
    #[cfg(unix)]
    #[test]
    fn a_passphrase_rotation_leaves_other_temp_files_alone() {
        use std::os::unix::fs::symlink;
        let path = rekey_path("retire-keep");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        let vault_bytes = std::fs::read(&path).unwrap();
        let leftover = || dir.join(format!(".tmp-{}", crate::random_id()));
        let library = leftover();
        std::fs::write(&library, b"RBSTORE and the rest of a Library").unwrap();
        let export = leftover();
        std::fs::write(&export, b"RBVEXPT and the rest of an export").unwrap();
        let plaintext = leftover();
        std::fs::write(&plaintext, b"{\"credentials\": []}").unwrap();
        let fragment = leftover();
        std::fs::write(&fragment, &vault_bytes[..64]).unwrap();
        let short_fragment = leftover();
        std::fs::write(&short_fragment, &vault_bytes[..30]).unwrap();
        let short_name = dir.join(format!(".tmp-{}", "a".repeat(31)));
        std::fs::write(&short_name, &vault_bytes).unwrap();
        let upper_name = dir.join(format!(".tmp-{}", "A".repeat(32)));
        std::fs::write(&upper_name, &vault_bytes).unwrap();
        let outside = rekey_path("retire-keep-outside");
        std::fs::write(&outside, &vault_bytes).unwrap();
        let link = leftover();
        symlink(&outside, &link).unwrap();
        let directory = leftover();
        std::fs::create_dir(&directory).unwrap();
        let not_a_vault = path.with_file_name("vault.rbv.tmp");
        std::fs::write(&not_a_vault, b"someone's own notes").unwrap();

        vault.change_passphrase("old-pass", "new-pass").unwrap();

        for kept in [
            &library,
            &export,
            &plaintext,
            &fragment,
            &short_fragment,
            &short_name,
            &upper_name,
            &not_a_vault,
        ] {
            assert!(kept.is_file(), "{} was removed", kept.display());
        }
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "a symlink at a leftover's name was removed"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            vault_bytes,
            "the symlink's target changed"
        );
        assert!(
            directory.is_dir(),
            "a directory at a leftover's name was removed"
        );
    }

    /// Final review, 2026-09-27: a name proves nothing. A vault that is not a
    /// copy of this one, moved here under a leftover's name WITHOUT its lock
    /// sidecar, is never removed. It is kept, and the rotation reports its
    /// cleanup as incomplete rather than claiming success.
    #[test]
    fn an_unidentified_vault_at_a_leftover_name_is_kept_and_reported() {
        let path = rekey_path("retire-moved");
        let elsewhere = rekey_path("retire-moved-elsewhere");
        let (other, _) =
            crate::Vault::create_with_params(&elsewhere, "other-pass", 8192, 1, 1).unwrap();
        drop(other);
        let moved = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        std::fs::rename(&elsewhere, &moved).unwrap();
        assert!(
            !sidecar_of(&moved).exists(),
            "precondition: moved without its sidecar"
        );
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();

        let outcome = vault.change_passphrase("old-pass", "new-pass");

        assert!(
            matches!(outcome, Err(crate::VaultError::BackupsRetained(_))),
            "got {outcome:?}"
        );
        assert!(
            moved.is_file(),
            "a vault that is not this vault's copy was removed"
        );
        drop(vault);
        assert!(
            crate::Vault::unlock(&path, "new-pass").is_ok(),
            "the rotation must still be committed"
        );
        assert!(crate::Vault::unlock(&moved, "other-pass").is_ok());
    }

    /// A second vault in the same directory, named like a leftover, is kept
    /// even with its lock sidecar beside it, and reported: a sidecar proves
    /// nothing about what a file is (final review, 2026-09-27).
    #[test]
    fn a_second_vault_named_like_a_leftover_is_kept_and_reported() {
        let path = rekey_path("retire-other");
        let other = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        let (other_vault, _) =
            crate::Vault::create_with_params(&other, "other-pass", 8192, 1, 1).unwrap();
        drop(other_vault); // closed: its lock sidecar stays on disk
        assert!(
            sidecar_of(&other).exists(),
            "precondition: it has a sidecar"
        );
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();

        let outcome = vault.change_passphrase("old-pass", "new-pass");

        assert!(
            matches!(outcome, Err(crate::VaultError::BackupsRetained(_))),
            "got {outcome:?}"
        );
        assert!(other.is_file(), "the rotation deleted another vault");
        drop(vault);
        assert!(crate::Vault::unlock(&path, "new-pass").is_ok());
        assert!(crate::Vault::unlock(&other, "other-pass").is_ok());
    }

    /// Final review, 2026-09-27: a vault-shaped leftover that cannot be proven
    /// ours is Unknown even with a sidecar beside it. A copy from before an
    /// earlier rotation, cut short, shares no slot and cannot be decrypted, yet
    /// its old slot still unwraps the unchanged master key; a v1 file has no
    /// slots at all; a copy past the read cap is only compared by its slots.
    #[test]
    fn a_leftover_that_cannot_be_proven_ours_is_unknown_even_with_a_sidecar() {
        let path = rekey_path("retire-unproven");
        let params = KdfParams {
            m_cost: 8192,
            t_cost: 1,
            p_cost: 1,
        };
        let mut vault = crate::Vault::create_inner(&path, "first-pass", params, None).unwrap();
        let earlier = std::fs::read(&path).unwrap();
        vault
            .change_passphrase("first-pass", "second-pass")
            .unwrap();
        let header_len = format::decode_header(&earlier).unwrap().len();
        let unproven = |bytes: &[u8]| {
            let file = path.with_file_name(format!(".tmp-{}", crate::random_id()));
            std::fs::write(&file, bytes).unwrap();
            std::fs::write(sidecar_of(&file), b"").unwrap();
            file
        };
        let cut_short = unproven(&earlier[..header_len + 10]);
        let mut v1 = format::MAGIC.to_vec();
        v1.push(format::VERSION_V1);
        v1.extend_from_slice(&[0u8; format::V1_HEADER_LEN]);
        let v1_file = unproven(&v1);
        let past_cap = unproven(&earlier[..header_len]);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&past_cap)
            .unwrap()
            .set_len(LEFTOVER_READ_LIMIT + 4096)
            .unwrap();
        let retired = vault.slots_ref()[0].clone();
        for file in [&cut_short, &v1_file, &past_cap] {
            assert_eq!(
                classify_leftover(&vault, &retired, file).unwrap(),
                Leftover::Unknown,
                "{} was not reported",
                file.display()
            );
        }

        let outcome = vault.change_passphrase("second-pass", "third-pass");

        assert!(
            matches!(outcome, Err(crate::VaultError::BackupsRetained(_))),
            "got {outcome:?}"
        );
        for file in [&cut_short, &v1_file, &past_cap] {
            assert!(file.exists(), "{} was removed", file.display());
        }
    }

    /// Final review, 2026-09-27: a listing that fails part-way is recorded
    /// like any other failure. Every entry still listed is still retired, and
    /// the error is returned at the end.
    #[test]
    fn a_listing_that_fails_part_way_still_retires_the_rest() {
        let path = rekey_path("retire-listing");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        for _ in 0..3 {
            vault.save().unwrap();
        }
        let backups = backups_of(&path);
        assert!(backups.len() >= 2, "precondition: two backups: {backups:?}");
        let entry = |backup: &std::path::PathBuf| {
            Ok((backup.file_name().unwrap().to_owned(), backup.clone()))
        };
        let listing = vec![
            entry(&backups[0]),
            Err(std::io::Error::other("injected: the listing failed")),
            entry(&backups[1]),
        ];
        let dir = path.parent().unwrap();

        let outcome = retire_entries(&path, dir, listing.into_iter(), |_: &Path| {
            Ok(Leftover::Foreign)
        });

        assert!(
            matches!(&outcome, Err(BackupError::Io(e)) if e.to_string().contains("the listing failed")),
            "the listing failure was not reported: {outcome:?}"
        );
        assert!(
            !backups[0].exists(),
            "the entry before the failure was kept"
        );
        assert!(!backups[1].exists(), "the entry after the failure was kept");
        drop(vault);
    }

    /// Plan review, 2026-09-27: never the vault itself, even when its own name
    /// is shaped like a leftover. It carries this vault's slots, so the
    /// self-exclusion is the only thing protecting it.
    #[test]
    fn a_vault_named_like_a_leftover_survives_its_own_rotation() {
        let dir = rekey_path("retire-self").parent().unwrap().to_path_buf();
        let path = dir.join(format!(".tmp-{}", crate::random_id()));
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        vault.add_note("kept", "body").unwrap();

        vault.change_passphrase("old-pass", "new-pass").unwrap();

        assert!(path.is_file(), "the rotation deleted the vault itself");
        drop(vault);
        let reopened = crate::Vault::unlock(&path, "new-pass")
            .expect("the new passphrase must open the vault");
        assert!(reopened.list_notes().iter().any(|n| n.title == "kept"));
        drop(reopened);
        assert!(
            crate::Vault::unlock(&path, "old-pass").is_err(),
            "the old passphrase still opens the vault"
        );
    }

    /// Final review, 2026-09-27: judging a leftover must not block on a FIFO
    /// that sits at a leftover's name (or is swapped in for one).
    #[cfg(unix)]
    #[test]
    fn a_rotation_does_not_block_on_a_fifo_at_a_leftover_name() {
        use std::os::unix::fs::FileTypeExt;
        let path = rekey_path("retire-fifo");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        let fifo = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success(), "precondition: mkfifo");
        let (done, outcome) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = vault.change_passphrase("old-pass", "new-pass");
            let _ = done.send(result.map(|()| vault));
        });
        let vault = outcome
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the rotation blocked on a FIFO at a leftover's name")
            .unwrap();
        assert!(
            std::fs::symlink_metadata(&fifo)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the FIFO was removed"
        );
        drop(vault);
    }

    /// Plan review, 2026-09-27: a leftover that cannot be read is not skipped
    /// as "not ours". That would report a retirement that may not have
    /// happened; it fails the retirement instead (BackupsRetained at the
    /// rotation) and the file is kept. Injected, because the tests run as root.
    #[test]
    fn a_leftover_that_cannot_be_inspected_fails_the_retirement_and_is_kept() {
        let path = rekey_path("retire-unreadable");
        let (vault, _rk) = crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        let crashed = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        let legacy = path.with_file_name("vault.rbv.tmp");
        for unreadable in [&crashed, &legacy] {
            std::fs::copy(&path, unreadable).unwrap();
            let outcome = retire_backups_with(&path, |p: &Path| {
                if p == unreadable.as_path() {
                    Err(std::io::Error::other("injected: cannot read this leftover"))
                } else {
                    Ok(Leftover::Foreign)
                }
            });
            assert!(
                matches!(&outcome, Err(BackupError::Io(e)) if e.to_string().contains("cannot read this leftover")),
                "an unreadable leftover was skipped as not ours: {outcome:?}"
            );
            assert!(
                unreadable.exists(),
                "a leftover nobody could inspect was removed"
            );
            std::fs::remove_file(unreadable).unwrap();
        }
        drop(vault);
    }

    /// Compliance review, 2026-09-27: a failure on one entry must not stop
    /// the rest. Every backup is still removed and every other leftover still
    /// judged, and the failure is reported at the end. Counting the judged
    /// leftovers makes this independent of the order the directory lists them.
    #[test]
    fn one_failure_does_not_stop_the_rest_of_the_retirement() {
        let path = rekey_path("retire-continue");
        let (mut vault, _rk) =
            crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        vault.save().unwrap();
        vault.save().unwrap();
        assert!(!backups_of(&path).is_empty(), "precondition: backups exist");
        let leftovers: Vec<_> = (0..3)
            .map(|_| path.with_file_name(format!(".tmp-{}", crate::random_id())))
            .collect();
        for leftover in &leftovers {
            std::fs::copy(&path, leftover).unwrap();
        }
        let judged = std::cell::Cell::new(0);
        let outcome = retire_backups_with(&path, |_: &Path| {
            judged.set(judged.get() + 1);
            Err(std::io::Error::other("injected: cannot read this leftover"))
        });
        assert!(
            matches!(&outcome, Err(BackupError::Io(e)) if e.to_string().contains("cannot read this leftover")),
            "the failure was not reported: {outcome:?}"
        );
        assert_eq!(
            judged.get(),
            leftovers.len(),
            "a failure on one leftover stopped the others being judged"
        );
        assert!(
            backups_of(&path).is_empty(),
            "a failure stopped the backups being removed"
        );
        for leftover in &leftovers {
            assert!(
                leftover.exists(),
                "a leftover nobody could inspect was removed"
            );
        }
        drop(vault);
    }

    /// A leftover identified as ours that then cannot be removed fails the
    /// retirement, exactly as a stuck backup does.
    #[test]
    fn a_leftover_that_cannot_be_removed_fails_the_retirement() {
        let path = rekey_path("retire-stuck-leftover");
        let (vault, _rk) = crate::Vault::create_with_params(&path, "old-pass", 8192, 1, 1).unwrap();
        // A directory at a leftover's name, judged ours by the classifier
        // below: remove_file refuses a directory.
        let stuck = path.with_file_name(format!(".tmp-{}", crate::random_id()));
        std::fs::create_dir(&stuck).unwrap();
        let outcome = retire_backups_with(&path, |p: &Path| {
            Ok(if p == stuck.as_path() {
                Leftover::Ours
            } else {
                Leftover::Foreign
            })
        });
        assert!(
            matches!(outcome, Err(BackupError::Io(_))),
            "a removal that failed was reported as success: {outcome:?}"
        );
        assert!(stuck.is_dir());
        drop(vault);
    }

    /// The Library repair step confirms the CURRENT passphrase without
    /// changing anything; it must follow a rotation exactly.
    #[test]
    fn verify_passphrase_follows_the_current_passphrase_and_writes_nothing() {
        let path = rekey_path("verify");
        let (mut vault, _rk) = crate::Vault::create(&path, "old-pass").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(vault.verify_passphrase("old-pass").unwrap());
        assert!(!vault.verify_passphrase("not-it").unwrap());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "verification wrote the vault"
        );
        vault.change_passphrase("old-pass", "new-pass").unwrap();
        assert!(vault.verify_passphrase("new-pass").unwrap());
        assert!(
            !vault.verify_passphrase("old-pass").unwrap(),
            "the retired passphrase still verifies"
        );
    }

    /// Pentest F-004. A rotation whose save fails leaves memory AND disk under
    /// the old passphrase: the next ordinary save must not commit the new one.
    #[test]
    fn a_failed_rotation_rolls_the_slot_back() {
        let path = rekey_path("rollback");
        let (mut vault, _rk) = crate::Vault::create(&path, "old-pass").unwrap();
        vault.fail_next_save_for_test();
        assert!(vault.change_passphrase("old-pass", "new-pass").is_err(), "the injected failure must surface");
        vault.save().unwrap();
        drop(vault);
        let reopened = crate::Vault::unlock(&path, "old-pass");
        assert!(reopened.is_ok(), "the failed rotation was committed by a later save");
        drop(reopened);
        assert!(crate::Vault::unlock(&path, "new-pass").is_err());
    }

    use super::*;
    use std::fs;
    use std::path::Path;

    /// Cheap KDF parameters so tests don't spend seconds in Argon2; the
    /// vault exposes `create_with_params` for exactly this.
    const TEST_M: u32 = 8192;
    const TEST_T: u32 = 1;
    const TEST_P: u32 = 1;

    /// Unique temp directory that removes itself even when the test panics.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let random: [u8; 8] = crypto::random_bytes();
            let mut name = format!("rbv-backup-test-{tag}-");
            for b in random {
                name.push_str(&format!("{b:02x}"));
            }
            let path = std::env::temp_dir().join(name);
            fs::create_dir_all(&path).expect("create temp dir");
            TestDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn create_test_vault(dir: &TestDir, name: &str, passphrase: &str) -> (Vault, RecoveryKey) {
        Vault::create_with_params(&dir.path().join(name), passphrase, TEST_M, TEST_T, TEST_P)
            .expect("create vault")
    }

    /// A vault created without a recovery key can be given one, and the key
    /// that comes back genuinely opens it.
    ///
    /// The assertion that matters is the LAST one. Minting a key, storing a
    /// slot and handing back a printable string could all succeed while the
    /// key opens nothing -- and the user would find out only on the day they
    /// needed it, having done exactly what they were told.
    #[test]
    fn a_vault_without_a_recovery_key_can_be_given_one_that_works() {
        let dir = TestDir::new("addrec");
        let path = dir.path().join("v.rbv");
        let mut vault = Vault::create_without_recovery(&path, "vault-pw").expect("create");
        assert!(!vault.has_recovery(), "precondition: no recovery key");

        let id = vault
            .add_credential("example.com", None, "alice", "secret-pw", "")
            .expect("store something worth recovering");

        let key = vault.add_recovery("vault-pw").expect("mint a recovery key");
        assert!(vault.has_recovery(), "the slot must be recorded");
        drop(vault);

        let reopened = Vault::unlock_with_recovery(&path, &key)
            .expect("the minted key must actually open the vault");
        assert_eq!(
            reopened.get_credential(&id).map(|c| c.password.as_str()),
            Some("secret-pw"),
            "and the contents must be intact -- adding a slot re-encrypts nothing"
        );
    }

    #[test]
    fn adding_a_recovery_key_needs_the_current_passphrase() {
        let dir = TestDir::new("addrec-auth");
        let path = dir.path().join("v.rbv");
        let mut vault = Vault::create_without_recovery(&path, "vault-pw").expect("create");
        // An unlocked vault is not authorisation to mint a permanent second
        // credential: that is exactly what someone walking up to an unattended
        // machine would do.
        assert!(
            matches!(
                vault.add_recovery("wrong-pw"),
                Err(VaultError::AuthFailed)
            ),
            "a wrong passphrase must be refused"
        );
        assert!(!vault.has_recovery(), "and nothing may be written");
    }

    #[test]
    fn a_second_recovery_key_is_refused() {
        let dir = TestDir::new("addrec-twice");
        let (mut vault, _first) = create_test_vault(&dir, "v.rbv", "vault-pw");
        assert!(vault.has_recovery());
        // Two live keys while the user believes there is one is worse than the
        // position they started in.
        assert!(vault.add_recovery("vault-pw").is_err());
    }

    /// The plaintext export must contain passwords and NOT key material.
    ///
    /// It previously serialized `VaultData` wholesale, which emitted every
    /// per-contact X25519 private key and the long-term chat identity — while
    /// the sentence the user types says only that their passwords will be
    /// readable. The old test asserted the password WAS present and never
    /// asserted what else was.
    #[test]
    fn plaintext_export_contains_passwords_but_never_key_material() {
        let dir = TestDir::new("plainkeys");
        let (mut vault, _r) = create_test_vault(&dir, "v.rbv", "vault-pw");
        vault
            .add_credential("example.com", None, "alice", "s3cret-p4ss", "")
            .unwrap();
        vault.add_contact("mum", "hash-mum", [0xAA; 32]).unwrap();
        vault.set_chat_identity([0xBB; 32]).unwrap();

        let dest = dir.path().join("plain.json");
        vault
            .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
            .expect("export");
        let text = fs::read_to_string(&dest).unwrap();

        // What the user consented to is present.
        assert!(text.contains("s3cret-p4ss"), "passwords must be exported");
        assert!(text.contains("mum"), "the contact label is the user's own note");

        // What they did not consent to is absent, in every encoding serde
        // could have produced.
        assert!(!text.contains("our_secret"), "contact private keys must not be exported");
        assert!(!text.contains("chat_identity"), "the identity secret must not be exported");
        let aa = [0xAAu8; 32];
        let bb = [0xBBu8; 32];
        for (name, bytes) in [("contact key", &aa), ("identity key", &bb)] {
            let as_json_array = format!("{:?}", bytes.to_vec());
            let as_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!text.contains(&as_json_array), "{name} leaked as a byte array");
            assert!(
                !text.to_lowercase().contains(&as_hex),
                "{name} leaked as hex"
            );
        }
    }

    /// The live vault must survive a destination that merely *spells* itself
    /// differently — `..` traversal or a symlink. Getting past this guard
    /// overwrote the vault with the export: irreversible loss, and for the
    /// plaintext path it wrote every password in cleartext into the file the
    /// user believed was their encrypted vault.
    #[test]
    fn exports_refuse_any_path_that_resolves_to_the_live_vault() {
        let dir = TestDir::new("aliasguard");
        let (mut vault, _r) = create_test_vault(&dir, "vault.rbv", "vault-pw");
        vault
            .add_credential("example.com", None, "alice", "s3cret-p4ss", "")
            .unwrap();
        let vault_path = dir.path().join("vault.rbv");
        let before = fs::read(&vault_path).unwrap();

        // 1. `..` traversal through a real subdirectory.
        let sub = dir.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        let traversal = sub.join("..").join("vault.rbv");
        assert!(matches!(
            vault.export_plaintext(&traversal, PLAINTEXT_EXPORT_CONFIRMATION),
            Err(ExportError::TargetIsLiveVault)
        ));
        assert!(matches!(
            vault.export_encrypted(&traversal, "export-pw"),
            Err(ExportError::TargetIsLiveVault)
        ));

        // 2. A symlink pointing at the vault.
        #[cfg(unix)]
        {
            let link = dir.path().join("alias.rbv");
            std::os::unix::fs::symlink(&vault_path, &link).unwrap();
            assert!(matches!(
                vault.export_plaintext(&link, PLAINTEXT_EXPORT_CONFIRMATION),
                Err(ExportError::TargetIsLiveVault)
            ));
        }

        // The vault is byte-for-byte intact.
        assert_eq!(fs::read(&vault_path).unwrap(), before, "vault was modified");

        // A genuinely different destination still works.
        let ok_dest = dir.path().join("real-export.json");
        vault
            .export_plaintext(&ok_dest, PLAINTEXT_EXPORT_CONFIRMATION)
            .expect("a distinct destination must still be allowed");
        assert!(ok_dest.is_file());

        // ...and it still OPENS. Checked last, because one process per vault
        // means this handle has to let go first.
        drop(vault);
        assert!(Vault::unlock(&vault_path, "vault-pw").is_ok(), "vault no longer opens");
    }

    #[test]
    fn encrypted_export_round_trips_through_import() {
        let dir = TestDir::new("roundtrip");
        let (mut vault, _recovery) = create_test_vault(&dir, "source.rbv", "vault-pw");
        let cred_id = vault
            .add_credential("example.com", None, "alice", "s3cret-p4ss", "a note")
            .unwrap();
        let note_id = vault.add_note("wifi", "hunter2").unwrap();

        let export_path = dir.path().join("export.rbx");
        vault
            .export_encrypted(&export_path, "export-pw")
            .expect("export");

        let imported_path = dir.path().join("imported.rbv");
        let (imported, imported_recovery, carried) = Vault::import_encrypted(
            &export_path,
            &imported_path,
            "export-pw",
            "new-vault-pw",
        )
        .expect("import");
        // An export taken without carried bytes yields none. This is the
        // shape the app relies on to tell "nothing was attached" from
        // "something was attached and came back empty".
        assert!(carried.is_none());

        // Contents survived the round trip, ids included.
        let cred = imported.get_credential(&cred_id).expect("credential present");
        assert_eq!(cred.site, "example.com");
        assert_eq!(cred.username, "alice");
        assert_eq!(cred.password, "s3cret-p4ss");
        assert_eq!(cred.note, "a note");
        assert_eq!(imported.get_note(&note_id).unwrap().body, "hunter2");
        assert!(imported.has_recovery());
        drop(imported);

        // The imported vault opens with its new passphrase and its fresh
        // recovery key, and with NEITHER the export passphrase nor the
        // source vault's passphrase: the export passphrase is independent.
        assert!(Vault::unlock(&imported_path, "new-vault-pw").is_ok());
        assert!(matches!(
            Vault::unlock(&imported_path, "export-pw"),
            Err(VaultError::AuthFailed)
        ));
        assert!(matches!(
            Vault::unlock(&imported_path, "vault-pw"),
            Err(VaultError::AuthFailed)
        ));
        assert!(Vault::unlock_with_recovery(&imported_path, &imported_recovery).is_ok());

        // The source vault is untouched by all of this. Its handle lets go
        // first: one process per vault. (`imported` was already dropped
        // above, before the reopen assertions.)
        drop(vault);
        assert!(Vault::unlock(&dir.path().join("source.rbv"), "vault-pw").is_ok());
    }

    #[test]
    fn wrong_export_passphrase_fails() {
        let dir = TestDir::new("wrongpw");
        let (vault, _r) = create_test_vault(&dir, "source.rbv", "vault-pw");
        let export_path = dir.path().join("export.rbx");
        vault.export_encrypted(&export_path, "export-pw").unwrap();

        let result = Vault::import_encrypted(
            &export_path,
            &dir.path().join("imported.rbv"),
            "not-the-export-pw",
            "new-vault-pw",
        );
        assert!(
            matches!(result, Err(ExportError::AuthFailed)),
            "wrong export passphrase must fail as AuthFailed, got {result:?}"
        );
        // And nothing may have been created at the destination.
        assert!(!dir.path().join("imported.rbv").exists());
    }

    /// IMPORT REPLACES AN EXISTING VAULT. This test used to assert the
    /// opposite -- that import refused when the destination existed -- and
    /// that refusal is why an import control could not be offered on any
    /// machine that had a vault: the button could only ever fail.
    ///
    /// The refusal was protecting people from losing credentials, which is a
    /// real risk and has not gone away. It moved: the panel states plainly
    /// that importing discards what is here, BEFORE the file is chosen. A
    /// warning the user reads while deciding beats an error they meet after.
    ///
    /// What must still hold is that the replacement is COMPLETE. A half-
    /// replaced vault -- new file, old passphrase still working, or contents
    /// from both -- would be worse than either behaviour.
    #[test]
    fn import_replaces_an_existing_vault_completely() {
        let dir = TestDir::new("clobber");
        let (mut source, _r) = create_test_vault(&dir, "source.rbv", "vault-pw");
        let carried_id = source
            .add_credential("carried.example", None, "alice", "carried-pw", "")
            .unwrap();
        let export_path = dir.path().join("export.rbx");
        source.export_encrypted(&export_path, "export-pw").unwrap();

        // The vault about to be destroyed, holding something of its own.
        let dest = dir.path().join("existing.rbv");
        let (mut existing, _r2) =
            Vault::create_with_params(&dest, "existing-pw", TEST_M, TEST_T, TEST_P).unwrap();
        let doomed_id = existing
            .add_credential("doomed.example", None, "bob", "doomed-pw", "")
            .unwrap();
        // One process per vault: let go before the import writes over it.
        drop(existing);

        let (imported, _r3, _carried) =
            Vault::import_encrypted(&export_path, &dest, "export-pw", "new-pw")
                .expect("import must replace an existing vault");

        // The export's contents are here...
        assert_eq!(
            imported
                .get_credential(&carried_id)
                .map(|c| c.password.clone()),
            Some("carried-pw".to_string())
        );
        // ...and the vault that was here is GONE, not merged underneath.
        // Merging would leave a state neither machine ever had.
        assert!(
            imported.get_credential(&doomed_id).is_none(),
            "the replaced vault's contents survived the import"
        );
        drop(imported);

        // The old passphrase is dead. If it still opened the file, a user who
        // imported to get away from a compromised passphrase would not have.
        assert!(matches!(
            Vault::unlock(&dest, "existing-pw"),
            Err(VaultError::AuthFailed)
        ));
        assert!(Vault::unlock(&dest, "new-pw").is_ok());
    }

    /// Bytes handed to the export come back from the import unchanged.
    ///
    /// The vault crate does not know what these are and must not learn: the
    /// app puts bookmarks here, and a vault that understood bookmarks would
    /// be a vault that depends on the store it is meant to be independent of.
    #[test]
    fn carried_bytes_survive_the_round_trip() {
        let dir = TestDir::new("carried");
        let (vault, _r) = create_test_vault(&dir, "source.rbv", "vault-pw");
        // Deliberately not valid UTF-8 and containing a NUL: these are opaque
        // bytes, and anything that treats them as text would corrupt them.
        let payload: Vec<u8> = vec![0x00, 0xff, 0xfe, b'{', b'}', 0x80, 0x00];
        let export_path = dir.path().join("export.rbx");
        vault
            .export_encrypted_with(&export_path, "export-pw", Some(&payload))
            .expect("export");

        let (_imported, _r2, carried) = Vault::import_encrypted(
            &export_path,
            &dir.path().join("imported.rbv"),
            "export-pw",
            "new-pw",
        )
        .expect("import");
        assert_eq!(carried.as_deref(), Some(&payload[..]));
    }

    /// Carried bytes are INSIDE the encryption, not beside it.
    ///
    /// Bookmarks are a list of everywhere the user cared enough to save, so an
    /// export that sealed the credentials and left the URLs legible would be a
    /// browsing-history leak in a file people are told is safe to copy
    /// anywhere.
    #[test]
    fn carried_bytes_are_not_readable_in_the_export_file() {
        let dir = TestDir::new("carried-sealed");
        let (vault, _r) = create_test_vault(&dir, "source.rbv", "vault-pw");
        let secret = b"https://very-distinctive-bookmark.example/path";
        let export_path = dir.path().join("export.rbx");
        vault
            .export_encrypted_with(&export_path, "export-pw", Some(secret))
            .expect("export");
        let raw = fs::read(&export_path).unwrap();
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "carried bytes appear in cleartext in the export file"
        );
    }

    /// A v1 export -- written before the format grew a carried-bytes field --
    /// still imports.
    ///
    /// This is the assertion that matters most in this file. Someone's only
    /// copy of every credential they own may be a v1 file on a USB stick, and
    /// "we added a field" is not a reason for it to stop opening. The v1 body
    /// is a bare `VaultData`; v2 wraps it in an envelope. Both decode.
    #[test]
    fn a_v1_export_still_imports() {
        let dir = TestDir::new("v1compat");
        let (mut vault, _r) = create_test_vault(&dir, "source.rbv", "vault-pw");
        let cred_id = vault
            .add_credential("old.example", None, "alice", "old-pw", "")
            .unwrap();

        // Hand-built v1 file: same header, version byte 0x01, and a bare
        // `VaultData` body rather than an envelope. Written here rather than
        // checked in as a fixture because the KDF parameters must be the
        // cheap test ones -- a fixture would bake in production cost and make
        // this test take minutes.
        let params = vault.kdf_params();
        let salt: [u8; SALT_LEN] = crypto::random_bytes();
        let nonce: [u8; NONCE_LEN] = crypto::random_bytes();
        let key = crypto::derive_key(b"export-pw", &salt, &params).unwrap();
        let mut header = encode_export_header(&params, &salt, &nonce);
        header[7] = EXPORT_VERSION_V1;
        let plaintext = serde_json::to_vec(vault.data_ref()).unwrap();
        let ciphertext = crypto::encrypt(&key, &nonce, &header, &plaintext).unwrap();
        let mut out = header.to_vec();
        out.extend_from_slice(&ciphertext);
        let export_path = dir.path().join("v1.rbx");
        fs::write(&export_path, &out).unwrap();

        let (imported, _r2, carried) = Vault::import_encrypted(
            &export_path,
            &dir.path().join("imported.rbv"),
            "export-pw",
            "new-pw",
        )
        .expect("a v1 export must still import");
        assert_eq!(
            imported.get_credential(&cred_id).map(|c| c.password.clone()),
            Some("old-pw".to_string())
        );
        // v1 carried nothing, and that is reported as nothing rather than as
        // an empty list -- the app uses the difference.
        assert!(carried.is_none());
    }

    #[test]
    fn plaintext_export_requires_the_confirmation_phrase() {
        let dir = TestDir::new("plaintext");
        let (mut vault, _r) = create_test_vault(&dir, "source.rbv", "vault-pw");
        vault
            .add_credential("example.com", None, "alice", "visible-password", "")
            .unwrap();
        let dest = dir.path().join("leave.json");

        for wrong in ["", "yes", "I understand", "I UNDERSTAND MY PASSWORDS WILL BE READABLE IN THIS FILE"] {
            let result = vault.export_plaintext(&dest, wrong);
            assert!(
                matches!(result, Err(ExportError::PlaintextNotConfirmed)),
                "confirmation {wrong:?} must be rejected"
            );
            assert!(!dest.exists(), "no file may be written without confirmation");
        }

        vault
            .export_plaintext(&dest, PLAINTEXT_EXPORT_CONFIRMATION)
            .expect("confirmed export");
        let written = fs::read(&dest).unwrap();
        // It really is plaintext: the password sits in the file, readable.
        let as_text = String::from_utf8(written.clone()).unwrap();
        assert!(as_text.contains("visible-password"));
        // And it parses back into the same data.
        let parsed: crate::VaultData = serde_json::from_slice(&written).unwrap();
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.credentials[0].password, "visible-password");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "even plaintext export must be owner-only");
        }
    }

    #[test]
    fn export_never_overwrites_the_live_vault() {
        let dir = TestDir::new("livetarget");
        let (vault, _r) = create_test_vault(&dir, "vault.rbv", "vault-pw");
        let vault_path = dir.path().join("vault.rbv");
        assert!(matches!(
            vault.export_encrypted(&vault_path, "export-pw"),
            Err(ExportError::TargetIsLiveVault)
        ));
        assert!(matches!(
            vault.export_plaintext(&vault_path, PLAINTEXT_EXPORT_CONFIRMATION),
            Err(ExportError::TargetIsLiveVault)
        ));
        // Still a working vault, not an export file. `vault` must let go
        // first: one process per vault is now enforced.
        drop(vault);
        assert!(Vault::unlock(&vault_path, "vault-pw").is_ok());
    }

    #[test]
    fn passphrase_change_keeps_recovery_and_kills_the_old_passphrase() {
        let dir = TestDir::new("pwchange");
        let path = dir.path().join("vault.rbv");
        let (mut vault, recovery) = create_test_vault(&dir, "vault.rbv", "old-pw");
        let cred_id = vault
            .add_credential("example.com", None, "bob", "bobs-password", "")
            .unwrap();

        vault.change_passphrase("old-pw", "new-pw").expect("change");
        drop(vault);

        // New passphrase opens it and the data is intact.
        let reopened = Vault::unlock(&path, "new-pw").expect("unlock with new");
        assert_eq!(reopened.get_credential(&cred_id).unwrap().password, "bobs-password");
        // One process per vault, and unlock takes the lock before reading
        // (full-diff R-002): let go before trying another passphrase, or the
        // answer is Locked rather than a verdict on the passphrase.
        drop(reopened);
        // The old passphrase is dead.
        assert!(matches!(
            Vault::unlock(&path, "old-pw"),
            Err(VaultError::AuthFailed)
        ));
        // The recovery key written down BEFORE the change still opens it —
        // the property this whole feature must not break.
        assert!(Vault::unlock_with_recovery(&path, &recovery).is_ok());
    }

    #[test]
    fn passphrase_change_with_wrong_current_changes_nothing() {
        let dir = TestDir::new("wrongcurrent");
        let path = dir.path().join("vault.rbv");
        let (mut vault, recovery) = create_test_vault(&dir, "vault.rbv", "old-pw");
        assert!(matches!(
            vault.change_passphrase("not-old-pw", "new-pw"),
            Err(VaultError::AuthFailed)
        ));
        drop(vault);
        assert!(Vault::unlock(&path, "old-pw").is_ok());
        assert!(matches!(
            Vault::unlock(&path, "new-pw"),
            Err(VaultError::AuthFailed)
        ));
        assert!(Vault::unlock_with_recovery(&path, &recovery).is_ok());
    }

    #[test]
    fn passphrase_change_on_vault_without_recovery_still_works() {
        let dir = TestDir::new("norecovery");
        let path = dir.path().join("vault.rbv");
        let mut vault =
            Vault::create_without_recovery(&path, "old-pw").expect("create without recovery");
        // create_without_recovery uses default (slow) KDF params; that's
        // acceptable for a single test vault.
        assert!(!vault.has_recovery());
        vault.change_passphrase("old-pw", "new-pw").unwrap();
        drop(vault);
        assert!(Vault::unlock(&path, "new-pw").is_ok());
        assert!(matches!(
            Vault::unlock_with_recovery(&path, &RecoveryKey::generate()),
            Err(VaultError::NoRecoverySlot)
        ));
    }

    /// A future payload must be refused BEFORE its unknown fields have been
    /// discarded into a lossy in-memory copy. Nothing was ever saved from
    /// that state, but deciding after the fact is avoidable ambiguity next
    /// to a destructive boundary.
    #[test]
    fn a_newer_schema_is_refused_and_nothing_is_written() {
        let dir = TestDir::new("newer-schema");
        let path = dir.path().join("vault.rbv");
        let (mut vault, _r) = crate::Vault::create(&path, "correct horse").unwrap();
        vault.add_credential("example.com", None, "user", "pw", "").unwrap();
        let before = std::fs::read(&path).unwrap();

        // A payload from a build newer than this one.
        let plaintext = serde_json::json!({
            "schema": crate::model::SCHEMA_VERSION + 1,
            "credentials": [],
            "notes": [],
            "something_this_build_has_never_heard_of": {"a": 1},
        });
        let err = crate::Vault::parse_payload(&serde_json::to_vec(&plaintext).unwrap())
            .expect_err("a newer schema must be refused");
        // The message must name BOTH numbers and must NOT suggest damage: a
        // reader has to be able to tell "use your other build" from "your
        // vault may be lost" without help.
        let text = format!("{err}");
        assert!(text.contains("newer PATANYX"), "got {text}");
        let newer = format!("schema {}", crate::model::SCHEMA_VERSION + 1);
        assert!(text.contains(&newer), "must name what it found: {text}");
        assert!(
            !text.contains("damaged") && !text.contains("invalid"),
            "must not imply the file is broken: {text}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "refusing to parse must not have touched the vault"
        );
    }

    /// A rotation that fails must leave BOTH the vault and the existing
    /// backups exactly as they were. A backup step that damages the thing it
    /// is protecting is worse than no backup step.
    #[test]
    fn a_failed_rotation_leaves_the_vault_and_backups_untouched() {
        let dir = TestDir::new("rotate-fails");
        let path = dir.path().join("vault.rbv");
        let (mut vault, _r) = crate::Vault::create(&path, "correct horse").unwrap();
        vault.add_credential("example.com", None, "user", "pw", "").unwrap();
        let vault_before = std::fs::read(&path).unwrap();
        let backups_before: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| (e.file_name(), std::fs::read(e.path()).unwrap_or_default()))
            .collect();

        // A vault path that cannot be read is the closest reliable stand-in
        // for a rotation failure without mocking the filesystem.
        let missing = dir.path().join("not-there.rbv");
        assert!(rotate_backups(&missing, DEFAULT_MAX_BACKUPS).unwrap().is_none());

        assert_eq!(std::fs::read(&path).unwrap(), vault_before);
        let backups_after: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| (e.file_name(), std::fs::read(e.path()).unwrap_or_default()))
            .collect();
        assert_eq!(backups_after.len(), backups_before.len());
    }

    /// Corrupting the newest backup must still leave an older one openable.
    /// A rotation depth of one that all shares a fate is not a history.
    #[test]
    fn corrupting_the_newest_backup_still_leaves_an_older_one() {
        let dir = TestDir::new("corrupt-newest");
        let path = dir.path().join("vault.rbv");
        let (mut vault, _r) = crate::Vault::create(&path, "correct horse").unwrap();
        vault.add_credential("one.com", None, "user", "pw", "").unwrap();
        vault.add_credential("two.com", None, "user", "pw", "").unwrap();

        let mut backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().contains(BACKUP_SUFFIX))
            .collect();
        backups.sort();
        assert!(backups.len() >= 2, "need a history to test one");

        std::fs::write(backups.last().unwrap(), b"shredded").unwrap();
        assert!(
            crate::Vault::unlock(backups.last().unwrap(), "correct horse").is_err(),
            "the corrupted one must not open"
        );
        assert!(
            crate::Vault::unlock(&backups[0], "correct horse").is_ok(),
            "an older backup must still be restorable"
        );
    }

    /// THE DEFECT. `rotate_backups` documented "call this BEFORE overwriting
    /// the vault", had passing tests, and had NO CALLERS -- `mod backup` is
    /// private and only `ExportError` and the confirmation constant are
    /// re-exported, so nothing outside could reach it either. The documented
    /// guarantee existed in the comment and nowhere else.
    ///
    /// This test is deliberately at the `Vault::save` level rather than
    /// calling `rotate_backups` directly, because calling it directly is
    /// exactly what the old tests did while the product shipped without it.
    #[test]
    fn saving_the_vault_actually_rotates_a_backup() {
        let dir = TestDir::new("save-rotates");
        let path = dir.path().join("vault.rbv");
        let (mut vault, _recovery) = crate::Vault::create(&path, "correct horse").unwrap();

        let count = |d: &TestDir| {
            std::fs::read_dir(d.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().contains(BACKUP_SUFFIX))
                .count()
        };
        // `create` wrote the file; the first save should preserve that copy.
        assert_eq!(count(&dir), 0, "nothing to back up before the first save");

        vault.add_credential("example.com", None, "user", "pw", "").unwrap();
        assert_eq!(
            count(&dir),
            1,
            "saving must preserve the previous ciphertext, or the documented \
             guarantee is a comment and nothing more"
        );

        vault.add_credential("other.com", None, "user", "pw", "").unwrap();
        assert_eq!(count(&dir), 2, "each save keeps another");
        assert!(vault.last_backup_error().is_none(), "no failure to report");
    }

    /// The history stays bounded, or a vault that is saved often quietly
    /// fills the user's disk with ciphertext.
    #[test]
    fn the_backup_history_stays_bounded_across_many_saves() {
        let dir = TestDir::new("save-bounded");
        let path = dir.path().join("vault.rbv");
        let (mut vault, _r) = crate::Vault::create(&path, "correct horse").unwrap();
        for i in 0..(DEFAULT_MAX_BACKUPS + 6) {
            vault.add_credential(&format!("site{i}.com"), None, "user", "pw", "").unwrap();
        }
        let backups = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(BACKUP_SUFFIX))
            .count();
        assert_eq!(backups, DEFAULT_MAX_BACKUPS);
    }

    /// A backup is the vault's ciphertext byte-for-byte, so it must be
    /// openable with the same passphrase. A "backup" that cannot be restored
    /// is decoration.
    #[test]
    fn a_rotated_backup_can_actually_be_opened() {
        let dir = TestDir::new("save-restorable");
        let path = dir.path().join("vault.rbv");
        let (mut vault, _r) = crate::Vault::create(&path, "correct horse").unwrap();
        vault.add_credential("example.com", None, "user", "secret-one", "").unwrap();
        let backup = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.to_string_lossy().contains(BACKUP_SUFFIX))
            .expect("a backup exists");

        let restored = crate::Vault::unlock(&backup, "correct horse")
            .expect("the backup opens with the same passphrase");
        // It is the state from BEFORE that save, which is the whole point.
        assert!(restored.list_credentials().is_empty());
    }

    #[test]
    fn backups_are_bounded_and_prune_oldest_first() {
        let dir = TestDir::new("rotate");
        let vault_path = dir.path().join("vault.rbv");
        let max = 5;
        let mut created = Vec::new();

        for i in 1..=7u8 {
            // Stand-in for the vault's ciphertext: distinct content each
            // "save" so we can tell the copies apart.
            fs::write(&vault_path, format!("ciphertext-version-{i}")).unwrap();
            let backup = rotate_backups(&vault_path, max)
                .expect("rotate")
                .expect("a backup is created once the vault exists");
            created.push(backup);
            // The bound holds after EVERY rotation, not just at the end.
            let remaining = backup_files(&dir, "vault.rbv");
            assert_eq!(
                remaining.len(),
                usize::min(i as usize, max),
                "backups must never exceed the bound"
            );
        }

        // Oldest first: the first two backups are gone, the five newest stay.
        assert!(!created[0].exists(), "oldest backup must be pruned first");
        assert!(!created[1].exists(), "second-oldest must be pruned");
        for backup in &created[2..] {
            assert!(backup.exists(), "newer backups must survive: {backup:?}");
        }
        // The newest backup holds the most recent pre-save content.
        assert_eq!(
            fs::read(created.last().unwrap()).unwrap(),
            b"ciphertext-version-7"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(created.last().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "backups inherit the vault's 0600 rule");
        }
    }

    #[test]
    fn rotation_handles_first_save_and_disabled_backups() {
        let dir = TestDir::new("firstsave");
        let vault_path = dir.path().join("vault.rbv");
        // No vault yet: nothing to preserve, no error.
        assert_eq!(rotate_backups(&vault_path, 5).unwrap(), None);
        // Bound of 0 disables rotation and creates nothing.
        fs::write(&vault_path, b"v1").unwrap();
        assert_eq!(rotate_backups(&vault_path, 0).unwrap(), None);
        assert!(backup_files(&dir, "vault.rbv").is_empty());
    }

    fn backup_files(dir: &TestDir, vault_name: &str) -> Vec<PathBuf> {
        let prefix = format!("{vault_name}{BACKUP_SUFFIX}");
        let mut out: Vec<PathBuf> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n.starts_with(&prefix))
            })
            .collect();
        out.sort();
        out
    }
}
