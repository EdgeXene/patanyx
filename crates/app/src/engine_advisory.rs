//! The engine advisory on the client: fetch, verify, persist, and answer.
//!
//! `patanyx-update` defines the advisory class (`verify_advisory_manifest`):
//! a warning-only signed document that can raise the WebView2 threshold the
//! banner measures against, and nothing else. This module is its impure
//! half, the way `updater.rs` is for release manifests.
//!
//! # Two registers, two authorities
//!
//! The release manifest's `engine_floor` still lands in `engine-floor.json`
//! through `updater::remember_engine_floors`, unchanged in meaning. Advisory
//! floors land in a SEPARATE file, `engine-advisory.json`, and the two are
//! never merged on disk: the platform layer takes the effective maximum at
//! the moment it answers (`platform::effective_floor`). Keeping them apart
//! is what makes the advisory revocable: the release register is a plain
//! high-water mark, while the advisory register keeps the SIGNED ENVELOPE
//! under the verifying key that authenticated it and re-verifies every entry
//! against the compiled `ADVISORY_KEYS` each time it is read or written. A
//! key dropped from that list in a later release takes its floors with it.
//! A forged or mistaken advisory is therefore bounded to "a false banner
//! until the next release", never "a false banner forever".
//!
//! # Only signed evidence has authority
//!
//! Every decision this module makes -- what the effective floor is, whether
//! an incoming advisory is higher than what a key already holds -- is taken
//! from an ENVELOPE THAT VERIFIES NOW under the compiled keys. The register
//! also stores the floor and reason beside each envelope for a human reading
//! the file, and those copies have no authority at all: a corrupt or edited
//! copy is repaired from the envelope on the next write, and an envelope
//! that no longer verifies (revoked key, edited bytes) is dropped. The
//! independent review of 2026-09-11 reproduced the earlier defect exactly:
//! an unsigned cached floor edited upward blocked every authentic advisory
//! afterwards while contributing nothing. Now nothing unsigned can block
//! anything signed.
//!
//! # Monotonic per key; one transaction at a time, across processes
//!
//! An entry is replaced only by a HIGHER floor from the SAME key, at the same
//! exact four-field precision, so a replayed older advisory is a no-op. The
//! whole read-verify-merge-replace runs under TWO locks: a process-wide
//! mutex for threads, and an exclusive OS file lock (`std::fs::File::lock`:
//! `flock` on Unix, `LockFileEx` on Windows) on `engine-advisory.lock` for
//! OTHER PROCESSES sharing the data directory. Atomic rename alone was shown
//! to be insufficient: two browser processes that both read an empty
//! register and then rename in turn let the lower value land last. The lock
//! makes the second writer re-read after the first has committed. The file
//! is still written whole through a temp file and a rename, so a crash mid-
//! write leaves the previous bytes exactly as they were. A failed write is
//! RETURNED, not swallowed; the check reports it.
//!
//! # What the fetch reveals
//!
//! One unconditional GET of a URL identical for every install:
//! `<UPDATE_BASE_URL>/v1/engine-advisory.json`. No version, no token, no
//! query string, no cache validator. It is ONE MORE REQUEST to the same
//! host, in the same six-hour check as the release manifest: the host (and
//! anything on the path) sees, once more, an IP address, the request time,
//! the requested path and the generic `patanyx` user agent -- and nothing
//! that distinguishes one install from another. The Updates panel describes
//! update checks as release information plus, when configured, engine
//! advisories, without an exact request count: an unconfigured build makes
//! no advisory request, and the transport retries a failed connection. The
//! comparison happens here, against the compiled floor; the runtime version
//! never leaves the machine.
//!
//! # Not configured is a state, and it is visible
//!
//! Until a release ships with a real key in `ADVISORY_KEYS`, the channel is
//! `Unconfigured`: nothing is fetched, nothing is persisted, and the status
//! snapshot says so in words that cannot be mistaken for a working channel.
//! Tests inject their own keys; the production list is empty on purpose and
//! a test pins it that way until the lander provisions it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use patanyx_update::{verify_advisory_manifest, AdvisoryManifest, TrustedKeys, UpdateError};
use serde_json::{json, Value};

use crate::updater::FetchError;

/// The fixed advisory path under the distribution host. One file for every
/// install; nothing per-platform because the document names its engine.
pub(crate) const ADVISORY_PATH: &str = "/v1/engine-advisory.json";

/// An advisory envelope is a few hundred bytes; the verifier caps at 16 KiB
/// and the fetch must never buffer more than the verifier would look at.
const MAX_ADVISORY_FETCH_BYTES: u64 = 16 * 1024;

/// Wire version of the on-disk register, so a future shape cannot be
/// misread by this reader.
const REGISTER_VERSION: u64 = 1;

pub(crate) fn advisory_url() -> String {
    format!("{}{ADVISORY_PATH}", crate::updater::base_url())
}

/// Where advisory floors live: `updates/engine-advisory.json`, beside the
/// release register.
pub(crate) fn register_path(dir: &Path) -> PathBuf {
    dir.join("engine-advisory.json")
}

/// The cross-process lock file. Separate from the register so the register
/// itself can be replaced by rename while the lock stays held.
pub(crate) fn lock_path(dir: &Path) -> PathBuf {
    dir.join("engine-advisory.lock")
}

/// The one in-process lock every register write takes. Both registers share
/// it: they are two files, but a check may touch both, and one lock is
/// simpler to reason about than an ordering rule.
static REGISTER_LOCK: Mutex<()> = Mutex::new(());

fn thread_lock() -> std::sync::MutexGuard<'static, ()> {
    REGISTER_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// An exclusive OS-level lock on `engine-advisory.lock`, held for the life
/// of the guard. Threads are serialised by the mutex first, then processes
/// by the file lock, so a second browser instance sharing the directory
/// waits for the first's transaction to commit before it reads.
///
/// `std::fs::File::lock` is `flock(LOCK_EX)` on Unix and `LockFileEx` with
/// `LOCKFILE_EXCLUSIVE_LOCK` on Windows; both release when the file closes,
/// so a crashed holder never leaves the register locked.
pub(crate) struct RegisterGuard {
    _thread: std::sync::MutexGuard<'static, ()>,
    file: std::fs::File,
}

impl Drop for RegisterGuard {
    fn drop(&mut self) {
        // Best effort: close releases the lock on every platform anyway.
        let _ = self.file.unlock();
    }
}

/// Take both locks. Creates the directory and the lock file if needed;
/// a directory that cannot be created is an error the caller reports.
pub(crate) fn register_guard(dir: &Path) -> std::io::Result<RegisterGuard> {
    let thread = thread_lock();
    std::fs::create_dir_all(dir)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path(dir))?;
    file.lock()?;
    Ok(RegisterGuard {
        _thread: thread,
        file,
    })
}

/// Write `bytes` to `path` atomically: a uniquely named temp file in the
/// same directory, flushed and synced, then renamed over the target. A
/// reader sees the old file or the new one, never a torn one, and a failure
/// at any step leaves the old file untouched and the temp file removed.
///
/// Shared with the release-floor register (`updater::remember_engine_floors`),
/// which used to be a plain `fs::write` -- a crash mid-write could leave an
/// unparseable file, and an unparseable register reads as "no floor".
/// Atomicity is about torn files; ORDERING between writers is the lock's
/// job, and callers hold `register_guard` around read-merge-write.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "register path has no parent")
    })?;
    std::fs::create_dir_all(dir)?;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("register");
    let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The outcome of one advisory check, for the status snapshot and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdvisoryOutcome {
    /// No advisory key is compiled into this build. Nothing was fetched.
    Unconfigured,
    /// Verified, plausible, and higher than what this key had persisted.
    Raised { floor: [u32; 4] },
    /// Verified and plausible, but not higher than what was already held.
    Unchanged { floor: [u32; 4] },
    /// Fetched but not authentic or not sane. Nothing changed.
    Refused(String),
    /// Could not fetch, or could not persist. Nothing changed on disk (a
    /// persist failure leaves the previous bytes intact by construction).
    Failed(String),
}

impl AdvisoryOutcome {
    /// The snapshot shape update.js may read. `state` strings are a
    /// contract; the detail strings are for diagnostics, not the banner
    /// (the banner's words come from the platform layer).
    pub(crate) fn to_json(&self) -> Value {
        match self {
            AdvisoryOutcome::Unconfigured => json!({
                "state": "unconfigured",
                "detail": "no engine advisory key is compiled into this build; \
                           the advisory channel is not active",
            }),
            AdvisoryOutcome::Raised { floor } => {
                json!({ "state": "raised", "floor": crate::platform::join_version(floor) })
            }
            AdvisoryOutcome::Unchanged { floor } => {
                json!({ "state": "unchanged", "floor": crate::platform::join_version(floor) })
            }
            AdvisoryOutcome::Refused(why) => json!({ "state": "refused", "detail": why }),
            AdvisoryOutcome::Failed(why) => json!({ "state": "failed", "detail": why }),
        }
    }
}

/// One advisory check with every impure input injected: the compiled key
/// set (or the error that says there is none), the fetch, the register
/// directory, the compiled floor and the clock. Production binds the real
/// ones in `check`; tests bind their own and drive the REAL verifier.
pub(crate) fn run_advisory_check(
    keys: Result<TrustedKeys, UpdateError>,
    fetch: impl FnOnce() -> Result<Vec<u8>, FetchError>,
    dir: &Path,
    compiled: &[u32; 4],
    now_unix: u64,
) -> AdvisoryOutcome {
    let Ok(keys) = keys else {
        return AdvisoryOutcome::Unconfigured;
    };
    let bytes = match fetch() {
        Ok(bytes) => bytes,
        Err(e) => return AdvisoryOutcome::Failed(format!("fetch: {}", fetch_word(&e))),
    };
    let manifest = match verify_advisory_manifest(&bytes, &keys) {
        Ok(m) => m,
        Err(e) => return AdvisoryOutcome::Refused(format!("verify: {e}")),
    };
    if let Err(e) = manifest.check_plausible(compiled, now_unix) {
        return AdvisoryOutcome::Refused(format!("bounds: {e}"));
    }
    match remember(dir, &keys, &manifest, &bytes, compiled, now_unix) {
        Ok(true) => AdvisoryOutcome::Raised {
            floor: *manifest.webview2(),
        },
        Ok(false) => AdvisoryOutcome::Unchanged {
            floor: *manifest.webview2(),
        },
        Err(e) => AdvisoryOutcome::Failed(format!("persist: {e}")),
    }
}

/// No Rust error text for the user; the network detail is not actionable.
fn fetch_word(e: &FetchError) -> &'static str {
    match e {
        FetchError::Network(_) => "could not reach the advisory server",
        FetchError::Http(_) => "the advisory server answered with an error",
        FetchError::TooLarge => "the advisory was larger than an advisory can be",
    }
}

/// The production check: real keys, real fetch, real directory, real clock.
/// Called from the update check's worker thread after the release manifest
/// has been handled, whatever that handling concluded -- a failed or refused
/// release check must not cost the user the advisory.
pub(crate) fn check() -> AdvisoryOutcome {
    let keys = crate::updater::advisory_trusted_keys();
    let url = advisory_url();
    run_advisory_check(
        keys,
        || crate::updater::net::get(&url, MAX_ADVISORY_FETCH_BYTES, crate::updater::net::MANIFEST_TIMEOUT),
        &crate::updater::data_dir(),
        &crate::platform::MIN_WEBVIEW2,
        crate::updater::unix_now(),
    )
}

fn key_hex(key: &[u8; 32]) -> String {
    patanyx_update::hex::encode(key)
}

/// Read the register leniently: a missing or unparseable file is an empty
/// register (its contents are re-verified on every read anyway, so nothing
/// in it is trusted for being on disk).
fn read_register(dir: &Path) -> serde_json::Map<String, Value> {
    let Ok(raw) = std::fs::read_to_string(register_path(dir)) else {
        return serde_json::Map::new();
    };
    let Ok(doc) = serde_json::from_str::<Value>(&raw) else {
        return serde_json::Map::new();
    };
    if doc.get("v").and_then(Value::as_u64) != Some(REGISTER_VERSION) {
        return serde_json::Map::new();
    }
    match doc.get("entries") {
        Some(Value::Object(map)) => map.clone(),
        _ => serde_json::Map::new(),
    }
}

/// Every entry that still counts: its envelope verifies NOW under `keys`
/// and is within the plausibility bounds. Keyed by the key that ACTUALLY
/// signed it (the slot name is bookkeeping, not evidence). Where two entries
/// somehow verify under one key, the higher floor is kept.
fn authenticated_entries(
    entries: &serde_json::Map<String, Value>,
    keys: &TrustedKeys,
    compiled: &[u32; 4],
    now_unix: u64,
) -> std::collections::BTreeMap<String, (AdvisoryManifest, String)> {
    let mut out: std::collections::BTreeMap<String, (AdvisoryManifest, String)> =
        std::collections::BTreeMap::new();
    for entry in entries.values() {
        let Some(envelope) = entry.get("envelope").and_then(Value::as_str) else {
            continue;
        };
        let Ok(manifest) = verify_advisory_manifest(envelope.as_bytes(), keys) else {
            continue;
        };
        if manifest.check_plausible(compiled, now_unix).is_err() {
            continue;
        }
        let slot = key_hex(manifest.verified_by());
        match out.get(&slot) {
            Some((have, _)) if have.webview2() >= manifest.webview2() => {}
            _ => {
                out.insert(slot, (manifest, envelope.to_string()));
            }
        }
    }
    out
}

/// The canonical on-disk entry for a verified envelope. The floor and
/// reason are copies for a human reading the file and carry no authority.
fn canonical_entry(manifest: &AdvisoryManifest, envelope: &str) -> Value {
    json!({
        "floor": manifest.webview2().to_vec(),
        "published_at": manifest.published_at(),
        "reason": manifest.reason(),
        "envelope": envelope,
    })
}

/// The merge, pure: given the entries that currently VERIFY and an incoming
/// verified advisory, the register to write and whether the incoming floor
/// rose above what its key already held. `None` means the register on disk
/// already equals what would be written -- a true no-op.
///
/// Authority for "what this key already holds" is the verified old envelope
/// and nothing else. An entry whose envelope no longer verifies is not in
/// `current` and so cannot block anything; an entry whose human-readable
/// copies disagree with its envelope is rewritten from the envelope.
fn merge(
    on_disk: &serde_json::Map<String, Value>,
    current: &std::collections::BTreeMap<String, (AdvisoryManifest, String)>,
    incoming: &AdvisoryManifest,
    envelope: &str,
) -> (Option<serde_json::Map<String, Value>>, bool) {
    let slot = key_hex(incoming.verified_by());
    let mut next: serde_json::Map<String, Value> = serde_json::Map::new();
    for (k, (m, e)) in current {
        next.insert(k.clone(), canonical_entry(m, e));
    }
    let rose = match current.get(&slot) {
        Some((have, _)) if have.webview2() >= incoming.webview2() => false,
        _ => {
            next.insert(slot, canonical_entry(incoming, envelope));
            true
        }
    };
    if !rose && *on_disk == next {
        return (None, false);
    }
    (Some(next), rose)
}

/// Record a VERIFIED advisory under its key. Returns `Ok(true)` when the
/// register rose, `Ok(false)` when the key already held an authenticated
/// floor at least this high, `Err` when the file could not be written
/// (previous bytes are intact). A register whose unsigned copies were
/// corrupt, or which carried entries under revoked keys, is repaired on the
/// way through even when the incoming floor is not higher.
pub(crate) fn remember(
    dir: &Path,
    keys: &TrustedKeys,
    manifest: &AdvisoryManifest,
    envelope: &[u8],
    compiled: &[u32; 4],
    now_unix: u64,
) -> std::io::Result<bool> {
    remember_with(dir, keys, manifest, envelope, compiled, now_unix, write_atomic)
}

/// `remember` with the writer injected, so a test can make the write fail
/// and prove the previous file survives, or pause inside the transaction
/// and prove a second process waits. The writer runs WITH THE LOCKS HELD.
pub(crate) fn remember_with(
    dir: &Path,
    keys: &TrustedKeys,
    manifest: &AdvisoryManifest,
    envelope: &[u8],
    compiled: &[u32; 4],
    now_unix: u64,
    writer: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<bool> {
    let envelope = std::str::from_utf8(envelope).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "envelope is not utf-8")
    })?;
    let _guard = register_guard(dir)?;
    let on_disk = read_register(dir);
    let current = authenticated_entries(&on_disk, keys, compiled, now_unix);
    let (next, rose) = merge(&on_disk, &current, manifest, envelope);
    if let Some(next) = next {
        let doc = json!({ "v": REGISTER_VERSION, "entries": next });
        writer(&register_path(dir), doc.to_string().as_bytes())?;
    }
    Ok(rose)
}

/// The highest advisory floor any CURRENTLY TRUSTED key has asserted, or
/// `None`. Every entry is re-verified against `keys` here; the file is not
/// trusted for being on disk. Entries under a revoked key, entries whose
/// envelope no longer verifies, and entries out of the plausibility bounds
/// contribute nothing. The unsigned copies beside each envelope are not
/// consulted.
pub(crate) fn persisted_floor_with(
    dir: &Path,
    keys: &TrustedKeys,
    compiled: &[u32; 4],
    now_unix: u64,
) -> Option<[u32; 4]> {
    authenticated_entries(&read_register(dir), keys, compiled, now_unix)
        .values()
        .map(|(m, _)| *m.webview2())
        .max()
}

/// The production reader: compiled keys, real directory, real clock. `None`
/// while the channel is unconfigured, which is the honest answer -- an
/// empty key set can verify nothing, so nothing persisted can count.
pub(crate) fn persisted_floor() -> Option<[u32; 4]> {
    let keys = crate::updater::advisory_trusted_keys().ok()?;
    persisted_floor_with(
        &crate::updater::data_dir(),
        &keys,
        &crate::platform::MIN_WEBVIEW2,
        crate::updater::unix_now(),
    )
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Explicit TEST keys. Never the production list, which is empty until
    //! the lander provisions it; never a key generated outside a test.
    use ed25519_dalek::{Signer, SigningKey};
    use patanyx_update::{TrustedKeys, SIGNING_DOMAIN_ADVISORY};

    pub const SEED_ADVISORY_A: [u8; 32] = *b"patanyx-test-advisory-key-A-0000";
    pub const SEED_ADVISORY_B: [u8; 32] = *b"patanyx-test-advisory-key-B-0000";
    pub const SEED_ATTACKER: [u8; 32] = *b"patanyx-test-advisory-attacker-0";

    pub fn key(seed: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    pub fn trusted(seeds: &[&[u8; 32]]) -> TrustedKeys {
        TrustedKeys::new(seeds.iter().map(|s| key(s).verifying_key()).collect())
            .expect("a non-empty test key set")
    }

    pub fn hex(bytes: &[u8]) -> String {
        patanyx_update::hex::encode(bytes)
    }

    pub fn payload(floor: &str, published_at: u64, reason: &str) -> String {
        format!(
            "{{\"engine\":\"webview2\",\"floor\":\"{floor}\",\"published_at\":{published_at},\"reason\":\"{reason}\"}}"
        )
    }

    /// The exact construction the signer example reproduces: Ed25519 over
    /// `SIGNING_DOMAIN_ADVISORY || payload`, payload embedded as a JSON
    /// string.
    pub fn sign(payload: &str, key: &SigningKey) -> Vec<u8> {
        let mut message = Vec::with_capacity(SIGNING_DOMAIN_ADVISORY.len() + payload.len());
        message.extend_from_slice(SIGNING_DOMAIN_ADVISORY);
        message.extend_from_slice(payload.as_bytes());
        format!(
            "{{\"v\":1,\"payload\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(payload).expect("a string always serializes"),
            hex(&key.sign(&message).to_bytes())
        )
        .into_bytes()
    }

    pub fn signed(floor: &str, published_at: u64, seed: &[u8; 32]) -> Vec<u8> {
        sign(&payload(floor, published_at, "CVE-TEST-0001"), &key(seed))
    }

    pub fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "patanyx-engine-advisory-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    const COMPILED: [u32; 4] = [152, 0, 4191, 62];
    const NOW: u64 = 1_757_600_000;
    const T: u64 = 1_757_570_000;

    fn check(dir: &Path, keys: &[&[u8; 32]], bytes: Vec<u8>) -> AdvisoryOutcome {
        run_advisory_check(Ok(trusted(keys)), || Ok(bytes), dir, &COMPILED, NOW)
    }

    fn floor_now(dir: &Path, keys: &[&[u8; 32]]) -> Option<[u32; 4]> {
        persisted_floor_with(dir, &trusted(keys), &COMPILED, NOW)
    }

    fn register_bytes(dir: &Path) -> Vec<u8> {
        std::fs::read(register_path(dir)).unwrap()
    }

    /// The URL is fixed for every install: TLS, no version, no token, no
    /// query string. The privacy property the release check has, kept.
    #[test]
    fn the_advisory_url_is_one_fixed_tls_address_with_nothing_per_install() {
        let url = advisory_url();
        assert!(url.starts_with("https://"), "{url}");
        assert!(url.ends_with(ADVISORY_PATH), "{url}");
        assert!(!url.contains('?'), "no query string: {url}");
        assert!(!url.contains(env!("CARGO_PKG_VERSION")), "no running version: {url}");
        assert!(!url.contains("152.0"), "no runtime version: {url}");
    }

    /// The register starts empty, rises on a verified advisory, and is read
    /// back as the effective advisory floor.
    #[test]
    fn a_verified_advisory_raises_the_register_and_is_read_back() {
        let dir = scratch("raise");
        assert_eq!(floor_now(&dir, &[&SEED_ADVISORY_A]), None);
        let out = check(&dir, &[&SEED_ADVISORY_A], signed("152.0.4191.66", T, &SEED_ADVISORY_A));
        assert_eq!(out, AdvisoryOutcome::Raised { floor: [152, 0, 4191, 66] });
        assert_eq!(floor_now(&dir, &[&SEED_ADVISORY_A]), Some([152, 0, 4191, 66]));
        assert!(register_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lower, equal (replayed) and omitted floors change nothing -- neither
    /// the answer nor the BYTES; only a strictly higher floor at the same
    /// precision rises. The fourth field is the field that decides.
    #[test]
    fn stale_lower_replayed_and_omitted_floors_never_lower_the_register() {
        let dir = scratch("monotonic");
        let a = &SEED_ADVISORY_A;
        assert!(matches!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Raised { .. }
        ));
        let bytes_after_raise = register_bytes(&dir);
        // Replayed: same bytes again.
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Unchanged { floor: [152, 0, 4191, 66] }
        );
        assert_eq!(register_bytes(&dir), bytes_after_raise, "a replay rewrites nothing");
        // Lower in the fourth field, newer timestamp: still not higher.
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.62", T + 1000, a)),
            AdvisoryOutcome::Unchanged { floor: [152, 0, 4191, 62] }
        );
        assert_eq!(register_bytes(&dir), bytes_after_raise);
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 66]));
        // Omitted floor: refused by the verifier, register untouched.
        let omitted = sign(
            &format!("{{\"engine\":\"webview2\",\"published_at\":{T}}}"),
            &key(a),
        );
        assert!(matches!(check(&dir, &[a], omitted), AdvisoryOutcome::Refused(_)));
        assert_eq!(register_bytes(&dir), bytes_after_raise);
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 66]));
        // Higher in the fourth field only: rises.
        assert!(matches!(
            check(&dir, &[a], signed("152.0.4191.70", T, a)),
            AdvisoryOutcome::Raised { .. }
        ));
        assert_ne!(register_bytes(&dir), bytes_after_raise);
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 70]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Forged (untrusted key), malformed (wrong precision), and implausible
    /// (far future major, future timestamp) advisories are refused and the
    /// register is untouched -- and nothing is written by a refusal.
    #[test]
    fn forged_malformed_and_future_advisories_are_refused_without_a_write() {
        let dir = scratch("refuse");
        let a = &SEED_ADVISORY_A;
        for (name, bytes) in [
            ("forged", signed("153.0.4300.10", T, &SEED_ATTACKER)),
            ("three fields", signed("153.0.4300", T, a)),
            ("five fields", signed("153.0.4300.10.1", T, a)),
            ("far-future major", signed("999.0.0.1", T, a)),
            ("future timestamp", signed("153.0.4300.10", NOW + 30 * 86400, a)),
            ("garbage", b"not an envelope".to_vec()),
        ] {
            let out = check(&dir, &[a], bytes);
            assert!(
                matches!(out, AdvisoryOutcome::Refused(_)),
                "{name} should be refused, got {out:?}"
            );
        }
        assert!(!register_path(&dir).exists(), "a refusal must not create the register");
        assert_eq!(floor_now(&dir, &[a]), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KEY REVOCATION. A floor persisted under key A stops counting the
    /// moment A leaves the compiled set, even though the bytes on disk are
    /// unchanged; and the next write under the remaining key PRUNES the
    /// revoked entry, so nothing revoked lingers. The release-floor register
    /// is never touched by any of this.
    #[test]
    fn revoking_a_key_removes_its_persisted_floor() {
        let dir = scratch("revoke");
        let a = &SEED_ADVISORY_A;
        let b = &SEED_ADVISORY_B;
        assert!(matches!(
            check(&dir, &[a, b], signed("153.0.4300.10", T, a)),
            AdvisoryOutcome::Raised { .. }
        ));
        assert!(matches!(
            check(&dir, &[a, b], signed("152.0.4191.66", T, b)),
            AdvisoryOutcome::Raised { .. }
        ));
        // Both trusted: the effective floor is A's higher one.
        assert_eq!(floor_now(&dir, &[a, b]), Some([153, 0, 4300, 10]));
        // A revoked: B's floor is what remains, with the bytes unchanged.
        assert_eq!(floor_now(&dir, &[b]), Some([152, 0, 4191, 66]));
        // Both revoked: nothing.
        assert_eq!(floor_now(&dir, &[&SEED_ATTACKER]), None);
        // A write under B alone prunes A's entry from the file.
        assert_eq!(
            check(&dir, &[b], signed("152.0.4191.66", T, b)),
            AdvisoryOutcome::Unchanged { floor: [152, 0, 4191, 66] }
        );
        let doc: Value = serde_json::from_slice(&register_bytes(&dir)).unwrap();
        let entries = doc["entries"].as_object().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key(&hex(key(b).verifying_key().as_bytes())));
        // Re-trusting A does not resurrect the pruned floor from disk; the
        // next fetch would. Nothing on disk is believed for being there.
        assert_eq!(floor_now(&dir, &[a, b]), Some([152, 0, 4191, 66]));
        // The release-floor register was never created by any of this.
        assert!(!dir.join("engine-floor.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REPRODUCED BY THE INDEPENDENT REVIEW, NOW A REGRESSION: the unsigned
    /// copies beside an envelope have no authority. Editing the cached
    /// floor upward neither raises the effective floor nor blocks a later
    /// authentic advisory; the entry is repaired from its envelope on the
    /// next write. Editing the ENVELOPE drops the entry; a genuine entry in
    /// the wrong slot still counts (the signature is the evidence) and is
    /// moved to the right slot; a corrupt or legacy shape is an absence.
    #[test]
    fn unsigned_register_metadata_has_no_authority_and_is_repaired() {
        let dir = scratch("tamper");
        let a = &SEED_ADVISORY_A;
        assert!(matches!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Raised { .. }
        ));
        let raw = String::from_utf8(register_bytes(&dir)).unwrap();
        let slot = hex(key(a).verifying_key().as_bytes());

        // THE REVIEW'S CASE. Cached floor edited to 999: the envelope still
        // says .66, so .66 is what counts...
        let mut doc: Value = serde_json::from_str(&raw).unwrap();
        doc["entries"][&slot]["floor"] = json!([999, 0, 0, 0]);
        std::fs::write(register_path(&dir), doc.to_string()).unwrap();
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 66]));
        // ...an authentic replay of .66 is Unchanged AND repairs the file...
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Unchanged { floor: [152, 0, 4191, 66] }
        );
        let repaired: Value = serde_json::from_slice(&register_bytes(&dir)).unwrap();
        assert_eq!(repaired["entries"][&slot]["floor"], json!([152, 0, 4191, 66]));
        // ...and an authentic .70 rises past it.
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.70", T, a)),
            AdvisoryOutcome::Raised { floor: [152, 0, 4191, 70] }
        );
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 70]));

        // Cached floor edited DOWN under a genuine .70 envelope: the higher
        // authenticated floor is preserved; an incoming .66 does not win.
        let raw70 = String::from_utf8(register_bytes(&dir)).unwrap();
        let mut doc: Value = serde_json::from_str(&raw70).unwrap();
        doc["entries"][&slot]["floor"] = json!([1, 0, 0, 0]);
        std::fs::write(register_path(&dir), doc.to_string()).unwrap();
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 70]));
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Unchanged { floor: [152, 0, 4191, 66] }
        );
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 70]));
        let repaired: Value = serde_json::from_slice(&register_bytes(&dir)).unwrap();
        assert_eq!(repaired["entries"][&slot]["floor"], json!([152, 0, 4191, 70]));

        // Envelope edited in place: nothing verifies, nothing counts, and
        // an authentic .66 then raises from empty.
        let edited = raw70.replace("152.0.4191.70", "160.0.0.1");
        assert_ne!(edited, raw70);
        std::fs::write(register_path(&dir), edited).unwrap();
        assert_eq!(floor_now(&dir, &[a]), None);
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Raised { floor: [152, 0, 4191, 66] }
        );
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 66]));

        // Genuine entry filed under another key's slot: the signature is
        // the evidence, so it counts, and the next write moves it home.
        let raw66 = String::from_utf8(register_bytes(&dir)).unwrap();
        let mut doc: Value = serde_json::from_str(&raw66).unwrap();
        let entry = doc["entries"][&slot].clone();
        let other = hex(key(&SEED_ADVISORY_B).verifying_key().as_bytes());
        doc["entries"] = json!({ other.clone(): entry });
        std::fs::write(register_path(&dir), doc.to_string()).unwrap();
        assert_eq!(floor_now(&dir, &[a, &SEED_ADVISORY_B]), Some([152, 0, 4191, 66]));
        assert_eq!(
            check(&dir, &[a, &SEED_ADVISORY_B], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Unchanged { floor: [152, 0, 4191, 66] }
        );
        let moved: Value = serde_json::from_slice(&register_bytes(&dir)).unwrap();
        assert!(moved["entries"].get(&slot).is_some());
        assert!(moved["entries"].get(&other).is_none());

        // A legacy or corrupt shape: not a truncation, an absence.
        std::fs::write(register_path(&dir), "{\"v\":1,\"entries\":{\"x\":{\"floor\":[1,2,3,99999999999]}}}").unwrap();
        assert_eq!(floor_now(&dir, &[a]), None);
        std::fs::write(register_path(&dir), "garbage").unwrap();
        assert_eq!(floor_now(&dir, &[a]), None);
        assert_eq!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Raised { floor: [152, 0, 4191, 66] }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// INTERRUPTED WRITE. A writer that fails leaves the previous bytes
    /// exactly as they were and the failure is returned, not swallowed. A
    /// temp file left by a crashed writer is not mistaken for the register.
    #[test]
    fn a_failed_write_leaves_the_last_good_register_intact_and_is_reported() {
        let dir = scratch("interrupted");
        let a = &SEED_ADVISORY_A;
        assert!(matches!(
            check(&dir, &[a], signed("152.0.4191.66", T, a)),
            AdvisoryOutcome::Raised { .. }
        ));
        let before = register_bytes(&dir);

        let bytes = signed("153.0.4300.10", T, a);
        let manifest = verify_advisory_manifest(&bytes, &trusted(&[a])).unwrap();
        let err = remember_with(&dir, &trusted(&[a]), &manifest, &bytes, &COMPILED, NOW, |_, _| {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "disk full"))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert_eq!(register_bytes(&dir), before);
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 66]));

        // Through the pipeline the failure is an observable outcome: a
        // register directory that is actually a regular file cannot hold
        // the lock file, so the transaction fails before anything moves.
        std::fs::write(dir.join("not-a-directory"), b"x").unwrap();
        let out = run_advisory_check(
            Ok(trusted(&[a])),
            || Ok(signed("153.0.4300.10", T, a)),
            &dir.join("not-a-directory"),
            &COMPILED,
            NOW,
        );
        assert!(
            matches!(out, AdvisoryOutcome::Failed(ref w) if w.starts_with("persist:")),
            "got {out:?}"
        );
        assert_eq!(std::fs::read(dir.join("not-a-directory")).unwrap(), b"x");

        // A stale temp file from a crashed run is ignored by the reader and
        // not renamed over the register by anyone.
        std::fs::write(dir.join(".engine-advisory.json.999.0.tmp"), b"{\"v\":1,\"entries\":{}}").unwrap();
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 66]));
        assert_eq!(register_bytes(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CONCURRENT OBSERVATIONS, IN ONE PROCESS. Many threads racing distinct
    /// floors under the same key end with a valid file holding the highest,
    /// never a torn file and never a lower value winning by arriving last.
    #[test]
    fn concurrent_observations_converge_on_the_highest_floor() {
        let dir = scratch("concurrent");
        let a = &SEED_ADVISORY_A;
        let mut handles = Vec::new();
        for i in 0..16u32 {
            let dir = dir.clone();
            handles.push(std::thread::spawn(move || {
                // Shuffled order so "last writer" is not "highest".
                let fourth = 62 + ((i * 7) % 16);
                let floor = format!("152.0.4191.{fourth}");
                check(&dir, &[&SEED_ADVISORY_A], signed(&floor, T, &SEED_ADVISORY_A))
            }));
        }
        for h in handles {
            let out = h.join().expect("thread");
            assert!(
                matches!(out, AdvisoryOutcome::Raised { .. } | AdvisoryOutcome::Unchanged { .. }),
                "{out:?}"
            );
        }
        assert_eq!(floor_now(&dir, &[a]), Some([152, 0, 4191, 77]));
        // Valid JSON with exactly one entry, no temp files left behind.
        let doc: Value = serde_json::from_slice(&register_bytes(&dir)).unwrap();
        assert_eq!(doc["entries"].as_object().unwrap().len(), 1);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The worker half of the cross-process test below. Runs only when the
    /// driver re-executes this test binary with the environment set; as an
    /// ordinary test it returns immediately.
    ///
    /// Behaviour: write `<floor>` through the real transaction. The "hold"
    /// worker pauses INSIDE the transaction (locks held, register read and
    /// merged) until the driver says go, then commits. The "wait" worker
    /// records when it got in, whether its writer ran, and what it returned.
    #[test]
    fn cross_process_worker_entry() {
        let Ok(dir) = std::env::var("PATANYX_ADVISORY_RACE_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let role = std::env::var("PATANYX_ADVISORY_RACE_ROLE").unwrap();
        let floor = std::env::var("PATANYX_ADVISORY_RACE_FLOOR").unwrap();
        let a = &SEED_ADVISORY_A;
        let bytes = signed(&floor, T, a);
        let manifest = verify_advisory_manifest(&bytes, &trusted(&[a])).unwrap();
        let mut writer_ran = false;
        let rose = remember_with(&dir, &trusted(&[a]), &manifest, &bytes, &COMPILED, NOW, |p, b| {
            writer_ran = true;
            if role == "hold" {
                std::fs::write(dir.join("hold-inside"), b"inside").unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while !dir.join("go").exists() {
                    assert!(std::time::Instant::now() < deadline, "driver never said go");
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            write_atomic(p, b)
        })
        .unwrap();
        std::fs::write(
            dir.join(format!("result-{role}")),
            format!("rose={rose} writer_ran={writer_ran}"),
        )
        .unwrap();
    }

    /// CROSS-PROCESS, REPRODUCED BY THE INDEPENDENT REVIEW, NOW A REGRESSION.
    /// Two separate processes share one register. Process H enters the
    /// transaction with a HIGHER floor (.70) and pauses with the locks held.
    /// Process L then tries to record a LOWER floor (.66). Before the file
    /// lock, L would have read the empty register, merged, and renamed its
    /// stale .66 over H's .70. Now L blocks until H commits, re-reads .70,
    /// and its writer never runs: the register ends at .70, and the bytes
    /// are the bytes H wrote.
    #[test]
    fn a_second_process_cannot_lower_the_floor_by_arriving_last() {
        let dir = scratch("race");
        let exe = std::env::current_exe().unwrap();
        let spawn = |role: &str, floor: &str| {
            std::process::Command::new(&exe)
                .args(["--exact", "engine_advisory::tests::cross_process_worker_entry", "--nocapture", "--test-threads=1"])
                .env("PATANYX_ADVISORY_RACE_DIR", &dir)
                .env("PATANYX_ADVISORY_RACE_ROLE", role)
                .env("PATANYX_ADVISORY_RACE_FLOOR", floor)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn worker")
        };
        let wait_for = |name: &str| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !dir.join(name).exists() {
                assert!(std::time::Instant::now() < deadline, "timed out waiting for {name}");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };
        let mut high = spawn("hold", "152.0.4191.70");
        wait_for("hold-inside");
        // H is inside the transaction with the locks held. Start L.
        let mut low = spawn("wait", "152.0.4191.66");
        // Give L a real chance to misbehave: if the lock did not hold, L
        // would finish here with its own stale write.
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(!dir.join("result-wait").exists(), "L committed while H held the lock");
        assert!(!register_path(&dir).exists(), "nothing may be written while H holds the lock");
        std::fs::write(dir.join("go"), b"go").unwrap();
        assert!(high.wait().unwrap().success(), "H must succeed");
        assert!(low.wait().unwrap().success(), "L must succeed");
        let h_bytes = register_bytes(&dir);
        assert_eq!(
            std::fs::read_to_string(dir.join("result-hold")).unwrap(),
            "rose=true writer_ran=true"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("result-wait")).unwrap(),
            "rose=false writer_ran=false",
            "L must have re-read H's commit and written nothing"
        );
        assert_eq!(floor_now(&dir, &[&SEED_ADVISORY_A]), Some([152, 0, 4191, 70]));
        assert_eq!(register_bytes(&dir), h_bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// UNCONFIGURED IS VISIBLE. With no compiled key nothing is fetched (the
    /// fetch closure must not run), nothing is written, and the snapshot
    /// says so in words that cannot be read as a working channel.
    #[test]
    fn an_unconfigured_channel_fetches_nothing_and_says_so() {
        let dir = scratch("unconfigured");
        let mut fetched = false;
        let out = run_advisory_check(
            Err(UpdateError::NoTrustedKeys),
            || {
                fetched = true;
                Ok(Vec::new())
            },
            &dir,
            &COMPILED,
            NOW,
        );
        assert_eq!(out, AdvisoryOutcome::Unconfigured);
        assert!(!fetched, "an unconfigured channel must not fetch");
        assert!(!register_path(&dir).exists());
        let snapshot = out.to_json();
        assert_eq!(snapshot["state"], "unconfigured");
        assert!(snapshot["detail"].as_str().unwrap().contains("not active"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fetch failure is a failure, reported as such, with nothing changed.
    #[test]
    fn a_fetch_failure_is_reported_and_changes_nothing() {
        let dir = scratch("fetchfail");
        let out = run_advisory_check(
            Ok(trusted(&[&SEED_ADVISORY_A])),
            || Err(FetchError::Network("boom".into())),
            &dir,
            &COMPILED,
            NOW,
        );
        assert!(matches!(out, AdvisoryOutcome::Failed(ref w) if w.starts_with("fetch:")));
        assert!(
            !format!("{out:?}").contains("boom"),
            "no raw network text reaches the snapshot"
        );
        assert!(!register_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The atomic writer, on its own: the target is replaced whole and no
    /// temp file survives success or failure.
    #[test]
    fn write_atomic_replaces_whole_and_cleans_up() {
        let dir = scratch("atomic");
        let target = dir.join("engine-advisory.json");
        write_atomic(&target, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        write_atomic(&target, b"second, longer").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second, longer");
        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1, "only the register itself remains");
        // A target whose parent cannot be created fails and leaves nothing.
        let blocked = dir.join("file");
        std::fs::write(&blocked, b"x").unwrap();
        assert!(write_atomic(&blocked.join("register.json"), b"z").is_err());
        assert_eq!(std::fs::read(&blocked).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
