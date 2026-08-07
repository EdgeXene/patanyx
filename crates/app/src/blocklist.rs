//! Known-malicious hosts, and the decision to refuse them.
//!
//! This is the protection for users who never open a settings panel. Choosing
//! Mullvad or Quad9 already refuses malicious domains at the resolver, but that
//! is opt-in and Windows-only; SmartScreen is off; and until now the browser's
//! own answer was a matching engine ([`HostSet`], built and tested in 882c3ce)
//! that nothing ever constructed. A user on default settings had strictly less
//! malware protection than stock Edge.
//!
//! # Where the decision happens, and why not in the content filter
//!
//! In the NAVIGATION HANDLER, not the WebKit content filter. The content
//! filter would need one regex rule per host compiled to a DFA on the UI
//! thread, and `compile_and_add_filter` saves the compiled store on every tab
//! creation, every policy change and every unfreeze. Tens of thousands of
//! hosts through that path is a stall the user feels. A sorted arena and a
//! binary search is a few hundred nanoseconds and needs no engine cooperation,
//! so it also works identically on both platforms.
//!
//! Coverage differs by platform and that is worth stating rather than
//! smoothing over:
//!
//!   * **Linux** -- wry's navigation handler is not filtered to the main
//!     frame, so this covers subframe navigations too. It does NOT cover
//!     subresources (scripts, images).
//!   * **Windows** -- navigations, plus whatever the request handler observes.
//!
//! # Independent of ad blocking, deliberately
//!
//! `RuleSet` is gated behind `policy.block_ads` in `decide_request`. Putting
//! malicious hosts in there would mean a user who turned off ad blocking also
//! silently turned off malware blocking, having been told nothing of the kind.
//! This is a separate set with a separate check.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::platform::HostSet;

/// The bundled floor.
///
/// Compiled in so protection never depends on the network having worked, and
/// checked in as a plain file so it is reviewable in a diff rather than
/// arriving as an opaque blob.
///
/// It is deliberately SMALL. A build-time list is good against long-lived
/// malware and command-and-control infrastructure and nearly worthless against
/// this week's credential harvester, because phishing domains often live
/// hours. The bundled set is the floor before the first signed refresh, not
/// the protection itself.
/// COMPILED HASHES, not the text. build.rs turns `blocklist.txt` into sorted
/// 128-bit hashes; the plaintext stays in the repository so additions remain
/// reviewable in a diff, and only the artifact is hashed. See build.rs for why
/// (ClamAV quarantined every Windows build over five bank names in the list).
const BUNDLED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist.bin"));

/// Override for probes: point at a file, or at an empty one to prove the LIST
/// is what blocked something rather than a blanket deny.
///
/// That control is the most important assertion available to the blocking
/// probe. The ad-blocking work already shipped a defect of exactly this shape
/// -- a rule that matched nothing while the UI reported protection -- and the
/// only thing that would have caught it is running the same binary with an
/// empty list and requiring the host to be reached.
const PATH_ENV: &str = "PATANYX_BLOCKLIST_PATH";

/// The set in force. Swappable, because a refreshed list must take effect
/// without a restart -- unlike the DNS setting, which the engine only accepts
/// at startup. An `Arc` so a reader can clone out and drop the lock rather
/// than hold it across a match.
static ACTIVE: RwLock<Option<Arc<HostSet>>> = RwLock::new(None);

/// The refreshed list on disk. Hashes, like the bundled copy: a plaintext file
/// of ~400k phishing domains sitting in the user's profile is the same
/// signature-scanner target as the plaintext inside the binary was, and an
/// on-access scanner quarantining it would silently revert them to the bundled
/// floor with nothing on screen to explain why.
const LIST_FILE: &str = "list.bin";

/// The compiled-in floor, or an empty set if the artifact is malformed.
///
/// build.rs asserts the count at build time, so a malformed artifact here means
/// the binary was tampered with after linking; an empty set is the honest
/// answer and every indicator will report zero.
fn bundled_set() -> HostSet {
    HostSet::from_hashes(BUNDLED).unwrap_or_default()
}

/// Where a refreshed list is kept between runs.
fn store_dir() -> PathBuf {
    crate::updater::data_dir()
        .parent()
        .map_or_else(|| PathBuf::from("."), |p| p.to_path_buf())
        .join("blocklist")
}

/// The set, loading it on first use.
///
/// Order: the probe override, then a refreshed list from disk, then the
/// bundled floor. A refreshed list that fails to parse or is empty is IGNORED
/// rather than accepted -- falling to zero hosts would silently disable
/// protection while every indicator still reported a list in force, which is
/// the exact failure this module exists to prevent.
fn set() -> Arc<HostSet> {
    if let Some(existing) = ACTIVE.read().ok().and_then(|g| g.clone()) {
        return existing;
    }
    let loaded = match std::env::var_os(PATH_ENV) {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(text) => HostSet::from_lines(&text),
            // A named-but-unreadable override is an operator mistake during a
            // probe, not a reason to fall back to the bundled list and report
            // a misleading result. Empty is the honest answer and the probe
            // will say so.
            Err(_) => HostSet::from_lines(""),
        },
        None => {
            let refreshed = std::fs::read(store_dir().join(LIST_FILE))
                .ok()
                .and_then(|b| HostSet::from_hashes(&b))
                .filter(|s| !s.is_empty());
            refreshed.unwrap_or_else(bundled_set)
        }
    };
    let shared = Arc::new(loaded);
    if let Ok(mut guard) = ACTIVE.write() {
        guard.get_or_insert_with(|| shared.clone());
        return guard.clone().expect("just inserted");
    }
    shared
}

/// Write the compiled-in hashes verbatim, for publishing. Returns the count.
///
/// Verbatim rather than re-derived: this is the exact byte sequence the
/// running browser matches against, so a published file produced this way
/// cannot disagree with what installs actually use.
pub fn write_bundled(dest: &std::path::Path) -> std::io::Result<usize> {
    std::fs::write(dest, BUNDLED)?;
    Ok(BUNDLED.len() / 16)
}

/// How many hosts are in force. For the privacy panel, so "am I protected"
/// has an answer that is a number rather than a claim.
pub fn len() -> usize {
    set().len()
}

/// The `list_version` of the refreshed list on disk, or 0 for the bundled
/// floor. Rollback protection compares against this.
fn stored_version() -> u64 {
    std::fs::read_to_string(store_dir().join("version"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The rule that matches `host`, if any.
///
/// Returns the RULE rather than a bool because the user is owed the reason: a
/// banner saying "blocked" is an accusation, and one naming `evil.example`
/// when they typed `mail.evil.example` is an explanation.
///
/// Owned rather than borrowed: the set is swappable now, so a `&'static str`
/// would outlive the list it came from. One allocation per BLOCKED navigation
/// is not a cost worth engineering around.
pub fn matched_rule(host: &str) -> Option<String> {
    set().matched_rule(host).map(str::to_owned)
}

// ---------------------------------------------------------------------------
// The signed hourly refresh.
// ---------------------------------------------------------------------------

/// Where the signed blocklist manifest lives. Same host as update manifests --
/// one DNS lookup, one TLS session, one disclosure event rather than two -- and
/// the same URL for every install, so it is CDN-cacheable and singles nobody
/// out.
fn manifest_url() -> String {
    format!("{}/v1/blocklist.json", crate::updater::base_url())
}

/// Fetch, verify, and install a newer list. Runs on a worker thread.
///
/// EVERY FAILURE PATH LEAVES THE PREVIOUS LIST IN FORCE. A refresh that cannot
/// complete is a missed improvement; a refresh that empties the set is a
/// silent protection outage while every indicator still says protected. The
/// second is far worse, so nothing here ever clears `ACTIVE` -- it is only
/// ever replaced by a set that verified.
fn refresh_blocking() -> Result<(u64, usize), String> {
    use patanyx_update::{verify_blocklist_bytes, verify_blocklist_manifest, MAX_BLOCKLIST_BYTES};

    // BLOCKLIST keys, not the release keys. This one line is what stops the
    // automated publisher's key -- which lives on a server and signs every
    // hour -- from being the same secret that authorises binary installs.
    // See `BLOCKLIST_KEYS` in updater.rs for the full reasoning.
    let keys = crate::updater::blocklist_trusted_keys().map_err(|e| format!("keys: {e}"))?;
    let raw = crate::updater::net::get(
        &manifest_url(),
        16 * 1024,
        std::time::Duration::from_secs(20),
    )
    .map_err(|e| format!("manifest fetch: {e:?}"))?;

    // Signature FIRST. Until this returns Ok the bytes are attacker-controlled
    // and nothing is parsed from them.
    let manifest = verify_blocklist_manifest(&raw, &keys).map_err(|e| format!("manifest: {e}"))?;

    // Rollback refusal. An attacker who can serve bytes can replay an OLD
    // validly-signed list -- one from before a domain was added -- and thereby
    // un-block it. Monotonic versions make that a no-op.
    let have = stored_version();
    if manifest.list_version() <= have {
        return Ok((have, set().len()));
    }

    let body = crate::updater::net::get(
        manifest.url(),
        MAX_BLOCKLIST_BYTES,
        std::time::Duration::from_secs(60),
    )
    .map_err(|e| format!("list fetch: {e:?}"))?;

    // Hash and length against the SIGNED manifest. This is what makes the
    // hosting untrusted: whoever serves the file cannot change it.
    verify_blocklist_bytes(&body, &manifest).map_err(|e| format!("list: {e}"))?;

    let count = install_verified_list(&body, manifest.entries(), manifest.list_version(), &store_dir())?;
    Ok((manifest.list_version(), count))
}

/// Everything after the bytes are known authentic: cross-check, persist, swap.
///
/// SPLIT OUT SO IT CAN BE TESTED. The network half needs a signed manifest and
/// an https endpoint; this half is where the decisions live -- whether a list
/// is believable, in what order it reaches disk, and whether a failure can
/// leave a user less protected than before. None of that had a test, on the
/// one code path whose whole job is to not silently stop protecting people.
///
/// Returns the number of hosts now in force.
fn install_verified_list(
    body: &[u8],
    declared_entries: u64,
    list_version: u64,
    dir: &std::path::Path,
) -> Result<usize, String> {
    let parsed = HostSet::from_hashes(body).ok_or_else(|| {
        "list is not a whole number of 128-bit hashes; a truncated blocklist is \
         a partial one and is refused"
            .to_string()
    })?;

    // The declared count, cross-checked. A truncation cannot survive the hash,
    // but a parse that silently drops most lines very much can -- an encoding
    // change, a format change, a stray BOM -- and that failure looks exactly
    // like a working blocklist with less in it. Allow a small shortfall for
    // duplicates the publisher counted and HostSet collapsed; reject a
    // collapse.
    // SATURATING, and the cast is bounded first.
    //
    // `declared_entries` comes from the signed manifest, so reaching this with
    // an absurd value means the publisher key was used to sign one -- but
    // `overflow-checks` is off in release, so `declared * 9` on a value near
    // u64::MAX wrapped silently to something small and the shortfall test then
    // passed whatever it was given. The check that exists to refuse a
    // collapsed list would have been the thing that let one through. On a
    // 32-bit target the `as usize` truncated as well.
    let declared = usize::try_from(declared_entries).unwrap_or(usize::MAX);
    if parsed.len().saturating_mul(10) < declared.saturating_mul(9) {
        return Err(format!(
            "list declared {declared} entries and parsed to {}; refusing a set \
             that lost most of its contents",
            parsed.len()
        ));
    }

    // Persist before swapping, so a crash between the two leaves the old list
    // rather than a set nothing can reproduce on next launch.
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    let tmp = dir.join("list.bin.new");
    std::fs::write(&tmp, body).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(&tmp, dir.join(LIST_FILE)).map_err(|e| format!("rename: {e}"))?;
    std::fs::write(dir.join("version"), list_version.to_string())
        .map_err(|e| format!("version: {e}"))?;

    let count = parsed.len();
    if let Ok(mut guard) = ACTIVE.write() {
        *guard = Some(Arc::new(parsed));
    }
    Ok(count)
}

/// Kick off a refresh on a worker thread. Called from the hourly schedule.
///
/// Off the UI thread for the same reason the update check is: this is two
/// network round trips, one of them potentially megabytes, and IPC dispatch
/// runs on the event loop.
pub fn refresh_in_background(proxy: &tao::event_loop::EventLoopProxy<crate::UserEvent>) {
    let proxy = proxy.clone();
    let _ = std::thread::Builder::new()
        .name("blocklist-refresh".into())
        .spawn(move || {
            let outcome = refresh_blocking();
            let _ = proxy.send_event(crate::UserEvent::BlocklistRefreshed(match outcome {
                Ok((version, hosts)) => Ok((version, hosts)),
                Err(why) => Err(why),
            }));
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_list_parses_and_is_not_secretly_empty() {
        // `from_lines` silently drops entries it cannot accept (non-ASCII,
        // bare TLDs, malformed). A file full of rejected lines would leave a
        // set of zero while every count and label claimed a blocklist exists,
        // which is the failure this whole module is meant to end.
        let s = bundled_set();
        // A REAL floor, not a placeholder. This bound was `>= 3` while the file
        // held three .invalid test names; leaving it there after the list was
        // populated would have let a gutted or mis-parsed file pass as healthy,
        // which is the precise failure this assertion exists to catch.
        assert!(
            s.len() > 300_000,
            "the bundled list parsed to {} entries, far below the shipped \
             list -- either the file was truncated or most lines were rejected",
            s.len()
        );
        // A host actually in the file must match, and its subdomains with it.
        // Counting entries proves parsing; this proves LOOKUP.
        assert!(
            s.matched_rule("fruitfulshortlinux.opreaopoi.repl.co").is_some(),
            "a host present in the bundled file did not match"
        );
        assert!(s.matched_rule("login.fruitfulshortlinux.opreaopoi.repl.co").is_some());
        assert!(s.matched_rule("example.invalid").is_none());
    }

    #[test]
    fn matching_respects_dot_boundaries() {
        let s = HostSet::from_lines("evil.example\n");
        assert!(s.matched_rule("evil.example").is_some());
        assert!(
            s.matched_rule("login.evil.example").is_some(),
            "subdomains of a listed host are listed"
        );
        assert!(
            s.matched_rule("notevil.example").is_none(),
            "a suffix that does not fall on a label boundary is a DIFFERENT \
             domain, and blocking it would be blocking an innocent site"
        );
        assert!(s.matched_rule("evil.example.org").is_none());
    }

    #[test]
    fn an_empty_list_blocks_nothing() {
        // The probe's most important control depends on this being true.
        let s = HostSet::from_lines("");
        assert_eq!(s.len(), 0);
        assert!(s.matched_rule("anything.example").is_none());
    }

    // -----------------------------------------------------------------------
    // install_verified_list -- the half that decides whether a refresh is
    // believable, and what reaches disk in what order.
    //
    // These run against a temp directory and do NOT touch ACTIVE's contents
    // beyond what the production path would, because the assertions that
    // matter here are about the refusal and about the files.
    // -----------------------------------------------------------------------

    /// Tests describe hosts as text; the install path takes compiled hashes.
    /// This is the same transform build.rs applies, so a test that passes here
    /// exercises the bytes production actually ships.
    fn compiled(hosts: &str) -> Vec<u8> {
        HostSet::from_lines(hosts).to_hashes()
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("patanyx-bl-test-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_list_that_lost_most_of_its_contents_is_refused() {
        // The failure this check exists for: an encoding or format change that
        // parses to almost nothing. It looks exactly like a working blocklist
        // with less in it, and the hash cannot catch it because the publisher
        // signed the broken bytes.
        let dir = tmpdir("collapse");
        let text = "evil.example\nalso-evil.example\n";
        let err = install_verified_list(&compiled(text), 1000, 2, &dir)
            .expect_err("a list declaring 1000 and parsing to 2 must be refused");
        assert!(err.contains("lost most of its contents"), "{err}");
        // AND nothing was written: a refused list must not leave a partial
        // state that the next launch would load.
        assert!(!dir.join(LIST_FILE).exists());
        assert!(!dir.join("version").exists());
    }

    #[test]
    fn a_small_shortfall_is_accepted() {
        // Publishers count lines; HostSet collapses duplicates. A few percent
        // of drift must not refuse an otherwise good list.
        let dir = tmpdir("shortfall");
        let hosts: Vec<String> = (0..100).map(|i| format!("h{i}.example")).collect();
        let text = hosts.join("\n");
        let count = install_verified_list(&compiled(&text), 105, 3, &dir).expect("5% shortfall is fine");
        assert_eq!(count, 100);
    }

    #[test]
    fn the_list_and_its_version_both_reach_disk() {
        let dir = tmpdir("persist");
        let text = "one.example\ntwo.example\n";
        install_verified_list(&compiled(text), 2, 7, &dir).unwrap();
        assert_eq!(std::fs::read(dir.join(LIST_FILE)).unwrap(), compiled(text));
        assert_eq!(std::fs::read_to_string(dir.join("version")).unwrap(), "7");
        // The staging file must not survive: a leftover .new is what a reader
        // would find if the rename had not happened.
        assert!(!dir.join("list.bin.new").exists());
    }

    #[test]
    fn the_version_on_disk_is_what_rollback_protection_reads_back() {
        // stored_version() is what refuses a replayed older list. If install
        // and read-back disagree on format, every refresh after the first
        // either re-applies or is refused forever.
        let dir = tmpdir("version-roundtrip");
        install_verified_list(&compiled("a.example\n"), 1, 42, &dir).unwrap();
        let read: u64 = std::fs::read_to_string(dir.join("version"))
            .unwrap()
            .trim()
            .parse()
            .expect("version file must parse as the u64 stored_version expects");
        assert_eq!(read, 42);
    }

    #[test]
    fn a_refused_list_leaves_the_previous_one_on_disk() {
        // The property the whole module exists for: a bad refresh is a missed
        // improvement, never a protection outage.
        let dir = tmpdir("keeps-previous");
        install_verified_list(&compiled("good.example\n"), 1, 1, &dir).unwrap();
        let _ = install_verified_list(&compiled("x.example\n"), 100_000, 2, &dir).unwrap_err();
        assert_eq!(
            std::fs::read(dir.join(LIST_FILE)).unwrap(),
            compiled("good.example\n"),
            "the refused list overwrote the working one"
        );
        assert_eq!(std::fs::read_to_string(dir.join("version")).unwrap(), "1");
    }
}
