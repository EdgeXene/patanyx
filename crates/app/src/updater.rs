//! The signed updater: everything around `patanyx-update`.
//!
//! `patanyx-update` is deliberately pure — bytes in, decisions out; no HTTP,
//! no filesystem, no clock. This module is the impure layer: it fetches
//! bytes, holds the compiled-in policy (trusted keys, floor, manifest URL),
//! drives the state machine the UI renders, and stages verified payloads for
//! the installer.
//!
//! The pipeline order is not negotiable:
//!
//! 1. [`verify_manifest`] — Ed25519 signature against keys compiled into
//!    this binary;
//! 2. [`decide`] — newer than running, at or above the floor, built for
//!    this platform;
//! 3. download the payload — capped by the manifest's SIGNED size;
//! 4. [`verify_payload`] — sha256 and length against the signed manifest;
//! 5. hand off to the installer — [`installer::apply`], the seam.
//!
//! Steps 1–2 run on "Check now". Steps 3–5 run only after the user accepts
//! the prompt: nothing downloads unprompted, nothing installs automatically,
//! and nothing installs AT ALL without step 4 returning Ok. A failure at
//! step 1 or 4 is not "an error" — it is a REFUSED update, and the user is
//! told plainly.
//!
//! # The network is a feature
//!
//! Only the GETs need TLS, so fetching lives behind the `updater-net` cargo
//! feature. With the feature off, every IPC command still answers: the status
//! snapshot carries `available: false`, the panel shows the control disabled
//! and says why, and the build carries no TLS code at all (the `net` module
//! compiles to a stub, so the command bodies below need no `#[cfg]`
//! duplication).
//!
//! It is ON by default as of 2026-07-27. This paragraph previously said TLS
//! "pulls `ring`, whose build script fails when cross-compiling to Windows",
//! and that the flag was therefore off. The claim was false: ring's C
//! compiled all along and the real failure was cc-rs unable to find
//! `llvm-lib` (see scripts/build-windows.sh, which records the same
//! correction for `relay-client`). `relay-client` was rescued when that was
//! discovered and this flag was not, so the browser shipped with no update
//! mechanism on the strength of a constraint that had already been
//! disproven. Re-verified by building AND LINKING for
//! x86_64-pc-windows-msvc, since `cargo check` never exercises the linker,
//! which is where the original failure actually was.
//!
//! # What a check reveals
//!
//! One unconditional GET per platform: no cookies, no authorization, no
//! cache validators, no version in the request — the comparison happens
//! locally, in `decide`. The server still sees an IP address and a
//! timestamp; that is the honest minimum, and the panel says so.
//!
//! Since 2026-07-28 there IS a scheduled check, roughly every six hours with
//! wide jitter (`schedule.rs`), in addition to the user's "Check now" button.
//! This paragraph previously said there were none and called an automatic
//! schedule "a deliberate follow-up, not an oversight"; the follow-up has
//! landed, and the reason is that a browser nobody clicks never learns a
//! security fix exists.
//!
//! IT NOTIFIES AND NOTHING ELSE. A scheduled check runs steps 1 and 2 and
//! stops -- no download, no install. The guarantee that nothing installs
//! without an explicit accept is untouched. Jitter is not decoration: an exact
//! interval turns "when this machine is awake" into a fingerprint even with no
//! identifier in the request.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use patanyx_update::{
    decide, verify_manifest, verify_payload, Decision, Manifest, Platform, TrustedKeys,
    UpdateError, Version,
};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Compiled-in policy. These constants ARE the update channel's trust root.
// ---------------------------------------------------------------------------

/// THE PUBLISHER'S REAL VERIFYING KEY. Generated 2026-07-28.
///
/// This is PUBLIC by design and belongs in the repository: it appears in every
/// binary, and publishing it costs nothing. The matching SIGNING key exists in
/// exactly one place, on the signing machine, and must never reach a
/// build machine, this repository, or any synced backup. Anyone holding that
/// half can sign an update every existing install will accept and install.
///
/// It replaced an all-zeros placeholder that `TrustedKeys::new` actively
/// refuses — so until now every authentic manifest failed verification and the
/// user saw a refusal. That was the correct unconfigured state, not a bug, and
/// this is the line that ends it.
///
/// TWO KEYS, AND THE SECOND ONE IS ROTATION INSURANCE. Both were generated
/// 2026-07-28. The first is the WORKING key, used to sign every release. The
/// second is held in reserve, stored separately, and ideally never used until
/// it has to be.
///
/// Why two. With a single key a leak is close to unrecoverable: shipping a
/// replacement means publishing a build that lists the new key, and the only
/// thing that can sign that build is the key you are trying to retire. Every
/// install that misses the intermediate build is stranded on a key you no
/// longer trust, permanently. With the reserve key already compiled into every
/// binary, rotation becomes ONE release: sign the next build with the reserve
/// key, and have that build list only the reserve key. Every existing install
/// accepts it, because it already trusts both.
///
/// THE COST IS REAL AND CONDITIONAL. Verification accepts a signature from
/// EITHER key, so the channel's security is now the weaker of the two. That is
/// only a good trade if the reserve key genuinely lives somewhere else --
/// different machine, different medium, ideally offline. Both keys in one
/// folder is not two keys; it is one key and a false sense of preparedness.
///
/// Verification tries every key every time with no short-circuit and folds the
/// results into one bit (see `verify_manifest`), so a second entry costs
/// nothing in timing and reveals nothing about which key came closest.
///
/// The `compiled_keys_parse` test proves these constants parse on the pinned
/// ed25519-dalek. It says nothing about whether the project owner holds the private
/// halves — only they can know that, and the way to check is
/// `patanyx-sign verify` against a manifest they signed.
const PUBLISHER_KEYS: &[&str] = &[
    // Working key: signs releases.
    "49ecd13929f38f8961e52b284bf55d725c38e990fddf4e7ea949729584cc0a09",
    // Reserve key: exists so a leak of the above is survivable in one release.
    "6c0d4f23c5d5b5fd9c0cb86fddf35cefac44719a710058747cffdfe5235f219b",
];

/// Keys that may sign a BLOCKLIST manifest. Deliberately not `PUBLISHER_KEYS`.
///
/// WHY A SECOND LIST AT ALL. The blocklist is republished constantly -- the
/// feeds behind it update hourly -- while releases are cut rarely. Nobody
/// signs hourly by hand, so this key lives on the server and is used by an
/// automated publisher: handled far more often, and protected far less.
///
/// Giving that job to `PUBLISHER_KEYS` would mean putting the key that signs
/// BINARIES on a networked machine. The asymmetry is the whole point:
///
///   * a stolen blocklist key buys a wrong host list, repaired by publishing
///     a corrected one;
///   * a stolen release key buys arbitrary code on every install.
///
/// Only the second is unrecoverable, so only the second stays offline.
///
/// Domain separation (`SIGNING_DOMAIN` vs `SIGNING_DOMAIN_BLOCKLIST`) already
/// stops a blocklist signature being replayed as an update. This is the other
/// half: stopping one stolen secret from being able to do both jobs.
///
/// TRANSITIONAL SECOND ENTRY, AND IT IS MEANT TO BE REMOVED. Every install
/// already in the field verifies blocklists against `PUBLISHER_KEYS`, because
/// that is what it was built with. Shipping only the new key would strand
/// those installs on whatever list they hold -- not a security failure, but a
/// silent end to their refreshes. So the release working key stays valid for
/// blocklists for one release, then goes.
///
/// Note what that costs while it is here: a release key can still sign a
/// blocklist. That was already true before this change, so nothing is worse in
/// the meantime -- but the improvement is not real until the entry is gone.
const BLOCKLIST_KEYS: &[&str] = &[
    // The automated publisher's key. Lives on the server, used by cron.
    "1e0225c3731b06a55400ee0cb0bac1b25d8afe36971c5e38bcb5f2cef7b5b216",
    // TRANSITIONAL: the release working key, so installs predating
    // BLOCKLIST_KEYS keep refreshing. Delete this line one release after the
    // build carrying it has propagated.
    "49ecd13929f38f8961e52b284bf55d725c38e990fddf4e7ea949729584cc0a09",
];

/// The distribution host, shared with the blocklist channel.
pub(crate) fn base_url() -> &'static str {
    UPDATE_BASE_URL
}

/// The floor: versions below this are refused even when validly signed. This
/// is how a known-bad release is retired permanently. Bump deliberately, in
/// a commit of its own, naming the incident it answers.
const FLOOR: Version = Version::new(0, 0, 0);

/// Where manifests live. One URL per platform, identical for every install
/// of that platform: no version, no token, nothing that singles a user out
/// (see patanyx-update's "What an update check unavoidably reveals"). The
/// per-platform path is load-bearing for that privacy story.
///
/// THE REAL ENDPOINT, set 2026-07-28. It replaced `updates.patanyx.example`,
/// an RFC 2606 reserved name that can never resolve — so every check failed by
/// construction, which was the correct unconfigured state.
///
/// What this host must serve, over TLS:
///
///   `/v1/<platform>.json` — one signed manifest per platform.
///
/// It SHOULD be CDN-fronted. The URL is identical for every install of a
/// platform, so the response is cacheable and most checks never reach the
/// origin at all — fewer machines see the request, which is the privacy
/// argument as much as the cost one.
///
/// NOTHING PER-INSTALL MAY EVER BE ADDED TO THIS URL. No version, no token, no
/// query string, not for analytics and not for debugging. The comparison that
/// answers "is there something newer" happens locally in `decide`, against the
/// same bytes every other install just fetched. A version parameter would
/// convert an anonymous cacheable GET into a per-install report, and it would
/// do so quietly. `manifest_url_is_tls_and_per_platform` asserts the running
/// version never appears here.
///
/// Deliberately the same host the blocklist channel will use: one DNS lookup,
/// one TLS session, one disclosure event rather than two.
///
/// Test fixtures elsewhere in this crate and in patanyx-update keep the
/// `.example` domain ON PURPOSE — it is guaranteed never to resolve, which is
/// what keeps a test from reaching the network if a mock is ever missed.
const UPDATE_BASE_URL: &str = "https://patanyx.edgexene.io";

/// Mirrors patanyx-update's `MAX_ENVELOPE_BYTES` (not exported) so the fetch
/// never buffers more than the verifier would even look at. If the crate cap
/// changes, change this too.
const MAX_MANIFEST_FETCH_BYTES: u64 = 16 * 1024;

/// A manual check is still a disclosure (IP + timestamp), so the button is
/// not a machine gun: a completed check within this window returns the
/// status it already produced. Failures are exempt — retrying a network
/// error is normal; re-polling a finished check is not.
const CHECK_COOLDOWN: Duration = Duration::from_secs(60);

/// Dev-only signing seed for end-to-end tests. Any 32 bytes are a valid
/// Ed25519 secret seed, and these are printed on the tin; the matching
/// verifying key is what `dev_print_keypair` prints. NEVER the production
/// key, never anything the project owner generates.
#[cfg(test)]
const DEV_SIGNING_SEED: [u8; 32] = *b"patanyx-dev-signing-key-00000000";

// The updater panel's script is NOT here. It was, as a second `include_str!`
// of chrome/update.js, under a comment saying it was "injected into the chrome
// webview at first ping — exactly the mechanism chat.js uses". That stopped
// being true when index.html gained `<script src="update.js" defer>`: main.rs
// now serves the file over the custom protocol from its own constant, and this
// copy was dead for long enough that the compiler had been reporting it as
// unused in every build.
//
// The distinction is real and worth keeping straight. chat.js IS evaluated at
// first ping (ipc.rs) precisely because it must NOT be referenced from
// index.html -- a non-chat build would then request a file that does not
// exist. integrity.js and update.js ship in every build, so they are plain
// script tags.

// ---------------------------------------------------------------------------
// Build identity.
// ---------------------------------------------------------------------------

/// The running version, from the package version of THIS binary.
fn current_version() -> Option<Version> {
    env!("CARGO_PKG_VERSION").parse().ok()
}

/// The platform this build is, mapped onto patanyx-update's closed set —
/// `Platform::from_name` exists for exactly this, its docstring says so.
/// `None` means this build can never match a manifest, and the status says
/// so rather than guessing.
fn running_platform() -> Option<Platform> {
    Platform::from_name(&format!(
        "{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
    .ok()
}

pub(crate) fn trusted_keys() -> Result<TrustedKeys, UpdateError> {
    TrustedKeys::from_hex(PUBLISHER_KEYS)
}

/// Keys the BLOCKLIST channel verifies against. See `BLOCKLIST_KEYS`.
///
/// Separate function rather than a parameter on `trusted_keys`, so that
/// choosing the wrong set is a visibly wrong call at the call site rather than
/// a boolean nobody reads. There is exactly one caller, in blocklist.rs, and a
/// test asserts it is this one.
pub(crate) fn blocklist_trusted_keys() -> Result<TrustedKeys, UpdateError> {
    TrustedKeys::from_hex(BLOCKLIST_KEYS)
}

/// Whether this build can fetch at all. Everything else — status, refusal
/// display, the panel — works regardless.
pub fn available() -> bool {
    cfg!(feature = "updater-net")
}

/// One fixed URL per platform PER CHANNEL, and that qualifier is the whole
/// design: `Beta` is a second URL every beta subscriber fetches identically,
/// never a per-install path, so choosing it does not create anything the
/// stable URL did not already have -- see `UpdateChannel`'s own doc.
fn manifest_url(platform: Platform, channel: crate::prefs::UpdateChannel) -> String {
    // Debug builds may point at a local server for end-to-end testing.
    // Release builds ignore the environment entirely: where updates come
    // from is a property of the binary, not of whoever launched it.
    #[cfg(debug_assertions)]
    if let Ok(url) = std::env::var("PATANYX_UPDATE_MANIFEST_URL") {
        if !url.is_empty() {
            return url;
        }
    }
    match channel {
        crate::prefs::UpdateChannel::Stable => {
            format!("{UPDATE_BASE_URL}/v1/{}.json", platform.as_str())
        }
        crate::prefs::UpdateChannel::Beta => {
            format!("{UPDATE_BASE_URL}/v1/{}-beta.json", platform.as_str())
        }
    }
}

// ---------------------------------------------------------------------------
// State machine. The UI renders this verbatim via status_json; refusal
// REASONS come from patanyx-update itself, written for users.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Phase {
    Idle,
    Checking,
    UpToDate,
    /// Authentic, newer, at/above floor, for this platform. The prompt is
    /// showing; nothing has been downloaded yet.
    Offered { manifest: Manifest },
    /// A refusal is a security event, not an error. `offered` is `None`
    /// when the bytes were not authentic: an unverifiable manifest tells us
    /// NOTHING trustworthy, not even the version it claims, so the UI is
    /// not handed one.
    Refused {
        reason: String,
        offered: Option<Version>,
    },
    /// An ordinary operational failure (server unreachable, disk full).
    /// Retryable, shown without alarm. `resume` carries the offered
    /// manifest when the failure was mid-download, so "try again" does not
    /// need a fresh check.
    Failed {
        detail: String,
        resume: Option<Box<Manifest>>,
    },
    Downloading { manifest: Manifest },
    /// `verify_payload` returned Ok and the bytes are on disk. THIS is
    /// where verification ends. Installation (`installer::apply`) begins
    /// after it — and is not wired in this draft, which the status says
    /// plainly (`wired: false`).
    Ready { manifest: Manifest, staged: PathBuf },
}

struct Updater {
    phase: Phase,
    last_check_started: Option<Instant>,
}

static UPDATER: Mutex<Updater> = Mutex::new(Updater {
    phase: Phase::Idle,
    last_check_started: None,
});

fn lock() -> MutexGuard<'static, Updater> {
    // A poisoned mutex here means a worker panicked; that must not take
    // update status down with it (degrade, never crash).
    UPDATER.lock().unwrap_or_else(|e| e.into_inner())
}

fn in_cooldown(last_check_started: Option<Instant>, phase: &Phase) -> bool {
    match last_check_started {
        Some(started) => {
            started.elapsed() < CHECK_COOLDOWN && !matches!(phase, Phase::Failed { .. })
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// IPC surface. All three commands return the SAME status snapshot, so the
// UI has one render path. Domain outcomes — including a REFUSED update —
// travel INSIDE the snapshot, not as IPC error codes: a refusal is a result
// the user must see, not a command failure. No new error codes, so
// ERROR_TEXT in chrome.js needs no additions.
// ---------------------------------------------------------------------------

pub fn status() -> Value {
    status_json(&lock())
}

pub fn check_now() -> Value {
    {
        let u = lock();
        if !available() {
            // The snapshot says available:false; the panel explains.
            return status_json(&u);
        }
        if matches!(u.phase, Phase::Checking | Phase::Downloading { .. })
            || in_cooldown(u.last_check_started, &u.phase)
        {
            return status_json(&u);
        }
    }
    let current = match current_version() {
        Some(current) => current,
        None => {
            let mut u = lock();
            u.phase = Phase::Failed {
                detail: format!(
                    "this build reports version {:?}, which is not a semantic version, so it \
                     cannot be checked against an update",
                    env!("CARGO_PKG_VERSION")
                ),
                resume: None,
            };
            return status_json(&u);
        }
    };
    let Some(platform) = running_platform() else {
        let mut u = lock();
        u.phase = Phase::Failed {
            detail: format!(
                "this build's platform ({}-{}) has no update channel",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
            resume: None,
        };
        return status_json(&u);
    };
    let keys = match trusted_keys() {
        Ok(keys) => keys,
        Err(_) => {
            let mut u = lock();
            u.phase = Phase::Failed {
                detail: "this build's update keys are misconfigured, so update checking is \
                         disabled"
                    .to_string(),
                resume: None,
            };
            return status_json(&u);
        }
    };
    {
        let mut u = lock();
        u.phase = Phase::Checking;
        u.last_check_started = Some(Instant::now());
    }
    // Fetch+verify runs off the event-loop thread: a slow server must never
    // freeze the browser mid-session. The UI polls update_status.
    let spawned = std::thread::Builder::new()
        .name("patanyx-update-check".to_string())
        .spawn(move || {
            let url = manifest_url(platform, crate::prefs::load().update_channel);
            let phase = run_check_with(&keys, &FLOOR, current, platform, || {
                net::get(&url, MAX_MANIFEST_FETCH_BYTES, net::MANIFEST_TIMEOUT)
            });
            // Background download, the Firefox shape MINUS the silent apply:
            // when a verified offer lands and the pref allows it, fetch and
            // stage NOW so the user's consent click is an instant restart
            // rather than a wait. What does NOT change: nothing installs
            // without `update_apply`, which the panel only fires on an
            // explicit user action. Skipped in Flatpak (installing is not
            // ours there; downloading what cannot install is waste) and
            // skipped when the user turned it off.
            let manifest = match &phase {
                Phase::Offered { manifest }
                    if crate::prefs::load().update_background_download && !in_flatpak() =>
                {
                    Some(manifest.clone())
                }
                _ => None,
            };
            lock().phase = phase;
            if let Some(manifest) = manifest {
                {
                    let mut u = lock();
                    // Re-check under the lock: a user click may have raced
                    // this thread into Downloading already.
                    if !matches!(u.phase, Phase::Offered { .. }) {
                        return;
                    }
                    u.phase = Phase::Downloading {
                        manifest: manifest.clone(),
                    };
                }
                lock().phase = download_and_stage(&manifest);
            }
        });
    if let Err(e) = spawned {
        let mut u = lock();
        u.phase = Phase::Failed {
            detail: format!("could not start the update check ({e})"),
            resume: None,
        };
        return status_json(&u);
    }
    status()
}

/// True when this process is running inside a Flatpak sandbox.
///
/// `/app` is mounted READ-ONLY there, and application delivery belongs to the
/// Flatpak repository rather than to us. A self-replacing updater in that
/// environment cannot succeed: at best it fails partway through with a
/// confusing permissions error, at worst it leaves a half-written binary
/// beside a read-only one.
///
/// `FLATPAK_ID` is set by flatpak-run in the sandbox; the `/.flatpak-info`
/// file is the belt-and-braces check for an environment where it was cleared.
pub fn in_flatpak() -> bool {
    std::env::var_os("FLATPAK_ID").is_some() || std::path::Path::new("/.flatpak-info").exists()
}

/// Apply the staged update and relaunch. Only valid from `Phase::Ready`.
///
/// Separate from `install` on purpose. `install` downloads and verifies;
/// this REPLACES THE RUNNING BINARY, which is the one irreversible step in
/// the whole pipeline, so it is its own command and its own explicit click.
/// Install the staged update and QUIT, so the relaunched process is the only
/// one left.
///
/// The quit is the point. `swap_and_relaunch` renames the running executable
/// aside, writes the new one, and spawns it -- and nothing used to end this
/// process, so the user got a SECOND browser while the first kept running.
/// Pressing the button again produced a third. `clean_previous()` has always
/// existed to delete the `.old` file "when the lock from the previous process
/// is gone", so the design assumed this exit; it was simply never wired.
///
/// Exiting through the event loop rather than `process::exit` so webviews and
/// the vault shut down the way they do on any other close.
pub fn apply_staged(proxy: &tao::event_loop::EventLoopProxy<crate::UserEvent>) -> Result<Value, &'static str> {
    let (manifest, staged) = {
        let u = lock();
        match &u.phase {
            Phase::Ready { manifest, staged } => (manifest.clone(), staged.clone()),
            // Any other phase means nothing verified is waiting. Refuse rather
            // than reaching for whatever happens to be on disk.
            _ => return Err("not_ready"),
        }
    };
    // The staged file is left in place on failure: a failed swap must not
    // also destroy the verified download the user already waited for.
    installer::apply(&staged, &manifest).map_err(|_| "install_failed")?;
    // ONLY after apply returned Ok. A failed swap must leave a working
    // browser running, not close the one the user still has.
    let _ = proxy.send_event(crate::UserEvent::QuitForUpdate);
    Ok(json!({ "relaunching": true }))
}

pub fn install() -> Result<Value, &'static str> {
    if !available() {
        return Ok(status());
    }
    // Checking for a NEW version is still useful inside a Flatpak: the panel
    // can say one exists and show the notes. Installing it is not ours to do.
    if in_flatpak() {
        return Err("managed_by_flatpak");
    }
    let manifest = {
        let u = lock();
        match &u.phase {
            Phase::Offered { manifest } => manifest.clone(),
            Phase::Failed {
                resume: Some(manifest),
                ..
            } => (**manifest).clone(),
            // Already in flight or already staged: a re-click is harmless,
            // answer with the current snapshot.
            Phase::Downloading { .. } | Phase::Ready { .. } => return Ok(status_json(&u)),
            // Nothing was offered; the request is nonsense. (The panel only
            // shows the button from Offered/Failed-resume states.)
            _ => return Err("bad_args"),
        }
    };
    {
        let mut u = lock();
        u.phase = Phase::Downloading {
            manifest: manifest.clone(),
        };
    }
    let worker = manifest.clone();
    let spawned = std::thread::Builder::new()
        .name("patanyx-update-download".to_string())
        .spawn(move || {
            lock().phase = download_and_stage(&worker);
        });
    if let Err(e) = spawned {
        let mut u = lock();
        u.phase = Phase::Failed {
            detail: format!("could not start the download ({e})"),
            resume: Some(Box::new(manifest)),
        };
        return Ok(status_json(&u));
    }
    Ok(status())
}

/// The one real download body, shared by the user's install click and the
/// background chain, so the two paths cannot drift: same fetch, same delta
/// attempt, same verification, same staging.
fn download_and_stage(manifest: &Manifest) -> Phase {
    run_install_with(
        |url, cap| net::get(url, cap, net::PAYLOAD_TIMEOUT),
        || std::env::current_exe().ok().and_then(|p| std::fs::read(p).ok()),
        manifest,
        &data_dir(),
    )
}

/// The one snapshot shape every command returns and update.js renders. The
/// `state` strings are a contract with the JS — the tests pin them.
fn status_json(u: &Updater) -> Value {
    let mut out = json!({
        "available": available(),
        "running": current_version().map(|v| v.to_string()),
        "platform": running_platform().map(|p| p.as_str()),
        "state": "idle",
    });
    match &u.phase {
        Phase::Idle => {}
        Phase::Checking => out["state"] = json!("checking"),
        Phase::UpToDate => out["state"] = json!("uptodate"),
        Phase::Offered { manifest } => {
            out["state"] = json!("offered");
            out["offered"] = json!(manifest.version().to_string());
            out["size"] = json!(manifest.size());
            out["published_at"] = json!(manifest.published_at());
            // Publisher-signed release blurb, shown beside the install
            // decision -- which is why only the SIGNED field is ever the
            // source, never anything fetched separately. Absent stays
            // absent: the panel must not render an empty "What is new".
            if !manifest.notes().is_empty() {
                out["notes"] = json!(manifest.notes());
            }
        }
        Phase::Refused { reason, offered } => {
            out["state"] = json!("refused");
            // Verbatim. These strings were written to be shown.
            out["reason"] = json!(reason);
            if let Some(v) = offered {
                out["offered"] = json!(v.to_string());
            }
        }
        Phase::Failed { detail, resume } => {
            out["state"] = json!("failed");
            out["detail"] = json!(detail);
            out["retry"] = json!(resume.is_some());
            if let Some(m) = resume {
                out["offered"] = json!(m.version().to_string());
            }
        }
        Phase::Downloading { manifest } => {
            out["state"] = json!("downloading");
            out["offered"] = json!(manifest.version().to_string());
            out["size"] = json!(manifest.size());
            if !manifest.notes().is_empty() {
                out["notes"] = json!(manifest.notes());
            }
        }
        Phase::Ready { manifest, staged } => {
            out["state"] = json!("ready");
            out["offered"] = json!(manifest.version().to_string());
            out["staged"] = json!(staged.to_string_lossy());
            if !manifest.notes().is_empty() {
                out["notes"] = json!(manifest.notes());
            }
            // Wired since 2026-07-28. It was false while installer::apply was
            // a todo!(), and the panel correctly refused to promise a restart
            // the build could not perform.
            out["wired"] = json!(true);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The pipeline, with every impure input injected, so tests drive the REAL
// verify → decide → verify → stage path with no network at all. Policy
// (keys, floor, current, platform) is a parameter for the same reason: the
// production callers bind the compiled-in constants; tests bind their own.
// ---------------------------------------------------------------------------

fn run_check_with(
    keys: &TrustedKeys,
    floor: &Version,
    current: Version,
    platform: Platform,
    fetch_manifest: impl FnOnce() -> Result<Vec<u8>, FetchError>,
) -> Phase {
    let bytes = match fetch_manifest() {
        Ok(bytes) => bytes,
        Err(e) => {
            return Phase::Failed {
                detail: fetch_detail(&e),
                resume: None,
            }
        }
    };
    let manifest = match verify_manifest(&bytes, keys) {
        Ok(manifest) => manifest,
        // Not authentic. This is a REFUSAL, not an operational error: do not
        // retry it silently, do not parse the bytes for hints, tell the user.
        Err(e) => {
            return Phase::Refused {
                reason: manifest_refusal_text(&e),
                offered: None,
            }
        }
    };
    match decide(&current, floor, platform, &manifest) {
        Decision::UpToDate => Phase::UpToDate,
        Decision::Update(manifest) => Phase::Offered { manifest },
        Decision::Refused(why) => Phase::Refused {
            // The Display impls on RefusalReason were written for users.
            reason: why.to_string(),
            offered: Some(manifest.version()),
        },
    }
}

/// Download → verify → stage. The ONLY path to `Ready`, and `Ready` is the
/// only state the (future) installer may act on: nothing installs without
/// `verify_payload`'s Ok.
///
/// The delta path changes TRANSPORT only: when the running binary's hash
/// matches a published delta, the small patch is fetched and applied, and
/// the RESULT walks through the very same `verify_payload` a full download
/// does. Any delta problem -- fetch failure, hash mismatch, patch refusal
/// -- falls back to the full download silently (diag'd), because the
/// fallback is exactly as trustworthy and availability should not hinge on
/// an optimization.
fn run_install_with(
    fetch: impl Fn(&str, u64) -> Result<Vec<u8>, FetchError>,
    current_exe: impl FnOnce() -> Option<Vec<u8>>,
    manifest: &Manifest,
    stage_dir: &Path,
) -> Phase {
    let delta_bytes = try_delta(&fetch, current_exe, manifest);
    let bytes = match delta_bytes {
        Some(bytes) => Ok(bytes),
        None => fetch(manifest.url(), manifest.size()),
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        // The manifest's `size` is SIGNED: a body that cannot match it
        // contradicts the publisher's own statement, so this is a refusal,
        // not an operational error.
        Err(FetchError::TooLarge) => {
            return Phase::Refused {
                reason: "the downloaded update is larger than the size in the signed manifest; \
                         it was not installed"
                    .to_string(),
                offered: Some(manifest.version()),
            }
        }
        Err(e) => {
            return Phase::Failed {
                detail: fetch_detail(&e),
                resume: Some(Box::new(manifest.clone())),
            }
        }
    };
    if let Err(e) = verify_payload(&bytes, manifest) {
        return Phase::Refused {
            reason: payload_refusal_text(&e),
            offered: Some(manifest.version()),
        };
    }
    // ─────────────────── Verification ends here. ───────────────────
    // The bytes are authentic and complete. Everything after this line —
    // staging, then installer::apply — acts on VERIFIED bytes only.
    match stage_to(stage_dir, &bytes, manifest) {
        // Staging STOPS here, and the swap is a separate call. That is not a
        // second button -- the panel invokes `update_apply` the moment it sees
        // `ready`, so the user clicks once -- it is a separate FUNCTION,
        // because replacing the running binary is the one irreversible step in
        // this pipeline and it must be callable, gated and testable on its own.
        //
        // Chaining it in here briefly seemed simpler and broke
        // `verified_payload_is_staged_and_ready` immediately: the test could no
        // longer check that bytes were staged without the process attempting to
        // overwrite and re-exec itself. A test that cannot observe an
        // intermediate state is a design telling you the states were welded
        // together.
        Ok(staged) => Phase::Ready {
            manifest: manifest.clone(),
            staged,
        },
        Err(e) => Phase::Failed {
            detail: format!("the update verified but could not be written to disk ({e})"),
            resume: Some(Box::new(manifest.clone())),
        },
    }
}

/// stderr, honestly. The Windows diag ring is private to its backend and
/// unix has none; a delta fallback is worth a line somewhere, and worth
/// zero machinery. If the updater ever earns real diagnostics, route this
/// through them.
fn diag(message: &str) {
    eprintln!("updater: {message}");
}

/// The delta fast path: Some(candidate full bytes) or None for "use the
/// full download". Every early return here is a FALLBACK, not a failure --
/// the caller's `verify_payload` remains the only judge of what stages.
///
/// The one security-relevant check that is NOT optional: the fetched patch
/// must hash to the manifest's signed `sha256` FOR THAT DELTA before it is
/// applied. Applying an unverified patch would hand attacker bytes to the
/// bsdiff decoder; the decoder is safe Rust, but "parse attacker input for
/// no reason" is a habit this codebase refuses.
fn try_delta(
    fetch: &impl Fn(&str, u64) -> Result<Vec<u8>, FetchError>,
    current_exe: impl FnOnce() -> Option<Vec<u8>>,
    manifest: &Manifest,
) -> Option<Vec<u8>> {
    if manifest.deltas().is_empty() {
        return None;
    }
    let old = current_exe()?;
    let from = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&old);
        let out: [u8; 32] = hasher.finalize().into();
        out
    };
    let delta = manifest.delta_from(&from)?;
    let patch = match fetch(delta.url(), delta.size()) {
        Ok(patch) => patch,
        Err(e) => {
            diag(&format!("update delta: fetch failed ({e:?}); using the full download"));
            return None;
        }
    };
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&patch);
        let got: [u8; 32] = hasher.finalize().into();
        if &got != delta.sha256() {
            diag("update delta: patch hash mismatch; using the full download");
            return None;
        }
    }
    match patanyx_update::apply_delta(&old, &patch, manifest.size()) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            diag(&format!("update delta: apply refused ({e:?}); using the full download"));
            None
        }
    }
}

/// User-facing text for a manifest that failed verification. Deliberately
/// NOT UpdateError's Debug output: these sentences are written for the
/// person reading them. To a user, "bad signature" and "malformed" are the
/// same news — these bytes are not the publisher's — and patanyx-update
/// already collapses the cryptographic distinction.
fn manifest_refusal_text(error: &UpdateError) -> String {
    match error {
        UpdateError::BadSignature => "the update server's response was not signed by the PATANYX \
                                      release key; it may have been tampered with, and it was \
                                      not used"
            .to_string(),
        UpdateError::Malformed(_) => {
            "the update server sent something that is not a valid update manifest; it was not \
             used"
                .to_string()
        }
        // Note: covers any UpdateError variant I could not see
        // (error.rs was not in my context); the named arms above cover
        // every variant the rest of the crate constructs.
        _ => "the update manifest failed verification; it was not used".to_string(),
    }
}

fn payload_refusal_text(error: &UpdateError) -> String {
    match error {
        UpdateError::PayloadHash => "the downloaded update does not match the signed manifest; \
                                      it may have been tampered with, and it was not installed"
            .to_string(),
        UpdateError::PayloadLength { .. } => {
            "the downloaded update is the wrong size for the signed manifest; it was not \
             installed"
                .to_string()
        }
        _ => "the downloaded update failed verification; it was not installed".to_string(),
    }
}

fn fetch_detail(error: &FetchError) -> String {
    match error {
        FetchError::Network(detail) => format!("could not reach the update server ({detail})"),
        FetchError::Http(status) => format!("the update server answered with HTTP {status}"),
        FetchError::TooLarge => {
            "the update server sent more data than a valid answer can contain".to_string()
        }
    }
}

/// Read at most `cap` bytes. The cap is enforced by `Take`, so memory stays
/// bounded even if the server lies about Content-Length or sends none — no
/// unbounded body is ever buffered.
// In an updater-net build this is what net::get uses; in a feature-off
// build only the tests exercise it.
#[cfg_attr(not(feature = "updater-net"), allow(dead_code))]
pub(crate) fn read_capped(reader: impl Read, cap: u64) -> Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    reader
        .take(cap.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|e| FetchError::Network(e.to_string()))?;
    if body.len() as u64 > cap {
        return Err(FetchError::TooLarge);
    }
    Ok(body)
}

/// Write VERIFIED bytes to the staging directory. The filename carries
/// version and platform so a stale staged file from an older offer can
/// never be confused for this one.
fn stage_to(dir: &Path, bytes: &[u8], manifest: &Manifest) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!(
        "patanyx-{}-{}.bin",
        manifest.version(),
        manifest.platform().as_str()
    ));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// Where verified payloads are staged, as data rather than control flow, so
/// the precedence can be tested on a machine that is not the platform it
/// describes.
///
/// PRECEDENCE, corrected: `PATANYX_DATA_DIR`, then `XDG_DATA_HOME` and `HOME`
/// on unix, then `%APPDATA%` on Windows, then temp. The old text listed only
/// three of those and omitted the `%APPDATA%` arm entirely -- which was the
/// arm that stopped Windows falling through to temp and silently losing the
/// refreshed blocklist on every cleanup.
///
/// It also carried a Note saying "state.rs owns the real data-dir logic;
/// reuse that instead of this mirror". state.rs owns no such logic and never
/// did: this function and its `data_dir()` caller are the only implementation.
/// The staged file is re-verified at handoff time (see `installer::apply`'s
/// contract), so a shared temp directory here remains a hygiene issue rather
/// than a forge-an-update one -- and the temp path is now namespaced so the
/// blocklist derived from it does not land loose in a shared directory.
///
/// `temp` is the caller's fallback. It is a parameter and not a call so a test
/// can tell "we chose temp" apart from "we chose a real directory".
fn data_dir_from(
    explicit: Option<&str>,
    xdg: Option<&str>,
    home: Option<&str>,
    appdata: Option<&str>,
    temp: &Path,
) -> PathBuf {
    fn set(v: Option<&str>) -> Option<&str> {
        v.filter(|d| !d.is_empty())
    }
    if let Some(dir) = set(explicit) {
        return PathBuf::from(dir).join("updates");
    }
    if let Some(dir) = set(xdg) {
        return PathBuf::from(dir).join("patanyx").join("updates");
    }
    if let Some(dir) = set(home) {
        return PathBuf::from(dir)
            .join(".local")
            .join("share")
            .join("patanyx")
            .join("updates");
    }
    if let Some(dir) = set(appdata) {
        return PathBuf::from(dir).join("patanyx").join("updates");
    }
    // Two levels, matching `data_dir()`: the blocklist store is derived from
    // this path's PARENT, so a single-level name put it directly in temp.
    temp.join("patanyx").join("updates")
}

pub(crate) fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PATANYX_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("updates");
        }
    }
    #[cfg(unix)]
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("patanyx").join("updates");
        }
    }
    #[cfg(unix)]
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("patanyx")
                .join("updates");
        }
    }
    // WINDOWS HAD NO ARM HERE AT ALL, and fell through to temp. This directory
    // is the parent of `blocklist::store_dir()`, so the refreshed
    // malicious-host list -- the thing that makes phishing protection current
    // rather than a build-time snapshot -- was being written somewhere Windows
    // deletes. Every cleanup silently reverted users to the bundled floor while
    // the panel still reported a host count, which is the exact shape of
    // failure the blocklist module was written to avoid.
    //
    // %APPDATA% matches `Vault::default_path()`, so all of a user's state now
    // lives under one root instead of two.
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        if !appdata.is_empty() {
            return PathBuf::from(appdata).join("patanyx").join("updates");
        }
    }
    // Last resort only. A staged update in temp is survivable -- it is
    // re-downloadable and verified before use; a blocklist in temp is a silent
    // protection outage, which is why it is no longer the Windows default.
    //
    // NAMESPACED UNDER `patanyx/`, and the extra level is the point.
    // `blocklist::store_dir()` is this path's PARENT plus "blocklist", so
    // while this was `<temp>/patanyx-updates` the blocklist resolved to
    // `<temp>/blocklist` -- straight into a directory every user on the
    // machine can write, under a name owned by nobody. Both artifacts now sit
    // inside one directory this application owns.
    std::env::temp_dir().join("patanyx").join("updates")
}

/// Fetch failures. Which variants can be CONSTRUCTED depends on the
/// `updater-net` feature (the stub fetch only ever says Network), hence the
/// allow: a variant unused in this build is load-bearing in the other.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum FetchError {
    /// Unreachable, timeout, TLS failure, truncated stream: retryable.
    Network(String),
    /// Non-2xx answer (including an unfollowed redirect): retryable.
    Http(u16),
    /// The body exceeded the caller's cap.
    TooLarge,
}

// ---------------------------------------------------------------------------
// The fetch. Real with `updater-net`, a stub without — so the command
// bodies above compile identically in both builds and the default build
// carries no TLS code at all.
// ---------------------------------------------------------------------------

/// Note — HTTP client choice: ureq 2.x, `default-features = false`,
/// `features = ["rustls"]`.
///
///   * blocking: this codebase has no async runtime, and the updater
///     already runs on its own thread;
///   * rustls + webpki-roots: real certificate validation, the same TLS
///     stack patanyx-chat's `relay-client` uses — confirm ureq's rustls is
///     0.23 so both features build ONE rustls when both are on;
///   * `ring` enters the tree ONLY with `updater-net`, which is the whole
///     reason the feature exists (ring's build script fails cross-compiling
///     to Windows — see patanyx-chat's Cargo.toml);
///   * no cookies feature, no gzip feature: smaller tree, and the check
///     stays the plain unconditional GET the privacy docs require.
///
/// Rejected: reqwest-blocking (far larger tree); hand-rolled HTTP over raw
/// rustls, like the relay client (more code to review for nothing the
/// update fetch needs). ureq 3.x exists with a changed API; if the reviewer
/// prefers it, the blast radius is this module only. Builder method names
/// below are written against the 2.x API and are the one thing I could not
/// compile-check — if the pinned version spells them differently
/// (`max_redirects`, per-request `timeout`), fix them HERE.
#[cfg(feature = "updater-net")]
pub(crate) mod net {
    use super::{read_capped, FetchError};
    use std::time::Duration;

    /// A manifest is 16 KiB over one GET; half a minute is generous.
    pub const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);
    /// Payloads can be tens of MB on slow links; the cap bounds memory, this
    /// bounds time. A stalled server then fails the download instead of
    /// parking the worker thread forever.
    pub const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(600);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn get(url: &str, cap: u64, timeout: Duration) -> Result<Vec<u8>, FetchError> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout(timeout)
            // Redirects are NOT followed: a redirect target is outside the
            // signed manifest's guarantees and could silently drop TLS. If
            // the CDN needs redirects, add an https-only redirect policy
            // here as its own reviewed change.
            .redirects(0)
            // A user agent is data about the user; carry the minimum.
            .user_agent("patanyx");
        // ureq never consults the engine's proxy, so before this line the
        // updater LEFT OUTSIDE an imported tunnel -- flagged when the tunnel
        // was designed, closed when downloads became automatic (a hole that
        // needed a click is a hole; one that fires on a schedule is a
        // policy violation). engine_proxy_port() is the engine's own rule:
        // Some(port) whenever the user chose or is running a tunnel -- the
        // dead port when the tunnel is down, so this FAILS CLOSED exactly
        // like a page load -- and None only when direct is sanctioned.
        if let Some(port) = crate::tunnel_control::engine_proxy_port() {
            match ureq::Proxy::new(format!("socks5://127.0.0.1:{port}")) {
                Ok(proxy) => builder = builder.proxy(proxy),
                // Refusing to fetch is the only safe answer to "could not
                // express the proxy": going direct here is the one
                // unacceptable outcome.
                Err(e) => return Err(FetchError::Network(format!(
                    "tunnel proxy could not be configured ({e}); refusing a direct connection"
                ))),
            }
        }
        let agent = builder.build();
        let response = agent.get(url).call().map_err(|e| match e {
            ureq::Error::Status(code, _) => FetchError::Http(code),
            ureq::Error::Transport(t) => FetchError::Network(t.to_string()),
        })?;
        // Fail fast when the server announces more than the cap; the capped
        // read below stays the enforcement of record.
        if let Some(len) = response
            .header("content-length")
            .and_then(|h| h.parse::<u64>().ok())
        {
            if len > cap {
                return Err(FetchError::TooLarge);
            }
        }
        read_capped(response.into_reader(), cap)
    }
}

#[cfg(not(feature = "updater-net"))]
pub(crate) mod net {
    //! No TLS stack in this build. The commands still run; the fetch simply
    //! cannot, and says so. (`check_now`/`install` short-circuit on
    //! `available()` before ever calling this, so it is unreachable in
    //! practice — it exists so both builds compile one code path.)
    use super::FetchError;
    use std::time::Duration;

    pub const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);
    pub const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(600);

    pub fn get(_url: &str, _cap: u64, _timeout: Duration) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::Network(
            "this build was compiled without update networking".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// ═══════════════════════ VERIFICATION HAS ENDED ═══════════════════════════
// Everything in this module is INSTALLATION. It may only ever run on bytes
// that passed verify_payload and were staged to disk. Nothing outside this
// module swaps binaries.
// ---------------------------------------------------------------------------
pub mod installer {
    use std::path::Path;

    use patanyx_update::Manifest;

    /// Apply a staged, VERIFIED update: replace the running binary with the
    /// staged payload and relaunch.
    ///
    /// WAS A `todo!()` UNTIL 2026-07-28. The whole chain worked -- fetch,
    /// signature, decide, download, verify_payload -- and then handed the user
    /// a file path in their temp directory, which is half a feature. The
    /// that was the decision.
    ///
    /// # The hash is checked AGAIN here, and that is not paranoia
    ///
    /// `verify_payload` ran at download time. The file then SAT ON DISK in a
    /// world-writable temp directory while the user read a panel and decided.
    /// Anything with write access could have replaced it in between, and the
    /// path proves nothing about the contents. So the bytes are re-read and
    /// re-hashed against the signed manifest immediately before they are moved
    /// into place. Trust the hash, never the path.
    pub fn apply(staged: &Path, manifest: &Manifest) -> std::io::Result<()> {
        let bytes = std::fs::read(staged)?;
        patanyx_update::verify_payload(&bytes, manifest).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("staged update no longer matches the signed manifest: {e}"),
            )
        })?;

        let current = std::env::current_exe()?;
        swap_and_relaunch(&current, &bytes)
    }

    /// Unix: write a sibling, then rename over the running binary.
    ///
    /// A same-filesystem rename is atomic, and unix permits replacing the file
    /// of a running process -- the kernel keeps the old inode alive for the
    /// existing process. The sibling matters: renaming across filesystems is
    /// not atomic and would leave a half-written browser.
    #[cfg(unix)]
    fn swap_and_relaunch(current: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let staging = current.with_extension("new");
        std::fs::write(&staging, bytes)?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&staging, current)?;
        relaunch(current)
    }

    /// Windows: move the running binary aside, then put the new one in its
    /// place.
    ///
    /// A running executable cannot be deleted or overwritten on Windows, but
    /// it CAN be renamed -- the file is locked by path, not by name. So:
    /// rename ourselves to `.old`, write the new bytes at the real path, and
    /// relaunch. The `.old` file is removed on the next start, because it is
    /// still locked while this process lives.
    ///
    /// If the second step fails the rename is undone, so a failed update
    /// leaves a working browser rather than no browser at all. That ordering
    /// is the whole reason this is not three lines.
    #[cfg(windows)]
    fn swap_and_relaunch(current: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let aside = current.with_extension("old");
        let _ = std::fs::remove_file(&aside);
        std::fs::rename(current, &aside)?;
        if let Err(error) = std::fs::write(current, bytes) {
            // Put the working browser back before reporting failure.
            let _ = std::fs::rename(&aside, current);
            return Err(error);
        }
        relaunch(current)
    }

    /// Start the replacement and let this process exit normally.
    ///
    /// Deliberately does NOT kill the current process: the caller returns to
    /// the event loop, which closes windows and drops the vault in order. A
    /// hard exit here would skip that, and the vault zeroizes its key material
    /// on drop.
    fn relaunch(path: &Path) -> std::io::Result<()> {
        std::process::Command::new(path).spawn()?;
        Ok(())
    }

    /// Remove the `.old` file a previous update left behind. Called at
    /// startup, when the lock from the previous process is gone.
    ///
    /// Failure is ignored on purpose: a leftover file is untidy, and refusing
    /// to start a browser over it would be absurd.
    pub fn clean_previous() {
        if let Ok(current) = std::env::current_exe() {
            let _ = std::fs::remove_file(current.with_extension("old"));
        }
    }
}

#[cfg(test)]
mod tests {
    //! The fetch is a closure parameter everywhere, so these tests drive the
    //! REAL verify → decide → verify → stage pipeline — Ed25519 signatures,
    //! not mocks — with no network. They run in the DEFAULT build (feature
    //! off); `updater-net` only adds the ureq GET itself.
    //!
    //! Signing uses ed25519-dalek and sha2 as DEV-dependencies (add stanza
    //! in the draft notes); both are already in the workspace tree via
    //! patanyx-update, so nothing new is vendored.
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    use patanyx_update::RefusalReason;

    /// Mirrors patanyx-update's `SIGNING_DOMAIN` (module-private there, so
    /// not importable). If the wire format ever changes, every signed test
    /// here fails — which is exactly the tripwire wanted.
    const SIGNING_DOMAIN: &[u8] = b"PATANYX-UPDATE-MANIFEST-V1\n";

    const TEST_BINARY: &[u8] = b"patanyx updater test binary: not a real release";

    fn dev_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&DEV_SIGNING_SEED)
    }

    fn dev_trusted_keys() -> TrustedKeys {
        TrustedKeys::new(vec![dev_signing_key().verifying_key()])
            .expect("one key is a valid set")
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        hex_encode(&sha2::Sha256::digest(bytes))
    }

    /// Same construction as patanyx-update's testutil::payload_json.
    fn payload_json(version: &str, platform: &str, size: u64) -> String {
        // The size argument stays in the signature because callers pass a
        // deliberately WRONG one in the length-mismatch tests; the bytes
        // hashed are always TEST_BINARY.
        payload_json_over(version, platform, TEST_BINARY, "").replace(
            &format!("\"size\":{}", TEST_BINARY.len()),
            &format!("\"size\":{size}"),
        )
    }

    /// A manifest payload over ARBITRARY release bytes. `deltas` is the raw
    /// JSON array text, or "" for a manifest without the field at all (what
    /// every published manifest looks like today, and must keep parsing as).
    fn payload_json_over(
        version: &str,
        platform: &str,
        binary: &[u8],
        deltas: &str,
    ) -> String {
        let deltas = if deltas.is_empty() {
            String::new()
        } else {
            format!("\"deltas\":{deltas},")
        };
        format!(
            "{{\"version\":\"{version}\",\"platform\":\"{platform}\",\
             \"url\":\"https://updates.patanyx.example/releases/test\",\
             \"sha256\":\"{}\",{deltas}\"size\":{},\"published_at\":1735689600}}",
            sha256_hex(binary),
            binary.len()
        )
    }

    /// A realistically-sized pair of "binaries" for the delta tests.
    ///
    /// TEST_BINARY is 47 bytes, and a bsdiff patch carries ~160 bytes of
    /// header -- so a patch of it is necessarily LARGER than the payload,
    /// which the manifest validator correctly refuses. That refusal is the
    /// rule working; the fixture just has to be the size real binaries are.
    fn delta_fixture() -> (Vec<u8>, Vec<u8>) {
        let old: Vec<u8> = (0u32..20_000).flat_map(|i| i.to_le_bytes()).collect();
        let mut new = old.clone();
        new[4_000..4_200].fill(0x5A);
        new.extend_from_slice(b"and a new tail for the newer release");
        (old, new)
    }

    /// A bsdiff patch turning `old` into `new`, plus its hex hash.
    fn patch_between(old: &[u8], new: &[u8]) -> (Vec<u8>, String) {
        let mut raw = Vec::new();
        bsdiff::diff(old, new, &mut raw).expect("in-memory diff");
        // Same compression the publisher applies; apply_delta inflates.
        let patch = patanyx_update::compress_delta(&raw);
        let hash = sha256_hex(&patch);
        (patch, hash)
    }

    /// Same construction as patanyx-update's testutil::sign: Ed25519 over
    /// SIGNING_DOMAIN || payload-bytes, payload embedded as a JSON string.
    fn sign_with(payload: &str, key: &ed25519_dalek::SigningKey) -> String {
        use ed25519_dalek::Signer;
        let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + payload.len());
        message.extend_from_slice(SIGNING_DOMAIN);
        message.extend_from_slice(payload.as_bytes());
        let signature = key.sign(&message);
        format!(
            "{{\"v\":1,\"payload\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(payload).expect("a string always serializes"),
            hex_encode(&signature.to_bytes())
        )
    }

    fn signed_manifest_for(version: Version, platform: Platform) -> String {
        sign_with(
            &payload_json(
                &version.to_string(),
                platform.as_str(),
                TEST_BINARY.len() as u64,
            ),
            &dev_signing_key(),
        )
    }

    fn current_plus(minor_delta: u64) -> Version {
        let current = current_version().expect("test build version must be semver");
        Version::new(current.major, current.minor + minor_delta, 0)
    }

    static STAGE_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn fresh_stage_dir() -> PathBuf {
        let n = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("patanyx-updater-test-{}-{n}", std::process::id()))
    }

    fn dir_is_empty_or_missing(dir: &Path) -> bool {
        std::fs::read_dir(dir)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true)
    }

    // ---- compiled-in policy ----

    #[test]
    fn compiled_keys_parse() {
        // THIRD FORM OF THIS TEST, and the transitions are the point.
        //
        // It first asserted the all-zeros placeholder PARSES, which it did --
        // 32 zero bytes decode to a valid small-order Ed25519 point. That made
        // a build carrying the placeholder look configured while being the one
        // input against which forged signatures verify.
        //
        // 2026-07-27 it was inverted to require the placeholder be REFUSED,
        // with a message saying that when a real key was pasted in this test
        // would start failing and should be replaced by one asserting the key
        // parses. That is exactly what happened on 2026-07-28, and this is
        // that replacement -- the failure was the handover, working.
        //
        // What this proves and what it does NOT. It proves the compiled
        // constant is a well-formed, non-weak Ed25519 verifying key on the
        // pinned dalek. It says NOTHING about whether the project owner holds the
        // matching private half; a stranger's key would pass here just as
        // happily. Only `patanyx-sign verify` against a manifest they actually
        // signed can answer that, and only they can run it.
        let keys = trusted_keys().expect(
            "the compiled publisher key must be a usable Ed25519 verifying key; \
             if this fails, every authentic update will be refused",
        );
        assert_eq!(
            keys.len(),
            2,
            "working key plus reserve; if this drops to one, rotation has \
             stopped being a single release and a leak becomes near-permanent"
        );
        // Distinct, which is the entire point of holding a reserve. A
        // copy-paste that duplicated the working key would look exactly like
        // preparedness and provide none.
        assert_ne!(
            PUBLISHER_KEYS[0], PUBLISHER_KEYS[1],
            "the reserve key must not be a copy of the working key"
        );
        assert!(
            !PUBLISHER_KEYS
                .iter()
                .any(|k| k.chars().all(|c| c == '0')),
            "the all-zeros placeholder is back in PUBLISHER_KEYS -- that is the \
             one key forged signatures verify against"
        );
    }

    /// The blocklist key list, checked harder than the release one, because a
    /// mistake here is SILENT.
    ///
    /// A bad `PUBLISHER_KEYS` surfaces as a visible update failure with its own
    /// phase and detail string. A bad `BLOCKLIST_KEYS` becomes
    /// `format!("keys: {e}")` inside a background refresh and shows up as
    /// nothing at all -- a browser that has quietly stopped receiving
    /// malicious-host updates while every indicator still says protected. These
    /// assertions are the only thing standing between that and a release; no
    /// CI step anywhere checks key configuration.
    #[test]
    fn compiled_blocklist_keys_parse() {
        let keys = blocklist_trusted_keys().expect(
            "the compiled blocklist keys must be usable Ed25519 verifying keys; \
             if this fails, every blocklist refresh is refused and the browser \
             silently keeps whatever list it already had",
        );
        assert!(!keys.is_empty(), "the blocklist key list must not be empty");
        assert!(
            !BLOCKLIST_KEYS.iter().any(|k| k.chars().all(|c| c == '0')),
            "the all-zeros placeholder is in BLOCKLIST_KEYS -- that is the one \
             key forged signatures verify against"
        );

        // THE INVARIANT THAT MATTERS, and it is one-directional.
        //
        // BLOCKLIST_KEYS[0] is the automated publisher's key: it sits on a
        // server and signs unattended. It must never appear in PUBLISHER_KEYS,
        // because that list authorises BINARY installs and the whole point of
        // the split is that losing the frequently-handled key costs a wrong
        // host list rather than arbitrary code on every machine.
        //
        // Full disjointness is deliberately NOT asserted: BLOCKLIST_KEYS
        // currently also carries the release working key so that installs
        // predating this change keep refreshing. That direction is harmless --
        // it only means a release key may also sign a blocklist, which was
        // already true before the split existed. When that transitional entry
        // is removed, tighten this to a full disjointness check.
        assert!(
            !PUBLISHER_KEYS.contains(&BLOCKLIST_KEYS[0]),
            "the automated blocklist key is in PUBLISHER_KEYS, so a key that \
             lives on a server and signs every hour can now authorise a binary \
             install on every machine. This is the exact outcome the separate \
             key list exists to prevent"
        );
    }

    /// The constant is useless unless the call site uses it.
    ///
    /// Adding BLOCKLIST_KEYS and `blocklist_trusted_keys` without repointing
    /// blocklist.rs produces a build that LOOKS separated -- new constant, new
    /// function, new tests, all green -- and still verifies blocklists against
    /// the release keys. `blocklist_trusted_keys` would simply be dead code,
    /// and nothing else in the suite would notice. So this reads the source.
    #[test]
    fn the_blocklist_channel_uses_the_blocklist_keys() {
        let src = include_str!("blocklist.rs");
        assert!(
            src.contains("blocklist_trusted_keys()"),
            "blocklist.rs does not call blocklist_trusted_keys -- the key split \
             is cosmetic and blocklists are still verified against the release \
             keys"
        );
        // And not the other one, which would mean both are wired and whichever
        // runs first wins.
        assert!(
            !src.contains("updater::trusted_keys()"),
            "blocklist.rs still calls updater::trusted_keys somewhere; the \
             blocklist channel must reach for exactly one key list"
        );
    }

    /// The compiled-in key must verify a signature from the REAL private key.
    ///
    /// Everything above checks the key list's SHAPE -- it parses, it has no
    /// placeholder, it is not the release key. None of that catches a key that
    /// is well-formed, correctly separated, and simply WRONG: a typo, a
    /// transposed pair of hex characters, or the verifying key of a keypair
    /// whose private half was never kept. All of those compile, pass every
    /// other test here, and produce a browser whose blocklist silently stops
    /// updating the moment it ships -- `refresh_blocking` returns an error into
    /// a background task and no user-visible state changes at all.
    ///
    /// So this is a real envelope, produced by
    /// `patanyx-sign sign-blocklist` with the actual blocklist private key on
    /// 2026-07-31, run through the exact verifier `blocklist.rs:190` calls
    /// with the exact keys it passes. Signed with the blocklist key ALONE, not
    /// the transitional release key, so it keeps proving the right thing after
    /// that entry is dropped.
    ///
    /// If the blocklist key is ever rotated, this fixture must be regenerated
    /// with the new key -- and its failure is the point: a rotation that
    /// forgets to update the browser is exactly the mistake worth catching
    /// before release rather than after.
    #[test]
    fn the_real_blocklist_key_verifies_a_real_signature() {
        const SIGNED: &str = r#"{
          "payload": "{\"list_version\":1,\"url\":\"https://patanyx.edgexene.io/dl/blocklist-1.bin\",\"sha256\":\"3b1f8c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e\",\"size\":6250048,\"entries\":390628,\"published_at\":1785542400}",
          "sig": "8bec419920de7bef37f5fca906393039effb7848e29e375a832777701cda5ca9869a7a074f516d53cdd99f609375ebfb71583d730f430c1e44391419dd01c200",
          "v": 1
        }"#;

        let keys = blocklist_trusted_keys().expect("blocklist keys must parse");
        let m = patanyx_update::verify_blocklist_manifest(SIGNED.as_bytes(), &keys).expect(
            "the compiled-in BLOCKLIST_KEYS did not verify a manifest signed by \
             the real blocklist private key. Either the key is wrong, or it was \
             rotated without regenerating this fixture. Shipping this means \
             every install stops receiving malicious-host updates, silently",
        );
        assert_eq!(m.list_version(), 1);
        assert_eq!(m.entries(), 390628);

        // The same bytes must NOT verify as an update. Domain separation is
        // tested in manifest.rs against synthetic keys; this asserts it holds
        // for the real ones, which is the pair that actually ships.
        assert!(
            patanyx_update::verify_manifest(SIGNED.as_bytes(), &trusted_keys().unwrap()).is_err(),
            "a blocklist manifest verified as a software update -- the \
             automated hourly key can authorise a binary install"
        );
    }

    #[test]
    fn floor_does_not_exceed_current_version() {
        // A floor above the running version would refuse EVERY update,
        // including the fix for the incident the floor was raised for.
        let current = current_version().expect("CARGO_PKG_VERSION must be semver");
        assert!(FLOOR <= current, "floor {FLOOR} is above running {current}");
    }

    #[test]
    fn supported_targets_map_to_a_platform() {
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            assert_eq!(running_platform(), Some(Platform::LinuxX86_64));
        }
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert_eq!(running_platform(), Some(Platform::MacosAarch64));
        }
        if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
            assert_eq!(running_platform(), Some(Platform::WindowsX86_64));
        }
    }

    #[test]
    fn manifest_url_is_tls_and_per_platform() {
        // The debug-build env override would invalidate this test, so clear
        // it; nothing else in the process reads it.
        std::env::remove_var("PATANYX_UPDATE_MANIFEST_URL");
        for channel in [
            crate::prefs::UpdateChannel::Stable,
            crate::prefs::UpdateChannel::Beta,
        ] {
            for platform in [Platform::LinuxX86_64, Platform::WindowsX86_64] {
                let url = manifest_url(platform, channel);
                assert!(url.starts_with("https://"), "manifest fetch must be TLS");
                assert!(url.contains(platform.as_str()));
                // No version, no token, nothing per-install (privacy docs) --
                // true of BOTH channels: beta is a second FIXED url, not a
                // per-install one.
                assert!(!url.contains(&current_version().unwrap().to_string()));
                assert!(!url.contains('?'), "no query string on either channel's url: {url}");
            }
        }
    }

    #[test]
    fn beta_and_stable_are_two_distinct_fixed_urls_not_a_query_string() {
        std::env::remove_var("PATANYX_UPDATE_MANIFEST_URL");
        let stable = manifest_url(Platform::WindowsX86_64, crate::prefs::UpdateChannel::Stable);
        let beta = manifest_url(Platform::WindowsX86_64, crate::prefs::UpdateChannel::Beta);
        assert_ne!(stable, beta, "the two channels must resolve to different URLs");
        assert!(
            beta.ends_with("-beta.json"),
            "beta manifest must be its own path, not the stable one with a suffix appended \
             some other way: {beta}"
        );
        assert!(
            !stable.contains("beta"),
            "the stable URL must not mention beta anywhere: {stable}"
        );
    }

    #[test]
    fn read_capped_bounds_the_body() {
        let exact = vec![7u8; 64];
        assert_eq!(
            read_capped(std::io::Cursor::new(exact.clone()), 64).unwrap(),
            exact
        );
        assert!(matches!(
            read_capped(std::io::Cursor::new(vec![7u8; 65]), 64),
            Err(FetchError::TooLarge)
        ));
        assert!(read_capped(std::io::Cursor::new(Vec::<u8>::new()), 64)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cooldown_skips_completed_checks_but_not_failures() {
        assert!(!in_cooldown(None, &Phase::Idle));
        assert!(in_cooldown(Some(Instant::now()), &Phase::UpToDate));
        assert!(!in_cooldown(
            Some(Instant::now()),
            &Phase::Failed {
                detail: String::new(),
                resume: None,
            }
        ));
    }

    #[test]
    fn status_snapshot_is_the_js_contract() {
        let idle = Updater {
            phase: Phase::Idle,
            last_check_started: None,
        };
        let snap = status_json(&idle);
        assert_eq!(snap["state"], json!("idle"));
        for key in ["available", "running", "platform"] {
            assert!(snap.get(key).is_some(), "snapshot must always carry {key}");
        }

        let refused = Updater {
            phase: Phase::Refused {
                reason: "verbatim reason".to_string(),
                offered: None,
            },
            last_check_started: None,
        };
        let snap = status_json(&refused);
        assert_eq!(snap["state"], json!("refused"));
        assert_eq!(snap["reason"], json!("verbatim reason"));

        let Some(platform) = running_platform() else {
            return;
        };
        let offered = current_plus(1);
        let envelope = signed_manifest_for(offered, platform);
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let offered_state = Updater {
            phase: Phase::Offered {
                manifest: manifest.clone(),
            },
            last_check_started: None,
        };
        let snap = status_json(&offered_state);
        assert_eq!(snap["state"], json!("offered"));
        assert_eq!(snap["offered"], json!(offered.to_string()));
        assert_eq!(snap["size"], json!(manifest.size()));
        // The fixture carries no notes, so the key must be ABSENT, not
        // empty: the panel keys its "What is new" block on presence.
        assert!(snap.get("notes").is_none());

        // A manifest that does carry notes surfaces them verbatim, in the
        // ready state too (the one the background download parks in).
        let with_notes = sign_with(
            &payload_json(
                &offered.to_string(),
                platform.as_str(),
                TEST_BINARY.len() as u64,
            )
            .replace(
                "\"published_at\"",
                "\"notes\":\"Adds fingerprint noise.\",\"published_at\"",
            ),
            &dev_signing_key(),
        );
        let manifest = verify_manifest(with_notes.as_bytes(), &dev_trusted_keys()).unwrap();
        let snap = status_json(&Updater {
            phase: Phase::Ready {
                manifest,
                staged: PathBuf::from("/nonexistent-staged-path"),
            },
            last_check_started: None,
        });
        assert_eq!(snap["notes"], json!("Adds fingerprint noise."));
    }

    // ---- check pipeline (real signatures, injected fetch) ----

    #[test]
    fn signed_newer_manifest_is_offered() {
        let Some(platform) = running_platform() else {
            return; // unsupported CI target: the property is vacuous here
        };
        let offered = current_plus(1);
        let envelope = signed_manifest_for(offered, platform);
        let phase = run_check_with(
            &dev_trusted_keys(),
            &FLOOR,
            current_version().unwrap(),
            platform,
            || Ok(envelope.into_bytes()),
        );
        match phase {
            Phase::Offered { manifest } => assert_eq!(manifest.version(), offered),
            other => panic!("expected Offered, got {other:?}"),
        }
    }

    #[test]
    fn same_version_is_up_to_date_not_offered() {
        let Some(platform) = running_platform() else {
            return;
        };
        let current = current_version().unwrap();
        let envelope = signed_manifest_for(current, platform);
        let phase = run_check_with(&dev_trusted_keys(), &FLOOR, current, platform, || {
            Ok(envelope.into_bytes())
        });
        assert!(matches!(phase, Phase::UpToDate), "got {phase:?}");
    }

    #[test]
    fn older_signed_manifest_is_refused_with_verbatim_reason() {
        let Some(platform) = running_platform() else {
            return;
        };
        let current = current_version().unwrap();
        let older = Version::new(current.major, current.minor.saturating_sub(1), 0);
        if older >= current {
            return; // degenerate package version; property untestable here
        }
        let envelope = signed_manifest_for(older, platform);
        let phase = run_check_with(&dev_trusted_keys(), &FLOOR, current, platform, || {
            Ok(envelope.into_bytes())
        });
        let expected = RefusalReason::NotNewer {
            offered: older,
            running: current,
        }
        .to_string();
        match phase {
            Phase::Refused {
                reason,
                offered: Some(v),
            } => {
                assert_eq!(v, older);
                assert_eq!(reason, expected, "the UI must get RefusalReason verbatim");
            }
            other => panic!("expected NotNewer refusal, got {other:?}"),
        }
    }

    #[test]
    fn below_floor_is_refused_even_when_newer_and_signed() {
        let Some(platform) = running_platform() else {
            return;
        };
        let current = current_version().unwrap();
        let offered = current_plus(1);
        let floor = current_plus(2); // retires `offered`
        let envelope = signed_manifest_for(offered, platform);
        let phase = run_check_with(&dev_trusted_keys(), &floor, current, platform, || {
            Ok(envelope.into_bytes())
        });
        let expected = RefusalReason::BelowFloor { offered, floor }.to_string();
        match phase {
            Phase::Refused { reason, .. } => assert_eq!(reason, expected),
            other => panic!("expected BelowFloor refusal, got {other:?}"),
        }
    }

    #[test]
    fn wrong_platform_is_refused() {
        let Some(platform) = running_platform() else {
            return;
        };
        let other_platform = match platform {
            Platform::LinuxX86_64 => Platform::WindowsX86_64,
            _ => Platform::LinuxX86_64,
        };
        let envelope = signed_manifest_for(current_plus(1), other_platform);
        let phase = run_check_with(
            &dev_trusted_keys(),
            &FLOOR,
            current_version().unwrap(),
            platform,
            || Ok(envelope.into_bytes()),
        );
        assert!(matches!(phase, Phase::Refused { .. }), "got {phase:?}");
    }

    #[test]
    fn bad_signature_is_refused_never_failed() {
        // Honesty requirement: a verification failure is a REFUSAL shown
        // plainly — not an operational error to be retried silently. And an
        // unverifiable manifest must not lend the UI even its claimed
        // version.
        let Some(platform) = running_platform() else {
            return;
        };
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0xE5; 32]);
        let envelope = sign_with(
            &payload_json(
                &current_plus(1).to_string(),
                platform.as_str(),
                TEST_BINARY.len() as u64,
            ),
            &attacker,
        );
        let phase = run_check_with(
            &dev_trusted_keys(),
            &FLOOR,
            current_version().unwrap(),
            platform,
            || Ok(envelope.into_bytes()),
        );
        match phase {
            Phase::Refused {
                offered: None,
                reason,
            } => assert!(!reason.is_empty()),
            other => panic!("expected refusal with no offered version, got {other:?}"),
        }
    }

    #[test]
    fn tampered_manifest_is_refused() {
        let Some(platform) = running_platform() else {
            return;
        };
        let envelope = signed_manifest_for(current_plus(1), platform);
        let tampered = envelope.replace(
            &current_plus(1).to_string(),
            &current_plus(2).to_string(),
        );
        assert_ne!(tampered, envelope);
        let phase = run_check_with(
            &dev_trusted_keys(),
            &FLOOR,
            current_version().unwrap(),
            platform,
            || Ok(tampered.into_bytes()),
        );
        assert!(matches!(phase, Phase::Refused { .. }), "got {phase:?}");
    }

    // ---- install pipeline: nothing stages without verify_payload's Ok ----

    #[test]
    fn a_matching_delta_is_used_and_the_full_payload_is_never_fetched() {
        let Some(platform) = running_platform() else {
            return;
        };
        // The "running binary" this test patches FROM, and the release.
        let (old, new) = delta_fixture();
        let (patch, patch_hash) = patch_between(&old, &new);
        let offered = current_plus(1);
        let deltas = format!(
            "[{{\"from\":\"{}\",\"url\":\"https://updates.patanyx.example/d/1\",\"sha256\":\"{patch_hash}\",\"size\":{}}}]",
            sha256_hex(&old),
            patch.len()
        );
        let envelope = sign_with(
            &payload_json_over(&offered.to_string(), platform.as_str(), &new, &deltas),
            &dev_signing_key(),
        );
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        assert_eq!(manifest.deltas().len(), 1, "the delta must have parsed");
        let dir = fresh_stage_dir();
        let phase = run_install_with(
            |url, _| {
                // The whole point: the FULL url must never be requested.
                assert!(
                    url.contains("/d/1"),
                    "delta path must not fetch the full payload ({url})"
                );
                Ok(patch.clone())
            },
            move || Some(old.clone()),
            &manifest,
            &dir,
        );
        match phase {
            // Staged bytes are the PATCHED result, and they passed the same
            // verify_payload a full download passes.
            Phase::Ready { staged, .. } => {
                assert_eq!(std::fs::read(&staged).unwrap(), new)
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupted_delta_falls_back_to_the_full_download() {
        let Some(platform) = running_platform() else {
            return;
        };
        let (old, new) = delta_fixture();
        let (patch, patch_hash) = patch_between(&old, &new);
        let offered = current_plus(1);
        let deltas = format!(
            "[{{\"from\":\"{}\",\"url\":\"https://updates.patanyx.example/d/1\",\"sha256\":\"{patch_hash}\",\"size\":{}}}]",
            sha256_hex(&old),
            patch.len()
        );
        let envelope = sign_with(
            &payload_json_over(&offered.to_string(), platform.as_str(), &new, &deltas),
            &dev_signing_key(),
        );
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let dir = fresh_stage_dir();
        let new_for_fetch = new.clone();
        let full_fetched = std::sync::atomic::AtomicBool::new(false);
        let phase = run_install_with(
            |url, _| {
                if url.contains("/d/1") {
                    // Right size, wrong bytes: the hash check must catch it
                    // BEFORE the patch decoder ever sees them.
                    return Ok(vec![0xEE; patch.len()]);
                }
                full_fetched.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(new_for_fetch.clone())
            },
            move || Some(old.clone()),
            &manifest,
            &dir,
        );
        assert!(
            full_fetched.load(std::sync::atomic::Ordering::SeqCst),
            "a bad delta must fall back to the full download"
        );
        match phase {
            Phase::Ready { staged, .. } => {
                assert_eq!(std::fs::read(&staged).unwrap(), new)
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn a_delta_that_patches_to_the_wrong_bytes_is_refused_not_staged() {
        let Some(platform) = running_platform() else {
            return;
        };
        // A patch that applies cleanly but produces something OTHER than the
        // signed release: the delta layer cannot catch this, and it must not
        // have to -- verify_payload is the judge, and it must REFUSE.
        let (old, new) = delta_fixture();
        let mut wrong = new.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 0xFF; // same size, one byte off the signed release
        let (patch, patch_hash) = patch_between(&old, &wrong);
        let offered = current_plus(1);
        let deltas = format!(
            "[{{\"from\":\"{}\",\"url\":\"https://updates.patanyx.example/d/1\",\"sha256\":\"{patch_hash}\",\"size\":{}}}]",
            sha256_hex(&old),
            patch.len()
        );
        let envelope = sign_with(
            &payload_json_over(&offered.to_string(), platform.as_str(), &new, &deltas),
            &dev_signing_key(),
        );
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let dir = fresh_stage_dir();
        let phase = run_install_with(
            |_, _| Ok(patch.clone()),
            move || Some(old.clone()),
            &manifest,
            &dir,
        );
        match phase {
            Phase::Refused { .. } => {}
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn verified_payload_is_staged_and_ready() {
        let Some(platform) = running_platform() else {
            return;
        };
        let offered = current_plus(1);
        let envelope = signed_manifest_for(offered, platform);
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let dir = fresh_stage_dir();
        let phase = run_install_with(|_, _| Ok(TEST_BINARY.to_vec()), || None, &manifest, &dir);
        match phase {
            Phase::Ready { staged, .. } => {
                assert_eq!(std::fs::read(&staged).unwrap(), TEST_BINARY);
                let name = staged.file_name().unwrap().to_string_lossy();
                assert!(name.contains(&offered.to_string()));
                assert!(name.contains(platform.as_str()));
            }
            other => panic!("expected Ready, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_payload_is_refused_and_nothing_is_staged() {
        // The acceptance criterion, as a test: no verify_payload Ok, no file.
        let Some(platform) = running_platform() else {
            return;
        };
        let envelope = signed_manifest_for(current_plus(1), platform);
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let mut forged = TEST_BINARY.to_vec();
        forged[0] ^= 1;
        let dir = fresh_stage_dir();
        let phase = run_install_with(|_, _| Ok(forged.clone()), || None, &manifest, &dir);
        assert!(matches!(phase, Phase::Refused { .. }), "got {phase:?}");
        assert!(
            dir_is_empty_or_missing(&dir),
            "a refused payload must never reach the staging directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_payload_is_refused_and_nothing_is_staged() {
        let Some(platform) = running_platform() else {
            return;
        };
        let envelope = signed_manifest_for(current_plus(1), platform);
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let truncated = TEST_BINARY[..TEST_BINARY.len() - 1].to_vec();
        let dir = fresh_stage_dir();
        let phase = run_install_with(|_, _| Ok(truncated.clone()), || None, &manifest, &dir);
        assert!(matches!(phase, Phase::Refused { .. }), "got {phase:?}");
        assert!(dir_is_empty_or_missing(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_download_is_refused_before_staging() {
        // The fetch cap IS the signed size; one byte more contradicts the
        // publisher's own statement, so it is a refusal, not an error.
        let Some(platform) = running_platform() else {
            return;
        };
        let envelope = signed_manifest_for(current_plus(1), platform);
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let dir = fresh_stage_dir();
        let phase = run_install_with(|_, _| Err(FetchError::TooLarge), || None, &manifest, &dir);
        assert!(matches!(phase, Phase::Refused { .. }), "got {phase:?}");
        assert!(dir_is_empty_or_missing(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn network_failure_is_retryable_not_a_refusal() {
        let Some(platform) = running_platform() else {
            return;
        };
        let envelope = signed_manifest_for(current_plus(1), platform);
        let manifest = verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).unwrap();
        let dir = fresh_stage_dir();
        for error in [
            FetchError::Network("connection refused".to_string()),
            FetchError::Http(503),
        ] {
            let phase = run_install_with(|_, _| Err(error.clone()), || None, &manifest, &dir);
            match phase {
                Phase::Failed {
                    resume: Some(_), ..
                } => {}
                other => panic!("expected retryable failure, got {other:?}"),
            }
        }
        assert!(dir_is_empty_or_missing(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Prints the verifying key matching DEV_SIGNING_SEED, for local
    /// end-to-end testing: put it in PUBLISHER_KEYS temporarily, sign test
    /// manifests with the seed, serve them over TLS, and point a debug build
    /// at them with PATANYX_UPDATE_MANIFEST_URL.
    #[test]
    #[ignore = "prints key material on demand"]
    fn dev_print_keypair() {
        let verifying = dev_signing_key().verifying_key();
        println!("dev signing seed (hex):   {}", hex_encode(&DEV_SIGNING_SEED));
        println!("dev verifying key (hex):  {}", hex_encode(verifying.as_bytes()));
        println!("THIS IS A DEV KEY. It must never sign a shipped release.");
    }
}

/// Run a check on a worker thread and report the resulting status.
///
/// Used by BOTH the schedule and the "Check now" button, because `check_now`
/// is synchronous and performs an HTTP GET on whatever thread calls it.
///
/// This comment previously said blocking was "tolerable for the IPC path (the
/// user pressed a button and is watching)". That was wrong, and the project owner
/// found it: pressing Check now froze the whole browser -- shortcuts, tabs,
/// clicks -- for up to the 30s manifest timeout, and with encrypted DNS
/// failing closed the full timeout was the likely case. A user watching a
/// spinner has not agreed to their other tabs freezing.
///
/// It runs the same pipeline as the button: verify the manifest, decide --
/// and, since background download landed, a verified offer is then FETCHED
/// AND STAGED too when the pref allows (see the chain in `check_now`; off
/// switch in the panel; skipped in Flatpak). NOTHING IS INSTALLED. The
/// guarantee that no update installs without an explicit accept is
/// unchanged; what changed is that the accept became an instant restart
/// instead of a wait, and the disclosure text in update.js says all of
/// this in the user's language.
pub fn check_in_background(proxy: &tao::event_loop::EventLoopProxy<crate::UserEvent>) {
    let proxy = proxy.clone();
    let _ = std::thread::Builder::new()
        .name("update-check".into())
        .spawn(move || {
            let status = check_now();
            let _ = proxy.send_event(crate::UserEvent::UpdateChecked(status));
        });
}

#[cfg(test)]
mod data_dir_tests {
    use super::*;

    const TEMP: &str = "/tmp";

    #[test]
    fn an_explicit_override_wins_over_everything() {
        let d = data_dir_from(Some("/x"), Some("/xdg"), Some("/home"), Some("/appdata"), Path::new(TEMP));
        assert_eq!(d, PathBuf::from("/x/updates"));
    }

    #[test]
    fn windows_uses_appdata_rather_than_temp() {
        // THE BUG THIS EXISTS FOR. There was no APPDATA arm at all, so Windows
        // fell through to temp -- and this directory is the parent of the
        // blocklist store, so every temp cleanup silently reverted users to
        // the bundled floor while the panel still reported a host count.
        let d = data_dir_from(None, None, None, Some("C:/Users/x/AppData/Roaming"), Path::new(TEMP));
        assert_eq!(d, PathBuf::from("C:/Users/x/AppData/Roaming/patanyx/updates"));
        assert!(!d.starts_with(TEMP), "a refreshed blocklist must not live in temp");
    }

    #[test]
    fn unix_prefers_xdg_then_home() {
        assert_eq!(
            data_dir_from(None, Some("/xdg"), Some("/home"), None, Path::new(TEMP)),
            PathBuf::from("/xdg/patanyx/updates")
        );
        assert_eq!(
            data_dir_from(None, None, Some("/home"), None, Path::new(TEMP)),
            PathBuf::from("/home/.local/share/patanyx/updates")
        );
    }

    #[test]
    fn an_empty_variable_is_not_a_directory() {
        // Set-but-empty is how a shell exports a variable it could not resolve.
        // Treating "" as a path would put the blocklist at "/updates".
        let d = data_dir_from(Some(""), Some(""), Some(""), Some(""), Path::new(TEMP));
        assert_eq!(d, PathBuf::from("/tmp/patanyx/updates"));
    }

    #[test]
    fn temp_is_the_last_resort_only() {
        let d = data_dir_from(None, None, None, None, Path::new(TEMP));
        assert_eq!(d, PathBuf::from("/tmp/patanyx/updates"));
    }

    /// Even in temp, the blocklist stays inside a directory we own.
    ///
    /// `blocklist::store_dir()` is `data_dir().parent() + "blocklist"`. While
    /// the temp fallback was a single level (`<temp>/patanyx-updates`) that
    /// parent was temp ITSELF, so the refreshed malicious-host list landed at
    /// `<temp>/blocklist` -- an unnamespaced name in a directory every account
    /// on a multi-user machine can write to. The list is hashes rather than
    /// domains and a corrupt one falls back to the bundled floor, so this was
    /// integrity and availability rather than disclosure; it is still not
    /// somewhere a security artifact belongs.
    #[test]
    fn the_temp_fallback_keeps_the_blocklist_namespaced() {
        let d = data_dir_from(None, None, None, None, Path::new(TEMP));
        let store = d
            .parent()
            .expect("the fallback must have a parent to derive from")
            .join("blocklist");
        assert_eq!(store, PathBuf::from("/tmp/patanyx/blocklist"));
        assert_ne!(
            store,
            PathBuf::from("/tmp/blocklist"),
            "the blocklist must not sit directly in a shared temp directory"
        );
    }
}
