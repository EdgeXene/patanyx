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
/// ed25519-dalek. It says nothing about whether the publisher holds the private
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
/// Keys that may sign a LANGUAGE PACK manifest. A THIRD list, and the reason
/// is the decision of 2026-08-31: the model feed's key authorises
/// model-feed artifacts ONLY, and a valid model-feed signature must never be
/// interpreted as authority to sign a blocklist or a release.
///
/// TWO MECHANISMS, AND BOTH ARE NEEDED. Domain separation
/// (`SIGNING_DOMAIN_MODELS`) stops a model signature being REPLAYED against
/// another verifier. It does nothing about forgery: a key the verifier trusts
/// can always sign a fresh message in another domain. Only a separate key SET
/// stops that, which is this list.
///
/// NO TRANSITIONAL ENTRY, deliberately, and note the contrast with
/// `BLOCKLIST_KEYS` above. That list still carries the release working key so
/// installs already in the field keep refreshing, and its own comment is
/// honest that "a release key can still sign a blocklist" until the entry
/// goes. Nothing in the field verifies a model manifest yet, so there is no
/// compatibility debt to pay here and this list starts clean. It must stay
/// that way: adding a second key for convenience would give away the property
/// on the day it was added.
///
/// The private half lives at /root/.patanyx-keys/models.key on the publishing
/// server, like the blocklist key and for the same reason -- packs are
/// republished by automation, and nobody signs by hand on a schedule.
const MODEL_KEYS: &[&str] =
    &["acb24fc2688ae44ad771e764c824053a1c0ebcbbf4cbd8bd18fe9bb8b21873bd"];

const BLOCKLIST_KEYS: &[&str] = &[
    // The automated publisher's key. Lives on the server, used by cron.
    "1e0225c3731b06a55400ee0cb0bac1b25d8afe36971c5e38bcb5f2cef7b5b216",
    // TRANSITIONAL: the release working key, so installs predating
    // BLOCKLIST_KEYS keep refreshing. Delete this line one release after the
    // build carrying it has propagated.
    "49ecd13929f38f8961e52b284bf55d725c38e990fddf4e7ea949729584cc0a09",
];

/// Keys that may sign an ENGINE ADVISORY: the warning-only WebView2
/// threshold (`patanyx_update::verify_advisory_manifest`, and the client half
/// in `engine_advisory.rs`). A FOURTH list, and the fourth class.
///
/// EMPTY ON PURPOSE, AND THIS IS NOT A PLACEHOLDER KEY. The other lists once
/// shipped an all-zeros placeholder that parsed and looked configured;
/// `TrustedKeys::new` refuses that shape now. An EMPTY list is refused too
/// (`NoTrustedKeys`), and `engine_advisory::check` turns that refusal into
/// the `unconfigured` state: nothing is fetched, nothing is persisted, and
/// the status snapshot says the channel is not active. That is the truthful
/// state of every build until the production key exists, and it cannot be
/// mistaken for delivery.
///
/// PROVISIONING IS A ONE-TIME LANDING STEP, not part of this change:
///
///   1. `patanyx-sign keygen /root/.patanyx-keys/advisory.key advisory` on
///      the publishing server (0600, beside blocklist.key -- same terms, same
///      reasoning: an unattended hourly signer cannot use an offline key).
///   2. Paste the printed verifying key here. `advisory_keys_are_provisioned`
///      below flips from pinning EMPTY to pinning ONE key in that same change.
///   3. Ship a release. Only builds carrying the key can receive advisories;
///      builds already in the field keep the release-manifest floor path.
///
/// WHAT A STOLEN ADVISORY KEY BUYS: a false banner on Windows, until the key
/// is dropped from this list in a release. The client keeps advisory floors
/// UNDER THE KEY THAT SIGNED THEM and re-verifies them against this list on
/// every read, so revocation removes them; nothing signed becomes permanent.
/// It cannot lower a floor, refuse startup, name a URL or reach Linux.
///
/// It must never appear in `PUBLISHER_KEYS`, `BLOCKLIST_KEYS` or
/// `MODEL_KEYS`; `advisory_key_tests` asserts disjointness and pins exactly
/// one key.
///
/// PROVISIONED 2026-09-11 on the publishing server with
/// `patanyx-sign keygen /root/.patanyx-keys/advisory.key advisory` (0600,
/// beside blocklist.key). Only the verifying half is here; the signing half
/// has never left that file.
const ADVISORY_KEYS: &[&str] = &[
    // The hourly engine-advisory monitor's key. Lives on the server, used by
    // the timer.
    "e16998e637f88c04a57c7093aec5711e14cfd0811b157f67872896f14e4ea768",
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

/// How often the scheduled check looks to see whether its own fetch has
/// settled, and how long it is willing to wait before reporting whatever is
/// true at that moment. The wait covers a background DOWNLOAD as well as the
/// manifest fetch, which is why it is minutes rather than seconds.
const SETTLE_POLL: Duration = Duration::from_millis(250);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Dev-only signing seed for end-to-end tests. Any 32 bytes are a valid
/// Ed25519 secret seed, and these are printed on the tin; the matching
/// verifying key is what `dev_print_keypair` prints. NEVER the production
/// key, never anything generated outside tests.
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

/// Keys the LANGUAGE PACK channel verifies against. See `MODEL_KEYS`.
///
/// Separate function rather than a parameter, exactly as
/// `blocklist_trusted_keys` is: choosing the wrong set must be a visibly wrong
/// call at the call site, not an argument nobody reads.
pub(crate) fn model_trusted_keys() -> Result<TrustedKeys, UpdateError> {
    TrustedKeys::from_hex(MODEL_KEYS)
}

/// Keys the ENGINE ADVISORY channel verifies against. See `ADVISORY_KEYS`.
/// `Err(NoTrustedKeys)` until the list is provisioned, which the advisory
/// check reports as `unconfigured` rather than as a fetch failure.
pub(crate) fn advisory_trusted_keys() -> Result<TrustedKeys, UpdateError> {
    TrustedKeys::from_hex(ADVISORY_KEYS)
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
    /// This machine runs a NEWER version than the server offers. Not a
    /// refusal in the user's sense: nothing is wrong, nothing is withheld,
    /// the server is simply behind (a test build ahead of the feed, or the
    /// feed not yet carrying a release). Shown as up to date with the two
    /// versions named, never as "Update refused" in red (decided 2026-09-16).
    Ahead { offered: Version },
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
    /// The last engine-advisory outcome, reported beside the release phase.
    /// `None` until a check has run. Independent of `phase`: a failed or
    /// refused release check does not cost the user the advisory, and the
    /// snapshot shows both so neither can hide behind the other.
    advisory: Option<crate::engine_advisory::AdvisoryOutcome>,
    /// The raw signed envelope of the last successful check, kept so that a
    /// download reaching `Ready` can be made durable (remember_pending) no
    /// matter WHICH chain staged it. The background chain and the user's
    /// install click share download_and_stage precisely so they cannot
    /// drift; persisting from only one of them was exactly such a drift --
    /// a manually downloaded Ready evaporated on quit and could never
    /// self-install, while the copy promised it would.
    envelope: Option<Vec<u8>>,
}

static UPDATER: Mutex<Updater> = Mutex::new(Updater {
    phase: Phase::Idle,
    last_check_started: None,
    advisory: None,
    envelope: None,
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
            // The envelope bytes outlive the check: if this offer background-
            // downloads all the way to Ready, they are what makes Ready
            // durable across a restart (remember_pending re-verifies nothing
            // here -- the startup reader does that against the compiled keys).
            let mut envelope_bytes: Option<Vec<u8>> = None;
            let phase = run_check_observed(
                &keys,
                &FLOOR,
                current,
                platform,
                || {
                    let fetched =
                        net::get(&url, MAX_MANIFEST_FETCH_BYTES, net::MANIFEST_TIMEOUT);
                    if let Ok(bytes) = &fetched {
                        envelope_bytes = Some(bytes.clone());
                    }
                    fetched
                },
                |manifest| {
                    if let Err(e) = remember_engine_floors(&data_dir(), manifest) {
                        // Observable, not swallowed: the compiled floor stays
                        // in force, and the log says why the raise did not
                        // persist.
                        eprintln!("PATANYX: engine floor register not written: {e}");
                    }
                },
            );
            // THE ENGINE ADVISORY, after the release manifest and WHATEVER
            // it concluded. Same schedule, same host, one more fixed URL;
            // its own key set and its own verifier. See engine_advisory.rs.
            let advisory = observe_advisory_after(&phase, crate::engine_advisory::check);
            // Background download, the mainstream shape MINUS the silent apply:
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
            {
                let mut u = lock();
                u.envelope = envelope_bytes.clone();
                u.phase = phase;
                u.advisory = Some(advisory);
            }
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
                let phase = download_and_stage(&manifest);
                if let (Phase::Ready { staged, manifest }, Some(envelope)) =
                    (&phase, &envelope_bytes)
                {
                    remember_pending(&data_dir(), envelope, staged, manifest);
                }
                lock().phase = phase;
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

/// The advisory check runs AFTER the release check and REGARDLESS of how the
/// release check ended. A function rather than a line in the worker so the
/// independence is a tested property: every `Phase`, including `Failed` and
/// `Refused`, still runs `advisory`. The phase is read only to make that
/// promise explicit at the type level; nothing about it changes the call.
fn observe_advisory_after(
    phase: &Phase,
    advisory: impl FnOnce() -> crate::engine_advisory::AdvisoryOutcome,
) -> crate::engine_advisory::AdvisoryOutcome {
    let _ = phase;
    advisory()
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
            let phase = download_and_stage(&worker);
            let mut u = lock();
            if let (Phase::Ready { staged, manifest }, Some(envelope)) =
                (&phase, &u.envelope)
            {
                remember_pending(&data_dir(), envelope, staged, manifest);
            }
            u.phase = phase;
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

// ─────────────── A staged update that survives a restart ───────────────
//
// `Phase::Ready` used to live only in memory: quit without clicking and the
// verified download was forgotten, re-fetched next session, and the consent
// click never became the instant restart it was built to be. These few files
// make Ready durable, and `apply_pending_at_startup` is what turns a durable
// Ready into the mainstream behavior: maintenance and security releases
// install themselves at the next launch; a pure feature release waits for the
// user or for `GRACE_SECONDS`, whichever comes first.
//
// TRUST MODEL, stated once: the envelope on disk is VERIFIED AGAIN at startup
// against the compiled-in keys, and the staged bytes are re-hashed against the
// signed manifest inside `installer::apply`. Nothing on disk is believed for
// its location. The one unsigned file is the meta (staged filename +
// first-seen clock): tampering with the filename changes which bytes get
// re-hashed (they must still match the signed sha256, so substitution fails),
// and backdating first-seen can ripen a feature release early -- an actor with
// local write access could do strictly worse things to an unsandboxed browser,
// so the clock does not pretend to be tamper-proof.

/// How long an announced feature release waits before it stops waiting.
/// Seven days: long enough that nobody's UI changes mid-week without warning,
/// short enough that "ignored the banner" does not become "never patched".
const GRACE_SECONDS: u64 = 7 * 24 * 60 * 60;

fn pending_envelope_path(dir: &Path) -> PathBuf {
    dir.join("pending-envelope.json")
}

fn pending_meta_path(dir: &Path) -> PathBuf {
    dir.join("pending-meta.json")
}

/// Where the highest engine floors ever seen in a signed manifest live:
/// `{"webview2":[152,0,4191,62],"webkitgtk":[2,52,5]}`.
fn engine_floor_path(dir: &Path) -> PathBuf {
    dir.join("engine-floor.json")
}

/// The persisted floors, merged with what a freshly VERIFIED manifest
/// asserts. Monotonic: an engine's floor only ever rises, so a replayed
/// older manifest (which `decide` may still accept as "up to date") cannot
/// lower it. Returns the document to write, or `None` when nothing rose.
/// Pure, so the monotonicity is tested without a disk.
fn raise_engine_floors(existing: &Value, floors: &patanyx_update::EngineFloors) -> Option<Value> {
    let mut out = match existing {
        Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    let mut rose = false;
    for (key, asserted) in [("webview2", floors.webview2()), ("webkitgtk", floors.webkitgtk())] {
        let Some(asserted) = asserted else { continue };
        // STRICT conversion of the stored fields. This was `x as u32`, which
        // truncates: a stored field of 2^32 + 5 read back as 5, so a corrupt
        // or hand-edited register could compare as LOWER than a signed value
        // and be "raised" to it -- or, with a field near u32::MAX, compare as
        // higher than any honest floor and pin the register forever. A field
        // that does not fit is now a stored value that does not exist, and
        // the signed value wins.
        let current = out.get(key).and_then(|v| v.as_array()).and_then(|a| {
            a.iter()
                .map(|x| x.as_u64().and_then(|x| u32::try_from(x).ok()))
                .collect::<Option<Vec<u32>>>()
        });
        let higher = match &current {
            Some(cur) if cur.len() == asserted.len() => asserted > cur.as_slice(),
            // Nothing stored, or stored at a precision the manifest no longer
            // uses: the signed value wins.
            _ => true,
        };
        if higher {
            out.insert(key.to_string(), json!(asserted));
            rose = true;
        }
    }
    rose.then_some(Value::Object(out))
}

/// Records the engine floors a verified manifest carries. Called on EVERY
/// verified manifest, not only on an offered update: the whole point is that
/// a floor can rise while the browser is already at the newest version.
///
/// A failed write leaves the compiled floor in force, which is what every
/// build before this had -- but the failure is RETURNED now rather than
/// discarded, so the caller can say so. The write is atomic (temp file and
/// rename, `engine_advisory::write_atomic`) and the read-merge-replace runs
/// under the same process-wide lock the advisory register uses: two checks
/// racing produce a whole file holding the higher floor, and a crash mid-
/// write leaves the previous bytes exactly as they were. `Ok(true)` when the
/// register rose.
fn remember_engine_floors(dir: &Path, manifest: &Manifest) -> std::io::Result<bool> {
    let floors = manifest.engine_floors();
    if floors.is_empty() {
        return Ok(false);
    }
    // Same two locks as the advisory register (thread mutex plus the OS
    // file lock), so a second browser process sharing the directory cannot
    // rename a stale, lower document over this one.
    let _guard = crate::engine_advisory::register_guard(dir)?;
    let existing = std::fs::read_to_string(engine_floor_path(dir))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    match raise_engine_floors(&existing, floors) {
        Some(doc) => {
            crate::engine_advisory::write_atomic(&engine_floor_path(dir), doc.to_string().as_bytes())?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The highest floor a signed manifest has asserted for `engine`
/// ("WebView2" or "WebKitGTK", the names the browser reports), if any.
/// The platform layer compares it against the compiled constant and takes
/// the higher; a stored value can only ever raise, never lower.
pub(crate) fn persisted_engine_floor(engine: &str) -> Option<Vec<u32>> {
    let key = match engine {
        "WebView2" => "webview2",
        "WebKitGTK" => "webkitgtk",
        _ => return None,
    };
    let raw = std::fs::read_to_string(engine_floor_path(&data_dir())).ok()?;
    let doc: Value = serde_json::from_str(&raw).ok()?;
    let fields: Vec<u32> = doc
        .get(key)?
        .as_array()?
        .iter()
        .map(|x| x.as_u64().and_then(|x| u32::try_from(x).ok()))
        .collect::<Option<Vec<u32>>>()?;
    (!fields.is_empty()).then_some(fields)
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Record a staged update so the next launch can act on it. Called the
/// moment the background chain lands `Ready`, with the same envelope bytes
/// the check verified.
///
/// The first-seen clock is preserved across re-checks OF THE SAME VERSION:
/// every scheduled check re-stages, and a grace period that reset on each
/// one would never elapse.
fn remember_pending(dir: &Path, envelope: &[u8], staged: &Path, manifest: &Manifest) {
    let version = manifest.version().to_string();
    let first_seen = read_pending_meta(dir)
        .filter(|m| m.version == version)
        .map(|m| m.first_seen_unix)
        .unwrap_or_else(unix_now);
    // Filename only, never a path: the reader joins it back onto its own
    // data dir, so the meta cannot point the startup apply at foreign bytes
    // elsewhere on disk (which would still fail the hash, but why offer it).
    let Some(name) = staged.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let meta = json!({
        "version": version,
        "staged": name,
        "first_seen_unix": first_seen,
    });
    // Best effort, deliberately: failing to persist leaves exactly the
    // behavior every build before this had.
    let _ = std::fs::write(pending_envelope_path(dir), envelope);
    let _ = std::fs::write(pending_meta_path(dir), meta.to_string());
}

struct PendingMeta {
    version: String,
    staged: String,
    first_seen_unix: u64,
}

fn read_pending_meta(dir: &Path) -> Option<PendingMeta> {
    let raw = std::fs::read_to_string(pending_meta_path(dir)).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    // The writer stores a bare filename, and the READER is where that
    // property has to hold: `dir.join` follows `..`, and an absolute
    // component makes it discard `dir` entirely. A traversing value cannot
    // stage wrong bytes (the hash decides), but it could aim the startup
    // read at an arbitrary path, and the containment claim belongs to this
    // function, not to a comment about the writer.
    let staged = v["staged"].as_str()?;
    if Path::new(staged).file_name() != Some(std::ffi::OsStr::new(staged)) {
        return None;
    }
    Some(PendingMeta {
        version: v["version"].as_str()?.to_string(),
        staged: staged.to_string(),
        first_seen_unix: v["first_seen_unix"].as_u64()?,
    })
}

fn clean_pending(dir: &Path) {
    let _ = std::fs::remove_file(pending_envelope_path(dir));
    let _ = std::fs::remove_file(pending_meta_path(dir));
}

/// Is this pending release allowed to install itself RIGHT NOW?
///
/// The signed manifest speaks first (`installs_silently`: maintenance and
/// security releases qualify); an announced feature release ripens when its
/// grace period lapses. Pure, so the timing table is testable.
fn pending_is_ripe(manifest: &Manifest, first_seen_unix: u64, now_unix: u64) -> bool {
    manifest.installs_silently()
        || now_unix >= first_seen_unix.saturating_add(GRACE_SECONDS)
}

/// Apply a pending update at launch, before any window or vault exists.
/// Returns true when the replacement process has been spawned and THIS
/// process must exit without building a UI.
///
/// Every early return leaves the browser starting normally on its current
/// version -- this function must never be the reason PATANYX fails to open.
pub fn apply_pending_at_startup() -> bool {
    // A Flatpak cannot self-replace, and a smoke run must not: a gate that
    // swapped the binary under the test would invalidate the run.
    if in_flatpak() || std::env::args().any(|a| a == "--smoke-test") {
        return false;
    }
    let dir = data_dir();
    let Ok(envelope) = std::fs::read(pending_envelope_path(&dir)) else {
        return false;
    };
    let Ok(keys) = trusted_keys() else {
        return false;
    };
    // Not authentic = not ours. Remove it so a corrupt file is not re-parsed
    // at every launch forever.
    let Ok(manifest) = verify_manifest(&envelope, &keys) else {
        clean_pending(&dir);
        return false;
    };
    let Some(meta) = read_pending_meta(&dir) else {
        clean_pending(&dir);
        return false;
    };
    let (Some(current), Some(platform)) = (current_version(), running_platform()) else {
        return false;
    };
    // The normal end of the story: the relaunched (updated) process runs this,
    // finds the pending release is no longer newer than itself, and tidies up.
    let Decision::Update(_) = decide(&current, &FLOOR, platform, &manifest) else {
        clean_pending(&dir);
        return false;
    };
    if !crate::prefs::load().update_auto_apply {
        return false;
    }
    if !pending_is_ripe(&manifest, meta.first_seen_unix, unix_now()) {
        return false;
    }
    let staged = dir.join(&meta.staged);
    // `apply` re-reads and re-hashes the staged bytes against the signed
    // manifest before touching the running binary; a failure leaves both the
    // browser and the staged file in place.
    match installer::apply(&staged, &manifest) {
        Ok(()) => {
            clean_pending(&dir);
            let _ = std::fs::remove_file(&staged);
            true
        }
        Err(_) => false,
    }
}

/// The `kind` word the JS renders. One place, so the string contract with
/// update.js cannot fork.
fn release_kind_word(manifest: &Manifest) -> &'static str {
    match manifest.release_kind() {
        patanyx_update::ReleaseKind::Feature => "feature",
        patanyx_update::ReleaseKind::Maintenance => "maintenance",
    }
}

/// The one snapshot shape every command returns and update.js renders. The
/// `state` strings are a contract with the JS — the tests pin them.
fn status_json(u: &Updater) -> Value {
    let mut out = json!({
        "available": available(),
        "auto_apply": crate::prefs::load().update_auto_apply,
        "running": current_version().map(|v| v.to_string()),
        "platform": running_platform().map(|p| p.as_str()),
        "state": "idle",
        // Something on the network terminated TLS and the fetch only
        // succeeded once the OS trust store was accepted. Surfaced rather
        // than swallowed: the user is entitled to know their traffic is
        // being inspected, and to know the update was still verified
        // against the publisher's signature despite it. False on every
        // ordinary network, and on a build with no update networking.
        "intercepted": net::LAST_FETCH_WAS_INTERCEPTED
            .load(std::sync::atomic::Ordering::Relaxed),
    });
    // The engine advisory's own outcome, beside the release phase and never
    // folded into it. Absent until a check has run; `unconfigured` while no
    // advisory key is compiled in, which is every build until provisioning.
    if let Some(advisory) = &u.advisory {
        out["advisory"] = advisory.to_json();
    }
    match &u.phase {
        Phase::Idle => {}
        Phase::Checking => out["state"] = json!("checking"),
        Phase::UpToDate => out["state"] = json!("uptodate"),
        Phase::Ahead { offered } => {
            out["state"] = json!("ahead");
            out["offered"] = json!(offered.to_string());
        }
        Phase::Offered { manifest } => {
            out["state"] = json!("offered");
            out["offered"] = json!(manifest.version().to_string());
            out["size"] = json!(manifest.size());
            out["published_at"] = json!(manifest.published_at());
            out["kind"] = json!(release_kind_word(manifest));
            out["security"] = json!(manifest.security());
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
            out["kind"] = json!(release_kind_word(manifest));
            out["security"] = json!(manifest.security());
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
    run_check_observed(keys, floor, current, platform, fetch_manifest, |_| {})
}

/// `run_check_with`, plus a look at every manifest that VERIFIES, before
/// `decide` has its say. The engine floor rides on this: a manifest that is
/// "up to date" for the browser version still carries the newest floor, and
/// the browser must learn it. Nothing unverified ever reaches `on_verified`.
fn run_check_observed(
    keys: &TrustedKeys,
    floor: &Version,
    current: Version,
    platform: Platform,
    fetch_manifest: impl FnOnce() -> Result<Vec<u8>, FetchError>,
    on_verified: impl FnOnce(&Manifest),
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
    on_verified(&manifest);
    match decide(&current, floor, platform, &manifest) {
        Decision::UpToDate => Phase::UpToDate,
        Decision::Update(manifest) => Phase::Offered { manifest },
        Decision::Refused(patanyx_update::RefusalReason::NotNewer { offered, .. }) => Phase::Ahead { offered },
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

/// Whether a transport error is a certificate refusal rather than a plain
/// failure to connect. Matched on the text because that is all the transport
/// gives us, and matched broadly on purpose: a false positive here says
/// "something is inspecting your connection" about an ordinary outage, which
/// is a worse answer than the generic one, so the phrases are the specific
/// ones rustls produces for a chain it will not accept.
fn is_certificate_refusal(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    d.contains("unknownissuer")
        || d.contains("invalid peer certificate")
        || d.contains("certificate")
}

fn fetch_detail(error: &FetchError) -> String {
    match error {
        // NO RUST ERROR TEXT IN ANY OF THESE. What the user used to get was
        // `{detail}` verbatim -- "tls connection init failed: invalid peer
        // certificate: UnknownIssuer", or an os error number -- which names
        // no cause a person can act on and reads as a fault in the browser.
        //
        // The certificate case is worth telling apart because it has a real
        // explanation and a real remedy: something between this browser and
        // us is terminating TLS, and downloading the installer from the
        // website works because that download goes through a browser using
        // the certificates this computer already trusts.
        FetchError::Network(detail) if is_certificate_refusal(detail) => {
            "PATANYX could not confirm it was talking to the update server. \
             Something on this computer or its network is inspecting \
             encrypted traffic and presenting its own certificate, which this \
             browser does not recognize. Nothing was installed. You can still \
             update by downloading the installer from the website."
                .to_string()
        }
        FetchError::Network(_) => {
            "could not reach the update server. It may be temporarily \
             unavailable, or something on this network is blocking the \
             connection."
                .to_string()
        }
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
    read_capped_progress(reader, cap, |_| {})
}

/// Read a capped body, calling `on_progress(bytes_so_far)` as chunks arrive.
///
/// SAME CAP ENFORCEMENT as `read_capped` -- the `take(cap+1)` and the
/// post-check are identical, so progress reporting cannot become a way to read
/// past the limit. The callback is advisory: it drives a UI and is never
/// allowed to change what bytes are accepted. Chunked at 64 KiB so a 36 MB
/// pack reports ~570 times, often enough to feel live and rare enough not to
/// flood the event loop.
pub(crate) fn read_capped_progress(
    mut reader: impl Read,
    cap: u64,
    mut on_progress: impl FnMut(u64),
) -> Result<Vec<u8>, FetchError> {
    let mut limited = reader.by_ref().take(cap.saturating_add(1));
    let mut body = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = limited
            .read(&mut chunk)
            .map_err(|e| FetchError::Network(e.to_string()))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() as u64 > cap {
            return Err(FetchError::TooLarge);
        }
        on_progress(body.len() as u64);
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

    /// Whether the last fetch only succeeded once the OS trust store was
    /// accepted -- i.e. something is terminating TLS between here and the
    /// distribution host. Reported to the user rather than swallowed; see
    /// `crate::net::Roots`.
    pub static LAST_FETCH_WAS_INTERCEPTED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// One GET: compiled-in roots first, the OS store only as the retry.
    ///
    /// SHARED BY BOTH FETCHERS, DELIBERATELY. This retry was added to `get`
    /// alone (security audit 2026-08-18, F21) and `get_with_progress` never
    /// grew it. On an intercepting corporate network the two therefore
    /// disagreed about the SAME feed: the signed manifest downloaded through
    /// the relaxed retry, and the pack body -- fifty megabytes later, same
    /// host, same integrity argument -- failed on the strict agent with no
    /// second attempt. The user was told "could not reach the language pack
    /// server" about a server that was answering perfectly. Neither function
    /// was wrong when read on its own, which is exactly why this is now one
    /// function and not two.
    ///
    /// A TRANSPORT FAILURE MAY BE AN INTERCEPTING PROXY, AND THE RETRY IS THE
    /// TEST. On such a network every connection is terminated and re-signed by
    /// a CA in the OS store and in no public root list, so the strict agent
    /// reports UnknownIssuer while the rest of the browser works, because the
    /// engine consults the OS store and this does not. Rather than match on an
    /// error string, which is brittle across ureq and rustls versions, the
    /// retry IS the diagnosis: if the same request succeeds once OS roots are
    /// accepted, something the machine trusts and Mozilla does not is in the
    /// path. If it fails too, the STRICT error is what the user sees, so a
    /// genuine outage still reads as an outage.
    ///
    /// SAFE FOR THIS FEED AND NO OTHER: manifests and payloads rest on the
    /// compiled-in Ed25519 key and a sha256 and length from the signed
    /// manifest, not on TLS -- a proxy that can read this connection still
    /// cannot forge a pack that verifies. The activation call carries a licence
    /// token, has no such signature, and keeps using `crate::net::agent` only.
    fn call_strict_then_os_roots(
        url: &str,
        timeout: Duration,
    ) -> Result<ureq::Response, FetchError> {
        // The agent comes from crate::net, the ONE place that knows the tunnel
        // rule (proxy when the engine says so, fail closed when it cannot be
        // expressed, no redirects).
        let agent = crate::net::agent(timeout).map_err(|e| FetchError::Network(e.to_string()))?;
        match agent.get(url).call() {
            Ok(response) => {
                LAST_FETCH_WAS_INTERCEPTED.store(false, std::sync::atomic::Ordering::Relaxed);
                Ok(response)
            }
            Err(ureq::Error::Status(code, _)) => Err(FetchError::Http(code)),
            Err(ureq::Error::Transport(strict_error)) => {
                let relaxed = crate::net::agent_accepting_os_roots(timeout)
                    .map_err(|e| FetchError::Network(e.to_string()))?;
                match relaxed.get(url).call() {
                    Ok(response) => {
                        LAST_FETCH_WAS_INTERCEPTED
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        Ok(response)
                    }
                    Err(ureq::Error::Status(code, _)) => Err(FetchError::Http(code)),
                    // Report the STRICT error, not the retry's: the retry is a
                    // diagnostic, and its failure says nothing the first did not.
                    Err(ureq::Error::Transport(_)) => {
                        Err(FetchError::Network(strict_error.to_string()))
                    }
                }
            }
        }
    }

    pub fn get(url: &str, cap: u64, timeout: Duration) -> Result<Vec<u8>, FetchError> {
        let response = call_strict_then_os_roots(url, timeout)?;
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

    /// Like `get`, but reports download progress against `cap`.
    ///
    /// The header content-length is passed to `on_progress` first as the
    /// denominator when the server offers one; it is advisory (the signed
    /// manifest size is the number that actually matters and is checked later),
    /// but it lets the UI show "12 of 36 MB" instead of a bare byte count.
    pub fn get_with_progress(
        url: &str,
        cap: u64,
        timeout: Duration,
        mut on_progress: impl FnMut(u64, Option<u64>),
    ) -> Result<Vec<u8>, FetchError> {
        let response = call_strict_then_os_roots(url, timeout)?;
        let announced = response
            .header("content-length")
            .and_then(|h| h.parse::<u64>().ok());
        if let Some(len) = announced {
            if len > cap {
                return Err(FetchError::TooLarge);
            }
        }
        on_progress(0, announced);
        super::read_capped_progress(response.into_reader(), cap, |n| on_progress(n, announced))
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

    /// Always false here: this build makes no TLS connection to intercept.
    /// Present so `status_json` compiles one way in both builds.
    pub static LAST_FETCH_WAS_INTERCEPTED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    pub fn get_with_progress(
        _url: &str,
        _cap: u64,
        _timeout: Duration,
        _on_progress: impl FnMut(u64, Option<u64>),
    ) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::Network("no TLS stack in this build".to_string()))
    }

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

    /// Start a replacement of THIS binary and let this process exit normally.
    ///
    /// Same three lines as `relaunch`, and deliberately the same ones: this
    /// is a restart, not an update, so nothing is written to disk first. The
    /// tunnel's "Apply and restart" needs a new process because WebView2
    /// reads `--proxy-server` only when the environment is created, and there
    /// was no way to restart the browser from anywhere outside this module.
    ///
    /// WHY THE SPAWN-THEN-QUIT ORDER IS SAFE HERE, and it is not obvious:
    /// the vault holds an OS file lock (mandatory on Windows), so two live
    /// processes could not both open it. They never do. The replacement
    /// starts at the unlock screen and touches no vault until the user types
    /// a passphrase, by which time this process has returned to the event
    /// loop, exited, and had its lock released by the kernel. The updater
    /// has relied on exactly this since 0.9.x.
    ///
    /// The caller sends `QuitForRelaunch` AFTER this returns Ok, never
    /// before: a failed spawn must leave a working browser running.
    pub(crate) fn relaunch_current_exe() -> std::io::Result<()> {
        relaunch(&std::env::current_exe()?)
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

    /// The scheduled check must report a SETTLED state, because the chrome
    /// only interrupts the user for one. This pins the predicate that decides
    /// when the reporting thread is still waiting.
    ///
    /// The defect it exists for: `check_now` returns the moment it spawns its
    /// fetch, so the emitted state was `checking` forever and the banner
    /// could not fire on any platform. Both halves matter -- treating
    /// `downloading` as settled would announce an update mid-download and the
    /// banner would claim bytes that are not there yet.
    #[test]
    fn only_a_finished_check_is_worth_announcing() {
        for state in ["checking", "downloading"] {
            assert!(
                in_flight(&json!({ "state": state })),
                "{state} is still in progress; announcing it tells the user \
                 something that is not true yet"
            );
        }
        for state in ["offered", "ready", "uptodate", "failed", "refused"] {
            assert!(
                !in_flight(&json!({ "state": state })),
                "{state} is a settled answer and must be reported, or the \
                 scheduled check stays silent the way it did before"
            );
        }
        // A snapshot with no state at all is settled by default: waiting
        // forever on a shape we do not recognise would be the same silence
        // in a new costume.
        assert!(!in_flight(&json!({})));
    }

    pub(super) fn dev_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&DEV_SIGNING_SEED)
    }

    pub(super) fn dev_trusted_keys() -> TrustedKeys {
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
    pub(super) fn payload_json(version: &str, platform: &str, size: u64) -> String {
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
    pub(super) fn sign_with(payload: &str, key: &ed25519_dalek::SigningKey) -> String {
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
        // pinned dalek. It says NOTHING about whether the publisher holds the
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

    /// The startup-apply timing table. `pending_is_ripe` is the only gate
    /// between "a verified update is on disk" and "the binary replaces
    /// itself with no click", so every row is pinned: quiet kinds install at
    /// once, an announced feature release waits out its full grace period to
    /// the second, and a security fix inside a feature release does not wait.
    #[test]
    fn a_pending_release_ripens_by_kind_grace_and_security() {
        let manifest_with = |extra: &str| {
            let payload = payload_json("9.9.9", "linux-x86_64", TEST_BINARY.len() as u64)
                .replace(",\"size\":", &format!(",{extra}\"size\":"));
            verify_manifest(
                sign_with(&payload, &dev_signing_key()).as_bytes(),
                &dev_trusted_keys(),
            )
            .expect("test manifest must verify")
        };
        let t0 = 1_000_000;

        // Maintenance (explicit or defaulted): ripe the moment it is staged.
        assert!(pending_is_ripe(&manifest_with(""), t0, t0));
        assert!(pending_is_ripe(
            &manifest_with("\"kind\":\"maintenance\","),
            t0,
            t0
        ));

        // A feature release waits the WHOLE grace period...
        let feature = manifest_with("\"kind\":\"feature\",");
        assert!(!pending_is_ripe(&feature, t0, t0));
        assert!(!pending_is_ripe(&feature, t0, t0 + GRACE_SECONDS - 1));
        // ...and then stops waiting.
        assert!(pending_is_ripe(&feature, t0, t0 + GRACE_SECONDS));

        // A security fix never waits, even inside a feature release.
        assert!(pending_is_ripe(
            &manifest_with("\"kind\":\"feature\",\"security\":true,"),
            t0,
            t0
        ));
    }

    /// The durable half of Ready. The meta round-trips, and re-staging the
    /// SAME version keeps the original first-seen clock -- a grace period
    /// that reset on every scheduled re-check would never elapse, and the
    /// feature banner would quietly become "wait forever".
    #[test]
    fn pending_meta_round_trips_and_the_grace_clock_survives_a_recheck() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = verify_manifest(
            signed_manifest_for(Version::new(9, 9, 9), Platform::LinuxX86_64).as_bytes(),
            &dev_trusted_keys(),
        )
        .expect("must verify");
        let staged = dir.path().join("patanyx-9.9.9-linux-x86_64.bin");

        remember_pending(dir.path(), b"envelope-bytes", &staged, &manifest);
        let first = read_pending_meta(dir.path()).expect("meta must round-trip");
        assert_eq!(first.version, "9.9.9");
        assert_eq!(first.staged, "patanyx-9.9.9-linux-x86_64.bin");
        assert!(first.first_seen_unix > 0);

        // A re-check of the same version must NOT reset the clock.
        remember_pending(dir.path(), b"envelope-bytes", &staged, &manifest);
        let again = read_pending_meta(dir.path()).expect("meta must still parse");
        assert_eq!(again.first_seen_unix, first.first_seen_unix);

        // The envelope landed verbatim, and cleaning removes both files.
        assert_eq!(
            std::fs::read(pending_envelope_path(dir.path())).expect("envelope on disk"),
            b"envelope-bytes"
        );
        clean_pending(dir.path());
        assert!(read_pending_meta(dir.path()).is_none());
        assert!(!pending_envelope_path(dir.path()).exists());
    }

    /// The reader refuses a `staged` value that is anything but a bare
    /// filename. Traversal cannot install wrong bytes (the hash decides),
    /// but the startup read must not be aimable at arbitrary paths.
    #[test]
    fn a_pending_meta_naming_a_path_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        for evil in ["../../etc/hostname", "/etc/hostname", "a/b.bin"] {
            std::fs::write(
                pending_meta_path(dir.path()),
                format!(
                    "{{\"version\":\"9.9.9\",\"staged\":\"{evil}\",\"first_seen_unix\":1}}"
                ),
            )
            .expect("write meta");
            assert!(
                read_pending_meta(dir.path()).is_none(),
                "meta with staged={evil} was accepted"
            );
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
            advisory: None,
            envelope: None,
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
            advisory: None,
            envelope: None,
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
            advisory: None,
            envelope: None,
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
            advisory: None,
            envelope: None,
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
        // An older offer is not a refusal the user must read: the machine is
        // AHEAD of the server, and the panel says so calmly, naming the
        // offered version (decided 2026-09-16).
        match phase {
            Phase::Ahead { offered } => assert_eq!(offered, older),
            other => panic!("expected Ahead, got {other:?}"),
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
/// user pressed a button and is watching)". That was wrong, and hardware
/// testing found it: pressing Check now froze the whole browser -- shortcuts, tabs,
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
            // WAIT FOR THE ANSWER BEFORE REPORTING IT.
            //
            // `check_now` SPAWNS the fetch and returns immediately, so its
            // return value is `checking` in every case that matters. That
            // value was what got emitted, and the chrome deliberately does not
            // interrupt anyone for `checking` -- so the scheduled check could
            // never raise the banner, on any platform, for any release. The
            // notification half of "notify, never install" was silently
            // absent: the phase settled on this thread's sibling and nothing
            // ever told the UI.
            //
            // Polling rather than a callback because the phase lives behind
            // the same lock the panel reads, and a settled phase is the only
            // thing worth announcing. The deadline is generous: a full
            // download on a slow link is a legitimate reason to still be
            // in flight, and expiring merely reports whatever is true then.
            let mut status = check_now();
            let deadline = Instant::now() + SETTLE_TIMEOUT;
            while in_flight(&status) && Instant::now() < deadline {
                std::thread::sleep(SETTLE_POLL);
                status = self::status();
            }
            let _ = proxy.send_event(crate::UserEvent::UpdateChecked(status));
        });
}

/// True while a check has not yet reached a state worth reporting.
///
/// Named states rather than the `Phase` enum because this reads the same
/// snapshot the chrome does, so the two cannot drift apart on what "still
/// working" means.
fn in_flight(status: &Value) -> bool {
    matches!(
        status.get("state").and_then(Value::as_str),
        Some("checking") | Some("downloading")
    )
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

#[cfg(test)]
mod key_class_separation_tests {
    //! The decision of 2026-08-31 made mechanical at the KEY level.
    //!
    //! `manifest.rs` proves the other half -- that a signature in one domain
    //! cannot be replayed against another verifier. That is replay protection,
    //! and it is not the same property: a key a verifier TRUSTS can always
    //! sign a fresh message in any domain it likes. So the classes are only
    //! genuinely separated if the key SETS are disjoint, and until this module
    //! existed nothing checked that. I planted the defect -- pasted the
    //! release key into MODEL_KEYS -- and the whole suite stayed green.

    use super::{BLOCKLIST_KEYS, MODEL_KEYS, PUBLISHER_KEYS};

    /// The model feed's key authorises model-feed artifacts ONLY.
    ///
    /// Disjoint from both other classes, with no exception and no transitional
    /// entry: nothing in the field verifies a model manifest yet, so there is
    /// no compatibility debt that could justify one. If this ever fails, the
    /// separation the ruling asked for has been given away.
    #[test]
    fn the_model_key_set_is_disjoint_from_every_other_class() {
        for key in MODEL_KEYS {
            assert!(
                !PUBLISHER_KEYS.contains(key),
                "a model key must never also be a release key: {key}"
            );
            assert!(
                !BLOCKLIST_KEYS.contains(key),
                "a model key must never also be a blocklist key: {key}"
            );
        }
    }

    /// The ONE overlap that exists, pinned so it cannot grow quietly.
    ///
    /// `BLOCKLIST_KEYS` still carries the release working key, deliberately:
    /// installs already in the field verify blocklists against
    /// `PUBLISHER_KEYS`, and dropping it would silently end their refreshes.
    /// Its own comment is honest that "a release key can still sign a
    /// blocklist" until the entry goes.
    ///
    /// This test does not object to that. It objects to a SECOND one
    /// appearing, and it will fail the moment the transitional entry is
    /// removed -- which is the reminder to tighten this assertion to zero
    /// rather than a licence to leave it at one. 1.0.0 is when the field
    /// catches up and that removal becomes safe.
    #[test]
    fn the_only_cross_class_overlap_is_the_documented_transitional_key() {
        let overlap: Vec<&&str> = BLOCKLIST_KEYS
            .iter()
            .filter(|k| PUBLISHER_KEYS.contains(k))
            .collect();
        assert_eq!(
            overlap.len(),
            1,
            "expected exactly the one transitional release key in BLOCKLIST_KEYS, found {overlap:?}. \
             If this is now ZERO, delete the transitional entry's comment and change this \
             assertion to 0 -- the improvement is finally real. If it is more than one, \
             a key was shared that should not have been."
        );
    }
    /// The feed must build its strict agent in exactly ONE place.
    ///
    /// It did not. `get` grew the intercepting-proxy retry (F21) and
    /// `get_with_progress` never did, so on a corporate network the signed
    /// manifest arrived through the relaxed retry and the pack body -- same
    /// host, same feed, same integrity argument -- died on the strict agent
    /// with no second attempt. Users behind Zscaler were told the language
    /// pack server was unreachable while it answered every request.
    ///
    /// Nothing caught it because each function was correct read on its own;
    /// only the PAIR was wrong. So the invariant is now structural: one
    /// construction site, and a second one fails here.
    ///
    /// The needle is built at run time so this scan cannot match its own
    /// source. `agent_accepting_os_roots` does not match: the open paren is
    /// part of the needle.
    #[test]
    fn the_feed_builds_its_strict_agent_in_exactly_one_place() {
        const UPDATER_RS: &str = include_str!("updater.rs");
        let needle = format!("crate::net::{}(", "agent");
        let sites = UPDATER_RS.matches(needle.as_str()).count();
        assert_eq!(
            sites, 1,
            "the strict agent is constructed at {sites} sites in updater.rs. \
             Every feed fetch must go through call_strict_then_os_roots, or \
             one path silently loses the intercepting-proxy retry the other \
             has -- which is exactly how the pack body broke for corporate \
             users while the manifest kept working."
        );
    }

}

#[cfg(test)]
mod engine_floor_tests {
    use super::tests::{dev_signing_key, dev_trusted_keys, payload_json, sign_with};
    use super::{
        raise_engine_floors, remember_engine_floors, run_check_observed, FetchError, Phase, FLOOR,
    };
    use patanyx_update::{verify_manifest, Platform, Version};
    use serde_json::json;

    const V: &str = "2.10.0";

    fn manifest_with(floor: &str) -> patanyx_update::Manifest {
        let base = payload_json(V, "linux-x86_64", 47);
        let payload = base.replace(
            ",\"published_at\"",
            &format!(",\"engine_floor\":{floor},\"published_at\""),
        );
        assert_ne!(payload, base, "payload_json changed shape; the splice missed");
        let envelope = sign_with(&payload, &dev_signing_key());
        verify_manifest(envelope.as_bytes(), &dev_trusted_keys()).expect("must verify")
    }

    /// A signed floor only ever rises. The manifest `decide` accepts as
    /// "up to date" may be older than one already seen, and it must not
    /// drag the floor back down with it.
    #[test]
    fn a_signed_floor_rises_and_never_falls() {
        let m = manifest_with("{\"webview2\":\"152.0.4191.62\",\"webkitgtk\":\"2.52.5\"}");
        let first = raise_engine_floors(&json!(null), m.engine_floors()).expect("rose");
        assert_eq!(first["webview2"], json!([152, 0, 4191, 62]));
        assert_eq!(first["webkitgtk"], json!([2, 52, 5]));

        let older = manifest_with("{\"webview2\":\"152.0.4191.53\"}");
        assert!(raise_engine_floors(&first, older.engine_floors()).is_none());
        let same = manifest_with("{\"webview2\":\"152.0.4191.62\"}");
        assert!(raise_engine_floors(&first, same.engine_floors()).is_none());

        let newer = manifest_with("{\"webview2\":\"153.0.4234.6\"}");
        let second = raise_engine_floors(&first, newer.engine_floors()).expect("rose");
        assert_eq!(second["webview2"], json!([153, 0, 4234, 6]));
        // The engine the newer manifest said nothing about keeps its floor.
        assert_eq!(second["webkitgtk"], json!([2, 52, 5]));

        let none = manifest_with("{}");
        assert!(raise_engine_floors(&second, none.engine_floors()).is_none());
    }

    /// The observed check hands EVERY verified manifest to the observer, and
    /// nothing that fails verification. Pinned through the real pipeline.
    #[test]
    fn only_verified_manifests_reach_the_floor_observer() {
        let current = Version::new(2, 10, 0);
        let mut seen = 0;
        let good = sign_with(&payload_json(V, "linux-x86_64", 47), &dev_signing_key());
        // Same version as current: decide says UpToDate, and the observer
        // must still have been called -- that is the whole point.
        let _ = run_check_observed(
            &dev_trusted_keys(),
            &FLOOR,
            current,
            Platform::LinuxX86_64,
            || Ok(good.into_bytes()),
            |_| seen += 1,
        );
        assert_eq!(seen, 1);

        let forged = payload_json(V, "linux-x86_64", 47);
        let mut seen_forged = 0;
        let _ = run_check_observed(
            &dev_trusted_keys(),
            &FLOOR,
            current,
            Platform::LinuxX86_64,
            || {
                Ok(format!(
                    "{{\"v\":1,\"payload\":{},\"sig\":\"00\"}}",
                    serde_json::to_string(&forged).unwrap()
                )
                .into_bytes())
            },
            |_| seen_forged += 1,
        );
        assert_eq!(seen_forged, 0, "an unverified manifest reached the observer");
    }

    #[test]
    fn remembering_writes_the_file_and_a_manifest_without_floors_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("patanyx-engine-floor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(remember_engine_floors(&dir, &manifest_with("{}")).unwrap(), false);
        assert!(!super::engine_floor_path(&dir).exists());
        assert_eq!(
            remember_engine_floors(&dir, &manifest_with("{\"webview2\":\"152.0.4191.62\"}")).unwrap(),
            true
        );
        let raw = std::fs::read_to_string(super::engine_floor_path(&dir)).expect("written");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&raw).unwrap()["webview2"], json!([152, 0, 4191, 62]));
        // A replay does not rewrite; a write that cannot happen is reported
        // and leaves the file exactly as it was.
        assert_eq!(
            remember_engine_floors(&dir, &manifest_with("{\"webview2\":\"152.0.4191.62\"}")).unwrap(),
            false
        );
        let blocked = dir.join("blocked");
        std::fs::write(&blocked, b"a file where a directory is needed").unwrap();
        let err = remember_engine_floors(&blocked, &manifest_with("{\"webview2\":\"152.0.4191.66\"}"));
        assert!(err.is_err(), "a failed register write must be observable");
        assert_eq!(
            std::fs::read_to_string(super::engine_floor_path(&dir)).unwrap(),
            raw,
            "last-good bytes intact"
        );
        // No temp file survives.
        assert!(std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// STRICT LEGACY CONVERSION. A stored field that does not fit u32 is not
    /// truncated into a small number the signed floor then "beats": it is
    /// treated as absent, and the signed value replaces it. Before this the
    /// conversion was `as u32`.
    #[test]
    fn a_stored_field_that_does_not_fit_is_absent_not_truncated() {
        let m = manifest_with("{\"webview2\":\"152.0.4191.66\"}");
        // 4294967302 as u32 would be 6, which is below 66 -- a truncating
        // reader would "raise" a register that actually holds an absurd
        // value; a strict reader replaces it.
        let absurd = json!({"webview2": [152u64, 0, 4191, 4_294_967_302u64]});
        let doc = raise_engine_floors(&absurd, m.engine_floors()).expect("replaced");
        assert_eq!(doc["webview2"], json!([152, 0, 4191, 66]));
        // And a genuinely higher stored value is kept.
        let higher = json!({"webview2": [152, 0, 4191, 70]});
        assert!(raise_engine_floors(&higher, m.engine_floors()).is_none());
    }

    /// THE ADVISORY RIDES ON THE SAME CHECK, INDEPENDENTLY. Whatever the
    /// release check concluded -- up to date with no app release, refused,
    /// failed at the network -- the advisory observer still runs. Pinned
    /// through the function the worker thread calls.
    #[test]
    fn the_advisory_check_runs_after_every_release_outcome() {
        use super::{observe_advisory_after, Phase};
        use crate::engine_advisory::AdvisoryOutcome;
        let phases = [
            Phase::UpToDate,
            Phase::Failed { detail: "unreachable".into(), resume: None },
            Phase::Refused { reason: "forged".into(), offered: None },
            Phase::Idle,
            Phase::Checking,
        ];
        for phase in &phases {
            let mut ran = false;
            let out = observe_advisory_after(phase, || {
                ran = true;
                AdvisoryOutcome::Raised { floor: [152, 0, 4191, 66] }
            });
            assert!(ran, "the advisory must run after {phase:?}");
            assert_eq!(out, AdvisoryOutcome::Raised { floor: [152, 0, 4191, 66] });
        }
    }

    /// SAME-VERSION APP CHECK and FAILED APP CHECK, end to end through the
    /// real verifiers: the release manifest is up to date (no app release)
    /// or unreachable, and the advisory still lands in its own register and
    /// raises the effective floor above the compiled one.
    #[test]
    fn a_same_version_or_failed_app_check_still_delivers_the_advisory() {
        use crate::engine_advisory::testkit::{signed, trusted, SEED_ADVISORY_A};
        use crate::engine_advisory::{persisted_floor_with, run_advisory_check, AdvisoryOutcome};
        let dir = std::env::temp_dir().join(format!("patanyx-advisory-pair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let compiled = [152u32, 0, 4191, 62];
        let now = 1_757_600_000;

        // Same version: the release check says up to date and observes no floor.
        let current = Version::new(2, 10, 0);
        let good = sign_with(&payload_json(V, "linux-x86_64", 47), &dev_signing_key());
        let phase = run_check_observed(
            &dev_trusted_keys(),
            &FLOOR,
            current,
            Platform::LinuxX86_64,
            || Ok(good.into_bytes()),
            |m| assert!(m.engine_floors().is_empty()),
        );
        assert!(matches!(phase, Phase::UpToDate));
        let advisory = super::observe_advisory_after(&phase, || {
            run_advisory_check(
                Ok(trusted(&[&SEED_ADVISORY_A])),
                || Ok(signed("152.0.4191.66", now - 1000, &SEED_ADVISORY_A)),
                &dir,
                &compiled,
                now,
            )
        });
        assert_eq!(advisory, AdvisoryOutcome::Raised { floor: [152, 0, 4191, 66] });

        // Failed app check: the release fetch is unreachable; the advisory
        // fetch is a separate closure and still succeeds with a higher floor.
        let phase = run_check_observed(
            &dev_trusted_keys(),
            &FLOOR,
            current,
            Platform::LinuxX86_64,
            || Err(FetchError::Network("unreachable".into())),
            |_| panic!("nothing verified"),
        );
        assert!(matches!(phase, Phase::Failed { .. }));
        let advisory = super::observe_advisory_after(&phase, || {
            run_advisory_check(
                Ok(trusted(&[&SEED_ADVISORY_A])),
                || Ok(signed("152.0.4191.70", now - 500, &SEED_ADVISORY_A)),
                &dir,
                &compiled,
                now,
            )
        });
        assert_eq!(advisory, AdvisoryOutcome::Raised { floor: [152, 0, 4191, 70] });

        // The effective floor now rests on the advisory register alone: no
        // release floor was ever persisted here.
        let advisory_floor = persisted_floor_with(&dir, &trusted(&[&SEED_ADVISORY_A]), &compiled, now);
        assert_eq!(advisory_floor, Some([152, 0, 4191, 70]));
        assert!(!super::engine_floor_path(&dir).exists());
        let effective = crate::platform::effective_floor_from(
            &compiled,
            None,
            advisory_floor.map(|f| f.to_vec()),
        );
        assert_eq!(effective, vec![152, 0, 4191, 70]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod advisory_key_tests {
    //! The advisory key list, pinned in BOTH directions: disjoint from every
    //! other class, and EMPTY until the lander provisions it -- so nothing in
    //! this tree can be read as an active advisory channel.
    use super::{ADVISORY_KEYS, BLOCKLIST_KEYS, MODEL_KEYS, PUBLISHER_KEYS};

    /// A stolen advisory key must not be a key any other verifier trusts.
    /// Domain separation stops replay; only disjoint key SETS stop forgery.
    #[test]
    fn the_advisory_key_set_is_disjoint_from_every_other_class() {
        for key in ADVISORY_KEYS {
            assert!(!PUBLISHER_KEYS.contains(key), "advisory key is a release key: {key}");
            assert!(!BLOCKLIST_KEYS.contains(key), "advisory key is a blocklist key: {key}");
            assert!(!MODEL_KEYS.contains(key), "advisory key is a model key: {key}");
        }
    }

    /// PROVISIONED: exactly one real key, and the channel is configured.
    ///
    /// This test was the visible marker of the missing production
    /// configuration while `ADVISORY_KEYS` was empty; it flipped in the
    /// provisioning commit. It now pins that the list holds exactly ONE
    /// entry, that the entry is a well-formed, non-weak Ed25519 key the
    /// verifier constructs from, and that it is the production key rather
    /// than any test seed's verifying key. A second entry is a rotation and
    /// must be added deliberately here as well.
    #[test]
    fn advisory_keys_hold_exactly_one_real_provisioned_key() {
        assert_eq!(ADVISORY_KEYS.len(), 1, "one advisory key; rotation adds a second deliberately");
        let key = ADVISORY_KEYS[0];
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!key.chars().all(|c| c == '0'), "the all-zeros placeholder is not a key");
        let keys = super::advisory_trusted_keys().expect("the compiled advisory key must construct");
        assert_eq!(keys.len(), 1);
        // Not the verifying key of any test seed used in this crate.
        for seed in [
            crate::engine_advisory::testkit::SEED_ADVISORY_A,
            crate::engine_advisory::testkit::SEED_ADVISORY_B,
            crate::engine_advisory::testkit::SEED_ATTACKER,
            super::DEV_SIGNING_SEED,
        ] {
            let test_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            assert_ne!(
                patanyx_update::hex::encode(test_key.as_bytes()),
                key,
                "a TEST key must never be the production advisory key"
            );
        }
        // And the placeholder shape is refused if someone pastes it.
        assert!(patanyx_update::TrustedKeys::from_hex(&[&"0".repeat(64)]).is_err());
    }
}
