//! patanyx-update — verification and decision core for the signed update
//! channel of PATANYX Browser.
//!
//! Pure logic: bytes in, decisions out. There is no networking here, no
//! filesystem, no clock, and no platform-specific code, so every property is
//! testable offline. The caller fetches bytes however it sees fit; this
//! crate decides whether those bytes may run.
//!
//! # The two problems this exists to solve at once
//!
//! **Authenticity.** Anyone who can serve bytes to a user must not be able
//! to make those bytes run. Every release is described by a manifest signed
//! with Ed25519 by the publisher; the verifying keys are compiled into the
//! binary, because a key fetched over the network authenticates nothing —
//! whoever can substitute the update can substitute the key. A signature is
//! the right primitive here and an HMAC would not be: the verifier (the
//! user's machine) is a third party that must check a claim BY the publisher
//! without sharing a secret with it.
//!
//! **Not becoming surveillance.** An update check is a request to a server,
//! and a request is data about a user. The next section is written to be
//! quoted, not summarized.
//!
//! # What an update check unavoidably reveals
//!
//! HTTPS hides content, not existence. However this crate is used, the
//! update server — and the network path to it — learns two things:
//!
//! - an **IP address**, which locates the user roughly, and
//! - a **timestamp**, which says when the machine is awake.
//!
//! That is the honest minimum, and this design adds NOTHING to it. The check
//! carries no install identifier, no token, no counters, and no machine
//! fingerprint. It does not even carry the running version: the comparison
//! that answers "is there something newer" happens locally, in [`decide`],
//! against the same manifest every other install of the platform just
//! fetched. The manifest URL is identical for every install of a platform,
//! so the response is CDN-cacheable — which also means fewer machines see
//! the request at all.
//!
//! The fetch layer (written elsewhere) owes these properties, stated here so
//! they get reviewed against:
//!
//! - one plain unconditional GET: no cookies, no authorization, and no
//!   `If-Modified-Since` / `If-None-Match` — a cache validator is a
//!   server-chosen string the client echoes back, which is a cookie with
//!   extra steps;
//! - TLS for both the manifest and the payload (this crate refuses a
//!   manifest whose payload URL is not https);
//! - checks on a jittered schedule, so "when the machine is awake"
//!   correlates less tightly with "when the checks happen".
//!
//! # Freshness: considered, documented, deliberately not built
//!
//! Rollback protection here is version-monotonic: [`decide`] never accepts a
//! version lower than or equal to the running one, so replaying yesterday's
//! manifest to a user who already updated achieves nothing. The residual
//! attack is against a user who has NOT yet updated: serve last week's
//! legitimately signed 2.10.0 to a 2.9.0 user while a fixed 2.11.0 exists,
//! and the user "updates" into a build with known holes — over a valid
//! signature.
//!
//! A freshness bound (refuse manifests whose `published_at` is older than N
//! days, or implausibly far in the future) closes that, at the price of
//! coupling updates to a clock and of update outages when the publisher is
//! quiet longer than N days. It is not built here on purpose: `published_at`
//! is already inside the signed payload, so the bound can be added inside
//! [`decide`] later with NO format change, and picking N is a product
//! decision, not a cryptographic one.
//!
//! # Why there is no zeroizing here
//!
//! The vault wipes keys because it holds secrets. This crate holds none:
//! public keys, published manifests, payload hashes. The signing key never
//! exists on a user machine. Wiping public data would be theater, and
//! theater is how real hygiene gets skipped.
//!
//! # Flow
//!
//! ```no_run
//! use patanyx_update::{
//!     decide, verify_manifest, verify_payload, Decision, Platform, RunningEngine, TrustedKeys,
//!     Version,
//! };
//!
//! // Compiled into the binary; placeholder hex stands in for the publisher's
//! // Ed25519 verifying keys. More than one, so keys can rotate (see
//! // `TrustedKeys`).
//! const PUBLISHER_KEYS: &[&str] = &[
//!     "0000000000000000000000000000000000000000000000000000000000000000",
//!     "1111111111111111111111111111111111111111111111111111111111111111",
//! ];
//! const FLOOR: Version = Version::new(0, 0, 0); // raise to retire a known-bad release
//!
//! fn on_check_response(
//!     bytes: &[u8],
//!     current: Version,
//!     platform: Platform,
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let keys = TrustedKeys::from_hex(PUBLISHER_KEYS)?;
//!     // Err here means "not authentic": bad signature and untrusted key are
//!     // deliberately the same error.
//!     let manifest = verify_manifest(bytes, &keys)?;
//!     match decide(&current, &FLOOR, platform, &RunningEngine::UNGATED, &manifest) {
//!         Decision::UpToDate => {}
//!         // A refusal is a security event; the reason is for the UI to show.
//!         Decision::Refused(why) => eprintln!("update refused: {why}"),
//!         Decision::Update(m) => {
//!             let payload: Vec<u8> = todo!("fetch(m.url()) — fetch layer is written elsewhere");
//!             // Err: do not install. There is no "probably".
//!             verify_payload(&payload, &m)?;
//!             // Hand off to the platform installer — written elsewhere.
//!         }
//!     }
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]

mod advisory;
mod delta;
mod error;
mod keys;
mod manifest;
mod payload;
mod version;

/// Hex, public because PUBLISHER TOOLING needs it (see
/// `examples/patanyx-sign.rs`): a key is pasted into source as hex and a
/// signature is published as hex, so the signer and the verifier must agree on
/// the encoding. Nothing here is secret -- it encodes public keys, signatures
/// and hashes.
pub mod hex;

pub use advisory::{
    verify_advisory_manifest, AdvisoryManifest, MAX_FUTURE_SECONDS as ADVISORY_MAX_FUTURE_SECONDS,
    MAX_MAJOR_AHEAD as ADVISORY_MAX_MAJOR_AHEAD, SIGNING_DOMAIN_ADVISORY,
};
pub use delta::{apply_delta, compress as compress_delta};
pub use error::UpdateError;
pub use keys::TrustedKeys;
pub use manifest::{
    verify_blocklist_manifest, verify_manifest, verify_manifest_linux_v2, verify_model_manifest,
    BlocklistManifest, Delta, EngineFloors, Manifest, ModelManifest, Platform, ReleaseKind,
    MAX_BLOCKLIST_BYTES, MAX_MODEL_PACK_BYTES, SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST,
    SIGNING_DOMAIN_LINUX_V2, SIGNING_DOMAIN_MODELS,
};
pub use payload::{verify_blocklist_bytes, verify_model_bytes, verify_payload};
pub use version::Version;

use std::fmt;

/// What the user may do next, given a verified manifest.
///
/// `Refused` carries a precise reason on purpose. Verification FAILURES are
/// coarse so they cannot be probed as an oracle; refusals are policy, not
/// cryptography, and refusing an update is a security event the user
/// deserves to see, not something to swallow silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The offered version IS the running version; there is nothing to do.
    UpToDate,
    /// Newer than the running version, at or above the floor, built for this
    /// platform, and the manifest's signature has already verified. The
    /// downloaded bytes must still pass [`verify_payload`] before anything
    /// installs.
    Update(Manifest),
    /// The manifest is authentic but must not be installed. The reason is
    /// written for the UI to show.
    Refused(RefusalReason),
}

/// Why an authentic manifest was refused. Shown to the user; written
/// accordingly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// Older than the running version. This is the rollback attack: serving
    /// an OLD, legitimately signed release with known holes needs no key at
    /// all, which is exactly why the signature cannot be the only check.
    NotNewer { offered: Version, running: Version },
    /// Below the compiled-in floor: a release the publisher has retired as
    /// known-bad, refused even with a perfect signature.
    BelowFloor { offered: Version, floor: Version },
    /// Built for a different platform than the one running.
    WrongPlatform { offered: Platform, running: Platform },
    /// The release needs a newer web engine than this machine has, and on
    /// this engine a release refuses to start below its floor. Installing it
    /// would replace a working browser with one that does not open.
    EngineTooOld {
        offered: Version,
        engine: String,
        needed: Vec<u32>,
        running: Vec<u32>,
    },
    /// The release names an engine requirement, but this machine's engine
    /// version could not be read at the precision the requirement needs.
    /// Unknown is refused here (unlike the banner, which stays quiet): the
    /// cost of guessing wrong is a browser that does not start.
    EngineUnknown {
        offered: Version,
        engine: String,
        needed: Vec<u32>,
    },
    /// The release names NO requirement for this engine, where one is
    /// required before installing. A publishing mistake, refused rather than
    /// trusted: the release might not start here.
    EngineRequirementMissing { offered: Version, engine: String },
}

/// `[2, 54, 0]` as "2.54.0".
fn join_fields(fields: &[u32]) -> String {
    fields
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefusalReason::NotNewer { offered, running } => write!(
                f,
                "the update server offered version {offered}, but this machine already runs the \
                 newer {running}; refusing to downgrade"
            ),
            RefusalReason::BelowFloor { offered, floor } => write!(
                f,
                "version {offered} has been withdrawn as unsafe to run (the oldest version still \
                 accepted is {floor}); refusing to install it"
            ),
            RefusalReason::WrongPlatform { offered, running } => write!(
                f,
                "this update was built for {offered}, but this installation is {running}; \
                 refusing to install it"
            ),
            RefusalReason::EngineTooOld {
                offered,
                engine,
                needed,
                running,
            } => write!(
                f,
                "PATANYX {offered} needs {engine} {needed} or newer, and this computer has \
                 {running}; update the system, then PATANYX can install it",
                needed = join_fields(needed),
                running = join_fields(running),
            ),
            RefusalReason::EngineUnknown {
                offered,
                engine,
                needed,
            } => write!(
                f,
                "PATANYX {offered} needs {engine} {needed} or newer, and this computer's \
                 {engine} version could not be read; it was not installed",
                needed = join_fields(needed),
            ),
            RefusalReason::EngineRequirementMissing { offered, engine } => write!(
                f,
                "the update to {offered} does not say which {engine} version it needs, so it \
                 was not installed"
            ),
        }
    }
}

/// The web engine this installation runs on, as far as an update needs to know.
///
/// On WebKitGTK a release build refuses to start below its compiled engine
/// floor, so an update whose floor this machine does not meet would replace a
/// working browser with one that never opens. `gates_install` says whether that
/// is true for this engine; WebView2 updates itself and a below-floor runtime
/// still starts, so it does not gate.
#[derive(Debug, Clone, Copy)]
pub struct RunningEngine<'a> {
    /// The name the manifest's `engine_floor` keys on ("WebKitGTK", "WebView2").
    pub name: &'a str,
    /// Every numeric field the engine reports, in order; `None` when it could
    /// not be read.
    pub version: Option<&'a [u32]>,
    /// Whether an engine below the offered release's floor stops the install.
    pub gates_install: bool,
}

impl RunningEngine<'static> {
    /// No engine gate: Windows, and every test that is not about engines.
    pub const UNGATED: RunningEngine<'static> = RunningEngine {
        name: "",
        version: None,
        gates_install: false,
    };
}

/// Does `found` meet `needed`? Compared field by field from the left over the
/// fields `needed` has. `None` when `found` has fewer fields than that: the
/// version is unknown at the precision the requirement needs.
pub fn engine_meets(found: &[u32], needed: &[u32]) -> Option<bool> {
    if found.len() < needed.len() {
        return None;
    }
    for (have, want) in found.iter().zip(needed) {
        if have != want {
            return Some(have > want);
        }
    }
    Some(true)
}

/// The engine half of `decide`, for an update that would otherwise install:
/// `None` when the engine allows it, the refusal when it does not. Public so
/// the installer can ask the same question again immediately before it
/// replaces the running binary.
pub fn engine_refusal(engine: &RunningEngine<'_>, manifest: &Manifest) -> Option<RefusalReason> {
    if !engine.gates_install {
        return None;
    }
    let offered = manifest.version();
    let Some(needed) = manifest.engine_floors().for_engine(engine.name) else {
        return Some(RefusalReason::EngineRequirementMissing {
            offered,
            engine: engine.name.to_string(),
        });
    };
    let unknown = || RefusalReason::EngineUnknown {
        offered,
        engine: engine.name.to_string(),
        needed: needed.to_vec(),
    };
    let Some(found) = engine.version else {
        return Some(unknown());
    };
    match engine_meets(found, needed) {
        Some(true) => None,
        Some(false) => Some(RefusalReason::EngineTooOld {
            offered,
            engine: engine.name.to_string(),
            needed: needed.to_vec(),
            running: found.to_vec(),
        }),
        None => Some(unknown()),
    }
}

/// Version policy: given an ALREADY VERIFIED manifest, may it be installed?
///
/// `floor` is the compiled-in minimum: any version below it is refused even
/// when correctly signed, which is how a known-bad release is permanently
/// retired. `running` is the platform of THIS build; it is a parameter (not
/// a separate check the caller might forget) so that an authentic manifest
/// for the wrong platform is refused rather than downloaded and failed
/// later.
///
/// The branch order only chooses WHICH honest reason the user sees; every
/// non-update branch refuses.
///
/// `engine` is checked LAST, so it can only ever stop something that would
/// otherwise install: an up-to-date or older offer is reported as exactly
/// that, never as an engine problem.
pub fn decide(
    current: &Version,
    floor: &Version,
    running: Platform,
    engine: &RunningEngine<'_>,
    manifest: &Manifest,
) -> Decision {
    if manifest.platform() != running {
        return Decision::Refused(RefusalReason::WrongPlatform {
            offered: manifest.platform(),
            running,
        });
    }
    if manifest.version() < *floor {
        return Decision::Refused(RefusalReason::BelowFloor {
            offered: manifest.version(),
            floor: *floor,
        });
    }
    if manifest.version() == *current {
        return Decision::UpToDate;
    }
    if manifest.version() < *current {
        return Decision::Refused(RefusalReason::NotNewer {
            offered: manifest.version(),
            running: *current,
        });
    }
    if let Some(why) = engine_refusal(engine, manifest) {
        return Decision::Refused(why);
    }
    Decision::Update(manifest.clone())
}

#[cfg(test)]
pub(crate) mod testutil {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use crate::hex;
    use crate::manifest::{Manifest, SIGNING_DOMAIN};
    use crate::TrustedKeys;

    /// Fixed seeds rather than an RNG: tests must be deterministic, and any
    /// 32 bytes are a valid Ed25519 secret seed, so no rand dependency is
    /// needed even for tests.
    pub const SEED_TRUSTED_A: u8 = 0xA1;
    pub const SEED_TRUSTED_B: u8 = 0xB2;
    pub const SEED_ATTACKER: u8 = 0xE5;

    /// The bytes a test release "contains".
    pub const BINARY: &[u8] = b"patanyx test binary: the quick brown fox";

    pub fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub fn trusted_keys() -> TrustedKeys {
        TrustedKeys::new(vec![signing_key(SEED_TRUSTED_A).verifying_key()])
            .expect("one key is a valid set")
    }

    pub fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(&Sha256::digest(bytes))
    }

    /// A payload document as compact JSON. Built by string formatting — not
    /// by serializing a typed struct — precisely so tests can also produce
    /// INVALID versions and platforms, which a typed builder would forbid.
    pub fn payload_json(
        version: &str,
        platform: &str,
        url: &str,
        sha256: &str,
        size: u64,
        published_at: u64,
    ) -> String {
        format!(
            "{{\"version\":\"{version}\",\"platform\":\"{platform}\",\"url\":\"{url}\",\
             \"sha256\":\"{sha256}\",\"size\":{size},\"published_at\":{published_at}}}"
        )
    }

    pub fn good_payload() -> String {
        payload_json(
            "2.10.0",
            "linux-x86_64",
            "https://updates.patanyx.example/releases/patanyx-2.10.0-linux-x86_64",
            &sha256_hex(BINARY),
            BINARY.len() as u64,
            1_735_689_600, // 2025-01-01T00:00:00Z
        )
    }

    /// Wrap a payload in a signed v1 envelope. This is the EXACT construction
    /// publisher tooling must reproduce: Ed25519 over
    /// `SIGNING_DOMAIN || payload-bytes`, hex-encoded, with the payload
    /// embedded as a JSON string so the signed bytes survive verbatim.
    pub fn sign(payload: &str, key: &SigningKey) -> String {
        let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + payload.len());
        message.extend_from_slice(SIGNING_DOMAIN);
        message.extend_from_slice(payload.as_bytes());
        let signature = key.sign(&message);
        format!(
            "{{\"v\":1,\"payload\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(payload).expect("a string always serializes"),
            hex::encode(&signature.to_bytes())
        )
    }

    /// A signature over the BARE payload, with no domain separation: what a
    /// different protocol might legitimately produce. Must not verify here.
    pub fn sign_undomained(payload: &str, key: &SigningKey) -> String {
        let signature = key.sign(payload.as_bytes());
        format!(
            "{{\"v\":1,\"payload\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(payload).expect("a string always serializes"),
            hex::encode(&signature.to_bytes())
        )
    }

    /// Sign and verify a manifest for the given version, panicking if the
    /// trusted pipeline rejects it — the failure mode of any test using this
    /// helper is that verification itself broke.
    pub fn manifest_for(version: &str, platform: &str) -> Manifest {
        let payload = payload_json(
            version,
            platform,
            "https://updates.patanyx.example/x",
            &sha256_hex(BINARY),
            BINARY.len() as u64,
            1_735_689_600,
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        crate::verify_manifest(envelope.as_bytes(), &trusted_keys())
            .expect("test manifest must verify")
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::hex;

    fn v(s: &str) -> Version {
        s.parse().expect("literal test version")
    }

    // ---- authenticity ----

    #[test]
    fn valid_manifest_verifies_and_fields_roundtrip() {
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        let m = verify_manifest(envelope.as_bytes(), &trusted_keys()).expect("must verify");
        assert_eq!(m.version(), v("2.10.0"));
        assert_eq!(m.platform(), Platform::LinuxX86_64);
        assert_eq!(
            m.url(),
            "https://updates.patanyx.example/releases/patanyx-2.10.0-linux-x86_64"
        );
        assert_eq!(hex::encode(m.sha256()), sha256_hex(BINARY));
        assert_eq!(m.size(), BINARY.len() as u64);
        assert_eq!(m.published_at(), 1_735_689_600);
    }

    #[test]
    fn a_payload_with_deltas_parses_and_the_lookup_matches_by_from_hash() {
        let old_hash = "11".repeat(32);
        let delta_hash = "22".repeat(32);
        let payload = good_payload().replace(
            ",\"published_at\"",
            &format!(
                ",\"deltas\":[{{\"from\":\"{old_hash}\",\"url\":\"https://updates.patanyx.example/d/1\",\"sha256\":\"{delta_hash}\",\"size\":7}}],\"published_at\""
            ),
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        let m = verify_manifest(envelope.as_bytes(), &trusted_keys()).expect("must verify");
        assert_eq!(m.deltas().len(), 1);
        let from = hex::decode_32(&old_hash).unwrap();
        let d = m.delta_from(&from).expect("lookup by from-hash");
        assert_eq!(d.size(), 7);
        assert_eq!(hex::encode(d.sha256()), delta_hash);
        assert!(m.delta_from(&[0u8; 32]).is_none());
    }

    /// The engine floor rides inside the signature, so only the publisher
    /// can raise it; old manifests carry none; and the precision is exact,
    /// because a three-field WebView2 floor would compare at the wrong depth
    /// and call the exposed .53 and the fixed .62 the same runtime.
    #[test]
    fn the_engine_floor_is_signed_optional_and_exact_in_precision() {
        let with = |floor: &str| {
            let payload = good_payload().replace(
                ",\"published_at\"",
                &format!(",\"engine_floor\":{floor},\"published_at\""),
            );
            let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
            verify_manifest(envelope.as_bytes(), &trusted_keys())
        };
        let plain = verify_manifest(
            sign(&good_payload(), &signing_key(SEED_TRUSTED_A)).as_bytes(),
            &trusted_keys(),
        )
        .expect("must verify");
        assert!(plain.engine_floors().is_empty());

        let both = with("{\"webview2\":\"152.0.4191.62\",\"webkitgtk\":\"2.52.5\"}")
            .expect("must verify");
        assert_eq!(both.engine_floors().webview2(), Some(&[152, 0, 4191, 62][..]));
        assert_eq!(both.engine_floors().webkitgtk(), Some(&[2, 52, 5][..]));
        assert_eq!(both.engine_floors().for_engine("WebView2"), Some(&[152, 0, 4191, 62][..]));
        assert_eq!(both.engine_floors().for_engine("Other"), None);

        let only_one = with("{\"webview2\":\"153.0.4234.6\"}").expect("must verify");
        assert_eq!(only_one.engine_floors().webkitgtk(), None);

        for bad in [
            "{\"webview2\":\"152.0.4191\"}",
            "{\"webkitgtk\":\"2.52.5.1\"}",
            "{\"webview2\":\"152.0.4191.beta\"}",
            "{\"webview2\":\"\"}",
            "{\"blink\":\"1.2.3.4\"}",
        ] {
            assert!(with(bad).is_err(), "accepted a malformed engine floor: {bad}");
        }
    }

    /// THE SILENT-INSTALL POLICY, pinned. `installs_silently` is the one
    /// place that decides whether a release may replace the browser without
    /// telling anyone first, so every combination is asserted here rather
    /// than inferred at the call site.
    #[test]
    fn only_an_unannounced_feature_release_waits_and_a_security_fix_never_does() {
        let kinds = |kind: &str, security: bool| {
            let payload = good_payload().replace(
                ",\"published_at\"",
                &format!(",\"kind\":\"{kind}\",\"security\":{security},\"published_at\""),
            );
            let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
            verify_manifest(envelope.as_bytes(), &trusted_keys()).expect("must verify")
        };

        // Maintenance: the quiet path, with or without a fix in it.
        assert!(kinds("maintenance", false).installs_silently());
        assert!(kinds("maintenance", true).installs_silently());

        // A feature release is announced and waits for the user...
        let feature = kinds("feature", false);
        assert_eq!(feature.release_kind(), ReleaseKind::Feature);
        assert!(!feature.installs_silently());

        // ...UNLESS it carries a security fix, which must never sit behind a
        // banner nobody clicked. This is the whole reason `security` is a
        // separate field rather than a third kind.
        let urgent = kinds("feature", true);
        assert_eq!(urgent.release_kind(), ReleaseKind::Feature);
        assert!(urgent.security());
        assert!(urgent.installs_silently());
    }

    /// Backward compatibility, and it is load-bearing: every manifest already
    /// published (0.9.65 among them) carries neither field. Reading those as
    /// "maintenance, no security fix" is what keeps them installing exactly
    /// as they always have instead of stalling behind a banner for a feature
    /// nobody announced.
    #[test]
    fn a_manifest_without_the_new_fields_reads_as_quiet_maintenance() {
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        let m = verify_manifest(envelope.as_bytes(), &trusted_keys()).expect("must verify");
        assert_eq!(m.release_kind(), ReleaseKind::Maintenance);
        assert!(!m.security());
        assert!(m.installs_silently());
    }

    #[test]
    fn a_delta_no_smaller_than_the_release_refuses_the_manifest() {
        // size == full payload size: not a delta, a publisher mistake, and
        // it must be loud rather than silently skipped.
        let payload = good_payload().replace(
            ",\"published_at\"",
            &format!(
                ",\"deltas\":[{{\"from\":\"{}\",\"url\":\"https://updates.patanyx.example/d/1\",\"sha256\":\"{}\",\"size\":{}}}],\"published_at\"",
                "11".repeat(32),
                "22".repeat(32),
                BINARY.len()
            ),
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        let err = verify_manifest(envelope.as_bytes(), &trusted_keys()).unwrap_err();
        assert!(matches!(err, UpdateError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_delta_claiming_to_patch_the_release_itself_refuses_the_manifest() {
        let payload = good_payload().replace(
            ",\"published_at\"",
            &format!(
                ",\"deltas\":[{{\"from\":\"{}\",\"url\":\"https://updates.patanyx.example/d/1\",\"sha256\":\"{}\",\"size\":7}}],\"published_at\"",
                sha256_hex(BINARY),
                "22".repeat(32),
            ),
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        let err = verify_manifest(envelope.as_bytes(), &trusted_keys()).unwrap_err();
        assert!(matches!(err, UpdateError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn tampered_version_field_fails_verification() {
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        // The payload lives inside the envelope as an escaped JSON string;
        // the version digits themselves are not escaped, so replacing them
        // edits the signed bytes in place.
        let tampered = envelope.replace("2.10.0", "2.11.0");
        assert_ne!(tampered, envelope);
        let err = verify_manifest(tampered.as_bytes(), &trusted_keys()).unwrap_err();
        assert!(matches!(err, UpdateError::BadSignature), "got {err:?}");
    }

    #[test]
    fn tampered_url_field_fails_verification() {
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        let tampered = envelope.replace("updates.patanyx.example", "updates.evil.example");
        assert_ne!(tampered, envelope);
        let err = verify_manifest(tampered.as_bytes(), &trusted_keys()).unwrap_err();
        assert!(matches!(err, UpdateError::BadSignature), "got {err:?}");
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        // Flip the first signature hex digit to a DIFFERENT valid hex digit:
        // the envelope still parses, and the signature must still not verify.
        let pos = envelope.find("\"sig\":\"").expect("envelope has a sig") + 7;
        let mut bytes = envelope.into_bytes();
        bytes[pos] = if bytes[pos] == b'0' { b'1' } else { b'0' };
        let err = verify_manifest(&bytes, &trusted_keys()).unwrap_err();
        assert!(matches!(err, UpdateError::BadSignature), "got {err:?}");
    }

    #[test]
    fn untrusted_key_is_refused_as_bad_signature() {
        let envelope = sign(&good_payload(), &signing_key(SEED_ATTACKER));
        let err = verify_manifest(envelope.as_bytes(), &trusted_keys()).unwrap_err();
        // Not "unknown key", not "wrong key": one coarse answer, so the error
        // cannot be probed for which key would have worked.
        assert!(matches!(err, UpdateError::BadSignature), "got {err:?}");
    }

    #[test]
    fn second_trusted_key_also_verifies() {
        let keys = TrustedKeys::new(vec![
            signing_key(SEED_TRUSTED_A).verifying_key(),
            signing_key(SEED_TRUSTED_B).verifying_key(),
        ])
        .expect("two keys is a valid set");
        // During a rotation window BOTH the outgoing and the incoming key
        // must verify, or installs that have not yet received the new key
        // list are stranded.
        for seed in [SEED_TRUSTED_A, SEED_TRUSTED_B] {
            let envelope = sign(&good_payload(), &signing_key(seed));
            verify_manifest(envelope.as_bytes(), &keys)
                .expect("both keys must verify during rotation");
        }
        // ...and an outside key still does not.
        let envelope = sign(&good_payload(), &signing_key(SEED_ATTACKER));
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &keys),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn signature_without_domain_separation_fails() {
        // A valid signature over the bare payload — something another
        // protocol could produce with the very same key — must not double as
        // a manifest signature.
        let envelope = sign_undomained(&good_payload(), &signing_key(SEED_TRUSTED_A));
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::BadSignature)
        ));
    }

    // ---- rollback protection ----

    #[test]
    fn lower_version_is_refused_even_when_signed() {
        // The manifest is VALIDLY SIGNED: a replayed old release is exactly
        // the attack a signature cannot stop, so decide() must.
        let m = manifest_for("2.9.0", "linux-x86_64");
        match decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &RunningEngine::UNGATED, &m) {
            Decision::Refused(RefusalReason::NotNewer { offered, running }) => {
                assert_eq!(offered, v("2.9.0"));
                assert_eq!(running, v("2.10.0"));
            }
            other => panic!("expected NotNewer refusal, got {other:?}"),
        }
    }

    #[test]
    fn equal_version_is_not_offered_as_an_update() {
        let m = manifest_for("2.10.0", "linux-x86_64");
        let decision = decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &RunningEngine::UNGATED, &m);
        // Note cross-reference: the brief lists "an equal version is
        // refused" among the required properties. It is refused AS AN UPDATE;
        // the honest label for "offered == running" is UpToDate, not an
        // attack. The property that matters is asserted on the next line.
        assert_eq!(decision, Decision::UpToDate);
        assert!(!matches!(decision, Decision::Update(_)));
    }

    #[test]
    fn below_floor_is_refused_even_when_signed() {
        // Offered (2.4.0) IS newer than running (2.3.0): without a floor this
        // would be an update. The floor exists to retire a known-bad release
        // permanently, signature or no signature.
        let m = manifest_for("2.4.0", "linux-x86_64");
        match decide(&v("2.3.0"), &v("2.5.0"), Platform::LinuxX86_64, &RunningEngine::UNGATED, &m) {
            Decision::Refused(RefusalReason::BelowFloor { offered, floor }) => {
                assert_eq!(offered, v("2.4.0"));
                assert_eq!(floor, v("2.5.0"));
            }
            other => panic!("expected BelowFloor refusal, got {other:?}"),
        }
    }

    #[test]
    fn multi_digit_versions_compare_numerically() {
        // "2.10.0" < "2.9.0" lexicographically; numerically 2.10.0 is newer.
        // String comparison gets this backwards, and that backwards is a
        // rollback channel.
        assert!(v("2.10.0") > v("2.9.0"));
        assert!(v("10.0.0") > v("9.9.9"));
        let m = manifest_for("2.10.0", "linux-x86_64");
        assert!(matches!(
            decide(&v("2.9.0"), &v("2.0.0"), Platform::LinuxX86_64, &RunningEngine::UNGATED, &m),
            Decision::Update(_)
        ));
    }

    #[test]
    fn decide_never_offers_a_downgrade_or_reinstall() {
        for offered in ["1.0.0", "2.9.9", "2.10.0"] {
            let m = manifest_for(offered, "linux-x86_64");
            assert!(
                !matches!(
                    decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &RunningEngine::UNGATED, &m),
                    Decision::Update(_)
                ),
                "{offered} must not be offered to a 2.10.0 install"
            );
        }
    }

    #[test]
    fn wrong_platform_is_refused() {
        let m = manifest_for("2.11.0", "linux-x86_64");
        assert!(matches!(
            decide(&v("2.10.0"), &v("2.0.0"), Platform::MacosAarch64, &RunningEngine::UNGATED, &m),
            Decision::Refused(RefusalReason::WrongPlatform { .. })
        ));
    }

    #[test]
    fn newer_version_is_offered_as_an_update() {
        let m = manifest_for("2.11.0", "linux-x86_64");
        match decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &RunningEngine::UNGATED, &m) {
            Decision::Update(offered) => assert_eq!(offered, m),
            other => panic!("expected Update, got {other:?}"),
        }
    }

    // ---- the engine gate ----

    /// A signed manifest for linux-x86_64 carrying `engine_floor` (raw JSON
    /// object text, e.g. `{"webkitgtk":"2.54.0"}`).
    fn manifest_with_floor(version: &str, floor: &str) -> Manifest {
        let payload = payload_json(
            version,
            "linux-x86_64",
            "https://updates.patanyx.example/x",
            &sha256_hex(BINARY),
            BINARY.len() as u64,
            1_735_689_600,
        )
        .replace(",\"published_at\"", &format!(",\"engine_floor\":{floor},\"published_at\""));
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        crate::verify_manifest(envelope.as_bytes(), &trusted_keys()).expect("test manifest must verify")
    }

    fn webkit(version: Option<&[u32]>) -> RunningEngine<'_> {
        RunningEngine {
            name: "WebKitGTK",
            version,
            gates_install: true,
        }
    }

    fn decide_on(engine: &RunningEngine<'_>, m: &Manifest) -> Decision {
        decide(&v("1.0.5"), &v("0.0.0"), Platform::LinuxX86_64, engine, m)
    }

    #[test]
    fn an_engine_below_the_floor_is_refused() {
        let m = manifest_with_floor("1.0.6", r#"{"webkitgtk":"2.54.0"}"#);
        match decide_on(&webkit(Some(&[2, 52, 6])), &m) {
            Decision::Refused(RefusalReason::EngineTooOld { needed, running, engine, offered }) => {
                assert_eq!(needed, vec![2, 54, 0]);
                assert_eq!(running, vec![2, 52, 6]);
                assert_eq!(engine, "WebKitGTK");
                assert_eq!(offered, v("1.0.6"));
            }
            other => panic!("expected EngineTooOld, got {other:?}"),
        }
        // The last 2.53 development release is still below 2.54.0.
        assert!(matches!(
            decide_on(&webkit(Some(&[2, 53, 92])), &m),
            Decision::Refused(RefusalReason::EngineTooOld { .. })
        ));
    }

    #[test]
    fn an_engine_at_or_above_the_floor_is_offered() {
        let m = manifest_with_floor("1.0.6", r#"{"webkitgtk":"2.54.0"}"#);
        for found in [&[2, 54, 0][..], &[2, 54, 1], &[2, 56, 0], &[3, 0, 0]] {
            assert!(
                matches!(decide_on(&webkit(Some(found)), &m), Decision::Update(_)),
                "{found:?} meets 2.54.0"
            );
        }
    }

    #[test]
    fn a_missing_engine_requirement_is_refused_where_the_engine_gates() {
        // No engine_floor at all, and one naming only the other engine.
        for m in [
            manifest_for("1.0.6", "linux-x86_64"),
            manifest_with_floor("1.0.6", r#"{"webview2":"152.0.4191.62"}"#),
        ] {
            assert!(matches!(
                decide_on(&webkit(Some(&[2, 60, 0])), &m),
                Decision::Refused(RefusalReason::EngineRequirementMissing { .. })
            ));
        }
    }

    #[test]
    fn an_unreadable_or_short_engine_version_is_refused() {
        let m = manifest_with_floor("1.0.6", r#"{"webkitgtk":"2.54.0"}"#);
        assert!(matches!(
            decide_on(&webkit(None), &m),
            Decision::Refused(RefusalReason::EngineUnknown { .. })
        ));
        assert!(matches!(
            decide_on(&webkit(Some(&[2, 54])), &m),
            Decision::Refused(RefusalReason::EngineUnknown { .. })
        ));
    }

    #[test]
    fn an_ungated_engine_is_never_refused_for_its_version() {
        // Windows: WebView2 updates itself and a below-floor runtime starts.
        let m = manifest_with_floor("1.0.6", r#"{"webview2":"152.0.4191.62"}"#);
        let old = [140, 0, 0, 0];
        let engine = RunningEngine {
            name: "WebView2",
            version: Some(&old),
            gates_install: false,
        };
        assert!(matches!(decide_on(&engine, &m), Decision::Update(_)));
        assert!(matches!(decide_on(&RunningEngine::UNGATED, &manifest_for("1.0.6", "linux-x86_64")), Decision::Update(_)));
    }

    #[test]
    fn the_engine_gate_never_relabels_an_older_or_equal_offer() {
        // Up to date and downgrade answers win over an engine problem: the
        // engine check only ever stops something that would install.
        let old_engine = webkit(Some(&[2, 40, 0]));
        assert_eq!(
            decide_on(&old_engine, &manifest_with_floor("1.0.5", r#"{"webkitgtk":"2.54.0"}"#)),
            Decision::UpToDate
        );
        assert!(matches!(
            decide_on(&old_engine, &manifest_with_floor("1.0.4", r#"{"webkitgtk":"2.54.0"}"#)),
            Decision::Refused(RefusalReason::NotNewer { .. })
        ));
    }

    #[test]
    fn engine_meets_compares_fields_numerically() {
        assert_eq!(engine_meets(&[2, 54, 0], &[2, 54, 0]), Some(true));
        assert_eq!(engine_meets(&[2, 100, 0], &[2, 54, 0]), Some(true));
        assert_eq!(engine_meets(&[2, 9, 9], &[2, 54, 0]), Some(false));
        assert_eq!(engine_meets(&[2, 54, 0, 7], &[2, 54, 0]), Some(true));
        assert_eq!(engine_meets(&[2, 54], &[2, 54, 0]), None);
    }

    #[test]
    fn engine_refusals_read_as_sentences() {
        let m = manifest_with_floor("1.0.7", r#"{"webkitgtk":"2.56.0"}"#);
        let Decision::Refused(why) = decide_on(&webkit(Some(&[2, 54, 0])), &m) else {
            panic!("expected a refusal");
        };
        assert_eq!(
            why.to_string(),
            "PATANYX 1.0.7 needs WebKitGTK 2.56.0 or newer, and this computer has 2.54.0; \
             update the system, then PATANYX can install it"
        );
    }

    // ---- feed binding: Linux /v2 manifests under their own domain ----

    fn sign_in(payload: &str, domain: &[u8]) -> String {
        let key = signing_key(SEED_TRUSTED_A);
        let mut message = domain.to_vec();
        message.extend_from_slice(payload.as_bytes());
        let sig = ed25519_dalek::Signer::sign(&key, &message);
        serde_json::json!({ "v": 1, "payload": payload, "sig": hex::encode(&sig.to_bytes()) }).to_string()
    }

    fn linux_payload() -> String {
        payload_json(
            "1.0.7",
            "linux-x86_64",
            "https://updates.patanyx.example/x",
            &sha256_hex(BINARY),
            BINARY.len() as u64,
            1_735_689_600,
        )
    }

    #[test]
    fn a_v2_linux_manifest_is_refused_by_the_old_verifier() {
        // What every pre-1.0.6 Linux copy runs: it must see a bad signature.
        let envelope = sign_in(&linux_payload(), SIGNING_DOMAIN_LINUX_V2);
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::BadSignature)
        ));
        verify_manifest_linux_v2(envelope.as_bytes(), &trusted_keys()).expect("the v2 verifier accepts it");
    }

    #[test]
    fn a_v1_manifest_is_refused_by_the_v2_verifier() {
        // The bridge or any older /v1 manifest cannot be replayed to 1.0.6+.
        let envelope = sign_in(&linux_payload(), SIGNING_DOMAIN);
        assert!(matches!(
            verify_manifest_linux_v2(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn a_v2_manifest_must_name_a_linux_platform() {
        let windows = linux_payload().replace("linux-x86_64", "windows-x86_64");
        let envelope = sign_in(&windows, SIGNING_DOMAIN_LINUX_V2);
        assert!(matches!(
            verify_manifest_linux_v2(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn the_linux_v2_domain_is_distinct_from_every_other() {
        for other in [SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST, SIGNING_DOMAIN_MODELS] {
            assert_ne!(SIGNING_DOMAIN_LINUX_V2, other);
        }
        assert_eq!(SIGNING_DOMAIN_LINUX_V2, b"PATANYX-UPDATE-MANIFEST-LINUX-V2\n");
    }

    // ---- payload verification ----

    #[test]
    fn payload_roundtrip_ok() {
        let m = manifest_for("2.11.0", "linux-x86_64");
        verify_payload(BINARY, &m).expect("the exact bytes must pass");
    }

    #[test]
    fn payload_with_wrong_hash_is_refused() {
        let m = manifest_for("2.11.0", "linux-x86_64");
        let mut forged = BINARY.to_vec();
        // Same length, different bytes: the length check passes and the hash
        // check is the only thing left — it must not pass.
        forged[0] ^= 1;
        assert!(matches!(
            verify_payload(&forged, &m),
            Err(UpdateError::PayloadHash)
        ));
    }

    #[test]
    fn truncated_payload_is_refused() {
        let m = manifest_for("2.11.0", "linux-x86_64");
        let truncated = &BINARY[..BINARY.len() - 1];
        assert!(matches!(
            verify_payload(truncated, &m),
            Err(UpdateError::PayloadLength { .. })
        ));
    }

    // ---- defensive parsing ----

    #[test]
    fn empty_and_garbage_inputs_are_malformed() {
        // Annotated as a slice array: the literals are `&[u8; N]` of five
        // different N and will not unify on their own.
        let cases: [&[u8]; 5] = [b"", b"not json at all", b"{}", b"null", b"[1,2,3]"];
        for input in cases {
            assert!(
                matches!(
                    verify_manifest(input, &trusted_keys()),
                    Err(UpdateError::Malformed(_))
                ),
                "{input:?} must be malformed"
            );
        }
    }

    #[test]
    fn trailing_data_is_rejected() {
        let valid = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        for suffix in ["x", " {}", " {\"extra\":true}"] {
            let mut bytes = valid.clone().into_bytes();
            bytes.extend_from_slice(suffix.as_bytes());
            assert!(
                matches!(
                    verify_manifest(&bytes, &trusted_keys()),
                    Err(UpdateError::Malformed(_))
                ),
                "trailing {suffix:?} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_envelope_field_is_rejected() {
        // The envelope is UNSIGNED attacker space; nothing extra gets to ride
        // along in it, even a harmless-looking note.
        let payload = serde_json::to_string(&good_payload()).unwrap();
        let envelope = format!(
            "{{\"v\":1,\"payload\":{payload},\"sig\":\"{}\",\"note\":\"hello\"}}",
            "00".repeat(64)
        );
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_payload_field_is_ignored() {
        // The payload is SIGNED: only the publisher can add a field, and the
        // publisher adding one is how the format grows without breaking old
        // clients.
        let payload = good_payload().replace("\"size\":", "\"future_field\":[1,2,3],\"size\":");
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        verify_manifest(envelope.as_bytes(), &trusted_keys())
            .expect("an unknown signed field must not break old clients");
    }

    #[test]
    fn oversized_envelope_is_rejected_even_if_signed() {
        let long_url = format!("https://updates.patanyx.example/{}", "x".repeat(20 * 1024));
        let payload = payload_json(
            "2.11.0",
            "linux-x86_64",
            &long_url,
            &"0".repeat(64),
            BINARY.len() as u64,
            1_735_689_600,
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        assert!(envelope.len() > crate::manifest::MAX_ENVELOPE_BYTES);
        // A valid publisher signature does not buy unlimited memory.
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn oversized_payload_is_rejected_even_if_signed() {
        // ~9.4 KB of payload: under the 16 KB envelope cap, over the 8 KB
        // payload cap. The inner cap must do its own work.
        let url = format!("https://updates.patanyx.example/{}", "x".repeat(9 * 1024));
        let payload = payload_json(
            "2.11.0",
            "linux-x86_64",
            &url,
            &"0".repeat(64),
            BINARY.len() as u64,
            1_735_689_600,
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        assert!(envelope.len() <= crate::manifest::MAX_ENVELOPE_BYTES);
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn http_url_is_rejected_even_if_signed() {
        let payload = payload_json(
            "2.11.0",
            "linux-x86_64",
            "http://updates.patanyx.example/x",
            &sha256_hex(BINARY),
            BINARY.len() as u64,
            1_735_689_600,
        );
        let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn signed_but_semantically_invalid_fields_are_rejected() {
        // The publisher's key does not make "2.9" a version: a signature
        // proves ORIGIN, not well-formedness.
        let bad_version = payload_json(
            "2.9",
            "linux-x86_64",
            "https://updates.patanyx.example/x",
            &sha256_hex(BINARY),
            1,
            1,
        );
        let envelope = sign(&bad_version, &signing_key(SEED_TRUSTED_A));
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
        // Nor is an unknown platform a platform.
        let bad_platform = payload_json(
            "2.9.0",
            "plan9-m68k",
            "https://updates.patanyx.example/x",
            &sha256_hex(BINARY),
            1,
            1,
        );
        let envelope = sign(&bad_platform, &signing_key(SEED_TRUSTED_A));
        assert!(matches!(
            verify_manifest(envelope.as_bytes(), &trusted_keys()),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn absurd_payload_size_is_rejected_even_if_signed() {
        for size in [0u64, u64::MAX] {
            let payload = payload_json(
                "2.11.0",
                "linux-x86_64",
                "https://updates.patanyx.example/x",
                &sha256_hex(BINARY),
                size,
                1,
            );
            let envelope = sign(&payload, &signing_key(SEED_TRUSTED_A));
            assert!(
                matches!(
                    verify_manifest(envelope.as_bytes(), &trusted_keys()),
                    Err(UpdateError::Malformed(_))
                ),
                "size {size} must be rejected"
            );
        }
    }

    #[test]
    fn every_truncated_prefix_fails_without_panic() {
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A));
        let bytes = envelope.as_bytes();
        for end in 0..bytes.len() {
            assert!(
                verify_manifest(&bytes[..end], &trusted_keys()).is_err(),
                "a {end}-byte prefix must not verify"
            );
        }
    }

    #[test]
    fn every_single_byte_flip_fails_without_panic() {
        // Every byte of the envelope is either signed payload, signature,
        // or strict structure — so no single-bit neighbourhood of a valid
        // manifest contains another valid manifest.
        let envelope = sign(&good_payload(), &signing_key(SEED_TRUSTED_A)).into_bytes();
        for i in 0..envelope.len() {
            let mut mutated = envelope.clone();
            mutated[i] ^= 0x01;
            assert!(
                verify_manifest(&mutated, &trusted_keys()).is_err(),
                "flipping byte {i} must not verify"
            );
        }
    }

    // ---- trusted key set ----

    #[test]
    fn empty_trusted_key_set_is_an_error() {
        assert!(matches!(
            TrustedKeys::new(vec![]),
            Err(UpdateError::NoTrustedKeys)
        ));
        assert!(matches!(
            TrustedKeys::from_hex(&[]),
            Err(UpdateError::NoTrustedKeys)
        ));
    }

    #[test]
    fn bad_trusted_key_hex_is_an_error() {
        assert!(matches!(
            TrustedKeys::from_hex(&["not-hex"]),
            Err(UpdateError::BadKey(_))
        ));
        // Right alphabet, wrong length.
        assert!(matches!(
            TrustedKeys::from_hex(&["00"]),
            Err(UpdateError::BadKey(_))
        ));
    }
}
