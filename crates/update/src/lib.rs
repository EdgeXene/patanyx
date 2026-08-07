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
//!     decide, verify_manifest, verify_payload, Decision, Platform, TrustedKeys, Version,
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
//!     match decide(&current, &FLOOR, platform, &manifest) {
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

pub use delta::{apply_delta, compress as compress_delta};
pub use error::UpdateError;
pub use keys::TrustedKeys;
pub use manifest::{
    verify_blocklist_manifest, verify_manifest, BlocklistManifest, Delta, Manifest, Platform,
    MAX_BLOCKLIST_BYTES, SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST,
};
pub use payload::{verify_blocklist_bytes, verify_payload};
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
        }
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
pub fn decide(
    current: &Version,
    floor: &Version,
    running: Platform,
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
        match decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &m) {
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
        let decision = decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &m);
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
        match decide(&v("2.3.0"), &v("2.5.0"), Platform::LinuxX86_64, &m) {
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
            decide(&v("2.9.0"), &v("2.0.0"), Platform::LinuxX86_64, &m),
            Decision::Update(_)
        ));
    }

    #[test]
    fn decide_never_offers_a_downgrade_or_reinstall() {
        for offered in ["1.0.0", "2.9.9", "2.10.0"] {
            let m = manifest_for(offered, "linux-x86_64");
            assert!(
                !matches!(
                    decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &m),
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
            decide(&v("2.10.0"), &v("2.0.0"), Platform::MacosAarch64, &m),
            Decision::Refused(RefusalReason::WrongPlatform { .. })
        ));
    }

    #[test]
    fn newer_version_is_offered_as_an_update() {
        let m = manifest_for("2.11.0", "linux-x86_64");
        match decide(&v("2.10.0"), &v("2.0.0"), Platform::LinuxX86_64, &m) {
            Decision::Update(offered) => assert_eq!(offered, m),
            other => panic!("expected Update, got {other:?}"),
        }
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
