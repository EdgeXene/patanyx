//! The ENGINE ADVISORY: a warning-only signed document whose entire authority
//! is to raise the WebView2 security threshold the browser warns at.
//!
//! # Why a fourth signed class
//!
//! The release manifest already carries `engine_floor` inside its signed
//! payload, and every verified manifest raises the persisted floor. That path
//! works, and it stays. What it cannot do is run unattended: the release key
//! is offline and signed by a human, so raising the floor through it means a
//! human re-signing the current manifest on the day an advisory lands.
//!
//! Microsoft's security notes name an exploited CVE and its fixed build a few
//! times a year, usually within hours of the runtime shipping. A monitor that
//! reads those notes hourly needs a key it may hold on a networked machine --
//! and a key handled that often must not be able to do anything worse than
//! raise a warning. Hence a separate class with a separate domain and a
//! separate compiled key set:
//!
//!   * DOMAIN separation (`SIGNING_DOMAIN_ADVISORY`) stops an advisory
//!     signature being REPLAYED as a release, a blocklist or a language pack.
//!   * A separate KEY SET (`ADVISORY_KEYS` in the app) stops a STOLEN advisory
//!     key from FORGING any of those.
//!
//! Both are needed and both are tested, exactly as the model-feed class
//! established on 2026-08-31.
//!
//! # What the document may and may not do
//!
//! It may raise the WebView2 warning threshold. It cannot lower it (clients
//! only ever raise), cannot refuse startup (that stays tied to the compiled
//! constant), cannot name a URL, a command or a binary, and cannot speak for
//! any engine other than WebView2 -- `engine` is a closed one-member set on
//! purpose, so a compromised advisory key cannot reach the Linux side, where
//! the compiled floor is a refusal rather than a banner.
//!
//! A compromised advisory key buys a FALSE BANNER on Windows until the key is
//! revoked in a browser release. The client keeps advisory floors keyed by the
//! verifying key that authenticated them (see the app's `engine_advisory`
//! module), so revoking the key removes its persisted floors as well; nothing
//! it signed becomes permanent.
//!
//! # Bounds
//!
//! "Signed" means the publisher said it, not that it is sensible, and the
//! publisher here is an unattended script reading HTML. So the verifier is
//! strict about shape, and [`AdvisoryManifest::check_plausible`] refuses a
//! floor that leaps implausibly far ahead of the compiled constant or claims
//! to have been published in the future. Those bounds take the compiled floor
//! and the clock as PARAMETERS, keeping this crate free of both.

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::error::UpdateError;
use crate::keys::TrustedKeys;
use crate::manifest::{verify_envelope_identified, MAX_ADVISORY_REASON_CHARS};

/// Domain separation for the ENGINE ADVISORY class. Newline-terminated like
/// the other three so it can never be a prefix of another domain.
pub const SIGNING_DOMAIN_ADVISORY: &[u8] = b"PATANYX-ENGINE-ADVISORY-V1\n";

/// How many major versions ahead of the compiled WebView2 floor an advisory
/// may point before it is refused as implausible: 24 majors, stated as a
/// count of majors and nothing else, because the runtime's release cadence
/// is Microsoft's to change. A client whose compiled floor is that far
/// behind the advisory keeps its compiled floor; nothing is lowered. The
/// same bound is applied by the signer (`sign-advisory --baseline`) and the
/// publisher before anything is signed, so an implausible document is a
/// publishing refusal first and a client refusal second.
pub const MAX_MAJOR_AHEAD: u32 = 24;

/// How far in the future a `published_at` may sit before the document is
/// refused. Clocks skew; a week covers any honest skew and refuses a
/// document dated next year.
pub const MAX_FUTURE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// An engine advisory whose signature has ALREADY VERIFIED. Private fields,
/// one constructor, like every other verified type in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryManifest {
    webview2: [u32; 4],
    published_at: u64,
    reason: String,
    /// The compiled key that verified this document. Reported so the client
    /// can persist the floor UNDER THAT KEY and drop it when the key is
    /// revoked. Public data: the compiled key set is in every binary.
    verified_by: [u8; 32],
}

impl AdvisoryManifest {
    /// The WebView2 threshold, exactly four fields.
    pub fn webview2(&self) -> &[u32; 4] {
        &self.webview2
    }

    pub fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Short publisher note, e.g. the CVE the floor answers. Bounded and
    /// control-character free; shown in logs and diagnostics only.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The verifying key that authenticated this advisory.
    pub fn verified_by(&self) -> &[u8; 32] {
        &self.verified_by
    }

    /// Policy bounds that need inputs this crate does not own: the compiled
    /// WebView2 floor and the current time. A verified document that fails
    /// these is refused as implausible; the caller keeps whatever it had.
    pub fn check_plausible(
        &self,
        compiled_webview2: &[u32; 4],
        now_unix: u64,
    ) -> Result<(), UpdateError> {
        let ceiling = compiled_webview2[0].saturating_add(MAX_MAJOR_AHEAD);
        if self.webview2[0] > ceiling {
            return Err(UpdateError::Malformed(format!(
                "advisory names WebView2 major {}, more than {MAX_MAJOR_AHEAD} ahead of the \
                 compiled floor major {}",
                self.webview2[0], compiled_webview2[0]
            )));
        }
        if self.published_at > now_unix.saturating_add(MAX_FUTURE_SECONDS) {
            return Err(UpdateError::Malformed(format!(
                "advisory published_at {} is in the future (now {now_unix})",
                self.published_at
            )));
        }
        Ok(())
    }
}

/// The signed document. Unknown fields are allowed, as in every other signed
/// payload: only the publisher can add one.
#[derive(Deserialize)]
struct RawAdvisoryPayload {
    /// Closed set: exactly `"webview2"`. See the module doc for why the
    /// advisory cannot speak for WebKitGTK.
    engine: String,
    /// `"152.0.4191.66"`: exactly four dotted decimal fields.
    floor: String,
    published_at: u64,
    #[serde(default)]
    reason: String,
}

/// "152.0.4191.66" -> [152, 0, 4191, 66], refusing anything else. The same
/// rule the release manifest's `engine_floor.webview2` applies, restated here
/// rather than shared so this class's precision cannot drift with a change
/// meant for the other.
fn parse_four_fields(text: &str) -> Option<[u32; 4]> {
    if text.len() > 32 {
        return None;
    }
    let mut out = [0u32; 4];
    let mut n = 0;
    for part in text.split('.') {
        if n == 4 || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[n] = part.parse::<u32>().ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// Parse and verify an ENGINE ADVISORY envelope.
///
/// A fourth entry point rather than a flag on the others, for the reason the
/// blocklist and model verifiers each give: the domain is hard-wired here, so
/// choosing the wrong verifier is a visibly wrong call at the call site.
pub fn verify_advisory_manifest(
    bytes: &[u8],
    keys: &TrustedKeys,
) -> Result<AdvisoryManifest, UpdateError> {
    let (payload, key) = verify_envelope_identified(bytes, keys, SIGNING_DOMAIN_ADVISORY)?;
    let raw: RawAdvisoryPayload = serde_json::from_str(&payload).map_err(|e| {
        UpdateError::Malformed(format!("signed payload is not the expected JSON: {e}"))
    })?;
    if raw.engine != "webview2" {
        return Err(UpdateError::Malformed(format!(
            "advisory names engine {:?}; only \"webview2\" may be raised this way",
            raw.engine
        )));
    }
    let webview2 = parse_four_fields(&raw.floor).ok_or_else(|| {
        UpdateError::Malformed(format!(
            "advisory floor must be exactly 4 dotted decimal fields, got {:?}",
            raw.floor
        ))
    })?;
    if webview2 == [0, 0, 0, 0] {
        return Err(UpdateError::Malformed(
            "advisory floor 0.0.0.0 raises nothing and is refused".to_string(),
        ));
    }
    if raw.published_at == 0 {
        return Err(UpdateError::Malformed(
            "advisory published_at must be a real timestamp".to_string(),
        ));
    }
    if raw.reason.chars().count() > MAX_ADVISORY_REASON_CHARS {
        return Err(UpdateError::Malformed(format!(
            "advisory reason runs {} characters; the cap is {MAX_ADVISORY_REASON_CHARS}",
            raw.reason.chars().count()
        )));
    }
    if raw.reason.chars().any(|c| c.is_control() || crate::manifest::is_deceptive_text(c)) {
        return Err(UpdateError::Malformed(
            "advisory reason may contain no control or direction-override characters"
                .to_string(),
        ));
    }
    Ok(AdvisoryManifest {
        webview2,
        published_at: raw.published_at,
        reason: raw.reason,
        verified_by: key_bytes(&key),
    })
}

fn key_bytes(key: &VerifyingKey) -> [u8; 32] {
    *key.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST, SIGNING_DOMAIN_MODELS,
    };
    use crate::testutil::{signing_key, SEED_ATTACKER, SEED_TRUSTED_A, SEED_TRUSTED_B};
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_in_domain(payload: &str, key: &SigningKey, domain: &[u8]) -> String {
        let mut message = Vec::with_capacity(domain.len() + payload.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(payload.as_bytes());
        format!(
            "{{\"v\":1,\"payload\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(payload).expect("a string always serializes"),
            crate::hex::encode(&key.sign(&message).to_bytes())
        )
    }

    fn advisory_keys() -> TrustedKeys {
        TrustedKeys::new(vec![signing_key(SEED_TRUSTED_A).verifying_key()]).expect("keys")
    }

    const GOOD: &str = r#"{"engine":"webview2","floor":"152.0.4191.66","published_at":1757570000,"reason":"CVE-2026-87491"}"#;

    #[test]
    fn the_domain_is_exactly_this_and_terminated() {
        assert_eq!(SIGNING_DOMAIN_ADVISORY, b"PATANYX-ENGINE-ADVISORY-V1\n");
        for other in [SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST, SIGNING_DOMAIN_MODELS] {
            assert_ne!(SIGNING_DOMAIN_ADVISORY, other);
            assert!(!other.starts_with(SIGNING_DOMAIN_ADVISORY));
            assert!(!SIGNING_DOMAIN_ADVISORY.starts_with(other));
        }
    }

    #[test]
    fn a_good_advisory_verifies_and_reports_its_key() {
        let key = signing_key(SEED_TRUSTED_A);
        let signed = sign_in_domain(GOOD, &key, SIGNING_DOMAIN_ADVISORY);
        let m = verify_advisory_manifest(signed.as_bytes(), &advisory_keys()).expect("verifies");
        assert_eq!(m.webview2(), &[152, 0, 4191, 66]);
        assert_eq!(m.published_at(), 1_757_570_000);
        assert_eq!(m.reason(), "CVE-2026-87491");
        assert_eq!(m.verified_by(), key.verifying_key().as_bytes());
    }

    /// With two trusted keys the reported identity is the one that actually
    /// signed -- the client persists floors under it, so a wrong answer here
    /// would attach a floor to the wrong revocation.
    #[test]
    fn the_verifying_key_identity_is_the_signer_not_the_first_in_the_set() {
        let a = signing_key(SEED_TRUSTED_A);
        let b = signing_key(SEED_TRUSTED_B);
        let keys = TrustedKeys::new(vec![a.verifying_key(), b.verifying_key()]).unwrap();
        let signed = sign_in_domain(GOOD, &b, SIGNING_DOMAIN_ADVISORY);
        let m = verify_advisory_manifest(signed.as_bytes(), &keys).unwrap();
        assert_eq!(m.verified_by(), b.verifying_key().as_bytes());
        assert_ne!(m.verified_by(), a.verifying_key().as_bytes());
    }

    /// CROSS-DOMAIN, BOTH DIRECTIONS, AND THE REFUSAL MUST BE THE SIGNATURE.
    ///
    /// `is_err()` alone would also pass if the domain check were broken and
    /// the destination verifier merely refused the advisory's SCHEMA. So the
    /// forward direction signs payloads that are VALID for the destination
    /// class -- a real release payload, a real blocklist payload, a real
    /// model payload -- under the advisory domain, and asserts each
    /// destination answers `BadSignature`: nothing but the domain differs.
    /// The reverse direction signs the advisory payload under each other
    /// domain and asserts the advisory verifier answers `BadSignature`.
    #[test]
    fn an_advisory_cannot_be_replayed_as_another_class_nor_the_reverse() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = advisory_keys();

        // Forward: destination-valid payloads, advisory domain.
        let release = sign_in_domain(&crate::testutil::good_payload(), &key, SIGNING_DOMAIN_ADVISORY);
        assert!(
            matches!(crate::verify_manifest(release.as_bytes(), &keys), Err(UpdateError::BadSignature)),
            "a release-shaped payload signed under the advisory domain must fail the SIGNATURE"
        );
        // Control: the same payload under the release domain verifies, so
        // the refusal above is the domain and not the payload.
        let release_ok = sign_in_domain(&crate::testutil::good_payload(), &key, SIGNING_DOMAIN);
        assert!(crate::verify_manifest(release_ok.as_bytes(), &keys).is_ok());

        const BLOCKLIST: &str = r#"{"list_version":7,"url":"https://example.invalid/list.txt","sha256":"aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899","size":4096,"entries":300,"published_at":1}"#;
        let blocklist = sign_in_domain(BLOCKLIST, &key, SIGNING_DOMAIN_ADVISORY);
        assert!(matches!(
            crate::verify_blocklist_manifest(blocklist.as_bytes(), &keys),
            Err(UpdateError::BadSignature)
        ));
        assert!(crate::verify_blocklist_manifest(
            sign_in_domain(BLOCKLIST, &key, SIGNING_DOMAIN_BLOCKLIST).as_bytes(),
            &keys
        )
        .is_ok());

        const MODEL: &str = r#"{"pair":"en-es","url":"https://models.patanyx.net/en-es/1.pack","sha256":"0000000000000000000000000000000000000000000000000000000000000001","size":36600000,"version":1}"#;
        let model = sign_in_domain(MODEL, &key, SIGNING_DOMAIN_ADVISORY);
        assert!(matches!(
            crate::verify_model_manifest(model.as_bytes(), &keys),
            Err(UpdateError::BadSignature)
        ));
        assert!(crate::verify_model_manifest(
            sign_in_domain(MODEL, &key, SIGNING_DOMAIN_MODELS).as_bytes(),
            &keys
        )
        .is_ok());

        // Reverse: the advisory payload under each other domain.
        for domain in [SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST, SIGNING_DOMAIN_MODELS] {
            let wrong = sign_in_domain(GOOD, &key, domain);
            assert!(
                matches!(
                    verify_advisory_manifest(wrong.as_bytes(), &keys),
                    Err(UpdateError::BadSignature)
                ),
                "a payload signed under another domain verified as an advisory"
            );
        }
    }

    /// PLANTED WRONG DOMAIN. The one internal seam where the domain is a
    /// parameter (`verify_envelope_identified`) is driven with the advisory
    /// envelope's exact bytes under the right domain and then under a wrong
    /// one. Same bytes, same key, same schema: only the domain differs, and
    /// only the domain decides. A verifier that ignored its domain (a bare
    /// signature over the payload, `sign_undomained`) is refused too.
    #[test]
    fn a_planted_wrong_domain_is_refused_on_the_same_bytes() {
        use crate::manifest::verify_envelope_identified;
        let key = signing_key(SEED_TRUSTED_A);
        let keys = advisory_keys();
        let signed = sign_in_domain(GOOD, &key, SIGNING_DOMAIN_ADVISORY);
        // Right domain: the payload string comes back and the key is named.
        let (payload, who) =
            verify_envelope_identified(signed.as_bytes(), &keys, SIGNING_DOMAIN_ADVISORY)
                .expect("right domain verifies");
        assert_eq!(payload, GOOD);
        assert_eq!(who.as_bytes(), key.verifying_key().as_bytes());
        // Planted: a domain one byte off, and each real other domain.
        let mut off_by_one = SIGNING_DOMAIN_ADVISORY.to_vec();
        off_by_one[0] ^= 0x01;
        for wrong in [
            off_by_one.as_slice(),
            SIGNING_DOMAIN,
            SIGNING_DOMAIN_BLOCKLIST,
            SIGNING_DOMAIN_MODELS,
            b"",
        ] {
            assert!(
                matches!(
                    verify_envelope_identified(signed.as_bytes(), &keys, wrong),
                    Err(UpdateError::BadSignature)
                ),
                "domain {wrong:?} must not verify the advisory bytes"
            );
        }
        // A signature with no domain at all -- what a verifier that forgot
        // the prefix would accept -- is refused by the real verifier.
        let bare = crate::testutil::sign_undomained(GOOD, &key);
        assert!(matches!(
            verify_advisory_manifest(bare.as_bytes(), &keys),
            Err(UpdateError::BadSignature)
        ));
    }

    /// KEY-SET separation, the half domain separation cannot provide: a key
    /// the advisory channel trusts must be refused by a verifier that does
    /// not trust it, even with a fresh signature in the right domain.
    #[test]
    fn a_stolen_advisory_key_cannot_forge_a_release_and_vice_versa() {
        let advisory_key = signing_key(SEED_ATTACKER);
        let advisory_side = TrustedKeys::new(vec![advisory_key.verifying_key()]).unwrap();
        let release_side = crate::testutil::trusted_keys();
        // Advisory key, release domain, release verifier: refused AS A
        // SIGNATURE (the payload is a valid release payload).
        let forged = sign_in_domain(&crate::testutil::good_payload(), &advisory_key, SIGNING_DOMAIN);
        assert!(matches!(
            crate::verify_manifest(forged.as_bytes(), &release_side),
            Err(UpdateError::BadSignature)
        ));
        // Release key, advisory domain, advisory verifier: refused likewise.
        let release_key = signing_key(SEED_TRUSTED_A);
        let forged = sign_in_domain(GOOD, &release_key, SIGNING_DOMAIN_ADVISORY);
        assert!(matches!(
            verify_advisory_manifest(forged.as_bytes(), &advisory_side),
            Err(UpdateError::BadSignature)
        ));
        // Sanity: each key is accepted by its own side.
        let own = sign_in_domain(GOOD, &advisory_key, SIGNING_DOMAIN_ADVISORY);
        assert!(verify_advisory_manifest(own.as_bytes(), &advisory_side).is_ok());
    }

    #[test]
    fn a_signed_advisory_is_still_validated() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = advisory_keys();
        for bad in [
            // Precision: three and five fields, and a word.
            r#"{"engine":"webview2","floor":"152.0.4191","published_at":1}"#,
            r#"{"engine":"webview2","floor":"152.0.4191.66.1","published_at":1}"#,
            r#"{"engine":"webview2","floor":"152.0.4191.beta","published_at":1}"#,
            r#"{"engine":"webview2","floor":"","published_at":1}"#,
            r#"{"engine":"webview2","floor":" 152.0.4191.66","published_at":1}"#,
            r#"{"engine":"webview2","floor":"152.0.4191.66 ","published_at":1}"#,
            r#"{"engine":"webview2","floor":"152..4191.66","published_at":1}"#,
            r#"{"engine":"webview2","floor":"99999999999.0.0.0","published_at":1}"#,
            // Omitted floor.
            r#"{"engine":"webview2","published_at":1}"#,
            // Zero floor.
            r#"{"engine":"webview2","floor":"0.0.0.0","published_at":1}"#,
            // Another engine, or none.
            r#"{"engine":"webkitgtk","floor":"2.52.5","published_at":1}"#,
            r#"{"engine":"WebView2","floor":"152.0.4191.66","published_at":1}"#,
            r#"{"floor":"152.0.4191.66","published_at":1}"#,
            // No timestamp.
            r#"{"engine":"webview2","floor":"152.0.4191.66"}"#,
            r#"{"engine":"webview2","floor":"152.0.4191.66","published_at":0}"#,
            // A reason that is not a note.
            "{\"engine\":\"webview2\",\"floor\":\"152.0.4191.66\",\"published_at\":1,\"reason\":\"a\\u001b[31m\"}",
            "{\"engine\":\"webview2\",\"floor\":\"152.0.4191.66\",\"published_at\":1,\"reason\":\"x\\u202ey\"}",
            "not json",
            "[]",
        ] {
            let signed = sign_in_domain(bad, &key, SIGNING_DOMAIN_ADVISORY);
            assert!(
                verify_advisory_manifest(signed.as_bytes(), &keys).is_err(),
                "must refuse {bad}"
            );
        }
        let long = format!(
            "{{\"engine\":\"webview2\",\"floor\":\"152.0.4191.66\",\"published_at\":1,\"reason\":\"{}\"}}",
            "r".repeat(MAX_ADVISORY_REASON_CHARS + 1)
        );
        let signed = sign_in_domain(&long, &key, SIGNING_DOMAIN_ADVISORY);
        assert!(verify_advisory_manifest(signed.as_bytes(), &keys).is_err());
    }

    #[test]
    fn tampering_and_forgery_fail_closed() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = advisory_keys();
        let signed = sign_in_domain(GOOD, &key, SIGNING_DOMAIN_ADVISORY);
        // Edit the floor inside the signed bytes.
        let tampered = signed.replace("152.0.4191.66", "152.0.4191.99");
        assert_ne!(tampered, signed);
        assert!(matches!(
            verify_advisory_manifest(tampered.as_bytes(), &keys),
            Err(UpdateError::BadSignature)
        ));
        // An untrusted key.
        let forged = sign_in_domain(GOOD, &signing_key(SEED_ATTACKER), SIGNING_DOMAIN_ADVISORY);
        assert!(matches!(
            verify_advisory_manifest(forged.as_bytes(), &keys),
            Err(UpdateError::BadSignature)
        ));
        // Every truncation.
        for end in 0..signed.len() {
            assert!(verify_advisory_manifest(&signed.as_bytes()[..end], &keys).is_err());
        }
    }

    /// The plausibility bounds: an absurd future major and a future
    /// timestamp are refused; the real candidate passes against the real
    /// compiled floor.
    #[test]
    fn implausible_floors_are_refused_by_the_bounds() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = advisory_keys();
        let compiled = [152, 0, 4191, 62];
        let now = 1_757_600_000;

        let good = sign_in_domain(GOOD, &key, SIGNING_DOMAIN_ADVISORY);
        let m = verify_advisory_manifest(good.as_bytes(), &keys).unwrap();
        m.check_plausible(&compiled, now).expect("the real candidate is plausible");

        // Exactly at the ceiling passes; one past it does not.
        let at = GOOD.replace("152.0.4191.66", &format!("{}.0.0.1", 152 + MAX_MAJOR_AHEAD));
        let m = verify_advisory_manifest(
            sign_in_domain(&at, &key, SIGNING_DOMAIN_ADVISORY).as_bytes(),
            &keys,
        )
        .unwrap();
        assert!(m.check_plausible(&compiled, now).is_ok());
        let past = GOOD.replace("152.0.4191.66", &format!("{}.0.0.1", 153 + MAX_MAJOR_AHEAD));
        let m = verify_advisory_manifest(
            sign_in_domain(&past, &key, SIGNING_DOMAIN_ADVISORY).as_bytes(),
            &keys,
        )
        .unwrap();
        assert!(m.check_plausible(&compiled, now).is_err());

        // Published next month: refused. Published an hour ahead: tolerated.
        let future = GOOD.replace("1757570000", &(now + 40 * 24 * 3600).to_string());
        let m = verify_advisory_manifest(
            sign_in_domain(&future, &key, SIGNING_DOMAIN_ADVISORY).as_bytes(),
            &keys,
        )
        .unwrap();
        assert!(m.check_plausible(&compiled, now).is_err());
        let skew = GOOD.replace("1757570000", &(now + 3600).to_string());
        let m = verify_advisory_manifest(
            sign_in_domain(&skew, &key, SIGNING_DOMAIN_ADVISORY).as_bytes(),
            &keys,
        )
        .unwrap();
        assert!(m.check_plausible(&compiled, now).is_ok());
    }

    #[test]
    fn four_field_parse_is_exact() {
        assert_eq!(parse_four_fields("152.0.4191.66"), Some([152, 0, 4191, 66]));
        assert_eq!(parse_four_fields("0.0.0.1"), Some([0, 0, 0, 1]));
        for bad in ["152.0.4191", "1.2.3.4.5", "", "a.b.c.d", "1.2.3.", ".1.2.3", "1.2.3.-4", "1.2.3.+4"] {
            assert_eq!(parse_four_fields(bad), None, "{bad:?}");
        }
    }
}
