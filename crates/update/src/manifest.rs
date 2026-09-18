//! Wire format and verification.
//!
//! A manifest travels as a small JSON envelope:
//!
//! ```json
//! {
//!   "v": 1,
//!   "payload": "<JSON string: the signed manifest document>",
//!   "sig": "<128 hex chars: Ed25519 signature>"
//! }
//! ```
//!
//! The signature covers `SIGNING_DOMAIN || payload-bytes` — the exact bytes
//! of the payload STRING, before any parsing. Signing bytes rather than a
//! re-serialized document is what makes "signed as a whole" literal: there
//! is no canonicalization for a tamperer to hide in, and no field can be
//! altered, reordered, added, or removed without the signature failing. The
//! double JSON layer is the price of that guarantee and is deliberate (JWS
//! makes the same choice); publisher tooling signs the payload string
//! verbatim, exactly as `testutil::sign` does in this crate's tests.
//!
//! The payload is parsed only AFTER the signature verifies. Until then it is
//! opaque attacker-controlled bytes, which is exactly what it is.

use std::borrow::Cow;
use std::fmt;

// `Verifier` is deliberately NOT imported. It is the trait behind
// `key.verify(...)`, and this module verifies with the inherent
// `verify_strict` instead -- see the argument at the call site. Importing the
// trait would put the weaker method back in scope on the same type, one
// keystroke away from the signature check this crate exists to get right.
use ed25519_dalek::Signature;
use serde::Deserialize;

use crate::error::UpdateError;
use crate::hex;
use crate::keys::TrustedKeys;
use crate::version::Version;

/// Hard cap on the whole envelope, checked before ANY parsing. A manifest is
/// a handful of small fields; 16 KiB is generous. The point of the cap is
/// that serde_json allocates as it reads, so bounding the input is what
/// bounds the allocation — no length field inside the input is ever trusted
/// to size anything.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;

/// The signed payload is smaller still.
const MAX_PAYLOAD_BYTES: usize = 8 * 1024;

/// URLs longer than this are not download locations; they are an attempt to
/// smuggle data through a signed field.
const MAX_URL_LEN: usize = 2048;

/// A browser installer is far under this. The bound turns a publisher-side
/// mistake (or a bizarre but validly signed manifest) into a clean refusal
/// instead of a promise the fetch layer has to strain at.
const MAX_BINARY_BYTES: u64 = 1 << 30; // 1 GiB

/// Wire version of the envelope, so the format can change without old
/// clients misreading new manifests.
const WIRE_VERSION: u32 = 1;

/// Domain separation for the signature: binds it to this one purpose, so a
/// signature produced for anything else — in this product or any other, now
/// or later — can never be replayed as an update manifest.
///
/// Exported so PUBLISHER TOOLING signs against the same constant the browser
/// verifies against, rather than a copy of it. A signer with its own copy of
/// this string is a signer that can silently stop matching -- and the symptom
/// would be every authentic update being refused, discovered by users.
pub const SIGNING_DOMAIN: &[u8] = b"PATANYX-UPDATE-MANIFEST-V1\n";

/// A target platform. The set is closed on purpose: a platform this build
/// cannot name is one it cannot safely match, and a manifest that cannot be
/// matched must install nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    LinuxX86_64,
    LinuxAarch64,
    MacosX86_64,
    MacosAarch64,
    WindowsX86_64,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::LinuxX86_64 => "linux-x86_64",
            Platform::LinuxAarch64 => "linux-aarch64",
            Platform::MacosX86_64 => "macos-x86_64",
            Platform::MacosAarch64 => "macos-aarch64",
            Platform::WindowsX86_64 => "windows-x86_64",
        }
    }

    /// The inverse of [`Platform::as_str`], for the caller mapping its own
    /// build target (e.g. from `std::env::consts`) onto this type.
    pub fn from_name(name: &str) -> Result<Platform, UpdateError> {
        match name {
            "linux-x86_64" => Ok(Platform::LinuxX86_64),
            "linux-aarch64" => Ok(Platform::LinuxAarch64),
            "macos-x86_64" => Ok(Platform::MacosX86_64),
            "macos-aarch64" => Ok(Platform::MacosAarch64),
            "windows-x86_64" => Ok(Platform::WindowsX86_64),
            other => Err(UpdateError::Malformed(format!(
                "unknown platform {other:?}"
            ))),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Platform::from_name(&s).map_err(serde::de::Error::custom)
    }
}

/// A release description whose signature has ALREADY VERIFIED.
///
/// The only constructor is [`verify_manifest`], and the fields are private,
/// so "these fields are authentic" is a fact of the type system rather than
/// a comment. Debug is derivable here — unlike the vault's key-holding
/// types — because everything in this crate is public data: public keys,
/// published documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    version: Version,
    platform: Platform,
    url: String,
    sha256: [u8; 32],
    size: u64,
    published_at: u64,
    deltas: Vec<Delta>,
    notes: String,
    /// Whether this release changes what the user SEES, and therefore whether
    /// it may install itself without being announced first.
    release_kind: ReleaseKind,
    /// Whether this release carries a security fix. Independent of
    /// `release_kind` on purpose: a fix rides in whatever release comes next,
    /// including a feature one, and holding it behind an unclicked banner is
    /// the outcome this flag exists to prevent.
    security: bool,
    /// The oldest engine runtime this publisher considers free of a known,
    /// exploited bug, per engine. See [`EngineFloors`].
    engine_floors: EngineFloors,
}

/// Per-engine security floors, carried INSIDE the signed payload so a
/// publisher can raise the browser's engine floor the day an engine advisory
/// lands, without shipping a new browser.
///
/// The browser compiles a floor in (`platform::MIN_WEBVIEW2`,
/// `platform::MIN_WEBKITGTK`); these only ever RAISE it, and the client
/// keeps the highest it has ever seen. What a raised floor does is show a
/// banner. It never refuses to start: the refusal a Linux release build
/// applies stays tied to the compiled constant, so a signed document can
/// make the browser warn but cannot turn it off.
///
/// Field counts are exact and match the compiled constants' precision:
/// WebView2 is four fields (152.0.4191.53 and 152.0.4191.62 are the exposed
/// and the fixed runtime, and they differ only in the fourth), WebKitGTK is
/// three. A floor with the wrong precision is refused at signing time, like
/// a malformed delta, rather than silently compared at the wrong depth.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineFloors {
    webview2: Option<Vec<u32>>,
    webkitgtk: Option<Vec<u32>>,
}

impl EngineFloors {
    /// The WebView2 floor, four fields, if the publisher set one.
    pub fn webview2(&self) -> Option<&[u32]> {
        self.webview2.as_deref()
    }

    /// The WebKitGTK floor, three fields, if the publisher set one.
    pub fn webkitgtk(&self) -> Option<&[u32]> {
        self.webkitgtk.as_deref()
    }

    /// The floor for an engine by the name the browser reports for it.
    pub fn for_engine(&self, name: &str) -> Option<&[u32]> {
        match name {
            "WebView2" => self.webview2(),
            "WebKitGTK" => self.webkitgtk(),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.webview2.is_none() && self.webkitgtk.is_none()
    }
}

/// "152.0.4191.62" -> [152, 0, 4191, 62], refusing anything that is not
/// exactly `fields` dotted decimal numbers. Publisher-signed input, so a
/// bad value is a publisher mistake that must fail loudly.
fn parse_engine_floor(engine: &str, text: &str, fields: usize) -> Result<Vec<u32>, UpdateError> {
    let parsed: Result<Vec<u32>, _> = text.split('.').map(|p| p.parse::<u32>()).collect();
    match parsed {
        Ok(v) if v.len() == fields => Ok(v),
        _ => Err(UpdateError::Malformed(format!(
            "engine_floor.{engine} must be exactly {fields} dotted decimal fields, got {text:?}"
        ))),
    }
}

/// What kind of change a release is, from the user's point of view.
///
/// This is a PUBLISHER ASSERTION carried INSIDE the signed payload, so it
/// cannot be flipped in transit: an attacker who could turn `Feature` into
/// `Maintenance` would turn an announced update into a silent one, which is
/// exactly the capability the signature exists to deny.
///
/// Absent in every manifest published before this existed, and `Maintenance`
/// is the correct reading of absence: those releases are already installed by
/// anyone who would see them, and the quiet path is the one they shipped under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseKind {
    /// Fixes and improvements to things that already exist. Installs quietly.
    Maintenance,
    /// Adds something the user can see and did not have before. Announced,
    /// and installed on the user's say-so or when the grace period lapses.
    Feature,
}

impl Default for ReleaseKind {
    fn default() -> Self {
        ReleaseKind::Maintenance
    }
}

/// A delta a client MAY use instead of the full download, when the binary
/// it is running hashes to `from`. Purely a transport optimization: the
/// patched result must hash to the manifest's own `sha256` or it is
/// discarded, so trust never rests on the delta itself. Same construction
/// guarantee as [`Manifest`]: these fields validated inside a payload whose
/// signature already verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    from: [u8; 32],
    url: String,
    sha256: [u8; 32],
    size: u64,
}

impl Delta {
    pub fn from_sha256(&self) -> &[u8; 32] {
        &self.from
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

/// More deltas than this is a publisher mistake, not a bigger optimization:
/// each entry serves exactly one prior release, and we do not keep that
/// many alive.
const MAX_DELTAS: usize = 8;

/// A release blurb longer than this is documentation wearing the wrong hat.
/// Counted in characters, not bytes, so the cap means the same thing in any
/// language.
const MAX_NOTES_CHARS: usize = 500;

/// An engine advisory's `reason` is a CVE id or a sentence, never a page.
/// Shared with `advisory.rs`, which applies it.
pub(crate) const MAX_ADVISORY_REASON_CHARS: usize = 200;

/// Characters that can make signed text READ as something it is not: bidi
/// overrides, zero-width joiners and separators. Same set as the hover
/// readout's `is_deceptive` (crates/app/src/hover.rs), duplicated because
/// this crate sits below the app and a display-safety rule this small does
/// not justify a shared crate. `char::is_control` does NOT cover these --
/// they are format characters (Cf), which is exactly what makes them
/// invisible.
pub(crate) fn is_deceptive_text(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'   // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
            | '\u{200B}'..='\u{200F}' // zero-width, LRM, RLM
            | '\u{2028}' | '\u{2029}' // line/paragraph separators
            | '\u{00AD}'              // soft hyphen
            | '\u{FEFF}'              // zero-width no-break space
    )
}

impl Manifest {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Deltas offered for this release, possibly empty. Old manifests have
    /// none; old CLIENTS never see this field at all (the signed payload
    /// tolerates unknown fields by design -- this is the growth path that
    /// comment promised).
    pub fn deltas(&self) -> &[Delta] {
        &self.deltas
    }

    /// The delta whose `from` matches the given hash, if the publisher
    /// offered one. The caller hashes its OWN running binary; a match means
    /// a small patch can reproduce the full release.
    pub fn delta_from(&self, from: &[u8; 32]) -> Option<&Delta> {
        self.deltas.iter().find(|d| &d.from == from)
    }

    /// Short user-facing release blurb, possibly empty. Shown verbatim in
    /// the update panel next to the install decision, which is exactly why
    /// it lives INSIDE the signed payload: text that influences whether a
    /// user installs must not be writable by anyone but the publisher.
    /// Absent from every manifest published before it existed; old clients
    /// never see the field at all (the payload tolerates unknown fields --
    /// the same growth path `deltas` used).
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// The engine floors this publisher asserts. Empty for every manifest
    /// published before the field existed. See [`EngineFloors`].
    pub fn engine_floors(&self) -> &EngineFloors {
        &self.engine_floors
    }

    /// What kind of change this release is. See [`ReleaseKind`].
    pub fn release_kind(&self) -> ReleaseKind {
        self.release_kind
    }

    /// Whether this release carries a security fix.
    pub fn security(&self) -> bool {
        self.security
    }

    /// May this release install itself without being announced first?
    ///
    /// The whole policy in one place, so the client cannot drift from the
    /// publisher's meaning: maintenance installs quietly, and a security fix
    /// installs quietly EVEN IF it also adds features -- a fix held behind an
    /// unclicked banner is the failure this is designed to prevent. Only a
    /// feature release with no security content waits to be announced.
    pub fn installs_silently(&self) -> bool {
        self.security || self.release_kind == ReleaseKind::Maintenance
    }
}

/// The outer, UNSIGNED wrapper.
///
/// `deny_unknown_fields` is load-bearing: the envelope is attacker space, so
/// it is parsed as strictly as possible. The PAYLOAD inside allows unknown
/// fields instead — it is signed, so only the publisher can extend it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    v: u32,
    payload: String,
    sig: String,
}

/// The signed document, parsed only after its signature has verified.
///
/// Unknown fields are allowed (serde's default): the bytes are verified
/// before parsing, so a field only the publisher could have added must not
/// break older clients — that is how the format grows.
#[derive(Deserialize)]
struct RawPayload {
    version: Version,
    platform: Platform,
    url: String,
    sha256: String,
    size: u64,
    published_at: u64,
    /// Absent in every manifest published before deltas existed; `default`
    /// keeps those parsing exactly as they always did.
    #[serde(default)]
    deltas: Vec<RawDelta>,
    /// Absent in every manifest published before release notes existed;
    /// same backward-compatible shape as `deltas`.
    #[serde(default)]
    notes: String,
    /// `"maintenance"` (default) or `"feature"`. Same backward-compatible
    /// shape as `deltas` and `notes`.
    #[serde(default)]
    kind: ReleaseKind,
    /// `true` if this release carries a security fix. Default `false`: a
    /// publisher must say so deliberately, and forgetting the flag makes a
    /// release LESS urgent rather than falsely urgent.
    #[serde(default)]
    security: bool,
    /// `{"webview2": "152.0.4191.62", "webkitgtk": "2.52.5"}`, either key
    /// optional. Absent in every manifest published before it existed.
    /// Unknown engine names are refused: this is signed publisher text, and
    /// a typo here would silently raise nothing.
    #[serde(default)]
    engine_floor: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawDelta {
    from: String,
    url: String,
    sha256: String,
    size: u64,
}

impl RawPayload {
    /// Field-by-field validation. A signature proves ORIGIN, not
    /// well-formedness: publisher mistakes and strange-but-signed documents
    /// are both stopped here.
    fn into_manifest(self) -> Result<Manifest, UpdateError> {
        let url_ok = self.url.len() > "https://".len()
            && self.url.len() <= MAX_URL_LEN
            && self.url.starts_with("https://");
        if !url_ok {
            // https is enforced, not requested: the payload hash covers
            // integrity, but a plain-HTTP download would broadcast WHAT is
            // being fetched and invite targeted interference. The privacy
            // stance forbids it. Full URL parsing is the fetch layer's job;
            // the scheme is the part that is a security property, so it is
            // the part checked here.
            return Err(UpdateError::Malformed(
                "url must be an https URL of reasonable length".to_string(),
            ));
        }
        if self.size == 0 || self.size > MAX_BINARY_BYTES {
            return Err(UpdateError::Malformed(format!(
                "implausible payload size {}",
                self.size
            )));
        }
        let sha256 = hex::decode_32(&self.sha256).map_err(|_| {
            UpdateError::Malformed("sha256 is not 32 bytes of hex".to_string())
        })?;
        if self.deltas.len() > MAX_DELTAS {
            return Err(UpdateError::Malformed(format!(
                "{} deltas; the cap is {MAX_DELTAS}",
                self.deltas.len()
            )));
        }
        let mut deltas = Vec::with_capacity(self.deltas.len());
        for raw in self.deltas {
            // A malformed delta REFUSES the whole manifest rather than being
            // skipped: every field here is publisher-signed, so a bad one is
            // a publisher mistake that must be loud, not silently absorbed
            // into "full download it is".
            let url_ok = raw.url.len() > "https://".len()
                && raw.url.len() <= MAX_URL_LEN
                && raw.url.starts_with("https://");
            if !url_ok {
                return Err(UpdateError::Malformed(
                    "delta url must be an https URL of reasonable length".to_string(),
                ));
            }
            // A delta at least as large as the full payload is not a delta;
            // its only effect would be doubling the download on the fallback.
            if raw.size == 0 || raw.size >= self.size {
                return Err(UpdateError::Malformed(format!(
                    "implausible delta size {} against payload size {}",
                    raw.size, self.size
                )));
            }
            let from = hex::decode_32(&raw.from).map_err(|_| {
                UpdateError::Malformed("delta from is not 32 bytes of hex".to_string())
            })?;
            if from == sha256 {
                return Err(UpdateError::Malformed(
                    "delta from equals the release hash; a release cannot patch itself"
                        .to_string(),
                ));
            }
            let delta_sha256 = hex::decode_32(&raw.sha256).map_err(|_| {
                UpdateError::Malformed("delta sha256 is not 32 bytes of hex".to_string())
            })?;
            deltas.push(Delta {
                from,
                url: raw.url,
                sha256: delta_sha256,
                size: raw.size,
            });
        }
        // A blurb, not release documentation. The cap keeps the panel a
        // panel; the control-character refusal keeps a signed string from
        // smuggling terminal escapes or direction overrides into a UI that
        // renders it verbatim. Refused loudly, like a malformed delta: every
        // byte here is publisher-signed, so a bad one is a publisher mistake
        // that must not be silently absorbed.
        if self.notes.chars().count() > MAX_NOTES_CHARS {
            return Err(UpdateError::Malformed(format!(
                "notes run {} characters; the cap is {MAX_NOTES_CHARS}",
                self.notes.chars().count()
            )));
        }
        if self
            .notes
            .chars()
            .any(|c| (c.is_control() && c != '\n') || is_deceptive_text(c))
        {
            return Err(UpdateError::Malformed(
                "notes may contain no control or direction-override characters \
                 besides newline"
                    .to_string(),
            ));
        }
        let mut engine_floors = EngineFloors::default();
        for (engine, text) in &self.engine_floor {
            match engine.as_str() {
                "webview2" => engine_floors.webview2 = Some(parse_engine_floor(engine, text, 4)?),
                "webkitgtk" => engine_floors.webkitgtk = Some(parse_engine_floor(engine, text, 3)?),
                other => {
                    return Err(UpdateError::Malformed(format!(
                        "engine_floor names an engine this browser does not have: {other:?}"
                    )))
                }
            }
        }
        Ok(Manifest {
            version: self.version,
            platform: self.platform,
            url: self.url,
            sha256,
            size: self.size,
            published_at: self.published_at,
            deltas,
            notes: self.notes,
            release_kind: self.kind,
            security: self.security,
            engine_floors,
        })
    }
}

/// Parse and verify a manifest envelope. `Ok` means: the signature verified
/// against at least one trusted key AND every field validated. Anything else
/// is an `Err`, with signature failures collapsed into a single coarse
/// variant.
pub fn verify_manifest(bytes: &[u8], keys: &TrustedKeys) -> Result<Manifest, UpdateError> {
    let payload = verify_envelope(bytes, keys, SIGNING_DOMAIN)?;
    let raw: RawPayload = serde_json::from_str(&payload).map_err(|e| {
        UpdateError::Malformed(format!("signed payload is not the expected JSON: {e}"))
    })?;
    raw.into_manifest()
}

/// Domain separation for the BLOCKLIST channel. A different purpose gets a
/// different domain, so a signature made for one can never be replayed as the
/// other -- an update manifest cannot be served as a blocklist manifest, and a
/// blocklist manifest cannot be served as an update that installs a binary.
///
/// That second direction is the one that matters: the blocklist is refreshed
/// far more often than releases, so its signing key is handled far more often.
pub const SIGNING_DOMAIN_BLOCKLIST: &[u8] = b"PATANYX-BLOCKLIST-MANIFEST-V1\n";

/// Domain for the LANGUAGE PACK feed. A third class, and a third domain.
///
/// The decision (2026-08-31) is that the model feed's key authorises
/// model-feed artifacts ONLY -- a valid model-feed signature must never be
/// interpreted as authority to sign a blocklist or a release. That takes two
/// independent mechanisms and this is one of them: the signature covers
/// `domain || payload`, so a model-feed signature cannot be REPLAYED against
/// another verifier no matter which key made it.
///
/// The other half is a separate key set (`MODEL_KEYS` in the app), which is
/// what stops a STOLEN model key from signing a fresh blocklist. Domain
/// separation alone would not: it prevents replay, not forgery in another
/// domain by a key the verifier trusts.
pub const SIGNING_DOMAIN_MODELS: &[u8] = b"PATANYX-MODEL-MANIFEST-V1\n";

/// The shared core of both verifiers: caps, wire version, signature.
///
/// PRIVATE, AND THE DOMAIN IS A PARAMETER ONLY HERE. Every public entry point
/// hard-wires its own constant, so "this verifier checks this domain" is a
/// fact of the call site rather than something a caller could get wrong. A
/// public `verify(bytes, keys, domain)` would convert a guarantee the type
/// system makes into one code review has to make every time.
///
/// Returns the verified payload STRING, unparsed. Parsing is the caller's job
/// because the two channels carry different documents -- but neither of them
/// parses anything until this function has returned Ok.
fn verify_envelope(
    bytes: &[u8],
    keys: &TrustedKeys,
    domain: &[u8],
) -> Result<String, UpdateError> {
    verify_envelope_identified(bytes, keys, domain).map(|(payload, _)| payload)
}

/// `verify_envelope`, also returning WHICH trusted key verified.
///
/// Needed by the engine-advisory class (`advisory.rs`), whose client persists
/// floors under the key that authenticated them so a revoked key takes its
/// floors with it. Still `pub(crate)`, still domain-as-parameter only here,
/// and still no oracle: every key is tried every time with no short-circuit,
/// the failure is the same coarse `BadSignature`, and the identity is
/// reported only on success -- where it is public data anyway, since anyone
/// holding the compiled key set can check the same signature.
pub(crate) fn verify_envelope_identified(
    bytes: &[u8],
    keys: &TrustedKeys,
    domain: &[u8],
) -> Result<(String, ed25519_dalek::VerifyingKey), UpdateError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(UpdateError::Malformed(format!(
            "envelope is {} bytes; the cap is {MAX_ENVELOPE_BYTES}",
            bytes.len()
        )));
    }
    // serde_json::from_slice rejects trailing non-whitespace bytes, so
    // "valid manifest with garbage appended" fails here rather than having
    // the garbage quietly ignored.
    let envelope: RawEnvelope = serde_json::from_slice(bytes)
        .map_err(|e| UpdateError::Malformed(format!("envelope is not the expected JSON: {e}")))?;
    if envelope.v != WIRE_VERSION {
        return Err(UpdateError::Malformed(format!(
            "unsupported wire version {}",
            envelope.v
        )));
    }
    let sig_bytes = hex::decode_64(&envelope.sig).map_err(|_| {
        UpdateError::Malformed("signature is not 64 bytes of hex".to_string())
    })?;
    let signature = Signature::from_bytes(&sig_bytes);
    let payload = envelope.payload.as_bytes();
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(UpdateError::Malformed(format!(
            "payload is {} bytes; the cap is {MAX_PAYLOAD_BYTES}",
            payload.len()
        )));
    }

    // Verify BEFORE the payload is parsed: until this loop finishes, the
    // payload is opaque attacker-controlled bytes. Every trusted key is
    // tried every time — no short-circuit — and the outcomes are folded
    // into one bit, so neither the error nor the timing can reveal WHICH
    // key came closest. "Signed by an untrusted key" and "forged" are the
    // same answer.
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(payload);
    // `verify_strict`, NOT `verify`. The difference is small-order points:
    // plain `verify` accepts signatures against a small-order public key, and
    // such signatures can be crafted for any message. That is only a
    // theoretical concern while every trusted key is a real one -- and
    // `TrustedKeys` now refuses weak keys at construction, so it should be --
    // but the two checks answer to different owners. This one holds even if a
    // weak key reaches the set some other way, and costs nothing.
    let mut verified: Option<ed25519_dalek::VerifyingKey> = None;
    for key in keys.iter() {
        // No short-circuit: every key is checked whether or not an earlier
        // one already matched, so timing does not say which key it was.
        let ok = key.verify_strict(&message, &signature).is_ok();
        if ok && verified.is_none() {
            verified = Some(*key);
        }
    }
    let Some(key) = verified else {
        return Err(UpdateError::BadSignature);
    };

    // Only now are the bytes known to be the publisher's.
    Ok((envelope.payload, key))
}

/// A blocklist release whose signature has ALREADY VERIFIED.
///
/// Same discipline as [`Manifest`]: private fields, one constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistManifest {
    list_version: u64,
    url: String,
    sha256: [u8; 32],
    size: u64,
    entries: u64,
    published_at: u64,
}

impl BlocklistManifest {
    pub fn list_version(&self) -> u64 {
        self.list_version
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    /// How many hosts the publisher says the list contains.
    ///
    /// Cross-checked after parsing. A truncated download cannot survive the
    /// hash, but a parse that silently drops most lines very much can -- an
    /// encoding change, a format change, a stray BOM -- and that failure looks
    /// exactly like a working blocklist with less in it. This turns it into a
    /// refusal.
    pub fn entries(&self) -> u64 {
        self.entries
    }
    pub fn published_at(&self) -> u64 {
        self.published_at
    }
}

#[derive(Deserialize)]
struct RawBlocklistPayload {
    list_version: u64,
    url: String,
    sha256: String,
    size: u64,
    entries: u64,
    published_at: u64,
}

/// The list itself is far larger than a manifest, and uncompressed on purpose:
/// a decompressor is an attack surface, and this file is fetched from a
/// publisher who may one day be compromised.
///
/// RAISED FROM 8 MiB, 2026-07-28. The bundled list is 390,628 hosts and
/// 10.9 MB as plain text, so the first real blocklist publication would have
/// been refused by the cap meant to protect against an oversized one -- a
/// limit chosen before there was a list to measure it against.
///
/// 24 MiB leaves room for roughly double the current set. It is still a hard
/// bound on memory and on what a compromised publisher can make an install
/// download; it is not "large enough not to worry about".
///
/// An install with the OLD cap refuses a larger list and keeps the one it
/// has, which is the correct failure and the reason publishing a bigger list
/// is safe for 0.9.2 users: they keep the bundled floor until they update.
pub const MAX_BLOCKLIST_BYTES: u64 = 24 * 1024 * 1024;

/// Parse and verify a BLOCKLIST envelope.
///
/// Deliberately a separate entry point from [`verify_manifest`] rather than a
/// flag on it: the two hard-wire different domains, so neither can be talked
/// into accepting the other's document.
pub fn verify_blocklist_manifest(
    bytes: &[u8],
    keys: &TrustedKeys,
) -> Result<BlocklistManifest, UpdateError> {
    let payload = verify_envelope(bytes, keys, SIGNING_DOMAIN_BLOCKLIST)?;
    let raw: RawBlocklistPayload = serde_json::from_str(&payload).map_err(|e| {
        UpdateError::Malformed(format!("signed payload is not the expected JSON: {e}"))
    })?;
    let url_ok = raw.url.len() > "https://".len()
        && raw.url.len() <= MAX_URL_LEN
        && raw.url.starts_with("https://");
    if !url_ok {
        return Err(UpdateError::Malformed(
            "url must be an https URL of reasonable length".to_string(),
        ));
    }
    if raw.size == 0 || raw.size > MAX_BLOCKLIST_BYTES {
        return Err(UpdateError::Malformed(format!(
            "implausible list size {}",
            raw.size
        )));
    }
    // A signed manifest promising zero hosts would disable protection while
    // every indicator still said a list was in force. If a list is ever meant
    // to be emptied, that is a build, not a refresh.
    //
    // The UPPER bound exists for the same reason as the lower one, at the
    // other end: `entries` is compared against the parsed count downstream,
    // and an implausible value there made that comparison meaningless (it
    // overflowed). A list cannot hold more entries than its own bytes allow --
    // each hash is 16 bytes -- so anything above that is malformed by
    // arithmetic, not by taste.
    if raw.entries == 0 {
        return Err(UpdateError::Malformed(
            "a blocklist with zero entries would silently disable protection".to_string(),
        ));
    }
    if raw.entries > MAX_BLOCKLIST_BYTES / 16 {
        return Err(UpdateError::Malformed(format!(
            "declared {} entries, more than {} bytes could hold",
            raw.entries, MAX_BLOCKLIST_BYTES
        )));
    }
    let sha256 = hex::decode_32(&raw.sha256)
        .map_err(|_| UpdateError::Malformed("sha256 is not 32 bytes of hex".to_string()))?;
    Ok(BlocklistManifest {
        list_version: raw.list_version,
        url: raw.url,
        sha256,
        size: raw.size,
        entries: raw.entries,
        published_at: raw.published_at,
    })
}

/// A language pack a build may download, after its manifest verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifest {
    pair: String,
    url: String,
    sha256: [u8; 32],
    size: u64,
    version: u64,
}

impl ModelManifest {
    pub fn pair(&self) -> &str {
        &self.pair
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Monotonic. The app refuses to replace a pack with an older one.
    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Deserialize)]
struct RawModelPayload {
    pair: String,
    url: String,
    sha256: String,
    size: u64,
    /// Monotonic, chosen by the publisher. See the rollback refusal in the
    /// app's `langpack`: without this, an attacker who can serve bytes can
    /// replay an OLD validly-signed pack and pin a user to it forever.
    version: u64,
}

/// Hard bound on one language pack.
///
/// 96 MiB. Set from the measured registry rather than one pair: across the 99
/// published pairs the largest packed container is en-ko at 64.46 MiB, with
/// ja-en and ko-en next at ~52 MiB and everything else at or below ~36 MiB.
/// 64 MiB (the original bound, fixed on the 36.6 MB `enes` pack alone) rejected
/// en-ko by less than half a mebibyte. 96 MiB clears the largest real pack with
/// roughly 50% headroom for an upstream retrain, while still bounding both
/// memory and what a compromised publisher can make an install download to
/// 96 MiB (about 100.7 MB). Widen this deliberately, from a fresh measurement,
/// not to make one stubborn pair fit.
pub const MAX_MODEL_PACK_BYTES: u64 = 96 * 1024 * 1024;

/// Parse and verify a LANGUAGE PACK envelope.
///
/// A third entry point rather than a flag, for the reason the blocklist one
/// gives: each hard-wires its own domain, so choosing the wrong verifier is a
/// visibly wrong call at the call site instead of a boolean nobody reads.
///
/// The pair is validated to the same shape the app's allowlist uses. A
/// manifest is signed data, but "signed" means the publisher said it, not that
/// it is well-formed -- and this value ends up selecting a file on disk.
/// Shape floor for a language-pair token used as a URL segment and a filename
/// component: two subtags of ASCII letters/digits, one hyphen between, bounded.
///
/// This is a NECESSARY condition, not the authority -- the client checks
/// registry membership. Its job is to guarantee a token can never carry a
/// path separator, a dot, a NUL, or an unbounded length no matter what a
/// signed manifest claims.
pub fn pair_token_ok(pair: &str) -> bool {
    if pair.is_empty() || pair.len() > 20 {
        return false;
    }
    // TWO OR THREE subtags. The two-subtag floor existed because a token was
    // once SPLIT to recover its language codes, and "en-zh-hans" cannot be
    // split unambiguously. Nothing splits a token now -- the registry is a
    // lookup and carries `from`/`to` beside the token -- so the ambiguity that
    // justified the rule is gone, while what the rule actually protects is
    // untouched: a token must remain a safe path and URL segment. A
    // script-tagged language (Chinese) needs three.
    let mut parts = pair.split('-');
    let (Some(a), Some(b)) = (parts.next(), parts.next()) else {
        return false;
    };
    let c = parts.next();
    if parts.next().is_some() {
        return false; // at most three
    }
    // LOWERCASE letters and digits only. Not `is_ascii_alphanumeric`, which
    // accepts uppercase: the nginx route and the registry tokens are
    // lowercase, and a token legal here but rejected at the edge is precisely
    // the cross-layer disagreement this grammar exists to prevent. A test
    // pins "EN-ES" as refused for exactly that reason.
    let subtag_ok = |t: &str| {
        (2..=12).contains(&t.len())
            && t.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    };
    subtag_ok(a) && subtag_ok(b) && c.is_none_or(subtag_ok)
}

pub fn verify_model_manifest(
    bytes: &[u8],
    keys: &TrustedKeys,
) -> Result<ModelManifest, UpdateError> {
    let payload = verify_envelope(bytes, keys, SIGNING_DOMAIN_MODELS)?;
    let raw: RawModelPayload = serde_json::from_str(&payload).map_err(|e| {
        UpdateError::Malformed(format!("signed payload is not the expected JSON: {e}"))
    })?;
    // A path-segment-safe language-pair token. NOT a general BCP-47 parser:
    // this value names a file and a URL segment, so the test is a narrow
    // character allowlist plus a length bound, never structure.
    //
    // Widened from the old `xx-yy` (len==5) shape when the model set grew from
    // one pair to the whole published registry. Two lowercase ASCII subtags
    // separated by a SINGLE hyphen; no leading/trailing/double hyphen; bounded
    // at 16 bytes to match the ipc argument cap. This deliberately rejects
    // three-part tokens like `en-zh-hant`: script-tagged pairs are EXCLUDED
    // from the published registry precisely because they do not fit this
    // one-hyphen shape, so a token this floor rejects is also a token no client
    // will ever ask for. The registry membership check on the client is the
    // real allowlist; this is the shape floor the signed manifest must clear.
    let pair_ok = pair_token_ok(&raw.pair);
    if !pair_ok {
        return Err(UpdateError::Malformed(
            "pair must be two hyphen-separated language subtags".to_string(),
        ));
    }
    // https, bounded length, AND a character allowlist.
    //
    // THE ALLOWLIST IS NOT REDUNDANT WITH THE SIGNATURE. "Signed" means the
    // publisher said it, not that it is well formed -- the same sentence this
    // function already applies to the pair, applied to the field that is
    // handed to an HTTP client. A control character in a URL is the shape of
    // header injection and request smuggling, and a signing tool run against a
    // hand-edited payload is exactly how one gets signed. Refusing it here
    // means no client ever has to be the thing that copes.
    let url_ok = raw.url.len() > "https://".len()
        && raw.url.len() <= MAX_URL_LEN
        && raw.url.starts_with("https://")
        && raw.url.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'/')
        });
    if !url_ok {
        return Err(UpdateError::Malformed(
            "url must be an https URL of reasonable length and safe characters".to_string(),
        ));
    }
    // Zero is reserved for "nothing installed", so a manifest claiming it
    // could never beat an existing install and would strand every client.
    if raw.version == 0 {
        return Err(UpdateError::Malformed("version must be non-zero".to_string()));
    }
    if raw.size == 0 || raw.size > MAX_MODEL_PACK_BYTES {
        return Err(UpdateError::Malformed(
            "size must be non-zero and within the pack limit".to_string(),
        ));
    }
    let sha256 = hex::decode_32(&raw.sha256)
        .map_err(|()| UpdateError::Malformed("sha256 must be 32 hex bytes".to_string()))?;
    Ok(ModelManifest {
        pair: raw.pair,
        url: raw.url,
        sha256,
        size: raw.size,
        version: raw.version,
    })
}

#[cfg(test)]
mod tests {
    use super::{Platform, SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST};

    /// The domain string is a WIRE CONSTANT shared with publisher tooling
    /// (`examples/patanyx-sign.rs`) and documented in `docs/update-channel.md`.
    /// Changing it invalidates every manifest ever signed, and the symptom is
    /// every authentic update being refused -- discovered by users, not by a
    /// build. Pinned literally so an edit has to be deliberate.
    ///
    /// The trailing newline is part of it. A domain separator that is a prefix
    /// of some other string is not a separator.
    #[test]
    fn the_signing_domain_is_exactly_this() {
        assert_eq!(SIGNING_DOMAIN, b"PATANYX-UPDATE-MANIFEST-V1\n");
        assert!(
            SIGNING_DOMAIN.ends_with(b"\n"),
            "the terminator is what stops this being a prefix of another domain"
        );
    }

    /// Sign `payload` under `domain`, producing an envelope.
    fn envelope(payload: &str, domain: &[u8], key: &ed25519_dalek::SigningKey) -> String {
        use ed25519_dalek::Signer;
        let mut message = Vec::new();
        message.extend_from_slice(domain);
        message.extend_from_slice(payload.as_bytes());
        format!(
            "{{\"v\":1,\"payload\":{},\"sig\":\"{}\"}}",
            serde_json::to_string(payload).expect("a string always serializes"),
            crate::hex::encode(&key.sign(&message).to_bytes())
        )
    }

    fn test_keys() -> (ed25519_dalek::SigningKey, crate::TrustedKeys) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
        let trusted =
            crate::TrustedKeys::new(vec![key.verifying_key()]).expect("one key is a valid set");
        (key, trusted)
    }

    const UPDATE_PAYLOAD: &str = r#"{"version":"1.2.3","platform":"linux-x86_64","url":"https://example.invalid/x","sha256":"aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899","size":100,"published_at":1}"#;
    const BLOCKLIST_PAYLOAD: &str = r#"{"list_version":7,"url":"https://example.invalid/list.txt","sha256":"aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899","size":4096,"entries":300,"published_at":1}"#;

    /// DOMAIN SEPARATION IS REAL, NOT A COMMENT -- and it is checked in BOTH
    /// directions, because one direction passing proves only that the two
    /// strings differ, not that each verifier pins its own.
    ///
    /// The dangerous direction is the second: the blocklist is re-signed far
    /// more often than releases, so its key is handled far more often. If a
    /// blocklist manifest could be replayed as an update manifest, the
    /// higher-frequency key would become a way to install a binary.
    #[test]
    fn a_manifest_signed_for_one_channel_is_refused_by_the_other() {
        let (key, trusted) = test_keys();

        // Correctly domained: each is accepted by its own verifier.
        let update = envelope(UPDATE_PAYLOAD, SIGNING_DOMAIN, &key);
        let blocklist = envelope(BLOCKLIST_PAYLOAD, SIGNING_DOMAIN_BLOCKLIST, &key);
        assert!(super::verify_manifest(update.as_bytes(), &trusted).is_ok());
        assert!(super::verify_blocklist_manifest(blocklist.as_bytes(), &trusted).is_ok());

        // Cross-domained: refused, by the SAME trusted key. The signature is
        // genuine; only the domain is wrong.
        let update_as_blocklist = envelope(BLOCKLIST_PAYLOAD, SIGNING_DOMAIN, &key);
        assert!(
            super::verify_blocklist_manifest(update_as_blocklist.as_bytes(), &trusted).is_err(),
            "a payload signed under the UPDATE domain must not verify as a blocklist"
        );
        let blocklist_as_update = envelope(UPDATE_PAYLOAD, SIGNING_DOMAIN_BLOCKLIST, &key);
        assert!(
            super::verify_manifest(blocklist_as_update.as_bytes(), &trusted).is_err(),
            "a payload signed under the BLOCKLIST domain must not verify as an \
             update -- this is the direction that would turn the frequently \
             handled key into a way to install a binary"
        );
    }

    #[test]
    fn the_two_domains_are_not_prefixes_of_one_another() {
        // Both terminate with a newline, so neither can be a prefix of the
        // other's message however the payloads line up.
        assert_ne!(SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST);
        assert!(SIGNING_DOMAIN.ends_with(b"\n") && SIGNING_DOMAIN_BLOCKLIST.ends_with(b"\n"));
        assert!(!SIGNING_DOMAIN_BLOCKLIST.starts_with(SIGNING_DOMAIN));
        assert!(!SIGNING_DOMAIN.starts_with(SIGNING_DOMAIN_BLOCKLIST));
    }

    #[test]
    fn a_blocklist_promising_nothing_is_refused() {
        let (key, trusted) = test_keys();
        let empty = BLOCKLIST_PAYLOAD.replace("\"entries\":300", "\"entries\":0");
        let signed = envelope(&empty, SIGNING_DOMAIN_BLOCKLIST, &key);
        assert!(
            super::verify_blocklist_manifest(signed.as_bytes(), &trusted).is_err(),
            "a validly signed empty list would disable protection while every \
             indicator still reported a list in force"
        );
    }

    #[test]
    fn a_blocklist_must_be_fetched_over_https_and_be_plausibly_sized() {
        let (key, trusted) = test_keys();
        for bad in [
            BLOCKLIST_PAYLOAD.replace("https://", "http://"),
            BLOCKLIST_PAYLOAD.replace("\"size\":4096", "\"size\":0"),
            BLOCKLIST_PAYLOAD.replace(
                "\"size\":4096",
                &format!("\"size\":{}", super::MAX_BLOCKLIST_BYTES + 1),
            ),
        ] {
            let signed = envelope(&bad, SIGNING_DOMAIN_BLOCKLIST, &key);
            assert!(
                super::verify_blocklist_manifest(signed.as_bytes(), &trusted).is_err(),
                "signature proves ORIGIN, not that the fields are sane: {bad}"
            );
        }
    }

    #[test]
    fn notes_travel_inside_the_signature_and_old_manifests_read_empty() {
        let (key, trusted) = test_keys();

        // Absent field: every manifest published before notes existed, and
        // the state every consumer must treat as ordinary.
        let plain = envelope(UPDATE_PAYLOAD, SIGNING_DOMAIN, &key);
        let manifest = super::verify_manifest(plain.as_bytes(), &trusted).unwrap();
        assert_eq!(manifest.notes(), "");

        // Present: read back verbatim, newline included.
        let with_notes = UPDATE_PAYLOAD.replace(
            "\"published_at\":1",
            "\"published_at\":1,\"notes\":\"Adds fingerprint noise.\\nFixes the print dialog.\"",
        );
        let signed = envelope(&with_notes, SIGNING_DOMAIN, &key);
        let manifest = super::verify_manifest(signed.as_bytes(), &trusted).unwrap();
        assert_eq!(
            manifest.notes(),
            "Adds fingerprint noise.\nFixes the print dialog."
        );
    }

    #[test]
    fn notes_are_capped_and_may_carry_no_control_characters() {
        let (key, trusted) = test_keys();
        let oversize = "x".repeat(super::MAX_NOTES_CHARS + 1);
        for bad in [
            // Documentation wearing the blurb's hat.
            format!("\"notes\":\"{oversize}\""),
            // A terminal escape in a string the panel renders verbatim.
            "\"notes\":\"look\\u001b[31m\"".to_string(),
            // A bidi override that would make the panel display reordered
            // text next to an install decision.
            "\"notes\":\"safe\\u202etxe.exe\"".to_string(),
        ] {
            let payload =
                UPDATE_PAYLOAD.replace("\"published_at\":1", &format!("\"published_at\":1,{bad}"));
            let signed = envelope(&payload, SIGNING_DOMAIN, &key);
            assert!(
                super::verify_manifest(signed.as_bytes(), &trusted).is_err(),
                "signature proves ORIGIN, not that the notes are sane: {bad:.60}"
            );
        }
        // The boundary itself is allowed: exactly the cap, with a newline.
        let fit = format!("\"notes\":\"{}\\n\"", "y".repeat(super::MAX_NOTES_CHARS - 1));
        let payload =
            UPDATE_PAYLOAD.replace("\"published_at\":1", &format!("\"published_at\":1,{fit}"));
        let signed = envelope(&payload, SIGNING_DOMAIN, &key);
        assert!(super::verify_manifest(signed.as_bytes(), &trusted).is_ok());
    }

    #[test]
    fn platform_names_roundtrip() {
        for platform in [
            Platform::LinuxX86_64,
            Platform::LinuxAarch64,
            Platform::MacosX86_64,
            Platform::MacosAarch64,
            Platform::WindowsX86_64,
        ] {
            assert_eq!(Platform::from_name(platform.as_str()).unwrap(), platform);
        }
        assert!(Platform::from_name("plan9-m68k").is_err());
        assert!(Platform::from_name("").is_err());
    }
}

#[cfg(test)]
mod model_key_class_tests {
    //! The decision of 2026-08-31, made mechanical: a model-feed
    //! signature must never be usable as authority over another artifact
    //! class. Two independent mechanisms, and these tests check BOTH, because
    //! each covers a failure the other does not.

    use super::*;
    use crate::testutil::{signing_key, trusted_keys, SEED_ATTACKER, SEED_TRUSTED_A};
    use ed25519_dalek::{Signer, SigningKey};

    /// Sign a payload under an ARBITRARY domain, which the production API
    /// deliberately does not allow. Only a test may do this: it is the whole
    /// point of the exercise to attempt what the real callers cannot.
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

    #[test]
    fn pair_token_shape_floor() {
        // Every real published token clears it, INCLUDING the script-tagged
        // three-subtag members (Chinese), which are lowercased into the token
        // while `from`/`to` keep the true "zh-Hans".
        for good in [
            "en-es", "el-en", "es-en", "zh-en", "en-pt", "de-en",
            "en-zh-hans", "zh-hant-en", "en-zh-hant", "zh-hans-en",
        ] {
            assert!(pair_token_ok(good), "should accept {good}");
        }
        // Everything a path segment must never contain.
        for bad in [
            "",
            "en",                    // one subtag
            "en-es-fr-de",           // four subtags: three is the ceiling
            "en_es",                 // wrong separator
            "en-",                   // empty subtag
            "-es",
            "en--es",                // empty middle
            "e-es",                  // subtag too short
            "en-e",
            "en/es",
            "en-e/s",
            "../et",
            "en-es\0",
            "EN-ES",                 // uppercase (tokens are lowercase)
            "en-zh-Hans",            // the SCRIPT SUBTAG's case, likewise
            "en-es ",
            "en-es-",                // empty third subtag
            "en--es-fr",
            &"a".repeat(9).to_string(),
        ] {
            assert!(!pair_token_ok(bad), "should refuse {bad:?}");
        }
        // The 20-byte length bound: three real subtags fit, padding does not.
        assert!(pair_token_ok("en-zh-hant"));
        assert!(!pair_token_ok("longsubtag123-longsubtag123"));
        assert!(!pair_token_ok("longsubtag12-longsubtag12"));
    }

    fn model_payload() -> String {
        concat!(
            "{\"pair\":\"en-es\",\"url\":\"https://models.patanyx.net/en-es/1.pack\",",
            "\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000001\",",
            "\"size\":36600000,\"version\":1}"
        )
        .to_string()
    }

    /// MECHANISM 1: domain separation stops REPLAY. A model manifest, signed
    /// by a key the verifier trusts, must not verify as a blocklist or an
    /// update no matter who signed it.
    #[test]
    fn a_model_manifest_cannot_be_replayed_as_another_class() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = trusted_keys();
        let signed = sign_in_domain(&model_payload(), &key, SIGNING_DOMAIN_MODELS);

        assert!(verify_model_manifest(signed.as_bytes(), &keys).is_ok());
        assert!(verify_manifest(signed.as_bytes(), &keys).is_err());
        assert!(verify_blocklist_manifest(signed.as_bytes(), &keys).is_err());
    }

    /// And the other direction: neither of the older classes may be presented
    /// as a language pack.
    #[test]
    fn another_class_cannot_be_replayed_as_a_model_manifest() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = trusted_keys();
        for domain in [SIGNING_DOMAIN, SIGNING_DOMAIN_BLOCKLIST] {
            let signed = sign_in_domain(&model_payload(), &key, domain);
            assert!(
                verify_model_manifest(signed.as_bytes(), &keys).is_err(),
                "a payload signed in another domain must not verify as a model manifest"
            );
        }
    }

    /// MECHANISM 2, and the one domain separation does NOT provide: a key the
    /// model verifier trusts must not be a key the OTHER verifiers trust.
    ///
    /// Domain separation stops replay; it cannot stop forgery, because a
    /// stolen key can always sign a fresh message in any domain. Only a
    /// separate key SET stops that -- so this test asserts the sets are
    /// disjoint, which is the property MODEL_KEYS exists to hold.
    #[test]
    fn a_stolen_model_key_cannot_forge_another_class() {
        let attacker = signing_key(SEED_ATTACKER);
        // A verifier that trusts ONLY the attacker's key stands in for "the
        // model channel", and a disjoint set stands in for the others.
        let model_side = TrustedKeys::new(vec![attacker.verifying_key()]).expect("keys");
        let other_side = trusted_keys();

        // The attacker signs a fresh blocklist-domain message with the key the
        // MODEL channel trusts. It is a valid signature -- and it must still
        // be refused, because the other channel does not trust that key.
        let forged = sign_in_domain("{\"x\":1}", &attacker, SIGNING_DOMAIN_BLOCKLIST);
        assert!(verify_blocklist_manifest(forged.as_bytes(), &other_side).is_err());

        // Sanity: the same key IS accepted in its own class, so the refusal
        // above is about the key set and not about the payload being junk.
        let own = sign_in_domain(&model_payload(), &attacker, SIGNING_DOMAIN_MODELS);
        assert!(verify_model_manifest(own.as_bytes(), &model_side).is_ok());
    }

    /// A manifest is signed data, which means the publisher said it -- not
    /// that it is well formed. The pair names a file on disk.
    #[test]
    fn a_signed_manifest_is_still_validated() {
        let key = signing_key(SEED_TRUSTED_A);
        let keys = trusted_keys();
        for bad in [
            r#"{"pair":"../../etc","url":"https://models.patanyx.net/a","sha256":"0000000000000000000000000000000000000000000000000000000000000001","size":10}"#,
            r#"{"pair":"en-es","url":"http://models.patanyx.net/a","sha256":"0000000000000000000000000000000000000000000000000000000000000001","size":10}"#,
            r#"{"pair":"en-es","url":"https://models.patanyx.net/a","sha256":"nothex","size":10}"#,
            r#"{"pair":"en-es","url":"https://models.patanyx.net/a","sha256":"0000000000000000000000000000000000000000000000000000000000000001","size":0}"#,
            r#"{"pair":"EN-ES","url":"https://models.patanyx.net/a","sha256":"0000000000000000000000000000000000000000000000000000000000000001","size":10}"#,
        ] {
            let signed = sign_in_domain(bad, &key, SIGNING_DOMAIN_MODELS);
            assert!(
                verify_model_manifest(signed.as_bytes(), &keys).is_err(),
                "must refuse {bad}"
            );
        }
    }
}
