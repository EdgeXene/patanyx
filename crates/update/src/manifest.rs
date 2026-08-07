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

/// Characters that can make signed text READ as something it is not: bidi
/// overrides, zero-width joiners and separators. Same set as the hover
/// readout's `is_deceptive` (crates/app/src/hover.rs), duplicated because
/// this crate sits below the app and a display-safety rule this small does
/// not justify a shared crate. `char::is_control` does NOT cover these --
/// they are format characters (Cf), which is exactly what makes them
/// invisible.
fn is_deceptive_text(c: char) -> bool {
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
        Ok(Manifest {
            version: self.version,
            platform: self.platform,
            url: self.url,
            sha256,
            size: self.size,
            published_at: self.published_at,
            deltas,
            notes: self.notes,
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
    let mut verified = false;
    for key in keys.iter() {
        verified |= key.verify_strict(&message, &signature).is_ok();
    }
    if !verified {
        return Err(UpdateError::BadSignature);
    }

    // Only now are the bytes known to be the publisher's.
    Ok(envelope.payload)
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
