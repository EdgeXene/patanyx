//! Signed executable add-on metadata. Constructors authenticate before parsing.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{hex, manifest::verify_envelope_identified, TrustedKeys, UpdateError, Version};

pub const SIGNING_DOMAIN_ADDON_MANIFEST: &[u8] = b"PATANYX-ADDON-MANIFEST-V1\n";
pub const SIGNING_DOMAIN_ADDON_INDEX: &[u8] = b"PATANYX-ADDON-INDEX-V1\n";
pub const MAX_ADDON_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_ADDON_PAYLOAD_BYTES: usize = 8 * 1024;
pub const MAX_ADDON_FILES: usize = 256;
pub const MAX_ADDON_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_ADDON_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

/// Kept as separate pieces in the public tree, including test fixtures.
pub fn addon_mark() -> String {
    ["PATANYX", "CLOSED", "ADDON"].join("-")
}

fn malformed() -> UpdateError {
    UpdateError::Malformed("invalid add-on metadata".into())
}

pub fn valid_addon_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !device_name(id)
}

fn device_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix)
                .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
        })
}

/// Portable literal paths: percent escapes, URL syntax, Windows aliases and
/// separators are never interpreted. Filesystem callers must also refuse links.
pub fn valid_addon_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 128
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.ends_with('.') && !device_name(s))
}

fn version(text: &str) -> Result<Version, UpdateError> {
    let parsed: Version = text.parse()?;
    // One spelling per on-disk version, including no leading zero aliases.
    if parsed.to_string() != text {
        return Err(malformed());
    }
    Ok(parsed)
}

fn compatibility(host_api: u32, data_format: &str) -> Result<(), UpdateError> {
    if host_api != 1 || data_format != "text-pages-v1" {
        return Err(malformed());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddonFile {
    path: String,
    sha256: [u8; 32],
    size: u64,
}

impl AddonFile {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<(), UpdateError> {
        verify_addon_bytes(bytes, self.size, &self.sha256)
    }
}

pub fn verify_addon_bytes(bytes: &[u8], size: u64, hash: &[u8; 32]) -> Result<(), UpdateError> {
    if bytes.len() as u64 != size {
        return Err(UpdateError::PayloadLength {
            expected: size,
            actual: bytes.len() as u64,
        });
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if &actual != hash {
        return Err(UpdateError::PayloadHash);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddonManifest {
    id: String,
    name: String,
    version: Version,
    host_api: u32,
    data_format: String,
    capabilities: Vec<String>,
    files: Vec<AddonFile>,
}

impl AddonManifest {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn host_api(&self) -> u32 {
        self.host_api
    }
    pub fn data_format(&self) -> &str {
        &self.data_format
    }
    pub fn premium(&self) -> bool {
        true
    }
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }
    pub fn files(&self) -> &[AddonFile] {
        &self.files
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: String,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    id: String,
    name: String,
    version: String,
    host_api: u32,
    data_format: String,
    premium: bool,
    capabilities: Vec<String>,
    mark: String,
    files: Vec<RawFile>,
}

pub fn verify_addon_manifest(
    bytes: &[u8],
    keys: &TrustedKeys,
) -> Result<AddonManifest, UpdateError> {
    let (payload, _) = verify_envelope_identified(bytes, keys, SIGNING_DOMAIN_ADDON_MANIFEST)?;
    let raw: RawManifest = serde_json::from_str(&payload).map_err(|_| malformed())?;
    compatibility(raw.host_api, &raw.data_format)?;
    let version = version(&raw.version)?;
    if !valid_addon_id(&raw.id)
        || raw.name.is_empty()
        || raw.name.chars().count() > 80
        || raw.name.chars().any(char::is_control)
        || !raw.premium
        || raw.mark != addon_mark()
        || raw.files.is_empty()
        || raw.files.len() > MAX_ADDON_FILES
    {
        return Err(malformed());
    }
    let mut capabilities = BTreeSet::new();
    for cap in &raw.capabilities {
        if !matches!(
            cap.as_str(),
            // `notebook`: notes delivered from the Assistant, and the
            // trackers (host-api-1-notebook.md). Known to every build with
            // the add-on host so a manifest naming it is valid everywhere;
            // only builds with the Assistant route what it grants.
            "text_pages" | "vault_notes_read" | "selection_receive" | "notebook"
        ) || !capabilities.insert(cap)
        {
            return Err(malformed());
        }
    }
    if !capabilities.contains(&"text_pages".to_string()) {
        return Err(malformed());
    }
    let mut paths = BTreeSet::new();
    let mut spellings = BTreeMap::new();
    let mut files = Vec::new();
    let mut total = 0u64;
    for file in raw.files {
        if !valid_addon_path(&file.path)
            || !paths.insert(file.path.to_ascii_lowercase())
            || file.size > MAX_ADDON_FILE_BYTES
        {
            return Err(malformed());
        }
        for end in file
            .path
            .match_indices('/')
            .map(|(i, _)| i)
            .chain(std::iter::once(file.path.len()))
        {
            let prefix = &file.path[..end];
            if spellings
                .insert(prefix.to_ascii_lowercase(), prefix.to_owned())
                .is_some_and(|old| old != prefix)
            {
                return Err(malformed());
            }
        }
        total = total.checked_add(file.size).ok_or_else(malformed)?;
        if total > MAX_ADDON_TOTAL_BYTES {
            return Err(malformed());
        }
        files.push(AddonFile {
            path: file.path,
            size: file.size,
            sha256: hex::decode_32(&file.sha256).map_err(|_| malformed())?,
        });
    }
    // A path cannot be both a file and a directory, even with different casing.
    for path in &paths {
        for (i, _) in path.match_indices('/') {
            if paths.contains(&path[..i]) {
                return Err(malformed());
            }
        }
    }
    if !files.iter().any(|f| f.path == "index.html") {
        return Err(malformed());
    }
    Ok(AddonManifest {
        id: raw.id,
        name: raw.name,
        version,
        host_api: raw.host_api,
        data_format: raw.data_format,
        capabilities: raw.capabilities,
        files,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddonRelease {
    version: Version,
    host_api: u32,
    data_format: String,
    manifest_sha256: [u8; 32],
    manifest_size: u64,
}

impl AddonRelease {
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn host_api(&self) -> u32 {
        self.host_api
    }
    pub fn data_format(&self) -> &str {
        &self.data_format
    }
    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }
    pub fn manifest_size(&self) -> u64 {
        self.manifest_size
    }
    pub fn verify_manifest(
        &self,
        id: &str,
        bytes: &[u8],
        keys: &TrustedKeys,
    ) -> Result<AddonManifest, UpdateError> {
        verify_addon_bytes(bytes, self.manifest_size, &self.manifest_sha256)?;
        let manifest = verify_addon_manifest(bytes, keys)?;
        if manifest.id() != id
            || manifest.version() != self.version
            || manifest.host_api() != self.host_api
            || manifest.data_format() != self.data_format
        {
            return Err(malformed());
        }
        Ok(manifest)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelease {
    version: String,
    host_api: u32,
    data_format: String,
    manifest_sha256: String,
    manifest_size: u64,
}

impl RawRelease {
    fn verify(self) -> Result<AddonRelease, UpdateError> {
        compatibility(self.host_api, &self.data_format)?;
        if self.manifest_size == 0 || self.manifest_size > MAX_ADDON_ENVELOPE_BYTES as u64 {
            return Err(malformed());
        }
        Ok(AddonRelease {
            version: version(&self.version)?,
            host_api: self.host_api,
            data_format: self.data_format,
            manifest_size: self.manifest_size,
            manifest_sha256: hex::decode_32(&self.manifest_sha256).map_err(|_| malformed())?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddonIndex {
    id: String,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    current: AddonRelease,
    rollback: Option<AddonRelease>,
    payload_sha256: [u8; 32],
}

impl AddonIndex {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn current(&self) -> &AddonRelease {
        &self.current
    }
    pub fn rollback(&self) -> Option<&AddonRelease> {
        self.rollback.as_ref()
    }
    pub fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }
    pub fn valid_at(&self, now: u64) -> bool {
        self.issued_at <= now && now < self.expires_at
    }
    pub fn succeeds(&self, previous: &Self) -> bool {
        self.id == previous.id
            && (self.sequence > previous.sequence
                || (self.sequence == previous.sequence
                    && self.payload_sha256 == previous.payload_sha256))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIndex {
    schema: u32,
    id: String,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    current: RawRelease,
    #[serde(deserialize_with = "required_rollback")]
    rollback: Option<RawRelease>,
}

fn required_rollback<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RawRelease>, D::Error> {
    Option::deserialize(d)
}

pub fn verify_addon_index(bytes: &[u8], keys: &TrustedKeys) -> Result<AddonIndex, UpdateError> {
    let (payload, _) = verify_envelope_identified(bytes, keys, SIGNING_DOMAIN_ADDON_INDEX)?;
    let raw: RawIndex = serde_json::from_str(&payload).map_err(|_| malformed())?;
    if raw.schema != 1 || !valid_addon_id(&raw.id) || raw.issued_at >= raw.expires_at {
        return Err(malformed());
    }
    let current = raw.current.verify()?;
    let rollback = raw.rollback.map(RawRelease::verify).transpose()?;
    if rollback
        .as_ref()
        .is_some_and(|r| r.version >= current.version)
    {
        return Err(malformed());
    }
    Ok(AddonIndex {
        id: raw.id,
        sequence: raw.sequence,
        issued_at: raw.issued_at,
        expires_at: raw.expires_at,
        current,
        rollback,
        payload_sha256: Sha256::digest(payload.as_bytes()).into(),
    })
}

/// What a Premium licence includes, for display: one entry per add-on with the
/// words a person needs to choose it. Never an install authority: installing,
/// updating and rolling back still go through each add-on's own signed index and
/// manifest. Signed by the add-on key under its own domain, so a catalog can
/// never be read as an index or a manifest, or the reverse.
pub const SIGNING_DOMAIN_ADDON_CATALOG: &[u8] = b"PATANYX-ADDON-CATALOG-V1\n";
pub const MAX_CATALOG_ENTRIES: usize = 32;
pub const MAX_CATALOG_SUMMARY_CHARS: usize = 200;
/// A first install downloads the current release and, when the index names one,
/// the rollback release too, so the size covers two releases.
pub const MAX_CATALOG_SIZE: u64 = 2 * (MAX_ADDON_TOTAL_BYTES + MAX_ADDON_ENVELOPE_BYTES as u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    id: String,
    name: String,
    summary: String,
    version: Version,
    size: u64,
}

impl CatalogEntry {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn summary(&self) -> &str {
        &self.summary
    }
    pub fn version(&self) -> Version {
        self.version
    }
    /// Bytes a first install downloads (current plus rollback release).
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddonCatalog {
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    addons: Vec<CatalogEntry>,
    payload_sha256: [u8; 32],
}

impl AddonCatalog {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn addons(&self) -> &[CatalogEntry] {
        &self.addons
    }
    pub fn valid_at(&self, now: u64) -> bool {
        self.issued_at <= now && now < self.expires_at
    }
    /// The same rule as an index: a higher sequence, or the same sequence with
    /// the very same payload (a repeat of what is already held).
    pub fn succeeds(&self, previous: &Self) -> bool {
        self.sequence > previous.sequence
            || (self.sequence == previous.sequence && self.payload_sha256 == previous.payload_sha256)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalogEntry {
    id: String,
    name: String,
    summary: String,
    version: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    schema: u32,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    addons: Vec<RawCatalogEntry>,
}

fn display_text_ok(text: &str, max_chars: usize) -> bool {
    !text.trim().is_empty() && text.chars().count() <= max_chars && !text.chars().any(char::is_control)
}

pub fn verify_addon_catalog(bytes: &[u8], keys: &TrustedKeys) -> Result<AddonCatalog, UpdateError> {
    let (payload, _) = verify_envelope_identified(bytes, keys, SIGNING_DOMAIN_ADDON_CATALOG)?;
    let raw: RawCatalog = serde_json::from_str(&payload).map_err(|_| malformed())?;
    if raw.schema != 1
        || raw.issued_at >= raw.expires_at
        || raw.addons.is_empty()
        || raw.addons.len() > MAX_CATALOG_ENTRIES
    {
        return Err(malformed());
    }
    let mut ids = BTreeSet::new();
    let mut addons = Vec::with_capacity(raw.addons.len());
    for entry in raw.addons {
        if !valid_addon_id(&entry.id)
            || !ids.insert(entry.id.clone())
            || !display_text_ok(&entry.name, 80)
            || !display_text_ok(&entry.summary, MAX_CATALOG_SUMMARY_CHARS)
            || entry.size == 0
            || entry.size > MAX_CATALOG_SIZE
        {
            return Err(malformed());
        }
        addons.push(CatalogEntry {
            version: version(&entry.version)?,
            id: entry.id,
            name: entry.name,
            summary: entry.summary,
            size: entry.size,
        });
    }
    Ok(AddonCatalog {
        sequence: raw.sequence,
        issued_at: raw.issued_at,
        expires_at: raw.expires_at,
        addons,
        payload_sha256: Sha256::digest(payload.as_bytes()).into(),
    })
}

#[cfg(test)]
#[path = "addon_tests.rs"]
mod tests;
