//! Authenticated add-on downloads. Only fixed POST routes on the licence
//! service carry credentials: the signed index, and a short-lived download
//! pass for one release. That release's manifest and files then come by GET
//! from the add-on CDN (`ADDON_CDN`), which sees the pass and nothing else:
//! never the Premium token or the device identifier. Transport errors and
//! server text never enter diagnostics.
//! The host owns entitlement/session admission and cancels before lock, licence
//! replacement, Library replacement or a network-policy change.

use crate::addon_install::{
    InstallError, InstallStore, PreparedInstall, ReleaseChoice, VerifiedBundle,
};
use patanyx_update::{addon::*, AddonCatalog, AddonIndex, AddonRelease};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_TIMEOUT: Duration = Duration::from_secs(300);
const ERROR_CAP: usize = 4096;
/// The longest download pass accepted from the licence service (the CDN
/// Worker refuses anything longer too).
const MAX_PASS_CHARS: usize = 1024;

/// Where add-on manifests and files come from: a Cloudflare Worker in front of
/// a private bucket, which serves a release only with a pass for it.
const ADDON_CDN: &str = "https://dl.patanyx.net";

/// The add-on CDN's origin. `PATANYX_ADDON_CDN` overrides it for end-to-end
/// runs in DEBUG builds only, and only with a loopback origin, exactly as
/// `activation::licence_origin` does.
pub(crate) fn addon_cdn_origin() -> String {
    #[cfg(debug_assertions)]
    if let Some(v) = std::env::var("PATANYX_ADDON_CDN")
        .ok()
        .filter(|v| crate::activation::is_loopback_origin(v))
    {
        return v;
    }
    ADDON_CDN.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryError {
    Unavailable,
    InvalidRequest,
    Cancelled,
    Transport,
    Redirect,
    Response,
    TooLarge,
    Refused {
        code: Refusal,
        retry_after: Option<u64>,
    },
    Install(InstallError),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    BadRequest,
    BadToken,
    NotActivated,
    NotFound,
    Expired,
    RateLimited,
    /// The CDN refused the download pass (expired, or for another release).
    BadGrant,
    /// The licence service cannot issue passes right now.
    Unavailable,
}
impl From<InstallError> for DeliveryError {
    fn from(e: InstallError) -> Self {
        Self::Install(e)
    }
}
impl From<patanyx_update::UpdateError> for DeliveryError {
    fn from(_: patanyx_update::UpdateError) -> Self {
        Self::Install(InstallError::Integrity)
    }
}
impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "addon_delivery_{self:?}")
    }
}
impl std::error::Error for DeliveryError {}

/// Shared with the UI's session owner. Cancellation linearizes with activation:
/// once cancel returns, this job cannot publish a new active record.
#[derive(Clone)]
pub(crate) struct Cancellation {
    cancelled: Arc<Mutex<bool>>,
    deadline: Instant,
}
impl Cancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(Mutex::new(false)),
            deadline: Instant::now() + JOB_TIMEOUT,
        }
    }
    pub(crate) fn cancel(&self) {
        if let Ok(mut flag) = self.cancelled.lock() {
            *flag = true;
        }
    }
    pub(crate) fn check(&self) -> Result<(), DeliveryError> {
        if *self
            .cancelled
            .lock()
            .map_err(|_| DeliveryError::Cancelled)?
            || Instant::now() >= self.deadline
        {
            return Err(DeliveryError::Cancelled);
        }
        Ok(())
    }
    pub(super) fn commit<T>(
        &self,
        f: impl FnOnce() -> Result<T, InstallError>,
    ) -> Result<T, InstallError> {
        let flag = self.cancelled.lock().map_err(|_| InstallError::Cancelled)?;
        if *flag || Instant::now() >= self.deadline {
            return Err(InstallError::Cancelled);
        }
        f()
    }
}

/// No Debug implementation: neither the token nor its JSON body may be logged.
/// A caller supplies these only after its live local entitlement check. The
/// service independently authenticates the token, term and activated device.
pub(crate) struct Credentials {
    token: Zeroizing<String>,
    device_id: String,
}
impl Credentials {
    pub(crate) fn new(token: String, device_id: String) -> Result<Self, DeliveryError> {
        let token = Zeroizing::new(token);
        if token.is_empty()
            || token.len() > 4096
            || token.chars().any(char::is_control)
            || crate::activation::decode_hex_16(&device_id).is_none()
        {
            return Err(DeliveryError::InvalidRequest);
        }
        Ok(Self { token, device_id })
    }
}

struct Request {
    url: String,
    body: Zeroizing<Vec<u8>>,
}
/// One manifest or file from the add-on CDN: a GET with the pass, no body.
struct CdnRequest {
    url: String,
    pass: Zeroizing<String>,
}
#[derive(serde::Serialize)]
struct Body<'a> {
    token: &'a str,
    device_id: &'a str,
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}
/// An origin a request may go to: HTTPS (or, in debug builds, a loopback
/// HTTP port), no credentials, no query or fragment, no path.
fn origin_ok(origin: &str) -> Result<(), DeliveryError> {
    let parsed = url::Url::parse(origin).map_err(|_| DeliveryError::InvalidRequest)?;
    let secure = parsed.scheme() == "https";
    // This matches the existing activation test-origin hook. Release builds
    // accept only HTTPS, and no origin can contain credentials or URL arguments.
    #[cfg(debug_assertions)]
    let secure = secure
        || (parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            && parsed.port().is_some());
    if !secure
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(DeliveryError::InvalidRequest);
    }
    Ok(())
}

/// A POST to the licence service: the add-on's signed index, or (with
/// `grant_for`) a download pass for that release.
fn request(
    origin: &str,
    auth: &Credentials,
    id: &str,
    grant_for: Option<&AddonRelease>,
) -> Result<Request, DeliveryError> {
    if !valid_addon_id(id) {
        return Err(DeliveryError::InvalidRequest);
    }
    origin_ok(origin)?;
    let endpoint = if grant_for.is_some() {
        "/premium/addon/grant"
    } else {
        "/premium/addon/index"
    };
    let url = format!("{}{endpoint}", origin.trim_end_matches('/'));
    let body = Body {
        token: &auth.token,
        device_id: &auth.device_id,
        id,
        version: grant_for.map(|r| r.version().to_string()),
    };
    let body =
        Zeroizing::new(serde_json::to_vec(&body).map_err(|_| DeliveryError::InvalidRequest)?);
    Ok(Request { url, body })
}

/// The catalog request: the same credentials as the index, and no add-on id.
#[derive(serde::Serialize)]
struct CatalogBody<'a> {
    token: &'a str,
    device_id: &'a str,
}
fn catalog_request(origin: &str, auth: &Credentials) -> Result<Request, DeliveryError> {
    origin_ok(origin)?;
    let url = format!("{}/premium/addon/catalog", origin.trim_end_matches('/'));
    let body = CatalogBody {
        token: &auth.token,
        device_id: &auth.device_id,
    };
    let body =
        Zeroizing::new(serde_json::to_vec(&body).map_err(|_| DeliveryError::InvalidRequest)?);
    Ok(Request { url, body })
}

/// A GET from the add-on CDN for one file of one release, carrying the pass
/// in its Authorization header and nothing else of the person's.
fn cdn_request(
    origin: &str,
    id: &str,
    release: &AddonRelease,
    path: &str,
    pass: &Zeroizing<String>,
) -> Result<CdnRequest, DeliveryError> {
    if !valid_addon_id(id) {
        return Err(DeliveryError::InvalidRequest);
    }
    origin_ok(origin)?;
    if path != "manifest.sig.json" && !path.strip_prefix("files/").is_some_and(valid_addon_path) {
        return Err(DeliveryError::InvalidRequest);
    }
    let version = release.version().to_string();
    if !version.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())) {
        return Err(DeliveryError::InvalidRequest);
    }
    Ok(CdnRequest {
        url: format!("{}/addons/{id}/{version}/{path}", origin.trim_end_matches('/')),
        pass: pass.clone(),
    })
}

/// The pass from a /premium/addon/grant answer: `{"grant":"<a>.<b>"}`, both
/// parts base64url, nothing else in the object.
fn parse_pass(bytes: &[u8]) -> Result<Zeroizing<String>, DeliveryError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Answer {
        grant: String,
    }
    let answer: Answer = serde_json::from_slice(bytes).map_err(|_| DeliveryError::Response)?;
    let pass = Zeroizing::new(answer.grant);
    let shape = pass.split('.').collect::<Vec<_>>();
    if pass.len() > MAX_PASS_CHARS
        || shape.len() != 2
        || shape.iter().any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return Err(DeliveryError::Response);
    }
    Ok(pass)
}

struct Response {
    status: u16,
    length: Option<u64>,
    content_type: Option<String>,
    retry_after: Option<u64>,
    reader: Box<dyn Read>,
}
trait Transport {
    fn post(&mut self, request: Request) -> Result<Response, DeliveryError>;
    fn get(&mut self, request: CdnRequest) -> Result<Response, DeliveryError>;
}

#[cfg(feature = "updater-net")]
struct Http {
    agent: ureq::Agent,
    /// Its own agent: the machine's proxy is chosen for the CDN's host, not
    /// the licence host's (review R-903).
    cdn: ureq::Agent,
}
#[cfg(feature = "updater-net")]
impl Http {
    fn new() -> Result<Self, DeliveryError> {
        // No updater fallback: these requests carry a bearer credential or a pass.
        let cdn_host = crate::state::host_of(&addon_cdn_origin()).ok_or(DeliveryError::InvalidRequest)?;
        Ok(Self {
            agent: crate::net::agent(REQUEST_TIMEOUT).map_err(|_| DeliveryError::Transport)?,
            cdn: crate::net::agent_for(&cdn_host, REQUEST_TIMEOUT).map_err(|_| DeliveryError::Transport)?,
        })
    }
}
#[cfg(feature = "updater-net")]
fn into_response(response: ureq::Response) -> Result<Response, DeliveryError> {
    let length = response
        .header("Content-Length")
        .map(|s| s.parse::<u64>().map_err(|_| DeliveryError::Response))
        .transpose()?;
    Ok(Response {
        status: response.status(),
        length,
        content_type: response.header("Content-Type").map(str::to_owned),
        retry_after: response.header("Retry-After").and_then(|s| s.parse().ok()),
        reader: response.into_reader(),
    })
}
#[cfg(feature = "updater-net")]
impl Transport for Http {
    fn post(&mut self, request: Request) -> Result<Response, DeliveryError> {
        // The index is a signed envelope served as bytes; a pass is JSON.
        let accept = if request.url.ends_with("/premium/addon/grant") {
            "application/json"
        } else {
            "application/octet-stream, application/json"
        };
        let response = match self
            .agent
            .post(&request.url)
            .set("Content-Type", "application/json")
            .set("Accept", accept)
            .send_bytes(&request.body)
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(_) => return Err(DeliveryError::Transport),
        };
        into_response(response)
    }
    fn get(&mut self, request: CdnRequest) -> Result<Response, DeliveryError> {
        let authorization = Zeroizing::new(format!("PATANYX-Grant {}", request.pass.as_str()));
        let response = match self
            .cdn
            .get(&request.url)
            .set("Accept", "application/octet-stream")
            .set("Authorization", &authorization)
            .call()
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(_) => return Err(DeliveryError::Transport),
        };
        into_response(response)
    }
}
fn receive(
    response: Response,
    cap: usize,
    file: bool,
    cancel: &Cancellation,
) -> Result<Vec<u8>, DeliveryError> {
    let Response {
        status,
        length,
        content_type,
        retry_after,
        mut reader,
    } = response;
    if (300..400).contains(&status) {
        return Err(DeliveryError::Redirect);
    }
    let limit = if status == 200 { cap } else { ERROR_CAP };
    // A rate limit stays a rate limit, with its Retry-After, even when the
    // front server's page is larger than an error body may be (review R-004).
    let too_large = || {
        if status == 429 {
            DeliveryError::Refused {
                code: Refusal::RateLimited,
                retry_after,
            }
        } else {
            DeliveryError::TooLarge
        }
    };
    if length.is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        cancel.check()?;
        let remaining = (limit + 1 - bytes.len()).min(chunk.len());
        let n = reader
            .read(&mut chunk[..remaining])
            .map_err(|_| DeliveryError::Transport)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > limit {
            return Err(too_large());
        }
    }
    cancel.check()?;
    if length.is_some_and(|n| n != bytes.len() as u64) {
        return Err(DeliveryError::Response);
    }
    if status == 200 {
        if file && content_type.as_deref() != Some("application/octet-stream") {
            return Err(DeliveryError::Response);
        }
        return Ok(bytes);
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorBody {
        error: String,
    }
    let body: ErrorBody = match serde_json::from_slice(&bytes) {
        Ok(body) => body,
        // A rate limit answered by the front server rather than the service
        // has an HTML body; it is still a rate limit, not a broken answer.
        Err(_) if status == 429 => {
            return Err(DeliveryError::Refused {
                code: Refusal::RateLimited,
                retry_after,
            })
        }
        // So is a route the front server does not know yet (an HTML 404):
        // nothing is published there, which is not a forged answer.
        Err(_) if status == 404 => {
            return Err(DeliveryError::Refused {
                code: Refusal::NotFound,
                retry_after: None,
            })
        }
        Err(_) => return Err(DeliveryError::Response),
    };
    let code = match (status, body.error.as_str()) {
        (400, "bad_request") => Refusal::BadRequest,
        (401, "bad_token") => Refusal::BadToken,
        (403, "not_activated") => Refusal::NotActivated,
        (404, "not_found") => Refusal::NotFound,
        (410, "expired") => Refusal::Expired,
        (429, "rate_limited") => Refusal::RateLimited,
        (401, "bad_grant") => Refusal::BadGrant,
        (503, "unavailable") => Refusal::Unavailable,
        _ => return Err(DeliveryError::Response),
    };
    Err(DeliveryError::Refused {
        code,
        retry_after: if status == 429 { retry_after } else { None },
    })
}

pub(crate) struct DeliveryClient {
    auth: Credentials,
    cancel: Cancellation,
}
impl DeliveryClient {
    pub(crate) fn new(auth: Credentials, cancel: Cancellation) -> Self {
        Self { auth, cancel }
    }
    /// Explicit metadata check. The same transport and verifier used by download.
    pub(crate) fn check(&self, id: &str, store: &InstallStore) -> Result<AddonIndex, DeliveryError> {
        #[cfg(feature = "updater-net")]
        {
            let envelope = self.fetch_index(&crate::activation::licence_origin(), id, &mut Http::new()?)?;
            self.cancel.check()?;
            Ok(store.accept_index(id, &envelope, crate::addon_install::now()?)?)
        }
        #[cfg(not(feature = "updater-net"))]
        {
            let _ = (id, store);
            Err(DeliveryError::Unavailable)
        }
    }
    /// What this licence's Premium includes, for the Add-ons panel: the
    /// signed catalog, verified and recorded. Display data; it authorizes
    /// nothing. The same transport and strict roots as the index.
    pub(crate) fn catalog(&self, store: &InstallStore) -> Result<AddonCatalog, DeliveryError> {
        #[cfg(feature = "updater-net")]
        {
            self.catalog_with(&crate::activation::licence_origin(), store, &mut Http::new()?)
        }
        #[cfg(not(feature = "updater-net"))]
        {
            let _ = store;
            Err(DeliveryError::Unavailable)
        }
    }
    #[cfg_attr(not(feature = "updater-net"), allow(dead_code))]
    fn catalog_with(
        &self,
        origin: &str,
        store: &InstallStore,
        transport: &mut impl Transport,
    ) -> Result<AddonCatalog, DeliveryError> {
        self.cancel.check()?;
        let response = transport.post(catalog_request(origin, &self.auth)?)?;
        let envelope = receive(response, MAX_ADDON_ENVELOPE_BYTES, false, &self.cancel)?;
        self.cancel.check()?;
        Ok(store.accept_catalog(&envelope, crate::addon_install::now()?)?)
    }
    pub(crate) fn download(
        &self,
        id: &str,
        choice: ReleaseChoice,
        store: &InstallStore,
    ) -> Result<PreparedInstall, DeliveryError> {
        #[cfg(feature = "updater-net")]
        {
            self.download_with(
                &crate::activation::licence_origin(),
                &addon_cdn_origin(),
                id,
                choice,
                store,
                &mut Http::new()?,
            )
        }
        #[cfg(not(feature = "updater-net"))]
        {
            let _ = (id, choice, store);
            Err(DeliveryError::Unavailable)
        }
    }
    fn download_with(
        &self,
        origin: &str,
        cdn: &str,
        id: &str,
        choice: ReleaseChoice,
        store: &InstallStore,
        transport: &mut impl Transport,
    ) -> Result<PreparedInstall, DeliveryError> {
        let envelope = self.fetch_index(origin, id, transport)?;
        let index = store.accept_index(id, &envelope, crate::addon_install::now()?)?;
        let selected = self.package(origin, cdn, &index, choice.release(&index)?, store, transport)?;
        let rollback = if choice == ReleaseChoice::Current {
            index
                .rollback()
                .map(|r| self.package(origin, cdn, &index, r, store, transport))
                .transpose()?
        } else {
            None
        };
        self.cancel.check()?;
        Ok(store.prepare(envelope, choice, selected, rollback)?)
    }
    /// One release: its pass from the licence service, then its manifest and
    /// every file from the CDN, each verified before the next is asked for.
    fn package(
        &self,
        origin: &str,
        cdn: &str,
        index: &AddonIndex,
        release: &AddonRelease,
        store: &InstallStore,
        transport: &mut impl Transport,
    ) -> Result<VerifiedBundle, DeliveryError> {
        self.cancel.check()?;
        let response = transport.post(request(origin, &self.auth, index.id(), Some(release))?)?;
        let pass = parse_pass(&receive(response, MAX_PASS_CHARS + 64, false, &self.cancel)?)?;
        let envelope = self.fetch_cdn(
            cdn,
            index.id(),
            release,
            "manifest.sig.json",
            release.manifest_size() as usize,
            &pass,
            transport,
        )?;
        let manifest = release.verify_manifest(index.id(), &envelope, store.keys())?;
        let mut files = BTreeMap::new();
        for file in manifest.files() {
            let bytes = self.fetch_cdn(
                cdn,
                index.id(),
                release,
                &format!("files/{}", file.path()),
                file.size() as usize,
                &pass,
                transport,
            )?;
            file.verify(&bytes)?;
            files.insert(file.path().to_owned(), bytes);
        }
        Ok(store.verify_package(index, release, envelope, files)?)
    }
    fn fetch_index(&self, origin: &str, id: &str, transport: &mut impl Transport) -> Result<Vec<u8>, DeliveryError> {
        self.cancel.check()?;
        let response = transport.post(request(origin, &self.auth, id, None)?)?;
        receive(response, MAX_ADDON_ENVELOPE_BYTES, false, &self.cancel)
    }
    #[allow(clippy::too_many_arguments)]
    fn fetch_cdn(
        &self,
        cdn: &str,
        id: &str,
        release: &AddonRelease,
        path: &str,
        cap: usize,
        pass: &Zeroizing<String>,
        transport: &mut impl Transport,
    ) -> Result<Vec<u8>, DeliveryError> {
        self.cancel.check()?;
        let response = transport.get(cdn_request(cdn, id, release, path, pass)?)?;
        receive(response, cap, true, &self.cancel)
    }
}

#[cfg(test)]
#[path = "addon_delivery_tests.rs"]
mod tests;
