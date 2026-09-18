//! Premium activation on THIS device (Phase 4 of the Premium design: a
//! licence activates on up to five devices).
//!
//! The pieces, and where each lives:
//!
//! * The DEVICE ID: a random 128-bit per-install identifier in
//!   `<vault dir>/device-id`, OUTSIDE the vault on purpose. Inside the
//!   vault, copying one vault to fifty machines would be one slot and
//!   "five devices" a fiction. Missing means a new install and is minted;
//!   present but unreadable is REFUSED and never overwritten (a device id
//!   you cannot read is not a new device, and minting one would burn a slot
//!   the user did not spend). It is minted LAZILY, at the first activation,
//!   so a free user who never buys never has an identifier generated.
//! * The RECEIPTS: signed `prx1-` texts in the vault (schema 7,
//!   `activation`), one per device that activated under the current
//!   licence, so a synced vault carries every device's receipt and each
//!   machine finds its own by device id.
//! * The CALL: `POST {origin}/premium/activate` with the full token and the
//!   device id, over the tunnel when one is in force (`crate::net`, fail
//!   closed). It happens ONCE per device in the normal life of a licence.
//!   Every later unlock re-verifies the cached receipt offline; while a
//!   device is unactivated (first unlock after paste, or a refused earlier
//!   try) each unlock makes ONE silent retry. Nothing here runs on a
//!   schedule and nothing phones home to switch anything OFF.
//! * The GATE: `licence_control` decides `premium_active` = the token is
//!   ACTIVE and a receipt in the vault binds to this device. This module
//!   only produces the receipt.
//!
//! What the server learns per activation: the licence id (it minted it),
//! this device id, the day. What it does not: an IP address (`access_log
//! off` on the location; the app never sends one), a user agent beyond
//! "patanyx", anything about the machine.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use zeroize::Zeroize as _;

use crate::state::AppState;

// ---- device id ---------------------------------------------------------------

/// The file name beside the vault.
pub const DEVICE_ID_FILE: &str = "device-id";

/// Why the device id could not be produced. Every arm is user-visible
/// through the activation state's message.
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceIdError {
    /// The file exists and is not 32 lowercase hex: refused, never
    /// overwritten.
    Unreadable,
    /// The file could not be read or written for an I/O reason.
    Io,
}

/// Where the device id lives for a vault at `vault_path`.
pub fn device_id_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .map(|dir| dir.join(DEVICE_ID_FILE))
        .unwrap_or_else(|| PathBuf::from(DEVICE_ID_FILE))
}

/// The device id if the file already exists; `Ok(None)` if there is none
/// yet. Never mints: reading the vault must not create an identifier.
pub fn device_id_if_present(vault_path: &Path) -> Result<Option<[u8; 16]>, DeviceIdError> {
    let path = device_id_path(vault_path);
    match std::fs::read(&path) {
        Ok(bytes) => parse_device_id_file(&bytes)
            .map(Some)
            .ok_or(DeviceIdError::Unreadable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(DeviceIdError::Io),
    }
}

/// The device id, minting it if this install has none yet.
pub fn device_id_or_mint(vault_path: &Path) -> Result<[u8; 16], DeviceIdError> {
    if let Some(id) = device_id_if_present(vault_path)? {
        return Ok(id);
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|_| DeviceIdError::Io)?;
    write_device_id_file(&device_id_path(vault_path), &id)?;
    Ok(id)
}

/// Exactly 32 lowercase hex, an optional trailing newline. Anything else
/// is not ours.
fn parse_device_id_file(bytes: &[u8]) -> Option<[u8; 16]> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    decode_hex_16(text)
}

fn write_device_id_file(path: &Path, id: &[u8; 16]) -> Result<(), DeviceIdError> {
    // create_new: if a second thread or process minted between our read
    // and this write, we must NOT overwrite its id.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(format!("{}\n", hex_encode_16(id)).as_bytes())
                .map_err(|_| DeviceIdError::Io)?;
            file.sync_all().map_err(|_| DeviceIdError::Io)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Someone else minted first; their id wins and ours is dropped.
            Ok(())
        }
        Err(_) => Err(DeviceIdError::Io),
    }
}

pub fn hex_encode_16(bytes: &[u8; 16]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing hex into a String cannot fail");
    }
    out
}

pub fn decode_hex_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

// ---- the call --------------------------------------------------------------------

/// The licence endpoints live on the update origin: a separate `licence.`
/// host name would put "this machine is a paying Premium user" into a DNS
/// query. `PATANYX_LICENCE_ORIGIN` overrides it for the end-to-end gate,
/// exactly like `PATANYX_UPDATE_MANIFEST_URL` does for the updater; a
/// shipped build never sets it.
fn licence_origin() -> String {
    // DEBUG BUILDS ONLY. The loopback filter was the only guard in a shipped
    // binary, and a local process that controls the launch environment and a
    // loopback port would receive the full bearer token on the next unlock
    // (pentest F-009). The end-to-end gate runs a debug binary.
    #[cfg(debug_assertions)]
    if let Some(v) = std::env::var("PATANYX_LICENCE_ORIGIN")
        .ok()
        .filter(|v| is_loopback_origin(v))
    {
        return v;
    }
    crate::updater::base_url().to_string()
}

/// Is this override a real loopback origin, by the HOST rather than by how
/// the string begins?
///
/// A prefix test reads `http://localhost:@evil.example/` as loopback: the
/// userinfo runs up to the last `@`, so everything before it is a username
/// and the actual host is `evil.example` (security audit 2026-08-18, F5).
/// The override then aims the activation POST -- which carries the full
/// licence token and this install's device id -- at whatever that resolves
/// to. Reaching it needs control of the process environment, which is
/// already a lost machine, but "you had to be compromised first" is a reason
/// to fix a hole cheaply rather than a reason to keep it.
///
/// `host_of` is the same extraction the content allowlist uses, so the two
/// agree about where a host ends and there is one place to correct if a
/// browser ever normalizes differently. A port is required, as before: the
/// override exists for the end-to-end gate, which always names one.
fn is_loopback_origin(value: &str) -> bool {
    let Some(host) = crate::state::host_of(value) else {
        return false;
    };
    if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
        return false;
    }
    // http only, and a port must be present: this is a test hook, not a
    // second production endpoint.
    value.starts_with("http://") && value.rsplit(':').next().is_some_and(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
}

/// How one activation attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateOutcome {
    /// The server granted (or re-served) this device's slot.
    Activated { receipt_text: String },
    /// The server answered and said no. The code is one of the server's:
    /// `slots_full`, `grants_exhausted`, `expired`, `bad_token`.
    Refused(String),
    /// The server could not be reached, or refused to talk (proxy not
    /// expressible, TLS, timeout, non-JSON answer, 5xx). Retryable.
    Offline(CallFailure),
}

/// What is known about a failed call without guessing from display text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Offline,
    TunnelCarried,
    OtherCertificate,
    Intercepted,
}

/// A printable diagnostic plus the typed class used to choose user copy.
/// ureq preserves rustls below its transport error, so classification happens
/// before that source chain is flattened for a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFailure {
    detail: String,
    kind: FailureKind,
}

impl CallFailure {
    fn offline(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            kind: FailureKind::Offline,
        }
    }

    #[cfg(feature = "updater-net")]
    fn from_net_error(error: crate::net::NetError) -> Self {
        Self::from_net_error_with_carrier(error, tunnel_in_force_after_failure())
    }

    #[cfg(feature = "updater-net")]
    fn from_net_error_with_carrier(error: crate::net::NetError, tunnel_in_force: bool) -> Self {
        Self::classified_transport(error.to_string(), None, tunnel_in_force)
    }

    #[cfg(feature = "updater-net")]
    fn from_transport(transport: ureq::Transport) -> Self {
        let certificate_kind = transport_certificate_kind(&transport);
        Self::classified_transport(
            transport.to_string(),
            certificate_kind,
            tunnel_in_force_after_failure(),
        )
    }

    #[cfg(feature = "updater-net")]
    fn from_response_io(error: std::io::Error) -> Self {
        Self::classified_transport(error.to_string(), None, tunnel_in_force_after_failure())
    }

    #[cfg(all(test, feature = "updater-net"))]
    fn from_transport_with_carrier(transport: ureq::Transport, tunnel_in_force: bool) -> Self {
        let certificate_kind = transport_certificate_kind(&transport);
        Self::classified_transport(transport.to_string(), certificate_kind, tunnel_in_force)
    }

    #[cfg(feature = "updater-net")]
    fn classified_transport(
        detail: impl Into<String>,
        certificate_kind: Option<FailureKind>,
        tunnel_in_force: bool,
    ) -> Self {
        Self {
            detail: detail.into(),
            kind: classify_transport_failure(certificate_kind, tunnel_in_force),
        }
    }

    #[cfg(all(test, feature = "updater-net"))]
    fn from_certificate(error: rustls::CertificateError) -> Self {
        Self::from_certificate_with_carrier(error, false)
    }

    #[cfg(all(test, feature = "updater-net"))]
    fn from_certificate_with_carrier(
        error: rustls::CertificateError,
        tunnel_in_force: bool,
    ) -> Self {
        let error = rustls::Error::InvalidCertificate(error);
        Self::classified_transport(
            error.to_string(),
            Some(certificate_failure_kind(&error)),
            tunnel_in_force,
        )
    }
}

#[cfg(feature = "updater-net")]
fn transport_certificate_kind(transport: &ureq::Transport) -> Option<FailureKind> {
    let mut certificate_kind = None;
    let mut source = std::error::Error::source(transport);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<rustls::Error>() {
            certificate_kind = Some(certificate_failure_kind(error));
            break;
        }
        source = error.source();
    }
    certificate_kind
}

/// Read the request carrier at the last useful point: after ureq has reported
/// the failure and immediately before we classify it for user-visible copy.
/// This is deliberately an after-the-fact read rather than state captured with
/// the request. If the tunnel is switched off between request setup/send and
/// classification, that race can classify a request that did use it as plain
/// offline.
#[cfg(feature = "updater-net")]
fn tunnel_in_force_after_failure() -> bool {
    crate::tunnel_control::engine_proxy_port().is_some()
}

/// Certificate evidence wins because it gives the reader a more actionable
/// explanation. Otherwise the carrier decides: every non-certificate failure
/// is tunnel-carried when PATANYX's own tunnel was in force, irrespective of
/// whether it arose while constructing the proxy, connecting to its loopback
/// port, completing SOCKS, waiting for an answer, or reaching EdgeXene.
#[cfg(feature = "updater-net")]
fn classify_transport_failure(
    certificate_kind: Option<FailureKind>,
    tunnel_in_force: bool,
) -> FailureKind {
    match certificate_kind {
        Some(FailureKind::Intercepted) => FailureKind::Intercepted,
        Some(FailureKind::OtherCertificate) => FailureKind::OtherCertificate,
        _ if tunnel_in_force => FailureKind::TunnelCarried,
        _ => FailureKind::Offline,
    }
}

impl std::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

#[cfg(feature = "updater-net")]
fn certificate_failure_kind(error: &rustls::Error) -> FailureKind {
    match error {
        rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer | rustls::CertificateError::BadSignature,
        ) => FailureKind::Intercepted,
        rustls::Error::InvalidCertificate(_) => FailureKind::OtherCertificate,
        _ => FailureKind::Offline,
    }
}

/// One POST attempt with a given agent: send, and turn the answer into a
/// `(status, json)` pair or a typed `CallFailure`. Factored out so the caller
/// can try one agent, read the FAILURE KIND, and decide whether a second agent
/// is worth trying.
#[cfg(feature = "updater-net")]
fn send_once(
    agent: &ureq::Agent,
    url: &str,
    body: &Value,
) -> Result<(u16, Value), CallFailure> {
    let sent = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    let (status, response) = match sent {
        Ok(response) => (response.status(), response),
        Err(ureq::Error::Status(code, response)) => (code, response),
        Err(ureq::Error::Transport(t)) => return Err(CallFailure::from_transport(t)),
    };
    let text = response
        .into_string()
        .map_err(CallFailure::from_response_io)?;
    let value: Value =
        serde_json::from_str(&text).map_err(|_| CallFailure::offline("non-JSON answer"))?;
    Ok((status, value))
}

/// Blocking: call the server. Runs on a worker thread, never on the event loop.
/// Compiled without a network client, it answers `Offline` honestly.
///
/// REACHABILITY, WITH THE PROXY DECISION MADE BY WHAT ACTUALLY HAPPENS. When
/// there is no user tunnel, the first attempt goes through the machine's own
/// proxy (if it has one -- corporate egress like Zscaler). If that attempt
/// fails to CONNECT, the proxy is unreachable -- most often a stale registry
/// entry that outlived the network it belonged to (the laptop is now on a
/// hotspot where the corporate proxy is switched off) -- so the SAME request is
/// retried DIRECT, which is what would have worked all along.
///
/// The fallback fires ONLY on a connect-level failure (`Offline`). A CERTIFICATE
/// refusal (`Intercepted`/`OtherCertificate`) means the connection reached a
/// proxy that re-signs TLS: retrying direct cannot help on that network, and
/// more importantly the honest "something is inspecting this connection" answer
/// must stand rather than being buried under a second failure. The token is
/// never sent to such a proxy -- `Roots::Bundled` refused it -- and it is not
/// sent direct either, because we stop.
///
/// The user-tunnel path takes no fallback at all: the tunnel is the chosen
/// egress and bypassing it would defeat the privacy the user asked for.
#[cfg(feature = "updater-net")]
fn post_json_blocking(route: &str, body: &Value) -> Result<(u16, Value), CallFailure> {
    use std::time::Duration;
    let url = format!("{}/premium/{route}", licence_origin());
    let timeout = Duration::from_secs(20);

    if crate::tunnel_control::engine_proxy_port().is_some() {
        let agent = crate::net::agent(timeout).map_err(CallFailure::from_net_error)?;
        return send_once(&agent, &url, body);
    }

    let agent = crate::net::agent(timeout).map_err(CallFailure::from_net_error)?;
    match send_once(&agent, &url, body) {
        Err(why) if retry_direct_after(why.kind) => {
            // The first attempt could not connect. If a proxy was in play it may
            // be stale/unreachable; retry with the proxy deliberately skipped.
            // (When no proxy was configured this simply reattempts direct, which
            // is harmless -- it only happens on an already-failing call.)
            let direct = crate::net::agent_direct(timeout).map_err(CallFailure::from_net_error)?;
            send_once(&direct, &url, body)
        }
        other => other,
    }
}

/// Whether a first-attempt failure of this kind is worth retrying DIRECT
/// (proxy skipped). Only a connect-level `Offline` is: a stale/unreachable
/// proxy is the case direct rescues. A CERTIFICATE refusal must NOT retry
/// direct -- it means a proxy re-signed the TLS, the token was correctly
/// withheld, and the honest "inspected" answer has to stand rather than be
/// replaced by whatever a second, direct attempt happens to hit. Retrying it
/// direct would also be pointless: the interceptor sits on the network, not on
/// the proxy hop.
fn retry_direct_after(kind: FailureKind) -> bool {
    matches!(kind, FailureKind::Offline)
}

#[cfg(not(feature = "updater-net"))]
fn post_json_blocking(_route: &str, _body: &Value) -> Result<(u16, Value), CallFailure> {
    Err(CallFailure::offline("this build has no network client"))
}

/// Which failed-call copy applies: the request's carrier could not reach the
/// service, or TLS refused the peer certificate.
///
/// The activation call accepts only the compiled-in roots (`net::agent`,
/// `Roots::Bundled`) and deliberately never falls back to the operating
/// system's store the way the signature-protected updater may. On a network
/// that re-signs TLS with a private root -- an ordinary corporate proxy --
/// the handshake therefore fails, and the old copy told the user PATANYX
/// "could not reach EdgeXene" and would try again. Both halves were wrong:
/// EdgeXene was reachable, and retrying can never succeed, because nothing
/// about a retry changes the trust decision. The user retries forever.
///
/// ureq retains rustls as a typed source. Unknown issuer and bad certificate
/// signature fit interception; every other certificate refusal gets neutral
/// copy that makes no claim about its cause.
fn offline_reason(why: &CallFailure) -> &'static str {
    match why.kind {
        FailureKind::Intercepted => "intercepted",
        FailureKind::OtherCertificate => "certificate",
        FailureKind::TunnelCarried => "tunnel_carried",
        FailureKind::Offline => "offline",
    }
}

/// The same typed split for RELEASE. Releasing needs the server -- there is no
/// local-only release, because dropping the receipt here while the server
/// still counts the slot would strand a slot the user believes is free -- so
/// the advice differs from activation's: try elsewhere, rather than "this is
/// one time".
///
/// `release_blocking` collapses a server refusal and a failed call into the
/// same `Err`, so this must use only the typed failure kind and never infer a
/// cause from its printable detail.
fn release_reason(why: &CallFailure) -> &'static str {
    match why.kind {
        FailureKind::Intercepted => "release_intercepted",
        FailureKind::OtherCertificate => "release_certificate",
        FailureKind::TunnelCarried => "release_tunnel_carried",
        FailureKind::Offline => "release_offline",
    }
}

/// Turn the server's answer into an outcome. Pure, so the mapping is
/// table-tested below without a server.
pub fn outcome_from_reply(reply: Result<(u16, Value), CallFailure>) -> ActivateOutcome {
    match reply {
        Ok((200, value)) => match value.get("receipt").and_then(Value::as_str) {
            Some(receipt) if receipt.starts_with("prx1-") => ActivateOutcome::Activated {
                receipt_text: receipt.to_string(),
            },
            _ => ActivateOutcome::Offline(CallFailure::offline("200 without a receipt")),
        },
        Ok((code, value)) if (400..500).contains(&code) => {
            let error = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("bad_request")
                .to_string();
            ActivateOutcome::Refused(error)
        }
        Ok((code, _)) => ActivateOutcome::Offline(CallFailure::offline(format!("HTTP {code}"))),
        Err(why) => ActivateOutcome::Offline(why),
    }
}

pub fn activate_blocking(token_text: &str, device_id: &[u8; 16]) -> ActivateOutcome {
    let body = json!({ "token": token_text, "device_id": hex_encode_16(device_id) });
    outcome_from_reply(post_json_blocking("activate", &body))
}

/// Release this device's slot. `Ok(released)`; `Err` when the server could
/// not be reached (the local receipt is then KEPT: releasing locally while
/// the server still counts the slot would strand a slot the user thinks is
/// free).
pub fn release_blocking(token_text: &str, device_id: &[u8; 16]) -> Result<bool, CallFailure> {
    let body = json!({ "token": token_text, "device_id": hex_encode_16(device_id) });
    match post_json_blocking("release", &body) {
        Ok((200, value)) => Ok(value
            .get("released")
            .and_then(Value::as_bool)
            .unwrap_or(false)),
        Ok((code, value)) => Err(CallFailure::offline(
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("HTTP {code}")),
        )),
        Err(why) => Err(why),
    }
}

// ---- the asynchronous flow ---------------------------------------------------

/// What kind of call a worker ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Activate,
    Release,
}

/// A finished call, on its way back to the event loop.
#[derive(Debug)]
pub struct ActivationEvent {
    pub kind: CallKind,
    /// The licence the call was made for; if the vault now holds a
    /// different licence (replaced meanwhile), the result is dropped.
    pub license_id_hex: String,
    pub device_id_hex: String,
    pub activate: Option<ActivateOutcome>,
    pub release: Option<Result<bool, CallFailure>>,
}

/// Deliver a result that arrived while the vault was locked. Called right
/// after the unlock-time evaluation, so the licence check inside
/// `handle_event` sees the session the result belongs to.
pub fn replay_pending(state: &mut AppState) {
    if let Some(event) = state.pending_activation_event.take() {
        handle_event_from(state, event, false);
    }
}

/// Finish a release this device started and never resolved. Called from the
/// unlock arms, right after the unlock-time evaluation: at that moment the
/// vault is open, nothing else is claiming the slot, and the user is
/// present. Bounded by the in-flight flag, and free to repeat because
/// releasing the same device twice is what the server calls idempotent.
pub fn finish_pending_release(state: &mut AppState) -> bool {
    if !release_is_pending_here(state) {
        return false;
    }
    start_release_call(state)
}

/// Whether this device has a release recorded but not yet answered.
pub fn release_is_pending_here(state: &AppState) -> bool {
    let Ok(Some(device_id)) = device_id_if_present(&state.vault_path) else {
        return false;
    };
    let here = hex_encode_16(&device_id);
    state
        .vault
        .as_ref()
        .and_then(|vault| vault.release_pending())
        .is_some_and(|pending| pending == here)
}

/// Start ONE activation attempt for the stored token, if the session says
/// one is due. Returns whether a worker was started. Called from
/// `licence_control::on_vault_unlocked` (the silent retry) and from the
/// `licence_activate` IPC arm (the user's explicit "Activate now").
///
/// The token text is read from the vault for the worker and wiped by the
/// worker as soon as the request body is built.
pub fn start_activation(state: &AppState) -> bool {
    let Some(session) = crate::licence_control::current() else {
        return false;
    };
    if !session.state.premium_active() {
        // FREE or LAPSED: there is nothing to activate.
        return false;
    }
    if crate::licence_control::activation_in_flight() {
        return false;
    }
    let vault_path = state.vault_path.clone();
    let device_id = match device_id_or_mint(&vault_path) {
        Ok(id) => id,
        Err(DeviceIdError::Unreadable) => {
            crate::licence_control::set_activation_result("device_id_unreadable");
            return false;
        }
        Err(DeviceIdError::Io) => {
            crate::licence_control::set_activation_result("device_id_io");
            return false;
        }
    };
    let Some(mut record) = state.vault.as_ref().and_then(|v| v.licence_record()) else {
        return false;
    };
    let Some(license_id_hex) = crate::licence_control::current_license_id_hex() else {
        record.token_text.zeroize();
        return false;
    };
    crate::licence_control::mark_activation_in_flight();
    let proxy = state.proxy();
    let handle = std::thread::spawn(move || {
        let outcome = activate_blocking(&record.token_text, &device_id);
        record.token_text.zeroize();
        let _ = proxy.send_event(crate::UserEvent::Activation(ActivationEvent {
            kind: CallKind::Activate,
            license_id_hex,
            device_id_hex: hex_encode_16(&device_id),
            activate: Some(outcome),
            release: None,
        }));
    });
    remember_worker(handle);
    true
}

/// The most recent worker thread, so a caller that must know the network
/// side is finished (the smoke, before it asserts on the busy flag) can
/// JOIN it instead of polling a flag that a synthetic result can clear.
static WORKER: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> =
    std::sync::Mutex::new(None);

fn remember_worker(handle: std::thread::JoinHandle<()>) {
    let previous = WORKER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(handle);
    if let Some(previous) = previous {
        // At most one is in flight (mark_activation_in_flight gates the
        // start), so a previous handle is a finished thread; reap it.
        let _ = previous.join();
    }
}

/// Block until the last started worker has finished its network call and
/// posted its result. The result itself still arrives through the event
/// loop; this only guarantees the thread is done.
pub fn join_worker() {
    let handle = WORKER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

/// Start a release of THIS device's slot. Only meaningful while activated;
/// the IPC arm checks that. Returns whether a worker was started.
pub fn start_release(state: &mut AppState) -> bool {
    // THE INTENT GOES TO DISK BEFORE THE REQUEST LEAVES. Everything that
    // used to make a release lossy -- a lock while the worker ran, a failed
    // write afterwards, an ordinary exit -- is answered here: the next
    // unlock finds this record and asks the server again. Releasing the
    // same device twice is free, so the retry costs nothing.
    let Ok(Some(device_id)) = device_id_if_present(&state.vault_path) else {
        return false;
    };
    let here = hex_encode_16(&device_id);
    let Some(vault) = state.vault.as_mut() else {
        return false;
    };
    if vault.begin_release(&here).is_err() {
        crate::licence_control::set_activation_result("vault_io");
        return false;
    }
    start_release_call(state)
}

/// The network half, without recording the intent: the unlock-time RETRY of
/// a release already recorded in the vault comes through here.
pub fn start_release_call(state: &AppState) -> bool {
    let vault_path = state.vault_path.clone();
    let Ok(Some(device_id)) = device_id_if_present(&vault_path) else {
        return false;
    };
    let Some(mut record) = state.vault.as_ref().and_then(|v| v.licence_record()) else {
        return false;
    };
    let Some(license_id_hex) = crate::licence_control::current_license_id_hex() else {
        record.token_text.zeroize();
        return false;
    };
    crate::licence_control::mark_activation_in_flight();
    let proxy = state.proxy();
    let handle = std::thread::spawn(move || {
        let result = release_blocking(&record.token_text, &device_id);
        record.token_text.zeroize();
        let _ = proxy.send_event(crate::UserEvent::Activation(ActivationEvent {
            kind: CallKind::Release,
            license_id_hex,
            device_id_hex: hex_encode_16(&device_id),
            activate: None,
            release: Some(result),
        }));
    });
    remember_worker(handle);
    true
}

/// Back on the event loop: record the outcome in the vault and the session,
/// then tell the chrome. If the vault locked or the licence changed while
/// the worker ran, the result is dropped: it belongs to a state that no
/// longer exists.
pub fn handle_event(state: &mut AppState, event: ActivationEvent) {
    handle_event_from(state, event, true);
}

/// `from_worker`: true when a worker thread just finished (its busy flag is
/// cleared here); false for a REPLAY of a parked result, which must not
/// clear the flag of whatever worker may be running now.
fn handle_event_from(state: &mut AppState, event: ActivationEvent, from_worker: bool) {
    if from_worker {
        crate::licence_control::clear_activation_in_flight();
    }
    // Vault locked meanwhile: KEEP the result for the next unlock rather
    // than drop it. The licence check below cannot run now (the session is
    // gone with the lock) and runs at replay instead.
    if state.vault.is_none() {
        // ACTIVATION results only. A release result needs no in-memory
        // parking: the vault already records that this device is being
        // released, so the next unlock retries the call whatever happens
        // to this answer. (It used to be parked here, and every way that
        // parking could be lost or overwritten was a way for a released
        // device to come back to life.)
        if event.kind == CallKind::Activate {
            state.pending_activation_event = Some(event);
        }
        return;
    }
    let still_same_licence =
        crate::licence_control::current_license_id_hex().as_deref() == Some(&*event.license_id_hex);
    if !still_same_licence {
        return;
    }
    let Some(vault) = state.vault.as_mut() else {
        return;
    };
    match event.kind {
        CallKind::Activate => match event.activate {
            Some(ActivateOutcome::Activated { receipt_text }) => {
                let mut records: Vec<patanyx_vault::ActivationRecord> = vault
                    .activation_records()
                    .into_iter()
                    // Prune to the current licence and drop any older row
                    // for this device: one row per device, receipts of a
                    // replaced licence are dead weight.
                    .filter(|r| {
                        r.license_id_hex == event.license_id_hex
                            && r.device_id_hex != event.device_id_hex
                    })
                    .collect();
                records.push(patanyx_vault::ActivationRecord {
                    license_id_hex: event.license_id_hex.clone(),
                    device_id_hex: event.device_id_hex.clone(),
                    receipt_text,
                });
                // At most five per licence: the server never grants more
                // than five ACTIVE, so a sixth row here is stale.
                while records.len() > 5 {
                    records.remove(0);
                }
                // A successful activation supersedes an earlier release OF
                // THIS DEVICE: the marker that suppresses silent
                // re-activation must not outlive the receipt it guards. Only
                // this device's marker: a vault that travelled from a device
                // that released must keep saying so for that device.
                if vault.set_activation_records(records).is_err()
                    || vault.clear_released_device_if(&event.device_id_hex).is_err()
                    || vault.clear_release_pending_if(&event.device_id_hex).is_err()
                {
                    crate::licence_control::set_activation_result("vault_io");
                } else {
                    // Re-run the unlock-time evaluation from the vault: the
                    // same offline path every later unlock takes decides
                    // that this device is now activated. No cached bit.
                    crate::licence_control::on_vault_unlocked(state);
                }
            }
            Some(ActivateOutcome::Refused(code)) => {
                crate::licence_control::set_activation_result(refusal_code(&code));
            }
            Some(ActivateOutcome::Offline(why)) => {
                eprintln!("patanyx activation: could not reach the licence server ({why})");
                crate::licence_control::set_activation_result(offline_reason(&why));
            }
            None => {}
        },
        CallKind::Release => match event.release {
            Some(Ok(_released)) => {
                // Released on the server (or it never held a slot there):
                // either way this device's receipt is dead. Remove it, then
                // re-evaluate: Premium goes off on THIS machine, in front of
                // the user, which is what release means. No app-side copy of
                // the receipts here: the vault filters its own rows and wipes
                // the old ones, and a clone would be plaintext left behind.
                //
                // ONE durable write drops the receipt, records the release
                // and answers the started-release record together. If it
                // fails, the started-release record is still on disk: the
                // next unlock asks the server again and writes again. So a
                // failed write costs a retry, never the user's decision.
                if vault.release_device(&event.device_id_hex).is_ok() {
                    crate::licence_control::set_activation_result("released");
                    crate::licence_control::on_vault_unlocked(state);
                } else {
                    crate::licence_control::on_vault_unlocked(state);
                    crate::licence_control::set_activation_result("vault_io");
                }
            }
            Some(Err(why)) => {
                eprintln!("patanyx activation: release did not reach the licence server ({why})");
                crate::licence_control::set_activation_result(release_reason(&why));
            }
            None => {}
        },
    }
    state.emit("licence_changed", json!({}));
}

/// OFFLINE ACTIVATION. Import a receipt minted elsewhere, for a machine that
/// cannot reach EdgeXene at all -- a corporate network (Zscaler and the like)
/// that blocks the licence host outright, where no proxy setting can help.
///
/// The receipt is the SAME artifact `/premium/activate` returns. It is stored
/// and then judged by the SAME unlock-time evaluation every activation goes
/// through (`on_vault_unlocked` -> `activation_state` -> `Receipt::parse` +
/// `binds`). So this adds NO new trust path: a forged receipt, or a genuine one
/// minted for another device or another licence, fails to bind exactly as it
/// would after a normal unlock, and is rolled back. The only thing that reaches
/// Premium is a receipt whose signature verifies against the compiled-in ring
/// AND whose device id is this machine's AND whose licence is the one held.
///
/// Needs no network, so it is not behind `updater-net`: a locked-down machine
/// is exactly the one that may be built or run without the network client.
///
/// Returns a code for the chrome: "activated"; "receipt_malformed" (not a
/// prx1- receipt); "receipt_rejected" (parsed but did not verify or bind here);
/// "no_licence" (paste the token first); "locked"; "device_id"; "vault_io".
pub fn import_receipt(state: &mut AppState, receipt_text: &str) -> &'static str {
    let receipt_text = receipt_text.trim();
    if !receipt_text.starts_with("prx1-") {
        // `ptx1-` (the licence TOKEN) and `prx1-` (this device's activation
        // receipt) differ by one character and both are pasted from the same
        // panel, so pasting the token here is the predictable mistake rather
        // than an exotic one. Name it: a generic "malformed" sends the reader
        // hunting for a typo in a string that was never the right string.
        if receipt_text.starts_with("ptx1-") {
            return "looks_like_token";
        }
        return "receipt_malformed";
    }
    let device_id = match device_id_or_mint(&state.vault_path) {
        Ok(id) => id,
        Err(_) => return "device_id",
    };
    let Some(license_id_hex) = crate::licence_control::current_license_id_hex() else {
        return "no_licence";
    };
    let device_id_hex = hex_encode_16(&device_id);

    // Snapshot the records so a receipt that does not verify at evaluation can
    // be rolled back cleanly -- the vault must not keep a receipt Premium won't
    // honour.
    let previous = match state.vault.as_mut() {
        Some(vault) => vault.activation_records(),
        None => return "locked",
    };
    let mut records: Vec<patanyx_vault::ActivationRecord> = previous
        .iter()
        .cloned()
        // Same rule as the network path: one row per device, current licence.
        .filter(|r| r.license_id_hex == license_id_hex && r.device_id_hex != device_id_hex)
        .collect();
    records.push(patanyx_vault::ActivationRecord {
        license_id_hex: license_id_hex.clone(),
        device_id_hex: device_id_hex.clone(),
        receipt_text: receipt_text.to_string(),
    });
    while records.len() > 5 {
        records.remove(0);
    }
    match state.vault.as_mut() {
        Some(vault) => {
            if vault.set_activation_records(records).is_err() {
                return "vault_io";
            }
        }
        None => return "locked",
    }

    // The one and only judge: the unlock-time evaluation, run from the vault.
    crate::licence_control::on_vault_unlocked(state);
    let activated = crate::licence_control::current()
        .map(|s| s.activation == crate::licence_control::ActivationState::Activated)
        .unwrap_or(false);
    if activated {
        // An imported receipt is the user activating this device on purpose:
        // an earlier release of it is over, like every other activation --
        // including one still parked for retry, which would otherwise delete
        // this receipt at the next unlock.
        if let Some(vault) = state.vault.as_mut() {
            if vault.clear_released_device_if(&device_id_hex).is_err()
                || vault.clear_release_pending_if(&device_id_hex).is_err()
            {
                return "vault_io";
            }
        }
        state.emit("licence_changed", json!({}));
        return "activated";
    }

    // Rejected: restore what was there and re-evaluate, so a bad paste leaves
    // no trace and cannot displace a receipt that was already valid.
    if let Some(vault) = state.vault.as_mut() {
        let _ = vault.set_activation_records(previous);
    }
    crate::licence_control::on_vault_unlocked(state);
    "receipt_rejected"
}

/// The server's refusal codes, narrowed to the ones the copy knows; any
/// other string is reported as a generic refusal rather than echoed.
fn refusal_code(code: &str) -> &'static str {
    match code {
        "slots_full" => "slots_full",
        "grants_exhausted" => "grants_exhausted",
        "expired" => "expired",
        "bad_token" => "bad_token",
        _ => "refused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token-safety line of the reachability fallback: a connect failure
    /// retries direct (that is how a stale corporate proxy on a home network is
    /// rescued), but a CERTIFICATE refusal never does. If this ever flipped for
    /// `Intercepted`, activation would answer a re-signing proxy by trying the
    /// same call direct and burying the "this network is inspecting you"
    /// warning -- and the whole reason the token is withheld there.
    #[test]
    fn only_a_connect_failure_retries_direct_never_a_certificate_one() {
        assert!(retry_direct_after(FailureKind::Offline), "a dead proxy must fall back to direct");
        assert!(!retry_direct_after(FailureKind::Intercepted), "a re-signing proxy must NOT retry direct");
        assert!(!retry_direct_after(FailureKind::OtherCertificate));
        assert!(!retry_direct_after(FailureKind::TunnelCarried));
    }

    #[test]
    fn a_missing_device_id_is_minted_once_and_then_stable() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.bin");
        assert_eq!(device_id_if_present(&vault_path), Ok(None));
        let first = device_id_or_mint(&vault_path).unwrap();
        let second = device_id_or_mint(&vault_path).unwrap();
        assert_eq!(first, second);
        assert_eq!(device_id_if_present(&vault_path), Ok(Some(first)));
        let raw = std::fs::read_to_string(device_id_path(&vault_path)).unwrap();
        assert_eq!(raw.trim_end().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(device_id_path(&vault_path))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_unreadable_device_id_is_refused_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.bin");
        std::fs::write(device_id_path(&vault_path), "garbage\n").unwrap();
        assert_eq!(
            device_id_if_present(&vault_path),
            Err(DeviceIdError::Unreadable)
        );
        assert_eq!(
            device_id_or_mint(&vault_path),
            Err(DeviceIdError::Unreadable)
        );
        assert_eq!(
            std::fs::read_to_string(device_id_path(&vault_path)).unwrap(),
            "garbage\n"
        );
        // Uppercase is not ours either.
        std::fs::write(device_id_path(&vault_path), "AB".repeat(16)).unwrap();
        assert_eq!(
            device_id_if_present(&vault_path),
            Err(DeviceIdError::Unreadable)
        );
    }

    #[test]
    fn hex_round_trips() {
        let id = [0xd1u8; 16];
        assert_eq!(decode_hex_16(&hex_encode_16(&id)), Some(id));
        assert_eq!(decode_hex_16("zz"), None);
    }

    #[test]
    fn server_replies_map_to_outcomes() {
        assert_eq!(
            outcome_from_reply(Ok((200, json!({"receipt": "prx1-abc"})))),
            ActivateOutcome::Activated {
                receipt_text: "prx1-abc".to_string()
            }
        );
        assert!(matches!(
            outcome_from_reply(Ok((200, json!({"receipt": "ptx1-not-a-receipt"})))),
            ActivateOutcome::Offline(_)
        ));
        assert_eq!(
            outcome_from_reply(Ok((409, json!({"error": "slots_full"})))),
            ActivateOutcome::Refused("slots_full".to_string())
        );
        assert_eq!(
            outcome_from_reply(Ok((401, json!({"error": "bad_token"})))),
            ActivateOutcome::Refused("bad_token".to_string())
        );
        assert!(matches!(
            outcome_from_reply(Ok((502, json!({})))),
            ActivateOutcome::Offline(_)
        ));
        assert!(matches!(
            outcome_from_reply(Err(CallFailure::offline("timeout"))),
            ActivateOutcome::Offline(_)
        ));
        assert_eq!(refusal_code("slots_full"), "slots_full");
        assert_eq!(refusal_code("something_new"), "refused");
    }

    /// ACTIVATION MUST NEVER ACCEPT AN INTERCEPTED CONNECTION.
    ///
    /// The update and blocklist channels may fall back to the OS trust store,
    /// because their integrity rests on the compiled-in Ed25519 key rather
    /// than on TLS (see `net::Roots`, security audit 2026-08-18, F21). This
    /// request is the opposite case: it SENDS the licence token and this
    /// install's device id, so TLS confidentiality is the whole protection
    /// and no signature can recover a secret already handed to a proxy.
    ///
    /// Reading the source is the only way to state "this function is not
    /// called here" as a test. Same idiom as privacy.rs's zero-channels
    /// check. If activation ever legitimately needs the relaxed agent, that
    /// is a decision to argue for in a commit message, not a line to slip in.
    #[test]
    fn activation_never_reaches_for_the_relaxed_agent() {
        // ONLY THE SHIPPED HALF. The test module below necessarily names the
        // function it is asserting the absence of, which would match itself --
        // the same self-match the export guard avoids by excluding its own
        // file. Everything above `#[cfg(test)]` is what is compiled into the
        // binary, and that is what this is about.
        let source = include_str!("activation.rs");
        let shipped = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(source);
        let needle = concat!("agent_accepting", "_os_roots");
        let calls: Vec<&str> = shipped
            .lines()
            .filter(|l| l.contains(needle))
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        assert!(
            calls.is_empty(),
            "activation must use only the strict agent; found: {calls:?}"
        );
        // And it does still build one, or it would not be talking to anything.
        assert!(
            shipped.contains("crate::net::agent("),
            "the activation call lost its agent entirely"
        );
    }

    /// Only certificate failures that fit re-signing may accuse the network.
    #[test]
    fn activation_only_calls_unknown_issuer_or_bad_signature_interception() {
        for cert in [
            rustls::CertificateError::UnknownIssuer,
            rustls::CertificateError::BadSignature,
        ] {
            let failure = CallFailure::from_certificate(cert);
            assert_eq!(
                offline_reason(&failure),
                "intercepted",
                "a re-signing-shaped trust failure lost its warning: {failure}"
            );
        }
        assert_eq!(
            offline_reason(&CallFailure::offline(
                "invalid peer certificate: UnknownIssuer",
            )),
            "offline",
            "display text must not decide the user's accusation"
        );
    }

    #[test]
    fn activation_gives_other_certificate_failures_neutral_copy() {
        for cert in [
            rustls::CertificateError::Expired,
            rustls::CertificateError::NotValidYet,
            rustls::CertificateError::Revoked,
            rustls::CertificateError::NotValidForName,
        ] {
            let failure = CallFailure::from_certificate(cert);
            let reason = offline_reason(&failure);
            assert_eq!(reason, "certificate", "{failure}");
            let copy = crate::licence_control::activation_copy(reason);
            assert!(!copy.contains("inspecting"), "{copy}");
            assert!(!copy.contains("this network"), "{copy}");
        }
    }

    #[test]
    fn activation_classifies_transport_failures_by_carrier() {
        assert_activation_carrier_split(
            "proxy construction",
            CallFailure::from_net_error_with_carrier(proxy_construction_failure(), true),
            CallFailure::from_net_error_with_carrier(proxy_construction_failure(), false),
        );
        assert_activation_carrier_split(
            "connect refused",
            CallFailure::from_transport_with_carrier(connect_refused_transport(), true),
            CallFailure::from_transport_with_carrier(connect_refused_transport(), false),
        );
        assert_activation_carrier_split(
            "timeout",
            CallFailure::from_transport_with_carrier(timeout_transport(), true),
            CallFailure::from_transport_with_carrier(timeout_transport(), false),
        );
    }

    /// Release has the same two failures and must tell them apart the same
    /// way -- and must NOT start blaming interception for a server refusal,
    /// which arrives through the same `Err` on this path.
    #[test]
    fn release_gives_other_certificate_failures_neutral_copy() {
        for cert in [
            rustls::CertificateError::Expired,
            rustls::CertificateError::NotValidYet,
            rustls::CertificateError::Revoked,
            rustls::CertificateError::NotValidForName,
        ] {
            let failure = CallFailure::from_certificate(cert);
            let reason = release_reason(&failure);
            assert_eq!(reason, "release_certificate", "{failure}");
            let copy = crate::licence_control::activation_copy(reason);
            assert!(!copy.contains("inspecting"), "{copy}");
            assert!(!copy.contains("this network"), "{copy}");
        }
        assert_eq!(
            release_reason(&CallFailure::from_certificate(
                rustls::CertificateError::UnknownIssuer,
            )),
            "release_intercepted"
        );
        assert_eq!(
            release_reason(&CallFailure::from_certificate(
                rustls::CertificateError::BadSignature,
            )),
            "release_intercepted"
        );
    }

    #[test]
    fn release_classifies_transport_failures_by_carrier() {
        assert_release_carrier_split(
            "proxy construction",
            CallFailure::from_net_error_with_carrier(proxy_construction_failure(), true),
            CallFailure::from_net_error_with_carrier(proxy_construction_failure(), false),
        );
        assert_release_carrier_split(
            "connect refused",
            CallFailure::from_transport_with_carrier(connect_refused_transport(), true),
            CallFailure::from_transport_with_carrier(connect_refused_transport(), false),
        );
        assert_release_carrier_split(
            "timeout",
            CallFailure::from_transport_with_carrier(timeout_transport(), true),
            CallFailure::from_transport_with_carrier(timeout_transport(), false),
        );
    }

    fn proxy_construction_failure() -> crate::net::NetError {
        crate::net::NetError::ProxyUnavailable("proxy could not be built".to_string())
    }

    fn connect_refused_transport() -> ureq::Transport {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let transport = transport_from(ureq::get(&format!("http://{address}/")).call());
        assert!(
            transport
                .to_string()
                .to_ascii_lowercase()
                .contains("refused"),
            "the refused-connection fixture produced a different failure: {transport}"
        );
        transport
    }

    fn timeout_transport() -> ureq::Transport {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let _connection = listener.accept().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(20))
            .build();
        let transport = transport_from(agent.get(&format!("http://{address}/")).call());
        server.join().unwrap();
        let detail = transport.to_string().to_ascii_lowercase();
        assert!(
            detail.contains("timed out") || detail.contains("timeout"),
            "the silent-server fixture produced a different failure: {transport}"
        );
        transport
    }

    fn transport_from(result: Result<ureq::Response, ureq::Error>) -> ureq::Transport {
        match result.expect_err("the test endpoint unexpectedly answered") {
            ureq::Error::Transport(transport) => transport,
            ureq::Error::Status(code, _) => panic!("test endpoint answered HTTP {code}"),
        }
    }

    fn assert_activation_carrier_split(shape: &str, tunnel: CallFailure, direct: CallFailure) {
        assert_eq!(
            offline_reason(&tunnel),
            "tunnel_carried",
            "{shape} through PATANYX's tunnel lost its carrier"
        );
        assert_eq!(
            offline_reason(&direct),
            "offline",
            "{shape} without a tunnel named one"
        );
    }

    fn assert_release_carrier_split(shape: &str, tunnel: CallFailure, direct: CallFailure) {
        assert_eq!(
            release_reason(&tunnel),
            "release_tunnel_carried",
            "{shape} through PATANYX's tunnel lost its carrier"
        );
        assert_eq!(
            release_reason(&direct),
            "release_offline",
            "{shape} without a tunnel named one"
        );
    }

    #[test]
    fn certificate_evidence_takes_precedence_inside_the_tunnel() {
        for (certificate, activation, release) in [
            (
                rustls::CertificateError::UnknownIssuer,
                "intercepted",
                "release_intercepted",
            ),
            (
                rustls::CertificateError::Expired,
                "certificate",
                "release_certificate",
            ),
        ] {
            let failure = CallFailure::from_certificate_with_carrier(certificate, true);
            assert_eq!(offline_reason(&failure), activation, "{failure}");
            assert_eq!(release_reason(&failure), release, "{failure}");
        }
    }

    #[test]
    fn tunnel_carried_copy_names_the_carrier_and_keeps_the_network_remedy() {
        for reason in ["tunnel_carried", "release_tunnel_carried"] {
            let copy = crate::licence_control::activation_copy(reason);
            let lower = copy.to_ascii_lowercase();
            assert!(!lower.contains("vpn"), "{reason}: {copy}");
            assert!(copy.contains("PATANYX sent"), "{reason}: {copy}");
            assert!(copy.contains("through its own tunnel"), "{reason}: {copy}");
            assert!(
                copy.contains("could not reach EdgeXene"),
                "{reason}: {copy}"
            );
            assert!(
                lower.contains("another network"),
                "{reason} lost the alternative-network remedy: {copy}"
            );
        }
    }

    /// The release copy must not promise the one-time workaround activation
    /// can offer: a release has to reach the server or the slot stays counted.
    #[test]
    fn the_release_copy_offers_no_one_time_workaround() {
        let copy = crate::licence_control::activation_copy("release_intercepted");
        assert_ne!(copy, crate::licence_control::activation_copy("no_such_reason"));
        assert!(copy.contains("inspecting"), "{copy}");
        assert!(
            !copy.contains("stays activated"),
            "release borrowed activation's one-time promise, which is not true here: {copy}"
        );
    }

    /// Every reason the activation path can produce must have a sentence.
    #[test]
    fn the_new_reason_has_copy_and_it_is_not_the_fallback() {
        let copy = crate::licence_control::activation_copy("intercepted");
        assert_ne!(
            copy,
            crate::licence_control::activation_copy("no_such_reason"),
            "`intercepted` fell through to the generic refusal sentence"
        );
        assert!(
            copy.contains("inspecting"),
            "the copy must say what actually happened: {copy}"
        );
        assert!(
            !copy.contains("try again"),
            "the copy must not invite a retry that cannot succeed: {copy}"
        );
    }

    #[test]
    fn the_origin_override_only_accepts_loopback() {
        // USERINFO IS NOT A HOST (security audit 2026-08-18, F5). The last
        // `@` ends the userinfo, so each of these has a real host that is not
        // loopback while BEGINNING with a loopback-looking string. A prefix
        // test accepted every one and aimed the activation POST -- the full
        // licence token and this install's device id -- at the attacker.
        for spelling in [
            "http://localhost:@evil.example/",
            "http://127.0.0.1:@evil.example/",
            "http://localhost:8788@evil.example/",
            "http://127.0.0.1:1@evil.example/",
            // A host that merely starts with the loopback name.
            "http://localhost.evil.example:8788/",
            "http://127.0.0.1.evil.example:8788/",
            // https is not the shape this hook takes.
            "https://127.0.0.1:8788/",
        ] {
            std::env::set_var("PATANYX_LICENCE_ORIGIN", spelling);
            assert_ne!(
                licence_origin(),
                spelling,
                "a non-loopback host reached the override: {spelling}"
            );
        }
        // The genuine article still works, or the end-to-end gate cannot run.
        for good in ["http://127.0.0.1:18788", "http://localhost:18788"] {
            std::env::set_var("PATANYX_LICENCE_ORIGIN", good);
            if cfg!(debug_assertions) {
                assert_eq!(licence_origin(), good, "loopback override refused: {good}");
            } else {
                // Release builds carry no override at all (pentest F-009).
                assert_eq!(licence_origin(), crate::updater::base_url(), "a release build honoured the override");
            }
        }
        std::env::set_var("PATANYX_LICENCE_ORIGIN", "http://evil.example");
        assert_eq!(licence_origin(), crate::updater::base_url());
        std::env::set_var("PATANYX_LICENCE_ORIGIN", "http://127.0.0.1:18788");
        if cfg!(debug_assertions) {
            assert_eq!(licence_origin(), "http://127.0.0.1:18788");
        } else {
            assert_eq!(licence_origin(), crate::updater::base_url());
        }
        std::env::remove_var("PATANYX_LICENCE_ORIGIN");
        assert_eq!(licence_origin(), crate::updater::base_url());
    }
}
