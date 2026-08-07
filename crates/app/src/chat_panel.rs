//! Chat wiring for the app crate: owns the `patanyx-chat` transport on the
//! event-loop thread, keeps chat secrets in the vault, and implements the IPC
//! surface the chrome chat panel drives.
//!
//! The entire module exists only with `--features chat` (the `mod` item at the
//! crate root is `#[cfg(feature = "chat")]`). The published build contains
//! none of this: `patanyx-chat` is an optional dependency and this file is
//! the only place the app references it.
//!
//! Security invariants enforced here (brief §0):
//!
//!   * TEXT ONLY. Payloads are JSON text envelopes inside chat sessions and
//!     the transport refuses non-UTF-8 before reporting a message, so no
//!     binary decoder ever sees peer bytes. Received strings go to the chrome
//!     webview as JSON values and are inserted with `textContent` there —
//!     never `innerHTML` — because the chrome webview holds IPC and vault
//!     access.
//!   * NOTHING IS STORED. No history, no queue; sending to an offline peer
//!     returns the distinct `peer_offline` refusal (synchronously from the
//!     session mirror, asynchronously as a `SendFailed` event). Store-and-
//!     forward is the one feature that would pull the project out of "mere
//!     conduit" territory, so it is refused by construction.
//!   * PRESENCE IS MANUAL. Nothing announces the user — not browser start,
//!     not vault unlock, not adding a contact, not minting an identity. The
//!     transport runs only after an explicit "Go online" (`chat_go_online`)
//!     and is torn down on "Go offline", on vault lock, and on exit.
//!     Teardown withdraws every mDNS announcement (with goodbyes) and drops
//!     any relay registration. Presence is never inferred or published as a
//!     side effect of anything else the user did.
//!   * AFK IS IN-BAND. Away is the one presence state the network cannot
//!     infer (offline is mere absence — a peer who is not announcing is
//!     offline, no marker needed), so it must be actively announced. It
//!     travels as a `Status` envelope INSIDE the encrypted session, never
//!     in the mDNS TXT record: "this person is not at their keyboard" is
//!     behavioural metadata a contact may learn, but a TXT record is
//!     browsable by every device on the LAN — strangers' laptops included —
//!     and "nobody is watching this screen" is not something to broadcast
//!     to a room. The chat channel reaches exactly the contacts the user
//!     chose, over an authenticated encrypted session. Cost, stated
//!     honestly: a contact with no live session never sees orange — the
//!     flag is pushed on every SessionEstablished and broadcast on toggle
//!     to live sessions, which are the only places it can be seen anyway.
//!   * RELAY = ONE CHOSEN IDENTITY. The relay is optional and off unless the
//!     user configures it. When configured, EXACTLY the user-selected
//!     identity is registered — never the whole per-contact set, which a
//!     remote relay could link to one connection. Settings (URL, on/off,
//!     which identity) live in the vault: they tie a person to a relay
//!     operator and a registered address, so they belong in the only
//!     encrypted store the app opens, and they lock away with the identities
//!     they reference.
//!   * A received tab URL is untrusted navigation input. It is checked
//!     against the content allowlist when it arrives AND again when the user
//!     accepts it, so a peer can never steer the browser to `file://` or the
//!     privileged chrome origin, and consent never opens the foreground.
//!   * Contact keypairs live only in the encrypted vault, one per contact,
//!     so revoking a contact breaks exactly that one address. The transport
//!     holds all of them at once and announces every fingerprint on the LAN
//!     (acceptable there — observers are physically present); it never
//!     answers a handshake with a different key than the one dialed. The
//!     ephemeral identity below never leaves memory.

// Integration points, all live:
//   * `main.rs` declares this module behind `--features chat`, carries the
//     `UserEvent::Chat(TransportEvent)` variant, dispatches it to
//     `handle_transport_event`, and calls `shutdown` on `LoopDestroyed` so the
//     transport's threads JOIN rather than detach.
//   * `state.rs` holds `chat: ChatState` and calls `on_vault_locked` from both
//     lock paths — the transport's identities come out of the vault, so a
//     locked vault must stop announcing them.
//   * `ipc.rs` dispatches the `chat_*` commands below and evaluates `CHAT_JS`
//     into the chrome webview on chrome.js's first ping. index.html
//     deliberately does not reference chat.js, so a non-chat build never asks
//     for an asset it does not serve.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;

use patanyx_chat::wire::ErrorCode;
use patanyx_chat::{
    validate_outgoing, ChatError, Delivery, DiscoveryState, Fingerprint, Identity, MessageId,
    RelayConfig, SendFailure, Transport, TransportConfig, TransportEvent,
};

use crate::ipc::vault_code;
use crate::state::{is_allowed_content_url, AppState};
use crate::UserEvent;

/// The chat panel script, embedded only in chat builds. `ipc.rs` evaluates it
/// into the chrome webview on chrome.js's first ping.
pub const CHAT_JS: &str = include_str!("chrome/chat.js");

const MAX_LABEL_CHARS: usize = 64;

/// Whether this build contains the relay client. The app feature forwards to
/// `patanyx-chat/relay-client`; it is OFF by default because `ring` breaks
/// the Windows cross-compile — a build constraint, not a policy. When false,
/// relay settings persist but stay inert, and the UI must SAY the support is
/// not compiled in rather than silently hiding the option.
const RELAY_COMPILED: bool = cfg!(feature = "relay-client");

// ---------------------------------------------------------------------------
// Payload envelopes
//
// Everything beyond plain chat is a JSON TEXT envelope inside the same
// encrypted session: still text-only on the wire (no binary payload path),
// still capped at MAX_MESSAGE_BYTES, still sealed to exactly one peer.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChatPayload {
    Text { text: String },
    Tab { url: String },
    Credential {
        site: String,
        username: String,
        password: String,
        note: String,
    },
    /// "Here is my digest ladder for `url` (normalized); compare yours."
    /// `url` travels alongside so the receiver can match it against its open
    /// tabs (and tell its user what is being compared) before decoding.
    CorroborateRequest { url: String, data: String },
    /// The other half of the ladder, for the same URL.
    CorroborateResponse { data: String },
    /// Machine-readable "cannot compare" (page not open here, platform
    /// unsupported, ...) so the asking side is not left waiting forever.
    /// `reason` is pinned to a fixed vocabulary by the receiver.
    CorroborateNote { reason: String },
    /// "I am away" / "I am back": the AFK marker, the ONLY writer of a
    /// peer's away flag. Purely a courtesy signal — delivery is unaffected
    /// (spec: messages to an AFK contact are delivered normally). It rides
    /// the encrypted session on purpose (see the module docs); an old build
    /// decodes unknown `kind`s to plain display text, so a peer on an older
    /// version sees the envelope as a message rather than misfiring.
    Status { away: bool },
}

fn encode_payload(payload: &ChatPayload) -> Result<String, ChatError> {
    // Serializing these string-only payloads cannot actually fail; the
    // map_err exists only because serde_json's signature forces the question.
    let text = serde_json::to_string(payload).map_err(|_| ChatError::NotText)?;
    // Reject rather than truncate: the sender must see exactly what the
    // recipient reads.
    validate_outgoing(&text)?;
    Ok(text)
}

fn decode_payload(text: &str) -> ChatPayload {
    // Anything that is not a well-formed envelope — including unknown or
    // hand-crafted `kind` values — degrades to plain display-only text. That
    // is the safe path: a malformed structured message can never trigger
    // behaviour, it can only be read.
    serde_json::from_str(text)
        .unwrap_or_else(|_| ChatPayload::Text { text: text.to_string() })
}

/// Validation for URLs received from peers (brief §5). The same allowlist as
/// tab creation: http/https/about:blank and never the chrome origin. Called
/// when the URL arrives and again in `ipc_accept_tab`, because the chrome
/// confirm dialog merely relays the user's click — the peer controls the
/// string, so the check must live here.
pub fn validate_incoming_tab_url(url: &str) -> Result<(), &'static str> {
    if is_allowed_content_url(url) {
        Ok(())
    } else {
        Err("bad_args")
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct PeerState {
    online: bool,
    /// A session exists with this peer.
    ///
    /// This used to mean two things at once — "we have a session" and "we
    /// can reach them" — and the second was never cleared when a link died,
    /// because link death emitted no event at all. A send therefore passed
    /// the pre-check and went out on a route that no longer existed. The two
    /// facts are separate now; `reachable` is the one to test before sending.
    connected: bool,
    /// A route to this peer exists right now. Cleared by
    /// `SessionUnreachable`, restored by `SessionReachable`.
    reachable: bool,
    /// The peer's announced AFK flag (`Status` envelope). False means
    /// "present or unknown" — the safe default, since away can only ever be
    /// asserted by the peer themselves and is never inferred locally.
    away: bool,
    /// Pass-through of the transport's `verified` flag so the UI can show
    /// when a session was NOT pinned to an expected static key. See
    /// `start_transport` for why every session is currently unverified and
    /// why that is acceptable in the contact model.
    verified: bool,
}

pub struct ChatState {
    /// Some iff the user has gone online: transport running == announced and
    /// reachable. There is deliberately no half-running state.
    transport: Option<Transport>,
    /// The user's explicit intent, set only by `chat_go_online` /
    /// `chat_go_offline` (and cleared by vault lock). Separate from
    /// `transport` so a failed start does not read as "chose to be online".
    online: bool,
    /// The user's own AFK flag, set only by `chat_set_away` and cleared by
    /// going offline. Away is a state you are in WHILE announcing; it never
    /// survives a teardown into the next online session — a status is a
    /// deliberate act, not a sticky preference.
    away: bool,
    /// Keyed by the peer's hash NUMBER (String, not Fingerprint) so no trait
    /// bounds are assumed of the chat crate's Fingerprint type. Only
    /// currently-visible peers are kept; a vanished peer is simply absent,
    /// which the UI renders as "offline".
    peers: HashMap<String, PeerState>,
    discovery: &'static str,
    /// Last reported relay link state: "off" | "connecting" | "up" | "down".
    /// Meaningful only while online with a relay configured; the reported
    /// state is derived in `relay_state_label`.
    relay_link: &'static str,
    /// Last connection-level error the relay sent us (e.g. the address is
    /// already registered from another connection). Cleared on RelayUp.
    relay_error: Option<&'static str>,
    /// Throwaway keypair for chats with peers that were never added as
    /// contacts (brief §2). Never written to the vault; dropped on lock/exit.
    ephemeral_secret: Option<[u8; 32]>,
    ephemeral_in_transport: bool,
}

impl Default for ChatState {
    fn default() -> Self {
        Self {
            transport: None,
            online: false,
            away: false,
            peers: HashMap::new(),
            discovery: "starting",
            relay_link: "off",
            relay_error: None,
            ephemeral_secret: None,
            ephemeral_in_transport: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Transport lifecycle helpers
// ---------------------------------------------------------------------------

fn identity_from_secret(secret: [u8; 32]) -> Identity {
    Identity::from_secret_bytes(secret)
}

fn fresh_secret() -> [u8; 32] {
    Identity::generate().secret_bytes()
}

fn hash_of_secret(secret: [u8; 32]) -> String {
    identity_from_secret(secret).fingerprint().to_hash_number()
}

fn start_transport(
    identities: Vec<Identity>,
    relay: Option<RelayConfig>,
    relay_token: Option<Vec<u8>>,
    proxy: EventLoopProxy<UserEvent>,
) -> Result<Transport, ChatError> {
    let config = TransportConfig {
        // ALL identities are handed over and ALL their fingerprints are
        // announced on the LAN — the deliberate multi-identity decision: a
        // LAN observer is physically present and learns almost nothing from
        // co-announcement, while a contact who dials one fingerprint is only
        // ever answered by that one.
        identities,
        // The relay, by contrast, gets EXACTLY ONE identity — the one the
        // user picked in the relay settings (see RelayConfig). None means
        // LAN-only: no relay is ever contacted that the user did not
        // configure.
        relay,
        // Ephemeral LAN port; the announced port is the one actually bound.
        lan_port: 0,
        // The vault stores each contact's peer as a FINGERPRINT, which cannot
        // be inverted to the static key bytes this callback would return, so
        // no key-pinning closure can be offered. Sessions are still bound to
        // the peer's static key by the transport's anti-spoofing check (the
        // `from` fingerprint must match the handshake's identity key), and we
        // only ever dial the fingerprint stored for the contact — the hash
        // number the user verified out of band when adding them. `verified:
        // false` on SessionEstablished therefore means "not pinned by key
        // bytes", not "anonymous stranger".
        expected_peer_key: None,
        // The Premium licence token's wire bytes (P3, design 4.1), opaque
        // to the transport. None whenever no valid token is stored — which
        // changes nothing on the wire while the relay's enforcement is
        // config-gated off.
        relay_token,
    };
    Transport::start(config, move |event| {
        // Established app pattern (brief §1): the callback never touches
        // state; everything is re-dispatched onto the event-loop thread. A
        // send error means the loop is going away — the only time dropping
        // an event is acceptable.
        let _ = proxy.send_event(UserEvent::Chat(event));
    })
}

/// The UI needs to tell three situations apart, because they call for
/// different words: peers are findable, the network appears to be eating
/// multicast, and mDNS is not working here at all. Collapsing `Quiet` into
/// "no peers" is what produces the empty list that reads as "nobody is
/// there" — the exact dishonesty the discovery heuristic exists to avoid.
fn discovery_label(state: &DiscoveryState) -> &'static str {
    match state {
        DiscoveryState::Active => "active",
        DiscoveryState::Quiet => "quiet",
        DiscoveryState::Unavailable => "unavailable",
    }
}

fn chat_code(error: ChatError) -> &'static str {
    match error {
        ChatError::TooLong => "too_long",
        // NotText is only produced while decoding inbound bytes; surfaced as
        // bad_args here because the caller handed us something unsendable.
        ChatError::NotText => "bad_args",
        _ => "io",
    }
}

/// Maps the transport's send refusal to the IPC/UI code. `Offline` MUST stay
/// distinguishable: refusing offline delivery (never queuing it) is the
/// designed behaviour, so it can never collapse into a generic failure.
/// Every cause gets its own code, and that is the point of having causes.
/// `peer_offline` used to be the catch-all, so its copy -- "they are not on
/// this network right now, nothing was sent and nothing is waiting" -- ran
/// under messages to peers who were demonstrably present, after we closed a
/// working link for overflow. The transport now names the hop; this mapping
/// must stay one-to-one so no cause borrows another's wording.
fn send_failure_code(failure: &SendFailure) -> &'static str {
    failure.as_str()
}

/// Message ids reach the chrome as hex, matching how every other byte string
/// crosses the IPC boundary. The chrome treats it as an opaque key.
fn hex_mid(mid: &MessageId) -> String {
    let mut out = String::with_capacity(mid.len() * 2);
    for byte in mid {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// Note: assumed helper — the same one that pushes `url_changed`,
// `vault_locked`, `download_started`, ... to the chrome webview.
fn emit(state: &AppState, event: &str, data: Value) {
    state.emit(event, data);
}

// ---------------------------------------------------------------------------
// Relay settings (persisted in the vault — see the module docs for why)
// ---------------------------------------------------------------------------
//
// Note: vault API assumed and NOT yet implemented — see the vault
// snippet in this change set. `RelaySettings { enabled: bool,
// url: Option<String>, identity_hash: Option<String> }`, exported from
// `patanyx_vault` under the same feature as `ContactBook`, with
// `chat_relay_settings(&self) -> RelaySettings` (defaults when never set)
// and `set_chat_relay_settings(&mut self, RelaySettings) ->
// Result<(), VaultError>` persisting immediately, the way
// `set_chat_identity` does.
use patanyx_vault::RelaySettings;

fn relay_settings(state: &AppState) -> RelaySettings {
    state
        .vault
        .as_ref()
        .map(|vault| vault.chat_relay_settings())
        .unwrap_or_default()
}

/// Hash numbers of every identity we currently hold (long-term + one per
/// contact). The ephemeral throwaway key is deliberately NOT eligible for
/// relay registration: it is not persisted, so a settings reference to it
/// would dangle on the next run.
fn held_identity_hashes(state: &AppState) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(vault) = state.vault.as_ref() {
        if let Some(secret) = vault.chat_identity() {
            out.push(hash_of_secret(secret));
        }
        out.extend(
            vault
                .list_contacts()
                .iter()
                .map(|contact| hash_of_secret(contact.our_secret)),
        );
    }
    out
}

/// Syntactic gate for the relay URL; the relay client does the full parse.
/// TLS is mandatory — there is no `ws://` mode in the protocol.
///
/// Its own error code rather than `bad_args`, because the requirement is not
/// discoverable from the failure otherwise. An operator typing a perfectly
/// well-formed `http://` address got "Invalid input" and nothing telling them
/// the scheme was the problem. The validation below is unchanged and correct;
/// only the code it returns is.
/// Longest relay URL accepted. Matches `MAX_URL_LEN` in the update crate's
/// manifest parser -- the same kind of value, so the same ceiling rather than
/// a second number to reason about. This is persisted into the vault and then
/// dialled, and it had no length bound at all.
const MAX_RELAY_URL_LEN: usize = 2048;

fn validate_relay_url(url: &str) -> Result<String, &'static str> {
    if url.len() > MAX_RELAY_URL_LEN {
        return Err("bad_relay_url");
    }
    let rest = url.strip_prefix("wss://").ok_or("bad_relay_url")?;
    let host = rest
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or_default();
    if host.is_empty() {
        return Err("bad_relay_url");
    }
    Ok(url.to_string())
}

/// Validates relay settings from IPC args into a persistable shape. Pure
/// (the held-identity check is a closure) so the rules are unit-testable:
///
///   * junk input is rejected even when disabled — nothing invalid persists;
///   * enabling requires a compiled relay client, a server URL, and the hash
///     number of an identity we actually hold (never a contact's hash, never
///     a removed contact's key — no substitution, ever).
fn parse_relay_settings(
    args: &Value,
    compiled: bool,
    holds_identity: impl Fn(&str) -> bool,
) -> Result<RelaySettings, &'static str> {
    let enabled = args
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let url = match args.get("url").and_then(Value::as_str).map(str::trim) {
        Some("") | None => None,
        Some(u) => Some(validate_relay_url(u)?),
    };
    let identity_hash = match args
        .get("identity_hash")
        .and_then(Value::as_str)
        .map(str::trim)
    {
        Some("") | None => None,
        // Canonicalize through the fingerprint type so what is stored always
        // compares equal to what identity lists carry.
        Some(h) => Some(
            Fingerprint::parse_hash_number(h)
                .ok_or("bad_args")?
                .to_hash_number(),
        ),
    };
    if enabled {
        if !compiled {
            // A build constraint, surfaced honestly — never silently ignored.
            return Err("relay_unavailable");
        }
        if url.is_none() || identity_hash.is_none() {
            return Err("bad_args");
        }
        if let Some(hash) = &identity_hash {
            if !holds_identity(hash) {
                return Err("bad_args");
            }
        }
    }
    Ok(RelaySettings {
        enabled,
        url,
        identity_hash,
    })
}

/// Builds the transport's relay config from the saved settings, or None for
/// LAN-only operation. A dangling saved choice (its contact was removed) is
/// scrubbed by `ipc_contact_remove`, so a None here after `enabled` means
/// "not fully configured" and is shown as such in the UI — never as a live
/// relay.
fn relay_config_for(state: &AppState) -> Option<RelayConfig> {
    if !RELAY_COMPILED {
        return None;
    }
    let settings = relay_settings(state);
    if !settings.enabled {
        return None;
    }
    let url = settings.url?;
    let hash = settings.identity_hash?;
    let identity = Fingerprint::parse_hash_number(&hash)?;
    if !held_identity_hashes(state).iter().any(|h| h == &hash) {
        return None;
    }
    Some(RelayConfig { url, identity })
}

/// The one-word relay state the UI renders. Distinct words for distinct
/// realities, because "am I exposed to a server right now" is a question the
/// UI must answer truthfully at a glance.
fn relay_state_label(state: &AppState, settings: &RelaySettings) -> &'static str {
    if !RELAY_COMPILED {
        return "not_compiled";
    }
    if !settings.enabled {
        return "off";
    }
    if settings.url.is_none() || settings.identity_hash.is_none() {
        return "not_configured";
    }
    if !state.chat.online || state.chat.transport.is_none() {
        // Configured and enabled, but the user is offline: nothing is
        // registered anywhere, and "off" says exactly that.
        return "off";
    }
    state.chat.relay_link
}

fn relay_json(state: &AppState) -> Value {
    let settings = relay_settings(state);
    let label = relay_state_label(state, &settings);
    // The address ACTUALLY registered right now (as opposed to saved): only
    // while online with the relay link in play. The UI must never show a
    // registration that is not happening.
    let live = state.chat.online && matches!(label, "connecting" | "up" | "down");
    json!({
        "compiled": RELAY_COMPILED,
        "enabled": settings.enabled,
        "url": settings.url,
        "identity_hash": settings.identity_hash,
        "state": label,
        "active_identity_hash": if live { settings.identity_hash.clone() } else { None },
        "error": state.chat.relay_error,
    })
}

fn status_json(state: &AppState) -> Value {
    json!({
        "locked": state.vault.is_none(),
        "online": state.chat.online,
        "away": state.chat.away,
        "discovery": state.chat.discovery,
        "relay": relay_json(state),
    })
}

fn relay_error_label(code: &ErrorCode) -> &'static str {
    // Note: variant set inferred from crates/relay/src/main.rs; confirm
    // against wire.rs. The wildcard keeps unknown codes honest-but-generic.
    match code {
        // The address we tried to register already has a live connection —
        // a second device, or a stale registration the relay has not reaped.
        ErrorCode::AlreadyRegistered => "already_registered",
        ErrorCode::Unavailable => "unavailable",
        ErrorCode::VersionMismatch => "version_mismatch",
        // The Premium licence refusals (P3, design 4.4), surfaced from
        // registration via RelayEvent::Refused -> TransportEvent::RelayError.
        // chat.js's RELAY_ERROR_TEXT owns their user copy.
        ErrorCode::TokenRequired => "token_required",
        ErrorCode::TokenInvalid => "token_invalid",
        ErrorCode::TokenExpired => "token_expired",
        ErrorCode::KeyRejected => "key_rejected",
        _ => "error",
    }
}

/// The token bytes for relay registration (P3): the stored licence record,
/// re-parsed and re-verified against the compiled-in ring (design 3.3 step
/// 2's no-cached-trust rule applies here too), encoded as the 90 wire
/// bytes. None when no token is stored, the ring is unavailable (every
/// real build today), or the stored record fails verification. An EXPIRED
/// token is still sent: the relay's clock is the authority (design 3.6),
/// and its TokenExpired answer gives the user honest copy where a locally
/// withheld token would only ever produce TokenRequired.
fn relay_token_bytes(state: &AppState) -> Option<Vec<u8>> {
    use zeroize::Zeroize as _;
    let mut record = state.vault.as_ref()?.licence_record()?;
    let keys = patanyx_licence::licence_keys().ok();
    let token = keys
        .as_ref()
        .and_then(|keys| patanyx_licence::Token::parse(&record.token_text, keys).ok());
    record.token_text.zeroize();
    Some(token?.to_wire_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Transport lifecycle — driven EXCLUSIVELY by the user's presence control
// ---------------------------------------------------------------------------

/// Gathers every identity the transport should hold: one per contact, the
/// long-term one if minted, and the throwaway one if this session already
/// created it. Pure collection — announces nothing by itself.
fn gather_identities(state: &mut AppState) -> Vec<Identity> {
    // Note: vault contact/identity accessors are the new API
    // described in crates/vault/src/contacts.rs (see its header note).
    let mut secrets: Vec<[u8; 32]> = Vec::new();
    if let Some(vault) = state.vault.as_ref() {
        secrets.extend(vault.list_contacts().iter().map(|contact| contact.our_secret));
        if let Some(secret) = vault.chat_identity() {
            secrets.push(secret);
        }
    }
    if let Some(secret) = state.chat.ephemeral_secret {
        secrets.push(secret);
        state.chat.ephemeral_in_transport = true;
    }
    secrets.into_iter().map(identity_from_secret).collect()
}

/// The ONLY path that starts the transport — i.e. the only path that
/// announces anything anywhere. Called from `chat_go_online` and from the
/// apply-step of relay settings changes; never from unlock, contact add, or
/// identity minting.
fn go_online(state: &mut AppState) -> Result<(), &'static str> {
    if state.chat.transport.is_some() {
        state.chat.online = true;
        return Ok(());
    }
    let identities = gather_identities(state);
    let relay = relay_config_for(state);
    let relay_active = relay.is_some();
    // Only read the vault for a token when a relay is actually configured:
    // LAN-only operation sends nothing anywhere.
    let relay_token = if relay_active {
        relay_token_bytes(state)
    } else {
        None
    };
    match start_transport(identities, relay, relay_token, state.proxy()) {
        Ok(transport) => {
            state.chat.transport = Some(transport);
            state.chat.online = true;
            state.chat.relay_link = if relay_active { "connecting" } else { "off" };
            state.chat.relay_error = None;
            Ok(())
        }
        Err(_) => {
            // Degrade, honestly: the user is NOT online, and the UI shows
            // both the error and the offline state.
            state.chat.discovery = "unavailable";
            Err("chat_down")
        }
    }
}

/// Stops the transport and clears every derived mirror. Tearing the
/// transport down withdraws every mDNS announcement (with goodbyes) and
/// drops any relay registration — after this returns, nothing anywhere
/// announces or answers for the user. The throwaway key deliberately
/// survives: "go offline / go online" must not silently change the address
/// an ephemeral peer was given.
fn teardown_transport(state: &mut AppState) {
    if let Some(transport) = state.chat.transport.take() {
        transport.shutdown();
    }
    state.chat.peers.clear();
    state.chat.online = false;
    // Going offline retracts every signal including the AFK marker; the next
    // "Go online" starts as present-and-here. A status is a deliberate act,
    // not a sticky preference (spec: defaults and transitions).
    state.chat.away = false;
    state.chat.relay_link = "off";
    state.chat.relay_error = None;
    state.chat.discovery = "starting";
}

/// Full teardown including the throwaway key: vault lock and app exit.
/// Transport threads JOIN (brief §1).
pub fn shutdown(state: &mut AppState) {
    teardown_transport(state);
    state.chat.ephemeral_secret = None;
    state.chat.ephemeral_in_transport = false;
}

pub fn on_vault_locked(state: &mut AppState) {
    shutdown(state);
    emit(state, "chat_state", json!({ "locked": true }));
    emit(state, "chat_presence", json!({ "online": false, "away": false }));
    emit(state, "chat_relay_state", relay_json(state));
}

pub fn on_vault_unlocked(state: &mut AppState) {
    // Unlocking a password vault is NOT a request to become visible to a
    // network: no transport is started here. The panel is told the state so
    // it renders "offline" rather than something ambiguous.
    emit(state, "chat_state", json!({ "locked": false }));
    emit(state, "chat_presence", json!({ "online": false, "away": false }));
    emit(state, "chat_relay_state", relay_json(state));
}

// ---------------------------------------------------------------------------
// Transport events (arrive on the event-loop thread via UserEvent::Chat)
// ---------------------------------------------------------------------------

pub fn handle_transport_event(state: &mut AppState, event: TransportEvent) {
    match event {
        TransportEvent::PeerAppeared {
            fingerprint,
            verified,
            ..
        } => {
            // An mDNS announcement is an unauthenticated address HINT. Any
            // host on the LAN can announce any fingerprint at its own address,
            // so treating a bare announcement as presence would let a stranger
            // paint a contact green — and green means "you can message this
            // person", which is a claim we would have no basis for.
            //
            // Presence therefore comes from the two things that actually prove
            // it: a completed handshake (SessionEstablished below) or an
            // announcement at an address a handshake already verified.
            if !verified {
                return;
            }
            let hash = fingerprint.to_hash_number();
            state.chat.peers.entry(hash.clone()).or_default().online = true;
            emit_peer_state(state, &hash);
        }
        TransportEvent::PeerDisappeared { fingerprint } => {
            let hash = fingerprint.to_hash_number();
            // Absent == offline for the UI.
            state.chat.peers.remove(&hash);
            emit_peer_state(state, &hash);
        }
        TransportEvent::SessionEstablished {
            peer, verified, ..
        } => {
            let hash = peer.to_hash_number();
            // A session implies presence even if discovery missed the peer.
            let entry = state.chat.peers.entry(hash.clone()).or_default();
            entry.online = true;
            entry.connected = true;
            entry.reachable = true;
            entry.verified = verified;
            emit_peer_state(state, &hash);
            // AFK cannot be inferred from the network, so it is PUSHED: every
            // new session immediately learns our current flag (a peer who saw
            // us away yesterday must not stay orange forever), and toggles
            // broadcast to live sessions in `ipc_set_away`.
            send_status_to(state, peer);
        }
        TransportEvent::SessionFailed { peer, .. } => {
            let hash = peer.to_hash_number();
            if let Some(entry) = state.chat.peers.get_mut(&hash) {
                entry.connected = false;
                entry.reachable = false;
            }
            emit_peer_state(state, &hash);
            emit(
                state,
                "chat_notice",
                json!({ "peer_hash": hash, "reason": "session_failed" }),
            );
        }
        TransportEvent::Delivery { to, mid, state: delivery } => {
            let hash = to.to_hash_number();
            emit(
                state,
                "chat_delivery",
                json!({
                    "peer_hash": hash,
                    "mid": hex_mid(&mid),
                    "state": delivery.as_str(),
                    // Present only on a failure, and it is what lets the UI
                    // say which hop lost the message instead of blaming the
                    // peer's network for our own closed link.
                    "reason": match delivery {
                        Delivery::Failed(reason) => Some(reason.as_str()),
                        _ => None,
                    },
                }),
            );
        }
        TransportEvent::SessionUnreachable { peer } => {
            let hash = peer.to_hash_number();
            if let Some(entry) = state.chat.peers.get_mut(&hash) {
                entry.reachable = false;
            }
            emit_peer_state(state, &hash);
        }
        TransportEvent::CandidatesCapped => {
            // Announcements are being refused, so the contact list may be
            // incomplete. Saying so is the point: showing a short list as
            // though it were the whole network is the same class of lie as a
            // freeze reporting enforced.
            emit(
                state,
                "chat_notice",
                json!({ "reason": "candidates_capped" }),
            );
        }
        TransportEvent::SessionReachable { peer } => {
            let hash = peer.to_hash_number();
            if let Some(entry) = state.chat.peers.get_mut(&hash) {
                entry.reachable = true;
            }
            emit_peer_state(state, &hash);
        }
        TransportEvent::Message { from, text } => handle_message(state, from, text),
        TransportEvent::MessageDropped { from, error } => {
            let hash = from.to_hash_number();
            // `NotText` is the transport refusing non-UTF-8 peer bytes; the
            // rest are decrypt/replay/oversize drops the session survives.
            let reason = match error {
                ChatError::NotText => "undecodable",
                _ => "dropped",
            };
            emit(
                state,
                "chat_notice",
                json!({ "peer_hash": hash, "reason": reason }),
            );
        }
        TransportEvent::SendFailed { to, reason } => {
            let hash = to.to_hash_number();
            // The distinguishable offline refusal, delivered to the UI for
            // sends that were already enqueued (e.g. the link died after the
            // session mirror said connected). Nothing is queued for retry.
            emit(
                state,
                "chat_notice",
                json!({ "peer_hash": hash, "reason": send_failure_code(&reason) }),
            );
        }
        TransportEvent::IdentityNotAnnounced { fingerprint } => {
            // ONE of our addresses could not be announced; the others are
            // fine. Tell the user which, rather than letting a contact who
            // cannot find them look merely offline.
            emit(
                state,
                "chat_notice",
                json!({
                    "peer_hash": fingerprint.to_hash_number(),
                    "reason": "not_announced",
                }),
            );
        }
        TransportEvent::DiscoveryState(discovery) => {
            state.chat.discovery = discovery_label(&discovery);
            emit(
                state,
                "chat_discovery",
                json!({ "state": state.chat.discovery }),
            );
        }
        TransportEvent::RelayUp => {
            state.chat.relay_link = "up";
            state.chat.relay_error = None;
            emit(state, "chat_relay_state", relay_json(state));
        }
        TransportEvent::RelayDown => {
            // A Down during teardown is expected noise; only a live transport
            // can be "disconnected — retrying".
            if state.chat.transport.is_some() {
                state.chat.relay_link = "down";
            }
            emit(state, "chat_relay_state", relay_json(state));
        }
        TransportEvent::RelayError(code) => {
            // Connection-level refusal reported by the relay — e.g.
            // `already_registered` means this address has another live
            // registration (a second device, or a stale one). Never about
            // message contents.
            state.chat.relay_error = Some(relay_error_label(&code));
            emit(state, "chat_relay_state", relay_json(state));
        }
    }
}

fn handle_message(state: &mut AppState, from: Fingerprint, text: String) {
    let hash = from.to_hash_number();
    // A message implies a live session; reflect that before anything else.
    {
        let entry = state.chat.peers.entry(hash.clone()).or_default();
        entry.online = true;
        entry.connected = true;
    }
    let contact_id = state
        .vault
        .as_ref()
        .and_then(|vault| vault.find_contact_by_peer_hash(&hash))
        .map(|contact| contact.id.clone());
    // The transport has already refused non-UTF-8 and oversized payloads, so
    // `text` is guaranteed displayable text — it still goes to the DOM via
    // textContent, never innerHTML, in chat.js.
    match decode_payload(&text) {
        ChatPayload::Text { text } => {
            emit(
                state,
                "chat_message",
                json!({ "peer_hash": hash, "contact_id": contact_id, "text": text }),
            );
        }
        ChatPayload::Tab { url } => {
            // First allowlist check, before the UI is even told (see the
            // second one in ipc_accept_tab).
            if validate_incoming_tab_url(&url).is_ok() {
                emit(
                    state,
                    "chat_tab_received",
                    json!({ "peer_hash": hash, "contact_id": contact_id, "url": url }),
                );
            } else {
                // Tell the user it was REFUSED — silently dropping would look
                // like a lost message, and the refusal is the security
                // property working as designed.
                emit(
                    state,
                    "chat_notice",
                    json!({ "peer_hash": hash, "contact_id": contact_id, "reason": "refused_url" }),
                );
            }
        }
        ChatPayload::Credential {
            site,
            username,
            password,
            note,
        } => {
            // NOTHING is written to the vault here. The offer is forwarded
            // and the receiver must confirm; only then does the existing
            // `cred_add` path store it (brief §6).
            emit(
                state,
                "chat_credential_offered",
                json!({
                    "peer_hash": hash,
                    "contact_id": contact_id,
                    "site": site,
                    "username": username,
                    "password": password,
                    "note": note,
                }),
            );
        }
        ChatPayload::CorroborateRequest { url, data } => {
            crate::page_integrity::handle_corroborate_request(state, hash, contact_id, url, data);
        }
        ChatPayload::CorroborateResponse { data } => {
            crate::page_integrity::handle_corroborate_response(state, hash, contact_id, data);
        }
        ChatPayload::CorroborateNote { reason } => {
            crate::page_integrity::handle_corroborate_note(state, hash, contact_id, &reason);
        }
        ChatPayload::Status { away } => {
            // The AFK marker, and the ONLY writer of a peer's away flag:
            // asserted by the peer themselves, inside the encrypted session.
            // Nothing here is inferred — no idle timers, no last-seen.
            state.chat.peers.entry(hash.clone()).or_default().away = away;
            emit_peer_state(state, &hash);
        }
    }
}

fn emit_peer_state(state: &AppState, peer_hash: &str) {
    let peer = state.chat.peers.get(peer_hash).copied().unwrap_or_default();
    let contact_id = state
        .vault
        .as_ref()
        .and_then(|vault| vault.find_contact_by_peer_hash(peer_hash))
        .map(|contact| contact.id.clone());
    emit(
        state,
        "chat_peer_state",
        json!({
            "peer_hash": peer_hash,
            "contact_id": contact_id,
            "online": peer.online,
            "connected": peer.connected,
            "verified": peer.verified,
            "away": peer.away,
        }),
    );
}

// ---------------------------------------------------------------------------
// IPC handlers (dispatched from ipc.rs; same `Result<Value, &'static str>`
// convention, short stable codes)
// ---------------------------------------------------------------------------

/// `chat_go_online` — the ONLY announcement path. Starts the transport: every
/// identity's fingerprint is announced over mDNS, and — only if the user
/// configured a relay — exactly the chosen identity is registered with it.
pub fn ipc_go_online(state: &mut AppState) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    go_online(state)?;
    emit(
        state,
        "chat_presence",
        json!({ "online": true, "away": state.chat.away }),
    );
    emit(state, "chat_relay_state", relay_json(state));
    Ok(status_json(state))
}

/// `chat_go_offline` — withdraws every announcement (mDNS goodbyes), drops
/// any relay registration, joins the transport threads. Contacts see the
/// user as not present; a send to them is refused, never queued — and ours
/// to them too.
pub fn ipc_go_offline(state: &mut AppState) -> Result<Value, &'static str> {
    teardown_transport(state);
    emit(state, "chat_presence", json!({ "online": false, "away": false }));
    emit(state, "chat_relay_state", relay_json(state));
    Ok(status_json(state))
}

/// `chat_set_away` — the AFK flag: the one presence state that CANNOT be
/// inferred (offline is mere absence), so it is announced in-band as a
/// `Status` envelope to every live session, and pushed onto each new session
/// (see SessionEstablished). It is a courtesy signal, never a delivery
/// state: messages to an AFK user arrive normally. Requires being online —
/// away is a state you are in WHILE announcing, so an offline user gets the
/// actionable `offline` refusal rather than a flag that reaches nobody.
pub fn ipc_set_away(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    if !state.chat.online || state.chat.transport.is_none() {
        return Err("offline");
    }
    let away = args.get("away").and_then(Value::as_bool).ok_or("bad_args")?;
    state.chat.away = away;
    // Broadcast to live sessions only; everyone else has no session through
    // which they could see us anyway, and picks the flag up at session start.
    let targets: Vec<String> = state
        .chat
        .peers
        .iter()
        .filter(|(_, peer)| peer.connected)
        .map(|(hash, _)| hash.clone())
        .collect();
    for hash in targets {
        // Best effort per peer: a dying session simply misses the marker and
        // keeps the safe default (present, not away).
        let _ = send_payload(state, &hash, &ChatPayload::Status { away });
    }
    emit(state, "chat_presence", json!({ "online": true, "away": away }));
    Ok(status_json(state))
}

/// `chat_status` — everything the panel needs to render presence and relay
/// state honestly, including when the vault is locked.
pub fn ipc_status(state: &mut AppState) -> Result<Value, &'static str> {
    Ok(status_json(state))
}

/// `chat_relay_get` — saved settings, current live state, and the identities
/// eligible for registration (long-term + one per contact, labeled so the
/// user can recognize them; the throwaway key is never offered).
pub fn ipc_relay_get(state: &mut AppState) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let mut data = relay_json(state);
    let mut choices = Vec::new();
    if let Some(vault) = state.vault.as_ref() {
        if let Some(secret) = vault.chat_identity() {
            choices.push(json!({
                "hash": hash_of_secret(secret),
                "label": "Long-term identity",
            }));
        }
        for contact in vault.list_contacts() {
            choices.push(json!({
                "hash": hash_of_secret(contact.our_secret),
                "label": format!("For contact: {}", contact.label),
                "contact_id": contact.id,
            }));
        }
    }
    data["identity_choices"] = Value::Array(choices);
    Ok(data)
}

/// `chat_relay_set` — validate, persist to the vault, apply. Applying while
/// online restarts the transport so the RUNNING state always equals the
/// SAVED state (the UI warns that saving briefly reconnects). Never silently
/// defers: what the settings say is what the network sees.
pub fn ipc_relay_set(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let held = held_identity_hashes(state);
    let draft = parse_relay_settings(args, RELAY_COMPILED, |h| held.iter().any(|x| x == h))?;
    {
        let vault = state.vault.as_mut().ok_or("not_unlocked")?;
        vault.set_chat_relay_settings(draft).map_err(vault_code)?;
    }
    if state.chat.online {
        teardown_transport(state);
        emit(state, "chat_presence", json!({ "online": false, "away": false }));
        go_online(state)?;
        emit(state, "chat_presence", json!({ "online": true, "away": false }));
    }
    emit(state, "chat_relay_state", relay_json(state));
    ipc_relay_get(state)
}

/// `chat_identity` — our hash number for a given contact, or (no contact
/// given) the long-term identity's, or null when none has been minted yet.
///
/// READ-ONLY, and that is the whole point. This used to mint on first use,
/// which made a read-shaped command a mutation: the only way to ask "do I
/// have an identity?" was to call this, and calling it made the answer yes.
/// The UI could therefore never ask, so it guessed from an empty contact
/// list instead and told users with a perfectly good identity to create one
/// (`chat.js`, the intro pane). Minting now lives in `chat_identity_create`,
/// so asking is free and the caller says when it wants a key generated.
pub fn ipc_identity(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if let Some(contact_id) = args.get("contact_id").and_then(Value::as_str) {
        let vault = state.vault.as_ref().ok_or("not_unlocked")?;
        let contact = vault.get_contact(contact_id).ok_or("not_found")?;
        let hash = identity_from_secret(contact.our_secret)
            .fingerprint()
            .to_hash_number();
        return Ok(json!({ "hash": hash, "contact_id": contact_id }));
    }
    let vault = state.vault.as_ref().ok_or("not_unlocked")?;
    // `null` is a real answer, not a failure: "no identity yet" is the state
    // a first-run user is legitimately in, and the UI needs to tell it apart
    // from a locked vault (which is the `not_unlocked` error above).
    let hash = vault
        .chat_identity()
        .map(|secret| identity_from_secret(secret).fingerprint().to_hash_number());
    Ok(json!({ "hash": hash, "minted": false }))
}

/// `chat_identity_create` — mint the long-term identity, or return the
/// existing one untouched.
///
/// Idempotent on purpose: a user who clicks the button twice, or who had an
/// identity already and reached this path anyway, must not get a second key.
/// Replacing a live identity would silently orphan every contact who knows
/// the old hash number. Minting is a purely local key generation; it
/// announces NOTHING.
pub fn ipc_identity_create(state: &mut AppState) -> Result<Value, &'static str> {
    let (secret, minted) = {
        let vault = state.vault.as_mut().ok_or("not_unlocked")?;
        match vault.chat_identity() {
            Some(secret) => (secret, false),
            None => {
                let secret = fresh_secret();
                vault.set_chat_identity(secret).map_err(vault_code)?;
                (secret, true)
            }
        }
    };
    let hash = identity_from_secret(secret).fingerprint().to_hash_number();
    if minted {
        // Only if the user is ALREADY online does the running transport adopt
        // the new identity (announced immediately, because they chose to be
        // online). Offline, it is simply picked up by the next "Go online".
        if let Some(transport) = state.chat.transport.as_ref() {
            let _ = transport.add_identity(identity_from_secret(secret));
        }
    }
    Ok(json!({ "hash": hash, "minted": minted }))
}

/// `chat_contact_note` — the user's own note about a contact.
///
/// A hash number is unmemorable by design, so this is where "the one from the
/// conference, blue laptop" lives. Stored in the vault beside the contact's
/// key, so it is encrypted at rest and unreadable while locked. An empty
/// string clears it.
pub fn ipc_contact_note(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    let contact_id = args
        .get("contact_id")
        .and_then(Value::as_str)
        .ok_or("bad_args")?;
    let note = args.get("note").and_then(Value::as_str).unwrap_or("");
    let vault = state.vault.as_mut().ok_or("not_unlocked")?;
    vault.set_contact_note(contact_id, note).map_err(vault_code)?;
    Ok(json!({}))
}

pub fn ipc_contacts(state: &mut AppState) -> Result<Value, &'static str> {
    let vault = state.vault.as_ref().ok_or("not_unlocked")?;
    let items: Vec<Value> = vault
        .list_contacts()
        .iter()
        .map(|contact| {
            // our_secret is deliberately NOT serialized: key material never
            // crosses into the chrome webview. The note IS serialized: it is
            // the user's own words about the contact, and showing those words
            // back is the whole point of the feature — without it the panel
            // would claim "no note" for every contact forever.
            json!({
                "id": contact.id,
                "label": contact.label,
                "peer_hash": contact.peer_hash,
                "note": contact.note,
            })
        })
        .collect();
    Ok(json!({ "items": items }))
}

/// `chat_contact_add` — a contact is a label plus the peer's hash number;
/// adding one mints OUR per-contact keypair (brief §3). Adding a contact
/// announces nothing by itself: offline stays offline.
pub fn ipc_contact_add(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    let label = parse_label(args)?;
    let peer_hash = parse_peer_hash(args)?;
    let vault = state.vault.as_mut().ok_or("not_unlocked")?;
    // Fresh keypair for THIS contact only: the hash number the user reads to
    // this person is the fingerprint of this key and of no other contact's.
    let identity = Identity::generate();
    let id = vault
        .add_contact(&label, &peer_hash, identity.secret_bytes())
        .map_err(vault_code)?;
    let our_hash = identity.fingerprint().to_hash_number();
    if let Some(transport) = state.chat.transport.as_ref() {
        // Already online: the new contact becomes reachable immediately,
        // without restarting the transport or disturbing other conversations.
        let _ = transport.add_identity(identity);
    }
    // Returning our hash lets the UI show "give them this number" immediately.
    Ok(json!({ "id": id, "hash": our_hash }))
}

/// `chat_contact_remove` — deleting one keypair; every other contact's
/// address is untouched (proved in tests).
pub fn ipc_contact_remove(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    let contact_id = args
        .get("contact_id")
        .and_then(Value::as_str)
        .ok_or("bad_args")?;
    let (peer_hash, our_fp) = {
        let vault = state.vault.as_ref().ok_or("not_unlocked")?;
        let contact = vault.get_contact(contact_id).ok_or("not_found")?;
        (
            contact.peer_hash.clone(),
            identity_from_secret(contact.our_secret).fingerprint(),
        )
    };
    let vault = state.vault.as_mut().ok_or("not_unlocked")?;
    vault.delete_contact(contact_id).map_err(vault_code)?;
    if let Some(transport) = state.chat.transport.as_ref() {
        // Revocation: the fingerprint stops being announced and every session
        // built on this key is torn down. Other identities are untouched. If
        // this was the identity registered with the relay, the transport
        // tears that registration down too.
        let _ = transport.remove_identity(our_fp);
    }
    // If the revoked identity was the one chosen for the relay, clear the
    // saved choice: leaving it would let the next "Go online" resurrect a
    // registration the user just revoked. The relay settings then read
    // "not_configured" — honest, and visible.
    let settings = relay_settings(state);
    if settings.identity_hash == Some(our_fp.to_hash_number()) {
        let updated = RelaySettings {
            identity_hash: None,
            ..settings
        };
        let vault = state.vault.as_mut().ok_or("not_unlocked")?;
        vault.set_chat_relay_settings(updated).map_err(vault_code)?;
        emit(state, "chat_relay_state", relay_json(state));
    }
    state.chat.peers.remove(&peer_hash);
    emit(
        state,
        "chat_peer_state",
        json!({
            "peer_hash": peer_hash,
            "contact_id": contact_id,
            "online": false,
            "connected": false,
            "verified": false,
            "away": false,
        }),
    );
    Ok(json!({}))
}

/// `chat_peers` — who is visible on the LAN right now, plus an explicit
/// discovery state so the UI can say "this network may block local
/// discovery" instead of showing a misleading empty list (brief §7).
pub fn ipc_peers(state: &mut AppState) -> Result<Value, &'static str> {
    let vault = state.vault.as_ref().ok_or("not_unlocked")?;
    let peers: Vec<Value> = state
        .chat
        .peers
        .iter()
        .map(|(hash, peer)| {
            let contact_id = vault
                .find_contact_by_peer_hash(hash)
                .map(|contact| contact.id.clone());
            json!({
                "hash": hash,
                "contact_id": contact_id,
                "connected": peer.connected,
                "away": peer.away,
            })
        })
        .collect();
    Ok(json!({ "discovery": state.chat.discovery, "peers": peers }))
}

/// `chat_open` — start a session. With `contact_id` we present that
/// contact's per-contact key; with a bare `peer_hash` it is an ephemeral
/// chat on the throwaway key. Requires being online: opening a session
/// announces and connects, so an offline user gets the distinguishable
/// `offline` refusal, never a silent announcement.
pub fn ipc_open(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    if !state.chat.online {
        return Err("offline");
    }
    let peer_hash = resolve_peer_hash(state, args)?;
    let our = our_identity_for(state, args)?;
    let transport = state.chat.transport.as_ref().ok_or("chat_down")?;
    let peer = Fingerprint::parse_hash_number(&peer_hash).ok_or("bad_args")?;
    // Session establishment is asynchronous: an immediate error only means
    // the transport itself is gone. The outcome arrives as `chat_peer_state`
    // (connected) or `chat_notice` (session_failed / peer_offline). The
    // transport fails closed if we name an identity it does not hold.
    transport
        .open_session(our.fingerprint(), peer)
        .map_err(|_| "chat_down")?;
    Ok(json!({}))
}

pub fn ipc_close(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let peer_hash = resolve_peer_hash(state, args)?;
    if let (Some(transport), Some(peer)) = (
        state.chat.transport.as_ref(),
        Fingerprint::parse_hash_number(&peer_hash),
    ) {
        // Closing destroys the session keys; a later send requires a fresh
        // `chat_open`.
        let _ = transport.close_session(peer);
    }
    if let Some(entry) = state.chat.peers.get_mut(&peer_hash) {
        entry.connected = false;
    }
    emit_peer_state(state, &peer_hash);
    Ok(json!({}))
}

/// `chat_send` — text only. An offline peer produces the distinguishable
/// `peer_offline` refusal; nothing is queued, ever (brief §3).
pub fn ipc_send(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let text = args.get("text").and_then(Value::as_str).ok_or("bad_args")?;
    if text.is_empty() {
        return Err("bad_args");
    }
    let peer_hash = resolve_peer_hash(state, args)?;
    let wire = encode_payload(&ChatPayload::Text { text: text.to_string() })
        .map_err(chat_code)?;
    send_wire(state, peer_hash, &wire)
}

/// `chat_send_tab` — send the current tab's URL to one contact (the user's
/// own other device is just their own contact; brief §5). Same session
/// machinery, no second transport.
pub fn ipc_send_tab(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let peer_hash = resolve_peer_hash(state, args)?;
    let url = state.active_url();
    // We never offer a peer something we would refuse to open ourselves.
    if !is_allowed_content_url(&url) {
        return Err("bad_args");
    }
    let wire = encode_payload(&ChatPayload::Tab { url }).map_err(chat_code)?;
    send_wire(state, peer_hash, &wire)
}

/// `chat_share_credential` — one explicitly chosen entry, one contact, sealed
/// like any other message (brief §6). There is deliberately no bulk path.
pub fn ipc_share_credential(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    if state.vault.is_none() {
        return Err("not_unlocked");
    }
    let cred_id = args
        .get("cred_id")
        .and_then(Value::as_str)
        .ok_or("bad_args")?;
    let peer_hash = resolve_peer_hash(state, args)?;
    let vault = state.vault.as_ref().ok_or("not_unlocked")?;
    let entry = vault.get_credential(cred_id).ok_or("not_found")?;
    let wire = encode_payload(&ChatPayload::Credential {
        site: entry.site.clone(),
        username: entry.username.clone(),
        password: entry.password.clone(),
        note: entry.note.clone(),
    })
    .map_err(chat_code)?;
    send_wire(state, peer_hash, &wire)
}

/// `chat_accept_tab` — the user confirmed a received link. Re-validated here
/// because the chrome side merely relays the click; and it ALWAYS opens in a
/// background tab so a peer can never take over the foreground (brief §5).
pub fn ipc_accept_tab(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    let url = args.get("url").and_then(Value::as_str).ok_or("bad_args")?;
    validate_incoming_tab_url(url)?;
    if state.tabs.len() >= crate::state::MAX_TABS {
        return Err("bad_args");
    }
    // The second parameter is `switch`, not "foreground": `false` means the
    // tab is created but not selected, which is what accepting a peer's tab
    // should do -- a contact must not be able to yank the user's view onto a
    // page they have not looked at yet. (Was a Note inferring this from
    // `tab_new`; confirmed against `AppState::new_tab`.)
    let id = state.new_tab(url, false)?;
    Ok(json!({ "id": id }))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Shared send path for structured envelopes (page corroboration uses it;
/// the IPC handlers keep their own call sites so their errors stay
/// synchronous). Same rules as `send_wire`: text only, capped, never queued.
pub(crate) fn send_payload(
    state: &AppState,
    peer_hash: &str,
    payload: &ChatPayload,
) -> Result<(), &'static str> {
    let wire = encode_payload(payload).map_err(chat_code)?;
    send_wire(state, peer_hash.to_string(), &wire)?;
    Ok(())
}

/// Best-effort push of our own AFK flag to one peer over its session. This
/// is courtesy metadata, not delivery state: if it cannot go out the peer
/// simply keeps the safe default (present, not away). Note: assumes
/// `Fingerprint` is `Copy` (evidence: existing code uses a fingerprint after
/// passing it by value, e.g. `remove_identity(our_fp)` then
/// `our_fp.to_hash_number()`); if it is only `Clone`, add `.clone()` here.
fn send_status_to(state: &AppState, peer: Fingerprint) {
    let Some(transport) = state.chat.transport.as_ref() else {
        return;
    };
    if let Ok(wire) = encode_payload(&ChatPayload::Status {
        away: state.chat.away,
    }) {
        let _ = transport.send_text(peer, &wire);
    }
}

fn send_wire(state: &AppState, peer_hash: String, wire: &str) -> Result<Value, &'static str> {
    let peer = Fingerprint::parse_hash_number(&peer_hash).ok_or("bad_args")?;
    // No running transport: if the user never went online, say THAT — it is
    // the actionable truth ("go online to send"), distinguishable from the
    // peer being away. `chat_down` covers "chose online but the machinery
    // failed".
    let transport = match state.chat.transport.as_ref() {
        Some(transport) => transport,
        None => {
            return Err(if state.chat.online {
                "chat_down"
            } else {
                "offline"
            })
        }
    };
    // A cheap synchronous refusal for the common case of sending with no
    // session or no route, so the user is not left watching a bubble that was
    // never going anywhere.
    //
    // `reachable`, not `connected`: the two used to be one flag that link
    // death never cleared, so this check passed and the message went out on a
    // route that no longer existed. Note this is still only a PRE-check —
    // it can be stale by a millisecond, which is exactly why success below
    // means "accepted", never "delivered".
    match state.chat.peers.get(&peer_hash) {
        Some(peer_state) if peer_state.connected && peer_state.reachable => {}
        Some(peer_state) if peer_state.connected => return Err("link_lost"),
        _ => return Err("peer_offline"),
    }
    let mid = transport.send_text(peer, wire).map_err(|error| match error {
        ChatError::Closed => "chat_down",
        other => chat_code(other),
    })?;
    // The id, NOT a verdict. Everything the caller may claim about this
    // message from here on arrives as a `chat_delivery` event keyed by it.
    Ok(json!({ "mid": hex_mid(&mid) }))
}

/// Resolve the peer from either `contact_id` (contact path) or `peer_hash`
/// (ephemeral path). One-to-one only: there is no multi-recipient argument
/// by design (brief §0.4).
pub(crate) fn resolve_peer_hash(state: &AppState, args: &Value) -> Result<String, &'static str> {
    if let Some(contact_id) = args.get("contact_id").and_then(Value::as_str) {
        let vault = state.vault.as_ref().ok_or("not_unlocked")?;
        return Ok(vault
            .get_contact(contact_id)
            .ok_or("not_found")?
            .peer_hash
            .clone());
    }
    parse_peer_hash(args)
}

/// Which of OUR identities to present when opening a session: the contact's
/// per-contact key, or the throwaway ephemeral key for contactless peers.
/// The transport never guesses this — presenting the wrong key would show
/// the peer an address they were never given.
fn our_identity_for(state: &mut AppState, args: &Value) -> Result<Identity, &'static str> {
    if let Some(contact_id) = args.get("contact_id").and_then(Value::as_str) {
        let vault = state.vault.as_ref().ok_or("not_unlocked")?;
        let contact = vault.get_contact(contact_id).ok_or("not_found")?;
        return Ok(identity_from_secret(contact.our_secret));
    }
    parse_peer_hash(args)?; // ephemeral chats still require an explicit peer
    let secret = *state.chat.ephemeral_secret.get_or_insert_with(fresh_secret);
    // If the transport is already running (started for contacts) and has not
    // seen the throwaway key yet, adopt it now.
    if !state.chat.ephemeral_in_transport {
        if let Some(transport) = state.chat.transport.as_ref() {
            let _ = transport.add_identity(identity_from_secret(secret));
        }
        state.chat.ephemeral_in_transport = true;
    }
    Ok(identity_from_secret(secret))
}

fn parse_label(args: &Value) -> Result<String, &'static str> {
    let label = args
        .get("label")
        .and_then(Value::as_str)
        .ok_or("bad_args")?
        .trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        return Err("bad_args");
    }
    Ok(label.to_string())
}

/// Validates the typed/pasted hash number and returns its canonical form, so
/// what is stored in the vault always compares equal to what events carry.
fn parse_peer_hash(args: &Value) -> Result<String, &'static str> {
    let raw = args
        .get("peer_hash")
        .and_then(Value::as_str)
        .ok_or("bad_args")?;
    let fingerprint = Fingerprint::parse_hash_number(raw).ok_or("bad_args")?;
    Ok(fingerprint.to_hash_number())
}

// ---------------------------------------------------------------------------
// tests — property proofs, not API demos
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // Only the property tests need the wire cap.
    use patanyx_chat::MAX_MESSAGE_BYTES;
    // Note: assumed export path (vault `chat` feature, see contacts.rs).
    use patanyx_vault::ContactBook;

    /// A peer must never navigate us outside the content allowlist (§5).
    #[test]
    fn incoming_tab_urls_follow_the_content_allowlist() {
        assert!(validate_incoming_tab_url("https://example.com").is_ok());
        assert!(validate_incoming_tab_url("http://example.com/path").is_ok());
        assert!(validate_incoming_tab_url("about:blank").is_ok());
        assert!(validate_incoming_tab_url("file:///etc/passwd").is_err());
        assert!(validate_incoming_tab_url("data:text/html,<script>").is_err());
        assert!(validate_incoming_tab_url("rbchrome://localhost/index.html").is_err());
        // The chrome origin explicitly, including on Windows where it is http.
        assert!(validate_incoming_tab_url(crate::platform::CHROME_URL).is_err());
        assert!(validate_incoming_tab_url(crate::platform::CHROME_ORIGIN_PREFIX).is_err());
    }

    #[test]
    fn envelopes_round_trip_as_text() {
        let payloads = vec![
            ChatPayload::Text { text: "hello 👋🏻".into() },
            ChatPayload::Tab { url: "https://example.com".into() },
            ChatPayload::Credential {
                site: "example.com".into(),
                username: "u".into(),
                password: "p".into(),
                note: "n".into(),
            },
        ];
        for payload in payloads {
            let wire = encode_payload(&payload).unwrap();
            // Envelopes stay under the protocol's text cap.
            assert!(wire.len() <= MAX_MESSAGE_BYTES);
            assert_eq!(decode_payload(&wire), payload);
        }
    }

    /// The AFK marker is a text envelope like everything else: it
    /// round-trips losslessly and stays microscopic next to the wire cap.
    /// Both directions matter — "away" asserted AND "back" retracted —
    /// because a stuck orange dot is exactly the failure this protocol
    /// exists to avoid.
    #[test]
    fn status_envelope_round_trips_as_text() {
        let wire = encode_payload(&ChatPayload::Status { away: true }).unwrap();
        assert!(wire.len() <= MAX_MESSAGE_BYTES);
        assert_eq!(decode_payload(&wire), ChatPayload::Status { away: true });
        let wire = encode_payload(&ChatPayload::Status { away: false }).unwrap();
        assert_eq!(decode_payload(&wire), ChatPayload::Status { away: false });
    }

    /// Unknown or malformed structure degrades to display-only text; it can
    /// never trigger behaviour.
    #[test]
    fn non_envelope_text_degrades_to_plain_text() {
        match decode_payload("just a message") {
            ChatPayload::Text { text } => assert_eq!(text, "just a message"),
            other => panic!("expected text fallback, got {other:?}"),
        }
        match decode_payload("{\"kind\":\"binary\",\"data\":\"AAAA\"}") {
            ChatPayload::Text { .. } => {}
            other => panic!("unknown kind must fall back to text, got {other:?}"),
        }
    }

    /// Oversized payloads are refused, never truncated — the sender must see
    /// exactly what the recipient reads.
    #[test]
    fn oversized_payload_is_refused_not_truncated() {
        let payload = ChatPayload::Credential {
            site: "s".into(),
            username: "u".into(),
            password: "p".repeat(MAX_MESSAGE_BYTES),
            note: String::new(),
        };
        assert!(matches!(encode_payload(&payload), Err(ChatError::TooLong)));
    }

    /// Offline delivery is a DISTINCT, user-legible refusal — the designed
    /// behaviour, not a generic failure, and never a queue (§3, §6 of the
    /// acceptance criteria).
    #[test]
    fn offline_send_is_a_distinct_refusal() {
        assert_eq!(send_failure_code(&SendFailure::Offline), "peer_offline");
        assert_ne!(send_failure_code(&SendFailure::Offline), "io");
        assert_ne!(send_failure_code(&SendFailure::Offline), "bad_args");
        // "No session yet" is distinguishable from "peer went offline", so
        // the UI can say "open the conversation first" vs "they are away".
        assert_eq!(send_failure_code(&SendFailure::NoSession), "no_session");
        assert_ne!(send_failure_code(&SendFailure::NoSession), "peer_offline");
    }

    /// Revoking one contact deletes one keypair and must not disturb any
    /// other contact's address (§2).
    #[test]
    fn removing_a_contact_preserves_other_contact_addresses() {
        let mut book = ContactBook::default();
        let alice_key = Identity::generate();
        let bob_key = Identity::generate();
        let alice_peer = Identity::generate().fingerprint().to_hash_number();
        let bob_peer = Identity::generate().fingerprint().to_hash_number();
        book.add("id-a".into(), "alice".into(), alice_peer, alice_key.secret_bytes());
        book.add("id-b".into(), "bob".into(), bob_peer, bob_key.secret_bytes());

        let address_before =
            identity_from_secret(book.get("id-a").unwrap().our_secret)
                .fingerprint()
                .to_hash_number();
        assert!(book.remove("id-b").is_some());
        let address_after = identity_from_secret(book.get("id-a").unwrap().our_secret)
            .fingerprint()
            .to_hash_number();
        assert_eq!(address_before, address_after, "alice's address must not move");

        // Contacts never share key material, so addresses cannot correlate.
        assert_ne!(alice_key.secret_bytes(), bob_key.secret_bytes());
        // And the two per-contact addresses are genuinely different.
        let bob_address = identity_from_secret(bob_key.secret_bytes())
            .fingerprint()
            .to_hash_number();
        assert_ne!(address_before, bob_address);
    }

    /// IPC argument parsing: bad labels and bad hash numbers are `bad_args`,
    /// valid input canonicalizes (§9).
    #[test]
    fn ipc_argument_parsing_rejects_bad_input() {
        let hash = Identity::generate().fingerprint().to_hash_number();
        assert_eq!(
            parse_peer_hash(&json!({ "peer_hash": hash.clone() })).unwrap(),
            hash
        );
        assert!(parse_peer_hash(&json!({ "peer_hash": "not a hash number" })).is_err());
        assert!(parse_peer_hash(&json!({})).is_err());

        assert_eq!(parse_label(&json!({ "label": " mum " })).unwrap(), "mum");
        assert!(parse_label(&json!({ "label": "   " })).is_err());
        assert!(parse_label(&json!({ "label": "x".repeat(MAX_LABEL_CHARS + 1) })).is_err());
        assert!(parse_label(&json!({})).is_err());
    }

    fn relay_args(enabled: bool, url: Option<&str>, hash: Option<&str>) -> Value {
        json!({ "enabled": enabled, "url": url, "identity_hash": hash })
    }

    /// Relay settings validation: enabling requires a compiled client, a
    /// TLS URL, and an identity WE hold; junk is rejected even when disabled
    /// so nothing invalid ever persists; and the chosen identity is stored
    /// verbatim — never substituted.
    #[test]
    fn relay_settings_validation() {
        let held_hash = Identity::generate().fingerprint().to_hash_number();
        let holds = |h: &str| h == held_hash;

        // Disabled with nothing set is the default and always fine.
        let saved = parse_relay_settings(&relay_args(false, None, None), true, &holds).unwrap();
        assert!(!saved.enabled && saved.url.is_none() && saved.identity_hash.is_none());

        // Junk URLs are refused even while disabled, and refused with a code
        // that NAMES the requirement. `bad_args` renders as "Invalid input",
        // which is what an operator got for typing a perfectly well-formed
        // http:// address and left them nothing to act on.
        assert_eq!(
            parse_relay_settings(
                &relay_args(false, Some("http://relay.example/ws"), None),
                true,
                &holds
            ),
            Err("bad_relay_url")
        );
        assert_eq!(
            parse_relay_settings(&relay_args(false, Some("ws://relay.example/ws"), None), true, &holds),
            Err("bad_relay_url")
        );
        assert_eq!(
            parse_relay_settings(&relay_args(false, Some("wss:///ws"), None), true, &holds),
            Err("bad_relay_url")
        );

        // Enabling without a compiled relay client is refused, honestly.
        assert_eq!(
            parse_relay_settings(
                &relay_args(true, Some("wss://relay.example/ws"), Some(&held_hash)),
                false,
                &holds
            ),
            Err("relay_unavailable")
        );

        // Enabling needs both a server and an identity.
        assert_eq!(
            parse_relay_settings(&relay_args(true, None, Some(&held_hash)), true, &holds),
            Err("bad_args")
        );
        assert_eq!(
            parse_relay_settings(
                &relay_args(true, Some("wss://relay.example/ws"), None),
                true,
                &holds
            ),
            Err("bad_args")
        );

        // An identity we do not hold (a contact's hash, a removed contact's
        // key) can never be registered.
        let stranger = Identity::generate().fingerprint().to_hash_number();
        assert_eq!(
            parse_relay_settings(
                &relay_args(true, Some("wss://relay.example/ws"), Some(&stranger)),
                true,
                &holds
            ),
            Err("bad_args")
        );

        // The happy path keeps exactly the user's choices.
        let saved = parse_relay_settings(
            &relay_args(true, Some("wss://relay.example/ws"), Some(&held_hash)),
            true,
            &holds,
        )
        .unwrap();
        assert!(saved.enabled);
        assert_eq!(saved.url.as_deref(), Some("wss://relay.example/ws"));
        assert_eq!(saved.identity_hash.as_deref(), Some(held_hash.as_str()));

        // Plain `ws://` is never accepted: the relay client speaks TLS only.
        assert_eq!(
            parse_relay_settings(
                &relay_args(true, Some("ws://relay.example/ws"), Some(&held_hash)),
                true,
                &holds
            ),
            Err("bad_relay_url")
        );
    }
}
