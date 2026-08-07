//! Synchronous WebSocket client to the relay: one connection per browser
//! instance, on its own thread, no async runtime.
//!
//! Reconnect is NORMAL OPERATION here, not an error path: a relay restart
//! drops every connection by nature. Connect failures and dropped connections
//! retry with exponential backoff and jitter, forever, until shutdown.
//!
//! Note (tungstenite 0.30 API, verify at compile time):
//!   * `tungstenite::client::client_with_config(request, stream, Option<WebSocketConfig>)`
//!     is assumed to exist (older/newer names: `client`, `client_tls_with_config`).
//!   * `WebSocket::{read, send, flush}` — older releases call these
//!     `read_message` / `write_message` (+`write_pending`).
//!   * `Message::Text` is assumed to hold `Utf8Bytes`; the code only uses
//!     `.into()` and `.as_bytes()`, which compile against `String` too.
//!
//! Note (root certificates): this uses webpki-roots (Mozilla's store,
//! compiled in, cross-platform). Users behind TLS-intercepting corporate
//! proxies will fail to connect; if that matters, switch to
//! rustls-native-certs (OS trust store) — one-line dependency change, see
//! `tls_config`.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rand_core::RngCore;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

use crate::wire::{self, ErrorCode, Frame, FrameKind};
use crate::{ChatError, Identity};

/// BOUNDED BY DESIGN: every channel in the transport is small, and overflow
/// CLOSES the connection rather than growing a buffer. Never "fix" dropped
/// frames with a bigger queue — buffering is where "nothing is stored" stops
/// being true in code.
const OUTBOUND_QUEUE: usize = 32;

/// Outbound frames drained per poll iteration, so a loud relay cannot starve
/// our own sends.
const OUTBOUND_DRAIN_PER_TICK: usize = 16;

/// How long the blocking read waits before servicing flags and queues. This is
/// the worst-case added latency for an outbound frame on an idle connection.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Caps on connect, TLS/WebSocket handshake, and registration.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

pub enum RelayEvent {
    Up,
    Down,
    Frame(Frame),
    /// Frames that were still queued when the connection died, and were
    /// dropped rather than carried across the reconnect. The count, not the
    /// frames: the core knows what it had in flight and fails those itself.
    Dropped { count: usize },
    /// Registration was REFUSED with a Premium licence code (P3, design
    /// 4.4). Without this, the refusal died inside the connection thread
    /// (`Err(_) => CycleEnd::Lost`) and the UI could never say WHY chat is
    /// down — the copy for these codes would be dead. The client keeps its
    /// ordinary backoff-and-retry after emitting it: the relay's flag, or
    /// the user's token, can change without a restart, and the backoff cap
    /// keeps the retry traffic bounded.
    Refused(ErrorCode),
}

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Owns the connection thread. Dropping outbound senders or setting the flag
/// ends it; `shutdown` joins it.
pub struct RelayClient {
    outbound: SyncSender<Frame>,
    shutdown: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RelayClient {
    /// `token` is the 90 licence-token wire bytes (P3, design 4.1), opaque
    /// to this layer: hex-encoded into the Register frame on every
    /// (re)registration when present, never inspected here.
    pub fn spawn(
        url: String,
        identity: Arc<Identity>,
        token: Option<Vec<u8>>,
        events: SyncSender<RelayEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let (outbound, inbound) = mpsc::sync_channel::<Frame>(OUTBOUND_QUEUE);
        let reset = Arc::new(AtomicBool::new(false));
        let thread = {
            let shutdown = shutdown.clone();
            let reset = reset.clone();
            thread::spawn(move || run(url, identity, token, inbound, events, shutdown, reset))
        };
        Self {
            outbound,
            shutdown,
            reset,
            thread: Some(thread),
        }
    }

    /// Queues one frame for the relay. A full queue means the connection is
    /// wedged: the connection is reset (dropped and re-established) and the
    /// frame is refused, per the bounded-channels rule.
    pub fn send(&self, frame: Frame) -> Result<(), ChatError> {
        match self.outbound.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                self.reset.store(true, Ordering::SeqCst);
                Err(ChatError::Closed)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => Err(ChatError::Closed),
        }
    }

    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            // Can block up to CONNECT_TIMEOUT if a connect is in flight.
            let _ = handle.join();
        }
    }
}

enum CycleEnd {
    Shutdown,
    Lost { fast_retry: bool },
}

fn run(
    url: String,
    identity: Arc<Identity>,
    token: Option<Vec<u8>>,
    outbound: Receiver<Frame>,
    events: SyncSender<RelayEvent>,
    shutdown: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
) {
    let mut attempt: u32 = 0;
    let mut up = false;
    while !shutdown.load(Ordering::SeqCst) {
        let end = match connect_and_register(&url, &identity, token.as_deref()) {
            Ok(ws) => {
                up = events.try_send(RelayEvent::Up).is_ok();
                if !up {
                    CycleEnd::Lost { fast_retry: false }
                } else {
                    reset.store(false, Ordering::SeqCst);
                    run_poll(ws, &outbound, &events, &shutdown, &reset)
                }
            }
            // A Premium licence refusal (P3) is surfaced BEFORE the retry
            // machinery takes over — every other connect failure stays an
            // anonymous Lost, exactly as before.
            Err(e) => {
                if let Some(code) = licence_refusal_code(&e) {
                    let _ = events.try_send(RelayEvent::Refused(code));
                }
                CycleEnd::Lost { fast_retry: false }
            }
        };
        match end {
            CycleEnd::Shutdown => break,
            CycleEnd::Lost { fast_retry } => {
                // Anything still queued when the connection died is DROPPED,
                // not carried across the reconnect.
                //
                // This channel is not drained by the cycle that ends, so
                // without this the frames sat here and went out on the next
                // successful cycle -- after a backoff of up to thirty
                // seconds, a fresh TCP connection and a re-registration. That
                // is store-and-forward in everything but name, and this
                // project's hardest constraint is that a message to an
                // unreachable peer is refused, never held. The sender is told
                // instead, and decides for itself whether to send again.
                let dropped = outbound.try_iter().count();
                if dropped > 0 {
                    let _ = events.try_send(RelayEvent::Dropped { count: dropped });
                }
                if up {
                    let _ = events.try_send(RelayEvent::Down);
                    up = false;
                }
                if fast_retry {
                    attempt = 0;
                } else {
                    sleep_interruptible(backoff(attempt), &shutdown);
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
    if up {
        let _ = events.try_send(RelayEvent::Down);
    }
}

/// Connects, does the TLS and WebSocket handshakes, and registers with proof
/// of possession. After this returns, the connection is routed by the relay.
fn connect_and_register(
    url: &str,
    identity: &Identity,
    token: Option<&[u8]>,
) -> Result<WebSocket<TlsStream>, ChatError> {
    let (host, port, _path) = parse_wss_url(url)?;

    let connect_target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut tcp = None;
    let mut last_err = None;
    for addr in connect_target.to_socket_addrs().map_err(ChatError::from)? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| last_err.map(ChatError::from).unwrap_or(ChatError::Closed))?;
    let _ = tcp.set_nodelay(true); // chat frames are small; latency beats coalescing
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(ChatError::from)?;
    tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(ChatError::from)?;

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| ChatError::InvalidUrl)?;
    let conn = ClientConnection::new(Arc::new(tls_config()), server_name)
        .map_err(|_| ChatError::InvalidUrl)?;
    let tls = StreamOwned::new(conn, tcp);

    let (mut ws, _response) = tungstenite::client::client_with_config(url, tls, Some(ws_config()))
        .map_err(|e| ChatError::Io(e.to_string()))?;

    register(&mut ws, identity, token)?;

    // Switch the socket to the poll cadence for the steady state. Timeouts on
    // a read are safe here: tungstenite buffers partial frames internally, so
    // a WouldBlock mid-frame loses nothing (tokio-tungstenite's entire model
    // relies on this same property).
    ws.get_mut()
        .sock
        .set_read_timeout(Some(POLL_INTERVAL))
        .map_err(ChatError::from)?;
    Ok(ws)
}

fn tls_config() -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Note: with only the `ring` provider feature enabled, `builder()`
    // selects it unambiguously. If another provider feature is ever added this
    // needs an explicit builder_with_provider call.
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// WebSocketConfig is `#[non_exhaustive]`, so it is built through its
/// consuming setters rather than a struct literal.
fn ws_config() -> WebSocketConfig {
    // The frame cap is enforced at the WebSocket layer too, so an oversized
    // message is rejected before tungstenite buffers any of it.
    WebSocketConfig::default()
        .max_message_size(Some(wire::MAX_FRAME_BYTES))
        .max_frame_size(Some(wire::MAX_FRAME_BYTES))
}

/// The registration exchange: challenge, proof of possession, verdict.
/// `token` (P3) rides the Register frame as lowercase hex when present; a
/// relay with enforcement off ignores it, and a client with none simply
/// omits the field — see the compatibility note on `FrameKind::Register`.
fn register<S: Read + Write>(
    ws: &mut WebSocket<S>,
    identity: &Identity,
    token: Option<&[u8]>,
) -> Result<(), ChatError> {
    let challenge = read_ws_frame(ws)?;
    let FrameKind::RegisterChallenge {
        ephemeral_public,
        challenge,
    } = challenge.kind
    else {
        return Err(ChatError::BadFrame);
    };
    let (static_public, mac) = wire::registration_response(identity, &ephemeral_public, &challenge);
    let reply = Frame::new(FrameKind::Register {
        static_public,
        mac,
        // TokenHex, not String: the wrapper's redacting Debug is what keeps
        // the credential out of any formatted Frame (see wire.rs).
        token: token.map(|bytes| wire::TokenHex(hex_lower(bytes))),
    });
    ws.send(Message::Text(wire::encode(&reply)?.into()))
        .map_err(|e| ChatError::Io(e.to_string()))?;
    let answer = read_ws_frame(ws)?;
    match answer.kind {
        FrameKind::Registered => Ok(()),
        FrameKind::Error { code } => Err(match code {
            wire::ErrorCode::VersionMismatch => ChatError::VersionMismatch,
            // The four Premium refusal classes (design 4.4) stay distinct:
            // the UI maps them to different copy.
            wire::ErrorCode::TokenRequired => ChatError::TokenRequired,
            wire::ErrorCode::TokenInvalid => ChatError::TokenInvalid,
            wire::ErrorCode::TokenExpired => ChatError::TokenExpired,
            wire::ErrorCode::KeyRejected => ChatError::KeyRejected,
            _ => ChatError::RegistrationRefused,
        }),
        _ => Err(ChatError::BadFrame),
    }
}

/// Maps the licence-refusal ChatErrors back to their wire codes for the
/// `RelayEvent::Refused` event; every other error is None (an anonymous
/// connection loss, handled exactly as before P3).
fn licence_refusal_code(error: &ChatError) -> Option<ErrorCode> {
    match error {
        ChatError::TokenRequired => Some(ErrorCode::TokenRequired),
        ChatError::TokenInvalid => Some(ErrorCode::TokenInvalid),
        ChatError::TokenExpired => Some(ErrorCode::TokenExpired),
        ChatError::KeyRejected => Some(ErrorCode::KeyRejected),
        _ => None,
    }
}

/// Reads the next protocol frame, tolerating control frames. Used during
/// registration, before the poll loop starts.
fn read_ws_frame<S: Read + Write>(ws: &mut WebSocket<S>) -> Result<Frame, ChatError> {
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => return wire::decode(t.as_bytes()),
            Ok(Message::Close(_)) => return Err(ChatError::Closed),
            Ok(_) => {
                let _ = ws.flush(); // pushes any queued pong
            }
            Err(e) => return Err(ChatError::Io(e.to_string())),
        }
    }
}

/// Steady state: relay frames in, outbound frames out, until something ends
/// the connection. See `connect_and_register` for why read timeouts are safe.
fn run_poll(
    mut ws: WebSocket<TlsStream>,
    outbound: &Receiver<Frame>,
    events: &SyncSender<RelayEvent>,
    shutdown: &AtomicBool,
    reset: &AtomicBool,
) -> CycleEnd {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return CycleEnd::Shutdown;
        }
        if reset.load(Ordering::SeqCst) {
            // The outbound queue overflowed: this connection is wedged, so it
            // dies and is re-established immediately (fast retry, no backoff).
            return CycleEnd::Lost { fast_retry: true };
        }

        // Outbound first, so a loud relay cannot starve our own sends.
        let mut sent = false;
        for _ in 0..OUTBOUND_DRAIN_PER_TICK {
            match outbound.try_recv() {
                Ok(frame) => {
                    let text = match wire::encode(&frame) {
                        Ok(t) => t,
                        Err(_) => continue, // our own bug, not the relay's; drop the frame
                    };
                    if ws.send(Message::Text(text.into())).is_err() {
                        return CycleEnd::Lost { fast_retry: false };
                    }
                    sent = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return CycleEnd::Shutdown,
            }
        }
        if sent {
            let _ = ws.flush();
        }

        match ws.read() {
            Ok(Message::Text(t)) => match wire::decode(t.as_bytes()) {
                Ok(frame) => {
                    // If the core stops draining, this connection is useless;
                    // drop it rather than let frames pile up anywhere.
                    if events.try_send(RelayEvent::Frame(frame)).is_err() {
                        return CycleEnd::Lost { fast_retry: false };
                    }
                }
                Err(_) => return CycleEnd::Lost { fast_retry: false }, // a relay speaking garbage is dropped
            },
            Ok(Message::Close(_)) => return CycleEnd::Lost { fast_retry: false },
            Ok(_) => {
                // Ping/Pong are answered by tungstenite's queued pongs; Binary
                // is ignored — there is no binary payload path in this
                // protocol, so there is nothing to do with one.
                let _ = ws.flush();
            }
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // Idle tick: nothing arrived within POLL_INTERVAL. Loop back
                // and service the flags and outbound queue.
            }
            Err(_) => return CycleEnd::Lost { fast_retry: false },
        }
    }
}

/// Exponential backoff with ±25% jitter, capped. Jitter matters because a
/// relay restart drops EVERY client at once; synchronized retries would herd.
fn backoff(attempt: u32) -> Duration {
    let shift = attempt.min(5);
    let base_ms = (BACKOFF_BASE.as_millis() as u64)
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_CAP.as_millis() as u64);
    let mut rng = rand_core::OsRng;
    let factor = 75 + rng.next_u64() % 51; // 75%..=125%
    Duration::from_millis(base_ms * factor / 100)
}

fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) {
    let step = Duration::from_millis(100);
    let mut remaining = duration;
    while remaining > step {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(step);
        remaining -= step;
    }
    if !shutdown.load(Ordering::SeqCst) {
        thread::sleep(remaining);
    }
}

/// Lowercase hex, the encoding of the `Register.token` field (design 4.1).
/// Lives here rather than in wire.rs because wire.rs's hex helpers are
/// serde-bound; no new dependency for five lines.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// --- local pre-check (design 4.4) ------------------------------------------

/// The verdict of `relay_precheck`: whether opening a relay connection is
/// worth attempting at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precheck {
    /// License active and a token in hand: connect.
    Connect,
    /// No token stored. Chat stays off with the no-token copy ("Chat is a
    /// Premium feature."). Also the answer for the defensive
    /// (active, no-token) combination — which cannot occur in practice,
    /// ACTIVE implies a verified token — because failing toward "do not
    /// connect" never produces traffic the relay would only reject.
    NoToken,
    /// A token is stored but the license is lapsed: connecting would only
    /// produce relay traffic to be rejected. Chat stays off with the
    /// lapsed copy.
    Lapsed,
}

/// Design 4.4's local evaluation, run BEFORE connecting so a lapsed
/// subscription never produces relay traffic just to be rejected ("the
/// browser evaluates locally before connecting").
///
/// CALLED BY NOTHING — deliberately. The relay's token requirement is
/// config-gated and DEFAULT OFF in this phase, and flipping it is a later,
/// deliberate deliberate act (design preamble). This function lands fully
/// tested so the later wiring is a one-line call in chat_panel, not new
/// logic. Do not "fix" the dead code; the call site arrives with the
/// enforcement flip.
pub fn relay_precheck(state_active: bool, has_token: bool) -> Precheck {
    match (state_active, has_token) {
        (true, true) => Precheck::Connect,
        (false, true) => Precheck::Lapsed,
        // (true, false) is the impossible state documented on `NoToken`.
        (_, false) => Precheck::NoToken,
    }
}

/// Parses `wss://host[:port]/path`. TLS is mandatory: there is no `ws://`
/// mode in the client (the relay itself listens plaintext only behind nginx's
/// TLS termination; the client always sees TLS).
fn parse_wss_url(url: &str) -> Result<(String, u16, String), ChatError> {
    let rest = url.strip_prefix("wss://").ok_or(ChatError::InvalidUrl)?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(ChatError::InvalidUrl);
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        // [v6:literal]:port
        let end = bracketed.find(']').ok_or(ChatError::InvalidUrl)?;
        let host = &bracketed[..end];
        let port = match bracketed[end + 1..].strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| ChatError::InvalidUrl)?,
            None => 443,
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => {
                (h.to_string(), p.parse().map_err(|_| ChatError::InvalidUrl)?)
            }
            _ => (authority.to_string(), 443),
        }
    };
    if host.is_empty() {
        return Err(ChatError::InvalidUrl);
    }
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_stays_capped() {
        let first = backoff(0);
        assert!(first >= Duration::from_millis(700) && first <= Duration::from_millis(1300));
        for attempt in 0..20 {
            assert!(
                backoff(attempt) <= Duration::from_millis(40_000),
                "jittered backoff must stay near the cap"
            );
        }
        let high = backoff(10);
        assert!(high >= Duration::from_millis(20_000));
        assert!(high <= Duration::from_millis(40_000));
    }

    #[test]
    fn wss_urls_parse() {
        assert_eq!(
            parse_wss_url("wss://relay.example.com/ws").unwrap(),
            ("relay.example.com".to_string(), 443, "/ws".to_string())
        );
        assert_eq!(
            parse_wss_url("wss://relay.example.com:8443/").unwrap(),
            ("relay.example.com".to_string(), 8443, "/".to_string())
        );
        assert_eq!(
            parse_wss_url("wss://10.0.0.2/ws").unwrap().1,
            443,
            "default port"
        );
        assert_eq!(
            parse_wss_url("wss://[fd00::1]:9000/ws").unwrap(),
            ("fd00::1".to_string(), 9000, "/ws".to_string())
        );
        assert_eq!(
            parse_wss_url("wss://relay.example.com").unwrap().2,
            "/",
            "missing path defaults to /"
        );
    }

    #[test]
    fn hex_encoding_is_lowercase_and_unpadded() {
        assert_eq!(hex_lower(&[0x00, 0xab, 0xff, 0x10]), "00abff10");
        assert_eq!(hex_lower(&[]), "");
    }

    #[test]
    fn the_local_precheck_matches_the_design_table() {
        assert_eq!(relay_precheck(true, true), Precheck::Connect);
        assert_eq!(relay_precheck(false, true), Precheck::Lapsed);
        assert_eq!(relay_precheck(false, false), Precheck::NoToken);
        // Impossible in practice (ACTIVE implies a verified token); fails
        // toward "do not connect", never toward wasted relay traffic.
        assert_eq!(relay_precheck(true, false), Precheck::NoToken);
    }

    #[test]
    fn only_the_four_licence_errors_map_to_refusal_codes() {
        assert_eq!(
            licence_refusal_code(&ChatError::TokenRequired),
            Some(ErrorCode::TokenRequired)
        );
        assert_eq!(
            licence_refusal_code(&ChatError::TokenInvalid),
            Some(ErrorCode::TokenInvalid)
        );
        assert_eq!(
            licence_refusal_code(&ChatError::TokenExpired),
            Some(ErrorCode::TokenExpired)
        );
        assert_eq!(
            licence_refusal_code(&ChatError::KeyRejected),
            Some(ErrorCode::KeyRejected)
        );
        // Everything else stays an anonymous connection loss.
        assert_eq!(licence_refusal_code(&ChatError::RegistrationRefused), None);
        assert_eq!(licence_refusal_code(&ChatError::Closed), None);
    }

    #[test]
    fn non_tls_and_malformed_urls_are_refused() {
        assert!(parse_wss_url("http://relay.example.com/ws").is_err());
        assert!(parse_wss_url("ws://relay.example.com/ws").is_err());
        assert!(parse_wss_url("wss:///ws").is_err());
        assert!(parse_wss_url("wss://").is_err());
        assert!(parse_wss_url("wss://host:notaport/ws").is_err());
    }
}
