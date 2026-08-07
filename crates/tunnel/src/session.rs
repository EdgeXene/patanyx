//! The WireGuard session: one `boringtun::noise::Tunn`, one connected UDP
//! socket to the peer endpoint, and the timer pump that keeps both honest.
//!
//! WHY A CONNECTED UDP SOCKET. There is exactly one peer and the config
//! names it. `connect()` makes the kernel drop datagrams from anywhere else
//! for free, and -- just as valuable -- it lets ICMP port-unreachable come
//! back as a `recv` error, which is the fastest possible "the peer is gone"
//! signal on a loopback or a LAN. The slow path (silence longer than the
//! keepalive-scaled limit) covers networks that swallow ICMP.
//!
//! WHAT IS DELIBERATELY NOT DONE HERE. No retry policy of our own:
//! `update_timers` IS the retry policy (handshake retransmits, keepalives),
//! and inventing a second one would only fight it. No rate limiter: the
//! `rate_limiter` argument exists for servers facing arbitrary internet
//! senders; this is a single-peer client whose socket only accepts packets
//! from the configured endpoint, so `None` is passed and the justification
//! is this paragraph. No key storage: keys are decoded, handed to boringtun
//! by value, and the local copies zeroized in the same function.
//!
//! KEYS. The 32-byte arrays this module holds exist only inside `start()`
//! and are zeroized there. boringtun keeps its own `StaticSecret`, which
//! zeroizes on drop through x25519-dalek's zeroize support (default-on, and
//! boringtun does not disable x25519-dalek's default features). The x25519
//! types come through `boringtun::x25519` -- the crate's own re-export -- so
//! there is no separate x25519-dalek dependency whose version could drift
//! from the one `Tunn::new` actually takes. Nothing in this module
//! implements `Debug`, and no error carries key material.

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::config::TunnelConfig;
use crate::{TunnelError, TunnelEvent};

/// Largest UDP datagram we will read. A WireGuard data packet carrying a
/// full-MTU inner packet is ~1480 bytes; this is generous headroom, and
/// anything larger is truncated by the socket and then rejected by
/// boringtun's parser anyway.
const UDP_RECV_BUF: usize = 4096;

/// Scratch for `decapsulate`/`update_timers`: must hold a plaintext IP
/// packet, which is bounded by the tunnel MTU plus a header's slack.
const DECAP_BUF: usize = 4096;

/// Scratch for `encapsulate`. boringtun PANICS if dst < src.len() + 32 or
/// < 148 (its own doc comment says so); smoltcp never emits more than the
/// MTU (1420), so 2048 always satisfies the contract.
const ENCAP_BUF: usize = 2048;

/// How often `update_timers` runs. boringtun's own timers (rekey, handshake
/// retransmits, keepalives, session expiry) only need sub-second granularity.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// How long a never-answered handshake runs before `HandshakeFailed` is
/// emitted. Retrying continues afterwards -- this is a signal, not a
/// give-up. Shortened under cfg(test) so the test suite measures in seconds.
#[cfg(not(test))]
const HANDSHAKE_FAIL_AFTER: Duration = Duration::from_secs(15);
#[cfg(test)]
const HANDSHAKE_FAIL_AFTER: Duration = Duration::from_secs(5);

/// Consecutive ICMP-refused errors that count as "the peer is gone". One
/// could be a transient; several in a row, on a connected socket, from a
/// kernel that only forwards them for OUR peer's address, is evidence.
#[cfg(not(test))]
const UNREACHABLE_STRIKES: u32 = 3;
#[cfg(test)]
const UNREACHABLE_STRIKES: u32 = 2;

/// Our `index` argument to `Tunn::new`: it only labels this tunnel in
/// boringtun's internal bookkeeping (and its tracing), and there is exactly
/// one Tunn in the process.
const OUR_INDEX: u32 = 0;

/// Session state, owned here; `TunnelStatus` is the published projection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Connecting,
    Up,
    Down,
}

/// Decode a WireGuard key: exactly 44 base64 characters, one `=` of
/// padding, 32 bytes out.
///
/// WHY HAND-WRITTEN AND NOT A CRATE. The only thing this crate ever
/// base64-decodes is KEY MATERIAL, in exactly this one shape. That is small
/// enough to own and too sensitive to casually delegate -- the same
/// reasoning config.rs gives for owning the parser. The parser's
/// `looks_like_key` already bounds the shape; this decoder re-checks every
/// character because a decoder that trusts its caller is a decoder waiting
/// for a second caller.
fn decode_key(b64: &str) -> Option<[u8; 32]> {
    fn sextet(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = b64.as_bytes();
    // 32 bytes = 10 full 3-byte groups (40 chars) + 2 bytes (3 chars + '=').
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }
    let mut out = [0u8; 32];
    for group in 0..10 {
        let (s0, s1, s2, s3) = (
            sextet(bytes[group * 4])?,
            sextet(bytes[group * 4 + 1])?,
            sextet(bytes[group * 4 + 2])?,
            sextet(bytes[group * 4 + 3])?,
        );
        out[group * 3] = (s0 << 2) | (s1 >> 4);
        out[group * 3 + 1] = (s1 << 4) | (s2 >> 2);
        out[group * 3 + 2] = (s2 << 6) | s3;
    }
    let (s0, s1, s2) = (sextet(bytes[40])?, sextet(bytes[41])?, sextet(bytes[42])?);
    out[30] = (s0 << 2) | (s1 >> 4);
    out[31] = (s1 << 4) | (s2 >> 2);
    // Non-canonical trailing bits in s2 are tolerated on purpose: the KEY is
    // the 32 bytes, and both ends of every real workflow produce canonical
    // padding anyway.
    Some(out)
}

fn is_unreachable(e: &io::Error) -> bool {
    // Linux/macOS report ICMP port-unreachable on a connected UDP socket as
    // ECONNREFUSED; Windows as WSAECONNRESET. Both mean "the far end, or
    // something near it, is telling us there is nobody there".
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}

pub(crate) struct Session {
    socket: UdpSocket,
    tunn: Tunn,
    state: SessionState,
    connecting_since: Instant,
    last_inbound: Instant,
    last_timer_tick: Instant,
    unreachable_strikes: u32,
    handshake_failed_sent: bool,
    /// Silence longer than this, on a session WITH keepalives configured,
    /// means the peer is gone. `None` when the config has no keepalive:
    /// without keepalives an idle tunnel is legitimately silent and there is
    /// no honest timeout to apply (ICMP refusal still applies).
    silence_limit: Option<Duration>,
}

impl Session {
    pub(crate) fn start(config: &TunnelConfig) -> Result<Self, TunnelError> {
        let mut private =
            decode_key(&config.private_key_b64).ok_or(TunnelError::InvalidKey("PrivateKey"))?;
        let mut peer_public = decode_key(&config.peer_public_key_b64)
            .ok_or(TunnelError::InvalidKey("PublicKey"))?;
        let mut psk = match &config.preshared_key_b64 {
            Some(s) => Some(decode_key(s).ok_or(TunnelError::InvalidKey("PresharedKey"))?),
            None => None,
        };
        let tunn = {
            let secret = StaticSecret::from(private);
            let public = PublicKey::from(peer_public);
            Tunn::new(
                secret,
                public,
                psk,
                config.keepalive_secs,
                OUR_INDEX,
                None, // rate_limiter: single-peer client; see module docs.
            )
        };
        private.zeroize();
        peer_public.zeroize();
        if let Some(p) = psk.as_mut() {
            p.zeroize();
        }

        // The endpoint hostname (if it is one) resolves through the HOST
        // resolver by necessity: the tunnel cannot carry the lookup that
        // finds its own far end. The disclosure copy must say so.
        let peer_addr = config
            .endpoint
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| TunnelError::EndpointUnresolvable(config.endpoint.clone()))?;
        let bind_addr: SocketAddr = match peer_addr {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(peer_addr)?;
        socket.set_nonblocking(true)?;

        let now = Instant::now();
        let mut session = Self {
            socket,
            tunn,
            state: SessionState::Connecting,
            connecting_since: now,
            last_inbound: now,
            last_timer_tick: now,
            unreachable_strikes: 0,
            handshake_failed_sent: false,
            silence_limit: config
                .keepalive_secs
                .map(|k| Duration::from_secs(u64::from(k.max(1)) * 3 + 10)),
        };
        session.kick();
        Ok(session)
    }

    pub(crate) fn is_up(&self) -> bool {
        self.state == SessionState::Up
    }

    /// Start the handshake NOW rather than on the first user packet: a SOCKS
    /// proxy can sit idle for minutes, and "Connecting" must converge to Up
    /// or HandshakeFailed without waiting for one. boringtun exposes exactly
    /// this: `format_handshake_initiation` is a no-op (`Done`) when a
    /// handshake is already in progress, so calling it once at start is safe
    /// -- verified against the vendored 0.7.1 source, not remembered. A lost
    /// initiation is retransmitted by `update_timers`.
    fn kick(&mut self) {
        let mut dst = [0u8; ENCAP_BUF];
        if let TunnResult::WriteToNetwork(packet) =
            self.tunn.format_handshake_initiation(&mut dst, false)
        {
            let _ = self.socket.send(packet);
        }
    }

    /// A packet that boringtun ACCEPTED arrived from the peer. WireGuard
    /// peers send nothing valid before the handshake completes, so this is
    /// the up-proof -- and it doubles as liveness and strike reset.
    fn note_valid_inbound(&mut self, events: &mut Vec<TunnelEvent>) {
        self.unreachable_strikes = 0;
        self.last_inbound = Instant::now();
        if self.state != SessionState::Up {
            self.state = SessionState::Up;
            events.push(TunnelEvent::Up);
        }
    }

    /// One more piece of "nobody is there" evidence.
    fn strike(&mut self, events: &mut Vec<TunnelEvent>) {
        self.unreachable_strikes += 1;
        if self.unreachable_strikes < UNREACHABLE_STRIKES {
            return;
        }
        match self.state {
            SessionState::Up => {
                self.state = SessionState::Down;
                events.push(TunnelEvent::PeerUnreachable);
            }
            SessionState::Connecting if !self.handshake_failed_sent => {
                self.handshake_failed_sent = true;
                events.push(TunnelEvent::HandshakeFailed);
            }
            _ => {}
        }
    }

    fn send_raw(&mut self, packet: &[u8], events: &mut Vec<TunnelEvent>) {
        match self.socket.send(packet) {
            Ok(_) => {}
            Err(e) if is_unreachable(&e) => self.strike(events),
            // UDP is best-effort; boringtun's timers retransmit what matters
            // (handshakes), and TCP above retransmits the rest.
            Err(_) => {}
        }
    }

    /// Read and decapsulate every waiting datagram; append plaintext IPv4
    /// packets to `inbound`.
    pub(crate) fn poll(&mut self, inbound: &mut VecDeque<Vec<u8>>, events: &mut Vec<TunnelEvent>) {
        loop {
            let mut buf = [0u8; UDP_RECV_BUF];
            match self.socket.recv(&mut buf) {
                // An EMPTY datagram must NOT reach decapsulate: boringtun
                // defines an empty datagram as the drain-queue call, and a
                // real empty datagram is meaningless here anyway.
                Ok(0) => continue,
                Ok(n) => self.handle_datagram(&buf[..n], inbound, events),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if is_unreachable(&e) => {
                    self.strike(events);
                    return;
                }
                Err(_) => return, // transient; the next tick retries
            }
        }
    }

    fn handle_datagram(
        &mut self,
        datagram: &[u8],
        inbound: &mut VecDeque<Vec<u8>>,
        events: &mut Vec<TunnelEvent>,
    ) {
        let mut dst = [0u8; DECAP_BUF];
        match self.tunn.decapsulate(None, datagram, &mut dst) {
            TunnResult::Done => self.note_valid_inbound(events),
            TunnResult::WriteToNetwork(packet) => {
                self.note_valid_inbound(events);
                self.send_raw(packet, events);
                // boringtun's documented contract: after WriteToNetwork,
                // keep calling decapsulate with an EMPTY datagram until it
                // stops yielding them. Known trip hazard; do not "simplify".
                self.drain_queued(inbound, events);
            }
            TunnResult::WriteToTunnelV4(packet, _src) => {
                self.note_valid_inbound(events);
                inbound.push_back(packet.to_vec());
            }
            TunnResult::WriteToTunnelV6(_packet, _src) => {
                self.note_valid_inbound(events);
                // The stack is IPv4-only in this pass; v6 inside the tunnel
                // is dropped, not errored.
            }
            // A datagram that fails decapsulation proves nothing either way
            // (replay, corruption, a stray): it must not mark the peer
            // alive, and it must not kill a working session.
            TunnResult::Err(_) => {}
        }
    }

    fn drain_queued(&mut self, inbound: &mut VecDeque<Vec<u8>>, events: &mut Vec<TunnelEvent>) {
        loop {
            let mut dst = [0u8; DECAP_BUF];
            match self.tunn.decapsulate(None, &[], &mut dst) {
                TunnResult::WriteToNetwork(packet) => self.send_raw(packet, events),
                TunnResult::WriteToTunnelV4(packet, _) => inbound.push_back(packet.to_vec()),
                TunnResult::WriteToTunnelV6(..) => {}
                TunnResult::Done | TunnResult::Err(_) => return,
            }
        }
    }

    /// The timer pump: handshake retransmits and keepalives come FROM here,
    /// so this must run on a tick or the session is a corpse. Self-gated.
    pub(crate) fn tick_timers(&mut self, events: &mut Vec<TunnelEvent>) {
        if self.last_timer_tick.elapsed() < TIMER_TICK {
            return;
        }
        self.last_timer_tick = Instant::now();

        loop {
            let mut dst = [0u8; DECAP_BUF];
            match self.tunn.update_timers(&mut dst) {
                TunnResult::WriteToNetwork(packet) => self.send_raw(packet, events),
                // Done, errors (including a timed-out handshake attempt --
                // boringtun just tries again on the next tick), and the
                // tunnel-write results this call never produces in practice.
                _ => break,
            }
        }

        if self.state == SessionState::Connecting
            && !self.handshake_failed_sent
            && self.connecting_since.elapsed() >= HANDSHAKE_FAIL_AFTER
        {
            self.handshake_failed_sent = true;
            events.push(TunnelEvent::HandshakeFailed);
        }
        if self.state == SessionState::Up {
            if let Some(limit) = self.silence_limit {
                if self.last_inbound.elapsed() >= limit {
                    self.state = SessionState::Down;
                    events.push(TunnelEvent::PeerUnreachable);
                }
            }
        }
    }

    /// Encapsulate one IP packet from the stack and send it. Loss is fine:
    /// before the handshake, boringtun queues the packet and flushes it when
    /// the session establishes; after it, UDP loss is TCP's problem.
    pub(crate) fn send_packet(&mut self, packet: &[u8], events: &mut Vec<TunnelEvent>) {
        let mut dst = [0u8; ENCAP_BUF];
        if let TunnResult::WriteToNetwork(encrypted) = self.tunn.encapsulate(packet, &mut dst) {
            self.send_raw(encrypted, events);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn b64_encode(bytes: &[u8; 32]) -> String {
        let mut out = String::with_capacity(44);
        for chunk in bytes.chunks(3) {
            let n = chunk.len();
            let b = |i: usize| *chunk.get(i).unwrap_or(&0);
            out.push(ALPHABET[(b(0) >> 2) as usize] as char);
            out.push(ALPHABET[((b(0) << 4 | b(1) >> 4) & 0x3f) as usize] as char);
            out.push(if n > 1 {
                ALPHABET[((b(1) << 2 | b(2) >> 6) & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if n > 2 { ALPHABET[(b(2) & 0x3f) as usize] as char } else { '=' });
        }
        out
    }

    #[test]
    fn the_base64_decoder_reads_the_exact_shape_wireguard_uses() {
        assert_eq!(decode_key(&b64_encode(&[0u8; 32])), Some([0u8; 32]));
        assert_eq!(decode_key(&b64_encode(&[0xffu8; 32])), Some([0xffu8; 32]));
        let sequential: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(decode_key(&b64_encode(&sequential)), Some(sequential));
        // Known vector: 32 zero bytes are 43 'A's and one '='.
        let zeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(zeros.len(), 44);
        assert_eq!(decode_key(zeros), Some([0u8; 32]));
    }

    #[test]
    fn the_base64_decoder_rejects_every_other_shape() {
        let good = b64_encode(&[7u8; 32]);
        assert_eq!(decode_key(&good[..43]), None, "truncated");
        assert_eq!(decode_key(&format!("{good}x")), None, "too long");
        assert_eq!(decode_key(&good.replace('=', "")), None, "padding missing");
        let mut bad_char = good.clone();
        bad_char.replace_range(10..11, "!");
        assert_eq!(decode_key(&bad_char), None, "character outside the alphabet");
        assert_eq!(decode_key(""), None);
    }

    const CLIENT_PRIV: [u8; 32] = [1u8; 32];
    const SERVER_PRIV: [u8; 32] = [2u8; 32];

    fn public_of(private: &[u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(*private)).as_bytes()
    }

    fn client_session_config(endpoint: String) -> TunnelConfig {
        TunnelConfig {
            private_key_b64: b64_encode(&CLIENT_PRIV),
            peer_public_key_b64: b64_encode(&public_of(&SERVER_PRIV)),
            endpoint,
            preshared_key_b64: None,
            keepalive_secs: Some(1),
            allowed_ips: vec![],
            address: vec!["10.99.0.2/32".into()],
            dns: vec![],
        }
    }

    /// A "server" Tunn on a loopback UDP socket: answers handshakes and
    /// echoes any decapsulated IP packet straight back. Proves the session
    /// pump with no real WireGuard server anywhere.
    #[test]
    fn two_tunn_instances_handshake_and_round_trip_a_packet_over_loopback_udp() {
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let server_port = server_socket.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let client_public = public_of(&CLIENT_PRIV);
        let server = thread::spawn(move || {
            let mut tunn = Tunn::new(
                StaticSecret::from(SERVER_PRIV),
                PublicKey::from(client_public),
                None,
                None,
                9,
                None,
            );
            let mut peer: Option<SocketAddr> = None;
            while !stop2.load(Ordering::SeqCst) {
                let mut buf = [0u8; 4096];
                if let Ok((n, src)) = server_socket.recv_from(&mut buf) {
                    peer = Some(src);
                    let mut echo: Option<Vec<u8>> = None;
                    {
                        let mut dst = [0u8; 4096];
                        match tunn.decapsulate(None, &buf[..n], &mut dst) {
                            TunnResult::WriteToNetwork(p) => {
                                let _ = server_socket.send_to(p, src);
                            }
                            TunnResult::WriteToTunnelV4(p, _) => echo = Some(p.to_vec()),
                            _ => {}
                        }
                    }
                    loop {
                        let mut dst = [0u8; 4096];
                        match tunn.decapsulate(None, &[], &mut dst) {
                            TunnResult::WriteToNetwork(p) => {
                                let _ = server_socket.send_to(p, src);
                            }
                            TunnResult::WriteToTunnelV4(p, _) => echo = Some(p.to_vec()),
                            _ => break,
                        }
                    }
                    if let Some(packet) = echo {
                        let mut dst = [0u8; 2048];
                        if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&packet, &mut dst) {
                            let _ = server_socket.send_to(p, src);
                        }
                    }
                }
                let _ = peer;
            }
        });

        let mut session = Session::start(&client_session_config(format!("127.0.0.1:{server_port}")))
            .expect("session starts");
        let mut inbound: VecDeque<Vec<u8>> = VecDeque::new();
        let mut events = Vec::new();

        let deadline = Instant::now() + Duration::from_secs(15);
        while !session.is_up() {
            assert!(Instant::now() < deadline, "handshake never completed");
            session.poll(&mut inbound, &mut events);
            session.tick_timers(&mut events);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(events.contains(&TunnelEvent::Up));

        // A minimal VALID IPv4 header. "Any 20 bytes" does NOT work here:
        // boringtun's validate_decapsulated_packet checks the version
        // nibble and the total-length field before it will hand a
        // decapsulated packet back (noise/mod.rs:464-494, vendored 0.7.1),
        // so a byte-counter payload is silently swallowed as
        // WireGuardError::InvalidPacket -- measured, not theorized.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // version 4, IHL 5
        packet[2..4].copy_from_slice(&20u16.to_be_bytes()); // total length
        packet[8] = 64; // TTL
        packet[9] = 253; // protocol: RFC 3692 experimental
        packet[12..16].copy_from_slice(&[10, 99, 0, 2]); // src
        packet[16..20].copy_from_slice(&[10, 99, 0, 1]); // dst
        session.send_packet(&packet, &mut events);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            session.poll(&mut inbound, &mut events);
            if let Some(echoed) = inbound.pop_front() {
                assert_eq!(echoed, packet, "the packet must round-trip untouched");
                break;
            }
            assert!(Instant::now() < deadline, "the packet never came back");
            session.tick_timers(&mut events);
            thread::sleep(Duration::from_millis(10));
        }

        stop.store(true, Ordering::SeqCst);
        let _ = server.join();
    }

    #[test]
    fn a_handshake_to_nowhere_surfaces_as_handshake_failed_not_silence() {
        let dead = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let mut session =
            Session::start(&client_session_config(format!("127.0.0.1:{dead_port}"))).unwrap();
        let mut inbound = VecDeque::new();
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            session.poll(&mut inbound, &mut events);
            session.tick_timers(&mut events);
            if events.contains(&TunnelEvent::HandshakeFailed) {
                break;
            }
            assert!(!session.is_up());
            assert!(Instant::now() < deadline, "no HandshakeFailed within the bound");
            thread::sleep(Duration::from_millis(10));
        }
    }

    // A `key_material_is_zeroized_after_the_tunn_is_built` test lived here
    // and was DELETED rather than kept: its body was "start a session, assert
    // it is Ok", which passes with every `.zeroize()` call in `start` removed
    // -- a test that cannot fail, asserting a property it never touched.
    //
    // NOTHING REPLACES IT, and that is the honest position rather than a
    // gap nobody noticed. The decoded arrays here and the config Strings
    // `Tunnel::start_on` wipes are both consumed by value, so no caller can
    // observe either buffer afterwards; a test could only re-prove that
    // `String::zeroize` zeroes a String, which is the same vacuity wearing
    // a different name. The wiping is a code-shape property held by review.
    // What IS tested, because it is observable: neither type's `Debug` can
    // print a key (config.rs and the vault's model.rs both assert it).
}
