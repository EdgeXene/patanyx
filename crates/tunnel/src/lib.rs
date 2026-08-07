//! Userspace WireGuard for PATANYX: a tunnel the user supplies the far end of.
//!
//! PATANYX OPERATES NO VPN SERVICE, and this crate is where that decision is
//! enforced rather than merely stated. There is no endpoint list compiled in,
//! no account, no API client and no default server. Every tunnel this crate can
//! bring up is one the user pasted a configuration for.
//!
//! WHAT IT COVERS, AND WHAT IT DOES NOT. A userspace WireGuard session with a
//! loopback SOCKS5 proxy in front of it carries the traffic of whatever is
//! pointed at that proxy -- which is this browser, and nothing else on the
//! machine. That is a smaller promise than a system VPN and the UI has to say
//! so. It is also the only design that needs no elevation and no driver, which
//! is what keeps the product installable by a normal user and keeps the Flatpak
//! (`--share=network`, no `/dev/net/tun`) working at all.
//!
//! FAIL CLOSED. If the session is not up, the proxy refuses connections and the
//! engine fails the request. It never falls back to the direct route: a
//! silent fallback is indistinguishable, from the user's side, from the tunnel
//! working -- which is the one failure this whole feature must not have.
//!
//! ARCHITECTURE. Two threads, no async runtime, exactly the lifecycle the
//! chat transport uses: `start()` validates, binds and spawns; an
//! `Arc<AtomicBool>` is the shutdown signal; `shutdown()` joins. An accept
//! thread owns the loopback SOCKS5 listener and hands accepted streams to a
//! core thread over a bounded channel. The core thread owns everything else
//! -- the UDP socket, the boringtun session, the smoltcp stack and every
//! proxied connection -- so no smoltcp state ever crosses a thread boundary,
//! and so that there is exactly one place in the crate where a connection
//! toward a destination can be opened. That single place is what makes
//! fail-closed a property of the structure instead of a thing to remember.
//!
//! BINDING BEFORE CONFIGURATION. A caller can need the proxy port before
//! the tunnel configuration exists at all: a browser engine picks its proxy
//! at startup, while the configuration is still inside an encrypted store.
//! `bind_proxy` binds the loopback listener early and refuses every
//! connection until `start_on` hands the SAME socket to the real accept
//! loop. The port is never rebound, so the fail-closed promise above holds
//! across the handover with no window where the port is free for another
//! process.

mod config;
mod session;
mod socks;
mod stack;

pub use config::{parse, ConfigError, TunnelConfig, MAX_CONFIG_BYTES};

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use zeroize::Zeroize;

use session::Session;
use socks::{Client, Step};
use stack::Stack;

/// How the tunnel is doing, as of the last event the core thread processed.
/// Shared with the core as a plain atomic: `status()` must never block on
/// the core, and a poisoned lock has no place on a status read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    /// Handshake initiated (or being retried); no valid packet from the peer
    /// yet. The SOCKS5 proxy refuses every CONNECT in this state.
    Connecting = 0,
    /// A cryptographically valid packet has arrived from the peer: WireGuard
    /// peers send nothing valid before the handshake completes, so one valid
    /// packet is proof the session exists.
    Up = 1,
    /// Was up (or tried to be) and is not now. New CONNECTs are refused.
    /// The session keeps running: WireGuard recovers by itself if the peer
    /// returns, and the next valid packet moves this back to `Up`.
    Down = 2,
}

/// Something the tunnel wants the caller to know. Delivered on the core
/// thread, like the chat transport's events: the callback must be cheap and
/// must not call back into the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelEvent {
    /// The session is established (see `TunnelStatus::Up` for the proof).
    Up,
    /// The session is down for a reason this crate can describe. Reserved
    /// for session-ending faults; the current core never ends a session on
    /// its own, so today nothing emits this -- it exists so the first
    /// caller that needs "down because X" is not a breaking change.
    Down(String),
    /// The handshake has been retried without an answer for longer than the
    /// crate is willing to stay quiet about. The tunnel keeps retrying
    /// (that is what WireGuard does), but a config pointing at a dead
    /// endpoint must surface as this event, never as a silent eternal
    /// "connecting".
    HandshakeFailed,
    /// The session WAS up and the peer has stopped answering: ICMP refusal
    /// on the connected socket, or silence past the keepalive-scaled limit.
    PeerUnreachable,
}

/// Why a tunnel refused to start. Named variants, in the style of
/// `ConfigError`: the message says what is wrong, never what the keys were.
#[derive(Debug)]
pub enum TunnelError {
    /// `[Interface] Address` had no usable IPv4 CIDR (`a.b.c.d/prefix`).
    /// Refused at start, not at import: importing is not a network event.
    NoIpv4Address,
    /// `[Interface] DNS` had no usable IPv4 server.
    ///
    /// REFUSED rather than started, because a tunnel without one cannot
    /// carry a browser: every engine CONNECT through a SOCKS5 proxy names a
    /// HOSTNAME, resolution happens inside the tunnel by design (resolving
    /// on the host would leak exactly what the tunnel exists to hide), and
    /// with no server to ask, `socks.rs` refuses every DOMAIN request. That
    /// tunnel handshakes, reports Up, answers the liveness probe -- and
    /// loads nothing. A session that can only ever fail must fail HERE,
    /// where the panel can name the reason, rather than look healthy while
    /// nothing works.
    NoDnsServer,
    /// A base64 key did not decode to 32 bytes. Carries WHICH key, never
    /// the key material.
    InvalidKey(&'static str),
    /// The endpoint host:port could not be resolved to an address. The
    /// endpoint is not secret (it is in every packet the tunnel sends), so
    /// it is carried for the message.
    EndpointUnresolvable(String),
    /// The smoltcp interface could not be assembled.
    InterfaceSetup(&'static str),
    /// A std socket (UDP to the peer, or the loopback listener) failed.
    Io(io::Error),
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoIpv4Address => write!(
                f,
                "the configuration's [Interface] Address has no usable IPv4 \
                 address (a.b.c.d/prefix) for the tunnel interface"
            ),
            Self::NoDnsServer => write!(
                f,
                "the configuration's [Interface] DNS has no usable IPv4 \
                 server. The tunnel resolves names inside itself, so without \
                 one no site could be reached through it"
            ),
            Self::InvalidKey(k) => write!(f, "{k} is not in the form WireGuard uses"),
            Self::EndpointUnresolvable(e) => {
                write!(f, "the peer endpoint {e} could not be resolved")
            }
            Self::InterfaceSetup(what) => {
                write!(f, "the virtual TCP/IP stack could not be set up: {what}")
            }
            Self::Io(e) => write!(f, "a socket needed for the tunnel could not be opened: {e}"),
        }
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TunnelError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Accepted-but-not-yet-serviced SOCKS connections. Bounded: a loopback
/// connect flood cannot grow memory, and a full queue drops the newest
/// client instead of blocking the accept thread (which `shutdown()` joins).
const ACCEPT_QUEUE: usize = 64;

/// The core loop's cadence. Everything the core does is nonblocking; this
/// is the granularity of SOCKS progress, stack polling and shutdown
/// latency. Clarity first: 100 Hz for a browser proxy is not a bottleneck.
const CORE_TICK: Duration = Duration::from_millis(10);

/// The first `[Interface] Address` entry that is a real IPv4 CIDR. Junk and
/// IPv6 entries are skipped, not fatal: providers hand out dual-stack
/// addresses, and this stack is IPv4-only in this pass.
fn first_ipv4_cidr(values: &[String]) -> Option<smoltcp::wire::Ipv4Cidr> {
    values.iter().find_map(|v| v.parse::<smoltcp::wire::Ipv4Cidr>().ok())
}

/// The first `[Interface] DNS` entry that is an IPv4 address: the server
/// SOCKS5 DOMAIN requests are resolved against, INSIDE the tunnel.
fn first_dns_ipv4(values: &[String]) -> Option<Ipv4Addr> {
    values.iter().find_map(|v| v.parse::<Ipv4Addr>().ok())
}

/// A bound loopback listener with no tunnel behind it yet: the answer to
/// "the engine needs the proxy port before the vault can be unlocked".
///
/// Created by [`Tunnel::bind_proxy`]; turned into a real tunnel by
/// [`Tunnel::start_on`], which takes the SAME listener over -- the port is
/// never rebound, so there is no window where another process could claim
/// it and no race between "refuse" and "serve". Until the handover, a
/// refuse thread accepts and immediately drops every connection: the
/// engine reads a closed proxy connection as a failed request, which is
/// exactly the fail-closed behaviour wanted while the vault is locked.
/// Accept-and-drop is sufficient; nothing here speaks SOCKS.
///
/// `Drop` signals and joins the refuse thread, so an aborted startup
/// leaves no thread behind -- and leaves the port closed, which is the
/// other sanctioned fail-closed state.
pub struct BoundProxy {
    // `Option` solely so `into_listener` can move the listener out of a
    // type that implements `Drop`, without `unsafe`.
    listener: Option<TcpListener>,
    port: u16,
    refuse_shutdown: Arc<AtomicBool>,
    refuse_thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for BoundProxy {
    /// Hand-written because the derived one would print the raw listener
    /// and the thread handle -- noise in a `FailedStart` that a caller may
    /// well log. The port is the only fact worth reporting, and it is not
    /// secret (it is loopback, and the engine was told it at startup).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundProxy")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl BoundProxy {
    /// The loopback port the engine should point at.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stops the refuse thread and hands the still-bound listener to the
    /// real accept loop. The port never goes unbound in the handover: the
    /// listener is the same socket `bind_proxy` created.
    fn into_listener(mut self) -> (TcpListener, u16) {
        self.stop_refuse();
        // Taken exactly once, here; `stop_refuse` does not touch it.
        let listener = self.listener.take().expect("bound listener taken once");
        (listener, self.port)
    }

    /// Idempotent by construction: called by `into_listener` and then again
    /// by `Drop` when the husk drops.
    fn stop_refuse(&mut self) {
        self.refuse_shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.refuse_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for BoundProxy {
    fn drop(&mut self) {
        self.stop_refuse();
    }
}

/// A `start_on` that failed, WITH the proxy it was given handed back.
///
/// The point of the type: the loopback port must not be released while an
/// engine is still pointing at it. The caller parks `proxy` again (it is
/// still bound and still refusing every connection, which is the
/// fail-closed state) and reports `error`. `proxy` is `None` only past the
/// handover, where the listener has already moved into the accept loop and
/// there is nothing left to park.
#[derive(Debug)]
pub struct FailedStart {
    pub proxy: Option<BoundProxy>,
    pub error: TunnelError,
}

impl FailedStart {
    fn without_proxy(error: TunnelError) -> Self {
        Self { proxy: None, error }
    }
}

impl fmt::Display for FailedStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

/// The handle the app keeps. Methods only read shared state; everything the
/// tunnel does back arrives through the `on_event` callback.
pub struct Tunnel {
    shutdown: Arc<AtomicBool>,
    status: Arc<AtomicU8>,
    socks_port: u16,
    accept_thread: Option<JoinHandle<()>>,
    core_thread: Option<JoinHandle<()>>,
}

impl Tunnel {
    /// Validates, binds, spawns -- as `bind_proxy()` followed by
    /// `start_on(...)`. The bind now happens BEFORE validation, which is
    /// safe for the one refusal ordering that matters: the listener is
    /// loopback-only and ephemeral, and the network event the ordering
    /// protects -- endpoint resolution -- still happens strictly after the
    /// address and key checks inside `start_on`. A config that can never
    /// start simply drops the parked `BoundProxy`, so on any error nothing
    /// is left behind, exactly as before.
    pub fn start(
        config: TunnelConfig,
        on_event: impl Fn(TunnelEvent) + Send + 'static,
    ) -> Result<Tunnel, TunnelError> {
        // The parked proxy is handed back on failure and dropped here: a
        // caller that binds and starts in one breath has nothing to keep it
        // for. `start_on`'s callers who kept the port DO keep it.
        Self::start_on(Self::bind_proxy()?, config, on_event).map_err(|failed| failed.error)
    }

    /// Binds the loopback SOCKS listener WITHOUT a tunnel behind it, for
    /// callers that must know the port before the configuration exists
    /// (the browser engine picks its proxy at startup; the configuration
    /// is still locked inside the vault at that moment). The listener is
    /// live immediately: a refuse thread accepts and drops every
    /// connection, so anything pointed at the port fails its requests
    /// instead of hanging -- the fail-closed state, available before there
    /// is a tunnel at all. `start_on` turns this into a real tunnel on the
    /// SAME port.
    pub fn bind_proxy() -> io::Result<BoundProxy> {
        // Loopback ONLY, ephemeral port: this listener is for this browser
        // and must never be a service the machine (or the LAN) can reach.
        let listener = socks::bind_listener()?;
        let port = listener.local_addr()?.port();
        let refuse_shutdown = Arc::new(AtomicBool::new(false));
        // The thread gets its own handle to the SAME socket: the port stays
        // bound for as long as either handle lives, so joining the thread
        // later and handing the listener to `start_on` cannot lose the
        // port in between.
        let thread_listener = listener.try_clone()?;
        // Accepting must stay nonblocking on the clone too: a blocking
        // accept would never observe the shutdown flag and
        // `BoundProxy::drop` could hang inside join.
        thread_listener.set_nonblocking(true)?;
        let refuse_thread = thread::Builder::new()
            .name("patanyx-tunnel-refuse".into())
            .spawn({
                let refuse_shutdown = refuse_shutdown.clone();
                move || socks::refuse_loop(thread_listener, refuse_shutdown)
            })?;
        Ok(BoundProxy {
            listener: Some(listener),
            port,
            refuse_shutdown,
            refuse_thread: Some(refuse_thread),
        })
    }

    /// Starts the tunnel on an ALREADY-BOUND proxy: stops and joins the
    /// refuse thread, then runs the normal accept loop on the same
    /// listener. The port is never rebound, so there is no window where it
    /// is free for another process and no race with the engine, which is
    /// already pointing at it.
    pub fn start_on(
        proxy: BoundProxy,
        mut config: TunnelConfig,
        on_event: impl Fn(TunnelEvent) + Send + 'static,
    ) -> Result<Tunnel, FailedStart> {
        // Refusal order matters, exactly as `start` documents: the address
        // and the resolver are checked first (before anything touches the
        // network), then the keys, then the endpoint.
        //
        // EVERY failure hands `proxy` BACK, still bound and still refusing.
        // The first version let `?` drop it, which released the loopback
        // port while the engine -- which took that number at startup and
        // cannot be told a new one -- went on pointing at it. Any local
        // process could then bind it and become the browser's proxy: worse
        // than the direct connection the whole feature exists to prevent.
        macro_rules! give_back {
            ($proxy:expr, $result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(FailedStart {
                            proxy: Some($proxy),
                            error: error.into(),
                        })
                    }
                }
            };
        }

        let address = give_back!(
            proxy,
            first_ipv4_cidr(&config.address).ok_or(TunnelError::NoIpv4Address)
        );
        // A browser proxy resolves names INSIDE the tunnel or not at all;
        // see `TunnelError::NoDnsServer` for why this is fatal rather than
        // a degraded mode.
        let dns_server = give_back!(
            proxy,
            first_dns_ipv4(&config.dns).ok_or(TunnelError::NoDnsServer)
        );

        let session = give_back!(proxy, Session::start(&config));
        // The decoded keys now live inside boringtun, which zeroizes its
        // own copies on drop. These base64 Strings are the last plaintext
        // copies this crate holds, and nothing below reads them -- so wipe
        // them here rather than letting the config drop unwiped at return.
        config.private_key_b64.zeroize();
        if let Some(psk) = config.preshared_key_b64.as_mut() {
            psk.zeroize();
        }
        let stack = give_back!(proxy, Stack::new(address, Some(dns_server)));

        // Validation passed. The SAME socket the engine is already pointing
        // at moves from the refuse thread to the real accept loop.
        let (listener, socks_port) = proxy.into_listener();

        let shutdown = Arc::new(AtomicBool::new(false));
        let status = Arc::new(AtomicU8::new(TunnelStatus::Connecting as u8));
        let (accepted_tx, accepted_rx) = mpsc::sync_channel::<TcpStream>(ACCEPT_QUEUE);

        // Past the handover: the listener now belongs to the accept loop,
        // so there is no BoundProxy left to hand back. A spawn failure here
        // leaves the port bound by `listener` until this frame unwinds --
        // it is never released while the engine still holds the number.
        let accept_thread = match thread::Builder::new()
            .name("patanyx-tunnel-accept".into())
            .spawn({
                let shutdown = shutdown.clone();
                move || socks::accept_loop(listener, accepted_tx, shutdown)
            }) {
            Ok(handle) => handle,
            Err(e) => return Err(FailedStart::without_proxy(e.into())),
        };

        let core = Core {
            session,
            stack,
            clients: Vec::new(),
            accepted: accepted_rx,
            on_event: Box::new(on_event),
            shutdown: shutdown.clone(),
            status: status.clone(),
        };
        let core_thread = match thread::Builder::new()
            .name("patanyx-tunnel-core".into())
            .spawn(move || core.run())
        {
            Ok(handle) => handle,
            Err(e) => {
                // The accept thread is already running; a leaked thread
                // holding a live listener is exactly the "nothing is left
                // behind" promise broken.
                shutdown.store(true, Ordering::SeqCst);
                let _ = accept_thread.join();
                return Err(FailedStart::without_proxy(e.into()));
            }
        };

        Ok(Self {
            shutdown,
            status,
            socks_port,
            accept_thread: Some(accept_thread),
            core_thread: Some(core_thread),
        })
    }

    /// The loopback port the SOCKS5 listener is bound to.
    pub fn local_socks_port(&self) -> u16 {
        self.socks_port
    }

    /// Last state the core published. Never blocks on the core.
    pub fn status(&self) -> TunnelStatus {
        match self.status.load(Ordering::SeqCst) {
            1 => TunnelStatus::Up,
            2 => TunnelStatus::Down,
            _ => TunnelStatus::Connecting,
        }
    }

    /// Signals every thread the tunnel owns and joins them. Blocks briefly
    /// (one core tick plus one accept-loop sleep at most).
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(core) = self.core_thread.take() {
            let _ = core.join();
        }
        if let Some(accept) = self.accept_thread.take() {
            let _ = accept.join();
        }
    }
}

impl Drop for Tunnel {
    /// Dropping without `shutdown()` still leaves nothing behind: the
    /// handles are ours, so Drop can join rather than merely signal.
    /// `shutdown()` remains the polite path because it says so in the API.
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(core) = self.core_thread.take() {
            let _ = core.join();
        }
        if let Some(accept) = self.accept_thread.take() {
            let _ = accept.join();
        }
    }
}

/// Everything the core thread owns. All of it dies with `run()`'s stack.
struct Core {
    session: Session,
    stack: Stack,
    clients: Vec<Client>,
    accepted: Receiver<TcpStream>,
    on_event: Box<dyn Fn(TunnelEvent) + Send>,
    shutdown: Arc<AtomicBool>,
    status: Arc<AtomicU8>,
}

impl Core {
    fn run(mut self) {
        let mut inbound: VecDeque<Vec<u8>> = VecDeque::new();
        let mut events: Vec<TunnelEvent> = Vec::new();
        while !self.shutdown.load(Ordering::SeqCst) {
            // 1. UDP -> WireGuard -> IP packets, fed into the stack.
            self.session.poll(&mut inbound, &mut events);
            while let Some(packet) = inbound.pop_front() {
                self.stack.feed(packet);
            }

            // 2. Drive TCP/IP; whatever the stack emits goes back through
            //    WireGuard. There is no other egress anywhere in this loop.
            self.stack.poll();
            while let Some(packet) = self.stack.pop_outbound() {
                self.session.send_packet(&packet, &mut events);
            }

            // 3. Handshake retries and keepalives (self-gated to ~250 ms).
            self.session.tick_timers(&mut events);

            // 4. New loopback clients. Bounded twice: the channel, and this
            //    cap. Over the cap the stream is dropped, not queued.
            while let Ok(stream) = self.accepted.try_recv() {
                if self.clients.len() < socks::MAX_CLIENTS {
                    self.clients.push(Client::new(stream));
                }
            }

            // 5. SOCKS handshakes and byte relaying. `is_up()` is the
            //    fail-closed gate; see the comment in socks.rs.
            let up = self.session.is_up();
            let mut i = 0;
            while i < self.clients.len() {
                match self.clients[i].step(&mut self.stack, up) {
                    Step::Keep => i += 1,
                    Step::Remove => {
                        self.clients.swap_remove(i);
                    }
                }
            }

            // 6. Publish transitions, then report them.
            for event in events.drain(..) {
                match event {
                    TunnelEvent::Up => self.status.store(TunnelStatus::Up as u8, Ordering::SeqCst),
                    TunnelEvent::PeerUnreachable | TunnelEvent::Down(_) => {
                        self.status.store(TunnelStatus::Down as u8, Ordering::SeqCst)
                    }
                    // Still Connecting, and still retrying -- the event is
                    // the signal, the state stays honest about the retrying.
                    TunnelEvent::HandshakeFailed => {}
                }
                (self.on_event)(event);
            }

            thread::sleep(CORE_TICK);
        }
        // Shutdown is deliberate, not a failure: no Down event is emitted.
        // Every socket here is closed by being dropped.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Instant;

    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519::{PublicKey, StaticSecret};
    use smoltcp::wire::Ipv4Cidr;

    /// Test-only base64 ENCODER (the crate itself only needs the decoder).
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

    const CLIENT_PRIV: [u8; 32] = [1u8; 32];
    const SERVER_PRIV: [u8; 32] = [2u8; 32];

    fn public_of(private: &[u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(*private)).as_bytes()
    }

    fn client_config(endpoint: String) -> TunnelConfig {
        TunnelConfig {
            private_key_b64: b64_encode(&CLIENT_PRIV),
            peer_public_key_b64: b64_encode(&public_of(&SERVER_PRIV)),
            endpoint,
            preshared_key_b64: None,
            // Short keepalive so keepalive packets double as dead-peer
            // probes and the peer-death test runs in seconds, not minutes.
            keepalive_secs: Some(1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            dns: vec!["10.99.0.1".into()],
            address: vec!["10.99.0.2/32".into()],
        }
    }

    /// A closed loopback UDP port: a peer that can never answer.
    fn dead_endpoint() -> String {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        format!("127.0.0.1:{port}")
    }

    /// The least machinery that genuinely exercises
    /// SOCKS5 -> smoltcp -> WireGuard encapsulation -> UDP -> peer and back:
    /// a second `Tunn` with swapped keys, the crate's own `Stack` as the
    /// peer's TCP/IP, and a smoltcp listen socket echoing on 10.99.0.1:7.
    struct EchoPeer {
        port: u16,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl EchoPeer {
        fn start() -> Self {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            udp.set_nonblocking(true).unwrap();
            let port = udp.local_addr().unwrap().port();
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            let client_public = public_of(&CLIENT_PRIV);
            let thread = thread::spawn(move || {
                let mut tunn = Tunn::new(
                    StaticSecret::from(SERVER_PRIV),
                    PublicKey::from(client_public),
                    None,
                    None,
                    9,
                    None,
                );
                let cidr: Ipv4Cidr = "10.99.0.1/32".parse().unwrap();
                let mut stack = Stack::new(cidr, None).unwrap();
                let echo = stack.tcp_listen(7).unwrap();
                let mut peer: Option<SocketAddr> = None; // learned from the first datagram
                let mut last_timers = Instant::now();
                while !stop2.load(Ordering::SeqCst) {
                    let mut buf = [0u8; 4096];
                    if let Ok((n, src)) = udp.recv_from(&mut buf) {
                        peer = Some(src);
                        let mut decapsulated: Vec<Vec<u8>> = Vec::new();
                        {
                            let mut dst = [0u8; 4096];
                            match tunn.decapsulate(None, &buf[..n], &mut dst) {
                                TunnResult::WriteToNetwork(p) => {
                                    let _ = udp.send_to(p, src);
                                }
                                TunnResult::WriteToTunnelV4(p, _) => {
                                    decapsulated.push(p.to_vec())
                                }
                                _ => {}
                            }
                        }
                        loop {
                            let mut dst = [0u8; 4096];
                            match tunn.decapsulate(None, &[], &mut dst) {
                                TunnResult::WriteToNetwork(p) => {
                                    let _ = udp.send_to(p, src);
                                }
                                TunnResult::WriteToTunnelV4(p, _) => {
                                    decapsulated.push(p.to_vec())
                                }
                                _ => break,
                            }
                        }
                        for packet in decapsulated {
                            stack.feed(packet);
                        }
                    }
                    stack.poll();
                    {
                        let socket = stack.tcp(echo);
                        if socket.can_recv() {
                            let mut data = [0u8; 4096];
                            if let Ok(n) = socket.recv_slice(&mut data) {
                                if n > 0 {
                                    let _ = socket.send_slice(&data[..n]);
                                }
                            }
                        }
                    }
                    while let Some(packet) = stack.pop_outbound() {
                        if let Some(src) = peer {
                            let mut dst = [0u8; 2048];
                            if let TunnResult::WriteToNetwork(p) =
                                tunn.encapsulate(&packet, &mut dst)
                            {
                                let _ = udp.send_to(p, src);
                            }
                        }
                    }
                    if last_timers.elapsed() >= Duration::from_millis(250) {
                        last_timers = Instant::now();
                        if let Some(src) = peer {
                            loop {
                                let mut dst = [0u8; 4096];
                                match tunn.update_timers(&mut dst) {
                                    TunnResult::WriteToNetwork(p) => {
                                        let _ = udp.send_to(p, src);
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            });
            Self { port, stop, thread: Some(thread) }
        }

        fn stop(mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn collect_events() -> (impl Fn(TunnelEvent) + Send, Receiver<TunnelEvent>) {
        let (tx, rx) = mpsc::channel();
        (move |e| { let _ = tx.send(e); }, rx)
    }

    fn wait_for_up(rx: &Receiver<TunnelEvent>) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(TunnelEvent::Up) => return,
                Ok(TunnelEvent::HandshakeFailed) => panic!("handshake failed against a live peer"),
                Ok(_) => continue,
                Err(e) => panic!("the tunnel never came up: {e}"),
            }
        }
    }

    fn socks_greeting(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00], "NO AUTH must be accepted");
    }

    fn connect_request_v4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut v = vec![0x05, 0x01, 0x00, 0x01];
        v.extend_from_slice(&ip.octets());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    fn read_socks_reply(stream: &mut TcpStream) -> [u8; 10] {
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).unwrap();
        reply
    }

    #[test]
    fn a_config_with_no_usable_ipv4_address_is_refused_at_start() {
        for address in [
            vec!["fd00::1/128".to_string(), "not-an-address".to_string()],
            Vec::new(),
        ] {
            let mut config = client_config(dead_endpoint());
            config.address = address;
            match Tunnel::start(config, |_| {}) {
                Err(TunnelError::NoIpv4Address) => {}
                Err(e) => panic!("expected NoIpv4Address, got {e}"),
                Ok(_) => panic!("a tunnel with no IPv4 address must not start"),
            }
        }
    }

    #[test]
    fn a_failed_start_hands_the_port_back_still_refusing() {
        // THE fail-closed invariant of the handover, and the one the first
        // version broke: on failure the caller's port must still be bound
        // and still refusing. The engine took that number at startup and
        // cannot be told another one, so releasing it would let any local
        // process bind it and become the browser's proxy.
        let proxy = Tunnel::bind_proxy().expect("bind");
        let port = proxy.port();
        let mut config = client_config(dead_endpoint());
        config.address = vec!["fd00::1/128".into()]; // refused: no IPv4
        let failed = match Tunnel::start_on(proxy, config, |_| {}) {
            Err(failed) => failed,
            Ok(_) => panic!("a tunnel with no IPv4 address must not start"),
        };
        assert!(matches!(failed.error, TunnelError::NoIpv4Address));
        let returned = failed.proxy.expect("the proxy must be handed back");
        assert_eq!(returned.port(), port, "and it must be the SAME port");
        // Still refusing, not merely still bound: connect and prove nobody
        // answers a greeting.
        let mut stream =
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("still bound");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = stream.write_all(&[0x05, 0x01, 0x00]);
        let mut byte = [0u8; 1];
        // Same discipline as `bound_proxy_accepts_and_immediately_closes`:
        // a clean close or a reset are both the refusal; a TIMEOUT means
        // the connection was held open, and any byte means it was served.
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                panic!("the handed-back proxy held the connection open")
            }
            Err(_) => {}
            Ok(n) => panic!("the handed-back proxy served {n} bytes instead of refusing"),
        }
        drop(returned);
        assert!(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
            "and dropping it releases the port, once the caller says so"
        );
    }

    #[test]
    fn a_config_with_no_usable_dns_server_is_refused_before_it_can_lie() {
        // A tunnel with no in-tunnel resolver handshakes, reports Up and
        // answers the liveness probe -- while refusing every DOMAIN CONNECT
        // the browser makes, which is all of them. "Healthy and loads
        // nothing" is the worst state this feature can be in, so it is
        // refused at start where the panel can name the reason.
        let proxy = Tunnel::bind_proxy().expect("bind");
        let mut config = client_config(dead_endpoint());
        config.dns = vec!["fd00::53".into()]; // v6-only: unusable here
        match Tunnel::start_on(proxy, config, |_| {}) {
            Err(failed) => assert!(matches!(failed.error, TunnelError::NoDnsServer)),
            Ok(_) => panic!("a tunnel that could never resolve must not start"),
        }
        let proxy = Tunnel::bind_proxy().expect("bind");
        let mut config = client_config(dead_endpoint());
        config.dns = Vec::new(); // the hand-written `wg genkey` shape
        match Tunnel::start_on(proxy, config, |_| {}) {
            Err(failed) => assert!(matches!(failed.error, TunnelError::NoDnsServer)),
            Ok(_) => panic!("a config with no DNS line at all must not start"),
        }
    }

    #[test]
    fn the_first_usable_ipv4_address_wins_and_junk_is_skipped() {
        let mut config = client_config(dead_endpoint());
        config.address = vec!["junk".into(), "fc00::9/128".into(), "10.99.0.2/32".into()];
        let tunnel = Tunnel::start(config, |_| {}).expect("starts with a usable address");
        tunnel.shutdown();
    }

    #[test]
    fn bound_proxy_binds_a_loopback_port_and_reports_it() {
        let proxy = Tunnel::bind_proxy().expect("bind");
        let local = proxy
            .listener
            .as_ref()
            .expect("listener parked")
            .local_addr()
            .expect("addr");
        assert!(local.ip().is_loopback(), "the proxy must be loopback-only");
        assert_ne!(proxy.port(), 0, "an ephemeral bind must yield a real port");
        assert_eq!(proxy.port(), local.port());
    }

    #[test]
    fn bound_proxy_accepts_and_immediately_closes() {
        let proxy = Tunnel::bind_proxy().expect("bind");
        let mut stream =
            TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).expect("connect");
        // A regression to "accept and hold" must fail this test, not hang
        // the suite.
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            // Clean close (Ok(0)) or a reset: the refused request the
            // fail-closed design wants the engine to see.
            Ok(0) => {}
            // A TIMEOUT is a held-open connection, which is exactly the
            // regression this test exists to catch -- the first version
            // accepted every Err and would have passed on it (independent
            // review, MEDIUM). Timeouts surface as WouldBlock or TimedOut
            // depending on platform; both mean "nobody closed us".
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                panic!("the refuse listener held the connection open")
            }
            Err(_) => {}
            Ok(n) => panic!("a refuse listener sent {n} bytes"),
        }
    }

    #[test]
    fn dropped_bound_proxy_leaves_the_port_refusing() {
        // The temporary drops at the end of this statement.
        let port = Tunnel::bind_proxy().expect("bind").port();
        // Dropping closed the listener AND joined the refuse thread -- and
        // the thread's own clone of the socket kept the port open until the
        // join, so a refused connect here proves the thread is really gone,
        // not merely that the original handle closed.
        assert!(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
            "a dropped BoundProxy left something accepting on {port}"
        );
    }

    #[test]
    fn start_on_serves_socks_on_the_port_the_bound_proxy_reported() {
        let proxy = Tunnel::bind_proxy().expect("bind");
        let port = proxy.port();
        // A dead endpoint on purpose: the session stays in Connecting, and
        // the SOCKS method reply comes before any CONNECT and therefore
        // before any handshake state matters -- which is exactly what lets
        // this test prove the listener is the tunnel's SOCKS front without
        // standing up a peer.
        let tunnel =
            Tunnel::start_on(proxy, client_config(dead_endpoint()), |_event| {}).expect("start_on");
        assert_eq!(
            tunnel.local_socks_port(),
            port,
            "the tunnel must keep the port the engine was told about"
        );

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).expect("method reply");
        assert_eq!(reply, [0x05, 0x00], "SOCKS5 must accept NO AUTH");
        tunnel.shutdown();
    }

    #[test]
    fn a_socks5_connect_echoes_through_a_loopback_wireguard_peer() {
        let peer = EchoPeer::start();
        let (on_event, events) = collect_events();
        let tunnel = Tunnel::start(client_config(format!("127.0.0.1:{}", peer.port)), on_event)
            .expect("tunnel starts");
        wait_for_up(&events);
        assert_eq!(tunnel.status(), TunnelStatus::Up);

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port()))
            .expect("loopback connect");
        socks_greeting(&mut stream);
        stream
            .write_all(&connect_request_v4(Ipv4Addr::new(10, 99, 0, 1), 7))
            .unwrap();
        let reply = read_socks_reply(&mut stream);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00, "CONNECT must succeed through an established tunnel");

        let payload = b"hello wireguard";
        stream.write_all(payload).unwrap();
        let mut echoed = [0u8; 15];
        stream.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, payload);

        drop(stream);
        tunnel.shutdown();
        peer.stop();
    }

    #[test]
    fn a_connect_is_refused_when_the_session_never_came_up() {
        let tunnel = Tunnel::start(client_config(dead_endpoint()), |_| {}).expect("starts");
        assert_eq!(tunnel.status(), TunnelStatus::Connecting);

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port()))
            .expect("loopback connect");
        socks_greeting(&mut stream);
        let asked = Instant::now();
        stream
            .write_all(&connect_request_v4(Ipv4Addr::new(10, 99, 0, 1), 7))
            .unwrap();
        let reply = read_socks_reply(&mut stream);
        assert_eq!(reply[0], 0x05);
        assert_eq!(
            reply[1], 0x01,
            "with no session the CONNECT must be refused with general failure"
        );
        // PLANTED-DEFECT CONTROL: this test proves the fail-closed gate --
        // the `if !up` check in `Client::step_request` in socks.rs. The
        // reply code alone is NOT the proof: with the gate deleted the
        // request proceeds to `stack.tcp_connect`, times out after
        // CONNECT_TIMEOUT (10s) and STILL replies 0x01 -- measured when the
        // defect was actually planted. What distinguishes the gate is that
        // its refusal is immediate; hence the time bound.
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "the refusal must come from the gate (immediate), not from a \
             connect timeout wearing the same reply code"
        );
        tunnel.shutdown();
    }

    #[test]
    fn new_connects_are_refused_after_the_peer_dies() {
        let peer = EchoPeer::start();
        let (on_event, events) = collect_events();
        let tunnel = Tunnel::start(client_config(format!("127.0.0.1:{}", peer.port)), on_event)
            .expect("starts");
        wait_for_up(&events);

        // Sanity: one working CONNECT first, so "refused later" means something.
        {
            let mut stream =
                TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port())).unwrap();
            socks_greeting(&mut stream);
            stream
                .write_all(&connect_request_v4(Ipv4Addr::new(10, 99, 0, 1), 7))
                .unwrap();
            assert_eq!(read_socks_reply(&mut stream)[1], 0x00);
        }

        peer.stop(); // the peer's UDP port closes; keepalives now hit a wall

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(TunnelEvent::PeerUnreachable) => break,
                Ok(_) => continue,
                Err(e) => panic!("a dead peer was not detected: {e}"),
            }
        }
        assert_eq!(tunnel.status(), TunnelStatus::Down);

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port()))
            .expect("the listener itself is still alive");
        socks_greeting(&mut stream);
        let asked = Instant::now();
        stream
            .write_all(&connect_request_v4(Ipv4Addr::new(10, 99, 0, 1), 7))
            .unwrap();
        assert_eq!(
            read_socks_reply(&mut stream)[1],
            0x01,
            "after the peer dies, NEW connects must be refused"
        );
        // PLANTED-DEFECT CONTROL: same gate as the never-came-up test, and
        // the same time bound for the same measured reason -- with the gate
        // deleted this reply still arrives as 0x01, just after the 10s
        // connect timeout, and whether the client's own 10s read timeout
        // fired first was a coin flip when the defect was planted. The
        // pre-death CONNECT above is the control proving the tunnel really
        // was up before it was refused.
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "the refusal must come from the gate (immediate), not from a \
             connect timeout wearing the same reply code"
        );
        tunnel.shutdown();
    }

    #[test]
    fn shutdown_joins_every_thread_and_start_can_be_repeated() {
        for round in 0..2 {
            let tunnel = Tunnel::start(client_config(dead_endpoint()), |_| {}).expect("starts");
            let port = tunnel.local_socks_port();
            assert!(
                TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok(),
                "round {round}: the listener accepts before shutdown"
            );
            tunnel.shutdown(); // returns => both threads were joined
            assert!(
                TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
                "round {round}: after shutdown the listener (and its thread) must be gone"
            );
            // NOTE ON PROOF STRENGTH: `shutdown()` joining is a property of
            // its code (it owns the only JoinHandles); this test proves the
            // observable half -- no hang, no surviving listener, and a clean
            // second start in the same process.
        }
    }

    #[test]
    fn ipv6_targets_get_the_rfc_1928_address_type_reply() {
        let tunnel = Tunnel::start(client_config(dead_endpoint()), |_| {}).expect("starts");
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port()))
            .unwrap();
        socks_greeting(&mut stream);
        let mut request = vec![0x05, 0x01, 0x00, 0x04];
        request.extend_from_slice(&[0u8; 16]); // ::1-ish; content irrelevant
        request.extend_from_slice(&7u16.to_be_bytes());
        stream.write_all(&request).unwrap();
        assert_eq!(read_socks_reply(&mut stream)[1], 0x08, "ATYP IPv6 -> 0x08");
        tunnel.shutdown();
    }

    #[test]
    fn non_connect_commands_get_the_command_not_supported_reply() {
        let tunnel = Tunnel::start(client_config(dead_endpoint()), |_| {}).expect("starts");
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port()))
            .unwrap();
        socks_greeting(&mut stream);
        // UDP ASSOCIATE (0x03) toward 10.0.0.1:53.
        stream
            .write_all(&[0x05, 0x03, 0x00, 0x01, 10, 0, 0, 1, 0, 53])
            .unwrap();
        assert_eq!(read_socks_reply(&mut stream)[1], 0x07, "CMD != CONNECT -> 0x07");
        tunnel.shutdown();
    }

    #[test]
    fn a_greeting_without_no_auth_gets_no_acceptable_methods() {
        let tunnel = Tunnel::start(client_config(dead_endpoint()), |_| {}).expect("starts");
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel.local_socks_port()))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(&[0x05, 0x01, 0x02]).unwrap(); // offers only GSSAPI
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0xFF]);
        // ... and then the server must hang up.
        let mut one = [0u8; 1];
        assert!(stream.read_exact(&mut one).is_err(), "no-auth refusal ends the connection");
        tunnel.shutdown();
    }
}
