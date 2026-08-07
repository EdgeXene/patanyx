//! The client transport: discovery, direct LAN links, the relay connection,
//! and session bookkeeping, behind one channel-driven API.
//!
//! Architecture (per the project decision: synchronous client, dedicated
//! threads, no Tokio):
//!
//!   * ONE core thread owns all mutable state (sessions, pendings, links,
//!     peers). Nothing else touches it, so there are no locks in the design.
//!   * Helper threads (mDNS, LAN listener, per-link reader/writer, relay
//!     connection, dialers) only send messages INTO the core over bounded
//!     channels, exactly matching the app's callback pattern.
//!   * The core invokes `on_event` for everything the app needs to know; the
//!     app forwards those into its GUI event loop and mutates state there.
//!   * `Transport::shutdown` joins every thread. No detached threads.
//!
//! BOUNDED CHANNELS ONLY: every channel below is small, and overflow CLOSES
//! the connection it belongs to. Never "fix" dropped frames by enlarging or
//! unbounding a queue — buffering is the one change that would make "nothing
//! is stored" false in code rather than policy, and it must not happen here
//! any more than on the relay.
//!
//! MULTI-IDENTITY: the transport holds a SET of identities, one X25519
//! keypair per contact, so the fingerprint a contact is given belongs to them
//! alone and cannot be correlated with the fingerprint anyone else sees.
//! Every identity's fingerprint is announced on the LAN at once — that is a
//! deliberate decision, not an oversight: LAN observers are physically
//! present and already know the user is there, so co-announcement tells them
//! almost nothing. A RELAY is different (co-announcement would let a remote
//! party link the identities), which is why the relay is given exactly ONE
//! identity: the one named in `TransportConfig::relay` (`RelayConfig::
//! identity`), chosen deliberately by the user. Naming an identity the
//! transport does not hold fails closed with `ChatError::UnknownIdentity`;
//! no other key is ever substituted, and removing that identity tears its
//! relay registration down with it. Inbound handshakes are answered ONLY by
//! the identity whose fingerprint the peer dialed; an unknown fingerprint is
//! refused, because answering with a different key would hand the contact an
//! address they were never given — the exact linkage the per-contact model
//! exists to prevent.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use x25519_dalek::PublicKey;

use crate::discovery::{self, Discovery, DiscoveryEvent, DiscoveryState};
use crate::envelope::{self, MessageId, SessionEnvelope};
use crate::relay_client::{RelayClient, RelayEvent};
use crate::wire::{ErrorCode, Frame, FrameKind};
use crate::{
    decode_incoming, validate_outgoing, ChatError, Fingerprint, Handshake, Identity, Pending,
    Role, Session, FINGERPRINT_LEN,
};

/// See the module docs: all bounded, all close-on-overflow.
const CORE_QUEUE: usize = 256;
const LINK_QUEUE: usize = 32;
const DISCOVERY_QUEUE: usize = 64;
const RELAY_QUEUE: usize = 64;

/// A brand-new direct link must identify itself (first frame) within this
/// window; after the first frame the read timeout is lifted.
const LINK_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Relay connection settings: the server URL and THE ONE identity to
/// register. Kept as a single `Option<RelayConfig>` in `TransportConfig` so
/// that "a relay URL without a chosen identity" is unrepresentable — that
/// state previously caused the transport to register an ARBITRARY identity
/// (randomized `HashMap` iteration order), so which of the user's
/// per-contact addresses a remote relay could see, and link to one
/// connection, changed on every run. That is the privacy bug this type
/// exists to make impossible.
pub struct RelayConfig {
    /// `wss://host[:port]/path` of the relay. TLS is mandatory client-side.
    pub url: String,
    /// The fingerprint of the identity — out of `TransportConfig::
    /// identities` — to register. Exactly one, always deliberate: a remote
    /// relay can link every fingerprint it sees on a connection (and to one
    /// IP), so registering the whole per-contact set would defeat the
    /// unlinkability those keys exist for.
    pub identity: Fingerprint,
}

pub struct TransportConfig {
    /// This instance's identities: one keypair per contact, plus optionally a
    /// long-term and an ephemeral one (vault storage and selection live in
    /// the app, out of scope here). ALL of their fingerprints are announced
    /// over mDNS — see the module docs for why co-announcement is acceptable
    /// on a LAN and why the relay is treated differently. May be empty: the
    /// transport then announces nothing and refuses all sessions until
    /// `add_identity` is called.
    pub identities: Vec<Identity>,
    /// The relay connection, or None for LAN-only operation. No relay is
    /// ever contacted when this is None; when it is Some, exactly the named
    /// identity is registered (see `RelayConfig`), and `Transport::start`
    /// fails closed if that identity is not among `identities`.
    pub relay: Option<RelayConfig>,
    /// The 90 licence-token wire bytes carried into relay registration
    /// (P3, design 4.1). Opaque to the transport. `None` until the app
    /// wires the vault read (chat_panel); with relay enforcement
    /// config-gated off, `None` changes nothing on the wire.
    pub relay_token: Option<Vec<u8>>,
    /// Port for the direct LAN listener; 0 picks an ephemeral port (the
    /// announced port is always the actually-bound one).
    pub lan_port: u16,
    /// Looks up the expected static public key for a contact. This is what
    /// turns an anonymous exchange into an authenticated one (see
    /// `Pending::complete`). Called ON THE CORE THREAD: it must be cheap and
    /// non-blocking (e.g. a read from an `Arc<Mutex<HashMap>>` the app keeps).
    /// Returning None yields an unauthenticated session and the app MUST show
    /// the fingerprint for out-of-band comparison (`verified: false` on the
    /// event).
    ///
    /// Note: this callback shape is a guess at what AppState integration
    /// will want. If the app would rather be asked via an event + reply
    /// command, replace it — the crypto call sites are `complete_pending` and
    /// `become_responder` below.
    pub expected_peer_key: Option<Box<dyn Fn(Fingerprint) -> Option<[u8; 32]> + Send + Sync>>,
}

#[derive(Debug)]
pub enum TransportEvent {
    PeerAppeared {
        fingerprint: Fingerprint,
        addr: SocketAddr,
        version: u16,
        /// True only once a handshake at this address proved control of the
        /// key behind `fingerprint`. mDNS alone can never set this: it is an
        /// unauthenticated hint, and treating it as presence is what let any
        /// LAN host claim a victim's fingerprint.
        verified: bool,
    },
    PeerDisappeared {
        fingerprint: Fingerprint,
    },
    DiscoveryState(DiscoveryState),
    /// One identity could not be announced on the LAN. Discovery as a whole is
    /// still up and every other identity is still reachable; only this address
    /// is invisible. Reported per-identity rather than collapsed into
    /// `DiscoveryState::Unavailable` because per-contact keypairs exist so that
    /// one contact breaking costs exactly that contact.
    IdentityNotAnnounced {
        fingerprint: Fingerprint,
    },
    RelayUp,
    RelayDown,
    /// A connection-level error reported by the relay (e.g. it rejected one of
    /// our frames). Never about message contents.
    RelayError(ErrorCode),
    SessionEstablished {
        peer: Fingerprint,
        /// The peer's static public key, for displaying its hash number when
        /// `verified` is false (new contact: compare out of band).
        peer_identity: [u8; 32],
        /// True when `expected_peer_key` authenticated the peer; false means
        /// anonymous and MUST be confirmed by comparing fingerprints.
        verified: bool,
    },
    SessionFailed {
        peer: Fingerprint,
        error: ChatError,
    },
    Message {
        from: Fingerprint,
        text: String,
    },
    /// An inbound frame was dropped: undecryptable, replayed, oversized, or
    /// for a peer we have no session with. The session itself survives.
    MessageDropped {
        from: Fingerprint,
        error: ChatError,
    },
    SendFailed {
        to: Fingerprint,
        reason: SendFailure,
    },
    /// What one message may now claim about itself. Emitted on every
    /// transition, so the UI never has to infer a state it was not told.
    Delivery {
        to: Fingerprint,
        mid: MessageId,
        state: Delivery,
    },
    /// The session survives but has no route right now. Emitted so the app
    /// stops believing a cached "connected" flag that link death never
    /// cleared — the flag that let a send pass through onto a route which no
    /// longer existed.
    SessionUnreachable {
        peer: Fingerprint,
    },
    /// A route exists again for a session that had none.
    SessionReachable {
        peer: Fingerprint,
    },
    /// The network is announcing more addresses than can be tracked, so some
    /// were refused and a contact may not appear. Rate-limited; see
    /// `note_candidates_capped`.
    CandidatesCapped,
}

/// What a message is ALLOWED to claim about its own delivery.
///
/// Same discipline as `FreezeEnforcement` in the browser's privacy layer:
/// what was ASKED for and what was CONFIRMED are different facts and never
/// share a field. There, only a confirmed engine filter may claim a tab is
/// making no requests. Here, only an `Ack` that opened under the peer's
/// session key may claim Delivered — and a relay holds neither key, so it
/// can neither forge one nor strip one unnoticed.
///
/// The rule, stated once: an AUTHENTICATED frame may move a message forward.
/// An unauthenticated signal — a relay refusal, a dead socket, a timer — may
/// only move it backward. A message that has proved nothing stays `Sending`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Sealed and handed to a route. Proves nothing about arrival, and is
    /// the only state a sender may claim unaided.
    Sending,
    /// The peer's own key acknowledged this exact message id. Terminal.
    ///
    /// Delivered to a DEVICE. Not read, not seen by a person; there is no
    /// read receipt and its absence is deliberate.
    Delivered,
    /// It did not arrive, for the recorded reason. Terminal.
    Failed(SendFailure),
}

impl Delivery {
    /// The wire/UI spelling. Deliberately not `Display`, so adding a variant
    /// forces a decision here rather than silently producing a string the
    /// chrome has no case for.
    pub fn as_str(self) -> &'static str {
        match self {
            Delivery::Sending => "sending",
            Delivery::Delivered => "delivered",
            Delivery::Failed(_) => "failed",
        }
    }

    /// Terminal states are never revised. A late refusal after an ack does
    /// not un-deliver a message: the ack is proof and the refusal is most
    /// likely answering a retry of something already delivered.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Delivery::Sending)
    }
}

/// Why a send did not arrive. The cause is not decoration: the UI used to
/// report every failure as "they are not on this network right now — nothing
/// was sent and nothing is waiting", including when we had just closed a
/// working link to a peer who was demonstrably present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendFailure {
    /// No route of any kind. Nothing was sent, nothing is waiting.
    Offline,
    /// No session with this peer; call `open_session` first.
    NoSession,
    /// Handed to a route that then died with it in flight.
    LinkLost,
    /// The relay refused this message. It does not say why, on purpose:
    /// offline, congested and wedged are indistinguishable so that nobody
    /// can probe a fingerprint's connection health.
    Refused,
    /// Sent, retried to the limit, never acknowledged.
    NoAck,
    /// The session ended with this message in flight.
    SessionEnded,
    /// Too many messages are already awaiting acknowledgement. A bound, not
    /// a queue — see `MAX_OUTSTANDING_PER_SESSION`.
    TooManyOutstanding,
}

impl SendFailure {
    /// Stable codes; the app maps these to user-facing copy and the mapping
    /// must stay one-to-one so no cause borrows another's wording.
    pub fn as_str(self) -> &'static str {
        match self {
            SendFailure::Offline => "peer_offline",
            SendFailure::NoSession => "no_session",
            SendFailure::LinkLost => "link_lost",
            SendFailure::Refused => "refused",
            SendFailure::NoAck => "no_ack",
            SendFailure::SessionEnded => "session_ended",
            SendFailure::TooManyOutstanding => "too_many_outstanding",
        }
    }
}

enum Command {
    AddIdentity { identity: Identity },
    RemoveIdentity { fingerprint: Fingerprint },
    OpenSession { our: Fingerprint, peer: Fingerprint },
    SendText {
        peer: Fingerprint,
        text: String,
        mid: MessageId,
    },
    CloseSession { peer: Fingerprint },
    Shutdown,
}

enum CoreMsg {
    Command(Command),
    ListenerAccepted { stream: TcpStream },
    OutboundConnected {
        peer: Fingerprint,
        result: Result<TcpStream, ChatError>,
    },
    LinkFrame { id: u64, frame: Frame },
    LinkDead { id: u64 },
}

/// The handle the app keeps. Methods only validate and enqueue; everything the
/// transport does back arrives through the `on_event` callback.
pub struct Transport {
    core_tx: SyncSender<CoreMsg>,
    shutdown: Arc<AtomicBool>,
    core: Option<JoinHandle<()>>,
}

impl Transport {
    pub fn start(
        config: TransportConfig,
        on_event: impl Fn(TransportEvent) + Send + 'static,
    ) -> Result<Self, ChatError> {
        // Validate the relay choice BEFORE anything is bound or spawned:
        // naming an identity the transport does not hold fails closed, and it
        // fails HERE so the error leaves nothing behind (no listener, no
        // announcement, no threads). Without the relay client compiled in,
        // the relay config is inert by design — the app reports that itself.
        #[cfg(feature = "relay-client")]
        if let Some(relay) = &config.relay {
            if !config
                .identities
                .iter()
                .any(|identity| identity.fingerprint() == relay.identity)
            {
                return Err(ChatError::UnknownIdentity);
            }
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let (core_tx, core_rx) = mpsc::sync_channel::<CoreMsg>(CORE_QUEUE);
        let (disc_tx, disc_rx) = mpsc::sync_channel::<DiscoveryEvent>(DISCOVERY_QUEUE);
        let (relay_tx, relay_rx) = mpsc::sync_channel::<RelayEvent>(RELAY_QUEUE);

        let mut identities = HashMap::new();
        for identity in config.identities {
            // Duplicate fingerprints collapse to one entry; announcing the
            // same key twice would buy nothing.
            identities.insert(identity.fingerprint(), Arc::new(identity));
        }

        // LAN listener. Failure degrades to relay-only operation (discovery is
        // pointless without a port to announce) instead of killing the
        // transport — chat must keep working where local listeners are blocked.
        let mut aux_threads = Vec::new();
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, config.lan_port)).ok();
        // Note: IPv4-only listener; dialing prefers v4 too. Dual-stack
        // LANs work, v6-only LANs don't — revisit if that matters.
        let lan_port = listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port());
        if let Some(listener) = listener {
            listener.set_nonblocking(true).map_err(ChatError::from)?;
            let tx = core_tx.clone();
            let flag = shutdown.clone();
            aux_threads.push(thread::spawn(move || accept_loop(listener, tx, flag)));
        }

        // ONE daemon announcing every identity. `discovery` owns its own
        // shutdown flag, so stopping it can never stop the listener, the relay,
        // or this core.
        let discovery = lan_port.and_then(|port| {
            let fps: Vec<Fingerprint> = identities.keys().copied().collect();
            discovery::start(&fps, port, disc_tx, shutdown.clone()).ok()
        });

        // Relay registration is EXACTLY ONE identity — the one named in
        // `config.relay.identity`, validated above. Never an arbitrary pick
        // (the old `values().next()` was randomized per process: the privacy
        // bug this replaces) and never the whole per-contact set, which a
        // remote relay could link. See `RelayConfig` and the module docs.
        //
        // This is the ONLY place in the transport that knows whether the relay
        // client was compiled in. Everywhere else, `Option<RelayClient>` is
        // simply always `None` in a LAN-only build, because the stub type
        // cannot be constructed.
        #[cfg(feature = "relay-client")]
        let (relay, relay_identity) = match select_relay_identity(&identities, config.relay) {
            Some((url, fingerprint, identity)) => (
                Some(RelayClient::spawn(
                    url,
                    identity,
                    config.relay_token.clone(),
                    relay_tx,
                    shutdown.clone(),
                )),
                Some(fingerprint),
            ),
            // Unreachable for a Some config (validated above); None config is
            // the ordinary LAN-only case.
            None => (None, None),
        };
        #[cfg(not(feature = "relay-client"))]
        let (relay, relay_identity) = {
            // No relay client in this build: a configured relay is ignored
            // rather than silently pretended to work.
            let _ = (&config.relay, &config.relay_token, relay_tx);
            (None, None)
        };

        let core = Core {
            identities,
            discovery,
            discovery_up: true,
            expected_peer_key: config
                .expected_peer_key
                .map(|f| Arc::from(f) as Arc<dyn Fn(Fingerprint) -> Option<[u8; 32]> + Send + Sync>),
            on_event: Box::new(on_event),
            rx: core_rx,
            tx: core_tx.clone(),
            disc_rx,
            relay_rx,
            shutdown: shutdown.clone(),
            sessions: HashMap::new(),
            provisional: HashMap::new(),
            pendings: HashMap::new(),
            lan_peers: HashMap::new(),
            links: HashMap::new(),
            peer_link: HashMap::new(),
            resources: crate::limits::ResourceManager::new(crate::limits::Limits::default()),
            denied_pending: 0,
            dialing: HashMap::new(),
            dial_tried: HashMap::new(),
            relay,
            relay_identity,
            relay_up: false,
            next_link_id: 1,
            link_threads: Vec::new(),
            connector_threads: Vec::new(),
            aux_threads,
            candidates_capped_at: None,
            timings: Timings::default(),
        };
        let handle = thread::spawn(move || core.run());

        Ok(Self {
            core_tx,
            shutdown,
            core: Some(handle),
        })
    }

    /// Adds an identity while running: its fingerprint starts being announced
    /// immediately, so a newly added contact becomes reachable without
    /// restarting the transport or disturbing any live session.
    pub fn add_identity(&self, identity: Identity) -> Result<(), ChatError> {
        self.command(Command::AddIdentity { identity })
    }

    /// Removes an identity: its fingerprint stops being announced and every
    /// session and pending handshake built on it is torn down (the keys die
    /// with the dropped `Session`s). Revoking a contact breaks exactly their
    /// address; every other identity keeps working. If the removed identity
    /// was the one registered with the relay, the relay registration is torn
    /// down too — revoked means gone, on every network.
    pub fn remove_identity(&self, fingerprint: Fingerprint) -> Result<(), ChatError> {
        self.command(Command::RemoveIdentity { fingerprint })
    }

    /// Opens a session to a peer (initiates the handshake) presenting the
    /// identity `our`. The caller MUST name the identity: per-contact
    /// keypairs make "the" identity ambiguous, and guessing wrong would show
    /// the peer a fingerprint they were never given. If `our` is not an
    /// identity the transport holds, the attempt fails closed with
    /// `SessionFailed` — no other key is ever substituted. Other outcomes
    /// arrive as `SessionEstablished`, `SessionFailed`, or `SendFailed`.
    pub fn open_session(&self, our: Fingerprint, peer: Fingerprint) -> Result<(), ChatError> {
        self.command(Command::OpenSession { our, peer })
    }

    /// Validates and queues one text message. Oversized text is refused
    /// synchronously, before it can enter any pipe; delivery failures arrive
    /// as `SendFailed` events.
    /// Sends one message and returns the id its delivery will be reported
    /// under.
    ///
    /// The id is minted HERE, by the caller's thread, so the caller holds a
    /// handle to the message before the core has even seen it. Minting it
    /// inside the core would leave the UI with a bubble it cannot name, and a
    /// bubble that cannot be named cannot be revised -- which is how the old
    /// code ended up drawing a delivered-looking message and never touching
    /// it again.
    ///
    /// Ok means accepted and identified. It does NOT mean sent, and never
    /// means arrived: watch for `TransportEvent::Delivery` for that.
    pub fn send_text(&self, peer: Fingerprint, text: &str) -> Result<MessageId, ChatError> {
        validate_outgoing(text)?;
        let mid = envelope::new_message_id();
        self.command(Command::SendText {
            peer,
            text: text.to_string(),
            mid,
        })?;
        Ok(mid)
    }

    /// Ends the session. The keys are destroyed with the dropped `Session` —
    /// that, and nothing else, is the forward-secrecy mechanism.
    pub fn close_session(&self, peer: Fingerprint) -> Result<(), ChatError> {
        self.command(Command::CloseSession { peer })
    }

    /// Stops every thread the transport owns and joins them. Blocks up to a
    /// few seconds (a relay connect in flight is the slowest case).
    pub fn shutdown(mut self) {
        // The flag is the real signal; the command only shortens the latency,
        // and the send is best-effort because a full queue must not deadlock
        // shutdown either.
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self
            .core_tx
            .try_send(CoreMsg::Command(Command::Shutdown));
        if let Some(core) = self.core.take() {
            let _ = core.join();
        }
    }

    fn command(&self, cmd: Command) -> Result<(), ChatError> {
        self.core_tx
            .send(CoreMsg::Command(cmd))
            .map_err(|_| ChatError::Closed)
    }
}

impl Drop for Transport {
    /// Dropping without `shutdown()` still signals every thread to exit; the
    /// core's teardown does the rest. `shutdown()` is preferred because it
    /// joins rather than detaches.
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self
            .core_tx
            .try_send(CoreMsg::Command(Command::Shutdown));
    }
}

fn accept_loop(listener: TcpListener, core_tx: SyncSender<CoreMsg>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = stream.set_nodelay(true);
                if core_tx.send(CoreMsg::ListenerAccepted { stream }).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            // Transient accept errors (fd pressure, …) must not kill discovery.
            Err(_) => thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// Picks the identity to register with the relay: exactly the one named in
/// the config, or None when no relay is configured or the named identity is
/// not held (`Transport::start` rejects that case before this runs). The old
/// code used `identities.values().next()` — randomized HashMap order — so
/// which of the user's per-contact addresses a remote relay could see (and
/// link to one connection) changed on every run and was never the user's
/// choice. Kept as a pure function so the property is testable without
/// binding sockets.
#[cfg(feature = "relay-client")]
fn select_relay_identity(
    identities: &HashMap<Fingerprint, Arc<Identity>>,
    config: Option<RelayConfig>,
) -> Option<(String, Fingerprint, Arc<Identity>)> {
    config.and_then(|relay| {
        identities
            .get(&relay.identity)
            .cloned()
            .map(|identity| (relay.url, relay.identity, identity))
    })
}

/// What mDNS told us, kept strictly apart from what a handshake PROVED.
///
/// mDNS is unauthenticated. Any host on the LAN can announce any fingerprint
/// at its own address, and the announcement survives the 120s TTL. This used
/// to be one `addr` field that every announcement overwrote, which turned a
/// spoofed record into three separate attacks at once: dials for a victim
/// went to the attacker, the victim's real address was destroyed, and a
/// spoofed goodbye showed a live contact as offline.
///
/// So an announcement is a CANDIDATE ENDPOINT and nothing more. Only a
/// completed handshake — which already proves the peer controls the key
/// behind the fingerprint, see `on_handshake_frame` — promotes an address to
/// `verified`, and only a verified address is treated as the contact being
/// reachable.
struct LanPeer {
    /// Addresses announced for this fingerprint, most recent first.
    ///
    /// SEVERAL, not one, and that is the whole point. A host with more than
    /// one interface -- which is any machine running Docker, a VPN, or IPv6
    /// link-local, i.e. most of them -- announces itself at every address it
    /// has, as separate records arriving over time. Keeping only the latest
    /// meant the dial used whichever happened to arrive last, and if that one
    /// was unreachable the session simply never formed. Measured at one run
    /// in three on an ordinary multi-homed host.
    ///
    /// Still hints, never identity: none of them is evidence the contact is
    /// there, and a handshake is what promotes one to `verified`.
    candidates: VecDeque<SocketAddr>,
    /// An address whose handshake proved control of this fingerprint's key.
    /// A candidate announcement must NEVER overwrite this.
    verified: Option<SocketAddr>,
    #[allow(dead_code)] // carried for the UI's version display; routing ignores it
    version: u16,
    /// Last time this fingerprint was announced. Only used to decide which
    /// candidate a full table may give up; never treated as presence.
    last_seen: Instant,
}

/// Announced addresses remembered per peer. Enough for a well-connected host
/// (loopback, LAN v4, a bridge or two) and bounded against one announcing
/// without end.
const MAX_ADDRS_PER_PEER: usize = 8;

/// Whether an announced address is one we could actually dial.
///
/// mDNS reports every address an interface has, and some of them cannot be
/// connected to as written. A link-local IPv6 address needs a scope
/// identifier to say WHICH interface it means, and the announcement carries
/// none; dialling it fails every time. The unspecified and multicast ranges
/// are not destinations at all.
///
/// This matters more than tidiness. Announcements arrive one address at a
/// time, so the FIRST one can easily be a link-local — and a failed dial used
/// to end the whole attempt. Measured: the session then never formed, while
/// a perfectly good loopback address arrived milliseconds later.
fn is_dialable(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast()
        }
        // `is_unicast_link_local` is unstable, so the fe80::/10 test is
        // spelled out. Scoped forms never reach here: the announcement is
        // parsed from the record's address bytes, which carry no scope.
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            !v6.is_unspecified()
                && !v6.is_multicast()
                && (segments[0] & 0xffc0) != 0xfe80
        }
    }
}

impl LanPeer {
    /// The most recent announcement, for display and for the change check.
    fn candidate(&self) -> Option<SocketAddr> {
        self.candidates.front().copied()
    }

    /// Where to dial next, skipping addresses this attempt has already tried.
    ///
    /// A proven address is preferred over any announcement, so a spoofed
    /// record cannot redirect traffic away from a contact we have already
    /// reached -- and it is tried first even if it failed once, because a
    /// contact that was genuinely there a moment ago is the best guess.
    fn dial_addr(&self, tried: &BTreeSet<SocketAddr>) -> Option<SocketAddr> {
        if let Some(verified) = self.verified.filter(|a| !tried.contains(a)) {
            return Some(verified);
        }
        self.candidates
            .iter()
            .find(|addr| !tried.contains(addr))
            .copied()
    }

    fn note_address(&mut self, addr: SocketAddr) {
        if let Some(existing) = self.candidates.iter().position(|a| *a == addr) {
            self.candidates.remove(existing);
        }
        self.candidates.push_front(addr);
        while self.candidates.len() > MAX_ADDRS_PER_PEER {
            self.candidates.pop_back();
        }
    }
}

struct Link {
    peer: Option<Fingerprint>,
    initiator: bool,
    /// Resource claim for this connection, from accept through teardown.
    /// Dropping the `Link` releases it, whatever stage it reached — which is
    /// the reason it lives here rather than being tracked in a side counter
    /// that every early return would have to remember to decrement.
    ///
    /// `None` only for links this side dialled, which are our own doing and
    /// bounded by the contact list rather than by a remote party.
    lease: Option<crate::limits::Lease>,
    writer: SyncSender<Frame>,
    /// Kept so teardown can `shutdown()` the socket, which is what wakes the
    /// reader thread blocked in `read_frame`.
    stream: TcpStream,
}

/// A live session plus the fingerprint of OUR identity it is bound to. Every
/// frame we send on it must name that identity, and every frame we receive
/// must address it — the binding is what keeps one contact from ever seeing
/// another contact's address.
struct Established {
    session: Session,
    our_fp: Fingerprint,
    /// Ephemeral public keys already accepted from this peer.
    ///
    /// A fresh initiation over an existing session deliberately REPLACES it —
    /// that is how a peer which restarted regains a live session. The problem
    /// is that a passive sniffer can replay a captured initiation to trigger
    /// the same replacement, silently rekeying us to keys the real peer does
    /// not hold. Both sides then talk past each other permanently, and the
    /// attacker never needed a private key to do it.
    ///
    /// A genuine re-initiation always carries a fresh ephemeral; a replay
    /// necessarily reuses a captured one. That is the whole difference, so it
    /// is what we key on.
    ///
    /// Bounded, and carried across rekeys so the history is not lost exactly
    /// when it starts mattering. Memory is bounded by session count rather
    /// than by anything an attacker chooses, because this lives inside an
    /// established session rather than in a map keyed by claimed identity.
    seen_ephemerals: VecDeque<[u8; 32]>,
    /// Messages sent on this session and not yet acknowledged.
    ///
    /// This is the retry buffer, and every property that keeps it from being
    /// a queue is structural rather than a promise:
    ///
    ///   * it lives HERE, inside the session, so it dies with the session —
    ///     it cannot survive a reconnect, a lock, or a restart;
    ///   * it is capped in COUNT (`MAX_OUTSTANDING_PER_SESSION`), so it never
    ///     grows to absorb load; the send past the cap is refused;
    ///   * nothing enters it for a peer that is not in session, so there is
    ///     no path at all from "offline peer" to "held message";
    ///   * it holds the ENVELOPE bytes and an attempt count, never the sealed
    ///     bytes — a retry must be resealed under a fresh counter or the peer
    ///     rejects it as a replay.
    outstanding: HashMap<MessageId, Outstanding>,
    /// When this session last opened ANY authenticated frame. Liveness reads
    /// this, and an ack counts: a quiet conversation is not a dead one.
    last_authenticated: Instant,
    /// An unanswered liveness probe, with the moment it went out.
    outstanding_ping: Option<(MessageId, Instant)>,
    /// Consecutive probes that went unanswered.
    missed_pings: u8,
    /// Message ids already delivered to the app on THIS session.
    ///
    /// Deliberately NOT carried across a rekey, unlike `seen_ephemerals`: a
    /// promoted session has new keys, so an id from the old one cannot be
    /// replayed into it — the frame would not open at all.
    seen_mids: VecDeque<(MessageId, Instant)>,
}

impl Established {
    /// One constructor, so a new per-session field cannot be forgotten at one
    /// of the several places a session comes into being. `last_authenticated`
    /// starts now because completing a handshake IS an authentication.
    fn new(session: Session, our_fp: Fingerprint, seen_ephemerals: VecDeque<[u8; 32]>) -> Self {
        Self {
            session,
            our_fp,
            seen_ephemerals,
            outstanding: HashMap::new(),
            last_authenticated: Instant::now(),
            outstanding_ping: None,
            missed_pings: 0,
            seen_mids: VecDeque::new(),
        }
    }
}

/// What `route` did with a frame. It used to answer Ok/Err, where Ok meant
/// only "entered a bounded in-process channel" — which the sender then
/// reported to the user as a message sent. Naming the outcomes is what lets a
/// failure say which hop lost it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Routed {
    /// Handed to a live route. `link` is `Some` for a direct LAN link and
    /// `None` for the relay — the distinction matters when that link dies,
    /// because only its own in-flight messages are affected.
    Sent { link: Option<u64> },
    /// A handshake deferred to a dial in progress; it goes out when the link
    /// connects. Only ever a handshake.
    Dialing,
    /// No route of any kind. Nothing was sent.
    NoRoute,
    /// We had a link and killed it for overflow. The peer was present; this
    /// is our backpressure, not their absence.
    LinkOverflow,
}

impl Routed {
    /// Whether the frame reached a route at all. Handshakes and control
    /// frames only need this much; a user message needs the specific outcome
    /// so its failure can name the hop.
    fn reached_a_route(self) -> bool {
        matches!(self, Routed::Sent { .. } | Routed::Dialing)
    }
}

/// One message awaiting acknowledgement.
struct Outstanding {
    /// The plaintext envelope, resealed on each attempt. Storing the sealed
    /// bytes instead would be worse than useless: `Session::open` rejects a
    /// counter it has already passed, so a byte-identical resend reads as a
    /// replay and is dropped.
    envelope: Vec<u8>,
    attempts: u8,
    last_attempt: Instant,
    /// Where the last attempt went. A relay refusal names only the peer —
    /// it CANNOT name a message, because the message id lives inside the
    /// ciphertext and the relay must never see in there. So the attribution
    /// is done here instead: a refusal fails the messages we actually handed
    /// to the relay, and leaves alone anything that went out over a direct
    /// link.
    ///
    /// Putting the id in the clear so the relay could echo it was the
    /// obvious alternative and is worse: retries reuse their id, so the
    /// relay would learn which sends are retries of which message. Keeping
    /// it blind costs a field here.
    last_route: Option<Routed>,
}

/// How many past ephemerals a session remembers. Each legitimate rekey adds
/// one, so this is generous for real use while staying trivially bounded.
const SEEN_EPHEMERAL_LIMIT: usize = 16;

/// Message ids remembered for duplicate suppression, with the moment each
/// was first seen. 24 bytes each, so this is under 8 KiB per session and
/// bounded by the session cap overall.
///
/// The count alone is NOT sufficient and the earlier reasoning here was
/// wrong. It argued that the session counter would catch an id evicted from
/// the window -- but a retry is resealed under a fresh counter BY DESIGN, so
/// the counter never sees it as a duplicate. With a sender allowed 8
/// outstanding messages on a 4-second deadline, 128 distinct messages inside
/// one 12-second retry window is ordinary LAN traffic, and the retry was
/// then delivered a second time. Measured, not theorised.
///
/// So the window is bounded by TIME as well: an id is retained at least as
/// long as any retry of it can still be in flight. Whichever bound is hit
/// first, an id is only ever forgotten after its sender has given up on it.
const SEEN_MID_LIMIT: usize = 512;

/// How long a seen id is retained regardless of how many messages follow it.
/// Comfortably longer than `MAX_SEND_ATTEMPTS * ACK_DEADLINE`, which is the
/// longest a sender can still be retrying.
const SEEN_MID_RETENTION: Duration = Duration::from_secs(120);

/// Attempts per message, the original included. Three is enough to ride out
/// a link swap without becoming a mechanism that hides a broken route.
const MAX_SEND_ATTEMPTS: u8 = 3;

/// How long one attempt waits for its acknowledgement before being resent.
const ACK_DEADLINE: Duration = Duration::from_secs(4);

/// Messages that may await acknowledgement at once, per session. The cap is
/// what makes the retry buffer a bound rather than a queue: past it, sending
/// is REFUSED. It does not grow.
const MAX_OUTSTANDING_PER_SESSION: usize = 8;

/// Quiet time before a liveness probe goes out. Only silence triggers it;
/// any authenticated frame, an acknowledgement included, resets the clock.
const IDLE_BEFORE_PING: Duration = Duration::from_secs(20);

/// How long a probe waits for its answer.
const PONG_DEADLINE: Duration = Duration::from_secs(10);

/// Unanswered probes before the session is declared dead. Two, not one, so a
/// garbage-collection pause or a moment of packet loss cannot end a working
/// conversation.
const MISSED_PINGS_BEFORE_DEAD: u8 = 2;

/// mDNS candidates held at once, across the whole network. Generous for any
/// real LAN and trivially bounded against one that is not.
///
/// This bounds MEMORY, and that is all it can honestly claim. There was a
/// per-source cap here as well, and it was vacuous: the address comes from
/// the announcer's own A record (`discovery.rs`, `info.get_addresses()`),
/// not from the packet, so a flooder simply claimed a different address each
/// time and the counter never moved. Measured filling the table to 256 from
/// one host. A cap that fires only under conditions the attacker chooses not
/// to meet is worse than none, because it is cited as protection.
///
/// What holds instead is below: a full table may evict an UNVERIFIED,
/// UNUSED, stale candidate, and never a verified one or one with a live
/// session. So a flood cannot lock a genuine contact out permanently -- the
/// contact re-announces and takes a slot back -- and cannot displace anyone
/// we have actually talked to. A hostile host on a LAN can always degrade
/// mDNS discovery (it can flood the multicast group directly); what it must
/// not do is exhaust our memory or evict a proven peer.
const MAX_LAN_CANDIDATES: usize = 256;

/// How stale an unverified candidate must be before a newcomer may take its
/// slot. Longer than a normal mDNS re-announcement interval, so a live
/// contact is never the thing evicted.
const CANDIDATE_EVICTABLE_AFTER: Duration = Duration::from_secs(300);

/// Quiet period between "the candidate table is full" reports. Emitting one
/// per refused announcement would turn our own warning into the flood's
/// amplifier.
const CANDIDATES_CAPPED_QUIET: Duration = Duration::from_secs(60);

/// How many unproven replacement sessions may be held at once, across all
/// peers. Each is one `Established` and nothing more; the cap exists so a
/// stranger cannot mint them without bound.
const MAX_PROVISIONAL: usize = 32;

/// How long an unproven replacement holds its contact's candidate slot.
///
/// It must expire, or a failed or abandoned candidate blocks that contact's
/// reconnection forever. It must NOT be evictable by a newer candidate, or an
/// attacker simply overwrites the real peer's attempt on repeat -- unable to
/// take the session, but able to stop anyone else proving themselves, which
/// is the same denial of service one layer along.
///
/// First candidate holds the slot; a later one waits for this to elapse.
/// Either ordering races, but this way a legitimate peer that keeps retrying
/// eventually gets a slot, whereas newest-wins hands it to whoever floods
/// hardest.
const PROVISIONAL_TTL: Duration = Duration::from_secs(30);

/// An unproven replacement session plus when it claimed the slot.
struct Provisional {
    entry: Established,
    claimed: Instant,
    /// The link this candidate's handshake ARRIVED on.
    ///
    /// Key identity and transport-channel binding are separate questions. A
    /// frame that opens under the candidate key proves the genuine peer
    /// produced it; it does NOT prove that the socket delivering it is the
    /// socket that handshake belongs to. Without this, a LAN attacker could
    /// forward a genuine encrypted proof frame over its own connection --
    /// unable to read or forge a byte -- and steer the contact route onto its
    /// own link.
    ///
    /// It is also what makes promotion actually work: `peer_link` still
    /// points at the incumbent while a candidate is proving itself, so
    /// promotion has to move the route here or the reconnected peer would
    /// reach us while nothing we sent reached them.
    link: Option<u64>,
}

/// A half-done handshake plus the identity we started it with; completion
/// must use that same key.
struct PendingEntry {
    pending: Pending,
    our_fp: Fingerprint,
}

struct Core {
    identities: HashMap<Fingerprint, Arc<Identity>>,
    /// ONE mDNS daemon announcing every identity's fingerprint. Identities
    /// added or removed at runtime are announced and withdrawn on it in place;
    /// it is never shut down except during teardown.
    discovery: Option<Discovery>,
    /// Whether discovery is believed usable, mirroring `relay_up`. Used to
    /// report `Unavailable` exactly once when the discovery thread dies.
    discovery_up: bool,
    expected_peer_key: Option<Arc<dyn Fn(Fingerprint) -> Option<[u8; 32]> + Send + Sync>>,
    on_event: Box<dyn Fn(TransportEvent) + Send>,
    rx: Receiver<CoreMsg>,
    tx: SyncSender<CoreMsg>,
    disc_rx: Receiver<DiscoveryEvent>,
    relay_rx: Receiver<RelayEvent>,
    shutdown: Arc<AtomicBool>,
    sessions: HashMap<Fingerprint, Established>,
    /// Sessions built from a handshake that arrived while an established
    /// session already existed, held aside instead of replacing it.
    ///
    /// A handshake proves only that the sender knows the peer's PUBLIC
    /// identity key, which contacts already have and which the hash number is
    /// derived from. It does not prove possession of the private half:
    /// `Session::complete` performs a Diffie-Hellman, and an impostor simply
    /// derives different keys. Letting such a handshake replace a live session
    /// therefore handed anyone who knew a contact's public key a permanent
    /// denial of service against that contact -- they could not read a word,
    /// but they could reliably destroy the conversation.
    ///
    /// So a replacement must EARN the slot: it is promoted only when a frame
    /// actually opens under its key, which an impostor cannot produce. No wire
    /// change is needed, because the session key is itself the proof.
    provisional: HashMap<Fingerprint, Provisional>,
    pendings: HashMap<Fingerprint, PendingEntry>,
    lan_peers: HashMap<Fingerprint, LanPeer>,
    links: HashMap<u64, Link>,
    peer_link: HashMap<Fingerprint, u64>,
    /// Bounds every object a remote party can make us allocate. See
    /// `crate::limits`.
    resources: Arc<crate::limits::ResourceManager>,
    /// Connections refused by a cap. A counter, never per-fingerprint: a
    /// per-peer breakdown would be a presence oracle.
    denied_pending: u64,
    /// Peers with a dial in flight, and the address it went to.
    dialing: HashMap<Fingerprint, SocketAddr>,
    /// Addresses already tried for the current attempt at each peer. Cleared
    /// when a dial succeeds or the attempt is given up, so a later attempt
    /// starts fresh rather than inheriting an old verdict.
    dial_tried: HashMap<Fingerprint, BTreeSet<SocketAddr>>,
    relay: Option<RelayClient>,
    /// The fingerprint registered with the relay, when there is a relay
    /// client. Tracked separately from the client because revocation
    /// (`remove_identity`) must tear the registration down even though the
    /// client holds its own `Arc<Identity>` and would otherwise keep the
    /// address registered after the user revoked it.
    relay_identity: Option<Fingerprint>,
    relay_up: bool,
    next_link_id: u64,
    link_threads: Vec<JoinHandle<()>>,
    connector_threads: Vec<JoinHandle<()>>,
    aux_threads: Vec<JoinHandle<()>>,
    /// When we last told the UI that candidate announcements are being
    /// refused. Rate-limits that report; see `note_candidates_capped`.
    candidates_capped_at: Option<Instant>,
    /// Retry and liveness deadlines, as a field rather than as constants
    /// read directly.
    ///
    /// This exists for the tests, and the reason is worth stating: a test
    /// that proves "the third attempt gives up" by SLEEPING twelve seconds
    /// is a test nobody runs, and a suite nobody runs stops being evidence.
    /// Production uses `Timings::default()`, which is the constants above.
    timings: Timings,
}

/// Deadlines the core measures against. See the field on `Core`.
#[derive(Clone, Copy, Debug)]
struct Timings {
    ack_deadline: Duration,
    max_send_attempts: u8,
    idle_before_ping: Duration,
    pong_deadline: Duration,
    missed_pings_before_dead: u8,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            ack_deadline: ACK_DEADLINE,
            max_send_attempts: MAX_SEND_ATTEMPTS,
            idle_before_ping: IDLE_BEFORE_PING,
            pong_deadline: PONG_DEADLINE,
            missed_pings_before_dead: MISSED_PINGS_BEFORE_DEAD,
        }
    }
}

impl Core {
    fn run(mut self) {
        loop {
            while let Ok(ev) = self.disc_rx.try_recv() {
                self.on_discovery_event(ev);
            }
            while let Ok(ev) = self.relay_rx.try_recv() {
                self.on_relay_event(ev);
            }
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(msg) => {
                    if self.handle(msg) {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            self.reap();
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
        }
        self.teardown();
    }

    fn emit(&self, event: TransportEvent) {
        (self.on_event)(event);
    }

    fn expected_key(&self, peer: Fingerprint) -> Option<[u8; 32]> {
        self.expected_peer_key.as_ref().and_then(|f| f(peer))
    }

    // --- commands -----------------------------------------------------------

    fn handle(&mut self, msg: CoreMsg) -> bool {
        match msg {
            CoreMsg::Command(Command::Shutdown) => return true,
            CoreMsg::Command(Command::AddIdentity { identity }) => self.on_add_identity(identity),
            CoreMsg::Command(Command::RemoveIdentity { fingerprint }) => {
                self.on_remove_identity(fingerprint)
            }
            CoreMsg::Command(Command::OpenSession { our, peer }) => self.on_open_session(our, peer),
            CoreMsg::Command(Command::SendText { peer, text, mid }) => {
                self.on_send_text(peer, &text, mid)
            }
            CoreMsg::Command(Command::CloseSession { peer }) => {
                self.end_session(peer, SendFailure::SessionEnded);
                self.pendings.remove(&peer);
            }
            CoreMsg::ListenerAccepted { stream } => {
                let _ = stream.set_nodelay(true);
                self.alloc_link(stream, false);
            }
            CoreMsg::OutboundConnected { peer, result } => self.on_outbound_connected(peer, result),
            CoreMsg::LinkFrame { id, frame } => self.on_frame(Some(id), frame),
            CoreMsg::LinkDead { id } => self.remove_link(id),
        }
        false
    }

    fn on_add_identity(&mut self, identity: Identity) {
        let fp = identity.fingerprint();
        if self.identities.contains_key(&fp) {
            // Already held: re-adding must not restart the announcement or
            // touch sessions built on this key.
            return;
        }
        // Insert FIRST, then announce, so the invariant "everything discovery
        // announces, we hold" is true at every observable point. A failed
        // announcement (no mDNS on this host) must not make the identity
        // unusable for outbound sessions.
        self.identities.insert(fp, Arc::new(identity));
        if let Some(discovery) = self.discovery.as_ref() {
            if discovery.announce(fp).is_err() {
                self.discovery_lost();
            }
        }
    }

    fn on_remove_identity(&mut self, fingerprint: Fingerprint) {
        if self.identities.remove(&fingerprint).is_none() {
            return;
        }
        // Withdraw the announcement — NEVER shut discovery down. Discovery is
        // shared by every identity, so tearing it down here would silently
        // unannounce every other contact's address as well.
        if let Some(discovery) = self.discovery.as_ref() {
            if discovery.withdraw(fingerprint).is_err() {
                self.discovery_lost();
            }
        }
        // If the revoked identity was the one registered with the relay, the
        // registration must die with it: the relay client holds its own
        // `Arc<Identity>`, so without this the address would stay registered
        // (and reachable through the relay) after the user revoked it.
        // `shutdown` joins the connection thread and can block the core up to
        // a connect timeout in the worst case — bounded, and revocation is
        // rare; "revoked means gone" wins.
        if self.relay_identity == Some(fingerprint) {
            self.relay_identity = None;
            if let Some(relay) = self.relay.take() {
                relay.shutdown();
            }
            let was_up = self.relay_up;
            self.relay_up = false;
            if was_up {
                self.emit(TransportEvent::RelayDown);
            }
        }
        // Tear down everything built on the removed key. Sessions and
        // pendings die by being dropped — the forward-secrecy mechanism — and
        // the peer's next frame is refused as addressed-to-unknown.
        let doomed: Vec<Fingerprint> = self
            .sessions
            .iter()
            .filter(|(_, e)| e.our_fp == fingerprint)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in doomed {
            self.end_session(peer, SendFailure::SessionEnded);
            // One peer is bound to one of our identities (see the invariant
            // on `Established`), so no surviving session can still need this
            // peer's link.
            if let Some(id) = self.peer_link.get(&peer).copied() {
                self.close_link(id);
            }
        }
        self.pendings.retain(|_, e| e.our_fp != fingerprint);
        // A dial in flight for a removed identity lands in
        // `on_outbound_connected` with neither pending nor session and is
        // closed there as a purposeless link.
    }

    fn on_open_session(&mut self, our: Fingerprint, peer: Fingerprint) {
        let Some(identity) = self.identities.get(&our).cloned() else {
            // The caller named an identity we do not hold (removed, or never
            // added). Fail CLOSED: substituting any other key would present
            // the peer an address they were never given.
            self.emit(TransportEvent::SessionFailed {
                peer,
                error: ChatError::UnknownIdentity,
            });
            return;
        };
        if our == peer {
            return; // a session with oneself is meaningless
        }
        if self.sessions.contains_key(&peer) || self.pendings.contains_key(&peer) {
            // Already established or in flight; close first to force a rekey.
            return;
        }
        let pending = Pending::start(&identity, Role::Initiator);
        let handshake = pending.handshake().to_bytes();
        self.pendings.insert(
            peer,
            PendingEntry {
                pending,
                our_fp: our,
            },
        );
        let frame = Frame::handshake(peer, our, handshake, false);
        if !self.route(peer, frame).reached_a_route() {
            self.pendings.remove(&peer);
            self.emit(TransportEvent::SendFailed {
                to: peer,
                reason: SendFailure::Offline,
            });
        }
    }

    fn on_send_text(&mut self, peer: Fingerprint, text: &str, mid: MessageId) {
        let Some(entry) = self.sessions.get_mut(&peer) else {
            self.emit(TransportEvent::SendFailed {
                to: peer,
                reason: SendFailure::NoSession,
            });
            return;
        };
        // The cap, before anything is allocated. This is the line that makes
        // the outstanding map a bound rather than a queue: past it we refuse,
        // we do not grow and we do not hold.
        if entry.outstanding.len() >= MAX_OUTSTANDING_PER_SESSION {
            self.emit(TransportEvent::SendFailed {
                to: peer,
                reason: SendFailure::TooManyOutstanding,
            });
            return;
        }

        let envelope = match (SessionEnvelope::Msg {
            mid,
            body: text.to_string(),
        })
        .encode()
        {
            Ok(bytes) => bytes,
            Err(e) => {
                self.emit(TransportEvent::MessageDropped { from: peer, error: e });
                return;
            }
        };
        // Registered as Sending BEFORE it goes anywhere, so a route that
        // fails synchronously still finds a message to fail.
        entry.outstanding.insert(
            mid,
            Outstanding {
                envelope: envelope.clone(),
                attempts: 0,
                last_attempt: Instant::now(),
                last_route: None,
            },
        );
        self.emit(TransportEvent::Delivery {
            to: peer,
            mid,
            state: Delivery::Sending,
        });
        self.attempt_send(peer, mid);
    }

    /// Seals one attempt of an outstanding message and routes it.
    ///
    /// Every attempt reseals. The peer's `Session::open` refuses a counter it
    /// has already passed, so re-sending the same bytes would be dropped as a
    /// replay — and a reseal without an id would deliver twice. The id is
    /// what makes resealing safe, and the receiver's dedup is what makes it
    /// invisible.
    fn attempt_send(&mut self, peer: Fingerprint, mid: MessageId) {
        let Some(entry) = self.sessions.get_mut(&peer) else {
            return;
        };
        let Some(pending) = entry.outstanding.get_mut(&mid) else {
            return;
        };
        pending.attempts = pending.attempts.saturating_add(1);
        pending.last_attempt = Instant::now();
        let plaintext = pending.envelope.clone();
        let our_fp = entry.our_fp;
        let sealed = match entry.session.seal(&plaintext) {
            Ok(sealed) => sealed,
            Err(e) => {
                // A failed seal (counter exhaustion is the only reachable
                // case) ends the session rather than risking desync.
                self.end_session(peer, SendFailure::SessionEnded);
                self.emit(TransportEvent::SessionFailed { peer, error: e });
                return;
            }
        };
        let frame = Frame::payload(peer, our_fp, sealed);
        let routed = self.route(peer, frame);
        if let Some(pending) = self
            .sessions
            .get_mut(&peer)
            .and_then(|entry| entry.outstanding.get_mut(&mid))
        {
            pending.last_route = Some(routed);
        }
        match routed {
            Routed::Sent { .. } | Routed::Dialing => {}
            Routed::NoRoute => self.settle(peer, mid, Delivery::Failed(SendFailure::Offline)),
            Routed::LinkOverflow => {
                self.settle(peer, mid, Delivery::Failed(SendFailure::LinkLost))
            }
        }
    }

    /// Moves one message to a terminal state and tells the app, once.
    ///
    /// Refuses to revise a message that is already terminal, which is the
    /// backward-only rule in code: a late refusal cannot un-deliver an
    /// acknowledged message, and a second failure cannot re-report the first.
    fn settle(&mut self, peer: Fingerprint, mid: MessageId, state: Delivery) {
        let Some(entry) = self.sessions.get_mut(&peer) else {
            return;
        };
        if entry.outstanding.remove(&mid).is_none() {
            return;
        }
        self.emit(TransportEvent::Delivery {
            to: peer,
            mid,
            state,
        });
    }

    /// Ends a session and gives everything in flight on it a verdict.
    ///
    /// EVERY path that drops or replaces a session must go through here.
    /// `settle` is a no-op once the session is gone, so removing one first
    /// strands its messages at Sending with no terminal event -- and the UI
    /// only ever revises a bubble on a delivery event, so "Sending…" becomes
    /// permanent. Four separate paths did exactly that.
    fn end_session(&mut self, peer: Fingerprint, reason: SendFailure) {
        if !self.sessions.contains_key(&peer) {
            return;
        }
        self.fail_session_messages(peer, reason);
        self.sessions.remove(&peer);
    }

    /// Fails every message still in flight on a session, for one reason.
    fn fail_session_messages(&mut self, peer: Fingerprint, reason: SendFailure) {
        let Some(entry) = self.sessions.get_mut(&peer) else {
            return;
        };
        let mids: Vec<MessageId> = entry.outstanding.keys().copied().collect();
        for mid in mids {
            self.settle(peer, mid, Delivery::Failed(reason));
        }
    }

    /// Seals and routes a transport-level envelope (ack, ping, pong).
    ///
    /// Best-effort by design and never retried: an acknowledgement that does
    /// not arrive costs one resend of the message it was for, which the
    /// sender's own deadline already handles. Retrying acks would build a
    /// second, subtler queue.
    fn send_control(&mut self, peer: Fingerprint, control: SessionEnvelope) {
        let Some(entry) = self.sessions.get_mut(&peer) else {
            return;
        };
        let Ok(plaintext) = control.encode() else {
            return;
        };
        let our_fp = entry.our_fp;
        let Ok(sealed) = entry.session.seal(&plaintext) else {
            return;
        };
        let _ = self.route(peer, Frame::payload(peer, our_fp, sealed));
    }

    // --- inbound frames -------------------------------------------------------

    fn on_frame(&mut self, link: Option<u64>, frame: Frame) {
        match frame.kind {
            FrameKind::Handshake {
                to,
                from,
                body,
                response,
            } => self.on_handshake_frame(link, to, from, body, response),
            FrameKind::Payload { to, from, body } => self.on_payload_frame(link, to, from, body),
            FrameKind::Refused { to } => self.on_refused(to),
            FrameKind::Error { code } => self.emit(TransportEvent::RelayError(code)),
            // Register* frames belong to the relay handshake; they are never
            // valid here.
            _ => {}
        }
    }

    fn on_handshake_frame(
        &mut self,
        link: Option<u64>,
        to: [u8; FINGERPRINT_LEN],
        from: [u8; FINGERPRINT_LEN],
        body: [u8; crate::session::HANDSHAKE_LEN],
        response: bool,
    ) {
        // The peer dialed ONE specific fingerprint of ours; only the identity
        // behind it may answer. Anything else — including a fingerprint we
        // used to hold — is refused, because answering with a different key
        // would hand this contact an address they were never given, which is
        // the exact linkage per-contact keypairs exist to prevent.
        let Some(our_fp) = fp_from_bytes(&to) else {
            if let Some(id) = link {
                self.close_link(id);
            }
            return;
        };
        if !self.identities.contains_key(&our_fp) {
            if let Some(id) = link {
                self.close_link(id);
            }
            return;
        }
        let Some(peer) = fp_from_bytes(&from) else {
            if let Some(id) = link {
                self.close_link(id);
            }
            return;
        };
        let their_hs = match Handshake::from_bytes(&body) {
            Ok(h) => h,
            Err(_) => {
                if let Some(id) = link {
                    self.close_link(id);
                }
                return;
            }
        };
        // Anti-spoofing on direct links (the relay stamps `from` itself): the
        // claimed fingerprint must be bound to the identity key inside the
        // handshake, or the frame is dropped and the liar disconnected.
        if Fingerprint::of(&PublicKey::from(their_hs.identity_public)) != peer {
            if let Some(id) = link {
                self.close_link(id);
            }
            return;
        }
        if let Some(id) = link {
            self.associate_link(id, peer, our_fp);
        }

        // A completed handshake is the ONLY thing that may promote an
        // announced address to verified. Evaluated after the match below,
        // because only then is it known whether a session actually resulted.
        let had_session = self.sessions.contains_key(&peer);

        match (self.pendings.contains_key(&peer), response) {
            (true, true) => self.complete_pending(peer, their_hs),
            (true, false) => {
                // Simultaneous initiation: the LOWER fingerprint's initiation
                // wins. Both sides compute the same winner — the comparison
                // uses the fingerprint the peer addresses us by, which under
                // the one-peer-one-identity invariant is also the identity
                // our pending initiation used — so exactly one session
                // results. If ours is lower, we ignore their initiation: they
                // will abandon it and answer ours as responder.
                let our_pending_fp = self.pendings.get(&peer).map(|e| e.our_fp);
                let Some(our_pending_fp) = our_pending_fp else {
                    return;
                };
                if !fp_lt(our_pending_fp.as_bytes(), &from) {
                    self.pendings.remove(&peer);
                    self.become_responder(peer, their_hs, our_fp, link);
                }
            }
            (false, false) => self.become_responder(peer, their_hs, our_fp, link),
            (false, true) => {
                // A reply to nothing we have pending: stale (we gave up or
                // already completed). Ignored.
            }
        }

        if !had_session && self.sessions.contains_key(&peer) {
            self.promote_verified(peer, link);
        }
    }

    /// Promotes the announced address to verified, having just proved that the
    /// host on this link controls the key behind `peer`.
    ///
    /// Compared by IP, not by full socket address: an INBOUND connection
    /// arrives from an ephemeral source port, so it can never equal the
    /// announced listening port. The claim being checked is "the host at this
    /// IP controls this key", which is exactly the binding mDNS could not
    /// make, and the address stored is the announced one because that is what
    /// a later dial has to use.
    ///
    /// A relay-routed handshake carries no link and promotes nothing: it
    /// proves the key, but says nothing about any LAN address.
    fn promote_verified(&mut self, peer: Fingerprint, link: Option<u64>) {
        let Some(id) = link else {
            return;
        };
        let Some(proven_ip) = self
            .links
            .get(&id)
            .and_then(|l| l.stream.peer_addr().ok())
            .map(|a| a.ip())
        else {
            return;
        };
        let Some(entry) = self.lan_peers.get_mut(&peer) else {
            return;
        };
        if let Some(candidate) = entry.candidate() {
            if candidate.ip() == proven_ip {
                entry.verified = Some(candidate);
            }
        }
    }

    fn complete_pending(&mut self, peer: Fingerprint, their_hs: Handshake) {
        let Some(entry) = self.pendings.remove(&peer) else {
            return;
        };
        let Some(identity) = self.identities.get(&entry.our_fp).cloned() else {
            // Defensive: `on_remove_identity` already drops the pendings that
            // use a removed key, so this is unreachable in practice.
            self.emit(TransportEvent::SessionFailed {
                peer,
                error: ChatError::NoSession,
            });
            return;
        };
        let expected = self.expected_key(peer);
        let peer_identity = their_hs.identity_public;
        match entry.pending.complete(&identity, &their_hs, expected.as_ref()) {
            Ok(session) => {
                let mut seen_ephemerals = self
                    .sessions
                    .get(&peer)
                    .map(|e| e.seen_ephemerals.clone())
                    .unwrap_or_default();
                seen_ephemerals.push_back(their_hs.ephemeral_public);
                while seen_ephemerals.len() > SEEN_EPHEMERAL_LIMIT {
                    seen_ephemerals.pop_front();
                }
                // Same as the promotion path: whatever the outgoing session
                // still had in flight was sealed under keys nobody will hold
                // a moment from now.
                self.fail_session_messages(peer, SendFailure::SessionEnded);
                self.sessions.insert(
                    peer,
                    Established::new(session, entry.our_fp, seen_ephemerals),
                );
                self.emit(TransportEvent::SessionEstablished {
                    peer,
                    peer_identity,
                    verified: expected.is_some(),
                });
            }
            Err(e) => self.emit(TransportEvent::SessionFailed { peer, error: e }),
        }
    }

    fn become_responder(
        &mut self,
        peer: Fingerprint,
        their_hs: Handshake,
        our_fp: Fingerprint,
        link: Option<u64>,
    ) {
        let Some(identity) = self.identities.get(&our_fp).cloned() else {
            return;
        };
        // Replay check BEFORE any key work: an initiation carrying an
        // ephemeral we have already accepted from this peer cannot be fresh,
        // so it must not be allowed to replace a live session. Refused rather
        // than completed, and the link is left alone — the real peer may be
        // on it, and punishing them for an attacker's frame would turn a
        // replay into a disconnect.
        if let Some(existing) = self.sessions.get(&peer) {
            if existing
                .seen_ephemerals
                .contains(&their_hs.ephemeral_public)
            {
                self.emit(TransportEvent::SessionFailed {
                    peer,
                    error: ChatError::ReplayedHandshake,
                });
                return;
            }
        }
        let pending = Pending::start(&identity, Role::Responder);
        let our_hs = pending.handshake().to_bytes();
        let expected = self.expected_key(peer);
        let peer_identity = their_hs.identity_public;
        let session = match pending.complete(&identity, &their_hs, expected.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                self.emit(TransportEvent::SessionFailed { peer, error: e });
                return;
            }
        };
        // The reply goes back over the link it ARRIVED on, not through
        // `route`. Once an incumbent session is protected, `peer_link` still
        // points at the old link, so routing the answer would send it to the
        // connection the peer may have just lost — and a peer that never
        // receives our answer can never complete the handshake, never produce
        // a frame under the new key, and therefore never prove itself. That
        // would leave genuine reconnection permanently broken.
        let reply = Frame::handshake(peer, our_fp, our_hs, true);
        let sent_on_link = link
            .and_then(|id| self.links.get(&id))
            .map(|l| l.writer.try_send(reply.clone()).is_ok())
            .unwrap_or(false);
        if !sent_on_link && !self.route(peer, reply).reached_a_route() {
            // The peer never gets our answer, so this session can never carry
            // traffic; drop it rather than keep a phantom.
            self.emit(TransportEvent::SendFailed {
                to: peer,
                reason: SendFailure::Offline,
            });
            return;
        }
        // An existing session is NOT displaced by an unproven handshake. A
        // handshake proves only knowledge of the peer's PUBLIC identity key,
        // which every contact already has; the replacement therefore waits in
        // `provisional` until a frame actually opens under its key, which
        // only the real peer can produce. See the field's documentation.
        if self.sessions.contains_key(&peer) {
            let now = Instant::now();
            // An existing candidate keeps the slot until it expires. Letting
            // a newer one evict it would let an attacker overwrite the real
            // peer's attempt indefinitely: unable to take the session, but
            // able to stop the legitimate peer ever proving itself.
            let slot_taken = self
                .provisional
                .get(&peer)
                .is_some_and(|p| now.duration_since(p.claimed) < PROVISIONAL_TTL);
            if !slot_taken && self.provisional.len() < MAX_PROVISIONAL {
                self.provisional.insert(
                    peer,
                    Provisional {
                        entry: Established::new(session, our_fp, VecDeque::new()),
                        claimed: now,
                        link,
                    },
                );
            }
            return;
        }

        // No incumbent, so this initiation simply establishes the session. It
        // is reached only for an ephemeral we have never accepted from this
        // peer — see the replay check above.
        let mut seen_ephemerals = self
            .sessions
            .get(&peer)
            .map(|e| e.seen_ephemerals.clone())
            .unwrap_or_default();
        seen_ephemerals.push_back(their_hs.ephemeral_public);
        while seen_ephemerals.len() > SEEN_EPHEMERAL_LIMIT {
            seen_ephemerals.pop_front();
        }
        self.sessions.insert(
            peer,
            Established::new(session, our_fp, seen_ephemerals),
        );
        self.emit(TransportEvent::SessionEstablished {
            peer,
            peer_identity,
            verified: expected.is_some(),
        });
    }

    fn on_payload_frame(
        &mut self,
        link: Option<u64>,
        to: [u8; FINGERPRINT_LEN],
        from: [u8; FINGERPRINT_LEN],
        body: Vec<u8>,
    ) {
        let Some(our_fp) = fp_from_bytes(&to) else {
            if let Some(id) = link {
                self.close_link(id);
            }
            return;
        };
        if !self.identities.contains_key(&our_fp) {
            // Addressed to a fingerprint we do not (or no longer) hold; a
            // direct peer sending frames addressed elsewhere is broken.
            if let Some(id) = link {
                self.close_link(id);
            }
            return;
        }
        let Some(peer) = fp_from_bytes(&from) else {
            return;
        };
        if let Some(id) = link {
            self.associate_link(id, peer, our_fp);
        }
        // The payload must address the identity the session is bound to. Only
        // the session peer can produce valid payloads at all, and they know
        // exactly one of our fingerprints, so a mismatch is a peer bug, not
        // an attack surface — drop silently like other protocol garbage.
        if self
            .sessions
            .get(&peer)
            .map(|e| e.our_fp != our_fp)
            .unwrap_or(false)
        {
            return;
        }
        let result = self.sessions.get_mut(&peer).map(|e| e.session.open(&body));
        // The incumbent could not open it. If a replacement is waiting, this
        // is its audition: only the real peer can produce a frame that opens
        // under the new key, so success here is the proof the handshake could
        // not give.
        let result = match result {
            Some(Ok(p)) => Some(Ok(p)),
            other => {
                // An expired candidate is dropped rather than auditioned: it
                // has already had its window, and its key material should not
                // linger.
                if self
                    .provisional
                    .get(&peer)
                    .is_some_and(|p| p.claimed.elapsed() >= PROVISIONAL_TTL)
                {
                    self.provisional.remove(&peer);
                }
                // The proof must arrive on the candidate's OWN link. See the
                // `link` field: opening under the key proves who produced the
                // frame, not which socket carried it.
                let on_candidate_link = self
                    .provisional
                    .get(&peer)
                    .is_some_and(|p| p.link.is_some() && p.link == link);
                let promoted = if on_candidate_link {
                    self.provisional
                        .get_mut(&peer)
                        .map(|p| p.entry.session.open(&body))
                } else {
                    None
                };
                match promoted {
                    Some(Ok(plaintext)) => {
                        let won = self.provisional.remove(&peer).expect("just matched");
                        // Move the route onto the proving link and retire the
                        // one it replaces, or every outbound frame would keep
                        // going to the connection the peer just lost.
                        if let Some(new_link) = won.link {
                            let stale = self.peer_link.insert(peer, new_link);
                            if let Some(old) = stale {
                                if old != new_link {
                                    self.close_link(old);
                                }
                            }
                            if let Some(l) = self.links.get_mut(&new_link) {
                                l.peer = Some(peer);
                            }
                        }
                        let winner = won.entry;
                        let carried = self
                            .sessions
                            .get(&peer)
                            .map(|e| e.seen_ephemerals.clone())
                            .unwrap_or_default();
                        let peer_identity = *winner.session.peer_identity();
                        // The incumbent's in-flight messages were sealed
                        // under keys that are about to be dropped, so they
                        // can never be acknowledged. Fail them before the
                        // session they belong to disappears.
                        self.fail_session_messages(peer, SendFailure::SessionEnded);
                        self.sessions.insert(
                            peer,
                            Established {
                                seen_ephemerals: carried,
                                ..winner
                            },
                        );
                        self.emit(TransportEvent::SessionEstablished {
                            peer,
                            peer_identity,
                            verified: self.expected_key(peer).is_some(),
                        });
                        Some(Ok(plaintext))
                    }
                    _ => other,
                }
            }
        };
        match result {
            Some(Ok(plaintext)) => self.on_session_envelope(peer, &plaintext),
            // A Replay verdict is EXPECTED traffic now, not an attack signal.
            // Retries reseal under a fresh counter, so two attempts at one
            // message can reach us out of order -- the LAN link overtaking
            // the relay is the ordinary case -- and the older one then looks
            // exactly like a replay to the counter. Telling the user "a
            // message failed its security checks" for our own retry is a
            // false alarm about the one subject where a false alarm is most
            // expensive.
            //
            // It is still dropped: the counter rule is what stops a genuine
            // replay, and nothing here weakens it. Only the REPORT changes.
            Some(Err(ChatError::Replay)) => {}
            // Decrypt failures and the rest: the session survives (gaps are
            // legal; injected garbage must not wedge it), but the drop is
            // surfaced.
            Some(Err(e)) => self.emit(TransportEvent::MessageDropped { from: peer, error: e }),
            None => self.emit(TransportEvent::MessageDropped {
                from: peer,
                error: ChatError::NoSession,
            }),
        }
    }

    /// Dispatches one envelope that opened under a live session.
    ///
    /// Reaching here is itself the authentication: these bytes came out of
    /// `Session::open`, so only the holder of the peer's session key could
    /// have produced them. That is what entitles an `Ack` to move a message
    /// to Delivered and any frame at all to count as liveness.
    fn on_session_envelope(&mut self, peer: Fingerprint, plaintext: &[u8]) {
        let envelope = match SessionEnvelope::decode(plaintext) {
            Ok(envelope) => envelope,
            Err(e) => {
                self.emit(TransportEvent::MessageDropped { from: peer, error: e });
                return;
            }
        };

        // ANY authenticated frame counts as liveness, an acknowledgement
        // included. The rule is deliberately not "the peer has sent a
        // message recently": a quiet conversation is not a dead connection,
        // and we probe with our own ping rather than punishing silence.
        if let Some(entry) = self.sessions.get_mut(&peer) {
            entry.last_authenticated = Instant::now();
            entry.missed_pings = 0;
            // Clearing the outstanding probe too, not just the counter.
            // Otherwise one lost Pong left a probe permanently outstanding
            // and the session was re-probed every ten seconds for the rest
            // of an ACTIVE conversation -- the opposite of "a quiet
            // conversation is not a dead connection". Any authenticated
            // frame answers the question the probe was asking.
            entry.outstanding_ping = None;
        }

        match envelope {
            SessionEnvelope::Ack { mid } => {
                // The one path to Delivered in the entire transport.
                self.settle(peer, mid, Delivery::Delivered);
            }
            SessionEnvelope::Ping { nonce } => {
                self.send_control(peer, SessionEnvelope::Pong { nonce });
            }
            SessionEnvelope::Pong { nonce } => {
                if let Some(entry) = self.sessions.get_mut(&peer) {
                    // Only the nonce we actually sent clears the probe. A
                    // replayed pong would otherwise keep a dead session
                    // looking alive indefinitely.
                    if entry.outstanding_ping.map(|(sent, _)| sent) == Some(nonce) {
                        entry.outstanding_ping = None;
                    }
                }
            }
            SessionEnvelope::Msg { mid, body } => {
                // Acknowledge FIRST, and acknowledge duplicates too. The
                // likeliest reason to see a message twice is that our first
                // acknowledgement was lost, and staying silent the second
                // time would guarantee the sender gives up on a message we
                // have in fact received.
                self.send_control(peer, SessionEnvelope::Ack { mid });

                let duplicate = match self.sessions.get_mut(&peer) {
                    Some(entry) => {
                        let now = Instant::now();
                        // Age out first, so the count bound never evicts an
                        // id whose sender could still be retrying it.
                        while entry
                            .seen_mids
                            .front()
                            .is_some_and(|(_, seen)| {
                                now.duration_since(*seen) > SEEN_MID_RETENTION
                            })
                        {
                            entry.seen_mids.pop_front();
                        }
                        if entry.seen_mids.iter().any(|(seen, _)| *seen == mid) {
                            true
                        } else {
                            entry.seen_mids.push_back((mid, now));
                            while entry.seen_mids.len() > SEEN_MID_LIMIT {
                                entry.seen_mids.pop_front();
                            }
                            false
                        }
                    }
                    None => false,
                };
                if duplicate {
                    // Acknowledged, not delivered twice. The user never sees
                    // that a retry happened, which is the point.
                    return;
                }
                match decode_incoming(body.as_bytes()) {
                    Ok(text) => self.emit(TransportEvent::Message { from: peer, text }),
                    Err(e) => {
                        self.emit(TransportEvent::MessageDropped { from: peer, error: e })
                    }
                }
            }
        }
    }

    fn on_refused(&mut self, to: [u8; FINGERPRINT_LEN]) {
        let Some(peer) = fp_from_bytes(&to) else {
            return;
        };
        // Offline delivery is REFUSED, never queued; if the refused frame was
        // our handshake, the pending attempt is over too.
        self.pendings.remove(&peer);
        // Fail exactly what we handed to the relay. The refusal names only
        // the peer, deliberately: offline, congested and wedged are one
        // indistinguishable answer so nobody can probe a fingerprint's
        // connection health. That property is preserved here -- the
        // attribution happens locally, from what WE routed, not from
        // anything the relay told us.
        //
        // Messages on a direct link are untouched: the relay refusing has
        // nothing to say about a LAN conversation that is working.
        let relayed: Vec<MessageId> = self
            .sessions
            .get(&peer)
            .map(|entry| {
                entry
                    .outstanding
                    .iter()
                    .filter(|(_, pending)| {
                        matches!(pending.last_route, Some(Routed::Sent { link: None }))
                    })
                    .map(|(mid, _)| *mid)
                    .collect()
            })
            .unwrap_or_default();
        for mid in &relayed {
            self.settle(peer, *mid, Delivery::Failed(SendFailure::Refused));
        }
        // The peer-level notice fires ONLY when no individual message
        // claimed the refusal. Emitting both put a per-bubble "not
        // delivered" under a banner saying the peer is offline, which is two
        // statements about one event and invites the reader to believe the
        // less specific one. When we know which messages were refused, they
        // say so themselves.
        if relayed.is_empty() {
            self.emit(TransportEvent::SendFailed {
                to: peer,
                reason: SendFailure::Offline,
            });
        }
    }

    // --- discovery & relay events --------------------------------------------

    /// Reports, at most once a minute, that announcements are being refused.
    ///
    /// The UI needs to be able to say "this network is announcing more
    /// addresses than can be tracked, so a contact may not appear" rather
    /// than showing an incomplete list as though it were complete. Silence
    /// here would be the same class of lie as a freeze that reports enforced.
    fn note_candidates_capped(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.candidates_capped_at {
            if now.duration_since(last) < CANDIDATES_CAPPED_QUIET {
                return;
            }
        }
        self.candidates_capped_at = Some(now);
        self.emit(TransportEvent::CandidatesCapped);
    }

    fn on_discovery_event(&mut self, event: DiscoveryEvent) {
        match event {
            DiscoveryEvent::Resolved {
                fingerprint,
                addr,
                version,
            } => {
                // Our own announcements echo back to our own browser on many
                // networks. Discovery filters them too, but its view lags this
                // one by a control-channel hop, and `identities` is updated
                // synchronously — so this check is the authoritative one and
                // both are needed to close the window.
                if self.identities.contains_key(&fingerprint) {
                    return;
                }
                // A candidate we could not talk to costs a cap slot for
                // nothing: the version is bound into the session transcript,
                // so a handshake with a peer on another version cannot
                // produce a working session at all. Refuse it before it takes
                // the slot.
                if version != crate::wire::PROTOCOL_VERSION {
                    return;
                }
                // Nor one we could not dial if we wanted to. See `is_dialable`.
                if !is_dialable(&addr) {
                    return;
                }
                // CAPS. mDNS is unauthenticated, so anything reachable on the
                // network can announce fingerprints at will, and the table
                // below is the thing it grows.
                //
                // Overflow REFUSES the newcomer; it never evicts. Eviction is
                // exactly how a flooder displaces real peers, and this table
                // already learned that lesson once for candidate slots (see
                // `a_later_candidate_cannot_evict_an_unexpired_one`).
                //
                // A peer we already know is always allowed through, so a
                // flood cannot stop an existing contact updating its address.
                let now = Instant::now();
                if !self.lan_peers.contains_key(&fingerprint)
                    && self.lan_peers.len() >= MAX_LAN_CANDIDATES
                {
                    // Full. A slot may be taken from a candidate that is
                    // unverified, has no live session, and has not been
                    // announced for a while -- oldest first. Never from a
                    // peer we have proven or are talking to.
                    let victim = self
                        .lan_peers
                        .iter()
                        .filter(|(fp, peer)| {
                            peer.verified.is_none()
                                && !self.sessions.contains_key(*fp)
                                && now.duration_since(peer.last_seen) >= CANDIDATE_EVICTABLE_AFTER
                        })
                        .min_by_key(|(_, peer)| peer.last_seen)
                        .map(|(fp, _)| *fp);
                    match victim {
                        Some(fp) => {
                            self.lan_peers.remove(&fp);
                        }
                        None => {
                            self.note_candidates_capped();
                            return;
                        }
                    }
                }
                // Records the candidate. Deliberately does NOT touch
                // `verified`: an attacker announcing a victim's fingerprint
                // at its own address must not be able to displace an address
                // that actually answered for that key.
                let entry = self.lan_peers.entry(fingerprint).or_insert(LanPeer {
                    candidates: VecDeque::new(),
                    verified: None,
                    version,
                    last_seen: now,
                });
                let changed = entry.candidate() != Some(addr);
                let is_new = !entry.candidates.contains(&addr);
                entry.note_address(addr);
                entry.version = version;
                entry.last_seen = now;
                // A NEW address for a peer we are part-way through reaching is
                // another chance to reach them. Announcements arrive one at a
                // time and out of order, so the address that works is often
                // not the first to show up -- without this, an initiation that
                // exhausted the addresses known at the time stayed dead while
                // a usable one sat unused a moment later.
                //
                // Bounded by construction: only on a genuinely new address,
                // only while an initiation is outstanding, and only when no
                // dial is already in flight.
                let retry_initiation = is_new;
                let verified = entry.verified;
                if retry_initiation
                    && self.pendings.contains_key(&fingerprint)
                    && !self.dialing.contains_key(&fingerprint)
                {
                    self.dial(fingerprint);
                }
                if changed {
                    self.emit(TransportEvent::PeerAppeared {
                        fingerprint,
                        addr,
                        version,
                        // False until a handshake proves it. The UI must not
                        // show an unverified candidate as the contact being
                        // online, because saying so is exactly the lie a
                        // spoofed announcement is trying to get us to tell.
                        verified: verified == Some(addr),
                    });
                }
            }
            DiscoveryEvent::Removed { fingerprint } => {
                if self.identities.contains_key(&fingerprint) {
                    return;
                }
                // A goodbye is as unauthenticated as an announcement, so a
                // spoofed one must not take a live contact offline. But
                // "keep the verified address forever" is the wrong way to get
                // that: a contact who genuinely leaves would then look
                // reachable permanently, and a sender MUST be able to learn
                // they cannot be reached — that is the whole reason offline is
                // the one status announced automatically.
                //
                // So the test is live-session evidence, not the mere fact
                // that an address was once proven. A session we are still
                // holding says the peer is there regardless of what the LAN
                // claims; without one, an old proof is just stale.
                let has_live_session = self.sessions.contains_key(&fingerprint);
                let Some(entry) = self.lan_peers.get_mut(&fingerprint) else {
                    return;
                };
                // A goodbye withdraws every announced address; only the
                // proven one (and only with a live session behind it) may
                // survive it.
                entry.candidates.clear();
                if has_live_session {
                    return;
                }
                self.lan_peers.remove(&fingerprint);
                self.emit(TransportEvent::PeerDisappeared { fingerprint });
            }
            DiscoveryEvent::AnnounceFailed { fingerprint } => {
                self.emit(TransportEvent::IdentityNotAnnounced { fingerprint })
            }
            DiscoveryEvent::State(state) => {
                self.discovery_up = state != DiscoveryState::Unavailable;
                self.emit(TransportEvent::DiscoveryState(state));
            }
        }
    }

    /// The discovery thread is gone. Report it once. The handle is
    /// deliberately NOT taken: teardown still has to join the thread.
    fn discovery_lost(&mut self) {
        if self.discovery_up {
            self.discovery_up = false;
            self.emit(TransportEvent::DiscoveryState(DiscoveryState::Unavailable));
        }
    }

    fn on_relay_event(&mut self, event: RelayEvent) {
        match event {
            RelayEvent::Up => {
                if !self.relay_up {
                    self.relay_up = true;
                    self.emit(TransportEvent::RelayUp);
                }
            }
            RelayEvent::Down => {
                if self.relay_up {
                    self.relay_up = false;
                    self.emit(TransportEvent::RelayDown);
                }
            }
            RelayEvent::Frame(frame) => self.on_frame(None, frame),
            // A Premium licence refusal at registration (P3, design 4.4).
            // Surfaced through the EXISTING RelayError event, which
            // chat_panel already maps to a label and the chat UI to copy —
            // without this arm the refusal died in the connection thread and
            // the UI could only ever say "down", never why.
            RelayEvent::Refused(code) => {
                self.emit(TransportEvent::RelayError(code));
            }
            RelayEvent::Dropped { .. } => {
                // The relay connection died with frames still QUEUED, and
                // those were discarded rather than carried across the
                // reconnect.
                //
                // What this must NOT do is declare every relayed message
                // lost. The client counts only what was still in the queue; a
                // frame already written to the socket is not among them, and
                // may well have arrived. Failing those outright made a
                // delivered message read Failed permanently -- Failed is
                // terminal, so the peer's genuine acknowledgement then had
                // nothing left to settle, and the user resent a message the
                // peer already had.
                //
                // So this only resets the RETRY CLOCK: anything relayed is
                // treated as due for another attempt, and the existing
                // bounded retry decides what happens next. A message that did
                // arrive gets acknowledged and stops; one that did not gets
                // resent and, if nothing comes back, ends at NoAck. Both
                // outcomes are earned rather than assumed.
                let now = Instant::now();
                let deadline = self.timings.ack_deadline;
                for entry in self.sessions.values_mut() {
                    for pending in entry.outstanding.values_mut() {
                        if matches!(pending.last_route, Some(Routed::Sent { link: None })) {
                            pending.last_attempt = now
                                .checked_sub(deadline)
                                .unwrap_or(now);
                        }
                    }
                }
            }
        }
    }

    // --- routing ---------------------------------------------------------------

    /// Sends one frame to a peer: direct link first, then the relay, then a
    /// LAN dial. Returns Err(PeerOffline) when no route exists — delivery is
    /// refused, never queued for later.
    fn route(&mut self, peer: Fingerprint, frame: Frame) -> Routed {
        let is_handshake = matches!(frame.kind, FrameKind::Handshake { .. });
        let mut overflowed = false;

        if let Some(id) = self.peer_link.get(&peer).copied() {
            match self.links.get(&id) {
                Some(link) => match link.writer.try_send(frame.clone()) {
                    Ok(()) => return Routed::Sent { link: Some(id) },
                    Err(mpsc::TrySendError::Full(_)) => {
                        // BOUNDED BY DESIGN: the link queue must never grow to
                        // absorb load. Overflow closes the connection.
                        //
                        // Recorded, because this is NOT the peer being
                        // offline: they were present and we killed the link.
                        // Reporting it as Offline is what put "they are not on
                        // this network right now" under a message to someone
                        // demonstrably on this network.
                        self.close_link(id);
                        overflowed = true;
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        self.remove_link(id);
                        overflowed = true;
                    }
                },
                None => {
                    self.peer_link.remove(&peer);
                }
            }
        }

        // The relay carries only the identity registered with it.
        //
        // This is not tidiness. The relay overwrites `from` with the
        // fingerprint the connection proved, so routing an identity-A session
        // over a relay registered as identity B hands the peer an address of
        // ours they were never given — precisely the linkage per-contact
        // keypairs exist to prevent — and their own transport drops it
        // anyway, because it answers only on the key that was dialed.
        let ours_on_relay = self
            .sessions
            .get(&peer)
            .map(|entry| entry.our_fp)
            .filter(|our| self.relay_identity == Some(*our))
            .is_some();
        if self.relay_up && (ours_on_relay || is_handshake && self.relay_identity.is_some()) {
            if let Some(relay) = &self.relay {
                if relay.send(frame.clone()).is_ok() {
                    return Routed::Sent { link: None };
                }
            }
        }

        if self.lan_peers.contains_key(&peer) {
            self.dial(peer);
            if is_handshake {
                // The pending handshake is sent the moment the link connects
                // (see on_outbound_connected), so the initiation succeeded.
                return Routed::Dialing;
            }
            // A payload that beat the dial is refused; the link will be up for
            // the next attempt. Honest, bounded, and visible to the UI.
        }

        if overflowed {
            Routed::LinkOverflow
        } else {
            Routed::NoRoute
        }
    }

    fn dial(&mut self, peer: Fingerprint) {
        if self.dialing.contains_key(&peer) {
            return;
        }
        let tried = self.dial_tried.entry(peer).or_default();
        let Some(lan) = self.lan_peers.get(&peer) else {
            return;
        };
        let Some(addr) = lan.dial_addr(tried) else {
            // Every announced address has been tried. Clearing here would
            // start an endless loop over the same unreachable set; the entry
            // is cleared when an attempt is given up or succeeds instead.
            return;
        };
        tried.insert(addr);
        self.dialing.insert(peer, addr);
        let tx = self.tx.clone();
        let handle = thread::spawn(move || {
            let result =
                TcpStream::connect_timeout(&addr, DIAL_TIMEOUT).map_err(ChatError::from);
            // Blocking send is fine: the core drains, and teardown keeps
            // draining precisely so this can never wedge shutdown.
            let _ = tx.send(CoreMsg::OutboundConnected { peer, result });
        });
        self.connector_threads.push(handle);
    }

    fn on_outbound_connected(&mut self, peer: Fingerprint, result: Result<TcpStream, ChatError>) {
        self.dialing.remove(&peer);
        let stream = match result {
            Ok(s) => s,
            Err(_) => {
                // One unreachable address is not an unreachable peer.
                //
                // A multi-homed host announces itself at every address it
                // has, and some of them -- a docker bridge, an IPv6
                // link-local with no scope, an interface that does not route
                // here -- will not connect. This used to throw the pending
                // handshake away on the first such failure and report the
                // contact offline, so whether a session formed depended on
                // which record happened to arrive last. Measured at one run
                // in three.
                //
                // Bounded: each address is tried at most once per attempt
                // (`dial_tried`), and the set is capped by the number of
                // addresses a peer may announce at all.
                let another = self
                    .lan_peers
                    .get(&peer)
                    .zip(self.dial_tried.get(&peer))
                    .and_then(|(lan, tried)| lan.dial_addr(tried))
                    .is_some();
                if another {
                    self.dial(peer);
                    return;
                }
                self.dial_tried.remove(&peer);
                if self.pendings.remove(&peer).is_some() {
                    self.emit(TransportEvent::SendFailed {
                        to: peer,
                        reason: SendFailure::Offline,
                    });
                }
                return;
            }
        };
        // Connected: the next attempt at this peer starts from a clean slate.
        self.dial_tried.remove(&peer);
        let _ = stream.set_nodelay(true);
        let Some(id) = self.alloc_link(stream, true) else {
            return;
        };
        // The identity this link will speak for is determined by what the
        // dial was FOR — a pending initiation, or a live session to rekey.
        // If neither exists (the attempt was cancelled, or the identity was
        // removed while dialing), the link has no purpose and is closed.
        let our_fp = self
            .pendings
            .get(&peer)
            .map(|e| e.our_fp)
            .or_else(|| self.sessions.get(&peer).map(|e| e.our_fp));
        let Some(our_fp) = our_fp else {
            self.close_link(id);
            return;
        };
        // We dialed them, so the association is known immediately; the tie-
        // break inside resolves the both-dialed-at-once case.
        self.associate_link(id, peer, our_fp);

        if self.pendings.contains_key(&peer) {
            let hs = self
                .pendings
                .get(&peer)
                .map(|e| e.pending.handshake().to_bytes());
            if let Some(hs) = hs {
                let frame = Frame::handshake(peer, our_fp, hs, false);
                if !self.route(peer, frame).reached_a_route() {
                    self.pendings.remove(&peer);
                    self.emit(TransportEvent::SendFailed {
                        to: peer,
                        reason: SendFailure::Offline,
                    });
                }
            }
        } else {
            // Redialed with a live session (the old link died): rekey over the
            // new link. The peer replaces its session when this arrives; the
            // old keys die with the replaced Session.
            let Some(identity) = self.identities.get(&our_fp).cloned() else {
                self.close_link(id);
                return;
            };
            let pending = Pending::start(&identity, Role::Initiator);
            let hs = pending.handshake().to_bytes();
            self.pendings.insert(peer, PendingEntry { pending, our_fp });
            let frame = Frame::handshake(peer, our_fp, hs, false);
            if !self.route(peer, frame).reached_a_route() {
                self.pendings.remove(&peer);
                self.emit(TransportEvent::SendFailed {
                    to: peer,
                    reason: SendFailure::Offline,
                });
            }
        }
    }

    // --- link bookkeeping -------------------------------------------------------

    fn alloc_link(&mut self, stream: TcpStream, initiator: bool) -> Option<u64> {
        // An INBOUND socket is created by a remote party and must be paid for
        // out of a bounded budget before any thread is spawned for it. An
        // outbound dial is our own decision, bounded by the contact list.
        let lease = if initiator {
            None
        } else {
            let source = stream
                .peer_addr()
                .ok()
                .map(|a| crate::limits::canonical_source(&a))?;
            match self.resources.accept(source, Instant::now()) {
                Ok(lease) => Some(lease),
                Err(_) => {
                    // Refused before spawning anything. The socket drops here,
                    // which is the cheapest possible answer to a flood.
                    self.denied_pending = self.denied_pending.saturating_add(1);
                    return None;
                }
            }
        };
        let id = self.next_link_id;
        self.next_link_id += 1;
        let (writer, reader, writer_thread) = spawn_link(id, &stream, &self.tx)?;
        self.link_threads.push(reader);
        self.link_threads.push(writer_thread);
        self.links.insert(
            id,
            Link {
                peer: None,
                initiator,
                lease,
                writer,
                stream,
            },
        );
        Some(id)
    }

    /// Closes links whose ABSOLUTE handshake deadline has passed.
    ///
    /// Absolute, so a peer feeding one byte before each expiry cannot hold a
    /// thread forever; the deadline is stamped at accept and never restamped.
    fn reap_expired_links(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, l)| {
                l.peer.is_none() && l.lease.as_ref().is_some_and(|lease| lease.expired(now))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.close_link(id);
        }
    }

    /// Records that a link belongs to a peer, resolving the duplicate-link
    /// case: when both sides dial at once there are briefly two TCP links, and
    /// both sides must keep the SAME one or traffic splits. `our_fp` is the
    /// fingerprint the peer knows us by on this link; the canonicality rule
    /// only agrees on both sides because each peer sees exactly one of our
    /// fingerprints.
    fn associate_link(&mut self, id: u64, peer: Fingerprint, our_fp: Fingerprint) {
        let Some(link) = self.links.get_mut(&id) else {
            return;
        };
        if link.peer == Some(peer) {
            return;
        }
        link.peer = Some(peer);
        // A live session's link is not surrendered to an unproven newcomer.
        // The tie-break below is for two HONEST peers racing to connect; it
        // has no way to tell an impostor from the real contact, because at
        // this point nothing has proved possession of the private key. Any
        // stranger who knew the contact's public key could otherwise close
        // the real link out from under an active conversation.
        //
        // The newcomer is left connected and unassociated. If it is genuine
        // its session proves itself in `on_payload_frame` and takes over
        // there; if it is not, it simply idles until it is torn down.
        if self.sessions.contains_key(&peer) {
            if let Some(existing) = self.peer_link.get(&peer).copied() {
                if existing != id && self.links.contains_key(&existing) {
                    return;
                }
            }
        }
        // The tie-break reads the EXISTING link's direction, not this one's:
        // exactly one direction is canonical, so keeping the canonical
        // incumbent (or replacing a non-canonical one) converges either way.
        if let Some(existing) = self.peer_link.get(&peer).copied() {
            if existing != id {
                let existing_initiator = self
                    .links
                    .get(&existing)
                    .map(|l| l.initiator)
                    .unwrap_or(false);
                if link_is_canonical(our_fp.as_bytes(), peer.as_bytes(), existing_initiator) {
                    self.close_link(id);
                    return;
                } else {
                    self.close_link(existing);
                }
            }
        }
        self.peer_link.insert(peer, id);
    }

    fn remove_link(&mut self, id: u64) {
        if let Some(link) = self.links.remove(&id) {
            if let Some(peer) = link.peer {
                if self.peer_link.get(&peer) == Some(&id) {
                    self.peer_link.remove(&peer);
                }
                // The SESSION survives link loss — that part of the old
                // comment was right, and sessions outliving links is what
                // lets a peer reconnect without a new handshake.
                //
                // What was wrong was the silence. Frames the writer thread
                // had already accepted died with it, and nothing said so:
                // the message vanished after the UI had drawn it, and the
                // app's cached "connected" flag stayed true, so the NEXT
                // send went out on a route that no longer existed.
                //
                // Only the messages that went out on THIS link are
                // affected, and only if there is nowhere else to try.
                //
                // Failing everything outstanding for the peer was wrong in
                // the ordinary case: when both sides dial each other at once
                // there are briefly two links and the tie-break closes one,
                // so a message travelling happily on the survivor was
                // reported Failed. The two-transport probe caught it as a
                // delivered message reported failed -- a false verdict, which
                // is the exact class of defect this whole area exists to
                // eliminate, pointing the other way.
                //
                // And if another route exists, a message is not lost: reset
                // its retry clock and let the bounded retry decide, the same
                // treatment a relay reconnect gets. It may already have
                // arrived, in which case the acknowledgement stops it.
                if !self.sessions.contains_key(&peer) {
                    return;
                }
                let stranded: Vec<MessageId> = self
                    .sessions
                    .get(&peer)
                    .map(|entry| {
                        entry
                            .outstanding
                            .iter()
                            .filter(|(_, pending)| {
                                pending.last_route == Some(Routed::Sent { link: Some(id) })
                            })
                            .map(|(mid, _)| *mid)
                            .collect()
                    })
                    .unwrap_or_default();
                let has_route = self.peer_link.contains_key(&peer)
                    || self.lan_peers.contains_key(&peer)
                    || (self.relay_up && self.relay.is_some());
                if has_route {
                    let now = Instant::now();
                    let deadline = self.timings.ack_deadline;
                    if let Some(entry) = self.sessions.get_mut(&peer) {
                        for mid in &stranded {
                            if let Some(pending) = entry.outstanding.get_mut(mid) {
                                pending.last_attempt =
                                    now.checked_sub(deadline).unwrap_or(now);
                            }
                        }
                    }
                } else {
                    for mid in stranded {
                        self.settle(peer, mid, Delivery::Failed(SendFailure::LinkLost));
                    }
                    self.emit(TransportEvent::SessionUnreachable { peer });
                }
            }
        }
    }

    fn close_link(&mut self, id: u64) {
        if let Some(link) = self.links.get(&id) {
            let _ = link.stream.shutdown(std::net::Shutdown::Both);
        }
        self.remove_link(id);
    }

    fn reap(&mut self) {
        // Finished handles are dropped, not joined — the threads have already
        // exited; teardown joins anything still alive.
        self.link_threads.retain(|h| !h.is_finished());
        self.connector_threads.retain(|h| !h.is_finished());
        // A connection that never completed a handshake is on an ABSOLUTE
        // clock; this is what actually enforces it.
        self.reap_expired_links();
        self.reap_unacknowledged();
        self.probe_quiet_sessions();
    }

    /// Resends or gives up on messages whose acknowledgement never came.
    ///
    /// Runs on the core tick that already exists, so there is no timer thread
    /// and no wakeup this did not already have.
    fn reap_unacknowledged(&mut self) {
        let now = Instant::now();
        let mut retry: Vec<(Fingerprint, MessageId)> = Vec::new();
        let mut give_up: Vec<(Fingerprint, MessageId)> = Vec::new();
        for (peer, entry) in &self.sessions {
            for (mid, pending) in &entry.outstanding {
                if now.duration_since(pending.last_attempt) < self.timings.ack_deadline {
                    continue;
                }
                if pending.attempts >= self.timings.max_send_attempts {
                    give_up.push((*peer, *mid));
                } else {
                    retry.push((*peer, *mid));
                }
            }
        }
        for (peer, mid) in give_up {
            self.settle(peer, mid, Delivery::Failed(SendFailure::NoAck));
        }
        for (peer, mid) in retry {
            self.attempt_send(peer, mid);
        }
    }

    /// Probes sessions that have gone quiet, and ends the ones that stay
    /// silent through two probes.
    ///
    /// Note what does NOT trigger a probe: the user not typing. Any
    /// authenticated frame resets the clock, an acknowledgement included, so
    /// an active conversation is never probed at all.
    fn probe_quiet_sessions(&mut self) {
        let now = Instant::now();
        let mut probe: Vec<Fingerprint> = Vec::new();
        let mut dead: Vec<Fingerprint> = Vec::new();
        for (peer, entry) in &self.sessions {
            match entry.outstanding_ping {
                Some((_, sent)) if now.duration_since(sent) >= self.timings.pong_deadline => {
                    if entry.missed_pings.saturating_add(1) >= self.timings.missed_pings_before_dead
                    {
                        dead.push(*peer);
                    } else {
                        probe.push(*peer);
                    }
                }
                Some(_) => {}
                None => {
                    if now.duration_since(entry.last_authenticated) >= self.timings.idle_before_ping
                    {
                        probe.push(*peer);
                    }
                }
            }
        }
        for peer in dead {
            self.end_session(peer, SendFailure::SessionEnded);
            self.emit(TransportEvent::SessionFailed {
                peer,
                error: ChatError::PeerUnresponsive,
            });
        }
        for peer in probe {
            let nonce = envelope::new_message_id();
            if let Some(entry) = self.sessions.get_mut(&peer) {
                if entry.outstanding_ping.is_some() {
                    entry.missed_pings = entry.missed_pings.saturating_add(1);
                }
                entry.outstanding_ping = Some((nonce, now));
            }
            self.send_control(peer, SessionEnvelope::Ping { nonce });
        }
    }

    // --- shutdown ---------------------------------------------------------------

    fn teardown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);

        // Closing the sockets wakes the reader threads; dropping the Link
        // values drops the writer senders, which ends the writer threads.
        for (_, link) in self.links.drain() {
            let _ = link.stream.shutdown(std::net::Shutdown::Both);
        }
        self.peer_link.clear();

        // Keep draining the core channel while link and connector threads make
        // their final sends, so nothing blocks on a full queue during
        // shutdown — that is the deadlock this loop exists to prevent.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            while self.rx.try_recv().is_ok() {}
            let alive = self
                .link_threads
                .iter()
                .chain(self.connector_threads.iter())
                .any(|h| !h.is_finished());
            if !alive {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        for h in self.link_threads.drain(..) {
            let _ = h.join();
        }
        for h in self.connector_threads.drain(..) {
            let _ = h.join();
        }
        if let Some(relay) = self.relay.take() {
            relay.shutdown();
        }
        self.relay_identity = None;
        // The only place discovery is ever shut down. It unregisters every
        // announced fingerprint and waits briefly for the goodbyes, so peers
        // drop us now rather than after the TTL.
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown();
        }
        for h in self.aux_threads.drain(..) {
            let _ = h.join();
        }
        // Sessions and pendings drop here: every key this transport ever held
        // is gone, which is the forward-secrecy story told one last time.
    }
}

/// One reader + one writer thread per link; `TcpStream::try_clone` makes the
/// two directions independent. Both report death as `LinkDead`.
fn spawn_link(
    id: u64,
    stream: &TcpStream,
    core_tx: &SyncSender<CoreMsg>,
) -> Option<(SyncSender<Frame>, JoinHandle<()>, JoinHandle<()>)> {
    let mut reader_stream = stream.try_clone().ok()?;
    let mut writer_stream = stream.try_clone().ok()?;
    let (tx, rx) = mpsc::sync_channel::<Frame>(LINK_QUEUE);

    let reader_tx = core_tx.clone();
    let reader = thread::spawn(move || {
        let _ = reader_stream.set_read_timeout(Some(LINK_FIRST_FRAME_TIMEOUT));
        let mut first = true;
        loop {
            match crate::wire::read_frame(&mut reader_stream) {
                Ok(frame) => {
                    if first {
                        first = false;
                        let _ = reader_stream.set_read_timeout(None);
                    }
                    if reader_tx.send(CoreMsg::LinkFrame { id, frame }).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = reader_tx.send(CoreMsg::LinkDead { id });
                    break;
                }
            }
        }
    });

    let writer_tx = core_tx.clone();
    let writer = thread::spawn(move || {
        while let Ok(frame) = rx.recv() {
            if crate::wire::write_frame(&mut writer_stream, &frame).is_err() {
                let _ = writer_tx.send(CoreMsg::LinkDead { id });
                break;
            }
        }
    });

    Some((tx, reader, writer))
}

/// The link initiated by the lower fingerprint is canonical; both peers
/// compute the same answer, so both keep the same link.
fn link_is_canonical(own: &[u8; FINGERPRINT_LEN], peer: &[u8; FINGERPRINT_LEN], initiator: bool) -> bool {
    initiator == fp_lt(own, peer)
}

fn fp_lt(a: &[u8; FINGERPRINT_LEN], b: &[u8; FINGERPRINT_LEN]) -> bool {
    a < b
}

/// Note: `Fingerprint` has no public from-bytes constructor (and no Ord,
/// hence `fp_lt` above). Rather than modify the crypto API, this round-trips
/// through the hash-number string — the only public path back. Suggest adding
/// `Fingerprint::from_bytes([u8; FINGERPRINT_LEN]) -> Self` (and deriving
/// `PartialOrd`/`Ord`) to identity.rs.
fn fp_from_bytes(bytes: &[u8; FINGERPRINT_LEN]) -> Option<Fingerprint> {
    let mut hex = String::with_capacity(FINGERPRINT_LEN * 2);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    Fingerprint::parse_hash_number(&hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use std::sync::Mutex;

    // --- core-level harness --------------------------------------------------
    //
    // These tests drive `Core` directly (it is single-threaded, so method
    // calls stand in for channel messages) with captured event and link
    // channels, which lets them assert what went ON THE WIRE, not just what
    // state changed. Links are injected as bare `Link` values: no reader/
    // writer threads are spawned, so nothing needs joining.

    fn loopback_stream() -> TcpStream {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (_server, _) = listener.accept().unwrap();
        client
    }

    struct Harness {
        core: Core,
        events: Arc<Mutex<Vec<TransportEvent>>>,
    }

    fn harness(identities: Vec<Identity>) -> Harness {
        let (_unused_tx, core_rx) = mpsc::sync_channel::<CoreMsg>(CORE_QUEUE);
        let (core_tx, _unused_rx) = mpsc::sync_channel::<CoreMsg>(CORE_QUEUE);
        let (_disc_tx, disc_rx) = mpsc::sync_channel::<DiscoveryEvent>(DISCOVERY_QUEUE);
        let (_relay_tx, relay_rx) = mpsc::sync_channel::<RelayEvent>(RELAY_QUEUE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let mut map = HashMap::new();
        for identity in identities {
            map.insert(identity.fingerprint(), Arc::new(identity));
        }
        Harness {
            core: Core {
                identities: map,
                discovery: None,
                discovery_up: false,
                expected_peer_key: None,
                on_event: Box::new(move |e| captured.lock().unwrap().push(e)),
                rx: core_rx,
                tx: core_tx,
                disc_rx,
                relay_rx,
                shutdown: Arc::new(AtomicBool::new(false)),
                sessions: HashMap::new(),
                provisional: HashMap::new(),
                pendings: HashMap::new(),
                lan_peers: HashMap::new(),
                links: HashMap::new(),
                peer_link: HashMap::new(),
                resources: crate::limits::ResourceManager::new(crate::limits::Limits::default()),
                denied_pending: 0,
                dialing: HashMap::new(),
                dial_tried: HashMap::new(),
                relay: None,
                relay_identity: None,
                relay_up: false,
                next_link_id: 1,
                link_threads: Vec::new(),
                connector_threads: Vec::new(),
                aux_threads: Vec::new(),
                candidates_capped_at: None,
                timings: Timings::default(),
            },
            events,
        }
    }

    /// Injects a link already associated with `peer`, returning the receiver
    /// end of its writer queue so tests can read what the core sent.
    fn inject_link(core: &mut Core, id: u64, peer: Fingerprint) -> Receiver<Frame> {
        let (writer, rx) = mpsc::sync_channel::<Frame>(LINK_QUEUE);
        core.links.insert(
            id,
            Link {
                peer: Some(peer),
                initiator: false,
                lease: None,
                writer,
                stream: loopback_stream(),
            },
        );
        core.peer_link.insert(peer, id);
        rx
    }

    /// A freshly accepted inbound link: NOT yet bound to any peer, which is
    /// the real state before `associate_link` runs. `inject_link` pre-binds
    /// it, which would quietly pre-decide the very thing under test.
    fn inject_unassociated_link(core: &mut Core, id: u64) -> Receiver<Frame> {
        let (writer, rx) = mpsc::sync_channel::<Frame>(LINK_QUEUE);
        core.links.insert(
            id,
            Link {
                peer: None,
                initiator: false,
                lease: None,
                writer,
                stream: loopback_stream(),
            },
        );
        rx
    }

    /// What a peer actually puts on the wire for one user message: the text
    /// inside a `SessionEnvelope::Msg`. Tests seal THIS, never raw bytes —
    /// raw bytes would exercise a path no real peer produces.
    fn user_message(text: &[u8]) -> Vec<u8> {
        SessionEnvelope::Msg {
            mid: envelope::new_message_id(),
            body: String::from_utf8(text.to_vec()).expect("test text is utf-8"),
        }
        .encode()
        .expect("encode")
    }

    /// The same, with a caller-chosen id, for dedup and acknowledgement tests.
    fn user_message_with_id(mid: MessageId, text: &str) -> Vec<u8> {
        SessionEnvelope::Msg {
            mid,
            body: text.to_string(),
        }
        .encode()
        .expect("encode")
    }

    /// Reads the message ids the core put on a link, in order. This is how a
    /// test observes what was actually SENT rather than what was intended.
    fn sent_mids(rx: &Receiver<Frame>, session: &mut Session) -> Vec<MessageId> {
        let mut out = Vec::new();
        for frame in rx.try_iter() {
            if let FrameKind::Payload { body, .. } = frame.kind {
                if let Ok(plain) = session.open(&body) {
                    if let Ok(SessionEnvelope::Msg { mid, .. }) = SessionEnvelope::decode(&plain) {
                        out.push(mid);
                    }
                }
            }
        }
        out
    }

    fn initiation_from(peer_id: &Identity) -> (Fingerprint, Pending, [u8; crate::session::HANDSHAKE_LEN]) {
        let pending = Pending::start(peer_id, Role::Initiator);
        // Hoisted: `Pending` is not Copy, so building the tuple inline would
        // move it in one element and borrow it in the next.
        let handshake = pending.handshake().to_bytes();
        (peer_id.fingerprint(), pending, handshake)
    }

    // --- an unproven handshake cannot displace a live session ----------------

    /// THE ATTACK. A handshake proves only that the sender knows the peer's
    /// PUBLIC identity key -- which every contact already has, and which the
    /// hash number is derived from. `Session::complete` is a Diffie-Hellman,
    /// not a proof of possession, so an impostor gets a session with the
    /// wrong keys. That used to REPLACE the real one and close its link: a
    /// permanent denial of service against any contact whose public key was
    /// known, without reading a single word.
    #[test]
    fn an_impostor_cannot_destroy_a_live_session_with_a_public_key() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);

        // The real contact establishes a session over link 1.
        let peer_id = Identity::generate();
        let (peer_fp, _p, real_hs) = initiation_from(&peer_id);
        let _rx1 = inject_link(&mut h.core, 1, peer_fp);
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), real_hs, false,
        );
        assert!(h.core.sessions.contains_key(&peer_fp));

        // The impostor knows only the contact's PUBLIC key. It mints its own
        // ephemeral and claims the contact's fingerprint -- which passes the
        // fingerprint-matches-key check, because that key really is theirs.
        let impostor_pending = Pending::start(&peer_id, Role::Initiator);
        let forged = impostor_pending.handshake().to_bytes();
        let _rx2 = inject_unassociated_link(&mut h.core, 2);
        h.core.on_handshake_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), forged, false,
        );

        assert!(
            h.core.sessions.contains_key(&peer_fp),
            "the live session must survive an unproven handshake"
        );
        assert!(
            h.core.links.contains_key(&1),
            "the real contact's link must not be closed by a stranger"
        );
        assert_eq!(
            h.core.peer_link.get(&peer_fp),
            Some(&1),
            "routing must still point at the proven link"
        );
        assert!(
            h.core.provisional.contains_key(&peer_fp),
            "the replacement waits for proof rather than being applied"
        );
    }

    /// The other half: a replacement that can actually produce a frame under
    /// its own key IS the real peer, and must take over. Otherwise protecting
    /// the incumbent would break genuine reconnection.
    #[test]
    fn a_replacement_that_proves_itself_takes_over() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _p, first) = initiation_from(&peer_id);
        let _rx1 = inject_link(&mut h.core, 1, peer_fp);
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), first, false,
        );

        // The peer restarts and re-initiates. We answer as responder, so the
        // peer's side derives the SAME key from our reply -- reconstructed
        // here by completing their pending against our answering handshake.
        let their_pending = Pending::start(&peer_id, Role::Initiator);
        let their_hs = their_pending.handshake().to_bytes();
        let _rx2 = inject_unassociated_link(&mut h.core, 2);
        h.core.on_handshake_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), their_hs, false,
        );
        assert!(h.core.provisional.contains_key(&peer_fp), "held aside");

        // Our reply went out on link 2; feed it back into their pending so
        // they hold the matching session, then send a real frame under it.
        let reply = _rx2.try_iter().find_map(|f| match f.kind {
            FrameKind::Handshake { body, response: true, .. } => Some(body),
            _ => None,
        }).expect("we answered the initiation");
        let our_hs = Handshake::from_bytes(&reply).unwrap();
        let mut their_session = their_pending.complete(&peer_id, &our_hs, None).unwrap();
        // Messages travel as plain UTF-8 bytes; decode_incoming validates them.
        let sealed = their_session.seal(&user_message(b"hello again")).unwrap();

        h.core.on_payload_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), sealed,
        );

        assert!(
            !h.core.provisional.contains_key(&peer_fp),
            "a proven replacement is promoted, not left waiting"
        );
        assert!(h.events.lock().unwrap().iter().any(|e| matches!(
            e,
            TransportEvent::Message { .. }
        )), "the message must be delivered");
    }

    /// An attacker who cannot take the session must not be able to stop the
    /// real peer from reclaiming it either. Newest-candidate-wins would have
    /// let them overwrite the legitimate attempt on repeat -- the same denial
    /// of service, one layer along.
    #[test]
    fn a_later_candidate_cannot_evict_an_unexpired_one() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _p, first) = initiation_from(&peer_id);
        let _rx1 = inject_link(&mut h.core, 1, peer_fp);
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), first, false,
        );

        // The real peer reconnects and claims the candidate slot.
        let real = Pending::start(&peer_id, Role::Initiator).handshake().to_bytes();
        let _rx2 = inject_unassociated_link(&mut h.core, 2);
        h.core.on_handshake_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), real, false,
        );
        let claimed = h.core.provisional.get(&peer_fp).expect("slot claimed").claimed;

        // The attacker floods candidates for the same fingerprint.
        for _ in 0..10 {
            let forged = Pending::start(&peer_id, Role::Initiator).handshake().to_bytes();
            let _rx = inject_unassociated_link(&mut h.core, 99);
            h.core.on_handshake_frame(
                Some(99), *our_fp.as_bytes(), *peer_fp.as_bytes(), forged, false,
            );
        }

        assert_eq!(
            h.core.provisional.get(&peer_fp).expect("still held").claimed,
            claimed,
            "the first candidate must keep the slot against a flood"
        );
    }

    /// The other half: the slot must not be held forever, or a failed or
    /// abandoned candidate blocks that contact's reconnection permanently.
    #[test]
    fn an_expired_candidate_releases_the_slot() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _p, first) = initiation_from(&peer_id);
        let _rx1 = inject_link(&mut h.core, 1, peer_fp);
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), first, false,
        );

        let stale = Pending::start(&peer_id, Role::Initiator).handshake().to_bytes();
        let _rx2 = inject_unassociated_link(&mut h.core, 2);
        h.core.on_handshake_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), stale, false,
        );
        // Age it past the TTL.
        h.core.provisional.get_mut(&peer_fp).unwrap().claimed =
            Instant::now() - PROVISIONAL_TTL - Duration::from_secs(1);

        let fresh = Pending::start(&peer_id, Role::Initiator).handshake().to_bytes();
        let _rx3 = inject_unassociated_link(&mut h.core, 3);
        h.core.on_handshake_frame(
            Some(3), *our_fp.as_bytes(), *peer_fp.as_bytes(), fresh, false,
        );

        assert!(
            h.core.provisional.get(&peer_fp).unwrap().claimed.elapsed() < PROVISIONAL_TTL,
            "an expired candidate must release the slot to a newcomer"
        );
    }

    /// The regression the review asked for: a candidate is created on link A,
    /// and a VALID proof frame for it is delivered on link B. Opening under
    /// the key proves who produced the frame, not which socket carried it, so
    /// a LAN attacker forwarding a genuine encrypted frame must not be able to
    /// steer the contact route onto its own link.
    #[test]
    fn a_proof_frame_on_the_wrong_link_cannot_promote() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _p, first) = initiation_from(&peer_id);
        let _rx1 = inject_link(&mut h.core, 1, peer_fp);
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), first, false,
        );

        // The real peer reconnects on link 2 and becomes the candidate.
        let their_pending = Pending::start(&peer_id, Role::Initiator);
        let their_hs = their_pending.handshake().to_bytes();
        let rx2 = inject_unassociated_link(&mut h.core, 2);
        h.core.on_handshake_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), their_hs, false,
        );
        let reply = rx2.try_iter().find_map(|f| match f.kind {
            FrameKind::Handshake { body, response: true, .. } => Some(body),
            _ => None,
        }).expect("we answered on the candidate's link");
        let our_hs = Handshake::from_bytes(&reply).unwrap();
        let mut their_session = their_pending.complete(&peer_id, &our_hs, None).unwrap();
        let sealed = their_session.seal(&user_message(b"genuine proof")).unwrap();

        // The attacker forwards that genuine, unmodified frame over ITS link.
        let _rx3 = inject_unassociated_link(&mut h.core, 3);
        h.core.on_payload_frame(
            Some(3), *our_fp.as_bytes(), *peer_fp.as_bytes(), sealed.clone(),
        );

        assert!(
            h.core.provisional.contains_key(&peer_fp),
            "a frame on the wrong link must not promote the candidate"
        );
        assert_eq!(
            h.core.peer_link.get(&peer_fp),
            Some(&1),
            "the contact route must not move to the forwarder's link"
        );

        // Delivered on its own link, the same frame promotes normally.
        h.core.on_payload_frame(
            Some(2), *our_fp.as_bytes(), *peer_fp.as_bytes(), sealed,
        );
        assert!(!h.core.provisional.contains_key(&peer_fp), "promoted");
        assert_eq!(
            h.core.peer_link.get(&peer_fp),
            Some(&2),
            "promotion must move the route onto the proving link, or nothing \
             we send reaches the peer that just reconnected"
        );
    }

    // --- the caps are WIRED, not decoration ----------------------------------

    /// The wiring test. `limits` has its own unit tests, but a resource
    /// manager the transport never consults is decoration -- which is exactly
    /// the failure mode that shipped `verified` with no promotion path and a
    /// `record_download_provenance` with no callers.
    #[test]
    fn the_per_source_cap_actually_refuses_inbound_links() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        h.core.resources = crate::limits::ResourceManager::new(crate::limits::Limits {
            pending_per_ip: 2,
            ..Default::default()
        });

        // Real loopback sockets, so peer_addr() resolves and the accept path
        // is the one under test rather than a stub.
        let mut accepted = Vec::new();
        for _ in 0..4 {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).unwrap();
            let (server, _) = listener.accept().unwrap();
            drop(client);
            accepted.push(h.core.alloc_link(server, false));
        }
        let allowed = accepted.iter().filter(|r| r.is_some()).count();
        assert_eq!(
            allowed, 2,
            "all four came from 127.0.0.1; the per-source cap must stop at 2"
        );
        assert_eq!(h.core.denied_pending, 2, "refusals are counted");
        assert_eq!(h.core.resources.snapshot().0, 2, "only the admitted ones hold slots");
    }

    /// Closing a link must give its slot back, or the cap becomes a slow
    /// denial of service against ourselves.
    #[test]
    fn closing_a_link_returns_its_slot() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        h.core.resources = crate::limits::ResourceManager::new(crate::limits::Limits {
            pending_per_ip: 1,
            ..Default::default()
        });
        let mk = |core: &mut Core| {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).unwrap();
            let (server, _) = listener.accept().unwrap();
            drop(client);
            core.alloc_link(server, false)
        };
        let first = mk(&mut h.core).expect("first admitted");
        assert!(mk(&mut h.core).is_none(), "second refused at the cap");
        h.core.close_link(first);
        assert_eq!(h.core.resources.snapshot().0, 0, "slot released on close");
        assert!(mk(&mut h.core).is_some(), "and is reusable");
    }

    // --- mDNS is an address HINT, never identity -----------------------------

    /// An announcement from a peer on OUR protocol version. A candidate on
    /// another version is refused before it takes a cap slot (it could not
    /// produce a working session anyway), which `announce_version` covers.
    fn announce(core: &mut Core, fp: Fingerprint, addr: &str) {
        announce_version(core, fp, addr, crate::wire::PROTOCOL_VERSION);
    }

    fn announce_version(core: &mut Core, fp: Fingerprint, addr: &str, version: u16) {
        core.on_discovery_event(DiscoveryEvent::Resolved {
            fingerprint: fp,
            addr: addr.parse().unwrap(),
            version,
        });
    }

    /// THE ATTACK. Any LAN host can announce any fingerprint at its own
    /// address, and the record survives the 120s TTL. This used to overwrite
    /// the stored address outright, so a spoof redirected every dial for the
    /// victim to the attacker AND destroyed the real address on the way past.
    #[test]
    fn a_spoofed_announcement_cannot_displace_a_proven_address() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let victim = Identity::generate().fingerprint();

        announce(&mut h.core, victim, "192.0.2.10:7777");
        // Simulate the proof a completed handshake provides.
        h.core.lan_peers.get_mut(&victim).unwrap().verified =
            Some("192.0.2.10:7777".parse().unwrap());

        // The attacker announces the victim's fingerprint at its own address.
        announce(&mut h.core, victim, "192.0.2.66:7777");

        let entry = h.core.lan_peers.get(&victim).unwrap();
        assert_eq!(
            entry.verified,
            Some("192.0.2.10:7777".parse().unwrap()),
            "a spoofed announcement must not displace a proven address"
        );
        assert_eq!(
            entry.dial_addr(&BTreeSet::new()),
            Some("192.0.2.10:7777".parse().unwrap()),
            "dials must keep going to the address that actually answered"
        );
    }

    /// An unproven announcement must never be reported as the contact being
    /// online. Claiming so is precisely the lie the spoof is fishing for.
    #[test]
    fn an_announcement_alone_is_never_reported_verified() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let stranger = Identity::generate().fingerprint();
        announce(&mut h.core, stranger, "192.0.2.66:7777");

        let events = h.events.lock().unwrap();
        let appeared: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                TransportEvent::PeerAppeared { verified, .. } => Some(*verified),
                _ => None,
            })
            .collect();
        assert_eq!(appeared, vec![false], "mDNS alone cannot verify anything");
    }

    /// A spoofed goodbye must not take a contact offline while we are holding
    /// a live session with them: the session is better evidence than the LAN.
    #[test]
    fn a_spoofed_goodbye_cannot_drop_a_peer_we_hold_a_session_with() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _p, hs) = initiation_from(&peer_id);
        let _rx = inject_link(&mut h.core, 1, peer_fp);
        announce(&mut h.core, peer_fp, "192.0.2.10:7777");
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), hs, false,
        );
        assert!(h.core.sessions.contains_key(&peer_fp));

        h.core
            .on_discovery_event(DiscoveryEvent::Removed { fingerprint: peer_fp });

        assert!(
            h.core.lan_peers.contains_key(&peer_fp),
            "a goodbye must not drop a peer we are actively talking to"
        );
    }

    /// The other half, and the reason "keep verified forever" is WRONG. A
    /// contact who genuinely leaves must become unreachable, or a sender can
    /// never learn they cannot be reached — which is the entire reason
    /// offline is the one status announced automatically.
    #[test]
    fn a_genuine_departure_still_takes_the_peer_offline() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let peer = Identity::generate().fingerprint();
        announce(&mut h.core, peer, "192.0.2.10:7777");
        h.core.lan_peers.get_mut(&peer).unwrap().verified =
            Some("192.0.2.10:7777".parse().unwrap());
        // No session: the old proof is stale, not evidence of presence.
        assert!(!h.core.sessions.contains_key(&peer));

        h.core
            .on_discovery_event(DiscoveryEvent::Removed { fingerprint: peer });

        assert!(
            !h.core.lan_peers.contains_key(&peer),
            "a proven-but-departed contact must not look reachable forever"
        );
        assert!(h.events.lock().unwrap().iter().any(|e| matches!(
            e,
            TransportEvent::PeerDisappeared { .. }
        )));
    }

    // --- handshake replay ----------------------------------------------------

    /// The attack: a PASSIVE sniffer captures an initiation frame and later
    /// replays it verbatim. No private key is needed. Before the fix,
    /// `become_responder` completed it and `sessions.insert` replaced the live
    /// session, so our keys no longer matched the peer's and both sides talked
    /// past each other permanently.
    #[test]
    fn a_replayed_initiation_cannot_rekey_a_live_session() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _pending, handshake) = initiation_from(&peer_id);
        let _rx = inject_link(&mut h.core, 1, peer_fp);

        // First delivery: a legitimate initiation establishes a session.
        h.core.on_handshake_frame(
            Some(1),
            *our_fp.as_bytes(),
            *peer_fp.as_bytes(),
            handshake,
            false,
        );
        let established = h
            .core
            .sessions
            .get(&peer_fp)
            .expect("the first initiation must establish a session");
        assert!(established.seen_ephemerals.contains(&Handshake::from_bytes(&handshake).unwrap().ephemeral_public));

        // Replay the SAME bytes. This is all a sniffer has.
        h.core.on_handshake_frame(
            Some(1),
            *our_fp.as_bytes(),
            *peer_fp.as_bytes(),
            handshake,
            false,
        );

        // The session must still exist and must NOT have been replaced.
        assert!(
            h.core.sessions.contains_key(&peer_fp),
            "a replay must never destroy the live session"
        );
        // The link stays up: the real peer may be on it, and disconnecting
        // them over an attacker's frame turns a replay into a disconnect.
        assert!(
            h.core.links.contains_key(&1),
            "a replay must not drop the link"
        );
    }

    /// The fix must not break the case the clobber existed to serve: a peer
    /// that restarted redials with a FRESH ephemeral and legitimately rekeys.
    #[test]
    fn a_fresh_reinitiation_becomes_a_candidate_not_a_rekey() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _p1, first) = initiation_from(&peer_id);
        let _rx = inject_link(&mut h.core, 1, peer_fp);

        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), first, false,
        );
        let second = Pending::start(&peer_id, Role::Initiator).handshake().to_bytes();
        assert_ne!(first, second, "a fresh Pending must not reuse an ephemeral");

        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), second, false,
        );

        // Changed deliberately from "a rekey happens on arrival". A handshake
        // proves only knowledge of a PUBLIC key, so it now buys candidacy
        // rather than the session slot; promotion happens in
        // `on_payload_frame` once a frame opens under the new key.
        assert!(
            h.core.sessions.contains_key(&peer_fp),
            "the incumbent survives until the replacement proves itself"
        );
        assert!(
            h.core.provisional.contains_key(&peer_fp),
            "a fresh re-initiation is accepted as a candidate"
        );
    }

    /// The retained history is bounded, so an attacker cannot grow it.
    #[test]
    fn unproven_replacements_are_bounded() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let _rx = inject_link(&mut h.core, 1, Identity::generate().fingerprint());

        // Each distinct fingerprint that handshakes over a live session
        // leaves one candidate behind. Identities are free to mint, so the
        // set has to be capped or a stranger could grow it without bound.
        for _ in 0..(MAX_PROVISIONAL + 8) {
            let peer_id = Identity::generate();
            let (peer_fp, _p, hs) = initiation_from(&peer_id);
            let id = h.core.next_link_id;
            h.core.next_link_id += 1;
            let _r = inject_link(&mut h.core, id, peer_fp);
            // Establish, then immediately re-initiate to create a candidate.
            h.core.on_handshake_frame(
                Some(id), *our_fp.as_bytes(), *peer_fp.as_bytes(), hs, false,
            );
            let again = Pending::start(&peer_id, Role::Initiator).handshake().to_bytes();
            h.core.on_handshake_frame(
                Some(id), *our_fp.as_bytes(), *peer_fp.as_bytes(), again, false,
            );
        }
        assert!(
            h.core.provisional.len() <= MAX_PROVISIONAL,
            "unproven replacements must stay bounded, got {}",
            h.core.provisional.len()
        );
    }

    // --- the pre-existing tests, unchanged in substance ----------------------

    #[test]
    fn the_lower_fingerprints_initiation_wins_the_link_tie_break() {
        let low = [0x00; FINGERPRINT_LEN];
        let high = [0xff; FINGERPRINT_LEN];
        // On the low side: our outbound (initiated) link is canonical.
        assert!(link_is_canonical(&low, &high, true));
        assert!(!link_is_canonical(&low, &high, false));
        // On the high side the mirror image holds, so both peers agree on
        // which of the two simultaneous links survives.
        assert!(!link_is_canonical(&high, &low, true));
        assert!(link_is_canonical(&high, &low, false));
    }

    #[test]
    fn fingerprint_bytes_round_trip() {
        let fp = Identity::generate().fingerprint();
        assert_eq!(fp_from_bytes(fp.as_bytes()), Some(fp));
    }

    // --- multi-identity properties --------------------------------------------

    /// An inbound handshake to identity A is answered with identity A — on
    /// the wire AND in the resulting session keys — never with B.
    #[test]
    fn an_inbound_handshake_is_answered_with_the_dialed_identity() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let fp_a = id_a.fingerprint();
        let fp_b = id_b.fingerprint();
        let mut h = harness(vec![id_a, id_b]);

        let peer_id = Identity::generate();
        let (peer_fp, their_pending, their_hs) = initiation_from(&peer_id);
        let replies = inject_link(&mut h.core, 1, peer_fp);

        // The peer dials fingerprint A.
        h.core.on_handshake_frame(
            Some(1),
            *fp_a.as_bytes(),
            *peer_fp.as_bytes(),
            their_hs,
            false,
        );

        // The session is bound to A, not to the other identity we hold.
        assert_eq!(h.core.sessions.get(&peer_fp).map(|e| e.our_fp), Some(fp_a));
        assert_ne!(h.core.sessions.get(&peer_fp).map(|e| e.our_fp), Some(fp_b));

        // The on-wire reply names A as its sender and is marked a response.
        let reply = replies.try_recv().expect("a reply must have been routed");
        let our_hs = match reply.kind {
            FrameKind::Handshake {
                to,
                from,
                body,
                response,
            } => {
                assert!(response);
                assert_eq!(from, *fp_a.as_bytes());
                assert_eq!(to, *peer_fp.as_bytes());
                Handshake::from_bytes(&body).unwrap()
            }
            _ => panic!("expected a handshake reply"),
        };

        // And the session actually WORKS with A's key: the peer completes
        // against the reply and both directions decrypt.
        let mut peer_session = their_pending.complete(&peer_id, &our_hs, None).unwrap();
        let sealed = peer_session.seal(&user_message(b"hi")).unwrap();
        let opened = h
            .core
            .sessions
            .get_mut(&peer_fp)
            .unwrap()
            .session
            .open(&sealed)
            .unwrap();
        // The property is that both sides hold a working key, so assert on
        // the message the peer sent. Comparing raw bytes would pin the wire
        // encoding instead, which is the JSON-shape mistake.
        assert!(matches!(
            SessionEnvelope::decode(&opened).unwrap(),
            SessionEnvelope::Msg { body, .. } if body == "hi"
        ));

        let events = h.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e, TransportEvent::SessionEstablished { peer, .. } if *peer == peer_fp)));
    }

    /// A handshake to a fingerprint we do not hold is refused: no session, no
    /// answer on the wire, the direct link dropped — and no other key is
    /// substituted for the missing one.
    #[test]
    fn a_handshake_to_an_unknown_fingerprint_is_refused() {
        let id_a = Identity::generate();
        let mut h = harness(vec![id_a]);

        let peer_id = Identity::generate();
        let (peer_fp, _their_pending, their_hs) = initiation_from(&peer_id);
        let replies = inject_link(&mut h.core, 1, peer_fp);

        // Addressed to a fingerprint we never had (or one already removed).
        let stranger_fp = Identity::generate().fingerprint();
        h.core.on_handshake_frame(
            Some(1),
            *stranger_fp.as_bytes(),
            *peer_fp.as_bytes(),
            their_hs,
            false,
        );

        assert!(h.core.sessions.is_empty());
        assert!(h.core.links.is_empty(), "the direct link must be dropped");
        assert!(
            replies.try_recv().is_err(),
            "no answer may leave on the wire for an unknown fingerprint"
        );
        let events = h.events.lock().unwrap();
        assert!(!events
            .iter()
            .any(|e| matches!(e, TransportEvent::SessionEstablished { .. })));
    }

    /// Removing one identity tears down exactly its own sessions and stops it
    /// from answering; every other identity stays reachable.
    #[test]
    fn removing_one_identity_leaves_the_others_reachable() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let fp_a = id_a.fingerprint();
        let fp_b = id_b.fingerprint();
        let mut h = harness(vec![id_a, id_b]);

        // Live sessions on BOTH identities, driven through the inbound path.
        let peer1_id = Identity::generate();
        let peer2_id = Identity::generate();
        let (peer1, _p1, hs1) = initiation_from(&peer1_id);
        let (peer2, _p2, hs2) = initiation_from(&peer2_id);
        // The receivers MUST stay bound: dropping them disconnects the link
        // writers, every handshake reply then fails as Offline, and no session
        // is ever established.
        let _replies1 = inject_link(&mut h.core, 1, peer1);
        let _replies2 = inject_link(&mut h.core, 2, peer2);
        h.core
            .on_handshake_frame(Some(1), *fp_a.as_bytes(), *peer1.as_bytes(), hs1, false);
        h.core
            .on_handshake_frame(Some(2), *fp_b.as_bytes(), *peer2.as_bytes(), hs2, false);
        assert!(h.core.sessions.contains_key(&peer1));
        assert!(h.core.sessions.contains_key(&peer2));

        // Remove A: its session and its peer's link die; B is untouched.
        h.core.on_remove_identity(fp_a);
        assert!(!h.core.identities.contains_key(&fp_a));
        assert!(h.core.identities.contains_key(&fp_b));
        assert!(!h.core.sessions.contains_key(&peer1));
        assert!(h.core.peer_link.get(&peer1).is_none());
        assert!(h.core.sessions.contains_key(&peer2));

        // B still answers new inbound handshakes...
        let peer3_id = Identity::generate();
        let (peer3, _p3, hs3) = initiation_from(&peer3_id);
        let replies3 = inject_link(&mut h.core, 3, peer3);
        h.core
            .on_handshake_frame(Some(3), *fp_b.as_bytes(), *peer3.as_bytes(), hs3, false);
        assert_eq!(h.core.sessions.get(&peer3).map(|e| e.our_fp), Some(fp_b));
        assert!(replies3.try_recv().is_ok(), "identity B must keep answering");

        // ...while the removed A is now just another unknown fingerprint.
        let peer4_id = Identity::generate();
        let (peer4, _p4, hs4) = initiation_from(&peer4_id);
        let replies4 = inject_link(&mut h.core, 4, peer4);
        h.core
            .on_handshake_frame(Some(4), *fp_a.as_bytes(), *peer4.as_bytes(), hs4, false);
        assert!(!h.core.sessions.contains_key(&peer4));
        assert!(
            replies4.try_recv().is_err(),
            "a removed identity must not answer"
        );

        // Discovery is SHARED by every identity, so removing one must never
        // signal transport shutdown. An earlier draft called
        // `Discovery::shutdown()` here, which stored into the transport-wide
        // flag and tore down the listener, the relay, and the core loop.
        assert!(
            !h.core.shutdown.load(Ordering::SeqCst),
            "removing one identity must not shut the transport down"
        );
    }

    /// An outbound session presents exactly the identity the caller named.
    #[test]
    fn an_outbound_session_uses_the_named_identity() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let fp_a = id_a.fingerprint();
        let mut h = harness(vec![id_a, id_b]);

        let peer = Identity::generate().fingerprint();
        let sent = inject_link(&mut h.core, 1, peer);
        h.core.on_open_session(fp_a, peer);

        let frame = sent.try_recv().expect("the initiation must be routed");
        match frame.kind {
            FrameKind::Handshake {
                to, from, response, ..
            } => {
                assert!(!response);
                assert_eq!(from, *fp_a.as_bytes());
                assert_eq!(to, *peer.as_bytes());
            }
            _ => panic!("expected an initiation handshake"),
        }
        assert_eq!(h.core.pendings.get(&peer).map(|e| e.our_fp), Some(fp_a));
    }

    /// Naming an identity we do not hold fails closed: no pending is created
    /// and nothing is sent under a substituted key.
    #[test]
    fn an_outbound_session_with_an_unknown_identity_fails_closed() {
        let id_a = Identity::generate();
        let mut h = harness(vec![id_a]);

        let stranger = Identity::generate().fingerprint();
        let peer = Identity::generate().fingerprint();
        let sent = inject_link(&mut h.core, 1, peer);
        h.core.on_open_session(stranger, peer);

        assert!(h.core.pendings.is_empty());
        assert!(
            sent.try_recv().is_err(),
            "nothing may be sent under a substituted key"
        );
        let events = h.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e, TransportEvent::SessionFailed { .. })));
    }

    // --- relay identity selection (feature-gated) ------------------------------

    /// The relay gets EXACTLY the identity the config names — deterministically,
    /// never by HashMap order (randomized per process; that was the privacy
    /// bug) and never a fallback when the named identity is absent.
    #[cfg(feature = "relay-client")]
    #[test]
    fn the_relay_registers_exactly_the_chosen_identity() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let fp_a = id_a.fingerprint();
        let fp_b = id_b.fingerprint();
        let mut identities = HashMap::new();
        identities.insert(fp_a, Arc::new(id_a));
        identities.insert(fp_b, Arc::new(id_b));

        // Repeat: selection must be stable regardless of iteration order.
        for _ in 0..16 {
            let (url, fp, identity) = select_relay_identity(
                &identities,
                Some(RelayConfig {
                    url: "wss://relay.example/ws".into(),
                    identity: fp_b,
                }),
            )
            .expect("a held identity must be selected");
            assert_eq!(url, "wss://relay.example/ws");
            assert_eq!(fp, fp_b);
            assert_eq!(identity.fingerprint(), fp_b);
        }

        // An identity we do not hold selects NOTHING — no substitution.
        let stranger = Identity::generate().fingerprint();
        assert!(select_relay_identity(
            &identities,
            Some(RelayConfig {
                url: "wss://relay.example/ws".into(),
                identity: stranger,
            }),
        )
        .is_none());

        // No relay configured: nothing selected at all.
        assert!(select_relay_identity(&identities, None).is_none());
    }

    /// Starting with a relay identity the transport does not hold fails
    /// closed. Validation runs before anything is bound or spawned, so this
    /// test is hermetic: no listener, no announcement, no threads.
    #[cfg(feature = "relay-client")]
    #[test]
    fn transport_start_fails_closed_on_an_unheld_relay_identity() {
        let config = TransportConfig {
            identities: vec![Identity::generate()],
            relay: Some(RelayConfig {
                url: "wss://127.0.0.1:1/ws".into(),
                identity: Identity::generate().fingerprint(),
            }),
            relay_token: None,
            lan_port: 0,
            expected_peer_key: None,
        };
        assert!(matches!(
            Transport::start(config, |_| {}),
            Err(ChatError::UnknownIdentity)
        ));
    }

    // --- delivery: what a message may claim about itself ---------------------

    /// Establishes a session the way the transport really does, and hands
    /// back the peer's side so a test can act as the far end.
    fn established_pair(h: &mut Harness, our_fp: Fingerprint, peer_id: &Identity)
        -> (Fingerprint, Session, Receiver<Frame>)
    {
        let peer_fp = peer_id.fingerprint();
        let their_pending = Pending::start(peer_id, Role::Initiator);
        let their_hs = their_pending.handshake().to_bytes();
        let rx = inject_link(&mut h.core, 1, peer_fp);
        h.core.on_handshake_frame(
            Some(1), *our_fp.as_bytes(), *peer_fp.as_bytes(), their_hs, false,
        );
        // Our answer went out on the link; completing against it gives the
        // peer the matching session.
        let reply = rx
            .try_iter()
            .find_map(|f| match f.kind {
                FrameKind::Handshake { body, response: true, .. } => Some(body),
                _ => None,
            })
            .expect("we answered the initiation");
        let our_hs = Handshake::from_bytes(&reply).unwrap();
        let their_session = their_pending.complete(peer_id, &our_hs, None).unwrap();
        (peer_fp, their_session, rx)
    }

    fn deliveries(h: &Harness) -> Vec<(MessageId, Delivery)> {
        h.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                TransportEvent::Delivery { mid, state, .. } => Some((*mid, *state)),
                _ => None,
            })
            .collect()
    }

    /// THE gate-4 test. A message handed to a link that then dies must reach
    /// Failed, and must never have claimed Delivered on the way.
    #[test]
    fn killing_the_link_mid_send_reaches_failed_not_delivered() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core.on_send_text(peer_fp, "did this arrive?", envelope::new_message_id());
        let sent = deliveries(&h);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, Delivery::Sending);
        let mid = sent[0].0;

        // The link dies before any acknowledgement.
        h.core.remove_link(1);

        let after = deliveries(&h);
        assert!(
            after.iter().any(|(m, s)| *m == mid && *s == Delivery::Failed(SendFailure::LinkLost)),
            "a message lost with its link must say so: {after:?}"
        );
        assert!(
            !after.iter().any(|(_, s)| *s == Delivery::Delivered),
            "nothing may have claimed delivery: {after:?}"
        );
    }

    /// A redundant link closing must not condemn a message travelling on the
    /// surviving one.
    ///
    /// When both sides dial at once there are briefly two links and the
    /// tie-break closes one. Failing every outstanding message for the peer
    /// therefore reported a message Failed while it was on its way -- and the
    /// two-transport probe caught exactly that, as a delivered message
    /// reported failed. A false verdict pointing the other way is still a
    /// false verdict.
    #[test]
    fn closing_a_redundant_link_does_not_fail_a_message_on_another_route() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core
            .on_send_text(peer_fp, "on the good link", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;

        // A second, redundant link exists and is the one that dies.
        let _rx2 = inject_unassociated_link(&mut h.core, 2);
        h.core.remove_link(2);

        assert!(
            !deliveries(&h).iter().any(|(m, s)| *m == mid && s.is_terminal()),
            "a message on a different link must be untouched: {:?}",
            deliveries(&h)
        );

        // And it still delivers when the peer acknowledges it.
        let ack = their
            .seal(&SessionEnvelope::Ack { mid }.encode().unwrap())
            .unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, ack));
        assert!(deliveries(&h)
            .iter()
            .any(|(m, s)| *m == mid && *s == Delivery::Delivered));
    }

    /// The other half: when the link that CARRIED the message dies and there
    /// is still somewhere to try, it is retried rather than condemned -- the
    /// same treatment a relay reconnect gets, and for the same reason (it may
    /// already have arrived).
    #[test]
    fn a_message_stranded_by_a_link_is_retried_while_a_route_remains() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _their, _rx) = established_pair(&mut h, our_fp, &peer_id);
        // A LAN candidate means a route still exists after the link dies.
        announce(&mut h.core, peer_fp, "10.2.0.1:41205");

        h.core
            .on_send_text(peer_fp, "stranded", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        h.core.remove_link(1);

        assert!(
            !deliveries(&h).iter().any(|(m, s)| *m == mid && s.is_terminal()),
            "somewhere left to try means the message is not lost yet"
        );
        assert!(
            h.core
                .sessions
                .get(&peer_fp)
                .unwrap()
                .outstanding
                .contains_key(&mid),
            "it stays outstanding for the retry to pick up"
        );
    }

    /// The negative control for the test above, and it is what makes it mean
    /// anything: the SAME sequence with the acknowledgement fed first reaches
    /// Delivered, and the later link death does not take it back.
    #[test]
    fn an_acknowledged_message_is_not_undelivered_by_a_later_link_death() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core.on_send_text(peer_fp, "did this arrive?", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        // The peer read it off the link and acknowledges under its own key.
        assert_eq!(sent_mids(&rx, &mut their), vec![mid]);
        let ack = their.seal(&SessionEnvelope::Ack { mid }.encode().unwrap()).unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, ack));
        assert!(deliveries(&h).iter().any(|(m, s)| *m == mid && *s == Delivery::Delivered));

        h.core.remove_link(1);
        let states: Vec<Delivery> =
            deliveries(&h).into_iter().filter(|(m, _)| *m == mid).map(|(_, s)| s).collect();
        assert_eq!(
            states.last(),
            Some(&Delivery::Delivered),
            "a delivered message must not be un-delivered by anything: {states:?}"
        );
    }

    /// Only an acknowledgement that OPENED under the session key may deliver.
    /// A relay holds no key, so everything it could fabricate is fed here and
    /// must fail to move the message.
    #[test]
    fn nothing_a_relay_could_fabricate_can_claim_delivery() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core.on_send_text(peer_fp, "prove it", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        // 1. Our own ciphertext, reflected back at us as though the peer had
        //    sent it. A relay holds exactly these bytes and both fingerprints,
        //    so this is the strongest thing it can build without a key.
        //
        //    Payload bodies only, re-addressed to us: replaying the frame
        //    verbatim would be addressed to the PEER, which the transport
        //    correctly treats as a broken link and closes -- a different
        //    behaviour with its own reasoning, not this one.
        let reflected: Vec<Vec<u8>> = rx
            .try_iter()
            .filter_map(|f| match f.kind {
                FrameKind::Payload { body, .. } => Some(body),
                _ => None,
            })
            .collect();
        for body in reflected {
            h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, body));
        }
        // 2. A plaintext ack, unsealed. A relay knows the format.
        let plain = SessionEnvelope::Ack { mid }.encode().unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, plain));
        // 3. An ack sealed by a THIRD party who is not our peer.
        let stranger = Identity::generate();
        let (_sfp, mut stranger_session, _srx) = {
            let a = Pending::start(&stranger, Role::Initiator);
            let b = Pending::start(&peer_id, Role::Responder);
            let ahs = a.handshake();
            let bhs = b.handshake();
            let sa = a.complete(&stranger, &bhs, None).unwrap();
            let _sb = b.complete(&peer_id, &ahs, None).unwrap();
            (stranger.fingerprint(), sa, ())
        };
        let forged = stranger_session
            .seal(&SessionEnvelope::Ack { mid }.encode().unwrap())
            .unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, forged));

        assert!(
            !deliveries(&h).iter().any(|(_, s)| *s == Delivery::Delivered),
            "only the peer's own key may deliver: {:?}",
            deliveries(&h)
        );

        // Control: the real acknowledgement does deliver, so the assertions
        // above are about authentication and not about a broken path.
        let real = their.seal(&SessionEnvelope::Ack { mid }.encode().unwrap()).unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, real));
        assert!(deliveries(&h).iter().any(|(m, s)| *m == mid && *s == Delivery::Delivered));
    }

    /// A duplicate is acknowledged again -- the likeliest reason to see one
    /// is that our first acknowledgement was lost -- and shown once.
    #[test]
    fn a_duplicate_is_acknowledged_again_and_delivered_once() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);
        let _ = rx.try_iter().count();

        let mid = envelope::new_message_id();
        // The same message, resealed, exactly as a retry produces it.
        for _ in 0..2 {
            let sealed = their.seal(&user_message_with_id(mid, "only once")).unwrap();
            h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, sealed));
        }

        let shown = h
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, TransportEvent::Message { text, .. } if text == "only once"))
            .count();
        assert_eq!(shown, 1, "a retry must not show twice");

        let acks = rx
            .try_iter()
            .filter(|f| match &f.kind {
                FrameKind::Payload { body, .. } => matches!(
                    their.open(body).ok().map(|p| SessionEnvelope::decode(&p)),
                    Some(Ok(SessionEnvelope::Ack { .. }))
                ),
                _ => false,
            })
            .count();
        assert_eq!(acks, 2, "both copies must be acknowledged, or the sender gives up on a message we have");
    }

    /// The retry buffer is a BOUND, not a queue: past the cap the send is
    /// refused, and the map does not grow by one more.
    #[test]
    fn the_outstanding_cap_refuses_rather_than_grows() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        for i in 0..MAX_OUTSTANDING_PER_SESSION + 4 {
            h.core.on_send_text(peer_fp, &format!("message {i}"), envelope::new_message_id());
        }
        assert_eq!(
            h.core.sessions.get(&peer_fp).unwrap().outstanding.len(),
            MAX_OUTSTANDING_PER_SESSION,
            "the buffer must stop at the cap, not absorb the overflow"
        );
        assert!(
            h.events.lock().unwrap().iter().any(|e| matches!(
                e,
                TransportEvent::SendFailed { reason: SendFailure::TooManyOutstanding, .. }
            )),
            "and the sends past it must be refused out loud"
        );
    }

    /// Nothing is retained for a peer we have no session with. There is no
    /// path from "offline" to "held message" at all.
    #[test]
    fn an_offline_peer_leaves_nothing_behind() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let stranger = Identity::generate().fingerprint();

        h.core.on_send_text(stranger, "into the void", envelope::new_message_id());
        assert!(h.core.sessions.is_empty());
        assert!(
            h.events.lock().unwrap().iter().any(|e| matches!(
                e,
                TransportEvent::SendFailed { reason: SendFailure::NoSession, .. }
            )),
            "an offline send is refused, never held"
        );
        assert!(
            deliveries(&h).is_empty(),
            "and nothing was ever registered as in flight"
        );
    }

    /// Closing a session fails everything still in flight on it, and a late
    /// acknowledgement afterwards resurrects nothing.
    #[test]
    fn nothing_outstanding_survives_its_session() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core.on_send_text(peer_fp, "in flight", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        h.core.fail_session_messages(peer_fp, SendFailure::SessionEnded);
        h.core.sessions.remove(&peer_fp);
        assert!(deliveries(&h)
            .iter()
            .any(|(m, s)| *m == mid && *s == Delivery::Failed(SendFailure::SessionEnded)));

        let late = their.seal(&SessionEnvelope::Ack { mid }.encode().unwrap()).unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, late));
        assert!(
            !deliveries(&h).iter().any(|(_, s)| *s == Delivery::Delivered),
            "a late acknowledgement for a dead session delivers nothing"
        );
    }

    /// Bounded retry: exactly MAX_SEND_ATTEMPTS frames go out, then the
    /// message fails. Driven by a shortened deadline rather than by sleeping,
    /// because a test that takes twelve seconds is a test nobody runs.
    #[test]
    fn retry_is_bounded_and_then_gives_up() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        h.core.timings.ack_deadline = Duration::from_millis(0);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);
        let _ = rx.try_iter().count();

        h.core.on_send_text(peer_fp, "nobody answers", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        // Each tick past the deadline either resends or gives up.
        for _ in 0..MAX_SEND_ATTEMPTS + 2 {
            h.core.reap_unacknowledged();
        }

        let attempts = sent_mids(&rx, &mut their);
        assert_eq!(
            attempts.iter().filter(|m| **m == mid).count(),
            MAX_SEND_ATTEMPTS as usize,
            "every attempt carries the SAME id, and there are exactly {MAX_SEND_ATTEMPTS}"
        );
        assert!(
            deliveries(&h).iter().any(|(m, s)| *m == mid && *s == Delivery::Failed(SendFailure::NoAck)),
            "and then it gives up rather than retrying forever"
        );
    }

    /// The negative control for the retry bound: an acknowledgement stops the
    /// resends, so the mechanism is answering evidence and not just counting.
    #[test]
    fn an_acknowledgement_stops_the_retries() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        h.core.timings.ack_deadline = Duration::from_millis(0);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);
        let _ = rx.try_iter().count();

        h.core.on_send_text(peer_fp, "answered promptly", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        let ack = their.seal(&SessionEnvelope::Ack { mid }.encode().unwrap()).unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, ack));

        for _ in 0..MAX_SEND_ATTEMPTS + 2 {
            h.core.reap_unacknowledged();
        }
        let attempts = sent_mids(&rx, &mut their);
        assert_eq!(
            attempts.iter().filter(|m| **m == mid).count(),
            1,
            "an acknowledged message must not be resent"
        );
    }

    // --- liveness ------------------------------------------------------------

    /// "A quiet conversation is not a dead connection." Any authenticated
    /// frame counts, so a stream of acknowledgements with no messages at all
    /// must produce no probes.
    #[test]
    fn any_authenticated_frame_counts_as_liveness() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);
        let _ = rx.try_iter().count();

        let count_pings = |rx: &Receiver<Frame>, their: &mut Session| {
            rx.try_iter()
                .filter(|f| match &f.kind {
                    FrameKind::Payload { body, .. } => matches!(
                        their.open(body).ok().map(|p| SessionEnvelope::decode(&p)),
                        Some(Ok(SessionEnvelope::Ping { .. }))
                    ),
                    _ => false,
                })
                .count()
        };

        // Age the session well past the idle threshold, then let ONE
        // acknowledgement arrive. An ack for a message that is not even
        // outstanding is still an authenticated frame, which is the point.
        let stale = Instant::now() - h.core.timings.idle_before_ping * 4;
        h.core.sessions.get_mut(&peer_fp).unwrap().last_authenticated = stale;
        let ack = their
            .seal(&SessionEnvelope::Ack { mid: envelope::new_message_id() }.encode().unwrap())
            .unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, ack));
        h.core.probe_quiet_sessions();
        assert_eq!(
            count_pings(&rx, &mut their),
            0,
            "a session hearing acknowledgements must never be probed"
        );

        // CONTROL: with nothing arriving, the same staleness DOES probe. This
        // is what proves the assertion above is about the acknowledgement and
        // not about a probe path that never fires.
        h.core.sessions.get_mut(&peer_fp).unwrap().last_authenticated = stale;
        h.core.probe_quiet_sessions();
        assert_eq!(
            count_pings(&rx, &mut their),
            1,
            "silence must still be probed, or the test above proves nothing"
        );
    }

    /// Silence IS probed, and two unanswered probes end the session. One is
    /// not enough: a garbage-collection pause must not kill a conversation.
    #[test]
    fn two_unanswered_probes_end_a_session_and_one_does_not() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        h.core.timings.idle_before_ping = Duration::from_millis(0);
        h.core.timings.pong_deadline = Duration::from_millis(0);
        let peer_id = Identity::generate();
        let (peer_fp, _their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core.probe_quiet_sessions();
        assert!(h.core.sessions.contains_key(&peer_fp), "the first probe only asks");
        h.core.probe_quiet_sessions();
        assert!(h.core.sessions.contains_key(&peer_fp), "one missed answer is not a death");
        h.core.probe_quiet_sessions();
        assert!(
            !h.core.sessions.contains_key(&peer_fp),
            "but a session that answers nothing must not be reported as live forever"
        );
    }

    /// A probe is answered by ANY frame that opens, not only by a matching
    /// Pong -- opening proves freshness, because `Session::open` refuses a
    /// counter it has already passed, so a replayed frame cannot reach here
    /// at all. The nonce is what stops a replayed PONG specifically; the
    /// counter is what stops replays generally, and it is the stronger of
    /// the two.
    ///
    /// This matters because the alternative was worse: with the probe
    /// cleared only by a matching nonce, one lost Pong left it outstanding
    /// forever and an ACTIVE conversation was re-probed every ten seconds --
    /// the exact opposite of "a quiet conversation is not a dead one".
    #[test]
    fn any_authenticated_frame_answers_an_outstanding_probe() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        h.core.timings.idle_before_ping = Duration::from_millis(0);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core.probe_quiet_sessions();
        assert!(h.core.sessions.get(&peer_fp).unwrap().outstanding_ping.is_some());

        // An ordinary message from the peer -- nothing to do with the probe.
        let unrelated = their.seal(&user_message(b"still here")).unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, unrelated));
        assert!(
            h.core.sessions.get(&peer_fp).unwrap().outstanding_ping.is_none(),
            "a peer that just spoke has answered the question the probe asked"
        );

        // And the session is not counting against it either.
        assert_eq!(h.core.sessions.get(&peer_fp).unwrap().missed_pings, 0);

        // Control: silence still escalates. Without this the assertion above
        // would be satisfied by a probe mechanism that never fires.
        h.core.timings.pong_deadline = Duration::from_millis(0);
        h.core.probe_quiet_sessions();
        assert!(
            h.core.sessions.get(&peer_fp).unwrap().outstanding_ping.is_some(),
            "silence must still be probed"
        );
        h.core.probe_quiet_sessions();
        assert!(
            h.core.sessions.get(&peer_fp).unwrap().missed_pings > 0
                || !h.core.sessions.contains_key(&peer_fp),
            "an unanswered probe must count against the session"
        );
    }

    /// A ping must be answered, or the peer probing us tears the session
    /// down and the conversation dies for a reason that never existed.
    #[test]
    fn a_ping_is_answered_with_its_own_nonce() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, rx) = established_pair(&mut h, our_fp, &peer_id);
        let _ = rx.try_iter().count();

        let nonce = envelope::new_message_id();
        let ping = their.seal(&SessionEnvelope::Ping { nonce }.encode().unwrap()).unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, ping));

        let answered = rx.try_iter().any(|f| match &f.kind {
            FrameKind::Payload { body, .. } => matches!(
                their.open(body).ok().map(|p| SessionEnvelope::decode(&p)),
                Some(Ok(SessionEnvelope::Pong { nonce: n })) if n == nonce
            ),
            _ => false,
        });
        assert!(answered, "a probe must be answered with the nonce it carried");
    }




    /// A relay refusal must fail what we relayed and nothing else. The
    /// refusal names only the peer -- on purpose, so nobody can probe a
    /// fingerprint's connection health -- so the attribution is done here
    /// from what WE routed.
    #[test]
    fn a_relay_refusal_leaves_a_message_sent_over_the_lan_alone() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, _their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        // One message over the direct link, one marked as having gone via the
        // relay (which is what `Sent { link: None }` means).
        h.core.on_send_text(peer_fp, "over the lan", envelope::new_message_id());
        let lan_mid = deliveries(&h)[0].0;
        h.core.on_send_text(peer_fp, "over the relay", envelope::new_message_id());
        let relay_mid = deliveries(&h)[1].0;
        h.core
            .sessions
            .get_mut(&peer_fp)
            .unwrap()
            .outstanding
            .get_mut(&relay_mid)
            .unwrap()
            .last_route = Some(Routed::Sent { link: None });

        h.core.on_refused(*peer_fp.as_bytes());

        let states = deliveries(&h);
        assert!(
            states.iter().any(|(m, s)| *m == relay_mid
                && *s == Delivery::Failed(SendFailure::Refused)),
            "the relayed message must be failed: {states:?}"
        );
        assert!(
            !states.iter().any(|(m, s)| *m == lan_mid && s.is_terminal()),
            "a working LAN conversation is no business of the relay's: {states:?}"
        );
    }

    /// A relay reconnect must not condemn a message that may already have
    /// arrived. The client counts only frames still QUEUED; one already on
    /// the socket is not among them.
    #[test]
    fn a_relay_reconnect_retries_rather_than_condemns() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        let peer_id = Identity::generate();
        let (peer_fp, mut their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core
            .on_send_text(peer_fp, "did arrive", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        h.core
            .sessions
            .get_mut(&peer_fp)
            .unwrap()
            .outstanding
            .get_mut(&mid)
            .unwrap()
            .last_route = Some(Routed::Sent { link: None });

        h.core.on_relay_event(RelayEvent::Dropped { count: 1 });
        assert!(
            !deliveries(&h).iter().any(|(m, s)| *m == mid && s.is_terminal()),
            "a message that may be on the wire must not be declared lost"
        );

        // The peer HAD received it, and says so.
        let ack = their
            .seal(&SessionEnvelope::Ack { mid }.encode().unwrap())
            .unwrap();
        h.core.on_frame(Some(1), Frame::payload(our_fp, peer_fp, ack));
        assert!(
            deliveries(&h)
                .iter()
                .any(|(m, s)| *m == mid && *s == Delivery::Delivered),
            "an authenticated acknowledgement must not be lost to a relay hiccup"
        );
    }

    /// The other half: a message that genuinely did NOT arrive still ends at
    /// NoAck rather than sitting Sending forever.
    #[test]
    fn a_relay_reconnect_still_ends_a_message_nobody_answers() {
        let ours = Identity::generate();
        let our_fp = ours.fingerprint();
        let mut h = harness(vec![ours]);
        h.core.timings.ack_deadline = Duration::from_millis(0);
        let peer_id = Identity::generate();
        let (peer_fp, _their, _rx) = established_pair(&mut h, our_fp, &peer_id);

        h.core
            .on_send_text(peer_fp, "never arrived", envelope::new_message_id());
        let mid = deliveries(&h)[0].0;
        h.core
            .sessions
            .get_mut(&peer_fp)
            .unwrap()
            .outstanding
            .get_mut(&mid)
            .unwrap()
            .last_route = Some(Routed::Sent { link: None });
        h.core.on_relay_event(RelayEvent::Dropped { count: 1 });

        for _ in 0..MAX_SEND_ATTEMPTS + 2 {
            h.core.reap_unacknowledged();
        }
        assert!(
            deliveries(&h)
                .iter()
                .any(|(m, s)| *m == mid && *s == Delivery::Failed(SendFailure::NoAck)),
            "an unanswered message must still reach a verdict"
        );
    }

    /// Every path that ends a session must give its in-flight messages a
    /// verdict. `settle` is a no-op once the session is gone, so a path that
    /// removes first strands them at Sending -- and the UI only revises a
    /// bubble on a delivery event, so "Sending…" becomes permanent.
    ///
    /// Four separate paths did exactly that; this covers each production
    /// entry point rather than the helper they all now share.
    #[test]
    fn every_way_a_session_ends_settles_its_messages() {
        // 1. The user closing the chat.
        {
            let ours = Identity::generate();
            let our_fp = ours.fingerprint();
            let mut h = harness(vec![ours]);
            let peer_id = Identity::generate();
            let (peer_fp, _t, _rx) = established_pair(&mut h, our_fp, &peer_id);
            h.core
                .on_send_text(peer_fp, "in flight", envelope::new_message_id());
            let mid = deliveries(&h)[0].0;
            h.core
                .handle(CoreMsg::Command(Command::CloseSession { peer: peer_fp }));
            assert!(
                deliveries(&h).iter().any(|(m, s)| *m == mid && s.is_terminal()),
                "closing a chat must settle what was in flight"
            );
        }
        // 2. Revoking the identity the session runs on.
        {
            let ours = Identity::generate();
            let our_fp = ours.fingerprint();
            let mut h = harness(vec![ours]);
            let peer_id = Identity::generate();
            let (peer_fp, _t, _rx) = established_pair(&mut h, our_fp, &peer_id);
            h.core
                .on_send_text(peer_fp, "in flight", envelope::new_message_id());
            let mid = deliveries(&h)[0].0;
            h.core.on_remove_identity(our_fp);
            assert!(
                deliveries(&h).iter().any(|(m, s)| *m == mid && s.is_terminal()),
                "revoking an identity must settle its sessions' messages"
            );
        }
        // 3. A peer reconnecting and its replacement session being promoted.
        {
            let ours = Identity::generate();
            let our_fp = ours.fingerprint();
            let mut h = harness(vec![ours]);
            let peer_id = Identity::generate();
            let (peer_fp, _t, _rx) = established_pair(&mut h, our_fp, &peer_id);
            h.core
                .on_send_text(peer_fp, "in flight", envelope::new_message_id());
            let mid = deliveries(&h)[0].0;

            // The peer restarts: a fresh initiation is held aside, then earns
            // the slot by producing a frame that opens under its key.
            let their_pending = Pending::start(&peer_id, Role::Initiator);
            let their_hs = their_pending.handshake().to_bytes();
            let rx2 = inject_unassociated_link(&mut h.core, 2);
            h.core.on_handshake_frame(
                Some(2),
                *our_fp.as_bytes(),
                *peer_fp.as_bytes(),
                their_hs,
                false,
            );
            let reply = rx2
                .try_iter()
                .find_map(|f| match f.kind {
                    FrameKind::Handshake {
                        body,
                        response: true,
                        ..
                    } => Some(body),
                    _ => None,
                })
                .expect("we answered the initiation");
            let our_hs = Handshake::from_bytes(&reply).unwrap();
            let mut their_new = their_pending.complete(&peer_id, &our_hs, None).unwrap();
            let proof = their_new.seal(&user_message(b"i am back")).unwrap();
            h.core
                .on_frame(Some(2), Frame::payload(our_fp, peer_fp, proof));

            assert!(
                deliveries(&h).iter().any(|(m, s)| *m == mid && s.is_terminal()),
                "a rekey must settle what the old session still had in flight: {:?}",
                deliveries(&h)
            );
        }
    }

    /// mDNS reports every address an interface has, and some cannot be
    /// dialled as written. A link-local IPv6 address needs a scope
    /// identifier to say which interface it means and the announcement
    /// carries none.
    ///
    /// This is not hypothetical tidiness: announcements arrive one at a time,
    /// a link-local often arrives FIRST, and a failed dial used to end the
    /// whole session attempt. The two-transport probe failed one run in three
    /// on exactly this.
    #[test]
    fn an_address_that_cannot_be_dialled_is_not_a_candidate() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        for undialable in [
            "[fe80::d085:c7ff:fe2c:3a8b]:43919", // link-local, no scope
            "0.0.0.0:41205",                     // unspecified
            "[::]:41205",
            "127.0.0.1:0", // no port
        ] {
            let fp = Identity::generate().fingerprint();
            announce(&mut h.core, fp, undialable);
            assert!(
                !h.core.lan_peers.contains_key(&fp),
                "{undialable} is not somewhere we could connect to"
            );
        }
        // Control: ordinary addresses ARE stored, so the filter is not simply
        // rejecting everything.
        for dialable in ["127.0.0.1:41205", "192.168.1.4:41205", "[2001:db8::1]:41205"] {
            let fp = Identity::generate().fingerprint();
            announce(&mut h.core, fp, dialable);
            assert!(
                h.core.lan_peers.contains_key(&fp),
                "{dialable} is perfectly dialable"
            );
        }
    }

    /// A peer's addresses arrive separately and out of order, so the one that
    /// works is often not the first. All of them are remembered, most recent
    /// first, and bounded.
    #[test]
    fn several_announced_addresses_are_remembered_and_bounded() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let peer = Identity::generate().fingerprint();
        for i in 0..MAX_ADDRS_PER_PEER + 4 {
            announce(&mut h.core, peer, &format!("10.1.0.{}:41205", i + 1));
        }
        let entry = h.core.lan_peers.get(&peer).unwrap();
        assert_eq!(
            entry.candidates.len(),
            MAX_ADDRS_PER_PEER,
            "remembered addresses must be bounded"
        );
        assert_eq!(
            entry.candidate(),
            Some(format!("10.1.0.{}:41205", MAX_ADDRS_PER_PEER + 4).parse().unwrap()),
            "the most recent announcement leads"
        );

        // A dial that has tried the newest moves to the next, rather than
        // giving up on a peer that announced eight places to look.
        let mut tried = BTreeSet::new();
        let first = entry.dial_addr(&tried).unwrap();
        tried.insert(first);
        let second = entry.dial_addr(&tried).unwrap();
        assert_ne!(first, second);
    }

    /// A proven address is preferred over any announcement, so a spoofed
    /// record cannot redirect traffic away from a contact already reached.
    #[test]
    fn a_verified_address_is_dialled_before_any_announcement() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let peer = Identity::generate().fingerprint();
        announce(&mut h.core, peer, "10.1.0.1:41205");
        let proven: SocketAddr = "10.1.0.9:41205".parse().unwrap();
        h.core.lan_peers.get_mut(&peer).unwrap().verified = Some(proven);
        announce(&mut h.core, peer, "10.1.0.2:41205");
        assert_eq!(
            h.core.lan_peers.get(&peer).unwrap().dial_addr(&BTreeSet::new()),
            Some(proven),
            "a later announcement must not steal a proven address"
        );
    }

    // --- mDNS caps -----------------------------------------------------------

    /// A flood must not displace a peer we have PROVEN. An unverified,
    /// unused, stale candidate may lose its slot -- that is what stops a
    /// flood locking the table shut forever -- but a verified address never
    /// can.
    #[test]
    fn a_candidate_flood_cannot_evict_a_verified_peer() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let established = Identity::generate().fingerprint();
        announce(&mut h.core, established, "10.0.0.9:9000");
        // Proven: a handshake at this address answered for the key. And made
        // old, so only the verified flag is protecting it.
        {
            let peer = h.core.lan_peers.get_mut(&established).unwrap();
            peer.verified = Some("10.0.0.9:9000".parse().unwrap());
            peer.last_seen = Instant::now() - CANDIDATE_EVICTABLE_AFTER * 2;
        }
        for i in 0..MAX_LAN_CANDIDATES + 32 {
            announce(
                &mut h.core,
                Identity::generate().fingerprint(),
                &format!("10.0.{}.{}:9000", i / 200, (i % 200) + 10),
            );
        }
        assert!(
            h.core.lan_peers.len() <= MAX_LAN_CANDIDATES,
            "the table must stay bounded"
        );
        assert!(
            h.core.lan_peers.contains_key(&established),
            "a proven address must survive any flood"
        );
    }

    /// The other half, and the reason eviction exists at all: a table filled
    /// by a flood must not stay shut against a real contact forever. mDNS is
    /// unauthenticated, so a hostile host can always degrade discovery on a
    /// LAN; what it must not do is exhaust memory or lock us out permanently.
    #[test]
    fn a_full_table_still_admits_a_contact_by_giving_up_a_stale_candidate() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        for i in 0..MAX_LAN_CANDIDATES {
            announce(
                &mut h.core,
                Identity::generate().fingerprint(),
                &format!("10.0.{}.{}:9000", i / 200, (i % 200) + 10),
            );
        }
        assert_eq!(h.core.lan_peers.len(), MAX_LAN_CANDIDATES, "full");

        // While every candidate is fresh, nothing may be taken: a live LAN
        // must not lose peers to a newcomer.
        let too_soon = Identity::generate().fingerprint();
        announce(&mut h.core, too_soon, "10.0.9.9:9000");
        assert!(
            !h.core.lan_peers.contains_key(&too_soon),
            "a fresh table must refuse rather than churn"
        );

        // Once the flood's entries are stale, a genuine contact gets in.
        let stale = Instant::now() - CANDIDATE_EVICTABLE_AFTER * 2;
        for peer in h.core.lan_peers.values_mut() {
            peer.last_seen = stale;
        }
        let contact = Identity::generate().fingerprint();
        announce(&mut h.core, contact, "10.0.9.10:9000");
        assert!(
            h.core.lan_peers.contains_key(&contact),
            "a flood must not lock a real contact out permanently"
        );
        assert!(h.core.lan_peers.len() <= MAX_LAN_CANDIDATES);
    }

    /// A known peer keeps updating its address even while the table is full,
    /// or a flood would freeze every contact at a stale address.
    #[test]
    fn a_known_peer_can_still_move_while_the_table_is_full() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let known = Identity::generate().fingerprint();
        announce(&mut h.core, known, "10.0.0.9:9000");
        for i in 0..MAX_LAN_CANDIDATES + 8 {
            announce(
                &mut h.core,
                Identity::generate().fingerprint(),
                &format!("10.0.{}.{}:9000", i / 200, (i % 200) + 10),
            );
        }
        announce(&mut h.core, known, "10.0.0.9:9100");
        assert_eq!(
            h.core.lan_peers.get(&known).and_then(|p| p.candidate()),
            Some("10.0.0.9:9100".parse().unwrap()),
            "an existing contact must not be frozen at a stale address by a flood"
        );
    }

    /// A candidate on another protocol version cannot produce a working
    /// session -- the version is bound into the transcript -- so it must not
    /// spend a cap slot.
    #[test]
    fn a_candidate_on_another_protocol_version_is_not_stored() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        let stale = Identity::generate().fingerprint();
        announce_version(
            &mut h.core,
            stale,
            "10.0.0.9:9000",
            crate::wire::PROTOCOL_VERSION.wrapping_sub(1),
        );
        assert!(
            !h.core.lan_peers.contains_key(&stale),
            "a peer we could not talk to must not take a slot"
        );
        // Control: the same announcement on our version IS stored.
        announce(&mut h.core, stale, "10.0.0.9:9000");
        assert!(h.core.lan_peers.contains_key(&stale));
    }

    /// Refusals are reported, but rate-limited: one event per refused
    /// announcement would make our own warning the flood's amplifier.
    #[test]
    fn a_capped_table_says_so_once_not_once_per_refusal() {
        let ours = Identity::generate();
        let mut h = harness(vec![ours]);
        for i in 0..MAX_LAN_CANDIDATES + 8 {
            announce(
                &mut h.core,
                Identity::generate().fingerprint(),
                &format!("10.0.{}.{}:9000", i / 200, (i % 200) + 10),
            );
        }
        let notices = h
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, TransportEvent::CandidatesCapped))
            .count();
        assert_eq!(
            notices, 1,
            "the user is told the list may be incomplete, once -- not per refusal"
        );
    }
}
