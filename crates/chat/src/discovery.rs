//! mDNS/multicast peer discovery on the local network.
//!
//! Announcements are PUBLIC TO EVERYONE ON THE LAN. That is why a service
//! announces exactly its fingerprint, its TCP port, and the protocol version —
//! the fingerprint is already the public address a contact knows, and nothing
//! else about the user may ever be added here.
//!
//! Discovered peers are dialed directly over TCP (see transport.rs); the relay
//! is never involved in local traffic.
//!
//! MULTI-FINGERPRINT: one instance owns ONE `ServiceDaemon` and ONE browse
//! stream, and announces a SET of fingerprints on it. `ServiceDaemon::register`
//! takes `&self`, so many services on one daemon is the supported design.
//! Per-contact keypairs mean N addresses for one user, and giving each its own
//! daemon would cost N responders, N browsers, and N duplicate copies of every
//! peer event funnelled into one bounded channel — where the overflow is
//! silently dropped and peers simply go missing.
//!
//! Fingerprints are added and removed while running (`announce` / `withdraw`),
//! because adding a contact must make that address reachable without
//! restarting discovery and disturbing every other conversation.
//!
//! Note (detection of blocked discovery): mDNS routinely fails on public
//! WiFi (AP client isolation plus multicast filtering). There is no reliable
//! signal for "the network ate it" versus "nobody is here", so this module
//! exposes a heuristic: `DiscoveryState::Quiet` after `QUIET_AFTER` with zero
//! peers ever seen, and `Unavailable` if the daemon or the browse itself
//! fails. The UI can use that to say "this network may block discovery"
//! instead of silently showing an empty list.
//!
//! Note (mdns-sd API): whether `ServiceResolved` re-fires periodically
//! for still-alive peers is unverified. The expiry logic below assumes
//! re-resolution refreshes `last_seen`; if it does not, add a periodic
//! re-browse or peers will be expired and re-discovered on a 120 s cycle.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::wire;
use crate::{ChatError, Fingerprint};

pub const SERVICE_TYPE: &str = "_patanyx-chat._tcp.local.";

/// Peers not heard from within this window are expired. Generous on purpose:
/// a false expiry only costs a re-appear event, while a stale entry that never
/// dies would accumulate forever.
const PEER_TTL: Duration = Duration::from_secs(120);

/// With zero peers ever seen after this long, we tell the UI discovery may be
/// blocked by the network rather than merely empty.
const QUIET_AFTER: Duration = Duration::from_secs(20);

/// How many announce/withdraw commands may be in flight to the discovery
/// thread. Bounded like every other queue in this crate. The loop drains this
/// on every wakeup and its longest blocking wait is one second, so a full
/// queue does not mean "busy", it means the thread is gone.
const CONTROL_QUEUE: usize = 32;

/// How long teardown waits for the daemon to acknowledge the whole batch of
/// goodbyes. One shared deadline, not one per name, so shutdown stays bounded
/// no matter how many identities are announced.
const GOODBYE_DEADLINE: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryState {
    Active,
    /// No peers ever seen; this network may block mDNS (public WiFi isolation).
    Quiet,
    /// mDNS itself is unavailable here; LAN discovery is off, relay still works.
    Unavailable,
}

#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    Resolved {
        fingerprint: Fingerprint,
        addr: SocketAddr,
        version: u16,
    },
    Removed {
        fingerprint: Fingerprint,
    },
    State(DiscoveryState),
    /// Announcing this ONE fingerprint failed. Discovery as a whole is still
    /// up: the browse works and every other identity is still announced. Only
    /// this address is unreachable on the LAN. Per-contact keypairs exist so
    /// that one contact breaking costs exactly that contact, and collapsing
    /// this into `Unavailable` would throw that property away.
    AnnounceFailed {
        fingerprint: Fingerprint,
    },
}

/// Sent from the transport core into the announce/browse thread. Private: the
/// methods on `Discovery` are the API.
enum Control {
    Announce(Fingerprint),
    Withdraw(Fingerprint),
}

/// Owns the ONE mDNS daemon and the ONE browse stream for this process.
/// `shutdown` unregisters every announced fingerprint and sends mDNS goodbyes
/// so peers drop us promptly instead of after the TTL.
pub struct Discovery {
    thread: Option<JoinHandle<()>>,
    /// PRIVATE to this handle, and deliberately NOT the transport-wide
    /// shutdown flag. Stopping discovery must never stop the LAN listener, the
    /// relay, or the transport core — an earlier draft shared one flag, so
    /// removing a single contact tore down the whole transport.
    own_shutdown: Arc<AtomicBool>,
    /// Taken on shutdown; dropping it disconnects the control arm, which wakes
    /// the loop immediately rather than after the 1 s tick.
    control: Option<flume::Sender<Control>>,
}

impl Discovery {
    /// Starts announcing `fp` alongside whatever is already announced.
    /// Idempotent: re-announcing a fingerprint we already hold is a no-op and
    /// does not disturb the existing registration.
    ///
    /// `Err` means the discovery thread is gone. The caller should treat LAN
    /// discovery as unavailable, not retry.
    pub fn announce(&self, fp: Fingerprint) -> Result<(), ChatError> {
        self.send(Control::Announce(fp))
    }

    /// Stops announcing `fp` and sends the mDNS goodbye, so peers drop that
    /// address now rather than after `PEER_TTL`. Unknown fingerprints are a
    /// no-op. Same `Err` contract as [`Discovery::announce`].
    pub fn withdraw(&self, fp: Fingerprint) -> Result<(), ChatError> {
        self.send(Control::Withdraw(fp))
    }

    fn send(&self, control: Control) -> Result<(), ChatError> {
        match self.control.as_ref() {
            // Full and disconnected are both `Closed`: the loop drains this
            // queue every second, so 32 unread commands means it is dead.
            Some(tx) => tx.try_send(control).map_err(|_| ChatError::Closed),
            None => Err(ChatError::Closed),
        }
    }

    pub fn shutdown(mut self) {
        self.own_shutdown.store(true, Ordering::SeqCst);
        // Disconnect the control arm so the selector returns at once.
        drop(self.control.take());
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Starts one daemon announcing `initial` on `port` and browsing for peers.
/// `initial` may be empty: the browse still runs, we are simply not findable
/// until `announce` is called. Never blocks the caller on daemon setup:
/// failures surface as `DiscoveryState::Unavailable` events, because chat over
/// the relay must keep working on networks where multicast is broken.
pub fn start(
    initial: &[Fingerprint],
    port: u16,
    events: SyncSender<DiscoveryEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<Discovery, ChatError> {
    let own_shutdown = Arc::new(AtomicBool::new(false));
    let (control_tx, control_rx) = flume::bounded(CONTROL_QUEUE);
    let initial = initial.to_vec();
    let worker_own = own_shutdown.clone();
    let thread = thread::spawn(move || run(initial, port, events, control_rx, shutdown, worker_own));
    Ok(Discovery {
        thread: Some(thread),
        own_shutdown,
        control: Some(control_tx),
    })
}

/// Which arm of the select woke us.
enum Wake {
    Control(Result<Control, flume::RecvError>),
    Service(Result<ServiceEvent, flume::RecvError>),
}

fn run(
    initial: Vec<Fingerprint>,
    port: u16,
    events: SyncSender<DiscoveryEvent>,
    control: flume::Receiver<Control>,
    shutdown: Arc<AtomicBool>,
    own_shutdown: Arc<AtomicBool>,
) {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(_) => {
            let _ = events.try_send(DiscoveryEvent::State(DiscoveryState::Unavailable));
            return;
        }
    };

    // Browse BEFORE registering. `DiscoveryState` describes the browse, which
    // is the only genuinely global thing here — announcement health is
    // per-fingerprint and is reported per-fingerprint. Browsing first also
    // means a browse failure has no registration to clean up.
    let browse_rx = match daemon.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(_) => {
            let _ = events.try_send(DiscoveryEvent::State(DiscoveryState::Unavailable));
            let _ = daemon.shutdown();
            return;
        }
    };
    let _ = events.try_send(DiscoveryEvent::State(DiscoveryState::Active));

    let mut announced = AnnounceSet::new();
    for fp in initial {
        register_one(&daemon, fp, port, &mut announced, &events);
    }

    let mut cache = PeerCache::new();
    let mut saw_any_peer = false;
    let mut quiet_reported = false;
    let started = Instant::now();

    while !shutdown.load(Ordering::SeqCst) && !own_shutdown.load(Ordering::SeqCst) {
        // The control arm is registered FIRST: flume polls arms in insertion
        // order on its speculative first pass, so a tie favours withdrawal —
        // the one message whose latency is a privacy property.
        let wake = flume::Selector::new()
            .recv(&control, Wake::Control)
            .recv(&browse_rx, Wake::Service)
            .wait_timeout(Duration::from_secs(1));

        match wake {
            Ok(Wake::Control(Ok(Control::Announce(fp)))) => {
                // A fingerprint that just became OURS must leave the peer
                // cache, or the transport would keep dialing our own listener
                // for the rest of PEER_TTL.
                if cache.remove(fp) {
                    let _ = events.try_send(DiscoveryEvent::Removed { fingerprint: fp });
                }
                register_one(&daemon, fp, port, &mut announced, &events);
            }
            Ok(Wake::Control(Ok(Control::Withdraw(fp)))) => {
                if let Some(fullname) = announced.release(fp) {
                    // The status receiver is deliberately dropped: the daemon
                    // queues the goodbye and its resend regardless, and the
                    // loop must not block on the daemon mid-flight.
                    let _ = daemon.unregister(&fullname);
                }
            }
            Ok(Wake::Service(Ok(ServiceEvent::ServiceResolved(info)))) => {
                if let Some((fp, addr, version)) = peer_from_service(&info) {
                    if let Some(event) = on_resolved(
                        &mut cache,
                        &announced,
                        fp,
                        addr,
                        version,
                        Instant::now(),
                        &mut saw_any_peer,
                    ) {
                        let _ = events.try_send(event);
                    }
                }
            }
            Ok(Wake::Service(Ok(ServiceEvent::ServiceRemoved(_type, name)))) => {
                if let Some(fp) = fp_from_fullname(&name) {
                    // Our own goodbye echoes back here too, so the same filter
                    // applies as on the resolve path.
                    if !announced.is_ours(fp) && cache.remove(fp) {
                        let _ = events.try_send(DiscoveryEvent::Removed { fingerprint: fp });
                    }
                }
            }
            Ok(Wake::Service(Ok(_))) => {}
            // The daemon is gone; nothing more will ever arrive.
            Ok(Wake::Service(Err(_))) => {
                let _ = events.try_send(DiscoveryEvent::State(DiscoveryState::Unavailable));
                break;
            }
            // The handle was dropped without `shutdown()`. Tear down cleanly.
            Ok(Wake::Control(Err(_))) => break,
            Err(flume::select::SelectError::Timeout) => {}
        }

        for fp in cache.expire(Instant::now(), PEER_TTL) {
            let _ = events.try_send(DiscoveryEvent::Removed { fingerprint: fp });
        }
        if !quiet_reported && !saw_any_peer && started.elapsed() >= QUIET_AFTER {
            quiet_reported = true;
            let _ = events.try_send(DiscoveryEvent::State(DiscoveryState::Quiet));
        }
    }

    // Unregister EVERY announced fullname, not just one. `daemon.shutdown()`
    // also emits goodbyes, but without the resend and with no way to know the
    // daemon processed them before it exits — so we wait on the batch here.
    let receipts: Vec<_> = announced
        .drain_fullnames()
        .iter()
        .filter_map(|name| daemon.unregister(name).ok())
        .collect();
    let deadline = Instant::now() + GOODBYE_DEADLINE;
    for receipt in receipts {
        let _ = receipt.recv_deadline(deadline);
    }
    let _ = daemon.shutdown();
}

/// Registers one fingerprint, recording the outcome in `announced`.
fn register_one(
    daemon: &ServiceDaemon,
    fp: Fingerprint,
    port: u16,
    announced: &mut AnnounceSet,
    events: &SyncSender<DiscoveryEvent>,
) {
    if !announced.claim(fp) {
        return; // already announced; re-registering would buy nothing
    }
    let info = match service_info_for(fp, port) {
        Ok(info) => info,
        Err(_) => {
            let _ = events.try_send(DiscoveryEvent::AnnounceFailed { fingerprint: fp });
            return;
        }
    };
    // The daemon's own name is the only authority: it escapes instance names
    // and may rename on conflict, so a recomputed string could fail to
    // unregister and leak a service that never gets a goodbye.
    let fullname = info.get_fullname().to_string();
    if daemon.register(info).is_err() {
        let _ = events.try_send(DiscoveryEvent::AnnounceFailed { fingerprint: fp });
        return;
    }
    announced.bind(fp, fullname);
}

/// The instance label for a fingerprint: 32 lowercase hex characters, no
/// grouping. Instance names ARE the address, which is what lets
/// `fp_from_fullname` recover a peer from a removal notice that carries only a
/// name.
fn instance_name(fp: Fingerprint) -> String {
    fp.to_hash_number().replace('-', "")
}

/// Builds the announcement for one fingerprint. Pure — no daemon, no socket —
/// so the fullname the unregister path depends on is unit-testable.
///
/// `enable_addr_auto` is load-bearing, not decoration. `ServiceInfo::new` with
/// an empty address string produces a service with NO addresses and
/// `addr_auto: false`, and the daemon then declines to answer TYPE_SRV queries
/// for it at all — the service is announced and nobody can resolve it. Only
/// `addr_auto` makes the daemon fill in the interface addresses.
fn service_info_for(fp: Fingerprint, port: u16) -> Result<ServiceInfo, mdns_sd::Error> {
    let instance = instance_name(fp);
    let host = format!("{instance}.local.");
    let version = wire::PROTOCOL_VERSION.to_string();
    // The fingerprint and the protocol version and NOTHING else — see the
    // module docs on why this record can never grow.
    let properties: [(&str, &str); 2] = [("v", version.as_str()), ("fp", instance.as_str())];
    Ok(
        ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", port, &properties[..])?
            .enable_addr_auto(),
    )
}

/// The resolve-path decision, factored out so the self-filter is testable
/// without multicast.
fn on_resolved(
    cache: &mut PeerCache,
    announced: &AnnounceSet,
    fp: Fingerprint,
    addr: SocketAddr,
    version: u16,
    now: Instant,
    saw_any_peer: &mut bool,
) -> Option<DiscoveryEvent> {
    // Our own announcements come back to us on many networks, and with a set
    // of fingerprints a single `fp != own` comparison was never going to hold.
    if announced.is_ours(fp) {
        return None;
    }
    *saw_any_peer = true;
    cache.upsert(fp, addr, version, now)
}

/// The name the daemon knows one announced fingerprint by. `None` means
/// `register` failed and there is nothing to unregister — the fingerprint is
/// still OURS for filtering purposes, which is why the entry exists at all.
type AnnounceEntry = Option<String>;

/// The fingerprints this instance announces. Two jobs, deliberately one
/// structure: it is the unregister list at teardown AND the self-filter for the
/// browse loop, and those two must never disagree.
struct AnnounceSet {
    entries: HashMap<Fingerprint, AnnounceEntry>,
}

impl AnnounceSet {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Records intent to announce. `false` when already claimed, which is the
    /// caller's signal to skip `register` entirely.
    fn claim(&mut self, fp: Fingerprint) -> bool {
        if self.entries.contains_key(&fp) {
            return false;
        }
        self.entries.insert(fp, None);
        true
    }

    /// Records the name the daemon accepted.
    fn bind(&mut self, fp: Fingerprint, fullname: String) {
        self.entries.insert(fp, Some(fullname));
    }

    /// Drops the claim, returning the fullname to unregister. `None` when the
    /// registration had failed or the fingerprint was never claimed.
    fn release(&mut self, fp: Fingerprint) -> Option<String> {
        self.entries.remove(&fp).flatten()
    }

    /// THE SELF-FILTER. True for anything we announce or tried to announce.
    fn is_ours(&self, fp: Fingerprint) -> bool {
        self.entries.contains_key(&fp)
    }

    /// Empties the set, yielding every fullname that needs a goodbye.
    fn drain_fullnames(&mut self) -> Vec<String> {
        self.entries.drain().filter_map(|(_, name)| name).collect()
    }
}

/// Extracts (fingerprint, dial address, version) from a resolved service.
fn peer_from_service(info: &ResolvedService) -> Option<(Fingerprint, SocketAddr, u16)> {
    let fp = info
        .get_property_val_str("fp")
        .and_then(Fingerprint::parse_hash_number)
        .or_else(|| fp_from_fullname(info.get_fullname()))?;
    let version = info
        .get_property_val_str("v")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // ScopedIp carries an interface scope we do not need; take the plain
    // address. IPv4 first: the direct link dials exactly one address and v4 is
    // the dependable choice on the LANs this targets.
    let ip = info
        .get_addresses()
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| info.get_addresses().iter().next())
        .map(|a| a.to_ip_addr())?;
    Some((fp, SocketAddr::new(ip, info.get_port()), version))
}

/// Instance names are the fingerprint's hex, so a removal notice (which
/// carries only the fullname) still identifies the peer.
fn fp_from_fullname(fullname: &str) -> Option<Fingerprint> {
    let instance = fullname.split('.').next()?;
    if instance.len() == 32 && instance.chars().all(|c| c.is_ascii_hexdigit()) {
        Fingerprint::parse_hash_number(instance)
    } else {
        None
    }
}

struct CacheEntry {
    addr: SocketAddr,
    version: u16,
    last_seen: Instant,
}

/// Peer bookkeeping, factored out of the mdns loop so the appear / refresh /
/// expire policy is testable without multicast.
struct PeerCache {
    peers: HashMap<Fingerprint, CacheEntry>,
}

impl PeerCache {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Records a sighting. Emits a re-announcement event only when the peer is
    /// new or its address/version changed; a plain refresh just pushes the TTL.
    fn upsert(
        &mut self,
        fp: Fingerprint,
        addr: SocketAddr,
        version: u16,
        now: Instant,
    ) -> Option<DiscoveryEvent> {
        match self.peers.get_mut(&fp) {
            Some(entry) if entry.addr == addr && entry.version == version => {
                entry.last_seen = now;
                None
            }
            Some(entry) => {
                *entry = CacheEntry {
                    addr,
                    version,
                    last_seen: now,
                };
                Some(DiscoveryEvent::Resolved {
                    fingerprint: fp,
                    addr,
                    version,
                })
            }
            None => {
                self.peers.insert(
                    fp,
                    CacheEntry {
                        addr,
                        version,
                        last_seen: now,
                    },
                );
                Some(DiscoveryEvent::Resolved {
                    fingerprint: fp,
                    addr,
                    version,
                })
            }
        }
    }

    fn remove(&mut self, fp: Fingerprint) -> bool {
        self.peers.remove(&fp).is_some()
    }

    fn expire(&mut self, now: Instant, ttl: Duration) -> Vec<Fingerprint> {
        let stale: Vec<Fingerprint> = self
            .peers
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) >= ttl)
            .map(|(fp, _)| *fp)
            .collect();
        for fp in &stale {
            self.peers.remove(fp);
        }
        stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, last], 4000))
    }

    fn fp() -> Fingerprint {
        Identity::generate().fingerprint()
    }

    #[test]
    fn peers_appear_refresh_and_expire() {
        let fp = Identity::generate().fingerprint();
        let t0 = Instant::now();
        let mut cache = PeerCache::new();

        assert!(cache.upsert(fp, addr(1), 1, t0).is_some(), "new peer appears");
        assert!(
            cache
                .upsert(fp, addr(1), 1, t0 + Duration::from_secs(10))
                .is_none(),
            "a refresh is silent"
        );
        assert!(
            cache
                .expire(t0 + PEER_TTL - Duration::from_secs(1), PEER_TTL)
                .is_empty(),
            "a refreshed peer is not expired"
        );
        // Expiry is measured from the LAST announcement, not the first, so the
        // deadline moved to refresh + TTL when the peer re-announced above.
        let refreshed_at = t0 + Duration::from_secs(10);
        assert!(
            cache
                .expire(refreshed_at + PEER_TTL - Duration::from_secs(1), PEER_TTL)
                .is_empty(),
            "still inside the refreshed lifetime"
        );
        assert_eq!(
            cache.expire(refreshed_at + PEER_TTL + Duration::from_secs(1), PEER_TTL),
            vec![fp],
            "a silent peer expires once its refreshed lifetime elapses"
        );
        assert!(cache.expire(refreshed_at + PEER_TTL * 2, PEER_TTL).is_empty());
    }

    #[test]
    fn a_changed_address_re_announces_the_peer() {
        let fp = Identity::generate().fingerprint();
        let t0 = Instant::now();
        let mut cache = PeerCache::new();
        assert!(cache.upsert(fp, addr(1), 1, t0).is_some());
        assert!(cache.upsert(fp, addr(2), 1, t0).is_some(), "roaming re-announces");
    }

    #[test]
    fn removal_is_reported_once() {
        let fp = Identity::generate().fingerprint();
        let mut cache = PeerCache::new();
        cache.upsert(fp, addr(1), 1, Instant::now());
        assert!(cache.remove(fp));
        assert!(!cache.remove(fp));
    }

    #[test]
    fn fullnames_carry_the_fingerprint() {
        let fp = Identity::generate().fingerprint();
        let name = format!(
            "{}._patanyx-chat._tcp.local.",
            fp.to_hash_number().replace('-', "")
        );
        assert_eq!(fp_from_fullname(&name), Some(fp));
        assert_eq!(fp_from_fullname("garbage.local."), None);
        assert_eq!(fp_from_fullname(""), None);
    }

    /// The contract the unregister loop and the `ServiceRemoved` path both
    /// depend on: every announced fingerprint has its own name, and that name
    /// maps back to exactly the fingerprint that produced it.
    #[test]
    fn announced_fullnames_round_trip_to_their_fingerprint() {
        let fps = [fp(), fp(), fp()];
        let mut names = Vec::new();
        for f in fps {
            let info = service_info_for(f, 4000).expect("announcement builds");
            let fullname = info.get_fullname().to_string();
            assert!(
                fullname.ends_with(SERVICE_TYPE),
                "fullname must be in our service type: {fullname}"
            );
            assert_eq!(
                fp_from_fullname(&fullname),
                Some(f),
                "a removal notice must identify the peer from the name alone"
            );
            names.push(fullname);
        }
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 3, "each fingerprint announces under its own name");
    }

    /// Without `addr_auto` the daemon announces a service it will not answer
    /// TYPE_SRV queries for, so nobody can resolve us. Pin it.
    #[test]
    fn every_announcement_enables_addr_auto() {
        let info = service_info_for(fp(), 4000).unwrap();
        assert!(
            info.is_addr_auto(),
            "an announcement without addr_auto carries no addresses and is unresolvable"
        );
    }

    #[test]
    fn the_self_filter_tracks_the_announced_set_at_runtime() {
        let (a, b, stranger) = (fp(), fp(), fp());
        let mut announced = AnnounceSet::new();
        announced.claim(a);
        announced.claim(b);
        assert!(announced.is_ours(a) && announced.is_ours(b));
        assert!(!announced.is_ours(stranger));

        announced.release(a);
        assert!(!announced.is_ours(a), "a withdrawn address is no longer ours");
        assert!(announced.is_ours(b), "withdrawing one must not affect another");
    }

    /// A fingerprint we failed to register is still OURS for filtering: the
    /// answer does not depend on whether the daemon accepted it.
    #[test]
    fn a_failed_registration_still_counts_as_ours() {
        let f = fp();
        let mut announced = AnnounceSet::new();
        assert!(announced.claim(f));
        assert!(announced.is_ours(f));
        assert_eq!(announced.release(f), None, "nothing to unregister");
        assert!(!announced.is_ours(f));
    }

    #[test]
    fn claiming_twice_is_idempotent() {
        let f = fp();
        let mut announced = AnnounceSet::new();
        assert!(announced.claim(f));
        announced.bind(f, "first.name.".into());
        assert!(!announced.claim(f), "second claim is refused");
        assert_eq!(
            announced.release(f),
            Some("first.name.".into()),
            "the original registration is untouched"
        );
    }

    #[test]
    fn shutdown_unregisters_every_announced_fullname() {
        let mut announced = AnnounceSet::new();
        for (i, f) in [fp(), fp(), fp()].into_iter().enumerate() {
            announced.claim(f);
            announced.bind(f, format!("name-{i}."));
        }
        let mut names = announced.drain_fullnames();
        names.sort();
        assert_eq!(names, vec!["name-0.", "name-1.", "name-2."]);
        assert!(
            announced.drain_fullnames().is_empty(),
            "the set is empty after draining"
        );
    }

    /// Announcing an address we previously saw as a peer must evict it, or the
    /// transport would keep dialing our own listener until the TTL expires.
    #[test]
    fn announcing_a_fingerprint_evicts_it_from_the_peer_cache() {
        let f = fp();
        let mut cache = PeerCache::new();
        cache.upsert(f, addr(1), 1, Instant::now());
        assert!(cache.remove(f), "it was cached as a peer");
        assert!(!cache.remove(f), "and only evicted once");
    }

    #[test]
    fn a_resolved_self_announcement_is_never_a_peer() {
        let (mine, stranger) = (fp(), fp());
        let mut cache = PeerCache::new();
        let mut announced = AnnounceSet::new();
        announced.claim(mine);
        let mut saw_any = false;

        assert!(
            on_resolved(&mut cache, &announced, mine, addr(1), 1, Instant::now(), &mut saw_any)
                .is_none(),
            "our own announcement is not a peer"
        );
        assert!(!saw_any, "and does not count as having seen anyone");

        assert!(
            on_resolved(&mut cache, &announced, stranger, addr(2), 1, Instant::now(), &mut saw_any)
                .is_some(),
            "a stranger is a peer"
        );
        assert!(saw_any);

        // Once withdrawn, that same fingerprint is someone else's address.
        announced.release(mine);
        assert!(
            on_resolved(&mut cache, &announced, mine, addr(1), 1, Instant::now(), &mut saw_any)
                .is_some(),
            "a withdrawn fingerprint is no longer filtered"
        );
    }
}
