//! One resource manager, one lease, atomic state transitions.
//!
//! Everything an unauthenticated remote party can cause us to allocate passes
//! through here: an accepted socket, an unproven candidate session, an
//! authenticated link. Each is represented by a single `Lease` that CHANGES
//! STATE rather than by separate guards acquired from separate pools.
//!
//! That is deliberate. Independent semaphores for the same object introduce
//! accounting gaps between release and reacquire, double counting when a path
//! forgets which pool it drew from, permit leaks on the early-return paths
//! this codebase is full of, and the specific failure of a legitimate session
//! failing promotion because an unrelated cap filled in the instant between
//! releasing one permit and taking the next. One lease that transitions under
//! one short lock has none of those failure modes.
//!
//! The lock is held only for counter arithmetic. No socket I/O, no callbacks,
//! no teardown happens while it is held.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::Fingerprint;

/// Every bound in one place, so a reviewer can read the whole resource policy
/// without grepping for scattered constants.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Sockets accepted but not yet through a handshake, across all sources.
    pub global_pending: usize,
    /// Pending sockets from ONE source address. A global cap alone lets a
    /// single host consume every slot; a per-source cap alone is weak against
    /// many sources. Both are needed.
    pub pending_per_ip: usize,
    /// Absolute, from `accept()`. NOT renewable — see `Lease::deadline`.
    pub handshake_deadline: Duration,
    /// Unproven replacement sessions, across all contacts.
    pub global_provisional: usize,
    /// Unproven replacements for ONE contact. Two, not one: a single slot
    /// lets a hostile or stalled candidate block the legitimate peer, which
    /// is the starvation this exists to prevent.
    pub provisional_per_contact: usize,
    /// Absolute proof deadline for a candidate. Activity does not extend it.
    pub provisional_deadline: Duration,
    /// Authenticated links across all contacts.
    pub global_authenticated: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            global_pending: 64,
            pending_per_ip: 4,
            handshake_deadline: Duration::from_secs(15),
            global_provisional: 32,
            provisional_per_contact: 2,
            provisional_deadline: Duration::from_secs(30),
            global_authenticated: 256,
        }
    }
}

/// Collapses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) onto the IPv4 address it
/// denotes.
///
/// Without this the per-source cap is bypassed by asking for the same peer in
/// its other spelling: a dual-stack listener reports the same host under two
/// addresses that compare unequal, so an attacker gets two budgets for free.
pub fn canonical_source(addr: &SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Provisional,
    Authenticated,
    Released,
}

#[derive(Default)]
struct Counts {
    pending: usize,
    pending_by_ip: HashMap<IpAddr, usize>,
    provisional: usize,
    provisional_by_contact: HashMap<Fingerprint, usize>,
    authenticated: usize,
}

/// Why a lease could not be taken or advanced. Reported as counters, never
/// per-fingerprint, so `/health`-style output cannot become a presence oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    GlobalPending,
    PerSourcePending,
    GlobalProvisional,
    PerContactProvisional,
    GlobalAuthenticated,
}

pub struct ResourceManager {
    limits: Limits,
    counts: Mutex<Counts>,
}

impl ResourceManager {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            counts: Mutex::new(Counts::default()),
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Takes a pending lease for a freshly accepted socket, or refuses.
    pub fn accept(self: &Arc<Self>, source: IpAddr, now: Instant) -> Result<Lease, Denied> {
        let mut c = self.counts.lock().expect("resource counts poisoned");
        if c.pending >= self.limits.global_pending {
            return Err(Denied::GlobalPending);
        }
        let per_ip = c.pending_by_ip.get(&source).copied().unwrap_or(0);
        if per_ip >= self.limits.pending_per_ip {
            return Err(Denied::PerSourcePending);
        }
        c.pending += 1;
        *c.pending_by_ip.entry(source).or_insert(0) += 1;
        Ok(Lease {
            manager: self.clone(),
            state: State::Pending,
            source,
            contact: None,
            // ABSOLUTE. Stamped once, here, and never restamped: a deadline
            // that resets on activity lets a peer send one byte before each
            // expiry and hold a thread forever.
            deadline: now + self.limits.handshake_deadline,
        })
    }

    /// Snapshot for operational reporting. Counts only.
    pub fn snapshot(&self) -> (usize, usize, usize) {
        let c = self.counts.lock().expect("resource counts poisoned");
        (c.pending, c.provisional, c.authenticated)
    }

    fn release(&self, state: State, source: IpAddr, contact: Option<Fingerprint>) {
        let mut c = self.counts.lock().expect("resource counts poisoned");
        match state {
            State::Pending => {
                c.pending = c.pending.saturating_sub(1);
                if let Some(n) = c.pending_by_ip.get_mut(&source) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        c.pending_by_ip.remove(&source);
                    }
                }
            }
            State::Provisional => {
                c.provisional = c.provisional.saturating_sub(1);
                if let Some(fp) = contact {
                    if let Some(n) = c.provisional_by_contact.get_mut(&fp) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            c.provisional_by_contact.remove(&fp);
                        }
                    }
                }
            }
            State::Authenticated => {
                c.authenticated = c.authenticated.saturating_sub(1);
            }
            State::Released => {}
        }
    }
}

/// One remotely-created object's claim on resources, from accept to teardown.
///
/// Dropping it releases whatever state it currently holds, which is the whole
/// point: this codebase has enough early returns that manual decrements would
/// eventually become their own denial of service.
pub struct Lease {
    manager: Arc<ResourceManager>,
    state: State,
    source: IpAddr,
    contact: Option<Fingerprint>,
    deadline: Instant,
}

impl Lease {
    /// The ABSOLUTE deadline for whatever stage this lease is in. Never
    /// extended by activity.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    pub fn source(&self) -> IpAddr {
        self.source
    }

    /// Pending -> Provisional, atomically: the pending slot is released and
    /// the candidate slot taken under ONE lock, so no other caller can slip
    /// in between and make a legitimate promotion fail on a cap that was free
    /// a microsecond earlier.
    pub fn to_provisional(&mut self, contact: Fingerprint, now: Instant) -> Result<(), Denied> {
        debug_assert_eq!(self.state, State::Pending);
        let mut c = self.manager.counts.lock().expect("resource counts poisoned");
        if c.provisional >= self.manager.limits.global_provisional {
            return Err(Denied::GlobalProvisional);
        }
        let per_contact = c
            .provisional_by_contact
            .get(&contact)
            .copied()
            .unwrap_or(0);
        if per_contact >= self.manager.limits.provisional_per_contact {
            return Err(Denied::PerContactProvisional);
        }
        c.pending = c.pending.saturating_sub(1);
        if let Some(n) = c.pending_by_ip.get_mut(&self.source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.pending_by_ip.remove(&self.source);
            }
        }
        c.provisional += 1;
        *c.provisional_by_contact.entry(contact).or_insert(0) += 1;
        drop(c);
        self.state = State::Provisional;
        self.contact = Some(contact);
        // A fresh absolute deadline for the new stage, stamped once.
        self.deadline = now + self.manager.limits.provisional_deadline;
        Ok(())
    }

    /// Provisional (or Pending, for a first session) -> Authenticated.
    pub fn to_authenticated(&mut self, contact: Fingerprint) -> Result<(), Denied> {
        let mut c = self.manager.counts.lock().expect("resource counts poisoned");
        if c.authenticated >= self.manager.limits.global_authenticated {
            return Err(Denied::GlobalAuthenticated);
        }
        match self.state {
            State::Pending => {
                c.pending = c.pending.saturating_sub(1);
                if let Some(n) = c.pending_by_ip.get_mut(&self.source) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        c.pending_by_ip.remove(&self.source);
                    }
                }
            }
            State::Provisional => {
                c.provisional = c.provisional.saturating_sub(1);
                if let Some(fp) = self.contact {
                    if let Some(n) = c.provisional_by_contact.get_mut(&fp) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            c.provisional_by_contact.remove(&fp);
                        }
                    }
                }
            }
            State::Authenticated | State::Released => return Ok(()),
        }
        c.authenticated += 1;
        drop(c);
        self.state = State::Authenticated;
        self.contact = Some(contact);
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.manager.release(self.state, self.source, self.contact);
        self.state = State::Released;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn mgr(l: Limits) -> Arc<ResourceManager> {
        ResourceManager::new(l)
    }

    #[test]
    fn the_global_pending_cap_refuses_excess_connections() {
        let m = mgr(Limits {
            global_pending: 3,
            pending_per_ip: 99,
            ..Default::default()
        });
        let now = Instant::now();
        let held: Vec<_> = (0..3)
            .map(|i| m.accept(ip(&format!("192.0.2.{i}")), now).unwrap())
            .collect();
        assert_eq!(m.accept(ip("192.0.2.9"), now).err(), Some(Denied::GlobalPending));
        drop(held);
        assert!(m.accept(ip("192.0.2.9"), now).is_ok(), "slots return");
    }

    #[test]
    fn one_source_cannot_consume_every_slot() {
        let m = mgr(Limits {
            global_pending: 64,
            pending_per_ip: 2,
            ..Default::default()
        });
        let now = Instant::now();
        let _a = m.accept(ip("192.0.2.7"), now).unwrap();
        let _b = m.accept(ip("192.0.2.7"), now).unwrap();
        assert_eq!(
            m.accept(ip("192.0.2.7"), now).err(),
            Some(Denied::PerSourcePending)
        );
        // A different host is unaffected, which is the whole point.
        assert!(m.accept(ip("192.0.2.8"), now).is_ok());
    }

    /// The per-source cap is bypassed by spelling the same host two ways
    /// unless mapped addresses are collapsed. A dual-stack listener really
    /// does report both forms.
    #[test]
    fn ipv4_mapped_ipv6_is_the_same_source() {
        let v4: SocketAddr = "192.0.2.7:1234".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:1234".parse().unwrap();
        assert_eq!(canonical_source(&v4), canonical_source(&mapped));

        let m = mgr(Limits {
            pending_per_ip: 1,
            ..Default::default()
        });
        let now = Instant::now();
        let _a = m.accept(canonical_source(&v4), now).unwrap();
        assert_eq!(
            m.accept(canonical_source(&mapped), now).err(),
            Some(Denied::PerSourcePending),
            "the same host in its other spelling must not get a second budget"
        );
    }

    #[test]
    fn a_real_ipv6_address_is_left_alone() {
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(canonical_source(&v6), ip("2001:db8::1"));
    }

    /// A byte-at-a-time peer must still expire. The deadline is stamped at
    /// accept and never restamped, so activity cannot push it out.
    #[test]
    fn the_handshake_deadline_is_absolute_not_renewable() {
        let m = mgr(Limits {
            handshake_deadline: Duration::from_secs(15),
            ..Default::default()
        });
        let t0 = Instant::now();
        let lease = m.accept(ip("192.0.2.1"), t0).unwrap();
        assert!(!lease.expired(t0 + Duration::from_secs(14)));
        assert!(lease.expired(t0 + Duration::from_secs(15)));
        // There is deliberately no API to extend it: `deadline` is read-only
        // and nothing restamps it. If a renewal method ever appears, this
        // test is the reason it should not.
        assert_eq!(lease.deadline(), t0 + Duration::from_secs(15));
    }

    #[test]
    fn every_drop_releases_its_lease_whatever_state_it_is_in() {
        let m = mgr(Limits::default());
        let now = Instant::now();
        let fp = Identity::generate().fingerprint();
        {
            let _pending = m.accept(ip("192.0.2.1"), now).unwrap();
            assert_eq!(m.snapshot().0, 1);
        }
        assert_eq!(m.snapshot(), (0, 0, 0), "pending released on drop");
        {
            let mut l = m.accept(ip("192.0.2.1"), now).unwrap();
            l.to_provisional(fp, now).unwrap();
            assert_eq!(m.snapshot(), (0, 1, 0), "pending freed as provisional taken");
        }
        assert_eq!(m.snapshot(), (0, 0, 0), "provisional released on drop");
        {
            let mut l = m.accept(ip("192.0.2.1"), now).unwrap();
            l.to_provisional(fp, now).unwrap();
            l.to_authenticated(fp).unwrap();
            assert_eq!(m.snapshot(), (0, 0, 1));
        }
        assert_eq!(m.snapshot(), (0, 0, 0), "authenticated released on drop");
    }

    /// The starvation fix. One stalled or hostile candidate must not stop the
    /// real peer taking the other slot.
    #[test]
    fn one_stalled_candidate_cannot_block_a_second_for_the_same_contact() {
        let m = mgr(Limits {
            provisional_per_contact: 2,
            ..Default::default()
        });
        let now = Instant::now();
        let fp = Identity::generate().fingerprint();

        let mut hostile = m.accept(ip("192.0.2.66"), now).unwrap();
        hostile.to_provisional(fp, now).unwrap();

        let mut genuine = m.accept(ip("192.0.2.10"), now).unwrap();
        assert!(
            genuine.to_provisional(fp, now).is_ok(),
            "a squatter holding one slot must not deny the real peer another"
        );

        // The third is refused: two is a cap, not a suggestion.
        let mut third = m.accept(ip("192.0.2.77"), now).unwrap();
        assert_eq!(
            third.to_provisional(fp, now),
            Err(Denied::PerContactProvisional)
        );
    }

    #[test]
    fn a_failed_candidate_returns_its_slot() {
        let m = mgr(Limits {
            provisional_per_contact: 1,
            ..Default::default()
        });
        let now = Instant::now();
        let fp = Identity::generate().fingerprint();
        {
            let mut failed = m.accept(ip("192.0.2.66"), now).unwrap();
            failed.to_provisional(fp, now).unwrap();
        }
        let mut next = m.accept(ip("192.0.2.10"), now).unwrap();
        assert!(next.to_provisional(fp, now).is_ok(), "slot came back");
    }

    /// Candidate slots are per contact, so one contact under attack must not
    /// consume another contact's budget.
    #[test]
    fn candidate_pressure_on_one_contact_does_not_starve_another() {
        let m = mgr(Limits {
            provisional_per_contact: 1,
            ..Default::default()
        });
        let now = Instant::now();
        let a = Identity::generate().fingerprint();
        let b = Identity::generate().fingerprint();
        let mut la = m.accept(ip("192.0.2.66"), now).unwrap();
        la.to_provisional(a, now).unwrap();
        let mut lb = m.accept(ip("192.0.2.67"), now).unwrap();
        assert!(lb.to_provisional(b, now).is_ok());
    }

    /// The reason for one lease rather than separate guards: releasing the
    /// pending slot and taking the candidate slot happen under ONE lock, so a
    /// legitimate promotion cannot fail on a cap that filled in between.
    #[test]
    fn the_transition_is_atomic_with_no_accounting_gap() {
        let m = mgr(Limits {
            global_pending: 1,
            provisional_per_contact: 2,
            ..Default::default()
        });
        let now = Instant::now();
        let fp = Identity::generate().fingerprint();
        let mut l = m.accept(ip("192.0.2.1"), now).unwrap();
        assert_eq!(m.snapshot(), (1, 0, 0));
        l.to_provisional(fp, now).unwrap();
        // Exactly one slot moved; nothing was double counted and nothing
        // leaked, which a release-then-reacquire pair could get wrong.
        assert_eq!(m.snapshot(), (0, 1, 0));
    }

    #[test]
    fn the_provisional_deadline_is_also_absolute() {
        let m = mgr(Limits {
            provisional_deadline: Duration::from_secs(30),
            ..Default::default()
        });
        let t0 = Instant::now();
        let fp = Identity::generate().fingerprint();
        let mut l = m.accept(ip("192.0.2.1"), t0).unwrap();
        l.to_provisional(fp, t0).unwrap();
        assert!(!l.expired(t0 + Duration::from_secs(29)));
        assert!(l.expired(t0 + Duration::from_secs(30)));
    }
}
