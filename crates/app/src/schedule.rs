//! The browser's only self-initiated network activity, and its timing.
//!
//! Until now nothing here checked anything on its own: updates happened when
//! the user pressed "Check now", and the blocklist never refreshed at all. That
//! is a defensible privacy stance and an indefensible security one -- an
//! install nobody touches never learns a fix exists, and a blocklist that
//! refreshes on a button press protects nobody against a domain registered this
//! morning.
//!
//! So the browser now reaches out by itself, and because that is a real change
//! in what the product does on the network, everything about it is stated
//! rather than buried.
//!
//! # What a check reveals, and what jitter is for
//!
//! Each check is one unconditional GET to a URL identical for every install:
//! no version, no token, no query string, no cache validator. The server learns
//! an IP address and a timestamp. Nothing distinguishes one install from
//! another, so the response is CDN-cacheable and most checks never reach the
//! origin at all.
//!
//! JITTER IS NOT DECORATION. An exact interval turns "when this machine is
//! awake" into a fingerprint: a server seeing requests at 14:03:07, 15:03:07,
//! 16:03:07 is watching one identifiable install, even with no identifier in
//! the request. Spreading each deadline over a wide window breaks that
//! correlation, and the first check is delayed too, so a fleet of installs
//! started by the same deploy does not arrive in lockstep.
//!
//! # Notify, never install
//!
//! A due update check runs steps 1 and 2 of the pipeline -- verify the
//! manifest, decide -- and stops. It downloads nothing and installs nothing.
//! The existing guarantee (nothing installs without an explicit accept) is
//! untouched; what changes is that the user finds out there is something to
//! accept.

use std::time::{Duration, Instant};

/// Roughly hourly, which is what what was asked for and what the blocklist
/// needs to be worth having: phishing domains often live hours, so a daily
/// refresh would miss most of what it exists to catch.
const BLOCKLIST_EVERY: Duration = Duration::from_secs(60 * 60);

/// Updates change far less often than blocklists, and each check is a
/// disclosure event. Six hours finds a release the same day without making the
/// browser chatty.
const UPDATE_EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// Jitter as a FRACTION of the interval, applied in both directions. A quarter
/// of an hour of spread on an hourly check is enough to destroy the
/// correlation an exact interval creates without letting the list get stale.
const JITTER_NUMERATOR: u64 = 1;
const JITTER_DENOMINATOR: u64 = 4;

/// Nothing fires immediately at startup. A browser that phones home the
/// instant it opens makes launch time observable, and start-up is the moment
/// it should be doing the user's work rather than its own.
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// Fetch and verify the blocklist manifest; swap the list if it is newer.
    Blocklist,
    /// Verify the update manifest and decide. Downloads nothing.
    Update,
}

/// Per-process randomness with no dependency and no unsafe.
///
/// `RandomState` is seeded by the OS once per process, which is exactly the
/// property jitter needs: unpredictable to an observer, stable enough to be
/// cheap, and available identically on Windows and Linux. Reading /dev/urandom
/// would not work on Windows, and pulling in `rand` for a few bits of timing
/// noise would mean regenerating the Flatpak offline source list.
///
/// This is NOT cryptographic randomness and must never be used as if it were.
/// It decides when to make a request; nothing depends on it being unguessable
/// to an attacker who already controls the network.
fn noise(seed: u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(seed);
    hasher.finish()
}

/// `base` spread by +/- `base * JITTER_NUMERATOR / JITTER_DENOMINATOR`.
fn jittered(base: Duration, seed: u64) -> Duration {
    let secs = base.as_secs().max(1);
    let spread = (secs * JITTER_NUMERATOR / JITTER_DENOMINATOR).max(1);
    // Uniform over [-spread, +spread].
    let offset = (noise(seed) % (spread * 2 + 1)) as i64 - spread as i64;
    let adjusted = (secs as i64 + offset).max(1) as u64;
    Duration::from_secs(adjusted)
}

/// When each periodic task is next due.
///
/// Pure: it owns no clock and performs no work. The caller supplies `now` and
/// carries out whatever [`Schedule::due`] returns, which is what lets the
/// timing policy be tested without waiting an hour.
#[derive(Debug)]
pub struct Schedule {
    next_blocklist: Instant,
    next_update: Instant,
}

impl Schedule {
    pub fn new(now: Instant) -> Self {
        Self {
            next_blocklist: now + jittered(FIRST_CHECK_AFTER, 1),
            next_update: now + jittered(FIRST_CHECK_AFTER, 2),
        }
    }

    /// Tasks due at `now`, rescheduling each one it returns.
    ///
    /// Rescheduling HERE rather than in the caller is deliberate: a task that
    /// failed still has to be pushed forward, or a persistent failure becomes
    /// a hot loop hammering a server that is already having a bad day.
    pub fn due(&mut self, now: Instant) -> Vec<Task> {
        let mut tasks = Vec::new();
        if now >= self.next_blocklist {
            self.next_blocklist = now + jittered(BLOCKLIST_EVERY, now.elapsed().as_nanos() as u64);
            tasks.push(Task::Blocklist);
        }
        if now >= self.next_update {
            self.next_update = now + jittered(UPDATE_EVERY, now.elapsed().as_nanos() as u64 ^ 0x5a);
            tasks.push(Task::Update);
        }
        tasks
    }

    /// The earliest deadline, for folding into the event loop's wait.
    pub fn next_deadline(&self) -> Instant {
        self.next_blocklist.min(self.next_update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_fires_at_startup() {
        // A browser that phones home the instant it opens makes launch time
        // observable, and is doing its own errands before the user's.
        let now = Instant::now();
        let mut s = Schedule::new(now);
        assert!(s.due(now).is_empty());
        assert!(s.next_deadline() > now);
    }

    #[test]
    fn both_tasks_come_due_and_reschedule() {
        let now = Instant::now();
        let mut s = Schedule::new(now);
        let later = now + Duration::from_secs(60 * 60 * 24);
        let mut fired = s.due(later);
        fired.sort_by_key(|t| format!("{t:?}"));
        assert_eq!(fired, vec![Task::Blocklist, Task::Update]);
        // Both moved into the future, so a due task cannot fire twice.
        assert!(s.due(later).is_empty());
        assert!(s.next_deadline() > later);
    }

    #[test]
    fn a_failing_task_is_still_pushed_forward() {
        // `due` reschedules whatever it hands out, whether or not the caller
        // succeeds. Without that, a server that is down turns this into a hot
        // loop hammering it on every event-loop wake.
        let now = Instant::now();
        let mut s = Schedule::new(now);
        let later = now + Duration::from_secs(60 * 60 * 24);
        assert!(!s.due(later).is_empty());
        for _ in 0..100 {
            assert!(
                s.due(later).is_empty(),
                "a task rescheduled itself into the past"
            );
        }
    }

    #[test]
    fn the_blocklist_is_checked_far_more_often_than_updates() {
        // Phishing domains live hours; releases live months. If these ever
        // invert, the blocklist has stopped being worth fetching.
        assert!(BLOCKLIST_EVERY < UPDATE_EVERY);
    }

    #[test]
    fn jitter_actually_spreads_and_stays_positive() {
        let base = Duration::from_secs(3600);
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..200u64 {
            let d = jittered(base, seed);
            assert!(d.as_secs() > 0, "a non-positive interval would busy-loop");
            // Within the declared window, so jitter cannot quietly become a
            // delay long enough to matter.
            assert!(d.as_secs() >= 3600 - 900 && d.as_secs() <= 3600 + 900);
            seen.insert(d.as_secs());
        }
        assert!(
            seen.len() > 20,
            "jitter produced only {} distinct intervals; an exact interval \
             turns 'when this machine is awake' into a fingerprint",
            seen.len()
        );
    }

    #[test]
    fn a_short_interval_still_gets_usable_jitter() {
        // The 90s first check must not degenerate to zero spread through
        // integer division.
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..100u64 {
            let d = jittered(FIRST_CHECK_AFTER, seed);
            assert!(d.as_secs() > 0);
            seen.insert(d.as_secs());
        }
        assert!(seen.len() > 5, "the first check would arrive in lockstep");
    }
}
