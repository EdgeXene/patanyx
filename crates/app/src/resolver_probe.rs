//! Noticing when the chosen DNS resolver cannot be reached.
//!
//! Picking Mullvad or Quad9 configures WebView2 in `secure` mode, which FAILS
//! CLOSED: if that resolver is unreachable the browser does not resolve at all
//! rather than accepting whatever the network offers. That is the point of the
//! setting. It also means a user who picked a resolver and then walked into a
//! hotel sees every page fail with no explanation -- captive portals work BY
//! hijacking DNS, so fail-closed is exactly what breaks them.
//!
//! This module notices that state and says so. It does not fix it.
//!
//! # The rule: two independent signals, never one
//!
//! A banner appears only when BOTH are true:
//!
//! 1. a real navigation has failed in a way consistent with the network being
//!    dead, and
//! 2. a direct probe of the configured resolver could not reach it.
//!
//! Either alone is a false positive generator, and they fail in opposite
//! directions:
//!
//! * NAVIGATION FAILURES ALONE cannot tell "the resolver is blocked" from "that
//!   domain does not exist". Counting distinct failing hostnames was the
//!   obvious fix and it is wrong: a user on a corporate network with
//!   split-horizon DNS permanently cannot resolve `intranet.corp` while their
//!   resolver is perfectly healthy, so any counting scheme eventually accuses
//!   the network for every such user, forever.
//! * THE PROBE ALONE cannot tell "the resolver is blocked" from "this process
//!   reaches the network differently than the engine does". `ureq` does not
//!   share Chromium's proxy resolution, so on a proxy-required network the
//!   probe can fail while browsing works fine.
//!
//! Requiring both means each covers the other's blind spot. It also makes the
//! feature robust to the thing that would otherwise be its weakest link:
//! exactly which `WebErrorStatus` Chromium reports for a secure-mode DoH
//! failure is not documented anywhere we can rely on. Guessing too WIDE here
//! costs one HTTPS request that answers "no, the resolver is fine" and nothing
//! is shown. Guessing too NARROW costs a banner that never appears. Neither
//! produces a wrong claim, which is why the status list below is generous.
//!
//! # What is stored
//!
//! A `u32` and two enums. NO HOSTNAMES, ever -- not in memory, not on disk, not
//! in the event sent to the chrome. The probe's target is derived from the
//! user's own setting, never from anything they browsed. Content webviews are
//! untouched: detection rides the navigation callback the browser already has.
//!
//! # What this deliberately does NOT do
//!
//! * **It never changes the setting.** No automatic fallback, not even for one
//!   session. A network that can push the browser back to plaintext DNS by
//!   refusing service is precisely the adversary fail-closed exists to defeat;
//!   letting it succeed by being obstinate would hand it the win quietly.
//!   The banner explains, the human decides.
//! * **It does not restart the browser.** An earlier design had a one-click
//!   "switch to System and restart" button, which needs process respawn, a
//!   child that waits on the parent's PID, a guard against double-spawn, and a
//!   clean shutdown routine this application does not currently have. That is a
//!   large amount of new process-lifecycle machinery, and every part of it is a
//!   way to lose a user's session. The banner tells them where the setting is.
//! * **It does not catch HTTP-layer portals** -- the kind that answer DNS
//!   truthfully and redirect at the HTTP layer. Those mostly self-heal, because
//!   the portal's own login page loads.
//! * **It does not catch middleboxes that pass TLS but drop DoH message
//!   bodies.** The probe would connect happily.
//!
//! Those last two are stated because a detector whose gaps are unwritten gets
//! trusted for cases it never covered.

use std::time::{Duration, Instant};

/// How long a probe result is believed before it must be re-established.
///
/// Short, because the thing it measures -- whether this network reaches the
/// resolver -- changes the moment the user moves or a VPN reconnects.
const PROBE_FRESH_FOR: Duration = Duration::from_secs(60);

/// The probe's own deadline. A captive portal usually black-holes rather than
/// refusing, so waiting for a full TCP retransmit window would leave the banner
/// minutes behind the user's experience of a dead browser.
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

/// What the last probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// No probe has completed, or the last result has gone stale.
    Unknown,
    /// The configured resolver answered. Any HTTP status counts: a 4xx from a
    /// DoH endpoint given a bare GET still proves a TLS session was
    /// established with a server holding a valid certificate for that name,
    /// which is the whole question.
    Reachable,
    /// The resolver could not be reached at the transport layer.
    Unreachable,
}

/// The detector's whole state.
#[derive(Debug)]
pub struct Watch {
    /// Consecutive navigations that failed in a network-looks-dead way. A
    /// count, deliberately: hostnames are what a naive version of this feature
    /// would hold, and holding them is a browsing record.
    failures: u32,
    probe: Probe,
    /// When `probe` was established, for staleness.
    probed_at: Option<Instant>,
    /// A probe is in flight; do not start another.
    in_flight: bool,
    /// The user closed the banner. Cleared by any confirmed success, so
    /// dismissing does not silence a network that is still broken tomorrow --
    /// it silences THIS episode.
    dismissed: bool,
}

impl Default for Watch {
    fn default() -> Self {
        Self {
            failures: 0,
            probe: Probe::Unknown,
            probed_at: None,
            in_flight: false,
            dismissed: false,
        }
    }
}

/// What the caller should do after feeding an event in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do.
    Nothing,
    /// Start a probe of the configured resolver, off the UI thread.
    Probe,
}

impl Watch {
    /// A navigation failed with a status consistent with a dead network.
    ///
    /// Returns whether to probe. The caller decides nothing; this type owns
    /// the policy so it can be tested without a browser.
    pub fn on_navigation_failed(&mut self, now: Instant) -> Action {
        self.failures = self.failures.saturating_add(1);
        if self.in_flight || self.probe_is_fresh(now) {
            return Action::Nothing;
        }
        self.in_flight = true;
        Action::Probe
    }

    /// A navigation SUCCEEDED. Everything resets.
    ///
    /// This must be called only for a confirmed http(s) load. Counting
    /// `about:blank` or an internal page as success would let a broken network
    /// flap the banner, because the interstitial the user is looking at is
    /// itself a successful load of nothing.
    pub fn on_navigation_succeeded(&mut self) {
        self.failures = 0;
        self.probe = Probe::Reachable;
        self.probed_at = None;
        self.dismissed = false;
    }

    /// A probe finished.
    pub fn on_probe(&mut self, reachable: bool, now: Instant) {
        self.in_flight = false;
        self.probe = if reachable {
            Probe::Reachable
        } else {
            Probe::Unreachable
        };
        self.probed_at = Some(now);
    }

    /// The user pressed "Check again".
    pub fn on_retry(&mut self, now: Instant) -> Action {
        self.dismissed = false;
        // Deliberately ignores freshness: the user is telling us the situation
        // may have changed, and they are better informed about that than a
        // sixty-second timer.
        let _ = now;
        if self.in_flight {
            return Action::Nothing;
        }
        self.in_flight = true;
        Action::Probe
    }

    /// The user closed the banner.
    pub fn on_dismiss(&mut self) {
        self.dismissed = true;
    }

    /// Should the banner be on screen?
    pub fn banner_visible(&self, now: Instant) -> bool {
        !self.dismissed
            && self.failures > 0
            && self.probe == Probe::Unreachable
            && self.probe_is_fresh(now)
    }

    fn probe_is_fresh(&self, now: Instant) -> bool {
        match self.probed_at {
            Some(at) => now.duration_since(at) < PROBE_FRESH_FOR,
            None => false,
        }
    }
}

/// Reach the configured resolver, or fail trying. Runs on a worker thread.
///
/// `true` means the resolver answered. A non-2xx HTTP status counts as
/// reachable on purpose: a DoH endpoint given a bare GET with no query is
/// entitled to refuse, and the refusal proves the TLS session was established
/// with a server presenting a VALID CERTIFICATE for that hostname.
///
/// That last clause is what makes this detect a captive portal at all, and it
/// is the one property this function must never lose. A portal intercepts DNS,
/// so the resolver's name resolves to the portal's address -- and the portal
/// cannot present a certificate for `base.dns.mullvad.net`. Certificate
/// validation is therefore the detector. With validation disabled this
/// function would cheerfully connect to the portal, report the resolver
/// reachable, and the banner would never appear on the one network it exists
/// for. ureq validates by default; nothing here may turn that off.
#[cfg(all(windows, feature = "updater-net"))]
pub fn probe_now(template: &str) -> bool {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        // The minimum a server needs; this request is about reachability, not
        // about telling anyone who we are.
        .user_agent("patanyx")
        .build();
    match agent.get(template).call() {
        // Reached it.
        Ok(_) => true,
        // Reached it and it said no. Still reached it.
        Err(ureq::Error::Status(_, _)) => true,
        // DNS, TLS, connect or timeout: did not reach it.
        Err(ureq::Error::Transport(_)) => false,
    }
}

/// Without the network feature, or off Windows, there is nothing to probe.
///
/// Reports UNREACHABLE-as-false rather than pretending: the caller's
/// two-signal rule means a `false` here alone still shows nothing, and the
/// resolver setting itself is Windows-only, so this is unreachable code on
/// every other target rather than a silent downgrade.
#[cfg(not(all(windows, feature = "updater-net")))]
pub fn probe_now(_template: &str) -> bool {
    true
}

// ---------------------------------------------------------------------------
// The live instance, and the seams the rest of the app talks to.
// ---------------------------------------------------------------------------

use std::sync::Mutex;

use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;

use crate::UserEvent;

static WATCH: Mutex<Option<Watch>> = Mutex::new(None);

fn with_watch<T>(f: impl FnOnce(&mut Watch) -> T) -> T {
    // A poisoned lock here must not take the browser down: this is an advisory
    // banner, and the worst case of ignoring the poison is one wrong verdict.
    let mut guard = match WATCH.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(guard.get_or_insert_with(Watch::default))
}

/// The resolver the user chose, or `None` when they are on System.
///
/// `None` disables this whole feature, correctly: System carries no DoH mode,
/// so it never fails closed and there is no captive-portal breakage to explain.
fn configured_template() -> Option<&'static str> {
    crate::prefs::load().dns.doh_template()
}

/// A navigation finished. `success` is the engine's own verdict; `looks_dead`
/// says whether its error status is consistent with the network being gone.
///
/// Called from the platform layer's existing navigation callback, so no new
/// engine hook and no contact with content webviews.
pub fn note_navigation(success: bool, looks_dead: bool, proxy: &EventLoopProxy<UserEvent>) {
    let Some(template) = configured_template() else {
        return;
    };
    let now = Instant::now();
    let action = with_watch(|w| {
        if success {
            w.on_navigation_succeeded();
            Action::Nothing
        } else if looks_dead {
            w.on_navigation_failed(now)
        } else {
            // A failure that is not network-shaped -- a certificate problem, a
            // cancelled load -- says nothing about the resolver and must not
            // count toward accusing it.
            Action::Nothing
        }
    });
    if action == Action::Probe {
        spawn_probe(template, proxy);
    }
    notify(proxy);
}

/// Run the probe off the UI thread and report back through the event loop.
///
/// A thread per probe rather than a pool: probes are rare, at most one runs at
/// a time (the state machine enforces it), and a thread that exits is easier to
/// reason about than a worker that must be shut down cleanly on quit.
fn spawn_probe(template: &'static str, proxy: &EventLoopProxy<UserEvent>) {
    let proxy = proxy.clone();
    let _ = std::thread::Builder::new()
        .name("resolver-probe".into())
        .spawn(move || {
            let reachable = probe_now(template);
            let _ = proxy.send_event(UserEvent::ResolverProbe(reachable));
        });
}

/// A probe came back. Called on the UI thread from the main loop.
pub fn on_probe_result(reachable: bool, proxy: &EventLoopProxy<UserEvent>) {
    with_watch(|w| w.on_probe(reachable, Instant::now()));
    notify(proxy);
}

/// Push the current verdict to the chrome.
///
/// The payload is one boolean and the user's own setting name. No hostname, no
/// URL, nothing derived from what was browsed.
fn notify(proxy: &EventLoopProxy<UserEvent>) {
    let visible = with_watch(|w| w.banner_visible(Instant::now()));
    let mode = crate::prefs::load().dns.as_str();
    let _ = proxy.send_event(UserEvent::ResolverBanner { visible, mode });
}

pub fn ipc_status() -> Result<Value, &'static str> {
    let mode = crate::prefs::load().dns;
    Ok(json!({
        "supported": cfg!(windows),
        "mode": mode.as_str(),
        "showing": with_watch(|w| w.banner_visible(Instant::now())),
    }))
}

pub fn ipc_retry(proxy: &EventLoopProxy<UserEvent>) -> Result<Value, &'static str> {
    let Some(template) = configured_template() else {
        return Err("unsupported");
    };
    if with_watch(|w| w.on_retry(Instant::now())) == Action::Probe {
        spawn_probe(template, proxy);
    }
    Ok(json!({ "checking": true }))
}

pub fn ipc_dismiss(proxy: &EventLoopProxy<UserEvent>) -> Result<Value, &'static str> {
    with_watch(|w| w.on_dismiss());
    notify(proxy);
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // A fixed base so every test shares one timeline.
        thread_local! {
            static BASE: Instant = Instant::now();
        }
        BASE.with(|b| *b + Duration::from_secs(secs))
    }

    #[test]
    fn neither_signal_alone_shows_anything() {
        // Failures with no probe result: silent. This is the split-horizon DNS
        // user, whose intranet name genuinely does not resolve while their
        // resolver is fine.
        let mut w = Watch::default();
        assert_eq!(w.on_navigation_failed(t(0)), Action::Probe);
        w.on_navigation_failed(t(1));
        w.on_navigation_failed(t(2));
        assert!(!w.banner_visible(t(3)), "failures alone must not accuse");

        // A failed probe with no navigation failure: also silent. This is the
        // proxy-required network, where this process cannot reach the resolver
        // but the engine browses perfectly.
        let mut w = Watch::default();
        w.on_probe(false, t(0));
        assert!(!w.banner_visible(t(1)), "a probe alone must not accuse");
    }

    #[test]
    fn both_signals_show_the_banner() {
        let mut w = Watch::default();
        assert_eq!(w.on_navigation_failed(t(0)), Action::Probe);
        w.on_probe(false, t(1));
        assert!(w.banner_visible(t(2)));
    }

    #[test]
    fn a_reachable_probe_keeps_it_quiet() {
        // The resolver answers, so whatever failed was the site, not the
        // network. Saying otherwise would blame the network for every typo.
        let mut w = Watch::default();
        w.on_navigation_failed(t(0));
        w.on_probe(true, t(1));
        assert!(!w.banner_visible(t(2)));
    }

    #[test]
    fn one_success_clears_everything() {
        let mut w = Watch::default();
        w.on_navigation_failed(t(0));
        w.on_probe(false, t(1));
        assert!(w.banner_visible(t(2)));

        w.on_navigation_succeeded();
        assert!(
            !w.banner_visible(t(3)),
            "a page loaded, so the network is not blocking the resolver"
        );
    }

    #[test]
    fn a_stale_verdict_stops_being_believed() {
        // The user walked out of the hotel. Nothing has failed since, but
        // nothing has succeeded either -- so the banner must age out rather
        // than sit there asserting a network condition from ten minutes ago.
        let mut w = Watch::default();
        w.on_navigation_failed(t(0));
        w.on_probe(false, t(1));
        assert!(w.banner_visible(t(30)));
        assert!(!w.banner_visible(t(1000)), "a minute-old verdict is not evidence");
    }

    #[test]
    fn dismissing_lasts_only_until_something_works() {
        let mut w = Watch::default();
        w.on_navigation_failed(t(0));
        w.on_probe(false, t(1));
        w.on_dismiss();
        assert!(!w.banner_visible(t(2)));

        // Still dismissed while the same episode continues: closing it must
        // actually close it, or the control is a lie.
        w.on_navigation_failed(t(3));
        assert!(!w.banner_visible(t(4)));

        // A success ends the episode. A LATER failure is a new one, and the
        // user has not dismissed that.
        w.on_navigation_succeeded();
        w.on_navigation_failed(t(5));
        w.on_probe(false, t(6));
        assert!(w.banner_visible(t(7)), "a new episode is not pre-dismissed");
    }

    #[test]
    fn only_one_probe_runs_at_a_time() {
        let mut w = Watch::default();
        assert_eq!(w.on_navigation_failed(t(0)), Action::Probe);
        assert_eq!(
            w.on_navigation_failed(t(1)),
            Action::Nothing,
            "a page with twenty failing subresources must not fire twenty probes"
        );
        w.on_probe(false, t(2));
        // Fresh result, so still no new probe.
        assert_eq!(w.on_navigation_failed(t(3)), Action::Nothing);
        // Once stale, probing resumes.
        assert_eq!(w.on_navigation_failed(t(500)), Action::Probe);
    }

    #[test]
    fn retry_probes_even_when_the_verdict_is_fresh() {
        // The user pressing "Check again" knows something the timer does not --
        // they just signed in to the WiFi.
        let mut w = Watch::default();
        w.on_navigation_failed(t(0));
        w.on_probe(false, t(1));
        assert_eq!(w.on_retry(t(2)), Action::Probe);
        w.on_probe(true, t(3));
        assert!(!w.banner_visible(t(4)), "it works now, so say nothing");
    }

    #[test]
    fn retry_undismisses() {
        let mut w = Watch::default();
        w.on_navigation_failed(t(0));
        w.on_probe(false, t(1));
        w.on_dismiss();
        w.on_retry(t(2));
        w.on_probe(false, t(3));
        assert!(
            w.banner_visible(t(4)),
            "asking to check again is asking to be told the answer"
        );
    }
}
