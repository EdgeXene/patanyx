//! Noticing when the DNS resolver in force cannot be reached.
//!
//! Choosing Quad9 configures WebView2 in `secure` mode, which FAILS CLOSED:
//! if that resolver is unreachable the browser does not resolve at all rather
//! than accepting whatever the network offers. That is the point of the
//! setting. It also means a user who chose it and then walked into a hotel
//! sees every page fail with no explanation -- captive portals work BY
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
    /// A page loaded. The verdict is cleared; the PROBE BUDGET is not.
    ///
    /// `probed_at` used to be reset here, which meant a network that
    /// alternated one success and one failure could draw one HTTPS request
    /// to the resolver per failure, with the 60-second window never taking
    /// effect. The window is a promise about how often this browser talks
    /// to the resolver on its own; a success does not renew it. The cost is
    /// that a failure inside the window after a success waits for the
    /// window to pass before it can raise the banner, which is bounded and
    /// stated in PROBE_FRESH_FOR's doc.
    pub fn on_navigation_succeeded(&mut self) {
        self.failures = 0;
        self.probe = Probe::Reachable;
        self.dismissed = false;
    }

    /// The probe could not even start (the worker thread failed to spawn).
    /// Nothing is in flight, so the next failure may try again; the previous
    /// verdict and its timestamp are left alone.
    pub fn on_probe_aborted(&mut self) {
        self.in_flight = false;
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
/// cannot present a certificate for `dns.quad9.net`. Certificate
/// validation is therefore the detector. With validation disabled this
/// function would cheerfully connect to the portal, report the resolver
/// reachable, and the banner would never appear on the one network it exists
/// for. ureq validates by default; nothing here may turn that off.
#[cfg(all(windows, feature = "updater-net"))]
pub fn probe_now(template: &str) -> bool {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        // NO REDIRECTS. This request exists to prove a TLS session to the
        // template's own hostname; following a 3xx would send a second
        // request wherever the answer pointed, with this user agent, which
        // is egress the design does not intend. ureq follows five by
        // default. A 3xx counts as "reached it" below, like any other
        // status, because the certificate check already happened.
        .redirects(0)
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

// The encrypted choice fails closed, and the ONLY explanation a stranded user
// gets is the banner this module raises from a real probe. A Windows build
// without the network feature would offer that choice with a stub that
// always answers "reachable", so the banner could never appear. Refuse to
// build that combination rather than ship it.
#[cfg(all(windows, not(feature = "updater-net")))]
compile_error!(
    "PATANYX on Windows offers a fail-closed encrypted resolver; the `updater-net` \
     feature (the reachability probe behind the resolver-unreachable banner) is required"
);

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

/// The resolver the ENGINE is running, or `None` when it is on System.
///
/// `None` disables this whole feature, correctly: System carries no DoH mode,
/// so it never fails closed and there is no captive-portal breakage to explain.
/// The APPLIED resolver, not the file: the file can change under a running
/// engine (a choice pending a restart, or the file becoming unreadable and
/// reading as the System default), and probing a resolver the engine is not
/// using would explain a failure that has a different cause. On Linux no
/// engine ever records one, so this is `None` there and nothing probes.
fn configured_template() -> Option<&'static str> {
    crate::prefs::applied_dns().doh_template()
}

/// A navigation finished. `success` is the engine's own verdict; `looks_dead`
/// says whether its error status is consistent with the network being gone.
///
/// Called from the platform layer's existing navigation callback, so no new
/// engine hook and no contact with content webviews.
/// Whether the engine's traffic rides the Private Tunnel, now or since boot.
///
/// The probe must not run then. `ureq` does not use the engine's proxy, so
/// the probe would leave the machine DIRECT -- from the user's real address,
/// with the resolver's name in the clear -- and its trigger, a failed
/// navigation, is exactly what a tunnel outage produces -- so every tunnel
/// user who also chose Quad9 would be exposed at the moment they are most
/// exposed. The tunnel's own fail-closed banner explains that outage, so
/// nothing is lost by staying silent here. Both the current setting and the
/// booted one count: `engine_proxy_port` is Some whenever the mode is
/// Imported (bound, or the dead port), and `restart_pending` is true when
/// the booted mode differs from the current one.
///
/// Verified by reading, not by a unit test: both inputs are process-global
/// tunnel state, and the callers below take an event-loop proxy.
fn tunnel_is_the_route() -> bool {
    crate::tunnel_control::engine_proxy_port().is_some()
        || crate::tunnel_control::restart_pending()
}

pub fn note_navigation(success: bool, looks_dead: bool, proxy: &EventLoopProxy<UserEvent>) {
    let Some(template) = configured_template() else {
        return;
    };
    // Checked only on the one shape of event that can lead to a probe, so a
    // successful navigation never pays for the tunnel state reads. And
    // checked BEFORE the state machine sees the failure, so it never waits
    // for a probe result that will not come.
    if !success && looks_dead && tunnel_is_the_route() {
        return;
    }
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
    let spawned = std::thread::Builder::new()
        .name("resolver-probe".into())
        .spawn(move || {
            let reachable = probe_now(template);
            let _ = proxy.send_event(UserEvent::ResolverProbe(reachable));
        });
    // A thread that never started would never answer, and `in_flight` would
    // stay set forever: no later failure and no manual retry could probe
    // again, for the rest of the session. Clear it so the next one can.
    if spawned.is_err() {
        with_watch(|w| w.on_probe_aborted());
    }
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
    let mode = crate::prefs::applied_dns().as_str();
    let _ = proxy.send_event(UserEvent::ResolverBanner { visible, mode });
}

/// The banner's whole sentence, composed here for BOTH producers -- the
/// probe event and the boot-time status reply -- so a banner restored at
/// startup can never render an empty claim. The resolver's display name
/// comes from the catalog too: proper nouns today, but the fallback phrase
/// is language, and one path for all of it beats a special case.
pub fn banner_body(i18n: &crate::i18n::I18n, mode: &str) -> String {
    let name = i18n.text(match mode {
        "quad9" => crate::i18n::keys::CHROME_JS_DNS_SHORT_QUAD9,
        _ => crate::i18n::keys::CHROME_RESOLVER_NAME_FALLBACK,
    });
    let mut args = crate::i18n::Args::default();
    args.set("name", name);
    i18n.resolve(crate::i18n::keys::CHROME_RESOLVER_BODY, &args)
}

pub fn ipc_status(i18n: &crate::i18n::I18n) -> Result<Value, &'static str> {
    // The banner is about the resolver the engine is RUNNING.
    let mode = crate::prefs::applied_dns();
    Ok(json!({
        "supported": cfg!(windows),
        "mode": mode.as_str(),
        "showing": with_watch(|w| w.banner_visible(Instant::now())),
        "body": banner_body(i18n, mode.as_str()),
    }))
}

pub fn ipc_retry(proxy: &EventLoopProxy<UserEvent>) -> Result<Value, &'static str> {
    let Some(template) = configured_template() else {
        return Err("unsupported");
    };
    // Same rule as `note_navigation`: no direct egress while the tunnel is
    // the route. The banner cannot be showing then anyway.
    if tunnel_is_the_route() {
        return Err("unsupported");
    }
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
    fn a_success_does_not_renew_the_probe_budget() {
        // fail -> probe -> success -> fail, all inside the window. The
        // second failure must NOT probe again: the window bounds how often
        // this browser contacts the resolver on its own, and a page loading
        // in between does not renew it.
        let mut w = Watch::default();
        assert_eq!(w.on_navigation_failed(t(0)), Action::Probe);
        w.on_probe(false, t(1));
        w.on_navigation_succeeded();
        assert_eq!(
            w.on_navigation_failed(t(10)),
            Action::Nothing,
            "a probe ran 9 seconds ago; a success in between is not a licence to probe again"
        );
        // Once the window has passed, the next failure probes as normal.
        assert_eq!(w.on_navigation_failed(t(100)), Action::Probe);
    }

    #[test]
    fn an_aborted_probe_frees_the_next_one() {
        // The worker failed to start. Without this, in_flight would stay set
        // and no failure or retry could ever probe again this session.
        let mut w = Watch::default();
        assert_eq!(w.on_navigation_failed(t(0)), Action::Probe);
        assert_eq!(w.on_navigation_failed(t(1)), Action::Nothing, "one in flight");
        w.on_probe_aborted();
        assert_eq!(w.on_navigation_failed(t(2)), Action::Probe, "free again");
        assert!(!w.banner_visible(t(3)), "an abort is not a verdict");
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
