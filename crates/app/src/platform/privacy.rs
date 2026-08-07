//! Engine-free privacy logic shared by both backends.
//!
//! Everything in this module is pure: no engine types, no I/O, no display.
//! That is deliberate — `cargo test` must prove the security properties
//! (rule matching decides what never leaves the machine, the freeze state
//! machine is per-tab and reversible, the ledger accounts correctly, TLS
//! classification never guesses) on a headless CI box. unix.rs and
//! windows.rs contain only the glue that feeds engine callbacks into these
//! functions.
//!
//! A note on honesty for the ephemeral mode: memory-only storage means site
//! state is never written *through* to the profile on disk and dies with
//! the session. It is NOT unrecoverable erasure — the kernel can page the
//! process to swap or a hibernation image, and neither backend can prevent
//! that. User-facing docs must say "dies with the session", not "shredded".

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Grace period after `load-finished` during which late subresources
/// (deferred images, scripts the page legitimately loads late) may still
/// fetch before the tab freezes. Short on purpose: it exists so pages
/// finish rendering, not so applications can keep streaming. Quarantine
/// tabs use the same grace; 1.5 s after the load event is "immediately"
/// for any interactive purpose, and zero would leave pages half-rendered.
pub const FREEZE_GRACE: Duration = Duration::from_millis(1500);

/// Whether a tab keeps site state on disk intentionally, or not at all.
/// Two explicit modes, no ambiguous default: the UI can query and display
/// this per tab via `profile_mode`.
///
/// The Serialize derive is the IPC wire format (snake_case strings); the
/// chrome UI matches on these names, and the wire-names test below locks
/// them so a refactor cannot silently break the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMode {
    /// The user intentionally keeps sessions (cookies, cache, storage) on
    /// disk across runs.
    Persistent,
    /// All site state (cookies, cache, localStorage, IndexedDB, service
    /// workers) lives in memory and dies with the session. See the module
    /// docs: this is not cryptographic erasure (swap/hibernation).
    Ephemeral,
}

/// Per-tab privacy configuration. Tabs are independent, so every field is
/// per-tab and changeable per tab (though `ephemeral` is construction-time:
/// the engine profile is fixed once the webview exists, so toggling it
/// requires recreating the tab — the backends document this no-op).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabPolicy {
    pub ephemeral: bool,
    pub javascript: bool,
    pub block_ads: bool,
    pub freeze_after_load: bool,
}

impl Default for TabPolicy {
    /// Persistent profile, JavaScript on, no freeze -- and ad/tracker
    /// blocking ON.
    ///
    /// Blocking defaulted OFF until 2026-07-31 ("matches the browser's
    /// historical behaviour"). The project owner flipped it: a privacy browser
    /// that ships its protection disabled is asking every user to find one
    /// toggle before getting the thing they installed it for. The Privacy
    /// panel toggle still turns it off per session, and the indicator keeps
    /// reporting what the ENGINE confirmed, not this default.
    fn default() -> Self {
        Self {
            ephemeral: false,
            javascript: true,
            block_ads: true,
            freeze_after_load: false,
        }
    }
}

impl TabPolicy {
    /// Quarantine tab: the one-call paranoid preset. JavaScript off, no
    /// storage, ephemeral, and frozen right after the document loads. A
    /// caller passes this to `build_content` (and `apply_policy`) instead
    /// of flipping five switches.
    pub fn quarantine() -> Self {
        Self {
            ephemeral: true,
            javascript: false,
            block_ads: true,
            freeze_after_load: true,
        }
    }

    /// Ephemeral tab: keeps nothing on disk, and that is the ONLY difference
    /// from an ordinary tab.
    ///
    /// Deliberately not `quarantine()` with one field changed. Quarantine is
    /// four decisions bundled into a posture for a page you actively distrust;
    /// this is one decision, for a page you simply do not want recorded. Most
    /// of the web does not work with JavaScript off, so a preset that killed
    /// script would make "open this link privately" a broken-page button and
    /// teach people to avoid it.
    ///
    /// Blocking stays ON because it costs nothing and the tab is throwaway
    /// anyway; freeze stays OFF because the page is meant to be usable.
    pub fn ephemeral() -> Self {
        Self {
            ephemeral: true,
            javascript: true,
            block_ads: true,
            freeze_after_load: false,
        }
    }

    /// What was ASKED FOR. Not what the engine did.
    ///
    /// Callers that display a storage mode to the user must go through
    /// `TabState::profile_mode`, which will only say "Ephemeral" once the
    /// engine has confirmed it. This one stays because construction needs to
    /// know the request before there is an engine to ask.
    pub fn requested_profile_mode(&self) -> ProfileMode {
        if self.ephemeral {
            ProfileMode::Ephemeral
        } else {
            ProfileMode::Persistent
        }
    }
}

/// One row of the per-tab ledger: a host the tab contacted, how many
/// requests it saw, and how many of those were blocked. User-visible data.
/// Serialize is the IPC wire format for the `tab_ledger` reply.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HostRecord {
    pub host: String,
    pub allowed: u64,
    pub blocked: u64,
}

/// Per-tab request ledger. Keyed BTreeMap so iteration is deterministic.
/// Hosts are recorded normalized (see `host_of`).
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    hosts: BTreeMap<String, (u64, u64)>,
}

impl Ledger {
    pub fn record(&mut self, host: &str, blocked: bool) {
        let entry = self.hosts.entry(host.to_string()).or_insert((0, 0));
        if blocked {
            entry.1 += 1;
        } else {
            entry.0 += 1;
        }
    }

    /// Moves one request from blocked to allowed.
    ///
    /// For the case where the decision was to block and the ENGINE then
    /// refused to carry it out. The row must describe what happened, not
    /// what was intended: the panel states that blocked requests never left
    /// the browser, and this is what keeps that sentence true.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn correct_block_to_allowed(&mut self, host: &str) {
        if let Some(entry) = self.hosts.get_mut(host) {
            if entry.1 > 0 {
                entry.1 -= 1;
                entry.0 += 1;
            }
        }
    }

    /// How many requests this tab has had BLOCKED, across every host.
    ///
    /// Separate from `snapshot` because it rides on `tab_status`, which is
    /// emitted on every navigation, tab switch and load-state change. The
    /// shield badge needs one integer; building, cloning and sorting the whole
    /// host table to add up a column would be paid for on each of those.
    ///
    /// Meaningless where the platform cannot observe blocking -- on WebKitGTK
    /// the column is structurally zero, and `LEDGER_COUNTS_BLOCKED` is what
    /// tells the UI whether this number is an observation or an artefact.
    pub fn blocked_total(&self) -> u64 {
        self.hosts.values().map(|(_, blocked)| blocked).sum()
    }

    /// Sorted for display: most-contacted first, ties alphabetical, so the
    /// UI gets a stable order across calls.
    pub fn snapshot(&self) -> Vec<HostRecord> {
        let mut rows: Vec<HostRecord> = self
            .hosts
            .iter()
            .map(|(host, (allowed, blocked))| HostRecord {
                host: host.clone(),
                allowed: *allowed,
                blocked: *blocked,
            })
            .collect();
        rows.sort_by(|a, b| {
            (b.allowed + b.blocked)
                .cmp(&(a.allowed + a.blocked))
                .then_with(|| a.host.cmp(&b.host))
        });
        rows
    }
}

// --- Session receipt --------------------------------------------------------

/// Session-cumulative count of requests the browser REFUSED, across every
/// tab including ones already closed. Per-tab ledgers answer "on this
/// page"; this answers "this session".
///
/// It is a fold-on-close, not a second counter beside `record`, for one
/// reason: there must be ONE source of truth for "refused", and it must be
/// MOVED, never copied. A process-wide counter incremented at the `record`
/// site would be a second truth that `correct_block_to_allowed` had to
/// mirror forever; the first missed correction would split the session
/// number from the tab numbers, and the split would run in the reassuring
/// direction (overcounted refusals read as more protection). Folding the
/// tab's own total at close cannot drift from the tabs, because it is the
/// tabs.
///
/// Nothing here is persisted: a lifetime-total pref is fingerprintable disk
/// state, and a lie after any manual data clear. The counter dies with the
/// process, which is exactly what "this session" means.
#[derive(Default)]
pub struct SessionBlocked {
    from_closed_tabs: u64,
}

impl SessionBlocked {
    pub const fn new() -> Self {
        Self {
            from_closed_tabs: 0,
        }
    }

    /// Fold a closing tab's ledger into the session total.
    ///
    /// The ledger is taken BY VALUE: after this call the caller no longer
    /// holds it, so the same refusals cannot be folded twice. The teardown
    /// paths `mem::take` it out of the tab state, so a second teardown for
    /// the same tab folds a fresh empty ledger -- zero -- instead of a
    /// copy. If this took `&Ledger`, a double close would double-count and
    /// the receipt would overstate protection: the reassuring lie.
    pub fn fold_closed_tab(&mut self, ledger: Ledger) {
        self.from_closed_tabs += ledger.blocked_total();
    }

    /// Refused this session: what closed tabs folded in, plus what every
    /// still-open tab has refused so far, summed AT READ TIME. Reading live
    /// tabs lazily is what keeps "blocked requests never left the browser"
    /// true for the session number: a `correct_block_to_allowed` on an open
    /// tab lowers its `blocked_total`, and the session total follows with
    /// no extra code. A snapshot taken earlier would keep counting, as
    /// refused, a request that in the end left the browser.
    pub fn total_with_live(&self, live_blocked: impl Iterator<Item = u64>) -> u64 {
        self.from_closed_tabs + live_blocked.sum::<u64>()
    }
}

/// The process-wide session counter. Module-level state matches this
/// crate's other per-process surfaces and avoids threading a new field
/// through every tab-construction site.
///
/// THREADING: every writer and reader (tab teardown via Tab::drop inside
/// state methods, and the IPC arm) runs on the one UI/event-loop thread, so
/// there is no window where a tab is counted both live and folded. The
/// Mutex exists because statics must be Sync, not because two threads race
/// here; if a second thread ever reaches this, the fold-vs-live handoff
/// needs a real protocol, not just this lock.
static SESSION_BLOCKED: std::sync::Mutex<SessionBlocked> =
    std::sync::Mutex::new(SessionBlocked::new());

/// Called from tab teardown with the closing tab's ledger (taken by value;
/// see `SessionBlocked::fold_closed_tab` for why that is load-bearing).
///
/// A poisoned lock must not silently eat the fold: `into_inner` keeps
/// counting rather than dropping a tab's refusals, which would understate
/// the session number with no signal anywhere.
pub fn fold_closed_tab(ledger: Ledger) {
    let mut session = SESSION_BLOCKED.lock().unwrap_or_else(|e| e.into_inner());
    session.fold_closed_tab(ledger);
}

/// Session total plus the live tabs' current totals, for the
/// `privacy_receipt` IPC arm. `live_blocked` must be the per-tab
/// `blocked_total()` values from the SAME tab store `tab_status` reads --
/// never a second walk maintained just for this.
pub fn session_blocked_total(live_blocked: impl Iterator<Item = u64>) -> u64 {
    let session = SESSION_BLOCKED.lock().unwrap_or_else(|e| e.into_inner());
    session.total_with_live(live_blocked)
}

/// The receipt's honesty gate, as data: counts are `Some` only where the
/// platform can observe blocking at all (state.rs's LEDGER_COUNTS_BLOCKED).
/// On WebKitGTK the content blocker drops matches inside the engine and
/// never calls back, so both columns are structurally zero there; returning
/// `None` keeps "no measurement" unrepresentable as a number, so the panel
/// can never render a structural zero as if blocking were observed and
/// nothing matched. Both counts share ONE gate because they come from the
/// same observation path; gating them separately could put an observation
/// and an artefact side by side in one panel.
pub fn observable_counts(
    counts_blocked: bool,
    session: u64,
    page: u64,
) -> (Option<u64>, Option<u64>) {
    if counts_blocked {
        (Some(session), Some(page))
    } else {
        (None, None)
    }
}


/// Serialize is the IPC wire format; the always-visible toolbar chip and
/// the per-tab panel both match on these snake_case names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezePhase {
    Loading,
    Loaded,
    Frozen,
}

/// Whether the engine-level block backing a freeze is actually installed.
///
/// This type exists because `FreezePhase::Frozen` is set the instant the user
/// clicks, while on WebKitGTK the content filter that does the blocking is
/// compiled ASYNCHRONOUSLY and can fail — an unwritable cache directory, a
/// rule list the engine rejects, a NULL store. Reporting "Frozen, making no
/// requests" off the phase alone means the UI asserts a protection that may
/// not be running.
///
/// That is not hypothetical here. Ad blocking shipped in exactly that shape:
/// the UI said nothing reached trackers while the Linux rule blocked nothing
/// at all, and the tests passed the whole time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeEnforcement {
    /// No freeze is in effect, so there is nothing to enforce.
    Inactive,
    /// The user asked to freeze and the block is still being installed.
    /// Requests may still be going out RIGHT NOW.
    Pending,
    /// The engine confirmed the block is installed.
    Active,
    /// The block could not be installed. The tab is NOT protected.
    Failed,
}

impl FreezeEnforcement {
    /// The wire/UI spelling. Deliberately not `Display`, so adding a variant
    /// forces a decision here rather than silently producing a new string
    /// the chrome has no case for.
    pub fn as_str(self) -> &'static str {
        match self {
            FreezeEnforcement::Inactive => "inactive",
            FreezeEnforcement::Pending => "pending",
            FreezeEnforcement::Active => "active",
            FreezeEnforcement::Failed => "failed",
        }
    }
}

/// How far per-tab request interception got at registration time.
///
/// Windows-only in practice: WebView2 enforces through one per-tab
/// `WebResourceRequested` handler registered at build time, and every step
/// of that registration can fail. The old code discarded those failures
/// (`let _ =`, bare `return`) and then claimed enforcement anyway — the
/// first Windows measurement (2026-07-25, commit 98ec725) caught exactly
/// that: ten fetches left a tab whose toolbar said it was making none.
/// This type lives here, not in windows.rs, so the reporting rules it
/// feeds are provable under `cargo test` on a headless Linux box.
/// unix.rs never sets it — WebKitGTK blocks with compiled content
/// filters, a different mechanism with its own async confirmation.
/// Whether a policy setting the ENGINE has to apply actually took.
///
/// `TabPolicy` is what the USER ASKED FOR. This is what the engine CONFIRMED,
/// and they are not the same fact. Conflating them is how a browser reports
/// "JavaScript off" over a tab still running script: the policy is recorded
/// the moment the user clicks, and the setter meant to enforce it fails into
/// a log line nobody reads -- in a release build, into nothing at all.
///
/// Same discipline as `InterceptionState`, and here for the same reason: a
/// protection the UI counts must be one the engine acknowledged. Found by an
/// adversarial review of the Windows backend, where `apply_policy` wrote the
/// policy before calling the engine and reported the failure only through a
/// debug-only `diag()`. The unix backend had the same shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SettingState {
    /// No attempt yet: a tab that has never had a policy applied.
    #[default]
    NotAttempted,
    /// The engine accepted it.
    Applied,
    /// The engine refused it, or could not be reached to ask. The user's
    /// intent stands in `TabPolicy`; this says it is not in force.
    Failed,
}

/// What the ENGINE confirmed, per tab, for the panel that reports it.
///
/// A named struct rather than the tuple this used to be. Both backends build
/// it and one call site destructures it, and every field is `&'static str` --
/// so in tuple form two fields could be swapped at either end and nothing,
/// not the compiler and not a test, would notice. The panel would then report
/// one protection's state under another's label, which is precisely the class
/// of lie this whole mechanism exists to prevent. Adding a fifth field is what
/// made that risk worth removing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineSettings {
    pub smartscreen_off: &'static str,
    pub tracking_prevention: &'static str,
    pub navigation_tracking: &'static str,
    pub autofill_off: &'static str,
    pub ephemeral_confirmed: &'static str,
    /// Process-wide, not per-tab: whether the browser got its own hardened
    /// engine environment. Reported through the same per-tab channel because
    /// there is exactly one panel that renders confirmed-vs-requested, and a
    /// second reporting path for one value would be a second thing to keep in
    /// sync. Every tab carries the same answer.
    pub hardened_environment: &'static str,
    /// Process-wide, like `hardened_environment`: whether the OS accepted our
    /// request to be told when the workstation locks or the machine suspends.
    /// "failed" means the vault will NOT close on a screen lock, and only the
    /// inactivity timer is protecting it.
    pub session_lock_registered: &'static str,
    /// Per-tab, unlike `hardened_environment` above: whether autofill's
    /// content-script + message-handler registration succeeded for THIS
    /// tab. See `TabState::content_script_registered`.
    pub content_script_registered: &'static str,
    /// Per-tab, like `content_script_registered`: whether the deny-by-default
    /// permission handler registered for THIS tab. "failed" means camera,
    /// microphone, location and notification requests fall through to the
    /// engine's own prompts for this tab, so the panel must not offer controls
    /// that would do nothing. Always "not_attempted" on unix, where the
    /// feature does not exist.
    pub permissions_registered: &'static str,
    /// Process-wide, like `hardened_environment`, and the one field here
    /// that is MEASURED rather than read back off an API: a background
    /// probe thread completes a real SOCKS5 greeting against the loopback
    /// tunnel front and reads the tunnel's own status before this may say
    /// "applied". It is also the one row whose "failed" can mean
    /// "protecting you by refusing" -- before the vault unlocks, the proxy
    /// port deliberately accepts nothing, so the tunnel is not carrying
    /// traffic and the row must say so -- as well as "broken".
    pub tunnel: &'static str,
}

impl SettingState {
    /// Stable name for the UI. Separate from `Debug` so renaming a variant
    /// cannot silently change what the chrome renders.
    pub fn as_str(self) -> &'static str {
        match self {
            SettingState::NotAttempted => "not_attempted",
            SettingState::Applied => "applied",
            SettingState::Failed => "failed",
        }
    }

    /// Whether a protection resting on this setting may be presented as
    /// active. Only an acknowledged setting counts.
    pub fn is_enforced(self) -> bool {
        matches!(self, SettingState::Applied)
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptionState {
    /// Registration has not run (or never completed).
    NotAttempted,
    /// Wildcard filter added AND handler attached. `covers_workers` is
    /// true when the `ICoreWebView2_22` source-kinds overload succeeded;
    /// false means the legacy overload, whose filter delivers only
    /// DOCUMENT-sourced requests — service/shared/dedicated workers
    /// bypass it entirely. That distinction decides whether a freeze may
    /// ever claim "making no requests" (see `freeze_with_interception`).
    Registered { covers_workers: bool },
    /// A required registration step returned a failure HRESULT. The tab
    /// has NO working interception: no ledger, no ad blocking, no freeze.
    Failed(InterceptionFailure),
}

/// Which registration step failed, for the diagnostic line. The
/// distinction matters when reading a probe run: a filter failure and a
/// handler failure implicate different WebView2 calls.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptionFailure {
    /// `AddWebResourceRequestedFilter[WithRequestSourceKinds]` failed.
    AddFilter,
    /// `add_WebResourceRequested` failed.
    AttachHandler,
}

/// What the unix backend reports for `interception`. It is not an
/// `InterceptionState`: WebKitGTK has no per-request handler to register, it
/// compiles a content filter whose outcome is already reported through
/// `FreezeEnforcement`. Naming the mechanism is the honest answer, and it
/// lives here so the full set of values the chrome may see is in one place.
pub const UNIX_INTERCEPTION_NAME: &str = "content_filter";

impl InterceptionState {
    /// The wire/diagnostic spelling. Same rationale as
    /// `FreezeEnforcement::as_str`: adding a variant forces a decision
    /// here rather than silently producing a string nothing matches.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn as_str(self) -> &'static str {
        match self {
            InterceptionState::NotAttempted => "not_attempted",
            InterceptionState::Registered {
                covers_workers: true,
            } => "registered",
            InterceptionState::Registered {
                covers_workers: false,
            } => "registered_legacy",
            InterceptionState::Failed(_) => "failed",
        }
    }
}

/// Per-tab freeze state machine.
///
/// Freezing exists to stop a *finished* page from phoning home. It breaks
/// web applications — that is a documented consequence, not a bug to hide —
/// so the machine carries two escape hatches the UI must expose: per-site
/// overrides (`add_override`, survives navigation because it is the user's
/// exception, not the page's) and one-call `unfreeze`. Auto-freeze is
/// inhibited while the tab shows a live channel (WebSocket / service worker
/// — i.e. an app, not a page) ON THE ENGINES THAT REPORT ONE, which today
/// means WebView2 and not WebKitGTK (see `note_live_channel` for both limits
/// on that inhibition); an explicit `freeze()` is always honoured because it
/// is the user's stated intent, and is therefore the control to reach for
/// when the heuristic is wrong in either direction.
#[derive(Clone, Debug)]
pub struct FreezeController {
    auto: bool,
    phase: FreezePhase,
    loaded_at: Option<Instant>,
    grace: Duration,
    overrides: BTreeSet<String>,
    live_channel: bool,
    /// Whether the current freeze was ASKED FOR or inferred.
    ///
    /// The two must survive navigation differently. A manual freeze is the
    /// user saying "this tab stops talking", and a page that navigates itself
    /// must not be able to undo that — otherwise a frozen tab's still-running
    /// script does `location.href = "https://tracker/?data"` and the freeze
    /// evaporates one instruction before the request it was meant to stop. An
    /// auto-freeze is a heuristic about a FINISHED page, and it must yield:
    /// blocking the navigation a user just clicked would be a browser that
    /// appears broken.
    manual: bool,
    /// See `FreezeEnforcement`: what the ENGINE did, as opposed to what the
    /// user asked for.
    enforcement: FreezeEnforcement,
}

impl FreezeController {
    pub fn new(auto: bool) -> Self {
        Self {
            auto,
            phase: FreezePhase::Loading,
            loaded_at: None,
            grace: FREEZE_GRACE,
            overrides: BTreeSet::new(),
            live_channel: false,
            manual: false,
            enforcement: FreezeEnforcement::Inactive,
        }
    }

    pub fn phase(&self) -> FreezePhase {
        self.phase
    }

    /// Whether the engine-level block behind a freeze is ACTUALLY in place.
    ///
    /// Read this, not `phase()`, before telling a user that nothing is
    /// leaving the machine. `phase()` is what the user asked for; this is
    /// what the engine did about it.
    pub fn enforcement(&self) -> FreezeEnforcement {
        self.enforcement
    }

    /// The engine confirmed the block is installed.
    pub fn note_enforced(&mut self) {
        // Ignore a late confirmation for a freeze the user already lifted;
        // otherwise an in-flight compile would resurrect "enforced" on a tab
        // that is deliberately live again.
        if self.phase == FreezePhase::Frozen {
            self.enforcement = FreezeEnforcement::Active;
        }
    }

    /// The block could not be installed. Requests are NOT being stopped.
    pub fn note_enforcement_failed(&mut self) {
        if self.phase == FreezePhase::Frozen {
            self.enforcement = FreezeEnforcement::Failed;
        }
    }

    pub fn set_auto(&mut self, auto: bool) {
        self.auto = auto;
    }

    pub fn on_load_started(&mut self) {
        // A MANUAL freeze survives navigation, and this is the whole point of
        // the distinction.
        //
        // Clearing it unconditionally meant a page could lift its own freeze:
        // WebView2 raises NavigationStarting BEFORE the document's
        // WebResourceRequested, so a frozen tab's still-running script doing
        // `location.href = "https://tracker/?data"` reset the phase to Loading
        // and the request went out — along with every subresource of whatever
        // it navigated to. On WebKitGTK the mirror image: the compiled filter
        // is not removed on navigation, so the tab kept blocking everything
        // while the toolbar reported it was not frozen. A blank page and no
        // explanation.
        //
        // The user's way out is unchanged and one call either way: unfreeze,
        // or allow this host.
        if self.manual && self.phase == FreezePhase::Frozen {
            // A new page may not hold the old page's WebSocket; re-detect.
            self.live_channel = false;
            return;
        }
        self.phase = FreezePhase::Loading;
        self.loaded_at = None;
        self.live_channel = false;
        self.manual = false;
        self.enforcement = FreezeEnforcement::Inactive;
    }

    pub fn on_load_finished(&mut self, now: Instant) {
        // A manual freeze during loading must not be silently undone by the
        // load finishing — the user asked for frozen, they get frozen.
        if self.phase != FreezePhase::Frozen {
            self.phase = FreezePhase::Loaded;
            self.loaded_at = Some(now);
        }
    }

    /// Called when the engine observes a WebSocket (or equivalent live
    /// channel). Inhibits AUTO-freeze only; closing the channel is not
    /// observable, so the inhibition lasts until the next navigation.
    ///
    /// TWO LIMITS, both real and neither claimed away:
    ///
    /// * It is WINDOWS ONLY. WebKitGTK's resource-load signal does not
    ///   distinguish a socket upgrade, so on Linux a live web application IS
    ///   auto-frozen. The `FreezeController` doc above reads as a general
    ///   property and is not one — it holds where the engine can tell us,
    ///   and on one of the two engines it cannot.
    /// * One ATTEMPT is enough. A page calling
    ///   `new WebSocket("wss://nowhere/")` once inhibits auto-freeze for the
    ///   rest of its life, whether or not the socket ever connected, because
    ///   the request event is all we see. That is a page opting out of a
    ///   heuristic, which is why `quarantine()`'s freeze-after-load can be
    ///   defeated this way — and why a MANUAL freeze deliberately ignores
    ///   this flag entirely.
    pub fn note_live_channel(&mut self) {
        self.live_channel = true;
    }

    /// Requests a freeze. Enforcement starts PENDING, never Active: the
    /// caller has not installed anything yet, and on WebKitGTK it cannot know
    /// the outcome until an async callback fires.
    pub fn freeze(&mut self) {
        self.phase = FreezePhase::Frozen;
        self.manual = true;
        self.enforcement = FreezeEnforcement::Pending;
    }

    /// The timer-driven auto-freeze transition, for backends without an
    /// engine timer. Identical to the lazy one; named separately so the two
    /// call sites are greppable.
    pub fn freeze_auto_now(&mut self) {
        self.auto_freeze();
    }

    /// When the grace period ends for a loaded, armed, quiet tab -- or `None`
    /// if this tab is not waiting to auto-freeze. Lets the event loop wake
    /// exactly once rather than poll.
    pub fn auto_freeze_deadline(&self) -> Option<Instant> {
        if !self.auto || self.phase != FreezePhase::Loaded || self.live_channel {
            return None;
        }
        self.loaded_at.map(|t| t + self.grace)
    }

    /// The lazy auto-freeze transition. Same phase, but NOT the user's stated
    /// intent, so a navigation clears it — see `on_load_started`.
    fn auto_freeze(&mut self) {
        self.phase = FreezePhase::Frozen;
        self.manual = false;
        self.enforcement = FreezeEnforcement::Pending;
    }

    /// One-call unfreeze. Marks the tab Loaded-at-now so a later auto-freeze
    /// timer does not immediately re-freeze it under the user's feet.
    pub fn unfreeze(&mut self, now: Instant) {
        self.phase = FreezePhase::Loaded;
        self.loaded_at = Some(now);
        self.manual = false;
        self.enforcement = FreezeEnforcement::Inactive;
    }

    pub fn add_override(&mut self, host: &str) {
        self.overrides.insert(host.to_lowercase());
    }

    /// Sorted (BTreeSet) so the unix freeze filter's JSON is deterministic.
    pub fn overrides(&self) -> Vec<String> {
        self.overrides.iter().cloned().collect()
    }

    /// True when the grace period has elapsed on a loaded, auto-freeze tab
    /// with no live channel. Pure: engine timers (unix) call this on fire.
    pub fn should_auto_freeze(&self, now: Instant) -> bool {
        self.auto
            && self.phase == FreezePhase::Loaded
            && !self.live_channel
            && self
                .loaded_at
                .and_then(|t| now.checked_duration_since(t))
                .map_or(false, |elapsed| elapsed >= self.grace)
    }

    /// Per-request decision. `host` must come from `host_of` (normalized).
    /// Also performs the auto-freeze transition lazily, so engines that
    /// decide inside the request callback (WebView2) behave identically to
    /// timer-driven ones (WebKitGTK) without needing a timer at all.
    pub fn should_block(&mut self, host: &str, now: Instant) -> bool {
        if self.overrides.contains(host) {
            return false;
        }
        if self.should_auto_freeze(now) {
            self.auto_freeze();
        }
        self.phase == FreezePhase::Frozen
    }

    /// Frozen-now check for a request that cannot be attributed to a host,
    /// so per-site overrides cannot apply. Performs the same lazy
    /// auto-freeze transition as `should_block`, for the same reason.
    /// Exists for the fail-closed rule: a request the engine cannot even
    /// describe must not be allowed out of a tab that says it is frozen.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn should_block_unattributable(&mut self, now: Instant) -> bool {
        if self.should_auto_freeze(now) {
            self.auto_freeze();
        }
        self.phase == FreezePhase::Frozen
    }

    /// Manual freeze as the WINDOWS backend must report it. The old
    /// windows.rs called `note_enforced()` unconditionally right here, on
    /// the reasoning that a per-request handler makes enforcement
    /// instantaneous; the first behavioural measurement (2026-07-25,
    /// commit 98ec725) proved that false — ten fetches left a "frozen"
    /// tab. So: Pending, and only when this tab holds a FULLY registered
    /// handler. Anything less is Failed on the spot —
    ///
    /// - `NotAttempted` / `Failed(_)`: there is no handler; nothing will
    ///   ever block, and Pending would be a lie of omission.
    /// - `Registered { covers_workers: false }` (legacy filter): worker
    ///   requests bypass the filter entirely, so "making no network
    ///   requests" can never truthfully be claimed on this runtime. Within
    ///   the four reportable states that is Failed — over-warning beats
    ///   the claim of a protection with a known hole.
    ///
    /// Active comes solely from the engine accepting a synthesized 403
    /// while frozen (`TabState::confirm_freeze_block`), mirroring the unix
    /// rule that only the async filter-save callback may confirm.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn freeze_with_interception(&mut self, interception: InterceptionState) {
        self.freeze();
        if !matches!(
            interception,
            InterceptionState::Registered {
                covers_workers: true
            }
        ) {
            self.note_enforcement_failed();
        }
    }
}

/// Everything a backend keeps per tab, shared so both `TabView`s and the
/// engine callbacks (which only outlive the closure by `Rc`) can reach it.
/// Whether a document URL is a plain-HTTP web page.
///
/// `http:` only. `https:`, and every internal or non-web scheme, is not the
/// case this boundary exists for.
pub fn is_insecure_page_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://")
}

/// Whether a host names a destination inside the user's own network.
///
/// LITERAL ADDRESSES ONLY, AND THAT LIMIT IS THE FEATURE'S HONEST EDGE. What
/// arrives here is a URL, never a resolved address: the request decision runs
/// before any socket exists and the engine hands over a string. So a hostname
/// that RESOLVES to a private address -- the DNS-rebinding shape -- is not
/// caught, cannot be caught at this layer, and must be stated as a limit
/// rather than papered over. Catching it needs a hook between resolution and
/// connection, which this browser does not have.
///
/// Covers the families a page has no business reaching: loopback, RFC1918,
/// link-local (including the cloud metadata address, which is link-local and
/// is the nastiest single target in the list), CGNAT, and their IPv6
/// equivalents.
pub fn is_private_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    // Bracketed IPv6 literal.
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return is_private_ipv6(inner);
    }
    if host.contains(':') {
        return is_private_ipv6(&host);
    }
    // `localhost` and anything under it resolve to loopback by convention and
    // by RFC 6761, so treat the NAME as private without needing to resolve it.
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match parse_ipv4(&host) {
        Some(o) => is_private_ipv4(o),
        // Any other name is a public name as far as this layer can tell.
        None => false,
    }
}

fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = 0;
    for (i, part) in host.split('.').enumerate() {
        if i >= 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[i] = part.parse::<u8>().ok()?;
        parts += 1;
    }
    (parts == 4).then_some(out)
}

fn is_private_ipv4(o: [u8; 4]) -> bool {
    match o {
        [127, ..] => true,                              // loopback
        [10, ..] => true,                               // RFC1918
        [172, b, ..] if (16..=31).contains(&b) => true, // RFC1918
        [192, 168, ..] => true,                         // RFC1918
        [169, 254, ..] => true,                         // link-local, incl. 169.254.169.254
        [100, b, ..] if (64..=127).contains(&b) => true, // CGNAT
        [0, ..] => true,                                // "this network"
        _ => false,
    }
}

fn is_private_ipv6(addr: &str) -> bool {
    let a = addr.split('%').next().unwrap_or(addr); // drop any zone id
    if a == "::1" || a == "::" {
        return true;
    }
    // IPv4-mapped: judge the embedded address.
    if let Some(v4) = a.rsplit(':').next() {
        if v4.contains('.') {
            if let Some(o) = parse_ipv4(v4) {
                return is_private_ipv4(o);
            }
        }
    }
    let head = a.split(':').next().unwrap_or("");
    if head.len() >= 2 {
        let prefix = &head[..2];
        // fc00::/7 unique-local, fe80::/10 link-local.
        if prefix == "fc" || prefix == "fd" || prefix == "fe" {
            return true;
        }
    }
    false
}

pub struct TabState {
    pub policy: TabPolicy,
    pub ledger: Ledger,
    pub freeze: FreezeController,
    /// Whether the DOCUMENT in this tab was loaded over plain HTTP.
    ///
    /// Drives the local-network boundary below. Set on every navigation, and
    /// defaults to FALSE so a tab whose page URL could not be read does not
    /// start blocking its own subresources: this feature must not break an
    /// ordinary page when it cannot tell what kind of page it is.
    pub page_insecure: bool,
    /// Verdict recorded by the TLS-failure signal, for when the live
    /// certificate can no longer be read after the load failed. Cleared on
    /// every navigation so an http page never shows a stale https verdict.
    pub tls_error_verdict: Option<TlsState>,
    /// JSON of the currently installed freeze content-filter. Lives here
    /// (not in `TabView`) because the unix auto-freeze timer fires with
    /// access to `TabState` only. Pure data; engine handles stay out.
    pub freeze_json: Option<String>,
    /// How far this tab's request interception got. Windows sets it at
    /// registration; unix leaves it `NotAttempted` and reports its own
    /// mechanism. Gates what a freeze may claim — see
    /// `FreezeController::freeze_with_interception`.
    pub interception: InterceptionState,
    /// Whether the engine confirmed this tab's JavaScript setting. See
    /// `SettingState`: `policy.javascript` is the ask, this is the answer.
    pub script_setting: SettingState,
    /// Whether SmartScreen reputation checking was actually turned off.
    ///
    /// It needs `ICoreWebView2Settings8`. On an older runtime the cast fails
    /// and SmartScreen stays ON, sending every URL the user visits to
    /// Microsoft -- in a browser sold on privacy. That has to be visible.
    pub smartscreen_off: SettingState,
    /// Whether STRICT tracking prevention was actually accepted. Needs
    /// Runtime 111+; an older one silently keeps BALANCED.
    pub tracking_prevention: SettingState,
    /// Whether the navigation handlers registered.
    ///
    /// Without `NavigationCompleted` a quarantine tab NEVER auto-freezes,
    /// because nothing ever marks the page loaded. Manual freeze is
    /// unaffected: it goes through the request filter, not this.
    pub navigation_tracking: SettingState,
    /// Whether the ENGINE's own autofill and password store were turned off.
    ///
    /// Windows only in practice: WebView2 keeps its own form-fill and password
    /// database, which is a second credential store outside the vault. There
    /// is no WebKitGTK equivalent, so the unix side reports NotAttempted
    /// rather than claiming a protection it never had to apply.
    pub autofill_off: SettingState,
    /// Whether the ENGINE confirmed this tab's storage mode.
    ///
    /// `Applied` means the engine's in-private flag matches what the policy
    /// asked for. Anything else means the tab's cookies, cache and
    /// localStorage may not be where `TabPolicy::ephemeral` claims, and
    /// `profile_mode` refuses to say "Ephemeral" on that basis -- see the
    /// module docs on why "dies with the session" is a promise that must be
    /// confirmed rather than assumed. Windows reads this back; the unix
    /// backend cannot yet and reports NotAttempted.
    pub ephemeral_confirmed: SettingState,
    /// How many requests the engine handler has delivered for this tab.
    /// DIAGNOSTIC ONLY. It proves events flow; it does NOT prove a
    /// synthesized 403 sticks, which is the link that was actually
    /// broken, so it must never gate an enforcement claim.
    pub handler_events: u64,
    /// Whether this tab's content-script injection AND the message handler
    /// that reads what it posts both registered successfully. Gates the
    /// credential save/fill affordance -- see `windows.rs::build_content`'s
    /// autofill section and `chrome.js`'s use of `content_script_registered`
    /// in `tab_status`. Distinct from `autofill_off` above, which is the
    /// ENGINE's own form-fill/password store, not this browser's vault.
    pub content_script_registered: SettingState,
    /// See `EngineSettings::permissions_registered`.
    pub permissions_registered: SettingState,
}

/// One intercepted request's fate.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDecision {
    Allow,
    Block(BlockReason),
}

/// Why a request was blocked. The reason is not cosmetic: only a
/// freeze-motivated block is evidence that a FREEZE is enforced, and the
/// diagnostic trace names it so a probe run is readable.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    /// Matched the ad/tracker rule set with `block_ads` on.
    AdRule,
    /// The tab is frozen and the host carries no override.
    Freeze,
    /// The tab is frozen and the request could not be attributed to a
    /// host (unreadable URI, or network-shaped with no parseable
    /// authority). Fail closed.
    FrozenOpaque,
    /// Content asked for the host the chrome UI is served on.
    ///
    /// Closes the SUBFRAME half of the origin boundary. wry drives the
    /// navigation handler from `NavigationStarting`, which fires for the top
    /// level only, so `is_allowed_content_url` never sees a subframe -- an
    /// iframe could name `rbchrome.localhost` and nothing in the navigation
    /// path objected. The request filter, unlike that handler, sees every
    /// source kind, so the check belongs here.
    ///
    /// Deliberately NARROW: it refuses one host, not the top-level scheme
    /// allowlist. Applying that allowlist to subframes would refuse `data:`,
    /// `blob:` and `about:srcdoc`, which ordinary pages use constantly -- a
    /// rule that breaks legitimate browsing to close a gap this one closes
    /// exactly.
    ReservedOrigin,
    /// A page served over plain HTTP reached for the user's own network.
    ///
    /// Scoped to insecure pages by deliberate decision, which follows the
    /// direction of the Private Network Access work: a secure context may
    /// reach a private address, an insecure one may not. That leaves the
    /// larger case -- a hostile HTTPS page scanning the same network --
    /// deliberately out of scope, and the About copy says so.
    LocalNetwork,
}

impl BlockReason {
    /// Whether a SUCCESSFUL block for this reason is evidence the freeze
    /// is enforced. An ad block proves the handler works, but it would
    /// have happened with no freeze at all, so it says nothing about
    /// whether freezing stops anything.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn confirms_freeze(self) -> bool {
        matches!(self, BlockReason::Freeze | BlockReason::FrozenOpaque)
    }

    /// Short tag for the debug request trace.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn as_str(self) -> &'static str {
        match self {
            BlockReason::AdRule => "ads",
            BlockReason::Freeze => "freeze",
            BlockReason::FrozenOpaque => "frozen-opaque",
            BlockReason::ReservedOrigin => "reserved-origin",
            BlockReason::LocalNetwork => "local-network",
        }
    }
}

impl TabState {
    pub fn new(policy: &TabPolicy) -> Self {
        Self {
            policy: policy.clone(),
            ledger: Ledger::default(),
            freeze: FreezeController::new(policy.freeze_after_load),
            page_insecure: false,
            tls_error_verdict: None,
            freeze_json: None,
            interception: InterceptionState::NotAttempted,
            script_setting: SettingState::NotAttempted,
            smartscreen_off: SettingState::NotAttempted,
            tracking_prevention: SettingState::NotAttempted,
            navigation_tracking: SettingState::NotAttempted,
            autofill_off: SettingState::NotAttempted,
            ephemeral_confirmed: SettingState::NotAttempted,
            handler_events: 0,
            content_script_registered: SettingState::NotAttempted,
            permissions_registered: SettingState::NotAttempted,
        }
    }

    /// The storage mode to SHOW THE USER: the engine's answer, not ours.
    ///
    /// "Ephemeral" is a promise that cookies, cache and localStorage die with
    /// the session. This returns it only when the engine has confirmed the
    /// in-private flag actually took. A requested-but-unconfirmed tab reports
    /// `Persistent`, which is the honest direction to be wrong in: it
    /// understates the protection instead of promising one that may not exist,
    /// and a user who is told "persistent" behaves more carefully, not less.
    ///
    /// This is why `TabPolicy::profile_mode` was renamed to
    /// `requested_profile_mode` -- so a future caller reaching for the obvious
    /// name gets the confirmed answer rather than the wish.
    pub fn profile_mode(&self) -> ProfileMode {
        match (self.policy.ephemeral, self.ephemeral_confirmed) {
            (true, SettingState::Applied) => ProfileMode::Ephemeral,
            _ => ProfileMode::Persistent,
        }
    }

    /// `url` is the document being navigated to, or None when the engine
    /// could not report it.
    pub fn on_load_started(&mut self, url: Option<&str>) {
        self.freeze.on_load_started();
        self.tls_error_verdict = None;
        // Unknown counts as secure, deliberately: see `page_insecure`.
        self.page_insecure = url.is_some_and(is_insecure_page_url);
    }

    pub fn on_load_finished(&mut self, now: Instant) {
        self.freeze.on_load_finished(now);
    }

    /// Decides one intercepted request and does the ledger accounting.
    /// This is the WHOLE decision — the engine handler contributes COM
    /// plumbing only, so every rule here is provable under `cargo test`
    /// on a box with no WebView2.
    ///
    /// `uri` is None when the engine could not produce the URI at all.
    /// `websocket` is what the engine reported; the caller maps a FAILED
    /// context read to `false`, because an unclassifiable request must
    /// stay eligible for blocking rather than inherit the socket path.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn decide_request(
        &mut self,
        uri: Option<&str>,
        websocket: bool,
        rules: &RuleSet,
        now: Instant,
    ) -> RequestDecision {
        // Every call proves the engine pipeline delivered an event. The
        // freeze diagnostic prints this; it is NOT an enforcement gate
        // (events firing says nothing about whether a synthesized 403
        // sticks — see confirm_freeze_block).
        self.handler_events += 1;

        let class = uri.map(classify_uri);
        // THE LOCAL-NETWORK BOUNDARY, ahead of every other rule.
        //
        // First because it is the one rule here that is about the DESTINATION
        // being somewhere the page has no business reaching, rather than about
        // what the user asked this tab to do. A frozen tab, an allow-listed
        // host, an ad-rule exemption -- none of them should be able to hand a
        // plain-HTTP page a route to the router.
        //
        // It applies to SUBRESOURCES only. A top-level navigation to a local
        // address is the user typing their router's address, which must keep
        // working; this handler never sees those on Windows (NavigationStarting
        // owns them) and the class check keeps it true on both backends.
        if self.page_insecure {
            if let Some(UriClass::Network(host)) = &class {
                if is_private_host(host) {
                    self.ledger.record(host, true);
                    return RequestDecision::Block(BlockReason::LocalNetwork);
                }
            }
        }
        let decision = self.decide_inner(class, websocket, rules, now);
        // An AUTO-freeze transitions lazily inside should_block, so it never
        // passes through freeze_with_interception and would otherwise sit at
        // Pending forever on a tab whose interception cannot enforce — the
        // manual path reports Failed for exactly that tab. Reconcile here so
        // both doors give the same verdict: a freeze this tab cannot deliver
        // is Failed however it started.
        if self.freeze.enforcement() == FreezeEnforcement::Pending
            && !matches!(
                self.interception,
                InterceptionState::Registered {
                    covers_workers: true
                }
            )
        {
            self.freeze.note_enforcement_failed();
        }
        decision
    }

    fn decide_inner(
        &mut self,
        class: Option<UriClass>,
        websocket: bool,
        rules: &RuleSet,
        now: Instant,
    ) -> RequestDecision {

        if websocket {
            // Seeing a socket inhibits AUTO-freeze until the next
            // navigation (its close is not observable through the request
            // event). Recorded BEFORE the frozen checks below so the
            // inhibition happens on every upgrade, allowed or not.
            self.freeze.note_live_channel();
            return match class {
                Some(UriClass::Network(host)) => {
                    // A manual (or already-completed auto) freeze blocks
                    // NEW upgrades: the user said stop, and an upgrade is
                    // a brand-new connection, not the live app the
                    // auto-freeze heuristic protects. Already-open
                    // sockets are invisible to this event on either
                    // engine — documented, and never claimed otherwise.
                    // Ad rules deliberately do not apply to upgrades yet.
                    let frozen = self.freeze.should_block(&host, now);
                    self.ledger.record(&host, frozen);
                    if frozen {
                        RequestDecision::Block(BlockReason::Freeze)
                    } else {
                        RequestDecision::Allow
                    }
                }
                // An upgrade whose URI is unreadable or unparseable: fail
                // closed while frozen, allow otherwise. (A socket flag on
                // a local-scheme URI is an engine inconsistency; treating
                // it as opaque keeps the conservative branch.)
                _ => {
                    if self.freeze.should_block_unattributable(now) {
                        RequestDecision::Block(BlockReason::FrozenOpaque)
                    } else {
                        RequestDecision::Allow
                    }
                }
            };
        }

        match class {
            // The engine gave no URI, or a network-shaped one with no
            // parseable host. While frozen, fail CLOSED — the old handler
            // allowed these through (`?` exits and a bare `return` on a
            // failed host parse), which meant precisely the requests we
            // understood least were the ones a frozen tab still made.
            // No ledger entry: the ledger is host-keyed and user-facing,
            // and a pseudo-host row would be noise. The debug trace is
            // the visibility.
            None | Some(UriClass::NetworkOpaque) => {
                if self.freeze.should_block_unattributable(now) {
                    RequestDecision::Block(BlockReason::FrozenOpaque)
                } else {
                    RequestDecision::Allow
                }
            }
            // data:/blob:/about:/custom put no bytes on the wire; a freeze
            // has nothing to enforce against them. Never ledgered, which
            // matches the previous behaviour exactly.
            Some(UriClass::Local) => RequestDecision::Allow,
            Some(UriClass::Network(host)) => {
                // BEFORE every other rule, and unconditional: not gated on
                // `block_ads`, not overridable by the per-tab malicious-host
                // allowance, and not affected by freeze state. Content has no
                // legitimate reason to fetch the browser's own UI origin, and
                // the one path that could reach it -- a subframe -- bypasses
                // the navigation-time allowlist entirely.
                if host == super::CHROME_RESERVED_HOST {
                    self.ledger.record(&host, true);
                    return RequestDecision::Block(BlockReason::ReservedOrigin);
                }
                let ads = self.policy.block_ads && rules.blocks_host(&host);
                let frozen = self.freeze.should_block(&host, now);
                let blocked = ads || frozen;
                self.ledger.record(&host, blocked);
                if frozen {
                    RequestDecision::Block(BlockReason::Freeze)
                } else if ads {
                    RequestDecision::Block(BlockReason::AdRule)
                } else {
                    RequestDecision::Allow
                }
            }
        }
    }

    /// The ONE entry point through which a successful engine block may
    /// upgrade freeze enforcement to Active. Returns true exactly on the
    /// Pending -> Active edge, so the caller can print its CONFIRMED
    /// diagnostic once rather than per blocked request.
    ///
    /// Two deliberate refusals live here, in pure code, because
    /// `note_enforced()`'s only guard is `phase == Frozen`:
    ///
    /// - Legacy interception (`covers_workers: false`) never confirms.
    ///   Without this gate the first blocked DOCUMENT request would flip
    ///   the Failed that `freeze_with_interception` reported back to
    ///   Active — and Active claims "making no requests" on a runtime
    ///   where workers bypass the filter.
    /// - Failed never resurrects to Active within one freeze. A freeze
    ///   that demonstrably leaked a request (`freeze_block_failed`) does
    ///   not win the claim back by succeeding later; the user re-freezes
    ///   deliberately (freeze() resets enforcement to Pending) if they
    ///   want a fresh attempt.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn confirm_freeze_block(&mut self) -> bool {
        if self.freeze.enforcement() != FreezeEnforcement::Pending {
            return false;
        }
        if !matches!(
            self.interception,
            InterceptionState::Registered {
                covers_workers: true
            }
        ) {
            return false;
        }
        self.freeze.note_enforced();
        self.freeze.enforcement() == FreezeEnforcement::Active
    }

    /// A block attempt errored: the synthesized 403 never happened and the
    /// request went out. The UI must stop claiming protection immediately
    /// — this is the downgrade the old Windows backend could never issue.
    ///
    /// `uri` is the request that got away, so the ledger can be corrected.
    /// It is recorded as blocked at DECISION time, before the engine has
    /// been asked to do anything, and the panel tells the user that requests
    /// counted as blocked never left the browser. That sentence has to stay
    /// true: a row that says blocked while the bytes went out is a false
    /// statement about egress, which is the one thing this ledger exists to
    /// report.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn freeze_block_failed(&mut self, uri: Option<&str>) {
        self.freeze.note_enforcement_failed();
        if let Some(UriClass::Network(host)) = uri.map(classify_uri) {
            self.ledger.correct_block_to_allowed(&host);
        }
    }
}

/// Per-tab TLS verdict. Detection informs, never blocks: corporate TLS
/// inspection is legitimate, and a browser that refuses to work gets
/// uninstalled. Classification is therefore deliberately conservative.
/// Serialize is the IPC wire format; the chrome UI shows a full-width
/// warning for `intercepted` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsState {
    /// Chain issuer matches a known public CA.
    Normal,
    /// Chain issuer matches a known TLS-interception product — something on
    /// the network is decrypting traffic the user believes is private.
    Intercepted,
    /// Plaintext connection; there is no chain to classify.
    NotTls,
    /// A chain was available and its issuer matched nothing on either list
    /// (or the engine gave no usable issuer for THIS certificate) — an
    /// observation about this connection. Reported rather than guessed.
    Unknown,
    /// The platform exposes no way to read the serving certificate's chain
    /// at all, so no classification was ever attempted. This is a statement
    /// about the browser, not about the site: unlike `Unknown` it does NOT
    /// mean an issuer was inspected and not recognized. Same distinction
    /// `SettingState` draws between `NotAttempted` and `Failed`, and for the
    /// same reason — the UI copy for the two is not interchangeable.
    Unreadable,
}

/// Substring hints (matched case-insensitively) for the issuer names of
/// well-known TLS-interception products: corporate proxies and the
/// antivirus "web shields" that MITM connections with a locally installed
/// root. This is a heuristic, documented as such: WebKitGTK trusts the
/// system store, so a locally installed root is cryptographically
/// indistinguishable from a shipped one — name matching is the only signal
/// available in-process.
const INTERCEPTOR_ISSUER_HINTS: &[&str] = &[
    "fortinet",
    "fortigate",
    "fortica",
    "zscaler",
    "bluecoat",
    "blue coat",
    "palo alto",
    "netskope",
    "forcepoint",
    "websense",
    "barracuda",
    "sophos",
    "check point",
    "checkpoint",
    "watchguard",
    "sonicwall",
    "opendns",
    "cisco umbrella",
    "avast",
    "avg technologies",
    "kaspersky",
    "eset",
    "bitdefender",
    "norton",
    "symantec",
    "mcafee",
    "trend micro",
    "fiddler",
    "mitmproxy",
    "burp suite",
    "charles proxy",
];

/// Substring hints for well-known public CA names in issuer strings. Only
/// used after the interceptor list has failed to match, so a corporate CA
/// that happens to contain one of these words is still flagged first.
const PUBLIC_CA_ISSUER_HINTS: &[&str] = &[
    "digicert",
    "let's encrypt",
    "isrg",
    "globalsign",
    "sectigo",
    "comodo",
    "usertrust",
    "entrust",
    "godaddy",
    "starfield",
    "google trust services",
    "amazon",
    "baltimore",
    "verisign",
    "thawte",
    "geotrust",
    "rapidssl",
    "certum",
    "swisssign",
    "ssl.com",
];

/// Classifies a certificate issuer string. Interceptor hints win over
/// public-CA hints (a false "intercepted" warning is cheaper than a false
/// "normal" one). Anything unrecognized — including no issuer at all — is
/// `Unknown`, never a guess.
pub fn classify_issuer(issuer: Option<&str>) -> TlsState {
    let Some(issuer) = issuer else {
        return TlsState::Unknown;
    };
    let issuer = issuer.to_lowercase();
    if INTERCEPTOR_ISSUER_HINTS
        .iter()
        .any(|hint| issuer.contains(hint))
    {
        return TlsState::Intercepted;
    }
    if PUBLIC_CA_ISSUER_HINTS
        .iter()
        .any(|hint| issuer.contains(hint))
    {
        return TlsState::Normal;
    }
    TlsState::Unknown
}

/// The schemes that can put bytes on a network. One list, shared by
/// `host_of` and `classify_uri`, so the two can never disagree about what
/// counts as network-shaped.
const NETWORK_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];

/// Extracts a normalized host from a URL. Only schemes that can put bytes
/// on a network have a host worth ledgereing; everything else (data:,
/// blob:, about:, rbchrome:, file:) returns None. Normalization: lowercase,
/// no port, no userinfo, no trailing dot — so ledger keys and rule matches
/// are not defeated by cosmetic URL variation.
pub fn host_of(url: &str) -> Option<String> {
    let rest = NETWORK_SCHEMES
        .iter()
        .find_map(|prefix| url.strip_prefix(prefix))?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    // userinfo would poison the host if kept ("https://evil@real.com/").
    let authority = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal: host ends at ']'.
        stripped.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// The three ways a request URI can relate to the network. The distinction
/// exists for the frozen fail-closed rule: a network-shaped URI we cannot
/// attribute must be BLOCKED while frozen, but data:/blob:/about: cannot
/// put bytes on the wire and blocking them would break pages for nothing.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UriClass {
    /// http(s)/ws(s) with a parseable, normalized host.
    Network(String),
    /// A network scheme whose authority `host_of` could not parse. While
    /// frozen this fails CLOSED: unidentifiable is not the same as safe.
    NetworkOpaque,
    /// Non-network scheme (data:, blob:, about:, file:, custom). No bytes
    /// leave the machine, so a freeze has nothing to say about it.
    Local,
}

/// Splits a URI into the three classes above. Scheme list shared with
/// `host_of` (NETWORK_SCHEMES) so the two can never disagree.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn classify_uri(uri: &str) -> UriClass {
    // An engine that returns S_OK with an empty string has told us nothing,
    // and "nothing" classified as Local — which is allowed even while frozen.
    // Only `None` failed closed, in the one function whose job is failing
    // closed. An empty URI is now as opaque as an unreadable one.
    if uri.trim().is_empty() {
        return UriClass::NetworkOpaque;
    }
    // Schemes are case-INSENSITIVE per RFC 3986, and engines do normalise —
    // but a matcher that only recognises lowercase is a matcher an attacker
    // steps around by not lowercasing, and the cost of being right is one
    // allocation on a path that already allocates.
    let lowered = uri.to_ascii_lowercase();
    let network_scheme = NETWORK_SCHEMES.iter().any(|p| lowered.starts_with(p));
    match (network_scheme, host_of(&lowered)) {
        (true, Some(host)) => UriClass::Network(host),
        (true, None) => UriClass::NetworkOpaque,
        (false, _) => UriClass::Local,
    }
}

/// Suffix match with a dot boundary, so "notdoubleclick.net" does NOT match
/// the "doubleclick.net" rule while "ads.doubleclick.net" does.
///
/// Case-insensitive on both sides rather than requiring pre-lowercased input.
/// Rules ship lowercase and `host_of` already lowercases, so in practice this
/// compares equal-case bytes -- but making it total removes the caller's
/// obligation to remember, which is what the allocation in `blocks_host` was
/// paying for on every single request.
pub fn host_matches(host: &str, rule: &str) -> bool {
    host.eq_ignore_ascii_case(rule)
        || (host.len() > rule.len()
            && host.as_bytes()[host.len() - rule.len() - 1] == b'.'
            && host[host.len() - rule.len()..].eq_ignore_ascii_case(rule))
}

/// The rule set. Network rules are the security boundary (a matched
/// request never leaves the machine); cosmetic selectors are aesthetics
/// (hiding the empty container a blocked request leaves behind) and are
/// applied as a user STYLESHEET, never as injected script — content
/// webviews are never script-evaluated.
///
/// Structured as data (not hardcoded match arms) so a larger list can be
/// loaded later; `from_lines` is the seam for that.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    pub blocked_hosts: Vec<String>,
    pub cosmetic_selectors: Vec<String>,
}

impl RuleSet {
    /// Minimal line format — one host per line, `#` comments — so a bigger
    /// hosts-style list can be dropped in later without pulling in a
    /// filter-list crate. Deliberately NOT EasyList syntax.
    pub fn from_lines(input: &str) -> Self {
        let blocked_hosts = input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_lowercase())
            .collect();
        Self {
            blocked_hosts,
            cosmetic_selectors: Vec::new(),
        }
    }

    /// No allocation. This runs inside the `WebResourceRequested` handler on
    /// the Windows UI thread for EVERY request, and it used to `to_lowercase()`
    /// the host each time -- an allocation per subresource, redoing work
    /// `host_of` had already done. `host_matches` is case-insensitive now, so
    /// the copy bought nothing.
    pub fn blocks_host(&self, host: &str) -> bool {
        self.blocked_hosts
            .iter()
            .any(|rule| host_matches(host, rule))
    }
}

// ---------------------------------------------------------------------------
// GLOBAL PRIVACY CONTROL (GPC)
//
// GPC is an opt-out-of-sale/share signal with legal weight under CCPA/CPRA.
// PATANYX sends it two ways, because sites read it two ways:
//   * `Sec-GPC: 1` on outgoing requests (set in the platform interception
//     handlers -- Windows sets it on the WebResourceRequested request; the
//     Linux request header is a follow-up that needs a web-process
//     extension WebKitGTK does not expose from the UI process);
//   * `navigator.globalPrivacyControl === true`, presented by GPC_SCRIPT as
//     a registered document-start script (the same category as autofill.js),
//     never via evaluate_script.
// ---------------------------------------------------------------------------

/// Request header carrying the GPC signal. "1" is the only defined value;
/// the signal is binary: header present, or no preference stated.
pub const GPC_HEADER_NAME: &str = "Sec-GPC";
pub const GPC_HEADER_VALUE: &str = "1";

/// Document-start script presenting `navigator.globalPrivacyControl` to page
/// script. Registered with the engine (WebView2 initialization script on
/// Windows, WebKitGTK UserScript at Start on Linux), so it runs in the page's
/// MAIN world, before the page's own scripts, on every navigation.
///
/// The property is an own, non-writable, non-configurable data property on
/// the navigator object: a page must not be able to delete, redefine, or
/// assign over the signal it is being shown. The try/catch covers an exotic
/// realm that locks Navigator down; a privacy courtesy must never throw into
/// page script. The IIFE defines no globals of its own.
pub const GPC_SCRIPT: &str = r#"(function () {
  "use strict";
  try {
    Object.defineProperty(navigator, "globalPrivacyControl", {
      value: true,
      writable: false,
      enumerable: true,
      configurable: false,
    });
  } catch (e) {
    // defineProperty failing must stay silent: see the module comment.
  }
})();
"#;

#[cfg(test)]
mod gpc_tests {
    use super::{GPC_HEADER_NAME, GPC_HEADER_VALUE, GPC_SCRIPT};

    #[test]
    fn gpc_header_is_sec_gpc_1() {
        assert_eq!(GPC_HEADER_NAME, "Sec-GPC");
        assert_eq!(GPC_HEADER_VALUE, "1");
        assert_eq!(format!("{GPC_HEADER_NAME}: {GPC_HEADER_VALUE}"), "Sec-GPC: 1");
    }

    #[test]
    fn gpc_script_defines_true_once_and_locked() {
        assert!(GPC_SCRIPT.contains("navigator, \"globalPrivacyControl\""));
        assert!(GPC_SCRIPT.contains("value: true"));
        assert!(GPC_SCRIPT.contains("writable: false"));
        assert!(GPC_SCRIPT.contains("configurable: false"));
        // Exactly one property defined, no other global touched.
        assert_eq!(GPC_SCRIPT.matches("Object.defineProperty").count(), 1);
        assert!(!GPC_SCRIPT.contains("window."));
        // Guarded: registered into untrusted-page territory, it must not
        // throw uncaught.
        assert!(GPC_SCRIPT.contains("try {"));
        assert!(GPC_SCRIPT.contains("catch"));
    }
}

// ---------------------------------------------------------------------------
// Fingerprint Divergence -- fingerprint noise, the lite set.
//
// A site fingerprints a browser by reading high-entropy device readouts:
// canvas pixels, audio samples, the GPU model string. We feed every site a
// readout with small deterministic noise mixed in, seeded from
// (session token, top-frame host): stable for that site all session, unique
// per site, regenerated on restart. The identifier stops linking anything.
//
// Design decisions, so they are not re-litigated at the next reading:
//   * The session token is drawn ONCE per app start from OS randomness and
//     never persisted -- a token that survived restarts would make the noise
//     stable across restarts, which is itself a fingerprint. If randomness
//     is unavailable the answer is NO SCRIPT, never a fixed token, for the
//     same reason.
//   * TWO tokens, normal and ephemeral. With one, a site could link an
//     ephemeral-tab visit to a normal-tab visit by matching canvas hashes --
//     the exact linkage ephemeral tabs exist to prevent.
//   * Per-site keying uses the top-frame FULL HOSTNAME, resolved in-page,
//     not Rust-side eTLD+1 via psl.rs. A per-navigation push from Rust
//     would race page scripts and violate the only-the-chrome-webview
//     evaluate_script invariant (state.rs). Keying on the full hostname
//     rather than the registrable domain fails only in the safe direction: www.example.com and example.com get different noise
//     differently, so a fingerprinter sees MORE fragmentation, never less.
//   * The toggle (prefs::fingerprint_noise) applies to tabs created after a
//     change. Both engines accept registered scripts at construction only;
//     the same non-retroactive shape `ephemeral` has, and the panel copy
//     says so.
// ---------------------------------------------------------------------------

/// The template's token stand-in. Must appear exactly once in fingerprint_divergence.js --
/// pinned by `divergence_tests::template_carries_the_placeholder_exactly_once`,
/// because `replacen(.., 1)` substitutes the FIRST occurrence and a stray
/// second copy (say, in a comment) would ship the placeholder as the token.
const DIVERGENCE_TOKEN_PLACEHOLDER: &str = "__DIVERGENCE_TOKEN__";

/// Document-start script applying the noise; see the file's own header for
/// the endpoint-by-endpoint story and the worker-context hole. Registered
/// like GPC_SCRIPT (WebView2 document-created script on Windows, WebKitGTK
/// UserScript at Start on Linux), never via evaluate_script.
pub const DIVERGENCE_TEMPLATE: &str = include_str!("../content_scripts/fingerprint_divergence.js");

/// (normal, ephemeral). `None` inside the OnceLock records that OS
/// randomness failed at first use; every later call then skips divergence
/// rather than retrying into a half-seeded session.
static DIVERGENCE_TOKENS: OnceLock<Option<(String, String)>> = OnceLock::new();

fn divergence_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn divergence_session_tokens() -> Option<&'static (String, String)> {
    DIVERGENCE_TOKENS
        .get_or_init(|| {
            let mut buf = [0u8; 64];
            getrandom::getrandom(&mut buf).ok()?;
            Some((divergence_hex(&buf[..32]), divergence_hex(&buf[32..])))
        })
        .as_ref()
}

/// The script to register for a new webview, or `None` for "register
/// nothing" (pref off, or no OS randomness). Decision half; the I/O half is
/// [`divergence_script`], split the way `onboarding_resolved_for` is so tests
/// never touch the real prefs.json.
fn divergence_script_with(enabled: bool, ephemeral: bool) -> Option<String> {
    if !enabled {
        return None;
    }
    let (normal, eph) = divergence_session_tokens()?;
    let token = if ephemeral { eph } else { normal };
    Some(DIVERGENCE_TEMPLATE.replacen(DIVERGENCE_TOKEN_PLACEHOLDER, token, 1))
}

/// Called from both platforms' `build_content`. Reads the pref at tab build
/// time, so a toggle takes effect for the next tab without a restart.
pub fn divergence_script(ephemeral: bool) -> Option<String> {
    divergence_script_with(crate::prefs::load().fingerprint_noise, ephemeral)
}

#[cfg(test)]
mod divergence_tests {
    use super::{divergence_script_with, DIVERGENCE_TEMPLATE, DIVERGENCE_TOKEN_PLACEHOLDER};

    #[test]
    fn template_carries_the_placeholder_exactly_once() {
        // Twice would mean replacen(.., 1) ships the literal placeholder as
        // the token for the real occurrence; zero would mean no token at all.
        assert_eq!(
            DIVERGENCE_TEMPLATE.matches(DIVERGENCE_TOKEN_PLACEHOLDER).count(),
            1
        );
    }

    #[test]
    fn substitution_removes_the_placeholder() {
        let script = divergence_script_with(true, false).expect("token available in tests");
        assert!(!script.contains(DIVERGENCE_TOKEN_PLACEHOLDER));
        assert_ne!(script, DIVERGENCE_TEMPLATE);
    }

    #[test]
    fn the_token_is_stable_within_a_run_and_split_for_ephemeral() {
        let normal_a = divergence_script_with(true, false).unwrap();
        let normal_b = divergence_script_with(true, false).unwrap();
        let ephemeral = divergence_script_with(true, true).unwrap();
        // Stable: every normal tab this session gets the same noise, or a
        // site could tell two of this user's tabs apart.
        assert_eq!(normal_a, normal_b);
        // Split: an ephemeral tab must not share the normal tabs' noise, or
        // a canvas hash links the two visits.
        assert_ne!(normal_a, ephemeral);
    }

    #[test]
    fn disabled_means_no_script_at_all() {
        assert!(divergence_script_with(false, false).is_none());
        assert!(divergence_script_with(false, true).is_none());
    }

    #[test]
    fn the_script_is_guarded_and_keys_on_the_top_frame() {
        assert!(DIVERGENCE_TEMPLATE.contains("\"use strict\""));
        assert!(DIVERGENCE_TEMPLATE.contains("try {"));
        assert!(DIVERGENCE_TEMPLATE.contains("catch"));
        assert!(DIVERGENCE_TEMPLATE.contains("ancestorOrigins"));
    }

    #[test]
    fn the_script_has_zero_channels() {
        // The trust boundary from the script's header, pinned: nothing this
        // script could read may leave the page. autofill.js legitimately
        // speaks postMessage; this one must not even do that.
        for forbidden in [
            "fetch(",
            "XMLHttpRequest",
            "import(",
            "postMessage",
            "window.ipc",
            "window.chrome.webview",
        ] {
            assert!(
                !DIVERGENCE_TEMPLATE.contains(forbidden),
                "fingerprint_divergence.js must not contain {forbidden}"
            );
        }
    }
}

/// Small bundled set of major ad/tracker hosts. Intentionally tiny: it
/// exists to prove the machinery and cover the worst offenders, not to
/// compete with EasyList.
const BUNDLED_HOSTS: &[&str] = &[
    // Google ad/tracking stack.
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    "2mdn.net",
    // Programmatic exchanges.
    "adnxs.com",
    "adsrvr.org",
    "adform.net",
    "advertising.com",
    "amazon-adsystem.com",
    "pubmatic.com",
    "rubiconproject.com",
    "openx.net",
    "indexww.com",
    "casalemedia.com",
    "contextweb.com",
    "33across.com",
    "sharethrough.com",
    "criteo.com",
    "criteo.net",
    // Content-recommendation ad networks.
    "taboola.com",
    "outbrain.com",
    "revcontent.com",
    // Platform ad/tracking endpoints (not the platforms themselves —
    // blocking facebook.com would break the site, blocking
    // connect.facebook.net only breaks the tracking pixel).
    "connect.facebook.net",
    "ads.twitter.com",
    "analytics.twitter.com",
    "bat.bing.com",
    "ads.linkedin.com",
    "ads.yahoo.com",
    // Adobe analytics / Omniture (SiteCatalyst). demdex.net (Audience
    // Manager) is listed above; these are the analytics beacons.
    "omtrdc.net",
    "2o7.net",
    // Twitter/X conversion pixel (static.ads-twitter.com/uwt.js). The list
    // already has ads.twitter.com; ads-twitter.com is a DIFFERENT
    // registrable domain and was missing. NOT t.co -- t.co is Twitter's
    // link wrapper and blocking it breaks every link on the site.
    "ads-twitter.com",
    // Yandex ad network. an.yandex.ru is Yandex.Direct; a subdomain, so the
    // suffix matcher never touches yandex.ru search. NOT yandex.ru itself.
    "an.yandex.ru",
    "yandexadexchange.net",
    // Ad verification / measurement.
    "scorecardresearch.com",
    "quantserve.com",
    "moatads.com",
    "doubleverify.com",
    "adsafeprotected.com",
    // Behavioural analytics / session recording.
    "chartbeat.com",   // Chartbeat (static.chartbeat.com)
    "demdex.net",      // Adobe Audience Manager (dpm.demdex.net)
    "newrelic.com",    // New Relic agent (js-agent.newrelic.com); the
                       // nr-data.net RUM beacon is already listed below
    "hotjar.com",
    "mouseflow.com",
    "crazyegg.com",
    "luckyorange.com",
    "fullstory.com",
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "heapanalytics.com",
    "optimizely.com",
    "branch.io",
    "adjust.com",
    "appsflyer.com",
    "nr-data.net",
];

/// Small, conservative cosmetic set. Broad generic rules hide real page
/// content, so this sticks to containers that exist only to hold ads.
const COSMETIC_SELECTORS: &[&str] = &[
    ".adsbygoogle",
    "[id^='google_ads_']",
    "[id^='div-gpt-ad']",
    ".ad-banner",
    ".ad-container",
    "#ad-container",
    ".ad-slot",
    "[data-ad-slot]",
];

static BUNDLED: OnceLock<RuleSet> = OnceLock::new();

pub fn bundled_rules() -> &'static RuleSet {
    BUNDLED.get_or_init(|| RuleSet {
        blocked_hosts: BUNDLED_HOSTS.iter().map(|s| s.to_string()).collect(),
        cosmetic_selectors: COSMETIC_SELECTORS.iter().map(|s| s.to_string()).collect(),
    })
}

/// Escapes a host for use inside a WebKit content-blocker `url-filter` regex.
///
/// Hosts come from a rule list, not from user input, but a literal `.` in a
/// regex matches any character — so an unescaped `doubleclick.net` would also
/// match `doubleclickXnet`. Escaping is about matching the intended host
/// exactly, not about injection.
fn escape_host_for_filter(host: &str) -> String {
    let mut out = String::with_capacity(host.len() + 8);
    for ch in host.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' | '/'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// A `url-filter` regex matching `host` and any subdomain of it, anchored at
/// the scheme so it can only match the REQUEST's host — never a path segment
/// or query parameter that happens to contain the name.
fn host_url_filter(host: &str) -> String {
    // Trailing `[:/]` rather than an `([:/]|$)` alternation: WebKit's content
    // blocker accepts only a subset of regex and rejects the whole rule list
    // if any pattern is outside it — which silently means NO filter compiles
    // at all. A request URL always has a path or port after the authority
    // (engines normalise `https://host` to `https://host/`), so requiring one
    // costs nothing and keeps the pattern inside the supported subset.
    format!(
        "^https?://([^/]+\\.)?{}[:/]",
        escape_host_for_filter(host)
    )
}

/// Serializes network rules to WebKit content-blocker JSON.
///
/// The rule matches on `url-filter` — the REQUEST's URL — which is what
/// "block requests to this tracker" actually means, and what the Windows
/// backend does with `blocks_host(host_of(request_uri))`.
///
/// It deliberately does NOT use `if-domain`. In WebKit content blockers (and
/// in the `$domain=` syntax it inherits from) `if-domain` constrains the
/// TOP-LEVEL DOCUMENT's domain, not the request's. An earlier version paired
/// `url-filter: ".*"` with `if-domain: ["*doubleclick.net"]`, which reads as
/// "block everything while the user is browsing ON doubleclick.net" — the
/// inverse of the intent, and effectively a no-op in normal browsing. The two
/// backends silently disagreed while the UI told the user nothing was being
/// sent to trackers.
pub fn content_blocker_json(rules: &RuleSet) -> String {
    let entries: Vec<serde_json::Value> = rules
        .blocked_hosts
        .iter()
        .map(|host| {
            serde_json::json!({
                "trigger": {
                    "url-filter": host_url_filter(host),
                    "url-filter-is-case-sensitive": false,
                },
                "action": { "type": "block" },
            })
        })
        .collect();
    // Serialization of a Value tree cannot fail; the fallback keeps the
    // never-panic constraint literal rather than theoretical.
    serde_json::to_string(&serde_json::Value::Array(entries))
        .unwrap_or_else(|_| "[]".to_string())
}

/// The freeze filter: block every request, then re-allow the per-site
/// overrides. A frozen tab blocks navigations too — the user proceeds via
/// `unfreeze` or `allow_site`, both one call.
///
/// Exceptions are expressed as later `ignore-previous-rules` entries rather
/// than `unless-domain`, for the same reason as above: `unless-domain` matches
/// the DOCUMENT's domain, so allowing a third party (`api.example.com` while
/// on `example.com`) matched nothing, and allowing the page's own host
/// suppressed the block trigger for every request on the page — silently
/// lifting the entire freeze. WebKit applies rules in order, so "block all,
/// then ignore for these hosts" is the construction that means what the UI
/// says: this one host keeps working, everything else stays frozen.
pub fn freeze_filter_json(exceptions: &[String]) -> String {
    let mut rules = vec![serde_json::json!({
        "trigger": { "url-filter": ".*" },
        "action": { "type": "block" },
    })];
    for host in exceptions {
        rules.push(serde_json::json!({
            "trigger": {
                "url-filter": host_url_filter(host),
                "url-filter-is-case-sensitive": false,
            },
            "action": { "type": "ignore-previous-rules" },
        }));
    }
    serde_json::to_string(&serde_json::Value::Array(rules))
        .unwrap_or_else(|_| "[]".to_string())
}

/// One CSS rule hiding every known ad container. `!important` because the
/// page's own styles would otherwise win over a user sheet at equal
/// specificity.
pub fn cosmetic_css(rules: &RuleSet) -> String {
    if rules.cosmetic_selectors.is_empty() {
        return String::new();
    }
    format!(
        "{} {{ display: none !important; }}",
        rules.cosmetic_selectors.join(",\n")
    )
}

/// Deterministic identifier for a compiled filter, derived from its JSON so
/// that different rule sets (adblock vs. freeze-with-exceptions) never
/// collide in the store or in a UserContentManager. FNV-1a: no dependency,
/// stable across runs, collision-safe enough for same-process cache keys.
pub fn filter_id_for(json: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in json.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("patanyx-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- URL classification ------------------------------------------------

    #[test]
    fn host_extraction_normalizes() {
        assert_eq!(
            host_of("https://Sub.Example.COM:8443/path?q=1#frag"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            host_of("http://user:pass@example.com/"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_of("https://example.com./"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_of("wss://[2001:db8::1]:443/socket"),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(
            host_of("ws://localhost:9000"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn host_extraction_rejects_non_network_urls() {
        assert_eq!(host_of("data:text/html,<p>hi</p>"), None);
        assert_eq!(host_of("blob:https://example.com/uuid"), None);
        assert_eq!(host_of("about:blank"), None);
        assert_eq!(host_of("rbchrome://localhost/index.html"), None);
        assert_eq!(host_of("file:///etc/passwd"), None);
        assert_eq!(host_of("https:///no-authority"), None);
        assert_eq!(host_of("ftp://example.com/"), None);
    }

    // --- Rule matching (the property a blocked request relies on) ----------

    #[test]
    fn host_matching_respects_dot_boundary() {
        assert!(host_matches("doubleclick.net", "doubleclick.net"));
        assert!(host_matches("ads.doubleclick.net", "doubleclick.net"));
        assert!(host_matches("a.b.doubleclick.net", "doubleclick.net"));
        // Suffix without a boundary must NOT match.
        assert!(!host_matches("notdoubleclick.net", "doubleclick.net"));
        assert!(!host_matches("doubleclick.net.evil.com", "doubleclick.net"));
        assert!(!host_matches("example.com", "doubleclick.net"));
    }

    #[test]
    fn host_matching_is_case_insensitive_on_both_sides() {
        // `blocks_host` used to lowercase the host into a fresh String on
        // every request to make this work. The comparison does it now, so the
        // allocation could go -- but that only holds if the case-insensitivity
        // is real rather than incidental, which is what this pins.
        assert!(host_matches("DoubleClick.NET", "doubleclick.net"));
        assert!(host_matches("ADS.DOUBLECLICK.NET", "doubleclick.net"));
        assert!(host_matches("ads.doubleclick.net", "DoubleClick.Net"));
        // The dot boundary must survive the case folding, not be lost to it.
        assert!(!host_matches("NOTdoubleclick.net", "doubleclick.net"));
    }

    #[test]
    fn bundled_rules_block_trackers_not_the_open_web() {
        let rules = bundled_rules();
        assert!(rules.blocks_host("ADS.DoubleClick.NET"));
        assert!(rules.blocks_host("static.hotjar.com"));
        assert!(rules.blocks_host("connect.facebook.net"));
        // Trackers added 2026-08-04 from the privacytests.org run; suffix
        // match catches the real subdomains the pixels load from.
        assert!(rules.blocks_host("static.chartbeat.com"));
        assert!(rules.blocks_host("dpm.demdex.net"));
        assert!(rules.blocks_host("js-agent.newrelic.com"));
        assert!(rules.blocks_host("static.ads-twitter.com"));
        assert!(rules.blocks_host("an.yandex.ru"));
        // Surgical: the vendor ad hosts must never take the whole platform
        // with them -- that is the user-experience cost the project owner ruled
        // out. yandex.ru search and t.co links stay reachable.
        assert!(!rules.blocks_host("yandex.ru"));
        assert!(!rules.blocks_host("t.co"));
        assert!(!rules.blocks_host("google.com"));
        assert!(!rules.blocks_host("facebook.com"));
        assert!(!rules.blocks_host("example.com"));
        assert!(!rules.blocks_host("google.com"));
    }

    #[test]
    fn from_lines_is_the_future_import_seam() {
        let rules = RuleSet::from_lines("# comment\n\nExample.COM\ntracker.example\n");
        assert_eq!(
            rules.blocked_hosts,
            vec!["example.com".to_string(), "tracker.example".to_string()]
        );
        assert!(rules.cosmetic_selectors.is_empty());
    }

    // --- Content-blocker JSON (what unix feeds the engine) -----------------

    #[test]
    fn content_blocker_json_is_well_formed_and_complete() {
        let rules = bundled_rules();
        let json = content_blocker_json(rules);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entries = parsed.as_array().unwrap();
        assert_eq!(entries.len(), rules.blocked_hosts.len());
        for (entry, host) in entries.iter().zip(rules.blocked_hosts.iter()) {
            assert_eq!(entry["action"]["type"], "block");
            // Assert the MEANING, not the shape. The previous version of this
            // test asserted `url-filter == ".*"` and `if-domain == ["*host"]`
            // — which is a precise description of a rule that blocks nothing,
            // and it passed for as long as that rule shipped.
            let filter = entry["trigger"]["url-filter"].as_str().unwrap();
            assert!(
                entry["trigger"]["if-domain"].is_null(),
                "if-domain keys on the document, not the request"
            );
            assert!(
                regex_lite_match(filter, &format!("https://{host}/beacon")),
                "must block a request to {host}"
            );
            assert!(
                regex_lite_match(filter, &format!("https://sub.{host}/beacon")),
                "must block a request to a subdomain of {host}"
            );
            assert!(
                !regex_lite_match(filter, "https://example.com/index.html"),
                "must not block an unrelated host"
            );
        }
    }

    #[test]
    fn freeze_filter_blocks_everything_except_overrides() {
        // Bare freeze: one block-all rule, no exception rules.
        let json = freeze_filter_json(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["action"]["type"], "block");
        assert_eq!(parsed[0]["trigger"]["url-filter"], ".*");

        // An override must be a LATER ignore-previous-rules entry keyed on the
        // REQUEST url, not `unless-domain`. unless-domain matches the document
        // domain: allowing a third party matched nothing, and allowing the
        // page's own host lifted the whole freeze.
        let json = freeze_filter_json(&["example.com".to_string(), "app.io".to_string()]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rules = parsed.as_array().unwrap();
        assert_eq!(rules.len(), 3, "block-all plus one ignore per exception");
        assert_eq!(rules[0]["action"]["type"], "block");
        for rule in &rules[1..] {
            assert_eq!(rule["action"]["type"], "ignore-previous-rules");
            assert!(
                rule["trigger"]["unless-domain"].is_null(),
                "exceptions must not key on the document domain"
            );
        }
        let filters: Vec<&str> = rules[1..]
            .iter()
            .map(|r| r["trigger"]["url-filter"].as_str().unwrap())
            .collect();
        assert!(filters.iter().any(|f| f.contains("example\\.com")));
        assert!(filters.iter().any(|f| f.contains("app\\.io")));
    }

    /// The rule must match the REQUEST's host and nothing else. This is the
    /// property the previous shape-only test could not see: it asserted the
    /// JSON looked a certain way while that shape meant the opposite thing.
    #[test]
    fn block_rules_match_the_request_url_not_the_document() {
        let rules = RuleSet {
            blocked_hosts: vec!["doubleclick.net".to_string()],
            cosmetic_selectors: vec![],
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&content_blocker_json(&rules)).unwrap();
        let trigger = &parsed[0]["trigger"];

        // Never key on the top-level document.
        assert!(
            trigger["if-domain"].is_null(),
            "if-domain constrains the DOCUMENT domain — the inverse of the intent"
        );
        let filter = trigger["url-filter"].as_str().unwrap();
        assert_ne!(filter, ".*", "a match-everything filter blocks nothing useful");

        // The regex must accept the host and its subdomains, and reject
        // lookalikes and unrelated hosts.
        let re = regex_lite_match;
        assert!(re(filter, "https://doubleclick.net/pixel"));
        assert!(re(filter, "http://ads.doubleclick.net/x"));
        assert!(re(filter, "https://doubleclick.net:443/x"));
        assert!(!re(filter, "https://example.com/doubleclick.net"));
        assert!(!re(filter, "https://notdoubleclick.net/x"));
        assert!(!re(filter, "https://doubleclickXnet/x"));
    }

    /// Tiny anchored matcher covering the exact regex shape `host_url_filter`
    /// emits, so the semantic test above needs no regex dependency.
    fn regex_lite_match(filter: &str, url: &str) -> bool {
        let host = filter
            .trim_start_matches("^https?://([^/]+\\.)?")
            .trim_end_matches("[:/]")
            .replace("\\", "");
        let Some(rest) = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
        else {
            return false;
        };
        let authority = rest.split('/').next().unwrap_or("");
        let bare = authority.split(':').next().unwrap_or("");
        bare == host || bare.ends_with(&format!(".{host}"))
    }

    #[test]
    fn cosmetic_css_hides_selectors() {
        let css = cosmetic_css(bundled_rules());
        assert!(css.contains("display: none !important"));
        assert!(css.contains(".adsbygoogle"));
        assert_eq!(cosmetic_css(&RuleSet::default()), "");
    }

    #[test]
    fn filter_ids_are_stable_and_distinct() {
        let ads = content_blocker_json(bundled_rules());
        let freeze = freeze_filter_json(&[]);
        assert_eq!(filter_id_for(&ads), filter_id_for(&ads));
        assert_ne!(filter_id_for(&ads), filter_id_for(&freeze));
        assert_ne!(
            filter_id_for(&freeze),
            filter_id_for(&freeze_filter_json(&["x.com".to_string()]))
        );
    }

    // --- Ledger accounting ---------------------------------------------------

    #[test]
    fn ledger_counts_allowed_and_blocked_per_host() {
        let mut ledger = Ledger::default();
        ledger.record("a.com", false);
        ledger.record("a.com", false);
        ledger.record("a.com", true);
        ledger.record("b.com", false);
        let rows = ledger.snapshot();
        assert_eq!(rows.len(), 2);
        // a.com has 3 total, b.com 1: most-contacted first.
        assert_eq!(
            rows[0],
            HostRecord {
                host: "a.com".to_string(),
                allowed: 2,
                blocked: 1,
            }
        );
        assert_eq!(
            rows[1],
            HostRecord {
                host: "b.com".to_string(),
                allowed: 1,
                blocked: 0,
            }
        );
    }

    #[test]
    fn ledger_snapshot_order_is_stable() {
        let mut ledger = Ledger::default();
        ledger.record("z.com", false);
        ledger.record("m.com", false);
        let rows = ledger.snapshot();
        // Tie on totals: alphabetical.
        assert_eq!(rows[0].host, "m.com");
        assert_eq!(rows[1].host, "z.com");
    }

    // --- Session receipt ---------------------------------------------------

    #[test]
    fn session_fold_counts_refusals_not_contacts() {
        // The fold moves blocked_total(), not allowed + blocked: the receipt
        // reports what was REFUSED. Folding the contact total would inflate
        // the session number with requests the browser carried.
        let mut closed = Ledger::default();
        closed.record("a.com", false);
        closed.record("a.com", false);
        closed.record("a.com", true);
        let mut session = SessionBlocked::new();
        session.fold_closed_tab(closed);
        assert_eq!(session.total_with_live(std::iter::empty::<u64>()), 1);
    }

    #[test]
    fn a_tab_taken_at_close_cannot_be_counted_twice() {
        // THE BUG THIS CATCHES: if teardown ever runs twice for one tab,
        // the fold must see the refusals once. The teardown paths mem::take
        // the ledger out of the tab state, so the second take is empty --
        // the count MOVES from tab to session, it is never copied.
        let mut state_ledger = Ledger::default();
        state_ledger.record("a.com", true);
        state_ledger.record("b.com", true);
        state_ledger.record("b.com", false);

        let mut session = SessionBlocked::new();
        session.fold_closed_tab(std::mem::take(&mut state_ledger));
        // The racing second teardown folds what is left: nothing.
        session.fold_closed_tab(std::mem::take(&mut state_ledger));
        assert_eq!(session.total_with_live(std::iter::empty::<u64>()), 2);
    }

    #[test]
    fn a_correction_on_a_live_tab_lowers_the_session_total() {
        // The receipt's sentence is "refused requests never left the
        // browser". When a request counted as refused turns out to have
        // been allowed, the per-tab column is corrected; because the
        // session total sums live tabs AT READ TIME, the session number
        // follows for free. Were it snapshotted instead, one request that
        // left the browser would stay sold as one that did not.
        let mut tab = Ledger::default();
        tab.record("a.com", true);
        let session = SessionBlocked::new();
        assert_eq!(
            session.total_with_live(std::iter::once(tab.blocked_total())),
            1
        );
        tab.correct_block_to_allowed("a.com");
        assert_eq!(
            session.total_with_live(std::iter::once(tab.blocked_total())),
            0
        );
    }

    #[test]
    fn session_total_survives_close_and_includes_live_tabs() {
        let mut closed = Ledger::default();
        closed.record("a.com", true);
        let mut session = SessionBlocked::new();
        session.fold_closed_tab(closed);
        let mut open = Ledger::default();
        open.record("b.com", true);
        open.record("b.com", true);
        assert_eq!(
            session.total_with_live(std::iter::once(open.blocked_total())),
            3
        );
    }

    #[test]
    fn counts_are_numbers_only_where_blocking_is_observable() {
        // Where the platform cannot observe blocking, the counts must be
        // ABSENT, never zero -- zero reads as "nothing was refused", a
        // measurement that was never taken.
        assert_eq!(observable_counts(false, 412, 9), (None, None));
        assert_eq!(observable_counts(true, 412, 9), (Some(412), Some(9)));
    }

    #[test]
    fn the_process_wide_counter_counts_exactly_the_folds() {
        // The ONLY test that touches the global, so nothing else in this
        // test binary can race it; delta-asserted regardless.
        let before = session_blocked_total(std::iter::empty::<u64>());
        let mut tab = Ledger::default();
        tab.record("x.com", true);
        tab.record("x.com", true);
        fold_closed_tab(tab);
        assert_eq!(
            session_blocked_total(std::iter::empty::<u64>()) - before,
            2
        );
    }

    // --- Freeze state machine ------------------------------------------------

    #[test]
    fn an_armed_quiet_tab_reports_a_deadline_and_then_freezes() {
        // THE BUG THIS CATCHES, reported on Windows 2026-07-28: with
        // "freeze pages after they load" ticked, a loaded page that made no
        // further requests stayed at phase Loaded forever, so the toolbar said
        // "Live" on a tab that was armed to freeze. Enforcement was fine --
        // the next request WOULD have been blocked -- but the user has only
        // the report to go on, and the report was wrong.
        //
        // The lazy transition inside should_block cannot fix that, because a
        // quiet tab never calls it. So the controller must be able to say WHEN
        // it will freeze, and freeze on being told the time has come.
        let t0 = Instant::now();
        let mut f = FreezeController::new(true);
        f.on_load_started();
        f.on_load_finished(t0);

        let deadline = f
            .auto_freeze_deadline()
            .expect("an armed, loaded, quiet tab must report when it will freeze");
        assert_eq!(deadline, t0 + FREEZE_GRACE);

        // Before the grace period: not yet, and no request has happened.
        assert!(!f.should_auto_freeze(t0));
        assert_eq!(f.phase(), FreezePhase::Loaded);

        // After it: the timer-driven transition takes effect with no request.
        assert!(f.should_auto_freeze(deadline));
        f.freeze_auto_now();
        assert_eq!(
            f.phase(),
            FreezePhase::Frozen,
            "the tab must report Frozen once the grace period has passed, \
             whether or not anything asked it to block a request"
        );
        // And nothing is left pending: a frozen tab has no future deadline.
        assert!(f.auto_freeze_deadline().is_none());
    }

    #[test]
    fn an_unarmed_tab_never_reports_a_freeze_deadline() {
        // The event loop folds this deadline into its wait. A controller that
        // returned Some() while auto-freeze was OFF would wake the browser
        // forever for a transition that must never happen.
        let t0 = Instant::now();
        let mut f = FreezeController::new(false);
        f.on_load_started();
        f.on_load_finished(t0);
        assert!(f.auto_freeze_deadline().is_none());
        assert!(!f.should_auto_freeze(t0 + FREEZE_GRACE * 4));
    }

    #[test]
    fn loading_and_grace_allow_then_auto_freeze_blocks() {
        let mut f = FreezeController::new(true);
        let t0 = Instant::now();
        assert!(!f.should_block("example.com", t0)); // Loading
        f.on_load_finished(t0);
        assert!(!f.should_block("example.com", t0 + FREEZE_GRACE / 2));
        // Boundary is inclusive: at exactly grace the tab freezes.
        assert!(f.should_block("example.com", t0 + FREEZE_GRACE));
        assert_eq!(f.phase(), FreezePhase::Frozen);
    }

    #[test]
    fn auto_freeze_requires_the_policy_flag() {
        let mut f = FreezeController::new(false);
        let t0 = Instant::now();
        f.on_load_finished(t0);
        assert!(!f.should_block("example.com", t0 + FREEZE_GRACE * 10));
        assert_eq!(f.phase(), FreezePhase::Loaded);
    }

    #[test]
    fn override_allows_even_when_frozen() {
        let mut f = FreezeController::new(false);
        let t0 = Instant::now();
        f.add_override("App.Example.com"); // stored lowercase
        f.freeze();
        assert!(!f.should_block("app.example.com", t0));
        assert!(f.should_block("other.com", t0));
    }

    #[test]
    fn unfreeze_is_one_call_and_survives_until_next_navigation() {
        let mut f = FreezeController::new(true);
        let t0 = Instant::now();
        f.on_load_finished(t0);
        assert!(f.should_block("x.com", t0 + FREEZE_GRACE));
        f.unfreeze(t0 + FREEZE_GRACE * 2);
        assert!(!f.should_block("x.com", t0 + FREEZE_GRACE * 2));
        // Next navigation restarts the cycle: loading, grace, frozen again.
        f.on_load_started();
        let t1 = t0 + FREEZE_GRACE * 4;
        f.on_load_finished(t1);
        assert!(f.should_block("x.com", t1 + FREEZE_GRACE));
    }

    #[test]
    fn live_channel_inhibits_auto_freeze_but_not_manual_freeze() {
        let mut f = FreezeController::new(true);
        let t0 = Instant::now();
        f.on_load_finished(t0);
        f.note_live_channel();
        let late = t0 + FREEZE_GRACE * 10;
        assert!(!f.should_auto_freeze(late));
        assert!(!f.should_block("example.com", late));
        // The user can still freeze explicitly; intent beats the heuristic.
        f.freeze();
        assert!(f.should_block("example.com", late));
        // Navigation clears the live-channel flag for re-detection. The
        // manual freeze itself SURVIVES navigation (a page must not be able
        // to lift it), so lift it deliberately first, the way a user would.
        f.unfreeze(late);
        f.on_load_started();
        f.on_load_finished(late);
        assert!(f.should_auto_freeze(late + FREEZE_GRACE));
    }

    #[test]
    fn load_finishing_does_not_undo_a_manual_freeze() {
        let mut f = FreezeController::new(false);
        let t0 = Instant::now();
        f.freeze();
        f.on_load_finished(t0);
        assert!(f.should_block("x.com", t0));
    }

    // --- TLS classification ----------------------------------------------------

    #[test]
    fn known_interceptor_issuers_are_flagged() {
        assert_eq!(
            classify_issuer(Some("CN=Zscaler Intermediate Root CA (zscalertwo.net)")),
            TlsState::Intercepted
        );
        assert_eq!(
            classify_issuer(Some("CN=FortiGate CA, O=Fortinet")),
            TlsState::Intercepted
        );
        assert_eq!(
            classify_issuer(Some("CN=Avast Web/Mail Shield Root, O=AVAST Software")),
            TlsState::Intercepted
        );
    }

    #[test]
    fn known_public_ca_issuers_are_normal() {
        assert_eq!(
            classify_issuer(Some("CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1, O=DigiCert Inc")),
            TlsState::Normal
        );
        assert_eq!(
            classify_issuer(Some("CN=R3, O=Let's Encrypt, C=US")),
            TlsState::Normal
        );
    }

    #[test]
    fn unrecognized_or_missing_issuer_is_unknown_never_guessed() {
        assert_eq!(
            classify_issuer(Some("CN=Acme Corp Internal Root CA")),
            TlsState::Unknown
        );
        assert_eq!(classify_issuer(Some("")), TlsState::Unknown);
        assert_eq!(classify_issuer(None), TlsState::Unknown);
    }

    // --- Policy presets --------------------------------------------------------

    #[test]
    fn quarantine_is_the_full_paranoid_preset_in_one_call() {
        let q = TabPolicy::quarantine();
        assert!(q.ephemeral);
        assert!(!q.javascript);
        assert!(q.block_ads);
        assert!(q.freeze_after_load);
        assert_eq!(q.requested_profile_mode(), ProfileMode::Ephemeral);
        assert_eq!(
            TabPolicy::default().requested_profile_mode(),
            ProfileMode::Persistent
        );
    }

    /// The displayed storage mode follows the ENGINE, not the request.
    ///
    /// A quarantine tab asks for ephemeral storage. Until the engine confirms
    /// the in-private flag actually took, the panel must not tell the user
    /// this tab keeps nothing -- that promise covers cookies, cache and
    /// localStorage, and it used to be made purely on the strength of having
    /// asked. Understating it is the only safe direction to be wrong in.
    #[test]
    fn ephemeral_is_displayed_only_once_the_engine_confirms_it() {
        let mut st = TabState::new(&TabPolicy::quarantine());

        // Requested, not yet asked about (the unix backend's permanent state,
        // and every tab's state for the instant before harden_privacy runs).
        assert_eq!(st.ephemeral_confirmed, SettingState::NotAttempted);
        assert_eq!(
            st.profile_mode(),
            ProfileMode::Persistent,
            "an unconfirmed ephemeral tab must not be shown as ephemeral"
        );

        // The engine said no.
        st.ephemeral_confirmed = SettingState::Failed;
        assert_eq!(
            st.profile_mode(),
            ProfileMode::Persistent,
            "a REFUSED ephemeral tab is a persistent tab, whatever was asked"
        );

        // The engine agreed.
        st.ephemeral_confirmed = SettingState::Applied;
        assert_eq!(st.profile_mode(), ProfileMode::Ephemeral);

        // And confirmation cannot manufacture ephemeral storage on a tab that
        // never asked for it -- the readback compares against the request, so
        // "applied" on a persistent tab means confirmed-persistent.
        let mut persistent = TabState::new(&TabPolicy::default());
        persistent.ephemeral_confirmed = SettingState::Applied;
        assert_eq!(persistent.profile_mode(), ProfileMode::Persistent);
    }

    // --- IPC wire names (the chrome UI matches on these strings) -------------

    #[test]
    fn status_enums_serialize_to_stable_wire_names() {
        assert_eq!(
            serde_json::to_value(FreezePhase::Loading).unwrap(),
            serde_json::json!("loading")
        );
        assert_eq!(
            serde_json::to_value(FreezePhase::Loaded).unwrap(),
            serde_json::json!("loaded")
        );
        assert_eq!(
            serde_json::to_value(FreezePhase::Frozen).unwrap(),
            serde_json::json!("frozen")
        );
        assert_eq!(
            serde_json::to_value(ProfileMode::Persistent).unwrap(),
            serde_json::json!("persistent")
        );
        assert_eq!(
            serde_json::to_value(ProfileMode::Ephemeral).unwrap(),
            serde_json::json!("ephemeral")
        );
        assert_eq!(
            serde_json::to_value(TlsState::Normal).unwrap(),
            serde_json::json!("normal")
        );
        assert_eq!(
            serde_json::to_value(TlsState::Intercepted).unwrap(),
            serde_json::json!("intercepted")
        );
        assert_eq!(
            serde_json::to_value(TlsState::NotTls).unwrap(),
            serde_json::json!("not_tls")
        );
        assert_eq!(
            serde_json::to_value(TlsState::Unknown).unwrap(),
            serde_json::json!("unknown")
        );
        assert_eq!(
            serde_json::to_value(TlsState::Unreadable).unwrap(),
            serde_json::json!("unreadable")
        );
        let row = serde_json::to_value(HostRecord {
            host: "example.com".to_string(),
            allowed: 3,
            blocked: 1,
        })
        .unwrap();
        assert_eq!(
            row,
            serde_json::json!({ "host": "example.com", "allowed": 3, "blocked": 1 })
        );
    }
}

#[cfg(test)]
mod freeze_enforcement_tests {
    use super::{FreezeController, FreezeEnforcement, FreezePhase, FREEZE_GRACE};
    use std::time::{Duration, Instant};

    /// The defect this type exists to prevent: `freeze()` marks the phase
    /// Frozen synchronously, and the UI used to report "frozen, making no
    /// requests" from that alone. Nothing has been installed at this point.
    #[test]
    fn freeze_is_pending_not_active_until_the_engine_confirms() {
        let mut c = FreezeController::new(false);
        c.freeze();
        assert_eq!(c.phase(), FreezePhase::Frozen);
        assert_eq!(
            c.enforcement(),
            FreezeEnforcement::Pending,
            "a freeze must never report Active before the engine confirms it"
        );
        c.note_enforced();
        assert_eq!(c.enforcement(), FreezeEnforcement::Active);
    }

    /// A filter that fails to compile leaves the tab unprotected, and that
    /// has to be visible rather than swallowed.
    #[test]
    fn a_failed_compile_is_reported_not_swallowed() {
        let mut c = FreezeController::new(false);
        c.freeze();
        c.note_enforcement_failed();
        assert_eq!(c.enforcement(), FreezeEnforcement::Failed);
        // The REQUEST stands, so the button can still offer "unfreeze".
        assert_eq!(c.phase(), FreezePhase::Frozen);
    }

    #[test]
    fn unfreezing_clears_enforcement() {
        let mut c = FreezeController::new(false);
        c.freeze();
        c.note_enforced();
        c.unfreeze(Instant::now());
        assert_eq!(c.phase(), FreezePhase::Loaded);
        assert_eq!(c.enforcement(), FreezeEnforcement::Inactive);
    }

    /// WebKit's compile is async, so a confirmation can land AFTER the user
    /// has already unfrozen. It must not resurrect "enforced" on a tab that
    /// is deliberately live again — that would be the original bug inverted.
    #[test]
    fn a_late_confirmation_cannot_resurrect_a_lifted_freeze() {
        let mut c = FreezeController::new(false);
        c.freeze();
        c.unfreeze(Instant::now());
        c.note_enforced();
        assert_eq!(
            c.enforcement(),
            FreezeEnforcement::Inactive,
            "a stale callback must not mark an unfrozen tab enforced"
        );
        // Same for a late failure: it must not invent a scary state either.
        c.note_enforcement_failed();
        assert_eq!(c.enforcement(), FreezeEnforcement::Inactive);
    }

    /// A MANUAL freeze survives navigation. The old rationale here --
    /// "navigating drops the installed filter along with the page" -- was
    /// wrong on both backends, and the hole it left was a page lifting its
    /// own freeze by navigating itself one instruction before the request the
    /// freeze existed to stop.
    #[test]
    fn a_navigation_does_not_lift_a_manual_freeze() {
        let mut c = FreezeController::new(false);
        c.freeze();
        c.note_enforced();
        c.on_load_started();
        assert_eq!(
            c.phase(),
            FreezePhase::Frozen,
            "a page must not be able to navigate its way out of a freeze"
        );
        assert_eq!(c.enforcement(), FreezeEnforcement::Active);
        // The user's way out is unchanged, and is one call.
        c.unfreeze(Instant::now());
        c.on_load_started();
        assert_eq!(c.phase(), FreezePhase::Loading);
    }

    /// The other half: an AUTO-freeze is a heuristic about a finished page,
    /// not a stated intent, so it must yield to a navigation. Otherwise a
    /// clicked link does nothing and the browser looks broken.
    #[test]
    fn a_navigation_does_clear_an_auto_freeze() {
        let mut c = FreezeController::new(true);
        let t0 = Instant::now();
        c.on_load_finished(t0);
        assert!(c.should_block("x.com", t0 + FREEZE_GRACE));
        assert_eq!(c.phase(), FreezePhase::Frozen);
        c.on_load_started();
        assert_eq!(c.phase(), FreezePhase::Loading);
        assert_eq!(c.enforcement(), FreezeEnforcement::Inactive);
    }

    /// An auto-freeze goes through the same door, so it gets the same
    /// pending-until-confirmed treatment rather than a shortcut.
    #[test]
    fn auto_freeze_is_also_pending_until_confirmed() {
        let mut c = FreezeController::new(true);
        let t0 = Instant::now();
        c.on_load_finished(t0);
        assert!(c.should_auto_freeze(t0 + Duration::from_secs(5)));
        c.freeze();
        assert_eq!(c.enforcement(), FreezeEnforcement::Pending);
    }

    /// The wire spellings are matched by name in chrome.js; a rename here
    /// silently breaks the UI, exactly as it would for FreezePhase.
    #[test]
    fn enforcement_wire_names_are_stable() {
        assert_eq!(FreezeEnforcement::Inactive.as_str(), "inactive");
        assert_eq!(FreezeEnforcement::Pending.as_str(), "pending");
        assert_eq!(FreezeEnforcement::Active.as_str(), "active");
        assert_eq!(FreezeEnforcement::Failed.as_str(), "failed");
    }
}

/// The per-request decision the WebView2 handler makes, and the rules
/// governing what a freeze may CLAIM. Every test here runs on Linux; the
/// Windows backend contributes COM plumbing only.
///
/// These exist because the measured defect (2026-07-25, commit 98ec725)
/// was not in the state machine — that was correct and tested — but in the
/// untested caller that misused it. Testing the decision, not the shape of
/// the code around it, is the lesson from the ad-block regression whose
/// JSON-shape test passed while the rule blocked nothing.
#[cfg(test)]
mod request_decision_tests {
    use super::{
        classify_uri, host_of, host_url_filter, BlockReason, FreezeEnforcement, FreezePhase,
        InterceptionFailure, InterceptionState, RequestDecision, RuleSet, SettingState, TabPolicy,
        TabState, UriClass, FREEZE_GRACE,
    };
    use std::time::Instant;

    /// A tab with a fully registered handler, since that is the only
    /// configuration in which enforcement can be confirmed at all.
    fn registered_tab(policy: TabPolicy) -> TabState {
        let mut st = TabState::new(&policy);
        st.interception = InterceptionState::Registered {
            covers_workers: true,
        };
        st
    }

    fn rules() -> RuleSet {
        RuleSet::from_lines("doubleclick.net\ntracker.example\n")
    }

    fn blocking_policy() -> TabPolicy {
        TabPolicy {
            block_ads: true,
            ..TabPolicy::default()
        }
    }

    // --- the decision itself -------------------------------------------------

    /// The user's ASK and the engine's ANSWER are separate facts, and only the
    /// answer may be presented as a protection.
    ///
    /// This is the defect an adversarial review found in `apply_policy` on
    /// both backends: the policy was written first and unconditionally, the
    /// engine was asked second, and a refusal reported itself only through a
    /// debug-only log line. The panel then counted "JavaScript off" over a tab
    /// that was still running script.
    #[test]
    fn a_refused_setting_is_not_reported_as_a_protection() {
        let mut st = TabState::new(&TabPolicy {
            javascript: false,
            ..TabPolicy::default()
        });
        // A tab nobody has applied a policy to yet claims nothing.
        assert_eq!(st.script_setting, SettingState::NotAttempted);
        assert!(!st.script_setting.is_enforced());

        // The engine refused. The user's intent survives untouched -- that is
        // what they asked for and the UI should keep showing the toggle where
        // they left it -- but the protection is NOT in force.
        st.script_setting = SettingState::Failed;
        assert!(!st.policy.javascript, "the ask is unchanged");
        assert!(
            !st.script_setting.is_enforced(),
            "a refused setter must never read as enforced"
        );

        st.script_setting = SettingState::Applied;
        assert!(st.script_setting.is_enforced());
    }

    /// Stable across renames: these strings reach the chrome.
    #[test]
    fn setting_state_names_are_stable() {
        assert_eq!(SettingState::NotAttempted.as_str(), "not_attempted");
        assert_eq!(SettingState::Applied.as_str(), "applied");
        assert_eq!(SettingState::Failed.as_str(), "failed");
    }


    /// A blocked host stays blocked when the URL carries an explicit port.
    ///
    /// Not hypothetical: `scripts/blocking-probe.ps1` serves its probe page
    /// from a high port now, because binding :80 on Windows needs elevation
    /// and http.sys often has it reserved. If a port defeated the match, that
    /// probe would report "nothing was blocked" and the fault would look like
    /// the browser rather than the URL it was asked about.
    ///
    /// Both paths are checked because they parse differently: unix builds a
    /// regex ending `[:/]`, Windows extracts the host and drops the port.
    #[test]
    fn a_blocked_host_is_still_blocked_on_an_explicit_port() {
        assert_eq!(
            host_of("http://doubleclick.net:8090/pixel.png").as_deref(),
            Some("doubleclick.net"),
            "the Windows path must drop the port before matching"
        );

        let filter = host_url_filter("doubleclick.net");
        assert!(
            filter.ends_with("[:/]"),
            "the unix regex must admit a port as a host terminator: {filter}"
        );

        let mut tab = registered_tab(blocking_policy());
        let decision = tab.decide_request(
            Some("http://doubleclick.net:8090/pixel.png"),
            false,
            &rules(),
            Instant::now(),
        );
        assert!(
            matches!(decision, RequestDecision::Block(BlockReason::AdRule)),
            "a ported URL to a blocked host must still be blocked, got {decision:?}"
        );
    }


    #[test]
    fn a_frozen_tab_blocks_and_ledgers_an_ordinary_request() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        let d = st.decide_request(Some("https://x.com/a"), false, &rules(), Instant::now());
        assert_eq!(d, RequestDecision::Block(BlockReason::Freeze));
        let rows = st.ledger.snapshot();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host, "x.com");
        assert_eq!((rows[0].allowed, rows[0].blocked), (0, 1));
    }

    /// The old handler's `?` exits allowed a request out whenever the
    /// engine could not describe it. On a tab claiming to make no
    /// requests, "we could not tell what this was" must mean block.
    #[test]
    fn an_unreadable_uri_fails_closed_only_while_frozen() {
        let mut live = registered_tab(TabPolicy::default());
        assert_eq!(
            live.decide_request(None, false, &rules(), Instant::now()),
            RequestDecision::Allow
        );

        let mut frozen = registered_tab(TabPolicy::default());
        frozen.freeze.freeze();
        assert_eq!(
            frozen.decide_request(None, false, &rules(), Instant::now()),
            RequestDecision::Block(BlockReason::FrozenOpaque)
        );
        // Not ledgered: there is no host to key a user-facing row on.
        assert!(frozen.ledger.snapshot().is_empty());
    }

    #[test]
    fn a_network_shaped_unparseable_uri_fails_closed_while_frozen() {
        let mut frozen = registered_tab(TabPolicy::default());
        frozen.freeze.freeze();
        assert_eq!(
            frozen.decide_request(Some("https:///no-authority"), false, &rules(), Instant::now()),
            RequestDecision::Block(BlockReason::FrozenOpaque)
        );

        let mut live = registered_tab(TabPolicy::default());
        assert_eq!(
            live.decide_request(Some("https:///no-authority"), false, &rules(), Instant::now()),
            RequestDecision::Allow
        );
    }

    /// Fail-closed must not become block-everything: these schemes put no
    /// bytes on the wire, so blocking them breaks pages for no privacy
    /// gain whatsoever.
    #[test]
    fn local_schemes_are_never_blocked_even_frozen() {
        let mut st = registered_tab(blocking_policy());
        st.freeze.freeze();
        for uri in [
            "data:text/plain,hi",
            "about:blank",
            "blob:https://x.com/9f1",
            "file:///etc/hostname",
        ] {
            assert_eq!(
                st.decide_request(Some(uri), false, &rules(), Instant::now()),
                RequestDecision::Allow,
                "{uri} carries no network traffic and must stay allowed"
            );
        }
        assert!(st.ledger.snapshot().is_empty());
    }

    // --- WebSockets ----------------------------------------------------------

    /// The project owner's decision, 2026-07-26: a manual freeze blocks NEW
    /// upgrades. Inverting this test is the whole change if that is ever
    /// reversed.
    #[test]
    fn a_manual_freeze_blocks_new_websocket_upgrades() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        let d = st.decide_request(Some("ws://live.example/s"), true, &rules(), Instant::now());
        assert_eq!(d, RequestDecision::Block(BlockReason::Freeze));
        let rows = st.ledger.snapshot();
        assert_eq!((rows[0].host.as_str(), rows[0].blocked), ("live.example", 1));
    }

    /// Blocking upgrades must not cost the auto-freeze inhibition: a live
    /// app is still a live app, and the heuristic must keep its hands off
    /// it. (Mirror of live_channel_inhibits_auto_freeze_but_not_manual_freeze.)
    #[test]
    fn a_websocket_still_inhibits_auto_freeze_when_it_is_allowed() {
        let mut st = registered_tab(TabPolicy::default());
        let t0 = Instant::now();
        st.freeze.set_auto(true);
        st.on_load_finished(t0);
        let d = st.decide_request(Some("wss://live.example/s"), true, &rules(), t0);
        assert_eq!(d, RequestDecision::Allow);
        let rows = st.ledger.snapshot();
        assert_eq!((rows[0].host.as_str(), rows[0].allowed), ("live.example", 1));
        // The socket was seen, so the tab must not auto-freeze under it.
        assert!(!st.freeze.should_auto_freeze(t0 + FREEZE_GRACE * 10));
    }

    #[test]
    fn a_websocket_host_override_allows_the_upgrade_even_frozen() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.add_override("live.example");
        st.freeze.freeze();
        assert_eq!(
            st.decide_request(Some("ws://live.example/s"), true, &rules(), Instant::now()),
            RequestDecision::Allow
        );
    }

    /// The handler maps a FAILED ResourceContext read to websocket=false.
    /// That request must be decided on the ordinary path rather than
    /// inheriting anything from the socket branch.
    #[test]
    fn an_unreadable_context_does_not_inherit_the_socket_path() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        let d = st.decide_request(Some("ws://live.example/s"), false, &rules(), Instant::now());
        assert_eq!(d, RequestDecision::Block(BlockReason::Freeze));
        // ...and no live-channel inhibition was recorded from it.
        st.freeze.unfreeze(Instant::now());
        st.freeze.set_auto(true);
        let t0 = Instant::now();
        st.on_load_finished(t0);
        assert!(st.freeze.should_auto_freeze(t0 + FREEZE_GRACE));
    }

    // --- ads, overrides, auto-freeze -----------------------------------------

    #[test]
    fn ad_rules_block_only_with_the_policy_on_and_never_confirm_a_freeze() {
        // Spelled out rather than `TabPolicy::default()`: the default flipped
        // to blocking-ON on 2026-07-31, and this test is about the POLICY
        // GATE, not about what the default happens to be.
        let mut off = registered_tab(TabPolicy {
            block_ads: false,
            ..TabPolicy::default()
        });
        assert_eq!(
            off.decide_request(Some("https://ads.doubleclick.net/x"), false, &rules(), Instant::now()),
            RequestDecision::Allow
        );

        let mut on = registered_tab(blocking_policy());
        assert_eq!(
            on.decide_request(Some("https://ads.doubleclick.net/x"), false, &rules(), Instant::now()),
            RequestDecision::Block(BlockReason::AdRule)
        );

        assert!(!BlockReason::AdRule.confirms_freeze());
        assert!(BlockReason::Freeze.confirms_freeze());
        assert!(BlockReason::FrozenOpaque.confirms_freeze());
    }

    #[test]
    fn overrides_allow_through_decide_even_frozen() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.add_override("App.Example.com");
        st.freeze.freeze();
        assert_eq!(
            st.decide_request(Some("https://app.example.com/x"), false, &rules(), Instant::now()),
            RequestDecision::Allow
        );
        assert_eq!(
            st.decide_request(Some("https://other.com/x"), false, &rules(), Instant::now()),
            RequestDecision::Block(BlockReason::Freeze)
        );
    }

    /// WebView2 has no freeze timer; the transition happens lazily inside
    /// the decision. That equivalence with the timer-driven unix backend
    /// is the thing worth pinning.
    #[test]
    fn auto_freeze_transitions_inside_decide_request() {
        let mut st = registered_tab(TabPolicy {
            freeze_after_load: true,
            ..TabPolicy::default()
        });
        let t0 = Instant::now();
        st.on_load_finished(t0);
        assert_eq!(
            st.decide_request(Some("https://x.com/a"), false, &rules(), t0),
            RequestDecision::Allow
        );
        assert_eq!(
            st.decide_request(Some("https://x.com/b"), false, &rules(), t0 + FREEZE_GRACE),
            RequestDecision::Block(BlockReason::Freeze)
        );
        assert_eq!(st.freeze.phase(), FreezePhase::Frozen);
    }

    #[test]
    fn classify_uri_partitions_network_opaque_and_local() {
        assert_eq!(
            classify_uri("https://Example.COM:8443/p?q"),
            UriClass::Network("example.com".to_string())
        );
        assert_eq!(
            classify_uri("ws://user@host.example/s"),
            UriClass::Network("host.example".to_string())
        );
        assert_eq!(classify_uri("https:///nothing"), UriClass::NetworkOpaque);
        assert_eq!(classify_uri("http://"), UriClass::NetworkOpaque);
        for local in ["data:text/plain,x", "about:blank", "file:///x", "blob:https://x/1"] {
            assert_eq!(classify_uri(local), UriClass::Local, "{local}");
        }
    }

    // --- what a freeze may CLAIM (the measured defect) -----------------------

    /// No handler, no protection. Reporting Pending here would be a lie of
    /// omission: nothing is coming.
    #[test]
    fn freezing_a_tab_with_no_interception_reports_failed_at_once() {
        for state in [
            InterceptionState::NotAttempted,
            InterceptionState::Failed(InterceptionFailure::AddFilter),
            InterceptionState::Failed(InterceptionFailure::AttachHandler),
        ] {
            let mut st = TabState::new(&TabPolicy::default());
            st.interception = state;
            st.freeze.freeze_with_interception(st.interception);
            assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Failed, "{state:?}");
            // The REQUEST stands, so the button still offers "unfreeze".
            assert_eq!(st.freeze.phase(), FreezePhase::Frozen);
        }
    }

    /// The legacy WebResourceRequested filter delivers DOCUMENT-sourced
    /// requests only, so workers keep talking. "Making no network
    /// requests" is unclaimable on such a runtime.
    #[test]
    fn freezing_with_only_the_legacy_filter_reports_failed() {
        let mut st = TabState::new(&TabPolicy::default());
        st.interception = InterceptionState::Registered {
            covers_workers: false,
        };
        st.freeze.freeze_with_interception(st.interception);
        assert_eq!(
            st.freeze.enforcement(),
            FreezeEnforcement::Failed,
            "a filter that misses workers must never report enforced"
        );
    }

    /// The core honesty rule. Registration proves two HRESULTs succeeded;
    /// it does NOT prove CreateWebResourceResponse/SetResponse works, and
    /// that is one of the ranked candidates for the measured failure. So:
    /// Pending until the engine actually accepts a 403.
    #[test]
    fn a_registered_tab_stays_pending_until_a_block_is_confirmed() {
        let mut st = registered_tab(TabPolicy::default());
        // Events having fired proves nothing about the block path.
        st.decide_request(Some("https://x.com/a"), false, &rules(), Instant::now());
        assert!(st.handler_events > 0);

        st.freeze.freeze_with_interception(st.interception);
        assert_eq!(
            st.freeze.enforcement(),
            FreezeEnforcement::Pending,
            "prior handler traffic must not confirm the block path"
        );

        assert!(st.confirm_freeze_block(), "the Pending -> Active edge");
        assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Active);
        assert!(
            !st.confirm_freeze_block(),
            "the edge fires once, so the diagnostic prints once"
        );
    }

    /// The back door the legacy=Failed decision opens if unguarded:
    /// note_enforced() only checks phase, so a blocked DOCUMENT request on
    /// a legacy runtime would flip Failed straight back to Active.
    #[test]
    fn a_successful_block_under_legacy_registration_never_claims_active() {
        let mut st = TabState::new(&TabPolicy::default());
        st.interception = InterceptionState::Registered {
            covers_workers: false,
        };
        st.freeze.freeze_with_interception(st.interception);
        assert!(!st.confirm_freeze_block());
        assert_eq!(
            st.freeze.enforcement(),
            FreezeEnforcement::Failed,
            "a document-only block must not resurrect the claim"
        );
    }

    /// The 403 errored, so the request went out. Whatever the UI was
    /// saying, it stops saying it now.
    #[test]
    fn a_block_failure_downgrades_a_confirmed_freeze() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze_with_interception(st.interception);
        assert!(st.confirm_freeze_block());
        st.freeze_block_failed(None);
        assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Failed);
        assert_eq!(st.freeze.phase(), FreezePhase::Frozen);
        // And it does not win the claim back within the same freeze.
        assert!(!st.confirm_freeze_block());
        assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Failed);
    }

    /// A fresh freeze is a fresh attempt: re-freezing resets to Pending so
    /// a recovered engine can prove itself again.
    #[test]
    fn refreezing_after_a_failure_starts_a_new_attempt() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze_with_interception(st.interception);
        st.freeze_block_failed(None);
        st.freeze.unfreeze(Instant::now());
        st.freeze.freeze_with_interception(st.interception);
        assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Pending);
        assert!(st.confirm_freeze_block());
    }

    /// An auto-freeze never passes through `freeze_with_interception` — it
    /// transitions lazily inside `should_block` — so without the reconcile
    /// in `decide_request` it would sit at Pending forever on exactly the
    /// tab the manual path calls Failed. Two doors, one verdict.
    #[test]
    fn an_auto_freeze_on_an_unenforceable_tab_also_reports_failed() {
        for state in [
            InterceptionState::NotAttempted,
            InterceptionState::Failed(InterceptionFailure::AttachHandler),
            InterceptionState::Registered {
                covers_workers: false,
            },
        ] {
            let mut st = TabState::new(&TabPolicy {
                freeze_after_load: true,
                ..TabPolicy::default()
            });
            st.interception = state;
            let t0 = Instant::now();
            st.on_load_finished(t0);
            // Past the grace period: this request performs the auto-freeze.
            let d = st.decide_request(Some("https://x.com/a"), false, &rules(), t0 + FREEZE_GRACE);
            assert_eq!(d, RequestDecision::Block(BlockReason::Freeze), "{state:?}");
            assert_eq!(st.freeze.phase(), FreezePhase::Frozen);
            assert_eq!(
                st.freeze.enforcement(),
                FreezeEnforcement::Failed,
                "an auto-freeze this tab cannot enforce must say so: {state:?}"
            );
        }
    }

    /// The same path on a healthy tab must NOT be dragged down by the
    /// reconcile: it stays Pending, then confirms on the block.
    #[test]
    fn an_auto_freeze_on_a_registered_tab_still_confirms_normally() {
        let mut st = registered_tab(TabPolicy {
            freeze_after_load: true,
            ..TabPolicy::default()
        });
        let t0 = Instant::now();
        st.on_load_finished(t0);
        assert_eq!(
            st.decide_request(Some("https://x.com/a"), false, &rules(), t0 + FREEZE_GRACE),
            RequestDecision::Block(BlockReason::Freeze)
        );
        assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Pending);
        assert!(st.confirm_freeze_block());
        assert_eq!(st.freeze.enforcement(), FreezeEnforcement::Active);
    }

    /// The panel tells the user that requests counted as blocked never left
    /// the browser. A block the ENGINE refused to carry out must therefore
    /// not stay counted as blocked, or that sentence is false about egress.
    #[test]
    fn a_block_the_engine_refused_stops_counting_as_blocked() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        assert_eq!(
            st.decide_request(Some("https://x.com/a"), false, &rules(), Instant::now()),
            RequestDecision::Block(BlockReason::Freeze)
        );
        let before = st.ledger.snapshot();
        assert_eq!((before[0].allowed, before[0].blocked), (0, 1));

        // The engine would not synthesize the 403; the bytes went out.
        st.freeze_block_failed(Some("https://x.com/a"));
        let after = st.ledger.snapshot();
        assert_eq!(
            (after[0].allowed, after[0].blocked),
            (1, 0),
            "a request that got away must not be counted as one that never left"
        );
    }

    /// The fail-closed function must not fail OPEN on the inputs it exists
    /// for: an engine returning success with an empty string, or a scheme
    /// that is not lowercase.
    #[test]
    fn an_empty_or_oddly_cased_uri_does_not_slip_through_a_freeze() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        for uri in ["", "   ", "HTTPS://Tracker.example/x", "HtTp://x.test/y"] {
            assert!(
                matches!(
                    st.decide_request(Some(uri), false, &rules(), Instant::now()),
                    RequestDecision::Block(_)
                ),
                "{uri:?} escaped a freeze"
            );
        }
        // Control: genuinely local schemes are still allowed, whatever their
        // case, because they put no bytes on the wire.
        for uri in ["DATA:text/plain,x", "About:Blank"] {
            assert_eq!(
                st.decide_request(Some(uri), false, &rules(), Instant::now()),
                RequestDecision::Allow,
                "{uri:?} carries no traffic and must stay allowed"
            );
        }
    }

    /// Content may not fetch the chrome UI's own origin, from any frame.
    ///
    /// The navigation-time allowlist (`is_allowed_content_url`) is driven from
    /// `NavigationStarting`, which fires for the TOP LEVEL only on WebView2 --
    /// so an iframe naming `rbchrome.localhost` never reached it. The request
    /// filter sees every source kind, which is why the check lives here.
    #[test]
    fn content_cannot_fetch_the_chrome_origin_from_any_frame() {
        let mut st = registered_tab(TabPolicy::default());
        for uri in [
            "http://rbchrome.localhost/index.html",
            "http://rbchrome.localhost/chrome.js",
            // Case and port are normalised by classify_uri, so these are the
            // same origin wearing different spellings.
            "HTTP://RBChrome.LocalHost/index.html",
            "http://rbchrome.localhost:80/",
        ] {
            assert_eq!(
                st.decide_request(Some(uri), false, &rules(), Instant::now()),
                RequestDecision::Block(BlockReason::ReservedOrigin),
                "{uri:?} reached the browser's own UI origin from content"
            );
        }

        // NOT over-broad. A host that merely CONTAINS the reserved name is an
        // ordinary site and must load: refusing these would hand anyone the
        // ability to make a domain unreachable by naming it after ours.
        for uri in [
            "https://rbchrome.localhost.evil.com/",
            "https://notrbchrome.localhost/",
            "https://example.com/rbchrome.localhost",
        ] {
            assert_eq!(
                st.decide_request(Some(uri), false, &rules(), Instant::now()),
                RequestDecision::Allow,
                "{uri:?} is an ordinary address and must not be blocked"
            );
        }

        // And the block is not a freeze confirmation: it would have happened
        // with no freeze at all, so it must not upgrade enforcement.
        assert!(!BlockReason::ReservedOrigin.confirms_freeze());
    }

    #[test]
    fn interception_wire_names_are_stable() {
        // The unix backend reports its own mechanism rather than one of
        // these, and that is deliberate -- but the chrome matches on the
        // whole set, so the extra name belongs in the same list as the
        // others rather than living only in unix.rs.
        assert_eq!(super::UNIX_INTERCEPTION_NAME, "content_filter");
        assert_eq!(InterceptionState::NotAttempted.as_str(), "not_attempted");
        assert_eq!(
            InterceptionState::Registered {
                covers_workers: true
            }
            .as_str(),
            "registered"
        );
        assert_eq!(
            InterceptionState::Registered {
                covers_workers: false
            }
            .as_str(),
            "registered_legacy"
        );
        assert_eq!(
            InterceptionState::Failed(InterceptionFailure::AddFilter).as_str(),
            "failed"
        );
    }
}

#[cfg(test)]
mod local_network_tests {
    use super::*;

    fn insecure_tab() -> TabState {
        let mut st = TabState::new(&TabPolicy::default());
        st.on_load_started(Some("http://news.example/article"));
        st
    }
    fn secure_tab() -> TabState {
        let mut st = TabState::new(&TabPolicy::default());
        st.on_load_started(Some("https://news.example/article"));
        st
    }

    /// The address families a page has no business reaching. Each is a real
    /// target: routers on 192.168, printers and NAS boxes on 10, developer
    /// servers on loopback, and 169.254.169.254 which is the cloud metadata
    /// endpoint and the nastiest single address in the list.
    #[test]
    fn an_insecure_page_cannot_reach_the_local_network() {
        for host in [
            "127.0.0.1",
            "127.9.9.9",
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "localhost",
            "router.localhost",
            "[::1]",
            "[fd00::1]",
            "[fe80::1]",
            "[::ffff:192.168.1.1]",
        ] {
            let mut st = insecure_tab();
            let uri = format!("http://{host}/status");
            let d = st.decide_request(Some(&uri), false, &RuleSet::default(), Instant::now());
            assert_eq!(
                d,
                RequestDecision::Block(BlockReason::LocalNetwork),
                "an http page must not reach {host}"
            );
        }
    }

    /// The project owner's scope, stated as a test so nobody widens or narrows it
    /// by accident. An HTTPS page reaching the same address is OUT OF SCOPE
    /// and deliberately allowed; the About copy says so.
    #[test]
    fn a_secure_page_is_out_of_scope_and_allowed() {
        for host in ["127.0.0.1", "192.168.1.1", "169.254.169.254"] {
            let mut st = secure_tab();
            let uri = format!("http://{host}/status");
            let d = st.decide_request(Some(&uri), false, &RuleSet::default(), Instant::now());
            assert_eq!(
                d,
                RequestDecision::Allow,
                "https pages are out of scope for this boundary: {host}"
            );
        }
    }

    /// Ordinary browsing must not break. A public address that merely looks
    /// adjacent to a private range is public.
    #[test]
    fn public_destinations_are_untouched() {
        for host in [
            "example.com",
            "172.15.0.1",
            "172.32.0.1",
            "11.0.0.1",
            "192.169.1.1",
            "169.253.0.1",
            "100.63.0.1",
            "100.128.0.1",
            "8.8.8.8",
            "notlocalhost.example",
            "[2606:4700::1111]",
        ] {
            let mut st = insecure_tab();
            let uri = format!("http://{host}/page");
            let d = st.decide_request(Some(&uri), false, &RuleSet::default(), Instant::now());
            assert_eq!(d, RequestDecision::Allow, "{host} is public");
        }
    }

    /// A tab whose page URL the engine could not report must not start
    /// blocking its own subresources. Unknown counts as secure.
    #[test]
    fn an_unknown_page_url_does_not_enable_the_boundary() {
        let mut st = TabState::new(&TabPolicy::default());
        st.on_load_started(None);
        let d = st.decide_request(
            Some("http://192.168.1.1/"),
            false,
            &RuleSet::default(),
            Instant::now(),
        );
        assert_eq!(d, RequestDecision::Allow);
    }

    /// Navigating from an http page to an https one must lift the boundary,
    /// or a tab stays restricted for the rest of its life.
    #[test]
    fn the_boundary_follows_the_current_page_not_the_first_one() {
        let mut st = insecure_tab();
        assert!(st.page_insecure);
        st.on_load_started(Some("https://secure.example/"));
        assert!(!st.page_insecure, "navigating to https must lift it");
        st.on_load_started(Some("http://back.example/"));
        assert!(st.page_insecure, "and navigating back must restore it");
    }

    /// WebSockets are the other way a page reaches a local device, and they
    /// take a different path through decide_request.
    #[test]
    fn a_websocket_to_a_local_address_is_blocked_too() {
        let mut st = insecure_tab();
        let d = st.decide_request(
            Some("ws://192.168.1.1:8080/"),
            true,
            &RuleSet::default(),
            Instant::now(),
        );
        assert_eq!(d, RequestDecision::Block(BlockReason::LocalNetwork));
    }

    /// THE DOCUMENTED LIMIT. A hostname that resolves to a private address is
    /// not caught, because this layer only ever sees a URL. Pinned as a test
    /// so the gap is deliberate and visible rather than discovered later.
    #[test]
    fn a_rebinding_hostname_is_not_caught_and_that_is_known() {
        let mut st = insecure_tab();
        let d = st.decide_request(
            Some("http://rebind.attacker.example/"),
            false,
            &RuleSet::default(),
            Instant::now(),
        );
        assert_eq!(
            d,
            RequestDecision::Allow,
            "documented limit: DNS rebinding needs a post-resolution hook this browser has not got"
        );
    }
}
