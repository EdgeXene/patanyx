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
    /// historical behaviour"). The default was flipped: a privacy browser
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

/// The engine-confirmed tracking-prevention level.
///
/// A generic `Applied` loses the fact field diagnostics need most: whether the
/// profile was running Strict or Balanced. This type keeps the accepted level
/// in the wire value and reserves `Failed` for an unconfirmed setter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackingPreventionState {
    Strict,
    Balanced,
    Failed,
    NotAttempted,
}

impl TrackingPreventionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Failed => "failed",
            Self::NotAttempted => "not_attempted",
        }
    }
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
        [127, ..] => true,                               // loopback
        [10, ..] => true,                                // RFC1918
        [172, b, ..] if (16..=31).contains(&b) => true,  // RFC1918
        [192, 168, ..] => true,                          // RFC1918
        [169, 254, ..] => true,                          // link-local, incl. 169.254.169.254
        [100, b, ..] if (64..=127).contains(&b) => true, // CGNAT
        [0, ..] => true,                                 // "this network"
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
    /// The one host this tab may reach despite the ad/tracker list, after the
    /// user answered the held-page banner.
    ///
    /// `Option`, never a set. A set would accumulate hosts for the life of the
    /// tab from one banner each, which is the shape the malicious-host
    /// override has and deliberately not this one: the user consents to a
    /// page, not to a growing list.
    ///
    /// Not persisted and not shared. It dies with the tab, and it is dropped
    /// when the tab's committed top-level host changes, which is the sentence
    /// the banner puts in front of the user.
    adlist_override: Option<String>,
    /// Which intercepted request is the top-level document. Windows-only in
    /// use, platform-neutral in shape: the rule is pure and tested everywhere
    /// (see `toplevel_request`), and it lives here so the navigation events
    /// and the request handler reach it through the one `state` Rc they
    /// already hold rather than a second one threaded through every closure.
    pub toplevel: crate::toplevel_request::TopLevelRequests,
    /// The method of the most recent top-level navigation, "GET" or "POST".
    /// Read when a held page is raised, because a held form submission cannot
    /// be replayed and the banner must say so before the click.
    pub last_top_level_method: String,
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
    /// The serving certificate's issuer name, for DISPLAY ONLY -- the Info tab
    /// shows "Issued by X". It is NEVER an input to any decision: the verdict
    /// (`classify_issuer`) is, and a pinned test holds that line. Stored on the
    /// failure path because a failed cert's issuer is otherwise lost; the live
    /// path re-reads it from the current certificate.
    pub tls_issuer: Option<String>,
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
    /// Which tracking-prevention level was actually accepted. Needs Runtime
    /// 111+; `Failed` means the requested level was not confirmed.
    pub tracking_prevention: TrackingPreventionState,
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
    /// Whether a document in this tab has announced that it is listening for
    /// translation commands.
    ///
    /// WINDOWS ONLY. WebKitGTK carries the same news differently -- a parked
    /// poll IS the announcement there, so the unix backend reads its outbox
    /// instead of this field and never sets it. Both are reached through
    /// `platform::translate_page_ready`, so callers see one signal.
    ///
    /// Reset on every navigation, because the document that announced itself
    /// is gone and the next one has not spoken yet. A stale true would offer
    /// the user a control whose command lands nowhere.
    pub translate_page_ready: bool,
    /// Whether the one-way channel used by Fingerprint Divergence to push
    /// batched count deltas registered for this tab. This says only that the
    /// channel exists; the counts themselves remain untrusted page claims.
    pub fingerprint_probe_reporting: SettingState,
    /// See `EngineSettings::permissions_registered`.
    pub permissions_registered: SettingState,
    /// WebView2's id for this tab's registered page-scrollbar script
    /// (`page_scrollbar_script`), kept so a palette change can REMOVE the
    /// old registration before adding the new one -- without it every
    /// accent change would stack another script on the tab, each adopting
    /// its own sheet on the next load. `None` on unix, where the sheet is
    /// swapped through the content manager instead, and on a tab whose
    /// registration the engine refused.
    pub scrollbar_script_id: Option<String>,
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
            adlist_override: None,
            toplevel: crate::toplevel_request::TopLevelRequests::default(),
            last_top_level_method: "GET".to_string(),
            page_insecure: false,
            tls_error_verdict: None,
            tls_issuer: None,
            freeze_json: None,
            interception: InterceptionState::NotAttempted,
            script_setting: SettingState::NotAttempted,
            smartscreen_off: SettingState::NotAttempted,
            tracking_prevention: TrackingPreventionState::NotAttempted,
            navigation_tracking: SettingState::NotAttempted,
            autofill_off: SettingState::NotAttempted,
            ephemeral_confirmed: SettingState::NotAttempted,
            handler_events: 0,
            content_script_registered: SettingState::NotAttempted,
            translate_page_ready: false,
            fingerprint_probe_reporting: SettingState::NotAttempted,
            permissions_registered: SettingState::NotAttempted,
            scrollbar_script_id: None,
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
        // The document that announced itself is gone. The next one has not
        // spoken yet, and until it does there is nothing listening for a
        // translation command. (Windows only; see the field.)
        self.translate_page_ready = false;
        self.freeze.on_load_started();
        self.tls_error_verdict = None;
        self.tls_issuer = None;
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
    ///
    /// `override_host` is the tab's ad-list override, set when the user
    /// answered "Open anyway" on the blocked-navigation banner: "this tab may
    /// reach THIS host despite the ad/tracker list". It is an INPUT rather
    /// than state on the tab so that the decision stays a function of its
    /// arguments, which is what makes every rule here provable on a box with
    /// no WebView2.
    ///
    /// It exempts the AdRule predicate and nothing else. Freeze, the reserved
    /// chrome origin, and the malicious list (checked by the caller, above
    /// this function) are all unaffected, and the request is still ledgered --
    /// as ALLOWED, because it is about to be sent. EXACT host equality, never
    /// a suffix match: `sub.tracker.example` is a different host from
    /// `tracker.example` and the user consented to one of them. The WebKitGTK
    /// side anchors its exception rule to the exact host for the same reason,
    /// so the two engines agree about what was consented to.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn decide_request(
        &mut self,
        uri: Option<&str>,
        websocket: bool,
        rules: &RuleSet,
        now: Instant,
        override_host: Option<&str>,
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
        let decision = self.decide_inner(class, websocket, rules, now, override_host);
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
        override_host: Option<&str>,
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
                // The override lifts the ad rule for ONE host. Written as
                // an equality against the whole host, not a suffix test: a
                // suffix test would make consent to `tracker.example` also
                // consent to `evil.tracker.example`, which the user never saw.
                let overridden = override_host.is_some_and(|allowed| allowed == host);
                let ads = self.policy.block_ads && !overridden && rules.blocks_host(&host);
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

    /// This tab's ad-list override, if the user consented to one.
    ///
    /// Owned by TabState so the engine adapter has somewhere to read it from
    /// without reaching into the consent machine, and returned by value
    /// because the caller holds a RefCell borrow it must release before any
    /// COM call (see the borrow comment at the Windows request handler).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn adlist_override_host(&self) -> Option<String> {
        self.adlist_override.clone()
    }

    /// Set or clear the override. Clearing is not an afterthought here: it is
    /// the same call, so the revocation cannot be the path nobody wrote.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn set_adlist_override(&mut self, host: Option<String>) {
        self.adlist_override = host;
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
    // The inspection products Symantec shipped after acquiring Blue Coat,
    // named specifically. The bare "symantec" token used to stand in for
    // these and swept up Managed PKI for SSL and the Class 3 public roots
    // with them -- issuance, not interception. `bluecoat` still catches the
    // ProxySG-branded deployments; these two are the WSS-branded ones it
    // does not.
    "symantec web security",
    "symantec ssl visibility",
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

/// Whether `needle` appears in `haystack` STARTING at a word boundary.
///
/// A bare `contains` fired from inside unrelated words, and the banner it
/// raises states a fact in the flat indicative, so a collision is the browser
/// telling a user something false about their connection. Two real ones:
/// `eset` inside "G**eset**zliche Krankenversicherung" (a German health
/// insurer's internal CA) and inside "Pr**eset** Analytics". Both classified
/// as interception.
///
/// THE START ONLY, and that asymmetry is the whole design. Requiring a
/// boundary at BOTH ends looked tidier and silently broke real detection:
/// Fiddler's root is `CN=DO_NOT_TRUST_FiddlerRoot, ... OU=Created by
/// http://www.fiddler2.com`, where `fiddler` is followed by `R` and by `2`.
/// Both occurrences were rejected and a live interception proxy classified as
/// Unknown.
///
/// Vendor names appear as the PREFIX of a compound certificate name --
/// FiddlerRoot, fiddler2, ZscalerRoot -- so what follows carries no
/// information. The false positives all went the other way, with the hint
/// starting inside another word: `eset` in "G(eset)zliche Krankenversicherung"
/// and in "Pr(eset) Analytics". Testing the leading edge rejects those and
/// keeps the compounds.
///
/// A boundary is anything non-alphanumeric, which is what separates tokens in
/// a distinguished name: `CN=`, `, O=`, spaces, underscores, dots. Multi-word
/// hints such as "blue coat" work unchanged, since only the leading edge is
/// tested.
///
/// This does NOT fix every false positive and is not meant to read as if it
/// does. "Norton Rose Fulbright" still matches `norton`, and a word that
/// merely BEGINS with a hint still matches. Narrowing either needs to know
/// which DN field it is reading, which this dependency-free matcher does not.
fn starts_word(haystack: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(at) = haystack[from..].find(needle) {
        let start = from + at;
        if haystack[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
        {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Classifies a certificate issuer string.
///
/// Interceptor hints are tested before public-CA hints, so a string carrying
/// both resolves to `Intercepted`. Anything unrecognized -- including no
/// issuer at all -- is `Unknown`, never a guess, and `Unknown` renders a calm
/// panel line rather than a warning.
///
/// This ORDERING is the only thing the precedence rule decides. It used to be
/// justified as "a false intercepted warning is cheaper than a false normal
/// one", and that is no longer the house position: the banner states
/// decryption as fact, so a false positive is the browser telling a user
/// something untrue about their connection. `symantec` was in the interceptor
/// list on the strength of that old reasoning and reported every certificate
/// chaining to Symantec's public roots as decrypted. Prefer a narrow hint that
/// names the inspection product over a broad one that names a company.
pub fn classify_issuer(issuer: Option<&str>) -> TlsState {
    let Some(issuer) = issuer else {
        return TlsState::Unknown;
    };
    let issuer = issuer.to_lowercase();
    if INTERCEPTOR_ISSUER_HINTS
        .iter()
        .any(|hint| starts_word(&issuer, hint))
    {
        return TlsState::Intercepted;
    }
    if PUBLIC_CA_ISSUER_HINTS
        .iter()
        .any(|hint| starts_word(&issuer, hint))
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
    /// Sorted-hash membership index over `blocked_hosts`, built by
    /// `from_lines`. At the 59 hosts this list started with, the linear scan
    /// below was free; at the ~144k the shipped lists now carry, 144k string
    /// comparisons per subresource on the Windows UI thread is not a budget
    /// that exists -- hostset.rs makes the argument at length. The index is
    /// the same `HostSet` the malicious blocklist has run at 580k+ entries
    /// since it shipped: one lookup structure, not two that can disagree.
    ///
    /// PRIVATE, and that is the correctness boundary: the two public Vecs can
    /// be built by hand (tests do), and a hand-built set has an EMPTY index.
    /// `blocks_host` therefore consults the index only when it is non-empty
    /// and falls back to the scan otherwise, so a wrong answer is impossible;
    /// the worst case is the old speed on a set nothing hot constructs.
    index: super::HostSet,
}

impl RuleSet {
    /// Minimal line format — one host per line, `#` comments — so a bigger
    /// hosts-style list can be dropped in later without pulling in a
    /// filter-list crate. Deliberately NOT EasyList syntax.
    ///
    /// ONE PARSE, ONE PREDICATE, both representations built from it. This
    /// mirrors `hashes_from_lines` step for step -- trim, drop comments and
    /// blanks, take the LAST whitespace field (hosts-file shape
    /// "0.0.0.0 tracker.example"), then `acceptable`. Parsing the Vec and the
    /// index differently was three defects in one:
    ///
    ///   * the Vec kept whole lines, so a hosts-file line became the literal
    ///     rule "0.0.0.0 tracker.example" on Unix -- a regex matching no URL --
    ///     while the index correctly blocked tracker.example on Windows;
    ///   * the Vec skipped `acceptable`, so an entry the index refuses still
    ///     compiled into a WebKit rule: blocking on Linux, silently not
    ///     blocking on Windows;
    ///   * a list of ONLY refused entries left the index empty, sending
    ///     `blocks_host` to the linear fallback over that same unvalidated
    ///     Vec, so `RuleSet::from_lines("com")` blocked every .com host --
    ///     the exact catastrophe `acceptable` exists to prevent.
    ///
    /// Filtering here fixes all three at the source: the Vec and the index
    /// describe the same set by construction, the fallback can only ever scan
    /// validated entries, and the two platforms cannot disagree.
    pub fn from_lines(input: &str) -> Self {
        let blocked_hosts: Vec<String> = input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_whitespace().last())
            .map(|host| host.to_ascii_lowercase())
            .filter(|host| super::hostset::acceptable(host))
            .collect();
        let index = super::HostSet::from_lines(&blocked_hosts.join("\n"));
        Self {
            blocked_hosts,
            cosmetic_selectors: Vec::new(),
            index,
        }
    }

    /// Size of the private membership index. Exists so tests can assert the
    /// index and `blocked_hosts` agree entry-for-entry; nothing in the running
    /// browser needs it, and exposing the index itself would invite a second
    /// lookup path.
    pub fn index_len(&self) -> usize {
        self.index.len()
    }

    /// No allocation. This runs inside the `WebResourceRequested` handler on
    /// the Windows UI thread for EVERY request, and it used to `to_lowercase()`
    /// the host each time -- an allocation per subresource, redoing work
    /// `host_of` had already done. `host_matches` is case-insensitive now, so
    /// the copy bought nothing.
    ///
    /// Suffix semantics are identical on both paths: `host_matches` per rule
    /// and the index walk both mean "the host is the rule, or ends with `.`
    /// plus the rule". A test holds the two against each other.
    pub fn blocks_host(&self, host: &str) -> bool {
        if !self.index.is_empty() {
            return self.index.matched_rule(host).is_some();
        }
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

// ---- the page scrollbar wears the chrome's accent -------------------------
//
// The one visible piece of a page the browser draws rather than the site --
// its scrollbar -- used to be the engine's grey beside a chrome in the user's
// colour. This hands pages ONE declaration: `scrollbar-color: <accent>
// transparent` on the root, at zero specificity.
//
// WHAT IT IS AND IS NOT, stated because it is a courtesy in the same
// registration category as GPC and the divergence script and must keep to
// the same trust boundary:
//
// - Zero channels. Nothing is read from the page and nothing leaves it: no
//   fetch, no postMessage, no bridge. The colour is a literal baked in at
//   registration time. `the_scrollbar_script_has_zero_channels` pins it.
// - The PAGE'S OWN CHOICE WINS. `:where(html)` has zero specificity, so a
//   site that sets `scrollbar-color` itself, however weakly, beats this. On
//   WebKitGTK the sheet is at User level, which author rules beat by
//   definition; on WebView2 it is a constructed sheet, which is why the
//   selector carries the `:where`.
// - Constructed, not an injected <style>: a page's `style-src` would refuse
//   an inline style element and the courtesy would silently apply only on
//   permissive sites. CSSOM construction is not governed by CSP.
// - Inherited, deliberately: `scrollbar-color` inherits, so every scroll
//   area on the page follows the accent, not only the viewport. Chromium
//   ignores a site's `::-webkit-scrollbar` styling on any element carrying a
//   non-auto `scrollbar-color`, so a site's hand-drawn scrollbars are
//   REPLACED by the accent unless it also sets `scrollbar-color`. The About
//   disclosure says so.
// - Readable by the page. `document.adoptedStyleSheets` and
//   `getComputedStyle` both expose the value, so a page can learn which of
//   the nine accents this visitor wears. That is a few bits of fingerprint,
//   accepted knowingly on 2026-08-17 as the price of the feature, and
//   disclosed in About beside the accent setting itself.
//
// LIVE on Windows, in two halves. A registration script cannot reach a
// document that already exists, and this crate never evaluates script in
// content, by invariant -- so a palette change (a) re-registers the script
// for the NEXT document and (b) posts the new colour INTO the current one
// with `PostWebMessageAsJson`, the same host-to-page channel autofill's fill
// uses, and the script's listener swaps its own sheet. One direction, host
// into page: the page learns a colour it could already read, and nothing it
// sends reaches this listener (a page CAN dispatch a fake event on
// chrome.webview, and all it can do with it is recolour its own scrollbar).
// Reloading to see a theme is not a behaviour this browser asks of anyone.
//
// On WebKitGTK the sheet is installed at User level and swapped live, but
// the engine does not implement `scrollbar-color` (2.50.6 checked), so
// nothing shows there and the panel copy does not claim it:
// `chrome_caps.page_scrollbar` carries the engine's answer and the sentence
// is shown only where it is true.

/// The single CSS declaration, for both backends. Its own function so the
/// two engines cannot drift into styling different things.
pub fn page_scrollbar_css(rgb: [u8; 3]) -> String {
    format!(
        ":where(html){{scrollbar-color:{} transparent}}",
        super::ChromePalette::hex(rgb)
    )
}

/// The message `set_page_scrollbar` posts into a live document, and the
/// only shape the script's listener acts on. `kind` is the discriminator
/// (autofill's fill message uses the same field), `color` is `#rrggbb`.
pub const PAGE_SCROLLBAR_MESSAGE_KIND: &str = "scrollbar_color";

/// The JSON `set_page_scrollbar` posts. Built here so the Rust side and the
/// listener's checks are pinned against one shape by one test.
pub fn page_scrollbar_message(rgb: [u8; 3]) -> String {
    format!(
        "{{\"kind\":\"{}\",\"color\":\"{}\"}}",
        PAGE_SCROLLBAR_MESSAGE_KIND,
        super::ChromePalette::hex(rgb)
    )
}

/// The WebView2 form: a document-created script that adopts a constructed
/// sheet carrying `page_scrollbar_css`, then listens for the host's colour
/// message and swaps the sheet in place. Fail-open on every path -- an old
/// engine without constructed sheets, a page that has frozen the array, no
/// chrome.webview object -- because a courtesy must never throw into page
/// script. The listener accepts exactly `#` + six lower-case hex digits and
/// nothing else, so a forged event cannot smuggle CSS into the sheet.
pub fn page_scrollbar_script(rgb: [u8; 3]) -> String {
    // The CSS is a fixed shape (`page_scrollbar_css` interpolates six hex
    // digits and nothing else), so it can be quoted as a JS string literal
    // without escaping. `the_scrollbar_css_is_a_fixed_shape` pins that.
    format!(
        "(function () {{\n\
         \x20 \"use strict\";\n\
         \x20 try {{\n\
         \x20   if (typeof CSSStyleSheet !== \"function\") return;\n\
         \x20   if (!(\"adoptedStyleSheets\" in document)) return;\n\
         \x20   var sheet = new CSSStyleSheet();\n\
         \x20   sheet.replaceSync(\"{css}\");\n\
         \x20   document.adoptedStyleSheets = document.adoptedStyleSheets.concat(sheet);\n\
         \x20   var host = window.chrome && window.chrome.webview;\n\
         \x20   if (!host || typeof host.addEventListener !== \"function\") return;\n\
         \x20   host.addEventListener(\"message\", function (ev) {{\n\
         \x20     try {{\n\
         \x20       var msg = ev && ev.data;\n\
         \x20       if (!msg || msg.kind !== \"{kind}\") return;\n\
         \x20       if (typeof msg.color !== \"string\" || !/^#[0-9a-f]{{6}}$/.test(msg.color)) return;\n\
         \x20       sheet.replaceSync(\":where(html){{scrollbar-color:\" + msg.color + \" transparent}}\");\n\
         \x20     }} catch (_) {{}}\n\
         \x20   }});\n\
         \x20 }} catch (_) {{}}\n\
         }})();\n",
        css = page_scrollbar_css(rgb),
        kind = PAGE_SCROLLBAR_MESSAGE_KIND,
    )
}

#[cfg(test)]
mod page_scrollbar_tests {
    use super::{page_scrollbar_css, page_scrollbar_message, page_scrollbar_script};

    #[test]
    fn the_scrollbar_css_is_a_fixed_shape() {
        // Six lower-case hex digits and nothing a page could inject through:
        // this string is dropped into a JS string literal unescaped, so any
        // quote or backslash here would break the script (or worse).
        for rgb in [[0, 0, 0], [0x4f, 0x8c, 0xff], [255, 255, 255]] {
            let css = page_scrollbar_css(rgb);
            assert!(css.starts_with(":where(html){scrollbar-color:#"));
            assert!(css.ends_with(" transparent}"));
            assert!(!css.contains('"') && !css.contains('\\') && !css.contains('\n'));
        }
        assert_eq!(
            page_scrollbar_css([0x4f, 0x8c, 0xff]),
            ":where(html){scrollbar-color:#4f8cff transparent}"
        );
    }

    #[test]
    fn the_page_s_own_choice_wins() {
        // Zero specificity is the whole contract with sites: `html {}` in an
        // author sheet must beat this. Pinned as the selector, since a
        // "cleanup" to `html {` would silently start overriding sites.
        assert!(page_scrollbar_css([1, 2, 3]).starts_with(":where(html)"));
    }

    #[test]
    fn the_scrollbar_script_has_zero_channels_out_of_the_page() {
        // Same trust boundary as GPC and divergence: nothing leaves the page.
        // It LISTENS on chrome.webview (host into page, the live recolour)
        // and never posts on it -- `postMessage` in any form is the banned
        // token, and the listener is the one allowed use of the object.
        let script = page_scrollbar_script([0xf0, 0xa8, 0x32]);
        for forbidden in [
            "fetch(",
            "XMLHttpRequest",
            "import(",
            "postMessage",
            "window.ipc",
            "sendBeacon",
            "WebSocket",
        ] {
            assert!(
                !script.contains(forbidden),
                "scrollbar script must not contain {forbidden}"
            );
        }
        assert!(script.contains("#f0a832 transparent"));
        assert!(script.contains("addEventListener(\"message\""));
        // Constructed, not injected: no <style> element for a page's
        // style-src to refuse.
        assert!(!script.contains("createElement"));
        assert!(script.contains("adoptedStyleSheets"));
    }

    #[test]
    fn the_listener_and_the_message_agree_on_one_shape() {
        // The Rust side posts `page_scrollbar_message`; the listener checks
        // `kind` and a strict `#rrggbb`. Pinned together so neither can be
        // renamed without the other, and so a forged event carrying CSS in
        // `color` is refused by the regex the script embeds.
        let msg = page_scrollbar_message([0xa1, 0x80, 0xff]);
        assert_eq!(msg, "{\"kind\":\"scrollbar_color\",\"color\":\"#a180ff\"}");
        let script = page_scrollbar_script([0, 0, 0]);
        assert!(script.contains("msg.kind !== \"scrollbar_color\""));
        assert!(script.contains("/^#[0-9a-f]{6}$/.test(msg.color)"));
    }
}

#[cfg(test)]
mod gpc_tests {
    use super::{GPC_HEADER_NAME, GPC_HEADER_VALUE, GPC_SCRIPT};

    #[test]
    fn gpc_header_is_sec_gpc_1() {
        assert_eq!(GPC_HEADER_NAME, "Sec-GPC");
        assert_eq!(GPC_HEADER_VALUE, "1");
        assert_eq!(
            format!("{GPC_HEADER_NAME}: {GPC_HEADER_VALUE}"),
            "Sec-GPC: 1"
        );
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
    divergence_script_full(enabled, ephemeral, "{}")
}

/// The second placeholder: a JSON object of per-site choices, keyed by the
/// same full lowercase hostname the script derives in-page.
const DIVERGENCE_OVERRIDES_PLACEHOLDER: &str = "__DIVERGENCE_OVERRIDES__";

/// Builds the script with a per-site override table.
///
/// `overrides` is a JSON object literal. An EMPTY table ("{}") must leave
/// the script behaving exactly as it did before this feature existed: the
/// in-page code reads it, finds nothing for the host, and falls through to
/// the same paragraphs it always ran. That is what keeps
/// scripts/divergence-detect-gate.js honest, since it pins the SET of
/// techniques that can detect the noise and fails on drift in either
/// direction.
fn divergence_script_full(enabled: bool, ephemeral: bool, overrides_json: &str) -> Option<String> {
    if !enabled {
        return None;
    }
    let (normal, eph) = divergence_session_tokens()?;
    let token = if ephemeral { eph } else { normal };
    Some(
        DIVERGENCE_TEMPLATE
            .replacen(DIVERGENCE_TOKEN_PLACEHOLDER, token, 1)
            .replacen(DIVERGENCE_OVERRIDES_PLACEHOLDER, overrides_json, 1),
    )
}

/// Serializes the override table for injection.
///
/// Only hosts the script can actually key on: anything with a character
/// outside a hostname is dropped rather than escaped, because a value that
/// cannot match a real `location.hostname` can only ever be dead weight in
/// every page's memory. Serialized with serde, so quoting is not hand-rolled
/// into a script.
pub fn divergence_overrides_json(entries: &[(String, bool)]) -> String {
    let map: std::collections::BTreeMap<&str, &str> = entries
        .iter()
        .filter(|(host, _)| {
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        })
        .map(|(host, off)| (host.as_str(), if *off { "off" } else { "default" }))
        .collect();
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

/// Called from both platforms' `build_content`. Reads the pref at tab build
/// time, so a toggle takes effect for the next tab without a restart.
pub fn divergence_script(ephemeral: bool) -> Option<String> {
    divergence_script_full(
        crate::prefs::load().fingerprint_noise,
        ephemeral,
        &crate::state::divergence_overrides_snapshot(),
    )
}

#[cfg(test)]
mod divergence_tests {
    use super::{divergence_script_with, DIVERGENCE_TEMPLATE, DIVERGENCE_TOKEN_PLACEHOLDER};

    #[test]
    fn template_carries_the_placeholder_exactly_once() {
        // Twice would mean replacen(.., 1) ships the literal placeholder as
        // the token for the real occurrence; zero would mean no token at all.
        assert_eq!(
            DIVERGENCE_TEMPLATE
                .matches(DIVERGENCE_TOKEN_PLACEHOLDER)
                .count(),
            1
        );
    }

    #[test]
    fn the_overrides_placeholder_appears_exactly_once_and_is_substituted() {
        use super::{divergence_script_full, DIVERGENCE_OVERRIDES_PLACEHOLDER};
        // Twice would leave a literal placeholder in the script, which is a
        // bare identifier and throws, taking every hook down with it. Zero
        // would mean per-site choices reach no page.
        assert_eq!(
            DIVERGENCE_TEMPLATE
                .matches(DIVERGENCE_OVERRIDES_PLACEHOLDER)
                .count(),
            1
        );
        let script = divergence_script_full(true, false, "{}").expect("token");
        assert!(!script.contains(DIVERGENCE_OVERRIDES_PLACEHOLDER));
    }

    #[test]
    fn an_empty_table_leaves_the_script_byte_identical_to_the_default_build() {
        use super::divergence_script_full;
        // The rule the detectability gate rests on: with no per-site
        // choices, this feature changes nothing about what any page sees.
        // If these two ever differ, the pinned 5-of-12 figure is measuring a
        // script no user runs.
        let with_empty = divergence_script_full(true, false, "{}").expect("token");
        let plain = super::divergence_script_with(true, false).expect("token");
        assert_eq!(with_empty, plain);
    }

    #[test]
    fn only_hostname_shaped_keys_reach_the_table() {
        use super::divergence_overrides_json;
        let json = divergence_overrides_json(&[
            ("example.com".to_string(), true),
            ("sub.example.co.uk".to_string(), false),
            // None of these can ever match a real location.hostname, so
            // carrying them would be dead weight in every page's memory,
            // and the quote-shaped one is the reason this filters rather
            // than escapes.
            ("has space.com".to_string(), true),
            ("UPPER.com".to_string(), true),
            ("quote\".com".to_string(), true),
            ("sla/sh.com".to_string(), true),
            (String::new(), true),
        ]);
        assert!(json.contains("example.com"));
        assert!(json.contains("sub.example.co.uk"));
        for bad in ["has space", "UPPER", "quote", "sla/sh"] {
            assert!(!json.contains(bad), "{bad} reached the table: {json}");
        }
        assert_eq!(divergence_overrides_json(&[]), "{}");
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
    fn the_script_has_only_the_count_report_channel() {
        // It carries a per-session token, so network/module channels and the
        // privileged chrome IPC shim remain forbidden. The two native engine
        // bridges below may receive only the fixed count payload.
        for forbidden in ["fetch(", "XMLHttpRequest", "import(", "window.ipc"] {
            assert!(
                !DIVERGENCE_TEMPLATE.contains(forbidden),
                "fingerprint_divergence.js must not contain {forbidden}"
            );
        }
        assert_eq!(
            DIVERGENCE_TEMPLATE
                .matches("window.chrome.webview.postMessage(payload)")
                .count(),
            1
        );
        assert_eq!(
            DIVERGENCE_TEMPLATE
                .matches("window.webkit.messageHandlers.ipc.postMessage(payload)")
                .count(),
            1
        );
        for forbidden_content in [
            "sample:",
            "pixels:",
            "parameter:",
            "url: location",
            "TOKEN:",
        ] {
            assert!(
                !DIVERGENCE_TEMPLATE.contains(forbidden_content),
                "probe payload must not contain {forbidden_content}"
            );
        }
        // postMessage is the one nuance, and this mirrors the shell channel
        // gate (scripts/chrome-js-gate.sh). The Worker wrapper's facade
        // forwards the page's own messages onto a worker THE PAGE created --
        // w.postMessage(...). Since 1.0.1 (22ea1a3) that wrapper is never
        // installed: its code is retained but the wrapper and its facade are
        // never called. The call sites are still in the template, so this check
        // still has to allow them. Were it revived, it would still not be a channel out of
        // the page: the shim carries only the canvas seed, never the token. So
        // postMessage is allowed ONLY as a method call on a local receiver, and
        // is still forbidden as a bare/implicit call or on any page-reachable
        // global (self/window/parent/top/opener), which WOULD carry data out of
        // the page.
        const BANNED_RECEIVERS: [&str; 5] = ["self", "window", "parent", "top", "opener"];
        for (i, line) in DIVERGENCE_TEMPLATE.lines().enumerate() {
            let mut from = 0usize;
            while let Some(rel) = line[from..].find("postMessage") {
                let pos = from + rel;
                let after = pos + "postMessage".len();
                from = after;
                // Only actual calls: "postMessage" then optional spaces, "(".
                if !line[after..].trim_start().starts_with('(') {
                    continue;
                }
                let before = line[..pos].chars().last();
                // A word char before means this is part of a larger identifier,
                // not a postMessage call (the grep's \b / [^.alnum_$]).
                let is_boundary = match before {
                    None => true,
                    Some(c) => !(c.is_ascii_alphanumeric() || c == '_' || c == '$'),
                };
                if !is_boundary {
                    continue;
                }
                assert!(
                    before == Some('.'),
                    "fingerprint_divergence.js line {}: a bare/implicit \
                     postMessage is an outbound channel: {}",
                    i + 1,
                    line.trim()
                );
                // Receiver = the identifier immediately before the '.'.
                let head = &line[..pos - 1];
                let receiver: String = head
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                    .collect::<Vec<char>>()
                    .into_iter()
                    .rev()
                    .collect();
                let count_bridge = line.trim() == "window.chrome.webview.postMessage(payload);"
                    || line.trim() == "window.webkit.messageHandlers.ipc.postMessage(payload);";
                assert!(
                    count_bridge || !BANNED_RECEIVERS.contains(&receiver.as_str()),
                    "fingerprint_divergence.js line {}: postMessage on `{}` \
                     would send out of the page: {}",
                    i + 1,
                    receiver,
                    line.trim()
                );
            }
        }
    }
}

/// The shipped ad and tracker rules: ShadowWhisperer's Ads and Tracking
/// lists (The Unlicense; a primary curator rather than an aggregate -- each
/// file's header carries the provenance argument), regenerated by
/// scripts/build-adlist.sh and checked in like blocklist.txt.
///
/// TWO FILES because they compile to two separate WebKit content filters: the
/// engine refuses a compiled list over 150,000 rules (measured 2026-09-01:
/// 150,000 compiles, 150,001 errors "Too many rules in JSON array", the same
/// on 2.50.6 and 2.52.6), and the combined lists already sit at ~144k. Split,
/// each half has years of headroom, and --verify-content-filter asks the
/// engine rather than trusting that number to stay true.
///
/// Plain text rather than build-time hashes, unlike the malicious blocklist,
/// because the Unix path needs literal hostnames to serialize into
/// content-blocker JSON. The ClamAV incident that forced the blocklist to
/// hashes (bank names in the binary) does not recur here: ad-network
/// hostnames are not phishing-signature material.
#[cfg(test)]
mod shipped_adlist_guard {
    //! A GATE THE USER CANNOT REACH IS NOT AN AD.
    //!
    //! `consent.google.com` sat on the Ads list because an upstream curator
    //! filed it there. Google routes every visit through that host before it
    //! will serve Maps or Search, so refusing it did not block an ad: it made
    //! Google answer "an error has occurred" and the site unusable. Found on
    //! the 1.0.0 candidate, by loading google.com/maps with exactly the
    //! shipped rules in force; the only refused host the page asked for was
    //! that one, and with consent stored the same page worked with every
    //! other rule still on.
    //!
    //! These names are in `scripts/adlist-allow.txt`, so a regeneration drops
    //! them again. This test is the part that fails loudly if one comes back
    //! by another route.
    use super::*;

    #[test]
    fn hosts_that_break_a_site_are_not_in_the_shipped_rules() {
        let rules = RuleSet::from_lines(&format!("{ADLIST_ADS}\n{ADLIST_TRACKING}"));
        for host in [
            // The gate. Blocking it breaks all of Google, not one ad slot.
            "consent.google.com",
            "consent.google.com.au",
            "consent.google.com.bd",
            // Map tiles and Street View imagery: the pictures themselves.
            "t1.gstatic.com",
            "t2.gstatic.com",
            "geo1.ggpht.com",
            "geo3.ggpht.com",
        ] {
            assert!(
                !rules.blocks_host(host),
                "{host} is back in the shipped ad rules; it breaks the site rather than blocking an ad"
            );
        }
    }

    #[test]
    fn instrumentation_is_still_blocked() {
        // The counterpart assertion. Without it, "fix the breakage" could be
        // satisfied by shipping an empty list, and this test would still pass.
        let rules = RuleSet::from_lines(&format!("{ADLIST_ADS}\n{ADLIST_TRACKING}"));
        for host in ["csi.gstatic.com", "metric.gstatic.com", "google-analytics.com"] {
            assert!(rules.blocks_host(host), "{host} should still be blocked");
        }
    }
}

const ADLIST_ADS: &str = include_str!("../adlist-ads.txt");
const ADLIST_TRACKING: &str = include_str!("../adlist-tracking.txt");

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
static BUNDLED_ADS: OnceLock<RuleSet> = OnceLock::new();
static BUNDLED_TRACKING: OnceLock<RuleSet> = OnceLock::new();

/// The COMBINED set: what `decide_request` consults on Windows, where one
/// membership question is asked per request and the split serves no purpose.
pub fn bundled_rules() -> &'static RuleSet {
    BUNDLED.get_or_init(|| {
        let mut rules = RuleSet::from_lines(&format!("{ADLIST_ADS}\n{ADLIST_TRACKING}"));
        rules.cosmetic_selectors = COSMETIC_SELECTORS.iter().map(|s| s.to_string()).collect();
        rules
    })
}

/// The ads half alone, for the Unix path's first compiled filter. Cosmetic
/// selectors ride here only in the sense that `cosmetic_css` is fed this set;
/// they never become filter rules and never count against the 150k ceiling.
pub fn bundled_ads() -> &'static RuleSet {
    BUNDLED_ADS.get_or_init(|| {
        let mut rules = RuleSet::from_lines(ADLIST_ADS);
        rules.cosmetic_selectors = COSMETIC_SELECTORS.iter().map(|s| s.to_string()).collect();
        rules
    })
}

/// The tracking half alone, for the second compiled filter.
pub fn bundled_tracking() -> &'static RuleSet {
    BUNDLED_TRACKING.get_or_init(|| RuleSet::from_lines(ADLIST_TRACKING))
}

static ADS_FILTER_ID: OnceLock<String> = OnceLock::new();
static TRACKING_FILTER_ID: OnceLock<String> = OnceLock::new();

/// Store identifiers for the two bundled filters, hashed from the SHIPPED TEXT
/// rather than the serialized JSON. The JSON is ~15MB and building it just to
/// name a filter would defeat the load-first path these ids exist for: after
/// the first compile the Unix backend asks the store for this id (~70ms
/// measured) instead of recompiling (~3.1s and 46MB of bytecode for the pair).
/// The text determines the JSON byte for byte, so hashing it is the same
/// version key at a fortieth of the work. The suffix keeps the two lists from
/// colliding with each other or with a freeze filter's json-derived id.
pub fn bundled_ads_filter_id() -> &'static str {
    ADS_FILTER_ID.get_or_init(|| format!("{}-ads", filter_id_for(ADLIST_ADS)))
}

pub fn bundled_tracking_filter_id() -> &'static str {
    TRACKING_FILTER_ID.get_or_init(|| format!("{}-tracking", filter_id_for(ADLIST_TRACKING)))
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
            '.' | '+'
                | '*'
                | '?'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '|'
                | '^'
                | '$'
                | '\\'
                | '/'
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
    format!("^https?://([^/]+\\.)?{}[:/]", escape_host_for_filter(host))
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
    serde_json::to_string(&serde_json::Value::Array(entries)).unwrap_or_else(|_| "[]".to_string())
}

// NO PER-TAB AD-LIST EXCEPTION ON THIS BACKEND, and the machinery for one is
// deliberately absent rather than dormant.
//
// An earlier revision of this feature carried it: an exact-host
// `ignore-previous-rules` entry compiled INTO each shipped list, because a
// separate filter carrying the exception does not override a block in another
// one (measured on WebKitGTK 2.52.6, 2026-09-15). It worked, and it cost a
// ~500 ms recompile of the 116k-rule tracking list on every grant and another
// on every revocation.
//
// Removed 2026-09-15: Linux gets the held-page
// explanation, not the button. The only route past the list here is the
// browser-wide switch, and About says exactly that.
//
// Left as a comment rather than as uncalled functions on purpose. Dormant
// mechanism with no caller is how the next reader concludes the feature exists
// and writes copy, or a test, against something nothing invokes.

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
    serde_json::to_string(&serde_json::Value::Array(rules)).unwrap_or_else(|_| "[]".to_string())
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
        // with them -- that is a user-experience cost ruled out by
        // design. yandex.ru search and t.co links stay reachable.
        assert!(!rules.blocks_host("yandex.ru"));
        assert!(!rules.blocks_host("t.co"));
        assert!(!rules.blocks_host("google.com"));
        assert!(!rules.blocks_host("facebook.com"));
        assert!(!rules.blocks_host("example.com"));
        assert!(!rules.blocks_host("google.com"));
    }

    #[test]
    fn shipped_adlists_hold_their_floors_and_the_webkit_ceiling() {
        // scripts/build-adlist.sh asserts both bounds when it regenerates;
        // this re-asserts them on what was actually CHECKED IN, because the
        // file and the pipeline run are separated by a human and a diff.
        // 150k is measured, not documented: WebKit 2.52.6 compiles 150,000
        // rules and refuses 150,001, so a list crossing it ships a browser
        // whose ad blocking silently never compiles.
        let ads = bundled_ads().blocked_hosts.len();
        let tracking = bundled_tracking().blocked_hosts.len();
        assert!(
            ads >= 20_000,
            "ads list shrank to {ads}: truncated checkin?"
        );
        assert!(
            tracking >= 80_000,
            "tracking list shrank to {tracking}: truncated checkin?"
        );
        assert!(ads < 150_000, "ads list at {ads} has outgrown WebKit");
        assert!(
            tracking < 150_000,
            "tracking list at {tracking} has outgrown WebKit"
        );
    }

    #[test]
    fn shipped_adlists_never_carry_first_party_hosts() {
        // scripts/adlist-allow.txt screens these out at generation; asserted
        // here too because an upstream adding our own infrastructure and
        // slipping through a regeneration would break updates for every
        // install with ad blocking on, and nothing else would notice.
        let rules = bundled_rules();
        for host in ["patanyx.com", "patanyx.net", "edgexene.io"] {
            assert!(
                !rules.blocks_host(host),
                "{host} is first-party and must never be filtered"
            );
        }
        // Suffix matching means the apex assertions cover these, but naming
        // the real endpoints makes a failure say what it costs.
        assert!(!rules.blocks_host("patanyx.edgexene.io"));
        assert!(!rules.blocks_host("relay.edgexene.io"));
    }

    #[test]
    fn every_shipped_adlist_host_survives_the_runtime_gate() {
        // THE PLATFORM-DIVERGENCE GUARD, exhaustive rather than sampled. Unix
        // compiles `blocked_hosts` into WebKit rules; Windows answers from the
        // HostSet index, which drops anything `acceptable` rejects. A host
        // that ships but the index refuses would block on Linux and silently
        // NOT block on Windows -- a handful of entries in ~144k, which
        // sampling would miss.
        // ASSERTED ON THE RAW FILE, not on `blocked_hosts`. `from_lines`
        // filters through `acceptable`, so a bad entry never reaches the Vec
        // and a test reading the Vec can never fail -- it would be vacuous.
        // A planted `evil..example` proved exactly that. Runtime stays safe
        // either way; what this catches is the file claiming to ship rules it
        // silently drops, which makes the counts and the floors dishonest.
        for (label, raw) in [("ads", ADLIST_ADS), ("tracking", ADLIST_TRACKING)] {
            for line in raw.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                assert!(
                    crate::platform::hostset::acceptable(line),
                    "{label}: {line} is in the shipped file but the runtime \
                     index rejects it -- it would be counted and never block"
                );
            }
        }
        assert_eq!(
            bundled_ads().blocked_hosts.len(),
            bundled_ads().index_len(),
            "ads: Vec and index disagree on size"
        );
        assert_eq!(
            bundled_tracking().blocked_hosts.len(),
            bundled_tracking().index_len(),
            "tracking: Vec and index disagree on size"
        );
    }

    #[test]
    fn no_shipped_adlist_host_is_a_bare_shared_platform_suffix() {
        // The catastrophic case named explicitly. A bare `amazonaws.com` in a
        // url-filter blocks every S3 bucket, and this repository has already
        // shipped 25 AWS regional endpoints once.
        // Raw file again, for the same reason: `acceptable` already refuses a
        // bare protected suffix, so checking the parsed set proves nothing
        // about what the pipeline emitted.
        for (label, raw) in [("ads", ADLIST_ADS), ("tracking", ADLIST_TRACKING)] {
            for suffix in crate::platform::hostset::PROTECTED_SUFFIXES {
                assert!(
                    !raw.lines().any(|l| l.trim() == *suffix),
                    "{label}: {suffix} is a shared-platform suffix and must never ship"
                );
            }
        }
    }

    #[test]
    fn adlist_extra_survives_regeneration() {
        // connect.facebook.net is the one host of the original hand-picked 59
        // the upstream lists do not carry; scripts/adlist-extra.txt re-adds
        // it. A failure here means the extras file was skipped and the
        // curated-to-bigger-list swap quietly UNBLOCKED something.
        assert!(bundled_rules().blocks_host("connect.facebook.net"));
        assert!(bundled_ads().blocks_host("connect.facebook.net"));
    }

    #[test]
    fn ruleset_index_and_scan_agree() {
        // blocks_host has two implementations: the sorted-hash index (any set
        // from from_lines) and the linear host_matches scan (the fallback for
        // hand-built sets). They must be the same function. A stratified
        // sample catches a drifted hash as surely as exhaustion would, in test
        // time that stays negligible.
        let indexed = bundled_ads();
        let scanned = RuleSet {
            blocked_hosts: indexed.blocked_hosts.clone(),
            cosmetic_selectors: vec![],
            ..RuleSet::default()
        };
        for host in indexed.blocked_hosts.iter().step_by(997) {
            assert!(scanned.blocks_host(host), "scan misses shipped {host}");
            assert!(indexed.blocks_host(host), "index misses shipped {host}");
            let sub = format!("cdn.{host}");
            assert_eq!(
                indexed.blocks_host(&sub),
                scanned.blocks_host(&sub),
                "index and scan disagree on subdomain {sub}"
            );
        }
        for miss in ["example.com", "patanyx.com", "a.b.c.example.test"] {
            assert_eq!(indexed.blocks_host(miss), scanned.blocks_host(miss));
        }
    }

    #[test]
    fn bundled_filter_ids_are_distinct_and_stable() {
        // The Unix load-first path keys the filter store on these. Colliding
        // ids would make the second list's load return the FIRST list's
        // bytecode: ad blocking that looks on while filtering half of what it
        // claims. Stability across calls is what makes them cache keys.
        let ads = bundled_ads_filter_id();
        let tracking = bundled_tracking_filter_id();
        assert_ne!(ads, tracking);
        assert_eq!(ads, bundled_ads_filter_id());
        assert_eq!(tracking, bundled_tracking_filter_id());
        assert!(ads.ends_with("-ads") && tracking.ends_with("-tracking"));
    }

    #[test]
    fn an_all_rejected_list_cannot_reach_the_unsafe_fallback() {
        // A list whose every entry HostSet rejects leaves the index empty,
        // which sends blocks_host to the linear fallback. If that fallback
        // read the raw Vec, a bare TLD would block the whole suffix.
        let rules = RuleSet::from_lines("com\n");
        assert!(
            !rules.blocks_host("example.com"),
            "a bare TLD reached the fallback and blocked the whole suffix"
        );
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
            ..RuleSet::default()
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
        assert_ne!(
            filter, ".*",
            "a match-everything filter blocks nothing useful"
        );

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
        assert_eq!(session_blocked_total(std::iter::empty::<u64>()) - before, 2);
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
            classify_issuer(Some(
                "CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1, O=DigiCert Inc"
            )),
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

    /// A hint inside another word is not a hint.
    ///
    /// Every case here classified as INTERCEPTED before whole-word matching,
    /// which means the browser told the user their traffic was being decrypted
    /// on the strength of a coincidence.
    #[test]
    fn an_issuer_that_merely_contains_a_hint_is_not_interception() {
        for issuer in [
            // "eset" inside a German health insurer's internal CA.
            "CN=Gesetzliche Krankenversicherung Root CA, O=GKV, C=DE",
            // "eset" again, inside a product name.
            "CN=Preset Analytics Internal Root, O=Preset Inc",
        ] {
            assert_ne!(
                classify_issuer(Some(issuer)),
                TlsState::Intercepted,
                "{issuer} matched a hint from inside another word"
            );
        }
    }

    /// Non-ASCII issuer text does not panic the byte walk.
    ///
    /// `starts_word` indexes by byte. That is sound because every hint is
    /// ASCII, so a match's start and end are always char boundaries and
    /// `start + 1` lands inside the matched run -- but a DN is attacker-
    /// adjacent text and `to_lowercase` can change a string's byte length,
    /// so the invariant is worth a test rather than a comment.
    #[test]
    fn a_non_ascii_issuer_does_not_panic_the_matcher() {
        for issuer in [
            "CN=Ångström Certifieringsmyndighet, O=Åäö AB, C=SE",
            "CN=İstanbul Kök Sertifika, O=TÜRKTRUST, C=TR",
            "CN=日本ルート認証局, O=セキュリティ, C=JP",
            // A hint's bytes, adjacent to multi-byte characters on both sides.
            "CN=Ω eset Ω",
            "CN=Ωeset Ω",
            "CN=\u{1F512}zscaler\u{1F512}",
        ] {
            // The assertion is that this RETURNS at all.
            let _ = classify_issuer(Some(issuer));
        }
        // And the boundary logic still reads correctly across them: a hint
        // fenced by non-alphanumerics is a word, one glued to a letter is not.
        assert_eq!(classify_issuer(Some("CN=Ω eset Ω")), TlsState::Intercepted);
        assert_ne!(classify_issuer(Some("CN=Ωeset Ω")), TlsState::Intercepted);
        // A hint glued to a following multi-byte char still matches, because
        // only the leading edge is tested. That is deliberate: see starts_word.
        assert_eq!(classify_issuer(Some("CN=Ω esetΩ")), TlsState::Intercepted);
    }

    /// A retired public CA is not an interception product.
    ///
    /// `symantec` was in the interceptor list, so every certificate still
    /// chaining to Symantec's old public roots was reported as decrypted.
    #[test]
    fn a_legacy_public_ca_is_not_an_interceptor() {
        for issuer in [
            "CN=Symantec Class 3 Secure Server CA - G4",
            // Widely deployed for enterprise-INTERNAL TLS. Issuance, not
            // interception, and the bare token swept it up too.
            "CN=Symantec Managed PKI for SSL",
        ] {
            assert_ne!(
                classify_issuer(Some(issuer)),
                TlsState::Intercepted,
                "{issuer} is issuance, not interception"
            );
        }
    }

    /// The Symantec-branded inspection products are still caught.
    ///
    /// Dropping the bare `symantec` token cost these, because `bluecoat` only
    /// covers the ProxySG-branded lineage. They are named individually so the
    /// hint matches the product rather than the company.
    #[test]
    fn symantec_branded_inspection_is_still_detected() {
        for issuer in [
            "CN=Symantec Web Security Service CA",
            "CN=Symantec SSL Visibility Appliance CA",
        ] {
            assert_eq!(
                classify_issuer(Some(issuer)),
                TlsState::Intercepted,
                "{issuer} is an inspection product and stopped being detected"
            );
        }
    }

    /// The hints that DO mean interception still do: multi-word ones, and the
    /// compound names where the hint is a prefix rather than a whole word.
    #[test]
    fn a_hint_at_a_word_start_still_detects_the_real_interceptors() {
        for issuer in [
            "CN=Zscaler Intermediate Root CA (zscalertwo.net)",
            "CN=FortiGate CA, O=Fortinet",
            "CN=Blue Coat SSL CA, O=Blue Coat Systems",
            "CN=Cisco Umbrella Secondary SubCA",
            "CN=ESET SSL Filter CA, O=ESET, spol. s r.o.",
            // The one whole-word matching broke. `fiddler` is followed by `R`
            // here and by `2` in the OU, so both ends being tested rejected
            // a live interception proxy.
            "CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, \
             OU=Created by http://www.fiddler2.com",
        ] {
            assert_eq!(
                classify_issuer(Some(issuer)),
                TlsState::Intercepted,
                "{issuer} is a real interceptor and stopped being detected"
            );
        }
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
        classify_uri, host_of,
        host_url_filter, BlockReason, FreezeEnforcement, FreezePhase,
        InterceptionFailure, InterceptionState, RequestDecision, RuleSet, SettingState, TabPolicy,
        TabState, TrackingPreventionState, UriClass, FREEZE_GRACE,
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

    #[test]
    fn tracking_prevention_names_the_confirmed_level() {
        assert_eq!(TrackingPreventionState::Strict.as_str(), "strict");
        assert_eq!(TrackingPreventionState::Balanced.as_str(), "balanced");
        assert_eq!(TrackingPreventionState::Failed.as_str(), "failed");
        assert_eq!(
            TrackingPreventionState::NotAttempted.as_str(),
            "not_attempted"
        );
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
            Instant::now(), None);
        assert!(
            matches!(decision, RequestDecision::Block(BlockReason::AdRule)),
            "a ported URL to a blocked host must still be blocked, got {decision:?}"
        );
    }

    #[test]
    fn a_frozen_tab_blocks_and_ledgers_an_ordinary_request() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        let d = st.decide_request(Some("https://x.com/a"), false, &rules(), Instant::now(), None);
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
            live.decide_request(None, false, &rules(), Instant::now(), None),
            RequestDecision::Allow
        );

        let mut frozen = registered_tab(TabPolicy::default());
        frozen.freeze.freeze();
        assert_eq!(
            frozen.decide_request(None, false, &rules(), Instant::now(), None),
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
            frozen.decide_request(
                Some("https:///no-authority"),
                false,
                &rules(),
                Instant::now(), None),
            RequestDecision::Block(BlockReason::FrozenOpaque)
        );

        let mut live = registered_tab(TabPolicy::default());
        assert_eq!(
            live.decide_request(
                Some("https:///no-authority"),
                false,
                &rules(),
                Instant::now(), None),
            RequestDecision::Allow
        );
    }

    /// T1. The per-tab ad-list override: "this tab may reach HOST despite the
    /// ad/tracker list".
    ///
    /// It exempts ONE predicate and nothing else. The cases below are the
    /// whole contract, and each is a way the feature could quietly become a
    /// hole rather than an exception:
    ///
    /// - the named host loads, and is ledgered as ALLOWED rather than hidden;
    /// - a DIFFERENT listed host on the same page stays blocked, so consenting
    ///   to one tracker is not consenting to the page's others;
    /// - a SUBDOMAIN of the allowed host stays blocked (exact host only, which
    ///   is what keeps the two engines in step: the Linux exception rule is
    ///   anchored to the exact host for the same reason);
    /// - a FROZEN tab still blocks it, because freeze is a different promise;
    /// - the browser's own UI origin is still refused, because that check is
    ///   unconditional and sits above every policy.
    #[test]
    fn an_override_exempts_only_the_ad_rule_and_only_for_that_exact_host() {
        let now = Instant::now();

        // Allowed: the named host, and it must be ledgered as allowed.
        let mut st = registered_tab(blocking_policy());
        assert_eq!(
            st.decide_request(
                Some("https://tracker.example/pixel"),
                false,
                &rules(),
                now,
                Some("tracker.example"),
            ),
            RequestDecision::Allow,
            "the override did not let its own host through"
        );
        let row = st
            .ledger
            .snapshot()
            .into_iter()
            .find(|r| r.host == "tracker.example")
            .expect("an allowed override must still appear in the ledger");
        assert_eq!(
            row.blocked, 0,
            "an overridden request was ledgered as blocked; the panel would \
             tell the user it was stopped when it was sent"
        );

        // Still blocked: a different listed host.
        let mut st = registered_tab(blocking_policy());
        assert_eq!(
            st.decide_request(
                Some("https://doubleclick.net/ad"),
                false,
                &rules(),
                now,
                Some("tracker.example"),
            ),
            RequestDecision::Block(BlockReason::AdRule),
            "allowing one host also allowed another listed host"
        );

        // Still blocked: a SUBDOMAIN of the allowed host. Exact host only.
        let mut st = registered_tab(blocking_policy());
        assert_eq!(
            st.decide_request(
                Some("https://sub.tracker.example/beacon"),
                false,
                &rules(),
                now,
                Some("tracker.example"),
            ),
            RequestDecision::Block(BlockReason::AdRule),
            "the override covered a subdomain; it must be the exact host, or \
             the two engines disagree about what was consented to"
        );

        // Still blocked: frozen beats the override.
        let mut frozen = registered_tab(blocking_policy());
        frozen.freeze.freeze();
        assert_eq!(
            frozen.decide_request(
                Some("https://tracker.example/pixel"),
                false,
                &rules(),
                now,
                Some("tracker.example"),
            ),
            RequestDecision::Block(BlockReason::Freeze),
            "an ad-list override lifted a FREEZE; they are different promises"
        );

        // Still blocked: the chrome origin, which no policy may reach.
        let mut st = registered_tab(blocking_policy());
        let reserved = format!("https://{}/x", super::super::CHROME_RESERVED_HOST);
        assert_eq!(
            st.decide_request(Some(&reserved), false, &rules(), now, Some(super::super::CHROME_RESERVED_HOST)),
            RequestDecision::Block(BlockReason::ReservedOrigin),
            "an override reached the browser's own UI origin"
        );
    }

    /// No override means no change: the ordinary path must be untouched by
    /// the parameter existing.
    #[test]
    fn no_override_decides_exactly_as_before() {
        let now = Instant::now();
        let mut st = registered_tab(blocking_policy());
        assert_eq!(
            st.decide_request(Some("https://tracker.example/p"), false, &rules(), now, None),
            RequestDecision::Block(BlockReason::AdRule)
        );
        let mut st = registered_tab(blocking_policy());
        assert_eq!(
            st.decide_request(Some("https://unlisted.example/p"), false, &rules(), now, None),
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
                st.decide_request(Some(uri), false, &rules(), Instant::now(), None),
                RequestDecision::Allow,
                "{uri} carries no network traffic and must stay allowed"
            );
        }
        assert!(st.ledger.snapshot().is_empty());
    }

    // --- WebSockets ----------------------------------------------------------

    /// Decided 2026-07-26: a manual freeze blocks NEW
    /// upgrades. Inverting this test is the whole change if that is ever
    /// reversed.
    #[test]
    fn a_manual_freeze_blocks_new_websocket_upgrades() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.freeze();
        let d = st.decide_request(Some("ws://live.example/s"), true, &rules(), Instant::now(), None);
        assert_eq!(d, RequestDecision::Block(BlockReason::Freeze));
        let rows = st.ledger.snapshot();
        assert_eq!(
            (rows[0].host.as_str(), rows[0].blocked),
            ("live.example", 1)
        );
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
        let d = st.decide_request(Some("wss://live.example/s"), true, &rules(), t0, None);
        assert_eq!(d, RequestDecision::Allow);
        let rows = st.ledger.snapshot();
        assert_eq!(
            (rows[0].host.as_str(), rows[0].allowed),
            ("live.example", 1)
        );
        // The socket was seen, so the tab must not auto-freeze under it.
        assert!(!st.freeze.should_auto_freeze(t0 + FREEZE_GRACE * 10));
    }

    #[test]
    fn a_websocket_host_override_allows_the_upgrade_even_frozen() {
        let mut st = registered_tab(TabPolicy::default());
        st.freeze.add_override("live.example");
        st.freeze.freeze();
        assert_eq!(
            st.decide_request(Some("ws://live.example/s"), true, &rules(), Instant::now(), None),
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
        let d = st.decide_request(Some("ws://live.example/s"), false, &rules(), Instant::now(), None);
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
            off.decide_request(
                Some("https://ads.doubleclick.net/x"),
                false,
                &rules(),
                Instant::now(), None),
            RequestDecision::Allow
        );

        let mut on = registered_tab(blocking_policy());
        assert_eq!(
            on.decide_request(
                Some("https://ads.doubleclick.net/x"),
                false,
                &rules(),
                Instant::now(), None),
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
            st.decide_request(
                Some("https://app.example.com/x"),
                false,
                &rules(),
                Instant::now(), None),
            RequestDecision::Allow
        );
        assert_eq!(
            st.decide_request(Some("https://other.com/x"), false, &rules(), Instant::now(), None),
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
            st.decide_request(Some("https://x.com/a"), false, &rules(), t0, None),
            RequestDecision::Allow
        );
        assert_eq!(
            st.decide_request(Some("https://x.com/b"), false, &rules(), t0 + FREEZE_GRACE, None),
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
        for local in [
            "data:text/plain,x",
            "about:blank",
            "file:///x",
            "blob:https://x/1",
        ] {
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
            assert_eq!(
                st.freeze.enforcement(),
                FreezeEnforcement::Failed,
                "{state:?}"
            );
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
        st.decide_request(Some("https://x.com/a"), false, &rules(), Instant::now(), None);
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
            let d = st.decide_request(Some("https://x.com/a"), false, &rules(), t0 + FREEZE_GRACE, None);
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
            st.decide_request(Some("https://x.com/a"), false, &rules(), t0 + FREEZE_GRACE, None),
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
            st.decide_request(Some("https://x.com/a"), false, &rules(), Instant::now(), None),
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
                    st.decide_request(Some(uri), false, &rules(), Instant::now(), None),
                    RequestDecision::Block(_)
                ),
                "{uri:?} escaped a freeze"
            );
        }
        // Control: genuinely local schemes are still allowed, whatever their
        // case, because they put no bytes on the wire.
        for uri in ["DATA:text/plain,x", "About:Blank"] {
            assert_eq!(
                st.decide_request(Some(uri), false, &rules(), Instant::now(), None),
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
                st.decide_request(Some(uri), false, &rules(), Instant::now(), None),
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
                st.decide_request(Some(uri), false, &rules(), Instant::now(), None),
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
            let d = st.decide_request(Some(&uri), false, &RuleSet::default(), Instant::now(), None);
            assert_eq!(
                d,
                RequestDecision::Block(BlockReason::LocalNetwork),
                "an http page must not reach {host}"
            );
        }
    }

    /// The chosen scope, stated as a test so nobody widens or narrows it
    /// by accident. An HTTPS page reaching the same address is OUT OF SCOPE
    /// and deliberately allowed; the About copy says so.
    #[test]
    fn a_secure_page_is_out_of_scope_and_allowed() {
        for host in ["127.0.0.1", "192.168.1.1", "169.254.169.254"] {
            let mut st = secure_tab();
            let uri = format!("http://{host}/status");
            let d = st.decide_request(Some(&uri), false, &RuleSet::default(), Instant::now(), None);
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
            let d = st.decide_request(Some(&uri), false, &RuleSet::default(), Instant::now(), None);
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
            Instant::now(), None);
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
            Instant::now(), None);
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
            Instant::now(), None);
        assert_eq!(
            d,
            RequestDecision::Allow,
            "documented limit: DNS rebinding needs a post-resolution hook this browser has not got"
        );
    }
}
