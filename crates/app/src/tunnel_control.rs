//! Engine-side tunnel lifecycle: the proxy port must exist BEFORE the vault
//! does, and the tunnel must come up WHEN the vault does.
//!
//! WHY THIS MODULE EXISTS. Both engine backends need a proxy port at a
//! moment when the tunnel configuration cannot exist yet: WebView2 takes
//! `--proxy-server` only at environment creation, WebKitGTK takes proxy
//! settings per view at construction -- and the configuration lives in the
//! encrypted vault, which is locked at browser start. The split this module
//! implements: bind the loopback listener as early as the engine asks
//! (`bind_if_enabled`), keep it refusing every connection while the vault
//! is locked (a closed proxy connection is a failed request, never a
//! silent direct route), and swap the refuse loop for the real tunnel ON
//! THE SAME PORT when the vault opens (`on_vault_unlocked`). The port never
//! changes underneath the engine, so there is no window in which it could
//! fall back to a direct connection.
//!
//! DELIBERATELY NOT HERE:
//! * No panel or banner UI. The engine-confirmed ROW is served from here
//!   (`report()`, measured by the probe thread); the panel and banner that
//!   explain it land with the tunnel UI phase. The latest `TunnelEvent`
//!   and any start failure are RECORDED (`last_event`, `last_start_error`)
//!   for that phase to read.
//! * No stop-on-lock. Locking the vault does NOT stop a running tunnel: the
//!   session already holds its keys in memory, and killing the user's
//!   browsing because the password store locked would conflate two features
//!   that share nothing but the word "vault". There is deliberately no
//!   `on_vault_locked` entry point.
//! * No runtime application on Windows. WebView2 accepts the proxy only at
//!   environment creation; toggling the mode is a restart there, exactly as
//!   `TunnelMode::describe` already tells the user.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use patanyx_tunnel::{BoundProxy, Tunnel, TunnelConfig, TunnelEvent};
use patanyx_vault::TunnelSettings;

use crate::platform::SettingState;
use crate::state::AppState;

/// One bind attempt per process, success or failure: `bind_if_enabled` is
/// called from more than one engine path and must be idempotent, and a
/// second attempt could only double-bind a second port the engine would
/// never learn about.
static BIND_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// True while the start worker is in flight. `RUNNING` is still None during
/// that window, so this is what stops a second unlock from starting a
/// second tunnel on a proxy the first one already took.
static STARTING: AtomicBool = AtomicBool::new(false);

/// The mode the ENGINE booted with, and whether it has been recorded yet.
///
/// Both engines take their proxy exactly once -- WebView2 at environment
/// creation, WebKitGTK per view from a port chosen at the same moment -- so
/// the mode in prefs can drift away from the mode actually in force the
/// instant the user changes it. These two record what the engine got, so
/// `restart_pending` can answer "is what you are looking at actually live"
/// with a FACT rather than the UI inferring it from having seen a click.
static BOOT_MODE_IMPORTED: AtomicBool = AtomicBool::new(false);
static BOOT_MODE_RECORDED: AtomicBool = AtomicBool::new(false);

/// The listener parked between engine start and vault unlock. `None` means
/// either the mode is not `Imported` (the engine never asks), the bind
/// failed (the engine was pointed at the dead port -- see
/// `engine_proxy_port`), or the tunnel has already consumed it.
static BOUND_PROXY: Mutex<Option<BoundProxy>> = Mutex::new(None);

/// The port that was bound this process, 0 meaning none. SEPARATE from
/// `BOUND_PROXY` because the port must OUTLIVE the parked listener:
/// `on_vault_unlocked` consumes the `BoundProxy` to start the tunnel, and
/// the running tunnel serves the SAME port -- but a `proxy_port()` that
/// read only the parked slot would go None at that exact moment, and every
/// Linux view built after unlock would be pointed at the dead port while
/// the tunnel ran. That defect shipped in the first draft of this module
/// and was caught by the independent review; this static is the fix.
static BOUND_PORT: AtomicU16 = AtomicU16::new(0);

/// The running tunnel, once the vault has yielded a config. Held so the
/// tunnel outlives the unlock IPC call; read for "is it running yet".
static RUNNING: Mutex<Option<Tunnel>> = Mutex::new(None);

/// The latest event the tunnel reported. Written on the tunnel's core
/// thread; the tunnel crate's contract is that the callback is cheap and
/// never calls back into the tunnel, and a mutex store is both.
static LAST_EVENT: Mutex<Option<TunnelEvent>> = Mutex::new(None);

/// Why the last `start_on` failed, if it did. Never contains key material:
/// `TunnelError`'s `Display` says WHAT is wrong while never naming any key
/// (the tunnel crate specifies exactly that), so storing the formatted text
/// is safe. Recorded rather than logged because the app has no
/// cross-platform diag sink -- the status-surface phase reads this.
static LAST_START_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// u8 wire encoding for PROBE_STATE, kept explicit so the atomic's contents
/// survive a SettingState rename. The probe thread writes only APPLIED and
/// FAILED; NOT_ATTEMPTED exists so the decode is total (report() answers
/// that state itself when the mode is Off).
const PROBE_NOT_ATTEMPTED: u8 = 0;
const PROBE_APPLIED: u8 = 1;
const PROBE_FAILED: u8 = 2;

/// The probe thread's latest classified answer. Initialized to FAILED on
/// purpose: until the first probe cycle completes, nothing has been
/// measured, and nothing unmeasured may claim "applied". Written only by
/// the probe thread; `report()` reads it and never blocks on more than
/// this load.
static PROBE_STATE: AtomicU8 = AtomicU8::new(PROBE_FAILED);

/// Shutdown signal for the probe thread. NOTHING SETS THIS in this phase,
/// on purpose: the tunnel has no stop path (locking the vault deliberately
/// does not stop it -- see the module header), so the tunnel outlives
/// everything and the probe thread ends with the process alongside it. The
/// flag exists so the phase that adds a stop path has the hook already
/// wired into the loop instead of having to retrofit one.
static PROBE_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Poisoning is not fatal here: a panic elsewhere must not make the tunnel
/// state unreadable -- the same rule the tunnel crate applies to its own
/// status read.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Binds the loopback proxy listener once, if the user chose
/// `TunnelMode::Imported`. Idempotent: later calls -- from either engine
/// path -- do nothing. The bound listener REFUSES connections until
/// `on_vault_unlocked` hands it a real tunnel; that refusal is the
/// fail-closed state while the vault is locked.
pub fn bind_if_enabled() {
    let imported = matches!(crate::prefs::load().tunnel, crate::prefs::TunnelMode::Imported);
    // Record what the ENGINE is booting with, once, BEFORE the Off early
    // return -- booting with the tunnel off is a state `restart_pending`
    // has to be able to compare against, so it cannot live behind a guard
    // that only runs when the tunnel is on.
    if !BOOT_MODE_RECORDED.swap(true, Ordering::SeqCst) {
        BOOT_MODE_IMPORTED.store(imported, Ordering::SeqCst);
    }
    // Mode first, latch second: a call while the mode is Off must not
    // consume the one attempt, or an Off-then-Imported process (possible on
    // Linux, where nothing forces a restart) could never bind.
    if !imported {
        return;
    }
    // Everything below happens under the proxy lock so the attempt and its
    // publication are one atomic step: a concurrent caller either sees the
    // finished result or waits for it, never a latched-but-empty middle.
    let mut parked = lock(&BOUND_PROXY);
    if BIND_ATTEMPTED.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Ok(bound) = Tunnel::bind_proxy() {
        BOUND_PORT.store(bound.port(), Ordering::SeqCst);
        *parked = Some(bound);
    }
    // A failed bind is not retried here: the engine sites translate
    // "Imported but nothing bound" into the dead port, which is the
    // sanctioned fail-closed fallback. A bind never attempted reads the
    // same as a failed one, which is the conservative direction.
}

/// The loopback port bound this process. Some ONLY when a bind succeeded --
/// synthesizing the fail-closed dead port is `engine_proxy_port`'s job, not
/// this function's. Reads the PORT record, not the parked listener: the
/// port stays valid across `on_vault_unlocked` consuming the listener,
/// because the tunnel keeps serving the same port.
pub fn proxy_port() -> Option<u16> {
    match BOUND_PORT.load(Ordering::SeqCst) {
        0 => None,
        port => Some(port),
    }
}

/// The port the engine must route through, or None when the user chose no
/// tunnel. Some(bound) when the listener exists; Some(1) when the mode is
/// Imported but the bind failed -- port 1 is closed, so every request fails
/// instead of silently going direct, which is the one unacceptable outcome.
/// Those two are the ONLY sanctioned states; nothing here may ever yield
/// "no proxy" for a user who chose Imported.
pub fn engine_proxy_port() -> Option<u16> {
    engine_port_for(
        matches!(crate::prefs::load().tunnel, crate::prefs::TunnelMode::Imported),
        proxy_port(),
        lock(&RUNNING).is_some(),
    )
}

/// Whether the tunnel setting the user is looking at is NOT the one this
/// browser is actually running with -- i.e. a restart would change
/// behaviour.
///
/// This exists because the panel used to infer it: it showed a restart
/// note as a REACTION to a click, so the note vanished the moment the
/// panel was closed and reopened, while the restart stayed just as
/// pending. We hit exactly that -- turned the tunnel off, and
/// nothing on screen said the browser was still tunnelling. A fact the
/// engine already knows should not be re-derived from UI events.
///
/// False before the engine has booted (nothing to disagree with yet), and
/// false once the user sets the mode back to whatever is in force -- the
/// note goes away by itself, because at that point no restart is owed.
pub fn restart_pending() -> bool {
    if !BOOT_MODE_RECORDED.load(Ordering::SeqCst) {
        return false;
    }
    let now_imported = matches!(
        crate::prefs::load().tunnel,
        crate::prefs::TunnelMode::Imported
    );
    now_imported != BOOT_MODE_IMPORTED.load(Ordering::SeqCst)
}

/// The pure rule behind `engine_proxy_port`, extracted for the same reason
/// `classify` was: the invariant is worth a table test, and it cannot be
/// tested while it reads three process-wide statics.
///
/// The `running` input is what the first version lacked. It only ever
/// consulted the bound port, so once a bind had happened the MODE stopped
/// mattering -- and after `tunnel_remove` set the mode to Off, new views
/// were still pointed at the tunnel while the panel said "off (no tunnel
/// chosen)". Now: a running tunnel keeps its port whatever the mode says
/// (traffic really is going there until the restart the UI promises), and
/// with no tunnel running the mode decides.
fn engine_port_for(mode_imported: bool, bound: Option<u16>, running: bool) -> Option<u16> {
    // Direct ONLY when the user chose no tunnel and none is running. Every
    // other combination gets a port -- the real one if we know it, the dead
    // one if we do not. The `bound: None, running: true` corner is why this
    // is written as one rule rather than two: an earlier version returned
    // the bound port unconditionally while running, which for that corner
    // meant None, i.e. browsing direct with a tunnel up. The table test
    // caught it, which is the entire reason this function was extracted.
    if !mode_imported && !running {
        return None;
    }
    Some(bound.unwrap_or(DEAD_PORT))
}

/// The fail-closed fallback port: closed on both platforms, so every
/// request through it fails. Deliberately NOT a low "privileged" port on
/// the theory that nothing can bind it -- Windows has no privileged-port
/// rule at all, so the guarantee here is only that nothing of OURS listens
/// and the connection fails fast. That is the whole requirement.
const DEAD_PORT: u16 = 1;

/// The vault has just opened: if a proxy was bound, no tunnel is running
/// yet, and this vault carries an ENABLED tunnel config, bring the tunnel
/// up on the already-bound port. All three conditions are checked here
/// because the engine cannot distinguish them -- it only ever sees a port.
///
/// A start failure is RECORDED (`last_start_error`), never propagated: the
/// unlock must not fail because the tunnel could not start, and the engine
/// is already pointing at the proxy port, which keeps refusing -- the
/// failure state stays fail-closed on its own.
pub fn on_vault_unlocked(state: &AppState) {
    if lock(&RUNNING).is_some() {
        // A re-unlock must not spawn a second tunnel. The running one kept
        // its keys when the vault locked -- see the module header for why
        // locking never stops it.
        return;
    }
    if STARTING.swap(true, Ordering::SeqCst) {
        // A start is already in flight on the worker thread; RUNNING is
        // still None until it finishes, so this latch is what stops a
        // second unlock from starting a second tunnel in the window
        // between.
        return;
    }
    // Decide from the vault FIRST: only a vault that actually enables a
    // tunnel may consume the parked proxy. Taking it out and then finding
    // nothing to start would close the listener and turn a disabled tunnel
    // into a dead port -- fail-closed, but failing a user who asked for
    // nothing.
    let settings = state
        .vault
        .as_ref()
        .and_then(|vault| vault.tunnel_settings())
        .filter(|settings| settings.enabled);
    let Some(settings) = settings else {
        STARTING.store(false, Ordering::SeqCst);
        return;
    };
    let Some(bound) = lock(&BOUND_PROXY).take() else {
        // Imported was chosen but no proxy is parked (the bind failed at
        // startup): the engine is already on the dead port, and nothing
        // here can improve that.
        STARTING.store(false, Ordering::SeqCst);
        return;
    };
    let config = into_tunnel_config(settings);
    // ON A WORKER THREAD, not here. This function is called from the IPC
    // dispatch, which runs on the tao event-loop thread -- and starting a
    // tunnel resolves the endpoint hostname with a blocking `getaddrinfo`.
    // Against an unreachable resolver that freezes the whole browser for
    // the platform's DNS timeout, at the exact moment the user has just
    // typed their passphrase. Nothing here is needed synchronously: the
    // engine is already pointed at the port, which refuses until this
    // succeeds, and `report()` reads statics the worker fills in.
    let spawned = std::thread::Builder::new()
        .name("patanyx-tunnel-start".to_string())
        .spawn(move || {
            match Tunnel::start_on(bound, config, |event| {
                // Cheap, and never calls back into the tunnel -- the
                // crate's callback contract.
                *lock(&LAST_EVENT) = Some(event);
            }) {
                Ok(tunnel) => {
                    *lock(&RUNNING) = Some(tunnel);
                    *lock(&LAST_START_ERROR) = None;
                    // Measurement starts WITH the tunnel, not on the first
                    // poll.
                    spawn_probe_thread();
                }
                Err(failed) => {
                    // PARK THE PROXY AGAIN. The crate hands it back still
                    // bound and still refusing, and the engine is still
                    // pointing at that port -- releasing it would let any
                    // local process bind it and become the browser's proxy.
                    if let Some(proxy) = failed.proxy {
                        *lock(&BOUND_PROXY) = Some(proxy);
                    }
                    *lock(&LAST_START_ERROR) = Some(failed.error.to_string());
                }
            }
            STARTING.store(false, Ordering::SeqCst);
        });
    if spawned.is_err() {
        // Could not even spawn: the proxy stays taken (BOUND_PROXY is now
        // None) but BOUND_PORT still names it, and `bound` was moved into
        // the closure that never ran -- it drops, closing the port. Say so,
        // and let engine_proxy_port fall back to the dead port for any view
        // built afterwards.
        BOUND_PORT.store(0, Ordering::SeqCst);
        *lock(&LAST_START_ERROR) = Some("the tunnel could not be started".to_string());
        STARTING.store(false, Ordering::SeqCst);
    }
}

/// Field-for-field into the tunnel crate's config: the two shapes match 1:1
/// (the vault type exists only so the vault need not depend on the tunnel
/// crate). `enabled` is consumed by the caller's filter -- it is a vault
/// decision, not tunnel configuration. The secret Strings MOVE into the
/// config; neither type gets a Debug or Display that could print them.
fn into_tunnel_config(settings: TunnelSettings) -> TunnelConfig {
    TunnelConfig {
        private_key_b64: settings.private_key_b64,
        peer_public_key_b64: settings.peer_public_key_b64,
        endpoint: settings.endpoint,
        preshared_key_b64: settings.preshared_key_b64,
        keepalive_secs: settings.keepalive_secs,
        allowed_ips: settings.allowed_ips,
        dns: settings.dns,
        address: settings.address,
    }
}

/// The latest tunnel event, for the status surface a later phase adds.
/// Nothing reads it yet -- that phase does not exist -- so this is
/// `allow(dead_code)` rather than a pretense of a consumer.
#[allow(dead_code)]
pub fn last_event() -> Option<TunnelEvent> {
    lock(&LAST_EVENT).clone()
}

/// Why the tunnel did not start at unlock, for the same later phase.
#[allow(dead_code)]
pub fn last_start_error() -> Option<String> {
    lock(&LAST_START_ERROR).clone()
}

/// The tri-state behind `report()`, pure so the honesty rules can be pinned
/// by a table test rather than re-derived at every call site.
///
/// * Not Imported -> NotAttempted: the user chose no tunnel.
/// * Imported, tunnel Up, greeting answered -> Applied. BOTH measurements
///   are required: an answering front with a tunnel still Connecting is
///   not carrying traffic yet, and an Up tunnel whose front does not
///   answer cannot actually be loaded through.
/// * Everything else -> Failed. That INCLUDES the parked pre-unlock state,
///   on purpose: fail-closed refusal is protecting the user, but the row
///   claims "tunnel carrying traffic", and before unlock it is not. The
///   one thing this function may never do is call an unmeasured or
///   half-measured tunnel "applied".
fn classify(mode_imported: bool, tunnel_up: bool, probe_ok: bool) -> SettingState {
    if !mode_imported {
        return SettingState::NotAttempted;
    }
    if tunnel_up && probe_ok {
        return SettingState::Applied;
    }
    SettingState::Failed
}

/// Listener-liveness probe: speak one SOCKS5 greeting to the front on
/// `port` -- in production always `proxy_port()` -- and return whether it
/// answered "no authentication required" ([0x05, 0x00]). A dead port
/// refuses the connect; the parked refuse listener closes without
/// answering; either way the answer is false, so a true here means the
/// REAL tunnel front took the port over.
///
/// This is deliberately a LISTENER-LIVENESS measurement, not an exit-path
/// measurement: it proves the greeting round-trip works and says nothing
/// about whether traffic reaches the outside world through the tunnel.
/// The leak probe at test time is what measures the exit path. That split
/// is why classify() never treats probe_ok alone as "applied".
///
/// Runs only on the probe thread: the timeouts are short, but `report()`
/// is called from the UI thread on every tab_status poll and must never
/// wait on a socket.
fn probe(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(250)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }
    // Version 5, one method offered, no-authentication: exactly what the
    // engine's own proxied connections send.
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut reply = [0u8; 2];
    // read_exact maps a timeout, a close, and a short read to the same
    // false; only the exact two-byte acceptance is success.
    stream.read_exact(&mut reply).is_ok() && reply == [0x05, 0x00]
}

/// The tunnel's own word on whether it is carrying traffic, read through
/// the RUNNING static so the probe thread never takes ownership of the
/// tunnel to ask. Kept behind one helper so classify() holds the honesty
/// rules and this is the only place that speaks the tunnel crate's status
/// vocabulary.
fn tunnel_status_is_up() -> bool {
    match lock(&RUNNING).as_ref() {
        Some(tunnel) => matches!(tunnel.status(), patanyx_tunnel::TunnelStatus::Up),
        None => false,
    }
}

fn state_to_u8(state: SettingState) -> u8 {
    match state {
        SettingState::NotAttempted => PROBE_NOT_ATTEMPTED,
        SettingState::Applied => PROBE_APPLIED,
        SettingState::Failed => PROBE_FAILED,
    }
}

/// Unknown values decode to Failed: a corrupted or future state must never
/// read as a working tunnel.
fn state_from_u8(value: u8) -> SettingState {
    match value {
        PROBE_NOT_ATTEMPTED => SettingState::NotAttempted,
        PROBE_APPLIED => SettingState::Applied,
        _ => SettingState::Failed,
    }
}

/// Every ten seconds: measure, classify, store. The probe runs FIRST and
/// the sleep after, so the first honest answer lands within a second of
/// the tunnel starting rather than a full period later; until that first
/// store, PROBE_STATE's FAILED initial value is what report() reads.
///
/// The mode input to classify() is hardwired `true`: this thread exists
/// only because an Imported mode started a tunnel, and the mode half of
/// the tri-state is report()'s job to re-check on every read (it can
/// change at runtime on Linux). Nothing sets PROBE_SHUTDOWN yet -- see its
/// doc -- so this loop ends with the process, exactly like the tunnel it
/// measures.
fn probe_loop() {
    loop {
        if PROBE_SHUTDOWN.load(Ordering::SeqCst) {
            return;
        }
        // A missing port with a running tunnel "cannot happen" (the tunnel
        // serves the port it consumed); unwrap_or(false) keeps even that
        // reading fail-closed instead of panicking the measurement thread.
        let probe_ok = proxy_port().map(probe).unwrap_or(false);
        let tunnel_up = tunnel_status_is_up();
        PROBE_STATE.store(state_to_u8(classify(true, tunnel_up, probe_ok)), Ordering::SeqCst);
        std::thread::sleep(Duration::from_secs(10));
    }
}

/// Spawns the single probe thread. Called from on_vault_unlocked's success
/// arm, which the RUNNING guard already makes once-per-process, so no
/// spawn latch is needed. A spawn failure leaves PROBE_STATE at FAILED
/// forever: the tunnel may be fine, but with no measurement the only
/// honest report is "failed" -- and the unlock must not fail over
/// reporting.
fn spawn_probe_thread() {
    let _ = std::thread::Builder::new()
        .name("patanyx-tunnel-probe".to_string())
        .spawn(probe_loop);
    // A spawn failure is fail-closed by construction (see the doc comment);
    // nothing to roll back, and nothing here may propagate into unlock.
}

/// The engine-confirmed answer for the tunnel row, called from BOTH
/// backends' engine_settings on the UI thread -- which is why this never
/// blocks beyond a mutex/atomic load (plus the same prefs read every other
/// per-command site already does) and all socket work lives on the probe
/// thread.
///
/// * Mode Off -> "not_attempted". The user chose no tunnel; the chrome
///   renders this row's not_attempted as "off (no tunnel chosen)" rather
///   than the generic "not applicable" text (see renderEngineConfirmed).
/// * Imported with no running tunnel -> "failed": pre-unlock (the port is
///   parked and refusing every connection), failed bind, or failed start.
///   The parked case is fail-closed WORKING AS INTENDED, and it still must
///   not read "applied" -- the row claims "tunnel carrying traffic", and
///   before unlock nothing can load. Protecting the user and carrying
///   their traffic are different states; this row reports the second.
/// * Imported with a running tunnel -> the probe thread's latest
///   classified answer. That is "failed" until the first cycle completes:
///   nothing measured yet means nothing may claim applied.
///
/// The three wire names are the entire vocabulary. No key material, no
/// endpoint, no error text may ever ride this channel; last_start_error()
/// already owns the diagnostic half.
pub fn report() -> &'static str {
    // A RUNNING tunnel outranks the mode, and that order matters: after
    // `tunnel_remove` the mode is Off while the tunnel keeps carrying this
    // session's traffic until the restart. Reading the mode first said
    // "not_attempted", which the chrome renders as "off (no tunnel
    // chosen)" -- a flat lie told about live traffic. Report what is
    // happening, then what was chosen.
    if lock(&RUNNING).is_some() {
        return state_from_u8(PROBE_STATE.load(Ordering::SeqCst)).as_str();
    }
    if !matches!(
        crate::prefs::load().tunnel,
        crate::prefs::TunnelMode::Imported
    ) {
        return SettingState::NotAttempted.as_str();
    }
    SettingState::Failed.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};

    #[test]
    fn classify_says_applied_only_for_a_measured_up_tunnel_that_answers() {
        // (mode_imported, tunnel_up, probe_ok, expected wire name)
        let cases = [
            (false, false, false, "not_attempted"),
            // A live tunnel with the mode Off is still not_attempted: the
            // row reports the user's chosen state, not a stray process.
            (false, true, true, "not_attempted"),
            (true, true, true, "applied"),
            // The parked pre-unlock state: fail-closed is protecting the
            // user, and the row must still not claim "applied".
            (true, false, false, "failed"),
            // A greeting answered while the tunnel is still Connecting is
            // liveness, not carriage.
            (true, false, true, "failed"),
            // Up by the tunnel's own account but nothing answers the port:
            // no page can load, so nothing may claim applied.
            (true, true, false, "failed"),
        ];
        for (mode_imported, tunnel_up, probe_ok, expected) in cases {
            assert_eq!(
                classify(mode_imported, tunnel_up, probe_ok).as_str(),
                expected,
                "classify({mode_imported}, {tunnel_up}, {probe_ok})",
            );
        }
    }

    #[test]
    fn the_engine_is_never_left_unproxied_for_a_user_who_chose_a_tunnel() {
        // The invariant engine_port_for's doc states, as a table -- it had
        // no test at all while it read three statics, which is exactly how
        // the mode-ignored-after-bind defect survived.
        // (mode_imported, bound, running, expected)
        let cases = [
            // Off and nothing running: direct, by the user's choice.
            (false, None, false, None),
            (false, Some(4000), false, None),
            // Imported: the bound port, or the dead port -- NEVER None.
            (true, Some(4000), false, Some(4000)),
            (true, None, false, Some(DEAD_PORT)),
            // A running tunnel outranks the mode: traffic really is going
            // there until the restart the UI promised.
            (true, Some(4000), true, Some(4000)),
            (false, Some(4000), true, Some(4000)),
            // Running with no port recorded "cannot happen" -- and gets the
            // dead port rather than a direct connection anyway, because
            // "cannot happen" is not a thing to route traffic on.
            (true, None, true, Some(DEAD_PORT)),
            (false, None, true, Some(DEAD_PORT)),
        ];
        for (mode_imported, bound, running, expected) in cases {
            assert_eq!(
                engine_port_for(mode_imported, bound, running),
                expected,
                "engine_port_for({mode_imported}, {bound:?}, {running})",
            );
        }
        // Stated as its own assertion because it is the product promise,
        // not one row of a table: no combination may yield "no proxy" for
        // a user whose mode is Imported.
        for bound in [None, Some(4000u16)] {
            for running in [false, true] {
                assert!(
                    engine_port_for(true, bound, running).is_some(),
                    "Imported must never browse direct ({bound:?}, {running})"
                );
            }
        }
    }

    #[test]
    fn probe_rejects_a_listener_that_answers_garbage() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            conn.read_exact(&mut greeting).unwrap();
            // Whatever owns this port, it is not the tunnel's front: the
            // probe must check the ANSWER, not just that bytes came back.
            conn.write_all(b"garbage").unwrap();
        });
        assert!(!probe(port));
        server.join().unwrap();
    }

    #[test]
    fn probe_rejects_a_listener_that_accepts_and_closes() {
        // The parked refuse listener's exact behavior before unlock:
        // accept, then close without answering. If the probe read this as
        // success, report() would claim "applied" while the port is
        // deliberately failing every connection.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            drop(conn);
        });
        assert!(!probe(port));
        server.join().unwrap();
    }

    #[test]
    fn probe_accepts_the_real_tunnel_front_while_it_is_still_connecting() {
        let bound = Tunnel::bind_proxy().unwrap();
        let port = bound.port();
        let tunnel = Tunnel::start_on(bound, dead_endpoint_test_config(), |_| {})
            .expect("startup must not depend on the peer: WireGuard is connectionless");
        // The greeting works while the tunnel is Connecting -- the front
        // owns the port from the start, and the handshake to the dead
        // endpoint never completes. This is precisely why classify()
        // requires tunnel_up AND probe_ok: probe() alone would call this
        // tunnel "applied" with no exit path at all.
        assert!(probe(port));
        // The premise, ASSERTED rather than narrated (the independent
        // review caught the test claiming Connecting without checking it):
        // if this fixture ever reaches Up, the test above is measuring a
        // different situation than its name says.
        assert_eq!(
            tunnel.status(),
            patanyx_tunnel::TunnelStatus::Connecting,
            "the dead-endpoint fixture must still be Connecting when probed"
        );
    }

    /// A config that starts but can never connect: the keys are 32 zero
    /// bytes in base64 (test fixtures, NOT a real keypair, never valid
    /// against any real peer) and the endpoint is a loopback port nothing
    /// listens on -- ON-HOST on purpose, so the test emits no packet toward
    /// any real network. The tunnel stays in Connecting, which is the state
    /// the test above needs (the SOCKS greeting is answered regardless of
    /// session state; only CONNECT is gated on it).
    fn dead_endpoint_test_config() -> TunnelConfig {
        let dead_port = {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = socket.local_addr().unwrap().port();
            drop(socket);
            port
        };
        TunnelConfig {
            private_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            peer_public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            endpoint: format!("127.0.0.1:{dead_port}"),
            preshared_key_b64: None,
            keepalive_secs: None,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            // A resolver is REQUIRED for a tunnel to start at all (a
            // browser proxy resolves names inside the tunnel or not at
            // all -- see TunnelError::NoDnsServer). Never contacted here:
            // the endpoint is dead, so nothing is ever sent.
            dns: vec!["10.0.0.1".to_string()],
            address: vec!["10.0.0.2/32".to_string()],
        }
    }
}
