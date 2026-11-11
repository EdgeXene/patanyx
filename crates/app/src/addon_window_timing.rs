//! Debug-only native geometry measurements. No payload or input text is logged.
//! The native runner sets PATANYX_ADDON_WINDOW_TIMING in its disposable profile.
use std::{cell::Cell, sync::OnceLock, time::Instant};
thread_local! {
    static RECEIVED: Cell<Option<Instant>> = const { Cell::new(None) };
    static PENDING: Cell<Option<(Instant, u32)>> = const { Cell::new(None) };
}
fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("PATANYX_ADDON_WINDOW_TIMING").is_some())
}
pub fn received(at: Instant) {
    if enabled() {
        RECEIVED.set(Some(at));
    }
}
pub fn begin(sequence: Option<u32>) -> Option<Instant> {
    if !enabled() {
        return None;
    }
    let sequence = sequence?;
    PENDING.set(RECEIVED.take().map(|at| (at, sequence)));
    Some(Instant::now())
}
pub fn handled(started: Option<Instant>) {
    if let Some(started) = started {
        eprintln!("addon-motion host_us={}", started.elapsed().as_micros());
    }
}
/// Called at GTK's child allocation / after WebView2 applies bounds.
pub fn applied() {
    if let Some((received, sequence)) = PENDING.take() {
        eprintln!(
            "addon-motion applied_us={} sequence={sequence}",
            received.elapsed().as_micros()
        );
    }
}
