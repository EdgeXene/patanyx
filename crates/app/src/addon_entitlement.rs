//! Whether the open add-on may write, decided against the live date.
//!
//! Premium is evaluated at unlock (`licence_control`), but an add-on window
//! can stay open across the moment a licence ends. So its access is decided
//! again from the licence's absolute expiry day and today's UTC day: on every
//! ordinary write, after every event the loop handles (which covers a resume
//! from sleep and every activation result), and at each UTC day boundary
//! while a window is open. Activation on this device stays a separate
//! requirement, exactly as `licence_control::premium_active` has it.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use patanyx_licence::LicenceState;

use crate::licence_control::{ActivationState, SessionLicence};

/// The host API's read-only reasons.
pub const EXPIRED: &str = "expired";
pub const NOT_ACTIVE: &str = "not_active";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Full,
    /// Read only, with the reason the add-on is told (`None`: no licence).
    ReadOnly(Option<&'static str>),
}

/// The rule, pure. A perpetual licence never ends; any other needs today on
/// or before its expiry day, and a device that is activated. No licence, or
/// a locked Vault (`None`), is read-only without a reason.
pub fn decide(session: Option<&SessionLicence>, expires_day: Option<u32>, today: u32) -> Access {
    let Some(session) = session else {
        return Access::ReadOnly(None);
    };
    let live = match session.state {
        LicenceState::Free => return Access::ReadOnly(None),
        LicenceState::Perpetual => true,
        // An active licence whose day is unknown is treated as ended.
        LicenceState::Active { .. } => expires_day.is_some_and(|day| today <= day),
        LicenceState::Lapsed { .. } => false,
    };
    if !live {
        return Access::ReadOnly(Some(EXPIRED));
    }
    if session.activation != ActivationState::Activated {
        return Access::ReadOnly(Some(NOT_ACTIVE));
    }
    Access::Full
}

/// The decision now.
#[cfg(not(feature = "premium-unlocked"))]
pub fn current() -> Access {
    let (session, expires_day, today) = crate::licence_control::live_view();
    decide(session.as_ref(), expires_day, today)
}

/// DANGEROUS TEST ARTIFACT, as `licence_control::premium_active` has it: the
/// `premium-unlocked` build opens every Premium path.
#[cfg(feature = "premium-unlocked")]
pub fn current() -> Access {
    Access::Full
}

/// Brings the open window in line with the decision now. Called after every
/// event the loop handles. Full to read-only is a lapse, with its one final
/// save (`addon_session::lapse`); read-only to full, or a new reason, is
/// told to the add-on (`addon_host::set_mode`). A window not yet ready, or
/// ending, is left alone: its ready answer, or its end, decides.
pub fn recheck(app: &mut crate::state::AppState) {
    use crate::addon_host::Mode;
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    if !session.is_ready() || session.ending.borrow().is_some() {
        return;
    }
    match (session.mode.get(), current()) {
        (Mode::Full, Access::Full) => {}
        (Mode::Full, Access::ReadOnly(reason)) => crate::addon_session::lapse(app, reason),
        (Mode::ReadOnly, Access::Full) => crate::addon_host::set_mode(app, Mode::Full, None),
        (Mode::ReadOnly, Access::ReadOnly(reason)) => {
            if session.reason.get() != reason {
                crate::addon_host::set_mode(app, Mode::ReadOnly, reason);
            }
        }
    }
}

/// While a window is open, the loop wakes at the next UTC midnight, when a
/// licence can end with nothing else happening.
pub fn deadline(app: &crate::state::AppState) -> Option<Instant> {
    app.addon.as_ref().map(|_| next_day_boundary(SystemTime::now(), Instant::now()))
}

/// The next UTC midnight after `now`, as an `Instant`: when a licence can
/// next end. A clock before 1970 reads as a day away.
pub fn next_day_boundary(now: SystemTime, now_instant: Instant) -> Instant {
    const DAY_MS: u128 = 86_400_000;
    let until = now.duration_since(UNIX_EPOCH).map_or(DAY_MS, |d| DAY_MS - d.as_millis() % DAY_MS);
    now_instant + Duration::from_millis(u64::try_from(until.max(1)).unwrap_or(1))
}

#[cfg(test)]
#[path = "addon_entitlement_tests.rs"]
mod tests;
