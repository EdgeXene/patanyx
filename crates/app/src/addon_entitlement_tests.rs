use super::*;

fn session(state: LicenceState, activation: ActivationState) -> SessionLicence {
    SessionLicence { state, keys_available: true, diagnostic: None, activation, license_id_hex: Some("00".repeat(16)) }
}

const DAY: u32 = 20_500;

#[test]
fn an_active_activated_licence_is_full_through_its_last_day_and_ends_the_day_after() {
    let s = session(LicenceState::Active { days_left: 3 }, ActivationState::Activated);
    let last = DAY + 2;
    assert_eq!(decide(Some(&s), Some(last), DAY), Access::Full);
    assert_eq!(decide(Some(&s), Some(last), last), Access::Full);
    // Evaluated active at unlock, the window stays open past midnight.
    assert_eq!(decide(Some(&s), Some(last), last + 1), Access::ReadOnly(Some(EXPIRED)));
}

#[test]
fn the_expiry_day_comes_from_the_unlock_evaluation_exactly() {
    use crate::licence_control::expires_day_of;
    assert_eq!(expires_day_of(LicenceState::Active { days_left: 1 }, DAY), Some(DAY));
    assert_eq!(expires_day_of(LicenceState::Active { days_left: 30 }, DAY), Some(DAY + 29));
    assert_eq!(expires_day_of(LicenceState::Lapsed { expires_day: 7 }, DAY), Some(7));
    assert_eq!(expires_day_of(LicenceState::Perpetual, DAY), None);
    assert_eq!(expires_day_of(LicenceState::Free, DAY), None);
}

#[test]
fn a_perpetual_licence_never_ends_and_an_unknown_end_counts_as_ended() {
    let p = session(LicenceState::Perpetual, ActivationState::Activated);
    assert_eq!(decide(Some(&p), None, u32::MAX), Access::Full);
    let a = session(LicenceState::Active { days_left: 9 }, ActivationState::Activated);
    assert_eq!(decide(Some(&a), None, DAY), Access::ReadOnly(Some(EXPIRED)));
}

#[test]
fn activation_is_its_own_requirement() {
    for activation in [ActivationState::NotNeeded, ActivationState::Unactivated { reason: "pending" }] {
        let s = session(LicenceState::Active { days_left: 9 }, activation);
        assert_eq!(decide(Some(&s), Some(DAY + 8), DAY), Access::ReadOnly(Some(NOT_ACTIVE)));
    }
    // An ended licence says ended, whatever the activation.
    let s = session(LicenceState::Lapsed { expires_day: DAY - 1 }, ActivationState::Unactivated { reason: "pending" });
    assert_eq!(decide(Some(&s), Some(DAY - 1), DAY), Access::ReadOnly(Some(EXPIRED)));
}

#[test]
fn no_licence_or_a_locked_vault_is_read_only_without_a_reason() {
    assert_eq!(decide(None, None, DAY), Access::ReadOnly(None));
    let f = session(LicenceState::Free, ActivationState::NotNeeded);
    assert_eq!(decide(Some(&f), None, DAY), Access::ReadOnly(None));
}

#[test]
fn the_next_boundary_is_the_coming_utc_midnight() {
    let now = Instant::now();
    let at = |secs: u64| next_day_boundary(UNIX_EPOCH + Duration::from_secs(secs), now) - now;
    assert_eq!(at(86_400 * 10), Duration::from_secs(86_400));
    assert_eq!(at(86_400 * 10 + 86_399), Duration::from_secs(1));
    assert_eq!(at(86_400 * 10 + 3_600), Duration::from_secs(86_400 - 3_600));
    // A fraction of a second before midnight wakes at midnight, not a second late.
    let late = next_day_boundary(UNIX_EPOCH + Duration::from_millis(86_400_000 * 10 + 86_399_900), now) - now;
    assert_eq!(late, Duration::from_millis(100));
}

/// The wiring, checked in the source because an AppState cannot be built in
/// a unit test.
#[test]
fn the_live_decision_is_asked_on_every_write_every_event_and_at_midnight() {
    let main = include_str!("main.rs");
    let end = main.find("addon_selection::sync_menu(&app);\n    });").expect("the loop's end moved");
    assert!(main[..end].ends_with("addon_entitlement::recheck(&mut app);\n        "), "no recheck after every event");
    assert!(main.contains("addon_entitlement::deadline(&app)"), "no wake at the day boundary");
    let host = include_str!("addon_host.rs");
    let admit = &host[host.find("fn admit_storage(").expect("admit_storage moved")..];
    assert!(admit[..2200].contains("crate::addon_entitlement::current() != crate::addon_entitlement::Access::Full"));
    let ready = &host[host.find("Command::Ready { host_api } =>").expect("ready moved")..];
    assert!(ready[..1500].contains("crate::addon_entitlement::current()"), "the mode at ready is not live");
    let session = include_str!("addon_session.rs");
    let complete = &session[session.find("fn complete(").expect("complete moved")..];
    let kept = complete.find("lapse: Some(reason), then: Then::NOTHING").expect("a lapse no longer keeps the window");
    let destroyed = complete.find("addon_host::destroy(app);").expect("complete moved");
    assert!(kept < destroyed);
}
