//! Session-side Premium licence state: the vault stores the token TEXT,
//! and only this module turns it into a session fact.
//!
//! WHY THIS MODULE EXISTS. Design 3.3 requires the stored token to be
//! re-parsed and RE-VERIFIED at every unlock — there is no cached trust
//! bit, because a signature checked this session is the only thing that
//! makes a pasted string a licence. That evaluation (and its result,
//! FREE / ACTIVE / LAPSED) lives here for the session; feature gates read
//! it, never the vault. The parse + evaluate step is a pure function
//! (`evaluate_stored`) so the whole state machine is unit-testable on
//! Linux with no display, no clock, and no vault — and so the P2
//! planted-defect gate has exactly one line to stub.
//!
//! HONESTY RULES, stated once:
//!
//! * The compiled-in key ring is REAL since the 2026-08-05 ceremony
//!   (`LICENCE_KEYS` carries the working key at id 0), so
//!   `keys_available` is TRUE in every real build and paste genuinely
//!   verifies. The empty-ring path below is kept and tested because a
//!   `--no-default-features`-style build without the ring must still
//!   report "cannot verify" honestly rather than a confusing "bad
//!   token" message about a token nothing tried to verify.
//! * A stored token that fails re-verification is FREE with a local-only
//!   diagnostic (3.3 step 2). The diagnostic names the failure class and
//!   NEVER contains the token text — a test pins that.
//! * The clock is read in exactly one function here
//!   (`today_utc_day_number`); everything else takes a day number, so
//!   tests inject days and never the clock.
//! * NO FALLBACK LICENSE (decided 2026-08-05, design preamble):
//!   LAPSED gates exactly like FREE. `premium_active` is the entire rule.
//! * NO ENFORCEMENT: `premium_active` is landed fully tested and CALLED
//!   BY NOTHING. Flipping any feature switch is a later, deliberate
//!   deliberate act.

use std::sync::{Mutex, MutexGuard};

use patanyx_licence::{evaluate, LicenceKeys, LicenceState, Token};
use zeroize::Zeroize as _;

use crate::state::AppState;

/// The unlock-time evaluation result, held for the session (design 3.3:
/// "held in memory for the session; feature gates read it").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLicence {
    /// FREE / ACTIVE{days_left} / LAPSED{expires_day}.
    pub state: LicenceState,
    /// Whether this build carries a usable verification key ring. TRUE in
    /// every real build since the 2026-08-05 key ceremony; false only in a
    /// build stripped of the ring, where the UI and the paste flow say
    /// "cannot verify" instead of "bad token".
    pub keys_available: bool,
    /// Local-only diagnostic for the anomalous paths (a stored token that
    /// fails re-verification, a stored token with no ring to check it
    /// against). NEVER the token text; `eprintln!`-ed at evaluation time
    /// and otherwise only read by tests.
    pub diagnostic: Option<String>,
}

/// The session state. `None` means "locked" (or never evaluated): nothing
/// licence-related may survive a lock, so `on_vault_locked` clears it and
/// every reader treats `None` as FREE.
static SESSION: Mutex<Option<SessionLicence>> = Mutex::new(None);

/// Poisoning is not fatal here: a panic elsewhere must not make the
/// licence state unreadable.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The ONE clock read in this module — and the only licence-related clock
/// read in the crate. Everything else takes a day number.
fn today_utc_day_number() -> u32 {
    const SECS_PER_DAY: u64 = 86_400;
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        // A clock past day u32::MAX (~11.7 million years out) saturates
        // high: every token reads LAPSED. Fail-closed beats fail-open here.
        Ok(duration) => u32::try_from(duration.as_secs() / SECS_PER_DAY).unwrap_or(u32::MAX),
        // A clock before 1970-01-01 reads as day 0, which makes every token
        // ACTIVE — fail-open, and accepted: design 3.6 puts client clock
        // games out of scope (the relay enforces real dates for the one
        // feature with ongoing cost). Saturating is at least honest about
        // "we cannot know".
        Err(_) => 0,
    }
}

/// The pure heart of the module: given the stored token text (or none),
/// the key ring (or why it could not be built), and today's UTC day
/// number, compute the session state. No clock, no vault, no statics —
/// the P2 planted-defect gate stubs the verification-failure arm below
/// and asserts the suite then fails.
fn evaluate_stored(
    token_text: Option<&str>,
    keys: Result<&LicenceKeys, String>,
    today: u32,
) -> SessionLicence {
    let keys_available = keys.is_ok();
    // 3.3 step 1: no record, state FREE. A missing ring with nothing to
    // verify earns no diagnostic — it is every real build today, not an
    // anomaly.
    let Some(text) = token_text else {
        return SessionLicence {
            state: LicenceState::Free,
            keys_available,
            diagnostic: None,
        };
    };
    let keys = match keys {
        Ok(keys) => keys,
        // A stored token nothing can verify: FREE with the fact on record,
        // NEVER a bad-token claim about a token that was never checked.
        // Unreachable in real builds today (paste can never succeed while
        // the ring is empty), so this arm is exercised by test injection.
        Err(why) => {
            return SessionLicence {
                state: LicenceState::Free,
                keys_available: false,
                diagnostic: Some(format!(
                    "the stored licence token could not be verified: {why}"
                )),
            };
        }
    };
    // 3.3 step 2: re-parse and re-verify at every unlock. There is no
    // cached trust bit: the vault stores text, and only a signature
    // checked against the compiled-in ring THIS session makes it a licence.
    let verified = Token::parse(text, keys);
    // A verification failure "should be impossible" for a token that
    // validated at paste time, so it is recorded locally, not surfaced.
    // The error's Display names the failure class (unknown key id, bad
    // signature, …) and carries no token text.
    let diagnostic = verified
        .as_ref()
        .err()
        .map(|error| format!("a stored licence token failed re-verification at unlock: {error}"));
    let state = match verified {
        Ok(token) => evaluate(Some(&token), today),
        // PLANTED-DEFECT GATE TARGET (scripts/licence-planted-defect-gate.sh,
        // P2 phase): this arm is the re-verification's teeth — it is what
        // makes a stored-but-invalid token FREE. The gate rewrites this arm
        // to always-ACTIVE and asserts the suite fails; it exits 2 if it
        // cannot find the arm verbatim. Keep this exact line, or update the
        // gate in the same commit.
        Err(_) => LicenceState::Free,
    };
    SessionLicence {
        state,
        keys_available,
        diagnostic,
    }
}

/// The vault has just opened (create, unlock, or recovery unlock): read
/// the licence record, re-verify it against the compiled-in ring, and
/// hold the result for the session. Never fails: a verification problem
/// is FREE plus a local diagnostic, not an unlock failure.
///
/// Wired into `vault_create`, `vault_unlock`, and `vault_unlock_recovery`
/// in ipc.rs, next to the tunnel_control calls.
pub fn on_vault_unlocked(state: &AppState) {
    // The clone `licence_record` hands out carries the bearer token on the
    // heap; the vault's caller-owns-wiping contract makes it ours to wipe.
    let mut record = state
        .vault
        .as_ref()
        .and_then(|vault| vault.licence_record());
    let keys = patanyx_licence::licence_keys();
    let session = evaluate_stored(
        record.as_ref().map(|record| record.token_text.as_str()),
        keys.as_ref().map_err(|error| error.to_string()),
        today_utc_day_number(),
    );
    if let Some(record) = record.as_mut() {
        record.token_text.zeroize();
    }
    if let Some(diagnostic) = &session.diagnostic {
        // Local-only diagnostics, never the token.
        eprintln!("patanyx licence: {diagnostic}");
    }
    *lock(&SESSION) = Some(session);
}

/// The vault has just locked: the session state dies with it, for the same
/// reason the chat identity dies at lock (see `lock_vault` in state.rs) —
/// the next unlock re-verifies from the vault, and nothing licence-related
/// may survive the lock in memory.
pub fn on_vault_locked() {
    *lock(&SESSION) = None;
}

/// The current session state, if the vault is unlocked and has been
/// evaluated. `None` means locked — readers must treat it as FREE, never
/// as an error.
pub fn current() -> Option<SessionLicence> {
    lock(&SESSION).clone()
}

/// Whether this build carries a usable verification key ring. P1 ships an
/// EMPTY ring, so this is false in every real build today: paste can never
/// succeed and unlock-time evaluation lands FREE. Reported on the read
/// payload so the panel never has to guess.
pub fn keys_available() -> bool {
    patanyx_licence::licence_keys().is_ok()
}

/// The entire gating rule: premium features are on while the session state
/// is ACTIVE, off otherwise. LAPSED gates exactly like FREE (no fallback
/// license — decided 2026-08-05), and a locked or
/// never-evaluated session reads as FREE: an absence of information must
/// never gate anything ON.
///
/// CALLED BY NOTHING yet — and that is deliberate. P2 lands the machinery
/// fully tested but with NO enforcement: nothing in this phase switches
/// chat, the tunnel, OCR, or themes off for any licence state. Flipping a
/// feature switch is a later, deliberate deliberate act.
pub fn premium_active() -> bool {
    lock(&SESSION)
        .as_ref()
        .map(|session| session.state.premium_active())
        .unwrap_or(false)
}

/// The row copy for the current session, with the clock read here so the
/// pure half stays injectable. Rust words this copy; the chrome writes it
/// verbatim and never retypes it.
pub fn row_copy_for(state: &LicenceState) -> (String, String) {
    row_copy(state, today_utc_day_number())
}

/// The date text the paste flow's expired notice needs (`was_expired`):
/// the same wording the row uses, from the same function, so one surface
/// words one fact.
pub fn ended_display_for(expires_day: u32) -> String {
    ended_display(expires_day, today_utc_day_number())
}

/// The three design-3.4 states, verbatim. Pure: the clock is a parameter.
fn row_copy(state: &LicenceState, today: u32) -> (String, String) {
    match *state {
        // "Premium Time Left: {N} days" -- reworded 2026-08-05,
        // superseding the design's "Premium: {N} days left" verbatim form.
        // The singular keeps the same shape.
        LicenceState::Active { days_left: 1 } => {
            ("Premium Time Left: 1 day".to_string(), String::new())
        }
        LicenceState::Active { days_left } => {
            (format!("Premium Time Left: {days_left} days"), String::new())
        }
        LicenceState::Lapsed { expires_day } => (
            format!("Premium ended {}.", ended_display(expires_day, today)),
            "Free features always remain free.".to_string(),
        ),
        LicenceState::Free => (
            "PATANYX Free".to_string(),
            "Free features always remain free.".to_string(),
        ),
    }
}

/// "March 12" — or "March 12, 2026" when the lapse is MORE than twelve
/// months before today (design preamble decision). Exactly twelve months
/// keeps the year-less verbatim form.
fn ended_display(expires_day: u32, today: u32) -> String {
    let (year, month, day) = patanyx_licence::civil_from_day_number(expires_day);
    if today > twelve_months_after(expires_day) {
        format!("{} {day}, {year}", month_name(month))
    } else {
        format!("{} {day}", month_name(month))
    }
}

/// The day twelve calendar months after `day`: same month, same date, one
/// year later. The only clamp the calendar needs is Feb 29 -> Feb 28 when
/// the following year is not a leap year, so the `expect` cannot fire: a
/// clamped date always exists.
fn twelve_months_after(day: u32) -> u32 {
    let (year, month, date) = patanyx_licence::civil_from_day_number(day);
    let date = if month == 2 && date == 29 && !is_leap_year(i64::from(year) + 1) {
        28
    } else {
        date
    };
    patanyx_licence::day_number_from_civil(year + 1, month, date)
        .expect("a clamped calendar date one year later always exists")
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn month_name(month: u32) -> &'static str {
    const NAMES: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    // `civil_from_day_number` yields 1..=12 by construction; a violation
    // would be a licence-crate bug, and the copy pins below would catch it.
    NAMES
        .get(month.wrapping_sub(1) as usize)
        .copied()
        .unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Fixed seeds, never an RNG — the workspace rule, and it keeps the
    /// tests deterministic (mirrors the licence crate's own tests).
    const RING_SEED: [u8; 32] = [0x42; 32];
    const WRONG_SEED: [u8; 32] = [0xA5; 32];
    const LICENSE_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    /// 2026-03-12 UTC — the design's worked example (2.2).
    const EXPIRES: u32 = 20524;

    fn test_ring() -> LicenceKeys {
        LicenceKeys::new(vec![SigningKey::from_bytes(&RING_SEED).verifying_key()])
            .expect("one strong key")
    }

    fn mint_text(seed: &[u8; 32], expires_day: u32) -> String {
        Token::mint(&SigningKey::from_bytes(seed), 0, LICENSE_ID, expires_day).to_text()
    }

    /// Session-mutating tests serialize through this: SESSION is process-
    /// wide and Rust runs tests on threads.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn no_stored_token_evaluates_free() {
        let ring = test_ring();
        let session = evaluate_stored(None, Ok(&ring), 21000);
        assert_eq!(session.state, LicenceState::Free);
        assert!(session.keys_available);
        assert_eq!(session.diagnostic, None);
    }

    #[test]
    fn a_valid_stored_token_unlocks_active_and_counts_the_expiry_day_itself() {
        let ring = test_ring();
        let text = mint_text(&RING_SEED, EXPIRES);
        assert_eq!(
            evaluate_stored(Some(&text), Ok(&ring), EXPIRES - 24).state,
            LicenceState::Active { days_left: 25 }
        );
        assert_eq!(
            evaluate_stored(Some(&text), Ok(&ring), EXPIRES).state,
            LicenceState::Active { days_left: 1 },
            "the expiry day itself counts (design 3.3 step 5)"
        );
    }

    #[test]
    fn an_expired_but_valid_stored_token_unlocks_lapsed() {
        let ring = test_ring();
        let text = mint_text(&RING_SEED, 19000);
        let session = evaluate_stored(Some(&text), Ok(&ring), 21000);
        assert_eq!(session.state, LicenceState::Lapsed { expires_day: 19000 });
        assert_eq!(
            session.diagnostic, None,
            "an expired token is valid, not anomalous"
        );
    }

    /// THE P2 planted-defect property: with unlock-time re-verification
    /// stubbed out, this test must fail. A stored token whose signature
    /// does not verify against the ring is FREE — never ACTIVE — with a
    /// local-only diagnostic.
    #[test]
    fn a_stored_token_that_fails_reverification_unlocks_free_never_active() {
        let ring = test_ring();
        // Honestly signed — but by a key the ring does not carry.
        let text = mint_text(&WRONG_SEED, EXPIRES);
        let session = evaluate_stored(Some(&text), Ok(&ring), EXPIRES - 24);
        assert_eq!(
            session.state,
            LicenceState::Free,
            "a stored token that fails re-verification is FREE, never ACTIVE"
        );
        let diagnostic = session.diagnostic.expect("the anomaly is recorded");
        assert!(
            !diagnostic.contains(&text),
            "the diagnostic must never contain the token text: {diagnostic}"
        );
    }

    #[test]
    fn a_garbage_stored_string_unlocks_free_with_a_token_free_diagnostic() {
        let ring = test_ring();
        let text = "ptx1-DEFINITELY-NOT-A-REAL-TOKEN";
        let session = evaluate_stored(Some(text), Ok(&ring), 21000);
        assert_eq!(session.state, LicenceState::Free);
        let diagnostic = session.diagnostic.expect("the anomaly is recorded");
        assert!(!diagnostic.contains(text));
    }

    #[test]
    fn a_build_without_licence_keys_unlocks_free_and_says_so_honestly() {
        // Every real build today: the ring is empty, so the outcome is
        // "keys unavailable", never a confusing bad-token message.
        let text = mint_text(&RING_SEED, EXPIRES);
        let session = evaluate_stored(
            Some(&text),
            Err("no licence keys are compiled into this build".to_string()),
            EXPIRES - 24,
        );
        assert_eq!(session.state, LicenceState::Free);
        assert!(!session.keys_available);
        let diagnostic = session
            .diagnostic
            .expect("a stored token with no ring is recorded");
        assert!(!diagnostic.contains(&text));
        // With no token stored there is nothing to verify, and nothing
        // anomalous to record — that is the ordinary P1-build state.
        let session = evaluate_stored(None, Err("no licence keys".to_string()), EXPIRES);
        assert_eq!(session.state, LicenceState::Free);
        assert!(!session.keys_available);
        assert_eq!(session.diagnostic, None);
    }

    #[test]
    fn the_three_row_states_are_worded_verbatim() {
        assert_eq!(
            row_copy(&LicenceState::Free, 21000),
            (
                "PATANYX Free".to_string(),
                "Free features always remain free.".to_string()
            )
        );
        assert_eq!(
            row_copy(&LicenceState::Active { days_left: 43 }, 21000),
            ("Premium Time Left: 43 days".to_string(), String::new())
        );
        assert_eq!(
            row_copy(&LicenceState::Active { days_left: 1 }, 21000).0,
            "Premium Time Left: 1 day",
            "reworded 2026-08-05; if the project owner changes it again, change this pin"
        );
        let lapsed = LicenceState::Lapsed {
            expires_day: EXPIRES,
        };
        assert_eq!(
            row_copy(&lapsed, 20600),
            (
                "Premium ended March 12.".to_string(),
                "Free features always remain free.".to_string()
            )
        );
    }

    #[test]
    fn the_expired_row_adds_the_year_only_after_twelve_months() {
        let lapsed = LicenceState::Lapsed {
            expires_day: EXPIRES, // 2026-03-12
        };
        // 2027-03-12 is day 20889: exactly twelve months on — still the
        // year-less verbatim form.
        assert_eq!(row_copy(&lapsed, 20889).0, "Premium ended March 12.");
        // One day later the lapse is MORE than twelve months old, and the
        // year appears.
        assert_eq!(row_copy(&lapsed, 20890).0, "Premium ended March 12, 2026.");
    }

    #[test]
    fn the_year_rule_handles_a_leap_day_lapse() {
        let lapsed = LicenceState::Lapsed {
            expires_day: 19782, // 2024-02-29
        };
        // Twelve months after 2024-02-29 clamps to 2025-02-28 (day 20147):
        // exactly twelve months on, still no year.
        assert_eq!(row_copy(&lapsed, 20147).0, "Premium ended February 29.");
        assert_eq!(row_copy(&lapsed, 20148).0, "Premium ended February 29, 2024.");
    }

    #[test]
    fn premium_active_reads_the_session_state_and_locked_means_free() {
        let _serial = lock(&SERIAL);
        *lock(&SESSION) = None;
        assert!(
            !premium_active(),
            "a locked vault is FREE: an absence of information gates nothing ON"
        );
        *lock(&SESSION) = Some(SessionLicence {
            state: LicenceState::Active { days_left: 3 },
            keys_available: true,
            diagnostic: None,
        });
        assert!(premium_active());
        // LAPSED gates exactly like FREE: no fallback license (operator
        // decision 2026-08-05).
        *lock(&SESSION) = Some(SessionLicence {
            state: LicenceState::Lapsed { expires_day: 20669 },
            keys_available: true,
            diagnostic: None,
        });
        assert!(!premium_active(), "lapsed means NO premium features at all");
        *lock(&SESSION) = Some(SessionLicence {
            state: LicenceState::Free,
            keys_available: true,
            diagnostic: None,
        });
        assert!(!premium_active());
        *lock(&SESSION) = None;
    }

    #[test]
    fn on_vault_locked_clears_the_session() {
        let _serial = lock(&SERIAL);
        *lock(&SESSION) = Some(SessionLicence {
            state: LicenceState::Active { days_left: 3 },
            keys_available: true,
            diagnostic: None,
        });
        on_vault_locked();
        assert_eq!(current(), None, "nothing licence-related survives a lock");
    }
}
