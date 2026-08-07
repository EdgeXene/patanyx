//! Offline-verified Ed25519 licence tokens for PATANYX Premium.
//!
//! This crate is phase P1 of the Premium design: the token core library and
//! nothing else. It knows the 94-byte binary
//! layout, the `ptx1-` text form, the section 3.2 validation order, the
//! compiled-in verification key ring, and day-number date math. It does NOT
//! know: any user-facing copy (the 3.2 messages are draft and live in the
//! app layer, P2), any storage (the vault stores the text form as a string,
//! P2), the replace/confirm flow (3.2 step 8, P2), or the relay handshake
//! itself (P3). P3 adds ONLY the 90-byte wire form (`parse_wire` /
//! `to_wire_bytes`): the layout keeps exactly one implementation, shared by
//! signer, browser, and relay.
//!
//! Security posture, stated once here and enforced below:
//!
//! * A token is trusted because a compiled-in EdgeXene key signed it,
//!   never because it parsed or decoded.
//! * Verification is `verify_strict`, never `verify`; weak (small-order)
//!   keys and an empty ring are refused at construction, loudly — see
//!   `keys.rs` for why the refusals matter.
//! * An EXPIRED token is VALID. Expiry is a state (`evaluate`), never a
//!   parse error: the stored token carries the license_id the renewal
//!   path needs (design 3.2 step 8) and the date the vault row reports.
//!   It entitles the holder to NOTHING while lapsed -- there is no
//!   fallback license (decided 2026-08-05, design preamble).
//! * The token is a bearer credential. Nothing here prints, logs, or
//!   Debug-formats full token bytes or the text form; the one `Debug` impl
//!   on token material is hand-written and redacts.
//! * No clock, no filesystem, no network, no RNG. `today_utc` is always a
//!   parameter.

mod base64url;
mod crc32;
mod days;
mod error;
mod hex;
mod keys;
mod token;

pub use days::{civil_from_day_number, day_number_from_civil};
pub use error::LicenceError;
pub use keys::{licence_keys, LicenceKeys, LICENCE_KEYS};
pub use token::{evaluate, LicenceState, Token, TIER_PREMIUM, TOKEN_LEN, TOKEN_TEXT_LEN, WIRE_LEN};
