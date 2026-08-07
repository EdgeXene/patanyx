//! The 94-byte token layout, its text form, minting, validation, and
//! unlock-time evaluation.
//!
//! One rule keeps signer and verifier from drifting: BOTH paths run
//! through the same `payload_of` / `signing_message` / `assemble`
//! functions. There is no second place that knows where a field lives.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::base64url;
use crate::crc32::crc32_ieee;
use crate::error::LicenceError;
use crate::keys::LicenceKeys;

/// ASCII domain separator prefixed to every signature input (design 2.2):
/// it prevents cross-protocol confusion with update-manifest signatures,
/// which sign a different domain. 18 bytes; `signing_message` asserts the
/// length so a future edit cannot silently change the signed bytes' shape.
const DOMAIN_SEPARATOR: &[u8] = b"PATANYX-LICENSE-V1";

/// 0x01 = premium. All other values are reserved (design 2.2).
pub const TIER_PREMIUM: u8 = 0x01;

/// Binary token length: 1 + 16 + 1 + 4 + 4 + 64 + 4.
pub const TOKEN_LEN: usize = 94;

/// Wire form length (design 4.1): the token bytes 0..90 — payload (26) +
/// signature (64). The CRC is a paste-time concern and is NOT on the wire.
pub const WIRE_LEN: usize = 90;

/// Text form length: "ptx1-" (5) + 126 base64url chars for 94 bytes.
pub const TOKEN_TEXT_LEN: usize = 131;

const TEXT_PREFIX: &str = "ptx1-";
const PAYLOAD_LEN: usize = 26;
const SIGNATURE_OFFSET: usize = 26;
const CRC_OFFSET: usize = WIRE_LEN;

/// Parse rejects inputs longer than this before any allocation. A token is
/// 131 characters; 4096 allows pathological-but-honest whitespace wrapping
/// (every character on its own CRLF line is 393 bytes) with an order of
/// magnitude to spare, while a multi-megabyte paste is refused in O(1).
const MAX_PASTE_LEN: usize = 4096;

/// key_id(1) | license_id(16) | tier(1) | expires_day(u32 LE) |
/// features_until_day(u32 LE) — the 26 bytes the signature covers.
fn payload_of(
    key_id: u8,
    license_id: &[u8; 16],
    tier: u8,
    expires_day: u32,
    features_until_day: u32,
) -> [u8; PAYLOAD_LEN] {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0] = key_id;
    payload[1..17].copy_from_slice(license_id);
    payload[17] = tier;
    payload[18..22].copy_from_slice(&expires_day.to_le_bytes());
    payload[22..26].copy_from_slice(&features_until_day.to_le_bytes());
    payload
}

/// DOMAIN_SEPARATOR || payload — the exact 44 signature-input bytes.
fn signing_message(payload: &[u8; PAYLOAD_LEN]) -> [u8; 44] {
    debug_assert_eq!(DOMAIN_SEPARATOR.len(), 18);
    let mut message = [0u8; 44];
    let (domain, rest) = message.split_at_mut(DOMAIN_SEPARATOR.len());
    domain.copy_from_slice(DOMAIN_SEPARATOR);
    rest.copy_from_slice(payload);
    message
}

/// payload || signature || crc32(payload || signature) — the 94 bytes.
fn assemble(payload: &[u8; PAYLOAD_LEN], signature: &[u8; 64]) -> [u8; TOKEN_LEN] {
    let mut bytes = [0u8; TOKEN_LEN];
    bytes[..PAYLOAD_LEN].copy_from_slice(payload);
    bytes[SIGNATURE_OFFSET..CRC_OFFSET].copy_from_slice(signature);
    let crc = crc32_ieee(&bytes[..CRC_OFFSET]);
    bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn text_of(bytes: &[u8; TOKEN_LEN]) -> String {
    let mut out = String::with_capacity(TOKEN_TEXT_LEN);
    out.push_str(TEXT_PREFIX);
    out.push_str(&base64url::encode(bytes));
    debug_assert_eq!(out.len(), TOKEN_TEXT_LEN);
    out
}

/// A parsed and verified token. Fields are readable; the signature stays
/// private because nothing outside this file needs it except through
/// `to_bytes`, and narrowing the surface keeps it that way.
///
/// Note what construction means: `Token` values exist only from `mint`
/// (honestly signed just now) or `parse`/`parse_wire` (verified against the
/// ring). There
/// is no public constructor, so "I hold a `Token`" always means "this
/// verified". An expired token is still a `Token` — expiry is a state, not
/// an error (design 3.2 step 7 stores it: the record keeps the
/// license_id the renewal path matches on, nothing more).
pub struct Token {
    /// Index into the compiled-in key ring (design 2.4).
    key_id: u8,
    /// Random 128-bit licence identifier, minted at first purchase. P2's
    /// replace/confirm flow (3.2 step 8) reads this to tell a renewal
    /// (same id, silent replace) from a different licence (confirm first).
    license_id: [u8; 16],
    /// 0x01 = premium; reserved values never validate.
    tier: u8,
    /// Token valid through the END of this UTC day (days since 1970-01-01).
    expires_day: u32,
    /// RESERVED. Carried in the signed layout (offset 22, validated by
    /// 3.2 step 6) but consulted by nothing: the fallback license it was
    /// designed for was removed by decided 2026-08-05 (design
    /// preamble). Minted equal to `expires_day`.
    features_until_day: u32,
    /// Kept so `to_bytes` can rebuild the exact wire form (the P3 relay
    /// handshake sends bytes 0..89). Never Debug-formatted.
    signature: [u8; 64],
}

// Every field is PRIVATE with a read-only getter, and that is load-bearing,
// not style: the struct doc above promises that holding a `Token` means it
// verified. Public fields would let any safe caller rewrite `expires_day`
// or `features_until_day` AFTER verification and hand the result straight
// to `evaluate`, which trusts what it is given. Readable must not imply
// writable. (Found in independent review before first landing.)
impl Token {
    /// Index into the compiled-in key ring (design 2.4).
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// The random 128-bit licence identifier. P2's replace/confirm flow
    /// (3.2 step 8) reads this to tell a renewal from a different licence.
    pub fn license_id(&self) -> [u8; 16] {
        self.license_id
    }

    /// 0x01 = premium; reserved values never validate.
    pub fn tier(&self) -> u8 {
        self.tier
    }

    /// Token valid through the END of this UTC day (days since 1970-01-01).
    pub fn expires_day(&self) -> u32 {
        self.expires_day
    }

    /// RESERVED field (see the struct doc); exposed only so tooling can
    /// display the raw layout. Nothing gates on it.
    pub fn features_until_day(&self) -> u32 {
        self.features_until_day
    }
}

impl Token {
    /// Construct and sign a premium token. Used by tests today and by the
    /// operator's signing tool tomorrow; it shares the layout code with
    /// `parse`, so the two cannot drift.
    ///
    /// `features_until_day` is RESERVED (no fallback license exists --
    /// decided 2026-08-05, design preamble) and is always minted
    /// EQUAL to `expires_day`, which also satisfies the 3.2 step 6 layout
    /// check every browser applies. There is deliberately no parameter for
    /// it: a signer that could set it independently would be minting a
    /// field with no meaning.
    pub fn mint(
        signing_key: &SigningKey,
        key_id: u8,
        license_id: [u8; 16],
        expires_day: u32,
    ) -> Token {
        let features_until_day = expires_day;
        let payload = payload_of(
            key_id,
            &license_id,
            TIER_PREMIUM,
            expires_day,
            features_until_day,
        );
        let message = signing_message(&payload);
        let signature = signing_key.sign(&message);
        Token {
            key_id,
            license_id,
            tier: TIER_PREMIUM,
            expires_day,
            features_until_day,
            signature: signature.to_bytes(),
        }
    }

    /// Parse and validate the text form, in the EXACT order of design 3.2
    /// steps 1–7. Each step's failure is a distinct typed error; the app
    /// layer owns the copy. Step 7 is deliberately absent: an expired token
    /// is valid and is stored; `evaluate` computes the state.
    pub fn parse(text: &str, keys: &LicenceKeys) -> Result<Token, LicenceError> {
        // Before anything allocates: a valid token is 131 characters plus
        // whatever whitespace wrapped it. This bound exists so a paste of
        // arbitrary size is rejected in O(1) rather than copied and decoded
        // first; it is generous enough that no legitimately wrapped token
        // can ever hit it.
        if text.len() > MAX_PASTE_LEN {
            return Err(LicenceError::NotAToken);
        }
        // Step 1: strip ALL ASCII whitespace first, so a token line-wrapped
        // by a plain-text email still pastes cleanly; then dispatch on the
        // prefix and decode. `ptx2-` and everything else without the exact
        // `ptx1-` prefix is rejected here.
        let stripped: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let encoded = stripped
            .strip_prefix(TEXT_PREFIX)
            .ok_or(LicenceError::NotAToken)?;
        let bytes = base64url::decode(encoded).map_err(|_| LicenceError::NotAToken)?;

        // Step 2: length and CRC, BEFORE any cryptography, so a truncated
        // or corrupted paste is reported as a paste problem and no key
        // lookup or signature work runs on garbage.
        if bytes.len() != TOKEN_LEN {
            return Err(LicenceError::CrcMismatch);
        }
        let stored_crc =
            u32::from_le_bytes(bytes[CRC_OFFSET..].try_into().expect("length checked"));
        if crc32_ieee(&bytes[..CRC_OFFSET]) != stored_crc {
            return Err(LicenceError::CrcMismatch);
        }

        // Steps 3-6 run on the 90 wire bytes and are shared with
        // `parse_wire` via `validate_wire_bytes`, so the paste path and the
        // relay path can never drift.
        let wire: &[u8; WIRE_LEN] = bytes[..WIRE_LEN].try_into().expect("length checked");
        validate_wire_bytes(wire, keys)
    }

    /// Parse and validate the 90-byte WIRE form the relay handshake carries
    /// (design 4.1): exactly the token bytes 0..90 — payload (26) +
    /// signature (64). There is no CRC on the wire, so a wrong LENGTH here
    /// is a framing problem, not a paste problem, and maps to `NotAToken`;
    /// `CrcMismatch` stays paste-only. Everything after the length check is
    /// the SAME `validate_wire_bytes` as `parse` steps 3-6, same order,
    /// same error variants.
    pub fn parse_wire(bytes: &[u8], keys: &LicenceKeys) -> Result<Token, LicenceError> {
        let wire: &[u8; WIRE_LEN] = bytes.try_into().map_err(|_| LicenceError::NotAToken)?;
        validate_wire_bytes(wire, keys)
    }

    /// The 94-byte binary form (the P3 relay handshake sends bytes 0..89).
    pub fn to_bytes(&self) -> [u8; TOKEN_LEN] {
        assemble(
            &payload_of(
                self.key_id,
                &self.license_id,
                self.tier,
                self.expires_day,
                self.features_until_day,
            ),
            &self.signature,
        )
    }

    /// The 90-byte wire form (design 4.1): `to_bytes` without the CRC. This
    /// is what the P3 relay handshake carries, hex-encoded.
    pub fn to_wire_bytes(&self) -> [u8; WIRE_LEN] {
        self.to_bytes()[..WIRE_LEN]
            .try_into()
            .expect("TOKEN_LEN == WIRE_LEN + 4")
    }

    /// The `ptx1-…` text form the user pastes and the vault stores.
    pub fn to_text(&self) -> String {
        text_of(&self.to_bytes())
    }
}

/// Steps 3-6 of design 3.2, shared by `Token::parse` (which reaches them
/// after the prefix/base64/length/CRC stages) and `Token::parse_wire`
/// (which reaches them after only a length check — the wire has no CRC).
/// One implementation so the paste path and the relay path cannot drift:
/// key_id lookup, strict verification over the domain-separated payload,
/// tier, date ordering — same order, same error variants.
fn validate_wire_bytes(wire: &[u8; WIRE_LEN], keys: &LicenceKeys) -> Result<Token, LicenceError> {
    // Step 3: key_id is an index into the ring.
    let key_id = wire[0];
    let key = keys.get(key_id).ok_or(LicenceError::UnknownKeyId { key_id })?;

    // Step 4: strict verification over the domain-separated payload.
    let payload: &[u8; PAYLOAD_LEN] = wire[..PAYLOAD_LEN].try_into().expect("length checked");
    let message = signing_message(payload);
    let signature = Signature::from_bytes(
        wire[SIGNATURE_OFFSET..WIRE_LEN]
            .try_into()
            .expect("length checked"),
    );
    verify_signature(key, &message, &signature)?;

    // Step 5: only tier 0x01 exists.
    let tier = wire[17];
    if tier != TIER_PREMIUM {
        return Err(LicenceError::UnknownTier { tier });
    }

    let expires_day = u32::from_le_bytes(wire[18..22].try_into().expect("length checked"));
    let features_until_day = u32::from_le_bytes(wire[22..26].try_into().expect("length checked"));

    // Step 6: no legitimate signer produces expires < features_until; the
    // design maps this to the signature-failure class.
    if expires_day < features_until_day {
        return Err(LicenceError::BadSignature);
    }

    Ok(Token {
        key_id,
        license_id: wire[1..17].try_into().expect("length checked"),
        tier,
        expires_day,
        features_until_day,
        signature: signature.to_bytes(),
    })
}

/// The single verification call site in the crate — `verify_strict`, never
/// `verify`, so non-canonical signatures and weak-key edge cases are
/// rejected rather than accepted under ZIP-215 rules. It exists as its own
/// function so the planted-defect gate
/// (`scripts/licence-planted-defect-gate.sh`) has one obvious line to stub:
/// the gate builds a temp copy with this body replaced by `Ok(())` and
/// asserts the suite then FAILS. If you reformat or rename this line,
/// update the gate's pattern; the gate fails loudly if it cannot find it.
fn verify_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), LicenceError> {
    key.verify_strict(message, signature).map_err(|_| LicenceError::BadSignature)
}

impl fmt::Debug for Token {
    /// Hand-written and redacted: the token is a bearer credential, so
    /// neither the signature nor the license_id may appear in logs (the
    /// vault's tunnel secrets get the same treatment). Day numbers, tier,
    /// and key index are not secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("key_id", &self.key_id)
            .field("license_id", &"<redacted>")
            .field("tier", &self.tier)
            .field("expires_day", &self.expires_day)
            .field("features_until_day", &self.features_until_day)
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// The unlock-time state (design 3.3). Held in memory for the session by
/// the app; feature gates read it, never the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenceState {
    /// No token stored. The premium build with no token behaves exactly
    /// like the free build (3.1).
    Free,
    /// `today_utc <= expires_day`. `days_left` counts the expiry day
    /// itself (3.3 step 5), so it is 1 on the final day.
    Active { days_left: u32 },
    /// The token is still VALID and stays stored -- it carries the
    /// license_id the renewal path needs (3.2 step 8) and `expires_day`
    /// so the vault row can say when Premium ended. It entitles the user
    /// to NOTHING: there is no fallback license (a deliberate decision)
    /// 2026-08-05, recorded in the design preamble -- if they don't
    /// renew, they don't get Premium features at all).
    Lapsed { expires_day: u32 },
}

impl LicenceState {
    /// The whole gating rule: premium features are on while ACTIVE and
    /// off otherwise. LAPSED gates exactly like FREE by deliberate decision
    /// (2026-08-05, design preamble) -- an earlier draft carried a
    /// JetBrains-style fallback keyed on `features_until_day`, and that
    /// rule is dead; the field is reserved in the layout, ignored here.
    pub fn premium_active(&self) -> bool {
        matches!(*self, LicenceState::Active { .. })
    }
}

/// Design 3.3, with the clock injected: given a VERIFIED token (or none)
/// and today's UTC day number, compute the state. `days_left` counts the
/// expiry day itself; the saturating add only matters for the absurd
/// `expires_day == u32::MAX` corner and keeps release and debug builds
/// identical there.
///
/// The 3.3 step-2 rule — re-parse and re-verify at every unlock, treating
/// a verification failure as FREE with a local log — is the caller's job:
/// call `Token::parse` first, then this. This function is pure math over a
/// token that already verified.
pub fn evaluate(token: Option<&Token>, today_utc: u32) -> LicenceState {
    match token {
        None => LicenceState::Free,
        Some(token) if today_utc <= token.expires_day => LicenceState::Active {
            days_left: (token.expires_day - today_utc).saturating_add(1),
        },
        Some(token) => LicenceState::Lapsed {
            expires_day: token.expires_day,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test seed; tests derive keys from bytes, never from an RNG
    /// (workspace rule, and it keeps goldens stable).
    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const WRONG_SEED: [u8; 32] = [0xA5; 32];
    /// Fixed licence id for the golden inputs: bytes 0x10..=0x1f.
    const TEST_LICENSE_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    /// 2026-03-12 UTC — the design's worked example (2.2).
    const TEST_EXPIRES_DAY: u32 = 20524;
    /// The golden token mints with features_until_day == expires_day; the
    /// boundary tests exercise the general case separately.
    const TEST_FEATURES_UNTIL_DAY: u32 = 20524;

    /// The pinned text form of the golden token.
    ///
    /// Pinned 2026-08-05 and INDEPENDENTLY verified before pinning: the
    /// value was decoded in Python, its first 26 bytes matched the
    /// hand-derived payload hex below, its CRC matched zlib.crc32, and the
    /// Ed25519 signature verified against the seed's public key using
    /// python-cryptography — a second implementation, not dalek checking
    /// itself. A failure against this pin means the layout, codec, CRC, or
    /// signing input drifted: fix the code, never blindly re-pin.
    const GOLDEN_TEXT: &str = "ptx1-ABAREhMUFRYXGBkaGxwdHh8BLFAAACxQAABCg-uu0eSh4uU6sUIjt_frV5UkZLVmfxvP0kQTiU-pVeWp8Lo3mQxo823M-NMPkIdm0DRsmnn-CDhD7cVY8gQPAT0UIg";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn test_ring() -> LicenceKeys {
        LicenceKeys::new(vec![test_signing_key().verifying_key()]).expect("one strong key")
    }

    fn golden_token() -> Token {
        Token::mint(&test_signing_key(), 0, TEST_LICENSE_ID, TEST_EXPIRES_DAY)
    }

    /// Full control of every byte, honestly signed — for tokens the public
    /// `mint` rightly refuses to make (reserved tier, inverted date order).
    fn mint_raw(
        key_id: u8,
        license_id: [u8; 16],
        tier: u8,
        expires_day: u32,
        features_until_day: u32,
    ) -> [u8; TOKEN_LEN] {
        let payload = payload_of(key_id, &license_id, tier, expires_day, features_until_day);
        let message = signing_message(&payload);
        let signature = test_signing_key().sign(&message);
        assemble(&payload, &signature.to_bytes())
    }

    /// Test-local hex decode so crypto vectors can be pinned as strings.
    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_signing_path_is_plain_rfc_8032_ed25519() {
        // RFC 8032 section 7.1, TEST 2. Pins that mint uses stock Ed25519
        // over exactly the message it is given — no context, no prehash —
        // so the domain separator in `signing_message` is the ONLY thing
        // between a payload and its signature.
        let seed: [u8; 32] =
            hex_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .try_into()
                .unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            hex_bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        assert_eq!(
            key.sign(&[0x72]).to_bytes().to_vec(),
            hex_bytes(concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ))
        );
    }

    #[test]
    fn the_payload_layout_matches_the_spec_byte_for_byte() {
        // Hand-derived from design 2.2: key_id 0x00 | license_id 0x10..0x1f
        // | tier 0x01 | 20524 as u32 LE (2c 50 00 00), twice.
        let payload = payload_of(0, &TEST_LICENSE_ID, TIER_PREMIUM, 20524, 20524);
        assert_eq!(
            payload.to_vec(),
            hex_bytes("00101112131415161718191a1b1c1d1e1f012c5000002c500000")
        );
        let message = signing_message(&payload);
        assert_eq!(message.len(), 44);
        assert_eq!(&message[..18], b"PATANYX-LICENSE-V1");
        assert_eq!(&message[18..], &payload[..]);
    }

    #[test]
    fn the_golden_token_text_is_pinned_against_layout_drift() {
        let actual = golden_token().to_text();
        assert_eq!(actual.len(), TOKEN_TEXT_LEN);
        assert!(actual.starts_with(TEXT_PREFIX));
        assert_eq!(
            actual, GOLDEN_TEXT,
            "the golden token's text form drifted — layout, codec, CRC, or \
             signing input changed. Fix the code; never re-pin without \
             independently re-verifying (see the comment on GOLDEN_TEXT)."
        );
    }

    #[test]
    fn the_golden_token_parses_back_to_the_exact_fields() {
        let token = Token::parse(GOLDEN_TEXT, &test_ring()).expect("golden parses");
        assert_eq!(token.key_id, 0);
        assert_eq!(token.license_id, TEST_LICENSE_ID);
        assert_eq!(token.tier, TIER_PREMIUM);
        assert_eq!(token.expires_day, TEST_EXPIRES_DAY);
        assert_eq!(token.features_until_day, TEST_FEATURES_UNTIL_DAY);
        assert_eq!(token.to_bytes(), golden_token().to_bytes());
    }

    #[test]
    fn text_and_binary_forms_round_trip() {
        let token = golden_token();
        let parsed = Token::parse(&token.to_text(), &test_ring()).expect("round trip");
        assert_eq!(parsed.to_bytes(), token.to_bytes());
        assert_eq!(parsed.to_text(), token.to_text());
    }

    #[test]
    fn tampering_with_each_of_the_94_bytes_fails_with_the_error_class_for_its_region() {
        let ring = test_ring();
        let original = golden_token().to_bytes();
        for offset in 0..TOKEN_LEN {
            let mut tampered = original;
            tampered[offset] ^= 0x01;
            if offset < CRC_OFFSET {
                // Repair the CRC so the flip reaches the stage that guards
                // this region; otherwise every flip would (correctly) stop
                // at the CRC and the later stages would go untested.
                let repaired = crc32_ieee(&tampered[..CRC_OFFSET]);
                tampered[CRC_OFFSET..].copy_from_slice(&repaired.to_le_bytes());
            }
            let err = Token::parse(&text_of(&tampered), &ring)
                .expect_err("a one-bit tamper must never validate");
            match offset {
                // key_id flips to 1; the ring carries only index 0, so the
                // key-ring stage fires before the signature stage.
                0 => assert!(
                    matches!(err, LicenceError::UnknownKeyId { key_id: 1 }),
                    "offset {offset}: {err:?}"
                ),
                // Payload (1..26) and signature (26..90): strict
                // verification over the domain-separated payload catches
                // both regions.
                1..CRC_OFFSET => assert!(
                    matches!(err, LicenceError::BadSignature),
                    "offset {offset}: {err:?}"
                ),
                // The CRC bytes themselves: only the CRC guards them.
                CRC_OFFSET.. => assert!(
                    matches!(err, LicenceError::CrcMismatch),
                    "offset {offset}: {err:?}"
                ),
            }
        }
    }

    #[test]
    fn a_token_signed_by_the_wrong_key_fails_verification() {
        let wrong_ring =
            LicenceKeys::new(vec![SigningKey::from_bytes(&WRONG_SEED).verifying_key()]).unwrap();
        let err = Token::parse(&golden_token().to_text(), &wrong_ring).expect_err("wrong key");
        assert!(matches!(err, LicenceError::BadSignature));
    }

    #[test]
    fn a_key_id_the_ring_does_not_carry_is_unknown_key_not_bad_signature() {
        let bytes = mint_raw(
            1,
            TEST_LICENSE_ID,
            TIER_PREMIUM,
            TEST_EXPIRES_DAY,
            TEST_FEATURES_UNTIL_DAY,
        );
        let err = Token::parse(&text_of(&bytes), &test_ring()).expect_err("unknown key id");
        assert!(matches!(err, LicenceError::UnknownKeyId { key_id: 1 }));
    }

    #[test]
    fn key_id_is_an_index_into_a_ring_that_only_ever_grows() {
        // Rotation per design 2.5: minting moves to the newest key; old
        // keys keep verifying forever.
        let key_a = SigningKey::from_bytes(&[0x11; 32]);
        let key_b = SigningKey::from_bytes(&[0x22; 32]);
        let ring = LicenceKeys::new(vec![key_a.verifying_key(), key_b.verifying_key()]).unwrap();
        let old = Token::mint(&key_a, 0, TEST_LICENSE_ID, TEST_EXPIRES_DAY);
        let new = Token::mint(&key_b, 1, TEST_LICENSE_ID, TEST_EXPIRES_DAY);
        assert!(Token::parse(&old.to_text(), &ring).is_ok());
        assert!(Token::parse(&new.to_text(), &ring).is_ok());
        // Claiming the other index points verification at the wrong key.
        let mut bytes = new.to_bytes();
        bytes[0] = 0;
        let crc = crc32_ieee(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            Token::parse(&text_of(&bytes), &ring),
            Err(LicenceError::BadSignature)
        ));
    }

    #[test]
    fn a_reserved_tier_byte_is_rejected_even_with_a_valid_signature() {
        let bytes = mint_raw(
            0,
            TEST_LICENSE_ID,
            0x02,
            TEST_EXPIRES_DAY,
            TEST_FEATURES_UNTIL_DAY,
        );
        let err = Token::parse(&text_of(&bytes), &test_ring()).expect_err("reserved tier");
        assert!(matches!(err, LicenceError::UnknownTier { tier: 0x02 }));
    }

    #[test]
    fn the_crc_catches_a_truncated_paste_before_any_crypto_runs() {
        let text = golden_token().to_text();
        // Drop two payload characters: still valid base64url, three bytes
        // short — the length/CRC stage must fire, not key lookup.
        let truncated = &text[..text.len() - 2];
        let err = Token::parse(truncated, &test_ring()).expect_err("truncated paste");
        assert!(matches!(err, LicenceError::CrcMismatch));
    }

    #[test]
    fn a_longer_but_decodable_paste_is_rejected_by_length_before_any_crypto_runs() {
        let oversized = format!("ptx1-{}", base64url::encode(&[0u8; 200]));
        let err = Token::parse(&oversized, &test_ring()).expect_err("oversized paste");
        assert!(matches!(err, LicenceError::CrcMismatch));
    }

    #[test]
    fn validation_stages_run_in_the_spec_order() {
        let ring = test_ring();
        // CRC before key lookup: unknown key id + corrupted CRC => CrcMismatch.
        let mut bytes = mint_raw(
            1,
            TEST_LICENSE_ID,
            TIER_PREMIUM,
            TEST_EXPIRES_DAY,
            TEST_FEATURES_UNTIL_DAY,
        );
        bytes[93] ^= 0xFF;
        assert!(matches!(
            Token::parse(&text_of(&bytes), &ring),
            Err(LicenceError::CrcMismatch)
        ));
        // Key lookup before signature: unknown key id + corrupted
        // signature (CRC repaired) => UnknownKeyId.
        let mut bytes = mint_raw(
            1,
            TEST_LICENSE_ID,
            TIER_PREMIUM,
            TEST_EXPIRES_DAY,
            TEST_FEATURES_UNTIL_DAY,
        );
        bytes[30] ^= 0xFF;
        let crc = crc32_ieee(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            Token::parse(&text_of(&bytes), &ring),
            Err(LicenceError::UnknownKeyId { key_id: 1 })
        ));
        // Signature before tier: reserved tier + corrupted signature (CRC
        // repaired) => BadSignature, not UnknownTier.
        let mut bytes = mint_raw(
            0,
            TEST_LICENSE_ID,
            0x02,
            TEST_EXPIRES_DAY,
            TEST_FEATURES_UNTIL_DAY,
        );
        bytes[40] ^= 0xFF;
        let crc = crc32_ieee(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            Token::parse(&text_of(&bytes), &ring),
            Err(LicenceError::BadSignature)
        ));
    }

    #[test]
    fn expires_before_features_until_is_malformed_and_maps_to_the_signature_class() {
        let bytes = mint_raw(0, TEST_LICENSE_ID, TIER_PREMIUM, 20000, 20001);
        let err = Token::parse(&text_of(&bytes), &test_ring()).expect_err("inverted dates");
        assert!(matches!(err, LicenceError::BadSignature));
    }

    #[test]
    fn mint_writes_the_reserved_field_equal_to_expires_day() {
        // No fallback license exists (decided 2026-08-05), so
        // features_until_day is reserved and mint pins it to expires_day --
        // which is also what keeps every minted token inside the 3.2 step 6
        // layout rule.
        let token = golden_token();
        assert_eq!(token.features_until_day(), token.expires_day());
    }

    #[test]
    fn the_parser_dispatches_on_the_prefix_and_rejects_everything_else() {
        let ring = test_ring();
        let text = golden_token().to_text();
        let payload = &text[TEXT_PREFIX.len()..];
        assert!(matches!(
            Token::parse(&format!("ptx2-{payload}"), &ring),
            Err(LicenceError::NotAToken)
        ));
        assert!(matches!(
            Token::parse(&format!("PTX1-{payload}"), &ring),
            Err(LicenceError::NotAToken)
        ));
        assert!(matches!(Token::parse("", &ring), Err(LicenceError::NotAToken)));
        assert!(matches!(
            Token::parse("hello", &ring),
            Err(LicenceError::NotAToken)
        ));
        // The bare prefix decodes to zero bytes: a length failure, not a
        // prefix failure.
        assert!(matches!(
            Token::parse("ptx1-", &ring),
            Err(LicenceError::CrcMismatch)
        ));
    }

    #[test]
    fn a_multi_megabyte_paste_is_rejected_by_the_length_cap() {
        let huge = "x".repeat(5 * 1024 * 1024);
        assert!(matches!(
            Token::parse(&huge, &test_ring()),
            Err(LicenceError::NotAToken)
        ));
        // The cap must never reject a legitimately wrapped token: even one
        // CRLF after every single character stays well inside it.
        let text = golden_token().to_text();
        let mut wrapped = String::new();
        for c in text.chars() {
            wrapped.push(c);
            wrapped.push_str("\r\n");
        }
        assert!(wrapped.len() <= MAX_PASTE_LEN);
        assert!(Token::parse(&wrapped, &test_ring()).is_ok());
    }

    #[test]
    fn a_whitespace_wrapped_paste_still_parses() {
        let text = golden_token().to_text();
        let mut wrapped = String::from(" \t\r\n");
        for (i, chunk) in text.as_bytes().chunks(16).enumerate() {
            if i > 0 {
                wrapped.push_str("\n \t");
            }
            wrapped.push_str(std::str::from_utf8(chunk).unwrap());
        }
        wrapped.push_str("\r\n\x0c ");
        let parsed = Token::parse(&wrapped, &test_ring()).expect("whitespace-wrapped parses");
        assert_eq!(parsed.to_bytes(), golden_token().to_bytes());
    }

    #[test]
    fn non_ascii_whitespace_is_not_stripped() {
        // Only ASCII whitespace is stripped (spec 2.3); a no-break space
        // inside the payload makes the paste undecodable.
        let text = golden_token().to_text();
        let with_nbsp = format!("{}\u{a0}{}", &text[..10], &text[10..]);
        assert!(matches!(
            Token::parse(&with_nbsp, &test_ring()),
            Err(LicenceError::NotAToken)
        ));
    }

    #[test]
    fn an_expired_token_still_parses_because_expiry_is_a_state_not_an_error() {
        let bytes = mint_raw(0, TEST_LICENSE_ID, TIER_PREMIUM, 19000, 19000);
        let token = Token::parse(&text_of(&bytes), &test_ring()).expect("expired tokens are valid");
        assert_eq!(
            evaluate(Some(&token), 20524),
            LicenceState::Lapsed { expires_day: 19000 }
        );
    }

    #[test]
    fn the_expiry_day_itself_is_active_and_the_next_day_is_lapsed() {
        let token = golden_token();
        assert_eq!(
            evaluate(Some(&token), TEST_EXPIRES_DAY),
            LicenceState::Active { days_left: 1 }
        );
        assert_eq!(
            evaluate(Some(&token), TEST_EXPIRES_DAY - 9),
            LicenceState::Active { days_left: 10 }
        );
        assert_eq!(
            evaluate(Some(&token), TEST_EXPIRES_DAY + 1),
            LicenceState::Lapsed {
                expires_day: TEST_EXPIRES_DAY,
            }
        );
        assert_eq!(evaluate(None, TEST_EXPIRES_DAY), LicenceState::Free);
    }

    #[test]
    fn a_lapsed_licence_gates_exactly_like_no_licence() {
        // The project owner's rule, verbatim intent: if they don't renew, they
        // don't get Premium features AT ALL. No fallback set, no ship-day
        // comparison, nothing.
        let token = golden_token();
        assert!(evaluate(Some(&token), TEST_EXPIRES_DAY).premium_active());
        assert!(!evaluate(Some(&token), TEST_EXPIRES_DAY + 1).premium_active());
        assert!(!evaluate(None, TEST_EXPIRES_DAY).premium_active());
        assert_eq!(
            evaluate(Some(&token), TEST_EXPIRES_DAY + 1).premium_active(),
            evaluate(None, TEST_EXPIRES_DAY + 1).premium_active(),
            "lapsed and free must gate identically"
        );
    }

    #[test]
    fn the_wire_form_is_the_first_90_bytes_and_round_trips() {
        let token = golden_token();
        let wire = token.to_wire_bytes();
        assert_eq!(&wire[..], &token.to_bytes()[..WIRE_LEN]);
        let parsed = Token::parse_wire(&wire, &test_ring()).expect("wire form parses");
        assert_eq!(parsed.to_bytes(), token.to_bytes());
    }

    #[test]
    fn the_wire_form_never_carries_or_consults_the_crc() {
        // Corrupt ONLY the CRC region of the 94-byte form: the paste parser
        // rejects it, and the wire parser is completely unaffected — the
        // CRC is a paste-time concern and does not exist on the wire.
        let mut bytes = golden_token().to_bytes();
        bytes[CRC_OFFSET] ^= 0xFF;
        assert!(matches!(
            Token::parse(&text_of(&bytes), &test_ring()),
            Err(LicenceError::CrcMismatch)
        ));
        assert!(Token::parse_wire(&bytes[..WIRE_LEN], &test_ring()).is_ok());
    }

    #[test]
    fn the_wire_form_must_be_exactly_90_bytes() {
        let bytes = golden_token().to_bytes();
        assert!(matches!(
            Token::parse_wire(&bytes[..WIRE_LEN - 1], &test_ring()),
            Err(LicenceError::NotAToken)
        ));
        // The full 94-byte paste form is rejected on the wire: a wrong
        // length is NotAToken, never CrcMismatch.
        assert!(matches!(
            Token::parse_wire(&bytes[..], &test_ring()),
            Err(LicenceError::NotAToken)
        ));
        assert!(matches!(
            Token::parse_wire(&[], &test_ring()),
            Err(LicenceError::NotAToken)
        ));
    }

    #[test]
    fn tampering_with_each_of_the_90_wire_bytes_fails_with_the_error_class_for_its_region() {
        let ring = test_ring();
        let original = golden_token().to_wire_bytes();
        for offset in 0..WIRE_LEN {
            let mut tampered = original;
            tampered[offset] ^= 0x01;
            // No CRC repair here, unlike the 94-byte matrix: the wire form
            // has no CRC region, so every flip reaches its guarding stage
            // directly.
            let err = Token::parse_wire(&tampered, &ring)
                .expect_err("a one-bit tamper must never validate");
            match offset {
                // key_id flips to 1; the ring carries only index 0.
                0 => assert!(
                    matches!(err, LicenceError::UnknownKeyId { key_id: 1 }),
                    "offset {offset}: {err:?}"
                ),
                // Payload (1..26) and signature (26..90): same classes as
                // `parse`, minus the CRC region, which does not exist here.
                _ => assert!(
                    matches!(err, LicenceError::BadSignature),
                    "offset {offset}: {err:?}"
                ),
            }
        }
    }

    #[test]
    fn parse_and_parse_wire_cannot_disagree() {
        // Both front doors funnel into `validate_wire_bytes`; assert the
        // observable outcome is identical for the same token.
        let ring = test_ring();
        let token = golden_token();
        let via_text = Token::parse(&token.to_text(), &ring).unwrap();
        let via_wire = Token::parse_wire(&token.to_wire_bytes(), &ring).unwrap();
        assert_eq!(via_text.to_bytes(), via_wire.to_bytes());
        assert_eq!(via_text.to_wire_bytes(), via_wire.to_wire_bytes());
    }

    #[test]
    fn debug_redacts_the_bearer_material() {
        let token = golden_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains(&format!("{:?}", TEST_LICENSE_ID)),
            "license_id leaked into Debug: {debug}"
        );
        let bytes = token.to_bytes();
        assert!(
            !debug.contains(&format!("{:?}", &bytes[SIGNATURE_OFFSET..CRC_OFFSET])),
            "signature leaked into Debug: {debug}"
        );
        assert!(!debug.contains(&token.to_text()));
    }
}
