//! The 106-byte activation receipt (`prx1-...`): the server's signed
//! statement that ONE device holds ONE of a licence's activation slots.
//!
//! Why it exists (Phase 4 of the Premium design, decided 2026-08-06 and
//! confirmed 2026-08-16: "max of 5 devices"): a token alone says "this
//! licence is paid for"; the receipt says "and this install is one of the
//! five it runs on". The browser caches the receipt in the vault and
//! re-verifies it OFFLINE at every later unlock, exactly the way it
//! re-verifies the token, so the receipt must be signed by the same
//! compiled-in ring -- an unsigned receipt would make that offline check a
//! no-op that any file editor could satisfy.
//!
//! What it deliberately does NOT carry:
//!
//! * No expiry of its own. The receipt dies with the token's `expires_day`;
//!   a shorter re-check clock would buy only the ability to switch off a
//!   paying device, at the price of a per-device liveness timeline on the
//!   server. `binds` therefore checks licence and device, never a date.
//! * No slot number, no grant count, no IP, nothing about the other
//!   devices. Two receipts for the same licence reveal nothing about each
//!   other beyond the licence id they share.
//!
//! Same discipline as `token.rs`: signer and verifier share `payload_of` /
//! `signing_message` / `assemble`, so there is one place that knows where a
//! field lives; the domain separator is DIFFERENT from the token's and a
//! DIFFERENT LENGTH (21 bytes against 18), so a token signature can never
//! be replayed as a receipt or the reverse, even by length confusion; and
//! `verify_strict` is the only verification call.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::base64url;
use crate::crc32::crc32_ieee;
use crate::error::LicenceError;
use crate::keys::LicenceKeys;
use crate::token::Token;

/// 21 bytes, on purpose not 18 (the token's). `signing_message` asserts it.
const DOMAIN_SEPARATOR: &[u8] = b"PATANYX-ACTIVATION-V1";

/// Binary receipt length: payload 38 + signature 64 + crc 4.
pub const RECEIPT_LEN: usize = 106;

/// Text form length: "prx1-" (5) + 142 base64url chars for 106 bytes.
pub const RECEIPT_TEXT_LEN: usize = 147;

const TEXT_PREFIX: &str = "prx1-";
/// key_id(1) | license_id(16) | device_id(16) | activated_day(u32 LE) |
/// flags(1, reserved, must be 0).
const PAYLOAD_LEN: usize = 38;
const SIGNATURE_OFFSET: usize = PAYLOAD_LEN;
const CRC_OFFSET: usize = PAYLOAD_LEN + 64;
const MESSAGE_LEN: usize = 21 + PAYLOAD_LEN;
/// Same generous O(1) bound as the token's paste path. A receipt is never
/// pasted by a person, but it does arrive over the network, and the
/// response body is not to be trusted with an unbounded decode either.
const MAX_TEXT_LEN: usize = 4096;

fn payload_of(
    key_id: u8,
    license_id: &[u8; 16],
    device_id: &[u8; 16],
    activated_day: u32,
) -> [u8; PAYLOAD_LEN] {
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[0] = key_id;
    payload[1..17].copy_from_slice(license_id);
    payload[17..33].copy_from_slice(device_id);
    payload[33..37].copy_from_slice(&activated_day.to_le_bytes());
    payload[37] = 0; // reserved flags
    payload
}

fn signing_message(payload: &[u8; PAYLOAD_LEN]) -> [u8; MESSAGE_LEN] {
    debug_assert_eq!(DOMAIN_SEPARATOR.len(), 21);
    let mut message = [0u8; MESSAGE_LEN];
    let (domain, rest) = message.split_at_mut(DOMAIN_SEPARATOR.len());
    domain.copy_from_slice(DOMAIN_SEPARATOR);
    rest.copy_from_slice(payload);
    message
}

fn assemble(payload: &[u8; PAYLOAD_LEN], signature: &[u8; 64]) -> [u8; RECEIPT_LEN] {
    let mut bytes = [0u8; RECEIPT_LEN];
    bytes[..PAYLOAD_LEN].copy_from_slice(payload);
    bytes[SIGNATURE_OFFSET..CRC_OFFSET].copy_from_slice(signature);
    let crc = crc32_ieee(&bytes[..CRC_OFFSET]);
    bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

/// A parsed and VERIFIED receipt. As with `Token`, there is no public
/// constructor: holding a `Receipt` means the ring signed it. Verified is
/// not the same as BOUND -- see [`Receipt::binds`], which is the check the
/// gate actually turns on.
pub struct Receipt {
    key_id: u8,
    license_id: [u8; 16],
    /// The random 128-bit per-install identifier the browser minted at
    /// first activation. It is personal data (linkable to a payer through
    /// the licence); never Debug-formatted, never logged.
    device_id: [u8; 16],
    /// UTC day the slot was granted. Informational: the vault row can say
    /// "activated on"; nothing gates on it.
    activated_day: u32,
    signature: [u8; 64],
}

impl Receipt {
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    pub fn license_id(&self) -> [u8; 16] {
        self.license_id
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    pub fn activated_day(&self) -> u32 {
        self.activated_day
    }

    /// Server side: sign a receipt for (licence, device). The server keeps
    /// the slot ledger; this only states what the ledger decided.
    pub fn mint(
        signing_key: &SigningKey,
        key_id: u8,
        license_id: [u8; 16],
        device_id: [u8; 16],
        activated_day: u32,
    ) -> Receipt {
        let payload = payload_of(key_id, &license_id, &device_id, activated_day);
        let signature = signing_key.sign(&signing_message(&payload));
        Receipt {
            key_id,
            license_id,
            device_id,
            activated_day,
            signature: signature.to_bytes(),
        }
    }

    /// Parse and verify the text form. Same order as `Token::parse`:
    /// bound, prefix + base64url, length + CRC (before any cryptography),
    /// key_id lookup, strict signature, reserved byte. The error variants
    /// are the token's, deliberately: the app layer already maps every one
    /// of them, and a receipt failure is never shown to a person verbatim
    /// (it arrives from the server or the vault, not from a paste box).
    pub fn parse(text: &str, keys: &LicenceKeys) -> Result<Receipt, LicenceError> {
        if text.len() > MAX_TEXT_LEN {
            return Err(LicenceError::NotAToken);
        }
        let stripped: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let encoded = stripped
            .strip_prefix(TEXT_PREFIX)
            .ok_or(LicenceError::NotAToken)?;
        let bytes = base64url::decode(encoded).map_err(|_| LicenceError::NotAToken)?;
        if bytes.len() != RECEIPT_LEN {
            return Err(LicenceError::CrcMismatch);
        }
        let stored_crc =
            u32::from_le_bytes(bytes[CRC_OFFSET..].try_into().expect("length checked"));
        if crc32_ieee(&bytes[..CRC_OFFSET]) != stored_crc {
            return Err(LicenceError::CrcMismatch);
        }

        let key_id = bytes[0];
        let key = keys
            .get(key_id)
            .ok_or(LicenceError::UnknownKeyId { key_id })?;
        let payload: &[u8; PAYLOAD_LEN] = bytes[..PAYLOAD_LEN].try_into().expect("length checked");
        let signature = Signature::from_bytes(
            bytes[SIGNATURE_OFFSET..CRC_OFFSET]
                .try_into()
                .expect("length checked"),
        );
        verify_receipt_signature(key, &signing_message(payload), &signature)?;
        // No legitimate signer sets the reserved byte; same class as the
        // token's step-6 inconsistency.
        if payload[37] != 0 {
            return Err(LicenceError::BadSignature);
        }
        Ok(Receipt {
            key_id,
            license_id: payload[1..17].try_into().expect("length checked"),
            device_id: payload[17..33].try_into().expect("length checked"),
            activated_day: u32::from_le_bytes(payload[33..37].try_into().expect("length checked")),
            signature: signature.to_bytes(),
        })
    }

    /// THE binding check, and the line the planted-defect gate stubs: a
    /// verified receipt unlocks Premium only when it names THIS token's
    /// licence AND THIS install's device id. A receipt copied along with a
    /// vault to a second machine verifies perfectly and binds to nothing,
    /// which is what makes "five devices" a fact rather than a fiction.
    /// Constant-time is not required (nothing here is secret from the
    /// caller, who holds all three values), plain equality is fine.
    pub fn binds(&self, token: &Token, device_id: &[u8; 16]) -> bool {
        self.license_id == token.license_id() && self.device_id == *device_id
    }

    pub fn to_bytes(&self) -> [u8; RECEIPT_LEN] {
        assemble(
            &payload_of(
                self.key_id,
                &self.license_id,
                &self.device_id,
                self.activated_day,
            ),
            &self.signature,
        )
    }

    /// The `prx1-...` text form the server returns and the vault stores.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(RECEIPT_TEXT_LEN);
        out.push_str(TEXT_PREFIX);
        out.push_str(&base64url::encode(&self.to_bytes()));
        debug_assert_eq!(out.len(), RECEIPT_TEXT_LEN);
        out
    }
}

/// The receipt's single verification call site: `verify_strict`, never
/// `verify`, for the reasons on `token::verify_signature`. Its own function
/// so `scripts/licence-planted-defect-gate.sh` has one obvious line to stub.
fn verify_receipt_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), LicenceError> {
    key.verify_strict(message, signature)
        .map_err(|_| LicenceError::BadSignature)
}

impl fmt::Debug for Receipt {
    /// Redacted: the device id is a per-install identifier linkable to a
    /// payer, and the licence id is bearer material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receipt")
            .field("key_id", &self.key_id)
            .field("license_id", &"<redacted>")
            .field("device_id", &"<redacted>")
            .field("activated_day", &self.activated_day)
            .field("signature", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const WRONG_SEED: [u8; 32] = [0xA5; 32];
    const TEST_LICENSE_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const TEST_DEVICE_ID: [u8; 16] = [
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
        0xdf,
    ];
    const OTHER_DEVICE_ID: [u8; 16] = [0x77; 16];
    /// 2026-03-12 UTC, the token golden's day, reused for the receipt.
    const TEST_ACTIVATED_DAY: u32 = 20524;

    /// Pinned 2026-08-17 from this implementation and INDEPENDENTLY
    /// re-derived in Python before pinning (payload hex hand-assembled,
    /// CRC via zlib.crc32, signature verified with python-cryptography
    /// against the seed's public key over b"PATANYX-ACTIVATION-V1" || payload).
    /// A failure here means the layout, codec, CRC or signing input drifted:
    /// fix the code, never blindly re-pin.
    const GOLDEN_TEXT: &str = "prx1-ABAREhMUFRYXGBkaGxwdHh_Q0dLT1NXW19jZ2tvc3d7fLFAAAAAj27ErvZJua4ev0hz3ADZN-hWq_ZOhMS_uWWA7v_woQo7ABo3nD78F_pZOEZ2Aewdl-q2tmz7gPdpExPb8K8oF3GC-cA";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn test_ring() -> LicenceKeys {
        LicenceKeys::new(vec![test_signing_key().verifying_key()]).expect("one strong key")
    }

    fn golden_receipt() -> Receipt {
        Receipt::mint(
            &test_signing_key(),
            0,
            TEST_LICENSE_ID,
            TEST_DEVICE_ID,
            TEST_ACTIVATED_DAY,
        )
    }

    fn golden_token() -> Token {
        Token::mint(&test_signing_key(), 0, TEST_LICENSE_ID, TEST_ACTIVATED_DAY)
    }

    #[test]
    fn the_golden_receipt_text_is_pinned_against_layout_drift() {
        assert_eq!(golden_receipt().to_text(), GOLDEN_TEXT);
        assert_eq!(GOLDEN_TEXT.len(), RECEIPT_TEXT_LEN);
    }

    #[test]
    fn the_golden_receipt_parses_back_to_the_exact_fields() {
        let r = Receipt::parse(GOLDEN_TEXT, &test_ring()).expect("golden parses");
        assert_eq!(r.key_id(), 0);
        assert_eq!(r.license_id(), TEST_LICENSE_ID);
        assert_eq!(r.device_id(), TEST_DEVICE_ID);
        assert_eq!(r.activated_day(), TEST_ACTIVATED_DAY);
        assert_eq!(r.to_bytes(), golden_receipt().to_bytes());
    }

    #[test]
    fn a_receipt_binds_only_to_its_own_licence_and_device() {
        let r = golden_receipt();
        assert!(r.binds(&golden_token(), &TEST_DEVICE_ID));
        // Same vault copied to another machine: verifies, does not bind.
        assert!(!r.binds(&golden_token(), &OTHER_DEVICE_ID));
        // Another licence's token on the same machine: does not bind.
        let other = Token::mint(&test_signing_key(), 0, [0x42; 16], TEST_ACTIVATED_DAY);
        assert!(!r.binds(&other, &TEST_DEVICE_ID));
    }

    #[test]
    fn whitespace_wrapping_is_tolerated() {
        let wrapped: String = GOLDEN_TEXT
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i % 40 == 0 {
                    vec!['\r', '\n', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        assert!(Receipt::parse(&wrapped, &test_ring()).is_ok());
    }

    #[test]
    fn a_token_is_not_a_receipt_and_a_receipt_is_not_a_token() {
        assert!(matches!(
            Receipt::parse(&golden_token().to_text(), &test_ring()),
            Err(LicenceError::NotAToken)
        ));
        assert!(matches!(
            Token::parse(GOLDEN_TEXT, &test_ring()),
            Err(LicenceError::NotAToken)
        ));
    }

    #[test]
    fn a_receipt_signed_under_the_token_separator_is_refused() {
        // Cross-protocol: sign the receipt payload the way a token is
        // signed (token separator) and present it as a receipt.
        let payload = payload_of(0, &TEST_LICENSE_ID, &TEST_DEVICE_ID, TEST_ACTIVATED_DAY);
        let mut msg = Vec::new();
        msg.extend_from_slice(b"PATANYX-LICENSE-V1");
        msg.extend_from_slice(&payload);
        let sig = test_signing_key().sign(&msg);
        let bytes = assemble(&payload, &sig.to_bytes());
        let text = format!("{}{}", TEXT_PREFIX, base64url::encode(&bytes));
        assert!(matches!(
            Receipt::parse(&text, &test_ring()),
            Err(LicenceError::BadSignature)
        ));
    }

    #[test]
    fn a_flipped_payload_byte_fails_the_crc_before_any_cryptography() {
        let mut bytes = golden_receipt().to_bytes();
        bytes[20] ^= 0x01;
        let text = format!("{}{}", TEXT_PREFIX, base64url::encode(&bytes));
        assert!(matches!(
            Receipt::parse(&text, &test_ring()),
            Err(LicenceError::CrcMismatch)
        ));
    }

    #[test]
    fn a_repaired_crc_over_a_forged_device_id_fails_the_signature() {
        // The attack a file editor would try: change the device id, fix the
        // CRC. Verification, not the checksum, is what refuses it.
        let mut bytes = golden_receipt().to_bytes();
        bytes[17..33].copy_from_slice(&OTHER_DEVICE_ID);
        let crc = crc32_ieee(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        let text = format!("{}{}", TEXT_PREFIX, base64url::encode(&bytes));
        assert!(matches!(
            Receipt::parse(&text, &test_ring()),
            Err(LicenceError::BadSignature)
        ));
    }

    #[test]
    fn a_wrong_key_and_an_unknown_key_id_are_refused() {
        let wrong_ring =
            LicenceKeys::new(vec![SigningKey::from_bytes(&WRONG_SEED).verifying_key()]).unwrap();
        assert!(matches!(
            Receipt::parse(GOLDEN_TEXT, &wrong_ring),
            Err(LicenceError::BadSignature)
        ));
        let r = Receipt::mint(&test_signing_key(), 3, TEST_LICENSE_ID, TEST_DEVICE_ID, 1);
        assert!(matches!(
            Receipt::parse(&r.to_text(), &test_ring()),
            Err(LicenceError::UnknownKeyId { key_id: 3 })
        ));
    }

    #[test]
    fn a_set_reserved_byte_is_refused_even_when_honestly_signed() {
        let mut payload = payload_of(0, &TEST_LICENSE_ID, &TEST_DEVICE_ID, TEST_ACTIVATED_DAY);
        payload[37] = 1;
        let sig = test_signing_key().sign(&signing_message(&payload));
        let bytes = assemble(&payload, &sig.to_bytes());
        let text = format!("{}{}", TEXT_PREFIX, base64url::encode(&bytes));
        assert!(matches!(
            Receipt::parse(&text, &test_ring()),
            Err(LicenceError::BadSignature)
        ));
    }

    #[test]
    fn oversized_and_truncated_inputs_are_refused_cheaply() {
        let huge = format!("{}{}", TEXT_PREFIX, "A".repeat(MAX_TEXT_LEN));
        assert!(matches!(
            Receipt::parse(&huge, &test_ring()),
            Err(LicenceError::NotAToken)
        ));
        // Six characters fewer decodes cleanly to 102 bytes: a length
        // problem, reported as the paste class, not as undecodable text.
        let short = &GOLDEN_TEXT[..GOLDEN_TEXT.len() - 6];
        assert!(matches!(
            Receipt::parse(short, &test_ring()),
            Err(LicenceError::CrcMismatch)
        ));
    }

    #[test]
    fn debug_redacts_the_identifiers_and_signature() {
        let s = format!("{:?}", golden_receipt());
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("d0"));
        assert!(!s.contains("208"));
    }
}
