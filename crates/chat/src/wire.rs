//! The wire protocol, defined ONCE and shared by the client transport and the
//! relay server so the two implementations cannot drift apart.
//!
//! Frames are JSON, one per WebSocket message or one per length-prefixed chunk
//! on a direct LAN TCP stream. JSON is self-describing (a malformed frame
//! fails structurally, not semantically) and the payloads are opaque
//! ciphertext, so there is no parser attack surface worth a smaller encoding.
//! Byte strings are hex: they double JSON's size for payloads but keep the
//! encoding dependency-free and printable for debugging. A payload frame looks
//! like:
//!
//! ```json
//! {"v":1,"t":"payload","to":"f81c…","from":"2a7b…","body":"…"}
//! ```
//!
//! Every frame carries a protocol version (`v`) so a future change is
//! detectable as `ChatError::VersionMismatch` rather than silently misparsed.
//!
//! Size caps are enforced BEFORE buffering: `decode` rejects a frame larger
//! than `MAX_FRAME_BYTES` before parsing, and `read_frame` rejects an
//! oversized length prefix before allocating. There is no binary payload
//! path anywhere: the largest legitimate frame is a `Payload` carrying
//! `MAX_CIPHERTEXT_BYTES` of ciphertext, and anything bigger is refused.

use std::io::{Read, Write};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{ChatError, Fingerprint, Identity, MAX_MESSAGE_BYTES, FINGERPRINT_LEN};

/// Current protocol version. Bump on any incompatible frame change; peers
/// running a different version fail loudly at decode time.
///
/// v2: the handshake body grew from 64 to `HANDSHAKE_LEN` bytes to carry a
/// per-handshake nonce and the version itself, and both are bound into the
/// session KDF. A v1 peer cannot talk to a v2 one, which is correct and
/// costless: nothing has shipped, there is no remote and no tag, so there is
/// no installed base to migrate. The version is ALSO inside the transcript,
/// so a downgrade attempt does not merely fail this check — it derives a
/// different key and opens nothing.
pub const PROTOCOL_VERSION: u16 = 2;

/// Hard cap on one encoded frame, enforced before buffering.
///
/// Sized so the largest legitimate frame (a Payload at the ciphertext cap,
/// hex-encoded, plus envelope, well under 9 KiB) always fits, and small enough
/// that even a queue full of maximum frames is a few hundred KiB, never a
/// memory-exhaustion vector.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Largest ciphertext a Payload frame may carry: an 8-byte counter prefix,
/// `MAX_MESSAGE_BYTES` of plaintext, and a 16-byte Poly1305 tag — exactly what
/// `Session::seal` produces for a maximum-length message.
pub const MAX_CIPHERTEXT_BYTES: usize = 8 + MAX_MESSAGE_BYTES + 16;

/// One frame on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub v: u16,
    #[serde(flatten)]
    pub kind: FrameKind,
}

/// The Premium licence token's hex, wrapped ONLY so `Debug` can redact it:
/// `Frame` and `FrameKind` derive `Debug`, and a plain `String` field would
/// print the complete bearer credential into any error message or log line
/// that formatted a Register frame (found in independent review). On the
/// wire it serializes as the bare string (`#[serde(transparent)]`), so the
/// JSON is unchanged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenHex(pub String);

impl std::fmt::Debug for TokenHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenHex(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FrameKind {
    /// Relay -> client: opens registration. See the proof-of-possession notes
    /// on `registration_challenge`.
    RegisterChallenge {
        #[serde(with = "hex_array")]
        ephemeral_public: [u8; 32],
        #[serde(with = "hex_array")]
        challenge: [u8; 32],
    },
    /// Client -> relay: the static public key (whose fingerprint IS the
    /// address being registered — there is no separately "claimed" address to
    /// disagree with it) and the proof of possession.
    ///
    /// `token` (P3, design 4.1): the Premium licence token as lowercase hex
    /// of the 90 wire bytes (payload + signature; the CRC is paste-time only
    /// and is NOT on the wire). OPTIONAL on purpose: this enum has no
    /// `deny_unknown_fields`, so an old relay ignores the field and an old
    /// client simply omits it, and the protocol version stays unchanged
    /// while the relay's enforcement is config-gated and off. Once an
    /// operator turns RELAY_REQUIRE_TOKEN on, clients older than the P3
    /// release cannot decode the new error codes and will see garbage-frame
    /// reconnect loops — acceptable because no chat build has ever been
    /// published, and enforcement only flips at launch.
    Register {
        #[serde(with = "hex_array")]
        static_public: [u8; 32],
        #[serde(with = "hex_array")]
        mac: [u8; 32],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<TokenHex>,
    },
    /// Relay -> client: registration accepted; routing is now possible.
    Registered,
    /// Routed session-handshake material (exactly the `HANDSHAKE_LEN` bytes
    /// of `Handshake::to_bytes`). `response` distinguishes an answer to our
    /// own initiation from a fresh initiation, which is what makes
    /// simultaneous initiation resolvable (see transport.rs).
    ///
    /// `response` is transport-level and deliberately NOT trusted: it is not
    /// in the KDF, but the role it selects orders the transcript, so flipping
    /// it in transit yields a session that opens nothing rather than one an
    /// attacker steers.
    Handshake {
        #[serde(with = "hex_array")]
        to: [u8; FINGERPRINT_LEN],
        #[serde(with = "hex_array")]
        from: [u8; FINGERPRINT_LEN],
        #[serde(with = "hex_array")]
        body: [u8; crate::session::HANDSHAKE_LEN],
        response: bool,
    },
    /// Routed ciphertext from `Session::seal` plus routing fingerprints. The
    /// relay forwards this unread; nothing in the frame reveals content.
    Payload {
        #[serde(with = "hex_array")]
        to: [u8; FINGERPRINT_LEN],
        #[serde(with = "hex_array")]
        from: [u8; FINGERPRINT_LEN],
        #[serde(with = "hex_vec")]
        body: Vec<u8>,
    },
    /// Relay -> sender: the destination is not connected. Delivery is REFUSED,
    /// never queued; `to` is the unreachable destination.
    Refused {
        #[serde(with = "hex_array")]
        to: [u8; FINGERPRINT_LEN],
    },
    /// Connection-level error. Deliberately coarse and never about payload
    /// contents, which the relay cannot and must not inspect.
    Error { code: ErrorCode },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    VersionMismatch,
    Malformed,
    Oversized,
    Unexpected,
    RegistrationFailed,
    AlreadyRegistered,
    Unavailable,
    // --- Premium licence refusals (P3, design 4.4) ---
    //
    // Sent as the final frame before closing, during registration, so the
    // client's existing `register()` error path surfaces them. Appended at
    // the END so every pre-existing wire name is unchanged. See the note on
    // `FrameKind::Register` for what pre-P3 clients do with these.
    TokenRequired,
    TokenInvalid,
    TokenExpired,
    KeyRejected,
}

impl Frame {
    pub fn new(kind: FrameKind) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind,
        }
    }

    pub fn handshake(
        to: Fingerprint,
        from: Fingerprint,
        body: [u8; crate::session::HANDSHAKE_LEN],
        response: bool,
    ) -> Self {
        Self::new(FrameKind::Handshake {
            to: *to.as_bytes(),
            from: *from.as_bytes(),
            body,
            response,
        })
    }

    pub fn payload(to: Fingerprint, from: Fingerprint, body: Vec<u8>) -> Self {
        Self::new(FrameKind::Payload {
            to: *to.as_bytes(),
            from: *from.as_bytes(),
            body,
        })
    }

    pub fn refused(to: [u8; FINGERPRINT_LEN]) -> Self {
        Self::new(FrameKind::Refused { to })
    }

    pub fn error(code: ErrorCode) -> Self {
        Self::new(FrameKind::Error { code })
    }

    /// The routing destination of a frame, where it has one.
    pub fn destination(&self) -> Option<[u8; FINGERPRINT_LEN]> {
        match &self.kind {
            FrameKind::Handshake { to, .. } | FrameKind::Payload { to, .. } => Some(*to),
            FrameKind::Refused { to } => Some(*to),
            _ => None,
        }
    }

    /// Stamps the sender. The relay calls this with the connection's
    /// authenticated fingerprint so a client cannot route frames under an
    /// address it did not prove.
    pub fn set_from(&mut self, from: [u8; FINGERPRINT_LEN]) {
        match &mut self.kind {
            FrameKind::Handshake { from: f, .. } | FrameKind::Payload { from: f, .. } => *f = from,
            _ => {}
        }
    }
}

/// Serializes one frame to its JSON text form.
pub fn encode(frame: &Frame) -> Result<String, ChatError> {
    if let FrameKind::Payload { body, .. } = &frame.kind {
        if body.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ChatError::OversizedFrame);
        }
    }
    let text = serde_json::to_string(frame).map_err(|_| ChatError::BadFrame)?;
    if text.len() > MAX_FRAME_BYTES {
        return Err(ChatError::OversizedFrame);
    }
    Ok(text)
}

/// Parses a frame. The size cap is checked BEFORE parsing so an oversized
/// frame is rejected before it is buffered.
pub fn decode(bytes: &[u8]) -> Result<Frame, ChatError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ChatError::OversizedFrame);
    }
    let frame: Frame = serde_json::from_slice(bytes).map_err(|_| ChatError::BadFrame)?;
    if frame.v != PROTOCOL_VERSION {
        return Err(ChatError::VersionMismatch);
    }
    if let FrameKind::Payload { body, .. } = &frame.kind {
        if body.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ChatError::OversizedFrame);
        }
    }
    Ok(frame)
}

/// Length-prefixed framing for direct LAN TCP streams: a u32 big-endian length
/// followed by one JSON frame. WebSocket transport does not use this (a
/// WebSocket message is already a frame boundary).
pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), ChatError> {
    let text = encode(frame)?;
    writer
        .write_all(&(text.len() as u32).to_be_bytes())
        .map_err(ChatError::from)?;
    writer.write_all(text.as_bytes()).map_err(ChatError::from)?;
    writer.flush().map_err(ChatError::from)
}

/// Reads one length-prefixed frame. The declared length is checked BEFORE the
/// body buffer is allocated: a hostile length can cost at most the 4 bytes of
/// the prefix.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame, ChatError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(ChatError::from)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(ChatError::OversizedFrame);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(ChatError::from)?;
    decode(&buf)
}

// --- proof of possession at registration -------------------------------------
//
// X25519 is a key-agreement scheme, not a signature scheme, so "sign a
// challenge with your identity key" does not exist. Instead: the relay holds a
// fresh ephemeral keypair per connection and the client proves possession of
// its static secret by completing a DH against the relay's ephemeral public
// key and keying an HMAC with the result over a random challenge. Only the
// holder of the static secret can produce the DH output the relay computes,
// and a fresh ephemeral per connection makes every proof single-use.
//
// What this prevents: registering a fingerprint whose private key you do not
// hold — address squatting and routing hijack.
// What it does NOT prevent: the relay operator learning which fingerprints are
// currently online and which pairs exchange traffic. The relay routes opaque
// ciphertext; metadata visibility to the project owner is accepted and documented,
// not hidden.

/// Relay side: a fresh ephemeral keypair and challenge for one registration.
pub fn registration_challenge() -> (EphemeralSecret, [u8; 32], [u8; 32]) {
    let ephemeral = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let mut challenge = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut challenge);
    (ephemeral, ephemeral_public, challenge)
}

/// Client side: our static public key plus the HMAC proof over the challenge.
pub fn registration_response(
    identity: &Identity,
    relay_ephemeral_public: &[u8; 32],
    challenge: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    // Same StaticSecret reconstruction pattern as session.rs; the raw copy is
    // scoped to this call.
    let secret = StaticSecret::from(identity.secret_bytes());
    let shared = secret.diffie_hellman(&PublicKey::from(*relay_ephemeral_public));
    let mac = pop_mac(shared.as_bytes(), challenge);
    (identity.public_bytes(), mac)
}

/// Relay side: verifies the proof in constant time and returns the
/// now-authenticated fingerprint (derived from the proven key, never from a
/// claimed address string).
pub fn verify_registration(
    relay_ephemeral: EphemeralSecret,
    static_public: &[u8; 32],
    challenge: &[u8; 32],
    mac: &[u8; 32],
) -> Result<[u8; FINGERPRINT_LEN], ChatError> {
    let shared = relay_ephemeral.diffie_hellman(&PublicKey::from(*static_public));
    if !pop_verify(shared.as_bytes(), challenge, mac) {
        return Err(ChatError::RegistrationRefused);
    }
    Ok(*Fingerprint::of(&PublicKey::from(*static_public)).as_bytes())
}

type HmacSha256 = hmac::Hmac<Sha256>;

fn pop_mac(shared_secret: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(shared_secret)
        .expect("HMAC accepts keys of any length");
    mac.update(challenge);
    mac.finalize().into_bytes().into()
}

fn pop_verify(shared_secret: &[u8; 32], challenge: &[u8; 32], expected: &[u8; 32]) -> bool {
    use hmac::Mac;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(shared_secret)
        .expect("HMAC accepts keys of any length");
    mac.update(challenge);
    mac.verify_slice(expected).is_ok() // constant-time comparison
}

// --- hex serde helpers --------------------------------------------------------
// Hex keeps the wire printable and avoids pulling in a base64 crate for a
// handful of byte fields.

/// Decodes one two-byte ASCII hex pair, or `None`.
///
/// Deliberately byte-oriented and total: it accepts any two bytes and cannot
/// panic. `u8::from_str_radix` over a `&str` slice was the previous approach
/// and required the indices to fall on char boundaries, which a hostile peer
/// controls.
fn parse_hex_pair(pair: &[u8]) -> Option<u8> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    match pair {
        [hi, lo] => Some(nibble(*hi)? << 4 | nibble(*lo)?),
        _ => None,
    }
}

mod hex_array {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        ser.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        de: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(de)?;
        // Operate on BYTES, never on string slices.
        //
        // `s.len()` is a byte count, but `&s[i..j]` panics unless both indices
        // land on char boundaries. A peer that sends a multi-byte character
        // padded to exactly N*2 bytes passes the length check and then panics
        // the deserializer — unauthenticated, from any host on the LAN, and on
        // the relay before the proof-of-possession check has run. Indexing the
        // byte slice cannot panic; a non-ASCII byte simply fails to parse as
        // hex and returns an error like any other malformed frame.
        let bytes = s.as_bytes();
        if bytes.len() != N * 2 {
            return Err(D::Error::custom("wrong hex length"));
        }
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = super::parse_hex_pair(&bytes[i * 2..i * 2 + 2])
                .ok_or_else(|| D::Error::custom("invalid hex"))?;
        }
        Ok(out)
    }
}

mod hex_vec {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        ser.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        // Bytes, not string slices — see the note in `hex_array`. A multi-byte
        // character here panicked the reader thread on an unauthenticated
        // frame.
        let bytes = s.as_bytes();
        if bytes.len() % 2 != 0 {
            return Err(D::Error::custom("odd hex length"));
        }
        // Bounded by MAX_FRAME_BYTES on the raw frame, so this allocation can
        // never exceed a few KiB even before the payload cap is applied.
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            out.push(super::parse_hex_pair(pair).ok_or_else(|| D::Error::custom("invalid hex"))?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn two_fps() -> ([u8; FINGERPRINT_LEN], [u8; FINGERPRINT_LEN]) {
        let a = Identity::generate();
        let b = Identity::generate();
        (*a.fingerprint().as_bytes(), *b.fingerprint().as_bytes())
    }

    #[test]
    fn every_frame_kind_round_trips() {
        let (to, from) = two_fps();
        let frames = vec![
            Frame::new(FrameKind::RegisterChallenge {
                ephemeral_public: [1u8; 32],
                challenge: [2u8; 32],
            }),
            Frame::new(FrameKind::Register {
                static_public: [3u8; 32],
                mac: [4u8; 32],
                token: None,
            }),
            Frame::new(FrameKind::Register {
                static_public: [3u8; 32],
                mac: [4u8; 32],
                token: Some(TokenHex("ab".repeat(90))),
            }),
            Frame::new(FrameKind::Registered),
            Frame::new(FrameKind::Handshake {
                to,
                from,
                body: [5u8; crate::session::HANDSHAKE_LEN],
                response: false,
            }),
            Frame::new(FrameKind::Handshake {
                to,
                from,
                body: [6u8; crate::session::HANDSHAKE_LEN],
                response: true,
            }),
            Frame::new(FrameKind::Payload {
                to,
                from,
                body: b"ciphertext bytes".to_vec(),
            }),
            Frame::new(FrameKind::Refused { to }),
            Frame::new(FrameKind::Error {
                code: ErrorCode::RegistrationFailed,
            }),
        ];
        for frame in frames {
            let text = encode(&frame).unwrap();
            assert_eq!(decode(text.as_bytes()).unwrap(), frame);
        }
    }

    #[test]
    fn an_oversized_frame_is_rejected_before_parsing() {
        let big = vec![b' '; MAX_FRAME_BYTES + 1];
        assert_eq!(decode(&big), Err(ChatError::OversizedFrame));
        assert_eq!(decode(b""), Err(ChatError::OversizedFrame));
    }

    #[test]
    fn an_oversized_payload_is_rejected_at_both_ends() {
        let (to, from) = two_fps();
        // Exactly at the cap is fine...
        let ok = Frame::new(FrameKind::Payload {
            to,
            from,
            body: vec![0u8; MAX_CIPHERTEXT_BYTES],
        });
        let text = encode(&ok).unwrap();
        assert!(decode(text.as_bytes()).is_ok());
        // ...one byte over is not, on encode...
        let over = Frame {
            v: PROTOCOL_VERSION,
            kind: FrameKind::Payload {
                to,
                from,
                body: vec![1u8; MAX_CIPHERTEXT_BYTES + 1],
            },
        };
        assert_eq!(encode(&over), Err(ChatError::OversizedFrame));
        // ...and a hand-encoded oversized payload is rejected on decode.
        let json = serde_json::to_string(&over).unwrap();
        assert_eq!(decode(json.as_bytes()), Err(ChatError::OversizedFrame));
    }

    #[test]
    fn a_version_mismatch_is_detectable() {
        let (to, _) = two_fps();
        let frame = Frame {
            v: PROTOCOL_VERSION + 1,
            kind: FrameKind::Refused { to },
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert_eq!(decode(json.as_bytes()), Err(ChatError::VersionMismatch));
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(decode(b"not json"), Err(ChatError::BadFrame));
        assert_eq!(
            decode(br#"{"v":1,"t":"nonsense"}"#),
            Err(ChatError::BadFrame)
        );
        // Invalid hex inside an otherwise well-formed frame.
        assert_eq!(
            decode(br#"{"v":1,"t":"refused","to":"zz"}"#),
            Err(ChatError::BadFrame)
        );
        // Wrong-length hex for a fixed field.
        assert_eq!(
            decode(br#"{"v":1,"t":"refused","to":"aabb"}"#),
            Err(ChatError::BadFrame)
        );
    }

    /// A hex field whose BYTE length is correct but which contains multi-byte
    /// UTF-8 must be refused, not panic.
    ///
    /// This was a remote denial of service: `&s[i*2..i*2+2]` on a `String`
    /// panics when an index falls inside a character, and the length guard
    /// counts bytes, so a padded multi-byte character sailed through it. The
    /// unwind skipped the link-teardown path, so every such frame permanently
    /// leaked a thread, a socket and two routing-table entries — and the same
    /// code decoded the relay's registration reply before any proof of
    /// possession, making it reachable with no key at all.
    #[test]
    fn multibyte_hex_fields_are_refused_and_never_panic() {
        // "€" is 3 bytes; 29 ASCII bytes pad the field to exactly
        // FINGERPRINT_LEN * 2 == 32 bytes, satisfying the length check.
        let field = format!("\u{20ac}{}", "a".repeat(29));
        assert_eq!(field.len(), FINGERPRINT_LEN * 2, "fixture must pass the byte-length guard");
        let frame = format!(r#"{{"v":1,"t":"refused","to":"{field}"}}"#);
        assert_eq!(decode(frame.as_bytes()), Err(ChatError::BadFrame));

        // The variable-length path (payload bodies) had the identical bug.
        let body = format!("\u{20ac}{}", "b".repeat(5));
        assert_eq!(body.len() % 2, 0, "fixture must pass the parity guard");
        let frame = format!(
            r#"{{"v":1,"t":"payload","to":"{to}","from":"{from}","body":"{body}"}}"#,
            to = "aa".repeat(FINGERPRINT_LEN),
            from = "bb".repeat(FINGERPRINT_LEN),
        );
        assert_eq!(decode(frame.as_bytes()), Err(ChatError::BadFrame));

        // And the same frame arriving over the real reader path.
        let mut stream = std::io::Cursor::new({
            let mut buf = (frame.len() as u32).to_be_bytes().to_vec();
            buf.extend_from_slice(frame.as_bytes());
            buf
        });
        assert!(read_frame(&mut stream).is_err());
    }

    /// Every byte value is either parsed or rejected — never a panic.
    #[test]
    fn hex_pair_parsing_is_total() {
        for hi in 0u8..=255 {
            for lo in 0u8..=255 {
                let expected_ok = (hi as char).is_ascii_hexdigit() && (lo as char).is_ascii_hexdigit();
                assert_eq!(parse_hex_pair(&[hi, lo]).is_some(), expected_ok);
            }
        }
        assert_eq!(parse_hex_pair(b"ff"), Some(0xff));
        assert_eq!(parse_hex_pair(b"A0"), Some(0xa0));
        assert_eq!(parse_hex_pair(b""), None);
    }

    /// The compatibility pin for the optional token field: absent on the
    /// wire when None (old clients change nothing), absent in the JSON
    /// still decodes (as None), and unknown fields are ignored (old relays
    /// tolerate a P3 client's token).
    #[test]
    fn the_register_token_field_is_optional_on_the_wire() {
        let without = Frame::new(FrameKind::Register {
            static_public: [3u8; 32],
            mac: [4u8; 32],
            token: None,
        });
        let text = encode(&without).unwrap();
        assert!(
            !text.contains("token"),
            "None must be omitted, not null: {text}"
        );
        assert_eq!(decode(text.as_bytes()).unwrap(), without);

        // A hand-written frame with no token field at all decodes as None.
        let bare = format!(
            r#"{{"v":{PROTOCOL_VERSION},"t":"register","static_public":"{}","mac":"{}"}}"#,
            "03".repeat(32),
            "04".repeat(32)
        );
        assert_eq!(decode(bare.as_bytes()).unwrap(), without);
    }

    /// `Frame` derives `Debug`, so without the redacting `TokenHex` wrapper
    /// any error message or log line that formatted a Register frame would
    /// print the complete bearer credential.
    #[test]
    fn debug_formatting_a_register_frame_never_prints_the_token() {
        let hex = "ab".repeat(90);
        let frame = Frame::new(FrameKind::Register {
            static_public: [3u8; 32],
            mac: [4u8; 32],
            token: Some(TokenHex(hex.clone())),
        });
        let debug = format!("{frame:?}");
        assert!(
            !debug.contains(&hex),
            "the token hex leaked into Debug output: {debug}"
        );
        assert!(debug.contains("<redacted>"));
        // The wire form is unchanged by the wrapper: the bare string.
        let text = encode(&frame).unwrap();
        assert!(text.contains(&format!("\"token\":\"{hex}\"")));
        assert_eq!(decode(text.as_bytes()).unwrap(), frame);
    }

    /// The client maps these strings to ChatError variants and then to user
    /// copy; renaming one would silently break both.
    #[test]
    fn the_token_error_codes_have_stable_wire_names() {
        for (code, name) in [
            (ErrorCode::TokenRequired, "token_required"),
            (ErrorCode::TokenInvalid, "token_invalid"),
            (ErrorCode::TokenExpired, "token_expired"),
            (ErrorCode::KeyRejected, "key_rejected"),
        ] {
            let frame = Frame::error(code);
            let text = encode(&frame).unwrap();
            assert!(
                text.contains(&format!("\"code\":\"{name}\"")),
                "{name} drifted: {text}"
            );
            assert_eq!(decode(text.as_bytes()).unwrap(), frame);
        }
    }

    #[test]
    fn length_prefixed_frames_round_trip() {
        let (to, from) = two_fps();
        let frame = Frame::new(FrameKind::Payload {
            to,
            from,
            body: b"hello lan".to_vec(),
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        assert_eq!(read_frame(&mut cursor).unwrap(), frame);
    }

    #[test]
    fn a_hostile_length_prefix_is_rejected_without_a_body() {
        // The prefix claims more than the cap; the stream ends right there.
        // If read_frame tried to read the body first it would fail with an I/O
        // error instead of the cap error.
        let evil = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        let mut cursor = std::io::Cursor::new(&evil);
        assert_eq!(read_frame(&mut cursor), Err(ChatError::OversizedFrame));
        let zero = 0u32.to_be_bytes();
        let mut cursor = std::io::Cursor::new(&zero);
        assert_eq!(read_frame(&mut cursor), Err(ChatError::OversizedFrame));
    }

    #[test]
    fn proof_of_possession_accepts_the_key_holder() {
        let identity = Identity::generate();
        let (ephemeral, ephemeral_public, challenge) = registration_challenge();
        let (static_public, mac) = registration_response(&identity, &ephemeral_public, &challenge);
        let fp = verify_registration(ephemeral, &static_public, &challenge, &mac)
            .expect("an honest prover is accepted");
        assert_eq!(fp, *identity.fingerprint().as_bytes());
    }

    #[test]
    fn proof_of_possession_rejects_an_impostor() {
        let victim = Identity::generate();
        let impostor = Identity::generate();
        let (ephemeral, ephemeral_public, challenge) = registration_challenge();
        // The impostor can only ever prove the key it actually holds, so it can
        // only register its OWN fingerprint...
        let (impostor_public, impostor_mac) =
            registration_response(&impostor, &ephemeral_public, &challenge);
        let fp = verify_registration(ephemeral, &impostor_public, &challenge, &impostor_mac)
            .unwrap();
        assert_ne!(fp, *victim.fingerprint().as_bytes());
        // ...and a MAC computed without the victim's secret fails outright.
        let (ephemeral2, ephemeral_public2, challenge2) = registration_challenge();
        let (_, wrong_mac) = registration_response(&impostor, &ephemeral_public2, &challenge2);
        assert!(verify_registration(
            ephemeral2,
            &victim.public_bytes(),
            &challenge2,
            &wrong_mac
        )
        .is_err());
    }

    #[test]
    fn a_mac_is_bound_to_its_challenge_and_connection() {
        let identity = Identity::generate();
        let (ephemeral1, ephemeral_public1, challenge1) = registration_challenge();
        let (ephemeral2, _ephemeral_public2, challenge2) = registration_challenge();
        let (static_public, mac1) = registration_response(&identity, &ephemeral_public1, &challenge1);
        // Replayed against a different connection/challenge, the proof is void.
        assert!(verify_registration(ephemeral2, &static_public, &challenge2, &mac1).is_err());
        drop(ephemeral1);
    }

    #[test]
    fn the_wire_cap_always_admits_a_max_length_message() {
        // Guards the relationship between the crypto cap and the wire cap:
        // the largest ciphertext Session::seal can produce must always fit.
        assert_eq!(MAX_CIPHERTEXT_BYTES, 8 + MAX_MESSAGE_BYTES + 16);
        let worst_frame_json = 2 * MAX_CIPHERTEXT_BYTES + 512;
        assert!(worst_frame_json <= MAX_FRAME_BYTES);
    }
}
