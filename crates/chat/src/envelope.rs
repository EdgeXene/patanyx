//! What travels INSIDE the encrypted session.
//!
//! Everything here is sealed by `Session::seal` before it reaches a frame, so
//! the relay sees only ciphertext. That placement is the whole design, not an
//! implementation detail: an acknowledgement carried as a wire frame would be
//! a thing the relay could synthesize, and a delivery report a relay can forge
//! is not evidence of delivery. An acknowledgement that only opens under the
//! peer's session key can only have come from the peer.
//!
//! Two layers of envelope exist and they belong to different crates. This one
//! is the TRANSPORT's: message identity, acknowledgement, liveness. The app's
//! `ChatPayload` (text, tab offers, status) rides inside `Msg.body` and is
//! opaque here — this crate must not learn what a message means, only whether
//! it arrived.
//!
//! Still JSON, still text-only, for the same reason as the wire: a malformed
//! envelope fails structurally, and there is no binary decoder anywhere near
//! peer-supplied bytes.

use serde::{Deserialize, Serialize};

use crate::error::ChatError;

/// Length of a message id. 128 bits from the OS RNG, so the chance of two
/// messages in one session colliding is not worth reasoning about, and it is
/// short enough that the dedup window costs kilobytes rather than megabytes.
pub const MID_LEN: usize = 16;

/// A message id. Minted by the sender, echoed by the acknowledgement, and
/// meaningful only inside the session that produced it (see
/// `Session::session_id`) — nothing about it is a global name.
pub type MessageId = [u8; MID_LEN];

/// Mints a fresh message id from the OS RNG.
///
/// Deliberately not derived from the send counter, which would leak how many
/// messages a session has carried to anyone who later obtained one id. Random
/// ids say nothing.
pub fn new_message_id() -> MessageId {
    let mut id = [0u8; MID_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    id
}

/// One item inside the encrypted session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "e", rename_all = "snake_case")]
pub enum SessionEnvelope {
    /// A message from the user, with the id its acknowledgement will echo.
    /// `body` is the app's own envelope and is never parsed here.
    Msg {
        #[serde(with = "hex_mid")]
        mid: MessageId,
        body: String,
    },
    /// "I decrypted this exact message." Emitted by the RECIPIENT at decrypt
    /// time, which is the only moment anyone can honestly claim delivery to a
    /// device. It says nothing about a human having read it, and there is no
    /// read receipt — that is a deliberate absence, not a missing feature.
    Ack {
        #[serde(with = "hex_mid")]
        mid: MessageId,
    },
    /// Liveness probe, sent only after the line has gone quiet. The nonce
    /// makes a reply attributable to this probe, so a replayed pong cannot
    /// keep a dead session looking alive.
    Ping {
        #[serde(with = "hex_mid")]
        nonce: MessageId,
    },
    /// The answer, echoing the probe's nonce.
    Pong {
        #[serde(with = "hex_mid")]
        nonce: MessageId,
    },
}

impl SessionEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, ChatError> {
        // Serializing these fixed shapes cannot fail; the map_err exists
        // only because serde_json's signature forces the question.
        serde_json::to_vec(self).map_err(|_| ChatError::NotText)
    }

    /// Parses one envelope out of decrypted bytes.
    ///
    /// A peer on a build that knows envelope kinds we do not gets
    /// `ChatError::NotText`, and the caller reports the message as dropped
    /// rather than displaying JSON at the user. That is the honest failure:
    /// this crate cannot render what it cannot name.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChatError> {
        serde_json::from_slice(bytes).map_err(|_| ChatError::NotText)
    }
}

/// Hex for the fixed-width ids, matching `wire.rs`'s treatment of byte
/// strings: printable in a debug dump and dependency-free.
mod hex_mid {
    use super::MID_LEN;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; MID_LEN], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(MID_LEN * 2);
        for byte in value {
            out.push_str(&format!("{byte:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; MID_LEN], D::Error> {
        let text = String::deserialize(d)?;
        // Length is checked in CHARACTERS before any indexing. A byte-indexed
        // slice of a multi-byte string panics, and that exact mistake in the
        // wire hex helpers was an unauthenticated remote panic found by two
        // reviewers independently. Not repeating it here.
        if text.len() != MID_LEN * 2 || !text.is_ascii() {
            return Err(serde::de::Error::custom("bad id length"));
        }
        let mut out = [0u8; MID_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| serde::de::Error::custom("bad id hex"))?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_envelope_kind_round_trips() {
        let mid = new_message_id();
        for envelope in [
            SessionEnvelope::Msg {
                mid,
                body: "hello 🙂".to_string(),
            },
            SessionEnvelope::Ack { mid },
            SessionEnvelope::Ping { nonce: mid },
            SessionEnvelope::Pong { nonce: mid },
        ] {
            let bytes = envelope.encode().unwrap();
            assert_eq!(SessionEnvelope::decode(&bytes).unwrap(), envelope);
        }
    }

    #[test]
    fn ids_are_not_predictable_from_each_other() {
        let a = new_message_id();
        let b = new_message_id();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; MID_LEN]);
    }

    /// The hex helper takes peer-supplied text. A byte-indexed slice of a
    /// multi-byte string panics, and that mistake shipped once already in the
    /// wire helpers as an unauthenticated remote panic.
    #[test]
    fn a_multibyte_id_field_is_refused_without_panicking() {
        for hostile in [
            r#"{"e":"ack","mid":"ααααααααααααααααα"}"#,
            r#"{"e":"ack","mid":"🙂🙂🙂🙂🙂🙂🙂🙂"}"#,
            r#"{"e":"ack","mid":""}"#,
            r#"{"e":"ack","mid":"zz"}"#,
            r#"{"e":"ack","mid":"00112233445566778899aabbccddeeff00"}"#,
        ] {
            assert!(
                SessionEnvelope::decode(hostile.as_bytes()).is_err(),
                "{hostile} must be refused"
            );
        }
    }

    #[test]
    fn an_unknown_envelope_kind_is_refused_not_displayed() {
        let unknown = br#"{"e":"telepathy","mid":"00112233445566778899aabbccddeeff"}"#;
        assert!(matches!(
            SessionEnvelope::decode(unknown),
            Err(ChatError::NotText)
        ));
    }

}
