//! patanyx-chat — anonymous, end-to-end encrypted one-to-one chat.
//!
//! Design constraints this crate exists to enforce (see `docs/chat-design.md`):
//!
//!   * TEXT ONLY. There is no binary payload path, so no decoder ever touches
//!     peer-supplied bytes. Emoji ride along as ordinary UTF-8.
//!   * Identity is a locally generated X25519 keypair whose fingerprint is the
//!     user-visible "hash number". No accounts, no registration, no server
//!     involvement in identity at all.
//!   * One keypair PER CONTACT, so revoking one person breaks only their
//!     address and contacts cannot correlate the user with each other.
//!   * Forward secrecy from per-session ephemeral keys, not a ratchet: nothing
//!     is stored, so there is no history for a ratchet to protect.
//!   * Nothing is persisted here and offline delivery is refused rather than
//!     queued. A store-and-forward queue is the one change that would pull the
//!     project out of "mere conduit" territory; it is a hard constraint.
//!
//! Transport layer (this change):
//!
//!   * `wire` defines the frames once, shared by the client transport and the
//!     relay server so the two cannot drift.
//!   * `transport::Transport` owns the client side: mDNS discovery and direct
//!     TCP links on the LAN, one synchronous WebSocket connection to the
//!     relay, and the session bookkeeping. It is thread-based, not async, and
//!     every channel in it is bounded — overflow closes a connection, it is
//!     never absorbed by a buffer (see the constraint in `transport.rs`).
//!
//! This crate is compiled only into the private build (`--features chat` on the
//! app crate). The published browser does not contain it.

#![forbid(unsafe_code)]

mod envelope;
mod error;
mod identity;
mod session;

pub mod wire;

pub mod limits;
mod discovery;
/// The relay client and its TLS stack exist only under `relay-client`; the
/// default build substitutes an uninhabited stub with the same shape, so the
/// transport compiles identically either way. See relay_stub.rs.
#[cfg(feature = "relay-client")]
mod relay_client;
#[cfg(not(feature = "relay-client"))]
#[path = "relay_stub.rs"]
mod relay_client;
mod transport;

pub use discovery::DiscoveryState;
pub use envelope::{MessageId, MID_LEN};
pub use error::ChatError;
pub use identity::{Fingerprint, Identity, FINGERPRINT_LEN};
pub use session::{Handshake, Pending, Role, Session};
pub use transport::{
    Delivery, RelayConfig, SendFailure, Transport, TransportConfig, TransportEvent,
};
// Discovery's own event type stays crate-private; only the app-facing state
// enum above is re-exported.
pub use wire::ErrorCode;

/// Maximum length of a single message in bytes.
///
/// Enforced at the protocol layer so an oversized frame is refused before it is
/// buffered, and chosen small deliberately: this carries conversation text, and
/// a generous cap would be the beginning of a file-transfer path the design
/// explicitly excludes.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// Validates outgoing text before it is sealed.
///
/// Rejecting here rather than truncating matters: silently shortening a message
/// would show the sender something different from what the recipient reads.
pub fn validate_outgoing(text: &str) -> Result<(), ChatError> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(ChatError::TooLong);
    }
    Ok(())
}

/// Converts a decrypted payload into text.
///
/// Peer-supplied bytes are never assumed to be valid UTF-8, and invalid input
/// is refused rather than replaced with substitution characters, so a peer
/// cannot use lossy conversion to make one string display as another. The
/// caller must insert the result as DOM text, never as HTML: the chat panel
/// lives in the chrome webview, which holds IPC and vault access.
pub fn decode_incoming(bytes: &[u8]) -> Result<String, ChatError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ChatError::TooLong);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ChatError::NotText)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_outgoing_text_is_refused() {
        let big = "a".repeat(MAX_MESSAGE_BYTES + 1);
        assert_eq!(validate_outgoing(&big), Err(ChatError::TooLong));
        assert_eq!(validate_outgoing(&"a".repeat(MAX_MESSAGE_BYTES)), Ok(()));
    }

    #[test]
    fn oversized_incoming_payload_is_refused() {
        let big = vec![b'a'; MAX_MESSAGE_BYTES + 1];
        assert_eq!(decode_incoming(&big), Err(ChatError::TooLong));
    }

    #[test]
    fn invalid_utf8_is_refused_rather_than_mangled() {
        assert_eq!(decode_incoming(&[0xff, 0xfe, 0xfd]), Err(ChatError::NotText));
    }

    #[test]
    fn emoji_decode_intact() {
        let text = "ok 👍🏻 🎉";
        assert_eq!(decode_incoming(text.as_bytes()).unwrap(), text);
    }

    /// End-to-end at the public API: two identities, a handshake, and a message.
    #[test]
    fn full_exchange_through_the_public_api() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();

        // Each side hands the other its hash number out of band; parsing it
        // back is what the UI will do with typed input.
        let bob_hash = bob_id.fingerprint().to_hash_number();
        assert_eq!(
            Fingerprint::parse_hash_number(&bob_hash),
            Some(bob_id.fingerprint())
        );

        let alice = Pending::start(&alice_id, Role::Initiator);
        let bob = Pending::start(&bob_id, Role::Responder);
        let alice_hs = alice.handshake();
        let bob_hs = bob.handshake();

        let mut alice_session = alice
            .complete(&alice_id, &bob_hs, Some(&bob_id.public_bytes()))
            .unwrap();
        let mut bob_session = bob
            .complete(&bob_id, &alice_hs, Some(&alice_id.public_bytes()))
            .unwrap();

        let text = "hey, does this work? 🙂";
        validate_outgoing(text).unwrap();
        let sealed = alice_session.seal(text.as_bytes()).unwrap();
        let received = decode_incoming(&bob_session.open(&sealed).unwrap()).unwrap();
        assert_eq!(received, text);
    }
}
