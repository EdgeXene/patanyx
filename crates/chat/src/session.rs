//! Session establishment and message encryption.
//!
//! Forward secrecy comes from per-session ephemeral keys rather than a
//! Double-Ratchet-style per-message rekey. A ratchet's main benefit is
//! protecting a stored message history, and this product stores none, refuses
//! offline delivery, and is one-to-one only. Each conversation performs a fresh
//! ephemeral-to-ephemeral X25519 exchange and destroys the result when the
//! session ends, so a key recovered later decrypts nothing.
//!
//! The static per-contact identity keys authenticate the exchange; the
//! ephemeral keys provide the secrecy. Both are mixed into the KDF, so an
//! attacker needs to break the ephemeral exchange AND hold the contact's static
//! key to impersonate a peer.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::ChatError;
use crate::identity::Identity;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Domain separator, so keys derived here can never collide with keys derived
/// for any other purpose from the same shared secret.
///
/// v2: the transcript now carries a per-handshake nonce and the protocol
/// version. Bumping the label with the transcript is not decoration — it
/// guarantees that a v1 and a v2 peer cannot accidentally agree on a key
/// from partially-overlapping inputs; they simply fail to open anything.
const KDF_INFO: &[u8] = b"patanyx-chat/session/v2";

/// Bytes of a serialized `Handshake`: ephemeral (32) + identity (32) +
/// nonce (32) + version (2, big-endian).
pub const HANDSHAKE_LEN: usize = 98;

/// Length of the derived session identifier. Not a secret in use — it
/// namespaces message ids within a session — but derived from the session
/// KDF rather than sent in the clear, so neither the relay nor an observer
/// can correlate two sessions by it.
pub const SESSION_ID_LEN: usize = 16;

/// Which side of the exchange this peer is. The two directions get separate
/// keys from the same handshake so a message can never be replayed back at its
/// own sender and still authenticate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

/// The public half of a handshake, sent to the peer.
///
/// The `nonce` is what makes a captured handshake worthless on replay. Both
/// nonces enter the KDF transcript, so a replayed initiation is paired with
/// the victim's FRESH nonce and derives a key that differs from the original
/// session's — a key the replaying attacker cannot compute, because doing so
/// still needs the original initiator's ephemeral secret. Before this, the
/// only defence was a bounded cache of ephemerals seen recently, which an
/// attacker able to drive enough legitimate rekeys could age a captured value
/// out of. That cache remains, now as defence in depth rather than the whole
/// argument.
///
/// The `version` is in here rather than only on the frame envelope so it is
/// covered by the key derivation: a downgrade attempt changes the transcript
/// and the session simply fails to open, instead of two peers negotiating
/// down to whatever an attacker preferred.
#[derive(Clone, Copy)]
pub struct Handshake {
    pub ephemeral_public: [u8; 32],
    pub identity_public: [u8; 32],
    pub nonce: [u8; 32],
    pub version: u16,
}

impl Handshake {
    pub fn to_bytes(self) -> [u8; HANDSHAKE_LEN] {
        let mut out = [0u8; HANDSHAKE_LEN];
        out[..32].copy_from_slice(&self.ephemeral_public);
        out[32..64].copy_from_slice(&self.identity_public);
        out[64..96].copy_from_slice(&self.nonce);
        out[96..].copy_from_slice(&self.version.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChatError> {
        if bytes.len() != HANDSHAKE_LEN {
            return Err(ChatError::BadHandshake);
        }
        let mut ephemeral_public = [0u8; 32];
        let mut identity_public = [0u8; 32];
        let mut nonce = [0u8; 32];
        let mut version = [0u8; 2];
        ephemeral_public.copy_from_slice(&bytes[..32]);
        identity_public.copy_from_slice(&bytes[32..64]);
        nonce.copy_from_slice(&bytes[64..96]);
        version.copy_from_slice(&bytes[96..]);
        Ok(Self {
            ephemeral_public,
            identity_public,
            nonce,
            version: u16::from_be_bytes(version),
        })
    }
}

/// Our half of an in-progress handshake. Consumed by `complete`: an
/// `EphemeralSecret` can only be used once, which is what makes it ephemeral.
pub struct Pending {
    ephemeral: EphemeralSecret,
    handshake: Handshake,
    role: Role,
}

impl Pending {
    /// Begin a session. The returned `Handshake` goes to the peer in the clear;
    /// it carries no secret.
    pub fn start(identity: &Identity, role: Role) -> Self {
        let ephemeral = EphemeralSecret::random_from_rng(rand_core::OsRng);
        // Fresh per handshake, from the OS. This is the freshness the
        // transcript binds; see the note on `Handshake`.
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let handshake = Handshake {
            ephemeral_public: PublicKey::from(&ephemeral).to_bytes(),
            identity_public: identity.public_bytes(),
            nonce,
            version: crate::wire::PROTOCOL_VERSION,
        };
        Self {
            ephemeral,
            handshake,
            role,
        }
    }

    pub fn handshake(&self) -> Handshake {
        self.handshake
    }

    /// Finish the exchange against the peer's handshake.
    ///
    /// `expected_peer` is the contact's known static key. Passing it is what
    /// turns an anonymous exchange into an authenticated one, and it is the
    /// step that makes a relay unable to impersonate a contact. Callers that
    /// genuinely want an unauthenticated session (a brand-new contact whose
    /// hash number was just typed in) pass None and MUST show the peer's
    /// fingerprint for out-of-band comparison.
    pub fn complete(
        self,
        identity: &Identity,
        peer: &Handshake,
        expected_peer: Option<&[u8; 32]>,
    ) -> Result<Session, ChatError> {
        if let Some(expected) = expected_peer {
            // Constant-time comparison is unnecessary here: the expected value
            // is public key material, not a secret.
            if expected != &peer.identity_public {
                return Err(ChatError::PeerMismatch);
            }
        }
        // Our own handshake reflected back at us. It would otherwise
        // complete: the Diffie-Hellman against ourselves is perfectly
        // computable, so it produces a live-looking session with an attacker
        // in the middle of nothing.
        //
        // EVERY field is checked, not just the identity. Checking the
        // identity alone left a one-field bypass: the peer's static key is
        // PUBLIC — the hash number is derived from it — so an attacker
        // bounces our handshake back with that one field swapped and sails
        // through. Measured. The ephemeral and the nonce are ours alone, and
        // seeing either of them come back is conclusive.
        if peer.identity_public == identity.public_bytes()
            || peer.ephemeral_public == self.handshake.ephemeral_public
            || peer.nonce == self.handshake.nonce
        {
            return Err(ChatError::PeerMismatch);
        }
        // Version is bound into the transcript below, but refusing here gives
        // a NAMED error instead of a session that silently opens nothing.
        if peer.version != crate::wire::PROTOCOL_VERSION {
            return Err(ChatError::VersionMismatch);
        }
        let peer_ephemeral = PublicKey::from(peer.ephemeral_public);
        let peer_identity = PublicKey::from(peer.identity_public);

        // Ephemeral-to-ephemeral gives forward secrecy; static-to-static
        // binds the session to the contact's long-lived key. Both must be
        // present for the derived key to be right, so an attacker with only one
        // of the two learns nothing.
        let ephemeral_shared = self.ephemeral.diffie_hellman(&peer_ephemeral);
        let static_shared = {
            let secret = identity.secret_bytes();
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.diffie_hellman(&peer_identity)
        };
        // Both exchanges must actually contribute. x25519-dalek does not
        // reject low-order points, so a peer sending one — all-zero being
        // the easy case — makes that half of the key material a public
        // constant. With both halves so chosen the whole `ikm` becomes
        // `0^32 || 0^32 || transcript`, which anyone who saw the handshakes
        // can compute: the relay could read the conversation while the UI
        // says end-to-end encrypted. Reachable on the unauthenticated path
        // (`expected_peer = None`) that a contact added by hash number uses.
        //
        // Refusing here rather than in the caller because a non-contributing
        // exchange is not a policy question — there is no configuration in
        // which it is acceptable.
        if !bool::from(ephemeral_shared.was_contributory())
            || !bool::from(static_shared.was_contributory())
        {
            return Err(ChatError::BadHandshake);
        }

        // Transcript binding: both sides hash the same handshake pair in a
        // fixed order, so the two peers derive identical keys while a tampered
        // handshake yields a different key and every message fails to open.
        //
        // Each serialized handshake now carries the sender's fresh nonce and
        // the protocol version, so the transcript covers freshness and version
        // as well as the keys. The ordering is by ROLE, which is what binds
        // the role itself: a peer that took the wrong role orders the pair the
        // other way and derives a different key, so the `response` flag cannot
        // be flipped in transit to any useful effect.
        let (first, second) = match self.role {
            Role::Initiator => (self.handshake.to_bytes(), peer.to_bytes()),
            Role::Responder => (peer.to_bytes(), self.handshake.to_bytes()),
        };

        let mut ikm = Vec::with_capacity(64 + 2 * HANDSHAKE_LEN);
        ikm.extend_from_slice(ephemeral_shared.as_bytes());
        ikm.extend_from_slice(static_shared.as_bytes());
        ikm.extend_from_slice(&first);
        ikm.extend_from_slice(&second);

        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut initiator_key = Zeroizing::new([0u8; KEY_LEN]);
        let mut responder_key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(&[KDF_INFO, b"/i2r"].concat(), initiator_key.as_mut())
            .map_err(|_| ChatError::Crypto)?;
        hkdf.expand(&[KDF_INFO, b"/r2i"].concat(), responder_key.as_mut())
            .map_err(|_| ChatError::Crypto)?;
        // Both sides derive the same id from the same transcript, so it never
        // travels on the wire and cannot be used to correlate sessions.
        let mut session_id = [0u8; SESSION_ID_LEN];
        hkdf.expand(&[KDF_INFO, b"/sid"].concat(), &mut session_id)
            .map_err(|_| ChatError::Crypto)?;
        ikm.zeroize();

        let (send_key, recv_key) = match self.role {
            Role::Initiator => (initiator_key, responder_key),
            Role::Responder => (responder_key, initiator_key),
        };

        Ok(Session {
            sender: XChaCha20Poly1305::new_from_slice(send_key.as_ref())
                .map_err(|_| ChatError::Crypto)?,
            receiver: XChaCha20Poly1305::new_from_slice(recv_key.as_ref())
                .map_err(|_| ChatError::Crypto)?,
            send_counter: 0,
            recv_counter: 0,
            peer_identity: peer.identity_public,
            session_id,
        })
    }
}

/// An established one-to-one session. Dropping it destroys the keys, which is
/// the whole forward-secrecy story: nothing is written to disk and nothing
/// survives the conversation.
pub struct Session {
    sender: XChaCha20Poly1305,
    receiver: XChaCha20Poly1305,
    send_counter: u64,
    recv_counter: u64,
    peer_identity: [u8; 32],
    session_id: [u8; SESSION_ID_LEN],
}

impl Session {
    pub fn peer_identity(&self) -> &[u8; 32] {
        &self.peer_identity
    }

    /// Both peers derive this from the same transcript, and it never travels
    /// on the wire. It namespaces message ids so an id from one session can
    /// carry no meaning in another.
    pub fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Encrypt one message. The nonce is the message counter, never random:
    /// XChaCha20-Poly1305 catastrophically fails on nonce reuse, and a counter
    /// makes reuse structurally impossible within a session where a random
    /// nonce only makes it unlikely.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ChatError> {
        let counter = self.send_counter;
        let nonce = counter_nonce(counter);
        let ciphertext = self
            .sender
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| ChatError::Crypto)?;
        // Only advance after success, so a failed encryption cannot silently
        // burn a counter value and desynchronize the peers.
        self.send_counter = counter.checked_add(1).ok_or(ChatError::CounterExhausted)?;
        let mut framed = Vec::with_capacity(8 + ciphertext.len());
        framed.extend_from_slice(&counter.to_be_bytes());
        framed.extend_from_slice(&ciphertext);
        Ok(framed)
    }

    /// Decrypt one message.
    ///
    /// Counters must strictly increase, which rejects both replays of an
    /// earlier message and re-delivery of the current one. Gaps are permitted
    /// because a dropped message should not wedge the session, but going
    /// backwards never is.
    pub fn open(&mut self, framed: &[u8]) -> Result<Vec<u8>, ChatError> {
        if framed.len() < 8 {
            return Err(ChatError::BadFrame);
        }
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&framed[..8]);
        let counter = u64::from_be_bytes(counter_bytes);
        if counter < self.recv_counter {
            return Err(ChatError::Replay);
        }
        let plaintext = self
            .receiver
            .decrypt(
                &counter_nonce(counter),
                Payload {
                    msg: &framed[8..],
                    aad: &counter_bytes,
                },
            )
            .map_err(|_| ChatError::Decrypt)?;
        self.recv_counter = counter.checked_add(1).ok_or(ChatError::CounterExhausted)?;
        Ok(plaintext)
    }
}

fn counter_nonce(counter: u64) -> XNonce {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    XNonce::from(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a full handshake and returns both sides' sessions.
    fn paired() -> (Session, Session, Identity, Identity) {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let alice = Pending::start(&alice_id, Role::Initiator);
        let bob = Pending::start(&bob_id, Role::Responder);
        let alice_hs = alice.handshake();
        let bob_hs = bob.handshake();
        let alice_session = alice
            .complete(&alice_id, &bob_hs, Some(&bob_id.public_bytes()))
            .expect("alice completes");
        let bob_session = bob
            .complete(&bob_id, &alice_hs, Some(&alice_id.public_bytes()))
            .expect("bob completes");
        (alice_session, bob_session, alice_id, bob_id)
    }

    /// The MITIGATED handshake-replay finding, closed at the crypto layer.
    ///
    /// The transport keeps a bounded cache of ephemerals it has seen, but an
    /// attacker able to drive enough legitimate rekeys ages a captured value
    /// out of it. This test deliberately does NOT involve the transport, so
    /// the cache cannot help: it replays a captured initiation directly into
    /// a fresh responder and asserts the resulting session is useless.
    ///
    /// It works because the responder's own fresh nonce is in the transcript.
    /// The replayed session's keys therefore differ from the original's, and
    /// computing the new ones needs the initiator's ephemeral SECRET, which
    /// the attacker never saw.
    #[test]
    fn a_replayed_initiation_produces_a_session_that_cannot_read_a_word() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();

        // The real session, and the initiation an attacker captures off it.
        let alice = Pending::start(&alice_id, Role::Initiator);
        let captured = alice.handshake();
        let bob_first = Pending::start(&bob_id, Role::Responder);
        let bob_first_hs = bob_first.handshake();
        let mut alice_session = alice
            .complete(&alice_id, &bob_first_hs, Some(&bob_id.public_bytes()))
            .expect("alice completes");
        let mut bob_session = bob_first
            .complete(&bob_id, &captured, Some(&alice_id.public_bytes()))
            .expect("bob completes");
        // Control: the genuine pair works, or the rest proves nothing.
        let genuine = alice_session.seal(b"the real message").unwrap();
        assert_eq!(bob_session.open(&genuine).unwrap(), b"the real message");

        // Later, the attacker replays the captured initiation verbatim. Bob
        // has no memory of it here and completes a session against it.
        let bob_again = Pending::start(&bob_id, Role::Responder);
        let mut replayed = bob_again
            .complete(&bob_id, &captured, Some(&alice_id.public_bytes()))
            .expect("a replayed initiation still COMPLETES; that is expected");

        // ...and it is worthless. Alice's genuine traffic does not open
        // under it, in either direction.
        let from_alice = alice_session.seal(b"a later message").unwrap();
        assert!(
            replayed.open(&from_alice).is_err(),
            "a replayed initiation must not yield a session that can read the real one"
        );
        let from_replay = replayed.seal(b"forged").unwrap();
        assert!(
            bob_session.open(&from_replay).is_err(),
            "nor one whose output the real session accepts"
        );
    }

    /// Our own handshake bounced back at us. It would otherwise complete —
    /// the Diffie-Hellman against oneself is perfectly computable — and
    /// produce a live-looking session with nobody on the other end.
    #[test]
    fn a_reflected_handshake_is_refused() {
        let id = Identity::generate();
        let ours = Pending::start(&id, Role::Initiator);
        let mirror = ours.handshake();
        let responder = Pending::start(&id, Role::Responder);
        assert!(matches!(
            responder.complete(&id, &mirror, None),
            Err(ChatError::PeerMismatch)
        ));
    }

    /// A peer announcing a different protocol version gets a NAMED refusal
    /// rather than a session that silently opens nothing.
    #[test]
    fn a_version_mismatch_is_named_not_silent() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let alice = Pending::start(&alice_id, Role::Initiator);
        let bob = Pending::start(&bob_id, Role::Responder);
        let mut stale = bob.handshake();
        stale.version = crate::wire::PROTOCOL_VERSION.wrapping_sub(1);
        assert!(matches!(
            alice.complete(&alice_id, &stale, Some(&bob_id.public_bytes())),
            Err(ChatError::VersionMismatch)
        ));
    }

    /// Flipping one byte of the peer's nonce in transit must break the
    /// session outright. The negative control is `paired()` itself, which
    /// does the same exchange untampered and round-trips.
    #[test]
    fn a_tampered_nonce_produces_a_session_that_cannot_read_a_word() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let alice = Pending::start(&alice_id, Role::Initiator);
        let bob = Pending::start(&bob_id, Role::Responder);
        let alice_hs = alice.handshake();
        let mut tampered = bob.handshake();
        tampered.nonce[0] ^= 0x01;

        let mut alice_session = alice
            .complete(&alice_id, &tampered, Some(&bob_id.public_bytes()))
            .expect("alice completes against the tampered handshake");
        let mut bob_session = bob
            .complete(&bob_id, &alice_hs, Some(&alice_id.public_bytes()))
            .expect("bob completes");

        let sealed = alice_session.seal(b"hello").unwrap();
        assert!(
            bob_session.open(&sealed).is_err(),
            "one flipped nonce byte must cost the whole session"
        );
    }

    /// Both peers must derive the SAME session id, and two different
    /// sessions must not collide — it is the namespace message ids live in.
    #[test]
    fn both_peers_derive_one_session_id_and_two_sessions_differ() {
        let (alice, bob, _, _) = paired();
        assert_eq!(alice.session_id(), bob.session_id());
        let (other, _, _, _) = paired();
        assert_ne!(
            alice.session_id(),
            other.session_id(),
            "two sessions sharing an id would let one session's message ids mean something in another"
        );
    }

    /// The reflection check must cover EVERY field. Checking only the
    /// identity left a one-field bypass, because the peer's static key is
    /// public information — it is what the hash number is derived from — so
    /// an attacker bounces our own handshake back with that field swapped.
    #[test]
    fn a_reflected_handshake_is_refused_even_with_the_identity_swapped() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let alice = Pending::start(&alice_id, Role::Initiator);
        let mut bounced = alice.handshake();
        // Our own ephemeral and nonce, with the one public field replaced.
        bounced.identity_public = bob_id.public_bytes();
        assert!(
            matches!(
                alice.complete(&alice_id, &bounced, Some(&bob_id.public_bytes())),
                Err(ChatError::PeerMismatch)
            ),
            "our own ephemeral coming back must be conclusive on its own"
        );
    }

    /// A peer's key must actually contribute. x25519-dalek does not reject
    /// low-order points, so without this the shared secret becomes a public
    /// constant and anyone who saw the handshakes — the relay included —
    /// derives the session keys while the UI says end-to-end encrypted.
    #[test]
    fn a_non_contributing_peer_key_is_refused() {
        let alice_id = Identity::generate();
        let alice = Pending::start(&alice_id, Role::Initiator);
        let evil = Handshake {
            ephemeral_public: [0u8; 32],
            identity_public: [0u8; 32],
            nonce: [7u8; 32],
            version: crate::wire::PROTOCOL_VERSION,
        };
        assert!(
            matches!(
                alice.complete(&alice_id, &evil, None),
                Err(ChatError::BadHandshake)
            ),
            "an all-zero peer key must not produce a session"
        );
    }

    /// The control for both refusals above: an ordinary exchange still works.
    /// Without this, a `complete` that rejected everything would pass them.
    #[test]
    fn an_ordinary_exchange_still_completes() {
        let (mut alice, mut bob, _, _) = paired();
        let sealed = alice.seal(b"still works").unwrap();
        assert_eq!(bob.open(&sealed).unwrap(), b"still works");
    }

    #[test]
    fn messages_round_trip_in_both_directions() {
        let (mut alice, mut bob, _, _) = paired();
        let sealed = alice.seal(b"hello").unwrap();
        assert_eq!(bob.open(&sealed).unwrap(), b"hello");
        let sealed = bob.seal(b"hi back").unwrap();
        assert_eq!(alice.open(&sealed).unwrap(), b"hi back");
    }

    #[test]
    fn emoji_survive_round_trip() {
        // Emoji are ordinary UTF-8 in the text payload; this guards the claim
        // that they need no protocol support of their own.
        let (mut alice, mut bob, _, _) = paired();
        let message = "hey 👋🏽 done 🎉 — ok?";
        let sealed = alice.seal(message.as_bytes()).unwrap();
        let opened = bob.open(&sealed).unwrap();
        assert_eq!(String::from_utf8(opened).unwrap(), message);
    }

    #[test]
    fn many_messages_keep_their_order_and_content() {
        let (mut alice, mut bob, _, _) = paired();
        for i in 0..100u32 {
            let msg = format!("message {i}");
            let sealed = alice.seal(msg.as_bytes()).unwrap();
            assert_eq!(bob.open(&sealed).unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn a_replayed_message_is_rejected() {
        let (mut alice, mut bob, _, _) = paired();
        let sealed = alice.seal(b"once").unwrap();
        assert_eq!(bob.open(&sealed).unwrap(), b"once");
        assert!(matches!(bob.open(&sealed), Err(ChatError::Replay)));
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let (mut alice, mut bob, _, _) = paired();
        let mut sealed = alice.seal(b"authentic").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(bob.open(&sealed), Err(ChatError::Decrypt)));
    }

    #[test]
    fn tampered_counter_fails_to_open() {
        // The counter is the nonce and the AAD, so moving it breaks the tag
        // rather than silently decrypting under a different nonce.
        let (mut alice, mut bob, _, _) = paired();
        let mut sealed = alice.seal(b"authentic").unwrap();
        sealed[7] ^= 0x01;
        assert!(matches!(bob.open(&sealed), Err(ChatError::Decrypt)));
    }

    #[test]
    fn a_peer_cannot_open_its_own_message() {
        // Directional keys: without them a relay could echo a message back and
        // have it authenticate as though the peer had sent it.
        let (mut alice, _bob, _, _) = paired();
        let sealed = alice.seal(b"mine").unwrap();
        assert!(matches!(alice.open(&sealed), Err(ChatError::Decrypt)));
    }

    #[test]
    fn a_third_party_session_cannot_read_the_conversation() {
        let (mut alice, _bob, _alice_id, bob_id) = paired();
        let sealed = alice.seal(b"private").unwrap();

        let mallory_id = Identity::generate();
        let mallory = Pending::start(&mallory_id, Role::Responder);
        let alice2_id = Identity::generate();
        let alice2 = Pending::start(&alice2_id, Role::Initiator);
        let mallory_hs = mallory.handshake();
        let mut mallory_session = mallory
            .complete(&mallory_id, &alice2.handshake(), None)
            .unwrap();
        let _ = alice2.complete(&alice2_id, &mallory_hs, None).unwrap();
        let _ = bob_id;

        assert!(mallory_session.open(&sealed).is_err());
    }

    #[test]
    fn an_impersonated_identity_is_refused() {
        // Mallory runs the handshake but Alice expects Bob's static key, which
        // is exactly the check that stops a relay swapping itself in.
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let mallory_id = Identity::generate();
        let alice = Pending::start(&alice_id, Role::Initiator);
        let mallory = Pending::start(&mallory_id, Role::Responder);
        let result = alice.complete(&alice_id, &mallory.handshake(), Some(&bob_id.public_bytes()));
        assert!(matches!(result, Err(ChatError::PeerMismatch)));
    }

    #[test]
    fn two_sessions_between_the_same_pair_use_different_keys() {
        // Forward secrecy between sessions: yesterday's recovered key must not
        // open today's conversation.
        let (mut a1, _b1, alice_id, bob_id) = paired();
        let alice2 = Pending::start(&alice_id, Role::Initiator);
        let bob2 = Pending::start(&bob_id, Role::Responder);
        let alice2_hs = alice2.handshake();
        let _a2 = alice2
            .complete(&alice_id, &bob2.handshake(), Some(&bob_id.public_bytes()))
            .unwrap();
        let mut b2 = bob2
            .complete(&bob_id, &alice2_hs, Some(&alice_id.public_bytes()))
            .unwrap();
        let sealed_in_session_one = a1.seal(b"session one").unwrap();
        assert!(b2.open(&sealed_in_session_one).is_err());
    }

    #[test]
    fn a_short_frame_is_rejected_without_panicking() {
        let (_alice, mut bob, _, _) = paired();
        for len in 0..8 {
            assert!(matches!(bob.open(&vec![0u8; len]), Err(ChatError::BadFrame)));
        }
    }

    #[test]
    fn a_malformed_handshake_is_rejected() {
        assert!(matches!(
            Handshake::from_bytes(&[0u8; HANDSHAKE_LEN - 1]),
            Err(ChatError::BadHandshake)
        ));
        assert!(matches!(
            Handshake::from_bytes(&[0u8; HANDSHAKE_LEN + 1]),
            Err(ChatError::BadHandshake)
        ));
        // The OLD length must now be refused too. A v1 peer's 64-byte
        // handshake is not a short v2 one to be padded; it is a different
        // protocol, and accepting it would be the downgrade the transcript
        // binding exists to prevent.
        assert!(matches!(
            Handshake::from_bytes(&[0u8; 64]),
            Err(ChatError::BadHandshake)
        ));
        assert!(Handshake::from_bytes(&[0u8; HANDSHAKE_LEN]).is_ok());
    }

    #[test]
    fn dropped_messages_do_not_wedge_the_session() {
        let (mut alice, mut bob, _, _) = paired();
        let _dropped = alice.seal(b"lost in transit").unwrap();
        let delivered = alice.seal(b"arrived").unwrap();
        assert_eq!(bob.open(&delivered).unwrap(), b"arrived");
    }
}
