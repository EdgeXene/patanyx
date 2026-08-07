use thiserror::Error;

/// Deliberately coarse: an attacker learning *why* a frame failed to open is a
/// decryption oracle, so everything from a bad tag to a wrong key collapses
/// into `Decrypt`.
///
/// The transport variants below the crypto variants are allowed to be precise
/// because none of them distinguish why a decryption failed: they describe
/// framing, routing, and connection state, which an observer of the connection
/// already knows.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChatError {
    /// An initiation handshake reused an ephemeral public key we have already
    /// accepted from this peer, so it cannot be fresh. A genuine
    /// re-initiation always carries a new ephemeral; a replay necessarily
    /// carries a captured one. The live session is left untouched.
    #[error("replayed handshake")]
    ReplayedHandshake,
    #[error("handshake is malformed")]
    BadHandshake,
    #[error("peer identity does not match the expected contact")]
    PeerMismatch,
    #[error("frame is malformed")]
    BadFrame,
    #[error("message failed to decrypt")]
    Decrypt,
    #[error("message counter went backwards")]
    Replay,
    #[error("message counter exhausted")]
    CounterExhausted,
    #[error("message exceeds the maximum length")]
    TooLong,
    #[error("message is not valid UTF-8 text")]
    NotText,
    #[error("cryptographic operation failed")]
    Crypto,
    // --- transport layer: precision here is safe, see the type-level comment ---
    #[error("protocol version mismatch")]
    VersionMismatch,
    #[error("frame exceeds the wire size limit")]
    OversizedFrame,
    #[error("peer is not currently reachable")]
    PeerOffline,
    #[error("no session exists with this peer")]
    NoSession,
    /// The session was authenticated and then stopped answering liveness
    /// probes. Distinct from `PeerOffline`, which means we never had a route:
    /// this one had a working session that went silent, and the difference is
    /// what the user needs to know.
    #[error("peer stopped answering")]
    PeerUnresponsive,
    /// The caller named one of OUR identities that this transport does not
    /// hold — a revoked contact, or a stale handle from before a removal.
    /// Distinct from `NoSession`, which is about the PEER: conflating them
    /// would tell the UI "they are not connected" when the truth is "that
    /// address of yours no longer exists".
    #[error("no such local identity")]
    UnknownIdentity,
    #[error("the relay refused registration")]
    RegistrationRefused,
    /// The relay enforces Premium tokens and this client presented none
    /// (design 4.4). Distinct from `RegistrationRefused`: the identity
    /// proved itself fine; what is missing is a license.
    #[error("the relay requires a Premium token")]
    TokenRequired,
    /// The relay rejected the presented token. Deliberately one class —
    /// the relay collapses bad-hex, bad-signature, reserved tier, and
    /// inverted dates into it, and the UI copy covers them all.
    #[error("the relay rejected the Premium token as invalid")]
    TokenInvalid,
    /// The token verified but its term has ended by the RELAY's clock.
    #[error("the relay rejected the Premium token as expired")]
    TokenExpired,
    /// The token's key_id is no longer in the relay's accepted set (a key
    /// the project owner dropped server-side, design 2.5).
    #[error("the relay no longer accepts the Premium token's signing key")]
    KeyRejected,
    #[error("invalid relay URL (wss://host[:port]/path expected)")]
    InvalidUrl,
    #[error("connection is closed")]
    Closed,
    #[error("i/o error: {0}")]
    Io(String),
}

impl From<std::io::Error> for ChatError {
    fn from(e: std::io::Error) -> Self {
        ChatError::Io(e.to_string())
    }
}
