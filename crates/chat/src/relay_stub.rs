//! Stand-in for the relay client when the `relay-client` feature is off.
//!
//! This is the DEFAULT build. The browser is mDNS-only: no relay is deployed,
//! none is ever configured, and with the feature off the crate carries no TLS
//! stack at all — no rustls, no ring, no webpki-roots. That is what lets
//! `--features chat` cross-compile to Windows, where ring's build script has no
//! toolchain.
//!
//! `RelayClient` here holds an `Infallible`, so it CANNOT be constructed. Every
//! `Option<RelayClient>` in the transport is therefore provably `None` and the
//! relay branches are dead code the optimiser removes — the transport needs no
//! `#[cfg]` of its own to stay correct. `spawn` deliberately does not exist:
//! the one place that would call it is the only line in the transport that has
//! to know which build this is.

use crate::wire::{ErrorCode, Frame};
use crate::ChatError;

/// Mirrors the real client's event type so the transport's channel and match
/// arms compile unchanged. Nothing ever sends one, which is the point: the
/// variants are unconstructed BY DESIGN in a LAN-only build, not left over.
#[allow(dead_code)]
pub enum RelayEvent {
    Up,
    Down,
    Frame(Frame),
    /// Frames that were still queued when the connection died, and were
    /// dropped rather than carried across the reconnect. The count, not the
    /// frames: the core knows what it had in flight and fails those itself.
    Dropped { count: usize },
    /// Registration refused with a Premium licence code (P3). Mirrored from
    /// the real client so the transport's match compiles unchanged.
    Refused(ErrorCode),
}

/// Uninhabited: there is no relay client in this build.
pub struct RelayClient {
    never: std::convert::Infallible,
}

impl RelayClient {
    pub fn send(&self, _frame: Frame) -> Result<(), ChatError> {
        match self.never {}
    }

    pub fn shutdown(self) {
        match self.never {}
    }
}
