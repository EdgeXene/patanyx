//! The ONE HTTP client builder for this process's own requests: the update
//! check and download, and (Phase 4) the Premium activation call.
//!
//! WHY ONE. `ureq` never consults the engine's proxy, so a `ureq` request
//! built anywhere else goes DIRECT, outside the tunnel the user chose. The
//! updater had exactly this hole (`resolver_probe.rs` notes it; closed in
//! 552746f), and a second copy of the fix is how the hole reopens in three
//! months. Every caller goes through [`agent`] and inherits the rule:
//!
//! * `engine_proxy_port()` is the engine's own decision: `Some(port)`
//!   whenever the user chose or is running a tunnel (the dead port when the
//!   tunnel is down, so this FAILS CLOSED exactly like a page load), `None`
//!   only when direct is sanctioned.
//! * A proxy that cannot be expressed is an ERROR, never a fallback to
//!   direct. For the activation call the stakes are higher than for the
//!   updater: a direct call would tell the network "this IP holds this
//!   licence", which is the exact fact the tunnel exists to keep private.
//! * No redirects, minimal user agent, explicit timeouts.
//!
//! Compiled only with `updater-net` (the feature that owns the `ureq`
//! dependency); the default build carries no TLS code and the callers say
//! so honestly instead of pretending to fetch.

#![cfg(feature = "updater-net")]

use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an agent could not be built. One class today, kept as an enum so a
/// second reason can be added without changing every caller.
#[derive(Debug)]
pub(crate) enum NetError {
    /// The tunnel is in force and the SOCKS proxy could not be expressed.
    /// Refusing is the only safe answer.
    ProxyUnavailable(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::ProxyUnavailable(why) => write!(
                f,
                "tunnel proxy could not be configured ({why}); refusing a direct connection"
            ),
        }
    }
}

/// An agent that honours the tunnel, with the given overall timeout.
pub(crate) fn agent(timeout: Duration) -> Result<ureq::Agent, NetError> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(timeout)
        // Redirects are NOT followed: a redirect target is outside whatever
        // guarantee the caller has about the origin (a signed manifest, a
        // fixed licence endpoint) and could silently drop TLS.
        .redirects(0)
        // A user agent is data about the user; carry the minimum.
        .user_agent("patanyx");
    if let Some(port) = crate::tunnel_control::engine_proxy_port() {
        match ureq::Proxy::new(format!("socks5://127.0.0.1:{port}")) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => return Err(NetError::ProxyUnavailable(e.to_string())),
        }
    }
    Ok(builder.build())
}
