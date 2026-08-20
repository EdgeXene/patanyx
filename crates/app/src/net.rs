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
//! * TWO ROOT STORES, and which one a caller gets is a security decision
//!   rather than a convenience. See [`Roots`].
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

/// Which certificate authorities a request will accept.
///
/// WHY THIS IS A CHOICE AND NOT A SETTING. A work laptop behind a corporate
/// proxy sees every TLS connection terminated and re-signed by a CA that
/// lives in the OS store and in no public root list. Judged against the
/// bundled Mozilla roots, that is `UnknownIssuer` and the request fails --
/// which is how a user on such a network came to receive no security updates
/// at all, silently, while the rest of the browser worked (found on a real
/// machine, 2026-08-18).
///
/// Whether that refusal is worth its cost depends entirely on what the
/// request carries, which is why the two channels are split:
///
/// * [`Roots::Bundled`] is the strict default. The compiled-in Mozilla list,
///   and nothing the machine's owner or its administrator has added.
/// * [`Roots::OperatingSystem`] additionally accepts whatever the OS trusts.
///
/// The update and blocklist channels may fall back to the OS store because
/// TLS is not what protects them: the manifest is Ed25519-signed against a
/// key compiled into this binary, and the payload is checked by sha256 and
/// length against that signed manifest. An intercepting proxy therefore
/// cannot forge a manifest, substitute a binary, or downgrade a version
/// (`decide` refuses anything not newer). The most it can do is stop the
/// check happening -- which is exactly what it already does today by making
/// the connection fail.
///
/// THE ACTIVATION CALL MUST NEVER FALL BACK. It sends the licence token and
/// this install's device id, and there TLS confidentiality is the whole
/// protection: a proxy that terminates the connection reads a paying user's
/// bearer token. No signature saves that, because the secret is in the
/// request rather than the response. It is better for activation to fail on
/// an intercepted network and be done at home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Roots {
    /// Compiled-in Mozilla roots only.
    Bundled,
    /// Whatever this machine trusts, including anything its administrator
    /// installed. Only for requests whose integrity rests on a signature.
    OperatingSystem,
}

fn tls_config(roots: Roots) -> std::sync::Arc<rustls::ClientConfig> {
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store(roots))
            .with_no_client_auth(),
    )
}

/// The trust anchors for `roots`. Split out from [`tls_config`] because
/// `ClientConfig` does not expose the store it was built from, and the
/// property worth testing is about the store.
fn root_store(roots: Roots) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    match roots {
        Roots::Bundled => {
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        Roots::OperatingSystem => {
            // Both stores, not the OS one alone: a machine with a damaged or
            // empty trust store would otherwise fail every request on the
            // fallback path too, turning a recoverable interception into a
            // dead end.
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            // `CertificateResult` carries certs AND errors together, and its
            // own `unwrap`/`expect` PANIC on any error. Neither is acceptable
            // here: a machine with one unreadable entry in its store would
            // take the browser down with it. A partial load is exactly what
            // this path wants -- whatever was readable is merged, whatever
            // was not is ignored, and the bundled roots are already in the
            // store either way.
            let found = rustls_native_certs::load_native_certs();
            let (_added, _ignored) = store.add_parsable_certificates(found.certs);
        }
    }
    store
}

/// An agent that honours the tunnel, with the given overall timeout, and
/// accepts ONLY the compiled-in roots. The default, and what the activation
/// call must keep using.
pub(crate) fn agent(timeout: Duration) -> Result<ureq::Agent, NetError> {
    agent_with_roots(timeout, Roots::Bundled)
}

/// The retry an intercepted network needs, for the signature-protected
/// channels only. A caller reaching for this is asserting that a forged
/// response cannot hurt it; see [`Roots`].
pub(crate) fn agent_accepting_os_roots(timeout: Duration) -> Result<ureq::Agent, NetError> {
    agent_with_roots(timeout, Roots::OperatingSystem)
}

fn agent_with_roots(timeout: Duration, roots: Roots) -> Result<ureq::Agent, NetError> {
    let mut builder = ureq::AgentBuilder::new()
        .tls_config(tls_config(roots))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The two stores must actually differ, or the fallback is theatre.
    ///
    /// Both configs are built and their root counts compared. `Bundled` is the
    /// compiled-in Mozilla list; `OperatingSystem` is that list PLUS whatever
    /// the machine trusts, so it can never be smaller. On a build machine with
    /// a stock trust store the two may be close, which is why this asserts the
    /// invariant (never fewer) rather than a number that would differ per host.
    #[test]
    fn the_os_store_never_narrows_the_bundled_one() {
        let bundled = root_store(Roots::Bundled);
        let os = root_store(Roots::OperatingSystem);
        assert!(
            !bundled.is_empty(),
            "the bundled roots are what every ordinary network is judged against"
        );
        assert!(
            os.len() >= bundled.len(),
            "the fallback store dropped roots the strict one had: {} < {}",
            os.len(),
            bundled.len()
        );
    }

    /// A machine whose OS store is unreadable must still verify ordinary
    /// sites. `load_native_certs` returns certs AND errors together and its
    /// own unwrap panics; this pins that the fallback path keeps the bundled
    /// roots regardless of what the OS hands back.
    #[test]
    fn the_fallback_still_carries_the_bundled_roots() {
        let os = root_store(Roots::OperatingSystem);
        assert!(
            os.len() >= webpki_roots::TLS_SERVER_ROOTS.len(),
            "the OS path must ADD to the bundled roots, never replace them"
        );
    }
}
