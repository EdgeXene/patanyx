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
//! * A TUNNEL proxy that cannot be expressed is an ERROR, never a fallback to
//!   direct. For the activation call the stakes are higher than for the
//!   updater: a direct call would tell the network "this IP holds this
//!   licence", which is the exact fact the tunnel exists to keep private.
//! * When there is NO tunnel, direct is sanctioned -- but a machine may still
//!   reach the network only through a corporate proxy (Zscaler and the like).
//!   `corporate_proxy()` honors that proxy so activation can REACH EdgeXene
//!   instead of failing `offline` forever. It is safe because activation keeps
//!   the strict Bundled roots: a forwarding proxy passes the real cert through,
//!   a re-signing one is still refused, and the token is never handed over.
//!   This is a reachability aid, so an unparseable value falls through to
//!   direct rather than erroring the way a tunnel misconfig does.
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
/// A CLEAR TOKEN NEVER FALLS BACK. A call that sends the licence token and
/// this install's device id in clear relies on TLS confidentiality alone: a
/// proxy that terminates the connection reads a paying user's bearer token,
/// and no signature saves that, because the secret is in the request. So such
/// a call keeps `Roots::Bundled`. Since 1.1.1 the Premium calls do not send it
/// in clear: their bodies are sealed to the licence server's own key and their
/// answers sealed back (premium_seal.rs), which is what lets them, and only
/// them, use the OS store through `sealed_premium_agent`.
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
    agent_with_roots(timeout, Roots::Bundled, true)
}

/// The add-on CDN agent that also accepts the operating system's roots, so an
/// add-on downloads on a network that re-signs TLS. What it carries is a
/// short-lived download pass for one release, never the Premium token, and
/// every file is checked against the Ed25519-signed index before use; the
/// pass itself arrived sealed (premium_seal.rs).
pub(crate) fn agent_for_accepting_os_roots(host: &str, timeout: Duration) -> Result<ureq::Agent, NetError> {
    agent_for_with_roots(host, timeout, Roots::OperatingSystem)
}

/// No redirects, the user's tunnel when there is one (fail closed), else the
/// machine's proxy for THIS host, so a NO_PROXY rule written for one host never
/// decides another's route.
fn agent_for_with_roots(host: &str, timeout: Duration, roots: Roots) -> Result<ureq::Agent, NetError> {
    let mut builder = ureq::AgentBuilder::new()
        .tls_config(tls_config(roots))
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(timeout)
        .redirects(0)
        .user_agent("patanyx");
    // The same egress rule as `agent_with_roots`: the user's tunnel is the way
    // out, and one that cannot be expressed is an error, never a direct
    // connection; with no tunnel, the machine's proxy for THIS host, else direct.
    if let Some(port) = crate::tunnel_control::engine_proxy_port() {
        match ureq::Proxy::new(format!("socks5://127.0.0.1:{port}")) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => return Err(NetError::ProxyUnavailable(e.to_string())),
        }
    } else if let Some(proxy_url) = proxy_from_env(host, |k| std::env::var(k).ok()).or_else(|| system_proxy(host)) {
        if let Ok(proxy) = ureq::Proxy::new(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    }
    Ok(builder.build())
}

/// The agent for a SEALED Premium call (premium_seal.rs): the operating
/// system's roots and, unless `direct`, the machine's proxy. Its body is
/// sealed to the licence server's own key and its answer sealed back to the
/// call's one-time key, so a network that re-signs TLS (Zscaler) reads only
/// ciphertext; that, and nothing weaker, is why these calls may trust what
/// the machine trusts, so every Premium call works on such a network with
/// nothing to set up. A caller that sends a
/// Premium token or device id in clear must keep `agent`.
pub(crate) fn sealed_premium_agent(timeout: Duration, direct: bool) -> Result<ureq::Agent, NetError> {
    agent_with_roots(timeout, Roots::OperatingSystem, !direct)
}

/// The retry an intercepted network needs, for the signature-protected
/// channels only. A caller reaching for this is asserting that a forged
/// response cannot hurt it; see [`Roots`].
pub(crate) fn agent_accepting_os_roots(timeout: Duration) -> Result<ureq::Agent, NetError> {
    agent_with_roots(timeout, Roots::OperatingSystem, true)
}

fn agent_with_roots(
    timeout: Duration,
    roots: Roots,
    use_corporate_proxy: bool,
) -> Result<ureq::Agent, NetError> {
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
        // The user chose a tunnel. It is the egress, and a tunnel that cannot
        // be expressed is an ERROR rather than a silent direct connection --
        // the fail-closed rule the whole module exists to keep.
        match ureq::Proxy::new(format!("socks5://127.0.0.1:{port}")) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(e) => return Err(NetError::ProxyUnavailable(e.to_string())),
        }
    } else if use_corporate_proxy {
        if let Some(proxy_url) = corporate_proxy() {
        // NO user tunnel, so direct is sanctioned -- but this machine may be on
        // a network whose only way out is a proxy (Zscaler and other corporate
        // egress). Left as a plain direct connection, the request never leaves
        // and activation reports `offline` forever; honoring the machine's own
        // proxy is what lets it REACH EdgeXene.
        //
        // This does NOT weaken the token. With `Roots::Bundled` a proxy that
        // terminates and re-signs TLS is `UnknownIssuer` and refused; with the
        // OS store (the sealed Premium calls) it is accepted but reads only a
        // body sealed to the licence server's own key. Either way the bearer
        // token is never handed to the middle. The proxy learns that this IP
        // spoke to the licence host, which on a managed network it already sees.
        //
        // An unparseable value falls through to direct rather than erroring:
        // unlike the tunnel above, this is a reachability aid, not a privacy
        // choice, and direct is the safe status quo it is trying to improve on.
            if let Ok(proxy) = ureq::Proxy::new(&proxy_url) {
                builder = builder.proxy(proxy);
            }
        }
    }
    Ok(builder.build())
}

/// The proxy this machine would use to reach EdgeXene, or `None` for a direct
/// connection. An explicit environment variable wins over the OS setting, so a
/// deliberate override beats an inherited corporate default.
fn corporate_proxy() -> Option<String> {
    let host = target_host();
    proxy_from_env(&host, |k| std::env::var(k).ok()).or_else(|| system_proxy(&host))
}

/// The host every request in this module is bound for. Both the updater and the
/// activation call talk to the one distribution origin, so the proxy decision
/// (and its NO_PROXY bypass) is made for that host rather than threaded through
/// every caller.
fn target_host() -> String {
    let base = crate::updater::base_url();
    let rest = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    rest.split(['/', ':']).next().unwrap_or(rest).to_ascii_lowercase()
}

/// The proxy named by the standard environment variables, honoring `NO_PROXY`.
///
/// `get` is injected so the parsing is testable without touching the real
/// environment. `HTTPS_PROXY` first because every request here is https;
/// `ALL_PROXY` as the catch-all both curl and reqwest honor. A value with no
/// scheme is assumed to be an HTTP CONNECT proxy, the corporate norm.
fn proxy_from_env(host: &str, get: impl Fn(&str) -> Option<String>) -> Option<String> {
    let no_proxy = get("NO_PROXY").or_else(|| get("no_proxy")).unwrap_or_default();
    if host_matches_no_proxy(host, &no_proxy) {
        return None;
    }
    for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Some(v) = get(key) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(normalize_proxy(v));
            }
        }
    }
    None
}

/// Whether `host` is exempted by a `NO_PROXY` list. `*` bypasses everything; an
/// entry matches the host itself or any subdomain of it, with a leading dot
/// treated the same as none (`.corp` and `corp` both cover `x.corp`).
fn host_matches_no_proxy(host: &str, no_proxy: &str) -> bool {
    for raw in no_proxy.split(',') {
        let entry = raw.trim().trim_start_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" || host == entry || host.ends_with(&format!(".{entry}")) {
            return true;
        }
    }
    false
}

/// Give a bare `host:port` an `http://` scheme so `ureq::Proxy` reads it as an
/// HTTP CONNECT proxy; leave an explicit scheme (http/https/socks) alone.
fn normalize_proxy(v: &str) -> String {
    if v.contains("://") {
        v.to_string()
    } else {
        format!("http://{v}")
    }
}

/// Parse a WinINET `ProxyServer` value for the https entry. It is either a bare
/// `host:port` (one proxy for everything) or a `scheme=host:port;...` list; we
/// want the https proxy, falling back to a bare value.
#[cfg(any(windows, test))]
fn parse_win_proxy_server(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains('=') {
        return Some(normalize_proxy(raw));
    }
    let mut http_fallback = None;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((scheme, addr)) = part.split_once('=') {
            let addr = addr.trim();
            if addr.is_empty() {
                continue;
            }
            match scheme.trim().to_ascii_lowercase().as_str() {
                "https" => return Some(normalize_proxy(addr)),
                "http" => http_fallback.get_or_insert_with(|| normalize_proxy(addr)),
                _ => continue,
            };
        }
    }
    http_fallback
}

/// The machine's configured static proxy on Windows (WinINET), honoring the
/// bypass list. PAC/WPAD auto-config is not resolved here -- a user on a
/// PAC-only network still gets the honest "activate once elsewhere" copy rather
/// than a wrong answer.
#[cfg(windows)]
fn system_proxy(host: &str) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, REG_DWORD,
        REG_VALUE_TYPE,
    };

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    unsafe {
        let mut key = HKEY::default();
        let path = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
        if RegOpenKeyExW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()), None, KEY_READ, &mut key).is_err()
        {
            return None;
        }
        let read_dword = |name: &str| -> Option<u32> {
            let n = wide(name);
            let mut ty = REG_VALUE_TYPE::default();
            let mut buf = 0u32;
            let mut len = std::mem::size_of::<u32>() as u32;
            let ok = RegQueryValueExW(
                key,
                PCWSTR(n.as_ptr()),
                None,
                Some(&mut ty),
                Some(&mut buf as *mut u32 as *mut u8),
                Some(&mut len),
            )
            .is_ok();
            (ok && ty == REG_DWORD).then_some(buf)
        };
        let read_string = |name: &str| -> Option<String> {
            let n = wide(name);
            let mut len = 0u32;
            // First call sizes the value.
            if RegQueryValueExW(key, PCWSTR(n.as_ptr()), None, None, None, Some(&mut len)).is_err()
                || len == 0
            {
                return None;
            }
            let mut bytes = vec![0u8; len as usize];
            if RegQueryValueExW(
                key,
                PCWSTR(n.as_ptr()),
                None,
                None,
                Some(bytes.as_mut_ptr()),
                Some(&mut len),
            )
            .is_err()
            {
                return None;
            }
            let u16s: Vec<u16> = bytes[..len as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&u16s))
        };

        let enabled = read_dword("ProxyEnable").unwrap_or(0) != 0;
        let server = read_string("ProxyServer");
        let override_list = read_string("ProxyOverride").unwrap_or_default();
        let _ = RegCloseKey(key);

        if !enabled {
            return None;
        }
        // WinINET's bypass list uses ';' and its own `<local>` token for
        // dotless hosts; EdgeXene is not dotless, so only the host entries
        // matter. Reuse the NO_PROXY matcher with ';' swapped for ','.
        if host_matches_no_proxy(host, &override_list.replace(';', ",")) {
            return None;
        }
        server.and_then(|s| parse_win_proxy_server(&s))
    }
}

#[cfg(not(windows))]
fn system_proxy(_host: &str) -> Option<String> {
    // Every non-Windows corporate proxy this reaches is expressed through the
    // environment, already handled by `proxy_from_env`.
    None
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

    /// The whole point of the corporate-proxy change: an env-configured proxy
    /// is picked up, https before the generic catch-all, and a bare host:port
    /// becomes an http CONNECT proxy rather than being dropped.
    #[test]
    fn an_env_proxy_is_honored_and_scheme_completed() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("proxy.corp:8080".to_string()),
            _ => None,
        };
        assert_eq!(
            proxy_from_env("patanyx.edgexene.io", env).as_deref(),
            Some("http://proxy.corp:8080"),
            "a bare host:port must become an http CONNECT proxy, not be discarded"
        );

        let with_scheme = |k: &str| (k == "ALL_PROXY").then(|| "socks5://127.0.0.1:1080".to_string());
        assert_eq!(
            proxy_from_env("patanyx.edgexene.io", with_scheme).as_deref(),
            Some("socks5://127.0.0.1:1080"),
            "an explicit scheme must be left alone"
        );

        let https_wins = |k: &str| match k {
            "HTTPS_PROXY" => Some("https-proxy:1".to_string()),
            "ALL_PROXY" => Some("all-proxy:2".to_string()),
            _ => None,
        };
        assert_eq!(
            proxy_from_env("h", https_wins).as_deref(),
            Some("http://https-proxy:1"),
            "HTTPS_PROXY must win over the generic ALL_PROXY for an https request"
        );
    }

    /// NO_PROXY must be able to turn the proxy back off, or an org that exempts
    /// its own hosts from the proxy would have activation forced through one.
    #[test]
    fn no_proxy_exempts_the_host_and_its_domain() {
        let env = |k: &str| match k {
            "HTTPS_PROXY" => Some("proxy.corp:8080".to_string()),
            "NO_PROXY" => Some("localhost,.edgexene.io".to_string()),
            _ => None,
        };
        assert_eq!(
            proxy_from_env("patanyx.edgexene.io", env),
            None,
            "a subdomain of a NO_PROXY entry must bypass the proxy"
        );
        // A host NOT on the list still gets the proxy.
        let env2 = |k: &str| match k {
            "HTTPS_PROXY" => Some("proxy.corp:8080".to_string()),
            "NO_PROXY" => Some("example.com".to_string()),
            _ => None,
        };
        assert!(proxy_from_env("patanyx.edgexene.io", env2).is_some());
        // The wildcard turns everything off.
        let star = |k: &str| match k {
            "HTTPS_PROXY" => Some("proxy.corp:8080".to_string()),
            "NO_PROXY" => Some("*".to_string()),
            _ => None,
        };
        assert_eq!(proxy_from_env("anything", star), None);
    }

    /// The Windows `ProxyServer` value comes in two shapes; the https one wins,
    /// a bare value covers everything, and http is a last resort.
    #[test]
    fn wininet_proxy_server_prefers_the_https_entry() {
        assert_eq!(
            parse_win_proxy_server("127.0.0.1:9000").as_deref(),
            Some("http://127.0.0.1:9000"),
            "a bare value proxies every scheme"
        );
        assert_eq!(
            parse_win_proxy_server("http=a:1;https=b:2;ftp=c:3").as_deref(),
            Some("http://b:2"),
            "the https entry is the one an https request must use"
        );
        assert_eq!(
            parse_win_proxy_server("http=a:1;ftp=c:3").as_deref(),
            Some("http://a:1"),
            "with no https entry, http is the sensible fallback"
        );
        assert_eq!(parse_win_proxy_server("ftp=c:3"), None);
        assert_eq!(parse_win_proxy_server("   "), None);
    }

    // ---- The eMudhra / emSign distrust, October 2026 ----------------------
    //
    // The private keys of eight eMudhra intermediate CAs "were generated with
    // insufficient randomness", which lets anyone forge certificates under
    // them (Chrome Root Program, 2026-10-20), so a certificate chaining
    // through one proves nothing. Two fixes, in two crates, both pinned here
    // by behaviour rather than by version number:
    //
    // * webpki-roots 1.0.10 (RUSTSEC-2026-0381) drops emSign ECC Root CA - G3
    //   from the bundled Mozilla roots.
    // * rustls-webpki 0.103.16 (RUSTSEC-2026-0382) refuses any chain holding
    //   one of the eight public keys, whatever root it ends at. That is what
    //   protects `Roots::OperatingSystem`, whose OS half may still carry the
    //   root on a machine that has not updated.
    //
    // No compromised private key is used or needed: a certificate that merely
    // CARRIES one of the published public keys, issued by a throwaway test CA,
    // is enough, because the key is refused before any signature is checked.

    /// The subject of emSign ECC Root CA - G3 as webpki-roots 1.0.9 carried it
    /// (the Name's contents, without the outer SEQUENCE).
    const EMSIGN_ECC_ROOT_G3_SUBJECT: &[u8] = b"1\x0b0\t\x06\x03U\x04\x06\x13\x02IN1\x130\x11\x06\x03U\x04\x0b\x13\nemSign PKI1%0#\x06\x03U\x04\n\x13\x1ceMudhra Technologies Limited1 0\x1e\x06\x03U\x04\x03\x13\x17emSign ECC Root CA - G3";

    /// One of the eight distrusted public keys (P-384): rustls-webpki 0.103.16,
    /// src/data/distrusted/EMOVTLSCAG3B.spki.der, which holds the
    /// SubjectPublicKeyInfo's contents, wrapped here in its outer SEQUENCE
    /// (30 76) as a certificate carries it.
    const DISTRUSTED_EMSIGN_SPKI_HEX: &str = "3076301006072a8648ce3d020106052b810400220362000473897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac280c5e05638ae7a2acd71c322a8e361cdeb9f69c4302b9dd8d73d1cc6caab2cc0aee4e216ce979dd518a4af4b626e5684cdd658037ed0c854e4cc12f4cf8646d0d";

    fn carries_subject(store: &rustls::RootCertStore, subject: &[u8]) -> bool {
        store.roots.iter().any(|anchor| anchor.subject.as_ref() == subject)
    }

    #[test]
    fn the_bundled_roots_no_longer_carry_emsign_ecc_root_g3() {
        // Control: the check can see the root when it is there.
        let mut planted = rustls::RootCertStore::empty();
        planted.roots.push(rustls::pki_types::TrustAnchor {
            subject: rustls::pki_types::Der::from_slice(EMSIGN_ECC_ROOT_G3_SUBJECT),
            subject_public_key_info: rustls::pki_types::Der::from_slice(&[]),
            name_constraints: None,
        });
        assert!(carries_subject(&planted, EMSIGN_ECC_ROOT_G3_SUBJECT));

        assert!(
            !carries_subject(&root_store(Roots::Bundled), EMSIGN_ECC_ROOT_G3_SUBJECT),
            "the strict store still trusts emSign ECC Root CA - G3; webpki-roots must be >= 1.0.10"
        );
    }

    // A minimal DER writer: just enough X.509 for a test CA, an intermediate
    // and a leaf. Short-form and long-form lengths, nothing else.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend(bytes);
        }
        out.extend_from_slice(body);
        out
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn cn_name(cn: &str) -> Vec<u8> {
        let atv = seq(&[&[0x06, 0x03, 0x55, 0x04, 0x03], &tlv(0x0c, cn.as_bytes())]);
        seq(&[&tlv(0x31, &atv)])
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// A P-256 key the test owns, and its SubjectPublicKeyInfo.
    fn test_key() -> (ring::signature::EcdsaKeyPair, Vec<u8>) {
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let alg = seq(&[
            &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        ]);
        let spki = seq(&[&alg, &tlv(0x03, &[&[0u8][..], key.public_key().as_ref()].concat())]);
        (key, spki)
    }

    /// An X.509 v3 certificate for `spki`, signed by `issuer_key`. A CA gets
    /// basicConstraints cA; a leaf gets a DNS name instead.
    fn cert(serial: u8, issuer: &str, subject: &str, spki: &[u8], ca: bool, issuer_key: &ring::signature::EcdsaKeyPair) -> Vec<u8> {
        let ecdsa_sha256 = seq(&[&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]]);
        let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"270101000000Z")]);
        let extension = if ca {
            let value = seq(&[&[0x01, 0x01, 0xff]]);
            seq(&[&[0x06, 0x03, 0x55, 0x1d, 0x13], &[0x01, 0x01, 0xff], &tlv(0x04, &value)])
        } else {
            let value = seq(&[&tlv(0x82, b"updates.patanyx.test")]);
            seq(&[&[0x06, 0x03, 0x55, 0x1d, 0x11], &tlv(0x04, &value)])
        };
        let tbs = seq(&[
            &[0xa0, 0x03, 0x02, 0x01, 0x02],
            &[0x02, 0x01, serial],
            &ecdsa_sha256,
            &cn_name(issuer),
            &validity,
            &cn_name(subject),
            spki,
            &tlv(0xa3, &seq(&[&extension])),
        ]);
        let signature = issuer_key.sign(&ring::rand::SystemRandom::new(), &tbs).unwrap();
        seq(&[&tbs, &ecdsa_sha256, &tlv(0x03, &[&[0u8][..], signature.as_ref()].concat())])
    }

    /// The strict store plus one throwaway test root, judged by the same
    /// rustls verifier `tls_config` builds from it.
    fn verify(test_root: &[u8], chain: &[Vec<u8>]) -> Result<(), rustls::Error> {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        let mut store = root_store(Roots::Bundled);
        store.add(CertificateDer::from(test_root.to_vec())).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            std::sync::Arc::new(store),
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let intermediates: Vec<CertificateDer<'_>> = chain[1..].iter().map(|c| CertificateDer::from(c.clone())).collect();
        verifier
            .verify_server_cert(
                &CertificateDer::from(chain[0].clone()),
                &intermediates,
                &ServerName::try_from("updates.patanyx.test").unwrap(),
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(1_792_713_600)), // 2026-10-23
            )
            .map(|_| ())
    }

    fn is_distrusted(result: &Result<(), rustls::Error>) -> bool {
        matches!(
            result,
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(e)))
                if format!("{e:?}").contains("CertDistrusted")
        )
    }

    #[test]
    fn a_chain_through_a_distrusted_emsign_key_is_refused() {
        let (root_key, root_spki) = test_key();
        let root = cert(1, "PATANYX Test Root", "PATANYX Test Root", &root_spki, true, &root_key);

        // Controls: the same shapes with keys nobody distrusts verify, so a
        // refusal below is the distrust and not a malformed test chain.
        let (_, leaf_spki) = test_key();
        let leaf = cert(2, "PATANYX Test Root", "leaf", &leaf_spki, false, &root_key);
        assert_eq!(verify(&root, &[leaf]), Ok(()), "control: a plain test leaf must verify");

        let (mid_key, mid_spki) = test_key();
        let mid = cert(3, "PATANYX Test Root", "PATANYX Test CA", &mid_spki, true, &root_key);
        let (_, leaf_spki) = test_key();
        let leaf = cert(4, "PATANYX Test CA", "leaf", &leaf_spki, false, &mid_key);
        assert_eq!(verify(&root, &[leaf, mid]), Ok(()), "control: a test intermediate must verify");

        let distrusted = hex(DISTRUSTED_EMSIGN_SPKI_HEX);

        // A leaf carrying the key, correctly signed by a trusted root: every
        // other check passes, so only the distrust can refuse it.
        let leaf = cert(5, "PATANYX Test Root", "leaf", &distrusted, false, &root_key);
        let result = verify(&root, &[leaf]);
        assert!(is_distrusted(&result), "a certificate holding a distrusted emSign key was not refused as distrusted: {result:?}");

        // The real attack shape: the key as an INTERMEDIATE between a trusted
        // root and a leaf. Nobody here can sign as it, and nobody needs to.
        let mid = cert(6, "PATANYX Test Root", "emSign test intermediate", &distrusted, true, &root_key);
        let (other_key, leaf_spki) = test_key();
        let leaf = cert(7, "emSign test intermediate", "leaf", &leaf_spki, false, &other_key);
        let result = verify(&root, &[leaf, mid]);
        assert!(is_distrusted(&result), "a chain through a distrusted emSign intermediate was not refused as distrusted: {result:?}");
    }
}
