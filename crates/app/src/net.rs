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
    agent_with_roots(timeout, Roots::Bundled, true)
}

/// The same strict agent, but with the corporate proxy DELIBERATELY skipped:
/// a plain direct connection. It exists for one job -- the fallback the
/// activation caller takes when the configured proxy could not be reached, so a
/// stale proxy setting (a Zscaler entry that lingers in the registry after the
/// laptop moves onto a home network or a phone hotspot) can never strand a
/// connection that would have worked direct. It keeps `Roots::Bundled`, so it
/// is no weaker than the proxy path it backs up, and it is used ONLY when there
/// is no user tunnel -- the tunnel's egress is never bypassed.
pub(crate) fn agent_direct(timeout: Duration) -> Result<ureq::Agent, NetError> {
    agent_with_roots(timeout, Roots::Bundled, false)
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
        // This does NOT weaken the token. Activation keeps `Roots::Bundled`, so
        // the certificate is still judged against the compiled-in Mozilla roots
        // END TO END. A proxy that merely forwards the TLS (CONNECT) passes it
        // through untouched and EdgeXene's real chain validates; a proxy that
        // terminates and re-signs is `UnknownIssuer` and refused, exactly as a
        // direct intercepted connection is today -- the bearer token is never
        // handed to the middle. The proxy learns only that this IP spoke to the
        // licence host, which on a managed network it already sees.
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
}
