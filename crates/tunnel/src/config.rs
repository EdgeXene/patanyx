//! Parsing a WireGuard `.conf` — the `wg-quick` INI format every provider and
//! every `wg genkey` workflow emits.
//!
//! WHY THIS IS HAND-WRITTEN AND NOT A CRATE. The file contains a PRIVATE KEY,
//! and this is the only place in the browser that reads one. A parser is a
//! small thing to own and a large thing to trust: writing it here keeps the
//! key's path through memory short, visible, and covered by tests in this
//! repository rather than in someone else's.
//!
//! WHAT IS DELIBERATELY REFUSED. `wg-quick` supports directives that run
//! commands (`PostUp`, `PostDown`, `PreUp`, `PreDown`) and directives that
//! rewrite the host's routing table and DNS. A browser must not do either. A
//! config carrying them is not silently stripped -- it is REFUSED, by name, so
//! the user learns their file does something this cannot honour instead of
//! believing a tunnel is doing what the file says.
//!
//! `AllowedIPs` is parsed and reported but does NOT gate traffic here. This is
//! a SOCKS5 proxy in front of one peer, not a routing table: everything the
//! browser sends goes to that peer or nowhere. Storing the field lets the UI
//! say what the config asked for; pretending to enforce it would be a claim
//! with nothing behind it.

use std::fmt;

/// Longest config we will read. A real `.conf` is a few hundred bytes; this is
/// a bound on a file picker pointed at something else entirely.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// A base64 WireGuard key is 32 bytes -> 44 characters with padding.
const KEY_B64_LEN: usize = 44;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The file is larger than any real WireGuard config.
    TooLarge,
    /// A `[Interface]` or `[Peer]` section is missing entirely.
    MissingSection(&'static str),
    /// A required key is absent.
    Missing(&'static str),
    /// Present but not parseable as what it claims to be.
    Malformed(&'static str),
    /// A directive this browser will not honour. Carries the directive name so
    /// the message can say which one rather than "unsupported config".
    Refused(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "that file is too large to be a WireGuard configuration"),
            Self::MissingSection(s) => write!(f, "the configuration has no [{s}] section"),
            Self::Missing(k) => write!(f, "the configuration has no {k}"),
            Self::Malformed(k) => write!(f, "{k} is not in the form WireGuard uses"),
            Self::Refused(d) => write!(
                f,
                "this configuration runs {d}, which a browser will not do. \
                 Remove that line if you want to use the rest of it."
            ),
        }
    }
}

/// Directives that execute commands or rewrite host network state. Refused by
/// name rather than ignored -- see the module header.
const REFUSED_DIRECTIVES: &[&str] = &["postup", "postdown", "preup", "predown", "table", "saveconfig"];

/// A parsed configuration, minus nothing: the private key stays here and is the
/// caller's job to put somewhere safe (the vault) and to zeroize.
///
/// `Debug` is hand-written because the derived one prints `private_key_b64`:
/// logs and panic messages are exactly where key material goes to be forgotten
/// in, and this struct must never put it there. Same rule as the vault's
/// `TunnelSettings` and `Contact`.
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// `[Interface] PrivateKey`, still base64. Decoding is the session's job.
    pub private_key_b64: String,
    /// `[Peer] PublicKey`, base64.
    pub peer_public_key_b64: String,
    /// `[Peer] Endpoint`, verbatim `host:port`. Not resolved here -- resolution
    /// belongs where the socket is opened, and doing it at parse time would
    /// make importing a config a network event.
    pub endpoint: String,
    /// `[Peer] PresharedKey`, if the config carries one.
    pub preshared_key_b64: Option<String>,
    /// `[Peer] PersistentKeepalive`, seconds.
    pub keepalive_secs: Option<u16>,
    /// `[Peer] AllowedIPs`, verbatim, for display only. See the module header
    /// for why this is not enforced.
    pub allowed_ips: Vec<String>,
    /// `[Interface] DNS`, verbatim, for display only. PATANYX does not rewrite
    /// the host resolver; the browser's own encrypted-DNS setting is a separate
    /// control and this field must not be mistaken for it.
    pub dns: Vec<String>,
    /// `[Interface] Address`, verbatim and comma-split exactly like `dns`.
    /// Kept as strings for the same reason: parsing a CIDR is the caller's
    /// job (the stack setup takes the first usable IPv4 one), and a config
    /// whose Address is all junk or all IPv6 is refused AT TUNNEL START with
    /// `TunnelError::NoIpv4Address`, not at import time -- an import is not a
    /// network event and must not become one.
    pub address: Vec<String>,
}

impl fmt::Debug for TunnelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfig")
            .field("private_key_b64", &"<redacted>")
            .field("peer_public_key_b64", &self.peer_public_key_b64)
            .field("endpoint", &self.endpoint)
            .field("preshared_key_b64", &self.preshared_key_b64.as_ref().map(|_| "<redacted>"))
            .field("keepalive_secs", &self.keepalive_secs)
            .field("allowed_ips", &self.allowed_ips)
            .field("dns", &self.dns)
            .field("address", &self.address)
            .finish()
    }
}

fn looks_like_key(value: &str) -> bool {
    value.len() == KEY_B64_LEN
        && value.ends_with('=')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Endpoint validation without resolving anything: a host part that is not
/// empty, and a port that is a real port. `[v6]:port` is accepted by taking the
/// LAST colon, which is also what makes a bare IPv6 address without brackets
/// fail rather than silently parse its last group as a port.
fn valid_endpoint(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() {
        return false;
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return false;
    }
    matches!(port.parse::<u16>(), Ok(p) if p != 0)
}

/// Parse a `wg-quick` configuration.
///
/// Comments (`#` and `;`), blank lines and unknown keys inside a known section
/// are ignored -- WireGuard itself tolerates them and a config that works with
/// `wg-quick` should import here. Unknown SECTIONS are ignored too, but their
/// contents cannot satisfy a required field, so a typo'd `[Peers]` fails with
/// "no [Peer] section" rather than a confusing missing-key error.
pub fn parse(text: &str) -> Result<TunnelConfig, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }

    let mut section = String::new();
    let (mut seen_interface, mut seen_peer) = (false, false);
    let mut private_key = None;
    let mut peer_public = None;
    let mut endpoint = None;
    let mut preshared = None;
    let mut keepalive = None;
    let mut allowed_ips = Vec::new();
    let mut dns = Vec::new();
    let mut address = Vec::new();

    for raw in text.lines() {
        // Strip inline comments before anything else, so `Endpoint = a:1 # x`
        // does not become a host with a comment glued to it.
        let line = raw
            .split(['#', ';'])
            .next()
            .unwrap_or("")
            .trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            seen_interface |= section == "interface";
            seen_peer |= section == "peer";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        // Keys are base64 and END in '=', so splitting on the FIRST '=' and
        // trimming is right, but the value must keep its own padding.
        let value = value.trim();

        if REFUSED_DIRECTIVES.contains(&key.as_str()) {
            return Err(ConfigError::Refused(key));
        }

        match (section.as_str(), key.as_str()) {
            ("interface", "privatekey") => private_key = Some(value.to_string()),
            ("interface", "address") => {
                address = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            ("interface", "dns") => {
                dns = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            ("peer", "publickey") => peer_public = Some(value.to_string()),
            ("peer", "presharedkey") => preshared = Some(value.to_string()),
            ("peer", "endpoint") => endpoint = Some(value.to_string()),
            ("peer", "allowedips") => {
                allowed_ips = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            ("peer", "persistentkeepalive") => {
                keepalive = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| ConfigError::Malformed("PersistentKeepalive"))?,
                );
            }
            _ => {}
        }
    }

    if !seen_interface {
        return Err(ConfigError::MissingSection("Interface"));
    }
    if !seen_peer {
        return Err(ConfigError::MissingSection("Peer"));
    }

    let private_key_b64 = private_key.ok_or(ConfigError::Missing("PrivateKey"))?;
    let peer_public_key_b64 = peer_public.ok_or(ConfigError::Missing("PublicKey"))?;
    let endpoint = endpoint.ok_or(ConfigError::Missing("Endpoint"))?;

    if !looks_like_key(&private_key_b64) {
        return Err(ConfigError::Malformed("PrivateKey"));
    }
    if !looks_like_key(&peer_public_key_b64) {
        return Err(ConfigError::Malformed("PublicKey"));
    }
    if let Some(psk) = &preshared {
        if !looks_like_key(psk) {
            return Err(ConfigError::Malformed("PresharedKey"));
        }
    }
    if !valid_endpoint(&endpoint) {
        return Err(ConfigError::Malformed("Endpoint"));
    }

    Ok(TunnelConfig {
        private_key_b64,
        peer_public_key_b64,
        endpoint,
        preshared_key_b64: preshared,
        keepalive_secs: keepalive,
        allowed_ips,
        dns,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEf0=";
    const KEY_B: &str = "ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHhGgFfE=";

    fn minimal() -> String {
        format!(
            "[Interface]\nPrivateKey = {KEY_A}\n\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = vpn.example.com:51820\n"
        )
    }

    #[test]
    fn a_real_provider_config_parses() {
        // The shape Mullvad, IVPN and `wg genkey` all emit, including the
        // fields we keep for display only.
        let text = format!(
            "[Interface]\n\
             PrivateKey = {KEY_A}\n\
             Address = 10.64.0.2/32,fc00::2/128\n\
             DNS = 10.64.0.1, 10.64.0.2\n\
             \n\
             [Peer]\n\
             PublicKey = {KEY_B}\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = 185.65.135.1:51820\n\
             PersistentKeepalive = 25\n"
        );
        let c = parse(&text).expect("a standard config must import");
        assert_eq!(c.private_key_b64, KEY_A);
        assert_eq!(c.peer_public_key_b64, KEY_B);
        assert_eq!(c.endpoint, "185.65.135.1:51820");
        assert_eq!(c.keepalive_secs, Some(25));
        assert_eq!(c.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(c.dns, vec!["10.64.0.1", "10.64.0.2"]);
        assert_eq!(c.preshared_key_b64, None);
    }

    /// The reason this parser refuses rather than strips. A config with PostUp
    /// asks the host to run a command; silently importing it and not running it
    /// would leave the user believing their tunnel does something it does not.
    #[test]
    fn command_running_directives_are_refused_by_name() {
        for directive in ["PostUp", "PreDown", "Table", "SaveConfig"] {
            let text = format!("{}{directive} = something\n", minimal());
            match parse(&text) {
                Err(ConfigError::Refused(d)) => {
                    assert_eq!(d, directive.to_ascii_lowercase());
                    assert!(
                        ConfigError::Refused(d).to_string().contains(&directive.to_ascii_lowercase()),
                        "the message must name the directive so the user can find the line"
                    );
                }
                other => panic!("{directive} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_truncated_or_wrong_key_is_malformed_not_accepted() {
        let short = minimal().replace(KEY_A, "tooshort=");
        assert_eq!(parse(&short), Err(ConfigError::Malformed("PrivateKey")));
        let unpadded = minimal().replace(KEY_B, &KEY_B.replace('=', "x"));
        assert_eq!(parse(&unpadded), Err(ConfigError::Malformed("PublicKey")));
    }

    #[test]
    fn endpoints_are_checked_without_resolving_anything() {
        let ok = ["a.example:1", "1.2.3.4:51820", "[fc00::1]:51820"];
        for e in ok {
            let text = minimal().replace("vpn.example.com:51820", e);
            assert!(parse(&text).is_ok(), "{e} should be accepted");
        }
        // No port, port 0, empty host, and a bare v6 address whose last group
        // would otherwise be read as a port.
        let bad = ["vpn.example.com", "host:0", ":51820", "fc00::1", "host:notaport"];
        for e in bad {
            let text = minimal().replace("vpn.example.com:51820", e);
            assert_eq!(
                parse(&text),
                Err(ConfigError::Malformed("Endpoint")),
                "{e} should be refused"
            );
        }
    }

    #[test]
    fn missing_sections_say_which_one() {
        let no_peer = format!("[Interface]\nPrivateKey = {KEY_A}\n");
        assert_eq!(parse(&no_peer), Err(ConfigError::MissingSection("Peer")));
        let no_iface = format!("[Peer]\nPublicKey = {KEY_B}\nEndpoint = a:1\n");
        assert_eq!(parse(&no_iface), Err(ConfigError::MissingSection("Interface")));
        // A typo'd section name must not read as a missing KEY -- the user
        // needs to be told the section is wrong.
        let typo = format!("[Interface]\nPrivateKey = {KEY_A}\n[Peers]\nPublicKey = {KEY_B}\n");
        assert_eq!(parse(&typo), Err(ConfigError::MissingSection("Peer")));
    }

    #[test]
    fn comments_and_junk_do_not_break_a_valid_file() {
        let text = format!(
            "# exported by a provider\n\
             [Interface]\n\
             PrivateKey = {KEY_A}   # the secret\n\
             MTU = 1420\n\
             ; a semicolon comment\n\
             \n\
             [Peer]\n\
             PublicKey = {KEY_B}\n\
             Endpoint = vpn.example.com:51820\n\
             UnknownFutureKey = whatever\n"
        );
        let c = parse(&text).expect("comments and unknown keys are tolerated");
        // The inline comment must not have been glued onto the key.
        assert_eq!(c.private_key_b64, KEY_A);
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        let huge = "#".repeat(MAX_CONFIG_BYTES + 1);
        assert_eq!(parse(&huge), Err(ConfigError::TooLarge));
    }

    #[test]
    fn the_interface_address_is_kept_verbatim_comma_split_and_all() {
        // Including the IPv6 entry and a junk entry: the parser's job is to
        // carry the field, not to judge it. Judging happens at tunnel start.
        let text = minimal().replace(
            "PrivateKey",
            "Address = 10.64.0.2/32, fc00::2/128 , not-an-address\nPrivateKey",
        );
        let c = parse(&text).expect("Address must not affect import");
        assert_eq!(c.address, vec!["10.64.0.2/32", "fc00::2/128", "not-an-address"]);
    }

    #[test]
    fn a_missing_address_is_an_empty_list_not_an_error() {
        // Plenty of hand-written configs omit Address; importing one is fine.
        // STARTING a tunnel from it is the refusal, and it happens elsewhere.
        let c = parse(&minimal()).expect("no Address still imports");
        assert_eq!(c.address, Vec::<String>::new());
    }

    #[test]
    fn the_private_key_is_never_in_the_debug_output() {
        let c = parse(&minimal()).expect("parses");
        let debug = format!("{c:?}");
        assert!(!debug.contains(KEY_A), "Debug must redact the private key");
        assert!(debug.contains("redacted"));
    }
}
