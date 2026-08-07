//! URL normalization for corroborated comparison.
//!
//! Two people who mean to open the same page type it differently: case
//! varies, the scheme is omitted, a default port is spelled out, a fragment
//! is pasted along. Those forms must compare equal. Everything a server may
//! legitimately treat as a *different* resource must stay different.
//!
//! The rule when unsure is to NOT normalize. A false mismatch costs a
//! confusing verdict between two trusting peers; a false merge — treating
//! two genuinely different endpoints as "the same page" — silently defeats
//! the entire feature. Deliberately NOT normalized, and why:
//!
//! - the scheme (`http` vs `https` are different endpoints),
//! - `www.` prefixes (many sites serve different content on the apex),
//! - trailing slashes below the root (`/a` vs `/a/`),
//! - letter case and percent-encoding in path and query,
//! - query parameter order,
//! - non-default ports.

use crate::CorroborateError;
use std::fmt;

/// A URL in canonical comparison form. Construct only via
/// [`normalize_url`]; equality of two `NormalizedUrl`s is the equality the
/// whole protocol relies on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedUrl(String);

impl NormalizedUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for NormalizedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalize a URL as a person might type or paste it.
///
/// What IS normalized: surrounding whitespace, scheme and host case, an
/// omitted scheme (browsers default to `https`), a single trailing dot on
/// the host (DNS-equivalent), default ports (`:80`/`:443`), an empty path
/// (equals `/`), and the fragment — which is never sent to the server, so
/// it cannot affect what either viewer was served. Only `http` and `https`
/// are accepted: anything else is not a page two browsers can corroborate.
pub fn normalize_url(input: &str) -> Result<NormalizedUrl, CorroborateError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CorroborateError::InvalidUrl("address is empty".into()));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(CorroborateError::InvalidUrl(
            "address contains control characters".into(),
        ));
    }
    if trimmed.chars().any(|c| c == ' ') {
        return Err(CorroborateError::InvalidUrl(
            "address contains a space".into(),
        ));
    }

    // Scheme: people differ by case and by omitting it; an omitted scheme
    // is what a browser treats as https.
    let (scheme, mut rest) = match trimmed.find("://") {
        Some(i) => {
            let raw = &trimmed[..i];
            let valid = !raw.is_empty()
                && raw.chars().next().map_or(false, |c| c.is_ascii_alphabetic())
                && raw
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if !valid {
                return Err(CorroborateError::InvalidUrl(format!("bad scheme {raw:?}")));
            }
            (raw.to_ascii_lowercase(), &trimmed[i + 3..])
        }
        None => ("https".to_string(), trimmed),
    };
    // Tolerate the protocol-relative spelling "//host/path".
    if let Some(stripped) = rest.strip_prefix("//") {
        rest = stripped;
    }
    match scheme.as_str() {
        "http" | "https" => {}
        other => {
            return Err(CorroborateError::InvalidUrl(format!(
                "only http and https pages can be compared, not {other:?}"
            )))
        }
    }

    // The fragment never reaches the server; it cannot distinguish what two
    // viewers were served.
    let rest = rest.split('#').next().unwrap_or(rest);

    // Authority ends at the first '/' or '?'.
    let split_at = rest
        .find(|c: char| c == '/' || c == '?')
        .unwrap_or(rest.len());
    let authority = &rest[..split_at];
    let mut tail = &rest[split_at..];

    // The LAST '@' separates userinfo from host; earlier ones can legally
    // sit in a password.
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };

    let (host, port) = split_host_port(host_port)?;
    if host.is_empty() {
        return Err(CorroborateError::InvalidUrl("address has no host".into()));
    }
    // One trailing dot is DNS-equivalent; the host is case-insensitive.
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();

    // Only the scheme's default port carries no information.
    let default_port = if scheme == "http" { 80 } else { 443 };
    let keep_port = port.filter(|p| *p != default_port);

    // Empty path and "/" are the same request. A bare query ("?x=1") means
    // the root path. Everything else in the tail stays byte-for-byte typed.
    let tail_storage;
    if tail.is_empty() {
        tail = "/";
    } else if tail.starts_with('?') {
        tail_storage = format!("/{tail}");
        tail = &tail_storage;
    }

    let mut out = String::with_capacity(
        scheme.len() + 3 + authority.len() + tail.len() + 8,
    );
    out.push_str(&scheme);
    out.push_str("://");
    if let Some(u) = userinfo {
        out.push_str(u);
        out.push('@');
    }
    out.push_str(&host);
    if let Some(p) = keep_port {
        out.push(':');
        out.push_str(&p.to_string());
    }
    out.push_str(tail);
    Ok(NormalizedUrl(out))
}

fn split_host_port(authority: &str) -> Result<(&str, Option<u16>), CorroborateError> {
    // Bracketed IPv6 literal: [::1] or [::1]:8080.
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return Err(CorroborateError::InvalidUrl(
                "unterminated ipv6 literal".into(),
            ));
        };
        let host = &authority[..end + 1];
        let after = &authority[end + 1..];
        return match after.strip_prefix(':') {
            Some(p) => Ok((host, Some(parse_port(p)?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(CorroborateError::InvalidUrl(
                "unexpected characters after ipv6 literal".into(),
            )),
        };
    }
    match authority.matches(':').count() {
        0 => Ok((authority, None)),
        1 => {
            let i = authority.find(':').unwrap_or(authority.len());
            Ok((&authority[..i], Some(parse_port(&authority[i + 1..])?)))
        }
        // Multiple colons without brackets: a bare IPv6 literal, no port.
        _ => Ok((authority, None)),
    }
}

fn parse_port(text: &str) -> Result<u16, CorroborateError> {
    text.parse::<u16>()
        .map_err(|_| CorroborateError::InvalidUrl(format!("bad port {text:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_forms_normalize_equal() {
        let pairs: [(&str, &str); 10] = [
            ("https://example.com/", "https://example.com"),
            ("HTTPS://Example.COM/path", "https://example.com/path"),
            ("https://example.com:443/", "https://example.com/"),
            ("http://example.com:80/a", "http://example.com/a"),
            ("example.com/a?b=c", "https://example.com/a?b=c"),
            ("https://example.com./", "https://example.com/"),
            ("https://example.com/page#section", "https://example.com/page"),
            ("  https://example.com/  ", "https://example.com/"),
            ("example.com?x=1", "https://example.com/?x=1"),
            ("//example.com/a", "https://example.com/a"),
        ];
        for (a, b) in pairs {
            assert_eq!(
                normalize_url(a).expect(a),
                normalize_url(b).expect(b),
                "{a:?} and {b:?} should normalize equal"
            );
        }
    }

    #[test]
    fn meaningfully_different_forms_stay_distinct() {
        // Each pair is something a server MAY treat as different content;
        // merging any of these would silently defeat the comparison.
        let pairs: [(&str, &str); 7] = [
            // Different scheme = different endpoint.
            ("http://example.com/", "https://example.com/"),
            // www. is not decoration.
            ("https://www.example.com/", "https://example.com/"),
            // Trailing slash below the root can be a different resource.
            ("https://example.com/a", "https://example.com/a/"),
            // Query order can matter to the application.
            ("https://example.com/?a=1&b=2", "https://example.com/?b=2&a=1"),
            // Paths are case-sensitive on many servers.
            ("https://example.com/Path", "https://example.com/path"),
            // A non-default port is a different endpoint.
            ("https://example.com:8443/", "https://example.com/"),
            // Different hosts, obviously.
            ("https://example.co.uk/", "https://example.com/"),
        ];
        for (a, b) in pairs {
            assert_ne!(
                normalize_url(a).expect(a),
                normalize_url(b).expect(b),
                "{a:?} and {b:?} must NOT be merged"
            );
        }
    }

    #[test]
    fn invalid_addresses_are_rejected() {
        for bad in [
            "",
            "   ",
            "https://",
            "https:///path",
            "ftp://example.com/",
            "https://exa mple.com/",
            "https://example.com:abc/",
            "://example.com/",
            "https://user@/",
        ] {
            assert!(
                normalize_url(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
