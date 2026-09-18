//! Sponsorship identifiers and their immutable destinations.
//!
//! Sponsorship is optional support for PATANYX development. It is neither a
//! Premium purchase nor an affiliate placement, so it deliberately does not
//! live in `PartnerTarget`. It does preserve the partner path's security
//! property: chrome sends a NAME, never a URL, and Rust resolves that name to
//! a destination compiled into the binary.
//!
//! The resolved destination receives no navigation exemption. It is normalized
//! and checked against the content allowlist here, then opened with
//! `AppState::new_tab`, whose navigation handler applies the reserved-origin
//! refusal, malicious-host blocklist, insecure-navigation policy and every
//! other ordinary navigation decision.

use serde_json::Value;

/// A sponsorship destination resolved from a non-URL identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SponsorshipTarget {
    Patanyx,
    /// TEST ONLY: proves that resolving a name cannot bypass URL gates.
    #[cfg(test)]
    RefusedFixture,
}

impl SponsorshipTarget {
    /// The identifier chrome is allowed to send.
    pub fn id(self) -> &'static str {
        match self {
            Self::Patanyx => "patanyx",
            #[cfg(test)]
            Self::RefusedFixture => "__refused_fixture",
        }
    }

    /// Unknown identifiers fail closed; there is no default destination.
    pub fn from_id(id: &str) -> Option<Self> {
        if id == Self::Patanyx.id() {
            return Some(Self::Patanyx);
        }
        #[cfg(test)]
        if id == Self::RefusedFixture.id() {
            return Some(Self::RefusedFixture);
        }
        None
    }

    /// The published sponsorship destination, emitted byte for byte.
    fn url(self) -> &'static str {
        match self {
            Self::Patanyx => "https://donate.stripe.com/7sYaEZ1Qxh126KteDRbsc00",
            #[cfg(test)]
            Self::RefusedFixture => "file:///sponsorship-fixture-must-be-refused",
        }
    }
}

/// Resolve a `sponsorship_open` argument to an already-checked destination.
///
/// Only the exact `"sponsorship"` string field is read. In particular, a
/// caller-supplied `"url"` field is never consulted.
pub fn destination_for(args: &Value) -> Result<String, &'static str> {
    let target = args
        .get("sponsorship")
        .and_then(Value::as_str)
        .and_then(SponsorshipTarget::from_id)
        .ok_or("bad_args")?;
    let normalized = crate::ipc::normalize_input(target.url());
    if !crate::state::is_allowed_content_url(&normalized) {
        return Err("bad_args");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const APPROVED: &str = "https://donate.stripe.com/7sYaEZ1Qxh126KteDRbsc00";

    #[test]
    fn published_destination_is_pinned_byte_for_byte() {
        assert_eq!(SponsorshipTarget::Patanyx.url(), APPROVED);
        assert_eq!(
            destination_for(&json!({ "sponsorship": "patanyx" })).unwrap(),
            APPROVED
        );
    }

    #[test]
    fn chrome_can_name_a_target_but_cannot_supply_a_url() {
        for args in [
            json!({}),
            json!({ "sponsorship": "" }),
            json!({ "sponsorship": "not-a-target" }),
            json!({ "sponsorship": "Patanyx" }),
            json!({ "sponsorship": "patanyx " }),
            json!({ "url": APPROVED }),
            json!({ "sponsorship_id": "patanyx" }),
            json!({ "nested": { "sponsorship": "patanyx" } }),
        ] {
            assert_eq!(destination_for(&args), Err("bad_args"), "accepted {args}");
        }
    }

    #[test]
    fn extra_fields_cannot_redirect_a_known_identifier() {
        assert_eq!(
            destination_for(&json!({
                "sponsorship": "patanyx",
                "url": "file:///etc/passwd",
                "partner": "nordvpn"
            }))
            .unwrap(),
            APPROVED
        );
    }

    #[test]
    fn identifier_path_observably_runs_the_content_url_gates() {
        assert_eq!(
            destination_for(&json!({ "sponsorship": "__refused_fixture" })),
            Err("bad_args")
        );
    }
}
