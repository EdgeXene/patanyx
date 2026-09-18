//! Premium-purchase identifiers and their immutable destinations.
//!
//! Chrome names a target; it never receives or sends the URL. This is the
//! same security shape as `sponsorship.rs`, kept separate because sponsorship
//! buys nothing while this destination sells a Premium licence. The IPC arm
//! independently requires `PREMIUM_ON_SALE`, so a caller cannot reach the
//! intentionally password-gated pre-launch page by bypassing the hidden UI.
//!
//! The resolved destination receives no navigation exemption. It is normalized
//! and checked against the content allowlist here, then opened with
//! `AppState::new_tab`, whose navigation handler applies every ordinary
//! navigation decision.

use serde_json::Value;

/// A Premium purchase destination resolved from a non-URL identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PremiumPurchaseTarget {
    Patanyx,
    /// TEST ONLY: proves that resolving a name cannot bypass URL gates.
    #[cfg(test)]
    RefusedFixture,
}

impl PremiumPurchaseTarget {
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

    /// The published Premium purchase destination, emitted byte for byte.
    fn url(self) -> &'static str {
        match self {
            Self::Patanyx => "https://patanyx.net/premium/",
            #[cfg(test)]
            Self::RefusedFixture => "file:///premium-purchase-fixture-must-be-refused",
        }
    }
}

/// Resolve a `premium_purchase_open` argument to an already-checked target.
///
/// Only the exact `purchase` string field is read. In particular, a
/// caller-supplied `url` field is never consulted.
pub fn destination_for(args: &Value) -> Result<String, &'static str> {
    let target = args
        .get("purchase")
        .and_then(Value::as_str)
        .and_then(PremiumPurchaseTarget::from_id)
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

    const APPROVED: &str = "https://patanyx.net/premium/";

    #[test]
    fn published_destination_is_pinned_byte_for_byte() {
        assert_eq!(PremiumPurchaseTarget::Patanyx.url(), APPROVED);
        assert_eq!(
            destination_for(&json!({ "purchase": "patanyx" })).unwrap(),
            APPROVED
        );
    }

    #[test]
    fn chrome_can_name_a_target_but_cannot_supply_a_url() {
        for args in [
            json!({}),
            json!({ "purchase": "" }),
            json!({ "purchase": "not-a-target" }),
            json!({ "purchase": "Patanyx" }),
            json!({ "purchase": "patanyx " }),
            json!({ "url": APPROVED }),
            json!({ "purchase_id": "patanyx" }),
            json!({ "nested": { "purchase": "patanyx" } }),
        ] {
            assert_eq!(destination_for(&args), Err("bad_args"), "accepted {args}");
        }
    }

    #[test]
    fn extra_fields_cannot_redirect_a_known_identifier() {
        assert_eq!(
            destination_for(&json!({
                "purchase": "patanyx",
                "url": "file:///etc/passwd",
                "sponsorship": "patanyx"
            }))
            .unwrap(),
            APPROVED
        );
    }

    #[test]
    fn identifier_path_observably_runs_the_content_url_gates() {
        assert_eq!(
            destination_for(&json!({ "purchase": "__refused_fixture" })),
            Err("bad_args")
        );
    }
}
