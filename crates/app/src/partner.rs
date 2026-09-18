//! Affiliate partner identifiers and their immutable destinations.
//!
//! WHY THIS TAKES AN IDENTIFIER AND NOT A URL. The chrome asks to open a
//! partner by NAME -- `"nordvpn"` -- and this module resolves that name to a
//! URL compiled into the binary. The alternative, letting the chrome pass the
//! URL, would turn one IPC command into an arbitrary-navigation primitive
//! reachable from the chrome document, which is the one thing a partner link
//! must not become. An identifier cannot be pointed somewhere else.
//!
//! WHAT THE PARTNER PATH IS EXEMPT FROM, EXACTLY. It is exempt from generic
//! attribution-parameter removal at emission, because a disclosed partner click
//! is a link the reader was told earns us a commission, and delivering it with
//! the attribution stripped would be a quiet lie to both sides. It is exempt
//! from NOTHING ELSE. Normalization, scheme restriction, the reserved-host
//! refusal, the blocklist and navigation policy all apply exactly as they do to
//! any other URL. If the security system ever refuses a partner's host, the
//! partner link is refused with it: revenue does not outrank the blocklist.
//!
//! NO SPECIAL CASE IN THE GENERIC CLEANERS, IN EITHER DIRECTION. These
//! parameter names are deliberately absent from `TRACKING_PARAMS`, and these
//! hosts are deliberately absent from `REDIRECT_WRAPPERS`. Do not add them to
//! protect the revenue, and do not add them to demonstrate neutrality either:
//! the first makes the cleaner serve us, the second lets the affiliate deal
//! change what "Copy clean link" does. Generic rules decide, and today they
//! already come out right.

use serde_json::Value;

/// An affiliate partner, resolved to an immutable URL at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartnerTarget {
    NordVpn,
    Pia,
    NordPass,
    Coveron,
    Saily,
    /// TEST ONLY, compiled out of every real build.
    ///
    /// WHY A FIXTURE IS NECESSARY HERE. All four shipping destinations are
    /// absolute https URLs that `normalize_input` returns unchanged and
    /// `is_allowed_content_url` accepts. With only those four, no test can
    /// tell "the gates ran and passed" apart from "the gates were never
    /// called": the observable output is byte-identical either way. An
    /// independent review found exactly that, and deleting the `checked` call
    /// from `destination_for` was confirmed to leave every test passing.
    ///
    /// This variant's URL is one the allowlist MUST refuse, which makes the
    /// difference observable. It is deliberately NOT in `ALL`, so it is not a
    /// partner; `from_id` resolves it only under `cfg(test)`.
    #[cfg(test)]
    RefusedFixture,
}

impl PartnerTarget {
    /// Every partner, so tests can walk the set without a hand-maintained list
    /// that can fall out of step with the enum.
    pub const ALL: [PartnerTarget; 5] =
        [Self::NordVpn, Self::Pia, Self::NordPass, Self::Coveron, Self::Saily];

    /// The identifier the chrome sends. Kept lowercase and hyphen-free so it
    /// cannot be confused with a hostname or a path segment.
    pub fn id(self) -> &'static str {
        match self {
            Self::NordVpn => "nordvpn",
            Self::Pia => "pia",
            Self::NordPass => "nordpass",
            Self::Coveron => "coveron",
            Self::Saily => "saily",
            #[cfg(test)]
            Self::RefusedFixture => "__refused_fixture",
        }
    }

    /// The product name shown on the disclosed chrome card.
    pub fn name(self) -> &'static str {
        match self {
            Self::NordVpn => "NordVPN",
            Self::Pia => "Private Internet Access",
            Self::NordPass => "NordPass",
            Self::Coveron => "Coveron",
            Self::Saily => "Saily",
            #[cfg(test)]
            Self::RefusedFixture => "Refused fixture",
        }
    }

    /// A short, factual reason this partner sits beside the PATANYX feature.
    ///
    /// These sentences deliberately distinguish the external service from
    /// what PATANYX does locally; the small card must not imply that one
    /// product provides the other's coverage.
    pub fn description(self) -> &'static str {
        match self {
            Self::NordVpn => "A managed VPN for needs beyond this browser.",
            Self::Pia => {
                "A managed VPN with an official WireGuard config for Private Tunnel."
            }
            Self::NordPass => "Passwords across devices. PATANYX Vault keeps passwords local.",
            Self::Coveron => "Identity theft and scam protection beyond a saved-page record.",
            // Narrow on purpose, like the others: what the product does is give
            // the phone data on arrival. No price claim against roaming rates,
            // which vary by carrier and are not ours to characterise.
            Self::Saily => "An eSIM data plan abroad, so the phone is online when you land.",
            #[cfg(test)]
            Self::RefusedFixture => "A destination-refusal test fixture.",
        }
    }

    /// The standing discount code for this partner's card, `(code, terms)`, or
    /// `None` for a partner without one.
    ///
    /// EXACTLY ONE PARTNER HAS ONE, AND IT MUST STAY THAT WAY. NordVPN, NordPass
    /// and Coveron share a single Nord affiliate account whose rules forbid a
    /// coupon not assigned to it; a breach terminates the account and cancels
    /// commissions owed. Saily is a SEPARATE programme (its link carries
    /// `aff_id=16311`, not Nord's `155286`), so its code is its own to give.
    /// This is an explicit per-variant match rather than a lookup precisely so
    /// the Nord arms read `None` in plain sight, and
    /// `only_saily_carries_a_discount_code` fails the build if that ever
    /// changes. The one place the site keeps the same rule is
    /// `site-shell::OFFERS`; the two must not disagree on who has a code.
    pub fn offer(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Saily => Some(("PATANYX", "10% discount")),
            Self::NordVpn | Self::Pia | Self::NordPass | Self::Coveron => None,
            #[cfg(test)]
            Self::RefusedFixture => None,
        }
    }

    /// Resolve an identifier. Unknown names are `None`, never a default: a
    /// typo must fail loudly rather than open somebody else's link.
    pub fn from_id(id: &str) -> Option<Self> {
        if let Some(p) = Self::ALL.into_iter().find(|p| p.id() == id) {
            return Some(p);
        }
        // The refusal fixture is reachable by name in tests only, and is not a
        // member of `ALL`, so no shipping build can resolve it at all.
        #[cfg(test)]
        if id == Self::RefusedFixture.id() {
            return Some(Self::RefusedFixture);
        }
        None
    }

    /// The approved destination, emitted byte for byte.
    ///
    /// The query identifies EdgeXene as the referring publisher. It carries
    /// nothing about the reader, and nothing reader-derived may ever be added
    /// to it: the moment a value here varies per person, per session or per
    /// query, the published privacy policy stops being true.
    pub fn url(self) -> &'static str {
        match self {
            Self::NordVpn => "https://go.nordvpn.net/aff_c?offer_id=15&aff_id=155286&url_id=902",
            Self::Pia => "https://www.privateinternetaccess.com/offer/patanyx_6o8lkem",
            Self::NordPass => "https://go.nordpass.io/aff_c?offer_id=488&aff_id=155286&url_id=9356",
            Self::Coveron => {
                "https://go.coveron.net/aff_c?offer_id=1025&aff_id=155286&url_id=34071"
            }
            // Saily runs its own affiliate program, so this aff_id is NOT the
            // 155286 the other Nord-family links carry. Confirmed
            // 2026-08-28: it is a separate account, not a typo of the others.
            Self::Saily => "https://go.saily.site/aff_c?offer_id=101&aff_id=16311",
            // A scheme with no http(s) authority. `is_allowed_content_url`
            // refuses it, and unlike a reserved-host spelling this does not
            // silently stop testing anything if that host constant is ever
            // renamed.
            #[cfg(test)]
            Self::RefusedFixture => "file:///partner-fixture-must-be-refused",
        }
    }
}

/// Run a candidate destination through the same gates `tab_new` applies, and
/// return THE STRING THAT PASSED THEM.
///
/// RETURNING THE CHECKED VALUE IS THE WHOLE POINT. An earlier draft validated
/// the normalized form and then returned the raw constant, so the string that
/// was inspected and the string that would have been navigated to were two
/// different objects. That is harmless while `normalize_input` happens to be a
/// no-op on an absolute https URL, and it is exactly the shape that becomes a
/// hole the moment normalization grows a case. One string is checked, and that
/// same string is what the caller gets.
fn checked(raw: &str) -> Result<String, &'static str> {
    let normalized = crate::ipc::normalize_input(raw);
    if !crate::state::is_allowed_content_url(&normalized) {
        return Err("bad_args");
    }
    Ok(normalized)
}

/// Resolve a `partner_open` argument object to a destination that has already
/// passed every gate.
///
/// Reads only `"partner"`. A `"url"` key is not consulted, so a caller cannot
/// smuggle a destination past the identifier indirection by supplying one.
pub fn destination_for(args: &Value) -> Result<String, &'static str> {
    let target = args
        .get("partner")
        .and_then(Value::as_str)
        .and_then(PartnerTarget::from_id)
        .ok_or("bad_args")?;
    checked(target.url())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The approved destinations as LITERALS. Written out rather than read
    /// from `url()`, because a test that compares a constant with itself
    /// proves only that `==` works. If a URL drifts, this notices.
    const APPROVED: [(&str, &str); 5] = [
        (
            "nordvpn",
            "https://go.nordvpn.net/aff_c?offer_id=15&aff_id=155286&url_id=902",
        ),
        (
            "pia",
            "https://www.privateinternetaccess.com/offer/patanyx_6o8lkem",
        ),
        (
            "nordpass",
            "https://go.nordpass.io/aff_c?offer_id=488&aff_id=155286&url_id=9356",
        ),
        (
            "coveron",
            "https://go.coveron.net/aff_c?offer_id=1025&aff_id=155286&url_id=34071",
        ),
        ("saily", "https://go.saily.site/aff_c?offer_id=101&aff_id=16311"),
    ];

    #[test]
    fn every_partner_url_is_byte_identical_to_the_approved_constant() {
        for (id, url) in APPROVED {
            let target = PartnerTarget::from_id(id).expect("known identifier");
            assert_eq!(target.url(), url, "{id}: destination drifted");
        }
    }

    /// EXACTLY ONE partner may carry a discount code, and it must be Saily.
    /// NordVPN, NordPass and Coveron are one Nord affiliate account that forbids
    /// coupons not assigned to it; a code on any of their cards can cost the
    /// account. This fails the build the instant a second partner grows an offer
    /// or a Nord one does. The code itself is pinned so a typo cannot ship a
    /// coupon the partner will not honour.
    #[test]
    fn only_saily_carries_a_discount_code() {
        let with_offer: Vec<_> =
            PartnerTarget::ALL.into_iter().filter(|p| p.offer().is_some()).collect();
        assert_eq!(
            with_offer,
            vec![PartnerTarget::Saily],
            "a partner other than Saily carries a coupon, which can breach the Nord account rule"
        );
        assert_eq!(PartnerTarget::Saily.offer(), Some(("PATANYX", "10% discount")));
        for nord in [PartnerTarget::NordVpn, PartnerTarget::NordPass, PartnerTarget::Coveron] {
            assert_eq!(nord.offer(), None, "{} must never carry a coupon", nord.name());
        }
    }

    #[test]
    fn the_approved_table_covers_every_variant() {
        // Guards against adding a partner to the enum and forgetting to pin it.
        assert_eq!(PartnerTarget::ALL.len(), 5);
        assert_eq!(PartnerTarget::ALL.len(), APPROVED.len());
        let mut occurrences = [0; 5];
        for target in PartnerTarget::ALL {
            occurrences[match target {
                PartnerTarget::NordVpn => 0,
                PartnerTarget::Pia => 1,
                PartnerTarget::NordPass => 2,
                PartnerTarget::Coveron => 3,
                PartnerTarget::Saily => 4,
                PartnerTarget::RefusedFixture => {
                    unreachable!("the refusal fixture is never a member of ALL")
                }
            }] += 1;
            assert!(
                APPROVED.iter().any(|(id, _)| *id == target.id()),
                "{} is not pinned by the approved table",
                target.id()
            );
        }
        assert_eq!(
            occurrences,
            [1, 1, 1, 1, 1],
            "ALL must contain each variant once"
        );
    }

    #[test]
    fn identifiers_stay_lowercase_hyphen_free_and_not_url_like() {
        for target in PartnerTarget::ALL {
            let id = target.id();
            assert!(!id.is_empty(), "a partner identifier must not be empty");
            assert_eq!(id, id.to_lowercase(), "{id:?} is not lowercase");
            assert!(!id.contains('-'), "{id:?} contains a hyphen");
            assert!(!id.contains('.'), "{id:?} looks like a hostname");
            assert!(
                !id.contains('/') && !id.contains('\\'),
                "{id:?} looks like a path"
            );
        }
    }

    #[test]
    fn every_shipping_partner_has_short_human_copy() {
        for target in PartnerTarget::ALL {
            assert!(
                !target.name().trim().is_empty(),
                "{} has no name",
                target.id()
            );
            assert!(
                !target.description().trim().is_empty(),
                "{} has no description",
                target.id()
            );
            assert!(
                target.description().chars().count() <= 80,
                "{} has card copy too long for the small placement",
                target.id()
            );
        }
    }

    #[test]
    fn a_known_identifier_resolves_to_its_own_destination() {
        for (id, url) in APPROVED {
            let got = destination_for(&json!({ "partner": id })).expect("resolves");
            assert_eq!(got, url, "{id}: resolved to the wrong destination");
        }
    }

    #[test]
    fn an_unknown_identifier_is_refused() {
        for bogus in ["", "not-a-partner", "NordVPN", "nordvpn ", "../nordvpn"] {
            assert_eq!(
                destination_for(&json!({ "partner": bogus })).unwrap_err(),
                "bad_args",
                "{bogus:?} must not resolve"
            );
        }
    }

    #[test]
    fn unusual_identifier_strings_are_matched_exactly() {
        let very_long = "nordvpn".repeat(1024);
        for bogus in [
            " nordvpn",
            "nordvpn\n",
            "nordvpn\0",
            "nordvpn.com",
            "/nordvpn",
            "nordvpn?url=https://example.com",
            "nordvp\u{043d}", // Final letter is Cyrillic en, not ASCII n.
            very_long.as_str(),
        ] {
            assert_eq!(
                destination_for(&json!({ "partner": bogus })).unwrap_err(),
                "bad_args",
                "{bogus:?} must not resolve"
            );
        }
    }

    #[test]
    fn non_object_and_non_string_arguments_are_refused() {
        for args in [
            Value::Null,
            json!(true),
            json!(7),
            json!("nordvpn"),
            json!([]),
            json!(["nordvpn"]),
            json!({}),
            json!({ "partner": null }),
            json!({ "partner": true }),
            json!({ "partner": 7 }),
            json!({ "partner": ["nordvpn"] }),
            json!({ "partner": { "partner": "nordvpn" } }),
        ] {
            assert_eq!(
                destination_for(&args).unwrap_err(),
                "bad_args",
                "unexpectedly accepted {args}"
            );
        }
    }

    #[test]
    fn only_the_exact_top_level_partner_key_is_consulted() {
        for args in [
            json!({ "Partner": "nordvpn" }),
            json!({ " partner": "nordvpn" }),
            json!({ "partner ": "nordvpn" }),
            json!({ "partner_id": "nordvpn" }),
            json!({ "nested": { "partner": "nordvpn" } }),
            json!({ "url": { "partner": "nordvpn" } }),
        ] {
            assert_eq!(
                destination_for(&args).unwrap_err(),
                "bad_args",
                "a lookalike or nested key was accepted: {args}"
            );
        }

        let args = json!({
            "partner": "nordvpn",
            "Partner": "coveron",
            "partner_id": "nordpass",
            "url": ["file:///etc/passwd", { "partner": "coveron" }],
            "nested": { "partner": "coveron" },
            "reader_derived": "must not reach the destination",
            "control": "\u{0000}\n\t",
        });
        assert_eq!(destination_for(&args).expect("resolves"), APPROVED[0].1);
    }

    #[test]
    fn a_url_argument_is_ignored_entirely() {
        // The indirection is the security property. Supplying a URL must not
        // navigate anywhere, with or without a partner alongside it.
        assert_eq!(
            destination_for(&json!({ "url": "https://example.com/" })).unwrap_err(),
            "bad_args"
        );
        // And when both are present, the identifier decides and the URL is
        // not consulted.
        let got = destination_for(&json!({
            "partner": "nordvpn",
            "url": "https://example.com/",
        }))
        .expect("resolves");
        assert_eq!(got, APPROVED[0].1);
        assert!(!got.contains("example.com"));
    }

    #[test]
    fn the_partner_path_has_no_exemption_from_the_content_allowlist() {
        // Proves the gate on the partner path, not merely that the gate exists
        // somewhere: `checked` is the exact function `destination_for` calls.
        let reserved = format!(
            "https://{}/aff_c?aff_id=155286",
            crate::platform::CHROME_RESERVED_HOST
        );
        assert_eq!(checked(&reserved).unwrap_err(), "bad_args");

        // A scheme carrying an authority is refused outright.
        assert!(checked("file:///etc/passwd").is_err());

        // ASSERTING "EVERY HOSTILE STRING IS REFUSED" WOULD BE WRONG, and this
        // test said that first. `data:text/html,x` and `javascript:alert(1)`
        // carry neither a dot nor "://", so `normalize_input` classifies them
        // as search TEXT and hands back an https search URL. Nothing navigates
        // to the dangerous scheme, which is the property that matters. The
        // invariant is therefore about what SURVIVES, not about what is
        // rejected: whatever comes out is http(s) and is not the chrome origin.
        for text in ["data:text/html,x", "javascript:alert(1)"] {
            let out = checked(text).expect("classified as a search");
            assert!(out.starts_with("https://"), "{text} produced {out}");
            assert!(!out.starts_with(text), "{text} survived as its own scheme");
        }
    }

    #[test]
    fn destination_for_actually_runs_its_candidate_through_the_gates() {
        // THE TEST THE OTHERS COULD NOT BE. Every shipping URL passes the
        // gates, so a suite built only from them cannot distinguish a
        // `destination_for` that calls `checked` from one that returns the raw
        // constant. This was not hypothetical: replacing the call with
        // `Ok(target.url().to_string())` left all thirteen other tests green.
        //
        // The fixture resolves like any other identifier and then hits a
        // destination the allowlist must refuse. If the gates are skipped, this
        // returns Ok and the test fails, which is the whole point.
        let refused = destination_for(&json!({ "partner": "__refused_fixture" }));
        assert_eq!(
            refused.unwrap_err(),
            "bad_args",
            "destination_for returned a destination the allowlist refuses, \
             which means it is not running its candidate through checked()"
        );

        // And the fixture is genuinely reachable, so the assertion above is
        // failing for the right reason rather than because the name resolved
        // to nothing.
        assert_eq!(
            PartnerTarget::from_id("__refused_fixture"),
            Some(PartnerTarget::RefusedFixture)
        );
        assert!(!PartnerTarget::ALL.contains(&PartnerTarget::RefusedFixture));
    }

    #[test]
    fn a_destination_that_passes_is_returned_unchanged() {
        // The checked string and the returned string are the same object.
        for (_, url) in APPROVED {
            assert_eq!(checked(url).expect("passes"), url);
        }
    }

    #[test]
    fn checked_returns_the_normalized_value_not_the_raw_candidate() {
        assert_eq!(
            checked("  example.com  ").expect("a bare domain passes after normalization"),
            "https://example.com"
        );
    }

    #[test]
    fn generic_cleaners_do_not_special_case_partner_urls() {
        for (id, url) in APPROVED {
            assert_eq!(
                crate::ipc::strip_tracking_params(url),
                url,
                "{id}: generic tracking removal changed the partner URL"
            );
            assert_eq!(
                crate::ipc::unwrap_redirect(url),
                url,
                "{id}: generic redirect unwrapping changed the partner URL"
            );
        }
    }
}
