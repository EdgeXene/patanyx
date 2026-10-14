//! The browser's own guide pages on patanyx.net, opened from About by name.
//!
//! Chrome names a page; it never sends or receives the URL. The same shape as
//! `premium_purchase.rs`, and for the same reason: no `patanyx.net/premium*`
//! address may sit in a chrome asset (premium-toolbar-gate.js, "the chrome
//! contains no Premium destination in any state"), so the Premium guide's
//! address lives here, beside the plain Guide's.
//!
//! The Premium guide is refused while `PREMIUM_ON_SALE` is false. It is a
//! how-to, not a checkout, but its navigation links the purchase page, and
//! nothing in the browser may point one click from a sale before a sale is
//! possible (compliance audit 2026-10-13). The chrome also hides its button
//! then; this refusal is the half a chrome that forgot cannot undo.
//!
//! The resolved destination gets no navigation exemption: it is normalized,
//! checked against the content allowlist, and opened with `AppState::new_tab`,
//! whose navigation handler applies every ordinary decision.

use serde_json::Value;

/// A guide page the chrome may ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SitePage {
    Guide,
    PremiumGuide,
    /// TEST ONLY: proves that resolving a name cannot bypass URL gates.
    #[cfg(test)]
    RefusedFixture,
}

impl SitePage {
    /// The identifier chrome is allowed to send.
    pub fn id(self) -> &'static str {
        match self {
            Self::Guide => "guide",
            Self::PremiumGuide => "premium_guide",
            #[cfg(test)]
            Self::RefusedFixture => "__refused_fixture",
        }
    }

    /// Unknown identifiers fail closed; there is no default page.
    pub fn from_id(id: &str) -> Option<Self> {
        if let Some(page) = [Self::Guide, Self::PremiumGuide]
            .into_iter()
            .find(|page| page.id() == id)
        {
            return Some(page);
        }
        #[cfg(test)]
        if id == Self::RefusedFixture.id() {
            return Some(Self::RefusedFixture);
        }
        None
    }

    /// Whether this build may open the page at all.
    pub fn available(self) -> bool {
        match self {
            Self::Guide => true,
            Self::PremiumGuide => crate::licence_control::PREMIUM_ON_SALE,
            #[cfg(test)]
            Self::RefusedFixture => true,
        }
    }

    /// The published page, emitted byte for byte.
    fn url(self) -> &'static str {
        match self {
            Self::Guide => "https://patanyx.net/guide/",
            Self::PremiumGuide => "https://patanyx.net/premium-guide/",
            #[cfg(test)]
            Self::RefusedFixture => "file:///site-page-fixture-must-be-refused",
        }
    }
}

/// Resolve a `site_page_open` argument to an already-checked URL.
///
/// Exactly one field, the `page` string; a request carrying anything else
/// (a `url` above all) is refused rather than half-honoured (code review
/// 2026-10-13, R-003).
pub fn destination_for(args: &Value) -> Result<String, &'static str> {
    if args.as_object().is_none_or(|fields| fields.len() != 1) {
        return Err("bad_args");
    }
    let page = args
        .get("page")
        .and_then(Value::as_str)
        .and_then(SitePage::from_id)
        .filter(|page| page.available())
        .ok_or("bad_args")?;
    let normalized = crate::ipc::normalize_input(page.url());
    if !crate::state::is_allowed_content_url(&normalized) {
        return Err("bad_args");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn each_name_opens_its_exact_page() {
        assert_eq!(
            destination_for(&json!({ "page": "guide" })).as_deref(),
            Ok("https://patanyx.net/guide/")
        );
        let premium = destination_for(&json!({ "page": "premium_guide" }));
        if crate::licence_control::PREMIUM_ON_SALE {
            assert_eq!(premium.as_deref(), Ok("https://patanyx.net/premium-guide/"));
        } else {
            assert_eq!(premium, Err("bad_args"));
        }
    }

    #[test]
    fn the_premium_guide_follows_the_sale_flag() {
        assert_eq!(
            SitePage::PremiumGuide.available(),
            crate::licence_control::PREMIUM_ON_SALE
        );
        assert!(SitePage::Guide.available());
    }

    #[test]
    fn anything_but_a_known_name_is_refused() {
        for args in [
            json!({}),
            json!({ "page": "" }),
            json!({ "page": "Guide" }),
            json!({ "page": "premium" }),
            json!({ "page": 1 }),
            json!({ "page": null }),
            json!({ "url": "https://patanyx.net/guide/" }),
            json!({ "page": "https://patanyx.net/guide/" }),
        ] {
            assert_eq!(destination_for(&args), Err("bad_args"), "{args}");
        }
    }

    #[test]
    fn a_request_with_any_other_field_is_refused() {
        for args in [
            json!({ "page": "guide", "url": "https://evil.example/" }),
            json!({ "page": "guide", "extra": 1 }),
            json!(["guide"]),
            json!("guide"),
        ] {
            assert_eq!(destination_for(&args), Err("bad_args"), "{args}");
        }
    }

    #[test]
    fn a_name_cannot_bypass_the_content_allowlist() {
        assert_eq!(
            destination_for(&json!({ "page": SitePage::RefusedFixture.id() })),
            Err("bad_args")
        );
    }

    /// The IPC arm keeps the tab ceiling, checked BEFORE a page is resolved
    /// or a tab built (plan review 2026-10-13, R-002). AppState holds live
    /// webviews, so no unit test can dispatch at 31 and 32 tabs; the arm is
    /// pinned by its source like the other arms that open tabs, and the pin
    /// is the whole refusal, not just the comparison, so dropping the
    /// `return` fails it (code review 2026-10-13, R-002).
    #[test]
    fn the_ipc_arm_refuses_at_the_tab_ceiling_first() {
        let src = include_str!("ipc.rs");
        let start = src
            .find("\"site_page_open\" =>")
            .expect("the site_page_open arm is missing");
        let arm = &src[start..start + src[start..].find("\n        }\n").expect("arm end")];
        let ceiling = arm
            .find(
                "if state.tabs.len() >= crate::state::MAX_TABS {\n                return Err(\"bad_args\");\n            }",
            )
            .expect("site_page_open lost the tab ceiling or its refusal");
        let resolve = arm
            .find("crate::site_pages::destination_for(args)?")
            .expect("site_page_open no longer resolves by name");
        let open = arm.find("state.new_tab(&url, true)?").expect("site_page_open no longer opens a tab");
        assert!(ceiling < resolve && resolve < open, "the ceiling must come first");
    }
}
