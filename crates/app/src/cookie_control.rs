//! Every user-facing string the two cookie-clearing controls say, in one
//! place, as pure functions with the wording pinned by tests.
//!
//! WHY THE COPY LIVES IN RUST. The per-site control's wording sits in
//! `chrome.js` and `index.html`, and that is exactly how it can drift: the
//! rule that makes "Forget this site" honest -- it clears COOKIES, not saved
//! logins, not history, not site settings -- is enforced by `state.rs`'s doc
//! comment and by nothing else. A sentence of copy is doing the work of a
//! security control there, and it is the only part of the feature no test
//! reads.
//!
//! So the browser-wide control words itself here instead, the way
//! `licence_control::row_copy` does: the strings are values, the tests below
//! pin them, and `ipc` assembles a payload without phrasing anything. The
//! chrome writes what arrives, verbatim, through `textContent`.
//!
//! COOKIES, AND THE COPY MAY NOT SAY MORE THAN THAT. The primitive underneath
//! is `ICoreWebView2CookieManager::DeleteAllCookies` (see
//! `platform::forget_all_cookies`), which touches cookies and nothing else.
//! `ClearBrowsingData` is the call that would reach history, cache and site
//! data, and this feature deliberately does not make it. Copy claiming a
//! wider erasure than the code performs is the failure this module exists to
//! make hard.

/// The static wording of the browser-wide control. Four strings, because a
/// destructive action needs all four to agree: what it does, what it costs,
/// what the button says, and what confirming it says.
pub struct ForgetAllCopy {
    /// Sits above the button, always visible.
    pub intro: &'static str,
    /// The confirmation step's warning. Names what is NOT touched, because
    /// "clears cookies for every site" is the sentence a user is most likely
    /// to read as "wipes everything".
    pub warning: &'static str,
    /// The control itself.
    pub button: &'static str,
    /// The confirming button.
    pub confirm: &'static str,
    /// The way out.
    pub cancel: &'static str,
}

/// The browser-wide control's wording. Pure and constant: there is no state
/// this copy varies with, and the day it grows one, it grows a parameter
/// here rather than a branch in the chrome.
pub fn forget_all_copy() -> ForgetAllCopy {
    ForgetAllCopy {
        intro: "Clears cookies for every site, not just the one you are looking at. \
                Sites you are signed in to will sign you out.",
        warning: "This clears cookies for every site. Your saved passwords, bookmarks, \
                  history and site settings are left alone. This cannot be undone.",
        button: "Clear cookies for all sites",
        confirm: "Yes, clear them all",
        cancel: "Cancel",
    }
}

/// What the panel says once the clear has actually happened.
///
/// Returned by the COMMAND, not by the status payload, so it can only appear
/// after the engine reported success -- the same discipline as the per-site
/// result line, which is written from the reply rather than from the click.
pub fn cleared_line() -> &'static str {
    "Cookies cleared for every site."
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every string this module hands the chrome, for the checks that have to
    /// hold across all of them.
    fn all_strings() -> Vec<&'static str> {
        let c = forget_all_copy();
        vec![c.intro, c.warning, c.button, c.confirm, c.cancel, cleared_line()]
    }

    #[test]
    fn the_wording_is_pinned() {
        let c = forget_all_copy();
        assert_eq!(
            c.intro,
            "Clears cookies for every site, not just the one you are looking at. Sites \
             you are signed in to will sign you out."
        );
        assert_eq!(
            c.warning,
            "This clears cookies for every site. Your saved passwords, bookmarks, history \
             and site settings are left alone. This cannot be undone."
        );
        assert_eq!(c.button, "Clear cookies for all sites");
        assert_eq!(c.confirm, "Yes, clear them all");
        assert_eq!(c.cancel, "Cancel");
        assert_eq!(cleared_line(), "Cookies cleared for every site.");
    }

    /// The claim this feature can most easily overstate. A rewrite that
    /// reaches for "site data", "everything" or "browsing data" is describing
    /// `ClearBrowsingData`, which this code does not call.
    #[test]
    fn the_copy_never_claims_more_than_cookies_are_cleared() {
        const OVERCLAIMS: [&str; 5] = [
            "site data",
            "browsing data",
            "everything",
            "all your data",
            "history and cookies",
        ];
        for s in all_strings() {
            let lower = s.to_lowercase();
            for claim in OVERCLAIMS {
                assert!(
                    !lower.contains(claim),
                    "copy says {claim:?}, but only cookies are cleared: {s:?}"
                );
            }
        }
    }

    /// The warning has to name what SURVIVES, or "every site" is the only
    /// thing the user takes from it.
    #[test]
    fn the_warning_names_what_is_left_alone() {
        let warning = forget_all_copy().warning.to_lowercase();
        for kept in ["passwords", "bookmarks", "history", "site settings"] {
            assert!(
                warning.contains(kept),
                "the warning does not say {kept} are left alone: {warning:?}"
            );
        }
        assert!(warning.contains("cannot be undone"));
    }

    /// House style. Pinned here rather than remembered, because a rewrite is
    /// exactly when an em dash gets typed.
    #[test]
    fn no_em_dashes_anywhere_in_the_copy() {
        for s in all_strings() {
            assert!(!s.contains('\u{2014}'), "em dash in user-facing copy: {s:?}");
        }
    }
}
