//! "Keep this site?" for Messenger, at the moment it matters (1.0.7).
//!
//! WHY THIS EXISTS. PATANYX clears all site data every time it starts, and
//! Messenger keeps its end-to-end device keys in IndexedDB. Each start is
//! therefore a new device to Messenger: the person signs in, enters the code,
//! and waits while the whole encrypted history downloads and decrypts again,
//! which a large history turns into minutes. The keep-list (Privacy, "Sites to
//! keep when PATANYX starts", prefs `wipe_exempt_hosts`) already solves this,
//! but it starts empty and nothing pointed anyone at it. This module decides
//! when to offer it: the first time in a session that the active tab of a
//! normal window lands on a Messenger page whose site is not kept.
//!
//! What it is not: it keeps nothing itself. The offer only names the site; the
//! chrome sends the ordinary `wipe_exempt_add` when the person chooses Keep.
//! The default stays a clean start. Nothing about offers is stored: the set of
//! sites already offered lives for this process only.
//!
//! Where: only where kept sites have their own profile (kept_profile.rs;
//! Windows today). Never in a Strict or ephemeral tab, whose data dies with
//! the tab anyway. Keep reopens the tab in the kept profile; the site's data
//! in the ordinary profile is not carried over, so the person signs in once.

use std::collections::HashSet;

/// The site to keep for a Messenger page at `url`, or `None` if this is not a
/// Messenger page. messenger.com (and its subdomains) is Messenger; on
/// facebook.com (and its subdomains) only the /messages pages are, because
/// the rest of Facebook is not what loses its keys.
pub fn messenger_site(url: &str) -> Option<&'static str> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let under = |site: &str| host == site || host.ends_with(&format!(".{site}"));
    if under("messenger.com") {
        return Some("messenger.com");
    }
    let path = parsed.path();
    if under("facebook.com") && (path == "/messages" || path.starts_with("/messages/")) {
        return Some("facebook.com");
    }
    None
}

/// The sites offered this session.
#[derive(Debug, Default)]
pub struct KeepOffers {
    offered: HashSet<&'static str>,
}

impl KeepOffers {
    /// Whether to offer keeping a site now, and which. `kept` is the current
    /// keep-list; `strict` and `ephemeral` describe the tab; `supported` is
    /// whether this platform's start-up clear honours the keep-list. Spends
    /// the site's one offer for this session when it returns one.
    pub fn offer(
        &mut self,
        url: &str,
        kept: &[String],
        strict: bool,
        ephemeral: bool,
        supported: bool,
    ) -> Option<&'static str> {
        if !supported || strict || ephemeral {
            return None;
        }
        let site = messenger_site(url)?;
        if crate::prefs::wipe_exempts(kept, site) || self.offered.contains(site) {
            return None;
        }
        self.offered.insert(site);
        Some(site)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messenger_pages_name_their_site() {
        for (url, site) in [
            ("https://www.messenger.com/", "messenger.com"),
            ("https://messenger.com/t/123", "messenger.com"),
            ("https://www.facebook.com/messages/t/123", "facebook.com"),
            ("https://www.facebook.com/messages", "facebook.com"),
            ("https://m.facebook.com/messages/", "facebook.com"),
            ("https://WWW.FACEBOOK.COM./messages/", "facebook.com"),
        ] {
            assert_eq!(messenger_site(url), Some(site), "{url}");
        }
    }

    #[test]
    fn everything_else_is_not_messenger() {
        for url in [
            "https://www.facebook.com/",
            "https://www.facebook.com/marketplace",
            "https://www.facebook.com/messagesx",
            "https://www.facebook.com/groups/messages/",
            "https://notfacebook.com/messages/",
            "https://facebook.com.evil.example/messages/",
            "https://notmessenger.com/",
            "https://messenger.com.evil.example/",
            "http://www.messenger.com/",
            "about:blank",
            "not a url",
        ] {
            assert_eq!(messenger_site(url), None, "{url}");
        }
    }

    #[test]
    fn a_site_is_offered_once_a_session() {
        let mut offers = KeepOffers::default();
        let url = "https://www.messenger.com/";
        assert_eq!(offers.offer(url, &[], false, false, true), Some("messenger.com"));
        assert_eq!(offers.offer(url, &[], false, false, true), None);
        // The other site has its own offer.
        assert_eq!(
            offers.offer("https://www.facebook.com/messages/", &[], false, false, true),
            Some("facebook.com")
        );
    }

    #[test]
    fn no_offer_where_it_cannot_help() {
        let url = "https://www.facebook.com/messages/t/1";
        let kept = vec!["facebook.com".to_string()];
        assert_eq!(KeepOffers::default().offer(url, &kept, false, false, true), None, "already kept");
        assert_eq!(KeepOffers::default().offer(url, &[], true, false, true), None, "Strict tab");
        assert_eq!(KeepOffers::default().offer(url, &[], false, true, true), None, "ephemeral tab");
        assert_eq!(KeepOffers::default().offer(url, &[], false, false, false), None, "no keep-list here");
    }

    #[test]
    fn a_refused_offer_does_not_spend_the_session_offer() {
        // A Strict tab on Messenger first, then a normal one: the normal tab
        // still gets its offer.
        let mut offers = KeepOffers::default();
        let url = "https://www.messenger.com/";
        assert_eq!(offers.offer(url, &[], true, false, true), None);
        assert_eq!(offers.offer(url, &[], false, false, true), Some("messenger.com"));
    }
}
