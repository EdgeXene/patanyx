//! "This site is already open in another tab", pure.
//!
//! What this module is: every rule about WHEN the duplicate-site notice
//! appears, which tab it names, and whether a click on it may still act.
//! What it is not: it touches no platform type, no webview, no clock and no
//! file. `AppState` owns a `Tab` with a live `WebView`, so no unit test can
//! build one; the rules therefore live here, where a test can drive every one
//! of them, and state.rs only feeds events in and emits what comes back.
//!
//! ONLY SITES THE USER OPENS. A navigation counts only
//! if the browser's own controls started it: the address bar, a bookmark, a
//! new tab opened from the chrome or the right-click menu, a restored shelf,
//! an accepted shared link, Back and Forward, and Continue or Open anyway on
//! a warning. `AppState` marks the tab with `note_user_navigation` at that
//! moment, and the tab's next committed load spends the mark. A navigation
//! that is held or refused instead of committing (the plain-HTTP warning,
//! the malicious-site list, the ad-list hold, a first page that could not
//! be issued) takes its mark with it through `forget_user_navigation`, so
//! the page's own next navigation cannot spend it (code review 2026-10-07,
//! R-019). A page's own navigations -- a link it follows, a redirect,
//! a `window.open` -- never raise the notice. That decision replaced an
//! earlier one to let pages count: a page redirecting itself through several
//! open sites could swap the notice under the user's cursor, and five review
//! rounds of click-timing defences each left a gap. With pages unable to raise
//! it, nothing replaces a notice but the user's own next navigation, and the
//! timing defences are gone. The accepted cost: a duplicate
//! reached by clicking a link gets no notice.
//!
//! The rest of the shape follows the plan review of 2026-10-05 (R-001..R-006)
//! and the code review of 2026-10-06:
//!
//! - A tab's last-seen site starts EMPTY, never seeded from the URL it was
//!   created with. A tab opened straight at a site already holds that URL in
//!   `Tab.url` before its first load, so seeding from it would make the first
//!   load compare the site with itself and the commonest case would never
//!   notify (R-001).
//! - Detection and presentation are separate. A tab entering a site records a
//!   candidate; the candidate is SHOWN only while its tab is active, and is
//!   re-checked on every activation, including the one that happens when the
//!   active tab closes (R-004).
//! - There is NO cooldown. One existed, and the code review found that a
//!   candidate it held back had nothing to retry it. A notice is shown once
//!   per (tab, site) and only one is ever on screen.
//! - Every notice has an id, and a click acts only if that id is the current
//!   notice AND both tabs are still on the site. A queued click from a notice
//!   that has since moved on is refused, never re-aimed (R-002).
//!
//! "Dismiss" silences the SITE for the rest of this process -- the same
//! session boundary as the per-process cookie wipe. The set is never written
//! anywhere: it is a list of sites the user visited, and persisting it would
//! be a new stored-data surface. A Dismiss pressed in a Strict (quarantine)
//! tab is kept apart from one pressed in a normal tab and is forgotten when
//! the last Strict tab closes, so a Strict visit leaves nothing behind it
//! here either (compliance audit, 2026-10-05).

use std::collections::{HashMap, HashSet};

/// The site a URL belongs to, or `None` when it has no registrable domain.
///
/// `None` covers about:blank and every non-http(s) URL (`host_of` reads
/// http and https only), IP literals, `localhost` and every `*.localhost`
/// name, single-label intranet names and bare public suffixes. None of those
/// gets a notice: two local apps on different ports share a host but are not
/// the same site, and a host that belongs to nobody (`github.io`) has no site
/// to be a duplicate of.
///
/// `*.localhost` needs its own test: `localhost` is not in the public suffix
/// list, so the default rule would give `app.localhost` a site of its own and
/// `app.localhost:3000` beside `app.localhost:4000` would read as a
/// duplicate. Other local names (`nas.local`, `wiki.corp`) DO get a site,
/// the same way the rest of the browser treats them.
pub fn site_key(url: &str) -> Option<String> {
    let host = crate::state::host_of(url)?;
    if host == "localhost" || host.ends_with(".localhost") {
        return None;
    }
    crate::psl::registrable_domain(&host).map(str::to_string)
}

/// What the tracker needs to know about one tab. Borrowed from `Tab`, in
/// strip order, so "the first matching tab" means the leftmost one.
#[derive(Debug, Clone, Copy)]
pub struct TabView<'a> {
    pub id: u64,
    pub url: &'a str,
    pub strict: bool,
}

/// One notice as shown: tab `tab_id` has entered `site`, which tab `other_id`
/// already has open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub id: u64,
    pub tab_id: u64,
    pub other_id: u64,
    pub site: String,
    /// Whether the two tabs are Strict (quarantine) tabs. They are always
    /// the same kind; this decides which dismissal set a Dismiss lands in.
    pub strict: bool,
}

/// The three buttons. Parsed from the IPC argument; anything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Switch,
    Close,
    Dismiss,
}

impl Choice {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "switch" => Some(Self::Switch),
            "close" => Some(Self::Close),
            "dismiss" => Some(Self::Dismiss),
            _ => None,
        }
    }
}

/// What a validated click asks `AppState` to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    SwitchTo(u64),
    Close(u64),
    Dismissed,
}

/// How long the user's mark on a tab waits for the load it was made for.
/// Generous for a slow site; a load slower than this simply gets no notice.
const MARK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct DuplicateSites {
    /// Per tab: the site its last committed load was on. Absent = no load
    /// seen yet; `Some(None)` = on a page with no site.
    last_site: HashMap<u64, Option<String>>,
    /// Per tab: a site it entered that has not been shown or ruled out yet.
    pending: HashMap<u64, String>,
    /// Tabs whose next committed load was started by the user from the
    /// browser's own controls, and when. Spent by that load, whatever it
    /// turns out to be, so a mark can never be carried over to a page's own
    /// navigation. A mark older than `MARK_LIFETIME` is not spent but void: a
    /// navigation that never commits and says so nowhere (a download, a 204,
    /// a jump within the page) must not hand its mark to whatever the page
    /// does next (code review 2026-10-12, R-001).
    user_initiated: HashMap<u64, std::time::Instant>,
    /// (tab, site) pairs already shown, so a tab is told about a site once.
    notified: HashSet<(u64, String)>,
    /// (site, Strict-tab?) pairs the user dismissed this session. Memory
    /// only, by design. Keyed by tab kind so a Dismiss in a Strict tab does
    /// not silence normal tabs, and so the Strict half can be forgotten when
    /// the last Strict tab closes.
    dismissed: HashSet<(String, bool)>,
    /// The notice on screen, if any. There is never more than one.
    current: Option<Notice>,
    next_id: u64,
}

impl DuplicateSites {
    /// The user just asked for a page in `tab_id` from the browser itself
    /// (the module header lists the paths). The tab's next committed load is
    /// theirs.
    pub fn note_user_navigation(&mut self, tab_id: u64) {
        self.user_initiated.insert(tab_id, std::time::Instant::now());
    }

    /// The navigation the user asked for in `tab_id` will not commit: it was
    /// held, refused, or never started. Its mark goes with it. Without this
    /// the mark waits for the tab's next committed load, and that load can be
    /// the page's own doing (code review 2026-10-07, R-019).
    ///
    /// Safe to call when the tab has no mark, and when the refusal was of
    /// something else in the tab (WebKitGTK reports a refused subframe the
    /// same way): the worst it does is withhold one notice, never raise one.
    pub fn forget_user_navigation(&mut self, tab_id: u64) {
        self.user_initiated.remove(&tab_id);
    }

    /// A committed main-frame load on `tab_id`. Records a candidate when the
    /// tab ENTERS a site on a load the user started, and returns the id of
    /// the current notice if this load took either of its tabs off its site
    /// (the chrome must drop it). A page's own navigation updates where the
    /// tab is and can end a notice, but never raises one.
    pub fn on_navigation(&mut self, tab_id: u64, url: &str) -> Option<u64> {
        let by_user = self
            .user_initiated
            .remove(&tab_id)
            .is_some_and(|at| at.elapsed() <= MARK_LIFETIME);
        let key = site_key(url);
        let prev = self.last_site.insert(tab_id, key.clone()).flatten();
        if prev != key {
            self.pending.remove(&tab_id);
            if let Some(site) = key.as_ref().filter(|_| by_user) {
                self.pending.insert(tab_id, site.clone());
            }
        }
        let leaves_notice = self.current.as_ref().is_some_and(|n| {
            (n.tab_id == tab_id || n.other_id == tab_id) && key.as_deref() != Some(n.site.as_str())
        });
        if leaves_notice {
            return self.current.take().map(|n| n.id);
        }
        None
    }

    /// The tab is gone. Forgets everything about it and returns the current
    /// notice's id if the notice named it. `strict_tabs_remain` says whether
    /// any OTHER Strict tab is still open; when none is, every dismissal
    /// made in a Strict tab is forgotten with it, the way a Strict tab's
    /// cookies die with the tab.
    pub fn on_tab_closed(&mut self, tab_id: u64, strict_tabs_remain: bool) -> Option<u64> {
        self.last_site.remove(&tab_id);
        self.pending.remove(&tab_id);
        self.user_initiated.remove(&tab_id);
        self.notified.retain(|(t, _)| *t != tab_id);
        if !strict_tabs_remain {
            self.dismissed.retain(|(_, strict)| !*strict);
        }
        let names_it = self
            .current
            .as_ref()
            .is_some_and(|n| n.tab_id == tab_id || n.other_id == tab_id);
        if names_it {
            return self.current.take().map(|n| n.id);
        }
        None
    }

    /// A different tab is now active. A notice belongs to the tab it was
    /// shown on, so it is retired the moment that tab is no longer in front.
    pub fn on_active_changed(&mut self, active_id: u64) -> Option<u64> {
        if self.current.as_ref().is_some_and(|n| n.tab_id != active_id) {
            return self.current.take().map(|n| n.id);
        }
        None
    }

    /// The setting was turned off. Drops every waiting candidate so nothing
    /// queued while it was on can surface later, and retires the current one.
    pub fn disable(&mut self) -> Option<u64> {
        self.pending.clear();
        self.current.take().map(|n| n.id)
    }

    /// Whether the active tab has a notice to show right now, and if so which.
    ///
    /// Called after every navigation and every activation. A candidate that
    /// no longer holds (the tab moved on, the other copy closed, the site was
    /// dismissed) is dropped. One that holds is shown at once unless another
    /// notice is already up for this tab. The (tab, site) pair is spent only
    /// when a notice is actually returned.
    pub fn present(
        &mut self,
        active_id: u64,
        tabs: &[TabView<'_>],
        enabled: bool,
    ) -> Option<Notice> {
        if !enabled || self.current.is_some() {
            return None;
        }
        let site = self.pending.get(&active_id)?.clone();
        let Some(me) = tabs.iter().find(|t| t.id == active_id) else {
            self.pending.remove(&active_id);
            return None;
        };
        let still_there = site_key(me.url).as_deref() == Some(site.as_str());
        let silenced = self.dismissed.contains(&(site.clone(), me.strict))
            || self.notified.contains(&(active_id, site.clone()));
        // The other copy must have LOADED the site, not merely been asked
        // for it: a tab still held on a warning, or refused, has the address
        // and nothing else, and offering to switch to it (or close the only
        // working copy) would be wrong (code review 2026-10-12, R-002).
        let other = tabs.iter().find(|t| {
            t.id != active_id
                && t.strict == me.strict
                && site_key(t.url).as_deref() == Some(site.as_str())
                && self.committed_on(t.id, &site)
        });
        let Some(other) = other.filter(|_| still_there && !silenced) else {
            self.pending.remove(&active_id);
            return None;
        };
        self.pending.remove(&active_id);
        self.notified.insert((active_id, site.clone()));
        self.next_id += 1;
        let notice = Notice {
            id: self.next_id,
            tab_id: active_id,
            other_id: other.id,
            site,
            strict: me.strict,
        };
        self.current = Some(notice.clone());
        Some(notice)
    }

    /// Whether tab `id`'s last committed load was on `site`.
    fn committed_on(&self, id: u64, site: &str) -> bool {
        matches!(self.last_site.get(&id), Some(Some(s)) if s == site)
    }

    /// Test only: make every mark `by` older.
    #[cfg(test)]
    fn age_marks(&mut self, by: std::time::Duration) {
        for at in self.user_initiated.values_mut() {
            if let Some(older) = at.checked_sub(by) {
                *at = older;
            }
        }
    }

    /// A button on notice `notice_id` was clicked.
    ///
    /// The notice is over whatever happens. The click acts only if it came
    /// from the CURRENT notice and both of its tabs are still open on its
    /// site; otherwise it is refused as "stale" and nothing is switched,
    /// closed or silenced.
    pub fn act(
        &mut self,
        notice_id: u64,
        choice: Choice,
        tabs: &[TabView<'_>],
    ) -> Result<Outcome, &'static str> {
        let notice = match &self.current {
            Some(n) if n.id == notice_id => self.current.take().expect("matched above"),
            _ => return Err("stale"),
        };
        let on_site = |id: u64| {
            tabs.iter()
                .find(|t| t.id == id)
                .and_then(|t| site_key(t.url))
                .as_deref()
                == Some(notice.site.as_str())
                && self.committed_on(id, &notice.site)
        };
        if !(on_site(notice.tab_id) && on_site(notice.other_id)) {
            return Err("stale");
        }
        Ok(match choice {
            Choice::Switch => Outcome::SwitchTo(notice.other_id),
            Choice::Close => Outcome::Close(notice.tab_id),
            // No pending purge here: `present` re-checks the dismissal set
            // for every candidate, and purging by site alone would also drop
            // the OTHER tab kind's candidates.
            Choice::Dismiss => {
                self.dismissed.insert((notice.site, notice.strict));
                Outcome::Dismissed
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tv(id: u64, url: &str) -> TabView<'_> {
        TabView {
            id,
            url,
            strict: false,
        }
    }

    /// The USER opens `url` in tab `id`: the browser marks the tab, then the
    /// engine reports one committed load. The first load of every tab goes
    /// through here, which is the whole point of R-001.
    fn load(d: &mut DuplicateSites, id: u64, url: &str) -> Option<u64> {
        d.note_user_navigation(id);
        d.on_navigation(id, url)
    }

    /// The PAGE in tab `id` navigates on its own: a link it follows, a
    /// redirect, a script. No mark.
    fn page_load(d: &mut DuplicateSites, id: u64, url: &str) -> Option<u64> {
        d.on_navigation(id, url)
    }

    #[test]
    fn site_keys_follow_the_registrable_domain() {
        assert_eq!(site_key("https://mail.google.com/x").as_deref(), Some("google.com"));
        assert_eq!(site_key("https://docs.google.com/").as_deref(), Some("google.com"));
        assert_eq!(site_key("http://example.co.uk/").as_deref(), Some("example.co.uk"));
        // Private suffix: two people's pages are two sites.
        assert_eq!(site_key("https://alice.github.io/").as_deref(), Some("alice.github.io"));
        assert_ne!(site_key("https://alice.github.io/"), site_key("https://bob.github.io/"));
        // Nothing that belongs to nobody, and nothing local.
        for url in [
            "about:blank",
            "file:///etc/hosts",
            "data:text/html,hi",
            "https://github.io/",
            "http://127.0.0.1:3000/",
            "http://localhost:8080/",
            "http://app.localhost:3000/",
            "http://api.app.localhost:4000/",
            "http://intranet/",
        ] {
            assert_eq!(site_key(url), None, "{url} must not have a site");
        }
        // A local name outside .localhost is treated like any other name;
        // the comment on `site_key` says so, and this pins it.
        assert_eq!(site_key("http://nas.local/").as_deref(), Some("nas.local"));
    }

    #[test]
    fn two_local_apps_on_different_ports_are_not_duplicates() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "http://app.localhost:3000/");
        load(&mut d, 2, "http://app.localhost:4000/");
        let tabs = [tv(1, "http://app.localhost:3000/"), tv(2, "http://app.localhost:4000/")];
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn a_tab_opened_straight_at_an_open_site_is_told_once() {
        // R-001. Tab 2 is created at the destination; its first load is the
        // only navigation it ever reports, and it must count as entering.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://mail.google.com/");
        load(&mut d, 2, "https://mail.google.com/inbox");
        let tabs = [tv(1, "https://mail.google.com/"), tv(2, "https://mail.google.com/inbox")];
        let n = d.present(2, &tabs, true).expect("one notice");
        assert_eq!((n.tab_id, n.other_id, n.site.as_str()), (2, 1, "google.com"));
        d.act(n.id, Choice::Switch, &tabs).unwrap();
        // Back on tab 2 well past the cooldown, a same-site navigation is not
        // an entry, so there is no second notice.
        d.on_active_changed(2);
        load(&mut d, 2, "https://docs.google.com/");
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn returning_to_a_site_does_not_tell_the_same_tab_twice() {
        let mut d = DuplicateSites::default();
        let on_site = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let n = d.present(2, &on_site, true).unwrap();
        assert_eq!(d.on_navigation(2, "https://elsewhere.example/"), Some(n.id));
        load(&mut d, 2, "https://example.com/");
        assert!(d.present(2, &on_site, true).is_none());
    }

    #[test]
    fn the_first_tab_on_a_site_is_not_a_duplicate() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "about:blank")];
        assert!(d.present(1, &tabs, true).is_none());
    }

    #[test]
    fn different_sites_and_a_tab_alone_never_notify() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.org/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.org/")];
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn staying_within_a_site_does_not_re_fire() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/a");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/b")];
        let n = d.present(2, &tabs, true).unwrap();
        d.act(n.id, Choice::Switch, &tabs).unwrap();
        load(&mut d, 2, "https://example.com/b");
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn quarantine_and_normal_tabs_are_never_paired() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let tabs = [
            tv(1, "https://example.com/"),
            TabView {
                id: 2,
                url: "https://example.com/",
                strict: true,
            },
        ];
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn a_background_duplicate_is_shown_when_selected() {
        // R-004. Tab 2 loads while tab 1 is in front: nothing for tab 1, and
        // the candidate waits for tab 2 to be selected.
        // The real call order: AppState asks after EVERY navigation of the
        // active tab, so tab 1's own first load is asked about while it is
        // still the only copy.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        assert!(d.present(1, &[tv(1, "https://example.com/")], true).is_none());
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(1, &tabs, true).is_none());
        assert_eq!(d.on_active_changed(2), None);
        let n = d.present(2, &tabs, true).expect("shown on select");
        assert_eq!(n.tab_id, 2);
    }

    #[test]
    fn a_page_redirecting_through_open_sites_raises_nothing() {
        // Only sites the user opens count. A page in the
        // active tab redirecting itself A -> B -> C, each already open in
        // another tab, gets no notice at any step.
        let mut d = DuplicateSites::default();
        let open = ["https://a.example/", "https://b.example/", "https://c.example/"];
        for (i, url) in open.iter().enumerate() {
            load(&mut d, i as u64 + 1, url);
        }
        load(&mut d, 4, "https://start.example/");
        for url in open {
            assert_eq!(page_load(&mut d, 4, url), None);
            let tabs = [tv(1, open[0]), tv(2, open[1]), tv(3, open[2]), tv(4, url)];
            assert!(d.present(4, &tabs, true).is_none(), "{url}: a page's own navigation raised a notice");
        }
        assert!(d.current.is_none());
    }

    #[test]
    fn a_page_redirect_after_the_users_navigation_only_ends_the_notice() {
        // The user opens A (open elsewhere): notice. The page then sends the
        // tab on to B (also open elsewhere): A's notice ends, and B's is NOT
        // raised, because the user did not open B.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://a.example/");
        load(&mut d, 2, "https://b.example/");
        load(&mut d, 3, "https://a.example/");
        let on_a = [tv(1, "https://a.example/"), tv(2, "https://b.example/"), tv(3, "https://a.example/")];
        let n = d.present(3, &on_a, true).expect("the user's own navigation counts");
        assert_eq!(page_load(&mut d, 3, "https://b.example/"), Some(n.id));
        let on_b = [tv(1, "https://a.example/"), tv(2, "https://b.example/"), tv(3, "https://b.example/")];
        assert!(d.present(3, &on_b, true).is_none());
    }

    #[test]
    fn the_users_mark_is_spent_by_the_next_load_whatever_it_is() {
        // The user asks for a page with no site (about:blank). That load
        // spends the mark, so the page's own navigation afterwards to an open
        // site does not inherit it.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        d.note_user_navigation(2);
        page_load(&mut d, 2, "about:blank");
        page_load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, true).is_none(), "a spent mark was carried into a page's navigation");
    }

    #[test]
    fn a_closed_tab_takes_its_unspent_mark_with_it() {
        let mut d = DuplicateSites::default();
        d.note_user_navigation(7);
        d.on_tab_closed(7, false);
        assert!(d.user_initiated.is_empty());
    }

    #[test]
    fn a_mark_from_a_navigation_that_never_committed_is_not_spent_by_the_page() {
        // R-019 (code review 2026-10-07). The user asks for a page in tab 2;
        // it is held or refused (plain-HTTP warning, malicious-site list,
        // ad-list hold, a first page that could not be issued), so nothing
        // commits. The page still in tab 2 then navigates on its own to a
        // site open in tab 1. That load must not inherit the user's mark.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://start.example/");
        d.note_user_navigation(2);
        d.forget_user_navigation(2);
        assert_eq!(page_load(&mut d, 2, "https://example.com/"), None);
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(
            d.present(2, &tabs, true).is_none(),
            "a held navigation's mark was spent by the page's own navigation"
        );
        assert!(d.current.is_none());
    }

    #[test]
    fn without_the_forget_the_same_page_navigation_would_have_notified() {
        // The control for the test above: the identical sequence minus the
        // forget DOES notify, so the test above is not passing for some
        // unrelated reason (the sites, the tab kinds, the order of calls).
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://start.example/");
        d.note_user_navigation(2);
        page_load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, true).is_some(), "the leftover mark was spent");
    }

    #[test]
    fn the_users_continue_after_a_hold_is_a_fresh_mark_and_counts() {
        // Held, mark dropped; the user then chooses Continue (or Open anyway
        // on the malicious-site banner, or Back): that is a new user
        // navigation, marked again, and the site it reaches counts (R-021).
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "http://plain.example/");
        load(&mut d, 2, "https://start.example/");
        d.note_user_navigation(2);
        d.forget_user_navigation(2);
        // Continue: AppState marks again, then the engine commits the load.
        d.note_user_navigation(2);
        d.on_navigation(2, "http://plain.example/");
        let tabs = [tv(1, "http://plain.example/"), tv(2, "http://plain.example/")];
        let n = d.present(2, &tabs, true).expect("the user's own Continue counts");
        assert_eq!((n.tab_id, n.other_id), (2, 1));
    }

    #[test]
    fn forgetting_touches_only_the_named_tab_and_a_tab_with_no_mark() {
        // A refusal in tab 3 (or a refused subframe there) must not cost
        // tab 2 its mark, and forgetting a tab that has none is a no-op.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        d.note_user_navigation(2);
        d.forget_user_navigation(3);
        d.forget_user_navigation(9);
        // Committed WITHOUT marking again (`load` would re-mark tab 2 and
        // hide a forget that cleared every tab; code review 2026-10-12,
        // R-004).
        d.on_navigation(2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, true).is_some());
    }

    /// A mark that waited too long is void: the user's navigation never
    /// committed (a download, a 204, a jump within the page), and the page's
    /// own later navigation must not be taken for theirs (code review
    /// 2026-10-12, R-001).
    #[test]
    fn an_old_mark_is_not_spent_by_a_later_page_navigation() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://other.example/");
        d.note_user_navigation(2);
        d.age_marks(MARK_LIFETIME + std::time::Duration::from_secs(1));
        d.on_navigation(2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, true).is_none(), "a page navigation raised the notice on an old mark");
        // A fresh mark still counts.
        load(&mut d, 2, "https://other.example/");
        load(&mut d, 2, "https://example.com/");
        assert!(d.present(2, &tabs, true).is_some());
    }

    /// The other copy must have loaded the site, not merely been asked for
    /// it (code review 2026-10-12, R-002): a tab held on a warning has the
    /// address and nothing else.
    #[test]
    fn a_tab_that_never_loaded_the_site_is_not_the_open_copy() {
        let mut d = DuplicateSites::default();
        // Tab 1 was asked for example.com but never committed a load.
        d.note_user_navigation(1);
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, true).is_none(), "offered a tab that never loaded the site");
        // Once tab 1 commits, a later user visit in tab 3 is told.
        d.on_navigation(1, "https://example.com/");
        load(&mut d, 3, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(3, "https://example.com/")];
        let n = d.present(3, &tabs, true).expect("the committed copy counts");
        // And a click is refused if that copy is no longer committed there.
        d.on_navigation(1, "https://other.example/");
        assert_eq!(d.act(n.id, Choice::Switch, &tabs), Err("stale"));
    }

    #[test]
    fn a_second_duplicate_is_shown_without_waiting() {
        // Code review 2026-10-06 (R-002): a cooldown held this candidate with
        // nothing to retry it, so the notice was lost for the whole visit.
        // There is no cooldown now; the second notice shows as soon as the
        // first is over.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://a.example/");
        load(&mut d, 2, "https://a.example/");
        let tabs = [
            tv(1, "https://a.example/"),
            tv(2, "https://a.example/"),
            tv(3, "https://b.example/"),
            tv(4, "https://b.example/"),
        ];
        let first = d.present(2, &tabs, true).unwrap();
        d.act(first.id, Choice::Switch, &tabs).unwrap();
        load(&mut d, 3, "https://b.example/");
        load(&mut d, 4, "https://b.example/");
        let second = d.present(4, &tabs, true).expect("shown at once");
        assert_eq!((second.tab_id, second.site.as_str()), (4, "b.example"));
    }

    #[test]
    fn a_notice_is_retired_when_either_tab_leaves_the_site_or_closes() {
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        for (who, leave) in [(1u64, true), (2, true), (1, false), (2, false)] {
            let mut d = DuplicateSites::default();
            load(&mut d, 1, "https://example.com/");
            load(&mut d, 2, "https://example.com/");
            let n = d.present(2, &tabs, true).unwrap();
            let retired = if leave {
                d.on_navigation(who, "https://elsewhere.example/")
            } else {
                d.on_tab_closed(who, false)
            };
            assert_eq!(retired, Some(n.id), "tab {who} leave={leave}");
            assert_eq!(d.act(n.id, Choice::Close, &tabs), Err("stale"));
        }
    }

    #[test]
    fn a_navigation_within_the_site_keeps_the_notice() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://www.example.com/x")];
        let n = d.present(2, &tabs, true).unwrap();
        assert_eq!(d.on_navigation(2, "https://www.example.com/x"), None);
        assert_eq!(d.act(n.id, Choice::Switch, &tabs), Ok(Outcome::SwitchTo(1)));
    }

    #[test]
    fn switching_away_retires_the_notice() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        let n = d.present(2, &tabs, true).unwrap();
        assert_eq!(d.on_active_changed(2), None, "same tab: kept");
        assert_eq!(d.on_active_changed(1), Some(n.id));
    }

    #[test]
    fn stale_clicks_do_nothing() {
        // R-002: every action, from a notice whose tabs have moved on, and
        // an old id delivered after a replacement.
        let tabs_now = [tv(1, "https://example.com/"), tv(2, "https://other.example/")];
        for choice in [Choice::Switch, Choice::Close, Choice::Dismiss] {
            let mut d = DuplicateSites::default();
            load(&mut d, 1, "https://example.com/");
            load(&mut d, 2, "https://example.com/");
            let shown = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
            let n = d.present(2, &shown, true).unwrap();
            // The tab moved but the retire has not been processed yet: the
            // click must still be refused, against the tabs as they are now.
            assert_eq!(d.act(n.id, choice, &tabs_now), Err("stale"), "{choice:?}");
            assert!(d.dismissed.is_empty(), "a stale dismiss silenced a site");
        }
        // Old id after a replacement notice on the same tab.
        let mut d = DuplicateSites::default();
        let tabs = [
            tv(1, "https://a.example/"),
            tv(2, "https://b.example/"),
            tv(3, "https://b.example/"),
        ];
        load(&mut d, 1, "https://a.example/");
        load(&mut d, 3, "https://b.example/");
        load(&mut d, 2, "https://a.example/");
        let old = d
            .present(2, &[tv(1, "https://a.example/"), tv(2, "https://a.example/")], true)
            .unwrap();
        assert_eq!(load(&mut d, 2, "https://b.example/"), Some(old.id));
        let new = d.present(2, &tabs, true).unwrap();
        assert_ne!(old.id, new.id);
        assert_eq!(d.act(old.id, Choice::Dismiss, &tabs), Err("stale"));
        assert!(!d.dismissed.contains(&("b.example".to_string(), false)), "an old Dismiss silenced the new site");
        assert_eq!(d.act(new.id, Choice::Close, &tabs), Ok(Outcome::Close(2)));
    }

    #[test]
    fn dismiss_silences_the_site_for_every_tab_and_only_that_site() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://mail.google.com/");
        load(&mut d, 2, "https://mail.google.com/");
        let tabs = [
            tv(1, "https://mail.google.com/"),
            tv(2, "https://mail.google.com/"),
            tv(3, "https://docs.google.com/"),
            tv(4, "https://example.com/"),
            tv(5, "https://example.com/"),
        ];
        let n = d.present(2, &tabs, true).unwrap();
        assert_eq!(d.act(n.id, Choice::Dismiss, &tabs), Ok(Outcome::Dismissed));
        // Another tab, another subdomain of the same site: silent.
        load(&mut d, 3, "https://docs.google.com/");
        assert!(d.present(3, &tabs, true).is_none());
        // A different site still gets one.
        load(&mut d, 4, "https://example.com/");
        load(&mut d, 5, "https://example.com/");
        assert!(d.present(5, &tabs, true).is_some());
    }

    fn strict(id: u64, url: &str) -> TabView<'_> {
        TabView {
            id,
            url,
            strict: true,
        }
    }

    #[test]
    fn a_strict_dismissal_stays_with_strict_tabs_and_dies_with_the_last_one() {
        // Compliance audit 2026-10-05: a Dismiss pressed in a Strict tab must
        // not silence normal tabs, and must not outlive the Strict tabs.
        let mut d = DuplicateSites::default();
        let tabs = [
            strict(1, "https://example.com/"),
            strict(2, "https://example.com/"),
            tv(3, "https://example.com/"),
            tv(4, "https://example.com/"),
            strict(5, "https://example.com/"),
        ];
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let n = d.present(2, &tabs, true).unwrap();
        assert!(n.strict);
        assert_eq!(d.act(n.id, Choice::Dismiss, &tabs), Ok(Outcome::Dismissed));
        // Normal tabs are still told.
        load(&mut d, 3, "https://example.com/");
        load(&mut d, 4, "https://example.com/");
        let normal = d.present(4, &tabs, true).expect("normal tabs unaffected");
        assert!(!normal.strict);
        d.act(normal.id, Choice::Switch, &tabs).unwrap();
        // Another Strict tab, while Strict tabs remain: still silenced.
        load(&mut d, 5, "https://example.com/");
        assert!(d.present(5, &tabs, true).is_none());
        // Closing a Strict tab while another remains keeps the dismissal...
        d.on_tab_closed(5, true);
        assert!(d.dismissed.contains(&("example.com".to_string(), true)));
        // ...and closing the last one forgets it, leaving normal ones alone.
        d.on_tab_closed(2, true);
        d.on_tab_closed(1, false);
        assert!(!d.dismissed.iter().any(|(_, strict)| *strict), "a Strict dismissal outlived the Strict tabs");
    }

    #[test]
    fn a_normal_dismissal_survives_strict_tabs_closing() {
        let mut d = DuplicateSites::default();
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/"), strict(3, "about:blank")];
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let n = d.present(2, &tabs, true).unwrap();
        d.act(n.id, Choice::Dismiss, &tabs).unwrap();
        d.on_tab_closed(3, false);
        assert!(d.dismissed.contains(&("example.com".to_string(), false)));
    }

    #[test]
    fn switch_and_close_silence_nothing() {
        for choice in [Choice::Switch, Choice::Close] {
            let mut d = DuplicateSites::default();
            load(&mut d, 1, "https://example.com/");
            load(&mut d, 2, "https://example.com/");
            let tabs = [
                tv(1, "https://example.com/"),
                tv(2, "https://example.com/"),
                tv(3, "https://example.com/"),
            ];
            let n = d.present(2, &tabs, true).unwrap();
            d.act(n.id, choice, &tabs).unwrap();
            load(&mut d, 3, "https://example.com/");
            assert!(d.present(3, &tabs, true).is_some(), "{choice:?}");
        }
    }

    #[test]
    fn a_new_session_starts_with_nothing_dismissed() {
        // The set lives in memory only: a fresh tracker -- a fresh process --
        // knows nothing about the last one.
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        let n = d.present(2, &tabs, true).unwrap();
        d.act(n.id, Choice::Dismiss, &tabs).unwrap();
        let mut fresh = DuplicateSites::default();
        load(&mut fresh, 1, "https://example.com/");
        load(&mut fresh, 2, "https://example.com/");
        assert!(fresh.present(2, &tabs, true).is_some());
    }

    #[test]
    fn off_means_off_and_drops_what_was_waiting() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, false).is_none());
        assert_eq!(d.disable(), None);
        // Turned back on: the candidate queued while it was on is gone.
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn one_notice_at_a_time() {
        let mut d = DuplicateSites::default();
        load(&mut d, 1, "https://example.com/");
        load(&mut d, 2, "https://example.com/");
        let tabs = [tv(1, "https://example.com/"), tv(2, "https://example.com/")];
        assert!(d.present(2, &tabs, true).is_some());
        load(&mut d, 2, "https://example.com/again");
        assert!(d.present(2, &tabs, true).is_none());
    }

    #[test]
    fn choices_parse_strictly() {
        assert_eq!(Choice::parse("switch"), Some(Choice::Switch));
        assert_eq!(Choice::parse("close"), Some(Choice::Close));
        assert_eq!(Choice::parse("dismiss"), Some(Choice::Dismiss));
        for bad in ["", "Switch", "close ", "dismiss_all"] {
            assert_eq!(Choice::parse(bad), None, "{bad:?}");
        }
    }
}

/// Where AppState and the IPC layer feed the tracker. `AppState` holds live
/// webviews, so these call sites cannot be driven from a test; they are
/// pinned in the source instead, the way state.rs pins its own wiring.
/// Comment lines are dropped first, so a call that is commented out fails.
/// Code review 2026-10-07: R-019 (a held or refused navigation drops its
/// mark), R-020 (every path the user opens a site through marks) and R-021
/// (Back, Forward, Continue and Open anyway mark).
#[cfg(test)]
mod wiring {
    const STATE_RS: &str = include_str!("state.rs");
    const IPC_RS: &str = include_str!("ipc.rs");
    const MAIN_RS: &str = include_str!("main.rs");
    const CHAT_PANEL_RS: &str = include_str!("chat_panel.rs");

    /// The code from `start` to the first `end` after it, comment lines
    /// removed and every line trimmed, so indentation changes do not break
    /// a pin but a commented-out call does.
    fn code(src: &str, start: &str, end: &str) -> String {
        let at = src.find(start).unwrap_or_else(|| panic!("{start:?} not found"));
        let len = src[at..].find(end).unwrap_or_else(|| panic!("no {end:?} after {start:?}"));
        src[at..at + len]
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A method of `impl AppState` or `impl Tab`: four-space indented, so
    /// it ends at the first closing brace at that depth.
    fn method(src: &str, signature: &str) -> String {
        code(src, signature, "\n    }\n")
    }

    fn before(body: &str, first: &str, second: &str) -> bool {
        match (body.find(first), body.find(second)) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        }
    }

    const FORGET: &str = "self.duplicate_sites.forget_user_navigation(";
    const MARK: &str = "self.duplicate_sites.note_user_navigation(";

    // ---- R-019: a held or refused navigation drops its mark ---------------

    #[test]
    fn a_plain_http_hold_drops_the_mark_before_any_early_return() {
        let body = method(STATE_RS, "pub fn note_insecure_navigation_at(");
        assert!(body.contains("self.duplicate_sites.forget_user_navigation(id);"), "R-019: the hold keeps the mark");
        assert!(before(&body, FORGET, "return"), "R-019: an early return skips the forget");
    }

    #[test]
    fn a_malicious_site_refusal_drops_the_mark() {
        let body = method(STATE_RS, "pub fn note_navigation_blocked(");
        assert!(body.contains("self.duplicate_sites.forget_user_navigation(tab_id);"), "R-019: the refusal keeps the mark");
        assert!(before(&body, FORGET, "?;"), "R-019: a missing tab returns before the forget");
    }

    #[test]
    fn an_ad_list_hold_drops_the_mark_whatever_the_tab_policy() {
        let body = method(STATE_RS, "pub fn adlist_hold(");
        assert!(body.contains("self.duplicate_sites.forget_user_navigation(tab_id);"), "R-019: the hold keeps the mark");
        assert!(before(&body, FORGET, "if !tab.block_ads"), "R-019: the policy check returns before the forget");
    }

    #[test]
    fn a_first_page_that_could_not_be_issued_drops_the_mark() {
        // The Tab side reports the failure...
        let tab = method(STATE_RS, "fn finish_initial_navigation(&mut self) -> bool {");
        let failure = tab.find("load_initial_url(").expect("the first page is issued here");
        assert!(tab[failure..].contains("return true;"), "R-019: a failed first page is not reported");
        // ...and every AppState caller acts on it: the guard's two answers
        // and both releases in the session wipe (a failed wipe still ends
        // there).
        for (signature, calls) in [
            ("pub fn on_local_network_guard_settled(", 1),
            ("pub fn on_local_network_guard_overdue(", 1),
            ("pub fn finish_session_wipe(", 2),
        ] {
            let body = method(STATE_RS, signature);
            assert_eq!(body.matches("finish_initial_navigation();").count(), calls, "{signature}");
            assert_eq!(
                body.matches("if failed {\nself.duplicate_sites.forget_user_navigation(").count(),
                calls,
                "R-019: {signature} ignores a first page that was never issued"
            );
        }
    }

    #[test]
    fn the_address_bar_marks_only_a_navigation_that_was_accepted() {
        let body = method(STATE_RS, "pub fn navigate(&mut self, url: &str)");
        assert!(before(&body, "tab.queue_or_navigate(url)?;", MARK), "a refused navigation is marked");
        assert!(
            body.contains("if is_allowed_content_url(url) {\nself.duplicate_sites.note_user_navigation(id);"),
            "R-019: an address the handler refuses silently is marked"
        );
    }

    #[test]
    fn back_and_forward_at_the_end_of_history_issue_nothing_and_say_so() {
        for signature in [
            "pub fn history_back(&mut self) -> Result<bool, &'static str> {",
            "pub fn history_forward(&mut self) -> Result<bool, &'static str> {",
        ] {
            let body = method(STATE_RS, signature);
            assert!(body.contains("_ => return Ok(false),"), "{signature}: a no-op reads as a navigation");
            assert!(body.ends_with("Ok(true)"), "{signature}: a navigation reads as a no-op");
        }
    }

    // ---- R-020: user paths that open a tab mark it ------------------------

    #[test]
    fn a_foreground_tab_from_the_browser_marks_and_a_pages_window_open_does_not() {
        let body = method(STATE_RS, "pub fn new_tab(&mut self, url: &str, switch: bool)");
        assert!(body.contains("if switch {\nself.duplicate_sites.note_user_navigation(id);\n}"));
        // window.open arrives as a background tab and nothing marks it.
        let arm = code(MAIN_RS, "Event::UserEvent(UserEvent::OpenInNewTab { url, allowed }) => {", "\n            }\n");
        assert!(arm.contains("app.new_tab(&url, false);"), "a page's window.open must not open a foreground tab");
        assert!(!arm.contains("note_user_navigation"), "a page's window.open must never mark");
    }

    #[test]
    fn every_tab_opened_with_a_policy_is_marked() {
        // Open with profile, the right-click menu's open entries, the Strict
        // Tab button: all the user's, foreground and background alike.
        let body = method(STATE_RS, "pub fn new_tab_with_policy(");
        let push = body.find("self.tabs.push(tab);").expect("the tab is added");
        let mark = body.find("self.duplicate_sites.note_user_navigation(id);").expect("R-020: never marked");
        assert!(push < mark, "marked before the tab exists");
        assert!(!body[push..mark].contains("if "), "R-020: the mark is conditional (a background open is the user's too)");
    }

    #[test]
    fn every_tab_of_a_restored_shelf_is_marked() {
        let body = code(IPC_RS, "fn restore_shelf_tabs(", "\n}\n");
        assert!(
            body.contains("Ok(tab) => {\nstate.note_user_navigation(tab);\nopened_ids.push(tab);"),
            "R-020: the background tabs of a restored shelf are not marked"
        );
    }

    #[test]
    fn an_accepted_shared_link_is_marked() {
        let body = code(CHAT_PANEL_RS, "pub fn ipc_accept_tab(", "\n}\n");
        assert!(
            before(&body, "let id = state.new_tab(url, false)?;", "state.note_user_navigation(id);"),
            "R-020: an accepted shared link is not marked"
        );
    }

    // ---- R-021: Back, Forward, Continue and Open anyway mark --------------

    #[test]
    fn back_and_forward_mark_when_they_navigate() {
        for (signature, call) in [
            ("pub fn history_back(&mut self) -> Result<(), &'static str> {", "if tab.history_back()? {"),
            ("pub fn history_forward(&mut self) -> Result<(), &'static str> {", "if tab.history_forward()? {"),
        ] {
            let body = method(STATE_RS, signature);
            assert!(
                body.contains(&format!("{call}\nself.duplicate_sites.note_user_navigation(id);")),
                "R-021: {signature} does not mark"
            );
        }
    }

    #[test]
    fn continue_on_the_plain_http_warning_marks_once_the_load_starts() {
        let body = method(STATE_RS, "pub fn insecure_allow(");
        assert!(
            body.contains("if tab.load_url(&url).is_ok() {\nself.duplicate_sites.note_user_navigation(id);"),
            "R-021: Continue does not mark"
        );
    }

    #[test]
    fn open_anyway_on_the_malicious_site_banner_marks_once_the_load_starts() {
        let arm = code(IPC_RS, "\"blocklist_allow\" => {", "\n        }\n");
        assert!(
            arm.contains("if started {\nstate.note_user_navigation(tab_id);"),
            "R-021: Open anyway does not mark"
        );
    }

    #[test]
    fn open_anyway_on_the_held_page_marks_only_after_the_resume_started() {
        let body = method(STATE_RS, "pub fn adlist_allow(");
        assert!(before(&body, "if let Err(reason) = resumed {", MARK), "a failed resume is marked");
        assert!(body.contains("self.duplicate_sites.note_user_navigation(tab_id);"), "Open anyway does not mark");
    }

    // ---- the port's own wiring ----------------------------------------------

    #[test]
    fn navigations_activations_and_closes_reach_the_tracker() {
        let url = method(STATE_RS, "pub fn on_url_changed(");
        assert!(before(&url, "self.duplicate_sites.on_navigation(id, &url);", "self.present_duplicate_notice();"));
        let active = method(STATE_RS, "fn set_active_inner(");
        assert!(before(&active, "self.duplicate_sites.on_active_changed(tab_id);", "self.present_duplicate_notice();"));
        let close = method(STATE_RS, "pub fn close_tab(");
        assert!(close.contains("self.duplicate_sites.on_tab_closed(id, strict_tabs_remain);"));
        assert!(before(&close, "self.duplicate_sites.on_active_changed(new_active_id);", "self.present_duplicate_notice();"));
    }

    /// "Strict" here is a Strict Tab, not any private tab: a private tab is
    /// ephemeral too but runs scripts and is never frozen, so pairing on
    /// ephemeral offered a Strict duplicate a switch to it, and kept a Strict
    /// dismissal alive while only private tabs remained (release review
    /// 2026-10-12, R-002).
    #[test]
    fn strict_means_a_strict_tab_not_any_private_tab() {
        for name in ["fn present_duplicate_notice(", "pub fn duplicate_site_action("] {
            let body = method(STATE_RS, name);
            assert!(body.contains("strict: t.policy.strict,"), "{name} pairs on something other than a Strict Tab");
        }
        let close = method(STATE_RS, "pub fn close_tab(");
        assert!(
            close.contains("let strict_tabs_remain = self.tabs.iter().any(|t| t.id != id && t.policy.strict);"),
            "a private tab keeps a Strict dismissal alive"
        );
    }
}
