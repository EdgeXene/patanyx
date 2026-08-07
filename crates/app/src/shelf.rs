//! Pure decision logic for tab set-aside ("shelves"), kept free of `Tab`,
//! webviews, and the store so it is unit-testable without a UI. The IPC
//! arms translate `Tab`s into `Candidate`s, act on the `Plan`, and never
//! re-decide any of this themselves.

/// One tab as `shelf_create` sees it: the facts that decide its fate,
/// nothing else.
pub(crate) struct Candidate<'a> {
    pub id: u64,
    pub ephemeral: bool,
    pub title: &'a str,
    pub url: &'a str,
}

/// What create stores for one tab: title + URL. Nothing else is stored
/// anywhere in the feature -- no favicons, no scroll positions, no
/// cookies, no history. That minimality is the privacy contract, not a
/// shortcut.
pub(crate) struct Entry<'a> {
    pub id: u64,
    pub title: &'a str,
    pub url: &'a str,
}

pub(crate) struct Plan<'a> {
    /// Tabs to store and then close, in tab order.
    pub entries: Vec<Entry<'a>>,
    /// Tabs deliberately left out: ephemeral tabs (their contract is that
    /// nothing outlives them) plus internal or empty URLs. The create
    /// reply carries this count so the chrome can state it plainly.
    pub left_out: usize,
}

/// A tab's URL qualifies unless it is empty or an internal page. about:
/// pages are skipped: they are cheap to reopen by hand, and several are
/// meaningless without the live session state behind them.
pub(crate) fn is_storable_url(url: &str) -> bool {
    let url = url.trim();
    // Scheme compare is case-insensitive: "ABOUT:blank" is the same
    // internal page, and a case variant must not sneak onto a shelf.
    !url.is_empty()
        && !(url.len() >= 6 && url[..6].eq_ignore_ascii_case("about:"))
}

/// Fixed phrasing per the feature spec: the count is the only variable and
/// no timestamp ever appears in the name. Shelves with equal counts share
/// a name on purpose; the stored creation order (`seq`) tells them apart.
pub(crate) fn shelf_name(count: usize) -> String {
    if count == 1 {
        "Set aside 1 tab".to_string()
    } else {
        format!("Set aside {} tabs", count)
    }
}

pub(crate) fn plan_create<'a>(tabs: &'a [Candidate<'a>]) -> Plan<'a> {
    let mut entries = Vec::new();
    let mut left_out = 0;
    for tab in tabs {
        // Ephemeral is checked first: that exclusion is a privacy promise,
        // not a filter preference, so no URL shape may ever relax it.
        if tab.ephemeral || !is_storable_url(tab.url) {
            left_out += 1;
        } else {
            entries.push(Entry {
                id: tab.id,
                title: tab.title,
                url: tab.url,
            });
        }
    }
    Plan { entries, left_out }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: u64, ephemeral: bool, url: &str) -> Candidate {
        Candidate {
            id,
            ephemeral,
            title: "title",
            url,
        }
    }

    #[test]
    fn plain_pages_qualify() {
        assert!(is_storable_url("https://example.com/"));
        assert!(is_storable_url("http://example.com/page?x=1"));
    }

    #[test]
    fn internal_and_empty_urls_do_not_qualify() {
        assert!(!is_storable_url(""));
        assert!(!is_storable_url("   "));
        assert!(!is_storable_url("about:blank"));
        assert!(!is_storable_url("about:config"));
        assert!(!is_storable_url("ABOUT:BLANK"), "schemes are case-insensitive");
    }

    #[test]
    fn ephemeral_tabs_are_left_out_even_with_storable_urls() {
        let tabs = [cand(1, true, "https://example.com/")];
        let plan = plan_create(&tabs);
        assert!(plan.entries.is_empty());
        assert_eq!(plan.left_out, 1);
    }

    #[test]
    fn mixed_window_partitions_in_tab_order() {
        let tabs = [
            cand(1, false, "https://a.example/"),
            cand(2, false, "about:blank"),
            cand(3, true, "https://b.example/"),
            cand(4, false, ""),
            cand(5, false, "https://c.example/"),
        ];
        let plan = plan_create(&tabs);
        let ids: Vec<u64> = plan.entries.iter().map(|entry| entry.id).collect();
        assert_eq!(ids, vec![1, 5]);
        assert_eq!(plan.entries[0].url, "https://a.example/");
        assert_eq!(plan.entries[1].url, "https://c.example/");
        assert_eq!(plan.left_out, 3);
    }

    #[test]
    fn nothing_storable_yields_an_empty_plan() {
        let tabs = [
            cand(1, false, "about:blank"),
            cand(2, true, "https://a.example/"),
        ];
        let plan = plan_create(&tabs);
        assert!(plan.entries.is_empty());
        assert_eq!(plan.left_out, 2);
        // The IPC arm turns exactly this plan into the "no_storable_tabs"
        // refusal; an empty shelf is never written.
    }

    #[test]
    fn a_fully_storable_window_leaves_none_out() {
        let tabs = [
            cand(1, false, "https://a.example/"),
            cand(2, false, "https://b.example/"),
        ];
        let plan = plan_create(&tabs);
        assert_eq!(plan.entries.len(), 2);
        assert_eq!(plan.left_out, 0);
    }

    #[test]
    fn shelf_names_carry_count_and_no_timestamp() {
        // Exact phrasing per the spec, count included, nothing else.
        assert_eq!(shelf_name(1), "Set aside 1 tab");
        assert_eq!(shelf_name(12), "Set aside 12 tabs");
    }
}
