//! Side by Side: the decisions, kept pure so every rule is unit-tested here.
//!
//! AppState holds `pair: Option<(left, right)>` and keeps `active` equal to
//! the pane with the keyboard; it asks this module what each event means and
//! does the platform work itself.

/// What selecting `arriving` (from `leaving`) does to the pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Both are panes: move between them, both stay on screen.
    PaneSwitch,
    /// A pair is showing and the new tab is not in it: end it first.
    EndPair,
    /// No pair: an ordinary tab switch.
    Plain,
}

pub fn on_select(pair: Option<(u64, u64)>, leaving: u64, arriving: u64) -> Selection {
    match pair {
        None => Selection::Plain,
        Some((l, r)) if [l, r].contains(&leaving) && [l, r].contains(&arriving) => {
            Selection::PaneSwitch
        }
        Some(_) => Selection::EndPair,
    }
}

/// Whether closing `closing` ends the pair.
pub fn close_ends_pair(pair: Option<(u64, u64)>, closing: u64) -> bool {
    pair.is_some_and(|(l, r)| l == closing || r == closing)
}

/// Whether a "this tab's page took the keyboard" report should make it the
/// active tab. Only a pane that is not already active qualifies; anything
/// else (a tab outside the pair, a tab already gone, no pair) is ignored.
/// The switch it causes must NOT focus the page again: the page already has
/// the keyboard, and refocusing turns queued reports into a loop.
pub fn focus_activates(pair: Option<(u64, u64)>, focused: u64, active: Option<u64>) -> bool {
    match pair {
        Some((l, r)) => (focused == l || focused == r) && active != Some(focused),
        None => false,
    }
}

/// Left and right follow the tab strip: whichever of the two tabs comes
/// first in the strip is shown on the left, so the screen never reverses the
/// order the strip shows. Arguments are (strip index, tab id) pairs.
pub fn ordered_pair(a: (usize, u64), b: (usize, u64)) -> (u64, u64) {
    if a.0 <= b.0 {
        (a.1, b.1)
    } else {
        (b.1, a.1)
    }
}

/// The tab the toggle pairs the active one with: its right-hand neighbor,
/// or the left-hand one for the last tab. None with fewer than two tabs.
pub fn toggle_partner(tab_count: usize, active: usize) -> Option<usize> {
    if tab_count < 2 || active >= tab_count {
        return None;
    }
    Some(if active + 1 < tab_count { active + 1 } else { active - 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_between_panes_keeps_the_pair_and_anything_else_ends_it() {
        let pair = Some((1, 2));
        assert_eq!(on_select(pair, 1, 2), Selection::PaneSwitch);
        assert_eq!(on_select(pair, 2, 1), Selection::PaneSwitch);
        assert_eq!(on_select(pair, 1, 3), Selection::EndPair);
        assert_eq!(on_select(pair, 3, 1), Selection::EndPair, "coming back from outside is not a pane switch");
        assert_eq!(on_select(None, 1, 2), Selection::Plain);
    }

    #[test]
    fn closing_either_pane_ends_the_pair_and_other_tabs_do_not() {
        assert!(close_ends_pair(Some((1, 2)), 1));
        assert!(close_ends_pair(Some((1, 2)), 2));
        assert!(!close_ends_pair(Some((1, 2)), 3));
        assert!(!close_ends_pair(None, 1));
    }

    #[test]
    fn focus_reports_activate_only_the_other_pane() {
        let pair = Some((1, 2));
        assert!(focus_activates(pair, 2, Some(1)));
        assert!(!focus_activates(pair, 1, Some(1)), "already active");
        assert!(!focus_activates(pair, 3, Some(1)), "not a pane");
        assert!(!focus_activates(None, 2, Some(1)), "no pair");
    }

    #[test]
    fn queued_focus_reports_settle_on_the_last_one_without_feedback() {
        // A -> B -> A clicked quickly: reports for B then A arrive. Each
        // activation is applied without refocusing, so no new report is
        // generated and the final state is the last real focus.
        let pair = Some((1, 2));
        let mut active = Some(1);
        for focused in [2u64, 1] {
            if focus_activates(pair, focused, active) {
                active = Some(focused);
            }
        }
        assert_eq!(active, Some(1));
    }

    #[test]
    fn panes_follow_strip_order_whichever_tab_is_active() {
        // Active tab 7 at index 2 paired with its left neighbor 5 at index 1:
        // 5 is on the left, as in the strip.
        assert_eq!(ordered_pair((2, 7), (1, 5)), (5, 7));
        assert_eq!(ordered_pair((0, 3), (1, 4)), (3, 4));
    }

    #[test]
    fn the_toggle_pairs_with_the_right_neighbor_or_the_left_for_the_last_tab() {
        assert_eq!(toggle_partner(3, 0), Some(1));
        assert_eq!(toggle_partner(3, 2), Some(1));
        assert_eq!(toggle_partner(1, 0), None);
        assert_eq!(toggle_partner(0, 0), None);
    }
}
