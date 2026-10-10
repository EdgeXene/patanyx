//! Page fullscreen: a video's own "full screen" button, given the whole screen.
//!
//! Until 1.0.6 neither backend handled the engine's fullscreen request, so the
//! element filled the TAB's rectangle and the toolbar stayed on screen. Now the
//! window goes fullscreen, the toolbar steps aside and the page takes the
//! window, for as long as the page holds its fullscreen element.
//!
//! Only the DECISIONS live here, free of any window, so they can be tested.
//! The geometry is the platform layer's and the state is `AppState`'s.
//!
//! THE BROWSER UI IS NEVER LEFT HIDDEN BEHIND A PAGE. Fullscreen is the one
//! state in which a page owns every pixel, so anything that needs the toolbar
//! or a panel ends it first: a tab switch, closing the tab, a new load in it, a
//! modal, and every shortcut except the few that act on the page itself. The
//! engine still owns Esc, which is the user's way out from the page side, and
//! the notice says so.

use crate::shortcuts::Shortcut;

/// How long the "Press Esc to exit" notice stays up, in seconds.
pub const NOTICE_SECS: u64 = 4;

/// The tabs whose page may go fullscreen right now: the visible page, or both
/// Side by Side panes. None at all while a modal covers the window, because a
/// fullscreen page would hide the panel the user is in the middle of.
///
/// The Linux backend asks this BEFORE the window changes (its engine lets the
/// request be refused); Windows reports the change after the fact, and a page
/// outside this list then simply keeps its tab-sized fullscreen.
pub fn eligible_tabs(active: Option<u64>, pair: Option<(u64, u64)>, modal: bool) -> Vec<u64> {
    if modal {
        return Vec::new();
    }
    match (pair, active) {
        (Some((l, r)), _) => vec![l, r],
        (None, Some(id)) => vec![id],
        (None, None) => Vec::new(),
    }
}

/// Whether a shortcut may run while a page is fullscreen without ending it.
///
/// Only the ones that act on the page and need no browser UI: zoom, and
/// stepping through matches of a find that is already open. Everything else
/// either focuses the toolbar (Ctrl+L, Alt+D, F6, Ctrl+F), opens a panel, or
/// changes which page is shown, and each of those would otherwise act on UI
/// the user cannot see.
pub fn shortcut_keeps_fullscreen(shortcut: &Shortcut) -> bool {
    matches!(
        shortcut,
        Shortcut::ZoomIn
            | Shortcut::ZoomOut
            | Shortcut::ZoomReset
            | Shortcut::FindNext
            | Shortcut::FindPrevious
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modal_makes_no_page_eligible() {
        assert!(eligible_tabs(Some(1), None, true).is_empty());
        assert!(eligible_tabs(Some(1), Some((1, 2)), true).is_empty());
    }

    #[test]
    fn only_the_visible_page_or_both_panes_are_eligible() {
        assert_eq!(eligible_tabs(Some(7), None, false), vec![7]);
        assert_eq!(eligible_tabs(Some(1), Some((1, 2)), false), vec![1, 2]);
        assert!(eligible_tabs(None, None, false).is_empty());
    }

    #[test]
    fn chrome_shortcuts_end_fullscreen() {
        for s in [
            Shortcut::FocusUrlBar,
            Shortcut::OpenFind,
            Shortcut::OpenFindAcrossTabs,
            Shortcut::OpenCommandPalette,
            Shortcut::NewTab,
            Shortcut::NextTab,
            Shortcut::CloseTab,
            Shortcut::LockVault,
            Shortcut::ToggleSideBySide,
            Shortcut::ToggleReaderView,
        ] {
            assert!(!shortcut_keeps_fullscreen(&s), "{s:?} must end fullscreen");
        }
    }

    #[test]
    fn page_shortcuts_keep_fullscreen() {
        for s in [
            Shortcut::ZoomIn,
            Shortcut::ZoomOut,
            Shortcut::ZoomReset,
            Shortcut::FindNext,
            Shortcut::FindPrevious,
        ] {
            assert!(shortcut_keeps_fullscreen(&s), "{s:?} should keep fullscreen");
        }
    }
}
