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
//!
//! NO NOTICE, NO SCREEN. A page never gets the screen while the notice that
//! says how to leave cannot be drawn (release review R-004): see `entry`.

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

/// What happens to a page's request for the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// The page gets the window, and the notice says how to leave.
    Grant,
    /// Not a page that may go fullscreen now (`eligible_tabs`). Linux refuses
    /// it in the engine; on Windows the page keeps the tab-sized fullscreen
    /// every earlier build gave it. The window is not touched.
    Ineligible,
    /// The "Press Esc to exit" notice cannot be drawn, so no page gets the
    /// screen. Linux refuses it in the engine, and wherever the window was
    /// made fullscreen anyway it is given back.
    NoNotice,
}

/// The one rule for a page asking for the screen.
///
/// A page that owns every pixel can draw a fake desktop, a fake browser or a
/// fake sign-in window. The notice is the browser telling the user that a page
/// has the screen and how to take it back, so a page never gets the screen
/// while the notice cannot be drawn. That outranks eligibility: an ineligible
/// request that slipped past the engine's check (Linux, a modal opening in
/// between) still gives the window back when nothing could warn the user.
pub fn entry(eligible: bool, notice_can_draw: bool) -> Entry {
    match (eligible, notice_can_draw) {
        (_, false) => Entry::NoNotice,
        (false, true) => Entry::Ineligible,
        (true, true) => Entry::Grant,
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

    /// Every combination of the two facts (R-004).
    #[test]
    fn a_page_gets_the_screen_only_when_eligible_and_the_notice_can_draw() {
        assert_eq!(entry(true, true), Entry::Grant);
        assert_eq!(entry(false, true), Entry::Ineligible);
        assert_eq!(
            entry(true, false),
            Entry::NoNotice,
            "an eligible page was given the screen with no way to show how to leave"
        );
        assert_eq!(
            entry(false, false),
            Entry::NoNotice,
            "a notice that cannot draw must give the window back even for an ineligible page"
        );
    }

    // ---- source pins ------------------------------------------------------
    //
    // A whole AppState or a real window cannot be built in a unit test, and
    // windows.rs is not even compiled on the Linux test host. These pin the
    // wiring of `entry` and of the notice's result where it is used, so a
    // change that quietly drops either fails here rather than on a screen.

    const STATE_RS: &str = include_str!("state.rs");
    const UNIX_RS: &str = include_str!("platform/unix.rs");
    const WINDOWS_RS: &str = include_str!("platform/windows.rs");

    fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let after = source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing source marker {start:?}"))
            .1;
        after
            .split_once(end)
            .unwrap_or_else(|| panic!("missing source marker {end:?}"))
            .0
    }

    fn at(haystack: &str, needle: &str) -> usize {
        haystack
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?}"))
    }

    #[test]
    fn appstate_asks_the_rule_and_refuses_without_a_notice() {
        let body = between(
            STATE_RS,
            "pub fn on_page_fullscreen(&mut self, id: u64, on: bool) {",
            "fn refuse_page_fullscreen(&mut self) {",
        );
        assert!(
            body.contains(
                "crate::fullscreen::entry(eligible, platform::fullscreen_notice_can_draw(&self.hosts))"
            ),
            "on_page_fullscreen no longer decides through fullscreen::entry with the notice's state"
        );
        let refused = between(body, "crate::fullscreen::Entry::NoNotice => {", "}");
        assert!(
            refused.contains("self.refuse_page_fullscreen();") && refused.contains("return;"),
            "a request with no drawable notice is not refused"
        );
        let refuse = between(
            STATE_RS,
            "fn refuse_page_fullscreen(&mut self) {",
            "pub fn exit_page_fullscreen(&mut self) {",
        );
        assert!(
            refuse.contains("self.exit_page_fullscreen();")
                && refuse.contains("platform::set_page_fullscreen(&self.hosts, false);"),
            "refusing must end any page fullscreen and give the window back"
        );
    }

    #[test]
    fn the_notice_is_drawn_before_the_window_and_a_failed_draw_ends_it() {
        let body = between(
            STATE_RS,
            "pub fn on_page_fullscreen(&mut self, id: u64, on: bool) {",
            "fn refuse_page_fullscreen(&mut self) {",
        );
        let draw = at(body, "if !self.show_fullscreen_notice() {");
        let window = at(body, "platform::set_page_fullscreen(&self.hosts, true);");
        assert!(
            draw < window,
            "the window is made fullscreen before anyone knows whether the notice drew"
        );
        let failed = &body[draw..window];
        assert!(
            failed.contains("self.leave_page_fullscreen();") && failed.contains("return;"),
            "a notice that failed to draw does not end page fullscreen"
        );
        assert_eq!(
            body.matches("show_fullscreen_notice()").count(),
            1,
            "the notice is shown somewhere its result is not checked"
        );
        let show = between(
            STATE_RS,
            "fn show_fullscreen_notice(&mut self) -> bool {",
            "pub fn on_fullscreen_notice_end(",
        );
        let shown = at(show, "if !platform::set_fullscreen_notice(&self.hosts, Some(&text)) {");
        let bail = at(show, "return false;");
        let timer = at(show, "std::thread::spawn");
        assert!(
            shown < bail && bail < timer,
            "show_fullscreen_notice does not report a notice that failed to draw"
        );
    }

    #[test]
    fn both_backends_report_whether_the_notice_drew() {
        for (name, src) in [("unix.rs", UNIX_RS), ("windows.rs", WINDOWS_RS)] {
            assert!(
                src.contains("pub fn set_fullscreen_notice(hosts: &Hosts, text: Option<&str>) -> bool {"),
                "{name}: set_fullscreen_notice no longer reports whether the notice drew"
            );
            assert!(
                src.contains("pub fn fullscreen_notice_can_draw("),
                "{name}: no fullscreen_notice_can_draw for AppState to ask"
            );
            let notice = between(
                src,
                "pub fn set_fullscreen_notice(hosts: &Hosts, text: Option<&str>) -> bool {",
                "fn take_down_notice(",
            );
            assert!(
                notice.contains("Some(text) if fullscreen_notice_can_draw(hosts) =>"),
                "{name}: the notice is drawn without checking that it can be"
            );
        }
    }

    #[test]
    fn linux_refuses_in_the_engine_when_the_notice_cannot_draw() {
        let handler = between(
            UNIX_RS,
            "native.connect_enter_fullscreen(move |_view| {",
            "native.connect_leave_fullscreen(",
        );
        assert!(
            handler.contains("crate::fullscreen::entry(allowed, notice_can_draw(&styled, &readout))"),
            "the enter-fullscreen handler no longer consults the notice"
        );
        assert!(handler.contains("crate::fullscreen::Entry::Ineligible => return true"));
        let refused = between(handler, "crate::fullscreen::Entry::NoNotice => {", "}");
        assert!(
            refused.contains("return true;"),
            "the engine is not stopped when the notice cannot draw"
        );
        let can_draw = between(
            UNIX_RS,
            "fn notice_can_draw(styled: &Cell<bool>, readout: &gtk::Label) -> bool {",
            "}",
        );
        assert!(
            can_draw.contains("styled.get()") && can_draw.contains("readout.parent().is_some()"),
            "notice_can_draw no longer checks the style and the label"
        );
    }

    #[test]
    fn windows_reports_the_show_call_it_made() {
        let notice = between(
            WINDOWS_RS,
            "pub fn set_fullscreen_notice(hosts: &Hosts, text: Option<&str>) -> bool {",
            "fn take_down_notice(",
        );
        let drawn = at(notice, "if readout_draw(text, true) {");
        // The notice is an owned POPUP, not the child readout: a child never
        // showed over a fullscreen page (measured on Windows 11, 2026-10-12).
        assert!(WINDOWS_RS.contains("static NOTICE_POPUP: AtomicIsize"));
        assert!(WINDOWS_RS.contains("WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE"));
        let draw_fn = between(WINDOWS_RS, "fn readout_draw(text: &str, notice: bool) -> bool {", "fn rebuild_readout_font(");
        assert!(draw_fn.contains("NOTICE_POPUP.load(Ordering::Relaxed)") && draw_fn.contains("ClientToScreen(parent, &mut origin)"));
        assert!(
            notice[drawn..].contains("return true;"),
            "a drawn notice is not reported"
        );
        let draw = between(
            WINDOWS_RS,
            "fn readout_draw(text: &str, notice: bool) -> bool {",
            "fn rebuild_readout_font(",
        );
        let placed = at(draw, "let placed = unsafe {");
        assert!(
            draw[placed..].contains(".is_ok();"),
            "the SetWindowPos result is not what readout_draw reports"
        );
        assert!(
            draw.contains("    placed && unsafe { IsWindowVisible(hwnd) }.as_bool()\n}\n"),
            "readout_draw no longer ends by reporting the show"
        );
        let can_draw = between(
            WINDOWS_RS,
            "pub fn fullscreen_notice_can_draw(_hosts: &Hosts) -> bool {",
            "}\n",
        );
        assert!(
            can_draw.contains("NOTICE_POPUP.load") && can_draw.contains("IsWindow("),
            "fullscreen_notice_can_draw no longer checks the notice's popup window"
        );
    }
}
