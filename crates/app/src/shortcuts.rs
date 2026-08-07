//! Keyboard shortcut resolution.
//!
//! Deliberately platform-neutral and free of any windowing types: the platform
//! backends translate a native key event into `Mods` + `Key` and call
//! `resolve`, so the actual binding table is one testable function rather than
//! two divergent copies of the same `if` chain.
//!
//! Why this lives in Rust and not in page JavaScript: shortcuts must work while
//! focus is inside a web page, and content webviews have no IPC channel by
//! design. Handling keys natively is what lets Ctrl+T work on an untrusted page
//! without opening a bridge into the trusted UI.

/// Modifier state at the moment a key went down.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Mods {
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
}

impl Mods {
    pub fn new(ctrl: bool, shift: bool, alt: bool) -> Self {
        Self { ctrl, shift, alt }
    }
}

/// Only the keys any binding cares about. Anything else never reaches
/// `resolve`, so the backends can map a small fixed set of native codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    T,
    W,
    L,
    R,
    K,
    F,
    P,
    Tab,
    F5,
    F3,
    Left,
    Right,
    /// 1 through 9. Zero is not bound as a TAB shortcut -- Ctrl+0 is zoom
    /// reset, per every browser convention.
    Digit(u8),
    /// Ctrl+= is what an unshifted "+" key actually reports; both spellings
    /// are bound because keyboards and layouts disagree about which one the
    /// user pressed, and a zoom shortcut that works on one layout is a bug
    /// report from everyone else.
    Equal,
    Plus,
    Minus,
    Zero,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shortcut {
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    /// Zero-based index of the tab to select.
    SelectTab(usize),
    /// Browser convention: Ctrl+9 is the LAST tab, not the ninth.
    SelectLastTab,
    FocusUrlBar,
    Reload,
    /// Page zoom, per tab. Not a privacy control -- it is here because a
    /// browser without zoom is unusable for anyone who needs larger text, and
    /// accessibility is not a feature to defer.
    ZoomIn,
    ZoomOut,
    ZoomReset,
    Back,
    Forward,
    LockVault,
    /// Opens the chrome's own command palette. Resolved here so the key works
    /// while a content webview has focus -- see this file's top doc for why
    /// that means native, not a page-side listener.
    OpenCommandPalette,
    /// Print the PAGE.
    ///
    /// Bound natively for the same reason Ctrl+T is: left to the engine, the
    /// key lands on whichever webview holds focus, and that is usually the
    /// chrome -- so Ctrl+P printed the toolbar, footed
    /// `rbchrome.localhost/index.html`, in a dialog clipped to the strip.
    /// Resolving it here aims it at the content webview no matter what was
    /// clicked last.
    Print,

    /// Find-in-page. Bound natively for the same reason Ctrl+T is: the key
    /// must work while a content webview holds focus, and a page-side
    /// listener on the chrome would never see it. OpenFind asks the chrome
    /// to open its bar; FindNext / FindPrevious step the engine session of
    /// the active tab directly, so they work with chrome focus or page
    /// focus, no round trip through the UI.
    OpenFind,
    FindNext,
    FindPrevious,
}

/// The numeric keypad, by hardware SCAN CODE rather than virtual key.
///
/// WHY THIS EXISTS. Ctrl+= zoomed and Ctrl+keypad-plus did nothing, on a build
/// whose virtual-key table already mapped VK_ADD and whose `resolve` already
/// bound it. Every line of our own path was correct, which means the virtual
/// key arriving from the engine is not the one the keypad sent. Scan codes are
/// reported by the keyboard before any layout mapping or engine normalisation
/// can rewrite them, so they say what was physically pressed.
///
/// Only keys carrying a browser shortcut are listed; everything else returns
/// None and falls through to the page, which is what keeps typing on the
/// keypad working.
///
/// `extended` separates the keypad from the dedicated navigation cluster.
/// Keypad Enter and keypad `/` are extended keys, and so are the real Home,
/// End and arrow keys -- which share scan codes with the keypad digits. Without
/// this check, pressing Home would fire whatever keypad-7 is bound to.
pub fn keypad_scan_code(scan: u32, extended: bool) -> Option<Key> {
    if extended {
        return None;
    }
    let key = match scan {
        0x4E => Key::Plus,     // keypad +
        0x4A => Key::Minus,    // keypad -
        0x52 => Key::Zero,     // keypad 0
        0x4F => Key::Digit(1), // keypad 1..9, in physical row order
        0x50 => Key::Digit(2),
        0x51 => Key::Digit(3),
        0x4B => Key::Digit(4),
        0x4C => Key::Digit(5),
        0x4D => Key::Digit(6),
        0x47 => Key::Digit(7),
        0x48 => Key::Digit(8),
        0x49 => Key::Digit(9),
        _ => return None,
    };
    Some(key)
}

/// Translates the few Win32 virtual-key codes any binding uses. Letter and
/// digit codes are the ASCII values of their uppercase forms.
pub fn vk_key(virtual_key: u32) -> Option<Key> {
    const VK_TAB: u32 = 0x09;
    const VK_F5: u32 = 0x74;
    const VK_LEFT: u32 = 0x25;
    const VK_RIGHT: u32 = 0x27;
    const VK_OEM_PLUS: u32 = 0xBB;
    const VK_OEM_MINUS: u32 = 0xBD;
    const VK_ADD: u32 = 0x6B;
    const VK_SUBTRACT: u32 = 0x6D;
    const VK_NUMPAD0: u32 = 0x60;
    let key = match virtual_key {
        0x54 => Key::T,
        0x57 => Key::W,
        0x4C => Key::L,
        0x52 => Key::R,
        0x4B => Key::K,
        0x46 => Key::F,
        0x50 => Key::P,
        VK_TAB => Key::Tab,
        VK_F5 => Key::F5,
        0x72 => Key::F3,
        VK_LEFT => Key::Left,
        VK_RIGHT => Key::Right,
        // Zoom. VK_OEM_PLUS/MINUS are the main-row keys and report the same
        // code shifted or not, so Ctrl+= and Ctrl++ both arrive here; the
        // keypad has separate codes. Binding only one spelling is how a
        // shortcut works on the author's keyboard and nowhere else.
        VK_OEM_PLUS => Key::Equal,
        VK_ADD => Key::Plus,
        VK_OEM_MINUS | VK_SUBTRACT => Key::Minus,
        0x30 | VK_NUMPAD0 => Key::Zero,
        // '1'..='9' on the number row, then the numeric keypad.
        code @ 0x31..=0x39 => Key::Digit((code - 0x30) as u8),
        code @ 0x61..=0x69 => Key::Digit((code - 0x60) as u8),
        _ => return None,
    };
    Some(key)
}

/// Maps a key press to an action, or None to let the page have the key.
///
/// Returning None matters as much as returning Some: a page's own Ctrl+F or
/// text input must keep working, so anything not explicitly bound falls
/// through untouched.
pub fn resolve(mods: Mods, key: Key) -> Option<Shortcut> {
    match key {
        // Ctrl+Shift+L locks the vault; Ctrl+L focuses the URL bar. Checked
        // shift-first so the more specific binding wins.
        Key::L if mods.ctrl && mods.shift && !mods.alt => Some(Shortcut::LockVault),
        Key::L if mods.ctrl && !mods.alt => Some(Shortcut::FocusUrlBar),

        Key::T if mods.ctrl && !mods.alt => Some(Shortcut::NewTab),
        Key::W if mods.ctrl && !mods.alt => Some(Shortcut::CloseTab),
        Key::R if mods.ctrl && !mods.alt => Some(Shortcut::Reload),
        Key::K if mods.ctrl && !mods.alt => Some(Shortcut::OpenCommandPalette),
        Key::P if mods.ctrl && !mods.alt => Some(Shortcut::Print),
        // Swallowing Ctrl+F takes the key away from pages that implement
        // their own find. That is deliberate: the engine's default find UI
        // is suppressed (windows.rs), so a page-side find would open nothing,
        // and one find bar -- ours, with honest counts -- answers everywhere.
        Key::F if mods.ctrl && !mods.alt => Some(Shortcut::OpenFind),

        Key::Tab if mods.ctrl && mods.shift && !mods.alt => Some(Shortcut::PrevTab),
        Key::Tab if mods.ctrl && !mods.alt => Some(Shortcut::NextTab),

        // F5 is unmodified by convention; Ctrl+F5 (hard reload) is not
        // distinguished because there is no cache-bypass API to hang it on.
        Key::F5 if !mods.ctrl && !mods.shift && !mods.alt => Some(Shortcut::Reload),

        // F3 continues a find from anywhere, per browser convention. With no
        // live session the platform call is an honest no-op, so there is no
        // state check here.
        Key::F3 if !mods.ctrl && !mods.shift && !mods.alt => Some(Shortcut::FindNext),
        Key::F3 if !mods.ctrl && mods.shift && !mods.alt => Some(Shortcut::FindPrevious),

        Key::Left if mods.alt && !mods.ctrl => Some(Shortcut::Back),
        Key::Right if mods.alt && !mods.ctrl => Some(Shortcut::Forward),

        // Zoom. Ctrl+0 resets, matching every browser; it is deliberately not
        // a tab selector, which is why Digit() starts at 1.
        Key::Equal | Key::Plus if mods.ctrl && !mods.alt => Some(Shortcut::ZoomIn),
        Key::Minus if mods.ctrl && !mods.alt => Some(Shortcut::ZoomOut),
        Key::Zero if mods.ctrl && !mods.alt => Some(Shortcut::ZoomReset),

        Key::Digit(9) if mods.ctrl && !mods.alt => Some(Shortcut::SelectLastTab),
        Key::Digit(n) if mods.ctrl && !mods.alt && (1..=8).contains(&n) => {
            Some(Shortcut::SelectTab(usize::from(n) - 1))
        }

        _ => None,
    }
}

#[cfg(test)]
mod zoom_tests {
    use super::*;

    fn ctrl() -> Mods {
        Mods { ctrl: true, shift: false, alt: false }
    }

    #[test]
    fn every_spelling_of_the_zoom_keys_is_bound() {
        // Layouts and keypads disagree about which code a "+" press reports.
        // Binding one of them is how a shortcut works on the author's keyboard
        // and generates bug reports from everyone else, so both main-row and
        // keypad spellings map to the same action.
        for k in [Key::Equal, Key::Plus] {
            assert_eq!(resolve(ctrl(), k), Some(Shortcut::ZoomIn), "{k:?}");
        }
        assert_eq!(resolve(ctrl(), Key::Minus), Some(Shortcut::ZoomOut));
        assert_eq!(resolve(ctrl(), Key::Zero), Some(Shortcut::ZoomReset));
    }

    #[test]
    fn zoom_needs_ctrl_and_leaves_the_page_alone_without_it() {
        // Unmodified "-" and "0" are text the user is typing. Swallowing them
        // would break every form on the web.
        let none = Mods { ctrl: false, shift: false, alt: false };
        for k in [Key::Equal, Key::Plus, Key::Minus, Key::Zero] {
            assert_eq!(resolve(none, k), None, "{k:?} must reach the page");
        }
    }

    #[test]
    fn the_keypad_reaches_the_same_shortcuts_as_the_main_row() {
        // The defect this exists for: Ctrl+= zoomed, Ctrl+keypad-plus did not.
        // Asserted through `resolve` rather than on the mapping alone, because
        // a scan code that decodes to a Key nothing binds is still a dead key.
        for (scan, want) in [
            (0x4E, Shortcut::ZoomIn),
            (0x4A, Shortcut::ZoomOut),
            (0x52, Shortcut::ZoomReset),
        ] {
            let key = keypad_scan_code(scan, false)
                .unwrap_or_else(|| panic!("keypad scan {scan:#04x} decoded to nothing"));
            assert_eq!(resolve(ctrl(), key), Some(want), "scan {scan:#04x}");
        }
    }

    #[test]
    fn the_keypad_digits_select_tabs_like_the_number_row() {
        for (scan, n) in [(0x4F, 1), (0x4B, 4), (0x47, 7), (0x49, 9)] {
            assert_eq!(
                keypad_scan_code(scan, false),
                Some(Key::Digit(n)),
                "keypad {n} (scan {scan:#04x})"
            );
        }
    }

    #[test]
    fn the_navigation_cluster_is_not_mistaken_for_the_keypad() {
        // Home, End and the arrows share scan codes with keypad 7, 1 and the
        // rest; the extended-key bit is the only thing telling them apart. Get
        // this wrong and pressing Home jumps to a tab.
        for scan in [0x47, 0x4F, 0x4B, 0x4D, 0x52, 0x49] {
            assert_eq!(
                keypad_scan_code(scan, true),
                None,
                "extended scan {scan:#04x} must not be read as a keypad key"
            );
        }
    }

    #[test]
    fn unbound_keypad_keys_fall_through_to_the_page() {
        // Keypad * and . carry no shortcut, and must stay typeable.
        for scan in [0x37, 0x53] {
            assert_eq!(keypad_scan_code(scan, false), None, "scan {scan:#04x}");
        }
    }

    #[test]
    fn ctrl_zero_is_zoom_reset_not_a_tab_selector() {
        // Ctrl+1..8 select tabs and Ctrl+9 selects the LAST one. Ctrl+0 is
        // zoom reset in every mainstream browser, which is why Digit() starts
        // at 1 rather than 0.
        assert_eq!(resolve(ctrl(), Key::Zero), Some(Shortcut::ZoomReset));
        assert_eq!(resolve(ctrl(), Key::Digit(9)), Some(Shortcut::SelectLastTab));
        assert_eq!(resolve(ctrl(), Key::Digit(1)), Some(Shortcut::SelectTab(0)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Mods = Mods {
        ctrl: false,
        shift: false,
        alt: false,
    };
    const CTRL: Mods = Mods {
        ctrl: true,
        shift: false,
        alt: false,
    };
    const CTRL_SHIFT: Mods = Mods {
        ctrl: true,
        shift: true,
        alt: false,
    };
    const ALT: Mods = Mods {
        ctrl: false,
        shift: false,
        alt: true,
    };

    #[test]
    fn tab_management_bindings() {
        assert_eq!(resolve(CTRL, Key::T), Some(Shortcut::NewTab));
        assert_eq!(resolve(CTRL, Key::W), Some(Shortcut::CloseTab));
        assert_eq!(resolve(CTRL, Key::Tab), Some(Shortcut::NextTab));
        assert_eq!(resolve(CTRL_SHIFT, Key::Tab), Some(Shortcut::PrevTab));
    }

    #[test]
    fn ctrl_shift_l_locks_rather_than_focusing_the_url_bar() {
        // The two L bindings overlap; the more specific one must win, or
        // locking the vault would silently focus the URL bar instead.
        assert_eq!(resolve(CTRL, Key::L), Some(Shortcut::FocusUrlBar));
        assert_eq!(resolve(CTRL_SHIFT, Key::L), Some(Shortcut::LockVault));
    }

    #[test]
    fn digits_select_tabs_and_nine_means_last() {
        assert_eq!(resolve(CTRL, Key::Digit(1)), Some(Shortcut::SelectTab(0)));
        assert_eq!(resolve(CTRL, Key::Digit(8)), Some(Shortcut::SelectTab(7)));
        assert_eq!(resolve(CTRL, Key::Digit(9)), Some(Shortcut::SelectLastTab));
    }

    #[test]
    fn reload_accepts_ctrl_r_and_bare_f5() {
        assert_eq!(resolve(CTRL, Key::R), Some(Shortcut::Reload));
        assert_eq!(resolve(NONE, Key::F5), Some(Shortcut::Reload));
    }

    #[test]
    fn alt_arrows_navigate_history() {
        assert_eq!(resolve(ALT, Key::Left), Some(Shortcut::Back));
        assert_eq!(resolve(ALT, Key::Right), Some(Shortcut::Forward));
    }

    #[test]
    fn unmodified_keys_belong_to_the_page() {
        // Typing "t" into a text field must never open a tab.
        assert_eq!(resolve(NONE, Key::T), None);
        assert_eq!(resolve(NONE, Key::L), None);
        assert_eq!(resolve(NONE, Key::Digit(1)), None);
        assert_eq!(resolve(NONE, Key::Tab), None);
        assert_eq!(resolve(NONE, Key::Left), None);
    }

    #[test]
    fn alt_combinations_do_not_trigger_ctrl_bindings() {
        // AltGr on many layouts reports as Ctrl+Alt; treating that as Ctrl
        // would hijack keys used to type characters like @ and #.
        let ctrl_alt = Mods::new(true, false, true);
        assert_eq!(resolve(ctrl_alt, Key::T), None);
        assert_eq!(resolve(ctrl_alt, Key::W), None);
        assert_eq!(resolve(ctrl_alt, Key::Digit(1)), None);
    }

    #[test]
    fn modified_f5_is_left_alone() {
        assert_eq!(resolve(CTRL_SHIFT, Key::F5), None);
    }

    #[test]
    fn ctrl_p_prints_the_page_and_p_alone_does_not() {
        assert_eq!(resolve(CTRL, Key::P), Some(Shortcut::Print));
        // Unbound, this key reached the engine and printed the CHROME. The
        // binding is what stops that, so its absence is the regression.
        assert_eq!(resolve(NONE, Key::P), None, "typing \"p\" belongs to the page");
    }

    /// EVERY key this resolver binds must be one the WINDOWS table can
    /// actually produce.
    ///
    /// The unix table lost its entries for the letters k and p, so Ctrl+K
    /// (the command palette the onboarding tour tells users to press) and
    /// Ctrl+P were dead on that platform while `resolve` answered both
    /// happily and the Windows build worked. The mirror of that test lives in
    /// platform/unix.rs, where the gdk constants are; this one covers Windows
    /// from any host, which is why `vk_key` was moved next to the resolver
    /// instead of staying in a file the Linux CI cannot compile.
    #[test]
    fn every_shortcut_key_can_be_produced_on_windows() {
        // (virtual-key code, what the resolver calls it). Letter and digit
        // codes are the ASCII values of their uppercase forms.
        let table: &[(u32, Key)] = &[
            (0x54, Key::T),
            (0x57, Key::W),
            (0x4C, Key::L),
            (0x52, Key::R),
            (0x4B, Key::K),
            (0x46, Key::F),
            (0x50, Key::P),
            (0x09, Key::Tab),
            (0x74, Key::F5),
            (0x72, Key::F3),
            (0x25, Key::Left),
            (0x27, Key::Right),
        ];
        for (vk, expected) in table {
            assert_eq!(
                vk_key(*vk),
                Some(*expected),
                "the Windows table cannot produce {expected:?}, so every \
                 shortcut bound to it is dead there"
            );
        }
        // The property, stated as a property rather than a list: a key bound
        // under Ctrl must not be one the platform drops before the resolver
        // ever sees it.
        let ctrl = Mods::new(true, false, false);
        for (vk, expected) in table {
            if resolve(ctrl, *expected).is_some() {
                assert!(
                    vk_key(*vk).is_some(),
                    "Ctrl+{expected:?} resolves to a shortcut but the Windows \
                     table drops the key first"
                );
            }
        }
        // The two shortcuts that were dead on the other platform, pinned by
        // name so a future edit to this table has to look at them.
        assert_eq!(
            vk_key(0x4B).and_then(|k| resolve(ctrl, k)),
            Some(Shortcut::OpenCommandPalette)
        );
        assert_eq!(
            vk_key(0x50).and_then(|k| resolve(ctrl, k)),
            Some(Shortcut::Print)
        );
    }

    #[test]
    fn ctrl_k_opens_the_command_palette() {
        assert_eq!(resolve(CTRL, Key::K), Some(Shortcut::OpenCommandPalette));
        assert_eq!(resolve(NONE, Key::K), None, "typing \"k\" belongs to the page");
    }

    #[test]
    fn ctrl_f_opens_find_and_f_alone_belongs_to_the_page() {
        assert_eq!(resolve(CTRL, Key::F), Some(Shortcut::OpenFind));
        assert_eq!(resolve(NONE, Key::F), None, "typing \"f\" belongs to the page");
        // AltGr reports as Ctrl+Alt on many layouts; it must not open find.
        assert_eq!(resolve(Mods::new(true, false, true), Key::F), None);
    }

    #[test]
    fn f3_continues_find_and_shift_f3_goes_backwards() {
        assert_eq!(resolve(NONE, Key::F3), Some(Shortcut::FindNext));
        assert_eq!(
            resolve(Mods::new(false, true, false), Key::F3),
            Some(Shortcut::FindPrevious)
        );
        // Ctrl+F3 is nobody's binding; it falls through to the page.
        assert_eq!(resolve(CTRL, Key::F3), None);
    }
}
