//! Platform abstraction over the two webview backends.
//!
//! Everything GTK/WebKitGTK (unix) or WebView2/child-window (Windows)
//! specific lives in the per-platform module re-exported here, so main.rs,
//! state.rs and ipc.rs stay free of `#[cfg]`. Both modules expose the same
//! surface: `Hosts`/`TabView`, chrome/content webview construction, tab
//! show/hide/remove, chrome height, layout, and the privacy controls
//! (per-tab `TabPolicy`, network+cosmetic ad blocking, network freeze with
//! ledger, quarantine preset, TLS-interception state).
//!
//! The engine-free half of the privacy features — rule matching, ledger
//! accounting, the freeze state machine, TLS issuer classification, and the
//! platform-neutral API types — lives in `privacy`. It is pure code with
//! unit tests, because `cargo test` must be able to prove the security
//! properties (a blocked request never leaves the machine, freezing is
//! per-tab and reversible) without a display. The backends only adapt
//! engine callbacks to those functions.

use std::path::{Path, PathBuf};

/// How the chrome and the page share the window.
///
/// THREE STATES, NOT TWO BOOLEANS. Overlay-and-split is not a thing, and an
/// enum makes that unrepresentable rather than something a caller has to
/// remember. It grew out of a `bool overlay`, which was fine while there were
/// exactly two arrangements and would have become a pair of flags with one
/// illegal combination the moment a third arrived.
///
/// The shapes are possible at all because of an ordering fact recorded in the
/// Windows backend: content webviews are created AFTER the chrome, so a
/// content webview DRAWS OVER the chrome where the two overlap. Nothing is
/// composited -- these are sibling child windows -- so every arrangement here
/// is a matter of which rectangle is given to whom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChromeLayout {
    /// The chrome is a strip at the top; the page gets everything below it.
    Strip,
    /// A modal covers the window: the chrome takes all of it. What happens
    /// to the page depends on the backend's answer to `chrome_caps`: where
    /// the translucent lift is armed (Windows, modern runtime) the page
    /// keeps its rectangle, keeps rendering, and shows through a genuinely
    /// transparent chrome behind a dimming scrim; everywhere else the page
    /// is given a zero rect, is genuinely NOT VISIBLE, and the UI must not
    /// imply otherwise. The stylesheet keys the scrim on the same answer,
    /// so each mode tells its own truth.
    Overlay,
    /// A docked pane. The chrome takes the whole window and the page is given
    /// the area below the strip and LEFT of the pane, so it draws over the
    /// chrome everywhere except the strip and the pane's column -- which is
    /// exactly where the pane renders.
    Split { pane_width: i32 },
}

impl ChromeLayout {
    /// Width reserved on the right for a docked pane, zero in every other
    /// arrangement.
    pub fn pane_width(self) -> i32 {
        match self {
            Self::Split { pane_width } => pane_width.max(0),
            _ => 0,
        }
    }
}

/// Rate-limit for the "a human is here" signal both key hooks raise.
///
/// A keydown hook fires per character, so typing a sentence would send fifty
/// events through the loop to set one timestamp fifty times. The auto-lock
/// only needs to know somebody was present within the last few seconds, so one
/// event every five is exactly as accurate and costs nothing.
///
/// Shared by both backends so the two cannot drift into different rates and
/// give the vault different behaviour per platform.
pub fn presence_throttle_elapsed() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const EVERY_MS: u64 = 5_000;
    static LAST_MS: AtomicU64 = AtomicU64::new(0);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let last = LAST_MS.load(Ordering::Relaxed);
    // `now < last` is a clock that went backwards: treat it as due rather than
    // as a reason to stop reporting presence until the clock catches up.
    if now_ms < last || now_ms.saturating_sub(last) >= EVERY_MS {
        LAST_MS.store(now_ms, Ordering::Relaxed);
        return true;
    }
    false
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

// The pure half of the Windows page-bytes path: which response IS the
// document, and the per-tab cache. Compiled on Windows for use, and under
// `cfg(test)` everywhere so its decision logic is tested on the Linux build
// machine -- the COM half around it cannot run here at all. Excluded from
// ordinary unix builds, where nothing calls it.
#[cfg(any(windows, test))]
pub mod main_resource;

mod hostset;
pub use hostset::HostSet;
// The blocklist's host hash, re-exported for the public-suffix matcher. Same
// function deliberately: both compile a text list into sorted hashes at build
// time and look candidates up at runtime, and a second hash implementation
// would be a second thing that can silently disagree with its own build step.
pub use hostset::hash_host;

// pub(crate): the session-receipt helpers (fold/read/gate) are called from
// ipc.rs and state.rs; everything else in it stays crate-internal anyway.
pub(crate) mod privacy;
pub use privacy::*;

/// Right-click menu command ids.
///
/// Here rather than in `platform::windows` because `AppState` interprets them
/// and `AppState` is cross-platform: keeping the ids beside the Win32 code
/// that builds the menu would mean state.rs could only see them on one target,
/// and a `#[cfg]` in the middle of a match arm is how the two ends drift.
///
/// NONE MAY BE ZERO. `TrackPopupMenu` with `TPM_RETURNCMD` returns 0 to mean
/// "dismissed without choosing", so a zero id would make a dismissal
/// indistinguishable from a command.
pub mod menu_ids {
    pub const OPEN_NEW_TAB: u32 = 1;
    pub const OPEN_BACKGROUND: u32 = 2;
    pub const OPEN_EPHEMERAL: u32 = 3;
    pub const OPEN_QUARANTINE: u32 = 4;
    pub const COPY_LINK: u32 = 5;
    pub const COPY_LINK_CLEAN: u32 = 6;
    // Image actions carry the image source in the same `target` slot of the
    // event that link actions use for the link: one URL per event, never
    // both, and state.rs re-validates it like every menu-opened URL.
    pub const OPEN_IMAGE_NEW_TAB: u32 = 7;
    pub const COPY_IMAGE: u32 = 8;
    // Navigation acts on the ACTIVE tab (the right-clicked tab is the active
    // one) and carries no URL at all.
    pub const HISTORY_BACK: u32 = 9;
    pub const HISTORY_FORWARD: u32 = 10;
    pub const HISTORY_RELOAD: u32 = 11;
    // There is deliberately NO id for cut/copy/paste/select-all: those are
    // engine-local editing commands (WebKit's execute_editing_command on
    // Linux, WebView2's SetSelectedCommandId on Windows), run entirely in
    // the platform layer. state.rs cannot reach the content webview's
    // editing state, so routing them through a menu id here would be a lie
    // about where they execute. See menu_compose::Editing.
}

/// WHAT SHOWS FOR WHICH TARGET. The single, platform-free decision point for
/// the context menu's contents: each engine reduces its right-click data
/// (WebView2's ContextMenuTarget, WebKit's HitTestResult) to a `Target`, and
/// the platform files render exactly what `compose` returns. Kept free of
/// COM, GTK and wry so `cargo test` pins the behaviour with no display.
pub mod menu_compose {
    use super::menu_ids;

    /// The facts about the click the menu cares about. Flags, not the
    /// engine's kind enum, because targets combine: a linked image is both
    /// `link` and `image`, and an editable field may carry a selection.
    /// `link`/`image` are set only when the engine also supplied the URI --
    /// a flag with nothing to act on would produce a dead row.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Target {
        pub link: bool,
        pub image: bool,
        pub editable: bool,
        pub selection: bool,
    }

    /// A command the ENGINE runs on the content webview itself: WebKit's
    /// `execute_editing_command` on Linux, WebView2's `SetSelectedCommandId`
    /// on Windows. These never become a `menu_ids` round trip through
    /// state.rs, because state.rs cannot reach the content webview's editing
    /// state; only the engine can.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Editing {
        Cut,
        Copy,
        Paste,
        SelectAll,
    }

    impl Editing {
        /// The label every platform shows.
        pub fn label(self) -> &'static str {
            match self {
                Editing::Cut => "Cut",
                Editing::Copy => "Copy",
                Editing::Paste => "Paste",
                Editing::SelectAll => "Select all",
            }
        }

        /// WebKitGTK's command string for `execute_editing_command` (Linux).
        /// Windows matches the engine's default menu items by their
        /// unlocalized `Name`, which uses the same identifiers.
        pub fn engine_command(self) -> &'static str {
            match self {
                Editing::Cut => "cut",
                Editing::Copy => "copy",
                Editing::Paste => "paste",
                Editing::SelectAll => "selectAll",
            }
        }

        /// The WebKitGTK `execute_editing_command` spelling (capitalised).
        pub fn webkit_command(self) -> &'static str {
            match self {
                Editing::Cut => "Cut",
                Editing::Copy => "Copy",
                Editing::Paste => "Paste",
                Editing::SelectAll => "SelectAll",
            }
        }
    }

    /// One row of the menu before a platform gives it a widget or a Win32 id.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Entry {
        /// A `menu_ids` value; a chosen one goes to state.rs, the single
        /// interpreter of menu ids.
        Action(u32),
        /// An engine-local editing command; the platform layer executes it
        /// and nothing is sent to state.rs.
        Editing(Editing),
        Separator,
    }

    /// The label every platform shows for a cross-platform action. Kept here
    /// rather than in the platform files so the two menus cannot drift in
    /// wording. None for an id this build does not know: the platform skips
    /// the row rather than rendering a blank one.
    pub fn action_label(id: u32) -> Option<&'static str> {
        match id {
            menu_ids::OPEN_NEW_TAB => Some("Open link in new tab"),
            menu_ids::OPEN_BACKGROUND => Some("Open link in background tab"),
            menu_ids::OPEN_EPHEMERAL => Some("Open link in ephemeral tab"),
            menu_ids::OPEN_QUARANTINE => Some("Open link in quarantine tab"),
            menu_ids::COPY_LINK => Some("Copy link"),
            // "known tracking parameters", never "clean link": the list is
            // closed and finite, so promising a tracker-free URL would be a
            // claim this cannot keep.
            // "known" is load-bearing in both halves: the wrapper list and the
            // tracking-parameter list are both finite and curated, so this
            // entry handles the shapes we recognise and says so. Never "clean
            // link", which would promise a general guarantee neither list can
            // give.
            menu_ids::COPY_LINK_CLEAN => {
                Some("Copy link without known redirects or tracking parameters")
            }
            menu_ids::OPEN_IMAGE_NEW_TAB => Some("Open image in new tab"),
            menu_ids::COPY_IMAGE => Some("Copy image address"),
            menu_ids::HISTORY_BACK => Some("Back"),
            menu_ids::HISTORY_FORWARD => Some("Forward"),
            menu_ids::HISTORY_RELOAD => Some("Reload"),
            _ => None,
        }
    }

    /// The entries for a target, in display order. Sections joined by one
    /// Separator each: link (opens then copies), image (open then copy
    /// address), editing (see below), else back/forward/reload.
    ///
    /// EDITING: an editable field gets all four commands (Cut, Copy, Paste,
    /// Select all) -- the same set every browser shows; cut/copy simply
    /// no-op when there is no selection, which is what the engine does
    /// anyway, and is less surprising than rows that appear and vanish. A
    /// non-editable selection gets Copy and Select all. The editable section
    /// takes precedence over the selection-only one, so a selection inside a
    /// field never yields a second, engine-less copy row.
    ///
    /// NEVER EMPTY: every right-click gets a menu, which is the point. There
    /// is deliberately no "Save image": WebView2 gives the host no way to
    /// start a download (see the Windows file), and a menu that differs by
    /// platform for it is worse than one that omits it on both.
    pub fn compose(target: Target) -> Vec<Entry> {
        let mut sections: Vec<Vec<Entry>> = Vec::new();

        if target.link {
            sections.push(vec![
                Entry::Action(menu_ids::OPEN_NEW_TAB),
                Entry::Action(menu_ids::OPEN_BACKGROUND),
                Entry::Action(menu_ids::OPEN_EPHEMERAL),
                Entry::Action(menu_ids::OPEN_QUARANTINE),
                Entry::Separator,
                Entry::Action(menu_ids::COPY_LINK),
                Entry::Action(menu_ids::COPY_LINK_CLEAN),
            ]);
        }
        if target.image {
            sections.push(vec![
                Entry::Action(menu_ids::OPEN_IMAGE_NEW_TAB),
                Entry::Action(menu_ids::COPY_IMAGE),
            ]);
        }
        if target.editable {
            sections.push(vec![
                Entry::Editing(Editing::Cut),
                Entry::Editing(Editing::Copy),
                Entry::Editing(Editing::Paste),
                Entry::Editing(Editing::SelectAll),
            ]);
        } else if target.selection {
            sections.push(vec![
                Entry::Editing(Editing::Copy),
                Entry::Editing(Editing::SelectAll),
            ]);
        }
        if sections.is_empty() {
            sections.push(vec![
                Entry::Action(menu_ids::HISTORY_BACK),
                Entry::Action(menu_ids::HISTORY_FORWARD),
                Entry::Action(menu_ids::HISTORY_RELOAD),
            ]);
        }

        let mut entries = Vec::new();
        for section in sections {
            if !entries.is_empty() {
                entries.push(Entry::Separator);
            }
            entries.extend(section);
        }
        entries
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const ALL_IDS: [u32; 11] = [
            menu_ids::OPEN_NEW_TAB,
            menu_ids::OPEN_BACKGROUND,
            menu_ids::OPEN_EPHEMERAL,
            menu_ids::OPEN_QUARANTINE,
            menu_ids::COPY_LINK,
            menu_ids::COPY_LINK_CLEAN,
            menu_ids::OPEN_IMAGE_NEW_TAB,
            menu_ids::COPY_IMAGE,
            menu_ids::HISTORY_BACK,
            menu_ids::HISTORY_FORWARD,
            menu_ids::HISTORY_RELOAD,
        ];

        #[test]
        fn no_menu_id_is_zero_and_every_id_is_labelled() {
            for id in ALL_IDS {
                assert_ne!(id, 0);
                assert!(action_label(id).is_some(), "menu id {id} has no label");
            }
            // Ids are unique: a collision would route one action to another.
            let mut seen = std::collections::HashSet::new();
            for id in ALL_IDS {
                assert!(seen.insert(id), "duplicate menu id {id}");
            }
        }

        #[test]
        fn plain_page_gets_navigation_only() {
            assert_eq!(
                compose(Target::default()),
                vec![
                    Entry::Action(menu_ids::HISTORY_BACK),
                    Entry::Action(menu_ids::HISTORY_FORWARD),
                    Entry::Action(menu_ids::HISTORY_RELOAD),
                ]
            );
        }

        #[test]
        fn link_gets_opens_then_copies() {
            assert_eq!(
                compose(Target { link: true, ..Target::default() }),
                vec![
                    Entry::Action(menu_ids::OPEN_NEW_TAB),
                    Entry::Action(menu_ids::OPEN_BACKGROUND),
                    Entry::Action(menu_ids::OPEN_EPHEMERAL),
                    Entry::Action(menu_ids::OPEN_QUARANTINE),
                    Entry::Separator,
                    Entry::Action(menu_ids::COPY_LINK),
                    Entry::Action(menu_ids::COPY_LINK_CLEAN),
                ]
            );
        }

        #[test]
        fn image_gets_open_then_copy() {
            assert_eq!(
                compose(Target { image: true, ..Target::default() }),
                vec![
                    Entry::Action(menu_ids::OPEN_IMAGE_NEW_TAB),
                    Entry::Action(menu_ids::COPY_IMAGE),
                ]
            );
        }

        #[test]
        fn linked_image_composes_both_sections_with_one_separator() {
            assert_eq!(
                compose(Target { link: true, image: true, ..Target::default() }),
                vec![
                    Entry::Action(menu_ids::OPEN_NEW_TAB),
                    Entry::Action(menu_ids::OPEN_BACKGROUND),
                    Entry::Action(menu_ids::OPEN_EPHEMERAL),
                    Entry::Action(menu_ids::OPEN_QUARANTINE),
                    Entry::Separator,
                    Entry::Action(menu_ids::COPY_LINK),
                    Entry::Action(menu_ids::COPY_LINK_CLEAN),
                    Entry::Separator,
                    Entry::Action(menu_ids::OPEN_IMAGE_NEW_TAB),
                    Entry::Action(menu_ids::COPY_IMAGE),
                ]
            );
        }

        #[test]
        fn editable_gets_all_four_editing_commands() {
            let want = vec![
                Entry::Editing(Editing::Cut),
                Entry::Editing(Editing::Copy),
                Entry::Editing(Editing::Paste),
                Entry::Editing(Editing::SelectAll),
            ];
            assert_eq!(compose(Target { editable: true, ..Target::default() }), want);
            // Selection inside a field does not add a second copy section.
            assert_eq!(
                compose(Target { editable: true, selection: true, ..Target::default() }),
                want
            );
        }

        #[test]
        fn selection_alone_gets_copy_and_select_all() {
            assert_eq!(
                compose(Target { selection: true, ..Target::default() }),
                vec![
                    Entry::Editing(Editing::Copy),
                    Entry::Editing(Editing::SelectAll),
                ]
            );
        }

        #[test]
        fn separators_are_only_ever_between_rows_and_menu_is_never_empty() {
            let targets = [
                Target::default(),
                Target { link: true, ..Target::default() },
                Target { image: true, ..Target::default() },
                Target { link: true, image: true, ..Target::default() },
                Target { editable: true, ..Target::default() },
                Target { editable: true, selection: true, ..Target::default() },
                Target { selection: true, ..Target::default() },
                Target { link: true, image: true, editable: true, selection: true },
            ];
            for target in targets {
                let entries = compose(target);
                assert!(!entries.is_empty(), "every right-click gets a menu");
                assert_ne!(entries.first(), Some(&Entry::Separator));
                assert_ne!(entries.last(), Some(&Entry::Separator));
                for pair in entries.windows(2) {
                    assert!(
                        pair != [Entry::Separator, Entry::Separator],
                        "adjacent separators for {target:?}"
                    );
                }
                for entry in &entries {
                    if let Entry::Action(id) = entry {
                        assert_ne!(*id, 0);
                        assert!(action_label(*id).is_some());
                    }
                }
            }
        }
    }
}

/// Initial height of the chrome strip in logical pixels (IPC clamps updates
/// to 120..=600). AppState stores the current value because Windows must
/// re-apply it on every resize, unlike GTK where the size request persists
/// on the widget.
pub const CHROME_HEIGHT_PX: i32 = 120;

/// Chrome UI origin. WebKitGTK serves custom protocols at their real
/// scheme, but WebView2 cannot register non-standard schemes and wry
/// rewrites `rbchrome://...` to `http://rbchrome.localhost/...`, so the
/// boot URL is platform-specific. The page's 'self'-based CSP is
/// origin-relative and needs no change for either form.
#[cfg(unix)]
pub const CHROME_URL: &str = "rbchrome://localhost/index.html";
/// See the unix arm.
#[cfg(windows)]
pub const CHROME_URL: &str = "http://rbchrome.localhost/index.html";

/// Exact navigation allowlist prefix for the chrome webview. This must
/// match the platform's origin form precisely — anything looser (e.g. "any
/// http: URL", to accommodate the WebView2 form) would let the trusted
/// chrome webview navigate onto the open web.
#[cfg(unix)]
pub const CHROME_ORIGIN_PREFIX: &str = "rbchrome://";
/// See the unix arm.
#[cfg(windows)]
pub const CHROME_ORIGIN_PREFIX: &str = "http://rbchrome.localhost/";

/// Minimum WebKitGTK the browser will run unwarned.
///
/// 2.52.5 is the fix version for WSA-2026-0004 (10 July 2026), which covers 23
/// CVEs including several "processing maliciously crafted web content may lead
/// to memory corruption". Every one of them is reachable by visiting a page,
/// which is the entire job of this program.
///
/// This is a RUNTIME floor, not a build-time one. WebKitGTK is linked
/// dynamically, so the version we compiled against says nothing about the
/// version that will be loaded on a user's machine.
///
/// Debian 12 (bookworm) ships 2.50.6 and will never ship the fix: the Debian
/// security tracker marks webkit2gtk in bookworm END-OF-LIFE (see DSA-6232-1),
/// so waiting for it is not a plan. The fix is in trixie security as
/// 2.52.5-1~deb13u1 (DSA-6398-1). A native build on bookworm is therefore
/// permanently below this floor, which is why `enforce_engine_floor` refuses
/// to start a release build rather than merely printing a line.
///
/// Raise this whenever a new advisory lands. It is not a compatibility
/// minimum and should never be lowered to silence the banner.
pub const MIN_WEBKITGTK: (u32, u32, u32) = (2, 52, 5);

/// What engine is actually underneath us, and is it old enough to be a
/// known-vulnerable one. Reported to the chrome UI so the answer lives
/// somewhere the user can see rather than only in a release note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineInfo {
    /// Display name, e.g. "WebKitGTK" or "WebView2".
    pub name: &'static str,
    /// Runtime version if it could be determined.
    pub version: Option<(u32, u32, u32)>,
    /// Human-readable state of the engine's own tracker defence. Separate
    /// from the content blocker, which is ours.
    pub tracking_prevention: &'static str,
    /// True only when a version was determined AND it is below the floor.
    /// Unknown is not treated as unsafe: a false alarm every launch trains
    /// the user to ignore the banner, which costs more than it buys.
    pub below_floor: bool,
}

impl EngineInfo {
    pub fn version_string(&self) -> String {
        match self.version {
            Some((a, b, c)) => format!("{a}.{b}.{c}"),
            None => "unknown".to_string(),
        }
    }
}

/// Compares a detected version against a floor, ordering major, then minor,
/// then micro. Split out from the FFI so it is testable without an engine.
pub fn below_floor(found: (u32, u32, u32), floor: (u32, u32, u32)) -> bool {
    found < floor
}

#[cfg(test)]
mod engine_tests {
    use super::{below_floor, MIN_WEBKITGTK};

    /// The floor exists because of WSA-2026-0004 (10 July 2026), which fixes
    /// 23 CVEs in WebKitGTK before 2.52.5, several of them memory corruption
    /// reachable by visiting a page.
    #[test]
    fn known_vulnerable_versions_are_below_the_floor() {
        // Debian 12 bookworm ships this one, so the banner is expected to
        // fire on a stock install. That is not a bug in the check.
        assert!(below_floor((2, 50, 6), MIN_WEBKITGTK));
        assert!(below_floor((2, 52, 4), MIN_WEBKITGTK));
        assert!(below_floor((2, 48, 0), MIN_WEBKITGTK));
        assert!(below_floor((1, 99, 99), MIN_WEBKITGTK));
    }

    #[test]
    fn the_fix_version_and_later_are_not() {
        assert!(!below_floor((2, 52, 5), MIN_WEBKITGTK));
        assert!(!below_floor((2, 52, 6), MIN_WEBKITGTK));
        assert!(!below_floor((2, 53, 4), MIN_WEBKITGTK));
        assert!(!below_floor((3, 0, 0), MIN_WEBKITGTK));
    }

    /// Ordering is major, then minor, then micro. A naive numeric compare
    /// of any single component gets this wrong.
    #[test]
    fn components_are_ordered_not_summed() {
        assert!(below_floor((2, 9, 99), (2, 10, 0)));
        assert!(!below_floor((2, 10, 0), (2, 9, 99)));
    }
}

/// The host the chrome document is reachable at when it is served over http,
/// which is the WebView2 case (see CHROME_URL above).
///
/// Reserved on EVERY platform, not only the one that serves it. Nothing on
/// unix answers for this name, so reserving it there costs nothing, and it
/// buys a predicate that behaves identically on both backends. Backends that
/// quietly disagree is not a hypothetical failure mode in this tree: the
/// ad-block rule was correct on Windows and blocked literally nothing on
/// Linux for as long as it shipped, and the tests passed throughout.
pub const CHROME_RESERVED_HOST: &str = "rbchrome.localhost";

// ---------------------------------------------------------------------------
// Where the persistent browsing profile lives
//
// Pure path arithmetic, kept here rather than in windows.rs so `cargo test`
// on this host can execute it. The backend that consumes it needs a WebView2
// runtime; the question "which directory does this resolve to" does not, and
// getting that answer wrong is how the profile ended up beside the exe in the
// first place.
//
// All three items are consumed by the Windows backend and by the tests at the
// bottom of this file, which makes them dead code in a unix NON-test build —
// hence the allows. Compiled unconditionally rather than `#[cfg(windows)]` on
// purpose: this host cannot run the Windows backend, so keeping the pure part
// in every build is the only way a plain `cargo check` here still type-checks
// it.
// ---------------------------------------------------------------------------

/// Directory name for the persistent browsing profile inside the app's data
/// directory. Named for what a user finds inside it if they look.
#[allow(dead_code)]
pub const BROWSING_PROFILE_DIR_NAME: &str = "WebView2";

/// Where the persistent browsing profile belongs: beside the vault.
///
/// Derived from the vault's RESOLVED path rather than recomputed from the
/// environment, which buys two things for nothing. `PATANYX_DATA_DIR` is
/// honoured exactly as `Vault::default_path` honours it, with no second copy
/// of that precedence to drift out of step. And a pre-rename install whose
/// vault still lives in `rustbrowse/` (see `vault::LEGACY_DIR_NAME`) keeps its
/// browsing profile beside that vault instead of splitting one install's data
/// across two directories.
#[allow(dead_code)]
pub fn browsing_profile_dir(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        // Every `default_path` arm ends in a join, so a parent always exists.
        // A relative directory beats a panic in a function that runs before
        // there is a window to show anything in.
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        .join(BROWSING_PROFILE_DIR_NAME)
}

/// The folder WebView2 creates when nobody hands it a user-data directory:
/// `<exe-file-name>.WebView2`, beside the executable.
///
/// Computed so the app can NOTICE one left over from a build that shipped
/// without an explicit directory. Nothing is migrated out of it and nothing
/// deletes it — see the `report_stray_profile` docs on either backend for why
/// that is the decision rather than an omission.
#[allow(dead_code)]
pub fn stray_profile_dir(exe_path: &Path) -> Option<PathBuf> {
    let mut folder = exe_path.file_name()?.to_os_string();
    // The suffix appends to the WHOLE file name, extension included:
    // `patanyx.exe` -> `patanyx.exe.WebView2`. `set_extension` would replace
    // `.exe` instead of following it.
    folder.push(".WebView2");
    Some(exe_path.parent()?.join(folder))
}

#[cfg(test)]
mod profile_path_tests {
    use super::{browsing_profile_dir, stray_profile_dir};
    use std::path::{Path, PathBuf};

    /// Built by joining rather than by writing a literal, so the assertions
    /// are separator-agnostic and mean the same thing on both platforms.
    fn joined(parts: &[&str]) -> PathBuf {
        parts
            .iter()
            .fold(PathBuf::new(), |acc, part| acc.join(part))
    }

    #[test]
    fn the_profile_is_a_sibling_of_the_vault() {
        assert_eq!(
            browsing_profile_dir(&joined(&["root", "patanyx", "vault.rbv"])),
            joined(&["root", "patanyx", "WebView2"])
        );
    }

    /// The reason this is derived from the vault path instead of recomputed:
    /// an install whose vault never moved out of the pre-rename directory
    /// must not have its browsing profile land in the other one.
    #[test]
    fn a_legacy_install_keeps_both_halves_together() {
        assert_eq!(
            browsing_profile_dir(&joined(&["root", "rustbrowse", "vault.rbv"])),
            joined(&["root", "rustbrowse", "WebView2"])
        );
    }

    /// `PATANYX_DATA_DIR` needs no handling here at all — it is already
    /// baked into the path the vault resolved to, which is the point.
    #[test]
    fn an_overridden_data_dir_carries_through_untouched() {
        assert_eq!(
            browsing_profile_dir(&joined(&["tmp", "smoke-1234", "patanyx", "vault.rbv"])),
            joined(&["tmp", "smoke-1234", "patanyx", "WebView2"])
        );
    }

    #[test]
    fn a_parentless_vault_path_does_not_panic() {
        assert_eq!(
            browsing_profile_dir(Path::new("vault.rbv")),
            joined(&["WebView2"])
        );
    }

    /// The exact shape the project owner found beside the exe on 2026-07-27.
    #[test]
    fn the_stray_folder_follows_the_whole_file_name() {
        assert_eq!(
            stray_profile_dir(&joined(&[
                "Downloads",
                "patanyx-v1.0-rc-windows-x64-debug.exe"
            ]))
            .unwrap(),
            joined(&[
                "Downloads",
                "patanyx-v1.0-rc-windows-x64-debug.exe.WebView2"
            ])
        );
    }

    #[test]
    fn a_path_with_no_file_name_yields_nothing_to_report() {
        assert!(stray_profile_dir(Path::new("..")).is_none());
    }
}
