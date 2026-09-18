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
use std::sync::atomic::{AtomicU8, Ordering};

/// The process-wide gate in front of the saved engine profile's startup wipe.
///
/// Three states are necessary. A boolean can say "someone started" but cannot
/// tell a tab created one millisecond later whether it is safe to navigate or
/// whether the asynchronous clear is still running. Every tab that sees
/// `Waiting` stays blank; the completion event releases all of them together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionWipeEntry {
    Start,
    Waiting,
    Ready,
}

pub(crate) struct SessionWipeGate(AtomicU8);

impl SessionWipeGate {
    const NOT_STARTED: u8 = 0;
    const RUNNING: u8 = 1;
    const FINISHED: u8 = 2;

    pub const fn new() -> Self {
        Self(AtomicU8::new(Self::NOT_STARTED))
    }

    /// Claims the one clear, waits behind it, or observes its completion.
    /// `compare_exchange` is the once-per-process guard: no load-then-store
    /// window can let two near-simultaneous tab builds both start a wipe.
    pub fn enter(&self) -> SessionWipeEntry {
        match self.0.compare_exchange(
            Self::NOT_STARTED,
            Self::RUNNING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => SessionWipeEntry::Start,
            Err(Self::RUNNING) => SessionWipeEntry::Waiting,
            Err(_) => SessionWipeEntry::Ready,
        }
    }

    pub fn finish(&self) {
        self.0.store(Self::FINISHED, Ordering::SeqCst);
    }
}

static SESSION_WIPE: SessionWipeGate = SessionWipeGate::new();

pub(crate) fn enter_session_wipe() -> SessionWipeEntry {
    SESSION_WIPE.enter()
}

pub(crate) fn finish_session_wipe() {
    SESSION_WIPE.finish();
}

/// Issues a tab's first navigation with the same first-party marker used by
/// both backends. Kept outside either engine file because an asynchronous
/// session wipe may release the navigation later from `AppState`, after the
/// platform builder has returned.
pub(crate) fn load_initial_url(
    webview: &wry::WebView,
    id: u64,
    url: &str,
) -> Result<(), wry::Error> {
    let launch = id == 1 && url == crate::HOME_URL;
    match crate::marker::headers_for(url, launch) {
        Some(headers) => webview.load_url_with_headers(url, headers),
        None => webview.load_url(url),
    }
}

#[cfg(test)]
mod session_wipe_tests {
    use super::{SessionWipeEntry, SessionWipeGate};

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

    #[test]
    fn once_gate_distinguishes_running_from_finished() {
        let gate = SessionWipeGate::new();
        assert_eq!(gate.enter(), SessionWipeEntry::Start);
        assert_eq!(
            gate.enter(),
            SessionWipeEntry::Waiting,
            "a second tab must wait, never start a second profile wipe"
        );
        gate.finish();
        assert_eq!(
            gate.enter(),
            SessionWipeEntry::Ready,
            "tabs built after completion must navigate without another wipe"
        );
    }

    #[test]
    fn windows_mask_is_site_data_and_cache_not_profile_records() {
        // windows.rs is cfg-excluded on this Linux test host, so inspect the
        // exact expression passed to ClearBrowsingData. This is a compile-time
        // tripwire for a privacy-sensitive Windows-only mask, not a substitute
        // for the Windows cross-build or hardware acceptance test.
        let source = include_str!("windows.rs");
        let function = between(source, "fn begin_new_session_wipe(", "/// Applies a policy");
        assert!(function.contains("ClearBrowsingDataCompletedHandler"));
        assert!(function.contains(".ClearBrowsingData(kinds, &handler)"));
        assert!(
            !function.contains("DeleteAllCookies"),
            "the startup reset must not regress to the cookie-only primitive"
        );
        let mask = between(function, "let kinds =", "if let Err(error)");
        for required in ["ALL_SITE", "SERVICE_WORKERS", "DISK_CACHE"] {
            assert!(mask.contains(required), "Windows wipe lost {required}");
        }
        for excluded in [
            "SETTINGS",
            "DOWNLOAD_HISTORY",
            "BROWSING_HISTORY",
            "GENERAL_AUTOFILL",
            "PASSWORD_AUTOSAVE",
            "ALL_PROFILE",
        ] {
            assert!(
                !mask.contains(excluded),
                "Windows wipe unexpectedly includes profile record {excluded}"
            );
        }
    }

    #[test]
    fn unix_mask_matches_the_site_data_promise() {
        let source = include_str!("unix.rs");
        let function = between(source, "fn begin_new_session_wipe(", "/// See `chrome_caps`");
        assert!(function.contains("manager.clear("));
        assert!(function.contains("TimeSpan(0)"));
        let mask = between(function, "let types =", "let done_proxy");
        for required in [
            "MEMORY_CACHE",
            "DISK_CACHE",
            "OFFLINE_APPLICATION_CACHE",
            "SESSION_STORAGE",
            "LOCAL_STORAGE",
            "WEBSQL_DATABASES",
            "INDEXEDDB_DATABASES",
            "COOKIES",
            "SERVICE_WORKER_REGISTRATIONS",
            "DOM_CACHE",
        ] {
            assert!(mask.contains(required), "Unix wipe lost {required}");
        }
        for preserved in ["HSTS_CACHE", "WebsiteDataTypes::ITP"] {
            assert!(
                !mask.contains(preserved),
                "Unix wipe unexpectedly weakens engine protection {preserved}"
            );
        }
    }
}

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
pub mod motw;

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
/// to `CHROME_TOP_RANGE`). AppState stores the current value because Windows
/// must re-apply it on every resize, unlike GTK where the inset persists on
/// the widget.
pub const CHROME_HEIGHT_PX: i32 = 120;

/// What the IPC will accept as a top inset, in logical pixels.
///
/// The floor is below the ~136 a closed two-row strip measures and the ~88 a
/// closed strip measures with the feature buttons in the sidebar, because
/// both are real chromes; the ceiling is the tallest panel plus its banners.
/// It exists to bound a malformed or hostile frame, not to express a design
/// opinion -- a chrome taller than the window is the failure this stops, and
/// on GTK it is now a real one: the page is inset by this number rather than
/// pushing the window taller, so an unbounded value would hide the page
/// instead of growing the window as it used to.
pub const CHROME_TOP_RANGE: std::ops::RangeInclusive<i64> = 80..=800;

/// What the IPC will accept as a horizontal edge inset, in logical pixels.
///
/// Zero is the whole of the Top layout and must stay reachable. The ceiling
/// is far above the ~56 the sidebar asks for, and is deliberately not a
/// fraction of the window: a page squeezed to nothing is the `Split` clamp's
/// problem, and this one only has to stop a number that could not be a
/// toolbar.
pub const CHROME_LEFT_RANGE: std::ops::RangeInclusive<i64> = 0..=400;
/// The right strip is deliberately governed by the same bound: it is the
/// mirror of the left strip, not a second kind of chrome.
pub const CHROME_RIGHT_RANGE: std::ops::RangeInclusive<i64> = CHROME_LEFT_RANGE;

/// The chrome's colours, resolved, for the parts of the window the chrome
/// document does not paint: the OS title bar and border, and the scrollbars
/// of pages.
///
/// RESOLVED BY THE CHROME, NOT BY RUST. The nine accents and three schemes
/// are `color-mix` tokens in chrome.css and only the stylesheet knows what a
/// pair resolves to; chrome.js reads the computed values off the live
/// document after it wears a theme and reports them (`chrome_palette_set`).
/// Rust never has a second table of hex values to drift out of step with the
/// first. Plain sRGB bytes, because that is what both consumers take
/// (`COLORREF` and a `scrollbar-color` literal).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChromePalette {
    /// The window's 1px border, and the frame it continues: the accent.
    pub border: [u8; 3],
    /// The title bar: the tab strip's own tinted surface, so the strip reads
    /// as continuing up into it rather than sitting under a stranger.
    pub caption: [u8; 3],
    /// Title-bar text, legible on `caption` in the current scheme.
    pub text: [u8; 3],
    /// The scrollbar thumb PAGES are given (`page_scrollbar_css`).
    pub scrollbar: [u8; 3],
}

/// The default accent on the default scheme, exactly as chrome.css resolves
/// it: the values the chrome reports on a first boot before anybody has
/// chosen anything, so a tab created before the chrome has spoken wears the
/// same colours the chrome is about to. Kept in step with chrome.css by
/// hand; the tab-strip surface with 4% of the accent mixed in is what the
/// stylesheet computes for `--sf-tabstrip-a`.
impl Default for ChromePalette {
    fn default() -> Self {
        Self {
            border: [0x4f, 0x8c, 0xff],
            caption: [0x1b, 0x1f, 0x28],
            text: [0xe9, 0xe9, 0xee],
            scrollbar: [0x4f, 0x8c, 0xff],
        }
    }
}

impl ChromePalette {
    /// `#rrggbb` for a channel triple. Lower-case, six digits, always -- this
    /// is interpolated into CSS and a script, and a fixed shape is what makes
    /// the injected text predictable.
    pub fn hex(rgb: [u8; 3]) -> String {
        format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])
    }
}

/// `COLORREF` packing for the Windows title-bar colours: `0x00BBGGRR`, the
/// reverse of how the bytes are written. Here rather than beside its one
/// caller so the Linux build machine's tests pin it -- the Windows backend
/// does not compile here, and a channel order is exactly the kind of thing
/// that is right by luck until it is not.
pub fn colorref(rgb: [u8; 3]) -> u32 {
    u32::from(rgb[0]) | (u32::from(rgb[1]) << 8) | (u32::from(rgb[2]) << 16)
}

/// The accent frame around the page, in logical pixels.
///
/// The chrome paints a line in the accent along every edge of the window
/// (`#page-frame` in chrome.css; the top edge is `#tabstrip::before`), and
/// the page is inset by this much on the three edges the strip does not
/// already own so that line is not painted under it. It is the same width as
/// the top edge, so the four sides read as one frame rather than a strip
/// with a border. Nothing else in the layout is allowed to change this: the
/// chrome does not report it and the IPC does not accept it, because a
/// frame the page could ask to widen is a page that can hide itself.
///
/// THIS NUMBER LIVES IN THREE PLACES and they have to agree: here, the
/// `#page-frame` border, and the `#tabstrip::before` height. Only this one
/// moves the page; the other two only change what is painted, so a mismatch
/// is a frame thicker on one edge than the others with nothing failing.
/// `the_accent_frame_is_one_width_on_all_four_edges` reads the stylesheet and
/// holds the three together.
///
/// Narrowed from 2 to 1 on 2026-09-10 by decision: the frame
/// read too heavy and wanted to be "just a tad slimmer".
pub const PAGE_FRAME_PX: i32 = 1;

/// The four chrome inset numbers, and the rules for moving between them.
///
/// Pure, and deliberately not methods on `AppState`, because the defect this
/// type exists to prevent never appears in a single call. It only appears in a
/// SEQUENCE: open a panel, change something while it is open, close the panel.
/// `AppState` needs a real window to build, so a sequence can only be tested
/// from a value type like this one.
///
/// `top` is whatever must be given room right now. `strip` is what the chrome
/// measures with no panel open. While a panel is open they differ, and that gap
/// is the whole problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChromeInsets {
    pub top: i32,
    pub left: i32,
    pub right: i32,
    pub strip: i32,
}

impl ChromeInsets {
    /// A chrome message applied.
    ///
    /// `stated` is the chrome's own `strip` field. `None` means the caller had
    /// only three numbers, and the strip is KEPT.
    ///
    /// `None` must never be read as "same as `top`". While a panel is open
    /// `top` is the panel's height, and `toolbar_placement_set` passes exactly
    /// that, so reading it as the strip writes a 760 where a 148 belongs and
    /// shoves the page down until the chrome next remeasures. Only the chrome
    /// knows which of its numbers is which, so only the chrome may state one.
    #[must_use]
    pub fn applied(self, top: i32, left: i32, right: i32, stated: Option<i32>) -> Self {
        Self {
            top,
            left,
            right,
            strip: stated.unwrap_or(self.strip),
        }
    }

    /// Coming back from a panel to a bare strip.
    ///
    /// The height restored is the strip this chrome last REPORTED, not the
    /// build-time constant. `CHROME_HEIGHT_PX` is 120 and the sidebar layout's
    /// closed strip is nearer 88, so the constant would itself be a 32px jump
    /// on that layout: the same defect, one third the size, and harder to see.
    #[must_use]
    pub fn leaving_cover(self) -> Self {
        Self {
            top: self.strip.max(0),
            ..self
        }
    }
}

/// WHICH height the page is laid out against, for a given arrangement.
///
/// Separated from `page_rect` because it is the decision, not the arithmetic,
/// and because it is the decision that has been got wrong repeatedly. A test
/// that calls `page_rect` directly cannot catch a backend feeding it the wrong
/// number; a test that calls this can.
///
/// `top` is whatever the chrome needs room for right now, which while a panel
/// is open is the PANEL's height. `strip` is what the chrome measures with no
/// panel open, banners included.
///
/// `Overlay` takes the strip: a modal must not move the page, so the page
/// stays where the closed chrome would have put it. Taking `top` there pushes
/// the page down by the whole panel height, which is the original defect.
/// `Strip` and `Split` take `top`, because with no modal covering the window
/// `top` IS the height the page must clear.
#[must_use]
pub fn page_top_for(arrangement: ChromeLayout, top: i32, strip: i32) -> i32 {
    match arrangement {
        ChromeLayout::Overlay => strip,
        ChromeLayout::Strip | ChromeLayout::Split { .. } => top,
    }
}

/// Where the page goes, given the window and what the chrome is using.
///
/// THE ONE PLACE THE PAGE'S RECTANGLE IS DECIDED, and pure so it can be
/// tested from a machine with neither backend. Windows calls it to set real
/// bounds; GTK calls it to position the content overlay. Everything is
/// logical pixels.
///
/// `top`, `left` and `right` are what the chrome reported it is using. `pane`
/// is the docked pane on the RIGHT and adds to a right toolbar strip when both
/// exist. `frame` is the accent frame (`PAGE_FRAME_PX`; tests pass zero to
/// check the insets on their own): it takes an edge only when no strip/pane
/// does, and the bottom always. Side chrome sits INSIDE the frame and carries
/// its own inner border, so a second line there would be a double rule. Every
/// number is clamped into the window, and the result is never negative: a
/// window smaller than its own chrome yields an empty page rectangle rather
/// than an inverted one.
pub fn page_rect(
    win_w: f64,
    win_h: f64,
    top: i32,
    left: i32,
    right: i32,
    pane: i32,
    frame: i32,
) -> (f64, f64, f64, f64) {
    let win_w = win_w.max(0.0);
    let win_h = win_h.max(0.0);
    let frame = f64::from(frame.max(0));
    let top = f64::from(top.max(0)).min(win_h);
    let left = if left > 0 { f64::from(left) } else { frame }.min(win_w);
    let right_uses_chrome = right > 0 || pane > 0;
    let right = if right_uses_chrome {
        f64::from(right.max(0)) + f64::from(pane.max(0))
    } else {
        frame
    }
    .min(win_w - left);
    let bottom = frame.min((win_h - top).max(0.0));
    (
        left,
        top,
        (win_w - left - right).max(0.0),
        (win_h - top - bottom).max(0.0),
    )
}

/// Whether the chrome must be given the WHOLE window rather than a strip.
///
/// The chrome is one webview and the layout it paints is not a rectangle:
/// a strip along the top, a column down either side when the toolbar lives
/// there, and -- always -- the accent frame along the other three edges of
/// the window. On Windows that is not a problem to solve but a fact to use:
/// the page is created after the chrome and draws over it, so handing the
/// chrome the window and the page its inset rectangle leaves the chrome
/// visible in exactly the shape it paints. `Split` already relies on this
/// for its pane; either sidebar is the same trick on its edge, and the
/// frame is the same trick on all of them, which is why this is now true
/// for every arrangement. The parameters stay so the reasoning is still
/// stated per case and a frame width of zero would give the old answer.
///
/// GTK needs no equivalent, which is why this carries a cfg: there the
/// chrome widget is the root overlay's main child and always fills the
/// window, so covering is its resting state rather than a decision. Same
/// shape as the other Windows-only helpers in this module.
#[cfg(any(windows, test))]
pub fn chrome_covers_window(left: i32, right: i32, arrangement: ChromeLayout) -> bool {
    PAGE_FRAME_PX > 0 || left > 0 || right > 0 || !matches!(arrangement, ChromeLayout::Strip)
}

/// Whether the toolbar can be laid out down either edge.
///
/// True on both backends, and shared here rather than written twice: both
/// inset the page through `page_rect`, so there is one answer and no way for
/// the two to drift into disagreeing. It is still ASKED (see `chrome_caps`)
/// rather than assumed, because this browser's rule is that a control the
/// platform cannot honour is explained or hidden, never shown and inert --
/// and a future backend that cannot do it needs somewhere to say so.
pub fn sidebar_supported() -> bool {
    true
}

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

/// Translator origin. A SEPARATE ORIGIN FROM THE CHROME UI, and that is the
/// whole point rather than a detail.
///
/// The design this replaces put the translator webview on `rbchrome` so it
/// could be served chrome assets, on the reasoning that withholding an
/// `ipc_handler` was enough isolation. Phase 0 measured that in the product
/// and it is not: the ipc handler IS per-webview and held, but storage is
/// origin-scoped and went straight around it. IndexedDB crossed live between
/// a same-origin pair, the chrome document was loadable and readable in a
/// frame, and a fetch reached the chrome protocol handler -- which answers
/// `/region-capture/` with a screen capture and `/archive-picture/` with a
/// DECRYPTED archive page. See `docs/page-translation-spike.md`.
///
/// Hostile page text goes into this view, so it gets its own origin, its own
/// data store and its own protocol handler that is never wired to
/// `serve_chrome`.
#[cfg(unix)]
pub const TRANSLATE_URL: &str = "rbtranslate://localhost/translator.html";
/// See the unix arm; wry rewrites custom schemes on WebView2.
#[cfg(windows)]
pub const TRANSLATE_URL: &str = "http://rbtranslate.localhost/translator.html";

/// The scheme name the translator's protocol handler registers under.
pub const TRANSLATE_SCHEME: &str = "rbtranslate";

/// Navigation allowlist prefix for the translator webview, same discipline as
/// `CHROME_ORIGIN_PREFIX`: exact, and never loosened to "any http URL" to
/// accommodate the WebView2 form.
#[cfg(unix)]
pub const TRANSLATE_ORIGIN_PREFIX: &str = "rbtranslate://";
/// See the unix arm.
#[cfg(windows)]
pub const TRANSLATE_ORIGIN_PREFIX: &str = "http://rbtranslate.localhost/";

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
/// 2.52.6 is the fix version for WSA-2026-0005 (20 August 2026): nine CVEs,
/// among them an iframe sandbox policy violation (CVE-2026-64728), a UI spoof
/// through framed content (CVE-2026-64730), a visited-link history leak
/// (CVE-2026-64713) and use-after-free crashes (CVE-2026-64783, -64787).
/// It supersedes 2.52.5, the fix version for WSA-2026-0004 (10 July 2026,
/// 23 CVEs, several "processing maliciously crafted web content may lead to
/// memory corruption"). Every one of them is reachable by visiting a page,
/// which is the entire job of this program.
///
/// This is a RUNTIME floor, not a build-time one. WebKitGTK is linked
/// dynamically, so the version we compiled against says nothing about the
/// version that will be loaded on a user's machine.
///
/// Debian 12 (bookworm) ships 2.50.6 and will never ship the fix: the Debian
/// security tracker marks webkit2gtk in bookworm END-OF-LIFE (see DSA-6232-1),
/// so waiting for it is not a plan. The fix is in trixie security as
/// 2.52.6-1~deb13u1 (2.52.5-1~deb13u1 was DSA-6398-1). A native build on
/// bookworm is therefore
/// permanently below this floor, which is why `enforce_engine_floor` refuses
/// to start a release build rather than merely printing a line.
///
/// RAISING THIS STRANDS ANY RUNTIME BELOW IT, and on Linux that is a refusal
/// to start, not a banner. Before raising, check what the shipping channels
/// actually carry: Debian 13 security has 2.52.6, but the Flatpak's
/// `org.gnome.Platform` runtime is pinned separately and may lag (see
/// `packaging/flatpak/io.edgexene.Patanyx.yml`).
///
/// Raise this whenever a new advisory lands. It is not a compatibility
/// minimum and should never be lowered to silence the banner.
pub const MIN_WEBKITGTK: [u32; 3] = [2, 52, 6];

/// Why the WebKitGTK floor is where it is, in the words printed when a
/// runtime is below it. Beside the constant so the two move together: a
/// floor raised for a new advisory with last year's explanation under it
/// would send someone reading the log to the wrong fix.
pub const WEBKITGTK_ADVISORY: &str = "WSA-2026-0005 fixes 9 CVEs in this engine, among them an iframe sandbox\n  \
     violation and use-after-free crashes reachable by visiting a page (and\n  \
     WSA-2026-0004 before it, 23 more). Debian marks webkit2gtk in bookworm\n  \
     END-OF-LIFE, so no update is coming on that release: the fix is\n  \
     Debian 13 security (2.52.6-1~deb13u1), or a Flatpak whose runtime\n  \
     carries WebKitGTK 2.52.6 or newer.";

/// Minimum WebView2 runtime the browser will run unwarned.
///
/// FOUR fields, because the fourth is where a security fix lands: runtime
/// 152.0.4191.53 (28 August 2026) carried CVE-2026-85046 and 152.0.4191.62
/// (2 September 2026) did not, and a three-field compare cannot tell the
/// two apart. That is why `EngineInfo::version` keeps every field the
/// engine reports instead of a semver-shaped triple.
///
/// The value follows Microsoft Edge Stable, whose security notes name each
/// CVE and the version that closed it. The WebView2 Evergreen runtime is
/// built from the same tree and ships alongside Edge, so the Edge number is
/// the runtime number once the Update Catalog lists that runtime build.
///
/// CURRENT VALUE: 152.0.4191.66 (Edge Stable, 4 September 2026), which
/// closed CVE-2026-87491, reported by the Chromium team as having an
/// exploit in the wild. Verified directly against Microsoft's security
/// notes and the Update Catalog's x64 WebView2 Runtime row for that build
/// on 11 September 2026 (docs/engine-advisory.md, "Evidence"). The previous
/// value, .62, closed CVE-2026-85046 two days earlier; .66 is above it, so
/// nothing this raise says was ever false. A first launch that is offline
/// warns from this constant alone, which is why the compiled value tracks
/// the verified fix rather than waiting for the advisory channel.
///
/// Being below it raises a BANNER and never a refusal (see
/// `enforce_engine_floor` in main.rs). The Evergreen runtime updates itself
/// out of band, on a rollout that takes days, and a GUI application with no
/// console cannot refuse to start and still explain why. The WebKitGTK
/// floor refuses because Debian 12 will NEVER ship its fix; the WebView2
/// floor warns because Windows will, shortly.
///
/// Raise this whenever an engine advisory with an in-the-wild exploit
/// lands (the hourly monitor in scripts/engine-advisory-monitor.py finds
/// them; the signed advisory reaches installed browsers first, and the
/// constant follows in the next release). It is not a compatibility minimum
/// and should never be lowered to silence the banner.
pub const MIN_WEBVIEW2: [u32; 4] = [152, 0, 4191, 66];

/// See `WEBKITGTK_ADVISORY`; the same rule, for the Windows floor.
pub const WEBVIEW2_ADVISORY: &str = "CVE-2026-87491 is reachable from a web page and was reported by the\n  \
     Chromium team as exploited in the wild before the fix shipped. Microsoft Edge\n  \
     152.0.4191.66 (4 September 2026) closed it and the WebView2 Evergreen runtime\n  \
     follows Edge; there is nothing to install by hand. Restart PATANYX once it\n  \
     has arrived.";

/// What engine is actually underneath us, and is it old enough to be a
/// known-vulnerable one. Reported to the chrome UI so the answer lives
/// somewhere the user can see rather than only in a release note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineInfo {
    /// Display name, e.g. "WebKitGTK" or "WebView2".
    pub name: &'static str,
    /// Runtime version, every numeric field the engine reports, in order.
    /// WebKitGTK reports three; WebView2 reports four, and the fourth is
    /// the one that says whether a security fix is present. `None` when it
    /// could not be determined.
    pub version: Option<Vec<u32>>,
    /// Human-readable state of the engine's own tracker defence. Separate
    /// from the content blocker, which is ours.
    pub tracking_prevention: &'static str,
    /// True only when a version was determined AND it is below the floor
    /// IN FORCE (`floor`). Unknown is not treated as unsafe: a false alarm
    /// every launch trains the user to ignore the banner, which costs more
    /// than it buys.
    pub below_floor: bool,
    /// True only when a version was determined AND it is below the floor
    /// COMPILED IN (`compiled_floor`). This is the only bit that may refuse
    /// to start: a floor raised by a signed manifest can make the browser
    /// warn, never turn it off.
    pub below_compiled_floor: bool,
    /// The floor in force: the compiled constant, or the higher value a
    /// signed update manifest has asserted since (see
    /// `effective_floor`). The banner names this one.
    pub floor: Vec<u32>,
    /// The floor this build was compiled with.
    pub compiled_floor: &'static [u32],
    /// Why the compiled floor is where it is, for the log line. Static,
    /// because the advisory is a property of the constant and not of the
    /// machine; a floor raised by a manifest is reported as exactly that.
    pub advisory: &'static str,
    /// The runtime INSTALLED on this machine, when the platform can read it
    /// separately from what is running. On Windows the Evergreen runtime
    /// updates itself while PATANYX is open, so the installed build can be
    /// newer than the one every live webview is still using; that gap is
    /// the "restart to pick up the fix" case. `None` on Linux (the loaded
    /// library is the installed library) and when it cannot be read.
    pub installed: Option<Vec<u32>>,
    /// Where `version` came from, so a diagnostic can say whether the number
    /// is the engine underneath the pages or merely the one on disk.
    pub version_source: EngineVersionSource,
}

/// Which fact `EngineInfo::version` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineVersionSource {
    /// Read from a live webview environment: the engine actually rendering.
    Running,
    /// No webview exists yet, so the installed runtime stands in. Honest at
    /// startup diagnostics; never used once environments exist.
    Installed,
    /// Could not be determined. Unknown is not unsafe: no banner.
    Unknown,
}

/// What this process has observed about the engine its webviews run on.
///
/// The Windows backend records the environment's own `BrowserVersionString`
/// each time a webview is built (chrome, content, translator, probe). The
/// LOWEST observed version is kept: if two environments ever disagreed, the
/// older one is the exposure. A read that fails after environments exist
/// leaves the answer `Unknown` rather than borrowing the installed runtime's
/// number, which may be newer than anything actually rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunningVersion {
    /// No webview has been built yet.
    NoneYet,
    /// At least one live environment reported this (the lowest seen).
    Known(Vec<u32>),
    /// Environments exist and none could be read.
    Unknown,
}

/// Fold one environment's report into what is known. Pure, so the "lowest
/// wins, failure never falls back" rule is tested without an engine.
///
/// `required` is the engine's precision (four fields for WebView2, three
/// for WebKitGTK). A report with any other field count is INCOMPLETE and is
/// treated exactly like a failed read: it cannot become the known version,
/// and it cannot displace one. The independent review reproduced the
/// defect this closes: a synthetic `152.0.4191.66 beta` parsed to three
/// fields, compared lower than the known `152.0.4191.62`, replaced it, and
/// the stale runtime's warning vanished. Shorter is not lower; it is unknown.
pub fn merge_running(
    current: RunningVersion,
    observed: Option<Vec<u32>>,
    required: usize,
) -> RunningVersion {
    let observed = observed.filter(|v| v.len() == required);
    match (current, observed) {
        (RunningVersion::Known(have), Some(seen)) => {
            RunningVersion::Known(if seen < have { seen } else { have })
        }
        (_, Some(seen)) => RunningVersion::Known(seen),
        (RunningVersion::Known(have), None) => RunningVersion::Known(have),
        (_, None) => RunningVersion::Unknown,
    }
}

/// The version to judge, and where it came from. Before any webview exists
/// the installed runtime serves startup diagnostics; once environments
/// exist, only a live report counts, and a failed read stays unknown.
pub fn resolve_engine_version(
    running: RunningVersion,
    installed: Option<Vec<u32>>,
) -> (Option<Vec<u32>>, EngineVersionSource) {
    match running {
        RunningVersion::Known(v) => (Some(v), EngineVersionSource::Running),
        RunningVersion::NoneYet => match installed {
            Some(v) => (Some(v), EngineVersionSource::Installed),
            None => (None, EngineVersionSource::Unknown),
        },
        RunningVersion::Unknown => (None, EngineVersionSource::Unknown),
    }
}

impl EngineInfo {
    pub fn version_string(&self) -> String {
        match &self.version {
            Some(fields) => join_version(fields),
            None => "unknown".to_string(),
        }
    }

    pub fn floor_string(&self) -> String {
        join_version(&self.floor)
    }

    pub fn installed_string(&self) -> String {
        match &self.installed {
            Some(fields) => join_version(fields),
            None => "unknown".to_string(),
        }
    }

    /// True when a signed update manifest has raised the floor above the
    /// compiled constant, so the log can say the advisory text is behind.
    pub fn floor_raised(&self) -> bool {
        self.floor.as_slice() != self.compiled_floor
    }

    /// The running engine is below the floor AND the installed runtime is
    /// POSITIVELY at or above it: a restart, and nothing else, clears the
    /// warning. The banner says that instead of "this computer does not
    /// have it yet", which would be false.
    ///
    /// "Positively" means the installed version carries EVERY field the
    /// floor has. `below_floor` answers false for a version too short to
    /// judge because unknown is not unsafe -- the right answer for a
    /// banner, and the wrong one for a promise. An installed `[152,0,4191]`
    /// against floor `152.0.4191.66` is not known to be fixed, so no
    /// restart is promised on its strength (reproduced by the independent
    /// review before this check existed).
    pub fn restart_clears(&self) -> bool {
        self.below_floor
            && self.version_source == EngineVersionSource::Running
            && self.installed.as_deref().is_some_and(|installed| {
                installed.len() >= self.floor.len() && !below_floor(installed, &self.floor)
            })
    }
}

/// The floor in force for an engine: the compiled constant, unless a signed
/// update manifest has asserted a HIGHER one at the same precision, which
/// the updater persisted (`updater::persisted_engine_floor`), or -- for
/// WebView2 only -- a signed engine advisory under a currently trusted
/// advisory key has (`engine_advisory::persisted_floor`). The two registers
/// stay separate on disk; this is where their maximum is taken. Lower or
/// differently-shaped stored values are ignored: this can only raise.
pub fn effective_floor(engine: &str, compiled: &'static [u32]) -> Vec<u32> {
    let advisory = if engine == "WebView2" {
        crate::engine_advisory::persisted_floor().map(|f| f.to_vec())
    } else {
        None
    };
    effective_floor_from(
        compiled,
        crate::updater::persisted_engine_floor(engine),
        advisory,
    )
}

/// The pure half of `effective_floor`: the maximum of the compiled constant
/// and whichever persisted authorities are present and well-shaped.
pub fn effective_floor_from(
    compiled: &[u32],
    release: Option<Vec<u32>>,
    advisory: Option<Vec<u32>>,
) -> Vec<u32> {
    let with_release = raise_floor(compiled, release);
    raise_floor(&with_release, advisory)
}

/// The pure half of `effective_floor`, so the raise-only rule is tested
/// without a data directory.
pub fn raise_floor(compiled: &[u32], persisted: Option<Vec<u32>>) -> Vec<u32> {
    match persisted {
        Some(p) if p.len() == compiled.len() && p.as_slice() > compiled => p,
        _ => compiled.to_vec(),
    }
}

/// "152.0.4191.62" from its fields. One place, so the log line, the banner
/// and the About panel cannot format the same version three ways.
pub fn join_version(fields: &[u32]) -> String {
    fields
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// "152.0.4191.62" -> [152, 0, 4191, 62], every field kept. A piece that is
/// not a number (a trailing channel word, should one ever appear) is simply
/// not a field rather than fatal; a string with no numeric field at all is
/// `None`, which the callers report as an unknown version. Shared by both
/// engines so the parse that decides "is the fix present" has a Linux-run
/// test before hardware is the first thing to exercise it.
pub fn parse_version_fields(text: &str) -> Option<Vec<u32>> {
    let fields: Vec<u32> = text
        .split('.')
        .filter_map(|p| p.trim().parse::<u32>().ok())
        .collect();
    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

/// Does a cookie's `Domain` attribute apply to `host`?
///
/// RFC 6265 section 5.1.3 domain-matching, and it is load-bearing for
/// "Forget this site". That clear enumerates EVERY cookie in the profile and
/// decides membership here, rather than asking the engine for one URI's
/// cookies: a URI query applies PATH matching as well, so a cookie scoped to
/// `/account` is simply absent from the answer for `https://host/`, and the
/// clear then reported success with that cookie still on disk (review R-001).
/// A login left behind by a clear that said it worked is the whole failure
/// this function exists to prevent.
///
/// THE LEADING DOT IS THE WHOLE ANSWER, and reading it as decoration was a
/// defect of its own. In an HTTP `Set-Cookie` header the dot is historical
/// and means nothing, which is what the first version of this function
/// assumed. But the string handed back by the engine is not that header: it
/// is the engine's STORED form, and Chromium -- which is what WebView2 is --
/// records a cookie with no `Domain` attribute as `example.com` and a cookie
/// that asked for `Domain=example.com` as `.example.com`. The dot is how the
/// store says "this one covers subdomains". Stripping it merged the two, so
/// forgetting `shop.example.com` would have deleted a cookie belonging only
/// to `example.com` -- reaching outside the site the person named, which is
/// the one thing a per-site clear must never do.
///
/// So: a leading dot means subdomains are included, and no leading dot means
/// this host and no other. Either way the suffix must fall on a label
/// boundary, which keeps `evil-example.com` out of `example.com`.
///
/// Deliberately NOT symmetric. A cookie for `www.example.com` does not apply
/// to `example.com`, so forgetting `example.com` leaves it alone, exactly as
/// a URI query would have. Widening that is a product decision about what
/// "this site" means, not a bug fix.
///
/// THE TRAILING DOT IS TRIMMED ON PURPOSE, and a review round three raised it
/// as a possible over-match: `foo.com.` and `foo.com` are distinct strings in
/// the cookie store, so trimming merges two scopes the store keeps apart.
/// Kept anyway, because in DNS they are the same name -- the trailing dot is
/// the root label, not a different host -- and "forget this site" is a
/// statement about a site rather than about a string. Leaving it untrimmed
/// would mean a cookie stored as `foo.com.` survived a clear of `foo.com`
/// while the panel reported success, which is the exact failure this whole
/// function exists to end, traded for an over-match that is confined to the
/// same site. If that trade is ever revisited it needs a measurement of what
/// WebView2 actually stores, which this machine cannot take.
pub fn cookie_domain_matches(domain: &str, host: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.');
    let host = host.trim().trim_end_matches('.');
    if domain.is_empty() || host.is_empty() {
        return false;
    }
    let Some(covers_subdomains) = domain.strip_prefix('.') else {
        // Host-only: it belongs to exactly one name.
        return domain.eq_ignore_ascii_case(host);
    };
    if covers_subdomains.is_empty() {
        return false;
    }
    if covers_subdomains.eq_ignore_ascii_case(host) {
        return true;
    }
    host.len() > covers_subdomains.len()
        && host.as_bytes()[host.len() - covers_subdomains.len() - 1] == b'.'
        && host[host.len() - covers_subdomains.len()..].eq_ignore_ascii_case(covers_subdomains)
}

#[cfg(test)]
mod cookie_domain_tests {
    use super::cookie_domain_matches;

    #[test]
    fn a_cookie_for_this_exact_host_is_cleared_either_way_it_is_stored() {
        assert!(cookie_domain_matches("example.com", "example.com"));
        assert!(cookie_domain_matches(".example.com", "example.com"));
    }

    #[test]
    fn a_dotted_domain_cookie_covers_its_subdomains() {
        assert!(cookie_domain_matches(".youtube.com", "www.youtube.com"));
        assert!(cookie_domain_matches(".youtube.com", "m.www.youtube.com"));
    }

    #[test]
    fn a_host_only_cookie_on_the_parent_survives_forgetting_a_subdomain() {
        // The dot decides, and this is the case that made it decide. A cookie
        // the parent set for itself alone is stored WITHOUT the dot, and it
        // is not this subdomain's to delete.
        assert!(!cookie_domain_matches("example.com", "shop.example.com"));
        assert!(!cookie_domain_matches("youtube.com", "m.www.youtube.com"));
        // Asking for the parent itself still reaches it.
        assert!(cookie_domain_matches("example.com", "example.com"));
    }

    #[test]
    fn a_neighbour_that_merely_ends_the_same_way_is_not_the_site() {
        assert!(!cookie_domain_matches(".example.com", "notexample.com"));
        assert!(!cookie_domain_matches(".example.com", "evil-example.com"));
        assert!(!cookie_domain_matches(".ample.com", "example.com"));
        assert!(!cookie_domain_matches("example.com", "notexample.com"));
    }

    #[test]
    fn a_narrower_cookie_is_left_for_its_own_host() {
        assert!(!cookie_domain_matches("www.example.com", "example.com"));
        assert!(!cookie_domain_matches(".www.example.com", "example.com"));
    }

    #[test]
    fn case_does_not_decide_whether_a_cookie_is_cleared() {
        assert!(cookie_domain_matches(".EXAMPLE.com", "www.example.COM"));
        assert!(cookie_domain_matches("EXAMPLE.com", "example.COM"));
    }

    #[test]
    fn a_trailing_root_label_is_the_same_site() {
        // Pinned because it is a decision, not an accident: see the note on
        // the function. The match must stay INSIDE the site either way round.
        assert!(cookie_domain_matches("foo.com.", "foo.com"));
        assert!(cookie_domain_matches(".foo.com.", "www.foo.com"));
        assert!(!cookie_domain_matches("foo.com.", "www.foo.com"));
        assert!(!cookie_domain_matches(".foo.com.", "foo.com.evil.test"));
    }

    #[test]
    fn nothing_matches_an_empty_side() {
        assert!(!cookie_domain_matches("", "example.com"));
        assert!(!cookie_domain_matches("example.com", ""));
        assert!(!cookie_domain_matches(".", "example.com"));
        assert!(!cookie_domain_matches("..", "example.com"));
    }
}

/// A pretend engine version, DEBUG BUILDS ONLY, so the banner can be seen on
/// a machine whose real runtime is already past the floor. The hardware
/// checklist sets PATANYX_ENGINE_VERSION_OVERRIDE=152.0.4191.53 against the
/// debug exe and expects the banner; nothing else reads it.
///
/// A release build ignores the variable entirely. The one thing the switch
/// could do there is make the banner lie in either direction, and a security
/// surface should not ship with a knob whose only purpose is that -- even
/// one that needs the user's own environment to turn.
pub fn debug_version_override() -> Option<Vec<u32>> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var("PATANYX_ENGINE_VERSION_OVERRIDE")
        .ok()
        .and_then(|text| parse_version_fields(&text))
}

/// Compares a detected version against a floor, field by field from the
/// left, over as many fields as the FLOOR has. Split out from the FFI so it
/// is testable without an engine.
///
/// A version reporting fewer fields than the floor needs is UNKNOWN at the
/// precision that matters, and unknown is not treated as unsafe (see
/// `EngineInfo::below_floor`): the answer is false. The alternative, padding
/// the short side with zeros, would have called 152.0.4191 "below"
/// 152.0.4191.62 on a runtime that may well be .66.
pub fn below_floor(found: &[u32], floor: &[u32]) -> bool {
    if found.len() < floor.len() {
        return false;
    }
    found[..floor.len()] < *floor
}

/// The chrome's boot-time question: is the engine underneath me one with a
/// known exploited bug, and what do I tell the user. The sentence is
/// composed here, in the locale, for the same reason the resolver banner's
/// is: a claim about the user's safety is catalog property, and the chrome
/// renders it verbatim rather than wording it a second way.
pub fn engine_ipc_status(
    i18n: &crate::i18n::I18n,
) -> Result<serde_json::Value, &'static str> {
    let engine = engine_info();
    Ok(serde_json::json!({
        "name": engine.name,
        "version": engine.version_string(),
        "floor": engine.floor_string(),
        "below_floor": engine.below_floor,
        "body": engine_floor_body(i18n, &engine),
        // Diagnostics the chrome may show but does not word: which fact the
        // version is, what is installed, and whether a restart alone clears
        // the warning.
        "version_source": match engine.version_source {
            EngineVersionSource::Running => "running",
            EngineVersionSource::Installed => "installed",
            EngineVersionSource::Unknown => "unknown",
        },
        "installed": engine.installed.as_deref().map(join_version),
        "restart_clears": engine.restart_clears(),
    }))
}

/// The banner's whole body. The first sentence is true of either engine;
/// the second, that the platform updates the engine on its own, is only
/// true of the Evergreen runtime, so it is appended for WebView2 alone. A
/// debug build on an old WebKitGTK gets the banner too and must not be told
/// that Debian will fix it, because Debian will not.
pub fn engine_floor_body(i18n: &crate::i18n::I18n, engine: &EngineInfo) -> String {
    let mut args = crate::i18n::Args::default();
    args.set("engine", engine.name);
    args.set("version", engine.version_string());
    args.set("floor", engine.floor_string());
    // INSTALLED NEWER, RUNNING OLDER: the standard body says only what is
    // known -- pages in this session still use an older version -- and
    // makes no claim about the installed runtime. When the installed build
    // is POSITIVELY at or above the floor, this case gets its own body,
    // naming that build and the one act that clears the warning.
    if engine.restart_clears() {
        args.set("installed", engine.installed_string());
        return i18n.resolve(crate::i18n::keys::CHROME_ENGINE_FLOOR_BODY_RESTART, &args);
    }
    let mut body = i18n.resolve(crate::i18n::keys::CHROME_ENGINE_FLOOR_BODY, &args);
    if engine.name == "WebView2" {
        body.push(' ');
        body.push_str(&i18n.text(crate::i18n::keys::CHROME_ENGINE_FLOOR_EVERGREEN));
    }
    body
}

/// The closed strip, checked as a SEQUENCE.
///
/// Same reason as the rectangle tests below: one backend cannot be run on the
/// machine this is developed on, so this is the only place the Windows
/// behaviour is checked before it reaches hardware. The numbers here are not
/// invented. They were read off the real chrome document running in a real
/// browser on 2026-09-10, with the native bridge stubbed, and they are what it
/// sends: 148 for the closed two-row strip, 500 for the Vault panel, 760 for
/// the Theme panel.
#[cfg(test)]
mod chrome_inset_tests {
    use super::ChromeInsets;

    /// The chrome's opening statement: a bare strip, top and strip agreeing.
    fn booted() -> ChromeInsets {
        ChromeInsets {
            top: 148,
            left: 0,
            right: 0,
            strip: 148,
        }
    }

    #[test]
    fn a_panel_raises_the_top_and_leaves_the_closed_strip_alone() {
        let open = booted().applied(500, 0, 0, Some(148));
        assert_eq!(open.top, 500);
        assert_eq!(open.strip, 148, "a panel is not a strip");
    }

    #[test]
    fn a_placement_switch_mid_panel_does_not_eat_the_closed_strip() {
        // The regression, driven in the order it actually happens.
        let mut i = booted();
        // Theme opens. The chrome states both numbers.
        i = i.applied(760, 0, 0, Some(148));
        // The user switches toolbar placement WHILE the panel is open.
        // `toolbar_placement_set` has only three numbers and passes
        // `chrome_height()`, which is 760 right now. This is the call that
        // used to write 760 into the closed strip.
        i = i.applied(760, 0, 0, None);
        assert_eq!(
            i.strip, 148,
            "the panel's height was adopted as the closed strip"
        );
        // And closing must come back to the strip, not to the panel height.
        assert_eq!(i.leaving_cover().top, 148);
    }

    #[test]
    fn an_absent_strip_keeps_the_last_one_stated_not_the_newest_top() {
        // Three numbers arriving twice in a row must not drift. Each call
        // keeps what the chrome last stated, however far `top` has moved.
        let i = booted()
            .applied(500, 0, 0, None)
            .applied(760, 0, 0, None)
            .applied(300, 0, 0, None);
        assert_eq!(i.strip, 148);
    }

    #[test]
    fn a_sidebar_strip_survives_the_same_sequence() {
        // The layout where getting this wrong is worst: the closed sidebar
        // strip is nearer 88 than the 120 constant, so a wrong restore is a
        // small jump rather than an obvious one.
        let mut i = ChromeInsets {
            top: 88,
            left: 56,
            right: 0,
            strip: 88,
        };
        i = i.applied(760, 56, 0, Some(88));
        i = i.applied(760, 56, 0, None);
        assert_eq!(i.strip, 88);
        assert_eq!(i.leaving_cover().top, 88);
        assert_eq!(i.left, 56, "the side axis rides along untouched");
    }

    #[test]
    fn the_chrome_may_restate_a_strip_that_has_genuinely_changed() {
        // Showing the bookmarks bar adds a third row. The chrome measures it
        // and says so, and that statement must be taken -- "keep what you
        // have" applies only when nothing was stated.
        let i = booted().applied(188, 0, 0, Some(188));
        assert_eq!(i.strip, 188);
        assert_eq!(i.leaving_cover().top, 188);
    }

    /// The rule the Windows `Overlay` branch now rests on.
    ///
    /// That branch lays the page out against the STATED STRIP, using the same
    /// `page_rect` call the `Strip` branch makes against `chrome_height`. With
    /// no panel open those two numbers are equal, so the two arrangements must
    /// produce one rectangle. If they ever diverge, opening a modal moves the
    /// page and closing it moves it back, which is the flicker the old
    /// "preserve y verbatim" rule existed to prevent.
    mod overlay_agrees_with_strip {
        use super::super::{page_rect, page_top_for, ChromeLayout, PAGE_FRAME_PX};

        /// The production choice, then the production arithmetic. Nothing here
        /// picks the height by hand: that is the point, because the defect was
        /// always in the CHOICE and never in `page_rect`.
        fn laid_out(
            win: (f64, f64),
            arrangement: ChromeLayout,
            top: i32,
            strip: i32,
            left: i32,
            right: i32,
        ) -> (f64, f64, f64, f64) {
            page_rect(
                win.0,
                win.1,
                page_top_for(arrangement, top, strip),
                left,
                right,
                0,
                PAGE_FRAME_PX,
            )
        }

        const WIN: (f64, f64) = (1100.0, 780.0);

        #[test]
        fn opening_a_modal_does_not_move_the_page() {
            // Closed: top and strip agree at 148.
            let closed = laid_out(WIN, ChromeLayout::Strip, 148, 148, 0, 0);
            // Theme opens: `top` becomes the panel's 760, the strip does not
            // move. The page must not move either.
            let open = laid_out(WIN, ChromeLayout::Overlay, 760, 148, 0, 0);
            assert_eq!(closed, open, "a modal moved the page");
            assert_eq!(open.1, 148.0);
        }

        #[test]
        fn a_placement_switch_mid_panel_closes_the_band() {
            // The reported defect, in the order it happens. Theme is open at
            // 760 over a 148 strip; the toolbar moves to the left rail, so the
            // strip drops to 88 and a 56px rail appears. The page must follow
            // the strip. Freezing y left it at 148 while the chrome painted
            // 88, and the 60px between was the grey band.
            let before = laid_out(WIN, ChromeLayout::Overlay, 760, 148, 0, 0);
            let after = laid_out(WIN, ChromeLayout::Overlay, 760, 88, 56, 0);
            assert_eq!(before.1, 148.0);
            assert_eq!(after.1, 88.0, "the page must follow the shortened strip");
            assert_eq!(after.0, 56.0, "and sit beside the rail");
        }

        #[test]
        fn a_docked_pane_still_lays_out_against_the_live_height() {
            // Split is not a modal: nothing covers the window, so `top` IS the
            // height to clear. Reading the strip there would put the page
            // under the chrome whenever the two differ.
            let split = ChromeLayout::Split { pane_width: 320 };
            assert_eq!(laid_out(WIN, split, 192, 148, 0, 0).1, 192.0);
        }

        #[test]
        fn a_window_smaller_than_its_chrome_yields_no_negative_page() {
            // The case a remembered-offset rule got wrong: the top clamps to
            // the window, so a stored delta would be a lie. Choosing from the
            // current numbers every time cannot drift.
            let (_, y, w, h) = laid_out((400.0, 100.0), ChromeLayout::Overlay, 760, 148, 0, 0);
            assert_eq!(y, 100.0);
            assert!(w >= 0.0 && h >= 0.0);
            assert_eq!(
                laid_out((400.0, 100.0), ChromeLayout::Overlay, 760, 88, 0, 0).1,
                88.0,
                "and it recovers exactly when the strip shrinks"
            );
        }

        #[test]
        fn a_banner_appearing_during_a_modal_moves_the_page_down() {
            // Banners ride in the stated strip, so the page sits below them
            // during a modal exactly as it does outside one. The strip arrives
            // ALREADY floored with the banner included -- 180, not 192 -- and
            // 180 is where the banner's last row actually is. See the note in
            // `closedChromePx`: flooring before adding the banner counted the
            // 12px of slack twice and left that much unpainted.
            let bare = laid_out(WIN, ChromeLayout::Overlay, 760, 148, 0, 0);
            let bannered = laid_out(WIN, ChromeLayout::Overlay, 760, 180, 0, 0);
            assert_eq!((bare.1, bannered.1), (148.0, 180.0));
            assert!(
                bannered.3 < bare.3,
                "the page gives up the height the banner took"
            );
        }
    }

    /// The strip is floored ONCE, with the banner already inside it.
    ///
    /// A STRUCTURAL guard, and a weak one: it forbids the exact expression
    /// the regression is, and a rename would walk straight past it.
    ///
    /// The REAL check is behavioural and lives in
    /// `scripts/blocked-banner-gate.js`, which drives a panel close with the
    /// rows measuring 41 + 95 and a 48px banner and requires the number 184.
    /// That gate fails on 196 (the floor applied to the rows and the banner
    /// added after, counting the 12px of slack twice) and on 148 (the banner
    /// ignored). This test exists anyway because `scripts/pre-commit-audit.sh`
    /// runs the i18n, pseudo-locale, translator-isolation and attribution
    /// gates and NOT `chrome-js-gate.sh`, so nothing in the commit path
    /// exercises that one. This rides along in `cargo test`, which pre-commit
    /// does run.
    ///
    /// Third check, for a person rather than CI:
    /// PATANYX-test/chrome-strip-probe-20260910/probe5.js reads the same
    /// numbers out of a real browser, 148 bare and 184 with the banner.
    #[test]
    fn the_closed_strip_is_floored_once_with_the_extra_inside_it() {
        const JS: &str = include_str!("../chrome/chrome.js");
        // Comments stripped first. The note at the call site QUOTES the
        // expression this forbids, in order to explain it, and a guard that
        // cannot tell code from prose would force the documentation to be
        // vaguer to keep itself green.
        let code: String = JS
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("closedChromePx() + extra"),
            "`closedChromePx() + extra` is back. The floor must be applied to \
             the rows AND the banner together, not to the rows alone, or the \
             slack between the measured rows and the floor is counted twice."
        );
        assert!(
            code.contains("Math.ceil(measured + extra)"),
            "closedChromePx no longer folds `extra` into the measurement \
             before flooring"
        );
        assert!(
            code.contains("function closedChromePx(extra = 0)"),
            "closedChromePx no longer takes the extra"
        );
    }

    /// A warning stays readable while a panel is open, and does not cover it.
    ///
    /// Three z-indexes in chrome.css have to stay in this order and not one of
    /// them fails loudly when it does not. Banners are static and unpositioned,
    /// which put them UNDER the modal scrim while the two rows directly above
    /// them were lifted above it: a TLS or insecure-HTTP warning dimmed to
    /// roughly 38% on the lifted backdrop and hidden outright on the opaque
    /// one, with the toolbar bright above it.
    ///
    /// Raising them past the panel would be the other half of the same
    /// mistake, because a banner and an open card share the band between the
    /// strip and the panel. They belong between the two.
    #[test]
    fn a_banner_outranks_the_scrim_and_yields_to_the_panel() {
        const CSS: &str = include_str!("../chrome/chrome.css");

        /// The z-index declared in the block that follows `needle`, and ONLY
        /// in that block.
        ///
        /// Bounded at the rule's closing brace on purpose. Searching the rest
        /// of the stylesheet let this read a LATER element's number: deleting
        /// `.panel-modal`'s own `z-index: 40` still passed, because it walked
        /// on and found `#confirm-overlay`'s 40. A guard that survives the
        /// removal of the thing it guards is worse than none, because it reads
        /// as coverage.
        fn z_after(css: &str, needle: &str) -> i32 {
            let at = css
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} is gone from chrome.css"));
            let rest = &css[at..];
            let end = rest
                .find('}')
                .unwrap_or_else(|| panic!("{needle} has no closing brace"));
            let rest = &rest[..end];
            let z = rest
                .find("z-index:")
                .unwrap_or_else(|| panic!("{needle} declares no z-index"));
            rest[z + "z-index:".len()..]
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .unwrap_or_else(|_| panic!("no z-index number after {needle}"))
        }

        let scrim = z_after(CSS, "body.modal-open::after {");
        let banner = z_after(CSS, "body.modal-open > [role=\"alert\"],");
        let panel = z_after(CSS, ".panel-modal {");

        assert!(
            scrim < banner,
            "a banner at {banner} sits under the scrim at {scrim}, so a warning \
             is dimmed or hidden for as long as a panel is open"
        );
        assert!(
            banner < panel,
            "a banner at {banner} sits over the panel at {panel}, so it covers \
             the card's title instead of being covered by it"
        );

        // The lifted backdrop's opaque backing must be UNDER the banners too.
        // At 45 it covered the first banner's top 12.5px, which reaches into
        // the content box because the banner's own top padding is 10px.
        let backing = z_after(CSS, "body.translucent-backdrop.modal-open::before {");
        assert!(
            backing < banner,
            "the modal backing at {backing} covers a banner at {banner}; the \
             top of the first warning is painted over"
        );
        assert!(
            scrim < backing,
            "the backing at {backing} is under the scrim at {scrim}, so the \
             slack below the toolbar is dimmed instead of hidden"
        );

        // And the card has to be placed below the strip INCLUDING banners, or
        // it opens inside the band a banner is drawn in.
        assert!(
            CSS.contains("top: calc(var(--chrome-strip-px"),
            ".panel-modal is positioned from the bare closed strip again; a \
             panel opened while a banner shows will start inside it"
        );

        // EVERY cap on the card, including the more specific platform rule.
        // That one is the reason this assertion is by count rather than by
        // presence: `body.page-covers-chrome .panel-modal` wins the cascade,
        // and while it still subtracted the bare height a capped card ended
        // 53px below the chrome the page then covers, with no scrollbar that
        // reaches the rows underneath.
        let caps = CSS.matches("var(--chrome-strip-px, var(--chrome-closed-px, 148px))").count();
        assert!(
            caps >= 3,
            "only {caps} of the card's three measurements use the \
             banner-inclusive strip; the platform max-height override is the \
             one that silently wins the cascade"
        );
    }

    /// The frame is one width on all four edges, or it is not a frame.
    ///
    /// `PAGE_FRAME_PX` insets the page; the stylesheet paints the line. Only
    /// the first moves anything, so if the two drift the result is a frame
    /// heavier on three edges than on the top, or a painted line the page
    /// covers -- and every test still passes. Read the stylesheet instead.
    #[test]
    fn the_accent_frame_is_one_width_on_all_four_edges() {
        use super::PAGE_FRAME_PX;
        const CSS: &str = include_str!("../chrome/chrome.css");

        /// The px value on the first line matching `needle`, after `skip`.
        fn px_after(css: &str, needle: &str, prop: &str) -> i32 {
            let at = css.find(needle).unwrap_or_else(|| panic!("{needle} is gone from chrome.css"));
            let rest = &css[at..];
            let p = rest.find(prop).unwrap_or_else(|| panic!("{prop} is gone from {needle}"));
            let line: String = rest[p..].chars().take_while(|c| *c != ';').collect();
            let digits: String = line
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().unwrap_or_else(|_| panic!("no px number in {line:?}"))
        }

        // The three sides the page is inset from.
        let border = px_after(CSS, "#page-frame {", "border:");
        // The top edge, which the strip owns and the page never covers.
        let top = px_after(CSS, "#tabstrip::before {", "height:");

        assert_eq!(
            border, PAGE_FRAME_PX,
            "#page-frame paints {border}px but the page is inset {PAGE_FRAME_PX}px"
        );
        assert_eq!(
            top, PAGE_FRAME_PX,
            "#tabstrip::before paints {top}px but the other three edges are {PAGE_FRAME_PX}px"
        );
    }

    #[test]
    fn a_negative_strip_cannot_pull_the_page_above_the_window() {
        let i = ChromeInsets {
            top: 500,
            left: 0,
            right: 0,
            strip: -40,
        };
        assert_eq!(i.leaving_cover().top, 0);
    }
}

/// The page's rectangle, checked without a window.
///
/// Both backends compute it here, and one of them cannot be run on the
/// machine this is developed on. That makes these tests the only place the
/// Windows arithmetic is checked before it reaches hardware, which is why
/// they cover the degenerate cases rather than just the happy one -- a
/// window smaller than its own chrome is what a user does with the mouse in
/// half a second.
#[cfg(test)]
mod page_rect_tests {
    use super::{
        chrome_covers_window, page_rect, ChromeLayout, CHROME_LEFT_RANGE, CHROME_RIGHT_RANGE,
        CHROME_TOP_RANGE, PAGE_FRAME_PX,
    };

    #[test]
    fn a_top_strip_leaves_the_page_the_full_width() {
        // The shape every build has shipped: nothing on the left axis.
        assert_eq!(
            page_rect(1100.0, 780.0, 148, 0, 0, 0, 0),
            (0.0, 148.0, 1100.0, 632.0)
        );
    }

    #[test]
    fn a_sidebar_moves_the_page_right_and_narrows_it_by_the_same_amount() {
        // The two must move together. Insetting the origin without taking
        // the width off is how a page ends up running off the right edge of
        // the window, which is invisible until something is scrolled to.
        let (x, y, w, h) = page_rect(1100.0, 780.0, 88, 56, 0, 0, 0);
        assert_eq!((x, y), (56.0, 88.0));
        assert_eq!(x + w, 1100.0, "the page must still end at the window edge");
        assert_eq!(y + h, 780.0);
    }

    #[test]
    fn a_right_strip_keeps_the_origin_and_narrows_the_page_from_the_right() {
        let (x, y, w, h) = page_rect(1100.0, 780.0, 88, 0, 56, 0, 0);
        assert_eq!((x, y), (0.0, 88.0));
        assert_eq!(w, 1044.0);
        assert_eq!(x + w, 1044.0, "the page must stop at the right strip");
        assert_eq!(y + h, 780.0);
    }

    #[test]
    fn a_docked_pane_and_a_sidebar_take_from_opposite_edges() {
        // Different axes, and they have to be able to coexist: the pane is
        // on the right, the sidebar on the left, and each takes only its
        // own side.
        let (x, _, w, _) = page_rect(1000.0, 700.0, 88, 56, 0, 300, 0);
        assert_eq!(x, 56.0);
        assert_eq!(w, 644.0);
        assert_eq!(x + w, 700.0, "the pane's column is left for the chrome");
    }

    #[test]
    fn a_docked_pane_and_right_strip_both_leave_room_on_the_right() {
        let (x, _, w, _) = page_rect(1000.0, 700.0, 88, 0, 56, 300, 0);
        assert_eq!(x, 0.0);
        assert_eq!(w, 644.0);
        assert_eq!(x + w, 644.0, "pane and strip must add, not overlap the page");
    }

    #[test]
    fn a_window_smaller_than_its_chrome_yields_an_empty_page_not_a_negative_one() {
        // Dragging a window small enough that the chrome does not fit is a
        // half-second of mouse movement. A negative width here reaches
        // set_bounds as a garbage rectangle.
        for r in [
            page_rect(40.0, 40.0, 148, 56, 56, 0, 0),
            page_rect(0.0, 0.0, 148, 56, 56, 0, 0),
            page_rect(200.0, 100.0, 800, 400, 400, 0, 0),
        ] {
            assert!(r.2 >= 0.0 && r.3 >= 0.0, "negative page rectangle: {r:?}");
            assert!(r.0 >= 0.0 && r.1 >= 0.0, "negative page origin: {r:?}");
        }
    }

    #[test]
    fn nothing_is_placed_outside_the_window() {
        // Every clamp in one assertion, over a spread that includes insets
        // larger than the window and a pane larger than what is left.
        for (w, h) in [(1100.0, 780.0), (320.0, 240.0), (10.0, 10.0)] {
            for top in [0, 88, 148, 800] {
                for left in [0, 56, 400] {
                    for right in [0, 56, 400] {
                        for pane in [0, 300, 4096] {
                            let (x, y, pw, ph) =
                                page_rect(w, h, top, left, right, pane, 0);
                            assert!(x + pw <= w + 0.001, "page runs past the right edge");
                            assert!(y + ph <= h + 0.001, "page runs past the bottom edge");
                            assert!(pw >= 0.0 && ph >= 0.0);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn negative_insets_are_treated_as_none() {
        // The IPC clamps, but this function is also called with values from
        // state that a future caller could set directly.
        assert_eq!(
            page_rect(1100.0, 780.0, -50, -20, -20, -5, 0),
            page_rect(1100.0, 780.0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn the_chrome_takes_the_window_in_every_arrangement_because_of_the_frame() {
        // A sidebar makes the chrome an L, and no rectangle is an L; the
        // accent frame makes it a ring, and no rectangle is a ring either.
        // The page draws over the chrome, so covering the window is what
        // leaves the chrome visible in exactly the shape it paints -- and
        // with a frame that is every arrangement, the plain strip included.
        assert!(PAGE_FRAME_PX > 0, "the frame is the reason the strip covers");
        assert!(chrome_covers_window(0, 0, ChromeLayout::Strip));
        assert!(chrome_covers_window(56, 0, ChromeLayout::Strip));
        assert!(chrome_covers_window(0, 56, ChromeLayout::Strip));
        assert!(chrome_covers_window(0, 0, ChromeLayout::Overlay));
        assert!(chrome_covers_window(0, 0, ChromeLayout::Split { pane_width: 300 }));
        assert!(chrome_covers_window(56, 0, ChromeLayout::Split { pane_width: 300 }));
    }

    #[test]
    fn the_frame_insets_the_page_on_the_three_edges_the_strip_does_not_own() {
        // The top edge is the strip's; the other three are the frame's. The
        // page starts PAGE_FRAME_PX in from the left, ends that much short of
        // the right, and that much short of the bottom, so the chrome's line
        // is painted beside the page rather than under it.
        let f = f64::from(PAGE_FRAME_PX);
        assert_eq!(
            page_rect(1100.0, 780.0, 148, 0, 0, 0, PAGE_FRAME_PX),
            (f, 148.0, 1100.0 - 2.0 * f, 632.0 - f)
        );
    }

    #[test]
    fn a_sidebar_or_a_pane_replaces_the_frame_on_its_own_edge() {
        // The sidebar and the pane sit INSIDE the frame and carry their own
        // inner border, so the page abuts them directly: no second line, no
        // 2px gap of body colour between the rail and the page.
        let (x, _, w, _) = page_rect(1000.0, 700.0, 88, 56, 0, 300, PAGE_FRAME_PX);
        assert_eq!(x, 56.0, "the page starts at the sidebar's edge, not past a frame");
        assert_eq!(x + w, 700.0, "the page ends at the pane's edge, not short of it");
        // Bottom is the frame's regardless.
        let (_, y, _, h) = page_rect(1000.0, 700.0, 88, 56, 0, 300, PAGE_FRAME_PX);
        assert_eq!(y + h, 700.0 - f64::from(PAGE_FRAME_PX));
    }

    #[test]
    fn a_frame_never_makes_a_negative_page() {
        for (w, h) in [(1100.0, 780.0), (3.0, 3.0), (0.0, 0.0)] {
            for top in [0, 148, 800] {
                for left in [0, 56] {
                    for right in [0, 56] {
                        for pane in [0, 300] {
                            let (x, y, pw, ph) =
                                page_rect(w, h, top, left, right, pane, PAGE_FRAME_PX);
                            assert!(pw >= 0.0 && ph >= 0.0, "negative page: {:?}", (x, y, pw, ph));
                            assert!(x + pw <= w + 0.001 && y + ph <= h + 0.001);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn colorref_is_bgr_and_hex_is_rgb() {
        // The two consumers of a palette triple read the bytes in opposite
        // orders. Pinned so a refactor cannot swap one and turn every accent
        // into its complement on one platform.
        assert_eq!(super::colorref([0x4f, 0x8c, 0xff]), 0x00ff_8c4f);
        assert_eq!(super::colorref([0, 0, 0]), 0);
        assert_eq!(super::ChromePalette::hex([0x4f, 0x8c, 0xff]), "#4f8cff");
        assert_eq!(super::ChromePalette::hex([0, 0, 0]), "#000000");
    }

    #[test]
    fn the_accepted_insets_cover_both_real_chromes() {
        // ~136 closed with the buttons on top, ~88 closed with them in the
        // sidebar, and the tallest panel plus its banners. If a future panel
        // grows past the ceiling it is clamped and renders below the fold --
        // this is the assertion that says which numbers were meant.
        assert!(CHROME_TOP_RANGE.contains(&88));
        assert!(CHROME_TOP_RANGE.contains(&148));
        assert!(CHROME_TOP_RANGE.contains(&740));
        assert!(!CHROME_TOP_RANGE.contains(&0));
        assert!(!CHROME_TOP_RANGE.contains(&4096));
        // Zero is the whole of the Top layout and must stay reachable.
        assert!(CHROME_LEFT_RANGE.contains(&0));
        assert!(CHROME_LEFT_RANGE.contains(&56));
        assert!(!CHROME_LEFT_RANGE.contains(&-1));
        assert!(!CHROME_LEFT_RANGE.contains(&4096));
        assert!(CHROME_RIGHT_RANGE.contains(&0));
        assert!(CHROME_RIGHT_RANGE.contains(&56));
        assert!(!CHROME_RIGHT_RANGE.contains(&-1));
        assert!(!CHROME_RIGHT_RANGE.contains(&4096));
    }
}

#[cfg(test)]
mod engine_tests {
    use super::{
        below_floor, effective_floor_from, engine_floor_body, join_version, merge_running,
        parse_version_fields, resolve_engine_version, EngineInfo, EngineVersionSource,
        RunningVersion, MIN_WEBKITGTK, MIN_WEBVIEW2, WEBKITGTK_ADVISORY, WEBVIEW2_ADVISORY,
    };

    /// The parse that decides whether a fix is present. Four fields survive,
    /// because the fourth is the one that matters on WebView2; junk is
    /// dropped rather than fatal; nothing numeric is unknown, not zero.
    #[test]
    fn the_version_parse_keeps_every_numeric_field() {
        assert_eq!(parse_version_fields("152.0.4191.62"), Some(vec![152, 0, 4191, 62]));
        assert_eq!(parse_version_fields("2.52.5"), Some(vec![2, 52, 5]));
        assert_eq!(parse_version_fields(" 141.0.3537.57 "), Some(vec![141, 0, 3537, 57]));
        // A word where a field should be is not a field. The result is then
        // too short to judge against a four-field floor, which below_floor
        // reports as not-below: unknown, not unsafe.
        assert_eq!(parse_version_fields("152.0.4191.beta"), Some(vec![152, 0, 4191]));
        assert_eq!(parse_version_fields(""), None);
        assert_eq!(parse_version_fields("unknown"), None);
    }

    /// The floor exists because of WSA-2026-0005 (20 August 2026), which fixes
    /// 9 CVEs in WebKitGTK before 2.52.6 (iframe sandbox violation, use-after-
    /// free), on top of WSA-2026-0004 (23 CVEs before 2.52.5). 2.52.5 is now a
    /// vulnerable version and must sit below the floor.
    #[test]
    fn known_vulnerable_versions_are_below_the_floor() {
        // Debian 12 bookworm ships this one, so the banner is expected to
        // fire on a stock install. That is not a bug in the check.
        assert!(below_floor(&[2, 50, 6], &MIN_WEBKITGTK));
        assert!(below_floor(&[2, 52, 4], &MIN_WEBKITGTK));
        assert!(below_floor(&[2, 52, 5], &MIN_WEBKITGTK)); // WSA-2026-0005: affected
        assert!(below_floor(&[2, 48, 0], &MIN_WEBKITGTK));
        assert!(below_floor(&[1, 99, 99], &MIN_WEBKITGTK));
    }

    #[test]
    fn the_fix_version_and_later_are_not() {
        assert!(!below_floor(&[2, 52, 6], &MIN_WEBKITGTK));
        assert!(!below_floor(&[2, 52, 7], &MIN_WEBKITGTK));
        assert!(!below_floor(&[2, 53, 4], &MIN_WEBKITGTK));
        assert!(!below_floor(&[3, 0, 0], &MIN_WEBKITGTK));
    }

    /// Ordering is major, then minor, then micro. A naive numeric compare
    /// of any single component gets this wrong.
    #[test]
    fn components_are_ordered_not_summed() {
        assert!(below_floor(&[2, 9, 99], &[2, 10, 0]));
        assert!(!below_floor(&[2, 10, 0], &[2, 9, 99]));
    }

    /// The WebView2 floor is 152.0.4191.66 (4 September 2026), which closed
    /// CVE-2026-87491, exploited in the wild. Below it sit .62 (which closed
    /// the earlier CVE-2026-85046 and carried the later one), .53 and every
    /// older branch. .62 and .66 differ ONLY in the fourth field.
    #[test]
    fn the_exposed_webview2_runtime_is_below_the_floor() {
        assert!(below_floor(&[152, 0, 4191, 62], &MIN_WEBVIEW2));
        assert!(below_floor(&[152, 0, 4191, 53], &MIN_WEBVIEW2));
        assert!(below_floor(&[151, 0, 4129, 107], &MIN_WEBVIEW2));
        assert!(below_floor(&[141, 0, 3537, 57], &MIN_WEBVIEW2));
    }

    #[test]
    fn the_fixed_webview2_runtime_and_later_are_not() {
        assert!(!below_floor(&[152, 0, 4191, 66], &MIN_WEBVIEW2));
        assert!(!below_floor(&[152, 0, 4191, 67], &MIN_WEBVIEW2));
        assert!(!below_floor(&[153, 0, 4234, 6], &MIN_WEBVIEW2));
        assert!(!below_floor(&[160, 0, 0, 0], &MIN_WEBVIEW2));
    }

    /// The compiled value IS the directly verified fix, pinned so a merge
    /// cannot quietly carry the older .62 baseline into the release that
    /// introduces the advisory channel: a first launch that is offline warns
    /// from this constant and nothing else.
    #[test]
    fn the_compiled_baseline_is_the_verified_fix_for_cve_2026_87491() {
        assert_eq!(MIN_WEBVIEW2, [152, 0, 4191, 66]);
        assert!(WEBVIEW2_ADVISORY.contains("CVE-2026-87491"));
        assert!(WEBVIEW2_ADVISORY.contains("152.0.4191.66"));
    }

    /// A three-field floor would call .53 and .62 the same version and the
    /// whole check would be decoration. Pinned, because a future edit that
    /// "tidies" the constant to semver shape would pass every other test.
    #[test]
    fn the_webview2_floor_keeps_the_field_a_fix_lands_in() {
        assert_eq!(MIN_WEBVIEW2.len(), 4);
        assert_ne!(MIN_WEBVIEW2[3], 0, "the fourth field is the point");
    }

    /// Fewer fields than the floor needs is unknown, and unknown is not
    /// unsafe. Zero-padding would have said "below" here.
    #[test]
    fn a_version_too_short_to_judge_is_not_called_below() {
        assert!(!below_floor(&[152, 0, 4191], &MIN_WEBVIEW2));
        assert!(!below_floor(&[], &MIN_WEBVIEW2));
        // Extra fields beyond the floor's precision are ignored, not fatal.
        assert!(!below_floor(&[2, 52, 6, 1], &MIN_WEBKITGTK));
        assert!(below_floor(&[2, 52, 5, 99], &MIN_WEBKITGTK));
    }

    #[test]
    fn versions_print_every_field_they_have() {
        assert_eq!(join_version(&[152, 0, 4191, 62]), "152.0.4191.62");
        assert_eq!(join_version(&[2, 52, 5]), "2.52.5");
        let unknown = EngineInfo {
            name: "WebView2",
            version: None,
            tracking_prevention: "",
            below_floor: false,
            below_compiled_floor: false,
            floor: MIN_WEBVIEW2.to_vec(),
            compiled_floor: &MIN_WEBVIEW2,
            advisory: WEBVIEW2_ADVISORY,
            installed: None,
            version_source: EngineVersionSource::Running,
        };
        assert!(!unknown.floor_raised());
        assert_eq!(unknown.version_string(), "unknown");
        assert_eq!(unknown.floor_string(), "152.0.4191.66");
    }

    /// A signed manifest can only RAISE the floor, at the same precision.
    /// Anything else leaves the compiled constant in force: a lower value,
    /// a three-field value against a four-field floor, or nothing stored.
    #[test]
    fn a_persisted_floor_can_only_raise_the_compiled_one() {
        use super::raise_floor;
        assert_eq!(raise_floor(&MIN_WEBVIEW2, None), MIN_WEBVIEW2.to_vec());
        assert_eq!(raise_floor(&MIN_WEBVIEW2, Some(vec![152, 0, 4191, 53])), MIN_WEBVIEW2.to_vec());
        assert_eq!(raise_floor(&MIN_WEBVIEW2, Some(vec![152, 0, 4191, 62])), MIN_WEBVIEW2.to_vec());
        assert_eq!(raise_floor(&MIN_WEBVIEW2, Some(vec![152, 0, 4191, 66])), MIN_WEBVIEW2.to_vec());
        assert_eq!(raise_floor(&MIN_WEBVIEW2, Some(vec![153, 0, 4234, 6])), vec![153, 0, 4234, 6]);
        assert_eq!(raise_floor(&MIN_WEBVIEW2, Some(vec![160, 0, 0])), MIN_WEBVIEW2.to_vec());
        assert_eq!(raise_floor(&MIN_WEBVIEW2, Some(vec![])), MIN_WEBVIEW2.to_vec());
        // With the raised floor in force, the runtime that cleared the
        // compiled floor is below again, and the banner names the new one.
        let raised = raise_floor(&MIN_WEBVIEW2, Some(vec![153, 0, 4234, 6]));
        assert!(below_floor(&[152, 0, 4191, 66], &raised));
        assert!(!below_floor(&[152, 0, 4191, 66], &MIN_WEBVIEW2));
        let info = EngineInfo {
            name: "WebView2",
            version: Some(vec![152, 0, 4191, 66]),
            tracking_prevention: "",
            below_floor: true,
            below_compiled_floor: false,
            floor: raised,
            compiled_floor: &MIN_WEBVIEW2,
            advisory: WEBVIEW2_ADVISORY,
            installed: None,
            version_source: EngineVersionSource::Running,
        };
        assert!(info.floor_raised());
        assert_eq!(info.floor_string(), "153.0.4234.6");
    }

    /// Each advisory must name the version that clears its floor, or the
    /// log line points at a fix and the paragraph under it describes
    /// another one.
    #[test]
    fn each_advisory_names_its_own_floor() {
        assert!(WEBKITGTK_ADVISORY.contains(&join_version(&MIN_WEBKITGTK)));
        assert!(WEBVIEW2_ADVISORY.contains(&join_version(&MIN_WEBVIEW2)));
    }

    /// The banner body is composed from the catalog with the engine, its
    /// version and the floor as arguments. Asserted against the real English
    /// catalog: every placeable filled, the two versions named, and the
    /// Evergreen sentence present for WebView2 only, because on Linux it
    /// would promise an update Debian 12 will never deliver.
    #[test]
    fn the_banner_body_names_both_versions_and_promises_only_what_is_true() {
        let i18n = crate::i18n::I18n::bootstrap("en")
            .expect("the embedded English catalog is valid");
        let windows = EngineInfo {
            name: "WebView2",
            version: Some(vec![152, 0, 4191, 53]),
            tracking_prevention: "",
            below_floor: true,
            below_compiled_floor: true,
            floor: MIN_WEBVIEW2.to_vec(),
            compiled_floor: &MIN_WEBVIEW2,
            advisory: WEBVIEW2_ADVISORY,
            installed: None,
            version_source: EngineVersionSource::Running,
        };
        let body = engine_floor_body(&i18n, &windows);
        assert!(body.contains("152.0.4191.53"), "{body}");
        assert!(body.contains("152.0.4191.66"), "{body}");
        assert!(body.contains("WebView2"), "{body}");
        assert!(!body.contains("{ $"), "unfilled placeable: {body}");
        assert!(body.contains("on its own"), "WebView2 gets the Evergreen sentence: {body}");

        let linux = EngineInfo {
            name: "WebKitGTK",
            version: Some(vec![2, 50, 6]),
            tracking_prevention: "",
            below_floor: true,
            below_compiled_floor: true,
            floor: MIN_WEBKITGTK.to_vec(),
            compiled_floor: &MIN_WEBKITGTK,
            advisory: WEBKITGTK_ADVISORY,
            installed: None,
            version_source: EngineVersionSource::Running,
        };
        let body = engine_floor_body(&i18n, &linux);
        assert!(body.contains("2.50.6") && body.contains("2.52.6"), "{body}");
        assert!(
            !body.contains("on its own"),
            "WebKitGTK must not be promised a self-updating engine: {body}"
        );
    }

    /// EXACT FOUR-PART COMPARISON. The runtime that carried CVE-2026-87491
    /// (152.0.4191.62) and the one that fixed it (152.0.4191.66) differ only
    /// in the fourth field, and the comparison is numeric on every field.
    #[test]
    fn the_fourth_field_decides_and_compares_numerically() {
        let floor = [152, 0, 4191, 66];
        assert!(below_floor(&[152, 0, 4191, 62], &floor));
        assert!(below_floor(&[152, 0, 4191, 65], &floor));
        assert!(!below_floor(&[152, 0, 4191, 66], &floor));
        assert!(!below_floor(&[152, 0, 4191, 67], &floor));
        assert!(!below_floor(&[152, 0, 4191, 100], &floor));
        assert!(!below_floor(&[152, 0, 4192, 0], &floor));
        assert!(!below_floor(&[153, 0, 0, 0], &floor));
        // Numeric, not lexicographic: "9" sorts after "66" as text.
        assert!(below_floor(&[152, 0, 4191, 9], &floor));
        assert!(!below_floor(&[152, 0, 4191, 100], &[152, 0, 4191, 99]));
    }

    /// PLANTED COMPARATOR DEFECT, as a control. Two wrong comparators that a
    /// careless rewrite could introduce -- string comparison, and a
    /// three-field compare -- must DISAGREE with the real one on the cases
    /// above. If a "tidied" comparator ever agreed with these on every
    /// case here, this test would be the one to notice.
    #[test]
    fn a_planted_wrong_comparator_is_caught_by_these_cases() {
        fn lexicographic(found: &[u32], floor: &[u32]) -> bool {
            join_version(found) < join_version(floor)
        }
        fn three_fields(found: &[u32], floor: &[u32]) -> bool {
            below_floor(&found[..3.min(found.len())], &floor[..3.min(floor.len())])
        }
        let floor = [152, 0, 4191, 66];
        // The real comparator: 9 < 66 and 100 > 99.
        assert!(below_floor(&[152, 0, 4191, 9], &floor));
        assert!(!below_floor(&[152, 0, 4191, 100], &[152, 0, 4191, 99]));
        // String comparison gets both backwards.
        assert!(!lexicographic(&[152, 0, 4191, 9], &floor), "the planted defect must differ");
        assert!(lexicographic(&[152, 0, 4191, 100], &[152, 0, 4191, 99]));
        // A three-field compare cannot see the exposed .62 under the .66 floor.
        assert!(below_floor(&[152, 0, 4191, 62], &floor));
        assert!(!three_fields(&[152, 0, 4191, 62], &floor), "the planted defect must differ");
    }

    /// INSTALLED NEWER, RUNNING OLDER. The Evergreen runtime updated while
    /// the browser was open: the running environment is still .62, the disk
    /// has .66, the floor is .66. The session is BELOW the floor, and the
    /// honest remedy is a restart, which the info reports and the banner
    /// body says.
    #[test]
    fn installed_newer_running_older_is_below_the_floor_and_a_restart_clears_it() {
        let floor = vec![152, 0, 4191, 66];
        let (version, source) = resolve_engine_version(
            RunningVersion::Known(vec![152, 0, 4191, 62]),
            Some(vec![152, 0, 4191, 66]),
        );
        assert_eq!(version, Some(vec![152, 0, 4191, 62]));
        assert_eq!(source, EngineVersionSource::Running);
        let info = EngineInfo {
            name: "WebView2",
            version: version.clone(),
            tracking_prevention: "",
            below_floor: below_floor(version.as_deref().unwrap(), &floor),
            below_compiled_floor: false,
            floor: floor.clone(),
            compiled_floor: &MIN_WEBVIEW2,
            advisory: WEBVIEW2_ADVISORY,
            installed: Some(vec![152, 0, 4191, 66]),
            version_source: source,
        };
        assert!(info.below_floor, "the RUNNING engine decides, not the installed one");
        assert!(info.restart_clears());
        let i18n = crate::i18n::I18n::bootstrap("en").unwrap();
        let body = engine_floor_body(&i18n, &info);
        assert!(body.contains("152.0.4191.62"), "{body}");
        assert!(body.contains("152.0.4191.66"), "{body}");
        assert!(body.contains("Restart PATANYX"), "{body}");
        assert!(!body.contains("still use an older version"), "false once installed: {body}");
        assert!(!body.contains("{ $"), "unfilled placeable: {body}");

        // Same running version, installed ALSO old: no restart claim, the
        // standard body with the Evergreen sentence.
        let stale = EngineInfo {
            installed: Some(vec![152, 0, 4191, 62]),
            ..info.clone()
        };
        assert!(!stale.restart_clears());
        let body = engine_floor_body(&i18n, &stale);
        assert!(body.contains("still use an older version"), "{body}");
        assert!(body.contains("on its own"), "{body}");

        // Installed unreadable: no restart claim either.
        let unread = EngineInfo { installed: None, ..info.clone() };
        assert!(!unread.restart_clears());

        // Above the floor: nothing to clear.
        let fine = EngineInfo {
            version: Some(vec![152, 0, 4191, 66]),
            below_floor: false,
            ..info.clone()
        };
        assert!(!fine.restart_clears());
    }

    /// The running-version rule. Installed serves only before any webview
    /// exists; the lowest live report wins; a failed read after environments
    /// exist is UNKNOWN and never borrows the installed number.
    #[test]
    fn running_version_prefers_live_reports_and_never_falls_back_to_installed() {
        let installed = Some(vec![152, 0, 4191, 66]);
        // Startup: nothing built yet, the installed runtime stands in.
        assert_eq!(
            resolve_engine_version(RunningVersion::NoneYet, installed.clone()),
            (installed.clone(), EngineVersionSource::Installed)
        );
        assert_eq!(
            resolve_engine_version(RunningVersion::NoneYet, None),
            (None, EngineVersionSource::Unknown)
        );
        // Environments exist and none could be read: unknown, not .66.
        assert_eq!(
            resolve_engine_version(RunningVersion::Unknown, installed.clone()),
            (None, EngineVersionSource::Unknown)
        );
        // Merge: first report, then a lower one, then a higher one.
        let r = merge_running(RunningVersion::NoneYet, Some(vec![152, 0, 4191, 66]), 4);
        assert_eq!(r, RunningVersion::Known(vec![152, 0, 4191, 66]));
        let r = merge_running(r, Some(vec![152, 0, 4191, 62]), 4);
        assert_eq!(r, RunningVersion::Known(vec![152, 0, 4191, 62]), "lowest wins");
        let r = merge_running(r, Some(vec![153, 0, 4300, 1]), 4);
        assert_eq!(r, RunningVersion::Known(vec![152, 0, 4191, 62]), "lowest still wins");
        // A failed read after a known one keeps the known one; a failed
        // read with nothing known is Unknown, and a later success recovers.
        let r = merge_running(r, None, 4);
        assert_eq!(r, RunningVersion::Known(vec![152, 0, 4191, 62]));
        assert_eq!(merge_running(RunningVersion::NoneYet, None, 4), RunningVersion::Unknown);
        assert_eq!(
            merge_running(RunningVersion::Unknown, Some(vec![1, 2, 3, 4]), 4),
            RunningVersion::Known(vec![1, 2, 3, 4])
        );
        // Below/equal/above/unknown against a floor, from the resolved value.
        let floor = [152, 0, 4191, 66];
        for (running, expect_below) in [
            (RunningVersion::Known(vec![152, 0, 4191, 62]), true),
            (RunningVersion::Known(vec![152, 0, 4191, 66]), false),
            (RunningVersion::Known(vec![152, 0, 4191, 70]), false),
            (RunningVersion::Unknown, false),
        ] {
            let (v, _) = resolve_engine_version(running.clone(), installed.clone());
            let below = v.as_deref().is_some_and(|f| below_floor(f, &floor));
            assert_eq!(below, expect_below, "{running:?}");
        }
    }

    /// INCOMPLETE REPORTS, reproduced by the independent review as input
    /// handling (no Windows device returned these strings). A running
    /// report with fewer fields than WebView2's four -- what a suffixed
    /// "152.0.4191.66 beta" parses to -- is not a lower version and must
    /// not erase a known stale observation; with nothing known it is
    /// simply unknown. WebKitGTK's three-field precision is unaffected.
    #[test]
    fn an_incomplete_running_report_never_displaces_a_known_stale_observation() {
        let stale = RunningVersion::Known(vec![152, 0, 4191, 62]);
        let partial = parse_version_fields("152.0.4191.66 beta");
        assert_eq!(partial, Some(vec![152, 0, 4191]), "the parser keeps the numeric prefix");
        // THE DEFECT: three fields compare lower than four and used to win.
        assert!(partial.as_deref().unwrap() < [152u32, 0, 4191, 62].as_slice());
        let merged = merge_running(stale.clone(), partial.clone(), 4);
        assert_eq!(merged, stale, "an incomplete report is a failed read, not a lower version");
        // The warning it protects: still below the floor after the merge.
        let (v, _) = resolve_engine_version(merged, Some(vec![152, 0, 4191, 66]));
        assert!(below_floor(v.as_deref().unwrap(), &[152, 0, 4191, 66]));
        // Nothing known plus an incomplete report is unknown, never the
        // installed number and never the partial one.
        assert_eq!(merge_running(RunningVersion::NoneYet, partial.clone(), 4), RunningVersion::Unknown);
        assert_eq!(
            resolve_engine_version(merge_running(RunningVersion::NoneYet, partial, 4), Some(vec![152, 0, 4191, 66])),
            (None, EngineVersionSource::Unknown)
        );
        // Five fields are not four either.
        assert_eq!(merge_running(stale.clone(), Some(vec![152, 0, 4191, 66, 1]), 4), stale);
        // WebKitGTK: three fields are complete at its precision.
        assert_eq!(
            merge_running(RunningVersion::NoneYet, Some(vec![2, 52, 5]), 3),
            RunningVersion::Known(vec![2, 52, 5])
        );
        assert_eq!(merge_running(RunningVersion::Known(vec![2, 52, 5]), Some(vec![2, 52]), 3), RunningVersion::Known(vec![2, 52, 5]));
    }

    /// An INCOMPLETE INSTALLED number cannot prove that a restart clears
    /// the warning: `[152,0,4191]` is not known to be at or above
    /// 152.0.4191.66, so the banner keeps the standard body rather than
    /// promising a restart. Reproduced by the independent review.
    #[test]
    fn an_incomplete_installed_version_never_promises_that_a_restart_clears_it() {
        let floor = vec![152, 0, 4191, 66];
        let info = EngineInfo {
            name: "WebView2",
            version: Some(vec![152, 0, 4191, 62]),
            tracking_prevention: "",
            below_floor: true,
            below_compiled_floor: true,
            floor: floor.clone(),
            compiled_floor: &MIN_WEBVIEW2,
            advisory: WEBVIEW2_ADVISORY,
            installed: Some(vec![152, 0, 4191]),
            version_source: EngineVersionSource::Running,
        };
        // The permissive comparison says "not below" for a short version;
        // that is right for a banner and must not become a promise.
        assert!(!below_floor(&[152, 0, 4191], &floor));
        assert!(!info.restart_clears(), "three fields cannot prove the fix is installed");
        let i18n = crate::i18n::I18n::bootstrap("en").unwrap();
        let body = engine_floor_body(&i18n, &info);
        assert!(!body.contains("Restart PATANYX so pages use the new version"), "{body}");
        assert!(body.contains("still use an older version"), "{body}");
        // Full precision at the floor DOES prove it; five fields also do
        // (extra precision beyond the floor is ignored by below_floor).
        let full = EngineInfo { installed: Some(vec![152, 0, 4191, 66]), ..info.clone() };
        assert!(full.restart_clears());
        let longer = EngineInfo { installed: Some(vec![152, 0, 4191, 66, 0]), ..info.clone() };
        assert!(longer.restart_clears());
        // Empty and absent: no promise.
        assert!(!EngineInfo { installed: Some(vec![]), ..info.clone() }.restart_clears());
        assert!(!EngineInfo { installed: None, ..info.clone() }.restart_clears());
    }

    /// THE EFFECTIVE FLOOR is the maximum of three authorities, each of
    /// which can only raise: compiled, release-manifest register, advisory
    /// register. Unknown, lower and mis-shaped values from either register
    /// leave the others in force.
    #[test]
    fn the_effective_floor_is_the_maximum_of_compiled_release_and_advisory() {
        let c = MIN_WEBVIEW2.to_vec();
        assert_eq!(effective_floor_from(&MIN_WEBVIEW2, None, None), c);
        assert_eq!(
            effective_floor_from(&MIN_WEBVIEW2, Some(vec![152, 0, 4191, 70]), None),
            vec![152, 0, 4191, 70]
        );
        assert_eq!(
            effective_floor_from(&MIN_WEBVIEW2, None, Some(vec![152, 0, 4191, 70])),
            vec![152, 0, 4191, 70]
        );
        // Advisory higher than release: advisory wins. Release higher:
        // release wins. Neither is ever lowered by the other.
        assert_eq!(
            effective_floor_from(&MIN_WEBVIEW2, Some(vec![152, 0, 4191, 70]), Some(vec![153, 0, 4300, 1])),
            vec![153, 0, 4300, 1]
        );
        assert_eq!(
            effective_floor_from(&MIN_WEBVIEW2, Some(vec![153, 0, 4300, 1]), Some(vec![152, 0, 4191, 70])),
            vec![153, 0, 4300, 1]
        );
        // Lower or mis-shaped values change nothing.
        assert_eq!(
            effective_floor_from(&MIN_WEBVIEW2, Some(vec![152, 0, 4191, 53]), Some(vec![152, 0, 4191])),
            c
        );
        assert_eq!(effective_floor_from(&MIN_WEBVIEW2, Some(vec![]), Some(vec![0, 0, 0, 0])), c);
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

/// Where the translator webview's own website data lives.
///
/// BESIDE the browsing profile, not inside it. Two reasons, and both are about
/// what a future change would do by accident: a "clear browsing data" that
/// empties the profile directory should not silently delete downloaded
/// language packs, and someone reading the disk should be able to tell which
/// bytes came from browsing and which from translation.
pub fn translator_profile_dir_for(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        .join("translator-data")
}

/// Where downloaded language packs live.
///
/// BESIDE the browsing profile for the reason above, and beside the
/// translator's website data rather than inside it: the engine's own storage is
/// disposable and these files are not. A pack is tens of megabytes the user
/// waited for and consented to fetch; clearing engine state must never throw it
/// away and make them fetch it again.
pub fn translator_pack_dir_for(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        .join("translator-packs")
}

/// The three files one Bergamot language pack is made of.
///
/// NORMALISED NAMES, and this is a security property rather than tidiness.
/// Upstream ships them as `model.enes.intgemm.alphas.bin`,
/// `lex.50.50.enes.s2t.bin` and `vocab.enes.spm` -- names that encode the pair
/// and would have to be BUILT from it at request time. Renaming at install
/// time means the served route is a fixed table with no pair-derived component
/// in any filename, so there is no string concatenation between a request and
/// a path, and therefore nothing to traverse out of.
pub const PACK_FILES: [&str; 3] = ["model.bin", "lex.bin", "vocab.spm"];

/// The same, for a pair whose vocabulary is SPLIT into a source and a target
/// segmenter. Mozilla publishes Japanese and Chinese this way, and its browser
/// hands the engine both; a pack for such a pair carries four parts, not
/// three.
pub const PACK_FILES_SPLIT: [&str; 4] =
    ["model.bin", "lex.bin", "srcvocab.spm", "trgvocab.spm"];

/// What a pack for this vocabulary layout is made of, in CONTAINER ORDER.
///
/// Position is the only thing that names a part -- the container carries no
/// filenames by design -- so this is the single place position becomes a
/// destination, and both layouts share the first two slots.
pub fn pack_files(vocab_layout: &str) -> &'static [&'static str] {
    if vocab_layout == "split" {
        &PACK_FILES_SPLIT
    } else {
        &PACK_FILES
    }
}

/// Every filename any layout can produce, for an allowlist that must not
/// depend on knowing the pair.
pub const PACK_FILES_ANY: [&str; 5] = [
    "model.bin",
    "lex.bin",
    "vocab.spm",
    "srcvocab.spm",
    "trgvocab.spm",
];

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

    /// The exact shape found beside the exe on real hardware, 2026-07-27.
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
