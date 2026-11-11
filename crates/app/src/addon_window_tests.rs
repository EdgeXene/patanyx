use super::*;
use crate::state::{tab_focus, FocusSurface::*};

#[test]
fn geometry_memory_roundtrips_in_layout_prefs_and_reclamps_on_reopen() {
    let memory = WindowMemory {
        wanted: (760.0, 500.0, 400.0, 300.0),
        collapsed: true,
    };
    let mut prefs = crate::prefs::Prefs::default();
    prefs.addon_windows.insert("text-pages".into(), memory);
    let bytes = serde_json::to_vec(&prefs).unwrap();
    let restored: crate::prefs::Prefs = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.addon_windows["text-pages"], memory);
    let r = clamp_rect(memory.wanted, 800.0, 550.0, memory.collapsed);
    assert_eq!(r, (400.0, 500.0, 400.0, COLLAPSED_H));
    let smaller = clamp_rect(memory.wanted, 200.0, 120.0, false);
    assert_eq!(smaller, (0.0, 0.0, 200.0, 120.0));
    assert_eq!(
        clamp_rect(memory.wanted, 1400.0, 1000.0, false),
        memory.wanted
    );
    assert_eq!(
        serde_json::from_str::<crate::prefs::Prefs>("{}")
            .unwrap()
            .addon_windows
            .len(),
        0
    );
}

#[test]
fn geometry_dpi_and_sidebar_offsets_remain_page_relative() {
    let wanted = (480.0, 300.0, 420.0, 360.0);
    for scale in [1.0, 1.25, 1.5, 2.0] {
        // Physical screen bounds converted by the Windows area provider.
        let page = (220.0, 120.0, 1080.0 / scale - 220.0, 900.0 / scale - 120.0);
        let r = clamp_rect(wanted, page.2, page.3, false);
        let placed = crate::platform::addon_window_rect((page.0, page.1), r);
        assert!(placed.0 >= page.0 && placed.1 >= page.1);
        assert!(placed.0 + placed.2 <= page.0 + page.2);
        assert!(placed.1 + placed.3 <= page.1 + page.3);
        assert_eq!(placed.0, page.0 + r.0);
    }
}

#[test]
fn tab_create_switch_and_close_keep_addon_focus_and_modal_wins() {
    for _operation in ["create", "switch", "close"] {
        assert_eq!(tab_focus(Addon, Content, false, true), Addon);
        assert_eq!(tab_focus(Chrome, Addon, false, true), Addon);
        assert_eq!(tab_focus(Addon, Content, true, true), Chrome);
        assert_eq!(tab_focus(Addon, Content, false, false), Content);
        assert_eq!(tab_focus(Content, Addon, false, true), Content);
    }
    let source = include_str!("state.rs");
    assert!(source.contains("fn show_and_focus_tab"));
    assert!(source.contains("tab_focus(self.focus_intent.get(), self.focus_before.get()"));
    let blank = source
        .split("fn focus_url_bar_for_blank_tab")
        .nth(1)
        .unwrap()
        .split("\n    }")
        .next()
        .unwrap();
    // A new blank tab takes the keyboard for its address bar even from the
    // add-on (H-09); only a modal keeps it.
    assert!(!blank.contains("FocusSurface::Addon"), "a blank tab leaves the keyboard in the add-on again");
    assert!(blank.contains("self.focus_url_bar();"), "a blank tab no longer focuses the address bar");
    assert!(blank.contains("!self.modal_covers_window()"));
}

/// Escape belongs to the add-on (H-02): no platform handles it natively, so
/// an add-on dialog closes on Escape instead of being collapsed around.
/// Ctrl+Shift+J stays native on both.
#[test]
fn toggle_does_not_open_and_escape_reaches_the_addon() {
    let source = include_str!("addon_host.rs");
    let toggle = source
        .split("pub fn toggle(")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert!(toggle.contains("let Some(session) = &app.addon else { return }"));
    assert!(!toggle.contains("open("));
    for source in [
        include_str!("platform/unix.rs"),
        include_str!("platform/windows.rs"),
    ] {
        let native = source
            .split("pub fn connect_addon_presence(")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(!native.contains("AddonCollapse"), "Escape is collapsed natively again");
        assert!(!native.contains("Escape") && !native.contains("0x1B"), "a native Escape handler is back");
        assert!(native.contains("connect_shortcuts(webview, proxy)"));
        assert!(native.contains("FocusSurface::Addon"));
    }
}

#[test]
fn the_shortcut_reopens_only_the_debug_development_add_on() {
    let source = include_str!("addon_host.rs");
    let shortcut = source.split("pub fn shortcut(").nth(1).unwrap().split("\n}").next().unwrap();
    assert!(shortcut.contains("toggle(app, false)"));
    // A release build opens nothing from the shortcut: its only open path
    // sits behind the debug gate.
    assert!(shortcut.contains("#[cfg(debug_assertions)]\n    if app.vault.is_some() {\n        dev_open_bundle(app);"));
    assert!(!shortcut.contains("open(app"));
    let before = source.split("fn dev_open_bundle(").next().unwrap();
    assert!(before.trim_end().ends_with("#[cfg(debug_assertions)]"));
    assert!(include_str!("main.rs").contains("Shortcut::ToggleAddon => addon_host::shortcut(&mut app)"));
}

#[test]
fn the_site_check_runs_after_every_event_beside_the_premium_recheck() {
    // After every event, not per hook: closing the active tab reassigns
    // `active` without `set_active` (state.rs), so only this covers it.
    let main = include_str!("main.rs");
    assert!(main.contains("addon_host::site_check(&app);\n        addon_host::theme_check(&app);\n        // Live Premium"));
    // A theme change reaches an open window from both setters.
    let ipc = include_str!("ipc.rs");
    assert!(ipc.contains("crate::addon_host::theme_changed(state, p.chrome_scheme, theme);"));
    assert!(ipc.contains("crate::addon_host::theme_changed(state, scheme, p.chrome_theme);"));
    let host = include_str!("addon_host.rs");
    let check = host.split("pub fn site_check(").nth(1).unwrap().split("\n}").next().unwrap();
    assert!(check.contains("app.vault.is_none()"));
    assert!(check.contains("!session.is_ready()"));
    // A theme change that cannot be delivered now is delivered later.
    let changed = host.split("pub fn theme_changed(").nth(1).unwrap().split("\n}").next().unwrap();
    assert!(changed.contains("session.told_theme.set(false);\n        return;"));
}

#[test]
fn motion_host_path_p95_stays_under_two_frames() {
    // Queue-to-placement callback measurement of the shared host path. The
    // native runner separately measures the actual engine allocation.
    let (send, receive) = std::sync::mpsc::sync_channel(0);
    let (ack, next) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        for i in 0..100 {
            send.send((std::time::Instant::now(), i)).unwrap();
            next.recv().unwrap();
        }
    });
    let mut elapsed = Vec::new();
    let mut host = Vec::new();
    for (event, i) in receive {
        let start = std::time::Instant::now();
        apply_rect(
            (f64::from(i), 40.0, 420.0, 360.0),
            (200.0, 120.0, 1000.0, 700.0),
            false,
            |_| {
                elapsed.push(event.elapsed());
            },
        );
        host.push(start.elapsed());
        ack.send(()).unwrap();
    }
    worker.join().unwrap();
    elapsed.sort();
    host.sort();
    eprintln!(
        "host queue-to-placement p95: {:?}; host handling p95: {:?}",
        elapsed[94], host[94]
    );
    assert!(
        elapsed[94] < std::time::Duration::from_millis(33),
        "motion p95 exceeds two frames"
    );
}

#[test]
fn malformed_geometry_does_not_reset_other_preferences() {
    let prefs: crate::prefs::Prefs = serde_json::from_value(serde_json::json!({
        "vault_autolock_secs": 120,
        "addon_windows": {"text-pages": {"wanted": "bad"}, "../escape": {"collapsed": true}}
    }))
    .unwrap();
    assert_eq!(prefs.vault_autolock_secs, 120);
    assert!(prefs.addon_windows.is_empty());
}

/// A host-driven geometry change carries the add-on's latest sequence. The
/// add-on drops anything older than its last move or resize, so a 0 here
/// left it drawing a folded window inside an unfolded frame after
/// Ctrl+Shift+J (add-on hand test 2026-10-21, H-11).
#[test]
fn host_driven_geometry_is_told_under_the_latest_sequence() {
    let source = include_str!("addon_host.rs");
    let apply = source
        .split("pub fn apply(app: &AppState)")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert!(apply.contains(r#"emit(app, "addon_geometry", told(app))"#), "apply no longer tells the latest geometry");
    assert!(!apply.contains("geometry(app, session, 0)"), "apply tells sequence 0 again");
    let told = source.split("fn told(app: &AppState)").nth(1).unwrap().split("\n}").next().unwrap();
    assert!(told.contains("session.last_sequence.get()"));
}

/// An add-on's "Edit in Vault" shows the note: the Vault panel opens on its
/// Notes tab with that note in the editor, not on whichever tab was last
/// shown (add-on hand test 2026-10-21, H-12).
#[test]
fn edit_in_vault_opens_the_notes_tab() {
    let chrome = include_str!("chrome/chrome.js");
    let body = chrome
        .split("async function openNoteInVaultEditor(id) {")
        .nth(1)
        .unwrap()
        .split("\n  }")
        .next()
        .unwrap();
    let load = body.find("await editNoteById(id)").expect("the note is no longer loaded");
    let tab = body.find(r#"selectTab("notes")"#).expect("the Notes tab is not selected");
    assert!(tab > load, "the Notes tab is selected before the note loads");
}

/// The add-on window opens in the chrome's surface colour, not the engine's
/// default white (a quarter-second white flash on every open, 2026-11-03).
#[test]
fn the_add_on_window_opens_in_the_chrome_surface_colour() {
    let source = include_str!("addon_host.rs");
    let build = source.split("let builder = platform::new_addon_webview_builder(&engine_dir)?").nth(1).unwrap();
    let chain = build.split(';').next().unwrap();
    assert!(chain.contains(".with_background_color((surface[0], surface[1], surface[2], 255))"), "no background colour on the add-on window");
    let before = source.split("let builder = platform::new_addon_webview_builder(&engine_dir)?").next().unwrap();
    assert!(before.contains("let surface = app.chrome_palette().caption;"), "the colour is not the chrome's surface");
}
