use super::*;
use crate::addon_protocol::{self as proto, Command};

fn ending(flush_id: &str) -> Ending {
    Ending {
        flush_id: flush_id.to_string(),
        then: Then::NOTHING,
        flush_request: None,
        flush_failed: false,
        acked: None,
        lapse: None,
    }
}

fn command(name: &str, args: serde_json::Value) -> Command {
    let frame = json!({ "v": 1, "id": 1, "generation": "7", "command": name, "args": args, "presence": false });
    proto::parse(&frame.to_string()).unwrap_or_else(|_| panic!("{name} did not parse")).command
}

fn put(flush_id: Option<&str>) -> Command {
    command(
        "addon_store_put",
        json!({ "id": null, "base_revision": "0", "title": "t", "body_b64": "eA==", "flush_id": flush_id }),
    )
}

fn done(flush_id: &str) -> Command {
    command("addon_flush_done", json!({ "flush_id": flush_id, "status": "saved" }))
}

const F: &str = "00112233445566778899aabbccddeeff";
const G: &str = "ffeeddccbbaa99887766554433221100";

#[test]
fn an_ending_session_admits_only_its_one_final_save_and_the_acknowledgment() {
    let e = ending(F);
    assert_eq!(admission(Some(&e), &put(Some(F))), None);
    assert_eq!(admission(Some(&e), &done(F)), None);
    // Another flush id, or none, is refused; so is everything ordinary.
    assert_eq!(admission(Some(&e), &put(Some(G))), Some("invalid_flush"));
    assert_eq!(admission(Some(&e), &done(G)), Some("invalid_flush"));
    assert_eq!(admission(Some(&e), &put(None)), Some("session_ending"));
    for (name, args) in [
        ("addon_store_list", json!({ "cursor": null, "limit": 10 })),
        ("vault_notes_list", json!({ "cursor": null, "limit": 10 })),
        ("window_move", json!({ "x": 1.0, "y": 1.0, "sequence": 1 })),
        ("addon_presence", json!({})),
    ] {
        assert_eq!(admission(Some(&e), &command(name, args)), Some("session_ending"), "{name}");
    }
}

#[test]
fn the_final_save_and_the_acknowledgment_are_each_single_use() {
    let mut e = ending(F);
    e.flush_request = Some(4);
    assert_eq!(admission(Some(&e), &put(Some(F))), Some("invalid_flush"));
    assert_eq!(admission(Some(&e), &done(F)), None);
    e.acked = Some(true);
    assert_eq!(admission(Some(&e), &done(F)), Some("invalid_flush"));
    let mut late = ending(F);
    late.acked = Some(false);
    assert_eq!(admission(Some(&late), &put(Some(F))), Some("invalid_flush"));
}

#[test]
fn outside_an_ending_flush_frames_are_refused_and_ordinary_ones_admitted() {
    assert_eq!(admission(None, &put(Some(F))), Some("invalid_flush"));
    assert_eq!(admission(None, &done(F)), Some("invalid_flush"));
    assert_eq!(admission(None, &put(None)), None);
}

#[test]
fn asking_twice_is_asking_once_and_nothing_is_lost() {
    let lock = Then { lock: true, ..Then::NOTHING };
    let close = Then { close: true, ..Then::NOTHING };
    assert_eq!(lock.or(lock), lock);
    let both = lock.or(close);
    assert!(both.lock && both.close && !both.quit_update && !both.quit_relaunch);
}

#[test]
fn the_window_to_save_is_300_ms() {
    assert_eq!(FLUSH_DEADLINE, Duration::from_millis(300));
}

/// The call sites, checked in the source because an AppState cannot be built
/// in a unit test. Each line is one exit path that must end the session
/// through this module before it goes on.
#[test]
fn every_exit_path_ends_the_session_first() {
    let body_of = |source: &'static str, anchor: &str| -> &'static str {
        let start = source.find(anchor).unwrap_or_else(|| panic!("{anchor} moved"));
        let end = start + source[start..].find("\n    }\n").unwrap_or_else(|| panic!("{anchor} has no end"));
        &source[start..end]
    };
    let state = include_str!("state.rs");
    let lock = body_of(state, "pub fn lock_vault(&mut self) {");
    let asked = lock.find("crate::addon_session::on_lock(self)").expect("lock_vault no longer asks the add-on");
    let dropped = lock.find("self.vault = None;").expect("lock_vault no longer drops the vault");
    assert!(asked < dropped, "the add-on must be asked before the vault goes");
    let deadline = body_of(state, "pub fn autolock_deadline(&self) -> Option<Instant> {");
    assert!(deadline.contains("crate::addon_session::lock_pending(self)"), "a held lock would spin the loop");

    let main = include_str!("main.rs");
    for arm in [
        "UserEvent::QuitForUpdate) => {",
        "UserEvent::QuitForRelaunch) => {",
        "event: WindowEvent::CloseRequested,",
        "Event::UserEvent(UserEvent::CloseWindow) => {",
    ] {
        let at = main.find(arm).unwrap_or_else(|| panic!("{arm} moved"));
        let next = &main[at..at + 1200.min(main.len() - at)];
        assert!(
            next.contains("addon_session::hold_close(&mut app)") || next.contains("addon_session::hold_quit(&mut app,"),
            "{arm} no longer ends the add-on session first"
        );
    }
    let destroyed = &main[main.find("Event::LoopDestroyed => {").expect("LoopDestroyed moved")..];
    assert!(destroyed[..600].contains("addon_session::end_now(&mut app)"), "the loop's end no longer ends the session");

    // Free functions end at a closing brace in the first column.
    let function = |source: &'static str, anchor: &str| -> &'static str {
        let start = source.find(anchor).unwrap_or_else(|| panic!("{anchor} moved"));
        let end = start + source[start..].find("\n}\n").unwrap_or_else(|| panic!("{anchor} has no end"));
        &source[start..end]
    };
    let backup = include_str!("backup_job.rs");
    let start = function(backup, "pub fn start_import(");
    assert!(start.contains("crate::addon_session::end(state, crate::addon_session::Reason::VaultImport"));
    let staged = function(backup, "fn staged_ready(state: &mut AppState, staged: Staged) {");
    let barrier = staged.find("crate::addon_session::quiescent(state)").expect("no worker barrier before the commit");
    let detach = staged.find("state.vault = None;").expect("staged_ready moved");
    assert!(barrier < detach, "the barrier must come before the Library is detached");

    let ipc = include_str!("ipc.rs");
    let import = &ipc[ipc.find("\"vault_import\" => {").expect("vault_import moved")..];
    // The older import waits for the add-on to be quiet, ending its window
    // with a save and refusing until the storage worker is done (R-006).
    let quiet = import.find("if !crate::addon_session::quiescent(state) {").expect("the older import no longer waits for the add-on");
    let ended = import.find("crate::addon_session::Reason::VaultImport").expect("the older import no longer ends the session");
    let refused = import.find("return Err(\"addon_busy\");").expect("the older import no longer refuses while the add-on writes");
    let replaced = import.find("replace_library(").expect("vault_import moved");
    assert!(quiet < ended && ended < refused && refused < replaced, "the older import must wait before it replaces the Library");
    let finish = function(ipc, "fn finish_library_replacement(");
    let retired = finish.find("retire_addons(").expect("the older import no longer retires add-on data");
    let cleared = finish.find("clear_library_replace_marker(").expect("finish_library_replacement moved");
    assert!(retired < cleared, "add-on data must go before the replacement marker does (R-004)");

    let host = include_str!("addon_host.rs");
    let close = &host[host.find("Answer::Close => {").expect("window_close moved")..];
    assert!(close[..400].contains("Reason::WindowClose"), "window_close no longer flushes");
}

/// An end asked for during a lapse's save window wins even when nothing is
/// to follow it (an import): the window must not stay open read-only.
#[test]
fn an_end_during_a_lapse_cancels_the_lapse() {
    let source = include_str!("addon_session.rs");
    let end = &source[source.find("pub fn end(").expect("end moved")..];
    let merge = &end[..end.find("start(app, reason, then, None);").expect("end moved")];
    assert!(merge.contains("ending.lapse = None;"), "a lapse would swallow an end that asks for nothing after it");
}
