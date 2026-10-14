//! The job's decisions, and the guards that keep everything else off the vault
//! and the Library while it runs.
//!
//! The decisions are pure and tested as tables. The guards live in the rest of
//! the app; they are pinned at the source, because the failure they prevent
//! (a write an import cannot see, a lock that waits forever, a close that
//! loses the recovery key) only shows in a real window with real timing.

use super::*;

#[test]
fn only_a_job_that_has_not_committed_can_be_stopped() {
    assert!(cancel_allowed(JobPhase::Working));
    assert!(!cancel_allowed(JobPhase::Committing));
}

#[test]
fn a_lock_stops_a_job_unless_it_is_committing() {
    assert_eq!(lock_decision(None), LockDecision::Lock);
    assert_eq!(lock_decision(Some(JobPhase::Working)), LockDecision::StopAndLock);
    assert_eq!(lock_decision(Some(JobPhase::Committing)), LockDecision::LockAfter);
}

#[test]
fn a_close_stops_or_holds_and_a_second_close_always_closes() {
    assert_eq!(close_decision(None, 0), CloseDecision::Exit);
    assert_eq!(close_decision(Some(JobPhase::Working), 0), CloseDecision::StopThenExit);
    assert_eq!(close_decision(Some(JobPhase::Committing), 0), CloseDecision::Hold);
    for phase in [JobPhase::Working, JobPhase::Committing] {
        assert_eq!(close_decision(Some(phase), 1), CloseDecision::Exit, "{phase:?}");
        assert_eq!(close_decision(Some(phase), 7), CloseDecision::Exit, "{phase:?}");
    }
}

// ---- source pins ------------------------------------------------------------------

/// Every app source file without its test module, by name.
fn app_sources() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let code = match text.find("\n#[cfg(test)]\nmod tests") {
            Some(at) => text[..at].to_string(),
            None => text,
        };
        out.push((name, joined_chains(&code)));
    }
    assert!(out.len() > 20, "the app's sources were not found");
    out
}

/// A method chain split across lines (`state\n    .store\n    .as_mut()`)
/// joined back onto one line, so a raw write cannot hide behind rustfmt.
fn joined_chains(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    for line in code.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('.') && !trimmed.starts_with("..") && !out.is_empty() {
            while out.ends_with('\n') || out.ends_with(' ') {
                out.pop();
            }
            out.push_str(trimmed);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// The function an offset falls in: the last `fn name(` before it.
fn enclosing_fn(code: &str, at: usize) -> &str {
    let before = &code[..at];
    let start = before.rfind("fn ").expect("not inside a function");
    let rest = &before[start + 3..];
    &rest[..rest.find('(').unwrap()]
}

/// The IPC arm an offset falls in, if any: the last `"name" =>` before it.
fn enclosing_arm(code: &str, at: usize) -> Option<&str> {
    let before = &code[..at];
    let arm = before.rfind("\" => ")?;
    let open = before[..arm].rfind('"')?;
    Some(&before[open + 1..arm])
}

/// A write an import cannot see is one that does not go through
/// `vault_for_write` / `store_for_write`. The few raw ones left are each
/// refused first while a job runs.
#[test]
fn every_vault_and_library_write_goes_through_the_accessors() {
    let raw = [".vault.as_mut()", ".store.as_mut()", "&mut state.vault", "&mut self.vault"];
    let mut found = Vec::new();
    for (name, code) in app_sources() {
        for pattern in raw {
            for (at, _) in code.match_indices(pattern) {
                found.push((name.clone(), enclosing_fn(&code, at).to_string(), enclosing_arm(&code, at).map(str::to_string)));
            }
        }
        // `&mut self.store` but not `&mut self.store_lock`.
        for (at, _) in code.match_indices("&mut self.store") {
            if !code[at + "&mut self.store".len()..].starts_with('_') {
                found.push((name.clone(), enclosing_fn(&code, at).to_string(), None));
            }
        }
    }
    for (file, function, arm) in &found {
        // The smoke run's own fixtures (ipc.rs `smoke_*`, run only under
        // --smoke-test with no job running) set state up directly.
        let allowed = matches!(
            (file.as_str(), function.as_str(), arm.as_deref()),
            ("state.rs", "vault_for_write" | "store_for_write", _)
                | ("ipc.rs", "store_open", _)
                | ("ipc.rs", _, Some("vault_change_passphrase"))
        ) || (file == "ipc.rs" && function.starts_with("smoke_"));
        assert!(allowed, "a raw vault or Library write in {file}, {function} ({arm:?}): use vault_for_write or store_for_write");
    }
    assert!(found.iter().any(|(_, f, _)| f == "vault_for_write"), "the accessors moved; this pin no longer looks");
    // And it sees chains split across lines: the smoke fixtures use them.
    assert!(
        found.iter().any(|(_, f, _)| f == "smoke_fill_every_kind"),
        "a raw write split across lines is invisible to this pin"
    );
}

/// The body of the function `anchor` opens, up to the closing brace at the
/// anchor's own indentation (none for a free function, four for a method).
fn body<'a>(code: &'a str, anchor: &str) -> &'a str {
    let start = code.find(anchor).unwrap_or_else(|| panic!("{anchor} not found"));
    let line_start = code[..start].rfind('\n').map_or(0, |n| n + 1);
    let close = format!("\n{}}}\n", " ".repeat(start - line_start));
    let end = start + code[start..].find(&close).unwrap_or_else(|| panic!("{anchor} has no end"));
    &code[start..end]
}

fn arm_body<'a>(code: &'a str, arm: &str) -> &'a str {
    let head = format!("        \"{arm}\" => {{");
    let start = code.find(&head).unwrap_or_else(|| panic!("no arm {arm}"));
    let end = start + code[start..].find("\n        }\n").unwrap_or_else(|| panic!("{arm} has no end"));
    &code[start..end]
}

#[test]
fn the_two_raw_writes_left_are_refused_first_during_a_job() {
    let ipc = include_str!("ipc.rs");
    let open = body(ipc, "fn store_open(state: &mut AppState)");
    let refused = open.find("crate::backup_job::importing(state)").expect("store_open no longer refuses during an import");
    assert!(refused < open.find("state.store.as_mut()").unwrap());
    let change = arm_body(ipc, "vault_change_passphrase");
    let refused = change.find("crate::backup_job::refuse_if_running(state)?;").expect("a passphrase change runs under a backup");
    assert!(refused < change.find("state.vault.as_mut()").unwrap());
}

#[test]
fn commands_that_unlock_rewrite_replace_or_quit_are_refused_while_a_job_runs() {
    let ipc = include_str!("ipc.rs");
    for arm in [
        "vault_create",
        "vault_unlock",
        "vault_unlock_recovery",
        "vault_export_encrypted",
        "vault_import",
        "vault_change_passphrase",
        "store_repair_passphrase",
        "tunnel_apply_restart",
        "update_apply",
    ] {
        let body = arm_body(ipc, arm);
        assert!(
            body.contains("crate::backup_job::refuse_if_running(state)?;"),
            "{arm} runs under a backup"
        );
    }
}

#[test]
fn the_lock_asks_the_job_first_and_the_commit_has_no_idle_deadline() {
    let state = include_str!("state.rs");
    let lock = body(state, "pub fn lock_vault(&mut self) {");
    let asked = lock.find("crate::backup_job::on_lock(self)").expect("lock_vault no longer asks the job");
    assert!(asked < lock.find("self.vault = None;").unwrap(), "the vault is dropped before the job is asked");
    let deadline = body(state, "pub fn autolock_deadline(&self) -> Option<Instant> {");
    let none = deadline.find("crate::backup_job::committing(self)").expect("a commit would spin on a past deadline");
    assert!(none < deadline.find("self.autolock_after()").unwrap());
    // And only the commit: a job that can still stop keeps the idle lock.
    assert_eq!(lock_decision(Some(JobPhase::Working)), LockDecision::StopAndLock);
}

#[test]
fn an_answer_or_a_download_arriving_mid_import_waits_for_the_right_vault() {
    let activation = include_str!("activation.rs");
    let handler = body(activation, "fn handle_event_from(");
    assert!(
        handler.contains("state.vault.is_none() || crate::backup_job::importing(state)"),
        "an activation answer would be written into the vault an import is replacing"
    );
    let state = include_str!("state.rs");
    let download = body(state, "pub fn record_download_provenance(");
    let parked = download.find("crate::backup_job::park_download(").expect("a download record would be lost mid-import");
    assert!(parked < download.find("self.record_parked_download(").unwrap());
}

#[test]
fn the_window_asks_the_job_before_closing_and_before_the_end() {
    let main = include_str!("main.rs");
    assert_eq!(main.matches("if backup_job::hold_close(&mut app) {").count(), 2, "both close paths ask the job");
    let destroyed = &main[main.find("Event::LoopDestroyed => {").unwrap()..];
    assert!(destroyed[..200].contains("backup_job::on_exit(&mut app);"));
}

/// The commit's handler attaches what the worker opened and never opens or
/// recovers the Library on this thread (code review: no bulk work at the end).
#[test]
fn the_commit_is_attached_never_reopened_on_this_thread() {
    let job = include_str!("backup_job.rs");
    let ready = body(job, "fn committed_ready(");
    assert!(ready.contains("state.attach_imported_library(library);"));
    for forbidden in ["open_store(", "recover(", "Store::open("] {
        assert!(!ready.contains(forbidden), "committed_ready runs {forbidden} on the UI thread");
    }
    // A late stop removes what was built on a worker, never on this thread
    // (code review round 1, R-005: the previous form of this check was true
    // whatever the code did).
    let staged = body(job, "fn staged_ready(");
    let late = &staged[staged.find("if stopped {").expect("the late-stop branch is gone")..];
    let late = &late[..late.find("\n        return;\n").expect("the late-stop branch no longer returns")];
    let spawned = late.find("spawn_outcome(").expect("a late stop no longer uses a worker");
    let abandoned = late.find("staged.abandon()").expect("a late stop no longer abandons");
    assert!(spawned < abandoned, "a late stop removes its files on this thread");
}

/// Every worker a job starts goes through spawn_outcome, which leaves the
/// result and only then rings, and marks `rang` only once the doorbell was
/// actually sent. The smoke driver refuses a result that never rang, so a
/// worker that forgot its doorbell fails there instead of hanging the real app
/// (code review round 2, R-004).
#[test]
fn every_worker_rings_the_doorbell_through_one_place() {
    let job = include_str!("backup_job.rs");
    let code = &job[..job.find("#[cfg(test)]\n#[path").unwrap()];
    // The ticker, the close grace timer, and spawn_outcome: nothing else.
    assert_eq!(code.matches("std::thread::spawn(").count(), 3, "a worker started outside spawn_outcome");
    let helper = body(job, "fn spawn_outcome(");
    let filled = helper.find("*slot = Some(outcome);").unwrap();
    let rung = helper.find("send_event(UserEvent::BackupJob(Bell::Ready(id)))").unwrap();
    let marked = helper.find("rang.store(true, Ordering::SeqCst);").unwrap();
    assert!(filled < rung && rung < marked, "the doorbell rings before the result is there, or rang is set without it");
    let step = body(job, "pub fn drive_step(");
    assert!(step.contains("if !job.rang.load(Ordering::SeqCst) {\n        return None;"), "the smoke driver fabricates the doorbell");
}

/// An activation answer belongs to the vault epoch its call started in: an
/// import that may have replaced the vault moves the epoch, and the answer is
/// then dropped (code review round 2 R-002; round 3 R-004 asked for coverage
/// that fails when any part is removed).
#[test]
fn an_activation_answer_from_before_a_replacement_is_dropped() {
    use crate::activation::answer_belongs;
    assert!(answer_belongs(Some(3), 3), "an answer for the open vault was dropped");
    assert!(!answer_belongs(Some(3), 4), "an answer from before a replacement was kept");
    assert!(answer_belongs(None, 4), "an answer with no recorded epoch was dropped");
    let activation = include_str!("activation.rs");
    assert_eq!(
        activation.matches("state.activation_epoch.set(Some(state.vault_epoch));").count(),
        2,
        "an activation or release call no longer records its epoch"
    );
    let handler = body(activation, "fn handle_event_from(");
    assert!(handler.contains("if !answer_belongs(state.activation_epoch.take(), state.vault_epoch) {"));
    let job = include_str!("backup_job.rs");
    let staged = body(job, "fn staged_ready(");
    let moved = staged.find("state.vault_epoch += 1;").expect("a commit no longer moves the epoch");
    assert!(moved < staged.find("vault_backup::commit(").unwrap());
    assert!(!body(job, "pub fn cancel(").contains("vault_epoch"), "a stop moves the epoch");
    assert!(include_str!("ipc.rs").contains("state.vault = None;\n                // The vault may be replaced from here on"));
}

/// A result followed by a lock never carries the one-time recovery key.
#[test]
fn a_result_a_lock_follows_carries_no_recovery_key() {
    let job = include_str!("backup_job.rs");
    let finished = body(job, "fn finish(");
    let stripped = finished.find("data.remove(\"recovery_key\")").expect("the key travels although a lock follows");
    let emitted = finished.find("state.emit(\"backup_finished\"").unwrap();
    assert!(stripped < emitted);
    assert!(finished.contains("\"lock_follows\": job.lock_after"));
}

/// The commit runs with no idle deadline; its end asks whether the idle lock
/// came due meanwhile, before the new session's first touch resets the clock
/// (code review round 1, R-002), and then starts the countdown rather than
/// locking with no warning (compliance audit).
#[test]
fn an_idle_deadline_passed_during_the_commit_starts_the_countdown() {
    let job = include_str!("backup_job.rs");
    let ready = body(job, "fn committed_ready(");
    let asked = ready.find("let idle_due = state.idle_lock_due();").expect("the idle deadline is no longer asked");
    let touched = ready.find("state.touch();").unwrap();
    let armed = ready.find("state.arm_idle_warning_now();").expect("a due idle lock no longer warns");
    assert!(asked < touched && touched < armed, "the clock is reset before the deadline is read");
    assert!(!ready.contains("lock_after = true"), "an idle commit locks with no countdown");
}

/// An import that reached its commit drops answers parked for the vault it may
/// have replaced; one that never committed replays them (code review round 1,
/// R-003).
#[test]
fn parked_answers_follow_the_vault_they_belong_to() {
    let job = include_str!("backup_job.rs");
    let finished = body(job, "fn finish(");
    assert!(finished.contains("if original_kept && job.kind == JobKind::Import {\n        crate::activation::replay_pending(state);"));
    assert!(finished.contains("if !original_kept && job.kind == JobKind::Import {\n        state.pending_activation_event = None;"));
    let handled = body(job, "fn handle(");
    assert!(handled.contains("finish(state, Err(\"backup_failed\"), !committing)"), "a crash's ownership of parked answers changed");
}


/// The whole-Library import keeps every guarantee the synchronous one had, in
/// the same order, now spread over the job's handlers (ported from the pin on
/// the removed `import_whole_backup`): the Library lock before anything,
/// nothing closed until the backup is fully read and staged, a failed commit
/// locks the session and gives the lock back, and the imported vault's
/// session starts only after it is in and its Library attached.
#[test]
fn a_whole_library_import_keeps_the_older_imports_order() {
    let job = include_str!("backup_job.rs");
    let at = |body: &str, needle: &str| body.find(needle).unwrap_or_else(|| panic!("`{needle}` is gone"));

    let start = body(job, "pub fn start_import(");
    let lock = at(start, "state.hold_library_lock(\"import_library_in_use\")?;");
    let transaction = at(start, "patanyx_vault::lock::acquire(&marker)");
    let stage = at(start, "vault_backup::stage_with(");
    assert!(lock < transaction && transaction < stage, "locks before anything is read");

    let handled = body(job, "fn handle(");
    assert!(
        handled.contains("Outcome::Staged(Ok(staged)) => {\n            staged_ready(state, staged);"),
        "the live profile is closed on a path other than a staged backup"
    );
    let staged = body(job, "fn staged_ready(");
    let stopped = at(staged, "job.watch.is_stopped()");
    let vault_closed = at(staged, "state.vault = None;");
    let store_closed = at(staged, "state.store = None;");
    let ended = at(staged, "state.end_vault_session();");
    let commit = at(staged, "vault_backup::commit(");
    assert!(stopped < vault_closed, "a stop that arrived late is not honoured before closing");
    assert!(vault_closed < commit && store_closed < commit && ended < commit, "nothing writes to the files being replaced");

    let failed = at(handled, "// As the synchronous import did");
    let failed_branch = &handled[failed..];
    let released = at(failed_branch, "release_import_locks(state);");
    let relock = at(failed_branch, "job.lock_after |= had_live;");
    let reported = at(failed_branch, "finish(state, Err(code), false)");
    assert!(released < reported && relock < reported, "a failed commit locks and gives the lock back");
    let finished = body(job, "fn finish(");
    assert!(finished.contains("if job.lock_after {\n        state.lock_vault();"), "the lock after a failed commit is gone");

    let ready = body(job, "fn committed_ready(");
    let installed = at(ready, "state.vault = Some(vault);");
    let attached = at(ready, "state.attach_imported_library(library);");
    let starts = at(ready, "crate::ipc::start_imported_vault_session(state);");
    assert!(installed < attached && attached < starts, "the Library moves in before the session starts");
    assert!(ready.contains("finish(state, Ok(payload), false)"), "a committed import replays the old vault's parked results");
    assert!(!ready.contains("replay_pending"));
    assert!(
        finished.contains("if original_kept && job.kind == JobKind::Import {\n        crate::activation::replay_pending(state);"),
        "a stopped import no longer gives the original vault its parked results"
    );
}


/// The result tells the chrome the idle countdown started (code review round
/// 4, R-001), and the patient lock runs only on the commit worker's path,
/// never on the UI thread's older import (R-004).
#[test]
fn the_countdown_is_announced_and_the_lock_waits_only_off_the_ui_thread() {
    let job = include_str!("backup_job.rs");
    let ready = body(job, "fn committed_ready(");
    assert!(ready.contains("if idle_due {\n        payload[\"idle_warning\"] = json!(true);"));
    let backup = include_str!("vault_backup.rs");
    assert!(backup.contains("pending.install_waiting(vault_path, new_passphrase, std::time::Duration::from_millis(500))"));
    let v4 = include_str!("../../vault/src/backup_v4.rs");
    let install = body(v4, "    pub fn install(\n");
    assert!(install.contains("self.install_waiting(dest, new_vault_passphrase, std::time::Duration::ZERO)"), "the UI thread's import waits for the lock");
    let lib = include_str!("../../vault/src/lib.rs");
    let assemble = body(lib, "    pub(crate) fn assemble(\n");
    assert!(assemble.contains("std::time::Duration::ZERO"), "an import on the UI thread sleeps for the lock");
}
