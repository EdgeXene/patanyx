//! Export and import of the whole Library on worker threads, with progress
//! and Stop.
//!
//! WHY A JOB. A Library with its pictures can take minutes to seal or to read
//! back, and both used to run inside the IPC call, on the thread that draws
//! the window: the browser froze for the whole backup and nothing could stop
//! it. Now the IPC call answers at once with `{job}`, a worker does the slow
//! part, and the result arrives as a `backup_finished` event carrying exactly
//! the payload the call used to return.
//!
//! WHAT RUNS WHERE.
//! - Export: one worker, on a snapshot taken here ([`ExportInput::take`]), so
//!   it never borrows the vault or the Library.
//! - Import, phase A ([`vault_backup::stage_with`]): reads the file once and
//!   builds the Library aside. Stoppable; nothing live changes.
//! - Import, phase B ([`vault_backup::commit`]): writes the imported vault,
//!   moves its Library into place, checks it, opens it. NOT stoppable: past
//!   the vault write, stopping would leave a vault without its Library.
//! - This thread decides between the phases, holds the Library lock and the
//!   import lock for the whole job, closes the live vault and Library before
//!   phase B, and attaches what phase B hands back. It never waits on a
//!   worker; a worker never touches `AppState`.
//!
//! The on-disk protocol (the import journal, its phases, the locks, what
//! recovery decides) is exactly the synchronous import's: only the thread
//! running each step changed, so a crash at any point is recovered as before.
//!
//! HOW A WORKER REPORTS. It puts its result in the job's mailbox and rings a
//! doorbell (`UserEvent::BackupJob(Bell::Ready)`). Progress is shared atomics
//! ([`BackupWatch`]); a ticker thread rings `Bell::Tick` four times a second
//! and a `backup_progress` event goes out only when something changed.
//!
//! WHILE A JOB RUNS.
//! - One job at a time. Commands that would rewrite the vault or the Library
//!   underneath it are refused with `backup_in_progress`
//!   ([`refuse_if_running`]).
//! - During an import, nothing may write to the vault or the Library about to
//!   be replaced: every write goes through `AppState::vault_for_write` and
//!   `store_for_write`, which refuse. A finished download's record is parked
//!   and written into whichever Library is open when the job ends; an
//!   activation answer is parked by `activation` and replayed only if the
//!   original vault is still the one open.
//! - A lock stops an export or an import that has not committed, and locks at
//!   once; the idle lock therefore still fires on time. During an import's
//!   commit the lock waits for the result, and there is no idle deadline
//!   (a past deadline would spin the event loop); the commit is bounded.
//! - A close stops an export or an uncommitted import and closes when the
//!   worker reports (or after a grace period). During a commit the close is
//!   held, because closing then loses the one-time recovery key; a second
//!   close always closes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use patanyx_store::Store;
use patanyx_vault::{BackupStage, BackupWatch, ExportError, VaultLock, WatchSnapshot};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::state::AppState;
use crate::vault_backup::{self, Committed, ExportInput, ExportOutcome, ImportError, Staged};
use crate::UserEvent;

/// How often a running job's progress is looked at.
const TICK: Duration = Duration::from_millis(250);
/// How long a close waits for a stopped worker before closing anyway.
const CLOSE_GRACE: Duration = Duration::from_secs(10);
/// How long the end of the program waits for a stopped worker, so an
/// export's temporary file is removed.
const EXIT_WAIT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    Export,
    Import,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPhase {
    /// An export writing, or an import reading and building aside. Stoppable.
    Working,
    /// An import's commit: the vault is being written and its Library moved
    /// into place. Not stoppable.
    Committing,
}

/// Why a job was stopped, for the words the person sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Person,
    Lock,
    Close,
}

/// What a doorbell says.
#[derive(Clone, Copy, Debug)]
pub enum Bell {
    /// Look at the progress of job `n`.
    Tick(u64),
    /// Job `n`'s worker left its result in the mailbox.
    Ready(u64),
}

/// What a worker leaves in the mailbox.
enum Outcome {
    Exported(Result<ExportOutcome, ExportError>),
    Staged(Result<Staged, ImportError>),
    Committed(Box<Result<Committed, ImportError>>),
    Abandoned(std::io::Result<()>),
    Panicked,
}

type Mailbox = Arc<Mutex<Option<Outcome>>>;

/// A download that finished while an import was replacing the Library. Its
/// file was hashed when it finished; the record waits for the Library.
pub struct ParkedDownload {
    url: String,
    filename: String,
    byte_len: u64,
    sha256: [u8; 32],
}

/// What an import holds from start to end.
struct ImportHold {
    /// Whether this job took the Library lock (and so releases it on failure).
    newly_locked: bool,
    /// The import lock, held until the job ends.
    transaction: Option<VaultLock>,
    new_passphrase: Zeroizing<String>,
    /// Whether a vault was open when the commit began (phase B).
    had_live_vault: bool,
    /// A Library on disk that was not open cannot vouch for its download
    /// records, so none were kept; said in the result.
    library_was_closed: bool,
}

pub struct BackupJob {
    pub id: u64,
    pub kind: JobKind,
    pub phase: JobPhase,
    watch: BackupWatch,
    /// Cleared when the job ends, so its ticker stops.
    alive: Arc<AtomicBool>,
    mailbox: Mailbox,
    /// Set by a worker only once its doorbell was actually sent, so the smoke
    /// run's driver can tell a result that was delivered from one that would
    /// have sat unnoticed in the mailbox (code review round 2, R-004).
    rang: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    last_sent: Option<WatchSnapshot>,
    pub stop_reason: Option<StopReason>,
    /// A lock asked for during the commit: it happens once the result is
    /// handled.
    pub lock_after: bool,
    /// Close requests seen while this job ran.
    pub close_requests: u8,
    /// A close stopped this job: the window closes when it ends. Never set by
    /// a close held during a commit, which must not close by itself once the
    /// recovery key is on screen.
    exit_when_done: bool,
    import: Option<ImportHold>,
    parked_downloads: Vec<ParkedDownload>,
}

impl std::fmt::Debug for BackupJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupJob")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("phase", &self.phase)
            .field("stop_reason", &self.stop_reason)
            .finish_non_exhaustive()
    }
}

// ---- decisions (pure, tested on their own) --------------------------------------

/// Whether a person may stop a job in this phase.
pub(crate) fn cancel_allowed(phase: JobPhase) -> bool {
    matches!(phase, JobPhase::Working)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockDecision {
    /// No job: lock as always.
    Lock,
    /// Stop the job, and lock at once.
    StopAndLock,
    /// The commit cannot be stopped: lock when its result has been handled.
    LockAfter,
}

pub(crate) fn lock_decision(phase: Option<JobPhase>) -> LockDecision {
    match phase {
        None => LockDecision::Lock,
        Some(JobPhase::Working) => LockDecision::StopAndLock,
        Some(JobPhase::Committing) => LockDecision::LockAfter,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseDecision {
    /// Close now.
    Exit,
    /// Stop the job; close when the worker reports, or after the grace.
    StopThenExit,
    /// The commit is running: hold the close, say what closing now costs.
    Hold,
}

/// `requests_before`: close requests already seen during this job. A second
/// request always closes.
pub(crate) fn close_decision(phase: Option<JobPhase>, requests_before: u8) -> CloseDecision {
    match (phase, requests_before) {
        (None, _) => CloseDecision::Exit,
        (Some(_), n) if n >= 1 => CloseDecision::Exit,
        (Some(JobPhase::Working), _) => CloseDecision::StopThenExit,
        (Some(JobPhase::Committing), _) => CloseDecision::Hold,
    }
}

// ---- what the rest of the app asks ---------------------------------------------

/// `Err("backup_in_progress")` while any job runs: for commands that rewrite
/// the vault or the Library, unlock or create one, or quit to update.
pub fn refuse_if_running(state: &AppState) -> Result<(), &'static str> {
    if state.backup_job.is_some() {
        Err("backup_in_progress")
    } else {
        Ok(())
    }
}

/// Whether an import job is replacing the vault and the Library.
pub fn importing(state: &AppState) -> bool {
    state
        .backup_job
        .as_ref()
        .is_some_and(|job| job.kind == JobKind::Import)
}

/// Whether an import is in its commit, when there is no idle deadline.
pub fn committing(state: &AppState) -> bool {
    state
        .backup_job
        .as_ref()
        .is_some_and(|job| job.phase == JobPhase::Committing)
}

/// Asked first by `lock_vault`. True: lock now. False: the lock waits for the
/// commit's result.
pub fn on_lock(state: &mut AppState) -> bool {
    let phase = state.backup_job.as_ref().map(|job| job.phase);
    match lock_decision(phase) {
        LockDecision::Lock => true,
        LockDecision::StopAndLock => {
            if let Some(job) = state.backup_job.as_mut() {
                job.watch.stop();
                job.stop_reason.get_or_insert(StopReason::Lock);
            }
            true
        }
        LockDecision::LockAfter => {
            if let Some(job) = state.backup_job.as_mut() {
                job.lock_after = true;
            }
            false
        }
    }
}

/// Asked by the close arms. True: close now.
pub fn hold_close(state: &mut AppState) -> bool {
    let phase = state.backup_job.as_ref().map(|job| job.phase);
    let before = state.backup_job.as_ref().map_or(0, |job| job.close_requests);
    let decision = close_decision(phase, before);
    if let Some(job) = state.backup_job.as_mut() {
        job.close_requests = job.close_requests.saturating_add(1);
    }
    match decision {
        CloseDecision::Exit => true,
        CloseDecision::StopThenExit => {
            let (kind, id) = match state.backup_job.as_mut() {
                Some(job) => {
                    job.watch.stop();
                    job.stop_reason.get_or_insert(StopReason::Close);
                    job.exit_when_done = true;
                    (job.kind, job.id)
                }
                None => return true,
            };
            state.emit(
                "backup_close_held",
                json!({ "job": id, "kind": kind_name(kind), "committing": false }),
            );
            // The grace: a worker that does not report in time is not waited
            // on forever. The second close this sends always closes.
            let proxy = state.proxy();
            std::thread::spawn(move || {
                std::thread::sleep(CLOSE_GRACE);
                let _ = proxy.send_event(UserEvent::CloseWindow);
            });
            false
        }
        CloseDecision::Hold => {
            let id = state.backup_job.as_ref().map_or(0, |job| job.id);
            state.emit(
                "backup_close_held",
                json!({ "job": id, "kind": "import", "committing": true }),
            );
            false
        }
    }
}

/// A finished download while an import replaces the Library: kept for the
/// Library that is open when the job ends. False when no import runs.
pub fn park_download(state: &mut AppState, url: &str, filename: &str, byte_len: u64, sha256: [u8; 32]) -> bool {
    match state.backup_job.as_mut() {
        Some(job) if job.kind == JobKind::Import => {
            job.parked_downloads.push(ParkedDownload {
                url: url.to_string(),
                filename: filename.to_string(),
                byte_len,
                sha256,
            });
            true
        }
        _ => false,
    }
}

/// `backup_job_status`: what a reopened panel needs to redraw a running job.
/// Never the result; that comes once, in `backup_finished`.
pub fn status(state: &AppState) -> Value {
    match state.backup_job.as_ref() {
        None => json!({ "job": Value::Null }),
        Some(job) => progress_json(job, &job.watch.snapshot()),
    }
}

/// `backup_job_cancel {job}`.
pub fn cancel(state: &mut AppState, id: u64) -> Result<Value, &'static str> {
    let job = match state.backup_job.as_mut() {
        Some(job) if job.id == id => job,
        _ => return Err("backup_not_running"),
    };
    if !cancel_allowed(job.phase) {
        return Err("backup_past_commit");
    }
    job.watch.stop();
    job.stop_reason.get_or_insert(StopReason::Person);
    Ok(json!({}))
}

// ---- starting --------------------------------------------------------------------

/// `vault_export_encrypted`: takes the snapshot here and writes on a worker.
pub fn start_export(
    state: &mut AppState,
    dest: std::path::PathBuf,
    passphrase: Zeroizing<String>,
) -> Result<Value, &'static str> {
    refuse_if_running(state)?;
    let vault = state.vault.as_ref().ok_or("not_unlocked")?;
    let input = ExportInput::take(vault, state.store.as_ref()).map_err(crate::ipc::export_code)?;
    let mut job = new_job(state, JobKind::Export);
    let watch = job.watch.clone();
    job.worker = Some(spawn_outcome(state.proxy(), &job, move || {
        Outcome::Exported(input.write(&dest, &passphrase, &watch))
    }));
    Ok(start(state, job))
}

/// `vault_import` for a whole-Library backup: takes the locks and what the
/// import keeps here, and runs phase A on a worker.
pub fn start_import(
    state: &mut AppState,
    src: std::path::PathBuf,
    passphrase: Zeroizing<String>,
    new_passphrase: Zeroizing<String>,
) -> Result<Value, &'static str> {
    refuse_if_running(state)?;
    let newly_locked = state.hold_library_lock("import_library_in_use")?;
    // The same lock the import of an older backup takes, keyed on the same
    // marker path, so the two kinds never run at once either.
    let marker = state.library_replace_marker();
    let transaction = match patanyx_vault::lock::acquire(&marker) {
        Ok(lock) => lock,
        Err(_) => {
            state.release_unused_library_lock(newly_locked);
            return Err("library_replace_refused");
        }
    };
    let kept = state.store.as_ref().map(Store::kept_downloads);
    let library_was_closed = state.store.is_none() && Store::exists(&state.store_path);
    let store_path = state.store_path.clone();
    let mut job = new_job(state, JobKind::Import);
    job.import = Some(ImportHold {
        newly_locked,
        transaction: Some(transaction),
        new_passphrase,
        had_live_vault: false,
        library_was_closed,
    });
    let watch = job.watch.clone();
    job.worker = Some(spawn_outcome(state.proxy(), &job, move || {
        Outcome::Staged(vault_backup::stage_with(&store_path, &src, &passphrase, kept.as_ref(), &watch))
    }));
    Ok(start(state, job))
}

fn new_job(state: &mut AppState, kind: JobKind) -> BackupJob {
    state.backup_job_seq += 1;
    BackupJob {
        id: state.backup_job_seq,
        kind,
        phase: JobPhase::Working,
        watch: BackupWatch::new(),
        alive: Arc::new(AtomicBool::new(true)),
        mailbox: Arc::new(Mutex::new(None)),
        rang: Arc::new(AtomicBool::new(false)),
        worker: None,
        last_sent: None,
        stop_reason: None,
        lock_after: false,
        close_requests: 0,
        exit_when_done: false,
        import: None,
        parked_downloads: Vec::new(),
    }
}

fn start(state: &mut AppState, job: BackupJob) -> Value {
    let id = job.id;
    let kind = job.kind;
    // Four times a second while the job lives; the event loop decides
    // whether anything changed. Never more, by construction.
    let alive = Arc::clone(&job.alive);
    let proxy = state.proxy();
    std::thread::spawn(move || {
        while alive.load(Ordering::SeqCst) {
            std::thread::sleep(TICK);
            if !alive.load(Ordering::SeqCst) || proxy.send_event(UserEvent::BackupJob(Bell::Tick(id))).is_err() {
                break;
            }
        }
    });
    state.backup_job = Some(job);
    json!({ "job": id, "kind": kind_name(kind) })
}

/// Runs `work` on a worker: THE way every worker of a job starts. Its result
/// goes in the mailbox, then the doorbell rings, then `rang` is set. A panic
/// still rings, as `Panicked`: an import's journal then decides at the next
/// open, as after a crash.
fn spawn_outcome(
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
    job: &BackupJob,
    work: impl FnOnce() -> Outcome + Send + 'static,
) -> JoinHandle<()> {
    let mailbox = Arc::clone(&job.mailbox);
    let rang = Arc::clone(&job.rang);
    rang.store(false, Ordering::SeqCst);
    let id = job.id;
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
            .unwrap_or(Outcome::Panicked);
        if let Ok(mut slot) = mailbox.lock() {
            *slot = Some(outcome);
        }
        if proxy.send_event(UserEvent::BackupJob(Bell::Ready(id))).is_ok() {
            rang.store(true, Ordering::SeqCst);
        }
    })
}

// ---- the event loop's side ------------------------------------------------------

/// `UserEvent::BackupJob`. Returns the `backup_finished` event when this bell
/// ended the job (the smoke run reads it; nothing keeps it).
pub fn on_bell(state: &mut AppState, bell: Bell) -> Option<Value> {
    match bell {
        Bell::Tick(id) => {
            tick(state, id);
            None
        }
        Bell::Ready(id) => {
            let outcome = match state.backup_job.as_mut() {
                Some(job) if job.id == id => {
                    if let Some(worker) = job.worker.take() {
                        // It rang after leaving its result: joining is immediate.
                        let _ = worker.join();
                    }
                    job.mailbox.lock().ok().and_then(|mut slot| slot.take())
                }
                _ => None,
            };
            outcome.and_then(|outcome| handle(state, outcome))
        }
    }
}

fn tick(state: &mut AppState, id: u64) {
    let Some(job) = state.backup_job.as_mut() else {
        return;
    };
    if job.id != id {
        return;
    }
    let snapshot = job.watch.snapshot();
    if job.last_sent == Some(snapshot) {
        return;
    }
    job.last_sent = Some(snapshot);
    let payload = progress_json(job, &snapshot);
    state.emit("backup_progress", payload);
}

fn handle(state: &mut AppState, outcome: Outcome) -> Option<Value> {
    match outcome {
        Outcome::Exported(result) => {
            let payload = match result {
                Ok(outcome) => Ok(crate::ipc::export_outcome_json(outcome)),
                Err(error) => Err(crate::ipc::export_code(error)),
            };
            finish(state, payload, false)
        }
        Outcome::Staged(Err(error)) => {
            release_import_locks(state);
            finish(state, Err(crate::ipc::import_code(error)), true)
        }
        Outcome::Staged(Ok(staged)) => {
            staged_ready(state, staged);
            None
        }
        Outcome::Abandoned(cleaned) => {
            release_import_locks(state);
            let code = if cleaned.is_ok() {
                "backup_cancelled"
            } else {
                "backup_cancelled_cleanup_pending"
            };
            finish(state, Err(code), true)
        }
        Outcome::Committed(result) => match *result {
            Ok(committed) => committed_ready(state, committed),
            Err(error) => {
                // As the synchronous import did: a live vault closed for a
                // replacement that then failed is locked properly, and whether
                // the vault was replaced after all is decided at the next
                // unlock, from the vault actually on disk.
                let had_live = state
                    .backup_job
                    .as_ref()
                    .and_then(|job| job.import.as_ref())
                    .is_some_and(|hold| hold.had_live_vault);
                release_import_locks(state);
                let code = crate::ipc::import_code(error);
                // The lock path asks the job first; the job is ending, so it
                // goes as an ordinary lock below, after the result.
                if let Some(job) = state.backup_job.as_mut() {
                    job.lock_after |= had_live;
                }
                finish(state, Err(code), false)
            }
        },
        Outcome::Panicked => {
            let committing = committing(state);
            let had_live = state
                .backup_job
                .as_ref()
                .and_then(|job| job.import.as_ref())
                .is_some_and(|hold| hold.had_live_vault);
            release_import_locks(state);
            if let Some(job) = state.backup_job.as_mut() {
                job.lock_after |= committing && had_live;
            }
            finish(state, Err("backup_failed"), !committing)
        }
    }
}

/// Phase A finished. Unless a stop arrived meanwhile, the live vault and
/// Library are closed and phase B starts.
fn staged_ready(state: &mut AppState, staged: Staged) {
    let stopped = state.backup_job.as_ref().is_some_and(|job| job.watch.is_stopped());
    let proxy = state.proxy();
    if stopped {
        // Stopped after the last check but before this thread saw the
        // result: given up exactly as a stop during staging, on a worker,
        // since removing what it built can take a while.
        if let Some(job) = state.backup_job.as_mut() {
            job.worker = Some(spawn_outcome(proxy, job, move || Outcome::Abandoned(staged.abandon())));
        }
        return;
    }
    // Nothing may keep writing to the files about to be replaced. The old
    // vault's session ends here, before the commit, rather than after it:
    // the event loop runs during the commit, and nothing derived from the
    // old vault may run on meanwhile.
    let had_live_vault = state.vault.is_some();
    state.vault = None;
    state.store = None;
    // From here the vault may be replaced: an activation answer still in
    // flight for the old one is dropped when it arrives (code review round 2,
    // R-002).
    state.vault_epoch += 1;
    if had_live_vault {
        state.end_vault_session();
    }
    let vault_path = state.vault_path.clone();
    let Some(job) = state.backup_job.as_mut() else {
        return;
    };
    job.phase = JobPhase::Committing;
    let Some(hold) = job.import.as_mut() else {
        return;
    };
    hold.had_live_vault = had_live_vault;
    let new_passphrase = hold.new_passphrase.clone();
    let id = job.id;
    job.worker = Some(spawn_outcome(proxy, job, move || {
        Outcome::Committed(Box::new(vault_backup::commit(staged, &vault_path, &new_passphrase)))
    }));
    state.emit("backup_progress", json!({ "job": id, "kind": "import", "phase": "committing", "cancellable": false }));
}

/// Phase B finished: the imported vault is in, its Library opened on the
/// worker. Attached here in the synchronous import's order.
fn committed_ready(state: &mut AppState, committed: Committed) -> Option<Value> {
    let Committed {
        vault,
        recovery,
        summary,
        library_included,
        library,
    } = committed;
    let library_was_closed = state
        .backup_job
        .as_ref()
        .and_then(|job| job.import.as_ref())
        .is_some_and(|hold| hold.library_was_closed);
    let retained_copies = vault.import_retained_leftovers();
    state.vault = Some(vault);
    state.attach_imported_library(library);
    release_import_transaction(state);
    let library = if state.store.is_some() {
        "replaced"
    } else {
        state.store_error().unwrap_or("not_opened")
    };
    crate::ipc::start_imported_vault_session(state);
    // The commit ran with no idle deadline. If the person was away past it,
    // the idle lock is not forgotten (code review round 1, R-002): its
    // one-minute countdown starts now, with "I'm still here", as the lock
    // always warns first (compliance audit: a lock with no countdown broke
    // that promise and cost the recovery key). Read before the session's
    // first touch resets the clock.
    let idle_due = state.idle_lock_due();
    // The imported vault's session begins now, as an unlock's does.
    state.touch();
    if idle_due {
        state.arm_idle_warning_now();
    }
    let mut payload = crate::ipc::import_result_json(
        &recovery,
        retained_copies,
        &summary,
        library,
        library_included,
        library_was_closed,
    );
    // The countdown started with this result: the chrome then refreshes
    // nothing that would count as presence until the person acts, or the
    // countdown would quietly restart (code review round 4, R-001).
    if idle_due {
        payload["idle_warning"] = json!(true);
    }
    finish(state, Ok(payload), false)
}

/// Ends the job and tells the chrome. `original_kept`: the vault that was open
/// before the job is still the one open (an export, or an import that never
/// committed), so an activation answer parked meanwhile belongs to it.
fn finish(state: &mut AppState, payload: Result<Value, &'static str>, original_kept: bool) -> Option<Value> {
    let mut job = state.backup_job.take()?;
    job.alive.store(false, Ordering::SeqCst);
    // A lock follows this result: the one-time recovery key would never be
    // shown, so it is not sent to the chrome at all. The chrome is told it was
    // lost instead, and says so (compliance audit and code review round 2).
    let mut payload = payload;
    if job.lock_after {
        if let Ok(Value::Object(data)) = payload.as_mut() {
            if data.remove("recovery_key").is_some() {
                data.insert("key_lost".into(), Value::Bool(true));
            }
        }
    }
    // `lock_follows`: the vault locks right after this event. The chrome then
    // never draws a result it would have to take back, and says what the lock
    // cost (an import's recovery key) instead (code review round 2, R-003).
    let event = match &payload {
        Ok(data) => json!({
            "job": job.id,
            "kind": kind_name(job.kind),
            "ok": true,
            "data": data,
            "stopped_by": job.stop_reason.map(reason_name),
            "lock_follows": job.lock_after,
        }),
        Err(code) => json!({
            "job": job.id,
            "kind": kind_name(job.kind),
            "ok": false,
            "error": code,
            "stopped_by": job.stop_reason.map(reason_name),
            "lock_follows": job.lock_after,
        }),
    };
    // Parked download records go into whichever Library is open now: the
    // imported one, or the original after a stop. With none open they are
    // reported lost, exactly as a download finishing while locked is.
    for parked in std::mem::take(&mut job.parked_downloads) {
        state.record_parked_download(&parked.url, &parked.filename, parked.byte_len, parked.sha256);
    }
    if original_kept && job.kind == JobKind::Import {
        crate::activation::replay_pending(state);
    }
    // An import that reached its commit may have replaced the vault, even if
    // it then failed or crashed: an answer parked for the vault it replaced
    // must not be replayed into whichever one the next unlock opens (code
    // review round 1, R-003). Dropping it costs one retry; the server answers
    // the same device the same way.
    if !original_kept && job.kind == JobKind::Import {
        state.pending_activation_event = None;
    }
    state.emit("backup_finished", event.clone());
    // Through the one lock path, now that no job is asked first: a lock asked
    // for during the commit, or a live vault closed for a commit that failed.
    // Even with the vault already closed it ends the session and tells the
    // chrome, as the synchronous import's failure did.
    if job.lock_after {
        state.lock_vault();
    }
    if job.exit_when_done {
        let _ = state.proxy().send_event(UserEvent::CloseWindow);
    }
    Some(event)
}

fn release_import_transaction(state: &mut AppState) {
    if let Some(hold) = state.backup_job.as_mut().and_then(|job| job.import.as_mut()) {
        hold.transaction = None;
    }
}

/// An import that ends without a commit gives back what it took.
fn release_import_locks(state: &mut AppState) {
    let newly = match state.backup_job.as_mut().and_then(|job| job.import.as_mut()) {
        Some(hold) => {
            hold.transaction = None;
            hold.newly_locked
        }
        None => return,
    };
    state.release_unused_library_lock(newly);
}

/// The end of the program: a running worker is asked to stop and given a
/// moment, so an export's temporary file is removed. A commit cannot stop;
/// the journal decides at the next start, as after a crash.
pub fn on_exit(state: &mut AppState) {
    let Some(job) = state.backup_job.as_mut() else {
        return;
    };
    job.watch.stop();
    job.alive.store(false, Ordering::SeqCst);
    if let Some(worker) = job.worker.take() {
        let until = std::time::Instant::now() + EXIT_WAIT;
        while !worker.is_finished() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Smoke tests only: waits for the running worker and handles its result on
/// this thread, the way the event loop would. One step: phase A of an import
/// ends with its commit started. Returns `backup_finished` if the job ended.
pub fn drive_step(state: &mut AppState) -> Option<Value> {
    let job = state.backup_job.as_mut()?;
    let id = job.id;
    let worker = job.worker.take()?;
    let _ = worker.join();
    // The event loop learns of a result only through the doorbell. A worker
    // that left its result without ringing would leave the job running for
    // ever in the real app, so it is not handled here either.
    if !job.rang.load(Ordering::SeqCst) {
        return None;
    }
    on_bell(state, Bell::Ready(id))
}

/// Smoke tests only: runs the job to its end and returns `backup_finished`.
pub fn drive_to_end(state: &mut AppState) -> Option<Value> {
    let mut finished = None;
    while state.backup_job.as_ref().is_some_and(|job| job.worker.is_some()) {
        if let Some(event) = drive_step(state) {
            finished = Some(event);
        }
    }
    finished
}

// ---- wording for the chrome ------------------------------------------------------

fn kind_name(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Export => "export",
        JobKind::Import => "import",
    }
}

fn reason_name(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Person => "person",
        StopReason::Lock => "lock",
        StopReason::Close => "close",
    }
}

fn stage_name(stage: BackupStage) -> &'static str {
    match stage {
        BackupStage::Preparing => "preparing",
        BackupStage::Writing => "writing",
        BackupStage::Checking => "checking",
        BackupStage::Reading => "reading",
    }
}

fn progress_json(job: &BackupJob, snapshot: &WatchSnapshot) -> Value {
    let phase = match job.phase {
        JobPhase::Working => stage_name(snapshot.stage),
        JobPhase::Committing => "committing",
    };
    json!({
        "job": job.id,
        "kind": kind_name(job.kind),
        "phase": phase,
        "done": snapshot.done,
        "total": snapshot.total,
        "items_done": snapshot.items_done,
        "items_total": snapshot.items_total,
        "cancellable": cancel_allowed(job.phase),
        "stopping": snapshot.stopped,
    })
}

#[cfg(test)]
#[path = "backup_job_tests.rs"]
mod tests;
