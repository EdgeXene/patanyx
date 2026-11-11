//! Ending an add-on session: the one path every exit takes.
//!
//! An ending session is hidden at once, admits nothing but its final save,
//! and is asked to flush. It is destroyed when the add-on acknowledges and
//! its storage worker has answered everything it was given, or when the
//! deadline passes, whichever comes first. Whatever asked for the ending (a
//! lock, a close, a quit) then goes on.
//!
//! Nothing here waits on the event loop. The deadline is a timer event. A
//! storage worker still inside a disk write when its window goes keeps the
//! old namespace until it finishes; `quiescent` reports that to anything
//! that would replace or reopen the add-on's files, and they wait for it.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use crate::addon_host::{self, Mode};
use crate::addon_protocol::Command;
use crate::state::AppState;
use crate::UserEvent;

/// The add-on's whole window to save after it is asked.
pub const FLUSH_DEADLINE: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    VaultLock,
    VaultImport,
    WindowClose,
    BrowserClose,
    Update,
    Relaunch,
    /// Premium ended under an editable session: the window stays, read-only.
    PremiumExpired,
    DeleteData,
    AddonRemove,
    AddonUpdate,
}

impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Self::VaultLock => "vault_lock",
            Self::VaultImport => "vault_import",
            Self::WindowClose => "window_close",
            Self::BrowserClose => "browser_close",
            Self::Update => "update",
            Self::Relaunch => "relaunch",
            Self::PremiumExpired => "premium_expired",
            Self::DeleteData => "delete_data",
            Self::AddonRemove => "addon_remove",
            Self::AddonUpdate => "addon_update",
        }
    }
}

/// What goes on once the session has ended. Flags, so asking twice is asking
/// once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Then {
    pub lock: bool,
    pub close: bool,
    pub quit_update: bool,
    pub quit_relaunch: bool,
}

impl Then {
    pub const NOTHING: Self = Self { lock: false, close: false, quit_update: false, quit_relaunch: false };

    fn or(self, other: Self) -> Self {
        Self {
            lock: self.lock || other.lock,
            close: self.close || other.close,
            quit_update: self.quit_update || other.quit_update,
            quit_relaunch: self.quit_relaunch || other.quit_relaunch,
        }
    }
}

/// An ending in progress.
#[derive(Debug)]
pub struct Ending {
    pub flush_id: String,
    pub then: Then,
    /// The request id of the one final save it admitted.
    pub flush_request: Option<u32>,
    /// That save was refused or failed.
    pub flush_failed: bool,
    /// The add-on's acknowledgment: Some(true) when it reported saved.
    pub acked: Option<bool>,
    /// A lapse: the window stays, read-only with this reason, unless an end
    /// was asked for meanwhile (`then` not empty).
    pub lapse: Option<Option<&'static str>>,
}

/// What an ending session admits: its final save under the issued flush id
/// (once), and the acknowledgment. Outside an ending, neither. `None` admits.
pub fn admission(ending: Option<&Ending>, command: &Command) -> Option<&'static str> {
    match (ending, command) {
        (Some(e), Command::StorePut { flush_id: Some(f), .. }) => {
            (*f != e.flush_id || e.flush_request.is_some() || e.acked.is_some()).then_some("invalid_flush")
        }
        (Some(e), Command::FlushDone { flush_id, .. }) => {
            (*flush_id != e.flush_id || e.acked.is_some()).then_some("invalid_flush")
        }
        (Some(_), _) => Some("session_ending"),
        (None, Command::StorePut { flush_id: Some(_), .. } | Command::FlushDone { .. }) => Some("invalid_flush"),
        (None, _) => None,
    }
}

fn flush_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Starts ending the open session, or ends it at once when it has nothing
/// it could still save (never ready, or read-only). True: no session is
/// left and the caller goes on now. False: `then` runs when it has ended.
pub fn end(app: &mut AppState, reason: Reason, then: Then) -> bool {
    let Some(session) = app.addon.as_ref() else {
        return true;
    };
    if let Some(ending) = session.ending.borrow_mut().as_mut() {
        // Under a lapse too: an end asked for meanwhile wins, the window
        // goes, even one that asks for nothing to follow (an import).
        ending.then = ending.then.or(then);
        ending.lapse = None;
        return false;
    }
    if !session.is_ready() || session.mode.get() == Mode::ReadOnly {
        addon_host::destroy(app);
        return true;
    }
    start(app, reason, then, None);
    false
}

/// Premium ended under an editable session: closes ordinary writes at once,
/// gives the add-on its one final save, then leaves the window open and
/// read-only with `reason`. Nothing to save (not yet ready) goes read-only
/// at once.
pub fn lapse(app: &mut AppState, reason: Option<&'static str>) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    if session.mode.get() != Mode::Full || session.ending.borrow().is_some() {
        return;
    }
    if !session.is_ready() {
        session.mode.set(Mode::ReadOnly);
        session.reason.set(reason);
        return;
    }
    start(app, Reason::PremiumExpired, Then::NOTHING, Some(reason));
}

fn start(app: &mut AppState, reason: Reason, then: Then, lapse: Option<Option<&'static str>>) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    let id = flush_id();
    let generation = session.generation;
    *session.ending.borrow_mut() = Some(Ending {
        flush_id: id.clone(),
        then,
        flush_request: None,
        flush_failed: false,
        acked: None,
        lapse,
    });
    // Out of the person's reach from now on: hidden, and every ordinary
    // request refused.
    addon_host::apply(app);
    let after = if lapse.is_some() { "read_only" } else { "close" };
    addon_host::emit(
        app,
        "addon_flush",
        json!({ "flush_id": id, "reason": reason.name(), "deadline_ms": FLUSH_DEADLINE.as_millis() as u64, "after": after }),
    );
    let proxy = app.proxy();
    std::thread::spawn(move || {
        std::thread::sleep(FLUSH_DEADLINE);
        let _ = proxy.send_event(UserEvent::AddonFlushDeadline { generation, flush_id: id });
    });
}

/// Ends the session without a flush window, for a caller that cannot wait
/// (the synchronous import of an older backup, and the loop's own end).
pub fn end_now(app: &mut AppState) {
    if let Some(session) = app.addon.as_ref() {
        // An end, never a lapse that keeps the window.
        if let Some(ending) = session.ending.borrow_mut().as_mut() {
            ending.lapse = None;
        }
        complete(app, false);
    }
}

/// The deadline of the flush `flush_id` in the window at `generation` passed.
/// A later flush in the same window has its own deadline.
pub fn deadline(app: &mut AppState, generation: u64, flush_id: &str) {
    let ending = app.addon.as_ref().is_some_and(|s| {
        s.generation == generation && s.ending.borrow().as_ref().is_some_and(|e| e.flush_id == flush_id)
    });
    if ending {
        complete(app, false);
    }
}

/// Completes the ending once the add-on has acknowledged and its worker has
/// answered everything queued, including the final save. Called after every
/// add-on frame and every storage completion.
pub fn settle(app: &mut AppState) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    let clean = match session.ending.borrow().as_ref() {
        Some(Ending { acked: Some(saved), flush_failed, .. }) => *saved && !*flush_failed,
        _ => return,
    };
    if session.storage_idle() {
        complete(app, clean);
    }
}

fn complete(app: &mut AppState, clean: bool) {
    let Some(session) = app.addon.as_ref() else {
        return;
    };
    let ending = session.ending.borrow_mut().take();
    let marker = incomplete_marker(&session.id);
    if clean {
        let _ = std::fs::remove_file(marker);
    }
    // A lapse nothing else overtook: the window stays, read-only.
    if let Some(Ending { lapse: Some(reason), then: Then::NOTHING, .. }) = ending {
        addon_host::set_mode(app, Mode::ReadOnly, reason);
        addon_host::apply(app);
        // A layout change while it was saving was not told then.
        addon_host::notify_geometry(app);
        return;
    }
    addon_host::destroy(app);
    let then = ending.map_or(Then::NOTHING, |e| e.then);
    if then.lock {
        app.lock_vault();
    }
    let proxy = app.proxy();
    if then.close {
        let _ = proxy.send_event(UserEvent::CloseWindow);
    }
    if then.quit_update {
        let _ = proxy.send_event(UserEvent::QuitForUpdate);
    }
    if then.quit_relaunch {
        let _ = proxy.send_event(UserEvent::QuitForRelaunch);
    }
    crate::backup_job::resume_parked(app);
}

/// A storage worker whose window had already gone finished its last job.
pub fn worker_quiet(app: &mut AppState) {
    settle(app);
    crate::backup_job::resume_parked(app);
}

/// No add-on window is open and no worker of an earlier one is still
/// writing: the add-on's files may be replaced or reopened.
pub fn quiescent(app: &mut AppState) -> bool {
    app.addon_draining.retain(|token| std::sync::Arc::strong_count(token) > 1);
    app.addon.is_none() && app.addon_draining.is_empty()
}

/// A lock is waiting for the add-on's last save. The auto-lock deadline is
/// then nothing to wake for: it would only spin the loop.
pub fn lock_pending(app: &AppState) -> bool {
    app.addon
        .as_ref()
        .is_some_and(|s| s.ending.borrow().as_ref().is_some_and(|e| e.then.lock))
}

/// Asked first by `lock_vault`. True: lock now.
pub fn on_lock(app: &mut AppState) -> bool {
    end(app, Reason::VaultLock, Then { lock: true, ..Then::NOTHING })
}

/// Asked by the close arms, after the backup job. True: close now.
pub fn hold_close(app: &mut AppState) -> bool {
    end(app, Reason::BrowserClose, Then { close: true, ..Then::NOTHING })
}

/// Asked by the quit arms. True: quit now.
pub fn hold_quit(app: &mut AppState, update: bool) -> bool {
    let (reason, then) = if update {
        (Reason::Update, Then { quit_update: true, ..Then::NOTHING })
    } else {
        (Reason::Relaunch, Then { quit_relaunch: true, ..Then::NOTHING })
    };
    end(app, reason, then)
}

/// Present from an editable session's start until it ends with a clean
/// flush, so a session that ended any other way is reported when the add-on
/// next opens. It holds nothing.
pub fn incomplete_marker(id: &str) -> PathBuf {
    crate::platform::addon_profile_dir_for(&patanyx_vault::Vault::default_path(), id).join("session-incomplete")
}

#[cfg(test)]
#[path = "addon_session_tests.rs"]
mod tests;
