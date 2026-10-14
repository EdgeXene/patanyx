//! The window a Linux build shows instead of crashing when the system will not
//! let WebKitGTK's web page sandbox start.
//!
//! 1.0.6 turned the sandbox on (vendor/wry/PATANYX-PATCH.md, third hunk):
//! WebKitGTK starts every web page process inside bubblewrap. Where bubblewrap
//! cannot set itself up, the web process never starts and the browser aborts
//! with SIGTRAP ("Connection: failed to receive credentials") and no
//! explanation at all. Measured in the Debian 13 CI image, which is how 1.0.6
//! found it. This module notices first, before any browser window exists, and
//! says so in a window, the way `engine_window` does for an engine that is too
//! old.
//!
//! IT NEVER TURNS THE SANDBOX OFF AND NEVER STARTS WITHOUT IT. The only two
//! outcomes are "start exactly as before" and "refuse, with a reason". Every
//! unclear answer is "start exactly as before", which on a system where the
//! sandbox really cannot start is the same crash as before this module existed.
//!
//! TWO STAGES, because a quick test alone is not reliable and the faithful one
//! is too slow to run on every launch:
//!
//! 1. `quick_probe`: bubblewrap itself, asked for the namespaces and first
//!    mounts WebKitGTK 2.54.0 asks for (its argv measured 2026-10-11, see
//!    `probe_args`), then to run `true`. A few milliseconds. When it works,
//!    PATANYX starts as before. A smaller probe is NOT enough, and that was
//!    measured too: `bwrap --unshare-ipc --unshare-net --unshare-pid
//!    --unshare-uts --ro-bind / / true` succeeded in a container (seccomp and
//!    AppArmor unconfined, an ordinary user) where WebKitGTK's own bubblewrap
//!    then failed with "Can't mount proc on /proc: Operation not permitted".
//! 2. Only when the quick probe did not work: `child`, the real engine, in a
//!    child process (this binary with `--sandbox-check`), starting one web
//!    process exactly as the browser would. A refusal needs this child to end
//!    abnormally AND a line on its stderr naming the sandbox's failure
//!    (bubblewrap's own error, or the engine saying it could not run
//!    bubblewrap). So a quick probe that fails for its own reasons (an unusual
//!    library layout that stops `true` from running, say) costs a moment at
//!    startup, never a refusal, and a refusal always rests on the engine's
//!    own failure.
//!
//! Inside a Flatpak the engine starts its processes through the Flatpak portal,
//! not bubblewrap (WebKitGTK tests for /.flatpak-info), so nothing here runs.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The bubblewrap WebKitGTK runs. The engine has this path compiled in (the
/// string is in libwebkit2gtk-4.1, 2.50.6 and 2.54.0 alike) and offers no way
/// to point it elsewhere, so this is the one to test.
pub const BWRAP: &str = "/usr/bin/bwrap";

/// Present inside a Flatpak.
const FLATPAK_INFO: &str = "/.flatpak-info";

/// The hidden flag that runs `child`.
pub const CHECK_FLAG: &str = "--sandbox-check";

/// How a refused start ends. 2 is the engine-floor refusal and 3 the
/// updater's `--preflight` "would refuse"; this is neither.
pub const REFUSAL_EXIT: i32 = 4;

/// The child's own exit codes. 0 is "a web process started in the sandbox".
const CHILD_STARTED: i32 = 0;
const CHILD_NO_DISPLAY: i32 = 10;
const CHILD_WEB_PROCESS_ENDED: i32 = 11;
const CHILD_TIMED_OUT: i32 = 12;

const QUICK_TIMEOUT: Duration = Duration::from_secs(5);
/// The child gives the engine this long to load one empty page; the parent
/// waits a little longer than that before giving up on the child itself.
const CHILD_LOAD_TIMEOUT: Duration = Duration::from_secs(20);
const CHILD_TIMEOUT: Duration = Duration::from_secs(25);
/// Enough for bubblewrap's error line and the engine's abort message.
const STDERR_LIMIT: usize = 64 * 1024;

/// The answer.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Start as before.
    Starts,
    /// The sandbox cannot start here. The text is the line that said why
    /// (`sandbox_error_line`).
    CannotStart(String),
    /// Nothing could be concluded; start as before.
    Unknown,
}

/// The quick probe's arguments: a subset of what WebKitGTK 2.54.0 passed to
/// bubblewrap for a web process (captured 2026-10-11 in the Debian 13 image:
/// --unshare-uts, --unshare-pid, --unshare-net, --dev /dev, --proc /proc,
/// --tmpfs /tmp, the library directories with --ro-bind-try, then its seccomp
/// filter and about sixty more binds). Only `true` is added, so the probe has
/// something to run. The namespaces and the /proc mount are the steps that
/// fail where the sandbox cannot start; they are all here.
pub fn probe_args(true_bin: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "--unshare-uts",
        "--unshare-pid",
        "--unshare-net",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for dir in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        args.extend(["--ro-bind-try", dir, dir].iter().map(|s| s.to_string()));
    }
    args.extend(["--ro-bind", true_bin, true_bin, "--", true_bin].iter().map(|s| s.to_string()));
    args
}

/// The line that says the sandbox itself failed, if there is one: bubblewrap's
/// own error (every one starts with its name, "bwrap: Creating new namespace
/// failed: ..."), or else the engine saying it could not start bubblewrap at
/// all ("Failed to spawn child process “/usr/bin/bwrap” (Permission denied)",
/// measured with bwrap made unusable; GLib may translate the words, never the
/// path). Bounded, because it is shown in a window.
pub fn sandbox_error_line(stderr: &str) -> Option<String> {
    let lines = || stderr.lines().map(str::trim);
    // The path QUOTED, as GLib's spawn error quotes it, never a bare
    // substring: "/usr/bin/bwrap.missing" in some unrelated warning says
    // nothing about the sandbox (code review 2026-10-12, R-003).
    let quoted = [format!("“{BWRAP}”"), format!("\"{BWRAP}\""), format!("'{BWRAP}'")];
    lines()
        .find(|line| line.starts_with("bwrap: "))
        .or_else(|| lines().find(|line| quoted.iter().any(|q| line.contains(q.as_str()))))
        .map(|line| line.chars().take(300).collect())
}

/// How the child ended: exit code, or the signal that ended it; `None` when it
/// could not be started or did not end in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildEnd {
    Code(i32),
    Signal(i32),
}

/// The pure decision on the child's result. A refusal needs BOTH an abnormal
/// end (killed by a signal: the engine's own abort is SIGTRAP; or the web
/// process ending under it) AND a line naming the sandbox's failure. A child
/// that could not open a display, timed out, or failed in any other way says
/// nothing about the sandbox.
pub fn judge_child(end: Option<ChildEnd>, stderr: &str) -> Verdict {
    match end {
        Some(ChildEnd::Code(CHILD_STARTED)) => Verdict::Starts,
        Some(ChildEnd::Signal(_)) | Some(ChildEnd::Code(CHILD_WEB_PROCESS_ENDED)) => {
            match sandbox_error_line(stderr) {
                Some(line) => Verdict::CannotStart(line),
                None => Verdict::Unknown,
            }
        }
        _ => Verdict::Unknown,
    }
}

/// Runs `command` in its own process group with stdin and stdout closed,
/// collects up to STDERR_LIMIT bytes of its stderr, and kills the whole group
/// at `timeout` or once it has ended (nothing it started is needed after).
fn run_bounded(mut command: Command, timeout: Duration) -> (Option<ChildEnd>, String) {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn();
    let Ok(mut child) = child else {
        return (None, String::new());
    };
    // Read on a thread, into a buffer the caller can take whenever it likes:
    // a grandchild still holding the pipe after the deadline must not stall
    // startup, so the reader is never joined.
    let collected = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut pipe) = child.stderr.take() {
        let sink = Arc::clone(&collected);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut buf = sink.lock().unwrap_or_else(|e| e.into_inner());
                let room = STDERR_LIMIT.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
        });
    }
    // The group is signalled only while its leader is NOT yet reaped: an
    // exited but unreaped child is a zombie that still holds its pid, and so
    // the group id, which then cannot belong to anyone else. Signalling after
    // the reap could reach an unrelated group that had been handed the same
    // number (code review 2026-10-12, R-001). So "has it exited?" is asked
    // with WNOWAIT, the group is killed, and only then is the child reaped.
    let kill_group = |child: &std::process::Child| {
        if let Ok(pgid) = i32::try_from(child.id()) {
            // SAFETY: kill(2) with a negative pid signals the process group
            // this (unreaped) child leads; no memory is shared.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
    };
    let exited_unreaped = |child: &std::process::Child| -> bool {
        let Ok(pid) = libc::id_t::try_from(child.id()) else {
            return false;
        };
        // SAFETY: waitid writes only into `info`, a zeroed siginfo_t we own.
        // WNOWAIT leaves the child waitable, so `wait` below still reaps it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
        };
        // With WNOHANG, a still-running child leaves si_pid at 0.
        rc == 0 && unsafe { info.si_pid() } != 0
    };
    let deadline = Instant::now() + timeout;
    let timed_out = loop {
        if exited_unreaped(&child) {
            break false;
        }
        if Instant::now() >= deadline {
            break true;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Nothing the child started is needed now, finished or not.
    kill_group(&child);
    let end = match child.wait() {
        Ok(_) if timed_out => None,
        Ok(status) => match (status.code(), status.signal()) {
            (Some(code), _) => Some(ChildEnd::Code(code)),
            (None, Some(signal)) => Some(ChildEnd::Signal(signal)),
            (None, None) => None,
        },
        Err(_) => None,
    };
    // The pipe closes once the group is gone; give the reader a moment to
    // drain what was already written.
    let settle = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle && Arc::strong_count(&collected) > 1 {
        std::thread::sleep(Duration::from_millis(10));
    }
    let text = String::from_utf8_lossy(&collected.lock().unwrap_or_else(|e| e.into_inner())).into_owned();
    (end, text)
}

/// Stage 1. True only when bubblewrap ran `true` inside the probe sandbox.
fn quick_probe_works() -> bool {
    let Some(true_bin) = ["/usr/bin/true", "/bin/true"].into_iter().find(|p| Path::new(p).is_file()) else {
        return false;
    };
    if !Path::new(BWRAP).is_file() {
        return false;
    }
    let mut command = Command::new(BWRAP);
    command.args(probe_args(true_bin));
    matches!(run_bounded(command, QUICK_TIMEOUT).0, Some(ChildEnd::Code(0)))
}

/// Stage 2, the parent's half: run this binary with CHECK_FLAG and judge it.
fn ask_the_engine(exe: &Path) -> Verdict {
    let mut command = Command::new(exe);
    command.arg(CHECK_FLAG);
    let (end, stderr) = run_bounded(command, CHILD_TIMEOUT);
    judge_child(end, &stderr)
}

/// Both stages. `exe` is this binary.
pub fn check(exe: &Path) -> Verdict {
    if debug_refusal() {
        return Verdict::CannotStart("bwrap: (PATANYX_DEBUG_SANDBOX_REFUSE=1 in a debug build)".into());
    }
    if Path::new(FLATPAK_INFO).exists() {
        return Verdict::Starts;
    }
    if quick_probe_works() {
        return Verdict::Starts;
    }
    eprintln!("PATANYX: the quick sandbox probe did not succeed; asking the web engine itself.");
    ask_the_engine(exe)
}

/// Debug builds only: show the refusal without a system that refuses, so the
/// window can be seen and tested. It can only add a refusal, never skip the
/// check. Always false in release builds.
fn debug_refusal() -> bool {
    cfg!(debug_assertions) && std::env::var("PATANYX_DEBUG_SANDBOX_REFUSE").is_ok_and(|v| v == "1")
}

/// Stage 2, the child's half: the real engine, with the sandbox requested
/// exactly as the vendored wry requests it for every browser context
/// (`set_sandbox_enabled(true)` before the context starts a process), loading
/// one empty page. Returns the exit code. Where bubblewrap cannot start, the
/// engine aborts this process before any of the handlers below runs, which
/// is the answer the parent reads.
pub fn child() -> i32 {
    use gtk::prelude::*;
    use webkit2gtk::{LoadEvent, WebContextExt, WebViewExt};

    if gtk::init().is_err() {
        return CHILD_NO_DISPLAY;
    }
    // Ephemeral: nothing is written to the profile. Where the web process
    // runs is the same as for the browser's own context.
    let context = webkit2gtk::WebContext::new_ephemeral();
    context.set_sandbox_enabled(true);
    let view = webkit2gtk::WebView::with_context(&context);
    // Offscreen: realized, so the engine treats it as a real view, and never
    // drawn on screen.
    let window = gtk::OffscreenWindow::new();
    window.add(&view);
    window.show_all();
    view.connect_load_changed(|_, event| {
        if event == LoadEvent::Finished {
            std::process::exit(CHILD_STARTED);
        }
    });
    view.connect_web_process_terminated(|_, _| std::process::exit(CHILD_WEB_PROCESS_ENDED));
    gtk::glib::timeout_add_local_once(CHILD_LOAD_TIMEOUT, || std::process::exit(CHILD_TIMED_OUT));
    view.load_html("<!doctype html><title>sandbox check</title>", None);
    gtk::main();
    CHILD_TIMED_OUT
}

/// Called once, before any browser window exists. Returns when PATANYX may
/// start; otherwise says why and exits with REFUSAL_EXIT. `headless` (the
/// smoke test) prints the reason and shows no window, because nobody is there
/// to close one and a CI run would wait forever.
pub fn enforce(headless: bool) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let detail = match check(&exe) {
        Verdict::CannotStart(detail) => detail,
        Verdict::Starts | Verdict::Unknown => return,
    };
    eprintln!("PATANYX: the web page sandbox could not start on this system ({detail}).");
    eprintln!("  PATANYX runs every web page inside it, so it stopped instead of starting without it.");
    if !headless && !show(&detail) {
        eprintln!("  (No display to show the explanation window on.)");
    }
    std::process::exit(REFUSAL_EXIT);
}

/// Shows the window and blocks until it is closed. False when there is no
/// display to show it on. It offers no way to continue: Close is the only
/// button.
fn show(detail: &str) -> bool {
    use gtk::prelude::*;

    if gtk::init().is_err() {
        return false;
    }
    let i18n = crate::i18n::I18n::bootstrap(&crate::prefs::load().ui_locale)
        .or_else(|_| crate::i18n::I18n::bootstrap("en"));
    let Ok(i18n) = i18n else {
        return false;
    };
    use crate::i18n::keys as k;
    let mut args = crate::i18n::Args::default();
    args.set("detail", detail.to_string());
    let mut body = i18n.text(k::SANDBOX_WINDOW_BODY);
    body.push_str("\n\n");
    body.push_str(&i18n.text(k::SANDBOX_WINDOW_CAUSE));
    body.push_str("\n\n");
    body.push_str(&i18n.resolve(k::SANDBOX_WINDOW_DETAIL, &args));

    let dialog = gtk::MessageDialog::new(
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Error,
        gtk::ButtonsType::None,
        &i18n.text(k::SANDBOX_WINDOW_TITLE),
    );
    dialog.set_title("PATANYX");
    dialog.set_secondary_text(Some(&body));
    // Selectable, so the detail line can be copied into a bug report.
    if let Ok(area) = dialog.message_area().downcast::<gtk::Box>() {
        for child in area.children() {
            if let Ok(label) = child.downcast::<gtk::Label>() {
                label.set_selectable(true);
            }
        }
    }
    dialog.add_button(&i18n.text(k::SANDBOX_WINDOW_CLOSE), gtk::ResponseType::Close);
    dialog.set_default_response(gtk::ResponseType::Close);
    dialog.run();
    dialog.close();
    while gtk::events_pending() {
        gtk::main_iteration();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare mention of the path is not a sandbox failure; the engine's own
    /// quoted spawn error is (code review 2026-10-12, R-003).
    #[test]
    fn only_the_quoted_spawn_failure_counts_not_a_mention() {
        let unrelated = "ERROR: ld.so: object '/usr/bin/bwrap.missing' from LD_PRELOAD cannot be preloaded: ignored.\n";
        assert_eq!(sandbox_error_line(unrelated), None);
        assert_eq!(judge_child(Some(ChildEnd::Signal(libc::SIGTRAP)), unrelated), Verdict::Unknown);
        let quoted = "Failed to spawn child process \u{201c}/usr/bin/bwrap\u{201d} (No such file or directory)\n";
        assert!(sandbox_error_line(quoted).is_some());
    }

    /// The bounded runner, for real (code review 2026-10-12, R-002): exit
    /// codes and signals come back as they happened, stderr is collected, a
    /// child past its time is stopped, and nothing it started outlives it.
    #[test]
    fn the_bounded_runner_reports_ends_and_cleans_up() {
        let sh = |script: &str| {
            let mut c = Command::new("/bin/sh");
            c.args(["-c", script]);
            c
        };
        let (end, _) = run_bounded(sh("exit 3"), Duration::from_secs(5));
        assert_eq!(end, Some(ChildEnd::Code(3)));
        // SIGTERM, not the engine's SIGTRAP: a trap dumps core into the
        // crate directory on every test run.
        let (end, err) = run_bounded(sh("echo 'bwrap: test line' >&2; kill -TERM $$"), Duration::from_secs(5));
        assert_eq!(end, Some(ChildEnd::Signal(libc::SIGTERM)));
        assert!(err.contains("bwrap: test line"), "{err:?}");
        let started = Instant::now();
        let (end, _) = run_bounded(sh("sleep 30"), Duration::from_millis(300));
        assert_eq!(end, None, "a child past its time is not an answer");
        assert!(started.elapsed() < Duration::from_secs(5), "the runner waited for the child");
        // A grandchild left running is killed with the group.
        let (end, err) = run_bounded(sh("sleep 30 & echo $! >&2; exit 0"), Duration::from_secs(5));
        assert_eq!(end, Some(ChildEnd::Code(0)));
        let pid: i32 = err.trim().parse().expect("the grandchild's pid");
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: signal 0 only checks for existence.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "the child's own child outlived the check");
    }

    /// Startup still runs the check, after the engine floor and before
    /// anything that starts a web process, and a refusal exits with its own
    /// code (code review 2026-10-12, R-002).
    #[test]
    fn startup_runs_the_check_and_a_refusal_has_its_own_exit() {
        let main = include_str!("main.rs");
        let floor = main.find("    enforce_engine_floor();").expect("engine floor");
        // After a pending update has had its chance (release review
        // 2026-10-12, R-001), before the event loop and the first webview.
        let update = main.find("    if updater::apply_pending_at_startup() {").expect("pending update");
        let check = main.find("    sandbox_check::enforce(smoke_mode);").expect("startup no longer runs the sandbox check");
        let first_web = main.find("let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();").expect("event loop");
        assert!(floor < update && update < check && check < first_web);
        assert_eq!(REFUSAL_EXIT, 4);
        let own = include_str!("sandbox_check.rs");
        let enforce = &own[own.find("pub fn enforce(headless: bool) {").unwrap()..];
        assert!(enforce[..enforce.find("\n}\n").unwrap()].contains("std::process::exit(REFUSAL_EXIT);"));
    }

    #[test]
    fn the_probe_asks_for_what_the_engine_asks_for() {
        let args = probe_args("/usr/bin/true");
        // The namespaces WebKitGTK 2.54.0 requests for a web process. No
        // more: a namespace the engine does not request could fail where the
        // engine would not (it only costs the slow check, but still).
        for ns in ["--unshare-uts", "--unshare-pid", "--unshare-net"] {
            assert!(args.iter().any(|a| a == ns), "{ns}");
        }
        assert!(!args.iter().any(|a| a == "--unshare-user" || a == "--unshare-all"));
        // The /proc mount is the step that failed in the measured container
        // where a probe without it succeeded.
        assert!(args.windows(2).any(|w| w[0] == "--proc" && w[1] == "/proc"));
        assert!(args.windows(2).any(|w| w[0] == "--dev" && w[1] == "/dev"));
        // Nothing is bound writable, and the whole root is not bound.
        assert!(!args.iter().any(|a| a == "--bind" || a == "--dev-bind"));
        assert!(!args.windows(2).any(|w| w[0].ends_with("bind") && w[1] == "/"));
        // It runs `true`, and only that.
        assert_eq!(&args[args.len() - 2..], ["--", "/usr/bin/true"]);
    }

    #[test]
    fn bubblewraps_error_line_is_found_among_the_engines_noise() {
        // Verbatim from the Debian 13 image, 2026-10-11 (non-root, seccomp and
        // AppArmor unconfined).
        let stderr = "bwrap: Can't mount proc on /proc: Operation not permitted\n\n\
                      (process:165): libsoup-WARNING **: 03:52:56.919: Failed to execute query: database is locked\n\
                      ** (patanyx:21): ERROR **: 03:52:59.325: Connection: failed to receive credentials: \
                      Expecting to read a single byte for receiving credentials but read zero bytes\n";
        assert_eq!(
            sandbox_error_line(stderr).as_deref(),
            Some("bwrap: Can't mount proc on /proc: Operation not permitted")
        );
        assert_eq!(sandbox_error_line("** ERROR **: something else\n"), None);
        // The line is bounded: it ends up in a window.
        let long = format!("bwrap: {}", "x".repeat(1000));
        assert_eq!(sandbox_error_line(&long).unwrap().chars().count(), 300);
    }

    #[test]
    fn an_engine_that_cannot_run_bubblewrap_at_all_is_recognized() {
        // Verbatim, with an empty file mounted over /usr/bin/bwrap in the
        // Debian 13 image, 2026-10-11.
        let stderr = "** (patanyx:22): ERROR **: 04:05:05.368: Unable to spawn a new child process: \
                      Failed to spawn child process \u{201c}/usr/bin/bwrap\u{201d} (Permission denied)\n\
                      Trace/breakpoint trap (core dumped)\n";
        let line = sandbox_error_line(stderr).expect("the spawn failure names bubblewrap");
        assert!(line.contains("/usr/bin/bwrap") && line.contains("Permission denied"), "{line}");
        assert!(matches!(
            judge_child(Some(ChildEnd::Signal(libc::SIGTRAP)), stderr),
            Verdict::CannotStart(_)
        ));
        // bubblewrap's own words win over the engine's echo of them.
        let both = format!("bwrap: Creating new namespace failed: Operation not permitted\n{stderr}");
        assert_eq!(
            sandbox_error_line(&both).as_deref(),
            Some("bwrap: Creating new namespace failed: Operation not permitted")
        );
    }

    #[test]
    fn a_refusal_needs_an_abnormal_end_and_bubblewraps_own_words() {
        let bwrap = "bwrap: Creating new namespace failed: Operation not permitted\n";
        let refused = Verdict::CannotStart(
            "bwrap: Creating new namespace failed: Operation not permitted".into(),
        );
        // The engine's abort (SIGTRAP), or the web process ending, with
        // bubblewrap's line: refuse.
        assert_eq!(judge_child(Some(ChildEnd::Signal(libc::SIGTRAP)), bwrap), refused);
        assert_eq!(judge_child(Some(ChildEnd::Code(CHILD_WEB_PROCESS_ENDED)), bwrap), refused);
        // An abort WITHOUT bubblewrap's line is some other failure: start as
        // before rather than blame the sandbox.
        assert_eq!(judge_child(Some(ChildEnd::Signal(libc::SIGTRAP)), "** ERROR **: x\n"), Verdict::Unknown);
        // A web process that loaded the page: start, whatever else was said.
        assert_eq!(judge_child(Some(ChildEnd::Code(CHILD_STARTED)), bwrap), Verdict::Starts);
        // No display, a timeout, a child that never ran: nothing concluded.
        for end in [
            Some(ChildEnd::Code(CHILD_NO_DISPLAY)),
            Some(ChildEnd::Code(CHILD_TIMED_OUT)),
            Some(ChildEnd::Code(1)),
            None,
        ] {
            assert_eq!(judge_child(end, bwrap), Verdict::Unknown, "{end:?}");
        }
    }

    #[test]
    fn the_refusal_exit_code_is_its_own() {
        // 2 is the engine-floor refusal, 3 the preflight's "would refuse".
        assert!(![0, 1, 2, 3].contains(&REFUSAL_EXIT));
    }
}
