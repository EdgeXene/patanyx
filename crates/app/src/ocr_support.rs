//! Glue between the IPC surface and the `patanyx-ocr` crate.
//!
//! Everything here is local. There is no network client in the OCR path and
//! none may be added: an OCR feature that uploads the user's document would
//! contradict the one claim this product is built on.
//!
//! # Why the scan is asynchronous
//!
//! `recognize()` takes about a second on a real photo, measured. IPC dispatch
//! runs ON THE EVENT LOOP (`UserEvent::Ipc`, main.rs), so doing that work
//! inline would freeze the whole browser for the duration -- and worse, would
//! freeze it in the state BEFORE the "scanning" message could paint, because
//! the `evaluate_script` that would show it and the OCR itself are the same
//! thread. The user would see a dead window and no explanation.
//!
//! So a scan starts a worker, the command returns immediately, and the result
//! arrives as a `UserEvent::Ocr` the way page bytes arrive as
//! `UserEvent::Integrity`. That pattern is copied deliberately rather than
//! reinvented.
//!
//! # Why the engine is cached and lazy
//!
//! Loading the models takes ~160ms, measured. Charging that at startup would
//! punish every session for a feature most sessions never open, and missing
//! models must degrade to "unavailable" rather than failing the browser's
//! startup.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use patanyx_ocr::{OcrEngine, OcrError, TextRegion};
use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;

use crate::state::AppState;
use crate::UserEvent;

/// Refused before reading, not after. The engine's own pixel cap would reject
/// a bomb once decoded, but that is after paying for the read; a file this
/// large is not a photograph of a recovery key under any circumstances.
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// What a completed scan is for. The engine does the same work either way;
/// this decides how the text is interpreted and what the UI is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// Idea 1: pull a recovery key out of a photograph of the written one.
    Recovery,
    /// Idea 2: report what is legible in an image before it is shared.
    Leaks,
}

impl ScanKind {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "recovery" => Some(Self::Recovery),
            "leaks" => Some(Self::Leaks),
            _ => None,
        }
    }
}

/// A finished scan, on its way back to the event loop.
#[derive(Debug)]
pub struct OcrEvent {
    pub token: u64,
    pub kind: ScanKind,
    pub result: Result<Vec<TextRegion>, &'static str>,
}

// The engine is behind a Mutex so a scan running on a worker cannot race
// another; tract's plan is cheap to share but not obviously re-entrant, and
// two concurrent scans would only contend for the same CPU anyway.
static ENGINE: OnceLock<Result<Mutex<OcrEngine>, OcrError>> = OnceLock::new();

/// Short stable codes, exactly like every other IPC failure. Every one of
/// these MUST have an `ERROR_TEXT` entry in chrome.js or the user is shown a
/// raw identifier.
fn error_code(e: &OcrError) -> &'static str {
    match e {
        OcrError::ModelsMissing(_) => "ocr_unavailable",
        OcrError::ImageDecode => "bad_image",
        OcrError::ModelsInvalid(_) | OcrError::Inference(_) => "ocr_failed",
    }
}

/// Where the model files live.
///
/// Beside the executable, in step with how the Flatpak installs them. The env
/// override exists for development and for the probe; it is read on every call
/// rather than cached so a test can point it somewhere without process state.
/// An explicit override, or None to use the compiled-in weights.
///
/// No longer falls back to a directory beside the executable: that path was
/// the production default, was never populated by any build we distribute,
/// and its absence is exactly what kept this feature invisible.
fn override_model_dir() -> Option<PathBuf> {
    std::env::var_os("PATANYX_OCR_MODEL_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

/// Whether OCR can run at all, without loading anything.
///
/// Now TRUE for every normal install, because the weights are compiled into
/// the binary. It used to be a file check against a directory beside the
/// executable that nothing ever populated -- the published download is one
/// file and the updater swaps one file -- so this returned false everywhere
/// and the panel hid itself on every machine that has ever run PATANYX.
///
/// Still a cheap predicate rather than a load: the panel asks on every open,
/// and answering by optimising 10 MB of graphs would cost ~160ms for a
/// question with a constant answer.
///
/// The override remains a file check, because an override that silently fell
/// back to the embedded weights would make testing a different model
/// impossible to distinguish from testing the shipped one.
pub fn available() -> bool {
    let Some(dir) = override_model_dir() else {
        return true;
    };
    [
        patanyx_ocr::DET_MODEL_FILE,
        patanyx_ocr::REC_MODEL_FILE,
        patanyx_ocr::REC_DICT_FILE,
    ]
    .iter()
    .all(|f| dir.join(f).is_file())
}

/// `ocr_status` -- what the panel needs to decide whether to offer the button.
pub fn ipc_status() -> Result<Value, &'static str> {
    Ok(json!({
        "available": available(),
        "file_choice": crate::platform::file_choice_supported(),
    }))
}

/// `ocr_scan` -- starts a scan and returns immediately.
///
/// The reply carries only the token. The RESULT arrives later as an
/// `ocr_result` event, because the work is too slow to hold the event loop.
pub fn ipc_scan(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    // A TOKEN, NOT A PATH.
    //
    // This took `args["path"]` and read whatever it named, under a comment
    // claiming it was "a path the user just chose" -- which nothing enforced.
    // Any string the chrome origin sent was read from disk, giving a bounded
    // arbitrary-file read (64 MB, laundered through OCR) and, because the
    // reply distinguishes a missing file from a readable one, a clean
    // existence-and-size oracle for anything the process can open.
    //
    // The token is minted by `file_pick_open` when the user confirms a native
    // dialog, and redeeming it consumes it. The path never crosses the IPC
    // boundary in either direction, so there is no string here to forge.
    let token = args.get("token").and_then(Value::as_u64).ok_or("bad_args")?;
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .and_then(ScanKind::parse)
        .ok_or("bad_args")?;
    if !available() {
        return Err("ocr_unavailable");
    }
    let path = state
        .take_picked_path(token)
        .ok_or("bad_args")?
        .to_string_lossy()
        .into_owned();
    // Size is checked here rather than on the worker: a refusal the user
    // caused should come back as a failed command, not as an event arriving
    // seconds later.
    match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_IMAGE_BYTES => return Err("bad_image"),
        Ok(m) if m.is_file() => {}
        _ => return Err("bad_image"),
    }

    // The counter lives here rather than on AppState, matching how
    // page_integrity keeps its own: nothing outside this module has any use
    // for it, and threading it through shared state would only widen the
    // surface. Relaxed ordering is enough -- the token's only job is to let
    // the UI ignore a result from a scan it already abandoned.
    static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let token = NEXT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let proxy: EventLoopProxy<UserEvent> = state.proxy();
    // A worker per scan rather than a pool: scans are user-initiated, one at a
    // time in practice, and a thread that exits when it is done cannot leak.
    std::thread::spawn(move || {
        let result = scan_blocking(&path);
        let _ = proxy.send_event(UserEvent::Ocr(OcrEvent {
            token,
            kind,
            result,
        }));
    });
    Ok(json!({ "token": token }))
}

/// The actual work, on the worker thread. Returns codes, not errors, so the
/// event arm has nothing left to decide.
fn scan_blocking(path: &str) -> Result<Vec<TextRegion>, &'static str> {
    let bytes = std::fs::read(path).map_err(|_| "bad_image")?;
    match ENGINE.get_or_init(|| {
        match override_model_dir() {
            Some(dir) => OcrEngine::load(&dir),
            None => OcrEngine::load_embedded(),
        }
        .map(Mutex::new)
    }) {
        Err(e) => Err(error_code(e)),
        Ok(m) => {
            // A poisoned lock means a previous scan panicked. Report a failure
            // rather than propagating the panic into the event loop.
            let guard = m.lock().map_err(|_| "ocr_failed")?;
            guard.recognize(&bytes).map_err(|e| error_code(&e))
        }
    }
}

/// Called on the event loop when a worker finishes. Emits exactly one
/// `ocr_result` event, whatever happened.
pub fn handle_event(state: &mut AppState, event: OcrEvent) {
    let payload = match event.result {
        Err(code) => json!({ "token": event.token, "ok": false, "error": code }),
        Ok(regions) => match event.kind {
            ScanKind::Recovery => {
                let joined = regions
                    .iter()
                    .map(|r| r.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                // `None` is a RESULT, not a failure: the user pointed at an
                // image with no key in it, which is an ordinary thing to do
                // and deserves a plain answer rather than an error dialog.
                let candidate = patanyx_ocr::recovery::extract_recovery_candidate(&joined);
                json!({
                    "token": event.token,
                    "ok": true,
                    "kind": "recovery",
                    "key": candidate.as_deref().map(patanyx_ocr::recovery::format_grouped),
                })
            }
            ScanKind::Leaks => {
                let findings: Vec<Value> = patanyx_ocr::leaks::scan_regions(&regions)
                    .into_iter()
                    .map(|f| {
                        json!({
                            "kind": f.kind.as_str(),
                            "text": f.text,
                            "x": f.x, "y": f.y, "w": f.w, "h": f.h,
                        })
                    })
                    .collect();
                json!({
                    "token": event.token,
                    "ok": true,
                    "kind": "leaks",
                    "findings": findings,
                    // Distinguishes "nothing sensitive found" from "no text at
                    // all", which mean very different things to someone about
                    // to share a screenshot.
                    "regions": regions.len(),
                })
            }
        },
    };
    state.emit("ocr_result", payload);
}

/// Only used to prove the model directory resolves without a process env; the
/// real behaviour is covered by the engine crate's own tests.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_is_honoured_and_its_absence_means_embedded() {
        std::env::set_var("PATANYX_OCR_MODEL_DIR", "/tmp/patanyx-ocr-test-dir");
        assert_eq!(
            override_model_dir(),
            Some(PathBuf::from("/tmp/patanyx-ocr-test-dir"))
        );
        std::env::remove_var("PATANYX_OCR_MODEL_DIR");
        // None means "use the compiled-in weights", which is the production
        // path and the reason `available()` is now true by default.
        assert_eq!(override_model_dir(), None);
        assert!(
            available(),
            "with no override the weights are compiled in, so OCR is available"
        );
    }

    #[test]
    fn scan_kind_rejects_anything_it_does_not_know() {
        assert_eq!(ScanKind::parse("recovery"), Some(ScanKind::Recovery));
        assert_eq!(ScanKind::parse("leaks"), Some(ScanKind::Leaks));
        assert_eq!(ScanKind::parse(""), None);
        assert_eq!(ScanKind::parse("Recovery"), None);
    }
}
