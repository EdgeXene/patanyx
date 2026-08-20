//! Premium activation on THIS device (Phase 4 of the Premium design: a
//! licence activates on up to five devices).
//!
//! The pieces, and where each lives:
//!
//! * The DEVICE ID: a random 128-bit per-install identifier in
//!   `<vault dir>/device-id`, OUTSIDE the vault on purpose. Inside the
//!   vault, copying one vault to fifty machines would be one slot and
//!   "five devices" a fiction. Missing means a new install and is minted;
//!   present but unreadable is REFUSED and never overwritten (a device id
//!   you cannot read is not a new device, and minting one would burn a slot
//!   the user did not spend). It is minted LAZILY, at the first activation,
//!   so a free user who never buys never has an identifier generated.
//! * The RECEIPTS: signed `prx1-` texts in the vault (schema 7,
//!   `activation`), one per device that activated under the current
//!   licence, so a synced vault carries every device's receipt and each
//!   machine finds its own by device id.
//! * The CALL: `POST {origin}/premium/activate` with the full token and the
//!   device id, over the tunnel when one is in force (`crate::net`, fail
//!   closed). It happens ONCE per device in the normal life of a licence.
//!   Every later unlock re-verifies the cached receipt offline; while a
//!   device is unactivated (first unlock after paste, or a refused earlier
//!   try) each unlock makes ONE silent retry. Nothing here runs on a
//!   schedule and nothing phones home to switch anything OFF.
//! * The GATE: `licence_control` decides `premium_active` = the token is
//!   ACTIVE and a receipt in the vault binds to this device. This module
//!   only produces the receipt.
//!
//! What the server learns per activation: the licence id (it minted it),
//! this device id, the day. What it does not: an IP address (`access_log
//! off` on the location; the app never sends one), a user agent beyond
//! "patanyx", anything about the machine.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use zeroize::Zeroize as _;

use crate::state::AppState;

// ---- device id ---------------------------------------------------------------

/// The file name beside the vault.
pub const DEVICE_ID_FILE: &str = "device-id";

/// Why the device id could not be produced. Every arm is user-visible
/// through the activation state's message.
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceIdError {
    /// The file exists and is not 32 lowercase hex: refused, never
    /// overwritten.
    Unreadable,
    /// The file could not be read or written for an I/O reason.
    Io,
}

/// Where the device id lives for a vault at `vault_path`.
pub fn device_id_path(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .map(|dir| dir.join(DEVICE_ID_FILE))
        .unwrap_or_else(|| PathBuf::from(DEVICE_ID_FILE))
}

/// The device id if the file already exists; `Ok(None)` if there is none
/// yet. Never mints: reading the vault must not create an identifier.
pub fn device_id_if_present(vault_path: &Path) -> Result<Option<[u8; 16]>, DeviceIdError> {
    let path = device_id_path(vault_path);
    match std::fs::read(&path) {
        Ok(bytes) => parse_device_id_file(&bytes)
            .map(Some)
            .ok_or(DeviceIdError::Unreadable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(DeviceIdError::Io),
    }
}

/// The device id, minting it if this install has none yet.
pub fn device_id_or_mint(vault_path: &Path) -> Result<[u8; 16], DeviceIdError> {
    if let Some(id) = device_id_if_present(vault_path)? {
        return Ok(id);
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|_| DeviceIdError::Io)?;
    write_device_id_file(&device_id_path(vault_path), &id)?;
    Ok(id)
}

/// Exactly 32 lowercase hex, an optional trailing newline. Anything else
/// is not ours.
fn parse_device_id_file(bytes: &[u8]) -> Option<[u8; 16]> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    decode_hex_16(text)
}

fn write_device_id_file(path: &Path, id: &[u8; 16]) -> Result<(), DeviceIdError> {
    // create_new: if a second thread or process minted between our read
    // and this write, we must NOT overwrite its id.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(format!("{}\n", hex_encode_16(id)).as_bytes())
                .map_err(|_| DeviceIdError::Io)?;
            file.sync_all().map_err(|_| DeviceIdError::Io)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Someone else minted first; their id wins and ours is dropped.
            Ok(())
        }
        Err(_) => Err(DeviceIdError::Io),
    }
}

pub fn hex_encode_16(bytes: &[u8; 16]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing hex into a String cannot fail");
    }
    out
}

pub fn decode_hex_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

// ---- the call --------------------------------------------------------------------

/// The licence endpoints live on the update origin: a separate `licence.`
/// host name would put "this machine is a paying Premium user" into a DNS
/// query. `PATANYX_LICENCE_ORIGIN` overrides it for the end-to-end gate,
/// exactly like `PATANYX_UPDATE_MANIFEST_URL` does for the updater; a
/// shipped build never sets it.
fn licence_origin() -> String {
    std::env::var("PATANYX_LICENCE_ORIGIN")
        .ok()
        .filter(|v| is_loopback_origin(v))
        .unwrap_or_else(|| crate::updater::base_url().to_string())
}

/// Is this override a real loopback origin, by the HOST rather than by how
/// the string begins?
///
/// A prefix test reads `http://localhost:@evil.example/` as loopback: the
/// userinfo runs up to the last `@`, so everything before it is a username
/// and the actual host is `evil.example` (security audit 2026-08-18, F5).
/// The override then aims the activation POST -- which carries the full
/// licence token and this install's device id -- at whatever that resolves
/// to. Reaching it needs control of the process environment, which is
/// already a lost machine, but "you had to be compromised first" is a reason
/// to fix a hole cheaply rather than a reason to keep it.
///
/// `host_of` is the same extraction the content allowlist uses, so the two
/// agree about where a host ends and there is one place to correct if a
/// browser ever normalizes differently. A port is required, as before: the
/// override exists for the end-to-end gate, which always names one.
fn is_loopback_origin(value: &str) -> bool {
    let Some(host) = crate::state::host_of(value) else {
        return false;
    };
    if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
        return false;
    }
    // http only, and a port must be present: this is a test hook, not a
    // second production endpoint.
    value.starts_with("http://") && value.rsplit(':').next().is_some_and(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
}

/// How one activation attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateOutcome {
    /// The server granted (or re-served) this device's slot.
    Activated { receipt_text: String },
    /// The server answered and said no. The code is one of the server's:
    /// `slots_full`, `grants_exhausted`, `expired`, `bad_token`.
    Refused(String),
    /// The server could not be reached, or refused to talk (proxy not
    /// expressible, TLS, timeout, non-JSON answer, 5xx). Retryable.
    Offline(String),
}

/// Blocking: call the server. Runs on a worker thread, never on the event
/// loop. Compiled without a network client, it answers `Offline` honestly.
#[cfg(feature = "updater-net")]
fn post_json_blocking(route: &str, body: &Value) -> Result<(u16, Value), String> {
    use std::time::Duration;
    let agent = crate::net::agent(Duration::from_secs(20)).map_err(|e| e.to_string())?;
    let url = format!("{}/premium/{route}", licence_origin());
    let sent = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    let (status, response) = match sent {
        Ok(response) => (response.status(), response),
        Err(ureq::Error::Status(code, response)) => (code, response),
        Err(ureq::Error::Transport(t)) => return Err(t.to_string()),
    };
    let text = response.into_string().map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_str(&text).map_err(|_| "non-JSON answer".to_string())?;
    Ok((status, value))
}

#[cfg(not(feature = "updater-net"))]
fn post_json_blocking(_route: &str, _body: &Value) -> Result<(u16, Value), String> {
    Err("this build has no network client".to_string())
}

/// Turn the server's answer into an outcome. Pure, so the mapping is
/// table-tested below without a server.
pub fn outcome_from_reply(reply: Result<(u16, Value), String>) -> ActivateOutcome {
    match reply {
        Ok((200, value)) => match value.get("receipt").and_then(Value::as_str) {
            Some(receipt) if receipt.starts_with("prx1-") => ActivateOutcome::Activated {
                receipt_text: receipt.to_string(),
            },
            _ => ActivateOutcome::Offline("200 without a receipt".to_string()),
        },
        Ok((code, value)) if (400..500).contains(&code) => {
            let error = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("bad_request")
                .to_string();
            ActivateOutcome::Refused(error)
        }
        Ok((code, _)) => ActivateOutcome::Offline(format!("HTTP {code}")),
        Err(why) => ActivateOutcome::Offline(why),
    }
}

pub fn activate_blocking(token_text: &str, device_id: &[u8; 16]) -> ActivateOutcome {
    let body = json!({ "token": token_text, "device_id": hex_encode_16(device_id) });
    outcome_from_reply(post_json_blocking("activate", &body))
}

/// Release this device's slot. `Ok(released)`; `Err` when the server could
/// not be reached (the local receipt is then KEPT: releasing locally while
/// the server still counts the slot would strand a slot the user thinks is
/// free).
pub fn release_blocking(token_text: &str, device_id: &[u8; 16]) -> Result<bool, String> {
    let body = json!({ "token": token_text, "device_id": hex_encode_16(device_id) });
    match post_json_blocking("release", &body) {
        Ok((200, value)) => Ok(value
            .get("released")
            .and_then(Value::as_bool)
            .unwrap_or(false)),
        Ok((code, value)) => Err(value
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {code}"))),
        Err(why) => Err(why),
    }
}

// ---- the asynchronous flow ---------------------------------------------------

/// What kind of call a worker ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Activate,
    Release,
}

/// A finished call, on its way back to the event loop.
#[derive(Debug)]
pub struct ActivationEvent {
    pub kind: CallKind,
    /// The licence the call was made for; if the vault now holds a
    /// different licence (replaced meanwhile), the result is dropped.
    pub license_id_hex: String,
    pub device_id_hex: String,
    pub activate: Option<ActivateOutcome>,
    pub release: Option<Result<bool, String>>,
}

/// Start ONE activation attempt for the stored token, if the session says
/// one is due. Returns whether a worker was started. Called from
/// `licence_control::on_vault_unlocked` (the silent retry) and from the
/// `licence_activate` IPC arm (the user's explicit "Activate now").
///
/// The token text is read from the vault for the worker and wiped by the
/// worker as soon as the request body is built.
pub fn start_activation(state: &AppState) -> bool {
    let Some(session) = crate::licence_control::current() else {
        return false;
    };
    if !session.state.premium_active() {
        // FREE or LAPSED: there is nothing to activate.
        return false;
    }
    if crate::licence_control::activation_in_flight() {
        return false;
    }
    let vault_path = state.vault_path.clone();
    let device_id = match device_id_or_mint(&vault_path) {
        Ok(id) => id,
        Err(DeviceIdError::Unreadable) => {
            crate::licence_control::set_activation_result("device_id_unreadable");
            return false;
        }
        Err(DeviceIdError::Io) => {
            crate::licence_control::set_activation_result("device_id_io");
            return false;
        }
    };
    let Some(mut record) = state.vault.as_ref().and_then(|v| v.licence_record()) else {
        return false;
    };
    let Some(license_id_hex) = crate::licence_control::current_license_id_hex() else {
        record.token_text.zeroize();
        return false;
    };
    crate::licence_control::mark_activation_in_flight();
    let proxy = state.proxy();
    std::thread::spawn(move || {
        let outcome = activate_blocking(&record.token_text, &device_id);
        record.token_text.zeroize();
        let _ = proxy.send_event(crate::UserEvent::Activation(ActivationEvent {
            kind: CallKind::Activate,
            license_id_hex,
            device_id_hex: hex_encode_16(&device_id),
            activate: Some(outcome),
            release: None,
        }));
    });
    true
}

/// Start a release of THIS device's slot. Only meaningful while activated;
/// the IPC arm checks that. Returns whether a worker was started.
pub fn start_release(state: &AppState) -> bool {
    let vault_path = state.vault_path.clone();
    let Ok(Some(device_id)) = device_id_if_present(&vault_path) else {
        return false;
    };
    let Some(mut record) = state.vault.as_ref().and_then(|v| v.licence_record()) else {
        return false;
    };
    let Some(license_id_hex) = crate::licence_control::current_license_id_hex() else {
        record.token_text.zeroize();
        return false;
    };
    crate::licence_control::mark_activation_in_flight();
    let proxy = state.proxy();
    std::thread::spawn(move || {
        let result = release_blocking(&record.token_text, &device_id);
        record.token_text.zeroize();
        let _ = proxy.send_event(crate::UserEvent::Activation(ActivationEvent {
            kind: CallKind::Release,
            license_id_hex,
            device_id_hex: hex_encode_16(&device_id),
            activate: None,
            release: Some(result),
        }));
    });
    true
}

/// Back on the event loop: record the outcome in the vault and the session,
/// then tell the chrome. If the vault locked or the licence changed while
/// the worker ran, the result is dropped: it belongs to a state that no
/// longer exists.
pub fn handle_event(state: &mut AppState, event: ActivationEvent) {
    crate::licence_control::clear_activation_in_flight();
    let still_same_licence =
        crate::licence_control::current_license_id_hex().as_deref() == Some(&*event.license_id_hex);
    let Some(vault) = state.vault.as_mut() else {
        return;
    };
    if !still_same_licence {
        return;
    }
    match event.kind {
        CallKind::Activate => match event.activate {
            Some(ActivateOutcome::Activated { receipt_text }) => {
                let mut records: Vec<patanyx_vault::ActivationRecord> = vault
                    .activation_records()
                    .into_iter()
                    // Prune to the current licence and drop any older row
                    // for this device: one row per device, receipts of a
                    // replaced licence are dead weight.
                    .filter(|r| {
                        r.license_id_hex == event.license_id_hex
                            && r.device_id_hex != event.device_id_hex
                    })
                    .collect();
                records.push(patanyx_vault::ActivationRecord {
                    license_id_hex: event.license_id_hex.clone(),
                    device_id_hex: event.device_id_hex.clone(),
                    receipt_text,
                });
                // At most five per licence: the server never grants more
                // than five ACTIVE, so a sixth row here is stale.
                while records.len() > 5 {
                    records.remove(0);
                }
                if vault.set_activation_records(records).is_err() {
                    crate::licence_control::set_activation_result("vault_io");
                } else {
                    // Re-run the unlock-time evaluation from the vault: the
                    // same offline path every later unlock takes decides
                    // that this device is now activated. No cached bit.
                    crate::licence_control::on_vault_unlocked(state);
                }
            }
            Some(ActivateOutcome::Refused(code)) => {
                crate::licence_control::set_activation_result(refusal_code(&code));
            }
            Some(ActivateOutcome::Offline(why)) => {
                eprintln!("patanyx activation: could not reach the licence server ({why})");
                crate::licence_control::set_activation_result("offline");
            }
            None => {}
        },
        CallKind::Release => match event.release {
            Some(Ok(_released)) => {
                // Released on the server (or it never held a slot there):
                // either way this device's receipt is dead. Remove it, then
                // re-evaluate: Premium goes off on THIS machine, in front of
                // the user, which is what release means.
                let records: Vec<patanyx_vault::ActivationRecord> = vault
                    .activation_records()
                    .into_iter()
                    .filter(|r| r.device_id_hex != event.device_id_hex)
                    .collect();
                if vault.set_activation_records(records).is_err() {
                    crate::licence_control::set_activation_result("vault_io");
                } else {
                    crate::licence_control::on_vault_unlocked(state);
                    crate::licence_control::set_activation_result("released");
                }
            }
            Some(Err(why)) => {
                eprintln!("patanyx activation: release did not reach the licence server ({why})");
                crate::licence_control::set_activation_result("release_offline");
            }
            None => {}
        },
    }
    state.emit("licence_changed", json!({}));
}

/// The server's refusal codes, narrowed to the ones the copy knows; any
/// other string is reported as a generic refusal rather than echoed.
fn refusal_code(code: &str) -> &'static str {
    match code {
        "slots_full" => "slots_full",
        "grants_exhausted" => "grants_exhausted",
        "expired" => "expired",
        "bad_token" => "bad_token",
        _ => "refused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_device_id_is_minted_once_and_then_stable() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.bin");
        assert_eq!(device_id_if_present(&vault_path), Ok(None));
        let first = device_id_or_mint(&vault_path).unwrap();
        let second = device_id_or_mint(&vault_path).unwrap();
        assert_eq!(first, second);
        assert_eq!(device_id_if_present(&vault_path), Ok(Some(first)));
        let raw = std::fs::read_to_string(device_id_path(&vault_path)).unwrap();
        assert_eq!(raw.trim_end().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(device_id_path(&vault_path))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_unreadable_device_id_is_refused_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.bin");
        std::fs::write(device_id_path(&vault_path), "garbage\n").unwrap();
        assert_eq!(
            device_id_if_present(&vault_path),
            Err(DeviceIdError::Unreadable)
        );
        assert_eq!(
            device_id_or_mint(&vault_path),
            Err(DeviceIdError::Unreadable)
        );
        assert_eq!(
            std::fs::read_to_string(device_id_path(&vault_path)).unwrap(),
            "garbage\n"
        );
        // Uppercase is not ours either.
        std::fs::write(device_id_path(&vault_path), "AB".repeat(16)).unwrap();
        assert_eq!(
            device_id_if_present(&vault_path),
            Err(DeviceIdError::Unreadable)
        );
    }

    #[test]
    fn hex_round_trips() {
        let id = [0xd1u8; 16];
        assert_eq!(decode_hex_16(&hex_encode_16(&id)), Some(id));
        assert_eq!(decode_hex_16("zz"), None);
    }

    #[test]
    fn server_replies_map_to_outcomes() {
        assert_eq!(
            outcome_from_reply(Ok((200, json!({"receipt": "prx1-abc"})))),
            ActivateOutcome::Activated {
                receipt_text: "prx1-abc".to_string()
            }
        );
        assert!(matches!(
            outcome_from_reply(Ok((200, json!({"receipt": "ptx1-not-a-receipt"})))),
            ActivateOutcome::Offline(_)
        ));
        assert_eq!(
            outcome_from_reply(Ok((409, json!({"error": "slots_full"})))),
            ActivateOutcome::Refused("slots_full".to_string())
        );
        assert_eq!(
            outcome_from_reply(Ok((401, json!({"error": "bad_token"})))),
            ActivateOutcome::Refused("bad_token".to_string())
        );
        assert!(matches!(
            outcome_from_reply(Ok((502, json!({})))),
            ActivateOutcome::Offline(_)
        ));
        assert!(matches!(
            outcome_from_reply(Err("timeout".to_string())),
            ActivateOutcome::Offline(_)
        ));
        assert_eq!(refusal_code("slots_full"), "slots_full");
        assert_eq!(refusal_code("something_new"), "refused");
    }

    #[test]
    /// ACTIVATION MUST NEVER ACCEPT AN INTERCEPTED CONNECTION.
    ///
    /// The update and blocklist channels may fall back to the OS trust store,
    /// because their integrity rests on the compiled-in Ed25519 key rather
    /// than on TLS (see `net::Roots`, security audit 2026-08-18, F21). This
    /// request is the opposite case: it SENDS the licence token and this
    /// install's device id, so TLS confidentiality is the whole protection
    /// and no signature can recover a secret already handed to a proxy.
    ///
    /// Reading the source is the only way to state "this function is not
    /// called here" as a test. Same idiom as privacy.rs's zero-channels
    /// check. If activation ever legitimately needs the relaxed agent, that
    /// is a decision to argue for in a commit message, not a line to slip in.
    #[test]
    fn activation_never_reaches_for_the_relaxed_agent() {
        // ONLY THE SHIPPED HALF. The test module below necessarily names the
        // function it is asserting the absence of, which would match itself --
        // the same self-match the export guard avoids by excluding its own
        // file. Everything above `#[cfg(test)]` is what is compiled into the
        // binary, and that is what this is about.
        let source = include_str!("activation.rs");
        let shipped = source
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(source);
        let needle = concat!("agent_accepting", "_os_roots");
        let calls: Vec<&str> = shipped
            .lines()
            .filter(|l| l.contains(needle))
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        assert!(
            calls.is_empty(),
            "activation must use only the strict agent; found: {calls:?}"
        );
        // And it does still build one, or it would not be talking to anything.
        assert!(
            shipped.contains("crate::net::agent("),
            "the activation call lost its agent entirely"
        );
    }

    #[test]
    fn the_origin_override_only_accepts_loopback() {
        // USERINFO IS NOT A HOST (security audit 2026-08-18, F5). The last
        // `@` ends the userinfo, so each of these has a real host that is not
        // loopback while BEGINNING with a loopback-looking string. A prefix
        // test accepted every one and aimed the activation POST -- the full
        // licence token and this install's device id -- at the attacker.
        for spelling in [
            "http://localhost:@evil.example/",
            "http://127.0.0.1:@evil.example/",
            "http://localhost:8788@evil.example/",
            "http://127.0.0.1:1@evil.example/",
            // A host that merely starts with the loopback name.
            "http://localhost.evil.example:8788/",
            "http://127.0.0.1.evil.example:8788/",
            // https is not the shape this hook takes.
            "https://127.0.0.1:8788/",
        ] {
            std::env::set_var("PATANYX_LICENCE_ORIGIN", spelling);
            assert_ne!(
                licence_origin(),
                spelling,
                "a non-loopback host reached the override: {spelling}"
            );
        }
        // The genuine article still works, or the end-to-end gate cannot run.
        for good in ["http://127.0.0.1:18788", "http://localhost:18788"] {
            std::env::set_var("PATANYX_LICENCE_ORIGIN", good);
            assert_eq!(licence_origin(), good, "loopback override refused: {good}");
        }
        std::env::set_var("PATANYX_LICENCE_ORIGIN", "http://evil.example");
        assert_eq!(licence_origin(), crate::updater::base_url());
        std::env::set_var("PATANYX_LICENCE_ORIGIN", "http://127.0.0.1:18788");
        assert_eq!(licence_origin(), "http://127.0.0.1:18788");
        std::env::remove_var("PATANYX_LICENCE_ORIGIN");
        assert_eq!(licence_origin(), crate::updater::base_url());
    }
}
