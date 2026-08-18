//! Download corroboration — app wiring for `patanyx_corroborate::download`.
//!
//! Two people who trust each other compare the SHA-256 of what each of them
//! downloaded from the same address. Matching hashes mean the server served
//! both the same bytes; differing hashes mean it did not, which is how a
//! swap aimed at one person becomes visible at all.
//!
//! # What this module adds to the protocol crate
//!
//! The crate is pure logic: message shapes and a verdict. Everything here is
//! the part that touches this browser — which of the user's own download
//! records answers a question, when to refuse, and what the chrome is told.
//!
//! # Two rules carried over from page corroboration, deliberately
//!
//! 1. **The answer is automatic, so the user must SEE that it happened.**
//!    `download_compare_request_received` is emitted BEFORE anything else,
//!    including before the message is decoded. A silent automatic reply is
//!    the shape of a backdoor even when it is not one.
//! 2. **Refusal reasons from a peer are pinned to a closed set.** The
//!    vocabulary lives in `patanyx_corroborate::DownloadRefusal`; anything
//!    else becomes `bad_message`, so a peer cannot put chosen text on the
//!    asker's screen.
//!
//! # What this module answers with, and what it will not
//!
//! Only records the asker already named. The request carries a URL; the
//! answer is about THAT URL or it is a refusal. Nothing here enumerates the
//! user's downloads, and a peer learns nothing about files they did not
//! already ask about by name.
//!
//! A record whose own HMAC fails is refused rather than answered
//! (`record_untrusted`): a hash that may have been altered on disk proves
//! nothing, and reporting it as a comparison would launder a local integrity
//! failure into a claim about a server.

use std::collections::HashMap;

use patanyx_corroborate::{
    download_verdict, DownloadCompareRequest, DownloadCompareResponse, DownloadRefusal,
};
use serde_json::{json, Value};

use crate::chat_panel::ChatPayload;
use crate::page_integrity::{hex_decode, hex_encode};
use crate::state::AppState;

/// Requests WE sent, keyed by peer hash, so a reply can be turned into a
/// verdict. Memory only: nothing is stored, so a locked vault or a restarted
/// app simply forgets a comparison was ever asked. Mirrors
/// `IntegrityState::pending_corroborations` rather than inventing a second
/// shape for the same idea.
#[derive(Default)]
pub struct DownloadCompareState {
    pending: HashMap<String, DownloadCompareRequest>,
}

/// `download_compare_request` — ask a contact what they got from the same
/// address. `id` names one of the USER'S OWN download records; the contact
/// never chooses which of our records is discussed.
pub fn ipc_request(state: &mut AppState, args: &Value) -> Result<Value, &'static str> {
    let id = args.get("id").and_then(Value::as_str).ok_or("bad_args")?;
    let peer_hash = crate::chat_panel::resolve_peer_hash(state, args)?;
    let contact_id = args
        .get("contact_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let store = state.store.as_ref().ok_or("not_unlocked")?;
    let record = store.get_download(id).ok_or("no_download")?;
    // Our OWN record's integrity first. Sending a hash that may have been
    // altered on disk would make this browser the source of a false alarm.
    // A verification that could not run is treated exactly like one that
    // failed: neither says the hash is sound.
    if !store.verify_download(id).unwrap_or(false) {
        return Err("record_untrusted");
    }
    let url = patanyx_corroborate::normalize_url(&record.url).map_err(|_| "bad_url")?;
    let request = DownloadCompareRequest::new(
        &url,
        record.sha256,
        record.byte_len,
        record.recorded_at,
    );
    let data = hex_encode(&request.to_bytes().map_err(|_| "bad_message")?);
    let payload = ChatPayload::DownloadCompareRequest {
        url: url.as_str().to_string(),
        data,
    };
    crate::chat_panel::send_payload(state, &peer_hash, &payload)?;
    state
        .download_compare
        .pending
        .insert(peer_hash.clone(), request);
    Ok(json!({ "state": "sent", "peer_hash": peer_hash, "contact_id": contact_id }))
}

/// A contact asked what we got from an address. Answered automatically, and
/// visibly (see the module docs).
pub fn handle_request(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    url: String,
    data: String,
) {
    state.emit(
        "download_compare_request_received",
        json!({ "peer_hash": peer_hash, "contact_id": contact_id, "url": url }),
    );
    let Some(raw) = hex_decode(&data) else {
        return send_note(state, &peer_hash, DownloadRefusal::BadMessage);
    };
    let request = match DownloadCompareRequest::from_bytes(&raw) {
        Ok(request) => request,
        Err(_) => return send_note(state, &peer_hash, DownloadRefusal::BadMessage),
    };
    let Some(store) = state.store.as_ref() else {
        // No store open means no records to speak for. "Unsupported" rather
        // than "no download": we cannot say whether one exists.
        return send_note(state, &peer_hash, DownloadRefusal::Unsupported);
    };
    let Some(record) = newest_matching(store.downloads(), &request.url) else {
        return send_note(state, &peer_hash, DownloadRefusal::NoDownload);
    };
    let id = record.id.clone();
    let (sha256, byte_len, recorded_at) = (record.sha256, record.byte_len, record.recorded_at);
    if !store.verify_download(&id).unwrap_or(false) {
        return send_note(state, &peer_hash, DownloadRefusal::RecordUntrusted);
    }
    let Ok(url) = patanyx_corroborate::normalize_url(&request.url) else {
        return send_note(state, &peer_hash, DownloadRefusal::BadMessage);
    };
    let response = DownloadCompareResponse::new(&url, sha256, byte_len, recorded_at);
    let Ok(bytes) = response.to_bytes() else {
        return send_note(state, &peer_hash, DownloadRefusal::BadMessage);
    };
    let payload = ChatPayload::DownloadCompareResponse {
        data: hex_encode(&bytes),
    };
    if crate::chat_panel::send_payload(state, &peer_hash, &payload).is_err() {
        // The peer went away mid-answer. Nothing to tell them; the asking
        // side's own transport-down path clears its pending entry.
        return;
    }
    // The responder sees the verdict too. Both sides learning the same thing
    // at the same time is the point of a mutual check, and hiding it from
    // the person who answered would make the feature feel like surveillance.
    if let Ok(verdict) = download_verdict(&request, &response) {
        state.emit(
            "download_compare_verdict",
            verdict_json(&peer_hash, contact_id.as_deref(), &request.url, &verdict),
        );
    }
}

/// Our question was answered: request + response become the verdict.
pub fn handle_response(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    data: String,
) {
    let Some(raw) = hex_decode(&data) else {
        return emit_error(state, "bad_message");
    };
    let response = match DownloadCompareResponse::from_bytes(&raw) {
        Ok(response) => response,
        Err(_) => return emit_error(state, "bad_message"),
    };
    let Some(request) = state.download_compare.pending.remove(&peer_hash) else {
        // An answer to a question this browser did not ask. Reported as a
        // local note, never as a verdict: a verdict implies we know what was
        // compared, and here we do not.
        state.emit(
            "download_compare_note",
            json!({
                "peer_hash": peer_hash,
                "contact_id": contact_id,
                "local": true,
                "reason": "unexpected",
            }),
        );
        return;
    };
    match download_verdict(&request, &response) {
        Ok(verdict) => state.emit(
            "download_compare_verdict",
            verdict_json(&peer_hash, contact_id.as_deref(), &request.url, &verdict),
        ),
        // The URLs disagree, which cannot happen between honest peers: the
        // response is built from the request's own URL. Reported generically
        // rather than by echoing either address, since a download URL can
        // carry credentials or signed parameters.
        Err(_) => emit_error(state, "url_mismatch"),
    }
}

/// A contact could not answer. `reason` is peer-supplied and therefore
/// sanitized to the closed set before it can reach the chrome.
pub fn handle_note(
    state: &mut AppState,
    peer_hash: String,
    contact_id: Option<String>,
    reason: &str,
) {
    state.download_compare.pending.remove(&peer_hash);
    let reason = DownloadRefusal::parse(reason)
        .unwrap_or(DownloadRefusal::BadMessage)
        .as_str();
    state.emit(
        "download_compare_note",
        json!({
            "peer_hash": peer_hash,
            "contact_id": contact_id,
            "local": false,
            "reason": reason,
        }),
    );
}

/// The transport died: every outstanding question is unanswerable now, and
/// leaving them pending would let a later, unrelated reply be matched to one.
pub fn on_transport_down(state: &mut AppState) {
    state.download_compare.pending.clear();
}

/// Which of the user's own records answers a question about `asked_url`.
///
/// Pure, so the two decisions inside it can be tested without a vault, a
/// store, or a peer: records are matched on the NORMALIZED url (the asker
/// sent a normalized one, and ours are raw as the engine saw them), and the
/// NEWEST match wins. Newest because a repeated download is the likeliest
/// reason for several, and it is the one whose age the verdict can report
/// honestly. A record whose url will not normalize is skipped rather than
/// compared as a raw string, which would match by accident or not at all.
fn newest_matching<'a>(
    records: &'a [patanyx_store::DownloadRecord],
    asked_url: &str,
) -> Option<&'a patanyx_store::DownloadRecord> {
    records
        .iter()
        .filter(|record| {
            patanyx_corroborate::normalize_url(&record.url)
                .is_ok_and(|normalized| normalized.as_str() == asked_url)
        })
        .max_by_key(|record| record.recorded_at)
}

fn send_note(state: &mut AppState, peer_hash: &str, reason: DownloadRefusal) {
    let payload = ChatPayload::DownloadCompareNote {
        reason: reason.as_str().to_string(),
    };
    let _ = crate::chat_panel::send_payload(state, peer_hash, &payload);
}

fn emit_error(state: &mut AppState, code: &str) {
    state.emit(
        "download_compare_error",
        json!({ "op": "download_compare", "code": code }),
    );
}

/// One shape for the verdict, so the chrome never assembles the wording.
/// `text` is the protocol crate's own Display output, shown verbatim.
fn verdict_json(
    peer_hash: &str,
    contact_id: Option<&str>,
    url: &str,
    verdict: &patanyx_corroborate::DownloadVerdict,
) -> Value {
    json!({
        "peer_hash": peer_hash,
        "contact_id": contact_id,
        "url": url,
        "kind": match verdict.corroboration {
            patanyx_corroborate::DownloadCorroboration::HashEqual => "hash_equal",
            patanyx_corroborate::DownloadCorroboration::HashDiffers => "hash_differs",
        },
        "text": verdict.corroboration.to_string(),
        "byte_len_equal": verdict.byte_len_equal,
        "recorded_gap_seconds": verdict.recorded_gap_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use patanyx_store::DownloadRecord;

    fn record(id: &str, url: &str, recorded_at: u64) -> DownloadRecord {
        DownloadRecord {
            id: id.to_string(),
            url: url.to_string(),
            filename: "setup.exe".to_string(),
            byte_len: 10,
            sha256: [7u8; 32],
            recorded_at,
            hmac: [0u8; 32],
        }
    }

    #[test]
    fn the_newest_record_for_that_address_answers_and_others_are_ignored() {
        let records = [
            record("old", "https://dl.example/setup.exe", 100),
            record("elsewhere", "https://other.example/setup.exe", 999),
            record("new", "https://dl.example/setup.exe", 300),
            record("older", "https://dl.example/setup.exe", 200),
        ];
        let hit = newest_matching(&records, "https://dl.example/setup.exe").expect("a match");
        assert_eq!(hit.id, "new", "the newest matching record must answer");

        // An address we have never downloaded from is None, which the caller
        // turns into a no_download refusal rather than a silent non-answer.
        assert!(newest_matching(&records, "https://nowhere.example/x").is_none());
    }

    #[test]
    fn matching_is_on_the_normalized_url_not_the_raw_one() {
        // The asker sends a normalized url; ours are stored as the engine saw
        // them. A case-different host is the same download and must match.
        let records = [record("a", "HTTPS://DL.Example/setup.exe", 10)];
        assert!(newest_matching(&records, "https://dl.example/setup.exe").is_some());

        // A record whose url cannot be normalized is skipped, never compared
        // as a raw string.
        let broken = [record("b", "not a url at all", 10)];
        assert!(newest_matching(&broken, "not a url at all").is_none());
    }

    #[test]
    fn a_peer_supplied_reason_can_only_ever_be_one_of_four_words() {
        // The app-side half of the sanitizer rule: whatever arrives, what
        // reaches the chrome is a word from the closed set.
        for bogus in ["gotcha", "", "NO_DOWNLOAD", "<script>", "no_download "] {
            let mapped = DownloadRefusal::parse(bogus)
                .unwrap_or(DownloadRefusal::BadMessage)
                .as_str();
            assert_eq!(mapped, "bad_message", "{bogus:?} must degrade, not pass");
        }
        for good in ["no_download", "record_untrusted", "bad_message", "unsupported"] {
            let mapped = DownloadRefusal::parse(good)
                .unwrap_or(DownloadRefusal::BadMessage)
                .as_str();
            assert_eq!(mapped, good, "a known reason must survive intact");
        }
    }

    #[test]
    fn the_verdict_payload_carries_the_crates_own_words_verbatim() {
        let url = patanyx_corroborate::normalize_url("https://dl.example/a.exe").unwrap();
        let req = DownloadCompareRequest::new(&url, [1u8; 32], 10, 100);
        let resp = DownloadCompareResponse::new(&url, [2u8; 32], 20, 160);
        let verdict = download_verdict(&req, &resp).expect("same url");
        let payload = verdict_json("hash", Some("contact"), &req.url, &verdict);

        assert_eq!(payload["kind"], "hash_differs");
        assert_eq!(payload["byte_len_equal"], false);
        assert_eq!(payload["recorded_gap_seconds"], 60);
        assert_eq!(
            payload["text"],
            verdict.corroboration.to_string(),
            "the wording must be the protocol crate's, never assembled here"
        );
        // The url the chrome renders is the normalized one both sides agreed
        // on, not anything a peer chose.
        assert_eq!(payload["url"], "https://dl.example/a.exe");
    }
}
