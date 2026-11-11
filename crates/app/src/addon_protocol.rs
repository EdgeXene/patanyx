//! The add-on message protocol, host API 1.
//!
//! An add-on is a separately delivered web bundle that runs in its own
//! webview, on its own origin, and talks to the browser ONLY through these
//! frames. They arrive on the add-on's own event (`UserEvent::AddonIpc`) and
//! never reach `ipc::dispatch`: the chrome's command set is not reachable from
//! here at all, and this module's closed `Command` enum is the whole of what
//! an add-on can ask for.
//!
//! PARSING IS STRICT AND CLOSED. Every object rejects unknown fields, every
//! command has its own argument shape, and every bound is checked before any
//! data is touched. A frame that does not parse is refused with a stable code
//! and nothing else happens.
//!
//! Wire shapes (UTF-8 JSON, at most `MAX_FRAME_BYTES` serialized):
//!
//! ```text
//! request: {"v":1,"id":<u32 > 0>,"generation":"<decimal u64>",
//!           "command":"<name>","args":{...},"presence":<bool>}
//! success: {"v":1,"id":..,"generation":"..","ok":true,"result":{...}}
//! failure: {"v":1,"id":<u32 or null>,"generation":"..","ok":false,"error":"<code>"}
//! event:   {"v":1,"generation":"..","event":"<name>","data":{...}}
//! ```
//!
//! Page bodies and selected text travel as standard padded base64 of valid
//! UTF-8, so JSON escaping cannot inflate them: a 512 KiB page is at most
//! 699,052 base64 characters, which leaves room for the rest of the frame.

use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// The host API this browser speaks.
pub const HOST_API: u32 = 1;
/// The largest frame accepted or sent, in serialized bytes.
pub const MAX_FRAME_BYTES: usize = 1_048_576;
/// The largest page body (and selected text), in decoded UTF-8 bytes.
pub const MAX_PAGE_BYTES: usize = 524_288;
/// `MAX_PAGE_BYTES` as padded base64.
pub const MAX_BODY_B64: usize = MAX_PAGE_BYTES.div_ceil(3) * 4;
/// The longest page title, in Unicode scalar values.
pub const MAX_TITLE_CHARS: usize = 200;
/// The most entries one list reply carries.
pub const MAX_LIST_ITEMS: u16 = 128;
/// The longest cursor string a list request may carry back.
const MAX_CURSOR_LEN: usize = 256;
/// The longest Vault note id accepted.
const MAX_NOTE_ID_LEN: usize = 128;
/// The smallest and largest Vault note chunk a read may ask for.
const NOTE_CHUNK: std::ops::RangeInclusive<u64> = 4..=MAX_PAGE_BYTES as u64;

/// A stable error code. These words are the protocol; the add-on keys on
/// them, so they never change meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    FrameTooLarge,
    BadFrame,
    BadArgs,
    NotAllowed,
}

impl ProtocolError {
    pub fn code(self) -> &'static str {
        match self {
            Self::FrameTooLarge => "frame_too_large",
            Self::BadFrame => "bad_frame",
            Self::BadArgs => "bad_args",
            Self::NotAllowed => "not_allowed",
        }
    }
}

/// A refused frame: what is known of it, and why.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejection {
    /// The request id, when the frame got far enough to have one.
    pub id: Option<u32>,
    /// The generation the frame claimed, when it parsed. Never authority:
    /// the host compares it with the generation it captured itself.
    pub generation: Option<u64>,
    pub error: ProtocolError,
}

/// A host-generated page id: 32 lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageId(String);

impl PageId {
    pub fn parse(s: &str) -> Option<Self> {
        (s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .then(|| Self(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical decimal u64 revision; `0` means "a new page".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(pub u64);

impl Revision {
    pub fn parse(s: &str) -> Option<Self> {
        parse_canonical_u64(s).map(Self)
    }
    pub fn to_wire(self) -> String {
        self.0.to_string()
    }
}

/// Decimal, no sign, no leading zero (except "0" itself), fits in u64.
fn parse_canonical_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// A host-issued token (flush id, delivery id): 32 lowercase hex characters.
fn token_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushStatus {
    Saved,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionStatus {
    Saved,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionError {
    PageTooLarge,
    QuotaExceeded,
    SaveFailed,
}

/// Everything an add-on can ask for. Nothing outside this enum is reachable.
#[derive(Debug)]
pub enum Command {
    Ready { host_api: u32 },
    Presence,
    StoreList { cursor: Option<String>, limit: u16 },
    StoreGet { id: PageId },
    StorePut {
        /// `None` creates a page; `base_revision` is then 0.
        id: Option<PageId>,
        base_revision: Revision,
        title: String,
        /// Decoded, valid UTF-8, at most `MAX_PAGE_BYTES`.
        body: Zeroizing<Vec<u8>>,
        flush_id: Option<String>,
        /// The page's site attachment: kept (field absent), set, or cleared
        /// (`null`).
        site: patanyx_store::SiteChange,
        /// Only on a create: the collection the page is made in.
        collection: Option<String>,
    },
    StoreDelete { id: PageId, base_revision: Revision },
    WindowMove { x: f64, y: f64, sequence: u32 },
    WindowResize { width: f64, height: f64, sequence: u32 },
    WindowCollapse { collapsed: bool },
    WindowClose,
    VaultNotesList { cursor: Option<String>, limit: u16 },
    VaultNotesGet { id: String, offset: u64, limit: u64, revision: Option<String> },
    VaultNoteEditInVault { id: String },
    VaultPremiumOpen,
    /// Takes no address: the host opens its own pinned destination.
    PremiumPurchaseOpen,
    FlushDone { flush_id: String, status: FlushStatus },
    SelectionResult { delivery_id: String, status: SelectionStatus, error: Option<SelectionError> },
}

impl Command {
    /// The wire name, for logs and counters (never page content).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "addon_ready",
            Self::Presence => "addon_presence",
            Self::StoreList { .. } => "addon_store_list",
            Self::StoreGet { .. } => "addon_store_get",
            Self::StorePut { .. } => "addon_store_put",
            Self::StoreDelete { .. } => "addon_store_delete",
            Self::WindowMove { .. } => "window_move",
            Self::WindowResize { .. } => "window_resize",
            Self::WindowCollapse { .. } => "window_collapse",
            Self::WindowClose => "window_close",
            Self::VaultNotesList { .. } => "vault_notes_list",
            Self::VaultNotesGet { .. } => "vault_notes_get",
            Self::VaultNoteEditInVault { .. } => "vault_note_edit_in_vault",
            Self::VaultPremiumOpen => "vault_premium_open",
            Self::PremiumPurchaseOpen => "premium_purchase_open",
            Self::FlushDone { .. } => "addon_flush_done",
            Self::SelectionResult { .. } => "addon_selection_result",
        }
    }
}

/// The names an add-on may send, for the allowlist test and the refusal of
/// anything else. Kept in step with `Command::name` by a test.
pub const COMMANDS: &[&str] = &[
    "addon_ready",
    "addon_presence",
    "addon_store_list",
    "addon_store_get",
    "addon_store_put",
    "addon_store_delete",
    "window_move",
    "window_resize",
    "window_collapse",
    "window_close",
    "vault_notes_list",
    "vault_notes_get",
    "vault_note_edit_in_vault",
    "vault_premium_open",
    "premium_purchase_open",
    "addon_flush_done",
    "addon_selection_result",
];

/// One parsed request.
#[derive(Debug)]
pub struct Request {
    pub id: u32,
    /// What the frame CLAIMS. The dispatcher compares it with the generation
    /// captured when the add-on's window was built; it is never authority.
    pub generation: u64,
    /// Parsed and never counted: no frame resets the auto-lock (typing in
    /// the add-on's window counts natively instead).
    pub presence: bool,
    pub command: Command,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFrame {
    v: u32,
    id: u32,
    generation: String,
    command: String,
    args: Value,
    presence: bool,
}

/// Parses one frame from an add-on.
pub fn parse(raw: &str) -> Result<Request, Rejection> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err(Rejection { id: None, generation: None, error: ProtocolError::FrameTooLarge });
    }
    let frame: RawFrame = serde_json::from_str(raw).map_err(|_| Rejection {
        id: None,
        generation: None,
        error: ProtocolError::BadFrame,
    })?;
    let generation = parse_canonical_u64(&frame.generation);
    let reject = |error| Rejection { id: Some(frame.id).filter(|&i| i > 0), generation, error };
    if frame.v != 1 || frame.id == 0 {
        return Err(reject(ProtocolError::BadFrame));
    }
    let Some(generation) = generation else {
        return Err(reject(ProtocolError::BadFrame));
    };
    if !COMMANDS.contains(&frame.command.as_str()) {
        return Err(reject(ProtocolError::NotAllowed));
    }
    let command = parse_command(&frame.command, frame.args).ok_or_else(|| reject(ProtocolError::BadArgs))?;
    Ok(Request { id: frame.id, generation, presence: frame.presence, command })
}

fn args<T: serde::de::DeserializeOwned>(value: Value) -> Option<T> {
    serde_json::from_value(value).ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyArgs {
    host_api: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    cursor: Option<String>,
    limit: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdArgs {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutArgs {
    id: Option<String>,
    base_revision: String,
    title: String,
    body_b64: String,
    flush_id: Option<String>,
    /// Absent: keep. `null`: clear. A string: set.
    #[serde(default, deserialize_with = "present")]
    site: Option<Option<String>>,
    /// The collection a NEW page is created in (host-api-1-notebook.md).
    #[serde(default)]
    collection: Option<String>,
}

/// Tells an absent field (`None`, by `default`) from an explicit `null`
/// (`Some(None)`).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteArgs {
    id: String,
    base_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveArgs {
    x: f64,
    y: f64,
    sequence: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResizeArgs {
    width: f64,
    height: f64,
    sequence: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollapseArgs {
    collapsed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotesGetArgs {
    id: String,
    offset: u64,
    limit: u64,
    revision: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PurchaseArgs {
    purchase: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlushDoneArgs {
    flush_id: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionResultArgs {
    delivery_id: String,
    status: String,
    error: Option<String>,
}

fn cursor_ok(c: &Option<String>) -> bool {
    c.as_ref().is_none_or(|c| {
        !c.is_empty() && c.len() <= MAX_CURSOR_LEN && c.bytes().all(|b| b.is_ascii_graphic())
    })
}

fn note_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_NOTE_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn parse_command(name: &str, value: Value) -> Option<Command> {
    Some(match name {
        "addon_ready" => Command::Ready { host_api: args::<ReadyArgs>(value)?.host_api },
        "addon_presence" => {
            args::<NoArgs>(value)?;
            Command::Presence
        }
        "addon_store_list" | "vault_notes_list" => {
            let a = args::<ListArgs>(value)?;
            if !(1..=MAX_LIST_ITEMS).contains(&a.limit) || !cursor_ok(&a.cursor) {
                return None;
            }
            if name == "addon_store_list" {
                Command::StoreList { cursor: a.cursor, limit: a.limit }
            } else {
                Command::VaultNotesList { cursor: a.cursor, limit: a.limit }
            }
        }
        "addon_store_get" => Command::StoreGet { id: PageId::parse(&args::<IdArgs>(value)?.id)? },
        "addon_store_put" => {
            let a = args::<PutArgs>(value)?;
            let id = match a.id {
                Some(id) => Some(PageId::parse(&id)?),
                None => None,
            };
            let base_revision = Revision::parse(&a.base_revision)?;
            // A create carries no id and revision 0; an update carries both.
            if id.is_none() != (base_revision.0 == 0) {
                return None;
            }
            if a.title.chars().count() > MAX_TITLE_CHARS {
                return None;
            }
            if a.flush_id.as_deref().is_some_and(|f| !token_ok(f)) {
                return None;
            }
            let site = match a.site {
                None => patanyx_store::SiteChange::Keep,
                Some(None) => patanyx_store::SiteChange::Clear,
                Some(Some(site)) if patanyx_store::valid_site(&site) => patanyx_store::SiteChange::Set(site),
                Some(Some(_)) => return None,
            };
            // A collection is chosen once, on a create, and must be well formed.
            if a.collection.as_deref().is_some_and(|c| id.is_some() || !patanyx_store::valid_collection(c)) {
                return None;
            }
            let body = decode_body(&a.body_b64)?;
            Command::StorePut { id, base_revision, title: a.title, body, flush_id: a.flush_id, site, collection: a.collection }
        }
        "addon_store_delete" => {
            let a = args::<DeleteArgs>(value)?;
            let base_revision = Revision::parse(&a.base_revision)?;
            if base_revision.0 == 0 {
                return None;
            }
            Command::StoreDelete { id: PageId::parse(&a.id)?, base_revision }
        }
        "window_move" => {
            let a = args::<MoveArgs>(value)?;
            if !(a.x.is_finite() && a.y.is_finite()) {
                return None;
            }
            Command::WindowMove { x: a.x, y: a.y, sequence: a.sequence }
        }
        "window_resize" => {
            let a = args::<ResizeArgs>(value)?;
            if !(a.width.is_finite() && a.height.is_finite() && a.width > 0.0 && a.height > 0.0) {
                return None;
            }
            Command::WindowResize { width: a.width, height: a.height, sequence: a.sequence }
        }
        "window_collapse" => Command::WindowCollapse { collapsed: args::<CollapseArgs>(value)?.collapsed },
        "window_close" => {
            args::<NoArgs>(value)?;
            Command::WindowClose
        }
        "vault_notes_get" => {
            let a = args::<NotesGetArgs>(value)?;
            if !note_id_ok(&a.id) || !NOTE_CHUNK.contains(&a.limit) {
                return None;
            }
            if a.revision.as_deref().is_some_and(|r| parse_canonical_u64(r).is_none()) {
                return None;
            }
            Command::VaultNotesGet { id: a.id, offset: a.offset, limit: a.limit, revision: a.revision }
        }
        "vault_note_edit_in_vault" => {
            let id = args::<IdArgs>(value)?.id;
            if !note_id_ok(&id) {
                return None;
            }
            Command::VaultNoteEditInVault { id }
        }
        "vault_premium_open" => {
            args::<NoArgs>(value)?;
            Command::VaultPremiumOpen
        }
        "premium_purchase_open" => {
            // Exactly {"purchase":"patanyx"}: any other target, and any extra
            // field (a `url`, say), is refused by deny_unknown_fields.
            if args::<PurchaseArgs>(value)?.purchase != "patanyx" {
                return None;
            }
            Command::PremiumPurchaseOpen
        }
        "addon_flush_done" => {
            let a = args::<FlushDoneArgs>(value)?;
            if !token_ok(&a.flush_id) {
                return None;
            }
            let status = match a.status.as_str() {
                "saved" => FlushStatus::Saved,
                "failed" => FlushStatus::Failed,
                _ => return None,
            };
            Command::FlushDone { flush_id: a.flush_id, status }
        }
        "addon_selection_result" => {
            let a = args::<SelectionResultArgs>(value)?;
            if !token_ok(&a.delivery_id) {
                return None;
            }
            let status = match a.status.as_str() {
                "saved" => SelectionStatus::Saved,
                "refused" => SelectionStatus::Refused,
                _ => return None,
            };
            let error = match a.error.as_deref() {
                None => None,
                Some("page_too_large") => Some(SelectionError::PageTooLarge),
                Some("quota_exceeded") => Some(SelectionError::QuotaExceeded),
                Some("save_failed") => Some(SelectionError::SaveFailed),
                Some(_) => return None,
            };
            // Saved carries no error; refused names one.
            if (status == SelectionStatus::Saved) != error.is_none() {
                return None;
            }
            Command::SelectionResult { delivery_id: a.delivery_id, status, error }
        }
        _ => return None,
    })
}

// ---- base64 ---------------------------------------------------------------------

/// Strict standard base64: padded, no whitespace, decoding to valid UTF-8 of
/// at most `MAX_PAGE_BYTES`.
pub fn decode_body(b64: &str) -> Option<Zeroizing<Vec<u8>>> {
    if b64.len() > MAX_BODY_B64 || b64.len() % 4 != 0 {
        return None;
    }
    if !b64.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
        return None;
    }
    let bytes = Zeroizing::new(crate::capture::decode_base64(b64)?);
    if bytes.len() > MAX_PAGE_BYTES || std::str::from_utf8(&bytes).is_err() {
        return None;
    }
    Some(bytes)
}

/// Standard padded base64.
pub fn encode_body(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

// ---- replies and events --------------------------------------------------------

/// A success reply. Falls back to `frame_too_large` rather than send a frame
/// over the limit.
pub fn success(id: u32, generation: u64, result: Value) -> String {
    let frame = json!({ "v": 1, "id": id, "generation": generation.to_string(), "ok": true, "result": result })
        .to_string();
    if frame.len() > MAX_FRAME_BYTES {
        return failure(Some(id), generation, ProtocolError::FrameTooLarge.code());
    }
    frame
}

/// A failure reply. `code` is a stable error word, never content.
pub fn failure(id: Option<u32>, generation: u64, code: &str) -> String {
    json!({ "v": 1, "id": id, "generation": generation.to_string(), "ok": false, "error": code }).to_string()
}

/// A host-to-add-on event, or `None` if it would exceed the frame limit.
pub fn event(generation: u64, name: &str, data: Value) -> Option<String> {
    let frame = json!({ "v": 1, "generation": generation.to_string(), "event": name, "data": data }).to_string();
    (frame.len() <= MAX_FRAME_BYTES).then_some(frame)
}

#[cfg(test)]
#[path = "addon_protocol_tests.rs"]
mod tests;
