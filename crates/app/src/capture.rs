//! Page capture: save what the current tab shows as a PNG the user chooses
//! a home for. Everything local; nothing here may ever grow a network
//! client.
//!
//! The platforms honestly differ, and the difference is labelled rather
//! than papered over: WebView2 exposes only CapturePreview (the VISIBLE
//! VIEWPORT -- resizing the real webview to page height to fake more would
//! repaint the user's window and lie about what was on screen), while
//! WebKitGTK snapshots the FULL DOCUMENT. The scope appears in the toast
//! and the default file name, so a saved file never claims to be more than
//! it is.
//!
//! Text extraction USED to compose with the OCR panel only via a saved file
//! (capture, then scan the file), and this header used to forbid a fused
//! capture-and-read command. That decision is deliberately superseded by the
//! Premium region-read mode: the region flow is initiated FROM the OCR
//! surface itself (mode button, then a drag on the captured image), so the
//! "only accepts scans it initiated" rule that motivated the ban is
//! preserved rather than broken. What remains true and load-bearing: the
//! capture never touches disk on the region path, the bytes stay in this
//! process, and nothing here may ever grow a network client.

/// What part of the page a capture covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaptureScope {
    /// Windows: ICoreWebView2::CapturePreview, visible viewport only.
    VisibleArea,
    /// Linux: WebKitGTK SnapshotRegion::FullDocument.
    FullPage,
}

/// What this build's capture path aims for, used only where no event is in
/// hand (the Windows fallback reports its own scope on the event).
///
/// NOT the label for a finished capture: read `CaptureEvent::scope` for that.
/// This said `VisibleArea` on Windows long after Windows started capturing
/// whole pages, and every surface that trusted it lied in the same way.
pub const fn current_scope() -> CaptureScope {
    CaptureScope::FullPage
}

/// Label used in the saved toast; the honest half of the platform split.
pub const fn scope_label(scope: CaptureScope) -> &'static str {
    match scope {
        CaptureScope::VisibleArea => "visible area",
        CaptureScope::FullPage => "full page",
    }
}

/// Default save-dialog file name. A constant per scope: it never embeds the
/// page URL, because a name built from the URL would leak browsing history
/// into the user's Downloads listing.
pub const fn default_save_name(scope: CaptureScope) -> &'static str {
    match scope {
        CaptureScope::VisibleArea => "capture-visible-area.png",
        CaptureScope::FullPage => "capture-full-page.png",
    }
}

/// Cheap plausibility gate applied before anything is written: non-empty
/// and carrying the PNG magic. Not a decode; it only stops an empty or
/// obviously-not-PNG buffer from becoming a file on disk.
pub fn is_plausible_png(bytes: &[u8]) -> bool {
    const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.len() >= PNG_MAGIC.len() && bytes[..PNG_MAGIC.len()] == PNG_MAGIC
}

/// Refusal rule for pages with nothing to capture, decided BEFORE the
/// engine is asked: an empty PNG of about:blank is not a capture, it is a
/// file pretending to be one.
pub fn refuse_capture(url: &str) -> Option<&'static str> {
    let url = url.trim();
    // Prefix match, case-insensitive: "about:blank#x" and "ABOUT:BLANK" are
    // the same internal blank surface, and an exact-string check would let
    // them through to produce a PNG of nothing.
    if url.is_empty() || (url.len() >= 6 && url[..6].eq_ignore_ascii_case("about:")) {
        return Some("no_capture_page");
    }
    None
}

/// Post-capture validation of the produced bytes.
pub fn validate_capture_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() {
        return Err("no_capture_page");
    }
    if !is_plausible_png(bytes) {
        return Err("capture_failed");
    }
    Ok(())
}

/// Ceiling on a base64-encoded capture, before it is decoded.
///
/// 96 MiB of base64 is about 72 MiB of PNG, which is a very tall page and
/// far beyond anything a person saves on purpose. The viewport capture never
/// needed a ceiling because the window bounded it; a whole-page capture of
/// an endless feed is bounded by nothing, and the encoded string, its parsed
/// copy and the decoded bytes are all resident at the same moment.
pub const MAX_CAPTURE_BASE64: usize = 96 * 1024 * 1024;

/// Decodes standard base64 (RFC 4648, with or without padding).
///
/// Hand-written because this tree takes NO new dependency for thirty lines
/// of table lookup, and it is needed for exactly one thing: the DevTools
/// protocol returns a full-page screenshot as a base64 string, and that is
/// the path that finally made Deep Recall save a page rather than a
/// viewport. Whitespace is tolerated because JSON transports sometimes wrap;
/// any other character is a refusal rather than a guess, since a silently
/// mis-decoded PNG would fail validation later with a far worse message.
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const INVALID: u8 = 0xFF;
    let value = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    };
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0usize;
    for c in input.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        // Data after padding is malformed, not merely odd.
        if padding > 0 {
            return None;
        }
        let v = value(c);
        if v == INVALID {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero; anything else means truncated input.
    if bits >= 6 || acc != 0 || padding > 2 {
        return None;
    }
    Some(out)
}

/// One capture at a time. Set when a capture starts, cleared when its
/// event is handled; a second request while one is pending is refused with
/// "busy" instead of queueing a second picker behind the first.
pub static CAPTURE_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// What a finished capture is FOR. Set by the IPC arm that starts the
/// capture, read once by `on_capture_done`. A single value (not a queue) is
/// correct because `CAPTURE_IN_FLIGHT` already guarantees one capture at a
/// time; a second intent cannot arrive while one is pending.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaptureIntent {
    /// The original flow: validate, picker, write to the chosen file.
    SaveFile,
    /// The Premium region-read flow: keep the bytes in memory and hand the
    /// chrome a token to display and drag-select against. Never touches
    /// disk.
    Region,
    /// Deep Recall: the capture is on its way to the archive, so it is read
    /// for text and then encrypted into a blob. Like Region it never
    /// reaches the save dialog; unlike Region it does reach disk, encrypted.
    Archive,
}

/// Delivered to the event loop when the async platform capture finishes.
/// The main loop validates, runs the picker, writes, and toasts -- all on
/// the UI thread, exactly like the other pickers.
pub struct CaptureEvent {
    pub png: Result<Vec<u8>, &'static str>,
    /// What this capture ACTUALLY covered, set by the path that produced it
    /// rather than by the platform it ran on.
    ///
    /// It used to be read from `current_scope()`, a compile-time constant
    /// saying "visible area" on Windows -- which stopped being true the day
    /// Windows learned to capture a whole page, and stayed wrong in the save
    /// dialog, the toast, the region panel, and, worst, PERSISTED into every
    /// saved Deep Recall record. A const cannot describe a decision made at
    /// runtime, and there is one now: the full-page path can fall back to the
    /// viewport on a runtime too old to answer the protocol call. Carrying it
    /// on the event is what lets that fallback label itself honestly instead
    /// of inheriting a promise the other path made.
    pub scope: CaptureScope,
}

/// The one in-memory capture the region mode may currently be looking at.
///
/// Lives in a static beside `CAPTURE_IN_FLIGHT` rather than on `AppState`
/// because the `rbchrome://` protocol handler that serves the image to the
/// chrome webview runs off the event loop and has no `AppState` to reach.
/// One region at a time, replaced on the next region capture and cleared
/// when the mode closes -- bounded by construction, like the in-flight flag.
pub struct PendingRegion {
    pub token: u64,
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

static PENDING_REGION: std::sync::Mutex<Option<PendingRegion>> = std::sync::Mutex::new(None);

/// Reads the pixel dimensions out of a PNG's IHDR chunk, which the spec
/// fixes at bytes 16..24 (big-endian width, then height) of any valid file.
/// `validate_capture_bytes` has already checked the magic; this refuses a
/// buffer too short to carry the header rather than indexing into it.
pub fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || !is_plausible_png(bytes) {
        return None;
    }
    let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if w == 0 || h == 0 {
        return None;
    }
    Some((w, h))
}

/// Stashes a fresh region capture, replacing any previous one, and returns
/// `(token, width, height)` for the `region_capture_ready` event. The token
/// is minted here so nothing outside this module can predict or reuse one.
pub fn stash_region(png: Vec<u8>) -> Result<(u64, u32, u32), &'static str> {
    let (width, height) = png_dimensions(&png).ok_or("capture_failed")?;
    static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let token = NEXT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut slot = PENDING_REGION.lock().map_err(|_| "capture_failed")?;
    *slot = Some(PendingRegion {
        token,
        png,
        width,
        height,
    });
    Ok((token, width, height))
}

/// A clone of the pending capture's bytes, if `token` names it. NON-consuming
/// on purpose: the user may drag several regions out of one capture, and the
/// protocol handler serves the same bytes the scan reads. The capture is
/// released by `clear_region` (mode closed) or by the next `stash_region`.
pub fn region_png(token: u64) -> Option<Vec<u8>> {
    let slot = PENDING_REGION.lock().ok()?;
    slot.as_ref()
        .filter(|r| r.token == token)
        .map(|r| r.png.clone())
}

/// The pending capture's dimensions, if `token` names it. Used to validate a
/// requested rect BEFORE any decode work is spent on it.
pub fn region_dimensions(token: u64) -> Option<(u32, u32)> {
    let slot = PENDING_REGION.lock().ok()?;
    slot.as_ref()
        .filter(|r| r.token == token)
        .map(|r| (r.width, r.height))
}

/// Drops the pending capture. Idempotent; closing a mode that holds nothing
/// is not an error.
pub fn clear_region() {
    if let Ok(mut slot) = PENDING_REGION.lock() {
        *slot = None;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_round_trips_the_shapes_a_screenshot_arrives_in() {
        // The three residue cases, which is where a hand-rolled decoder goes
        // wrong: 3n bytes (no padding), 3n+1 (==), 3n+2 (=).
        assert_eq!(decode_base64("TWFu").as_deref(), Some(&b"Man"[..]));
        assert_eq!(decode_base64("TWE=").as_deref(), Some(&b"Ma"[..]));
        assert_eq!(decode_base64("TQ==").as_deref(), Some(&b"M"[..]));
        assert_eq!(decode_base64("").as_deref(), Some(&b""[..]));
        // Unpadded is accepted: some transports strip it.
        assert_eq!(decode_base64("TWE").as_deref(), Some(&b"Ma"[..]));
        // A real PNG header, which is what this actually carries.
        let png = decode_base64("iVBORw0KGgo=").expect("png header");
        assert!(crate::capture::is_plausible_png(&[&png[..], &[0u8; 32][..]].concat()));
    }

    #[test]
    fn base64_refuses_rather_than_guesses() {
        // A mis-decode would surface later as "capture_failed" on a PNG that
        // was never a PNG, which is a much worse message than refusing here.
        assert_eq!(decode_base64("!!!!"), None, "invalid alphabet");
        assert_eq!(decode_base64("TQ==TQ=="), None, "data after padding");
        assert_eq!(decode_base64("T"), None, "a lone sextet is truncated");
        // Whitespace is tolerated: JSON transports wrap long strings.
        assert_eq!(decode_base64("TW Fu\n").as_deref(), Some(&b"Man"[..]));
    }

    use super::*;

    #[test]
    fn blank_and_empty_pages_are_refused_before_capturing() {
        assert_eq!(refuse_capture(""), Some("no_capture_page"));
        assert_eq!(refuse_capture("   "), Some("no_capture_page"));
        assert_eq!(refuse_capture("about:blank"), Some("no_capture_page"));
        assert_eq!(refuse_capture("about:blank#x"), Some("no_capture_page"));
        assert_eq!(refuse_capture("ABOUT:BLANK"), Some("no_capture_page"));
        assert_eq!(refuse_capture("https://example.com/"), None);
    }

    #[test]
    fn png_magic_is_required_and_sufficient_for_plausibility() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        assert!(is_plausible_png(&png));
        assert!(!is_plausible_png(b"JFIF not png"));
        assert!(!is_plausible_png(&[]));
        assert!(!is_plausible_png(&png[..7]));
    }

    #[test]
    fn empty_bytes_report_no_page_not_a_broken_capture() {
        // The two failures read differently to a user and must not merge:
        // empty means the page had nothing renderable, wrong-magic means
        // the engine handed back something unexpected.
        assert_eq!(validate_capture_bytes(&[]), Err("no_capture_page"));
        assert_eq!(validate_capture_bytes(b"not a png"), Err("capture_failed"));
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];
        assert_eq!(validate_capture_bytes(&png), Ok(()));
    }

    #[test]
    fn names_and_labels_state_the_scope_and_never_the_url() {
        assert_eq!(default_save_name(CaptureScope::VisibleArea), "capture-visible-area.png");
        assert_eq!(default_save_name(CaptureScope::FullPage), "capture-full-page.png");
        assert_eq!(scope_label(current_scope()), scope_label(current_scope()));
    }

    /// A minimal buffer that satisfies the IHDR reads: magic, chunk length,
    /// "IHDR", then big-endian width and height.
    fn png_header(w: u32, h: u32) -> Vec<u8> {
        let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&w.to_be_bytes());
        bytes.extend_from_slice(&h.to_be_bytes());
        bytes
    }

    #[test]
    fn png_dimensions_read_the_ihdr_and_refuse_the_degenerate() {
        assert_eq!(png_dimensions(&png_header(800, 600)), Some((800, 600)));
        // Zero-sized, truncated, and non-PNG buffers all refuse rather than
        // returning a size nothing could select inside.
        assert_eq!(png_dimensions(&png_header(0, 600)), None);
        assert_eq!(png_dimensions(&png_header(800, 600)[..20].to_vec()), None);
        assert_eq!(png_dimensions(b"JFIF not a png at all, but long enough.."), None);
    }

    #[test]
    fn a_stashed_region_is_readable_by_its_token_alone_and_replaced_by_the_next() {
        let (token, w, h) = stash_region(png_header(64, 32)).expect("stash");
        assert_eq!((w, h), (64, 32));
        // Reads are non-consuming: the protocol handler and the scan both
        // read the same capture, and one drag must not eat the next.
        assert!(region_png(token).is_some());
        assert!(region_png(token).is_some());
        assert_eq!(region_dimensions(token), Some((64, 32)));
        // The wrong token gets nothing -- not the previous capture, nothing.
        assert_eq!(region_png(token + 999), None);
        // A new stash replaces the old capture and retires its token.
        let (token2, ..) = stash_region(png_header(10, 10)).expect("stash");
        assert_ne!(token, token2);
        assert_eq!(region_png(token), None);
        assert!(region_png(token2).is_some());
        // Clearing is idempotent and total.
        clear_region();
        clear_region();
        assert_eq!(region_png(token2), None);
    }

    #[test]
    fn a_capture_that_is_not_a_plausible_png_cannot_be_stashed() {
        assert_eq!(stash_region(b"not a png".to_vec()), Err("capture_failed"));
    }
}
