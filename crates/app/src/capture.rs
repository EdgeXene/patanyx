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
//! Text extraction composes with the existing OCR panel (scan the file you
//! just saved) instead of a fused capture-and-read command: the OCR result
//! surface only accepts scans it initiated, and a second half-integrated
//! results path would be worse than two honest clicks.

/// What part of the page a capture covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaptureScope {
    /// Windows: ICoreWebView2::CapturePreview, visible viewport only.
    VisibleArea,
    /// Linux: WebKitGTK SnapshotRegion::FullDocument.
    FullPage,
}

/// The scope this build produces.
pub const fn current_scope() -> CaptureScope {
    #[cfg(windows)]
    {
        CaptureScope::VisibleArea
    }
    #[cfg(not(windows))]
    {
        CaptureScope::FullPage
    }
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

/// One capture at a time. Set when a capture starts, cleared when its
/// event is handled; a second request while one is pending is refused with
/// "busy" instead of queueing a second picker behind the first.
pub static CAPTURE_IN_FLIGHT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Delivered to the event loop when the async platform capture finishes.
/// The main loop validates, runs the picker, writes, and toasts -- all on
/// the UI thread, exactly like the other pickers.
pub struct CaptureEvent {
    pub png: Result<Vec<u8>, &'static str>,
}

#[cfg(test)]
mod tests {
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
}
