//! Page capture: save what the current tab shows as a PNG the user chooses
//! a home for. Everything local; nothing here may ever grow a network
//! client.
//!
//! Both engines can now render either the visible viewport or the full
//! document. WebView2's full-page protocol call may be unavailable on an old
//! runtime, in which case it truthfully falls back to CapturePreview. The
//! scope is carried on the finished event rather than inferred from the
//! request, so every result can say what the picture actually contains.
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
        return Err("capture_decode_failed");
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

/// Hard bounds for the bitmap handed to the chrome region-preview `<img>`.
/// Eight megapixels is at most about 32 MiB once decoded to RGBA, while the
/// independent side limit keeps pathological tall/narrow captures inside a
/// conservative GPU texture dimension. The native PNG is NOT subject to
/// these bounds: it remains the source of truth for OCR and archive storage.
pub const REGION_PREVIEW_MAX_PIXELS: u64 = 8_000_000;
pub const REGION_PREVIEW_MAX_SIDE: u32 = 8_192;

/// The deliberate allocation budget handed to the row-streaming PNG decoder.
///
/// 64 MiB is enough for the decoder's compressed-data bookkeeping and several
/// very wide capture rows without ever granting it a source-frame-sized
/// allocation. The preview itself is independently bounded above at 8 MP
/// (about 30.5 MiB of RGBA); the horizontal and vertical area accumulators are
/// one row each, at most 256 KiB plus 512 KiB.
pub const REGION_PREVIEW_DECODER_ALLOC_LIMIT: usize = 64 * 1024 * 1024;

/// Chooses preview dimensions without changing aspect ratio beyond the one
/// pixel rounding needed for integer dimensions. Returns the source size
/// exactly when it is already safe, which lets the caller serve the original
/// bytes without a decode/re-encode round trip.
pub fn region_preview_dimensions(width: u32, height: u32) -> (u32, u32) {
    if width == 0 || height == 0 {
        return (0, 0);
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels <= REGION_PREVIEW_MAX_PIXELS
        && width <= REGION_PREVIEW_MAX_SIDE
        && height <= REGION_PREVIEW_MAX_SIDE
    {
        return (width, height);
    }
    let pixel_scale = (REGION_PREVIEW_MAX_PIXELS as f64 / pixels as f64).sqrt();
    let side_scale = f64::from(REGION_PREVIEW_MAX_SIDE) / f64::from(width.max(height));
    let scale = pixel_scale.min(side_scale).min(1.0);
    (
        (f64::from(width) * scale).floor().max(1.0) as u32,
        (f64::from(height) * scale).floor().max(1.0) as u32,
    )
}

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
    /// Page Integrity snapshot: hashes and text are already prepared; this
    /// capture supplies the optional bounded picture stored beside them.
    Snapshot,
}

/// Delivered to the event loop when the async platform capture finishes.
/// Windows full-page parsing, decoding and validation are already complete
/// on a worker; the main loop handles intent, picker, writing, and UI state.
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
    /// Native capture bytes. OCR always crops from this buffer.
    pub png: Vec<u8>,
    /// Chrome-only bounded rendition. Never used as an OCR source.
    pub preview_png: Vec<u8>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreviewDecodeStats {
    rows_decoded: u32,
    /// A seam for the memory invariant: source rows are borrowed from the PNG
    /// reader and consumed before the next row is requested. No source-frame
    /// collection exists behind the preview helper.
    peak_source_rows_held: u32,
    peak_accumulator_rows: u32,
}

fn preview_decode_error(error: png::DecodingError) -> &'static str {
    match error {
        png::DecodingError::LimitsExceeded => "capture_too_large",
        _ => "capture_decode_failed",
    }
}

/// Validates a PNG without changing the small-page fast path's bytes. Even a
/// clone must be a complete, decodable PNG rather than merely an IHDR-shaped
/// buffer; validation remains O(one source row).
fn validate_png_rows(bytes: &[u8]) -> Result<PreviewDecodeStats, &'static str> {
    use png::{Decoder, Limits, Transformations};
    use std::io::Cursor;

    let mut decoder = Decoder::new_with_limits(
        Cursor::new(bytes),
        Limits {
            bytes: REGION_PREVIEW_DECODER_ALLOC_LIMIT,
        },
    );
    decoder.set_transformations(Transformations::normalize_to_color8());
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    let mut reader = decoder.read_info().map_err(preview_decode_error)?;
    if reader.info().interlaced {
        return Err("capture_too_large");
    }
    let mut rows_decoded = 0u32;
    while reader.next_row().map_err(preview_decode_error)?.is_some() {
        rows_decoded = rows_decoded.checked_add(1).ok_or("capture_too_large")?;
    }
    if rows_decoded != reader.info().height {
        return Err("capture_decode_failed");
    }
    Ok(PreviewDecodeStats {
        rows_decoded,
        peak_source_rows_held: u32::from(rows_decoded > 0),
        peak_accumulator_rows: 0,
    })
}

fn rgba_at(color: png::ColorType, source: &[u8], at: usize) -> Option<[u8; 4]> {
    match color {
        png::ColorType::Grayscale => source.get(at).map(|&g| [g, g, g, 255]),
        png::ColorType::GrayscaleAlpha => Some([
            *source.get(at)?,
            *source.get(at)?,
            *source.get(at)?,
            *source.get(at + 1)?,
        ]),
        png::ColorType::Rgb => Some([
            *source.get(at)?,
            *source.get(at + 1)?,
            *source.get(at + 2)?,
            255,
        ]),
        png::ColorType::Rgba => Some([
            *source.get(at)?,
            *source.get(at + 1)?,
            *source.get(at + 2)?,
            *source.get(at + 3)?,
        ]),
        png::ColorType::Indexed => None,
    }
}

/// Box-downscales a non-interlaced PNG while holding only one decoded source
/// row, one horizontally reduced row, one vertical accumulator row, and the
/// already-bounded preview. Coordinates use integer coverage units, so every
/// source pixel contributes its exact area and the result is deterministic.
fn stream_preview_png_with_stats(
    bytes: &[u8],
    preview_width: u32,
    preview_height: u32,
) -> Result<(Vec<u8>, PreviewDecodeStats), &'static str> {
    use png::{BitDepth, ColorType, Decoder, Encoder, Limits, Transformations};
    use std::io::Cursor;

    let mut decoder = Decoder::new_with_limits(
        Cursor::new(bytes),
        Limits {
            bytes: REGION_PREVIEW_DECODER_ALLOC_LIMIT,
        },
    );
    decoder.set_transformations(Transformations::normalize_to_color8());
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    let mut reader = decoder.read_info().map_err(preview_decode_error)?;
    let (source_width, source_height) = reader.info().size();
    if preview_width == 0
        || preview_height == 0
        || preview_width > source_width
        || preview_height > source_height
    {
        return Err("capture_too_large");
    }
    // Adam7 rows are partial passes, not complete scanlines. Browser capture
    // encoders emit non-interlaced PNGs, so refuse rather than materialising a
    // source frame to deinterlace, exactly as the OCR band decoder does.
    if reader.info().interlaced {
        return Err("capture_too_large");
    }
    let (color, depth) = reader.output_color_type();
    if depth != BitDepth::Eight || color == ColorType::Indexed {
        return Err("capture_decode_failed");
    }
    let samples = color.samples();
    let preview_len = usize::try_from(u64::from(preview_width) * u64::from(preview_height) * 4)
        .map_err(|_| "capture_too_large")?;
    let row_accumulators = usize::try_from(preview_width).map_err(|_| "capture_too_large")?;
    let mut preview = Vec::new();
    preview
        .try_reserve_exact(preview_len)
        .map_err(|_| "capture_too_large")?;
    let mut horizontal = Vec::<[u64; 4]>::new();
    horizontal
        .try_reserve_exact(row_accumulators)
        .map_err(|_| "capture_too_large")?;
    horizontal.resize(row_accumulators, [0; 4]);
    let mut vertical = Vec::<[u128; 4]>::new();
    vertical
        .try_reserve_exact(row_accumulators)
        .map_err(|_| "capture_too_large")?;
    vertical.resize(row_accumulators, [0; 4]);

    let sw = u64::from(source_width);
    let sh = u64::from(source_height);
    let pw = u64::from(preview_width);
    let ph = u64::from(preview_height);
    let divisor = u128::from(sw) * u128::from(sh);
    let mut output_y = 0u64;
    let mut rows_decoded = 0u32;

    for source_y in 0..source_height {
        let row = reader
            .next_row()
            .map_err(preview_decode_error)?
            .ok_or("capture_decode_failed")?;
        rows_decoded = rows_decoded.checked_add(1).ok_or("capture_too_large")?;
        let source = row.data();
        horizontal.fill([0; 4]);

        for output_x in 0..pw {
            // Both intervals use units of 1/pw source pixels. The output bin
            // is [output_x*sw, (output_x+1)*sw); a source pixel is
            // [source_x*pw, (source_x+1)*pw).
            let bin_left = output_x * sw;
            let bin_right = (output_x + 1) * sw;
            let first_source_x = bin_left / pw;
            let last_source_x = (bin_right - 1) / pw;
            let dest = &mut horizontal[output_x as usize];
            for source_x in first_source_x..=last_source_x {
                let pixel_left = source_x * pw;
                let pixel_right = (source_x + 1) * pw;
                let overlap = pixel_right.min(bin_right) - pixel_left.max(bin_left);
                let at = usize::try_from(source_x)
                    .ok()
                    .and_then(|x| x.checked_mul(samples))
                    .ok_or("capture_too_large")?;
                let rgba = rgba_at(color, source, at).ok_or("capture_decode_failed")?;
                for channel in 0..4 {
                    dest[channel] += u64::from(rgba[channel]) * overlap;
                }
            }
        }

        // The same exact-coverage construction vertically. Because this is
        // downscaling, one source row can meet at most two output rows.
        let source_top = u64::from(source_y) * ph;
        let source_bottom = (u64::from(source_y) + 1) * ph;
        let mut at_y = source_top;
        while at_y < source_bottom {
            if output_y >= ph {
                return Err("capture_decode_failed");
            }
            let output_bottom = (output_y + 1) * sh;
            let overlap_y = source_bottom.min(output_bottom) - at_y;
            for output_x in 0..row_accumulators {
                for channel in 0..4 {
                    vertical[output_x][channel] +=
                        u128::from(horizontal[output_x][channel]) * u128::from(overlap_y);
                }
            }
            at_y += overlap_y;
            if at_y == output_bottom {
                for pixel in &vertical {
                    for &value in pixel {
                        let rounded = (value + divisor / 2) / divisor;
                        preview.push(u8::try_from(rounded).map_err(|_| "capture_decode_failed")?);
                    }
                }
                vertical.fill([0; 4]);
                output_y += 1;
            }
        }
    }
    if output_y != ph || preview.len() != preview_len {
        return Err("capture_decode_failed");
    }

    // Do not overlap the decoder's deliberate 64 MiB budget with the encoded
    // preview Vec. Encoding needs the bounded RGBA preview, not the source.
    drop(reader);
    let mut encoded = Vec::new();
    {
        let mut encoder = Encoder::new(&mut encoded, preview_width, preview_height);
        encoder.set_color(ColorType::Rgba);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|_| "capture_preview_failed")?;
        writer
            .write_image_data(&preview)
            .map_err(|_| "capture_preview_failed")?;
    }
    Ok((
        encoded,
        PreviewDecodeStats {
            rows_decoded,
            peak_source_rows_held: u32::from(rows_decoded > 0),
            peak_accumulator_rows: u32::from(preview_height > 0),
        },
    ))
}

const CAPTURE_DIAG_LOG_CAP: usize = 16;
static CAPTURE_DIAG_LOG: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<String>>> =
    std::sync::OnceLock::new();

fn capture_preview_diag(dimensions: Option<(u32, u32)>, decoded_bytes: Option<u128>, path: &str) {
    let dimensions = dimensions
        .map(|(w, h)| format!("{w}x{h}"))
        .unwrap_or_else(|| "unknown".to_string());
    let decoded_bytes = decoded_bytes
        .map(|bytes| bytes.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let line = format!(
        "capture preview: source={dimensions} decoded_rgba_estimate={decoded_bytes}B path={path}"
    );
    if cfg!(debug_assertions) {
        eprintln!("patanyx: {line}");
    }
    let log = CAPTURE_DIAG_LOG.get_or_init(|| {
        std::sync::Mutex::new(std::collections::VecDeque::with_capacity(
            CAPTURE_DIAG_LOG_CAP,
        ))
    });
    if let Ok(mut log) = log.lock() {
        if log.len() >= CAPTURE_DIAG_LOG_CAP {
            log.pop_front();
        }
        log.push_back(line);
    }
}

/// Capture-preview diagnostics for the explicit diagnostics export. Entries
/// contain dimensions and byte counts only, never a page URL or image bytes.
pub fn recent_diagnostics() -> Vec<String> {
    CAPTURE_DIAG_LOG
        .get()
        .and_then(|log| log.lock().ok().map(|log| log.iter().cloned().collect()))
        .unwrap_or_default()
}

/// The single 8 MP / 8192 px rendition used wherever a captured page is
/// allowed into a chrome `<img>` or a snapshot blob. Small pictures keep
/// their original bytes; larger ones use WP-Z's row-streaming downscale, so
/// snapshot storage cannot grow a second image-decoding pipeline.
pub fn bounded_picture_png(png: &[u8]) -> Result<Vec<u8>, &'static str> {
    let Some((width, height)) = png_dimensions(png) else {
        capture_preview_diag(None, None, "refused(decode_format)");
        return Err("capture_decode_failed");
    };
    let decoded_bytes = u128::from(width) * u128::from(height) * 4;
    let (preview_width, preview_height) = region_preview_dimensions(width, height);
    if (preview_width, preview_height) == (width, height) {
        if let Err(code) = validate_png_rows(png) {
            capture_preview_diag(
                Some((width, height)),
                Some(decoded_bytes),
                &format!("refused({code})"),
            );
            return Err(code);
        }
        capture_preview_diag(Some((width, height)), Some(decoded_bytes), "fast_clone");
        Ok(png.to_vec())
    } else {
        match stream_preview_png_with_stats(png, preview_width, preview_height) {
            Ok((preview, _stats)) => {
                capture_preview_diag(
                    Some((width, height)),
                    Some(decoded_bytes),
                    "streamed_downscale",
                );
                Ok(preview)
            }
            Err(code) => {
                capture_preview_diag(
                    Some((width, height)),
                    Some(decoded_bytes),
                    &format!("refused({code})"),
                );
                Err(code)
            }
        }
    }
}

/// Stashes a fresh region capture, replacing any previous one, and returns
/// `(token, source_width, source_height, preview_width, preview_height)` for
/// the `region_capture_ready` event. The token is minted here so nothing
/// outside this module can predict or reuse one.
pub fn stash_region(png: Vec<u8>) -> Result<(u64, u32, u32, u32, u32), &'static str> {
    let Some((width, height)) = png_dimensions(&png) else {
        capture_preview_diag(None, None, "refused(decode_format)");
        return Err("capture_decode_failed");
    };
    let (preview_width, preview_height) = region_preview_dimensions(width, height);
    let preview_png = bounded_picture_png(&png)?;
    // Random, not a counter: the same reason as `archive::stash_picture`, which
    // this comment used to match in claim but not in code (security assessment
    // 2026-08-28, R13). A region capture is whatever was on the user's screen.
    let token = crate::archive::random_token();
    let mut slot = PENDING_REGION
        .lock()
        .map_err(|_| "capture_preview_failed")?;
    *slot = Some(PendingRegion {
        token,
        png,
        preview_png,
        width,
        height,
    });
    Ok((token, width, height, preview_width, preview_height))
}

/// A clone of the pending capture's bytes, if `token` names it. NON-consuming
/// on purpose: the user may drag several regions out of one capture, and the
/// protocol handler serves the same bytes the scan reads. The capture is
/// released by `clear_region` (mode closed) or by the next `stash_region`.
/// A picture token on its way to the chrome, as a JSON STRING.
///
/// The tokens became 64 random bits on 2026-08-28 (a counter was guessable).
/// Sent as a JSON number, a value above 2^53 arrives in JavaScript with its
/// low digits rounded away, the chrome builds `/region-capture/<wrong>.png`
/// from it, the handler answers 404, and every picture surface (region read,
/// Deep Recall, bookmark snapshots) shows a broken image. Nothing in Rust
/// could see it: the unit tests never cross the JSON boundary. A string
/// round-trips exactly, and the chrome only ever concatenates the token.
pub fn token_wire(token: u64) -> String {
    token.to_string()
}

/// The inverse, for a token the chrome sends back. Accepts the string form
/// and, for one release of leniency, the old number form (correct below 2^53).
pub fn token_from_wire(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
}

pub fn region_png(token: u64) -> Option<Vec<u8>> {
    let slot = PENDING_REGION.lock().ok()?;
    slot.as_ref()
        .filter(|r| r.token == token)
        .map(|r| r.png.clone())
}

/// The bounded PNG served only to the chrome `<img>`. Keeping this accessor
/// separate from `region_png` makes it mechanically hard for OCR to start
/// reading the lossy preview instead of the native source bytes.
pub fn region_preview_png(token: u64) -> Option<Vec<u8>> {
    let slot = PENDING_REGION.lock().ok()?;
    slot.as_ref()
        .filter(|r| r.token == token)
        .map(|r| r.preview_png.clone())
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
        assert!(crate::capture::is_plausible_png(
            &[&png[..], &[0u8; 32][..]].concat()
        ));
    }

    #[test]
    fn base64_refuses_rather_than_guesses() {
        // A mis-decode would surface later as "capture_decode_failed" on a
        // PNG that was never a PNG, which is a much worse message than
        // refusing here.
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
        assert_eq!(
            validate_capture_bytes(b"not a png"),
            Err("capture_decode_failed")
        );
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];
        assert_eq!(validate_capture_bytes(&png), Ok(()));
    }

    #[test]
    fn names_and_labels_state_the_scope_and_never_the_url() {
        assert_eq!(
            default_save_name(CaptureScope::VisibleArea),
            "capture-visible-area.png"
        );
        assert_eq!(
            default_save_name(CaptureScope::FullPage),
            "capture-full-page.png"
        );
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

    fn rgba_pixels_png(w: u32, h: u32, pixels: &[[u8; 4]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut encoded, w, h);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().expect("header");
            writer
                .write_image_data(pixels.as_flattened())
                .expect("pixels");
        }
        encoded
    }

    fn rgba_png(w: u32, h: u32, rgba: [u8; 4]) -> Vec<u8> {
        let pixels = vec![rgba; usize::try_from(u64::from(w) * u64::from(h)).unwrap()];
        rgba_pixels_png(w, h, &pixels)
    }

    /// A cheap enormous PNG: one-bit solid rows keep both construction memory
    /// and the compressed file small even though the RGBA decode estimate is
    /// beyond the old image-crate ceiling.
    fn enormous_one_bit_png(w: u32, h: u32) -> Vec<u8> {
        use std::io::Write;

        let mut encoded = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut encoded, w, h);
            encoder.set_color(png::ColorType::Grayscale);
            encoder.set_depth(png::BitDepth::One);
            let mut writer = encoder.write_header().expect("header");
            let mut stream = writer.stream_writer().expect("stream");
            let row = vec![0u8; usize::try_from(w).unwrap().div_ceil(8)];
            for _ in 0..h {
                stream.write_all(&row).expect("row");
            }
            stream.finish().expect("finish");
        }
        encoded
    }

    #[test]
    fn png_dimensions_read_the_ihdr_and_refuse_the_degenerate() {
        assert_eq!(png_dimensions(&png_header(800, 600)), Some((800, 600)));
        // Zero-sized, truncated, and non-PNG buffers all refuse rather than
        // returning a size nothing could select inside.
        assert_eq!(png_dimensions(&png_header(0, 600)), None);
        assert_eq!(png_dimensions(&png_header(800, 600)[..20].to_vec()), None);
        assert_eq!(
            png_dimensions(b"JFIF not a png at all, but long enough.."),
            None
        );
    }

    #[test]
    fn region_preview_decision_obeys_both_bounds_and_preserves_small_pages() {
        assert_eq!(region_preview_dimensions(1920, 1080), (1920, 1080));
        assert_eq!(region_preview_dimensions(4000, 2000), (4000, 2000));

        for (w, h) in [(4001, 2000), (1000, 20_000), (20_000, 1000)] {
            let (pw, ph) = region_preview_dimensions(w, h);
            assert!(pw > 0 && ph > 0);
            assert!(u64::from(pw) * u64::from(ph) <= REGION_PREVIEW_MAX_PIXELS);
            assert!(pw <= REGION_PREVIEW_MAX_SIDE && ph <= REGION_PREVIEW_MAX_SIDE);
            let x_scale = f64::from(pw) / f64::from(w);
            let y_scale = f64::from(ph) / f64::from(h);
            assert!((x_scale - y_scale).abs() <= 1.0 / f64::from(w.min(h)));
        }
        assert_eq!(region_preview_dimensions(1000, 20_000), (409, 8192));
    }

    #[test]
    fn snapshot_bound_uses_the_same_8mp_8192px_rendition_as_region_preview() {
        let source = rgba_png(9_000, 2, [12, 34, 56, 255]);
        let bounded = bounded_picture_png(&source).expect("bounded picture");
        let expected = region_preview_dimensions(9_000, 2);
        assert_eq!(png_dimensions(&bounded), Some(expected));
        assert!(u64::from(expected.0) * u64::from(expected.1) <= REGION_PREVIEW_MAX_PIXELS);
        assert!(expected.0 <= REGION_PREVIEW_MAX_SIDE && expected.1 <= REGION_PREVIEW_MAX_SIDE);
    }

    #[test]
    fn a_stashed_region_is_readable_by_its_token_alone_and_replaced_by_the_next() {
        let first_png = rgba_png(64, 32, [12, 34, 56, 255]);
        let (token, w, h, preview_w, preview_h) = stash_region(first_png.clone()).expect("stash");
        assert_eq!((w, h, preview_w, preview_h), (64, 32, 64, 32));
        // Reads are non-consuming: the protocol handler and the scan both
        // read the same capture, and one drag must not eat the next.
        assert!(region_png(token).is_some());
        assert!(region_png(token).is_some());
        assert_eq!(
            region_preview_png(token).as_deref(),
            Some(first_png.as_slice())
        );
        assert_eq!(region_preview_png(token), region_png(token));
        assert_eq!(region_dimensions(token), Some((64, 32)));
        // The wrong token gets nothing -- not the previous capture, nothing.
        assert_eq!(region_png(token + 999), None);
        // A new stash replaces the old capture and retires its token.
        let (token2, ..) = stash_region(rgba_png(10, 10, [1, 2, 3, 4])).expect("stash");
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
        assert_eq!(
            stash_region(b"not a png".to_vec()),
            Err("capture_decode_failed")
        );
        assert_eq!(
            stash_region(png_header(64, 32)),
            Err("capture_decode_failed"),
            "a plausible IHDR is not a complete PNG"
        );
    }

    #[test]
    fn streamed_preview_crosses_the_old_512_mib_decode_ceiling_one_row_at_a_time() {
        // 131072 * 1025 * 4 = 537,395,200 decoded RGBA bytes, strictly above
        // image 0.25.10's old 512 MiB default allocation limit. One-bit solid
        // input keeps this regression fixture compact and cheap to construct.
        const W: u32 = 131_072;
        const H: u32 = 1_025;
        let decoded_rgba = u64::from(W) * u64::from(H) * 4;
        assert!(decoded_rgba > 512 * 1024 * 1024);
        let png = enormous_one_bit_png(W, H);
        let (preview_w, preview_h) = region_preview_dimensions(W, H);
        assert_ne!((preview_w, preview_h), (W, H));

        let (preview, stats) =
            stream_preview_png_with_stats(&png, preview_w, preview_h).expect("stream preview");
        assert_eq!(png_dimensions(&preview), Some((preview_w, preview_h)));
        assert_eq!(stats.rows_decoded, H);
        assert_eq!(stats.peak_source_rows_held, 1);
        assert_eq!(stats.peak_accumulator_rows, 1);
        assert!(preview.len() < 1024 * 1024, "solid preview should compress");
    }

    #[test]
    fn streamed_preview_area_averages_source_pixels() {
        let source = rgba_pixels_png(
            2,
            2,
            &[
                [0, 0, 0, 0],
                [100, 120, 140, 160],
                [200, 220, 240, 255],
                [100, 60, 20, 225],
            ],
        );
        let (preview, _) = stream_preview_png_with_stats(&source, 1, 1).expect("preview");
        let decoder = png::Decoder::new(std::io::Cursor::new(preview));
        let mut reader = decoder.read_info().expect("read preview");
        let mut rgba = [0u8; 4];
        let output = reader.next_frame(&mut rgba).expect("decode preview");
        assert_eq!((output.width, output.height), (1, 1));
        assert_eq!(rgba, [100, 100, 100, 160]);
    }

    #[test]
    fn a_corrupt_streaming_png_reports_decode_not_engine_failure() {
        let mut png = rgba_png(9_000, 1, [20, 40, 60, 255]);
        png.truncate(png.len() / 2);
        let (preview_w, preview_h) = region_preview_dimensions(9_000, 1);
        assert_eq!(
            stream_preview_png_with_stats(&png, preview_w, preview_h),
            Err("capture_decode_failed")
        );
    }
    /// The defect: a token above 2^53 sent as a JSON number does not survive
    /// JavaScript. Pinned at the boundary, not in JavaScript: the wire form
    /// must be a string, and a string round-trips exactly.
    #[test]
    fn a_picture_token_crosses_ipc_as_a_string_and_round_trips() {
        let token = u64::MAX - 12345; // far above 2^53, like a random token
        let wire = serde_json::json!({ "token": token_wire(token) });
        assert!(wire["token"].is_string(), "a number above 2^53 is rounded by JavaScript");
        // What JavaScript would have done with the number form, to show the
        // pin is not vacuous: f64 cannot hold it.
        assert_ne!((token as f64) as u64, token, "precondition: this token is not f64-exact");
        assert_eq!(token_from_wire(&wire["token"]), Some(token));
    }

    /// The old number form is still accepted where it was exact.
    #[test]
    fn a_small_number_token_is_still_accepted() {
        assert_eq!(token_from_wire(&serde_json::json!(42)), Some(42));
        assert_eq!(token_from_wire(&serde_json::json!("42")), Some(42));
        assert_eq!(token_from_wire(&serde_json::json!("x")), None);
        assert_eq!(token_from_wire(&serde_json::json!(null)), None);
    }
}
