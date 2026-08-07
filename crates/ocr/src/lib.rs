//! Local OCR engine: PP-OCR detection + recognition running on tract.
//!
//! Everything in this crate runs offline. There is no network client here and
//! none may be added: the product's market position is that user data does
//! not leave the machine.

pub mod color;
pub mod leaks;
pub mod recovery;

use std::path::Path;

use image::imageops::FilterType;
use image::RgbImage;
use tract_onnx::prelude::*;

pub const DET_MODEL_FILE: &str = "det.onnx";
pub const REC_MODEL_FILE: &str = "rec.onnx";
pub const REC_DICT_FILE: &str = "rec_dict.txt";

// Note: tract's public types move a little between releases. This alias
// (and the `tvec!`/`to_array_view` call sites below) is written against 0.21;
// if the project pins another version, these are the lines to adjust first.
type TypedModel = Graph<TypedFact, Box<dyn TypedOp>>;
type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, TypedModel>;

/// The ONE det input size. Every image is scaled to fit and letterboxed onto
/// a square canvas of this side.
///
/// Fixed rather than per-image, and this is forced by the runtime rather than
/// chosen for tidiness. Measured 2026-07-27 against the converted graph:
/// tract CANNOT optimize det with symbolic H/W (it fails analysing a `Concat`),
/// but succeeds at any concrete shape. So a size must be pinned at load time,
/// and re-planning per image would mean re-running `into_optimized()` for every
/// call -- seconds of work to save milliseconds.
///
/// 960 because PP-OCR det is trained around it; larger photos only cost CPU,
/// they do not add readable text. Divisible by 32, as the head requires.
const DET_SIDE: u32 = 960;
/// Binarization threshold on the shrink map. 0.3 matches upstream defaults.
const DET_THRESHOLD: f32 = 0.3;
/// Below this many foreground pixels a component is noise, not a text line.
const MIN_COMPONENT_PX: usize = 8;
/// Hard cap on recognized boxes per image so a pathological mask cannot
/// turn one IPC call into minutes of recognition work.
const MAX_BOXES: usize = 200;
/// Rec input is FIXED at 48x320. The height is fixed by the architecture; the
/// width is fixed by the conversion.
///
/// Measured: the simplified rec graph runs at 48x320 and FAILS at 48x640
/// ("Failed analyse for node Conv.0"). `onnxsim` folded the dynamic-width
/// subgraph against 320, so that width is baked into the weights-level graph
/// and is not a parameter any more. Every crop is therefore scaled to fit and
/// right-padded to exactly this width, which is what PP-OCR's own batched
/// inference does anyway.
const REC_HEIGHT: u32 = 48;
const REC_WIDTH: u32 = 320;
/// Decode-time bomb guard: a small compressed file can decode to gigabytes.
const MAX_PIXELS: u64 = 40_000_000;

// Note: PP-OCR's reference inference feeds OpenCV BGR order with
// ImageNet stats for det and symmetric normalization for rec. If the ONNX
// conversion inserted a channel swap, flip this one const rather than editing
// both preprocessing loops.
const MODEL_EXPECTS_BGR: bool = true;
const DET_MEAN: [f32; 3] = [0.485, 0.456, 0.406];
const DET_STD: [f32; 3] = [0.229, 0.224, 0.225];

#[derive(Debug)]
pub enum OcrError {
    /// A required model file is absent; carries the missing path for logs.
    ModelsMissing(String),
    /// Files exist but do not load, or the dict does not match the model.
    ModelsInvalid(String),
    /// Input bytes are not a decodable image, or exceed the pixel cap.
    ImageDecode,
    /// Model ran but failed or returned an unexpected shape.
    Inference(String),
}

/// Written for a DEVELOPER reading a diagnostic line, not for a user. The
/// user-facing wording lives in the chrome's error table, keyed by the short
/// code the IPC layer maps these to -- an inference shape mismatch is not
/// something to put in front of someone who picked a photo.
impl std::fmt::Display for OcrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModelsMissing(p) => write!(f, "OCR model file missing: {p}"),
            Self::ModelsInvalid(d) => write!(f, "OCR models unusable: {d}"),
            Self::ImageDecode => write!(f, "not a decodable image, or too large"),
            Self::Inference(d) => write!(f, "OCR inference failed: {d}"),
        }
    }
}

impl std::error::Error for OcrError {}

#[derive(Debug, Clone)]
pub struct TextRegion {
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    /// Stroke colour against the colour behind it, measured while the decoded
    /// page is still in hand. `None` when the crop was degenerate.
    ///
    /// Carried on the region rather than returned alongside it because it is a
    /// property OF the region, and because the alternative -- a parallel vector
    /// the caller has to keep in step -- is the kind of thing that silently
    /// goes out of alignment the first time someone filters one and not the
    /// other.
    pub color: Option<color::RegionColor>,
}

pub struct OcrEngine {
    det: Plan,
    rec: Plan,
    /// CTC class k maps to dict[k - 1]; class 0 is the blank.
    dict: Vec<String>,
}

/// The weights, COMPILED IN.
///
/// They used to be loaded from `models/ocr/` beside the executable, and
/// nothing ever put them there: the published downloads are a single binary
/// and the updater swaps a single binary, so every install that has ever
/// existed had the OCR code and no weights. `available()` correctly reported
/// unavailable and the panel correctly hid itself, forever. A feature that
/// hides itself is indistinguishable from one that was never written.
///
/// Embedding costs ~10 MB on a binary that was already 32 MB, and buys the
/// property that shipping the browser IS shipping the feature. It matches how
/// the malicious-host list already works, and keeps the update channel's "one
/// signed executable" shape intact rather than growing a second artifact that
/// would need its own signing, its own verification and its own failure modes.
const DET_MODEL_BYTES: &[u8] = include_bytes!("../../../models/ocr/det.onnx");
const REC_MODEL_BYTES: &[u8] = include_bytes!("../../../models/ocr/rec.onnx");
const REC_DICT_BYTES: &str = include_str!("../../../models/ocr/rec_dict.txt");

impl OcrEngine {
    /// Loads the compiled-in models. This is the production path.
    ///
    /// Cannot fail for want of files, which is the whole point. It can still
    /// fail if the embedded graphs do not optimise, and that is a build
    /// defect rather than a user's problem -- covered by a test that loads
    /// them.
    pub fn load_embedded() -> Result<Self, OcrError> {
        let dict = parse_dict(REC_DICT_BYTES);
        if dict.is_empty() {
            return Err(OcrError::ModelsInvalid("embedded dict is empty".into()));
        }
        let det = load_onnx_bytes(
            DET_MODEL_BYTES,
            f32::fact([1, 3, DET_SIDE as i32, DET_SIDE as i32]).into(),
        )
        .map_err(|e| OcrError::ModelsInvalid(format!("embedded det: {e}")))?;
        let rec = load_onnx_bytes(
            REC_MODEL_BYTES,
            f32::fact([1, 3, REC_HEIGHT as i32, REC_WIDTH as i32]).into(),
        )
        .map_err(|e| OcrError::ModelsInvalid(format!("embedded rec: {e}")))?;
        Ok(Self { det, rec, dict })
    }

    /// Loads models from `dir`. Missing files are a distinct error so the
    /// caller can degrade to "unavailable" instead of failing startup.
    ///
    /// Retained for the `PATANYX_OCR_MODEL_DIR` override, which is how a
    /// different set of weights gets tested without a rebuild. Not the
    /// production path any more.
    pub fn load(dir: &Path) -> Result<Self, OcrError> {
        let det_path = dir.join(DET_MODEL_FILE);
        let rec_path = dir.join(REC_MODEL_FILE);
        let dict_path = dir.join(REC_DICT_FILE);
        for p in [&det_path, &rec_path, &dict_path] {
            if !p.is_file() {
                return Err(OcrError::ModelsMissing(p.display().to_string()));
            }
        }
        let dict_src = std::fs::read_to_string(&dict_path)
            .map_err(|e| OcrError::ModelsInvalid(format!("dict unreadable: {e}")))?;
        let dict = parse_dict(&dict_src);
        if dict.is_empty() {
            return Err(OcrError::ModelsInvalid("dict is empty".into()));
        }
        // Shapes measured from the converted graphs, not assumed: det is
        // [N,3,H,W] with H and W dynamic, rec is [N,3,48,W] with the height
        // fixed at 48 by the architecture. DET_SIDE is what det is specialised
        // to here; REC_HEIGHT/REC_WIDTH likewise for rec.
        let det = load_onnx(
            &det_path,
            f32::fact([1, 3, DET_SIDE as i32, DET_SIDE as i32]).into(),
        )
        .map_err(|e| OcrError::ModelsInvalid(format!("det: {e}")))?;
        let rec = load_onnx(
            &rec_path,
            f32::fact([1, 3, REC_HEIGHT as i32, REC_WIDTH as i32]).into(),
        )
        .map_err(|e| OcrError::ModelsInvalid(format!("rec: {e}")))?;
        Ok(Self { det, rec, dict })
    }

    /// Recognizes text in an encoded image (PNG/JPEG bytes). Returns regions
    /// in reading order with boxes in original-image pixels.
    pub fn recognize(&self, bytes: &[u8]) -> Result<Vec<TextRegion>, OcrError> {
        let img = decode_image(bytes)?;
        let boxes = self.detect(&img)?;
        let mut regions = Vec::new();
        for (x, y, w, h) in boxes.into_iter().take(MAX_BOXES) {
            if w < 2 || h < 2 {
                continue;
            }
            let crop = image::imageops::crop_imm(&img, x, y, w, h).to_image();
            let text = self.recognize_line(&crop)?;
            if !text.trim().is_empty() {
                // Measured here, on the page that is already decoded and in
                // scope. Doing it later would mean handing the caller the bytes
                // and decoding a second time.
                let color = color::region_color(&img, x, y, w, h);
                regions.push(TextRegion {
                    text,
                    x,
                    y,
                    w,
                    h,
                    color,
                });
            }
        }
        Ok(regions)
    }

    fn detect(&self, img: &RgbImage) -> Result<Vec<(u32, u32, u32, u32)>, OcrError> {
        let (ow, oh) = img.dimensions();
        // One scale for both axes, so aspect ratio is preserved and mapping a
        // detection back to source coordinates is a single division. Never
        // upscales: a small image sits in the corner of the canvas rather than
        // being stretched into blur the detector then reads as texture.
        let scale = det_scale(ow, oh);
        let sw = ((ow as f64 * scale).round() as u32).clamp(1, DET_SIDE);
        let sh = ((oh as f64 * scale).round() as u32).clamp(1, DET_SIDE);
        let resized = image::imageops::resize(img, sw, sh, FilterType::Triangle);

        // CHW float input, normalized exactly as PP-OCR det training does.
        //
        // The canvas is DET_SIDE square and the image is pasted at the origin;
        // the remainder stays at the normalized value of black. Padding cannot
        // invent a detection -- it is uniform, so the shrink map is flat there
        // -- and any box that did land in it is clipped away by the source
        // bounds when mapped back.
        let side = DET_SIDE as usize;
        let mut data = vec![0f32; 3 * side * side];
        for c in 0..3usize {
            let pad = (0.0 - DET_MEAN[c]) / DET_STD[c];
            data[c * side * side..(c + 1) * side * side].fill(pad);
        }
        for (x, y, px) in resized.enumerate_pixels() {
            for c in 0..3usize {
                let ch = if MODEL_EXPECTS_BGR { 2 - c } else { c };
                let v = px[ch] as f32 / 255.0;
                data[c * side * side + y as usize * side + x as usize] =
                    (v - DET_MEAN[c]) / DET_STD[c];
            }
        }
        let input = Tensor::from_shape(&[1, 3, side, side], &data)
            .map_err(|e| OcrError::Inference(e.to_string()))?;
        let outputs = self
            .det
            .run(tvec!(input.into()))
            .map_err(|e| OcrError::Inference(e.to_string()))?;

        // Output 0 IS the probability map: the converted graph has exactly one
        // output and it is named `sigmoid_0.tmp_0`. Verified 2026-07-27 by
        // inspecting the ONNX rather than assumed from the architecture.
        let view = outputs[0]
            .to_array_view::<f32>()
            .map_err(|e| OcrError::Inference(e.to_string()))?;
        let shape = view.shape().to_vec();
        if shape.len() < 2 {
            return Err(OcrError::Inference(format!("det output shape {shape:?}")));
        }
        let (mh, mw) = (shape[shape.len() - 2], shape[shape.len() - 1]);
        let mut vals: Vec<f32> = view.iter().copied().collect();
        if vals.len() != mh * mw {
            return Err(OcrError::Inference(format!("det output shape {shape:?}")));
        }

        // The shipped export is POST-sigmoid, so this normally does nothing.
        // Kept anyway, and not as hedging: the model is converted by a recipe
        // outside this repo, and a re-export that drops the final sigmoid would
        // otherwise turn every value into a detection silently. One pass over
        // the map to make that impossible is cheap; a wrong answer is not.
        let looks_like_logits = vals.iter().any(|v| *v < -1e-3 || *v > 1.0 + 1e-3);
        if looks_like_logits {
            for v in vals.iter_mut() {
                *v = 1.0 / (1.0 + (-*v).exp());
            }
        }

        let mask: Vec<bool> = vals.iter().map(|v| *v > DET_THRESHOLD).collect();
        // The map covers the whole padded canvas, so map-space maps to
        // canvas-space by one ratio, and canvas-space back to source by the
        // single `scale`. Boxes that lie entirely in the padding collapse to
        // zero width or height when clipped to the source and are dropped.
        let map_to_canvas = DET_SIDE as f64 / mw.max(1) as f64;
        let mut boxes: Vec<(u32, u32, u32, u32)> = components(&mask, mw, mh)
            .into_iter()
            .map(|b| expand_and_map(b, mw as u32, mh as u32, map_to_canvas, scale, ow, oh))
            .filter(|(_, _, w, h)| *w > 0 && *h > 0)
            .collect();
        // Reading order. Interleaved multi-column layouts are a known
        // limitation; the features here target single-column photos.
        boxes.sort_by_key(|b| (b.1, b.0));
        Ok(boxes)
    }

    fn recognize_line(&self, crop: &RgbImage) -> Result<String, OcrError> {
        let (w, h) = crop.dimensions();
        // Scale to the model's height, then pad to its EXACT width. The width
        // is not negotiable -- the simplified graph is planned for REC_WIDTH
        // and refuses any other -- so a wide crop is squeezed rather than
        // truncated. Truncating would silently drop the tail of a line, which
        // for a recovery key means losing characters with no signal at all;
        // squeezing degrades gracefully and the CTC decoder still reads it.
        let ideal = ((w as f32) * REC_HEIGHT as f32 / h.max(1) as f32).round() as u32;
        let rw = ideal.clamp(8, REC_WIDTH);
        let resized = image::imageops::resize(crop, rw, REC_HEIGHT, FilterType::Triangle);

        let (w_us, h_us) = (REC_WIDTH as usize, REC_HEIGHT as usize);
        // Pad value is the normalized form of mid-grey, i.e. 0.0 after the
        // symmetric (v - 0.5) / 0.5 transform. Padding with normalized BLACK
        // would put a hard edge next to the last glyph and the decoder reads
        // edges as strokes.
        let mut data = vec![0f32; 3 * w_us * h_us];
        for (x, y, px) in resized.enumerate_pixels() {
            for c in 0..3usize {
                let ch = if MODEL_EXPECTS_BGR { 2 - c } else { c };
                let v = px[ch] as f32 / 255.0;
                data[c * w_us * h_us + y as usize * w_us + x as usize] = (v - 0.5) / 0.5;
            }
        }
        let input = Tensor::from_shape(&[1, 3, h_us, w_us], &data)
            .map_err(|e| OcrError::Inference(e.to_string()))?;
        let outputs = self
            .rec
            .run(tvec!(input.into()))
            .map_err(|e| OcrError::Inference(e.to_string()))?;
        let view = outputs[0]
            .to_array_view::<f32>()
            .map_err(|e| OcrError::Inference(e.to_string()))?;
        let shape = view.shape().to_vec();
        if shape.len() != 3 || shape[0] != 1 {
            return Err(OcrError::Inference(format!("rec output shape {shape:?}")));
        }
        let (steps, classes) = (shape[1], shape[2]);
        if classes != self.dict.len() + 1 {
            // Failing loudly here beats silently emitting shifted garbage:
            // a dict/model mismatch would otherwise look like bad OCR.
            return Err(OcrError::ModelsInvalid(format!(
                "rec outputs {classes} classes but dict has {} entries",
                self.dict.len()
            )));
        }

        // Greedy CTC: collapse consecutive repeats, then drop blanks. A blank
        // between two equal symbols must reset the collapse, so prev tracks
        // every step, not just emitted ones.
        let mut text = String::new();
        let mut prev = usize::MAX;
        for t in 0..steps {
            let mut best = 0usize;
            let mut best_v = f32::NEG_INFINITY;
            for c in 0..classes {
                let v = view[[0, t, c]];
                if v > best_v {
                    best_v = v;
                    best = c;
                }
            }
            if best == prev {
                continue;
            }
            prev = best;
            if best == 0 {
                continue;
            }
            text.push_str(&self.dict[best - 1]);
        }
        Ok(text)
    }
}

/// One dict entry per line, verbatim: a line that is a single space is a real
/// entry in PP-OCR dicts, so no trimming. A trailing newline produces one
/// phantom empty entry and exactly one is dropped.
fn parse_dict(src: &str) -> Vec<String> {
    let mut v: Vec<String> = src.lines().map(str::to_string).collect();
    if v.last().map_or(false, |l| l.is_empty()) {
        v.pop();
    }
    v
}

/// Loads one graph, with the input shape pinned by the caller.
///
/// Facts are pinned rather than left symbolic, and that is not a style
/// preference -- it is what the models measured on 2026-07-27 actually need:
///
///   * det keeps dynamic H/W and optimizes fine ONCE a concrete fact is
///     supplied. Left fully symbolic it has nothing to specialise against.
///   * rec only optimizes at a static shape at all. The direct paddle2onnx
///     output fails shape analysis at a `Concat` whose input is rank 0 where
///     rank 1 is required -- and ONNX Runtime rejects that same node, so the
///     model is malformed rather than tract being limited. Running the graph
///     through `onnxsim` folds the dynamic-shape subgraph away and it loads.
///
/// The full recipe is in OCR-MODEL-CONVERSION.md with the private build notes.
fn load_onnx(path: &Path, input: InferenceFact) -> TractResult<Plan> {
    let model = tract_onnx::onnx()
        .model_for_path(path)?
        .with_input_fact(0, input)?;
    Ok(model.into_optimized()?.into_runnable()?)
}

fn load_onnx_bytes(bytes: &[u8], input: InferenceFact) -> TractResult<Plan> {
    let mut cursor = std::io::Cursor::new(bytes);
    let model = tract_onnx::onnx()
        .model_for_read(&mut cursor)?
        .with_input_fact(0, input)?;
    Ok(model.into_optimized()?.into_runnable()?)
}

fn decode_image(bytes: &[u8]) -> Result<RgbImage, OcrError> {
    use std::io::Cursor;
    // Header-only dimension read first, so oversized images are rejected
    // before paying for a full decode.
    let reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| OcrError::ImageDecode)?;
    let (w, h) = reader
        .into_dimensions()
        .map_err(|_| OcrError::ImageDecode)?;
    if w as u64 * h as u64 > MAX_PIXELS {
        return Err(OcrError::ImageDecode);
    }
    image::load_from_memory(bytes)
        .map(|i| i.to_rgb8())
        .map_err(|_| OcrError::ImageDecode)
}

/// Resize target for det: aspect preserved, capped at DET_MAX_SIDE, each side
/// rounded up to a multiple of 32 (the det backbone strides to 32).
/// Scale that fits `w`x`h` inside the square det canvas, never above 1.0.
///
/// Capped at 1.0 on purpose: upscaling a small image to fill the canvas does
/// not add information, it adds interpolation artefacts that the detector reads
/// as texture. A small image is better as a small image in the corner.
fn det_scale(w: u32, h: u32) -> f64 {
    let longest = w.max(h).max(1) as f64;
    (DET_SIDE as f64 / longest).min(1.0)
}

/// 4-connected flood fill over the binary mask. Chosen over contour finding
/// (what OpenCV does upstream) because connected components need no
/// dependency and axis-aligned boxes are sufficient here: the recognizer
/// crops lines, and the leak check only needs boxes to point at.
fn components(mask: &[bool], w: usize, h: usize) -> Vec<(u32, u32, u32, u32)> {
    let mut seen = vec![false; mask.len()];
    let mut out = Vec::new();
    for start in 0..mask.len() {
        if !mask[start] || seen[start] {
            continue;
        }
        let mut stack = vec![start];
        seen[start] = true;
        let (mut x0, mut y0, mut x1, mut y1) = (usize::MAX, usize::MAX, 0usize, 0usize);
        let mut count = 0usize;
        while let Some(i) = stack.pop() {
            let (x, y) = (i % w, i / w);
            count += 1;
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
            let neighbors = [
                (x.wrapping_sub(1), y, x > 0),
                (x + 1, y, x + 1 < w),
                (x, y.wrapping_sub(1), y > 0),
                (x, y + 1, y + 1 < h),
            ];
            for (nx, ny, ok) in neighbors {
                if ok {
                    let ni = ny * w + nx;
                    if mask[ni] && !seen[ni] {
                        seen[ni] = true;
                        stack.push(ni);
                    }
                }
            }
        }
        if count >= MIN_COMPONENT_PX {
            out.push((
                x0 as u32,
                y0 as u32,
                (x1 - x0 + 1) as u32,
                (y1 - y0 + 1) as u32,
            ));
        }
    }
    out
}

/// Expands a mask-space box and maps it to original-image pixels.
///
/// The margin approximates DBNet's Vatti unclip, which grows the shrink-map
/// region to cover full glyph extents. A polygon clipper would track upstream
/// more closely; a fractional margin is the dependency-free stand-in and errs
/// toward wider crops, which the recognizer tolerates far better than clipped
/// strokes. Vertical margin is larger because thresholding eats ascenders and
/// descenders first.
/// Grows a detected box slightly, then maps it from probability-map space back
/// to source-image pixels.
///
/// Two hops, not one: map -> padded canvas by `map_to_canvas`, canvas -> source
/// by dividing out the letterbox `scale`. Both axes use the SAME factors,
/// because the canvas was built with one scale for both.
///
/// The margin exists because DBNet's shrink map is deliberately smaller than
/// the glyphs; recognizing the unexpanded box clips ascenders and descenders.
/// It is proportional, wider vertically than horizontally, because that is
/// where the shrink is worst.
fn expand_and_map(
    b: (u32, u32, u32, u32),
    dw: u32,
    dh: u32,
    map_to_canvas: f64,
    scale: f64,
    ow: u32,
    oh: u32,
) -> (u32, u32, u32, u32) {
    let (x, y, w, h) = b;
    let mx = (w as f32 * 0.10).ceil() as u32 + 1;
    let my = (h as f32 * 0.20).ceil() as u32 + 1;
    let x0 = x.saturating_sub(mx);
    let y0 = y.saturating_sub(my);
    let x1 = (x.saturating_add(w).saturating_add(mx)).min(dw);
    let y1 = (y.saturating_add(h).saturating_add(my)).min(dh);
    // A zero scale would come from a zero-sized source, which decode rejects;
    // guard anyway so this stays total rather than producing infinities.
    let inv = if scale > 0.0 { 1.0 / scale } else { 1.0 };
    let to_src = |v: u32| v as f64 * map_to_canvas * inv;
    let nx0 = (to_src(x0).floor() as u32).min(ow);
    let ny0 = (to_src(y0).floor() as u32).min(oh);
    let nx1 = (to_src(x1).ceil() as u32).min(ow);
    let ny1 = (to_src(y1).ceil() as u32).min(oh);
    (nx0, ny0, nx1.saturating_sub(nx0), ny1.saturating_sub(ny0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dict_keeps_space_entry_and_drops_one_trailing_empty() {
        let d = parse_dict("a\n \nb\n");
        assert_eq!(d, vec!["a".to_string(), " ".to_string(), "b".to_string()]);
        let d2 = parse_dict("a\nb");
        assert_eq!(d2, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn det_scale_fits_the_canvas_and_never_upscales() {
        // A wide photo is reduced until its LONGEST side fits.
        let s = det_scale(4000, 1000);
        assert!((4000.0 * s).round() as u32 <= DET_SIDE);
        assert!((1000.0 * s).round() as u32 <= DET_SIDE);
        // Aspect ratio is preserved: one scale, both axes.
        assert!(((4000.0 * s) / (1000.0 * s) - 4.0).abs() < 1e-9);
        // Smaller than the canvas is left alone. Upscaling would add
        // interpolation artefacts the detector reads as texture.
        assert_eq!(det_scale(100, 50), 1.0);
        assert_eq!(det_scale(DET_SIDE, DET_SIDE), 1.0);
        // Degenerate input must not divide by zero.
        assert!(det_scale(0, 0).is_finite());
    }

    #[test]
    fn components_finds_separate_blobs() {
        // 8x4 mask: two blobs, one of 4 pixels (kept above MIN? no, dropped),
        // one of 12 pixels (kept). Diagonal touching must NOT connect.
        let w = 8;
        let h = 4;
        let mut mask = vec![false; w * h];
        for y in 0..3 {
            for x in 0..4 {
                mask[y * w + x] = true; // 12 px blob at top-left
            }
        }
        mask[3 * w + 7] = true; // single pixel, below MIN_COMPONENT_PX
        let boxes = components(&mask, w, h);
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0], (0, 0, 4, 3));
    }

    #[test]
    fn expand_clamps_to_image_bounds() {
        // Source 200x200 letterboxed onto a 960 canvas at scale 1.0 (no
        // upscale), probability map 100x100 so one map pixel is 9.6 canvas px.
        let m2c = DET_SIDE as f64 / 100.0;
        let b = expand_and_map((0, 0, 10, 10), 100, 100, m2c, 1.0, 200, 200);
        assert_eq!((b.0, b.1), (0, 0));
        assert!(
            b.2 <= 200 && b.3 <= 200,
            "must clip to the source, got {b:?}"
        );
        let corner = expand_and_map((90, 90, 10, 10), 100, 100, m2c, 1.0, 200, 200);
        assert!(corner.0 + corner.2 <= 200);
        assert!(corner.1 + corner.3 <= 200);
    }

    #[test]
    fn expand_and_map_scales_both_axes_by_the_same_factor() {
        // The regression this pins: the draft computed the x edge as
        // `x1 * sy.recip().recip() * sx` -- that is x1 * sy * sx -- so x was
        // mapped through the Y ratio as well and every box drifted
        // horizontally, worse the further from the origin.
        //
        // Both axes must use the SAME factor, here map_to_canvas(8.0) divided
        // by scale(0.5), i.e. 16. Note the margins are deliberately
        // ANISOTROPIC (10% of width, 20% of height), so the two extents are
        // legitimately unequal -- which is exactly why this asserts the mapped
        // COORDINATES rather than comparing width to height.
        let m2c = DET_SIDE as f64 / 120.0; // 8.0
        let b = expand_and_map((10, 10, 20, 20), 120, 120, m2c, 0.5, 4000, 4000);
        // mx = ceil(20*0.10)+1 = 3  ->  x: 7..33   -> *16 -> 112..528
        // my = ceil(20*0.20)+1 = 5  ->  y: 5..35   -> *16 ->  80..560
        assert_eq!(b, (112, 80, 416, 480), "both axes must map through *16");
        // Under the old expression the x edge would have been scaled by an
        // extra factor and nx0 could not have been exactly 7*16.
        assert_eq!(b.0, 7 * 16);
    }

    #[test]
    fn load_reports_missing_models_distinctly() {
        let dir = std::env::temp_dir().join("ocr-definitely-absent-draft-test");
        let _ = std::fs::remove_dir_all(&dir);
        // Matched on the error alone: OcrEngine holds tract plans and is not
        // Debug, so the Ok arm cannot print the engine. It should never be
        // reached anyway -- the directory was just removed.
        match OcrEngine::load(&dir) {
            Err(OcrError::ModelsMissing(p)) => assert!(p.contains("det.onnx")),
            Err(other) => panic!("expected ModelsMissing, got {other:?}"),
            Ok(_) => panic!("loaded an engine from a directory that does not exist"),
        }
    }
}

#[cfg(test)]
mod embedded_tests {
    use super::*;

    /// THE TEST THAT WOULD HAVE CAUGHT IT.
    ///
    /// The OCR feature shipped in every binary for weeks with no weights
    /// anywhere in the distribution. Every unit test passed, because they all
    /// loaded models from a directory that exists in the source tree and never
    /// in an install. Nothing asserted that a SHIPPED binary can OCR anything.
    #[test]
    fn the_embedded_models_are_present_and_load() {
        assert!(
            DET_MODEL_BYTES.len() > 1_000_000,
            "det model is {} bytes -- not the real weights",
            DET_MODEL_BYTES.len()
        );
        assert!(
            REC_MODEL_BYTES.len() > 1_000_000,
            "rec model is {} bytes -- not the real weights",
            REC_MODEL_BYTES.len()
        );
        // Loading is what proves the bytes are a usable graph and not just a
        // file of the right size.
        let engine = OcrEngine::load_embedded().expect("embedded models must load");
        assert!(!engine.dict.is_empty());
    }

    #[test]
    fn the_embedded_dictionary_matches_the_model_classes() {
        // A dictionary of the right LENGTH but the wrong ORDER returns wrong
        // characters silently; a wrong length is caught at load. This asserts
        // the length invariant the loader depends on.
        let dict = parse_dict(REC_DICT_BYTES);
        assert_eq!(
            dict.len(),
            96,
            "rec_dict must hold 96 entries for the 97-class CTC head"
        );
    }
}
