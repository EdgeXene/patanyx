//! Local OCR engine: PP-OCR detection + recognition running on tract.
//!
//! Everything in this crate runs offline. There is no network client here and
//! none may be added: the product's market position is that user data does
//! not leave the machine.

#![forbid(unsafe_code)]

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
/// Overlap between detection tiles, in source pixels.
///
/// A line that straddles a seam must appear WHOLE in at least one tile, or be
/// rejoinable from its halves. 96px is comfortably taller than any text line
/// these features meet (page captures at 100% zoom run 14-40px) and wide
/// enough that a short word is never split in both directions at once.
const DET_TILE_OVERLAP: u32 = 96;
/// Cap on the pieces one detected line is split into for recognition. Each
/// piece is a recognizer pass; a line needing more than this is pathological
/// (a whole paragraph detected as one box) and is squeezed as before rather
/// than spending the budget on it.
const MAX_LINE_PARTS: usize = 12;
/// Cap on detection tiles for one image. Each tile is a full detector pass,
/// so this is the CPU bound: 24 passes is a few seconds, not minutes. An
/// image needing more is downscaled until it fits, which is the old
/// whole-image behaviour applied only where it is genuinely unavoidable.
const MAX_DET_TILES: usize = 24;
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
    /// A `recognize_region` rect that is empty or falls outside the image.
    /// Its own class because the image was FINE -- reporting it as a decode
    /// failure would send whoever reads the diagnostic to the wrong code.
    BadRegion,
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
            Self::BadRegion => write!(f, "region rect empty or outside the image"),
            Self::Inference(d) => write!(f, "OCR inference failed: {d}"),
        }
    }
}

impl std::error::Error for OcrError {}

/// Marks a result that stopped at `MAX_BOXES` rather than reaching the end
/// of the page. Callers surface it; nobody parses it for meaning.
pub const TRUNCATED_MARKER: &str = "\u{2026}[more text on this page than could be read]";

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
        self.recognize_pixels(&img)
    }

    /// Recognizes text inside one rectangle of an encoded image, decoding
    /// exactly once: decode, crop in pixel space, run the same pipeline.
    /// Returned boxes are in ORIGINAL-image pixels (offset back by the
    /// rect's corner), so a caller drawing results over the full image needs
    /// no second coordinate space.
    ///
    /// The rect must lie inside the image and be non-empty; a violation is
    /// `BadRegion`, its own error class, because the caller validated user
    /// input against dimensions it holds -- reaching here out of bounds is a
    /// caller bug and must not be reported as a broken image.
    pub fn recognize_region(
        &self,
        bytes: &[u8],
        x: u32,
        y: u32,
        w: u32,
        h: u32,
    ) -> Result<Vec<TextRegion>, OcrError> {
        let img = decode_image(bytes)?;
        let (iw, ih) = img.dimensions();
        let in_bounds = w > 0
            && h > 0
            && x.checked_add(w).is_some_and(|r| r <= iw)
            && y.checked_add(h).is_some_and(|r| r <= ih);
        if !in_bounds {
            return Err(OcrError::BadRegion);
        }
        let crop = image::imageops::crop_imm(&img, x, y, w, h).to_image();
        let mut regions = self.recognize_pixels(&crop)?;
        for r in &mut regions {
            // Saturating because the truncation marker carries y: u32::MAX to
            // sort last, and a plain add would overflow it -- a panic in
            // debug and in tests, a wrapped coordinate in release. The marker
            // has no position worth preserving; every real box is far from
            // the ceiling.
            r.x = r.x.saturating_add(x);
            r.y = r.y.saturating_add(y);
        }
        Ok(regions)
    }

    /// The shared pipeline behind both entry points: detect, then recognize
    /// each detected line, on pixels that are already decoded.
    fn recognize_pixels(&self, img: &RgbImage) -> Result<Vec<TextRegion>, OcrError> {
        let (boxes, gave_up) = self.detect_tiled(img)?;
        // SILENT TRUNCATION IS THE ONE THING THIS MUST NOT DO. The cap keeps
        // a pathological mask from turning one call into minutes of work, and
        // it never bound before -- the whole image was squashed to 960px and
        // yielded a handful of boxes. A full-page capture reaches it easily,
        // and dropping everything past line 200 while reporting a word count
        // as if that were the page is exactly the "read 2 lines" failure in a
        // politer costume. The caller is told; see TextRegion::TRUNCATED.
        // Either way of running out counts: more lines than the cap, or
        // tiles abandoned before the page was even looked at.
        let truncated = boxes.len() > MAX_BOXES || gave_up;
        let mut regions = Vec::new();
        for (x, y, w, h) in boxes.into_iter().take(MAX_BOXES) {
            if w < 2 || h < 2 {
                continue;
            }
            let crop = image::imageops::crop_imm(img, x, y, w, h).to_image();
            let text = self.recognize_line(&crop)?;
            if !text.trim().is_empty() {
                // Measured here, on the page that is already decoded and in
                // scope. Doing it later would mean handing the caller the bytes
                // and decoding a second time.
                let color = color::region_color(img, x, y, w, h);
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
        if truncated {
            // A marker region rather than a new return type: every caller
            // already renders regions, and a caller that ignores this one is
            // no worse off than before. Placed last so reading order holds.
            regions.push(TextRegion {
                text: TRUNCATED_MARKER.to_string(),
                x: 0,
                y: u32::MAX,
                w: 0,
                h: 0,
                color: None,
            });
        }
        Ok(regions)
    }

    /// Detection over the whole image, in tiles that each fit the canvas at
    /// native scale. See `tile_plan` for why the old single-pass squash could
    /// not read a page capture.
    ///
    /// Boxes come back in ORIGINAL-image pixels, matching what `detect`
    /// returned and what `recognize_region` already promises, so nothing
    /// downstream learns a second coordinate space.
    /// Detections plus WHETHER THE TILE LOOP GAVE UP EARLY. The flag is not
    /// decoration: `recognize_pixels` decides truncation from the box count
    /// after merging, and a run that abandoned whole tiles can still come out
    /// of the merge under the cap. That held only by arithmetic -- the break
    /// is at four times the cap and merging rejoins a handful of pairs -- and
    /// a guarantee that depends on a merge rate is not a guarantee. Reported
    /// rather than inferred.
    fn detect_tiled(&self, img: &RgbImage) -> Result<(Vec<(u32, u32, u32, u32)>, bool), OcrError> {
        let (ow, oh) = img.dimensions();
        let (scale, tiles) = tile_plan(ow, oh);

        // One tile at native scale IS the old path; skip the resize and the
        // merge entirely so the common small-image case costs nothing new.
        if scale >= 1.0 && tiles.len() <= 1 {
            return self.detect(img).map(|boxes| (boxes, false));
        }

        // Resized ONCE if the tile budget demanded it, not per tile.
        let source;
        let work: &RgbImage = if scale < 1.0 {
            let sw = ((ow as f64 * scale).round() as u32).max(1);
            let sh = ((oh as f64 * scale).round() as u32).max(1);
            source = image::imageops::resize(img, sw, sh, FilterType::Triangle);
            &source
        } else {
            img
        };

        // The seam positions, in ORIGINAL-image space, so the merge can tell a
        // line the tiling cut from two lines that merely sit close together.
        let inv_scale = if scale > 0.0 { 1.0 / scale } else { 1.0 };
        let mut seams_x: Vec<u32> = Vec::new();
        let mut seams_y: Vec<u32> = Vec::new();
        for (tx, ty, _, _) in &tiles {
            if *tx > 0 {
                seams_x.push(((*tx as f64) * inv_scale).round() as u32);
            }
            if *ty > 0 {
                seams_y.push(((*ty as f64) * inv_scale).round() as u32);
            }
        }
        seams_x.sort_unstable();
        seams_x.dedup();
        seams_y.sort_unstable();
        seams_y.dedup();

        let mut all: Vec<(u32, u32, u32, u32)> = Vec::new();
        let mut gave_up = false;
        for (tx, ty, tw, th) in tiles {
            if tw < 2 || th < 2 {
                continue;
            }
            let tile = image::imageops::crop_imm(work, tx, ty, tw, th).to_image();
            for (bx, by, bw, bh) in self.detect(&tile)? {
                // Tile space -> working space -> original space. The second
                // step is a no-op at scale 1.0, which is the usual case.
                let inv = if scale > 0.0 { 1.0 / scale } else { 1.0 };
                let x = (((bx + tx) as f64) * inv).round() as u32;
                let y = (((by + ty) as f64) * inv).round() as u32;
                let w = ((bw as f64) * inv).round() as u32;
                let h = ((bh as f64) * inv).round() as u32;
                // Clip to the source: a box in a tile's padding can map just
                // outside after rounding.
                let x = x.min(ow.saturating_sub(1));
                let y = y.min(oh.saturating_sub(1));
                let w = w.min(ow - x);
                let h = h.min(oh - y);
                if w > 0 && h > 0 {
                    all.push((x, y, w, h));
                }
            }
            // The cap counts DETECTIONS, not tiles: a pathological mask in an
            // early tile must not buy itself the whole budget of later ones.
            if all.len() > MAX_BOXES * 4 {
                gave_up = true;
                break;
            }
        }
        Ok((merge_split_boxes(all, &seams_x, &seams_y), gave_up))
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

    /// Reads one detected line, splitting it first if it is too wide for the
    /// recognizer to see honestly.
    ///
    /// THE SQUEEZE THIS REPLACES. The recognizer's input is baked at 48x320
    /// by the graph conversion, and a crop was scaled to height 48 and then
    /// CLAMPED to 320 wide. A full-width page line is about 1200x30, whose
    /// honest width at height 48 is 1920 -- so it was squashed 6x
    /// horizontally and every glyph became a 1-2px smear. The old comment
    /// called that "degrades gracefully"; on a real page capture it does not,
    /// and it is the second half of why saved pages read back as almost
    /// nothing.
    ///
    /// So a line that would need more than REC_WIDTH is cut into pieces that
    /// each fit at their true aspect, read separately, and joined. The cuts
    /// land at the quietest column near each division -- the gap between two
    /// words -- because a blind cut bisects a glyph at every boundary.
    fn recognize_line(&self, crop: &RgbImage) -> Result<String, OcrError> {
        let (cw, ch) = crop.dimensions();
        let parts = line_parts(cw, ch);
        if parts > 1 {
            let profile = ink_profile(crop);
            let cuts = choose_cuts(&profile, parts, ch);
            if !cuts.is_empty() {
                let mut text = String::new();
                let mut start = 0u32;
                for (idx, (cut, _)) in cuts
                    .iter()
                    .map(|(c, g)| (*c as u32, *g))
                    .chain(std::iter::once((cw, false)))
                    .enumerate()
                {
                    let piece_w = cut.saturating_sub(start);
                    if piece_w < 2 {
                        start = cut;
                        continue;
                    }
                    let piece = image::imageops::crop_imm(crop, start, 0, piece_w, ch).to_image();
                    let part_text = self.recognize_one(&piece)?;
                    // A space ONLY across a cut that fell in a real word gap.
                    // A mid-word cut joins with nothing: inserting a space
                    // there is what produced "som ething" and "CA RRIAGE" at
                    // every chunk boundary.
                    if idx > 0 && !text.is_empty() && !part_text.is_empty() {
                        let (_, prev_was_gap) = cuts[idx - 1];
                        if prev_was_gap && !text.ends_with(' ') && !part_text.starts_with(' ') {
                            text.push(' ');
                        }
                    }
                    text.push_str(&part_text);
                    start = cut;
                }
                return Ok(text.trim().to_string());
            }
        }
        self.recognize_one(crop)
    }

    /// One crop, one pass through the recognizer, at whatever aspect it has.
    fn recognize_one(&self, crop: &RgbImage) -> Result<String, OcrError> {
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
/// How many pieces a detected line must be read in.
///
/// 1 means the crop already fits the recognizer at its true aspect and takes
/// the single-pass path unchanged. More than 1 means reading it whole would
/// require squeezing it horizontally -- 6x for an ordinary full-width page
/// line -- and the pieces are what avoids that.
fn line_parts(w: u32, h: u32) -> usize {
    if w < 4 || h == 0 {
        return 1;
    }
    let honest = ((w as f32) * REC_HEIGHT as f32 / h as f32).round() as u32;
    if honest <= REC_WIDTH {
        return 1;
    }
    (((honest + REC_WIDTH - 1) / REC_WIDTH) as usize).min(MAX_LINE_PARTS)
}

/// Per-column "how much ink is here", used to split a long line at a gap
/// between words rather than through a letter.
///
/// Measured as mean absolute deviation from the crop's MEDIAN luminance, so
/// it works for dark-on-light and light-on-dark alike: a background column
/// sits near the median whichever way round the page is, and a column with
/// glyphs in it does not. Nothing here assumes text is dark.
fn ink_profile(crop: &RgbImage) -> Vec<f32> {
    let (w, h) = crop.dimensions();
    if w == 0 || h == 0 {
        return Vec::new();
    }
    let lum = |px: &image::Rgb<u8>| -> f32 {
        0.299 * px[0] as f32 + 0.587 * px[1] as f32 + 0.114 * px[2] as f32
    };
    let mut all: Vec<f32> = crop.pixels().map(lum).collect();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = all[all.len() / 2];
    (0..w)
        .map(|x| {
            let mut acc = 0f32;
            for y in 0..h {
                acc += (lum(crop.get_pixel(x, y)) - median).abs();
            }
            acc / h as f32
        })
        .collect()
}

/// Where to cut a line into `parts` pieces, and whether each cut fell in a
/// real word gap.
///
/// THE SPURIOUS SPACES THIS FIXES. The first version slid each cut to the
/// quietest single column and added a space wherever that column was below a
/// fraction of peak ink. In anti-aliased text the gap BETWEEN LETTERS is also
/// quiet, so cuts landed mid-word and the join inserted a space there:
/// "som ething", "CA RRIAGE", "Unauth orized" -- every 6-10 characters, which
/// is exactly the chunk width. Reported from hardware with the whole readout
/// visible.
///
/// A word gap is not a dip, it is a RUN: several consecutive quiet columns.
/// So gaps are found as runs, the cut goes to the middle of the widest run
/// near the division, and a space is added ONLY there. Where no run qualifies
/// the cut still happens -- the piece must fit the recognizer -- but it is
/// marked as mid-word and the pieces are joined with nothing between them.
///
/// Landing in a run has a second benefit: the hard edge of the crop falls in
/// whitespace instead of through a glyph, so the recognizer stops reading the
/// cut itself as a stroke (the stray leading "-" and "I" in the same report).
fn choose_cuts(profile: &[f32], parts: usize, line_height: u32) -> Vec<(usize, bool)> {
    let w = profile.len();
    if parts <= 1 || w < parts * 2 {
        return Vec::new();
    }
    // Quiet is relative to this line's own ink, so a faint line and a bold
    // one are judged on their own terms.
    let peak = profile.iter().copied().fold(0f32, f32::max);
    if peak <= 0.0 {
        return Vec::new();
    }
    let quiet_at = peak * 0.10;
    // A word gap is about a quarter of the text height wide; letter spacing
    // is far narrower. Three columns is the floor for very small text.
    let min_gap = ((line_height / 4) as usize).max(3);

    // Every run of quiet columns, as (start, end_exclusive).
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut run_start: Option<usize> = None;
    for (x, v) in profile.iter().enumerate() {
        if *v <= quiet_at {
            run_start.get_or_insert(x);
        } else if let Some(st) = run_start.take() {
            if x - st >= min_gap {
                runs.push((st, x));
            }
        }
    }
    if let Some(st) = run_start {
        if w - st >= min_gap {
            runs.push((st, w));
        }
    }

    let part = w / parts;
    let window = (part / 2).max(8);
    let mut cuts: Vec<(usize, bool)> = Vec::with_capacity(parts - 1);
    let mut prev = 0usize;
    for i in 1..parts {
        let target = i * part;
        let lo = target.saturating_sub(window).max(prev + 1);
        let hi = (target + window).min(w.saturating_sub(1));
        if lo >= hi {
            continue;
        }
        // Prefer the WIDEST qualifying run overlapping the window; a wider
        // run is more certainly a space between words rather than a quirk of
        // one glyph.
        let mut best_run: Option<(usize, usize)> = None;
        for (rs, re) in &runs {
            let mid = (rs + re) / 2;
            if mid <= prev || mid < lo || mid > hi {
                continue;
            }
            if best_run.is_none_or(|(bs, be)| (re - rs) > (be - bs)) {
                best_run = Some((*rs, *re));
            }
        }
        if let Some((rs, re)) = best_run {
            cuts.push(((rs + re) / 2, true));
            prev = (rs + re) / 2;
            continue;
        }
        // No gap to use: cut at the quietest column and say so, so the join
        // does not invent a space in the middle of a word.
        let mut best = lo;
        let mut best_ink = f32::MAX;
        for x in lo..hi {
            if profile[x] < best_ink {
                best_ink = profile[x];
                best = x;
            }
        }
        if best > prev {
            cuts.push((best, false));
            prev = best;
        }
    }
    cuts
}

/// Where the detector should look, and at what scale.
///
/// THE DEFECT THIS REPLACES. `det_scale` fits the LONGEST side into the 960
/// canvas, which is right for a photo and ruinous for a page capture: a
/// 1600x4000 saved page became 384x960, turning 14px body text into 3.4px.
/// Below roughly 8px the detector finds nothing, so most lines were never
/// detected and never reached the recognizer -- reported as "Read 2 line(s)"
/// on a screenshot full of text, from the feature whose entire purpose is
/// finding words inside images.
///
/// Raising DET_SIDE is not available: tract cannot optimize the detection
/// graph with symbolic H/W (it fails analysing a Concat), so the input shape
/// is pinned at load time and re-planning per image would cost seconds.
///
/// So the image is cut into overlapping windows that each fit the canvas at
/// NATIVE scale, and the detector runs once per window. Returns the scale to
/// apply to the source first (1.0 in the common case) and the tile rects in
/// that scaled space.
///
/// Small images are unchanged: anything already inside the canvas yields
/// exactly one full-image tile at scale 1.0, which is byte-for-byte the old
/// path.
fn tile_plan(w: u32, h: u32) -> (f64, Vec<(u32, u32, u32, u32)>) {
    if w == 0 || h == 0 {
        return (1.0, Vec::new());
    }
    // Step between tile origins. Overlap is subtracted so consecutive tiles
    // share a band; a line landing in that band is whole in one of them.
    let step = DET_SIDE.saturating_sub(DET_TILE_OVERLAP).max(1);
    let count = |extent: u32| -> usize {
        if extent <= DET_SIDE {
            1
        } else {
            // Ceiling division over the stepped extent.
            (((extent - DET_SIDE) + step - 1) / step) as usize + 1
        }
    };

    // Shrink only as far as the tile budget demands, rather than as far as one
    // canvas demands. A page that needs 10 tiles keeps native scale; one that
    // would need 200 is reduced until it needs 24.
    let mut scale = 1.0f64;
    loop {
        let sw = ((w as f64 * scale).round() as u32).max(1);
        let sh = ((h as f64 * scale).round() as u32).max(1);
        if count(sw) * count(sh) <= MAX_DET_TILES || scale < 0.05 {
            let mut tiles = Vec::new();
            let mut y = 0u32;
            loop {
                let th = DET_SIDE.min(sh - y);
                let mut x = 0u32;
                loop {
                    let tw = DET_SIDE.min(sw - x);
                    tiles.push((x, y, tw, th));
                    if x + tw >= sw {
                        break;
                    }
                    x = (x + step).min(sw.saturating_sub(1));
                }
                if y + th >= sh {
                    break;
                }
                y = (y + step).min(sh.saturating_sub(1));
            }
            return (scale, tiles);
        }
        scale *= 0.8;
    }
}

/// Joins boxes that the tiling split apart -- and ONLY those.
///
/// THE RUNAWAY THIS FIXES. The first version applied its "are these one
/// line?" test to every pair of boxes in the image, with no requirement that
/// a seam lie between them. Simulated against the real predicate: sixty
/// stacked lines whose boxes overlap by two pixels collapsed into a SINGLE
/// box 1202px tall, because the union grows in place and each merge makes
/// the next one easier. That box then goes to the recognizer as one line and
/// is read as garbage. A two-column layout with a 50px gutter merged left
/// and right row by row, interleaving two columns into one crop. Ordinary
/// prose was untouched, which is exactly why the tests missed it: the
/// failure needs tight leading (code blocks, tables, dense headings) or
/// columns, and those are common in the page captures this release exists
/// to read.
///
/// So a merge now requires the pair to straddle a SEAM: a box that lies
/// wholly inside one tile's interior cannot have been split by tiling, and
/// is left alone whatever it overlaps. The chain is capped as well, since a
/// line split by one seam yields two pieces, not sixty.
fn merge_split_boxes(
    mut boxes: Vec<(u32, u32, u32, u32)>,
    seams_x: &[u32],
    seams_y: &[u32],
) -> Vec<(u32, u32, u32, u32)> {
    // No seams means one tile, which means nothing was split.
    if seams_x.is_empty() && seams_y.is_empty() {
        boxes.sort_by_key(|b| (b.1, b.0));
        return boxes;
    }
    boxes.sort_by_key(|b| (b.1, b.0));
    let mut out: Vec<(u32, u32, u32, u32)> = Vec::new();
    let mut heights: Vec<u32> = Vec::new();
    for b in boxes {
        let mut merged = false;
        for (i, a) in out.iter_mut().enumerate() {
            if !split_by_a_seam(*a, b, seams_x, seams_y) {
                continue;
            }
            let x0 = a.0.min(b.0);
            let y0 = a.1.min(b.1);
            let x1 = (a.0 + a.2).max(b.0 + b.2);
            let y1 = (a.1 + a.3).max(b.1 + b.3);
            // A seam split makes two pieces of one line. Anything that would
            // grow the box past twice the taller original's height is a chain
            // forming, not a line rejoining.
            let cap = heights[i].max(b.3).saturating_mul(2).max(4);
            if y1 - y0 > cap {
                continue;
            }
            *a = (x0, y0, x1 - x0, y1 - y0);
            heights[i] = heights[i].max(b.3);
            merged = true;
            break;
        }
        if !merged {
            out.push(b);
            heights.push(b.3);
        }
    }
    out.sort_by_key(|b| (b.1, b.0));
    out
}

/// Whether these two boxes are ONE line that a seam on the MATCHING AXIS
/// cut in half.
///
/// THE AXIS HOLE THIS CLOSES. The first seam gate asked only whether both
/// boxes came within the overlap band of SOME seam, either axis. On any page
/// wider than the canvas every full-width line crosses the vertical seam --
/// so every pair of full-width lines passed the gate on X, which re-armed
/// the VERTICAL merge across the whole page. The height cap stopped the
/// runaway but not the damage: sixty dense lines still glued into thirty
/// boxes of two lines each, and each of those went to a single-line
/// recognizer as one crop.
///
/// My tests passed only because they supplied an empty `seams_x`, which no
/// real 1600px capture has. Same shape of mistake as the runaway itself: the
/// test did not reproduce the condition.
///
/// So the axis has to match the join. A side-by-side pair can only have been
/// split by a VERTICAL seam, a stacked pair only by a HORIZONTAL one.
fn split_by_a_seam(
    a: (u32, u32, u32, u32),
    b: (u32, u32, u32, u32),
    seams_x: &[u32],
    seams_y: &[u32],
) -> bool {
    let (ax0, ay0, ax1, ay1) = (a.0, a.1, a.0 + a.2, a.1 + a.3);
    let (bx0, by0, bx1, by1) = (b.0, b.1, b.0 + b.2, b.1 + b.3);
    let y_overlap = ay1.min(by1).saturating_sub(ay0.max(by0));
    let x_overlap = ax1.min(bx1).saturating_sub(ax0.max(bx0));
    let short_h = a.3.min(b.3).max(1);
    let short_w = a.2.min(b.2).max(1);

    // THE FACING EDGES, not merely "both near a seam". A line the tiling cut
    // has one piece ENDING at the seam and the other STARTING there; two
    // adjacent lines that happen to sit within a hundred pixels of it do not.
    // Checking proximity alone still merged ten pairs out of a sixty-line
    // dense block, because at 20px pitch ten lines fall inside the band.
    let near_seam = |edge_a: u32, edge_b: u32, seams: &[u32]| -> bool {
        // Tighter than the tile overlap: the overlap is how much the tiles
        // SHARE, while a cut edge lands essentially on the seam. Slack here
        // buys nothing and costs exactly the false merges above.
        const EDGE_SLACK: u32 = 32;
        seams.iter().any(|s| {
            let da = edge_a.abs_diff(*s);
            let db = edge_b.abs_diff(*s);
            da <= EDGE_SLACK && db <= EDGE_SLACK
        })
    };

    // SIDE BY SIDE on one text row: only a vertical seam explains it, and
    // only if the pieces meet AT that seam.
    let same_row = y_overlap * 2 >= short_h;
    let x_gap = ax0.max(bx0).saturating_sub(ax1.min(bx1));
    if same_row && (x_overlap > 0 || x_gap <= DET_TILE_OVERLAP) {
        let (left_end, right_start) = if ax0 <= bx0 { (ax1, bx0) } else { (bx1, ax0) };
        if near_seam(left_end, right_start, seams_x) {
            return true;
        }
    }

    // STACKED in one column: only a horizontal seam, and the union must be
    // about ONE line tall. A cut line's halves overlap heavily, so their
    // union barely exceeds the taller piece; two stacked LINES are nearly
    // twice it. That ratio is what tells them apart once both are near a
    // seam.
    let same_col = x_overlap * 2 >= short_w;
    if same_col && y_overlap > 0 {
        let (top_end, bottom_start) = if ay0 <= by0 { (ay1, by0) } else { (by1, ay0) };
        let union_h = ay1.max(by1) - ay0.min(by0);
        let taller = a.3.max(b.3).max(1);
        if near_seam(top_end, bottom_start, seams_y) && union_h <= taller * 2 {
            return true;
        }
    }
    false
}

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
    fn a_full_width_line_is_split_rather_than_squeezed() {
        // THE DEFECT THIS PINS. A 1200x30 page line's honest width at the
        // recognizer's 48px height is 1920, so it used to be squashed into
        // 320 -- a 6x horizontal crush that turns glyphs into smears.
        assert_eq!(line_parts(1200, 30), 6, "six pieces is what un-squeezed costs");
        assert_eq!(line_parts(900, 26), 6);
        // The common case is untouched: one pass, no cuts, no joins.
        assert_eq!(line_parts(320, 48), 1);
        assert_eq!(line_parts(200, 30), 1);
        // Pathological input is squeezed as before rather than spending the
        // whole recognizer budget on one detection.
        assert_eq!(line_parts(100_000, 20), MAX_LINE_PARTS);
        assert_eq!(line_parts(0, 0), 1, "degenerate input must not divide by zero");
    }

    #[test]
    fn recognize_line_actually_uses_the_split_decision() {
        // WITHOUT THIS, THE TEST ABOVE PASSES ON A DISABLED FEATURE. Planting
        // `if false` over the split branch left every arithmetic assertion
        // green, because none of them reached recognize_line -- which cannot
        // be called here at all, since it needs the ONNX models. So the
        // wiring is asserted against the source, the way the licence gate
        // asserts its arms: recognize_line must ASK line_parts, and must not
        // reintroduce a literal clamp to REC_WIDTH as its only width policy.
        let src = include_str!("lib.rs");
        let start = src
            .find("fn recognize_line(")
            .expect("recognize_line is gone");
        let end = src[start..]
            .find("fn recognize_one(")
            .expect("recognize_one is gone")
            + start;
        let body = &src[start..end];
        assert!(
            body.contains("line_parts("),
            "recognize_line no longer consults line_parts, so a wide line is \
             squeezed again and every assertion about splitting is vacuous"
        );
        assert!(
            body.contains("choose_cuts("),
            "recognize_line no longer cuts at word gaps"
        );
    }

    #[test]
    fn abandoning_tiles_counts_as_truncation() {
        // Same reason as the test above: this path needs the ONNX models and
        // cannot be called here, so the wiring is asserted against the
        // source. The rule it guards: `detect_tiled` stops early when the
        // detections pass four times the cap, and `recognize_pixels` decides
        // truncation from the box count AFTER merging. Those two numbers are
        // not the same number. A run that gave up on whole tiles and then
        // merged its way back under the cap would report a clean read of a
        // page it never finished looking at -- the exact failure the marker
        // exists to prevent, arriving by a different door.
        let src = include_str!("lib.rs");
        let start = src
            .find("fn recognize_pixels(")
            .expect("recognize_pixels is gone");
        let end = src[start..]
            .find("fn detect_tiled(")
            .expect("detect_tiled is gone")
            + start;
        let body = &src[start..end];
        assert!(
            body.contains("gave_up"),
            "recognize_pixels no longer reads whether detection gave up, so \
             an abandoned page can report itself as fully read"
        );
        assert!(
            body.contains("|| gave_up"),
            "the early-exit flag must widen the truncation decision, not \
             narrow it"
        );

        let dstart = src.find("fn detect_tiled(").unwrap();
        let dend = src[dstart..].find("fn detect(").unwrap() + dstart;
        let detect_body = &src[dstart..dend];
        assert!(
            detect_body.contains("gave_up = true;"),
            "detect_tiled no longer records that it broke out of the tile \
             loop, so the flag it returns is always false"
        );
    }

    #[test]
    fn cuts_land_in_the_gaps_between_words() {
        // A blind cut bisects a glyph at every boundary and the recognizer
        // reads the halves as two wrong characters. A real word gap is a RUN
        // of quiet columns, and the cut must land in the middle of one.
        let mut profile = vec![9.0f32; 600];
        for gap in 190usize..210 {
            profile[gap] = 0.0;
        }
        for gap in 390usize..410 {
            profile[gap] = 0.0;
        }
        let cuts = choose_cuts(&profile, 3, 24);
        assert_eq!(cuts.len(), 2, "two interior cuts for three parts");
        for (c, is_gap) in &cuts {
            assert!(profile[*c] == 0.0, "cut at {c} landed on ink");
            assert!(*is_gap, "a run of 20 quiet columns is a word gap");
        }
    }

    #[test]
    fn a_dip_between_two_letters_is_not_a_word_gap() {
        // THE SPURIOUS SPACES THIS PINS. Anti-aliased text is quiet between
        // letters too. Treating those dips as gaps put a space at every chunk
        // boundary -- "som ething", "CA RRIAGE", "Unauth orized" -- reported
        // from hardware. A one- or two-column dip must NOT be called a gap,
        // so the join adds nothing across it.
        let mut profile = vec![9.0f32; 600];
        for dip in [199usize, 200, 399, 400] {
            profile[dip] = 0.0;
        }
        let cuts = choose_cuts(&profile, 3, 40);
        assert_eq!(cuts.len(), 2, "the line must still be cut to fit");
        for (_, is_gap) in &cuts {
            assert!(
                !*is_gap,
                "a two-column dip between letters was mistaken for a word gap, \
                 which is what inserts a space in the middle of a word"
            );
        }
    }

    #[test]
    fn a_wide_gap_is_preferred_over_a_narrow_one_nearby() {
        // Both qualify; the wider run is the likelier word boundary.
        let mut profile = vec![9.0f32; 400];
        for x in 180usize..186 {
            profile[x] = 0.0; // narrow
        }
        for x in 195usize..215 {
            profile[x] = 0.0; // wide
        }
        let cuts = choose_cuts(&profile, 2, 24);
        assert_eq!(cuts.len(), 1);
        let (at, is_gap) = cuts[0];
        assert!(*&is_gap);
        assert!((195..215).contains(&at), "cut at {at} took the narrow gap");
    }

    #[test]
    fn cuts_stay_ordered_and_inside_the_line() {
        let profile = vec![1.0f32; 500];
        let cuts = choose_cuts(&profile, 4, 30);
        assert!(
            cuts.windows(2).all(|p| p[0].0 < p[1].0),
            "cuts must ascend"
        );
        assert!(
            cuts.iter().all(|(c, _)| *c > 0 && *c < 500),
            "cuts must be interior"
        );
    }

    #[test]
    fn a_short_line_is_never_split() {
        // The common case must be untouched: one pass, no cuts, no joins.
        assert!(choose_cuts(&vec![1.0f32; 200], 1, 30).is_empty());
        // And a line too narrow to divide safely refuses rather than
        // producing degenerate one-pixel pieces.
        assert!(choose_cuts(&vec![1.0f32; 5], 4, 30).is_empty());
    }

    #[test]
    fn the_ink_profile_finds_text_whichever_way_round_the_page_is() {
        // Light-on-dark must profile the same as dark-on-light: the measure
        // is deviation from the median, not darkness.
        let mut dark_bg = RgbImage::new(20, 10);
        for p in dark_bg.pixels_mut() {
            *p = image::Rgb([10, 10, 10]);
        }
        let mut light_bg = RgbImage::new(20, 10);
        for p in light_bg.pixels_mut() {
            *p = image::Rgb([240, 240, 240]);
        }
        // One bright stripe on dark, one dark stripe on light, same column.
        for y in 0..10 {
            dark_bg.put_pixel(5, y, image::Rgb([240, 240, 240]));
            light_bg.put_pixel(5, y, image::Rgb([10, 10, 10]));
        }
        let a = ink_profile(&dark_bg);
        let b = ink_profile(&light_bg);
        assert!(a[5] > a[0] * 5.0 + 1.0, "stripe not found on a dark page");
        assert!(b[5] > b[0] * 5.0 + 1.0, "stripe not found on a light page");
    }

    #[test]
    fn a_small_image_still_takes_the_single_pass_path() {
        // The old behaviour must be untouched for anything already inside the
        // canvas: one tile, native scale, no merge step.
        let (scale, tiles) = tile_plan(800, 600);
        assert_eq!(scale, 1.0);
        assert_eq!(tiles, vec![(0, 0, 800, 600)]);
    }

    #[test]
    fn a_tall_page_capture_is_read_at_native_scale() {
        // THE DEFECT THIS PINS. 1600x4000 used to become 384x960, turning
        // 14px text into 3.4px and reading almost nothing. Native scale is
        // the whole point: at 1.0 a 14px line is still 14px.
        let (scale, tiles) = tile_plan(1600, 4000);
        assert_eq!(scale, 1.0, "a page capture must not be downscaled");
        assert!(tiles.len() > 1, "it must be tiled, not squashed");
        assert!(
            tiles.len() <= MAX_DET_TILES,
            "{} tiles exceeds the budget",
            tiles.len()
        );
        for (_, _, w, h) in &tiles {
            assert!(*w <= DET_SIDE && *h <= DET_SIDE, "a tile exceeds the canvas");
        }
    }

    #[test]
    fn tiles_cover_every_row_and_column_with_the_overlap() {
        // Nothing may fall between tiles: every pixel of the source is inside
        // at least one, and consecutive tiles share the overlap band so a
        // line on a seam is whole somewhere.
        let (w, h) = (1600u32, 4000u32);
        let (scale, tiles) = tile_plan(w, h);
        assert_eq!(scale, 1.0);
        let mut rows: Vec<(u32, u32)> = tiles.iter().map(|t| (t.1, t.1 + t.3)).collect();
        rows.sort_unstable();
        rows.dedup();
        assert_eq!(rows[0].0, 0, "the first tile must start at the top");
        assert_eq!(rows[rows.len() - 1].1, h, "the last tile must reach the bottom");
        for pair in rows.windows(2) {
            let (prev_end, next_start) = (pair[0].1, pair[1].0);
            assert!(next_start < prev_end, "a gap between tile rows");
            assert!(
                prev_end - next_start >= DET_TILE_OVERLAP.min(prev_end),
                "rows overlap by less than the band"
            );
        }
    }

    #[test]
    fn an_enormous_image_is_reduced_rather_than_tiled_forever() {
        // The budget is the CPU bound: each tile is a detector pass. A poster
        // scan must degrade to the old squash rather than take minutes.
        let (scale, tiles) = tile_plan(20000, 20000);
        assert!(scale < 1.0, "it must shrink to fit the tile budget");
        assert!(
            tiles.len() <= MAX_DET_TILES,
            "{} tiles exceeds the budget",
            tiles.len()
        );
    }

    #[test]
    fn a_line_split_by_a_vertical_seam_becomes_one_box() {
        // The failure this prevents: two half-lines recognized separately,
        // each reading as gibberish, instead of one line read correctly.
        let left = (100, 500, 400, 30);
        let right = (500, 502, 380, 28);
        // A vertical seam at 500 is what split this line.
        let merged = merge_split_boxes(vec![left, right], &[500], &[]);
        assert_eq!(merged.len(), 1, "the halves did not rejoin: {merged:?}");
        let (x, y, w, h) = merged[0];
        assert_eq!(x, 100);
        assert!(y <= 500);
        assert!(x + w >= 880, "the union must span both halves");
        assert!(h >= 30);
    }

    #[test]
    fn a_line_split_by_a_horizontal_seam_becomes_one_box() {
        let top = (100, 480, 400, 20);
        let bottom = (102, 494, 396, 18);
        // A horizontal seam at 494 is what split this line.
        let merged = merge_split_boxes(vec![top, bottom], &[], &[494]);
        assert_eq!(merged.len(), 1, "the halves did not rejoin: {merged:?}");
    }

    #[test]
    fn a_dense_block_far_from_any_seam_never_collapses() {
        // THE RUNAWAY THIS PINS, and it is the shape my first tests missed:
        // ordinary prose was fine, so nothing failed, while tight leading
        // chained. Sixty stacked lines overlapping by 2px collapsed into ONE
        // box 1202px tall, which the recognizer then read as garbage. Code
        // blocks, tables and dense headings all produce this.
        let stacked: Vec<(u32, u32, u32, u32)> =
            (0..60).map(|i| (100, 100 + i * 20, 1200, 22)).collect();
        // THE SEAMS A REAL 1600x4000 CAPTURE PRODUCES. Passing an empty
        // seams_x here is what let the axis hole through the first time: no
        // page wider than the canvas has one, and a full-width line always
        // crosses the vertical seam.
        let (_, tiles) = tile_plan(1600, 4000);
        let mut sx: Vec<u32> = tiles.iter().filter(|t| t.0 > 0).map(|t| t.0).collect();
        let mut sy: Vec<u32> = tiles.iter().filter(|t| t.1 > 0).map(|t| t.1).collect();
        sx.sort_unstable();
        sx.dedup();
        sy.sort_unstable();
        sy.dedup();
        assert!(!sx.is_empty(), "a 1600px page must have a vertical seam");
        let merged = merge_split_boxes(stacked.clone(), &sx, &sy);
        // A pair whose facing edges land ON a seam is a legitimate rejoin --
        // in a synthetic block one pair does, and refusing it would break the
        // real case. What must NOT happen is the block collapsing: before
        // the axis fix this was 30 boxes of two lines each, and before the
        // seam gate it was ONE box.
        assert!(
            merged.len() >= stacked.len() - 2,
            "a dense block collapsed: {} boxes became {}",
            stacked.len(),
            merged.len()
        );
        assert!(
            merged.iter().all(|b| b.3 < 46),
            "a merged box grew past about one line's height: tallest {}px",
            merged.iter().map(|b| b.3).max().unwrap_or(0)
        );
    }

    #[test]
    fn two_columns_are_not_merged_across_the_gutter() {
        // A 50px gutter is narrower than the overlap band, so the old rule
        // joined left and right row by row and fed the recognizer one crop
        // holding two columns of unrelated text.
        let mut cols = Vec::new();
        for i in 0..30u32 {
            cols.push((100, 100 + i * 40, 400, 24));
            cols.push((550, 100 + i * 40, 400, 24));
        }
        let (_, tiles) = tile_plan(1600, 4000);
        let mut sx: Vec<u32> = tiles.iter().filter(|t| t.0 > 0).map(|t| t.0).collect();
        let mut sy: Vec<u32> = tiles.iter().filter(|t| t.1 > 0).map(|t| t.1).collect();
        sx.sort_unstable();
        sx.dedup();
        sy.sort_unstable();
        sy.dedup();
        let merged = merge_split_boxes(cols.clone(), &sx, &sy);
        assert_eq!(merged.len(), cols.len(), "columns merged across the gutter");
    }

    #[test]
    fn the_chain_is_capped_even_when_a_seam_is_present() {
        // Belt and braces: at a real seam, a run of boxes must still not
        // accumulate into one tall block. A split line is two pieces.
        let stacked: Vec<(u32, u32, u32, u32)> =
            (0..40).map(|i| (100, 900 + i * 20, 1200, 22)).collect();
        let merged = merge_split_boxes(stacked, &[864], &[864, 1728]);
        assert!(
            merged.iter().all(|b| b.3 <= 88),
            "a chain formed at the seam: tallest is {}px",
            merged.iter().map(|b| b.3).max().unwrap_or(0)
        );
    }

    #[test]
    fn separate_lines_are_never_glued_together() {
        // Over-merging is worse than a duplicate: one crop holding two lines
        // recognizes as gibberish. Ordinary stacked lines with a gap, and
        // side-by-side columns far apart, must survive as separate boxes.
        let line_a = (100, 100, 400, 20);
        let line_b = (100, 140, 400, 20); // 20px gap below a
        let far_col = (900, 100, 300, 20); // same row, far to the right
        let merged = merge_split_boxes(vec![line_a, line_b, far_col], &[500], &[500]);
        assert_eq!(merged.len(), 3, "distinct lines were merged: {merged:?}");
    }

    #[test]
    fn tile_plan_survives_degenerate_input() {
        assert!(tile_plan(0, 0).1.is_empty());
        assert_eq!(tile_plan(1, 1).1, vec![(0, 0, 1, 1)]);
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

    /// Encodes a plain white image as PNG bytes, for the region-rect tests.
    /// No text in it: these tests pin the RECT contract, not recognition.
    fn white_png(w: u32, h: u32) -> Vec<u8> {
        let img = RgbImage::from_pixel(w, h, image::Rgb([255, 255, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("encode test png");
        bytes
    }

    #[test]
    fn region_rects_outside_the_image_or_empty_are_bad_region_not_bad_image() {
        let engine = OcrEngine::load_embedded().expect("embedded models must load");
        let png = white_png(64, 48);
        // Empty, overflowing-right, overflowing-bottom, and u32-overflow
        // rects all refuse with the rect's own error class.
        for (x, y, w, h) in [
            (0, 0, 0, 10),
            (0, 0, 10, 0),
            (60, 0, 10, 10),
            (0, 40, 10, 10),
            (u32::MAX, 0, 2, 2),
        ] {
            match engine.recognize_region(&png, x, y, w, h) {
                Err(OcrError::BadRegion) => {}
                other => panic!("rect ({x},{y},{w},{h}) gave {other:?}, wanted BadRegion"),
            }
        }
        // An in-bounds rect on a blank image is an ordinary empty result --
        // the crop ran, the pipeline ran, there was simply nothing to read.
        let regions = engine
            .recognize_region(&png, 8, 8, 32, 24)
            .expect("in-bounds rect must run");
        assert!(regions.is_empty());
        // Undecodable bytes keep their own class even with a plausible rect.
        match engine.recognize_region(b"not an image", 0, 0, 1, 1) {
            Err(OcrError::ImageDecode) => {}
            other => panic!("garbage bytes gave {other:?}, wanted ImageDecode"),
        }
    }
}
