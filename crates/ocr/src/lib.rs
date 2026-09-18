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
pub const CLS_MODEL_FILE: &str = "cls.onnx";
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
/// PaddleOCR 2.10 DB defaults from `tools/infer/utility.py`: binarize the
/// shrink map at 0.3, retain boxes scoring at least 0.6, then unclip at 1.5
/// using `ppocr/postprocess/db_postprocess.py`'s distance formula.
/// Keeping all three together prevents the threshold from looking like the
/// whole DB postprocess when it is only its first gate.
const DET_THRESHOLD: f32 = 0.3;
const DET_BOX_THRESHOLD: f32 = 0.6;
const DET_UNCLIP_RATIO: f64 = 1.5;
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
/// Source-coordinate overlap needed to call detections from two tiles the
/// same line. This is intersection / smaller-box area rather than IoU: a box
/// clipped by a tile edge may sit almost wholly inside the complete box while
/// having a low IoU with it. Three quarters still tolerates detector expansion
/// jitter without collapsing nearby words or stacked lines.
const TILE_DEDUP_CONTAINED_FRACTION: f64 = 0.75;
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
/// PP-OCR's mobile angle classifier input and decision threshold. These are
/// the PaddleOCR 2.10 inference defaults (`cls_image_shape=3,48,192` and
/// `cls_thresh=0.9` in `tools/infer/utility.py`). Class 0 is upright and
/// class 1 is 180 degrees.
const CLS_HEIGHT: u32 = 48;
const CLS_WIDTH: u32 = 192;
const CLS_THRESHOLD: f32 = 0.9;
/// Whole-image and region-crop bomb guard: RGB storage is at most 120 MB.
/// A small compressed file can otherwise decode to gigabytes.
const MAX_PIXELS: u64 = 40_000_000;
/// Region capture complexity guard. Region decoding is row-streamed, so this
/// is a CPU/work ceiling rather than an allocation request: realistic tall
/// pages up to 200 MP pass, while a crafted near-u32-sized PNG does not make a
/// worker walk billions of pixels to reach a selection near the bottom.
const MAX_REGION_SOURCE_PIXELS: u64 = 200_000_000;
/// Best-effort ceiling for allocations owned by the streaming PNG decoder.
/// The crop buffer is separate and is bounded by `MAX_PIXELS` above.
const REGION_DECODER_ALLOC_LIMIT: usize = 64 * 1024 * 1024;

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
    /// Input bytes are not a decodable image.
    ImageDecode,
    /// A valid image, region crop, or streaming decode exceeds a deliberate
    /// size/complexity ceiling. Kept separate from `ImageDecode` so an honest
    /// size refusal never wears file-format copy.
    ImageTooLarge,
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
            Self::ImageDecode => write!(f, "not a decodable image"),
            Self::ImageTooLarge => write!(f, "image or region exceeds OCR resource limits"),
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
    /// Optional by design: a broken angle graph must degrade to the old
    /// det -> rec pipeline, never make all OCR unavailable.
    cls: Option<Plan>,
    rec: Plan,
    /// Set at load time, or on the first classifier inference failure. Kept
    /// separate from `OcrError` because the classifier is a best-effort stage.
    cls_diagnostic: std::sync::Mutex<Option<String>>,
    /// CTC class k maps to dict[k - 1]; class 0 is the blank.
    dict: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TileDetection {
    rect: (u32, u32, u32, u32),
    tile_id: usize,
    tile_rect: (u32, u32, u32, u32),
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
const CLS_MODEL_BYTES: &[u8] = include_bytes!("../../../models/ocr/cls.onnx");
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
        let (cls, cls_diagnostic) = optional_classifier(
            || {
                load_onnx_bytes(
                    CLS_MODEL_BYTES,
                    f32::fact([1, 3, CLS_HEIGHT as i32, CLS_WIDTH as i32]).into(),
                )
            },
            "embedded cls",
        );
        Ok(Self {
            det,
            cls,
            rec,
            cls_diagnostic: std::sync::Mutex::new(cls_diagnostic),
            dict,
        })
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
        let cls_path = dir.join(CLS_MODEL_FILE);
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
        let (cls, cls_diagnostic) = if cls_path.is_file() {
            optional_classifier(
                || {
                    load_onnx(
                        &cls_path,
                        f32::fact([1, 3, CLS_HEIGHT as i32, CLS_WIDTH as i32]).into(),
                    )
                },
                "cls",
            )
        } else {
            (
                None,
                Some(format!("cls model missing: {}", cls_path.display())),
            )
        };
        Ok(Self {
            det,
            cls,
            rec,
            cls_diagnostic: std::sync::Mutex::new(cls_diagnostic),
            dict,
        })
    }

    /// Whether the optional angle stage is healthy right now.
    pub fn classifier_available(&self) -> bool {
        self.cls.is_some() && self.classifier_diagnostic().is_none()
    }

    /// A developer-facing degraded-mode reason for the diagnostics export.
    pub fn classifier_diagnostic(&self) -> Option<String> {
        self.cls_diagnostic
            .lock()
            .map(|d| d.clone())
            .unwrap_or_else(|_| Some("cls diagnostic lock poisoned".into()))
    }

    /// Recognizes text in an encoded image (PNG/JPEG bytes). Returns regions
    /// in reading order with boxes in original-image pixels.
    pub fn recognize(&self, bytes: &[u8]) -> Result<Vec<TextRegion>, OcrError> {
        let img = decode_image(bytes)?;
        self.recognize_pixels(&img)
    }

    /// Recognizes text inside one rectangle of a native PNG page capture.
    /// PNG has no random access, so rows are decoded in order through `y + h`,
    /// but only the crop is retained. A 40+ MP page with a small selection
    /// therefore consumes one decoder scanline plus the crop, not a full RGB
    /// page allocation.
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
        let crop = decode_png_region(bytes, x, y, w, h)?;
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
        // PP-OCR's detector and recognizer were trained on dark ink over a
        // light ground. Normalize THIS crop, not a process-wide/page-wide
        // setting: adjacent captures and user selections can have opposite
        // themes. Mean BT.601 luminance below 128 means the crop is mostly a
        // dark ground, so invert it once and let both det and rec consume the
        // same normalized pixels. We rejected border sampling because a tight
        // selection can begin mid-glyph (making its border ink), and rejected
        // border-vs-centre voting because a centred heading/photo can reverse
        // those roles. A median threshold was also rejected: bold or zoomed
        // glyphs crossing 50% of a tight crop make it flip discontinuously.
        // Mean luminance has the honest failure mode that a mostly-dark photo
        // can be inverted, but at the explicit 128 threshold it is stable for
        // the light/dark page grounds this OCR path is intended to read.
        let normalized = normalized_polarity(img);
        let ocr_img = normalized.as_ref();

        let (boxes, gave_up) = self.detect_tiled(ocr_img)?;
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
            let crop = image::imageops::crop_imm(ocr_img, x, y, w, h).to_image();
            let oriented = self.orient_line(&crop);
            let text = self.recognize_line(oriented.as_ref())?;
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

        let mut all: Vec<TileDetection> = Vec::new();
        let mut gave_up = false;
        for (tile_id, (tx, ty, tw, th)) in tiles.into_iter().enumerate() {
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
                    let tile_x0 = ((tx as f64) * inv).round() as u32;
                    let tile_y0 = ((ty as f64) * inv).round() as u32;
                    let tile_x1 = (((tx + tw) as f64) * inv).round() as u32;
                    let tile_y1 = (((ty + th) as f64) * inv).round() as u32;
                    all.push(TileDetection {
                        rect: (x, y, w, h),
                        tile_id,
                        tile_rect: (
                            tile_x0.min(ow),
                            tile_y0.min(oh),
                            tile_x1.min(ow).saturating_sub(tile_x0.min(ow)),
                            tile_y1.min(oh).saturating_sub(tile_y0.min(oh)),
                        ),
                    });
                }
            }
            // The cap counts DETECTIONS, not tiles: a pathological mask in an
            // early tile must not buy itself the whole budget of later ones.
            if all.len() > MAX_BOXES * 4 {
                gave_up = true;
                break;
            }
        }
        // Provenance is deliberately retained until here: only detections
        // from DIFFERENT tiles are duplicates. Once mapped to source space,
        // drop a near-contained copy before the seam rejoin sees it. Keeping
        // the copy with more clearance from its tile edges prefers the line
        // the detector saw whole; area breaks ties in favour of more glyphs.
        let all = dedupe_tile_boxes(all);
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
            .filter(|b| component_box_score(&vals, mw, *b) >= DET_BOX_THRESHOLD)
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
                    let prev_was_gap = idx > 0 && cuts[idx - 1].1;
                    append_recognized_part(&mut text, &part_text, prev_was_gap);
                    start = cut;
                }
                return Ok(text.trim().to_string());
            }
        }
        self.recognize_one(crop)
    }

    /// Runs PP-OCR's optional angle stage. Any classifier failure records a
    /// degraded diagnostic and returns the original crop: recognition remains
    /// available, matching the old det -> rec pipeline.
    fn orient_line<'a>(&self, crop: &'a RgbImage) -> std::borrow::Cow<'a, RgbImage> {
        let Some(cls) = &self.cls else {
            return std::borrow::Cow::Borrowed(crop);
        };
        match classifier_says_180(cls, crop) {
            Ok(true) => std::borrow::Cow::Owned(image::imageops::rotate180(crop)),
            Ok(false) => std::borrow::Cow::Borrowed(crop),
            Err(e) => {
                if let Ok(mut slot) = self.cls_diagnostic.lock() {
                    if slot.is_none() {
                        *slot = Some(e.to_string());
                    }
                }
                std::borrow::Cow::Borrowed(crop)
            }
        }
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
        // PaddleOCR 2.10 `tools/infer/predict_rec.py`'s
        // `TextRecognizer.resize_norm_img` uses ceil here.
        // A one-column narrower render changes the right-padding boundary and
        // is enough to move a marginal CTC character.
        let ideal = ((w as f64) * REC_HEIGHT as f64 / h.max(1) as f64).ceil() as u32;
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

fn optional_classifier(
    load: impl FnOnce() -> TractResult<Plan>,
    label: &str,
) -> (Option<Plan>, Option<String>) {
    match load() {
        Ok(plan) => (Some(plan), None),
        Err(e) => (None, Some(format!("{label}: {e}"))),
    }
}

/// PaddleOCR 2.10's `TextClassifier.resize_norm_img`, ported exactly: keep
/// aspect, ceil the resized width, resize to 48px high, right-pad to 192 with
/// normalized zero, and apply `(pixel / 255 - 0.5) / 0.5` in BGR order.
fn classifier_says_180(cls: &Plan, crop: &RgbImage) -> Result<bool, OcrError> {
    let (w, h) = crop.dimensions();
    let rw = ((CLS_HEIGHT as f64 * w as f64 / h.max(1) as f64).ceil() as u32).clamp(1, CLS_WIDTH);
    let resized = image::imageops::resize(crop, rw, CLS_HEIGHT, FilterType::Triangle);
    let (w_us, h_us) = (CLS_WIDTH as usize, CLS_HEIGHT as usize);
    let mut data = vec![0f32; 3 * w_us * h_us];
    for (x, y, px) in resized.enumerate_pixels() {
        for c in 0..3usize {
            let ch = if MODEL_EXPECTS_BGR { 2 - c } else { c };
            let v = px[ch] as f32 / 255.0;
            data[c * w_us * h_us + y as usize * w_us + x as usize] = (v - 0.5) / 0.5;
        }
    }
    let input = Tensor::from_shape(&[1, 3, h_us, w_us], &data)
        .map_err(|e| OcrError::Inference(format!("cls input: {e}")))?;
    let outputs = cls
        .run(tvec!(input.into()))
        .map_err(|e| OcrError::Inference(format!("cls: {e}")))?;
    let output = outputs
        .get(0)
        .ok_or_else(|| OcrError::Inference("cls returned no output".into()))?;
    let view = output
        .to_array_view::<f32>()
        .map_err(|e| OcrError::Inference(format!("cls output: {e}")))?;
    let shape = view.shape().to_vec();
    if shape != [1, 2] {
        return Err(OcrError::Inference(format!("cls output shape {shape:?}")));
    }
    // PaddleOCR takes argmax and rotates only label 180 above cls_thresh=0.9.
    Ok(view[[0, 1]] > view[[0, 0]] && view[[0, 1]] > CLS_THRESHOLD)
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
        return Err(OcrError::ImageTooLarge);
    }
    image::load_from_memory(bytes)
        .map(|i| i.to_rgb8())
        .map_err(|_| OcrError::ImageDecode)
}

/// Row-stream a PNG into one RGB crop. The returned row count is kept as a
/// small test seam: it proves the implementation stopped after the requested
/// band instead of silently returning to a whole-frame decode.
fn decode_png_region_with_rows(
    bytes: &[u8],
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<(RgbImage, u32), OcrError> {
    use png::{BitDepth, ColorType, Decoder, DecodingError, Limits, Transformations};
    use std::io::Cursor;

    let map_decode_error = |e: DecodingError| match e {
        DecodingError::LimitsExceeded => OcrError::ImageTooLarge,
        _ => OcrError::ImageDecode,
    };

    let mut decoder = Decoder::new_with_limits(
        Cursor::new(bytes),
        Limits {
            bytes: REGION_DECODER_ALLOC_LIMIT,
        },
    );
    decoder.set_transformations(Transformations::normalize_to_color8());
    // Captures do not need metadata, and untrusted ancillary chunks must not
    // spend memory that belongs to the selected pixels.
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    let mut reader = decoder.read_info().map_err(map_decode_error)?;
    let (iw, ih) = reader.info().size();
    if u64::from(iw) * u64::from(ih) > MAX_REGION_SOURCE_PIXELS {
        return Err(OcrError::ImageTooLarge);
    }
    let end_x = x.checked_add(w).ok_or(OcrError::BadRegion)?;
    let end_y = y.checked_add(h).ok_or(OcrError::BadRegion)?;
    if w == 0 || h == 0 || end_x > iw || end_y > ih {
        return Err(OcrError::BadRegion);
    }
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(OcrError::ImageTooLarge);
    }
    // Adam7 rows are partial passes, not complete source scanlines. Browser
    // capture encoders emit non-interlaced PNGs; refusing this extra
    // complexity is bounded and honest instead of allocating a full frame to
    // deinterlace an input that the capture path never produces.
    if reader.info().interlaced {
        return Err(OcrError::ImageTooLarge);
    }
    let (color, depth) = reader.output_color_type();
    if depth != BitDepth::Eight || color == ColorType::Indexed {
        return Err(OcrError::ImageDecode);
    }
    let samples = color.samples();
    let crop_len =
        usize::try_from(u64::from(w) * u64::from(h) * 3).map_err(|_| OcrError::ImageTooLarge)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(crop_len)
        .map_err(|_| OcrError::ImageTooLarge)?;
    pixels.resize(crop_len, 0);

    let mut rows_decoded = 0u32;
    for source_y in 0..end_y {
        let row = reader
            .next_row()
            .map_err(map_decode_error)?
            .ok_or(OcrError::ImageDecode)?;
        rows_decoded += 1;
        if source_y < y {
            continue;
        }
        let source = row.data();
        let source_start = usize::try_from(x)
            .ok()
            .and_then(|v| v.checked_mul(samples))
            .ok_or(OcrError::ImageTooLarge)?;
        let source_len = usize::try_from(w)
            .ok()
            .and_then(|v| v.checked_mul(samples))
            .ok_or(OcrError::ImageTooLarge)?;
        if source_start
            .checked_add(source_len)
            .is_none_or(|end| end > source.len())
        {
            return Err(OcrError::ImageDecode);
        }
        let dest_row = usize::try_from(source_y - y).map_err(|_| OcrError::ImageTooLarge)?;
        let dest_start = dest_row
            .checked_mul(usize::try_from(w).map_err(|_| OcrError::ImageTooLarge)?)
            .and_then(|v| v.checked_mul(3))
            .ok_or(OcrError::ImageTooLarge)?;
        for column in 0..usize::try_from(w).map_err(|_| OcrError::ImageTooLarge)? {
            let source_at = source_start + column * samples;
            let dest_at = dest_start + column * 3;
            match color {
                ColorType::Grayscale | ColorType::GrayscaleAlpha => {
                    let gray = source[source_at];
                    pixels[dest_at..dest_at + 3].fill(gray);
                }
                ColorType::Rgb | ColorType::Rgba => {
                    pixels[dest_at..dest_at + 3].copy_from_slice(&source[source_at..source_at + 3]);
                }
                ColorType::Indexed => unreachable!("expanded above"),
            }
        }
    }

    let crop = RgbImage::from_raw(w, h, pixels).ok_or(OcrError::ImageDecode)?;
    Ok((crop, rows_decoded))
}

fn decode_png_region(bytes: &[u8], x: u32, y: u32, w: u32, h: u32) -> Result<RgbImage, OcrError> {
    decode_png_region_with_rows(bytes, x, y, w, h).map(|(crop, _)| crop)
}

/// True when a crop is predominantly light marks over a dark ground.
///
/// Integer BT.601 weights keep the decision deterministic across platforms;
/// the 128 threshold and alternatives are documented where normalization is
/// wired into `recognize_pixels`.
fn light_text_on_dark(img: &RgbImage) -> bool {
    let pixels = u64::from(img.width()) * u64::from(img.height());
    if pixels == 0 {
        return false;
    }
    let sum: u64 = img
        .pixels()
        .map(|p| {
            (77u64 * u64::from(p[0]) + 150u64 * u64::from(p[1]) + 29u64 * u64::from(p[2])) >> 8
        })
        .sum();
    sum < pixels * 128
}

fn inverted(img: &RgbImage) -> RgbImage {
    let mut out = img.clone();
    for p in out.pixels_mut() {
        p.0 = [255 - p[0], 255 - p[1], 255 - p[2]];
    }
    out
}

fn normalized_polarity(img: &RgbImage) -> std::borrow::Cow<'_, RgbImage> {
    if light_text_on_dark(img) {
        std::borrow::Cow::Owned(inverted(img))
    } else {
        std::borrow::Cow::Borrowed(img)
    }
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

/// Joins one recognizer chunk across the split decision made from the source
/// pixels. Kept separate so the exact hardware strings can pin what this
/// heuristic can fix (an inserted space) without pretending a model-free unit
/// test can correct characters the recognizer itself read incorrectly.
fn append_recognized_part(text: &mut String, part: &str, separated: bool) {
    if separated
        && !text.is_empty()
        && !part.is_empty()
        && !text.ends_with(' ')
        && !part.starts_with(' ')
    {
        text.push(' ');
    }
    text.push_str(part);
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
    // Every interior run of quiet columns, as (start, end_exclusive). Keep
    // even narrow runs for the line's own letter-spacing statistic; the old
    // height floor is applied only after that statistic is known.
    let mut all_runs: Vec<(usize, usize)> = Vec::new();
    let mut run_start: Option<usize> = None;
    for (x, v) in profile.iter().enumerate() {
        if *v <= quiet_at {
            run_start.get_or_insert(x);
        } else if let Some(st) = run_start.take() {
            if st > 0 {
                all_runs.push((st, x));
            }
        }
    }
    // A run still open here is the trailing margin, not spacing between
    // glyphs, and deliberately does not participate in the statistic.

    // A word gap is about a quarter of the text height wide. On deliberately
    // letter-spaced small caps, however, ordinary inter-letter runs can also
    // clear that absolute floor. Six or more interior runs are enough to
    // establish the line's own spacing: require a word gap to be at least
    // 1.5x its median. Sparse lines retain the old rule, so a line exposing
    // only a few genuine word gaps is not reclassified against itself.
    let height_floor = ((line_height / 4) as usize).max(3);
    let relative_floor = if all_runs.len() >= 6 {
        let mut widths: Vec<usize> = all_runs.iter().map(|(st, end)| end - st).collect();
        widths.sort_unstable();
        (widths[widths.len() / 2] * 3).div_ceil(2)
    } else {
        0
    };
    let min_gap = height_floor.max(relative_floor);
    let runs: Vec<(usize, usize)> = all_runs
        .into_iter()
        .filter(|(st, end)| end - st >= min_gap)
        .collect();

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

/// Removes repeated detections caused by the overlap band between tiles.
/// Returns bare source-coordinate boxes only after tile provenance has served
/// its purpose, so two genuinely separate detections from one tile cannot be
/// mistaken for a seam duplicate.
fn dedupe_tile_boxes(mut boxes: Vec<TileDetection>) -> Vec<(u32, u32, u32, u32)> {
    boxes.sort_by_key(|b| (b.rect.1, b.rect.0, b.tile_id));
    let mut kept: Vec<TileDetection> = Vec::new();
    'candidate: for candidate in boxes {
        for existing in &mut kept {
            if existing.tile_id == candidate.tile_id
                || contained_overlap(existing.rect, candidate.rect) < TILE_DEDUP_CONTAINED_FRACTION
            {
                continue;
            }
            if tile_fit(candidate) > tile_fit(*existing) {
                *existing = candidate;
            }
            continue 'candidate;
        }
        kept.push(candidate);
    }
    let mut rects: Vec<_> = kept.into_iter().map(|b| b.rect).collect();
    rects.sort_by_key(|b| (b.1, b.0));
    rects
}

fn contained_overlap(a: (u32, u32, u32, u32), b: (u32, u32, u32, u32)) -> f64 {
    let ax1 = a.0.saturating_add(a.2);
    let ay1 = a.1.saturating_add(a.3);
    let bx1 = b.0.saturating_add(b.2);
    let by1 = b.1.saturating_add(b.3);
    let iw = ax1.min(bx1).saturating_sub(a.0.max(b.0));
    let ih = ay1.min(by1).saturating_sub(a.1.max(b.1));
    let intersection = u64::from(iw) * u64::from(ih);
    let smaller = (u64::from(a.2) * u64::from(a.3)).min(u64::from(b.2) * u64::from(b.3));
    if smaller == 0 {
        0.0
    } else {
        intersection as f64 / smaller as f64
    }
}

/// Preference key for duplicate copies. Clearance is the conservative proxy
/// for "how much of the line was inside this tile": a zero means detector
/// expansion met an edge and may have clipped glyphs. Area then prefers the
/// longer copy when both candidates meet an edge.
fn tile_fit(b: TileDetection) -> (u32, u64) {
    let (x, y, w, h) = b.rect;
    let (tx, ty, tw, th) = b.tile_rect;
    let clearance = x
        .saturating_sub(tx)
        .min(y.saturating_sub(ty))
        .min(tx.saturating_add(tw).saturating_sub(x.saturating_add(w)))
        .min(ty.saturating_add(th).saturating_sub(y.saturating_add(h)));
    (clearance, u64::from(w) * u64::from(h))
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

/// Mean detector probability inside an axis-aligned component box. PaddleOCR
/// uses `box_score_fast` over the minimum-area polygon; components give this
/// dependency-free implementation an axis-aligned polygon, but the 0.6 score
/// gate and the probability values being averaged are the same.
fn component_box_score(
    probabilities: &[f32],
    map_width: usize,
    b: (u32, u32, u32, u32),
) -> f32 {
    let (x, y, w, h) = b;
    if w == 0 || h == 0 || map_width == 0 {
        return 0.0;
    }
    let map_height = probabilities.len() / map_width;
    let x0 = (x as usize).min(map_width);
    let y0 = (y as usize).min(map_height);
    let x1 = x0.saturating_add(w as usize).min(map_width);
    let y1 = y0.saturating_add(h as usize).min(map_height);
    let mut sum = 0.0f64;
    let mut count = 0usize;
    for row in y0..y1 {
        for col in x0..x1 {
            sum += probabilities[row * map_width + col] as f64;
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        (sum / count as f64) as f32
    }
}

/// Expands a mask-space box and maps it to original-image pixels.
///
/// PaddleOCR's DB postprocess grows a polygon by
/// `area * unclip_ratio / perimeter`. The components path has axis-aligned
/// rectangles rather than OpenCV contours, so expanding every edge by that
/// exact distance is the corresponding rectangle operation. The ratio is the
/// PaddleOCR inference default 1.5, not a hand-tuned x/y percentage.
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
    let area = f64::from(w) * f64::from(h);
    let perimeter = 2.0 * f64::from(w.saturating_add(h));
    let margin = if perimeter > 0.0 {
        (area * DET_UNCLIP_RATIO / perimeter).ceil() as u32
    } else {
        0
    };
    let x0 = x.saturating_sub(margin);
    let y0 = y.saturating_sub(margin);
    let x1 = (x.saturating_add(w).saturating_add(margin)).min(dw);
    let y1 = (y.saturating_add(h).saturating_add(margin)).min(dh);
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
    fn letter_spaced_caps_use_the_lines_own_median_gap() {
        // The hardware examples were deliberately letter-spaced small caps.
        // Six-column gaps are wide enough to clear the old height/4 rule at
        // this size, so it called whichever one happened to sit near a chunk
        // division a word boundary. Relative to this line they are ordinary:
        // the 14-column runs are the actual spaces.
        let mut profile = vec![9.0f32; 600];
        for start in (10usize..590).step_by(20) {
            for x in start..start + 6 {
                profile[x] = 0.0;
            }
        }
        for (start, end) in [(193usize, 207usize), (393usize, 407usize)] {
            for x in start..end {
                profile[x] = 0.0;
            }
        }
        let cuts = choose_cuts(&profile, 3, 16);
        assert_eq!(cuts.len(), 2);
        for (at, is_gap) in cuts {
            assert!(is_gap, "the real word gap at {at} was not recognized");
            assert!(
                (193..207).contains(&at) || (393..407).contains(&at),
                "cut {at} chose ordinary letter spacing"
            );
        }
    }

    #[test]
    fn letter_spacing_does_not_insert_the_reported_fixture_spaces() {
        // These are the exact gap-family strings from hardware. This test is
        // intentionally honest about scope: false boundaries remove only the
        // spaces this join heuristic invented. It does not claim to turn the
        // model's C/L, P/n, "tor", or "contig" readings into other letters.
        let fixtures: &[(&[&str], &str)] = &[
            (&["PRI", "VACY"], "PRIVACY"),
            (&["PLAN", "NED. BROWS", "ER"], "PLANNED. BROWSER"),
            (&["CONNE", "C", "LON"], "CONNECLON"),
            (&["Nord", "VPn"], "NordVPn"),
            (
                &["-WireGuard contig", "uration."],
                "-WireGuard contiguration.",
            ),
        ];
        for (parts, expected) in fixtures {
            let mut joined = String::new();
            for part in *parts {
                append_recognized_part(&mut joined, part, false);
            }
            assert_eq!(&joined, expected);
        }
        // A genuine boundary still survives the same join helper.
        let mut words = "small".to_string();
        append_recognized_part(&mut words, "caps", true);
        assert_eq!(words, "small caps");
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
    fn polarity_is_decided_for_each_crop_at_mean_luminance_128() {
        let light = RgbImage::from_pixel(40, 20, image::Rgb([240, 240, 240]));
        let dark = RgbImage::from_pixel(40, 20, image::Rgb([15, 15, 15]));
        assert!(!light_text_on_dark(&light));
        assert!(light_text_on_dark(&dark));

        // Exact threshold: 127 is inverted and 128 is retained.
        assert!(light_text_on_dark(&RgbImage::from_pixel(
            1,
            1,
            image::Rgb([127, 127, 127]),
        )));
        assert!(!light_text_on_dark(&RgbImage::from_pixel(
            1,
            1,
            image::Rgb([128, 128, 128]),
        )));

        let normalized = inverted(&dark);
        assert_eq!(*normalized.get_pixel(0, 0), image::Rgb([240, 240, 240]));
        // A second crop makes its own choice rather than inheriting a mode.
        assert!(!light_text_on_dark(&light));

        // Pin the shared-pixel wiring as well as the arithmetic: both detector
        // and recognizer crops must come from the normalized per-crop image.
        let src = include_str!("lib.rs");
        let start = src.find("fn recognize_pixels(").unwrap();
        let end = src[start..].find("fn detect_tiled(").unwrap() + start;
        let body = &src[start..end];
        assert!(body.contains("normalized_polarity(img)"));
        assert!(body.contains("detect_tiled(ocr_img)"));
        assert!(body.contains("crop_imm(ocr_img"));
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
    fn a_text_line_straddling_a_tile_seam_is_kept_once() {
        // Synthetic detector fixture for one source line in the 96px overlap
        // of tiles 0 (x=0..960) and 1 (x=864..1500). Expansion jitter makes
        // the source boxes differ slightly, but 86/98 of the smaller box is
        // contained by the other. The copy with 10px clearance from tile 0's
        // edge wins over the copy clipped at tile 1's left edge.
        let line_from_left_tile = TileDetection {
            rect: (850, 100, 100, 30),
            tile_id: 0,
            tile_rect: (0, 0, 960, 600),
        };
        let same_line_from_right_tile = TileDetection {
            rect: (864, 101, 98, 29),
            tile_id: 1,
            tile_rect: (864, 0, 636, 600),
        };
        let once = dedupe_tile_boxes(vec![line_from_left_tile, same_line_from_right_tile]);
        assert_eq!(once, vec![line_from_left_tile.rect]);
    }

    #[test]
    fn tile_dedup_never_collapses_two_boxes_from_the_same_tile() {
        let a = TileDetection {
            rect: (100, 100, 300, 24),
            tile_id: 4,
            tile_rect: (0, 0, 960, 960),
        };
        let b = TileDetection {
            rect: (102, 101, 296, 23),
            tile_id: 4,
            tile_rect: (0, 0, 960, 960),
        };
        assert_eq!(dedupe_tile_boxes(vec![a, b]).len(), 2);
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
    fn db_box_score_and_unclip_match_the_paddleocr_defaults() {
        let probabilities = vec![0.6f32; 4 * 3];
        let score = component_box_score(&probabilities, 4, (1, 1, 2, 2));
        assert!((score - DET_BOX_THRESHOLD).abs() < f32::EPSILON);

        // area=200, perimeter=60, ratio=1.5 => distance=5 on every edge.
        assert_eq!(
            expand_and_map((10, 10, 20, 10), 100, 100, 1.0, 1.0, 100, 100),
            (5, 5, 30, 20)
        );
    }

    #[test]
    fn expand_and_map_scales_both_axes_by_the_same_factor() {
        // The regression this pins: the draft computed the x edge as
        // `x1 * sy.recip().recip() * sx` -- that is x1 * sy * sx -- so x was
        // mapped through the Y ratio as well and every box drifted
        // horizontally, worse the further from the origin.
        //
        // Both axes must use the SAME factor, here map_to_canvas(8.0) divided
        // by scale(0.5), i.e. 16. The upstream unclip is isotropic for this
        // square; this still asserts mapped coordinates rather than relying on
        // equal extents to prove the scale.
        let m2c = DET_SIDE as f64 / 120.0; // 8.0
        let b = expand_and_map((10, 10, 20, 20), 120, 120, m2c, 0.5, 4000, 4000);
        // area=400, perimeter=80, ratio=1.5 => margin=ceil(7.5)=8.
        // Both axes are 2..38 in map space, then *16 => 32..608.
        assert_eq!(b, (32, 32, 576, 576), "both axes must map through *16");
        // Under the old expression the x edge would have been scaled by an
        // extra factor and nx0 could not have been exactly 2*16.
        assert_eq!(b.0, 2 * 16);
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
        assert!(
            CLS_MODEL_BYTES.len() > 500_000,
            "cls model is {} bytes -- not the real weights",
            CLS_MODEL_BYTES.len()
        );
        // Loading is what proves the bytes are a usable graph and not just a
        // file of the right size.
        let engine = OcrEngine::load_embedded().expect("embedded models must load");
        assert!(!engine.dict.is_empty());
        assert!(
            engine.classifier_available(),
            "embedded cls degraded: {:?}",
            engine.classifier_diagnostic()
        );
    }

    #[test]
    fn a_broken_classifier_degrades_instead_of_failing_engine_load() {
        let (cls, diagnostic) = optional_classifier(
            || {
                load_onnx_bytes(
                    b"not an ONNX graph",
                    f32::fact([1, 3, CLS_HEIGHT as i32, CLS_WIDTH as i32]).into(),
                )
            },
            "test cls",
        );
        assert!(cls.is_none());
        assert!(
            diagnostic.as_deref().is_some_and(|d| d.contains("test cls")),
            "the degraded reason must survive for diagnostics: {diagnostic:?}"
        );
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

    /// A synthetic Liberation Sans raster at 20 source pixels, containing the
    /// exact f-heavy phrase from the hardware report. Kept as base64 inside
    /// this Rust test rather than as an opaque binary fixture; the dark-mode
    /// fixture is rendered from the same pixels by exact channel inversion.
    const F_HEAVY_LINE_PNG: &str = concat!(
        "iVBORw0KGgoAAAANSUhEUgAAAVQAAAAUCAAAAAD31pqxAAAFiUlEQVRYw+1Ya0wUVxg9K7sLi7viq+AuyAqtIb4osTStVWMDRDT4",
        "hLartooKtaCtolGxTXw2rrY2Wkt9RBMk0Na0NloSjTH9YQ2+UGtJG6FRCYiWpSg+ijwE4fTH7GN2ZnYdAf9x/kzud893vjPf3Dt7",
        "dzREL3oafbqRO0dzRyn8Q4R2jap81USVbup6Rl0q9Px4ZlMfrLYGRs26CAAPc4bpLZmOZyQ8ynz8ebKa0n6J228+753EJQd2yYas",
        "qkSoK6B/NAxDyvr3tUF/kk/GIm3rYl3UfdecDbcVMi5jKVXBH7EWJ9WJdEn9xVUVoH1GzzdU530MpKatO4E9V79YCyTbtn7lN6MV",
        "JnWP0x/xcnfXinobPVrVCcVWt34Z28845ssOMiexjWSnwUrGmVpJ8pXQTifLhspVFn3MHpKsWxqpGzzzEpkMAB+R1QstukHTS0na",
        "8G9SULGIIsBFFIVLZw3SWT+oIlMAoIQpeECyHYlKIh6PLjcOzkXjWqs+Ymenbxtz8WBJqOGN0qYVlr7jfleqaoNDnOfRVA3lpi7C",
        "vH37Z2OZu8m68WwJSCRJLkSl+zZSJto3ROMgWW8NyS2yRwT+xvN2pB4rY02ocU3B1vDAEnI+5k21/yWiCHASReErQZYtB9aZQu/x",
        "wnxsONYgbqpcROrRBgfTkZx14dxk5Pu2kY6kzVcLgiKn5V75uX9Ym0JVGxziPI9mN5saPI4kV6Y9dY53I4/XsZAkuRG/um9jYgdZ",
        "rY8is7WXSdaY4skS5JJMx1GS5QFvkosxuYNeFAECURTeO/Y0yTzkkdtwkhQ3VS4i9WiDgxmYS7IS03zbyEA2yffwDskVOKdQVXg6",
        "7jyRploov1N1t+pDgZ2u4Zk1E7LQiL4AACMa3bysPoB1/OnbEUdiI+oA3VunHhuFl8ovYbMAjBh3tmGQBul9AEopzrePKJydDbR3",
        "jES1giO5iMSjE+kAooNdRz25DQCpAIZjJoAYOAClquI8qaYKKB+pttQOX3DoH9focPLoYi0AjVDQeQWAWACIxq36e1fNZrPZfAo1",
        "wkTdo1EaAIjBdQAxAGQUAV7hokkD9IZEPFX0JBXx9uhCJADo2uHLBoBwAFqEA9ChHYpVvfO8NVVAeaUuH513tEgzda8VADdtmfKT",
        "CejnXKH/iX5W+wFAMFobEbdNiFiES5NzWRvQBCAEgIwiQBz+bFv8rqjAa5nKTqUiYo8e6LxGchtuipuoVNU7z1uzy01FQsKTku8K",
        "k67pwcz8T3YFAIjU3gIAVGK4m9YCAM0INgFTvPKNaHK6cz0BGUUWbv166Gkj8EhKaVNkiz36hNyGDIpVVeT5g89/VIFJBVk3y4CV",
        "+fZvAgBA/9qlZgCdZ4ZGukkVQpejwwb//RAA7romhgysIACUa5x7DjKKLFzXEm8EcMYzKWzPKkW22KNPyG3IIK+qLu+5m3oxvFCY",
        "0+Ho7hWfOqMZzTsAHKgVbZR8AHfOjxyCd1t3ALgbO901k+ooBlB2KaG/KyKjSMNhmmoAZYVoBQLQAsCMCgCFimyRRz+Q25BCXlVd",
        "nj8obv/4gR+ejdNcKZgQh7XoXAcAyB2wuGjTH2Mrfhyz2kN8Mntq84G29cCmE3bHpNr9DctdM5uPz18eU73H6Pl1llGkYUPK8ay3",
        "y7/9fsaJwzOisb1q4usL9q3aEVx8waTEFnn0A7kNKeRV1eX5heJBqyHn5eCQV+2N9HwYrCIbV1t14csa3KyZuJ9j1o84RJKO7KHa",
        "/jNK3cdP1iwya0PnlJPMwA16U8TnVFG4ft5LIQkl3Gwc4mhLMww4QhaMNIQteWiZoCTi8Sg+p94gyZBRvm0Il40oIXkQhxWq2uBQy",
        "AsZpf6cqun9ntrz6M731F74QG9TXwB6m/oC8D9UHUIJRWOCpQAAAABJRU5ErkJggg==",
    );

    fn decode_test_base64(input: &str) -> Vec<u8> {
        let value = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => u32::from(c - b'A'),
                b'a'..=b'z' => u32::from(c - b'a' + 26),
                b'0'..=b'9' => u32::from(c - b'0' + 52),
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid fixture base64"),
            }
        };
        let mut out = Vec::with_capacity(input.len() / 4 * 3);
        let mut acc = 0u32;
        let mut bits = 0u32;
        for c in input.bytes().take_while(|c| *c != b'=') {
            acc = (acc << 6) | value(c);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    /// A 40,002,000-pixel PNG built row by row, so the test fixture itself
    /// never allocates the whole image. The known OCR line sits in the first
    /// 20 rows; everything below it is white.
    fn larger_than_old_guard_with_text_band() -> Vec<u8> {
        use std::io::Write;

        const WIDTH: u32 = 2_000;
        const HEIGHT: u32 = 20_001;
        assert!(u64::from(WIDTH) * u64::from(HEIGHT) > MAX_PIXELS);
        let band = image::load_from_memory(&decode_test_base64(F_HEAVY_LINE_PNG))
            .expect("decode text band")
            .to_luma8();
        assert_eq!(band.height(), 20);
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, WIDTH, HEIGHT);
            encoder.set_color(png::ColorType::Grayscale);
            encoder.set_depth(png::BitDepth::Eight);
            encoder.set_compression(png::Compression::Fastest);
            let mut writer = encoder.write_header().expect("write tall PNG header");
            let mut stream = writer.stream_writer().expect("start tall PNG stream");
            let mut row = vec![255u8; WIDTH as usize];
            for source_y in 0..HEIGHT {
                row.fill(255);
                if source_y < band.height() {
                    let start = source_y as usize * band.width() as usize;
                    let end = start + band.width() as usize;
                    row[..band.width() as usize].copy_from_slice(&band.as_raw()[start..end]);
                }
                stream.write_all(&row).expect("write tall PNG row");
            }
            stream.finish().expect("finish tall PNG stream");
        }
        bytes
    }

    #[test]
    fn region_streams_a_text_crop_from_beyond_the_old_whole_image_guard() {
        let png = larger_than_old_guard_with_text_band();
        let (crop, rows) = decode_png_region_with_rows(&png, 0, 0, 340, 20)
            .expect("small crop from a 40+ MP page must decode");
        assert_eq!(crop.dimensions(), (340, 20));
        assert_eq!(rows, 20, "the decoder materialised rows below the crop band");
        assert_eq!(
            REGION_DECODER_ALLOC_LIMIT,
            64 * 1024 * 1024,
            "the explicit decoder allocation ceiling changed"
        );

        let engine = OcrEngine::load_embedded().expect("embedded models must load");
        let regions = engine
            .recognize_region(&png, 0, 0, 340, 20)
            .expect("OCR must run on the streamed crop");
        let text = regions
            .iter()
            .map(|region| region.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            text.contains("before features information"),
            "the >40 MP region did not return its selected text: {text:?}"
        );

        match decode_png_region(&png, 0, 0, 2_000, 20_001) {
            Err(OcrError::ImageTooLarge) => {}
            other => panic!("a >40 MP crop gave {other:?}, wanted ImageTooLarge"),
        }
    }

    #[test]
    fn f_heavy_text_recognizes_on_both_polarities_without_f_to_t() {
        let engine = OcrEngine::load_embedded().expect("embedded models must load");
        let light = image::load_from_memory(&decode_test_base64(F_HEAVY_LINE_PNG))
            .expect("decode rendered fixture")
            .to_rgb8();
        let dark = inverted(&light);
        assert!(!light_text_on_dark(&light));
        assert!(
            light_text_on_dark(&dark),
            "dark fixture must take inversion path"
        );

        let light_text = engine
            .recognize_line(normalized_polarity(&light).as_ref())
            .expect("recognize dark-on-light fixture");
        let dark_text = engine
            .recognize_line(normalized_polarity(&dark).as_ref())
            .expect("recognize inverted light-on-dark fixture");
        assert_eq!(light_text, "s20 before features information");
        assert_eq!(dark_text, light_text, "polarity changed recognition");
        for substitution in ["betore", "teatures", "intormation", " tor "] {
            assert!(
                !dark_text.contains(substitution),
                "inverted path retained f->t substitution {substitution:?}: {dark_text:?}"
            );
        }
    }

    #[test]
    fn an_upside_down_line_reads_correctly_with_cls_and_garbles_without_it() {
        let engine = OcrEngine::load_embedded().expect("embedded models must load");
        let upright = image::load_from_memory(&decode_test_base64(F_HEAVY_LINE_PNG))
            .expect("decode rendered fixture")
            .to_rgb8();
        let upside_down = image::imageops::rotate180(&upright);

        let oriented = engine.orient_line(&upside_down);
        assert_eq!(
            oriented.as_ref(),
            &upright,
            "class 180 did not rotate the crop back upright"
        );
        let with_cls = engine
            .recognize_line(oriented.as_ref())
            .expect("recognize classifier-oriented fixture");
        let without_cls = engine
            .recognize_line(&upside_down)
            .expect("recognize raw upside-down fixture");
        assert_eq!(with_cls, "s20 before features information");
        assert_ne!(
            without_cls, with_cls,
            "the no-cls control unexpectedly read the upside-down fixture: {without_cls:?}"
        );
    }
}
