//! Per-region text colour: which colour are the glyph strokes, and what is
//! behind them.
//!
//! PROVENANCE. This is a Rust port of `engine/color_detect.py` from XLiteOCR
//! (EdgeXene, Apache-2.0), the one piece of original algorithm in that product.
//! Both projects are Apache-2.0 and first-party, so this is internal reuse
//! rather than a third-party dependency; it adds nothing to the dependency
//! budget and nothing to THIRD_PARTY_LICENSES.md. The algorithm and the
//! reasoning behind its two unusual choices are carried over verbatim in the
//! comments below, because those choices are the whole value: a naive
//! implementation gets the common cases right and the interesting cases wrong.
//!
//! Why it exists here. The leak scan reports what is READABLE in a picture.
//! Colour answers a different and adjacent question: how readable, and against
//! what. Text whose stroke colour is nearly its background colour is either an
//! accessibility failure or a deliberate attempt to hide something, and neither
//! is visible from the recognised string alone.
//!
//! Everything in this module is pure arithmetic over pixels already in memory.
//! No new dependency, no network, no files.

use image::RgbImage;

/// Basic CSS colour anchors for nearest-name lookup. Deliberately small and
/// obvious: the name is a human label on a report line, not a colour science
/// claim, and a longer table makes the nearest-match answer less predictable
/// rather than more useful.
const NAMED_COLORS: [(&str, [u8; 3]); 14] = [
    ("black", [0, 0, 0]),
    ("white", [255, 255, 255]),
    ("gray", [128, 128, 128]),
    ("red", [220, 20, 20]),
    ("orange", [255, 140, 0]),
    ("yellow", [240, 220, 20]),
    ("green", [20, 160, 40]),
    ("teal", [0, 128, 128]),
    ("blue", [30, 60, 220]),
    ("navy", [0, 0, 128]),
    ("purple", [128, 0, 160]),
    ("magenta", [220, 20, 200]),
    ("pink", [255, 150, 190]),
    ("brown", [140, 80, 40]),
];

/// The dark Otsu class must cover this much of the crop before it is allowed to
/// be the background rather than the ink.
const DARK_BG_AREA_FRAC: f32 = 0.65;
/// ...and be this colour-uniform. A solid banner has a low spread; text does
/// not.
const DARK_BG_MAX_STD: f32 = 25.0;

/// k-means cluster count. Two: glyph body and anti-aliasing fringe.
const KMEANS_K: usize = 2;
/// Fixed iteration cap. Convergence on a two-cluster RGB problem is fast, and a
/// fixed bound keeps the function's cost predictable on adversarial input.
const KMEANS_ITERS: usize = 12;

/// Upper bound on pixels actually examined per region.
///
/// Not in the Python original, which only ever sees detector line crops. Here
/// the caller could hand over any rectangle, and this runs in the browser
/// process, so the cost is bounded by construction rather than by trusting the
/// caller. Above this the crop is strided, which changes nothing that matters:
/// this estimates two dominant colours, and a regular subsample of a text line
/// has the same two dominant colours as the whole of it.
const MAX_SAMPLE_PX: usize = 200_000;

/// Luma weights, Rec. 601, matching the original.
const LUMA: [f32; 3] = [0.299, 0.587, 0.114];

/// No `Eq`: `contrast` is an `f32`. `PartialEq` is enough for the determinism
/// test, which compares two results computed from identical input, so the
/// values are bit-identical rather than merely close.
#[derive(Debug, Clone, PartialEq)]
pub struct RegionColor {
    /// Dominant colour of the glyph strokes.
    pub rgb: [u8; 3],
    /// `#rrggbb`, for display.
    pub hex: String,
    /// Nearest entry in `NAMED_COLORS`.
    pub name: &'static str,
    /// Mean colour of whatever the strokes sit on.
    pub background_rgb: [u8; 3],
    /// Euclidean RGB distance between stroke and background, 0.0 to ~441.7.
    ///
    /// This is the number the leak scan actually wants. It is reported raw
    /// rather than as a boolean so the threshold lives with the policy that
    /// uses it, not buried in here.
    pub contrast: f32,
}

impl RegionColor {
    /// A deliberately conservative "these are the same colour" test.
    ///
    /// 32 is roughly 7% of the maximum RGB distance: comfortably past JPEG
    /// ringing and anti-aliasing spill, comfortably short of any colour pair a
    /// person would call legible.
    pub fn is_low_contrast(&self) -> bool {
        self.contrast < 32.0
    }
}

/// Dominant stroke colour of one rectangular region.
///
/// Returns `None` when the rectangle is empty or falls outside the image, which
/// is a caller error rather than a colour, and is not worth inventing a black
/// pixel for.
pub fn region_color(img: &RgbImage, x: u32, y: u32, w: u32, h: u32) -> Option<RegionColor> {
    let (iw, ih) = img.dimensions();
    let x0 = x.min(iw);
    let y0 = y.min(ih);
    let x1 = x.saturating_add(w).min(iw);
    let y1 = y.saturating_add(h).min(ih);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }

    // Stride so that at most MAX_SAMPLE_PX pixels are touched.
    let total = ((x1 - x0) as usize) * ((y1 - y0) as usize);
    let stride = if total > MAX_SAMPLE_PX {
        // ceil(sqrt(total / MAX)) applied on both axes.
        let ratio = (total as f64 / MAX_SAMPLE_PX as f64).sqrt().ceil() as u32;
        ratio.max(1)
    } else {
        1
    };

    let mut px: Vec<[f32; 3]> = Vec::new();
    let mut gray: Vec<u8> = Vec::new();
    let mut yy = y0;
    while yy < y1 {
        let mut xx = x0;
        while xx < x1 {
            let p = img.get_pixel(xx, yy).0;
            let rgb = [p[0] as f32, p[1] as f32, p[2] as f32];
            let g = rgb[0] * LUMA[0] + rgb[1] * LUMA[1] + rgb[2] * LUMA[2];
            px.push(rgb);
            gray.push(g as u8);
            xx += stride;
        }
        yy += stride;
    }
    if px.is_empty() {
        return None;
    }

    let t = otsu_threshold(&gray);
    let mut dark: Vec<[f32; 3]> = Vec::new();
    let mut light: Vec<[f32; 3]> = Vec::new();
    for (i, p) in px.iter().enumerate() {
        if gray[i] <= t {
            dark.push(*p);
        } else {
            light.push(*p);
        }
    }

    // Stroke is whichever class the background is not. Default to the darker
    // class -- ink on paper is the common case -- and only flip when the dark
    // class is a solid dark banner.
    //
    // The two rejected alternatives are the point of this function. Pixel-count
    // majority is wrong because a bold heading makes the stroke the majority.
    // Edge or corner sampling is wrong because a tight detector crop clips
    // through the glyphs, so the "edge" is ink. Area plus uniformity is what
    // survives real crops.
    let (stroke, background) = if background_is_dark(&dark, &light, px.len()) {
        (&light, &dark)
    } else {
        (&dark, &light)
    };

    let bg_ref = mean_rgb(background);
    let dominant = kmeans_dominant(stroke, bg_ref);

    let rgb = [
        dominant[0].round().clamp(0.0, 255.0) as u8,
        dominant[1].round().clamp(0.0, 255.0) as u8,
        dominant[2].round().clamp(0.0, 255.0) as u8,
    ];
    let bg = bg_ref.unwrap_or([0.0, 0.0, 0.0]);
    let background_rgb = [
        bg[0].round().clamp(0.0, 255.0) as u8,
        bg[1].round().clamp(0.0, 255.0) as u8,
        bg[2].round().clamp(0.0, 255.0) as u8,
    ];
    let contrast = dist(
        [rgb[0] as f32, rgb[1] as f32, rgb[2] as f32],
        [
            background_rgb[0] as f32,
            background_rgb[1] as f32,
            background_rgb[2] as f32,
        ],
    );

    Some(RegionColor {
        rgb,
        hex: format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2]),
        name: nearest_name(rgb),
        background_rgb,
        contrast,
    })
}

/// Classic Otsu threshold over a 0-255 histogram.
///
/// Returns the level maximising between-class variance; pixels `<= t` are the
/// dark class. Falls back to mid-grey on an empty input, matching the original.
fn otsu_threshold(gray: &[u8]) -> u8 {
    if gray.is_empty() {
        return 128;
    }
    let mut hist = [0u32; 256];
    for g in gray {
        hist[*g as usize] += 1;
    }
    let total = gray.len() as f64;
    let sum_all: f64 = (0..256).map(|i| i as f64 * hist[i] as f64).sum();

    let mut sum_b = 0f64;
    let mut w_b = 0f64;
    let mut max_var = -1f64;
    let mut threshold = 128u8;
    for t in 0..256 {
        w_b += hist[t] as f64;
        if w_b == 0.0 {
            continue;
        }
        let w_f = total - w_b;
        if w_f == 0.0 {
            break;
        }
        sum_b += t as f64 * hist[t] as f64;
        let m_b = sum_b / w_b;
        let m_f = (sum_all - sum_b) / w_f;
        let var_between = w_b * w_f * (m_b - m_f) * (m_b - m_f);
        if var_between > max_var {
            max_var = var_between;
            threshold = t as u8;
        }
    }
    threshold
}

/// Is the DARK Otsu class the background, i.e. light text on a dark ground?
///
/// Only when it both dominates the crop by area and is colour-uniform. See the
/// comment at the call site for why the obvious alternatives fail.
fn background_is_dark(dark: &[[f32; 3]], light: &[[f32; 3]], n_total: usize) -> bool {
    if dark.is_empty() {
        return false;
    }
    if light.is_empty() {
        return true;
    }
    let dark_frac = dark.len() as f32 / n_total.max(1) as f32;
    // Per-channel standard deviation, averaged over the three channels, exactly
    // as the original's `dark.std(axis=0).mean()`.
    let mean = mean_rgb(dark).unwrap_or([0.0; 3]);
    let mut acc = [0f32; 3];
    for p in dark {
        for c in 0..3 {
            let d = p[c] - mean[c];
            acc[c] += d * d;
        }
    }
    let n = dark.len() as f32;
    let std_mean = (0..3).map(|c| (acc[c] / n).sqrt()).sum::<f32>() / 3.0;
    dark_frac > DARK_BG_AREA_FRAC && std_mean < DARK_BG_MAX_STD
}

/// Two-cluster k-means over stroke pixels, returning the cluster centre
/// FURTHEST from the background.
///
/// Furthest, not most populous: the fringe where a glyph meets the paper is a
/// blend of the two, and on thin text there can be more fringe than solid body.
/// Taking the far cluster returns the actual ink colour instead of a muddy
/// average of ink and paper.
///
/// Seeding is deterministic -- the darkest and lightest stroke pixel by luma --
/// so the same crop always produces the same answer. A random seed would make
/// the leak report flicker between runs on identical input.
fn kmeans_dominant(pixels: &[[f32; 3]], background: Option<[f32; 3]>) -> [f32; 3] {
    if pixels.is_empty() {
        return [0.0, 0.0, 0.0];
    }
    if pixels.len() <= KMEANS_K {
        return mean_rgb(pixels).unwrap_or([0.0; 3]);
    }

    let mut order: Vec<usize> = (0..pixels.len()).collect();
    order.sort_by(|a, b| {
        luma(pixels[*a])
            .partial_cmp(&luma(pixels[*b]))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut centers = [[0f32; 3]; KMEANS_K];
    for (c, center) in centers.iter_mut().enumerate() {
        // linspace(0, n-1, k): for k=2 this is the darkest and lightest pixel.
        let idx = c * (order.len() - 1) / (KMEANS_K - 1);
        *center = pixels[order[idx]];
    }

    let mut labels = vec![usize::MAX; pixels.len()];
    for _ in 0..KMEANS_ITERS {
        let mut changed = false;
        for (i, p) in pixels.iter().enumerate() {
            let mut best = 0usize;
            let mut best_d = f32::INFINITY;
            for (c, center) in centers.iter().enumerate() {
                let d = dist(*p, *center);
                if d < best_d {
                    best_d = d;
                    best = c;
                }
            }
            if labels[i] != best {
                labels[i] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
        for c in 0..KMEANS_K {
            let members: Vec<[f32; 3]> = pixels
                .iter()
                .zip(labels.iter())
                .filter(|(_, l)| **l == c)
                .map(|(p, _)| *p)
                .collect();
            if let Some(m) = mean_rgb(&members) {
                centers[c] = m;
            }
        }
    }

    match background {
        Some(bg) => {
            let mut best = centers[0];
            let mut best_d = -1f32;
            for center in &centers {
                let d = dist(*center, bg);
                if d > best_d {
                    best_d = d;
                    best = *center;
                }
            }
            best
        }
        None => {
            let mut counts = [0usize; KMEANS_K];
            for l in &labels {
                if *l < KMEANS_K {
                    counts[*l] += 1;
                }
            }
            let mut best = 0usize;
            for c in 1..KMEANS_K {
                if counts[c] > counts[best] {
                    best = c;
                }
            }
            centers[best]
        }
    }
}

fn nearest_name(rgb: [u8; 3]) -> &'static str {
    let p = [rgb[0] as f32, rgb[1] as f32, rgb[2] as f32];
    let mut best = "black";
    let mut best_d = f32::INFINITY;
    for (name, ref_rgb) in NAMED_COLORS.iter() {
        let r = [
            ref_rgb[0] as f32,
            ref_rgb[1] as f32,
            ref_rgb[2] as f32,
        ];
        let d = dist(p, r);
        if d < best_d {
            best_d = d;
            best = name;
        }
    }
    best
}

fn mean_rgb(pixels: &[[f32; 3]]) -> Option<[f32; 3]> {
    if pixels.is_empty() {
        return None;
    }
    let mut acc = [0f64; 3];
    for p in pixels {
        for c in 0..3 {
            acc[c] += p[c] as f64;
        }
    }
    let n = pixels.len() as f64;
    Some([
        (acc[0] / n) as f32,
        (acc[1] / n) as f32,
        (acc[2] / n) as f32,
    ])
}

fn luma(p: [f32; 3]) -> f32 {
    p[0] * LUMA[0] + p[1] * LUMA[1] + p[2] * LUMA[2]
}

fn dist(a: [f32; 3], b: [f32; 3]) -> f32 {
    let dr = a[0] - b[0];
    let dg = a[1] - b[1];
    let db = a[2] - b[2];
    (dr * dr + dg * dg + db * db).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paints `text_rgb` glyph-ish columns onto a `bg_rgb` field.
    fn synth(w: u32, h: u32, bg: [u8; 3], fg: [u8; 3], ink_cols: &[u32]) -> RgbImage {
        let mut img = RgbImage::from_pixel(w, h, image::Rgb(bg));
        for x in ink_cols {
            for y in 0..h {
                if *x < w {
                    img.put_pixel(*x, y, image::Rgb(fg));
                }
            }
        }
        img
    }

    #[test]
    fn dark_ink_on_light_paper_reads_as_the_ink() {
        let img = synth(40, 20, [255, 255, 255], [10, 10, 10], &[5, 6, 15, 16, 25, 26]);
        let c = region_color(&img, 0, 0, 40, 20).expect("region");
        assert_eq!(c.name, "black", "got {:?}", c);
        assert!(c.contrast > 200.0, "expected high contrast, got {}", c.contrast);
        assert!(!c.is_low_contrast());
    }

    /// The case pixel-count majority gets wrong: a bold heading where the ink
    /// is the MAJORITY of the crop. A naive "background is whichever class has
    /// more pixels" would call this red-on-white backwards. 60% coverage: past
    /// the majority a naive implementation would trip on, short of the banner
    /// threshold.
    #[test]
    fn bold_ink_covering_most_of_the_crop_is_still_the_ink() {
        let cols: Vec<u32> = (0..40).filter(|x| x % 5 < 3).collect();
        assert_eq!(cols.len(), 24, "test intends 60% ink coverage");
        let img = synth(40, 20, [255, 255, 255], [200, 30, 30], &cols);
        let c = region_color(&img, 0, 0, 40, 20).expect("region");
        assert_eq!(c.name, "red", "got {:?}", c);
    }

    /// Above DARK_BG_AREA_FRAC with both classes uniform, the image is
    /// genuinely ambiguous: 75% flat red behind 25% flat white is exactly what
    /// white text on a red banner looks like, and nothing in the pixels
    /// distinguishes it from very heavy red text. The algorithm resolves it as
    /// a banner. This test pins that as intended behaviour rather than leaving
    /// the boundary undocumented -- it is the reason the constant is 0.65 and
    /// not 0.50.
    #[test]
    fn past_the_banner_threshold_the_dominant_uniform_class_becomes_background() {
        let cols: Vec<u32> = (0..40).filter(|x| x % 4 != 0).collect();
        assert_eq!(cols.len(), 30, "test intends 75% coverage");
        let img = synth(40, 20, [255, 255, 255], [200, 30, 30], &cols);
        let c = region_color(&img, 0, 0, 40, 20).expect("region");
        assert_eq!(c.name, "white", "got {:?}", c);
        assert_eq!(c.background_rgb, [200, 30, 30]);
    }

    /// Light text on a solid dark banner: the dark class dominates AND is
    /// uniform, so it is background and the light class is the stroke.
    #[test]
    fn light_text_on_a_solid_dark_banner_flips() {
        let img = synth(40, 20, [12, 12, 14], [250, 250, 250], &[8, 9, 20, 21]);
        let c = region_color(&img, 0, 0, 40, 20).expect("region");
        assert_eq!(c.name, "white", "got {:?}", c);
        assert!(c.contrast > 200.0);
    }

    /// The reason this module exists: text hidden by matching the background.
    #[test]
    fn white_on_white_is_flagged_low_contrast() {
        let img = synth(40, 20, [255, 255, 255], [252, 252, 253], &[5, 6, 15, 16]);
        let c = region_color(&img, 0, 0, 40, 20).expect("region");
        assert!(
            c.is_low_contrast(),
            "expected low contrast, got {} ({:?})",
            c.contrast,
            c
        );
    }

    #[test]
    fn identical_input_gives_identical_output() {
        let img = synth(40, 20, [255, 255, 255], [30, 90, 200], &[4, 5, 12, 13, 30, 31]);
        let a = region_color(&img, 0, 0, 40, 20).expect("region");
        let b = region_color(&img, 0, 0, 40, 20).expect("region");
        assert_eq!(a, b, "k-means seeding must be deterministic");
    }

    #[test]
    fn degenerate_rectangles_return_none() {
        let img = synth(10, 10, [255, 255, 255], [0, 0, 0], &[3]);
        assert!(region_color(&img, 0, 0, 0, 10).is_none(), "zero width");
        assert!(region_color(&img, 0, 0, 10, 0).is_none(), "zero height");
        assert!(region_color(&img, 50, 50, 10, 10).is_none(), "outside");
    }

    /// A rectangle running off the edge is clipped, not rejected, and must not
    /// panic on the out-of-bounds arithmetic.
    #[test]
    fn oversize_rectangle_is_clipped() {
        let img = synth(10, 10, [255, 255, 255], [0, 0, 0], &[3, 4]);
        let c = region_color(&img, 5, 5, u32::MAX, u32::MAX).expect("clipped region");
        assert!(c.contrast >= 0.0);
    }

    #[test]
    fn otsu_splits_a_bimodal_histogram() {
        let mut v = vec![10u8; 100];
        v.extend(std::iter::repeat(240).take(100));
        let t = otsu_threshold(&v);
        assert!(t >= 10 && t < 240, "threshold {t} should separate the modes");
    }

    #[test]
    fn otsu_on_empty_input_is_mid_grey() {
        assert_eq!(otsu_threshold(&[]), 128);
    }

    #[test]
    fn nearest_name_hits_the_obvious_anchors() {
        assert_eq!(nearest_name([0, 0, 0]), "black");
        assert_eq!(nearest_name([255, 255, 255]), "white");
        assert_eq!(nearest_name([250, 10, 10]), "red");
    }

    /// The subsample path must agree with the full-scan path on a uniform
    /// pattern, or the guard changes answers instead of just bounding cost.
    #[test]
    fn subsampling_does_not_change_the_verdict() {
        // Wider than MAX_SAMPLE_PX so the stride kicks in.
        let w = 900u32;
        let h = 300u32;
        let cols: Vec<u32> = (0..w).filter(|x| x % 5 == 0).collect();
        let img = synth(w, h, [255, 255, 255], [20, 20, 20], &cols);
        assert!((w * h) as usize > MAX_SAMPLE_PX, "test must exercise the stride");
        let c = region_color(&img, 0, 0, w, h).expect("region");
        assert_eq!(c.name, "black", "got {:?}", c);
    }
}
