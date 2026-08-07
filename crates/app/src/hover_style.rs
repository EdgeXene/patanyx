//! Everything the hover readout needs that is not a draw call.
//!
//! The readout is drawn by native code on both backends -- a `GtkLabel` in an
//! overlay on Linux, a child window painted with `DrawTextW` on Windows -- so
//! none of the rendering itself can run on a build box with no display and no
//! WebView2. What CAN run here is the arithmetic, and the arithmetic is where
//! this kind of feature actually breaks: a colour byte-swapped into orange, a
//! LOGFONT height with the wrong sign, a rectangle whose `y` goes negative on a
//! short window. Those are all Windows-only defects, and every one of them is
//! provable on Debian if the numbers live in a pure function.
//!
//! So the rule for this module is: no GTK, no Win32, no `cfg`. If a backend
//! needs a number, it asks for it here and a test on this box already knows the
//! answer.

use crate::prefs::ChromeScheme;

/// Horizontal padding either side of the text, in logical pixels.
const PAD_X: i32 = 8;
/// Vertical padding above and below the text, in logical pixels.
const PAD_Y: i32 = 2;

/// Point size of the readout text. Small on purpose: it is a status line, not
/// content, and it sits over the page.
const FONT_POINTS: f64 = 9.0;

/// The three colours the readout paints with, each `0xRRGGBB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// Text.
    pub fg: u32,
    /// Background fill behind the text.
    pub bg: u32,
    /// The hairline that separates the readout from the page.
    pub border: u32,
}

/// The readout's colours for a chrome scheme.
///
/// These are `--tx` on `--sf-card` with an `--ln` edge, copied from
/// `chrome.css`. That pair is not an aesthetic preference: it is already one of
/// the contrast pairs `scripts/theme-contrast-gate.py` checks across every
/// scheme and accent, so choosing it means the readout inherits a WCAG gate
/// that already exists instead of needing one of its own.
///
/// The values are duplicated from the stylesheet because native code cannot
/// read CSS variables. `palette_matches_the_stylesheet` is what stops the two
/// copies drifting -- without it, a scheme retune would leave the readout
/// wearing last season's colours and nobody would see it until it went grey on
/// grey.
pub fn palette(scheme: ChromeScheme) -> Palette {
    match scheme {
        ChromeScheme::Dark => Palette {
            fg: 0xd7d7dc,
            bg: 0x202128,
            border: 0x3a3b43,
        },
        ChromeScheme::White => Palette {
            fg: 0x26262c,
            bg: 0xf3f3f6,
            border: 0xc9c9d1,
        },
        ChromeScheme::Black => Palette {
            fg: 0xe4e4e9,
            bg: 0x101014,
            border: 0x26262e,
        },
    }
}

/// `0xRRGGBB` as the `#rrggbb` a GTK CSS provider expects.
pub fn css_hex(rgb: u32) -> String {
    format!("#{:06x}", rgb & 0x00ff_ffff)
}

/// `0xRRGGBB` as a Win32 `COLORREF`, which is `0x00BBGGRR`.
///
/// Win32 stores colour components in the opposite order to CSS, and the two
/// notations are indistinguishable by inspection -- a swapped constant is a
/// perfectly valid colour, just the wrong one. On a Linux build box the mistake
/// is completely invisible: nothing here renders. Hence a function rather than
/// a literal at the call site, and hence a test.
pub fn colorref(rgb: u32) -> u32 {
    let r = (rgb >> 16) & 0xff;
    let g = (rgb >> 8) & 0xff;
    let b = rgb & 0xff;
    (b << 16) | (g << 8) | r
}

/// The `lfHeight` for a `LOGFONTW` at this display scale. Always negative.
///
/// The sign is the whole point. A positive `lfHeight` asks Windows for a CELL
/// height and a negative one asks for a CHARACTER height, so dropping the minus
/// sign silently produces a font about a third too large -- it renders, it
/// looks almost right, and it is wrong on every machine. Nothing on this build
/// box can catch that except an assertion about the sign.
///
/// A scale that is zero, negative or non-finite falls back to 1.0 rather than
/// producing a nonsense height: a readout at the wrong size is legible, and a
/// readout with a zero-height font is not there at all.
pub fn font_height_px(scale: f64) -> i32 {
    let scale = if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    };
    let px = FONT_POINTS * 96.0 * scale / 72.0;
    -(px.round() as i32)
}

/// Where the readout sits, in the same pixel space as the client area:
/// `(x, y, width, height)`.
///
/// Bottom-left, hugging the corner, status-bar fashion. Every value is clamped
/// into the window. This codebase has shipped chrome geometry that was wrong by
/// a whole panel height once already (see the `ChromeLayout::Overlay` note in
/// the Windows backend), and the failure here is quiet in the same way: a
/// negative `y` puts the readout off the top of the screen, an unclamped width
/// puts it off the right edge, and in both cases the feature simply appears not
/// to work.
///
/// A window with no area yields a zero rectangle rather than a negative one, so
/// a caller that shows it anyway draws nothing instead of asking Windows to
/// create a window with a negative dimension.
pub fn readout_rect(client_w: i32, client_h: i32, text_w: i32, line_h: i32) -> (i32, i32, i32, i32) {
    if client_w <= 0 || client_h <= 0 {
        return (0, 0, 0, 0);
    }

    let h = (line_h.max(0) + 2 * PAD_Y).min(client_h);
    let w = (text_w.max(0) + 2 * PAD_X).min(client_w);
    let y = (client_h - h).max(0);

    (0, y, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust constants above and `chrome.css` are two copies of one fact.
    /// This is the only thing keeping them equal.
    #[test]
    fn palette_matches_the_stylesheet() {
        let css = include_str!("chrome/chrome.css");

        for (scheme, selector) in [
            (ChromeScheme::Dark, ":root"),
            (ChromeScheme::White, r#":root[data-scheme="white"]"#),
            (ChromeScheme::Black, r#":root[data-scheme="black"]"#),
        ] {
            let block = scheme_block(css, selector).unwrap_or_else(|| {
                panic!("no {selector} block in chrome.css defines --tx/--sf-card/--ln")
            });
            let want = palette(scheme);
            for (var, got) in [
                ("--tx", want.fg),
                ("--sf-card", want.bg),
                ("--ln", want.border),
            ] {
                let css_value = css_var(&block, var)
                    .unwrap_or_else(|| panic!("{selector} does not define {var}"));
                assert_eq!(
                    css_value,
                    css_hex(got),
                    "{selector} {var}: chrome.css and hover_style::palette disagree. \
                     A scheme was retuned without updating the native readout."
                );
            }
        }
    }

    /// Returns the body of the block for `selector` that actually carries the
    /// scheme variables. `:root` appears more than once in the stylesheet (the
    /// accent block is separate), so the one we want is identified by its
    /// contents, not by its position.
    fn scheme_block(css: &str, selector: &str) -> Option<String> {
        let needle = format!("{selector} {{");
        let mut from = 0usize;
        while let Some(rel) = css[from..].find(&needle) {
            let start = from + rel + needle.len();
            let end = start + css[start..].find('}')?;
            let block = &css[start..end];
            // Skip a same-selector block that is not the scheme definition.
            if block.contains("--tx:") && block.contains("--sf-card:") && block.contains("--ln:") {
                return Some(block.to_string());
            }
            from = end;
        }
        None
    }

    fn css_var(block: &str, name: &str) -> Option<String> {
        for line in block.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix(name) {
                if let Some(value) = rest.strip_prefix(':') {
                    return Some(value.trim().trim_end_matches(';').trim().to_string());
                }
            }
        }
        None
    }

    /// A swapped colour is still a valid colour, so nothing but arithmetic can
    /// catch this on a box that never renders it.
    #[test]
    fn colorref_swaps_red_and_blue_and_is_its_own_inverse() {
        assert_eq!(colorref(0x20_21_28), 0x28_21_20);
        assert_eq!(colorref(0xff_00_00), 0x00_00_ff, "pure red becomes pure blue");
        assert_eq!(colorref(0x00_00_ff), 0xff_00_00, "and pure blue becomes red");

        for rgb in [0x00_00_00, 0xff_ff_ff, 0xd7_d7_dc, 0x10_10_14, 0x12_34_56] {
            assert_eq!(colorref(colorref(rgb)), rgb, "swapping twice is identity");
        }
    }

    /// Green must stay green: a channel that is equal on both sides would hide
    /// a swap, so this pins the one channel the swap does not move.
    #[test]
    fn colorref_leaves_green_where_it_is() {
        assert_eq!(colorref(0x00_ab_00), 0x00_ab_00);
    }

    /// A positive lfHeight means "cell height" and silently oversizes the font.
    #[test]
    fn font_height_is_negative_at_every_scale() {
        for (scale, want) in [(1.0, -12), (1.25, -15), (1.5, -18), (2.0, -24)] {
            assert_eq!(font_height_px(scale), want, "scale {scale}");
        }
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(
                font_height_px(scale),
                -12,
                "a nonsense scale ({scale}) falls back to 100%, never to zero"
            );
        }
        for scale in [0.5, 1.0, 1.25, 1.5, 1.75, 2.0, 3.0] {
            assert!(
                font_height_px(scale) < 0,
                "lfHeight must be negative at scale {scale}"
            );
        }
    }

    /// Off-screen by arithmetic is indistinguishable from "the feature is
    /// broken", so every edge is pinned.
    #[test]
    fn readout_rect_stays_inside_the_window() {
        // Ordinary case: bottom-left, padded, narrower than the window.
        let (x, y, w, h) = readout_rect(1000, 700, 300, 16);
        assert_eq!((x, w, h), (0, 300 + 2 * PAD_X, 16 + 2 * PAD_Y));
        assert_eq!(y, 700 - h);
        assert!(y + h <= 700 && x + w <= 1000);

        // Text wider than the window is clipped to the window, never past it.
        let (x, y, w, h) = readout_rect(400, 300, 5_000, 16);
        assert_eq!(w, 400, "width is capped at the client area");
        assert!(x + w <= 400 && y + h <= 300);

        // A window shorter than the readout itself: still no negative y.
        let (_, y, _, h) = readout_rect(400, 10, 100, 40);
        assert_eq!(y, 0);
        assert!(h <= 10, "height is capped at the client area");

        // Degenerate windows produce nothing, not a negative-sized window.
        for (cw, ch) in [(0, 0), (0, 500), (500, 0), (-10, -10)] {
            assert_eq!(readout_rect(cw, ch, 100, 16), (0, 0, 0, 0), "{cw}x{ch}");
        }

        // Negative measurements from a failed text measurement must not
        // produce a negative width.
        let (_, _, w, h) = readout_rect(800, 600, -50, -50);
        assert!(w >= 0 && h >= 0);
    }

    #[test]
    fn css_hex_is_six_digits_and_lowercase() {
        assert_eq!(css_hex(0x0), "#000000");
        assert_eq!(css_hex(0xd7d7dc), "#d7d7dc");
        assert_eq!(css_hex(0xffffff), "#ffffff");
    }
}
