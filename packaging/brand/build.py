import re, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from textpath import outline

FONT = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"
FONT_R = "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
OUT = os.path.dirname(os.path.abspath(__file__))


def rnd(d, nd=2):
    return re.sub(r"-?\d+\.\d+", lambda m: f"{float(m.group()):.{nd}f}".rstrip("0").rstrip("."), d)


def shift(d, dx, dy):
    return f'<g transform="translate({dx},{dy})">{d}</g>'


# ---- the mark, drawn at 128x128 with the P spanning x40..89, y20..108 ----
# Stem is 17 wide and tapers to a 7-wide rounded tip below the bowl: the
# stroke thins away instead of stopping, which is the "leave less behind" idea
# carried by the letterform itself rather than by a separate faded element.
STEM = ("M44 20 L57 20 L57 64 L53.5 108 A3.5 3.5 0 0 1 46.5 108 "
        "L40 64 L40 24 A4 4 0 0 1 44 20 Z")
# Bowl is elliptical (rx 32 / ry 22) so the P is not condensed; the counter
# stays open at 16px.
BOWL = "M57 20 A32 22 0 0 1 57 64 L57 51 A17 9 0 0 0 57 33 Z"

GRAD = ('<linearGradient id="{i}" x1="40" y1="16" x2="92" y2="108" '
        'gradientUnits="userSpaceOnUse">'
        '<stop offset="0" stop-color="#bcd6ff"/>'
        '<stop offset=".55" stop-color="#5f97ff"/>'
        '<stop offset="1" stop-color="#3d7bf0"/></linearGradient>')

HDR = '<?xml version="1.0" encoding="UTF-8"?>\n'


def write(name, body):
    p = os.path.join(OUT, name)
    open(p, "w").write(HDR + body + "\n")
    print("wrote", name)


# 1. app icon: dark tile + mark
write("patanyx-icon.svg",
      f'<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128" role="img" aria-label="PATANYX Browser">'
      f'<defs>{GRAD.format(i="pnxIcon")}</defs>'
      f'<rect width="128" height="128" rx="28" fill="#14161c"/>'
      f'<g fill="url(#pnxIcon)"><path d="{STEM}"/><path d="{BOWL}"/></g></svg>')

# 2. bare mark, transparent, tight viewBox (x45..83 -> 38 wide, y24..106 -> 82 tall)
write("patanyx-mark.svg",
      f'<svg xmlns="http://www.w3.org/2000/svg" width="49" height="88" viewBox="40 20 49 88" role="img" aria-label="PATANYX Browser">'
      f'<defs>{GRAD.format(i="pnxMark")}</defs>'
      f'<g fill="url(#pnxMark)"><path d="{STEM}"/><path d="{BOWL}"/></g></svg>')

# 3. monochrome mark, inherits text colour
write("patanyx-mark-mono.svg",
      f'<svg xmlns="http://www.w3.org/2000/svg" width="49" height="88" viewBox="40 20 49 88" fill="currentColor" role="img" aria-label="PATANYX Browser">'
      f'<path d="{STEM}"/><path d="{BOWL}"/></svg>')

# ---- lockups ----
CAP = 30.0
d_word, w_word = outline(FONT, "PATANYX", CAP, 0.085)
d_word = rnd(d_word)
SLOGAN_CAP = 11.5
d_slog, w_slog = outline(FONT_R, "Leave less behind.", SLOGAN_CAP, 0.03)
d_slog = rnd(d_slog)

# mark scaled to 64 tall: 64/82 = 0.7805, width 38*0.7805 = 29.66
MS = 64.0 / 88.0
mark_w = 49 * MS
GAP = 22.0


def mark_g(gid, scale, tx, ty):
    """place the bare mark with its top-left (45,24) at (tx,ty), scaled."""
    return (f'<g transform="translate({tx:.2f},{ty:.2f}) scale({scale:.4f}) translate(-40,-20)" '
            f'fill="url(#{gid})"><path d="{STEM}"/><path d="{BOWL}"/></g>')


# Two colourways per lockup: the wordmark has to invert or it vanishes on the
# background it is placed on. Keyed by the background, not by the ink.
SCHEMES = {
    "on-dark":  ("#e9e9ee", "#8f909a"),
    "on-light": ("#1a1b20", "#5c5d66"),
}

for suffix, (word_fill, slog_fill) in SCHEMES.items():
    # horizontal lockup, name only
    W = mark_w + GAP + w_word
    gid = f"pnxLh{suffix[3]}"
    write(f"patanyx-logo-horizontal-{suffix}.svg",
          f'<svg xmlns="http://www.w3.org/2000/svg" width="{W:.0f}" height="64" viewBox="0 0 {W:.2f} 64" role="img" aria-label="PATANYX Browser">'
          f'<defs>{GRAD.format(i=gid)}</defs>'
          f'{mark_g(gid, MS, 0, 0)}'
          f'<g fill="{word_fill}" transform="translate({mark_w + GAP:.2f},47)"><path d="{d_word}"/></g></svg>')

    # horizontal lockup with slogan
    MS2 = 72.0 / 88.0
    mark_w2 = 49 * MS2
    W2 = mark_w2 + GAP + max(w_word, w_slog)
    gid2 = f"pnxLs{suffix[3]}"
    write(f"patanyx-logo-slogan-{suffix}.svg",
          f'<svg xmlns="http://www.w3.org/2000/svg" width="{W2:.0f}" height="76" viewBox="0 0 {W2:.2f} 76" role="img" aria-label="PATANYX Browser - Leave less behind.">'
          f'<defs>{GRAD.format(i=gid2)}</defs>'
          f'{mark_g(gid2, MS2, 0, 2)}'
          f'<g fill="{word_fill}" transform="translate({mark_w2 + GAP:.2f},42)"><path d="{d_word}"/></g>'
          f'<g fill="{slog_fill}" transform="translate({mark_w2 + GAP:.2f},68)"><path d="{d_slog}"/></g></svg>')

print("word width", round(w_word, 2), "slogan width", round(w_slog, 2))
