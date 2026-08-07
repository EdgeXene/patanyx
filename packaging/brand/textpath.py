import sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.misc.transform import Transform


def outline(fontfile, text, cap_height, tracking_em=0.0):
    """Return (path_d, advance_width, cap_scale) with baseline at y=0, y-down."""
    f = TTFont(fontfile)
    upm = f["head"].unitsPerEm
    try:
        cap = f["OS/2"].sCapHeight
    except Exception:
        cap = None
    if not cap:
        cap = upm * 0.716
    scale = cap_height / cap
    cmap = f.getBestCmap()
    gs = f.getGlyphSet()
    hmtx = f["hmtx"]
    try:
        kern = f["kern"].kernTables[0].kernTable
    except Exception:
        kern = {}

    d = []
    x = 0.0
    track = tracking_em * upm
    prev = None
    for ch in text:
        gname = cmap[ord(ch)]
        if prev is not None:
            x += kern.get((prev, gname), 0)
        # y-down flip: scale y by -1 so the font's y-up outline renders correctly
        t = Transform(scale, 0, 0, -scale, x * scale, 0)
        pen = SVGPathPen(gs)
        gs[gname].draw(TransformPen(pen, t))
        seg = pen.getCommands()
        if seg:
            d.append(seg)
        x += hmtx[gname][0] + track
        prev = gname
    # trailing track is not part of the visual width
    total = (x - track) * scale
    return " ".join(d), total


if __name__ == "__main__":
    font, text, cap = sys.argv[1], sys.argv[2], float(sys.argv[3])
    track = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
    d, w = outline(font, text, cap, track)
    print("WIDTH", round(w, 2))
    print(d)
