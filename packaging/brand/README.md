# PATANYX Browser — logo

The shipped mark. Landed 2026-07-25, replacing the earlier placeholder.

`packaging/flatpak/` carries the built copies the Flatpak installs (eight
hicolor PNGs, 16 through 512, plus the SVG kept as source but not installed
-- see the manifest for why). THIS directory is the design source: edit here,
rebuild, then copy the results across.

## The mark

A P whose stem tapers to a thinning tip instead of stopping square. The idea
of "Leave less behind." is carried by the letterform itself rather than by a
separate faded element bolted beside it.

That choice was made after rendering and rejecting four alternatives:

| Tried                                     | Why it was dropped                        |
| ----------------------------------------- | ----------------------------------------- |
| Stacked fading bars below the stem        | Reads as an exclamation mark              |
| Vertical gradient fading the stem out     | Reads as a crop/render bug, not a fade    |
| Horizontal erasure slats across the glyph | Reads as a barcode or a corrupted image   |
| Comet with a fading wake                  | Generic swoosh, no connection to the name |

Two constraints came out of actually rasterising rather than eyeballing:

- **No `<mask>`.** cairosvg rendered a masked version as fully blank at 32px
  and 16px. An app icon that vanishes in some rasteriser is disqualifying, so
  every asset here is plain filled paths.
- **No low-opacity fill on the dark tile.** Faint blue over `#14161c`
  disappears or reads as dirt on the tile. Anything meant to be seen is at
  full opacity.

The bowl is elliptical (rx 32 / ry 22) rather than semicircular so the P is
not condensed and the counter stays open at 16px.

## Files

| File                                          | Use                                                            |
| --------------------------------------------- | -------------------------------------------------------------- |
| `patanyx-icon.svg`                            | App icon / favicon. 128 grid, dark `#14161c` tile, rx 28.      |
| `patanyx-mark.svg`                            | Bare mark, transparent, gradient. Any background.              |
| `patanyx-mark-mono.svg`                       | Single colour via `currentColor`. **Inline only** — see below. |
| `patanyx-logo-horizontal-on-{dark,light}.svg` | Mark + wordmark.                                               |
| `patanyx-logo-slogan-on-{dark,light}.svg`     | Mark + wordmark + "Leave less behind."                         |
| `png/patanyx-{16..512}.png`                   | Icon rasters, rendered by Chrome.                              |

`-on-dark` / `-on-light` names the background the file is placed **on**, not
the ink. The wordmark inverts between them or it is invisible.

`patanyx-mark-mono.svg` uses `fill="currentColor"`, which only inherits when
the SVG is **inlined into the DOM**. Loaded through `<img src>` it renders
black, because an `<img>` document does not inherit the host page's colour.
For the chrome UI, inline it.

## Colour

Taken from the existing chrome UI (`crates/app/src/chrome/chrome.css`) so the
mark is native to the app rather than a fifth blue.

- Tile `#14161c` (chrome uses `#121317`/`#16161c`)
- Mark gradient `#bcd6ff` → `#5f97ff` → `#3d7bf0`, around the accent `#4f8cff`
- Wordmark on dark `#e9e9ee`, on light `#1a1b20`
- Slogan on dark `#8f909a`, on light `#5c5d66`

## Wordmark

Liberation Sans Bold, cap height 30, tracking 0.085em, **converted to
outlines** — no live `<text>`, so it cannot reflow or fall back to a different
face on a machine without the font. The slogan is Liberation Sans Regular at
cap height 11.5.

Liberation Sans is a Helvetica-metric clone: neutral and safe, but it is a
stock face, not a commissioned one. If PATANYX ever wants a proprietary
wordmark, that is a separate exercise; the mark does not depend on it.

## Rebuilding

`build.py` regenerates every SVG from one geometry definition, so the mark
cannot drift between files. It needs `fonttools`:

```bash
python3 -m venv venv && ./venv/bin/pip install fonttools && ./venv/bin/python build.py
```

`proof.html` is the review sheet; `proof.png` is it rendered.

## Verification done

Rendered in Chrome (not just cairosvg) at 16/24/32/48/64/128/256/512, on the
app's dark background and on light, and in mock toolbar chips. The counter
stays open and the mark still reads as a P at 16px.

On landing: every raster was checked to be correctly sized and non-blank (the
blank-at-small-sizes failure above is the one that matters), and the Flatpak
was rebuilt with all eight sizes confirmed present in the installed app.

The mono mark now sits at the left of PATANYX's own toolbar and has been
screenshotted rendering there under WebKitGTK, so the mark has been displayed
by the browser it belongs to and not only by Chrome.

It is INLINED into `index.html` rather than referenced with `<img src>`,
because `currentColor` does not inherit into an `<img>` document -- loaded
that way it renders solid black. It is decorative: `aria-hidden`, no click
handler, `pointer-events: none`. It cannot use the `.ico` class, which sets
`fill: none` and strokes, and would draw this as an outline of the letterform.
