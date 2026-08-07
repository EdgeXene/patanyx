#!/usr/bin/env python3
"""Contrast gate for chrome.css themes and schemes.

The accent lift's WCAG check was a run-before-landing one-shot; the scheme
lift made that untenable (9 accents x 3 schemes is 27 chromes nobody will
eyeball). This parses the variable blocks out of chrome.css, resolves the
cascade for every (scheme, accent) combination, and fails on any pair below
its bar.

Bars: non-text accent structure 3:1, text rungs 4.5:1 -- except where the
shipped DARK scheme itself sits below a bar, in which case Dark's own ratio
is the floor (the gate exists to stop regressions and unreadable schemes,
not to relitigate the shipped baseline).

Resolution order (matches the file's cascade by construction):
[data-scheme][data-theme] > [data-scheme] > [data-theme] > :root.
"""

import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "crates/app/src/chrome/chrome.css"


def lum(h):
    h = h.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def f(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def parse_blocks(src):
    """selector -> {var: hex} for every block that defines variables."""
    blocks = {}
    for m in re.finditer(r"^([^\n{}]+)\{([^{}]*)\}", src, re.M):
        sel, body = m.group(1).strip(), m.group(2)
        pairs = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", body))
        if pairs:
            blocks.setdefault(sel, {}).update(pairs)
    return blocks


def main():
    src = CSS.read_text()
    blocks = parse_blocks(src)
    root = blocks.get(":root", {})
    themes = sorted(
        m.group(1)
        for sel in blocks
        for m in [re.match(r':root\[data-theme="([\w-]+)"\]$', sel)]
        if m
    )
    schemes = sorted(
        m.group(1)
        for sel in blocks
        for m in [re.match(r':root\[data-scheme="([\w-]+)"\]$', sel)]
        if m
    )

    def resolve(scheme, theme):
        v = dict(root)
        if theme != "default":
            v.update(blocks.get(f':root[data-theme="{theme}"]', {}))
        if scheme != "dark":
            v.update(blocks.get(f':root[data-scheme="{scheme}"]', {}))
            v.update(
                blocks.get(f':root[data-scheme="{scheme}"][data-theme="{theme}"]', {})
            )
        return v

    # (foreground var, background var, bar, is_text)
    PAIRS = [
        ("accent", "sf-body", 3.0),
        ("accent-bright", "sf-strip", 3.0),
        ("accent-choice-text", "accent-choice-bg", 4.5),
        ("accent-text", "sf-body", 4.5),
        ("accent-tag", "sf-body", 4.5),
        ("tx", "sf-body", 4.5),
        ("tx", "sf-card", 4.5),
        ("tx-bright", "sf-body", 4.5),
        ("tx-bright", "sf-btn", 4.5),
        ("tx-dim", "sf-body", 4.5),
        ("tx-head", "sf-panel", 4.5),
        ("tx-code", "sf-code", 4.5),
        ("tx-find", "sf-find-input", 4.5),
        ("st-ok", "sf-body", 4.5),
        ("st-warn", "sf-body", 3.0),
        ("st-err", "sf-body", 4.5),
        ("st-ok-bg-text", "st-ok-bg", 4.5),
        ("st-warn-text", "st-warn-bg", 4.5),
        ("st-err-text2", "st-err-bg2", 4.5),
        ("st-ok-badge-text", "st-ok-dim", 4.5),
        ("st-upd-text", "st-upd-bg", 4.5),
        ("st-link", "st-msg-out-bg", 3.0),
    ]

    # Dark's own ratios cap the floors: the gate stops regressions, it does
    # not fail the baseline it was born from.
    floors = {}
    for theme in ["default"] + themes:
        base = resolve("dark", theme)
        for fg, bg, bar in PAIRS:
            if fg in base and bg in base:
                floors[(theme, fg, bg)] = min(bar, ratio(base[fg], base[bg]))

    failures = []
    combos = 0
    for scheme in ["dark"] + schemes:
        for theme in ["default"] + themes:
            v = resolve(scheme, theme)
            combos += 1
            for fg, bg, bar in PAIRS:
                if fg not in v or bg not in v:
                    failures.append(f"{scheme}/{theme}: missing --{fg} or --{bg}")
                    continue
                floor = floors.get((theme, fg, bg), bar)
                r = ratio(v[fg], v[bg])
                if r < floor - 0.005:
                    failures.append(
                        f"{scheme}/{theme}: --{fg} {v[fg]} on --{bg} {v[bg]}"
                        f" = {r:.2f} (floor {floor:.2f})"
                    )

    if not themes or not schemes:
        failures.append(
            f"parsed {len(themes)} themes / {len(schemes)} schemes -- the "
            "selector shapes changed and this gate is checking nothing"
        )

    if failures:
        print("THEME CONTRAST GATE FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"THEME CONTRAST OK: {combos} scheme/accent combos, "
        f"{len(PAIRS)} pairs each"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
