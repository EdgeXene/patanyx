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
not to relitigate the shipped baseline). Pairs marked STRICT opt out of that
relaxation: it exists to grandfather values that shipped before this gate
did, and a token added afterwards has no baseline to be grandfathered
against.

Resolution order (matches the file's cascade by construction):
[data-scheme][data-theme] > [data-scheme] > [data-theme] > :root.

DERIVED TOKENS. The accent-frame tints (--sf-strip-a and friends) are
`color-mix(in srgb, var(--accent) N%, var(--sf-strip))`: one declaration that
names BOTH axes and resolves differently for each of the 27 chromes. This
gate used to read hex only, so such a token parsed as nothing and any pair
naming it would have failed as "missing" -- loudly, but for the wrong reason.
It now evaluates var() and color-mix() against the MERGED map for the
(scheme, accent) being checked, which is the only place the answer exists:
resolving them at parse time would freeze every combination to the :root
accent and the gate would be checking one chrome twenty-seven times.
"""

import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "crates/app/src/chrome/chrome.css"


def rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))


def lum(h):
    r, g, b = (c / 255 for c in rgb(h))

    def f(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def parse_blocks(src):
    """selector -> {var: raw value} for every block that defines variables.

    Raw, not resolved: see the module docstring. `[^;}]+` stops at the
    declaration's own semicolon, so a trailing comment on the line is
    trimmed by the strip below rather than swallowed.
    """
    blocks = {}
    for m in re.finditer(r"^([^\n{}]+)\{([^{}]*)\}", src, re.M):
        sel, body = m.group(1).strip(), m.group(2)
        pairs = {
            name: value.split("/*")[0].strip()
            for name, value in re.findall(r"--([\w-]+):\s*([^;}]+)", body)
        }
        if pairs:
            blocks.setdefault(sel, {}).update(pairs)
    return blocks


# color-mix(in srgb, <A> <P>%, <B>) -- the only form this stylesheet uses.
MIX = re.compile(
    r"^color-mix\(\s*in\s+srgb\s*,\s*(.+?)\s+([\d.]+)%\s*,\s*(.+?)\s*\)$", re.I
)
VAR = re.compile(r"^var\(\s*--([\w-]+)\s*(?:,\s*(.+?)\s*)?\)$")


class Unresolvable(Exception):
    """A value this gate cannot reduce to a hex colour."""


def resolve_value(value, env, seen=()):
    """Reduce one declaration to #rrggbb, following var() and color-mix().

    `env` is the merged variable map for one (scheme, accent) pair. `seen`
    breaks a var() cycle rather than blowing the stack: a stylesheet that
    defines --a from --b from --a is a bug this should name, not crash on.
    """
    value = value.strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", value):
        return value.lower()
    if re.fullmatch(r"#[0-9a-fA-F]{3}", value):
        return "#" + "".join(c * 2 for c in value[1:]).lower()

    m = VAR.match(value)
    if m:
        name, fallback = m.group(1), m.group(2)
        if name in seen:
            raise Unresolvable(f"var(--{name}) is defined in terms of itself")
        if name in env:
            return resolve_value(env[name], env, seen + (name,))
        if fallback:
            return resolve_value(fallback, env, seen + (name,))
        raise Unresolvable(f"var(--{name}) is not defined")

    m = MIX.match(value)
    if m:
        a = resolve_value(m.group(1), env, seen)
        pct = float(m.group(2)) / 100.0
        b = resolve_value(m.group(3), env, seen)
        # Opaque sRGB mix, per-channel, which is what the engines compute for
        # two opaque colours: the alpha-weighting rules in the spec collapse
        # to a plain linear interpolation when both sides are alpha 1.
        mixed = tuple(
            round(ca * pct + cb * (1 - pct)) for ca, cb in zip(rgb(a), rgb(b))
        )
        return "#%02x%02x%02x" % mixed

    raise Unresolvable(f"cannot reduce {value!r} to a colour")


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

    # (foreground var, background var, bar) -- optional 4th element STRICT
    # opts the pair out of the Dark-baseline relaxation below.
    STRICT = "strict"
    PAIRS = [
        ("accent", "sf-body", 3.0),
        ("accent-bright", "sf-strip", 3.0),
        # ---- the accent frame. Everything the tinted strips carry, and the
        # tints themselves, all STRICT: these tokens post-date the gate, so
        # there is no shipped baseline to grandfather and the real bar is the
        # only honest floor. --sf-strip-a is where the whole toolbar's text
        # lives, so it is checked against every text rung that lands on it.
        ("tx", "sf-strip-a", 4.5, STRICT),
        ("tx-bright", "sf-strip-a", 4.5, STRICT),
        ("tx-dim", "sf-strip-a", 4.5, STRICT),
        ("tx-chip", "sf-tabstrip-a", 4.5, STRICT),
        ("tx-bright", "sf-tabstrip-a", 4.5, STRICT),
        # The active tab's label sits on the tinted strip colour, not the
        # untinted one, because the chip merges into the toolbar.
        ("accent-bright", "sf-strip-a", 3.0, STRICT),
        # The hairline along the top of the window IS meant to be seen, and
        # it is the accent itself, so it takes the same 3:1 the accent takes
        # against the body.
        ("accent", "sf-tabstrip-a", 3.0, STRICT),
        # The state colours must still out-read the tint they now sit on.
        # This is the pair that would catch a wash turned up until green
        # stopped meaning "a protection is on".
        ("st-ok", "sf-strip-a", 4.5, STRICT),
        ("st-warn", "sf-strip-a", 3.0, STRICT),
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

    # NOT EVERY LINE IS A CONTROL, and an absolute bar on the ones that are
    # not is a bar invented rather than derived.
    #
    # The two tinted line tokens replace hairlines that ship at 1.19:1
    # (--ln-soft2 on the strip) and 1.50:1 (--ln-input on the address bar's
    # own fill). They are dividers between two surfaces, not the thing that
    # identifies a control -- the address bar is identified by its fill
    # against the strip, which is why it has been legible for a year at
    # 1.50. Holding their tinted successors to WCAG's 3:1 for user interface
    # COMPONENTS would fail them for being four times as visible as what
    # they replace, which is not a standard, it is a number.
    #
    # The question worth asking is the relative one, and it is a real
    # regression guard: a tint that made a line HARDER to see than the plain
    # line it replaced would be a defect, and nothing else here would catch
    # it. (new token, background, the token it replaces)
    RELATIVE = [
        ("ln-accent-a", "sf-sunken", "ln-input"),
        ("ln-accent-edge", "sf-tabstrip-a", "ln-soft2"),
        ("ln-accent-edge", "sf-strip-a", "ln-soft2"),
    ]

    failures = []

    def colour_of(name, env, where):
        """The hex a variable resolves to in one chrome, or None + a failure."""
        if name not in env:
            failures.append(f"{where}: --{name} is not defined")
            return None
        try:
            return resolve_value(env[name], env)
        except Unresolvable as exc:
            failures.append(f"{where}: --{name} -- {exc}")
            return None

    # Dark's own ratios cap the floors: the gate stops regressions, it does
    # not fail the baseline it was born from. STRICT pairs are excluded --
    # they have no shipped baseline to be measured against.
    floors = {}
    for theme in ["default"] + themes:
        base = resolve("dark", theme)
        for fg, bg, bar, *flags in PAIRS:
            if STRICT in flags:
                continue
            a = colour_of(fg, base, f"dark/{theme}")
            b = colour_of(bg, base, f"dark/{theme}")
            if a and b:
                floors[(theme, fg, bg)] = min(bar, ratio(a, b))

    combos = 0
    for scheme in ["dark"] + schemes:
        for theme in ["default"] + themes:
            v = resolve(scheme, theme)
            combos += 1
            where = f"{scheme}/{theme}"
            for fg, bg, bar, *flags in PAIRS:
                a = colour_of(fg, v, where)
                b = colour_of(bg, v, where)
                if not a or not b:
                    continue
                floor = floors.get((theme, fg, bg), bar)
                r = ratio(a, b)
                if r < floor - 0.005:
                    failures.append(
                        f"{where}: --{fg} {a} on --{bg} {b}"
                        f" = {r:.2f} (floor {floor:.2f})"
                    )
            for fg, bg, was in RELATIVE:
                a = colour_of(fg, v, where)
                b = colour_of(bg, v, where)
                c = colour_of(was, v, where)
                if not a or not b or not c:
                    continue
                r, plain = ratio(a, b), ratio(c, b)
                if r < plain - 0.005:
                    failures.append(
                        f"{where}: --{fg} {a} on --{bg} {b} = {r:.2f}, LESS "
                        f"visible than the plain --{was} {c} it replaces "
                        f"({plain:.2f})"
                    )

    if not themes or not schemes:
        failures.append(
            f"parsed {len(themes)} themes / {len(schemes)} schemes -- the "
            "selector shapes changed and this gate is checking nothing"
        )
    # A derived token that stopped being derived -- someone flattening a
    # color-mix back to a hex -- would silently take this gate back to
    # checking one accent's tint twenty-seven times.
    if not any("color-mix" in val for val in root.values()):
        failures.append(
            "no derived (color-mix) token in :root -- the accent frame's "
            "tints are gone or were flattened, and this gate is no longer "
            "checking what it was extended to check"
        )

    if failures:
        print("THEME CONTRAST GATE FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"THEME CONTRAST OK: {combos} scheme/accent combos, "
        f"{len(PAIRS)} pairs + {len(RELATIVE)} no-regression checks each"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
