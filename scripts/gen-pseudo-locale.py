#!/usr/bin/env python3
"""en.ftl -> en-XA.ftl: the pseudo-locale that finds unextracted English.

Every ASCII letter is accented through a one-code-point, case-preserving
table, and every message grows ~40% through a padding marker that is itself
non-ASCII (` ·ẊÅ·`) so the coverage scan cannot be tripped by its own
instrument. A filled chrome that still shows plain ASCII words is showing
text that never went through the catalog -- which is the finding.

Fluent syntax passes through untouched: placeable expressions byte-for-byte,
selector lines intact, each select variant's own text transformed and padded
on its own length (padding the whole message would over-expand one variant
and starve another). Anything this transformer does not recognize is a fatal
error with a line number, never a silent skip -- a truncated pseudo-locale
would make the scan pass by checking nothing.

Usage: gen-pseudo-locale.py <en.ftl> <out.ftl>
"""

import re
import sys

UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
UPPER_X = "ÅƁÇÐÉƑĜĤÎĴĶĿḾÑÖÞɊŔŠŢÛṼŴẊÝŽ"
LOWER_X = "åƀçðéƒĝĥîĵķŀḿñöþɋŕšţûṽŵẋýž"
TABLE = str.maketrans(
    UPPER + UPPER.lower(), UPPER_X + LOWER_X
)
PAD = " ·ẊÅ·"


def accent(text):
    return text.translate(TABLE)


def pad_for(text):
    """At least 40% added length, deterministic, whole markers only."""
    need = max(1, int(len(text) * 0.4))
    reps = (need + len(PAD) - 1) // len(PAD)
    return PAD * reps


def transform_value(value, lineno):
    """Accent and pad the literal text of a single-line value, leaving
    placeable expressions untouched. Nested braces inside a placeable are
    tracked; a brace that never closes is fatal."""
    out = []
    literal = []
    depth = 0
    for ch in value:
        if ch == "{":
            depth += 1
            if depth == 1:
                out.append(accent("".join(literal)))
                literal = []
                out.append(ch)
                continue
        if depth:
            out.append(ch)
            if ch == "}":
                depth -= 1
            continue
        literal.append(ch)
    if depth:
        sys.exit(f"GATE FAIL: unclosed placeable at en.ftl line {lineno}")
    out.append(accent("".join(literal)))
    plain = "".join(literal)
    return "".join(out) + (pad_for(plain) if plain.strip() else "")


def main():
    src, dst = sys.argv[1], sys.argv[2]
    out = [
        "# GENERATED pseudo-locale (en-XA). Do not edit; do not translate.",
        "# scripts/gen-pseudo-locale.py writes it from en.ftl.",
    ]
    in_select = False
    for lineno, raw in enumerate(open(src, encoding="utf-8"), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            in_select = False if not line.strip() else in_select
            continue
        m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.*)$", line)
        if m:
            msg_id, value = m.groups()
            if value.strip() == "" or value.rstrip().endswith("->"):
                # A select or multiline message begins; its variant lines
                # follow as continuations.
                in_select = True
                out.append(f"{msg_id} ={value and ' ' + value or ''}".rstrip() or f"{msg_id} =")
                out[-1] = f"{msg_id} = {value}".rstrip()
                continue
            in_select = False
            out.append(f"{msg_id} = {transform_value(value, lineno)}")
            continue
        if line.strip() == "}":
            # A select's closing brace at any indentation, column 0 included
            # (fluent-rs's own examples put it there).
            out.append(line)
            continue
        if line[:1] in (" ", "\t"):
            stripped = line.strip()
            vm = re.match(r"^(\*?\[[^\]]+\]) *(.*)$", stripped)
            if vm:
                # A select variant: key stays, its text transforms on its
                # OWN length.
                indent = line[: len(line) - len(line.lstrip())]
                out.append(
                    f"{indent}{vm.group(1)} {transform_value(vm.group(2), lineno)}"
                )
                continue
            if stripped == "}":
                out.append(line)
                continue
            # Plain continuation text.
            out.append(
                line[: len(line) - len(line.lstrip())]
                + transform_value(stripped, lineno)
            )
            continue
        sys.exit(f"GATE FAIL: unrecognized FTL construct at line {lineno}: {line!r}")
    open(dst, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"en-XA: {sum(1 for l in out if re.match(r'^[a-z]', l))} messages")


if __name__ == "__main__":
    main()
