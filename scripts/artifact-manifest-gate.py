#!/usr/bin/env python3
"""The attribution gate for things that are not Cargo packages.

WHY THIS EXISTS. `scripts/attribution-gate.sh` regenerates the About panel's
attribution and diffs it, which is a real gate -- for crates. It builds its
inventory from `cargo tree` and `cargo metadata`, so a prebuilt `.onnx`, a
`.wasm` or a model file appears in no inventory at all. The regeneration comes
out identical, the diff is clean, and the gate prints OK while those components
ship with their licence terms unmet.

The PP-OCR models proved it rather than predicting it: they shipped attributed
only by a hand-written NOTICE entry, with nothing verifying the entry stayed
true and no hash pinning the bytes it described.

WHAT IT CHECKS, and each one exists because of a distinct way this goes wrong:

  1. Every declared artifact still exists.           (deleted, attribution left)
  2. Every declared artifact still hashes to what
     the register records.                           (SWAPPED bytes, stale text)
  3. Every file under a watched directory has a
     row.                                            (new model, no attribution)
  4. Every row carries a licence AND a copyright
     line.                                           (a row that says nothing)

Check 2 is the one that matters most and the one a hand-written NOTICE cannot
do: a model replaced by a differently-licensed one leaves the prose untouched
and completely wrong.

Run: scripts/artifact-manifest-gate.py
     scripts/artifact-manifest-gate.py --list   (print the attribution block)
"""

import hashlib
import json
import os
import sys

REGISTER = "shipped-artifacts.json"


def fail(msg):
    print(f"GATE FAIL: {msg}", file=sys.stderr)
    return 1


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load():
    if not os.path.exists(REGISTER):
        print(f"GATE FAIL: {REGISTER} is missing.", file=sys.stderr)
        sys.exit(1)
    with open(REGISTER, encoding="utf-8") as f:
        return json.load(f)


def attribution_block(reg):
    """The text these artifacts contribute to the About panel.

    Kept deliberately close in shape to what shipping-licenses.py emits for
    crates, so a reader cannot tell which mechanism produced which entry.
    """
    lines = []
    for a in sorted(reg["artifacts"], key=lambda x: x["component"].lower()):
        lines.append(a["component"])
        lines.append(f"    {a['copyright']}")
        lines.append(f"    Licensed under {a['licence']}.")
        if a.get("upstream"):
            ver = a.get("upstream_version") or "unrecorded"
            lines.append(f"    Upstream: {a['upstream']} ({ver})")
        lines.append("")
    return "\n".join(lines)


def main():
    reg = load()
    status = 0
    declared = {}

    for a in reg.get("artifacts", []):
        path = a.get("path")
        if not path:
            status = fail("an artifact row has no path")
            continue
        declared[os.path.normpath(path)] = a

        # 4: a row that names nothing is not attribution.
        for field in ("licence", "copyright", "component"):
            if not a.get(field):
                status = fail(f"{path}: row has no {field}")

        # 1: declared but absent.
        if not os.path.exists(path):
            status = fail(
                f"{path} is declared in {REGISTER} but does not exist. "
                "Either the file was removed and its attribution left behind, "
                "or the path is wrong."
            )
            continue

        # 2: present but changed. The failure a hand-written notice cannot catch.
        actual = sha256_of(path)
        recorded = a.get("sha256", "")
        if actual != recorded:
            status = fail(
                f"{path} does not match its recorded hash.\n"
                f"    recorded {recorded}\n"
                f"    actual   {actual}\n"
                "  The bytes changed. If this artifact was updated, its licence "
                "and copyright must be re-checked against the NEW file before "
                "the hash here is updated -- a swapped model can carry a "
                "different licence while the attribution text stays put."
            )

    # 3: shipped but undeclared.
    ignore = set(reg.get("ignore_in_watched_dirs", []))
    for watched in reg.get("watched_dirs", []):
        d = watched["path"]
        if not os.path.isdir(d):
            status = fail(f"watched directory {d} does not exist")
            continue
        for root, _dirs, files in os.walk(d):
            for name in sorted(files):
                if name in ignore:
                    continue
                p = os.path.normpath(os.path.join(root, name))
                if p not in declared:
                    status = fail(
                        f"{p} ships but has no row in {REGISTER}. "
                        "Every third-party artifact that ships must carry its "
                        "licence and copyright with the binary."
                    )

    if status == 0:
        n = len(reg.get("artifacts", []))
        print(f"ARTIFACT MANIFEST OK ({n} non-crate artifacts, hashes verified)")
    return status


if __name__ == "__main__":
    if "--list" in sys.argv:
        print(attribution_block(load()))
        sys.exit(0)
    sys.exit(main())
