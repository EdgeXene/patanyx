#!/usr/bin/env python3
"""Verifies packaging/flatpak/cargo-sources.json against Cargo.lock.

The Flatpak build runs with CARGO_NET_OFFLINE=true and every crate comes from
that JSON. It is GENERATED from Cargo.lock, by a script that needs network
access and two Python packages, so in practice nobody regenerates it on a
whim -- which is exactly the problem. Change a dependency, forget the
regeneration step, and the offline build either fails in a container the
author is not watching, or succeeds against a stale vendored tree.

This check needs neither the network nor those packages: Cargo.lock already
carries the checksum of every registry crate, so agreement is a pure
comparison. It is the difference between "we intend to keep these in sync"
and knowing whether they are.

Exit 0 when they agree; 1 with the specific drift when they do not.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK = ROOT / "Cargo.lock"
SOURCES = ROOT / "packaging" / "flatpak" / "cargo-sources.json"


def crates_from_lock(text):
    """Every registry crate in Cargo.lock, as name-version -> checksum.

    Path and git dependencies have no `checksum` line and are not vendored
    from crates.io, so they are correctly absent from the sources file; the
    workspace's own members are the obvious case.
    """
    crates = {}
    for block in text.split("\n[[package]]"):
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        version = re.search(r'^version = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([0-9a-f]+)"', block, re.M)
        if name and version and checksum:
            crates[f"{name.group(1)}-{version.group(1)}"] = checksum.group(1)
    return crates


def crates_from_sources(entries):
    """Every crate the Flatpak will vendor, as name-version -> sha256."""
    vendored = {}
    for entry in entries:
        if entry.get("type") != "archive":
            continue
        dest = entry.get("dest", "")
        prefix = "cargo/vendor/"
        if not dest.startswith(prefix):
            continue
        vendored[dest[len(prefix):]] = entry.get("sha256", "")
    return vendored


def main():
    if not LOCK.is_file():
        print(f"GATE FAIL: {LOCK} not found", file=sys.stderr)
        return 1
    if not SOURCES.is_file():
        print(f"GATE FAIL: {SOURCES} not found", file=sys.stderr)
        return 1

    locked = crates_from_lock(LOCK.read_text())
    vendored = crates_from_sources(json.loads(SOURCES.read_text()))

    if not locked:
        print("GATE FAIL: no checksummed crates parsed from Cargo.lock;", file=sys.stderr)
        print("  the lock format changed and this check is reading nothing", file=sys.stderr)
        return 1
    if not vendored:
        print("GATE FAIL: no vendored crates parsed from cargo-sources.json;", file=sys.stderr)
        print("  the generator's output shape changed", file=sys.stderr)
        return 1

    missing = sorted(set(locked) - set(vendored))
    extra = sorted(set(vendored) - set(locked))
    mismatched = sorted(
        name
        for name in set(locked) & set(vendored)
        if locked[name] != vendored[name]
    )

    if missing or extra or mismatched:
        print("GATE FAIL: cargo-sources.json does not match Cargo.lock.", file=sys.stderr)
        print("  Regenerate it:", file=sys.stderr)
        print(
            "    python3 packaging/flatpak/flatpak-cargo-generator.py Cargo.lock \\",
            file=sys.stderr,
        )
        print("      -o packaging/flatpak/cargo-sources.json", file=sys.stderr)
        for name in missing[:20]:
            print(f"  in Cargo.lock but NOT vendored: {name}", file=sys.stderr)
        for name in extra[:20]:
            print(f"  vendored but NOT in Cargo.lock: {name}", file=sys.stderr)
        for name in mismatched[:20]:
            print(f"  checksum differs: {name}", file=sys.stderr)
        total = len(missing) + len(extra) + len(mismatched)
        if total > 60:
            print(f"  ... {total} differences in total", file=sys.stderr)
        return 1

    print(f"cargo-sources.json matches Cargo.lock ({len(locked)} crates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
