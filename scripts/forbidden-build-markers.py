#!/usr/bin/env python3
"""Refuses a release artifact that carries a non-public build or a build path.

THE ONE LIST. Every Linux release check that asks "is this file the public
build?" reads it from here: check-linux-feeds.py (on the signed feed's files),
repro-verify.sh (on the reproduced binary) and ci-trixie.sh (on the binary its
smoke test runs). Each used to spell the strings itself, and copies drift:
ci-trixie.sh searched for "no licence checked" while the binary says "no
license checked", so its unlocked-build check could never fire, and the two
Linux publish checks had no copy at all (1.0.6 review, R-001: the scan was run
by hand on the staged files instead). build-windows.sh and build-flatpak.sh
still carry their own copies; check-linux-feeds-test.sh pins those equal to
this file, so a change here that is not made there fails a test.

What is searched for, as raw bytes anywhere in the file (the same thing
`strings -a FILE | grep -F` finds for these ASCII strings):

  * FEATURE MARKERS: text that only a non-public build compiles in.
      chat              the first line of the chat attribution file
                        (crates/app/src/chrome/attribution/*-chat.txt), which
                        about.rs include_str!s only under cfg(feature = "chat").
                        The window title is NOT usable: it is short enough that
                        rustc builds it from immediates and it never appears as
                        contiguous bytes (build-windows.sh has the measurement).
      premium-unlocked  about.rs UNLOCKED_BUILD_MARKER, compiled only under
                        cfg(feature = "premium-unlocked").
  * BUILD PATHS: /.cargo/ and /.rustup/ as directory names inside a path,
    which is what an unremapped registry or toolchain path looks like
    (/root/.cargo/registry/..., /root/.rustup/toolchains/...). The remapped
    forms (/cargo, /rust, /build) have no dot. Anchored between slashes so a
    domain in the compiled-in ad list (ads.cargo.lt) can never match, the same
    rule build-windows.sh documents.

Usage:
  forbidden-build-markers.py FILE...                  markers and build paths
  forbidden-build-markers.py --markers-only FILE...   markers only, for a plain
                                                      cargo build that was never
                                                      remapped (ci-trixie.sh)
  forbidden-build-markers.py --list                   kind<TAB>string, one per line

Exit 0 when every file is clean, 1 when any carries something (each finding is
printed), 2 when a file cannot be read or the arguments are wrong. A file that
cannot be read is a refusal, never a pass.
"""

import mmap
import os
import sys

# (feature, marker). Text that exists in the binary only when that feature was
# compiled in.
FEATURE_MARKERS = (
    ("chat", "PATANYX-Nabu-X for "),
    ("premium-unlocked", "UNLOCKED TEST BUILD: Premium forced on; no license checked"),
)

# A dotted cargo or rustup directory inside a path: an unremapped build path.
PATH_LEAKS = ("/.cargo/", "/.rustup/")

USAGE = "usage: forbidden-build-markers.py [--markers-only] FILE... | --list"


def _context(buf, at, size):
    """The printable run around offset `at`, bounded, for the error message."""
    start = at
    while start > 0 and at - start < 60 and 0x20 <= buf[start - 1] < 0x7F:
        start -= 1
    end = at
    while end < size and end - at < 80 and 0x20 <= buf[end] < 0x7F:
        end += 1
    return bytes(buf[start:end]).decode("ascii", "replace")


def _offsets(buf, needle):
    found = []
    at = buf.find(needle)
    while at != -1:
        found.append(at)
        at = buf.find(needle, at + 1)
    return found


def scan(path, paths=True):
    """Every finding in the file at `path`, as one line of text each.

    Raises OSError when the file cannot be read; a caller must treat that as a
    refusal.
    """
    findings = []
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            return findings
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            for feature, marker in FEATURE_MARKERS:
                if buf.find(marker.encode("ascii")) != -1:
                    findings.append(
                        f"carries the {feature} build marker {marker!r}: it was built with "
                        f"--features {feature}, which is never published"
                    )
            if paths:
                for leak in PATH_LEAKS:
                    hits = _offsets(buf, leak.encode("ascii"))
                    if hits:
                        findings.append(
                            f"embeds {len(hits)} build-machine path(s) containing {leak}, "
                            f"first: {_context(buf, hits[0], size)!r} (a --remap-path-prefix "
                            f"is missing or stopped matching; see scripts/repro-build.sh)"
                        )
    return findings


def main(argv):
    if argv == ["--list"]:
        for feature, marker in FEATURE_MARKERS:
            print(f"{feature}\t{marker}")
        for leak in PATH_LEAKS:
            print(f"path\t{leak}")
        return 0
    paths = True
    if argv and argv[0] == "--markers-only":
        paths = False
        argv = argv[1:]
    if not argv or any(a.startswith("--") for a in argv):
        print(USAGE, file=sys.stderr)
        return 2
    status = 0
    for path in argv:
        try:
            findings = scan(path, paths=paths)
        except OSError as e:
            print(f"FORBIDDEN-MARKER SCAN REFUSED: {path} cannot be read: {e}", file=sys.stderr)
            return 2
        for finding in findings:
            print(f"FORBIDDEN: {path} {finding}", file=sys.stderr)
            status = 1
        if not findings:
            what = "no non-public build marker, no build path" if paths else "no non-public build marker"
            print(f"clean: {path} ({what})")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
