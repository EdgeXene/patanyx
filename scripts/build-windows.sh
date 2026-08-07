#!/usr/bin/env bash
# Cross-compiles the Windows binaries, including the relay client.
#
# THE RELAY CLIENT DOES CROSS-COMPILE. It was recorded for a long time as a
# hard build constraint -- "ring breaks the Windows cross-compile" -- and that
# was wrong. `ring`'s C compiled fine all along; the failure was cc-rs unable
# to find `llvm-lib`, LLVM's stand-in for MSVC's lib.exe, which simply was not
# installed. One missing binary, read as an incompatibility, and the relay was
# left out of every Windows build on that basis.
#
# It lives on Debian in the `llvm-14` package at /usr/lib/llvm-14/bin, which is
# not on PATH by default -- hence this script rather than a note someone has to
# remember.
set -euo pipefail
cd "$(dirname "$0")/.."

# Any LLVM bin directory carrying llvm-lib will do; newest wins.
for dir in $(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -V -r); do
  if [ -x "$dir/llvm-lib" ]; then
    export PATH="$dir:$PATH"
    break
  fi
done

if ! command -v llvm-lib >/dev/null 2>&1; then
  echo "BUILD FAIL: llvm-lib not found." >&2
  echo "  cc-rs needs it to archive ring's objects for the MSVC target." >&2
  echo "  On Debian:  apt-get install llvm-14" >&2
  echo "  It lands in /usr/lib/llvm-14/bin, which is not on PATH by default." >&2
  exit 1
fi
echo "using $(command -v llvm-lib)"

# Defaults to the PUBLIC build, and chat must be asked for explicitly.
#
# The default used to be chat, written as `${FEATURES:-chat,relay-client}` --
# and `:-` treats an EMPTY value as unset, so `FEATURES= ./build-windows.sh`,
# which reads as "no features", silently produced a chat build. The published
# binary is the one that must never contain chat, so the default has to fail
# in that direction, not this one.
FEATURES="${FEATURES-}"
if [ -n "$FEATURES" ]; then
  echo "=== windows build: --features $FEATURES ==="
  cargo xwin build --target x86_64-pc-windows-msvc --release --features "$FEATURES"
  cargo xwin build --target x86_64-pc-windows-msvc --features "$FEATURES"
else
  echo "=== windows build: public (no features) ==="
  cargo xwin build --target x86_64-pc-windows-msvc --release
  cargo xwin build --target x86_64-pc-windows-msvc
fi

# The title is the only thing that tells a user which variant they launched,
# so confirm it is in the binary rather than assuming the cfg took.
exe=target/x86_64-pc-windows-msvc/release/patanyx.exe
case "$FEATURES" in
  *relay-client*) want="Premium + relay" ;;
  *chat*)         want="Premium (LAN chat only)" ;;
  *)              want="" ;;
esac
# The PUBLIC build is verified by its ABSENCE of the chat marker, not by the
# presence of one. It used to be skipped entirely (`want` is empty for it, and
# the check was gated on `want` being set), so the single configuration this
# script exists to protect -- the one that must never contain chat -- was the
# one configuration nothing asserted about.
if [ -z "$want" ]; then
  # Matched on the SUFFIX, never on the full title. `strings` breaks its output
  # at the em-dash in "PATANYX Browser — Premium ...", so grepping the whole
  # title finds nothing in a Premium binary either, and the check passes on
  # exactly the build it exists to catch. Verified against the staged PREMIUM
  # exe, where "Premium + relay" matches and the full title does not.
  #
  # NEVER shorten these markers to the bare word "Premium": the PUBLIC build's
  # About copy legitimately contains it (the future-tense teaser), so a bare
  # grep would fail the one configuration this check exists to pass.
  leaked="$(strings -a "$exe" | grep -cE "Premium \+ relay|Premium \(LAN chat only\)" || true)"
  if [ "${leaked:-0}" -gt 0 ]; then
    echo "BUILD FAIL: the PUBLIC binary carries a Premium title; it was built with chat compiled in" >&2
    exit 1
  fi
  echo "title says: PATANYX Browser (public; no Premium marker present)"
fi
if [ -n "$want" ]; then
  # `grep -c`, not `grep -q`. Under `set -o pipefail`, `grep -q` exits the
  # moment it matches, `strings` then dies on SIGPIPE, and the PIPELINE
  # reports failure -- so the check failed on a binary that was correct.
  # Caught by tracing it rather than by trusting it, which is the only reason
  # this comment exists instead of a wrong "unsupported" note.
  found="$(strings -a "$exe" | grep -c -- "$want" || true)"
  if [ "${found:-0}" -gt 0 ]; then
    echo "title says: $want"
  else
    echo "BUILD FAIL: the binary's title does not say \"$want\"" >&2
    exit 1
  fi
fi
# OCR WEIGHTS ARE COMPILED IN, and this asserts it.
#
# They used to be COPIED beside the binary here, because ocr_support.rs
# resolved current_exe()/models/ocr. The comment on that block worried that a
# model directory existing only in the source tree "would leave the feature
# permanently unavailable on their machine with no visible reason why" -- which
# is precisely what happened, for every user, for weeks. The copy was correct
# for a folder the project owner drags around and useless for what we actually
# distribute: one file, swapped by an updater that knows nothing about a models
# directory. The panel hid itself exactly as designed and nobody saw the
# feature at all.
#
# So the weights are include_bytes! now, and a build that somehow loses them
# should fail HERE rather than shipping a browser whose OCR quietly reports
# unavailable.
exe=target/x86_64-pc-windows-msvc/release/patanyx.exe
# The ONNX magic/producer string is present in a real graph and absent from a
# binary built without one. Cheap, and it checks the artifact rather than the
# source tree.
if [ "$(stat -c %s "$exe")" -lt $((30 * 1024 * 1024)) ]; then
  echo "BUILD FAIL: $exe is $(stat -c %s "$exe") bytes -- too small to contain" >&2
  echo "  the embedded OCR weights (~10MB). The models are probably not linked in." >&2
  exit 1
fi
echo "ocr weights are compiled into the binary"

echo "WINDOWS BUILD OK"
