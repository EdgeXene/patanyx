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

if ! command -v llvm-rc >/dev/null 2>&1 && ! command -v llvm-rc-14 >/dev/null 2>&1; then
  echo "BUILD FAIL: llvm-rc not found." >&2
  echo "  build.rs needs it to compile the icon and version resource into the" >&2
  echo "  exe. Without a resource the binary has NO ICON and a pinned taskbar" >&2
  echo "  shortcut shows the blank placeholder (reported from hardware," >&2
  echo "  2026-08-18). It ships beside llvm-lib in the same LLVM bin dir." >&2
  exit 1
fi
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
# CONTROL FLOW GUARD, and the path prefix that used to name this machine.
#
# A security review of the SHIPPED BINARY found DllCharacteristics carrying
# ASLR, high-entropy ASLR and DEP but NOT GUARD_CF, while a .00cfg section
# and a load-config directory were present -- the signature of a link that
# could have had CFG and was never asked for it. CFG validates indirect-call
# targets, so its absence does not create a bug; it lowers the cost of
# turning one into control-flow hijack. Every other browser ships it.
#
# `-C control-flow-guard` is STABLE rustc (it was `-Z` once, which is why
# reviews still call it nightly-only), so this needs nothing beyond the
# pinned toolchain, whatever rust-toolchain.toml currently names. Spelling the
# version here bought nothing and went stale the day the pin moved. The linker flag arms the CRT objects that carry
# CFG metadata already; the rustc flag is what instruments OUR code, and
# without it the linker flag alone would set a bit this binary had not
# earned.
#
# --remap-path-prefix answers the same review's information-leak finding:
# panic strings embedded /root/.cargo/... into the artifact, telling anyone
# with `strings` that the build runs as root and how its disk is laid out.
# Remapping keeps the panic messages useful and stops them describing this
# machine.
CFG_FLAGS="-C control-flow-guard=yes -C link-arg=/guard:cf"
# The SAME THREE roots repro-build.sh normalizes, spelled identically. A second
# convention here (/patanyx instead of /build) would make this script and the
# reproducible build disagree on the bytes they produce, which is the one thing
# docs/reproducible-builds.md exists to prevent.
#
# THE SYSROOT IS THE THIRD, and it was missing until 2026-08-27. Remapping
# CARGO_HOME and the source root still left 39 copies of
# /root/.rustup/toolchains/<version>-<host>/lib/rustlib/src/rust/library/... in
# the shipped exe: those are std's OWN panic locations, which come from the
# toolchain rather than from our code or our dependencies, so neither of the
# other two prefixes could reach them. They named the account the build ran
# under, the toolchain version and the build host triple. Measured before and
# after on a real exe: 39 occurrences, then zero.
#
# Computed at runtime, never hardcoded, for the reason the comment in
# repro-build.sh gives: a literal /root/.rustup would be correct on exactly one
# machine. rust-toolchain.toml pins the channel, so this resolves to the same
# pinned toolchain for everyone, and remapping erases the version and host
# triple from the artifact along with the path.
SYSROOT="$(rustc --print sysroot)"
REMAP="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$PWD=/build --remap-path-prefix=${SYSROOT}=/rust"
export RUSTFLAGS="${RUSTFLAGS:-} $CFG_FLAGS $REMAP"
echo "hardening: control-flow-guard on, build paths remapped"

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
target_dir="${CARGO_TARGET_DIR:-target}"
exe="$target_dir/x86_64-pc-windows-msvc/release/patanyx.exe"
case "$FEATURES" in
  *premium-unlocked*) want="UNLOCKED TEST BUILD: Premium forced on; no license checked" ;;
  *chat*)             want="PATANYX-Nabu-X for " ;;
  *)                  want="" ;;
esac
# The PUBLIC build is verified by its ABSENCE of the chat marker, not by the
# presence of one. It used to be skipped entirely (`want` is empty for it, and
# the check was gated on `want` being set), so the single configuration this
# script exists to protect -- the one that must never contain chat -- was the
# one configuration nothing asserted about.
if [ -z "$want" ]; then
  # THE MARKER IS THE ATTRIBUTION HEADER, NOT THE WINDOW TITLE, AND THAT IS
  # A MEASURED DECISION RATHER THAN A PREFERENCE.
  #
  # The obvious marker is the title, and it does not work. "PATANYX Nabu-X"
  # is fourteen bytes, so rustc does not put it in .rdata at all: it builds
  # the string at runtime from two eight-byte immediate moves, and the
  # disassembly reads movabs rax,"X Nabu-X" / movabs rax,"PATANYX ". The
  # phrase never exists as contiguous bytes in the file, so grep and strings
  # both find nothing, and a gate matching it passes the very build it is
  # meant to catch. Verified by searching the raw bytes of a built exe.
  # The old title survived only because "PATANYX Browser — Premium + relay"
  # was long enough to be stored; shortening the name removed that accident.
  #
  # The attribution header is a better marker anyway. about.rs picks
  # windows-chat.txt or windows.txt on cfg(feature = "chat"), so the header
  # tracks the COMPILED FEATURE by construction rather than by a developer
  # remembering to update a string, it is include_str!'d from a 300 KB file
  # so it is always in .rdata, and attribution-gate.sh independently
  # regenerates and diffs it, so it cannot drift unnoticed.
  #
  # The window title is still asserted, by main.rs::build_variant_tests,
  # which compares Rust strings and is unaffected by how they are stored.
  leaked="$(strings -a "$exe" | grep -cE "PATANYX-Nabu-X for |UNLOCKED TEST BUILD: Premium forced on; no license checked" || true)"
  if [ "${leaked:-0}" -gt 0 ]; then
    echo "BUILD FAIL: the PUBLIC binary carries a non-public Nabu-X title marker" >&2
    echo "  It was built with chat or premium-unlocked compiled in; refusing to stage it as public." >&2
    exit 1
  fi
  echo "attribution says: PATANYX (public; no Nabu-X build marker present)"
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
    echo "BUILD FAIL: the binary does not carry the marker \"$want\"" >&2
    exit 1
  fi
fi
# NO BUILD-MACHINE PATHS IN THE ARTIFACT, and this asserts it.
#
# The remap flags above are the fix; this is the check that they still work.
# Without it the flags are a diff nobody re-verifies, which is how the sysroot
# leak survived the first path-leak fix: that round set two prefixes, moved on,
# and nothing measured the result. 39 copies of the build account shipped.
#
# Matched on the DOTTED directory names, which are what a real leak looks like
# (/root/.cargo/..., /root/.rustup/toolchains/...). The remapped forms have no
# dot (/cargo, /rust, /build), so they cannot match this and a correct binary
# stays silent.
# ANCHORED TO A PATH COMPONENT. The unanchored form (\.cargo|\.rustup) was
# sound while no compiled-in DATA contained ".cargo" -- then the ad list
# arrived carrying ads.cargo.lt, assets.cargoboard.com and three more, and
# every Windows build failed on a binary where nothing had leaked. A real
# leak is a dotted DIRECTORY inside a path (/root/.cargo/registry/...), so
# the dot must sit between slashes; a domain can never match.
leaked_paths="$(strings -a "$exe" | grep -cE '/\.(cargo|rustup)/' || true)"
if [ "${leaked_paths:-0}" -gt 0 ]; then
  echo "BUILD FAIL: $leaked_paths build-machine path(s) embedded in the binary" >&2
  echo "  A --remap-path-prefix is missing or stopped matching. Offenders:" >&2
  strings -a "$exe" | grep -oE '[^ "]*/\.(cargo|rustup)/[^ "]{0,60}' | sort -u | head -5 >&2
  echo "  Fix the REMAP line above, and mirror it in scripts/repro-build.sh." >&2
  exit 1
fi
# Positive control: prove the remap RAN rather than that the paths merely
# vanished. A binary with neither the real paths nor the remapped ones would
# pass the check above while telling us nothing.
remapped="$(strings -a "$exe" | grep -cE '^/cargo|^/rust' || true)"
if [ "${remapped:-0}" -eq 0 ]; then
  echo "BUILD FAIL: no remapped /cargo or /rust paths found either." >&2
  echo "  The absence check above is therefore meaningless. Investigate." >&2
  exit 1
fi
echo "paths: no build-machine paths present, $remapped remapped references"

# OCR WEIGHTS ARE COMPILED IN, and this asserts it.
#
# They used to be COPIED beside the binary here, because ocr_support.rs
# resolved current_exe()/models/ocr. The comment on that block worried that a
# model directory existing only in the source tree "would leave the feature
# permanently unavailable on their machine with no visible reason why" -- which
# is precisely what happened, for every user, for weeks. The copy was correct
# for a folder dragged around by hand and useless for what we actually
# distribute: one file, swapped by an updater that knows nothing about a models
# directory. The panel hid itself exactly as designed and nobody saw the
# feature at all.
#
# So the weights are include_bytes! now, and a build that somehow loses them
# should fail HERE rather than shipping a browser whose OCR quietly reports
# unavailable.
exe="$target_dir/x86_64-pc-windows-msvc/release/patanyx.exe"
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
