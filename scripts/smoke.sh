#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export WEBKIT_DISABLE_COMPOSITING_MODE=1
# Throwaway vault location: the smoke run creates, locks, and unlocks a real
# vault file and must never touch the user's.
SMOKE_DATA="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DATA"' EXIT
export XDG_DATA_HOME="$SMOKE_DATA"

# Build first. This script used to run whatever binary happened to be on disk,
# which twice produced a "passing" smoke run against stale code — including one
# that cost about forty minutes of debugging a screenshot of a toolbar that had
# already been replaced. A gate that can pass without compiling the change is
# not a gate.
cargo build --quiet

xvfb-run -a --server-args="-screen 0 1280x900x24" ./target/debug/patanyx --smoke-test

# The smoke sequence enables ad blocking, which drives the raw-FFI content
# filter compile. That path is ASYNCHRONOUS, so "the app did not crash" proves
# almost nothing about it: WebKit writes the compiled bytecode only once the
# save actually completed. Its presence on disk is therefore the real evidence
# that the FFI call was well-formed and the callback ran.
FILTER_DIR="$SMOKE_DATA/patanyx/contentfilters"
if [ ! -d "$FILTER_DIR" ] || [ -z "$(ls -A "$FILTER_DIR" 2>/dev/null)" ]; then
  echo "SMOKE FAIL: no compiled content filter in $FILTER_DIR"
  echo "  ad blocking was enabled during the run, so WebKit should have cached"
  echo "  compiled bytecode there. An empty directory means the filter never"
  echo "  compiled and network blocking is not actually happening."
  exit 1
fi
echo "content filter compiled: $(ls -A "$FILTER_DIR" | head -1)"
