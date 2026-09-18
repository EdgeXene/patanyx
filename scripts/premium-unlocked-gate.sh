#!/usr/bin/env bash
# Build and run the compile-time-only v1 Premium-unlocked test artifact.
#
# This gate supplies no token, activation origin, receipt, or runtime override.
# The only authority to open Premium is `--features premium-unlocked`, and the
# real dispatcher prints one WP-K proof line for every gated arm. At the same
# time, licence_get must keep reporting the actual empty/free vault.
set -euo pipefail
cd "$(dirname "$0")/.."

marker="UNLOCKED TEST BUILD: Premium forced on; no license checked"
target_dir="${CARGO_TARGET_DIR:-target/premium-unlocked}"
export CARGO_TARGET_DIR="$target_dir"

echo "=== premium-unlocked: compile-time variant ==="
cargo build --locked --features premium-unlocked
bin="$CARGO_TARGET_DIR/debug/patanyx"

found="$(strings -a "$bin" | grep -cF "$marker" || true)"
if [ "${found:-0}" -eq 0 ]; then
  echo "PREMIUM UNLOCKED FAIL: the binary carries no unlocked title/About marker" >&2
  exit 1
fi

# Keep even transient test state inside this disposable workspace. Besides
# respecting the release-workbench boundary, it makes the proof's ownership
# obvious if a killed process leaves anything behind.
mkdir -p "$CARGO_TARGET_DIR/wp-l-tmp"
data_dir="$(mktemp -d "$CARGO_TARGET_DIR/wp-l-tmp/profile.XXXXXX")"
cleanup() {
  rm -rf "$data_dir"
}
trap cleanup EXIT
export XDG_DATA_HOME="$data_dir"
export WEBKIT_DISABLE_COMPOSITING_MODE=1

out="$(xvfb-run -a --server-args="-screen 0 1280x900x24" \
  "$bin" --smoke-test 2>&1)" || {
  echo "$out" >&2
  echo "PREMIUM UNLOCKED FAIL: unlocked binary refused to start or crashed" >&2
  exit 1
}

premium_arms=(
  tabs_switcher_list tabs_batch_enter
  find_tabs_search find_tabs_goto
  ocr_region_capture ocr_region_scan
  archive_save archive_search archive_list archive_picture_stage
  download_compare_request change_compare_request
)
for arm in "${premium_arms[@]}"; do
  count="$(printf '%s\n' "$out" | grep -c "^SMOKE licence: arm $arm: premium_required off; .* on$" || true)"
  if [ "$count" -ne 1 ]; then
    echo "PREMIUM UNLOCKED FAIL: no unique open-gate proof for $arm" >&2
    printf '%s\n' "$out" | grep '^SMOKE licence: arm ' >&2 || true
    exit 1
  fi
done
printf '%s\n' "$out" | grep '^SMOKE licence: arm '
printf '%s\n' "$out" | grep -q \
  '^SMOKE licence: unlocked test gate open; real licence row remains free$' || {
  echo "PREMIUM UNLOCKED FAIL: the real free/no-token licence-row proof did not run" >&2
  exit 1
}
printf '%s\n' "$out" | grep -q '^SMOKE OK$' || {
  echo "PREMIUM UNLOCKED FAIL: browser smoke did not finish" >&2
  exit 1
}

echo "  title/About marker: $marker"
echo "  licence row: real Free/no-token state; gate: compile-time forced open"
echo "PREMIUM UNLOCKED OK"
