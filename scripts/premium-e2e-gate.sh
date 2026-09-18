#!/usr/bin/env bash
# The licence flow END TO END, on a throwaway key, in the real binary.
#
# What every other check holds one link of, this holds together: a server
# mints a token from a signed payment, and a browser build pastes it through
# the real IPC, ACTIVATES this device against that same server (Phase 4: the
# real client, a real signed receipt, the real vault write, the real offline
# re-evaluation), turns Premium on, and a gated arm that refused a moment
# earlier answers. A receipt naming another device is proven NOT to count,
# release shuts the gate and re-activation reopens it. Then the token is
# removed and the arm refuses again.
#
# NO PRODUCTION SECRET IS TOUCHED. The signing seed is generated here and
# discarded; the verifying key it derives is compiled into a THROWAWAY build
# whose ring is exactly that one key. That build must ACCEPT the token. The
# ordinary build -- the real ring, the ceremony's key -- must REFUSE the same
# token as not issued. Both halves are asserted, so this proves the gate
# opens for the right key AND stays shut for the wrong one.
#
# Needs the licence server checkout beside this repo
# (../patanyx-licence-server) because that is where the minting side lives;
# its scripts/smoke-throwaway.sh does the minting.
#
# Runs the smoke sequence in the same way scripts/smoke.sh does (xvfb-run,
# a throwaway XDG_DATA_HOME), twice: once per build. Prints PREMIUM E2E OK.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$(pwd)"
server_repo="${LICENCE_SERVER_REPO:-$root/../patanyx-licence-server}"
[ -x "$server_repo/scripts/smoke-throwaway.sh" ] || {
  echo "PREMIUM E2E: no licence server checkout at $server_repo" >&2; exit 2; }

export WEBKIT_DISABLE_COMPOSITING_MODE=1
keys_rs="crates/licence/src/keys.rs"
# The production ring is read-only throughout this gate. A developer's ring
# edit is still a reason to refuse, because the "real ring" half would no
# longer mean the shipped ring.
git diff --quiet -- "$keys_rs" || { echo "PREMIUM E2E: keys.rs is already modified; refusing to run" >&2; exit 2; }
work="$(mktemp -d)"
# The two throwaway profiles, declared here so cleanup can remove them on
# every exit path -- a failed run used to leave a throwaway vault holding a
# throwaway token in /tmp.
data1="$(mktemp -d)"
data2="$(mktemp -d)"
smoke_port="${SMOKE_PORT:-18789}"
cleanup() {
  # The throwaway licence server was KEPT up for the activation half; it is
  # ours to stop. By its pid from the smoke log, never by name.
  if [ -n "${srv_pid:-}" ] && kill -0 "$srv_pid" 2>/dev/null; then
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
  fi
  rm -rf "$work" "$data1" "$data2" "${smoke_scratch:-}"
}
trap cleanup EXIT
# H1: build where cargo builds. ci-trixie sets CARGO_TARGET_DIR=target/trixie,
# and a hardcoded ./target/debug/patanyx would then run whatever host binary
# happened to be there -- one WITHOUT the throwaway key -- and prove nothing.
bin="${CARGO_TARGET_DIR:-target}/debug/patanyx"

# ---- 1. mint on a throwaway seed -------------------------------------------
echo "=== premium e2e: minting on a throwaway key ==="
# The server self-test is deliberately fail-closed against the client ring it
# compiles. Build the smoke in a detached sibling layout, with a detached copy
# of the licence crate carrying this run's key. Neither production source tree
# is edited, and the server still executes its real startup self-test.
detached="$work/detached"
detached_server="$detached/patanyx-licence-server"
detached_licence="$detached/rustbrowse/crates/licence"
mkdir -p "$detached_server" "$detached_licence" "$work/bin"
( cd "$server_repo" && tar --exclude='./target' --exclude='./.git' --exclude='./.cargo' -cf - . ) \
  | ( cd "$detached_server" && tar -xf - )
# HERMETIC ISOLATION. A host .cargo/config.toml `paths` override (a leftover
# dev pin to some worktree) would silently repoint the `patanyx-licence` path
# dependency away from the detached, throwaway-keyed crate this gate builds --
# so the server would embed a DIFFERENT ring and its boot self-test would fail
# on a seed/key mismatch that has nothing to do with the code under test.
# Exclude it from the copy AND belt-and-braces remove it here.
rm -rf "$detached_server/.cargo"
cp -a "$root/crates/licence/." "$detached_licence/"
real_openssl="$(command -v openssl)"
seed_hex="$($real_openssl rand -hex 32)"
pubkey="$(cd "$detached_licence" && cargo run -q --example mint_test_token -- \
  "$seed_hex" 0 00000000000000000000000000000000 1 2>/dev/null \
  | awk -F= '/^KEY_HEX=/{print $2}')"
[ ${#pubkey} = 64 ] || { echo "PREMIUM E2E FAIL: could not derive the throwaway key" >&2; exit 1; }
python3 - "$detached_licence/src/keys.rs" "$pubkey" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
new, n = re.subn(r'(pub const LICENCE_KEYS: &\[&str\] =\s*&\[")[0-9a-f]{64}("\];)', r'\g<1>' + sys.argv[2] + r'\2', s)
assert n == 1, "LICENCE_KEYS ring not found in the expected one-key shape"
p.write_text(new)
PY
ln -s "$root/scripts/openssl-smoke-wrapper.sh" "$work/bin/openssl"
# KEEP=1: the server stays up on the throwaway seed so the browser half can
# ACTIVATE against it (the receipt must be signed by the same key the token
# was). The OpenSSL shim supplies the seed whose public half is already in the
# detached ring; every signing and HMAC operation still uses real OpenSSL.
# H2: do not leak the browser's target directory into the detached server.
# ci-trixie sets a relative target/trixie, while callers may set an absolute
# path; unsetting handles both and matches smoke-throwaway.sh's own target/.
set +e
env -u CARGO_TARGET_DIR PATH="$work/bin:$PATH" PATANYX_REAL_OPENSSL="$real_openssl" \
  PATANYX_SMOKE_SEED_HEX="$seed_hex" KEEP=1 SMOKE_PORT="$smoke_port" \
  RUSTBROWSE_LICENCE_DIR="$detached_licence" \
  "$detached_server/scripts/smoke-throwaway.sh" > "$work/smoke.log" 2>&1
smoke_status=$?
set -e
# Parse cleanup ownership BEFORE checking success. The nested smoke prints
# this from its EXIT trap even after startup failure; delaying these reads used
# to strand both its process and /tmp/licence-smoke.* with the signing seed.
srv_pid="$(sed -n 's/^kept: .*server pid \([0-9]*\) still.*/\1/p' "$work/smoke.log")"
smoke_scratch="$(sed -n 's/^kept: \([^ ]*\) .*/\1/p' "$work/smoke.log")"
if [ "$smoke_status" -ne 0 ]; then
  echo "PREMIUM E2E FAIL: the server smoke did not pass" >&2
  tail -20 "$work/smoke.log" >&2
  exit 1
fi
token="$(awk -F= '/^TOKEN_TEXT=/{print $2}' "$work/smoke.log")"
[ "$(awk -F= '/^PUBKEY_HEX=/{print $2}' "$work/smoke.log")" = "$pubkey" ] || {
  echo "PREMIUM E2E FAIL: detached smoke used a different key" >&2; exit 1; }
[ -n "$token" ] && [ ${#pubkey} = 64 ] || { echo "PREMIUM E2E FAIL: no token/pubkey from the smoke" >&2; exit 1; }
[ -n "$srv_pid" ] && kill -0 "$srv_pid" 2>/dev/null || { echo "PREMIUM E2E FAIL: the smoke server was not kept up" >&2; exit 1; }
echo "  minted ${token:0:16}... verifying key ${pubkey:0:16}... server pid $srv_pid on :$smoke_port"

# ---- 2. the ORDINARY build must refuse it -----------------------------------
echo "=== premium e2e: the real ring refuses a foreign token ==="
cargo build --quiet
if ! XDG_DATA_HOME="$data1" PATANYX_SMOKE_FOREIGN_TOKEN="$token" PATANYX_LICENCE_ORIGIN="http://127.0.0.1:$smoke_port" \
     xvfb-run -a --server-args="-screen 0 1280x900x24" "$bin" --smoke-test > "$work/real.log" 2>&1; then
  echo "PREMIUM E2E FAIL: smoke with a foreign token on the REAL ring" >&2; tail -20 "$work/real.log" >&2; exit 1; fi
grep -q "SMOKE OK" "$work/real.log" || { echo "PREMIUM E2E FAIL: real-ring run did not print SMOKE OK" >&2; tail -20 "$work/real.log" >&2; exit 1; }
# M1: SMOKE OK alone cannot tell a vacuous run from a real one -- the
# sequence returns Ok(()) with nothing to prove when no token reaches it.
# The sequence prints one line per proof; require it.
grep -q "SMOKE licence: foreign token refused" "$work/real.log" || { echo "PREMIUM E2E FAIL: the foreign-token proof did not run (env var lost?)" >&2; exit 1; }
# The recovery-key scan must stay outside the paywall (it is how a locked-out
# user gets INTO the vault); the closed-gate run prints this only after the
# arm failed past the gate rather than at it.
grep -q "SMOKE licence: ocr_scan recovery not gated while leaks is" "$work/real.log" || { echo "PREMIUM E2E FAIL: the free recovery-scan proof did not run" >&2; exit 1; }
echo "  refused as not-issued, gate stayed shut"

# ---- 3. a THROWAWAY build must accept it -----------------------------------
echo "=== premium e2e: a build carrying the throwaway key accepts it ==="
detached_browser="$work/throwaway-browser"
mkdir -p "$detached_browser"
( tar --exclude='./target' --exclude='./.git' --exclude='./.cargo' -cf - . ) \
  | ( cd "$detached_browser" && tar -xf - )
rm -rf "$detached_browser/.cargo"
python3 - "$detached_browser/$keys_rs" "$pubkey" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
new, n = re.subn(r'(pub const LICENCE_KEYS: &\[&str\] =\s*&\[")[0-9a-f]{64}("\];)', r'\g<1>' + sys.argv[2] + r'\2', s)
assert n == 1, "LICENCE_KEYS ring not found in the expected one-key shape"
p.write_text(new)
PY
throwaway_target="$work/throwaway-target"
cargo build --quiet --manifest-path "$detached_browser/Cargo.toml" \
  --target-dir "$throwaway_target"
throwaway_bin="$throwaway_target/debug/patanyx"
if ! XDG_DATA_HOME="$data2" PATANYX_SMOKE_LICENCE_TOKEN="$token" PATANYX_LICENCE_ORIGIN="http://127.0.0.1:$smoke_port" \
     xvfb-run -a --server-args="-screen 0 1280x900x24" "$throwaway_bin" --smoke-test > "$work/throwaway.log" 2>&1; then
  echo "PREMIUM E2E FAIL: smoke with the throwaway token on the throwaway ring" >&2; tail -20 "$work/throwaway.log" >&2; exit 1; fi
grep -q "SMOKE OK" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: throwaway run did not print SMOKE OK" >&2; tail -20 "$work/throwaway.log" >&2; exit 1; }
grep -q "SMOKE licence: token accepted, gate opened and closed" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the accept proof did not run (env var lost?)" >&2; exit 1; }
grep -q "SMOKE licence: device activated, receipt bound offline" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the activation proof did not run" >&2; tail -20 "$work/throwaway.log" >&2; exit 1; }
premium_arms=(
  tabs_switcher_list tabs_batch_enter
  find_tabs_search find_tabs_goto
  ocr_region_capture ocr_region_scan ocr_scan
  archive_save archive_search archive_list archive_picture_stage
  download_compare_request change_compare_request
)
for arm in "${premium_arms[@]}"; do
  [ "$(grep -c "^SMOKE licence: arm $arm: premium_required off; .* on$" "$work/throwaway.log")" -eq 1 ] || {
    echo "PREMIUM E2E FAIL: no unique two-direction proof for $arm" >&2
    grep '^SMOKE licence: arm ' "$work/throwaway.log" >&2 || true
    exit 1
  }
done
# Keep every proof visible in the gate's own output. A successful browser log
# hidden in a temporary directory is not a human-readable release proof.
grep '^SMOKE licence: arm ' "$work/throwaway.log"
grep -q "SMOKE licence: foreign-device receipt refused, release and re-activation round-trip" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the receipt-binding / release proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: offline import activates own receipt, rejects foreign and malformed" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the offline receipt-import proof did not run" >&2; exit 1; }
# The server's own view: this device activated, released, activated again.
health="$(curl -s "http://127.0.0.1:$smoke_port/health")"
# The smoke itself released one device (its step 8); the browser releases
# three times (vault open; vault locked, result landing at the next unlock;
# vault write failing, release retried at the next unlock), so the server
# The number is every release that actually FREED a slot, and it is load
# bearing: when the browser wrongly fired a release from inside a paste or a
# receipt import, this count was what caught it (7 where 5 was right). The
# browser frees four -- with the vault open, interrupted by a restart, with
# its vault write failing, and once more for the foreign-pending guard --
# and each of those scenarios' RETRIES releases nothing, because releasing an
# already-released device is what the server counts as not active.
echo "$health" | grep -q '^releases 5$' || { echo "PREMIUM E2E FAIL: the server did not count exactly the browser's four slot releases" >&2; echo "$health" >&2; exit 1; }
grep -q "SMOKE licence: a started release survives a failed activation, and Activate now or an imported receipt cancels it" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the started-release user-action proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: a replay leaves a live worker's busy flag alone" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the replay-flag proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: a parked result for another licence does not block the retry" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the foreign-pending guard proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: a release whose write failed is retried at the next unlock" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the failed-write retry proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: an unresolved release outranks the activation retry" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the release-precedence proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: a parked activation result is applied without a second worker" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the parked-activation proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: a release interrupted by a restart is finished at the next unlock" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the interrupted-release proof did not run" >&2; exit 1; }
grep -q "SMOKE licence: released device stays released across a lock" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the stays-released proof did not run" >&2; exit 1; }
[ -f "$data2/patanyx/device-id" ] || [ -n "$(find "$data2" -name device-id | head -1)" ] || { echo "PREMIUM E2E FAIL: no device-id file was minted beside the vault" >&2; exit 1; }
echo "  accepted, activated against the throwaway server, receipt bound, foreign receipt refused,"
echo "  offline receipt import verified (own accepted, foreign + malformed refused),"
echo "  released + re-activated, removed, gate shut again"

# ---- 4. prove the production ring was never touched -------------------------
git diff --quiet -- "$keys_rs" || { echo "PREMIUM E2E FAIL: keys.rs not restored" >&2; exit 1; }
echo "PREMIUM E2E OK"
