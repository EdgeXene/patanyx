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
# BEFORE the trap is armed: the trap restores keys.rs from git, so a check
# that ran after arming it would destroy the very edit it refuses to run
# over. A modified ring is a developer's work in progress, not ours to drop.
git diff --quiet -- "$keys_rs" || { echo "PREMIUM E2E: keys.rs is already modified; refusing to run" >&2; exit 2; }
work="$(mktemp -d)"
# The two throwaway profiles, declared here so cleanup can remove them on
# every exit path -- a failed run used to leave a throwaway vault holding a
# throwaway token in /tmp.
data1="$(mktemp -d)"
data2="$(mktemp -d)"
smoke_port="${SMOKE_PORT:-18789}"
cleanup() {
  # The ring is restored from git no matter how this exits: a throwaway key
  # left in keys.rs is a build that trusts a key nobody holds.
  git checkout -- "$keys_rs" 2>/dev/null || true
  # The throwaway licence server was KEPT up for the activation half; it is
  # ours to stop. By its pid from the smoke log, never by name.
  if [ -n "${srv_pid:-}" ] && kill -0 "$srv_pid" 2>/dev/null; then kill "$srv_pid" 2>/dev/null || true; fi
  rm -rf "$work" "$data1" "$data2" "${smoke_scratch:-}"
}
trap cleanup EXIT
# H1: build where cargo builds. ci-trixie sets CARGO_TARGET_DIR=target/trixie,
# and a hardcoded ./target/debug/patanyx would then run whatever host binary
# happened to be there -- one WITHOUT the throwaway key -- and prove nothing.
bin="${CARGO_TARGET_DIR:-target}/debug/patanyx"

# ---- 1. mint on a throwaway seed -------------------------------------------
echo "=== premium e2e: minting on a throwaway key ==="
# KEEP=1: the server stays up on the throwaway seed so the browser half can
# ACTIVATE against it (the receipt must be signed by the same key the token
# was). RUSTBROWSE_LICENCE_DIR points the smoke's two crate cross-checks at
# THIS tree, so a branch is tested against its own licence crate.
KEEP=1 SMOKE_PORT="$smoke_port" RUSTBROWSE_LICENCE_DIR="$root/crates/licence" \
  "$server_repo/scripts/smoke-throwaway.sh" > "$work/smoke.log" 2>&1 || {
  echo "PREMIUM E2E FAIL: the server smoke did not pass" >&2; tail -20 "$work/smoke.log" >&2; exit 1; }
token="$(awk -F= '/^TOKEN_TEXT=/{print $2}' "$work/smoke.log")"
pubkey="$(awk -F= '/^PUBKEY_HEX=/{print $2}' "$work/smoke.log")"
srv_pid="$(sed -n 's/^kept: .*server pid \([0-9]*\) still.*/\1/p' "$work/smoke.log")"
smoke_scratch="$(sed -n 's/^kept: \([^ ]*\) .*/\1/p' "$work/smoke.log")"
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
echo "  refused as not-issued, gate stayed shut"

# ---- 3. a THROWAWAY build must accept it -----------------------------------
echo "=== premium e2e: a build carrying the throwaway key accepts it ==="
python3 - "$keys_rs" "$pubkey" <<'PY'
import re, sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text()
new, n = re.subn(r'(pub const LICENCE_KEYS: &\[&str\] =\s*&\[")[0-9a-f]{64}("\];)', r'\g<1>' + sys.argv[2] + r'\2', s)
assert n == 1, "LICENCE_KEYS ring not found in the expected one-key shape"
p.write_text(new)
PY
cargo build --quiet
if ! XDG_DATA_HOME="$data2" PATANYX_SMOKE_LICENCE_TOKEN="$token" PATANYX_LICENCE_ORIGIN="http://127.0.0.1:$smoke_port" \
     xvfb-run -a --server-args="-screen 0 1280x900x24" "$bin" --smoke-test > "$work/throwaway.log" 2>&1; then
  echo "PREMIUM E2E FAIL: smoke with the throwaway token on the throwaway ring" >&2; tail -20 "$work/throwaway.log" >&2; exit 1; fi
grep -q "SMOKE OK" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: throwaway run did not print SMOKE OK" >&2; tail -20 "$work/throwaway.log" >&2; exit 1; }
grep -q "SMOKE licence: token accepted, gate opened and closed" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the accept proof did not run (env var lost?)" >&2; exit 1; }
grep -q "SMOKE licence: device activated, receipt bound offline" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the activation proof did not run" >&2; tail -20 "$work/throwaway.log" >&2; exit 1; }
grep -q "SMOKE licence: foreign-device receipt refused, release and re-activation round-trip" "$work/throwaway.log" || { echo "PREMIUM E2E FAIL: the receipt-binding / release proof did not run" >&2; exit 1; }
# The server's own view: this device activated, released, activated again.
health="$(curl -s "http://127.0.0.1:$smoke_port/health")"
# The smoke itself released one device (its step 8); the browser's makes two.
echo "$health" | grep -q '^releases 2$' || { echo "PREMIUM E2E FAIL: the server did not count the browser's release" >&2; echo "$health" >&2; exit 1; }
[ -f "$data2/patanyx/device-id" ] || [ -n "$(find "$data2" -name device-id | head -1)" ] || { echo "PREMIUM E2E FAIL: no device-id file was minted beside the vault" >&2; exit 1; }
echo "  accepted, activated against the throwaway server, receipt bound, foreign receipt refused,"
echo "  released + re-activated, removed, gate shut again"

# ---- 4. restore the ring and rebuild so nothing downstream sees the key -----
git checkout -- "$keys_rs"
cargo build --quiet
git diff --quiet -- "$keys_rs" || { echo "PREMIUM E2E FAIL: keys.rs not restored" >&2; exit 1; }
echo "PREMIUM E2E OK"
