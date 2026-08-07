#!/usr/bin/env bash
# Runs the two-transport delivery probe, several times.
#
# ONCE IS NOT ENOUGH, and that is the point of the loop. This probe found a
# defect that only appeared in about one run in three: mDNS announces a host's
# addresses one at a time, a link-local IPv6 address often arrives first, and a
# failed dial to it used to end the whole session attempt while a perfectly
# good loopback address arrived milliseconds later. A single green run would
# have reported that code as working two times out of three.
#
# What it proves, on ONE host: real mDNS discovery, a real TCP link dialled to
# an announced address, a real handshake, a message sealed and delivered, and
# an acknowledgement that could only have come from the peer's own key -- plus
# the negative control, that a message to a departed peer is reported failed
# and never delivered.
#
# What it does NOT prove: anything that needs two machines. MTU, NAT, a switch
# that drops multicast, interface selection across a real network. Those stay
# outstanding and this must not be cited as covering them.
set -euo pipefail
cd "$(dirname "$0")/.."

RUNS="${RUNS:-5}"
echo "=== chat delivery probe, $RUNS runs ==="

pass=0
fail=0
for i in $(seq 1 "$RUNS"); do
  if out="$(cargo run -q -p patanyx-chat --example delivery-probe 2>/dev/null)"; then
    pass=$((pass + 1))
    echo "  run $i: OK"
  else
    fail=$((fail + 1))
    echo "  run $i: FAIL"
    echo "$out" | sed 's/^/    /'
  fi
done

echo
echo "passed $pass, failed $fail"
if [ "$fail" -ne 0 ]; then
  echo "DELIVERY PROBE FAILED — re-run one with PATANYX_PROBE_TRACE=1 for the event stream" >&2
  exit 1
fi
echo "DELIVERY PROBE OK ($pass/$RUNS)"
