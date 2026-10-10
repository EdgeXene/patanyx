#!/usr/bin/env bash
# Proves scripts/check-linux-feeds.py accepts the right mapping and refuses
# every wrong one. Stand-in binaries answer --build-identity with a chosen
# identity; manifests are built to match them, so each case changes ONE thing.
# A checker never seen refusing is not a checker.
set -u
here=$(cd "$(dirname "$0")" && pwd)
check="$here/check-linux-feeds.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0

# fake <name> <variant> <compiled-floor> [version]
fake() {
  local f="$work/$1"
  printf '#!/bin/sh\n[ "$1" = "--build-identity" ] || exit 9\necho '\''{"version":"%s","variant":"%s","platform":"linux-x86_64","compiled_webkitgtk_floor":"%s"}'\''\n' \
    "${4:-1.0.6}" "$2" "$3" >"$f"
  chmod +x "$f"
  echo "$f"
}

# manifest <out> <binary> <floor-or-empty> [version] [url]
manifest() {
  local out="$1" bin="$2" floor="$3" version="${4:-1.0.6}" url="${5:-https://example.invalid/$(basename "$2")}"
  python3 -I - "$out" "$bin" "$floor" "$version" "$url" <<'PY'
import hashlib, json, os, sys
out, binary, floor, version, url = sys.argv[1:]
p = {"version": version, "platform": "linux-x86_64", "url": url,
     "sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
     "size": os.path.getsize(binary), "published_at": 1791700000}
if floor:
    p["engine_floor"] = {"webkitgtk": floor}
json.dump({"v": 1, "payload": json.dumps(p), "sig": "00"}, open(out, "w"))
PY
}

expect() {  # expect <ok|refuse> <label> <args...>
  local want="$1" label="$2"; shift 2
  if python3 -I "$check" "$@" >"$work/out" 2>&1; then got=ok; else got=refuse; fi
  if [ "$got" = "$want" ]; then
    echo "  ok  $label"
  else
    echo "  FAIL $label: expected $want, got $got"; sed 's/^/       /' "$work/out"; fail=1
  fi
}

strict=$(fake strict strict 2.54.0)
bridge=$(fake bridge bridge 2.52.5)
manifest "$work/v2.json" "$strict" 2.54.0
manifest "$work/v2b.json" "$strict" 2.54.0
manifest "$work/v1.json" "$bridge" 2.54.0
manifest "$work/v1b.json" "$bridge" 2.54.0
V2=(--v2-manifest "$work/v2.json" --v2-beta-manifest "$work/v2b.json" --v2-binary "$strict")
BRIDGE=(--v1-manifest "$work/v1.json" --v1-beta-manifest "$work/v1b.json" --v1-binary "$bridge")
f1=$(sha256sum "$work/v1.json" | cut -d' ' -f1); f1b=$(sha256sum "$work/v1b.json" | cut -d' ' -f1)
FROZEN=(--v1-manifest "$work/v1.json" --v1-beta-manifest "$work/v1b.json" --v1-frozen "$f1" --v1-beta-frozen "$f1b")

echo "=== check-linux-feeds.py ==="
expect ok     "the 1.0.6 bridge release passes" "${V2[@]}" "${BRIDGE[@]}"
expect ok     "a later release with a frozen /v1 passes" "${V2[@]}" "${FROZEN[@]}"
expect refuse "a release that skips /v1 entirely is refused" "${V2[@]}" \
  --v1-manifest "$work/v1.json" --v1-beta-manifest "$work/v1b.json"

manifest "$work/v1-strict.json" "$strict" 2.54.0 1.0.6 https://example.invalid/v1-strict
expect refuse "the strict build on /v1 is refused" "${V2[@]}" \
  --v1-manifest "$work/v1-strict.json" --v1-beta-manifest "$work/v1b.json" --v1-binary "$strict"
manifest "$work/v1b-strict.json" "$strict" 2.54.0 1.0.6 https://example.invalid/v1b-strict
expect refuse "the strict build on /v1 BETA is refused" "${V2[@]}" \
  --v1-manifest "$work/v1.json" --v1-beta-manifest "$work/v1b-strict.json" --v1-binary "$bridge"
manifest "$work/v2-bridge.json" "$bridge" 2.54.0
expect refuse "the bridge on /v2 is refused" \
  --v2-manifest "$work/v2-bridge.json" --v2-beta-manifest "$work/v2-bridge.json" --v2-binary "$bridge" "${FROZEN[@]}"
manifest "$work/v2b-nofloor.json" "$strict" ""
expect refuse "a /v2 BETA manifest without engine_floor is refused" \
  --v2-manifest "$work/v2.json" --v2-beta-manifest "$work/v2b-nofloor.json" --v2-binary "$strict" "${FROZEN[@]}"

low=$(fake low bridge 2.52.4); manifest "$work/v1-low.json" "$low" 2.54.0
expect refuse "a bridge floor BELOW 2.52.5 is refused" "${V2[@]}" \
  --v1-manifest "$work/v1-low.json" --v1-beta-manifest "$work/v1-low.json" --v1-binary "$low"
high=$(fake high bridge 2.52.6); manifest "$work/v1-high.json" "$high" 2.54.0
expect refuse "a bridge floor ABOVE 2.52.5 is refused" "${V2[@]}" \
  --v1-manifest "$work/v1-high.json" --v1-beta-manifest "$work/v1-high.json" --v1-binary "$high"

manifest "$work/v2-nofloor.json" "$strict" ""
expect refuse "a /v2 manifest without engine_floor is refused" \
  --v2-manifest "$work/v2-nofloor.json" --v2-beta-manifest "$work/v2b.json" --v2-binary "$strict" "${FROZEN[@]}"
manifest "$work/v2-lowfloor.json" "$strict" 2.52.5
expect refuse "a /v2 floor that disagrees with the strict build is refused" \
  --v2-manifest "$work/v2-lowfloor.json" --v2-beta-manifest "$work/v2b.json" --v2-binary "$strict" "${FROZEN[@]}"

other=$(fake other strict 2.54.0 1.0.6); echo "# changed" >>"$other"
expect refuse "a binary that does not match the manifest hash is refused" \
  --v2-manifest "$work/v2.json" --v2-beta-manifest "$work/v2b.json" --v2-binary "$other" "${FROZEN[@]}"

expect refuse "a frozen /v1 that changed is refused" "${V2[@]}" \
  --v1-manifest "$work/v1-strict.json" --v1-beta-manifest "$work/v1b.json" --v1-frozen "$f1" --v1-beta-frozen "$f1b"
expect refuse "a frozen /v1 BETA that changed is refused" "${V2[@]}" \
  --v1-manifest "$work/v1.json" --v1-beta-manifest "$work/v1b-strict.json" --v1-frozen "$f1" --v1-beta-frozen "$f1b"
expect refuse "bridge and frozen together are refused" "${V2[@]}" "${BRIDGE[@]}" --v1-frozen "$f1" --v1-beta-frozen "$f1b"

manifest "$work/v1b-highfloor.json" "$bridge" 2.60.0
expect refuse "a /v1 BETA floor above /v2's is refused" "${V2[@]}" \
  --v1-manifest "$work/v1.json" --v1-beta-manifest "$work/v1b-highfloor.json" --v1-binary "$bridge"
manifest "$work/v2b-highfloor.json" "$strict" 2.60.0
expect refuse "a /v2 BETA floor that differs from /v2's is refused" \
  --v2-manifest "$work/v2.json" --v2-beta-manifest "$work/v2b-highfloor.json" --v2-binary "$strict" "${FROZEN[@]}"

# A LATER release trying bridge mode: real 1.0.7 binaries and manifests.
strict7=$(fake strict7 strict 2.54.0 1.0.7); bridge7=$(fake bridge7 bridge 2.52.5 1.0.7)
manifest "$work/v2-7.json" "$strict7" 2.54.0 1.0.7; manifest "$work/v2b-7.json" "$strict7" 2.54.0 1.0.7
manifest "$work/v1-7.json" "$bridge7" 2.54.0 1.0.7; manifest "$work/v1b-7.json" "$bridge7" 2.54.0 1.0.7
expect refuse "bridge mode in a later release (1.0.7) is refused" \
  --v2-manifest "$work/v2-7.json" --v2-beta-manifest "$work/v2b-7.json" --v2-binary "$strict7" \
  --v1-manifest "$work/v1-7.json" --v1-beta-manifest "$work/v1b-7.json" --v1-binary "$bridge7"
expect ok     "a later release (1.0.7) with /v1 frozen passes" \
  --v2-manifest "$work/v2-7.json" --v2-beta-manifest "$work/v2b-7.json" --v2-binary "$strict7" "${FROZEN[@]}"

if [ "$fail" -ne 0 ]; then echo "LINUX FEEDS GATE FAILED"; exit 1; fi
echo "LINUX FEEDS GATE OK"
