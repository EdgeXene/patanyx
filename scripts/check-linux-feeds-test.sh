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

# NON-PUBLIC BUILD MARKERS AND BUILD PATHS (1.0.6 review, R-001). A chat or
# premium-unlocked build answers --build-identity exactly like the public one,
# so only the bytes can tell. Each planted binary is a correct stand-in with
# ONE line appended, and its manifest is rebuilt from it, so the marker is the
# only thing wrong. A refusal for any other reason would not prove the scan, so
# each case also requires the refusal to name what was planted.
markers="$here/forbidden-build-markers.py"
chat_marker="PATANYX-Nabu-X for "
unlocked_marker="UNLOCKED TEST BUILD: Premium forced on; no license checked"

# plant <from> <name> <line>: a copy of a stand-in with one more line.
plant() {
  local f="$work/$2"
  cp "$1" "$f"
  printf '# %s\n' "$3" >>"$f"
  echo "$f"
}

expect_named() {  # expect_named <label> <text the refusal must contain> <args...>
  local label="$1" want="$2"; shift 2
  if python3 -I "$check" "$@" >"$work/out" 2>&1; then
    echo "  FAIL $label: expected refuse, got ok"; fail=1
  elif ! grep -qF -- "$want" "$work/out"; then
    echo "  FAIL $label: refused, but not for \"$want\""; sed 's/^/       /' "$work/out"; fail=1
  else
    echo "  ok  $label"
  fi
}

# planted_v2 <name> <line>: a /v2 run whose strict binary carries <line>.
planted_v2() {
  local bin; bin=$(plant "$strict" "$1" "$2")
  manifest "$work/$1.json" "$bin" 2.54.0
  P2=(--v2-manifest "$work/$1.json" --v2-beta-manifest "$work/$1.json" --v2-binary "$bin" "${FROZEN[@]}")
}

planted_v2 strict-chat "${chat_marker}Linux -- third-party software"
expect_named "a chat build on /v2 is refused" "chat build marker" "${P2[@]}"
planted_v2 strict-unlocked "PATANYX Browser -- $unlocked_marker"
expect_named "a premium-unlocked build on /v2 is refused" "premium-unlocked build marker" "${P2[@]}"
planted_v2 strict-cargo "/root/.cargo/registry/src/index.crates.io-0000/gtk-0.18.2/src/lib.rs"
expect_named "a binary with a /.cargo/ build path is refused" "containing /.cargo/" "${P2[@]}"
planted_v2 strict-rustup "/root/.rustup/toolchains/1.98.1-x86_64-unknown-linux-gnu/lib/rustlib/src"
expect_named "a binary with a /.rustup/ build path is refused" "containing /.rustup/" "${P2[@]}"
# Negative control: the remapped forms and ad-list domains that merely contain
# "cargo" are what a correct binary holds, and must pass.
planted_v2 strict-clean "/cargo/registry/src/x.rs /rust/library/std/src/lib.rs ads.cargo.lt assets.cargoboard.com /build/crates/app"
expect ok "remapped paths and cargo-like domains pass" "${P2[@]}"

bridge_chat=$(plant "$bridge" bridge-chat "${chat_marker}Linux -- third-party software")
manifest "$work/v1-chat.json" "$bridge_chat" 2.54.0
expect_named "a chat build as the /v1 bridge is refused" "chat build marker" "${V2[@]}" \
  --v1-manifest "$work/v1-chat.json" --v1-beta-manifest "$work/v1-chat.json" --v1-binary "$bridge_chat"

echo "=== forbidden-build-markers.py ==="
scan() {  # scan <want-exit> <label> <args...>
  local want="$1" label="$2"; shift 2
  python3 -I "$markers" "$@" >"$work/out" 2>&1; local got=$?
  if [ "$got" = "$want" ]; then echo "  ok  $label"; else
    echo "  FAIL $label: expected exit $want, got $got"; sed 's/^/       /' "$work/out"; fail=1; fi
}
scan 0 "a clean stand-in passes" "$strict"
scan 1 "a chat marker is found" "$work/strict-chat"
scan 1 "the unlocked marker is found" "$work/strict-unlocked"
scan 1 "a /.cargo/ path is found" "$work/strict-cargo"
scan 1 "a /.rustup/ path is found" "$work/strict-rustup"
scan 0 "remapped paths and cargo-like domains are not findings" "$work/strict-clean"
scan 1 "--markers-only still finds the unlocked marker" --markers-only "$work/strict-unlocked"
scan 0 "--markers-only ignores build paths (a plain cargo build)" --markers-only "$work/strict-cargo"
scan 1 "one marked file among clean ones fails the run" "$strict" "$work/strict-chat" "$bridge"
scan 2 "a file that cannot be read is a refusal, not a pass" "$work/does-not-exist"
scan 2 "no file at all is a usage error" --markers-only

# PINS: the one list is only right while it matches what the code compiles in,
# and while the two scripts that still keep their own copy agree with it.
src="$here/.."
pin() {  # pin <label> <condition...>
  local label="$1"; shift
  if "$@"; then echo "  ok  $label"; else echo "  FAIL $label"; fail=1; fi
}
listed() { python3 -I "$markers" --list | grep -qxF -- "$1$2$3"; }
tab=$'\t'
pin "the list carries the chat marker" listed chat "$tab" "$chat_marker"
pin "the list carries the unlocked marker" listed premium-unlocked "$tab" "$unlocked_marker"
pin "the list carries /.cargo/" listed path "$tab" /.cargo/
pin "the list carries /.rustup/" listed path "$tab" /.rustup/
pin "the unlocked marker is about.rs UNLOCKED_BUILD_MARKER" \
  grep -qF "\"$unlocked_marker\";" "$src/crates/app/src/about.rs"
for f in linux-chat windows-chat; do
  pin "the chat marker opens attribution/$f.txt" \
    sh -c 'case "$(head -1 "$1")" in "$2"*) exit 0 ;; esac; exit 1' _ \
    "$src/crates/app/src/chrome/attribution/$f.txt" "$chat_marker"
done
for f in linux windows; do
  pin "the chat marker is absent from the public attribution/$f.txt" \
    sh -c '! grep -qF "$2" "$1"' _ "$src/crates/app/src/chrome/attribution/$f.txt" "$chat_marker"
done
# Every feature marker in the list, not the two named above: a marker added to
# the list must be added to both copies too, or this fails.
while IFS="$tab" read -r kind text; do
  [ "$kind" = path ] && continue
  for s in build-windows.sh build-flatpak.sh; do
    pin "$s carries the $kind marker verbatim" grep -qF -- "$text" "$src/scripts/$s"
  done
done < <(python3 -I "$markers" --list)
pin "build-windows.sh scans the same build paths" grep -qF "'/\.(cargo|rustup)/'" "$src/scripts/build-windows.sh"

if [ "$fail" -ne 0 ]; then echo "LINUX FEEDS GATE FAILED"; exit 1; fi
echo "LINUX FEEDS GATE OK"
