#!/usr/bin/env bash
# Build and sign one language pack for models.patanyx.net.
#
# WHAT IT PRODUCES, for a pair like en-es:
#   <out>/en-es.pxpack   the three model files in one container
#   <out>/en-es.json     the SIGNED manifest the browser fetches first
#
# THE KEY NEVER LEAVES THIS MACHINE and never goes on the web server. That is
# the blocklist publisher's discipline and it is the whole point of signing:
# whoever serves the files cannot change them, so the host does not have to be
# trusted. This follows the publisher-side blocklist script.
#
# THE CONTAINER HAS NO FILENAMES IN IT. Three lengths, then three blobs, in a
# fixed order. Nothing inside a pack can influence where bytes land when it is
# unpacked -- see crates/app/src/langpack.rs for why tar and zip were both the
# wrong shape here.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PAIR="${1:-}"
SRC="${2:-}"
OUT="${3:-}"
# MONOTONIC, and the publisher's job to increment. The browser refuses to
# replace a pack with one carrying a version it already has or has passed, so a
# republish that forgets to bump reaches nobody -- and an attacker replaying an
# old manifest reaches nobody either, which is the point.
VERSION="${4:-1}"
KEY="${PATANYX_MODELS_KEY:-/root/.patanyx-keys/models.key}"
HOST="${PATANYX_MODELS_HOST:-https://models.patanyx.net}"

if [ -z "$PAIR" ] || [ -z "$SRC" ] || [ -z "$OUT" ]; then
  cat >&2 <<USAGE
usage: scripts/build-langpack.sh <pair> <source-dir> <out-dir> [version]

  <pair>        e.g. en-es
  <source-dir>  holding model.bin, lex.bin and vocab.spm
  <out-dir>     where <pair>.pxpack and <pair>.json are written
  [version]     monotonic, default 1. MUST increase on every republish or
                installs that already have this pair will ignore it.

env:
  PATANYX_MODELS_KEY   signing key (default /root/.patanyx-keys/models.key)
  PATANYX_MODELS_HOST  URL prefix baked into the manifest
USAGE
  exit 2
fi

# The pair shape the browser enforces, enforced here too so a bad one fails at
# the desk rather than at every install.
# Two hyphen-separated subtags, matching the client's pair_token_ok, the
# nginx route, and the registry generator. Widened from the old xx-yy shape
# when the model set grew to the whole published registry.
if ! printf '%s' "$PAIR" | grep -Eq '^[a-z0-9]{2,12}-[a-z0-9]{2,12}(-[a-z0-9]{2,12})?$'; then
  echo "pair must be two or three hyphen-separated lowercase subtags" >&2
  exit 2
fi
if [ "${#PAIR}" -gt 20 ]; then
  echo "pair token must be at most 20 bytes" >&2
  exit 2
fi
[ -r "$KEY" ] || { echo "signing key not readable: $KEY" >&2; exit 2; }

mkdir -p "$OUT"
PACK="$OUT/$PAIR.pxpack"

# Order is POSITIONAL and must match platform::pack_files for this layout.
#
# TWO LAYOUTS. A joint-vocabulary pack is three parts and is written in the V1
# container, so the packs already published stay byte-identical and need no
# republish. A split-vocabulary pack (Japanese, Chinese) is four parts and uses
# V2, which states its count. Which one is decided by WHAT IS IN THE SOURCE
# DIRECTORY, and the reader checks that against the registry, so a mistake here
# is refused at install rather than shipped.
python3 - "$SRC" "$PACK" <<'PY'
import sys, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
if (src / "srcvocab.spm").is_file() or (src / "trgvocab.spm").is_file():
    names = ("model.bin", "lex.bin", "srcvocab.spm", "trgvocab.spm")
    magic = b"PXPACK2\n"
else:
    names = ("model.bin", "lex.bin", "vocab.spm")
    magic = b"PXPACK1\n"
parts = [src / n for n in names]
for p in parts:
    if not p.is_file():
        raise SystemExit(f"missing: {p}")
blobs = [p.read_bytes() for p in parts]
with out.open("wb") as f:
    f.write(magic)
    if magic == b"PXPACK2\n":
        f.write(f"{len(blobs)}\n".encode())
    for b in blobs:
        f.write(f"{len(b)}\n".encode())
    for b in blobs:
        f.write(b)
print(f"packed {out} from {len(blobs)} parts", file=sys.stderr)
PY

SIZE=$(stat -c %s "$PACK")
SHA=$(sha256sum "$PACK" | cut -d' ' -f1)

PAYLOAD="$OUT/.$PAIR.payload.json"
if ! printf '%s' "$VERSION" | grep -Eq '^[1-9][0-9]*$'; then
  echo "version must be a positive integer (zero is reserved for 'nothing installed')" >&2
  exit 2
fi

printf '{"pair":"%s","url":"%s/packs/%s.pxpack","sha256":"%s","size":%s,"version":%s}\n' \
  "$PAIR" "$HOST" "$PAIR" "$SHA" "$SIZE" "$VERSION" > "$PAYLOAD"

# Signed through the tool, which VERIFIES its own output before emitting it.
cargo run --quiet -p patanyx-update --example patanyx-sign -- \
  sign-models "$KEY" "$PAYLOAD" > "$OUT/$PAIR.json"
rm -f "$PAYLOAD"

echo "pack:     $PACK ($SIZE bytes)"
echo "sha256:   $SHA"
echo "manifest: $OUT/$PAIR.json"
echo "version:  $VERSION"
echo
echo "NOT PUBLISHED. Copying these into a web root is publishing and needs an"
echo "explicit, deliberate go."
