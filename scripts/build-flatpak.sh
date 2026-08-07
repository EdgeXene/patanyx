#!/usr/bin/env bash
# Builds the Flatpak inside a Debian 13 container and PROVES the sandboxed
# binary runs on a compliant engine.
#
# The container is Debian 13 only because flatpak-builder has to run somewhere;
# it contributes nothing to the resulting app. The engine inside the Flatpak
# comes from org.gnome.Platform//50, which is an independent dependency chain
# from the build host. That distinction matters: "built on Debian 13" does NOT
# mean "ships Debian 13's WebKit", and conflating the two would hide exactly
# the kind of version drift this whole gate exists to catch.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-debian:13}"

# Which build variant to package. Empty (the default) is the PUBLIC build:
# no chat compiled in at all, which is what gets published. Set it to build
# the private one, e.g.
#
#   FEATURES=chat,relay-client ./scripts/build-flatpak.sh
#
# The app-id does not change, so the two cannot be installed side by side --
# installing one replaces the other. That is deliberate rather than an
# oversight: you run one or the other, and since the window title now names
# the variant there is no ambiguity about which. Two ids would mean two
# separate data directories and therefore two separate vaults, which is a
# much easier way to lose credentials than to gain anything.
FEATURES="${FEATURES:-}"
export FEATURES
docker run --rm --privileged -v "$PWD":/src -e FEATURES "$IMAGE" bash -c '
  set -euo pipefail
  apt-get update -qq >/dev/null
  # python3 is named explicitly, not inherited. It used to arrive as a
  # transitive dependency of flatpak-builder and stopped doing so, which
  # took the offline-build gate below out with it. The gate aborts the run
  # under set -e rather than skipping, so nothing shipped unchecked — but a
  # security gate must not depend on another package deciding to pull in
  # its interpreter.
  apt-get install -y -qq flatpak flatpak-builder xvfb desktop-file-utils python3 \
    appstream >/dev/null
  flatpak remote-add --if-not-exists flathub \
    https://dl.flathub.org/repo/flathub.flatpakrepo >/dev/null
  desktop-file-validate /src/packaging/flatpak/io.edgexene.Patanyx.desktop
  # The metainfo was never validated, only compiled. appstreamcli compose
  # runs during the build and fails on some problems, but it is not a
  # validator: it will happily produce a catalogue entry that Flathub then
  # rejects. Validating here means the answer arrives now rather than at
  # submission.
  appstreamcli validate --no-net --explain \
    /src/packaging/flatpak/io.edgexene.Patanyx.metainfo.xml

  # The offline build vendors every crate from cargo-sources.json, which is
  # GENERATED from Cargo.lock by a script needing network and two Python
  # packages -- so nobody regenerates it casually, and drift is silent.
  python3 /src/scripts/check-cargo-sources.py

  # The BUILD must have no network. finish-args legitimately grants the
  # running browser --share=network; build-options must not, or the build
  # stops being reproducible and stops being Flathub-eligible, and neither
  # failure is visible in a build that simply succeeds.
  #
  # COMMENTS ARE STRIPPED FIRST, and that is the whole substance of this
  # check rather than a detail. The manifest documents the rule in prose
  # ("NO --share=network"), so a raw substring search matches the sentence
  # forbidding the thing and fails a manifest that is correct. The first
  # version did exactly that, which is why this gate had never once passed
  # -- it was written and committed alongside the comment that defeats it,
  # and the artifact shipped from a build predating it. A gate nobody has
  # seen succeed is not evidence of anything.
  python3 - <<PYEOF
import sys
m = open("/src/packaging/flatpak/io.edgexene.Patanyx.yml").read()
if "build-options:" not in m:
    print("GATE FAIL: no build-options block found; manifest shape changed", file=sys.stderr)
    sys.exit(1)
# EVERY build-options block, not just the first. Splitting once meant a
# second module granting network passed clean; confirmed by adding one.
blocks = []
rest = m
while "build-options:" in rest:
    after = rest.split("build-options:", 1)[1]
    blocks.append(after.split("sources:", 1)[0])
    rest = after
block = "\n".join(blocks)
# Directives only: anything after a '#' is prose about the rule, not the
# rule. Splitting per line keeps an inline trailing comment from hiding a
# real directive earlier on the same line.
directives = "\n".join(line.split("#", 1)[0] for line in block.splitlines())
# Negative control. The previous one was a tautology: it appended the
# forbidden string to a copy and then checked the copy contained it, which
# string concatenation guarantees. It could never fail, and it never
# exercised the comment-stripping it existed to protect.
#
# This one runs the WHOLE check -- parse, strip, search -- over a manifest
# that genuinely grants network, and requires it to be caught. If the strip
# ever eats real directives, or the parse yields nothing, this fires.
def offending(text):
    found = []
    rest = text
    while "build-options:" in rest:
        after = rest.split("build-options:", 1)[1]
        found.append(after.split("sources:", 1)[0])
        rest = after
    joined = "\n".join(found)
    stripped = "\n".join(line.split("#", 1)[0] for line in joined.splitlines())
    return "--share=network" in stripped

if offending(m):
    print("GATE FAIL: build-options grants network; the build is not offline", file=sys.stderr)
    sys.exit(1)
control = m.replace("build-options:", "build-options:\n      - --share=network", 1)
if not offending(control):
    print("GATE FAIL: the check cannot detect a manifest that DOES grant network",
          file=sys.stderr)
    sys.exit(1)
if not directives.strip():
    print("GATE FAIL: build-options parsed as empty; the check proved nothing", file=sys.stderr)
    sys.exit(1)
print("build-options grants no network (all blocks, comments stripped, detector verified)")
PYEOF
  flatpak install -y --noninteractive flathub \
    org.gnome.Platform//50 org.gnome.Sdk//50 >/dev/null

  # Copied out of the bind mount: flatpak-builder writes build state beside
  # the manifest, and it must not land in the working tree.
  cp -a /src /build && cd /build/packaging/flatpak
  # Patch the build line in the COPY, never the tree. The manifest stays the
  # single source of truth for everything else, and a variant build cannot
  # leave the working tree modified.
  if [ -n "${FEATURES:-}" ]; then
    echo "=== variant build: --features $FEATURES ==="
    sed -i "s|cargo build --release --frozen --offline|cargo build --release --frozen --offline --features $FEATURES|" \
      io.edgexene.Patanyx.yml
    grep -q -- "--features $FEATURES" io.edgexene.Patanyx.yml || {
      echo "GATE FAIL: the feature flag did not reach the manifest" >&2
      exit 1
    }
  fi
  flatpak-builder --force-clean --disable-rofiles-fuse --install --user \
    --repo=/build/fp-repo /build/fp-build io.edgexene.Patanyx.yml

  echo
  echo "=== sandboxed run ==="
  out="$(xvfb-run -a --server-args="-screen 0 1280x900x24" \
          flatpak run io.edgexene.Patanyx --smoke-test 2>&1)"
  echo "$out" | grep -E "ENGINE|SMOKE" || true

  line="$(echo "$out" | grep "^ENGINE " || true)"
  [ -n "$line" ] || { echo "GATE FAIL: no ENGINE line" >&2; exit 1; }
  case "$line" in *"floor ok"*) ;; *) echo "GATE FAIL: $line" >&2; exit 1 ;; esac
  case "$line" in *"ITP enabled"*) ;; *) echo "GATE FAIL: ITP off -> $line" >&2; exit 1 ;; esac

  echo
  echo "=== variant marker: the build is what it claims to be ==="
  # THE FLATPAK HALF OF THE GUARD IN build-windows.sh, and it was missing.
  #
  # That script asserts the PUBLIC Windows exe carries no chat marker, and its
  # comment explains why in terms that apply here word for word: the one
  # configuration these scripts exist to protect -- the one that must never
  # contain chat -- was the one configuration nothing asserted about. On the
  # Linux side that was still true. FEATURES is an environment variable, so a
  # value exported in the project owner s shell (or inherited by a CI runner) would
  # have compiled chat into the PUBLIC bundle, and every other gate here --
  # engine floor, ITP, sandbox permissions -- passes identically either way.
  #
  # Matched on the title SUFFIX for the same reason as the Windows script, and
  # with `grep -a` on the binary rather than `strings`, which needs binutils
  # that this container does not install and which splits its output at the
  # em-dash in the full title anyway.
  loc="$(flatpak info --show-location io.edgexene.Patanyx)"
  binary="$loc/files/bin/patanyx"
  [ -f "$binary" ] || {
    echo "GATE FAIL: no binary at $binary; the install layout changed and" >&2
    echo "  this guard would have silently checked nothing" >&2
    exit 1
  }
  # NEVER shorten to the bare word "Premium": the public build's About copy
  # contains it, and this grep must fail only on the title markers.
  markers="$(grep -acE "Premium \+ relay|Premium \(LAN chat only\)" "$binary" || true)"
  if [ -z "${FEATURES:-}" ]; then
    if [ "${markers:-0}" -gt 0 ]; then
      echo "GATE FAIL: the PUBLIC bundle carries a chat title marker; it was" >&2
      echo "  built with chat compiled in. Check FEATURES in the environment." >&2
      exit 1
    fi
    echo "  public build: no chat marker present"
  else
    if [ "${markers:-0}" -eq 0 ]; then
      echo "GATE FAIL: FEATURES=$FEATURES was requested but the binary carries" >&2
      echo "  no chat marker; the feature flag did not reach the compiler" >&2
      exit 1
    fi
    echo "  variant build: chat marker present ($FEATURES)"
  fi

  echo
  echo "=== granted permissions (there must be NO filesystems= line) ==="
  perms="$(flatpak info --show-permissions io.edgexene.Patanyx)"
  echo "$perms"
  if echo "$perms" | grep -qE "^filesystems="; then
    echo "GATE FAIL: the sandbox was granted filesystem access" >&2
    exit 1
  fi
  # The bundle the project owner actually receives, exported from the SAME build
  # the gates above just passed. It used to be produced by a separate manual
  # step, which meant the artifact in hand and the artifact proven were only
  # related by intent -- and the shipped one turned out to predate a gate
  # entirely. Exporting here makes "verified" and "handed over" the same
  # object.
  #
  # /src/dist is the bind mount, so it lands on the host; the directory is
  # git-ignored, because build output does not belong in the tree.
  # PATANYX. Nothing else. See "Artifact naming" in docs/update-channel.md --
  # the rule is the product name and only the product name:
  #
  #   * NO version. The version is a fact about the bytes and the Updates panel
  #     is where it is read. These were "patanyx-v1.0-rc*.flatpak", naming a
  #     version that never shipped.
  #   * NO platform or architecture. `x86_64` is a Linux packaging habit;
  #     nothing here needs it. The Flatpak is Linux by construction and the
  #     update manifest is per-platform already.
  #   * PATANYX, not `patanyx`. Lowercase is the cargo package, the binary
  #     inside the bundle and the app id -- not a name anyone reads.
  mkdir -p /src/dist
  bundle_name="PATANYX.flatpak"
  [ -n "${FEATURES:-}" ] && bundle_name="PATANYX-Premium.flatpak"
  flatpak build-bundle /build/fp-repo "/src/dist/$bundle_name" \
    io.edgexene.Patanyx master
  echo "bundle: $(sha256sum "/src/dist/$bundle_name")"

  echo
  echo "FLATPAK OK"
'
