#!/usr/bin/env python3
"""Refuse a Linux release unless each update feed points at the right file.

From 1.0.6 there are TWO Linux feeds (docs/update-channel.md, "Two Linux
feeds"):

  /v1/linux-x86_64*.json  read by Linux builds BEFORE 1.0.6, which install
                          whatever it offers without checking the engine. It
                          must offer the BRIDGE build, whose compiled WebKitGTK
                          floor is exactly the lowest any /v1 reader enforced
                          (2.52.5, 0.9.x), so it starts everywhere
                          those builds ran. Re-signed ONCE, for
                          1.0.6, then frozen.
  /v2/linux-x86_64*.json  read by 1.0.6 and later, which check the engine. It
                          must offer the STRICT build, and its signed
                          engine_floor must equal that build's compiled floor.

A swapped pair is the failure this exists for: the strict build on /v1 strands
every old copy on a 2.52.x engine with a browser that will not start, and the
bridge on /v2 relaxes the floor for every future install. Each binary is asked
what it is (`--build-identity`) rather than trusted for its file name.

Usage:
  check-linux-feeds.py --v2-manifest M --v2-beta-manifest M --v2-binary B
                       ( --v1-manifest M --v1-beta-manifest M --v1-binary B
                       | --v1-manifest M --v1-beta-manifest M
                         --v1-frozen SHA256 --v1-beta-frozen SHA256 )

  Every feed is checked with its BETA manifest too: Linux beta copies before
  1.0.6 read /v1's beta file and install whatever it offers, exactly like the
  stable ones.
  --v1-binary            the 1.0.6 release, which re-signs /v1 for the bridge.
  --v1-frozen/-beta-...  every later release: both /v1 manifest files must be
                         byte-identical to the ones published with 1.0.6. One of
                         the two forms is REQUIRED: a release may not skip /v1.

Exit 0 when every check passes; 1 with every failure listed otherwise.
Signatures are checked by `patanyx-sign verify` in the publish script; this
checks the MAPPING the signature cannot judge.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

BRIDGE_FLOOR = "2.52.5"
# The one release that publishes the bridge. Bridge mode for any other
# version is refused: /v1 is re-signed once and then frozen.
BRIDGE_RELEASE = "1.0.6"
PLATFORM = "linux-x86_64"


def payload(path):
    with open(path, encoding="utf-8") as f:
        envelope = json.load(f)
    return json.loads(envelope["payload"])


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def identity(binary):
    # The file answers for itself. A file that cannot run here cannot be
    # judged, and is refused rather than waved through.
    out = subprocess.run(
        [os.path.abspath(binary), "--build-identity"],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    if out.returncode != 0:
        raise ValueError(f"{binary} --build-identity exited {out.returncode}")
    return json.loads(out.stdout.strip().splitlines()[-1])


def check_feed(name, manifest, binary, variant, failures):
    try:
        p = payload(manifest)
    except Exception as e:  # noqa: BLE001 - every shape problem is a refusal
        failures.append(f"{name}: manifest {manifest} unreadable: {e}")
        return None
    try:
        ident = identity(binary)
    except Exception as e:  # noqa: BLE001
        failures.append(f"{name}: binary {binary} cannot say what it is: {e}")
        return p
    if p.get("platform") != PLATFORM:
        failures.append(f"{name}: manifest platform is {p.get('platform')!r}, not {PLATFORM}")
    if ident.get("platform") != PLATFORM:
        failures.append(f"{name}: binary platform is {ident.get('platform')!r}, not {PLATFORM}")
    if p.get("sha256") != sha256(binary):
        failures.append(f"{name}: manifest sha256 does not match {binary}")
    if p.get("size") != os.path.getsize(binary):
        failures.append(f"{name}: manifest size does not match {binary}")
    if p.get("version") != ident.get("version"):
        failures.append(
            f"{name}: manifest version {p.get('version')} but the binary is {ident.get('version')}"
        )
    if ident.get("variant") != variant:
        failures.append(
            f"{name}: must carry the {variant} build, but {binary} is {ident.get('variant')!r}"
        )
    floor = (p.get("engine_floor") or {}).get("webkitgtk")
    if not floor:
        failures.append(f"{name}: manifest has no engine_floor.webkitgtk")
    compiled = ident.get("compiled_webkitgtk_floor")
    if variant == "bridge" and compiled != BRIDGE_FLOOR:
        failures.append(
            f"{name}: the bridge's compiled floor must be exactly {BRIDGE_FLOOR}, not {compiled}"
        )
    if variant == "strict" and floor and compiled != floor:
        failures.append(
            f"{name}: the strict build refuses below {compiled} but the manifest says {floor}"
        )
    return p


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--v2-manifest", required=True)
    ap.add_argument("--v2-beta-manifest", required=True)
    ap.add_argument("--v2-binary", required=True)
    ap.add_argument("--v1-manifest", required=True)
    ap.add_argument("--v1-beta-manifest", required=True)
    ap.add_argument("--v1-binary")
    ap.add_argument("--v1-frozen", metavar="SHA256")
    ap.add_argument("--v1-beta-frozen", metavar="SHA256")
    a = ap.parse_args(argv)

    failures = []
    v2 = check_feed("/v2", a.v2_manifest, a.v2_binary, "strict", failures)
    v2b = check_feed("/v2 beta", a.v2_beta_manifest, a.v2_binary, "strict", failures)
    floor = lambda p: (p.get("engine_floor") or {}).get("webkitgtk") if p else None  # noqa: E731
    if v2 and v2b and floor(v2) != floor(v2b):
        failures.append(f"/v2 beta engine_floor {floor(v2b)} must equal /v2's {floor(v2)}")

    frozen = a.v1_frozen or a.v1_beta_frozen
    if frozen and a.v1_binary:
        failures.append("/v1 is either re-signed for the bridge (--v1-binary) or frozen, not both")
    elif frozen:
        if not (a.v1_frozen and a.v1_beta_frozen):
            failures.append("a frozen /v1 needs both --v1-frozen and --v1-beta-frozen")
        else:
            if sha256(a.v1_manifest) != a.v1_frozen.lower():
                failures.append("/v1: the manifest changed; it is frozen after the 1.0.6 bridge")
            if sha256(a.v1_beta_manifest) != a.v1_beta_frozen.lower():
                failures.append("/v1 beta: the manifest changed; it is frozen after the 1.0.6 bridge")
    elif not a.v1_binary:
        failures.append(
            "every Linux release must either publish the bridge on /v1 (--v1-binary) or prove /v1 "
            "is unchanged (--v1-frozen and --v1-beta-frozen)"
        )
    else:
        v1 = check_feed("/v1", a.v1_manifest, a.v1_binary, "bridge", failures)
        v1b = check_feed("/v1 beta", a.v1_beta_manifest, a.v1_binary, "bridge", failures)
        for name, p in (("/v1", v1), ("/v1 beta", v1b)):
            if p and p.get("version") != BRIDGE_RELEASE:
                failures.append(
                    f"{name}: the bridge is published once, with {BRIDGE_RELEASE}; "
                    f"{p.get('version')} must leave /v1 frozen"
                )
        if v1 and v1b and v2 and v2b:
            if v1.get("version") != v2.get("version"):
                failures.append("/v1 and /v2 must offer the same release version for the bridge")
            # The bridge warns below the SECURITY floor; every bridge manifest
            # carries the same floor the strict feed enforces. A higher one
            # would permanently raise an old copy's floor register.
            for name, p in (("/v1", v1), ("/v1 beta", v1b)):
                if floor(p) and floor(v2) and floor(p) != floor(v2):
                    failures.append(f"{name} engine_floor {floor(p)} must equal /v2's {floor(v2)}")
            if {v1.get("url"), v1b.get("url")} & {v2.get("url"), v2b.get("url")}:
                failures.append("the /v1 and /v2 feeds must point at different files")

    if failures:
        print("LINUX FEEDS REFUSED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("LINUX FEEDS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
