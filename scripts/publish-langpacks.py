#!/usr/bin/env python3
"""Batch-publish the whole language-pack set to models.patanyx.net.

This is the fleet-scale twin of scripts/build-langpack.sh. That script packs
and signs ONE pair from a directory that already holds the three model files.
This one does the part that was still three hand-run curls in a comment: for
every pair the published registry offers, it fetches the right upstream files
from Mozilla's Remote Settings CDN, verifies each against the hash Mozilla
records, packs and signs through build-langpack.sh (one source of truth for the
container format and the signature), copies the result into the web root
atomically, and writes a machine-readable provenance register beside the code.

TRUST MODEL, stated plainly because every seat of an adversarial review flagged
the same gap in the first cut of this file:

  - Model bytes are authenticated by SHA-256 against Mozilla's records. Those
    records are fetched IN THIS SCRIPT over HTTPS directly from Mozilla's
    Remote Settings endpoint -- not read from an unauthenticated file a caller
    curled earlier. The CDN host is PINNED. So a poisoned local records file or
    a redirected CDN can no longer get attacker bytes signed with our key
    without an explicit, publish-disabling override flag.
  - What this does NOT yet do: verify Mozilla's own content-signature over the
    Remote Settings collection. Transport is authenticated (TLS to Mozilla),
    the per-file hashes are Mozilla's, but the collection is trusted on TLS
    alone. Full content-signature verification is the next hardening step and
    is called out at every run.
  - The monotonic version and the "already published" skip are decided from the
    BUILD-LOCAL provenance register, never from the web root the signing model
    distrusts. The web root is consulted only as a secondary consistency check.

WHY THE REGISTER EXISTS. The models are addressed upstream by opaque record
UUIDs that die on rotation, and the shipped attribution gate only sees crates
(cargo metadata), so a fetched-and-served artifact appears in no inventory. The
register is the second source of truth: pair -> the three record ids, their
upstream sha256s, the chosen upstream version, and the sha256/size/version of
the pack we actually serve.

VERSION SELECTION IS NOT REINVENTED HERE. It is imported verbatim from
gen-language-registry.py (choose_version): drop alpha versions, take the
highest COMPLETE stable version, require all three fileTypes at it, never mix
files across versions. Importing rather than re-implementing keeps the registry
the browser enforces and the packs the server delivers in agreement; the script
additionally CROSS-CHECKS its computed pair set against the shipped registry
(languages.rs) and refuses to publish on drift.

THE SIGNING KEY NEVER TOUCHES THE SERVER. build-langpack.sh reads it from
/root/.patanyx-keys/models.key (local); this script only ever copies the two
PUBLIC artifacts (.pxpack, .json) into the web root.

MONOTONIC, IDEMPOTENT, SINGLE-WRITER. An flock guards the whole run so two
publishers cannot race. The pack sha is computed BEFORE signing: if the
register already records that exact sha the pair is left untouched (a true
no-op, so the run is safe to repeat); otherwise the manifest version is bumped
past the highest the register (and the served manifest) has ever carried. A
brand-new pair starts at version 1. --force re-signs and republishes even on a
no-op, for a signing-key rotation.

usage:
  scripts/publish-langpacks.py [records.json] [options]

  records.json    Optional. If omitted, records are fetched over HTTPS from
                  Mozilla directly (the trusted path). If given, the file is an
                  UNAUTHENTICATED local override: it requires --allow-insecure-
                  records and forces --no-publish.

options:
  --pairs a-b,c-d       Only these tokens. A filtered run MERGES into the
                        register (never overwrites the other pairs' provenance).
  --publish-dir DIR     Web root to copy into (default /srv/patanyx-models/packs).
  --staging DIR         Scratch for downloads + packing (default a mktemp dir,
                        auto-removed at the end).
  --register PATH       Provenance register (default scripts/langpack-provenance.json).
  --registry PATH       Shipped registry to cross-check against
                        (default crates/app/src/languages.rs).
  --no-publish          Build, sign and register into staging; do NOT touch the
                        web root.
  --force               Re-sign and republish every pair even on a no-op
                        (for a signing-key rotation).
  --keep-blobs          Keep fetched .bin/.spm after packing (default: delete).
  --allow-insecure-records   Permit a local records.json (implies --no-publish).
  --allow-insecure-base URL  Permit a non-Mozilla attachment base (implies
                             --no-publish). Value is the base URL to use.
  --allow-registry-drift     Permit publishing a set that differs from the
                             shipped registry (for a deliberate pre-regen run).

env:
  PATANYX_MODELS_KEY   passed through to build-langpack.sh
  PATANYX_MODELS_HOST  passed through to build-langpack.sh
"""

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_PUBLISH_DIR = "/srv/patanyx-models/packs"
DEFAULT_REGISTER = os.path.join(HERE, "langpack-provenance.json")
DEFAULT_REGISTRY = os.path.join(REPO, "crates/app/src/languages.rs")
BUILD_LANGPACK = os.path.join(HERE, "build-langpack.sh")
OPUS_CATALOG = os.path.join(HERE, "opus-mt", "catalog.json")
MANIFEST_RS = os.path.join(REPO, "crates/update/src/manifest.rs")

MOZILLA_RECORDS_URL = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/"
    "collections/translations-models/records"
)
MOZILLA_RS_SERVER = "https://firefox.settings.services.mozilla.com/v1"
MOZILLA_RS_HOST = "firefox.settings.services.mozilla.com"
PINNED_ATTACHMENT_HOST = "firefox-settings-attachments.cdn.mozilla.net"

# The three files a PXPACK1 container is made of, in the POSITIONAL order
# build-langpack.sh writes them (model, lex, vocab). The predicted-sha helper
# reproduces exactly that framing, so it MUST stay in this order.
# TWO LAYOUTS, in container order. Joint is three parts written as PXPACK1
# (unchanged, so published packs stay byte-identical); split is four parts
# written as PXPACK2, which is what Mozilla publishes for Japanese and Chinese.
PACK_ORDER = ["model", "lex", "vocab"]
PACK_ORDER_SPLIT = ["model", "lex", "srcvocab", "trgvocab"]
PACK_FILENAME = {
    "model": "model.bin",
    "lex": "lex.bin",
    "vocab": "vocab.spm",
    "srcvocab": "srcvocab.spm",
    "trgvocab": "trgvocab.spm",
}


def pack_order(file_types):
    """The container order for whichever layout these records carry."""
    return PACK_ORDER_SPLIT if "srcvocab" in set(file_types) else PACK_ORDER

# Slack over a record's stated size when reading a fetched blob, so a
# malfunctioning or hostile CDN cannot stream unbounded bytes into memory
# before the hash check gets a chance to reject them.
READ_SLACK = 1 << 20  # 1 MiB


def load_generator():
    """Import gen-language-registry.py for its selection logic (it has a
    __main__ guard, so importing runs nothing)."""
    path = os.path.join(HERE, "gen-language-registry.py")
    spec = importlib.util.spec_from_file_location("genreg", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def max_pack_bytes(manifest_rs=MANIFEST_RS):
    """Read MAX_MODEL_PACK_BYTES from the Rust verifier so the publisher's
    size gate cannot drift from the client's. Falls back to 96 MiB if the
    constant cannot be parsed (and says so)."""
    try:
        src = open(manifest_rs).read()
    except OSError as e:
        raise SystemExit(f"cannot read {manifest_rs}: {e} -- the size bound "
                         "must come from the client, not a guess")
    m = re.search(
        r"MAX_MODEL_PACK_BYTES:\s*u64\s*=\s*(\d+)\s*\*\s*1024\s*\*\s*1024", src)
    if not m:
        raise SystemExit(
            f"MAX_MODEL_PACK_BYTES not found in {manifest_rs}; if its format "
            "changed, update this parser DELIBERATELY -- a guessed bound can "
            "publish packs the client rejects")
    return int(m.group(1)) * 1024 * 1024


def registry_tokens(registry_rs=DEFAULT_REGISTRY):
    """The set of pair tokens the shipped registry actually offers, parsed from
    languages.rs. Publication is cross-checked against this so the server and
    the browser cannot disagree about which pairs exist."""
    src = open(registry_rs).read()
    return set(re.findall(r'Pair\s*\{\s*token:\s*"([a-z0-9-]+)"', src))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is a change of trust boundary. Mozilla's endpoints answer
    directly; anything that 3xx's a pinned fetch is refused rather than
    silently followed to a host the pin never approved."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SystemExit(f"{req.full_url}: redirected ({code}) to {newurl} -- refusing")


_OPENER = urllib.request.build_opener(_NoRedirect())


def http_get(url, cap, timeout=120, expect_host=None):
    """GET a URL with a mandatory byte cap, no redirects, and (optionally) a
    host+scheme check on the URL actually fetched. The cap is checked against
    Content-Length up front and again while streaming."""
    if not url.startswith("https://"):
        raise SystemExit(f"{url}: not https -- refusing")
    with _OPENER.open(url, timeout=timeout) as r:
        final = r.geturl()
        if not final.startswith("https://"):
            raise SystemExit(f"{url}: final URL {final} is not https -- refusing")
        if expect_host is not None:
            host = final[len("https://"):].split("/")[0]
            if host != expect_host:
                raise SystemExit(
                    f"{url}: final host {host!r} is not the pinned {expect_host!r}")
        clen = r.headers.get("Content-Length")
        if clen is not None and int(clen) > cap:
            raise SystemExit(f"{url}: Content-Length {clen} exceeds cap {cap}")
        buf = bytearray()
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            buf += chunk
            if len(buf) > cap:
                raise SystemExit(f"{url}: body exceeds cap {cap} -- refusing")
        return bytes(buf)


def attachment_base(insecure_base):
    """Mozilla's attachment CDN base, host-PINNED. An override is only honoured
    with --allow-insecure-base (which forces --no-publish upstream)."""
    if insecure_base:
        return insecure_base.rstrip("/") + "/"
    info = json.loads(http_get(MOZILLA_RS_SERVER + "/", cap=1 << 20, timeout=30,
                               expect_host=MOZILLA_RS_HOST))
    base = info["capabilities"]["attachments"]["base_url"]
    # https REQUIRED, then the host compared: stripping "https?://" before the
    # compare would have let an http:// base through the pin.
    if not base.startswith("https://"):
        raise SystemExit(f"attachment base {base!r} is not https -- refusing")
    host = base[len("https://"):].split("/")[0]
    if host != PINNED_ATTACHMENT_HOST:
        raise SystemExit(
            f"attachment base host {host!r} is not the pinned "
            f"{PINNED_ATTACHMENT_HOST!r} -- refusing (use --allow-insecure-base "
            f"to override, which disables publishing)")
    return base.rstrip("/") + "/"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def predicted_pack_sha(blobs, order=None):
    """The sha256 build-langpack.sh's container will have, without writing it.

    Mirrors that script exactly: PXPACK1 for a three-part joint pack (no count
    line, so already-published packs keep their hashes), PXPACK2 with a count
    for a four-part split one.
    """
    order = order or pack_order(blobs.keys())
    split = order is PACK_ORDER_SPLIT or "srcvocab" in order
    h = hashlib.sha256()
    h.update(b"PXPACK2\n" if split else b"PXPACK1\n")
    if split:
        h.update(f"{len(order)}\n".encode())
    for k in order:
        h.update(f"{len(blobs[k])}\n".encode())
    for k in order:
        h.update(blobs[k])
    return h.hexdigest()


def served_manifest_sha_and_version(publish_dir, token):
    """(sha256, version) of the pack currently served, or (None, 0). Used ONLY
    as a secondary check; the register is the authority."""
    path = os.path.join(publish_dir, f"{token}.json")
    if not os.path.isfile(path):
        return None, 0
    try:
        payload = json.loads(json.load(open(path))["payload"])
        return payload.get("sha256"), int(payload.get("version", 0))
    except (ValueError, KeyError, OSError):
        return None, 0


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def pack_already_served(reg_entry, pack_sha, served_pack, served_sha):
    """True only when the register, the served manifest AND the served pack's
    ACTUAL BYTES all carry the predicted sha. Checking file existence alone let
    a corrupt or substituted pack freeze behind a permanent false no-op."""
    if (reg_entry or {}).get("pack_sha256") != pack_sha:
        return False
    if served_sha != pack_sha:
        return False
    if not os.path.isfile(served_pack):
        return False
    return sha256_file(served_pack) == pack_sha


def records_by_pair(records):
    by = {}
    for r in records:
        if r.get("fromLang") and r.get("toLang") and r.get("fileType"):
            by.setdefault((r["fromLang"], r["toLang"]), []).append(r)
    return by


def chosen_records(pair_records, version):
    """One record per fileType at the chosen version. Raises on a gap or a
    duplicate -- both are corruption we refuse rather than paper over."""
    at_version = [r["fileType"] for r in pair_records if r["version"] == version]
    order = pack_order(at_version)
    out = {}
    for r in pair_records:
        if r["version"] != version:
            continue
        ft = r["fileType"]
        if ft not in order:
            continue
        if ft in out:
            raise ValueError(
                f"two {ft} records at version {version} for "
                f"{r['fromLang']}-{r['toLang']}")
        out[ft] = r
    missing = [ft for ft in order if ft not in out]
    if missing:
        raise ValueError(f"version {version} missing fileTypes {missing}")
    return out


def atomic_write_bytes(dst, data):
    """Write bytes onto a path through an UNPREDICTABLE temp name in the same
    directory + fsync + rename. mkstemp (O_EXCL) defeats a pre-planted symlink
    and a colliding concurrent temp name; the rename is atomic on one fs."""
    d = os.path.dirname(dst) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pub-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            # mkstemp creates 0600 and os.replace keeps the inode's mode; the
            # web server runs as a different user, so a published artifact must
            # be world-readable or the publish silently 403s.
            os.fchmod(fh.fileno(), 0o644)
            os.fsync(fh.fileno())
        os.replace(tmp, dst)
        # rename durability: without an fsync on the DIRECTORY a power loss can
        # roll the entry back even though this function returned success -- and
        # the register written through here is the version high-water mark.
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _stage_beside(dst, data):
    """Write bytes to a temp file IN dst's directory (0644, fsynced), return
    its path. The caller renames it; splitting stage from rename is what lets
    two files go live back to back."""
    d = os.path.dirname(dst) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pub-", suffix=".tmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fchmod(fh.fileno(), 0o644)
        os.fsync(fh.fileno())
    return tmp


def publish_pair(publish_dir, token, pack_path, json_path):
    """Stage pack + manifest completely, then rename both adjacently (pack
    first) and fsync the directory once."""
    pack_dst = os.path.join(publish_dir, f"{token}.pxpack")
    json_dst = os.path.join(publish_dir, f"{token}.json")
    tmp_pack = tmp_json = None
    try:
        tmp_pack = _stage_beside(pack_dst, open(pack_path, "rb").read())
        tmp_json = _stage_beside(json_dst, open(json_path, "rb").read())
        os.replace(tmp_pack, pack_dst)
        tmp_pack = None
        os.replace(tmp_json, json_dst)
        tmp_json = None
        dfd = os.open(publish_dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        for t in (tmp_pack, tmp_json):
            if t is not None:
                try:
                    os.unlink(t)
                except OSError:
                    pass


def write_register(path, register):
    register = dict(register)
    register["pairs"] = dict(sorted(register["pairs"].items()))
    register["exclusions"] = sorted(register["exclusions"], key=lambda e: e["pair"])
    atomic_write_bytes(
        path, (json.dumps(register, indent=2, sort_keys=True) + "\n").encode())


def load_register(path):
    """Missing register = first run, start empty. UNPARSEABLE register = the
    version high-water mark is damaged; refusing beats silently resetting every
    pair to version 1 and then overwriting the evidence."""
    if not os.path.isfile(path):
        return {"pairs": {}, "exclusions": []}
    try:
        r = json.load(open(path))
    except (ValueError, OSError) as e:
        raise SystemExit(
            f"{path} exists but cannot be parsed ({e}); refusing to publish "
            "with a damaged high-water mark. Inspect or restore it first.")
    r.setdefault("pairs", {})
    r.setdefault("exclusions", [])
    return r


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("records", nargs="?", default=None)
    ap.add_argument("--pairs", default="")
    ap.add_argument("--publish-dir", default=DEFAULT_PUBLISH_DIR)
    ap.add_argument("--staging", default="")
    ap.add_argument("--register", default=DEFAULT_REGISTER)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    ap.add_argument("--no-publish", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--keep-blobs", action="store_true")
    ap.add_argument("--allow-insecure-records", action="store_true")
    ap.add_argument("--allow-insecure-base", default="")
    ap.add_argument("--allow-registry-drift", action="store_true")
    ap.add_argument("--opus-artifacts", default="",
                    help="directory holding converted tier-2 artifacts, one "
                         "<token>/ dir with model.bin, lex.bin (may be empty), "
                         "vocab.spm per catalog pair; without it, catalog "
                         "pairs are skipped (their register entries survive)")
    args = ap.parse_args()

    no_publish = args.no_publish

    # A build-only run must not advance the authoritative high-water mark: it
    # would record versions for packs that were never served, and the next real
    # publish would inherit provenance that lies about what is live. Redirect
    # its register to the staging area unless the caller chose a path.
    register_redirected = False

    # ---- input authenticity -------------------------------------------------
    if args.records:
        if not args.allow_insecure_records:
            print("a local records file is unauthenticated; pass "
                  "--allow-insecure-records (it forces --no-publish)",
                  file=sys.stderr)
            return 2
        print("WARNING: using a LOCAL records file -- publishing disabled",
              file=sys.stderr)
        no_publish = True
        records = json.load(open(args.records))["data"]
    else:
        print(f"fetching records over HTTPS: {MOZILLA_RECORDS_URL}", file=sys.stderr)
        records = json.loads(http_get(
            MOZILLA_RECORDS_URL, cap=32 << 20, timeout=60,
            expect_host=MOZILLA_RS_HOST))["data"]

    if args.allow_insecure_base:
        print("WARNING: non-Mozilla attachment base -- publishing disabled",
              file=sys.stderr)
        no_publish = True

    print("NOTE: Mozilla content-signature over the collection is NOT verified "
          "(transport + per-file hash only); see the module docstring.",
          file=sys.stderr)

    gen = load_generator()
    cap = max_pack_bytes()
    by_pair = records_by_pair(records)

    # ---- the usable set, computed the registry's way ------------------------
    want = set(x for x in args.pairs.split(",") if x) if args.pairs else None
    usable = []
    exclusions = []
    for (f, t) in sorted(by_pair):
        token = gen.pair_token(f, t)
        if want is not None and token not in want:
            continue
        if f not in gen.NAMES or t not in gen.NAMES:
            exclusions.append({"pair": token, "reason": "no display name"})
            continue
        version, why = gen.choose_version(by_pair[(f, t)])
        if version is None:
            exclusions.append({"pair": token, "reason": why})
            continue
        if not gen.token_shape_ok(token):
            # Match the generator's exact wording so register and registry agree.
            exclusions.append(
                {"pair": token, "reason": "token not two simple subtags (script-tagged)"})
            continue
        usable.append((f, t, version))

    # ---- tier 2: the OPUS-MT catalog ----------------------------------------
    # Same file the registry generator reads; the router decision (Mozilla
    # wins a shared token) was made THERE, so here a catalog token that is
    # also a Mozilla token is simply ignored.
    catalog_pairs = []
    if os.path.isfile(OPUS_CATALOG):
        moz_tokens = set(gen.pair_token(f, t) for (f, t, _) in usable)
        for row in json.load(open(OPUS_CATALOG)).get("pairs", []):
            # THE TOKEN BECOMES A PATH SEGMENT (the artifacts directory) and a
            # URL segment (the published pack), so it clears the same shape
            # floor as every other layer BEFORE it is joined to anything.
            # Without this a catalog token of "../.." would read artifacts from
            # outside the artifacts root and publish under a name the client
            # could never request.
            if not gen.token_shape_ok(row["token"]):
                raise SystemExit(
                    f"catalog token {row['token']!r} fails the shape floor "
                    "(two lowercase alnum subtags, <=16 bytes)")
            if row["token"] != f"{row['from']}-{row['to']}":
                raise SystemExit(
                    f"catalog {row['token']}: token does not match from/to")
            if want is not None and row["token"] not in want:
                continue
            if row["token"] in moz_tokens:
                continue
            catalog_pairs.append(row)

    # ---- F8: bind publication to the shipped registry -----------------------
    try:
        reg_tokens = registry_tokens(args.registry)
    except OSError as e:
        if args.allow_registry_drift:
            reg_tokens = None
        else:
            raise SystemExit(
                f"cannot read the shipped registry {args.registry}: {e}; the "
                "binding this run promises cannot be checked (pass "
                "--allow-registry-drift to proceed deliberately)")
    if reg_tokens is not None and want is not None and not args.allow_registry_drift:
        # A filtered run cannot be set-equal to the whole registry, but it must
        # never publish a pair the registry hides.
        hidden = set(gen.pair_token(f, t) for (f, t, _) in usable) - reg_tokens
        if hidden:
            raise SystemExit(
                f"--pairs names pairs the shipped registry hides: {sorted(hidden)}")
    if reg_tokens is not None and want is None and not args.allow_registry_drift:
        computed = set(gen.pair_token(f, t) for (f, t, _) in usable) | set(
            r["token"] for r in catalog_pairs)
        missing = reg_tokens - computed  # registry offers, publisher would not
        extra = computed - reg_tokens    # publisher would serve, registry hides
        if missing or extra:
            print("PUBLISHER/REGISTRY DRIFT -- refusing (regenerate the registry "
                  "or pass --allow-registry-drift):", file=sys.stderr)
            if missing:
                print(f"  registry offers but records lack: {sorted(missing)}",
                      file=sys.stderr)
            if extra:
                print(f"  records give but registry hides: {sorted(extra)}",
                      file=sys.stderr)
            return 3

    # ---- single-writer lock, keyed to the REGISTER -------------------------
    # The register is what every run mutates regardless of --publish-dir or
    # --no-publish, so the lock lives beside it: two runs with different
    # publish directories still serialize. Taken before staging is created so
    # a contended run leaves nothing on disk.
    lock_path = args.register + ".lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print(f"another publisher holds {lock_path} -- refusing to race",
              file=sys.stderr)
        return 4

    base = attachment_base(args.allow_insecure_base)
    staging_auto = not args.staging
    staging = args.staging or tempfile.mkdtemp(prefix="langpacks-")
    os.makedirs(staging, exist_ok=True)
    stage_out = os.path.join(staging, "_out")
    os.makedirs(stage_out, exist_ok=True)
    if not no_publish:
        os.makedirs(args.publish_dir, exist_ok=True)
    register_load_path = args.register
    if no_publish and args.register == DEFAULT_REGISTER:
        # LOAD the real high-water marks (so predicted versions are accurate)
        # but WRITE elsewhere: a build-only run must never advance them.
        args.register = os.path.join(staging, "register-no-publish.json")
        register_redirected = True
        print(f"--no-publish: register redirected to {args.register} so the "
              "authoritative high-water mark records only what is served",
              file=sys.stderr)

    # ---- register: MERGE onto the existing authority ------------------------
    register = load_register(register_load_path)
    register.setdefault("attribution", {
        "source": "https://github.com/mozilla/translations",
        "licence": "MPL-2.0",
        "note": "Model weights redistributed under the upstream MPL-2.0 terms, "
                "from Mozilla's Remote Settings translations-models collection. "
                "The training pipeline and evaluation now live at "
                "mozilla/translations; these weights were formerly published "
                "from mozilla/firefox-translations-models, which is no longer "
                "maintained and points there. Record ids and hashes below are "
                "Mozilla Remote Settings attachments, verified on fetch.",
    })
    # A FULL run recomputes every pair, so it is authoritative about what is
    # excluded and REPLACES the list outright. A filtered run only knows about
    # the pairs it was given, so it merges, keeping the others' entries.
    #
    # Replacing on a full run is also what clears entries that can no longer be
    # produced at all: when the token scheme changed (script-tagged pairs are
    # lowercased now), the old-cased exclusions were in nobody's scope and a
    # scope-limited merge left them behind forever.
    if want is None:
        register["exclusions"] = exclusions
    else:
        register["exclusions"] = [
            e for e in register.get("exclusions", []) if e["pair"] not in want
        ] + exclusions

    published = unchanged = excluded_oversize = 0

    try:
        for (f, t, version) in usable:
            token = gen.pair_token(f, t)
            try:
                chosen = chosen_records(by_pair[(f, t)], version)
            except ValueError as e:
                # A corrupt record set for one pair excludes THAT pair; it does
                # not abort the batch and strand the others.
                register["exclusions"].append({"pair": token, "reason": str(e)})
                print(f"{token:<10} EXCLUDED: {e}", file=sys.stderr)
                continue

            # Fetch + verify each file against Mozilla's own hash, bounded.
            # The ORDER comes from what this pair actually publishes: three
            # parts for a joint vocabulary, four when it is split.
            order = pack_order(chosen.keys())
            blobs = {}
            rec_meta = {}
            bad = None
            for ft in order:
                r = chosen[ft]
                att = r["attachment"]
                data = http_get(base + att["location"], cap=att["size"] + READ_SLACK)
                if sha256_hex(data) != att["hash"]:
                    bad = f"{ft}: sha256 mismatch"
                    break
                if len(data) != att["size"]:
                    bad = f"{ft}: size mismatch"
                    break
                blobs[ft] = data
                rec_meta[ft] = {"record_id": r["id"], "location": att["location"],
                                "sha256": att["hash"], "size": att["size"]}
            if bad:
                register["exclusions"].append({"pair": token, "reason": bad})
                print(f"{token:<10} EXCLUDED: {bad}", file=sys.stderr)
                continue

            # Review finding: an oversize pair is excluded, not a batch-killer.
            split = order is PACK_ORDER_SPLIT
            header = (len(b"PXPACK2\n") + len(f"{len(order)}\n")) if split \
                else len(b"PXPACK1\n")
            predicted_size = sum(len(blobs[k]) for k in order) + header \
                + sum(len(f"{len(blobs[k])}\n") for k in order)
            if predicted_size > cap:
                register["exclusions"].append(
                    {"pair": token, "reason": f"exceeds pack size bound ({predicted_size} > {cap})"})
                excluded_oversize += 1
                print(f"{token:<10} EXCLUDED: oversize {predicted_size} > {cap}",
                      file=sys.stderr)
                continue

            pack_sha = predicted_pack_sha(blobs, order)

            # F2: version + no-op from the BUILD-LOCAL register, never the web
            # root. The served manifest is a secondary check only.
            reg_entry = register["pairs"].get(token, {})
            reg_version = int(reg_entry.get("manifest_version", 0) or 0)
            served_sha, served_version = served_manifest_sha_and_version(
                args.publish_dir, token)
            served_pack = os.path.join(args.publish_dir, f"{token}.pxpack")

            already = pack_already_served(
                reg_entry, pack_sha, served_pack, served_sha)
            if already and not args.force:
                unchanged += 1
                # Refresh provenance in case record ids rotated but bytes did not.
                register["pairs"][token] = {
                    "from": f, "to": t, "upstream_version": version,
                    "manifest_version": reg_version or 1,
                    "pack_sha256": pack_sha,
                    "pack_size": predicted_size, "records": rec_meta,
                }
                print(f"{token:<10} {version:<5} unchanged v{reg_version or 1}",
                      file=sys.stderr)
                continue

            # Never decrease: bump past the highest version ever recorded.
            manifest_version = max(reg_version, served_version, 0) + 1

            # Stage the pack's files where build-langpack.sh expects them.
            src_dir = os.path.join(staging, token)
            os.makedirs(src_dir, exist_ok=True)
            for ft in order:
                with open(os.path.join(src_dir, PACK_FILENAME[ft]), "wb") as fh:
                    fh.write(blobs[ft])
            subprocess.run(
                ["bash", BUILD_LANGPACK, token, src_dir, stage_out, str(manifest_version)],
                check=True, cwd=REPO)

            pack_path = os.path.join(stage_out, f"{token}.pxpack")
            json_path = os.path.join(stage_out, f"{token}.json")
            actual_sha = sha256_hex(open(pack_path, "rb").read())
            if actual_sha != pack_sha:
                raise SystemExit(f"{token}: predicted {pack_sha} != built {actual_sha}")
            pack_size = os.path.getsize(pack_path)

            if not no_publish:
                # The two files cannot be replaced in one atomic step under this
                # URL scheme, so the next best thing: fully stage BOTH beside
                # their destinations (write + chmod + fsync), then rename pack
                # then manifest back to back. The reader-visible torn window is
                # two rename syscalls, not a 40 MB copy; a crash between them
                # leaves old-manifest/new-pack, which the next run's no-op check
                # detects (it hashes the served pack) and repairs. Pack first,
                # because the client reads the manifest and then fetches the
                # pack it names.
                publish_pair(args.publish_dir, token, pack_path, json_path)
                on_disk_sha = sha256_file(
                    os.path.join(args.publish_dir, f"{token}.pxpack"))
                man_sha, _ = served_manifest_sha_and_version(args.publish_dir, token)
                if on_disk_sha != pack_sha or man_sha != pack_sha:
                    raise SystemExit(
                        f"{token}: post-publish inconsistency (pack {on_disk_sha}, "
                        f"manifest {man_sha}, expected {pack_sha})")

            # F7: register THIS pair now, so a later abort still leaves every
            # already-published pair recorded (the finally block writes it).
            register["pairs"][token] = {
                "from": f, "to": t, "upstream_version": version,
                "manifest_version": manifest_version,
                "pack_sha256": pack_sha, "pack_size": pack_size,
                "records": rec_meta,
            }
            published += 1
            print(f"{token:<10} {version:<5} "
                  f"{'published' if not no_publish else 'built'} v{manifest_version}  "
                  f"{pack_size} bytes", file=sys.stderr)

            # F11: the staged copies are now in the web root and recorded.
            if not args.keep_blobs:
                shutil.rmtree(src_dir, ignore_errors=True)
                for p in (pack_path, json_path):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
        # ---- tier 2: catalog pairs from locally converted artifacts ---------
        # The bytes were CONVERTED on this machine (scripts/opus-mt/, recipe in
        # docs/opus-mt-spike.md), so there is no upstream hash to check them
        # against -- the register RECORDS their hashes instead, and the catalog
        # records the hash of the upstream release they were converted FROM.
        # The publish/no-op/version discipline is the Mozilla loop's, verbatim.
        for row in catalog_pairs:
            token = row["token"]
            if not args.opus_artifacts:
                print(f"{token:<10} SKIPPED: no --opus-artifacts (register "
                      "entry, if any, is preserved)", file=sys.stderr)
                continue
            src_dir = os.path.join(args.opus_artifacts, token)
            # The token already cleared the shape floor above, so this can only
            # fail if that check is ever weakened; it costs nothing to keep the
            # containment explicit at the point the path is used.
            root_abs = os.path.realpath(args.opus_artifacts)
            if os.path.commonpath([root_abs, os.path.realpath(src_dir)]) != root_abs:
                raise SystemExit(f"{token}: artifact path escapes the artifacts root")
            blobs = {}
            missing_f = None
            for ft in PACK_ORDER:
                path = os.path.join(src_dir, PACK_FILENAME[ft])
                if not os.path.isfile(path):
                    missing_f = PACK_FILENAME[ft]
                    break
                blobs[ft] = open(path, "rb").read()
            if missing_f:
                print(f"{token:<10} SKIPPED: {src_dir}/{missing_f} missing",
                      file=sys.stderr)
                continue
            # Model and vocabulary must have bytes; the shortlist may be empty
            # ("no shortlist") -- the same per-slot rule the client enforces.
            if not blobs["model"] or not blobs["vocab"]:
                register["exclusions"].append(
                    {"pair": token, "reason": "converted model/vocab empty"})
                print(f"{token:<10} EXCLUDED: empty model or vocab", file=sys.stderr)
                continue

            # THE PROVENANCE CHAIN CLOSES HERE. Mozilla packs are authenticated
            # against Mozilla's hashes; these bytes were converted on a build
            # host, so there is no upstream hash for THEM -- which previously
            # meant --opus-artifacts could point at any files at all and they
            # would be signed with the production key wearing this pair's
            # provenance. The CATALOG pins the exact converted bytes, so the
            # chain is: upstream release + its sha (recorded, and the recipe
            # that transforms it) -> these pinned per-file hashes -> the pack
            # sha the manifest signs. Anything else is refused, loudly.
            pinned = row.get("converted")
            if not pinned:
                raise SystemExit(
                    f"{token}: catalog carries no `converted` hashes; refusing to "
                    "sign unpinned artifacts (add them to catalog.json)")
            for ft in PACK_ORDER:
                want = pinned.get(ft, {})
                got_sha = sha256_hex(blobs[ft])
                if want.get("sha256") != got_sha or int(want.get("size", -1)) != len(blobs[ft]):
                    raise SystemExit(
                        f"{token}: converted {ft} does not match the catalog pin "
                        f"(catalog {want.get('sha256')} size {want.get('size')}, "
                        f"artifact {got_sha} size {len(blobs[ft])}) -- refusing")

            # `order` was READ here and never assigned on this branch: the
            # Mozilla path above sets it from the record's file types, and the
            # catalog path iterates PACK_ORDER directly. Publishing any catalog
            # pair therefore died with UnboundLocalError before it could sign
            # anything -- latent since the catalog mode was added, because the
            # one catalog pair published so far predates this size check.
            # Catalog packs are three-slot by construction (the converter emits
            # model/lex/vocab and the pins above are checked over PACK_ORDER),
            # so the layout is stated rather than inferred.
            order = PACK_ORDER
            split = False
            header = len(b"PXPACK1\n")
            predicted_size = sum(len(blobs[k]) for k in order) + header \
                + sum(len(f"{len(blobs[k])}\n") for k in order)
            if predicted_size > cap:
                register["exclusions"].append(
                    {"pair": token,
                     "reason": f"exceeds pack size bound ({predicted_size} > {cap})"})
                excluded_oversize += 1
                continue
            pack_sha = predicted_pack_sha(blobs, order)

            reg_entry = register["pairs"].get(token, {})
            reg_version = int(reg_entry.get("manifest_version", 0) or 0)
            served_sha, served_version = served_manifest_sha_and_version(
                args.publish_dir, token)
            served_pack = os.path.join(args.publish_dir, f"{token}.pxpack")
            if pack_already_served(reg_entry, pack_sha, served_pack, served_sha) \
                    and not args.force:
                unchanged += 1
                print(f"{token:<10} {row['upstream_version']:<22} unchanged "
                      f"v{reg_version or 1}", file=sys.stderr)
                continue
            manifest_version = max(reg_version, served_version, 0) + 1

            subprocess.run(
                ["bash", BUILD_LANGPACK, token, src_dir, stage_out,
                 str(manifest_version)],
                check=True, cwd=REPO)
            pack_path = os.path.join(stage_out, f"{token}.pxpack")
            json_path = os.path.join(stage_out, f"{token}.json")
            if sha256_hex(open(pack_path, "rb").read()) != pack_sha:
                raise SystemExit(f"{token}: predicted sha != built sha")
            pack_size = os.path.getsize(pack_path)
            if not no_publish:
                publish_pair(args.publish_dir, token, pack_path, json_path)
                on_disk_sha = sha256_file(
                    os.path.join(args.publish_dir, f"{token}.pxpack"))
                man_sha, _ = served_manifest_sha_and_version(args.publish_dir, token)
                if on_disk_sha != pack_sha or man_sha != pack_sha:
                    raise SystemExit(f"{token}: post-publish inconsistency")

            register["pairs"][token] = {
                "from": row["from"], "to": row["to"],
                "source": "opus-mt",
                # Default 1: OPUS-MT is free since 2026-09-01. A catalog row
                # always carries its own tier (the generator refuses one that
                # does not), so this default is a floor, never a promotion.
                "tier": row.get("tier", 1),
                "licence": row["upstream"]["licence"],
                "upstream_version": row["upstream_version"],
                "manifest_version": manifest_version,
                "pack_sha256": pack_sha, "pack_size": pack_size,
                "upstream_release": row["upstream"]["release"],
                "upstream_release_sha256": row["upstream"]["release_sha256"],
                "converted": {
                    ft: {"sha256": sha256_hex(blobs[ft]), "size": len(blobs[ft])}
                    for ft in PACK_ORDER
                },
                "conversion": row.get("conversion", ""),
            }
            register.setdefault("attribution_opus_mt", {
                "notice": "OPUS-MT Translation Models\n"
                          "Copyright (c) University of Helsinki / Helsinki-NLP "
                          "contributors.\n"
                          "Licensed under Creative Commons Attribution 4.0 "
                          "International (CC BY 4.0).\n"
                          "Models may have been converted or optimized for use "
                          "with PATANYX Browser.",
                "source": "https://github.com/Helsinki-NLP/Opus-MT",
            })
            published += 1
            print(f"{token:<10} {row['upstream_version']:<22} "
                  f"{'published' if not no_publish else 'built'} "
                  f"v{manifest_version}  {pack_size} bytes", file=sys.stderr)
    finally:
        # Always persist provenance for whatever was published, even on abort.
        write_register(args.register, register)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        if staging_auto and not args.keep_blobs:
            shutil.rmtree(staging, ignore_errors=True)

    print(f"\npublished {published}, unchanged {unchanged}, "
          f"oversize-excluded {excluded_oversize}, "
          f"excluded {len(register['exclusions'])} total; register -> {args.register}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
