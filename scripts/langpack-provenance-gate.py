#!/usr/bin/env python3
"""Gate: the language-pack provenance register must describe what is served.

The 99 language packs on models.patanyx.net are fetched-and-served artifacts,
not crates, so the crate attribution gate cannot see them and neither can
cargo. Their second source of truth is scripts/langpack-provenance.json, and a
checked-in file goes stale silently -- which is the whole failure this project
keeps hitting. This gate refuses a register that no longer describes the
shipped registry, or that has dropped the upstream attribution.

WHAT IT ENFORCES:
  - Every pair the registry (languages.rs) OFFERS has a provenance entry, and
    no entry exists for a pair the registry hides. (Register set == PAIRS set.)
  - The register's exclusions match the registry's EXCLUDED_PAIRS exactly, so
    the two accounts of "what was left out and why" cannot drift.
  - Every entry is complete: from/to, an upstream version, a manifest version
    >= 1, a 64-hex pack sha, a positive size, and three records (model, lex,
    vocab) each with a record id, a 64-hex upstream sha, a size and a location.
  - The attribution block cites mozilla/translations (the maintained home; the
    old firefox-translations-models repo now points there) under MPL-2.0 --
    redistributing the weights obliges it and a marketing pass must not quietly
    delete it.

WHAT THE TIER-2 CHAIN DOES AND DOES NOT PROVE. For an OPUS-MT pair the
binding is: catalog pin -> converted artifact bytes -> register entry ->
served pack sha (the publisher refuses artifacts that miss the pin; this gate
refuses a register that has drifted from it). So no artifact can be signed or
recorded except the exact bytes the catalog names.

What is NOT proven, stated plainly rather than implied: that those bytes are
what the recorded UPSTREAM RELEASE becomes when the recorded recipe is run.
Closing that needs a bit-reproducible conversion (marian-conv plus the alphas
calibration, pinned toolchain), which does not exist here yet. Re-downloading
the upstream zip would not close it either -- it proves the release exists,
not that these artifacts came from it. Until then the upstream release and its
sha are a RECORD of what was converted, attested by the person who ran the
conversion, not a proof.

Run: scripts/langpack-provenance-gate.py
It reads only checked-in files; it never contacts the network or the server.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
REGISTER = os.path.join(HERE, "langpack-provenance.json")
REGISTRY = os.path.join(REPO, "crates/app/src/languages.rs")
CATALOG = os.path.join(HERE, "opus-mt", "catalog.json")

HEX64 = re.compile(r"^[0-9a-f]{64}$")

# The approved third-party notice for OPUS-MT-derived packs,
# VERBATIM. The gate compares equality, not vibes: a marketing pass that
# "tidies" this text is exactly the drift being refused.
OPUS_NOTICE = (
    "OPUS-MT Translation Models\n"
    "Copyright (c) University of Helsinki / Helsinki-NLP contributors.\n"
    "Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).\n"
    "Models may have been converted or optimized for use with PATANYX Browser."
)


def fail(msg):
    print(f"GATE FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def registry_sets(path):
    src = open(path).read()
    pairs = set(re.findall(r'Pair\s*\{\s*token:\s*"([a-z0-9-]+)"', src))
    # EXCLUDED_PAIRS is [("from","to","reason"), ...]; build the token set.
    # These codes CAN carry a script tag (zh-Hans), so unlike the lowercase
    # pair tokens they may contain uppercase -- the regex must allow it or the
    # Chinese-variant exclusions silently vanish from the comparison.
    excl = {}
    block = re.search(r"EXCLUDED_PAIRS[^=]*=\s*&\[(.*?)\];", src, re.S)
    if block:
        for f, t, why in re.findall(
                r'\(\s*"([A-Za-z0-9-]+)"\s*,\s*"([A-Za-z0-9-]+)"\s*,\s*"([^"]*)"',
                block.group(1)):
            excl[f"{f}-{t}"] = why
    return pairs, excl


def main():
    if not os.path.isfile(REGISTER):
        fail(f"{REGISTER} does not exist. Run scripts/publish-langpacks.py.")
    try:
        reg = json.load(open(REGISTER))
    except ValueError as e:
        fail(f"{REGISTER} is not valid JSON: {e}")

    reg_pairs = reg.get("pairs", {})
    reg_excl = {e["pair"]: e.get("reason", "")
                for e in reg.get("exclusions", []) if "pair" in e}

    want_pairs, want_excl = registry_sets(REGISTRY)
    catalog_pins = {}
    if os.path.isfile(CATALOG):
        for row in json.load(open(CATALOG)).get("pairs", []):
            if row.get("converted"):
                catalog_pins[row["token"]] = row["converted"]

    missing = want_pairs - set(reg_pairs)
    extra = set(reg_pairs) - want_pairs
    if missing:
        fail(f"registry offers pairs the register omits: {sorted(missing)}")
    if extra:
        fail(f"register describes pairs the registry hides: {sorted(extra)}")

    if set(reg_excl) != set(want_excl):
        only_reg = sorted(set(reg_excl) - set(want_excl))
        only_registry = sorted(set(want_excl) - set(reg_excl))
        fail("register exclusions disagree with the registry's EXCLUDED_PAIRS "
             f"(register-only: {only_reg}; registry-only: {only_registry})")
    # The REASONS must agree too: the wording is the audit trail, and a
    # stripped or re-worded rationale is exactly the drift this gate exists
    # to refuse.
    for tok in sorted(want_excl):
        if reg_excl[tok] != want_excl[tok]:
            fail(f"exclusion reason for {tok} drifted: register says "
                 f"{reg_excl[tok]!r}, registry says {want_excl[tok]!r}")

    any_opus = False
    for token, e in sorted(reg_pairs.items()):
        for field in ("from", "to", "upstream_version"):
            if not e.get(field):
                fail(f"{token}: missing {field}")
        if int(e.get("manifest_version", 0) or 0) < 1:
            fail(f"{token}: manifest_version must be >= 1")
        if not HEX64.match(e.get("pack_sha256", "")):
            fail(f"{token}: pack_sha256 is not 64 hex chars")
        if int(e.get("pack_size", 0) or 0) <= 0:
            fail(f"{token}: pack_size must be positive")
        source = e.get("source", "mozilla")
        if source == "opus-mt":
            # Converted entries: no Mozilla records exist; the provenance is
            # the upstream release we converted FROM plus the hashes of what
            # the conversion produced -- and the licence that permits serving
            # it. NOT a tier claim: OPUS-MT became FREE on 2026-09-01, so the
            # tier is checked for VALIDITY here and the entitlement question
            # lives in the registry, not in provenance.
            any_opus = True
            if int(e.get("tier", 0) or 0) not in (1, 2):
                fail(f"{token}: opus-mt entries must record tier 1 or 2")
            if e.get("licence") != "CC-BY-4.0":
                fail(f"{token}: opus-mt entry must record licence CC-BY-4.0")
            rel = e.get("upstream_release", "")
            if not rel.startswith("https://"):
                fail(f"{token}: upstream_release must be an https URL")
            if not HEX64.match(e.get("upstream_release_sha256", "")):
                fail(f"{token}: upstream_release_sha256 is not 64 hex chars")
            conv = e.get("converted", {})
            for ft in ("model", "lex", "vocab"):
                c = conv.get(ft)
                if not c:
                    fail(f"{token}: missing converted {ft} hash")
                if not HEX64.match(c.get("sha256", "")):
                    fail(f"{token}: converted {ft} sha256 is not 64 hex chars")
                # Model and vocabulary must have bytes; the shortlist may be
                # empty -- the same per-slot rule the client enforces.
                if ft != "lex" and int(c.get("size", 0) or 0) <= 0:
                    fail(f"{token}: converted {ft} size must be positive")
            # THE CHAIN, CHECKED FROM THE OTHER END. The publisher refuses
            # artifacts that do not match the catalog's pins; this refuses a
            # REGISTER whose recorded hashes have drifted from those pins --
            # so neither file can be edited alone to launder a substitution.
            pin = catalog_pins.get(token)
            if pin is None:
                fail(f"{token}: opus-mt entry has no catalog pin "
                     "(scripts/opus-mt/catalog.json)")
            for ft in ("model", "lex", "vocab"):
                if conv[ft].get("sha256") != pin.get(ft, {}).get("sha256"):
                    fail(f"{token}: converted {ft} hash disagrees with the "
                         "catalog pin")
        elif source == "mozilla":
            recs = e.get("records", {})
            # Two layouts: a joint vocabulary (three records) or a split one
            # (four). Which is which is the registry's business; here the
            # record set simply has to BE one of them, completely.
            expected = ("model", "lex", "srcvocab", "trgvocab") \
                if "srcvocab" in recs else ("model", "lex", "vocab")
            if set(recs) != set(expected):
                fail(f"{token}: record set {sorted(recs)} is neither a joint "
                     "nor a split vocabulary layout")
            for ft in expected:
                r = recs.get(ft)
                if not r:
                    fail(f"{token}: missing {ft} record")
                if not r.get("record_id"):
                    fail(f"{token}: {ft} record has no record_id")
                if not HEX64.match(r.get("sha256", "")):
                    fail(f"{token}: {ft} sha256 is not 64 hex chars")
                if int(r.get("size", 0) or 0) <= 0:
                    fail(f"{token}: {ft} size must be positive")
                if not r.get("location"):
                    fail(f"{token}: {ft} has no upstream location")
        else:
            fail(f"{token}: unknown source {source!r}")

    att = reg.get("attribution", {})
    src = att.get("source", "")
    if "mozilla/translations" not in src:
        fail("attribution.source must cite mozilla/translations")
    if att.get("licence") != "MPL-2.0":
        fail("attribution.licence must be MPL-2.0")
    if any_opus:
        opus_att = reg.get("attribution_opus_mt", {})
        if opus_att.get("notice") != OPUS_NOTICE:
            fail("attribution_opus_mt.notice must carry the approved OPUS-MT "
                 "third-party notice verbatim")

    print(f"LANGPACK PROVENANCE OK ({len(reg_pairs)} pairs, "
          f"{len(reg_excl)} exclusions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
