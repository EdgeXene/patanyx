#!/usr/bin/env python3
"""Generate the language registry from Mozilla's published model list.

GENERATED, NOT HAND-WRITTEN, and that is the point. The set of pairs that
actually exist is a fact about Mozilla's Remote Settings collection, and a
hand-maintained copy drifts silently: a pair we list but they do not publish
becomes a language the user can select and never install.

Display names ARE hand-written below, because no machine-readable source of
English language names ships with Python. They are labels only -- a wrong one
is a cosmetic bug, never a wrong model -- but they are the part of this file a
reviewer should actually read.

  scripts/gen-language-registry.py <records.json> <out.rs>

Fetch the input with:
  curl -sS https://firefox.settings.services.mozilla.com/v1/buckets/main/\
collections/translations-models/records -o records.json
"""
import json, os, sys

NAMES = {
    "af": "Afrikaans",
    "ar": "Arabic", "az": "Azerbaijani", "be": "Belarusian", "bg": "Bulgarian",
    "bn": "Bengali", "bs": "Bosnian", "ca": "Catalan", "cs": "Czech",
    "da": "Danish", "de": "German", "el": "Greek", "en": "English",
    "es": "Spanish", "et": "Estonian", "eu": "Basque", "fa": "Persian",
    "fi": "Finnish", "fr": "French", "gl": "Galician", "gu": "Gujarati",
    "he": "Hebrew", "hi": "Hindi", "hr": "Croatian", "hu": "Hungarian",
    "id": "Indonesian", "is": "Icelandic", "it": "Italian", "ja": "Japanese",
    "kn": "Kannada", "ko": "Korean", "lt": "Lithuanian", "lv": "Latvian",
    "ml": "Malayalam", "mr": "Marathi", "ms": "Malay", "mt": "Maltese",
    "nb": "Norwegian Bokm\u00e5l", "nl": "Dutch", "nn": "Norwegian Nynorsk",
    "pl": "Polish", "pt": "Portuguese", "ro": "Romanian", "ru": "Russian",
    "sk": "Slovak", "sl": "Slovenian", "sq": "Albanian", "sr": "Serbian",
    "sv": "Swedish", "ta": "Tamil", "te": "Telugu", "th": "Thai",
    "tr": "Turkish", "uk": "Ukrainian", "ur": "Urdu", "vi": "Vietnamese",
    "zh": "Chinese",
    # Script variants Mozilla publishes separately from plain "zh". Named
    # explicitly because the generator DROPS any code it cannot label, and a
    # silent drop here would lose Traditional Chinese entirely -- which is how
    # the first run of this script lost four pairs before anyone looked at the
    # dropped list it prints.
    "zh-Hans": "Chinese (Simplified)",
    "zh-Hant": "Chinese (Traditional)",
}

# CHECKED AGAINST ISO 639-3 (the iso-codes package), which caught "Bokmal"
# written without its ring. 54 of 57 match that source exactly; three diverge
# on purpose and are listed here so the next reader knows they were decided
# rather than missed:
#
#   el  ISO "Modern Greek (1453-)"   -> "Greek".   The date range is scholarly
#                                        disambiguation from Ancient Greek and
#                                        belongs in a catalogue, not a menu.
#   ms  ISO "Malay (macrolanguage)"  -> "Malay".   "Macrolanguage" is a
#                                        taxonomy term with no meaning to
#                                        somebody choosing a language.
#   nb  ISO "Norwegian Bokmal"       -> "Norwegian Bokmal" WITH the ring, which
#                                        is simply correct and was my mistake.
#
# zh-Hans and zh-Hant are script variants and appear in no ISO 639 list; their
# names follow CLDR's usual rendering.

# Every catalog string that is INTERPOLATED INTO GENERATED RUST goes through
# this first. Refusing is deliberate rather than escaping: a display name with
# a quote in it is a mistake in the catalog, and quietly escaping it would hide
# that. Unescaped, a quote closes the Rust string literal and the rest of the
# field becomes code -- measured, not theorized: `La"tin` emitted
# `name: "La"tin"` and the generator exited 0.
# `+` is here because upstream release names carry it -- OPUS-MT's back-translation
# releases are literally "opus+bt-2020-02-26", and a provenance field must
# record the version that EXISTS rather than a sanitised one. It is as inert
# inside a Rust string literal as a comma; what this guard is actually for is
# quotes and backslashes, which remain excluded.
_RUST_SAFE = __import__("re").compile(r"^[A-Za-z0-9 .,()'+\u00c0-\u024f-]{1,64}$")


def rust_safe(value, what):
    """A catalog string that is safe to place inside a Rust string literal."""
    if not isinstance(value, str) or not _RUST_SAFE.match(value):
        raise SystemExit(
            f"catalog {what}: {value!r} contains characters that cannot be "
            "emitted into generated Rust source (letters, digits, spaces and "
            "simple punctuation only)")
    return value


def token_shape_ok(tok):
    """Mirror of Rust pair_token_ok / the nginx route / build-langpack grep:
    TWO OR THREE hyphen-separated lowercase alnum subtags of 2..12 chars,
    <=20 total. Kept in lockstep so no token is legal in one layer and
    illegal in another.

    WHY THREE IS NOW ALLOWED. The two-subtag floor existed because a token
    used to be SPLIT to recover the language codes, and "en-zh-Hans" cannot
    be split unambiguously. Nothing splits a token any more -- `pair_by_token`
    is a registry lookup and `from`/`to` are carried alongside it -- so the
    ambiguity that justified the rule is gone, while the property the rule
    actually protects (a token is a safe path and URL segment: lowercase,
    alnum, hyphens, nothing else) is unchanged. Script-tagged codes like
    zh-Hans therefore get a LOWERCASED token, "zh-hans-en", while `from`
    keeps the true "zh-Hans" the engine is given.
    """
    if not tok or len(tok) > 20:
        return False
    halves = tok.split("-")
    if len(halves) not in (2, 3):
        return False
    # LOWERCASE letters and digits only, to match Rust pair_token_ok exactly.
    # `str.isalnum()` accepts uppercase, which would let "EN-es" pass here and
    # be refused by the client verifier -- the cross-layer disagreement this
    # grammar exists to prevent. Upstream codes are all lowercase, so this is a
    # safety alignment, not a behaviour change on the real data.
    def sub_ok(h):
        return 2 <= len(h) <= 12 and h.isascii() and all(
            c.islower() or c.isdigit() for c in h) and h.isalnum()
    return all(sub_ok(h) for h in halves)


def is_alpha_version(v):
    """Mozilla ships alpha model versions (1.0a1, 2.0a) to Nightly only."""
    import re
    return re.search(r"a\d*$", v) is not None


def version_key(v):
    """Full numeric tuple for a non-alpha version string like '2.1' or '2.1.9'.

    Every dotted component is parsed, not just the first two: '2.1.9' must sort
    above '2.1' (== '2.1.0'), or two versions that differ only past the minor
    would tie and let records-file order decide which model set is chosen. The
    real Mozilla data carries only one- and two-component versions today, so
    this is determinism insurance, not a behaviour change on it."""
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError:
        return (0,)


def pair_token(f, t):
    """The wire/path/URL name for a pair.

    LOWERCASED, deliberately: a script-tagged code carries an uppercase script
    subtag ("zh-Hans") and the token grammar is lowercase-only in every layer
    that enforces it. The token is only an identifier; the TRUE codes travel
    beside it in `from`/`to`, and those are what the engine is handed.
    """
    return f"{f}-{t}".lower()


def choose_version(pair_records):
    """The version a pair actually ships at, or None if no version is usable.

    THE RULE, derived from the record set rather than invented: drop alpha
    versions (Nightly-only), then take the HIGHEST COMPLETE stable version --
    deliberately NOT "the numeric maximum or refuse". If 2.0 is mid-upload or
    has moved to a split vocabulary while 1.0 is complete, shipping working 1.0
    beats withdrawing the language; and because the publisher imports THIS
    function, registry and server make the identical choice, so no drift. An
    external review read this as a fallback bug; it is a decided behaviour.
    The three fileTypes a pack is made of ({model, lex, vocab}) must ALL exist
    at the chosen version. A pair with NO complete stable version at all (or
    only the split srcvocab/trgvocab layout) returns None and is EXCLUDED --
    the UI must never offer a language that cannot be packed. Mixing files from
    two versions is never done: a model and a vocabulary that did not train
    together are the corruption bug in a subtler costume.
    """
    by_version = {}
    for r in pair_records:
        by_version.setdefault(r["version"], set()).add(r["fileType"])
    stable = [v for v in by_version if not is_alpha_version(v)]
    for v in sorted(stable, key=version_key, reverse=True):
        # TWO LAYOUTS, both complete. "joint" is one shared SentencePiece
        # vocabulary; "split" is a separate source and target vocabulary, which
        # is what Mozilla publishes for Japanese and Chinese. The container
        # carries whichever the pair actually has, and the registry records it
        # so nothing has to guess from a file count.
        if by_version[v] == {"model", "lex", "vocab"}:
            return v, None
        if by_version[v] == {"model", "lex", "srcvocab", "trgvocab"}:
            return v, None
    # Name the reason precisely -- the exclusion list is an audit artefact.
    if not stable:
        return None, "alpha-only upstream (shipped to its nightly channel only)"
    return None, "no complete stable model/lex/vocabulary version"


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    records = json.load(open(sys.argv[1]))["data"]
    by_pair = {}
    for r in records:
        if r.get("fromLang") and r.get("toLang") and r.get("fileType"):
            by_pair.setdefault((r["fromLang"], r["toLang"]), []).append(r)
    pairs = sorted(by_pair)

    # A pair is usable only if BOTH ends have a name we can show AND a
    # complete stable version exists (see choose_version). Excluded pairs are
    # PRINTED, because the first run of this script silently dropped Chinese
    # and only the printed drop list caught it.
    chosen = {}
    excluded = []
    for f, t in pairs:
        if f not in NAMES or t not in NAMES:
            excluded.append((f, t, "no display name"))
            continue
        v, why = choose_version(by_pair[(f, t)])
        if v is None:
            excluded.append((f, t, why))
            continue
        # The token must clear the shape floor the manifest verifier and the
        # nginx route also enforce: exactly two hyphen-separated alnum subtags,
        # <=16 bytes. A script-tagged code like "zh-Hans" makes a three-hyphen
        # token that would pass registry membership but be rejected downstream
        # -- offered in the UI, un-installable in practice. Exclude it HERE so
        # the layers cannot disagree. (The zh-Hans/zh-Hant pairs are already
        # excluded for split vocab in one direction; this catches the other.)
        if not token_shape_ok(pair_token(f, t)):
            excluded.append((f, t, "token not two simple subtags (script-tagged)"))
            continue
        chosen[(f, t)] = v
    usable = sorted(chosen)
    dropped = excluded

    # Approximate per-pair download size at the chosen version: the sum of the
    # three attachments. Approximate on purpose -- it is shown to a person
    # deciding whether to download, not used to verify anything. Verification
    # is the signed manifest's exact size.
    VOCAB_TYPES = ("vocab", "srcvocab", "trgvocab")
    layout_of = {}
    size_of = {}
    for (f, t), v in chosen.items():
        types = {r["fileType"] for r in by_pair[(f, t)] if r["version"] == v}
        layout_of[(f, t)] = "split" if "srcvocab" in types else "joint"
        size_of[(f, t)] = sum(
            r["attachment"]["size"]
            for r in by_pair[(f, t)]
            if r["version"] == v and r["fileType"] in ("model", "lex") + VOCAB_TYPES
        )

    # ---- tier 2: the OPUS-MT catalog ------------------------------------
    # THE ROUTER LIVES HERE, at generation time: one token resolves to one
    # source, decided when this file is written and never at runtime. Mozilla
    # is preferred; a catalog token Mozilla also publishes is dropped with a
    # printed note. Catalog pairs carry their own display names (Latin is not
    # in Mozilla's set, so it is not in NAMES).
    catalog_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "opus-mt", "catalog.json")
    catalog_rows = []
    extra_names = {}
    if os.path.isfile(catalog_path):
        for row in json.load(open(catalog_path)).get("pairs", []):
            tok = row["token"]
            if not token_shape_ok(tok):
                print(f"  catalog {tok}: token fails the shape floor; dropped",
                      file=sys.stderr)
                continue
            if (row["from"], row["to"]) in chosen:
                print(f"  router: {tok} is published by Mozilla; the catalog "
                      "entry is shadowed (Mozilla preferred)", file=sys.stderr)
                continue
            if tok != f"{row['from']}-{row['to']}":
                print(f"  catalog {tok}: token does not match from/to; dropped",
                      file=sys.stderr)
                continue
            # The source vocabulary is CLOSED: the runtime picks the engine's
            # GEMM precision by exact-matching "opus-mt", and anything else
            # falls back to the Mozilla setting. A typo like "opus_mt" would
            # therefore route a calibrated model through the uncalibrated path
            # and produce word salad, silently. Refuse it here.
            if row.get("source") not in ("mozilla", "opus-mt"):
                raise SystemExit(
                    f"catalog {tok}: source must be 'mozilla' or 'opus-mt', "
                    f"got {row.get('source')!r}")
            # OPUS-MT IS FREE, decided 2026-09-01, superseding the
            # hybrid tiering in which Bergamot was free and OPUS-MT Premium.
            # The tier MECHANISM stays (tier_allows, the three gate points and
            # their tests are untouched and still correct), so a future
            # Premium language is a data change rather than a rebuild; there
            # simply is no tier-2 row today.
            if int(row.get("tier", 0)) != 1:
                raise SystemExit(f"catalog {tok}: catalog pairs must be tier 1")
            if any(r["token"] == tok for r in catalog_rows):
                raise SystemExit(
                    f"catalog {tok}: duplicate token; one token must resolve to "
                    "exactly one model")
            # Everything below is emitted verbatim into generated Rust.
            rust_safe(row["from_name"], f"{tok} from_name")
            rust_safe(row["to_name"], f"{tok} to_name")
            rust_safe(row["upstream_version"], f"{tok} upstream_version")
            if not isinstance(row.get("approx_bytes"), int) or row["approx_bytes"] <= 0:
                raise SystemExit(f"catalog {tok}: approx_bytes must be a positive int")
            catalog_rows.append(row)
            extra_names.setdefault(row["from"], row["from_name"])
            extra_names.setdefault(row["to"], row["to_name"])

    # NO MIXED-TIER LANGUAGE. A language whose directions straddle the tiers
    # cannot be presented honestly by one row and one button: the UI would
    # either over-gate a free direction or offer an Install that silently does
    # half the job. Rather than handle that, the registry refuses to contain
    # it -- the invariant the runtime relies on is enforced where the data is
    # made, and pinned by a generated test.
    tier_of = {}
    for f, t in usable:
        for c in (f, t):
            tier_of.setdefault(c, set()).add(1)
    for row in catalog_rows:
        for c in (row["from"], row["to"]):
            tier_of.setdefault(c, set()).add(int(row["tier"]))
    mixed = sorted(c for c, tiers in tier_of.items() if len(tiers) > 1 and c != "en")
    if mixed:
        raise SystemExit(
            f"mixed-tier languages are not allowed: {mixed}. A language must be "
            "wholly tier 1 or wholly tier 2 (English is the pivot and exempt).")

    display = dict(NAMES)
    for c, name in extra_names.items():
        display.setdefault(c, name)

    langs = sorted({c for p in usable for c in p}
                   | {r["from"] for r in catalog_rows}
                   | {r["to"] for r in catalog_rows})

    # ONE definition of the token, shared with the exclusion check above, so
    # the string that is tested is the string that is emitted.
    token = pair_token

    out = []
    out.append("// GENERATED by scripts/gen-language-registry.py. Do not edit by hand.")
    out.append("//")
    out.append("// The pairs below are the ones Mozilla actually publishes. Editing this")
    out.append("// file to add a pair would offer a language that can never be installed,")
    out.append("// because no model exists to fetch.")
    out.append("")
    out.append("/// A language this build can name.")
    out.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    out.append("pub struct Language {")
    out.append("    pub code: &'static str,")
    out.append("    pub name: &'static str,")
    out.append("}")
    out.append("")
    out.append(f"/// Every language appearing in at least one usable pair ({len(langs)}).")
    out.append("pub const LANGUAGES: &[Language] = &[")
    for c in langs:
        out.append(f'    Language {{ code: "{c}", name: "{display[c]}" }},')
    out.append("];")
    out.append("")
    out.append(f"/// Every usable translation direction ({len(usable)}): a stable")
    out.append("/// {model, lex, vocab} version exists upstream and both ends are namable.")
    out.append("///")
    out.append("/// One row per pair: token, source, target, chosen upstream version,")
    out.append("/// approximate download size in bytes. The TOKEN is the wire/path/URL")
    out.append("/// form; source and target are carried alongside precisely so that")
    out.append('/// nothing ever has to SPLIT a token -- "en-zh-Hans" cannot be split')
    out.append("/// unambiguously, and a registry lookup can never get it wrong.")
    out.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    out.append("pub struct Pair {")
    out.append("    pub token: &'static str,")
    out.append("    pub from: &'static str,")
    out.append("    pub to: &'static str,")
    out.append("    pub upstream_version: &'static str,")
    out.append("    pub approx_bytes: u64,")
    out.append('    /// "joint" (one vocab.spm) or "split" (srcvocab + trgvocab).')
    out.append("    /// Decides how many parts the pack container carries, and")
    out.append("    /// how many vocabularies the engine is handed.")
    out.append("    pub vocab: &'static str,")
    out.append("    /// 1 = free (Mozilla set); 2 = Premium (OPUS-MT supplemental).")
    out.append("    pub tier: u8,")
    out.append('    /// "mozilla" or "opus-mt": which upstream the pack derives from.')
    out.append("    pub source: &'static str,")
    out.append("}")
    out.append("")
    out.append("pub const PAIRS: &[Pair] = &[")
    for f, t in usable:
        v = chosen[(f, t)]
        sz = size_of[(f, t)]
        out.append(
            f'    Pair {{ token: "{token(f,t)}", from: "{f}", to: "{t}", '
            f'upstream_version: "{v}", approx_bytes: {sz}, '
            f'vocab: "{layout_of[(f, t)]}", tier: 1, source: "mozilla" }},'
        )
    for r in catalog_rows:
        out.append(
            f'    Pair {{ token: "{r["token"]}", from: "{r["from"]}", '
            f'to: "{r["to"]}", upstream_version: "{r["upstream_version"]}", '
            f'approx_bytes: {r["approx_bytes"]}, '
            f'vocab: "{r.get("vocab", "joint")}", '
            f'tier: {r["tier"]}, source: "{r["source"]}" }},'
        )
    out.append("];")
    out.append("")
    out.append("/// Resolves a caller's pair token to the registry row, returning the")
    out.append("/// 'static row so nothing downstream holds a caller-shaped string.")
    out.append("/// LOOKUP, NEVER SPLIT: token grammar is not self-delimiting.")
    out.append("pub fn pair_by_token(candidate: &str) -> Option<&'static Pair> {")
    out.append("    PAIRS.iter().find(|p| p.token == candidate)")
    out.append("}")
    out.append("")
    out.append(f"/// Pairs Mozilla publishes that this build EXCLUDES, with the reason.")
    out.append("/// Auditable: the provenance register must list exactly these too.")
    out.append("pub const EXCLUDED_PAIRS: &[(&str, &str, &str)] = &[")
    for f, t, why in dropped:
        out.append(f'    ("{f}", "{t}", "{why}"),')
    out.append("];")
    out.append("")
    out.append("#[cfg(test)]")
    out.append("mod tests {")
    out.append("    use super::*;")
    out.append("    #[test]")
    out.append("    fn pairs_are_english_anchored_and_named() {")
    out.append("        let codes: std::collections::HashSet<&str> =")
    out.append("            LANGUAGES.iter().map(|l| l.code).collect();")
    out.append("        for p in PAIRS {")
    out.append('            assert!(codes.contains(p.from), "{} unnamed", p.from);')
    out.append('            assert!(codes.contains(p.to), "{} unnamed", p.to);')
    out.append('            assert!(p.from == "en" || p.to == "en", "{} not en-anchored", p.token);')
    out.append('            assert_ne!(p.from, p.to);')
    out.append("            // The token is the LOWERCASED join: a script-tagged code")
    out.append('            // ("zh-Hans") keeps its case in `from`/`to`, which is what the')
    out.append("            // engine is handed, while the token stays a safe path segment.")
    out.append('            assert_eq!(')
    out.append('                p.token,')
    out.append('                format!("{}-{}", p.from, p.to).to_lowercase()')
    out.append("            );")
    out.append("            assert!(p.approx_bytes > 0);")
    out.append('            assert!(')
    out.append('                matches!(p.vocab, "joint" | "split"),')
    out.append('                "{}: unknown vocab layout {}", p.token, p.vocab')
    out.append("            );")
    out.append('            assert!(matches!(p.tier, 1 | 2), "{} bad tier", p.token);')
    out.append("            // The source vocabulary is CLOSED and tied to the tier: the")
    out.append("            // runtime selects the engine's GEMM precision by exact-matching")
    out.append('            // "opus-mt", so an unrecognized source silently routes a')
    out.append("            // calibrated model down the uncalibrated path.")
    out.append('            assert!(')
    out.append('                matches!(p.source, "mozilla" | "opus-mt"),')
    out.append('                "{}: unknown source {}", p.token, p.source')
    out.append("            );")
    out.append("            // Tier no longer follows source: OPUS-MT became FREE on")
    out.append("            // 2026-09-01, so a tier-1 pair may be either source. What")
    out.append("            // stays closed is the SOURCE set above, which is what selects")
    out.append("            // the GEMM precision; tier selects only the entitlement gate,")
    out.append("            // and nothing is gated today.")
    out.append('            assert!(')
    out.append('                p.tier != 2 || p.source == "opus-mt",')
    out.append('                "{}: a Premium pair must be opus-mt", p.token')
    out.append("            );")
    out.append("        }")
    out.append("    }")
    out.append("    #[test]")
    out.append("    fn lookup_is_exact_and_total() {")
    out.append('        assert!(pair_by_token("en-es").is_some());')
    out.append('        for miss in ["", "en-zz", "en-zz-hans", "EN-ES", "en", "en-es-fr-de"] {')
    out.append('            assert!(pair_by_token(miss).is_none(), "must miss {miss:?}");')
    out.append("        }")
    out.append("    }")
    out.append("    /// NO LANGUAGE STRADDLES THE TIERS. One language, one row, one")
    out.append("    /// button: a mixed-tier language could not be presented honestly")
    out.append("    /// by the packs panel, and `packs_status` reads the tier per")
    out.append("    /// language. The generator refuses to emit one; this pins it.")
    out.append("    #[test]")
    out.append("    fn no_language_mixes_tiers() {")
    out.append("        for lang in LANGUAGES {")
    out.append('            if lang.code == "en" {')
    out.append("                continue; // the pivot appears in every pair, both tiers")
    out.append("            }")
    out.append("            let tiers: std::collections::HashSet<u8> = PAIRS")
    out.append("                .iter()")
    out.append("                .filter(|p| p.from == lang.code || p.to == lang.code)")
    out.append("                .map(|p| p.tier)")
    out.append("                .collect();")
    out.append("            assert!(")
    out.append("                tiers.len() <= 1,")
    out.append('                "{} has directions in more than one tier: {:?}",')
    out.append("                lang.code,")
    out.append("                tiers")
    out.append("            );")
    out.append("        }")
    out.append("    }")
    out.append("    #[test]")
    out.append("    fn every_language_is_reachable() {")
    out.append("        for lang in LANGUAGES {")
    out.append("            assert!(")
    out.append("                PAIRS.iter().any(|p| p.from == lang.code || p.to == lang.code),")
    out.append('                "{} appears in no pair", lang.code')
    out.append("            );")
    out.append("        }")
    out.append("    }")
    out.append("}")
    out.append("")
    open(sys.argv[2], "w").write("\n".join(out))
    print(f"languages: {len(langs)}  pairs: {len(usable)} tier-1 + "
          f"{len(catalog_rows)} tier-2  excluded: {len(dropped)}",
          file=sys.stderr)
    for f, t, why in dropped:
        print(f"  excluded {f}-{t}: {why}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
