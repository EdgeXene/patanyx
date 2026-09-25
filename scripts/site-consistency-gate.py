#!/usr/bin/env python3
"""Hold every page of patanyx.edgexene.io to the same story.

WHY THIS EXISTS. The site is eight hand-edited pages describing one release,
with nothing to signal when one of them has gone stale. Two pages disagreeing
is not a typo: a reader who notices has been handed a reason to doubt the rest
of the site, and cannot tell which page is the wrong one. Every failure this
gate checks for is one that actually happened, on this site, in a single day:

  - the legal pages said "Beta" while the marketing pages said "prerelease"
    and the download page said "beta software" -- four vocabularies, one state
  - the About page said "close to two hundred thousand" for 183,680, rounding
    UP, while the landing page rounded down on purpose
  - the landing and About pages advertised 390,000 hosts after the list had
    grown to 567,000
  - the privacy policy took effect at the Stable Release while the terms took
    effect immediately, for the same software

WHAT IT REFUSES TO JUDGE. Prose. It checks facts that have an authority
elsewhere -- the shipped version, the published entry count, the two policy
headers being identical -- and vocabulary that has one correct spelling. It
cannot tell whether a sentence is honest, and a green run here is not a
substitute for reading the page.

THREE TIERS OF TEXT, and only one of them is a failure.
  Visible text ..... must agree. This is the rule.
  HTML comments .... notes to the next editor. Stale ones warn.
  Changelog entries. NEVER checked, and never edited to match the present. A
                     changelog reconciled with today records nothing.

Exit 0 when the site agrees with itself, 1 when it does not. Warnings never
fail the run.

Run:  ./scripts/site-consistency-gate.py [--site DIR] [--repo DIR]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# The one correct spelling. `beta` and `pre-release` are the synonyms that
# crept in; they are not wrong English, they are just a second word for a state
# that already has one.
MATURITY_WORD = "prerelease"
BANNED_SYNONYMS = (
    (re.compile(r"\bbeta\b", re.I), "beta"),
    (re.compile(r"\bpre-release\b", re.I), "pre-release"),
)

# CAPABILITY CLAIMS: sentences that say what a protection does or does not
# cover. The one class of prose this gate WILL judge, and the exception to the
# docstring's "it refuses to judge prose" -- because these are not style, they
# are a fact with an authority in the code, and a stale one is a lie about a
# security property rather than an awkward phrase.
#
# WHY THIS EXISTS. On 2026-08-14 the About page said BOTH "the protection
# reaches ordinary background workers" (feature card, true since 0.9.62) and
# "code running in a worker is not covered" (limits section, true before
# 0.9.62). A reader found the contradiction; every gate was green, because
# nothing here compared two prose claims about the same capability, and the
# HTML comment that was supposed to guard the limits section carried the stale
# claim itself, so it would have re-seeded the error at the next edit.
#
# THE SHAPE OF THE RULE, and why it is a phrase ban rather than a truth table.
# From 0.9.62 through 1.0.0 worker coverage was PARTIAL (ordinary same-origin
# workers only), so this table banned BOTH absolutes. 1.0.1 (commit 22ea1a3)
# stopped installing the Worker wrapper: a site whose CSP refuses blob: workers
# was broken by it, messenger.com among them. Workers now get NO divergence,
# so "workers are not covered" is the TRUE sentence -- the live limits section
# says exactly that -- and every positive claim, in any degree ("partially
# covered", "reaches ordinary background workers", "coverage of ordinary
# workers"), is false. The old negative ban now fired on the correct copy and
# its remedy told the editor to reinstate the false claim; it is gone.
#
# Extend this table when a capability's coverage CHANGES, in the same commit
# that changes it. An entry is (compiled pattern, what to say instead, excuse):
# `excuse(before, after, matched)` sees up to 160 characters on each side of a
# match, and the match itself, and returns True when the match is not a claim
# (None: nothing excuses it).
#
# PRESENT TENSE ONLY for the worker patterns, on purpose: "0.9.62 reached
# ordinary workers" is true history, and the live article tells it.
_WORKER_WORDS = (
    r"((all|any|some|most|many|the|your|its|their|every|each|ordinary|classic|"
    r"background|same-origin|dedicated|shared|service|module|web|page"
    r"|data:/blob:|data:|blob:)\s+)*"
    r"(shared|service)?workers?\b"
)
_COVERED_MODIFIERS = (
    r"((now|also|still|fully|partially|partly|largely|mostly|entirely|"
    r"completely|already)\s+){0,3}"
)

# A NEGATED positive is the honest sentence, and it contains the banned phrase:
# "the protection no longer reaches workers", "no workers are covered",
# "PATANYX doesn't cover workers" (straight or curly apostrophe), "nothing
# here reaches workers". At most two words, and no comma, may sit between the
# negation and the match: a negation in an earlier clause ("No setup is
# required, workers are covered") negates something else. "not only" / "not
# just" are NOT negations -- "not only covers workers but also canvases" is an
# affirmative claim -- and neither are "no doubt" or "no matter". A QUALIFIER
# is not an excuse either: "some workers are covered" is as false on 1.0.1 as
# "workers are covered". Known cost of the tight window: "does not, on any
# site, reach workers" is flagged; its remedy points at a true sentence.
_NOT_A_NEGATION = r"(?!\s+(only|just|merely|simply|doubt|question|matter)\b)"
_NEGATED_BEFORE = re.compile(
    r"(n['’]t|\b(not|never|no|nor|cannot|without|nothing|none|neither))\b"
    + _NOT_A_NEGATION
    + r"(\s+[\w'’-]+){0,2}\s*$",
    re.I,
)
# A removal verb only negates the claim it sits directly on: "1.0.1 withdrew
# coverage of workers", "dropped its coverage of workers" -- not "we removed
# bugs and now cover workers".
_REMOVED_BEFORE = re.compile(
    r"\b(withdr[ae]w|withdrawn|removed?|dropped|ended|disabled|lost)\s+"
    r"((its|the|all|their)\s+)?$",
    re.I,
)
# ...or the negation follows and denies AVAILABILITY: "coverage for workers is
# not available", "coverage of workers was removed in 1.0.1". Negating
# anything else asserts coverage: "is not optional", "isn't limited to classic
# workers", "is not only available but enabled".
_ABSENT = r"(available|supported|provided|offered|included|enabled|active|present)\b"
_NEGATED_AFTER = re.compile(
    r"^\s*(((is|are)\s+(not|no\s+longer|never)|(isn|aren)['’]t)\s+" + _ABSENT
    + r"|(is|are)\s+(unavailable|gone|off)\b"
    r"|(was|were|has\s+been|have\s+been)\s+(removed|withdrawn|dropped|disabled)\b)",
    re.I,
)

# DATED HISTORY, for the coverage noun only: "0.9.62 provided coverage for
# ordinary workers", "coverage for ordinary workers was available in 0.9.62".
# Needs BOTH a version number in the sentence and a past-tense frame, so
# "since 0.9.62 PATANYX provides coverage for workers" is still a claim.
_VERSION = re.compile(r"\b\d+\.\d+\.\d+\b")
_PAST_BEFORE = re.compile(
    r"\b(provided|gave|had|offered|shipped|added|brought|introduced)\s+"
    r"((its|the|some)\s+)?$",
    re.I,
)
_PAST_AFTER = re.compile(r"^\s*(was|were|had\s+been)\b", re.I)


# Sentence ends are punctuation FOLLOWED BY SPACE, so "0.9.62" stays whole.
_SENTENCE_END = re.compile(r"[.!?](?=\s|$)")


def _sentence(before: str, match: str, after: str) -> str:
    return _SENTENCE_END.split(before)[-1] + match + _SENTENCE_END.split(after, 1)[0]


# "Not all workers are covered", "does not cover every worker" deny UNIVERSAL
# coverage, which says some workers ARE covered: a partial claim, not a
# denial. ("not ... any" stays a denial: "does not cover any workers".)
_PARTIAL_QUANTIFIER = re.compile(r"\b(all|every|each)\b", re.I)
_BARE_NOT = re.compile(r"(n['’]t|\bnot)\s*$", re.I)


def _worker_claim_negated(before: str, after: str, matched: str = "") -> bool:
    if _PARTIAL_QUANTIFIER.search(matched) and _BARE_NOT.search(before):
        return False
    return bool(
        _NEGATED_BEFORE.search(before)
        or _REMOVED_BEFORE.search(before)
        or _NEGATED_AFTER.search(after)
    )


def _coverage_negated_or_dated(before: str, after: str, matched: str = "") -> bool:
    if _worker_claim_negated(before, after, matched):
        return True
    return bool(
        _VERSION.search(_sentence(before, " ", after))
        and (_PAST_BEFORE.search(before) or _PAST_AFTER.search(after))
    )


# An enumeration of the exotic kinds is excused when the SAME SENTENCE also
# names the ordinary kind, or all kinds, AS WORKERS: "ordinary, module and
# shared workers", "nor are ordinary workers" -- not "on all platforms".
_ALL_KINDS_LISTED = re.compile(
    r"\b(ordinary|classic|dedicated|all|every|any)\b"
    r"([\s,/]+(and|or|nor|are|kinds?|sorts?|types?|of|module|shared|service|"
    r"dedicated|classic|ordinary|background|web|data:/blob:|data:|blob:)){0,6}?"
    r"[\s,/]+workers?\b",
    re.I,
)


# The qualifier rule the two NON-worker entries have always had, kept verbatim
# so this change does not alter them. It was written for the pre-1.0.1 worker
# rule ("several kinds of worker are not covered" was the honest sentence then);
# whether it should excuse anything for these two is a separate decision.
CLAIM_QUALIFIERS = re.compile(
    r"("
    r"several|some|certain|a few|kinds? of|sorts? of|other"
    r"|module|data:|blob:|sharedworker|service"
    r")\s*[/,]?\s*(workers?\s*)?(and\s+)?(kinds? of\s+)?(background\s+)?$",
    re.I,
)


def _legacy_qualified(before: str, after: str, matched: str = "") -> bool:
    return bool(CLAIM_QUALIFIERS.search(before))


_PARTIAL_REMEDY = (
    "this implies the other workers ARE covered; since 1.0.1 (22ea1a3) none "
    "are. Say that workers are not covered"
)
_WORKER_REMEDY = (
    "workers get NO divergence since 1.0.1 (22ea1a3 stopped installing the "
    "Worker wrapper). Say that workers are not covered"
)

BANNED_CAPABILITY_CLAIMS = (
    (
        re.compile(
            r"\b" + _WORKER_WORDS + r"\s+(is|are)\s+" + _COVERED_MODIFIERS
            + r"(covered|protected)\b",
            re.I,
        ),
        _WORKER_REMEDY,
        _worker_claim_negated,
    ),
    (
        re.compile(
            r"\b(reach(es)?|cover(s)?|protects?|extends?\s+(in)?to"
            r"|appl(y|ies)\s+(to|in|inside|within))"
            r"\s+(into\s+)?" + _WORKER_WORDS,
            re.I,
        ),
        _WORKER_REMEDY,
        _worker_claim_negated,
    ),
    (
        re.compile(r"\bcoverage\s+(of|for|in)\s+" + _WORKER_WORDS, re.I),
        _WORKER_REMEDY,
        _coverage_negated_or_dated,
    ),
    # PARTIAL coverage, stated negatively: "a few kinds of background worker
    # stay out of reach", "some workers are not covered". True-looking, and the
    # house wording from 0.9.62 to 1.0.0, but it tells the reader the OTHER
    # workers are covered, and since 1.0.1 none are.
    (
        re.compile(
            r"\b(a\s+few|some|several|certain|other|most|many)\s+"
            r"((kinds?|sorts?|types?)\s+of\s+)?"
            r"((background|web|shared|service|module|dedicated)\s+)*workers?\s+"
            r"(are|is|stay|stays|remain|remains)\s+"
            r"(not\s+covered|uncovered|unprotected|out\s+of\s+reach)\b",
            re.I,
        ),
        _PARTIAL_REMEDY,
        None,
    ),
    # ...or by listing only the exotic kinds: "module workers, SharedWorker and
    # service workers are not covered". Excused when the list also names the
    # ordinary kind (or all of them), since then nothing is implied covered.
    (
        re.compile(
            r"\b(module\s+workers?|shared\s*workers?|service\s*workers?"
            r"|(data:/blob:|data:|blob:)\s+workers?)\b[^.]{0,120}?"
            r"\b(are|is|stay|remain)\s+(not\s+covered|uncovered|out\s+of\s+reach)\b",
            re.I,
        ),
        _PARTIAL_REMEDY,
        "enumeration",
    ),
    (
        re.compile(r"cannot be fingerprinted", re.I),
        'the site may never claim this; the approved frame is "noise, not '
        'invisibility"',
        _legacy_qualified,
    ),
    (
        re.compile(r"\bwas never free\b", re.I),
        "banned from user-facing copy: it reads as an accusation. State the "
        "mechanics instead (asks for a licence from day one)",
        _legacy_qualified,
    ),
)

# The same problem one layer up: the comments that ENFORCE these bans quote the
# banned phrase to name it ("Never write 'workers are covered'"). Those are the
# guard, not the leak, and warning about them trains editors to delete the
# guard. A quotation introduced by one of these is excused.
# Searched on BOTH sides of the match, because the marker lands either way:
# 'Never write "workers are covered"' puts it before, and '"cannot be
# fingerprinted" may never appear on this site' puts it after. Looking only
# behind flagged every guard comment on the site as a leak.
CLAIM_GUARD_MARKERS = re.compile(
    r"(never (write|appear|claim|say|use|that)|must never|may never|"
    r"do not (write|say|use)|banned|"
    r"stopped being true|used to say|corrected|instead of|rather than|"
    r"went back to|go back to|both are false|shipped here briefly)",
    re.I,
)


def claim_hits(
    text: str,
    pattern: re.Pattern[str],
    guard: re.Pattern[str] | None,
    excuse=None,
) -> list[str]:
    """Matches of `pattern` in `text` that are neither excused nor quoted-as-banned."""
    out: list[str] = []
    for match in pattern.finditer(text):
        before = text[max(0, match.start() - 160) : match.start()]
        after = text[match.end() : match.end() + 160]
        if excuse == "enumeration":
            # The list, from the start of its sentence, names the ordinary
            # kind (or all kinds) too.
            if _ALL_KINDS_LISTED.search(_sentence(before, match.group(0), after)):
                continue
        elif excuse is not None and excuse(before, after, match.group(0)):
            continue
        if guard is not None and guard.search(before + after):
            continue
        out.append(match.group(0))
    return out


# The capability rules judged against known sentences before they judge the
# site, so a regex edit that stops catching a false claim -- or starts failing
# the true one the live limits section carries -- fails this gate instead of
# passing it quietly. (sentence, True if it must be flagged as visible copy.)
CAPABILITY_SELF_TEST = (
    ("Workers are not covered.", False),  # the live limits section's heading
    ("screen size, fonts, and background workers are not covered.", False),
    ("The protection no longer reaches workers.", False),
    ("PATANYX doesn’t cover workers.", False),
    ("Coverage for workers is not available.", False),
    ("0.9.62 reached ordinary workers.", False),  # true history
    ("The protection reaches ordinary background workers.", True),
    ("Workers are now partially covered.", True),
    ("We cover some workers.", True),
    ("It covers service workers.", True),
    ("PATANYX not only covers workers but also canvases.", True),
    ("Some cannot be fingerprinted by naive scripts.", False),  # legacy excuse
    ("You cannot be fingerprinted.", True),
    ("Web workers are not covered.", False),  # what-a-browser-fingerprint-is
    ("and a few kinds of background worker stay out of reach.", True),  # old About
    ("Module workers, SharedWorker and service workers are not covered.", True),
    ("Ordinary, module and shared workers are not covered.", False),
    ("Workers are protected.", True),
    ("The noise applies inside workers.", True),
    ("Nothing here reaches workers.", False),
    ("It does not yet reach workers.", False),
    ("No setup is required, workers are covered.", True),
    ("We removed bugs and now cover workers.", True),
    ("Coverage for workers is not only available but enabled.", True),
    ("It covers data:/blob: workers.", True),
    ("On all platforms, module workers are not covered.", True),
    ("Module workers are not covered, nor are ordinary workers.", False),
    ("Shared memory and screen size are not covered.", False),
    ("0.9.62 provided coverage for ordinary workers.", False),
    ("Since 0.9.62 PATANYX provides coverage for workers.", True),
    ("Coverage for workers was added in this release.", True),  # undated: a claim
    ("Coverage for workers isn't only available but enabled.", True),
    ("Coverage for workers isn’t just available; it is enabled by default.", True),
    ("Not all workers are covered.", True),  # a partial claim
    ("Not every worker is covered.", True),
    ("No workers are covered.", False),
    ("Not each worker is covered.", True),
    ("PATANYX does not cover every worker.", True),
    ("PATANYX does not cover any workers.", False),
    ("Coverage for workers isn't limited to classic workers.", True),
    ("Coverage for workers is not optional.", True),
    ("Coverage for workers is not available.", False),
    ("1.0.1 withdrew coverage of workers.", False),
)


def capability_self_test() -> list[str]:
    wrong: list[str] = []
    for sentence, must_flag in CAPABILITY_SELF_TEST:
        flagged = any(
            claim_hits(sentence, pattern, guard=None, excuse=excuse)
            for pattern, _remedy, excuse in BANNED_CAPABILITY_CLAIMS
        )
        if flagged != must_flag:
            verdict = "passed" if must_flag else "was flagged"
            wrong.append(f'capability rules self-test: "{sentence}" {verdict}')
    return wrong

# AMERICAN ENGLISH. Settled 2026-08-14, after "licence" and
# "colours" reached the live site: the product is written in American English,
# and a British spelling is a defect like any other stale claim.
#
# VISIBLE COPY ONLY, and that restriction is load-bearing. `licence` is also a
# crate name (`patanyx-licence`), a module (`licence_control.rs`), a type
# (`LicenceState`) and four IPC commands (`licence_get`, `licence_paste`);
# renaming those is a refactor nobody asked for and would break the wire
# protocol between the chrome and Rust. This gate reads the SITE, so it cannot
# reach them, and any future extension to the app must scan string literals
# rather than identifiers.
BRITISH_SPELLINGS = (
    (re.compile(r"\blicenc(e|es|ed|ing)\b", re.I), "license"),
    (re.compile(r"\bcolour(s|ed|ing)?\b", re.I), "color"),
    (re.compile(r"\bbehaviour(s|al)?\b", re.I), "behavior"),
    (re.compile(r"\bcentre(s|d)?\b", re.I), "center"),
    (re.compile(r"\bdefence\b", re.I), "defense"),
    (re.compile(r"\bgrey\b", re.I), "gray"),
    (re.compile(r"\borganis(e|es|ed|ing|ation|ations)\b", re.I), "organize"),
    (re.compile(r"\brecognis(e|es|ed|ing)\b", re.I), "recognize"),
    (re.compile(r"\bauthoris(e|es|ed|ing|ation)\b", re.I), "authorize"),
    (re.compile(r"\bcustomis(e|es|ed|ing|ation)\b", re.I), "customize"),
    (re.compile(r"\banalys(e|es|ed|ing)\b", re.I), "analyze"),
    (re.compile(r"\bapologis(e|es|ed|ing)\b", re.I), "apologize"),
    (re.compile(r"\bfavourite(s)?\b", re.I), "favorite"),
    (re.compile(r"\bcatalogue(s|d)?\b", re.I), "catalog"),
    (re.compile(r"\bwhilst\b", re.I), "while"),
)

# Pages that quote the size of the bundled blocklist. Restricted on purpose:
# a six-figure number on the contact page is not a blocklist claim, and a gate
# that guesses at intent produces failures nobody trusts.
SIZE_CLAIM_PAGES = ("index.html", "about/index.html")

# How far below the real figure a rounded marketing number may sit. Rounding
# DOWN is required -- it fails into understatement instead of into a lie -- but
# a number so old it is half the truth is not honest either, it is neglect.
MAX_UNDERSTATEMENT = 0.35


def strip_changelog(html: str) -> str:
    """Remove changelog blocks. They are history and are exempt by design."""
    return re.sub(
        r'<div class="changelog">.*?</div>\s*(?=<|\Z)', "", html, flags=re.S
    )


def visible_text(html: str) -> str:
    html = strip_changelog(html)
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    html = re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", html)
    for entity, char in (("&middot;", "·"), ("&amp;", "&"), ("&nbsp;", " ")):
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text)


def comments(html: str) -> str:
    return " ".join(re.findall(r"<!--(.*?)-->", strip_changelog(html), flags=re.S))


def shipped_version(repo: pathlib.Path) -> str | None:
    cargo = repo / "crates/app/Cargo.toml"
    if not cargo.is_file():
        return None
    match = re.search(r'^version\s*=\s*"([^"]+)"', cargo.read_text(), re.M)
    return match.group(1) if match else None


def published_entries(site: pathlib.Path) -> int | None:
    """The entry count from the signed manifest -- the only authority for it.

    The payload is an embedded JSON string, because the signature covers those
    exact bytes; parse it rather than the outer object.
    """
    manifest = site / "v1/blocklist.json"
    if not manifest.is_file():
        return None
    try:
        outer = json.loads(manifest.read_text())
        payload = outer.get("payload")
        inner = json.loads(payload) if isinstance(payload, str) else outer
        return int(inner["entries"])
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", default="/srv/patanyx-dist")
    parser.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parent.parent))
    args = parser.parse_args()

    site = pathlib.Path(args.site)
    repo = pathlib.Path(args.repo)
    if not site.is_dir():
        print(f"FAIL: no site at {site}", file=sys.stderr)
        return 1

    pages = sorted(site.glob("**/index.html"))
    if not pages:
        print(f"FAIL: {site} contains no pages", file=sys.stderr)
        return 1

    failures: list[str] = []
    warnings: list[str] = []
    raw = {p: p.read_text(encoding="utf-8", errors="replace") for p in pages}

    def name(path: pathlib.Path) -> str:
        rel = path.relative_to(site).as_posix()
        return "landing" if rel == "index.html" else rel.removesuffix("/index.html")

    # --- 1. one maturity word ------------------------------------------------
    for page in pages:
        text = visible_text(raw[page])
        for pattern, word in BANNED_SYNONYMS:
            if pattern.search(text):
                failures.append(
                    f'{name(page)}: says "{word}" in visible text; the site word '
                    f'is "{MATURITY_WORD}"'
                )

    # --- 2. version matches what is being shipped ----------------------------
    version = shipped_version(repo)
    if version is None:
        warnings.append("could not read the version from Cargo.toml; version check skipped")
    else:
        # A VERSION CLAIM, not every dotted triple on the page. The download
        # page also states "Needs WebKitGTK 2.52.6 or newer", which is a
        # dependency and nothing to do with what PATANYX is at. A claim about
        # our version is introduced by "Version" or carries a `v` prefix; a
        # dependency requirement does neither.
        pattern = re.compile(r"\bv(\d+\.\d+\.\d+)\b|\bVersion\s+(\d+\.\d+\.\d+)\b")
        for page in pages:
            found_versions = {
                m[0] or m[1] for m in pattern.findall(visible_text(raw[page]))
            }
            for found in found_versions:
                if found != version:
                    failures.append(
                        f"{name(page)}: shows version {found} in visible text, "
                        f"but {version} is being shipped"
                    )
            stale = {
                (m[0] or m[1])
                for m in pattern.findall(comments(raw[page]))
            } - {version}
            if stale:
                warnings.append(
                    f"{name(page)}: HTML comments mention {', '.join(sorted(stale))} "
                    f"while {version} ships (comments, so not a blocker)"
                )

    # --- 3. blocklist size claims round DOWN ---------------------------------
    entries = published_entries(site)
    if entries is None:
        warnings.append("could not read entries from the signed manifest; size check skipped")
    else:
        for rel in SIZE_CLAIM_PAGES:
            page = site / rel
            if page not in raw:
                continue
            text = visible_text(raw[page])
            # NO SIX-FIGURE NUMBER MAY EXCEED THE LIST. The total bounds every
            # per-source figure too, so this one holds whatever the number
            # means.
            for claim in re.findall(r"\b(\d{3},\d{3})\+?", text):
                if int(claim.replace(",", "")) > entries:
                    failures.append(
                        f"{name(page)}: claims {claim} but the published list has "
                        f"{entries:,}. Marketing figures round DOWN."
                    )
            # Staleness is only meaningful for the HEADLINE figure. The About
            # page also quotes a per-source count (PhishDestroy's ~180,000),
            # which is legitimately a fraction of the total and would look
            # permanently "neglected" to a check that could not tell them
            # apart. The headline is the one attached to the phrase.
            for claim in re.findall(
                r"\b(\d{3},\d{3})\+?\s+(?:hosts reported as phishing"
                r"|known phishing|phishing sites)", text
            ):
                if int(claim.replace(",", "")) < entries * (1 - MAX_UNDERSTATEMENT):
                    warnings.append(
                        f"{name(page)}: headline figure {claim} against {entries:,}; "
                        f"correct but far enough behind to look neglected"
                    )

    # --- 4. the two legal documents say the same thing -----------------------
    header = re.compile(r"(Effective Date:.*?website)", re.S)
    legal = {}
    for rel in ("privacy/index.html", "terms/index.html"):
        page = site / rel
        if page in raw:
            found = header.search(visible_text(raw[page]))
            legal[rel] = found.group(1).strip() if found else None
    if len(legal) == 2:
        privacy, terms = legal["privacy/index.html"], legal["terms/index.html"]
        if privacy is None or terms is None:
            failures.append("privacy/terms: could not find an Effective Date header on both")
        elif privacy != terms:
            failures.append(
                "privacy and terms disagree in their header. Two legal documents "
                "cannot describe the same software differently.\n"
                f"      privacy: {privacy}\n"
                f"      terms:   {terms}"
            )

    # --- 5. capability claims ------------------------------------------------
    # Visible text FAILS; a stale claim in an HTML comment only warns, but it
    # does warn: the comment above the limits section is what re-seeds the
    # error into the next edit, which is exactly how the worker contradiction
    # survived a rewrite that had the correct fact three sections away.
    failures.extend(capability_self_test())
    for page in pages:
        text = visible_text(raw[page])
        note = comments(raw[page])
        for pattern, remedy, excuse in BANNED_CAPABILITY_CLAIMS:
            # Visible text: the entry's own excuse (a negation, for the worker
            # claims) and nothing else. A guard marker must NOT excuse visible
            # copy -- "we never say X" printed on the page is still the page
            # saying X to a reader skimming it.
            for hit in claim_hits(text, pattern, guard=None, excuse=excuse):
                failures.append(f'{name(page)}: says "{hit}" in visible text. {remedy}.')
            for hit in claim_hits(note, pattern, guard=CLAIM_GUARD_MARKERS, excuse=excuse):
                warnings.append(
                    f'{name(page)}: an HTML comment still says "{hit}"; '
                    f"it will be copied back into the page by the next editor. {remedy}"
                )

    # --- 6. American English -------------------------------------------------
    # Visible copy fails; comments are the next editor's notes and only warn,
    # for the same reason the capability check treats them that way: a British
    # spelling sitting in a comment is what gets copied into the page next.
    for page in pages:
        text = visible_text(raw[page])
        note = comments(raw[page])
        for pattern, american in BRITISH_SPELLINGS:
            for hit in {m.group(0) for m in pattern.finditer(text)}:
                failures.append(
                    f'{name(page)}: says "{hit}" in visible text; this product '
                    f'is written in American English ("{american}")'
                )
            for hit in {m.group(0) for m in pattern.finditer(note)}:
                warnings.append(
                    f'{name(page)}: an HTML comment says "{hit}"; American '
                    f'English is "{american}"'
                )

    # --- report --------------------------------------------------------------
    print(f"site consistency: {len(pages)} pages under {site}")
    if version:
        print(f"  shipping version {version}", end="")
        print(f", published list {entries:,} entries" if entries else "")
    for warning in warnings:
        print(f"  warn  {warning}")
    for failure in failures:
        print(f"  FAIL  {failure}")
    if failures:
        print(f"\n{len(failures)} inconsistenc{'y' if len(failures) == 1 else 'ies'}. "
              "Reconcile the pages as a set, against the version being shipped.")
        return 1
    print("  all pages agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
