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
# Worker coverage is PARTIAL: ordinary same-origin workers are covered, module
# workers, data:/blob: workers, SharedWorker and service workers are not. Both
# absolute sentences are therefore false, in opposite directions, and the
# honest copy has to name the split. A ban on both absolutes is checkable; "is
# this sentence a fair summary of a partial capability" is not.
#
# Extend this table when a capability's coverage CHANGES, in the same commit
# that changes it. An entry is (compiled pattern, what to say instead).
BANNED_CAPABILITY_CLAIMS = (
    (
        re.compile(r"(code running in a workers?|workers?)\s+(is|are)\s+not\s+covered", re.I),
        "worker coverage is partial, not absent: ordinary workers are covered "
        "since 0.9.62. Name the split (module, data:/blob:, SharedWorker, "
        "service workers) instead",
    ),
    (
        re.compile(r"\bworkers?\s+(is|are)\s+covered\b", re.I),
        "worker coverage is partial, not complete. Say which workers, or say "
        "ordinary background workers",
    ),
    (
        re.compile(r"cannot be fingerprinted", re.I),
        'the site may never claim this; the approved frame is "noise, not '
        'invisibility"',
    ),
    (
        re.compile(r"\bwas never free\b", re.I),
        "banned from user-facing copy: it reads as an accusation. State the "
        "mechanics instead (asks for a licence from day one)",
    ),
)

# A ban on an ABSOLUTE claim must not fire on the QUALIFIED one that replaces
# it. "several kinds of worker are not covered" is the honest sentence the
# worker rule asks for, and it contains the banned absolute as a substring;
# failing it would push an editor back toward the false version. So a match is
# excused when one of these sits immediately before it.
CLAIM_QUALIFIERS = re.compile(
    r"("
    r"several|some|certain|a few|kinds? of|sorts? of|other"
    # An explicit enumeration of the uncovered kinds is the most precise honest
    # form there is, and it ends in the banned substring by construction:
    # "module workers, data:/blob: workers, SharedWorker and service workers
    # are not covered". Naming them is exactly what the remedy asks for.
    r"|module|data:|blob:|sharedworker|service"
    r")\s*[/,]?\s*(workers?\s*)?(and\s+)?(kinds? of\s+)?(background\s+)?$",
    re.I,
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


def claim_hits(text: str, pattern: re.Pattern[str], guard: re.Pattern[str] | None) -> list[str]:
    """Matches of `pattern` in `text` that are neither qualified nor quoted-as-banned."""
    out: list[str] = []
    for match in pattern.finditer(text):
        before = text[max(0, match.start() - 160) : match.start()]
        if CLAIM_QUALIFIERS.search(before):
            continue
        if guard is not None:
            window = before + text[match.end() : match.end() + 160]
            if guard.search(window):
                continue
        out.append(match.group(0))
    return out

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
        # page also states "Needs WebKitGTK 2.52.5 or newer", which is a
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
    for page in pages:
        text = visible_text(raw[page])
        note = comments(raw[page])
        for pattern, remedy in BANNED_CAPABILITY_CLAIMS:
            # Visible text: a qualifier excuses it, nothing else does. A guard
            # marker must NOT excuse visible copy -- "we never say X" printed on
            # the page is still the page saying X to a reader skimming it.
            for hit in claim_hits(text, pattern, guard=None):
                failures.append(f'{name(page)}: says "{hit}" in visible text. {remedy}.')
            for hit in claim_hits(note, pattern, guard=CLAIM_GUARD_MARKERS):
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
