#!/usr/bin/env python3
"""Fetch Mozilla's Public Suffix List and normalise it for compiling in.

WHY THE LIST IS IN THIS REPOSITORY AT ALL.

"Registrable domain" is not computable by rule. Dropping the last two labels
turns mail.google.com into google.com correctly and turns mybank.co.uk into
co.uk catastrophically -- and PATANYX uses the registrable domain to decide
which saved password to offer a page. Getting it wrong offers your bank
credential to any other site under the same public suffix. The list is the
only thing that knows co.uk, com.au, github.io and s3.amazonaws.com are
shared infrastructure rather than somebody's domain.

WHY NORMALISED HERE RATHER THAN IN build.rs.

459 of the rules are Unicode (公司.cn, aéroport.ci) and NONE of them ship a
punycode twin in the upstream file -- checked, not assumed. Hosts arrive from
`host_of` in whatever form the URL carried, which for an IDN site is
punycode. A Unicode rule therefore never matches, and a MISSING public-suffix
rule fails open: without 公司.cn, two unrelated registrants under it collapse
to one registrable domain and are offered each other's passwords.

So the punycode conversion has to happen somewhere. Doing it here, once,
keeps build.rs free of an IDNA implementation and keeps the committed list
pure ASCII and reviewable in a diff -- the same reasoning blocklist.txt is
kept as text.

BOTH SECTIONS ARE KEPT, ICANN AND PRIVATE. The private section is what knows
alice.github.io and bob.github.io are different parties. Every rule it adds
makes registrable domains SMALLER, which is the safe direction for a
credential boundary: the failure mode of an extra rule is declining to offer
a password, and the failure mode of a missing one is offering it to a
stranger.

Run: python3 scripts/build-psl.py
Writes: crates/app/src/public_suffix_list.txt
"""

import datetime
import pathlib
import re
import sys
import urllib.request

SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/app/src/public_suffix_list.txt"

# A punycode label, or a plain ASCII one. Anything else is not something the
# matcher can ever be handed by `host_of`, so it must not reach the file.
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def to_ascii(rule: str) -> str:
    """Punycode a rule, preserving its leading ! or *. marker."""
    prefix = ""
    if rule.startswith("!"):
        prefix, rule = "!", rule[1:]
    elif rule.startswith("*."):
        prefix, rule = "*.", rule[2:]

    labels = []
    for label in rule.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        import idna

        # uts46 matches what browsers do when they build the host we will be
        # comparing against; std_3_rules off because some listed labels are
        # legitimately not STD3-conformant.
        labels.append(idna.encode(label, uts46=True, std3_rules=False).decode("ascii"))
    return prefix + ".".join(labels)


def main() -> int:
    with urllib.request.urlopen(SOURCE, timeout=120) as resp:
        if resp.status != 200:
            print(f"FAIL: {SOURCE} returned {resp.status}", file=sys.stderr)
            return 1
        text = resp.read().decode("utf-8")

    rules, converted = [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        ascii_rule = to_ascii(line)
        if ascii_rule != line:
            converted += 1

        body = ascii_rule.lstrip("!")
        body = body[2:] if body.startswith("*.") else body
        if not all(LABEL.match(p) for p in body.split(".")):
            print(f"FAIL: rule {line!r} normalised to {ascii_rule!r}, which is "
                  f"not a plain host", file=sys.stderr)
            return 1
        rules.append(ascii_rule)

    rules = sorted(set(rules))

    # Floors, not guesses: the upstream list has carried well over 9,000 rules
    # for years, and every one of the categories below has to survive the
    # normalisation. A silently truncated fetch would otherwise compile into a
    # browser that quietly widened every credential's blast radius.
    wildcards = [r for r in rules if r.startswith("*.")]
    exceptions = [r for r in rules if r.startswith("!")]
    for name, got, floor in (
        ("rules", len(rules), 9000),
        ("wildcard rules", len(wildcards), 200),
        ("exception rules", len(exceptions), 5),
    ):
        if got < floor:
            print(f"FAIL: {got} {name}, below the floor of {floor} -- the fetch "
                  f"was probably truncated", file=sys.stderr)
            return 1
    if not any(r.startswith("xn--") or ".xn--" in r for r in rules):
        print("FAIL: no punycode rules survived; the IDN conversion did nothing",
              file=sys.stderr)
        return 1

    stamp = datetime.date.today().isoformat()
    header = [
        "# Mozilla Public Suffix List, normalised to ASCII/punycode.",
        "#",
        "# GENERATED -- do not hand-edit. Regenerate with scripts/build-psl.py,",
        "# which documents why this file exists and why it is ASCII.",
        "#",
        f"# Source:    {SOURCE}",
        f"# Retrieved: {stamp}",
        f"# Rules:     {len(rules)} ({len(wildcards)} wildcard, "
        f"{len(exceptions)} exception, {converted} punycoded from Unicode)",
        "#",
        "# Licence: Mozilla Public License 2.0. The list is data, not code, and",
        "# is redistributed unmodified apart from the ASCII normalisation above.",
        "",
    ]
    OUT.write_text("\n".join(header + rules) + "\n", encoding="ascii")
    print(f"wrote {OUT} -- {len(rules)} rules, {converted} punycoded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
