#!/usr/bin/env python3
"""chrome.js and the catalog must tell the same story, like the markup does.

Every i18nText("id", "English") call site carries its golden English inline
-- that literal IS what an English build renders, with no lookup to miss.
This check extracts every (id, english) pair and fails when:

  - a call names a message the catalog does not carry (a locale fill could
    not cover it; the build's key scan also fails on this, two doors);
  - the catalog's value differs from the code's literal (the two English
    sources drifted, and a non-English reviewer translated words English
    users never saw reviewed);
  - one id is called with two different English literals (the id no longer
    names one string).

Only plain double-quoted second arguments are checkable; any other shape
(template, concatenation, variable) is a composed message that does not
belong in i18nText and fails loudly here.

Usage: i18n-js-check.py <chrome.js> <en.ftl>
"""

import json
import re
import sys


def render_literals(value):
    r"""Fluent string-literal placeables (uXXXX escapes included)
    render to their content -- the only way a single-line FTL value can
    carry a newline, and the comparison must see what a user would."""
    def sub(m):
        inner = m.group(1)
        inner = re.sub(
            r"\\u([0-9a-fA-F]{4})", lambda u: chr(int(u.group(1), 16)), inner
        )
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return re.sub(r'\{\s*"((?:[^"\\]|\\.)*)"\s*\}', sub, value)


def parse_ftl(path):
    msgs = {}
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.+)$", line)
        if m:
            msgs[m.group(1)] = render_literals(m.group(2))
    return msgs


def ftl_blocks(path):
    """Full multi-line value per message id.

    `parse_ftl` above keeps ONE LINE per message, which is what the i18nText
    drift check wants -- it compares a code literal against a catalog literal.
    A Fluent select expression spans several lines, so a placeable can live on
    a continuation line, and checking the first line alone reports a failure
    against a perfectly correct message. Found exactly that way:
    chrome-permissions-refused carries { $who } only inside its variants.
    """
    blocks, current = {}, None
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.*)$", line)
        if m:
            current = m.group(1)
            blocks[current] = m.group(2)
        elif current and (line.startswith((" ", "\t")) or line.strip() == "}"):
            blocks[current] += " " + line.strip()
        elif not line.strip():
            current = None
    return blocks


def main():
    js_path, ftl_path = sys.argv[1], sys.argv[2]
    js = open(js_path, encoding="utf-8").read()
    msgs = parse_ftl(ftl_path)
    blocks = ftl_blocks(ftl_path)
    status = 0
    seen = {}
    count = 0
    # THE KEY MUST SIT ON THE SAME LINE AS THE i18nText CALL.
    #
    # build.rs scans the chrome sources for the CONTIGUOUS needle `i18nText("`
    # and takes the next quoted token; that list becomes CHROME_MSG_KEYS, and
    # CHROME_MSG_KEYS is exactly what `push_locale_fill` ships as the runtime
    # locale snapshot. An id that wraps onto the next line never reaches the
    # snapshot, so `localeJsStrings[id]` is undefined and `i18nText` returns
    # its English fallback in EVERY locale. The catalog entry is fine. The
    # translation simply never arrives, and nothing looks wrong.
    #
    # i18nResolve is NOT checked, and the difference matters: it asks Rust for
    # the id at runtime and `i18n_resolve` accepts anything in `keys::ALL`, so
    # a wrapped i18nResolve still localizes correctly. Checking it too would
    # report dozens of sites that are not broken, and a gate that complains
    # about non-defects is one people learn to skip.
    #
    # FATAL. It was a warning for exactly one commit, while 44 pre-existing
    # sites were still wrapped -- about half of them in the translation panel,
    # the headline feature of this release. Those are fixed, so this fails now:
    # a warning nobody has to act on is how the backlog got to 44 in the first
    # place.
    for m in re.finditer(r'\bi18nText\(\s+"([a-z0-9-]+)"', js):
        line = js[: m.start()].count("\n") + 1
        print(
            f"GATE FAIL: {js_path}:{line}: {m.group(1)} is on a different line "
            f"from its i18nText( call."
        )
        print(
            "  build.rs only sees a contiguous i18nText(\"key\", so this string "
            "would render English in every locale."
        )
        status = 1

    # The English argument may be one literal or a pure-literal
    # concatenation chain broken for source width; both are golden copy.
    lit_chain = r'"(?:[^"\\]|\\.)*"(?:\s*\+\s*"(?:[^"\\]|\\.)*")*'
    for m in re.finditer(
        r'i18nText\(\s*"([a-z0-9-]+)"\s*,\s*(' + lit_chain + r')', js
    ):
        mid, chain = m.group(1), m.group(2)
        count += 1
        english = "".join(
            json.loads(part) for part in re.findall(r'"(?:[^"\\]|\\.)*"', chain)
        )
        if mid in seen and seen[mid] != english:
            print(f"GATE FAIL: {mid} is called with two different English texts:")
            print(f"  {seen[mid]!r}")
            print(f"  {english!r}")
            status = 1
            continue
        seen[mid] = english
        if mid not in msgs:
            print(f"GATE FAIL: i18nText names {mid} but en.ftl has no such message.")
            status = 1
        elif msgs[mid] != english:
            print(f"GATE FAIL: {mid} drifted between code and catalog.")
            print(f"  code:    {english!r}")
            print(f"  catalog: {msgs[mid]!r}")
            status = 1
    # A second argument that is not a plain literal is a composed message in
    # the wrong API. Catch the call shape, not just its absence.
    for m in re.finditer(r'i18nText\(\s*"[a-z0-9-]+"\s*,\s*([^")\s][^)]*)\)', js):
        print(f"GATE FAIL: i18nText with a non-literal English argument: {m.group(1)[:60]!r}")
        print("  Composed messages go through the resolve path, not i18nText.")
        status = 1
    # ---- i18nSet: an argument must have somewhere to go -------------------
    #
    # THE DEFECT THIS EXISTS FOR. Three chrome-update-feature-* values were
    # extracted from a JS ternary. Both branches were welded into one catalog
    # value -- "Version  adds An update adds new features..." -- and the
    # { $version } placeable was lost with the branch. The call sites kept
    # passing { version }, handing an argument to a message with nowhere to
    # put it. English never showed it, because i18nSet paints its fallback
    # synchronously and localeJsStrings is empty for English, so the only
    # locale read here was the one locale unaffected.
    #
    # The rule: every name in an i18nSet argument object must appear as a
    # placeable in that message. An argument with nowhere to go is either a
    # lost placeable or a stale call site, and both are defects. The existing
    # check above covers i18nText, which takes no arguments; i18nSet is the
    # one that does.
    setcount = 0
    for m in re.finditer(
        r'i18nSet\(\s*[^,]+?,\s*"([a-z0-9-]+)"\s*,\s*\{([^{}]*)\}', js
    ):
        mid, argblock = m.group(1), m.group(2)
        setcount += 1
        if mid not in msgs:
            print(f"GATE FAIL: i18nSet names {mid} but en.ftl has no such message.")
            status = 1
            continue
        # Shorthand `{ version }` and explicit `{ version: v }` both count.
        # KEY NAMES ONLY. The first draft of this check took every
        # identifier inside the braces, so `{ host: shownHost }` yielded both
        # `host` (the key, correct) and `shownHost` (the value), and reported
        # 21 false failures against messages that were perfectly fine. Split
        # on top-level commas, then take what is left of a colon; a shorthand
        # entry `{ version }` is its own key.
        names = []
        for piece in argblock.split(","):
            piece = piece.strip()
            if not piece:
                continue
            key = piece.split(":", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                names.append(key)
        seen_names = set()
        for name in names:
            if name in seen_names:
                continue
            seen_names.add(name)
            # WORD BOUNDARY, not substring: `$ver` occurs inside
            # `$version`, so a plain `in` test let a renamed argument
            # pass. That is the stale-call-site half of what this check
            # is for, and a mutation caught it being blind to it.
            placeable = re.compile(r"\$" + re.escape(name) + r"\b")
            if not placeable.search(blocks.get(mid, msgs[mid])):
                print(
                    f"GATE FAIL: i18nSet passes {{ {name} }} to {mid}, but that "
                    f"message has no {{ ${name} }} placeable."
                )
                print(f"  catalog: {blocks.get(mid, msgs[mid])[:110]!r}")
                print(
                    "  An argument with nowhere to go is a lost placeable or a"
                    " stale call site. English hides both."
                )
                status = 1
    print(f"i18nText sites checked: {count} ({len(seen)} distinct ids)")
    print(f"i18nSet argument sites checked: {setcount}")
    sys.exit(status)


if __name__ == "__main__":
    main()
