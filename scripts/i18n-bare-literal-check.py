#!/usr/bin/env python3
"""New chrome.js strings must enter through the catalog, not around it.

The other i18n checks validate what IS wired: markers against the catalog,
i18nText sites against the catalog, claims against the manifest. None of
them can see the string a future feature writes straight into a sink --
`el.textContent = "Saved."` -- which would ship English-only forever and
never fail anything. This check is that tripwire.

It flags a PURE string literal flowing into a user-facing sink
(.textContent/.title/.placeholder assignment, toast(...), el(tag, cls,
"...")) that is not wrapped in i18nText. Concatenations are deliberately
NOT flagged yet: they are the composed-message set, still being converted,
and flagging them would make this gate red for known work. When the
composed pass lands, the composed shapes join this scan.

At the time this check was written it flagged zero sites -- the extraction
was complete for these shapes -- so anything it flags is NEW.

Usage: i18n-bare-literal-check.py <chrome.js>
"""

import re
import sys

# Phase 2 (the composed sweep is done): a string literal CONCATENATED with
# a runtime value on its way to a sink is also flagged, unless it is
# (a) inside an i18n call span (the English fallback IS the golden copy),
# (b) within a few lines of one (the sync-paint twin of a patch block), or
# (c) not language: no space and fewer than three letter-runs, which is
# what id, URL and CSS construction look like.
CONCAT = re.compile(
    r'"((?:[^"\\]|\\.)*[A-Za-z]{2}(?:[^"\\]|\\.)*)"\s*\+\s*[a-zA-Z_$]'
)
TEMPLATE = re.compile(r"`[^`]*[A-Za-z]{2}[^`]*\$\{")


def strip_i18n_spans(src):
    out = []
    i = 0
    while True:
        m = re.search(r"i18n(?:Text|Resolve|Set)\(", src[i:])
        if not m:
            out.append(src[i:])
            break
        start = i + m.start()
        out.append(src[i:start])
        j = i + m.end()
        depth = 1
        while depth and j < len(src):
            c = src[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c in "\"'`":
                q = c
                j += 1
                while j < len(src) and src[j] != q:
                    if src[j] == "\\":
                        j += 1
                    j += 1
            j += 1
        # keep the newlines so line numbers survive the strip
        out.append("I18N_CALL()" + "\n" * src[start:j].count("\n"))
        i = j
    return "".join(out)


SINKS = [
    (r'(\.textContent|\.title|\.placeholder)\s*=\s*("(?:[^"\\]|\\.)*");', 2),
    (r'\btoast\(\s*("(?:[^"\\]|\\.)*")\s*[,)]', 1),
    (r'\bel\(\s*"[a-z]+"\s*,\s*(?:"[^"]*"|null)\s*,\s*("(?:[^"\\]|\\.)*")\s*\)', 1),
]


def main():
    path = sys.argv[1]
    status = 0
    for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
        code = line.split("//")[0]
        if "i18nText" in code:
            continue
        for pattern, group in SINKS:
            for m in re.finditer(pattern, code):
                lit = m.group(group)
                if re.search(r"[A-Za-z]{2}", lit):
                    print(
                        f"GATE FAIL: {path}:{lineno}: a bare English literal "
                        f"reaches a user-facing sink: {lit[:60]}"
                    )
                    print(
                        '  Wrap it: i18nText("chrome-js-<area>-<slug>", '
                        f"{lit[:40]}...) and add the message to en.ftl."
                    )
                    status = 1
    stripped = strip_i18n_spans(open(path, encoding="utf-8").read())
    lines = stripped.split("\n")
    for idx, line in enumerate(lines):
        code = line.split("//")[0]
        if "console." in code:
            continue  # diagnostics are not user-facing
        m = CONCAT.search(code) or TEMPLATE.search(code)
        if not m:
            continue
        lit = m.group(1) if m.re is CONCAT else m.group(0)
        if " " not in lit and len(re.findall(r"[A-Za-z]{2,}", lit)) < 3:
            continue  # id / URL / CSS construction, not language
        if re.fullmatch(r"[a-z][a-z0-9 -]*-", lit):
            continue  # CSS class-list construction ("presence presence-" + s)
        if re.match(r"^\d+px\b|^hsl\(|solid $| solid$", lit) or re.search(
            r"(?:border|margin|padding|background|font|style)\w*\s*[:=]", code
        ):
            continue  # a CSS value with a space is still not language
        window = "\n".join(lines[max(0, idx - 10) : idx + 11])
        if "I18N_CALL()" in window:
            continue  # the sync-paint twin of an adjacent patch block
        print(
            f"GATE FAIL: {path}:{idx + 1}: an unpaired English "
            f"concatenation: {code.strip()[:70]}"
        )
        print(
            "  Route it through i18nText / i18nResolve / i18nSet, or pair "
            "it with its patch block."
        )
        status = 1
    print("bare-literal scan: chrome.js")
    sys.exit(status)


if __name__ == "__main__":
    main()
