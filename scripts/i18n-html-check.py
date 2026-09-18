#!/usr/bin/env python3
"""The catalog and the chrome markup must tell the same story.

Every element carrying a data-msg marker (and every data-msg-title /
-placeholder / -aria-label / -alt attribute marker) names a message in
en.ftl. This check re-derives the English text from the markup, normalizes
whitespace the way HTML rendering does, and compares it with the catalog
value. A mismatch in either direction fails:

  - marker without a catalog message: a locale fill would erase that text;
  - catalog value differing from the markup text: the two English sources
    have drifted, and a non-English user would be shown a sentence English
    users never see reviewed.

The checked-in chrome files stay the English golden copies; nothing here
rewrites them. English builds ship them unchanged, which is what keeps
English rendering byte-identical without a generation step.

Exit 0 clean; exit 1 with one line per finding. Also prints the marker
count so the gate can report coverage.

Usage: i18n-html-check.py <index.html> <en.ftl>
"""

import html as html_mod
import re
import sys
from html.parser import HTMLParser

ATTR_MARKERS = {
    "data-msg-title": "title",
    "data-msg-placeholder": "placeholder",
    "data-msg-aria-label": "aria-label",
    "data-msg-alt": "alt",
}


def normalize(text):
    return re.sub(r"\s+", " ", text).strip()


def parse_ftl(path):
    """id -> normalized single-line value. The extractor writes single-line
    values only; a continuation line here is a format this checker does not
    understand and must fail loudly rather than mis-compare."""
    messages = {}
    in_select = False
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.*)$", line)
        if m:
            # A select spans lines; markup markers can never name one (a
            # marker fill has no arguments), so its value is not recorded
            # and any marker naming it fails as missing -- correctly.
            in_select = line.rstrip().endswith("->")
            if not in_select:
                messages[m.group(1)] = m.group(2)
        elif line[:1] in (" ", "\t") or line.strip() == "}":
            if not in_select:
                print(
                    "GATE FAIL: unexpected continuation outside a select "
                    f"in en.ftl: {line!r}"
                )
                sys.exit(1)
            if line.strip() == "}":
                in_select = False
    return messages


def key_to_ftl_id(key):
    return key.replace(".", "-")


class Walker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.findings = []
        self.marked = []  # (ftl_id, normalized_english, where)
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("script", "style"):
            self.skip_depth += 1
        for marker, attr in ATTR_MARKERS.items():
            if marker in d:
                value = d.get(attr)
                if value is None:
                    self.findings.append(
                        f"{marker}={d[marker]!r} on <{tag}> but the {attr} "
                        "attribute it localizes is absent"
                    )
                else:
                    self.marked.append(
                        (key_to_ftl_id(d[marker]), normalize(value), f"<{tag} {attr}>")
                    )
        self.stack.append(
            {"tag": tag, "msg": d.get("data-msg"), "text": "", "kids": 0}
        )

    def handle_endtag(self, tag):
        while self.stack:
            el = self.stack.pop()
            if self.stack:
                self.stack[-1]["kids"] += 1
            if el["msg"]:
                if el["kids"]:
                    self.findings.append(
                        f"data-msg={el['msg']!r} on <{el['tag']}> with child "
                        "elements: mixed content cannot be filled as text"
                    )
                else:
                    self.marked.append(
                        (key_to_ftl_id(el["msg"]), normalize(el["text"]), f"<{el['tag']}>")
                    )
            if el["tag"] == tag:
                break
        if tag in ("script", "style") and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data):
        if self.stack and not self.skip_depth:
            self.stack[-1]["text"] += data


def main():
    html_path, ftl_path = sys.argv[1], sys.argv[2]
    messages = parse_ftl(ftl_path)
    src = re.sub(
        r"<!--.*?-->", "", open(html_path, encoding="utf-8").read(), flags=re.S
    )
    w = Walker()
    w.feed(src)

    status = 0
    seen = {}
    for ftl_id, english, where in w.marked:
        if ftl_id in seen and seen[ftl_id] != english:
            print(
                f"GATE FAIL: {ftl_id} marks two different texts: "
                f"{seen[ftl_id]!r} and {english!r}"
            )
            status = 1
            continue
        seen[ftl_id] = english
        if ftl_id not in messages:
            print(
                f"GATE FAIL: {where} marks {ftl_id} but en.ftl has no such "
                "message. A locale fill would erase this text."
            )
            status = 1
        elif messages[ftl_id] != english:
            print(f"GATE FAIL: {ftl_id} drifted between markup and catalog.")
            print(f"  markup:  {english!r}")
            print(f"  catalog: {messages[ftl_id]!r}")
            status = 1
    for finding in w.findings:
        print(f"GATE FAIL: {finding}")
        status = 1

    print(f"markers checked: {len(seen)}")
    sys.exit(status)


if __name__ == "__main__":
    main()
