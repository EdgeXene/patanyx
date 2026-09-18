#!/usr/bin/env python3
"""Fill the chrome markup from a pseudo-locale, then hunt surviving English.

Simulates exactly what the runtime applier does -- data-msg text fills,
data-msg-<attr> attribute fills, textContent semantics, nothing else -- and
then visits EVERY text node and localizable attribute in the result, marked
or not. Any remaining ASCII alphabetic token is text that never went through
the catalog, unless its exact node text is on the allowlist below. The
pseudo-locale's own letters are all non-ASCII and its padding marker is
non-ASCII, so the instrument cannot trip itself.

The allowlist is EXACT text, one entry per line in scripts/i18n-ascii-allow.txt,
and every entry must actually occur -- a stale allowlist entry is a failure,
because it is a hole someone will hide new English in.

Usage: i18n-coverage-scan.py <index.html> <locale.ftl>
"""

import re
import sys
from html.parser import HTMLParser

ATTR_MARKERS = {
    "data-msg-title": "title",
    "data-msg-placeholder": "placeholder",
    "data-msg-aria-label": "aria-label",
    "data-msg-alt": "alt",
}
LOCALIZABLE_ATTRS = set(ATTR_MARKERS.values())


def parse_ftl(path):
    msgs = {}
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.+)$", line)
        if m:
            msgs[m.group(1)] = m.group(2)
    return msgs


class Scan(HTMLParser):
    def __init__(self, msgs, allow):
        super().__init__(convert_charrefs=True)
        self.msgs = msgs
        self.allow = allow
        self.findings = []
        self.allow_hits = set()
        self.stack = []
        self.skip = 0

    def fill(self, key):
        return self.msgs.get(key.replace(".", "-"))

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("script", "style", "template", "title"):
            self.skip += 1
        for marker, attr in ATTR_MARKERS.items():
            if marker in d and d.get(attr) is not None:
                filled = self.fill(d[marker])
                if filled is not None:
                    d[attr] = filled
        if not self.skip:
            for attr in LOCALIZABLE_ATTRS:
                v = d.get(attr)
                if v:
                    self.check(v, f"<{tag} {attr}>")
        self.stack.append({"tag": tag, "msg": d.get("data-msg"), "text": ""})

    def handle_endtag(self, tag):
        while self.stack:
            el = self.stack.pop()
            text = el["text"]
            if el["msg"]:
                filled = self.fill(el["msg"])
                if filled is not None:
                    text = filled
            if not self.skip and text.strip():
                self.check(text, f"<{el['tag']}>")
            if el["tag"] == tag:
                break
        if tag in ("script", "style", "template", "title") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if self.stack:
            self.stack[-1]["text"] += data

    def check(self, text, where):
        norm = re.sub(r"\s+", " ", text).strip()
        if norm in self.allow:
            self.allow_hits.add(norm)
            return
        tokens = re.findall(r"[A-Za-z]{2,}", norm)
        if tokens:
            self.findings.append((where, norm[:70], tokens[:4]))


def main():
    html_path, ftl_path = sys.argv[1], sys.argv[2]
    allow_path = "scripts/i18n-ascii-allow.txt"
    allow = {
        l.strip()
        for l in open(allow_path, encoding="utf-8")
        if l.strip() and not l.startswith("#")
    }
    msgs = parse_ftl(ftl_path)
    src = re.sub(
        r"<!--.*?-->", "", open(html_path, encoding="utf-8").read(), flags=re.S
    )
    s = Scan(msgs, allow)
    s.feed(src)
    status = 0
    for where, text, tokens in s.findings:
        print(f"GATE FAIL: unextracted English survives the fill at {where}:")
        print(f"  {text!r} (tokens: {', '.join(tokens)})")
        status = 1
    for stale in sorted(allow - s.allow_hits):
        print(f"GATE FAIL: allowlist entry never occurred: {stale!r}")
        print("  A stale exemption is a hole someone will hide new English in.")
        status = 1
    print(f"nodes clean, findings: {len(s.findings)}, allowlisted: {len(s.allow_hits)}")
    sys.exit(status)


if __name__ == "__main__":
    main()
