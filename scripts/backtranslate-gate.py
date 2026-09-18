#!/usr/bin/env python3
"""Back-translation review gate: a lens for reading a locale you cannot read.

For every claim-bearing message in a delivered locale (claims.list, plus any
English source message the negation/limit lexicon matches), the target text
is machine-translated BACK to English through a LOCAL LibreTranslate and
compared with the source English. The output is a ranked review file: the
messages most likely to have lost a limit come first, each with source,
target, back-translation, marker vectors and a word diff.

MT IS EVIDENCE FOR HUMAN REVIEW, NOT A CORRECTNESS RESULT. The gate's hard
failures are mechanical only: endpoint absent or misbehaving, a selected
message missing from the locale, malformed inputs. Semantic signals -- a
negation class vanishing, marker-count deltas -- affect report ORDER, never
the exit code. A paraphrase ("not available" -> "unavailable") moves counts
without changing meaning; treating counts as an oracle would either drown
the reviewer in false alarms or, worse, teach them to trust a green exit.

The endpoint is pinned to loopback and never followed through a redirect:
interface strings are public, but this pipeline must not quietly ship text
to a third party because someone re-pointed an env var.

Dormant by design: with no locale delivered it exits 0 saying so, which is
what lets CI wire it today.

Usage: backtranslate-gate.py <locale>            (e.g. de)
       BACKTRANSLATE_URL overrides the endpoint but MUST stay on 127.0.0.1.
"""

import difflib
import hashlib
import json
import os
import re
import sys
import urllib.request

I18N = "crates/app/src/chrome/i18n"
LEXICON = {
    "negation": [
        "no", "not", "never", "none", "nothing", "neither", "nor",
        "cannot", "without",
    ],
    "exclusivity": ["only", "except", "unless", "solely", "limited to"],
    "bounds": [
        "at most", "at least", "up to", "no more than", "no less than",
    ],
    "absolutes": ["complete", "fully", "all", "always", "every"],
}


def fail(msg):
    print(f"GATE FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_ftl(path):
    msgs = {}
    for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.+)$", line)
        if m:
            if m.group(1) in msgs:
                fail(f"{path}:{lineno}: duplicate message {m.group(1)}")
            msgs[m.group(1)] = m.group(2)
        elif line[:1] in (" ", "\t"):
            fail(
                f"{path}:{lineno}: continuation lines are not supported by "
                "this gate; keep locale values single-line"
            )
        else:
            fail(f"{path}:{lineno}: unparseable line {line!r}")
    return msgs


def normalize(text):
    import unicodedata

    t = unicodedata.normalize("NFKC", text).casefold()
    t = t.replace("’", "'").replace("n't", " not")
    t = re.sub(r"\{[^}]*\}", " ", t)  # placeables are not language
    return re.sub(r"\s+", " ", t).strip()


def tokens(text):
    return re.findall(r"[a-z']+(?: [a-z']+)?", normalize(text))


def marker_vector(text):
    norm = " " + normalize(text) + " "
    vec = {}
    for cls, words in LEXICON.items():
        vec[cls] = sum(norm.count(f" {w} ") for w in words)
    return vec


def translate(session_url, text, source, target):
    body = json.dumps(
        {"q": text, "source": source, "target": target, "format": "text"}
    ).encode()
    req = urllib.request.Request(
        session_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            fail("endpoint answered with a redirect; refusing to follow")

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            data = json.loads(r.read().decode())
    except Exception as e:
        fail(
            f"local LibreTranslate unreachable or unusable ({e}). Start it, "
            "or do not run this gate; there is no hosted fallback ON PURPOSE."
        )
    if "translatedText" not in data:
        fail(f"endpoint reply carries no translatedText: {data!r}")
    return data["translatedText"]


def inert(text):
    return json.dumps(text, ensure_ascii=False)


def main():
    if len(sys.argv) != 2:
        fail("usage: backtranslate-gate.py <locale>")
    locale = sys.argv[1]
    if not re.fullmatch(r"[a-z]{2}(-[A-Za-z]{2,4})?", locale):
        fail(f"locale tag {locale!r} refused")
    locale_path = f"{I18N}/locales/{locale}.ftl"
    if not os.path.exists(locale_path):
        print(f"no locale to check: {locale_path} does not exist. Dormant, OK.")
        sys.exit(0)

    url = os.environ.get("BACKTRANSLATE_URL", "http://127.0.0.1:5000/translate")
    if not re.match(r"^http://127\.0\.0\.1(:\d+)?/", url):
        fail(f"endpoint {url!r} is not loopback; this gate never leaves the machine")

    english = parse_ftl(f"{I18N}/locales/en.ftl")
    target = parse_ftl(locale_path)
    claims = [
        l.strip()
        for l in open(f"{I18N}/claims.list", encoding="utf-8")
        if l.strip() and not l.startswith("#")
    ]

    # Work set: registered claims plus lexicon-discovered messages.
    selected = []
    seen = set()
    for cid in claims:
        if cid not in english:
            fail(f"claims.list pins {cid} but en.ftl has no such message")
        selected.append((cid, "claim"))
        seen.add(cid)
    for mid, text in english.items():
        if mid not in seen and any(v for v in marker_vector(text).values()):
            selected.append((mid, "lexicon"))

    rows = []
    for mid, origin in selected:
        if mid not in target:
            fail(f"selected message {mid} is missing from {locale_path}")
        back = translate(url, target[mid], locale, "en")
        src_vec = marker_vector(english[mid])
        back_vec = marker_vector(back)
        vanished = [c for c in src_vec if src_vec[c] and not back_vec[c]]
        absent = sum(1 for c in src_vec if src_vec[c] and not back_vec[c])
        delta = sum(abs(src_vec[c] - back_vec[c]) for c in src_vec)
        sdelta = abs(
            len(re.findall(r"[.!?]", english[mid]))
            - len(re.findall(r"[.!?]", back))
        )
        rows.append(
            {
                "id": mid,
                "origin": origin,
                "rank": (
                    0 if origin == "claim" else 1,
                    0 if vanished else 1,
                    -absent,
                    -delta,
                    -sdelta,
                    mid,
                ),
                "vanished": vanished,
                "src_vec": src_vec,
                "back_vec": back_vec,
                "back": back,
            }
        )
    if len(rows) != len(selected):
        fail("selected-entry/result count mismatch")
    rows.sort(key=lambda r: r["rank"])

    os.makedirs("target/backtranslation", exist_ok=True)
    digest = hashlib.sha256(
        open(f"{I18N}/locales/en.ftl", "rb").read()
    ).hexdigest()[:16]
    out = [
        f"# Back-translation review: {locale}",
        f"en.ftl digest {digest}; {len(rows)} messages "
        f"({sum(1 for r in rows if r['origin']=='claim')} registered claims).",
        "",
        "MT is evidence for human review, not a correctness result. Read from",
        "the top: worst divergence first. Every selected message appears,",
        "divergent or not.",
        "",
    ]
    for r in rows:
        mid = r["id"]
        out.append(f"## {mid} ({r['origin']})")
        if r["vanished"]:
            out.append(f"RISK: marker class vanished: {', '.join(r['vanished'])}")
        out.append(f"source English:  {inert(english[mid])}")
        out.append(f"target text:     {inert(target[mid])}")
        out.append(f"back-translated: {inert(r['back'])}")
        out.append(f"markers src={r['src_vec']} back={r['back_vec']}")
        diff = " ".join(
            difflib.unified_diff(
                normalize(english[mid]).split(),
                normalize(r["back"]).split(),
                lineterm="",
                n=0,
            )
        )
        out.append(f"word diff: {inert(diff[:400])}")
        out.append("")
    report = f"target/backtranslation/{locale}.md"
    tmp = report + ".tmp"
    open(tmp, "w", encoding="utf-8").write("\n".join(out))
    os.replace(tmp, report)
    print(f"review file: {report} ({len(rows)} messages, worst first)")
    sys.exit(0)


if __name__ == "__main__":
    main()
