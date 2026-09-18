#!/usr/bin/env python3
"""Hourly engine-advisory monitor and publisher for the WebView2 floor.

WHAT THIS DOES, IN ONE PARAGRAPH. It reads two fixed Microsoft pages over
HTTPS: the Edge Stable security release notes, and the Update Catalog search
for the exact WebView2 Runtime build those notes name. When the notes'
NEWEST relevant desktop entry names a Stable build that fixes a CVE the
Chromium team reported as exploited in the wild, AND the Catalog lists an
x64 "Microsoft Edge-WebView2 Runtime" row for that exact build with a valid
date and a positive size, AND that build is higher than the floor already
published (or no valid publication exists yet), it signs a warning-only
engine advisory with the ADVISORY key (never the release key), verifies its
own output under the configured verifying key, and atomically publishes it
at <publish-root>/v1/engine-advisory.json. Everything else -- a source that
cannot be fetched, a page whose shape this parser does not recognise, an
ambiguous or split association, a missing runtime, an identical page --
leaves the last-good publication exactly as it was and says so through the
exit code and a timestamped status file. It sends no email, no webhook and no
message; whatever watches the journal and the status file does the paging.

STRICT SCOPE. Only "explicitly exploited desktop Chromium fixes": ONE
sentence that says the named CVE(s) have an exploit in the wild AND that
this update contains the fix for them, beside a desktop Stable build named
in the same paragraph. Edge-specific CVE lists, Android, iOS, macOS-only,
Beta/Dev/Canary and ordinary Stable releases are not candidates. Every
heading's material is classified: a relevant notice under a heading that is
not a dated h2 refuses the run rather than disappearing, and nothing older is
ever selected underneath a newer relevant notice this parser could not read.
If the selected CVE is associated with two different desktop builds (a
Stable and an Extended Stable branch, say) the association is ambiguous and
refused. Older sections with their own parallel branches are history, not a
veto. A notice dated in the future is refused rather than signed today.

TWO FLOORS, TWO JOBS. --baseline is the WebView2 floor the shipped browser
COMPILES IN; it is the only thing the client's plausibility bound is judged
against, here, in the signer and in the verifier. The floor already
published (last-good and the served manifest) is the MONOTONIC authority:
nothing is ever published below it. Raising the published floor never moves
the bound, so the fleet is never handed a document its compiled constant
would refuse.

BOOTSTRAP. When no valid publication exists (first activation), a candidate
equal to the current floor is corroborated, signed and published like any
raise, so the served endpoint exists before clients ship. Once a valid
publication exists, an equal candidate is a healthy no-op with the served
bytes untouched.

FRESHNESS is the fetched bytes, not <meta name="ms.date">, which is editorial
metadata that lags the content by months. An identical page on the next run
is a healthy no-op.

RUNS WITHOUT A KEY. --dry-run performs the whole discovery, writes the
candidate payload and status into the state directory, and exits 0 without
signing or publishing. That is the mode used to prove the
pipeline before provisioning the key, and the mode the tests use.

EXIT CODES (each is a distinct journal line, none is silent):
  0  published, or a healthy no-op (unchanged / would-raise / would-bootstrap
     in dry-run)
  2  a source could not be fetched within bounds (timeout, oversize, wrong
     media type, redirect, HTTP error)
  3  the source was fetched but refused: unrecognised shape, relevant
     material under an unfamiliar heading, unparsed relevant notice,
     ambiguous association, future-dated notice, missing or invalid catalog
     corroboration, implausible candidate against the compiled baseline
  4  another run holds the lock
  5  signing or self-verification refused
  6  publication could not be written (last-good untouched)
  7  configuration error (missing key, key/verifying-key mismatch, bad
     arguments, malformed local state, internal error); status still written

usage:
  engine-advisory-monitor.py --state-dir DIR --baseline a.b.c.d --dry-run
  engine-advisory-monitor.py --state-dir DIR --baseline a.b.c.d \
      --publish-root /srv/patanyx-dist --key /root/.patanyx-keys/advisory.key \
      --signer /path/to/patanyx-sign --public-key <hex>
  engine-advisory-monitor.py ... --fetch-from-dir DIR   (fixtures; tests)
"""
import argparse
import datetime
import fcntl
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request

SECURITY_NOTES_URL = "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security"
SECURITY_NOTES_HOST = "learn.microsoft.com"
CATALOG_SEARCH_URL = "https://www.catalog.update.microsoft.com/Search.aspx?q=Microsoft%20Edge-WebView2%20Runtime%20{version}"
CATALOG_HOST = "www.catalog.update.microsoft.com"

MAX_SOURCE_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT = 25
USER_AGENT = "PATANYX-engine-advisory-monitor/1.0"
# Same bound the client applies (patanyx_update::ADVISORY_MAX_MAJOR_AHEAD),
# stated in majors and nothing else, judged against the COMPILED baseline.
DEFAULT_MAX_MAJOR_AHEAD = 24
KEEP_EVIDENCE = 12
# A notice dated ahead of the clock by more than this is not "today with a
# time zone"; it is a future notice and is refused.
FUTURE_DATE_TOLERANCE_DAYS = 1

EXIT_OK, EXIT_FETCH, EXIT_REFUSED, EXIT_LOCKED, EXIT_SIGN, EXIT_PUBLISH, EXIT_CONFIG = 0, 2, 3, 4, 5, 6, 7


class Fetch(Exception):
    """A source could not be fetched within bounds."""


class Refused(Exception):
    """A source was fetched but its content is not acceptable."""


class ConfigError(Exception):
    """Local configuration or state is not usable."""


# --- versions ---------------------------------------------------------------

VERSION_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\.(\d+)\b")


def parse4(text):
    """Exactly four decimal fields that fit u32, or None. No leading sign, no
    suffix, no fifth field."""
    if not isinstance(text, str) or len(text) > 32:
        return None
    parts = text.split(".")
    if len(parts) != 4 or not all(p.isdigit() and p.isascii() for p in parts):
        return None
    out = tuple(int(p) for p in parts)
    if any(v > 0xFFFFFFFF for v in out):
        return None
    return out


def join4(v):
    return ".".join(str(x) for x in v)


# --- bounded fetch ----------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Fetch(f"{req.full_url}: redirected ({code}) to {newurl}; refusing to follow")


def http_get(url, expect_host, timeout=DEFAULT_TIMEOUT, cap=MAX_SOURCE_BYTES,
             opener=None, allow_http=False):
    """GET one fixed URL: https only, host pinned, no redirects, Content-Type
    must be HTML, body capped while streaming. Returns bytes."""
    scheme_ok = url.startswith("https://") or (allow_http and url.startswith("http://"))
    if not scheme_ok:
        raise Fetch(f"{url}: not https")
    host = url.split("://", 1)[1].split("/", 1)[0]
    if host != expect_host:
        raise Fetch(f"{url}: host {host!r} is not the pinned {expect_host!r}")
    opener = opener or urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    try:
        with opener.open(req, timeout=timeout) as r:
            status = getattr(r, "status", 200)
            if status != 200:
                raise Fetch(f"{url}: HTTP {status}")
            ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "text/html":
                raise Fetch(f"{url}: Content-Type {ctype!r} is not text/html")
            clen = r.headers.get("Content-Length")
            if clen is not None and clen.isdigit() and int(clen) > cap:
                raise Fetch(f"{url}: Content-Length {clen} exceeds cap {cap}")
            buf = bytearray()
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > cap:
                    raise Fetch(f"{url}: body exceeds cap {cap}")
            return bytes(buf)
    except urllib.error.HTTPError as e:
        raise Fetch(f"{url}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise Fetch(f"{url}: {e.__class__.__name__}: {e}") from None


# --- the security notes parser ----------------------------------------------

MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august",
     "september", "october", "november", "december"], 1)}
ANY_HEADING_RE = re.compile(r"<(h[1-6])\b[^>]*>(.*?)</\1>", re.S)
PARA_RE = re.compile(r"<p\b[^>]*>(.*?)</p>", re.S)
DATE_RE = re.compile(r"^([A-Za-z]+)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})$")
CVE = r"CVE[-‑‐]\d{4}[-‑‐]\d{4,7}"
CVE_TEXT_RE = re.compile(r"\b" + CVE + r"\b")
# Any anchor whose TEXT is a CVE, whatever the attribute quoting. The href is
# taken from either quote style; an anchor with a CVE text and no readable
# href is a mismatch.
ANCHOR_RE = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.S)
HREF_RE = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
EXPLOIT_RE = re.compile(r"exploit", re.I)
MOBILE_RE = re.compile(r"\b(?:Android|iOS|iPadOS|macOS)\b")
NON_STABLE_RE = re.compile(r"\b(?:Beta|Dev|Canary|Insider)\b")
# Desktop Stable clause: "Microsoft Edge [for] Stable [Channel] ([Version] X)".
STABLE_CLAUSE_RE = re.compile(
    r"Microsoft\s+Edge\s+(?:for\s+)?Stable(?:\s+Channel)?\s*\(\s*(?:[Vv]ersion\s+)?(\d+\.\d+\.\d+\.\d+)\s*\)")
EXTENDED_CLAUSE_RE = re.compile(
    r"Extended\s+Stable(?:\s+[Cc]hannel)?\s*\(?\s*(?:[Vv]ersion\s+)?(\d+\.\d+\.\d+\.\d+)\s*\)?")
# THE ASSOCIATION: one sentence in which the same CVE list is both "exploited
# in the wild" and "fixed by this update". Two grammars Microsoft has used;
# both are single sentences, so an exploited CVE in one sentence and a fix
# for another CVE in the next can never match.
CVE_LIST = r"(" + CVE + r"(?:\s*,\s*" + CVE + r")*(?:\s*,?\s*and\s+" + CVE + r")?)"
ASSOCIATION_A_RE = re.compile(
    r"The Chromium team reported that\s*" + CVE_LIST +
    r"\s+(?:has|have) an exploit in the wild,? and this update contains a fix for (?:it|them)\b", re.I)
ASSOCIATION_B_RE = re.compile(
    r"This update contains a fix for\s*" + CVE_LIST +
    r"\s*,?\s*(?:which|that) (?:has|have) been reported by the Chromium team as having an exploit in the wild\b", re.I)
# Microsoft's recurring commentary paragraph. STANDALONE ONLY: it qualifies
# for the exemption when it names no build, no Stable clause and no fix.
COMMENTARY_RE = re.compile(r"enhanced security mode feature mitigates", re.I)
FIX_WORD_RE = re.compile(r"\bfix", re.I)
STRUCTURAL_HEADINGS = {"in this article", "see also", "feedback", "additional resources"}


def strip_tags(fragment):
    return html.unescape(re.sub(r"<[^>]+>", "", fragment)).replace("\xa0", " ")


def norm_cve(c):
    return c.replace("‑", "-").replace("‐", "-")


def parse_heading_date(text):
    m = DATE_RE.match(text.strip())
    if not m:
        return None
    month = MONTHS.get(m.group(1).lower())
    if month is None:
        return None
    try:
        return datetime.date(int(m.group(3)), month, int(m.group(2)))
    except ValueError:
        return None


def split_sections(page):
    """EVERY heading of any level in the content container starts a section;
    the material before the first heading is a section too. A section is
    DATED only when it is an h2 whose text is a plain date. Undated sections
    (the title, "In this article", "See also", "July 02, 2026 macOS",
    "February - 26, 2026", an h3, a "(updated)" suffix) are returned with
    date None so the caller can insist they carry nothing relevant. Dated
    sections must be newest-first."""
    start = page.find('<div class="content">')
    if start < 0:
        raise Refused("security notes: no <div class=\"content\"> container; page shape changed")
    body = page[start:]
    sections = []
    pos = 0
    pending = {"title": "(before the first heading)", "date": None, "level": None, "html": ""}
    for m in ANY_HEADING_RE.finditer(body):
        pending["html"] = body[pos:m.start()]
        sections.append(pending)
        title = strip_tags(m.group(2)).strip()
        level = m.group(1)
        pending = {"title": title, "level": level,
                   "date": parse_heading_date(title) if level == "h2" else None, "html": ""}
        pos = m.end()
    pending["html"] = body[pos:]
    sections.append(pending)
    for s in sections:
        s["paragraphs"] = PARA_RE.findall(s["html"])
        # Relevant words OUTSIDE any <p>: a notice in a list item, a div or
        # bare text is unfamiliar structure and must not vanish.
        residual = strip_tags(PARA_RE.sub(" ", s["html"]))
        s["residual_relevant"] = bool(EXPLOIT_RE.search(residual) or "in the wild" in residual)
    dated = [s for s in sections if s["date"] is not None]
    if not dated:
        raise Refused("security notes: no dated sections found; page shape changed")
    for earlier, later in zip(dated, dated[1:]):
        if later["date"] > earlier["date"]:
            raise Refused(
                f"security notes: sections are not newest-first ({later['title']} after {earlier['title']}); refusing")
    return sections


def is_relevant(text):
    """Does this paragraph talk about an exploit in a way that could carry
    a candidate? Anything relevant that then fails to parse refuses."""
    if not EXPLOIT_RE.search(text) and "in the wild" not in text:
        return False
    if COMMENTARY_RE.search(text) and not VERSION_RE.search(text) and "Stable" not in text \
            and not FIX_WORD_RE.search(text.replace("mitigates", "")):
        # The standalone commentary paragraph: no build, no Stable clause,
        # no fix statement. An exact exemption; anything more is relevant.
        return False
    return True


def cve_links(raw):
    """(text, href) for every anchor whose text is a CVE, any quote style."""
    out = []
    for attrs, inner in ANCHOR_RE.findall(raw):
        label = strip_tags(inner).strip()
        if not CVE_TEXT_RE.fullmatch(label):
            continue
        h = HREF_RE.search(attrs)
        href = next((g for g in h.groups() if g is not None), None) if h else None
        out.append((norm_cve(label), href))
    return out


def classify_paragraph(raw):
    """One paragraph -> None (not relevant), or a dict describing a desktop
    exploited-fix notice, or raises Refused when the paragraph is relevant
    but cannot be read with confidence."""
    text = strip_tags(raw)
    if not is_relevant(text):
        return None
    stable = STABLE_CLAUSE_RE.findall(text)
    extended = EXTENDED_CLAUSE_RE.findall(text)
    if MOBILE_RE.search(text) and not stable:
        # Android / iOS / macOS-only: out of scope entirely.
        return None
    if NON_STABLE_RE.search(text):
        raise Refused(f"security notes: exploited notice names a non-Stable channel: {text[:160]!r}")
    if MOBILE_RE.search(text):
        raise Refused(f"security notes: exploited notice mixes desktop Stable with mobile: {text[:160]!r}")
    if not stable and not extended:
        raise Refused(f"security notes: exploited notice with no recognised Stable clause: {text[:160]!r}")
    # THE ASSOCIATION SENTENCE. Exactly one, and the CVE list inside it is
    # the whole set this notice is about.
    matches = [m for rx in (ASSOCIATION_A_RE, ASSOCIATION_B_RE) for m in rx.finditer(text)]
    if len(matches) != 1:
        raise Refused(
            f"security notes: exploited notice without exactly one exploited-and-fixed sentence "
            f"({len(matches)} found): {text[:200]!r}")
    cves = sorted({norm_cve(c) for c in CVE_TEXT_RE.findall(matches[0].group(1))})
    # No other CVE may be mentioned in the paragraph: a second CVE outside the
    # association sentence is a claim this grammar cannot attribute.
    all_cves = {norm_cve(c) for c in CVE_TEXT_RE.findall(text)}
    if all_cves != set(cves):
        raise Refused(
            f"security notes: CVEs outside the association sentence {sorted(all_cves - set(cves))}: {text[:200]!r}")
    # Every CVE must be linked, and every CVE link must point at itself.
    links = cve_links(raw)
    linked = {}
    for label, href in links:
        if href is None or not href.startswith("https://msrc.microsoft.com/") or not href.rstrip("/").endswith("/" + label):
            raise Refused(f"security notes: CVE link text {label!r} does not match its target {href!r}")
        linked[label] = href
    missing = [c for c in cves if c not in linked]
    if missing:
        raise Refused(f"security notes: CVE(s) {missing} are not linked to the Security Update Guide")
    stable_versions = [parse4(v) for v in stable]
    extended_versions = [parse4(v) for v in extended]
    if any(v is None for v in stable_versions + extended_versions):
        raise Refused(f"security notes: a version token is not four u32 fields: {text[:160]!r}")
    return {"text": text, "cves": cves, "stable": stable_versions, "extended": extended_versions}


def select_candidate(sections, today):
    """The newest DATED section with a relevant notice decides. Everything
    ABOVE it in document order is classified strictly first: relevant
    material under an undated or non-h2 heading, outside a paragraph, or in
    a paragraph this grammar cannot read refuses the run, so nothing newer
    can disappear underneath an older match. Everything BELOW it is history:
    Microsoft's older prose forms are not re-parsed, and only the selected
    CVE's other associations are looked at (the ambiguity scan)."""
    newest = None
    for section in sections:
        notices = []
        for raw in section["paragraphs"]:
            n = classify_paragraph(raw)  # raises on relevant-but-unreadable
            if n is not None:
                notices.append(n)
        if section["residual_relevant"]:
            raise Refused(
                f"security notes: exploit-related text outside a paragraph under {section['title']!r}; refusing")
        if section["date"] is None:
            if notices:
                raise Refused(
                    f"security notes: exploited notice under an undated or unfamiliar heading "
                    f"{section['title']!r} ({section['level']}); refusing")
            continue
        if notices:
            newest = (section, notices)
            break
    if newest is None:
        raise Refused("security notes: no exploited desktop notice found anywhere; page shape changed")
    section, notices = newest
    if section["date"] > today + datetime.timedelta(days=FUTURE_DATE_TOLERANCE_DAYS):
        raise Refused(f"security notes: newest exploited notice is dated {section['date']} (today {today}); refusing")
    stable = {v for n in notices for v in n["stable"]}
    extended = {v for n in notices for v in n["extended"]}
    cves = sorted({c for n in notices for c in n["cves"]})
    if len(stable) != 1:
        if not stable and extended:
            raise Refused(
                f"security notes ({section['title']}): newest exploited notice names only Extended Stable "
                f"{[join4(v) for v in extended]}; the WebView2 runtime follows Stable, refusing")
        raise Refused(
            f"security notes ({section['title']}): newest exploited notice names {len(stable)} Stable builds "
            f"{[join4(v) for v in sorted(stable)]}; refusing ambiguity")
    version = next(iter(stable))
    if extended and any(v != version for v in extended):
        raise Refused(
            f"security notes ({section['title']}): {cves} associated with Stable {join4(version)} and "
            f"Extended Stable {[join4(v) for v in sorted(extended)]}; refusing ambiguity")
    # The SELECTED CVE(s) must not be associated with another desktop build
    # anywhere else on the page. Other CVEs' branches are history.
    for other in sections:
        if other is section:
            continue
        for raw in other["paragraphs"]:
            text = strip_tags(raw)
            if not any(c in norm_cve(text) for c in cves):
                continue
            if not EXPLOIT_RE.search(text):
                continue
            builds = {parse4(v) for v in STABLE_CLAUSE_RE.findall(text) + EXTENDED_CLAUSE_RE.findall(text)}
            builds.discard(None)
            builds.discard(version)
            if builds:
                raise Refused(
                    f"security notes: {cves} also associated with {[join4(v) for v in sorted(builds)]} "
                    f"({other['title']}); refusing ambiguity")
    return {"version": version, "cves": cves, "section": section["title"],
            "date": section["date"].isoformat(), "text": notices[0]["text"]}


# --- the catalog parser -----------------------------------------------------

ROW_RE = re.compile(r'<tr\s+id="([0-9a-f-]{36})_R\d+"[^>]*>(.*?)</tr>', re.S)
CELL_RE = re.compile(r"<td\b[^>]*>(.*?)</td>", re.S)
SIZE_RE = re.compile(r'id="([0-9a-f-]{36})_originalSize"[^>]*>\s*(\d+)\s*<')
X64_TITLE_RE = re.compile(
    r"^Microsoft Edge-WebView2 Runtime Version (\d+) Update for x64 based Editions \(Build (\d+\.\d+\.\d+\.\d+)\)$")


def parse_catalog_date(text):
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", text.strip())
    if not m:
        return None
    try:
        return datetime.date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
    except ValueError:
        return None


def corroborate_catalog(page, version, today):
    """The x64 WebView2 Runtime row for EXACTLY this build: matching major
    and build in the title, product Microsoft Edge, classification Updates,
    a valid non-future date, and a positive integer size in the SAME row.
    x86 and ARM64 rows are not evidence for x64; ordinary Edge rows are not
    evidence for WebView2."""
    if 'id="ctl00_catalogBody_updateMatches"' not in page:
        raise Refused("catalog: no results table; page shape changed or search failed")
    matches = []
    for guid, row in ROW_RE.findall(page):
        cells = [strip_tags(c).strip() for c in CELL_RE.findall(row)]
        if len(cells) < 7:
            continue
        title = re.sub(r"\s+", " ", cells[1]).strip()
        m = X64_TITLE_RE.match(title)
        if not m:
            continue
        major, build = m.group(1), parse4(m.group(2))
        if build != version:
            continue
        if int(major) != version[0]:
            raise Refused(f"catalog: title major {major} disagrees with build {join4(version)}")
        product, classification = cells[2].strip(), cells[3].strip()
        if product != "Microsoft Edge" or classification != "Updates":
            raise Refused(f"catalog: x64 row has product {product!r} classification {classification!r}")
        date = parse_catalog_date(cells[4])
        if date is None:
            raise Refused(f"catalog: x64 row date {cells[4]!r} is not M/D/YYYY")
        if date > today + datetime.timedelta(days=FUTURE_DATE_TOLERANCE_DAYS):
            raise Refused(f"catalog: x64 row date {date} is in the future (today {today})")
        sizes = [(g, s) for g, s in SIZE_RE.findall(row) if g == guid]
        if len(sizes) != 1 or not sizes[0][1].isdigit() or int(sizes[0][1]) <= 0:
            raise Refused(f"catalog: x64 row {guid} has no positive originalSize of its own")
        matches.append({"guid": guid, "title": title, "date": date.isoformat(), "size": int(sizes[0][1])})
    if len(matches) != 1:
        raise Refused(
            f"catalog: expected exactly one x64 WebView2 Runtime row for {join4(version)}, found {len(matches)}")
    return matches[0]


# --- state ------------------------------------------------------------------

def atomic_write(path, data, mode=0o644):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".advisory-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_json(path):
    """The parsed document, or None when absent; raises ConfigError when the
    file exists but is not JSON."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ConfigError(f"{path}: {e}")
    try:
        return json.loads(raw)
    except ValueError as e:
        raise ConfigError(f"{path}: not JSON ({e})")


def load_last_good(state_dir):
    """last-good.json as a dict with a four-field floor, None when absent.
    Any other shape is a configuration error: a person must look, and
    nothing is published on top of state this run cannot read."""
    path = os.path.join(state_dir, "last-good.json")
    doc = load_json(path)
    if doc is None:
        return None
    if not isinstance(doc, dict) or parse4(doc.get("floor")) is None:
        raise ConfigError(f"{path}: malformed last-good record (expected an object with a four-field floor)")
    return doc


def served_publication(publish_root, signer, public_key, baseline, now):
    """What is served at <publish-root>/v1/engine-advisory.json:
    ("absent", None), ("invalid", reason), or ("valid", floor). Valid means
    the browser's own verifier accepts it under the configured verifying key
    and the compiled baseline's bounds; without a signer and key only the
    shape is checked and the result is at best "unverified"."""
    if not publish_root:
        return "absent", None
    path = os.path.join(publish_root, "v1", "engine-advisory.json")
    if not os.path.isfile(path):
        return "absent", None
    try:
        doc = load_json(path)
        payload = json.loads(doc.get("payload", "")) if isinstance(doc, dict) else None
        floor = parse4(payload.get("floor")) if isinstance(payload, dict) and payload.get("engine") == "webview2" else None
    except (ConfigError, ValueError, AttributeError):
        floor = None
    if floor is None:
        return "invalid", f"{path}: not an advisory envelope this monitor can read"
    if signer and public_key:
        proc = subprocess.run(
            [signer, "verify-advisory", path, public_key, "--baseline", join4(baseline), "--now", str(now)],
            capture_output=True, timeout=60)
        if proc.returncode != 0:
            return "invalid", f"{path}: {proc.stderr.decode('utf-8', 'replace').strip()[-300:]}"
        return "valid", floor
    return "unverified", floor


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def keep_evidence(evidence_dir, stamp, name, data):
    os.makedirs(evidence_dir, exist_ok=True)
    atomic_write(os.path.join(evidence_dir, f"{stamp}-{name}"), data, 0o600)
    files = sorted(f for f in os.listdir(evidence_dir) if f.endswith(name))
    for old in files[:-KEEP_EVIDENCE]:
        try:
            os.unlink(os.path.join(evidence_dir, old))
        except OSError:
            pass


# --- the run ----------------------------------------------------------------

def run(args, fetch_notes, fetch_catalog, log=print):
    """The whole check. Returns (exit_code, status_dict). `fetch_*` are
    injected so fixtures and transport failures are both testable. Every
    path, including an internal error, writes status.json."""
    now = args.now
    today = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).date()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    status = {"generated_at_unix": now, "generated_at": stamp, "outcome": None, "reason": None,
              "candidate": None, "catalog": None, "sources": {}, "published": None,
              "last_good": None, "served": None, "baseline": join4(args.baseline),
              "dry_run": bool(args.dry_run)}
    state_dir, evidence_dir = args.state_dir, os.path.join(args.state_dir, "evidence")

    def finish(code, outcome, reason=None):
        status["outcome"], status["reason"], status["exit_code"] = outcome, reason, code
        atomic_write(os.path.join(state_dir, "status.json"), (json.dumps(status, indent=2, sort_keys=True) + "\n").encode())
        log(f"engine-advisory: {outcome}" + (f": {reason}" if reason else ""))
        return code, status

    try:
        return _run(args, fetch_notes, fetch_catalog, status, finish, evidence_dir, now, today, stamp)
    except ConfigError as e:
        return finish(EXIT_CONFIG, "config-error", str(e))
    except Exception as e:  # noqa: BLE001 -- the status file is the report
        return finish(EXIT_CONFIG, "internal-error", f"{e.__class__.__name__}: {e}\n" + traceback.format_exc()[-1200:])


def _run(args, fetch_notes, fetch_catalog, status, finish, evidence_dir, now, today, stamp):
    state_dir = args.state_dir
    baseline = args.baseline
    last_good = load_last_good(state_dir)
    status["last_good"] = last_good
    served_state, served = served_publication(args.publish_root, args.signer, args.public_key, baseline, now)
    status["served"] = {"state": served_state, "floor": join4(served) if isinstance(served, tuple) else None,
                        "detail": served if isinstance(served, str) else None}
    # MONOTONIC authority: what has been published. The compiled baseline is
    # NOT part of it; it is the bound below.
    published_floors = [parse4(last_good["floor"])] if last_good else []
    if served_state in ("valid", "unverified"):
        published_floors.append(served)
    current = max(published_floors) if published_floors else None
    status["current_floor"] = join4(current) if current else None

    # 1. The security notes.
    try:
        notes = fetch_notes()
    except Fetch as e:
        return finish(EXIT_FETCH, "fetch-failed", str(e))
    status["sources"]["security_notes"] = {"url": SECURITY_NOTES_URL, "bytes": len(notes), "sha256": sha256_hex(notes)}
    try:
        page = notes.decode("utf-8")
        candidate = select_candidate(split_sections(page), today)
    except UnicodeDecodeError:
        keep_evidence(evidence_dir, stamp, "edge-security.html", notes)
        return finish(EXIT_REFUSED, "refused", "security notes: not utf-8")
    except Refused as e:
        keep_evidence(evidence_dir, stamp, "edge-security.html", notes)
        return finish(EXIT_REFUSED, "refused", str(e))
    status["candidate"] = {"version": join4(candidate["version"]), "cves": candidate["cves"],
                           "section": candidate["section"], "date": candidate["date"]}
    version = candidate["version"]

    # 2. The client's plausibility bound, against the COMPILED baseline only.
    if version[0] > baseline[0] + args.max_major_ahead:
        keep_evidence(evidence_dir, stamp, "edge-security.html", notes)
        return finish(EXIT_REFUSED, "refused",
                      f"candidate {join4(version)} is more than {args.max_major_ahead} majors past the compiled "
                      f"baseline {join4(baseline)}; clients would refuse it")

    # 3. Monotonic comparison, and the bootstrap decision.
    if current is not None and version < current:
        return finish(EXIT_OK, "unchanged-older-than-published",
                      f"newest exploited fix {join4(version)} is below the published floor {join4(current)}")
    if version < baseline:
        return finish(EXIT_OK, "unchanged-below-baseline",
                      f"newest exploited fix {join4(version)} is below the compiled baseline {join4(baseline)}")
    # A served file this run cannot verify (dry run without a signer and
    # key) counts as existing for the comparison; a live run must be able
    # to verify it before it may be replaced.
    served_counts = served_state == "valid" or (served_state == "unverified" and args.dry_run)
    # Bootstrap is a statement about the SERVED endpoint, so it needs a
    # publish root to look at. Without one, last-good is the only authority.
    bootstrap = bool(args.publish_root) and not served_counts and (current is None or version == current)
    if current is not None and version == current and not bootstrap:
        return finish(EXIT_OK, "unchanged", f"published floor {join4(current)} already equals the newest exploited fix")
    if bootstrap and served_state == "unverified":
        return finish(EXIT_CONFIG, "config-error",
                      f"served manifest at {args.publish_root} cannot be verified without --signer and --public-key; "
                      f"refusing to replace it")

    # 4. Corroborate availability in the catalog.
    try:
        catalog = fetch_catalog(version)
    except Fetch as e:
        return finish(EXIT_FETCH, "fetch-failed", str(e))
    status["sources"]["catalog"] = {"url": CATALOG_SEARCH_URL.format(version=join4(version)),
                                    "bytes": len(catalog), "sha256": sha256_hex(catalog)}
    try:
        row = corroborate_catalog(catalog.decode("utf-8", "replace"), version, today)
    except Refused as e:
        keep_evidence(evidence_dir, stamp, "edge-security.html", notes)
        keep_evidence(evidence_dir, stamp, "webview2-catalog.html", catalog)
        return finish(EXIT_REFUSED, "refused", str(e))
    status["catalog"] = row
    keep_evidence(evidence_dir, stamp, "edge-security.html", notes)
    keep_evidence(evidence_dir, stamp, "webview2-catalog.html", catalog)

    # 5. The payload the signer will see.
    payload = json.dumps({"engine": "webview2", "floor": join4(version), "published_at": now,
                          "reason": ", ".join(candidate["cves"])}, separators=(",", ":"))
    atomic_write(os.path.join(state_dir, "candidate-payload.json"), (payload + "\n").encode(), 0o600)
    action = "bootstrap" if bootstrap else "raise"
    if args.dry_run:
        if bootstrap and not args.publish_root:
            return finish(EXIT_OK, "would-raise",
                          f"{join4(current) if current else 'nothing published'} -> {join4(version)} for "
                          f"{candidate['cves']} (dry run; no publish root named, so bootstrap state is unknown)")
        return finish(EXIT_OK, f"would-{action}",
                      f"{join4(current) if current else 'nothing published'} -> {join4(version)} for "
                      f"{candidate['cves']} (dry run; nothing signed)")

    # 6. Sign with the ADVISORY key; the configured verifying key must be the
    # key's own, and the browser's verifier must accept the result under it
    # and under the compiled baseline's bounds.
    if not (args.key and args.signer and args.publish_root and args.public_key):
        return finish(EXIT_CONFIG, "config-error", "--key, --signer, --publish-root and --public-key are required to publish")
    try:
        with tempfile.TemporaryDirectory(dir=state_dir, prefix=".sign-") as work:
            payload_path = os.path.join(work, "payload.json")
            with open(payload_path, "wb") as fh:
                fh.write(payload.encode())
            proc = subprocess.run(
                [args.signer, "sign-advisory", args.key, payload_path, "--baseline", join4(baseline), "--now", str(now)],
                capture_output=True, timeout=60)
            if proc.returncode != 0:
                return finish(EXIT_SIGN, "sign-refused", proc.stderr.decode("utf-8", "replace").strip()[-400:])
            envelope = proc.stdout
            signed_by = re.search(r"\bkey ([0-9a-f]{64})\b", proc.stderr.decode("utf-8", "replace"))
            if not signed_by or signed_by.group(1) != args.public_key.lower():
                return finish(EXIT_CONFIG, "config-error",
                              "the signing key's verifying key does not match --public-key; refusing to publish "
                              "a document the configured key set would not verify")
            env_path = os.path.join(work, "envelope.json")
            with open(env_path, "wb") as fh:
                fh.write(envelope)
            ver = subprocess.run(
                [args.signer, "verify-advisory", env_path, args.public_key, "--baseline", join4(baseline), "--now", str(now)],
                capture_output=True, timeout=60)
            if ver.returncode != 0:
                return finish(EXIT_SIGN, "verify-refused", ver.stderr.decode("utf-8", "replace").strip()[-400:])
    except (OSError, subprocess.SubprocessError) as e:
        return finish(EXIT_SIGN, "sign-failed", f"{e.__class__.__name__}: {e}")

    # 7. Publish atomically, then record last-good.
    target = os.path.join(args.publish_root, "v1", "engine-advisory.json")
    try:
        if not os.path.isdir(os.path.dirname(target)):
            raise OSError(f"{os.path.dirname(target)} is not a directory")
        atomic_write(target, envelope, 0o644)
    except OSError as e:
        return finish(EXIT_PUBLISH, "publish-failed", f"{target}: {e}")
    record = {"floor": join4(version), "cves": candidate["cves"], "section": candidate["section"],
              "published_at": now, "envelope_sha256": sha256_hex(envelope), "catalog": row,
              "source_sha256": status["sources"]["security_notes"]["sha256"], "action": action}
    atomic_write(os.path.join(state_dir, "last-good.json"), (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
    status["published"] = {"path": target, "envelope_sha256": record["envelope_sha256"], "action": action}
    return finish(EXIT_OK, "published" if not bootstrap else "published-bootstrap",
                  f"{join4(current) if current else 'nothing published'} -> {join4(version)} for {candidate['cves']}")


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--baseline", required=True,
                    help="the WebView2 floor the shipped browser compiles in, a.b.c.d (platform::MIN_WEBVIEW2)")
    ap.add_argument("--publish-root", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--signer", default="")
    ap.add_argument("--public-key", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--fetch-from-dir", default="", help="read fixtures instead of HTTPS (tests)")
    ap.add_argument("--max-major-ahead", type=int, default=DEFAULT_MAX_MAJOR_AHEAD)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--now", type=int, default=None)
    args = ap.parse_args(argv)
    args.baseline = parse4(args.baseline)
    if args.baseline is None:
        ap.error("--baseline must be four decimal fields")
    if args.now is None:
        args.now = int(time.time())
    if not args.dry_run and not (args.key and args.signer and args.publish_root and args.public_key):
        ap.error("--key, --signer, --publish-root and --public-key are required unless --dry-run")
    if args.public_key and not re.fullmatch(r"[0-9a-fA-F]{64}", args.public_key):
        ap.error("--public-key must be 64 hex characters")
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        os.makedirs(args.state_dir, exist_ok=True)
    except OSError as e:
        print(f"engine-advisory: config-error: state dir {args.state_dir}: {e}", file=sys.stderr)
        return EXIT_CONFIG
    if args.key and not os.path.isfile(args.key):
        print(f"engine-advisory: config-error: no signing key at {args.key}", file=sys.stderr)
        return EXIT_CONFIG
    if args.key and (os.stat(args.key).st_mode & 0o777) != 0o600:
        print(f"engine-advisory: config-error: {args.key} is not mode 600", file=sys.stderr)
        return EXIT_CONFIG
    lock_fd = os.open(os.path.join(args.state_dir, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("engine-advisory: another run holds the lock; leaving it alone", file=sys.stderr)
        return EXIT_LOCKED
    try:
        if args.fetch_from_dir:
            def fetch_notes():
                p = os.path.join(args.fetch_from_dir, "edge-security.html")
                try:
                    with open(p, "rb") as fh:
                        return fh.read()
                except OSError as e:
                    raise Fetch(f"{p}: {e}")

            def fetch_catalog(version):
                p = os.path.join(args.fetch_from_dir, f"webview2-catalog-{join4(version)}.html")
                try:
                    with open(p, "rb") as fh:
                        return fh.read()
                except OSError as e:
                    raise Fetch(f"{p}: {e}")
        else:
            def fetch_notes():
                return http_get(SECURITY_NOTES_URL, SECURITY_NOTES_HOST, timeout=args.timeout)

            def fetch_catalog(version):
                return http_get(CATALOG_SEARCH_URL.format(version=join4(version)), CATALOG_HOST, timeout=args.timeout)
        code, _ = run(args, fetch_notes, fetch_catalog, log=lambda m: print(m, file=sys.stderr))
        return code
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
