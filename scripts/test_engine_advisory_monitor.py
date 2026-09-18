#!/usr/bin/env python3
"""Deterministic tests for scripts/engine-advisory-monitor.py.

Two fixture classes. REAL: the direct-origin captures under
fixtures/engine-advisory/real, whose sha256 is re-checked against
PROVENANCE.json so the test cannot drift from the capture it claims to be.
DERIVED: the same captures with one thing changed by string surgery, so each
negative case differs from the positive one in exactly the property under
test. No network: the monitor's fetches are injected, and the transport code
is exercised against a local HTTP server on 127.0.0.1.

The end-to-end signing test drives the REAL signer (patanyx-sign, built from
crates/update) with a throwaway key generated into scratch. Set PATANYX_SIGN
to the built example binary; without it that one test is skipped and says so.

Run: python3 scripts/test_engine_advisory_monitor.py
"""
import datetime
import hashlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "engine-advisory")
REAL = os.path.join(FIXTURES, "real")
# 11 September 2026 13:10 UTC: after the captured catalog date, before any
# future-date tolerance question.
NOW = 1789132200
SIGNER = os.environ.get("PATANYX_SIGN", "")


def load_monitor():
    spec = importlib.util.spec_from_file_location("monitor", os.path.join(HERE, "engine-advisory-monitor.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = load_monitor()


def real(name):
    with open(os.path.join(REAL, name), "rb") as fh:
        return fh.read()


NOTES = real("edge-security.html")
CATALOG = real("webview2-catalog-152.0.4191.66.html")
SEPT4 = ('<p>Microsoft released the latest <strong>Microsoft Edge for Stable (Version 152.0.4191.66)</strong> '
         'which incorporates the latest Security Updates of the Chromium project. The Chromium team reported that '
         '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-87491" data-linktype="external">'
         'CVE-2026-87491</a> has an exploit in the wild, and this update contains a fix for it. For more information, '
         'see the <a href="https://msrc.microsoft.com/update-guide" data-linktype="external">Security Update Guide</a>.</p>')
assert SEPT4 in NOTES.decode("utf-8"), "the September 4 paragraph must be present verbatim in the real capture"


class Args:
    """The subset of argparse output `run` reads."""

    def __init__(self, state_dir, baseline="152.0.4191.62", **kw):
        self.state_dir = state_dir
        self.baseline = M.parse4(baseline)
        self.publish_root = kw.get("publish_root", "")
        self.key = kw.get("key", "")
        self.signer = kw.get("signer", "")
        self.public_key = kw.get("public_key", "")
        self.dry_run = kw.get("dry_run", True)
        self.max_major_ahead = kw.get("max_major_ahead", M.DEFAULT_MAX_MAJOR_AHEAD)
        self.now = kw.get("now", NOW)


def run_with(state_dir, notes=NOTES, catalog=CATALOG, notes_exc=None, catalog_exc=None, **kw):
    def fetch_notes():
        if notes_exc:
            raise notes_exc
        return notes

    def fetch_catalog(version):
        if catalog_exc:
            raise catalog_exc
        if isinstance(catalog, dict):
            if version not in catalog:
                raise M.Fetch("no such catalog fixture")
            return catalog[version]
        return catalog

    logs = []
    code, status = M.run(Args(state_dir, **kw), fetch_notes, fetch_catalog, log=logs.append)
    return code, status, logs


def snapshot(d):
    """Every file under d with its bytes, for byte-level preservation checks."""
    out = {}
    for root, _, files in os.walk(d):
        for f in files:
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, d)] = fh.read()
    return out


def notes_with_new_section(paragraph_html, title="September 10, 2026", anchor="september-10-2026"):
    """The real notes with a NEW newest section inserted before September 8."""
    marker = '<h2 id="september-8-2026">'
    text = NOTES.decode("utf-8")
    assert marker in text
    return text.replace(marker, f'<h2 id="{anchor}">{title}</h2>\n{paragraph_html}\n{marker}', 1).encode("utf-8")


def catalog_without_x64():
    text = CATALOG.decode("utf-8")
    start = text.index('<tr id="373c4ff4-ad77-40b3-a1eb-ec266425b1ae_R1"')
    end = text.index("</tr>", start) + len("</tr>")
    out = text[:start] + text[end:]
    assert "x64 based Editions" not in out
    return out.encode("utf-8")


def catalog_edit(old, new, count=1):
    text = CATALOG.decode("utf-8")
    assert old in text, old
    return text.replace(old, new, count).encode("utf-8")


class Provenance(unittest.TestCase):
    def test_real_fixtures_match_their_recorded_capture(self):
        with open(os.path.join(FIXTURES, "PROVENANCE.json")) as fh:
            prov = json.load(fh)
        for f in prov["files"]:
            data = real(f["file"])
            self.assertEqual(len(data), f["bytes"], f["file"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), f["sha256"], f["file"])
            self.assertTrue(f["url"].startswith("https://"))
        self.assertEqual({f["url"].split("/")[2] for f in prov["files"]},
                         {M.SECURITY_NOTES_HOST, M.CATALOG_HOST})

    def test_the_ms_date_metadata_is_old_and_is_not_consulted(self):
        # Editorial metadata months behind the content. The monitor must not
        # treat it as freshness; the source's bytes are the freshness.
        self.assertIn(b'name="ms.date" content="2026-06-12', NOTES)
        with open(os.path.join(HERE, "engine-advisory-monitor.py")) as fh:
            src = fh.read()
        self.assertNotIn("ms.date", src.split('"""', 2)[2], "ms.date must not appear in the code")


class Positive(unittest.TestCase):
    def test_real_pair_selects_66_for_cve_2026_87491_and_would_raise_from_62(self):
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d)
            self.assertEqual(code, 0)
            self.assertEqual(status["outcome"], "would-raise")
            self.assertEqual(status["candidate"]["version"], "152.0.4191.66")
            self.assertEqual(status["candidate"]["cves"], ["CVE-2026-87491"])
            self.assertEqual(status["candidate"]["section"], "September 4, 2026")
            row = status["catalog"]
            self.assertEqual(row["size"], 262787408)
            self.assertEqual(row["date"], "2026-09-04")
            self.assertIn("x64 based Editions (Build 152.0.4191.66)", row["title"])
            with open(os.path.join(d, "candidate-payload.json")) as fh:
                payload = json.load(fh)
            self.assertEqual(payload, {"engine": "webview2", "floor": "152.0.4191.66",
                                       "published_at": NOW, "reason": "CVE-2026-87491"})
            # Evidence kept, status written, nothing published, no key needed.
            self.assertTrue(os.path.isfile(os.path.join(d, "status.json")))
            self.assertEqual(len(os.listdir(os.path.join(d, "evidence"))), 2)
            self.assertFalse(os.path.exists(os.path.join(d, "last-good.json")))

    def test_the_edge_specific_cve_list_item_is_not_the_selected_fix(self):
        with tempfile.TemporaryDirectory() as d:
            _, status, _ = run_with(d)
            self.assertNotIn("CVE-2026-85892", status["candidate"]["cves"])

    def test_identical_source_at_the_published_floor_is_a_healthy_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "last-good.json"), "w") as fh:
                json.dump({"floor": "152.0.4191.66", "cves": ["CVE-2026-87491"], "published_at": NOW - 3600}, fh)
            code, status, _ = run_with(d, baseline="152.0.4191.66")
            self.assertEqual(code, 0)
            self.assertEqual(status["outcome"], "unchanged")
            self.assertFalse(os.path.exists(os.path.join(d, "candidate-payload.json")))
            # Again, same bytes: still a no-op, the clock notwithstanding.
            code, status, _ = run_with(d, baseline="152.0.4191.66", now=NOW + 30 * 86400)
            self.assertEqual((code, status["outcome"]), (0, "unchanged"))

    def test_with_nothing_published_the_baseline_candidate_is_a_bootstrap(self):
        # First activation: baseline .66, source .66, nothing served. A dry
        # run with a publish root says so; without one it cannot know.
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            code, status, _ = run_with(d, baseline="152.0.4191.66", publish_root=root)
            self.assertEqual((code, status["outcome"]), (0, "would-bootstrap"), status["reason"])
            self.assertIsNotNone(status["catalog"], "bootstrap is corroborated like a raise")
            self.assertEqual(status["served"]["state"], "absent")
            code, status, _ = run_with(d, baseline="152.0.4191.66")
            self.assertEqual((code, status["outcome"]), (0, "would-raise"))
            # A served file the dry run cannot verify counts as existing.
            with open(os.path.join(root, "v1", "engine-advisory.json"), "w") as fh:
                json.dump({"v": 1, "payload": json.dumps({"engine": "webview2", "floor": "152.0.4191.66", "published_at": 1}), "sig": "00"}, fh)
            code, status, _ = run_with(d, baseline="152.0.4191.66", publish_root=root)
            self.assertEqual((code, status["outcome"]), (0, "unchanged"))
            self.assertEqual(status["served"]["state"], "unverified")

    def test_older_source_content_never_rolls_back_a_higher_published_floor(self):
        with tempfile.TemporaryDirectory() as d:
            last_good = {"floor": "152.0.4191.70", "cves": ["CVE-TEST"], "published_at": NOW - 100}
            with open(os.path.join(d, "last-good.json"), "w") as fh:
                json.dump(last_good, fh)
            before = snapshot(d)
            code, status, _ = run_with(d, baseline="152.0.4191.62")
            self.assertEqual(code, 0)
            self.assertEqual(status["outcome"], "unchanged-older-than-published")
            self.assertEqual(status["current_floor"], "152.0.4191.70")
            self.assertEqual(snapshot(d)["last-good.json"], before["last-good.json"])

    def test_newer_android_section_is_ignored_and_does_not_veto(self):
        # The real capture's newest section IS an Android release (Sept 8)
        # above the Sept 4 Stable fix; the positive test already passes
        # through it. Add an Android EXPLOIT notice on top: still ignored.
        p = ('<p>Microsoft released the latest <strong>Microsoft Edge for Android (Version 153.0.4300.20)</strong> '
             'which incorporates the latest Security Updates of the Chromium project. The Chromium team reported that '
             '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99001">CVE-2026-99001</a> has an '
             'exploit in the wild, and this update contains a fix for it.</p>')
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d, notes=notes_with_new_section(p))
            self.assertEqual((code, status["outcome"]), (0, "would-raise"))
            self.assertEqual(status["candidate"]["version"], "152.0.4191.66")

    def test_historical_parallel_branches_do_not_veto_the_current_candidate(self):
        # CVE-2026-2441 sits on 145.0.3800.58 Stable (Feb 14) and
        # 144.0.3719.130 Extended Stable (Feb 17) in the real capture.
        text = NOTES.decode("utf-8")
        self.assertIn("144.0.3719.130", text)
        self.assertIn("145.0.3800.58", text)
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d)
            self.assertEqual((code, status["outcome"]), (0, "would-raise"))


class NotesRefusals(unittest.TestCase):
    def assert_refused(self, notes, needle, catalog=CATALOG):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "last-good.json"), "w") as fh:
                json.dump({"floor": "152.0.4191.62", "cves": []}, fh)
            before = snapshot(d)
            code, status, _ = run_with(d, notes=notes, catalog=catalog)
            self.assertEqual(code, 3, status["reason"])
            self.assertEqual(status["outcome"], "refused")
            self.assertIn(needle, status["reason"])
            after = snapshot(d)
            self.assertEqual(after["last-good.json"], before["last-good.json"])
            self.assertFalse(os.path.exists(os.path.join(d, "candidate-payload.json")))
            self.assertTrue(any(k.endswith("edge-security.html") for k in after), "raw evidence kept on refusal")
            return status

    def test_unfamiliar_relevant_newer_desktop_notice_refuses_instead_of_selecting_the_older_match(self):
        p = ('<p>Microsoft has issued Edge Stable build 153.0.4300.33 to address CVE-2026-99002, which is being '
             'exploited; see the Security Update Guide.</p>')
        status = self.assert_refused(notes_with_new_section(p), "no recognised Stable clause")
        self.assertIsNone(status["candidate"])

    def test_same_cve_on_two_maintained_branches_is_ambiguous(self):
        p = ('<p>Microsoft released the latest <strong>Microsoft Edge Stable Channel (Version 153.0.4300.40) and '
             'Extended Stable Channel (Version 152.0.4191.90)</strong> which incorporates the latest Security Updates '
             'of the Chromium project. The Chromium team reported that '
             '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99003">CVE-2026-99003</a> has an '
             'exploit in the wild, and this update contains a fix for it.</p>')
        self.assert_refused(notes_with_new_section(p), "refusing ambiguity")

    def test_same_cve_across_two_sections_is_ambiguous(self):
        newer = ('<p>Microsoft released the latest <strong>Microsoft Edge Extended Stable Channel (Version 152.0.4191.95)'
                 '</strong> which incorporates the latest Security Updates of the Chromium project. The Chromium team '
                 'reported that <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99004">'
                 'CVE-2026-99004</a> has an exploit in the wild, and this update contains a fix for it.</p>')
        stable = ('<p>Microsoft released the latest <strong>Microsoft Edge Stable Channel (Version 153.0.4300.44)'
                  '</strong> which incorporates the latest Security Updates of the Chromium project. The Chromium team '
                  'reported that <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99004">'
                  'CVE-2026-99004</a> has an exploit in the wild, and this update contains a fix for it.</p>')
        # Newest section: Extended only -> refused outright (the runtime
        # follows Stable). Reorder: Stable newest, Extended second -> the
        # selected CVE has two builds -> ambiguous.
        self.assert_refused(notes_with_new_section(newer), "only Extended Stable")
        two = notes_with_new_section(stable, "September 11, 2026", "september-11-2026")
        two = two.replace(b'<h2 id="september-8-2026">', ('<h2 id="september-10-2026">September 10, 2026</h2>\n' + newer + '\n<h2 id="september-8-2026">').encode(), 1)
        self.assert_refused(two, "also associated with")

    def test_version_and_exploit_statement_split_across_paragraphs_is_refused(self):
        p = ('<p>Microsoft released the latest <strong>Microsoft Edge Stable Channel (Version 153.0.4300.50)</strong> '
             'which incorporates the latest Security Updates of the Chromium project.</p>'
             '<p>The Chromium team reported that <a href="https://msrc.microsoft.com/update-guide/vulnerability/'
             'CVE-2026-99005">CVE-2026-99005</a> has an exploit in the wild, and this update contains a fix for it.</p>')
        self.assert_refused(notes_with_new_section(p), "no recognised Stable clause")

    def test_the_recurring_commentary_paragraph_is_ignored_not_refused(self):
        # Microsoft's "enhanced security mode mitigates ..." paragraph sits
        # beside real notices throughout 2023-2024. Beside a valid newer
        # notice it must neither qualify nor refuse.
        notice = SEPT4.replace("152.0.4191.66", "153.0.4300.90").replace("CVE-2026-87491", "CVE-2026-99011")
        commentary = ("<p>It's worth highlighting that Microsoft Edge's enhanced security mode feature mitigates the "
                      "vulnerability described in CVE-2026-99011. You can opt-in into this security feature and have "
                      "peace of mind that Microsoft Edge is protecting you against this exploit.</p>")
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d, notes=notes_with_new_section(notice + commentary),
                                       catalog={M.parse4("153.0.4300.90"): CATALOG.replace(b"152.0.4191.66", b"153.0.4300.90").replace(b"Runtime Version 152", b"Runtime Version 153")})
            self.assertEqual((code, status["outcome"]), (0, "would-raise"), status["reason"])
            self.assertEqual(status["candidate"]["version"], "153.0.4300.90")

    def test_negated_fix_statement_is_refused(self):
        p = SEPT4.replace("this update contains a fix for it", "this update does not contain a fix for it")
        p = p.replace("152.0.4191.66", "153.0.4300.60").replace("CVE-2026-87491", "CVE-2026-99006")
        self.assert_refused(notes_with_new_section(p), "exploited-and-fixed sentence")

    def test_cve_link_text_and_target_mismatch_is_refused(self):
        p = SEPT4.replace("152.0.4191.66", "153.0.4300.61")
        p = p.replace('vulnerability/CVE-2026-87491"', 'vulnerability/CVE-2026-11111"')
        self.assert_refused(notes_with_new_section(p), "does not match its target")

    def test_beta_channel_notice_is_refused_not_selected(self):
        p = SEPT4.replace("Microsoft Edge for Stable (Version 152.0.4191.66)", "Microsoft Edge Beta Stable (Version 153.0.4300.70)")
        self.assert_refused(notes_with_new_section(p), "non-Stable")

    def test_no_exploit_notice_anywhere_or_wrong_page_shape_is_refused(self):
        self.assert_refused(b"<html><body><p>Sign in to continue</p></body></html>", "page shape changed")
        stripped = NOTES
        for phrase in (b"has an exploit in the wild", b"have an exploit in the wild", b"having an exploit in the wild",
                       b"an exploit in the wild", b"this exploit"):
            stripped = stripped.replace(phrase, b"a problem")
        self.assert_refused(stripped, "no exploited desktop notice")

    def test_sections_out_of_order_are_refused(self):
        p = SEPT4.replace("152.0.4191.66", "153.0.4300.80")
        self.assert_refused(notes_with_new_section(p, "January 1, 2020", "january-1-2020-x"), "not newest-first")

    def test_bad_version_tokens_are_refused(self):
        for bad in ["153.0.4300", "153.0.4300.80.1", "153.0.4300.beta", "-153.0.4300.80"]:
            p = SEPT4.replace("152.0.4191.66", bad)
            with tempfile.TemporaryDirectory() as d:
                code, status, _ = run_with(d, notes=notes_with_new_section(p))
                # Either refused outright or, for a token the regex cannot
                # even see as a version, the clause is unrecognised: never a
                # would-raise past .66 on a malformed token.
                self.assertNotEqual(status.get("candidate", {}) and status["candidate"]["version"], bad)
                self.assertIn(code, (0, 3))
                if code == 0:
                    self.assertEqual(status["candidate"]["version"], "152.0.4191.66")

    def test_a_candidate_too_many_majors_ahead_is_refused(self):
        p = SEPT4.replace("152.0.4191.66", "999.0.0.1").replace("CVE-2026-87491", "CVE-2026-99009")
        self.assert_refused(notes_with_new_section(p), "majors past")


class CatalogRefusals(unittest.TestCase):
    def assert_refused(self, catalog, needle):
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d, catalog=catalog)
            self.assertEqual(code, 3, status["reason"])
            self.assertIn(needle, status["reason"])
            self.assertEqual(status["candidate"]["version"], "152.0.4191.66", "the notes half still parsed")
            self.assertIsNone(status["catalog"])
            self.assertFalse(os.path.exists(os.path.join(d, "candidate-payload.json")))
            self.assertTrue(any(f.endswith("webview2-catalog.html") for f in os.listdir(os.path.join(d, "evidence"))))

    def test_missing_x64_row_is_not_borrowed_from_x86_or_arm64(self):
        self.assert_refused(catalog_without_x64(), "expected exactly one x64")

    def test_ordinary_edge_row_cannot_stand_in_for_webview2(self):
        self.assert_refused(catalog_edit("Microsoft Edge-WebView2 Runtime Version 152 Update for x64",
                                         "Microsoft Edge-Stable Channel Version 152 Update for x64"), "expected exactly one x64")

    def test_build_mismatch_in_the_x64_title_is_refused(self):
        self.assert_refused(catalog_edit("x64 based Editions (Build 152.0.4191.66)", "x64 based Editions (Build 152.0.4191.62)"),
                            "expected exactly one x64")
        self.assert_refused(catalog_edit("Runtime Version 152 Update for x64", "Runtime Version 153 Update for x64"),
                            "disagrees with build")

    def test_five_components_or_prerelease_suffix_in_title_is_refused(self):
        self.assert_refused(catalog_edit("x64 based Editions (Build 152.0.4191.66)", "x64 based Editions (Build 152.0.4191.66.1)"),
                            "expected exactly one x64")
        self.assert_refused(catalog_edit("x64 based Editions (Build 152.0.4191.66)", "x64 based Editions (Build 152.0.4191.66-beta)"),
                            "expected exactly one x64")

    def test_size_must_be_positive_numeric_and_belong_to_the_row(self):
        self.assert_refused(catalog_edit('373c4ff4-ad77-40b3-a1eb-ec266425b1ae_originalSize">262787408<',
                                         '373c4ff4-ad77-40b3-a1eb-ec266425b1ae_originalSize">0<'), "positive originalSize")
        self.assert_refused(catalog_edit('373c4ff4-ad77-40b3-a1eb-ec266425b1ae_originalSize">262787408<',
                                         '373c4ff4-ad77-40b3-a1eb-ec266425b1ae_originalSize">lots<'), "positive originalSize")
        # Size span re-labelled with another row's GUID: not this row's.
        self.assert_refused(catalog_edit('373c4ff4-ad77-40b3-a1eb-ec266425b1ae_originalSize"',
                                         '14b4f8fc-48d4-48f2-98bd-804e8f130e06_originalSize"'), "positive originalSize")

    def test_future_or_invalid_date_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            # A clock a month before the notes' own date: the notes check
            # fires first, and that is a refusal too.
            code, status, _ = run_with(d, now=NOW - 30 * 86400)
            self.assertEqual(code, 3)
            self.assertIn("is dated 2026-09-04", status["reason"])
        # The catalog's own date in the future while the notes are fine.
        self.assert_refused(catalog_edit("9/4/2026", "12/30/2026", 3), "in the future")
        row_date = CATALOG.count(b"9/4/2026")
        self.assertGreaterEqual(row_date, 3)
        text = CATALOG.decode("utf-8")
        start = text.index('<tr id="373c4ff4-ad77-40b3-a1eb-ec266425b1ae_R1"')
        end = text.index("</tr>", start)
        row = text[start:end].replace("9/4/2026", "13/45/2026", 1)
        self.assert_refused((text[:start] + row + text[end:]).encode(), "not M/D/YYYY")

    def test_login_or_error_page_instead_of_results_is_refused(self):
        self.assert_refused(b"<html><body>Sign in</body></html>", "no results table")


class Transport(unittest.TestCase):
    """The bounded fetch, against a local server. Every failure is a Fetch
    (exit 2) and preserves state; a redirect is refused, not followed."""

    class Handler(http.server.BaseHTTPRequestHandler):
        script = {}

        def log_message(self, *a):
            pass

        def do_GET(self):
            kind = self.script.get(self.path, "ok")
            if kind == "ok":
                body = b"<html>fine</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif kind == "json":
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif kind == "big":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                chunk = b"x" * 65536
                try:
                    for _ in range(40):
                        self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client stopped reading at its cap
            elif kind == "redirect":
                self.send_response(302)
                self.send_header("Location", "https://evil.example/notes")
                self.end_headers()
            elif kind == "slow":
                time.sleep(3)
            elif kind == "error":
                self.send_error(503)

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), cls.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.host = f"127.0.0.1:{cls.server.server_address[1]}"
        cls.Handler.script = {"/json": "json", "/big": "big", "/redirect": "redirect", "/slow": "slow", "/error": "error"}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def get(self, path, **kw):
        return M.http_get(self.base + path, self.host, allow_http=True, timeout=kw.get("timeout", 5), cap=kw.get("cap", M.MAX_SOURCE_BYTES))

    def test_plain_ok(self):
        self.assertEqual(self.get("/ok"), b"<html>fine</html>")

    def test_https_is_required_by_default_and_the_host_is_pinned(self):
        with self.assertRaises(M.Fetch):
            M.http_get(self.base + "/ok", self.host)
        with self.assertRaises(M.Fetch):
            M.http_get(self.base + "/ok", "learn.microsoft.com", allow_http=True)
        self.assertEqual(M.SECURITY_NOTES_URL.split("/")[2], M.SECURITY_NOTES_HOST)
        self.assertEqual(M.CATALOG_SEARCH_URL.split("/")[2], M.CATALOG_HOST)

    def test_wrong_media_type_oversize_redirect_timeout_and_error_are_fetch_failures(self):
        with self.assertRaises(M.Fetch):
            self.get("/json")
        with self.assertRaises(M.Fetch):
            self.get("/big", cap=1_000_000)
        with self.assertRaises(M.Fetch):
            self.get("/redirect")
        with self.assertRaises(M.Fetch):
            self.get("/slow", timeout=0.5)
        with self.assertRaises(M.Fetch):
            self.get("/error")

    def test_a_fetch_failure_is_exit_2_and_preserves_every_byte_of_state(self):
        with tempfile.TemporaryDirectory() as d:
            run_with(d, baseline="152.0.4191.62")  # a would-raise, to have state
            before = snapshot(d)
            code, status, _ = run_with(d, notes_exc=M.Fetch("timed out"))
            self.assertEqual((code, status["outcome"]), (2, "fetch-failed"))
            after = snapshot(d)
            for k, v in before.items():
                if k != "status.json":
                    self.assertEqual(after[k], v, k)
            code, status, _ = run_with(d, catalog_exc=M.Fetch("503"))
            self.assertEqual((code, status["outcome"]), (2, "fetch-failed"))
            self.assertEqual(status["candidate"]["version"], "152.0.4191.66")


class Publishing(unittest.TestCase):
    """The signing and publishing half, with the REAL signer when available
    and a fake one for the refusal paths."""

    FAKE_PUB = "ab" * 32

    def fake_signer(self, d, behaviour):
        path = os.path.join(d, "fake-sign.sh")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n")
            if behaviour == "refuse":
                fh.write("echo 'patanyx-sign: REFUSING TO EMIT: test' >&2; exit 1\n")
            else:
                fh.write('case "$1" in sign-advisory) echo "verified: engine advisory webview2 x (y) published_at 1 key %s" >&2; '
                         'printf \'{"v":1,"payload":"x","sig":"00"}\';; verify-advisory) exit 0;; esac\n' % self.FAKE_PUB)
        os.chmod(path, 0o700)
        return path

    def key_file(self, d):
        path = os.path.join(d, "test.key")
        with open(path, "w") as fh:
            fh.write("11" * 32)
        os.chmod(path, 0o600)
        return path

    def test_missing_key_or_signer_is_a_config_error_not_a_publish(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            code, status, _ = run_with(d, dry_run=False, publish_root=root)
            self.assertEqual((code, status["outcome"]), (7, "config-error"))
            self.assertEqual(os.listdir(os.path.join(root, "v1")), [])

    def test_a_signer_refusal_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            code, status, _ = run_with(d, dry_run=False, publish_root=root, key=self.key_file(d),
                                       signer=self.fake_signer(d, "refuse"), public_key=self.FAKE_PUB)
            self.assertEqual((code, status["outcome"]), (5, "sign-refused"))
            self.assertIn("REFUSING TO EMIT", status["reason"])
            self.assertEqual(os.listdir(os.path.join(root, "v1")), [])
            self.assertFalse(os.path.exists(os.path.join(d, "last-good.json")))

    def test_an_unwritable_publish_root_is_exit_6_with_last_good_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root")
            os.makedirs(root)
            with open(os.path.join(root, "v1"), "w") as fh:
                fh.write("a file where the directory should be")
            with open(os.path.join(d, "last-good.json"), "w") as fh:
                json.dump({"floor": "152.0.4191.62", "cves": []}, fh)
            before = snapshot(d)
            code, status, _ = run_with(d, dry_run=False, publish_root=root, key=self.key_file(d),
                                       signer=self.fake_signer(d, "ok"), public_key=self.FAKE_PUB)
            self.assertEqual((code, status["outcome"]), (6, "publish-failed"))
            self.assertEqual(snapshot(d)["last-good.json"], before["last-good.json"])
            with open(os.path.join(root, "v1")) as fh:
                self.assertEqual(fh.read(), "a file where the directory should be")

    def keygen(self, d, name):
        key = os.path.join(d, name)
        gen = subprocess.run([SIGNER, "keygen", key, "advisory"], capture_output=True, text=True)
        self.assertEqual(gen.returncode, 0, gen.stderr)
        pub = [l.strip() for l in gen.stdout.splitlines() if l.strip().startswith('&["')][0][3:-3]
        self.assertEqual(len(pub), 64)
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        return key, pub

    def read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def notes_for(self, version, cve):
        p = SEPT4.replace("152.0.4191.66", version).replace("CVE-2026-87491", cve)
        return notes_with_new_section(p)

    def catalog_for(self, version):
        major = version.split(".")[0]
        return {M.parse4(version): CATALOG.replace(b"152.0.4191.66", version.encode()).replace(b"Runtime Version 152", b"Runtime Version " + major.encode())}

    @unittest.skipUnless(SIGNER and os.access(SIGNER, os.X_OK), "PATANYX_SIGN not set to a built patanyx-sign")
    def test_bootstrap_then_raise_with_the_real_signer_and_a_throwaway_key(self):
        with tempfile.TemporaryDirectory() as d:
            key, pub = self.keygen(d, "throwaway-advisory.key")
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            state = os.path.join(d, "state")
            live = dict(dry_run=False, publish_root=root, key=key, signer=SIGNER, public_key=pub, baseline="152.0.4191.66")
            published = os.path.join(root, "v1", "engine-advisory.json")

            # BOOTSTRAP: baseline .66, source .66, nothing served -> published.
            code, status, _ = run_with(state, **live)
            self.assertEqual((code, status["outcome"]), (0, "published-bootstrap"), status["reason"])
            self.assertTrue(os.path.isfile(published))
            self.assertEqual(os.stat(published).st_mode & 0o777, 0o644)
            env = json.loads(self.read(published))
            self.assertEqual(json.loads(env["payload"]), {"engine": "webview2", "floor": "152.0.4191.66",
                                                          "published_at": NOW, "reason": "CVE-2026-87491"})
            ver = subprocess.run([SIGNER, "verify-advisory", published, pub, "--baseline", "152.0.4191.66", "--now", str(NOW)],
                                 capture_output=True, text=True)
            self.assertEqual(ver.returncode, 0, ver.stderr)
            self.assertIn("client bounds", ver.stdout)
            self.assertNotEqual(subprocess.run([SIGNER, "verify-advisory", published, "22" * 32], capture_output=True).returncode, 0)
            with open(os.path.join(state, "last-good.json")) as fh:
                last_good = json.load(fh)
            self.assertEqual((last_good["floor"], last_good["action"]), ("152.0.4191.66", "bootstrap"))
            first = self.read(published)
            self.assertEqual(last_good["envelope_sha256"], hashlib.sha256(first).hexdigest())

            # REPLAY: identical source, valid publication served -> no-op,
            # bytes untouched, served verified as valid.
            code, status, _ = run_with(state, **live)
            self.assertEqual((code, status["outcome"]), (0, "unchanged"), status["reason"])
            self.assertEqual(status["served"]["state"], "valid")
            self.assertEqual(self.read(published), first)

            # A RAISE past the bootstrap: .70 -> published.
            code, status, _ = run_with(state, notes=self.notes_for("152.0.4191.70", "CVE-2026-99010"),
                                       catalog=self.catalog_for("152.0.4191.70"), **live)
            self.assertEqual((code, status["outcome"]), (0, "published"), status["reason"])
            second = self.read(published)
            self.assertNotEqual(second, first)

            # OLDER SOURCE after progress: the real .66 page again -> no-op,
            # the .70 publication is kept.
            code, status, _ = run_with(state, **live)
            self.assertEqual((code, status["outcome"]), (0, "unchanged-older-than-published"))
            self.assertEqual(self.read(published), second)

    @unittest.skipUnless(SIGNER and os.access(SIGNER, os.X_OK), "PATANYX_SIGN not set to a built patanyx-sign")
    def test_the_plausibility_bound_is_the_compiled_baseline_not_the_rolling_floor(self):
        # THE REVIEW'S SEQUENCE. Baseline .66 (major 152). Major 176 is
        # exactly 24 ahead and publishes; major 177 would have been accepted
        # by a bound rolled forward to 176, and a client compiled at 152
        # refuses it. The publisher must refuse it first and keep 176.
        with tempfile.TemporaryDirectory() as d:
            key, pub = self.keygen(d, "throwaway-advisory.key")
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            state = os.path.join(d, "state")
            live = dict(dry_run=False, publish_root=root, key=key, signer=SIGNER, public_key=pub, baseline="152.0.4191.66")
            published = os.path.join(root, "v1", "engine-advisory.json")
            code, status, _ = run_with(state, notes=self.notes_for("176.0.4191.70", "CVE-2026-99011"),
                                       catalog=self.catalog_for("176.0.4191.70"), **live)
            self.assertEqual((code, status["outcome"]), (0, "published-bootstrap"), status["reason"])
            kept = self.read(published)
            code, status, _ = run_with(state, notes=self.notes_for("177.0.4191.70", "CVE-2026-99012"),
                                       catalog=self.catalog_for("177.0.4191.70"), **live)
            self.assertEqual((code, status["outcome"]), (3, "refused"), status["reason"])
            self.assertIn("compiled baseline", status["reason"])
            self.assertEqual(self.read(published), kept, "the valid 176 publication is preserved")
            self.assertEqual(status["current_floor"], "176.0.4191.70")
            ver = subprocess.run([SIGNER, "verify-advisory", published, pub, "--baseline", "152.0.4191.66", "--now", str(NOW)],
                                 capture_output=True, text=True)
            self.assertEqual(ver.returncode, 0, "a client compiled at 152 accepts what is served")
            # The signer alone would also refuse 177 against the baseline:
            # belt and braces, exercised with a widened monitor bound.
            code, status, _ = run_with(state, notes=self.notes_for("177.0.4191.70", "CVE-2026-99012"),
                                       catalog=self.catalog_for("177.0.4191.70"), max_major_ahead=100, **live)
            self.assertEqual((code, status["outcome"]), (5, "sign-refused"), status["reason"])
            self.assertIn("implausible", status["reason"])
            self.assertEqual(self.read(published), kept)

    @unittest.skipUnless(SIGNER and os.access(SIGNER, os.X_OK), "PATANYX_SIGN not set to a built patanyx-sign")
    def test_a_verifying_key_that_is_not_the_signing_keys_own_refuses_to_publish(self):
        with tempfile.TemporaryDirectory() as d:
            key, _pub = self.keygen(d, "signer.key")
            _other, other_pub = self.keygen(d, "other.key")
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            code, status, _ = run_with(os.path.join(d, "state"), dry_run=False, publish_root=root, key=key,
                                       signer=SIGNER, public_key=other_pub, baseline="152.0.4191.66")
            self.assertEqual((code, status["outcome"]), (7, "config-error"), status["reason"])
            self.assertIn("does not match --public-key", status["reason"])
            self.assertEqual(os.listdir(os.path.join(root, "v1")), [])

    @unittest.skipUnless(SIGNER and os.access(SIGNER, os.X_OK), "PATANYX_SIGN not set to a built patanyx-sign")
    def test_an_invalid_served_file_is_replaced_by_bootstrap_but_never_below_last_good(self):
        with tempfile.TemporaryDirectory() as d:
            key, pub = self.keygen(d, "throwaway-advisory.key")
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            published = os.path.join(root, "v1", "engine-advisory.json")
            with open(published, "w") as fh:
                fh.write("garbage")
            state = os.path.join(d, "state")
            os.makedirs(state)
            live = dict(dry_run=False, publish_root=root, key=key, signer=SIGNER, public_key=pub, baseline="152.0.4191.66")
            # last-good says .70 was published before; the served file is
            # junk; the source says .66: nothing may be published (below
            # last-good), and the junk is left for a human.
            with open(os.path.join(state, "last-good.json"), "w") as fh:
                json.dump({"floor": "152.0.4191.70", "cves": ["CVE-2026-99010"]}, fh)
            code, status, _ = run_with(state, **live)
            self.assertEqual((code, status["outcome"]), (0, "unchanged-older-than-published"))
            self.assertEqual(status["served"]["state"], "invalid")
            self.assertEqual(self.read(published), b"garbage")
            # With no last-good, the junk is replaced by a bootstrap.
            os.unlink(os.path.join(state, "last-good.json"))
            code, status, _ = run_with(state, **live)
            self.assertEqual((code, status["outcome"]), (0, "published-bootstrap"), status["reason"])
            self.assertEqual(json.loads(json.loads(self.read(published))["payload"])["floor"], "152.0.4191.66")


class ReviewMutants(unittest.TestCase):
    """The exact mutants of the independent monitor review, plus the
    unchanged real capture as control."""

    def notice(self, version="152.0.4191.70", body=None):
        if body is None:
            body = ('The Chromium team reported that '
                    '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99991">'
                    'CVE-2026-99991</a> has an exploit in the wild, and this update contains a fix for it.')
        return f'<p>Microsoft Edge for Stable (Version {version}). {body}</p>'

    def prepend(self, raw, heading='<h2>September 10, 2026</h2>'):
        marker = '<h2 id="september-8-2026">'
        return NOTES.decode("utf-8").replace(marker, heading + raw + marker, 1).encode("utf-8")

    def catalog70(self):
        return {M.parse4("152.0.4191.70"): CATALOG.replace(b"152.0.4191.66", b"152.0.4191.70")}

    def refused(self, notes, needle, catalog=CATALOG):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "last-good.json"), "w") as fh:
                json.dump({"floor": "152.0.4191.62", "cves": []}, fh)
            before = snapshot(d)
            code, status, _ = run_with(d, notes=notes, catalog=catalog)
            self.assertEqual((code, status["outcome"]), (3, "refused"), status["reason"])
            self.assertIn(needle, status["reason"])
            self.assertEqual(snapshot(d)["last-good.json"], before["last-good.json"])
            self.assertIsNone(status["candidate"], "nothing older may be selected underneath")

    def test_control_unchanged_real_capture(self):
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d)
            self.assertEqual((code, status["outcome"], status["candidate"]["version"]), (0, "would-raise", "152.0.4191.66"))

    def test_newer_notice_under_an_unknown_heading_refuses(self):
        self.refused(self.prepend(self.notice(), '<h2>September 10, 2026 (updated)</h2>'), "undated or unfamiliar heading")

    def test_newer_notice_under_an_h3_refuses(self):
        self.refused(self.prepend(self.notice(), '<h3>September 10, 2026</h3>'), "undated or unfamiliar heading")

    def test_newer_notice_outside_a_paragraph_refuses(self):
        li = self.notice().replace("<p>", "<ul><li>").replace("</p>", "</li></ul>")
        self.refused(self.prepend(li), "outside a paragraph")

    def test_commentary_appended_to_a_real_fix_does_not_hide_it(self):
        page = self.prepend(self.notice().replace('</p>', ' The enhanced security mode feature mitigates this vulnerability.</p>'))
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d, notes=page, catalog=self.catalog70())
            self.assertEqual((code, status["outcome"]), (0, "would-raise"), status["reason"])
            self.assertEqual(status["candidate"]["version"], "152.0.4191.70")
            self.assertEqual(status["candidate"]["cves"], ["CVE-2026-99991"])

    def test_single_quoted_mismatched_cve_link_refuses(self):
        page = NOTES.decode("utf-8").replace(
            'href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-87491"',
            "href='https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99999'", 1).encode("utf-8")
        self.refused(page, "does not match its target")

    def test_an_unlinked_cve_in_the_association_refuses(self):
        page = NOTES.decode("utf-8").replace(
            '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-87491" data-linktype="external">CVE-2026-87491</a>',
            "CVE-2026-87491", 1).encode("utf-8")
        self.refused(page, "not linked")

    def test_fix_for_a_different_cve_than_the_exploited_one_refuses(self):
        body = ('The Chromium team reported that <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99991">'
                'CVE-2026-99991</a> has an exploit in the wild. '
                '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99992">CVE-2026-99992</a> '
                'is a separate vulnerability, and this update contains a fix for it.')
        self.refused(self.prepend(self.notice(body=body)), "exploited-and-fixed sentence", self.catalog70())

    def test_a_second_cve_outside_the_association_sentence_refuses(self):
        body = ('The Chromium team reported that <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99991">'
                'CVE-2026-99991</a> has an exploit in the wild, and this update contains a fix for it. It also addresses '
                '<a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99993">CVE-2026-99993</a>.')
        self.refused(self.prepend(self.notice(body=body)), "outside the association sentence", self.catalog70())

    def test_a_future_dated_notice_is_refused_not_signed_today(self):
        self.refused(self.prepend(self.notice(), '<h2>September 30, 2026</h2>'), "is dated 2026-09-30", self.catalog70())

    def test_the_second_association_grammar_is_read(self):
        body = ('This update contains a fix for <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99994">'
                'CVE-2026-99994</a>, which has been reported by the Chromium team as having an exploit in the wild.')
        with tempfile.TemporaryDirectory() as d:
            code, status, _ = run_with(d, notes=self.prepend(self.notice(body=body)), catalog=self.catalog70())
            self.assertEqual((code, status["outcome"]), (0, "would-raise"), status["reason"])
            self.assertEqual(status["candidate"]["cves"], ["CVE-2026-99994"])

    def test_malformed_last_good_is_a_reported_config_error_with_served_bytes_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "v1"))
            served = os.path.join(root, "v1", "engine-advisory.json")
            with open(served, "w") as fh:
                fh.write("keep me")
            for bad in ("[]", "{}", '{"floor": "152.0"}', "not json", '"x"'):
                with open(os.path.join(d, "last-good.json"), "w") as fh:
                    fh.write(bad)
                code, status, _ = run_with(d, publish_root=root)
                self.assertEqual((code, status["outcome"]), (7, "config-error"), bad)
                self.assertIn("last-good", status["reason"])
                self.assertTrue(os.path.isfile(os.path.join(d, "status.json")), "status is written even then")
                with open(os.path.join(d, "status.json")) as fh:
                    self.assertEqual(json.load(fh)["outcome"], "config-error")
                with open(served) as fh:
                    self.assertEqual(fh.read(), "keep me")


class Locking(unittest.TestCase):
    def test_a_second_run_while_the_lock_is_held_exits_4(self):
        import fcntl
        with tempfile.TemporaryDirectory() as d:
            fd = os.open(os.path.join(d, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                proc = subprocess.run([sys.executable, os.path.join(HERE, "engine-advisory-monitor.py"), "--state-dir", d,
                                       "--baseline", "152.0.4191.62", "--dry-run", "--fetch-from-dir", REAL, "--now", str(NOW)],
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 4, proc.stderr)
                self.assertIn("another run holds the lock", proc.stderr)
            finally:
                os.close(fd)
            proc = subprocess.run([sys.executable, os.path.join(HERE, "engine-advisory-monitor.py"), "--state-dir", d,
                                   "--baseline", "152.0.4191.62", "--dry-run", "--fetch-from-dir", REAL, "--now", str(NOW)],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("would-raise", proc.stderr)


class Versions(unittest.TestCase):
    def test_parse4_is_exact(self):
        self.assertEqual(M.parse4("152.0.4191.66"), (152, 0, 4191, 66))
        for bad in ["152.0.4191", "1.2.3.4.5", "", "a.b.c.d", "1.2.3.", "-1.2.3.4", "+1.2.3.4", "1.2.3.4 ", "4294967296.0.0.0", None]:
            self.assertIsNone(M.parse4(bad), bad)
        self.assertLess(M.parse4("152.0.4191.9"), M.parse4("152.0.4191.66"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
