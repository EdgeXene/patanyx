#!/usr/bin/env python3
"""Unit tests for the pure logic of publish-langpacks.py.

These pin the exact failures an adversarial review (one review seat plus a
blind two-perspective pair) found in the first cut: predicted-sha correctness (the no-op/monotonic decision rests on it),
record selection refusing gaps and duplicates, the CDN host pin, the bounded
download, register merge (a filtered run must not erase the other pairs), and
the size parse staying in step with the Rust bound. Run: python3 -m pytest
scripts/test_publish_langpacks.py  (or: python3 scripts/test_publish_langpacks.py)
"""
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load_pub():
    spec = importlib.util.spec_from_file_location(
        "publang", os.path.join(HERE, "publish-langpacks.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = load_pub()


class PredictedSha(unittest.TestCase):
    def test_matches_hand_built_container(self):
        blobs = {"model": b"MODEL-bytes", "lex": b"LEX", "vocab": b"VOC-abc"}
        # Rebuild the exact framing build-langpack.sh writes: magic, three
        # length lines (model, lex, vocab), then the three blobs in that order.
        h = hashlib.sha256()
        h.update(b"PXPACK1\n")
        for k in ("model", "lex", "vocab"):
            h.update(f"{len(blobs[k])}\n".encode())
        for k in ("model", "lex", "vocab"):
            h.update(blobs[k])
        self.assertEqual(P.predicted_pack_sha(blobs), h.hexdigest())

    def test_order_is_model_lex_vocab_not_dict_order(self):
        a = {"lex": b"L", "vocab": b"V", "model": b"M"}
        b = {"model": b"M", "lex": b"L", "vocab": b"V"}
        self.assertEqual(P.predicted_pack_sha(a), P.predicted_pack_sha(b))


class ChosenRecords(unittest.TestCase):
    def _rec(self, ft, ver, rid="x"):
        return {"fromLang": "el", "toLang": "en", "fileType": ft,
                "version": ver, "id": rid,
                "attachment": {"location": "l", "hash": "h", "size": 1}}

    def test_complete_set(self):
        recs = [self._rec("model", "1.1"), self._rec("lex", "1.1"),
                self._rec("vocab", "1.1")]
        out = P.chosen_records(recs, "1.1")
        self.assertEqual(set(out), {"model", "lex", "vocab"})

    def test_missing_filetype_raises(self):
        recs = [self._rec("model", "1.1"), self._rec("lex", "1.1")]
        with self.assertRaises(ValueError):
            P.chosen_records(recs, "1.1")

    def test_duplicate_filetype_raises(self):
        recs = [self._rec("model", "1.1", "a"), self._rec("model", "1.1", "b"),
                self._rec("lex", "1.1"), self._rec("vocab", "1.1")]
        with self.assertRaises(ValueError):
            P.chosen_records(recs, "1.1")

    def test_never_mixes_versions(self):
        recs = [self._rec("model", "1.1"), self._rec("lex", "1.1"),
                self._rec("vocab", "1.1"), self._rec("model", "1.0")]
        out = P.chosen_records(recs, "1.1")
        self.assertEqual(len(out), 3)  # the 1.0 model is ignored, not mixed in


class AttachmentBase(unittest.TestCase):
    def test_pins_mozilla_host(self):
        payload = json.dumps({"capabilities": {"attachments": {
            "base_url": "https://evil.example.com/x/"}}}).encode()
        orig = P.http_get
        P.http_get = lambda *a, **k: payload
        try:
            with self.assertRaises(SystemExit):
                P.attachment_base(None)
        finally:
            P.http_get = orig

    def test_insecure_override_used_verbatim(self):
        self.assertEqual(P.attachment_base("https://x.test"), "https://x.test/")


class BoundedRead(unittest.TestCase):
    """These mock the module's no-redirect opener, not urllib.request.urlopen:
    http_get routes through _OPENER, and an earlier version of this class
    mocked urlopen with http:// URLs -- which passed via the https refusal
    without the cap logic ever running. A test passing for the wrong reason
    is the quietest kind of rot."""

    class _Resp:
        def __init__(self, data, url="https://x.test/", clen=None):
            self._d = io.BytesIO(data)
            self._url = url
            self.headers = {"Content-Length": str(clen)} if clen is not None else {}

        def geturl(self):
            return self._url

        def read(self, n=-1):
            return self._d.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _with_resp(self, resp, fn):
        orig = P._OPENER.open
        P._OPENER.open = lambda *a, **k: resp
        try:
            return fn()
        finally:
            P._OPENER.open = orig

    def test_content_length_over_cap_refuses(self):
        with self.assertRaises(SystemExit):
            self._with_resp(self._Resp(b"x" * 10, clen=10),
                            lambda: P.http_get("https://x.test/", cap=5))

    def test_streamed_body_over_cap_refuses(self):
        # No Content-Length, but the body itself exceeds the cap.
        with self.assertRaises(SystemExit):
            self._with_resp(self._Resp(b"x" * 100),
                            lambda: P.http_get("https://x.test/", cap=5))

    def test_under_cap_body_is_returned(self):
        got = self._with_resp(self._Resp(b"ok"),
                              lambda: P.http_get("https://x.test/", cap=10))
        self.assertEqual(got, b"ok")

    def test_final_host_must_match_expectation(self):
        # A response whose final URL landed on another host (a followed
        # redirect would look like this) is refused when a host is pinned.
        with self.assertRaises(SystemExit):
            self._with_resp(
                self._Resp(b"x", url="https://evil.test/"),
                lambda: P.http_get("https://x.test/", cap=10,
                                   expect_host="x.test"))


class RegisterMerge(unittest.TestCase):
    def test_filtered_run_keeps_other_pairs(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "reg.json")
            P.write_register(path, {
                "pairs": {"aa-en": {"manifest_version": 1, "pack_sha256": "s"},
                          "bb-en": {"manifest_version": 3, "pack_sha256": "t"}},
                "exclusions": [{"pair": "zz-en", "reason": "x"}],
            })
            reg = P.load_register(path)
            # Simulate a --pairs aa-en run touching only aa-en.
            reg["pairs"]["aa-en"] = {"manifest_version": 2, "pack_sha256": "s2"}
            P.write_register(path, reg)
            back = P.load_register(path)
            self.assertEqual(back["pairs"]["bb-en"]["manifest_version"], 3)
            self.assertEqual(back["pairs"]["aa-en"]["manifest_version"], 2)
            self.assertEqual(len(back["pairs"]), 2)

    def test_write_is_sorted_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "reg.json")
            P.write_register(path, {"pairs": {"zz-en": {}, "aa-en": {}},
                                    "exclusions": []})
            keys = list(json.load(open(path))["pairs"].keys())
            self.assertEqual(keys, sorted(keys))
            # The temp-then-rename write must not strand its temp file.
            self.assertEqual([f for f in os.listdir(d) if f != "reg.json"], [])

    def test_corrupt_register_is_fatal_not_reset(self):
        # A damaged high-water mark must refuse, never silently become empty.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "reg.json")
            open(path, "w").write("{not json")
            with self.assertRaises(SystemExit):
                P.load_register(path)

    def test_missing_register_is_a_fresh_start(self):
        self.assertEqual(
            P.load_register("/nonexistent/reg.json"),
            {"pairs": {}, "exclusions": []})


class NoOpPredicate(unittest.TestCase):
    def test_requires_served_pack_bytes_to_match(self):
        # Register + manifest agreeing is NOT enough: a substituted pack file
        # must break the no-op even when every recorded sha looks right.
        with tempfile.TemporaryDirectory() as d:
            pack = os.path.join(d, "x.pxpack")
            open(pack, "wb").write(b"REAL-PACK")
            sha = hashlib.sha256(b"REAL-PACK").hexdigest()
            entry = {"pack_sha256": sha}
            self.assertTrue(P.pack_already_served(entry, sha, pack, sha))
            open(pack, "wb").write(b"SUBSTITUTED")
            self.assertFalse(P.pack_already_served(entry, sha, pack, sha))

    def test_requires_register_and_manifest_agreement(self):
        with tempfile.TemporaryDirectory() as d:
            pack = os.path.join(d, "x.pxpack")
            open(pack, "wb").write(b"P")
            sha = hashlib.sha256(b"P").hexdigest()
            self.assertFalse(P.pack_already_served({}, sha, pack, sha))
            self.assertFalse(
                P.pack_already_served({"pack_sha256": sha}, sha, pack, "other"))
            self.assertFalse(P.pack_already_served(
                {"pack_sha256": sha}, sha, os.path.join(d, "absent"), sha))


class PublishedMode(unittest.TestCase):
    def test_atomic_write_produces_world_readable_files(self):
        # mkstemp creates 0600; a published artifact the web server's user
        # cannot read is a silent 403 for every client.
        with tempfile.TemporaryDirectory() as d:
            dst = os.path.join(d, "a.json")
            P.atomic_write_bytes(dst, b"{}")
            self.assertEqual(os.stat(dst).st_mode & 0o777, 0o644)


class RedirectRefusal(unittest.TestCase):
    def test_http_get_requires_https(self):
        with self.assertRaises(SystemExit):
            P.http_get("http://x.test/", cap=10)


class SizeBound(unittest.TestCase):
    def test_parses_rust_constant(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write("pub const MAX_MODEL_PACK_BYTES: u64 = 96 * 1024 * 1024;\n")
            name = f.name
        try:
            self.assertEqual(P.max_pack_bytes(name), 96 * 1024 * 1024)
        finally:
            os.unlink(name)

    def test_unparseable_constant_is_fatal(self):
        # Guessing the bound can publish packs the client rejects; a format
        # change in the Rust must be handled deliberately, not papered over.
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write("const SOMETHING_ELSE: u64 = 1;\n")
            name = f.name
        try:
            with self.assertRaises(SystemExit):
                P.max_pack_bytes(name)
        finally:
            os.unlink(name)


class RegistryTokens(unittest.TestCase):
    def test_extracts_tokens(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write('Pair { token: "el-en", from: "el", to: "en" },\n')
            f.write('Pair { token: "en-es", from: "en", to: "es" },\n')
            name = f.name
        try:
            self.assertEqual(P.registry_tokens(name), {"el-en", "en-es"})
        finally:
            os.unlink(name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
