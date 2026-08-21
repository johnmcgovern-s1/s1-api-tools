#!/usr/bin/env python3
"""Stdlib-only tests for s1_blocklist. No network: we monkeypatch `api_request`
with synthetic management-API responses and drive the logic that actually breaks
— hash classification/normalisation, blocklist indexing, parent-inclusion,
per-OS dedup on add, and dry-run vs apply.

Run:  python3 tools/s1-blocklist/tests/test_s1_blocklist.py
"""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # import the tool next to tests/

import s1_blocklist as t  # noqa: E402

SHA1_A = "a" * 40
SHA1_B = "b" * 40
SHA256_A = "c" * 64
MD5_A = "d" * 32


def entry(**kw):
    base = {"id": "id-%s" % kw.get("value", kw.get("sha256Value", "x"))[:6],
            "osType": "windows", "type": "black_hash", "scopePath": "Global",
            "source": "user", "description": "", "createdAt": "2026-01-01",
            "userName": "svc"}
    base.update(kw)
    return base


class Recorder:
    """Stands in for api_request: returns queued responses, records calls."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, host, token, method, path, query=None, body=None,
                 what="request"):
        self.calls.append({"method": method, "path": path, "query": query,
                           "body": body})
        return self.responses.pop(0)


class HashKind(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(t.hash_kind(SHA1_A), "sha1")
        self.assertEqual(t.hash_kind(SHA256_A), "sha256")
        self.assertEqual(t.hash_kind(MD5_A), "md5")
        self.assertIsNone(t.hash_kind("nothex!!"))
        self.assertIsNone(t.hash_kind("abc"))  # right chars, wrong length

    def test_load_normalises_dedups_and_reports_skips(self):
        raw = [SHA1_A.upper(), SHA1_A, "garbage", SHA256_A]
        hashes, skips = t.load_hashes(raw, None)
        self.assertEqual(hashes, [SHA1_A, SHA256_A])  # lowercased + deduped
        self.assertEqual(len(skips), 1)
        self.assertIn("garbage", skips[0][0])

    def test_load_from_file_with_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# advisory\n%s\n\n%s  # inline\n" % (SHA1_A, SHA1_B))
            path = fh.name
        try:
            hashes, skips = t.load_hashes([], path)
        finally:
            os.remove(path)
        self.assertEqual(hashes, [SHA1_A, SHA1_B])
        self.assertEqual(skips, [])


class Indexing(unittest.TestCase):
    def test_index_maps_both_hash_forms(self):
        entries = [entry(value=SHA1_A, sha256Value=SHA256_A),
                   entry(value=SHA1_B, osType="linux")]
        index = t.index_by_hash(entries)
        self.assertIn(SHA1_A, index)
        self.assertIn(SHA256_A, index)  # sha256Value indexed too
        self.assertIn(SHA1_B, index)
        self.assertEqual(len(index[SHA1_A]), 1)

    def test_index_is_case_insensitive(self):
        index = t.index_by_hash([entry(value=SHA1_A.upper())])
        self.assertIn(SHA1_A, index)  # lookup key is lowercase


class FetchPaging(unittest.TestCase):
    def test_follows_cursor_to_exhaustion(self):
        rec = Recorder([
            {"data": [entry(value=SHA1_A)],
             "pagination": {"nextCursor": "c1", "totalItems": 2}},
            {"data": [entry(value=SHA1_B)],
             "pagination": {"nextCursor": None, "totalItems": 2}},
        ])
        t.api_request = rec
        got = t.fetch_restrictions("h", "tok", {"accountIds": "1"}, True, False)
        self.assertEqual(len(got), 2)
        # second call carried the cursor and both carried type + includeParents
        self.assertEqual(rec.calls[1]["query"]["cursor"], "c1")
        self.assertEqual(rec.calls[0]["query"]["type"], "black_hash")
        self.assertEqual(rec.calls[0]["query"]["includeParents"], "true")


class OsTypeExpansion(unittest.TestCase):
    def test_all_expands_and_dedups(self):
        self.assertEqual(t.expand_os_types(["all"]), t.ALL_OS_TYPES)
        self.assertEqual(t.expand_os_types(["windows", "windows"]), ["windows"])

    def test_invalid_and_empty_raise(self):
        with self.assertRaises(SystemExit):
            t.expand_os_types([])
        with self.assertRaises(SystemExit):
            t.expand_os_types(["solaris"])


class AddDedup(unittest.TestCase):
    """add must skip an (already-present, same-OS) entry and add the rest."""

    def _args(self, out_dir, **over):
        ns = argparse_ns(
            host="h", token="tok", hash=[SHA1_A], hash_file=None,
            tenant=False, account_id=["1"], site_id=[], group_id=[],
            include_children=False, out_dir=out_dir, apply=True, dry_run=False,
            os_type=["windows", "linux"], description="d", source="user")
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def test_dedups_existing_os_and_adds_missing(self):
        # Existing: SHA1_A on windows only. Adding windows+linux -> windows is
        # already-blocked, linux is a real POST.
        fetch_resp = {"data": [entry(value=SHA1_A, osType="windows")],
                      "pagination": {"nextCursor": None, "totalItems": 1}}
        post_resp = {"data": [{"id": "new-linux"}]}
        rec = Recorder([fetch_resp, post_resp])
        t.api_request = rec
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out)
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_add(args, "h", "tok", scope, out, "RUN", dry_run=False)
        # exactly one POST (linux), and it carried value + osType
        posts = [c for c in rec.calls if c["method"] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["body"]["data"]["osType"], "linux")
        self.assertEqual(posts[0]["body"]["data"]["value"], SHA1_A)
        self.assertEqual(posts[0]["body"]["filter"], {"accountIds": ["1"]})

    def test_dry_run_makes_no_post(self):
        fetch_resp = {"data": [], "pagination": {"nextCursor": None,
                                                 "totalItems": 0}}
        rec = Recorder([fetch_resp])
        t.api_request = rec
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out, apply=False)
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_add(args, "h", "tok", scope, out, "RUN", dry_run=True)
        self.assertFalse([c for c in rec.calls if c["method"] == "POST"])

    def test_sha256_goes_in_sha256_field(self):
        fetch_resp = {"data": [], "pagination": {"nextCursor": None,
                                                 "totalItems": 0}}
        rec = Recorder([fetch_resp, {"data": [{"id": "n"}]}])
        t.api_request = rec
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out, hash=[SHA256_A], os_type=["windows"])
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_add(args, "h", "tok", scope, out, "RUN", dry_run=False)
        post = [c for c in rec.calls if c["method"] == "POST"][0]
        self.assertEqual(post["body"]["data"]["sha256Value"], SHA256_A)
        self.assertNotIn("value", post["body"]["data"])


class RemoveResolves(unittest.TestCase):
    def _args(self, out_dir, **over):
        ns = argparse_ns(
            host="h", token="tok", hash=[SHA1_A], hash_file=None,
            tenant=False, account_id=["1"], site_id=[], group_id=[],
            include_children=False, out_dir=out_dir, apply=True, dry_run=False)
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def test_resolves_hash_to_ids_and_deletes(self):
        fetch_resp = {"data": [entry(value=SHA1_A, id="del-1", osType="windows")],
                      "pagination": {"nextCursor": None, "totalItems": 1}}
        rec = Recorder([fetch_resp, {"data": None}])
        t.api_request = rec
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out)
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_remove(args, "h", "tok", scope, out, "RUN", dry_run=False)
        deletes = [c for c in rec.calls if c["method"] == "DELETE"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0]["body"]["data"]["ids"], ["del-1"])
        self.assertEqual(deletes[0]["body"]["data"]["type"], "black_hash")

    def test_dry_run_makes_no_delete(self):
        fetch_resp = {"data": [entry(value=SHA1_A, id="del-1")],
                      "pagination": {"nextCursor": None, "totalItems": 1}}
        rec = Recorder([fetch_resp])
        t.api_request = rec
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out, apply=False)
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_remove(args, "h", "tok", scope, out, "RUN", dry_run=True)
        self.assertFalse([c for c in rec.calls if c["method"] == "DELETE"])


def ioc(value, ioc_type="SHA1", **kw):
    base = {"value": value, "type": ioc_type, "source": "Mandiant",
            "name": "APT-x indicator"}
    base.update(kw)
    return base


class Coverage(unittest.TestCase):
    def test_blocked_when_on_blocklist_or_ti(self):
        self.assertEqual(t.compute_coverage("sha1", True, False, ""), "blocked")
        self.assertEqual(t.compute_coverage("sha1", False, True, ""), "blocked")

    def test_reputation_flagged_only_when_malicious(self):
        self.assertEqual(
            t.compute_coverage("sha1", False, False, "malicious"),
            "reputation-flagged")
        self.assertEqual(
            t.compute_coverage("sha1", False, False, "unknown"), "not-blocked")

    def test_md5_with_no_feed_hit_is_unknown(self):
        self.assertEqual(t.compute_coverage("md5", False, False, ""),
                         "unknown-md5")
        # but a feed hit on an MD5 still counts as blocked
        self.assertEqual(t.compute_coverage("md5", False, True, ""), "blocked")


class TiLookup(unittest.TestCase):
    def test_verifies_value_and_type(self):
        # server returns one true match and one that doesn't actually match
        rec = Recorder([{"data": [ioc(SHA1_A), ioc(SHA1_B)],
                         "pagination": {"nextCursor": None}}])
        t.api_request = rec
        got = t.fetch_iocs_for_hash("h", "tok", SHA1_A, "SHA1",
                                    {"accountIds": "1"})
        self.assertEqual([m["value"] for m in got], [SHA1_A])
        self.assertEqual(rec.calls[0]["query"]["value"], SHA1_A)
        self.assertEqual(rec.calls[0]["query"]["type"], "SHA1")

    def test_ti_scope_has_no_group(self):
        params = t.ti_scope_params(["1"], ["2"], True)
        self.assertEqual(params, {"accountIds": "1", "siteIds": "2",
                                  "tenant": "true"})


class CheckLayers(unittest.TestCase):
    def _args(self, out_dir, **over):
        ns = argparse_ns(
            host="h", token="tok", hash=[SHA1_A], hash_file=None,
            tenant=False, account_id=["1"], site_id=[], group_id=[],
            include_children=False, out_dir=out_dir,
            with_verdict=False, no_threat_intel=False, no_include_parents=False)
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _run(self, responses, **over):
        rec = Recorder(responses)
        t.api_request = rec
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out, **over)
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_check(args, "h", "tok", scope, out, "RUN")
            # read the CSV back
            csv_path = os.path.join(out, "blocklist_check_RUN.csv")
            import csv as _csv
            with open(csv_path) as fh:
                rows = list(_csv.DictReader(fh))
        return rec, rows

    def test_ti_hit_reports_blocked_even_when_not_on_blocklist(self):
        empty_bl = {"data": [], "pagination": {"nextCursor": None,
                                               "totalItems": 0}}
        ti_hit = {"data": [ioc(SHA1_A)], "pagination": {"nextCursor": None}}
        rec, rows = self._run([empty_bl, ti_hit])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["onBlocklist"], "no")
        self.assertEqual(rows[0]["inThreatIntel"], "yes")
        self.assertEqual(rows[0]["coverage"], "blocked")
        self.assertEqual(rows[0]["threatIntelSources"], "Mandiant")

    def test_no_threat_intel_flag_skips_layer2(self):
        empty_bl = {"data": [], "pagination": {"nextCursor": None,
                                               "totalItems": 0}}
        rec, rows = self._run([empty_bl], no_threat_intel=True)
        # only the blocklist fetch happened — no IOC query
        self.assertEqual(len(rec.calls), 1)
        self.assertEqual(rows[0]["inThreatIntel"], "skipped")
        self.assertEqual(rows[0]["coverage"], "not-blocked")

    def test_group_only_scope_disables_ti_layer(self):
        empty_bl = {"data": [], "pagination": {"nextCursor": None,
                                               "totalItems": 0}}
        # group-only: ti_scope_params is empty -> layer skipped, no IOC call
        rec, rows = self._run([empty_bl], account_id=[], group_id=["9"])
        self.assertEqual(len(rec.calls), 1)
        self.assertEqual(rows[0]["inThreatIntel"], "skipped")

    def test_ti_error_disables_layer_after_first_failure(self):
        empty_bl = {"data": [], "pagination": {"nextCursor": None,
                                               "totalItems": 0}}

        class BlThenBoom:
            def __init__(self):
                self.n = 0

            def __call__(self, *a, **k):
                self.n += 1
                if self.n == 1:
                    return empty_bl
                raise RuntimeError("HTTP 403 no TI license")
        t.api_request = BlThenBoom()
        with tempfile.TemporaryDirectory() as out:
            args = self._args(out, hash=[SHA1_A, SHA1_B])
            scope = t.scope_query_params(["1"], [], [], False)
            t.cmd_check(args, "h", "tok", scope, out, "RUN")
            import csv as _csv
            with open(os.path.join(out, "blocklist_check_RUN.csv")) as fh:
                rows = list(_csv.DictReader(fh))
        # first hash records the error; second is skipped (layer disabled)
        self.assertEqual(rows[0]["inThreatIntel"], "error")
        self.assertEqual(rows[1]["inThreatIntel"], "skipped")


class VerdictIsBestEffort(unittest.TestCase):
    def test_verdict_error_never_raises(self):
        def boom(*a, **k):
            raise RuntimeError("HTTP 404")
        t.api_request = boom
        out = t.get_verdict("h", "tok", SHA1_A)
        self.assertTrue(out.startswith("verdict-error"))


class ErrorArrayIsFatal(unittest.TestCase):
    def test_check_api_errors_raises_on_nonempty(self):
        with self.assertRaises(RuntimeError):
            t.check_api_errors({"errors": [{"detail": "nope"}]}, "x")
        t.check_api_errors({"errors": []}, "x")  # empty is fine
        t.check_api_errors({}, "x")


def argparse_ns(**kw):
    import argparse
    return argparse.Namespace(**kw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
