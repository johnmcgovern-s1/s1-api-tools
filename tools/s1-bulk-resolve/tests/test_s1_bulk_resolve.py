#!/usr/bin/env python3
"""Stdlib-only tests for s1_bulk_resolve. No network: we monkeypatch `post_json`
with synthetic GraphQL responses and drive the logic that actually breaks —
cursor paging, batch chunking, outcome folding, resume, and query rendering.

Run:  python3 tools/s1-bulk-resolve/tests/test_s1_bulk_resolve.py
"""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # import the tool next to tests/

import s1_bulk_resolve as t  # noqa: E402


def alert_page(ids, has_next, cursor=None):
    return {"data": {"alerts": {
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
        "edges": [{"node": {"id": i, "name": "n-%s" % i}} for i in ids],
    }}}


class FakePoster:
    """Stands in for post_json: returns queued responses and records payloads."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.payloads = []

    def __call__(self, url, token, payload, what):
        self.payloads.append(payload)
        return self.responses.pop(0)


class CollectPaging(unittest.TestCase):
    def test_pages_until_hasNextPage_false(self):
        fake = FakePoster([
            alert_page(["a", "b"], True, "c1"),
            alert_page(["c"], False, None),
        ])
        t.post_json = fake
        nodes = t.collect_alerts("h", "tok", [{"fieldId": "status",
                                 "stringEqual": {"value": "NEW"}}],
                                 ["1"], "ACCOUNT", ["id", "name"], 2)
        self.assertEqual([n["id"] for n in nodes], ["a", "b", "c"])
        # second request carried the cursor from page one
        self.assertIn('after: "c1"', self.q(fake.payloads[1]))

    def test_stops_when_cursor_missing_despite_hasNextPage(self):
        fake = FakePoster([alert_page(["a"], True, None)])
        t.post_json = fake
        nodes = t.collect_alerts("h", "tok", [], ["1"], "ACCOUNT", ["id"], 50)
        self.assertEqual(len(nodes), 1)  # did not loop forever

    @staticmethod
    def q(payload):
        return payload["query"]


class OutcomeFolding(unittest.TestCase):
    def test_failure_beats_skip_beats_success(self):
        result = {"actions": [
            {"actionId": "status", "success": [{"id": "ok"}], "failure": [{"id": "bad"}], "skip": []},
            {"actionId": "note", "success": [{"id": "ok"}], "failure": [], "skip": [{"id": "meh"}]},
        ]}
        out = t.fold_outcomes(result, ["ok", "bad", "meh", "ghost"])
        self.assertEqual(out["ok"], "resolved")
        self.assertEqual(out["bad"], "failed")
        self.assertEqual(out["meh"], "skipped")
        self.assertEqual(out["ghost"], "unknown")  # in no list


class ApplyBatching(unittest.TestCase):
    def _apply_result(self, ids):
        return {"data": {"alertTriggerActions": {
            "__typename": "ActionsTriggered",
            "actions": [{"actionId": "status",
                         "success": [{"id": i} for i in ids],
                         "failure": [], "skip": []}],
        }}}

    def test_chunks_ids_and_resolves_all(self):
        ids = ["i%d" % n for n in range(5)]
        fake = FakePoster([self._apply_result(ids[0:2]),
                           self._apply_result(ids[2:4]),
                           self._apply_result(ids[4:5])])
        t.post_json = fake
        actions, _, _ = t.build_actions(True, None, "FALSE_POSITIVE", None)
        with tempfile.TemporaryDirectory() as d:
            cp = os.path.join(d, "cp.json")
            out = t.apply_actions("h", "tok", ids, ["1"], "ACCOUNT", actions, 2, cp)
        self.assertEqual(len(fake.payloads), 3)         # 5 ids / batch 2 -> 3 calls
        self.assertTrue(all(v == "resolved" for v in out.values()))
        # each mutation carried exactly its batch's ids
        self.assertEqual(self._count_ids(fake.payloads[0]["query"]), 2)
        self.assertEqual(self._count_ids(fake.payloads[2]["query"]), 1)

    def test_resume_skips_completed_batches(self):
        ids = ["i%d" % n for n in range(4)]
        with tempfile.TemporaryDirectory() as d:
            cp = os.path.join(d, "cp.json")
            with open(cp, "w") as h:
                json.dump({"ids": ids, "batch_size": 2, "completed_batches": 1,
                           "outcomes": {"i0": "resolved", "i1": "resolved"}}, h)
            fake = FakePoster([self._apply_result(ids[2:4])])
            t.post_json = fake
            actions, _, _ = t.build_actions(True, None, None, None)
            out = t.apply_actions("h", "tok", ids, ["1"], "ACCOUNT", actions, 2, cp)
        self.assertEqual(len(fake.payloads), 1)  # only the second batch ran
        self.assertEqual(len(out), 4)

    def test_error_union_raises(self):
        fake = FakePoster([{"data": {"alertTriggerActions": {
            "__typename": "TriggerActionsError",
            "errors": [{"errorMessage": "nope"}]}}}])
        t.post_json = fake
        actions, _, _ = t.build_actions(True, None, None, None)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                t.apply_actions("h", "tok", ["x"], ["1"], "ACCOUNT", actions, 50,
                                os.path.join(d, "cp.json"))

    @staticmethod
    def _count_ids(query):
        return query.count('fieldId: "id"')


class QueryRendering(unittest.TestCase):
    def test_filter_and_scope_render(self):
        clauses = t.build_filter_clauses("Identity", "NEW", ['tag=foo'], None)
        q = t.build_alerts_query(clauses, ["acc1"], "ACCOUNT", ["id"], 100, None)
        self.assertIn('fieldId: "detectionProduct"', q)
        self.assertIn('stringEqual: { value: "Identity" }', q)
        self.assertIn('fieldId: "tag"', q)
        self.assertIn('scopeType: ACCOUNT', q)

    def test_enum_validation_rejects_injection(self):
        with self.assertRaises(RuntimeError):
            t.gql_enum('RESOLVED } evil', "--set-status")

    def test_note_is_escaped_string(self):
        actions, labels, status = t.build_actions(True, None, None,
                                                  'he said "hi"\nbye')
        mut = t.build_mutation(["id1"], ["s"], "SITE", actions)
        self.assertIn('S1/alert/addNote', mut)
        self.assertIn('\\"hi\\"', mut)   # embedded quotes escaped
        self.assertEqual(status, "RESOLVED")

    def test_filter_file_mutually_exclusive_semantics(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([{"fieldId": "severity", "stringEqual": {"value": "High"}}], f)
            path = f.name
        try:
            clauses = t.build_filter_clauses(None, None, [], path)
            q = t.build_alerts_query(clauses, ["s"], "SITE", ["id"], 10, None)
            self.assertIn('fieldId: "severity"', q)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
