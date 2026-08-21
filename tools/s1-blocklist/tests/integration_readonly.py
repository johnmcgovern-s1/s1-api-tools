#!/usr/bin/env python3
"""Live, READ-ONLY integration checks for s1-blocklist against a real tenant.

Unlike test_s1_blocklist.py (stdlib-only, no network), this exercises the actual
read paths — blocklist GET + paging, the Threat-Intel IOC lookup, the deprecated
verdict endpoint, and scope/includeParents behaviour — against a live console.
It performs NO writes.

It is data-agnostic and hardcodes nothing tenant-specific: it discovers a known
value straight from the tenant's own blocklist at runtime, so it works against
any environment and leaks no demo hashes / account ids into the repo.

    export S1_CONSOLE_TOKEN="<console API token>"
    export S1_HOST="your-console.sentinelone.net"
    export S1_ACCOUNT_ID="<account id>"             # and/or S1_SITE_ID
    python3 tools/s1-blocklist/tests/integration_readonly.py

Exit code is 0 only if every assertion passed. Skips (e.g. an empty blocklist,
or no TI permission) are reported but do not fail the run.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # import the tool next to tests/

import s1_blocklist as t  # noqa: E402

# Synthetic values that must never exist on a real blocklist/feed.
ABSENT_SHA1 = "00000000000000000000000000000000000000ff"
ABSENT_MD5 = "0000000000000000000000000000000f"

_passed = 0
_failed = 0
_skipped = 0


def check(name, condition, detail=""):
    global _passed, _failed
    mark = "PASS" if condition else "FAIL"
    if condition:
        _passed += 1
    else:
        _failed += 1
    print("  [%s] %s%s" % (mark, name, (" — " + detail) if detail else ""))


def skip(name, why):
    global _skipped
    _skipped += 1
    print("  [SKIP] %s — %s" % (name, why))


def main():
    host = os.environ.get("S1_HOST")
    token = os.environ.get("S1_CONSOLE_TOKEN")
    account_id = os.environ.get("S1_ACCOUNT_ID")
    site_id = os.environ.get("S1_SITE_ID")
    if not host or not token or not (account_id or site_id):
        raise SystemExit("Set S1_HOST, S1_CONSOLE_TOKEN, and S1_ACCOUNT_ID "
                         "and/or S1_SITE_ID.")

    account_ids = [account_id] if account_id else []
    site_ids = [site_id] if site_id else []
    scope = t.scope_query_params(account_ids, site_ids, [], False)
    ti_scope = t.ti_scope_params(account_ids, site_ids, False)
    print("Host: %s  Scope: %s" % (host, t.scope_label(account_ids, site_ids,
                                                        [], False)))

    # --- Layer 1: blocklist fetch + paging ---------------------------------
    print("\n[1] Blocklist fetch (GET /restrictions, includeParents=true)")
    entries = t.fetch_restrictions(host, token, scope, True, False)
    check("fetch returned a list", isinstance(entries, list),
          "%d entr(y/ies)" % len(entries))
    index = t.index_by_hash(entries)

    # --- Layer 1: match path (discovered from live data) -------------------
    print("\n[2] Match path — check a hash taken from the tenant's own blocklist")
    sample = next((e for e in entries if e.get("value")), None)
    if not sample:
        skip("match path", "blocklist is empty in this scope")
    else:
        sha1 = sample["value"].strip().lower()
        matches = index.get(sha1, [])
        check("discovered SHA1 is indexed", bool(matches))
        cov = t.compute_coverage("sha1", bool(matches), False, "")
        check("coverage == blocked", cov == "blocked", cov)
        # any entry carrying a SHA256 must be resolvable by that SHA256 too
        with256 = next((e for e in entries
                        if (e.get("sha256Value") or "").strip()), None)
        if with256:
            sha256 = with256["sha256Value"].strip().lower()
            check("a SHA256 value is indexed", sha256 in index)
        else:
            skip("sha256 index", "no entry in scope carries a sha256Value")

        # --- includeParents actually changes behaviour --------------------
        print("\n[3] includeParents flag flips behaviour for a parent-scope entry")
        entry_scope = t.entry_scope(sample)
        # A Global/parent entry should vanish when parents are excluded.
        if entry_scope and entry_scope.lower() != "global" and not site_ids:
            skip("includeParents", "sample entry is not at a parent scope")
        else:
            no_parents = t.fetch_restrictions(host, token, scope, False, False)
            np_index = t.index_by_hash(no_parents)
            check("parent-scope hash absent without includeParents",
                  sha1 not in np_index,
                  "scope=%s" % (entry_scope or "?"))

    # --- Miss path ---------------------------------------------------------
    print("\n[4] Miss path — synthetic hash that cannot be present")
    check("synthetic SHA1 not on blocklist", ABSENT_SHA1 not in index)
    check("coverage(miss) == not-blocked",
          t.compute_coverage("sha1", False, False, "unknown") == "not-blocked")

    # --- Layer 2: Threat-Intel IOC store -----------------------------------
    print("\n[5] Threat-Intel IOC lookup (GET /threat-intelligence/iocs)")
    if not ti_scope:
        skip("IOC lookup", "no account/site scope for TI layer")
    else:
        try:
            iocs = t.fetch_iocs_for_hash(host, token, ABSENT_SHA1, "SHA1",
                                         ti_scope)
            check("IOC endpoint responded", isinstance(iocs, list),
                  "%d match(es) for synthetic hash" % len(iocs))
            check("synthetic hash not in feed", len(iocs) == 0)
        except RuntimeError as exc:
            skip("IOC lookup", "endpoint/permission error: %s" % str(exc)[:80])

    # --- MD5 handling ------------------------------------------------------
    print("\n[6] MD5 handling (not a blocklist key)")
    check("coverage(md5, no hit) == unknown-md5",
          t.compute_coverage("md5", False, False, "") == "unknown-md5")

    # --- Layer 3: deprecated verdict endpoint ------------------------------
    print("\n[7] Reputation verdict (deprecated, best-effort)")
    if sample and sample.get("value"):
        verdict = t.get_verdict(host, token, sample["value"].strip().lower())
        ok = verdict in ("malicious", "non-malicious", "unknown") \
            or verdict.startswith("verdict-error")
        check("verdict endpoint returned a value", ok, verdict)
    else:
        verdict = t.get_verdict(host, token, ABSENT_SHA1)
        check("verdict endpoint returned a value",
              verdict in ("malicious", "non-malicious", "unknown")
              or verdict.startswith("verdict-error"), verdict)

    # --- Summary -----------------------------------------------------------
    print("\n" + "=" * 60)
    print("PASSED %d   FAILED %d   SKIPPED %d" % (_passed, _failed, _skipped))
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
