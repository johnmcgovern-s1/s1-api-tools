#!/usr/bin/env python3
"""Isolate which construct in the k8s report query the SDL powerQuery API rejects.

Sends a ladder of progressively more complex queries over a short window and
reports which succeed. The first FAIL identifies the culprit. Read-only: no
savelookup runs until the final probes, and each query is tiny.

    export S1_SDL_TOKEN="..."
    python3 probe_powerquery.py --host xdr.us1.sentinelone.net
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

PROBES = [
    # (label, query) — ordered simplest to most complex.
    ("1. powerQuery works at all (bare aggregation)",
     '| group c = count() by event.type'),

    ("2. filter on event.type, single line",
     'event.type = "Process Creation" | group c = count() by agent.uuid'),

    ("3. same query but MULTI-LINE (tests newline tolerance)",
     'event.type = "Process Creation"\n| group c = count() by agent.uuid'),

    ("4. explicit AND + endpoint.type, single line",
     'event.type = "Process Creation" AND endpoint.type = "kubernetes node" '
     '| group c = count() by agent.uuid'),

    ("5. implicit AND (space-separated, as the docs' examples use)",
     'event.type = "Process Creation" endpoint.type = "kubernetes node" '
     '| group c = count() by agent.uuid'),

    ("6. endpoint.type filter alone",
     'endpoint.type = "kubernetes node" | group c = count() by agent.uuid'),

    ("7. SAVELOOKUP — the prime suspect",
     'event.type = "Process Creation" AND endpoint.type = "kubernetes node" '
     '| group eventCount = count() by agent.uuid '
     '| savelookup "probe_test.csv"'),

    ("8. k8sCluster.name wildcard (Step 2's filter)",
     'k8sCluster.name = * | group c = count() by k8sCluster.name'),

    ("9. LOOKUP from a nonexistent file (expect a clear client error, not 500)",
     'k8sCluster.name = * | lookup eventCount from probe_missing.csv by agent.uuid '
     '| group c = count()'),
]


def call(host, token, query, start_ms, end_ms):
    """One powerQuery call, no retries. Returns (ok, detail)."""
    payload = json.dumps({
        "query": query,
        "startTime": str(start_ms),
        "endTime": str(end_ms),
        "priority": "low",
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://%s/api/powerQuery" % host,
        data=payload,
        headers={"Authorization": "Bearer %s" % token,
                 "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120,
                                    context=ssl.create_default_context()) as response:
            body = json.loads(response.read().decode("utf-8"))
        if body.get("status") == "success":
            return True, "rows=%d matching=%s omitted=%s" % (
                len(body.get("values", [])),
                body.get("matchingEvents", "?"),
                body.get("omittedEvents", "?"))
        return False, "status=%s message=%s" % (body.get("status"), body.get("message"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace").strip()
        try:
            parsed = json.loads(raw)
            raw = "status=%s message=%s" % (parsed.get("status"), parsed.get("message"))
        except ValueError:
            pass
        return False, "HTTP %d  %s" % (exc.code, raw[:300])
    except Exception as exc:  # noqa: BLE001 - diagnostic script, report anything
        return False, "%s: %s" % (type(exc).__name__, exc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--token", default=os.environ.get("S1_SDL_TOKEN"))
    parser.add_argument("--minutes", type=int, default=5,
                        help="Window size, kept small so probes are cheap (default 5).")
    args = parser.parse_args()
    if not args.token:
        parser.error("set --token or S1_SDL_TOKEN")

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=args.minutes)
    start_ms, end_ms = int(start.timestamp() * 1000), int(end.timestamp() * 1000)
    print("host=%s  window=%d min  [%d, %d)\n" % (args.host, args.minutes, start_ms, end_ms))

    results = []
    for label, query in PROBES:
        sys.stdout.write("%-58s " % label)
        sys.stdout.flush()
        ok, detail = call(args.host, args.token, query, start_ms, end_ms)
        results.append((label, ok))
        print("%-4s %s" % ("PASS" if ok else "FAIL", detail))

    print("\n--- summary ---")
    failed = [lbl for lbl, ok in results if not ok]
    if not failed:
        print("Everything passed. The 500 may be scale/time-window related rather "
              "than syntax — retry the real report over a shorter window.")
    else:
        print("First failure identifies the culprit:")
        for lbl in failed:
            print("  FAIL  %s" % lbl)


if __name__ == "__main__":
    main()
