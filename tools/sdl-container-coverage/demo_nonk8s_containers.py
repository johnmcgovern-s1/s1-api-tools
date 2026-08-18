#!/usr/bin/env python3
"""Show that k8sCluster.* container telemetry extends beyond Kubernetes.

A tester-facing demonstration. It proves, from the tenant's own data, that the
report's current filter (`k8sCluster.name = *`) is too narrow: it requires a
Kubernetes cluster, but the same k8sCluster.containerImage / containerName fields
also populate for standalone containers (Docker/Podman) running on ordinary
`server` endpoints that are NOT Kubernetes nodes.

It prints three things:
  1. Narrow vs broad event counts over the same window (the headline delta).
  2. The evidence table: real container activity on NON-Kubernetes-node
     endpoints — actual container/image names, with the cluster/pod/namespace
     columns shown so you can see which populate and which are blank.
  3. Writes that evidence table to a CSV you can hand to the tester.

All queries lead with an indexed filter and use a short window, so they stay
cheap (unfiltered aggregations time out). Read-only. Pure stdlib.

    export S1_SDL_TOKEN="..."
    python3 demo_nonk8s_containers.py --host xdr.us1.sentinelone.net --minutes 10
"""

import argparse
import csv
import json
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


def default_out_dir():
    """Where the evidence CSV goes by default: `<repo>/reports/container-coverage`.
    Resolved from this file's location, not the cwd, so it lands in the same place
    wherever the tool is invoked from. Falls back to a cwd-relative path when the
    file has been copied out of the repo on its own."""
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))  # tools/<tool>/ -> root
    if os.path.isdir(os.path.join(repo_root, "tools")):
        return os.path.join(repo_root, "reports", "container-coverage")
    return os.path.join("reports", "container-coverage")


# Detail columns to show for the non-k8s container evidence. Order matters — it
# reads left-to-right from "where" to "what container" to "is it a pod?".
DETAIL_COLUMNS = [
    "endpoint.name",
    "endpoint.type",
    "k8sCluster.name",         # expected BLANK for standalone containers
    "k8sCluster.namespace",    # expected BLANK
    "k8sCluster.podName",      # expected BLANK (Docker containers aren't pods)
    "k8sCluster.containerName",  # expected POPULATED
    "k8sCluster.containerImage",  # expected POPULATED
]

# The two headline counts and the evidence table all key off the SAME definition
# of "not Kubernetes" — endpoint.type != "kubernetes node" — so the headline and
# the evidence can never contradict each other. (An earlier version counted
# "image set but no cluster name", which wrongly included the S1 agent's own
# container running ON k8s nodes, and disagreed with the evidence table.)
COUNT_NARROW = ('k8sCluster.name = * | group eventCount = count()',
                "Current report scope: only containers that are in a Kubernetes cluster.")
NONK8S_FILTER = 'k8sCluster.containerImage = * AND NOT endpoint.type = "kubernetes node"'
COUNT_NONK8S = (NONK8S_FILTER + ' | group eventCount = count()',
                "Container activity on endpoints that are NOT Kubernetes nodes — "
                "standalone Docker/Podman. This is what the current filter misses.")
EVIDENCE = (NONK8S_FILTER + ' | group eventCount = count() by '
            + ", ".join(DETAIL_COLUMNS))


def run_query(host, token, query, start_ms, end_ms):
    payload = json.dumps({"query": query, "startTime": str(start_ms),
                          "endTime": str(end_ms), "priority": "low"}).encode("utf-8")
    request = urllib.request.Request(
        "https://%s/api/powerQuery" % host, data=payload,
        headers={"Authorization": "Bearer %s" % token,
                 "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120,
                                    context=ssl.create_default_context()) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return False, None, "HTTP %d: %s" % (exc.code, exc.read().decode("utf-8", "replace")[:200])
    except Exception as exc:  # noqa: BLE001
        return False, None, "%s: %s" % (type(exc).__name__, exc)
    if body.get("status") != "success":
        return False, None, "status=%s message=%s" % (body.get("status"), body.get("message"))
    return True, [c.get("name") for c in body.get("columns", [])], body.get("values", [])


def cell(v):
    return "" if v is None else v


def single_count(host, token, query, start_ms, end_ms):
    ok, _cols, values = run_query(host, token, query, start_ms, end_ms)
    if not ok:
        return None, values
    total = sum(r[-1] for r in values if r and isinstance(r[-1], (int, float)))
    return total, None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--token", default=os.environ.get("S1_SDL_TOKEN"))
    ap.add_argument("--minutes", type=float, default=10,
                    help="Window ending now, in minutes (default 10). Standalone-"
                         "container activity is bursty; widen (e.g. 240) if empty.")
    ap.add_argument("--out-dir", default=default_out_dir(),
                    help="Directory for the evidence CSV (default: "
                         "<repo>/reports/container-coverage, resolved from this "
                         "script's location). Contains customer data.")
    args = ap.parse_args()
    if not args.token:
        ap.error("set --token or S1_SDL_TOKEN")
    os.makedirs(args.out_dir, exist_ok=True)
    out_csv = os.path.join(args.out_dir, "nonk8s_container_evidence.csv")

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=args.minutes)
    start_ms, end_ms = int(start.timestamp() * 1000), int(end.timestamp() * 1000)
    print("host=%s  window=%.0f min  [%s -> %s]\n"
          % (args.host, args.minutes, start.isoformat(), end.isoformat()))

    narrow, err_n = single_count(args.host, args.token, COUNT_NARROW[0], start_ms, end_ms)
    nonk8s, err_x = single_count(args.host, args.token, COUNT_NONK8S[0], start_ms, end_ms)

    print("=" * 78)
    print("HEADLINE — container events over the same %.0f-minute window" % args.minutes)
    print("=" * 78)
    print("  In a Kubernetes cluster   (k8sCluster.name = *)           : %s"
          % ("ERROR: %s" % err_n if narrow is None else "%d events" % narrow))
    print("      %s" % COUNT_NARROW[1])
    print("  On NON-Kubernetes endpoints (containerImage, not a k8s node): %s"
          % ("ERROR: %s" % err_x if nonk8s is None else "%d events" % nonk8s))
    print("      %s" % COUNT_NONK8S[1])
    if nonk8s:
        print("  --> %d container events are on endpoints that are NOT Kubernetes"
              % nonk8s)
        print("      nodes — the current `k8sCluster.name` filter misses all of them.")
    elif nonk8s == 0:
        print("  --> 0 in this short window. Standalone-container activity is bursty;")
        print("      re-run with a longer --minutes (e.g. --minutes 240) to catch it.")
    print()

    print("=" * 78)
    print("EVIDENCE — container activity on NON-Kubernetes-node endpoints")
    print("=" * 78)
    print("  query: %s\n" % EVIDENCE)
    ok, cols, values = run_query(args.host, args.token, EVIDENCE, start_ms, end_ms)
    if not ok:
        print("  ERROR — %s" % values)
        return
    if not values:
        print("  (no non-k8s container activity in this window — try a longer --minutes)")
        return

    # Print a readable table.
    short = ["endpoint.name", "endpoint.type", "k8sCluster.name",
             "k8sCluster.podName", "k8sCluster.containerName", "k8sCluster.containerImage"]
    idx = {c: cols.index(c) for c in cols}
    print("  %-16s %-9s %-11s %-10s %-16s %s"
          % ("endpoint", "type", "cluster", "podName", "containerName", "containerImage"))
    print("  " + "-" * 96)
    for row in values[:25]:
        def g(name):
            return str(cell(row[idx[name]])) if name in idx else ""
        img = g("k8sCluster.containerImage")
        img = img if len(img) <= 40 else "..." + img[-37:]
        print("  %-16s %-9s %-11s %-10s %-16s %s"
              % (g("endpoint.name")[:16], g("endpoint.type")[:9],
                 (g("k8sCluster.name") or "(blank)")[:11],
                 (g("k8sCluster.podName") or "(blank)")[:10],
                 g("k8sCluster.containerName")[:16], img))
    if len(values) > 25:
        print("  ... (%d more rows)" % (len(values) - 25))

    # Write full evidence to CSV.
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for row in values:
            w.writerow([cell(c) for c in row])
    print("\n  Full evidence table -> %s (%d rows)" % (os.path.abspath(out_csv), len(values)))

    print()
    print("=" * 78)
    print("HOW TO READ THIS")
    print("=" * 78)
    print("  These containers run on `server` endpoints, NOT `kubernetes node`.")
    print("  Note: k8sCluster.name and podName are typically BLANK (they aren't in")
    print("  a cluster and aren't pods), yet containerName and containerImage ARE")
    print("  populated. So the `k8sCluster.*` field family is really generic")
    print("  container context — the report's `k8sCluster.name = *` filter is what")
    print("  narrows it to Kubernetes only.")


if __name__ == "__main__":
    main()
