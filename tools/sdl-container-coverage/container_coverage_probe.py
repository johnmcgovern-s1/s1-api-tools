#!/usr/bin/env python3
"""Discover what container telemetry actually populates in an SDL tenant.

Question this answers: "can we report all container activity across the fleet,
regardless of runtime?" SentinelOne exposes container context in *orchestrator-
specific* field namespaces, not one generic one:

  - Kubernetes -> k8sCluster.*   (populated only by the Container Agent in K8s)
  - AWS ECS    -> task.*         (task.cluster, task.taskArn, task.ecsVersion, ...)
  - standalone Podman/Docker/containerd with no orchestrator -> (no dedicated
    container fields documented at all)

So "all runtimes" isn't a single query. This probe runs a series of cheap
aggregation PowerQueries over a short window and reports, from the tenant's OWN
data, how many events each namespace covers — turning the doc-level answer into a
measured one before we commit to extending the report tool.

Every query is a `group ... count()` aggregate: tiny output, one API call each,
read-only. Nothing is written back to the tenant.

    export S1_SDL_TOKEN="<SDL Log Read Access token>"
    python3 container_coverage_probe.py --host xdr.us1.sentinelone.net --minutes 10

Pure stdlib.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# Each probe: (label, query, note). Queries are single-line, double-quoted —
# single quotes are invalid over the JSON API.
#
# IMPORTANT: every query leads with an indexed `field = value` filter. Unfiltered
# aggregations (a bare `| group count() by X`) full-scan the window and TIME OUT
# even over a few minutes — confirmed against a live tenant. `NOT` filters are
# similarly expensive and are avoided here; the "without k8s" question is answered
# by comparing two cheap filtered counts instead.
PROBES = [
    ("endpoint types with Process Creation activity",
     'event.type = "Process Creation" | group eventCount = count() by endpoint.type',
     "Scoped to Process Creation (the report's event type) so it stays cheap. "
     "'kubernetes node' rows = K8s nodes; everything else is non-k8s endpoints."),

    ("K8s coverage: events with a cluster name",
     'k8sCluster.name = * | group eventCount = count() by k8sCluster.name',
     "One row per Kubernetes cluster seen. This is what the current report covers."),

    ("K8s coverage: distinct container images (K8s)",
     'k8sCluster.containerImage = * | group eventCount = count() by k8sCluster.containerImage',
     "Container images observed via the K8s namespace."),

    ("ECS coverage: events with a task cluster",
     'task.cluster = * | group eventCount = count() by task.cluster',
     "One row per ECS cluster. NON-ZERO here = ECS workloads the current report misses."),

    ("ECS coverage: events with a task ARN",
     'task.taskArn = * | group eventCount = count()',
     "Total ECS task events. Confirms whether task.* is populated at all."),

    ("ECS coverage: distinct ECS services",
     'task.serviceName = * | group eventCount = count() by task.serviceName',
     "One row per ECS service name."),

    ("container images seen (any orchestrator that populates the field)",
     'k8sCluster.containerImage = * | group eventCount = count()',
     "Total events carrying a container image. Compare against the K8s cluster "
     "count above: a large gap can hint at container activity not tagged with a "
     "K8s cluster name (e.g. ECS, which reuses k8sCluster.containerImage)."),
]


def run_query(host, token, query, start_ms, end_ms):
    """One aggregation PowerQuery, no retries (probe fails fast). Returns
    (ok, columns, values) or (False, None, error_string)."""
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
    except urllib.error.HTTPError as exc:
        return False, None, "HTTP %d: %s" % (exc.code, exc.read().decode("utf-8", "replace")[:200])
    except Exception as exc:  # noqa: BLE001 - diagnostic, report anything
        return False, None, "%s: %s" % (type(exc).__name__, exc)
    if body.get("status") != "success":
        return False, None, "status=%s message=%s" % (body.get("status"), body.get("message"))
    cols = [c.get("name") for c in body.get("columns", [])]
    return True, cols, body.get("values", [])


def total_count(values):
    """Sum the last column across rows (the count column), best-effort."""
    total = 0
    for row in values:
        cell = row[-1]
        if isinstance(cell, (int, float)):
            total += cell
    return total


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--token", default=os.environ.get("S1_SDL_TOKEN"))
    parser.add_argument("--minutes", type=float, default=10,
                        help="Window ending now, in minutes (default 10). Window "
                             "size dominates cost: fleet-wide Process Creation over "
                             "an hour times out, but ~10 min is fine. Widen only if "
                             "counts are too sparse to judge.")
    parser.add_argument("--hours", type=float, default=None,
                        help="Alternative to --minutes, in hours. Use small values.")
    parser.add_argument("--max-rows", type=int, default=15,
                        help="Rows to print per probe before summarizing (default 15).")
    args = parser.parse_args()
    if not args.token:
        parser.error("set --token or S1_SDL_TOKEN")

    window_min = args.hours * 60 if args.hours is not None else args.minutes
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=window_min)
    start_ms, end_ms = int(start.timestamp() * 1000), int(end.timestamp() * 1000)
    print("host=%s  window=%.0f min  [%s -> %s]\n"
          % (args.host, window_min, start.isoformat(), end.isoformat()))

    verdict = {}
    for label, query, note in PROBES:
        print("=" * 78)
        print(label)
        print("  query: %s" % query)
        print("  why:   %s" % note)
        ok, cols, values = run_query(args.host, args.token, query, start_ms, end_ms)
        if not ok:
            print("  RESULT: ERROR — %s" % values)
            verdict[label] = None
            continue
        total = total_count(values)
        verdict[label] = total
        print("  RESULT: %d group(s), %d total events" % (len(values), total))
        if cols:
            print("          columns: %s" % ", ".join(cols))
        for row in values[:args.max_rows]:
            print("          %s" % "  ".join(str(c) for c in row))
        if len(values) > args.max_rows:
            print("          ... (%d more rows)" % (len(values) - args.max_rows))
        print()

    print("=" * 78)
    print("SUMMARY — container telemetry coverage in this tenant/window")
    print("=" * 78)
    ecs_tasks = verdict.get("ECS coverage: events with a task ARN")
    k8s = verdict.get("K8s coverage: events with a cluster name")
    images = verdict.get("container images seen (any orchestrator that populates the field)")

    def fmt(v):
        return "n/a (query errored)" if v is None else "%d events" % v

    print("  Kubernetes (k8sCluster.name):     %s" % fmt(k8s))
    print("  AWS ECS (task.taskArn):           %s" % fmt(ecs_tasks))
    print("  events carrying a container image:%s" % fmt(images))
    print()
    if ecs_tasks:
        print("  -> ECS workloads ARE present. The current K8s-only report misses them;")
        print("     extending Step 2 with the task.* namespace would capture them.")
    elif ecs_tasks == 0:
        print("  -> No ECS task events in this window. Either no ECS fleet, or none active.")
    if k8s is not None and images is not None and images > k8s * 1.1:
        print("  -> More container-image events than K8s-cluster events: some container")
        print("     activity may not be tagged with a K8s cluster name (e.g. ECS).")
    print()
    print("  Note: standalone Podman/Docker/containerd hosts with no orchestrator")
    print("  carry NO dedicated container fields in SDL, so they cannot be counted")
    print("  here directly — they appear only as ordinary process activity on their")
    print("  (non-k8s) endpoint. 'All container activity regardless of runtime' is")
    print("  therefore not expressible as a single field filter today.")


if __name__ == "__main__":
    main()
