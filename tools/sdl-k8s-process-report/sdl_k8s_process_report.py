#!/usr/bin/env python3
"""Run a two-step Kubernetes process-count report against the SDL PowerQuery API.

Calls a live tenant and writes CSVs. It exists because this report is impractical
in the console UI — the query times out on a large fleet — and because getting it
right over the API needs two non-obvious workarounds, both explained below.

See README.md next to this file for the full write-up, and SentinelOne's
Singularity Data Lake (DataSet) API documentation for the powerQuery spec.

The report:

  Step 1  Count "Process Creation" events per Kubernetes node (`agent.uuid`).
  Step 2  Pull container/pod/label detail for every `k8sCluster.*` event in the
          window, and attach each row's node event count from Step 1.

Workaround 1 — the join happens **client-side**.

  The console version of this report used `savelookup` to write Step 1's
  aggregate to a server-side CSV, then `lookup` to join it back in Step 2. Over
  the API that path returns `HTTP 500 error/server` ("internal Scalyr error while
  processing this query"): `savelookup` writes to the tenant's shared file
  namespace, which a read-scoped query cannot do.

  So Step 1's aggregate is kept in memory (and cached to CSV) and the
  `eventCount` column is attached to each Step 2 row here in Python, keyed on
  `agent.uuid`. Same output, no server-side state — which also means concurrent
  runs on one tenant no longer clobber each other's lookup file.

  Both queries are also sent as a **single line**. Every example in the SDL docs
  is single-line, and multi-line text was the other candidate cause of that 500;
  keeping them single-line removes the variable. Note too that the console-UI
  form of these queries used single quotes, which are *invalid over the JSON API*
  — "For JSON requests, single quotes are invalid, and you must \\" escape double
  quotes in strings" (SDL powerQuery docs).

Workaround 2 — pagination is **client-driven time-slicing**.

  `/api/powerQuery` is synchronous and carries neither `maxCount` nor
  `continuationToken` — compare `/api/query`, which has both. It signals
  over-limit results only via `omittedEvents`, so a single large call can return
  a *quietly incomplete* table with HTTP 200 and `status: success`. That, not the
  timeout, is the real hazard.

  Step 1 aggregates to one row per node and is very unlikely to truncate (the
  console limit it hits is a UI/gateway timeout, not the backend's compute
  budget), so it runs as one call. Step 2 returns one row per raw event, so it is
  sliced; any slice reporting `omittedEvents > 0` is bisected and retried down to
  `--min-slice-minutes`. Rows stream to CSV as they arrive, with a checkpoint so
  an interrupted run resumes instead of restarting.

Time bounds go out as absolute epoch-ms, never relative ("24h"), so slices are
stable and reproducible across a long run. Step 1 and Step 2 should use the same
window, or `eventCount` won't correspond to the detail rows.

Pure stdlib. Usage:

    export S1_SDL_TOKEN="<SDL Log Read Access token>"
    python3 sdl_k8s_process_report.py --host xdr.us1.sentinelone.net --hours 24

    # preview the queries and planned slices without calling the API
    python3 sdl_k8s_process_report.py --host xdr.us1.sentinelone.net --dry-run
"""

import argparse
import csv
import glob
import http.client
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# --- The report queries. ----------------------------------------------------
# Change the time window via --hours / --start / --end, not by editing these.
# Single-line and double-quoted on purpose — see "Workaround 1" above.

QUERY_STEP1 = (
    'event.type = "Process Creation" AND endpoint.type = "kubernetes node" '
    "| group eventCount = count() by agent.uuid"
)

# No `lookup` pipe: eventCount is joined client-side. `agent.uuid` must stay in
# the column list — it is the join key.
STEP2_COLUMNS = [
    "endpoint.name",
    "agent.uuid",
    "k8sCluster.containerImage",
    "k8sCluster.containerImage.sha256",
    "k8sCluster.containerLabels",
    "k8sCluster.containerName",
    "k8sCluster.name",
    "k8sCluster.namespace",
    "k8sCluster.podLabels",
    "k8sCluster.podName",
]

QUERY_STEP2 = "k8sCluster.name = * | columns " + ", ".join(STEP2_COLUMNS)

JOIN_KEY = "agent.uuid"
JOINED_COLUMN = "eventCount"

STEP1_CSV_NAME = "k8s_node_process_counts.csv"
STEP2_CSV_NAME = "k8s_container_report.csv"


def default_out_dir():
    """Where reports go unless --out-dir says otherwise: `<repo>/reports/k8s`.

    Resolved from this file's location, NOT the current directory — so the
    default lands in the same place no matter where the tool is invoked from.
    A cwd-relative default is how output ends up somewhere surprising.

    Falls back to a cwd-relative `reports/k8s` when the file has been copied out
    of the repo on its own (a supported way to run these tools), since there is
    no project root to anchor to in that case.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))  # tools/<tool>/ -> root
    if os.path.isdir(os.path.join(repo_root, "tools")):
        return os.path.join(repo_root, "reports", "k8s")
    return os.path.join("reports", "k8s")

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 6
INITIAL_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 60
# Generous on purpose: the console UI's timeout is the problem this script routes
# around, so don't reintroduce a tight one on the client side.
REQUEST_TIMEOUT_SECONDS = 600


# --- API --------------------------------------------------------------------

def run_power_query(host, token, query, start_ms, end_ms, priority="low"):
    """POST one PowerQuery call, retrying 429/5xx/network errors with backoff.

    Returns the parsed JSON body. The HTTP status can be 200 while `status` in
    the body is an error, so callers must check that too.
    """
    payload = json.dumps({
        "query": query,
        "startTime": str(start_ms),
        "endTime": str(end_ms),
        "priority": priority,
    }).encode("utf-8")
    headers = {
        "Authorization": "Bearer %s" % token,
        "Content-Type": "application/json",
    }
    url = "https://%s/api/powerQuery" % host
    context = ssl.create_default_context()

    backoff = INITIAL_BACKOFF_SECONDS
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS,
                                        context=context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if exc.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else backoff
                # Always show the body: the API puts the real reason there, and a
                # 500 caused by a malformed query will never succeed on retry, so
                # the operator needs to see why on the FIRST attempt, not the last.
                warn("HTTP %d from API; retrying in %.0fs (attempt %d/%d). "
                     "Response body: %s"
                     % (exc.code, wait, attempt, MAX_RETRIES, body.strip()[:500] or "(empty)"))
                time.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            raise RuntimeError("powerQuery failed: HTTP %d: %s" % (exc.code, body))
        except (urllib.error.URLError, TimeoutError, OSError,
                http.client.HTTPException, ValueError) as exc:
            # http.client.HTTPException covers IncompleteRead — the server
            # truncating a chunked response mid-body, which happens on long
            # PowerQuery calls. It subclasses HTTPException, NOT OSError, so it
            # is not covered by URLError/OSError and would otherwise crash the
            # run mid-slice. ValueError covers a JSON decode failure on a
            # partial body. Both are transient: retry.
            last_error = exc
            if attempt == MAX_RETRIES:
                break
            warn("%s while reading the response (%s); retrying in %ds "
                 "(attempt %d/%d)"
                 % (type(exc).__name__, exc, backoff, attempt, MAX_RETRIES))
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)

    raise RuntimeError("powerQuery failed after %d retries: %s" % (MAX_RETRIES, last_error))


def cell_to_str(cell):
    """Render one response cell for CSV, including PowerQuery special values."""
    if isinstance(cell, dict) and "special" in cell:
        return {"+infinity": "Infinity",
                "-infinity": "-Infinity",
                "NaN": "NaN"}.get(cell["special"], str(cell))
    if cell is None:
        return ""
    return cell


def column_index(response, name, step):
    """Index of `name` in a response's columns, or a clear error if absent."""
    names = [c.get("name") for c in response.get("columns", [])]
    if name not in names:
        raise RuntimeError(
            "%s response has no %r column (got %s) — cannot join on it."
            % (step, name, names))
    return names.index(name)


def warn(message):
    sys.stderr.write("  [warn] %s\n" % message)


# --- Time helpers -----------------------------------------------------------

def to_epoch_ms(moment):
    return int(moment.timestamp() * 1000)


def parse_bound(value):
    """Parse an ISO 8601 bound, e.g. 2026-08-17T00:00:00Z. Naive input is UTC."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def build_slices(start_ms, end_ms, slice_minutes):
    """Contiguous non-overlapping [start, end) bounds, oldest first."""
    slice_ms = slice_minutes * 60 * 1000
    slices = []
    cursor = start_ms
    while cursor < end_ms:
        nxt = min(cursor + slice_ms, end_ms)
        slices.append((cursor, nxt))
        cursor = nxt
    return slices


# --- Step 1: per-node event counts -----------------------------------------

def run_step1(host, token, start_ms, end_ms, priority, out_dir):
    """Aggregate Process Creation counts per node. Returns {agent.uuid: count}."""
    print("Step 1: counting Process Creation events by %s over [%d, %d) ..."
          % (JOIN_KEY, start_ms, end_ms))
    response = run_power_query(host, token, QUERY_STEP1, start_ms, end_ms, priority)
    if response.get("status") != "success":
        raise RuntimeError("Step 1 query did not succeed: %s" % response)

    key_at = column_index(response, JOIN_KEY, "Step 1")
    count_at = column_index(response, JOINED_COLUMN, "Step 1")
    values = response.get("values", [])
    omitted = response.get("omittedEvents", 0)

    counts = {}
    for row in values:
        counts[str(cell_to_str(row[key_at]))] = cell_to_str(row[count_at])

    print("  matchingEvents=%s  omittedEvents=%s  nodes=%d"
          % (response.get("matchingEvents", 0), omitted, len(counts)))
    if omitted:
        warn("Step 1's aggregate was itself truncated (omittedEvents=%s). That is "
             "unusual for a count-by-%s — the number of distinct nodes may be far "
             "larger than expected. Step 2's %s column will be incomplete; narrow "
             "the window." % (omitted, JOIN_KEY, JOINED_COLUMN))

    # Cached so --step2-only can rebuild the join without re-running Step 1.
    cache_path = os.path.join(out_dir, STEP1_CSV_NAME)
    with open(cache_path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([JOIN_KEY, JOINED_COLUMN])
        for key, count in sorted(counts.items()):
            writer.writerow([key, count])
    print("  Wrote per-node counts to %s" % cache_path)
    return counts


def load_step1_counts(out_dir):
    """Reload Step 1's counts for --step2-only. Clear error if never run."""
    cache_path = os.path.join(out_dir, STEP1_CSV_NAME)
    if not os.path.exists(cache_path):
        raise RuntimeError(
            "--step2-only needs Step 1's counts, but %s does not exist. Run "
            "without --step2-only first (Step 1 caches the counts there)."
            % cache_path)
    with open(cache_path, newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header != [JOIN_KEY, JOINED_COLUMN]:
            raise RuntimeError("%s has unexpected header %s; expected %s"
                               % (cache_path, header, [JOIN_KEY, JOINED_COLUMN]))
        counts = {row[0]: row[1] for row in reader if row}
    print("Step 2: loaded %d per-node count(s) from %s" % (len(counts), cache_path))
    return counts


# --- Output: one CSV, or one per time interval ------------------------------

class OutputSet:
    """CSV sink for Step 2 rows: a single file, or one per `split_ms` interval.

    Output-file boundaries are deliberately **decoupled from query slice
    boundaries**. Bisection makes slices non-uniform — a truncated hour becomes
    2x30min, then 4x15min — so a file-per-slice scheme would produce irregular
    files whose count depends on data density. Intervals here are fixed
    wall-clock windows measured from the run's window start, and
    `--split-minutes` is validated as a multiple of `--slice-minutes`, so no
    slice (or bisected sub-slice) ever straddles two files.

    Only one handle is open at a time. Slices are processed oldest-first,
    including through bisection recursion, so once an interval is passed it is
    never revisited — which keeps a 1-minute split over 24h from needing 1,440
    open files.
    """

    def __init__(self, out_dir, window_start_ms, split_ms):
        self.out_dir = out_dir
        self.window_start_ms = window_start_ms
        self.split_ms = split_ms
        self.header_row = None
        self._index = None
        self._handle = None
        self._writer = None
        self._rows = {}  # path -> rows written by this run

    def _interval_index(self, slice_start_ms):
        if not self.split_ms:
            return 0
        return (slice_start_ms - self.window_start_ms) // self.split_ms

    def path_for_index(self, index):
        base = STEP2_CSV_NAME[:-len(".csv")]
        if not self.split_ms:
            return os.path.join(self.out_dir, STEP2_CSV_NAME)
        start_ms = self.window_start_ms + index * self.split_ms
        stamp = datetime.fromtimestamp(
            start_ms / 1000.0, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return os.path.join(self.out_dir, "%s_%s.csv" % (base, stamp))

    def _select(self, slice_start_ms):
        index = self._interval_index(slice_start_ms)
        if index == self._index:
            return
        self._close_current()
        path = self.path_for_index(index)
        # Append, and write the header only for a genuinely new/empty file, so a
        # resumed run doesn't repeat it.
        is_new = not (os.path.exists(path) and os.path.getsize(path) > 0)
        self._handle = open(path, "a", newline="")
        self._writer = csv.writer(self._handle)
        self._index = index
        self._rows.setdefault(path, 0)
        if is_new and self.header_row:
            self._writer.writerow(self.header_row)

    def write_rows(self, slice_start_ms, rows):
        """Write already-rendered rows for a slice starting at slice_start_ms."""
        if not rows:
            return
        self._select(slice_start_ms)
        for row in rows:
            self._writer.writerow(row)
        self._rows[self.path_for_index(self._index)] += len(rows)

    def flush(self):
        if self._handle:
            self._handle.flush()
            os.fsync(self._handle.fileno())

    def _close_current(self):
        if self._handle:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
        self._handle = self._writer = self._index = None

    def close(self):
        self._close_current()

    def files(self):
        return sorted(self._rows.items())


def existing_output_paths(out_dir):
    """Every Step 2 output file, split or not, plus the manifest."""
    base = STEP2_CSV_NAME[:-len(".csv")]
    paths = glob.glob(os.path.join(out_dir, base + "*.csv"))
    manifest = os.path.join(out_dir, base + "_manifest.json")
    if os.path.exists(manifest):
        paths.append(manifest)
    return paths


# --- Step 2: sliced detail dump with the client-side join -------------------

def fetch_slice(host, token, start_ms, end_ms, priority, min_slice_ms,
                output, counts, stats, depth=0):
    """Fetch [start_ms, end_ms), join eventCount, write rows. Bisect and recurse
    while the result is truncated and the slice is wider than min_slice_ms."""
    indent = "  " * (depth + 1)
    response = run_power_query(host, token, QUERY_STEP2, start_ms, end_ms, priority)
    if response.get("status") != "success":
        raise RuntimeError("Step 2 query failed for slice [%d, %d): %s"
                           % (start_ms, end_ms, response))

    omitted = response.get("omittedEvents", 0)
    values = response.get("values", [])
    width_ms = end_ms - start_ms

    if omitted and width_ms > min_slice_ms:
        mid = start_ms + width_ms // 2
        # Discard this truncated response entirely; the halves supersede it.
        print("%s[%d,%d) truncated (omittedEvents=%s); bisecting at %d"
              % (indent, start_ms, end_ms, omitted, mid))
        fetch_slice(host, token, start_ms, mid, priority, min_slice_ms,
                    output, counts, stats, depth + 1)
        fetch_slice(host, token, mid, end_ms, priority, min_slice_ms,
                    output, counts, stats, depth + 1)
        return

    if omitted:
        warn("[%d,%d) is still truncated at the %.1f-minute floor "
             "(omittedEvents=%s); writing the %d rows returned and moving on. "
             "Lower --min-slice-minutes to close this gap."
             % (start_ms, end_ms, min_slice_ms / 60000.0, omitted, len(values)))
        stats["unresolved_slices"] += 1
        stats["unresolved_omitted"] += omitted

    if not values:
        stats["slices"] += 1
        print("%s[%d,%d) -> 0 rows" % (indent, start_ms, end_ms))
        return

    # The join: prepend eventCount, looked up by agent.uuid.
    key_at = column_index(response, JOIN_KEY, "Step 2")
    if output.header_row is None:
        names = [c.get("name") for c in response.get("columns", [])]
        output.header_row = [JOINED_COLUMN] + names

    rendered = []
    for row in values:
        key = str(cell_to_str(row[key_at]))
        count = counts.get(key, "")
        if count == "":
            stats["unmatched_rows"] += 1
        rendered.append([count] + [cell_to_str(c) for c in row])
    output.write_rows(start_ms, rendered)

    stats["rows"] += len(values)
    stats["slices"] += 1
    print("%s[%d,%d) -> %d rows (matchingEvents=%s)"
          % (indent, start_ms, end_ms, len(values), response.get("matchingEvents", 0)))


def run_step2(host, token, start_ms, end_ms, priority, slice_minutes,
              min_slice_minutes, out_dir, fresh, counts, split_minutes=0):
    checkpoint_path = os.path.join(out_dir, STEP2_CSV_NAME) + ".checkpoint.json"
    split_ms = split_minutes * 60 * 1000

    if fresh:
        for path in existing_output_paths(out_dir) + [checkpoint_path]:
            if os.path.exists(path):
                os.remove(path)

    resume_from = start_ms
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as handle:
            resume_from = max(start_ms, json.load(handle)["completed_until_ms"])
        print("Step 2: resuming from checkpoint at %d (pass --fresh to start over)"
              % resume_from)

    if resume_from >= end_ms:
        print("Step 2: the checkpoint says this window is already complete.")
        return

    slices = build_slices(resume_from, end_ms, slice_minutes)
    min_slice_ms = min_slice_minutes * 60 * 1000
    print("Step 2: %d top-level slice(s) of %d min, bisecting to %d min on "
          "truncation, over [%d, %d)"
          % (len(slices), slice_minutes, min_slice_minutes, resume_from, end_ms))
    if split_ms:
        print("        splitting output every %d min (one CSV per interval)"
              % split_minutes)

    stats = {"rows": 0, "slices": 0, "unresolved_slices": 0,
             "unresolved_omitted": 0, "unmatched_rows": 0}
    # Intervals are numbered from the *window* start, not the resume point, so a
    # resumed run keeps writing into the same interval files.
    output = OutputSet(out_dir, start_ms, split_ms)
    try:
        for index, (slice_start, slice_end) in enumerate(slices, start=1):
            print("[%d/%d] slice [%d, %d)" % (index, len(slices), slice_start, slice_end))
            fetch_slice(host, token, slice_start, slice_end, priority, min_slice_ms,
                        output, counts, stats)
            # Flush before checkpointing so a resume never skips buffered rows.
            output.flush()
            with open(checkpoint_path, "w") as cp:
                json.dump({"completed_until_ms": slice_end}, cp)
    finally:
        output.close()

    written = output.files()
    print("Step 2 done: %d rows across %d slice(s) into %d file(s)"
          % (stats["rows"], stats["slices"], len(written)))
    for path, rows in written:
        print("  %8d rows  %s" % (rows, os.path.basename(path)))
    if written:
        write_manifest(out_dir, start_ms, end_ms, written, stats)
    if stats["unmatched_rows"]:
        print("  %d row(s) had no Step 1 count for their %s (blank %s). Expected "
              "for pods on nodes with no Process Creation events in the window."
              % (stats["unmatched_rows"], JOIN_KEY, JOINED_COLUMN))
    if stats["unresolved_slices"]:
        warn("%d slice(s) hit the floor still truncated, dropping roughly %d rows. "
             "Re-run with a smaller --min-slice-minutes to close the gap."
             % (stats["unresolved_slices"], stats["unresolved_omitted"]))
    else:
        print("  No unresolved truncation — the output is complete for this window.")


def write_manifest(out_dir, start_ms, end_ms, written, stats):
    """Record what was produced, so a multi-file deliverable is self-describing."""
    base = STEP2_CSV_NAME[:-len(".csv")]
    path = os.path.join(out_dir, base + "_manifest.json")
    manifest = {
        "window": {
            "startMs": start_ms,
            "endMs": end_ms,
            "startUtc": datetime.fromtimestamp(
                start_ms / 1000.0, timezone.utc).isoformat(),
            "endUtc": datetime.fromtimestamp(
                end_ms / 1000.0, timezone.utc).isoformat(),
        },
        "queries": {"step1": QUERY_STEP1, "step2": QUERY_STEP2},
        "joinedColumn": JOINED_COLUMN,
        "joinKey": JOIN_KEY,
        "totals": {
            "rows": stats["rows"],
            "slices": stats["slices"],
            "unmatchedRows": stats["unmatched_rows"],
            "unresolvedTruncatedSlices": stats["unresolved_slices"],
            "approxRowsDropped": stats["unresolved_omitted"],
        },
        "files": [{"name": os.path.basename(p), "rows": n} for p, n in written],
    }
    with open(path, "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    print("  manifest: %s" % os.path.basename(path))


# --- CLI --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True,
                        help="SDL console host, e.g. xdr.us1.sentinelone.net")
    parser.add_argument("--token", default=os.environ.get("S1_SDL_TOKEN"),
                        help="SDL Log Read Access token. Prefer the S1_SDL_TOKEN env var.")
    parser.add_argument("--hours", type=float, default=24,
                        help="Window ending now, in hours (default 24). Ignored with --start.")
    parser.add_argument("--start", help="Absolute start, ISO 8601, e.g. 2026-08-17T00:00:00Z")
    parser.add_argument("--end", help="Absolute end, ISO 8601. Defaults to now.")
    parser.add_argument("--priority", choices=["low", "high"], default="low",
                        help="Query priority (default low: more generous rate limits).")
    parser.add_argument("--slice-minutes", type=int, default=60,
                        help="Step 2 top-level slice width (default 60).")
    parser.add_argument("--min-slice-minutes", type=int, default=1,
                        help="Bisection floor for truncated slices (default 1).")
    parser.add_argument("--split-minutes", type=int, default=0, metavar="N",
                        help="Split output into one CSV per N-minute interval "
                             "(e.g. 60 = hourly). Must be a multiple of "
                             "--slice-minutes. Default 0 = a single CSV.")
    parser.add_argument("--out-dir", default=default_out_dir(),
                        help="Output directory for CSVs and the checkpoint "
                             "(default: <repo>/reports/k8s, resolved from this "
                             "script's location, not the current directory).")
    parser.add_argument("--step1-only", action="store_true",
                        help="Run only Step 1 (per-node counts).")
    parser.add_argument("--step2-only", action="store_true",
                        help="Run only Step 2, reusing Step 1's cached counts from --out-dir.")
    parser.add_argument("--fresh", action="store_true",
                        help="Discard the Step 2 CSV/checkpoint and start over.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the queries and planned slices, without calling the API.")
    args = parser.parse_args()

    if args.step1_only and args.step2_only:
        parser.error("--step1-only and --step2-only are mutually exclusive")
    if args.slice_minutes < 1 or args.min_slice_minutes < 1:
        parser.error("--slice-minutes and --min-slice-minutes must be >= 1")
    if args.min_slice_minutes > args.slice_minutes:
        parser.error("--min-slice-minutes cannot exceed --slice-minutes")
    if args.split_minutes:
        # A split interval that isn't a whole number of slices would let one
        # slice straddle two files, so rows would land in the wrong interval.
        if args.split_minutes < args.slice_minutes:
            parser.error("--split-minutes (%d) cannot be smaller than "
                         "--slice-minutes (%d); a slice would straddle two files"
                         % (args.split_minutes, args.slice_minutes))
        if args.split_minutes % args.slice_minutes:
            parser.error("--split-minutes (%d) must be a multiple of "
                         "--slice-minutes (%d) so no slice straddles two files"
                         % (args.split_minutes, args.slice_minutes))
    if not args.token and not args.dry_run:
        parser.error("no token: set --token or the S1_SDL_TOKEN environment variable")

    if args.start:
        start = parse_bound(args.start)
        end = parse_bound(args.end) if args.end else datetime.now(timezone.utc)
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=args.hours)
    if start >= end:
        parser.error("the window is empty: start (%s) is not before end (%s)"
                     % (start.isoformat(), end.isoformat()))

    start_ms, end_ms = to_epoch_ms(start), to_epoch_ms(end)
    print("Window: %s -> %s  (%d -> %d ms)"
          % (start.isoformat(), end.isoformat(), start_ms, end_ms))
    # Always state the resolved absolute path, so where output landed is never a
    # guess — a relative --out-dir is easy to misjudge.
    print("Output: %s" % os.path.abspath(args.out_dir))

    if args.dry_run:
        print("\nStep 1 query:\n  %s" % QUERY_STEP1)
        print("\nStep 2 query:\n  %s" % QUERY_STEP2)
        print("\n%s is joined client-side on %s." % (JOINED_COLUMN, JOIN_KEY))
        slices = build_slices(start_ms, end_ms, args.slice_minutes)
        if args.split_minutes:
            preview = OutputSet(args.out_dir, start_ms, args.split_minutes * 60 * 1000)
            n = ((end_ms - start_ms - 1) // (args.split_minutes * 60 * 1000)) + 1
            print("\nOutput split every %d min -> %d file(s), e.g. %s"
                  % (args.split_minutes, n, os.path.basename(preview.path_for_index(0))))
        else:
            print("\nOutput: a single %s" % STEP2_CSV_NAME)
        print("\nStep 1: one call over the full window (%d ms)." % (end_ms - start_ms))
        print("Step 2: %d planned slice(s):" % len(slices))
        for slice_start, slice_end in slices:
            print("  [%d, %d)  (%.0f min)"
                  % (slice_start, slice_end, (slice_end - slice_start) / 60000.0))
        return

    os.makedirs(args.out_dir, exist_ok=True)
    if args.step2_only:
        counts = load_step1_counts(args.out_dir)
    else:
        counts = run_step1(args.host, args.token, start_ms, end_ms,
                           args.priority, args.out_dir)
    if not args.step1_only:
        run_step2(args.host, args.token, start_ms, end_ms, args.priority,
                  args.slice_minutes, args.min_slice_minutes, args.out_dir,
                  args.fresh, counts, args.split_minutes)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Step 2 checkpoints after each top-level slice, so a re-run resumes.
        sys.stderr.write("\nInterrupted. Re-run the same command to resume from "
                         "the last completed slice (or pass --fresh to restart).\n")
        raise SystemExit(130)
    except RuntimeError as exc:
        sys.stderr.write("\nError: %s\n" % exc)
        raise SystemExit(1)
