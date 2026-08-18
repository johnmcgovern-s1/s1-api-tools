# sdl-k8s-process-report

Per-container Kubernetes report joined to per-node process-creation counts, over
the Singularity Data Lake PowerQuery API. Use it when the equivalent console
query times out — which it does on any sizeable fleet.

- **Step 1** counts `Process Creation` events per Kubernetes node (`agent.uuid`).
- **Step 2** pulls container/pod/label detail for container events in the window,
  one row per matching event, and attaches each row's node count from Step 1.

Output is one CSV: `eventCount` first, then `endpoint.name`, `agent.uuid`, and
the `k8sCluster.*` columns.

## Container scope: Kubernetes only, or every runtime?

The `k8sCluster.*` field family is a **misnomer**. Verified against a live tenant:
`k8sCluster.containerImage` and `k8sCluster.containerName` also populate for
**standalone containers (Docker/Podman) under the Linux agent** on ordinary
`server` endpoints — not just Kubernetes. The `k8sCluster.name` (cluster) field
is what's actually K8s-specific.

`--container-scope` sets the Step 2 filter accordingly:

| Scope | Step 2 filter | Captures |
|---|---|---|
| `k8s` (default) | `k8sCluster.name = *` | Only containers **in a Kubernetes cluster** — unchanged behaviour |
| `all` | `k8sCluster.containerImage = *` | **Every container the agent tags** — K8s pods *and* standalone Docker/Podman |

```bash
# fleet-wide container activity, any runtime
python3 tools/sdl-k8s-process-report/sdl_k8s_process_report.py \
    --host xdr.us1.sentinelone.net --hours 24 --container-scope all
```

In `all` scope, rows on non-Kubernetes endpoints have **blank `k8sCluster.name`,
`namespace`, and `podName`** (they aren't pods) and a **blank `eventCount`**
(Step 1 counts Process Creation only on `kubernetes node` endpoints). Both are
expected, not bugs — the blank cluster/pod columns are how you tell a standalone
container from a K8s one.

## Gotcha 1: `savelookup` write fails over the API (`lookup` read is fine)

The console version of this report used `savelookup` to write Step 1's aggregate
to a server-side CSV, then `lookup` to join it back in Step 2. Over the API that
returns:

```
HTTP 500  {"message":"internal Scalyr error while processing this query","status":"error/server"}
```

deterministically — `savelookup` writes to the tenant's shared file namespace,
which a read-scoped query can't do. The 500 is generic, not a validation error,
so it gives no hint on its own. (The `lookup` *read* is supported — pointing it at
a missing file returns a clean `400 error/client/badParam` — but with no way to
create the file over a read-scoped API, the pair is unusable.)

**So the join is done client-side**: Step 1's counts are held in memory (and
cached to CSV), and `eventCount` is attached to each Step 2 row in Python, keyed
on `agent.uuid`. Same output, no server-side state — which also means concurrent
runs on one tenant can't clobber each other, `--step2-only` doesn't depend on
server state, and a Log-Read-only token is sufficient.

Two related syntax notes:

- **Single quotes are invalid over the JSON API.** The console form used
  `'kubernetes node'`; the API needs `"kubernetes node"` — *"For JSON requests,
  single quotes are invalid, and you must `\"` escape double quotes in strings"*
  (SDL powerQuery docs). Sending the UI form verbatim is another HTTP 500.
- **Queries are sent single-line.** Every example in the SDL docs is single-line;
  multi-line text was the other candidate cause of that 500.

The practical consequence: **the two-step console instructions can't be automated
as written.** Anything scripted against this data needs the client-side join.

## Gotcha 2: PowerQuery has no pagination

`/api/powerQuery` is **synchronous and carries neither `maxCount` nor
`continuationToken`** — compare `/api/query`, which has both. Switching to
`/api/query` isn't an option: `group` and `columns` are PowerQuery-only.

What PowerQuery reports instead is **`omittedEvents`** — rows silently dropped
when a result exceeds the server's in-memory limit. So a single large call can
return a *quietly incomplete* table with HTTP 200 and `status: success`. **That,
not the timeout, is the real hazard**, and it's the reason to use this rather
than a hand-rolled curl call.

The only way to page it is client-driven **time-slicing**:

- **Step 1** aggregates to one row per node, so it's very unlikely to truncate —
  the console limit it hits is a UI/gateway timeout, not the backend's compute
  budget. It runs as one call with a 600s client-side timeout.
- **Step 2** returns one row per raw event, so it's sliced. Any slice reporting
  `omittedEvents > 0` is **bisected and retried** down to `--min-slice-minutes`;
  the truncated response is discarded in favour of its halves. If a slice is
  still truncated at the floor, the tool **warns and reports the approximate rows
  lost** rather than presenting a partial CSV as complete.
- Rows stream to CSV as they arrive, with a checkpoint after each top-level
  slice, so an interrupted run resumes instead of restarting.

Time bounds go out as absolute epoch-ms, never relative (`24h`), so slices are
stable and reproducible across a long run.

**Window size, not query complexity, is the dominant cost.** A fleet-wide
aggregation (e.g. counting all Process Creation, unfiltered) times out even over
a few minutes, while the same query over a small window returns instantly. Every
query here leads with an indexed `field = value` filter and Step 2 is sliced, so
this is handled — but keep it in mind if you adapt the queries: filter first, and
widen the window gradually.

## Usage

```bash
export S1_SDL_TOKEN="<SDL Log Read Access token>"
```

Start with **one hour** to confirm host, auth, and that the data looks right:

```bash
python3 tools/sdl-k8s-process-report/sdl_k8s_process_report.py \
    --host xdr.us1.sentinelone.net \
    --start 2026-08-17T00:00:00Z --end 2026-08-17T01:00:00Z
```

Then widen to the full window:

```bash
python3 tools/sdl-k8s-process-report/sdl_k8s_process_report.py \
    --host xdr.us1.sentinelone.net --hours 24
```

Output goes to **`reports/k8s/`** in the project root by default — no `--out-dir`
needed. That path is resolved from the script's own location, not your current
directory, so it lands in the same place wherever you invoke it from. Every run
prints the resolved absolute path as its second line.

Preview the queries and slice plan without touching the API:

```bash
python3 sdl_k8s_process_report.py --host xdr.us1.sentinelone.net --hours 24 --dry-run
```

`--host` is the **SDL** endpoint for the tenant's geo, not the console host — see
the mapping table in the [root README](../../README.md).

### Options

| Flag | Default | Notes |
|---|---|---|
| `--host` | *required* | SDL endpoint, e.g. `xdr.us1.sentinelone.net` |
| `--token` | `$S1_SDL_TOKEN` | Prefer the env var |
| `--container-scope` | `k8s` | `k8s` = Kubernetes clusters only; `all` = every container incl. standalone Docker/Podman |
| `--hours` | `24` | Window ending now; ignored if `--start` is given |
| `--start` / `--end` | — | Absolute ISO 8601 bounds, e.g. `2026-08-17T00:00:00Z` |
| `--slice-minutes` | `60` | Step 2 top-level slice width |
| `--min-slice-minutes` | `1` | Bisection floor for truncated slices |
| `--split-minutes` | `0` (single file) | Split output into one CSV per N-minute interval; must be a multiple of `--slice-minutes` |
| `--priority` | `low` | `low` has more generous rate limits |
| `--out-dir` | `<repo>/reports/k8s` | CSVs + checkpoint land here; resolved from the script's location, not the cwd |
| `--step1-only` / `--step2-only` | — | Run one step; `--step2-only` reuses cached counts |
| `--fresh` | — | Discard the Step 2 CSV/checkpoint and start over |
| `--dry-run` | — | Print queries + slice plan and exit |

### Splitting output into multiple files

A 24-hour run over a busy fleet produces one very large CSV. `--split-minutes`
breaks it into one file per interval:

```bash
python3 tools/sdl-k8s-process-report/sdl_k8s_process_report.py \
    --host xdr.us1.sentinelone.net --hours 24 --split-minutes 60
```

That yields `k8s_container_report_20260817T000000Z.csv`,
`..._20260817T010000Z.csv`, … one per hour, each with its own header row, plus a
`k8s_container_report_manifest.json` recording the window, both queries, per-file
row counts, and totals — so a multi-file deliverable is self-describing.

Two things worth understanding:

- **File boundaries are decoupled from query slices.** Bisection makes slices
  non-uniform (a truncated hour becomes 2×30min, then 4×15min), so
  file-per-slice would give irregular files whose count depends on data density.
  Intervals are fixed wall-clock windows instead, and `--split-minutes` is
  validated as a multiple of `--slice-minutes` so no slice straddles two files.
- **This bounds file *duration*, not file *size*.** A single very busy hour still
  produces a large hourly file. If a hard size ceiling is what you need, ask for
  a row-count-based split — it's a different axis and not implemented.

Resume works across splits: intervals are numbered from the run's window start,
not the resume point, so a resumed run keeps writing into the same files without
duplicating headers.

### Output

In `reports/k8s/` (or wherever `--out-dir` points):

| File | Contents |
|---|---|
| `k8s_node_process_counts.csv` | Step 1's per-node counts (`agent.uuid`, `eventCount`). Also the cache `--step2-only` reads |
| `k8s_container_report.csv` | The report — the deliverable. With `--split-minutes`, becomes `k8s_container_report_<YYYYMMDDTHHMMSSZ>.csv` per interval |
| `k8s_container_report_manifest.json` | Written when output is split: window, queries, per-file row counts, totals |
| `k8s_container_report.csv.checkpoint.json` | Resume marker; delete it or pass `--fresh` to restart |

`reports/` is gitignored, so output stays out of git by default. That's a
backstop, not a substitute for care: **these CSVs contain customer data**
(hostnames, container images, pod names, namespaces, labels). If you copy this
tool to a jump host on its own, the default becomes `./reports/k8s` relative to
your current directory, since there's no project root to anchor to.

## Operational notes

- **Both steps must use the same window**, or `eventCount` won't correspond to the
  detail rows. A wider Step 2 window yields blank `eventCount` for nodes outside
  Step 1's range.
- **Blank `eventCount` is expected, not a bug**, for pods on nodes with no
  `Process Creation` events in the window. The run reports how many rows were
  unmatched so you can sanity-check the number.
- **`--step2-only` reads `k8s_node_process_counts.csv`** from `--out-dir`. It
  errors clearly if Step 1 hasn't run — no silent empty join.
- **Read the stderr warnings.** A clean run ends with "No unresolved truncation";
  anything else means rows were dropped and the window needs smaller slices.
- If Step 1 itself warns about truncation, don't trust the `eventCount` column —
  narrow the window instead.
- **If it fails with an opaque 500**, run
  [`sdl-powerquery-probe`](../sdl-powerquery-probe/) to find which construct the
  API is rejecting.
