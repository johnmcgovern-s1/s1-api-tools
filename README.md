# SentinelOne API Tools

Runnable command-line tools that call the SentinelOne APIs to do things the
console can't — reports too large for the UI, bulk extracts, diagnostics.

Every tool is **pure Python 3 standard library** — no `pip install`, no
`requirements.txt`. Copy a single file to a jump host, or hand it to a customer,
and it runs.

---

## Tools

| Tool | Use it for |
|---|---|
| [`sdl-k8s-process-report`](tools/sdl-k8s-process-report/) | Per-container Kubernetes report joined to per-node process-creation counts, over the SDL PowerQuery API. Pages a query that times out in the console. |
| [`sdl-powerquery-probe`](tools/sdl-powerquery-probe/) | Diagnose a failing PowerQuery by bisecting it — sends a ladder of progressively complex queries and reports which construct the API rejects. |

Each tool directory has its own README with usage, options, and output.

---

## Quick start

Run from the project root:

```bash
export S1_SDL_TOKEN="<SDL Log Read Access token>"
python3 tools/sdl-k8s-process-report/sdl_k8s_process_report.py \
    --host xdr.us1.sentinelone.net --hours 24
```

Start with a **short window** (an hour) to confirm host and auth before running
the full range.

### Where output goes

Tools write to **`reports/<tool>/`** in the project root — e.g.
`reports/k8s/`. The path is resolved from the tool's own location rather than
your current directory, so it's the same wherever you invoke from, and each run
prints the resolved absolute path. `reports/` is gitignored.

Override with `--out-dir` when you need output elsewhere.

### Tokens

SDL tools want an SDL key scoped to the operation — **Log Read Access** for
queries. A SentinelOne console user API token also works against the SDL API.
Pass it via `S1_SDL_TOKEN` rather than `--token` so it stays out of your shell
history, and `unset` it when you're done.

### Hosts: the SDL endpoint is not your console

The Data Lake API lives on a **different host** from the management console, per
tenant geo. A `usea1-purple.sentinelone.net` console maps to
`xdr.us1.sentinelone.net`, not to itself.

| SDL host | Region |
|---|---|
| `xdr.us1.sentinelone.net` | AWS us-east-1 (Prod) |
| `xdr.na4.sentinelone.net` | GCP us-central1 (Prod) |
| `xdr.ca1.sentinelone.net` | AWS ca-central-1 |
| `xdr.eu1.sentinelone.net` | AWS eu-central-1 (Frankfurt) |
| `xdr.euw31.sentinelone.net` | GCP europe-west3 |
| `xdr.aps1.sentinelone.net` | AWS ap-south-1 (Mumbai) |
| `xdr.ap1.sentinelone.net` | AWS ap-southeast-1 (Singapore) |
| `xdr.apse2.sentinelone.net` | AWS ap-southeast-2 (Sydney) |
| `xdr.me1.sentinelone.net` | GCP me-central2 |
| `xdr.usgw14.s1gov.net` | AWS GovCloud us-gov-west-1 (Fed Prod) |
| `app.scalyr.com` / `app.eu.scalyr.com` | DataSet direct (US / EU) |

Source: SentinelOne's Singularity Data Lake (DataSet) API documentation.

---

## Customer data

**Tool output routinely contains customer data** — hostnames, container images,
pod names, namespaces, labels. `.gitignore` blocks the usual output paths and
`*.csv` / `*.json` reports, but that's a backstop, not a policy. Prefer an
`--out-dir` outside the repo (`~/reports/...`) and handle the results according
to the customer's data-handling agreement.

---

## SDL PowerQuery: three constraints worth knowing up front

Learned the hard way; each one costs an afternoon if you don't know it.

1. **`savelookup` / `lookup` don't work over the API.** They return a
   deterministic `HTTP 500 error/server` ("internal Scalyr error while processing
   this query") — a read-scoped query can't write the tenant's shared file
   namespace. Join client-side instead. **Console reports built on `savelookup`
   cannot be automated as written.**
2. **Single quotes are invalid in JSON requests.** The console accepts
   `endpoint.type = 'kubernetes node'`; the API needs escaped double quotes.
   Sending the UI form verbatim is another HTTP 500. Send queries single-line too.
3. **`/api/powerQuery` has no pagination** — no `maxCount`, no
   `continuationToken` (unlike `/api/query`). Over-limit results are signalled
   *only* by `omittedEvents` in the body, so a large call can return a **quietly
   incomplete** table with HTTP 200 and `status: success`. Page by time-slicing.

For raw telemetry, **GraphQL is not an alternative**: the Unified Alerts GraphQL
API is entirely alert-scoped, and its Kubernetes fields are alert context ("at
the time of detection"), not a queryable event stream.

---

## Adding a tool

See [CONTRIBUTING.md](CONTRIBUTING.md).
