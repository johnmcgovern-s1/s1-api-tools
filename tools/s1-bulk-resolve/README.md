# s1-bulk-resolve

Bulk-resolve SentinelOne alerts via the **Unified Alerts GraphQL API**. Matches
alerts by a caller-defined filter in a scope, then sets their status (and,
optionally, analyst verdict and a note) in bulk.

Primary use case: a **spurious alert flooding the console** and degrading
performance — match it, confirm the count in a dry run, then resolve it away.

This is the Python successor to the `bulk-resolve-identity-alerts` Postman
collection, which was hardcoded to Identity + `NEW` with one fixed verdict/note
and had no dry run and no report. This tool is generic across alert types and
follows the house conventions of the other tools here.

> ⚠️ **This tool writes.** With `--apply` it **mutates alert state in bulk** —
> status, verdict, note — across an entire scope. **There is no undo.** It
> **defaults to a dry run** (queries and reports, changes nothing); you must pass
> `--apply` to write. Always dry-run against a **test scope** first, read the CSV,
> and confirm `--scope-id` / filters point where you intend before applying.

Pure Python 3 standard library — no `pip install`. Copy the single file to a jump
host and it runs.

## Host: the console, not the SDL endpoint

Unlike the SDL tools in this repo (which target `xdr.<geo>.sentinelone.net`), this
API lives on the **management console host itself** — the one you log in to, e.g.
`usea1-abc.sentinelone.net`. Pass **that** as `--host`, not an `xdr.*` host.

## Token

A **console API token** for a service user (the same kind the Postman collection
used as `SERVICE_USER_TOKEN`) — *not* an SDL Data Lake key. Prefer the env var so
it stays out of your shell history:

```bash
export S1_CONSOLE_TOKEN="<console API token>"
```

`--token` overrides it. `unset` it when you're done.

## Quick start

```bash
# 1) Discover valid alert fields / enum names on your tenant (optional but wise)
python3 s1_bulk_resolve.py --host usea1-abc.sentinelone.net --introspect

# 2) DRY RUN (default): match + report, change nothing
python3 s1_bulk_resolve.py --host usea1-abc.sentinelone.net \
    --scope-type ACCOUNT --scope-id 12345 \
    --product Identity --status NEW \
    --resolve --verdict FALSE_POSITIVE_USER_ERROR \
    --note "Bulk closed: spurious Over-PtH false positives; exclusions added."

# 3) Read reports/bulk-resolve/bulk_resolve_<ts>.csv. If it looks right:
python3 s1_bulk_resolve.py ...same args... --apply
```

Start with a **narrow filter and a test scope**. Confirm the matched count and the
CSV before you add `--apply`.

## How it works — two phases

1. **Collect** — pages the `alerts` query (cursor-based: `first` + `after`) until
   there are no more pages, gathering every matching alert. Cursor paging is used
   deliberately: the Postman "refetch until the `NEW` set is empty" loop only
   terminates when the filter is status-based; a non-status filter would re-return
   the same alerts forever.
2. **Apply** *(only with `--apply`)* — walks the collected IDs in `--batch-size`
   chunks; one `alertTriggerActions` mutation per chunk applies every action. Each
   alert's outcome is read back from the mutation's `success` / `failure` / `skip`
   lists. A **checkpoint** after each batch means an interrupted apply resumes
   (re-run the same command) instead of re-mutating from the top.

A dry run does phase 1 only and marks every row `would-resolve`.

## Filters — match the alerts you mean

All clauses are ANDed by the API. Nothing is hardcoded.

| Flag | Effect |
|---|---|
| `--product NAME` | `detectionProduct = NAME` (e.g. `Identity`) |
| `--status VALUE` | `status = VALUE` (e.g. `NEW`) |
| `--filter FIELD=VALUE` | generic `stringEqual` clause; repeatable |
| `--filter-file PATH` | raw GraphQL `filters` array as JSON; mutually exclusive with the three above, for operators the shorthands don't cover |
| `--match-all` | required to proceed with **no** filters (would match every alert in scope) — a deliberate foot-gun guard |

## Actions — what to do to each match (≥1 required)

| Flag | Effect |
|---|---|
| `--resolve` | set status to `RESOLVED` (alias for `--set-status RESOLVED`) |
| `--set-status ENUM` | set status to an arbitrary enum value |
| `--verdict ENUM` | set analyst verdict, e.g. `FALSE_POSITIVE_USER_ERROR` |
| `--note TEXT` | attach a note |

## Other options

| Flag | Default | Notes |
|---|---|---|
| `--apply` | off (dry run) | actually write. Without it, nothing is mutated |
| `--dry-run` | — | explicitly force a dry run (handy to defeat an aliased `--apply`) |
| `--fields A,B,C` | `id,name,detectedAt,status,analystVerdict,detectionProduct,severity` | alert node fields for the CSV; `id` always included |
| `--batch-size N` | `250` | alerts per query page and per mutation batch |
| `--scope-type` | — | `ACCOUNT`, `SITE`, or `GROUP` (required) |
| `--scope-id ID` | — | repeatable (required) |
| `--out-dir DIR` | `<repo>/reports/bulk-resolve` | resolved from the script's location, not the cwd |

## Output

Written to `reports/bulk-resolve/` (override with `--out-dir`). The resolved
absolute path is printed on every run. Per run:

- **`bulk_resolve_<ts>.csv`** — one row per matched alert: the requested
  `--fields` plus an `outcome` column
  (`would-resolve` in a dry run; `resolved` / `failed` / `skipped` / `unknown`
  after `--apply`).
- **`bulk_resolve_<ts>_manifest.json`** — host, scope, the resolved `filters`
  array, actions, `dryRun`, batch size, and totals. A self-describing audit
  record of the run.

**Both contain customer data** (alert names, assets). `reports/` is gitignored,
but prefer an `--out-dir` outside the repo and handle per the customer's
data-handling agreement.

## Alert fields are schema-dependent — use `--introspect`

The exact field names on the `Alert` type vary by tenant/version. The default
`--fields` set is a best-effort guess. If the API rejects one
(`Cannot query field X on type Alert`), the tool surfaces that error and points
you at `--introspect`, which lists the valid `Alert` fields (and explains how to
list enum values). Adjust `--fields` and re-run — no code edit needed. The same
applies to `--verdict` / `--set-status` enum values.

## Safety recap

- Dry run is the default; `--apply` is the only thing that writes.
- Empty filters are refused unless you pass `--match-all`.
- Enum-valued flags (`--set-status`, `--verdict`, `--scope-type`) are validated so
  a value can't break out of its position in the generated query; string values
  (notes, filter values) are JSON-escaped.
- An interrupted `--apply` resumes from a per-run checkpoint on re-run.

## Testing

Stdlib-only tests under `tests/` monkeypatch the request function and drive the
logic that actually breaks — cursor paging, batch chunking, outcome folding,
resume, and query rendering — with synthetic responses (no network):

```bash
python3 tools/s1-bulk-resolve/tests/test_s1_bulk_resolve.py
```

Mock tests prove the logic, not that your tenant accepts the query. Before a real
run, `--introspect` and then dry-run against a small test scope.
