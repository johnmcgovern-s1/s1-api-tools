# s1-blocklist

Check whether a hash is **blocked by SentinelOne** — across all the systems that
can block it — and manage the Global Blocklist from the command line. Built for
the industry-group / ISAC IOC workflow: a hash is shared with a customer and they
need to answer, fast —

1. **Is this hash already blocked by S1 (any mechanism)?** → `check` (read-only)
2. **If not, add it to the blocklist.** → `add`

It also does `remove`, so `check` / `add` / `remove` cover the CRUD on blocklist
hash entries.

## "Blocked by S1" is three systems, not one

A hash can be enforced by any of three independent systems. Answering "is it
already blocked?" from the blocklist alone gives **false negatives** — a
feed-ingested or reputation-flagged hash isn't on the blocklist but is still
acted on. So `check` reports all three layers:

| Layer | System | API | Notes |
|---|---|---|---|
| 1 | **Global Blocklist** | `/restrictions` (`black_hash`) | The tenant's explicit deny list. What `add`/`remove` manage. |
| 2 | **Threat Intelligence IOCs** | `/threat-intelligence/iocs` | **Feed-ingested** indicators (Singularity Threat Intel, STIX, custom uploads). Where "ingested via a threat feed" lives. Supports MD5/SHA1/SHA256. |
| 3 | **Reputation verdict** | `hashes/{hash}/verdict` *(deprecated)* | S1's global cloud opinion, evaluated at execution. Not tenant data — no list API, only a per-hash lookup, only via the deprecated endpoint. Off by default (`--with-verdict`), best-effort. |

`check` emits **one row per hash** with a `coverage` verdict:

- `blocked` — on the blocklist **or** in an ingested feed (layer 1 or 2)
- `reputation-flagged` — not in tenant config, but S1 Reputation says `malicious`
  (only when `--with-verdict` ran)
- `not-blocked` — none of the above
- `unknown-md5` — an MD5 with no feed hit (the blocklist has no MD5 key and the
  verdict endpoint needs a SHA1, so it can't be confirmed here)

plus per-layer columns (`onBlocklist`, `inThreatIntel`, sources/scopes, verdict).

> ⚠️ **This tool writes.** `add` and `remove` **mutate the blocklist**. Both
> **default to a dry run** (query + report, change nothing) and require an
> explicit `--apply` to write. **A delete has no undo.** Always dry-run against a
> **test scope** first, read the CSV, and confirm `--account-id` / `--site-id` /
> `--group-id` point where you intend before applying.

Pure Python 3 standard library — no `pip install`. Copy the single file to a jump
host and it runs.

## Why not just `hashes/{hash}/verdict`?

That endpoint (`/web/api/v2.1/hashes/{hash}/verdict`) is the one most people find
first, but on its own it gives a misleading answer:

- It is **deprecated** in the API spec.
- It only ever covered **layer 3** above — the Reputation cloud's global opinion
  (`malicious` / `non-malicious` / `unknown`), where `unknown` just means S1's
  intel hasn't scored the hash. It says nothing about whether the hash is on your
  **blocklist** (layer 1) or in an **ingested feed** (layer 2). That's why a hash
  that is in fact blocked comes back `unknown`.

This tool uses it only as the best-effort layer-3 signal (`--with-verdict`) and
gets the definitive answer from the blocklist and IOC-store APIs. A verdict error
never fails the check.

## Host: the console, not the SDL endpoint

Unlike the SDL tools in this repo (which target `xdr.<geo>.sentinelone.net`),
this API lives on the **management console host itself** — the one you log in to,
e.g. `usea1-abc.sentinelone.net`. Pass **that** as `--host`.

## Token

A **console API token** for a service user. The management REST API expects it as
`Authorization: ApiToken <token>` (the tool sets that header for you). Pass it via
the env var so it stays out of shell history:

```bash
export S1_CONSOLE_TOKEN="<console API token>"
```

`--token` works as an override. The token needs permission to view (and, for
`add`/`remove`, manage) the blocklist at the scope you target.

## Scope

A blocklist entry lives at a scope — **Global** (tenant), **Account**, **Site**,
or **Group** — and is **inherited downward**. Every command requires a scope:

- `--tenant` — the Global scope
- `--account-id ID` / `--site-id ID` / `--group-id ID` — repeatable

For `check`, the tool asks with **`includeParents=true` by default**, so a hash
blocked at Global or Account shows as blocked even when you query a Site. Turn
that off with `--no-include-parents`. For `add`, the scope names *where the new
entry is created*.

## Per-OS entries

Blocklist entries are **per-OS** (the API requires `osType`). Blocking a hash for
"everything" is four entries. `add` takes `--os-type` (repeatable), and
`--os-type all` expands to `windows`, `macos`, `linux`, `windows_legacy`.

## Hash types

`value` on an entry is a **SHA1**, `sha256Value` is a **SHA256**. The tool
classifies each input by length (40 hex → SHA1, 64 → SHA256) and puts it in the
right field. **MD5** (32 hex) is **not** a blocklist key: an MD5 can't be added,
and `check` reports it as `unknown-md5` rather than guessing.

## Usage

```bash
export S1_CONSOLE_TOKEN="<console API token>"

# 1) Which of these shared IOCs do we already block? (read-only)
python3 tools/s1-blocklist/s1_blocklist.py check \
    --host usea1-abc.sentinelone.net \
    --account-id 12345 \
    --hash-file shared_iocs.txt \
    --with-verdict

# 2) Add the ones we don't — DRY RUN first (default), then --apply
python3 tools/s1-blocklist/s1_blocklist.py add \
    --host usea1-abc.sentinelone.net \
    --account-id 12345 \
    --hash-file shared_iocs.txt \
    --os-type all \
    --description "ISAC advisory 2026-08"
# ...read the report, then:
python3 tools/s1-blocklist/s1_blocklist.py add ... --apply

# 3) Remove entries for a hash — DRY RUN first, then --apply
python3 tools/s1-blocklist/s1_blocklist.py remove \
    --host usea1-abc.sentinelone.net \
    --account-id 12345 \
    --hash <sha1> --apply
```

`add` and `remove` first fetch what's already on the blocklist in scope, so:

- `add` never creates a duplicate of an existing `(hash, osType)` entry — it
  reports it as `already-blocked`. This means an `add` dry run **doubles as the
  "already blocked vs. need to add" answer** in one pass.
- `remove` resolves each hash to the actual entry ids to delete (only entries
  owned at the queried scope; inherited parent entries aren't deletable from a
  child scope).

## Output

Written to **`reports/blocklist/`** by default (override with `--out-dir`),
resolved from the script's own location. Per run:

- a timestamped **CSV**:
  - `check`: one row per hash — `coverage` (`blocked` / `reputation-flagged` /
    `not-blocked` / `unknown-md5`), plus per-layer columns `onBlocklist`,
    `blocklistOsTypes`/`blocklistScopes`/`blocklistSources`, `inThreatIntel`
    (`yes`/`no`/`skipped`/`error`), `threatIntelSources`/`threatIntelNames`, and
    `reputationVerdict` (with `--with-verdict`)
  - `add`: one row per (hash, osType) — `outcome` = `would-add` / `added` /
    `already-blocked` / `failed`
  - `remove`: one row per matched entry — `outcome` = `would-remove` / `removed`
    / `not-found` / `delete-failed`
- a timestamped **JSON manifest** — host, scope, command, and totals — a
  self-describing audit record of the run.

`reports/` is gitignored; tool output (customer data) is never committed.

## Options

Common to all commands: `--host`, `--token`, `--hash` (repeatable),
`--hash-file`, `--tenant` / `--account-id` / `--site-id` / `--group-id`,
`--include-children`, `--out-dir`.

- `check`: `--with-verdict` (layer 3), `--no-threat-intel` (skip layer 2),
  `--no-include-parents`
- `add`: `--os-type` (repeatable / `all`, **required**), `--description`,
  `--source`, `--apply`, `--dry-run`
- `remove`: `--apply`, `--dry-run`

## Tests

**Unit tests** — stdlib-only, no network (monkeypatch the API layer):

```bash
python3 tools/s1-blocklist/tests/test_s1_blocklist.py
```

**Read-only integration checks** — exercise the real read paths (blocklist GET +
paging, IOC lookup, deprecated verdict, and `includeParents`/scope behaviour)
against a live console. **No writes.** It's data-agnostic: it discovers a known
value from the tenant's own blocklist at runtime, so it hardcodes nothing
tenant-specific and works against any environment.

```bash
export S1_CONSOLE_TOKEN="<console API token>"
export S1_HOST="your-console.sentinelone.net"
export S1_ACCOUNT_ID="123..."          # and/or S1_SITE_ID
python3 tools/s1-blocklist/tests/integration_readonly.py
```

Exit code is 0 only if every assertion passes; skips (empty blocklist, no TI
permission, etc.) are reported but don't fail the run.
