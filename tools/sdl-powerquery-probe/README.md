# sdl-powerquery-probe

Diagnose a failing PowerQuery by bisecting it. Sends a ladder of progressively
more complex queries over a short window and reports which succeed — **the first
FAIL identifies the construct the API is rejecting.**

Built because `/api/powerQuery` answers a malformed or unsupported query with a
generic, unhelpful 500:

```
HTTP 500  {"message":"internal Scalyr error while processing this query","status":"error/server"}
```

No indication of *which* part of the query is at fault. Rather than guess one
edit at a time against a slow query, this isolates every variable in one run.

## Usage

```bash
export S1_SDL_TOKEN="<SDL Log Read Access token>"
python3 probe_powerquery.py --host xdr.us1.sentinelone.net
```

| Flag | Default | Notes |
|---|---|---|
| `--host` | *required* | SDL endpoint, e.g. `xdr.us1.sentinelone.net` |
| `--token` | `$S1_SDL_TOKEN` | Prefer the env var |
| `--minutes` | `5` | Window size — kept small so probes are cheap |

Each probe is a separate call with **no retries**, so the run fails fast and
finishes in seconds.

## What it isolates

The ladder as shipped targets the Kubernetes process-count report, but it's meant
to be **edited** — change the `PROBES` list to bracket whatever query is failing.

| Probes | Question answered |
|---|---|
| 1–2 | Does powerQuery work at all with this token and host? |
| 3 | Is multi-line query text tolerated? (all doc examples are single-line) |
| 4–6 | `AND` vs implicit AND; does the `endpoint.type` filter work? |
| 7 | Does `savelookup` work? *(spoiler: no — see below)* |
| 8–9 | Wildcard filters, and `lookup` against a missing file |

Probes 1–2 are the ones people skip and shouldn't: if the token lacks Log Read
scope or the host is the console rather than the SDL endpoint, everything else is
noise.

## Known results

Established against a live tenant (Aug 2026):

- **Probe 7 (`savelookup`) fails.** A read-scoped query can't write the tenant's
  shared file namespace. Any report depending on `savelookup`/`lookup` must do
  the join client-side — see
  [`sdl-k8s-process-report`](../sdl-k8s-process-report/) for the pattern.
- **Single quotes fail** anywhere in a JSON request body, even though the console
  accepts them.

## Writing a good probe ladder

- **Order simplest to most complex**, changing **one thing per rung**. If two
  rungs differ by two edits, a failure doesn't tell you which one caused it.
- **Include a trivial sanity rung** that should always pass. If rung 1 fails, the
  problem is auth, host, or scope — not syntax.
- **Keep the window tiny.** You're testing acceptance, not gathering data.
- **Probe destructive or writing commands last**, after the read-only rungs have
  established a baseline.
