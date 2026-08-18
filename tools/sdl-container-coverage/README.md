# sdl-container-coverage

Two diagnostics for the question **"can we see all container activity across the
fleet, regardless of runtime?"** They answer it from the tenant's own data rather
than from the docs — which turn out to be misleading on this point.

| Script | Answers |
|---|---|
| `container_coverage_probe.py` | Survey: how much container telemetry falls under Kubernetes (`k8sCluster.*`) vs AWS ECS (`task.*`) vs neither, in this tenant/window. |
| `demo_nonk8s_containers.py` | Proof: a side-by-side count plus a table of **real standalone containers** (Docker/Podman) on non-Kubernetes endpoints, written to a CSV you can hand to a stakeholder. |

## The finding these encode

SentinelOne has **no runtime-agnostic container field**. Container context is
fragmented by orchestrator:

| Runtime | Field namespace |
|---|---|
| Kubernetes (incl. OpenShift, EKS/GKE/AKS, EKS Fargate) | `k8sCluster.*` |
| AWS ECS / Fargate-on-ECS | `task.*` (`task.cluster`, `task.taskArn`, `task.ecsVersion`, …) |
| Standalone Podman/Docker/containerd (no orchestrator) | *(no dedicated fields)* |

But the `k8sCluster.*` family is a **misnomer**: `k8sCluster.containerImage` and
`k8sCluster.containerName` also populate for **standalone containers under the
Linux agent** on ordinary `server` endpoints — verified against a live tenant
(real `traefik`, `crowdsec`, … containers with a blank `k8sCluster.name`). Only
`k8sCluster.name` / `namespace` / `podName` are truly Kubernetes-specific.

So `k8sCluster.name = *` (the report's default filter) sees Kubernetes only;
`k8sCluster.containerImage = *` also catches standalone containers. That's exactly
the `--container-scope all` switch in
[`sdl-k8s-process-report`](../sdl-k8s-process-report/).

For raw telemetry, **GraphQL is not an alternative** — the Unified Alerts GraphQL
API is entirely alert-scoped, and its Kubernetes fields are alert context ("at
the time of detection"), not a queryable event stream.

## Usage

```bash
export S1_SDL_TOKEN="<SDL Log Read Access token>"

# 1. Survey what container telemetry exists in this tenant
python3 tools/sdl-container-coverage/container_coverage_probe.py \
    --host xdr.us1.sentinelone.net

# 2. Prove standalone (non-K8s) container activity, with an evidence CSV
python3 tools/sdl-container-coverage/demo_nonk8s_containers.py \
    --host xdr.us1.sentinelone.net --minutes 240
```

`--host` is the **SDL** endpoint for the tenant's geo, not the console host — see
the mapping table in the [root README](../../README.md).

### container_coverage_probe.py

Runs seven read-only aggregations and prints a coverage summary. The number that
decides whether the report needs ECS support is **`task.taskArn`** — non-zero
means ECS workloads are present that a Kubernetes-only filter misses.

| Flag | Default | Notes |
|---|---|---|
| `--host` | *required* | SDL endpoint |
| `--token` | `$S1_SDL_TOKEN` | Prefer the env var |
| `--minutes` | `10` | Window ending now. **Window size dominates cost** — fleet-wide aggregations time out over an hour but are fine over ~10 min |
| `--hours` | — | Alternative to `--minutes`; use small values |
| `--max-rows` | `15` | Rows to print per probe before summarizing |

### demo_nonk8s_containers.py

Prints the Kubernetes-scoped vs non-Kubernetes container counts over the same
window, a table of the actual non-K8s containers (named images, on `server`
endpoints, with `cluster`/`podName` shown blank), and writes the full table to a
CSV.

| Flag | Default | Notes |
|---|---|---|
| `--host` | *required* | SDL endpoint |
| `--token` | `$S1_SDL_TOKEN` | Prefer the env var |
| `--minutes` | `10` | Standalone-container activity is **bursty** — widen to `240`+ if a short window comes back empty |
| `--out-dir` | `<repo>/reports/container-coverage` | Evidence CSV lands here; resolved from the script's location. Contains customer data |

## Notes

- **Every query leads with an indexed `field = value` filter.** Unfiltered
  aggregations (a bare `| group count() by X`) full-scan the window and time out
  even over minutes. If you adapt these, filter first and widen the window
  gradually.
- **Standalone-container process activity is bursty.** A quiet 10-minute window
  can show zero non-K8s containers while a 4-hour window shows plenty. When the
  demo finds nothing, it tells you to widen `--minutes`.
- **The demo's CSV contains customer data** (hostnames, container/image names).
  It defaults into the gitignored `reports/` tree; keep it there or somewhere
  outside the repo.
- `podName` / `namespace` come back **blank** for standalone containers — they
  aren't pods. That's expected and is itself the evidence that they're not
  Kubernetes.
