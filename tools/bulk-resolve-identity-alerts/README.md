# bulk-resolve-identity-alerts

> ⛔ **Superseded by [`s1-bulk-resolve`](../s1-bulk-resolve/).** That Python CLI
> does everything this collection does and generalizes it: any alert filter (not
> just Identity + `NEW`), configurable actions, a **dry-run default** with an
> explicit `--apply` to write, and a per-alert CSV + run manifest. Prefer it for
> new work. This collection is kept for reference and for anyone mid-transition.

A Postman collection that bulk-resolves SentinelOne **Identity** alerts via the
Unified Alerts GraphQL API. It pages through `NEW` alerts in a target scope and,
for each page, fires one mutation that resolves every alert, sets the analyst
verdict to **False Positive – User Error**, and attaches a closing note.

> ⚠️ **This tool writes.** Unlike the other tools in this repo (which only read),
> it **mutates alert state in bulk** — resolving alerts, setting verdicts, and
> adding notes across an entire scope. There is no dry-run and no undo. Run it
> against a **test scope first**, confirm the counts in the Postman Console, and
> be sure `SCOPE_ID` / `SCOPE_TYPE` point where you intend before running against
> production.

It is a **Postman collection**, not a Python CLI — a different form factor from
the other tools here. It needs Postman (desktop or web); nothing to install
beyond that.

## How it works

The collection uses Postman's `pm.execution.setNextRequest` to create a two-step
loop:

1. **`getAlertIds`** — queries up to 250 `NEW` Identity alerts in the target
   scope and stores their IDs in a collection variable.
2. **`resolveAlertBatch`** — builds an `alertTriggerActions` mutation from those
   IDs (using `or` filter clauses), fires it, and logs success/failure/skip
   counts to the Postman Console.

The Collection Runner cycles `getAlertIds → resolveAlertBatch` until no `NEW`
Identity alerts remain in the scope, then stops.

## Import

You need both files in this directory:

- `bulk-resolve-identity-alerts.postman_collection.json` — the requests + scripts
- `bulk-resolve-identity-alerts.postman_environment.json` — the config template

In Postman, **Import** each file (**Import** button → drag the file in). Then
select the imported environment from the environment dropdown (top-right).

## Configure

With the environment selected, open its variable editor (eye icon, or
**Environments** in the sidebar) and fill the **Current Value** column:

| Variable | Description |
|---|---|
| `SERVICE_USER_TOKEN` | API bearer token for your SentinelOne service user (typed `secret`) |
| `URL` | Console base URL, e.g. `https://usea1-abc.sentinelone.net` |
| `SCOPE_ID` | The account or site ID to target |
| `SCOPE_TYPE` | `ACCOUNT` or `SITE` |

The environment template ships with **empty values** — nothing sensitive is
committed. Fill them in your own Postman, not in the file.

## Run

Must be run with the **Collection Runner** — sending requests one at a time from
the sidebar won't work, because the loop relies on the runner's sequencing.

1. Hover the collection in the sidebar → **▶ Run** (or right-click → **Run
   collection**).
2. Check both **getAlertIds** and **resolveAlertBatch**.
3. Set **Iterations** to `1` (the collection loops itself internally via
   `setNextRequest`).
4. Click **Run**.
5. Watch the **Postman Console** (View → Postman Console) for per-batch
   fetched/resolved counts.

## What the mutation does to each alert

- Status → **Resolved**
- Analyst verdict → **False Positive – User Error**
- Adds a note: *"Alert bulk closed while addressing False Positives related to
  Over Pass-The-Hash attacks. Exclusions have been added for the False Positives
  and this alert will regenerate on next attempt."*

To change the verdict or note wording, edit the `resolveAlertBatch` request body
in the collection before running.
