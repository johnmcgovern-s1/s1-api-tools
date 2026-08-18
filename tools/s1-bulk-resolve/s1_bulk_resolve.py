#!/usr/bin/env python3
"""Bulk-resolve SentinelOne alerts via the Unified Alerts GraphQL API.

Matches alerts by a caller-defined filter in a scope, then (optionally) sets
their status, analyst verdict, and a note in bulk. Defaults to a **dry run** —
it queries and writes a report but changes nothing — and requires an explicit
`--apply` to write. The main use case is a spurious alert flooding the console
and degrading performance: match it, confirm the count in a dry run, then resolve.

This replaces the Postman collection `bulk-resolve-identity-alerts`, which was
hardcoded to Identity + NEW with one fixed verdict/note and no dry run or report.

⚠️  THIS TOOL WRITES. Unlike the read-only tools in this repo, `--apply` mutates
    alert state in bulk (status, verdict, note). There is no undo. Always dry-run
    against a TEST scope first and read the report before applying.

Pure stdlib. Usage:

    export S1_CONSOLE_TOKEN="<console API token for a service user>"

    # dry run (default): match, report, change nothing
    python3 s1_bulk_resolve.py --host usea1-abc.sentinelone.net \\
        --scope-type ACCOUNT --scope-id 12345 \\
        --product Identity --status NEW \\
        --resolve --verdict FALSE_POSITIVE_USER_ERROR --note "cleared: spurious flood"

    # same command with --apply actually resolves the matched alerts
    python3 s1_bulk_resolve.py ... --apply

    # discover valid alert node fields / enum values for --fields, --verdict, etc.
    python3 s1_bulk_resolve.py --host ... --introspect

--- Host: the console, not the SDL endpoint ------------------------------------

Unlike the SDL tools in this repo (which target `xdr.<geo>.sentinelone.net`),
this API lives on the **management console host itself** — the one you log in to,
e.g. `usea1-abc.sentinelone.net`. Pass that as --host.

--- Two phases -----------------------------------------------------------------

  1. Collect  Page the `alerts` query (cursor-based: first + after) until
              hasNextPage is false, gathering every matching alert's id plus the
              report fields. Cursor paging (not the Postman "refetch until empty"
              loop) is used because a non-status filter would otherwise re-return
              the same alerts forever.
  2. Apply    (only with --apply) Walk the collected ids in --batch-size chunks;
              one alertTriggerActions mutation per chunk applies every action.
              Each alert's outcome is read back from the mutation's
              success/failure/skip lists. A checkpoint after each batch lets an
              interrupted apply resume instead of re-mutating from the top.

Dry run runs phase 1 only and marks every row `would-<status>`.

Matched alerts are held in memory (id + a handful of fields) so the CSV can carry
each alert's final outcome. Alert counts — even a "flood" — are bounded (thousands
to tens of thousands), so this is fine; it is not the unbounded telemetry the SDL
tools stream.

--- Report ---------------------------------------------------------------------

Written to reports/bulk-resolve/ (override with --out-dir). Per run:
  * a timestamped CSV, one row per matched alert: the requested --fields plus an
    `outcome` column (would-resolve / resolved / failed / skipped).
  * a timestamped JSON manifest: host, scope, resolved filters, actions, dryRun,
    and totals — a self-describing audit record of the run.

--- Alert node fields are schema-dependent -------------------------------------

The exact field names on the Alert type vary by tenant/version. The default
--fields set below is a best-effort guess. If the API rejects one ("Cannot query
field X on type Alert"), this tool prints that error and points you at
--introspect, which lists the valid Alert fields and enum values. Adjust --fields
and re-run — no code edit needed.
"""

import argparse
import csv
import json
import os
import re
import ssl
import sys
import time
import http.client
import urllib.error
import urllib.request
from datetime import datetime, timezone

GRAPHQL_PATH = "/web/api/v2.1/unifiedalerts/graphql"

# Default alert node fields pulled into the report. Best-effort — verify with
# --introspect; override with --fields. `id` is required (it is the join/action
# key) and is always included even if omitted here.
DEFAULT_FIELDS = [
    "id",
    "name",
    "detectedAt",
    "status",
    "analystVerdict",
    "detectionProduct",
    "severity",
]

# GraphQL action IDs (from the Unified Alerts API; see the superseded Postman
# collection). payload value fields differ per action.
ACTION_STATUS = "S1/alert/statusUpdate"
ACTION_VERDICT = "S1/alert/analystVerdictUpdate"
ACTION_NOTE = "S1/alert/addNote"

# An enum literal in GraphQL is an unquoted identifier. Validate anything we drop
# into the query unquoted so a stray value can't break out of its position.
ENUM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 6
INITIAL_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 300


def warn(message):
    sys.stderr.write("  [warn] %s\n" % message)


def default_out_dir():
    """`<repo>/reports/bulk-resolve`, resolved from this file, not the cwd.

    A cwd-relative default scatters customer data wherever the operator happened
    to be standing. Falls back to a cwd-relative path when the file has been
    copied out of the repo on its own (a supported way to run these tools).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))  # tools/<tool>/ -> root
    if os.path.isdir(os.path.join(repo_root, "tools")):
        return os.path.join(repo_root, "reports", "bulk-resolve")
    return os.path.join("reports", "bulk-resolve")


# --- HTTP / GraphQL ---------------------------------------------------------

def post_json(url, token, payload, what):
    """POST a JSON payload, retrying 429/5xx/network errors with backoff.

    Returns the parsed JSON body. Mirrors the other tools in this repo. The error
    body is always surfaced on the first failure — a malformed-query 500 never
    succeeds on retry, and the operator needs the reason immediately.
    """
    data = json.dumps(payload).encode("utf-8")
    headers = {"Authorization": "Bearer %s" % token,
               "Content-Type": "application/json"}
    context = ssl.create_default_context()

    backoff = INITIAL_BACKOFF_SECONDS
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS,
                                        context=context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            if exc.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else backoff
                warn("HTTP %d from %s; retrying in %.0fs (attempt %d/%d). "
                     "Response body: %s"
                     % (exc.code, what, wait, attempt, MAX_RETRIES,
                        body.strip()[:500] or "(empty)"))
                time.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            raise RuntimeError("%s failed: HTTP %d: %s" % (what, exc.code, body))
        except (urllib.error.URLError, TimeoutError, OSError,
                http.client.HTTPException, ValueError) as exc:
            last_error = exc
            if attempt == MAX_RETRIES:
                break
            warn("%s while calling %s (%s); retrying in %ds (attempt %d/%d)"
                 % (type(exc).__name__, what, exc, backoff, attempt, MAX_RETRIES))
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)

    raise RuntimeError("%s failed after %d retries: %s"
                       % (what, MAX_RETRIES, last_error))


def graphql(host, token, query, what):
    """POST one GraphQL query/mutation. Returns the `data` object.

    A GraphQL endpoint can answer HTTP 200 with a top-level `errors` array — the
    request reached the server but the operation failed (bad field, auth, etc.).
    Treat that as an error, like the other tools treat a 200 body with an error
    `status`. The message usually names the exact problem.
    """
    url = "https://%s%s" % (host, GRAPHQL_PATH)
    body = post_json(url, token, {"query": query}, what)
    if body.get("errors"):
        messages = "; ".join(
            e.get("message", json.dumps(e)) for e in body["errors"])
        raise RuntimeError("%s: GraphQL error(s): %s" % (what, messages))
    if "data" not in body:
        raise RuntimeError("%s: response had no `data` field: %s"
                           % (what, json.dumps(body)[:500]))
    return body["data"]


# --- Query building ---------------------------------------------------------

def gql_string(value):
    """A safe GraphQL string literal. json.dumps produces a valid one (double
    quotes, escaped) for any Python str."""
    return json.dumps(str(value))


def gql_enum(value, what):
    """Validate and return an unquoted GraphQL enum literal."""
    if not ENUM_RE.match(value or ""):
        raise RuntimeError(
            "%s value %r is not a valid enum (letters, digits, underscore; must "
            "not start with a digit). Run --introspect to list valid values."
            % (what, value))
    return value


def build_filter_clauses(product, status, filters, filter_file):
    """Return the list of filter-clause dicts (fieldId + stringEqual value).

    --filter-file (raw JSON array) is the whole filter and is mutually exclusive
    with the shorthand flags. Otherwise --product / --status / --filter combine,
    ANDed by the API (the `filters` list is an implicit AND).
    """
    if filter_file:
        with open(filter_file) as handle:
            clauses = json.load(handle)
        if not isinstance(clauses, list):
            raise RuntimeError("--filter-file must contain a JSON array of filter "
                               "clauses (the GraphQL `filters` value).")
        return clauses

    clauses = []
    if product:
        clauses.append({"fieldId": "detectionProduct",
                        "stringEqual": {"value": product}})
    if status:
        clauses.append({"fieldId": "status", "stringEqual": {"value": status}})
    for raw in filters:
        if "=" not in raw:
            raise RuntimeError("--filter %r must be fieldId=value" % raw)
        field, value = raw.split("=", 1)
        field = field.strip()
        if not field:
            raise RuntimeError("--filter %r has an empty fieldId" % raw)
        clauses.append({"fieldId": field, "stringEqual": {"value": value}})
    return clauses


def render_clause(clause):
    """Render one filter-clause dict as GraphQL source.

    Only the stringEqual form is generated by the shorthand flags. A --filter-file
    clause can use any operator the schema supports; we render it structurally so
    those pass through unchanged.
    """
    return _render_value(clause)


def _render_value(value):
    """Render a Python value as GraphQL source. Dicts -> objects (unquoted keys),
    lists -> arrays, str/num/bool -> literals. Used for filter clauses from
    --filter-file so arbitrary operators pass through."""
    if isinstance(value, dict):
        parts = ["%s: %s" % (k, _render_value(v)) for k, v in value.items()]
        return "{ %s }" % ", ".join(parts)
    if isinstance(value, list):
        return "[ %s ]" % ", ".join(_render_value(v) for v in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    return gql_string(value)


def scope_source(scope_ids, scope_type):
    ids = ", ".join(gql_string(s) for s in scope_ids)
    return "{ scopeIds: [%s], scopeType: %s }" % (ids, gql_enum(scope_type,
                                                                "--scope-type"))


def build_alerts_query(clauses, scope_ids, scope_type, fields, page_size, after):
    filters_src = ", ".join(render_clause(c) for c in clauses)
    after_src = "\n    after: %s" % gql_string(after) if after else ""
    fields_src = "\n        ".join(fields)
    return (
        "query bulkResolveCollect {\n"
        "  alerts(\n"
        "    filters: [%s]\n"
        "    scope: %s\n"
        "    first: %d%s\n"
        "  ) {\n"
        "    pageInfo { hasNextPage endCursor }\n"
        "    edges { node {\n        %s\n      } }\n"
        "  }\n"
        "}" % (filters_src, scope_source(scope_ids, scope_type),
               page_size, after_src, fields_src))


def build_actions_source(actions):
    """Render the `actions` array from a list of (action_id, payload_src)."""
    items = []
    for action_id, payload_src in actions:
        items.append('{ id: %s, payload: %s }' % (gql_string(action_id),
                                                   payload_src))
    return "[ %s ]" % ", ".join(items)


def build_mutation(ids, scope_ids, scope_type, actions):
    or_clauses = ", ".join(
        '{ and: [ { fieldId: "id", stringEqual: { value: %s } } ] }'
        % gql_string(i) for i in ids)
    return (
        "mutation bulkResolveApply {\n"
        "  alertTriggerActions(\n"
        "    filter: { or: [ %s ] }\n"
        "    scope: %s\n"
        "    actions: %s\n"
        "  ) {\n"
        "    __typename\n"
        "    ... on ActionsTriggered {\n"
        "      actions { actionId success { id } failure { id } skip { id } }\n"
        "    }\n"
        "    ... on TriggerActionsError { errors { errorMessage } }\n"
        "  }\n"
        "}" % (or_clauses, scope_source(scope_ids, scope_type),
               build_actions_source(actions)))


def build_actions(resolve, set_status, verdict, note):
    """Translate action flags into (action_id, payload_src) pairs, and a list of
    human labels for the manifest/log."""
    actions = []
    labels = []
    status_value = "RESOLVED" if resolve else set_status
    if status_value:
        actions.append((ACTION_STATUS,
                        "{ status: { value: %s } }"
                        % gql_enum(status_value, "--set-status")))
        labels.append("status=%s" % status_value)
    if verdict:
        actions.append((ACTION_VERDICT,
                        "{ analystVerdict: { value: %s } }"
                        % gql_enum(verdict, "--verdict")))
        labels.append("verdict=%s" % verdict)
    if note:
        actions.append((ACTION_NOTE,
                        "{ note: { value: %s } }" % gql_string(note)))
        labels.append("note")
    return actions, labels, status_value


# --- Introspection ----------------------------------------------------------

def introspect(host, token):
    """Print the Alert type's fields and a few relevant enums, so an operator can
    pick valid --fields / --verdict / --set-status values without guessing."""
    query = (
        "query introspect {\n"
        "  alert: __type(name: \"Alert\") { fields { name type { name kind "
        "ofType { name kind } } } }\n"
        "}")
    data = graphql(host, token, query, "introspect")
    alert = data.get("alert")
    if not alert:
        warn("No `Alert` type found via introspection. The type name may differ "
             "on this tenant; inspect the schema in a GraphQL client.")
    else:
        print("Alert fields (name : type):")
        for field in alert.get("fields", []):
            typ = field.get("type") or {}
            name = typ.get("name") or (typ.get("ofType") or {}).get("name") or typ.get("kind")
            print("  %-32s %s" % (field["name"], name))
    print("\nEnum values differ by tenant/version. To list a specific enum "
          "(e.g. the analyst-verdict enum), introspect its type name in a GraphQL "
          "client:  __type(name: \"<EnumTypeName>\") { enumValues { name } }")


# --- Collect phase ----------------------------------------------------------

def flatten(node, fields):
    """One CSV row from an alert node. Missing/nested values render blank or JSON
    so a schema mismatch never crashes the row."""
    row = []
    for field in fields:
        value = node.get(field)
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        row.append("" if value is None else value)
    return row


def collect_alerts(host, token, clauses, scope_ids, scope_type, fields,
                   page_size):
    """Page the alerts query to exhaustion. Returns a list of node dicts."""
    nodes = []
    after = None
    page = 0
    while True:
        query = build_alerts_query(clauses, scope_ids, scope_type, fields,
                                   page_size, after)
        try:
            data = graphql(host, token, query, "collect")
        except RuntimeError as exc:
            _hint_bad_field(exc)
            raise
        alerts = data.get("alerts") or {}
        edges = alerts.get("edges") or []
        for edge in edges:
            node = (edge or {}).get("node")
            if node:
                nodes.append(node)
        page += 1
        info = alerts.get("pageInfo") or {}
        print("  page %d: +%d alerts (running total %d)"
              % (page, len(edges), len(nodes)))
        if not info.get("hasNextPage"):
            break
        after = info.get("endCursor")
        if not after:
            warn("hasNextPage was true but endCursor was empty; stopping to avoid "
                 "an endless loop. Results may be incomplete.")
            break
    return nodes


def _hint_bad_field(exc):
    """If a collect query failed on an unknown field, point at --introspect."""
    text = str(exc)
    if "Cannot query field" in text or "Unknown field" in text:
        warn("A requested alert field is not valid on this tenant's schema. "
             "Run with --introspect to list valid Alert fields, then pass a "
             "corrected --fields list.")


# --- Apply phase ------------------------------------------------------------

def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def fold_outcomes(mutation_result, batch_ids):
    """Map each id in the batch to resolved/failed/skipped from the mutation
    result. The API reports success/failure/skip PER action; fold across actions
    per id — any failure wins, then skip, else resolved. Cleaner and more honest
    than the Postman "divide totals by number of actions" heuristic."""
    failed, skipped, succeeded = set(), set(), set()
    for action in mutation_result.get("actions", []):
        for item in action.get("failure") or []:
            failed.add(item["id"])
        for item in action.get("skip") or []:
            skipped.add(item["id"])
        for item in action.get("success") or []:
            succeeded.add(item["id"])
    outcomes = {}
    for alert_id in batch_ids:
        if alert_id in failed:
            outcomes[alert_id] = "failed"
        elif alert_id in skipped:
            outcomes[alert_id] = "skipped"
        elif alert_id in succeeded:
            outcomes[alert_id] = "resolved"
        else:
            # Not mentioned in any list — the API neither confirmed nor rejected
            # it. Record it honestly rather than assuming success.
            outcomes[alert_id] = "unknown"
    return outcomes


def apply_actions(host, token, ids, scope_ids, scope_type, actions, batch_size,
                  checkpoint_path):
    """Resolve `ids` in batches. Returns {id: outcome}. Checkpoints after each
    batch so an interrupt resumes."""
    outcomes = {}
    completed_batches = 0
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as handle:
            saved = json.load(handle)
        if saved.get("ids") == ids and saved.get("batch_size") == batch_size:
            outcomes = saved.get("outcomes", {})
            completed_batches = saved.get("completed_batches", 0)
            print("  resuming apply from checkpoint: %d batch(es) already done"
                  % completed_batches)
        else:
            warn("checkpoint does not match this run (id set or batch size "
                 "changed); ignoring it and starting the apply from the top.")

    batches = list(chunked(ids, batch_size))
    for index, batch in enumerate(batches):
        if index < completed_batches:
            continue
        mutation = build_mutation(batch, scope_ids, scope_type, actions)
        data = graphql(host, token, mutation, "apply batch %d" % (index + 1))
        result = data.get("alertTriggerActions") or {}
        typename = result.get("__typename")
        if typename == "TriggerActionsError":
            errs = "; ".join(e.get("errorMessage", "")
                             for e in result.get("errors") or [])
            raise RuntimeError("apply batch %d rejected by API: %s"
                               % (index + 1, errs))
        batch_outcomes = fold_outcomes(result, batch)
        outcomes.update(batch_outcomes)
        counts = _tally(batch_outcomes.values())
        print("  batch %d/%d (%d alerts): %s"
              % (index + 1, len(batches), len(batch), counts))
        with open(checkpoint_path, "w") as handle:
            json.dump({"ids": ids, "batch_size": batch_size,
                       "completed_batches": index + 1, "outcomes": outcomes},
                      handle)
    return outcomes


def _tally(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))


# --- Report -----------------------------------------------------------------

def write_report(out_dir, run_id, fields, nodes, outcomes, dry_run,
                 status_value):
    """Write the per-alert CSV. Returns its path."""
    csv_path = os.path.join(out_dir, "bulk_resolve_%s.csv" % run_id)
    default_outcome = ("would-resolve" if status_value == "RESOLVED"
                       else "would-%s" % (status_value or "act")).lower()
    with open(csv_path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(fields + ["outcome"])
        for node in nodes:
            alert_id = node.get("id")
            outcome = default_outcome if dry_run else outcomes.get(alert_id, "unknown")
            writer.writerow(flatten(node, fields) + [outcome])
    return csv_path


def write_manifest(out_dir, run_id, host, scope_ids, scope_type, clauses,
                   action_labels, dry_run, batch_size, fields, nodes, outcomes):
    path = os.path.join(out_dir, "bulk_resolve_%s_manifest.json" % run_id)
    if dry_run:
        totals = {"matched": len(nodes)}
    else:
        totals = {"matched": len(nodes)}
        for value in outcomes.values():
            totals[value] = totals.get(value, 0) + 1
    manifest = {
        "runId": run_id,
        "timestampUtc": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "scope": {"scopeIds": scope_ids, "scopeType": scope_type},
        "filters": clauses,
        "actions": action_labels,
        "dryRun": dry_run,
        "batchSize": batch_size,
        "fields": fields,
        "totals": totals,
    }
    with open(path, "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return path


# --- CLI --------------------------------------------------------------------

def make_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True,
                        help="Console host (the one you log in to), e.g. "
                             "usea1-abc.sentinelone.net. NOT the SDL xdr.* host.")
    parser.add_argument("--token", default=os.environ.get("S1_CONSOLE_TOKEN"),
                        help="Console API token for a service user. Prefer the "
                             "S1_CONSOLE_TOKEN env var so it stays out of shell "
                             "history.")

    parser.add_argument("--introspect", action="store_true",
                        help="Print the Alert type's fields (and how to list "
                             "enums), then exit. Use it to pick valid --fields / "
                             "--verdict / --set-status values, then re-run.")

    parser.add_argument("--scope-type", choices=["ACCOUNT", "SITE", "GROUP"],
                        help="Scope type for the query and mutation.")
    parser.add_argument("--scope-id", action="append", default=[], metavar="ID",
                        help="Scope id to target. Repeatable.")

    parser.add_argument("--product", help="Shorthand filter: detectionProduct = "
                                          "this value (e.g. Identity).")
    parser.add_argument("--status", help="Shorthand filter: status = this value "
                                         "(e.g. NEW).")
    parser.add_argument("--filter", action="append", default=[], metavar="FIELD=VALUE",
                        help="Generic stringEqual filter clause, repeatable; "
                             "ANDed with the others.")
    parser.add_argument("--filter-file", metavar="PATH",
                        help="Raw GraphQL `filters` array as JSON. Mutually "
                             "exclusive with --product/--status/--filter.")
    parser.add_argument("--match-all", action="store_true",
                        help="Required to proceed with NO filters (would match "
                             "every alert in scope). A deliberate foot-gun guard.")

    parser.add_argument("--resolve", action="store_true",
                        help="Set status to RESOLVED (alias for --set-status RESOLVED).")
    parser.add_argument("--set-status", metavar="ENUM",
                        help="Set status to an arbitrary enum value.")
    parser.add_argument("--verdict", metavar="ENUM",
                        help="Set analyst verdict, e.g. FALSE_POSITIVE_USER_ERROR.")
    parser.add_argument("--note", metavar="TEXT", help="Attach a note.")

    parser.add_argument("--apply", action="store_true",
                        help="Actually perform the mutations. WITHOUT this the "
                             "run is a dry run: it queries and reports but changes "
                             "nothing.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Explicitly force a dry run (the default). Handy to "
                             "override a --apply set by a shell alias.")

    parser.add_argument("--fields", metavar="A,B,C",
                        help="Comma-separated alert node fields for the report "
                             "(default: %s). `id` is always included."
                             % ",".join(DEFAULT_FIELDS))
    parser.add_argument("--batch-size", type=int, default=250,
                        help="Alerts per query page and per mutation batch (default 250).")
    parser.add_argument("--out-dir", default=default_out_dir(),
                        help="Report output directory (default: <repo>/reports/"
                             "bulk-resolve, resolved from this script's location).")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if not args.token:
        raise SystemExit("Error: no token: set --token or the S1_CONSOLE_TOKEN "
                         "environment variable")

    if args.introspect:
        introspect(args.host, args.token)
        return

    # Validation for a real run.
    if not args.scope_type:
        raise SystemExit("Error: --scope-type is required")
    if not args.scope_id:
        raise SystemExit("Error: at least one --scope-id is required")
    if args.batch_size < 1:
        raise SystemExit("Error: --batch-size must be >= 1")
    if args.filter_file and (args.product or args.status or args.filter):
        raise SystemExit("Error: --filter-file is mutually exclusive with "
                         "--product/--status/--filter")
    if args.resolve and args.set_status and args.set_status != "RESOLVED":
        raise SystemExit("Error: --resolve conflicts with --set-status %s"
                         % args.set_status)

    dry_run = not args.apply or args.dry_run

    fields = ([f.strip() for f in args.fields.split(",") if f.strip()]
              if args.fields else list(DEFAULT_FIELDS))
    if "id" not in fields:
        fields = ["id"] + fields

    try:
        clauses = build_filter_clauses(args.product, args.status, args.filter,
                                       args.filter_file)
        actions, action_labels, status_value = build_actions(
            args.resolve, args.set_status, args.verdict, args.note)
    except RuntimeError as exc:
        raise SystemExit("Error: %s" % exc)

    if not clauses and not args.match_all:
        raise SystemExit("Error: no filters given — this would match EVERY alert "
                         "in scope. Pass --match-all to confirm you mean that.")
    if not actions:
        raise SystemExit("Error: no actions given — pass at least one of "
                         "--resolve/--set-status, --verdict, --note.")

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    run_id = make_run_id()

    print("=" * 70)
    print("APPLYING (writes)" if not dry_run else "DRY RUN (no writes)")
    print("=" * 70)
    print("Host:    %s" % args.host)
    print("Scope:   %s %s" % (args.scope_type, ", ".join(args.scope_id)))
    print("Filters: %s" % (json.dumps(clauses) if clauses else "(match all)"))
    print("Actions: %s" % ", ".join(action_labels))
    print("Fields:  %s" % ", ".join(fields))
    print("Output:  %s" % out_dir)
    print("-" * 70)

    print("Collecting matching alerts (paging %d/page)..." % args.batch_size)
    nodes = collect_alerts(args.host, args.token, clauses, args.scope_id,
                           args.scope_type, fields, args.batch_size)
    print("Matched %d alert(s)." % len(nodes))

    outcomes = {}
    if not nodes:
        print("Nothing to do.")
    elif dry_run:
        print("Dry run: not applying. Re-run with --apply to resolve these.")
    else:
        ids = [n.get("id") for n in nodes if n.get("id")]
        checkpoint_path = os.path.join(out_dir,
                                       "bulk_resolve_%s.checkpoint.json" % run_id)
        print("Applying actions to %d alert(s) in batches of %d..."
              % (len(ids), args.batch_size))
        outcomes = apply_actions(args.host, args.token, ids, args.scope_id,
                                 args.scope_type, actions, args.batch_size,
                                 checkpoint_path)
        print("Apply complete: %s" % _tally(outcomes.values()))
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)

    csv_path = write_report(out_dir, run_id, fields, nodes, outcomes, dry_run,
                            status_value)
    manifest_path = write_manifest(out_dir, run_id, args.host, args.scope_id,
                                   args.scope_type, clauses, action_labels,
                                   dry_run, args.batch_size, fields, nodes,
                                   outcomes)
    print("-" * 70)
    print("Report:   %s" % csv_path)
    print("Manifest: %s" % manifest_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted. An --apply run checkpoints after each "
                         "batch — re-run the same command to resume.\n")
        raise SystemExit(130)
    except RuntimeError as exc:
        sys.stderr.write("\nError: %s\n" % exc)
        raise SystemExit(1)
