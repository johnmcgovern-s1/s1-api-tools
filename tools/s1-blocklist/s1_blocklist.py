#!/usr/bin/env python3
"""Check and manage the SentinelOne Global Blocklist (hash restrictions).

The workflow this exists for: an IOC — typically a file hash — is shared with a
customer by an industry group / ISAC, and they need to answer two questions fast:

    1. Is this hash ALREADY blocked by our S1 tenant?  (check)
    2. If not, add it to the blocklist.                (add)

"Blocked by S1" is not one system — it is THREE independent ones, and a hash can
be enforced by any of them. `check` reports all three so the answer isn't a false
negative:

    1. Global Blocklist   /web/api/v2.1/restrictions (type: black_hash)
                          — the tenant's explicit deny list (GET/POST/PUT/DELETE).
    2. Threat Intel IOCs  /web/api/v2.1/threat-intelligence/iocs
                          — FEED-INGESTED indicators (Singularity Threat Intel,
                            STIX bundles, custom uploads). This is where a hash
                            "ingested via a threat feed" lives — NOT the blocklist.
    3. Reputation verdict /web/api/v2.1/hashes/{hash}/verdict  [DEPRECATED]
                          — S1's global cloud opinion (malicious/non-malicious/
                            unknown), evaluated by the agent at execution. Not
                            tenant data, so there is no "list" API — only a
                            per-hash lookup, and only via the deprecated endpoint.
                            Best-effort, off by default (`--with-verdict`).

    Do NOT rely on `hashes/{hash}/verdict` alone. It is DEPRECATED, and it only
    ever answered #3 — a hash can be on your blocklist (#1) or in an ingested
    feed (#2) and still return "unknown" from verdict, because "unknown" only
    means S1's reputation sources haven't scored it. That mismatch is exactly why
    a "blocked" hash looked unknown.

`add`/`remove` operate on the Global Blocklist (#1) — the layer you manage.

⚠️  THIS TOOL WRITES. `add` and `remove` mutate the blocklist. Both default to a
    dry run (query + report, change nothing) and require an explicit `--apply`.
    There is no undo on a delete. Always dry-run against a TEST scope first and
    read the report before applying.

Pure Python 3 standard library — no pip install. Copy the single file to a jump
host and it runs.

--- Host: the console, not the SDL endpoint ------------------------------------

This API lives on the **management console host itself** — the one you log in to,
e.g. usea1-abc.sentinelone.net. Pass that as --host, NOT an xdr.* SDL host.

--- Auth -----------------------------------------------------------------------

A console API token for a service user. The management REST API expects it as
`Authorization: ApiToken <token>` (this tool sets that header). Prefer the
S1_CONSOLE_TOKEN env var so the token stays out of your shell history.

--- Scope ----------------------------------------------------------------------

A blocklist entry lives at a scope (Global/tenant, Account, Site, or Group) and
is inherited downward. For a read (`check`) the tool asks with
includeParents=true by default, so a hash blocked at Global/Account shows as
blocked even when you query a Site. For a write you must name the scope the entry
should be created at: --tenant, or one or more of --account-id / --site-id /
--group-id.

--- Per-OS ---------------------------------------------------------------------

Blocklist entries are per-OS (osType is required by the API). Blocking a hash for
"everything" is four entries. `add` takes --os-type (repeatable), and
`--os-type all` expands to windows, macos, linux, windows_legacy.

--- Usage ----------------------------------------------------------------------

    export S1_CONSOLE_TOKEN="<console API token for a service user>"

    # 1) Is this list of shared IOCs already blocked?  (read-only)
    python3 s1_blocklist.py check --host usea1-abc.sentinelone.net \\
        --account-id 12345 --hash-file shared_iocs.txt --with-verdict

    # 2) Add the ones that aren't — dry run first (default), then --apply
    python3 s1_blocklist.py add --host usea1-abc.sentinelone.net \\
        --account-id 12345 --hash-file shared_iocs.txt \\
        --os-type all --description "ISAC advisory 2026-08"
    python3 s1_blocklist.py add ... --apply

    # 3) Remove entries for a hash (dry run first, then --apply)
    python3 s1_blocklist.py remove --host usea1-abc.sentinelone.net \\
        --account-id 12345 --hash <sha1> --apply

`add` and `remove` dedup/resolve against what is already on the blocklist first,
so `add` never creates a duplicate of an existing (hash, osType) entry and
reports it as `already-blocked` instead.
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
import urllib.parse
import urllib.request
from datetime import datetime, timezone

RESTRICTIONS_PATH = "/web/api/v2.1/restrictions"
IOCS_PATH = "/web/api/v2.1/threat-intelligence/iocs"
VERDICT_PATH = "/web/api/v2.1/hashes/%s/verdict"  # deprecated; secondary signal
RESTRICTION_TYPE = "black_hash"

# "Blocked by S1" spans three independent systems; `check` reports all three:
#   1. Global Blocklist  (/restrictions)          — explicit deny list
#   2. Threat Intel IOCs (/threat-intelligence)   — feed-ingested indicators
#   3. Reputation verdict (deprecated endpoint)   — S1 cloud intel, best-effort
# The IOC store keys hashes by these type names (MD5 is a valid IOC, unlike the
# blocklist which has no MD5 key).
IOC_TYPE_FOR = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256"}

ALL_OS_TYPES = ["windows", "macos", "linux", "windows_legacy"]

# The blocklist stores a SHA1 in `value` and a SHA256 in `sha256Value`. MD5 is
# not a blocklist key, so an MD5 IOC can be neither matched nor added here.
HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

PAGE_LIMIT = 1000  # max the API allows per page

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 6
INITIAL_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 120


def warn(message):
    sys.stderr.write("  [warn] %s\n" % message)


def default_out_dir():
    """`<repo>/reports/blocklist`, resolved from this file, not the cwd.

    Falls back to a cwd-relative path when the file has been copied out of the
    repo on its own (a supported way to run these tools)."""
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))  # tools/<tool>/ -> root
    if os.path.isdir(os.path.join(repo_root, "tools")):
        return os.path.join(repo_root, "reports", "blocklist")
    return os.path.join("reports", "blocklist")


# --- HTTP -------------------------------------------------------------------

def api_request(host, token, method, path, query=None, body=None, what="request"):
    """One management-API call. Returns the parsed JSON body.

    Retries 429/5xx/network errors with backoff honouring Retry-After. The error
    body is always surfaced on the first non-retryable failure — a 400 from a bad
    payload never succeeds on retry and the operator needs the reason at once.
    """
    url = "https://%s%s" % (host, path)
    if query:
        url = "%s?%s" % (url, urllib.parse.urlencode(query))
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": "ApiToken %s" % token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    context = ssl.create_default_context()

    backoff = INITIAL_BACKOFF_SECONDS
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS,
                                        context=context) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", "replace")
            if exc.code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else backoff
                warn("HTTP %d from %s; retrying in %.0fs (attempt %d/%d). "
                     "Response body: %s"
                     % (exc.code, what, wait, attempt, MAX_RETRIES,
                        payload.strip()[:500] or "(empty)"))
                time.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            raise RuntimeError("%s failed: HTTP %d: %s"
                               % (what, exc.code, payload.strip()[:800]))
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


def check_api_errors(body, what):
    """A management-API 200 can still carry a top-level `errors` array. Treat a
    non-empty one as a failure, like the other tools in this repo."""
    errors = body.get("errors")
    if errors:
        raise RuntimeError("%s: API returned error(s): %s"
                           % (what, json.dumps(errors)[:500]))


# --- Hashes -----------------------------------------------------------------

def hash_kind(value):
    """Return 'md5' / 'sha1' / 'sha256' for a hex hash, or None if it isn't one."""
    value = (value or "").strip()
    if HEX_RE.match(value):
        return HASH_KINDS.get(len(value))
    return None


def load_hashes(hash_args, hash_file):
    """Collect, validate, normalise (lowercase) and de-duplicate input hashes.

    Returns (ordered list of unique lowercased hashes, list of (raw, reason)
    skips). A '#' comment and blank lines in a hash file are ignored; anything
    that isn't a SHA1/SHA256/MD5 hex string is reported as a skip, not silently
    dropped."""
    raw_values = list(hash_args or [])
    if hash_file:
        with open(hash_file) as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw_values.append(line)

    seen = set()
    hashes = []
    skips = []
    for raw in raw_values:
        kind = hash_kind(raw)
        if not kind:
            skips.append((raw, "not a hex md5/sha1/sha256"))
            continue
        low = raw.strip().lower()
        if low in seen:
            continue
        seen.add(low)
        hashes.append(low)
    return hashes, skips


# --- Scope ------------------------------------------------------------------

def scope_query_params(account_ids, site_ids, group_ids, tenant):
    """Query params to scope a GET. Arrays go as comma-joined strings, which the
    management API accepts for id lists."""
    params = {}
    if tenant:
        params["tenant"] = "true"
    if account_ids:
        params["accountIds"] = ",".join(account_ids)
    if site_ids:
        params["siteIds"] = ",".join(site_ids)
    if group_ids:
        params["groupIds"] = ",".join(group_ids)
    return params


def scope_filter(account_ids, site_ids, group_ids, tenant):
    """The `filter` object for a create (POST) body — the scope the new entry is
    created at."""
    flt = {}
    if tenant:
        flt["tenant"] = True
    if account_ids:
        flt["accountIds"] = account_ids
    if site_ids:
        flt["siteIds"] = site_ids
    if group_ids:
        flt["groupIds"] = group_ids
    return flt


def scope_label(account_ids, site_ids, group_ids, tenant):
    parts = []
    if tenant:
        parts.append("tenant")
    if account_ids:
        parts.append("account=%s" % ",".join(account_ids))
    if site_ids:
        parts.append("site=%s" % ",".join(site_ids))
    if group_ids:
        parts.append("group=%s" % ",".join(group_ids))
    return " ".join(parts) if parts else "(none)"


# --- Read: fetch + index the blocklist --------------------------------------

def fetch_restrictions(host, token, scope_params, include_parents,
                       include_children):
    """Page the whole black_hash blocklist for a scope. Returns a list of entry
    dicts.

    Reading the whole (scoped) list once and matching locally is more robust than
    trusting a free-text hash query to match, and one fetch serves any number of
    input hashes. Blocklists are bounded (hundreds to low thousands), so this is
    a handful of pages at most."""
    entries = []
    cursor = None
    page = 0
    while True:
        query = dict(scope_params)
        query["type"] = RESTRICTION_TYPE
        query["limit"] = PAGE_LIMIT
        if include_parents:
            query["includeParents"] = "true"
        if include_children:
            query["includeChildren"] = "true"
        if cursor:
            query["cursor"] = cursor
        body = api_request(host, token, "GET", RESTRICTIONS_PATH, query=query,
                           what="fetch blocklist")
        check_api_errors(body, "fetch blocklist")
        data = body.get("data") or []
        entries.extend(data)
        page += 1
        pagination = body.get("pagination") or {}
        # totalItems is only reported on the first page by some tenants; show it
        # when present and non-zero, otherwise just the running total.
        total = pagination.get("totalItems")
        print("  page %d: +%d entries (running total %d%s)"
              % (page, len(data), len(entries),
                 "/%d" % total if total else ""))
        cursor = pagination.get("nextCursor")
        if not cursor:
            break
    return entries


def index_by_hash(entries):
    """Map every hash form present on each entry (lowercased `value` SHA1 and
    `sha256Value` SHA256) to the list of entries carrying it. One hash can map to
    several entries — different OS types and/or scope levels."""
    index = {}
    for entry in entries:
        for key in ("value", "sha256Value"):
            val = (entry.get(key) or "").strip().lower()
            if val:
                index.setdefault(val, []).append(entry)
    return index


def get_verdict(host, token, sha1):
    """Best-effort call to the DEPRECATED reputation-verdict endpoint. Returns a
    verdict string, or an error marker — never raises, since it is a secondary
    signal and must not fail a blocklist check. Only meaningful for a SHA1."""
    try:
        body = api_request(host, token, "GET", VERDICT_PATH % sha1,
                           what="verdict")
        return ((body.get("data") or {}).get("verdict")) or "unknown"
    except RuntimeError as exc:
        return "verdict-error(%s)" % str(exc)[:60]


# --- Read: Threat Intelligence IOC store ------------------------------------

def ti_scope_params(account_ids, site_ids, tenant):
    """Scope params for the IOC store. It is scoped by account/site/tenant only —
    there is no group scope on IOCs, so --group-id does not apply to this layer."""
    params = {}
    if tenant:
        params["tenant"] = "true"
    if account_ids:
        params["accountIds"] = ",".join(account_ids)
    if site_ids:
        params["siteIds"] = ",".join(site_ids)
    return params


def fetch_iocs_for_hash(host, token, value, ioc_type, scope_params):
    """Return IOC-store entries matching one hash. Queried by exact `value` +
    `type` (not fetch-all: an ingested feed store can hold millions of IOCs, so
    we must ask for the one hash). Verifies the returned value/type locally so a
    loose server-side match can't produce a false positive."""
    matches = []
    cursor = None
    while True:
        query = dict(scope_params)
        query["type"] = ioc_type
        query["value"] = value
        query["limit"] = PAGE_LIMIT
        if cursor:
            query["cursor"] = cursor
        body = api_request(host, token, "GET", IOCS_PATH, query=query,
                           what="threat-intel lookup %s" % value)
        check_api_errors(body, "threat-intel lookup")
        for item in body.get("data") or []:
            if ((item.get("value") or "").strip().lower() == value
                    and (item.get("type") or "").upper() == ioc_type):
                matches.append(item)
        cursor = (body.get("pagination") or {}).get("nextCursor")
        if not cursor:
            break
    return matches


def compute_coverage(kind, on_blocklist, in_threat_intel, verdict):
    """Reduce the three layers to one triage word.

    blocked            — enforced now: on the blocklist OR in an ingested feed.
    reputation-flagged — not in tenant config, but S1 Reputation says malicious
                         (only possible when --with-verdict ran).
    unknown-md5        — an MD5 with no feed hit: the blocklist has no MD5 key and
                         the verdict endpoint needs a SHA1, so it can't be
                         confirmed either way here.
    not-blocked        — none of the above.
    """
    if on_blocklist or in_threat_intel:
        return "blocked"
    if verdict == "malicious":
        return "reputation-flagged"
    if kind == "md5":
        return "unknown-md5"
    return "not-blocked"


# --- Entry -> row helpers ---------------------------------------------------

def entry_scope(entry):
    return entry.get("scopePath") or entry.get("scopeName") or ""


def describe_entry(entry):
    """A compact, human dict of the fields worth reporting for a matched entry."""
    return {
        "matchedId": entry.get("id", ""),
        "osType": entry.get("osType", ""),
        "scope": entry_scope(entry),
        "source": entry.get("source", ""),
        "description": entry.get("description", "") or "",
        "createdAt": entry.get("createdAt", ""),
        "userName": entry.get("userName", ""),
    }


# --- check ------------------------------------------------------------------

# One row per hash: a layered coverage view across all three "blocked by S1"
# systems, plus the best-effort reputation verdict.
CHECK_FIELDS = ["hash", "hashType", "coverage",
                "onBlocklist", "blocklistOsTypes", "blocklistScopes",
                "blocklistSources",
                "inThreatIntel", "threatIntelSources", "threatIntelNames",
                "reputationVerdict"]


def _joined(values):
    """Comma-join a set of non-empty strings, order-stable, for a CSV cell."""
    return ",".join(sorted({v for v in values if v}))


def cmd_check(args, host, token, scope_params, out_dir, run_id):
    hashes, skips = load_hashes(args.hash, args.hash_file)
    for raw, reason in skips:
        warn("skipping %r: %s" % (raw, reason))
    if not hashes:
        raise SystemExit("Error: no valid hashes to check")

    # Layer 1: fetch the (small) blocklist once and index it.
    print("Layer 1/3 — blocklist: fetching for scope %s (includeParents=%s)..."
          % (scope_label(args.account_id, args.site_id, args.group_id,
                         args.tenant), not args.no_include_parents))
    entries = fetch_restrictions(host, token, scope_params,
                                 not args.no_include_parents,
                                 args.include_children)
    index = index_by_hash(entries)
    print("  blocklist has %d entr(y/ies) in scope." % len(entries))

    # Layer 2: Threat Intel IOC store — queried per hash by exact value. Scoped
    # by account/site/tenant only (no group scope on IOCs).
    ti_params = ti_scope_params(args.account_id, args.site_id, args.tenant)
    ti_state = {"enabled": True, "checked": 0}
    if args.no_threat_intel:
        ti_state["enabled"] = False
        print("Layer 2/3 — threat-intel IOCs: skipped (--no-threat-intel).")
    elif not ti_params:
        # Only --group-id was given; the IOC store can't be scoped to a group.
        ti_state["enabled"] = False
        warn("threat-intel IOC layer skipped: it is scoped by account/site/"
             "tenant, and only --group-id was given. Add --account-id/--site-id/"
             "--tenant to include it.")
    else:
        print("Layer 2/3 — threat-intel IOCs: querying per hash by value...")

    if args.with_verdict:
        print("Layer 3/3 — reputation verdict: enabled (deprecated, best-effort).")

    print("Checking %d hash(es)." % len(hashes))
    rows = []
    coverage_counts = {}
    for h in hashes:
        kind = hash_kind(h)
        bl_matches = index.get(h, [])          # MD5 never matches (no key)
        on_blocklist = bool(bl_matches)

        ti_matches = []
        in_ti = False
        ti_cell = "no"
        if ti_state["enabled"]:
            try:
                ti_matches = fetch_iocs_for_hash(host, token, h,
                                                 IOC_TYPE_FOR[kind], ti_params)
                ti_state["checked"] += 1
                in_ti = bool(ti_matches)
                ti_cell = "yes" if in_ti else "no"
            except RuntimeError as exc:
                # Disable the layer after the first hard failure (e.g. no TI
                # license / permission) rather than repeating it per hash.
                warn("threat-intel lookup failed (%s); disabling that layer for "
                     "the rest of this run." % str(exc)[:120])
                ti_state["enabled"] = False
                ti_cell = "error"
        elif not args.no_threat_intel and not ti_params:
            ti_cell = "skipped"
        else:
            ti_cell = "skipped"

        verdict = ""
        if args.with_verdict:
            verdict = (get_verdict(host, token, h) if kind == "sha1"
                       else "n/a(not-sha1)")

        coverage = compute_coverage(kind, on_blocklist, in_ti, verdict)
        coverage_counts[coverage] = coverage_counts.get(coverage, 0) + 1

        rows.append({
            "hash": h,
            "hashType": kind,
            "coverage": coverage,
            "onBlocklist": ("n/a" if kind == "md5"
                            else ("yes" if on_blocklist else "no")),
            "blocklistOsTypes": _joined(e.get("osType") for e in bl_matches),
            "blocklistScopes": _joined(entry_scope(e) for e in bl_matches),
            "blocklistSources": _joined(e.get("source") for e in bl_matches),
            "inThreatIntel": ti_cell,
            "threatIntelSources": _joined(i.get("source") for i in ti_matches),
            "threatIntelNames": _joined(i.get("name") for i in ti_matches),
            "reputationVerdict": verdict,
        })

    print("-" * 70)
    print("Coverage: %s" % _tally(coverage_counts))

    csv_path = write_csv(out_dir, run_id, "check", CHECK_FIELDS, rows)
    manifest_path = write_manifest(out_dir, run_id, "check", args, host, {
        "hashesChecked": len(hashes),
        "blocklistEntriesInScope": len(entries),
        "threatIntelLayer": ("checked" if ti_state["checked"]
                             else ("disabled" if not ti_state["enabled"]
                                   else "none")),
        "threatIntelHashesQueried": ti_state["checked"],
        "withVerdict": bool(args.with_verdict),
        "coverage": coverage_counts,
        "skipped": len(skips),
    })
    print("Report:   %s" % csv_path)
    print("Manifest: %s" % manifest_path)


# --- add --------------------------------------------------------------------

ADD_FIELDS = ["hash", "hashType", "osType", "outcome", "matchedId", "detail"]


def cmd_add(args, host, token, scope_params, out_dir, run_id, dry_run):
    hashes, skips = load_hashes(args.hash, args.hash_file)
    for raw, reason in skips:
        warn("skipping %r: %s" % (raw, reason))
    addable = [h for h in hashes if hash_kind(h) in ("sha1", "sha256")]
    for h in hashes:
        if hash_kind(h) == "md5":
            warn("skipping %s: MD5 cannot be added to the blocklist "
                 "(keyed on SHA1/SHA256)." % h)
    if not addable:
        raise SystemExit("Error: no SHA1/SHA256 hashes to add")

    os_types = expand_os_types(args.os_type)

    # Dedup against what already exists in scope (includeParents so we don't
    # re-add something already inherited from Global/Account).
    print("Fetching existing blocklist for scope %s to dedup..."
          % scope_label(args.account_id, args.site_id, args.group_id,
                        args.tenant))
    existing = fetch_restrictions(host, token, scope_params, True, False)
    index = index_by_hash(existing)

    flt = scope_filter(args.account_id, args.site_id, args.group_id, args.tenant)
    rows = []
    counts = {}
    for h in addable:
        kind = hash_kind(h)
        already = {e.get("osType") for e in index.get(h, [])}
        for os_type in os_types:
            if os_type in already:
                _row(rows, counts, h, kind, os_type, "already-blocked",
                     detail="present in scope")
                continue
            if dry_run:
                _row(rows, counts, h, kind, os_type, "would-add")
                continue
            outcome, matched_id, detail = do_add(host, token, h, kind, os_type,
                                                  flt, args.description,
                                                  args.source)
            _row(rows, counts, h, kind, os_type, outcome, matched_id, detail)

    print("-" * 70)
    print("Add %s: %s" % ("(dry run)" if dry_run else "complete", _tally(counts)))
    csv_path = write_csv(out_dir, run_id, "add", ADD_FIELDS, rows)
    manifest_path = write_manifest(out_dir, run_id, "add", args, host, {
        "hashes": len(addable), "osTypes": os_types, "dryRun": dry_run,
        "outcomes": counts,
    })
    print("Report:   %s" % csv_path)
    print("Manifest: %s" % manifest_path)


def do_add(host, token, h, kind, os_type, flt, description, source):
    """POST one blocklist entry. Returns (outcome, matched_id, detail)."""
    data = {"osType": os_type, "type": RESTRICTION_TYPE}
    if kind == "sha1":
        data["value"] = h
    else:
        data["sha256Value"] = h
    if description:
        data["description"] = description
    if source:
        data["source"] = source
    body_payload = {"data": data, "filter": flt}
    try:
        body = api_request(host, token, "POST", RESTRICTIONS_PATH,
                           body=body_payload, what="add %s/%s" % (h, os_type))
        check_api_errors(body, "add %s/%s" % (h, os_type))
        created = body.get("data")
        new_id = ""
        if isinstance(created, list) and created:
            new_id = created[0].get("id", "")
        elif isinstance(created, dict):
            new_id = created.get("id", "")
        return "added", new_id, ""
    except RuntimeError as exc:
        return "failed", "", str(exc)[:200]


# --- remove -----------------------------------------------------------------

REMOVE_FIELDS = ["hash", "hashType", "osType", "outcome", "matchedId", "scope",
                 "detail"]


def cmd_remove(args, host, token, scope_params, out_dir, run_id, dry_run):
    hashes, skips = load_hashes(args.hash, args.hash_file)
    for raw, reason in skips:
        warn("skipping %r: %s" % (raw, reason))
    if not hashes:
        raise SystemExit("Error: no valid hashes to remove")

    print("Resolving hashes to blocklist entries in scope %s..."
          % scope_label(args.account_id, args.site_id, args.group_id,
                        args.tenant))
    # No includeParents: you can only delete entries owned at the queried scope,
    # not ones inherited from a parent. Surfacing only in-scope entries keeps the
    # tool from attempting a delete the API will reject.
    entries = fetch_restrictions(host, token, scope_params, False,
                                 args.include_children)
    index = index_by_hash(entries)

    rows = []
    counts = {}
    to_delete = []  # (id, hash, kind, osType, scope)
    for h in hashes:
        kind = hash_kind(h)
        matches = index.get(h, [])
        if not matches:
            _rrow(rows, counts, h, kind, "", "not-found", "", "")
            continue
        for entry in matches:
            to_delete.append((entry.get("id"), h, kind, entry.get("osType", ""),
                              entry_scope(entry)))

    if dry_run:
        for entry_id, h, kind, os_type, scope in to_delete:
            _rrow(rows, counts, h, kind, os_type, "would-remove", entry_id, scope)
    elif to_delete:
        ids = [d[0] for d in to_delete if d[0]]
        ok = do_remove(host, token, ids)
        outcome = "removed" if ok else "delete-failed"
        detail = "" if ok else "see stderr"
        for entry_id, h, kind, os_type, scope in to_delete:
            _rrow(rows, counts, h, kind, os_type, outcome, entry_id, scope,
                  detail)

    print("-" * 70)
    print("Remove %s: %s"
          % ("(dry run)" if dry_run else "complete", _tally(counts)))
    csv_path = write_csv(out_dir, run_id, "remove", REMOVE_FIELDS, rows)
    manifest_path = write_manifest(out_dir, run_id, "remove", args, host, {
        "hashes": len(hashes), "entriesMatched": len(to_delete),
        "dryRun": dry_run, "outcomes": counts,
    })
    print("Report:   %s" % csv_path)
    print("Manifest: %s" % manifest_path)


def do_remove(host, token, ids):
    """DELETE blocklist entries by id. Returns True on success. The API takes the
    ids in the body; scope is implied by the ids themselves."""
    payload = {"data": {"ids": ids, "type": RESTRICTION_TYPE}}
    try:
        body = api_request(host, token, "DELETE", RESTRICTIONS_PATH,
                           body=payload, what="remove %d entr(y/ies)" % len(ids))
        check_api_errors(body, "remove")
        return True
    except RuntimeError as exc:
        warn("delete failed: %s" % exc)
        return False


# --- row / tally helpers ----------------------------------------------------

def _row(rows, counts, h, kind, os_type, outcome, matched_id="", detail=""):
    rows.append({"hash": h, "hashType": kind, "osType": os_type,
                 "outcome": outcome, "matchedId": matched_id, "detail": detail})
    counts[outcome] = counts.get(outcome, 0) + 1


def _rrow(rows, counts, h, kind, os_type, outcome, matched_id, scope, detail=""):
    rows.append({"hash": h, "hashType": kind, "osType": os_type,
                 "outcome": outcome, "matchedId": matched_id, "scope": scope,
                 "detail": detail})
    counts[outcome] = counts.get(outcome, 0) + 1


def _tally(counts):
    return ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts)) or "(none)"


def expand_os_types(os_type_args):
    """Resolve --os-type values (repeatable; 'all' expands) to a de-duplicated,
    order-stable list validated against the API's enum."""
    requested = []
    for value in os_type_args or []:
        if value == "all":
            requested.extend(ALL_OS_TYPES)
        else:
            requested.append(value)
    if not requested:
        raise SystemExit("Error: add requires --os-type (repeatable, or 'all'). "
                         "Blocklist entries are per-OS.")
    result = []
    for value in requested:
        if value not in ALL_OS_TYPES:
            raise SystemExit("Error: invalid --os-type %r (valid: %s, all)"
                             % (value, ", ".join(ALL_OS_TYPES)))
        if value not in result:
            result.append(value)
    return result


# --- Report -----------------------------------------------------------------

def write_csv(out_dir, run_id, command, fields, rows):
    path = os.path.join(out_dir, "blocklist_%s_%s.csv" % (command, run_id))
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def write_manifest(out_dir, run_id, command, args, host, totals):
    path = os.path.join(out_dir, "blocklist_%s_%s_manifest.json"
                        % (command, run_id))
    manifest = {
        "runId": run_id,
        "timestampUtc": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "host": host,
        "scope": {
            "tenant": bool(args.tenant),
            "accountIds": args.account_id,
            "siteIds": args.site_id,
            "groupIds": args.group_id,
        },
        "totals": totals,
    }
    with open(path, "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return path


# --- CLI --------------------------------------------------------------------

def make_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def add_common(parser, writes):
    parser.add_argument("--host", required=True,
                        help="Console host (the one you log in to), e.g. "
                             "usea1-abc.sentinelone.net. NOT the xdr.* SDL host.")
    parser.add_argument("--token", default=os.environ.get("S1_CONSOLE_TOKEN"),
                        help="Console API token. Prefer the S1_CONSOLE_TOKEN env "
                             "var so it stays out of shell history.")
    parser.add_argument("--hash", action="append", default=[], metavar="HASH",
                        help="A hash to operate on. Repeatable.")
    parser.add_argument("--hash-file", metavar="PATH",
                        help="File of hashes, one per line ('#' comments ok).")

    parser.add_argument("--tenant", action="store_true",
                        help="Target the Global (tenant) scope.")
    parser.add_argument("--account-id", action="append", default=[], metavar="ID",
                        help="Account scope id. Repeatable.")
    parser.add_argument("--site-id", action="append", default=[], metavar="ID",
                        help="Site scope id. Repeatable.")
    parser.add_argument("--group-id", action="append", default=[], metavar="ID",
                        help="Group scope id. Repeatable.")

    parser.add_argument("--include-children", action="store_true",
                        help="Also include entries from child scopes in the read.")
    parser.add_argument("--out-dir", default=default_out_dir(),
                        help="Report output directory (default: <repo>/reports/"
                             "blocklist, resolved from this script's location).")
    if writes:
        parser.add_argument("--apply", action="store_true",
                            help="Actually write. WITHOUT this the run is a dry "
                                 "run: it queries and reports but changes nothing.")
        parser.add_argument("--dry-run", action="store_true",
                            help="Force a dry run (the default); overrides --apply.")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Report which hashes are already "
                             "blocked (read-only).",
                             formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common(p_check, writes=False)
    p_check.add_argument("--with-verdict", action="store_true",
                         help="Layer 3: also fetch the DEPRECATED reputation "
                              "verdict per SHA1 as a secondary signal "
                              "(best-effort).")
    p_check.add_argument("--no-threat-intel", action="store_true",
                         help="Skip layer 2 (the Threat Intelligence IOC store). "
                              "Use if the token lacks TI permissions or you only "
                              "care about the blocklist.")
    p_check.add_argument("--no-include-parents", action="store_true",
                         help="Do NOT include parent-scope entries. By default a "
                              "check includes them, so a hash blocked at "
                              "Global/Account shows as blocked at a Site.")

    p_add = sub.add_parser("add", help="Add hashes to the blocklist "
                           "(⚠️ writes; dry run by default).",
                           formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common(p_add, writes=True)
    p_add.add_argument("--os-type", action="append", default=[], metavar="OS",
                       help="OS for the entry: windows, macos, linux, "
                            "windows_legacy, or 'all'. Repeatable. Required.")
    p_add.add_argument("--description", metavar="TEXT",
                       help="Description stored on each entry (e.g. the advisory "
                            "id it came from).")
    p_add.add_argument("--source", metavar="TEXT",
                       help="Source field stored on each entry.")

    p_remove = sub.add_parser("remove", help="Remove blocklist entries for "
                              "hashes (⚠️ writes; dry run by default).",
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common(p_remove, writes=True)

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if not args.token:
        raise SystemExit("Error: no token: set --token or the S1_CONSOLE_TOKEN "
                         "environment variable")

    has_scope = args.tenant or args.account_id or args.site_id or args.group_id
    if not has_scope:
        raise SystemExit("Error: a scope is required — pass --tenant and/or "
                         "--account-id / --site-id / --group-id")

    scope_params = scope_query_params(args.account_id, args.site_id,
                                      args.group_id, args.tenant)
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    run_id = make_run_id()

    writes = args.command in ("add", "remove")
    dry_run = True
    if writes:
        dry_run = not args.apply or args.dry_run

    print("=" * 70)
    header = args.command.upper()
    if writes:
        header += "  —  " + ("APPLYING (writes)" if not dry_run
                             else "DRY RUN (no writes)")
    print(header)
    print("=" * 70)
    print("Host:   %s" % args.host)
    print("Scope:  %s" % scope_label(args.account_id, args.site_id,
                                     args.group_id, args.tenant))
    print("Output: %s" % out_dir)
    print("-" * 70)

    if args.command == "check":
        cmd_check(args, args.host, args.token, scope_params, out_dir, run_id)
    elif args.command == "add":
        cmd_add(args, args.host, args.token, scope_params, out_dir, run_id,
                dry_run)
    elif args.command == "remove":
        cmd_remove(args, args.host, args.token, scope_params, out_dir, run_id,
                   dry_run)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        raise SystemExit(130)
    except RuntimeError as exc:
        sys.stderr.write("\nError: %s\n" % exc)
        raise SystemExit(1)
