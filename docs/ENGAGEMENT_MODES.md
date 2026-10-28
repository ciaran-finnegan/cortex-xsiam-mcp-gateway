# Engagement Modes

An engagement records what an agent session is doing and what it has learned.
It holds a mode, an optional case id, the investigation scope, recorded facts,
and a log of every XQL query the session ran. Agents set scope once instead of
re-sending indicator lists with every query.

The MCP server sends `instructions` at initialization that tell clients to call
`set_engagement` first.

## Modes

| Mode | Use for | Default window | Default result shape | Hidden tools |
| --- | --- | --- | --- | --- |
| `incident_response` | A known incident with indicators and a time window. | 24 h | `rows` | none |
| `threat_hunt` | A hypothesis tested over a wider window. | 7 d | `aggregate` | none |
| `operations` | Health, volume, and coverage questions. | 1 h | `aggregate` | `execute_xql_query` |
| `unset` | Every session until `set_engagement` is called. | 1 h | `aggregate` | `execute_xql_query` |

`get_dataset_query_guidance` returns the workflow for the current mode under
`engagement.workflow`, alongside the generic query workflow.

## Modes Only Narrow Access

`TOOL_ACCESS_POLICY` and `LOG_SEARCH_DATASET_POLICY` remain the only grants.

- `authorize_tool` evaluates group policy first. The mode is applied after that
  decision and can only turn an allow into a deny.
- Dataset policy does not read the mode at all.
- The mode policy schema has no grant fields. Unknown keys, unknown modes,
  negative units, windows above `DATASET_QUERY_MAX_TIMEFRAME_MS`, and attempts
  to hide the engagement tools are rejected at startup and fail closed at
  runtime.

Tests in `tests/test_engagement.py` check every mode against every tool in the
test universe, including a mode policy that hides nothing, and confirm that a
Tier1 principal still cannot reach raw XQL or an ungranted dataset.

## Tool Listing

`ToolPolicyMiddleware.on_list_tools` advertises only tools the caller can
invoke: tools denied by group policy and tools hidden by the current mode are
removed. An unverified identity or an invalid policy lists nothing.
`set_engagement` sends `notifications/tools/list_changed` so clients re-list
after a mode change. Hidden tools are also denied on call, so a client that
skips listing gains nothing.

## Tools

| Tool | Purpose |
| --- | --- |
| `set_engagement(mode, case_id, iocs, internal, front_ends, servers, window, notes)` | Set mode and scope for this session. Omitted fields are restored from an existing case; an explicit empty list clears one. |
| `get_engagement()` | Current scope, the mode's policy, and this session's recorded spend against the mode budget. |
| `record_fact(key, value, evidence_query_id, confidence)` | Record a finding. `evidence_query_id` must be a query this engagement ran. |
| `get_engagement_log(case_id)` | Facts and the query log for a case, or for this session when `case_id` is omitted. |

Add these four tools to `TOOL_ACCESS_POLICY` for every group that should use
them. The default policy grants them to `SOC` and `Tier1`; `Security` and
`Admin` hold `*`.

### Scope Validation

| Field | Accepts | Cap |
| --- | --- | --- |
| `iocs` | IPv4/IPv6 addresses, CIDR ranges, hostnames or domains (optional leading `*.`), MD5/SHA1/SHA256 hashes | `ENGAGEMENT_MAX_SCOPE_ITEMS` |
| `internal`, `front_ends`, `servers` | IP addresses, CIDR ranges, hostnames | `ENGAGEMENT_MAX_SCOPE_ITEMS` |
| `case_id` | 1-64 characters: letters, digits, `.`, `_`, `-`; must start with a letter or digit | - |
| `window` | Relative or absolute timeframe; relative windows are frozen to absolute epoch milliseconds | `DATASET_QUERY_MAX_TIMEFRAME_MS` |
| `notes` | Free text, control characters removed | 2000 characters |
| `record_fact.key` | Lowercase letters, digits, `_`, `.`, `:`, `-` | 64 characters |
| `record_fact.value` | String, number, or boolean | 1024 characters |

Values are normalized (lowercase hostnames, canonical IPs and networks) and
deduplicated. Strict scope formats keep instructions and markup out of data the
server later returns to agents. Notes and fact values are free text and are
returned with `content_trust: "untrusted_data"`.

## Storage

### Session State

The engagement is stored with an awaited `ctx.set_state`, so FastMCP scopes it
to `ctx.session_id`. The state key also carries a SHA-256 of the principal id,
tenant id, and auth source, and the record stores that owner hash. A second
principal presenting the same session id reads and writes a different key and
sees `unset`. Session state uses FastMCP's default one-day TTL. The session
query log keeps the last 200 queries and 200 facts.

### Case Store

Set `ENGAGEMENT_STORE_DIR` to persist cases across sessions. Each case is a JSON
file at `<dir>/<owner sha256>/<case_id>.json`, so a principal can only read its
own cases.

- The directory must be an absolute path outside the gateway repository and
  outside any git working tree. Startup fails otherwise.
- Directories are created `0700` and files `0600`. Writes are atomic.
- Symbolic-link case files, files over 2 MiB, and files whose recorded owner
  does not match the caller are refused.
- A case keeps the last 1000 queries and 500 facts.

The store is a single-process local file store. Use one replica, or a shared
volume with a single writer, until a shared backend is added.

## Query Telemetry

`run_xql_query` records every query in the session log, and in the case file
when a case is set. Each entry holds:

| Field | Source |
| --- | --- |
| `query_id`, `tool`, `mode`, `case_id` | Executor result and the current tool call |
| `dataset` | First `dataset = <name>` stage of the XQL, else `null` |
| `window` | The XSIAM timeframe sent with the query |
| `rows`, `number_of_results` | Rows returned and XSIAM's reported total |
| `query_cost_units` | Sum of XSIAM `query_cost`; tenant keys are discarded |
| `remaining_quota`, `remaining_quota_delta` | XSIAM `remaining_quota` and the drop since this session's previous query |
| `units` | `query_cost_units` when present, else `remaining_quota_delta` |
| `duration_ms`, `status`, `error_type` | Executor timing and outcome |
| `query_sha256` | Hash of the XQL; query text is never stored |

The quota delta is approximate: other consumers of the tenant quota, and
concurrent queries in the same session, fall into it. Prefer `query_cost` when
XSIAM returns it.

Recording is telemetry only. It never blocks, retries, or alters a query, and a
recording failure is logged and ignored.

## Cost Guard Hooks

The cost guard in `run_xql_query` makes spend decisions. This module supplies
its inputs and makes none of them:

| Hook | Returns |
| --- | --- |
| `usecase.engagement.get_mode_policy(mode=None)` | The `ModePolicy` for a mode, defaulting to the current tool call's mode. |
| `usecase.engagement.current_mode()` | Mode of the current tool call. |
| `usecase.engagement.get_session_spend(ctx, principal)` | Query count and recorded units for this session. |
| `MCPContext.mode`, `MCPContext.case_id` | Set on every principal returned by `resolve_mcp_context`. |

`ModePolicy` fields: `default_window_ms`, `approval_threshold_units`,
`session_budget_units`, `reserve_units`, `default_result_shape`,
`heavy_tools_hidden`.

Budgets are spend ceilings for the cost guard, not access grants. Mode changes
are audited, and the session query log survives mode changes, so switching mode
does not reset recorded spend. A new MCP session starts with no recorded spend;
the tenant-wide reserve is the backstop.

## Mode Policy Overrides

`ENGAGEMENT_MODE_POLICY` is a JSON object of per-mode overrides merged over the
defaults above:

```bash
ENGAGEMENT_MODE_POLICY='{"threat_hunt":{"session_budget_units":10,"heavy_tools_hidden":["execute_xql_query"]}}'
```

Default units are a conservative starting point. Tune them to the tenant's
daily XQL quota.

## Audit

Every audit event carries `engagement.mode` and `engagement.case_id`. The start
event records the mode before the call; the end event records the mode after it,
so a `set_engagement` end event shows the new mode and `result.previous_mode`.
`set_engagement` requests log the mode, case id, and scope list sizes, never
scope values or notes. `record_fact` requests log the key, evidence query id,
and confidence, never the value.

## Continuation Cursors

Cursor version 2 binds the mode and case id. A cursor issued in one mode or
case is rejected in another, so changing the engagement invalidates open
cursors.
