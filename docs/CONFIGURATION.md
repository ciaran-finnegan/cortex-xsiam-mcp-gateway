# Configuration

Configuration is loaded from environment variables and optional `.env` files.
Do not commit `.env` files.

## Required XSIAM API Settings

| Variable | Description |
| --- | --- |
| `CORTEX_MCP_PAPI_URL` | XSIAM tenant API URL. If missing `api-`, the client normalizes the hostname. |
| `CORTEX_MCP_PAPI_AUTH_HEADER` | XSIAM API key value. |
| `CORTEX_MCP_PAPI_AUTH_ID` | XSIAM API key ID. |

## MCP Server Settings

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `MCP_HOST` | `0.0.0.0` | Host for HTTP transport. |
| `MCP_PORT` | `8080` | Port for HTTP transport. |
| `MCP_PATH` | `/api/v1/stream/mcp` | HTTP MCP path. |
| `MCP_ALLOW_UNAUTHENTICATED_HTTP` | `false` | Explicit isolated-test override. HTTP startup otherwise fails when identity mode is `none`. |
| `LOG_LEVEL` | `INFO` | Python log level. |

## Dataset Policy

`LOG_SEARCH_DATASET_POLICY` is a JSON object mapping group names to allowed
datasets. Use `*` to allow all datasets.

```bash
export LOG_SEARCH_DATASET_POLICY='{
  "Security": ["*"],
  "Tier1": ["xdr_data"],
  "CloudTeam": ["xdr_data", "cloud_audit_logs"]
}'
```

For local development before incoming identity is wired in:

```bash
export LOG_SEARCH_DEFAULT_PRINCIPAL_ID="dev-analyst@example.com"
export LOG_SEARCH_DEFAULT_GROUPS="Security"
```

Do not use default groups as a production authorization mechanism.

## Raw XQL Privilege

`execute_xql_query` is restricted to groups listed in
`RAW_XQL_PRIVILEGED_GROUPS`. It additionally requires that dataset policy grant
the principal `*`, because raw XQL can contain joins and subqueries that cannot
be authorized from one caller-declared dataset.

```bash
export RAW_XQL_PRIVILEGED_GROUPS="Security,Admin"
```

Use this raw XQL tool only for high-trust roles. Every raw query must end with a
numeric `| limit N` stage; the server strips `//` and `/* */` comments, then
clamps that stage to `DATASET_QUERY_MAX_ROWS` before execution, so a limit
written inside a comment does not count. Prefer `query_dataset` for routine
agent workflows because it requires an explicit dataset and compiles only
allowlisted query operations.

## Incoming Identity

HTTP transport supports three identity modes:

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_IDENTITY_AUTH_MODE` | `none` | `none`, `entra`, `gateway`, or `entra_or_gateway`. Use `none` only for local development or isolated stdio use. |
| `ENTRA_TENANT_ID` | empty | Tenant ID used to derive Entra issuer and JWKS URL. |
| `ENTRA_AUDIENCE` | empty | Expected `aud` claim for this MCP API. Required for Entra mode. |
| `ENTRA_ISSUER` | derived | Optional explicit expected issuer. |
| `ENTRA_JWKS_URI` | derived | Optional explicit JWKS URL. |
| `ENTRA_REQUIRED_SCOPES` | empty | Comma- or space-separated scopes required on bearer tokens. |
| `ENTRA_GROUPS_CLAIM` | `groups` | Claim containing group IDs or names. |
| `ENTRA_ROLES_CLAIM` | `roles` | Claim containing app roles. |

Gateway mode validates a signed forwarding contract rather than trusting plain
headers:

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_GATEWAY_SHARED_SECRET` | empty | HMAC secret shared only between the trusted gateway and this MCP service. |
| `MCP_GATEWAY_ALLOWED_ISSUERS` | empty | Optional comma-separated gateway issuer allowlist such as `portkey,litellm`. |
| `MCP_GATEWAY_MAX_CLOCK_SKEW_SECONDS` | `300` | Maximum age/skew for signed gateway assertions. |
| `MCP_GATEWAY_NONCE_CACHE_SIZE` | `10000` | Maximum in-memory replay entries for signed assertions. Saturation fails closed until entries expire. Use shared replay state before running multiple replicas. |

The gateway signature covers issuer, principal, groups, roles, timestamp, and
nonce. Do not deploy gateway mode unless the MCP service is reachable only from
the trusted gateway or a network segment with equivalent controls.

## Tool Policy

`TOOL_ACCESS_POLICY` maps verified groups/app roles to allowed MCP tools.

```bash
export TOOL_ACCESS_POLICY='{
  "Security": ["*"],
  "Tier1": [
    "get_log_search_guidance",
    "get_dataset_query_guidance",
    "get_xql_help",
    "list_log_datasets",
    "discover_log_fields",
    "query_dataset",
    "continue_dataset_query",
    "search_logs",
    "get_xql_query_quota",
    "get_cases",
    "get_issues"
  ]
}'
```

Tool policy is enforced for every MCP tool invocation. Dataset policy still
runs inside discovery and query tools.

## Structured Dataset Query Limits

| Variable | Default | Description |
| --- | --- | --- |
| `DATASET_QUERY_MAX_ROWS` | `100` | Maximum rows or aggregate groups returned by one call; valid range 1-1000. Continuation pages reserve one XSIAM result slot for lookahead, so their effective maximum is 999. |
| `DATASET_QUERY_MAX_FIELDS` | `25` | Maximum projected fields. Unrequested fields are removed server-side. |
| `DATASET_QUERY_MAX_FILTERS` | `20` | Maximum typed filters. |
| `DATASET_QUERY_MAX_METRICS` | `8` | Maximum aggregate metrics. |
| `DATASET_QUERY_MAX_GROUP_FIELDS` | `5` | Maximum aggregate grouping fields. |
| `DATASET_QUERY_MAX_RESPONSE_BYTES` | `65536` | Approximate serialized row budget. |
| `DATASET_QUERY_MAX_CELL_CHARS` | `2048` | Maximum string length per result cell. |
| `DATASET_QUERY_MAX_TIMEFRAME_MS` | `2592000000` | Maximum relative/absolute timeframe span; default 30 days. |
| `DATASET_QUERY_CURSOR_SECRET` | empty | Secret used to encrypt and authenticate continuation cursors. Required for continuation. |
| `DATASET_QUERY_CURSOR_TTL_SECONDS` | `900` | Cursor validity period. |
| `XQL_MAX_CONCURRENT_QUERIES` | `4` | Process-level XQL concurrency, hard-capped at XSIAM's four-query limit. |
| `XQL_MAX_QUERY_CHARS` | `32768` | Maximum compiled or privileged raw XQL length. |

Cursor state is bound to principal, tenant, auth source, groups, query plan, and
the current dataset-policy hash. A policy or identity change invalidates the
cursor, and policy is checked again on continuation.

## XQL Cost Guard

Every XQL query, whether raw, typed, discovery, or helper, passes the cost guard
in `run_xql_query` before submission. XSIAM charges compute units for bytes
scanned, and the API budget is shared with SOC tooling and playbook automation;
once it is spent, every query fails until 00:00 UTC.

Every query tool requires a `timeframe` (`{"from_ms": ..., "to_ms": ...}` or
`{"relative_ms": ...}`; the API shapes `{"from", "to"}` and `{"relativeTime"}`
are accepted). There is no server default window. The span is checked against
`DATASET_QUERY_MAX_TIMEFRAME_MS`, and so is any `config timeframe = <n><unit>`
stage inside raw XQL. `config timeframe between ...` is rejected; pass absolute
ranges in the `timeframe` argument.

The guard classifies each query as `light`, `medium`, `heavy`, or `extreme`
from a score:

| Factor | Points |
| --- | --- |
| Dataset tier `light` / `medium` / `heavy` (highest tier referenced; no dataset clause counts as `heavy`) | 0 / 2 / 4 |
| Window up to 1 d / 7 d / 30 d / 90 d / longer | 0 / 1 / 2 / 3 / 4 |
| Heavy dataset without a positive `=` or `in` filter on a field in `COST_GUARD_SELECTIVE_FIELDS` | +1 |
| `contains`, `~=`, `regextract`, `regexcapture` | +1 |
| `_raw_log` or `to_json_string(` | +2 |
| `join`, `union`, `dedup` / `search` / `call` | +1 each / +2 / +3 |

Scores up to 2 are light, up to 4 medium, up to 6 heavy, and above that
extreme. A query with only dataset, `fields`, `limit`, and `config` stages is an
early-exit sample and scores its tier points minus one, whatever the window.
Comments and string literals are removed before parsing, so neither can hide or
fake a stage. The dataset tier comes from the authored catalogue `volume` when
the catalogue is installed (`very_high` is heavy, `high` medium, `medium` and
`low` light), then `COST_GUARD_DATASET_TIERS`, then `COST_GUARD_DEFAULT_TIER`.
Estimates are deliberately conservative; tune the tier map and bands against
the `actual_units` each result records.

Rules, in order:

1. A cached result for the same principal, query text, timeframe, and limit is
   returned within `COST_GUARD_CACHE_TTL_SECONDS` without spending quota.
2. While `COST_GUARD_LONG_SLOT_LIMIT` queries have held a query slot longer than
   `COST_GUARD_LONG_SLOT_SECONDS`, new heavy and extreme queries are refused.
3. Any query whose estimate (the band's high bound), plus the estimates of
   queries in flight, would take the remaining quota below the reserve is
   refused. Approval never overrides the reserve. When the remaining quota is
   unknown, the guard reads `/xql/get_quota`; if it still cannot tell, heavy and
   extreme queries are refused.
4. A query whose estimate exceeds the approval threshold needs approval. When
   the MCP client supports elicitation, the guard asks the analyst directly with
   the estimate and alternatives. Otherwise, or when that prompt is cancelled,
   the tool's `approval` argument must carry the analyst's own words; the
   gateway stores only its SHA-256 and counts the approved units against a
   per-principal daily cap. An explicit decline is final for that call.

The approval threshold and reserve come from the engagement mode policy
(`get_mode_policy`) when engagement modes are installed, and from the settings
below otherwise. An `approval` string is an accountability record, not proof
that a human typed it; the cap bounds what an agent could approve for itself,
and clients with elicitation never rely on it unless the prompt is cancelled.

A refusal returns `success: false`, `error: "cost_guard"`, a `message` beginning
"Query not allowed by the cost guard", the `rule` (`approval_required`,
`approval_declined`, `approval_cap`, `reserve`, or `long_running_slots`), the
`estimate`, `remaining_units`, `reserve_units`, `approval_threshold_units`,
`mode`, and deterministic `alternatives`, each with its own estimate: the last
7 days and 24 hours of the window, a host filter when the engagement lists
servers, counts instead of rows, a cheaper dataset that the principal may query
(field names differ, so it carries no XQL), and the unchanged XQL for the XSIAM
console, which is not charged to the API quota.

Every result carries `quota`: `estimate_units`, `estimate_class`,
`estimate_band`, `actual_units` (from `query_cost`, else the drop in
`remaining_quota`), `actual_units_source`, `remaining_units`,
`session_spent_units`, `cached`, `approved`, and `approval_method`.

| Variable | Default | Description |
| --- | --- | --- |
| `COST_GUARD_ENABLED` | `true` | Apply the cache and the refusal rules. The timeframe requirement and timeout ceiling apply either way. |
| `COST_GUARD_UNIT_BANDS` | `{"light":[0.001,0.4],"medium":[0.5,3.6],"heavy":[5,9],"extreme":[10,31]}` | Unit band per class. Decisions use the high bound. |
| `COST_GUARD_DATASET_TIERS` | `{"xdr_data":"heavy","xdr_*":"heavy","*_story":"heavy","amazon_aws_raw":"heavy","msft_azure_raw":"heavy","google_gcp_*":"heavy"}` | Dataset name or `*` glob to `light`, `medium`, or `heavy`. Exact names win over globs. |
| `COST_GUARD_DEFAULT_TIER` | `medium` | Tier for datasets the catalogue and tier map do not list. |
| `COST_GUARD_SELECTIVE_FIELDS` | `agent_hostname,agent_id,endpoint_id,endpoint_name,host_name,hostname` | Fields whose positive equality scopes a heavy dataset to hosts. |
| `COST_GUARD_HOST_FIELDS` | `{"xdr_data":"agent_hostname"}` | Field used by the host-filter alternative per heavy dataset. |
| `COST_GUARD_CHEAPER_DATASETS` | `{"amazon_aws_raw":["cloud_audit_logs"],"msft_azure_raw":["cloud_audit_logs"]}` | Cheaper datasets for the same question. Catalogue datasets in the same domain that the principal's policy lists are added. |
| `COST_GUARD_APPROVAL_THRESHOLD_UNITS` | `1.0` | Approval threshold when engagement modes are not installed. Matches the unset mode. |
| `COST_GUARD_RESERVE_UNITS` | `20.0` | Units kept for automation when engagement modes are not installed. Matches the unset mode. |
| `COST_GUARD_APPROVAL_DAILY_CAP_UNITS` | `10.0` | Units one principal may approve per UTC day with the `approval` argument. `0` disables the argument. Elicitation approvals are not capped. |
| `COST_GUARD_DAILY_QUOTA_UNITS` | `0` | Daily budget used with `get_quota`'s `daily_used_quota`. `0` derives it from `license_quota` plus `additional_purchased_quota`, divided by 365. |
| `COST_GUARD_QUOTA_STALE_SECONDS` | `300` | Age after which the last observed `remaining_quota` is refreshed from `get_quota`. |
| `COST_GUARD_ELICITATION_ENABLED` | `true` | Ask the analyst through MCP elicitation when the client supports it. |
| `COST_GUARD_ELICITATION_TIMEOUT_SECONDS` | `120` | Time to wait for an answer before treating the prompt as unanswered. |
| `COST_GUARD_LONG_SLOT_SECONDS` | `60` | Slot age that counts as long-running. |
| `COST_GUARD_LONG_SLOT_LIMIT` | `2` | Long-running slots that block new heavy queries. |
| `COST_GUARD_CACHE_TTL_SECONDS` | `600` | Result cache lifetime. `0` disables the cache. |
| `COST_GUARD_CACHE_MAX_ENTRIES` | `64` | Cached results kept per process, least recently used first out. |
| `XQL_TIMEOUT_CEILING_SECONDS` | `120` | Ceiling for any query timeout, including `execute_xql_query`'s `timeout`. |
| `XQL_TIMEOUT_APPROVED_CEILING_SECONDS` | `300` | Ceiling once the query is approved. An `approval` on a query below the threshold also lifts the ceiling, recorded with zero units. |

Cache entries, approval totals, quota observations, and slot timings live in
the gateway process. Each replica keeps its own; size the cap and reserve with
the replica count in mind.

## XSIAM Credential Broker

The gateway does not dynamically create per-user XSIAM API keys. Instead, set
up role-scoped XSIAM API keys in advance and reference their environment
variable names:

```bash
export XSIAM_CREDENTIAL_BROKER_ENABLED=true
export XSIAM_CREDENTIAL_PROFILES='{
  "Tier1": {
    "priority": 10,
    "profile_name": "tier1-readonly",
    "api_key_env": "XSIAM_T1_KEY",
    "api_key_id_env": "XSIAM_T1_KEY_ID"
  },
  "Security": {
    "profile_name": "security-analyst",
    "api_key_env": "XSIAM_SEC_KEY",
    "api_key_id_env": "XSIAM_SEC_KEY_ID"
  }
}'
```

Store the actual API key values in your secret manager or local environment.
If the broker is enabled and no profile matches the verified principal, tool
execution fails closed. When several groups match, the lowest numeric
`priority` wins; group claim order is not trusted as authorization policy.

## Audit Logging

| Variable | Default | Description |
| --- | --- | --- |
| `AUDIT_LOG_ENABLED` | `true` | Emit structured audit events for tool calls. |
| `AUDIT_LOG_EMIT_START_EVENTS` | `true` | Emit a start event before the tool runs. |
| `AUDIT_LOG_INCLUDE_QUERY_TEXT` | `false` | Include raw XQL query text instead of hashes only. |
| `AUDIT_LOG_FAIL_CLOSED` | `false` | Fail tool calls if audit export fails. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED` | `false` | Forward audit events to a Cortex XSIAM HTTP Log Collector. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_URL` | empty | Collector URL, for example `https://api-tenant/logs/v1/event`. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY` | empty | HTTP collector API key. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_TIMEOUT_SECONDS` | `10` | Export timeout. |

Keep `AUDIT_LOG_INCLUDE_QUERY_TEXT=false` unless full query retention has been
approved. Query hashes are logged by default.

## Example `.env`

```bash
CORTEX_MCP_PAPI_URL=https://api-your-xsiam-tenant.example
CORTEX_MCP_PAPI_AUTH_HEADER=replace-me
CORTEX_MCP_PAPI_AUTH_ID=replace-me
MCP_TRANSPORT=streamable-http
MCP_IDENTITY_AUTH_MODE=entra
ENTRA_TENANT_ID=replace-with-tenant-id
ENTRA_AUDIENCE=api://your-mcp-app-registration
LOG_SEARCH_DATASET_POLICY={"Security":["*"],"Tier1":["xdr_data"]}
TOOL_ACCESS_POLICY={"Security":["*"],"Tier1":["get_dataset_query_guidance","list_log_datasets","discover_log_fields","query_dataset","continue_dataset_query"]}
RAW_XQL_PRIVILEGED_GROUPS=Security,Admin
DATASET_QUERY_CURSOR_SECRET=replace-with-a-long-random-secret
AUDIT_LOG_ENABLED=true
AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED=false
```

## Production Notes

- Use a secret manager for API credentials.
- Rotate API keys regularly.
- Use separate credentials for development and production tenants.
- Use role-scoped XSIAM API keys through the credential broker for shared HTTP
  deployments.
- Do not expose HTTP transport without incoming authentication.
- Keep audit logging enabled for security testing and production pilots.
- Export audit events to Cortex XSIAM or another durable SIEM/log system.
- An AI gateway such as Portkey or LiteLLM is optional. Use one when it is part
  of your enterprise AI control plane; otherwise validate Entra ID tokens
  directly in the MCP server.
