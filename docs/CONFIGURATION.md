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
numeric `| limit N` stage; the server clamps that stage to
`DATASET_QUERY_MAX_ROWS` before execution. Prefer `query_dataset` for routine
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
