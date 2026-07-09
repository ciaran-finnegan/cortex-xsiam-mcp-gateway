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
| `LOG_LEVEL` | `DEBUG` | Python log level. |

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

`execute_xql_query` and caller-supplied raw XQL through `search_logs(query=...)`
are restricted to groups listed in `RAW_XQL_PRIVILEGED_GROUPS`.

```bash
export RAW_XQL_PRIVILEGED_GROUPS="Security,Admin"
```

Use this legacy raw XQL tool only for high-trust roles. Prefer `search_logs`
for routine agent workflows because it requires an explicit dataset and applies
dataset policy.

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
    "list_log_datasets",
    "discover_log_fields",
    "search_logs",
    "get_xql_query_quota",
    "get_cases",
    "get_issues"
  ]
}'
```

Tool policy is enforced for every MCP tool invocation. Dataset policy still
runs inside log-search tools.

## XSIAM Credential Broker

The gateway does not dynamically create per-user XSIAM API keys. Instead, set
up role-scoped XSIAM API keys in advance and reference their environment
variable names:

```bash
export XSIAM_CREDENTIAL_BROKER_ENABLED=true
export XSIAM_CREDENTIAL_PROFILES='{
  "Tier1": {
    "profile_name": "tier1-readonly",
    "api_key_env": "XSIAM_TIER1_API_KEY",
    "api_key_id_env": "XSIAM_TIER1_API_KEY_ID"
  },
  "Security": {
    "profile_name": "security-analyst",
    "api_key_env": "XSIAM_SECURITY_API_KEY",
    "api_key_id_env": "XSIAM_SECURITY_API_KEY_ID"
  }
}'
```

Store the actual API key values in your secret manager or local environment.
If the broker is enabled and no profile matches the verified principal, tool
execution fails closed.

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
MCP_TRANSPORT=stdio
LOG_SEARCH_DATASET_POLICY={"Security":["*"],"Tier1":["xdr_data"]}
LOG_SEARCH_DEFAULT_GROUPS=Security
RAW_XQL_PRIVILEGED_GROUPS=Security,Admin
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
