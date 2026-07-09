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

`execute_xql_query` is restricted to groups listed in
`RAW_XQL_PRIVILEGED_GROUPS`.

```bash
export RAW_XQL_PRIVILEGED_GROUPS="Security,Admin"
```

Use this legacy raw XQL tool only for high-trust roles. Prefer `search_logs`
for routine agent workflows because it requires an explicit dataset and applies
dataset policy.

## Audit Logging

| Variable | Default | Description |
| --- | --- | --- |
| `AUDIT_LOG_ENABLED` | `true` | Emit structured audit events for tool calls. |
| `AUDIT_LOG_EMIT_START_EVENTS` | `true` | Emit a start event before the tool runs. |
| `AUDIT_LOG_INCLUDE_QUERY_TEXT` | `false` | Include raw XQL/NL query text instead of hashes only. |
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
- Use role-scoped XSIAM API keys once credential brokering is implemented.
- Do not expose HTTP transport without incoming authentication.
- Keep audit logging enabled for security testing and production pilots.
- Export audit events to Cortex XSIAM or another durable SIEM/log system.
- An AI gateway such as Portkey or LiteLLM is optional. Use one when it is part
  of your enterprise AI control plane; otherwise validate Entra ID tokens
  directly in the MCP server.
