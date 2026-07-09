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

For local development before Entra/Portkey identity is wired in:

```bash
export LOG_SEARCH_DEFAULT_PRINCIPAL_ID="dev-analyst@example.com"
export LOG_SEARCH_DEFAULT_GROUPS="Security"
```

Do not use default groups as a production authorization mechanism.

## Example `.env`

```bash
CORTEX_MCP_PAPI_URL=https://api-your-xsiam-tenant.example
CORTEX_MCP_PAPI_AUTH_HEADER=replace-me
CORTEX_MCP_PAPI_AUTH_ID=replace-me
MCP_TRANSPORT=stdio
LOG_SEARCH_DATASET_POLICY={"Security":["*"],"Tier1":["xdr_data"]}
LOG_SEARCH_DEFAULT_GROUPS=Security
```

## Production Notes

- Use a secret manager for API credentials.
- Rotate API keys regularly.
- Use separate credentials for development and production tenants.
- Use role-scoped XSIAM API keys once credential brokering is implemented.
- Do not expose HTTP transport without incoming authentication.
