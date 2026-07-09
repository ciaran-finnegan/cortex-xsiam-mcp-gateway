# Audit Logging

## Status

Audit logging is implemented as FastMCP middleware. Every MCP tool invocation
emits structured JSON audit events at the tool boundary, including imported
OpenAPI tools.

The audit layer records activity; it does not replace authorization. Tool-level
authorization is still an alpha blocker for most non-log-search tools.

## Event Model

Events use `event_type=cortex_xsiam_mcp.tool_invocation` and schema version
`1.0`.

Important fields:

| Field | Description |
| --- | --- |
| `event_id` | Unique event identifier. |
| `timestamp` | UTC event timestamp. |
| `phase` | `start` or `end`. |
| `outcome` | `started`, `success`, `denied`, or `error`. |
| `tool` | MCP tool name. |
| `principal.id` | Human or service principal known to the server. |
| `principal.groups` | Groups/app roles known to the server. |
| `request.argument_names` | Names of supplied tool arguments. |
| `request.argument_hash` | SHA-256 hash of the redacted argument object. |
| `request.dataset` | Dataset when present. |
| `request.query_sha256` | SHA-256 hash of raw XQL when present. |
| `xsiam.api_key_id_sha256` | SHA-256 hash of the XSIAM API key ID in use. |

Raw XQL and natural-language prompts are not logged by default because they can
contain sensitive indicators, user identifiers, hostnames, or investigation
content.

## Example Event

```json
{
  "schema_version": "1.0",
  "event_type": "cortex_xsiam_mcp.tool_invocation",
  "event_id": "a3a2e8f0-01c0-45cb-80ef-35d1fdfdfc75",
  "timestamp": "2026-07-09T12:00:00.000000+00:00",
  "service": "cortex-xsiam-mcp-gateway",
  "phase": "end",
  "outcome": "success",
  "tool": "search_logs",
  "transport": "streamable-http",
  "principal": {
    "id": "analyst@example.com",
    "groups": ["Tier1"]
  },
  "request": {
    "argument_names": ["dataset", "filters", "limit"],
    "argument_hash": "4f0b...",
    "dataset": "xdr_data",
    "limit": 100,
    "filter_count": 2,
    "filter_fields": ["event_type", "severity"]
  },
  "result": {
    "success": "true",
    "executed": true,
    "query_id": "123456"
  }
}
```

## Local Structured Logs

Audit events are written through the `cortex_xsiam_mcp.audit` logger as compact
JSON. In container platforms, route stdout/stderr to the platform log pipeline
and retain audit logs according to security policy.

## Cortex XSIAM SIEM Export

Palo Alto documents HTTP Log Collectors for receiving third-party logs in JSON,
Raw, CEF, or LEEF format and sending data to
`https://api-{tenant external URL}/logs/v1/event`.

Recommended setup:

1. In Cortex XSIAM, create an HTTP Log Collector.
2. Configure it for JSON format.
3. Record the collector URL and generated key.
4. Set:

```bash
export AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED="true"
export AUDIT_LOG_XSIAM_HTTP_COLLECTOR_URL="https://api-your-xsiam-tenant.example/logs/v1/event"
export AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY="collector-api-key"
```

The exporter sends newline-delimited JSON events. Export failures are logged and
do not block tool execution by default.

## Fail-Closed Mode

Set `AUDIT_LOG_FAIL_CLOSED=true` only when the operations team is ready for tool
calls to fail if audit export fails. This is useful for high-assurance
deployments but can cause outages if the collector or network path is unstable.

## Sensitive Query Logging

`AUDIT_LOG_INCLUDE_QUERY_TEXT=false` by default. Keep it false unless legal,
privacy, and SOC operations explicitly require full query content. Hashes are
usually enough to correlate repeated queries without storing sensitive text.

