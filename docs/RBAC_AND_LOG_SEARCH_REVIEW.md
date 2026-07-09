# Cortex XSIAM MCP RBAC And Log Search Review

## Short Answer

This MCP server can be used to search XSIAM logs. The preferred path is
`search_logs`, which is dataset-scoped, policy-checked, and designed for
Claude Code/Codex-style agents that turn plain-English investigation requests
into structured MCP tool calls.

The raw `execute_xql_query` tool remains available only to privileged groups.
Caller-supplied raw XQL through `search_logs(query=...)` is also privileged.

## Implemented Controls

The current alpha implementation includes:

- Entra bearer JWT validation for HTTP transport.
- Optional HMAC-signed trusted gateway identity forwarding for Portkey,
  LiteLLM, and similar gateways.
- Tool-level policy for every MCP tool through `TOOL_ACCESS_POLICY`.
- Dataset allowlist policy for `search_logs`, `list_log_datasets`, and
  `discover_log_fields`.
- Raw XQL restriction through `RAW_XQL_PRIVILEGED_GROUPS`.
- Role/group-scoped XSIAM credential selection from pre-provisioned API key
  profiles.
- Structured audit logging for every MCP tool invocation.
- Optional audit export to a Cortex XSIAM HTTP Log Collector.

For local stdio development, `LOG_SEARCH_DEFAULT_PRINCIPAL_ID` and
`LOG_SEARCH_DEFAULT_GROUPS` can still seed a development principal. Do not use
those defaults as production authorization.

## Current Tools

Python-implemented tools:

- `get_cases`: searches XSIAM cases/incidents.
- `get_issues`: searches XSIAM issues/alerts.
- `execute_xql_query`: privileged raw XQL query execution.
- `get_log_search_guidance`: compact agent instructions for XSIAM log search.
- `list_log_datasets`: policy-allowed dataset discovery.
- `discover_log_fields`: bounded XQL sample returning observed field metadata,
  not event values.
- `search_logs`: structured log search with optional privileged raw XQL.
- `get_xql_query_quota`: XQL query quota visibility.

OpenAPI-generated tools:

- `get_tenant_info`
- `get_assets`
- `get_asset_by_id`
- `get_filtered_endpoints`
- `get_vulnerabilities`
- `get_assessment_profile_results`

## Log Search Capability

The intended agent workflow is:

1. Agent translates the user's plain-English request into an investigation
   plan.
2. Agent calls `get_log_search_guidance`.
3. Agent discovers allowed datasets with `list_log_datasets`.
4. Agent discovers observed field names with `discover_log_fields`.
5. Agent calls `search_logs` with explicit `dataset`, `filters`, `fields`,
   `timeframe`, and a low `limit`.

`search_logs` supports two modes:

- Structured XQL generation through `dataset`, `filters`, `fields`, and
  `limit`.
- Privileged raw XQL through `query`.

It does not accept `natural_language_query`. The client agent is responsible
for interpreting plain English and producing structured MCP calls.

Before execution, the server checks:

- the MCP tool is allowed for the principal's groups/app roles;
- the requested dataset is allowed by `LOG_SEARCH_DATASET_POLICY`;
- raw XQL is allowed only for `RAW_XQL_PRIVILEGED_GROUPS`;
- result limits are capped.

## XSIAM XQL API Review

The XSIAM API supports the log-search use case through these endpoints:

- `POST /public_api/v1/xql/start_xql_query`
- `POST /public_api/v1/xql/get_query_results`
- `POST /public_api/v1/xql/get_query_results_stream`
- `POST /public_api/v1/xql/get_quota`
- `POST /public_api/v1/xql/get_datasets`

Field discovery uses bounded XQL samples because fields can vary by dataset,
parser, integration, and time range. Discovery returns field names, inferred
types, and observed counts only; it does not return sample event values.

Sources:

- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Start-an-XQL-query
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-XQL-query-results
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-XQL-query-results-Stream
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-XQL-query-Quota
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-all-datasets

## Credential Model

The gateway should not dynamically provision XSIAM API keys for every user.
Instead, provision least-privilege XSIAM API keys for roles or groups and map
verified Entra/gateway groups to those profiles with
`XSIAM_CREDENTIAL_PROFILES`.

If `XSIAM_CREDENTIAL_BROKER_ENABLED=true` and no credential profile matches the
principal, execution fails closed.

## Remaining Gaps

- Field-level output redaction is not implemented.
- Streaming XQL result retrieval is not implemented.
- Per-tenant/per-user XQL concurrency controls are not implemented.
- Live validation is still needed for each tenant-specific Entra, gateway,
  dataset, tool, credential, and audit-export configuration.
- FastMCP 3 compatibility work is still pending.

## Recommended Next Hardening

- Add field-level output policy for sensitive fields.
- Add streaming XQL result retrieval for controlled large investigations.
- Add XQL concurrency limits per tenant and principal.
- Add curated dataset catalog support for production tenants.
- Add live smoke tests for the target tenant using non-sensitive datasets and
  synthetic or approved security events.
