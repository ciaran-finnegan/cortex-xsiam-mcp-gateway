# Cortex XSIAM MCP RBAC And Log Search Review

## Short Answer

This MCP server can be used to search XSIAM logs. It has a safer `search_logs`
tool for dataset-scoped log search and a legacy `execute_xql_query` tool for
privileged raw XQL.

It is not yet a complete governed enterprise log-search MCP because incoming
Entra identity validation, trusted gateway claim validation, and role-scoped
XSIAM credential brokering are still alpha blockers.

For the Entra ID and XSIAM role-based access goal, this server is a reasonable
base to fork and refactor, but the authorization layer must be added before it
is exposed to multiple users.

## Current Runtime Server

The useful server implementation is the Python `cortex-mcp` service copied into
this repository. It uses FastMCP and supports `stdio` and `streamable-http`
transport modes.

The current authentication model is server-to-XSIAM only:

- `CORTEX_MCP_PAPI_URL`
- `CORTEX_MCP_PAPI_AUTH_HEADER`
- `CORTEX_MCP_PAPI_AUTH_ID`

There is no current incoming user authentication, Entra token validation,
optional AI gateway identity verification, user role mapping, or per-user/per-role
credential selection.

Log search has an initial dataset policy hook:

- `LOG_SEARCH_DATASET_POLICY`
  JSON object mapping groups to allowed datasets. Use `*` for all datasets.
- `LOG_SEARCH_DEFAULT_PRINCIPAL_ID`
  Development/default principal until incoming identity is wired in.
- `LOG_SEARCH_DEFAULT_GROUPS`
  Comma-separated development/default groups until incoming identity is wired in.
- `RAW_XQL_PRIVILEGED_GROUPS`
  Comma-separated groups allowed to invoke `execute_xql_query`.
- `AUDIT_LOG_*`
  Structured audit logging and optional Cortex XSIAM HTTP Log Collector export.

Example:

```json
{
  "Security": ["*"],
  "Tier1": ["xdr_data"],
  "CloudTeam": ["xdr_data", "cloud_audit_logs"]
}
```

In production, `groups` should come from verified identity claims, not from
default environment variables. Some deployments can validate Entra ID tokens
directly in the MCP server. Deployments that already use Portkey, LiteLLM, or a
similar AI gateway can instead forward trusted identity claims from that gateway,
provided the MCP server validates the forwarding contract.

## Current Tools

Python-implemented tools:

- `get_cases`: searches XSIAM cases/incidents.
- `get_issues`: searches XSIAM issues/alerts.
- `execute_xql_query`: runs an arbitrary XQL query and polls for results. This
  is restricted to `RAW_XQL_PRIVILEGED_GROUPS`.
- `search_logs`: searches logs using raw XQL, structured parameters, or a
  conservative natural-language template translator.
- `get_xql_query_quota`: retrieves XQL query quota usage.

OpenAPI-generated tools:

- `get_tenant_info`
- `get_assets`
- `get_asset_by_id`
- `get_filtered_endpoints`
- `get_vulnerabilities`
- `get_assessment_profile_results`

Resources:

- Example case response JSON.
- Example issue response JSON.

CLI commands:

- `start`
- `update`
- `version`

## Log Search Capability

The preferred log search path is `search_logs`.

Users can search logs if all of the following are true:

- The XSIAM API key has XQL/query permissions.
- The requested dataset is allowed for the caller's groups.
- The query stays within practical time and result limits.
- The current shared API key is acceptable until credential brokering is
  implemented.

It supports three modes:

- Raw XQL through `query`.
- Structured XQL generation through `dataset`, `filters`, `fields`, and `limit`.
- Conservative natural-language translation through `natural_language_query`.

The natural-language path is intentionally template-based. It handles common
SOC searches such as failed login/authentication searches, severity terms,
usernames, hosts, and IPv4 addresses. It refuses ambiguous prompts rather than
inventing a query. A production natural-language-to-XQL capability should use an
approved LLM translation service plus policy checks before execution.

Before execution, `search_logs` checks the requested `dataset` against the
caller's groups. Security-team users can be granted `*`; other groups can be
limited to specific datasets. Raw XQL also requires the caller to provide the
intended `dataset` parameter so the policy decision is deterministic.

The legacy `execute_xql_query` path does not parse datasets from arbitrary XQL,
so it is restricted to privileged groups.

## XSIAM XQL API Review

The XSIAM API supports the log-search use case through these endpoints:

- `POST /public_api/v1/xql/start_xql_query`
  Starts an XQL query. The request can include `query`, optional `tenants`, and
  optional `timeframe`.
- `POST /public_api/v1/xql/get_query_results`
  Retrieves results for a query started through `start_xql_query`. The standard
  result endpoint is capped at 1000 results and does not provide normal
  pagination.
- `POST /public_api/v1/xql/get_query_results_stream`
  Retrieves larger result sets with a stream ID returned by the query API.
- `POST /public_api/v1/xql/get_quota`
  Retrieves XQL query quota usage.

The API documentation states that XSIAM allows up to four API queries in
parallel for this query family, so the MCP server should eventually add
concurrency control per tenant and per user.

Sources:

- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Start-an-XQL-query
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-XQL-query-results
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-XQL-query-results-Stream
- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-XQL-query-Quota

## Why It Is Not Yet Enough

The current server has these gaps:

- No incoming OAuth/OIDC/JWT validation for users.
- No mapping from Entra user or group claims to XSIAM roles.
- No full tool policy enforcement before every tool executes.
- Dataset allowlist exists for `search_logs`, but it still needs incoming
  identity, whether direct Entra validation or optional gateway-forwarded
  claims, plus broader XQL guardrails.
- No per-role XSIAM API key selection.
- Audit trail currently ties MCP requests to the principal in `MCPContext`;
  Entra-backed user identity is still pending.
- `execute_xql_query` remains a raw XQL path and is restricted to
  security-team/admin groups.

The raw XQL tool is powerful, so it should be treated as a privileged capability
until those controls exist.

## Recommended Target Model

Recommended flow:

1. User authenticates through Entra ID, either directly to the MCP server or via
   an optional AI gateway such as Portkey or LiteLLM.
2. MCP server verifies user identity directly, or validates trusted claims
   forwarded by the optional gateway, and receives stable claims such as user
   ID, UPN, tenant ID, groups, and app roles.
3. MCP server maps Entra groups/app roles to XSIAM roles and scopes.
4. MCP server checks a local policy before tool execution.
5. MCP server selects the least-privilege XSIAM API credential for that role.
6. MCP server calls XSIAM.
7. MCP server logs the user, role, tool, dataset/API endpoint, decision, and
   credential profile used.
8. MCP server exports audit events to Cortex XSIAM or another durable sink.

## Recommended Log Search Refactor

Keep `execute_xql_query` restricted to high-trust roles.

Continue hardening the safer first-class tool:

`search_logs(dataset, time_range, filters, fields, limit)`

The wrapper should:

- Enforce allowed datasets by role.
- Enforce max lookback windows by role.
- Enforce max result limits by role.
- Generate XQL from structured parameters instead of requiring arbitrary text.
- Allow natural-language input only through an approved translator and policy
  validator.
- Require explicit approval or higher role for broad/raw XQL.
- Redact or drop fields that the caller's role should not see.

Example role policy:

| Role | Allowed Capability |
| --- | --- |
| SOC Tier 1 | Search selected endpoint/security datasets, short lookback |
| Threat Hunter | Broader XQL search, longer lookback, more datasets |
| Incident Responder | Endpoint/case actions plus search |
| Admin | Raw XQL and administrative tools |

## Forking Recommendation

Proceed with this fork as the base for the XSIAM MCP gateway. Do not base the
gateway on the separate `cortex-xsiam-sdk-mcp-tools` project; that project is
for Demisto content development and SDK operations, not governed XSIAM log and
security operations access.

The first implementation milestone should be:

1. Add request identity model.
2. Add direct Entra identity verification for HTTP mode.
3. Add policy engine and tool metadata.
4. Add credential broker for role-scoped XSIAM API keys.
5. Add safe `search_logs` wrapper.
6. Add optional Portkey/LiteLLM-style gateway identity-forwarding validation.
7. Complete FastMCP 3 compatibility work.
