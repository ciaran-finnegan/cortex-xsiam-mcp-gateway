# Cortex XSIAM MCP Gateway

[![CI](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/actions/workflows/codeql.yml/badge.svg)](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/actions/workflows/scorecard.yml/badge.svg)](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/actions/workflows/scorecard.yml)

An MCP server for Cortex XSIAM security operations, with a focus on governed
agent access to XQL log search, issues, cases, endpoints, assets, and related
XSIAM APIs.

This project is a fork and hardening track for the Cortex MCP server. The target
architecture is an enterprise MCP server where users authenticate through
Microsoft Entra ID and XSIAM API access is constrained by the user's security
role. Teams that already centralize AI traffic through a gateway such as
Portkey or LiteLLM should be able to place that gateway in front of this server,
but that gateway is optional and is not required for every deployment.

## Status

Alpha. The current server is useful for local and trusted analyst workflows, but
it is not yet ready for unrestricted multi-user production exposure.

Implemented:

- FastMCP server with `stdio` and `streamable-http` transports.
- XSIAM API key based server-to-XSIAM authentication.
- XQL execution and result polling.
- `search_logs` tool for raw XQL, structured filters, and conservative
  natural-language query translation.
- Dataset allowlist enforcement for `search_logs`.
- XSIAM tools for cases, issues, tenant info, assets, endpoints,
  vulnerabilities, and assessment profile results.
- CI, CodeQL, dependency review, Dependabot, and OpenSSF Scorecard workflows.

Planned:

- Entra ID incoming identity verification for direct MCP deployments.
- Optional gateway identity-forwarding validation for deployments that use
  Portkey, LiteLLM, or similar AI gateways.
- Role-to-dataset and role-to-credential mapping from real user claims.
- Per-role least-privilege XSIAM API credential selection.
- Tool-level authorization for all tools, including raw XQL.
- Audit logs tying every MCP call to a human principal.
- Streaming support for large XQL result sets.

## Why This Exists

Security teams want agents to help with XSIAM investigations, but unrestricted
agent access to a broad XSIAM API key is not acceptable. Analysts may be allowed
to query only specific datasets, while members of the security team may be
allowed to query every dataset.

This project provides a path toward:

- natural-language security investigation workflows;
- deterministic XQL execution for advanced analysts;
- dataset allowlists for non-security users;
- role-scoped access using Entra groups/app roles;
- least-privilege downstream XSIAM credentials;
- auditable agent activity.

## Core Tools

| Tool | Purpose |
| --- | --- |
| `search_logs` | Search XSIAM logs using raw XQL, structured filters, or safe natural-language templates. |
| `execute_xql_query` | Execute analyst-authored raw XQL. This should be restricted to security/admin roles before production use. |
| `get_xql_query_quota` | Retrieve XQL query quota usage. |
| `get_issues` | Search XSIAM issues/alerts. |
| `get_cases` | Search XSIAM cases/incidents. |
| `get_tenant_info` | Retrieve tenant/license information. |
| `get_assets`, `get_asset_by_id` | Retrieve asset inventory data. |
| `get_filtered_endpoints` | Retrieve endpoint data. |
| `get_vulnerabilities` | Retrieve vulnerability data. |
| `get_assessment_profile_results` | Retrieve assessment profile results. |

## Log Search Modes

### Raw XQL

Use `query` for advanced analysts who already know XQL:

```json
{
  "dataset": "xdr_data",
  "query": "dataset = xdr_data | filter event_type contains \"authentication\" | limit 100"
}
```

The explicit `dataset` parameter is required for deterministic dataset policy
checks. Do not infer authorization by trying to parse arbitrary XQL.

### Structured Search

Use `dataset`, `filters`, `fields`, and `limit` for routine agent workflows:

```json
{
  "dataset": "xdr_data",
  "filters": [
    {"field": "event_type", "operator": "contains", "value": "authentication"},
    {"field": "severity", "operator": "in", "value": ["high", "critical"]}
  ],
  "fields": ["event_id", "event_type", "severity"],
  "limit": 100
}
```

### Natural Language

Use `natural_language_query` for common SOC patterns:

```json
{
  "dataset": "xdr_data",
  "natural_language_query": "failed login for user alice on host laptop-01 from 192.0.2.10 in the last 24 hours",
  "limit": 50
}
```

The current translator is intentionally conservative. It handles common terms
such as failed login/authentication, severity, username, host, IPv4 address, and
relative windows like `last 24 hours`. Ambiguous prompts are refused rather than
converted into speculative XQL.

## Dataset Authorization

Configure dataset access with `LOG_SEARCH_DATASET_POLICY`.

Example:

```json
{
  "Security": ["*"],
  "Tier1": ["xdr_data"],
  "CloudTeam": ["xdr_data", "cloud_audit_logs"]
}
```

- `Security` can query every dataset.
- `Tier1` can query only `xdr_data`.
- `CloudTeam` can query `xdr_data` and `cloud_audit_logs`.

Until incoming identity is implemented, local development can set default
groups:

```bash
export LOG_SEARCH_DEFAULT_PRINCIPAL_ID="dev-analyst@example.com"
export LOG_SEARCH_DEFAULT_GROUPS="Security"
```

In production, groups must come from verified identity claims, not from
development defaults. In a direct deployment, this means claims validated from
Entra ID by the MCP server. In a gateway deployment, Portkey, LiteLLM, or a
similar gateway may authenticate the user and forward trusted identity claims,
but the MCP server still needs a way to validate that forwarding contract.

## Optional AI Gateway Deployment

Portkey, LiteLLM, and similar AI gateways are supported architecture patterns,
not mandatory dependencies.

Use a gateway when you need centralized model routing, usage controls, prompt
logging, policy enforcement, or a standard place to attach enterprise identity
for many AI applications. In that model, the gateway can authenticate users,
forward signed or otherwise verifiable identity claims, and route MCP traffic to
this server.

Skip the gateway when your MCP client can authenticate directly with Entra ID
and call this server without shared AI gateway infrastructure. In that model,
the MCP server validates the Entra token itself and applies the same tool,
dataset, credential, and audit policies.

## Configuration

Required:

```bash
export CORTEX_MCP_PAPI_URL="https://api-your-xsiam-tenant.example"
export CORTEX_MCP_PAPI_AUTH_HEADER="your-api-key"
export CORTEX_MCP_PAPI_AUTH_ID="your-api-key-id"
```

Optional:

```bash
export MCP_TRANSPORT="stdio"                    # stdio or streamable-http
export MCP_HOST="0.0.0.0"
export MCP_PORT="8080"
export MCP_PATH="/api/v1/stream/mcp"
export LOG_SEARCH_DATASET_POLICY='{"Security":["*"],"Tier1":["xdr_data"]}'
export LOG_SEARCH_DEFAULT_GROUPS="Security"     # development only
```

See [Configuration](docs/CONFIGURATION.md) for full details.

## Local Development

Requirements:

- Python 3.12 or 3.13. Python 3.14 is not currently supported by all native
  dependencies.
- Poetry.

Install:

```bash
poetry env use python3.12
poetry install
```

Run checks:

```bash
poetry run pytest
poetry run ruff check src tests
```

`mypy src` is a hardening target but is not yet a required gate because the
fork still carries inherited typing debt.

Run the MCP server:

```bash
poetry run python src/main.py
```

For Claude Desktop or Cursor, configure the MCP client to execute
`poetry run python src/main.py` or run the Docker image.

## Docker

```bash
docker build -t cortex-xsiam-mcp-gateway .
docker run --rm -i --env-file .env cortex-xsiam-mcp-gateway
```

## Security Model

The intended production security model is:

1. User authenticates through Entra ID, either directly to the MCP server or
   through an optional AI gateway such as Portkey or LiteLLM.
2. MCP server validates identity directly, or validates trusted claims forwarded
   by the optional gateway, and extracts stable claims.
3. Groups/app roles are mapped to MCP roles.
4. Tool and dataset policy is evaluated before execution.
5. The server selects a least-privilege XSIAM API credential for the role.
6. The XSIAM API call is made.
7. The request, decision, user, tool, dataset, and credential profile are logged.

See [Security Model](docs/SECURITY_MODEL.md).

## Repository Security

This repository includes:

- GitHub Actions CI.
- CodeQL analysis.
- Dependency Review.
- Dependabot updates.
- OpenSSF Scorecard.
- Security policy and private vulnerability reporting guidance.

Maintainers should also enable GitHub repository settings for:

- private vulnerability reporting;
- Dependabot alerts and security updates;
- secret scanning;
- branch protection for `main`.

## Licensing

This repository contains upstream code made available under the Palo Alto
Networks Cortex Communication Python Files License 1.0. That license permits
derivative works only for use with Palo Alto Networks Cortex XSIAM, Cortex
Cloud, Cortex XDR, and AgentiX products, and it imposes redistribution
requirements.

New separable project additions in this fork, including documentation, tests,
GitHub workflow configuration, and original glue code added for dataset policy
and gateway hardening, are offered under Apache License 2.0 where legally
separable from the upstream work.

The combined repository must still comply with the upstream Palo Alto Networks
license. See [NOTICE](NOTICE.md), [LICENSE](LICENSE), and
[Apache-2.0](LICENSES/Apache-2.0.txt).

This is a licensing summary, not legal advice.

## Project Governance

See:

- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Governance](GOVERNANCE.md)
- [Roadmap](docs/ROADMAP.md)

## Disclaimer

This is a community project. It is not officially supported by Palo Alto
Networks. Use it with least-privilege credentials and test it in non-production
tenants before using it in production workflows.
