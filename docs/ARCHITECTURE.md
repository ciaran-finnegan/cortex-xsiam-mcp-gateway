# Architecture

## Overview

Cortex XSIAM MCP Gateway is a FastMCP server that exposes Cortex XSIAM
capabilities to MCP clients. The current implementation supports local stdio
development and centrally hosted HTTP deployments with incoming identity,
tool policy, dataset policy, audit logging, and optional role-scoped XSIAM
credential selection.

An AI gateway such as Portkey or LiteLLM is optional. Teams can deploy this MCP
server directly behind Entra ID token validation, or place it behind an AI
gateway when they already use one for central model routing, policy, telemetry,
or identity forwarding.

```mermaid
flowchart LR
  User["User"] --> Client["MCP client"]
  Client --> OptionalGateway["Optional AI gateway<br/>Portkey, LiteLLM, etc."]
  Client --> MCP["MCP server"]
  OptionalGateway --> MCP
  MCP --> Auth["Identity validation<br/>Entra ID token or trusted gateway claims"]
  Auth --> Policy["Tool and dataset policy"]
  Policy --> Broker["Credential broker"]
  Broker --> XSIAM["Cortex XSIAM API"]
  Policy --> Audit["Audit log"]
```

## Runtime Components

| Component | Responsibility |
| --- | --- |
| `src/main.py` | Starts the FastMCP server and imports built-in/OpenAPI tools. |
| `src/service/cortex_mcp/server.py` | Creates the FastMCP server and lifespan context. |
| `src/usecase/builtin_components/` | Python tool modules. |
| `src/usecase/builtin_components/openapi/` | OpenAPI fragments converted into MCP tools. |
| `src/usecase/fetcher.py` | Calls XSIAM public APIs. |
| `src/usecase/identity.py` | Validates Entra/gateway identity and maps claims into `MCPContext`. |
| `src/service/cortex_mcp/identity_middleware.py` | Enforces incoming HTTP identity validation. |
| `src/usecase/tool_policy.py` | Enforces group/app-role to MCP tool allowlists. |
| `src/service/cortex_mcp/tool_policy_middleware.py` | Applies tool policy to every MCP tool invocation. |
| `src/usecase/credential_broker.py` | Selects pre-provisioned XSIAM credential profiles by group/app role. |
| `src/usecase/xql_builder.py` | Builds safe structured XQL from validated dataset, field, filter, and limit inputs. |
| `src/usecase/dataset_query.py` | Validates typed row/aggregate plans, compiles XQL, and creates principal/policy-bound cursors. |
| `src/usecase/xql_executor.py` | Starts and polls XQL under timeout and concurrency bounds. |
| `src/usecase/xql_results.py` | Enforces output projection, cell, field, and byte budgets. |
| `src/usecase/xql_discovery.py` | Normalizes dataset metadata and infers compact field catalogs from bounded XQL samples. |
| `src/usecase/log_policy.py` | Enforces dataset allowlists for log search and privileged raw XQL groups. |
| `src/usecase/audit.py` | Builds audit events and optionally exports them to Cortex XSIAM. |
| `src/service/cortex_mcp/audit_middleware.py` | Emits audit events for every MCP tool invocation. |
| `src/entities/MCPContext.py` | Holds auth headers and principal metadata. |

## Current Request Flow

1. HTTP identity middleware validates an Entra bearer token or trusted gateway
   assertion when HTTP identity mode is enabled.
2. MCP client calls a tool.
3. Audit middleware emits a start event.
4. Tool policy middleware checks `TOOL_ACCESS_POLICY`.
5. Tool-specific policy runs, including dataset and raw-XQL checks.
6. Credential broker selects a pre-provisioned XSIAM credential profile when
   enabled.
7. `Fetcher` calls the XSIAM API.
8. Audit middleware emits success, denied, or error outcome.
9. Tool returns JSON to the MCP client.

## Agent Log Search Flow

1. User gives the LLM agent a plain-English investigation request.
2. Agent calls `get_dataset_query_guidance` for compact rules.
3. Agent calls `list_log_datasets` to discover allowed datasets.
4. Agent calls `discover_log_fields` for one dataset. The server runs a bounded
   XQL sample and returns capped field metadata, not sample event values.
5. Agent calls `query_dataset` with an explicit typed row or aggregate plan.
6. The requested dataset is checked against `LOG_SEARCH_DATASET_POLICY`.
7. The server compiles only allowlisted XQL operations and starts the query
   under the four-query concurrency ceiling.
8. The server polls under a deadline and projects/bounds returned rows.
9. Results, provenance, truncation metadata, and at most one opaque continuation
   cursor are returned.

```mermaid
sequenceDiagram
  actor User
  participant Agent as "Claude Code or Codex"
  participant MCP as "XSIAM MCP Gateway"
  participant Policy as "Tool and dataset policy"
  participant XSIAM as "XSIAM XQL API"

  User->>Agent: "Top five departments by application usage"
  Agent->>MCP: "list_log_datasets"
  MCP->>Policy: "filter datasets for verified groups"
  MCP-->>Agent: "allowed datasets"
  Agent->>MCP: "discover_log_fields(application_usage)"
  MCP->>XSIAM: "bounded sample"
  MCP-->>Agent: "field names and types, no values"
  Agent->>MCP: "query_dataset(aggregate plan, limit=5)"
  MCP->>Policy: "authorize tool and explicit dataset"
  MCP->>XSIAM: "compiled count/group/sort XQL"
  XSIAM-->>MCP: "result rows"
  MCP-->>Agent: "projected bounded untrusted data"
  Agent-->>User: "summary"
```

## Target Production Flow

1. User signs in with Entra ID.
2. Either the MCP server validates the Entra token directly, or an optional AI
   gateway such as Portkey or LiteLLM validates the user and forwards a trusted
   identity assertion.
3. MCP server validates the direct token or the gateway forwarding contract.
4. User groups/app roles are stored in `MCPContext`.
5. Tool policy decides if the tool can be invoked.
6. Dataset policy decides if the dataset can be queried.
7. Credential broker selects a least-privilege XSIAM API key.
8. XSIAM request is executed.
9. Audit event records principal, role, tool, dataset, decision, and credential profile.
10. Audit event is forwarded to Cortex XSIAM or another durable sink.

## Design Principles

- Fail closed when identity or authorization is uncertain.
- Prefer structured query parameters for agent workflows.
- Keep schema discovery compact and progressive.
- Treat raw XQL as privileged.
- Keep plain-English interpretation in Claude Code or another MCP client agent;
  validate structured calls on the server.
- Avoid one broad XSIAM API key for all users.
- Preserve exact XSIAM data; do not invent security findings.
- Prefer aggregate answers over transporting large raw datasets into model
  context.
- Treat XSIAM values as untrusted data, never as agent instructions.
