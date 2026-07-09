# Security Model

## Current State

The current implementation authenticates to XSIAM with a configured API key and
API key ID. Incoming MCP users are not yet authenticated by Entra ID. Optional
AI gateway identity forwarding, such as Portkey or LiteLLM, is also not yet
implemented.

`search_logs` enforces dataset allowlists using groups from `MCPContext`. In
development, these groups come from environment defaults. In production, they
must come from verified identity claims.

## Target State

The target security model supports two deployment modes:

- Direct mode: the MCP server validates Entra ID tokens from the MCP client.
- Gateway mode: an optional AI gateway such as Portkey or LiteLLM validates the
  user, routes the request, and forwards identity claims that the MCP server can
  verify.

Gateway mode is useful for organizations that already centralize AI traffic, but
it is not required for teams that can connect MCP clients directly to this
server.

```mermaid
sequenceDiagram
  actor User
  participant Client as MCP Client
  participant Entra as Entra ID
  participant AIGateway as Optional AI Gateway
  participant Gateway as MCP Gateway
  participant Policy as Policy Engine
  participant XSIAM as Cortex XSIAM

  User->>Client: Start investigation
  Client->>Entra: Authenticate
  Entra-->>Client: Token
  alt Direct MCP deployment
    Client->>Gateway: Tool call + Entra token
  else Optional AI gateway deployment
    Client->>AIGateway: Tool call + Entra token
    AIGateway->>Gateway: Tool call + verifiable identity claims
  end
  Gateway->>Gateway: Validate token or gateway claims
  Gateway->>Policy: Authorize tool and dataset
  Policy-->>Gateway: Allow/deny + credential profile
  Gateway->>XSIAM: API call with least-privilege key
  XSIAM-->>Gateway: Result
  Gateway-->>Client: Result
```

## Authorization Layers

| Layer | Purpose |
| --- | --- |
| Identity | Verify the human or service calling MCP. |
| Tool policy | Decide which tools can be invoked. |
| Dataset policy | Decide which XSIAM datasets can be queried. |
| Credential policy | Select the least-privilege XSIAM API credential. |
| Output policy | Redact or suppress fields not allowed for the caller. |
| Audit | Record every decision and execution. |

## Dataset Policy

Dataset policy is implemented for `search_logs`.

Example:

```json
{
  "Security": ["*"],
  "Tier1": ["xdr_data"]
}
```

`Security` can query all datasets. `Tier1` can query only `xdr_data`.

## Known Gaps

- Incoming Entra authentication is not implemented.
- Optional Portkey/LiteLLM-style gateway identity forwarding is not
  implemented.
- Per-role XSIAM credential selection is not implemented.
- `execute_xql_query` bypasses dataset policy and must be restricted before
  production exposure.
- Output redaction is not implemented.
- Audit logging is not complete.
- Large result streaming is not implemented.

## Threat Model Summary

Primary risks:

- broad API key misuse;
- unauthorized dataset search;
- malicious or overbroad natural-language-to-XQL translation;
- leakage of query results to unauthorized users;
- prompt injection causing unsafe tool use;
- missing audit trails.

Core mitigations:

- verify identity before tool use;
- fail closed on policy ambiguity;
- restrict raw XQL;
- require explicit dataset declarations;
- use least-privilege API keys;
- log all authorization decisions;
- keep natural-language translation deterministic or policy-validated.
