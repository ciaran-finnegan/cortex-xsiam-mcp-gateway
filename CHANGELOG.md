# Changelog

This project follows a lightweight changelog format until stable releases begin.

## Unreleased

## 0.2.0-alpha.1 - 2026-07-10

- Added `query_dataset` with typed row projection, filters, aggregates, top-N,
  and time-bucketed trends for security and non-security datasets.
- Added encrypted principal/group/policy-bound keyset continuation with XSIAM
  timestamp conversion and policy rechecks.
- Added server-side output projection, row/field/cell/byte/timeframe limits,
  timeout-bounded polling, and a four-query concurrency ceiling.
- Upgraded to FastMCP 3.4.4 and removed the FastMCP 2.x transitive `diskcache`
  path from the lockfile.
- Regenerated the dependency lock within declared constraints and verified the
  full suite on active Python 3.12 and a fresh Python 3.13 environment.
- Added trusted-gateway nonce replay prevention and deterministic credential
  profile priority.
- Made gateway replay-cache saturation fail closed, clamped terminal raw-XQL
  limits before submission, and preserved continuation lookahead at XSIAM's
  result ceiling.
- Removed upstream PAPI response bodies and XQL failure details from exceptions,
  logs, and tool responses so rejected queries and sensitive literals cannot be
  echoed through MCP errors.
- Fixed OpenAPI-generated tools to resolve role-scoped XSIAM credentials per
  request and audit the credential actually selected.
- Added MCP-schema, executor, security-regression, opt-in live XSIAM, and blind
  Codex agent-planning tests.
- Validated dynamic field discovery, non-security rows and aggregates,
  time-bucketed trends, and timestamp keyset continuation against a locally
  configured XSIAM service without persisting tenant data or result values.
- Reworked agent guidance around progressive field discovery, aggregate-first
  answers, typed operators, raw-XQL fallback, and cursor-only continuation.

- Added compact agent log-search guidance, allowed dataset discovery, and
  XQL-backed field discovery tools for LLM agents.
- Removed the server-side `natural_language_query` log-search path in favor of
  Claude Code/Codex structured MCP calls.
- Added Claude Code/Codex log-search workflow tests for dataset discovery,
  field discovery, structured dry runs, denied datasets, and raw-XQL
  authorization.
- Added Entra JWT validation for HTTP transport.
- Added optional HMAC-signed trusted gateway identity forwarding for Portkey,
  LiteLLM, and similar gateways.
- Added tool-level policy middleware for every MCP tool invocation.
- Added XSIAM credential broker support for pre-provisioned role/group-scoped
  API key profiles.
- Added enterprise-first README with deployment diagrams, alpha limitations,
  and comparison with the current Palo Alto Cortex MCP deployment model.
- Added framework-level audit middleware for every MCP tool invocation.
- Added optional Cortex XSIAM HTTP Log Collector export for audit events.
- Restricted `execute_xql_query` to configured privileged groups.
- Added dependency remediation, release process, enterprise deployment, audit,
  and AI review documentation.
- Added review configuration scaffolding for Codex, Claude, CodeRabbit, and
  GitHub Copilot.
- Added Dependabot auto-merge and release workflows.

## 0.1.0-alpha.1 - 2026-07-09

- Created public fork hardening track for Cortex XSIAM MCP Gateway.
- Added `search_logs` with raw XQL, structured filters, and conservative
  natural-language translation.
- Added dataset policy enforcement for `search_logs`.
- Added XQL quota helper.
- Added project documentation, security policy, governance, and GitHub workflows.
- Added Python version constraint for Python 3.12 and 3.13.
- Added explicit `pydantic-settings` dependency.
