# Changelog

This project follows a lightweight changelog format until stable releases begin.

## Unreleased

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
