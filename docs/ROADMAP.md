# Roadmap

## Alpha

- [x] Create public fork and project scaffolding.
- [x] Add `search_logs` wrapper.
- [x] Add dataset allowlist policy.
- [x] Add conservative natural-language-to-XQL templates.
- [x] Add CI, CodeQL, Dependency Review, Dependabot, and Scorecard.
- [x] Add structured audit logging for every MCP tool invocation.
- [x] Add optional Cortex XSIAM HTTP Log Collector export for audit events.
- [x] Restrict `execute_xql_query` to security/admin roles.
- [x] Document enterprise deployment architecture and current upstream MCP
      limitations.
- [x] Add alpha release process documentation.
- [x] Add AI review configuration for Codex, Claude, CodeRabbit, and Copilot.
- [ ] Add Entra ID token validation for HTTP transport.
- [ ] Add optional AI gateway identity-forwarding validation for Portkey,
      LiteLLM, and similar gateways.
- [ ] Add tool-level policy for every MCP tool.
- [ ] Complete FastMCP 3 compatibility work to remove the unpatched transitive
      `diskcache` dependency carried by FastMCP 2.x
      ([#26](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/issues/26)).

## Beta

- [ ] Add role-to-XSIAM-credential broker.
- [ ] Add field-level output redaction.
- [ ] Add dataset catalogue discovery/configuration.
- [ ] Add streaming XQL result retrieval.
- [ ] Add policy tests for common enterprise roles.
- [ ] Add deployment examples for container platforms.
- [ ] Add XSIAM parser/dashboard content for MCP audit events.

## Stable

- [ ] Publish signed releases.
- [x] Add semantic versioning guidance.
- [ ] Add upgrade/migration documentation.
- [ ] Add reference architectures for direct Entra deployments and optional
      Portkey/LiteLLM gateway deployments.
- [ ] Add security review checklist.
