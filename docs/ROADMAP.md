# Roadmap

## Alpha

- [x] Create public fork and project scaffolding.
- [x] Add `search_logs` wrapper.
- [x] Add dataset allowlist policy.
- [x] Add conservative natural-language-to-XQL templates.
- [x] Add CI, CodeQL, Dependency Review, Dependabot, and Scorecard.
- [ ] Add Entra ID token validation for HTTP transport.
- [ ] Add Portkey identity-forwarding validation.
- [ ] Add tool-level policy for every MCP tool.
- [ ] Restrict `execute_xql_query` to security/admin roles.
- [ ] Add audit logging.
- [ ] Complete FastMCP 3 compatibility work to remove the unpatched transitive
      `diskcache` dependency carried by FastMCP 2.x.

## Beta

- [ ] Add role-to-XSIAM-credential broker.
- [ ] Add field-level output redaction.
- [ ] Add dataset catalogue discovery/configuration.
- [ ] Add streaming XQL result retrieval.
- [ ] Add policy tests for common enterprise roles.
- [ ] Add deployment examples for container platforms.

## Stable

- [ ] Publish signed releases.
- [ ] Add semantic versioning.
- [ ] Add upgrade/migration documentation.
- [ ] Add reference architecture for Portkey and Entra.
- [ ] Add security review checklist.
