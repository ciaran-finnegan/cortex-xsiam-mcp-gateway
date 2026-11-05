# Roadmap

## Alpha

- [x] Create public fork and project scaffolding.
- [x] Add `search_logs` wrapper.
- [x] Add dataset allowlist policy.
- [x] Remove server-side natural-language query handling in favor of Claude
      Code structured MCP calls.
- [x] Add CI, CodeQL, Dependency Review, Dependabot, and Scorecard.
- [x] Add structured audit logging for every MCP tool invocation.
- [x] Add optional Cortex XSIAM HTTP Log Collector export for audit events.
- [x] Restrict `execute_xql_query` to security/admin roles.
- [x] Add Entra ID token validation for HTTP transport.
- [x] Add optional AI gateway identity-forwarding validation for Portkey,
      LiteLLM, and similar gateways.
- [x] Add tool-level policy for every MCP tool.
- [x] Add role-to-XSIAM-credential broker using pre-provisioned profiles.
- [x] Add compact agent guidance, allowed dataset discovery, and XQL-backed
      field discovery for log-search agents.
- [x] Add agent workflow tests for Claude Code/Codex-style structured log
      searches.
- [x] Add typed row and aggregate dataset queries for security and non-security
      XSIAM datasets.
- [x] Add bounded result projection, byte/cell caps, query timeouts, and an
      XSIAM-aligned four-query concurrency ceiling.
- [x] Add encrypted principal/group/policy-bound keyset continuation.
- [x] Add blind Codex planning evaluation and opt-in live XSIAM workflow tests.
- [x] Document enterprise deployment architecture and current upstream MCP
      limitations.
- [x] Add alpha release process documentation.
- [x] Add AI review configuration for Codex, Claude, CodeRabbit, and Copilot.
- [x] Add engagement modes (`incident_response`, `threat_hunt`, `operations`,
      `unset`) with `set_engagement` and an engagement log, mode-aware tool
      policy that only narrows access, and the mode and case id on every audit
      event and continuation cursor
      ([Engagement Modes](ENGAGEMENT_MODES.md)).
- [x] Add the XQL cost guard on every query path: cost estimates, approval and
      reserve refusals with alternatives, a per-principal approval cap, a
      `quota` block on every result, and a result cache
      ([Configuration](CONFIGURATION.md#xql-cost-guard)).
- [x] Add `validate_xql` and classified XQL errors with links to the vendor's
      documentation ([XQL Validation](XQL_VALIDATION.md)).
- [x] Add tier-1 learned tenant facts, written by a separate learner process
      with evidence, expiry, verification, and administrator revert, and the
      tier-2 replay foundation ([Learning](LEARNING.md)).
- [x] Add the authored dataset catalogue, `find_datasets`, and the operator
      overlay `DATASET_CATALOGUE_OVERLAY_PATH`
      ([Dataset Catalogue](DATASET_CATALOGUE.md)).
- [x] Add question-shaped investigation helpers (`resolve_entity`,
      `entity_activity`, `firewall_traffic`, `firewall_verdict`,
      `dataset_health`, `threat_intel_lookup`, `coverage_gap`) that apply
      dataset policy, the cost guard, and a per-call query budget
      ([Investigation Helpers](INVESTIGATION_HELPERS.md)).
- [x] Add secrets guidance for workstations and servers, so the XSIAM API key
      stays out of `.env` ([Secrets And API Keys](SECRETS.md)).
- [ ] Validate Entra, gateway, dataset policy, tool policy, credential broker,
      and audit export against a non-production XSIAM tenant.
- [x] Complete FastMCP 3 compatibility work to remove the unpatched transitive
      `diskcache` dependency carried by FastMCP 2.x
      ([#26](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/issues/26)).

## Beta

- [ ] Add field-level output redaction.
- [x] Add curated dataset catalogue configuration for production tenants: a
      built-in catalogue plus an operator overlay, validated at startup.
- [ ] Cache the tenant dataset list for `list_log_datasets`, `find_datasets`,
      and the investigation helpers. Only `validate_xql` caches it today, per
      process; the others call `get_datasets` on every request.
- [ ] Add streaming XQL result retrieval.
- [ ] Add policy tests for common enterprise roles.
- [ ] Add deployment examples for container platforms.
- [ ] Add XSIAM parser/dashboard content for MCP audit events.
- [ ] Add distributed query rate limiting and gateway replay/cursor state for
      horizontally scaled deployments.

## Stable

- [ ] Publish signed releases.
- [x] Add semantic versioning guidance.
- [ ] Add upgrade/migration documentation.
- [ ] Add reference architectures for direct Entra deployments and optional
      Portkey/LiteLLM gateway deployments.
- [ ] Add security review checklist.
