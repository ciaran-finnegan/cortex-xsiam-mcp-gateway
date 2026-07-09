This repository is a security-focused MCP gateway for Cortex XSIAM.

When reviewing or suggesting code:

- Prioritize authentication, authorization, audit, dependency, and workflow risks.
- Do not suggest changes that broaden XSIAM access without policy enforcement.
- Keep raw XQL restricted to configured privileged groups.
- Keep `search_logs` dataset-scoped and deterministic.
- Do not log raw XQL or natural-language investigation prompts unless explicitly configured.
- Treat GitHub Actions permissions and secret handling as security-sensitive.
- Prefer focused tests for policy, audit, query construction, and failure paths.
