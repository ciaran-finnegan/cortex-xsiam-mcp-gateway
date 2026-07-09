# Repository Instructions For Coding Agents

This is a security-focused MCP gateway for Cortex XSIAM.

Review and implementation priorities:

- Treat authentication, authorization, audit, and dependency changes as security-sensitive.
- Never widen XSIAM data access without an explicit policy check.
- `search_logs` must keep an explicit dataset parameter and dataset policy enforcement.
- Raw XQL must remain restricted to privileged groups.
- Audit logging must capture every MCP tool invocation without logging raw XQL by default.
- Do not add local-only deployment guidance as the enterprise default.
- Prefer deterministic, testable natural-language-to-XQL translation over broad LLM-generated XQL.
- Add or update tests when changing policy, query construction, audit, or workflow behavior.

For review comments, lead with bugs, security risks, regressions, and missing tests. Avoid cosmetic-only feedback.
