# Repository Instructions For Coding Agents

This is a security-focused MCP gateway for Cortex XSIAM.

Review and implementation priorities:

- Treat authentication, authorization, audit, and dependency changes as security-sensitive.
- Never widen XSIAM data access without an explicit policy check.
- `search_logs` must keep an explicit dataset parameter and dataset policy enforcement.
- Raw XQL must remain restricted to privileged groups.
- Audit logging must capture every MCP tool invocation without logging raw XQL by default.
- Do not add local-only deployment guidance as the enterprise default.
- Do not add server-side natural-language-to-XQL translation. Claude Code, Codex, or another MCP client agent should translate user intent into structured MCP calls.
- Add or update tests when changing policy, query construction, audit, or workflow behavior.

For review comments, lead with bugs, security risks, regressions, and missing tests. Avoid cosmetic-only feedback.
