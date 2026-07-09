# Claude Review Instructions

This repository builds a security-focused MCP gateway for Cortex XSIAM.

Focus review on:

- authn/authz bypasses;
- dataset policy bypasses;
- raw XQL exposure;
- missing audit events or sensitive audit fields;
- unsafe dependency updates;
- workflow permission issues;
- secret handling;
- prompt-injection risk in agent-facing tools;
- missing tests for security behavior.

Do not recommend broad refactors unless they reduce a concrete security or reliability risk.
