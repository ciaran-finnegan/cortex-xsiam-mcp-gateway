# Review Checklist

- Does the change preserve least-privilege access to XSIAM APIs?
- Are MCP tool calls audited, including denied and error outcomes?
- Are raw XQL paths restricted to privileged groups?
- Does log search require an explicit dataset and enforce dataset policy?
- Are queries, tokens, API keys, and credentials redacted or hashed in logs?
- Do workflow permissions use the minimum practical GitHub token scope?
- Are dependency updates covered by CI, Dependency Review, and human review when major or security-sensitive?
- Are tests updated for policy, audit, and error paths?
