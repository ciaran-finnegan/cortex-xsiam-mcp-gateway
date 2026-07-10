# Dependency Remediation

## Updater Policy

Dependabot is the primary updater for this repository.

Renovate is not enabled. We should not run Dependabot and Renovate together
without a deliberate split because they create duplicate PRs, duplicate review
load, and conflicting update policy. If Renovate is adopted later, it should
replace Dependabot or be scoped to a Renovate-only use case.

## Current Automation

| Control | Status |
| --- | --- |
| Dependabot version updates | Enabled for Python and GitHub Actions, with patch/minor grouping. |
| Dependabot security alerts | Repository setting required; alerts are already visible. |
| Dependency Review | Blocks pull requests introducing high-severity dependencies. |
| Dependabot auto-merge | Added for passing patch/minor Dependabot PRs. |
| CodeQL | Enabled. |
| OpenSSF Scorecard | Enabled. |
| Release workflow | Tags create prerelease/stable GitHub releases. |

## FastMCP 3 Remediation

The runtime is now pinned to FastMCP `3.4.x`. The migration:

- updated FastMCP tool construction and server mounting APIs;
- revalidated middleware, resources, OpenAPI-generated tools, and full server
  initialization;
- resolves `py-key-value-aio` 0.4.x without the FastMCP 2.x `diskcache` path;
- has a regression test that initializes all built-in and OpenAPI tools;
- passes the unit/security/schema suite on both supported Python runtimes,
  Python 3.12 and 3.13.

The lockfile is the source of truth for resolved packages. This check must stay
empty:

```bash
rg '^name = "diskcache"' poetry.lock
```

Tracking issue: [#26](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/issues/26).
It can be closed after the merged lockfile is rescanned by Dependabot.

## Pull Request Handling

Patch and minor Dependabot PRs can have auto-merge enabled after required
checks pass, but repository branch protection still controls whether review is
required. Major updates, security-critical runtime changes, and FastMCP updates
require human review.

Security dependency review should prioritize:

- unauthenticated SSRF/path traversal paths;
- auth/OAuth callback behavior;
- command injection issues;
- unsafe deserialization;
- transitive dependencies used by server runtime paths.

## Maintainer Actions

- Keep Dependabot enabled.
- Close or ignore Renovate onboarding PRs unless the project intentionally
  switches to Renovate.
- Keep FastMCP 3 initialization and MCP schema tests in the required CI suite.
- Do not suppress Dependabot alerts without a documented compensating control.
