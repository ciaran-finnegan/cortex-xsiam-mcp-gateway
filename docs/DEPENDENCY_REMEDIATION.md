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

## Known Alerts

The current open alerts are concentrated in:

- `fastmcp`: fixed upstream in FastMCP 3.x, but FastMCP 3 introduces breaking
  import/runtime changes for this fork.
- `diskcache`: transitive dependency carried by the FastMCP 2.x line; no direct
  fixed version is available from the current dependency path.

The remediation path is therefore not a blind version bump. The project needs a
FastMCP 3 migration branch that:

1. Updates imports and middleware usage for FastMCP 3.
2. Revalidates OpenAPI tool generation.
3. Revalidates `stdio` and `streamable-http` transports.
4. Reruns XQL tool tests.
5. Confirms Dependabot alerts close after the upgrade.

Tracking issue: [#26](https://github.com/ciaran-finnegan/cortex-xsiam-mcp-gateway/issues/26).

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
- Track FastMCP 3 migration as an alpha blocker.
- Do not suppress Dependabot alerts without a documented compensating control.
