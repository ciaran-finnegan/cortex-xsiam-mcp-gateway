# Release Process

## Current Release Line

The current release line is `v0.2.0-alpha.1` (`0.2.0a1` in Python package
metadata). The previous release is `v0.1.0-alpha.1`.

Alpha means:

- APIs and configuration may change.
- Tenant-specific enterprise identity and policy configuration still requires
  deployment validation.
- The project is suitable for controlled pilots and design validation.
- Production rollout requires explicit risk acceptance.

## v0.2.0-alpha.1 Evidence

Local release verification on 2026-07-10:

- Python 3.12: `78 passed, 2 skipped` (live tests skipped by default).
- Python 3.13: `78 passed, 2 skipped` (live tests skipped by default).
- Opt-in XSIAM integration suite: `2 passed`, covering dynamic field
  discovery, non-security rows and aggregates, time trends, and keyset
  continuation without persisting tenant details or result values.
- Blind Codex client-agent planning evaluation: `10/10` cases using Codex CLI
  0.142.2 with `gpt-5.5`.
- Final independent Codex security review: no actionable findings after fixes
  for result bounds, replay-cache saturation, and upstream error sanitization.
- Gitleaks working-tree scan: no leaks found.
- `pip-audit` against a lock-synchronized environment: no known
  vulnerabilities found; `diskcache` is absent from the lockfile.
- Ruff, compileall, package metadata validation, and wheel/sdist build passed.

GitHub CI, CodeQL, Dependency Review, Dependabot rescan, and configured GitHub
AI reviewers remain merge gates and must be recorded on the pull request.

## Versioning

Use semantic version tags:

- `v0.2.0-alpha.1` for the current alpha prerelease.
- `v0.1.0-beta.1` for beta prereleases.
- `v0.1.0` for stable releases.

Python package metadata uses PEP 440 compatible versions, for example
`0.2.0a1` for `v0.2.0-alpha.1`.

## Release Gates

Before tagging:

1. CI passes on Python 3.12 and 3.13.
2. CodeQL completes.
3. Dependency Review passes.
4. Open Dependabot alerts are documented in release notes.
5. `CHANGELOG.md` is updated.
6. The normal, blind agent-planning, and opt-in live XSIAM evidence is recorded
   without tenant details or result values.
7. The release is marked prerelease unless all alpha blockers are complete.

## Tagging

```bash
git tag -a v0.2.0-alpha.1 -m "v0.2.0-alpha.1"
git push origin v0.2.0-alpha.1
```

The release workflow creates a GitHub release from the tag. Tags containing
`alpha`, `beta`, or `rc` are marked as prereleases.
