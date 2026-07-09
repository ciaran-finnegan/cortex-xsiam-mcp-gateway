# Release Process

## Current Release Line

The first release line is `v0.1.0-alpha.1`.

Alpha means:

- APIs and configuration may change.
- Enterprise identity enforcement is not complete.
- The project is suitable for controlled pilots and design validation.
- Production rollout requires explicit risk acceptance.

## Versioning

Use semantic version tags:

- `v0.1.0-alpha.1` for alpha prereleases.
- `v0.1.0-beta.1` for beta prereleases.
- `v0.1.0` for stable releases.

Python package metadata uses PEP 440 compatible versions, for example
`0.1.0a1` for `v0.1.0-alpha.1`.

## Release Gates

Before tagging:

1. CI passes on Python 3.12 and 3.13.
2. CodeQL completes.
3. Dependency Review passes.
4. Open Dependabot alerts are documented in release notes.
5. `CHANGELOG.md` is updated.
6. The release is marked prerelease unless all alpha blockers are complete.

## Tagging

```bash
git tag -a v0.1.0-alpha.1 -m "v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

The release workflow creates a GitHub release from the tag. Tags containing
`alpha`, `beta`, or `rc` are marked as prereleases.

