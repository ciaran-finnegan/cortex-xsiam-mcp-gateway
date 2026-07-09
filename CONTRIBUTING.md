# Contributing

Thank you for contributing to Cortex XSIAM MCP Gateway.

This is a security-sensitive project. Contributions should preserve least
privilege, explicit authorization, and auditable behavior.

## Development Setup

```bash
poetry env use python3.12
poetry install
poetry run pytest
```

Python 3.12 and 3.13 are supported. Python 3.14 is not currently supported.

## Before Opening A Pull Request

Run:

```bash
poetry run pytest
poetry run ruff check src tests
```

`mypy src` is encouraged for typed changes but is not yet a required gate
because the fork still carries inherited typing debt.

## Contribution Rules

- Do not commit secrets, `.env` files, logs containing query results, or tenant
  identifiers.
- Preserve the upstream Palo Alto Networks license and notices.
- Add tests for policy, auth, query translation, or API behavior changes.
- Fail closed on authorization uncertainty.
- Prefer structured parameters over free-form string parsing.
- Keep raw XQL capabilities behind explicit authorization.
- Document new tools, config variables, and security assumptions.

## Commit Style

Use concise, imperative commit messages:

```text
Add dataset policy enforcement for log search
```

## Pull Request Checklist

- [ ] Tests added or updated.
- [ ] Security impact considered.
- [ ] Documentation updated.
- [ ] No secrets or tenant-specific data committed.
- [ ] License impact considered.
- [ ] Backward compatibility noted.

## Licensing Of Contributions

By contributing, you agree that your contributions are provided under Apache
License 2.0 where legally separable from the upstream Palo Alto Networks
licensed code, and that the combined repository remains subject to the upstream
license requirements described in [NOTICE](NOTICE.md).
