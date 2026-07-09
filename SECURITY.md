# Security Policy

## Supported Versions

This project is in alpha. Security fixes are applied to the `main` branch.
Tagged releases will be supported once the project reaches a stable release
cadence.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| pre-release tags | Best effort |

## Reporting A Vulnerability

Do not open a public GitHub issue for suspected vulnerabilities.

Preferred reporting channel:

1. Use GitHub private vulnerability reporting for this repository.
2. Include enough information for maintainers to reproduce and assess impact.
3. If private vulnerability reporting is unavailable, contact the repository
   maintainer through the GitHub profile listed for this project.

Please include:

- affected version or commit;
- affected deployment mode (`stdio`, `streamable-http`, container, gateway);
- whether XSIAM credentials, datasets, or user identity can be exposed;
- reproduction steps;
- expected and observed behavior;
- logs or screenshots with secrets removed;
- suggested fix, if known.

## Response Targets

| Severity | Target acknowledgement | Target fix or mitigation |
| --- | --- | --- |
| Critical | 48 hours | 7 days |
| High | 72 hours | 14 days |
| Medium | 7 days | 30 days |
| Low | 14 days | Best effort |

These are targets, not guarantees.

## Security Boundaries

In scope:

- unauthorized XSIAM dataset access;
- bypassing `search_logs` dataset policy;
- leaking XSIAM API keys, auth IDs, or query results;
- incoming identity spoofing once Entra/Portkey auth is implemented;
- unsafe natural-language-to-XQL translation that expands access;
- command injection, path traversal, SSRF, or deserialization issues;
- container or CI secrets exposure.

Out of scope:

- issues in the XSIAM service itself;
- issues requiring compromised local admin/root access;
- denial-of-service from intentionally expensive authorized XQL queries unless
  the query bypasses configured policy;
- vulnerabilities only present in unsupported Python versions.

## Current Security Limitations

The current implementation still uses one configured XSIAM API key for
server-to-XSIAM requests. `search_logs` has dataset-level policy enforcement,
but the raw `execute_xql_query` tool should be restricted to security/admin
roles before production exposure.

Incoming Entra ID / Portkey identity verification and per-role XSIAM credential
selection are planned but not complete.

## Safe Operations Guidance

- Use least-privilege XSIAM API keys.
- Prefer staging tenants during development.
- Keep `LOG_SEARCH_DATASET_POLICY` restrictive.
- Do not expose `streamable-http` publicly until incoming auth is implemented.
- Treat raw XQL as privileged.
- Store secrets in a secret manager; do not commit `.env` files.

## Coordinated Disclosure

Maintainers will work with reporters on coordinated disclosure. Public
advisories will be published through GitHub Security Advisories when appropriate.
