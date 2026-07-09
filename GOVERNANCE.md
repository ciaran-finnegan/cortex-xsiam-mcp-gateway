# Governance

## Project Scope

Cortex XSIAM MCP Gateway provides an MCP server and gateway hardening layer for
secure, auditable interaction with Cortex XSIAM APIs.

The project prioritizes:

- least-privilege security operations workflows;
- Entra ID and Portkey-compatible identity;
- dataset and tool authorization;
- safe natural-language-to-XQL workflows;
- high-quality documentation and tests.

## Maintainers

The repository owner is the initial maintainer.

Maintainers are responsible for:

- reviewing security-sensitive changes;
- preserving licensing notices;
- triaging vulnerability reports;
- maintaining CI and release quality;
- deciding roadmap priorities.

## Decision Making

For ordinary changes, maintainers use lazy consensus through pull request
review. For security-sensitive changes, at least one maintainer must explicitly
approve the design and implementation.

Security-sensitive changes include:

- authentication and authorization logic;
- credential handling;
- XQL generation or execution;
- dataset policy;
- audit logging;
- dependency and CI trust boundaries.

## Releases

Until the project reaches stable maturity, releases are alpha/pre-release tags.
Stable releases should include:

- passing CI;
- updated changelog;
- migration notes;
- security considerations;
- dependency review.

## Vendor Relationship

This is a community project. It is not officially supported by Palo Alto
Networks.
