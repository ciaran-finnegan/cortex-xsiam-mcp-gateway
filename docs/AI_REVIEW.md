# AI Review

## Goal

AI review is a defense-in-depth control for a security project. It does not
replace maintainer review, CI, CodeQL, Dependency Review, or threat modeling.

## Configured Review Paths

| Reviewer | Repo artifact | Required GitHub setup |
| --- | --- | --- |
| Codex | `AGENTS.md`, `.github/workflows/codex-review.yml`, `.github/codex/prompts/review.md` | Configure `OPENAI_API_KEY` or enable Codex automatic reviews in Codex settings. |
| Claude | `CLAUDE.md`, `REVIEW.md`, `.github/workflows/claude-review.yml` | Configure `ANTHROPIC_API_KEY` or enable Claude Code Review for the repo/org. |
| CodeRabbit | `.coderabbit.yaml` | Install/enable the CodeRabbit GitHub app. |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/instructions/security-review.instructions.md` | Enable Copilot code review in repository settings. |

The GitHub Actions workflows skip safely when required secrets are missing.

## Review Expectations

AI reviewers should focus on:

- authn/authz bypasses;
- dataset policy bypasses;
- raw XQL exposure;
- audit logging omissions;
- secret leakage;
- unsafe dependency changes;
- prompt injection and tool misuse risks;
- tests for policy and failure paths.

AI reviewers should not approve releases or merge code. Maintainers own final
decisions.

## Manual Review Commands

When installed, reviewers can usually be invoked manually in PR comments:

- `@codex review`
- `@claude review`
- GitHub Copilot review request through the PR reviewer UI

CodeRabbit runs according to the installed app configuration.

