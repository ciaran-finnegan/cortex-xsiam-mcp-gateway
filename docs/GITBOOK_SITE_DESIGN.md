# GitBook Site Design

Status: draft for review. Nothing here is live. GitBook facts were checked on
2026-10-28 against [Sources](#sources). Claims marked **unverified** have no
source.

## Purpose And Scope

Publish the existing Markdown docs as a public GitBook site on a Free account,
synced from this repository with Git Sync. GitHub stays the source of truth:
every published word reaches `main` through a reviewed pull request. Covers
navigation, Git Sync, GitBook setup, and later page changes. Draft files:
`.gitbook.yaml` (repository root) and `docs/SUMMARY.md`.

## Free Plan Facts

| Feature | Free | Plan needed | Source |
| --- | --- | --- | --- |
| Public sites | Yes; unlimited basic sites, unlimited content | Free | [1], [2] |
| Sections per site | One; variants are Free | Ultimate for site sections and section groups | [3], [6] |
| Page groups in a section (`##` in SUMMARY) | Yes, no plan limit stated | Free | [12] |
| Members | One user | Essential or Ultimate, $12 per user/month | [3], [4] |
| Default URL `<org>.gitbook.io/<site>` | Yes | Free | [5] |
| Custom domain | No | Essential | [3], [4] |
| Git Sync with GitHub | Yes | Free | [3], [4] |
| GitHub pull request previews | Yes | Free | [3], [16] |
| Change requests; merge rules and approvals | Yes; No | Essential for merge rules and approvals | [3] |
| Title, icon, primary and tint colour, Clean and Muted themes | Yes | Free | [8] |
| Custom logo, fonts, footer, Bold and Gradient themes, semantic colours | Conflicting: docs badge them Essential; pricing lists "Advanced customization" as Free | Treat as Essential until checked in the UI | [3], [7], [8], [9] |
| Remove "Powered by GitBook" | No | Not offered on any plan | [7] |
| Full-text search | Yes | Free | [3] |
| AI Assistant Ask | No | Essential | [3], [4] |
| Page view analytics | Yes | Free | [3] |
| Search analytics, user feedback, share links, indexing opt-out, site redirects | No | Essential | [3], [10] |
| AI Assistant Chat, AI insights, adaptive content, authenticated access, broken links report | No | Ultimate | [3], [4] |
| `llms.txt`, `.md` pages, per-site MCP server | Yes | Free | [3], [11] |

Constraints on Free: one GitBook user; URL
`https://example-org.gitbook.io/cortex-xsiam-mcp-gateway` (the org name is the
subdomain, so pick a neutral one); one section, navigated by SUMMARY page
groups; search engines index the site; no broken-link report or redirect UI, so
links are checked locally and group names stay fixed (they are in page URLs
[12]). Paid features (custom domain, Ask, redirects, sections, authenticated
access) are not needed for the first release.

GitBook's Community plan is free and has every Ultimate feature except SAML SSO
[24]. It is for open source projects that meet GitBook's criteria, which include
a `LICENSE` file with a valid open source licence and no tie to a for-profit
company. This repository's root `LICENSE` is the upstream vendor licence, which
limits use to the vendor's products (see `NOTICE.md`), so it likely does not
qualify. Not pursued. GitBook also offers ad-funded Sponsored sites [24]; not
used.

## Information Architecture

One section: a short ungrouped head and four groups, in repository Title Case.
Pages stay flat so URLs do not change when siblings arrive. SUMMARY link text
matches each file's H1, because GitBook uses the SUMMARY text in the sidebar.

- (top): `README.md` (landing), `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`.
- Deploy And Operate: `docs/ENTERPRISE_DEPLOYMENT.md`, `docs/CONFIGURATION.md`,
  `docs/AUDIT_LOGGING.md`.
- Security: `docs/SECURITY_MODEL.md`, `docs/RBAC_AND_LOG_SEARCH_REVIEW.md`,
  `SECURITY.md`, `docs/DEPENDENCY_REMEDIATION.md`.
- Agents And Tools: `docs/AGENT_LOG_SEARCH.md`,
  `docs/CLAUDE_CODE_LOG_SEARCH_TESTING.md`.
- Project: `CHANGELOG.md`, `docs/RELEASES.md`, `CONTRIBUTING.md`,
  `GOVERNANCE.md`, `docs/AI_REVIEW.md`.

Not on the site: `CLAUDE.md`, `AGENTS.md`, `REVIEW.md`, `NOTICE.md`,
`CODE_OF_CONDUCT.md`, `LICENSE`, `LICENSES/`, `.github/**/*.md`,
`src/**/README.md`, and this doc. None is in `docs/SUMMARY.md`.

### Slots For Open Pull Requests

Final order of the two groups that change once the PRs land:

```markdown
## Deploy And Operate

* [Enterprise Deployment](ENTERPRISE_DEPLOYMENT.md)
* [Configuration](CONFIGURATION.md)
* [Audit Logging](AUDIT_LOGGING.md)
* [Learning](LEARNING.md)

## Agents And Tools

* [Agent Dataset Queries](AGENT_LOG_SEARCH.md)
* [Engagement Modes](ENGAGEMENT_MODES.md)
* [Dataset Catalogue](DATASET_CATALOGUE.md)
* [Investigation Helpers](INVESTIGATION_HELPERS.md)
* [XQL Validation And Error Classes](XQL_VALIDATION.md)
* [Agent And XSIAM Testing](CLAUDE_CODE_LOG_SEARCH_TESTING.md)
```

| PR | New page | Line to add to `docs/SUMMARY.md` |
| --- | --- | --- |
| #45 | `docs/DATASET_CATALOGUE.md` | `* [Dataset Catalogue](DATASET_CATALOGUE.md)` |
| #46 (adds the file; #47-#51 only edit it, #49 also edits SECURITY_MODEL) | `docs/INVESTIGATION_HELPERS.md` | `* [Investigation Helpers](INVESTIGATION_HELPERS.md)` |
| #57 | `docs/ENGAGEMENT_MODES.md` | `* [Engagement Modes](ENGAGEMENT_MODES.md)` |
| #58 | none | none |
| #59 | `docs/XQL_VALIDATION.md` | `* [XQL Validation And Error Classes](XQL_VALIDATION.md)` |
| #60 | `docs/LEARNING.md` | `* [Learning](LEARNING.md)` |

Rule: add the line directly after the last page that precedes it in the final
order and already exists on the branch. Merge order then does not matter, and
a rebase conflict resolves to the final order. PR #57 also edits
CONFIGURATION, AUDIT_LOGGING, SECURITY_MODEL, ARCHITECTURE and README; none of
that changes navigation. Learning (#60) covers tenant packs, learned facts and
the forgery guard; operators enable it, so it sits under Deploy And Operate.

XQL cost guard (#58) adds ~118 lines to CONFIGURATION describing a feature, not
a settings list. After it merges, consider `docs/XQL_COST_GUARD.md` with
`* [XQL Cost Guard](XQL_COST_GUARD.md)` under Deploy And Operate, directly
after Configuration. Not created here.

## Audience Paths

Operators (deploy, configure, run, audit):

1. Cortex XSIAM MCP Gateway: Alpha Status, Local Development, Docker.
2. Architecture.
3. Enterprise Deployment.
4. Configuration (and XQL Cost Guard if split).
5. Audit Logging.
6. Learning (#60): tenant pack, what is automatic.
7. Security Policy: Safe Operations Guidance.
8. Release Process, Changelog, Roadmap.

Security reviewers (threat model, authz, raw XQL, audit, supply chain):

1. Security Policy: boundaries and current limitations.
2. Security Model: authorization layers, dataset policy, gaps, threat model.
3. Architecture: request flow.
4. RBAC And Dataset Query Review: authorization chain, credential model, gaps.
5. Configuration: Dataset Policy, Raw XQL Privilege, Identity, Tool Policy.
6. Audit Logging: event model, fail-closed mode, sensitive query logging.
7. Engagement Modes (#57): modes only narrow access, policy overrides, audit.
8. XQL Validation And Error Classes (#59): access and what it spends.
9. Learning (#60): forgery guard, what is never automatic.
10. Dependency Remediation, AI Review.

Agent and client developers (MCP tools, dataset queries, modes, validation):

1. Cortex XSIAM MCP Gateway: Core Tools.
2. Agent Dataset Queries.
3. Engagement Modes (#57).
4. Dataset Catalogue (#45).
5. Investigation Helpers (#46-#51).
6. XQL Validation And Error Classes (#59).
7. Configuration: Tool Policy.
8. Agent And XSIAM Testing.

## Git Sync Approach

### Root And Structure

`.gitbook.yaml` sets `root: ./`, `structure.readme: README.md` and
`structure.summary: docs/SUMMARY.md`; paths in it are relative to `root` [14].
The root is the repository root because the landing page and four pages
(`SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `CHANGELOG.md`) live there.
GitBook reads content from `root` [14]; reaching files above it with
`root: ./docs/` is undocumented (**unverified**), so that option would drop
them. No `redirects` yet; whether they work on Free is **unverified**.

The cost: GitBook's write-back can touch any file, and GitBook may create new
Markdown files rather than reuse existing ones [13]. In a public repository
with this layout, one GitBook export moved every `docs/` page to the root and
replaced `CHANGELOG.md` with `changelog.md`. So GitBook gets no write path to
`main`.

### SUMMARY Link Resolution

Links inside `docs/SUMMARY.md` resolve relative to `docs/` (the SUMMARY.md
directory), not to `root`. GitBook's docs do not say so. The evidence is
third-party public repositories, not GitBook documentation:

- GitBook-authored export commits (one from 2020, three from 2024) in two
  repositories with `summary: docs/SUMMARY.md` write SUMMARY-relative entries:
  `../README.md` style for files above `docs/`, bare names for files in it.
- Five of six hand-written repositories found by GitHub code search for
  `"docs/SUMMARY.md" filename:.gitbook.yaml` use SUMMARY-relative entries. The
  sixth uses `./docs/...` with an unknown outcome.

GitBook's skill reference only says paths are "relative to the location
specified in .gitbook.yaml (typically the root)" [19]. SUMMARY-relative links
also work on GitHub. Treat this as **unverified** until the first import. If
it misses pages, switch to root-relative entries (`docs/ARCHITECTURE.md`) or
move SUMMARY.md to the root.

### Branch, Direction, And Review

- Sync branch `main`; initial direction GitHub to GitBook [15]; never "Swap
  direction". Sync is bidirectional after setup, with no one-way mode [17].
- `main` requires one approving review, last-push approval, linear history,
  admin enforcement and four status checks. GitBook says its app must bypass
  branch protection to push, "including during setup" [13].
- Decision: put `gitbook-com` on no bypass list, so GitBook cannot commit to
  `main`. Bypassing the review rule alone would likely fail anyway, since
  required status checks also gate direct pushes (**unverified** here).
- Live edits cannot be unlocked while Git Sync is on [18], so each UI edit
  needs a change request, and merging one commits to `main`, which fails
  without bypass. Free has no merge rules [3]; the one GitBook user is the
  only editor. No setting to disable change requests was found. Rule: never
  merge a change request in GitBook.
- PR previews: GitBook posts a status with a preview link, visible only to
  GitBook account holders [16]. Keep fork previews off (the default) so a fork
  cannot serve content under the site domain [16]. Do not make the GitBook
  status a required check.

### GitHub App Scope

GitBook.com (`gitbook-com`, owner GitbookIO) requests contents write, pull
requests write, commit statuses write, metadata read, and account email
addresses read, and subscribes to `push` and `pull_request` [21]. It has no
`workflows` permission, so it cannot change `.github/workflows/`.

Install it on the personal account with "Only select repositories", this
repository only. Contents write still reaches every unprotected branch, and
GitBook creates the sync branch if it does not exist [15]. Revoke under GitHub
Settings, Applications, Installed GitHub Apps.

Contents write also lets the app create tags. `.github/workflows/release.yml`
runs on any pushed `v*` tag, with `contents: write`, and publishes a GitHub
release built from the tagged commit, which can be on any branch. The
repository has no tag ruleset today. Before installing the app, add a tag
ruleset that restricts creating, updating and deleting `v*` tags to repository
admins, with no bypass for `gitbook-com`.

### Sync Errors

| Symptom | Action | Source |
| --- | --- | --- |
| "Missing permissions to push to ... protected branch" | Stop. Do not grant bypass. Use the fallback. | [13] |
| Unexpected error after a GitHub commit | Merge a small PR to `main`; GitBook re-imports everything. | [13] |
| Error during first setup | Remove the integration and set it up again. | [13] |
| Page missing | Check it is in `docs/SUMMARY.md` and the path resolves. | [13] |
| Page has no title or description | Fix the YAML front matter; quote values. | [13], [19] |

## Landing Page And Unlisted Files

- `README.md` is the landing page and first SUMMARY entry [12]. Edit it only in
  the repository [14].
- `docs/SUMMARY.md` is the navigation; each file may appear once [14]. Unlisted
  files are not imported: a new repository file does nothing on GitBook until
  SUMMARY.md lists it [13]. Folder-inferred navigation applies only when
  SUMMARY.md is missing [14].
- A SUMMARY entry for a file missing from the branch: behaviour
  **unverified**. `docs/SUMMARY.md` lists only files on `main`; each PR adds
  its own line.

## Markdown Conventions

- Callouts: plain blockquote with a bold label, `> **Warning:** ...`. It
  renders on both sites. GitBook's `{% hint %}` syntax [22] shows as literal
  text on GitHub. Whether Git Sync turns `> [!WARNING]` into a hint is
  **unverified**; try one in a PR preview first.
- Front matter: GitBook reads `description`, `icon`, `hidden`, `layout`,
  `cover` and `if` [19]. Use quoted `description` only. GitHub shows front
  matter as a small table above the page. `hidden: true` removes a page from
  the sidebar but not from `llms-full.txt` or the MCP server [11].
- Links to non-Markdown files or unlisted pages: published behaviour
  **unverified**; GitBook exports unresolved links as `/broken/pages/<id>`
  [19]. Use absolute GitHub URLs for them.
- Heading anchors may slug differently from GitHub (**unverified**); no doc
  links an anchor today. Mermaid fences render natively [23].

## Follow-Up Page Changes

Recommendations only.

| Page | `description` (draft) | Callout |
| --- | --- | --- |
| `README.md` | "Governed MCP access to Cortex XSIAM with identity, policy and audit." | Alpha status |
| `docs/CONFIGURATION.md` | "Environment variables for XSIAM, identity, policy, limits and audit." | `MCP_ALLOW_UNAUTHENTICATED_HTTP`; Raw XQL Privilege |
| `docs/AUDIT_LOGGING.md` | "Audit event model, XSIAM export and sensitive fields." | Fail-closed mode; sensitive query logging |
| `docs/SECURITY_MODEL.md` | "Authorization layers, dataset policy, query controls and gaps." | Known gaps |
| `SECURITY.md` | "Reporting vulnerabilities, security boundaries and limitations." | Do not open a public issue |
| `docs/AGENT_LOG_SEARCH.md` | "How MCP clients query XSIAM datasets with typed tools." | Raw XQL |
| `docs/CLAUDE_CODE_LOG_SEARCH_TESTING.md` | "Test layers, agent planning evaluation and live tests." | Live tests use tenant quota and secrets |
| Other listed pages | One line from the opening paragraph | none |

README (496 lines) repeats the identity, dataset policy, audit, configuration,
dependency and AI review content in `docs/`; two copies of security claims
drift. Keep intro, Alpha Status, Core Tools and a page map (~150 lines); move
Local Development and Docker to `docs/GETTING_STARTED.md`
(`* [Getting Started](GETTING_STARTED.md)`, first under Deploy And Operate).

CONFIGURATION (214 lines, ~350 after #57 and #58): split out the cost guard as
above. Split identity and tool policy later only if it keeps growing.

### Broken Links On GitBook

| File:line | Target | Fix |
| --- | --- | --- |
| `README.md:478` | `NOTICE.md` (unlisted) | Absolute GitHub URL |
| `README.md:478` | `LICENSE` (non-Markdown) | Absolute GitHub URL |
| `README.md:479` | `LICENSES/Apache-2.0.txt` (non-Markdown) | Absolute GitHub URL |
| `CONTRIBUTING.md:63` | `NOTICE.md` (unlisted) | Absolute GitHub URL |

Every other relative link targets a listed page. `src/`, `.env.example` and
`.github/` appear only as code spans, not links. `docs/INVESTIGATION_HELPERS.md`
(#46) links `DATASET_CATALOGUE.md`, which #45 lists first.

## Setup Steps

1. Merge `.gitbook.yaml` and `docs/SUMMARY.md` to `main` through a normal PR.
2. Sign in to GitBook on Free. Create an organization with a neutral name; it
   becomes `<org>.gitbook.io` [5].
3. In GitHub, add the `v*` tag ruleset above. Install the GitBook.com app:
   personal account, "Only select repositories", this repository. Confirm
   `gitbook-com` is on no bypass list for `main` or the tag ruleset.
4. Home, `+` next to Sites, name "Cortex XSIAM MCP Gateway", start from Git
   Sync [2].
5. Git Sync in the site sidebar: connect GitHub, select this repository and
   branch `main` [15].
6. Initial direction: GitHub to GitBook. Do not swap [15].
7. Project directory empty (repository root); map the single space to `./`;
   leave fork previews off; Sync [15].
8. On a protected-branch error, stop and use the fallback.
9. Check the sidebar matches `docs/SUMMARY.md` and no unlisted file was
   imported.
10. Customize title, icon, primary colour, Clean theme. Enable "Edit on
    GitHub". Decide on page actions, which also gate the MCP server [20].
11. Publish with audience Public [2]; check the site in a private window.
12. Open a docs PR; check the GitBook preview status, merge, check the site.

## Fallback: Mirror Branch

Only if step 8 fails. Sync GitBook to an unprotected `gitbook-sync` branch cut
from `main`. After each docs merge run
`git push origin origin/main:refs/heads/gitbook-sync`; a rejected fast-forward
means GitBook committed there, so review that commit in a PR to `main`.
Previews then appear only on PRs into `gitbook-sync`; turn "Edit on GitHub"
off.

## Open Questions And Risks

1. Site-wide Git Sync keeps `gitbook-docs.yaml` in the project directory and
   rewrites it when the mapping is saved [14], [19]; the enabling guide calls
   it `docs.yaml` [15]. If setup must commit it, `main` refuses
   (**unverified**). Options: pre-author it in a PR, or use the fallback.
2. A change request merged in GitBook may change the published site even if
   the push to GitHub fails, until the next GitHub commit re-imports
   (**unverified**; inferred from [5], [13]). Use SSO with MFA on the GitBook
   account and keep one member.
3. **Unverified**: SUMMARY link resolution (repository evidence only), GitHub
   alert conversion, missing SUMMARY targets, non-Markdown links, `.gitbook.yaml`
   redirects on Free, and Free logo, fonts and footer (sources disagree).
4. The site serves `llms.txt`, `.md` pages and an MCP server [11], so agents
   may read it; only reviewed content should reach them. GitBook's own `.md`
   pages append an "Agent Instructions" block telling agents to query
   GitBook; whether Free sites get it is **unverified**. Check after
   publishing and turn page actions off if needed.

## Sources

`docs.gitbook.com` redirects to `gitbook.com/docs`. Every page there has a
`.md` version (append `.md`) and an index at `https://gitbook.com/docs/llms.txt`.

1. <https://gitbook.com/docs/account-and-billing/billing-faq/plan-and-member-costs>: unlimited basic sites free.
2. <https://gitbook.com/docs/publish/publish-a-docs-site>: create and publish; public by default.
3. <https://www.gitbook.com/pricing>: per-feature plan table.
4. <https://gitbook.com/docs/account-and-billing/plans>: plan cards; Free is one user.
5. <https://gitbook.com/docs/getting-started/quickstart>: URL format; merged changes update a live site immediately.
6. <https://gitbook.com/docs/manage-your-site/site-structure/site-sections>: sections are Ultimate.
7. <https://gitbook.com/docs/manage-your-site/customization>: advanced customization; "Powered by GitBook" cannot be removed.
8. <https://gitbook.com/docs/manage-your-site/customization/icons-colors-and-themes>: branding options and plan badges.
9. <https://gitbook.com/docs/manage-your-site/customization/layout-and-structure>: header links, footer, announcement badges.
10. <https://gitbook.com/docs/publish/publish-a-docs-site/public-publishing>: indexing controls are paid.
11. <https://gitbook.com/docs/getting-started/llm-ready-docs>: `.md`, `llms.txt`, `llms-full.txt`, MCP server; hidden pages stay in them.
12. <https://gitbook.com/docs/create-content/content-structure/page>: landing page, URLs follow navigation and group slugs, `hidden`.
13. <https://gitbook.com/docs/docs-as-code/git-sync/troubleshooting>: protected branch bypass, re-import, unlisted files, README, YAML errors.
14. <https://gitbook.com/docs/docs-as-code/git-sync/content-configuration>: `.gitbook.yaml`, `gitbook-docs.yaml`, SUMMARY syntax, link titles.
15. <https://gitbook.com/docs/docs-as-code/git-sync/enabling-github-sync>: setup, initial direction, project directory, mapping.
16. <https://gitbook.com/docs/docs-as-code/git-sync/github-pull-request-preview>: previews; fork previews off by default.
17. <https://gitbook.com/docs/guides/editing-and-publishing-documentation/import-or-migrate-your-content-to-gitbook-with-git-sync>: bidirectional after initial sync.
18. <https://gitbook.com/docs/collaborate/live-edits>: live edits cannot be unlocked with Git Sync.
19. <https://github.com/GitbookIO/gitbook-skills> (`write-docs/references/frontmatter.md`, `configuration.md`, `git-sync-serialisation.md`; `configure-site/references/git-sync-handoff.md`): front matter, export rewrites, broken-link form.
20. <https://gitbook.com/docs/manage-your-site/customization/extra-configuration>: "Edit on GitHub", page actions, MCP link.
21. <https://api.github.com/apps/gitbook-com>: app permissions and events.
22. <https://gitbook.com/docs/create-content/blocks/hint>: hint syntax.
23. <https://gitbook.com/docs/create-content/blocks/mermaid-blocks>: Mermaid fences render.
24. <https://gitbook.com/docs/account-and-billing/plans/community>: Community plan features and open source criteria; Sponsored sites.
