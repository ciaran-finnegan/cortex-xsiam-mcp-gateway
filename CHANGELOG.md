# Changelog

This project follows a lightweight changelog format until stable releases begin.

## Unreleased

- CodeQL no longer analyses `tests/` (`.github/codeql/codeql-config.yml`). The
  tests create group-readable paths and assert on host names in strings on
  purpose, which were reported as findings. `src/` and `scripts/` are analysed
  as before.
- Fixed typed queries failing with an opaque server error when a field is
  named like an XQL stage or operator, for example the `target` field of
  SailPoint events. `query_dataset`, `continue_dataset_query`, `search_logs`,
  `dataset_health`, `coverage_gap`, and the helpers now write such a name in
  backticks in every position: filter, fields, sort, bin, `comp ... by`,
  metric argument, alias, and the continuation seek clause. The list is 52
  words (`XQL_RESERVED_WORDS`), measured against the XSIAM parser and matched
  in any letter case. Result rows keep the bare name. Field names still admit
  no backtick, so a quoted name cannot be closed early. Dataset names are not
  quoted. `validate_xql` does not yet flag a bare reserved word in raw XQL.
- Added `MCP_IDENTITY_AUTH_MODE=api_key`: per-person static client keys for a
  small test group before an identity provider is wired in. `MCP_API_KEYS`
  holds only each key's SHA-256 with the principal and groups it maps to, the
  server refuses to start on a malformed registry, and the mode accepts no
  Entra token or gateway header. See `docs/CONFIGURATION.md`.
- Added endpoint script execution, off by default (`SCRIPT_RUN_ENABLED`):
  `list_endpoint_scripts`, `run_endpoint_script`, and
  `get_endpoint_script_run` run a script from the XSIAM agent script library on
  named endpoints and read the result. A run needs an explicit
  `SCRIPT_RUN_GROUPS` membership on top of the tool policy (a `*` grant is not
  enough), a uid on `SCRIPT_RUN_ALLOWED_SCRIPTS` that XSIAM does not mark high
  risk, an explicit capped list of endpoint ids, `incident_response` or
  `threat_hunt` mode, a stated reason, and the analyst's approval by
  elicitation or a hashed `approval` argument. Runs and endpoints are capped
  per principal per UTC day. Results are served only for runs this process
  started for the same principal, capped and labelled untrusted; retrieved
  files are saved under `SCRIPT_RUN_RESULTS_DIR` and never returned. Every
  attempt emits a `cortex_xsiam_mcp.script_run` audit event. No API that runs
  code supplied in a request is called.
- Endpoint script execution hardening. A typed approval is accepted only for
  the exact request already refused with `approval_required` for the same
  principal, once, within 15 minutes; the audit event carries
  `request_sha256`. The approval prompt and refusal show parameter values and
  each endpoint as name, id, and status. Endpoint ids are resolved in XSIAM
  first (`endpoint_unknown`, `endpoint_lookup_failed`). Every XSIAM call has a
  deadline (`SCRIPT_RUN_API_TIMEOUT_SECONDS`); a submit that never answers is
  reported as outcome unknown and stays counted. `SCRIPT_RUN_ALLOWED_SCRIPTS`
  can pin a script's `modification_date` (`script_changed`). Retrieved-file
  links to an IP literal or `localhost` are refused.
- Added a durable run ledger (`SCRIPT_RUN_STATE_DIR`,
  `SCRIPT_RUN_RECORD_RETENTION_DAYS`): run records and per-principal daily
  counts survive a restart, the run is counted and saved before it is sent, and
  an unusable ledger refuses new runs (`state_unavailable`).
  `get_endpoint_script_run` with no `action_id` lists the caller's own runs.
- Added engagement modes (`incident_response`, `threat_hunt`, `operations`,
  `unset`) with `set_engagement`, `get_engagement`, `record_fact`, and
  `get_engagement_log`. Scope lists are validated and capped, state is bound to
  the session and principal, and `ENGAGEMENT_STORE_DIR` adds principal-scoped
  case files that are refused inside a git working tree.
- Modes only narrow access: tools hidden by the mode are denied on call and,
  with group-denied tools, removed from `tools/list`.
- Added mode and case id to `MCPContext`, every audit event, and continuation
  cursors (cursor version 2).
- Added the `ENGAGEMENT_MODE_POLICY` per-mode defaults table and
  `get_mode_policy()`, `current_mode()`, and `get_session_spend()` hooks for the
  XQL cost guard.
- Every XQL query now records dataset, window, rows, units, duration, and tool
  in the engagement log.
- Added server `instructions` and mode-specific `get_dataset_query_guidance`.
  The agent infers the mode from the opening request or asks the user one short
  question; `set_engagement` takes a `source` (`human`, `agent_inferred`,
  `header`), and `get_engagement` returns `confirm_with_user` while the mode is
  agent-inferred. `unset` inherits the `operations` defaults, and results carry
  a one-line nudge until an engagement is set. `source` is audited with mode
  and case id.
- Fixed un-awaited FastMCP `ctx.set_state` / `ctx.get_state` calls, so the
  selected credential profile now reaches the audit result; it is now
  request-scoped. Tests use a real FastMCP context or an async fake pinned to
  the FastMCP state API.
- Added the XQL cost guard (`src/usecase/cost_guard.py`) on every query path:
  light-to-extreme estimates with configurable unit bands and dataset tiers,
  approval-threshold, reserve, and long-running-slot refusals with structured
  alternatives, approval by MCP elicitation or a hashed analyst `approval`
  argument with a per-principal daily cap, `cortex_xsiam_mcp.cost_guard` audit
  events, a `quota` block on every result, and a per-principal result cache.
  The approval threshold and reserve come from the engagement mode policy, and
  `session_spent_units` from the engagement session log. Cache, approval
  totals, quota readings, and slot timings are per replica.
- Every query tool now requires a `timeframe`, normalised through
  `QueryTimeframe`; `config timeframe` inside raw XQL is bounded by the same
  maximum. Query timeouts are capped at 120 s, or 300 s with approval.
- Security fix: raw XQL comments are stripped before the terminal-limit check,
  so a `// | limit N` comment can no longer satisfy it, and identifier
  validation no longer accepts a trailing newline.
- Added `validate_xql`: strips comments and checks the terminal limit, dataset
  policy and existence, field names against the discovered schema, `=` on
  enum-backed fields, `contains` on IP address literals, and the timeframe.
  Returns problems with docs links and a `corrected_query` built only by
  deterministic rewrites, the cost guard's estimate, and an optional one-hour
  `| limit 1` probe for principals with the raw-XQL grants. Field discovery and
  the probe go through the cost guard; a refusal is reported, not cached.
- Classified XQL failures: known XSIAM validation messages now return
  `error: "xql_validation"` with a class (`unknown_field`, `unknown_dataset`,
  `syntax_error`, `type_mismatch`, `timeframe_invalid`), a fixed message, and a
  safe field name or position, alongside the existing hash. Other messages stay
  hashed. The audit event records `xql_error_class`.
- `get_xql_help` topics carry a `docs` link to the vendor's documentation site.
  The gateway never fetches it.
- Added tier-1 learning: measured tenant facts (schema, enum-like fields, absent
  fields, cost table, timings, helper usage) in `<TENANT_PACK_DIR>/learned/`,
  derived from queries the gateway already runs, with query-id evidence,
  confidence, expiry, contradiction demotion and a forgery guard.
- Gateway observers only append to a per-process journal; a separate learner
  process (`python -m learner`, run by a timer) is the single writer of fact
  files, audits each run, and runs UTC-scheduled engagement-close, nightly
  (expiry, cost recalibration from the query history as a capped `learner`
  principal) and weekly (digest, replay scoring, step mining) jobs, plus a deploy
  canary.
- Added automatic verification: a fact is labelled `verified` after 5
  confirmations from 3 distinct engagements over 7 days with no contradiction
  (all settings); one contradiction drops it back to `learned`.
- Added `python -m learner backfill --days N --max-units X`, run once by an
  operator, which reads older queries from `xql_query_center_history` into cost
  and absent-field facts with the source class `query_history_backfill`. It is
  resumable, never selects `issuer`, and keeps query text in memory. Its facts
  never count towards verification, leave live facts alone, and can raise a cost
  guard estimate but not lower it. It calls no model.
- Nightly recalibration now keeps a sample's quota delta when the history reports
  zero units, because zero there is not a measurement. Confirmed against a live
  tenant that `execution_id` in the history equals the public API's query id.
- Added `get_learned_facts`, the `tenant://learned/{kind}` resource,
  `learning_digest`, admin-only `revert_learned` (revert, pin, unpin), and the
  `LEARNING_ENABLED` kill switch for both processes.
- Added the tier-2 replay foundation: an opt-in bounded per-case result cache and
  `replay_engagement`, plus a synthetic IOC-flood triage agent-evaluation case.
- For the learner, the executor also tags an unknown-field failure with
  `error_class` and `unknown_field`, only when the field already appears in the
  submitted query.
- The cost guard reads the learned cost table before its seed band, floored at
  the band's low bound, and the learning observers run after the cost guard and
  query telemetry; refused queries and cache hits are not observed.
- `xql_query_center_history` is seeded as a light dataset in
  `COST_GUARD_DATASET_TIERS`, so the learner's nightly recalibration query
  stays under the default approval threshold.
- Fixed the learner's nightly cost recalibration failing with `TypeError` on a
  live tenant: its request context now has FastMCP's async `get_state` and
  `set_state(..., serializable=...)`, which `get_fetcher` has needed since
  engagement modes landed.
- Added `coverage_gap`, which counts and lists hosts present in a reference
  inventory and absent from a target inventory using one server-generated
  anti-join built only from validated catalogue identifiers, with both datasets
  policy checked. Added the authored `host_filter` catalogue attribute.
- Added `threat_intel_lookup`, which resolves one indicator to its verdict and
  related malware families and threat actors using sequential typed queries,
  without returning free-text threat intelligence fields.
- Added `value_type: enum` for typed filters so enum fields such as endpoint
  `event_type` can be filtered; member names are validated as bare uppercase
  identifiers.
- Added `get_xql_help` topics `enum_fields`, `field_types`, `ingestion_health`,
  and `helpers`.
- Added `dataset_health`, a bounded arrival, schema, and sample check for one
  data source, as the alternative to unfiltered dataset dumps.
- Added `entity_activity`, which summarizes recent activity for one user,
  computer, IP address, or cloud resource across allowed catalogued datasets
  with one bounded aggregate per dataset and capped samples. Identity sources
  are now read concurrently, and the helper query budget reserves slots before
  each query so concurrent work cannot exceed it.
- Corrected the built-in catalogue: in firewall session datasets the log source
  name is the reporting firewall, not the subject host.
- Added question-shaped investigation helpers: `resolve_entity` links a host,
  user, or IP address to the others it is known by; `firewall_traffic` and
  `firewall_verdict` answer traffic and blocking questions with aggregate-first
  typed plans. Helpers select datasets from the catalogue under dataset policy,
  verify fields against the live schema, and enforce a per-call query budget.
- Audit events now record `helper_queries` (dataset, purpose, query hash, query
  id, row count) for tools that choose datasets server-side.
- Added the `identity_source` catalogue flag.
- Added an authored dataset catalogue and the `find_datasets` tool so agents can
  select datasets by topic, domain, or entity type instead of guessing from
  names. Dataset policy is applied before catalogue lookup, catalogue text is
  authored content only, and field names are candidates that helpers verify
  against discovered fields.
- Added `DATASET_CATALOGUE_OVERLAY_PATH` for operator-authored, out-of-repo
  descriptions of site-specific datasets; an invalid overlay fails startup.
- Added `offset` paging and `next_offset` to `list_log_datasets` so tenants with
  more datasets than the response cap can be listed completely.
- The investigation helpers run under the XQL cost guard: every helper query
  carries the helper's tool name, a refusal is returned as the helper's result
  with the estimate, alternatives and the provenance of the queries already
  run, and each helper accepts the `approval` argument. `threat_intel_lookup`
  takes `window_days` (default 30) because every query needs a timeframe.
- Cost guard: an early-exit sample now scores its tier and window points minus
  two instead of its tier points minus one, so a short-window field-discovery
  sample of a heavy dataset is light and runs below the approval threshold.
  Before this, `discover_log_fields` and the `validate_xql` field check were
  refused for `xdr_data` in operations mode, and validation passed queries that
  named fields the dataset does not have.
- Added [Secrets And API Keys](docs/SECRETS.md): 1Password CLI, macOS Keychain
  and Windows SecretStore examples that inject the XSIAM key at start after a
  person approves, plus `.env.op.example`. `.env.example`, the README and the
  configuration and testing docs no longer put secrets in `.env`.
- Cost guard: refitted the score and the default unit bands to 880 queries with
  recorded compute units. A positive equality on a host key or on a field in the
  new `COST_GUARD_PARTITION_FIELDS` (default `event_type`) now takes window
  points off a heavy dataset instead of saving one point, pattern matching adds
  cost only to an un-narrowed multi-day scan of a heavy dataset, and the
  `medium` tier scores 1 point, down from 2. Un-narrowed scans of a heavy
  dataset over more than a day score as before. Default bands are now
  `{"light":[0.001,0.5],"medium":[0.05,2.5],"heavy":[2,9],"extreme":[5,32]}`.
- Cost guard: the narrowing credit needs a comparison with literals (a field
  compared with itself, another field or a function result earns nothing; a
  host list is capped at 20 values and a partition list at two), and every
  pipeline that reads a heavy dataset must carry its own filter, so a filter on
  one side of a join no longer narrows the other side. The filter must run on
  the dataset's own rows and fields: one that follows an aggregation, a join, a
  sort, a limit or a reassignment of the field earns nothing, and neither does
  a comparison under an enclosing `not`.
- Cost guard: an exact dataset name in `COST_GUARD_DATASET_TIERS` now pins the
  tier ahead of the catalogue volume, as the catalogue comment always said it
  would; globs stay a fallback. The default map pins the firewall traffic, URL
  and cloud flow log datasets to `medium`, and its existing `light` pin for
  `xql_query_center_history` now takes effect.
- Field discovery samples one day first and widens to seven days only when the day
  returns no rows, in `validate_xql`, the investigation helpers and `dataset_health`.
  With the early-exit sample scoring change (#68), discovery on a heavy dataset such as
  `xdr_data` starts from a light estimate and is normally below every mode's
  approval threshold, though both samples stay subject to every cost guard check;
  before, the fixed seven-day sample
  was rated medium and refused in operations mode, so `validate_xql` skipped its
  field check there. An idle dataset now costs two cheap samples instead of one.
  A sample the cost guard refuses, on either window, ends the helper or
  `dataset_health` call with that refusal, and a sample that fails reports the
  dataset as `unknown`, so an unverified dataset is never reported as empty.

## 0.2.0-alpha.1 - 2026-07-10

- Added `query_dataset` with typed row projection, filters, aggregates, top-N,
  and time-bucketed trends for security and non-security datasets.
- Added encrypted principal/group/policy-bound keyset continuation with XSIAM
  timestamp conversion and policy rechecks.
- Added server-side output projection, row/field/cell/byte/timeframe limits,
  timeout-bounded polling, and a four-query concurrency ceiling.
- Upgraded to FastMCP 3.4.4 and removed the FastMCP 2.x transitive `diskcache`
  path from the lockfile.
- Regenerated the dependency lock within declared constraints and verified the
  full suite on active Python 3.12 and a fresh Python 3.13 environment.
- Added trusted-gateway nonce replay prevention and deterministic credential
  profile priority.
- Made gateway replay-cache saturation fail closed, clamped terminal raw-XQL
  limits before submission, and preserved continuation lookahead at XSIAM's
  result ceiling.
- Removed upstream PAPI response bodies and XQL failure details from exceptions,
  logs, and tool responses so rejected queries and sensitive literals cannot be
  echoed through MCP errors.
- Fixed OpenAPI-generated tools to resolve role-scoped XSIAM credentials per
  request and audit the credential actually selected.
- Added MCP-schema, executor, security-regression, opt-in live XSIAM, and blind
  Codex agent-planning tests.
- Validated dynamic field discovery, non-security rows and aggregates,
  time-bucketed trends, and timestamp keyset continuation against a locally
  configured XSIAM service without persisting tenant data or result values.
- Reworked agent guidance around progressive field discovery, aggregate-first
  answers, typed operators, raw-XQL fallback, and cursor-only continuation.

- Added compact agent log-search guidance, allowed dataset discovery, and
  XQL-backed field discovery tools for LLM agents.
- Removed the server-side `natural_language_query` log-search path in favor of
  Claude Code/Codex structured MCP calls.
- Added Claude Code/Codex log-search workflow tests for dataset discovery,
  field discovery, structured dry runs, denied datasets, and raw-XQL
  authorization.
- Added Entra JWT validation for HTTP transport.
- Added optional HMAC-signed trusted gateway identity forwarding for Portkey,
  LiteLLM, and similar gateways.
- Added tool-level policy middleware for every MCP tool invocation.
- Added XSIAM credential broker support for pre-provisioned role/group-scoped
  API key profiles.
- Added enterprise-first README with deployment diagrams, alpha limitations,
  and comparison with the current Palo Alto Cortex MCP deployment model.
- Added framework-level audit middleware for every MCP tool invocation.
- Added optional Cortex XSIAM HTTP Log Collector export for audit events.
- Restricted `execute_xql_query` to configured privileged groups.
- Added dependency remediation, release process, enterprise deployment, audit,
  and AI review documentation.
- Added review configuration scaffolding for Codex, Claude, CodeRabbit, and
  GitHub Copilot.
- Added Dependabot auto-merge and release workflows.

## 0.1.0-alpha.1 - 2026-07-09

- Created public fork hardening track for Cortex XSIAM MCP Gateway.
- Added `search_logs` with raw XQL, structured filters, and conservative
  natural-language translation.
- Added dataset policy enforcement for `search_logs`.
- Added XQL quota helper.
- Added project documentation, security policy, governance, and GitHub workflows.
- Added Python version constraint for Python 3.12 and 3.13.
- Added explicit `pydantic-settings` dependency.
