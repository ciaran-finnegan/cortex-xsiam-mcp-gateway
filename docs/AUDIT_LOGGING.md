# Audit Logging

## Status

Audit logging is implemented as FastMCP middleware. Every MCP tool invocation
emits structured JSON audit events at the tool boundary, including imported
OpenAPI tools.

The audit layer records activity; it does not replace authorization. Tool-level
authorization is enforced separately by `TOOL_ACCESS_POLICY`.

## Event Model

Events use `event_type=cortex_xsiam_mcp.tool_invocation` and schema version
`1.0`.

Important fields:

| Field | Description |
| --- | --- |
| `event_id` | Unique event identifier. |
| `timestamp` | UTC event timestamp. |
| `phase` | `start` or `end`. |
| `outcome` | `started`, `success`, `denied`, or `error`. |
| `tool` | MCP tool name. |
| `principal.id` | Human or service principal known to the server. |
| `principal.groups` | Groups/app roles known to the server. |
| `engagement.mode` | Engagement mode in effect: `incident_response`, `threat_hunt`, `operations`, or `unset`. The end event of `set_engagement` records the new mode. |
| `engagement.case_id` | Validated case id of the engagement, or `null`. |
| `engagement.source` | Who chose the mode: `human`, `agent_inferred`, or `header`; `null` while unset. Caller-declared provenance, not used for authorization. |
| `request.argument_names` | Names of supplied tool arguments. |
| `request.argument_hash` | SHA-256 hash of the redacted argument object. |
| `request.dataset` | Dataset when present. |
| `request.query_sha256` | SHA-256 hash of raw XQL when present. |
| `xsiam.profile_name` | Configured nonsecret name of the XSIAM credential profile selected for the request. |
| `xsiam.matched_group` | Verified group that selected the credential profile, when profile brokering is enabled. |
| `request.engagement_mode`, `request.engagement_source`, `request.scope_counts` | `set_engagement` mode, source, and scope list sizes. Scope values and notes are never logged. |
| `request.fact_key`, `request.evidence_query_id` | `record_fact` key and evidence query; the fact value is never logged. |
| `result.previous_mode` | Mode before a `set_engagement` call. |
| `result.xsiam_credential_profile` | Credential profile selected during this request only. |
| `error.message_sha256` | SHA-256 of exception text; raw exception messages are not emitted. |
| `xql_error_class` | Class of the last failed XQL query in the call: `unknown_field`, `unknown_dataset`, `syntax_error`, `type_mismatch`, `timeframe_invalid`, or `unclassified`. Absent when no query failed. See [XQL Validation](XQL_VALIDATION.md). |
| `request.probe` | Whether a `validate_xql` call asked for a probe; `result.executed` records whether it ran. |

Raw XQL is not logged by default because it can contain sensitive indicators,
user identifiers, hostnames, or investigation content.

The end event uses the credential actually selected during the request, not
only the server's fallback credential. It records the profile name, matched
group, and SHA-256 of the API key ID; API key values are never included.

## Learning Events

Changes to the tier-1 learned store use `event_type=cortex_xsiam_mcp.learning`
and schema version `1.0`. The learner process is the only writer of fact files.
It emits one event per run that changes anything or runs a scheduled job, before
committing; under `AUDIT_LOG_FAIL_CLOSED=true` a failed export cancels the run
and the journal is read again next time.

| Field | Description |
| --- | --- |
| `operation` | Learner: `tick`, `nightly`, `weekly`. Gateway: `revert_requested`, `pin_requested`, `unpin_requested`, `read` (resource read). |
| `trigger` | `learner`, `revert_learned`, or `resource`. |
| `principal.id`, `principal.groups` | The learner principal (`LEARNER_PRINCIPAL_ID`), or the admin or reader in the gateway. |
| `actions` | Count of changes per action. |
| `changes[]` | Up to 100 changes: `entry_id`, `kind`, `dataset`, `action` (`learned`, `confirmed`, `promoted`, `demoted`, `verified`, `contradicted`, `pinned`, `unpinned`, `expired`, `reverted`), `fact`, `previous_fact` on a value change, `evidence` query ids, `confirmations`, `contradictions`, `confidence`, `status`, `expires_at`, `verified_at`, `pinned`, `engagements`. Verification and its loss are recorded as `verified` and `demoted` changes. |
| `changes_truncated` | True when more than 100 changes were made. |
| `details` | Learner: the run report (journal records read, engagements processed, jobs and their results), cached results, fact links, and `observed_by`, the principals whose calls produced the observations. Gateway: the entry for a revert request; kind, success and count for a read. |

The learner's nightly query of `xql_query_center_history` also emits a normal
`cortex_xsiam_mcp.tool_invocation` event for the learner principal. Facts are
validated short tokens and identifiers; result text and filter literals never
appear in these events. See [Learning](LEARNING.md).

## Example Event

```json
{
  "schema_version": "1.0",
  "event_type": "cortex_xsiam_mcp.tool_invocation",
  "event_id": "a3a2e8f0-01c0-45cb-80ef-35d1fdfdfc75",
  "timestamp": "2026-07-09T12:00:00.000000+00:00",
  "service": "cortex-xsiam-mcp-gateway",
  "phase": "end",
  "outcome": "success",
  "tool": "query_dataset",
  "transport": "streamable-http",
  "principal": {
    "id": "analyst@example.com",
    "groups": ["Tier1"]
  },
  "engagement": {
    "mode": "incident_response",
    "case_id": "IR-2026-001",
    "source": "human"
  },
  "request": {
    "argument_names": ["dataset", "fields", "filters", "limit", "mode"],
    "argument_hash": "4f0b...",
    "dataset": "xdr_data",
    "limit": 25,
    "filter_count": 2,
    "filter_fields": ["event_type", "severity"]
  },
  "result": {
    "success": true,
    "executed": true,
    "query_id": "123456"
  }
}
```

## Cost Guard Events

The XQL cost guard emits `event_type=cortex_xsiam_mcp.cost_guard` (schema
version `1.0`) for every refusal, approval, and elicitation outcome, in
addition to the tool invocation events. See the cost guard section of
`CONFIGURATION.md` for the rules.

| Field | Description |
| --- | --- |
| `decision` | `refused`, `approved`, or `elicitation`. |
| `outcome` | `denied` or `approved`; for elicitation `accepted`, `declined`, `cancelled`, `timeout`, or `error`. |
| `tool` | Tool that submitted the query. |
| `principal.id`, `principal.groups` | As in tool invocation events. |
| `cost_guard.rule` | Refusal rule: `approval_required`, `approval_declined`, `approval_cap`, `reserve`, or `long_running_slots`. |
| `cost_guard.mode`, `cost_guard.policy_source` | Engagement mode and whether the threshold came from the mode policy or settings. |
| `cost_guard.estimate_class`, `estimate_low_units`, `estimate_high_units` | Estimate band. |
| `cost_guard.datasets`, `cost_guard.window_ms` | Datasets referenced and the effective window. |
| `cost_guard.remaining_units`, `reserve_units`, `approval_threshold_units` | Quota position at the decision. |
| `cost_guard.query_sha256` | SHA-256 of the submitted XQL. Query text is never included. |
| `cost_guard.approval_method` | `elicitation` or `approval_argument`. |
| `cost_guard.approval_sha256` | SHA-256 of the analyst's approval text. The text itself is never logged. |
| `cost_guard.approval_reason` | `estimate_above_threshold` or `extended_timeout`. |
| `cost_guard.approved_units`, `approved_today_units`, `approval_cap_units` | Units approved, the principal's UTC-day total, and the cap. |

Tool invocation end events also carry `result.quota` (numeric
`estimate_units`, `actual_units`, `debited_units`, `remaining_units`,
`session_spent_units`;
`estimate_class`, `actual_units_source`, `approval_method` from fixed value
sets; `cached` and `approved` booleans) and `result.cost_guard_rule` for a
refusal. A refusal's end event has `outcome=denied`.

## Local Structured Logs

Audit events are written through the `cortex_xsiam_mcp.audit` logger as compact
JSON. In container platforms, route stdout/stderr to the platform log pipeline
and retain audit logs according to security policy.

## Cortex XSIAM SIEM Export

Palo Alto documents HTTP Log Collectors for receiving third-party logs in JSON,
Raw, CEF, or LEEF format and sending data to
`https://api-{tenant external URL}/logs/v1/event`.

Recommended setup:

1. In Cortex XSIAM, create an HTTP Log Collector.
2. Configure it for JSON format.
3. Record the collector URL and generated key.
4. Set:

```bash
export AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED="true"
export AUDIT_LOG_XSIAM_HTTP_COLLECTOR_URL="https://api-your-xsiam-tenant.example/logs/v1/event"
export AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY="collector-api-key"
```

The exporter sends newline-delimited JSON events. Export failures are logged and
do not block tool execution by default.

## Fail-Closed Mode

Set `AUDIT_LOG_FAIL_CLOSED=true` only when the operations team is ready for tool
calls to fail if audit export fails. This is useful for high-assurance
deployments but can cause outages if the collector or network path is unstable.

## Sensitive Query Logging

`AUDIT_LOG_INCLUDE_QUERY_TEXT=false` by default. Keep it false unless legal,
privacy, and SOC operations explicitly require full query content. Hashes are
usually enough to correlate repeated queries without storing sensitive text.
