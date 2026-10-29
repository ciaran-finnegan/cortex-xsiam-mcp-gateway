# XQL Validation And Error Classes

Most failed or misleading raw-XQL queries are detail errors: a field that does not
exist, an enum-backed field compared with `=`, `contains` on an IP address that also
matches longer addresses, or a search with no timeframe. `validate_xql` finds these
before a query spends quota, and the executor now tells the agent which class of
error XSIAM returned instead of only a hash.

## `validate_xql`

| Argument | Default | Meaning |
| --- | --- | --- |
| `query` | required | Raw XQL to check. |
| `timeframe` | none | `{"from_ms", "to_ms"}` or `{"relative_ms"}`; the API keys `from`, `to`, `relativeTime` are also accepted. |
| `probe` | `false` | After the static checks pass, run the query over one hour with `\| limit 1`. |

Result:

```json
{
  "success": true,
  "ok": false,
  "problems": [
    {
      "code": "enum_equality",
      "severity": "error",
      "message": "Field event_category is enum-backed. ...",
      "field": "event_category",
      "suggestion": "event_category contains \"LOGIN\"",
      "docs": "https://cortex-docs.paloaltonetworks.com/cortex-xsiam/reference-and-developer-docs/cortex-agentix-xql/get-started-with-xql/supported-operators"
    }
  ],
  "corrected_query": "dataset = sample_auth_logs | filter event_category contains \"LOGIN\" | limit 25",
  "estimate": null,
  "datasets": ["sample_auth_logs"],
  "field_check": {"status": "checked", "source": "discovery"},
  "probe": null,
  "executed": false
}
```

`ok` is false when any problem has severity `error`. `corrected_query` is set only
when a deterministic rewrite applies; it is built from the comment-stripped query
and never by a model. Field-name suggestions ("Did you mean") are not applied.

### Checks

| Code | Severity | Trigger | Rewrite |
| --- | --- | --- | --- |
| `query_invalid` | error | Empty, over `XQL_MAX_QUERY_CHARS`, unterminated `/*` comment or string. | none |
| `missing_limit` | error | No terminal `\| limit N` after comments are stripped. | append `\| limit 25` |
| `limit_invalid` | error | Terminal limit below 1. | none |
| `limit_clamped` | warning | Terminal limit above `DATASET_QUERY_MAX_ROWS`; the gateway runs it at the maximum. | none |
| `no_dataset` | error | First non-`config` stage is not `dataset`, `preset` or `datamodel`. | none |
| `dataset_unresolved` | warning | Source is a preset, data model or `call`; dataset policy cannot be checked by name. | none |
| `dataset_not_allowed` | error | Dataset policy denies a referenced dataset, including join subqueries and `union`. | none |
| `unknown_dataset` | error | Allowed dataset is not in the tenant's `get_datasets` list. Suggestions come from allowed datasets only. | none |
| `unknown_field` | error | Field in `filter`, `fields`, `alter`, `comp ... by`, `sort` or `dedup` is not in the discovered schema. | none |
| `field_check_skipped` | warning | Discovery unavailable, refused by the cost guard, or found no rows, or a stage such as `join`, `union`, `windowcomp` or `iploc` reshapes the schema; checking stops there. | none |
| `enum_equality` | error | `=`, `==` or `!=` with a string on an enum-backed field. | `f contains "v"`, `not (f contains "v")` |
| `contains_on_address` | error | `contains` or `not contains` with an IPv4 or IPv6 literal. | `f in ("v")`, `f not in ("v")` |
| `timeframe_missing` | error | No timeframe. | none |
| `timeframe_invalid` | error | Wrong keys, non-integer values, or `from_ms >= to_ms`. | none |
| `timeframe_too_long` | error | Span above `DATASET_QUERY_MAX_TIMEFRAME_MS`. | none |
| `timeframe_exceeds_mode_window` | warning | Span above the engagement mode's `default_window_ms`, when engagement modes are installed. | none |
| `config_timeframe` | warning | The query sets `config timeframe`, which overrides the API timeframe. | none |
| `probe_failed` | error | The probe failed with a message that matches no class. | none |

When the probe fails with a classified error, the problem code is the error class
(below).

Every problem carries `docs`, a page on the vendor's public documentation site
taken from `https://cortex-docs.paloaltonetworks.com/llms.txt`. The gateway never
fetches these pages. Clients that also connect the documentation MCP server
(`https://cortex-docs.paloaltonetworks.com/~gitbook/mcp`) should fetch the page
rather than rely on the summary. `get_xql_help` topics carry the same `docs` field.

### Enum-backed fields

Some string fields are enum-backed: `= "VALUE"` in a row filter returns no rows even
though `comp ... by` shows the value, while `contains "VALUE"` matches. Comparisons
with `ENUM.<NAME>` are not flagged. Enum-backed fields come from:

- built-in vendor-standard entries: `alerts.alert_source`,
  `management_auditing.management_auditing_type`, `xdr_data.event_type`,
  `xdr_data.event_sub_type`;
- `XQL_ENUM_FIELDS`, a JSON object mapping dataset names or glob patterns to field
  names, for example `{"sample_*": ["event_category"]}`;
- an `enum_fields` list on an authored dataset catalogue entry, when the catalogue
  module is installed.

### What it spends

The caller's query never runs unless `probe` is true.

- Dataset existence uses the `get_datasets` API, which spends no query quota, cached
  for an hour per tenant and credential profile.
- Field discovery runs `dataset = <name> | limit 25` over the last seven days, at most
  once per tenant, credential profile and dataset per hour. Failures and empty
  samples are cached too, so a failing dataset is not retried within the hour.
  Discovery goes through the cost guard like any other query. A heavy-tier dataset
  such as `xdr_data` can be rated above the mode's approval threshold; the guard then
  refuses it, `field_check` is `{"status": "skipped", "source": "cost_guard"}`, and the
  refusal is not cached, so a mode with a higher threshold can still discover fields.
- The probe runs the comment-stripped query with its terminal limit replaced by
  `| limit 1` over one hour: the last hour of an absolute timeframe, or the last hour
  (or less) of a relative one. It goes through the cost guard. A refused probe returns
  `{"ran": false, "reason": "cost_guard"}` with the rule and the estimate. Expected cost
  of a probe that runs is about a thousandth of a unit.

Both calls reach the cost guard as tool `validate_xql`. `estimate` holds the cost
guard's estimate for the corrected (or original) query and timeframe, or `null` when no
valid timeframe was given.

### Access

`validate_xql` is a separate tool in `TOOL_ACCESS_POLICY`. The default policy gives
it only to `Admin` and `Security` (`*`). Static checks apply dataset policy, so a
principal learns nothing about datasets it cannot query. The probe runs raw XQL, so
it needs the same grants as `execute_xql_query`: a group in
`RAW_XQL_PRIVILEGED_GROUPS` and a `*` dataset grant. Without them the result has
`"probe": {"ran": false, "reason": "not_authorized"}`. The probe also refuses a
query that sets `config timeframe`, because the one-hour window would not bind it.

## Classified executor errors

Every query passes through `run_xql_query`. When XSIAM reports a failed query, the
executor hashes the upstream message as before (`error_reference_sha256`). If the
message matches a known pattern, it also returns a class and a fixed,
gateway-authored message:

```json
{
  "error": "xql_validation",
  "class": "unknown_field",
  "field": "usr_name",
  "message": "XSIAM rejected the query because a field does not exist in the dataset. ...",
  "docs": "https://cortex-docs.paloaltonetworks.com/xql-schema-reference",
  "error_reference_sha256": "...",
  "xsiam_status": "FAILED",
  "query_id": "..."
}
```

| Class | Extra keys |
| --- | --- |
| `unknown_field` | `field`, when the message names one that passes the identifier check |
| `unknown_dataset` | none |
| `syntax_error` | `position` with integer `line` and `column` when the message gives them |
| `type_mismatch` | none |
| `timeframe_invalid` | none |

XSIAM text is never returned. A message that matches no class keeps today's form,
`{"error": "XQL query failed", "error_reference_sha256": ...}`. `query_dataset`,
`continue_dataset_query`, `search_logs`, `discover_log_fields` and
`execute_xql_query` pass these keys through to the agent.

XSIAM's message formats are not published. The patterns are deliberately narrow; a
message that classifies wrongly is less useful than one that stays hashed. HTTP
4xx and 5xx failures from the API carry no body through the client and are not
classified.

## Audit

The tool audit event gains `xql_error_class`, the class of the last failed query in
the call (`unclassified` when the message matched no class). `request.probe` records
whether a `validate_xql` call asked for a probe, and `result.executed` whether the
probe ran.

## Limits

- The parser is a tokenizer and stage splitter, not the XQL grammar. Field checks
  cover the main pipeline up to the first stage that reshapes the schema; enum and
  address checks cover top-level `filter` stages only.
- Discovery samples rows. A sparse field absent from the sample is reported as
  unknown; rerun `discover_log_fields` with `field_name_contains` before trusting it.
- `contains` on an array of addresses may be intended; the `in` rewrite suits scalar
  fields.
