# Configuration

Configuration is loaded from environment variables and an optional `.env`
file in the working directory, environment variables win. Keep API keys and
other secrets out of `.env` and inject them at start, see
[Secrets And API Keys](SECRETS.md). Do not commit `.env` files.

## Required XSIAM API Settings

| Variable | Description |
| --- | --- |
| `CORTEX_MCP_PAPI_URL` | XSIAM tenant API URL. If missing `api-`, the client normalizes the hostname. |
| `CORTEX_MCP_PAPI_AUTH_HEADER` | XSIAM API key value. |
| `CORTEX_MCP_PAPI_AUTH_ID` | XSIAM API key ID. |

Do not write the key into `.env`, the MCP client's config file or a command
line. [Secrets And API Keys](SECRETS.md) shows how to inject it at start from
1Password, the macOS Keychain or the Windows SecretStore.

## MCP Server Settings

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `MCP_HOST` | `0.0.0.0` | Host for HTTP transport. |
| `MCP_PORT` | `8080` | Port for HTTP transport. |
| `MCP_PATH` | `/api/v1/stream/mcp` | HTTP MCP path. |
| `MCP_ALLOW_UNAUTHENTICATED_HTTP` | `false` | Explicit isolated-test override. HTTP startup otherwise fails when identity mode is `none`. |
| `LOG_LEVEL` | `INFO` | Python log level. |

## Dataset Policy

`LOG_SEARCH_DATASET_POLICY` is a JSON object mapping group names to allowed
datasets. Use `*` to allow all datasets.

```bash
export LOG_SEARCH_DATASET_POLICY='{
  "Security": ["*"],
  "Tier1": ["xdr_data"],
  "CloudTeam": ["xdr_data", "cloud_audit_logs"]
}'
```

For local development before incoming identity is wired in:

```bash
export LOG_SEARCH_DEFAULT_PRINCIPAL_ID="dev-analyst@example.com"
export LOG_SEARCH_DEFAULT_GROUPS="Security"
```

Do not use default groups as a production authorization mechanism.

## Dataset Catalogue

`find_datasets` searches an authored catalogue that describes what each dataset
holds and which fields identify a host, user, IP address, or cloud resource.
The gateway ships a built-in catalogue of vendor-standard Cortex and marketplace
datasets. Describe site-specific datasets in an overlay file that lives outside
this repository.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATASET_CATALOGUE_OVERLAY_PATH` | empty | Path to an operator-authored overlay JSON file. Overlay entries win over built-in entries. An unreadable, oversized, or invalid overlay stops the server at startup. |

See [Dataset Catalogue](DATASET_CATALOGUE.md) for the file format and security
properties.

## Raw XQL Privilege

`execute_xql_query` is restricted to groups listed in
`RAW_XQL_PRIVILEGED_GROUPS`. It additionally requires that dataset policy grant
the principal `*`, because raw XQL can contain joins and subqueries that cannot
be authorized from one caller-declared dataset.

```bash
export RAW_XQL_PRIVILEGED_GROUPS="Security,Admin"
```

Use this raw XQL tool only for high-trust roles. Every raw query must end with a
numeric `| limit N` stage; the server strips `//` and `/* */` comments, then
clamps that stage to `DATASET_QUERY_MAX_ROWS` before execution, so a limit
written inside a comment does not count. Prefer `query_dataset` for routine
agent workflows because it requires an explicit dataset and compiles only
allowlisted query operations.

## Incoming Identity

HTTP transport supports four identity modes: Entra bearer tokens, a trusted
gateway's signed headers, either of those, or static client API keys.

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_IDENTITY_AUTH_MODE` | `none` | `none`, `entra`, `gateway`, `entra_or_gateway`, or `api_key`. Use `none` only for local development or isolated stdio use. |
| `ENTRA_TENANT_ID` | empty | Tenant ID used to derive Entra issuer and JWKS URL. |
| `ENTRA_AUDIENCE` | empty | Expected `aud` claim for this MCP API. Required for Entra mode. |
| `ENTRA_ISSUER` | derived | Optional explicit expected issuer. |
| `ENTRA_JWKS_URI` | derived | Optional explicit JWKS URL. |
| `ENTRA_REQUIRED_SCOPES` | empty | Comma- or space-separated scopes required on bearer tokens. |
| `ENTRA_GROUPS_CLAIM` | `groups` | Claim containing group IDs or names. |
| `ENTRA_ROLES_CLAIM` | `roles` | Claim containing app roles. |

Gateway mode validates a signed forwarding contract rather than trusting plain
headers:

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_GATEWAY_SHARED_SECRET` | empty | HMAC secret shared only between the trusted gateway and this MCP service. |
| `MCP_GATEWAY_ALLOWED_ISSUERS` | empty | Optional comma-separated gateway issuer allowlist such as `portkey,litellm`. |
| `MCP_GATEWAY_MAX_CLOCK_SKEW_SECONDS` | `300` | Maximum age/skew for signed gateway assertions. |
| `MCP_GATEWAY_NONCE_CACHE_SIZE` | `10000` | Maximum in-memory replay entries for signed assertions. Saturation fails closed until entries expire. Use shared replay state before running multiple replicas. |

The gateway signature covers issuer, principal, groups, roles, timestamp, and
nonce. Do not deploy gateway mode unless the MCP service is reachable only from
the trusted gateway or a network segment with equivalent controls.

### Static client API keys

`api_key` mode is for a small test group before an identity provider is wired
in. Each person gets their own key, so the audit trail still names who made
each call. It accepts nothing else: Entra tokens and gateway headers are
rejected while it is on.

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_API_KEYS` | empty | JSON object of key id to entry. Holds SHA-256 hashes only. Empty rejects every caller. |

A client sends `Authorization: Bearer xgw_<key_id>.<secret>`. The key id is
3-64 characters of `a-z`, `0-9` and hyphen. The secret is at least 32
URL-safe characters; generate it with a CSPRNG, for example
`python -c "import secrets; print(secrets.token_urlsafe(32))"`. The registry
entry stores the SHA-256 of the whole token:

```json
{
  "analyst-one": {
    "sha256": "<64 lowercase hex chars>",
    "principal": "analyst.one",
    "groups": ["Tier1"],
    "expires": "2027-01-31"
  }
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `sha256` | yes | SHA-256 of the full token, lowercase hex. Two entries cannot share one. |
| `principal` | yes | The identity written to audit events and used for per-principal caps. |
| `groups` | no | Groups for `TOOL_ACCESS_POLICY`, the dataset policy and raw XQL privilege. None means no tool access. |
| `expires` | no | `YYYY-MM-DD`. The key stops working at 00:00 UTC on that date. |
| `disabled` | no | `true` revokes the key without removing the entry. |
| `created`, `note` | no | Free text for the operator. Ignored. |

The server refuses to start on a malformed registry, and an unknown field is
malformed, so a misspelt `groups` cannot silently drop a restriction. A wrong
key id and a wrong secret get the same `401`. Rejections are logged with the
key id only.

Keep these keys out of files and chat. Inject `MCP_API_KEYS` at start from the
secret store, the same way as the XSIAM API key, and have each person keep
their token in the OS credential store ([Secrets](SECRETS.md)). The keys do
not expire unless you set `expires`, there is no rate limit on guesses beyond
the 256-bit secret, and revocation takes a restart. Move to `entra` mode
before widening access.

## Tool Policy

`TOOL_ACCESS_POLICY` maps verified groups/app roles to allowed MCP tools.

```bash
export TOOL_ACCESS_POLICY='{
  "Security": ["*"],
  "Tier1": [
    "get_log_search_guidance",
    "get_dataset_query_guidance",
    "get_xql_help",
    "find_datasets",
    "resolve_entity",
    "firewall_traffic",
    "firewall_verdict",
    "entity_activity",
    "dataset_health",
    "threat_intel_lookup",
    "coverage_gap",
    "list_log_datasets",
    "discover_log_fields",
    "query_dataset",
    "continue_dataset_query",
    "search_logs",
    "get_xql_query_quota",
    "get_cases",
    "get_issues",
    "set_engagement",
    "get_engagement",
    "record_fact",
    "get_engagement_log"
  ]
}'
```

Tool policy is enforced for every MCP tool invocation. Dataset policy still
runs inside discovery and query tools. Tools a principal cannot invoke are not
advertised in `tools/list`.

`run_endpoint_script` and `get_endpoint_script_run` also need a group in
`SCRIPT_RUN_GROUPS`; a `*` grant does not cover them. See
[Endpoint script execution](#endpoint-script-execution).

## Engagement Modes

| Variable | Default | Description |
| --- | --- | --- |
| `ENGAGEMENT_STORE_DIR` | empty | Optional absolute directory for principal-scoped case files. Must be outside the repository and any git working tree; startup fails otherwise. Empty keeps engagements in session state only. |
| `ENGAGEMENT_MODE_POLICY` | empty | JSON per-mode overrides of default window, approval threshold, session budget, reserve units, default result shape, and hidden tools. Empty uses the built-in defaults. `unset` inherits the `operations` row. |
| `ENGAGEMENT_MAX_SCOPE_ITEMS` | `100` | Maximum entries per scope list in `set_engagement`; valid range 1-1000. |

Modes only narrow what `TOOL_ACCESS_POLICY` grants. See
[Engagement Modes](ENGAGEMENT_MODES.md).

`validate_xql` is granted like any other tool; the default policy gives it to
`Admin` and `Security` only. Its optional probe also requires the raw-XQL grants.

## Structured Dataset Query Limits

| Variable | Default | Description |
| --- | --- | --- |
| `DATASET_QUERY_MAX_ROWS` | `100` | Maximum rows or aggregate groups returned by one call; valid range 1-1000. Continuation pages reserve one XSIAM result slot for lookahead, so their effective maximum is 999. |
| `DATASET_QUERY_MAX_FIELDS` | `25` | Maximum projected fields. Unrequested fields are removed server-side. |
| `DATASET_QUERY_MAX_FILTERS` | `20` | Maximum typed filters. |
| `DATASET_QUERY_MAX_METRICS` | `8` | Maximum aggregate metrics. |
| `DATASET_QUERY_MAX_GROUP_FIELDS` | `5` | Maximum aggregate grouping fields. |
| `DATASET_QUERY_MAX_RESPONSE_BYTES` | `65536` | Approximate serialized row budget. |
| `DATASET_QUERY_MAX_CELL_CHARS` | `2048` | Maximum string length per result cell. |
| `DATASET_QUERY_MAX_TIMEFRAME_MS` | `2592000000` | Maximum relative/absolute timeframe span; default 30 days. |
| `DATASET_QUERY_CURSOR_SECRET` | empty | Secret used to encrypt and authenticate continuation cursors. Required for continuation. |
| `DATASET_QUERY_CURSOR_TTL_SECONDS` | `900` | Cursor validity period. |
| `XQL_MAX_CONCURRENT_QUERIES` | `4` | Process-level XQL concurrency, hard-capped at XSIAM's four-query limit. |
| `XQL_MAX_QUERY_CHARS` | `32768` | Maximum compiled or privileged raw XQL length. |
| `XQL_ENUM_FIELDS` | `{}` | JSON object mapping dataset names or glob patterns to enum-backed field names, for `validate_xql`. Adds to the built-in vendor-standard list. Example: `{"sample_*": ["event_category"]}`. |

Cursor state is bound to principal, tenant, auth source, groups, query plan,
engagement mode, case id, and the current dataset-policy hash. A policy,
identity, or engagement change invalidates the cursor, and policy is checked
again on continuation.

## XQL Cost Guard

Every XQL query, whether raw, typed, discovery, or helper, passes the cost guard
in `run_xql_query` before submission. XSIAM charges compute units for bytes
scanned, and the API budget is shared with SOC tooling and playbook automation;
once it is spent, every query fails until 00:00 UTC.

Every query tool requires a `timeframe` (`{"from_ms": ..., "to_ms": ...}` or
`{"relative_ms": ...}`; the API shapes `{"from", "to"}` and `{"relativeTime"}`
are accepted). There is no server default window. The span is checked against
`DATASET_QUERY_MAX_TIMEFRAME_MS`, and so is any `config timeframe = <n><unit>`
stage inside raw XQL. `config timeframe between ...` is rejected; pass absolute
ranges in the `timeframe` argument.

The guard classifies each query as `light`, `medium`, `heavy`, or `extreme`
from a score:

| Factor | Points |
| --- | --- |
| Dataset tier `light` / `medium` / `heavy` (highest tier referenced; no dataset clause counts as `heavy`) | 0 / 1 / 4 |
| Window up to 1 d / 7 d / 30 d / 90 d / longer | 0 / 1 / 2 / 3 / 4 |
| Heavy dataset with a positive `=` or `in` filter on a field in `COST_GUARD_SELECTIVE_FIELDS` | up to 3 window points removed |
| Heavy dataset with a positive `=`, or an `in` list of at most two values, on a field in `COST_GUARD_PARTITION_FIELDS` | up to 2 window points removed |
| Heavy dataset with neither filter, over more than a day | +1 |
| `contains`, `~=`, `regextract`, `regexcapture` on that same un-narrowed scan | +1 |
| `_raw_log` or `to_json_string(` | +2 |
| `join`, `union`, `dedup` / `search` / `call` | +1 each / +2 / +3 |

Scores up to 2 are light, up to 4 medium, up to 6 heavy, and above that
extreme. A query with only dataset, `fields`, `limit`, and `config` stages is an
early-exit sample: it scores its tier and window points minus two and takes no
selectivity, text-scan, or stage penalties, so a bounded sample of a heavy
dataset over a day or less is light and the same sample over 90 days is heavy.
Field discovery and `validate_xql` field checks are such samples.
Comments and string literals are removed before parsing, so neither can hide or
fake a stage. A host or partition filter counts only in a filter stage without
`or`, never under `not`, and only when it compares the field with literals: a
field compared with itself, with another field or with a function result earns
nothing, and a host list may name at most 20 values. Every pipeline that reads a
heavy dataset needs its own filter, so a filter on one side of a join does not
narrow the other, and a heavy dataset added by `union <name>` is never narrowed.
The filter must also come before any stage that aggregates, joins, sorts, limits
or otherwise reshapes the rows, and before an `alter` or `fields` stage that
assigns the field, so it is the dataset's own field being filtered. A `not`
that encloses the comparison at any depth cancels the credit. The narrowing
credits take points off the window only, so a narrowed query never scores below
its tier.

The dataset tier is the first of: an exact dataset name in
`COST_GUARD_DATASET_TIERS`; the authored catalogue `volume` when the catalogue
is installed (`very_high` is heavy, `high` medium, `medium` and `low` light); a
glob in `COST_GUARD_DATASET_TIERS`; `COST_GUARD_DEFAULT_TIER`. Pin a dataset by
exact name when its recorded `actual_units` disagree with its catalogue volume.

The points and the default bands were fitted to 880 queries with recorded
compute units, taken from eight days of one tenant's `xql_query_center_history`.
What that sample showed:

- The dataset and the window alone do not predict cost. On endpoint telemetry
  an equality on a host key cost 0.1 units at the median and 1.1 at the 90th
  percentile for any window up to 30 days, and an `event_type` equality over 30
  days cost 0.2 to 1.4. The same 30 days with neither filter cost up to 15.
- Pattern matching made no measurable difference on light and medium datasets
  or on narrowed scans.
- Firewall traffic, URL and cloud flow logs on their own never cost more than
  0.4 units, including 90-day pattern scans, so the defaults pin them to medium.
  Joined to endpoint telemetry, a 7-day query cost 5 to 8.
- The same query cost 0.06 units on a quiet day and up to 3.6 in a burst of
  thirty concurrent runs. A band is a typical range, and the reserve and the
  session budget are what bound a bad day.

Against that sample the old points asked for approval on 635 of 880 queries in
`threat_hunt` mode, 621 of which cost less than the threshold. These points ask
on 66, and every query that cost more than 3.7 units is among them. Refit the
tier map and bands against the `actual_units` each result records.

When learning is enabled and the learned cost table has an active entry for a
single-dataset query's dataset, window bucket and selectivity, the guard uses
its units instead of the seed band: `high_units` is the learned high, but never
below the seed band's low bound, so learned data can raise an estimate freely
and lower it only to that floor. The class, and so the long-running-slot rule,
stays the seed class. The estimate's `factors` then carry
`units_source: "learned"` and the entry id.

Rules, in order:

1. A cached result for the same principal, groups, dataset policy, XSIAM
   credential profile, profile configuration, API key fingerprint, query text,
   timeframe, and limit is returned within `COST_GUARD_CACHE_TTL_SECONDS`
   without spending quota. The credential broker is checked first, so a principal it now rejects
   gets no cached result.
2. While `COST_GUARD_LONG_SLOT_LIMIT` queries have held a query slot longer than
   `COST_GUARD_LONG_SLOT_SECONDS`, new heavy and extreme queries are refused.
3. Any query whose estimate (the band's high bound), plus the estimates of
   queries in flight, would take the remaining quota below the reserve is
   refused. Approval never overrides the reserve. The remaining quota comes
   from the last XSIAM reply; when that is missing or older than
   `COST_GUARD_QUOTA_STALE_SECONDS`, the guard reads `/xql/get_quota` and uses
   its `remaining_quota`, or `COST_GUARD_DAILY_QUOTA_UNITS` minus
   `daily_used_quota`. If it still cannot tell, heavy and extreme queries are
   refused. A query that times out or fails without a reply after its start
   request was sent stays debited at its estimate until the next XSIAM
   reading, because XSIAM may still be running it. A query cancelled before
   submission is released without a debit.
4. A query whose estimate exceeds the approval threshold needs approval. When
   the MCP client supports elicitation, the guard asks the analyst directly with
   the estimate and alternatives. Otherwise, or when that prompt is cancelled,
   the tool's `approval` argument must carry the analyst's own words; the
   gateway stores only its SHA-256 and counts the approved units against a
   per-principal daily cap. An explicit decline is final for that call.

The approval threshold and reserve come from the current engagement mode's
policy (`get_mode_policy`, set with `ENGAGEMENT_MODE_POLICY`); the settings
below are used only if that policy cannot be read. `session_spent_units` is the
spend in the engagement session log plus the current query. Only queries that
reach XSIAM are written to the engagement log: a refusal runs nothing, and a
cache hit is a repeat of a query already logged under the same mode and case. An `approval` string is an accountability record, not proof
that a human typed it; the cap bounds what an agent could approve for itself,
and clients with elicitation never rely on it unless the prompt is cancelled.

A refusal returns `success: false`, `error: "cost_guard"`, a `message` beginning
"Query not allowed by the cost guard", the `rule` (`approval_required`,
`approval_declined`, `approval_cap`, `reserve`, or `long_running_slots`), the
`estimate`, `remaining_units`, `reserve_units`, `approval_threshold_units`,
`mode`, and deterministic `alternatives`, each with its own estimate: the last
7 days and 24 hours of the window, a host filter when the engagement lists
servers, counts instead of rows, a cheaper dataset that the principal may query
(field names differ, so it carries no XQL), and the unchanged XQL for the XSIAM
console, which is not charged to the API quota. A query run in the console is
outside this gateway: its cost guard, MCP audit events, raw-XQL privilege
check, and dataset policy do not apply. This repository does not define the
console's own authorization, audit, or cost controls; confirm them separately
before relying on that alternative.

Every result carries `quota`: `estimate_units`, `estimate_class`,
`estimate_band`, `actual_units` (from `query_cost`, else the drop in
`remaining_quota`), `actual_units_source`, `debited_units` (the estimate held
against a timed-out query), `remaining_units`,
`session_spent_units`, `cached`, `approved`, and `approval_method`.

| Variable | Default | Description |
| --- | --- | --- |
| `COST_GUARD_ENABLED` | `true` | Apply the cache and the refusal rules. The timeframe requirement and timeout ceiling apply either way. |
| `COST_GUARD_UNIT_BANDS` | `{"light":[0.001,0.5],"medium":[0.05,2.5],"heavy":[2,9],"extreme":[5,32]}` | Unit band per class. Decisions use the high bound. |
| `COST_GUARD_DATASET_TIERS` | `{"xdr_data":"heavy","xdr_*":"heavy","*_story":"heavy","amazon_aws_raw":"heavy","msft_azure_raw":"heavy","google_gcp_*":"heavy","panw_ngfw_traffic_raw":"medium","panw_ngfw_url_raw":"medium","msft_azure_flowlogs_raw":"medium","xql_query_center_history":"light"}` | Dataset name or `*` glob to `light`, `medium`, or `heavy`. Exact names win over globs. |
| `COST_GUARD_DEFAULT_TIER` | `medium` | Tier for datasets the catalogue and tier map do not list. |
| `COST_GUARD_SELECTIVE_FIELDS` | `agent_hostname,agent_id,endpoint_id,endpoint_name,host_name,hostname` | Fields whose positive equality scopes a heavy dataset to hosts. |
| `COST_GUARD_PARTITION_FIELDS` | `event_type` | Fields whose positive equality, or `in` list of at most two values, narrows a heavy dataset to a slice of its rows. Empty disables the credit. |
| `COST_GUARD_HOST_FIELDS` | `{"xdr_data":"agent_hostname"}` | Field used by the host-filter alternative per heavy dataset. |
| `COST_GUARD_CHEAPER_DATASETS` | `{"amazon_aws_raw":["cloud_audit_logs"],"msft_azure_raw":["cloud_audit_logs"]}` | Cheaper datasets for the same question. Catalogue datasets in the same domain that the principal's policy lists are added. |
| `COST_GUARD_APPROVAL_THRESHOLD_UNITS` | `1.0` | Approval threshold used only if the engagement mode policy cannot be read. Matches the unset mode. |
| `COST_GUARD_RESERVE_UNITS` | `20.0` | Reserve used only if the engagement mode policy cannot be read. Matches the unset mode. |
| `COST_GUARD_APPROVAL_DAILY_CAP_UNITS` | `10.0` | Units one principal may approve per UTC day with the `approval` argument. `0` disables the argument, including for timeout extensions. Elicitation approvals are not capped. |
| `COST_GUARD_DAILY_QUOTA_UNITS` | `0` | The tenant's daily API budget, used with `get_quota`'s `daily_used_quota` when that reply has no `remaining_quota`. `0` means unknown. `license_quota` is never used, because tenants report it either as an annual total or as a daily allowance. |
| `COST_GUARD_QUOTA_STALE_SECONDS` | `300` | Age after which the last observed `remaining_quota` is refreshed from `get_quota`. |
| `COST_GUARD_ELICITATION_ENABLED` | `true` | Ask the analyst through MCP elicitation when the client supports it. |
| `COST_GUARD_ELICITATION_TIMEOUT_SECONDS` | `120` | Time to wait for an answer before treating the prompt as unanswered. |
| `COST_GUARD_LONG_SLOT_SECONDS` | `60` | Slot age that counts as long-running. |
| `COST_GUARD_LONG_SLOT_LIMIT` | `2` | Long-running slots that block new heavy queries. |
| `COST_GUARD_CACHE_TTL_SECONDS` | `600` | Result cache lifetime. `0` disables the cache. |
| `COST_GUARD_CACHE_MAX_ENTRIES` | `64` | Cached results kept per process, least recently used first out. |
| `XQL_TIMEOUT_CEILING_SECONDS` | `120` | Ceiling for any query timeout, including `execute_xql_query`'s `timeout`. |
| `XQL_TIMEOUT_APPROVED_CEILING_SECONDS` | `300` | Ceiling once the query is approved. An `approval` on a query below the threshold also lifts the ceiling, recorded with zero units. |

Quota readings and in-flight reservations are keyed by the XSIAM API URL, so
every credential profile shares them. Cache entries, approval totals, quota
readings, reservations, and slot timings live in the gateway process. Each
replica keeps its own, so N replicas allow up to N times the approval cap and
can each admit queries against the same reserve; size the cap and reserve with
the replica count in mind.

## Endpoint script execution

Off by default. When on, three tools run a script from the XSIAM agent script
library on named endpoints and read the result: `list_endpoint_scripts`,
`run_endpoint_script` and `get_endpoint_script_run`. See
[Security Model](SECURITY_MODEL.md#endpoint-script-execution) for every rule.

XSIAM prerequisites:

- The API key's role needs permission to run agent scripts. Use a separate key
  through the credential broker so query-only groups keep a key without that
  permission.
- The script must already be in the tenant's script library. The gateway never
  uploads a script and never runs code passed in a request.
- Copy each script's uid from the library into `SCRIPT_RUN_ALLOWED_SCRIPTS`.
  Scripts XSIAM marks high risk are refused even when listed.
- The same key must be able to read endpoints: every endpoint id is looked up
  before approval.

A run needs all of these:

1. `SCRIPT_RUN_ENABLED=true`.
2. `TOOL_ACCESS_POLICY` grants the tool, and the principal is in a group named
   in `SCRIPT_RUN_GROUPS`. A `*` tool grant alone is not enough, and
   `SCRIPT_RUN_GROUPS` has no wildcard.
3. The engagement mode is `incident_response` or `threat_hunt`.
4. The script uid is on `SCRIPT_RUN_ALLOWED_SCRIPTS`, not high risk, and
   unchanged if it is pinned.
5. An explicit list of endpoint ids within `SCRIPT_RUN_MAX_ENDPOINTS`, every
   one known to XSIAM.
6. A stated reason and the analyst's approval, for every run.
7. Room under both daily caps.
8. A usable run ledger, when `SCRIPT_RUN_STATE_DIR` is set.

```bash
SCRIPT_RUN_ENABLED=true
SCRIPT_RUN_GROUPS=Responders
SCRIPT_RUN_ALLOWED_SCRIPTS='{"0a1b2c3d4e5f60718293a4b5c6d7e8f9":1800000000000}'
SCRIPT_RUN_STATE_DIR=/var/lib/cortex-mcp/script-state
SCRIPT_RUN_RESULTS_DIR=/var/lib/cortex-mcp/script-results
```

| Variable | Default | Description |
| --- | --- | --- |
| `SCRIPT_RUN_ENABLED` | `false` | Master switch. When false the three tools are not registered, not listed, and refused on call. |
| `SCRIPT_RUN_GROUPS` | empty | Comma-separated groups allowed to use `run_endpoint_script` and `get_endpoint_script_run`, checked in addition to `TOOL_ACCESS_POLICY`. Empty grants nobody. |
| `SCRIPT_RUN_ALLOWED_SCRIPTS` | `[]` | Scripts that may run: a JSON list of uids, or a JSON object mapping each uid to the script's `modification_date` (or `null` for no pin). Empty means nothing can run. An invalid value stops startup when the feature is on. |
| `SCRIPT_RUN_MAX_ENDPOINTS` | `30` | Endpoints per run after de-duplication; valid range 1-200. 200 is a hard ceiling. |
| `SCRIPT_RUN_DAILY_MAX_RUNS` | `5` | Runs one principal may submit per UTC day. `0` blocks every run. |
| `SCRIPT_RUN_DAILY_MAX_ENDPOINTS` | `100` | Endpoints one principal may target per UTC day, summed over runs. |
| `SCRIPT_RUN_ELICITATION_ENABLED` | `true` | Ask the analyst through MCP elicitation when the client supports it. |
| `SCRIPT_RUN_ELICITATION_TIMEOUT_SECONDS` | `120` | Time to wait for an answer before treating the prompt as unanswered. |
| `SCRIPT_RUN_MAX_OUTPUT_BYTES_PER_ENDPOINT` | `8192` | Bytes of standard output and returned values returned per endpoint. Each returned value is charged its key name and its serialised size, numbers and booleans included; a value that does not fit is omitted and counted in `returned_values_omitted`. |
| `SCRIPT_RUN_MAX_OUTPUT_BYTES` | `65536` | Bytes of script output returned per call, over all endpoints. |
| `SCRIPT_RUN_API_TIMEOUT_SECONDS` | `30` | Deadline for each XSIAM call this feature makes; valid range 1-300. |
| `SCRIPT_RUN_STATE_DIR` | empty | Absolute directory for the durable run ledger, `script_runs.json`. Same rules as `SCRIPT_RUN_RESULTS_DIR`. Empty keeps run records and daily counts in memory only. |
| `SCRIPT_RUN_RECORD_RETENTION_DAYS` | `30` | Age after which a run record is dropped; valid range 1-3650. At most 1000 records are kept, fewer when the ledger file reaches its size budget. |
| `SCRIPT_RUN_RESULTS_DIR` | empty | Absolute directory for retrieved files on the gateway host. Must not be a symbolic link, inside the repository, or inside a git working tree. Created owner-only; an existing directory open to group or others is refused. Empty disables file retrieval. |
| `SCRIPT_RUN_MAX_FILE_BYTES` | `52428800` | Largest retrieved-files zip the gateway will save. |
| `SCRIPT_RUN_ALLOW_FOREIGN_ACTIONS` | `false` | Let `get_endpoint_script_run` read any script action in the tenant, including runs started in the console. |

Limits fixed in code: script timeout 1 to 3600 seconds (default 600), at most
20 parameters, parameter strings up to 500 characters, reason up to 500
characters, files for at most 5 endpoints per call, a 300-second deadline per
file download, pending approvals kept 15 minutes (at most 256), and 50 runs per
listing.

### Approval

With elicitation the gateway asks the analyst directly; a declined prompt
refuses the run even if an `approval` argument was passed. A cancelled,
timed-out, or unsupported prompt falls back to the `approval` argument, which
must be the analyst's own typed words and is stored only as a SHA-256.

The prompt and the `approval_required` refusal show everything, with nothing
shortened: the script name and uid, every endpoint as `name (id), status`,
every parameter as `name = value` with the whole value, the timeout, and the
reason. Strings are quoted. A backslash and a double quote are escaped, and
control characters, direction overrides, zero-width and other format
characters, and unusual spaces are written as visible escapes such as `\n` or
`\u202e`, never removed. Two different values therefore never look the same,
and a value cannot start a new line in the prompt. With the largest allowed
run, 200 endpoints and 20 parameters of 500 characters, the prompt is long;
keep `SCRIPT_RUN_MAX_ENDPOINTS` at a size an analyst can read.

A typed approval is bound to exactly what was shown. It is accepted only when
this gateway process has already refused the same request with
`approval_required` for the same principal: same script uid and
`modification_date` as XSIAM reported it, same set of endpoint ids, same
parameters, same timeout, same reason. The first call is always refused, even
if it carries an approval. The pending entry is used once and expires after 15
minutes. Changing any of those needs a new refusal and a new approval.

After the approval, and immediately before the run is sent, the gateway reads
the script again. If its `modification_date` is no longer the one shown, if
XSIAM now marks it high risk, if a pin no longer matches, or if it cannot be
read, the run is refused, nothing is sent, and the attempt is not counted. This
covers a script edited while an approval prompt is open.

### Pinning a script version

An allow-listed uid names a script, not its content. To pin the reviewed
version, use the object form and copy `modification_date` from
`list_endpoint_scripts`:

```bash
SCRIPT_RUN_ALLOWED_SCRIPTS='{"0a1b2c3d4e5f60718293a4b5c6d7e8f9":1800000000000}'
```

In a shell, keep the single quotes: without them the shell removes the inner
double quotes and the value is no longer JSON. In a `.env` file read by the
gateway or passed with `docker --env-file`, write the JSON without surrounding
quotes, as `.env.example` does.

If XSIAM later reports a different date, or none, the run is refused with rule
`script_changed` until an operator reviews the script and updates the pin.

### Run ledger

A script action can take days to finish: offline endpoints pick it up when
they reconnect. Set `SCRIPT_RUN_STATE_DIR` so the gateway still knows its runs
after a restart.

With the directory set, one file, `script_runs.json`, holds every run record
(action id, a hash of the owner, script uid and name, endpoint ids and names,
start time, approval method, request hash) and each principal's daily counts.
The daily caps then hold across restarts. The run is counted and saved before
the request goes to XSIAM, and the action id is added after the reply. The file
is replaced atomically, owner-only, and never holds parameter values, the
approval text, or the reason.

The file stays under a 6 MiB write budget, below the 8 MiB the gateway will
read back, so the gateway never writes a ledger it would then refuse. Stored
script and endpoint names are cut at 128 characters. When the budget is
reached, the oldest records that already have an action id are dropped first.
Daily counts are always kept, and a run still waiting for XSIAM's answer is
never dropped. If the ledger still cannot fit, the write fails and the run is
refused before anything is sent.

The gateway fails closed. If the directory is invalid, or the file is
unreadable, malformed, a symbolic link, or open to group or others, new runs
are refused with rule `state_unavailable`, and so are listing and reads of
actions the process does not already hold. The message says why. An operator
must repair or remove the file. If the action id cannot be saved after a
successful submit, the action id is still returned with a warning.

With the directory empty, records and counts live in memory only. A restart
loses the records and resets the daily caps, so the caps can be bypassed by
restarting the gateway. Earlier runs stay visible in the XSIAM Action Center.

`get_endpoint_script_run` with no `action_id` lists the caller's own recorded
runs, newest first, at most 50. A run whose outcome is unknown is listed
without an action id.

The ledger file belongs to one gateway process. Do not point two replicas at
the same directory: give each its own, or use a shared store. Each replica
keeps its own counts, so N replicas allow up to N times the daily caps.

### Timeouts and submission outcome

Every XSIAM call the feature makes has its own deadline,
`SCRIPT_RUN_API_TIMEOUT_SECONDS`. A script or endpoint lookup that does not
answer refuses the run.

Once `run_script` has been sent, the run is reported as not executed
(`executed: false`) only when XSIAM's own response says so:

- a 4xx reply, including authentication and permission errors;
- a well-formed reply that reports failure and names no action.

The record is then removed. Everything else is reported as submitted with
outcome unknown (`executed: "unknown"`), because the action may be running:

- no answer before the deadline, or a lost connection;
- any 5xx, which a proxy can return after XSIAM started the action;
- a reply that cannot be decoded, or that names no action without reporting
  failure;
- a reply that names an action and also reports failure. The action id is
  kept and returned.

An unknown outcome keeps its record, without an action id unless XSIAM gave
one, so it stays in the caller's run list. The analyst should check the Action
Center before submitting again. Either way the attempt counts against the
daily caps.

## XSIAM Credential Broker

The gateway does not dynamically create per-user XSIAM API keys. Instead, set
up role-scoped XSIAM API keys in advance and reference their environment
variable names:

```bash
export XSIAM_CREDENTIAL_BROKER_ENABLED=true
export XSIAM_CREDENTIAL_PROFILES='{
  "Tier1": {
    "priority": 10,
    "profile_name": "tier1-readonly",
    "api_key_env": "XSIAM_T1_KEY",
    "api_key_id_env": "XSIAM_T1_KEY_ID"
  },
  "Security": {
    "profile_name": "security-analyst",
    "api_key_env": "XSIAM_SEC_KEY",
    "api_key_id_env": "XSIAM_SEC_KEY_ID"
  }
}'
```

Inject the key values at start from your secret manager or credential store
(see [Secrets And API Keys](SECRETS.md)), with 1Password that is one `op://`
line per variable in `.env.op`.
If the broker is enabled and no profile matches the verified principal, tool
execution fails closed. When several groups match, the lowest numeric
`priority` wins; group claim order is not trusted as authorization policy.

## Audit Logging

| Variable | Default | Description |
| --- | --- | --- |
| `AUDIT_LOG_ENABLED` | `true` | Emit structured audit events for tool calls. |
| `AUDIT_LOG_EMIT_START_EVENTS` | `true` | Emit a start event before the tool runs. |
| `AUDIT_LOG_INCLUDE_QUERY_TEXT` | `false` | Include raw XQL query text instead of hashes only. |
| `AUDIT_LOG_FAIL_CLOSED` | `false` | Fail tool calls if audit export fails. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED` | `false` | Forward audit events to a Cortex XSIAM HTTP Log Collector. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_URL` | empty | Collector URL, for example `https://api-tenant/logs/v1/event`. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY` | empty | HTTP collector API key. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_TIMEOUT_SECONDS` | `10` | Export timeout. |

Keep `AUDIT_LOG_INCLUDE_QUERY_TEXT=false` unless full query retention has been
approved. Query hashes are logged by default.

## Tenant Pack And Learning

Learning runs in two processes: gateway observers append to a journal, and the
learner (`python -m learner`, run by a timer) is the single writer of fact files.
See [Learning](LEARNING.md) for the design, schedules and deployment.

| Variable | Default | Description |
| --- | --- | --- |
| `TENANT_PACK_DIR` | empty | Absolute path of the private tenant pack, outside the repository. Empty disables learning. |
| `LEARNING_ENABLED` | `true` | Kill switch: `false` stops the observers and the learner. Revert requests are still accepted. |
| `LEARNING_SCHEMA_TTL_DAYS` | `30` | Expiry of schema, enum and absent-field facts without a confirmation. |
| `LEARNING_COST_TTL_DAYS` | `90` | Expiry of cost, timing and helper-usage facts without a confirmation. |
| `LEARNING_MAX_ENTRIES_PER_KIND` | `5000` | Cap per fact kind; new entries beyond it are refused, not evicted. |
| `LEARNING_COST_MIN_OBSERVATIONS` | `3` | Observations before the cost guard hook returns a learned cost. |
| `LEARNING_ADMIN_GROUPS` | `Admin` | Groups allowed to revert, pin or unpin facts with `revert_learned`, independent of `TOOL_ACCESS_POLICY`. |
| `LEARNING_VERIFY_MIN_CONFIRMATIONS` | `5` | Confirmations since the last contradiction before a fact is verified automatically. |
| `LEARNING_VERIFY_MIN_ENGAGEMENTS` | `3` | Distinct engagements those confirmations must come from. |
| `LEARNING_VERIFY_MIN_DAYS` | `7` | Days the confirmations must span. |
| `LEARNING_JOURNAL_MAX_BYTES` | `67108864` | Largest journal file per gateway process per day. |
| `LEARNING_RESULT_CACHE_ENABLED` | `false` | Cache bounded results of a case's tool calls for replay. Cached rows are tenant data. |
| `LEARNING_RESULT_MAX_BYTES` | `262144` | Largest single tool result kept in the replay cache. |
| `LEARNING_RESULT_CACHE_MAX_BYTES` | `5242880` | Replay cache size per case. |
| `LEARNER_PRINCIPAL_ID` | `learning-service` | Principal the learner queries XSIAM as. |
| `LEARNER_GROUPS` | `learner` | Groups of the learner principal for dataset policy, tool policy and the credential broker. |
| `LEARNER_DAILY_UNIT_CAP` | `0.5` | Units the learner may spend per UTC day. |
| `LEARNER_RESERVE_UNITS` | `20` | The learner skips queries when remaining units are below this; keep it equal to the cost guard's automation reserve. |
| `LEARNER_DAILY_QUOTA_UNITS` | `0` | Daily units for the reserve check; `0` derives them from the annual licence quota. |
| `LEARNER_ENGAGEMENT_CLOSE_SLA_MINUTES` | `15` | Closed engagements should be processed within this; run the learner at least this often. |
| `LEARNER_ENGAGEMENT_IDLE_HOURS` | `24` | Inactivity after which an open engagement is processed. |
| `LEARNER_NIGHTLY_UTC` | `13:30` | Nightly expiry and cost recalibration, `HH:MM` UTC. |
| `LEARNER_WEEKLY_UTC` | `MON 20:00` | Weekly digest, replay scoring and step mining, weekday and `HH:MM` UTC. |
| `LEARNER_RECALIBRATION_MAX_IDS` | `100` | Query ids looked up in `xql_query_center_history` per night. |

The default `TOOL_ACCESS_POLICY` grants `get_learned_facts` to `SOC` and `Tier1`;
`learning_digest` and `revert_learned` are reached only through `*` grants. It
also grants the `learner` group `query_dataset` and `discover_log_fields`, and the
default `LOG_SEARCH_DATASET_POLICY` grants `learner` only
`xql_query_center_history`. Members of `LEARNING_ADMIN_GROUPS` also need a dataset
policy that covers the facts they revert.

## Example `.env`

Non-secret settings only, the key, key id and cursor secret are injected at
start (see [Secrets And API Keys](SECRETS.md)).

```bash
CORTEX_MCP_PAPI_URL=https://api-your-xsiam-tenant.example
# CORTEX_MCP_PAPI_AUTH_HEADER and CORTEX_MCP_PAPI_AUTH_ID: injected at start,
# never written here.
MCP_TRANSPORT=streamable-http
MCP_IDENTITY_AUTH_MODE=entra
ENTRA_TENANT_ID=replace-with-tenant-id
ENTRA_AUDIENCE=api://your-mcp-app-registration
LOG_SEARCH_DATASET_POLICY={"Security":["*"],"Tier1":["xdr_data"]}
TOOL_ACCESS_POLICY={"Security":["*"],"Tier1":["get_dataset_query_guidance","find_datasets","resolve_entity","firewall_traffic","firewall_verdict","entity_activity","dataset_health","threat_intel_lookup","coverage_gap","list_log_datasets","discover_log_fields","query_dataset","continue_dataset_query","set_engagement","get_engagement","record_fact","get_engagement_log"]}
RAW_XQL_PRIVILEGED_GROUPS=Security,Admin
ENGAGEMENT_STORE_DIR=/var/lib/cortex-mcp/engagements
# DATASET_QUERY_CURSOR_SECRET: a long random value, injected the same way.
AUDIT_LOG_ENABLED=true
AUDIT_LOG_XSIAM_HTTP_COLLECTOR_ENABLED=false
```

## Production Notes

- Inject API credentials at start from a secret manager or credential store,
  see [Secrets And API Keys](SECRETS.md).
- Rotate API keys regularly.
- Use separate credentials for development and production tenants.
- Use role-scoped XSIAM API keys through the credential broker for shared HTTP
  deployments.
- Do not expose HTTP transport without incoming authentication.
- Keep audit logging enabled for security testing and production pilots.
- Export audit events to Cortex XSIAM or another durable SIEM/log system.
- An AI gateway such as Portkey or LiteLLM is optional. Use one when it is part
  of your enterprise AI control plane; otherwise validate Entra ID tokens
  directly in the MCP server.
