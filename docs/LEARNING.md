# Learning

The gateway improves from its own use without anyone merging a diff. It does this
in three tiers, each with a different approver. This release implements tier 1
and the replay foundation for tier 2. Tier 3 is ordinary configuration and stays
human.

## Tiers

| Tier | What changes | Approver | Status |
| --- | --- | --- | --- |
| 1. Measured facts | Per-dataset schema as this tenant has it, enum-like fields that only match with `contains`, fields XSIAM reports as unknown, a cost table of observed compute units, tool timings, helper usage. | Automatic, with evidence, confidence, expiry, audit and revert. | Implemented. |
| 2. Behaviour | Skill step order, candidate playbooks, validator rewrite rules, thresholds inside human-set bounds. | Replay of recorded engagements against the result cache at zero quota, with automatic rollback when live results underperform. | Foundation only: result cache and `replay_engagement`. No behaviour is changed automatically yet. |
| 3. Policy | Dataset and tool allowlists, caps, reserves, enforced modes, tuning bounds, admin groups. | Always a human, through configuration. | Unchanged. |

## What is automatic and what is not

Automatic, while `LEARNING_ENABLED=true` and `TENANT_PACK_DIR` is set:

- recording tier-1 facts from queries the gateway already runs (no extra quota);
- confirming, demoting, promoting and expiring those facts;
- caching the bounded result of each query-running tool call for an engagement
  that has a case id;
- serving facts to agents with a trust label.

Never automatic:

- any change to policy, allowlists, caps, reserves or admin groups;
- marking a fact `verified` (only a human note does that);
- reverting a fact (only a member of `LEARNING_ADMIN_GROUPS` can);
- changing gateway code, prompts or skills, or calling a model (the gateway
  calls no model);
- spending quota to learn: observers read only what a query already returned.

## Tenant pack layout

```text
<TENANT_PACK_DIR>/
  notes/                         human-written notes; may verify facts
  learned/                       machine-written tier-1 facts
    schema.json
    enum_fields.json
    absent_fields.json
    cost_table.json
    timings.json
    helper_usage.json
    changes.jsonl                lifecycle history read by learning_digest
  engagements/
    .gitignore                   keeps cached results out of the pack's history
    <case_id>/results/
      manifest.json              steps, query ids, units, fact links
      0000.json ...              bounded results the gateway returned
```

`TENANT_PACK_DIR` must be an absolute path outside the gateway repository. The
pack may have its own local git history; the gateway writes a `.gitignore` so
cached results are not committed to it. Directories are created `0700` and
files `0600`; symbolic links inside the pack are refused.

## Entry format

Every entry carries its provenance. Values below are synthetic.

```json
{
  "entry_id": "enm-3f1c0a9b2d4e6f8a1b2c",
  "kind": "enum_fields",
  "dataset": "alerts",
  "fact": {"field": "alert_source", "operator": "contains"},
  "evidence": ["synthetic_query_1", "synthetic_query_2"],
  "first_seen": "2026-10-01T09:00:00+00:00",
  "last_seen": "2026-10-03T14:12:00+00:00",
  "confirmations": 3,
  "contradictions": 0,
  "streak": 3,
  "confidence": 0.875,
  "expires_at": "2026-11-02T14:12:00+00:00",
  "source_class": "query_pair_outcome",
  "status": "active",
  "status_changed_at": "2026-10-01T09:00:00+00:00"
}
```

Entry ids are derived from the kind and the fact key (dataset and field, or
dataset, window and selectivity, or tool), so repeated observations of the same
fact accumulate on one entry.

## Observers

| Kind | Source class | Observed from | Evidence |
| --- | --- | --- | --- |
| `cost_table` | `query_metadata` | Every executed query: dataset (`dataset = X` only), window bucket, selectivity class, and units from `query_cost`, or the drop in `remaining_quota` since the previous query on the same credential profile. Queries with `join`, `union` or `call` are skipped. | The query id. |
| `schema` | `field_discovery_sample` | `discover_log_fields`: field names and inferred value types of the sample. `null` values are ignored; several types record `mixed`. | The discovery query id. |
| `absent_fields` | `query_error_class` | A failed query whose XSIAM error is classified `unknown_field`, when the field is read straight from the dataset (no `alter`, `comp`, `join` or similar stage before it). Demotes any `schema` fact for that field. | The failed query id. |
| `enum_fields` | `query_pair_outcome` | An equality filter on a string literal that returns no rows, followed in the same engagement by the identical query with `contains` on the same value and window that returns rows. A later equality filter on the field that returns rows demotes the fact. | Both query ids. |
| `helper_usage` | `tool_call_outcome` | Each tool call that ran at least one query: calls, successes, errors, queries. | The call's query ids. |
| `timings` | `tool_step_timing` | Duration of each query-running tool call, and the gap between consecutive query-running steps of one engagement (`step_gap_ms`, keyed by the previous and current tool). | The call's query ids; for gaps, the last id of the previous step and the first of this one. |

Window buckets: `le_1h`, `le_6h`, `le_24h`, `le_7d`, `le_30d`, `gt_30d`,
`unspecified` (no timeframe). Selectivity classes: `sample` (no filter or
aggregation), `unfiltered` (aggregation without filters), `filtered` (filters,
none an equality or `in` list), `selective` (at least one equality or `in` list).

An engagement is the case when the engagement module (`usecase.engagement`)
supplies a case id, otherwise the MCP session, always per principal.

## Forgery guard

Learned facts are read by agents, so they must not be writable from tenant data.

- Observers never read result cell values. They read the query the gateway
  submitted, response metadata (`query_id`, `query_cost`, `remaining_quota`,
  `number_of_results`), row counts, field names and value types, tool names and
  timings.
- Filter literals used to pair an equality query with a `contains` query are
  held only as SHA-256 hashes, in memory, for one hour. They are never written.
- Evidence must be query ids that XSIAM returned to this gateway process. An
  observation citing any other string is refused.
- Every string in an entry is an enumerated token, an identifier of at most 64
  characters (`[A-Za-z_][A-Za-z0-9_.]*`), or a query id. Unknown keys, free text,
  whitespace and over-long values are refused on write, and an entry in a file
  that fails the same checks is ignored on read.
- An XSIAM error message is classified `unknown_field` only when the field it
  names already appears in the submitted query outside string literals, so an
  error message cannot introduce a new name.
- `source_class` is one of the six classes above; there is no free-form source.

Field names are still identifiers chosen by whoever controls a log source, so
served facts carry `content_trust: "measured_metadata"` and guidance that field
names are not instructions.

## Lifecycle

- **Confirmation**: the same fact observed again. `confirmations` and `streak`
  rise; `confidence = 1 - 0.5^streak`, capped at 0.99. `expires_at` moves out.
- **Contradiction**: a different value for the same key (a new type for a field),
  a negative observation (an equality match on an enum-like field, a discovered
  field that was recorded absent), or a cost more than four times the recent
  maximum after three observations. The entry is demoted immediately:
  `status=demoted`, `confidence=0`, not served, not used by hooks. A changed
  value replaces the old one, which is kept as `previous_fact`.
- **Promotion**: a demoted entry returns to `active` after two consecutive
  confirmations.
- **Expiry**: an entry with no confirmation for `LEARNING_SCHEMA_TTL_DAYS`
  (schema, enum and absent-field facts; default 30) or `LEARNING_COST_TTL_DAYS`
  (cost, timing and helper facts; default 90) is hidden at once and removed by
  the next write to that kind or by `learning_digest`.
- **Revert**: a human removes a fact. It becomes a tombstone that is not served
  and is not re-learned until it expires.
- **Capacity**: at `LEARNING_MAX_ENTRIES_PER_KIND` new entries are refused rather
  than evicting existing ones, so a flood of new names cannot push out
  established facts.

## Serving

`get_learned_facts(kind, dataset=None)` and the resource
`tenant://learned/{kind}` return active, unexpired entries, filtered by
`LOG_SEARCH_DATASET_POLICY`. Facts not tied to a dataset (timings, helper usage)
are visible to anyone allowed the tool. The resource requires the same
`get_learned_facts` tool permission and emits a `read` audit event.

Each entry has a trust label:

- `{"label": "learned", "confirmations": N}`;
- `{"label": "verified", "note": "notes/<file>.md", "confirmations": N}` when a
  human note verifies it.

A human verifies a fact with a line in any Markdown file under `notes/`:

```text
verified: enm-3f1c0a9b2d4e6f8a1b2c
verified: enum_fields alerts alert_source
```

The second form names the kind, dataset and field. Note file names must be plain
paths (letters, digits, `_`, `.`, `-`, `/`); others are ignored.

## Digest and revert

`learning_digest(days=7)` lists what was learned, promoted, demoted, expired and
reverted in the window, newest first, each with its fact, evidence query ids,
counts and, for learned, promoted and demoted entries, a
`revert_with: {"tool": "revert_learned", "entry_id": ...}` hint. It also counts
entries confirmed in the window per kind. It is filtered by dataset policy and
first sweeps expired entries (an audited write, skipped while learning is
frozen). Run it weekly; the default tool policy grants it to `Admin` and
`Security`.

`revert_learned(entry_id)` is restricted to `LEARNING_ADMIN_GROUPS` (default
`Admin`) regardless of tool policy, and to datasets the caller's dataset policy
allows. It works while learning is frozen, so an operator can freeze learning
and then clean up.

## Kill switch

`LEARNING_ENABLED=false` freezes every automatic write: observations,
promotions, demotions, expiry sweeps and the result cache. Served facts stay
readable (expired ones are still hidden) and human reverts still work. Learning
with no `TENANT_PACK_DIR` is a no-op.

## Audit

Every write to the learned store emits one `cortex_xsiam_mcp.learning` event
before it is committed. If export fails under `AUDIT_LOG_FAIL_CLOSED=true`,
nothing is written. Operations: `observe`, `expire`, `revert`, `cache_result`
and `read`. Each `changes` item names the entry, kind, dataset, action
(`learned`, `confirmed`, `promoted`, `demoted`, `expired`, `reverted`), fact,
evidence and counts. See [Audit Logging](AUDIT_LOGGING.md).

## Hooks for other components

These are plain functions in `src/usecase/learned_store.py`; callers import them
lazily so the gateway runs without them.

| Caller | Function | Use |
| --- | --- | --- |
| Cost guard | `lookup_cost(dataset, window_bucket, selectivity)` | Read before the seed table. Returns `median_units`, `high_units` (maximum of the last 20 samples), `observations`, `confidence`, or `None` below `LEARNING_COST_MIN_OBSERVATIONS`. Use `high_units` and keep the seed band's lower bound as a floor. Bucket and class come from `learning_observers.window_bucket(window_ms(...))` and `selectivity_class(parse_xql(query))`. |
| XQL validator | `learned_enum_fields(dataset)`, `learned_absent_fields(dataset)` | Suggest `contains` for enum-like fields; reject or warn on fields XSIAM reported unknown. |
| Field cache | `learning_observers.observe_field_catalog(ctx, dataset=..., fields=..., query_id=...)` | Call after any field-cache fill with the sample's query id. |

Demoted, reverted and expired entries never reach these hooks.

## Replay foundation

While an engagement has a case id, each query-running tool call is recorded in
`engagements/<case_id>/results/`: the tool, a SHA-256 of its arguments, argument
names (not values), query ids, units, duration, outcome, and the bounded result
the gateway already returned (continuation cursors removed). Results are capped
by `LEARNING_RESULT_MAX_BYTES` each and `LEARNING_RESULT_CACHE_MAX_BYTES` per
case. Successful `record_fact` calls add a link from the fact key to its
evidence query id; fact values are not copied.

`usecase.replay.replay_engagement(case_id, candidate=None)` re-runs the recorded
sequence, or a candidate list of `{"tool", "arguments"}` (or
`{"tool", "arguments_sha256"}`) steps, against the cache and reports steps, cache
hits and misses, queries, units and the engagement facts reached and missed,
with the recorded sequence as a baseline. It never calls XSIAM. It is a Python
function for the tier-2 approval process, not an MCP tool, so agents cannot read
cached results through it.

`tests/agent_eval/cases.json` includes `ioc_flood_triage`, a synthetic IOC-flood
case that gives the planning agent learned enum and absent-field facts and
checks that it uses `contains` and avoids absent fields.

## Settings

| Variable | Default | Description |
| --- | --- | --- |
| `TENANT_PACK_DIR` | empty | Absolute path of the tenant pack, outside the repository. Empty disables learning and the result cache. |
| `LEARNING_ENABLED` | `true` | Kill switch. `false` freezes every automatic write. |
| `LEARNING_SCHEMA_TTL_DAYS` | `30` | Expiry of schema, enum and absent-field facts without confirmation. |
| `LEARNING_COST_TTL_DAYS` | `90` | Expiry of cost, timing and helper facts without confirmation. |
| `LEARNING_MAX_ENTRIES_PER_KIND` | `5000` | Cap per fact kind; new entries beyond it are refused. |
| `LEARNING_COST_MIN_OBSERVATIONS` | `3` | Observations before `lookup_cost` returns a learned cost. |
| `LEARNING_ADMIN_GROUPS` | `Admin` | Groups allowed to call `revert_learned`. |
| `LEARNING_RESULT_MAX_BYTES` | `262144` | Largest single result kept in the replay cache. |
| `LEARNING_RESULT_CACHE_MAX_BYTES` | `5242880` | Cache size per case. |

## Limits

- The enum detector is a heuristic: a `contains` match on a value that an
  equality filter missed can also mean the value is a substring of real values.
  The confirmation count, the contradiction rule and expiry bound the damage;
  a human note is the stronger signal.
- `remaining_quota` deltas are approximate when queries overlap or other
  clients share the quota; such samples are marked `remaining_quota_delta`.
- Unknown-field classification relies on XSIAM error wording; a message it does
  not recognise simply produces no fact.
- State is per process: the issued-query-id registry and the enum pairing memory
  are not shared across replicas. Files are locked across processes.
- Tool calls that run no query produce no helper or timing facts, because every
  fact needs query-id evidence.
