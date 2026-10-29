# Learning

The gateway improves from its own use without anyone merging a diff. It does this
in three tiers, each with a different approver. This release implements tier 1
and the replay foundation for tier 2. Tier 3 is ordinary configuration and stays
human.

## Tiers

| Tier | What changes | Approver | Status |
| --- | --- | --- | --- |
| 1. Measured facts | Per-dataset schema as this tenant has it, enum-like fields that only match with `contains`, fields XSIAM reports as unknown, a cost table of observed compute units, tool timings, helper usage. | Automatic, including verification, with evidence, confidence, expiry and audit. Humans may pin or revert. | Implemented. |
| 2. Behaviour | Skill step order, candidate playbooks, validator rewrite rules, thresholds inside human-set bounds. | Replay of recorded engagements against the result cache at zero quota, with automatic rollback when live results underperform. | Foundation only: result cache, `replay_engagement`, weekly replay scores, step-sequence mining and a deploy canary. No behaviour changes automatically yet. |
| 3. Policy | Dataset and tool allowlists, caps, reserves, enforced modes, tuning bounds, admin groups. | Always a human, through configuration. | Unchanged. |

## Two processes

```text
  MCP clients
      |
      v
 +-----------------------+      append only, per process      +---------------------------+
 | gateway (1..n)        | ---------------------------------> | <pack>/learned/journal/   |
 |  observers            |   events-<date>-<host>-<pid>.jsonl | (owner-only, git-ignored) |
 |  get_learned_facts    |   admin-<date>-<host>-<pid>.jsonl  +-------------+-------------+
 |  learning_digest      |                                                  |
 |  revert_learned       | <-- reads fact files ----+                       | folds in
 +-----------------------+                          |                       v
                                          +---------+----------+   +------------------+
                                          | <pack>/learned/    |<--| learner          |
                                          |  <kind>.json       |   | python -m learner|
                                          |  changes.jsonl     |   | (timer or cron)  |
                                          |  digests/          |   +--------+---------+
                                          +--------------------+            |
                                          | <pack>/engagements/|<-----------+ replay cache
                                          +--------------------+
```

**Gateway.** Observers inside the gateway only append to a JSONL journal under
`<TENANT_PACK_DIR>/learned/journal/`. They validate a record, queue it in memory
and return; a background task writes the queue to disk, off the event loop,
after the tool result has been returned. A journal error is logged and the record
dropped: it never blocks or fails a call. Each gateway process writes its own
files, named by stream, UTC date, a hash of the host name and the process id, so
replicas never share a file.

**Learner.** A second entry point in this codebase, `python -m learner`, run by a
system timer or container cron. It is the single writer of the fact files: every
run takes the learned-store lock (an in-process lock plus a non-blocking `flock`),
reads the new part of every journal file, applies it, audits the result, commits,
and then records how far it read. Several gateway replicas therefore produce one
consistent set of facts. A journal file that is a symbolic link or writable by
group or others is ignored.

## Schedules

All times are UTC and are settings.

| Job | When | Setting (default) | What it does |
| --- | --- | --- | --- |
| Fold the journal | Every learner run | Timer cadence | Apply observations, admin requests (revert, pin, unpin), fact links and tool steps; verify facts that meet the thresholds; write the replay cache. Cost samples measured from a drop in remaining quota are held for nightly recalibration. |
| Engagement close | Within the SLA of an engagement closing, or after it has been idle | `LEARNER_ENGAGEMENT_CLOSE_SLA_MINUTES` (`15`), `LEARNER_ENGAGEMENT_IDLE_HOURS` (`24`) | Derive helper usage, tool durations, gaps between steps and step sequences from the engagement's steps. A close processed later than the SLA is reported as `late`. |
| Nightly | Daily | `LEARNER_NIGHTLY_UTC` (`13:30`) | Expire entries; recalibrate held cost samples from `xql_query_center_history`. |
| Weekly | Weekly | `LEARNER_WEEKLY_UTC` (`MON 20:00`) | Write `learned/digests/<date>.json`; score a replay of each engagement recorded in the week; list the most frequent step sequences. |
| Canary | On every deploy | `python -m learner canary` | Replay every scored engagement; exit 1 if one now reaches fewer cache hits or facts than its score. |
| Agent evaluation | CI only | `scripts/evaluate_agent_plans.py` | The synthetic cases in `tests/agent_eval/cases.json` run in CI, never against the tenant. |

`tick` folds the journal and runs the nightly and weekly jobs when their last
scheduled time has passed since they last ran. The first run only records the
schedule baseline, so installing the learner does not trigger every job at once.
Run `tick` at least as often as the close SLA: every 5 minutes is a good default.

## Running the learner

```bash
PYTHONPATH=/app/src python -m learner tick
```

Commands: `tick` (default), `nightly`, `weekly`, `canary`, `status`. Each prints
one JSON report. Exit codes: `0` success or skipped, `1` canary regression, `2`
error (for example an audit export failure under fail-closed, an unreadable
state file, or an invalid schedule setting).

A systemd timer:

```ini
# /etc/systemd/system/cortex-xsiam-learner.service
[Service]
Type=oneshot
User=mcpuser
EnvironmentFile=/etc/cortex-xsiam-mcp/gateway.env
Environment=PYTHONPATH=/app/src
ExecStart=/usr/bin/python3 -m learner tick

# /etc/systemd/system/cortex-xsiam-learner.timer
[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
```

A container cron runs the gateway image with the same environment and
`python -m learner tick` as the command, every 5 minutes, with the tenant pack
mounted at the same path as the gateway's. Run `python -m learner canary` as a
deploy step after the new image is rolled out.

The learner and gateways must share the pack directory and run as the same user,
or as users in a group that does not grant write access to others' journal files.

## Learner principal and quota

The learner reaches XSIAM only for nightly recalibration, in-process, as the
principal `LEARNER_PRINCIPAL_ID` (`learning-service`) in the groups
`LEARNER_GROUPS` (`learner`). It goes through the gateway's normal query path:

- dataset policy: the default `LOG_SEARCH_DATASET_POLICY` gives `learner` only
  `xql_query_center_history`;
- tool policy: the default `TOOL_ACCESS_POLICY` gives `learner` only
  `query_dataset` and `discover_log_fields`; the learner checks it before each
  query;
- credentials: with the credential broker enabled, map the `learner` group to a
  read-only profile; otherwise the gateway's own key is used;
- audit: each query emits a `cortex_xsiam_mcp.tool_invocation` event for the
  learner principal, and each run a `cortex_xsiam_mcp.learning` event;
- spend: at most `LEARNER_DAILY_UNIT_CAP` (`0.5`) units per UTC day, recorded in
  `learned/learner_spend.json` and checked before each query; a query whose cost
  is not reported counts as the rest of the day's cap;
- reserve: before querying, the learner reads `get_quota` (no cost) and skips
  when remaining units are below `LEARNER_RESERVE_UNITS` (`20`, keep it equal to
  the cost guard's automation reserve). Daily remaining units are
  `LEARNER_DAILY_QUOTA_UNITS`, or the annual licence quota divided by 365 when
  that is `0`.

When recalibration is skipped (`not_authorized`, `daily_cap`, `below_reserve`,
`quota_unknown`, `query_failed`), the held samples are applied with their
remaining-quota delta, so no measurement is lost. Recalibration matches
`execution_id` in the history to the query id the gateway received; samples with
no match also keep their delta.

The service principal is set through a context variable that only in-process code
can set; no MCP request reaches it.

## What is automatic and what is not

Automatic, while `LEARNING_ENABLED=true` and `TENANT_PACK_DIR` is set:

- journalling observations from queries the gateway already runs (no extra quota);
- folding the journal into facts; confirming, demoting, promoting, verifying and
  expiring them;
- recalibrating cost samples within the learner's cap and the reserve;
- writing the weekly digest and replay scores;
- caching bounded results of a case's tool calls, when
  `LEARNING_RESULT_CACHE_ENABLED=true`;
- serving facts to agents with a trust label.

Never automatic:

- any change to policy, allowlists, caps, reserves or admin groups;
- pinning, unpinning or reverting a fact (only a member of `LEARNING_ADMIN_GROUPS`
  can; no human step is needed for verification);
- changing gateway code, prompts or skills, or calling a model (the gateway and
  the learner call no model);
- quota spent to learn, beyond the learner's nightly history query under its cap.

## Tenant pack layout

```text
<TENANT_PACK_DIR>/
  notes/                         human-written notes (not read by learning)
  learned/
    .gitignore                   journal, lock and learner state stay out of the pack's history
    schema.json                  fact files, written only by the learner
    enum_fields.json
    absent_fields.json
    cost_table.json
    timings.json
    helper_usage.json
    changes.jsonl                lifecycle history read by learning_digest
    digests/<date>.json          weekly digest
    journal/                     gateway journal files (pruned two days after they are read)
    learner_state.json           read offsets, open engagements, held samples, replay scores
    learner_spend.json           the learner's units for the current UTC day
  engagements/
    .gitignore                   keeps cached results out of the pack's history
    <case_id>/results/
      manifest.json              steps, query ids, units, fact links
      0000.json ...              bounded results the gateway returned
```

`TENANT_PACK_DIR` must be an absolute path outside the gateway repository.
Directories below it are kept `0700` and files `0600`; symbolic links inside the
pack are refused.

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

Entry ids derive from the kind and the fact key (dataset and field, or dataset,
window and selectivity, or tool), so repeated observations of the same fact
accumulate on one entry.

## Observations

| Kind | Source class | Observed in the gateway from | Applied by the learner |
| --- | --- | --- | --- |
| `cost_table` | `query_metadata` | Every executed query: dataset (`dataset = X` only), window bucket, selectivity class, and units from `query_cost`, or the drop in `remaining_quota` since the previous query on the same credential profile. Queries with `join`, `union` or `call` are skipped. | `query_cost` samples on the next run; quota-drop samples at nightly recalibration, with history units when found (`units_source: query_history`). |
| `schema` | `field_discovery_sample` | `discover_log_fields`: field names and inferred value types of the sample. `null` values are ignored; several types record `mixed`. | Next run. |
| `absent_fields` | `query_error_class` | A failed query whose XSIAM error is classified `unknown_field`, when the field is read straight from the dataset (no `alter`, `comp`, `join` or similar stage before it). Demotes any `schema` fact for that field. | Next run. |
| `enum_fields` | `query_pair_outcome` | An equality filter on a string literal that returns no rows, followed in the same engagement and process by the identical query with `contains` on the same value and window that returns rows. An equality filter on the field that returns rows demotes the fact. | Next run. |
| `helper_usage` | `tool_call_outcome` | A step record for each tool call that ran at least one query. | When the engagement closes or goes idle: calls, successes, errors, queries per tool. |
| `timings` | `tool_step_timing` | The same step records (start, end, duration). | When the engagement closes or goes idle: tool durations, and gaps between consecutive query-running steps keyed by previous and current tool. |

Window buckets: `le_1h`, `le_6h`, `le_24h`, `le_7d`, `le_30d`, `gt_30d`,
`unspecified` (no timeframe). Selectivity classes: `sample` (no filter or
aggregation), `unfiltered` (aggregation without filters), `filtered` (filters,
none an equality or `in` list), `selective` (at least one equality or `in` list).

An engagement is the case when the engagement module (`usecase.engagement`)
supplies a case id, otherwise the MCP session, always per principal. The
engagement module can mark one closed with
`learning_journal.journal_engagement_closed(engagement_key=..., case_id=...)`.

## Forgery guard

Learned facts are read by agents, so they must not be writable from tenant data.

- Observers never read result cell values. They read the query the gateway
  submitted, response metadata (`query_id`, `query_cost`, `remaining_quota`,
  `number_of_results`), row counts, field names and value types, tool names and
  timings.
- Filter literals used to pair an equality query with a `contains` query are
  held only as SHA-256 hashes, in memory, for one hour. They are never written to
  the journal, the facts or audit events.
- Evidence must be query ids that XSIAM returned to the gateway process that
  journals them; anything else is refused before it reaches the journal.
- Every string in an entry is an enumerated token, an identifier of at most 64
  characters (`[A-Za-z_][A-Za-z0-9_.]*`), or a query id. Field names that read as
  instructions (for example built from words such as "ignore", "instructions",
  or two of "previous", "prompt", "system", "override") are refused.
- The gateway validates each observation before journalling it and the learner
  validates every journal record again, so a hand-written journal line or a
  hand-edited fact file with free text is ignored.
- An XSIAM error message is classified `unknown_field` only when the field it
  names already appears in the submitted query outside string literals.
- `source_class` is one of six classes; there is no free-form source.

Served facts carry `content_trust: "measured_metadata"` and guidance that field
names are identifiers, not instructions.

## Lifecycle

- **Confirmation**: the same fact observed again. `confirmations` and `streak`
  rise; `confidence = 1 - 0.5^streak`, capped at 0.99. `expires_at` moves out.
- **Contradiction**: a different value for the same key (a new type for a field),
  a negative observation (an equality match on an enum-like field, a discovered
  field that was recorded absent), or a cost more than four times the recent
  maximum after three observations. The entry is demoted on the learner's next
  run: `status=demoted`, `confidence=0`, not served, not used by hooks. A changed
  value replaces the old one, which is kept as `previous_fact`.
- **Promotion**: a demoted entry returns to `active` after two consecutive
  confirmations.
- **Expiry**: an entry with no confirmation for `LEARNING_SCHEMA_TTL_DAYS`
  (schema, enum and absent-field facts; default 30) or `LEARNING_COST_TTL_DAYS`
  (cost, timing and helper facts; default 90) is hidden at once and removed by
  the nightly job.
- **Verification**: automatic. A fact becomes `verified` when it has at least
  `LEARNING_VERIFY_MIN_CONFIRMATIONS` (5) confirmations across at least
  `LEARNING_VERIFY_MIN_ENGAGEMENTS` (3) distinct engagements spanning at least
  `LEARNING_VERIFY_MIN_DAYS` (7) days, with no contradiction in that run. The
  window opens at the first confirmation after the fact was learned or last
  contradicted. A single contradiction demotes the fact, clears `verified_at` and
  resets the engagement count and window, so it starts again as `learned`.
- **Pin**: a human fixes a fact. A pinned fact never expires and is never demoted
  or replaced; a contradicting observation is still counted and recorded as
  `contradicted` so the digest shows it. Unpinning restores normal expiry from
  that moment.
- **Revert**: a human retires a fact. It becomes a tombstone that is not served
  and is not re-learned until it expires.
- **Capacity**: at `LEARNING_MAX_ENTRIES_PER_KIND` new entries are refused rather
  than evicting existing ones, so a flood of new names cannot push out
  established facts.

## Serving

`get_learned_facts(kind, dataset=None)` and the resource
`tenant://learned/{kind}` return active, unexpired entries, filtered by
`LOG_SEARCH_DATASET_POLICY`. Facts not tied to a dataset (timings, helper usage)
are visible to anyone allowed the tool, with their evidence ids withheld because
those queries may touch datasets the caller cannot see. The resource requires
the same `get_learned_facts` tool permission and emits a `read` audit event.

Each entry has a trust label:

- `{"label": "learned", "confirmations": N, "engagements": M}`;
- `{"label": "verified", "verified_at": "...", "confirmations": N, "engagements": M}`
  once the verification thresholds are met;
- `{"label": "pinned", "pinned_at": "...", "confirmations": N, "engagements": M}`
  when an administrator pinned it.

`engagements` counts the distinct engagements that confirmed the fact since it was
learned or last contradicted. Entries store only the first 16 hex characters of
each hashed engagement key.

## Digest, pin and revert

`learning_digest(days=7)` reads what the learner recorded: entries learned,
promoted, demoted, verified, contradicted while pinned, pinned, unpinned, expired
and reverted in the window, newest first, each with its fact, evidence query ids,
counts and, where useful, a `revert_with: {"tool": "revert_learned", "entry_id": ...}`
hint. It also counts entries confirmed in the window, lists pending admin
requests and shows when the learner last ran each job. It is filtered by dataset
policy and writes nothing. The weekly job writes the same digest, unfiltered, to
`learned/digests/<date>.json` with replay scores and step sequences. The default
tool policy grants the tool to `Admin` and `Security`.

`revert_learned(entry_id, action="revert")` is the only human override. It is
restricted to `LEARNING_ADMIN_GROUPS` (default `Admin`) regardless of tool policy,
and to datasets the caller's dataset policy allows. `action` is:

- `revert`: retire the fact; it becomes a tombstone;
- `pin`: keep the fact active, never expiring and never demoted;
- `unpin`: return a pinned fact to normal expiry and demotion.

The request is appended to the `admin` journal stream. Read paths apply it at
once (a reverted fact disappears, a pinned fact is served as `pinned`) and the
learner records it on its next run. Requests are accepted while learning is
frozen and applied when learning resumes. A reverted fact cannot be pinned.

## Kill switch

`LEARNING_ENABLED=false` stops both processes: observers journal nothing and the
learner exits without reading the journal or writing anything. Served facts stay
readable (expired ones are still hidden) and admin requests are still accepted.
With no `TENANT_PACK_DIR`, observers and the learner do nothing.

## Audit

- The learner emits one `cortex_xsiam_mcp.learning` event per run that changes
  anything or runs a scheduled job, before committing. `operation` is the command
  (`tick`, `nightly`, `weekly`); `changes` lists each entry change (`learned`,
  `confirmed`, `promoted`, `demoted`, `verified`, `contradicted`, `pinned`,
  `unpinned`, `expired`, `reverted`) with fact, evidence, counts, `verified_at`,
  `pinned` and the engagement count; `details` holds the run report, cached results, fact links and the
  principals whose calls produced the observations. If export fails under
  `AUDIT_LOG_FAIL_CLOSED=true`, nothing is written and the journal is re-read on
  the next run.
- The learner's history queries emit `cortex_xsiam_mcp.tool_invocation` events
  for the learner principal.
- The gateway emits `revert_requested`, `pin_requested`, `unpin_requested` and
  resource `read` learning events. Its
  tool calls are audited as before; journalling itself is not a change to facts.

See [Audit Logging](AUDIT_LOGGING.md).

## Hooks for other components

Plain functions; callers import them lazily so the gateway runs without them.

| Caller | Function | Use |
| --- | --- | --- |
| Cost guard | `learned_store.lookup_cost(dataset, window_bucket, selectivity)` | Called by `cost_guard.apply_learned_cost`, before the seed table. Returns `median_units`, `high_units` (maximum of the last 20 samples), `observations`, `confidence`, or `None` below `LEARNING_COST_MIN_OBSERVATIONS`. Use `high_units` and keep the seed band's lower bound as a floor. Bucket and class come from `learning_observers.window_bucket(window_ms(...))` and `selectivity_class(parse_xql(query))`. |
| XQL validator | `learned_store.learned_enum_fields(dataset)`, `learned_absent_fields(dataset)` | Suggest `contains` for enum-like fields; reject or warn on fields XSIAM reported unknown. |
| Field cache | `learning_observers.observe_field_catalog(ctx, dataset=..., fields=..., query_id=...)` | Call after any field-cache fill with the sample's query id. |
| Engagement module | `learning_journal.journal_engagement_closed(engagement_key=..., case_id=...)` | Mark an engagement closed so the learner processes it within the close SLA. |

Demoted, reverted, pending-revert and expired entries never reach these hooks;
pinned entries always do.

## Replay foundation

When `LEARNING_RESULT_CACHE_ENABLED=true` and an engagement has a case id, the
gateway journals each query-running tool call with the bounded result it
returned, and the learner writes it to `engagements/<case_id>/results/`: the
tool, a SHA-256 of its arguments, argument names (not values), query ids, units,
duration, outcome, and the result with continuation cursors removed. Results are
capped by `LEARNING_RESULT_MAX_BYTES` each and `LEARNING_RESULT_CACHE_MAX_BYTES`
per case. Successful `record_fact` calls add a link from the fact key to its
evidence query id; fact values are not copied.

The cache is off by default because cached rows are tenant data and contain the
values a query filtered for (indicators, user names, hosts). Turn it on only where
the pack's storage is approved for investigation data.

`usecase.replay.replay_engagement(case_id, candidate=None)` re-runs the recorded
sequence, or a candidate list of `{"tool", "arguments"}` (or
`{"tool", "arguments_sha256"}`) steps, against the cache and reports steps, cache
hits and misses, queries, units and the engagement facts reached and missed,
with the recorded sequence as a baseline. It never calls XSIAM. It is a Python
function for the learner and the tier-2 approval process, not an MCP tool, so
agents cannot read cached results through it.

`tests/agent_eval/cases.json` includes `ioc_flood_triage`, a synthetic IOC-flood
case that gives the planning agent learned enum and absent-field facts and checks
that it uses `contains` and avoids absent fields.

## Settings

| Variable | Default | Description |
| --- | --- | --- |
| `TENANT_PACK_DIR` | empty | Absolute path of the tenant pack, outside the repository. Empty disables learning. |
| `LEARNING_ENABLED` | `true` | Kill switch for the observers and the learner. |
| `LEARNING_SCHEMA_TTL_DAYS` | `30` | Expiry of schema, enum and absent-field facts without confirmation. |
| `LEARNING_COST_TTL_DAYS` | `90` | Expiry of cost, timing and helper facts without confirmation. |
| `LEARNING_MAX_ENTRIES_PER_KIND` | `5000` | Cap per fact kind; new entries beyond it are refused. |
| `LEARNING_COST_MIN_OBSERVATIONS` | `3` | Observations before `lookup_cost` returns a learned cost. |
| `LEARNING_ADMIN_GROUPS` | `Admin` | Groups allowed to revert, pin or unpin facts with `revert_learned`. |
| `LEARNING_VERIFY_MIN_CONFIRMATIONS` | `5` | Confirmations, since the last contradiction, before a fact is verified. |
| `LEARNING_VERIFY_MIN_ENGAGEMENTS` | `3` | Distinct engagements those confirmations must come from. |
| `LEARNING_VERIFY_MIN_DAYS` | `7` | Days the confirmations must span. |
| `LEARNING_JOURNAL_MAX_BYTES` | `67108864` | Largest journal file per process per day; records beyond it are dropped. |
| `LEARNING_RESULT_CACHE_ENABLED` | `false` | Cache bounded results of a case's tool calls for replay. |
| `LEARNING_RESULT_MAX_BYTES` | `262144` | Largest single result kept in the replay cache. |
| `LEARNING_RESULT_CACHE_MAX_BYTES` | `5242880` | Replay cache size per case. |
| `LEARNER_PRINCIPAL_ID` | `learning-service` | Principal the learner queries XSIAM as. |
| `LEARNER_GROUPS` | `learner` | Groups of that principal, for dataset policy, tool policy and the credential broker. |
| `LEARNER_DAILY_UNIT_CAP` | `0.5` | Units the learner may spend per UTC day. |
| `LEARNER_RESERVE_UNITS` | `20` | Skip learner queries when remaining units are below this. |
| `LEARNER_DAILY_QUOTA_UNITS` | `0` | Daily units for the reserve check; `0` derives them from the licence quota. |
| `LEARNER_ENGAGEMENT_CLOSE_SLA_MINUTES` | `15` | Time within which a closed engagement should be processed; later ones are reported late. |
| `LEARNER_ENGAGEMENT_IDLE_HOURS` | `24` | Inactivity after which an open engagement is processed. |
| `LEARNER_NIGHTLY_UTC` | `13:30` | Nightly expiry and recalibration time, `HH:MM` UTC. |
| `LEARNER_WEEKLY_UTC` | `MON 20:00` | Weekly digest, replay scoring and mining, weekday and `HH:MM` UTC. |
| `LEARNER_RECALIBRATION_MAX_IDS` | `100` | Query ids looked up in the history per night. |

## Limits

- The enum detector is a heuristic: a `contains` match on a value that an
  equality filter missed can also mean the value is a substring of real values.
  The confirmation count, the multi-engagement verification rule, the
  contradiction rule and expiry bound the damage; an administrator can revert. Pairing happens inside one gateway process,
  so the two queries must reach the same replica (sticky MCP sessions do this).
- `remaining_quota` deltas are approximate when queries overlap or other clients
  share the quota; that is why they wait for nightly recalibration.
- Recalibration assumes the history's `execution_id` equals the query id the
  public API returns; this has not been verified against a live tenant. Without a
  match the delta is kept.
- Unknown-field classification relies on XSIAM error wording; a message it does
  not recognise simply produces no fact.
- The instruction-shaped field-name guard is a word list, so it is defence in
  depth, not a guarantee; trust labels and the identifier-only rule remain the
  main controls.
- Tool calls that run no query produce no helper or timing facts, because every
  fact needs query-id evidence.
