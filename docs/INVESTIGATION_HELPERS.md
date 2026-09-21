# Investigation Helpers

The typed tools (`find_datasets`, `discover_log_fields`, `query_dataset`) are
flexible, but they expect the calling agent to plan several steps and to know
which dataset and fields answer a question. Less capable orchestrators, and
less technical users, do better with tools shaped like the question.

Each helper takes two or three plain arguments, chooses datasets from the
[dataset catalogue](DATASET_CATALOGUE.md), verifies field names against the
live schema, and runs bounded typed queries. No helper accepts a dataset query,
XQL, or field list.

## Tools

| Tool | Question it answers | Key arguments |
| --- | --- | --- |
| `resolve_entity` | "What is this computer's IP address?", "Who uses this address?", "Which machines does this user use?" | `value`, optional `entity_type` (`host`, `ip`, `user`), `window_hours` |
| `firewall_traffic` | "Show me firewall traffic between X and Y." | `source`, `destination`, optional `dest_port`, `window_hours`, `include_samples` |
| `firewall_verdict` | "Is the firewall dropping traffic to X?" | `destination`, optional `source`, `dest_port`, `window_hours` |
| `dataset_health` | "Is this data source arriving, and what does a record look like?" | `dataset` or `topic`, `window_hours`, `include_samples` |
| `threat_intel_lookup` | "What do we know about this IP address, domain, URL, hash, or email address?" | `indicator`, `include_related` |
| `entity_activity` | "Show me logs for this user / computer / IP address / cloud resource today." | `value`, optional `entity_type`, `window_hours`, `domains`, `max_datasets`, `include_samples` |

`source` and `destination` accept an IP address, a host name, or a user name.
Host names are resolved to IP addresses first, because firewall logs are keyed
by address. User names are matched on the dataset's user field when it has one.
CIDR ranges are not supported yet.

### `resolve_entity`

Reads catalogued **identity sources**: datasets marked `identity_source: true`
whose rows link at least two of host, IP address, and user. The built-in
catalogue marks the endpoint inventory, host inventory, firewall User-ID
mappings, and VPN sessions. Mark a site DHCP or DNS dataset in the overlay to
add it.

Low-volume sources are read as rows. High-volume sources are aggregated by
host, address, and user with an event count and last-seen time inside
`window_hours`. Matching is case-insensitive. Each link is labelled `exact`
(the value, its short host name, or its bare user name matched) or `partial`
(substring only), and the response carries an overall `match_quality`. When
nothing matches, the response says so and tells the agent not to guess an
address.

### `firewall_traffic` and `firewall_verdict`

Both select up to two allowed `network_traffic` datasets that have verified
source address, destination address, and action fields. They always aggregate
first:

- sessions and bytes by action, which also yields a `verdict` of
  `all_allowed`, `some_blocked`, `all_blocked`, or `no_traffic_seen`;
- `firewall_traffic`: top flows by action, rule, application, and port, plus up
  to 10 recent sessions when `include_samples` is true;
- `firewall_verdict`: top blocking rules and sources, only when something was
  blocked.

An action counts as blocking unless it is one of `allow`, `alert`, `accept`,
`permit`, `pass`, or `continue`. The list is returned as `allow_actions` so the
agent can explain the verdict.

The default window is 24 hours and is clamped to
`DATASET_QUERY_MAX_TIMEFRAME_MS`.

### `entity_activity`

Fans out across catalogued datasets the principal may query that have a field
for the entity kind, in an order that suits the kind: identity and VPN data
first for a user, endpoint telemetry first for a computer, network data first
for an address, cloud audit first for a cloud resource. Datasets with no
catalogue record are skipped, because nothing says which field to match.

For each dataset it runs one bounded aggregate: event count and last-seen
time, broken down by the dataset's operation, action, event type, or name
field, top five values. The two busiest datasets also return up to five recent
records. A computer is resolved first, then matched by exact host name where a
dataset has a host field and by resolved address where it has address fields.
A cloud resource must be declared with `entity_type: cloud_resource`, since
its identifier may contain `/` and `:`.

The response separates `datasets_with_activity`, `datasets_without_activity`,
and a count of `datasets_not_checked`, so the agent can say what was and was
not looked at. It checks six datasets by default and at most eight; per-dataset
work runs concurrently under the executor's concurrency limit.

### `dataset_health`

People validating a new data source tend to dump the dataset with no filter
and a very large limit. `dataset_health` answers the same question with at
most three bounded queries per dataset: a 25-row sample for field names and
types (values discarded), an arrival trend by hour (windows up to 48 hours) or
by day, and three recent records with up to eight fields. `status` is
`receiving`, `stale` (nothing in the window but records within seven days),
`no_data`, or `unknown` when no timestamp field was observed.

Give an exact `dataset`, or a `topic` to check the three best catalogue
matches. It works for datasets with no catalogue record, since it only needs
the dataset's own timestamp field.

### `threat_intel_lookup`

Looks one indicator up in the Cortex threat intelligence datasets and walks to
the malware families it is associated with and the threat actors linked to
those families. Analysts usually write this as a three-way join; the helper
uses sequential typed queries instead, so no raw XQL or join is involved.

Threat intelligence is third-party text, so only short identifying fields are
returned (names, aliases, type, verdict, origin, motivation, dates). Free-text
descriptions are never requested, and association names are truncated. An
indicator that is not found is reported as unknown to threat intelligence,
with guidance that this is not evidence it is benign.

Each of the four datasets is policy checked separately; related objects are
simply omitted when the principal may not read that dataset.

## Controls

- **Tool policy and audit apply unchanged.** Helpers are ordinary MCP tools.
  Add them to `TOOL_ACCESS_POLICY` for the groups that should have them; the
  shipped SOC and Tier1 defaults include them.
- **Dataset policy applies to every dataset a helper touches**, including
  identity sources. A helper never reads, names, or counts a dataset the
  principal cannot query. An explicit `dataset` argument is policy checked.
- **Typed compiler only.** Helpers build `DatasetQueryPlan` objects and use the
  same compiler, executor concurrency limit, and output budgets as
  `query_dataset`. Entity values are validated and only ever used as escaped
  filter literals.
- **Verified fields only.** Catalogue field names are intersected with the
  dataset's discovered fields before a plan is built. Field names are cached
  for an hour; values are never cached.
- **Query budget.** One helper call may issue at most 30 XQL queries, field
  discovery included. Slots are reserved before each query, so concurrent
  per-dataset work cannot overshoot it.
- **Provenance in the audit event.** Because the server chooses datasets, each
  response carries `provenance.queries` with dataset, purpose, query hash,
  query id, and row count. The audit event records the same list as
  `helper_queries`. Entity values appear in neither.
- **Results are untrusted data.** Values returned from datasets are labelled
  `content_trust: untrusted_data`. Resolved addresses are re-validated as IP
  addresses before they are reused in a follow-up query, so a hostile value in
  an inventory field cannot become a filter or an instruction.
