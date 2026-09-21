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
- **Query budget.** One helper call may issue at most 20 XQL queries, field
  discovery included.
- **Provenance in the audit event.** Because the server chooses datasets, each
  response carries `provenance.queries` with dataset, purpose, query hash,
  query id, and row count. The audit event records the same list as
  `helper_queries`. Entity values appear in neither.
- **Results are untrusted data.** Values returned from datasets are labelled
  `content_trust: untrusted_data`. Resolved addresses are re-validated as IP
  addresses before they are reused in a follow-up query, so a hostile value in
  an inventory field cannot become a filter or an instruction.
