# Dataset Catalogue

Dataset names rarely say what a dataset holds. `vendor_product_raw` tells an
agent nothing about whether the records are firewall sessions, identity
sign-ins, or an application audit trail, and nothing about which field holds a
hostname or a user. Agents that guess produce empty results and unknown-field
errors.

The dataset catalogue is authored metadata that closes that gap. The
`find_datasets` tool searches it and returns only datasets the current
principal is allowed to query.

## What A Record Holds

| Field | Meaning |
| --- | --- |
| `match` | Exact dataset name, or a glob using `*` such as `vendor_firewall_*`. |
| `domain` | One of the fixed domains: `endpoint_telemetry`, `endpoint_inventory`, `network_traffic`, `network_threat`, `web_proxy`, `dns`, `vpn_remote_access`, `authentication_identity`, `directory`, `cloud_audit`, `cloud_network`, `saas_audit`, `email`, `alerts_incidents`, `vulnerability`, `threat_intel`, `platform_audit`, `ingestion_health`, `application`, `other`. |
| `description` | One plain sentence, at most 240 characters. |
| `vendor`, `product` | Optional source labels. |
| `keywords` | Lowercase search tokens. |
| `time_field` | Timestamp field; defaults to `_time`. |
| `fields` | Map of field role to candidate field names, for example `source_ip`, `dest_ip`, `user`, `host`, `action`, `rule`, `resource_id`. |
| `volume` | `low`, `medium`, `high`, or `very_high`. `high` and above make `find_datasets` return `query_hint: aggregate_first`. |

## Three Layers

1. **Built-in catalogue.** Shipped in
   `src/entities/resources/dataset_catalogue.json`. It covers vendor-standard
   Cortex datasets and common marketplace integrations. It must never contain a
   dataset name, field, or description that is specific to one deployment.
2. **Operator overlay.** A JSON file outside this repository, named by
   `DATASET_CATALOGUE_OVERLAY_PATH`. Use it for site-specific datasets and to
   override a built-in record. Exact overlay names win, then exact built-in
   names, then overlay globs, then built-in globs. The longest glob wins within
   a layer.
3. **Inference.** A dataset with no record gets a domain guessed from its name,
   no fields, and a description telling the agent to run `discover_log_fields`.

## Overlay Example

```json
{
  "version": 1,
  "entries": [
    {
      "match": "acme_billing_raw",
      "domain": "application",
      "description": "Billing application audit trail with operator and customer account actions.",
      "vendor": "Acme",
      "product": "Billing",
      "keywords": ["billing", "invoice"],
      "fields": {"user": ["operator_id"], "source_ip": ["client_address"], "operation": ["action_name"]},
      "volume": "low"
    },
    {
      "match": "acme_edge_*",
      "domain": "network_traffic",
      "description": "Edge gateway session records.",
      "fields": {"source_ip": ["src"], "dest_ip": ["dst"], "action": ["verdict"]},
      "volume": "high"
    }
  ]
}
```

```bash
export DATASET_CATALOGUE_OVERLAY_PATH=/etc/cortex-mcp/dataset-catalogue.json
```

The overlay is validated strictly: unknown keys, unknown roles, field names
that are not valid XQL identifiers, text containing markup or control
characters, bare `*` matches, files over 1 MiB, and more than 2000 entries are
all rejected. An unreadable or invalid overlay stops the server at startup
rather than silently running without it.

## Using `find_datasets`

```json
{"topic": "firewall traffic", "entity_type": "ip"}
```

returns, for each allowed match: the dataset name, domain, description, vendor
and product, time field, candidate fields by role, `entity_fields` for the
requested entity type, `volume`, `query_hint`, and `catalogue_source`
(`overlay`, `builtin`, or `inferred`). Results are capped at 25 per call and
paged with `offset` and `next_offset`.

Topic matching is token based with a small synonym table, so "computer" also
matches host and endpoint records and "logon" also matches authentication
records. With no topic the tool lists allowed datasets, catalogued records
first.

## Security Properties

- **Policy before lookup.** Dataset policy filters the tenant dataset list
  before any catalogue lookup or scoring. A record is never returned, counted
  by name, or described for a dataset the principal cannot query.
- **Authored text only.** Descriptions and keywords come from the built-in file
  or the operator overlay. Nothing in a response is derived from log content,
  so the catalogue is not a prompt-injection path. Responses carry
  `content_trust: authored_catalogue`.
- **Tenant dataset names are validated.** Names returned by the XSIAM API that
  are not safe XQL identifiers are dropped, since no typed tool could query
  them and they would otherwise be attacker-influenced text.
- **No size or count metadata.** The catalogue exposes a coarse authored
  `volume` class only; it does not return stored bytes or event counts.
- **Candidates, not guarantees.** Field names are candidates. Agents confirm
  them with `discover_log_fields`, and server-side helpers intersect them with
  discovered fields before compiling a query.
- **Errors stay generic.** A misconfigured catalogue is reported to the caller
  without file paths, and upstream API errors are not echoed.
- **Audit and tool policy apply unchanged.** `find_datasets` is a normal MCP
  tool, so every call is policy checked and audited. The free-text `topic` is
  recorded only as part of the argument hash.

## Contributing Built-in Records

Add records only for datasets that any deployment of the product or
integration would have. Use vendor documentation for field names. Do not copy
dataset lists, field lists, or wording from a specific tenant.
