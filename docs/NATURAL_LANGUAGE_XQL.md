# Natural Language And XQL

## Recommended Approach

For enterprise MCP use, the LLM agent should translate the user's
plain-English request into structured MCP calls. The MCP server should provide
agent instructions, dataset discovery, field discovery, policy enforcement, XQL
execution, and audit logging.

Use this flow instead of broad server-side natural-language translation:

1. Agent calls `get_log_search_guidance`.
2. Agent calls `list_log_datasets`.
3. Agent calls `discover_log_fields`.
4. Agent calls `search_logs` with explicit structured filters.

See [Agent Log Search](AGENT_LOG_SEARCH.md).

## Experimental Fallback

The current natural-language-to-XQL implementation is intentionally conservative
and template-based. It is a fallback, not the preferred enterprise path.

It can translate common SOC requests such as:

- failed login searches;
- authentication searches;
- severity filters;
- username filters;
- host/endpoint filters;
- IPv4 source filters;
- relative time windows such as `last 24 hours`.

It refuses ambiguous prompts such as:

```text
show me suspicious things
```

Refusing ambiguous prompts is a security feature. The server should not invent a
query over sensitive security logs.

## Example

Input:

```text
failed login for user alice on host laptop-01 from 192.0.2.10 in the last 24 hours
```

Generated XQL:

```xql
dataset = xdr_data
| filter event_type contains "authentication"
| filter event_sub_type contains "fail"
| filter src_ip = "192.0.2.10"
| filter actor_effective_username contains "alice"
| filter agent_hostname contains "laptop-01"
| fields event_id, event_type, event_sub_type
| limit 50
```

The relative time window is sent through the XSIAM query API `timeframe`
parameter rather than embedded in XQL.

## If Server-Side LLM Translation Is Added Later

Before adding broad LLM-backed translation:

- use a constrained XQL schema and dataset catalogue;
- require the model to return structured JSON, not arbitrary tool calls;
- validate the generated XQL against policy before execution;
- enforce dataset allowlists independently of generated text;
- cap lookback windows and result sizes by role;
- record the natural-language prompt, generated XQL, policy decision, and user;
- provide a dry-run mode for analyst review;
- add tests for known risky prompt patterns.

## Server-Side Translation Flow

1. User provides natural language.
2. Translator returns structured intent and candidate XQL.
3. Policy validates dataset, fields, lookback, and operators.
4. Server executes only if policy passes.
5. Audit event stores prompt, generated XQL, and decision.
