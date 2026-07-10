# Agent And XSIAM Testing

## Test Layers

The project tests the server contract and the client-agent behavior separately.
Passing unit tests alone does not show that an LLM will choose valid MCP
arguments, while an agent transcript alone does not prove authorization or
result bounds.

| Layer | What it proves | Default CI |
| --- | --- | --- |
| Compiler/unit | Typed filters, aggregates, escaping, timestamp cursors, output budgets. | Yes |
| Security | Entra validation, gateway replay rejection, tool/dataset policy, raw-XQL dual authorization, deterministic credential selection, audit attribution. | Yes |
| MCP contract | FastMCP 3 startup, tool registration, required/forbidden arguments, nested schema enums. | Yes |
| XQL executor | Polling, failures, timeout, result caps, and four-query concurrency ceiling. | Yes |
| Agent evaluator | Plain-English plan uses allowed datasets/discovered fields and produces executable typed arguments. | Unit validator in CI; model run before release. |
| Live XSIAM | Dynamic discovery, non-security rows/aggregate, time trends, and two-page timestamp keyset continuation. | Opt-in only. |

## Standard Verification

```bash
poetry install --no-root
poetry run ruff check src tests scripts
poetry run python -m compileall -f -q src tests scripts
poetry run pytest -q
poetry check
```

The normal run skips `tests/test_xsiam_live.py` even if live credential
variables happen to be present. Live calls require explicit `--run-live`.

## Blind Codex Planning Evaluation

`tests/agent_eval/cases.json` contains ten synthetic cases spanning:

- targeted inventory rows;
- grouped device counts;
- top-five application usage;
- a 24-hour time trend;
- a non-security business average;
- a restricted dataset;
- an unbounded export request;
- a missing field requiring discovery;
- continuation with an opaque cursor;
- an unprivileged request for raw XQL whose intent can use typed tools.

The model-visible prompt intentionally excludes each case's `expect` block.
`scripts/evaluate_agent_plans.py` validates the result after generation and
rejects invented fields, invalid typed operators, raw query/tenant arguments,
overlarge limits, the wrong query mode, and reconstructed continuation calls.

Run Codex non-interactively:

```bash
prompt="$(poetry run python scripts/evaluate_agent_plans.py --emit-prompt)"
codex exec \
  --ephemeral \
  --ignore-user-config \
  --ignore-rules \
  --sandbox read-only \
  --output-schema tests/agent_eval/response.schema.json \
  --output-last-message /tmp/xsiam-agent-eval.json \
  "$prompt"
poetry run python scripts/evaluate_agent_plans.py \
  --validate /tmp/xsiam-agent-eval.json
```

The implementation run on 2026-07-10 exposed and corrected three evaluation or
guidance defects before producing a blind `10/10` result:

1. XQL `=` was initially accepted where typed filters require `eq`; the schema
   and validator now enforce the real operator enum.
2. An unprivileged raw-XQL request was denied instead of translated to a valid
   typed plan; public agent guidance now preserves supported intent.
3. A continuation call included a dataset argument; guidance now states that
   `continue_dataset_query` is cursor-only.

Do not commit generated transcripts. They are model/version dependent and may
contain user prompts in real deployments. Record only aggregate pass/fail data
in release evidence.

## Opt-In Live XSIAM Tests

The live suite receives secrets only through process environment variables:

| Variable | Purpose |
| --- | --- |
| `XSIAM_LIVE_API_URL` | API base URL. |
| `XSIAM_LIVE_API_KEY` | API key value. |
| `XSIAM_LIVE_API_KEY_ID` | API key identifier. |
| `XSIAM_LIVE_INVENTORY_DATASET` | Non-security/inventory dataset; default `host_inventory`. |
| `XSIAM_LIVE_PAGINATION_DATASET` | Active dataset for two-page test; default `xdr_data`. |
| `XSIAM_LIVE_PAGINATION_TIME_FIELD` | Timestamp sort field; default `_time`. |
| `XSIAM_LIVE_PAGINATION_ID_FIELD` | Stable tie-breaker; default `event_id`. |

```bash
XSIAM_LIVE_API_URL=... \
XSIAM_LIVE_API_KEY=... \
XSIAM_LIVE_API_KEY_ID=... \
poetry run pytest -q --run-live tests/test_xsiam_live.py
```

The tests do not print or persist result values. The implementation run on
2026-07-10 passed both live workflows and found three issues before passing:

- XSIAM returned an extra field after an XQL `fields` stage, leading to
  mandatory server-side output projection.
- `_time` was serialized as epoch milliseconds but remained an XQL timestamp,
  leading to `to_timestamp(..., "MILLIS")` in continuation predicates.
- The live XSIAM parser required a contiguous `bin` duration token such as
  `1h`, leading to a compiler regression test for time trends.

Never place tenant identifiers, service URLs, credentials, result values, or
organization-specific dataset names in this public repository.

## Release Evidence

An alpha release should record:

1. Python versions and FastMCP version.
2. Unit/security/schema pass counts.
3. Live test pass/fail without tenant details.
4. Blind agent evaluation score and model/CLI version.
5. Open dependency alerts after the merged lockfile is rescanned.
6. CI, CodeQL, Dependency Review, and configured AI review outcomes.
