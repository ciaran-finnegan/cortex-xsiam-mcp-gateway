import asyncio
import json
from types import SimpleNamespace

import pytest
from fastmcp.tools.tool import ToolResult

from config.config import Settings, get_config
from entities.MCPContext import MCPContext
from service.cortex_mcp import audit_middleware
from usecase import field_catalog, xql_executor
from usecase.builtin_components import datasets, issues, logs
from usecase.credential_broker import (
    clear_current_credential_selection,
    reset_current_credential_selection,
)
from usecase.dataset_query import QueryMetric, QuerySort, QueryTimeframe
from usecase.field_catalog import remember_observed_fields

WAREHOUSE_FIELDS = ["_time", "_reporting_device_ip", "_collector_name", "EVENT_TYPE", "USER_NAME", "local_ip"]


def _ctx(groups=("DataReader",)):
    state = {}
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(
                auth_headers={"Authorization": "test-key", "X-XDR-AUTH-ID": "test-id"},
                principal_id="analyst@example.test",
                groups=groups,
            )
        ),
        set_state=lambda key, value: state.__setitem__(key, value),
        get_state=lambda key: state.get(key),
    )


def _allow_warehouse(monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["warehouse_audit_raw"]}')


async def _fail_if_executed(*args, **kwargs):
    raise AssertionError("query must not execute")


class SequenceFetcher:
    """Return canned XSIAM replies in order; block forever once they run out."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    async def send_request(self, path, data):
        self.requests.append((path, data))
        if not self.responses:
            await asyncio.Event().wait()
        return self.responses.pop(0)


def _use_fetcher(monkeypatch, fetcher):
    async def fake_get_fetcher(ctx):
        return fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)


async def _audited_call(monkeypatch, tool_name, arguments, invoke):
    """Run a tool through ToolAuditMiddleware and return (tool response, end audit event)."""
    events = []
    outer_token = clear_current_credential_selection()

    async def capture(event):
        events.append(event)

    async def call_next(*, context):
        payload = await invoke(context.fastmcp_context)
        if isinstance(payload, str):
            payload = json.loads(payload)
        return ToolResult(structured_content=payload)

    monkeypatch.setattr(audit_middleware, "emit_audit_event", capture)
    middleware_context = SimpleNamespace(
        message=SimpleNamespace(name=tool_name, arguments=arguments),
        fastmcp_context=_ctx(),
    )
    try:
        result = await audit_middleware.ToolAuditMiddleware().on_call_tool(middleware_context, call_next)
    finally:
        reset_current_credential_selection(outer_token)
    return result.structured_content, next(event for event in events if event["phase"] == "end")


# --- 1. Field validation before execution -----------------------------------


@pytest.mark.asyncio
async def test_query_dataset_rejects_undiscovered_field_with_nearest_names_before_execution(monkeypatch):
    _allow_warehouse(monkeypatch)
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    monkeypatch.setattr(datasets, "run_xql_query", _fail_if_executed)
    monkeypatch.setattr(field_catalog, "run_xql_query", _fail_if_executed)

    response = await datasets.query_dataset(
        _ctx(),
        dataset="warehouse_audit_raw",
        fields=["_time", "_reporting_device_name"],
        order_by=[QuerySort(field="_time")],
    )

    assert response["success"] is False
    assert response["executed"] is False
    assert response["error_code"] == "unknown_fields"
    assert "_reporting_device_name" in response["error"]
    assert response["unknown_fields"] == [
        {
            "name": "_reporting_device_name",
            "used_in": ["fields"],
            "suggestions": response["unknown_fields"][0]["suggestions"],
        }
    ]
    suggestions = response["unknown_fields"][0]["suggestions"]
    assert suggestions[0] == "_reporting_device_ip"
    assert 1 <= len(suggestions) <= 3
    assert response["field_validation"]["source"] == "discovery_cache"


@pytest.mark.asyncio
async def test_query_dataset_runs_bounded_discovery_sample_once_and_never_returns_its_values(monkeypatch):
    _allow_warehouse(monkeypatch)
    sample_calls = []

    async def fake_sample(ctx, query, result_limit, **kwargs):
        sample_calls.append((query, result_limit, kwargs))
        return {
            "query_id": "sample-1",
            "reply": {
                "status": "SUCCESS",
                "results": {
                    "data": [
                        {field: f"value-{field}" for field in WAREHOUSE_FIELDS}
                        | {"USER_NAME": "SENSITIVE.USER@EXAMPLE.TEST"}
                    ]
                },
            },
        }

    monkeypatch.setattr(field_catalog, "run_xql_query", fake_sample)
    monkeypatch.setattr(datasets, "run_xql_query", _fail_if_executed)

    arguments = {
        "dataset": "warehouse_audit_raw",
        "mode": "aggregate",
        "metrics": [QueryMetric(function="count_distinct", field="USER_NAME", alias="users")],
        "group_by": ["_reporting_device_name"],
        "order_by": [QuerySort(field="users", direction="desc")],
        "timeframe": QueryTimeframe(from_ms=1, to_ms=2),
    }
    first = await datasets.query_dataset(_ctx(), **arguments)
    second = await datasets.query_dataset(_ctx(), **arguments)

    assert sample_calls == [
        (
            "dataset = warehouse_audit_raw | limit 25",
            25,
            {"timeframe": {"from": 1, "to": 2}, "timeout_seconds": 30},
        )
    ]
    assert first["error_code"] == "unknown_fields"
    assert [item["name"] for item in first["unknown_fields"]] == ["_reporting_device_name"]
    assert first["unknown_fields"][0]["used_in"] == ["group_by"]
    assert first["field_validation"]["source"] == "discovery_sample"
    assert first["field_validation"]["sample_query_id"] == "sample-1"
    assert second["field_validation"]["source"] == "discovery_cache"
    for response in (first, second):
        assert "SENSITIVE.USER" not in json.dumps(response)
        assert "value-" not in json.dumps(response)


@pytest.mark.asyncio
async def test_query_dataset_runs_unchecked_when_discovery_sample_is_empty(monkeypatch):
    _allow_warehouse(monkeypatch)

    async def empty_sample(ctx, query, result_limit, **kwargs):
        return {"query_id": "sample-empty", "reply": {"status": "SUCCESS", "results": {"data": []}}}

    async def fake_run(ctx, query, result_limit, **kwargs):
        return {"query_id": "query-1", "reply": {"status": "SUCCESS", "results": {"data": [{"EVENT_TYPE": "LOGIN"}]}}}

    monkeypatch.setattr(field_catalog, "run_xql_query", empty_sample)
    monkeypatch.setattr(datasets, "run_xql_query", fake_run)

    response = await datasets.query_dataset(_ctx(), dataset="warehouse_audit_raw", fields=["EVENT_TYPE"])

    assert response["success"] is True
    assert response["field_validation"] == {
        "status": "unverified",
        "source": "discovery_sample",
        "reason": "discovery_sample_empty",
        "sample_query_id": "sample-empty",
    }
    assert field_catalog.get_observed_fields("warehouse_audit_raw") is None


@pytest.mark.asyncio
async def test_query_dataset_dry_run_validates_against_cache_without_sampling(monkeypatch):
    _allow_warehouse(monkeypatch)
    monkeypatch.setattr(field_catalog, "run_xql_query", _fail_if_executed)

    unchecked = await datasets.query_dataset(
        _ctx(), dataset="warehouse_audit_raw", fields=["_reporting_device_name"], dry_run=True
    )
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    rejected = await datasets.query_dataset(
        _ctx(), dataset="warehouse_audit_raw", fields=["_reporting_device_name"], dry_run=True
    )

    assert unchecked["success"] is True
    assert unchecked["field_validation"] == {"status": "not_checked", "reason": "no_cached_discovery"}
    assert rejected["success"] is False
    assert rejected["error_code"] == "unknown_fields"


@pytest.mark.asyncio
async def test_search_logs_reuses_discover_log_fields_result_to_reject_unknown_filter_field(monkeypatch):
    _allow_warehouse(monkeypatch)
    queries = []

    async def fake_run(ctx, query, limit, **kwargs):
        queries.append(query)
        return {"reply": {"results": [dict.fromkeys(WAREHOUSE_FIELDS, "private-value")]}}

    monkeypatch.setattr(logs, "_run_xql_query", fake_run)
    monkeypatch.setattr(field_catalog, "run_xql_query", _fail_if_executed)

    discovered = json.loads(await logs.discover_log_fields(_ctx(), dataset="warehouse_audit_raw"))
    response = json.loads(
        await logs.search_logs(
            _ctx(),
            dataset="warehouse_audit_raw",
            fields=["EVENT_TYPE"],
            filters=[{"field": "user_name", "operator": "eq", "value": "someone"}],
        )
    )

    assert discovered["success"] == "true"
    assert queries == ["dataset = warehouse_audit_raw | limit 25"]
    assert response["success"] == "false"
    assert response["executed"] is False
    assert response["error_code"] == "unknown_fields"
    assert response["unknown_fields"] == [
        {"name": "user_name", "used_in": ["filters"], "suggestions": ["USER_NAME"]}
    ]
    assert "private-value" not in json.dumps(response)


@pytest.mark.asyncio
async def test_rejected_query_audit_event_records_dataset_principal_and_outcome(monkeypatch):
    _allow_warehouse(monkeypatch)
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    monkeypatch.setattr(datasets, "run_xql_query", _fail_if_executed)
    arguments = {"dataset": "warehouse_audit_raw", "fields": ["_reporting_device_name"]}

    response, event = await _audited_call(
        monkeypatch,
        "query_dataset",
        arguments,
        lambda ctx: datasets.query_dataset(ctx, **arguments),
    )

    assert response["error_code"] == "unknown_fields"
    assert event["outcome"] == "rejected"
    assert event["principal"]["id"] == "analyst@example.test"
    assert event["request"]["dataset"] == "warehouse_audit_raw"
    assert event["result"]["dataset"] == "warehouse_audit_raw"
    assert event["result"]["error_code"] == "unknown_fields"
    assert event["result"]["executed"] is False


# --- 2. Relaying XSIAM's failure reason -------------------------------------


def test_xsiam_error_sanitizer_keeps_query_identifiers_and_redacts_values():
    query = 'dataset = warehouse_audit_raw | filter USER_NAME = "alice@example.test" | comp count() by local_ip | limit 25'
    detail = (
        'Cannot group by array field "local_ip" (value "192.0.2.5") for user \'alice@example.test\' '
        "at 192.0.2.6 fe80::1 id 123e4567-e89b-12d3-a456-426614174000 ts 1700000000000 "
        "see https://tenant.example.test/q\n\tline 1:42"
    )

    message = xql_executor.sanitize_xsiam_error(detail, query)

    assert message == (
        'Cannot group by array field "local_ip" (value "<redacted>") for user \'<redacted>\' '
        "at <ip> <ip> id <value> ts <value> see <url> line 1:42"
    )
    assert xql_executor.sanitize_xsiam_error("x" * 400).endswith("...<truncated>")
    assert len(xql_executor.sanitize_xsiam_error("x" * 400)) <= xql_executor.MAX_XSIAM_ERROR_CHARS + 20
    assert xql_executor.sanitize_xsiam_error({"err_msg": 'bad "secret"'}) == 'bad "<redacted>"'
    assert xql_executor.sanitize_xsiam_error({"rows": [{"a": 1}]}) is None
    assert xql_executor.sanitize_xsiam_error(None) is None


@pytest.mark.asyncio
async def test_query_dataset_relays_sanitized_xsiam_failure_without_rows(monkeypatch):
    _allow_warehouse(monkeypatch)
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    upstream_error = 'Cannot group by array field local_ip, saw value "192.0.2.5" from 192.0.2.6'
    fetcher = SequenceFetcher(
        [
            {"reply": "query-fail"},
            {
                "reply": {
                    "status": "FAIL",
                    "error_message": upstream_error,
                    "results": {"data": [{"local_ip": "192.0.2.7"}]},
                }
            },
        ]
    )
    _use_fetcher(monkeypatch, fetcher)

    arguments = {
        "dataset": "warehouse_audit_raw",
        "mode": "aggregate",
        "metrics": [QueryMetric(function="count", alias="total")],
        "group_by": ["local_ip"],
    }

    response, event = await _audited_call(
        monkeypatch,
        "query_dataset",
        {"dataset": "warehouse_audit_raw", "mode": "aggregate"},
        lambda ctx: datasets.query_dataset(ctx, **arguments),
    )

    assert event["outcome"] == "error"
    assert event["result"]["error_code"] == "xql_failed"
    assert "array field" not in json.dumps(event)
    assert response["success"] is False
    assert response["executed"] is True
    assert response["error"] == "XQL query failed"
    assert response["error_code"] == "xql_failed"
    assert response["xsiam_status"] == "FAIL"
    assert response["xsiam_error"] == 'Cannot group by array field local_ip, saw value "<redacted>" from <ip>'
    assert len(response["error_reference_sha256"]) == 64
    assert response["query_id"] == "query-fail"
    assert "rows" not in response
    assert "192.0.2" not in json.dumps(response)


@pytest.mark.asyncio
async def test_execute_xql_query_relays_sanitized_xsiam_failure(monkeypatch):
    monkeypatch.setattr(get_config(), "raw_xql_privileged_groups", "Security")
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Security":["*"]}')
    fetcher = SequenceFetcher(
        [
            {"reply": "query-raw"},
            {"reply": {"status": "FAIL", "error": 'Unknown field _reporting_device_name near "private-literal"'}},
        ]
    )
    _use_fetcher(monkeypatch, fetcher)

    response = json.loads(
        await issues.execute_xql_query(
            _ctx(groups=("Security",)),
            'dataset = warehouse_audit_raw | filter USER_NAME = "private-literal" | fields _reporting_device_name | limit 5',
        )
    )

    assert response["success"] == "false"
    assert response["xsiam_status"] == "FAIL"
    assert response["xsiam_error"] == 'Unknown field _reporting_device_name near "<redacted>"'
    assert len(response["error_reference_sha256"]) == 64
    assert "private-literal" not in json.dumps(response)
    assert "rows" not in response


@pytest.mark.asyncio
async def test_search_logs_relays_sanitized_xsiam_failure(monkeypatch):
    _allow_warehouse(monkeypatch)
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    fetcher = SequenceFetcher(
        [{"reply": {"status": "ERROR", "err_msg": 'Type mismatch for EVENT_TYPE value "LOGIN-secret"'}}]
    )
    _use_fetcher(monkeypatch, fetcher)

    response = json.loads(await logs.search_logs(_ctx(), dataset="warehouse_audit_raw", fields=["EVENT_TYPE"]))

    assert response["success"] == "false"
    assert response["executed"] is True
    assert response["dataset"] == "warehouse_audit_raw"
    assert response["xsiam_error"] == 'Type mismatch for EVENT_TYPE value "<redacted>"'
    assert "LOGIN-secret" not in json.dumps(response)


# --- 3. Server-side timeout for typed queries -------------------------------


def test_dataset_query_timeout_setting_defaults_well_under_mcp_idle_timeout(monkeypatch):
    monkeypatch.delenv("DATASET_QUERY_TIMEOUT_SECONDS", raising=False)
    assert Settings(_env_file=None).dataset_query_timeout_seconds == 300

    monkeypatch.setenv("DATASET_QUERY_TIMEOUT_SECONDS", "120")
    assert Settings(_env_file=None).dataset_query_timeout_seconds == 120


@pytest.mark.asyncio
async def test_xql_executor_wall_clock_limit_bounds_a_hung_upstream_request(monkeypatch):
    fetcher = SequenceFetcher([{"reply": "query-hung"}])
    _use_fetcher(monkeypatch, fetcher)

    response = await asyncio.wait_for(
        xql_executor.run_xql_query(None, "dataset = sample | limit 1", 1, poll_interval_seconds=0, timeout_seconds=1),
        timeout=5,
    )

    assert response == {
        "query_id": "query-hung",
        "poll_attempts": 1,
        "error": "XQL query timed out after 1 seconds (server-side limit)",
        "error_code": "query_timeout",
        "timeout_seconds": 1,
        "xsiam_query_submitted": True,
        "xsiam_cancelled": False,
        "xsiam_cancel_note": xql_executor.XSIAM_CANCEL_NOTE,
    }


@pytest.mark.asyncio
async def test_query_dataset_timeout_returns_structured_error_and_audits_timeout(monkeypatch):
    _allow_warehouse(monkeypatch)
    monkeypatch.setattr(get_config(), "dataset_query_timeout_seconds", 1)
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    fetcher = SequenceFetcher([{"reply": "query-slow"}])
    _use_fetcher(monkeypatch, fetcher)
    arguments = {
        "dataset": "warehouse_audit_raw",
        "mode": "aggregate",
        "metrics": [QueryMetric(function="count", alias="total")],
        "group_by": ["EVENT_TYPE"],
    }

    response, event = await asyncio.wait_for(
        _audited_call(
            monkeypatch,
            "query_dataset",
            {"dataset": "warehouse_audit_raw", "mode": "aggregate"},
            lambda ctx: datasets.query_dataset(ctx, **arguments),
        ),
        timeout=5,
    )

    assert response["success"] is False
    assert response["executed"] is True
    assert response["error_code"] == "query_timeout"
    assert response["timeout_seconds"] == 1
    assert "1 seconds" in response["error"]
    assert response["query_id"] == "query-slow"
    assert response["xsiam_cancelled"] is False
    assert "rows" not in response
    assert event["outcome"] == "timeout"
    assert event["principal"]["id"] == "analyst@example.test"
    assert event["request"]["dataset"] == "warehouse_audit_raw"
    assert event["result"]["dataset"] == "warehouse_audit_raw"
    assert event["result"]["error_code"] == "query_timeout"
    assert event["result"]["timeout_seconds"] == 1


@pytest.mark.asyncio
async def test_search_logs_uses_dataset_query_timeout(monkeypatch):
    _allow_warehouse(monkeypatch)
    monkeypatch.setattr(get_config(), "dataset_query_timeout_seconds", 42)
    remember_observed_fields("warehouse_audit_raw", WAREHOUSE_FIELDS, rows_observed=25)
    seen = {}

    async def fake_run(ctx, query, limit, **kwargs):
        seen.update(kwargs)
        return {"query_id": "q", "reply": {"status": "SUCCESS", "results": {"data": []}}}

    monkeypatch.setattr(logs, "_run_xql_query", fake_run)

    response = json.loads(await logs.search_logs(_ctx(), dataset="warehouse_audit_raw", fields=["EVENT_TYPE"]))

    assert response["success"] == "true"
    assert seen["timeout_seconds"] == 42
