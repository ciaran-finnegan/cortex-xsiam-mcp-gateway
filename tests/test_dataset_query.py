import json
from types import SimpleNamespace

import pytest

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.builtin_components import datasets
from usecase.dataset_query import (
    DatasetQueryPlan,
    QueryCursorError,
    QueryFilter,
    QueryMetric,
    QuerySort,
    QueryTimeBucket,
    QueryTimeframe,
    build_dataset_xql,
    decode_query_cursor,
    encode_query_cursor,
)
from usecase.xql_results import bound_result_rows


def _principal(principal_id="analyst@example.test", groups=("DataReader",)):
    return MCPContext(
        auth_headers={},
        principal_id=principal_id,
        groups=groups,
        auth_source="entra",
        tenant_id="tenant-test",
    )


def _ctx(groups=("DataReader",)):
    state = {}
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(
                auth_headers={},
                principal_id="analyst@example.test",
                groups=groups,
            )
        ),
        set_state=lambda key, value: state.__setitem__(key, value),
        get_state=lambda key: state.get(key),
    )


def test_row_query_requires_explicit_fields():
    with pytest.raises(ValueError, match="explicit non-empty fields"):
        build_dataset_xql(DatasetQueryPlan(dataset="host_inventory"))


@pytest.mark.asyncio
async def test_agent_guidance_preserves_supported_intent_when_raw_xql_is_unavailable():
    guidance = await datasets.get_dataset_query_guidance()

    assert any("preserve the intent with query_dataset" in rule for rule in guidance["rules"])


def test_row_query_builds_typed_filters_sort_projection_and_extra_cursor_row():
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name", "os_type"],
        filters=[
            QueryFilter(field="os_type", operator="eq", value="WINDOWS"),
            QueryFilter(field="status", operator="is_not_null"),
        ],
        order_by=[QuerySort(field="last_seen", direction="desc"), QuerySort(field="host_id")],
        limit=25,
        enable_continuation=True,
    )

    compiled = build_dataset_xql(plan)

    assert compiled.xql == (
        'dataset = host_inventory | filter (os_type = "WINDOWS") and (status != null) '
        '| sort desc last_seen, asc host_id '
        '| fields host_name, os_type, last_seen, host_id | limit 26'
    )
    assert compiled.result_limit == 26
    assert compiled.page_limit == 25
    assert compiled.hidden_fields == ("last_seen", "host_id")


def test_continuation_reserves_one_xsiam_result_for_lookahead(monkeypatch):
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 1000)
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name"],
        order_by=[QuerySort(field="host_id")],
        limit=1000,
        enable_continuation=True,
    )

    compiled = build_dataset_xql(plan)

    assert compiled.page_limit == 999
    assert compiled.result_limit == 1000
    assert compiled.xql.endswith("| limit 1000")


def test_filter_literals_are_escaped_not_executed_as_xql():
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name"],
        filters=[QueryFilter(field="host_name", operator="eq", value='x" | limit 1000')],
    )

    query = build_dataset_xql(plan).xql

    assert 'host_name = "x\\" | limit 1000"' in query
    assert query.endswith("| fields host_name | limit 25")


def test_timestamp_filter_converts_epoch_milliseconds_to_xql_timestamp():
    plan = DatasetQueryPlan(
        dataset="authentication_events",
        fields=["event_id"],
        filters=[
            QueryFilter(
                field="observed_time",
                operator="gte",
                value=1_700_000_000_000,
                value_type="timestamp_ms",
            )
        ],
    )

    assert (
        'observed_time >= to_timestamp(1700000000000, "MILLIS")'
        in build_dataset_xql(plan).xql
    )


def test_generated_query_length_is_bounded(monkeypatch):
    monkeypatch.setattr(get_config(), "xql_max_query_chars", 80)
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name"],
        filters=[QueryFilter(field="host_name", operator="eq", value="x" * 100)],
    )

    with pytest.raises(ValueError, match="exceeds the configured"):
        build_dataset_xql(plan)


def test_aggregate_query_supports_metrics_grouping_and_top_values():
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        mode="aggregate",
        metrics=[
            QueryMetric(function="count", alias="total"),
            QueryMetric(function="count_distinct", field="host_id", alias="unique_hosts"),
        ],
        group_by=["os_type"],
        order_by=[QuerySort(field="total", direction="desc")],
        limit=10,
    )

    assert build_dataset_xql(plan).xql == (
        "dataset = host_inventory "
        "| comp count() as total, count_distinct(host_id) as unique_hosts by os_type "
        "| sort desc total | limit 10"
    )


def test_time_trend_query_bins_before_aggregation():
    plan = DatasetQueryPlan(
        dataset="sample_xql_raw",
        mode="aggregate",
        metrics=[QueryMetric(function="count", field="event_id", alias="events_per_hour")],
        time_bucket=QueryTimeBucket(field="_time", size=1, unit="h"),
        order_by=[QuerySort(field="_time")],
    )

    assert build_dataset_xql(plan).xql == (
        "dataset = sample_xql_raw | bin _time span = 1h "
        "| comp count(event_id) as events_per_hour by _time | sort asc _time | limit 25"
    )


def test_keyset_seek_uses_lexicographic_sort_values():
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name"],
        order_by=[QuerySort(field="last_seen", direction="desc"), QuerySort(field="host_id")],
        enable_continuation=True,
    )

    query = build_dataset_xql(plan, seek_values=[1000, "host-9"]).xql

    assert (
        '| filter ((last_seen < 1000) or (last_seen = 1000 and host_id > "host-9"))'
        in query
    )


def test_keyset_seek_converts_serialized_xsiam_time_to_timestamp():
    plan = DatasetQueryPlan(
        dataset="xdr_data",
        fields=["event_id"],
        order_by=[QuerySort(field="_time", direction="desc"), QuerySort(field="event_id")],
        enable_continuation=True,
    )

    query = build_dataset_xql(plan, seek_values=[1_700_000_000_000, "event-9"]).xql

    assert '_time < to_timestamp(1700000000000, "MILLIS")' in query
    assert '_time = to_timestamp(1700000000000, "MILLIS")' in query


def test_cursor_is_encrypted_principal_bound_and_policy_bound(monkeypatch):
    monkeypatch.setattr(get_config(), "dataset_query_cursor_secret", "unit-test-cursor-secret")
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["host_inventory"]}')
    plan = DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name", "host_id"],
        order_by=[QuerySort(field="host_id")],
        timeframe=QueryTimeframe(from_ms=1, to_ms=2),
        enable_continuation=True,
    )

    cursor = encode_query_cursor(plan, _principal(), ["host-1"])
    decoded_plan, values = decode_query_cursor(cursor, _principal())

    assert "host_inventory" not in cursor
    assert decoded_plan == plan
    assert values == ["host-1"]

    with pytest.raises(QueryCursorError, match="different principal"):
        decode_query_cursor(cursor, _principal(principal_id="other@example.test"))

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":[]}')
    with pytest.raises(QueryCursorError, match="policy has changed"):
        decode_query_cursor(cursor, _principal())


def test_result_budget_truncates_cells_fields_and_total_bytes(monkeypatch):
    monkeypatch.setattr(get_config(), "dataset_query_max_cell_chars", 5)
    monkeypatch.setattr(get_config(), "dataset_query_max_fields", 2)
    monkeypatch.setattr(get_config(), "dataset_query_max_response_bytes", 45)

    rows, metadata = bound_result_rows(
        [
            {"a": "abcdefgh", "b": 2, "c": 3},
            {"a": "second row", "b": 4},
        ]
    )

    assert len(rows) == 1
    assert rows[0] == {"a": "abcde...<truncated>", "b": 2}
    assert metadata["cell_truncations"] >= 1
    assert metadata["field_truncations"] == 1
    assert metadata["response_budget_exhausted"] is True


@pytest.mark.asyncio
async def test_query_dataset_live_shape_generates_cursor_without_exposing_hidden_sort_fields(monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["host_inventory"]}')
    monkeypatch.setattr(get_config(), "dataset_query_cursor_secret", "unit-test-cursor-secret")

    async def fake_run(ctx, query, result_limit, **kwargs):
        assert result_limit == 3
        assert kwargs["timeframe"]["from"] < kwargs["timeframe"]["to"]
        return {
            "query_id": "query-1",
            "reply": {
                "status": "SUCCESS",
                "number_of_results": 3,
                "results": {
                    "data": [
                        {"host_name": "a", "host_id": "1", "unrequested": "private-a"},
                        {"host_name": "b", "host_id": "2", "unrequested": "private-b"},
                        {"host_name": "c", "host_id": "3", "unrequested": "private-c"},
                    ]
                },
            },
        }

    monkeypatch.setattr(datasets, "run_xql_query", fake_run)

    response = await datasets.query_dataset(
        _ctx(),
        dataset="host_inventory",
        fields=["host_name"],
        order_by=[QuerySort(field="host_id")],
        timeframe=QueryTimeframe(relative_ms=60_000),
        limit=2,
        enable_continuation=True,
    )

    assert response["success"] is True
    assert response["returned"] == 2
    assert response["rows"] == [{"host_name": "a"}, {"host_name": "b"}]
    assert response["has_more"] is True
    assert response["continuation"]["available"] is True
    assert response["provenance"]["content_trust"] == "untrusted_data"
    assert json.dumps(response).find("query-1") >= 0


@pytest.mark.asyncio
async def test_query_dataset_keeps_cursor_at_xsiam_result_ceiling(monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["host_inventory"]}')
    monkeypatch.setattr(get_config(), "dataset_query_cursor_secret", "unit-test-cursor-secret")
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 1000)
    monkeypatch.setattr(get_config(), "dataset_query_max_response_bytes", 1_000_000)

    async def fake_run(ctx, query, result_limit, **kwargs):
        assert result_limit == 1000
        assert query.endswith("| limit 1000")
        return {
            "query_id": "query-ceiling",
            "reply": {
                "status": "SUCCESS",
                "results": {
                    "data": [
                        {"host_name": f"host-{index}", "host_id": str(index)}
                        for index in range(1000)
                    ]
                },
            },
        }

    monkeypatch.setattr(datasets, "run_xql_query", fake_run)
    response = await datasets.query_dataset(
        _ctx(),
        dataset="host_inventory",
        fields=["host_name"],
        order_by=[QuerySort(field="host_id")],
        timeframe=QueryTimeframe(from_ms=1, to_ms=2),
        limit=1000,
        enable_continuation=True,
    )

    assert response["returned"] == 999
    assert response["has_more"] is True
    assert response["continuation"]["available"] is True


@pytest.mark.asyncio
async def test_continue_dataset_query_uses_cursor_seek_and_rechecks_policy(monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["host_inventory"]}')
    monkeypatch.setattr(get_config(), "dataset_query_cursor_secret", "unit-test-cursor-secret")
    queries = []

    async def fake_run(ctx, query, result_limit, **kwargs):
        queries.append(query)
        if len(queries) == 1:
            rows = [
                {"host_name": "a", "host_id": "1"},
                {"host_name": "b", "host_id": "2"},
            ]
        else:
            rows = [{"host_name": "b", "host_id": "2"}]
        return {
            "query_id": f"query-{len(queries)}",
            "reply": {"status": "SUCCESS", "results": {"data": rows}},
        }

    monkeypatch.setattr(datasets, "run_xql_query", fake_run)
    ctx = _ctx()
    first = await datasets.query_dataset(
        ctx,
        dataset="host_inventory",
        fields=["host_name"],
        order_by=[QuerySort(field="host_id")],
        timeframe=QueryTimeframe(from_ms=1, to_ms=2),
        limit=1,
        enable_continuation=True,
    )
    second = await datasets.continue_dataset_query(ctx, first["continuation"]["cursor"])

    assert second["success"] is True
    assert '| filter ((host_id > "1"))' in queries[1]

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":[]}')
    denied = await datasets.continue_dataset_query(ctx, first["continuation"]["cursor"])
    assert denied["success"] is False
    assert denied["executed"] is False
    assert "policy has changed" in denied["error"]


@pytest.mark.asyncio
async def test_query_dataset_denies_dataset_before_execution(monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["host_inventory"]}')

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("denied dataset must not execute")

    monkeypatch.setattr(datasets, "run_xql_query", fail_if_called)
    response = await datasets.query_dataset(
        _ctx(),
        dataset="restricted_data",
        fields=["record_id"],
    )

    assert response["success"] is False
    assert response["executed"] is False
    assert "not allowed" in response["error"]
