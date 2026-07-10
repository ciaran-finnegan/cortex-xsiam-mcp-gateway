import json
import os
from types import SimpleNamespace

import pytest

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.builtin_components import datasets, logs
from usecase.dataset_query import (
    QueryMetric,
    QuerySort,
    QueryTimeBucket,
    QueryTimeframe,
)

pytestmark = pytest.mark.live


def _live_settings():
    values = {
        "url": os.getenv("XSIAM_LIVE_API_URL", ""),
        "api_key": os.getenv("XSIAM_LIVE_API_KEY", ""),
        "api_key_id": os.getenv("XSIAM_LIVE_API_KEY_ID", ""),
        "inventory_dataset": os.getenv("XSIAM_LIVE_INVENTORY_DATASET", "host_inventory"),
        "pagination_dataset": os.getenv("XSIAM_LIVE_PAGINATION_DATASET", "xdr_data"),
        "pagination_time_field": os.getenv("XSIAM_LIVE_PAGINATION_TIME_FIELD", "_time"),
        "pagination_id_field": os.getenv("XSIAM_LIVE_PAGINATION_ID_FIELD", "event_id"),
    }
    if not values["url"] or not values["api_key"] or not values["api_key_id"]:
        pytest.skip("live XSIAM credentials are not configured")
    return values


def _configure_live_context(monkeypatch, values):
    config = get_config()
    monkeypatch.setattr(config, "papi_url_env_key", values["url"])
    monkeypatch.setattr(config, "identity_auth_mode", "none")
    monkeypatch.setattr(config, "xsiam_credential_broker_enabled", False)
    monkeypatch.setattr(config, "log_search_dataset_policy", '{"LiveTest":["*"]}')
    monkeypatch.setattr(config, "dataset_query_cursor_secret", "ephemeral-live-test-cursor-secret")
    state = {}
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(
                auth_headers={
                    "Authorization": values["api_key"],
                    "X-XDR-AUTH-ID": values["api_key_id"],
                },
                principal_id="live-test-principal",
                groups=("LiveTest",),
            )
        ),
        set_state=lambda key, value: state.__setitem__(key, value),
        get_state=lambda key: state.get(key),
    )


@pytest.mark.asyncio
async def test_live_non_security_dataset_discovery_rows_and_aggregate(monkeypatch):
    values = _live_settings()
    ctx = _configure_live_context(monkeypatch, values)
    dataset = values["inventory_dataset"]

    discovery = json.loads(await logs.discover_log_fields(ctx, dataset=dataset, sample_size=5, max_fields=10))
    assert discovery["success"] == "true"
    assert discovery["field_count"] > 0
    field_names = [field["name"] for field in discovery["fields"][:2]]

    rows = await datasets.query_dataset(ctx, dataset=dataset, fields=field_names, limit=2)
    assert rows["success"] is True
    assert rows["returned"] <= 2
    assert all(set(row).issubset(field_names) for row in rows["rows"])

    aggregate = await datasets.query_dataset(
        ctx,
        dataset=dataset,
        mode="aggregate",
        metrics=[QueryMetric(function="count", alias="total")],
        limit=1,
    )
    assert aggregate["success"] is True
    assert aggregate["returned"] == 1
    assert set(aggregate["rows"][0]) == {"total"}


@pytest.mark.asyncio
async def test_live_keyset_continuation_returns_a_bounded_second_page(monkeypatch):
    values = _live_settings()
    ctx = _configure_live_context(monkeypatch, values)
    time_field = values["pagination_time_field"]
    id_field = values["pagination_id_field"]

    trend = await datasets.query_dataset(
        ctx,
        dataset=values["pagination_dataset"],
        mode="aggregate",
        metrics=[QueryMetric(function="count", alias="events_per_hour")],
        time_bucket=QueryTimeBucket(field=time_field, size=1, unit="h"),
        order_by=[QuerySort(field=time_field, direction="asc")],
        timeframe=QueryTimeframe(relative_ms=86_400_000),
        limit=3,
    )
    assert trend["success"] is True
    assert trend["returned"] <= 3
    assert all(set(row).issubset({time_field, "events_per_hour"}) for row in trend["rows"])

    first = await datasets.query_dataset(
        ctx,
        dataset=values["pagination_dataset"],
        fields=[time_field, id_field],
        order_by=[
            QuerySort(field=time_field, direction="desc"),
            QuerySort(field=id_field, direction="asc"),
        ],
        timeframe=QueryTimeframe(relative_ms=86_400_000),
        limit=1,
        enable_continuation=True,
    )
    assert first["success"] is True
    assert first["returned"] == 1
    assert first["continuation"]["available"] is True

    second = await datasets.continue_dataset_query(ctx, first["continuation"]["cursor"])
    assert second["success"] is True
    assert second["returned"] <= 1
    assert second["provenance"]["timeframe"] == first["provenance"]["timeframe"]
    if second["rows"]:
        assert second["rows"][0] != first["rows"][0]
