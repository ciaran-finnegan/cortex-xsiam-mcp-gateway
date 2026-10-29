"""The cost guard and the learning layer together: what the observers see, and learned costs."""

import time

import pytest
from learning_helpers import ctx, failure, success, use_fetcher

from config.config import get_config
from usecase import cost_guard, learned_store, xql_executor
from usecase.cost_guard import CostGuardRefusal

HOUR_MS = 3_600_000
DAY_MS = 24 * HOUR_MS
HISTORY_QUERY = (
    'dataset = xql_query_center_history | filter execution_id in ("a", "b") '
    "| fields execution_id, compute_units | limit 50"
)


@pytest.fixture(autouse=True)
def guard(monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "identity_auth_mode", "none")
    monkeypatch.setattr(config, "papi_auth_header_key", "synthetic-default-key")
    monkeypatch.setattr(config, "papi_auth_id_key", "9")
    monkeypatch.setattr(config, "cost_guard_approval_threshold_units", 1.0)
    monkeypatch.setattr(config, "cost_guard_reserve_units", 10.0)
    monkeypatch.setattr(cost_guard, "_engagement", lambda: None)
    monkeypatch.setattr(cost_guard, "_catalogue_volume", lambda dataset: None)
    monkeypatch.setattr(cost_guard, "_catalogue_domain", lambda dataset: None)
    cost_guard.observe_remaining_quota(cost_guard.tenant_quota_key(), 100.0)


@pytest.fixture
def observed(monkeypatch):
    calls = []

    async def spy(ctx, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(xql_executor, "observe_xql_execution", spy)
    return calls


def _window(span_ms):
    now_ms = int(time.time() * 1000)
    return {"from_ms": now_ms - span_ms, "to_ms": now_ms}


@pytest.mark.asyncio
async def test_observers_skip_a_refused_query(monkeypatch, observed):
    fetcher = use_fetcher(monkeypatch, [])

    with pytest.raises(CostGuardRefusal):
        await xql_executor.run_xql_query(ctx(), "dataset = xdr_data | limit 5", 5, timeframe=_window(7 * DAY_MS))

    assert observed == []
    assert fetcher.requests == []


@pytest.mark.asyncio
async def test_observers_see_a_query_once_and_skip_its_cache_hit(monkeypatch, observed):
    fetcher = use_fetcher(monkeypatch, [success("q-h1", [{"execution_id": "a", "compute_units": 0.0003}], cost=0.0003)])
    # The guard caches only replies fetched with the key the cache entry was built from.
    fetcher.api_key, fetcher.api_key_id = "synthetic-default-key", "9"
    timeframe = _window(HOUR_MS)

    first = await xql_executor.run_xql_query(ctx(), HISTORY_QUERY, 50, timeframe=timeframe)
    second = await xql_executor.run_xql_query(ctx(), HISTORY_QUERY, 50, timeframe=timeframe)

    assert first["quota"]["cached"] is False
    assert second["quota"]["cached"] is True
    assert len(observed) == 1
    assert observed[0]["response"]["query_id"] == "q-h1"
    assert observed[0]["timeframe"] == {"from": timeframe["from_ms"], "to": timeframe["to_ms"]}


@pytest.mark.asyncio
async def test_failed_query_carries_the_user_class_and_the_learner_class(monkeypatch, observed):
    use_fetcher(monkeypatch, [failure("q-f1", "Unknown field: actor_x")])

    response = await xql_executor.run_xql_query(
        ctx(), 'dataset = xql_query_center_history | filter actor_x = "a" | limit 5', 5, timeframe=_window(HOUR_MS)
    )

    assert response["error"] == "xql_validation"
    assert response["class"] == "unknown_field"
    assert response["error_class"] == "unknown_field"
    assert response["unknown_field"] == "actor_x"
    assert len(observed) == 1


def test_learner_recalibration_query_is_light_by_default():
    estimate = cost_guard.estimate_xql(HISTORY_QUERY, _window(2 * DAY_MS))

    assert estimate.cost_class == "light"
    assert estimate.high_units <= get_config().cost_guard_approval_threshold_units


@pytest.mark.parametrize(
    "learned_high, learned_median, expected_high, expected_low",
    [
        (6.0, 4.0, 6.0, 4.0),  # learned above the seed band raises the estimate
        (1.2, 0.8, 1.2, 0.8),  # learned inside the band lowers it
        (0.01, 0.005, 0.5, 0.5),  # learned below the band stops at the seed low bound
    ],
)
def test_learned_cost_replaces_the_seed_units_within_the_seed_floor(
    monkeypatch, learned_high, learned_median, expected_high, expected_low
):
    lookups = []

    def lookup(dataset, bucket, selectivity):
        lookups.append((dataset, bucket, selectivity))
        return {
            "entry_id": "cost_table:synthetic",
            "median_units": learned_median,
            "high_units": learned_high,
            "observations": 4,
            "confidence": "medium",
            "units_source": "query_cost",
        }

    monkeypatch.setattr(learned_store, "lookup_cost", lookup)
    query = 'dataset = sample_auth_logs | filter user_name = "a" | limit 5'
    seed_low, seed_high = cost_guard.unit_bands()["medium"]

    estimate = cost_guard.estimate_xql(query, _window(2 * DAY_MS))

    assert (seed_low, seed_high) == (0.5, 3.6)
    assert lookups == [("sample_auth_logs", "le_7d", "selective")]
    assert estimate.cost_class == "medium"
    assert (estimate.high_units, estimate.low_units) == (expected_high, expected_low)
    assert estimate.factors["units_source"] == "learned"
    assert estimate.factors["learned_entry_id"] == "cost_table:synthetic"


def test_learned_cost_is_ignored_for_multi_dataset_queries_and_without_an_entry(monkeypatch):
    calls = []

    def lookup(*args):
        calls.append(args)

    monkeypatch.setattr(learned_store, "lookup_cost", lookup)
    single = cost_guard.estimate_xql("dataset = sample_auth_logs | limit 5", _window(HOUR_MS))
    multi = cost_guard.estimate_xql("dataset in (sample_auth_logs, alerts) | limit 5", _window(HOUR_MS))

    assert len(calls) == 1
    assert "units_source" not in single.factors
    assert "units_source" not in multi.factors


@pytest.mark.asyncio
async def test_learned_cost_drives_the_approval_rule(monkeypatch, observed):
    monkeypatch.setattr(
        learned_store,
        "lookup_cost",
        lambda *args: {
            "entry_id": "cost_table:synthetic",
            "median_units": 0.2,
            "high_units": 0.3,
            "observations": 5,
            "confidence": "high",
            "units_source": "query_cost",
        },
    )
    use_fetcher(monkeypatch, [success("q-l1", [{"user_name": "a"}], cost=0.2)])

    # Over two days the seed rates this query medium (up to 3.6 units), above the 1-unit threshold;
    # the learned entry brings it to the band's 0.5-unit floor, so the query runs without approval.
    response = await xql_executor.run_xql_query(
        ctx(), 'dataset = sample_auth_logs | filter user_name = "a" | limit 5', 5, timeframe=_window(2 * DAY_MS)
    )

    assert response["query_id"] == "q-l1"
    assert response["quota"]["estimate_units"] == 0.5
