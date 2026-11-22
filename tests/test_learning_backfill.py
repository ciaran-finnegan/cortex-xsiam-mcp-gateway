"""The one-time history backfill: what it learns, what it refuses, and that it runs once."""

import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from learning_helpers import ctx, pack_text, principal, read_kind, settle, success

from config.config import get_config
from usecase import learned_store, learner, learning_journal, xql_executor
from usecase.builtin_components import learning as learning_tools
from usecase.learned_store import BACKFILL_SOURCE_CLASS, Observation

NOW = datetime(2026, 10, 1, tzinfo=UTC)
NOW_MS = int(NOW.timestamp() * 1000)
HOUR_MS = 3_600_000
DAY_MS = 24 * HOUR_MS
SECRET = "synthetic-secret-user"
QUERY = f'dataset = sample_auth_logs | filter user_name = "{SECRET}" | limit 5'
TENANT_KEY = "9999999999999"


@pytest.fixture(autouse=True)
def _cost_guard_off(monkeypatch):
    # test_learning_cost_guard.py covers the backfill through the guard and the real fetcher.
    monkeypatch.setattr(get_config(), "cost_guard_enabled", False)


class HistoryFetcher:
    """Answers history queries from synthetic rows, honouring the window and the limit."""

    def __init__(self, rows, cost=0.001):
        self.rows = rows
        self.cost = cost
        self.requests = []

    async def send_request(self, path, data):
        request = data["request_data"]
        self.requests.append(request)
        window = request["timeframe"]
        limit = int(re.search(r"\| limit (\d+)$", request["query"]).group(1))
        # Inclusive at both ends, and newest first: the backfill must rely on neither.
        matching = sorted(
            (row for row in self.rows if window["from"] <= row["_time"] <= window["to"]),
            key=lambda row: row["_time"],
            reverse=True,
        )
        return success(f"q-history-{len(self.requests)}", matching[:limit], cost=self.cost)


class Quota:
    """get_quota: 100 units a day by default. ``used`` may be a list, one reading per call."""

    def __init__(self, used=1.0, license_quota=36500.0):
        self.used = used
        self.license_quota = license_quota
        self.calls = 0

    async def send_request(self, path, data):
        assert path == "/xql/get_quota"
        self.calls += 1
        used = self.used.pop(0) if isinstance(self.used, list) else self.used
        return {"reply": {"daily_used_quota": used, "license_quota": self.license_quota}}


def _use_history(monkeypatch, rows, *, cost=0.001, quota=None):
    history = HistoryFetcher(rows, cost=cost)

    async def history_fetcher(context):
        return history

    monkeypatch.setattr(xql_executor, "get_fetcher", history_fetcher)
    quota = quota or Quota()

    async def quota_fetcher(context):
        return quota

    monkeypatch.setattr(learner, "get_fetcher", quota_fetcher)
    return history


def _row(execution_id, *, at=NOW_MS - HOUR_MS, query=QUERY, units=0.2, **overrides):
    return {
        "_time": at,
        "execution_id": execution_id,
        "status": "STATUS_050_DATA_DELETED",
        "status_details": None,
        "timeframe_duration_secs": 3600,
        "compute_units": units,
        "xql_query_source": "investigation",
        "xql_query": query,
        "issuer": "someone@example.com",
        **overrides,
    }


def _failed(execution_id, field_name="dest_ip", *, at=NOW_MS - HOUR_MS, query=None, message=None):
    return _row(
        execution_id,
        at=at,
        units=0,
        query=query or f'dataset = sample_auth_logs | filter {field_name} = "{SECRET}" | limit 5',
        status="STATUS_030_FAILED",
        status_details=json.dumps(
            {TENANT_KEY: "ERR_000_GENERAL_ERROR", "validation_message": message or f"unknown field {field_name}."}
        ),
    )


def _cost_entry(pack):
    # The learner's own history queries are observed like any other, under the history dataset.
    (entry,) = [entry for entry in read_kind(pack, "cost_table").values() if entry["dataset"] == "sample_auth_logs"]
    return entry


def _live_cost(units, query_id="q-live", dataset="sample_auth_logs"):
    return Observation(
        "cost_table",
        {"window_bucket": "le_1h", "selectivity": "selective", "units": units, "units_source": "query_cost"},
        (query_id,),
        "query_metadata",
        dataset,
        effect="measure",
    )


def _live_absent(field_name="dest_ip", query_id="q-live", engagement=None):
    return Observation(
        "absent_fields", {"field": field_name}, (query_id,), "query_error_class", "sample_auth_logs", engagement=engagement
    )


async def _record_live(*observations, engagement=None):
    for observation in observations:
        learned_store.register_query_id(observation.evidence[0])
    learning_journal.journal_observations(list(observations), principal=principal(), trigger="test", engagement=engagement)
    return await settle()


# --- What it learns ---


@pytest.mark.asyncio
async def test_backfill_builds_a_cost_fact_that_the_cost_guard_can_read(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_row("q-1", units=0.2), _row("q-2", units=0.4), _row("q-3", units=0.3)])

    report = await learner.run_backfill(1, 1.0)

    assert report["stopped"] is None
    assert report["outcomes"] == {"cost_table": 3}
    assert report["backfill"]["completed_at"] == NOW.isoformat()
    entry = _cost_entry(pack)
    assert entry["dataset"] == "sample_auth_logs"
    assert entry["source_class"] == BACKFILL_SOURCE_CLASS
    assert sorted(entry["evidence"]) == ["q-1", "q-2", "q-3"]
    assert entry["fact"]["window_bucket"] == "le_1h"
    assert entry["fact"]["selectivity"] == "selective"
    assert (entry["fact"]["observations"], entry["fact"]["units_source"]) == (3, "query_history")
    assert entry["fact"]["high_units"] == 0.4
    learned = learned_store.lookup_cost("sample_auth_logs", "le_1h", "selective")
    assert learned["median_units"] == 0.3
    assert learned["source_class"] == BACKFILL_SOURCE_CLASS


@pytest.mark.asyncio
async def test_backfill_classifies_the_wording_xsiam_writes_to_the_history(pack, audit_events, clock, monkeypatch):
    dotted = "xdm.target.host.hostname"
    _use_history(monkeypatch, [_failed("q-1"), _failed("q-2"), _failed("q-3", dotted)])

    report = await learner.run_backfill(1, 1.0)

    assert report["outcomes"] == {"absent_fields": 3}
    facts = {entry["fact"]["field"]: entry for entry in read_kind(pack, "absent_fields").values()}
    assert set(facts) == {"dest_ip", dotted}
    assert facts["dest_ip"]["confirmations"] == 2
    assert facts["dest_ip"]["source_class"] == BACKFILL_SOURCE_CLASS


@pytest.mark.asyncio
async def test_served_backfilled_facts_show_where_they_came_from(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_failed("q-1"), _failed("q-2")])
    await learner.run_backfill(1, 1.0)

    served = await learning_tools.get_learned_facts(ctx(("Security",)), kind="absent_fields")

    (entry,) = served["entries"]
    assert entry["source_class"] == BACKFILL_SOURCE_CLASS
    assert entry["trust"] == {"label": "learned", "confirmations": 2, "engagements": 0}


# --- What it reads and keeps ---


@pytest.mark.asyncio
async def test_backfill_excludes_system_and_never_selects_who_ran_a_query(pack, audit_events, clock, monkeypatch):
    history = _use_history(monkeypatch, [_row("q-1")])

    await learner.run_backfill(1, 1.0)

    query = history.requests[0]["query"]
    assert query.startswith("dataset = xql_query_center_history")
    assert 'issuer != "System"' in query
    assert "issuer" not in query.split("| fields", 1)[1]
    assert "sort" not in query


@pytest.mark.asyncio
async def test_query_text_identities_and_tenant_keys_stay_out_of_every_output(pack, audit_events, clock, monkeypatch):
    rows = [_row("q-1"), _row("q-2"), _row("q-3"), _failed("q-4")]
    _use_history(monkeypatch, rows)

    report = await learner.run_backfill(1, 1.0)
    await settle()

    written = pack_text(pack)
    emitted = json.dumps(audit_events) + json.dumps(report)
    assert "cost_table" in report["outcomes"]
    for forbidden in (SECRET, "someone@example.com", TENANT_KEY, "ERR_000_GENERAL_ERROR", "filter user_name"):
        assert forbidden not in written
        assert forbidden not in emitted


@pytest.mark.asyncio
async def test_backfill_audits_each_query_and_the_run_as_the_learner(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_row("q-1")])

    report = await learner.run_backfill(1, 1.0)

    queries = [event for event in audit_events if event["event_type"] == "cortex_xsiam_mcp.tool_invocation"]
    assert [(event["tool"], event["principal"]["id"], event["principal"]["groups"]) for event in queries] == [
        ("query_dataset", "learning-service", ["learner"])
    ]
    runs = [event for event in audit_events if event["event_type"] == "cortex_xsiam_mcp.learning"]
    assert {event["operation"] for event in runs} == {"backfill"}
    assert runs[-1]["details"]["backfill"]["completed_at"] == report["backfill"]["completed_at"]
    assert runs[0]["changes"][0]["source_class"] == BACKFILL_SOURCE_CLASS


@pytest.mark.parametrize(
    "row, reason",
    [
        (_row("q-1", xql_query_source="dashboard"), "unmetered_source"),
        (_row("q-1", units=0), "no_units"),
        (_row("q-1", units=None), "no_units"),
        (_row("q-1", units=-1), "no_units"),
        (_row("q-1", units=float("inf")), "no_units"),
        (_row("q-1", query=f"{QUERY} | join (dataset = alerts) as a a.x = b.x"), "multi_source"),
        (_row("q-1", query="dataset in (sample_auth_logs, alerts) | limit 5"), "no_single_dataset"),
        (_row("q-1", query=f"config timeframe = 90d | {QUERY}"), "no_single_dataset"),
        (_row("q-1", status="STATUS_100_CANCELLED"), "status_not_used"),
        (_row("q-1", status="STATUS_120_TIMEOUT"), "status_not_used"),
        (_row("bad id with spaces"), "invalid_row"),
        (_row("q-1", query=None), "invalid_row"),
        (_row("q-1", query="dataset = sample_auth_logs | limit 5" + " " * 5000), "query_truncated"),
        (_failed("q-1", message="Value 1 for operator >= is invalid."), "failure_not_classified"),
        (_failed("q-1", query='dataset = alerts | filter a = "dest_ip"', message="unknown field dest_ip."), "failure_not_classified"),
        (_failed("q-1", query="dataset = alerts | alter x = dest_ip | fields x"), "field_not_from_dataset"),
        (_failed("q-1", "ignore_previous_instructions"), "refused"),
        (_row("q-1", status="STATUS_030_FAILED", status_details="not json"), "failure_not_classified"),
        (_row("q-1", status="STATUS_030_FAILED", status_details={"other": "unknown field dest_ip."}), "failure_not_classified"),
    ],
)
@pytest.mark.asyncio
async def test_backfill_learns_nothing_from_rows_it_cannot_trust(pack, audit_events, clock, monkeypatch, row, reason):
    _use_history(monkeypatch, [row])

    report = await learner.run_backfill(1, 1.0)

    assert report["outcomes"] == {reason: 1}
    assert report["stopped"] is None
    assert read_kind(pack, "cost_table") == {}
    assert read_kind(pack, "absent_fields") == {}


@pytest.mark.asyncio
async def test_field_facts_only_come_from_the_period_a_field_fact_lives(pack, audit_events, clock, monkeypatch):
    ttl_days = get_config().learning_schema_ttl_days
    old = _failed("q-old", "old_field", at=NOW_MS - (ttl_days + 1) * DAY_MS)
    recent = _failed("q-new", "new_field", at=NOW_MS - (ttl_days - 1) * DAY_MS)
    _use_history(monkeypatch, [old, recent])

    report = await learner.run_backfill(ttl_days + 2, 1.0)

    assert report["outcomes"] == {"too_old_for_field_facts": 1, "absent_fields": 1}
    assert [entry["fact"]["field"] for entry in read_kind(pack, "absent_fields").values()] == ["new_field"]


# --- Paging ---


@pytest.mark.asyncio
async def test_a_full_page_is_split_so_every_row_counts_exactly_once(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 2)
    start = NOW_MS - DAY_MS
    rows = [_row(f"q-{index}", at=start + index * HOUR_MS) for index in range(7)]
    history = _use_history(monkeypatch, rows)

    report = await learner.run_backfill(1, 1.0)

    assert report["backfill"]["rows"] == 7
    assert _cost_entry(pack)["fact"]["observations"] == 7
    assert len(history.requests) > 1
    assert report["full_windows"] == 0


@pytest.mark.asyncio
async def test_a_row_on_a_slice_boundary_is_counted_once(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_row("q-boundary", at=NOW_MS - DAY_MS)])

    report = await learner.run_backfill(2, 1.0)

    assert report["backfill"]["rows"] == 1
    assert _cost_entry(pack)["fact"]["observations"] == 1


@pytest.mark.asyncio
async def test_a_window_too_small_to_split_is_reported(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 2)
    at = NOW_MS - HOUR_MS
    _use_history(monkeypatch, [_row(f"q-{index}", at=at) for index in range(3)])

    report = await learner.run_backfill(1, 1.0)

    assert report["full_windows"] == 1
    assert report["backfill"]["rows"] == 2


@pytest.mark.asyncio
async def test_slices_respect_a_lower_maximum_timeframe(pack, audit_events, clock, monkeypatch):
    modes = ("incident_response", "threat_hunt", "operations", "unset")
    monkeypatch.setattr(get_config(), "engagement_mode_policy", json.dumps({mode: {"default_window_ms": HOUR_MS} for mode in modes}))
    monkeypatch.setattr(get_config(), "dataset_query_max_timeframe_ms", HOUR_MS)
    history = _use_history(monkeypatch, [])

    report = await learner.run_backfill(1, 1.0)

    assert report["stopped"] is None
    assert len(history.requests) == 24


# --- Runs once, resumes, stays in budget ---


@pytest.mark.asyncio
async def test_a_finished_backfill_refuses_to_run_twice(pack, audit_events, clock, monkeypatch):
    history = _use_history(monkeypatch, [_row("q-1")])
    await learner.run_backfill(1, 1.0)
    requests = len(history.requests)

    second = await learner.run_backfill(30, 1.0)

    assert second["skipped"] == "already_completed"
    assert second["backfill"]["to_ms"] == NOW_MS
    assert len(history.requests) == requests
    assert _cost_entry(pack)["fact"]["observations"] == 1


@pytest.mark.asyncio
async def test_a_run_stops_at_its_budget_and_the_next_resumes_without_double_counting(pack, audit_events, clock, monkeypatch):
    rows = [_row(f"q-{index}", at=NOW_MS - index * DAY_MS - HOUR_MS) for index in range(3)]
    history = _use_history(monkeypatch, rows, cost=0.2)

    first = await learner.run_backfill(3, 0.1)

    assert first["stopped"] == "budget"
    assert first["this_run"] == {"queries": 1, "units_at_most": 0.2}
    assert first["backfill"]["completed_at"] is None
    assert first["backfill"]["next_ms"] == NOW_MS - 2 * DAY_MS
    assert json.loads((pack / "learned" / "learner_spend.json").read_text())["units"] == 0.2
    assert len(history.requests) == 1

    # The range was fixed by the first run; a different --days does not move it.
    second = await learner.run_backfill(30, 5.0)

    assert second["stopped"] is None
    assert second["backfill"]["from_ms"] == NOW_MS - 3 * DAY_MS
    assert second["backfill"]["queries"] == 3
    assert second["backfill"]["units_at_most"] == 0.6
    assert _cost_entry(pack)["fact"]["observations"] == 3
    assert len(history.requests) == 3


@pytest.mark.asyncio
async def test_a_stopped_slice_still_records_what_it_spent(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 1)
    start = NOW_MS - DAY_MS
    rows = [_row(f"q-{index}", at=start + index * HOUR_MS) for index in range(3)]
    _use_history(monkeypatch, rows, cost=0.2)

    report = await learner.run_backfill(1, 0.1)

    assert report["stopped"] == "budget"
    assert report["backfill"]["rows"] == 0
    assert report["backfill"]["next_ms"] == start
    assert report["backfill"]["queries"] == 1
    assert report["backfill"]["units_at_most"] == 0.2
    assert read_kind(pack, "cost_table") == {}


@pytest.mark.asyncio
async def test_cost_falls_back_to_the_drop_in_quota(pack, audit_events, clock, monkeypatch):
    # XSIAM's reply carries remaining_quota and no query_cost, so the budget reads get_quota around the query,
    # and anything else that ran meanwhile counts too.
    quota = Quota(used=[1.0, 1.25])
    history = _use_history(monkeypatch, [_row("q-1")], cost=None, quota=quota)

    report = await learner.run_backfill(1, 1.0)

    assert report["this_run"] == {"queries": 1, "units_at_most": 0.25}
    assert len(history.requests) == 1


@pytest.mark.asyncio
async def test_an_unknown_cost_counts_as_the_whole_budget(pack, audit_events, clock, monkeypatch):
    quota = Quota(used=[1.0, None, 1.0])
    rows = [_row(f"q-{index}", at=NOW_MS - index * DAY_MS - HOUR_MS) for index in range(2)]
    history = _use_history(monkeypatch, rows, cost=None, quota=quota)

    report = await learner.run_backfill(2, 1.0)

    assert report["stopped"] == "budget"
    assert report["this_run"] == {"queries": 1, "units_at_most": 1.0}
    assert len(history.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "quota, reason",
    [(Quota(used=95.0), "below_reserve"), (Quota(used=None), "quota_unknown")],
)
async def test_nothing_is_queried_below_the_reserve_or_without_a_quota_reading(pack, audit_events, clock, monkeypatch, quota, reason):
    history = _use_history(monkeypatch, [_row("q-1")], quota=quota)

    report = await learner.run_backfill(1, 1.0)

    assert report["stopped"] == reason
    assert history.requests == []
    assert report["backfill"]["completed_at"] is None


@pytest.mark.asyncio
async def test_a_failed_query_stops_the_run_and_keeps_the_slice(pack, audit_events, clock, monkeypatch):
    history = _use_history(monkeypatch, [_row("q-1")])

    async def fails(path, data):
        history.requests.append(data["request_data"])
        return {"reply": {"status": "FAILED", "query_id": "q-f", "error_message": "XQL query failed"}}

    monkeypatch.setattr(history, "send_request", fails)

    report = await learner.run_backfill(1, 1.0)

    assert report["stopped"] == "query_failed"
    assert report["backfill"]["next_ms"] == NOW_MS - DAY_MS


@pytest.mark.asyncio
async def test_a_concurrent_run_cannot_count_a_slice_twice(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_row("q-1")])
    real_slice = learner._backfill_slice

    async def another_run_commits_first(run, start, end):
        rows, stopped = await real_slice(run, start, end)
        state = learner.load_state(pack)
        state["backfill"]["next_ms"] = end
        learner.save_state(pack, state)
        return rows, stopped

    monkeypatch.setattr(learner, "_backfill_slice", another_run_commits_first)

    report = await learner.run_backfill(1, 1.0)

    assert report["stopped"] == "concurrent_run"
    assert read_kind(pack, "cost_table") == {}


# --- Live facts outrank history ---


@pytest.mark.asyncio
async def test_a_fact_the_gateway_measured_live_is_left_alone(pack, audit_events, clock, monkeypatch):
    await _record_live(_live_cost(0.5))
    before = _cost_entry(pack)
    _use_history(monkeypatch, [_row("q-1", units=9.0), _row("q-2", units=9.0)])

    report = await learner.run_backfill(1, 1.0)

    assert report["outcomes"] == {"kept_live_fact": 2}
    assert _cost_entry(pack) == before


@pytest.mark.asyncio
async def test_a_live_absent_field_is_not_confirmed_by_history(pack, audit_events, clock, monkeypatch):
    await _record_live(_live_absent())
    _use_history(monkeypatch, [_failed("q-1")])

    report = await learner.run_backfill(1, 1.0)

    assert report["outcomes"] == {"kept_live_fact": 1}
    (entry,) = read_kind(pack, "absent_fields").values()
    assert entry["confirmations"] == 1
    assert entry["source_class"] == "query_error_class"


@pytest.mark.asyncio
async def test_an_old_failure_cannot_contradict_a_discovered_field(pack, audit_events, clock, monkeypatch):
    discovered = Observation("schema", {"field": "dest_ip", "type": "string"}, ("q-live",), "field_discovery_sample", "sample_auth_logs")
    await _record_live(discovered)
    _use_history(monkeypatch, [_failed("q-1")])

    report = await learner.run_backfill(1, 1.0)

    assert report["outcomes"] == {"kept_live_fact": 1}
    assert read_kind(pack, "absent_fields") == {}
    (entry,) = read_kind(pack, "schema").values()
    assert (entry["status"], entry["contradictions"]) == ("active", 0)


@pytest.mark.asyncio
async def test_a_reverted_backfilled_fact_is_not_relearned_on_resume(pack, audit_events, clock, monkeypatch):
    rows = [_failed("q-1", at=NOW_MS - DAY_MS - HOUR_MS), _failed("q-2", at=NOW_MS - HOUR_MS)]
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Admin": ["*"], "learner": ["xql_query_center_history"]}')
    _use_history(monkeypatch, rows, cost=0.2)
    await learner.run_backfill(2, 0.1)
    (entry,) = read_kind(pack, "absent_fields").values()
    requested = await learning_tools.revert_learned(ctx(("Admin",)), entry_id=entry["entry_id"])
    assert requested["success"] is True
    await settle()

    await learner.run_backfill(2, 5.0)

    (entry,) = read_kind(pack, "absent_fields").values()
    assert (entry["status"], entry["confirmations"]) == ("reverted", 1)


# --- Verification and contradiction ---


@pytest.mark.asyncio
async def test_history_alone_never_raises_confidence_or_opens_verification(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_failed(f"q-{index}") for index in range(8)])

    await learner.run_backfill(1, 1.0)

    (entry,) = read_kind(pack, "absent_fields").values()
    assert entry["confirmations"] == 8
    assert (entry["streak"], entry["confidence"]) == (1, 0.5)
    assert (entry["verify_engagements"], entry["verify_window_start"], entry["verified_at"]) == ([], None, None)


@pytest.mark.asyncio
async def test_verification_still_needs_live_confirmations_after_a_backfill(pack, audit_events, clock, monkeypatch):
    engagements = ["1" * 64, "2" * 64, "3" * 64]
    _use_history(monkeypatch, [_failed(f"q-{index}") for index in range(8)])
    await learner.run_backfill(1, 1.0)

    # The window opens at the first live confirmation, not at the backfill.
    clock["now"] = NOW + timedelta(days=30)
    await _record_live(_live_absent(query_id="q-live-1"), engagement=engagements[0])
    clock["now"] = NOW + timedelta(days=31)
    await _record_live(_live_absent(query_id="q-live-2"), engagement=engagements[1])
    await _record_live(_live_absent(query_id="q-live-3"), engagement=engagements[2])
    (entry,) = read_kind(pack, "absent_fields").values()
    assert entry["verified_at"] is None
    assert entry["source_class"] == "query_error_class"
    assert len(entry["verify_engagements"]) == 3

    clock["now"] = NOW + timedelta(days=38)
    await _record_live(_live_absent(query_id="q-live-4"), engagement=engagements[0])
    (entry,) = read_kind(pack, "absent_fields").values()
    assert entry["verified_at"] is not None
    assert entry["streak"] == 5


@pytest.mark.asyncio
async def test_an_expensive_old_query_widens_the_range_instead_of_demoting(pack, audit_events, clock, monkeypatch):
    start = NOW_MS - DAY_MS
    costs = [0.1, 0.1, 0.1, 5.0]
    _use_history(monkeypatch, [_row(f"q-{index}", at=start + index * HOUR_MS, units=units) for index, units in enumerate(costs)])

    await learner.run_backfill(1, 1.0)

    entry = _cost_entry(pack)
    assert (entry["status"], entry["contradictions"]) == ("active", 0)
    assert entry["fact"]["high_units"] == 5.0


@pytest.mark.asyncio
async def test_a_live_outlier_still_demotes_a_backfilled_cost(pack, audit_events, clock, monkeypatch):
    start = NOW_MS - DAY_MS
    _use_history(monkeypatch, [_row(f"q-{index}", at=start + index * HOUR_MS, units=0.2) for index in range(3)])
    await learner.run_backfill(1, 1.0)

    await _record_live(_live_cost(50.0))

    assert _cost_entry(pack)["status"] == "demoted"


# --- Refusals and the command line ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setting, value",
    [
        ("log_search_dataset_policy", '{"Security": ["*"]}'),
        ("tool_access_policy", '{"Security": ["*"]}'),
    ],
)
async def test_backfill_needs_the_learner_policies(pack, audit_events, clock, monkeypatch, setting, value):
    history = _use_history(monkeypatch, [_row("q-1")])
    monkeypatch.setattr(get_config(), setting, value)

    report = await learner.run_backfill(1, 1.0)

    assert report == {"command": "backfill", "skipped": "not_authorized"}
    assert history.requests == []


@pytest.mark.asyncio
async def test_backfill_obeys_the_kill_switch(pack, audit_events, clock, monkeypatch):
    history = _use_history(monkeypatch, [_row("q-1")])
    monkeypatch.setattr(get_config(), "learning_enabled", False)

    assert (await learner.run_backfill(1, 1.0))["skipped"] == "learning_disabled"
    assert history.requests == []
    assert not (pack / "learned" / "learner_state.json").exists()


@pytest.mark.asyncio
async def test_backfill_needs_a_tenant_pack(clock, monkeypatch):
    monkeypatch.setattr(get_config(), "learning_enabled", True)
    monkeypatch.setattr(get_config(), "tenant_pack_dir", "")

    assert (await learner.run_backfill(1, 1.0))["skipped"] == "no_tenant_pack"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "days, max_units",
    [(0, 1.0), (366, 1.0), (True, 1.0), (1, 0.0), (1, -1.0), (1, 101.0), (1, float("nan"))],
)
async def test_backfill_refuses_out_of_range_arguments(pack, days, max_units):
    with pytest.raises(ValueError):
        await learner.run_backfill(days, max_units)


@pytest.mark.asyncio
async def test_status_reports_progress_and_a_tick_keeps_it(pack, audit_events, clock, monkeypatch):
    _use_history(monkeypatch, [_row("q-1")], cost=0.2)
    await learner.run_backfill(2, 0.1)

    await settle()

    status = await learner.run("status")
    assert status["backfill"]["next_ms"] == NOW_MS - DAY_MS
    assert status["backfill"]["completed_at"] is None


def test_cli_requires_both_flags_and_refuses_them_elsewhere(pack):
    from learner.__main__ import main

    for arguments in (["backfill"], ["backfill", "--days", "1"], ["backfill", "--max-units", "1"], ["tick", "--days", "1"]):
        with pytest.raises(SystemExit) as refused:
            main(arguments)
        assert refused.value.code == 2


def test_cli_exit_codes_say_whether_the_backfill_finished(pack, capsys, monkeypatch):
    from learner.__main__ import main

    _use_history(monkeypatch, [], cost=0.2)

    assert main(["backfill", "--days", "2", "--max-units", "0.1"]) == 1
    assert json.loads(capsys.readouterr().out)["stopped"] == "budget"
    assert main(["backfill", "--days", "2", "--max-units", "5"]) == 0
    assert json.loads(capsys.readouterr().out)["stopped"] is None
    assert main(["backfill", "--days", "2", "--max-units", "5"]) == 0
    assert json.loads(capsys.readouterr().out)["skipped"] == "already_completed"
    assert main(["backfill", "--days", "999", "--max-units", "5"]) == 2
