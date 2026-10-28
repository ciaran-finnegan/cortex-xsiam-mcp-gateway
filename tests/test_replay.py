import json
import stat

import pytest
from learning_helpers import ctx, pack_text, success, use_fetcher

from config.config import get_config
from usecase import learning_observers, replay, xql_executor
from usecase.learned_store import LearnedStoreError
from usecase.replay import replay_engagement

CASE_ID = "IR-SYNTH-0001"
TRIAGE_BY_RULE = {
    "dataset": "alerts",
    "mode": "aggregate",
    "filters": [{"field": "alert_source", "operator": "contains", "value": "SYNTH_IOC"}],
    "metrics": [{"function": "count", "alias": "alerts"}],
    "group_by": ["alert_name"],
    "order_by": [{"field": "alerts", "direction": "desc"}],
    "timeframe": {"relative_ms": 86_400_000},
    "limit": 10,
}
TRIAGE_BY_HOST = {**TRIAGE_BY_RULE, "group_by": ["host_name"]}
FIELD_CHECK = {"dataset": "xdr_data", "field_name_contains": "hash"}


async def _step(tool, arguments, query, response, payload, outcome="success"):
    token = learning_observers.begin_tool_call(tool, ctx())
    await xql_executor.run_xql_query(ctx(), query, 10, timeframe={"relativeTime": 86_400_000})
    await learning_observers.end_tool_call(token, outcome=outcome, payload=payload, arguments=arguments)


async def _fact(key, evidence_query_id):
    token = learning_observers.begin_tool_call("record_fact", ctx())
    await learning_observers.end_tool_call(
        token,
        outcome="success",
        payload={"success": True},
        arguments={"key": key, "value": "synthetic", "evidence_query_id": evidence_query_id, "confidence": "high"},
    )


@pytest.fixture
def recorded_ioc_flood(pack, audit_events, clock, monkeypatch):
    """A synthetic IOC-flood triage: alerts by rule, alerts by host, a field check, two engagement facts."""
    monkeypatch.setattr(learning_observers, "current_case_id", lambda: CASE_ID)
    use_fetcher(
        monkeypatch,
        [
            success("q-r1", [{"alert_name": "Synthetic IOC rule", "alerts": 412}], cost=0.4),
            success("q-r2", [{"host_name": "synthetic-host-01", "alerts": 377}], cost=1.1),
            success("q-r3", [{"action_file_sha256": "0" * 64}], cost=0.1),
        ],
    )

    async def build():
        await _step(
            "query_dataset",
            TRIAGE_BY_RULE,
            'dataset = alerts | filter (alert_source contains "SYNTH_IOC") | comp count() as alerts by alert_name | limit 10',
            None,
            {
                "rows": [{"alert_name": "Synthetic IOC rule", "alerts": 412}],
                "continuation": {"available": True, "cursor": "opaque-principal-bound-cursor"},
            },
        )
        await _fact("ioc.flood.top_rule", "q-r1")
        await _step(
            "query_dataset",
            TRIAGE_BY_HOST,
            'dataset = alerts | filter (alert_source contains "SYNTH_IOC") | comp count() as alerts by host_name | limit 10',
            None,
            {"rows": [{"host_name": "synthetic-host-01", "alerts": 377}]},
        )
        await _fact("ioc.flood.top_host", "q-r2")
        await _step(
            "discover_log_fields",
            FIELD_CHECK,
            "dataset = xdr_data | limit 25",
            None,
            {"fields": [{"name": "action_file_sha256", "type": "string"}]},
        )

    return build


@pytest.mark.asyncio
async def test_replay_of_recorded_engagement_reports_queries_units_and_facts(pack, recorded_ioc_flood, monkeypatch):
    await recorded_ioc_flood()

    async def no_live_queries(ctx):
        raise AssertionError("replay must not call XSIAM")

    monkeypatch.setattr(xql_executor, "get_fetcher", no_live_queries)

    report = replay_engagement(CASE_ID)

    assert report["sequence"] == "recorded"
    assert report["quota_units_spent"] == 0
    assert (report["steps"], report["cache_hits"], report["cache_misses"]) == (3, 3, 0)
    assert report["queries"] == 3
    assert report["units"] == 1.6
    assert report["facts_reached"] == ["ioc.flood.top_host", "ioc.flood.top_rule"]
    assert report["facts_missed"] == []


@pytest.mark.asyncio
async def test_replay_of_candidate_sequence_compares_with_the_recorded_baseline(pack, recorded_ioc_flood):
    await recorded_ioc_flood()

    candidate = [
        {"tool": "query_dataset", "arguments": TRIAGE_BY_RULE},
        {"tool": "query_dataset", "arguments": {**TRIAGE_BY_RULE, "limit": 25}},
    ]
    report = replay_engagement(CASE_ID, candidate=candidate)

    assert report["sequence"] == "candidate"
    assert (report["cache_hits"], report["cache_misses"]) == (1, 1)
    assert report["queries"] == 1
    assert report["units"] == 0.4
    assert report["facts_reached"] == ["ioc.flood.top_rule"]
    assert report["facts_missed"] == ["ioc.flood.top_host"]
    assert report["misses"][0]["position"] == 1
    assert report["baseline"]["queries"] == 3
    assert report["quota_units_spent"] == 0

    by_hash = replay_engagement(
        CASE_ID,
        candidate=[{"tool": "query_dataset", "arguments_sha256": replay.arguments_hash(TRIAGE_BY_HOST)}],
    )
    assert by_hash["facts_reached"] == ["ioc.flood.top_host"]


@pytest.mark.asyncio
async def test_result_cache_holds_bounded_results_without_cursors_or_argument_values(pack, recorded_ioc_flood, audit_events):
    await recorded_ioc_flood()

    results = pack / "engagements" / CASE_ID / "results"
    manifest = json.loads((results / "manifest.json").read_text())
    assert [step["tool"] for step in manifest["steps"]] == ["query_dataset", "query_dataset", "discover_log_fields"]
    assert manifest["steps"][0]["query_ids"] == ["q-r1"]
    assert manifest["steps"][0]["argument_names"] == sorted(TRIAGE_BY_RULE)
    assert manifest["facts"] == [
        {"key": "ioc.flood.top_rule", "evidence_query_id": "q-r1"},
        {"key": "ioc.flood.top_host", "evidence_query_id": "q-r2"},
    ]
    first = json.loads((results / "0000.json").read_text())
    assert first["continuation"] == {"available": True}
    assert "SYNTH_IOC" not in (results / "manifest.json").read_text()
    assert "synthetic" not in (results / "manifest.json").read_text()
    for path in results.iterdir():
        if path.name != ".lock":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert (pack / "engagements" / ".gitignore").read_text() == "*/results/\n"
    cache_events = [event for event in audit_events if event["operation"] == "cache_result"]
    assert [event["details"]["position"] for event in cache_events] == [0, 1, 2]
    assert cache_events[0]["details"]["case_id"] == CASE_ID


@pytest.mark.asyncio
async def test_result_cache_is_capped_and_capped_steps_replay_as_misses(pack, recorded_ioc_flood, monkeypatch):
    first_result = {"rows": [{"alert_name": "Synthetic IOC rule", "alerts": 412}], "continuation": {"available": True}}
    first_size = len(json.dumps(first_result, sort_keys=True, separators=(",", ":")).encode())
    monkeypatch.setattr(get_config(), "learning_result_cache_max_bytes", first_size)

    await recorded_ioc_flood()

    manifest = json.loads((pack / "engagements" / CASE_ID / "results" / "manifest.json").read_text())
    assert [step["cache_note"] for step in manifest["steps"]] == [None, "cache_full", "cache_full"]
    assert manifest["bytes"] == first_size
    report = replay_engagement(CASE_ID)
    assert (report["cache_hits"], report["cache_misses"]) == (1, 2)
    assert report["facts_missed"] == ["ioc.flood.top_host"]


@pytest.mark.asyncio
async def test_oversized_results_are_not_cached(pack, recorded_ioc_flood, monkeypatch):
    monkeypatch.setattr(get_config(), "learning_result_max_bytes", 10)

    await recorded_ioc_flood()

    manifest = json.loads((pack / "engagements" / CASE_ID / "results" / "manifest.json").read_text())
    assert {step["cache_note"] for step in manifest["steps"]} == {"result_too_large"}
    assert not list((pack / "engagements" / CASE_ID / "results").glob("0*.json"))


@pytest.mark.asyncio
async def test_result_cache_writes_nothing_while_learning_is_frozen(pack, recorded_ioc_flood, monkeypatch):
    monkeypatch.setattr(get_config(), "learning_enabled", False)

    await recorded_ioc_flood()

    assert not (pack / "engagements").exists()
    assert pack_text(pack) == ""


@pytest.mark.asyncio
async def test_replay_rejects_unknown_cases_and_bad_input(pack, recorded_ioc_flood):
    await recorded_ioc_flood()

    with pytest.raises(ValueError, match="No recorded engagement"):
        replay_engagement("IR-SYNTH-9999")
    with pytest.raises(ValueError, match="case_id"):
        replay_engagement("../IR-SYNTH-0001")
    with pytest.raises(ValueError):
        replay_engagement(CASE_ID, candidate=[{"arguments": TRIAGE_BY_RULE}])
    with pytest.raises(ValueError):
        replay_engagement(CASE_ID, candidate=[{"tool": "query_dataset", "arguments_sha256": "not-a-digest"}])


def test_replay_needs_a_tenant_pack(monkeypatch):
    monkeypatch.setattr(get_config(), "tenant_pack_dir", "")

    with pytest.raises(LearnedStoreError):
        replay_engagement(CASE_ID)


@pytest.mark.asyncio
async def test_no_case_means_no_result_cache(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(learning_observers, "current_case_id", lambda: None)
    use_fetcher(monkeypatch, [success("q-n1", [{"n": 1}], cost=0.2)])

    await _step("query_dataset", TRIAGE_BY_RULE, "dataset = alerts | limit 1", None, {"rows": []})

    assert not (pack / "engagements").exists()
