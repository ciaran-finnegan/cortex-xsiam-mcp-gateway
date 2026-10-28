import json
import stat
from datetime import timedelta

import pytest
from fastmcp import Client
from learning_helpers import (
    INJECTION,
    ctx,
    failure,
    pack_text,
    principal,
    read_kind,
    success,
    use_fetcher,
)

from config.config import get_config
from pkg.util import MAIN_DIR
from service.cortex_mcp.server import create_mcp_server
from usecase import learned_store, learning_observers, xql_executor
from usecase.audit import AuditExportError
from usecase.builtin_components import learning as learning_tools
from usecase.builtin_components import logs
from usecase.builtin_components.datasets import DatasetsModule
from usecase.builtin_components.learning import LearningModule
from usecase.learned_store import LearnedStoreError, Observation


def _issue(*query_ids):
    for query_id in query_ids:
        learned_store.register_query_id(query_id)


def _schema(field="action_file_path", field_type="string", query_id="q-1", dataset="xdr_data"):
    return Observation("schema", {"field": field, "type": field_type}, (query_id,), "field_discovery_sample", dataset)


def _cost(units=0.5, query_id="q-2", dataset="xdr_data"):
    return Observation(
        "cost_table",
        {"window_bucket": "le_24h", "selectivity": "selective", "units": units, "units_source": "query_cost"},
        (query_id,),
        "query_metadata",
        dataset,
        effect="measure",
    )


async def _record(*observations, who=None):
    return await learned_store.record_observations(list(observations), principal=who or principal(), trigger="test")


async def _run(context, query, timeframe=None, limit=25):
    return await xql_executor.run_xql_query(context, query, limit, timeframe=timeframe)


# --- Store: entries, lifecycle, expiry ---


@pytest.mark.asyncio
async def test_observation_writes_one_file_per_kind_with_provenance(pack, audit_events, clock):
    _issue("q-1")

    changes = await _record(_schema())

    assert [change["action"] for change in changes] == ["learned"]
    path = pack / "learned" / "schema.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((pack / "learned").stat().st_mode) == 0o700
    (entry,) = read_kind(pack, "schema").values()
    assert entry["fact"] == {"field": "action_file_path", "type": "string"}
    assert entry["evidence"] == ["q-1"]
    assert entry["first_seen"] == entry["last_seen"] == "2026-10-01T00:00:00+00:00"
    assert (entry["confirmations"], entry["contradictions"], entry["confidence"]) == (1, 0, 0.5)
    assert entry["expires_at"] == "2026-10-31T00:00:00+00:00"
    assert entry["source_class"] == "field_discovery_sample"
    assert entry["status"] == "active"
    (event,) = audit_events
    assert event["event_type"] == "cortex_xsiam_mcp.learning"
    assert event["operation"] == "observe"
    assert event["actions"] == {"learned": 1}
    assert event["changes"][0]["entry_id"] == entry["entry_id"]
    assert event["changes"][0]["evidence"] == ["q-1"]


@pytest.mark.asyncio
async def test_confirmation_raises_confidence_and_contradiction_demotes_at_once(pack, audit_events, clock):
    _issue("q-1", "q-2", "q-3", "q-4", "q-5")
    await _record(_schema(query_id="q-1"))
    await _record(_schema(query_id="q-2"))
    (entry,) = read_kind(pack, "schema").values()
    assert (entry["confirmations"], entry["confidence"]) == (2, 0.75)

    changes = await _record(_schema(field_type="integer", query_id="q-3"))

    assert [change["action"] for change in changes] == ["demoted"]
    (entry,) = read_kind(pack, "schema").values()
    assert entry["status"] == "demoted"
    assert (entry["contradictions"], entry["confidence"]) == (1, 0.0)
    assert entry["fact"]["type"] == "integer"
    assert entry["previous_fact"]["type"] == "string"
    assert changes[0]["previous_fact"] == {"field": "action_file_path", "type": "string"}
    assert learned_store.read_entries("schema") == []

    assert [change["action"] for change in await _record(_schema(field_type="integer", query_id="q-4"))] == ["confirmed"]
    assert learned_store.read_entries("schema") == []
    assert [change["action"] for change in await _record(_schema(field_type="integer", query_id="q-5"))] == ["promoted"]
    (served,) = learned_store.read_entries("schema")
    assert served["fact"]["type"] == "integer"
    assert served["evidence"] == ["q-1", "q-2", "q-3", "q-4", "q-5"]


@pytest.mark.asyncio
async def test_cost_far_above_learned_range_demotes_the_cost_entry(pack, audit_events, clock):
    _issue("q-1", "q-2", "q-3", "q-4")
    for query_id in ("q-1", "q-2", "q-3"):
        await _record(_cost(units=1.0, query_id=query_id))

    changes = await _record(_cost(units=9.0, query_id="q-4"))

    assert [change["action"] for change in changes] == ["demoted"]
    (entry,) = read_kind(pack, "cost_table").values()
    assert entry["fact"]["high_units"] == 9.0
    assert learned_store.lookup_cost("xdr_data", "le_24h", "selective") is None


@pytest.mark.asyncio
async def test_expiry_defaults_to_30_days_for_schema_and_90_for_cost(pack, audit_events, clock, monkeypatch):
    _issue("q-1", "q-2", "q-3")
    await _record(_schema(query_id="q-1"), _cost(query_id="q-2"))
    assert next(iter(read_kind(pack, "schema").values()))["expires_at"] == "2026-10-31T00:00:00+00:00"
    assert next(iter(read_kind(pack, "cost_table").values()))["expires_at"] == "2026-12-30T00:00:00+00:00"

    clock["now"] += timedelta(days=31)
    assert learned_store.read_entries("schema") == []
    changes = await learned_store.sweep_expired(principal=principal())

    assert [(change["action"], change["kind"]) for change in changes] == [("expired", "schema")]
    assert read_kind(pack, "schema") == {}
    assert len(read_kind(pack, "cost_table")) == 1
    assert audit_events[-1]["operation"] == "expire"

    monkeypatch.setattr(get_config(), "learning_schema_ttl_days", 7)
    await _record(_schema(query_id="q-3"))
    assert next(iter(read_kind(pack, "schema").values()))["expires_at"] == "2026-11-08T00:00:00+00:00"


@pytest.mark.asyncio
async def test_full_store_refuses_new_entries_instead_of_evicting(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(get_config(), "learning_max_entries_per_kind", 1)
    _issue("q-1", "q-2", "q-3")
    await _record(_schema(field="kept", query_id="q-1"))

    assert await _record(_schema(field="flooded", query_id="q-2")) == []
    assert [change["action"] for change in await _record(_schema(field="kept", query_id="q-3"))] == ["confirmed"]
    assert [entry["fact"]["field"] for entry in read_kind(pack, "schema").values()] == ["kept"]


def test_tenant_pack_must_be_absolute_and_outside_the_repository():
    with pytest.raises(LearnedStoreError, match="absolute"):
        learned_store.validate_pack_dir("relative/pack")
    with pytest.raises(LearnedStoreError, match="outside the gateway repository"):
        learned_store.validate_pack_dir(str(MAIN_DIR / "tenant-pack"))


@pytest.mark.asyncio
async def test_misconfigured_pack_never_breaks_a_query(audit_events, monkeypatch):
    monkeypatch.setattr(get_config(), "tenant_pack_dir", str(MAIN_DIR / "tenant-pack"))
    use_fetcher(monkeypatch, [success("q-1", [{"n": 1}], cost=0.2)])

    response = await _run(ctx(), "dataset = xdr_data | limit 1")

    assert response["query_id"] == "q-1"
    assert not (MAIN_DIR / "tenant-pack").exists()
    assert audit_events == []


# --- Forgery guard ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "evidence",
    [
        (INJECTION,),
        ("q-never-issued",),
        (),
        tuple(f"q-{index}" for index in range(11)),
    ],
)
async def test_store_refuses_evidence_that_is_not_an_issued_query_id(pack, audit_events, evidence):
    _issue(*(item for item in evidence if item != "q-never-issued" and " " not in item))

    observation = Observation("schema", {"field": "user_name", "type": "string"}, evidence, "field_discovery_sample", "xdr_data")

    assert await _record(observation) == []
    assert not (pack / "learned" / "schema.json").exists()
    assert audit_events == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind, fact, source_class",
    [
        ("schema", {"field": INJECTION, "type": "string"}, "field_discovery_sample"),
        ("schema", {"field": "a" * 65, "type": "string"}, "field_discovery_sample"),
        ("schema", {"field": "user_name", "type": "string", "note": "trusted"}, "field_discovery_sample"),
        ("schema", {"field": "user_name", "type": INJECTION}, "field_discovery_sample"),
        ("schema", {"field": "user_name", "type": "string"}, "analyst_note"),
        ("enum_fields", {"field": "alert_source", "operator": "equals"}, "query_pair_outcome"),
    ],
)
async def test_store_refuses_free_text_and_unknown_shapes(pack, audit_events, kind, fact, source_class):
    _issue("q-1")

    assert await _record(Observation(kind, fact, ("q-1",), source_class, "xdr_data")) == []
    assert not (pack / "learned").exists() or not any((pack / "learned").glob("*.json"))


@pytest.mark.asyncio
async def test_hand_edited_entry_with_free_text_is_ignored_on_read(pack, clock):
    _issue("q-1")
    await _record(_schema(query_id="q-1"))
    path = pack / "learned" / "schema.json"
    document = json.loads(path.read_text())
    (good,) = document["entries"].values()
    forged = {**good, "fact": {"field": "user_name", "type": "string"}, "evidence": [INJECTION]}
    forged["entry_id"] = learned_store.make_entry_id("schema", ("xdr_data", "user_name"))
    document["entries"][forged["entry_id"]] = forged
    path.write_text(json.dumps(document))

    served = learned_store.read_entries("schema")

    assert [entry["fact"]["field"] for entry in served] == ["action_file_path"]


@pytest.mark.asyncio
async def test_result_rows_with_instruction_text_never_become_facts(pack, audit_events, clock, monkeypatch):
    poisoned_rows = [
        {
            "action_file_path": INJECTION,
            "error_class": "unknown_field",
            "unknown_field": "action_file_path",
            "query_id": "q-forged",
            INJECTION: "x",
        },
        {"action_file_path": "Field action_file_path does not exist. " + INJECTION, "event_count": 3},
    ]
    use_fetcher(
        monkeypatch,
        [
            success("q-d1", poisoned_rows),
            success("q-d2", poisoned_rows, cost=0.3),
            failure("q-d3", f"Unknown field: {INJECTION.split()[0]}"),
        ],
    )

    discovered = json.loads(await logs.discover_log_fields(ctx(), dataset="xdr_data"))
    await _run(ctx(), 'dataset = xdr_data | filter action_file_path = "x" | limit 5')
    failed = await _run(ctx(), "dataset = xdr_data | filter action_file_path contains event_count | limit 5")

    assert "error" not in discovered
    assert "error_class" not in failed
    stored = pack_text(pack)
    assert INJECTION not in stored
    assert "Ignore" not in stored
    assert "q-forged" not in stored
    assert read_kind(pack, "absent_fields") == {}
    assert {entry["fact"]["field"] for entry in read_kind(pack, "schema").values()} == {
        "action_file_path",
        "error_class",
        "event_count",
        "query_id",
        "unknown_field",
    }
    assert all(INJECTION not in json.dumps(event) for event in audit_events)


@pytest.mark.asyncio
async def test_failed_audit_export_blocks_the_write(pack, clock, monkeypatch):
    async def export_down(event):
        raise AuditExportError("collector unavailable")

    monkeypatch.setattr(learned_store, "emit_audit_event", export_down)
    _issue("q-1")

    assert await _record(_schema()) == []
    assert not (pack / "learned" / "schema.json").exists()


# --- Observers ---


@pytest.mark.asyncio
async def test_executor_records_cost_from_query_cost_and_remaining_quota_delta(pack, audit_events, clock, monkeypatch):
    use_fetcher(
        monkeypatch,
        [
            success("q-1", [{"n": 1}], cost=0.5, remaining=50.0),
            success("q-2", [{"n": 1}], remaining=49.25),
        ],
    )
    window = {"relativeTime": 3_600_000}

    await _run(ctx(), 'dataset = xdr_data | filter agent_hostname = "host-a" | limit 10', window)
    await _run(ctx(), 'dataset = xdr_data | filter agent_hostname = "host-b" | limit 10', window)

    (entry,) = read_kind(pack, "cost_table").values()
    assert entry["dataset"] == "xdr_data"
    assert entry["fact"]["window_bucket"] == "le_1h"
    assert entry["fact"]["selectivity"] == "selective"
    assert entry["fact"]["recent_units"] == [0.5, 0.75]
    assert entry["fact"]["units_source"] == "mixed"
    assert entry["evidence"] == ["q-1", "q-2"]
    assert "host-a" not in pack_text(pack)
    assert learned_store.lookup_cost("xdr_data", "le_1h", "selective") is None
    monkeypatch.setattr(get_config(), "learning_cost_min_observations", 2)
    assert learned_store.lookup_cost("xdr_data", "le_1h", "selective")["high_units"] == 0.75


@pytest.mark.asyncio
async def test_multi_source_queries_do_not_feed_the_cost_table(pack, audit_events, clock, monkeypatch):
    use_fetcher(monkeypatch, [success("q-j1", [{"n": 1}], cost=4.0)])

    await _run(ctx(), "dataset = xdr_data | join (dataset = alerts | fields alert_id) as matched matched.alert_id = alert_id | limit 5")

    assert read_kind(pack, "cost_table") == {}


@pytest.mark.parametrize(
    "query, expected",
    [
        ("dataset = xdr_data | fields a | limit 5", "sample"),
        ("dataset = xdr_data | comp count() by a | limit 5", "unfiltered"),
        ('dataset = xdr_data | filter a contains "b = c" | limit 5', "filtered"),
        ('dataset = xdr_data | filter a != "b" | limit 5', "filtered"),
        ('dataset = xdr_data | filter a = "b" | limit 5', "selective"),
        ('dataset = xdr_data | filter a in ("b", "c") | limit 5', "selective"),
        ('dataset = xdr_data // | filter a = "b"\n | filter a contains "x" | limit 5', "filtered"),
    ],
)
def test_selectivity_class_ignores_literals_and_comments(query, expected):
    assert learning_observers.selectivity_class(learning_observers.parse_xql(query)) == expected


@pytest.mark.parametrize(
    "timeframe, query, expected",
    [
        (None, "dataset = a | limit 1", "unspecified"),
        ({"relativeTime": 86_400_000}, "dataset = a | limit 1", "le_24h"),
        ({"from": 0, "to": 2 * 86_400_000}, "dataset = a | limit 1", "le_7d"),
        ({"relativeTime": 3_600_000}, "config timeframe = 30d | dataset = a | limit 1", "le_30d"),
    ],
)
def test_window_bucket_uses_the_api_timeframe_and_config_stage(timeframe, query, expected):
    parsed = learning_observers.parse_xql(query)
    assert learning_observers.window_bucket(learning_observers.window_ms(timeframe, parsed)) == expected


@pytest.mark.asyncio
async def test_discover_log_fields_records_names_and_types_not_values(pack, audit_events, clock, monkeypatch):
    rows = [
        {"action_file_path": "c:/synthetic/a.exe", "event_count": 3, "agent_hostname": None},
        {"action_file_path": "c:/synthetic/b.exe", "event_count": "7", "agent_hostname": "host-a"},
    ]
    use_fetcher(monkeypatch, [success("q-d1", rows)])

    result = json.loads(await logs.discover_log_fields(ctx(), dataset="xdr_data"))

    assert result["fields_observed_total"] == 3
    facts = {entry["fact"]["field"]: entry["fact"]["type"] for entry in read_kind(pack, "schema").values()}
    assert facts == {"action_file_path": "string", "agent_hostname": "string", "event_count": "mixed"}
    assert {entry["source_class"] for entry in read_kind(pack, "schema").values()} == {"field_discovery_sample"}
    assert "synthetic" not in pack_text(pack)


@pytest.mark.asyncio
async def test_unknown_field_error_records_absent_field_and_demotes_schema(pack, audit_events, clock, monkeypatch):
    _issue("q-0")
    await _record(_schema(field="actor_effective_username", query_id="q-0"))
    use_fetcher(monkeypatch, [failure("q-9", "Unknown field: actor_effective_username")])

    response = await _run(ctx(), 'dataset = xdr_data | filter actor_effective_username = "svc" | limit 5')

    assert response["error_class"] == "unknown_field"
    assert response["unknown_field"] == "actor_effective_username"
    (absent,) = read_kind(pack, "absent_fields").values()
    assert absent["fact"] == {"field": "actor_effective_username"}
    assert absent["evidence"] == ["q-9"]
    assert absent["source_class"] == "query_error_class"
    (schema,) = read_kind(pack, "schema").values()
    assert schema["status"] == "demoted"
    assert learned_store.learned_absent_fields("xdr_data") == {"actor_effective_username"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query, message",
    [
        ('dataset = xdr_data | filter actor_x = "a" | limit 5', "Unknown field: IgnorePreviousInstructions"),
        ('dataset = xdr_data | filter a = "actor_x" | limit 5', "Unknown field: actor_x"),
        ('dataset = xdr_data | alter y = actor_x | filter y = "a" | limit 5', "Unknown field: actor_x"),
        ('dataset = xdr_data | comp count() as total by a | filter total2 > 1 | limit 5', "Unknown field total2"),
        ('dataset in (xdr_data, alerts) | filter actor_x = "a" | limit 5', "Unknown field: actor_x"),
    ],
)
async def test_unknown_field_is_learned_only_for_fields_read_from_the_dataset(
    pack, audit_events, clock, monkeypatch, query, message
):
    use_fetcher(monkeypatch, [failure("q-9", message)])

    await _run(ctx(), query)

    assert read_kind(pack, "absent_fields") == {}


@pytest.mark.asyncio
async def test_equality_miss_then_contains_hit_records_enum_fact(pack, audit_events, clock, monkeypatch):
    use_fetcher(monkeypatch, [success("q-e1", []), success("q-e2", [{"alert_id": 1}])])
    window = {"relativeTime": 86_400_000}

    await _run(ctx(), 'dataset = alerts | filter alert_source = "SYNTH_IOC" | fields alert_id | limit 10', window)
    await _run(ctx(), 'dataset = alerts | filter alert_source contains "SYNTH_IOC" | fields alert_id | limit 25', window)

    (entry,) = read_kind(pack, "enum_fields").values()
    assert entry["dataset"] == "alerts"
    assert entry["fact"] == {"field": "alert_source", "operator": "contains"}
    assert entry["evidence"] == ["q-e1", "q-e2"]
    assert entry["source_class"] == "query_pair_outcome"
    assert learned_store.learned_enum_fields("alerts") == {"alert_source"}
    assert "SYNTH_IOC" not in pack_text(pack)


@pytest.mark.asyncio
async def test_typed_queries_pair_equality_and_contains_into_an_enum_fact(pack, audit_events, clock, monkeypatch):
    from usecase.builtin_components import datasets

    use_fetcher(monkeypatch, [success("q-t1", []), success("q-t2", [{"alert_id": 7}])])
    arguments = {"dataset": "alerts", "fields": ["alert_id"], "timeframe": {"relative_ms": 86_400_000}, "limit": 10}

    await datasets.query_dataset(ctx(), filters=[{"field": "alert_source", "operator": "eq", "value": "SYNTH"}], **arguments)
    await datasets.query_dataset(ctx(), filters=[{"field": "alert_source", "operator": "contains", "value": "SYNTH"}], **arguments)

    assert learned_store.learned_enum_fields("alerts") == {"alert_source"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "second_query, second_context, second_window",
    [
        ('dataset = alerts | filter alert_source contains "SYNTH" | filter severity = "high" | limit 10', None, None),
        ('dataset = alerts | filter alert_source contains "SYNTH" | limit 10', ctx(principal="other@example.com"), None),
        ('dataset = alerts | filter alert_source contains "SYNT" | limit 10', None, None),
        ('dataset = alerts | filter alert_source contains "SYNTH" | limit 10', None, {"relativeTime": 3_600_000}),
        ('dataset = alerts | filter not (alert_source contains "SYNTH") | limit 10', None, None),
    ],
)
async def test_enum_fact_needs_the_same_query_engagement_value_and_window(
    pack, audit_events, clock, monkeypatch, second_query, second_context, second_window
):
    use_fetcher(monkeypatch, [success("q-e1", []), success("q-e2", [{"alert_id": 1}])])
    window = {"relativeTime": 86_400_000}

    await _run(ctx(), 'dataset = alerts | filter alert_source = "SYNTH" | limit 10', window)
    await _run(second_context or ctx(), second_query, second_window or window)

    assert read_kind(pack, "enum_fields") == {}


@pytest.mark.asyncio
async def test_equality_with_rows_contradicts_an_enum_fact(pack, audit_events, clock, monkeypatch):
    use_fetcher(
        monkeypatch,
        [success("q-e1", []), success("q-e2", [{"n": 1}]), success("q-e3", [{"n": 1}])],
    )
    await _run(ctx(), 'dataset = alerts | filter alert_source = "SYNTH" | limit 10')
    await _run(ctx(), 'dataset = alerts | filter alert_source contains "SYNTH" | limit 10')
    assert learned_store.learned_enum_fields("alerts") == {"alert_source"}

    await _run(ctx(), 'dataset = alerts | filter alert_source = "OTHER" | limit 10')

    (entry,) = read_kind(pack, "enum_fields").values()
    assert entry["status"] == "demoted"
    assert learned_store.learned_enum_fields("alerts") == frozenset()


@pytest.mark.asyncio
async def test_tool_calls_record_helper_usage_and_step_timings(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(get_config(), "log_search_default_groups", "Security")
    use_fetcher(monkeypatch, [success("q-h1", [{"n": 1}], cost=0.2), success("q-h2", [{"n": 2}], cost=0.3)])
    server = create_mcp_server("test-key", "test-key-id")
    DatasetsModule(server).register_tools()
    plan = {
        "dataset": "xdr_data",
        "mode": "aggregate",
        "metrics": [{"function": "count", "alias": "events"}],
        "timeframe": {"relative_ms": 3_600_000},
        "limit": 5,
    }

    async with Client(server) as client:
        await client.call_tool("query_dataset", plan)
        await client.call_tool("query_dataset", {**plan, "group_by": ["agent_hostname"]})

    (helper,) = read_kind(pack, "helper_usage").values()
    assert helper["fact"] == {"tool": "query_dataset", "calls": 2, "successes": 2, "errors": 0, "queries": 2}
    assert helper["evidence"] == ["q-h1", "q-h2"]
    timings = {entry["fact"]["metric"]: entry for entry in read_kind(pack, "timings").values()}
    assert timings["tool_duration_ms"]["fact"]["observations"] == 2
    gap = timings["step_gap_ms"]
    assert gap["fact"]["previous_tool"] == "query_dataset"
    assert gap["evidence"] == ["q-h1", "q-h2"]
    assert gap["source_class"] == "tool_step_timing"


@pytest.mark.asyncio
async def test_freeze_stops_every_automatic_write_but_not_a_human_revert(pack, audit_events, clock, monkeypatch):
    _issue("q-1")
    await _record(_schema(query_id="q-1"))
    before = pack_text(pack)
    entry_id = next(iter(read_kind(pack, "schema")))
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Security": ["*"], "Admin": ["*"]}')
    monkeypatch.setattr(get_config(), "learning_enabled", False)
    use_fetcher(
        monkeypatch,
        [
            success("q-2", [{"action_file_path": "x", "n": 1}], cost=0.4),
            failure("q-3", "Unknown field: actor_x"),
            success("q-4", []),
            success("q-5", [{"n": 1}]),
        ],
    )

    await logs.discover_log_fields(ctx(), dataset="xdr_data")
    await _run(ctx(), 'dataset = xdr_data | filter actor_x = "a" | limit 5')
    await _run(ctx(), 'dataset = alerts | filter alert_source = "SYNTH" | limit 10')
    await _run(ctx(), 'dataset = alerts | filter alert_source contains "SYNTH" | limit 10')
    clock["now"] += timedelta(days=60)
    assert await learned_store.sweep_expired(principal=principal()) == []

    assert pack_text(pack) == before
    assert len(audit_events) == 1

    reverted = await learning_tools.revert_learned(ctx(("Admin",)), entry_id=entry_id)
    assert reverted["success"] is True
    assert read_kind(pack, "schema")[entry_id]["status"] == "reverted"


# --- Serving, digest and revert ---


@pytest.fixture
def two_datasets(pack, audit_events, clock, monkeypatch):
    monkeypatch.setattr(
        get_config(),
        "log_search_dataset_policy",
        '{"Security": ["*"], "Admin": ["*"], "Tier1": ["xdr_data"]}',
    )
    _issue("q-1", "q-2", "q-3")

    async def build():
        await _record(_schema(field="action_file_path", query_id="q-1"))
        await _record(_schema(field="action_file_path", query_id="q-2"))
        await _record(_schema(field="alert_name", dataset="alerts", query_id="q-3"))

    return build


@pytest.mark.asyncio
async def test_get_learned_facts_filters_by_dataset_policy_and_labels_trust(pack, two_datasets):
    await two_datasets()
    (pack / "notes").mkdir()
    (pack / "notes" / "alerts.md").write_text("# Alerts\n- verified: schema alerts alert_name  # checked by a human\n")

    tier1 = await learning_tools.get_learned_facts(ctx(("Tier1",)), kind="schema")
    security = await learning_tools.get_learned_facts(ctx(("Security",)), kind="schema")
    denied = await learning_tools.get_learned_facts(ctx(("Tier1",)), kind="schema", dataset="alerts")

    assert [entry["dataset"] for entry in tier1["entries"]] == ["xdr_data"]
    assert tier1["entries"][0]["trust"] == {"label": "learned", "confirmations": 2}
    assert tier1["content_trust"] == "measured_metadata"
    by_dataset = {entry["dataset"]: entry for entry in security["entries"]}
    assert by_dataset["alerts"]["trust"] == {"label": "verified", "note": "notes/alerts.md", "confirmations": 1}
    assert denied["success"] is False and "not allowed" in denied["error"]


@pytest.mark.asyncio
async def test_a_note_can_verify_a_fact_by_entry_id(pack, two_datasets):
    await two_datasets()
    entry_id = learned_store.make_entry_id("schema", ("xdr_data", "action_file_path"))
    (pack / "notes").mkdir()
    (pack / "notes" / "endpoint.md").write_text(f"verified: {entry_id}\n")

    result = await learning_tools.get_learned_facts(ctx(("Tier1",)), kind="schema", dataset="xdr_data")

    assert result["entries"][0]["trust"]["label"] == "verified"


@pytest.mark.asyncio
async def test_notes_with_unsafe_file_names_verify_nothing(pack, two_datasets):
    await two_datasets()
    (pack / "notes").mkdir()
    (pack / "notes" / f"{INJECTION}.md").write_text("verified: schema xdr_data action_file_path\n")

    result = await learning_tools.get_learned_facts(ctx(("Tier1",)), kind="schema", dataset="xdr_data")

    assert result["entries"][0]["trust"] == {"label": "learned", "confirmations": 2}


@pytest.mark.asyncio
async def test_learned_resource_requires_tool_permission_and_is_audited(pack, two_datasets, audit_events, monkeypatch):
    await two_datasets()
    monkeypatch.setattr(get_config(), "log_search_default_groups", "Tier1")
    server = create_mcp_server("test-key", "test-key-id")
    module = LearningModule(server)
    module.register_tools()
    module.register_resources()

    async with Client(server) as client:
        allowed = json.loads((await client.read_resource("tenant://learned/schema"))[0].text)
    denied = json.loads(await learning_tools.learned_facts_resource("schema", ctx(("Contractors",))))

    assert [entry["dataset"] for entry in allowed["entries"]] == ["xdr_data"]
    assert denied["success"] is False
    reads = [event for event in audit_events if event["operation"] == "read"]
    assert [event["details"]["success"] for event in reads] == [True, False]
    assert reads[0]["details"]["count"] == 1


@pytest.mark.asyncio
async def test_learning_digest_lists_changes_with_evidence_and_revert_hint(pack, two_datasets, clock):
    await two_datasets()
    _issue("q-4")
    await _record(_schema(field="action_file_path", field_type="integer", query_id="q-4"))

    security = await learning_tools.learning_digest(ctx(("Security",)), days=7)
    tier1 = await learning_tools.learning_digest(ctx(("Tier1",)), days=7)

    assert security["summary"]["learned"] == 2
    assert security["summary"]["demoted"] == 1
    demoted = security["changes"]["demoted"][0]
    assert demoted["previous_fact"] == {"field": "action_file_path", "type": "string"}
    assert demoted["evidence"] == ["q-1", "q-2", "q-4"]
    assert demoted["revert_with"] == {"tool": "revert_learned", "entry_id": demoted["entry_id"]}
    assert security["revert"]["allowed_for_caller"] is False
    assert {item["dataset"] for item in tier1["changes"]["learned"]} == {"xdr_data"}

    clock["now"] += timedelta(days=8)
    later = await learning_tools.learning_digest(ctx(("Security",)), days=7)
    assert later["summary"]["learned"] == 0


@pytest.mark.asyncio
async def test_revert_is_restricted_to_learning_admin_groups(pack, two_datasets, audit_events, clock, monkeypatch):
    await two_datasets()
    entry_id = learned_store.make_entry_id("schema", ("xdr_data", "action_file_path"))

    denied = await learning_tools.revert_learned(ctx(("Security",)), entry_id=entry_id)
    assert denied["success"] is False and "not allowed" in denied["error"]
    assert read_kind(pack, "schema")[entry_id]["status"] == "active"

    reverted = await learning_tools.revert_learned(ctx(("Admin",), principal="admin@example.com"), entry_id=entry_id)
    assert reverted["success"] is True
    assert reverted["reverted"]["status"] == "reverted"
    assert entry_id not in {entry["entry_id"] for entry in learned_store.read_entries("schema")}
    event = audit_events[-1]
    assert (event["operation"], event["principal"]["id"], event["actions"]) == ("revert", "admin@example.com", {"reverted": 1})
    assert "admin@example.com" not in pack_text(pack)

    _issue("q-9")
    assert await _record(_schema(field="action_file_path", query_id="q-9")) == []
    again = await learning_tools.revert_learned(ctx(("Admin",)), entry_id=entry_id)
    assert "already reverted" in again["error"]
    malformed = await learning_tools.revert_learned(ctx(("Admin",)), entry_id="../schema")
    assert malformed["success"] is False

    clock["now"] += timedelta(days=31)
    await learned_store.sweep_expired(principal=principal())
    assert [change["action"] for change in await _record(_schema(field="action_file_path", query_id="q-9"))] == ["learned"]

    monkeypatch.setattr(get_config(), "learning_admin_groups", "LearningAdmins")
    assert (await learning_tools.revert_learned(ctx(("Admin",)), entry_id=entry_id))["success"] is False
