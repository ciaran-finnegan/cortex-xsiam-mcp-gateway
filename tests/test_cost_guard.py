import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastmcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from fastmcp.tools.tool import ToolResult

from config.config import get_config
from entities.MCPContext import MCPContext
from service.cortex_mcp import audit_middleware
from usecase import cost_guard, xql_executor
from usecase.builtin_components import datasets, issues, logs
from usecase.credential_broker import CredentialBrokerError
from usecase.dataset_query import QueryTimeframe

DAY_MS = 86_400_000
NOW_MS = 1_800_000_000_000
TIERS = '{"xdr_data":"heavy","amazon_aws_raw":"heavy","acme_alerts":"light","acme_flow_logs":"medium"}'


def _ctx(groups=("Security",), principal_id="analyst@example.test", elicit=None):
    ctx = SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id=principal_id, groups=groups)
        )
    )
    if elicit is not None:
        ctx.session = SimpleNamespace(check_client_capability=lambda caps: caps.elicitation is not None)
        ctx.elicit = elicit
    return ctx


def _observe(remaining):
    cost_guard.observe_remaining_quota(cost_guard.tenant_quota_key(), remaining)


def _days(days):
    return {"from_ms": NOW_MS - days * DAY_MS, "to_ms": NOW_MS}


class SequenceFetcher:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    async def send_request(self, path, data):
        self.requests.append((path, data))
        return next(self.responses)


def _success(rows=None, **reply):
    return {"reply": {"status": "SUCCESS", "results": {"data": rows or [{"total": 1}]}, **reply}}


@pytest.fixture(autouse=True)
def guard_settings(monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "identity_auth_mode", "none")
    monkeypatch.setattr(config, "cost_guard_dataset_tiers", TIERS)
    monkeypatch.setattr(config, "cost_guard_approval_threshold_units", 1.0)
    monkeypatch.setattr(config, "cost_guard_reserve_units", 10.0)
    monkeypatch.setattr(config, "log_search_dataset_policy", '{"Security":["*"]}')
    monkeypatch.setattr(config, "raw_xql_privileged_groups", "Security")
    monkeypatch.setattr(cost_guard, "_engagement", lambda: None)
    monkeypatch.setattr(cost_guard, "_catalogue_volume", lambda dataset: None)
    monkeypatch.setattr(cost_guard, "_catalogue_domain", lambda dataset: None)

    async def no_quota_api(ctx):
        raise RuntimeError("quota API unavailable in unit tests")

    monkeypatch.setattr(cost_guard, "_fetch_quota_reply", no_quota_api)


@pytest.fixture
def audit_events(monkeypatch):
    events = []

    async def capture(event):
        events.append(event)

    monkeypatch.setattr(cost_guard, "emit_audit_event", capture)
    return events


@pytest.fixture
def fetcher(monkeypatch):
    holder = SimpleNamespace(fetcher=SequenceFetcher([]))

    async def fake_get_fetcher(ctx):
        return holder.fetcher

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    return holder


# --- Estimation ---


@pytest.mark.parametrize(
    "query, days, expected",
    [
        ('dataset = acme_alerts | filter severity = "high" | fields alert_id | limit 25', 30, "light"),
        ("dataset = acme_flow_logs | comp count() as total by dest_port | limit 25", 30, "medium"),
        ('dataset = xdr_data | filter agent_hostname = "wks-0001" | fields action_process_image_name | limit 25', 1, "medium"),
        ('dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | fields agent_hostname | limit 25', 30, "extreme"),
        (
            'dataset = acme_flow_logs | filter dest_ip = "192.0.2.10" '
            '| join (dataset = xdr_data | filter agent_hostname = "wks-0001") as ep ep.action_remote_ip = dest_ip '
            "| limit 25",
            7,
            "heavy",
        ),
        ('dataset = amazon_aws_raw | filter to_json_string(responseElements) contains "acme" | limit 25', 30, "extreme"),
        ('dataset = xdr_data | filter action_file_name contains "invoice" | limit 25', 30, "extreme"),
    ],
)
def test_estimate_classifies_by_tier_window_selectivity_and_stages(query, days, expected):
    estimate = cost_guard.estimate_xql(query, _days(days))

    assert estimate.cost_class == expected
    low, high = cost_guard.unit_bands()[expected]
    assert (estimate.low_units, estimate.high_units) == (low, high)


def test_default_bands_match_the_profiled_unit_ranges():
    assert cost_guard.unit_bands() == {
        "light": (0.001, 0.4),
        "medium": (0.5, 3.6),
        "heavy": (5.0, 9.0),
        "extreme": (10.0, 31.0),
    }


def test_unit_bands_are_configurable_and_validated(monkeypatch):
    monkeypatch.setattr(
        get_config(), "cost_guard_unit_bands", '{"light":[0,1],"medium":[1,2],"heavy":[2,3],"extreme":[3,4]}'
    )
    assert cost_guard.estimate_xql("dataset = acme_alerts | limit 5", _days(1)).high_units == 1.0

    monkeypatch.setattr(get_config(), "cost_guard_unit_bands", '{"light":[2,1]}')
    with pytest.raises(ValueError, match="COST_GUARD_UNIT_BANDS"):
        cost_guard.unit_bands()


def test_text_scans_add_cost_and_keywords_inside_strings_or_comments_do_not():
    plain = cost_guard.estimate_xql('dataset = acme_flow_logs | filter src = "x" | limit 5', _days(7))
    pattern = cost_guard.estimate_xql('dataset = acme_flow_logs | filter src contains "x" | limit 5', _days(7))
    raw = cost_guard.estimate_xql('dataset = acme_flow_logs | filter _raw_log contains "x" | limit 5', _days(7))
    quoted = cost_guard.estimate_xql(
        'dataset = acme_flow_logs | filter note = "join _raw_log contains" | limit 5 // | join (dataset = xdr_data)',
        _days(7),
    )

    assert plain.score < pattern.score < raw.score
    assert raw.factors["text_scan"] == "raw_text"
    assert quoted.score == plain.score
    assert quoted.factors["datasets"] == ["acme_flow_logs"]


def test_host_scope_requires_a_positive_equality_without_or():
    scoped = cost_guard.parse_query('dataset = xdr_data | filter agent_hostname in ("wks-0001") | limit 5')
    with_or = cost_guard.parse_query('dataset = xdr_data | filter agent_hostname = "a" or action_remote_ip = "b"')
    negated = cost_guard.parse_query('dataset = xdr_data | filter not (agent_hostname = "wks-0001") | limit 5')
    inequality = cost_guard.parse_query('dataset = xdr_data | filter agent_hostname != "wks-0001" | limit 5')

    assert scoped.host_scoped is True
    assert with_or.host_scoped is False
    assert negated.host_scoped is False
    assert inequality.host_scoped is False


def test_union_by_name_and_saved_query_calls_are_priced():
    union = cost_guard.estimate_xql("dataset = acme_alerts | union xdr_data | limit 5", _days(1))
    call = cost_guard.estimate_xql('dataset = acme_alerts | call "saved_hunt" | limit 5', _days(1))

    assert union.factors["datasets"] == ["acme_alerts", "xdr_data"]
    assert union.factors["dataset_tier"] == "heavy"
    assert call.cost_class == "medium" and "call" in call.factors["stages"]


def test_query_without_a_dataset_is_priced_as_the_default_query_target():
    estimate = cost_guard.estimate_xql('filter action_remote_ip = "192.0.2.10" | limit 5', _days(30))

    assert estimate.factors["tier_source"] == "default_query_target"
    assert estimate.cost_class == "extreme"


def test_early_exit_samples_ignore_the_window():
    assert cost_guard.estimate_xql("dataset = xdr_data | limit 25", _days(30)).cost_class == "medium"
    assert cost_guard.estimate_xql("dataset = acme_flow_logs | limit 25", _days(30)).cost_class == "light"


def test_catalogue_volume_is_used_before_the_tier_map(monkeypatch):
    monkeypatch.setattr(cost_guard, "_catalogue_volume", lambda dataset: "very_high" if dataset == "acme_alerts" else None)

    assert cost_guard.dataset_tier("acme_alerts") == ("heavy", "catalogue")
    assert cost_guard.dataset_tier("acme_flow_logs") == ("medium", "tier_map")
    assert cost_guard.dataset_tier("acme_unlisted") == ("medium", "default")


def test_config_timeframe_in_xql_is_bounded_and_priced():
    estimate = cost_guard.estimate_xql(
        'config timeframe = 30d | dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5',
        {"relative_ms": 3_600_000},
    )
    assert estimate.factors["window_days"] == 30
    assert estimate.cost_class == "extreme"

    with pytest.raises(ValueError, match="exceeds configured maximum"):
        cost_guard.parse_query("config timeframe = 180d | dataset = xdr_data | limit 5")
    with pytest.raises(ValueError, match="relative duration"):
        cost_guard.parse_query('config timeframe between "2026-01-01" and "2026-06-01" | dataset = xdr_data | limit 5')
    with pytest.raises(ValueError, match="exceeds configured maximum"):
        cost_guard.parse_query("dataset = acme_flow_logs | join (config timeframe = 1y | dataset = xdr_data) as x x.a = a")


# --- Timeframe normalisation and timeout ceiling ---


def test_timeframe_normalisation_accepts_api_and_typed_shapes_and_requires_a_window():
    assert cost_guard.normalize_timeframe({"from": 1, "to": 2}).to_api() == {"from": 1, "to": 2}
    assert cost_guard.normalize_timeframe({"relativeTime": 60_000}).to_api() == {"relativeTime": 60_000}
    assert cost_guard.normalize_timeframe({"relative_ms": 60_000}).to_api() == {"relativeTime": 60_000}

    with pytest.raises(ValueError, match="timeframe is required"):
        cost_guard.normalize_timeframe(None)
    with pytest.raises(ValueError, match="Unsupported timeframe key"):
        cost_guard.normalize_timeframe({"from": 1, "to": 2, "extra": 3})
    with pytest.raises(ValueError, match="more than once"):
        cost_guard.normalize_timeframe({"from": 1, "from_ms": 1, "to": 2})
    with pytest.raises(ValueError, match="integer"):
        cost_guard.normalize_timeframe({"relativeTime": True})
    with pytest.raises(ValueError, match="configured maximum"):
        cost_guard.normalize_timeframe({"relative_ms": 31 * DAY_MS})


@pytest.mark.asyncio
async def test_raw_query_tools_require_a_bounded_timeframe_before_execution(monkeypatch):
    async def fail_if_called(*args, **kwargs):
        raise AssertionError("query must not run without a valid timeframe")

    monkeypatch.setattr(issues, "run_xql_query", fail_if_called)
    monkeypatch.setattr(logs, "_run_xql_query", fail_if_called)

    for timeframe in (None, {"relative_ms": 31 * DAY_MS}, {"relativeTime": "1d"}):
        raw = json.loads(await issues.execute_xql_query(_ctx(), "dataset = acme_alerts | limit 5", timeframe=timeframe))
        search = json.loads(
            await logs.search_logs(_ctx(), dataset="acme_alerts", fields=["alert_id"], timeframe=timeframe)
        )
        discover = json.loads(await logs.discover_log_fields(_ctx(), dataset="acme_alerts", timeframe=timeframe))
        typed = await datasets.query_dataset(
            _ctx(),
            dataset="acme_alerts",
            fields=["alert_id"],
            timeframe=None if timeframe is None else QueryTimeframe.model_construct(**{"relative_ms": 31 * DAY_MS}),
        )
        for response in (raw, search, discover):
            assert response["success"] == "false"
            assert "timeframe" in response["error"].lower()
        assert typed["success"] is False


@pytest.mark.asyncio
async def test_raw_query_tools_submit_the_normalised_timeframe(monkeypatch):
    seen = []

    async def capture(ctx, query, limit, **kwargs):
        seen.append((kwargs["tool"], kwargs["timeframe"]))
        return _success()

    monkeypatch.setattr(issues, "run_xql_query", capture)
    monkeypatch.setattr(logs, "_run_xql_query", capture)
    typed = {"from_ms": 1_000, "to_ms": 2_000}

    await issues.execute_xql_query(_ctx(), "dataset = acme_alerts | limit 5", timeframe=typed)
    await logs.search_logs(_ctx(), dataset="acme_alerts", fields=["alert_id"], timeframe=typed)
    await logs.discover_log_fields(_ctx(), dataset="acme_alerts", timeframe=typed)

    assert seen == [
        ("execute_xql_query", {"from": 1_000, "to": 2_000}),
        ("search_logs", {"from": 1_000, "to": 2_000}),
        ("discover_log_fields", {"from": 1_000, "to": 2_000}),
    ]


def test_timeout_is_capped_at_the_ceiling_and_the_approved_ceiling(monkeypatch):
    assert cost_guard.cap_timeout(10_000, approved=False) == 120
    assert cost_guard.cap_timeout(10_000, approved=True) == 300
    assert cost_guard.cap_timeout(0, approved=False) == 1
    monkeypatch.setattr(get_config(), "xql_timeout_ceiling_seconds", 30)
    assert cost_guard.cap_timeout(60, approved=False) == 30


@pytest.mark.asyncio
async def test_execute_xql_query_timeout_is_capped_unless_an_analyst_approves(monkeypatch, audit_events):
    timeouts = []

    async def fake_submit(ctx, query, safe_limit, *, timeframe, poll_interval_seconds, timeout_seconds, ticket):
        timeouts.append(timeout_seconds)
        return _success()

    monkeypatch.setattr(xql_executor, "_submit_and_poll", fake_submit)
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    await issues.execute_xql_query(_ctx(), query, timeout=100_000, timeframe=_days(1))
    approved = json.loads(
        await issues.execute_xql_query(_ctx(), query, timeout=100_000, timeframe=_days(2), approval="ok, long timeout")
    )

    assert timeouts == [120, 300]
    assert approved["quota"]["approved"] is True
    event = audit_events[-1]
    assert event["decision"] == "approved"
    assert event["cost_guard"]["approval_reason"] == "extended_timeout"
    assert event["cost_guard"]["approved_units"] == 0.0


# --- Decisions ---


@pytest.mark.asyncio
async def test_estimate_above_threshold_is_refused_with_structured_alternatives(fetcher, audit_events):
    _observe(50.0)
    query = 'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | fields agent_hostname, _time | limit 25'

    response = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(30)))

    assert response["success"] == "false"
    assert response["error"] == "cost_guard"
    assert response["rule"] == "approval_required"
    assert "not allowed" in response["message"]
    assert response["estimate"]["class"] == "extreme"
    assert response["remaining_units"] == 50.0
    assert response["reserve_units"] == 10.0
    assert response["approval"]["accepted"] is True
    kinds = [alternative["kind"] for alternative in response["alternatives"]]
    assert kinds[:2] == ["narrower_window", "narrower_window"]
    assert "aggregate" in kinds and kinds[-1] == "console"
    console = response["alternatives"][-1]
    assert console["xql"] == query and console["estimate"]["high_units"] == 0.0
    week, day = response["alternatives"][0], response["alternatives"][1]
    assert week["timeframe"] == {"from": NOW_MS - 7 * DAY_MS, "to": NOW_MS}
    assert week["estimate"]["score"] < response["estimate"]["score"]
    assert day["estimate"]["score"] < week["estimate"]["score"]
    assert fetcher.fetcher.requests == []
    refused = audit_events[-1]
    assert refused["event_type"] == "cortex_xsiam_mcp.cost_guard"
    assert refused["decision"] == "refused" and refused["outcome"] == "denied"
    assert refused["cost_guard"]["rule"] == "approval_required"
    assert refused["cost_guard"]["query_sha256"] == hashlib.sha256(query.encode()).hexdigest()
    assert "192.0.2.10" not in json.dumps(refused)


def test_refusal_payload_is_classified_as_denied_by_the_audit_middleware():
    payload = {"success": False, "error": "cost_guard", "message": "Query not allowed by the cost guard (reserve): x."}

    assert audit_middleware._infer_outcome(ToolResult(structured_content=payload)) == "denied"
    assert audit_middleware._infer_exception_outcome(cost_guard.CostGuardRefusal(payload)) == "denied"
    summary = audit_middleware._summarize_tool_result(ToolResult(structured_content={**payload, "rule": "reserve"}))
    assert summary["cost_guard_rule"] == "reserve"


@pytest.mark.asyncio
async def test_reserve_refuses_any_class_and_approval_cannot_override_it(fetcher, audit_events):
    _observe(10.2)
    light = "dataset = acme_alerts | fields alert_id | limit 5"

    response = json.loads(await issues.execute_xql_query(_ctx(), light, timeframe=_days(1), approval="approved by me"))

    assert response["rule"] == "reserve"
    assert response["approval"]["accepted"] is False
    assert "Approval cannot override the reserve" in response["message"]
    assert not any(event["decision"] == "approved" for event in audit_events)


@pytest.mark.asyncio
async def test_reserve_counts_queries_in_flight():
    _observe(11.0)
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    first = await cost_guard.prepare_query(None, query, timeframe=_days(1), result_limit=5, timeout_seconds=60)
    second = await cost_guard.prepare_query(None, query, timeframe=_days(2), result_limit=5, timeout_seconds=60)
    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(None, query, timeframe=_days(3), result_limit=5, timeout_seconds=60)
    cost_guard.release(first)
    cost_guard.release(second)
    third = await cost_guard.prepare_query(None, query, timeframe=_days(3), result_limit=5, timeout_seconds=60)

    assert refused.value.payload["rule"] == "reserve"
    assert third.reservation is not None


@pytest.mark.asyncio
async def test_unknown_remaining_quota_blocks_heavy_queries_only():
    heavy = 'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5'
    light = "dataset = acme_alerts | limit 5"

    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(None, heavy, timeframe=_days(7), result_limit=5, timeout_seconds=60)
    ticket = await cost_guard.prepare_query(None, light, timeframe=_days(7), result_limit=5, timeout_seconds=60)

    assert refused.value.payload["rule"] == "reserve"
    assert "unknown" in refused.value.payload["message"]
    assert ticket.estimate.cost_class == "light"


@pytest.mark.asyncio
async def test_remaining_quota_is_read_from_get_quota_when_unknown(monkeypatch):
    async def quota_reply(ctx):
        return {"license_quota": 365 * 40.0, "remaining_quota": 32.0, "daily_used_quota": 8.0}

    monkeypatch.setattr(cost_guard, "_fetch_quota_reply", quota_reply)
    query = 'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5'

    ticket = await cost_guard.prepare_query(
        _ctx(), query, timeframe=_days(7), result_limit=5, timeout_seconds=60, approval="analyst ok"
    )

    assert cost_guard._known_remaining(cost_guard.tenant_quota_key()) == 32.0
    assert ticket.approved is True


def test_quota_reply_never_guesses_a_budget_from_license_quota(monkeypatch):
    annual_or_daily = {"license_quota": 20_000.0, "additional_purchased_quota": 0.0, "daily_used_quota": 8.0}

    assert cost_guard.remaining_from_quota_reply(annual_or_daily) is None
    monkeypatch.setattr(get_config(), "cost_guard_daily_quota_units", 30.0)
    assert cost_guard.remaining_from_quota_reply(annual_or_daily) == 22.0
    assert cost_guard.remaining_from_quota_reply({"remaining_quota": 5.5, "daily_used_quota": 1.0}) == 5.5


def test_quota_observations_are_shared_by_every_credential_profile(monkeypatch):
    monkeypatch.setattr(get_config(), "papi_url_env_key", "https://api-tenant-a.example.test")
    first = cost_guard.tenant_quota_key()
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    assert cost_guard.tenant_quota_key() == first
    monkeypatch.setattr(get_config(), "papi_url_env_key", "https://api-tenant-b.example.test")
    assert cost_guard.tenant_quota_key() != first


@pytest.mark.asyncio
async def test_reserve_counts_in_flight_queries_across_principals_and_groups():
    _observe(11.0)
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    await cost_guard.prepare_query(
        _ctx(groups=("Tier1",), principal_id="one@example.test"), query, timeframe=_days(1), result_limit=5, timeout_seconds=60
    )
    await cost_guard.prepare_query(
        _ctx(groups=("Security",), principal_id="two@example.test"), query, timeframe=_days(1), result_limit=5, timeout_seconds=60
    )
    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            _ctx(groups=("SOC",), principal_id="three@example.test"), query, timeframe=_days(1), result_limit=5, timeout_seconds=60
        )

    assert refused.value.payload["rule"] == "reserve"


@pytest.mark.asyncio
async def test_timed_out_query_stays_debited_until_xsiam_reports_the_quota(monkeypatch):
    _observe(30.0)

    async def timed_out(ctx, query, safe_limit, **kwargs):
        return {"query_id": "query-9", "poll_attempts": 3, "error": "XQL query timed out after 1 seconds"}

    monkeypatch.setattr(xql_executor, "_submit_and_poll", timed_out)
    query = 'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5'

    response = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1), approval="analyst ok")

    assert response["quota"]["debited_units"] == 3.6
    assert cost_guard._known_remaining(cost_guard.tenant_quota_key()) == pytest.approx(26.4)
    assert cost_guard._inflight[cost_guard.tenant_quota_key()] == {}


@pytest.mark.asyncio
async def test_query_that_raises_stays_debited(monkeypatch):
    _observe(30.0)

    async def broken(ctx, query, safe_limit, **kwargs):
        kwargs["ticket"].submitted = True
        raise RuntimeError("connection reset")

    monkeypatch.setattr(xql_executor, "_submit_and_poll", broken)

    with pytest.raises(RuntimeError):
        await xql_executor.run_xql_query(_ctx(), "dataset = acme_alerts | limit 5", 5, timeframe=_days(1))

    assert cost_guard._known_remaining(cost_guard.tenant_quota_key()) == pytest.approx(29.6)
    assert cost_guard._inflight[cost_guard.tenant_quota_key()] == {}


@pytest.mark.asyncio
async def test_query_cancelled_before_submission_is_released_without_a_debit(monkeypatch):
    _observe(30.0)
    started = asyncio.Event()

    class BlockingFetcher:
        async def send_request(self, path, data):
            raise AssertionError("cancelled query must not reach XSIAM")

    async def fake_get_fetcher(ctx):
        started.set()
        await asyncio.Event().wait()
        return BlockingFetcher()

    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    task = asyncio.create_task(
        xql_executor.run_xql_query(_ctx(), "dataset = acme_alerts | limit 5", 5, timeframe=_days(1))
    )
    await started.wait()
    task.cancel()
    (outcome,) = await asyncio.gather(task, return_exceptions=True)

    assert isinstance(outcome, asyncio.CancelledError)
    assert cost_guard._known_remaining(cost_guard.tenant_quota_key()) == 30.0
    assert cost_guard._inflight[cost_guard.tenant_quota_key()] == {}


@pytest.mark.asyncio
async def test_local_debits_do_not_postpone_the_quota_refresh(monkeypatch, fetcher):
    clock = {"now": 1_000.0}
    monkeypatch.setattr(cost_guard, "_monotonic", lambda: clock["now"])
    refreshes = []

    async def quota_reply(ctx):
        refreshes.append(clock["now"])
        return {"remaining_quota": 20.0}

    monkeypatch.setattr(cost_guard, "_fetch_quota_reply", quota_reply)
    _observe(40.0)
    fetcher.fetcher = SequenceFetcher([_success(query_cost=0.1) for _ in range(3)])
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    for offset in (1, 2):
        clock["now"] += 200
        await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1) | {"to_ms": NOW_MS - offset})
    assert refreshes == [1_400.0]
    assert cost_guard._known_remaining(cost_guard.tenant_quota_key()) == pytest.approx(19.9)


@pytest.mark.asyncio
async def test_long_running_slots_refuse_new_heavy_queries(monkeypatch):
    _observe(50.0)
    clock = {"now": 1_000.0}
    monkeypatch.setattr(cost_guard, "_monotonic", lambda: clock["now"])
    heavy = 'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5'
    light = "dataset = acme_alerts | limit 5"

    with cost_guard.track_slot(), cost_guard.track_slot():
        clock["now"] += 61
        _observe(50.0)
        with pytest.raises(cost_guard.CostGuardRefusal) as refused:
            await cost_guard.prepare_query(
                None, heavy, timeframe=_days(7), result_limit=5, timeout_seconds=60, approval="analyst ok"
            )
        allowed = await cost_guard.prepare_query(None, light, timeframe=_days(7), result_limit=5, timeout_seconds=60)

    assert refused.value.payload["rule"] == "long_running_slots"
    assert allowed.estimate.cost_class == "light"
    assert cost_guard.long_running_slot_count() == 0


# --- Approval ---


@pytest.mark.asyncio
async def test_approval_argument_is_hashed_and_counted_against_the_daily_cap(fetcher, audit_events):
    _observe(50.0)
    fetcher.fetcher = SequenceFetcher([_success(remaining_quota=49.0) for _ in range(3)])
    approval_text = "Approved by the on-call analyst for case 42"
    query = 'dataset = xdr_data | filter agent_hostname = "wks-0001" | fields action_process_image_name | limit 5'

    first = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(1), approval=approval_text))
    second = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(1) | {"to_ms": NOW_MS - 1}, approval=approval_text))
    third = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(1) | {"to_ms": NOW_MS - 2}, approval=approval_text))

    assert first["success"] == "true" and second["success"] == "true"
    assert first["quota"]["approval_method"] == "approval_argument"
    assert third["rule"] == "approval_cap"
    approvals = [event for event in audit_events if event["decision"] == "approved"]
    assert [event["cost_guard"]["approved_today_units"] for event in approvals] == [3.6, 7.2]
    assert approvals[0]["cost_guard"]["approval_sha256"] == hashlib.sha256(approval_text.encode()).hexdigest()
    assert approval_text not in json.dumps(audit_events)


@pytest.mark.asyncio
async def test_approval_cap_is_per_principal(audit_events):
    _observe(50.0)
    query = 'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5'

    async def approve(ctx, offset_ms):
        return await cost_guard.prepare_query(
            ctx,
            query,
            timeframe={"from_ms": NOW_MS - DAY_MS - offset_ms, "to_ms": NOW_MS - offset_ms},
            result_limit=5,
            timeout_seconds=60,
            approval="analyst ok",
        )

    first = _ctx(principal_id="first@example.test")
    await approve(first, 1)
    await approve(first, 2)
    with pytest.raises(cost_guard.CostGuardRefusal) as capped:
        await approve(first, 3)
    other = await approve(_ctx(principal_id="second@example.test"), 4)

    assert capped.value.payload["rule"] == "approval_cap"
    assert other.approved is True


@pytest.mark.asyncio
async def test_zero_cap_disables_approval_arguments(monkeypatch):
    _observe(50.0)
    monkeypatch.setattr(get_config(), "cost_guard_approval_daily_cap_units", 0.0)

    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            None,
            'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5',
            timeframe=_days(1),
            result_limit=5,
            timeout_seconds=60,
            approval="analyst ok",
        )

    assert refused.value.payload["rule"] == "approval_cap"


@pytest.mark.asyncio
async def test_zero_cap_also_blocks_timeout_extension_approvals(monkeypatch):
    monkeypatch.setattr(get_config(), "cost_guard_approval_daily_cap_units", 0.0)

    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            None,
            "dataset = acme_alerts | limit 5",
            timeframe=_days(1),
            result_limit=5,
            timeout_seconds=10_000,
            approval="agent-written approval",
        )
    plain = await cost_guard.prepare_query(
        None, "dataset = acme_alerts | limit 5", timeframe=_days(1), result_limit=5, timeout_seconds=10_000
    )

    assert refused.value.payload["rule"] == "approval_cap"
    assert plain.timeout_seconds == 120


@pytest.mark.asyncio
async def test_elicitation_asks_the_human_and_their_answer_is_the_approval(audit_events):
    _observe(50.0)
    prompts = []

    async def elicit(message, response_type):
        prompts.append((message, response_type))
        return AcceptedElicitation(data="approve")

    ticket = await cost_guard.prepare_query(
        _ctx(elicit=elicit),
        'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5',
        timeframe=_days(1),
        result_limit=5,
        timeout_seconds=60,
    )

    assert ticket.approved is True and ticket.approval_method == "elicitation"
    message, response_type = prompts[0]
    assert response_type == ["approve", "deny"]
    assert "5 to 9 units (heavy)" in message
    assert "Remaining today: 50 units; reserve 10 units." in message
    assert "XSIAM console" in message
    assert [event["decision"] for event in audit_events] == ["elicitation", "approved"]
    assert audit_events[0]["outcome"] == "accepted"
    assert cost_guard._approved_units == {}


@pytest.mark.asyncio
async def test_declined_elicitation_refuses_even_with_an_approval_argument(audit_events):
    _observe(50.0)

    async def decline(message, response_type):
        return DeclinedElicitation()

    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            _ctx(elicit=decline),
            'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5',
            timeframe=_days(1),
            result_limit=5,
            timeout_seconds=60,
            approval="the agent wrote this",
        )

    assert refused.value.payload["rule"] == "approval_declined"
    assert [event["outcome"] for event in audit_events] == ["declined", "denied"]


@pytest.mark.asyncio
async def test_denied_choice_counts_as_declined():
    _observe(50.0)

    async def deny(message, response_type):
        return AcceptedElicitation(data="deny")

    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            _ctx(elicit=deny),
            'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5',
            timeframe=_days(1),
            result_limit=5,
            timeout_seconds=60,
        )

    assert refused.value.payload["rule"] == "approval_declined"


@pytest.mark.asyncio
async def test_cancelled_elicitation_falls_back_to_an_analyst_approval_argument(audit_events):
    _observe(50.0)

    async def cancel(message, response_type):
        return CancelledElicitation()

    query = 'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5'
    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            _ctx(elicit=cancel), query, timeframe=_days(1), result_limit=5, timeout_seconds=60
        )
    ticket = await cost_guard.prepare_query(
        _ctx(elicit=cancel), query, timeframe=_days(1), result_limit=5, timeout_seconds=60, approval="analyst ok"
    )

    assert refused.value.payload["rule"] == "approval_required"
    assert "cancelled" in refused.value.payload["message"]
    assert ticket.approval_method == "approval_argument"


@pytest.mark.asyncio
async def test_unanswered_elicitation_times_out(monkeypatch, audit_events):
    _observe(50.0)
    monkeypatch.setattr(get_config(), "cost_guard_elicitation_timeout_seconds", 1)

    async def never(message, response_type):
        raise TimeoutError

    with pytest.raises(cost_guard.CostGuardRefusal):
        await cost_guard.prepare_query(
            _ctx(elicit=never),
            'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5',
            timeframe=_days(1),
            result_limit=5,
            timeout_seconds=60,
        )

    assert audit_events[0]["outcome"] == "timeout"


@pytest.mark.asyncio
async def test_elicitation_can_be_disabled(monkeypatch, audit_events):
    _observe(50.0)
    monkeypatch.setattr(get_config(), "cost_guard_elicitation_enabled", False)

    async def elicit(message, response_type):
        raise AssertionError("elicitation is disabled")

    ticket = await cost_guard.prepare_query(
        _ctx(elicit=elicit),
        'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5',
        timeframe=_days(1),
        result_limit=5,
        timeout_seconds=60,
        approval="analyst ok",
    )

    assert ticket.approval_method == "approval_argument"


@pytest.mark.asyncio
async def test_engagement_mode_policy_and_servers_are_used_when_installed(monkeypatch):
    _observe(50.0)

    async def load_engagement(ctx, principal):
        return SimpleNamespace(servers=["srv-app-01", "srv-db-01"])

    async def get_session_spend(ctx, principal):
        return {"units": 2.5}

    engagement = SimpleNamespace(
        current_mode=lambda: "incident_response",
        get_mode_policy=lambda: SimpleNamespace(approval_threshold_units=5.0, reserve_units=10.0),
        load_engagement=load_engagement,
        get_session_spend=get_session_spend,
    )
    monkeypatch.setattr(cost_guard, "_engagement", lambda: engagement)
    ctx = _ctx()

    allowed = await cost_guard.prepare_query(
        ctx, 'dataset = xdr_data | filter agent_hostname = "wks-0001" | limit 5', timeframe=_days(1), result_limit=5, timeout_seconds=60
    )
    with pytest.raises(cost_guard.CostGuardRefusal) as refused:
        await cost_guard.prepare_query(
            ctx, 'dataset = xdr_data | filter action_remote_ip = "192.0.2.10" | limit 5', timeframe=_days(7), result_limit=5, timeout_seconds=60
        )
    finished = await cost_guard.finish_query(ctx, allowed, _success(query_cost=1.25))

    payload = refused.value.payload
    assert payload["mode"] == "incident_response" and payload["approval_threshold_units"] == 5.0
    host = next(alternative for alternative in payload["alternatives"] if alternative["kind"] == "host_filter")
    assert '| filter agent_hostname in ("srv-app-01", "srv-db-01")' in host["xql"]
    assert host["estimate"]["score"] < payload["estimate"]["score"]
    assert finished["quota"]["session_spent_units"] == 3.75


@pytest.mark.asyncio
async def test_cheaper_dataset_alternative_is_offered_only_when_authorized(monkeypatch):
    _observe(50.0)
    query = 'dataset = amazon_aws_raw | filter eventName = "ConsoleLogin" | limit 5'

    async def refuse(groups):
        with pytest.raises(cost_guard.CostGuardRefusal) as refused:
            await cost_guard.prepare_query(
                _ctx(groups=groups), query, timeframe=_days(30), result_limit=5, timeout_seconds=60
            )
        return [alt for alt in refused.value.payload["alternatives"] if alt["kind"] == "cheaper_dataset"]

    granted = await refuse(("Security",))
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Cloud":["amazon_aws_raw"]}')
    withheld = await refuse(("Cloud",))

    assert [alt["dataset"] for alt in granted] == ["cloud_audit_logs"]
    assert granted[0]["xql"] is None and "discover_log_fields" in granted[0]["next_step"]
    assert withheld == []


def test_narrower_window_rewrites_a_longer_config_timeframe():
    query = "config timeframe = 30d | dataset = xdr_data | filter action_remote_ip = \"192.0.2.10\" | limit 5"
    shape = cost_guard.parse_query(query)
    alternatives = cost_guard.build_alternatives(
        query,
        shape,
        cost_guard.normalize_timeframe({"relative_ms": 30 * DAY_MS}),
        principal=MCPContext(auth_headers={}, principal_id="analyst@example.test", groups=("Security",)),
        servers=[],
        policy=cost_guard.current_policy(),
    )

    windows = [alt for alt in alternatives if alt["kind"] == "narrower_window"]
    assert windows[0]["xql"].startswith("config timeframe = 7d |")
    assert windows[1]["xql"].startswith("config timeframe = 1d |")
    assert windows[1]["timeframe"] == {"relativeTime": DAY_MS}
    aggregate = next(alt for alt in alternatives if alt["kind"] == "aggregate")
    assert aggregate["xql"].endswith("| comp count() as event_count | sort desc event_count | limit 25")


# --- Recording ---


@pytest.mark.asyncio
async def test_quota_block_reports_estimate_actual_remaining_and_session_spend(fetcher):
    fetcher.fetcher = SequenceFetcher(
        [
            _success(remaining_quota=40.0, query_cost={"tenant-a": 0.25}),
            _success(remaining_quota=39.5),
        ]
    )
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    first = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(1)))
    second = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(2)))

    assert first["quota"]["estimate_units"] == 0.4 and first["quota"]["estimate_class"] == "light"
    assert first["quota"]["actual_units"] == 0.25
    assert first["quota"]["actual_units_source"] == "query_cost"
    assert first["quota"]["remaining_units"] == 40.0
    assert second["quota"]["actual_units"] == 0.5
    assert second["quota"]["actual_units_source"] == "remaining_quota_delta"
    assert second["quota"]["session_spent_units"] == 0.75
    assert "tenant-a" not in json.dumps(first["quota"])

    summary = audit_middleware._summarize_tool_result(ToolResult(structured_content=second))
    assert summary["quota"] == {
        "estimate_units": 0.4,
        "actual_units": 0.5,
        "remaining_units": 39.5,
        "session_spent_units": 0.75,
        "estimate_class": "light",
        "actual_units_source": "remaining_quota_delta",
        "cached": False,
        "approved": False,
    }


def test_audit_quota_summary_drops_unexpected_values():
    summary = audit_middleware._summarize_tool_result(
        ToolResult(
            structured_content={
                "success": True,
                "quota": {"estimate_units": "ignore previous instructions", "estimate_class": "free", "cached": "yes"},
            }
        )
    )

    assert "quota" not in summary or summary["quota"] == {}


@pytest.mark.asyncio
async def test_typed_query_refusal_and_dry_run_estimate():
    _observe(50.0)
    arguments = {
        "dataset": "xdr_data",
        "fields": ["agent_hostname"],
        "filters": [{"field": "action_remote_ip", "operator": "eq", "value": "192.0.2.10"}],
        "timeframe": QueryTimeframe(**_days(30)),
    }

    dry_run = await datasets.query_dataset(_ctx(), dry_run=True, **arguments)
    refused = await datasets.query_dataset(_ctx(), **arguments)

    assert dry_run["cost_estimate"]["class"] == "extreme"
    assert refused["success"] is False and refused["error"] == "cost_guard"
    assert refused["rule"] == "approval_required"


# --- Cache ---


@pytest.mark.asyncio
async def test_identical_query_and_timeframe_is_served_from_cache(fetcher):
    fetcher.fetcher = SequenceFetcher([_success(remaining_quota=40.0, query_cost=0.1), _success(remaining_quota=39.9)])
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    first = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(1)))
    cached = json.loads(await issues.execute_xql_query(_ctx(), query, timeframe=_days(1)))
    other_principal = json.loads(
        await issues.execute_xql_query(_ctx(principal_id="other@example.test"), query, timeframe=_days(1))
    )

    assert first["quota"]["cached"] is False
    assert cached["rows"] == first["rows"]
    assert cached["quota"]["cached"] is True and cached["quota"]["actual_units"] == 0.0
    assert cached["cost_guard"]["cache"] == "hit"
    assert "instead of spending quota" in cached["cost_guard"]["note"]
    assert other_principal["quota"]["cached"] is False
    assert len(fetcher.fetcher.requests) == 2


@pytest.mark.asyncio
async def test_cache_expires_and_skips_failures(monkeypatch, fetcher):
    clock = {"now": 5_000.0}
    monkeypatch.setattr(cost_guard, "_monotonic", lambda: clock["now"])
    fetcher.fetcher = SequenceFetcher(
        [
            {"reply": {"status": "FAILED", "error_message": "bad field"}},
            _success(),
            _success(),
        ]
    )
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    failed = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    fresh = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    clock["now"] += 601
    expired = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))

    assert failed["error"] == "XQL query failed"
    assert fresh["quota"]["cached"] is False
    assert expired["quota"]["cached"] is False
    assert len(fetcher.fetcher.requests) == 3


@pytest.mark.asyncio
async def test_cache_is_not_served_once_the_credential_broker_rejects_the_principal(monkeypatch, fetcher):
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        '{"Security":{"priority":10,"profile_name":"security-readonly","api_key_env":"ACME_TEST_KEY","api_key_id_env":"ACME_TEST_KEY_ID"}}',
    )
    monkeypatch.setenv("ACME_TEST_KEY", "synthetic-key")
    monkeypatch.setenv("ACME_TEST_KEY_ID", "1")
    fetcher.fetcher = SequenceFetcher([_success(), _success()])
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    cached = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    monkeypatch.delenv("ACME_TEST_KEY")
    with pytest.raises(CredentialBrokerError):
        await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    monkeypatch.setenv("ACME_TEST_KEY", "synthetic-key")
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        '{"Security":{"priority":10,"profile_name":"security-rotated","api_key_env":"ACME_TEST_KEY","api_key_id_env":"ACME_TEST_KEY_ID"}}',
    )
    reprofiled = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))

    assert cached["quota"]["cached"] is True
    assert reprofiled["quota"]["cached"] is False
    assert len(fetcher.fetcher.requests) == 2


@pytest.mark.asyncio
async def test_cache_misses_after_a_key_rotation_under_the_same_profile(monkeypatch, fetcher):
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        '{"Security":{"priority":10,"profile_name":"security-readonly","api_key_env":"ACME_TEST_KEY","api_key_id_env":"ACME_TEST_KEY_ID"}}',
    )
    monkeypatch.setenv("ACME_TEST_KEY", "synthetic-key-one")
    monkeypatch.setenv("ACME_TEST_KEY_ID", "1")
    fetcher.fetcher = SequenceFetcher([_success(), _success(), _success()])
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    monkeypatch.setenv("ACME_TEST_KEY", "synthetic-key-two")
    rotated = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", False)
    monkeypatch.setattr(get_config(), "papi_auth_header_key", "synthetic-server-key")
    monkeypatch.setattr(get_config(), "papi_auth_id_key", "2")
    server_key = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))

    assert rotated["quota"]["cached"] is False
    assert server_key["quota"]["cached"] is False
    assert len(fetcher.fetcher.requests) == 3
    assert "synthetic-key" not in json.dumps(list(cost_guard._cache))


@pytest.mark.asyncio
async def test_cache_misses_after_the_server_key_rotates_with_the_broker_disabled(monkeypatch, fetcher):
    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", False)
    monkeypatch.setattr(get_config(), "papi_auth_header_key", "synthetic-server-key-one")
    monkeypatch.setattr(get_config(), "papi_auth_id_key", "3")
    fetcher.fetcher = SequenceFetcher([_success(), _success(), _success()])
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    cached = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    monkeypatch.setattr(get_config(), "papi_auth_header_key", "synthetic-server-key-two")
    rotated = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))

    assert cached["quota"]["cached"] is True
    assert rotated["quota"]["cached"] is False
    assert len(fetcher.fetcher.requests) == 2


@pytest.mark.asyncio
async def test_reply_is_not_cached_when_the_key_changes_before_submission(monkeypatch):
    from usecase.credential_broker import select_xsiam_credentials

    monkeypatch.setattr(get_config(), "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        get_config(),
        "xsiam_credential_profiles",
        '{"Security":{"priority":10,"profile_name":"security-readonly","api_key_env":"ACME_TEST_KEY","api_key_id_env":"ACME_TEST_KEY_ID"}}',
    )
    monkeypatch.setenv("ACME_TEST_KEY", "synthetic-key-one")
    monkeypatch.setenv("ACME_TEST_KEY_ID", "1")
    ctx = _ctx()

    async def rotating_get_fetcher(ctx):
        # A key rotated while the query waited for a slot; get_fetcher selects again.
        monkeypatch.setenv("ACME_TEST_KEY", "synthetic-key-two")
        select_xsiam_credentials(ctx.request_context.lifespan_context, {})
        return SequenceFetcher([_success()])

    monkeypatch.setattr(xql_executor, "get_fetcher", rotating_get_fetcher)
    response = await xql_executor.run_xql_query(ctx, "dataset = acme_alerts | fields alert_id | limit 5", 5, timeframe=_days(1))

    assert response["quota"]["cached"] is False
    assert len(cost_guard._cache) == 0


@pytest.mark.asyncio
async def test_cache_can_be_disabled(monkeypatch, fetcher):
    monkeypatch.setattr(get_config(), "cost_guard_cache_ttl_seconds", 0)
    fetcher.fetcher = SequenceFetcher([_success(), _success()])
    query = "dataset = acme_alerts | fields alert_id | limit 5"

    await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    second = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))

    assert second["quota"]["cached"] is False
    assert len(fetcher.fetcher.requests) == 2


@pytest.mark.asyncio
async def test_cached_result_bypasses_refusal_rules(fetcher):
    fetcher.fetcher = SequenceFetcher([_success(remaining_quota=40.0)])
    query = "dataset = acme_alerts | fields alert_id | limit 5"
    await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))
    _observe(1.0)

    cached = await xql_executor.run_xql_query(_ctx(), query, 5, timeframe=_days(1))

    assert cached["quota"]["cached"] is True
    assert cached["quota"]["remaining_units"] == 1.0
