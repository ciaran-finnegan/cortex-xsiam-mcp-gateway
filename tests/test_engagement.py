import inspect
import json
import os
import stat
from dataclasses import replace

import pytest
from fake_context import FakeContext, fake_context
from fastmcp import Client, Context

from config.config import get_config
from entities.MCPContext import MCPContext
from pkg.util import MAIN_DIR
from service.cortex_mcp import audit_middleware
from service.cortex_mcp.server import SERVER_INSTRUCTIONS, create_mcp_server
from usecase import engagement, xql_executor
from usecase.builtin_components.datasets import DatasetsModule
from usecase.builtin_components.engagement import EngagementModule
from usecase.builtin_components.issues import IssuesModule
from usecase.builtin_components.logs import LogsModule
from usecase.dataset_query import (
    DatasetQueryPlan,
    QueryCursorError,
    QuerySort,
    QueryTimeframe,
    decode_query_cursor,
    encode_query_cursor,
)
from usecase.engagement import (
    ENGAGEMENT_MODES,
    EngagementError,
    EngagementStoreError,
    build_engagement,
    get_mode_policy,
    get_mode_policy_table,
    normalize_scope_value,
    validate_store_dir,
)
from usecase.fetcher import get_fetcher
from usecase.log_policy import DatasetAuthorizationError, ensure_dataset_authorized
from usecase.tool_policy import authorize_tool, get_tool_policy

TIER1_TOOLS = [
    "get_dataset_query_guidance",
    "get_xql_help",
    "query_dataset",
    "continue_dataset_query",
    "set_engagement",
    "get_engagement",
    "record_fact",
    "get_engagement_log",
]


class QueryFetcher:
    """Completes each XQL query on start, with synthetic quota metadata, so tests never poll."""

    def __init__(self, *, rows=None, query_cost=None, remaining=(40.0, 39.0, 38.5)):
        self.rows = rows if rows is not None else [{"host_name": "web-01", "_time": 1}]
        self.query_cost = query_cost
        self.remaining = list(remaining)
        self.started = 0
        self.requests = []

    async def send_request(self, path, data=None, **kwargs):
        self.requests.append((path, data))
        assert path.endswith("start_xql_query/")
        self.started += 1
        reply = {
            "query_id": f"synthetic-query-{self.started}",
            "status": "SUCCESS",
            "number_of_results": len(self.rows),
            "remaining_quota": self.remaining[min(self.started - 1, len(self.remaining) - 1)],
            "results": {"data": self.rows},
        }
        if self.query_cost is not None:
            reply["query_cost"] = self.query_cost
        return {"reply": reply}


@pytest.fixture
def gateway(monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "identity_auth_mode", "none")
    monkeypatch.setattr(config, "engagement_store_dir", "")
    monkeypatch.setattr(config, "engagement_mode_policy", "")
    monkeypatch.setattr(config, "dataset_query_cursor_secret", "unit-test-cursor-secret")
    monkeypatch.setattr(
        config,
        "log_search_dataset_policy",
        json.dumps({"Security": ["*"], "Tier1": ["host_inventory"]}),
    )
    monkeypatch.setattr(
        config,
        "tool_access_policy",
        json.dumps({"Security": ["*"], "Tier1": TIER1_TOOLS}),
    )
    monkeypatch.setattr(config, "xsiam_credential_broker_enabled", False)
    events = []

    async def capture(event):
        events.append(event)

    monkeypatch.setattr(audit_middleware, "emit_audit_event", capture)

    def build(groups="Security", fetcher=None):
        monkeypatch.setattr(config, "log_search_default_groups", groups)
        server = create_mcp_server("test-key", "test-key-id")
        for module in (DatasetsModule, IssuesModule, LogsModule, EngagementModule):
            module(server).register_tools()
        if fetcher is not None:

            async def fake_get_fetcher(ctx):
                return fetcher

            monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
        server.events = events
        return server

    return build


def _payload(result):
    return json.loads(result.content[0].text)


# --- (1) ctx state is awaited and works against a real FastMCP context ---


def test_fake_context_matches_fastmcp_state_api():
    from fake_context import FakeContext

    for name in ("set_state", "get_state", "delete_state", "send_notification"):
        real = getattr(Context, name)
        fake = getattr(FakeContext, name)
        assert inspect.iscoroutinefunction(real)
        assert inspect.iscoroutinefunction(fake), name
        assert list(inspect.signature(fake).parameters) == list(inspect.signature(real).parameters), name
        assert {
            key: value.kind for key, value in inspect.signature(fake).parameters.items()
        } == {key: value.kind for key, value in inspect.signature(real).parameters.items()}, name


@pytest.mark.asyncio
async def test_real_context_carries_credential_profile_to_audit_and_not_to_later_calls(gateway, monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "papi_url_env_key", "https://api-unit-test.example")
    monkeypatch.setattr(config, "xsiam_credential_broker_enabled", True)
    monkeypatch.setattr(
        config,
        "xsiam_credential_profiles",
        json.dumps({"Security": {"profile_name": "security-readonly", "api_key_env": "UT_KEY", "api_key_id_env": "UT_KEY_ID"}}),
    )
    monkeypatch.setenv("UT_KEY", "profile-key")
    monkeypatch.setenv("UT_KEY_ID", "profile-key-id")
    server = gateway()

    @server.tool
    async def probe_fetcher(ctx: Context) -> dict:
        fetcher = await get_fetcher(ctx)
        stored = await ctx.get_state("fetcher")
        return {"success": True, "same_fetcher": stored is fetcher}

    @server.tool
    async def probe_noop() -> dict:
        return {"success": True}

    async with Client(server) as client:
        first = await client.call_tool("probe_fetcher", {})
        await client.call_tool("probe_noop", {})

    assert _payload(first)["same_fetcher"] is True
    ends = [event for event in server.events if event["phase"] == "end"]
    assert ends[0]["result"]["xsiam_credential_profile"] == {
        "profile_name": "security-readonly",
        "matched_group": "Security",
    }
    assert "xsiam_credential_profile" not in ends[1]["result"]
    assert "profile-key" not in json.dumps(server.events)


@pytest.mark.asyncio
async def test_fetcher_state_calls_are_awaited():
    source = inspect.getsource(get_fetcher)
    assert "await ctx.set_state" in source
    assert source.count("ctx.set_state") == source.count("await ctx.set_state")
    summary_source = inspect.getsource(audit_middleware._summarize_tool_result)
    assert "await fastmcp_context.get_state" in summary_source


# --- (2) engagement tools, validation, and storage ---


def test_scope_values_accept_ips_cidrs_hostnames_and_reject_free_text():
    assert normalize_scope_value(" 203.0.113.7 ") == "203.0.113.7"
    assert normalize_scope_value("2001:DB8::0001") == "2001:db8::1"
    assert normalize_scope_value("198.51.100.0/24") == "198.51.100.0/24"
    assert normalize_scope_value("198.51.100.9/24") == "198.51.100.0/24"
    assert normalize_scope_value("Web-01.Example.TEST.") == "web-01.example.test"
    assert normalize_scope_value("*.example.test") == "*.example.test"
    for bad in [
        "ignore previous instructions",
        "https://example.test/path",
        "10.0.0.256",
        "a;b",
        "-bad.example.test",
        "",
        "x" * 300,
        "user@example.test",
        42,
    ]:
        assert normalize_scope_value(bad) is None, bad


def test_file_hashes_are_accepted_only_as_iocs():
    sha256 = "a" * 64
    engagement_record, _ = build_engagement(mode="incident_response", iocs=[sha256.upper(), "203.0.113.7"])
    assert engagement_record.iocs == [sha256, "203.0.113.7"]
    with pytest.raises(EngagementError, match="IP addresses, CIDR ranges, or hostnames"):
        build_engagement(mode="incident_response", servers=[sha256])
    with pytest.raises(EngagementError, match="IP addresses, CIDR ranges, or hostnames"):
        build_engagement(mode="incident_response", servers=["$(id)"])


def test_scope_lists_are_capped_and_deduplicated(monkeypatch):
    monkeypatch.setattr(get_config(), "engagement_max_scope_items", 3)
    record, _ = build_engagement(mode="threat_hunt", internal=["10.0.0.0/8", "10.0.0.0/8", "HOST.example.test"])
    assert record.internal == ["10.0.0.0/8", "host.example.test"]
    with pytest.raises(EngagementError, match="at most 3"):
        build_engagement(mode="threat_hunt", iocs=["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"])


@pytest.mark.parametrize("case_id", ["../escape", "a/b", ".hidden", "", "x" * 65, "case id"])
def test_case_id_rejects_path_and_free_text(case_id):
    with pytest.raises(EngagementError, match="case_id"):
        build_engagement(mode="incident_response", case_id=case_id)


def test_engagement_rejects_unknown_mode_and_freezes_relative_window():
    with pytest.raises(EngagementError, match="mode must be one of"):
        build_engagement(mode="admin")
    record, omitted = build_engagement(mode="incident_response", window=QueryTimeframe(relative_ms=3_600_000))
    assert record.window["to_ms"] - record.window["from_ms"] == 3_600_000
    assert "window" not in omitted
    assert {"iocs", "internal", "front_ends", "servers", "notes"} <= omitted


@pytest.mark.asyncio
async def test_engagement_tools_round_trip_and_record_facts_against_executed_queries(gateway):
    fetcher = QueryFetcher(query_cost={"synthetic-tenant": 0.25})
    server = gateway(fetcher=fetcher)
    async with Client(server) as client:
        assert _payload(await client.call_tool("get_engagement", {}))["engagement"]["mode"] == "unset"
        early = _payload(
            await client.call_tool(
                "record_fact",
                {"key": "c2.ip", "value": "203.0.113.7", "evidence_query_id": "synthetic-query-1", "confidence": "high"},
            )
        )
        assert early["success"] is False
        assert "set_engagement" in early["error"]

        set_result = _payload(
            await client.call_tool(
                "set_engagement",
                {
                    "mode": "incident_response",
                    "case_id": "IR-2026-001",
                    "iocs": ["203.0.113.7", "bad.example.test"],
                    "internal": ["10.0.0.0/8"],
                    "front_ends": ["lb-01.example.test"],
                    "servers": ["web-01.example.test"],
                    "window": {"from_ms": 1_700_000_000_000, "to_ms": 1_700_086_400_000},
                    "notes": "Synthetic engagement.\x07",
                },
            )
        )
        assert set_result["success"] is True
        assert set_result["previous_mode"] == "unset"
        assert set_result["engagement"]["notes"] == "Synthetic engagement."
        assert set_result["engagement"]["notes_trust"] == "untrusted_data"

        query = _payload(
            await client.call_tool(
                "query_dataset",
                {"dataset": "host_inventory", "fields": ["host_name"], "limit": 5},
            )
        )
        assert query["success"] is True
        query_id = query["provenance"]["query_id"]

        bogus = _payload(
            await client.call_tool(
                "record_fact",
                {"key": "c2.ip", "value": "203.0.113.7", "evidence_query_id": "made-up-id", "confidence": "high"},
            )
        )
        assert bogus["success"] is False
        assert "does not match a query" in bogus["error"]

        fact = _payload(
            await client.call_tool(
                "record_fact",
                {"key": "c2.ip", "value": "203.0.113.7", "evidence_query_id": query_id, "confidence": "high"},
            )
        )
        assert fact["success"] is True
        assert fact["fact"]["case_id"] == "IR-2026-001"

        current = _payload(await client.call_tool("get_engagement", {}))
        log = _payload(await client.call_tool("get_engagement_log", {"case_id": "IR-2026-001"}))

    assert current["engagement"]["iocs"] == ["203.0.113.7", "bad.example.test"]
    assert current["session_spend"]["query_count"] == 1
    assert current["session_spend"]["units"] == 0.25
    assert current["case_store"] == "disabled"
    assert log["source"] == "session"
    assert [item["key"] for item in log["facts"]] == ["c2.ip"]
    entry = log["queries"][0]
    assert entry["query_id"] == query_id
    assert entry["tool"] == "query_dataset"
    assert entry["dataset"] == "host_inventory"
    assert entry["mode"] == "incident_response"
    assert entry["rows"] == 1
    assert entry["query_cost_units"] == 0.25
    assert entry["units"] == 0.25
    assert entry["remaining_quota"] == 40.0
    assert entry["status"] == "success"
    assert entry["duration_ms"] >= 0
    assert "synthetic-tenant" not in json.dumps(log)
    assert log["content_trust"] == "untrusted_data"


@pytest.mark.asyncio
async def test_case_store_resumes_scope_in_a_new_session_and_is_principal_scoped(gateway, monkeypatch, tmp_path):
    store_dir = tmp_path / "engagements"
    monkeypatch.setattr(get_config(), "engagement_store_dir", str(store_dir))
    server = gateway(fetcher=QueryFetcher())
    async with Client(server) as client:
        await client.call_tool(
            "set_engagement",
            {"mode": "incident_response", "case_id": "IR-7", "iocs": ["203.0.113.7"], "servers": ["web-01.example.test"]},
        )
        await client.call_tool("query_dataset", {"dataset": "host_inventory", "fields": ["host_name"]})

    async with Client(server) as client:
        resumed = _payload(await client.call_tool("set_engagement", {"mode": "threat_hunt", "case_id": "IR-7"}))
        cleared = _payload(await client.call_tool("set_engagement", {"mode": "threat_hunt", "case_id": "IR-7", "iocs": []}))
        log = _payload(await client.call_tool("get_engagement_log", {"case_id": "IR-7"}))

    assert resumed["resumed_from_case"] is True
    assert resumed["engagement"]["iocs"] == ["203.0.113.7"]
    assert resumed["case_store"] == "enabled"
    assert cleared["engagement"]["iocs"] == []
    assert cleared["engagement"]["servers"] == ["web-01.example.test"]
    assert log["source"] == "case_store"
    assert log["queries_total"] == 1

    [case_file] = list(store_dir.glob("*/IR-7.json"))
    assert stat.S_IMODE(case_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(case_file.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store_dir.stat().st_mode) == 0o700

    other = MCPContext(auth_headers={}, principal_id="other@example.test", groups=("Security",))
    with pytest.raises(EngagementError, match="No engagement log"):
        await engagement.get_engagement_log(fake_context(principal_id="other@example.test"), other, "IR-7")


def test_case_store_refuses_foreign_owner_and_symlinked_files(monkeypatch, tmp_path):
    monkeypatch.setattr(get_config(), "engagement_store_dir", str(tmp_path))
    store = engagement.get_engagement_store()
    owner = MCPContext(auth_headers={}, principal_id="owner@example.test")
    intruder = MCPContext(auth_headers={}, principal_id="intruder@example.test")
    store.update(owner, "CASE-1", lambda case: None)

    planted = tmp_path / engagement.owner_key(intruder) / "CASE-1.json"
    planted.parent.mkdir()
    planted.write_text((tmp_path / engagement.owner_key(owner) / "CASE-1.json").read_text())
    with pytest.raises(EngagementStoreError, match="does not belong"):
        store.read(intruder, "CASE-1")

    planted.unlink()
    os.symlink(tmp_path / engagement.owner_key(owner) / "CASE-1.json", planted)
    with pytest.raises(EngagementStoreError, match="symbolic link"):
        store.read(intruder, "CASE-1")


def test_store_dir_is_refused_inside_the_repository_or_any_git_tree(tmp_path):
    with pytest.raises(EngagementStoreError, match="outside the gateway repository"):
        validate_store_dir(str(MAIN_DIR / "engagements"))
    with pytest.raises(EngagementStoreError, match="outside the gateway repository"):
        validate_store_dir(str(MAIN_DIR / "docs" / ".." / "data"))
    with pytest.raises(EngagementStoreError, match="absolute path"):
        validate_store_dir("engagements")
    git_tree = tmp_path / "other-repo"
    (git_tree / ".git").mkdir(parents=True)
    with pytest.raises(EngagementStoreError, match="git working tree"):
        validate_store_dir(str(git_tree / "cases"))
    assert validate_store_dir(str(tmp_path / "cases")) == (tmp_path / "cases").resolve()


def test_server_startup_fails_on_store_dir_inside_repository(monkeypatch):
    monkeypatch.setattr(get_config(), "engagement_store_dir", str(MAIN_DIR / "case-data"))
    with pytest.raises(EngagementStoreError):
        create_mcp_server("test-key", "test-key-id")


@pytest.mark.asyncio
async def test_principals_sharing_a_session_id_cannot_see_each_others_engagement():
    shared_store = {}
    alice = FakeContext(
        MCPContext(auth_headers={}, principal_id="alice@example.test", groups=("Security",)),
        session_id="reused-session",
        session_store=shared_store,
    )
    mallory = FakeContext(
        MCPContext(auth_headers={}, principal_id="mallory@example.test", groups=("Security",)),
        session_id="reused-session",
        session_store=shared_store,
    )
    alice_principal = alice.request_context.lifespan_context
    mallory_principal = mallory.request_context.lifespan_context
    record, omitted = build_engagement(mode="incident_response", case_id="IR-1", iocs=["203.0.113.7"])
    await engagement.set_session_engagement(alice, alice_principal, record, omitted)

    seen = await engagement.load_engagement(mallory, mallory_principal)
    assert seen.mode == "unset"
    assert seen.iocs == []
    assert (await engagement.load_engagement(alice, alice_principal)).iocs == ["203.0.113.7"]


@pytest.mark.asyncio
async def test_query_telemetry_uses_quota_delta_without_query_cost_and_records_failures(gateway):
    fetcher = QueryFetcher(remaining=(40.0, 38.5))
    server = gateway(fetcher=fetcher)
    async with Client(server) as client:
        await client.call_tool("set_engagement", {"mode": "threat_hunt"})
        await client.call_tool("query_dataset", {"dataset": "host_inventory", "fields": ["host_name"]})
        await client.call_tool(
            "query_dataset",
            {
                "dataset": "host_inventory",
                "mode": "aggregate",
                "metrics": [{"function": "count", "alias": "total"}],
                "timeframe": {"from_ms": 1_700_000_000_000, "to_ms": 1_700_003_600_000},
            },
        )
        log = _payload(await client.call_tool("get_engagement_log", {}))

    first, second = log["queries"]
    assert first["units"] is None
    assert first["remaining_quota"] == 40.0
    assert second["remaining_quota_delta"] == 1.5
    assert second["units"] == 1.5
    assert second["window"] == {"from_ms": 1_700_000_000_000, "to_ms": 1_700_003_600_000}
    assert log["spend"]["units"] == 1.5
    assert log["spend"]["queries_without_units"] == 1


@pytest.mark.asyncio
async def test_query_telemetry_records_executor_exceptions_without_masking_them(monkeypatch):
    class BrokenFetcher:
        async def send_request(self, path, data=None, **kwargs):
            raise RuntimeError("upstream down")

    async def fake_get_fetcher(ctx):
        return BrokenFetcher()

    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    ctx = fake_context()
    with pytest.raises(RuntimeError, match="upstream down"):
        await xql_executor.run_xql_query(ctx, "dataset = host_inventory | limit 1", 1)
    log = await engagement.get_engagement_log(ctx, ctx.request_context.lifespan_context)
    assert log["queries"][0]["status"] == "error"
    assert log["queries"][0]["error_type"] == "RuntimeError"
    assert "upstream down" not in json.dumps(log)


@pytest.mark.asyncio
async def test_telemetry_failure_never_breaks_a_query(monkeypatch):
    async def fake_get_fetcher(ctx):
        return QueryFetcher()

    async def broken_get_state(key):
        raise OSError("state store down")

    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(xql_executor, "get_fetcher", fake_get_fetcher)
    ctx = fake_context()
    monkeypatch.setattr(ctx, "get_state", broken_get_state)
    response = await xql_executor.run_xql_query(ctx, "dataset = host_inventory | limit 1", 1, poll_interval_seconds=0)
    assert response["query_id"] == "synthetic-query-1"


# --- (3) mode and case on MCPContext, audit, cursors, list filtering ---


@pytest.mark.asyncio
async def test_every_audit_event_carries_mode_and_case_and_engagement_args_are_not_logged(gateway):
    server = gateway()
    async with Client(server) as client:
        await client.call_tool("get_engagement", {})
        await client.call_tool(
            "set_engagement",
            {"mode": "incident_response", "case_id": "IR-9", "iocs": ["203.0.113.99"], "notes": "secret-ish note"},
        )
        await client.call_tool("get_engagement", {})

    assert all("engagement" in event for event in server.events)
    first_start, first_end, set_start, set_end, last_start, last_end = server.events
    assert first_start["engagement"] == {"mode": "unset", "case_id": None, "source": None}
    assert set_start["engagement"] == {"mode": "unset", "case_id": None, "source": None}
    assert set_end["engagement"] == {"mode": "incident_response", "case_id": "IR-9", "source": "agent_inferred"}
    assert set_end["result"]["previous_mode"] == "unset"
    assert set_end["request"]["engagement_mode"] == "incident_response"
    assert set_end["request"]["engagement_source"] == "agent_inferred"
    assert set_end["request"]["scope_counts"] == {"iocs": 1}
    assert last_start["engagement"] == {"mode": "incident_response", "case_id": "IR-9", "source": "agent_inferred"}
    serialized = json.dumps(server.events)
    assert "203.0.113.99" not in serialized
    assert "secret-ish note" not in serialized


def _cursor_plan():
    return DatasetQueryPlan(
        dataset="host_inventory",
        fields=["host_name"],
        order_by=[QuerySort(field="host_name")],
        timeframe=QueryTimeframe(from_ms=1, to_ms=2),
        enable_continuation=True,
    )


@pytest.mark.parametrize(
    ("issued", "presented"),
    [
        (("threat_hunt", None), ("incident_response", None)),
        (("incident_response", "IR-1"), ("incident_response", "IR-2")),
        (("incident_response", "IR-1"), ("unset", None)),
    ],
)
def test_cursor_cannot_cross_modes_or_cases(monkeypatch, issued, presented):
    monkeypatch.setattr(get_config(), "dataset_query_cursor_secret", "unit-test-cursor-secret")
    principal = MCPContext(auth_headers={}, principal_id="analyst@example.test", groups=("Security",))
    cursor = encode_query_cursor(_cursor_plan(), replace(principal, mode=issued[0], case_id=issued[1]), ["host-1"])

    plan, values = decode_query_cursor(cursor, replace(principal, mode=issued[0], case_id=issued[1]))
    assert values == ["host-1"]
    with pytest.raises(QueryCursorError, match="different engagement mode or case"):
        decode_query_cursor(cursor, replace(principal, mode=presented[0], case_id=presented[1]))


@pytest.mark.asyncio
async def test_continuation_cursor_is_rejected_after_mode_change(gateway):
    fetcher = QueryFetcher(rows=[{"host_name": f"host-{index}"} for index in range(3)])
    server = gateway(fetcher=fetcher)
    async with Client(server) as client:
        await client.call_tool("set_engagement", {"mode": "threat_hunt"})
        first = _payload(
            await client.call_tool(
                "query_dataset",
                {
                    "dataset": "host_inventory",
                    "fields": ["host_name"],
                    "order_by": [{"field": "host_name"}],
                    "timeframe": {"from_ms": 1, "to_ms": 2},
                    "limit": 2,
                    "enable_continuation": True,
                },
            )
        )
        cursor = first["continuation"]["cursor"]
        await client.call_tool("set_engagement", {"mode": "incident_response"})
        continued = _payload(await client.call_tool("continue_dataset_query", {"cursor": cursor}))

    assert continued["success"] is False
    assert "different engagement mode" in continued["error"]


@pytest.mark.asyncio
async def test_list_tools_hides_group_denied_and_mode_hidden_tools(gateway):
    tier1 = gateway(groups="Tier1")
    async with Client(tier1) as client:
        tier1_names = {tool.name for tool in await client.list_tools()}
    assert tier1_names == set(TIER1_TOOLS)

    security = gateway(groups="Security")
    async with Client(security) as client:
        unset_names = {tool.name for tool in await client.list_tools()}
        await client.call_tool("set_engagement", {"mode": "incident_response"})
        ir_names = {tool.name for tool in await client.list_tools()}
        await client.call_tool("set_engagement", {"mode": "operations"})
        ops_names = {tool.name for tool in await client.list_tools()}

    assert "execute_xql_query" not in unset_names
    assert "execute_xql_query" in ir_names
    assert "execute_xql_query" not in ops_names
    assert {"query_dataset", "set_engagement"} <= unset_names


@pytest.mark.asyncio
async def test_list_tools_fails_closed_without_verified_identity(gateway, monkeypatch):
    server = gateway()
    monkeypatch.setattr(get_config(), "identity_auth_mode", "entra")
    async with Client(server) as client:
        assert await client.list_tools() == []


@pytest.mark.asyncio
async def test_mode_hidden_tool_is_denied_on_call_and_audited(gateway):
    server = gateway(groups="Security")
    async with Client(server) as client:
        result = await client.call_tool(
            "execute_xql_query",
            {"query": "dataset = host_inventory | limit 1"},
            raise_on_error=False,
        )
    assert result.is_error
    assert "engagement mode unset" in result.content[0].text
    end = [event for event in server.events if event["phase"] == "end"][-1]
    assert end["outcome"] == "denied"
    assert end["engagement"]["mode"] == "unset"


# --- Narrowing guarantee: a mode can never unlock what groups deny ---


def _permissive_mode_policy():
    return json.dumps({mode: {"heavy_tools_hidden": []} for mode in ENGAGEMENT_MODES})


@pytest.mark.parametrize("mode", ENGAGEMENT_MODES)
def test_no_mode_grants_a_tool_or_dataset_the_groups_deny(gateway, monkeypatch, mode):
    gateway()
    monkeypatch.setattr(get_config(), "engagement_mode_policy", _permissive_mode_policy())
    tier1 = MCPContext(auth_headers={}, principal_id="tier1@example.test", groups=("Tier1",), mode=mode, case_id="IR-1")
    group_grants = set(get_tool_policy()["Tier1"])
    universe = {*TIER1_TOOLS, "execute_xql_query", "get_cases", "get_issues", "search_logs", "get_assets"}

    for tool_name in universe:
        if authorize_tool(tier1, tool_name).allowed:
            assert tool_name in group_grants, (mode, tool_name)
    assert not authorize_tool(tier1, "execute_xql_query").allowed
    with pytest.raises(DatasetAuthorizationError):
        ensure_dataset_authorized(tier1, "cloud_audit_logs")
    ensure_dataset_authorized(tier1, "host_inventory")


@pytest.mark.parametrize("mode", ENGAGEMENT_MODES)
def test_mode_only_removes_from_group_grants(gateway, monkeypatch, mode):
    gateway()
    security = MCPContext(auth_headers={}, principal_id="sec@example.test", groups=("Security",))
    in_mode = replace(security, mode=mode)
    for tool_name in ("execute_xql_query", "query_dataset", "set_engagement", "get_cases"):
        if authorize_tool(in_mode, tool_name).allowed:
            assert authorize_tool(replace(security, mode="incident_response"), tool_name).allowed
    for tool_name in engagement.ENGAGEMENT_TOOL_NAMES:
        assert authorize_tool(in_mode, tool_name).allowed


@pytest.mark.parametrize(
    "override",
    [
        {"incident_response": {"tools_allowed": ["execute_xql_query"]}},
        {"incident_response": {"datasets": ["*"]}},
        {"superuser": {"heavy_tools_hidden": []}},
        {"operations": {"heavy_tools_hidden": ["set_engagement"]}},
        {"threat_hunt": {"session_budget_units": -1}},
        {"threat_hunt": {"default_window_ms": 10 * 2_592_000_000}},
    ],
)
def test_mode_policy_rejects_grants_unknown_modes_and_unsafe_values(gateway, monkeypatch, override):
    gateway()
    monkeypatch.setattr(get_config(), "engagement_mode_policy", json.dumps(override))
    with pytest.raises(ValueError):
        get_mode_policy_table()
    tier1 = MCPContext(auth_headers={}, principal_id="tier1@example.test", groups=("Tier1",), mode="incident_response")
    with pytest.raises(ValueError):
        authorize_tool(tier1, "query_dataset")


@pytest.mark.asyncio
async def test_tier1_cannot_reach_ungranted_tool_or_dataset_in_any_mode(gateway, monkeypatch):
    monkeypatch.setattr(get_config(), "engagement_mode_policy", _permissive_mode_policy())
    server = gateway(groups="Tier1", fetcher=QueryFetcher())
    async with Client(server) as client:
        for mode in ("incident_response", "threat_hunt", "operations"):
            await client.call_tool("set_engagement", {"mode": mode})
            raw = await client.call_tool(
                "execute_xql_query",
                {"query": "dataset = cloud_audit_logs | limit 1"},
                raise_on_error=False,
            )
            assert raw.is_error
            assert "not allowed to invoke tool execute_xql_query" in raw.content[0].text
            denied = _payload(await client.call_tool("query_dataset", {"dataset": "cloud_audit_logs", "fields": ["x"]}))
            assert denied["success"] is False
            assert "not allowed to query dataset" in denied["error"]


# --- (4)/(5) mode policy hook, server instructions, guidance ---


def test_default_mode_policy_is_conservative():
    table = get_mode_policy_table()
    assert set(table) == set(ENGAGEMENT_MODES)
    assert table["unset"] == table["operations"]
    assert "execute_xql_query" in table["unset"].heavy_tools_hidden
    assert table["unset"].session_budget_units <= min(policy.session_budget_units for policy in table.values())
    assert table["unset"].reserve_units >= max(policy.reserve_units for policy in table.values())
    assert get_mode_policy() == table["unset"]


def test_mode_policy_overrides_merge_per_mode(monkeypatch):
    monkeypatch.setattr(get_config(), "engagement_mode_policy", json.dumps({"threat_hunt": {"session_budget_units": 9}}))
    assert get_mode_policy("threat_hunt").session_budget_units == 9
    assert get_mode_policy("threat_hunt").default_result_shape == "aggregate"
    assert get_mode_policy("incident_response").session_budget_units == 25


def test_unset_inherits_the_operations_row_including_overrides(monkeypatch):
    monkeypatch.setattr(get_config(), "engagement_mode_policy", json.dumps({"operations": {"session_budget_units": 2}}))
    assert get_mode_policy("unset") == get_mode_policy("operations")
    assert get_mode_policy("unset").session_budget_units == 2
    monkeypatch.setattr(
        get_config(),
        "engagement_mode_policy",
        json.dumps({"operations": {"session_budget_units": 2}, "unset": {"reserve_units": 30}}),
    )
    assert get_mode_policy("unset").session_budget_units == 2
    assert get_mode_policy("unset").reserve_units == 30


@pytest.mark.asyncio
async def test_agent_inferred_mode_asks_for_confirmation_until_recorded_from_the_human(gateway):
    server = gateway()
    async with Client(server) as client:
        unset = _payload(await client.call_tool("get_engagement", {}))
        inferred = _payload(await client.call_tool("set_engagement", {"mode": "operations"}))
        pending = _payload(await client.call_tool("get_engagement", {}))
        await client.call_tool("set_engagement", {"mode": "operations", "source": "human"})
        confirmed = _payload(await client.call_tool("get_engagement", {}))
        await client.call_tool("set_engagement", {"mode": "threat_hunt", "source": "header"})
        from_header = _payload(await client.call_tool("get_engagement", {}))
        invalid = await client.call_tool(
            "set_engagement", {"mode": "operations", "source": "admin"}, raise_on_error=False
        )

    assert unset["confirm_with_user"] is False
    assert inferred["engagement"]["source"] == "agent_inferred"
    assert inferred["confirm_with_user"] is True
    assert pending["confirm_with_user"] is True
    assert confirmed["engagement"]["source"] == "human"
    assert confirmed["confirm_with_user"] is False
    assert from_header["confirm_with_user"] is False
    assert invalid.is_error
    with pytest.raises(EngagementError, match="source must be one of"):
        build_engagement(mode="operations", source="admin")


@pytest.mark.asyncio
async def test_results_carry_a_one_line_nudge_only_while_unset(gateway):
    server = gateway(fetcher=QueryFetcher())
    query = {"dataset": "host_inventory", "fields": ["host_name"]}
    async with Client(server) as client:
        unset_query = await client.call_tool("query_dataset", query)
        unset_guidance = await client.call_tool("get_dataset_query_guidance", {})
        engagement_read = await client.call_tool("get_engagement", {})
        await client.call_tool("set_engagement", {"mode": "operations"})
        set_query = await client.call_tool("query_dataset", query)

    assert unset_query.content[-1].text == engagement.ENGAGEMENT_NUDGE
    assert "\n" not in engagement.ENGAGEMENT_NUDGE
    assert _payload(unset_query)["success"] is True
    assert unset_query.structured_content == _payload(unset_query)
    assert unset_guidance.content[-1].text == engagement.ENGAGEMENT_NUDGE
    assert all(block.text != engagement.ENGAGEMENT_NUDGE for block in engagement_read.content)
    assert all(block.text != engagement.ENGAGEMENT_NUDGE for block in set_query.content)


@pytest.mark.asyncio
async def test_cost_guard_hooks_see_current_mode_inside_a_tool_call(gateway):
    server = gateway(fetcher=QueryFetcher(query_cost=0.5))

    @server.tool
    async def probe_cost_hooks(ctx: Context) -> dict:
        principal = engagement.apply_engagement(ctx.request_context.lifespan_context)
        return {
            "success": True,
            "mode": engagement.current_mode(),
            "budget": get_mode_policy().session_budget_units,
            "spend": await engagement.get_session_spend(ctx, principal),
        }

    async with Client(server) as client:
        await client.call_tool("set_engagement", {"mode": "threat_hunt"})
        await client.call_tool("query_dataset", {"dataset": "host_inventory", "fields": ["host_name"]})
        probe = _payload(await client.call_tool("probe_cost_hooks", {}))

    assert probe["mode"] == "threat_hunt"
    assert probe["budget"] == get_mode_policy("threat_hunt").session_budget_units
    assert probe["spend"]["units"] == 0.5


@pytest.mark.asyncio
async def test_server_instructions_and_mode_specific_guidance(gateway):
    server = gateway()
    assert server.instructions == SERVER_INSTRUCTIONS
    for mode in ("incident_response", "threat_hunt", "operations"):
        assert mode in SERVER_INSTRUCTIONS
    instructions = " ".join(SERVER_INSTRUCTIONS.split())
    for cue in ("indicator list", "alert storm", "are we talking to X", "why is X failing", "firewall", "look for", "hunt", "hypothesis"):
        assert cue in instructions, cue
    assert "ask the user one short question before the first query" in instructions
    assert "Never ask the user to fill in a form" in instructions
    assert 'source="agent_inferred"' in instructions
    assert "confirm_with_user" in instructions

    async with Client(server) as client:
        assert client.initialize_result.instructions == SERVER_INSTRUCTIONS
        unset = _payload(await client.call_tool("get_dataset_query_guidance", {}))
        await client.call_tool("set_engagement", {"mode": "threat_hunt"})
        hunt = _payload(await client.call_tool("get_dataset_query_guidance", {}))

    assert unset["engagement"]["mode"] == "unset"
    assert "set_engagement" in unset["engagement"]["workflow"][0]
    assert "execute_xql_query" in unset["engagement"]["hidden_tools"]
    assert hunt["engagement"]["mode"] == "threat_hunt"
    assert hunt["engagement"]["default_result_shape"] == "aggregate"
    assert any("Aggregate first" in step for step in hunt["engagement"]["workflow"])
    assert hunt["workflow"] == unset["workflow"]
