import json
import re
from types import SimpleNamespace

import pytest
from fastmcp import FastMCP

from config.config import Settings, get_config
from entities.MCPContext import MCPContext
from usecase import dataset_catalogue as dc
from usecase import entity_resolution as er
from usecase import helper_runtime
from usecase.builtin_components import activity

XDR = "xdr_data"
TRAFFIC = "panw_ngfw_traffic_raw"
ENDPOINTS = "endpoints"
SIGNIN = "msft_azure_ad_raw"
CLOUD = "cloud_audit_logs"

SCHEMAS = {
    XDR: ["_time", "agent_hostname", "agent_ip_addresses", "actor_effective_username", "event_type"],
    TRAFFIC: ["_time", "source_ip", "dest_ip", "source_user", "dest_user", "action", "rule_matched", "app"],
    ENDPOINTS: ["endpoint_name", "ip_address", "user"],
    SIGNIN: ["_time", "userPrincipalName", "ipAddress", "appDisplayName"],
    CLOUD: ["_time", "identity_name", "caller_ip", "operation_name", "referenced_resource", "referenced_resource_name"],
}


def _ctx(groups=("Tier1",)):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=groups)
        )
    )


class FakeXsiam:
    def __init__(self, rows=None, schemas=None):
        self.rows = rows or {}
        self.schemas = schemas or SCHEMAS
        self.calls: list[dict] = []

    async def run(self, ctx, query, limit, timeframe=None, **kwargs):
        dataset = re.match(r"dataset = (\S+)", query).group(1)
        self.calls.append({"dataset": dataset, "query": query, "timeframe": timeframe})
        if re.fullmatch(rf"dataset = {dataset} \| limit \d+", query):
            return {"query_id": "q-disc", "reply": {"results": [dict.fromkeys(self.schemas.get(dataset, []))]}}
        key = "summary" if "comp count() as events" in query else "rows"
        return {"query_id": f"q-{key}", "reply": {"results": self.rows.get((dataset, key), [])}}

    def answers(self, dataset, kind="summary"):
        marker = "comp count() as events" if kind == "summary" else "| fields "
        return [c["query"] for c in self.calls if c["dataset"] == dataset and marker in c["query"]]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    dc.reset_catalogue_cache()
    helper_runtime.reset_field_cache()
    monkeypatch.setattr(get_config(), "dataset_catalogue_overlay_path", "")
    monkeypatch.setattr(get_config(), "dataset_query_max_timeframe_ms", 2_592_000_000)
    yield
    dc.reset_catalogue_cache()
    helper_runtime.reset_field_cache()


def _install(monkeypatch, fake, tenant_datasets, allowed):
    class FakeFetcher:
        async def send_request(self, path, data):
            return {"reply": [{"Dataset Name": name} for name in tenant_datasets]}

    async def fake_get_fetcher(ctx):
        return FakeFetcher()

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", json.dumps({"Tier1": allowed}))
    monkeypatch.setattr(helper_runtime, "get_fetcher", fake_get_fetcher)
    monkeypatch.setattr(helper_runtime, "run_xql_query", fake.run)


def test_cloud_resource_values_allow_identifier_punctuation_but_not_injection():
    arn = er.parse_entity("arn:aws:s3:::example-bucket/path", "cloud_resource")
    assert arn.kind == "cloud_resource" and arn.term == "arn:aws:s3:::example-bucket/path"

    for bad in ('bucket" | dataset = x', "ab", "a" * 600, "bucket\nname"):
        with pytest.raises(ValueError):
            er.parse_entity(bad, "cloud_resource")
    with pytest.raises(ValueError):
        er.parse_entity("arn:aws:s3:::example-bucket/path")


def test_activity_filters_match_host_by_name_and_by_resolved_address():
    entity = er.parse_entity("wks-1234")
    resolution = er.Resolution(entity, links=[{"dataset": ENDPOINTS, "match": "exact", "host": "WKS-1234", "ip": ["10.1.2.3"]}])

    filters, matched = activity.build_activity_filters(
        entity, {"host": ["agent_hostname"], "ip": ["agent_ip_addresses"]}, resolution
    )
    assert [(f.field, f.operator, f.value) for f in filters] == [
        ("agent_hostname", "in", ["WKS-1234"]),
        ("agent_ip_addresses", "in", ["10.1.2.3"]),
    ]
    assert matched == ["agent_hostname", "agent_ip_addresses"]

    network_only, _ = activity.build_activity_filters(entity, {"source_ip": ["source_ip"], "dest_ip": ["dest_ip"]}, resolution)
    assert [(f.field, f.operator) for f in network_only] == [("source_ip", "in"), ("dest_ip", "in")]

    unresolved, _ = activity.build_activity_filters(entity, {"host": ["agent_hostname"]}, er.Resolution(entity))
    assert [(f.field, f.operator, f.value) for f in unresolved] == [("agent_hostname", "contains", "wks-1234")]


@pytest.mark.asyncio
async def test_entity_activity_for_user_checks_only_allowed_datasets_with_user_fields(monkeypatch):
    fake = FakeXsiam(
        rows={
            (SIGNIN, "summary"): [{"appDisplayName": "Portal", "events": 12, "last_seen": 1700000000000}],
            (SIGNIN, "rows"): [{"_time": 1700000000000, "userPrincipalName": "jsmith@example.com", "appDisplayName": "Portal"}],
            (TRAFFIC, "summary"): [],
        }
    )
    _install(monkeypatch, fake, [SIGNIN, TRAFFIC, XDR, CLOUD, "mystery_raw"], [SIGNIN, TRAFFIC, "mystery_raw"])

    response = await activity.entity_activity(_ctx(), value="CORP\\jsmith")

    assert response["success"] is True and response["entity"] == {"input": "CORP\\jsmith", "kind": "user"}
    active = response["datasets_with_activity"]
    assert [item["dataset"] for item in active] == [SIGNIN]
    assert active[0]["events"] == 12 and active[0]["breakdown_by"] == "appDisplayName" and len(active[0]["samples"]) == 1
    assert "_sample" not in active[0]
    assert response["datasets_without_activity"] == [TRAFFIC]
    assert {call["dataset"] for call in fake.calls} == {SIGNIN, TRAFFIC}
    assert 'userPrincipalName contains "jsmith"' in fake.answers(SIGNIN)[0]
    assert "source_user contains" in fake.answers(TRAFFIC)[0] and " or " in fake.answers(TRAFFIC)[0]
    assert all(call["timeframe"] for call in fake.calls)


@pytest.mark.asyncio
async def test_entity_activity_resolves_host_then_queries_network_datasets_by_address(monkeypatch):
    fake = FakeXsiam(
        rows={
            (ENDPOINTS, "rows"): [{"endpoint_name": "WKS-1234", "ip_address": ["10.1.2.3"], "user": "jsmith"}],
            (XDR, "summary"): [{"event_type": "PROCESS", "events": 40, "last_seen": 2}],
            (TRAFFIC, "summary"): [{"action": "allow", "events": 9, "last_seen": 1}],
        }
    )
    _install(monkeypatch, fake, [ENDPOINTS, XDR, TRAFFIC], [ENDPOINTS, XDR, TRAFFIC])

    response = await activity.entity_activity(_ctx(), value="wks-1234", include_samples=False)

    assert response["resolution"]["ip_addresses"] == ["10.1.2.3"]
    assert [item["dataset"] for item in response["datasets_with_activity"]] == [XDR, TRAFFIC]
    assert 'agent_hostname in ("WKS-1234")' in fake.answers(XDR)[0]
    assert 'source_ip in ("10.1.2.3")' in fake.answers(TRAFFIC)[0] and "log_source_name" not in fake.answers(TRAFFIC)[0]
    assert all("samples" not in item for item in response["datasets_with_activity"])


@pytest.mark.asyncio
async def test_entity_activity_for_cloud_resource_and_domain_filter(monkeypatch):
    fake = FakeXsiam(rows={(CLOUD, "summary"): [{"operation_name": "PutObject", "events": 3, "last_seen": 5}]})
    _install(monkeypatch, fake, [CLOUD, TRAFFIC], [CLOUD, TRAFFIC])

    response = await activity.entity_activity(
        _ctx(), value="example-bucket", entity_type="cloud_resource", domains=["cloud_audit"], include_samples=False
    )

    assert [item["dataset"] for item in response["datasets_with_activity"]] == [CLOUD]
    assert 'referenced_resource contains "example-bucket"' in fake.answers(CLOUD)[0]
    assert {call["dataset"] for call in fake.calls} == {CLOUD}


@pytest.mark.asyncio
async def test_entity_activity_reports_nothing_found_without_inventing_activity(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [SIGNIN], [SIGNIN])

    response = await activity.entity_activity(_ctx(), value="nobody@example.com")

    assert response["datasets_with_activity"] == [] and response["datasets_without_activity"] == [SIGNIN]
    assert "Do not infer activity" in response["guidance"]


@pytest.mark.asyncio
async def test_entity_activity_caps_datasets_and_reports_the_remainder(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [SIGNIN, TRAFFIC, XDR, CLOUD], [SIGNIN, TRAFFIC, XDR, CLOUD])

    response = await activity.entity_activity(_ctx(), value="10.1.2.3", max_datasets=500)
    capped = await activity.entity_activity(_ctx(), value="10.1.2.3", max_datasets=1)

    assert response["datasets_not_checked"] == 0
    assert capped["datasets_not_checked"] == 3 and len(capped["datasets_without_activity"]) == 1
    assert capped["datasets_without_activity"] == [TRAFFIC]


@pytest.mark.asyncio
async def test_entity_activity_budget_holds_under_concurrency(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [SIGNIN, TRAFFIC, XDR, CLOUD], [SIGNIN, TRAFFIC, XDR, CLOUD])
    monkeypatch.setattr(helper_runtime, "MAX_HELPER_QUERIES", 3)

    response = await activity.entity_activity(_ctx(), value="10.1.2.3")

    assert response["success"] is False and "budget" in response["error"]
    assert len(fake.calls) <= 3


@pytest.mark.asyncio
async def test_entity_activity_rejects_bad_input_before_any_query(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [SIGNIN], [SIGNIN])

    response = await activity.entity_activity(_ctx(), value='x" | dataset = secrets')

    assert response["success"] is False and fake.calls == []


@pytest.mark.asyncio
async def test_entity_activity_contract_and_default_policy():
    server = FastMCP()
    activity.ActivityModule(server).register_tools()
    schema = (await server.get_tool("entity_activity")).parameters

    assert schema["required"] == ["value"]
    assert {"query", "xql", "filters", "fields", "dataset", "tenants"}.isdisjoint(schema["properties"])
    default_policy = json.loads(Settings.model_fields["tool_access_policy"].default)
    assert "entity_activity" in default_policy["Tier1"] and "entity_activity" in default_policy["SOC"]
