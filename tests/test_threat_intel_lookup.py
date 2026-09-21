import json
import re
from types import SimpleNamespace

import pytest
from fastmcp import FastMCP

from config.config import Settings, get_config
from entities.MCPContext import MCPContext
from usecase import helper_runtime
from usecase.builtin_components import threat_intel as ti

SCHEMAS = {
    ti.INDICATORS: ["id", "value", "type", "verdict", "tags", "associations", "description"],
    ti.RELATIONSHIPS: ["source_ref", "target_ref", "relationship_type"],
    ti.MALWARE: ["id", "name", "aliases", "description"],
    ti.THREAT_ACTORS: ["id", "name", "origin", "description"],
}
INDICATOR_ROW = {
    "id": "indicator--1",
    "value": "bad.example.com",
    "type": "domain",
    "verdict": "malicious",
    "associations": [
        {"id": "malware--m1", "type": "malware", "value": "ExampleLoader " + "x" * 300},
        {"id": "attack-pattern--a1", "type": "attack-pattern", "value": "T1059"},
        "not-a-dict",
    ],
}


def _ctx(groups=("Tier1",)):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=groups)
        )
    )


class FakeXsiam:
    def __init__(self, rows=None):
        self.rows = rows or {}
        self.calls: list[dict] = []

    async def run(self, ctx, query, limit, timeframe=None, **kwargs):
        dataset = re.match(r"dataset = (\S+)", query).group(1)
        self.calls.append({"dataset": dataset, "query": query})
        if re.fullmatch(rf"dataset = {dataset} \| limit \d+", query):
            return {"query_id": "d", "reply": {"results": [dict.fromkeys(SCHEMAS[dataset])]}}
        key = dataset
        if dataset == ti.RELATIONSHIPS:
            key = (dataset, "forward" if "source_ref in (" in query else "reverse")
        return {"query_id": "q", "reply": {"results": self.rows.get(key, [])}}

    def answers(self, dataset):
        return [c["query"] for c in self.calls if c["dataset"] == dataset and "| fields " in c["query"]]


@pytest.fixture(autouse=True)
def _isolate():
    helper_runtime.reset_field_cache()
    yield
    helper_runtime.reset_field_cache()


def _install(monkeypatch, fake, allowed):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", json.dumps({"Tier1": allowed}))
    monkeypatch.setattr(helper_runtime, "run_xql_query", fake.run)


@pytest.mark.parametrize("value", ['x" | dataset = secrets', "a b", "ab", "a" * 600, "bad\nvalue", "back\\slash"])
def test_indicator_input_is_validated(value):
    with pytest.raises(ValueError):
        ti.parse_indicator(value)


@pytest.mark.parametrize(
    "value", ["203.0.113.7", "2001:db8::1", "bad.example.com", "https://bad.example.com/a?b=c&d=%20", "user@example.com", "a" * 64]
)
def test_indicator_input_accepts_common_indicator_shapes(value):
    assert ti.parse_indicator(f" {value} ") == value


@pytest.mark.asyncio
async def test_lookup_walks_indicator_to_malware_to_actor_with_typed_queries_only(monkeypatch):
    fake = FakeXsiam(
        rows={
            ti.INDICATORS: [dict(INDICATOR_ROW)],
            (ti.RELATIONSHIPS, "forward"): [],
            (ti.RELATIONSHIPS, "reverse"): [{"source_ref": "threat-actor--t1", "target_ref": "malware--m1", "relationship_type": "uses"}],
            ti.MALWARE: [{"id": "malware--m1", "name": "ExampleLoader"}],
            ti.THREAT_ACTORS: [{"id": "threat-actor--t1", "name": "Example Group", "origin": "unknown"}],
        }
    )
    _install(monkeypatch, fake, list(SCHEMAS))

    response = await ti.threat_intel_lookup(_ctx(), indicator="bad.example.com")

    assert response["known"] is True and response["actor_link_count"] == 1
    assert response["related_malware"][0]["name"] == "ExampleLoader"
    assert response["related_threat_actors"][0]["name"] == "Example Group"
    associations = response["indicators"][0]["associations"]
    assert [item["type"] for item in associations] == ["malware", "attack-pattern"]
    assert len(associations[0]["name"]) == ti.MAX_NAME_CHARS
    assert 'value = "bad.example.com"' in fake.answers(ti.INDICATORS)[0]
    assert 'target_ref contains "threat-actor--"' in fake.answers(ti.RELATIONSHIPS)[0]
    for call in fake.calls:
        assert " join " not in call["query"] and "description" not in call["query"]
        assert re.search(r"\| limit \d+$", call["query"])
    assert response["provenance"]["content_trust"] == "untrusted_data"


@pytest.mark.asyncio
async def test_lookup_reports_unknown_indicator_without_calling_it_benign(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, list(SCHEMAS))

    response = await ti.threat_intel_lookup(_ctx(), indicator="203.0.113.77")

    assert response["known"] is False and "not evidence it is benign" in response["guidance"]
    assert {call["dataset"] for call in fake.calls} == {ti.INDICATORS}


@pytest.mark.asyncio
async def test_lookup_respects_dataset_policy_for_every_dataset(monkeypatch):
    fake = FakeXsiam(rows={ti.INDICATORS: [dict(INDICATOR_ROW)], ti.MALWARE: [{"id": "malware--m1", "name": "ExampleLoader"}]})
    _install(monkeypatch, fake, [ti.INDICATORS, ti.MALWARE])

    partial = await ti.threat_intel_lookup(_ctx(), indicator="bad.example.com")
    assert partial["related_malware"] and partial["related_threat_actors"] == []
    assert {call["dataset"] for call in fake.calls} == {ti.INDICATORS, ti.MALWARE}

    fake.calls.clear()
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", json.dumps({"Tier1": ["xdr_data"]}))
    denied = await ti.threat_intel_lookup(_ctx(), indicator="bad.example.com")
    assert denied["success"] is False and "not allowed" in denied["error"] and fake.calls == []


@pytest.mark.asyncio
async def test_lookup_skips_related_objects_when_not_requested_and_rejects_bad_input(monkeypatch):
    fake = FakeXsiam(rows={ti.INDICATORS: [dict(INDICATOR_ROW)]})
    _install(monkeypatch, fake, list(SCHEMAS))

    response = await ti.threat_intel_lookup(_ctx(), indicator="bad.example.com", include_related=False)
    assert {call["dataset"] for call in fake.calls} == {ti.INDICATORS} and response["related_malware"] == []

    fake.calls.clear()
    bad = await ti.threat_intel_lookup(_ctx(), indicator='x" | dataset = secrets')
    assert bad["success"] is False and fake.calls == []


@pytest.mark.asyncio
async def test_lookup_contract_and_default_policy():
    server = FastMCP()
    ti.ThreatIntelModule(server).register_tools()
    schema = (await server.get_tool("threat_intel_lookup")).parameters

    assert schema["required"] == ["indicator"]
    assert {"query", "xql", "filters", "fields", "dataset", "tenants"}.isdisjoint(schema["properties"])
    default_policy = json.loads(Settings.model_fields["tool_access_policy"].default)
    assert "threat_intel_lookup" in default_policy["Tier1"] and "threat_intel_lookup" in default_policy["SOC"]
