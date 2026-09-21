import json
import re
from types import SimpleNamespace

import pytest
from fastmcp import FastMCP

from config.config import Settings, get_config
from entities.MCPContext import MCPContext
from usecase import dataset_catalogue as dc
from usecase import helper_runtime
from usecase.builtin_components import dataset_health as health

AUDIT = "management_auditing"
TRAFFIC = "panw_ngfw_traffic_raw"
SITE = "acme_billing_raw"


def _ctx(groups=("Tier1",)):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=groups)
        )
    )


class FakeXsiam:
    def __init__(self, schema_rows=None, trend=None, samples=None):
        self.schema_rows = schema_rows or {}
        self.trend = trend or {}
        self.samples = samples or {}
        self.calls: list[dict] = []

    async def run(self, ctx, query, limit, timeframe=None, **kwargs):
        dataset = re.match(r"dataset = (\S+)", query).group(1)
        self.calls.append({"dataset": dataset, "query": query, "limit": limit, "timeframe": timeframe})
        if re.fullmatch(rf"dataset = {dataset} \| limit \d+", query):
            rows = self.schema_rows.get(dataset, [])
        elif "| bin " in query:
            rows = self.trend.get(dataset, [])
        else:
            rows = self.samples.get(dataset, [])
        return {"query_id": "q", "reply": {"results": rows}}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    dc.reset_catalogue_cache()
    helper_runtime.reset_field_cache()
    monkeypatch.setattr(get_config(), "dataset_catalogue_overlay_path", "")
    monkeypatch.setattr(get_config(), "dataset_query_max_timeframe_ms", 2_592_000_000)
    yield
    dc.reset_catalogue_cache()


def _install(monkeypatch, fake, tenant_datasets, allowed):
    class FakeFetcher:
        async def send_request(self, path, data):
            return {"reply": [{"Dataset Name": name} for name in tenant_datasets]}

    async def fake_get_fetcher(ctx):
        return FakeFetcher()

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", json.dumps({"Tier1": allowed}))
    monkeypatch.setattr(helper_runtime, "get_fetcher", fake_get_fetcher)
    monkeypatch.setattr(helper_runtime, "run_xql_query", fake.run)
    monkeypatch.setattr(health, "run_xql_query", fake.run)


@pytest.mark.asyncio
async def test_dataset_health_reports_arrival_schema_and_bounded_samples(monkeypatch):
    fake = FakeXsiam(
        schema_rows={AUDIT: [{"_time": 1, "user_name": "a", "email": "a@example.com", "subtype": "Login", "_raw": "x"}]},
        trend={AUDIT: [{"_time": 1000, "events": 4}, {"_time": 2000, "events": 6}]},
        samples={AUDIT: [{"_time": 2000, "user_name": "a", "subtype": "Login"}]},
    )
    _install(monkeypatch, fake, [AUDIT], [AUDIT])

    response = await health.dataset_health(_ctx(), dataset=AUDIT)

    report = response["datasets"][0]
    assert report["status"] == "receiving" and report["events"] == 10 and report["trend_bucket"] == "1h"
    assert report["last_bucket_start"] == 2000 and len(report["trend"]) == 2
    assert {"name": "user_name", "type": "string"} in report["fields"]
    assert all("value" not in field for field in report["fields"])
    assert len(report["samples"]) == 1

    discovery, trend, sample = (call["query"] for call in fake.calls)
    assert discovery == f"dataset = {AUDIT} | limit {health.SCHEMA_SAMPLE_ROWS}"
    assert "bin _time span = 1h" in trend and "comp count() as events" in trend
    assert re.search(rf"\| limit {health.SAMPLE_ROWS}$", sample) and "user_name" in sample and "_raw" not in sample
    assert [item["purpose"] for item in response["provenance"]["queries"]] == ["field_discovery", "arrival_trend", "recent_samples"]
    assert "do not dump" in response["guidance"]


@pytest.mark.asyncio
async def test_dataset_health_distinguishes_stale_from_no_data_and_uses_daily_buckets(monkeypatch):
    fake = FakeXsiam(schema_rows={AUDIT: [{"_time": 1, "user_name": "a"}]})
    _install(monkeypatch, fake, [AUDIT, TRAFFIC], [AUDIT, TRAFFIC])

    stale = await health.dataset_health(_ctx(), dataset=AUDIT, window_hours=168, include_samples=False)
    empty = await health.dataset_health(_ctx(), dataset=TRAFFIC)

    assert stale["datasets"][0]["status"] == "stale" and stale["datasets"][0]["trend_bucket"] == "1d"
    assert "samples" not in stale["datasets"][0]
    assert empty["datasets"][0]["status"] == "no_data" and empty["datasets"][0]["events"] == 0
    assert len([call for call in fake.calls if call["dataset"] == TRAFFIC]) == 1


@pytest.mark.asyncio
async def test_dataset_health_by_topic_checks_only_allowed_matches(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [TRAFFIC, "panw_ngfw_threat_raw", AUDIT], [TRAFFIC, AUDIT])

    response = await health.dataset_health(_ctx(), topic="firewall traffic")

    assert [item["dataset"] for item in response["datasets"]] == [TRAFFIC]
    assert {call["dataset"] for call in fake.calls} == {TRAFFIC}
    assert "panw_ngfw_threat_raw" not in json.dumps(response)


@pytest.mark.asyncio
async def test_dataset_health_refuses_disallowed_or_malformed_dataset_before_any_query(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [AUDIT, SITE], [AUDIT])

    denied = await health.dataset_health(_ctx(), dataset=SITE)
    malformed = await health.dataset_health(_ctx(), dataset="audit | limit 1000000")
    missing = await health.dataset_health(_ctx())

    assert denied["success"] is False and "not allowed" in denied["error"]
    assert malformed["success"] is False and missing["success"] is False
    assert fake.calls == []


@pytest.mark.asyncio
async def test_dataset_health_handles_uncatalogued_dataset_and_caps_fields(monkeypatch):
    wide_row = {"_time": 1, **{f"field_{index:03d}": "x" for index in range(90)}}
    fake = FakeXsiam(schema_rows={SITE: [wide_row]}, trend={SITE: [{"_time": 1, "events": 1}]}, samples={SITE: [{"_time": 1}]})
    _install(monkeypatch, fake, [SITE], [SITE])

    report = (await health.dataset_health(_ctx(), dataset=SITE))["datasets"][0]

    assert report["catalogue_source"] == "inferred" and report["status"] == "receiving"
    assert report["fields_observed"] == 91 and len(report["fields"]) == health.MAX_HEALTH_FIELDS and report["fields_truncated"]
    sample_query = fake.calls[-1]["query"]
    assert len(re.search(r"\| fields (.+?) \|", sample_query).group(1).split(", ")) == health.SAMPLE_FIELDS


@pytest.mark.asyncio
async def test_dataset_health_contract_and_default_policy():
    server = FastMCP()
    health.DatasetHealthModule(server).register_tools()
    properties = (await server.get_tool("dataset_health")).parameters["properties"]

    assert {"query", "xql", "filters", "fields", "limit", "tenants"}.isdisjoint(properties)
    default_policy = json.loads(Settings.model_fields["tool_access_policy"].default)
    assert "dataset_health" in default_policy["Tier1"] and "dataset_health" in default_policy["SOC"]
