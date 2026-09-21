import json
import re
from types import SimpleNamespace

import pytest
from fastmcp import FastMCP

from config.config import Settings, get_config
from entities.MCPContext import MCPContext
from usecase import dataset_catalogue as dc
from usecase import helper_runtime
from usecase.builtin_components import coverage
from usecase.dataset_query import QueryTimeframe

DIRECTORY = "pan_dss_raw"
ENDPOINTS = "endpoints"
TRAFFIC = "panw_ngfw_traffic_raw"
SCHEMAS = {
    DIRECTORY: ["_time", "name", "dns_host_name", "type", "sam_account_name"],
    ENDPOINTS: ["endpoint_name", "ip_address", "user"],
    TRAFFIC: ["_time", "source_ip", "dest_ip", "action"],
}


def _ctx(groups=("Tier1",)):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=groups)
        )
    )


class FakeXsiam:
    def __init__(self, total=10, missing=3, hosts=("WKS-1", "WKS-2", "WKS-3")):
        self.total, self.missing, self.hosts = total, missing, hosts
        self.calls: list[dict] = []

    async def run(self, ctx, query, limit, timeframe=None, **kwargs):
        dataset = re.match(r"dataset = (\S+)", query).group(1)
        self.calls.append({"dataset": dataset, "query": query, "limit": limit, "timeframe": timeframe})
        if re.fullmatch(rf"dataset = {dataset} \| limit \d+", query):
            rows = [dict.fromkeys(SCHEMAS[dataset])]
        elif "comp count() as total" in query:
            rows = [{"total": self.total}]
        elif "comp count() as missing" in query:
            rows = [{"missing": self.missing}]
        else:
            rows = [{coverage.REF_KEY: host, "secret_extra": "x"} for host in self.hosts]
        return {"query_id": "q", "reply": {"results": rows}}

    def generated(self):
        return [c["query"] for c in self.calls if " | limit 5" != c["query"][-10:] and "alter " in c["query"]]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    dc.reset_catalogue_cache()
    helper_runtime.reset_field_cache()
    monkeypatch.setattr(get_config(), "dataset_catalogue_overlay_path", "")
    monkeypatch.setattr(get_config(), "dataset_query_max_timeframe_ms", 2_592_000_000)
    yield
    dc.reset_catalogue_cache()
    helper_runtime.reset_field_cache()


def _install(monkeypatch, fake, allowed):
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", json.dumps({"Tier1": allowed}))
    monkeypatch.setattr(helper_runtime, "run_xql_query", fake.run)


def test_anti_join_builder_emits_one_fixed_shape_from_identifiers_only():
    count = coverage.build_anti_join_xql(DIRECTORY, "name", ("type", "computer"), ENDPOINTS, "endpoint_name", None, list_limit=None)
    listing = coverage.build_anti_join_xql(DIRECTORY, "name", None, ENDPOINTS, "endpoint_name", None, list_limit=5000)

    assert count == (
        'dataset = pan_dss_raw | filter name != null and type = "computer" '
        '| alter cg_reference_host = uppercase(arrayindex(split(name, "."), 0)) | dedup cg_reference_host '
        "| join type = left (dataset = endpoints | filter endpoint_name != null "
        '| alter cg_target_host = uppercase(arrayindex(split(endpoint_name, "."), 0)) | dedup cg_target_host '
        "| fields cg_target_host) as cg_target cg_target.cg_target_host = cg_reference_host "
        "| filter cg_target_host = null | comp count() as missing | limit 1"
    )
    assert listing.endswith(f"| fields cg_reference_host | sort asc cg_reference_host | limit {coverage.MAX_MISSING}")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"reference": "a | dataset = secrets"},
        {"reference_field": "name) | dataset = secrets | filter (x"},
        {"target": "endpoints\n"},
        {"target_field": "endpoint name"},
        {"reference_filter": ("type) or (1", "computer")},
    ],
)
def test_anti_join_builder_rejects_non_identifier_input(kwargs):
    args = {"reference": DIRECTORY, "reference_field": "name", "reference_filter": None, "target": ENDPOINTS, "target_field": "endpoint_name", "target_filter": None}
    args.update(kwargs)
    with pytest.raises(ValueError):
        coverage.build_anti_join_xql(**args, list_limit=None)


def test_host_filter_value_is_escaped_as_a_literal():
    xql = coverage.build_reference_total_xql(DIRECTORY, "name", ("type", 'comp" | dataset = x'))

    assert 'type = "comp\\" | dataset = x"' in xql


@pytest.mark.parametrize("entry", [{"field": "type | x", "value": "computer"}, {"field": "type", "value": 'computer" or 1=1'}, {"field": "type", "value": ""}])
def test_catalogue_rejects_unsafe_host_filter(entry):
    record = {"match": "site_dir_raw", "domain": "directory", "description": "Site directory.", "host_filter": entry}
    with pytest.raises(dc.CatalogueError):
        dc.parse_catalogue(json.dumps({"version": 1, "entries": [record]}), "overlay")


@pytest.mark.asyncio
async def test_coverage_gap_reports_counts_and_a_bounded_projected_list(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [DIRECTORY, ENDPOINTS])

    response = await coverage.coverage_gap(_ctx(), reference=DIRECTORY, target=ENDPOINTS, max_missing=5000)

    assert response["success"] is True
    assert response["reference"] == {"dataset": DIRECTORY, "host_field": "name", "hosts": 10}
    assert (response["missing_from_target"], response["covered"], response["coverage_percent"]) == (3, 7, 70.0)
    assert response["missing_hosts"] == ["WKS-1", "WKS-2", "WKS-3"] and response["missing_hosts_truncated"] is False
    assert "secret_extra" not in json.dumps(response)
    generated = fake.generated()
    assert len(generated) == 3 and all('type = "computer"' in query for query in generated)
    assert generated[-1].endswith(f"| limit {coverage.MAX_MISSING}")
    assert all(call["timeframe"] == {"relativeTime": 7 * 86_400_000} for call in fake.calls if "alter " in call["query"])
    purposes = [(item["dataset"], item["purpose"]) for item in response["provenance"]["queries"] if item["purpose"] != "field_discovery"]
    assert purposes == [(DIRECTORY, "reference_total"), (f"{DIRECTORY}+{ENDPOINTS}", "missing_count"), (f"{DIRECTORY}+{ENDPOINTS}", "missing_hosts")]


@pytest.mark.asyncio
async def test_coverage_gap_skips_the_list_when_nothing_is_missing(monkeypatch):
    fake = FakeXsiam(missing=0)
    _install(monkeypatch, fake, [DIRECTORY, ENDPOINTS])

    response = await coverage.coverage_gap(_ctx(), reference=DIRECTORY, target=ENDPOINTS)

    assert response["missing_hosts"] == [] and response["coverage_percent"] == 100.0
    assert len(fake.generated()) == 2


@pytest.mark.asyncio
async def test_coverage_gap_requires_policy_on_both_datasets_before_any_join(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [DIRECTORY])

    response = await coverage.coverage_gap(_ctx(), reference=DIRECTORY, target=ENDPOINTS)

    assert response["success"] is False and "not allowed" in response["error"] and ENDPOINTS in response["error"]
    assert fake.generated() == []
    assert ENDPOINTS not in {call["dataset"] for call in fake.calls}


@pytest.mark.asyncio
async def test_coverage_gap_refuses_datasets_without_a_verified_host_field(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [ENDPOINTS, TRAFFIC, "mystery_raw"])

    no_host_role = await coverage.coverage_gap(_ctx(), reference=ENDPOINTS, target=TRAFFIC)
    same = await coverage.coverage_gap(_ctx(), reference=ENDPOINTS, target=ENDPOINTS)
    malformed = await coverage.coverage_gap(_ctx(), reference="endpoints | limit 1", target=ENDPOINTS)

    assert "no verified host name field" in no_host_role["error"]
    assert same["success"] is False and malformed["success"] is False
    assert fake.generated() == []


@pytest.mark.asyncio
async def test_generated_xql_runner_checks_every_declared_dataset(monkeypatch):
    fake = FakeXsiam()
    _install(monkeypatch, fake, [DIRECTORY])
    run = helper_runtime.HelperRun(_ctx(), MCPContext(auth_headers={}, principal_id="tier1@example.com", groups=("Tier1",)))
    timeframe = QueryTimeframe(relative_ms=3_600_000)

    with pytest.raises(PermissionError):
        await helper_runtime.run_generated_xql(run, "dataset = pan_dss_raw | limit 1", (DIRECTORY, ENDPOINTS), ("x",), 1, timeframe, "t")
    with pytest.raises(ValueError):
        await helper_runtime.run_generated_xql(run, "dataset = pan_dss_raw | limit 1", (), ("x",), 1, timeframe, "t")
    assert fake.calls == []


@pytest.mark.asyncio
async def test_coverage_gap_contract_and_default_policy():
    server = FastMCP()
    coverage.CoverageModule(server).register_tools()
    schema = (await server.get_tool("coverage_gap")).parameters

    assert sorted(schema["required"]) == ["reference", "target"]
    assert {"query", "xql", "filters", "fields", "join", "tenants"}.isdisjoint(schema["properties"])
    default_policy = json.loads(Settings.model_fields["tool_access_policy"].default)
    assert "coverage_gap" in default_policy["Tier1"] and "coverage_gap" in default_policy["SOC"]
