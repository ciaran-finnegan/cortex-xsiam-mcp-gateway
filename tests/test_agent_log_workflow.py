import inspect
import json
from types import SimpleNamespace

import pytest

from entities.MCPContext import MCPContext
from usecase.builtin_components import logs


def _ctx(groups=("Tier1",)):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(
                auth_headers={},
                principal_id="tier1@example.com",
                groups=groups,
            )
        )
    )


def _response(payload: str) -> dict:
    return json.loads(payload)


@pytest.mark.asyncio
async def test_search_logs_signature_has_no_natural_language_query():
    signature = inspect.signature(logs.search_logs)

    assert "natural_language_query" not in signature.parameters


@pytest.mark.asyncio
async def test_guidance_tells_agent_to_use_structured_calls():
    guidance = _response(await logs.get_log_search_guidance())

    assert "natural_language_query" not in json.dumps(guidance)
    assert guidance["plain_english_handling"]["owner"].startswith("Claude Code, Codex")
    assert "list_log_datasets" in guidance["tools"]
    assert "discover_log_fields" in guidance["tools"]
    assert "query_dataset" in guidance["tools"]
    assert "search_logs" in guidance["tools"]
    assert "structured query_dataset arguments" in " ".join(guidance["rules"])


@pytest.mark.asyncio
async def test_list_log_datasets_filters_allowed_compact_metadata(monkeypatch):
    from config.config import get_config

    class FakeFetcher:
        async def send_request(self, path, data):
            assert path == "/xql/get_datasets"
            assert data == {"request_data": {}}
            return {
                "reply": [
                    {
                        "Dataset Name": "auth_logs ",
                        "Type": "CUSTOM",
                        "Log Update Type": "LOGS",
                        "Default Query Target": "TRUE",
                        "Total Size Stored": 999,
                    },
                    {
                        "Dataset Name": "secret_admin_logs",
                        "Type": "CUSTOM",
                        "Total Size Stored": 999,
                    },
                ]
            }

    async def fake_get_fetcher(ctx):
        return FakeFetcher()

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1":["auth_logs"]}')
    monkeypatch.setattr(logs, "get_fetcher", fake_get_fetcher)

    response = _response(await logs.list_log_datasets(_ctx(), name_contains="auth", max_datasets=10))

    assert response["success"] == "true"
    assert response["source"] == "xsiam_api"
    assert response["count"] == 1
    assert response["datasets"][0]["dataset_name"] == "auth_logs"
    assert "total_size_stored" not in response["datasets"][0]
    assert response["datasets"][0]["dataset_policy"]["matched_group"] == "Tier1"


@pytest.mark.asyncio
async def test_discover_log_fields_returns_capped_metadata_not_values(monkeypatch):
    from config.config import get_config

    async def fake_run_xql_query(ctx, query, limit, **kwargs):
        assert query == "dataset = auth_logs | limit 25"
        assert limit == 25
        assert kwargs["max_poll_attempts"] == 30
        return {
            "reply": {
                "results": [
                    {
                        "event_id": "1",
                        "actor_effective_username": "alice",
                        "agent_hostname": "laptop-01",
                        "severity": "high",
                    }
                ]
            }
        }

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1":["auth_logs"]}')
    monkeypatch.setattr(logs, "_run_xql_query", fake_run_xql_query)

    response = _response(await logs.discover_log_fields(_ctx(), dataset="auth_logs", max_fields=2))

    assert response["success"] == "true"
    assert response["field_count"] == 2
    assert response["truncated"] is True
    assert response["fields"] == [
        {"name": "actor_effective_username", "type": "string", "observed_count": 1},
        {"name": "agent_hostname", "type": "string", "observed_count": 1},
    ]
    assert "alice" not in json.dumps(response)
    assert "laptop-01" not in json.dumps(response)


@pytest.mark.asyncio
async def test_claude_code_structured_search_dry_run_builds_policy_checked_xql(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1":["auth_logs"]}')

    response = _response(
        await logs.search_logs(
            _ctx(),
            dataset="auth_logs",
            filters=[
                {"field": "actor_effective_username", "operator": "contains", "value": "alice"},
                {"field": "event_sub_type", "operator": "contains", "value": "fail"},
            ],
            fields=["event_id", "actor_effective_username", "agent_hostname"],
            timeframe={"from": 1, "to": 2},
            limit=25,
            dry_run=True,
        )
    )

    assert response["success"] == "true"
    assert response["executed"] is False
    assert response["timeframe"] == {"from": 1, "to": 2}
    assert response["dataset_policy"]["matched_group"] == "Tier1"
    assert response["query"] == (
        'dataset = auth_logs | filter actor_effective_username contains "alice" '
        '| filter event_sub_type contains "fail" '
        "| fields event_id, actor_effective_username, agent_hostname | limit 25"
    )
    assert "translation" not in response


@pytest.mark.asyncio
async def test_claude_code_structured_search_denies_unallowed_dataset_before_execution(monkeypatch):
    from config.config import get_config

    async def fail_if_executed(*args, **kwargs):
        raise AssertionError("unallowed dataset must not be executed")

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1":["auth_logs"]}')
    monkeypatch.setattr(logs, "_run_xql_query", fail_if_executed)

    response = _response(
        await logs.search_logs(
            _ctx(),
            dataset="secret_admin_logs",
            fields=["event_id"],
            dry_run=False,
        )
    )

    assert response["success"] == "false"
    assert response["executed"] is False
    assert "not allowed to query dataset secret_admin_logs" in response["error"]


@pytest.mark.asyncio
async def test_discover_log_fields_denies_unallowed_dataset_before_sampling(monkeypatch):
    from config.config import get_config

    async def fail_if_sampled(*args, **kwargs):
        raise AssertionError("unallowed dataset must not be sampled")

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1":["auth_logs"]}')
    monkeypatch.setattr(logs, "_run_xql_query", fail_if_sampled)

    response = _response(await logs.discover_log_fields(_ctx(), dataset="secret_admin_logs"))

    assert response["success"] == "false"
    assert "not allowed to query dataset secret_admin_logs" in response["error"]


@pytest.mark.asyncio
async def test_search_logs_has_no_raw_query_or_tenant_parameters():
    signature = inspect.signature(logs.search_logs)

    assert "query" not in signature.parameters
    assert "tenants" not in signature.parameters
    assert signature.parameters["dataset"].default is inspect.Parameter.empty
    assert signature.parameters["fields"].default is inspect.Parameter.empty


@pytest.mark.asyncio
async def test_search_logs_compatibility_path_projects_and_bounds_upstream_rows(monkeypatch):
    from config.config import get_config

    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"Tier1":["auth_logs"]}')
    monkeypatch.setattr(get_config(), "dataset_query_max_rows", 2)

    async def fake_run(ctx, query, limit, **kwargs):
        assert query.endswith("| fields event_id | limit 2")
        assert limit == 2
        return {
            "query_id": "query-1",
            "reply": {
                "status": "SUCCESS",
                "results": {
                    "data": [
                        {"event_id": "1", "unrequested": "hidden"},
                        {"event_id": "2", "unrequested": "hidden"},
                    ]
                },
            },
        }

    monkeypatch.setattr(logs, "_run_xql_query", fake_run)
    response = _response(
        await logs.search_logs(
            _ctx(),
            dataset="auth_logs",
            fields=["event_id"],
            limit=500,
        )
    )

    assert response["success"] == "true"
    assert response["returned"] == 2
    assert response["rows"] == [{"event_id": "1"}, {"event_id": "2"}]
    assert "reply" not in response
