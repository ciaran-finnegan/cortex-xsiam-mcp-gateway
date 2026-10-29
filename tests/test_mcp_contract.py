import inspect
import re
from types import SimpleNamespace
from typing import get_args

import pytest
from fastmcp import FastMCP

from config.config import get_config
from entities.MCPContext import MCPContext
from main import initialize_mcp_server
from usecase import xql_docs, xql_validation
from usecase.builtin_components.datasets import (
    DatasetsModule,
    XQLHelpTopic,
    get_xql_help,
)
from usecase.builtin_components.logs import LogsModule, search_logs
from usecase.builtin_components.validation import XQLValidationModule, validate_xql
from usecase.xql_docs import (
    CORTEX_DOCS_BASE_URL,
    XQL_HELP_TOPIC_DOCS,
    XQL_PROBLEM_DOCS,
    help_topic_docs,
)
from usecase.xql_errors import XQL_ERROR_CLASSES


@pytest.mark.asyncio
async def test_dataset_query_mcp_schema_exposes_typed_agent_contract():
    server = FastMCP()
    DatasetsModule(server).register_tools()
    tool = await server.get_tool("query_dataset")
    schema = tool.parameters

    assert schema["required"] == ["dataset"]
    assert schema["properties"]["mode"]["enum"] == ["rows", "aggregate"]
    assert schema["properties"]["filters"]["anyOf"][0]["items"]["$ref"] == "#/$defs/QueryFilter"
    assert "contains" in schema["$defs"]["QueryFilter"]["properties"]["operator"]["enum"]
    assert "count_distinct" in schema["$defs"]["QueryMetric"]["properties"]["function"]["enum"]


@pytest.mark.asyncio
async def test_log_tools_do_not_expose_raw_query_or_caller_selected_tenant():
    signature = inspect.signature(search_logs)
    assert "query" not in signature.parameters
    assert "tenants" not in signature.parameters
    assert signature.parameters["dataset"].default is inspect.Parameter.empty
    assert signature.parameters["fields"].default is inspect.Parameter.empty

    server = FastMCP()
    LogsModule(server).register_tools()
    schema = (await server.get_tool("search_logs")).parameters
    assert "query" not in schema["properties"]
    assert "tenants" not in schema["properties"]
    assert {"dataset", "fields"}.issubset(schema["required"])


@pytest.mark.asyncio
async def test_fastmcp3_full_server_initialization_registers_builtin_and_openapi_tools():
    server = await initialize_mcp_server("test-key", "test-key-id", "https://api.example.test")
    tool_names = {tool.name for tool in await server.list_tools(run_middleware=False)}

    assert {
        "query_dataset",
        "continue_dataset_query",
        "discover_log_fields",
        "execute_xql_query",
        "get_assets",
        "get_cases",
    }.issubset(tool_names)


@pytest.mark.asyncio
async def test_full_server_exposes_learning_tools_and_resource_template():
    server = await initialize_mcp_server("test-key", "test-key-id", "https://api.example.test")
    tool_names = {tool.name for tool in await server.list_tools(run_middleware=False)}
    templates = {template.uri_template for template in await server.list_resource_templates()}

    assert {"get_learned_facts", "learning_digest", "revert_learned"}.issubset(tool_names)
    assert "tenant://learned/{kind}" in templates
    revert_schema = (await server.get_tool("revert_learned")).parameters
    assert set(revert_schema["properties"]) == {"entry_id", "action"}
    assert revert_schema["required"] == ["entry_id"]
    assert revert_schema["properties"]["action"]["enum"] == ["revert", "pin", "unpin"]


@pytest.mark.asyncio
async def test_validate_xql_mcp_schema_and_description():
    server = FastMCP()
    XQLValidationModule(server).register_tools()
    tool = await server.get_tool("validate_xql")
    schema = tool.parameters

    assert schema["required"] == ["query"]
    assert set(schema["properties"]) == {"query", "timeframe", "probe"}
    assert schema["properties"]["query"]["type"] == "string"
    assert schema["properties"]["probe"]["type"] == "boolean"
    assert schema["properties"]["probe"]["default"] is False
    assert schema["properties"]["timeframe"]["default"] is None
    assert "documentation MCP server" in tool.description
    assert "never contacts the documentation site" in tool.description


@pytest.mark.asyncio
async def test_validate_xql_result_contract(monkeypatch):
    monkeypatch.setattr(get_config(), "identity_auth_mode", "none")
    monkeypatch.setattr(get_config(), "log_search_dataset_policy", '{"DataReader":["sample_auth_logs"]}')
    ctx = SimpleNamespace(
        request_context=SimpleNamespace(
            lifespan_context=MCPContext(auth_headers={}, principal_id="analyst@example.test", groups=("DataReader",))
        )
    )

    result = await validate_xql(ctx, "dataset = restricted_hr_logs | fields user_name")

    assert {"ok", "problems", "corrected_query", "estimate"}.issubset(result)
    assert result["ok"] is False
    assert isinstance(result["corrected_query"], str)
    for problem in result["problems"]:
        assert {"code", "message", "docs"}.issubset(problem)
        assert set(problem) <= {"code", "severity", "message", "field", "suggestion", "docs"}
        assert problem["docs"].startswith(CORTEX_DOCS_BASE_URL + "/")


@pytest.mark.asyncio
async def test_every_xql_help_topic_and_problem_code_links_to_the_vendor_docs():
    server = FastMCP()
    DatasetsModule(server).register_tools()
    help_tool = await server.get_tool("get_xql_help")
    assert "documentation MCP server" in help_tool.description

    for topic in get_args(XQLHelpTopic):
        response = await get_xql_help(topic)
        assert response["docs"] == help_topic_docs(topic)
        assert response["docs"].startswith(CORTEX_DOCS_BASE_URL + "/")
    assert set(XQL_HELP_TOPIC_DOCS) <= set(get_args(XQLHelpTopic))

    source = inspect.getsource(xql_validation)
    emitted = set(re.findall(r'Problem\(\s*"([a-z_]+)"', source)) | set(XQL_ERROR_CLASSES)
    assert emitted <= set(XQL_PROBLEM_DOCS)
    assert all(url.startswith(CORTEX_DOCS_BASE_URL + "/") for url in XQL_PROBLEM_DOCS.values())


def test_docs_links_are_static_and_never_fetched():
    source = inspect.getsource(xql_docs)
    assert not re.search(r"^\s*(import|from)\s+(httpx|requests|urllib|aiohttp|usecase\.fetcher)", source, re.MULTILINE)


@pytest.mark.asyncio
async def test_full_server_registers_validate_xql():
    server = await initialize_mcp_server("test-key", "test-key-id", "https://api.example.test")
    tool_names = {tool.name for tool in await server.list_tools(run_middleware=False)}

    assert "validate_xql" in tool_names
