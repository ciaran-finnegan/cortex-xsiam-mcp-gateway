import inspect

import pytest
from fastmcp import FastMCP

from main import initialize_mcp_server
from usecase.builtin_components.datasets import DatasetsModule
from usecase.builtin_components.logs import LogsModule, search_logs


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
