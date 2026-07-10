import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from config.config import get_config
from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from entities.llm_config import LLM_FORMATTING_BASE_INSTRUCTIONS
from pkg.util import create_response, read_resource
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher
from usecase.identity import resolve_mcp_context
from usecase.log_policy import (
    ALL_DATASETS,
    DatasetAuthorizationError,
    ToolAuthorizationError,
    ensure_dataset_authorized,
    ensure_raw_xql_authorized,
)
from usecase.xql_builder import enforce_terminal_xql_limit
from usecase.xql_discovery import extract_xql_rows
from usecase.xql_executor import run_xql_query
from usecase.xql_results import bound_result_rows, result_metadata

logger = logging.getLogger(__name__)

async def get_issues_response() -> str:
    try:
        issues_json = read_resource("issues_response.json")
        return create_response(data={"response": json.loads(issues_json)})
    except FileNotFoundError as e:
        logger.exception(f"Issues response file not found: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in issues response file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to read issues responses: {e}")
        return create_response(data={"error": str(e)}, is_error=True)

async def get_issues(ctx: Context,
                    filters: Annotated[list[dict] | None, Field(description="Filters list to get the issues by. Leave empty go get all issues")] = None,
                    search_from: Annotated[int, Field(description="Marker for pagination starting point", default=0)] = 0,
                    search_to: Annotated[int, Field(description="Marker for pagination ending point", default=30)] = 30,
                    sort: Annotated[dict | None, Field(description="Dictionary of field and keyword to sort by. By default the sort is defined as observation time, desc")] = None,
                    ) -> str:
    """
    Retrieves a list of issues or alerts from the Cortex platform.
    Use this tool to fetch all issues, or a filtered subset of issues, or one issue, based on various criteria such as time range, severity, status, or specific alert IDs.
    This is highly valuable for security monitoring, threat hunting, and reporting on detected security events.

    Args:
        ctx: The FastMCP context.
        filters: Filters list to get the issues by. Examples -
            [{
                        "field": "id",
                        "operator": "in",
                        "value": [123]
            }],
            [{
                        "field": "status",
                        "operator": "in",
                        "value": ["new", "under_investigation"]
            }]
            Leave empty go get all issues.
            Allowed values:"id","external_id","detection_method","issue_domain","severity","_insert_time","status"
        search_from: Marker for pagination starting point.
        search_to: Marker for pagination ending point.
        sort: Field to sort by. Example -
            {
                    "field": "observation_time",
                    "keyword": "desc"
            }
            Allowed fields are "id","observation_time","severity".
    Returns:
        JSON response containing issue data.
      """

    payload = {
        "request_data": {
            "search_from": search_from,
            "search_to": search_to,
        }
    }
    if filters:
        # Create a copy to avoid modifying the original
        filters_copy = [f.copy() for f in filters]
        for f in filters_copy:
            if f.get("field") == "id":
                f["value"] = [int(v) for v in f["value"]]  # Ensure id values are integers
        payload["request_data"]["filters"] = filters_copy
    if sort:
        payload["request_data"]["sort"] = sort

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("/issue/search/", data=payload)
        response_data["_metadata"] = {
            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
        }

        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting issues: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get issues: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def execute_xql_query(ctx: Context,
                            query: Annotated[str, Field(description="Privileged XQL ending with a numeric '| limit N' stage")],
                            timeout: Annotated[int, Field(description="Query timeout in seconds", default=60)] = 60,
                            result_limit: Annotated[int, Field(description="Maximum returned rows, capped by server policy", default=100)] = 100,
                            timeframe: Annotated[dict | None, Field(description="Optional XSIAM API relative or absolute timeframe")] = None,
                            ) -> str:
    """
    Execute an XQL (Extended Query Language) query to search for issues, events, or other data in Cortex XSIAM.
    This tool allows for advanced, flexible searches using XQL syntax, which is more powerful than standard filters.

    Use this tool to search for issues by name, description, or any other field using XQL query syntax.
    This is particularly useful for finding specific issues when you know part of the name or description.

    Args:
        ctx: The FastMCP context.
        query: The XQL query string. Example queries:
            - Search for issues with "developer secret" in the name:
              `dataset = xdr_data | filter event_type = "issue" | filter name contains "developer secret" | fields issue_id, name, observation_time, severity`
            - Search for issues in the last 30 days:
              `dataset = xdr_data | filter event_type = "issue" | filter observation_time >= now() - 30d | fields issue_id, name, observation_time`
        timeout: Query timeout in seconds (default: 60).

    Returns:
        JSON response containing query results.
    """
    try:
        context = resolve_mcp_context(ctx)
        ensure_raw_xql_authorized(context)
        # Raw XQL can reference joins or subqueries, so it is available only to
        # principals whose dataset policy grants all datasets.
        ensure_dataset_authorized(context, ALL_DATASETS)
        safe_limit = min(max(int(result_limit), 1), get_config().dataset_query_max_rows)
        bounded_query = enforce_terminal_xql_limit(query, safe_limit)
        response_data = await run_xql_query(
            ctx,
            bounded_query,
            safe_limit,
            timeframe=timeframe,
            timeout_seconds=timeout,
        )
        if response_data.get("error"):
            return create_response(data=response_data, is_error=True)
        rows, truncation = bound_result_rows(extract_xql_rows(response_data)[:safe_limit])
        return create_response(
            data={
                "rows": rows,
                "returned": len(rows),
                "query_id": response_data.get("query_id"),
                "xsiam": result_metadata(response_data),
                "truncation": truncation,
            }
        )

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while executing XQL query: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except ToolAuthorizationError as e:
        logger.info("Raw XQL authorization denied: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except DatasetAuthorizationError as e:
        logger.info("Raw XQL dataset authorization denied: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to execute XQL query: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IssuesModule(BaseModule):
    """
       Module for managing and retrieving security issues and alerts from the Cortex platform.

       This module provides tools and resources for interacting with the Cortex platform's issue/alert system,
       enabling users to search, filter, and paginate through security issues. It supports various filtering
       criteria such as status, severity, time range, and custom search parameters.

       The module registers:
       - Tools: get_issues - for retrieving filtered and paginated issue data
       - Resources: issues_response.json - example API response for reference

       This module is essential for security monitoring, threat hunting, incident response,
       and generating reports on detected security events within the Cortex platform.
       """

    def register_tools(self):
        self._add_tool(get_issues)
        self._add_tool(execute_xql_query)

    def register_resources(self):
        self._add_resource(get_issues_response, uri="resources://issues_response.json",
    name="issues_response.json",
    description="Example response from the issues API",
    mime_type="application/json",)

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
