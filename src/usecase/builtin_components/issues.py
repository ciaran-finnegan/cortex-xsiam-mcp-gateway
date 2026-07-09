import json
import logging
from typing import Annotated, Optional

from fastmcp import Context, FastMCP
from pydantic import Field

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
                    filters: Annotated[Optional[list[dict]], Field(description="Filters list to get the issues by. Leave empty go get all issues")] = None,
                    search_from: Annotated[int, Field(description="Marker for pagination starting point", default=0)] = 0,
                    search_to: Annotated[int, Field(description="Marker for pagination ending point", default=30)] = 30,
                    sort: Annotated[Optional[dict], Field(description="Dictionary of field and keyword to sort by. By default the sort is defined as observation time, desc")] = None,
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
                            query: Annotated[str, Field(description="The XQL query string to execute")],
                            timeout: Annotated[int, Field(description="Query timeout in seconds", default=60)] = 60,
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
    payload = {
        "request_data": {
            "query": query,
            "timeout": timeout,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        # Start the XQL query
        response_data = await fetcher.send_request("/xql/start_xql_query/", data=payload)
        logger.debug(f"XQL start query response: {response_data}")

        # Check if we got a query ID (async query) or results (sync query)
        if "reply" not in response_data:
            return create_response(data={"error": "Unexpected response format from XQL API: missing 'reply' field"}, is_error=True)

        reply = response_data["reply"]

        # Handle case where reply is a string (query ID) or dict
        query_id = None
        if isinstance(reply, str):
            # Query ID returned as string
            query_id = reply
            logger.info(f"XQL query started with query_id: {query_id}")
        elif isinstance(reply, dict):
            if "query_id" in reply:
                # Query ID in nested dict
                query_id = reply["query_id"]
                logger.info(f"XQL query started with query_id: {query_id}")
            elif "status" in reply and reply.get("status") == "SUCCESS":
                # Synchronous response with results already available
                logger.info("XQL query completed synchronously")
                response_data["_metadata"] = {
                    "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                }
                return create_response(data=response_data)
            else:
                # Unknown dict format, might be results directly
                logger.warning(f"Unexpected reply format (dict without query_id or status): {reply}")
                response_data["_metadata"] = {
                    "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                }
                return create_response(data=response_data)

        # If we have a query_id, we need to poll for results
        if not query_id:
            # No query ID and not synchronous results - treat as synchronous response
            logger.info("No query_id found, treating as synchronous response")
            response_data["_metadata"] = {
                "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
            }
            return create_response(data=response_data)

        # Poll for results
        import asyncio
        get_results_payload = {
            "request_data": {
                "query_id": query_id,
            }
        }

        max_attempts = 60  # Maximum polling attempts (60 seconds with 1 second intervals)
        attempt = 0

        logger.info(f"Starting to poll for XQL query results (query_id: {query_id})")

        while attempt < max_attempts:
            await asyncio.sleep(1)  # Wait 1 second between polls
            attempt += 1
            logger.debug(f"Polling attempt {attempt}/{max_attempts} for query_id: {query_id}")

            try:
                result_response = await fetcher.send_request("/xql/get_query_results/", data=get_results_payload)
                logger.debug(f"Poll response (attempt {attempt}): {result_response}")

                if "reply" not in result_response:
                    logger.warning(f"No 'reply' field in poll response: {result_response}")
                    # Check if results are directly in response
                    if "data" in result_response or "results" in result_response:
                        result_response["_metadata"] = {
                            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                        }
                        return create_response(data=result_response)
                    continue  # Try again

                result_reply = result_response["reply"]

                # Handle different response formats
                if isinstance(result_reply, dict):
                    status = result_reply.get("status", "PENDING")
                    logger.debug(f"Query status: {status}")

                    # Check if we have results data even if status isn't SUCCESS yet
                    # Also check for empty result sets (0 results is still a valid completion)
                    has_results = (
                        "data" in result_reply or
                        "results" in result_reply or
                        "data" in result_response or
                        "results" in result_response or
                        "number_of_results" in result_reply or
                        "result_count" in result_reply or
                        "total_count" in result_reply or
                        result_reply.get("number_of_results", -1) >= 0 or
                        result_reply.get("result_count", -1) >= 0
                    )

                    if status == "SUCCESS" or (has_results and status in ["SUCCESS", "COMPLETED", "DONE"]):
                        # Query completed successfully
                        logger.info(f"XQL query completed successfully after {attempt} attempts (status: {status})")
                        result_response["_metadata"] = {
                            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                        }
                        return create_response(data=result_response)
                    elif status == "FAILED" or status == "ERROR":
                        error_msg = result_reply.get("error_message", result_reply.get("error", "Query failed"))
                        logger.error(f"XQL query failed: {error_msg}")
                        return create_response(data={"error": f"XQL query failed: {error_msg}"}, is_error=True)
                    elif has_results:
                        # We have results even though status might be PENDING/RUNNING - return them
                        logger.info(f"XQL query returned results (status: {status}) after {attempt} attempts")
                        result_response["_metadata"] = {
                            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                        }
                        return create_response(data=result_response)
                    # Otherwise, status is PENDING or RUNNING, continue polling
                elif isinstance(result_reply, list):
                    # Results might be directly in a list
                    logger.info(f"Received results list with {len(result_reply)} items")
                    result_response["_metadata"] = {
                        "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                    }
                    return create_response(data=result_response)
                else:
                    # Unknown format, log and continue
                    logger.warning(f"Unexpected result_reply type: {type(result_reply)}, value: {result_reply}")
                    # Check if we have data elsewhere in the response
                    if "data" in result_response or "results" in result_response:
                        result_response["_metadata"] = {
                            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                        }
                        return create_response(data=result_response)
                    # If result_reply is a string and we've polled a few times, might be an error message
                    if isinstance(result_reply, str) and attempt > 5:
                        logger.warning(f"Received string response after multiple polls: {result_reply}")
                        # Might be an error or completion message, return it
                        result_response["_metadata"] = {
                            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
                        }
                        return create_response(data=result_response)

            except Exception as poll_error:
                logger.exception(f"Error during polling attempt {attempt}: {poll_error}")
                # Continue polling unless it's a critical error
                if attempt >= max_attempts - 1:
                    return create_response(data={"error": f"Error polling for results: {str(poll_error)}"}, is_error=True)

        # Timeout waiting for results
        logger.warning(f"XQL query timed out after {max_attempts} polling attempts")
        return create_response(data={"error": f"XQL query timed out waiting for results after {max_attempts} attempts"}, is_error=True)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while executing XQL query: {e}")
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
