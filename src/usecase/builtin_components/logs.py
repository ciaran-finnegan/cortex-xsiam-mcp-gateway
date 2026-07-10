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
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher
from usecase.identity import resolve_mcp_context
from usecase.log_policy import (
    DatasetAuthorizationError,
    ensure_dataset_authorized,
)
from usecase.xql_builder import (
    MAX_XQL_RESULT_LIMIT,
    build_structured_xql,
)
from usecase.xql_discovery import (
    DEFAULT_DISCOVERY_DATASET_COUNT,
    DEFAULT_DISCOVERY_FIELD_COUNT,
    DEFAULT_DISCOVERY_SAMPLE_SIZE,
    MAX_DISCOVERY_DATASET_COUNT,
    MAX_DISCOVERY_FIELD_COUNT,
    MAX_DISCOVERY_SAMPLE_SIZE,
    build_field_discovery_xql,
    extract_xql_rows,
    filter_authorized_dataset_records,
    filter_field_catalog,
    infer_field_catalog,
    normalize_dataset_record,
    policy_dataset_records,
)
from usecase.xql_executor import run_xql_query
from usecase.xql_results import bound_result_rows, result_metadata

logger = logging.getLogger(__name__)


async def get_log_search_guidance() -> str:
    """
    Return agent-facing instructions for safe Cortex XSIAM log search tool use.

    LLM agents should translate user intent into structured MCP calls. The MCP
    server supplies dataset/field discovery and enforces policy.
    """
    return create_response(
        data={
            "recommended_agent_workflow": [
                "Convert the user's plain-English goal into a small investigation plan.",
                "Call list_log_datasets with name_contains when possible to find allowed candidate datasets.",
                "Call discover_log_fields for one candidate dataset, using field_name_contains when the user mentioned a likely concept such as user, host, ip, process, or severity.",
                "Call query_dataset with explicit dataset, fields or metrics, timeframe, and a low limit.",
                "Refine with another discover_log_fields or search_logs call only when needed.",
            ],
            "rules": [
                "Do not invent dataset or field names; discover them first.",
                "Convert plain-English requests into structured query_dataset arguments in Claude Code, Codex, or another MCP client agent.",
                "Request only the fields needed to answer the user.",
                "Use low limits first and summarize results; do not pull broad result sets by default.",
                "Use dry_run=true on query_dataset when you need to inspect generated XQL before execution.",
                "If a dataset or field is denied or absent, ask the user for a narrower request or use another allowed dataset.",
            ],
            "tools": {
                "list_log_datasets": "Returns datasets allowed by current dataset policy.",
                "discover_log_fields": "Samples one allowed dataset with XQL and returns capped observed field metadata, not event data.",
                "query_dataset": "Preferred typed row and aggregate query tool for any allowed XSIAM dataset.",
                "continue_dataset_query": "Continues a deterministic row query without offset pagination.",
                "search_logs": "Compatibility wrapper for simple structured row searches.",
                "execute_xql_query": "Privileged raw-XQL escape hatch for security/admin roles.",
            },
            "plain_english_handling": {
                "owner": "Claude Code, Codex, or another MCP client agent",
                "server_contract": "This MCP server does not accept natural-language queries. It accepts discovered datasets, discovered fields, typed row or aggregate plans, privileged raw XQL, and bounded limits.",
            },
        }
    )


def _get_lifespan_context(ctx: Context):
    return resolve_mcp_context(ctx)


async def _run_xql_query(
    ctx: Context,
    query: str,
    limit: int,
    timeframe: dict | None = None,
    poll_interval_seconds: int = 1,
    max_poll_attempts: int = 60,
) -> dict:
    return await run_xql_query(
        ctx,
        query,
        min(max(int(limit), 1), MAX_XQL_RESULT_LIMIT),
        timeframe=timeframe,
        poll_interval_seconds=poll_interval_seconds,
        timeout_seconds=max(max_poll_attempts * max(poll_interval_seconds, 1), 1),
    )


async def search_logs(
    ctx: Context,
    dataset: Annotated[
        str,
        Field(description="Explicit policy-authorized dataset to search."),
    ],
    fields: Annotated[
        list[str],
        Field(description="Discovered fields to return. Required to keep responses compact across arbitrary datasets."),
    ],
    filters: Annotated[
        list[dict] | None,
        Field(description="Structured filters: [{'field': 'event_type', 'operator': 'contains', 'value': 'auth'}]."),
    ] = None,
    timeframe: Annotated[
        dict | None,
        Field(description="Optional XSIAM API timeframe object, for example {'from': 1598907600000, 'to': 1599080399000}."),
    ] = None,
    limit: Annotated[int, Field(description="Maximum result count. Prefer query_dataset for aggregates and continuation.")] = 25,
    dry_run: Annotated[
        bool,
        Field(description="When true, return generated XQL without executing it."),
    ] = False,
) -> str:
    """
    Compatibility wrapper for a simple structured row search in one XSIAM dataset.

    Claude Code, Codex, and other MCP agents should translate plain-English user
    requests into structured arguments after using list_log_datasets and
    discover_log_fields.
    """
    try:
        context = _get_lifespan_context(ctx)
        policy_decision = ensure_dataset_authorized(context, dataset)
        safe_limit = min(max(int(limit), 1), get_config().dataset_query_max_rows)
        xql = build_structured_xql(dataset, filters, fields, safe_limit)

        if dry_run:
            return create_response(
                data={
                    "query": xql,
                    "timeframe": timeframe,
                    "dataset_policy": policy_decision.__dict__,
                    "executed": False,
                }
            )

        response_data = await _run_xql_query(ctx, xql, safe_limit, timeframe=timeframe)
        if response_data.get("error"):
            return create_response(
                data={"error": response_data["error"], "executed": True},
                is_error=True,
            )
        rows, truncation = bound_result_rows(
            extract_xql_rows(response_data)[:safe_limit],
            allowed_fields=tuple(fields),
        )
        return create_response(
            data={
                "dataset": dataset,
                "rows": rows,
                "returned": len(rows),
                "executed": True,
                "query_id": response_data.get("query_id"),
                "dataset_policy": policy_decision.__dict__,
                "xsiam": result_metadata(response_data),
                "truncation": truncation,
            }
        )

    except DatasetAuthorizationError as e:
        logger.info(f"Dataset authorization denied: {e}")
        return create_response(data={"error": str(e), "executed": False}, is_error=True)
    except (ValueError, KeyError, TypeError) as e:
        logger.exception(f"Invalid log search request: {e}")
        return create_response(data={"error": str(e), "executed": False}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while searching logs: {e}")
        return create_response(data={"error": str(e), "executed": False}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to search logs: {e}")
        return create_response(data={"error": str(e), "executed": False}, is_error=True)


async def list_log_datasets(
    ctx: Context,
    name_contains: Annotated[
        str | None,
        Field(description="Optional case-insensitive substring filter for dataset names, for example 'cloud' or 'auth'."),
    ] = None,
    max_datasets: Annotated[
        int,
        Field(description=f"Maximum datasets to return. Capped at {MAX_DISCOVERY_DATASET_COUNT}."),
    ] = DEFAULT_DISCOVERY_DATASET_COUNT,
) -> str:
    """
    List XSIAM datasets the current principal is allowed to query.

    Uses the XSIAM `get_datasets` API when available, then filters results
    through `LOG_SEARCH_DATASET_POLICY`. If the API cannot be reached, returns
    the configured policy dataset names as a fallback.
    """
    context = _get_lifespan_context(ctx)
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("/xql/get_datasets", data={"request_data": {}})
        reply = response_data.get("reply", [])
        if not isinstance(reply, list):
            raise ValueError("Unexpected get_datasets response: reply must be a list")

        dataset_records = [
            normalized
            for item in reply
            if isinstance(item, dict)
            and (normalized := normalize_dataset_record(item)).get("dataset_name")
        ]
        allowed_records, truncated = filter_authorized_dataset_records(
            dataset_records,
            context,
            name_contains=name_contains,
            max_datasets=max_datasets,
        )
        return create_response(
            data={
                "source": "xsiam_api",
                "datasets": allowed_records,
                "count": len(allowed_records),
                "truncated": truncated,
                "guidance": "Use a name_contains filter to narrow broad dataset lists before selecting one dataset for field discovery.",
            }
        )
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, ValueError) as e:
        logger.exception("Failed to list XSIAM datasets dynamically: %s", e)
        fallback, truncated = policy_dataset_records(
            context,
            name_contains=name_contains,
            max_datasets=max_datasets,
        )
        return create_response(
            data={
                "source": "dataset_policy_fallback",
                "warning": str(e),
                "datasets": fallback,
                "count": len(fallback),
                "truncated": truncated,
            }
        )
    except Exception as e:
        logger.exception("Unexpected error while listing log datasets: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def discover_log_fields(
    ctx: Context,
    dataset: Annotated[
        str,
        Field(description="Allowed XSIAM dataset to sample for field discovery."),
    ],
    sample_size: Annotated[
        int,
        Field(description=f"Number of rows to sample with XQL. Capped at {MAX_DISCOVERY_SAMPLE_SIZE}."),
    ] = DEFAULT_DISCOVERY_SAMPLE_SIZE,
    timeframe: Annotated[
        dict | None,
        Field(description="Optional XSIAM API timeframe object for the sample query."),
    ] = None,
    field_name_contains: Annotated[
        str | None,
        Field(description="Optional case-insensitive substring filter for returned field names."),
    ] = None,
    max_fields: Annotated[
        int,
        Field(description=f"Maximum fields to return. Capped at {MAX_DISCOVERY_FIELD_COUNT}."),
    ] = DEFAULT_DISCOVERY_FIELD_COUNT,
) -> str:
    """
    Discover observed fields for an allowed XSIAM dataset by running a bounded XQL sample.

    This is agent guidance, not an exhaustive schema guarantee. XSIAM datasets can
    have sparse fields, parser-dependent fields, and delayed autocomplete/schema
    updates, so agents should handle missing fields and rerun discovery when a
    search fails.
    """
    try:
        context = _get_lifespan_context(ctx)
        policy_decision = ensure_dataset_authorized(context, dataset)
        safe_sample_size = min(max(int(sample_size), 1), MAX_DISCOVERY_SAMPLE_SIZE)
        query = build_field_discovery_xql(dataset, safe_sample_size)
        response_data = await _run_xql_query(
            ctx,
            query,
            safe_sample_size,
            timeframe=timeframe,
            max_poll_attempts=30,
        )
        if response_data.get("error"):
            return create_response(
                data={
                    "error": response_data["error"],
                    "dataset": dataset,
                    "dataset_policy": policy_decision.__dict__,
                },
                is_error=True,
            )

        rows = extract_xql_rows(response_data)
        all_fields = infer_field_catalog(rows)
        fields, truncated = filter_field_catalog(
            all_fields,
            field_name_contains=field_name_contains,
            max_fields=max_fields,
        )
        return create_response(
            data={
                "dataset": dataset,
                "source": "xql_sample",
                "sample_size_requested": safe_sample_size,
                "rows_observed": len(rows),
                "fields_observed_total": len(all_fields),
                "field_count": len(fields),
                "truncated": truncated,
                "fields": fields,
                "dataset_policy": policy_decision.__dict__,
                "exhaustive": False,
                "guidance": "Use these observed field names to build compact query_dataset calls. This tool returns schema guidance only; it intentionally does not return sample event values.",
            }
        )
    except DatasetAuthorizationError as e:
        logger.info("Dataset field discovery denied: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except (ValueError, KeyError, TypeError) as e:
        logger.exception("Invalid field discovery request: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception("PAPI error while discovering log fields: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("Failed to discover log fields: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def get_xql_query_quota(ctx: Context) -> str:
    """
    Retrieve XSIAM XQL query quota usage for operational visibility before running expensive searches.
    """
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("/xql/get_quota", data={"request_data": {}})
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting XQL query quota: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get XQL query quota: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class LogsModule(BaseModule):
    """
    Module for XSIAM log search and XQL query operations.
    """

    def register_tools(self):
        self._add_tool(get_log_search_guidance)
        self._add_tool(list_log_datasets)
        self._add_tool(discover_log_fields)
        self._add_tool(search_logs)
        self._add_tool(get_xql_query_quota)

    def register_resources(self):
        self._add_resource(
            get_log_search_guidance,
            uri="log-search://agent-guidance",
            name="XSIAM log search agent guidance",
            description="Instructions for agents using XSIAM log search tools safely.",
            mime_type="application/json",
        )

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
