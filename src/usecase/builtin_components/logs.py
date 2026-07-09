import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

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
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher
from usecase.log_policy import DatasetAuthorizationError, ensure_dataset_authorized
from usecase.xql_builder import (
    MAX_XQL_RESULT_LIMIT,
    XQLTranslationError,
    build_structured_xql,
    translate_log_search_to_xql,
)

logger = logging.getLogger(__name__)


def _relative_timeframe_to_epoch_ms(relative: str) -> dict:
    amount = int(relative[:-1])
    unit = relative[-1]
    now = datetime.now(timezone.utc)

    if unit == "m":
        start = now - timedelta(minutes=amount)
    elif unit == "h":
        start = now - timedelta(hours=amount)
    elif unit == "d":
        start = now - timedelta(days=amount)
    else:
        raise ValueError(f"Unsupported relative timeframe: {relative}")

    return {"from": int(start.timestamp() * 1000), "to": int(now.timestamp() * 1000)}


def _extract_query_id(response_data: dict) -> str | None:
    reply = response_data.get("reply")
    if isinstance(reply, str):
        return reply
    if isinstance(reply, dict):
        for key in ("query_id", "id"):
            if reply.get(key):
                return str(reply[key])
    return None


def _get_lifespan_context(ctx: Context):
    return ctx.request_context.lifespan_context


async def _run_xql_query(
    ctx: Context,
    query: str,
    limit: int,
    timeframe: dict | None = None,
    tenants: list[str] | None = None,
    poll_interval_seconds: int = 1,
    max_poll_attempts: int = 60,
) -> dict:
    fetcher = await get_fetcher(ctx)
    request_data = {"query": query}

    if tenants is not None:
        request_data["tenants"] = tenants
    if timeframe is not None:
        request_data["timeframe"] = timeframe

    start_response = await fetcher.send_request("/xql/start_xql_query/", data={"request_data": request_data})
    query_id = _extract_query_id(start_response)

    if not query_id:
        return {
            "query": query,
            "start_response": start_response,
            "_metadata": {"formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS},
        }

    result_payload = {
        "request_data": {
            "query_id": query_id,
            "pending_flag": True,
            "limit": min(max(int(limit), 1), MAX_XQL_RESULT_LIMIT),
            "format": "json",
        }
    }

    for attempt in range(1, max_poll_attempts + 1):
        await asyncio.sleep(poll_interval_seconds)
        result_response = await fetcher.send_request("/xql/get_query_results/", data=result_payload)
        reply = result_response.get("reply")

        if isinstance(reply, dict):
            status = str(reply.get("status", "")).upper()
            if status in {"PENDING", "RUNNING"}:
                continue
            if status in {"FAILED", "ERROR"}:
                return {
                    "query": query,
                    "query_id": query_id,
                    "error": reply.get("error_message", reply.get("error", "XQL query failed")),
                    "reply": reply,
                }

        result_response.update(
            {
                "query": query,
                "query_id": query_id,
                "poll_attempts": attempt,
                "_metadata": {"formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS},
            }
        )
        return result_response

    return {
        "query": query,
        "query_id": query_id,
        "error": f"XQL query timed out after {max_poll_attempts} polling attempts",
    }


async def search_logs(
    ctx: Context,
    query: Annotated[
        str | None,
        Field(description="Raw XQL query to execute. Use this for precise analyst-authored XQL."),
    ] = None,
    natural_language_query: Annotated[
        str | None,
        Field(description="Natural-language search request. The server only translates safe common SOC patterns."),
    ] = None,
    dataset: Annotated[
        str,
        Field(description="Dataset to search when building XQL from structured or natural-language inputs."),
    ] = "xdr_data",
    filters: Annotated[
        list[dict] | None,
        Field(description="Structured filters: [{'field': 'event_type', 'operator': 'contains', 'value': 'auth'}]."),
    ] = None,
    fields: Annotated[
        list[str] | None,
        Field(description="Fields to return. Defaults to event_id, event_type, and event_sub_type."),
    ] = None,
    timeframe: Annotated[
        dict | None,
        Field(description="Optional XSIAM API timeframe object, for example {'from': 1598907600000, 'to': 1599080399000}."),
    ] = None,
    tenants: Annotated[
        list[str] | None,
        Field(description="Optional tenant list for the XSIAM query API."),
    ] = None,
    limit: Annotated[int, Field(description="Maximum result count. XSIAM get_query_results is capped at 1000.")] = 100,
    dry_run: Annotated[
        bool,
        Field(description="When true, return generated XQL without executing it."),
    ] = False,
) -> str:
    """
    Search Cortex XSIAM logs using raw XQL, structured parameters, or a constrained natural-language query.

    Prefer structured filters for routine agent workflows. Raw XQL is powerful and should be restricted by the
    future policy layer when this server is exposed to multiple users.
    """
    try:
        translation = None
        if query:
            xql = query.strip()
        elif natural_language_query:
            translated = translate_log_search_to_xql(natural_language_query, dataset, fields, limit)
            xql = translated["query"]
            translation = translated["translation"]
            if timeframe is None and translation.get("time_window"):
                timeframe = _relative_timeframe_to_epoch_ms(translation["time_window"]["relative"])
        else:
            xql = build_structured_xql(dataset, filters, fields, limit)

        policy_decision = ensure_dataset_authorized(_get_lifespan_context(ctx), dataset)

        if dry_run:
            return create_response(
                data={
                    "query": xql,
                    "translation": translation,
                    "timeframe": timeframe,
                    "dataset_policy": policy_decision.__dict__,
                    "executed": False,
                }
            )

        response_data = await _run_xql_query(ctx, xql, limit, timeframe=timeframe, tenants=tenants)
        response_data["translation"] = translation
        response_data["dataset_policy"] = policy_decision.__dict__
        response_data["executed"] = True
        return create_response(data=response_data)

    except DatasetAuthorizationError as e:
        logger.info(f"Dataset authorization denied: {e}")
        return create_response(data={"error": str(e), "executed": False}, is_error=True)
    except XQLTranslationError as e:
        logger.info(f"Natural-language XQL translation refused: {e}")
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
        self._add_tool(search_logs)
        self._add_tool(get_xql_query_quota)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
