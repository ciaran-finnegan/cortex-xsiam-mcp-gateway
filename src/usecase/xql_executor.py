import asyncio
import hashlib
import json
import time
from typing import Any

from config.config import get_config
from usecase import cost_guard
from usecase.engagement import record_query_telemetry
from usecase.fetcher import get_fetcher
from usecase.xql_builder import MAX_XQL_RESULT_LIMIT

_semaphores: dict[tuple[int, int], asyncio.Semaphore] = {}


async def run_xql_query(
    ctx,
    query: str,
    result_limit: int,
    *,
    timeframe: dict[str, int] | None = None,
    poll_interval_seconds: float = 1,
    timeout_seconds: int = 60,
    approval: str | None = None,
    tool: str | None = None,
) -> dict[str, Any]:
    """Run one XQL query through the cost guard and record it in the engagement log.

    A timeframe is required. The guard may return a cached reply, cap the timeout, or raise
    CostGuardRefusal before anything is submitted; every reply it lets through carries a
    ``quota`` block. Only queries that reach XSIAM are recorded: a refusal ran nothing and a
    cache hit spent nothing, so recording either would count the same units twice. Recording
    is telemetry only and never blocks or alters a query.
    """
    if not isinstance(query, str) or not query.strip():
        raise ValueError("XQL query must be a non-empty string")
    if len(query) > get_config().xql_max_query_chars:
        raise ValueError(f"XQL query exceeds the configured {get_config().xql_max_query_chars}-character limit")
    safe_limit = min(max(int(result_limit), 1), MAX_XQL_RESULT_LIMIT)
    ticket = await cost_guard.prepare_query(
        ctx,
        query,
        timeframe=timeframe,
        result_limit=safe_limit,
        timeout_seconds=timeout_seconds,
        approval=approval,
        tool=tool,
    )
    if ticket.cached_response is not None:
        return ticket.cached_response
    # Duration uses its own clock so it stays independent of the polling deadline.
    started = time.monotonic()
    try:
        response = await _submit_and_poll(
            ctx,
            query,
            safe_limit,
            timeframe=ticket.timeframe_api,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=ticket.timeout_seconds,
            ticket=ticket,
        )
    except BaseException as e:
        cost_guard.abandon(ticket)
        if ticket.submitted and isinstance(e, Exception):
            await record_query_telemetry(
                ctx,
                query=query,
                timeframe=ticket.timeframe_api,
                response=None,
                duration_ms=(time.monotonic() - started) * 1000,
                error=e,
            )
        raise
    # finish_query reads the session spend before this query is recorded and adds it itself.
    response = await cost_guard.finish_query(ctx, ticket, response)
    await record_query_telemetry(
        ctx,
        query=query,
        timeframe=ticket.timeframe_api,
        response=response,
        duration_ms=(time.monotonic() - started) * 1000,
    )
    return response


async def _submit_and_poll(
    ctx,
    query: str,
    safe_limit: int,
    *,
    timeframe: dict[str, int],
    poll_interval_seconds: float,
    timeout_seconds: int,
    ticket: cost_guard.GuardTicket,
) -> dict[str, Any]:
    async with _query_semaphore():
        with cost_guard.track_slot():
            fetcher = await get_fetcher(ctx)
            await cost_guard.record_fetch_credential(ticket, fetcher)
            request_data: dict[str, Any] = {"query": query, "timeframe": timeframe}

            ticket.submitted = True
            start_response = await fetcher.send_request(
                "/xql/start_xql_query/",
                data={"request_data": request_data},
            )
            query_id = _extract_query_id(start_response)
            start_failure = _failure_response(start_response, query_id=query_id, poll_attempts=0)
            if start_failure is not None:
                return start_failure
            if _is_complete(start_response):
                start_response["query_id"] = query_id
                start_response["poll_attempts"] = 0
                return start_response
            if not query_id:
                return {
                    "error": "XSIAM did not return a query identifier",
                    "query_id": None,
                }

            result_payload = {
                "request_data": {
                    "query_id": query_id,
                    "pending_flag": True,
                    "limit": safe_limit,
                    "format": "json",
                }
            }
            deadline = _monotonic() + max(int(timeout_seconds), 1)
            attempts = 0
            while _monotonic() < deadline:
                await asyncio.sleep(max(float(poll_interval_seconds), 0))
                attempts += 1
                result_response = await fetcher.send_request("/xql/get_query_results/", data=result_payload)
                reply = result_response.get("reply")
                if isinstance(reply, dict):
                    status = str(reply.get("status", "")).upper()
                    if status in {"PENDING", "RUNNING"}:
                        continue
                    if status in {"FAILED", "FAIL", "ERROR"}:
                        failure = _failure_response(
                            result_response,
                            query_id=query_id,
                            poll_attempts=attempts,
                        )
                        if failure is not None:
                            return failure
                    if status in {"SUCCESS", "COMPLETED", "DONE"} or _has_results(result_response):
                        result_response["query_id"] = query_id
                        result_response["poll_attempts"] = attempts
                        return result_response
                elif _has_results(result_response):
                    result_response["query_id"] = query_id
                    result_response["poll_attempts"] = attempts
                    return result_response

            return {
                "query_id": query_id,
                "poll_attempts": attempts,
                "error": f"XQL query timed out after {max(int(timeout_seconds), 1)} seconds",
            }


def _extract_query_id(response_data: dict[str, Any]) -> str | None:
    reply = response_data.get("reply")
    if isinstance(reply, str):
        return reply
    if isinstance(reply, dict):
        for key in ("query_id", "id"):
            if reply.get(key):
                return str(reply[key])
    return None


def _has_results(response_data: dict[str, Any]) -> bool:
    reply = response_data.get("reply")
    if isinstance(reply, dict) and "results" in reply:
        return True
    return "results" in response_data or "data" in response_data


def _is_complete(response_data: dict[str, Any]) -> bool:
    if _has_results(response_data):
        return True
    reply = response_data.get("reply")
    return isinstance(reply, dict) and str(reply.get("status", "")).upper() in {
        "SUCCESS",
        "COMPLETED",
        "DONE",
    }


def _failure_response(
    response_data: dict[str, Any],
    *,
    query_id: str | None,
    poll_attempts: int,
) -> dict[str, Any] | None:
    reply = response_data.get("reply")
    if not isinstance(reply, dict):
        return None
    status = str(reply.get("status", "")).upper()
    if status not in {"FAILED", "FAIL", "ERROR"}:
        return None
    result: dict[str, Any] = {
        "query_id": query_id,
        "poll_attempts": poll_attempts,
        "error": "XQL query failed",
        "xsiam_status": status,
    }
    detail = reply.get("error_message", reply.get("error"))
    if detail is not None:
        encoded = json.dumps(detail, sort_keys=True, default=str, separators=(",", ":")).encode()
        result["error_reference_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def _query_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    limit = min(max(get_config().xql_max_concurrent_queries, 1), 4)
    key = (id(loop), limit)
    semaphore = _semaphores.get(key)
    if semaphore is None:
        semaphore = asyncio.Semaphore(limit)
        _semaphores[key] = semaphore
    return semaphore


def _monotonic() -> float:
    return time.monotonic()
