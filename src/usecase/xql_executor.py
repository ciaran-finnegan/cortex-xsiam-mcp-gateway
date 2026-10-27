import asyncio
import hashlib
import json
import re
import time
from typing import Any

from config.config import get_config
from usecase.fetcher import get_fetcher
from usecase.xql_builder import MAX_XQL_RESULT_LIMIT

FAILURE_STATUSES = {"FAILED", "FAIL", "ERROR"}
MAX_XSIAM_ERROR_CHARS = 300
XSIAM_CANCEL_NOTE = (
    "The XSIAM public XQL API has no cancel endpoint, so the query may keep running in XSIAM "
    "and consume quota until it finishes."
)
# Keys a tool may copy from an executor failure into its own error response.
# None of them carry rows or raw upstream text.
FAILURE_DETAIL_KEYS = (
    "error_code",
    "xsiam_status",
    "xsiam_error",
    "error_reference_sha256",
    "timeout_seconds",
    "xsiam_query_submitted",
    "xsiam_cancelled",
    "xsiam_cancel_note",
)

_ERROR_DETAIL_KEYS = ("error_message", "error", "err_msg", "message")
_QUOTED_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`[^`]*`')
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(
    r"(?<![\w:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
    r"|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?"
    r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}))(?![\w:])",
    re.IGNORECASE,
)
_UUID_RE = re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.IGNORECASE)
_LONG_TOKEN_RE = re.compile(r"\b(?:[0-9a-f]{16,}|\d{5,})\b", re.IGNORECASE)
_IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_semaphores: dict[tuple[int, int], asyncio.Semaphore] = {}


async def run_xql_query(
    ctx,
    query: str,
    result_limit: int,
    *,
    timeframe: dict[str, int] | None = None,
    poll_interval_seconds: float = 1,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("XQL query must be a non-empty string")
    if len(query) > get_config().xql_max_query_chars:
        raise ValueError(f"XQL query exceeds the configured {get_config().xql_max_query_chars}-character limit")
    safe_limit = min(max(int(result_limit), 1), MAX_XQL_RESULT_LIMIT)
    limit_seconds = max(int(timeout_seconds), 1)
    progress: dict[str, Any] = {"submitted": False, "query_id": None, "poll_attempts": 0}
    # The wall-clock limit covers waiting for a concurrency slot and every
    # upstream request, not only the polling loop, so no call outlives it.
    wall_clock = asyncio.timeout(limit_seconds)
    try:
        async with wall_clock:
            return await _start_and_poll(
                ctx,
                query,
                safe_limit,
                timeframe=timeframe,
                poll_interval_seconds=poll_interval_seconds,
                limit_seconds=limit_seconds,
                progress=progress,
            )
    except TimeoutError:
        if not wall_clock.expired():
            raise
        return _timeout_response(progress, limit_seconds)


async def _start_and_poll(
    ctx,
    query: str,
    safe_limit: int,
    *,
    timeframe: dict[str, int] | None,
    poll_interval_seconds: float,
    limit_seconds: int,
    progress: dict[str, Any],
) -> dict[str, Any]:
    async with _query_semaphore():
        fetcher = await get_fetcher(ctx)
        request_data: dict[str, Any] = {"query": query}
        if timeframe is not None:
            request_data["timeframe"] = timeframe

        progress["submitted"] = True
        start_response = await fetcher.send_request(
            "/xql/start_xql_query/",
            data={"request_data": request_data},
        )
        query_id = _extract_query_id(start_response)
        progress["query_id"] = query_id
        start_failure = _failure_response(start_response, query=query, query_id=query_id, poll_attempts=0)
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
        deadline = _monotonic() + limit_seconds
        attempts = 0
        while _monotonic() < deadline:
            await asyncio.sleep(max(float(poll_interval_seconds), 0))
            attempts += 1
            progress["poll_attempts"] = attempts
            result_response = await fetcher.send_request("/xql/get_query_results/", data=result_payload)
            reply = result_response.get("reply")
            if isinstance(reply, dict):
                status = str(reply.get("status", "")).upper()
                if status in {"PENDING", "RUNNING"}:
                    continue
                if status in FAILURE_STATUSES:
                    failure = _failure_response(
                        result_response,
                        query=query,
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

        return _timeout_response(progress, limit_seconds)


def failure_details(response_data: dict[str, Any]) -> dict[str, Any]:
    """Return the row-free failure fields a tool may relay from an executor response."""
    return {key: response_data[key] for key in FAILURE_DETAIL_KEYS if key in response_data}


def sanitize_xsiam_error(detail: Any, query: str | None = None) -> str | None:
    """Reduce an XSIAM failure message to text that cannot echo literals or log values.

    Quoted tokens survive only when they are identifiers that appear outside
    string literals in the submitted query (dataset, field, function names);
    every other quoted literal, URL, email or IP address, UUID, and long number
    or hex token is replaced with a placeholder.
    """
    text = _error_text(detail)
    if not text:
        return None
    identifiers = _query_identifiers(query)
    text = _QUOTED_LITERAL_RE.sub(lambda match: _redact_quoted(match.group(0), identifiers), text)
    text = _URL_RE.sub("<url>", text)
    text = _EMAIL_RE.sub("<email>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = _IPV6_RE.sub("<ip>", text)
    text = _UUID_RE.sub("<value>", text)
    text = _LONG_TOKEN_RE.sub("<value>", text)
    text = " ".join(_CONTROL_CHARS_RE.sub(" ", text).split())
    if len(text) > MAX_XSIAM_ERROR_CHARS:
        text = text[:MAX_XSIAM_ERROR_CHARS] + "...<truncated>"
    return text or None


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
    query: str,
    query_id: str | None,
    poll_attempts: int,
) -> dict[str, Any] | None:
    reply = response_data.get("reply")
    if not isinstance(reply, dict):
        return None
    status = str(reply.get("status", "")).upper()
    if status not in FAILURE_STATUSES:
        return None
    result: dict[str, Any] = {
        "query_id": query_id,
        "poll_attempts": poll_attempts,
        "error": "XQL query failed",
        "error_code": "xql_failed",
        "xsiam_status": status,
    }
    detail = _error_detail(reply)
    if detail is not None:
        encoded = json.dumps(detail, sort_keys=True, default=str, separators=(",", ":")).encode()
        result["error_reference_sha256"] = hashlib.sha256(encoded).hexdigest()
        message = sanitize_xsiam_error(detail, query)
        if message:
            result["xsiam_error"] = message
    return result


def _timeout_response(progress: dict[str, Any], limit_seconds: int) -> dict[str, Any]:
    return {
        "query_id": progress["query_id"],
        "poll_attempts": progress["poll_attempts"],
        "error": f"XQL query timed out after {limit_seconds} seconds (server-side limit)",
        "error_code": "query_timeout",
        "timeout_seconds": limit_seconds,
        "xsiam_query_submitted": progress["submitted"],
        "xsiam_cancelled": False,
        "xsiam_cancel_note": XSIAM_CANCEL_NOTE,
    }


def _error_detail(reply: dict[str, Any]) -> Any:
    for key in _ERROR_DETAIL_KEYS:
        if reply.get(key) is not None:
            return reply[key]
    return None


def _error_text(detail: Any) -> str | None:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        for key in _ERROR_DETAIL_KEYS:
            if isinstance(detail.get(key), str):
                return detail[key]
    return None


def _query_identifiers(query: str | None) -> frozenset[str]:
    if not query:
        return frozenset()
    return frozenset(_IDENTIFIER_TOKEN_RE.findall(_QUOTED_LITERAL_RE.sub(" ", query)))


def _redact_quoted(token: str, identifiers: frozenset[str]) -> str:
    if token[1:-1] in identifiers:
        return token
    return f"{token[0]}<redacted>{token[-1]}"


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
