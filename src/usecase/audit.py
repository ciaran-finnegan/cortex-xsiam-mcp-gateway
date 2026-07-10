import hashlib
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from config.config import get_config
from entities.MCPContext import MCPContext

logger = logging.getLogger("cortex_xsiam_mcp.audit")

SENSITIVE_ARGUMENT_MARKERS = ("api_key", "authorization", "bearer", "credential", "password", "secret", "token")


class AuditExportError(RuntimeError):
    """Raised when an audit event cannot be exported and fail-closed mode is enabled."""


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _contains_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_ARGUMENT_MARKERS)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("<redacted>" if _contains_sensitive_name(str(key)) else _redact_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def summarize_tool_arguments(tool_name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    config = get_config()
    arguments = arguments or {}
    summary: dict[str, Any] = {
        "argument_names": sorted(arguments.keys()),
        "argument_hash": stable_hash(_redact_value(arguments)),
    }

    if "dataset" in arguments:
        summary["dataset"] = arguments.get("dataset")
    if "limit" in arguments:
        summary["limit"] = arguments.get("limit")
    if "dry_run" in arguments:
        summary["dry_run"] = arguments.get("dry_run")
    if "timeframe" in arguments:
        summary["timeframe_provided"] = arguments.get("timeframe") is not None
    if "tenants" in arguments and isinstance(arguments.get("tenants"), list):
        summary["tenant_count"] = len(arguments["tenants"])
    if "filters" in arguments and isinstance(arguments.get("filters"), list):
        summary["filter_count"] = len(arguments["filters"])
        summary["filter_fields"] = sorted(
            {
                str(filter_item.get("field"))
                for filter_item in arguments["filters"]
                if isinstance(filter_item, dict) and filter_item.get("field")
            }
        )

    value = arguments.get("query")
    if isinstance(value, str) and value:
        summary["query_sha256"] = _hash_text(value)
        summary["query_length"] = len(value)
        if config.audit_log_include_query_text:
            summary["query"] = value

    if tool_name == "execute_xql_query" and "query" not in arguments:
        summary["raw_xql_requested"] = True

    return summary


def create_tool_audit_event(
    *,
    tool_name: str,
    phase: str,
    outcome: str,
    principal: MCPContext,
    arguments: dict[str, Any] | None = None,
    duration_ms: float | None = None,
    error: Exception | str | None = None,
    result_summary: dict[str, Any] | None = None,
    credential_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = get_config()
    credential_id = principal.auth_headers.get("X-XDR-AUTH-ID", "")
    event: dict[str, Any] = {
        "schema_version": "1.0",
        "event_type": "cortex_xsiam_mcp.tool_invocation",
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "cortex-xsiam-mcp-gateway",
        "phase": phase,
        "outcome": outcome,
        "tool": tool_name,
        "transport": config.mcp_transport,
        "principal": {
            "id": principal.principal_id,
            "groups": list(principal.groups),
        },
        "request": summarize_tool_arguments(tool_name, arguments),
    }
    if credential_summary:
        event["xsiam"] = credential_summary
    elif credential_id:
        event["xsiam"] = {"api_key_id_sha256": _hash_text(str(credential_id))}
    if duration_ms is not None:
        event["duration_ms"] = round(duration_ms, 3)
    if error is not None:
        event["error"] = _summarize_error(error)
    if result_summary:
        event["result"] = result_summary
    return event


def _summarize_error(error: Exception | str) -> dict[str, Any]:
    error_type = type(error).__name__ if isinstance(error, Exception) else "Error"
    message = str(error)
    return {
        "type": error_type,
        "message_sha256": _hash_text(message),
        "message_length": len(message),
    }


async def emit_audit_event(event: dict[str, Any]) -> None:
    config = get_config()
    if not config.audit_log_enabled:
        return

    payload = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
    logger.info(payload)

    if not config.audit_log_xsiam_http_collector_enabled:
        return

    try:
        await _send_to_xsiam_http_collector(payload)
    except Exception as e:
        logger.exception("Failed to export audit event to Cortex XSIAM HTTP Collector: %s", e)
        if config.audit_log_fail_closed:
            raise AuditExportError("Audit export failed and AUDIT_LOG_FAIL_CLOSED is enabled") from e


async def _send_to_xsiam_http_collector(payload: str) -> None:
    config = get_config()
    if not config.audit_log_xsiam_http_collector_url:
        raise AuditExportError("AUDIT_LOG_XSIAM_HTTP_COLLECTOR_URL is required when XSIAM audit export is enabled")
    if not config.audit_log_xsiam_http_collector_api_key:
        raise AuditExportError("AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY is required when XSIAM audit export is enabled")

    headers = {
        "Authorization": config.audit_log_xsiam_http_collector_api_key,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=config.audit_log_xsiam_http_collector_timeout_seconds) as client:
        response = await client.post(config.audit_log_xsiam_http_collector_url, content=f"{payload}\n", headers=headers)
        response.raise_for_status()


def now_monotonic() -> float:
    return time.monotonic()
