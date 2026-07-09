import json
from typing import Any

import mcp.types
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.audit import create_tool_audit_event, emit_audit_event, now_monotonic
from usecase.identity import (
    IdentityAuthenticationError,
    default_mcp_context,
    resolve_mcp_context,
)
from usecase.log_policy import ToolAuthorizationError


class ToolAuditMiddleware(Middleware):
    """Emit structured audit events for every MCP tool invocation."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mcp.types.CallToolRequestParams],
        call_next: CallNext[mcp.types.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        config = get_config()
        principal = _get_principal(context)
        tool_name = context.message.name
        arguments = context.message.arguments or {}

        if config.audit_log_emit_start_events:
            await emit_audit_event(
                create_tool_audit_event(
                    tool_name=tool_name,
                    phase="start",
                    outcome="started",
                    principal=principal,
                    arguments=arguments,
                )
            )

        started = now_monotonic()
        try:
            result = await call_next(context=context)
        except Exception as e:
            await emit_audit_event(
                create_tool_audit_event(
                    tool_name=tool_name,
                    phase="end",
                    outcome=_infer_exception_outcome(e),
                    principal=principal,
                    arguments=arguments,
                    duration_ms=(now_monotonic() - started) * 1000,
                    error=e,
                )
            )
            raise

        await emit_audit_event(
            create_tool_audit_event(
                tool_name=tool_name,
                phase="end",
                outcome=_infer_outcome(result),
                principal=principal,
                arguments=arguments,
                duration_ms=(now_monotonic() - started) * 1000,
                result_summary=_summarize_tool_result(result, context.fastmcp_context),
            )
        )
        return result


def _get_principal(context: MiddlewareContext[Any]) -> MCPContext:
    try:
        return resolve_mcp_context(context.fastmcp_context)
    except IdentityAuthenticationError:
        return default_mcp_context()


def _infer_outcome(result: ToolResult) -> str:
    payload = _extract_json_payload(result)
    if not payload:
        return "success"

    if str(payload.get("success", "")).lower() == "false":
        error = str(payload.get("error", "")).lower()
        if "not allowed" in error or "not authorized" in error or "privileged" in error:
            return "denied"
        return "error"
    return "success"


def _infer_exception_outcome(error: Exception) -> str:
    if isinstance(error, (IdentityAuthenticationError, ToolAuthorizationError)):
        return "denied"
    return "error"


def _summarize_tool_result(result: ToolResult, fastmcp_context: Any | None = None) -> dict[str, Any]:
    payload = _extract_json_payload(result)
    summary: dict[str, Any] = {"content_blocks": len(result.content)}
    if fastmcp_context is not None:
        credential_profile = fastmcp_context.get_state("xsiam_credential_profile")
        if isinstance(credential_profile, dict):
            summary["xsiam_credential_profile"] = credential_profile
    if payload:
        summary["success"] = payload.get("success")
        if "query_id" in payload:
            summary["query_id"] = payload["query_id"]
        if "executed" in payload:
            summary["executed"] = payload["executed"]
    return summary


def _extract_json_payload(result: ToolResult) -> dict[str, Any] | None:
    if isinstance(result.structured_content, dict):
        return result.structured_content

    for content_block in result.content:
        text = getattr(content_block, "text", None)
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None
