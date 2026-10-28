import json
from typing import Any

import mcp.types
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.audit import create_tool_audit_event, emit_audit_event, now_monotonic
from usecase.cost_guard import COST_GUARD_RULES, CostGuardRefusal
from usecase.credential_broker import (
    clear_current_credential_selection,
    get_current_credential_selection,
    reset_current_credential_selection,
)
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
        selection_token = clear_current_credential_selection()

        try:
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
                selection = get_current_credential_selection()
                await emit_audit_event(
                    create_tool_audit_event(
                        tool_name=tool_name,
                        phase="end",
                        outcome=_infer_exception_outcome(e),
                        principal=principal,
                        arguments=arguments,
                        duration_ms=(now_monotonic() - started) * 1000,
                        error=e,
                        credential_summary=_credential_summary(selection),
                    )
                )
                raise

            selection = get_current_credential_selection()
            await emit_audit_event(
                create_tool_audit_event(
                    tool_name=tool_name,
                    phase="end",
                    outcome=_infer_outcome(result),
                    principal=principal,
                    arguments=arguments,
                    duration_ms=(now_monotonic() - started) * 1000,
                    result_summary=_summarize_tool_result(result, context.fastmcp_context),
                    credential_summary=_credential_summary(selection),
                )
            )
            return result
        finally:
            reset_current_credential_selection(selection_token)


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
        # A cost guard refusal keeps error "cost_guard" for clients and words the denial in message.
        error = f"{payload.get('error', '')} {payload.get('message', '')}".lower()
        if "not allowed" in error or "not authorized" in error or "privileged" in error:
            return "denied"
        return "error"
    return "success"


def _infer_exception_outcome(error: Exception) -> str:
    if isinstance(error, (IdentityAuthenticationError, ToolAuthorizationError, CostGuardRefusal)):
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
        quota = _quota_summary(payload.get("quota"))
        if quota:
            summary["quota"] = quota
        if payload.get("error") == "cost_guard" and payload.get("rule") in COST_GUARD_RULES:
            summary["cost_guard_rule"] = payload["rule"]
    return summary


_QUOTA_NUMBER_FIELDS = ("estimate_units", "actual_units", "debited_units", "remaining_units", "session_spent_units")
_QUOTA_LABEL_FIELDS = {
    "estimate_class": {"light", "medium", "heavy", "extreme"},
    "actual_units_source": {"query_cost", "remaining_quota_delta", "cache"},
    "approval_method": {"elicitation", "approval_argument"},
}


def _quota_summary(quota: Any) -> dict[str, Any] | None:
    """Copy only numeric and allowlisted quota fields so tool output cannot inject audit content."""
    if not isinstance(quota, dict):
        return None
    summary: dict[str, Any] = {}
    for key in _QUOTA_NUMBER_FIELDS:
        value = quota.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            summary[key] = value
    for key, allowed in _QUOTA_LABEL_FIELDS.items():
        if quota.get(key) in allowed:
            summary[key] = quota[key]
    for key in ("cached", "approved"):
        if isinstance(quota.get(key), bool):
            summary[key] = quota[key]
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


def _credential_summary(selection) -> dict[str, Any] | None:
    if selection is None:
        return None
    return {
        "profile_name": selection.profile_name,
        "matched_group": selection.matched_group,
    }
