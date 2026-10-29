import logging
from collections.abc import Sequence
from dataclasses import replace

import mcp.types
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import Tool, ToolResult

from usecase.engagement import load_engagement
from usecase.identity import resolve_mcp_context
from usecase.tool_policy import authorize_tool, ensure_tool_authorized

logger = logging.getLogger(__name__)


class ToolPolicyMiddleware(Middleware):
    """Enforce configured tool-level policy before every MCP tool invocation."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mcp.types.CallToolRequestParams],
        call_next: CallNext[mcp.types.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        principal = resolve_mcp_context(context.fastmcp_context)
        ensure_tool_authorized(principal, context.message.name)
        return await call_next(context=context)

    async def on_list_tools(
        self,
        context: MiddlewareContext[mcp.types.ListToolsRequest],
        call_next: CallNext[mcp.types.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        """Advertise only tools the caller could invoke in the current engagement mode."""
        tools = await call_next(context)
        try:
            principal = resolve_mcp_context(context.fastmcp_context)
            engagement = await load_engagement(context.fastmcp_context, principal)
            principal = replace(principal, mode=engagement.mode, case_id=engagement.case_id)
            return [tool for tool in tools if authorize_tool(principal, tool.name).allowed]
        except Exception as e:
            # Fail closed: an unverified identity or invalid policy advertises nothing.
            logger.info("Tool listing withheld: %s", type(e).__name__)
            return []
