import mcp.types
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

from usecase.identity import resolve_mcp_context
from usecase.tool_policy import ensure_tool_authorized


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
