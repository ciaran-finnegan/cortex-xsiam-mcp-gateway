import mcp.types
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

from usecase.engagement import (
    ENGAGEMENT_NUDGE,
    ENGAGEMENT_TOOL_NAMES,
    UNSET_MODE,
    current_scope,
)


class EngagementGuidanceMiddleware(Middleware):
    """Append a one-line nudge to every tool result while no engagement is set.

    The nudge is a separate text block, so existing payloads and output schemas are untouched.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mcp.types.CallToolRequestParams],
        call_next: CallNext[mcp.types.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        result = await call_next(context=context)
        scope = current_scope()
        if scope is None or scope.mode != UNSET_MODE or context.message.name in ENGAGEMENT_TOOL_NAMES:
            return result
        return ToolResult(
            content=[*result.content, mcp.types.TextContent(type="text", text=ENGAGEMENT_NUDGE)],
            structured_content=result.structured_content,
            meta=result.meta,
            is_error=result.is_error,
        )
