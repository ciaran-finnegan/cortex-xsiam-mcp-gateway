import mcp.types
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

from service.cortex_mcp.audit_middleware import _extract_json_payload, _infer_outcome
from usecase.learning_observers import begin_tool_call, end_tool_call


class LearningMiddleware(Middleware):
    """Track each authorized tool call for tier-1 learning: helper usage, step timings, and the replay cache.

    Runs inside the policy middleware, so denied calls are never observed. Observation
    never changes a result and never raises into the call.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mcp.types.CallToolRequestParams],
        call_next: CallNext[mcp.types.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        token = begin_tool_call(context.message.name, context.fastmcp_context)
        arguments = context.message.arguments or {}
        try:
            result = await call_next(context=context)
        except Exception:
            await end_tool_call(token, outcome="error", payload=None, arguments=arguments)
            raise
        await end_tool_call(
            token,
            outcome=_infer_outcome(result),
            payload=_extract_json_payload(result),
            arguments=arguments,
        )
        return result
