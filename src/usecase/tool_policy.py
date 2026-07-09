import json
from dataclasses import dataclass

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.log_policy import ToolAuthorizationError

ALL_TOOLS = "*"


@dataclass(frozen=True)
class ToolPolicyDecision:
    allowed: bool
    principal_id: str
    tool_name: str
    matched_group: str | None = None
    allowed_tools: tuple[str, ...] = ()
    reason: str = ""


def get_tool_policy() -> dict[str, tuple[str, ...]]:
    raw_policy = get_config().tool_access_policy
    try:
        parsed = json.loads(raw_policy or "{}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid TOOL_ACCESS_POLICY JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError("TOOL_ACCESS_POLICY must be a JSON object mapping groups to tools")

    policy: dict[str, tuple[str, ...]] = {}
    for group, tools in parsed.items():
        if isinstance(tools, str):
            tool_values = (tools,)
        elif isinstance(tools, list) and all(isinstance(tool, str) for tool in tools):
            tool_values = tuple(tools)
        else:
            raise ValueError(f"Tool policy for group {group} must be a string or list of strings")
        policy[str(group)] = tuple(tool.strip() for tool in tool_values if tool.strip())

    return policy


def authorize_tool(context: MCPContext, tool_name: str) -> ToolPolicyDecision:
    policy = get_tool_policy()

    for group in context.groups:
        allowed_tools = policy.get(group)
        if not allowed_tools:
            continue
        if ALL_TOOLS in allowed_tools or tool_name in allowed_tools:
            return ToolPolicyDecision(
                allowed=True,
                principal_id=context.principal_id,
                tool_name=tool_name,
                matched_group=group,
                allowed_tools=allowed_tools,
                reason="tool allowed by group policy",
            )

    allowed_for_groups = tuple(sorted({tool for group in context.groups for tool in policy.get(group, ())}))
    return ToolPolicyDecision(
        allowed=False,
        principal_id=context.principal_id,
        tool_name=tool_name,
        allowed_tools=allowed_for_groups,
        reason="tool is not allowed for principal groups",
    )


def ensure_tool_authorized(context: MCPContext, tool_name: str) -> ToolPolicyDecision:
    decision = authorize_tool(context, tool_name)
    if not decision.allowed:
        raise ToolAuthorizationError(
            f"Principal {decision.principal_id} is not allowed to invoke tool {tool_name}"
        )
    return decision
