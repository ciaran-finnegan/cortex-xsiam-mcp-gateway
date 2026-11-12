import json
from dataclasses import dataclass

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase.engagement import SCRIPT_RUN_TOOL_NAMES, hidden_tools_for_mode
from usecase.log_policy import ToolAuthorizationError

ALL_TOOLS = "*"
# Tools that also need membership of SCRIPT_RUN_GROUPS. A "*" grant is not enough for these.
SCRIPT_RUN_GRANT_TOOLS: tuple[str, ...] = ("run_endpoint_script", "get_endpoint_script_run")


@dataclass(frozen=True)
class ToolPolicyDecision:
    allowed: bool
    principal_id: str
    tool_name: str
    matched_group: str | None = None
    allowed_tools: tuple[str, ...] = ()
    reason: str = ""
    rule: str = ""


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
    """Allow a tool only when group policy grants it and the engagement mode does not hide it.

    The mode is applied strictly after the group decision, so it can remove a tool
    from what the groups grant but can never add one.
    """
    decision = _authorize_tool_by_groups(context, tool_name)
    if not decision.allowed:
        return decision
    # The feature gate comes before the mode, so a caller is never told to change mode for a
    # tool that is switched off or that its groups cannot run in any mode.
    refusal = script_run_refusal(context, tool_name)
    if refusal is not None:
        return ToolPolicyDecision(
            allowed=False,
            principal_id=context.principal_id,
            tool_name=tool_name,
            reason=refusal[1],
            rule=refusal[0],
        )
    if tool_name in hidden_tools_for_mode(context.mode):
        return ToolPolicyDecision(
            allowed=False,
            principal_id=context.principal_id,
            tool_name=tool_name,
            matched_group=decision.matched_group,
            reason=f"tool is hidden in engagement mode {context.mode}",
            rule="mode",
        )
    return decision


def get_script_run_groups() -> tuple[str, ...]:
    return tuple(group.strip() for group in get_config().script_run_groups.split(",") if group.strip())


def script_run_refusal(context: MCPContext, tool_name: str) -> tuple[str, str] | None:
    """Return (rule, reason) when the endpoint script feature gate refuses a tool, else None.

    The gate only narrows: it runs after group policy has allowed the tool. Run and result
    tools need an explicit SCRIPT_RUN_GROUPS membership as well as the tool policy grant.
    """
    if tool_name not in SCRIPT_RUN_TOOL_NAMES:
        return None
    if not get_config().script_run_enabled:
        return "disabled", "endpoint script execution is disabled (SCRIPT_RUN_ENABLED=false)"
    if tool_name in SCRIPT_RUN_GRANT_TOOLS:
        granted = get_script_run_groups()
        if not any(group in granted for group in context.groups):
            return "group_required", "principal is not in a group listed in SCRIPT_RUN_GROUPS"
    return None


def _authorize_tool_by_groups(context: MCPContext, tool_name: str) -> ToolPolicyDecision:
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
        if decision.matched_group is not None:
            raise ToolAuthorizationError(
                f"Tool {tool_name} is not allowed in engagement mode {context.mode}; "
                "call set_engagement with a mode whose policy exposes it"
            )
        if decision.rule in ("disabled", "group_required"):
            raise ToolAuthorizationError(
                f"Principal {decision.principal_id} is not allowed to invoke tool {tool_name}: {decision.reason}"
            )
        raise ToolAuthorizationError(
            f"Principal {decision.principal_id} is not allowed to invoke tool {tool_name}"
        )
    return decision
