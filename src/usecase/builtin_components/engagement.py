import logging
from typing import Annotated, Any, Literal

import mcp.types
from fastmcp import Context, FastMCP
from pydantic import Field

from usecase import engagement as engagement_state
from usecase.base_module import BaseModule
from usecase.dataset_query import QueryTimeframe
from usecase.engagement import (
    EngagementError,
    EngagementStoreError,
    build_engagement,
    get_mode_policy,
)
from usecase.identity import resolve_mcp_context

logger = logging.getLogger(__name__)

ModeName = Literal["incident_response", "threat_hunt", "operations", "unset"]


async def set_engagement(
    ctx: Context,
    mode: Annotated[
        ModeName,
        Field(description="incident_response, threat_hunt, operations, or unset. Modes only narrow what your groups grant."),
    ],
    case_id: Annotated[
        str | None,
        Field(description="Case or ticket identifier. With a case store configured, an existing case's scope is restored for omitted fields."),
    ] = None,
    iocs: Annotated[
        list[str] | None,
        Field(description="Indicator IPs, CIDRs, hostnames or domains, and MD5/SHA1/SHA256 file hashes."),
    ] = None,
    internal: Annotated[
        list[str] | None,
        Field(description="Internal address ranges or domains as IPs, CIDRs, or hostnames."),
    ] = None,
    front_ends: Annotated[
        list[str] | None,
        Field(description="Internet-facing front ends (load balancers, gateways) as IPs, CIDRs, or hostnames."),
    ] = None,
    servers: Annotated[
        list[str] | None,
        Field(description="Servers in scope as IPs, CIDRs, or hostnames."),
    ] = None,
    window: Annotated[
        QueryTimeframe | None,
        Field(description="Engagement time window. Relative windows are frozen to absolute epoch milliseconds when set."),
    ] = None,
    notes: Annotated[
        str | None,
        Field(description="Short free-text notes, at most 2000 characters. Stored and returned as untrusted data."),
    ] = None,
) -> dict[str, Any]:
    """Set the engagement mode and scope for this session. Call this first.

    Scope is stored server-side so later queries can reuse it instead of re-sending
    indicator lists. Changing the mode or case invalidates existing continuation cursors.
    """
    principal = resolve_mcp_context(ctx)
    try:
        engagement, omitted = build_engagement(
            mode=mode,
            case_id=case_id,
            iocs=iocs,
            internal=internal,
            front_ends=front_ends,
            servers=servers,
            window=window,
            notes=notes,
        )
        result = await engagement_state.set_session_engagement(ctx, principal, engagement, omitted)
    except (EngagementError, EngagementStoreError, ValueError) as e:
        return {"success": False, "error": str(e)}

    await _notify_tool_list_changed(ctx)
    current = result["engagement"]
    policy = get_mode_policy(current.mode)
    return {
        "success": True,
        "engagement": _engagement_view(current),
        "previous_mode": result["previous_mode"],
        "resumed_from_case": result["resumed_from_case"],
        "case_store": result["case_store"],
        "mode_policy": policy.model_dump(mode="json"),
        "next_step": "Call get_dataset_query_guidance for the workflow of this mode, then re-list tools.",
    }


async def get_engagement(ctx: Context) -> dict[str, Any]:
    """Return the current engagement scope, the mode's policy defaults, and this session's recorded XQL spend."""
    principal = resolve_mcp_context(ctx)
    try:
        current = await engagement_state.load_engagement(ctx, principal)
        spend = await engagement_state.get_session_spend(ctx, principal)
        policy = get_mode_policy(current.mode)
        store = engagement_state.get_engagement_store()
    except (EngagementError, EngagementStoreError, ValueError) as e:
        return {"success": False, "error": str(e)}
    return {
        "success": True,
        "engagement": _engagement_view(current),
        "mode_policy": policy.model_dump(mode="json"),
        "session_spend": {
            **spend,
            "budget_units": policy.session_budget_units,
            "budget_remaining_units": round(max(policy.session_budget_units - spend["units"], 0.0), 6),
        },
        "case_store": "enabled" if store is not None else "disabled",
    }


async def record_fact(
    ctx: Context,
    key: Annotated[
        str,
        Field(description="Lowercase fact key such as initial_access.vector or c2.ip."),
    ],
    value: Annotated[
        str | int | float | bool,
        Field(description="Fact value, at most 1024 characters. Stored and returned as untrusted data."),
    ],
    evidence_query_id: Annotated[
        str,
        Field(description="query_id of a query this engagement ran that supports the fact."),
    ],
    confidence: Annotated[
        Literal["low", "medium", "high"],
        Field(description="How well the evidence supports the fact."),
    ],
) -> dict[str, Any]:
    """Record a finding for the current engagement, tied to the query that proves it."""
    principal = resolve_mcp_context(ctx)
    try:
        fact = await engagement_state.record_fact(
            ctx,
            principal,
            key=key,
            value=value,
            evidence_query_id=evidence_query_id,
            confidence=confidence,
        )
    except (EngagementError, EngagementStoreError, ValueError) as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "fact": fact}


async def get_engagement_log(
    ctx: Context,
    case_id: Annotated[
        str | None,
        Field(description="Case to read. Omit for this session's log. Only your own cases are readable."),
    ] = None,
) -> dict[str, Any]:
    """Return recorded facts and executed queries (dataset, window, rows, units, duration) for a case or this session."""
    principal = resolve_mcp_context(ctx)
    try:
        log = await engagement_state.get_engagement_log(ctx, principal, case_id)
    except (EngagementError, EngagementStoreError, ValueError) as e:
        return {"success": False, "error": str(e)}
    return {"success": True, **log}


def _engagement_view(current) -> dict[str, Any]:
    view = current.model_dump(mode="json")
    view["notes_trust"] = "untrusted_data"
    return view


async def _notify_tool_list_changed(ctx: Context) -> None:
    # The mode can hide tools, so prompt clients to re-list. Best effort only.
    try:
        await ctx.send_notification(mcp.types.ToolListChangedNotification())
    except Exception as e:
        logger.debug("Could not send tools/list_changed: %s", type(e).__name__)


class EngagementModule(BaseModule):
    """Session engagement mode, investigation scope, findings, and query telemetry."""

    def register_tools(self):
        self._add_tool(set_engagement)
        self._add_tool(get_engagement)
        self._add_tool(record_fact)
        self._add_tool(get_engagement_log)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
