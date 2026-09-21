"""Question-shaped investigation helpers.

Each tool answers one plain question with two or three plain arguments, so an orchestrating
agent never has to choose a dataset or field name. Dataset selection comes from the authored
catalogue, restricted by dataset policy; field names are verified against the live schema;
every query is compiled by the typed XQL compiler and recorded in ``provenance``.
"""

import logging
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from pydantic import Field

from usecase.base_module import BaseModule
from usecase.dataset_catalogue import CatalogueError, ResolvedDataset
from usecase.dataset_query import DatasetQueryPlan, QueryFilter, QueryMetric, QuerySort
from usecase.entity_resolution import EntityTerm, Resolution, parse_entity, resolve
from usecase.helper_runtime import (
    DEFAULT_WINDOW_HOURS,
    HelperRun,
    discovered_field_names,
    run_plan,
    select_datasets,
    verified_roles,
    window_timeframe,
)
from usecase.identity import resolve_mcp_context
from usecase.log_policy import DatasetAuthorizationError

logger = logging.getLogger(__name__)

MAX_TRAFFIC_DATASETS = 2
MAX_FLOW_GROUPS = 15
MAX_SAMPLE_ROWS = 10
MAX_BLOCKED_GROUPS = 10
ALLOW_ACTIONS = ("allow", "alert", "accept", "permit", "pass", "continue")

EntityKindArg = Literal["host", "ip", "user"]
WindowHours = Annotated[
    int,
    Field(description="How far back to look, in hours. Default 24. Capped by the server's maximum timeframe.", ge=1, le=2160),
]


def _error(message: str, run: HelperRun | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {"success": False, "error": message}
    if run is not None:
        response["provenance"] = run.provenance()
    return response


async def resolve_entity(
    ctx: Context,
    value: Annotated[str, Field(description="One host name, user name, or IP address.", max_length=253)],
    entity_type: Annotated[
        EntityKindArg | None,
        Field(description="Set when the value is ambiguous, for example a bare name that is a user rather than a host."),
    ] = None,
    window_hours: WindowHours = DEFAULT_WINDOW_HOURS,
) -> dict[str, Any]:
    """Find the host names, IP addresses, and users linked to one host, user, or IP address."""
    run = None
    try:
        run = HelperRun(ctx, resolve_mcp_context(ctx))
        entity = parse_entity(value, entity_type)
        resolution = await resolve(run, entity, window_hours)
        response = {"success": True, **resolution.to_dict(), "provenance": run.provenance()}
        if not resolution.links:
            response["guidance"] = (
                "No allowed identity source knows this value. It may be unmanaged, outside the time window, "
                "or spelled differently. Do not guess an IP address; ask the user for one if they need network logs."
            )
        elif response["match_quality"] == "partial":
            response["guidance"] = "Only partial matches were found. Confirm the intended match with the user before relying on it."
        return response
    except (ValueError, DatasetAuthorizationError) as e:
        return _error(str(e), run)
    except CatalogueError:
        return _error("Dataset catalogue is misconfigured; contact the gateway operator.", run)
    except Exception as e:
        logger.exception("resolve_entity failed: %s", type(e).__name__)
        return _error(f"Entity resolution failed: {type(e).__name__}", run)


class _Endpoint:
    """One side of a traffic question after resolution: IP addresses, a user term, or nothing."""

    def __init__(self, label: str):
        self.label = label
        self.entity: EntityTerm | None = None
        self.resolution: Resolution | None = None
        self.ips: list[str] = []
        self.user_term: str | None = None

    @property
    def given(self) -> bool:
        return self.entity is not None

    @property
    def usable(self) -> bool:
        return bool(self.ips or self.user_term)

    def describe(self) -> dict[str, Any] | None:
        if self.entity is None:
            return None
        detail: dict[str, Any] = {"input": self.entity.value, "kind": self.entity.kind, "ip_addresses": self.ips}
        if self.user_term:
            detail["matched_as_user"] = self.user_term
        if self.resolution is not None:
            detail["resolution"] = self.resolution.to_dict()
        return detail


async def _endpoint(run: HelperRun, label: str, value: str | None, window_hours: int) -> _Endpoint:
    endpoint = _Endpoint(label)
    if value is None or not value.strip():
        return endpoint
    endpoint.entity = parse_entity(value)
    if endpoint.entity.kind == "ip":
        endpoint.ips = [endpoint.entity.term]
    elif endpoint.entity.kind == "user":
        endpoint.user_term = endpoint.entity.term
    else:
        endpoint.resolution = await resolve(run, endpoint.entity, window_hours)
        endpoint.ips = endpoint.resolution.ip_addresses()[:5]
    return endpoint


def _side_filters(endpoint: _Endpoint, roles: dict[str, list[str]], side: str) -> list[QueryFilter] | None:
    """Filters for one side of the flow, or None when this dataset cannot express that side."""
    if not endpoint.given:
        return []
    if endpoint.ips:
        return [QueryFilter(field=roles[f"{side}_ip"][0], operator="in", value=endpoint.ips)]
    user_fields = roles.get(f"{side}_user")
    if endpoint.user_term and user_fields:
        return [QueryFilter(field=user_fields[0], operator="contains", value=endpoint.user_term)]
    return None


def _flow_filters(
    source: _Endpoint, destination: _Endpoint, dest_port: int | None, roles: dict[str, list[str]]
) -> list[QueryFilter] | None:
    source_filters = _side_filters(source, roles, "source")
    dest_filters = _side_filters(destination, roles, "dest")
    if source_filters is None or dest_filters is None:
        return None
    filters = [*source_filters, *dest_filters]
    if dest_port is not None and roles.get("dest_port"):
        filters.append(QueryFilter(field=roles["dest_port"][0], operator="eq", value=int(dest_port)))
    return filters


def _metrics(roles: dict[str, list[str]]) -> list[QueryMetric]:
    metrics = [QueryMetric(function="count", alias="sessions")]
    if roles.get("bytes"):
        metrics.append(QueryMetric(function="sum", alias="bytes", field=roles["bytes"][0]))
    return metrics


async def _traffic_datasets(run: HelperRun, dataset: str | None) -> list[ResolvedDataset]:
    selected = await select_datasets(
        run,
        domains=("network_traffic",),
        required_roles=("source_ip", "dest_ip", "action"),
        explicit=dataset,
    )
    return selected[:MAX_TRAFFIC_DATASETS]


def _is_blocking(action: Any) -> bool:
    return isinstance(action, str) and action.lower() not in ALLOW_ACTIONS


def _verdict(by_action: list[dict[str, Any]]) -> str:
    allowed = sum(row.get("sessions", 0) or 0 for row in by_action if not _is_blocking(row.get("action")))
    blocked = sum(row.get("sessions", 0) or 0 for row in by_action if _is_blocking(row.get("action")))
    if allowed == 0 and blocked == 0:
        return "no_traffic_seen"
    if blocked == 0:
        return "all_allowed"
    if allowed == 0:
        return "all_blocked"
    return "some_blocked"


async def _answer_traffic(
    ctx: Context,
    source: str | None,
    destination: str | None,
    dest_port: int | None,
    window_hours: int,
    dataset: str | None,
    *,
    blocked_detail: bool,
    include_samples: bool,
) -> dict[str, Any]:
    run = None
    try:
        run = HelperRun(ctx, resolve_mcp_context(ctx))
        src = await _endpoint(run, "source", source, window_hours)
        dst = await _endpoint(run, "destination", destination, window_hours)
        if not src.given and not dst.given:
            return _error("Give a source, a destination, or both.", run)

        timeframe = window_timeframe(window_hours)
        response: dict[str, Any] = {
            "success": True,
            "answered": False,
            "source": src.describe(),
            "destination": dst.describe(),
            "dest_port": dest_port,
            "window_hours": timeframe.relative_ms // 3_600_000,
            "datasets": [],
        }
        unresolved = [side.label for side in (src, dst) if side.given and not side.usable]
        if unresolved:
            response["guidance"] = (
                f"Could not resolve the {' and '.join(unresolved)} to an IP address. Firewall logs are keyed by IP "
                "address; ask the user for the address rather than guessing one."
            )
            response["provenance"] = run.provenance()
            return response

        candidates = await _traffic_datasets(run, dataset)
        if not candidates:
            response["guidance"] = "No allowed network traffic dataset is catalogued with source, destination, and action fields."
            response["provenance"] = run.provenance()
            return response

        for resolved in candidates:
            roles = await verified_roles(run, resolved)
            if not all(roles.get(role) for role in ("source_ip", "dest_ip", "action")):
                continue
            filters = _flow_filters(src, dst, dest_port, roles)
            if filters is None:
                continue
            action_field = roles["action"][0]
            by_action = await run_plan(
                run,
                DatasetQueryPlan(
                    dataset=resolved.dataset_name,
                    mode="aggregate",
                    filters=filters,
                    metrics=_metrics(roles),
                    group_by=[action_field],
                    order_by=[QuerySort(field="sessions", direction="desc")],
                    timeframe=timeframe,
                    limit=MAX_FLOW_GROUPS,
                ),
                "sessions_by_action",
            )
            by_action = [{"action": row.get(action_field), **{k: v for k, v in row.items() if k != action_field}} for row in by_action]
            section: dict[str, Any] = {
                "dataset": resolved.dataset_name,
                "verdict": _verdict(by_action),
                "total_sessions": sum(row.get("sessions", 0) or 0 for row in by_action),
                "by_action": by_action,
            }

            detail_fields = [
                roles[role][0]
                for role in (("action", "rule", "source_ip") if blocked_detail else ("action", "rule", "app", "dest_port"))
                if roles.get(role)
            ]
            detail_filters = list(filters)
            if blocked_detail:
                detail_filters.append(QueryFilter(field=action_field, operator="not_in", value=list(ALLOW_ACTIONS)))
            has_detail = section["verdict"] in ("some_blocked", "all_blocked") if blocked_detail else bool(section["total_sessions"])
            if has_detail and len(detail_fields) > 1:
                section["top_blocked" if blocked_detail else "top_flows"] = await run_plan(
                    run,
                    DatasetQueryPlan(
                        dataset=resolved.dataset_name,
                        mode="aggregate",
                        filters=detail_filters,
                        metrics=_metrics(roles),
                        group_by=detail_fields,
                        order_by=[QuerySort(field="sessions", direction="desc")],
                        timeframe=timeframe,
                        limit=MAX_BLOCKED_GROUPS if blocked_detail else MAX_FLOW_GROUPS,
                    ),
                    "blocked_by_rule_and_source" if blocked_detail else "top_flows",
                )

            if include_samples and section["total_sessions"]:
                discovered = await discovered_field_names(run, resolved.dataset_name)
                time_field = resolved.entry.time_field
                sample_fields = [
                    roles[role][0]
                    for role in ("source_ip", "source_port", "dest_ip", "dest_port", "app", "action", "rule")
                    if roles.get(role)
                ]
                if time_field in discovered:
                    section["samples"] = await run_plan(
                        run,
                        DatasetQueryPlan(
                            dataset=resolved.dataset_name,
                            mode="rows",
                            fields=[time_field, *sample_fields],
                            filters=filters,
                            order_by=[QuerySort(field=time_field, direction="desc")],
                            timeframe=timeframe,
                            limit=MAX_SAMPLE_ROWS,
                        ),
                        "recent_samples",
                    )
            response["datasets"].append(section)

        response["answered"] = bool(response["datasets"])
        if not response["answered"]:
            response["guidance"] = "No allowed traffic dataset has the verified fields needed for this question."
        response["allow_actions"] = list(ALLOW_ACTIONS)
        response["provenance"] = run.provenance()
        return response
    except (ValueError, DatasetAuthorizationError) as e:
        return _error(str(e), run)
    except CatalogueError:
        return _error("Dataset catalogue is misconfigured; contact the gateway operator.", run)
    except Exception as e:
        logger.exception("firewall helper failed: %s", type(e).__name__)
        return _error(f"Firewall query failed: {type(e).__name__}", run)


_SOURCE = Annotated[
    str | None,
    Field(description="Where the traffic comes from: an IP address, host name, or user name.", max_length=253),
]
_DESTINATION = Annotated[
    str | None,
    Field(description="Where the traffic goes: an IP address, host name, or user name.", max_length=253),
]
_PORT = Annotated[int | None, Field(description="Optional destination port.", ge=0, le=65535)]
_DATASET = Annotated[
    str | None,
    Field(description="Optional explicit traffic dataset. Leave empty to let the catalogue choose.", max_length=255),
]


async def firewall_traffic(
    ctx: Context,
    source: _SOURCE = None,
    destination: _DESTINATION = None,
    dest_port: _PORT = None,
    window_hours: WindowHours = DEFAULT_WINDOW_HOURS,
    dataset: _DATASET = None,
    include_samples: Annotated[bool, Field(description="Also return up to 10 of the most recent sessions.")] = False,
) -> dict[str, Any]:
    """Summarize firewall traffic between a source and a destination: sessions by action, top rules, apps, and ports."""
    return await _answer_traffic(
        ctx, source, destination, dest_port, window_hours, dataset, blocked_detail=False, include_samples=include_samples
    )


async def firewall_verdict(
    ctx: Context,
    destination: _DESTINATION = None,
    source: _SOURCE = None,
    dest_port: _PORT = None,
    window_hours: WindowHours = DEFAULT_WINDOW_HOURS,
    dataset: _DATASET = None,
) -> dict[str, Any]:
    """Say whether the firewall is blocking traffic to a destination, and which rules and sources are involved."""
    return await _answer_traffic(
        ctx, source, destination, dest_port, window_hours, dataset, blocked_detail=True, include_samples=False
    )


class InvestigationModule(BaseModule):
    """Entity resolution and firewall question helpers."""

    def register_tools(self):
        self._add_tool(resolve_entity)
        self._add_tool(firewall_traffic)
        self._add_tool(firewall_verdict)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
