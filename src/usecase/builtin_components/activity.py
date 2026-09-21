"""entity_activity: "show me logs for this user / computer / address / cloud resource today".

The helper fans out across catalogued datasets the principal may query, asks each one a
bounded aggregate question, and returns a per-dataset summary with a few recent samples from
the busiest datasets. It never returns unbounded rows.
"""

import asyncio
import logging
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from pydantic import Field

from usecase.base_module import BaseModule
from usecase.dataset_catalogue import (
    ENTITY_ROLES,
    CatalogueError,
    DatasetDomain,
    ResolvedDataset,
)
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

DEFAULT_ACTIVITY_DATASETS = 6
MAX_ACTIVITY_DATASETS = 8
MAX_BREAKDOWN_GROUPS = 5
MAX_SAMPLED_DATASETS = 2
MAX_SAMPLE_ROWS = 5
MAX_MATCH_VALUES = 5

ActivityEntityType = Literal["host", "ip", "user", "cloud_resource"]

# Where to look first for each kind of entity. Domains not listed are tried last.
_DOMAIN_PRIORITY: dict[str, tuple[str, ...]] = {
    "user": ("authentication_identity", "vpn_remote_access", "saas_audit", "cloud_audit", "endpoint_telemetry", "email", "alerts_incidents", "web_proxy", "network_traffic"),
    "host": ("endpoint_telemetry", "alerts_incidents", "network_traffic", "vpn_remote_access", "web_proxy", "network_threat", "vulnerability", "endpoint_inventory"),
    "ip": ("network_traffic", "network_threat", "cloud_network", "web_proxy", "authentication_identity", "vpn_remote_access", "cloud_audit", "endpoint_telemetry", "alerts_incidents"),
    "cloud_resource": ("cloud_audit", "cloud_network", "alerts_incidents", "endpoint_inventory"),
}
_BREAKDOWN_ROLES = ("operation", "action", "event_type", "name", "app", "log_type")
_SAMPLE_ROLES = ("operation", "action", "event_type", "name", "user", "source_user", "host", "source_ip", "dest_ip", "resource_name", "severity")


def _kind_fields(roles: dict[str, list[str]], kind: str) -> list[str]:
    names: list[str] = []
    for role in ENTITY_ROLES[kind]:
        for name in roles.get(role, []):
            if name not in names:
                names.append(name)
    return names


def build_activity_filters(
    entity: EntityTerm, roles: dict[str, list[str]], resolution: Resolution | None
) -> tuple[list[QueryFilter], list[str]]:
    """OR-joined filters that find the entity in one dataset, plus the fields they matched on."""
    filters: list[QueryFilter] = []
    matched: list[str] = []

    def add(fields: list[str], operator: str, value: Any) -> None:
        for name in fields:
            filters.append(QueryFilter(field=name, operator=operator, value=value))
            if name not in matched:
                matched.append(name)

    if entity.kind == "ip":
        add(_kind_fields(roles, "ip"), "eq", entity.term)
    elif entity.kind == "host":
        exact_hosts = resolution.values("host", exact_only=True)[:MAX_MATCH_VALUES] if resolution else []
        if exact_hosts:
            add(_kind_fields(roles, "host"), "in", exact_hosts)
        else:
            add(_kind_fields(roles, "host"), "contains", entity.term)
        addresses = resolution.ip_addresses()[:MAX_MATCH_VALUES] if resolution else []
        if addresses:
            add(_kind_fields(roles, "ip"), "in", addresses)
    else:
        add(_kind_fields(roles, entity.kind), "contains", entity.term)
    return filters, matched


def _rank(resolved: ResolvedDataset, kind: str) -> tuple[int, int, str]:
    priority = _DOMAIN_PRIORITY.get(kind, ())
    domain_rank = priority.index(resolved.entry.domain) if resolved.entry.domain in priority else len(priority)
    source_rank = 0 if resolved.source == "overlay" else 1
    return (domain_rank, source_rank, resolved.dataset_name)


async def _summarize_dataset(
    run: HelperRun, resolved: ResolvedDataset, entity: EntityTerm, resolution: Resolution | None, timeframe
) -> dict[str, Any] | None:
    roles = await verified_roles(run, resolved)
    filters, matched = build_activity_filters(entity, roles, resolution)
    if not filters:
        return None
    discovered = await discovered_field_names(run, resolved.dataset_name)
    time_field = resolved.entry.time_field if resolved.entry.time_field in discovered else None
    breakdown_field = next((roles[role][0] for role in _BREAKDOWN_ROLES if roles.get(role)), None)

    metrics = [QueryMetric(function="count", alias="events")]
    if time_field:
        metrics.append(QueryMetric(function="max", alias="last_seen", field=time_field))
    rows = await run_plan(
        run,
        DatasetQueryPlan(
            dataset=resolved.dataset_name,
            mode="aggregate",
            filters=filters,
            filter_logic="or",
            metrics=metrics,
            group_by=[breakdown_field] if breakdown_field else [],
            order_by=[QuerySort(field="events", direction="desc")],
            timeframe=timeframe,
            limit=MAX_BREAKDOWN_GROUPS,
        ),
        "activity_summary",
    )
    events = sum(row.get("events", 0) or 0 for row in rows)
    summary: dict[str, Any] = {
        "dataset": resolved.dataset_name,
        "domain": resolved.entry.domain,
        "description": resolved.entry.description,
        "matched_on": matched,
        "events": events,
        "last_seen": max((row.get("last_seen") or 0 for row in rows), default=0) or None,
    }
    if breakdown_field and events:
        summary["breakdown_by"] = breakdown_field
        summary["breakdown"] = [{"value": row.get(breakdown_field), "events": row.get("events")} for row in rows]
        if len(rows) == MAX_BREAKDOWN_GROUPS:
            summary["events_note"] = f"events counts the top {MAX_BREAKDOWN_GROUPS} {breakdown_field} values only"
    summary["_sample"] = {"filters": filters, "roles": roles, "time_field": time_field, "matched": matched}
    return summary


async def _add_samples(run: HelperRun, summary: dict[str, Any], timeframe) -> None:
    plan_parts = summary["_sample"]
    time_field = plan_parts["time_field"]
    if not time_field:
        return
    fields = [time_field, *plan_parts["matched"]]
    for role in _SAMPLE_ROLES:
        for name in plan_parts["roles"].get(role, [])[:1]:
            if name not in fields and len(fields) < 8:
                fields.append(name)
    summary["samples"] = await run_plan(
        run,
        DatasetQueryPlan(
            dataset=summary["dataset"],
            mode="rows",
            fields=fields,
            filters=plan_parts["filters"],
            filter_logic="or",
            order_by=[QuerySort(field=time_field, direction="desc")],
            timeframe=timeframe,
            limit=MAX_SAMPLE_ROWS,
        ),
        "recent_samples",
    )


async def entity_activity(
    ctx: Context,
    value: Annotated[
        str, Field(description="One host name, user name, IP address, or cloud resource identifier.", max_length=512)
    ],
    entity_type: Annotated[
        ActivityEntityType | None,
        Field(description="Required for a cloud resource. Otherwise set only when the value is ambiguous."),
    ] = None,
    window_hours: Annotated[
        int,
        Field(description="How far back to look, in hours. Default 24. Capped by the server's maximum timeframe.", ge=1, le=2160),
    ] = DEFAULT_WINDOW_HOURS,
    domains: Annotated[
        list[DatasetDomain] | None,
        Field(description="Optional catalogue domains to restrict the search to, for example ['authentication_identity'].", max_length=8),
    ] = None,
    max_datasets: Annotated[
        int, Field(description=f"How many datasets to check. Default {DEFAULT_ACTIVITY_DATASETS}, capped at {MAX_ACTIVITY_DATASETS}.")
    ] = DEFAULT_ACTIVITY_DATASETS,
    include_samples: Annotated[
        bool, Field(description=f"Return up to {MAX_SAMPLE_ROWS} recent records from the {MAX_SAMPLED_DATASETS} busiest datasets.")
    ] = True,
) -> dict[str, Any]:
    """Summarize recent activity for one user, computer, IP address, or cloud resource across allowed datasets."""
    run = None
    try:
        run = HelperRun(ctx, resolve_mcp_context(ctx))
        entity = parse_entity(value, entity_type)
        timeframe = window_timeframe(window_hours)
        resolution = await resolve(run, entity, window_hours) if entity.kind == "host" else None

        kinds = ("host", "ip") if entity.kind == "host" and resolution and resolution.ip_addresses() else (entity.kind,)
        candidates = [
            resolved
            for resolved in await select_datasets(run, domains=tuple(domains or ()))
            if resolved.source != "inferred" and any(resolved.fields_for_entity(kind) for kind in kinds)
        ]
        candidates.sort(key=lambda item: _rank(item, entity.kind))
        limit = min(max(int(max_datasets), 1), MAX_ACTIVITY_DATASETS)
        chosen = candidates[:limit]

        results = await asyncio.gather(
            *(_summarize_dataset(run, resolved, entity, resolution, timeframe) for resolved in chosen),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, (DatasetAuthorizationError, ValueError)):
                raise result
            if isinstance(result, BaseException):
                logger.warning("entity_activity dataset summary failed: %s", type(result).__name__)
        summaries = [item for item in results if isinstance(item, dict)]
        active = sorted((item for item in summaries if item["events"]), key=lambda item: -item["events"])
        quiet = [item["dataset"] for item in summaries if not item["events"]]

        if include_samples:
            await asyncio.gather(*(_add_samples(run, item, timeframe) for item in active[:MAX_SAMPLED_DATASETS]))
        for item in summaries:
            item.pop("_sample", None)

        response: dict[str, Any] = {
            "success": True,
            "entity": {"input": entity.value, "kind": entity.kind},
            "window_hours": timeframe.relative_ms // 3_600_000,
            "datasets_with_activity": active,
            "datasets_without_activity": quiet,
            "datasets_not_checked": max(len(candidates) - len(chosen), 0),
            "provenance": run.provenance(),
        }
        if resolution is not None:
            response["resolution"] = resolution.to_dict()
        if not candidates:
            response["guidance"] = "No allowed, catalogued dataset has a field for this kind of entity."
        elif not active:
            response["guidance"] = (
                "No activity was found in the datasets checked. The value may be spelled differently, inactive in "
                "this window, or recorded only in datasets that were not checked. Do not infer activity that was not returned."
            )
        elif response["datasets_not_checked"]:
            response["guidance"] = "More datasets could hold activity. Narrow with domains, or raise max_datasets, to check them."
        return response
    except (ValueError, DatasetAuthorizationError) as e:
        return {"success": False, "error": str(e), **({"provenance": run.provenance()} if run else {})}
    except CatalogueError:
        return {"success": False, "error": "Dataset catalogue is misconfigured; contact the gateway operator."}
    except Exception as e:
        logger.exception("entity_activity failed: %s", type(e).__name__)
        return {"success": False, "error": f"Activity lookup failed: {type(e).__name__}"}


class ActivityModule(BaseModule):
    """Cross-dataset activity summary for one entity."""

    def register_tools(self):
        self._add_tool(entity_activity)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
