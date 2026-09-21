"""dataset_health: "is this data arriving, and what does a record look like?"

People validating a new data source tend to answer that by dumping the dataset with no
filter and a huge limit. This helper answers it with three bounded queries per dataset: an
arrival trend, an observed field list, and a handful of recent records.
"""

import asyncio
import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

from usecase.base_module import BaseModule
from usecase.dataset_catalogue import (
    MAX_TOPIC_CHARS,
    CatalogueError,
    ResolvedDataset,
    get_catalogue,
    search_catalogue,
)
from usecase.dataset_query import (
    DatasetQueryPlan,
    QueryMetric,
    QuerySort,
    QueryTimeBucket,
    query_hash,
)
from usecase.helper_runtime import (
    DEFAULT_WINDOW_HOURS,
    HelperRun,
    allowed_dataset_names,
    run_plan,
    window_timeframe,
)
from usecase.identity import resolve_mcp_context
from usecase.log_policy import DatasetAuthorizationError, ensure_dataset_authorized
from usecase.xql_builder import _validate_identifier
from usecase.xql_discovery import (
    build_field_discovery_xql,
    extract_xql_rows,
    infer_field_catalog,
)
from usecase.xql_executor import run_xql_query

logger = logging.getLogger(__name__)

MAX_HEALTH_DATASETS = 3
MAX_HEALTH_FIELDS = 60
MAX_TREND_BUCKETS = 48
SCHEMA_SAMPLE_ROWS = 25
SAMPLE_ROWS = 3
SAMPLE_FIELDS = 8
STALE_LOOKBACK_HOURS = 24 * 7
_PREFERRED_SAMPLE_ROLES = ("host", "user", "source_ip", "dest_ip", "operation", "action", "event_type", "name", "severity", "resource_name")


def _bucket(window_hours: int) -> QueryTimeBucket:
    if window_hours <= MAX_TREND_BUCKETS:
        return QueryTimeBucket(field="_time", size=1, unit="h")
    return QueryTimeBucket(field="_time", size=1, unit="d")


async def _observed_fields(run: HelperRun, dataset: str) -> list[dict[str, Any]]:
    """Observed field names and types from a small sample. Values are discarded."""
    ensure_dataset_authorized(run.principal, dataset)
    run._spend()
    xql = build_field_discovery_xql(dataset, SCHEMA_SAMPLE_ROWS)
    response = await run_xql_query(run.ctx, xql, SCHEMA_SAMPLE_ROWS, timeframe=window_timeframe(STALE_LOOKBACK_HOURS).to_api())
    record = {"dataset": dataset, "purpose": "field_discovery", "query_sha256": query_hash(xql), "query_id": response.get("query_id")}
    if response.get("error"):
        record["error"] = True
        run.queries.append(record)
        return []
    run.queries.append(record)
    return infer_field_catalog(extract_xql_rows(response))


def _sample_fields(resolved: ResolvedDataset, fields: list[dict[str, Any]], time_field: str) -> list[str]:
    observed = [item["name"] for item in fields]
    chosen = [time_field]
    for role in _PREFERRED_SAMPLE_ROLES:
        for name in resolved.entry.fields.get(role, [])[:1]:
            if name in observed and name not in chosen:
                chosen.append(name)
    for name in observed:
        if len(chosen) >= SAMPLE_FIELDS:
            break
        if not name.startswith("_") and name not in chosen:
            chosen.append(name)
    return chosen[:SAMPLE_FIELDS]


async def _check_dataset(run: HelperRun, resolved: ResolvedDataset, window_hours: int, include_samples: bool) -> dict[str, Any]:
    dataset = resolved.dataset_name
    fields = await _observed_fields(run, dataset)
    names = {item["name"] for item in fields}
    time_field = resolved.entry.time_field if resolved.entry.time_field in names else ("_time" if "_time" in names else None)
    report: dict[str, Any] = {
        "dataset": dataset,
        "domain": resolved.entry.domain,
        "description": resolved.entry.description,
        "catalogue_source": resolved.source,
        "fields_observed": len(fields),
        "fields": [{"name": item["name"], "type": item["type"]} for item in fields[:MAX_HEALTH_FIELDS]],
        "fields_truncated": len(fields) > MAX_HEALTH_FIELDS,
    }
    if not fields:
        report.update({"status": "no_data", "events": 0, "detail": f"No records in the last {STALE_LOOKBACK_HOURS // 24} days."})
        return report
    if time_field is None:
        report.update({"status": "unknown", "detail": "Records exist but no timestamp field was observed, so arrival cannot be measured."})
        return report

    bucket = _bucket(window_hours)
    bucket = QueryTimeBucket(field=time_field, size=bucket.size, unit=bucket.unit)
    trend = await run_plan(
        run,
        DatasetQueryPlan(
            dataset=dataset,
            mode="aggregate",
            metrics=[QueryMetric(function="count", alias="events")],
            time_bucket=bucket,
            order_by=[QuerySort(field=time_field, direction="asc")],
            timeframe=window_timeframe(window_hours),
            limit=MAX_TREND_BUCKETS,
        ),
        "arrival_trend",
    )
    events = sum(row.get("events", 0) or 0 for row in trend)
    report["events"] = events
    report["trend_bucket"] = f"{bucket.size}{bucket.unit}"
    report["trend"] = [{"bucket_start": row.get(time_field), "events": row.get("events")} for row in trend]
    if events:
        report["status"] = "receiving"
        report["last_bucket_start"] = trend[-1].get(time_field)
    else:
        report["status"] = "stale"
        report["detail"] = f"No records in the last {window_hours} hours, but records exist within {STALE_LOOKBACK_HOURS // 24} days."

    if include_samples:
        report["samples"] = await run_plan(
            run,
            DatasetQueryPlan(
                dataset=dataset,
                mode="rows",
                fields=_sample_fields(resolved, fields, time_field),
                order_by=[QuerySort(field=time_field, direction="desc")],
                timeframe=window_timeframe(window_hours if events else STALE_LOOKBACK_HOURS),
                limit=SAMPLE_ROWS,
            ),
            "recent_samples",
        )
    return report


async def dataset_health(
    ctx: Context,
    dataset: Annotated[
        str | None, Field(description="Exact dataset name to check. Give this or topic.", max_length=255)
    ] = None,
    topic: Annotated[
        str | None,
        Field(description="Plain words for the data source, for example 'okta sign-ins'. The best catalogue matches are checked.", max_length=MAX_TOPIC_CHARS),
    ] = None,
    window_hours: Annotated[
        int, Field(description="Arrival window in hours. Default 24. Capped by the server's maximum timeframe.", ge=1, le=2160)
    ] = DEFAULT_WINDOW_HOURS,
    include_samples: Annotated[bool, Field(description=f"Return {SAMPLE_ROWS} recent records with up to {SAMPLE_FIELDS} fields.")] = True,
) -> dict[str, Any]:
    """Check whether a dataset is receiving data, list its observed fields, and show a few recent records."""
    run = None
    try:
        run = HelperRun(ctx, resolve_mcp_context(ctx))
        catalogue = get_catalogue()
        if dataset:
            _validate_identifier(dataset, "dataset")
            ensure_dataset_authorized(run.principal, dataset)
            targets = [catalogue.resolve(dataset)]
        elif topic and topic.strip():
            names, _source, _warning = await allowed_dataset_names(ctx, run.principal)
            matches = search_catalogue(names, topic=topic, max_results=MAX_HEALTH_DATASETS, catalogue=catalogue)["datasets"]
            targets = [catalogue.resolve(item["dataset_name"]) for item in matches]
        else:
            return {"success": False, "error": "Give a dataset name or a topic."}

        timeframe = window_timeframe(window_hours)
        clamped_hours = timeframe.relative_ms // 3_600_000
        reports = await asyncio.gather(
            *(_check_dataset(run, target, clamped_hours, include_samples) for target in targets), return_exceptions=True
        )
        for report in reports:
            if isinstance(report, (DatasetAuthorizationError, ValueError)):
                raise report
            if isinstance(report, BaseException):
                logger.warning("dataset_health check failed: %s", type(report).__name__)
        response: dict[str, Any] = {
            "success": True,
            "window_hours": clamped_hours,
            "datasets": [report for report in reports if isinstance(report, dict)],
            "provenance": run.provenance(),
        }
        if not targets:
            response["guidance"] = "No allowed dataset matches that topic. Try find_datasets with different words."
        else:
            response["guidance"] = "This is a bounded health check. Use query_dataset with filters for anything more; do not dump the dataset."
        return response
    except (ValueError, DatasetAuthorizationError) as e:
        return {"success": False, "error": str(e), **({"provenance": run.provenance()} if run else {})}
    except CatalogueError:
        return {"success": False, "error": "Dataset catalogue is misconfigured; contact the gateway operator."}
    except Exception as e:
        logger.exception("dataset_health failed: %s", type(e).__name__)
        return {"success": False, "error": f"Dataset health check failed: {type(e).__name__}"}


class DatasetHealthModule(BaseModule):
    """Arrival, schema, and sample check for one data source."""

    def register_tools(self):
        self._add_tool(dataset_health)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
