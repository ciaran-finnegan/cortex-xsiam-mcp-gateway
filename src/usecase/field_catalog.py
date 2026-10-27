import difflib
import time
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from threading import Lock
from typing import Any

from usecase.dataset_query import DatasetQueryPlan
from usecase.xql_builder import DEFAULT_LOG_FIELDS
from usecase.xql_discovery import (
    DEFAULT_DISCOVERY_SAMPLE_SIZE,
    build_field_discovery_xql,
    extract_xql_rows,
)
from usecase.xql_executor import run_xql_query

FIELD_CATALOG_TTL_SECONDS = 3600
FIELD_CATALOG_MAX_DATASETS = 256
FIELD_CATALOG_MAX_FIELDS_PER_DATASET = 5000
# Matches discover_log_fields, which polls for at most 30 one-second attempts.
DISCOVERY_SAMPLE_TIMEOUT_SECONDS = 30
MAX_FIELD_SUGGESTIONS = 3
FIELD_SUGGESTION_CUTOFF = 0.6

_catalog: OrderedDict[str, "ObservedFields"] = OrderedDict()
_catalog_lock = Lock()


@dataclass(frozen=True)
class ObservedFields:
    names: frozenset[str]
    rows_observed: int
    observed_at: float


@dataclass(frozen=True)
class FieldValidation:
    """Outcome of checking query field names against discovered dataset fields.

    status is one of: verified, rejected, not_needed (no field references),
    not_checked (dry run without cached discovery), or unverified (the
    discovery sample failed or returned no rows, so the query runs unchecked).
    """

    status: str
    source: str | None = None
    reason: str | None = None
    unknown_fields: tuple[dict[str, Any], ...] = ()
    fields_observed: int = 0
    rows_observed: int = 0
    sample_query_id: str | None = None

    def summary(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"status": self.status}
        if self.source:
            summary["source"] = self.source
        if self.reason:
            summary["reason"] = self.reason
        if self.fields_observed:
            summary["fields_observed"] = self.fields_observed
            summary["rows_observed"] = self.rows_observed
        if self.sample_query_id:
            summary["sample_query_id"] = self.sample_query_id
        return summary


def remember_observed_fields(dataset: str, field_names: Iterable[str], rows_observed: int) -> ObservedFields | None:
    """Cache observed field names (never values) for one dataset, merging fresh entries."""
    names = frozenset(name for name in field_names if isinstance(name, str) and name)
    if rows_observed <= 0 or not names:
        return None
    now = _monotonic()
    with _catalog_lock:
        existing = _catalog.get(dataset)
        if existing is not None and now - existing.observed_at <= FIELD_CATALOG_TTL_SECONDS:
            names = names | existing.names
            rows_observed += existing.rows_observed
        if len(names) > FIELD_CATALOG_MAX_FIELDS_PER_DATASET:
            _catalog.pop(dataset, None)
            return None
        entry = ObservedFields(names=names, rows_observed=rows_observed, observed_at=now)
        _catalog[dataset] = entry
        _catalog.move_to_end(dataset)
        while len(_catalog) > FIELD_CATALOG_MAX_DATASETS:
            _catalog.popitem(last=False)
    return entry


def get_observed_fields(dataset: str) -> ObservedFields | None:
    with _catalog_lock:
        entry = _catalog.get(dataset)
        if entry is None:
            return None
        if _monotonic() - entry.observed_at > FIELD_CATALOG_TTL_SECONDS:
            del _catalog[dataset]
            return None
        _catalog.move_to_end(dataset)
        return entry


def clear_observed_fields() -> None:
    with _catalog_lock:
        _catalog.clear()


def plan_field_references(plan: DatasetQueryPlan) -> dict[str, list[str]]:
    """Return every dataset field a typed plan names, mapped to where it is used."""
    references: dict[str, list[str]] = {}
    for field in plan.fields:
        _add_reference(references, field, "fields")
    for query_filter in plan.filters:
        _add_reference(references, query_filter.field, "filters")
    for metric in plan.metrics:
        if metric.field:
            _add_reference(references, metric.field, "metrics")
    for field in plan.group_by:
        _add_reference(references, field, "group_by")
    if plan.time_bucket:
        _add_reference(references, plan.time_bucket.field, "time_bucket")
    metric_aliases = {metric.alias for metric in plan.metrics} if plan.mode == "aggregate" else set()
    for sort_item in plan.order_by:
        if sort_item.field not in metric_aliases:
            _add_reference(references, sort_item.field, "order_by")
    return references


def search_field_references(fields: list[str] | None, filters: list[dict] | None) -> dict[str, list[str]]:
    """Return the dataset fields a search_logs request names, mapped to where it is used."""
    references: dict[str, list[str]] = {}
    for field in fields or DEFAULT_LOG_FIELDS:
        _add_reference(references, field, "fields")
    for filter_item in filters or []:
        _add_reference(references, filter_item["field"], "filters")
    return references


def find_unknown_fields(references: dict[str, list[str]], known: frozenset[str]) -> list[dict[str, Any]]:
    by_lowercase: dict[str, list[str]] = {}
    for name in sorted(known):
        by_lowercase.setdefault(name.lower(), []).append(name)

    unknown = []
    for name, locations in references.items():
        if name in known:
            continue
        suggestions: list[str] = []
        for candidate in difflib.get_close_matches(
            name.lower(),
            list(by_lowercase),
            n=MAX_FIELD_SUGGESTIONS,
            cutoff=FIELD_SUGGESTION_CUTOFF,
        ):
            for original in by_lowercase[candidate]:
                if original not in suggestions:
                    suggestions.append(original)
        unknown.append(
            {
                "name": name,
                "used_in": locations,
                "suggestions": suggestions[:MAX_FIELD_SUGGESTIONS],
            }
        )
    return unknown


async def validate_field_references(
    ctx,
    dataset: str,
    references: dict[str, list[str]],
    *,
    timeframe: dict[str, int] | None = None,
    allow_sample: bool = True,
) -> FieldValidation:
    """Check field names against discovered fields, sampling the dataset once if nothing is cached.

    Callers must authorize the dataset first. Only field names are kept from the
    sample; row values are discarded.
    """
    if not references:
        return FieldValidation(status="not_needed")

    observed = get_observed_fields(dataset)
    source = "discovery_cache"
    sample_query_id = None
    if observed is None:
        if not allow_sample:
            return FieldValidation(status="not_checked", reason="no_cached_discovery")
        response = await run_xql_query(
            ctx,
            build_field_discovery_xql(dataset, DEFAULT_DISCOVERY_SAMPLE_SIZE),
            DEFAULT_DISCOVERY_SAMPLE_SIZE,
            timeframe=timeframe,
            timeout_seconds=DISCOVERY_SAMPLE_TIMEOUT_SECONDS,
        )
        source = "discovery_sample"
        sample_query_id = response.get("query_id")
        if response.get("error"):
            return FieldValidation(
                status="unverified",
                source=source,
                reason="discovery_sample_failed",
                sample_query_id=sample_query_id,
            )
        rows = extract_xql_rows(response)
        observed = remember_observed_fields(dataset, (name for row in rows for name in row), len(rows))
        if observed is None:
            return FieldValidation(
                status="unverified",
                source=source,
                reason="discovery_sample_empty",
                sample_query_id=sample_query_id,
            )

    unknown = find_unknown_fields(references, observed.names)
    return FieldValidation(
        status="rejected" if unknown else "verified",
        source=source,
        unknown_fields=tuple(unknown),
        fields_observed=len(observed.names),
        rows_observed=observed.rows_observed,
        sample_query_id=sample_query_id,
    )


def unknown_fields_error(dataset: str, validation: FieldValidation) -> dict[str, Any]:
    names = ", ".join(item["name"] for item in validation.unknown_fields)
    return {
        "executed": False,
        "dataset": dataset,
        "error_code": "unknown_fields",
        "error": (
            f"Field(s) not observed in dataset {dataset}: {names}. Use a suggested field, or rerun "
            "discover_log_fields with a wider timeframe if you expect the field to exist."
        ),
        "unknown_fields": list(validation.unknown_fields),
        "field_validation": validation.summary(),
    }


def _add_reference(references: dict[str, list[str]], name: str, location: str) -> None:
    locations = references.setdefault(name, [])
    if location not in locations:
        locations.append(location)


def _monotonic() -> float:
    return time.monotonic()
