"""Shared runtime for question-shaped helper tools.

Helpers choose datasets and fields on the caller's behalf, so every query they issue goes
through the same gates as ``query_dataset``: dataset policy, the typed XQL compiler, the
concurrency-limited executor, and output budgets. ``HelperRun`` records each dataset and
query hash so the audit event shows what a helper actually touched.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from fastmcp import Context

from config.config import get_config
from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from entities.MCPContext import MCPContext
from usecase.dataset_catalogue import (
    DatasetCatalogue,
    ResolvedDataset,
    get_catalogue,
    verified_fields,
)
from usecase.dataset_query import (
    DatasetQueryPlan,
    QueryTimeframe,
    build_dataset_xql,
    query_hash,
)
from usecase.fetcher import get_fetcher
from usecase.log_policy import (
    ALL_DATASETS,
    authorize_dataset,
    ensure_dataset_authorized,
)
from usecase.xql_builder import SAFE_IDENTIFIER_RE
from usecase.xql_discovery import (
    build_field_discovery_xql,
    extract_xql_rows,
    parse_dataset_reply,
)
from usecase.xql_executor import run_xql_query
from usecase.xql_results import bound_result_rows

logger = logging.getLogger(__name__)

PAPI_ERRORS = (
    PAPIConnectionError,
    PAPIAuthenticationError,
    PAPIServerError,
    PAPIClientRequestError,
    PAPIResponseError,
    PAPIClientError,
)

HOUR_MS = 3_600_000
DEFAULT_WINDOW_HOURS = 24
FIELD_CACHE_TTL_SECONDS = 3600
FIELD_CACHE_MAX_ENTRIES = 256
FIELD_DISCOVERY_SAMPLE = 5
MAX_HELPER_QUERIES = 20

_field_cache: dict[str, tuple[float, frozenset[str]]] = {}


def reset_field_cache() -> None:
    _field_cache.clear()


@dataclass
class HelperRun:
    """Per-invocation state: the principal, a query budget, and provenance for audit."""

    ctx: Context
    principal: MCPContext
    queries: list[dict[str, Any]] = field(default_factory=list)

    def provenance(self) -> dict[str, Any]:
        return {"queries": list(self.queries), "content_trust": "untrusted_data"}

    def _spend(self) -> None:
        if len(self.queries) >= MAX_HELPER_QUERIES:
            raise ValueError(f"Helper query budget of {MAX_HELPER_QUERIES} exceeded; narrow the request")


def window_timeframe(window_hours: int) -> QueryTimeframe:
    """Clamp a caller window to at least one hour and at most the configured maximum timeframe."""
    max_ms = get_config().dataset_query_max_timeframe_ms
    requested = max(int(window_hours), 1) * HOUR_MS
    return QueryTimeframe(relative_ms=min(requested, max_ms) if max_ms > 0 else requested)


async def allowed_dataset_names(ctx: Context, principal: MCPContext) -> tuple[list[str], str, str | None]:
    """Return dataset names the principal may query, the source used, and an optional warning.

    Dataset policy is applied here, before any catalogue lookup, so catalogue text is never
    returned for, and helpers never select, a dataset the principal cannot query.
    """
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("/xql/get_datasets", data={"request_data": {}})
        names = [record["dataset_name"] for record in parse_dataset_reply(response_data)]
        source, warning = "xsiam_api", None
    except (*PAPI_ERRORS, ValueError) as e:
        logger.warning("Could not list XSIAM datasets; using policy names: %s", type(e).__name__)
        decision = authorize_dataset(principal, ALL_DATASETS)
        names = [name for name in decision.allowed_datasets if name != ALL_DATASETS]
        source = "dataset_policy_fallback"
        warning = "XSIAM dataset listing is unavailable; results are limited to dataset names written in policy."
    allowed = [
        name
        for name in names
        if isinstance(name, str) and SAFE_IDENTIFIER_RE.fullmatch(name) and authorize_dataset(principal, name).allowed
    ]
    return allowed, source, warning


async def select_datasets(
    run: HelperRun,
    *,
    domains: tuple[str, ...] = (),
    required_roles: tuple[str, ...] = (),
    identity_sources_only: bool = False,
    explicit: str | None = None,
    catalogue: DatasetCatalogue | None = None,
) -> list[ResolvedDataset]:
    """Pick catalogued, policy-allowed datasets for a helper, catalogue records first by name."""
    active = catalogue or get_catalogue()
    if explicit:
        ensure_dataset_authorized(run.principal, explicit)
        names = [explicit]
    else:
        names, _source, _warning = await allowed_dataset_names(run.ctx, run.principal)
    selected = []
    for name in sorted(names):
        resolved = active.resolve(name)
        entry = resolved.entry
        if not explicit and domains and entry.domain not in domains:
            continue
        if identity_sources_only and not entry.identity_source:
            continue
        if any(role not in entry.fields for role in required_roles):
            continue
        selected.append(resolved)
    return selected


async def discovered_field_names(run: HelperRun, dataset: str) -> frozenset[str]:
    """Return observed field names for an allowed dataset, cached briefly. Values are never kept."""
    ensure_dataset_authorized(run.principal, dataset)
    cached = _field_cache.get(dataset)
    now = time.monotonic()
    if cached and now - cached[0] < FIELD_CACHE_TTL_SECONDS:
        return cached[1]

    run._spend()
    xql = build_field_discovery_xql(dataset, FIELD_DISCOVERY_SAMPLE)
    response = await run_xql_query(
        run.ctx, xql, FIELD_DISCOVERY_SAMPLE, timeframe=window_timeframe(24 * 7).to_api()
    )
    run.queries.append(
        {"dataset": dataset, "purpose": "field_discovery", "query_sha256": query_hash(xql), "query_id": response.get("query_id")}
    )
    if response.get("error"):
        return frozenset()
    names = frozenset(name for row in extract_xql_rows(response) for name in row)
    if names:
        if len(_field_cache) >= FIELD_CACHE_MAX_ENTRIES:
            _field_cache.pop(next(iter(_field_cache)))
        _field_cache[dataset] = (now, names)
    return names


async def verified_roles(run: HelperRun, resolved: ResolvedDataset) -> dict[str, list[str]]:
    """Catalogue candidate fields that actually exist in the dataset, by role."""
    return verified_fields(resolved, await discovered_field_names(run, resolved.dataset_name))


def _output_fields(plan: DatasetQueryPlan) -> tuple[str, ...]:
    if plan.mode == "rows":
        return tuple(plan.fields)
    names = [*plan.group_by, *(metric.alias for metric in plan.metrics)]
    if plan.time_bucket and plan.time_bucket.field not in names:
        names.insert(0, plan.time_bucket.field)
    return tuple(names)


async def run_plan(run: HelperRun, plan: DatasetQueryPlan, purpose: str) -> list[dict[str, Any]]:
    """Execute one typed plan under policy and output budgets. Returns bounded rows; errors return []."""
    ensure_dataset_authorized(run.principal, plan.dataset)
    run._spend()
    compiled = build_dataset_xql(plan)
    response = await run_xql_query(
        run.ctx,
        compiled.xql,
        compiled.result_limit,
        timeframe=plan.timeframe.to_api() if plan.timeframe else None,
    )
    record = {
        "dataset": plan.dataset,
        "purpose": purpose,
        "query_sha256": query_hash(compiled.xql),
        "query_id": response.get("query_id"),
    }
    if response.get("error"):
        record["error"] = True
        run.queries.append(record)
        return []
    rows, _budget = bound_result_rows(
        extract_xql_rows(response)[: compiled.page_limit],
        hidden_fields=compiled.hidden_fields,
        allowed_fields=_output_fields(plan),
    )
    record["returned"] = len(rows)
    run.queries.append(record)
    return rows
