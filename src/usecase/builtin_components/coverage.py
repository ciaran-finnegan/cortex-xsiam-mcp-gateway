"""coverage_gap: "which computers in inventory A are missing from inventory B?"

Typical uses: domain-joined computers with no endpoint agent, agents with no vulnerability
scan record, managed hosts that never appear in VPN sessions. The answer needs an anti-join,
which typed plans deliberately cannot express and which otherwise requires raw XQL privilege.

The helper generates that one query shape server-side. The caller supplies two dataset
names and nothing else. Every identifier in the generated XQL comes from the authored
catalogue and is verified against the live schema; the only literal is the catalogue's
authored host_filter value. Both datasets are policy checked before execution.
"""

import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

from usecase.base_module import BaseModule
from usecase.dataset_catalogue import CatalogueError, ResolvedDataset, get_catalogue
from usecase.helper_runtime import (
    HelperRun,
    discovered_field_names,
    run_generated_xql,
    verified_roles,
    window_timeframe,
)
from usecase.identity import resolve_mcp_context
from usecase.log_policy import DatasetAuthorizationError, ensure_dataset_authorized
from usecase.xql_builder import format_xql_value, validate_identifier

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_DAYS = 7
DEFAULT_MISSING = 25
MAX_MISSING = 100
REF_KEY = "cg_reference_host"
TGT_KEY = "cg_target_host"


def _normalized_key(field: str, alias: str) -> str:
    """Upper-case short host name, so FQDNs and bare names compare equal."""
    return f'alter {alias} = uppercase(arrayindex(split({field}, "."), 0))'


def _side(dataset: str, host_field: str, alias: str, host_filter: tuple[str, str] | None) -> str:
    dataset = validate_identifier(dataset, "dataset")
    host_field = validate_identifier(host_field, "host field")
    clauses = [f"{host_field} != null"]
    if host_filter:
        clauses.append(f"{validate_identifier(host_filter[0], 'host filter field')} = {format_xql_value(host_filter[1])}")
    return f"dataset = {dataset} | filter {' and '.join(clauses)} | {_normalized_key(host_field, alias)} | dedup {alias}"


def build_reference_total_xql(dataset: str, host_field: str, host_filter: tuple[str, str] | None) -> str:
    return f"{_side(dataset, host_field, REF_KEY, host_filter)} | comp count() as total | limit 1"


def build_anti_join_xql(
    reference: str,
    reference_field: str,
    reference_filter: tuple[str, str] | None,
    target: str,
    target_field: str,
    target_filter: tuple[str, str] | None,
    *,
    list_limit: int | None,
) -> str:
    """Hosts present in reference and absent from target. ``list_limit`` None returns only the count."""
    left = _side(reference, reference_field, REF_KEY, reference_filter)
    right = f"{_side(target, target_field, TGT_KEY, target_filter)} | fields {TGT_KEY}"
    joined = f"{left} | join type = left ({right}) as cg_target cg_target.{TGT_KEY} = {REF_KEY} | filter {TGT_KEY} = null"
    if list_limit is None:
        return f"{joined} | comp count() as missing | limit 1"
    safe_limit = min(max(int(list_limit), 1), MAX_MISSING)
    return f"{joined} | fields {REF_KEY} | sort asc {REF_KEY} | limit {safe_limit}"


async def _host_side(run: HelperRun, dataset: str, label: str) -> tuple[ResolvedDataset, str, tuple[str, str] | None]:
    validate_identifier(dataset, f"{label} dataset")
    ensure_dataset_authorized(run.principal, dataset)
    resolved = get_catalogue().resolve(dataset)
    roles = await verified_roles(run, resolved)
    if not roles.get("host"):
        raise ValueError(
            f"The {label} dataset has no verified host name field in the dataset catalogue. "
            "Choose a dataset found with find_datasets and entity_type host."
        )
    host_filter = resolved.entry.host_filter
    if host_filter is not None:
        if host_filter.field not in await discovered_field_names(run, dataset):
            raise ValueError(f"The {label} dataset's catalogue host filter names a field the dataset does not have")
    return resolved, roles["host"][0], ((host_filter.field, host_filter.value) if host_filter else None)


async def coverage_gap(
    ctx: Context,
    reference: Annotated[
        str, Field(description="Dataset that lists the hosts that should be covered, for example a directory or asset inventory.", max_length=255)
    ],
    target: Annotated[
        str, Field(description="Dataset that shows coverage, for example an endpoint agent or vulnerability scanner inventory.", max_length=255)
    ],
    window_days: Annotated[int, Field(description="How far back both datasets are read, in days. Default 7.", ge=1, le=90)] = DEFAULT_WINDOW_DAYS,
    max_missing: Annotated[int, Field(description=f"How many missing host names to list. Default {DEFAULT_MISSING}, capped at {MAX_MISSING}.")] = DEFAULT_MISSING,
) -> dict[str, Any]:
    """Count and list hosts that appear in a reference inventory but not in a target inventory."""
    run = None
    try:
        run = HelperRun(ctx, resolve_mcp_context(ctx))
        if reference == target:
            return {"success": False, "error": "Reference and target must be different datasets."}
        ref, ref_field, ref_filter = await _host_side(run, reference, "reference")
        tgt, tgt_field, tgt_filter = await _host_side(run, target, "target")
        timeframe = window_timeframe(int(window_days) * 24)
        datasets = (ref.dataset_name, tgt.dataset_name)

        total_rows = await run_generated_xql(
            run, build_reference_total_xql(ref.dataset_name, ref_field, ref_filter), (ref.dataset_name,), ("total",), 1, timeframe, "reference_total"
        )
        count_rows = await run_generated_xql(
            run,
            build_anti_join_xql(ref.dataset_name, ref_field, ref_filter, tgt.dataset_name, tgt_field, tgt_filter, list_limit=None),
            datasets,
            ("missing",),
            1,
            timeframe,
            "missing_count",
        )
        if not total_rows or not count_rows:
            return {"success": False, "error": "Coverage query failed.", "provenance": run.provenance()}
        total = int(total_rows[0].get("total") or 0)
        missing = int(count_rows[0].get("missing") or 0)

        listed: list[str] = []
        if missing:
            list_limit = min(max(int(max_missing), 1), MAX_MISSING)
            rows = await run_generated_xql(
                run,
                build_anti_join_xql(ref.dataset_name, ref_field, ref_filter, tgt.dataset_name, tgt_field, tgt_filter, list_limit=list_limit),
                datasets,
                (REF_KEY,),
                list_limit,
                timeframe,
                "missing_hosts",
            )
            listed = [row[REF_KEY] for row in rows if isinstance(row.get(REF_KEY), str)]

        response: dict[str, Any] = {
            "success": True,
            "reference": {"dataset": ref.dataset_name, "host_field": ref_field, "hosts": total},
            "target": {"dataset": tgt.dataset_name, "host_field": tgt_field},
            "window_days": timeframe.relative_ms // 86_400_000,
            "missing_from_target": missing,
            "covered": max(total - missing, 0),
            "coverage_percent": round(100 * (total - missing) / total, 1) if total else None,
            "missing_hosts": listed,
            "missing_hosts_truncated": missing > len(listed),
            "comparison": "Host names are compared as upper-case short names, so FQDNs and bare names match.",
            "provenance": run.provenance(),
        }
        if total == 0:
            response["guidance"] = "The reference dataset has no host records in this window, so coverage cannot be measured."
        return response
    except (ValueError, DatasetAuthorizationError) as e:
        return {"success": False, "error": str(e), **({"provenance": run.provenance()} if run else {})}
    except CatalogueError:
        return {"success": False, "error": "Dataset catalogue is misconfigured; contact the gateway operator."}
    except Exception as e:
        logger.exception("coverage_gap failed: %s", type(e).__name__)
        return {"success": False, "error": f"Coverage check failed: {type(e).__name__}"}


class CoverageModule(BaseModule):
    """Host coverage reconciliation between two inventories."""

    def register_tools(self):
        self._add_tool(coverage_gap)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
