"""threat_intel_lookup: "what do we know about this indicator?"

Analysts answer this by hand-writing a three-way join across the Cortex threat intelligence
datasets. The helper walks the same graph with sequential typed queries instead, so no raw
XQL or join is involved: the indicator and its associations, the malware families it is
associated with, and the threat actors related to those families.

Threat intelligence is third-party text. Only short identifying fields are returned, never
free-text descriptions, and everything is labelled untrusted.
"""

import logging
import re
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

from usecase.base_module import BaseModule
from usecase.dataset_query import DatasetQueryPlan, QueryFilter
from usecase.helper_runtime import HelperRun, discovered_field_names, run_plan
from usecase.identity import resolve_mcp_context
from usecase.log_policy import DatasetAuthorizationError, authorize_dataset

logger = logging.getLogger(__name__)

INDICATORS = "threat_intel_indicators"
RELATIONSHIPS = "threat_intel_relationships"
MALWARE = "threat_intel_malware"
THREAT_ACTORS = "threat_intel_threat_actors"

MAX_INDICATOR_CHARS = 512
MAX_INDICATOR_ROWS = 5
MAX_RELATIONSHIPS = 50
MAX_RELATED = 10
MAX_NAME_CHARS = 120

_INDICATOR_RE = re.compile(r"^[\w.\-:/@%?=&+~#\[\]]+\Z")
_INDICATOR_FIELDS = ("id", "value", "type", "verdict", "verdict_categories", "first_seen", "last_seen", "expiration_status", "tags", "associations")
_MALWARE_FIELDS = ("id", "name", "aliases", "type", "mitre_id", "last_seen")
_ACTOR_FIELDS = ("id", "name", "aliases", "type", "origin", "motivation", "last_seen")


def parse_indicator(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Indicator must be text")
    cleaned = value.strip()
    if len(cleaned) < 3 or len(cleaned) > MAX_INDICATOR_CHARS:
        raise ValueError(f"Indicator must be between 3 and {MAX_INDICATOR_CHARS} characters")
    if not _INDICATOR_RE.fullmatch(cleaned):
        raise ValueError("Indicator contains unsupported characters; give one IP address, domain, URL, hash, or email address")
    return cleaned


async def _rows(run: HelperRun, dataset: str, wanted: tuple[str, ...], filters: list[QueryFilter], logic: str, limit: int, purpose: str):
    """Typed row query over the wanted fields that the dataset actually has. Empty when none exist."""
    observed = await discovered_field_names(run, dataset)
    fields = [name for name in wanted if name in observed]
    if not fields or any(item.field not in observed for item in filters):
        return []
    return await run_plan(
        run,
        DatasetQueryPlan(dataset=dataset, mode="rows", fields=fields, filters=filters, filter_logic=logic, limit=limit),
        purpose,
    )


def _allowed(run: HelperRun, dataset: str) -> bool:
    return authorize_dataset(run.principal, dataset).allowed


async def threat_intel_lookup(
    ctx: Context,
    indicator: Annotated[
        str, Field(description="One IP address, domain, URL, file hash, or email address.", max_length=MAX_INDICATOR_CHARS)
    ],
    include_related: Annotated[
        bool, Field(description="Also return the malware families and threat actors related to the indicator.")
    ] = True,
) -> dict[str, Any]:
    """Look up one indicator in Cortex threat intelligence: verdict, type, and related malware and threat actors."""
    run = None
    try:
        run = HelperRun(ctx, resolve_mcp_context(ctx))
        value = parse_indicator(indicator)
        if not _allowed(run, INDICATORS):
            return {"success": False, "error": f"Principal {run.principal.principal_id} is not allowed to query dataset {INDICATORS}"}

        matches = await _rows(
            run, INDICATORS, _INDICATOR_FIELDS, [QueryFilter(field="value", operator="eq", value=value)], "and", MAX_INDICATOR_ROWS, "indicator_lookup"
        )
        response: dict[str, Any] = {
            "success": True,
            "indicator": value,
            "known": bool(matches),
            "indicators": matches,
            "related_malware": [],
            "related_threat_actors": [],
        }
        if not matches:
            response["guidance"] = (
                "This indicator is not in the threat intelligence dataset. That is not evidence it is benign; "
                "say it is unknown to threat intelligence."
            )

        # Indicators carry their related objects in an associations list of {id, type, value}.
        associated: dict[str, list[str]] = {"malware": [], "threat-actor": []}
        for row in matches:
            summary = []
            for item in row.pop("associations", None) or []:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    continue
                prefix = item["id"].split("--", 1)[0]
                if prefix in associated and item["id"] not in associated[prefix]:
                    associated[prefix].append(item["id"])
                if len(summary) < MAX_RELATED:
                    summary.append({"type": str(item.get("type", prefix))[:40], "name": str(item.get("value", ""))[:MAX_NAME_CHARS]})
            row["associations"] = summary

        if include_related and any(associated.values()):
            malware_ids = associated["malware"][:MAX_RELATIONSHIPS]
            actor_ids = list(associated["threat-actor"])
            if malware_ids and _allowed(run, RELATIONSHIPS):
                # Malware families link to the actors that use them through the relationships dataset.
                # Ask for actor links only, in each direction, so other link types cannot fill the cap.
                relationship_count = 0
                for mine, other in (("source_ref", "target_ref"), ("target_ref", "source_ref")):
                    links = await _rows(
                        run,
                        RELATIONSHIPS,
                        ("source_ref", "target_ref", "relationship_type"),
                        [
                            QueryFilter(field=mine, operator="in", value=malware_ids),
                            QueryFilter(field=other, operator="contains", value="threat-actor--"),
                        ],
                        "and",
                        MAX_RELATIONSHIPS,
                        "malware_actor_links",
                    )
                    relationship_count += len(links)
                    for row in links:
                        ref = row.get(other)
                        if isinstance(ref, str) and ref.startswith("threat-actor--") and ref not in actor_ids:
                            actor_ids.append(ref)
                response["actor_link_count"] = relationship_count
            lookups = (
                ("related_malware", MALWARE, _MALWARE_FIELDS, malware_ids),
                ("related_threat_actors", THREAT_ACTORS, _ACTOR_FIELDS, actor_ids[:MAX_RELATIONSHIPS]),
            )
            for key, dataset, fields, ids in lookups:
                if ids and _allowed(run, dataset):
                    response[key] = await _rows(
                        run, dataset, fields, [QueryFilter(field="id", operator="in", value=ids)], "and", MAX_RELATED, key
                    )

        response["provenance"] = run.provenance()
        return response
    except (ValueError, DatasetAuthorizationError) as e:
        return {"success": False, "error": str(e), **({"provenance": run.provenance()} if run else {})}
    except Exception as e:
        logger.exception("threat_intel_lookup failed: %s", type(e).__name__)
        return {"success": False, "error": f"Threat intelligence lookup failed: {type(e).__name__}"}


class ThreatIntelModule(BaseModule):
    """Indicator lookup across the Cortex threat intelligence datasets."""

    def register_tools(self):
        self._add_tool(threat_intel_lookup)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
