"""Resolve a host name, user name, or IP address to the other identifiers it is known by.

Network and cloud logs are keyed by IP address, identity logs by user, endpoint logs by host
name. A person asking about "this computer" or "this user" has one of those, not all three.
Resolution reads catalogued *identity sources* (datasets whose rows link host, IP address,
and user) through the typed query compiler, under dataset policy.

Everything returned from a dataset is untrusted data. Values are only ever reused as typed
filter literals, and IP addresses are re-validated before reuse.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from usecase.dataset_catalogue import ENTITY_ROLES, ResolvedDataset
from usecase.dataset_query import DatasetQueryPlan, QueryFilter, QueryMetric, QuerySort
from usecase.helper_runtime import (
    HelperRun,
    discovered_field_names,
    run_plan,
    select_datasets,
    verified_roles,
    window_timeframe,
)

EntityKind = Literal["host", "ip", "user"]

MAX_ENTITY_CHARS = 253
MIN_PARTIAL_TERM_CHARS = 3
MAX_IDENTITY_SOURCES = 4
MAX_LINKS_PER_SOURCE = 10
MAX_VALUES_PER_KIND = 10

_ENTITY_VALUE_RE = re.compile(r"^[\w.\-@\\:$' ]+\Z")


@dataclass(frozen=True)
class EntityTerm:
    """A validated entity value plus the term used for case-insensitive matching."""

    kind: EntityKind
    value: str
    term: str
    exact_forms: tuple[str, ...]


@dataclass
class Resolution:
    entity: EntityTerm
    links: list[dict[str, Any]] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)

    def values(self, kind: str, *, exact_only: bool = False) -> list[str]:
        ordered: list[str] = []
        for wanted in ("exact", "partial"):
            if exact_only and wanted == "partial":
                break
            for link in self.links:
                if link["match"] != wanted:
                    continue
                raw = link.get(kind)
                for value in raw if isinstance(raw, list) else [raw]:
                    if isinstance(value, str) and value and value not in ordered:
                        ordered.append(value)
        return ordered[:MAX_VALUES_PER_KIND]

    def ip_addresses(self) -> list[str]:
        """Validated IP addresses, exact matches first, falling back to partial matches."""
        candidates = self.values("ip", exact_only=True) or self.values("ip")
        return [value for value in candidates if _is_ip(value)]

    def to_dict(self) -> dict[str, Any]:
        has_exact = any(link["match"] == "exact" for link in self.links)
        return {
            "input": self.entity.value,
            "kind": self.entity.kind,
            "resolved": bool(self.links),
            "match_quality": "exact" if has_exact else ("partial" if self.links else "none"),
            "hosts": self.values("host"),
            "ip_addresses": [value for value in self.values("ip") if _is_ip(value)],
            "users": self.values("user"),
            "links": self.links[: MAX_LINKS_PER_SOURCE * MAX_IDENTITY_SOURCES],
            "sources_used": self.sources_used,
        }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_entity(value: str, kind: str | None = None) -> EntityTerm:
    """Validate an entity value and work out whether it is a host, user, or IP address."""
    if not isinstance(value, str):
        raise ValueError("Entity value must be text")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > MAX_ENTITY_CHARS:
        raise ValueError(f"Entity value must be between 1 and {MAX_ENTITY_CHARS} characters")
    if "/" in cleaned:
        raise ValueError("CIDR ranges and paths are not supported; give one IP address, host name, or user name")
    if not _ENTITY_VALUE_RE.fullmatch(cleaned):
        raise ValueError("Entity value contains unsupported characters")
    if kind is not None and kind not in ("host", "ip", "user"):
        raise ValueError(f"Unknown entity kind: {kind}")

    if _is_ip(cleaned):
        if kind not in (None, "ip"):
            raise ValueError(f"{cleaned} is an IP address, not a {kind}")
        normalized = str(ipaddress.ip_address(cleaned))
        return EntityTerm("ip", normalized, normalized, (normalized.lower(),))
    if kind == "ip":
        raise ValueError("Value is not a valid IP address")

    if kind == "user" or (kind is None and ("@" in cleaned or "\\" in cleaned)):
        short = cleaned.split("\\")[-1].split("@")[0]
        return _partial_term("user", cleaned, short)

    short = cleaned.split(".")[0]
    return _partial_term("host", cleaned, short)


def _partial_term(kind: EntityKind, value: str, short: str) -> EntityTerm:
    if len(short) < MIN_PARTIAL_TERM_CHARS:
        raise ValueError(f"A {kind} name needs at least {MIN_PARTIAL_TERM_CHARS} characters to search safely")
    forms = tuple(dict.fromkeys(form.lower() for form in (value, short)))
    return EntityTerm(kind, value, short, forms)


def match_quality(entity: EntityTerm, candidate: Any) -> str | None:
    """Classify a returned value: 'exact', 'partial', or None when it does not match at all."""
    values = candidate if isinstance(candidate, list) else [candidate]
    best = None
    for raw in values:
        if not isinstance(raw, str):
            continue
        lowered = raw.lower()
        if entity.kind == "ip":
            if lowered == entity.term.lower():
                return "exact"
            continue
        bare = lowered.split("\\")[-1].split("@")[0] if entity.kind == "user" else lowered.split(".")[0]
        if lowered in entity.exact_forms or bare in entity.exact_forms:
            return "exact"
        if entity.term.lower() in lowered:
            best = "partial"
    return best


def _first(roles: dict[str, list[str]], kind: str) -> str | None:
    for role in ENTITY_ROLES[kind]:
        if roles.get(role):
            return roles[role][0]
    return None


def _all(roles: dict[str, list[str]], kind: str) -> list[str]:
    names: list[str] = []
    for role in ENTITY_ROLES[kind]:
        for name in roles.get(role, []):
            if name not in names:
                names.append(name)
    return names


def build_identity_plan(
    resolved: ResolvedDataset,
    roles: dict[str, list[str]],
    entity: EntityTerm,
    window_hours: int,
    discovered: frozenset[str] | set[str],
) -> tuple[DatasetQueryPlan, dict[str, str]] | None:
    """Build the typed lookup plan for one identity source, or None when it cannot answer."""
    search_fields = _all(roles, entity.kind)
    output = {kind: name for kind in ("host", "ip", "user") if (name := _first(roles, kind))}
    if not search_fields or len(output) < 2:
        return None

    operator = "eq" if entity.kind == "ip" else "contains"
    filters = [QueryFilter(field=name, operator=operator, value=entity.term) for name in search_fields]
    time_field = resolved.entry.time_field if resolved.entry.time_field in discovered else None
    group_fields = list(dict.fromkeys(output.values()))

    if resolved.entry.volume in ("high", "very_high") and time_field:
        plan = DatasetQueryPlan(
            dataset=resolved.dataset_name,
            mode="aggregate",
            filters=filters,
            filter_logic="or",
            metrics=[
                QueryMetric(function="count", alias="events"),
                QueryMetric(function="max", alias="last_seen", field=time_field),
            ],
            group_by=group_fields,
            order_by=[QuerySort(field="last_seen", direction="desc")],
            timeframe=window_timeframe(window_hours),
            limit=MAX_LINKS_PER_SOURCE,
        )
    else:
        plan = DatasetQueryPlan(
            dataset=resolved.dataset_name,
            mode="rows",
            fields=group_fields,
            filters=filters,
            filter_logic="or",
            limit=MAX_LINKS_PER_SOURCE,
        )
    return plan, output


async def resolve(run: HelperRun, entity: EntityTerm, window_hours: int) -> Resolution:
    """Look the entity up in every allowed identity source and merge what they say."""
    resolution = Resolution(entity)
    sources = await select_datasets(run, identity_sources_only=True)
    for resolved in sources[:MAX_IDENTITY_SOURCES]:
        roles = await verified_roles(run, resolved)
        discovered = await discovered_field_names(run, resolved.dataset_name)
        built = build_identity_plan(resolved, roles, entity, window_hours, discovered)
        if built is None:
            continue
        plan, output = built
        rows = await run_plan(run, plan, "identity_lookup")
        resolution.sources_used.append(resolved.dataset_name)
        for row in rows:
            quality = match_quality(entity, row.get(output.get(entity.kind, "")))
            if quality is None:
                # The filter matched a secondary candidate field that is not projected.
                quality = "partial"
            link: dict[str, Any] = {"dataset": resolved.dataset_name, "match": quality}
            for kind, name in output.items():
                link[kind] = row.get(name)
            for extra in ("events", "last_seen"):
                if extra in row:
                    link[extra] = row[extra]
            resolution.links.append(link)
    resolution.links.sort(key=lambda link: (link["match"] != "exact", -(link.get("last_seen") or 0)))
    return resolution
