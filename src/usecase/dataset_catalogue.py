"""Authored dataset catalogue for agent-facing dataset selection.

The catalogue answers "which dataset holds this kind of data, and which fields identify a
host, user, IP address, or cloud resource in it". It is built from three layers:

1. A built-in catalogue of vendor-standard Cortex and marketplace datasets shipped with
   the gateway. It never contains deployment-specific names.
2. An optional operator-authored overlay file (``DATASET_CATALOGUE_OVERLAY_PATH``) for
   site-specific datasets. The overlay lives outside the repository.
3. Name-based inference for datasets that match neither layer.

Security properties:

- Catalogue text is authored content only. Nothing here is derived from log data, so
  dataset descriptions cannot become a prompt-injection path.
- Callers must apply dataset policy *before* searching, so a description never reveals a
  dataset the principal cannot query. ``search_catalogue`` only ever sees allowed names.
- Field names are candidates. Helpers must intersect them with discovered fields
  (``verified_fields``) before compiling a query.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator

from config.config import get_config
from pkg.util import RESOURCES_DIR
from usecase.xql_builder import SAFE_IDENTIFIER_RE

BUILTIN_CATALOGUE_FILE = "dataset_catalogue.json"
MAX_OVERLAY_BYTES = 1_048_576
MAX_CATALOGUE_ENTRIES = 2000
MAX_TOPIC_CHARS = 200
MAX_TOPIC_TOKENS = 12
MAX_FIND_RESULTS = 25
DEFAULT_FIND_RESULTS = 10

DatasetDomain = Literal[
    "endpoint_telemetry",
    "endpoint_inventory",
    "network_traffic",
    "network_threat",
    "web_proxy",
    "dns",
    "vpn_remote_access",
    "authentication_identity",
    "directory",
    "cloud_audit",
    "cloud_network",
    "saas_audit",
    "email",
    "alerts_incidents",
    "vulnerability",
    "threat_intel",
    "platform_audit",
    "ingestion_health",
    "application",
    "other",
]

EntityType = Literal["host", "ip", "user", "cloud_resource", "url_domain", "file_hash", "email_address"]

FieldRole = Literal[
    "host",
    "ip",
    "source_ip",
    "dest_ip",
    "source_port",
    "dest_port",
    "user",
    "source_user",
    "dest_user",
    "action",
    "rule",
    "app",
    "source_zone",
    "dest_zone",
    "bytes",
    "url_domain",
    "file_hash",
    "process",
    "command_line",
    "email_sender",
    "email_recipient",
    "resource_id",
    "resource_name",
    "cloud_account",
    "operation",
    "event_id",
    "event_type",
    "severity",
    "name",
    "log_type",
]

VolumeClass = Literal["low", "medium", "high", "very_high"]
CatalogueSource = Literal["overlay", "builtin", "inferred"]

ENTITY_ROLES: dict[str, tuple[str, ...]] = {
    "host": ("host",),
    "ip": ("ip", "source_ip", "dest_ip"),
    "user": ("user", "source_user", "dest_user"),
    "cloud_resource": ("resource_id", "resource_name"),
    "url_domain": ("url_domain",),
    "file_hash": ("file_hash",),
    "email_address": ("email_sender", "email_recipient"),
}

_MATCH_RE = re.compile(r"^[A-Za-z_*][A-Za-z0-9_.*]*\Z")
_TEXT_RE = re.compile(r"^[A-Za-z0-9 .,;:()/&+'_\-]*\Z")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "a an and are for from in is it me my of on or our please show the this that to what which with logs log data events".split()
)
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "fw": ("firewall",),
    "firewalls": ("firewall",),
    "computer": ("host", "endpoint"),
    "machine": ("host", "endpoint"),
    "server": ("host", "endpoint"),
    "laptop": ("host", "endpoint"),
    "workstation": ("host", "endpoint"),
    "device": ("host", "endpoint"),
    "logon": ("login", "authentication"),
    "logons": ("login", "authentication"),
    "signin": ("login", "authentication"),
    "signins": ("login", "authentication"),
    "signon": ("login", "authentication"),
    "sso": ("login", "authentication"),
    "mfa": ("authentication",),
    "account": ("user",),
    "accounts": ("user",),
    "blocked": ("firewall", "deny"),
    "dropped": ("firewall", "deny"),
    "dropping": ("firewall", "deny"),
    "traffic": ("network",),
    "connections": ("network",),
    "connection": ("network",),
    "mail": ("email",),
    "phishing": ("email",),
    "vulnerabilities": ("vulnerability",),
    "cve": ("vulnerability",),
    "cves": ("vulnerability",),
    "incident": ("incidents", "alerts"),
    "alert": ("alerts",),
    "detections": ("alerts",),
    "ioc": ("indicator", "threat"),
    "iocs": ("indicator", "threat"),
    "ingestion": ("ingestion", "health"),
    "onboarding": ("ingestion", "health"),
    "cloudtrail": ("aws", "cloud", "audit"),
    "azure": ("azure", "cloud"),
    "gcp": ("gcp", "cloud"),
    "aws": ("aws", "cloud"),
    "proxy": ("proxy", "web"),
    "browsing": ("proxy", "web", "url"),
    "website": ("proxy", "web", "url"),
    "websites": ("proxy", "web", "url"),
    "vpn": ("vpn", "remote"),
}

_INFERENCE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"flow_?log|netflow|vpc_?flow"), "cloud_network"),
    (re.compile(r"firewall|ngfw|_asa_|fortigate|checkpoint"), "network_traffic"),
    (re.compile(r"proxy|squid|swg"), "web_proxy"),
    (re.compile(r"(^|_)dns(_|$)"), "dns"),
    (re.compile(r"vpn|globalprotect|anyconnect"), "vpn_remote_access"),
    (re.compile(r"login|signon|sign_in|(^|_)sso(_|$)|(^|_)auth(_|$)|(^|_)mfa(_|$)"), "authentication_identity"),
    (re.compile(r"email|(^|_)mail(_|$)"), "email"),
    (re.compile(r"alert|incident"), "alerts_incidents"),
    (re.compile(r"vuln|(^|_)cve"), "vulnerability"),
    (re.compile(r"threat_intel|indicator"), "threat_intel"),
    (re.compile(r"audit"), "saas_audit"),
    (re.compile(r"inventory|(^|_)assets?(_|$)"), "endpoint_inventory"),
)


class CatalogueError(ValueError):
    """Raised when a catalogue file is missing, oversized, or fails validation."""


class CatalogueEntry(BaseModel):
    """One authored catalogue record. ``match`` is an exact dataset name or a ``*`` glob."""

    model_config = ConfigDict(extra="forbid")

    match: str = Field(min_length=1, max_length=255)
    domain: DatasetDomain
    description: str = Field(min_length=1, max_length=240)
    vendor: str | None = Field(default=None, max_length=80)
    product: str | None = Field(default=None, max_length=80)
    keywords: list[str] = Field(default_factory=list, max_length=20)
    time_field: str = Field(default="_time", max_length=255)
    fields: dict[FieldRole, list[str]] = Field(default_factory=dict)
    volume: VolumeClass | None = None
    identity_source: bool = Field(
        default=False,
        description="True when rows link a host, IP address, and user, so resolve_entity may use the dataset.",
    )

    @field_validator("match")
    @classmethod
    def _validate_match(cls, value: str) -> str:
        if not _MATCH_RE.fullmatch(value):
            raise ValueError("match must be a dataset name or a glob using only '*'")
        if value.strip("*") == "":
            raise ValueError("match must not be a bare wildcard")
        return value

    @field_validator("description", "vendor", "product")
    @classmethod
    def _validate_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _TEXT_RE.fullmatch(value):
            raise ValueError("catalogue text may contain only letters, digits, spaces, and basic punctuation")
        return value.strip()

    @field_validator("keywords")
    @classmethod
    def _validate_keywords(cls, value: list[str]) -> list[str]:
        cleaned = []
        for keyword in value:
            if not isinstance(keyword, str) or not re.fullmatch(r"[a-z0-9_]{1,40}", keyword):
                raise ValueError("keywords must be lowercase tokens of letters, digits, or underscore")
            cleaned.append(keyword)
        return cleaned

    @field_validator("time_field")
    @classmethod
    def _validate_time_field(cls, value: str) -> str:
        if not SAFE_IDENTIFIER_RE.fullmatch(value):
            raise ValueError("time_field must be a valid field identifier")
        return value

    @field_validator("fields")
    @classmethod
    def _validate_fields(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        for role, names in value.items():
            if not names or len(names) > 8:
                raise ValueError(f"role {role} must list between 1 and 8 candidate fields")
            for name in names:
                if not isinstance(name, str) or len(name) > 255 or not SAFE_IDENTIFIER_RE.fullmatch(name):
                    raise ValueError(f"role {role} has an invalid field identifier")
        return value

    @property
    def is_pattern(self) -> bool:
        return "*" in self.match


class CatalogueFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    entries: list[CatalogueEntry] = Field(max_length=MAX_CATALOGUE_ENTRIES)


@dataclass(frozen=True)
class ResolvedDataset:
    """A tenant dataset name joined to the catalogue record that describes it."""

    dataset_name: str
    entry: CatalogueEntry
    source: str

    def fields_for_entity(self, entity_type: str) -> list[str]:
        names: list[str] = []
        for role in ENTITY_ROLES.get(entity_type, ()):
            for name in self.entry.fields.get(role, []):
                if name not in names:
                    names.append(name)
        return names

    def to_record(self, entity_type: str | None = None) -> dict[str, Any]:
        entry = self.entry
        record: dict[str, Any] = {
            "dataset_name": self.dataset_name,
            "domain": entry.domain,
            "description": entry.description,
            "vendor": entry.vendor,
            "product": entry.product,
            "time_field": entry.time_field,
            "fields": {role: list(names) for role, names in entry.fields.items()},
            "volume": entry.volume,
            "identity_source": entry.identity_source,
            "query_hint": _query_hint(entry),
            "catalogue_source": self.source,
            "fields_verified": False,
        }
        if entity_type:
            record["entity_fields"] = self.fields_for_entity(entity_type)
        return record


class DatasetCatalogue:
    """Immutable, validated catalogue with overlay-over-builtin resolution."""

    def __init__(self, builtin: list[CatalogueEntry], overlay: list[CatalogueEntry] | None = None):
        self._layers: tuple[tuple[str, dict[str, CatalogueEntry], list[CatalogueEntry]], ...] = tuple(
            (source, *_index(entries)) for source, entries in (("overlay", overlay or []), ("builtin", builtin))
        )

    def resolve(self, dataset_name: str) -> ResolvedDataset:
        """Return the best record for a dataset: exact overlay, exact builtin, glob overlay, glob builtin, inferred."""
        lowered = dataset_name.lower()
        for source, exact, _patterns in self._layers:
            if lowered in exact:
                return ResolvedDataset(dataset_name, exact[lowered], source)
        for source, _exact, patterns in self._layers:
            for entry in patterns:
                if fnmatch.fnmatchcase(lowered, entry.match.lower()):
                    return ResolvedDataset(dataset_name, entry, source)
        return ResolvedDataset(dataset_name, _infer_entry(dataset_name), "inferred")

    def entry_count(self) -> dict[str, int]:
        return {source: len(exact) + len(patterns) for source, exact, patterns in self._layers}


def _index(entries: list[CatalogueEntry]) -> tuple[dict[str, CatalogueEntry], list[CatalogueEntry]]:
    exact: dict[str, CatalogueEntry] = {}
    patterns: list[CatalogueEntry] = []
    for entry in entries:
        if entry.is_pattern:
            patterns.append(entry)
        else:
            exact.setdefault(entry.match.lower(), entry)
    # Longest pattern first so the most specific glob wins deterministically.
    patterns.sort(key=lambda item: (-len(item.match.replace("*", "")), item.match))
    return exact, patterns


def _infer_entry(dataset_name: str) -> CatalogueEntry:
    lowered = dataset_name.lower()
    domain = "other"
    for pattern, candidate in _INFERENCE_RULES:
        if pattern.search(lowered):
            domain = candidate
            break
    return CatalogueEntry(
        match=dataset_name,
        domain=domain,
        description="No catalogue entry. Domain is inferred from the dataset name; run discover_log_fields before querying.",
    )


def _query_hint(entry: CatalogueEntry) -> str:
    if entry.volume in ("high", "very_high"):
        return "aggregate_first"
    return "rows_or_aggregate"


def parse_catalogue(raw: str, label: str) -> list[CatalogueEntry]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CatalogueError(f"{label} is not valid JSON: {e.msg}") from e
    try:
        return CatalogueFile.model_validate(payload).entries
    except ValueError as e:
        raise CatalogueError(f"{label} failed validation: {_compact_validation_error(e)}") from e


def _compact_validation_error(error: ValueError) -> str:
    errors = getattr(error, "errors", None)
    if callable(errors):
        first = errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        return f"{location}: {first.get('msg', 'invalid value')}"
    return "invalid catalogue content"


def load_overlay(path: str) -> list[CatalogueEntry]:
    overlay_path = Path(path).expanduser()
    if not overlay_path.is_file():
        raise CatalogueError("DATASET_CATALOGUE_OVERLAY_PATH does not point to a readable file")
    if overlay_path.stat().st_size > MAX_OVERLAY_BYTES:
        raise CatalogueError(f"Dataset catalogue overlay exceeds {MAX_OVERLAY_BYTES} bytes")
    return parse_catalogue(overlay_path.read_text(encoding="utf-8"), "Dataset catalogue overlay")


@lru_cache(maxsize=4)
def _load_catalogue(overlay_path: str) -> DatasetCatalogue:
    builtin_raw = (RESOURCES_DIR / BUILTIN_CATALOGUE_FILE).read_text(encoding="utf-8")
    builtin = parse_catalogue(builtin_raw, "Built-in dataset catalogue")
    overlay = load_overlay(overlay_path) if overlay_path else []
    return DatasetCatalogue(builtin, overlay)


def get_catalogue() -> DatasetCatalogue:
    """Return the cached catalogue for the configured overlay path. Raises CatalogueError if invalid."""
    return _load_catalogue((get_config().dataset_catalogue_overlay_path or "").strip())


def reset_catalogue_cache() -> None:
    _load_catalogue.cache_clear()


def tokenize_topic(topic: str | None) -> list[str]:
    if not topic:
        return []
    tokens: list[str] = []
    for token in _TOKEN_RE.findall(topic[:MAX_TOPIC_CHARS].lower()):
        if token in _STOPWORDS or len(token) < 2:
            continue
        for expanded in (token, *_SYNONYMS.get(token, ())):
            if expanded not in tokens:
                tokens.append(expanded)
        if len(tokens) >= MAX_TOPIC_TOKENS:
            break
    return tokens[:MAX_TOPIC_TOKENS]


def _score(resolved: ResolvedDataset, tokens: list[str]) -> int:
    entry = resolved.entry
    name_tokens = set(_TOKEN_RE.findall(resolved.dataset_name.lower()))
    keyword_tokens = set(entry.keywords)
    domain_tokens = set(entry.domain.split("_"))
    vendor_tokens = set(_TOKEN_RE.findall(f"{entry.vendor or ''} {entry.product or ''}".lower()))
    description_tokens = set(_TOKEN_RE.findall(entry.description.lower())) if resolved.source != "inferred" else set()
    score = 0
    for token in tokens:
        if token in name_tokens:
            score += 5
        elif len(token) >= 3 and token in resolved.dataset_name.lower():
            score += 3
        if token in keyword_tokens:
            score += 4
        if token in domain_tokens:
            score += 3
        if token in vendor_tokens:
            score += 3
        if token in description_tokens:
            score += 1
    return score


def search_catalogue(
    allowed_dataset_names: list[str],
    *,
    topic: str | None = None,
    domain: str | None = None,
    entity_type: str | None = None,
    max_results: int = DEFAULT_FIND_RESULTS,
    offset: int = 0,
    catalogue: DatasetCatalogue | None = None,
) -> dict[str, Any]:
    """Rank policy-allowed dataset names against the catalogue.

    ``allowed_dataset_names`` must already be filtered by dataset policy. Names that are not
    valid XQL identifiers are dropped because no typed tool could query them.
    """
    if domain is not None and domain not in get_args(DatasetDomain):
        raise ValueError(f"Unknown domain: {domain}")
    if entity_type is not None and entity_type not in ENTITY_ROLES:
        raise ValueError(f"Unknown entity_type: {entity_type}")

    active = catalogue or get_catalogue()
    safe_limit = min(max(int(max_results), 1), MAX_FIND_RESULTS)
    safe_offset = max(int(offset), 0)
    tokens = tokenize_topic(topic)

    ranked: list[tuple[int, int, str, ResolvedDataset]] = []
    excluded_without_entity_fields = 0
    seen: set[str] = set()
    for name in allowed_dataset_names:
        if not isinstance(name, str) or len(name) > 255 or not SAFE_IDENTIFIER_RE.fullmatch(name) or name in seen:
            continue
        seen.add(name)
        resolved = active.resolve(name)
        if domain and resolved.entry.domain != domain:
            continue
        if entity_type and not resolved.fields_for_entity(entity_type):
            excluded_without_entity_fields += 1
            continue
        score = _score(resolved, tokens)
        if tokens and score == 0:
            continue
        source_rank = 0 if resolved.source != "inferred" else 1
        ranked.append((-score, source_rank, name, resolved))

    ranked.sort(key=lambda item: item[:3])
    page = ranked[safe_offset : safe_offset + safe_limit]
    next_offset = safe_offset + safe_limit if safe_offset + safe_limit < len(ranked) else None
    return {
        "datasets": [item[3].to_record(entity_type) for item in page],
        "returned": len(page),
        "total_matches": len(ranked),
        "offset": safe_offset,
        "next_offset": next_offset,
        "excluded_without_entity_fields": excluded_without_entity_fields,
        "topic_tokens": tokens,
    }


def verified_fields(resolved: ResolvedDataset, discovered_field_names: set[str] | list[str]) -> dict[str, list[str]]:
    """Intersect catalogue candidates with discovered field names, preserving candidate order."""
    discovered = set(discovered_field_names)
    verified: dict[str, list[str]] = {}
    for role, names in resolved.entry.fields.items():
        kept = [name for name in names if name in discovered]
        if kept:
            verified[role] = kept
    return verified
