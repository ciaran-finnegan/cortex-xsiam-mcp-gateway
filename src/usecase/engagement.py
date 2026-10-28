import asyncio
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import tempfile
import threading
import time
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from config.config import get_config
from entities.MCPContext import MCPContext
from pkg.util import MAIN_DIR
from usecase.dataset_query import QueryTimeframe
from usecase.xql_discovery import extract_xql_rows
from usecase.xql_results import result_metadata

logger = logging.getLogger(__name__)

EngagementMode = Literal["incident_response", "threat_hunt", "operations", "unset"]
FactConfidence = Literal["low", "medium", "high"]
ResultShape = Literal["aggregate", "rows"]

UNSET_MODE = "unset"
ENGAGEMENT_MODES: tuple[str, ...] = ("incident_response", "threat_hunt", "operations", UNSET_MODE)
ENGAGEMENT_TOOL_NAMES: tuple[str, ...] = ("set_engagement", "get_engagement", "record_fact", "get_engagement_log")
SCOPE_LISTS: tuple[str, ...] = ("iocs", "internal", "front_ends", "servers")

MAX_NOTES_CHARS = 2000
MAX_FACT_VALUE_CHARS = 1024
MAX_SESSION_QUERIES = 200
MAX_SESSION_FACTS = 200
MAX_CASE_QUERIES = 1000
MAX_CASE_FACTS = 500
MAX_CASE_FILE_BYTES = 2 * 1024 * 1024
MAX_LOG_QUERIES_RETURNED = 100

_STATE_KEY_PREFIX = "cortex_engagement"
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_FACT_KEY = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
_QUERY_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_FILE_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_XQL_DATASET = re.compile(r"^\s*dataset\s*=\s*([A-Za-z0-9_]+)", re.IGNORECASE)

# Conservative defaults. Units are XSIAM compute units. The cost guard reads
# these through get_mode_policy(); this module only records spend.
DEFAULT_MODE_POLICY: dict[str, dict[str, Any]] = {
    "incident_response": {
        "default_window_ms": 86_400_000,
        "approval_threshold_units": 5.0,
        "session_budget_units": 25.0,
        "reserve_units": 10.0,
        "default_result_shape": "rows",
        "heavy_tools_hidden": [],
    },
    "threat_hunt": {
        "default_window_ms": 604_800_000,
        "approval_threshold_units": 3.0,
        "session_budget_units": 15.0,
        "reserve_units": 15.0,
        "default_result_shape": "aggregate",
        "heavy_tools_hidden": [],
    },
    "operations": {
        "default_window_ms": 3_600_000,
        "approval_threshold_units": 1.0,
        "session_budget_units": 5.0,
        "reserve_units": 20.0,
        "default_result_shape": "aggregate",
        "heavy_tools_hidden": ["execute_xql_query"],
    },
    UNSET_MODE: {
        "default_window_ms": 3_600_000,
        "approval_threshold_units": 1.0,
        "session_budget_units": 3.0,
        "reserve_units": 25.0,
        "default_result_shape": "aggregate",
        "heavy_tools_hidden": ["execute_xql_query"],
    },
}


class EngagementError(ValueError):
    """Raised when an engagement request is invalid."""


class EngagementStoreError(RuntimeError):
    """Raised when the engagement case store is misconfigured or unreadable."""


class ModePolicy(BaseModel):
    """Per-mode defaults. The schema has no grant fields: a mode can only hide tools."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    default_window_ms: int = Field(gt=0)
    approval_threshold_units: float = Field(ge=0)
    session_budget_units: float = Field(ge=0)
    reserve_units: float = Field(ge=0)
    default_result_shape: ResultShape
    heavy_tools_hidden: tuple[str, ...] = ()


class Engagement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: EngagementMode = UNSET_MODE
    case_id: str | None = None
    iocs: list[str] = Field(default_factory=list)
    internal: list[str] = Field(default_factory=list)
    front_ends: list[str] = Field(default_factory=list)
    servers: list[str] = Field(default_factory=list)
    window: dict[str, int] | None = None
    notes: str | None = None
    set_at: str | None = None


@dataclass
class EngagementScope:
    """Engagement in effect for one tool call. set_engagement updates it in place."""

    mode: str = UNSET_MODE
    case_id: str | None = None
    tool_name: str | None = None


_active_scope: ContextVar[EngagementScope | None] = ContextVar("cortex_engagement_scope", default=None)
_session_locks: dict[tuple[int, int], asyncio.Lock] = {}
_LOCK_STRIPES = 64
_file_lock = threading.Lock()


# --- Mode policy ---


def get_mode_policy(mode: str | None = None) -> ModePolicy:
    """Return the validated policy for a mode, defaulting to the mode of the current tool call."""
    selected = current_mode() if mode is None else mode
    if selected not in ENGAGEMENT_MODES:
        raise EngagementError(f"Unknown engagement mode: {selected}")
    return get_mode_policy_table()[selected]


def get_mode_policy_table() -> dict[str, ModePolicy]:
    config = get_config()
    return _parse_mode_policy(config.engagement_mode_policy, config.dataset_query_max_timeframe_ms)


def hidden_tools_for_mode(mode: str) -> frozenset[str]:
    return frozenset(get_mode_policy(mode).heavy_tools_hidden)


@lru_cache(maxsize=8)
def _parse_mode_policy(raw_policy: str, max_timeframe_ms: int) -> dict[str, ModePolicy]:
    overrides: Any = {}
    if raw_policy.strip():
        try:
            overrides = json.loads(raw_policy)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid ENGAGEMENT_MODE_POLICY JSON: {e}") from e
    if not isinstance(overrides, dict):
        raise ValueError("ENGAGEMENT_MODE_POLICY must be a JSON object mapping modes to settings")
    unknown = sorted(set(overrides) - set(ENGAGEMENT_MODES))
    if unknown:
        raise ValueError(f"ENGAGEMENT_MODE_POLICY has unknown modes: {', '.join(unknown)}")

    table: dict[str, ModePolicy] = {}
    for mode in ENGAGEMENT_MODES:
        override = overrides.get(mode, {})
        if not isinstance(override, dict):
            raise ValueError(f"ENGAGEMENT_MODE_POLICY entry for {mode} must be an object")
        try:
            policy = ModePolicy.model_validate({**DEFAULT_MODE_POLICY[mode], **override})
        except ValidationError as e:
            raise ValueError(f"Invalid ENGAGEMENT_MODE_POLICY entry for {mode}: {e.errors()[0]['msg']}") from e
        if max_timeframe_ms > 0 and policy.default_window_ms > max_timeframe_ms:
            raise ValueError(f"ENGAGEMENT_MODE_POLICY default_window_ms for {mode} exceeds DATASET_QUERY_MAX_TIMEFRAME_MS")
        locked = sorted(set(policy.heavy_tools_hidden) & set(ENGAGEMENT_TOOL_NAMES))
        if locked:
            raise ValueError(f"ENGAGEMENT_MODE_POLICY cannot hide engagement tools: {', '.join(locked)}")
        table[mode] = policy
    return table


# --- Active scope for the current tool call ---


def current_scope() -> EngagementScope | None:
    return _active_scope.get()


def current_mode() -> str:
    scope = _active_scope.get()
    return scope.mode if scope else UNSET_MODE


def apply_engagement(principal: MCPContext) -> MCPContext:
    """Copy the active mode and case onto a principal. Never mutates shared lifespan state."""
    scope = _active_scope.get()
    if scope is None:
        return principal
    return replace(principal, mode=scope.mode, case_id=scope.case_id)


async def enter_engagement_scope(ctx: Any, principal: MCPContext | None, tool_name: str | None) -> Token:
    """Load the caller's engagement for this tool call. Any failure falls back to unset."""
    scope = EngagementScope(tool_name=tool_name)
    if principal is not None:
        try:
            engagement = await load_engagement(ctx, principal)
            scope.mode = engagement.mode
            scope.case_id = engagement.case_id
        except Exception as e:
            logger.warning("Engagement state unavailable; using unset mode: %s", type(e).__name__)
    return _active_scope.set(scope)


def exit_engagement_scope(token: Token) -> None:
    _active_scope.reset(token)


# --- Session state ---


def owner_key(principal: MCPContext) -> str:
    identity = {
        "principal_id": principal.principal_id,
        "tenant_id": principal.tenant_id,
        "auth_source": principal.auth_source,
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


async def load_engagement(ctx: Any, principal: MCPContext) -> Engagement:
    record = await _load_session_record(ctx, owner_key(principal))
    if record is None:
        return Engagement()
    try:
        return Engagement.model_validate(record.get("engagement") or {})
    except ValidationError:
        return Engagement()


async def set_session_engagement(
    ctx: Any,
    principal: MCPContext,
    engagement: Engagement,
    omitted: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Persist an engagement for this session and principal.

    When the case already exists, fields the caller omitted are restored from it so
    agents do not have to re-send indicator lists in a new session.
    """
    owner = owner_key(principal)
    store = get_engagement_store()
    async with _session_lock(ctx):
        record = await _load_session_record(ctx, owner) or _new_session_record(owner)
        previous = Engagement.model_validate(record.get("engagement") or {})
        resumed = False
        if engagement.case_id:
            source: Engagement | None = None
            if store is not None:
                stored = store.read(principal, engagement.case_id)
                if stored is not None:
                    source = Engagement.model_validate(stored.get("engagement") or {})
            elif previous.case_id == engagement.case_id:
                source = previous
            if source is not None:
                engagement, resumed = _merge_omitted_scope(engagement, source, omitted)
        stored_engagement = engagement.model_dump(mode="json")
        record["engagement"] = stored_engagement
        await _save_session_record(ctx, owner, record)
    if store is not None and engagement.case_id:

        def _set_case_engagement(case: dict[str, Any]) -> None:
            case["engagement"] = stored_engagement

        store.update(principal, engagement.case_id, _set_case_engagement)

    scope = _active_scope.get()
    if scope is not None:
        scope.mode = engagement.mode
        scope.case_id = engagement.case_id
    return {
        "engagement": engagement,
        "previous_mode": previous.mode,
        "resumed_from_case": resumed,
        "case_store": "enabled" if store is not None else "disabled",
    }


async def record_fact(
    ctx: Any,
    principal: MCPContext,
    *,
    key: str,
    value: Any,
    evidence_query_id: str,
    confidence: str,
) -> dict[str, Any]:
    fact_key = _validate_fact_key(key)
    fact_value = _validate_fact_value(value)
    query_id = _validate_query_id(evidence_query_id)
    if confidence not in ("low", "medium", "high"):
        raise EngagementError("confidence must be low, medium, or high")

    owner = owner_key(principal)
    store = get_engagement_store()
    async with _session_lock(ctx):
        record = await _load_session_record(ctx, owner)
        engagement = Engagement.model_validate((record or {}).get("engagement") or {})
        if record is None or engagement.mode == UNSET_MODE:
            raise EngagementError("Call set_engagement before recording facts")
        known_ids = {entry.get("query_id") for entry in record.get("queries", [])}
        case = store.read(principal, engagement.case_id) if store is not None and engagement.case_id else None
        if case is not None:
            known_ids.update(entry.get("query_id") for entry in case.get("queries", []))
        if query_id not in known_ids:
            raise EngagementError("evidence_query_id does not match a query recorded in this engagement")

        fact = {
            "key": fact_key,
            "value": fact_value,
            "evidence_query_id": query_id,
            "confidence": confidence,
            "mode": engagement.mode,
            "case_id": engagement.case_id,
            "recorded_at": _now_iso(),
        }
        record["facts"] = _capped([*record.get("facts", []), fact], MAX_SESSION_FACTS)
        await _save_session_record(ctx, owner, record)
    if store is not None and engagement.case_id:
        store.update(principal, engagement.case_id, lambda case: _append_capped(case, "facts", fact, MAX_CASE_FACTS))
    return fact


async def get_engagement_log(ctx: Any, principal: MCPContext, case_id: str | None = None) -> dict[str, Any]:
    owner = owner_key(principal)
    record = await _load_session_record(ctx, owner) or _new_session_record(owner)
    session_engagement = Engagement.model_validate(record.get("engagement") or {})
    if case_id is None:
        return _log_view(
            source="session",
            case_id=session_engagement.case_id,
            engagement=record.get("engagement"),
            facts=record.get("facts", []),
            queries=record.get("queries", []),
        )

    validated = validate_case_id(case_id)
    store = get_engagement_store()
    if store is not None:
        case = store.read(principal, validated)
        if case is None:
            raise EngagementError(f"No engagement log for case {validated}")
        return _log_view(
            source="case_store",
            case_id=validated,
            engagement=case.get("engagement"),
            facts=case.get("facts", []),
            queries=case.get("queries", []),
        )
    if session_engagement.case_id != validated:
        raise EngagementError(f"No engagement log for case {validated}; ENGAGEMENT_STORE_DIR is not configured")
    return _log_view(
        source="session",
        case_id=validated,
        engagement=record.get("engagement"),
        facts=[fact for fact in record.get("facts", []) if fact.get("case_id") == validated],
        queries=[query for query in record.get("queries", []) if query.get("case_id") == validated],
    )


async def get_session_spend(ctx: Any, principal: MCPContext) -> dict[str, Any]:
    """Return this session's recorded XQL spend. Hook for the cost guard; no decisions are made here."""
    record = await _load_session_record(ctx, owner_key(principal))
    return summarize_spend((record or {}).get("queries", []))


def summarize_spend(queries: list[dict[str, Any]]) -> dict[str, Any]:
    known = [entry["units"] for entry in queries if isinstance(entry.get("units"), (int, float))]
    return {
        "query_count": len(queries),
        "units": round(sum(known), 6),
        "queries_with_units": len(known),
        "queries_without_units": len(queries) - len(known),
    }


# --- Query telemetry ---


async def record_query_telemetry(
    ctx: Any,
    *,
    query: str,
    timeframe: dict[str, Any] | None,
    response: dict[str, Any] | None,
    duration_ms: float,
    error: Exception | None = None,
) -> None:
    """Append one executed XQL query to the session and case logs. Never raises."""
    if ctx is None or not hasattr(ctx, "set_state"):
        return
    try:
        principal = _telemetry_principal(ctx)
        if principal is None:
            return
        owner = owner_key(principal)
        scope = _active_scope.get() or EngagementScope()
        entry = _query_entry(query, timeframe, response or {}, duration_ms, error, scope)
        async with _session_lock(ctx):
            record = await _load_session_record(ctx, owner) or _new_session_record(owner)
            remaining = entry.get("remaining_quota")
            previous = record.get("last_remaining_quota")
            if isinstance(remaining, (int, float)):
                if isinstance(previous, (int, float)) and previous >= remaining:
                    entry["remaining_quota_delta"] = round(previous - remaining, 6)
                record["last_remaining_quota"] = remaining
            if entry.get("units") is None and entry.get("remaining_quota_delta") is not None:
                entry["units"] = entry["remaining_quota_delta"]
            record["queries"] = _capped([*record.get("queries", []), entry], MAX_SESSION_QUERIES)
            await _save_session_record(ctx, owner, record)
        store = get_engagement_store()
        if store is not None and scope.case_id:
            store.update(principal, scope.case_id, lambda case: _append_capped(case, "queries", entry, MAX_CASE_QUERIES))
    except EngagementError:
        # No MCP session to record into, for example a direct call outside a request.
        return
    except Exception as e:
        logger.warning("Failed to record XQL query telemetry: %s", type(e).__name__)


def _query_entry(
    query: str,
    timeframe: dict[str, Any] | None,
    response: dict[str, Any],
    duration_ms: float,
    error: Exception | None,
    scope: EngagementScope,
) -> dict[str, Any]:
    metadata = result_metadata(response)
    remaining = metadata.get("remaining_quota")
    query_cost = _query_cost_units(metadata.get("query_cost"))
    if error is not None:
        status = "error"
    elif response.get("error"):
        status = "timeout" if "timed out" in str(response["error"]) else "failed"
    else:
        status = "success"
    dataset_match = _XQL_DATASET.match(query or "")
    query_id = response.get("query_id")
    entry: dict[str, Any] = {
        "query_id": str(query_id) if query_id else None,
        "tool": scope.tool_name,
        "mode": scope.mode,
        "case_id": scope.case_id,
        "dataset": dataset_match.group(1) if dataset_match else None,
        "window": _normalize_window(timeframe),
        "rows": len(extract_xql_rows(response)) if status == "success" else 0,
        "number_of_results": metadata.get("number_of_results") if isinstance(metadata.get("number_of_results"), int) else None,
        "query_cost_units": query_cost,
        "remaining_quota": remaining if isinstance(remaining, (int, float)) and not isinstance(remaining, bool) else None,
        "remaining_quota_delta": None,
        "units": query_cost,
        "duration_ms": round(duration_ms, 3),
        "status": status,
        "query_sha256": hashlib.sha256((query or "").encode()).hexdigest(),
        "recorded_at": _now_iso(),
    }
    if error is not None:
        entry["error_type"] = type(error).__name__
    return entry


def _query_cost_units(value: Any) -> float | None:
    # XSIAM reports query_cost as a number or as a mapping of tenant to cost.
    # Only the total is kept so tenant identifiers never reach the log.
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return round(float(value), 6) if math.isfinite(value) else None
    if isinstance(value, dict):
        costs = [item for item in value.values() if isinstance(item, (int, float)) and not isinstance(item, bool)]
        if costs and all(math.isfinite(item) for item in costs):
            return round(float(sum(costs)), 6)
    return None


def _normalize_window(timeframe: dict[str, Any] | None) -> dict[str, int] | None:
    if not isinstance(timeframe, dict):
        return None
    if isinstance(timeframe.get("relativeTime"), int):
        return {"relative_ms": timeframe["relativeTime"]}
    if isinstance(timeframe.get("from"), int) and isinstance(timeframe.get("to"), int):
        return {"from_ms": timeframe["from"], "to_ms": timeframe["to"]}
    return None


def _telemetry_principal(ctx: Any) -> MCPContext | None:
    from usecase.identity import IdentityAuthenticationError, resolve_mcp_context

    try:
        return resolve_mcp_context(ctx)
    except IdentityAuthenticationError:
        return None


# --- Validation ---


def build_engagement(
    *,
    mode: str,
    case_id: str | None = None,
    iocs: list[str] | None = None,
    internal: list[str] | None = None,
    front_ends: list[str] | None = None,
    servers: list[str] | None = None,
    window: QueryTimeframe | dict[str, Any] | None = None,
    notes: str | None = None,
) -> tuple[Engagement, set[str]]:
    """Validate set_engagement input. Returns the engagement and the names of omitted fields."""
    if mode not in ENGAGEMENT_MODES:
        raise EngagementError(f"mode must be one of: {', '.join(ENGAGEMENT_MODES)}")
    limit = get_config().engagement_max_scope_items
    lists = {"iocs": iocs, "internal": internal, "front_ends": front_ends, "servers": servers}
    omitted = {name for name, values in lists.items() if values is None}
    if window is None:
        omitted.add("window")
    if notes is None:
        omitted.add("notes")
    engagement = Engagement(
        mode=mode,
        case_id=validate_case_id(case_id) if case_id is not None else None,
        iocs=validate_scope_list("iocs", iocs or [], limit=limit, allow_hashes=True),
        internal=validate_scope_list("internal", internal or [], limit=limit),
        front_ends=validate_scope_list("front_ends", front_ends or [], limit=limit),
        servers=validate_scope_list("servers", servers or [], limit=limit),
        window=_freeze_window(window),
        notes=_validate_notes(notes),
        set_at=_now_iso(),
    )
    return engagement, omitted


def validate_case_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
        raise EngagementError("case_id must be 1-64 characters of letters, digits, '.', '_' or '-', starting with a letter or digit")
    return case_id


def validate_scope_list(name: str, values: list[str], *, limit: int, allow_hashes: bool = False) -> list[str]:
    if not isinstance(values, list):
        raise EngagementError(f"{name} must be a list of strings")
    if len(values) > limit:
        raise EngagementError(f"{name} accepts at most {limit} entries")
    normalized: list[str] = []
    for value in values:
        item = normalize_scope_value(value, allow_hashes=allow_hashes)
        if item is None:
            kinds = "IP addresses, CIDR ranges, hostnames, or file hashes" if allow_hashes else "IP addresses, CIDR ranges, or hostnames"
            raise EngagementError(f"{name} entries must be {kinds}")
        if item not in normalized:
            normalized.append(item)
    return normalized


def normalize_scope_value(value: Any, *, allow_hashes: bool = False) -> str | None:
    """Return the canonical form of an IP, CIDR, hostname, or (optionally) file hash, else None."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not candidate or len(candidate) > 253 or any(char.isspace() for char in candidate):
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if "/" in candidate:
        try:
            return str(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            return None
    if allow_hashes and _FILE_HASH.fullmatch(candidate):
        return candidate
    hostname = candidate[:-1] if candidate.endswith(".") else candidate
    labels = hostname.split(".")
    if labels and labels[0] == "*" and len(labels) > 1:
        labels = labels[1:]
    if not labels or not all(_HOST_LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():
        # Rejects malformed IPv4 such as 10.0.0.256 rather than storing it as a hostname.
        return None
    return hostname


def normalize_audit_token(value: Any) -> str | None:
    """Return a caller-supplied identifier for audit only when it is well formed."""
    if value is None:
        return None
    if isinstance(value, str) and _QUERY_ID.fullmatch(value):
        return value
    return "invalid"


def _validate_notes(notes: str | None) -> str | None:
    if notes is None:
        return None
    if not isinstance(notes, str):
        raise EngagementError("notes must be a string")
    if len(notes) > MAX_NOTES_CHARS:
        raise EngagementError(f"notes accepts at most {MAX_NOTES_CHARS} characters")
    return _CONTROL_CHARS.sub("", notes).strip() or None


def _validate_fact_key(key: str) -> str:
    if not isinstance(key, str) or not _FACT_KEY.fullmatch(key):
        raise EngagementError("key must be 1-64 lowercase characters: letters, digits, '_', '.', ':' or '-', starting with a letter")
    return key


def _validate_fact_value(value: Any) -> str | int | float | bool:
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EngagementError("value must be a finite number")
        return value
    if isinstance(value, str):
        if len(value) > MAX_FACT_VALUE_CHARS:
            raise EngagementError(f"value accepts at most {MAX_FACT_VALUE_CHARS} characters")
        cleaned = _CONTROL_CHARS.sub("", value).strip()
        if not cleaned:
            raise EngagementError("value must not be empty")
        return cleaned
    raise EngagementError("value must be a string, number, or boolean")


def _validate_query_id(query_id: str) -> str:
    if not isinstance(query_id, str) or not _QUERY_ID.fullmatch(query_id):
        raise EngagementError("evidence_query_id must be a query_id returned by a query tool")
    return query_id


def _freeze_window(window: QueryTimeframe | dict[str, Any] | None) -> dict[str, int] | None:
    if window is None:
        return None
    try:
        timeframe = window if isinstance(window, QueryTimeframe) else QueryTimeframe.model_validate(window)
    except ValidationError as e:
        raise EngagementError(f"window is invalid: {e.errors()[0]['msg']}") from e
    if timeframe.relative_ms is not None:
        now_ms = int(time.time() * 1000)
        return {"from_ms": now_ms - timeframe.relative_ms, "to_ms": now_ms}
    return {"from_ms": int(timeframe.from_ms), "to_ms": int(timeframe.to_ms)}


def _merge_omitted_scope(
    engagement: Engagement,
    source: Engagement,
    omitted: set[str] | frozenset[str],
) -> tuple[Engagement, bool]:
    updates = {name: getattr(source, name) for name in omitted if getattr(source, name)}
    if not updates:
        return engagement, False
    return engagement.model_copy(update=updates), True


# --- Case store ---


class CaseStore:
    """Principal-scoped JSON case files: <root>/<owner sha256>/<case_id>.json."""

    def __init__(self, root: Path):
        self.root = root

    def read(self, principal: MCPContext, case_id: str) -> dict[str, Any] | None:
        path = self._path(principal, case_id)
        with _file_lock:
            return self._read_locked(path, owner_key(principal))

    def update(self, principal: MCPContext, case_id: str, mutate) -> dict[str, Any]:
        path = self._path(principal, case_id)
        owner = owner_key(principal)
        with _file_lock:
            case = self._read_locked(path, owner) or {
                "version": 1,
                "case_id": case_id,
                "owner": owner,
                "principal_id": principal.principal_id,
                "created_at": _now_iso(),
                "engagement": None,
                "facts": [],
                "queries": [],
            }
            mutate(case)
            case["updated_at"] = _now_iso()
            self._write_locked(path, case)
            return case

    def _path(self, principal: MCPContext, case_id: str) -> Path:
        directory = self.root / owner_key(principal)
        path = directory / f"{validate_case_id(case_id)}.json"
        if path.parent != directory or not path.resolve(strict=False).is_relative_to(self.root):
            raise EngagementStoreError("Case path escapes ENGAGEMENT_STORE_DIR")
        return path

    def _read_locked(self, path: Path, owner: str) -> dict[str, Any] | None:
        if path.is_symlink():
            raise EngagementStoreError("Case file must not be a symbolic link")
        if not path.exists():
            return None
        if path.stat().st_size > MAX_CASE_FILE_BYTES:
            raise EngagementStoreError("Case file exceeds the size limit")
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise EngagementStoreError("Case file is unreadable") from e
        if not isinstance(case, dict) or case.get("owner") != owner:
            raise EngagementStoreError("Case file does not belong to this principal")
        return case

    def _write_locked(self, path: Path, case: dict[str, Any]) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        payload = json.dumps(case, sort_keys=True, separators=(",", ":"), default=str)
        if len(payload.encode()) > MAX_CASE_FILE_BYTES:
            raise EngagementStoreError("Case file would exceed the size limit")
        descriptor, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".case-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
            os.replace(temp_name, path)
        except BaseException:
            Path(temp_name).unlink(missing_ok=True)
            raise


def get_engagement_store() -> CaseStore | None:
    raw = get_config().engagement_store_dir.strip()
    if not raw:
        return None
    return CaseStore(validate_store_dir(raw))


def validate_store_dir(raw: str) -> Path:
    """Refuse store locations that could end up committed: relative paths, the repo, or any git tree."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise EngagementStoreError("ENGAGEMENT_STORE_DIR must be an absolute path")
    resolved = path.resolve(strict=False)
    repository = MAIN_DIR.resolve()
    if resolved.is_relative_to(repository):
        raise EngagementStoreError("ENGAGEMENT_STORE_DIR must be outside the gateway repository")
    for ancestor in (resolved, *resolved.parents):
        if (ancestor / ".git").exists():
            raise EngagementStoreError("ENGAGEMENT_STORE_DIR must not be inside a git working tree")
    return resolved


def validate_engagement_settings() -> None:
    """Fail fast at startup on an invalid mode policy or case store location."""
    get_mode_policy_table()
    get_engagement_store()


# --- Helpers ---


def _state_key(owner: str) -> str:
    # FastMCP prefixes state keys with ctx.session_id. The owner suffix keeps two
    # principals that present the same session id from reading each other's state.
    return f"{_STATE_KEY_PREFIX}:{owner}"


def _new_session_record(owner: str) -> dict[str, Any]:
    return {
        "version": 1,
        "owner": owner,
        "engagement": Engagement().model_dump(mode="json"),
        "facts": [],
        "queries": [],
        "last_remaining_quota": None,
    }


async def _load_session_record(ctx: Any, owner: str) -> dict[str, Any] | None:
    if ctx is None or not hasattr(ctx, "get_state"):
        return None
    try:
        record = await ctx.get_state(_state_key(owner))
    except RuntimeError:
        # No MCP session, for example a direct call outside a request.
        return None
    if not isinstance(record, dict) or record.get("version") != 1 or record.get("owner") != owner:
        return None
    return record


async def _save_session_record(ctx: Any, owner: str, record: dict[str, Any]) -> None:
    if ctx is None or not hasattr(ctx, "set_state"):
        raise EngagementError("Engagement state requires an MCP session")
    try:
        await ctx.set_state(_state_key(owner), record)
    except RuntimeError as e:
        raise EngagementError("Engagement state requires an MCP session") from e


def _session_lock(ctx: Any) -> asyncio.Lock:
    try:
        session_id = str(ctx.session_id)
    except Exception:
        session_id = ""
    loop = asyncio.get_running_loop()
    key = (id(loop), int(hashlib.sha256(session_id.encode()).hexdigest(), 16) % _LOCK_STRIPES)
    lock = _session_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _session_locks[key] = lock
    return lock


def _log_view(
    *,
    source: str,
    case_id: str | None,
    engagement: dict[str, Any] | None,
    facts: list[dict[str, Any]],
    queries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "source": source,
        "case_id": case_id,
        "engagement": engagement,
        "facts": facts,
        "queries": queries[-MAX_LOG_QUERIES_RETURNED:],
        "queries_total": len(queries),
        "spend": summarize_spend(queries),
        "content_trust": "untrusted_data",
    }


def _capped(items: list[Any], limit: int) -> list[Any]:
    return items[-limit:]


def _append_capped(case: dict[str, Any], key: str, item: dict[str, Any], limit: int) -> None:
    case[key] = _capped([*case.get(key, []), item], limit)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()
