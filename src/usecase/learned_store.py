"""Tier-1 learned facts: the machine-written ``learned/`` layer of the tenant pack.

Facts live in ``<TENANT_PACK_DIR>/learned/<kind>.json``, one file per kind. Every entry
carries the fact, the query ids it was derived from, first and last seen, confirmation
and contradiction counts, a confidence, an expiry, a structured source class and a
status. ``learned/changes.jsonl`` keeps the lifecycle history that the digest reads.

Only structured observations become facts: query ids, query metadata (cost, remaining
quota, row counts), classified error classes, field names and value types, tool names
and timings. Every entry is validated on write and again on read: strings are short
tokens or identifiers and evidence must be query ids this process received from XSIAM,
so text from result rows cannot become a fact, and a hand-edited entry that fails
validation is ignored.

Writers: gateway processes never write these files. They append observations to the learning
journal (``learning_journal``) and the learner process (``usecase.learner``) is the single
writer, holding the store lock while it folds the journal in.

Lifecycle: a confirmation raises confidence; a contradiction demotes the entry at once
(confidence 0, not served) and it is promoted again only after ``PROMOTE_STREAK``
consecutive confirmations; entries expire after ``LEARNING_SCHEMA_TTL_DAYS`` (schema,
enum and absent-field facts) or ``LEARNING_COST_TTL_DAYS`` (cost, timing and helper
facts) without a confirmation. A human revert leaves a tombstone that stops the same
fact being re-learned until it expires.

The learner audits each run's changes before committing them, so when audit export fails
closed nothing is written. ``LEARNING_ENABLED=false`` stops the observers and the learner; a
human revert request is still recorded and hidden on read while learning is frozen.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import math
import os
import re
import tempfile
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - the gateway runs on POSIX hosts and containers
    fcntl = None

from config.config import get_config
from pkg.util import MAIN_DIR

logger = logging.getLogger(__name__)

KINDS: tuple[str, ...] = ("schema", "enum_fields", "absent_fields", "cost_table", "timings", "helper_usage")
SCHEMA_KINDS = frozenset({"schema", "enum_fields", "absent_fields"})
MEASUREMENT_KINDS = frozenset({"cost_table", "timings", "helper_usage"})
SOURCE_CLASSES = frozenset(
    {
        "field_discovery_sample",  # field names and value types from a discovery sample
        "query_metadata",  # query_cost, remaining_quota, row count of an executed query
        "query_error_class",  # a classified XSIAM failure of an executed query
        "query_pair_outcome",  # an equality query with no rows, then the same query with contains and rows
        "tool_step_timing",  # tool durations and gaps between engagement steps
        "tool_call_outcome",  # helper usage: calls, outcomes, queries per tool
    }
)
STATUSES = ("active", "demoted", "reverted")
LIFECYCLE_ACTIONS = frozenset({"learned", "promoted", "demoted", "expired", "reverted"})
FIELD_TYPES = frozenset({"string", "integer", "number", "boolean", "array", "object", "mixed"})
WINDOW_BUCKETS = ("le_1h", "le_6h", "le_24h", "le_7d", "le_30d", "gt_30d", "unspecified")
SELECTIVITY_CLASSES = ("sample", "unfiltered", "filtered", "selective")
UNITS_SOURCES = frozenset({"query_cost", "remaining_quota_delta", "query_history"})
TIMING_METRICS = frozenset({"tool_duration_ms", "step_gap_ms"})
TOOL_OUTCOMES = frozenset({"success", "error"})

MAX_TOKEN_CHARS = 64
MAX_EVIDENCE = 10
MAX_RECENT_SAMPLES = 20
MAX_UNITS = 1_000_000.0
MAX_DURATION_MS = 7 * 86_400_000.0
MAX_QUERIES_PER_CALL = 10_000
PROMOTE_STREAK = 2
OUTLIER_FACTOR = 4.0
OUTLIER_MIN_OBSERVATIONS = 3
OUTLIER_FLOOR_UNITS = 0.1
MAX_KIND_FILE_BYTES = 8 * 1024 * 1024
MAX_CHANGES_LOG_BYTES = 2 * 1024 * 1024
MAX_ISSUED_QUERY_IDS = 10_000
MAX_NOTE_FILES = 500
MAX_NOTE_FILE_BYTES = 512 * 1024
MAX_REVERT_JOURNAL_BYTES = 1024 * 1024
MAX_DIGEST_ITEMS_PER_ACTION = 100
LOCK_ATTEMPTS = 40
LOCK_RETRY_SECONDS = 0.05

QUERY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,63}$")
ENTRY_ID_RE = re.compile(r"^(sch|enm|abs|cst|tim|hlp)-[0-9a-f]{20}$")
NOTE_PATH_RE = re.compile(r"^notes/[A-Za-z0-9_./-]{1,120}\.md$")
_NOTE_LINE_RE = re.compile(
    r"^\s*(?:[-*]\s+)?verified:\s*(?P<first>\S+)(?:\s+(?P<dataset>\S+)\s+(?P<field>\S+))?\s*(?:#.*)?$",
    re.IGNORECASE,
)
_KIND_PREFIX = {
    "schema": "sch",
    "enum_fields": "enm",
    "absent_fields": "abs",
    "cost_table": "cst",
    "timings": "tim",
    "helper_usage": "hlp",
}
_PREFIX_KIND = {prefix: kind for kind, prefix in _KIND_PREFIX.items()}
# Field names come from log sources an attacker may influence. A name built from these words
# reads as an instruction to an agent, so it is never stored, even though it is a valid identifier.
_INSTRUCTION_WORDS = frozenset({"ignore", "disregard", "jailbreak", "instruction", "instructions"})
_INSTRUCTION_HINTS = frozenset(
    {"previous", "prompt", "assistant", "override", "verified", "trust", "rules", "system", "mark", "execute"}
)
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_ENTRY_KEYS = frozenset(
    {
        "entry_id",
        "kind",
        "dataset",
        "fact",
        "previous_fact",
        "evidence",
        "first_seen",
        "last_seen",
        "confirmations",
        "contradictions",
        "streak",
        "confidence",
        "expires_at",
        "source_class",
        "status",
        "status_changed_at",
        "reverted_by_sha256",
    }
)

_issued_query_ids: OrderedDict[str, None] = OrderedDict()
_async_locks: dict[tuple[int, str], asyncio.Lock] = {}
_snapshot_cache: dict[str, tuple[int, int, dict[str, dict[str, Any]]]] = {}
_notes_cache: dict[str, tuple[tuple[tuple[str, int, int], ...], dict[str, str]]] = {}


class LearnedStoreError(RuntimeError):
    """Raised when the tenant pack is misconfigured or a learned file is unusable."""


class LearnedFactRefused(ValueError):
    """Raised when an observation or entry fails the forgery guard."""


@dataclass(frozen=True)
class Observation:
    """One structured observation for one fact.

    For schema, enum and absent-field kinds ``fact`` is the asserted value and ``effect``
    is ``confirm`` or ``contradict``. For cost, timing and helper kinds ``fact`` is one
    sample and ``effect`` is ``measure``.
    """

    kind: str
    fact: dict[str, Any]
    evidence: tuple[str, ...]
    source_class: str
    dataset: str | None = None
    effect: str = "confirm"


# --- Evidence registry ---


def register_query_id(query_id: Any) -> str | None:
    """Remember a query id that XSIAM returned to this process. Only these can be evidence."""
    if not isinstance(query_id, str) or not QUERY_ID_RE.match(query_id):
        return None
    _issued_query_ids[query_id] = None
    _issued_query_ids.move_to_end(query_id)
    while len(_issued_query_ids) > MAX_ISSUED_QUERY_IDS:
        _issued_query_ids.popitem(last=False)
    return query_id


def is_issued_query_id(query_id: Any) -> bool:
    return isinstance(query_id, str) and query_id in _issued_query_ids


def reset_state() -> None:
    """Forget issued query ids and cached reads. For tests."""
    _issued_query_ids.clear()
    _snapshot_cache.clear()
    _notes_cache.clear()


# --- Keys and validation (the forgery guard) ---


def entry_key(kind: str, dataset: str | None, fact: dict[str, Any]) -> tuple[Any, ...]:
    if kind in SCHEMA_KINDS:
        return (dataset, fact.get("field"))
    if kind == "cost_table":
        return (dataset, fact.get("window_bucket"), fact.get("selectivity"))
    if kind == "timings":
        return (fact.get("metric"), fact.get("tool"), fact.get("previous_tool"))
    if kind == "helper_usage":
        return (fact.get("tool"),)
    raise LearnedFactRefused(f"Unknown learned fact kind: {kind}")


def make_entry_id(kind: str, key: tuple[Any, ...]) -> str:
    encoded = json.dumps([kind, *key], separators=(",", ":"), default=str).encode()
    return f"{_KIND_PREFIX[kind]}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def kind_of_entry_id(entry_id: Any) -> str | None:
    if not isinstance(entry_id, str) or not ENTRY_ID_RE.match(entry_id):
        return None
    return _PREFIX_KIND[entry_id.split("-", 1)[0]]


def _refuse(reason: str) -> None:
    raise LearnedFactRefused(reason)


def _identifier(value: Any) -> None:
    if not isinstance(value, str) or not IDENTIFIER_RE.match(value):
        _refuse("expected a short identifier")


def looks_like_instruction(name: str) -> bool:
    words = [word.lower() for word in _WORD_RE.findall(name)]
    return any(word in _INSTRUCTION_WORDS for word in words) or sum(word in _INSTRUCTION_HINTS for word in words) >= 2


def _field_name(value: Any) -> None:
    _identifier(value)
    if looks_like_instruction(value):
        _refuse("field name reads as an instruction")


def _token(value: Any) -> None:
    if not isinstance(value, str) or not TOKEN_RE.match(value):
        _refuse("expected a short token")


def _optional_token(value: Any) -> None:
    if value is not None:
        _token(value)


def _one_of(allowed: frozenset[str] | tuple[str, ...]):
    def check(value: Any) -> None:
        if value not in allowed:
            _refuse(f"value must be one of {sorted(allowed)}")

    return check


def _bounded_count(maximum: int):
    def check(value: Any) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
            _refuse("expected a non-negative integer in range")

    return check


_count = _bounded_count(10**9)


def _bounded_number(maximum: float):
    def check(value: Any) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            _refuse("expected a finite number")
        if value < 0 or value > maximum:
            _refuse("number out of range")

    return check


def _samples(maximum: float):
    number = _bounded_number(maximum)

    def check(value: Any) -> None:
        if not isinstance(value, list) or not value or len(value) > MAX_RECENT_SAMPLES:
            _refuse("expected a short list of samples")
        for item in value:
            number(item)

    return check


_FACT_SPECS: dict[str, dict[str, Any]] = {
    "schema": {"field": _field_name, "type": _one_of(FIELD_TYPES)},
    "enum_fields": {"field": _field_name, "operator": _one_of(frozenset({"contains"}))},
    "absent_fields": {"field": _field_name},
    "cost_table": {
        "window_bucket": _one_of(WINDOW_BUCKETS),
        "selectivity": _one_of(SELECTIVITY_CLASSES),
        "observations": _count,
        "low_units": _bounded_number(MAX_UNITS),
        "median_units": _bounded_number(MAX_UNITS),
        "high_units": _bounded_number(MAX_UNITS),
        "recent_units": _samples(MAX_UNITS),
        "units_source": _one_of(UNITS_SOURCES | {"mixed"}),
    },
    "timings": {
        "metric": _one_of(TIMING_METRICS),
        "tool": _token,
        "previous_tool": _optional_token,
        "observations": _count,
        "low_ms": _bounded_number(MAX_DURATION_MS),
        "median_ms": _bounded_number(MAX_DURATION_MS),
        "high_ms": _bounded_number(MAX_DURATION_MS),
        "recent_ms": _samples(MAX_DURATION_MS),
    },
    "helper_usage": {
        "tool": _token,
        "calls": _count,
        "successes": _count,
        "errors": _count,
        "queries": _count,
    },
}
_SAMPLE_SPECS: dict[str, dict[str, Any]] = {
    "cost_table": {
        "window_bucket": _one_of(WINDOW_BUCKETS),
        "selectivity": _one_of(SELECTIVITY_CLASSES),
        "units": _bounded_number(MAX_UNITS),
        "units_source": _one_of(UNITS_SOURCES),
    },
    "timings": {
        "metric": _one_of(TIMING_METRICS),
        "tool": _token,
        "previous_tool": _optional_token,
        "duration_ms": _bounded_number(MAX_DURATION_MS),
    },
    "helper_usage": {
        "tool": _token,
        "outcome": _one_of(TOOL_OUTCOMES),
        "queries": _bounded_count(MAX_QUERIES_PER_CALL),
    },
}
_OPTIONAL_FACT_KEYS = {"timings": frozenset({"previous_tool"})}


def _check_shape(value: Any, spec: dict[str, Any], optional: frozenset[str] = frozenset()) -> None:
    if not isinstance(value, dict):
        _refuse("fact must be an object")
    extra = set(value) - set(spec)
    if extra:
        _refuse(f"unexpected fact keys: {sorted(extra)}")
    missing = set(spec) - set(value) - optional
    if missing:
        _refuse(f"missing fact keys: {sorted(missing)}")
    for key, check in spec.items():
        check(value.get(key))


def validate_fact(kind: str, fact: Any) -> None:
    if kind not in _FACT_SPECS:
        _refuse(f"Unknown learned fact kind: {kind}")
    _check_shape(fact, _FACT_SPECS[kind], _OPTIONAL_FACT_KEYS.get(kind, frozenset()))


def validate_evidence(evidence: Any, *, require_issued: bool) -> None:
    if not isinstance(evidence, (list, tuple)) or not evidence or len(evidence) > MAX_EVIDENCE:
        _refuse("evidence must list between 1 and 10 query ids")
    for item in evidence:
        if not isinstance(item, str) or not QUERY_ID_RE.match(item):
            _refuse("evidence must be query ids")
        if require_issued and not is_issued_query_id(item):
            _refuse("evidence query id was not returned by XSIAM to this gateway")


def validate_observation(observation: Observation, *, require_issued: bool = True) -> None:
    if observation.kind not in KINDS:
        _refuse(f"Unknown learned fact kind: {observation.kind}")
    if observation.source_class not in SOURCE_CLASSES:
        _refuse("source_class must be a structured observation class")
    validate_evidence(observation.evidence, require_issued=require_issued)
    if observation.kind in MEASUREMENT_KINDS:
        if observation.effect != "measure":
            _refuse("measurement kinds accept only measure observations")
        _check_shape(observation.fact, _SAMPLE_SPECS[observation.kind], _OPTIONAL_FACT_KEYS.get(observation.kind, frozenset()))
    else:
        if observation.effect not in {"confirm", "contradict"}:
            _refuse("schema kinds accept only confirm or contradict observations")
        if observation.effect == "contradict":
            _check_shape({"field": observation.fact.get("field")}, {"field": _field_name})
        else:
            validate_fact(observation.kind, observation.fact)
    if observation.kind in SCHEMA_KINDS or observation.kind == "cost_table":
        _identifier(observation.dataset)
    elif observation.dataset is not None:
        _refuse("this kind is not scoped to a dataset")


def validate_entry(entry: Any) -> dict[str, Any]:
    """Validate a stored entry in full. Raises LearnedFactRefused."""
    if not isinstance(entry, dict):
        _refuse("entry must be an object")
    extra = set(entry) - _ENTRY_KEYS
    if extra:
        _refuse(f"unexpected entry keys: {sorted(extra)}")
    kind = entry.get("kind")
    if kind not in KINDS:
        _refuse("unknown kind")
    validate_fact(kind, entry.get("fact"))
    if entry.get("previous_fact") is not None:
        validate_fact(kind, entry["previous_fact"])
    dataset = entry.get("dataset")
    if kind in SCHEMA_KINDS or kind == "cost_table":
        _identifier(dataset)
    elif dataset is not None:
        _refuse("this kind is not scoped to a dataset")
    if entry.get("entry_id") != make_entry_id(kind, entry_key(kind, dataset, entry["fact"])):
        _refuse("entry_id does not match the fact key")
    validate_evidence(entry.get("evidence"), require_issued=False)
    for name in ("first_seen", "last_seen", "expires_at", "status_changed_at"):
        _timestamp(entry.get(name))
    for name in ("confirmations", "contradictions", "streak"):
        _count(entry.get(name))
    _bounded_number(1.0)(entry.get("confidence"))
    if entry.get("source_class") not in SOURCE_CLASSES:
        _refuse("source_class must be a structured observation class")
    if entry.get("status") not in STATUSES:
        _refuse("unknown status")
    reverted_by = entry.get("reverted_by_sha256")
    if reverted_by is not None and (not isinstance(reverted_by, str) or not re.fullmatch(r"[0-9a-f]{64}", reverted_by)):
        _refuse("reverted_by_sha256 must be a sha256 digest")
    return entry


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        _refuse("expected an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        _refuse("expected an ISO timestamp")
    if parsed.tzinfo is None:
        _refuse("timestamp must carry a timezone")
    return parsed


# --- Lifecycle ---


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso_timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds")


def ttl_for(kind: str) -> timedelta:
    config = get_config()
    days = config.learning_schema_ttl_days if kind in SCHEMA_KINDS else config.learning_cost_ttl_days
    return timedelta(days=days)


def _confidence(streak: int) -> float:
    return round(min(0.99, 1 - 0.5**streak), 3)


def _change(action: str, entry: dict[str, Any], now: datetime) -> dict[str, Any]:
    change = {
        "at": iso_timestamp(now),
        "action": action,
        "entry_id": entry["entry_id"],
        "kind": entry["kind"],
        "dataset": entry.get("dataset"),
        "fact": entry["fact"],
        "evidence": list(entry["evidence"]),
        "source_class": entry["source_class"],
        "confirmations": entry["confirmations"],
        "contradictions": entry["contradictions"],
        "confidence": entry["confidence"],
        "status": entry["status"],
        "expires_at": entry["expires_at"],
    }
    if entry.get("previous_fact") is not None and action == "demoted":
        change["previous_fact"] = entry["previous_fact"]
    return change


def _add_evidence(entry: dict[str, Any], evidence: tuple[str, ...]) -> None:
    merged = [item for item in entry["evidence"] if item not in evidence] + list(evidence)
    entry["evidence"] = merged[-MAX_EVIDENCE:]


def _touch(entry: dict[str, Any], observation: Observation, now: datetime) -> None:
    _add_evidence(entry, observation.evidence)
    entry["last_seen"] = iso_timestamp(now)
    entry["expires_at"] = iso_timestamp(now + ttl_for(entry["kind"]))
    entry["source_class"] = observation.source_class


def _initial_fact(observation: Observation) -> dict[str, Any]:
    sample = observation.fact
    if observation.kind == "cost_table":
        units = round(float(sample["units"]), 6)
        return {
            "window_bucket": sample["window_bucket"],
            "selectivity": sample["selectivity"],
            "observations": 1,
            "low_units": units,
            "median_units": units,
            "high_units": units,
            "recent_units": [units],
            "units_source": sample["units_source"],
        }
    if observation.kind == "timings":
        duration = round(float(sample["duration_ms"]), 3)
        return {
            "metric": sample["metric"],
            "tool": sample["tool"],
            "previous_tool": sample.get("previous_tool"),
            "observations": 1,
            "low_ms": duration,
            "median_ms": duration,
            "high_ms": duration,
            "recent_ms": [duration],
        }
    if observation.kind == "helper_usage":
        return {
            "tool": sample["tool"],
            "calls": 1,
            "successes": 1 if sample["outcome"] == "success" else 0,
            "errors": 1 if sample["outcome"] == "error" else 0,
            "queries": int(sample["queries"]),
        }
    return dict(sample)


def _merge_sample(kind: str, fact: dict[str, Any], sample: dict[str, Any]) -> dict[str, Any]:
    if kind == "helper_usage":
        return {
            **fact,
            "calls": fact["calls"] + 1,
            "successes": fact["successes"] + (1 if sample["outcome"] == "success" else 0),
            "errors": fact["errors"] + (1 if sample["outcome"] == "error" else 0),
            "queries": fact["queries"] + int(sample["queries"]),
        }
    if kind == "cost_table":
        recent = [*fact["recent_units"], round(float(sample["units"]), 6)][-MAX_RECENT_SAMPLES:]
        source = fact["units_source"] if fact["units_source"] == sample["units_source"] else "mixed"
        return {
            **fact,
            "observations": fact["observations"] + 1,
            "low_units": min(recent),
            "median_units": round(median(recent), 6),
            "high_units": max(recent),
            "recent_units": recent,
            "units_source": source,
        }
    recent = [*fact["recent_ms"], round(float(sample["duration_ms"]), 3)][-MAX_RECENT_SAMPLES:]
    return {
        **fact,
        "observations": fact["observations"] + 1,
        "low_ms": min(recent),
        "median_ms": round(median(recent), 3),
        "high_ms": max(recent),
        "recent_ms": recent,
    }


def _is_outlier(kind: str, fact: dict[str, Any], sample: dict[str, Any]) -> bool:
    """A cost far above what was learned contradicts the entry, so callers stop trusting it.

    A cheaper-than-learned query only makes the learned value conservative, so it is not
    treated as a contradiction.
    """
    if kind != "cost_table" or fact["observations"] < OUTLIER_MIN_OBSERVATIONS:
        return False
    return float(sample["units"]) > OUTLIER_FACTOR * max(fact["high_units"], OUTLIER_FLOOR_UNITS)


def _confirm(entry: dict[str, Any], now: datetime) -> dict[str, Any]:
    entry["confirmations"] += 1
    entry["streak"] += 1
    entry["confidence"] = _confidence(entry["streak"])
    if entry["status"] == "demoted" and entry["streak"] >= PROMOTE_STREAK:
        entry["status"] = "active"
        entry["status_changed_at"] = iso_timestamp(now)
        return _change("promoted", entry, now)
    return _change("confirmed", entry, now)


def _demote(entry: dict[str, Any], now: datetime, replacement: dict[str, Any] | None = None) -> dict[str, Any]:
    entry["contradictions"] += 1
    entry["streak"] = 0
    entry["confidence"] = 0.0
    entry["status"] = "demoted"
    entry["status_changed_at"] = iso_timestamp(now)
    if replacement is not None:
        entry["previous_fact"] = entry["fact"]
        entry["fact"] = replacement
    return _change("demoted", entry, now)


def apply_observation(
    entries: dict[str, dict[str, Any]],
    observation: Observation,
    now: datetime,
    *,
    max_entries: int,
) -> list[dict[str, Any]]:
    """Apply one validated observation to the entries of its kind and return the changes."""
    key = entry_key(observation.kind, observation.dataset, observation.fact)
    entry_id = make_entry_id(observation.kind, key)
    entry = entries.get(entry_id)
    if entry is not None and entry["status"] == "reverted":
        # A human reverted this fact; it is not re-learned until the tombstone expires.
        return []

    if observation.effect == "contradict":
        if entry is None:
            return []
        _touch(entry, observation, now)
        return [_demote(entry, now)]

    if entry is None:
        if len(entries) >= max_entries:
            # Refuse rather than evict, so a flood of new facts cannot push out established ones.
            logger.info("Learned %s store is full; observation not recorded", observation.kind)
            return []
        entry = {
            "entry_id": entry_id,
            "kind": observation.kind,
            "dataset": observation.dataset,
            "fact": _initial_fact(observation),
            "evidence": list(observation.evidence)[-MAX_EVIDENCE:],
            "first_seen": iso_timestamp(now),
            "last_seen": iso_timestamp(now),
            "confirmations": 1,
            "contradictions": 0,
            "streak": 1,
            "confidence": _confidence(1),
            "expires_at": iso_timestamp(now + ttl_for(observation.kind)),
            "source_class": observation.source_class,
            "status": "active",
            "status_changed_at": iso_timestamp(now),
        }
        entries[entry_id] = entry
        return [_change("learned", entry, now)]

    _touch(entry, observation, now)
    if observation.effect == "measure":
        outlier = _is_outlier(observation.kind, entry["fact"], observation.fact)
        entry["fact"] = _merge_sample(observation.kind, entry["fact"], observation.fact)
        return [_demote(entry, now)] if outlier else [_confirm(entry, now)]
    if entry["fact"] == observation.fact:
        return [_confirm(entry, now)]
    return [_demote(entry, now, replacement=dict(observation.fact))]


def sweep_entries(entries: dict[str, dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    changes = []
    for entry_id in list(entries):
        entry = entries[entry_id]
        if _timestamp(entry["expires_at"]) <= now:
            del entries[entry_id]
            changes.append(_change("expired", entry, now))
    return changes


def _is_live(entry: dict[str, Any], now: datetime) -> bool:
    return _timestamp(entry["expires_at"]) > now


# --- Files ---


def validate_pack_dir(raw: str) -> Path:
    """Refuse pack locations that could be committed with the gateway: relative paths or the repository.

    The pack may be its own git repository; that history is the operator's, not the gateway's.
    """
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise LearnedStoreError("TENANT_PACK_DIR must be an absolute path")
    resolved = path.resolve(strict=False)
    if resolved.is_relative_to(MAIN_DIR.resolve()):
        raise LearnedStoreError("TENANT_PACK_DIR must be outside the gateway repository")
    return resolved


def get_pack_root() -> Path | None:
    raw = get_config().tenant_pack_dir.strip()
    if not raw:
        return None
    return validate_pack_dir(raw)


def get_learned_store() -> "LearnedStore | None":
    root = get_pack_root()
    return LearnedStore(root) if root is not None else None


def write_private_file(path: Path, payload: str) -> None:
    """Write a file atomically with owner-only permissions. Refuses to follow a symbolic link."""
    if path.is_symlink():
        raise LearnedStoreError("Refusing to write through a symbolic link")
    descriptor, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def ensure_private_dir(path: Path, root: Path) -> None:
    """Create ``path`` under the pack root with owner-only permissions, refusing symbolic links below the root."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise LearnedStoreError("Refusing to use a symbolic link inside TENANT_PACK_DIR")
        current.mkdir(mode=0o700, exist_ok=True)
        if current.stat().st_mode & 0o077:
            current.chmod(0o700)


class LearnedStore:
    """JSON files under ``<pack>/learned/``. File methods are synchronous; call them under ``locked()``."""

    def __init__(self, pack_root: Path):
        self.pack_root = pack_root
        self.root = pack_root / "learned"

    def kind_path(self, kind: str) -> Path:
        if kind not in KINDS:
            raise LearnedFactRefused(f"Unknown learned fact kind: {kind}")
        return self.root / f"{kind}.json"

    @property
    def changes_path(self) -> Path:
        return self.root / "changes.jsonl"

    def load(self, kind: str) -> dict[str, dict[str, Any]]:
        """Read a kind file, dropping any entry that fails validation."""
        path = self.kind_path(kind)
        if path.is_symlink():
            raise LearnedStoreError("Learned file must not be a symbolic link")
        if not path.exists():
            return {}
        if path.stat().st_size > MAX_KIND_FILE_BYTES:
            raise LearnedStoreError(f"Learned {kind} file exceeds the size limit")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise LearnedStoreError(f"Learned {kind} file is unreadable") from e
        raw_entries = document.get("entries") if isinstance(document, dict) else None
        if not isinstance(raw_entries, dict):
            raise LearnedStoreError(f"Learned {kind} file has no entries object")
        entries: dict[str, dict[str, Any]] = {}
        dropped = 0
        for entry_id, entry in raw_entries.items():
            try:
                validate_entry(entry)
            except LearnedFactRefused:
                dropped += 1
                continue
            if entry_id != entry["entry_id"] or entry["kind"] != kind:
                dropped += 1
                continue
            entries[entry_id] = entry
        if dropped:
            logger.warning("Ignored %d invalid entries in learned %s file", dropped, kind)
        return entries

    def snapshot(self, kind: str) -> dict[str, dict[str, Any]]:
        """Cached read for serving. Callers must not mutate the result."""
        path = self.kind_path(kind)
        try:
            stat = path.stat()
        except FileNotFoundError:
            return {}
        cached = _snapshot_cache.get(str(path))
        if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
        entries = self.load(kind)
        _snapshot_cache[str(path)] = (stat.st_mtime_ns, stat.st_size, entries)
        return entries

    def save(self, kind: str, entries: dict[str, dict[str, Any]]) -> None:
        for entry in entries.values():
            validate_entry(entry)
        ensure_private_dir(self.root, self.pack_root)
        document = {"version": 1, "kind": kind, "updated_at": iso_timestamp(now_utc()), "entries": entries}
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
        if len(payload.encode()) > MAX_KIND_FILE_BYTES:
            raise LearnedStoreError(f"Learned {kind} file would exceed the size limit")
        write_private_file(self.kind_path(kind), payload)

    def append_changes(self, changes: list[dict[str, Any]]) -> None:
        if not changes:
            return
        ensure_private_dir(self.root, self.pack_root)
        path = self.changes_path
        if path.is_symlink():
            raise LearnedStoreError("Learned change log must not be a symbolic link")
        payload = "".join(json.dumps(change, sort_keys=True, separators=(",", ":")) + "\n" for change in changes)
        size = path.stat().st_size if path.exists() else 0
        if size + len(payload.encode()) > MAX_CHANGES_LOG_BYTES:
            # Keep the newer half so the digest still covers recent weeks.
            existing = path.read_text(encoding="utf-8").splitlines() if size else []
            kept = existing[len(existing) // 2 :]
            write_private_file(path, "".join(line + "\n" for line in kept) + payload)
            return
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, payload.encode())
        finally:
            os.close(descriptor)

    def read_changes(self, since: datetime) -> list[dict[str, Any]]:
        path = self.changes_path
        if path.is_symlink() or not path.exists():
            return []
        changes = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                change = json.loads(line)
                validate_entry_change(change)
            except (json.JSONDecodeError, LearnedFactRefused):
                continue
            if _timestamp(change["at"]) >= since:
                changes.append(change)
        return changes

    def locked(self):
        return directory_lock(self.pack_root, self.root)


@contextlib.asynccontextmanager
async def directory_lock(pack_root: Path, directory: Path):
    """Serialise writes to one pack directory: an asyncio lock in-process, a non-blocking flock across processes.

    The flock is polled with ``asyncio.sleep`` so a write held by another process never blocks the event loop.
    """
    loop_key = (id(asyncio.get_running_loop()), str(directory))
    lock = _async_locks.setdefault(loop_key, asyncio.Lock())
    async with lock:
        ensure_private_dir(directory, pack_root)
        if fcntl is None:
            yield
            return
        descriptor = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            for _ in range(LOCK_ATTEMPTS):
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    await asyncio.sleep(LOCK_RETRY_SECONDS)
            else:
                raise LearnedStoreError("Tenant pack directory is locked by another process")
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def validate_entry_change(change: Any) -> None:
    if not isinstance(change, dict):
        _refuse("change must be an object")
    _timestamp(change.get("at"))
    if change.get("action") not in LIFECYCLE_ACTIONS | {"confirmed"}:
        _refuse("unknown change action")
    kind = kind_of_entry_id(change.get("entry_id"))
    if kind is None or kind != change.get("kind"):
        _refuse("change entry id does not match its kind")
    validate_fact(kind, change.get("fact"))
    validate_evidence(change.get("evidence"), require_issued=False)


# --- Revert requests ---


def revert_in_entries(
    entries: dict[str, dict[str, Any]],
    entry_id: str,
    *,
    requested_by_sha256: str,
    now: datetime,
) -> dict[str, Any] | None:
    """Turn an entry into a tombstone on a human's request. Returns the change, or None when there is nothing to revert."""
    entry = entries.get(entry_id)
    if entry is None or entry["status"] == "reverted":
        return None
    entry["status"] = "reverted"
    entry["streak"] = 0
    entry["confidence"] = 0.0
    entry["status_changed_at"] = iso_timestamp(now)
    entry["expires_at"] = iso_timestamp(now + ttl_for(entry["kind"]))
    entry["reverted_by_sha256"] = requested_by_sha256
    return _change("reverted", entry, now)


def journal_dir(pack_root: Path) -> Path:
    return pack_root / "learned" / "journal"


def pending_revert_ids() -> frozenset[str]:
    """Entry ids with a revert request in the journal. Read paths hide them before the learner applies them."""
    root = get_pack_root()
    if root is None:
        return frozenset()
    directory = journal_dir(root)
    if directory.is_symlink() or not directory.is_dir():
        return frozenset()
    pending: set[str] = set()
    budget = MAX_REVERT_JOURNAL_BYTES
    for path in sorted(directory.glob("reverts-*.jsonl")):
        if path.is_symlink() or not path.is_file():
            continue
        size = path.stat().st_size
        if size > budget:
            logger.warning("Revert journal exceeds the read budget; some requests are applied only by the learner")
            break
        budget -= size
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            entry_id = record.get("entry_id") if isinstance(record, dict) else None
            if record.get("type") == "revert" and isinstance(entry_id, str) and ENTRY_ID_RE.match(entry_id):
                pending.add(entry_id)
    return frozenset(pending)


def build_digest(store: "LearnedStore", since: datetime, visible) -> dict[str, Any]:
    """Group lifecycle changes since a moment, newest first, keeping those whose dataset ``visible`` allows."""
    grouped: dict[str, list[dict[str, Any]]] = {action: [] for action in sorted(LIFECYCLE_ACTIONS)}
    for change in reversed(store.read_changes(since)):
        if visible(change.get("dataset")):
            grouped[change["action"]].append(digest_item(change))
    confirmed: dict[str, int] = {}
    for kind in KINDS:
        count = sum(
            1
            for entry in read_entries(kind)
            if entry["confirmations"] > 1 and _timestamp(entry["last_seen"]) >= since and visible(entry.get("dataset"))
        )
        if count:
            confirmed[kind] = count
    return {
        "since": iso_timestamp(since),
        "summary": {action: len(items) for action, items in grouped.items()},
        "changes": {action: items[:MAX_DIGEST_ITEMS_PER_ACTION] for action, items in grouped.items()},
        "confirmed_entries": confirmed,
    }


def digest_item(change: dict[str, Any]) -> dict[str, Any]:
    item = {
        key: change[key]
        for key in (
            "at",
            "entry_id",
            "kind",
            "dataset",
            "fact",
            "previous_fact",
            "evidence",
            "source_class",
            "confirmations",
            "contradictions",
            "confidence",
            "status",
            "expires_at",
        )
        if key in change
    }
    if change["action"] in {"learned", "promoted", "demoted"}:
        item["revert_with"] = {"tool": "revert_learned", "entry_id": change["entry_id"]}
    return item


# --- Read paths ---


def read_entries(kind: str, *, include_inactive: bool = False) -> list[dict[str, Any]]:
    """Return unexpired entries of one kind; only active ones unless include_inactive is set."""
    store = get_learned_store()
    if store is None:
        return []
    now = now_utc()
    entries = store.snapshot(kind).values()
    pending = pending_revert_ids()
    return [
        entry
        for entry in entries
        if _is_live(entry, now)
        and (include_inactive or (entry["status"] == "active" and entry["entry_id"] not in pending))
    ]


def find_entry(entry_id: str) -> dict[str, Any] | None:
    kind = kind_of_entry_id(entry_id)
    store = get_learned_store()
    if kind is None or store is None:
        return None
    return store.snapshot(kind).get(entry_id)


def _safe_read(kind: str) -> list[dict[str, Any]]:
    try:
        return read_entries(kind)
    except (LearnedStoreError, OSError) as e:
        logger.warning("Learned %s facts unavailable: %s", kind, type(e).__name__)
        return []


def lookup_cost(dataset: str, window_bucket: str, selectivity: str) -> dict[str, Any] | None:
    """Return the learned cost for a dataset, window bucket and selectivity class, or None.

    Hook for the cost guard: read this before the seed table. Only active entries with at
    least ``LEARNING_COST_MIN_OBSERVATIONS`` observations are returned; ``high_units`` is
    the maximum of the recent samples, so a caller using it stays conservative.
    """
    entry_id = make_entry_id("cost_table", (dataset, window_bucket, selectivity))
    minimum = get_config().learning_cost_min_observations
    for entry in _safe_read("cost_table"):
        if entry["entry_id"] == entry_id and entry["fact"]["observations"] >= minimum:
            return {
                "entry_id": entry_id,
                "median_units": entry["fact"]["median_units"],
                "high_units": entry["fact"]["high_units"],
                "observations": entry["fact"]["observations"],
                "confidence": entry["confidence"],
                "units_source": entry["fact"]["units_source"],
            }
    return None


def learned_enum_fields(dataset: str) -> frozenset[str]:
    """Hook for the validator: fields of a dataset that match with contains but not with equality."""
    return frozenset(entry["fact"]["field"] for entry in _safe_read("enum_fields") if entry["dataset"] == dataset)


def learned_absent_fields(dataset: str) -> frozenset[str]:
    """Hook for the validator: fields XSIAM reported as unknown in a dataset."""
    return frozenset(entry["fact"]["field"] for entry in _safe_read("absent_fields") if entry["dataset"] == dataset)


def verified_notes() -> dict[str, str]:
    """Map entry ids to the human note under ``<pack>/notes/`` that verifies them.

    A note verifies a fact with a line ``verified: <entry_id>`` or, for field facts,
    ``verified: <kind> <dataset> <field>``.
    """
    root = get_pack_root()
    if root is None:
        return {}
    notes_dir = root / "notes"
    if not notes_dir.is_dir() or notes_dir.is_symlink():
        return {}
    files = []
    for path in sorted(notes_dir.rglob("*.md"))[:MAX_NOTE_FILES]:
        if path.is_symlink() or not path.is_file():
            continue
        if not path.resolve(strict=False).is_relative_to(notes_dir.resolve()):
            continue
        stat = path.stat()
        if stat.st_size > MAX_NOTE_FILE_BYTES:
            continue
        files.append((path, stat.st_mtime_ns, stat.st_size))
    signature = tuple((str(path), mtime, size) for path, mtime, size in files)
    cached = _notes_cache.get(str(notes_dir))
    if cached and cached[0] == signature:
        return cached[1]
    index: dict[str, str] = {}
    for path, _, _ in files:
        relative = path.relative_to(root).as_posix()
        if not NOTE_PATH_RE.match(relative) or ".." in relative:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line in text.splitlines():
            match = _NOTE_LINE_RE.match(line)
            if not match:
                continue
            first, dataset, field_name = match.group("first"), match.group("dataset"), match.group("field")
            if dataset is None and ENTRY_ID_RE.match(first):
                index.setdefault(first, relative)
            elif (
                dataset is not None
                and first in SCHEMA_KINDS
                and IDENTIFIER_RE.match(dataset)
                and IDENTIFIER_RE.match(field_name)
            ):
                index.setdefault(make_entry_id(first, (dataset, field_name)), relative)
    _notes_cache[str(notes_dir)] = (signature, index)
    return index


def trust_label(entry: dict[str, Any], notes: dict[str, str]) -> dict[str, Any]:
    note = notes.get(entry["entry_id"])
    if note:
        return {"label": "verified", "note": note, "confirmations": entry["confirmations"]}
    return {"label": "learned", "confirmations": entry["confirmations"]}
