"""The learner: the single writer of tier-1 fact files.

A second entry point, ``python -m learner <command>`` with ``src`` on ``PYTHONPATH``, started by
a system timer or container cron. Every run holds the learned-store lock, so one learner writes
at a time, and first folds new journal records into the fact files:

- observations are applied, except cost samples measured from the drop in remaining quota,
  which are held for nightly recalibration;
- admin requests revert (tombstone), pin or unpin entries;
- tool steps of a case are written to the replay cache;
- an engagement that was closed, or has been idle for LEARNER_ENGAGEMENT_IDLE_HOURS, is
  processed: helper usage, tool durations, gaps between steps and step sequences.

Then the scheduled jobs run when due (``tick``) or on demand (all times UTC):

- ``nightly`` (LEARNER_NIGHTLY_UTC): expiry, and recalibration of held cost samples against
  ``xql_query_center_history``;
- ``weekly`` (LEARNER_WEEKLY_UTC): a digest file, replay scores for recorded engagements, and
  the most frequent step sequences;
- ``canary`` (on deploy): replay recorded engagements and fail when one reaches less than its
  stored score.

Changes are audited before they are committed. The learner queries XSIAM only as its own
principal (LEARNER_PRINCIPAL_ID in LEARNER_GROUPS) under the normal dataset and tool policy,
within LEARNER_DAILY_UNIT_CAP, and never when remaining quota is below LEARNER_RESERVE_UNITS.
LEARNING_ENABLED=false stops it.
"""

import hashlib
import json
import logging
import math
import re
import time
from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from config.config import get_config
from entities.MCPContext import MCPContext
from usecase import learned_store, learning_journal
from usecase.audit import (
    create_learning_audit_event,
    create_tool_audit_event,
    emit_audit_event,
)
from usecase.fetcher import get_fetcher
from usecase.identity import parse_csv, service_principal
from usecase.learned_store import (
    ADMIN_ACTIONS,
    ENTRY_ID_RE,
    KINDS,
    LIFECYCLE_ACTIONS,
    MAX_EVIDENCE,
    MAX_UNITS,
    QUERY_ID_RE,
    TOKEN_RE,
    LearnedFactRefused,
    LearnedStore,
    LearnedStoreError,
    Observation,
    apply_admin_action,
    apply_observation,
    build_digest,
    ensure_private_dir,
    get_learned_store,
    iso_timestamp,
    journal_dir,
    kind_of_entry_id,
    sweep_entries,
    validate_observation,
    write_private_file,
)
from usecase.log_policy import authorize_dataset
from usecase.replay import (
    CASE_ID_RE,
    FACT_KEY_RE,
    HASH_RE,
    MAX_CACHED_STEPS,
    MAX_MANIFEST_FACTS,
    ResultCache,
    ignore_results_in_pack_history,
    replay_engagement,
)
from usecase.tool_policy import authorize_tool

logger = logging.getLogger(__name__)

COMMANDS = ("tick", "nightly", "weekly", "canary", "status")
HISTORY_DATASET = "xql_query_center_history"
STATE_VERSION = 1
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_ENGAGEMENTS = 1000
MAX_STEPS_PER_ENGAGEMENT = 500
MAX_PENDING_RECALIBRATION = 5000
MAX_SEQUENCE_KEYS = 500
MAX_JOURNAL_READ_BYTES = 64 * 1024 * 1024
MAX_SCORED_CASES = 100
JOURNAL_RETENTION_DAYS = 2
HISTORY_LOOKBACK = timedelta(days=2)
_JOURNAL_FILE_RE = re.compile(r"^(events|admin)-(\d{8})-[0-9a-f]{8}-\d{1,10}\.jsonl$")
_ENGAGEMENT_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_WEEKDAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


# --- Schedules (UTC) ---


def parse_daily(value: str) -> tuple[int, int]:
    match = _HHMM_RE.match(value.strip())
    if not match:
        raise ValueError("LEARNER_NIGHTLY_UTC must be HH:MM in UTC, for example 13:30")
    return int(match.group(1)), int(match.group(2))


def parse_weekly(value: str) -> tuple[int, int, int]:
    parts = value.strip().upper().split()
    if len(parts) != 2 or parts[0] not in _WEEKDAYS or not _HHMM_RE.match(parts[1]):
        raise ValueError("LEARNER_WEEKLY_UTC must be a weekday and HH:MM in UTC, for example 'MON 20:00'")
    hour, minute = parse_daily(parts[1])
    return _WEEKDAYS.index(parts[0]), hour, minute


def last_daily_slot(now: datetime, hour: int, minute: int) -> datetime:
    slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return slot if slot <= now else slot - timedelta(days=1)


def last_weekly_slot(now: datetime, weekday: int, hour: int, minute: int) -> datetime:
    day = now - timedelta(days=(now.weekday() - weekday) % 7)
    slot = day.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return slot if slot <= now else slot - timedelta(days=7)


def _due(last: str | None, slot: datetime) -> bool:
    return last is not None and datetime.fromisoformat(last) < slot


# --- Principal and XSIAM access ---


def learner_principal() -> MCPContext:
    config = get_config()
    return MCPContext(
        auth_headers={"Authorization": config.papi_auth_header_key, "X-XDR-AUTH-ID": config.papi_auth_id_key},
        principal_id=config.learner_principal_id,
        groups=parse_csv(config.learner_groups),
        auth_source="learner-service",
    )


class LearnerContext:
    """The minimal request context the gateway's query path needs, for the learner's own principal."""

    session_id = None

    def __init__(self, principal: MCPContext):
        self.request_context = SimpleNamespace(lifespan_context=principal)
        self._state: dict[str, Any] = {}

    # Async, with FastMCP's keyword, because get_fetcher and the engagement store await these.
    async def set_state(self, key: str, value: Any, *, serializable: bool = True) -> None:
        self._state[key] = value

    async def get_state(self, key: str) -> Any:
        return self._state.get(key)


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


async def remaining_quota(ctx: LearnerContext) -> float | None:
    """Today's remaining units from get_quota. Costs no units."""
    config = get_config()
    fetcher = await get_fetcher(ctx)
    response = await fetcher.send_request("/xql/get_quota", data={"request_data": {}})
    reply = response.get("reply") if isinstance(response, dict) else None
    reply = reply if isinstance(reply, dict) else {}
    used = _finite(reply.get("daily_used_quota"))
    if used is None:
        return None
    budget = config.learner_daily_quota_units
    if budget <= 0:
        annual = _finite(reply.get("license_quota"))
        if annual is None or annual <= 0:
            return None
        budget = (annual + (_finite(reply.get("additional_purchased_quota")) or 0.0)) / 365
    return round(max(budget - used, 0.0), 6)


def _spend_path(root: Path) -> Path:
    return root / "learned" / "learner_spend.json"


def spent_today(root: Path, day: str) -> float:
    path = _spend_path(root)
    if path.is_symlink() or not path.exists():
        return 0.0
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # An unreadable ledger must not reopen the budget.
        return float("inf")
    units = _finite(record.get("units")) if isinstance(record, dict) and record.get("day") == day else 0.0
    return units if units is not None else float("inf")


def _add_spend(root: Path, day: str, units: float) -> None:
    current = spent_today(root, day)
    total = units if math.isinf(current) else current + units
    write_private_file(_spend_path(root), json.dumps({"day": day, "units": round(total, 6)}))


async def _history_query(ctx: LearnerContext, principal: MCPContext, ids: list[str], now: datetime) -> dict[str, Any]:
    from usecase.builtin_components.datasets import query_dataset
    from usecase.dataset_query import QueryFilter, QueryTimeframe

    to_ms = int(now.timestamp() * 1000)
    from_ms = int((now - HISTORY_LOOKBACK).timestamp() * 1000)
    limit = min(len(ids), get_config().dataset_query_max_rows)
    arguments = {
        "dataset": HISTORY_DATASET,
        "mode": "rows",
        "fields": ["execution_id", "compute_units"],
        "filters": [{"field": "execution_id", "operator": "in", "value": ids}],
        "timeframe": {"from_ms": from_ms, "to_ms": to_ms},
        "limit": limit,
    }
    started = time.monotonic()
    result = await query_dataset(
        ctx,
        dataset=HISTORY_DATASET,
        mode="rows",
        fields=["execution_id", "compute_units"],
        filters=[QueryFilter(field="execution_id", operator="in", value=ids)],
        timeframe=QueryTimeframe(from_ms=from_ms, to_ms=to_ms),
        limit=limit,
    )
    await emit_audit_event(
        create_tool_audit_event(
            tool_name="query_dataset",
            phase="end",
            outcome="success" if result.get("success") else "error",
            principal=principal,
            arguments=arguments,
            duration_ms=(time.monotonic() - started) * 1000,
            result_summary={
                "success": result.get("success"),
                "executed": result.get("executed"),
                "query_id": (result.get("provenance") or {}).get("query_id"),
                "caller": "learner",
            },
        )
    )
    return result


async def history_units(root: Path, ids: list[str], now: datetime) -> tuple[dict[str, float], str | None, float]:
    """Authoritative compute units per query id from the query history, or a reason it was skipped."""
    config = get_config()
    principal = learner_principal()
    if not authorize_tool(principal, "query_dataset").allowed or not authorize_dataset(principal, HISTORY_DATASET).allowed:
        return {}, "not_authorized", 0.0
    day = now.date().isoformat()
    spent = spent_today(root, day)
    if spent >= config.learner_daily_unit_cap:
        return {}, "daily_cap", 0.0
    ctx = LearnerContext(principal)
    with service_principal(principal):
        remaining = await remaining_quota(ctx)
        if remaining is None:
            return {}, "quota_unknown", 0.0
        if remaining < config.learner_reserve_units:
            return {}, "below_reserve", 0.0
        result = await _history_query(ctx, principal, ids, now)
    cost = _finite((result.get("xsiam") or {}).get("query_cost"))
    if cost is None:
        # Unknown cost: count the rest of today's cap so the learner stops querying until tomorrow.
        cost = max(config.learner_daily_unit_cap - spent, 0.0)
    _add_spend(root, day, cost)
    if not result.get("success"):
        return {}, "query_failed", cost
    wanted = set(ids)
    measured: dict[str, float] = {}
    for row in result.get("rows") or []:
        query_id = row.get("execution_id") if isinstance(row, dict) else None
        units = _finite(row.get("compute_units")) if isinstance(row, dict) else None
        if query_id in wanted and units is not None and 0 <= units <= MAX_UNITS:
            measured[query_id] = round(units, 6)
    return measured, None, cost


# --- State ---


def _state_path(root: Path) -> Path:
    return root / "learned" / "learner_state.json"


def empty_state() -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "journal_offsets": {},
        "engagements": {},
        "pending_recalibration": [],
        "step_sequences": {},
        "replay_scores": {},
        "last_tick": None,
        "last_nightly": None,
        "last_weekly": None,
    }


def load_state(root: Path) -> dict[str, Any]:
    path = _state_path(root)
    if path.is_symlink():
        raise LearnedStoreError("Learner state must not be a symbolic link")
    if not path.exists():
        return empty_state()
    if path.stat().st_size > MAX_STATE_BYTES:
        raise LearnedStoreError("Learner state exceeds the size limit")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise LearnedStoreError("Learner state is unreadable; inspect it before the journal is folded again") from e
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise LearnedStoreError("Learner state has an unknown version")
    merged = empty_state()
    merged.update({key: state[key] for key in merged if key in state})
    return merged


def save_state(root: Path, state: dict[str, Any]) -> None:
    write_private_file(_state_path(root), json.dumps(state, sort_keys=True, separators=(",", ":")))


# --- Journal ---


def read_journal(root: Path, offsets: dict[str, int]) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    """New complete records from every journal file, in time order, with the offsets after them."""
    directory = journal_dir(root)
    if directory.is_symlink() or not directory.is_dir():
        return [], dict(offsets), 0
    records: list[dict[str, Any]] = []
    new_offsets = dict(offsets)
    invalid = 0
    budget = MAX_JOURNAL_READ_BYTES
    for path in sorted(directory.iterdir()):
        if not _JOURNAL_FILE_RE.match(path.name) or path.is_symlink() or not path.is_file():
            continue
        stat = path.stat()
        if stat.st_mode & 0o022:
            logger.warning("Ignoring a journal file writable by group or others")
            continue
        offset = int(offsets.get(path.name, 0))
        if stat.st_size < offset:
            logger.warning("Ignoring a journal file that shrank since the last run")
            continue
        if stat.st_size == offset or budget <= 0:
            continue
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(min(stat.st_size - offset, budget))
        end = data.rfind(b"\n")
        if end < 0:
            continue
        budget -= end + 1
        stream = path.name.split("-", 1)[0]
        for line in data[: end + 1].splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue
            if not isinstance(record, dict) or record.get("v") != 1 or not isinstance(record.get("at"), str):
                invalid += 1
                continue
            record["_stream"] = stream
            records.append(record)
        new_offsets[path.name] = offset + end + 1
    records.sort(key=lambda record: record["at"])
    return records, new_offsets, invalid


def prune_journal(root: Path, offsets: dict[str, int], now: datetime) -> None:
    """Delete fully consumed journal files older than the retention window."""
    directory = journal_dir(root)
    for name in list(offsets):
        match = _JOURNAL_FILE_RE.match(name)
        path = directory / name
        if match is None or not path.exists():
            offsets.pop(name, None)
            continue
        age_days = (now.date() - datetime.strptime(match.group(2), "%Y%m%d").date()).days
        if age_days > JOURNAL_RETENTION_DAYS and not path.is_symlink() and path.stat().st_size == offsets[name]:
            path.unlink()
            offsets.pop(name, None)


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _principal_id(record: dict[str, Any]) -> str | None:
    principal = record.get("principal")
    value = principal.get("id") if isinstance(principal, dict) else None
    return value if isinstance(value, str) and 0 < len(value) <= 256 else None


def observation_from(record: dict[str, Any]) -> Observation | None:
    try:
        observation = Observation(
            kind=record["kind"],
            fact=record["fact"],
            evidence=tuple(record["evidence"]),
            source_class=record["source_class"],
            dataset=record.get("dataset"),
            effect=record.get("effect", "confirm"),
            engagement=record.get("engagement_key"),
        )
        validate_observation(observation, require_issued=False)
    except (KeyError, TypeError, LearnedFactRefused):
        return None
    return observation


def step_from(record: dict[str, Any]) -> dict[str, Any] | None:
    started, ended = _timestamp(record.get("started_at")), _timestamp(record.get("ended_at"))
    ids = record.get("query_ids")
    case_id = record.get("case_id")
    units = record.get("units")
    duration = _finite(record.get("duration_ms"))
    if (
        started is None
        or ended is None
        or not isinstance(record.get("tool"), str)
        or not TOKEN_RE.match(record["tool"])
        or not isinstance(record.get("engagement_key"), str)
        or not _ENGAGEMENT_KEY_RE.match(record["engagement_key"])
        or not (case_id is None or (isinstance(case_id, str) and CASE_ID_RE.match(case_id)))
        or not isinstance(ids, list)
        or not ids
        or not all(isinstance(item, str) and QUERY_ID_RE.match(item) for item in ids)
        or not (units is None or (_finite(units) is not None and 0 <= units <= MAX_UNITS))
        or duration is None
        or not 0 <= duration <= learned_store.MAX_DURATION_MS
        or record.get("outcome") not in {"success", "error"}
        or not isinstance(record.get("arguments_sha256"), str)
        or not HASH_RE.match(record["arguments_sha256"])
    ):
        return None
    names = record.get("argument_names") if isinstance(record.get("argument_names"), list) else []
    return {
        "engagement_key": record["engagement_key"],
        "case_id": case_id,
        "tool": record["tool"],
        "started_at": record["started_at"],
        "ended_at": record["ended_at"],
        "duration_ms": duration,
        "query_ids": ids[:50],
        "units": units,
        "outcome": record["outcome"],
        "arguments_sha256": record["arguments_sha256"],
        "argument_names": [name for name in names if isinstance(name, str) and TOKEN_RE.match(name)][:50],
        "principal_sha256": hashlib.sha256((_principal_id(record) or "").encode()).hexdigest(),
        "result": record.get("result"),
        "cache_note": record.get("cache_note") if record.get("cache_note") in {"result_too_large", "cache_disabled"} else None,
    }


# --- One run's changes ---


class Batch:
    """Changes of one learner run, kept in memory until they are audited and committed."""

    def __init__(self, store: LearnedStore, now: datetime):
        self.store = store
        self.cache = ResultCache(store.pack_root)
        self.now = now
        self.max_entries = get_config().learning_max_entries_per_kind
        self.entries: dict[str, dict[str, dict[str, Any]]] = {}
        self.dirty: set[str] = set()
        self.changes: list[dict[str, Any]] = []
        self.manifests: dict[str, dict[str, Any]] = {}
        self.result_files: list[tuple[str, str, str]] = []
        self.cached: list[dict[str, Any]] = []
        self.files: list[tuple[Path, str]] = []
        self.observed_by: set[str] = set()
        self.fact_links: list[dict[str, Any]] = []

    def _kind(self, kind: str) -> dict[str, dict[str, Any]]:
        if kind not in self.entries:
            self.entries[kind] = self.store.load(kind)
        return self.entries[kind]

    def _record(self, kind: str, changes: list[dict[str, Any]]) -> int:
        if changes:
            self.dirty.add(kind)
            self.changes.extend(changes)
        return len(changes)

    def apply(self, observation: Observation) -> int:
        entries = self._kind(observation.kind)
        return self._record(
            observation.kind,
            apply_observation(entries, observation, self.now, max_entries=self.max_entries),
        )

    def sweep(self) -> int:
        return sum(self._record(kind, sweep_entries(self._kind(kind), self.now)) for kind in KINDS)

    def admin(self, entry_id: str, action: str, requested_by: str) -> int:
        kind = kind_of_entry_id(entry_id)
        if kind is None:
            return 0
        change = apply_admin_action(
            self._kind(kind),
            entry_id,
            action,
            requested_by_sha256=hashlib.sha256(requested_by.encode()).hexdigest(),
            now=self.now,
        )
        return self._record(kind, [change] if change else [])

    def _manifest(self, case_id: str) -> dict[str, Any]:
        if case_id not in self.manifests:
            self.manifests[case_id] = self.cache.load_manifest(case_id)
        return self.manifests[case_id]

    def cache_step(self, step: dict[str, Any]) -> None:
        config = get_config()
        case_id = step["case_id"]
        manifest = self._manifest(case_id)
        if len(manifest["steps"]) >= MAX_CACHED_STEPS:
            return
        position = len(manifest["steps"])
        entry = {
            "position": position,
            "tool": step["tool"],
            "arguments_sha256": step["arguments_sha256"],
            "argument_names": step["argument_names"],
            "query_ids": step["query_ids"],
            "units": step["units"],
            "duration_ms": step["duration_ms"],
            "outcome": step["outcome"],
            "recorded_at": step["ended_at"],
            "principal_sha256": step["principal_sha256"],
            "result_file": None,
            "result_bytes": 0,
            "cache_note": step["cache_note"],
        }
        if step["cache_note"] is None:
            encoded = json.dumps(step["result"], sort_keys=True, separators=(",", ":"), default=str)
            size = len(encoded.encode())
            if size > config.learning_result_max_bytes:
                entry["cache_note"] = "result_too_large"
            elif manifest["bytes"] + size > config.learning_result_cache_max_bytes:
                entry["cache_note"] = "cache_full"
            else:
                entry["result_file"] = f"{position:04d}.json"
                entry["result_bytes"] = size
                manifest["bytes"] += size
                self.result_files.append((case_id, entry["result_file"], encoded))
        manifest.setdefault("created_at", entry["recorded_at"])
        manifest["steps"].append(entry)
        self.cached.append(
            {
                "case_id": case_id,
                "position": position,
                "tool": step["tool"],
                "result_bytes": entry["result_bytes"],
                "cache_note": entry["cache_note"],
                "query_ids": step["query_ids"][:10],
            }
        )

    def link_fact(self, case_id: str, key: str, evidence_query_id: str) -> None:
        manifest = self._manifest(case_id)
        link = {"key": key, "evidence_query_id": evidence_query_id}
        if link not in manifest["facts"] and len(manifest["facts"]) < MAX_MANIFEST_FACTS:
            manifest["facts"].append(link)
            self.fact_links.append({"case_id": case_id, **link})

    def write_file(self, path: Path, payload: str) -> None:
        self.files.append((path, payload))

    async def commit(self, *, principal: MCPContext, operation: str, details: dict[str, Any], force_audit: bool) -> None:
        """Audit, then write. An audit export failure under fail-closed raises before anything is written."""
        if self.changes or self.cached or self.fact_links or self.files or force_audit:
            await emit_audit_event(
                create_learning_audit_event(
                    operation=operation,
                    principal=principal,
                    changes=self.changes,
                    trigger="learner",
                    details={
                        **details,
                        "observed_by": sorted(self.observed_by)[:20],
                        "cached_results": self.cached[:50],
                        "cached_results_count": len(self.cached),
                        "fact_links": self.fact_links[:50],
                    },
                )
            )
        for kind in sorted(self.dirty):
            self.store.save(kind, self.entries[kind])
        root = self.store.pack_root
        if self.manifests:
            ensure_private_dir(root / "engagements", root)
            ignore_results_in_pack_history(root)
        for case_id, file_name, encoded in self.result_files:
            ensure_private_dir(self.cache.case_dir(case_id), root)
            write_private_file(self.cache.result_path(case_id, file_name), encoded)
        for case_id, manifest in self.manifests.items():
            ensure_private_dir(self.cache.case_dir(case_id), root)
            self.cache.save_manifest(case_id, manifest)
        for path, payload in self.files:
            ensure_private_dir(path.parent, root)
            write_private_file(path, payload)
        self.store.append_changes([change for change in self.changes if change["action"] in LIFECYCLE_ACTIONS])


# --- Folding the journal ---


def _fold(batch: Batch, state: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()
    for record in records:
        kind = record.get("type")
        if record["_stream"] == "admin":
            entry_id, action = record.get("entry_id"), record.get("action")
            requested_by = _principal_id(record)
            if (
                kind == "admin"
                and action in ADMIN_ACTIONS
                and isinstance(entry_id, str)
                and ENTRY_ID_RE.match(entry_id)
                and requested_by
            ):
                counts["admin_actions"] += batch.admin(entry_id, action, requested_by)
            else:
                counts["invalid"] += 1
        elif kind == "observation":
            observation = observation_from(record)
            if observation is None:
                counts["invalid"] += 1
                continue
            if _principal_id(record):
                batch.observed_by.add(_principal_id(record))
            if observation.kind == "cost_table" and observation.fact["units_source"] == "remaining_quota_delta":
                pending = state["pending_recalibration"]
                if len(pending) >= MAX_PENDING_RECALIBRATION:
                    _apply_held_sample(batch, pending.pop(0), None)
                pending.append(
                    {
                        "query_id": observation.evidence[0],
                        "dataset": observation.dataset,
                        "window_bucket": observation.fact["window_bucket"],
                        "selectivity": observation.fact["selectivity"],
                        "units": observation.fact["units"],
                        "engagement": observation.engagement,
                    }
                )
                counts["held_cost_samples"] += 1
            else:
                batch.apply(observation)
                counts["observations"] += 1
        elif kind == "tool_step":
            step = step_from(record)
            if step is None:
                counts["invalid"] += 1
                continue
            _track_step(state, step)
            if step["case_id"] and step["cache_note"] != "cache_disabled":
                batch.cache_step(step)
            counts["steps"] += 1
        elif kind == "fact_link":
            case_id, key, query_id = record.get("case_id"), record.get("key"), record.get("evidence_query_id")
            if (
                isinstance(case_id, str)
                and CASE_ID_RE.match(case_id)
                and isinstance(key, str)
                and FACT_KEY_RE.match(key)
                and isinstance(query_id, str)
                and QUERY_ID_RE.match(query_id)
            ):
                batch.link_fact(case_id, key, query_id)
                counts["fact_links"] += 1
            else:
                counts["invalid"] += 1
        elif kind == "engagement_closed":
            key = record.get("engagement_key")
            if isinstance(key, str) and _ENGAGEMENT_KEY_RE.match(key) and key in state["engagements"]:
                state["engagements"][key]["closed_at"] = record["at"]
                counts["closes"] += 1
        else:
            counts["invalid"] += 1
    return dict(counts)


def _track_step(state: dict[str, Any], step: dict[str, Any]) -> None:
    engagements = state["engagements"]
    engagement = engagements.get(step["engagement_key"])
    if engagement is None:
        engagement = {
            "case_id": step["case_id"],
            "first_activity": step["started_at"],
            "last_activity": step["ended_at"],
            "closed_at": None,
            "steps": [],
        }
        engagements[step["engagement_key"]] = engagement
    if len(engagement["steps"]) < MAX_STEPS_PER_ENGAGEMENT:
        engagement["steps"].append(
            {key: step[key] for key in ("tool", "started_at", "ended_at", "duration_ms", "query_ids", "outcome")}
        )
    if step["ended_at"] > engagement["last_activity"]:
        engagement["last_activity"] = step["ended_at"]


def _process_engagement(batch: Batch, state: dict[str, Any], key: str) -> int:
    """Derive helper usage, durations, step gaps and sequences from one finished engagement."""
    engagement = state["engagements"].pop(key)
    steps = sorted(engagement["steps"], key=lambda item: item["started_at"])
    observations = []
    sequences = state["step_sequences"]
    previous = None
    for step in steps:
        evidence = tuple(step["query_ids"][-MAX_EVIDENCE:])
        observations.append(
            Observation(
                "helper_usage",
                {"tool": step["tool"], "outcome": step["outcome"], "queries": len(step["query_ids"])},
                evidence,
                "tool_call_outcome",
                effect="measure",
            )
        )
        observations.append(
            Observation(
                "timings",
                {"metric": "tool_duration_ms", "tool": step["tool"], "previous_tool": None, "duration_ms": step["duration_ms"]},
                evidence,
                "tool_step_timing",
                effect="measure",
            )
        )
        if previous is not None:
            gap = (datetime.fromisoformat(step["started_at"]) - datetime.fromisoformat(previous["ended_at"])).total_seconds()
            if gap >= 0:
                observations.append(
                    Observation(
                        "timings",
                        {
                            "metric": "step_gap_ms",
                            "tool": step["tool"],
                            "previous_tool": previous["tool"],
                            "duration_ms": gap * 1000,
                        },
                        (previous["query_ids"][-1], step["query_ids"][0]),
                        "tool_step_timing",
                        effect="measure",
                    )
                )
            sequence = f"{previous['tool']}>{step['tool']}"
            if sequence in sequences or len(sequences) < MAX_SEQUENCE_KEYS:
                sequences[sequence] = sequences.get(sequence, 0) + 1
        previous = step
    applied = 0
    for observation in observations:
        observation = replace(observation, engagement=key)
        try:
            validate_observation(observation, require_issued=False)
        except LearnedFactRefused:
            continue
        applied += batch.apply(observation)
    return applied


def _process_due_engagements(batch: Batch, state: dict[str, Any], now: datetime) -> dict[str, int]:
    config = get_config()
    idle_cutoff = now - timedelta(hours=config.learner_engagement_idle_hours)
    sla = timedelta(minutes=config.learner_engagement_close_sla_minutes)
    engagements = state["engagements"]
    due = [
        key
        for key, engagement in engagements.items()
        if engagement["closed_at"] is not None or datetime.fromisoformat(engagement["last_activity"]) <= idle_cutoff
    ]
    overflow = len(engagements) - len(due) - MAX_ENGAGEMENTS
    if overflow > 0:
        waiting = sorted((key for key in engagements if key not in due), key=lambda key: engagements[key]["last_activity"])
        due.extend(waiting[:overflow])
    late = 0
    for key in due:
        closed_at = engagements[key]["closed_at"]
        if closed_at is not None and now - datetime.fromisoformat(closed_at) > sla:
            late += 1
        _process_engagement(batch, state, key)
    if late:
        logger.warning(
            "%d engagements were processed more than LEARNER_ENGAGEMENT_CLOSE_SLA_MINUTES after closing; run the learner more often",
            late,
        )
    return {"processed": len(due), "late": late, "open": len(engagements)}


# --- Scheduled jobs ---


def _apply_held_sample(batch: Batch, sample: dict[str, Any], measured: float | None) -> None:
    observation = Observation(
        "cost_table",
        {
            "window_bucket": sample["window_bucket"],
            "selectivity": sample["selectivity"],
            "units": measured if measured is not None else sample["units"],
            "units_source": "query_history" if measured is not None else "remaining_quota_delta",
        },
        (sample["query_id"],),
        "query_metadata",
        sample["dataset"],
        effect="measure",
        engagement=sample.get("engagement"),
    )
    try:
        validate_observation(observation, require_issued=False)
    except LearnedFactRefused:
        return
    batch.apply(observation)


async def _nightly(batch: Batch, state: dict[str, Any], now: datetime) -> dict[str, Any]:
    expired = batch.sweep()
    pending = state["pending_recalibration"]
    report: dict[str, Any] = {"expired": expired, "held_cost_samples": len(pending)}
    if pending:
        ids = list(dict.fromkeys(sample["query_id"] for sample in pending))[: get_config().learner_recalibration_max_ids]
        try:
            measured, skipped, spent = await history_units(batch.store.pack_root, ids, now)
        except Exception as e:
            logger.warning("Cost recalibration failed: %s", type(e).__name__)
            measured, skipped, spent = {}, "error", 0.0
        for sample in pending:
            _apply_held_sample(batch, sample, measured.get(sample["query_id"]))
        state["pending_recalibration"] = []
        report.update({"matched_in_history": len(measured), "skipped": skipped, "units_spent": spent})
    state["last_nightly"] = iso_timestamp(now)
    return report


def _recent_cases(root: Path, since: datetime) -> list[str]:
    engagements = root / "engagements"
    if engagements.is_symlink() or not engagements.is_dir():
        return []
    cases = []
    for directory in engagements.iterdir():
        manifest = directory / "results" / "manifest.json"
        if directory.is_symlink() or not CASE_ID_RE.match(directory.name) or not manifest.is_file():
            continue
        modified = manifest.stat().st_mtime
        if modified >= since.timestamp():
            cases.append((modified, directory.name))
    return [name for _, name in sorted(cases, reverse=True)[:MAX_SCORED_CASES]]


def _score(report: dict[str, Any], now: datetime) -> dict[str, Any]:
    return {
        "steps": report["steps"],
        "cache_hits": report["cache_hits"],
        "queries": report["queries"],
        "units": report["units"],
        "facts_reached": len(report["facts_reached"]),
        "scored_at": iso_timestamp(now),
    }


async def _weekly(batch: Batch, state: dict[str, Any], now: datetime) -> dict[str, Any]:
    root = batch.store.pack_root
    since = now - timedelta(days=7)
    digest = build_digest(batch.store, since, visible=lambda dataset: True)
    scores = {}
    for case_id in _recent_cases(root, since):
        try:
            scores[case_id] = _score(replay_engagement(case_id), now)
        except (ValueError, LearnedStoreError):
            continue
    combined = {**state["replay_scores"], **scores}
    state["replay_scores"] = dict(
        sorted(combined.items(), key=lambda item: item[1]["scored_at"], reverse=True)[:MAX_SCORED_CASES]
    )
    sequences = [
        {"sequence": sequence, "count": count}
        for sequence, count in Counter(state["step_sequences"]).most_common(20)
    ]
    state["step_sequences"] = {}
    path = root / "learned" / "digests" / f"{now:%Y-%m-%d}.json"
    batch.write_file(
        path,
        json.dumps(
            {"generated_at": iso_timestamp(now), "window_days": 7, **digest, "replay_scores": scores, "step_sequences": sequences},
            sort_keys=True,
            indent=2,
        ),
    )
    state["last_weekly"] = iso_timestamp(now)
    return {"digest_file": path.relative_to(root).as_posix(), "cases_scored": len(scores), "step_sequences": len(sequences)}


def run_canary(store: LearnedStore) -> dict[str, Any]:
    """Replay every scored engagement; fail when one now reaches fewer cache hits or facts than its score."""
    state = load_state(store.pack_root)
    regressions = []
    for case_id, score in sorted(state["replay_scores"].items()):
        try:
            report = replay_engagement(case_id)
        except (ValueError, LearnedStoreError) as e:
            regressions.append({"case_id": case_id, "error": type(e).__name__})
            continue
        if report["cache_hits"] < score["cache_hits"] or len(report["facts_reached"]) < score["facts_reached"]:
            regressions.append({"case_id": case_id, "expected": score, "observed": _score(report, learned_store.now_utc())})
    return {"command": "canary", "ok": not regressions, "cases": len(state["replay_scores"]), "regressions": regressions}


def status(store: LearnedStore | None) -> dict[str, Any]:
    config = get_config()
    report: dict[str, Any] = {
        "command": "status",
        "learning_enabled": config.learning_enabled,
        "tenant_pack_configured": store is not None,
        "schedule_utc": {"nightly": config.learner_nightly_utc, "weekly": config.learner_weekly_utc},
    }
    if store is None:
        return report
    state = load_state(store.pack_root)
    backlog = 0
    directory = journal_dir(store.pack_root)
    if directory.is_dir():
        for path in directory.iterdir():
            if _JOURNAL_FILE_RE.match(path.name) and path.is_file():
                backlog += max(path.stat().st_size - int(state["journal_offsets"].get(path.name, 0)), 0)
    report.update(
        {
            "last_tick": state["last_tick"],
            "last_nightly": state["last_nightly"],
            "last_weekly": state["last_weekly"],
            "open_engagements": len(state["engagements"]),
            "held_cost_samples": len(state["pending_recalibration"]),
            "replay_cases_scored": len(state["replay_scores"]),
            "journal_backlog_bytes": backlog,
        }
    )
    return report


# --- Entry ---


async def run(command: str = "tick", *, now: datetime | None = None) -> dict[str, Any]:
    """Run one learner command. ``tick`` folds the journal and runs whatever is due."""
    if command not in COMMANDS:
        raise ValueError(f"command must be one of {', '.join(COMMANDS)}")
    config = get_config()
    store = get_learned_store()
    if command == "status":
        return status(store)
    if not config.learning_enabled:
        logger.info("Learning is frozen (LEARNING_ENABLED=false); the learner did nothing")
        return {"command": command, "skipped": "learning_disabled"}
    if store is None:
        return {"command": command, "skipped": "no_tenant_pack"}
    if command == "canary":
        return run_canary(store)
    nightly_time = parse_daily(config.learner_nightly_utc)
    weekly_time = parse_weekly(config.learner_weekly_utc)
    principal = learner_principal()
    async with store.locked():
        now = now or learned_store.now_utc()
        root = store.pack_root
        learning_journal.ignore_runtime_files_in_pack_history(root)
        state = load_state(root)
        batch = Batch(store, now)
        records, offsets, unreadable = read_journal(root, state["journal_offsets"])
        folded = _fold(batch, state, records)
        engagements = _process_due_engagements(batch, state, now)
        # The first run sets the schedule baseline instead of running every job at once.
        for key in ("last_nightly", "last_weekly"):
            if state[key] is None:
                state[key] = iso_timestamp(now)
        jobs: dict[str, Any] = {}
        if command == "nightly" or (command == "tick" and _due(state["last_nightly"], last_daily_slot(now, *nightly_time))):
            jobs["nightly"] = await _nightly(batch, state, now)
        if command == "weekly" or (command == "tick" and _due(state["last_weekly"], last_weekly_slot(now, *weekly_time))):
            jobs["weekly"] = await _weekly(batch, state, now)
        report = {
            "command": command,
            "at": iso_timestamp(now),
            "journal_records": len(records),
            "unreadable_records": unreadable + folded.pop("invalid", 0),
            "folded": folded,
            "engagements": engagements,
            "jobs": jobs,
            "actions": dict(Counter(change["action"] for change in batch.changes)),
        }
        await batch.commit(principal=principal, operation=command, details=report, force_audit=bool(jobs))
        state["journal_offsets"] = offsets
        state["last_tick"] = iso_timestamp(now)
        prune_journal(root, state["journal_offsets"], now)
        save_state(root, state)
    await learning_journal.flush()
    return report
